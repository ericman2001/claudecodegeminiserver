use crate::{mime, request::GeminiRequest, response, tls};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, info, warn};

/// Maximum time allowed for the TLS handshake to complete before the
/// connection is dropped (slowloris mitigation).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time allowed for the whole connection (handshake, request read,
/// and response write) so a slow client cannot hold a permit indefinitely.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Run the Gemini server
pub async fn run_server(
    hostnames: Vec<String>,
    host: String,
    port: u16,
    cert_path: PathBuf,
    key_path: PathBuf,
    root_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate certificate files
    if !tls::cert_files_exist(&cert_path, &key_path) {
        error!("Certificate files not found. Generate them with --generate-cert");
        return Err("Certificate files not found".into());
    }

    tls::validate_cert_files(&cert_path, &key_path)?;

    // Load TLS acceptor
    let acceptor = tls::load_tls_acceptor(&cert_path, &key_path)?;

    // Canonicalize the cert and key paths so we can refuse to serve them even
    // if they live inside the served root.
    let mut forbidden_files: Vec<PathBuf> = Vec::new();
    if let Ok(canonical_cert) = cert_path.canonicalize() {
        forbidden_files.push(canonical_cert);
    }
    if let Ok(canonical_key) = key_path.canonicalize() {
        forbidden_files.push(canonical_key);
    }
    let forbidden_files = Arc::new(forbidden_files);

    // Bind to the configured address. `host` may be a DNS name rather than an
    // IP, so bind via (host, port) directly instead of parsing a SocketAddr.
    let listener = TcpListener::bind((host.as_str(), port)).await?;
    let local_addr = listener.local_addr()?;
    // The port we advertise/enforce must be the port we actually bound.
    info!("Server listening on {}", local_addr);

    // Share server state
    let hostnames = Arc::new(hostnames);
    let root_dir = Arc::new(root_dir);

    // Limit concurrent connections to prevent DoS
    // 100 concurrent connections is a reasonable default for a small server
    let connection_limit = Arc::new(tokio::sync::Semaphore::new(100));

    // Accept connections
    loop {
        // Acquire a permit before accepting a new connection
        // This provides backpressure if the server is overloaded
        let permit = match connection_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(e) => {
                error!("Semaphore closed: {}", e);
                break;
            }
        };

        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                debug!("New connection from {}", peer_addr);

                let acceptor = acceptor.clone();
                let hostnames = hostnames.clone();
                let root_dir = root_dir.clone();
                let forbidden_files = forbidden_files.clone();

                // Handle connection in a separate task
                tokio::spawn(async move {
                    // The permit is moved into the task and will be dropped when the task finishes
                    let _permit = permit;

                    // Cap the entire connection lifetime so slow response
                    // reads/writes cannot hold a permit indefinitely.
                    match tokio::time::timeout(
                        CONNECTION_TIMEOUT,
                        handle_connection(
                            stream,
                            acceptor,
                            hostnames,
                            port,
                            root_dir,
                            forbidden_files,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => error!("Connection error from {}: {}", peer_addr, e),
                        Err(_) => warn!("Connection from {} timed out", peer_addr),
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                // Drop the permit since we didn't spawn a task
                drop(permit);
            }
        }
    }
    Ok(())
}

/// Handle a single client connection
async fn handle_connection(
    stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    hostnames: Arc<Vec<String>>,
    served_port: u16,
    root_dir: Arc<PathBuf>,
    forbidden_files: Arc<Vec<PathBuf>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Perform TLS handshake with a timeout so a stalled handshake cannot hold
    // a semaphore permit indefinitely (slowloris mitigation).
    let mut tls_stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            warn!("TLS handshake failed: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            warn!("TLS handshake timed out");
            return Ok(());
        }
    };

    debug!("TLS handshake completed");

    // Read and parse request
    let request = match GeminiRequest::from_stream(&mut tls_stream).await {
        Ok(req) => req,
        Err(e) => {
            warn!("Failed to parse request: {}", e);
            response::send_bad_request(&mut tls_stream).await?;
            return Ok(());
        }
    };

    info!("Request: {} {}", request.url.as_str(), request.path);

    // Reject requests whose authority (hostname/port) we do not serve, per the
    // Gemini spec, with status 53 (proxy request refused).
    if !request.matches_authority(&hostnames, served_port) {
        if !request.matches_hostname(&hostnames) {
            warn!(
                "Rejecting request: hostname {:?} is not served (served: {:?})",
                request.hostname(),
                hostnames.as_ref()
            );
        } else {
            warn!(
                "Rejecting request: port {} does not match served port {}",
                request.port(),
                served_port
            );
        }
        response::send_proxy_request_refused(&mut tls_stream).await?;
        tls_stream.shutdown().await?;
        return Ok(());
    }

    // Resolve file path
    match resolve_path_checked(&root_dir, &request.path, &forbidden_files) {
        Some(file_path) => {
            // Serve the file
            serve_file(&mut tls_stream, &file_path).await?;
        }
        None => {
            // Path not found or invalid
            debug!("Path not found: {}", request.path);
            response::send_not_found(&mut tls_stream).await?;
        }
    }

    // Close TLS connection properly
    tls_stream.shutdown().await?;

    Ok(())
}

/// Resolve request path to filesystem path
fn resolve_path(root: &Path, request_path: &str) -> Option<PathBuf> {
    // Remove leading slash and decode URL encoding
    let decoded_path = request_path.trim_start_matches('/');

    // Perform iterative URL decoding to handle double/triple encoding
    let mut previous_decoded = String::new();
    let mut current_decoded = decoded_path.to_string();
    const MAX_DECODE_ITERATIONS: usize = 10;

    for _ in 0..MAX_DECODE_ITERATIONS {
        if previous_decoded == current_decoded {
            break;
        }
        previous_decoded = current_decoded.clone();
        current_decoded = match urlencoding::decode(&current_decoded) {
            Ok(decoded) => decoded.into_owned(),
            Err(_) => {
                warn!("Invalid URL encoding in path: {}", request_path);
                return None;
            }
        };
    }

    if previous_decoded != current_decoded {
        warn!("Path decoding reached iteration limit, potential DoS attack");
        return None;
    }

    // Robust directory traversal prevention
    if is_directory_traversal_attempt(&current_decoded) {
        warn!("Directory traversal attempt detected: {}", current_decoded);
        return None;
    }

    // Normalize path to prevent various bypass techniques
    let normalized_path = normalize_path(&current_decoded);

    // Join with root directory using the normalized path
    let base_path = root.join(&normalized_path);

    // SECURITY: Get canonical root path for validation
    let canonical_root = match root.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            error!("Failed to canonicalize root directory: {:?}", root);
            return None;
        }
    };

    // SECURITY: Pre-validate that our constructed path would be within root
    // before doing any filesystem operations that could leak information
    // We do this by checking if the base path (without resolving symlinks)
    // starts with our root when both are made absolute
    let absolute_base = match base_path.canonicalize() {
        Ok(canonical) => canonical,
        Err(_) => {
            // Path doesn't exist yet, so we can't canonicalize it
            // We need to validate using a different approach

            // Convert to absolute path without resolving symlinks
            let absolute_base = if base_path.is_absolute() {
                base_path.clone()
            } else {
                std::env::current_dir().unwrap_or_default().join(&base_path)
            };

            // Check if this absolute path would be under our root
            // by checking if it starts with the canonical root
            if !absolute_base.starts_with(&canonical_root) {
                warn!(
                    "Constructed path would be outside root: {:?}",
                    absolute_base
                );
                return None;
            }

            // If the base path doesn't exist, try our variations
            let path_candidates = vec![
                base_path.join("index.gmi"),     // Directory index
                base_path.with_extension("gmi"), // Adding .gmi extension
            ];

            for candidate in path_candidates {
                if candidate.exists() {
                    match candidate.canonicalize() {
                        Ok(canonical_path) => {
                            if canonical_path.starts_with(&canonical_root)
                                && canonical_path.is_file()
                            {
                                return Some(canonical_path);
                            } else if !canonical_path.starts_with(&canonical_root) {
                                warn!(
                                    "Path escape attempt: {:?} is not under {:?}",
                                    canonical_path, canonical_root
                                );
                                return None;
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
            return None;
        }
    };

    // If we got here, the base path exists and we have its canonical form
    // Verify it's within our root directory
    if !absolute_base.starts_with(&canonical_root) {
        warn!(
            "Path escape attempt: {:?} is not under {:?}",
            absolute_base, canonical_root
        );
        return None;
    }

    // Now safely check what type of file/directory we have
    if absolute_base.is_file() {
        return Some(absolute_base);
    } else if absolute_base.is_dir() {
        // Look for index.gmi in the directory
        let index_path = absolute_base.join("index.gmi");
        if index_path.exists() && index_path.is_file() {
            match index_path.canonicalize() {
                Ok(canonical_index) => {
                    if canonical_index.starts_with(&canonical_root) {
                        return Some(canonical_index);
                    } else {
                        warn!("Index path escape attempt: {:?}", canonical_index);
                        return None;
                    }
                }
                Err(_) => return None,
            }
        }
    } else {
        // Not a regular file or directory, try adding .gmi extension
        let gmi_path = absolute_base.with_extension("gmi");
        if gmi_path.exists() && gmi_path.is_file() {
            match gmi_path.canonicalize() {
                Ok(canonical_gmi) => {
                    if canonical_gmi.starts_with(&canonical_root) {
                        return Some(canonical_gmi);
                    } else {
                        warn!("GMI path escape attempt: {:?}", canonical_gmi);
                        return None;
                    }
                }
                Err(_) => return None,
            }
        }
    }

    // No valid file found
    None
}

/// Resolve a request path and then reject sensitive files inside the root.
///
/// This wraps `resolve_path` (whose directory-traversal defenses are left
/// untouched) and additionally refuses dotfiles and the configured cert/key
/// files, returning `None` (which callers translate to a 51 not-found).
fn resolve_path_checked(
    root: &Path,
    request_path: &str,
    forbidden_files: &[PathBuf],
) -> Option<PathBuf> {
    let resolved = resolve_path(root, request_path)?;
    let canonical_root = root.canonicalize().ok()?;
    if is_refused_file(&resolved, &canonical_root, forbidden_files) {
        debug!("Refusing to serve sensitive file: {:?}", resolved);
        return None;
    }
    Some(resolved)
}

/// Determine whether a canonical, in-root file should be refused.
///
/// A file is refused if any of its path components below the root begin with
/// a `.` (dotfiles) or if its canonical path equals one of `forbidden_files`
/// (the configured cert/key).
fn is_refused_file(
    canonical_path: &Path,
    canonical_root: &Path,
    forbidden_files: &[PathBuf],
) -> bool {
    // Refuse the configured cert/key files.
    if forbidden_files.iter().any(|f| f == canonical_path) {
        return true;
    }

    // Refuse dotfiles: inspect only the components below the root so a root
    // that itself lives under a dot-directory is not incorrectly refused.
    if let Ok(relative) = canonical_path.strip_prefix(canonical_root) {
        for component in relative.components() {
            if let Component::Normal(name) = component
                && name.to_string_lossy().starts_with('.')
            {
                return true;
            }
        }
    }

    false
}

/// Check if a decoded path contains directory traversal patterns
fn is_directory_traversal_attempt(path: &str) -> bool {
    // Check for various directory traversal patterns
    let traversal_patterns = [
        "..",     // Basic parent directory
        ".\\..",  // Windows style
        "../",    // With slash
        "..\\",   // Windows with backslash
        "%2e%2e", // URL encoded (should be caught by iterative decoding)
        "..\x00", // Null byte injection
    ];

    for pattern in &traversal_patterns {
        if path.contains(pattern) {
            return true;
        }
    }

    // Check for encoded variations that might slip through
    if path.contains('\0') {
        return true; // Null byte injection
    }

    // Check for various Unicode representations of dots
    // Unicode normalization attack prevention
    if path.contains("\u{002e}\u{002e}") || // Standard dots  
       path.contains("\u{ff0e}\u{ff0e}") || // Fullwidth dots
       path.contains("\u{2024}\u{2024}")
    {
        // One dot leader
        return true;
    }

    false
}

/// Normalize path to prevent various bypass techniques
fn normalize_path(path: &str) -> String {
    let mut normalized = path.to_string();

    // Replace backslashes with forward slashes for consistency
    normalized = normalized.replace('\\', "/");

    // Remove null bytes
    normalized = normalized.replace('\0', "");

    // Collapse multiple slashes into single slash
    const MAX_NORMALIZE_ITERATIONS: usize = 10;
    for _ in 0..MAX_NORMALIZE_ITERATIONS {
        if !normalized.contains("//") {
            break;
        }
        normalized = normalized.replace("//", "/");
    }

    if normalized.contains("//") {
        warn!("Path normalization reached iteration limit, potential DoS attack");
        // Return a value that will cause the path resolution to fail
        return "/.".to_string();
    }

    // Remove leading slashes
    normalized = normalized.trim_start_matches('/').to_string();

    // Remove trailing slashes
    normalized = normalized.trim_end_matches('/').to_string();

    normalized
}

/// Serve a file to the client
async fn serve_file(
    stream: &mut TlsStream<tokio::net::TcpStream>,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // TOCTOU Mitigation: Open the file first, then get metadata and read from the handle.
    // This ensures that we are checking and reading the same file, preventing a race
    // condition where the file could be swapped for a symlink after validation.
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open file {}: {}", path.display(), e);
            // The file might not be found if it was deleted after path resolution.
            // Treat as a temporary failure.
            response::send_not_found(stream).await?;
            return Ok(());
        }
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to get metadata for {}: {}", path.display(), e);
            response::send_not_found(stream).await?;
            return Ok(());
        }
    };

    // The resolved path should always be a file, but we check again on the handle
    // as a defense-in-depth measure against TOCTOU attacks.
    if !metadata.is_file() {
        warn!("Path is not a regular file: {}", path.display());
        response::send_not_found(stream).await?;
        return Ok(());
    }

    // Check file size (optional: add a maximum file size limit)
    const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB
    if metadata.len() > MAX_FILE_SIZE {
        warn!("File too large: {} bytes", metadata.len());
        response::send_temporary_failure(stream, "File too large").await?;
        return Ok(());
    }

    // Detect MIME type
    let mime_type = mime::get_mime_type(path);
    debug!("Serving {} with MIME type: {}", path.display(), mime_type);

    // Send response header with sanitized MIME type
    // Note: mime::get_mime_type returns static strings, but we use Response::success
    // which will construct a Response that sanitizes the meta field through Response::new
    let response = response::Response::success(mime_type, vec![]);
    response.write_header(stream).await?;

    // Stream file content
    if let Err(e) = tokio::io::copy(&mut file, stream).await {
        error!("Failed to stream file content {}: {}", path.display(), e);
        // We can't send an error response here because we've already sent the success header
        // The client will detect the truncated connection
        return Ok(());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_resolve_path_basic() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create test file
        let test_file = root.join("test.gmi");
        fs::write(&test_file, "test content").unwrap();

        // Test basic path resolution
        let resolved = resolve_path(root, "/test.gmi");
        assert_eq!(resolved, Some(test_file.canonicalize().unwrap()));
    }

    #[test]
    fn test_resolve_path_directory_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Test directory traversal prevention
        assert_eq!(resolve_path(root, "/../etc/passwd"), None);
        assert_eq!(resolve_path(root, "/../../etc/passwd"), None);
        assert_eq!(resolve_path(root, "/test/../../../etc/passwd"), None);

        // Test URL encoded traversal attempts
        assert_eq!(resolve_path(root, "/%2e%2e/etc/passwd"), None);
        assert_eq!(resolve_path(root, "/%2e%2e%2fetc%2fpasswd"), None);

        // Test double URL encoded traversal (the vulnerability we found)
        assert_eq!(resolve_path(root, "/%252e%252e/etc/passwd"), None);
        assert_eq!(resolve_path(root, "/%252e%252e%252fetc%252fpasswd"), None);

        // Test Windows-style traversal
        assert_eq!(resolve_path(root, "/..\\etc\\passwd"), None);
        assert_eq!(resolve_path(root, "/test\\..\\..\\..\\etc\\passwd"), None);

        // Test null byte injection
        assert_eq!(resolve_path(root, "/test.gmi\0../../../etc/passwd"), None);
        assert_eq!(resolve_path(root, "/test.gmi%00../../../etc/passwd"), None);
    }

    #[test]
    fn test_is_directory_traversal_attempt() {
        // Basic traversal patterns
        assert!(is_directory_traversal_attempt("../etc/passwd"));
        assert!(is_directory_traversal_attempt("../../etc/passwd"));
        assert!(is_directory_traversal_attempt("test/../../../etc/passwd"));

        // Windows style
        assert!(is_directory_traversal_attempt("..\\etc\\passwd"));
        assert!(is_directory_traversal_attempt("test\\..\\..\\etc\\passwd"));

        // With slashes
        assert!(is_directory_traversal_attempt("../"));
        assert!(is_directory_traversal_attempt("..\\"));

        // Null byte injection
        assert!(is_directory_traversal_attempt("test\0../etc/passwd"));

        // Valid paths should not be flagged
        assert!(!is_directory_traversal_attempt("test.gmi"));
        assert!(!is_directory_traversal_attempt("subdir/file.gmi"));
        assert!(!is_directory_traversal_attempt("index.gmi"));
        assert!(!is_directory_traversal_attempt(""));
    }

    #[test]
    fn test_normalize_path() {
        // Basic normalization
        assert_eq!(normalize_path("test.gmi"), "test.gmi");
        assert_eq!(normalize_path("/test.gmi"), "test.gmi");
        assert_eq!(normalize_path("test.gmi/"), "test.gmi");
        assert_eq!(normalize_path("/test.gmi/"), "test.gmi");

        // Multiple slashes
        assert_eq!(normalize_path("test//file.gmi"), "test/file.gmi");
        assert_eq!(normalize_path("///test///file.gmi///"), "test/file.gmi");

        // Backslash to forward slash conversion
        assert_eq!(normalize_path("test\\file.gmi"), "test/file.gmi");
        assert_eq!(normalize_path("test\\\\file.gmi"), "test/file.gmi");

        // Null byte removal
        assert_eq!(normalize_path("test\0file.gmi"), "testfile.gmi");

        // Empty and root cases
        assert_eq!(normalize_path(""), "");
        assert_eq!(normalize_path("/"), "");
        assert_eq!(normalize_path("///"), "");
    }

    #[test]
    fn test_resolve_path_index() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create index file
        let index_file = root.join("index.gmi");
        fs::write(&index_file, "index content").unwrap();

        // Test index file resolution
        let resolved = resolve_path(root, "/");
        assert_eq!(resolved, Some(index_file.canonicalize().unwrap()));
    }

    #[test]
    fn test_security_ordering_no_information_leakage() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a file outside the root directory (simulating /etc/passwd)
        let outside_dir = temp_dir.path().parent().unwrap();
        let outside_file = outside_dir.join("secret.txt");
        fs::write(&outside_file, "secret content").unwrap();

        // Attempt directory traversal to access the file
        // This should fail WITHOUT leaking whether the file exists
        let result = resolve_path(root, "/../secret.txt");
        assert_eq!(result, None);

        // The key security improvement: we should not be able to determine
        // if files exist outside our root directory through timing or other means
        // This test verifies our fix prevents information leakage

        // Test various traversal attempts that should all fail safely
        let traversal_attempts = vec![
            "/../secret.txt",
            "/%2e%2e/secret.txt",
            "/%252e%252e/secret.txt",
        ];

        for attempt in traversal_attempts {
            let result = resolve_path(root, attempt);
            assert_eq!(result, None, "Traversal attempt should fail: {}", attempt);
        }

        // Clean up
        let _ = fs::remove_file(&outside_file);
    }

    #[test]
    fn test_refuse_cert_and_key_and_dotfiles() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Place cert, key, a dotfile, and a normal file inside the root.
        let cert_file = root.join("cert.pem");
        let key_file = root.join("key.pem");
        let hidden_file = root.join(".hidden");
        let normal_file = root.join("index.gmi");
        fs::write(&cert_file, "cert").unwrap();
        fs::write(&key_file, "key").unwrap();
        fs::write(&hidden_file, "secret").unwrap();
        fs::write(&normal_file, "hello").unwrap();

        let forbidden = vec![
            cert_file.canonicalize().unwrap(),
            key_file.canonicalize().unwrap(),
        ];

        // The cert, key, and dotfile must all be refused.
        assert_eq!(resolve_path_checked(root, "/cert.pem", &forbidden), None);
        assert_eq!(resolve_path_checked(root, "/key.pem", &forbidden), None);
        assert_eq!(resolve_path_checked(root, "/.hidden", &forbidden), None);

        // A normal file is still served.
        assert_eq!(
            resolve_path_checked(root, "/index.gmi", &forbidden),
            Some(normal_file.canonicalize().unwrap())
        );
    }

    #[test]
    fn test_refuse_dotfile_in_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        let sub = root.join("sub");
        fs::create_dir(&sub).unwrap();
        let hidden = sub.join(".env");
        fs::write(&hidden, "SECRET=1").unwrap();

        assert_eq!(resolve_path_checked(root, "/sub/.env", &[]), None);
    }

    #[test]
    fn test_is_refused_file() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path().canonicalize().unwrap();

        let normal = root.join("page.gmi");
        let dotfile = root.join(".secret");
        let cert = root.join("cert.pem");
        let forbidden = vec![cert.clone()];

        assert!(!is_refused_file(&normal, &root, &forbidden));
        assert!(is_refused_file(&dotfile, &root, &forbidden));
        assert!(is_refused_file(&cert, &root, &forbidden));
    }
}
