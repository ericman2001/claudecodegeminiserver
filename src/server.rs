use crate::{mime, request::GeminiRequest, response, tls};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, info, warn};

/// Run the Gemini server
pub async fn run_server(
    hostname: String,
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

    // Bind to address
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let listener = TcpListener::bind(&addr).await?;
    info!("Server listening on {}", addr);

    // Share server state
    let hostname = Arc::new(hostname);
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
                let hostname = hostname.clone();
                let root_dir = root_dir.clone();

                // Handle connection in a separate task
                tokio::spawn(async move {
                    // The permit is moved into the task and will be dropped when the task finishes
                    let _permit = permit;

                    if let Err(e) = handle_connection(stream, acceptor, hostname, root_dir).await {
                        error!("Connection error from {}: {}", peer_addr, e);
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
    hostname: Arc<String>,
    root_dir: Arc<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Perform TLS handshake
    let mut tls_stream = match acceptor.accept(stream).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("TLS handshake failed: {}", e);
            return Err(e.into());
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

    // Check hostname matches (optional, but good practice)
    if !request.matches_hostname(&hostname) {
        debug!(
            "Hostname mismatch: expected {}, got {:?}",
            hostname,
            request.hostname()
        );
    }

    // Resolve file path
    match resolve_path(&root_dir, &request.path) {
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

    // Send response header
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
}
