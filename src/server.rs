use crate::{mime, request::GeminiRequest, response, tls};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
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
    
    // Accept connections
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                debug!("New connection from {}", peer_addr);
                
                let acceptor = acceptor.clone();
                let hostname = hostname.clone();
                let root_dir = root_dir.clone();
                
                // Handle connection in a separate task
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, acceptor, hostname, root_dir).await {
                        error!("Connection error from {}: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
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
        debug!("Hostname mismatch: expected {}, got {:?}", hostname, request.hostname());
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
    
    // Keep decoding until no more changes occur (prevents double encoding bypass)
    while previous_decoded != current_decoded {
        previous_decoded = current_decoded.clone();
        current_decoded = match urlencoding::decode(&current_decoded) {
            Ok(decoded) => decoded.into_owned(),
            Err(_) => {
                warn!("Invalid URL encoding in path: {}", request_path);
                return None;
            }
        };
    }
    
    // Robust directory traversal prevention
    if is_directory_traversal_attempt(&current_decoded) {
        warn!("Directory traversal attempt detected: {}", current_decoded);
        return None;
    }
    
    // Normalize path to prevent various bypass techniques
    let normalized_path = normalize_path(&current_decoded);
    
    // Join with root directory using the normalized path
    let mut path = root.join(&normalized_path);
    
    // If path is a directory, look for index.gmi
    if path.is_dir() {
        path = path.join("index.gmi");
    }
    
    // If file doesn't have an extension and doesn't exist, try adding .gmi
    if path.extension().is_none() && !path.exists() {
        let gmi_path = path.with_extension("gmi");
        if gmi_path.exists() {
            path = gmi_path;
        }
    }
    
    // Ensure the path exists and is a file
    if !path.exists() || !path.is_file() {
        return None;
    }
    
    // Final security check: ensure the resolved path is under the root directory
    // Use canonicalize on both paths to resolve any symlinks or relative components
    let canonical_root = match root.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            error!("Failed to canonicalize root directory: {:?}", root);
            return None;
        }
    };
    
    match path.canonicalize() {
        Ok(canonical_path) => {
            if canonical_path.starts_with(&canonical_root) {
                Some(canonical_path)
            } else {
                warn!("Path escape attempt: {:?} is not under {:?}", canonical_path, canonical_root);
                None
            }
        }
        Err(_) => {
            warn!("Failed to canonicalize file path: {:?}", path);
            None
        }
    }
}

/// Check if a decoded path contains directory traversal patterns
fn is_directory_traversal_attempt(path: &str) -> bool {
    // Check for various directory traversal patterns
    let traversal_patterns = [
        "..",           // Basic parent directory
        ".\\..",        // Windows style
        "../",          // With slash
        "..\\",         // Windows with backslash
        "%2e%2e",       // URL encoded (should be caught by iterative decoding)
        "..\x00",       // Null byte injection
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
       path.contains("\u{2024}\u{2024}") {  // One dot leader
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
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
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
    // Read file metadata
    let metadata = fs::metadata(path).await?;
    
    // Check file size (optional: add a maximum file size limit)
    const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB
    if metadata.len() > MAX_FILE_SIZE {
        warn!("File too large: {} bytes", metadata.len());
        response::send_temporary_failure(stream, "File too large").await?;
        return Ok(());
    }
    
    // Read file content
    let content = match fs::read(path).await {
        Ok(content) => content,
        Err(e) => {
            error!("Failed to read file {}: {}", path.display(), e);
            response::send_temporary_failure(stream, "Failed to read file").await?;
            return Ok(());
        }
    };
    
    // Detect MIME type
    let mime_type = mime::get_mime_type(path);
    debug!("Serving {} with MIME type: {}", path.display(), mime_type);
    
    // Send response
    response::send_file(stream, mime_type, content).await?;
    
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
}