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
    let decoded_path = urlencoding::decode(request_path.trim_start_matches('/')).ok()?;
    
    // Prevent directory traversal attacks
    if decoded_path.contains("..") {
        warn!("Directory traversal attempt: {}", decoded_path);
        return None;
    }
    
    // Join with root directory
    let mut path = root.join(decoded_path.as_ref());
    
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
    
    // Ensure the resolved path is still under the root directory
    match path.canonicalize() {
        Ok(canonical_path) => {
            if canonical_path.starts_with(root) {
                Some(canonical_path)
            } else {
                warn!("Path escape attempt: {:?}", canonical_path);
                None
            }
        }
        Err(_) => None,
    }
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