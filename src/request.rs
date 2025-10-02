use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::time::timeout;
use tracing::{debug, warn};
use url::Url;

const MAX_REQUEST_SIZE: usize = 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct GeminiRequest {
    pub url: Url,
    pub path: String,
}

impl GeminiRequest {
    /// Parse a Gemini request from the input stream
    pub async fn from_stream<R: AsyncRead + Unpin>(
        stream: R,
    ) -> Result<Self, RequestError> {
        let reader = BufReader::new(stream);
        let mut line = String::new();

        // Limit the reader to prevent OOM attacks
        let mut limited_reader = reader.take(MAX_REQUEST_SIZE as u64 + 1);

        // Read request with timeout
        let bytes_read = match timeout(REQUEST_TIMEOUT, limited_reader.read_line(&mut line)).await {
            Ok(Ok(0)) => return Err(RequestError::EmptyRequest),
            Ok(Ok(bytes_read)) => {
                debug!("Read {} bytes from request", bytes_read);
                bytes_read
            }
            Ok(Err(e)) => return Err(RequestError::IoError(e)),
            Err(_) => return Err(RequestError::Timeout),
        };

        // Check if the request is too large. This is now safe because we limited the read.
        if bytes_read > MAX_REQUEST_SIZE || !line.ends_with('\n') {
            warn!("Request exceeds size limit or is malformed");
            return Err(RequestError::TooLarge);
        }
        
        // Remove CRLF or LF
        let request = line.trim_end_matches("\r\n").trim_end_matches('\n');
        
        if request.is_empty() {
            return Err(RequestError::EmptyRequest);
        }
        
        debug!("Raw request: {}", request);
        
        // Parse URL
        let url = match Url::parse(request) {
            Ok(url) => url,
            Err(e) => {
                warn!("Failed to parse URL: {}", e);
                return Err(RequestError::InvalidUrl(e.to_string()));
            }
        };
        
        // Validate scheme
        if url.scheme() != "gemini" {
            warn!("Invalid scheme: {}", url.scheme());
            return Err(RequestError::InvalidScheme(url.scheme().to_string()));
        }
        
        // Extract path
        let path = url.path().to_string();
        
        Ok(GeminiRequest { url, path })
    }
    
    /// Get the hostname from the request
    pub fn hostname(&self) -> Option<&str> {
        self.url.host_str()
    }
    
    /// Check if the request matches the expected hostname
    pub fn matches_hostname(&self, expected: &str) -> bool {
        self.hostname() == Some(expected)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("Empty request")]
    EmptyRequest,
    
    #[error("Request too large")]
    TooLarge,
    
    #[error("Request timeout")]
    Timeout,
    
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    
    #[error("Invalid scheme: {0}")]
    InvalidScheme(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    
    #[tokio::test]
    async fn test_valid_request() {
        let (reader, mut writer) = tokio::io::duplex(1024);
        
        tokio::spawn(async move {
            writer.write_all(b"gemini://localhost/test.gmi\r\n").await.unwrap();
        });
        
        let request = GeminiRequest::from_stream(reader).await.unwrap();
        assert_eq!(request.path, "/test.gmi");
        assert_eq!(request.hostname(), Some("localhost"));
    }
    
    #[tokio::test]
    async fn test_request_too_large() {
        let (reader, mut writer) = tokio::io::duplex(2048);
        
        tokio::spawn(async move {
            let large_url = format!("gemini://localhost/{}\r\n", "x".repeat(2000));
            writer.write_all(large_url.as_bytes()).await.unwrap();
        });
        
        let result = GeminiRequest::from_stream(reader).await;
        assert!(matches!(result, Err(RequestError::TooLarge)));
    }
}