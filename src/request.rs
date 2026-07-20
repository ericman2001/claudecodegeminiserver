use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::time::timeout;
use tracing::{debug, warn};
use url::Url;

const MAX_REQUEST_SIZE: usize = 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Default port for the Gemini protocol when none is specified in the request URL.
pub const DEFAULT_GEMINI_PORT: u16 = 1965;

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

    /// Get the effective port for the request.
    ///
    /// An omitted port means the default Gemini port (1965), NOT "no port".
    /// `Url::port_or_known_default()` is intentionally avoided because the
    /// `url` crate does not know Gemini's default and returns `None` for
    /// `gemini://`, so we fall back to 1965 explicitly.
    pub fn port(&self) -> u16 {
        self.url.port().unwrap_or(DEFAULT_GEMINI_PORT)
    }

    /// Check if the request hostname matches one of the served hostnames
    /// (case-insensitive).
    pub fn matches_hostname(&self, hostnames: &[String]) -> bool {
        match self.hostname() {
            Some(host) => hostnames
                .iter()
                .any(|h| h.eq_ignore_ascii_case(host)),
            None => false,
        }
    }

    /// Check if the request authority (hostname and port) is served.
    ///
    /// Returns true only if the hostname matches one of `hostnames`
    /// (case-insensitive) AND the effective port equals `served_port`.
    pub fn matches_authority(&self, hostnames: &[String], served_port: u16) -> bool {
        self.matches_hostname(hostnames) && self.port() == served_port
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

    fn request_from(url: &str) -> GeminiRequest {
        let url = Url::parse(url).unwrap();
        let path = url.path().to_string();
        GeminiRequest { url, path }
    }

    #[test]
    fn test_matches_authority_hostname() {
        let served = vec!["example.com".to_string(), "alt.example".to_string()];

        // Direct match
        assert!(request_from("gemini://example.com/").matches_authority(&served, 1965));
        // Second served hostname
        assert!(request_from("gemini://alt.example/").matches_authority(&served, 1965));
        // Case-insensitive match
        assert!(request_from("gemini://EXAMPLE.COM/").matches_authority(&served, 1965));
        // Non-matching hostname
        assert!(!request_from("gemini://other.com/").matches_authority(&served, 1965));
    }

    #[test]
    fn test_port_defaulting() {
        // Omitted port defaults to 1965
        assert_eq!(request_from("gemini://localhost/x").port(), DEFAULT_GEMINI_PORT);
        assert_eq!(request_from("gemini://localhost/x").port(), 1965);
        // Explicit port is respected
        assert_eq!(request_from("gemini://localhost:1966/x").port(), 1966);
        assert_eq!(request_from("gemini://localhost:1965/x").port(), 1965);
    }

    #[test]
    fn test_matches_authority_port() {
        let served = vec!["localhost".to_string()];

        // Omitted port matches served default port
        assert!(request_from("gemini://localhost/x").matches_authority(&served, 1965));
        // Explicit default port matches served default port
        assert!(request_from("gemini://localhost:1965/x").matches_authority(&served, 1965));

        // Non-default port: refused against served 1965, accepted against served 1966
        assert!(!request_from("gemini://localhost:1966/x").matches_authority(&served, 1965));
        assert!(request_from("gemini://localhost:1966/x").matches_authority(&served, 1966));
    }

    #[test]
    fn test_matches_authority_both_dimensions_enforced() {
        let served = vec!["example.com".to_string()];

        // Right host, wrong port
        assert!(!request_from("gemini://example.com:1966/x").matches_authority(&served, 1965));
        // Wrong host, right port
        assert!(!request_from("gemini://other.com:1965/x").matches_authority(&served, 1965));
        // Wrong host AND wrong port
        assert!(!request_from("gemini://other.com:1966/x").matches_authority(&served, 1965));
        // Right host AND right port
        assert!(request_from("gemini://example.com:1965/x").matches_authority(&served, 1965));
    }
}