use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::debug;

/// Gemini status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    Success = 20,
    TemporaryFailure = 40,
    NotFound = 51,
    BadRequest = 59,
}

impl StatusCode {
    /// Get the numeric code
    pub fn code(&self) -> u8 {
        *self as u8
    }

    /// Get default meta text for status codes that don't require specific meta
    pub fn default_meta(&self) -> &'static str {
        match self {
            StatusCode::Success => "text/gemini; charset=utf-8",
            StatusCode::TemporaryFailure => "Temporary failure",
            StatusCode::NotFound => "Not found",
            StatusCode::BadRequest => "Bad request",
        }
    }
}

/// Gemini response builder
pub struct Response {
    status: StatusCode,
    meta: String,
    body: Option<Vec<u8>>,
}

impl Response {
    /// Create a new response with status and meta
    pub fn new(status: StatusCode, meta: impl Into<String>) -> Self {
        let meta = meta.into();
        // Sanitize meta to prevent header injection
        // Remove CR and LF characters
        let sanitized_meta = meta.replace('\r', "").replace('\n', "");

        Self {
            status,
            meta: sanitized_meta,
            body: None,
        }
    }

    /// Create a success response with content
    pub fn success(mime_type: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            status: StatusCode::Success,
            meta: mime_type.into(),
            body: Some(body),
        }
    }

    /// Create a not found response
    pub fn not_found() -> Self {
        Self::new(StatusCode::NotFound, StatusCode::NotFound.default_meta())
    }

    /// Create a bad request response
    pub fn bad_request() -> Self {
        Self::new(
            StatusCode::BadRequest,
            StatusCode::BadRequest.default_meta(),
        )
    }

    /// Create a temporary failure response
    pub fn temporary_failure(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::TemporaryFailure, reason)
    }

    /// Write the response to the stream
    pub async fn write_to<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<(), std::io::Error> {
        self.write_header(stream).await?;

        // Write body if present (only for success responses)
        if let Some(body) = &self.body {
            if self.status == StatusCode::Success {
                stream.write_all(body).await?;
            }
        }

        // Flush to ensure all data is sent
        stream.flush().await?;

        Ok(())
    }

    /// Write only the response header to the stream
    pub async fn write_header<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<(), std::io::Error> {
        // Write status line: <STATUS><SPACE><META><CR><LF>
        let header = format!("{} {}\r\n", self.status.code(), self.meta);
        debug!("Sending response: {}", header.trim());
        stream.write_all(header.as_bytes()).await?;
        Ok(())
    }
}

/// Helper function to send a not found response
pub async fn send_not_found<W: AsyncWrite + Unpin>(stream: &mut W) -> Result<(), std::io::Error> {
    let response = Response::not_found();
    response.write_to(stream).await
}

/// Helper function to send a bad request response
pub async fn send_bad_request<W: AsyncWrite + Unpin>(stream: &mut W) -> Result<(), std::io::Error> {
    let response = Response::bad_request();
    response.write_to(stream).await
}

/// Helper function to send a temporary failure response
pub async fn send_temporary_failure<W: AsyncWrite + Unpin>(
    stream: &mut W,
    reason: &str,
) -> Result<(), std::io::Error> {
    let response = Response::temporary_failure(reason);
    response.write_to(stream).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_success_response() {
        let mut buffer = Vec::new();
        let response = Response::success("text/plain", b"Hello, world!".to_vec());
        response.write_to(&mut buffer).await.unwrap();

        let result = String::from_utf8(buffer).unwrap();
        assert_eq!(result, "20 text/plain\r\nHello, world!");
    }

    #[tokio::test]
    async fn test_not_found_response() {
        let mut buffer = Vec::new();
        let response = Response::not_found();
        response.write_to(&mut buffer).await.unwrap();

        let result = String::from_utf8(buffer).unwrap();
        assert_eq!(result, "51 Not found\r\n");
    }

    #[tokio::test]
    async fn test_header_sanitization() {
        let response = Response::new(StatusCode::TemporaryFailure, "Error\r\nInjection");
        let mut buffer = Vec::new();
        response.write_header(&mut buffer).await.unwrap();

        let result = String::from_utf8(buffer).unwrap();
        assert_eq!(result, "40 ErrorInjection\r\n");
    }
}
