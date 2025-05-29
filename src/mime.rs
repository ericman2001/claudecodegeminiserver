use std::path::Path;

/// Detect MIME type based on file extension
pub fn get_mime_type(path: &Path) -> &'static str {
    match path.extension().and_then(|s| s.to_str()) {
        // Gemini files
        Some("gmi") | Some("gemini") => "text/gemini; charset=utf-8",
        
        // Text files
        Some("txt") => "text/plain; charset=utf-8",
        Some("md") => "text/markdown; charset=utf-8",
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("xml") => "text/xml; charset=utf-8",
        
        // Images
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        
        // Audio
        Some("mp3") => "audio/mpeg",
        Some("ogg") => "audio/ogg",
        Some("wav") => "audio/wav",
        Some("flac") => "audio/flac",
        
        // Video
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("ogv") => "video/ogg",
        
        // Documents
        Some("pdf") => "application/pdf",
        Some("doc") | Some("docx") => "application/msword",
        Some("odt") => "application/vnd.oasis.opendocument.text",
        
        // Archives
        Some("zip") => "application/zip",
        Some("tar") => "application/x-tar",
        Some("gz") => "application/gzip",
        Some("bz2") => "application/x-bzip2",
        Some("7z") => "application/x-7z-compressed",
        
        // Default
        _ => "application/octet-stream",
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_gemini_files() {
        assert_eq!(get_mime_type(Path::new("index.gmi")), "text/gemini; charset=utf-8");
        assert_eq!(get_mime_type(Path::new("page.gemini")), "text/gemini; charset=utf-8");
    }
    
    #[test]
    fn test_image_files() {
        assert_eq!(get_mime_type(Path::new("photo.jpg")), "image/jpeg");
        assert_eq!(get_mime_type(Path::new("icon.png")), "image/png");
        assert_eq!(get_mime_type(Path::new("animation.gif")), "image/gif");
    }
    
    #[test]
    fn test_unknown_extension() {
        assert_eq!(get_mime_type(Path::new("file.xyz")), "application/octet-stream");
        assert_eq!(get_mime_type(Path::new("noextension")), "application/octet-stream");
    }
}