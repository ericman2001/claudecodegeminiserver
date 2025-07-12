# Gemini Server

A minimal Gemini Protocol server written in Rust. This server provides static file serving with TLS support, implementing the core features of the Gemini protocol.

## Features

- **Static file serving** from a configurable root directory
- **TLS 1.2+ support** with self-signed certificate generation
- **Proper MIME type detection** for common file formats
- **Security features** including path traversal prevention
- **Request validation** with 1024 byte limit
- **Standard Gemini status codes** (20, 40, 51, 59)
- **Automatic index.gmi serving** for directories
- **Configurable logging levels**

## Installation

### Prerequisites

- Rust 1.70 or later
- OpenSSL development libraries (for certificate generation)

### Building from source

```bash
git clone https://github.com/ericman2001/claudecodegeminiserver.git
cd claudecodegeminiserver
cargo build --release
```

The binary will be available at `target/release/gemini-server`.

## Usage

### Quick Start

1. Generate a self-signed certificate:
```bash
gemini-server --generate-cert
```

2. Start the server (serves current directory on port 1965):
```bash
gemini-server
```

3. Test with a Gemini client:
```bash
# Using a Gemini client like gmni or amfora
gmni gemini://localhost/
```

### Command Line Options

```
gemini-server [OPTIONS]

OPTIONS:
    -r, --root <ROOT>              Root directory to serve files from [default: .]
    -p, --port <PORT>              Port to listen on [default: 1965]
        --cert <CERT>              TLS certificate file [default: cert.pem]
        --key <KEY>                TLS key file [default: key.pem]
        --generate-cert            Generate self-signed certificate and exit
        --hostname <HOSTNAME>      Hostname for the server [default: localhost]
        --log-level <LOG_LEVEL>    Log level (error, warn, info, debug, trace) [default: info]
    -h, --help                     Print help
    -V, --version                  Print version
```

### Examples

Serve a specific directory:
```bash
gemini-server --root /path/to/gemini/capsule
```

Run on a different port:
```bash
gemini-server --port 1966 --root ./content
```

Use existing certificates:
```bash
gemini-server --cert /path/to/cert.pem --key /path/to/key.pem
```

Enable debug logging:
```bash
gemini-server --log-level debug
```

## File Organization

The server serves files from the specified root directory. Here's a typical Gemini capsule structure:

```
my-capsule/
├── index.gmi          # Homepage
├── about.gmi          # About page
├── posts/
│   ├── index.gmi      # Posts listing
│   ├── first-post.gmi
│   └── second-post.gmi
└── images/
    └── logo.png
```

### URL Mapping

- `gemini://localhost/` → `./index.gmi`
- `gemini://localhost/about` → `./about.gmi`
- `gemini://localhost/posts/` → `./posts/index.gmi`
- `gemini://localhost/posts/first-post.gmi` → `./posts/first-post.gmi`

## Security Considerations

- **Comprehensive directory traversal protection**: Prevents all known traversal techniques including:
  - Basic traversal (`../../../etc/passwd`)
  - URL encoded traversal (`%2e%2e/etc/passwd`)
  - Double URL encoded traversal (`%252e%252e/etc/passwd`)
  - Windows-style traversal (`..\..\..\etc\passwd`)
  - Null byte injection (`file.gmi\0../../../etc/passwd`)
  - Unicode normalization attacks
- **Secure path validation ordering**: Validates path containment before filesystem operations to prevent information leakage
- **Robust path normalization**: Handles mixed separators, multiple slashes, and various encoding schemes
- Only regular files are served (no device files, sockets, etc.)
- File size limit of 10MB per file
- Request size limited to 1024 bytes per Gemini specification
- TLS-only connections (no plaintext option)
- Iterative URL decoding to prevent encoding bypass attacks

## Development

### Running tests
```bash
cargo test
```

### Building documentation
```bash
cargo doc --open
```

### Code formatting
```bash
cargo fmt
```

### Linting
```bash
cargo clippy
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- The Gemini Protocol specification: https://gemini.circumlunar.space/
- Rust async ecosystem: tokio, rustls, and related crates