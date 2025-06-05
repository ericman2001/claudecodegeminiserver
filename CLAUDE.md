# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

gemini-server - A minimal Gemini Protocol server written in Rust that serves static files over TLS.

## Architecture

The server is organized into modular components:

- `main.rs` - CLI interface and server initialization
- `server.rs` - Core server loop, connection handling, and file serving logic
- `tls.rs` - TLS certificate generation and configuration
- `request.rs` - Gemini request parsing with validation
- `response.rs` - Response building with standard Gemini status codes
- `mime.rs` - MIME type detection for file serving

Key architectural decisions:
- Uses `tokio` for async I/O and `rustls` for TLS
- Enforces security through path validation and size limits
- Implements only essential Gemini status codes (20, 40, 51, 59)
- Automatic index.gmi serving for directories

## Development Commands

```bash
# Build the project
cargo build --release

# Run tests
cargo test

# Check code without building
cargo check

# Format code
cargo fmt

# Run linter
cargo clippy

# Generate and serve with self-signed cert
cargo run -- --generate-cert
cargo run -- --root ./test-content

# Run with debug logging
cargo run -- --log-level debug
```

## Testing

Create test content:
```bash
mkdir test-content
echo "# Welcome to Gemini" > test-content/index.gmi
```

Test with a Gemini client:
```bash
# Using gmni or similar
gmni gemini://localhost/
```