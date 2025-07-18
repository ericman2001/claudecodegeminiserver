# GEMINI.md

This file provides guidance to Gemini when working with code in this repository.

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
- Uses `rcgen` 0.14+ for secure TLS certificate generation
- Enforces comprehensive security through robust path validation and size limits
- Implements only essential Gemini status codes (20, 40, 51, 59)
- Automatic index.gmi serving for directories
- Defense-in-depth security approach with multiple validation layers

## Changelog

- **2025-07-17:** Patched a Time-of-Check-to-Time-of-Use (TOCTOU) vulnerability in the `serve_file` function. The function was refactored to open a file handle and perform all subsequent operations (metadata check, reading) on that handle. This prevents a race condition where the file could be swapped with a symbolic link to a sensitive file after validation.

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

# Security audit for dependencies
cargo audit

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
