use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info};

mod mime;
mod request;
mod response;
mod server;
mod tls;

#[derive(Parser, Debug)]
#[command(author, version, about = "A minimal Gemini Protocol server", long_about = None)]
struct Args {
    /// Root directory to serve files from
    #[arg(short, long, default_value = ".")]
    root: PathBuf,

    /// Port to listen on
    #[arg(short, long, default_value = "1965")]
    port: u16,

    /// TLS certificate file
    #[arg(long, default_value = "cert.pem")]
    cert: PathBuf,

    /// TLS key file
    #[arg(long, default_value = "key.pem")]
    key: PathBuf,

    /// Generate self-signed certificate and exit
    #[arg(long)]
    generate_cert: bool,

    /// Hostname for the server
    #[arg(long, default_value = "localhost")]
    hostname: String,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    let log_level = args.log_level.parse::<tracing::Level>()
        .unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt::fmt()
        .with_max_level(log_level)
        .init();

    info!("Starting Gemini server v{}", env!("CARGO_PKG_VERSION"));

    // Handle certificate generation
    if args.generate_cert {
        info!("Generating self-signed certificate for hostname: {}", args.hostname);
        match tls::generate_self_signed_cert(&args.hostname, &args.cert, &args.key) {
            Ok(_) => {
                info!("Certificate generated successfully!");
                info!("Certificate written to: {}", args.cert.display());
                info!("Private key written to: {}", args.key.display());
                return Ok(());
            }
            Err(e) => {
                error!("Failed to generate certificate: {}", e);
                return Err(e);
            }
        }
    }

    // Validate root directory
    if !args.root.exists() {
        error!("Root directory does not exist: {}", args.root.display());
        return Err("Root directory not found".into());
    }

    if !args.root.is_dir() {
        error!("Root path is not a directory: {}", args.root.display());
        return Err("Root path must be a directory".into());
    }

    // Get canonical path for root directory
    let root = args.root.canonicalize()?;
    info!("Serving files from: {}", root.display());

    // Start the server
    info!("Starting server on {}:{}", args.hostname, args.port);
    
    match server::run_server(
        args.hostname,
        args.port,
        args.cert,
        args.key,
        root,
    ).await {
        Ok(_) => {
            info!("Server stopped gracefully");
            Ok(())
        }
        Err(e) => {
            error!("Server error: {}", e);
            Err(e)
        }
    }
}
