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

    /// Address to bind the server to
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// TLS certificate file
    #[arg(long, default_value = "cert.pem")]
    cert: PathBuf,

    /// TLS key file
    #[arg(long, default_value = "key.pem")]
    key: PathBuf,

    /// Generate self-signed certificate and exit
    #[arg(long)]
    generate_cert: bool,

    /// Hostname(s) the server answers for. May be specified multiple times.
    /// Defaults to "localhost" when none are provided.
    #[arg(long = "hostname")]
    hostnames: Vec<String>,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = Args::parse();

    // clap's `default_value` does not work cleanly with `Vec`, so default an
    // empty hostnames vec to ["localhost"] here.
    if args.hostnames.is_empty() {
        args.hostnames = vec!["localhost".to_string()];
    }

    // Initialize logging
    let log_level = args.log_level.parse::<tracing::Level>()
        .unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt::fmt()
        .with_max_level(log_level)
        .init();

    info!("Starting Gemini server v{}", env!("CARGO_PKG_VERSION"));

    // Handle certificate generation
    if args.generate_cert {
        info!(
            "Generating self-signed certificate for hostnames: {}",
            args.hostnames.join(", ")
        );
        match tls::generate_self_signed_cert(&args.hostnames, &args.cert, &args.key) {
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
    info!(
        "Starting server on {}:{} (hostnames: {})",
        args.host,
        args.port,
        args.hostnames.join(", ")
    );

    match server::run_server(
        args.hostnames,
        args.host,
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
