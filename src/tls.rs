use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

/// Generate a self-signed certificate for the given hostname
pub fn generate_self_signed_cert(
    hostname: &str,
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::new(vec![hostname.to_string()])?;

    // Set the subject name
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, hostname);
    params.distinguished_name = distinguished_name;

    // Generate key pair and certificate
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    // Write certificate to file
    let mut cert_file = File::create(cert_path)?;
    cert_file.write_all(cert.pem().as_bytes())?;

    // Write private key to file
    let mut key_file = File::create(key_path)?;
    key_file.write_all(key_pair.serialize_pem().as_bytes())?;

    Ok(())
}

/// Load TLS acceptor from certificate and key files
pub fn load_tls_acceptor(
    cert_path: &Path,
    key_path: &Path,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    // Load certificate
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);

    // rustls-pemfile 2.0 returns an iterator of Results
    let cert_chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    if cert_chain.is_empty() {
        return Err("No certificates found in file".into());
    }

    // Load private key
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);

    // rustls-pemfile 2.0 returns an iterator of Results for keys too, but we need to find the first private key
    let private_key =
        rustls_pemfile::private_key(&mut key_reader)?.ok_or("No private keys found in file")?;

    // Convert to PrivateKeyDer (rustls-pemfile returns PrivateKeyDer directly now)
    let key: PrivateKeyDer<'static> = private_key;

    // Build server config
    // rustls 0.23: with_safe_defaults() is removed, defaults are safer by default
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    debug!("TLS configuration loaded successfully");

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Check if certificate files exist
pub fn cert_files_exist(cert_path: &Path, key_path: &Path) -> bool {
    cert_path.exists() && key_path.exists()
}

/// Validate that certificate and key files can be loaded
pub fn validate_cert_files(cert_path: &Path, key_path: &Path) -> Result<(), String> {
    if !cert_path.exists() {
        return Err(format!(
            "Certificate file not found: {}",
            cert_path.display()
        ));
    }

    if !key_path.exists() {
        return Err(format!("Key file not found: {}", key_path.display()));
    }

    // Try to load the files to ensure they're valid
    match load_tls_acceptor(cert_path, key_path) {
        Ok(_) => {
            info!("Certificate files validated successfully");
            Ok(())
        }
        Err(e) => Err(format!("Invalid certificate files: {}", e)),
    }
}
