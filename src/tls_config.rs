//! TLS certificate loading and rustls server configuration.
//!
//! Supports PEM certificate chains + private keys (RSA/ECDSA). When
//! `cert`/`key` are not configured, a self-signed certificate is generated
//! in memory at startup (useful for testing; use a real certificate on a
//! production server).

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

pub struct TlsMaterial {
    pub server_config: Arc<ServerConfig>,
    pub alpn: Vec<Vec<u8>>,
}

impl TlsMaterial {
    /// Build a rustls `ServerConfig` from PEM files (or a generated
    /// self-signed certificate when `cert`/`key` are `None`).
    ///
    /// `sni_name` is used as the Common Name / SAN for generated certs.
    pub fn from_files(
        cert_path: Option<&str>,
        key_path: Option<&str>,
        sni_name: &str,
    ) -> std::io::Result<Self> {
        let (certs, key) = match (cert_path, key_path) {
            (Some(cert_path), Some(key_path)) => load_cert_and_key(cert_path, key_path)?,
            (None, None) => {
                log::warn!(
                    "No cert/key configured for {sni_name}: generating a self-signed \
                     certificate in memory (not suitable for production)"
                );
                generate_self_signed(sni_name)?
            }
            _ => {
                return Err(std::io::Error::other(
                    "cert and key must either both be configured or both omitted",
                ));
            }
        };

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| std::io::Error::other(format!("TLS version config: {e}")))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| std::io::Error::other(format!("invalid certificate/key: {e}")))?;

        Ok(Self {
            server_config: Arc::new(server_config),
            alpn: Vec::new(),
        })
    }

    /// Set the ALPN protocols (must be called before `into_quic`/`acceptor`
    /// if ALPN is needed).
    pub fn with_alpn(mut self, alpn: &[String]) -> Self {
        let alpn: Vec<Vec<u8>> = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        Arc::get_mut(&mut self.server_config).unwrap().alpn_protocols = alpn.clone();
        self.alpn = alpn;
        self
    }

    /// Build a QUIC (QUIC-validated) server config for Hysteria2.
    pub fn into_quic(self) -> std::io::Result<Arc<quinn::crypto::rustls::QuicServerConfig>> {
        let config: quinn::crypto::rustls::QuicServerConfig = Arc::try_unwrap(self.server_config)
            .map_err(|_| {
                std::io::Error::other("server config is still shared (QUIC conversion failed)")
            })?
            .try_into()
            .map_err(|e| std::io::Error::other(format!("invalid QUIC server config: {e}")))?;
        Ok(Arc::new(config))
    }

    /// Build a TLS acceptor for AnyTLS.
    pub fn acceptor(self) -> tokio_rustls::TlsAcceptor {
        tokio_rustls::TlsAcceptor::from(self.server_config)
    }
}

fn load_cert_and_key(
    cert_path: &str,
    key_path: &str,
) -> std::io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_file = File::open(cert_path).map_err(|e| {
        std::io::Error::new(e.kind(), format!("failed to open cert file {cert_path}: {e}"))
    })?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(cert_file))
            .collect::<Result<_, _>>()
            .map_err(|e| {
                std::io::Error::other(format!("failed to parse cert file {cert_path}: {e}"))
            })?;
    if certs.is_empty() {
        return Err(std::io::Error::other(format!(
            "no certificates found in {cert_path}"
        )));
    }

    let key_file = File::open(key_path).map_err(|e| {
        std::io::Error::new(e.kind(), format!("failed to open key file {key_path}: {e}"))
    })?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| {
            std::io::Error::other(format!("failed to parse key file {key_path}: {e}"))
        })?
        .ok_or_else(|| {
            std::io::Error::other(format!("no private key found in {key_path}"))
        })?;

    Ok((certs, key))
}

fn generate_self_signed(sni_name: &str) -> std::io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    let key_pair = KeyPair::generate()
        .map_err(|e| std::io::Error::other(format!("failed to generate key: {e}")))?;

    let mut params = CertificateParams::new(vec![sni_name.to_string()])
        .map_err(|e| std::io::Error::other(format!("cert params: {e}")))?;
    params.is_ca = IsCa::NoCa;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, sni_name);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| std::io::Error::other(format!("failed to self-sign cert: {e}")))?;

    let cert_der: CertificateDer<'static> = cert.der().clone().into();
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|_| std::io::Error::other("failed to serialize generated key"))?;

    Ok((vec![cert_der], key_der))
}
