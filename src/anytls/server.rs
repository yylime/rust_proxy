//! AnyTLS server entrypoint: TCP listener + TLS accept + auth + session.
//!
//! Ported from shoes (src/anytls/anytls_server_handler.rs and
//! src/tls_server_handler.rs), simplified for direct-connect routing.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use crate::address::NetLocation;
use crate::anytls::padding::PaddingFactory;
use crate::anytls::session::AnyTlsSession;
use crate::async_stream::AsyncStream;
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tls_config::TlsMaterial;
use crate::util::write_all;

use aws_lc_rs::digest::{SHA256, digest};

/// AnyTLS server configuration (runtime, translated from YAML config).
pub struct AnyTlsServerConfig {
    pub listen: String,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub udp_enabled: bool,
    /// (name, password) pairs for authentication.
    pub users: Vec<(String, String)>,
    pub padding_scheme: Option<String>,
    /// Optional fallback destination for failed authentication.
    pub fallback: Option<NetLocation>,
}

struct AnyTlsServerHandler {
    /// Authenticated users (password_hash -> user name)
    users: HashMap<[u8; 32], String>,
    /// 8-byte prefixes of all user password hashes for quick fallback.
    hash_prefixes: HashSet<[u8; 8]>,
    /// Padding factory for traffic obfuscation
    padding: Arc<PaddingFactory>,
    /// Resolver for destination addresses
    resolver: Arc<Resolver>,
    /// UDP enabled for UoT support
    udp_enabled: bool,
    /// Fallback destination for failed authentication
    fallback: Option<NetLocation>,
}

impl AnyTlsServerHandler {
    fn new(
        users: Vec<(String, String)>,
        padding: Arc<PaddingFactory>,
        resolver: Arc<Resolver>,
        udp_enabled: bool,
        fallback: Option<NetLocation>,
    ) -> Self {
        let mut user_map = HashMap::with_capacity(users.len());
        let mut hash_prefixes = HashSet::with_capacity(users.len());

        for (name, password) in users {
            let hash_result = digest(&SHA256, password.as_bytes());
            let mut password_hash = [0u8; 32];
            password_hash.copy_from_slice(hash_result.as_ref());

            let prefix: [u8; 8] = password_hash[..8].try_into().unwrap();
            hash_prefixes.insert(prefix);

            user_map.insert(password_hash, name);
        }

        Self {
            users: user_map,
            hash_prefixes,
            padding,
            resolver,
            udp_enabled,
            fallback,
        }
    }

    /// Authenticate the client and run the AnyTLS session.
    ///
    /// Equivalent to shoes' `AnyTlsServerHandler::setup_server_stream`
    /// followed by `AnyTlsSession::run`.
    async fn handle_connection(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<()> {
        let mut reader = StreamReader::new();

        // Peek at the 8-byte prefix for quick fallback (see shoes for the
        // timing-side-channel rationale: enumerating 2^64 prefixes is
        // infeasible).
        let prefix_data = reader.peek_slice(&mut server_stream, 8).await?;
        if !self.hash_prefixes.contains(prefix_data) {
            log::debug!("AnyTLS quick fallback: 8-byte prefix doesn't match any user");
            if let Some(ref fallback) = self.fallback {
                return self.fallback_to_dest(server_stream, reader, fallback).await;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "authentication failed (prefix mismatch)",
            ));
        }

        let auth_data = reader.peek_slice(&mut server_stream, 32).await?;
        let user_name = match self.users.get(auth_data) {
            Some(name) => {
                log::debug!("AnyTLS user authenticated: {name}");
                reader.consume(32);
                name.clone()
            }
            None => {
                log::debug!("AnyTLS authentication failed: unknown password");
                if let Some(ref fallback) = self.fallback {
                    return self.fallback_to_dest(server_stream, reader, fallback).await;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "authentication failed",
                ));
            }
        };

        let padding_len = reader.read_u16_be(&mut server_stream).await?;
        if padding_len > 0 {
            let _ = reader
                .read_slice(&mut *server_stream, padding_len as usize)
                .await?;
        }

        let initial_data = reader.unparsed_data_owned();

        let session = AnyTlsSession::new_server_with_initial_data(
            server_stream,
            Arc::clone(&self.padding),
            Arc::clone(&self.resolver),
            self.udp_enabled,
            user_name,
            initial_data,
        );

        session.run().await
    }

    /// Forward the connection to a fallback destination when authentication
    /// fails, making the server indistinguishable from a legitimate server.
    async fn fallback_to_dest(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        reader: StreamReader,
        fallback: &NetLocation,
    ) -> std::io::Result<()> {
        log::debug!("AnyTLS FALLBACK: Connecting to fallback: {fallback}");

        let unconsumed_data = reader.unparsed_data();
        let dest_addr = self.resolver.resolve(fallback).await?;

        let mut dest_stream = TcpStream::connect(dest_addr).await?;
        dest_stream.set_nodelay(true).ok();

        if !unconsumed_data.is_empty() {
            write_all(&mut dest_stream, unconsumed_data).await?;
            dest_stream.flush().await?;
        }

        log::debug!(
            "AnyTLS FALLBACK: Connected to fallback, forwarding {} bytes",
            unconsumed_data.len()
        );

        let mut dest_stream: Box<dyn AsyncStream> = Box::new(dest_stream);
        let result = crate::copy_bidirectional::copy_bidirectional(
            &mut *client_stream,
            &mut *dest_stream,
            false,
            false,
        )
        .await;

        let _ = client_stream.shutdown().await;
        let _ = dest_stream.shutdown().await;

        if let Err(e) = &result {
            log::debug!("AnyTLS FALLBACK: Connection ended: {e}");
        } else {
            log::debug!("AnyTLS FALLBACK: Connection completed");
        }

        result
    }
}

/// Start the AnyTLS server: binds the TCP listener, accepts TLS connections
/// and handles each in a spawned task.
pub async fn run_server(
    config: AnyTlsServerConfig,
    resolver: Arc<Resolver>,
) -> std::io::Result<JoinHandle<()>> {
    let bind_address: SocketAddr = config
        .listen
        .parse()
        .map_err(|e| std::io::Error::other(format!("invalid listen address '{}': {e}", config.listen)))?;

    let tls_material = TlsMaterial::from_files(
        config.cert.as_deref(),
        config.key.as_deref(),
        "anytls",
    )?;
    let acceptor = tls_material.acceptor();

    let padding = match config.padding_scheme {
        Some(scheme) => match PaddingFactory::new(scheme.as_bytes()) {
            Ok(factory) => Arc::new(factory),
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "invalid padding scheme: {e}"
                )));
            }
        },
        None => PaddingFactory::default_factory(),
    };

    let handler = Arc::new(AnyTlsServerHandler::new(
        config.users,
        padding,
        resolver,
        config.udp_enabled,
        config.fallback,
    ));

    let listener = crate::socket_util::new_tcp_listener(bind_address, 4096)?;
    log::info!("AnyTLS server listening on {bind_address}");

    Ok(tokio::spawn(async move {
        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::error!("AnyTLS accept failed: {e}");
                    continue;
                }
            };

            if let Err(e) = crate::socket_util::set_tcp_keepalive(
                &stream,
                std::time::Duration::from_secs(300),
                std::time::Duration::from_secs(60),
            ) {
                log::error!("Failed to set TCP keepalive: {e}");
            }
            if let Err(e) = stream.set_nodelay(true) {
                log::error!("Failed to set TCP nodelay: {e}");
            }

            let acceptor = acceptor.clone();
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        log::debug!("AnyTLS TLS handshake failed from {addr}: {e}");
                        return;
                    }
                };

                if let Err(e) = handler
                    .handle_connection(Box::new(tls_stream))
                    .await
                {
                    log::debug!("AnyTLS connection from {addr} ended: {e}");
                }
            });
        }
    }))
}
