//! Direct-connect helpers for the server.

use std::sync::Arc;

use tokio::net::{TcpStream, UdpSocket};

use crate::address::NetLocation;
use crate::resolver::Resolver;

/// Resolve and connect a TCP stream to the destination.
pub async fn connect_tcp(
    location: &NetLocation,
    resolver: &Resolver,
) -> std::io::Result<TcpStream> {
    let addr = resolver.resolve(location).await?;
    let stream = TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    // Detect dead destination servers so stream tasks don't leak.
    if let Err(e) = crate::socket_util::set_tcp_keepalive(
        &stream,
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(15),
    ) {
        log::debug!("Failed to set TCP keepalive on outbound connection: {e}");
    }
    Ok(stream)
}

/// Resolve and connect a TCP stream, applying the configured congestion
/// control algorithm (e.g. "bbr").
pub async fn connect_tcp_with_cc(
    location: &NetLocation,
    resolver: &Resolver,
    congestion_algo: &str,
) -> std::io::Result<TcpStream> {
    let stream = connect_tcp(location, resolver).await?;
    if !congestion_algo.is_empty() {
        match crate::socket_util::set_tcp_congestion(&stream, congestion_algo) {
            Ok(true) => {
                log::debug!(
                    "TCP congestion set to {congestion_algo} for {}",
                    location
                );
            }
            Ok(false) => {
                // Non-Linux: silently skip.
            }
            Err(e) => {
                log::warn!(
                    "Failed to set TCP congestion to {congestion_algo} for {}: {e}",
                    location
                );
            }
        }
    }
    Ok(stream)
}

/// Resolve and create a connected UDP socket to the destination.
pub async fn connect_udp(
    location: &NetLocation,
    resolver: &Resolver,
) -> std::io::Result<UdpSocket> {
    let addr = resolver.resolve(location).await?;
    let socket = crate::socket_util::new_udp_socket(addr.is_ipv6())?;
    socket.connect(addr).await?;
    Ok(socket)
}

/// Convenience wrapper for call sites holding an `Arc<Resolver>`.
/// Applies the resolver's configured TCP congestion control algorithm.
pub async fn connect_tcp_arc(
    location: &NetLocation,
    resolver: &Arc<Resolver>,
) -> std::io::Result<TcpStream> {
    connect_tcp_with_cc(location, resolver.as_ref(), resolver.tcp_congestion()).await
}
