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
pub async fn connect_tcp_arc(
    location: &NetLocation,
    resolver: &Arc<Resolver>,
) -> std::io::Result<TcpStream> {
    connect_tcp(location, resolver.as_ref()).await
}
