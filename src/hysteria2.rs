//! Hysteria2 server implementation, ported from shoes
//! (src/hysteria2_server.rs) and adapted for direct-connect forwarding.

use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::str;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use lru::LruCache;
use rand::{Rng, RngExt};
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::quic_stream::QuicStream;
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tls_config::TlsMaterial;
use crate::util::allocate_vec;

/// Maximum number of fragmented packets to track per session.
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;

/// Authentication timeout - close connection if client doesn't authenticate
/// within this time (3 seconds per sing-box reference implementation).
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// HTTP/3 error code for normal closure.
const CLOSE_ERR_CODE_OK: u32 = 0x100;

async fn process_connection(
    resolver: Arc<Resolver>,
    password: &'static str,
    conn: quinn::Incoming,
    udp_enabled: bool,
) -> std::io::Result<()> {
    let connection = conn.await?;

    let cancel_token = CancellationToken::new();

    // Keep the h3 connection alive for the entire connection lifecycle;
    // dropping it closes the underlying QUIC connection.
    let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        h3::server::Connection::new(h3_quinn_connection)
            .await
            .map_err(|e| std::io::Error::other(format!("H3 connection setup failed: {e}")))?;

    match timeout(
        AUTH_TIMEOUT,
        auth_connection(&mut h3_conn, password, udp_enabled),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            connection.close(CLOSE_ERR_CODE_OK.into(), b"auth failed");
            return Err(e);
        }
        Err(_elapsed) => {
            log::error!("Authentication timeout");
            connection.close(CLOSE_ERR_CODE_OK.into(), b"auth timeout");
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "authentication timeout",
            ));
        }
    }

    let udp_connection = connection.clone();
    let udp_resolver = resolver.clone();
    let udp_cancel_token = cancel_token.clone();

    let uni_connection = connection.clone();

    let udp_loop = async {
        if udp_enabled {
            run_udp_local_to_remote_loop(udp_connection, udp_resolver, udp_cancel_token).await
        } else {
            Ok(())
        }
    };

    let uni_loop = async {
        loop {
            match uni_connection.accept_uni().await {
                Ok(mut recv_stream) => {
                    let _ = recv_stream.stop(0u32.into());
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
                Err(e) => {
                    return Err(std::io::Error::other(format!(
                        "unidirectional loop error: {e}"
                    )));
                }
            }
        }
        Ok(())
    };

    let tcp_connection = connection.clone();
    let tcp_loop = run_tcp_loop(tcp_connection, resolver);

    let result = tokio::try_join!(udp_loop, uni_loop, tcp_loop);

    cancel_token.cancel();

    if let Err(ref e) = result {
        log::error!("Connection failed: {e}");
        connection.close(CLOSE_ERR_CODE_OK.into(), b"");
    }

    result.map(|_| ())
}

fn validate_auth_request<T>(req: http::Request<T>, password: &str) -> std::io::Result<()> {
    if req.uri() != "https://hysteria/auth" {
        return Err(std::io::Error::other(format!(
            "unexpected uri: {}",
            req.uri()
        )));
    }
    if req.method() != "POST" {
        return Err(std::io::Error::other(format!(
            "unexpected method: {}",
            req.method()
        )));
    }

    let headers = req.headers();
    let auth_value = match headers.get("hysteria-auth") {
        Some(h) => h,
        None => {
            return Err(std::io::Error::other("missing auth header"));
        }
    };
    let auth_str = auth_value
        .to_str()
        .map_err(|e| std::io::Error::other(format!("invalid auth header value: {e}")))?;
    if auth_str != password {
        return Err(std::io::Error::other(format!(
            "incorrect auth password: {auth_str}"
        )));
    }

    Ok(())
}

fn generate_ascii_string() -> String {
    let mut rng = rand::rng();
    let length = rng.random_range(1..80);
    rng.sample_iter(rand::distr::Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

async fn auth_connection(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
    password: &str,
    udp_enabled: bool,
) -> std::io::Result<()> {
    loop {
        match h3_conn
            .accept()
            .await
            .map_err(|e| std::io::Error::other(format!("H3 accept failed: {e}")))?
        {
            Some(resolver) => {
                let (req, mut stream) = resolver.resolve_request().await.map_err(|err| {
                    std::io::Error::other(format!("Failed to resolve request: {err}"))
                })?;
                match validate_auth_request(req, password) {
                    Ok(()) => {
                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::from_u16(233).unwrap())
                            .header("Hysteria-UDP", if udp_enabled { "true" } else { "false" })
                            .header("Hysteria-CC-RX", "0")
                            .header("Hysteria-Padding", generate_ascii_string())
                            .body(())
                            .unwrap();

                        stream.send_response(resp).await.map_err(|e| {
                            std::io::Error::other(format!("failed to send auth response: {e}"))
                        })?;
                        stream.finish().await.map_err(|e| {
                            std::io::Error::other(format!("failed to finish auth stream: {e}"))
                        })?;

                        return Ok(());
                    }
                    Err(e) => {
                        log::error!("Received non-hysteria2 auth http3 request: {e}");
                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::NOT_FOUND)
                            .body(())
                            .unwrap();
                        stream.send_response(resp).await.map_err(|e| {
                            std::io::Error::other(format!("failed to send reject response: {e}"))
                        })?;
                        stream.finish().await.map_err(|e| {
                            std::io::Error::other(format!("failed to finish reject stream: {e}"))
                        })?;
                    }
                }
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "no streams",
                ));
            }
        }
    }
}

struct UdpSession {
    fragments: LruCache<u16, FragmentedPacket>,
    send_socket: Arc<UdpSocket>,
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    override_remote_write_address: Option<SocketAddr>,
    last_activity: std::time::Instant,
    cancel_token: CancellationToken,
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: NetLocation,
}

impl UdpSession {
    fn start(
        session_id: u32,
        connection: quinn::Connection,
        client_socket: Arc<UdpSocket>,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        override_local_write_location: Option<NetLocation>,
        override_remote_write_address: Option<SocketAddr>,
        parent_cancel_token: &CancellationToken,
    ) -> Self {
        let session_cancel_token = parent_cancel_token.child_token();

        let session = UdpSession {
            fragments: LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap()),
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            override_remote_write_address,
            last_activity: std::time::Instant::now(),
            cancel_token: session_cancel_token.clone(),
        };

        tokio::spawn(async move {
            if let Err(e) = run_udp_remote_to_local_loop(
                session_id,
                connection,
                client_socket,
                override_local_write_location,
                session_cancel_token,
            )
            .await
            {
                log::error!("UDP remote-to-local write loop ended with error: {e}");
            }
        });

        session
    }
}

async fn run_udp_remote_to_local_loop(
    session_id: u32,
    connection: quinn::Connection,
    socket: Arc<UdpSocket>,
    override_local_write_address: Option<NetLocation>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| std::io::Error::other("datagram not supported by remote endpoint"))?;

    let original_address_bytes: Option<(Bytes, Bytes)> = match override_local_write_address {
        Some(a) => {
            let address_bytes: Bytes = a.to_string().into_bytes().into();
            let address_len = address_bytes.len();
            let address_len_bytes = encode_varint(address_len as u64)?.into();
            Some((address_bytes, address_len_bytes))
        }
        None => None,
    };

    let mut next_packet_id: u16 = 0;
    let mut buf = allocate_vec(65535);
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) = match socket.try_recv_from(&mut buf) {
            Ok(res) => res,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        return Ok(());
                    }
                    result = socket.readable() => {
                        result?;
                        continue;
                    }
                }
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to receive from UDP socket: {e}"
                )));
            }
        };

        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);

        let (address_bytes, address_len_bytes) = match original_address_bytes {
            Some((ref a, ref b)) => (a.clone(), b.clone()),
            None => {
                let address_bytes: Bytes = src_addr.to_string().into_bytes().into();
                let address_len = address_bytes.len();
                let address_len_bytes = encode_varint(address_len as u64)?.into();
                (address_bytes, address_len_bytes)
            }
        };

        // session_id(4) + packet_id(2) + fragment id(1) + fragment count(1) + address length varint + address bytes
        let header_overhead = 4 + 2 + 1 + 1 + address_len_bytes.len() + address_bytes.len();

        assert!(
            max_datagram_size > header_overhead,
            "max datagram size ({max_datagram_size}) is smaller than header overhead ({header_overhead})"
        );

        if header_overhead + payload_len <= max_datagram_size {
            let mut datagram = BytesMut::with_capacity(header_overhead + payload_len);
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            datagram.extend_from_slice(&[0, 1]);
            datagram.extend_from_slice(&address_len_bytes);
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&buf[..payload_len]);

            connection
                .send_datagram(datagram.freeze())
                .map_err(|e| std::io::Error::other(format!("Failed to send datagram: {e}")))?;
        } else {
            let available_payload = max_datagram_size - header_overhead;
            let fragment_count = payload_len.div_ceil(available_payload) as u8;
            for fragment_id in 0..fragment_count {
                let start = (fragment_id as usize) * available_payload;
                let end = std::cmp::min(start + available_payload, payload_len);
                let mut datagram = BytesMut::with_capacity(header_overhead + (end - start));
                datagram.extend_from_slice(&session_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
                datagram.extend_from_slice(&[fragment_id, fragment_count]);
                datagram.extend_from_slice(&address_len_bytes);
                datagram.extend_from_slice(&address_bytes);
                datagram.extend_from_slice(&buf[start..end]);

                connection.send_datagram(datagram.freeze()).map_err(|e| {
                    std::io::Error::other(format!(
                        "Failed to send datagram fragment {fragment_id}: {e}"
                    ))
                })?;
            }
        }
    }
}

async fn run_udp_local_to_remote_loop(
    connection: quinn::Connection,
    resolver: Arc<Resolver>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();
    let mut last_cleanup = std::time::Instant::now();

    const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
    const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

    loop {
        let now = std::time::Instant::now();
        if (now - last_cleanup) > CLEANUP_INTERVAL {
            sessions.retain(|session_id, session| {
                if session.last_activity.elapsed() > IDLE_TIMEOUT {
                    session.cancel_token.cancel();
                    log::debug!("Removing inactive UDP session {session_id}");
                    false
                } else {
                    true
                }
            });
            last_cleanup = now;
        }

        let data = connection
            .read_datagram()
            .await
            .map_err(|err| std::io::Error::other(format!("failed to read datagram: {err}")))?;

        // Per official hysteria reference, parse errors are ignored and we
        // continue waiting for the next message.
        if data.len() < 9 {
            log::debug!("Ignoring short datagram (len={})", data.len());
            continue;
        }
        let session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let fragment_id = data[6];
        let fragment_count = data[7];

        let (address_len, next_index) = {
            let first_byte = data[8];
            let length_indicator = first_byte >> 6;
            let mut value: u64 = (first_byte & 0b00111111) as u64;
            let num_bytes = match length_indicator {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                _ => unreachable!(),
            };
            let mut next_index = 9;
            if num_bytes > 1 {
                let remaining = &data[9..9 + (num_bytes - 1)];
                for byte in remaining {
                    value <<= 8;
                    value |= *byte as u64;
                }
                next_index += num_bytes - 1;
            }
            (value as usize, next_index)
        };

        if address_len == 0 {
            log::debug!("Ignoring packet with empty address");
            continue;
        }
        if address_len > 2048 {
            log::debug!("Ignoring packet with address length {address_len}");
            continue;
        }
        if data.len() < next_index + address_len {
            log::debug!("Ignoring datagram with truncated address");
            continue;
        }
        let address_bytes = &data[next_index..next_index + address_len];
        let payload_fragment = data.slice(next_index + address_len..);

        let addr_str = match str::from_utf8(address_bytes) {
            Ok(s) => s,
            Err(e) => {
                log::debug!("Invalid UTF-8 in address: {e}");
                continue;
            }
        };

        let remote_location = match NetLocation::from_str(addr_str, None) {
            Ok(loc) => loc,
            Err(e) => {
                log::debug!("Failed to parse address '{addr_str}': {e}");
                continue;
            }
        };

        let mut session_entry = sessions.entry(session_id);
        let session = match session_entry {
            Entry::Vacant(entry) => {
                let resolved_address = match resolver.resolve(&remote_location).await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!(
                            "Failed to resolve initial remote location {remote_location}: {e}"
                        );
                        continue;
                    }
                };

                let (override_remote_write_address, override_local_write_location) =
                    if resolved_address.to_string() != remote_location.to_string() {
                        (Some(resolved_address), Some(remote_location.clone()))
                    } else {
                        (None, None)
                    };

                // Use IPv6 dual-stack socket for direct UDP (matches shoes).
                let client_socket = crate::socket_util::new_udp_socket(true)?;

                let session = UdpSession::start(
                    session_id,
                    connection.clone(),
                    Arc::new(client_socket),
                    remote_location.clone(),
                    resolved_address,
                    override_local_write_location,
                    override_remote_write_address,
                    &cancel_token,
                );
                entry.insert(session)
            }
            Entry::Occupied(ref mut entry) => entry.get_mut(),
        };

        let (complete_payload, remote_location) = if fragment_count == 0 {
            log::error!("Ignoring empty UDP fragment for session {session_id}");
            continue;
        } else if fragment_count == 1 {
            (payload_fragment, remote_location)
        } else {
            let is_new = !session.fragments.contains(&packet_id);

            if is_new {
                session.fragments.put(
                    packet_id,
                    FragmentedPacket {
                        fragment_count,
                        fragment_received: 0,
                        packet_len: 0,
                        received: vec![None; fragment_count as usize],
                        remote_location: remote_location.clone(),
                    },
                );
            }

            let entry = match session.fragments.get_mut(&packet_id) {
                Some(e) => e,
                None => {
                    log::error!("Fragment cache error for session {session_id}");
                    continue;
                }
            };

            if entry.fragment_count != fragment_count {
                session.fragments.pop(&packet_id);
                log::error!(
                    "Mismatched fragment count for session {session_id} packet {packet_id}"
                );
                continue;
            }
            if entry.received[fragment_id as usize].is_some() {
                session.fragments.pop(&packet_id);
                log::error!("Duplicate fragment for session {session_id} packet {packet_id}");
                continue;
            }
            entry.fragment_received += 1;
            entry.packet_len += payload_fragment.len();
            entry.received[fragment_id as usize] = Some(payload_fragment);

            if entry.fragment_received != entry.fragment_count {
                continue;
            }

            let FragmentedPacket {
                remote_location: initial_location,
                received,
                packet_len,
                ..
            } = session.fragments.pop(&packet_id).unwrap();
            let mut complete_payload = BytesMut::with_capacity(packet_len);
            for frag in received.iter() {
                complete_payload.extend_from_slice(frag.as_ref().unwrap());
            }
            (complete_payload.freeze(), initial_location)
        };

        let socket_addr = match session.override_remote_write_address {
            Some(addr) => addr,
            None => {
                if remote_location == session.last_location {
                    session.last_socket_addr
                } else {
                    log::warn!(
                        "Location changed during ongoing UDP session: {remote_location}"
                    );
                    let updated_socket_addr = match resolver.resolve(&remote_location).await {
                        Ok(s) => s,
                        Err(e) => {
                            log::error!(
                                "Failed to resolve updated remote location {remote_location}: {e}"
                            );
                            continue;
                        }
                    };
                    session.last_location = remote_location;
                    session.last_socket_addr = updated_socket_addr;
                    updated_socket_addr
                }
            }
        };

        if let Err(e) = session
            .send_socket
            .send_to(&complete_payload, socket_addr)
            .await
        {
            log::error!("Failed to forward UDP payload for session {session_id}: {e}");
            sessions.remove(&session_id);
        }
    }
}

async fn run_tcp_loop(
    connection: quinn::Connection,
    resolver: Arc<Resolver>,
) -> std::io::Result<()> {
    loop {
        let (send_stream, recv_stream) = match connection.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to accept bidirectional stream: {e}"
                )));
            }
        };

        let resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = process_tcp_stream(resolver, send_stream, recv_stream).await {
                log::error!("Failed to process streams: {e}");
            }
        });
    }
    Ok(())
}

/// TCP request frame type constant from Hysteria2 protocol.
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

async fn handle_tcp_header(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> std::io::Result<(NetLocation, StreamReader)> {
    let mut stream_reader = StreamReader::new_with_buffer_size(8192);

    let tcp_request_id = read_varint(recv, &mut stream_reader).await?;
    if tcp_request_id != FRAME_TYPE_TCP_REQUEST {
        return Err(std::io::Error::other(format!(
            "invalid tcp request id: expected {:#x}, got {:#x}",
            FRAME_TYPE_TCP_REQUEST, tcp_request_id
        )));
    }

    let address_len = read_varint(recv, &mut stream_reader).await?;
    if address_len > 2048 {
        return Err(std::io::Error::other("invalid address length"));
    }
    let address_bytes = stream_reader.read_slice(recv, address_len as usize).await?;
    let address = std::str::from_utf8(address_bytes)
        .map_err(|e| std::io::Error::other(format!("invalid address encoding: {e}")))?;
    let remote_location = NetLocation::from_str(address, None)?;

    let padding_len = read_varint(recv, &mut stream_reader).await?;
    if padding_len > 4096 {
        return Err(std::io::Error::other("invalid padding length"));
    }
    stream_reader.read_slice(recv, padding_len as usize).await?;

    let response_bytes = {
        // [uint8] Status (0x00 = OK)
        // [varint] Message length
        // [bytes] Message string
        // [varint] Padding length
        // [bytes] Random padding
        let mut rng = rand::rng();

        let padding_len = rng.random_range(0..=63);

        let mut response_bytes = allocate_vec(3 + (padding_len as usize));
        response_bytes[0] = 0;
        response_bytes[1] = 0;
        response_bytes[2] = padding_len;
        rng.fill_bytes(&mut response_bytes[3..]);

        response_bytes
    };

    let len = response_bytes.len();
    let mut i = 0;
    while i < len {
        let count = send
            .write(&response_bytes[i..len])
            .await
            .map_err(|e| std::io::Error::other(format!("H3 stream write failed: {e}")))?;
        i += count;
    }

    Ok((remote_location, stream_reader))
}

async fn process_tcp_stream(
    resolver: Arc<Resolver>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> std::io::Result<()> {
    let (remote_location, stream_reader) = match handle_tcp_header(&mut send, &mut recv).await {
        Ok(res) => res,
        Err(e) => {
            let _ = send.shutdown().await;
            return Err(e);
        }
    };

    let mut server_stream: Box<dyn AsyncStream> = Box::new(QuicStream::from((send, recv)));

    let setup_client_stream_future = timeout(
        Duration::from_secs(60),
        crate::dial::connect_tcp_arc(&remote_location, &resolver),
    );

    let mut client_stream = match setup_client_stream_future.await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup client stream to {remote_location}: {e}"),
            ));
        }
        Err(elapsed) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {remote_location} timed out: {elapsed}"),
            ));
        }
    };

    let unparsed_data = stream_reader.unparsed_data();
    let client_requires_flush = if unparsed_data.is_empty() {
        false
    } else {
        let len = unparsed_data.len();
        let mut i = 0;
        while i < len {
            let count = client_stream
                .write(&unparsed_data[i..len])
                .await
                .map_err(|e| std::io::Error::other(format!("H3 stream write failed: {e}")))?;
            i += count;
        }
        true
    };
    drop(stream_reader);

    // Use 32KB buffers to match hysteria2/sing-box reference implementations.
    let copy_result = copy_bidirectional_with_sizes(
        &mut server_stream,
        &mut client_stream,
        false,
        client_requires_flush,
        32768,
        32768,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

#[inline]
fn encode_varint(value: u64) -> std::io::Result<Box<[u8]>> {
    if value <= 0b00111111 {
        Ok(Box::new([value as u8]))
    } else if value < (1 << 14) {
        let mut bytes = (value as u16).to_be_bytes();
        bytes[0] |= 0b01000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 30) {
        let mut bytes = (value as u32).to_be_bytes();
        bytes[0] |= 0b10000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 62) {
        let mut bytes = value.to_be_bytes();
        bytes[0] |= 0b11000000;
        Ok(Box::new(bytes))
    } else {
        Err(std::io::Error::other("value too large to encode as varint"))
    }
}

async fn read_varint(
    recv: &mut quinn::RecvStream,
    stream_reader: &mut StreamReader,
) -> std::io::Result<u64> {
    let first_byte = stream_reader.read_u8(recv).await?;

    let length = first_byte >> 6;
    let mut value: u64 = (first_byte & 0b00111111) as u64;

    let num_bytes = match length {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => panic!("invalid num bytes value"),
    };

    if num_bytes > 1 {
        let remaining_bytes = stream_reader.read_slice(recv, num_bytes - 1).await?;
        for byte in remaining_bytes {
            value <<= 8;
            value |= *byte as u64;
        }
    }

    Ok(value)
}

/// Runtime configuration for the Hysteria2 server.
pub struct Hysteria2ServerConfig {
    pub listen: String,
    pub password: String,
    pub udp_enabled: bool,
    pub cert: Option<String>,
    pub key: Option<String>,
    /// ALPN protocols (default `["h3"]`).
    pub alpn: Vec<String>,
}

/// Start the Hysteria2 server on the configured address.
pub async fn run_server(
    config: Hysteria2ServerConfig,
    resolver: Arc<Resolver>,
) -> std::io::Result<JoinHandle<()>> {
    let bind_address: SocketAddr = config
        .listen
        .parse()
        .map_err(|e| std::io::Error::other(format!("invalid listen address '{}': {e}", config.listen)))?;

    let alpn = if config.alpn.is_empty() {
        vec!["h3".to_string()]
    } else {
        config.alpn.clone()
    };

    let tls_material = TlsMaterial::from_files(
        config.cert.as_deref(),
        config.key.as_deref(),
        "hysteria2",
    )?
    .with_alpn(&alpn);

    let quic_server_config = tls_material.into_quic()?;
    let hysteria2_password: &'static str = Box::leak(config.password.into_boxed_str());

    let resolver = resolver.clone();
    Ok(tokio::spawn(async move {
        let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config);

        // Transport values estimated from the official hysteria reference.
        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_concurrent_bidi_streams(4096_u32.into())
            .max_concurrent_uni_streams(1024_u32.into())
            .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .send_window(16 * 1024 * 1024)
            .receive_window((20u32 * 1024 * 1024).into())
            .stream_receive_window((8u32 * 1024 * 1024).into())
            .initial_mtu(1200)
            .min_mtu(1200)
            .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
            .enable_segmentation_offload(true)
            .initial_rtt(Duration::from_millis(100));

        let socket2_socket = crate::socket_util::new_socket2_udp_socket_with_buffer_size(
            bind_address.is_ipv6(),
            Some(bind_address),
            true,
            Some(8_625_000),
        )
        .unwrap();

        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket2_socket.into(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();

        log::info!("Hysteria2 server listening on {bind_address}");

        while let Some(conn) = endpoint.accept().await {
            let cloned_resolver = resolver.clone();
            tokio::spawn(async move {
                if let Err(e) = process_connection(
                    cloned_resolver,
                    hysteria2_password,
                    conn,
                    config.udp_enabled,
                )
                .await
                {
                    log::error!("Connection ended with error: {e}");
                }
            });
        }
    }))
}
