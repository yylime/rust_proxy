//! AnyTLS Session implementation, ported from shoes
//! (src/anytls/anytls_server_session.rs) and adapted for direct-connect
//! forwarding (no proxy chaining / rules).
//!
//! A Session manages multiple Streams over a single TLS connection, handling
//! framing, multiplexing, padding, and stream routing.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::task::JoinHandle;

use crate::address::{Address, NetLocation};
use crate::anytls::padding::{CHECK_MARK, PaddingFactory};
use crate::anytls::stream::{AnyTlsStream, STREAM_CHANNEL_BUFFER};
use crate::anytls::types::{Command, FRAME_HEADER_SIZE, Frame, FrameCodec, StringMap};
use crate::async_stream::{AsyncMessageStream, AsyncTargetedMessageStream};
use crate::copy_bidirectional::copy_bidirectional;
use crate::message_stream::{UotV1ServerStream, VlessMessageStream};
use crate::resolver::Resolver;
use crate::udp_relay::{run_udp_copy, run_udp_routing};

/// Magic addresses used to signal UDP-over-TCP modes.
pub const UOT_V1_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";
pub const UOT_V2_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";

/// Timeout for control frame writes (matches reference implementation)
const CONTROL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for connecting to the destination server (30s).
/// Only covers TCP connect + SYNACK; data transfer has no hard limit.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);


/// AnyTLS Session manages multiplexed streams over a connection.
pub struct AnyTlsSession {
    reader: Mutex<Box<dyn AsyncRead + Send + Unpin>>,
    writer: Mutex<Box<dyn AsyncWrite + Send + Unpin>>,

    /// Stream management (bounded channels for backpressure)
    streams: RwLock<HashMap<u32, mpsc::Sender<Bytes>>>,

    /// Active stream handler tasks (for cancellation on session close)
    stream_tasks: Mutex<HashMap<u32, JoinHandle<()>>>,

    /// Channel for receiving outgoing data from streams
    outgoing_rx: Mutex<mpsc::Receiver<(u32, Bytes)>>,
    outgoing_tx: mpsc::Sender<(u32, Bytes)>,

    /// Session state
    is_closed: Arc<AtomicBool>,

    /// Padding configuration
    padding: Arc<PaddingFactory>,

    /// Padding state (server doesn't pad by default)
    send_padding: AtomicBool,
    pkt_counter: AtomicU32,

    /// Buffering state (for initial settings+SYN coalescing)
    buffering: AtomicBool,
    buffer: Mutex<Vec<u8>>,

    /// Reusable write buffer to avoid allocations in hot path
    write_buf: Mutex<BytesMut>,

    /// Protocol version negotiation
    peer_version: AtomicU8,

    /// Server settings received
    received_client_settings: AtomicBool,

    // === Stream handling dependencies ===
    resolver: Arc<Resolver>,

    /// UDP enabled for UoT support
    udp_enabled: bool,

    /// Authenticated user name for logging
    user_name: String,

    /// Initial data buffered during auth (prepended to first read)
    initial_data: std::sync::Mutex<Option<Box<[u8]>>>,
}

impl AnyTlsSession {
    /// Create a new server session with optional initial data that was
    /// buffered during auth.
    pub fn new_server_with_initial_data<IO>(
        conn: IO,
        padding: Arc<PaddingFactory>,
        resolver: Arc<Resolver>,
        udp_enabled: bool,
        user_name: String,
        initial_data: Option<Box<[u8]>>,
    ) -> Arc<Self>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (reader, writer) = tokio::io::split(conn);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER * 4);

        Arc::new(Self {
            reader: Mutex::new(Box::new(reader)),
            writer: Mutex::new(Box::new(writer)),
            streams: RwLock::new(HashMap::new()),
            stream_tasks: Mutex::new(HashMap::new()),
            outgoing_rx: Mutex::new(outgoing_rx),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
            padding,
            send_padding: AtomicBool::new(false),
            pkt_counter: AtomicU32::new(0),
            buffering: AtomicBool::new(false),
            buffer: Mutex::new(Vec::new()),
            write_buf: Mutex::new(BytesMut::with_capacity(
                65536 + FRAME_HEADER_SIZE + 64,
            )),
            peer_version: AtomicU8::new(0),
            received_client_settings: AtomicBool::new(false),
            resolver,
            udp_enabled,
            user_name,
            initial_data: std::sync::Mutex::new(initial_data),
        })
    }

    /// Check if the session is closed
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }

    /// Close the session
    pub async fn close(&self) {
        if self
            .is_closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            {
                let mut tasks = self.stream_tasks.lock().await;
                for (stream_id, handle) in tasks.drain() {
                    log::trace!("Aborting stream task {stream_id}");
                    handle.abort();
                }
            }

            let mut streams = self.streams.write().await;
            streams.clear();

            if let Ok(mut writer) = self.writer.try_lock() {
                let _ = writer.shutdown().await;
            }
        }
    }

    /// Get the peer protocol version
    pub fn peer_version(&self) -> u8 {
        self.peer_version.load(Ordering::Relaxed)
    }

    /// Run the session (blocking).
    pub async fn run(self: &Arc<Self>) -> io::Result<()> {
        let session = Arc::clone(self);

        let session_clone = Arc::clone(&session);
        let outgoing_task = tokio::spawn(async move {
            session_clone.process_outgoing().await;
        });

        let result = session.recv_loop().await;

        session.close().await;
        outgoing_task.abort();

        result
    }

    /// Process outgoing data from streams
    async fn process_outgoing(&self) {
        let mut rx = self.outgoing_rx.lock().await;

        while let Some((stream_id, data)) = rx.recv().await {
            if self.is_closed() {
                break;
            }

            if data.is_empty() {
                let frame = Frame::control(Command::Fin, stream_id);
                if let Err(e) = self.write_frame(&frame).await {
                    log::debug!("Failed to send FIN for stream {stream_id}: {e}");
                }

                let mut streams = self.streams.write().await;
                streams.remove(&stream_id);
            } else {
                let frame = Frame::data(stream_id, data);
                if let Err(e) = self.write_frame(&frame).await {
                    log::debug!("Failed to send data for stream {stream_id}: {e}");
                    break;
                }
            }
        }
    }

    /// Main receive loop - reads frames and dispatches them
    async fn recv_loop(self: &Arc<Self>) -> io::Result<()> {
        let mut buffer = BytesMut::with_capacity(8192);

        if let Some(initial) = self.initial_data.lock().unwrap().take() {
            buffer.extend_from_slice(&initial);
        }

        loop {
            if self.is_closed() {
                return Ok(());
            }

            while let Some(frame) = FrameCodec::decode(&mut buffer)? {
                if let Err(e) = self.handle_frame(frame).await {
                    log::warn!("Error handling frame: {e}");
                    return Err(e);
                }
            }

            let n = {
                let mut reader = self.reader.lock().await;
                match reader.read_buf(&mut buffer).await {
                    Ok(0) => return Ok(()),
                    Ok(n) => n,
                    Err(e) => return Err(e),
                }
            };

            log::trace!("Read {n} bytes from connection");
        }
    }

    /// Handle a received frame
    async fn handle_frame(self: &Arc<Self>, frame: Frame) -> io::Result<()> {
        match frame.cmd {
            Command::Psh => {
                if frame.data.is_empty() {
                    return Ok(());
                }

                let tx = {
                    let streams = self.streams.read().await;
                    streams.get(&frame.stream_id).cloned()
                };
                if let Some(tx) = tx {
                    if tx.send(frame.data).await.is_err() {
                        log::trace!("Stream {} channel closed", frame.stream_id);
                    }
                } else {
                    log::trace!("Data for unknown stream {}", frame.stream_id);
                }
            }

            Command::Syn => {
                if !self.received_client_settings.load(Ordering::Relaxed) {
                    let alert_frame = Frame::with_data(
                        Command::Alert,
                        0,
                        Bytes::from("client did not send its settings"),
                    );
                    self.write_control_frame(&alert_frame).await?;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "client did not send settings",
                    ));
                }

                let stream_id = frame.stream_id;

                let stream_opt = {
                    let mut streams = self.streams.write().await;
                    use std::collections::hash_map::Entry;
                    match streams.entry(stream_id) {
                        Entry::Occupied(_) => {
                            log::warn!("Duplicate SYN for stream {stream_id}");
                            None
                        }
                        Entry::Vacant(entry) => {
                            let (data_tx, data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
                            let stream = AnyTlsStream::new(
                                stream_id,
                                data_rx,
                                self.outgoing_tx.clone(),
                                Arc::clone(&self.is_closed),
                            );
                            entry.insert(data_tx);
                            Some(stream)
                        }
                    }
                };

                if let Some(stream) = stream_opt {
                    let session = Arc::clone(self);
                    let stream_id_for_cleanup = stream_id;
                    let session_for_cleanup = Arc::clone(self);

                    let handle = tokio::spawn(async move {
                        match session.handle_new_stream(stream).await {
                            Ok(()) => {
                                log::trace!("AnyTLS stream {stream_id_for_cleanup} completed");
                            }
                            Err(e) => {
                                log::debug!("AnyTLS stream {stream_id_for_cleanup} error: {e}");
                            }
                        }

                        let mut tasks = session_for_cleanup.stream_tasks.lock().await;
                        tasks.remove(&stream_id_for_cleanup);
                    });

                    let mut tasks = self.stream_tasks.lock().await;
                    tasks.insert(stream_id, handle);
                }
            }

            Command::Fin => {
                let stream_tx = {
                    let mut streams = self.streams.write().await;
                    streams.remove(&frame.stream_id)
                };

                if let Some(tx) = stream_tx {
                    let _ = tx.send(Bytes::new()).await;
                }
            }

            Command::Waste => {
                log::trace!("Received {} bytes of padding", frame.data.len());
            }

            Command::Settings => {
                self.received_client_settings.store(true, Ordering::Relaxed);

                let settings = StringMap::from_bytes(&frame.data);

                if settings
                    .get("padding-md5")
                    .is_some_and(|client_md5| client_md5 != self.padding.md5())
                {
                    let update_frame = Frame::with_data(
                        Command::UpdatePaddingScheme,
                        0,
                        Bytes::copy_from_slice(self.padding.raw_scheme()),
                    );
                    self.write_control_frame(&update_frame).await?;
                }

                if let Some(v) = settings
                    .get("v")
                    .and_then(|s| s.parse::<u8>().ok())
                    .filter(|&v| v >= 2)
                {
                    self.peer_version.store(v, Ordering::Relaxed);

                    let mut server_settings = StringMap::new();
                    server_settings.insert("v", "2");
                    let settings_frame = Frame::with_data(
                        Command::ServerSettings,
                        0,
                        Bytes::from(server_settings.to_bytes()),
                    );
                    self.write_control_frame(&settings_frame).await?;
                }
            }

            Command::HeartRequest => {
                let response = Frame::control(Command::HeartResponse, frame.stream_id);
                self.write_control_frame(&response).await?;
            }

            Command::Alert => {
                let msg = String::from_utf8_lossy(&frame.data);
                log::error!("Received alert: {msg}");
                return Err(io::Error::other(msg.to_string()));
            }

            // Client-only command paths (kept for protocol completeness).
            Command::SynAck | Command::ServerSettings | Command::UpdatePaddingScheme => {
                log::warn!("Unexpected {:?} received on server", frame.cmd);
            }

            Command::HeartResponse => {
                log::trace!("Received heartbeat response");
            }
        }

        Ok(())
    }

    /// Write a frame to the connection with padding applied
    async fn write_frame(&self, frame: &Frame) -> io::Result<()> {
        let mut write_buf = self.write_buf.lock().await;
        write_buf.clear();
        frame.encode_into(&mut write_buf);

        if self.buffering.load(Ordering::Relaxed) {
            let mut buffer = self.buffer.lock().await;
            buffer.extend_from_slice(&write_buf);
            return Ok(());
        }

        {
            let mut buffer = self.buffer.lock().await;
            if !buffer.is_empty() {
                let mut combined = BytesMut::from(&buffer[..]);
                combined.extend_from_slice(&write_buf);
                write_buf.clear();
                write_buf.extend_from_slice(&combined);
                buffer.clear();
            }
        }

        if self.send_padding.load(Ordering::Relaxed) {
            let pkt = self.pkt_counter.fetch_add(1, Ordering::SeqCst) + 1;

            if pkt < self.padding.stop() {
                let data = write_buf.split();
                return self.write_with_padding(data, pkt).await;
            } else {
                self.send_padding.store(false, Ordering::Relaxed);
            }
        }

        let mut writer = self.writer.lock().await;
        writer.write_all(&write_buf).await?;
        writer.flush().await
    }

    /// Write data with padding applied according to scheme
    async fn write_with_padding(&self, mut data: BytesMut, pkt: u32) -> io::Result<()> {
        let pkt_sizes = self.padding.generate_record_payload_sizes(pkt);

        if pkt_sizes.is_empty() {
            let mut writer = self.writer.lock().await;
            writer.write_all(&data).await?;
            return writer.flush().await;
        }

        let mut writer = self.writer.lock().await;

        for size in pkt_sizes {
            let remain_payload_len = data.len();

            if size == CHECK_MARK {
                if remain_payload_len == 0 {
                    break;
                }
                continue;
            }

            let size = size as usize;

            if remain_payload_len > size {
                writer.write_all(&data[..size]).await?;
                data = data.split_off(size);
            } else if remain_payload_len > 0 {
                let padding_len = size.saturating_sub(remain_payload_len + FRAME_HEADER_SIZE);

                if padding_len > 0 {
                    data.reserve(FRAME_HEADER_SIZE + padding_len);
                    data.put_u8(Command::Waste as u8);
                    data.put_u32(0);
                    data.put_u16(padding_len as u16);
                    data.put_bytes(0, padding_len);
                }

                writer.write_all(&data).await?;
                data.clear();
            } else {
                let header = [
                    Command::Waste as u8,
                    0,
                    0,
                    0,
                    0,
                    (size >> 8) as u8,
                    size as u8,
                ];
                writer.write_all(&header).await?;
                const ZERO_BUF: [u8; 1024] = [0u8; 1024];
                let mut remaining = size;
                while remaining > 0 {
                    let chunk = remaining.min(ZERO_BUF.len());
                    writer.write_all(&ZERO_BUF[..chunk]).await?;
                    remaining -= chunk;
                }
            }
        }

        if !data.is_empty() {
            writer.write_all(&data).await?;
        }

        writer.flush().await
    }

    /// Send SYNACK for a stream (server side, protocol v2)
    pub async fn send_synack(&self, stream_id: u32, error: Option<&str>) -> io::Result<()> {
        if self.peer_version() < 2 {
            return Ok(());
        }

        let frame = if let Some(err) = error {
            Frame::with_data(Command::SynAck, stream_id, Bytes::from(err.to_string()))
        } else {
            Frame::control(Command::SynAck, stream_id)
        };

        self.write_control_frame(&frame).await
    }

    /// Write a control frame with timeout
    async fn write_control_frame(&self, frame: &Frame) -> io::Result<()> {
        match tokio::time::timeout(CONTROL_FRAME_TIMEOUT, self.write_frame(frame)).await {
            Ok(result) => result,
            Err(_) => {
                log::warn!(
                    "Control frame write timed out after {CONTROL_FRAME_TIMEOUT:?}, closing session"
                );
                self.close().await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "control frame write timed out",
                ))
            }
        }
    }

    /// Handle a new stream by reading destination and routing appropriately
    async fn handle_new_stream(&self, mut stream: AnyTlsStream) -> io::Result<()> {
        let stream_id = stream.id();

        let destination = read_location_direct(&mut stream).await?;

        log::debug!(
            "AnyTLS stream {stream_id} (user: {}) -> {destination}",
            self.user_name
        );

        if let Address::Hostname(host) = destination.address() {
            if host == UOT_V2_MAGIC_ADDRESS {
                return self.handle_uot_v2(stream).await;
            } else if host == UOT_V1_MAGIC_ADDRESS {
                return self.handle_uot_v1(stream).await;
            }
        }

        self.handle_tcp_forward(stream, destination).await
    }

    /// Handle regular TCP forwarding
    async fn handle_tcp_forward(
        &self,
        mut stream: AnyTlsStream,
        destination: NetLocation,
    ) -> io::Result<()> {
        let stream_id = stream.id();

        let connect_result = tokio::time::timeout(
            CONNECT_TIMEOUT,
            crate::dial::connect_tcp_with_cc(&destination, &self.resolver, self.resolver.tcp_congestion()),
        )
        .await;

        let mut client_stream = match connect_result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let error_msg = format!("connect failed: {e}");
                let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                return Err(e);
            }
            Err(_elapsed) => {
                let error_msg = format!("connect to {destination} timed out after {CONNECT_TIMEOUT:?}");
                log::warn!("AnyTLS stream {stream_id}: {error_msg}");
                let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                return Err(std::io::Error::other(error_msg));
            }
        };

        if let Err(e) = self.send_synack(stream_id, None).await {
            log::debug!("Failed to send SYNACK for stream {stream_id}: {e}");
        }

        log::debug!("AnyTLS stream {stream_id} connected to destination");

        let result = copy_bidirectional(&mut stream, &mut client_stream, false, false).await;

        let _ = stream.shutdown().await;
        let _ = client_stream.shutdown().await;

        if let Err(e) = &result {
            log::debug!("AnyTLS stream {stream_id} ended: {e}");
        } else {
            log::debug!("AnyTLS stream {stream_id} completed");
        }

        result
    }

    /// Handle UoT V2 stream (sp.v2.udp-over-tcp.arpa)
    async fn handle_uot_v2(&self, mut stream: AnyTlsStream) -> io::Result<()> {
        let stream_id = stream.id();
        if !self.udp_enabled {
            log::debug!("AnyTLS stream {stream_id} UoT V2 rejected: UDP not enabled");
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP not enabled for AnyTLS",
            ));
        }

        let is_connect = stream.read_u8().await?;
        let destination = read_location_direct(&mut stream).await?;

        log::debug!(
            "AnyTLS stream {stream_id} UoT V2 (user: {}, connect={is_connect}) -> {destination}",
            self.user_name
        );

        if is_connect == 1 {
            self.handle_uot_v2_connect(stream, destination).await
        } else {
            self.handle_uot_multi_destination(stream).await
        }
    }

    /// Handle UoT V1 stream (sp.udp-over-tcp.arpa) - multi-destination mode
    async fn handle_uot_v1(&self, stream: AnyTlsStream) -> io::Result<()> {
        let stream_id = stream.id();
        if !self.udp_enabled {
            log::debug!("AnyTLS stream {stream_id} UoT V1 rejected: UDP not enabled");
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP not enabled for AnyTLS",
            ));
        }

        log::debug!(
            "AnyTLS stream {stream_id} UoT V1 (user: {})",
            self.user_name
        );

        self.handle_uot_multi_destination(stream).await
    }

    /// Handle UoT V2 Connect Mode (single destination, length-prefixed packets)
    async fn handle_uot_v2_connect(
        &self,
        stream: AnyTlsStream,
        destination: NetLocation,
    ) -> io::Result<()> {
        let stream_id = stream.id();

        let client_socket = match crate::dial::connect_udp(&destination, &self.resolver).await {
            Ok(s) => s,
            Err(e) => {
                let error_msg = format!("UDP connect failed: {e}");
                let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                return Err(e);
            }
        };

        let _ = self.send_synack(stream_id, None).await;

        log::debug!("AnyTLS stream {stream_id} UoT V2 connect: connected");

        let server_stream: Box<dyn AsyncMessageStream> =
            Box::new(VlessMessageStream::new(stream));
        let client_stream: Box<dyn AsyncMessageStream> = Box::new(client_socket);

        run_udp_copy(server_stream, client_stream, false, false).await
    }

    /// Handle UoT multi-destination mode (V1 and V2 non-connect)
    async fn handle_uot_multi_destination(&self, stream: AnyTlsStream) -> io::Result<()> {
        let stream_id = stream.id();

        log::debug!(
            "AnyTLS stream {stream_id} UoT multi-dest: starting per-destination routing"
        );

        let server_stream: Box<dyn AsyncTargetedMessageStream> =
            Box::new(UotV1ServerStream::new_uot(stream));

        let _ = self.send_synack(stream_id, None).await;

        run_udp_routing(server_stream, self.resolver.clone()).await
    }
}

/// SOCKS5-format destination address reader, ported from shoes
/// (src/socks_handler.rs::read_location_direct).
async fn read_location_direct<T: AsyncReadExt + Unpin>(
    stream: &mut T,
) -> std::io::Result<NetLocation> {
    const ADDR_TYPE_IPV4: u8 = 0x01;
    const ADDR_TYPE_IPV6: u8 = 0x04;
    const ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;

    let mut addr_type = [0u8; 1];
    stream.read_exact(&mut addr_type).await?;

    match addr_type[0] {
        ADDR_TYPE_IPV4 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
            let addr = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(NetLocation::new(Address::Ipv4(addr), port))
        }
        ADDR_TYPE_IPV6 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
            let addr = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&buf[0..16]).unwrap());
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(NetLocation::new(Address::Ipv6(addr), port))
        }
        ADDR_TYPE_DOMAIN_NAME => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let domain_len = len[0] as usize;

            let mut buf = vec![0u8; domain_len + 2];
            stream.read_exact(&mut buf).await?;

            let domain = std::str::from_utf8(&buf[..domain_len]).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid domain encoding: {e}"),
                )
            })?;
            let port = u16::from_be_bytes([buf[domain_len], buf[domain_len + 1]]);

            Ok(NetLocation::new(Address::from(domain)?, port))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unknown address type: {}", addr_type[0]),
        )),
    }
}
