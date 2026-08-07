//! UDP relay helpers for the direct-connect server, ported and simplified
//! from shoes (src/copy_bidirectional_message.rs, src/routing/udp_router.rs).

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::ready;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncMessageStream, AsyncPing, AsyncShutdownMessageExt, AsyncTargetedMessageStream,
};
use crate::resolver::Resolver;
use crate::util::allocate_vec;

/// UDP association timeout, matching shoes (200s).
const ASSOCIATION_TIMEOUT: Duration = Duration::from_secs(200);

// ================== copy_bidirectional_message ==================

struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    need_write_ping: bool,
    cache_length: usize,
    buf: Box<[u8]>,
    read_count: usize,
}

impl CopyBuffer {
    pub fn new(need_flush: bool) -> Self {
        Self {
            read_done: false,
            need_flush,
            need_write_ping: false,
            cache_length: 0,
            buf: allocate_vec(65535).into_boxed_slice(),
            read_count: 0,
        }
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncMessageStream + ?Sized,
        W: AsyncMessageStream + ?Sized,
    {
        let coop = ready!(tokio::task::coop::poll_proceed(cx));

        loop {
            let mut did_read = false;
            let mut did_write = false;
            let mut read_pending = false;
            let mut write_pending = false;

            if !self.read_done && self.cache_length == 0 {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);
                match reader.as_mut().poll_read_message(cx, &mut buf) {
                    Poll::Ready(val) => {
                        val?;
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.cache_length = n;
                            did_read = true;
                            self.read_count = self.read_count.wrapping_add(n);
                            coop.made_progress();
                        }
                    }
                    Poll::Pending => {
                        read_pending = true;
                    }
                }
            }

            if self.cache_length > 0 {
                let me = &mut *self;
                match writer
                    .as_mut()
                    .poll_write_message(cx, &me.buf[0..me.cache_length])
                {
                    Poll::Ready(val) => {
                        val?;
                        self.cache_length = 0;
                        self.need_flush = true;
                        self.need_write_ping = false;
                        did_write = true;
                        coop.made_progress();
                    }
                    Poll::Pending => {
                        write_pending = true;
                    }
                }
            }

            if !write_pending && self.need_write_ping {
                match writer.as_mut().poll_write_ping(cx) {
                    Poll::Ready(val) => {
                        let written = val?;
                        self.need_write_ping = false;
                        if written {
                            self.need_flush = true;
                            coop.made_progress();
                        }
                    }
                    Poll::Pending => {
                        write_pending = true;
                    }
                }
            }

            if did_read && did_write && !read_pending && !write_pending {
                continue;
            }

            if self.need_flush {
                ready!(writer.as_mut().poll_flush_message(cx))?;
                self.need_flush = false;
                coop.made_progress();
                continue;
            }

            if self.read_done && self.cache_length == 0 {
                return Poll::Ready(Ok(()));
            }

            if read_pending || write_pending {
                return Poll::Pending;
            }
        }
    }
}

enum TransferState {
    Running,
    ShuttingDown,
    Done,
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_buf: CopyBuffer,
    b_buf: CopyBuffer,
    a_to_b: TransferState,
    b_to_a: TransferState,
    sleep_future: Pin<Box<tokio::time::Sleep>>,
    last_active: Instant,
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    buf: &mut CopyBuffer,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<()>>
where
    A: AsyncMessageStream + ?Sized,
    B: AsyncMessageStream + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running => {
                ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown;
            }
            TransferState::ShuttingDown => {
                ready!(w.as_mut().poll_shutdown_message(cx))?;
                *state = TransferState::Done;
            }
            TransferState::Done => return Poll::Ready(Ok(())),
        }
    }
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncMessageStream + ?Sized,
    B: AsyncMessageStream + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let CopyBidirectional {
            a,
            b,
            a_buf,
            b_buf,
            a_to_b,
            b_to_a,
            sleep_future,
            last_active,
        } = &mut *self;

        let ping_fired = sleep_future.as_mut().poll(cx).is_ready();
        if ping_fired {
            a_buf.need_write_ping = b.supports_ping();
            b_buf.need_write_ping = a.supports_ping();
            sleep_future
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_secs(60));
        }

        let a_count = a_buf.read_count;
        let b_count = b_buf.read_count;

        let a_to_b = transfer_one_direction(cx, a_to_b, &mut *a_buf, &mut *a, &mut *b);
        let b_to_a = transfer_one_direction(cx, b_to_a, &mut *b_buf, &mut *b, &mut *a);

        if a_buf.read_count != a_count || b_buf.read_count != b_count {
            *last_active = Instant::now();
        } else if last_active.elapsed() >= ASSOCIATION_TIMEOUT {
            return Poll::Ready(Ok(()));
        }

        if a_to_b.is_ready() {
            return a_to_b;
        } else if b_to_a.is_ready() {
            return b_to_a;
        }

        Poll::Pending
    }
}

/// Copy messages bidirectionally between two message streams.
pub async fn copy_bidirectional_message<A, B>(
    a: &mut A,
    b: &mut B,
    a_initial_flush: bool,
    b_initial_flush: bool,
) -> io::Result<()>
where
    A: AsyncMessageStream + ?Sized,
    B: AsyncMessageStream + ?Sized,
{
    let sleep_future = Box::pin(tokio::time::sleep(Duration::from_secs(60)));

    CopyBidirectional {
        a,
        b,
        a_buf: CopyBuffer::new(b_initial_flush),
        b_buf: CopyBuffer::new(a_initial_flush),
        a_to_b: TransferState::Running,
        b_to_a: TransferState::Running,
        sleep_future,
        last_active: Instant::now(),
    }
    .await
}

/// Copy messages bidirectionally between a server stream and a connected UDP
/// socket, then shut both down.
pub async fn run_udp_copy(
    mut server_stream: Box<dyn AsyncMessageStream>,
    mut client_stream: Box<dyn AsyncMessageStream>,
    server_need_initial_flush: bool,
    client_need_initial_flush: bool,
) -> io::Result<()> {
    let copy_result = copy_bidirectional_message(
        &mut server_stream,
        &mut client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await;

    let (_, _) = futures::join!(
        server_stream.shutdown_message(),
        client_stream.shutdown_message()
    );

    copy_result
}

// ================== run_udp_routing (per-destination) ==================

struct Session {
    socket: Arc<tokio::net::UdpSocket>,
    cancel: CancellationToken,
    last_activity: Instant,
}

/// Route messages from a targeted server stream (each packet carries its own
/// destination) to the requested destinations via direct UDP, and deliver
/// responses back with their source address.
///
/// This is the direct-connect equivalent of shoes'
/// `routing::run_udp_routing`, with one UDP socket per destination.
pub async fn run_udp_routing(
    mut server: Box<dyn AsyncTargetedMessageStream>,
    resolver: Arc<Resolver>,
) -> io::Result<()> {
    let (response_tx, mut response_rx) = mpsc::unbounded_channel::<(SocketAddr, Bytes)>();
    let mut sessions: HashMap<NetLocation, Session> = HashMap::new();
    let mut last_cleanup = Instant::now();
    let mut buf = allocate_vec(65535);

    loop {
        // Periodic cleanup of idle sessions.
        if last_cleanup.elapsed() >= Duration::from_secs(10) {
            sessions.retain(|_, session| {
                if session.last_activity.elapsed() > ASSOCIATION_TIMEOUT {
                    session.cancel.cancel();
                    false
                } else {
                    true
                }
            });
            last_cleanup = Instant::now();
        }

        tokio::select! {
            biased;

            // Responses from remote UDP sockets -> client.
            Some((source, payload)) = response_rx.recv(), if !sessions.is_empty() => {
                if let Err(e) = write_sourced_message(&mut server, &payload, &source).await {
                    log::debug!("UDP routing: failed to write response to client: {e}");
                    break;
                }
            }

            // Inbound packet from client -> destination.
            result = read_targeted_message(&mut server, &mut buf) => {
                let (destination, payload_len) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        log::debug!("UDP routing: read error: {e}");
                        break;
                    }
                };
                if destination.is_unspecified() {
                    log::debug!("UDP routing: client closed the stream");
                    break;
                }

                // Resolve the destination.
                let addr = match resolver.resolve(&destination).await {
                    Ok(a) => a,
                    Err(e) => {
                        log::debug!("UDP routing: failed to resolve {destination}: {e}");
                        continue;
                    }
                };

                let now = Instant::now();
                if !sessions.contains_key(&destination) {
                    match create_session(addr.is_ipv6()).await {
                        Ok((socket, cancel)) => {
                            let socket = Arc::new(socket);
                            let task_socket = socket.clone();
                            let task_cancel = cancel.clone();
                            let tx = response_tx.clone();
                            tokio::spawn(async move {
                                let _ = recv_loop(task_socket, tx, task_cancel).await;
                            });
                            sessions.insert(destination.clone(), Session {
                                socket,
                                cancel,
                                last_activity: now,
                            });
                        }
                        Err(e) => {
                            log::debug!("UDP routing: failed to create socket: {e}");
                            continue;
                        }
                    }
                }

                let session = sessions.get_mut(&destination).unwrap();
                session.last_activity = now;
                let payload = &buf[..payload_len];
                let _ = session.socket.send_to(payload, addr).await;
            }
        }
    }

    // Cancel all session tasks.
    for (_, session) in sessions.drain() {
        session.cancel.cancel();
    }
    let _ = server.shutdown_message().await;
    Ok(())
}

async fn create_session(is_ipv6: bool) -> io::Result<(tokio::net::UdpSocket, CancellationToken)> {
    let socket = crate::socket_util::new_udp_socket(is_ipv6)?;
    Ok((socket, CancellationToken::new()))
}

async fn recv_loop(
    socket: Arc<tokio::net::UdpSocket>,
    tx: mpsc::UnboundedSender<(SocketAddr, Bytes)>,
    cancel: CancellationToken,
) -> io::Result<()> {
    let mut buf = allocate_vec(65535);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = socket.recv_from(&mut buf) => {
                let (len, source) = match result {
                    Ok(v) => v,
                    Err(e) => return Err(e),
                };
                let payload = Bytes::copy_from_slice(&buf[..len]);
                if tx.send((source, payload)).is_err() {
                    return Ok(());
                }
            }
        }
    }
}

async fn read_targeted_message(
    server: &mut (dyn AsyncTargetedMessageStream + Unpin),
    buf: &mut [u8],
) -> io::Result<(NetLocation, usize)> {
    use std::future::poll_fn;
    poll_fn(|cx| {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut *server).poll_read_targeted_message(cx, &mut read_buf) {
            Poll::Ready(Ok(loc)) => {
                let len = read_buf.filled().len();
                Poll::Ready(Ok((loc, len)))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

async fn write_sourced_message(
    server: &mut (dyn AsyncTargetedMessageStream + Unpin),
    payload: &[u8],
    source: &SocketAddr,
) -> io::Result<()> {
    use std::future::poll_fn;
    poll_fn(|cx| Pin::new(&mut *server).poll_write_sourced_message(cx, payload, source)).await?;
    poll_fn(|cx| Pin::new(&mut *server).poll_flush_message(cx)).await
}
