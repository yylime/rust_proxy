//! AnyTLS Stream implementation, ported from shoes
//! (src/anytls/anytls_stream.rs).
//!
//! A Stream represents a single multiplexed connection within an AnyTLS
//! Session. It implements `AsyncRead`/`AsyncWrite` for transparent
//! integration, with `poll_shutdown` blocking until the FIN frame is queued.

use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use crate::async_stream::{AsyncPing, AsyncStream};

/// Buffer size for bounded channels (number of messages, not bytes).
/// Each message is typically a frame's worth of data (up to 64KB).
pub const STREAM_CHANNEL_BUFFER: usize = 16;

/// Maximum data payload per frame (u16::MAX = 65535)
const MAX_FRAME_DATA_SIZE: usize = 65535;

/// AnyTlsStream represents a multiplexed stream within an AnyTLS session.
///
/// Reads come from data pushed by the session's recv loop; writes are sent
/// to the session for framing and transmission. Bounded channels provide
/// backpressure.
pub struct AnyTlsStream {
    /// Stream ID (unique within session)
    id: u32,

    /// Receiver for incoming data from session (bounded for backpressure)
    data_rx: mpsc::Receiver<Bytes>,

    /// Buffer for partial reads - uses Bytes for O(1) advance without memmove
    read_buffer: Bytes,

    /// Offset into read_buffer for partial consumption
    read_offset: usize,

    /// Poll-based sender for outgoing data to session (bounded with backpressure)
    data_tx: PollSender<(u32, Bytes)>,

    /// Shared flag indicating session closure
    session_closed: Arc<AtomicBool>,

    /// Local stream closed flag
    stream_closed: bool,

    /// Flag indicating shutdown is in progress (FIN being sent)
    shutdown_in_progress: bool,

    /// Flag to track if we've received EOF
    eof: bool,
}

impl AnyTlsStream {
    pub fn new(
        id: u32,
        data_rx: mpsc::Receiver<Bytes>,
        data_tx: mpsc::Sender<(u32, Bytes)>,
        session_closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            id,
            data_rx,
            read_buffer: Bytes::new(),
            read_offset: 0,
            data_tx: PollSender::new(data_tx),
            session_closed,
            stream_closed: false,
            shutdown_in_progress: false,
            eof: false,
        }
    }

    /// Get the stream ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Best-effort FIN send for Drop (cannot block in Drop)
    fn send_fin_best_effort(&mut self) {
        if let Some(sender) = self.data_tx.get_ref() {
            let _ = sender.try_send((self.id, Bytes::new()));
        }
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.stream_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        let remaining_in_buffer = self.read_buffer.len() - self.read_offset;
        if self.eof && remaining_in_buffer == 0 {
            return Poll::Ready(Ok(()));
        }

        if remaining_in_buffer > 0 {
            let n = std::cmp::min(remaining_in_buffer, buf.remaining());
            buf.put_slice(&self.read_buffer[self.read_offset..self.read_offset + n]);
            self.read_offset += n;

            if self.read_offset >= self.read_buffer.len() {
                self.read_buffer = Bytes::new();
                self.read_offset = 0;
            }

            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.data_rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                if data.is_empty() {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }

                let n = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..n]);

                if n < data.len() {
                    self.read_buffer = data;
                    self.read_offset = n;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.stream_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        if self.shutdown_in_progress {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream is shutting down",
            )));
        }

        if self.session_closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session closed",
            )));
        }

        match self.data_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let write_len = buf.len().min(MAX_FRAME_DATA_SIZE);
                let data = Bytes::copy_from_slice(&buf[..write_len]);
                let id = self.id;
                match self.data_tx.send_item((id, data)) {
                    Ok(()) => Poll::Ready(Ok(write_len)),
                    Err(_) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "session channel closed",
                    ))),
                }
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.stream_closed {
            return Poll::Ready(Ok(()));
        }

        if self.session_closed.load(Ordering::Relaxed) {
            self.stream_closed = true;
            return Poll::Ready(Ok(()));
        }

        self.shutdown_in_progress = true;

        match self.data_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let id = self.id;
                match self.data_tx.send_item((id, Bytes::new())) {
                    Ok(()) => {
                        self.stream_closed = true;
                        Poll::Ready(Ok(()))
                    }
                    Err(_) => {
                        self.stream_closed = true;
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "session channel closed during shutdown",
                        )))
                    }
                }
            }
            Poll::Ready(Err(_)) => {
                self.stream_closed = true;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "session channel closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        if !self.stream_closed {
            self.stream_closed = true;
            self.send_fin_best_effort();
        }
    }
}

impl AsyncPing for AnyTlsStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for AnyTlsStream {}

