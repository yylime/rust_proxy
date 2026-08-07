//! Async stream traits shared by the protocol implementations,
//! ported from shoes (src/async_stream.rs).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

use crate::address::NetLocation;

pub trait AsyncPing {
    fn supports_ping(&self) -> bool;

    /// Write a ping message to the stream, if supported.
    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>>;
}

pub trait AsyncReadMessage {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncWriteMessage {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncFlushMessage {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>;
}

pub trait AsyncShutdownMessage {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>>;
}

/// Extension trait that provides an async `shutdown_message()` method for types
/// implementing `AsyncShutdownMessage`.
pub trait AsyncShutdownMessageExt: AsyncShutdownMessage {
    fn shutdown_message(&mut self) -> ShutdownMessageFuture<'_, Self>
    where
        Self: Unpin,
    {
        ShutdownMessageFuture { stream: self }
    }
}

pub struct ShutdownMessageFuture<'a, T: ?Sized> {
    stream: &'a mut T,
}

impl<T: AsyncShutdownMessage + Unpin + ?Sized> Future for ShutdownMessageFuture<'_, T> {
    type Output = std::io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.stream).poll_shutdown_message(cx)
    }
}

impl<T: AsyncShutdownMessage + ?Sized> AsyncShutdownMessageExt for T {}

pub trait AsyncReadTargetedMessage {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>>;
}

pub trait AsyncWriteSourcedMessage {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>>;
}

impl AsyncReadMessage for UdpSocket {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_recv(cx, buf)
    }
}

impl AsyncWriteMessage for UdpSocket {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        self.poll_send(cx, buf).map(|result| result.map(|_| ()))
    }
}

impl AsyncFlushMessage for UdpSocket {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for UdpSocket {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub trait AsyncStream: AsyncRead + AsyncWrite + AsyncPing + Unpin + Send + Sync {}

pub trait AsyncMessageStream:
    AsyncReadMessage
    + AsyncWriteMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

/// Server stream trait connected to proxy clients, where received messages
/// have a target address, and we write forwarded messages along with the
/// source address we received them from.
pub trait AsyncTargetedMessageStream:
    AsyncReadTargetedMessage
    + AsyncWriteSourcedMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

impl AsyncPing for TcpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

impl AsyncStream for TcpStream {}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncPing for tokio_rustls::server::TlsStream<T> {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncStream
    for tokio_rustls::server::TlsStream<T>
{
}

impl AsyncPing for UdpSocket {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

impl AsyncMessageStream for UdpSocket {}

impl<T: ?Sized + AsyncPing + Unpin> AsyncPing for Box<T> {
    fn supports_ping(&self) -> bool {
        (**self).supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut **self).poll_write_ping(cx)
    }
}

impl<T: ?Sized + AsyncPing + Unpin> AsyncPing for &mut T {
    fn supports_ping(&self) -> bool {
        (**self).supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut **self).poll_write_ping(cx)
    }
}

impl<T: ?Sized + AsyncReadMessage + Unpin> AsyncReadMessage for Box<T> {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_read_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadMessage + Unpin> AsyncReadMessage for &mut T {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_read_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteMessage + Unpin> AsyncWriteMessage for Box<T> {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteMessage + Unpin> AsyncWriteMessage for &mut T {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncFlushMessage + Unpin> AsyncFlushMessage for Box<T> {
    fn poll_flush_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_flush_message(cx)
    }
}

impl<T: ?Sized + AsyncFlushMessage + Unpin> AsyncFlushMessage for &mut T {
    fn poll_flush_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_flush_message(cx)
    }
}

impl<T: ?Sized + AsyncShutdownMessage + Unpin> AsyncShutdownMessage for Box<T> {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_shutdown_message(cx)
    }
}

impl<T: ?Sized + AsyncShutdownMessage + Unpin> AsyncShutdownMessage for &mut T {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_shutdown_message(cx)
    }
}

impl<T: ?Sized + AsyncReadTargetedMessage + Unpin> AsyncReadTargetedMessage for Box<T> {
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        Pin::new(&mut **self).poll_read_targeted_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadTargetedMessage + Unpin> AsyncReadTargetedMessage for &mut T {
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        Pin::new(&mut **self).poll_read_targeted_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteSourcedMessage + Unpin> AsyncWriteSourcedMessage for Box<T> {
    fn poll_write_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_sourced_message(cx, buf, source)
    }
}

impl<T: ?Sized + AsyncWriteSourcedMessage + Unpin> AsyncWriteSourcedMessage for &mut T {
    fn poll_write_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_sourced_message(cx, buf, source)
    }
}

impl<T: ?Sized + AsyncStream + Unpin> AsyncStream for Box<T> {}
impl<T: ?Sized + AsyncStream + Unpin> AsyncStream for &mut T {}

impl<T: ?Sized + AsyncMessageStream + Unpin> AsyncMessageStream for Box<T> {}
impl<T: ?Sized + AsyncMessageStream + Unpin> AsyncMessageStream for &mut T {}

impl<T: ?Sized + AsyncTargetedMessageStream + Unpin> AsyncTargetedMessageStream for Box<T> {}
impl<T: ?Sized + AsyncTargetedMessageStream + Unpin> AsyncTargetedMessageStream for &mut T {}
