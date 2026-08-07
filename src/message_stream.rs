//! Message-oriented stream wrappers used by the AnyTLS UDP-over-TCP support,
//! ported from shoes (src/vless/vless_message_stream.rs,
//! src/uot/uot_v1_server_stream.rs, src/uot/uot_common.rs,
//! src/uot/socks_addr.rs, src/slide_buffer.rs).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::ReadBuf;

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncReadTargetedMessage,
    AsyncShutdownMessage, AsyncStream, AsyncTargetedMessageStream, AsyncWriteMessage,
    AsyncWriteSourcedMessage,
};
use crate::util::allocate_vec;

// ============================ SlideBuffer ============================

/// A fixed-capacity sliding buffer with zero-allocation read/write operations.
pub struct SlideBuffer {
    data: Box<[u8]>,
    start: usize,
    end: usize,
}

impl SlideBuffer {
    #[inline]
    pub fn new(capacity: usize) -> Self {
        Self {
            data: allocate_vec(capacity).into_boxed_slice(),
            start: 0,
            end: 0,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    #[inline]
    pub fn remaining_capacity(&self) -> usize {
        self.data.len() - self.end
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.start..self.end]
    }

    #[inline]
    pub fn write_slice(&mut self) -> &mut [u8] {
        &mut self.data[self.end..]
    }

    #[inline]
    pub fn advance_write(&mut self, n: usize) {
        debug_assert!(
            self.end + n <= self.data.len(),
            "SlideBuffer advance_write overflow"
        );
        self.end += n;
    }

    #[inline]
    pub fn consume(&mut self, n: usize) {
        debug_assert!(
            n <= self.len(),
            "SlideBuffer consume underflow: n={}, len={}",
            n,
            self.len()
        );
        self.start += n;
        if self.start >= self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    #[inline]
    pub fn maybe_compact(&mut self, threshold: usize) {
        if self.start > threshold {
            if self.start < self.end {
                self.data.copy_within(self.start..self.end, 0);
                self.end -= self.start;
            } else {
                self.end = 0;
            }
            self.start = 0;
        }
    }
}

// ===================== UoT / SOCKS address codecs =====================

/// UoT AddrParser ATYP values (used in V1 / V2 non-connect packets).
pub const UOT_ATYP_IPV4: u8 = 0x00;
pub const UOT_ATYP_IPV6: u8 = 0x01;
pub const UOT_ATYP_DOMAIN: u8 = 0x02;

/// Parse a UoT AddrParser address (ATYP + address + port).
/// Returns `Ok(Some((NetLocation, bytes consumed)))` on success,
/// `Ok(None)` if truncated, `Err` on invalid data.
#[inline]
pub fn parse_uot_address(data: &[u8]) -> std::io::Result<Option<(NetLocation, usize)>> {
    if data.is_empty() {
        return Ok(None);
    }
    let atyp = data[0];
    match atyp {
        UOT_ATYP_IPV4 => {
            if data.len() < 7 {
                return Ok(None);
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok(Some((NetLocation::new(Address::Ipv4(ip), port), 7)))
        }
        UOT_ATYP_IPV6 => {
            if data.len() < 19 {
                return Ok(None);
            }
            let ip_bytes: [u8; 16] = data[1..17].try_into().unwrap();
            let ip = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok(Some((NetLocation::new(Address::Ipv6(ip), port), 19)))
        }
        UOT_ATYP_DOMAIN => {
            if data.len() < 2 {
                return Ok(None);
            }
            let domain_len = data[1] as usize;
            let total_len = 1 + 1 + domain_len + 2;
            if data.len() < total_len {
                return Ok(None);
            }
            let domain = std::str::from_utf8(&data[2..2 + domain_len])
                .map_err(|e| std::io::Error::other(format!("invalid domain: {e}")))?;
            let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
            Ok(Some((
                NetLocation::new(Address::Hostname(domain.to_string()), port),
                total_len,
            )))
        }
        _ => Err(std::io::Error::other(format!("unknown UoT ATYP: {atyp}"))),
    }
}

/// Write a UoT AddrParser address (ATYP + address + port). Returns bytes written.
#[inline]
pub fn write_uot_address(buf: &mut [u8], addr: &SocketAddr) -> usize {
    match addr {
        SocketAddr::V4(v4) => {
            buf[0] = UOT_ATYP_IPV4;
            buf[1..5].copy_from_slice(&v4.ip().octets());
            buf[5..7].copy_from_slice(&v4.port().to_be_bytes());
            7
        }
        SocketAddr::V6(v6) => {
            buf[0] = UOT_ATYP_IPV6;
            buf[1..17].copy_from_slice(&v6.ip().octets());
            buf[17..19].copy_from_slice(&v6.port().to_be_bytes());
            19
        }
    }
}

// ========================= PacketAddrStream ==========================

/// Buffer size for reading and writing packet-address frames.
const BUFFER_SIZE: usize = 65535;

type ParseFn = fn(&[u8]) -> std::io::Result<Option<(NetLocation, usize)>>;

struct AddressCodec {
    parse: ParseFn,
    write: fn(&mut [u8], &SocketAddr) -> usize,
}

const UOT_ADDR_CODEC: AddressCodec = AddressCodec {
    parse: parse_uot_address,
    write: write_uot_address,
};

/// Packet-address stream for multi-destination UDP transports (UoT V1/V2
/// non-connect). Frame format:
/// `| ATYP | address | port | length | data |`
pub struct PacketAddrStream<S> {
    stream: S,
    codec: &'static AddressCodec,
    read_buf: SlideBuffer,
    write_buf: Box<[u8]>,
    write_buf_len: usize,
    write_buf_sent: usize,
    is_eof: bool,
}

impl<S: AsyncStream> PacketAddrStream<S> {
    fn new_with_codec(stream: S, codec: &'static AddressCodec) -> Self {
        Self {
            stream,
            codec,
            read_buf: SlideBuffer::new(BUFFER_SIZE),
            write_buf: allocate_vec(BUFFER_SIZE).into_boxed_slice(),
            write_buf_len: 0,
            write_buf_sent: 0,
            is_eof: false,
        }
    }

    /// Create a stream that uses sing UoT `AddrParser` packet addresses.
    pub fn new_uot(stream: S) -> Self {
        Self::new_with_codec(stream, &UOT_ADDR_CODEC)
    }

    #[inline]
    fn try_parse_packet(&self) -> std::io::Result<Option<(NetLocation, usize, usize)>> {
        let data = self.read_buf.as_slice();
        let (location, addr_len) = match (self.codec.parse)(data)? {
            Some(result) => result,
            None => return Ok(None),
        };
        if data.len() < addr_len + 2 {
            return Ok(None);
        }
        let payload_len = u16::from_be_bytes([data[addr_len], data[addr_len + 1]]) as usize;
        let payload_start = addr_len + 2;
        let total_len = payload_start + payload_len;
        if data.len() < total_len {
            return Ok(None);
        }
        Ok(Some((location, payload_start, payload_len)))
    }
}

impl<S: AsyncStream> AsyncReadTargetedMessage for PacketAddrStream<S> {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let this = self.get_mut();

        if this.is_eof {
            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
        }

        loop {
            match this.try_parse_packet()? {
                Some((location, payload_start, payload_len)) => {
                    let data = this.read_buf.as_slice();
                    buf.put_slice(&data[payload_start..payload_start + payload_len]);
                    let total_consumed = payload_start + payload_len;
                    this.read_buf.consume(total_consumed);
                    return Poll::Ready(Ok(location));
                }
                None => {}
            }

            this.read_buf.maybe_compact(4096);
            if this.read_buf.remaining_capacity() == 0 {
                return Poll::Ready(Err(std::io::Error::other(
                    "packet-address read buffer full but no complete packet",
                )));
            }

            let write_slice = this.read_buf.write_slice();
            let mut read_buf = ReadBuf::new(write_slice);
            match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let bytes_read = read_buf.filled().len();
                    if bytes_read == 0 {
                        this.is_eof = true;
                        return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
                    }
                    this.read_buf.advance_write(bytes_read);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncStream> AsyncWriteSourcedMessage for PacketAddrStream<S> {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        while this.write_buf_sent < this.write_buf_len {
            let remaining = &this.write_buf[this.write_buf_sent..this.write_buf_len];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf_sent += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.write_buf_len = 0;
        this.write_buf_sent = 0;

        let addr_len = match source {
            SocketAddr::V4(_) => 7,
            SocketAddr::V6(_) => 19,
        };
        let total_len = addr_len + 2 + buf.len();
        if total_len > this.write_buf.len() {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "packet-address frame too large: {total_len} > {}",
                this.write_buf.len()
            ))));
        }

        let offset = (this.codec.write)(&mut this.write_buf, source);
        let len_bytes = (buf.len() as u16).to_be_bytes();
        this.write_buf[offset..offset + 2].copy_from_slice(&len_bytes);
        let data_start = offset + 2;
        this.write_buf[data_start..data_start + buf.len()].copy_from_slice(buf);
        this.write_buf_len = data_start + buf.len();

        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncFlushMessage for PacketAddrStream<S> {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while this.write_buf_sent < this.write_buf_len {
            let remaining = &this.write_buf[this.write_buf_sent..this.write_buf_len];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf_sent += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.write_buf_len = 0;
        this.write_buf_sent = 0;
        Pin::new(&mut this.stream).poll_flush(cx)
    }
}

impl<S: AsyncStream> AsyncShutdownMessage for PacketAddrStream<S> {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();
        ready!(Pin::new(&mut this).poll_flush_message(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl<S: AsyncStream> AsyncPing for PacketAddrStream<S> {
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

impl<S: AsyncStream> AsyncTargetedMessageStream for PacketAddrStream<S> {}

pub type UotV1ServerStream<S> = PacketAddrStream<S>;

// ========================= VlessMessageStream =========================

/// Length-prefixed (u16be) message stream, used by UoT V2 connect mode.
pub struct VlessMessageStream<S> {
    stream: S,
    read_buf: Box<[u8]>,
    read_end_index: usize,
    pending_write: Vec<u8>,
    write_offset: usize,
    is_eof: bool,
}

impl<S: AsyncStream> VlessMessageStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_buf: allocate_vec(65537).into_boxed_slice(),
            read_end_index: 0,
            pending_write: Vec::with_capacity(65537),
            write_offset: 0,
            is_eof: false,
        }
    }
}

impl<S: AsyncStream> AsyncReadMessage for VlessMessageStream<S> {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out_buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.is_eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.read_end_index >= 2 {
                let payload_len =
                    u16::from_be_bytes([this.read_buf[0], this.read_buf[1]]) as usize;
                let total_len = 2 + payload_len;
                if this.read_end_index >= total_len {
                    if out_buf.remaining() < payload_len {
                        return Poll::Ready(Err(std::io::Error::other(
                            "out_buf is too small to hold the message",
                        )));
                    }
                    out_buf.put_slice(&this.read_buf[2..total_len]);
                    if this.read_end_index > total_len {
                        this.read_buf.copy_within(total_len..this.read_end_index, 0);
                        this.read_end_index -= total_len;
                    } else {
                        this.read_end_index = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
            }

            let read_buf_slice = &mut this.read_buf[this.read_end_index..];
            assert!(!read_buf_slice.is_empty());
            let mut tmp = ReadBuf::new(read_buf_slice);
            match Pin::new(&mut this.stream).poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(())) => {
                    let n = tmp.filled().len();
                    if n == 0 {
                        this.is_eof = true;
                        if this.read_end_index == 0 {
                            return Poll::Ready(Ok(()));
                        } else {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "EOF reached in the middle of a message",
                            )));
                        }
                    }
                    this.read_end_index += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncStream> AsyncWriteMessage for VlessMessageStream<S> {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();

        if !this.pending_write.is_empty() {
            if let Poll::Ready(Err(e)) = Pin::new(&mut this).poll_flush_message(cx) {
                return Poll::Ready(Err(e));
            }
            if !this.pending_write.is_empty() {
                return Poll::Pending;
            }
        }

        if buf.len() > 65535 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "message size too large",
            )));
        }

        this.pending_write
            .extend_from_slice(&(buf.len() as u16).to_be_bytes());
        this.pending_write.extend_from_slice(buf);
        this.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncFlushMessage for VlessMessageStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while this.write_offset < this.pending_write.len() {
            let chunk = &this.pending_write[this.write_offset..];
            match Pin::new(&mut this.stream).poll_write(cx, chunk) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "failed to write message",
                        )));
                    }
                    this.write_offset += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut this.stream).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.pending_write.clear();
                this.write_offset = 0;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncStream> AsyncShutdownMessage for VlessMessageStream<S> {
    fn poll_shutdown_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match <Self as AsyncFlushMessage>::poll_flush_message(Pin::new(this), cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl<S: AsyncStream> AsyncPing for VlessMessageStream<S> {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncMessageStream for VlessMessageStream<S> {}
