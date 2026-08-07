//! Small shared helpers, ported from shoes (src/util.rs).

use tokio::io::AsyncWriteExt;

/// Allocate a zero-initialized buffer of `len` bytes without going through
/// the slow path of `vec![0; len]` (the memory is then always fully written
/// before use by the callers).
#[inline]
pub fn allocate_vec(len: usize) -> Vec<u8> {
    let mut ret = Vec::with_capacity(len);
    unsafe {
        ret.set_len(len);
    }
    ret
}

/// A cancellable alternative to `AsyncWriteExt::write_all`.
#[inline]
pub async fn write_all<T: AsyncWriteExt + Unpin>(
    stream: &mut T,
    buf: &[u8],
) -> std::io::Result<()> {
    let mut i = 0;
    let n = buf.len();
    while i < n {
        let n = stream.write(&buf[i..]).await?;
        i += n;
    }
    Ok(())
}

