use std::{mem::size_of, pin::Pin};

use color_eyre::eyre::Context;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Maximum buffer size required to include the UDP datagram + a length header.
pub const MAX_PACKET_SIZE: usize = size_of::<u16>() + u16::MAX as usize;

/// Creates and returns a buffer on the heap with enough space to contain any possible
/// UDP datagram.
///
/// This is put on the heap and in a separate function to avoid the 64k buffer from ending
/// up on the stack and blowing up the size of the futures using it.
#[inline]
pub fn datagram_buffer() -> Box<[u8; MAX_PACKET_SIZE]> {
    Box::new([0u8; MAX_PACKET_SIZE])
}

/// Serialize an UDP datagram into the provided buffer.
#[inline]
pub fn serialize_datagram(buf: &mut [u8], datagram: &[u8]) -> usize {
    let len = datagram.len();
    buf[..size_of::<u16>()].copy_from_slice(&(len as u16).to_be_bytes()[..]);
    buf[size_of::<u16>()..size_of::<u16>() + len].copy_from_slice(&datagram[..len]);
    size_of::<u16>() + len
}

/// Deserialize a source of bytes into an UDP datagram at the provided buffer.
#[inline]
pub async fn deserialize_datagram<R: AsyncRead + Unpin>(
    buf: &mut [u8],
    source: &mut Pin<&mut R>,
) -> color_eyre::Result<usize> {
    let len = source
        .read_u16()
        .await
        .with_context(|| "Couldn't read UDP datagram size from source")?;
    source
        .read_exact(&mut buf[..len as usize])
        .await
        .with_context(|| "Couldn't read UDP data size from source")?;
    Ok(len as usize)
}
