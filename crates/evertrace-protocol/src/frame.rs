use std::io::{self, Read, Write};

#[cfg(feature = "runtime")]
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
#[cfg(feature = "runtime")]
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("connection closed")]
    Closed,
    #[error("frame contains invalid JSON")]
    InvalidJson,
    #[error("frame contains invalid UTF-8")]
    InvalidUtf8,
    #[error("frame is not canonical JSON")]
    NonCanonical,
    #[error("frame exceeds the negotiated limit")]
    Oversize,
    #[error("frame serialization failed")]
    Serialization,
    #[error("frame I/O failed")]
    Io(#[source] io::Error),
    #[error("frame I/O timed out")]
    Timeout,
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    serde_json::to_vec(value).map_err(|_| FrameError::Serialization)
}

pub fn read_frame_sync<T>(reader: &mut impl Read, max_payload: usize) -> Result<T, FrameError>
where
    T: DeserializeOwned + Serialize,
{
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).map_err(map_sync_read)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > max_payload {
        return Err(FrameError::Oversize);
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).map_err(map_sync_read)?;
    decode_payload(payload)
}

pub fn write_frame_sync<T: Serialize>(
    writer: &mut impl Write,
    value: &T,
    max_payload: usize,
) -> Result<(), FrameError> {
    let payload = canonical_json(value)?;
    if payload.len() > max_payload || payload.len() > u32::MAX as usize {
        return Err(FrameError::Oversize);
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .and_then(|()| writer.write_all(&payload))
        .and_then(|()| writer.flush())
        .map_err(map_sync_write)
}

fn map_sync_read(error: io::Error) -> FrameError {
    match error.kind() {
        io::ErrorKind::UnexpectedEof => FrameError::Closed,
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => FrameError::Timeout,
        _ => FrameError::Io(error),
    }
}

fn map_sync_write(error: io::Error) -> FrameError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => FrameError::Timeout,
        _ => FrameError::Io(error),
    }
}

#[cfg(feature = "runtime")]
pub async fn read_frame<T>(
    reader: &mut (impl AsyncRead + Unpin),
    max_payload: usize,
    frame_timeout: Duration,
) -> Result<T, FrameError>
where
    T: DeserializeOwned + Serialize,
{
    let mut prefix = [0_u8; 4];
    read_exact_timeout(reader, &mut prefix, frame_timeout).await?;
    read_frame_after_prefix(reader, prefix, max_payload, frame_timeout).await
}

#[cfg(feature = "runtime")]
pub(crate) async fn read_frame_after_idle<T>(
    reader: &mut (impl AsyncRead + Unpin),
    max_payload: usize,
    frame_timeout: Duration,
) -> Result<T, FrameError>
where
    T: DeserializeOwned + Serialize,
{
    let mut prefix = [0_u8; 4];
    reader
        .read_exact(&mut prefix[..1])
        .await
        .map_err(map_async_read)?;
    read_exact_timeout(reader, &mut prefix[1..], frame_timeout).await?;
    read_frame_after_prefix(reader, prefix, max_payload, frame_timeout).await
}

#[cfg(feature = "runtime")]
async fn read_frame_after_prefix<T>(
    reader: &mut (impl AsyncRead + Unpin),
    prefix: [u8; 4],
    max_payload: usize,
    frame_timeout: Duration,
) -> Result<T, FrameError>
where
    T: DeserializeOwned + Serialize,
{
    let length = u32::from_be_bytes(prefix) as usize;
    if length > max_payload {
        return Err(FrameError::Oversize);
    }
    let mut payload = vec![0_u8; length];
    read_exact_timeout(reader, &mut payload, frame_timeout).await?;
    decode_payload(payload)
}

fn decode_payload<T>(payload: Vec<u8>) -> Result<T, FrameError>
where
    T: DeserializeOwned + Serialize,
{
    std::str::from_utf8(&payload).map_err(|_| FrameError::InvalidUtf8)?;
    let value: T = serde_json::from_slice(&payload).map_err(|_| FrameError::InvalidJson)?;
    if canonical_json(&value)? != payload {
        return Err(FrameError::NonCanonical);
    }
    Ok(value)
}

#[cfg(feature = "runtime")]
async fn read_exact_timeout(
    reader: &mut (impl AsyncRead + Unpin),
    buffer: &mut [u8],
    frame_timeout: Duration,
) -> Result<(), FrameError> {
    timeout(frame_timeout, reader.read_exact(buffer))
        .await
        .map_err(|_| FrameError::Timeout)?
        .map(|_| ())
        .map_err(map_async_read)
}

#[cfg(feature = "runtime")]
fn map_async_read(error: io::Error) -> FrameError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        FrameError::Closed
    } else {
        FrameError::Io(error)
    }
}

#[cfg(feature = "runtime")]
pub async fn write_frame<T: Serialize>(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &T,
    max_payload: usize,
    frame_timeout: Duration,
) -> Result<(), FrameError> {
    let payload = canonical_json(value)?;
    if payload.len() > max_payload || payload.len() > u32::MAX as usize {
        return Err(FrameError::Oversize);
    }
    let prefix = (payload.len() as u32).to_be_bytes();
    timeout(frame_timeout, async {
        writer.write_all(&prefix).await?;
        writer.write_all(&payload).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| FrameError::Timeout)?
    .map_err(FrameError::Io)
}
