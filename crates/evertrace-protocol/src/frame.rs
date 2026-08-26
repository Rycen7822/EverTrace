use std::io;

#[cfg(feature = "runtime")]
use std::time::Duration;

use serde::Serialize;
#[cfg(feature = "runtime")]
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
    match timeout(frame_timeout, reader.read_exact(&mut prefix)).await {
        Err(_) => return Err(FrameError::Timeout),
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(FrameError::Closed);
        }
        Ok(Err(error)) => return Err(FrameError::Io(error)),
        Ok(Ok(_)) => {}
    }
    let length = u32::from_be_bytes(prefix) as usize;
    if length > max_payload {
        return Err(FrameError::Oversize);
    }
    let mut payload = vec![0_u8; length];
    match timeout(frame_timeout, reader.read_exact(&mut payload)).await {
        Err(_) => return Err(FrameError::Timeout),
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(FrameError::Closed);
        }
        Ok(Err(error)) => return Err(FrameError::Io(error)),
        Ok(Ok(_)) => {}
    }
    std::str::from_utf8(&payload).map_err(|_| FrameError::InvalidUtf8)?;
    let value: T = serde_json::from_slice(&payload).map_err(|_| FrameError::InvalidJson)?;
    if canonical_json(&value)? != payload {
        return Err(FrameError::NonCanonical);
    }
    Ok(value)
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
