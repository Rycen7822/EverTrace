#[cfg(feature = "runtime")]
use std::io;

pub use evertrace_domain::error::ErrorCode;
use evertrace_domain::ids::RequestId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SyncProtocolError {
    #[error("recovery barrier input is invalid")]
    InvalidInput,
    #[error("recovery barrier connection failed")]
    Connect,
    #[error("recovery barrier framing failed")]
    Frame,
    #[error("recovery barrier negotiation failed")]
    Negotiation,
    #[error("recovery barrier response is invalid")]
    InvalidResponse,
    #[error("recovery barrier timed out")]
    Timeout,
    #[error("recovery barrier daemon error")]
    Wire,
    #[error("recovery barrier request was not admitted")]
    NotAdmitted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireError {
    pub code: ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
}

#[cfg(feature = "runtime")]
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("accept failed")]
    Accept(#[source] io::Error),
    #[error("daemon is already running")]
    AlreadyRunning,
    #[error("bind failed")]
    Bind(#[source] io::Error),
    #[error("data directory canonicalization failed")]
    Canonicalize(#[source] io::Error),
    #[error("socket cleanup failed")]
    Cleanup(#[source] io::Error),
    #[error("connection failed")]
    Connect(#[source] io::Error),
    #[error("connection task failed")]
    ConnectionTask(#[source] tokio::task::JoinError),
    #[error("directory creation failed")]
    CreateDirectory(#[source] io::Error),
    #[error(transparent)]
    Frame(#[from] crate::frame::FrameError),
    #[error("handshake required")]
    HandshakeRequired,
    #[error("process identity lookup failed")]
    Identity(#[source] io::Error),
    #[error("process identity unavailable")]
    IdentityUnavailable,
    #[error("path inspection failed")]
    Inspect(#[source] io::Error),
    #[error("internal protocol failure")]
    Internal,
    #[error("build identifier is invalid")]
    InvalidBuildId,
    #[error("peer returned invalid health data")]
    InvalidHealth,
    #[error("peer returned invalid recovery terminal data")]
    InvalidRecoveryTerminal,
    #[error("peer returned invalid frame negotiation")]
    InvalidNegotiation,
    #[error("runtime directory is not a private owned directory")]
    InvalidRuntimeDirectory,
    #[error("socket is not a private owned Unix socket")]
    InvalidSocket,
    #[error("permission update failed")]
    Permissions(#[source] io::Error),
    #[error("socket was replaced")]
    SocketReplaced,
    #[error("response request ID does not match")]
    RequestIdMismatch,
    #[error("operation timed out")]
    Timeout,
    #[error("data directory could not be resolved")]
    UnresolvedDataDir,
    #[error("unexpected handshake")]
    UnexpectedHandshake,
    #[error("unexpected protocol message")]
    UnexpectedMessage,
    #[error("protocol version mismatch")]
    VersionMismatch,
    #[error("wire error: {0}")]
    Wire(ErrorCode),
}
