#![forbid(unsafe_code)]
#![deny(warnings)]

//! Closed local protocol and secure Unix-domain socket lifecycle.

pub mod command;
pub mod dto;
pub mod envelope;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod notification;
pub mod response;

#[cfg(feature = "runtime")]
use std::{
    ffi::OsString,
    fs, io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "runtime")]
use command::Command;
#[cfg(feature = "runtime")]
use dto::{MAX_FRAME_SIZE, PROTOCOL_VERSION};
#[cfg(feature = "runtime")]
use envelope::{ClientEnvelope, ServerEnvelope};
#[cfg(feature = "runtime")]
use error::{ErrorCode, ProtocolError, WireError};
#[cfg(feature = "runtime")]
use frame::{FrameError, canonical_json, read_frame, write_frame};
#[cfg(feature = "runtime")]
use handshake::{HandshakeAck, valid_build_id};
#[cfg(feature = "runtime")]
use notification::{Notification, NotificationEnvelope};
#[cfg(feature = "runtime")]
use response::{HealthResponse, Response};
#[cfg(feature = "runtime")]
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::timeout,
};

#[cfg(feature = "runtime")]
const DEFAULT_CONNECTION_LIMIT: usize = 32;
#[cfg(feature = "runtime")]
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

#[cfg(feature = "runtime")]
#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub build_id: String,
    pub frame_timeout: Duration,
    pub connection_limit: usize,
}

#[cfg(feature = "runtime")]
impl ServerOptions {
    pub fn new(build_id: impl Into<String>) -> Self {
        Self {
            build_id: build_id.into(),
            frame_timeout: Duration::from_secs(2),
            connection_limit: DEFAULT_CONNECTION_LIMIT,
        }
    }

    pub fn with_frame_timeout(mut self, value: Duration) -> Self {
        self.frame_timeout = value.max(Duration::from_millis(10));
        self
    }
}

#[cfg(feature = "runtime")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

#[cfg(feature = "runtime")]
pub struct LocalServer {
    listener: UnixListener,
    socket_path: PathBuf,
    identity: SocketIdentity,
    options: Arc<ServerOptions>,
}

#[cfg(feature = "runtime")]
impl LocalServer {
    pub fn bind(data_dir: &Path, options: ServerOptions) -> Result<Self, ProtocolError> {
        if !valid_build_id(&options.build_id) {
            return Err(ProtocolError::InvalidBuildId);
        }
        let data_dir = prepare_data_dir(data_dir)?;
        let runtime_dir = data_dir.join("runtime");
        ensure_runtime_dir(&runtime_dir)?;
        let socket_path = runtime_dir.join("evertraced-v1.sock");
        prepare_socket_path(&socket_path)?;
        let listener = UnixListener::bind(&socket_path).map_err(ProtocolError::Bind)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .map_err(ProtocolError::Permissions)?;
        let metadata = checked_socket_metadata(&socket_path)?;
        Ok(Self {
            listener,
            socket_path,
            identity: socket_identity(&metadata),
            options: Arc::new(options),
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn run<F>(
        mut self,
        mut shutdown: watch::Receiver<bool>,
        health_handler: F,
    ) -> Result<(), ProtocolError>
    where
        F: Fn() -> Result<HealthResponse, ErrorCode> + Send + Sync + 'static,
    {
        let semaphore = Arc::new(Semaphore::new(self.options.connection_limit.max(1)));
        let health_handler = Arc::new(health_handler);
        let mut tasks = JoinSet::new();
        loop {
            while let Some(result) = tasks.try_join_next() {
                result.map_err(ProtocolError::ConnectionTask)?;
            }
            let permit = tokio::select! {
                result = semaphore.clone().acquire_owned() => result.map_err(|_| ProtocolError::Internal)?,
                result = tasks.join_next(), if !tasks.is_empty() => {
                    result.expect("non-empty join set").map_err(ProtocolError::ConnectionTask)?;
                    continue;
                }
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() { break; }
                    continue;
                }
            };
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.map_err(ProtocolError::Accept)?;
                    let options = Arc::clone(&self.options);
                    let health_handler = Arc::clone(&health_handler);
                    let connection_shutdown = shutdown.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = handle_connection(
                            stream,
                            &options,
                            health_handler.as_ref(),
                            connection_shutdown,
                        )
                        .await;
                    });
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    drop(permit);
                    result.expect("non-empty join set").map_err(ProtocolError::ConnectionTask)?;
                }
                result = shutdown.changed() => {
                    drop(permit);
                    if result.is_err() || *shutdown.borrow() { break; }
                }
            }
        }
        match timeout(SHUTDOWN_GRACE, async {
            while let Some(result) = tasks.join_next().await {
                result.map_err(ProtocolError::ConnectionTask)?;
            }
            Ok::<(), ProtocolError>(())
        })
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
            }
        }
        self.cleanup_socket()?;
        Ok(())
    }

    fn cleanup_socket(&mut self) -> Result<(), ProtocolError> {
        let metadata = match fs::symlink_metadata(&self.socket_path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(ProtocolError::Inspect(error)),
        };
        if metadata.file_type().is_socket() && socket_identity(&metadata) == self.identity {
            fs::remove_file(&self.socket_path).map_err(ProtocolError::Cleanup)?;
        }
        Ok(())
    }
}

#[cfg(feature = "runtime")]
impl Drop for LocalServer {
    fn drop(&mut self) {
        let _ = self.cleanup_socket();
    }
}

#[cfg(feature = "runtime")]
async fn handle_connection(
    mut stream: UnixStream,
    options: &ServerOptions,
    health_handler: &(impl Fn() -> Result<HealthResponse, ErrorCode> + ?Sized),
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ProtocolError> {
    let first = match read_frame::<ClientEnvelope>(
        &mut stream,
        MAX_FRAME_SIZE,
        options.frame_timeout,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            let code = frame_error_code(&error);
            let _ = send_wire_error(&mut stream, code, None, MAX_FRAME_SIZE, options).await;
            return Err(error.into());
        }
    };
    let handshake = match first {
        ClientEnvelope::Handshake(value) => value,
        ClientEnvelope::Command(value) => {
            let _ = send_wire_error(
                &mut stream,
                ErrorCode::InvalidInput,
                Some(value.request_id),
                MAX_FRAME_SIZE,
                options,
            )
            .await;
            return Err(ProtocolError::HandshakeRequired);
        }
    };
    if handshake.protocol_version != PROTOCOL_VERSION {
        let _ = send_wire_error(
            &mut stream,
            ErrorCode::ProtocolMismatch,
            None,
            MAX_FRAME_SIZE,
            options,
        )
        .await;
        return Err(ProtocolError::VersionMismatch);
    }
    if handshake.max_frame == 0 || !valid_build_id(&handshake.build_id) {
        let _ = send_wire_error(
            &mut stream,
            ErrorCode::InvalidInput,
            None,
            MAX_FRAME_SIZE,
            options,
        )
        .await;
        return Err(ProtocolError::InvalidNegotiation);
    }
    let negotiated_max = handshake.max_frame.min(MAX_FRAME_SIZE as u32);
    let ack = ServerEnvelope::HandshakeAck(HandshakeAck {
        protocol_version: PROTOCOL_VERSION,
        build_id: options.build_id.clone(),
        max_frame: negotiated_max,
    });
    if canonical_json(&ack)?.len() > negotiated_max as usize {
        let _ = send_wire_error(
            &mut stream,
            ErrorCode::ResourceExhausted,
            None,
            MAX_FRAME_SIZE,
            options,
        )
        .await;
        return Err(ProtocolError::InvalidNegotiation);
    }
    write_frame(
        &mut stream,
        &ack,
        negotiated_max as usize,
        options.frame_timeout,
    )
    .await?;
    loop {
        let message = tokio::select! {
            result = read_frame::<ClientEnvelope>(&mut stream, negotiated_max as usize, options.frame_timeout) => {
                match result {
                    Ok(value) => value,
                    Err(FrameError::Closed) => return Ok(()),
                    Err(error) => {
                        let code = frame_error_code(&error);
                        let _ = send_wire_error(&mut stream, code, None, negotiated_max as usize, options).await;
                        return Err(error.into());
                    }
                }
            }
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    let notification = ServerEnvelope::Notification(NotificationEnvelope {
                        notification: Notification::ServerStopping,
                    });
                    write_frame(&mut stream, &notification, negotiated_max as usize, options.frame_timeout).await?;
                    return Ok(());
                }
                continue;
            }
        };
        let command = match message {
            ClientEnvelope::Command(value) => value,
            ClientEnvelope::Handshake(_) => {
                let _ = send_wire_error(
                    &mut stream,
                    ErrorCode::InvalidInput,
                    None,
                    negotiated_max as usize,
                    options,
                )
                .await;
                return Err(ProtocolError::UnexpectedHandshake);
            }
        };
        match command.command {
            Command::Health => {
                let health = match health_handler() {
                    Ok(value) => value,
                    Err(code) => {
                        let _ = send_wire_error(
                            &mut stream,
                            code,
                            Some(command.request_id),
                            negotiated_max as usize,
                            options,
                        )
                        .await;
                        continue;
                    }
                };
                let response = ServerEnvelope::Response(response::ResponseEnvelope {
                    request_id: command.request_id,
                    response: Response::Health(health),
                });
                if canonical_json(&response)?.len() > negotiated_max as usize {
                    let _ = send_wire_error(
                        &mut stream,
                        ErrorCode::ResourceExhausted,
                        Some(command.request_id),
                        negotiated_max as usize,
                        options,
                    )
                    .await;
                    continue;
                }
                write_frame(
                    &mut stream,
                    &response,
                    negotiated_max as usize,
                    options.frame_timeout,
                )
                .await?;
            }
        }
    }
}

#[cfg(feature = "runtime")]
async fn send_wire_error(
    stream: &mut UnixStream,
    code: ErrorCode,
    request_id: Option<evertrace_domain::ids::RequestId>,
    max_frame: usize,
    options: &ServerOptions,
) -> Result<(), FrameError> {
    let message = ServerEnvelope::Error(WireError { code, request_id });
    write_frame(stream, &message, max_frame, options.frame_timeout).await
}

#[cfg(feature = "runtime")]
fn frame_error_code(error: &FrameError) -> ErrorCode {
    if matches!(error, FrameError::Oversize) {
        ErrorCode::ResourceExhausted
    } else {
        ErrorCode::InvalidInput
    }
}

#[cfg(feature = "runtime")]
pub async fn request_health(
    socket_path: &Path,
    build_id: impl Into<String>,
    frame_timeout: Duration,
) -> Result<HealthResponse, ProtocolError> {
    let build_id = build_id.into();
    if !valid_build_id(&build_id) {
        return Err(ProtocolError::InvalidBuildId);
    }
    let mut stream = timeout(frame_timeout, UnixStream::connect(socket_path))
        .await
        .map_err(|_| ProtocolError::Timeout)?
        .map_err(ProtocolError::Connect)?;
    let handshake = ClientEnvelope::Handshake(handshake::Handshake {
        protocol_version: PROTOCOL_VERSION,
        client_kind: dto::ClientKind::Cli,
        build_id,
        max_frame: MAX_FRAME_SIZE as u32,
    });
    write_frame(&mut stream, &handshake, MAX_FRAME_SIZE, frame_timeout).await?;
    let negotiated_max =
        match read_frame::<ServerEnvelope>(&mut stream, MAX_FRAME_SIZE, frame_timeout).await? {
            ServerEnvelope::HandshakeAck(ack)
                if ack.protocol_version == PROTOCOL_VERSION
                    && ack.max_frame != 0
                    && ack.max_frame <= MAX_FRAME_SIZE as u32
                    && valid_build_id(&ack.build_id) =>
            {
                ack.max_frame as usize
            }
            ServerEnvelope::HandshakeAck(_) => return Err(ProtocolError::InvalidNegotiation),
            ServerEnvelope::Error(error) => return Err(ProtocolError::Wire(error.code)),
            _ => return Err(ProtocolError::UnexpectedMessage),
        };
    let request_id = evertrace_domain::ids::RequestId::from_uuid(uuid::Uuid::now_v7())
        .map_err(|_| ProtocolError::Internal)?;
    let command = ClientEnvelope::Command(command::CommandEnvelope {
        request_id,
        command: Command::Health,
    });
    write_frame(&mut stream, &command, negotiated_max, frame_timeout).await?;
    match read_frame::<ServerEnvelope>(&mut stream, negotiated_max, frame_timeout).await? {
        ServerEnvelope::Response(value) if value.request_id == request_id => match value.response {
            Response::Health(health) if valid_health(&health) => Ok(health),
            Response::Health(_) => Err(ProtocolError::InvalidHealth),
        },
        ServerEnvelope::Response(_) => Err(ProtocolError::RequestIdMismatch),
        ServerEnvelope::Error(error) if error.request_id == Some(request_id) => {
            Err(ProtocolError::Wire(error.code))
        }
        ServerEnvelope::Error(_) => Err(ProtocolError::RequestIdMismatch),
        _ => Err(ProtocolError::UnexpectedMessage),
    }
}

#[cfg(feature = "runtime")]
fn valid_health(health: &HealthResponse) -> bool {
    health.protocol_version == PROTOCOL_VERSION
        && health.config_version == 1
        && health.mode == dto::HealthMode::Normal
        && health.algorithm_revision != 0
        && health.effective_config_hash.len() == 64
        && health
            .effective_config_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(feature = "runtime")]
pub fn resolve_data_dir<F>(
    raw: &str,
    home: Option<&Path>,
    mut env_lookup: F,
) -> Result<PathBuf, ProtocolError>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let expanded = if raw == "~" || raw.starts_with("~/") {
        let home = home.ok_or(ProtocolError::UnresolvedDataDir)?;
        if raw == "~" {
            home.to_path_buf()
        } else {
            home.join(&raw[2..])
        }
    } else if let Some(rest) = raw.strip_prefix("${") {
        let end = rest.find('}').ok_or(ProtocolError::UnresolvedDataDir)?;
        let name = &rest[..end];
        validate_env_name(name)?;
        let suffix = &rest[end + 1..];
        if !suffix.is_empty() && !suffix.starts_with('/') {
            return Err(ProtocolError::UnresolvedDataDir);
        }
        append_env_path(name, suffix, &mut env_lookup)?
    } else if let Some(rest) = raw.strip_prefix('$') {
        let end = rest.find('/').unwrap_or(rest.len());
        let name = &rest[..end];
        validate_env_name(name)?;
        append_env_path(name, &rest[end..], &mut env_lookup)?
    } else {
        PathBuf::from(raw)
    };
    if !expanded.is_absolute() {
        return Err(ProtocolError::UnresolvedDataDir);
    }
    Ok(expanded)
}

#[cfg(feature = "runtime")]
fn append_env_path<F>(
    name: &str,
    suffix: &str,
    env_lookup: &mut F,
) -> Result<PathBuf, ProtocolError>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let base = PathBuf::from(env_lookup(name).ok_or(ProtocolError::UnresolvedDataDir)?);
    if base.as_os_str().is_empty() || !base.is_absolute() {
        return Err(ProtocolError::UnresolvedDataDir);
    }
    Ok(if suffix.is_empty() {
        base
    } else {
        base.join(suffix.trim_start_matches('/'))
    })
}

#[cfg(feature = "runtime")]
fn validate_env_name(value: &str) -> Result<(), ProtocolError> {
    let mut bytes = value.bytes();
    if !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(ProtocolError::UnresolvedDataDir);
    }
    Ok(())
}

#[cfg(feature = "runtime")]
fn prepare_data_dir(path: &Path) -> Result<PathBuf, ProtocolError> {
    if !path.is_absolute() {
        return Err(ProtocolError::UnresolvedDataDir);
    }
    fs::create_dir_all(path).map_err(ProtocolError::CreateDirectory)?;
    path.canonicalize().map_err(ProtocolError::Canonicalize)
}

#[cfg(feature = "runtime")]
fn ensure_runtime_dir(path: &Path) -> Result<(), ProtocolError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => checked_runtime_metadata(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(ProtocolError::CreateDirectory)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(ProtocolError::Permissions)?;
            checked_runtime_metadata(&fs::symlink_metadata(path).map_err(ProtocolError::Inspect)?)
        }
        Err(error) => Err(ProtocolError::Inspect(error)),
    }
}

#[cfg(feature = "runtime")]
fn checked_runtime_metadata(metadata: &fs::Metadata) -> Result<(), ProtocolError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid()?
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(ProtocolError::InvalidRuntimeDirectory);
    }
    Ok(())
}

#[cfg(feature = "runtime")]
fn prepare_socket_path(path: &Path) -> Result<(), ProtocolError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(ProtocolError::Inspect(error)),
    };
    checked_socket_metadata_value(&metadata)?;
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(ProtocolError::AlreadyRunning),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            let identity = socket_identity(&metadata);
            let current = fs::symlink_metadata(path).map_err(ProtocolError::Inspect)?;
            checked_socket_metadata_value(&current)?;
            if socket_identity(&current) != identity {
                return Err(ProtocolError::SocketReplaced);
            }
            fs::remove_file(path).map_err(ProtocolError::Cleanup)
        }
        Err(error) => Err(ProtocolError::Connect(error)),
    }
}

#[cfg(feature = "runtime")]
fn checked_socket_metadata(path: &Path) -> Result<fs::Metadata, ProtocolError> {
    let metadata = fs::symlink_metadata(path).map_err(ProtocolError::Inspect)?;
    checked_socket_metadata_value(&metadata)?;
    Ok(metadata)
}

#[cfg(feature = "runtime")]
fn checked_socket_metadata_value(metadata: &fs::Metadata) -> Result<(), ProtocolError> {
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != effective_uid()?
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(ProtocolError::InvalidSocket);
    }
    Ok(())
}

#[cfg(feature = "runtime")]
fn socket_identity(metadata: &fs::Metadata) -> SocketIdentity {
    SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
    }
}

#[cfg(feature = "runtime")]
fn effective_uid() -> Result<u32, ProtocolError> {
    let status = fs::read_to_string("/proc/self/status").map_err(ProtocolError::Identity)?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or(ProtocolError::IdentityUnavailable)?;
    line.split_ascii_whitespace()
        .nth(2)
        .and_then(|value| value.parse().ok())
        .ok_or(ProtocolError::IdentityUnavailable)
}
