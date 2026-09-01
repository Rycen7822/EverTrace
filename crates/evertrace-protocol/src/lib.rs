#![forbid(unsafe_code)]
#![deny(warnings)]

//! Closed local protocol and secure Unix-domain socket lifecycle.

pub mod command;
pub mod dto;
pub mod envelope;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod mcp;
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
#[cfg(unix)]
use std::{os::unix::net::UnixStream as StdUnixStream, time::Instant};
#[cfg(all(unix, not(feature = "runtime")))]
use std::{path::Path, time::Duration};

#[cfg(feature = "runtime")]
use command::Command;
#[cfg(feature = "runtime")]
use dto::{MAX_FRAME_SIZE, PROTOCOL_VERSION};
#[cfg(feature = "runtime")]
use envelope::{ClientEnvelope, ServerEnvelope};
#[cfg(feature = "runtime")]
use error::{ErrorCode, ProtocolError, WireError};
#[cfg(feature = "runtime")]
use frame::{FrameError, canonical_json, read_frame, read_frame_after_idle, write_frame};
#[cfg(feature = "runtime")]
use handshake::{HandshakeAck, valid_build_id};
#[cfg(feature = "runtime")]
use notification::{Notification, NotificationEnvelope};
#[cfg(feature = "runtime")]
use response::{HealthResponse, RecoveryActionResponse, Response};
#[cfg(feature = "runtime")]
use tokio::{
    net::{
        UnixListener, UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
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
        self,
        shutdown: watch::Receiver<bool>,
        health_handler: F,
    ) -> Result<(), ProtocolError>
    where
        F: Fn() -> Result<HealthResponse, ErrorCode> + Send + Sync + 'static,
    {
        self.run_dispatch(shutdown, move |_request_id, command| {
            std::future::ready(match command {
                Command::Health => health_handler().map(Response::Health),
                Command::RecoveryBarrier(_) => Err(ErrorCode::InvalidInput),
                Command::RequestRecovery(_) => Err(ErrorCode::InvalidInput),
                Command::IssueMcpBinding(_)
                | Command::McpCall(_)
                | Command::RecallCue(_)
                | Command::SessionImportAdmin(_)
                | Command::HumanGovernance(_) => Err(ErrorCode::InvalidInput),
            })
        })
        .await
    }

    pub async fn run_dispatch<F, Fut>(
        self,
        shutdown: watch::Receiver<bool>,
        command_handler: F,
    ) -> Result<(), ProtocolError>
    where
        F: Fn(evertrace_domain::ids::RequestId, Command) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Response, ErrorCode>> + Send + 'static,
    {
        self.run_dispatch_with_context(shutdown, move |_context, request_id, command| {
            command_handler(request_id, command)
        })
        .await
    }

    pub async fn run_dispatch_with_context<F, Fut>(
        mut self,
        mut shutdown: watch::Receiver<bool>,
        command_handler: F,
    ) -> Result<(), ProtocolError>
    where
        F: Fn(dto::ConnectionContext, evertrace_domain::ids::RequestId, Command) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: std::future::Future<Output = Result<Response, ErrorCode>> + Send + 'static,
    {
        let semaphore = Arc::new(Semaphore::new(self.options.connection_limit.max(1)));
        let command_handler = Arc::new(command_handler);
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
                    let command_handler = Arc::clone(&command_handler);
                    let connection_shutdown = shutdown.clone();
                    let connection_id = uuid::Uuid::now_v7().to_string();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = handle_connection(
                            stream,
                            &options,
                            command_handler.as_ref(),
                            connection_shutdown,
                            connection_id,
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
async fn handle_connection<F, Fut>(
    mut stream: UnixStream,
    options: &ServerOptions,
    command_handler: &F,
    mut shutdown: watch::Receiver<bool>,
    connection_id: String,
) -> Result<(), ProtocolError>
where
    F: Fn(dto::ConnectionContext, evertrace_domain::ids::RequestId, Command) -> Fut + ?Sized,
    Fut: std::future::Future<Output = Result<Response, ErrorCode>> + Send,
{
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
    let connection_context = dto::ConnectionContext {
        connection_id,
        client_kind: handshake.client_kind,
    };
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
        {
            if let Command::RecoveryBarrier(locator) = &command.command
                && !locator.validate()
            {
                let _ = send_wire_error(
                    &mut stream,
                    ErrorCode::InvalidInput,
                    Some(command.request_id),
                    negotiated_max as usize,
                    options,
                )
                .await;
                continue;
            }
            let dispatched = match command_handler(
                connection_context.clone(),
                command.request_id,
                command.command,
            )
            .await
            {
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
                response: dispatched,
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
pub struct LocalClient {
    stream: UnixStream,
    negotiated_max: usize,
    frame_timeout: Duration,
}

#[cfg(feature = "runtime")]
pub struct LocalCommandSender {
    writer: OwnedWriteHalf,
    negotiated_max: usize,
    frame_timeout: Duration,
}

#[cfg(feature = "runtime")]
pub struct LocalIncomingReceiver {
    reader: OwnedReadHalf,
    negotiated_max: usize,
    frame_timeout: Duration,
}

#[cfg(feature = "runtime")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalIncoming {
    Response(response::ResponseEnvelope),
    Error(WireError),
    Notification(Notification),
}

#[cfg(feature = "runtime")]
impl LocalCommandSender {
    pub async fn send(&mut self, command: command::CommandEnvelope) -> Result<(), ProtocolError> {
        write_frame(
            &mut self.writer,
            &ClientEnvelope::Command(command),
            self.negotiated_max,
            self.frame_timeout,
        )
        .await?;
        Ok(())
    }
}

#[cfg(feature = "runtime")]
impl LocalIncomingReceiver {
    pub async fn recv(&mut self) -> Result<LocalIncoming, ProtocolError> {
        match read_frame_after_idle::<ServerEnvelope>(
            &mut self.reader,
            self.negotiated_max,
            self.frame_timeout,
        )
        .await?
        {
            ServerEnvelope::Response(value) => Ok(LocalIncoming::Response(value)),
            ServerEnvelope::Error(value) => Ok(LocalIncoming::Error(value)),
            ServerEnvelope::Notification(value) => {
                Ok(LocalIncoming::Notification(value.notification))
            }
            ServerEnvelope::HandshakeAck(_) => Err(ProtocolError::UnexpectedMessage),
        }
    }
}

#[cfg(feature = "runtime")]
impl LocalClient {
    pub async fn connect(
        socket_path: &Path,
        build_id: impl Into<String>,
        client_kind: dto::ClientKind,
        frame_timeout: Duration,
    ) -> Result<Self, ProtocolError> {
        let build_id = build_id.into();
        if !valid_build_id(&build_id) {
            return Err(ProtocolError::InvalidBuildId);
        }
        let mut stream = timeout(frame_timeout, UnixStream::connect(socket_path))
            .await
            .map_err(|_| ProtocolError::Timeout)?
            .map_err(ProtocolError::Connect)?;
        write_frame(
            &mut stream,
            &ClientEnvelope::Handshake(handshake::Handshake {
                protocol_version: PROTOCOL_VERSION,
                client_kind,
                build_id,
                max_frame: MAX_FRAME_SIZE as u32,
            }),
            MAX_FRAME_SIZE,
            frame_timeout,
        )
        .await?;
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
        Ok(Self {
            stream,
            negotiated_max,
            frame_timeout,
        })
    }

    pub async fn request(
        &mut self,
        request_id: evertrace_domain::ids::RequestId,
        command: Command,
    ) -> Result<Response, ProtocolError> {
        write_frame(
            &mut self.stream,
            &ClientEnvelope::Command(command::CommandEnvelope {
                request_id,
                command,
            }),
            self.negotiated_max,
            self.frame_timeout,
        )
        .await?;
        match read_frame::<ServerEnvelope>(
            &mut self.stream,
            self.negotiated_max,
            self.frame_timeout,
        )
        .await?
        {
            ServerEnvelope::Response(value) if value.request_id == request_id => Ok(value.response),
            ServerEnvelope::Response(_) => Err(ProtocolError::RequestIdMismatch),
            ServerEnvelope::Error(error) if error.request_id == Some(request_id) => {
                Err(ProtocolError::Wire(error.code))
            }
            ServerEnvelope::Error(_) => Err(ProtocolError::RequestIdMismatch),
            _ => Err(ProtocolError::UnexpectedMessage),
        }
    }

    pub fn into_split(self) -> (LocalCommandSender, LocalIncomingReceiver) {
        let (reader, writer) = self.stream.into_split();
        (
            LocalCommandSender {
                writer,
                negotiated_max: self.negotiated_max,
                frame_timeout: self.frame_timeout,
            },
            LocalIncomingReceiver {
                reader,
                negotiated_max: self.negotiated_max,
                frame_timeout: self.frame_timeout,
            },
        )
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
            Response::Health(health) if health.validate() => Ok(health),
            Response::Health(_) => Err(ProtocolError::InvalidHealth),
            Response::RecoveryTerminal(_)
            | Response::RecoveryAction(_)
            | Response::McpBindingIssued(_)
            | Response::McpResult(_)
            | Response::RecallCue(_)
            | Response::SessionImportAdmin(_)
            | Response::HumanGovernance(_) => Err(ProtocolError::UnexpectedMessage),
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
pub async fn request_recovery(
    socket_path: &Path,
    build_id: impl Into<String>,
    request_id: evertrace_domain::ids::RequestId,
    request: command::RequestRecoveryCommand,
    frame_timeout: Duration,
) -> Result<RecoveryActionResponse, ProtocolError> {
    let build_id = build_id.into();
    if !valid_build_id(&build_id) {
        return Err(ProtocolError::InvalidBuildId);
    }
    let mut stream = timeout(frame_timeout, UnixStream::connect(socket_path))
        .await
        .map_err(|_| ProtocolError::Timeout)?
        .map_err(ProtocolError::Connect)?;
    write_frame(
        &mut stream,
        &ClientEnvelope::Handshake(handshake::Handshake {
            protocol_version: PROTOCOL_VERSION,
            client_kind: dto::ClientKind::Cli,
            build_id,
            max_frame: MAX_FRAME_SIZE as u32,
        }),
        MAX_FRAME_SIZE,
        frame_timeout,
    )
    .await?;
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
    write_frame(
        &mut stream,
        &ClientEnvelope::Command(command::CommandEnvelope {
            request_id,
            command: Command::RequestRecovery(request),
        }),
        negotiated_max,
        frame_timeout,
    )
    .await?;
    match read_frame::<ServerEnvelope>(&mut stream, negotiated_max, frame_timeout).await? {
        ServerEnvelope::Response(value) if value.request_id == request_id => match value.response {
            Response::RecoveryAction(response) if response.validate() => Ok(response),
            Response::RecoveryAction(_) => Err(ProtocolError::InvalidRecoveryAction),
            Response::Health(_)
            | Response::RecoveryTerminal(_)
            | Response::McpBindingIssued(_)
            | Response::McpResult(_)
            | Response::RecallCue(_)
            | Response::SessionImportAdmin(_)
            | Response::HumanGovernance(_) => Err(ProtocolError::UnexpectedMessage),
        },
        ServerEnvelope::Response(_) => Err(ProtocolError::RequestIdMismatch),
        ServerEnvelope::Error(error) if error.request_id == Some(request_id) => {
            Err(ProtocolError::Wire(error.code))
        }
        ServerEnvelope::Error(_) => Err(ProtocolError::RequestIdMismatch),
        _ => Err(ProtocolError::UnexpectedMessage),
    }
}

#[cfg(unix)]
struct SyncHookConnection {
    stream: StdUnixStream,
    deadline: Instant,
    socket_identity: (u64, u64, u32),
    negotiated_max: usize,
}

#[cfg(unix)]
fn connect_sync_hook(
    socket_path: &Path,
    build_id: &str,
    timeout_limit: Duration,
) -> Result<SyncHookConnection, error::SyncProtocolError> {
    use error::SyncProtocolError;
    use frame::{read_frame_sync, write_frame_sync};

    if !handshake::valid_build_id(build_id) || timeout_limit < Duration::from_millis(1) {
        return Err(SyncProtocolError::InvalidInput);
    }
    let deadline = Instant::now()
        .checked_add(timeout_limit)
        .ok_or(SyncProtocolError::InvalidInput)?;
    let socket_identity = checked_sync_socket(socket_path)?;
    let mut stream = connect_sync_deadline(socket_path, deadline)?;
    if checked_sync_socket(socket_path)? != socket_identity {
        return Err(SyncProtocolError::Connect);
    }
    set_sync_deadline(&stream, deadline)?;
    write_frame_sync(
        &mut stream,
        &envelope::ClientEnvelope::Handshake(handshake::Handshake {
            protocol_version: dto::PROTOCOL_VERSION,
            client_kind: dto::ClientKind::Hook,
            build_id: build_id.to_owned(),
            max_frame: dto::MAX_FRAME_SIZE as u32,
        }),
        dto::MAX_FRAME_SIZE,
    )
    .map_err(map_sync_frame_error)?;
    set_sync_deadline(&stream, deadline)?;
    let negotiated_max =
        match read_frame_sync::<envelope::ServerEnvelope>(&mut stream, dto::MAX_FRAME_SIZE)
            .map_err(map_sync_frame_error)?
        {
            envelope::ServerEnvelope::HandshakeAck(ack)
                if ack.protocol_version == dto::PROTOCOL_VERSION
                    && handshake::valid_build_id(&ack.build_id)
                    && ack.max_frame > 0
                    && ack.max_frame <= dto::MAX_FRAME_SIZE as u32 =>
            {
                ack.max_frame as usize
            }
            envelope::ServerEnvelope::Error(error) => {
                return Err(if error.code == error::ErrorCode::Untrusted {
                    SyncProtocolError::NotAdmitted
                } else {
                    SyncProtocolError::Wire
                });
            }
            _ => return Err(SyncProtocolError::Negotiation),
        };
    Ok(SyncHookConnection {
        stream,
        deadline,
        socket_identity,
        negotiated_max,
    })
}

#[cfg(unix)]
pub fn request_recovery_barrier_sync(
    socket_path: &Path,
    build_id: &str,
    locator: command::RecoveryBarrierLocator,
    timeout_limit: Duration,
) -> Result<response::RecoveryTerminalResponse, error::SyncProtocolError> {
    use error::SyncProtocolError;
    use frame::{read_frame_sync, write_frame_sync};

    if !locator.validate() {
        return Err(SyncProtocolError::InvalidInput);
    }
    let SyncHookConnection {
        mut stream,
        deadline,
        socket_identity,
        negotiated_max: negotiated,
    } = connect_sync_hook(socket_path, build_id, timeout_limit)?;
    let request_id = evertrace_domain::ids::RequestId::from_uuid(uuid::Uuid::now_v7())
        .map_err(|_| SyncProtocolError::InvalidInput)?;
    let command = envelope::ClientEnvelope::Command(command::CommandEnvelope {
        request_id,
        command: command::Command::RecoveryBarrier(locator.clone()),
    });
    set_sync_deadline(&stream, deadline)?;
    write_frame_sync(&mut stream, &command, negotiated).map_err(map_sync_frame_error)?;
    set_sync_deadline(&stream, deadline)?;
    match read_frame_sync::<envelope::ServerEnvelope>(&mut stream, negotiated)
        .map_err(map_sync_frame_error)?
    {
        envelope::ServerEnvelope::Response(value) if value.request_id == request_id => {
            match value.response {
                response::Response::RecoveryTerminal(terminal)
                    if terminal.validate()
                        && terminal.recovery_capture_request_id
                            == locator.recovery_capture_request_id
                        && terminal.pending_revision_id == locator.pending_revision_id =>
                {
                    if checked_sync_socket(socket_path)? != socket_identity {
                        return Err(SyncProtocolError::Connect);
                    }
                    Ok(terminal)
                }
                _ => Err(SyncProtocolError::InvalidResponse),
            }
        }
        envelope::ServerEnvelope::Error(error) if error.request_id == Some(request_id) => {
            Err(if error.code == error::ErrorCode::Untrusted {
                SyncProtocolError::NotAdmitted
            } else {
                SyncProtocolError::Wire
            })
        }
        _ => Err(SyncProtocolError::InvalidResponse),
    }
}

#[cfg(unix)]
pub fn request_mcp_binding_sync(
    socket_path: &Path,
    build_id: &str,
    request: command::McpBindingIssueCommand,
    timeout_limit: Duration,
) -> Result<response::McpBindingIssuedResponse, error::SyncProtocolError> {
    use error::SyncProtocolError;
    use frame::{read_frame_sync, write_frame_sync};

    let SyncHookConnection {
        mut stream,
        deadline,
        socket_identity,
        negotiated_max: negotiated,
    } = connect_sync_hook(socket_path, build_id, timeout_limit)?;
    let request_id = evertrace_domain::ids::RequestId::from_uuid(uuid::Uuid::now_v7())
        .map_err(|_| SyncProtocolError::InvalidInput)?;
    set_sync_deadline(&stream, deadline)?;
    write_frame_sync(
        &mut stream,
        &envelope::ClientEnvelope::Command(command::CommandEnvelope {
            request_id,
            command: command::Command::IssueMcpBinding(request),
        }),
        negotiated,
    )
    .map_err(map_sync_frame_error)?;
    set_sync_deadline(&stream, deadline)?;
    match read_frame_sync::<envelope::ServerEnvelope>(&mut stream, negotiated)
        .map_err(map_sync_frame_error)?
    {
        envelope::ServerEnvelope::Response(value) if value.request_id == request_id => {
            match value.response {
                response::Response::McpBindingIssued(response) => {
                    if checked_sync_socket(socket_path)? != socket_identity {
                        return Err(SyncProtocolError::Connect);
                    }
                    Ok(response)
                }
                _ => Err(SyncProtocolError::InvalidResponse),
            }
        }
        envelope::ServerEnvelope::Error(error) if error.request_id == Some(request_id) => {
            Err(SyncProtocolError::Wire)
        }
        _ => Err(SyncProtocolError::InvalidResponse),
    }
}

#[cfg(unix)]
pub fn request_recall_cue_sync<F>(
    socket_path: &Path,
    build_id: &str,
    snapshot: evertrace_domain::recall::RecallCueSnapshot,
    timeout_limit: Duration,
    emit: F,
) -> Result<bool, error::SyncProtocolError>
where
    F: FnOnce(
        &evertrace_domain::recall::RecallCueSnapshot,
    ) -> evertrace_domain::recall::PresentationAttemptState,
{
    use error::SyncProtocolError;
    use frame::{read_frame_sync, write_frame_sync};

    if !snapshot.validate() {
        return Err(SyncProtocolError::InvalidInput);
    }
    let SyncHookConnection {
        mut stream,
        deadline,
        socket_identity,
        negotiated_max: negotiated,
    } = connect_sync_hook(socket_path, build_id, timeout_limit)?;
    let request_id = evertrace_domain::ids::RequestId::new_v7();
    set_sync_deadline(&stream, deadline)?;
    write_frame_sync(
        &mut stream,
        &envelope::ClientEnvelope::Command(command::CommandEnvelope {
            request_id,
            command: command::Command::RecallCue(command::RecallCueCommand::Authorize {
                snapshot: snapshot.clone(),
            }),
        }),
        negotiated,
    )
    .map_err(map_sync_frame_error)?;
    set_sync_deadline(&stream, deadline)?;
    match read_frame_sync::<envelope::ServerEnvelope>(&mut stream, negotiated)
        .map_err(map_sync_frame_error)?
    {
        envelope::ServerEnvelope::Response(value) if value.request_id == request_id => {
            match value.response {
                response::Response::RecallCue(response::RecallCueResponse::Authorized) => {}
                _ => return Err(SyncProtocolError::InvalidResponse),
            }
        }
        envelope::ServerEnvelope::Error(error) if error.request_id == Some(request_id) => {
            return Err(SyncProtocolError::NotAdmitted);
        }
        _ => return Err(SyncProtocolError::InvalidResponse),
    }
    if checked_sync_socket(socket_path)? != socket_identity {
        return Err(SyncProtocolError::Connect);
    }
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SyncProtocolError::InvalidResponse)?
        .as_micros();
    let not_expired = i64::try_from(now_us)
        .ok()
        .is_some_and(|now| snapshot.expires_at_us > now);
    let outcome = if not_expired {
        emit(&snapshot)
    } else {
        evertrace_domain::recall::PresentationAttemptState::FailedPreEmit
    };
    if !matches!(
        outcome,
        evertrace_domain::recall::PresentationAttemptState::Emitted
            | evertrace_domain::recall::PresentationAttemptState::FailedPreEmit
            | evertrace_domain::recall::PresentationAttemptState::PresentationUnknown
    ) {
        return Err(SyncProtocolError::InvalidInput);
    }
    let emitted = outcome == evertrace_domain::recall::PresentationAttemptState::Emitted;
    let outcome_id = evertrace_domain::ids::RequestId::new_v7();
    set_sync_deadline(&stream, deadline)?;
    write_frame_sync(
        &mut stream,
        &envelope::ClientEnvelope::Command(command::CommandEnvelope {
            request_id: outcome_id,
            command: command::Command::RecallCue(command::RecallCueCommand::Outcome {
                snapshot,
                outcome,
            }),
        }),
        negotiated,
    )
    .map_err(map_sync_frame_error)?;
    set_sync_deadline(&stream, deadline)?;
    match read_frame_sync::<envelope::ServerEnvelope>(&mut stream, negotiated)
        .map_err(map_sync_frame_error)?
    {
        envelope::ServerEnvelope::Response(value) if value.request_id == outcome_id => {
            match value.response {
                response::Response::RecallCue(response::RecallCueResponse::OutcomeAccepted) => {
                    Ok(emitted)
                }
                _ => Err(SyncProtocolError::InvalidResponse),
            }
        }
        _ => Err(SyncProtocolError::InvalidResponse),
    }
}

#[cfg(unix)]
fn set_sync_deadline(
    stream: &StdUnixStream,
    deadline: Instant,
) -> Result<(), error::SyncProtocolError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(error::SyncProtocolError::Timeout)?;
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|()| stream.set_write_timeout(Some(remaining)))
        .map_err(|_| error::SyncProtocolError::Connect)
}

#[cfg(unix)]
fn connect_sync_deadline(
    socket_path: &Path,
    deadline: Instant,
) -> Result<StdUnixStream, error::SyncProtocolError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(error::SyncProtocolError::Timeout)?;
    let path = socket_path.to_path_buf();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(StdUnixStream::connect(path));
    });
    receiver
        .recv_timeout(remaining)
        .map_err(|error| match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => error::SyncProtocolError::Timeout,
            std::sync::mpsc::RecvTimeoutError::Disconnected => error::SyncProtocolError::Connect,
        })?
        .map_err(|_| error::SyncProtocolError::Connect)
}

#[cfg(unix)]
fn checked_sync_socket(socket_path: &Path) -> Result<(u64, u64, u32), error::SyncProtocolError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata =
        std::fs::symlink_metadata(socket_path).map_err(|_| error::SyncProtocolError::Connect)?;
    let uid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .and_then(|line| line.split_ascii_whitespace().nth(2))
                .and_then(|value| value.parse::<u32>().ok())
        })
        .ok_or(error::SyncProtocolError::Connect)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(error::SyncProtocolError::Connect);
    }
    Ok((metadata.dev(), metadata.ino(), metadata.uid()))
}

#[cfg(unix)]
fn map_sync_frame_error(error: frame::FrameError) -> error::SyncProtocolError {
    if matches!(error, frame::FrameError::Timeout) {
        error::SyncProtocolError::Timeout
    } else {
        error::SyncProtocolError::Frame
    }
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
