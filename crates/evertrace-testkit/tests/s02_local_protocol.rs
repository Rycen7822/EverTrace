use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use evertrace_domain::{config::EffectiveConfig, error::ErrorCode, ids::RequestId};
use evertrace_engine::{EngineService, HealthDispatchError, RuntimeMode};
use evertrace_protocol::{
    LocalClient, LocalServer, ServerOptions,
    command::{Command, CommandEnvelope},
    dto::{ClientKind, HealthMode, MAX_FRAME_SIZE, PROTOCOL_VERSION},
    envelope::{ClientEnvelope, ServerEnvelope},
    error::ProtocolError,
    frame::{FrameError, canonical_json, read_frame, write_frame},
    handshake::{Handshake, HandshakeAck},
    notification::{Notification, NotificationEnvelope},
    request_health,
    response::{HealthResponse, Response, ResponseEnvelope},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncWriteExt, duplex},
    net::UnixStream,
    sync::watch,
    time::sleep,
};

const ID: &str = "01890f47-6a4a-7cc1-98b9-01890f476a4a";
const WAIT: Duration = Duration::from_secs(1);

fn request_id() -> RequestId {
    RequestId::from_str(ID).expect("fixed UUIDv7")
}

fn handshake(version: u32) -> ClientEnvelope {
    ClientEnvelope::Handshake(Handshake {
        protocol_version: version,
        client_kind: ClientKind::Cli,
        build_id: "test".into(),
        max_frame: MAX_FRAME_SIZE as u32,
    })
}

fn command() -> ClientEnvelope {
    ClientEnvelope::Command(CommandEnvelope {
        request_id: request_id(),
        command: Command::Health,
    })
}

fn health(mode: HealthMode) -> HealthResponse {
    HealthResponse {
        protocol_version: PROTOCOL_VERSION,
        mode,
        config_version: 1,
        effective_config_hash: "0".repeat(64),
        algorithm_revision: 1,
    }
}

fn options() -> ServerOptions {
    ServerOptions::new("server").with_frame_timeout(Duration::from_millis(60))
}

fn data_dir(temp: &TempDir) -> PathBuf {
    temp.path().join("data")
}

async fn start_server(
    mode: HealthMode,
) -> (
    TempDir,
    PathBuf,
    watch::Sender<bool>,
    tokio::task::JoinHandle<Result<(), ProtocolError>>,
) {
    let runtime_mode = if mode == HealthMode::Maintenance {
        RuntimeMode::Maintenance
    } else {
        RuntimeMode::Normal
    };
    start_server_with(runtime_mode, options()).await
}

async fn start_server_with(
    mode: RuntimeMode,
    options: ServerOptions,
) -> (
    TempDir,
    PathBuf,
    watch::Sender<bool>,
    tokio::task::JoinHandle<Result<(), ProtocolError>>,
) {
    let temp = TempDir::new().expect("tempdir");
    let server = LocalServer::bind(&data_dir(&temp), options).expect("bind server");
    let socket = server.socket_path().to_path_buf();
    let engine = Arc::new(EngineService::new(EffectiveConfig::default(), mode));
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx, move || {
        let snapshot = engine.health().map_err(|error| match error {
            HealthDispatchError::MaintenanceMode => ErrorCode::MaintenanceMode,
        })?;
        Ok(HealthResponse {
            protocol_version: PROTOCOL_VERSION,
            mode: HealthMode::Normal,
            config_version: snapshot.config_version,
            effective_config_hash: hex(&snapshot.effective_config_hash),
            algorithm_revision: snapshot.algorithm_revision,
        })
    }));
    (temp, socket, tx, task)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

async fn send_raw(stream: &mut UnixStream, payload: &[u8]) {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .expect("prefix");
    stream.write_all(payload).await.expect("payload");
}

enum FakeReply {
    None,
    Health {
        wrong_request_id: bool,
        health: HealthResponse,
    },
    WrongRequestError,
}

async fn start_fake_peer(
    ack: HandshakeAck,
    reply: FakeReply,
) -> (
    TempDir,
    PathBuf,
    tokio::task::JoinHandle<Result<(), FrameError>>,
) {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("fake.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.map_err(FrameError::Io)?;
        let _: ClientEnvelope = read_frame(&mut stream, MAX_FRAME_SIZE, WAIT).await?;
        write_frame(
            &mut stream,
            &ServerEnvelope::HandshakeAck(ack.clone()),
            MAX_FRAME_SIZE,
            WAIT,
        )
        .await?;
        match reply {
            FakeReply::None => Ok(()),
            FakeReply::Health {
                wrong_request_id,
                health,
            } => {
                let command: ClientEnvelope =
                    read_frame(&mut stream, ack.max_frame as usize, WAIT).await?;
                let ClientEnvelope::Command(command) = command else {
                    return Err(FrameError::InvalidJson);
                };
                let request_id = if wrong_request_id {
                    RequestId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a4b").unwrap()
                } else {
                    command.request_id
                };
                let response =
                    ServerEnvelope::Response(evertrace_protocol::response::ResponseEnvelope {
                        request_id,
                        response: evertrace_protocol::response::Response::Health(health),
                    });
                write_frame(&mut stream, &response, ack.max_frame as usize, WAIT).await
            }
            FakeReply::WrongRequestError => {
                let _: ClientEnvelope =
                    read_frame(&mut stream, ack.max_frame as usize, WAIT).await?;
                let response = ServerEnvelope::Error(evertrace_protocol::error::WireError {
                    code: ErrorCode::MaintenanceMode,
                    request_id: Some(
                        RequestId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a4b").unwrap(),
                    ),
                });
                write_frame(&mut stream, &response, ack.max_frame as usize, WAIT).await
            }
        }
    });
    (temp, socket, task)
}

#[test]
fn canonical_handshake_health_and_error_golden_bytes() {
    assert_eq!(
        canonical_json(&handshake(1)).unwrap(),
        br#"{"kind":"handshake","body":{"protocol_version":1,"client_kind":"cli","build_id":"test","max_frame":1048576}}"#
    );
    let response = ServerEnvelope::Response(evertrace_protocol::response::ResponseEnvelope {
        request_id: request_id(),
        response: evertrace_protocol::response::Response::Health(health(HealthMode::Normal)),
    });
    assert_eq!(
        String::from_utf8(canonical_json(&response).unwrap()).unwrap(),
        format!(
            "{{\"kind\":\"response\",\"body\":{{\"request_id\":\"{ID}\",\"response\":{{\"health\":{{\"protocol_version\":1,\"mode\":\"normal\",\"config_version\":1,\"effective_config_hash\":\"{}\",\"algorithm_revision\":1}}}}}}}}",
            "0".repeat(64)
        )
    );
    let error = ServerEnvelope::Error(evertrace_protocol::error::WireError {
        code: ErrorCode::ProtocolMismatch,
        request_id: None,
    });
    assert_eq!(
        canonical_json(&error).unwrap(),
        br#"{"kind":"error","body":{"code":"protocol_mismatch"}}"#
    );
}

#[tokio::test]
async fn frame_handles_segments_and_rejects_invalid_payloads() {
    let value = handshake(1);
    let payload = canonical_json(&value).unwrap();
    let (mut writer, mut reader) = duplex(MAX_FRAME_SIZE + 4);
    let bytes = [&(payload.len() as u32).to_be_bytes()[..], &payload[..]].concat();
    let task = tokio::spawn(async move {
        for byte in bytes {
            writer.write_all(&[byte]).await.unwrap();
        }
    });
    assert_eq!(
        read_frame::<ClientEnvelope>(&mut reader, MAX_FRAME_SIZE, WAIT)
            .await
            .unwrap(),
        value
    );
    task.await.unwrap();

    type InvalidFrameCase<'a> = (&'a [u8], fn(&FrameError) -> bool);

    let invalid_cases: &[InvalidFrameCase<'_>] = &[
        (&[0xff], |error| matches!(error, FrameError::InvalidUtf8)),
        (b"{", |error| matches!(error, FrameError::InvalidJson)),
        (
            br#"{"kind":"handshake","body":{"protocol_version":1,"client_kind":"cli","build_id":"x","max_frame":1,"extra":true}}"#,
            |error| matches!(error, FrameError::InvalidJson),
        ),
        (
            br#"{ "kind":"handshake","body":{"protocol_version":1,"client_kind":"cli","build_id":"test","max_frame":1048576}}"#,
            |error| matches!(error, FrameError::NonCanonical),
        ),
    ];
    for (payload, matches_error) in invalid_cases {
        let (mut writer, mut reader) = duplex(payload.len() + 4);
        writer
            .write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .unwrap();
        writer.write_all(payload).await.unwrap();
        let error = read_frame::<ClientEnvelope>(&mut reader, MAX_FRAME_SIZE, WAIT)
            .await
            .unwrap_err();
        assert!(matches_error(&error), "unexpected error: {error:?}");
    }
}

#[tokio::test]
async fn oversize_and_partial_frames_fail_without_blocking() {
    let (mut writer, mut reader) = duplex(8);
    writer
        .write_all(&((MAX_FRAME_SIZE as u32) + 1).to_be_bytes())
        .await
        .unwrap();
    assert!(matches!(
        read_frame::<ClientEnvelope>(&mut reader, MAX_FRAME_SIZE, WAIT).await,
        Err(FrameError::Oversize)
    ));

    let (mut writer, mut reader) = duplex(8);
    writer.write_all(&[0, 0]).await.unwrap();
    drop(writer);
    assert!(matches!(
        read_frame::<ClientEnvelope>(&mut reader, MAX_FRAME_SIZE, WAIT).await,
        Err(FrameError::Closed)
    ));

    let (mut writer, mut reader) = duplex(8);
    writer.write_all(&4_u32.to_be_bytes()).await.unwrap();
    writer.write_all(b"{").await.unwrap();
    drop(writer);
    assert!(matches!(
        read_frame::<ClientEnvelope>(&mut reader, MAX_FRAME_SIZE, WAIT).await,
        Err(FrameError::Closed)
    ));
}

#[tokio::test]
async fn handshake_contract_and_health_succeed() {
    let (_temp, socket, shutdown, task) = start_server(HealthMode::Normal).await;
    let result = request_health(&socket, "client", WAIT).await.unwrap();
    assert_eq!(result.protocol_version, PROTOCOL_VERSION);
    assert_eq!(result.mode, HealthMode::Normal);
    assert_eq!(result.config_version, 1);
    assert_eq!(result.effective_config_hash.len(), 64);
    assert_eq!(result.algorithm_revision, 1);

    let mut stream = UnixStream::connect(&socket).await.unwrap();
    write_frame(&mut stream, &command(), MAX_FRAME_SIZE, WAIT)
        .await
        .unwrap();
    let response = read_frame::<ServerEnvelope>(&mut stream, MAX_FRAME_SIZE, WAIT)
        .await
        .unwrap();
    assert!(matches!(
        response,
        ServerEnvelope::Error(error) if error.code == ErrorCode::InvalidInput
    ));

    let mut stream = UnixStream::connect(&socket).await.unwrap();
    write_frame(&mut stream, &handshake(2), MAX_FRAME_SIZE, WAIT)
        .await
        .unwrap();
    let response = read_frame::<ServerEnvelope>(&mut stream, MAX_FRAME_SIZE, WAIT)
        .await
        .unwrap();
    assert!(matches!(
        response,
        ServerEnvelope::Error(error) if error.code == ErrorCode::ProtocolMismatch
    ));
    shutdown.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn server_rejects_zero_tiny_and_oversize_negotiation_stably() {
    let (_temp, socket, shutdown, task) = start_server(HealthMode::Normal).await;
    for (max_frame, expected) in [
        (0, ErrorCode::InvalidInput),
        (64, ErrorCode::ResourceExhausted),
    ] {
        let mut stream = UnixStream::connect(&socket).await.unwrap();
        let mut offered = handshake(1);
        let ClientEnvelope::Handshake(value) = &mut offered else {
            unreachable!()
        };
        value.max_frame = max_frame;
        write_frame(&mut stream, &offered, MAX_FRAME_SIZE, WAIT)
            .await
            .unwrap();
        let response = read_frame::<ServerEnvelope>(&mut stream, MAX_FRAME_SIZE, WAIT)
            .await
            .unwrap();
        assert!(matches!(response, ServerEnvelope::Error(error) if error.code == expected));
    }

    let mut stream = UnixStream::connect(&socket).await.unwrap();
    write_frame(&mut stream, &handshake(1), MAX_FRAME_SIZE, WAIT)
        .await
        .unwrap();
    let _: ServerEnvelope = read_frame(&mut stream, MAX_FRAME_SIZE, WAIT).await.unwrap();
    stream
        .write_all(&((MAX_FRAME_SIZE as u32) + 1).to_be_bytes())
        .await
        .unwrap();
    let response = read_frame::<ServerEnvelope>(&mut stream, MAX_FRAME_SIZE, WAIT)
        .await
        .unwrap();
    assert!(matches!(
        response,
        ServerEnvelope::Error(error) if error.code == ErrorCode::ResourceExhausted
    ));
    shutdown.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn client_enforces_ack_negotiation_and_command_limit() {
    for ack in [
        HandshakeAck {
            protocol_version: 2,
            build_id: "server".into(),
            max_frame: MAX_FRAME_SIZE as u32,
        },
        HandshakeAck {
            protocol_version: 1,
            build_id: "server".into(),
            max_frame: 0,
        },
        HandshakeAck {
            protocol_version: 1,
            build_id: "server".into(),
            max_frame: (MAX_FRAME_SIZE as u32) + 1,
        },
    ] {
        let (_temp, socket, task) = start_fake_peer(ack, FakeReply::None).await;
        assert!(matches!(
            request_health(&socket, "client", WAIT).await,
            Err(ProtocolError::InvalidNegotiation)
        ));
        task.await.unwrap().unwrap();
    }

    let ack = HandshakeAck {
        protocol_version: 1,
        build_id: "server".into(),
        max_frame: 64,
    };
    let (_temp, socket, task) = start_fake_peer(ack, FakeReply::None).await;
    assert!(matches!(
        request_health(&socket, "client", WAIT).await,
        Err(ProtocolError::Frame(FrameError::Oversize))
    ));
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn client_rejects_request_mismatch_and_invalid_health() {
    let ack = HandshakeAck {
        protocol_version: 1,
        build_id: "server".into(),
        max_frame: MAX_FRAME_SIZE as u32,
    };
    let (_temp, socket, task) = start_fake_peer(
        ack.clone(),
        FakeReply::Health {
            wrong_request_id: true,
            health: health(HealthMode::Normal),
        },
    )
    .await;
    assert!(matches!(
        request_health(&socket, "client", WAIT).await,
        Err(ProtocolError::RequestIdMismatch)
    ));
    task.await.unwrap().unwrap();

    let (_temp, socket, task) = start_fake_peer(ack.clone(), FakeReply::WrongRequestError).await;
    assert!(matches!(
        request_health(&socket, "client", WAIT).await,
        Err(ProtocolError::RequestIdMismatch)
    ));
    task.await.unwrap().unwrap();

    let mut invalid = Vec::new();
    let mut value = health(HealthMode::Normal);
    value.protocol_version = 2;
    invalid.push(value);
    let mut value = health(HealthMode::Normal);
    value.config_version = 0;
    invalid.push(value);
    let mut value = health(HealthMode::Normal);
    value.effective_config_hash = "A".repeat(64);
    invalid.push(value);
    let mut value = health(HealthMode::Normal);
    value.algorithm_revision = 0;
    invalid.push(value);
    for value in invalid {
        let (_temp, socket, task) = start_fake_peer(
            ack.clone(),
            FakeReply::Health {
                wrong_request_id: false,
                health: value,
            },
        )
        .await;
        assert!(matches!(
            request_health(&socket, "client", WAIT).await,
            Err(ProtocolError::InvalidHealth)
        ));
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn slow_and_malformed_clients_do_not_block_healthy_clients() {
    let (_temp, socket, shutdown, task) = start_server(HealthMode::Normal).await;
    let mut slow = UnixStream::connect(&socket).await.unwrap();
    slow.write_all(&[0]).await.unwrap();
    sleep(Duration::from_millis(100)).await;

    let mut malformed = UnixStream::connect(&socket).await.unwrap();
    send_raw(&mut malformed, b"{").await;
    drop(malformed);
    let health = request_health(&socket, "client", WAIT).await.unwrap();
    assert_eq!(health.mode, HealthMode::Normal);
    drop(slow);
    shutdown.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn completed_connection_tasks_are_reaped_and_shutdown_stays_prompt() {
    let mut server_options = options();
    server_options.connection_limit = 2;
    let (_temp, socket, shutdown, task) =
        start_server_with(RuntimeMode::Normal, server_options).await;
    for _ in 0..128 {
        assert_eq!(
            request_health(&socket, "client", WAIT).await.unwrap().mode,
            HealthMode::Normal
        );
    }
    shutdown.send(true).unwrap();
    tokio::time::timeout(WAIT, task)
        .await
        .expect("server shutdown remained prompt")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn negotiated_client_receives_server_stopping_notification() {
    let (_temp, socket, shutdown, task) = start_server(HealthMode::Normal).await;
    let mut stream = UnixStream::connect(&socket).await.unwrap();
    write_frame(&mut stream, &handshake(1), MAX_FRAME_SIZE, WAIT)
        .await
        .unwrap();
    let ack = read_frame::<ServerEnvelope>(&mut stream, MAX_FRAME_SIZE, WAIT)
        .await
        .unwrap();
    let ServerEnvelope::HandshakeAck(ack) = ack else {
        panic!("expected handshake acknowledgement")
    };
    shutdown.send(true).unwrap();
    let message = read_frame::<ServerEnvelope>(&mut stream, ack.max_frame as usize, WAIT)
        .await
        .unwrap();
    assert_eq!(
        message,
        ServerEnvelope::Notification(NotificationEnvelope {
            notification: Notification::ServerStopping,
        })
    );
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn legacy_request_rejects_notification_before_response() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("notification.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _: ClientEnvelope = read_frame(&mut stream, MAX_FRAME_SIZE, WAIT).await.unwrap();
        write_frame(
            &mut stream,
            &ServerEnvelope::HandshakeAck(HandshakeAck {
                protocol_version: PROTOCOL_VERSION,
                build_id: "server".into(),
                max_frame: MAX_FRAME_SIZE as u32,
            }),
            MAX_FRAME_SIZE,
            WAIT,
        )
        .await
        .unwrap();
        let _: ClientEnvelope = read_frame(&mut stream, MAX_FRAME_SIZE, WAIT).await.unwrap();
        write_frame(
            &mut stream,
            &ServerEnvelope::Notification(NotificationEnvelope {
                notification: Notification::ServerStopping,
            }),
            MAX_FRAME_SIZE,
            WAIT,
        )
        .await
        .unwrap();
    });
    let mut client = LocalClient::connect(&socket, "client", ClientKind::Cli, WAIT)
        .await
        .unwrap();
    assert!(matches!(
        client.request(request_id(), Command::Health).await,
        Err(ProtocolError::UnexpectedMessage)
    ));
    peer.await.unwrap();
}

#[tokio::test]
async fn split_receiver_stays_idle_then_receives_server_stopping() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("idle-notification.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _: ClientEnvelope = read_frame(&mut stream, MAX_FRAME_SIZE, WAIT).await.unwrap();
        write_frame(
            &mut stream,
            &ServerEnvelope::HandshakeAck(HandshakeAck {
                protocol_version: PROTOCOL_VERSION,
                build_id: "server".into(),
                max_frame: MAX_FRAME_SIZE as u32,
            }),
            MAX_FRAME_SIZE,
            WAIT,
        )
        .await
        .unwrap();
        let ClientEnvelope::Command(command) =
            read_frame(&mut stream, MAX_FRAME_SIZE, WAIT).await.unwrap()
        else {
            panic!("expected command")
        };
        write_frame(
            &mut stream,
            &ServerEnvelope::Response(ResponseEnvelope {
                request_id: command.request_id,
                response: Response::Health(health(HealthMode::Normal)),
            }),
            MAX_FRAME_SIZE,
            WAIT,
        )
        .await
        .unwrap();
        sleep(Duration::from_millis(80)).await;
        write_frame(
            &mut stream,
            &ServerEnvelope::Notification(NotificationEnvelope {
                notification: Notification::ServerStopping,
            }),
            MAX_FRAME_SIZE,
            WAIT,
        )
        .await
        .unwrap();
    });
    let client = LocalClient::connect(
        &socket,
        "client",
        ClientKind::Cli,
        Duration::from_millis(20),
    )
    .await
    .unwrap();
    let (mut sender, mut receiver) = client.into_split();
    sender
        .send(CommandEnvelope {
            request_id: request_id(),
            command: Command::Health,
        })
        .await
        .unwrap();
    assert!(matches!(
        receiver.recv().await.unwrap(),
        evertrace_protocol::LocalIncoming::Response(_)
    ));
    assert_eq!(
        receiver.recv().await.unwrap(),
        evertrace_protocol::LocalIncoming::Notification(Notification::ServerStopping)
    );
    peer.await.unwrap();
}

#[tokio::test]
async fn maintenance_and_shutdown_are_stable() {
    let (_temp, socket, shutdown, task) = start_server(HealthMode::Maintenance).await;
    assert!(matches!(
        request_health(&socket, "client", WAIT).await,
        Err(ProtocolError::Wire(ErrorCode::MaintenanceMode))
    ));
    shutdown.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert!(!socket.exists());
}

#[tokio::test]
async fn stale_active_permissions_and_path_types_are_enforced() {
    let temp = TempDir::new().unwrap();
    let data = data_dir(&temp);
    let server = LocalServer::bind(&data, options()).unwrap();
    let socket = server.socket_path().to_path_buf();
    let runtime = socket.parent().unwrap();
    assert_eq!(
        fs::symlink_metadata(runtime).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let socket_metadata = fs::symlink_metadata(&socket).unwrap();
    assert!(socket_metadata.file_type().is_socket());
    assert_eq!(socket_metadata.permissions().mode() & 0o777, 0o600);
    assert!(matches!(
        LocalServer::bind(&data, options()),
        Err(ProtocolError::AlreadyRunning)
    ));
    drop(server);

    fs::create_dir_all(data.join("runtime")).unwrap();
    fs::set_permissions(data.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
    let stale_path = data.join("runtime/evertraced-v1.sock");
    let stale = std::os::unix::net::UnixListener::bind(&stale_path).unwrap();
    fs::set_permissions(&stale_path, fs::Permissions::from_mode(0o600)).unwrap();
    drop(stale);
    let recovered = LocalServer::bind(&data, options()).unwrap();
    drop(recovered);

    let bad = TempDir::new().unwrap();
    let bad_data = data_dir(&bad);
    fs::create_dir_all(&bad_data).unwrap();
    fs::set_permissions(&bad_data, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(bad_data.join("runtime"), b"not a directory").unwrap();
    assert!(matches!(
        LocalServer::bind(&bad_data, options()),
        Err(ProtocolError::InvalidRuntimeDirectory)
    ));

    let linked = TempDir::new().unwrap();
    let linked_data = data_dir(&linked);
    fs::create_dir_all(&linked_data).unwrap();
    let target = linked.path().join("runtime-target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&target, linked_data.join("runtime")).unwrap();
    assert!(matches!(
        LocalServer::bind(&linked_data, options()),
        Err(ProtocolError::InvalidRuntimeDirectory)
    ));

    let bad_socket = TempDir::new().unwrap();
    let bad_socket_data = data_dir(&bad_socket);
    let runtime = bad_socket_data.join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(runtime.join("evertraced-v1.sock"), b"not a socket").unwrap();
    assert!(matches!(
        LocalServer::bind(&bad_socket_data, options()),
        Err(ProtocolError::InvalidSocket)
    ));

    let linked_socket = TempDir::new().unwrap();
    let linked_socket_data = data_dir(&linked_socket);
    let runtime = linked_socket_data.join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let target = linked_socket.path().join("socket-target");
    fs::write(&target, b"target").unwrap();
    symlink(&target, runtime.join("evertraced-v1.sock")).unwrap();
    assert!(matches!(
        LocalServer::bind(&linked_socket_data, options()),
        Err(ProtocolError::InvalidSocket)
    ));

    let wrong_runtime_permissions = TempDir::new().unwrap();
    let wrong_data = data_dir(&wrong_runtime_permissions);
    fs::create_dir_all(wrong_data.join("runtime")).unwrap();
    fs::set_permissions(
        wrong_data.join("runtime"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(matches!(
        LocalServer::bind(&wrong_data, options()),
        Err(ProtocolError::InvalidRuntimeDirectory)
    ));

    let wrong_socket_permissions = TempDir::new().unwrap();
    let wrong_data = data_dir(&wrong_socket_permissions);
    let runtime = wrong_data.join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = runtime.join("evertraced-v1.sock");
    let stale = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
    drop(stale);
    assert!(matches!(
        LocalServer::bind(&wrong_data, options()),
        Err(ProtocolError::InvalidSocket)
    ));

    let replacement = TempDir::new().unwrap();
    let replacement_data = data_dir(&replacement);
    let old_server = LocalServer::bind(&replacement_data, options()).unwrap();
    let socket = old_server.socket_path().to_path_buf();
    fs::remove_file(&socket).unwrap();
    let replacement_listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let replacement_inode = fs::symlink_metadata(&socket).unwrap().ino();
    drop(old_server);
    assert_eq!(
        fs::symlink_metadata(&socket).unwrap().ino(),
        replacement_inode
    );
    drop(replacement_listener);
}

#[test]
fn data_dir_expansion_is_explicit_and_absolute() {
    let home = Path::new("/tmp/evertrace-home");
    assert_eq!(
        evertrace_protocol::resolve_data_dir("~/data", Some(home), |_| None).unwrap(),
        home.join("data")
    );
    assert_eq!(
        evertrace_protocol::resolve_data_dir("$ROOT/data", None, |name| {
            (name == "ROOT").then(|| "/tmp/root".into())
        })
        .unwrap(),
        Path::new("/tmp/root/data")
    );
    assert_eq!(
        evertrace_protocol::resolve_data_dir("$ROOT//data", None, |name| {
            (name == "ROOT").then(|| "/tmp/root".into())
        })
        .unwrap(),
        Path::new("/tmp/root/data")
    );
    assert!(
        evertrace_protocol::resolve_data_dir("$ROOT/data", None, |_| Some("relative".into()))
            .is_err()
    );
    assert!(evertrace_protocol::resolve_data_dir("relative", Some(home), |_| None).is_err());
}
