use crate::{AppEvent, AppEventSender};
use evertrace_domain::ids::RequestId;
use evertrace_protocol::{
    LocalClient, LocalIncoming,
    command::{Command, CommandEnvelope},
    dto::ClientKind,
    response::Response,
};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio::{sync::mpsc, task::JoinSet, time::Instant};

const MAX_PENDING: usize = 8;
const PENDING_AFTER: Duration = Duration::from_millis(100);
const RESPONSE_DEADLINE: Duration = Duration::from_secs(2);
const RECONNECT_DELAYS_MS: [u64; 5] = [250, 500, 1_000, 2_000, 5_000];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientCommand {
    Refresh,
    Shutdown,
}

pub(crate) fn channel() -> (mpsc::Sender<ClientCommand>, mpsc::Receiver<ClientCommand>) {
    mpsc::channel(MAX_PENDING)
}

async fn send_health(
    sender: &mut evertrace_protocol::LocalCommandSender,
    pending: &mut BTreeMap<RequestId, Instant>,
) -> Result<(), evertrace_protocol::error::ProtocolError> {
    if !pending.is_empty() {
        return Ok(());
    }
    let request_id = RequestId::new_v7();
    sender
        .send(CommandEnvelope {
            request_id,
            command: Command::Health,
        })
        .await?;
    pending.insert(request_id, Instant::now());
    Ok(())
}

pub(crate) async fn run(
    socket: PathBuf,
    events: AppEventSender,
    mut commands: mpsc::Receiver<ClientCommand>,
) {
    let mut backoff = 0_usize;
    loop {
        let client = match LocalClient::connect(
            &socket,
            "evertrace-tui",
            ClientKind::Cli,
            Duration::from_secs(2),
        )
        .await
        {
            Ok(client) => client,
            Err(_) => {
                let _ = events.send(AppEvent::Disconnected).await;
                if wait_or_shutdown(&mut commands, RECONNECT_DELAYS_MS[backoff]).await {
                    return;
                }
                backoff = (backoff + 1).min(RECONNECT_DELAYS_MS.len() - 1);
                continue;
            }
        };

        let (mut outgoing, mut incoming) = client.into_split();
        let (incoming_sender, mut incoming_messages) = mpsc::channel(MAX_PENDING);
        let mut incoming_tasks = JoinSet::new();
        incoming_tasks.spawn(async move {
            loop {
                let message = incoming.recv().await;
                let terminal = message.is_err();
                if incoming_sender.send(message).await.is_err() || terminal {
                    return;
                }
            }
        });
        let mut pending = BTreeMap::new();
        if send_health(&mut outgoing, &mut pending).await.is_err() {
            incoming_tasks.abort_all();
            let _ = incoming_tasks.join_next().await;
            let _ = events.send(AppEvent::Pending(0)).await;
            let _ = events.send(AppEvent::Disconnected).await;
            if wait_or_shutdown(&mut commands, RECONNECT_DELAYS_MS[backoff]).await {
                return;
            }
            backoff = (backoff + 1).min(RECONNECT_DELAYS_MS.len() - 1);
            continue;
        }
        let mut pending_visible = false;
        let mut healthy = false;
        let mut shutdown_requested = false;

        loop {
            let pending_deadline = pending
                .values()
                .min()
                .copied()
                .map(|started| started + PENDING_AFTER)
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
            let response_deadline = pending
                .values()
                .min()
                .copied()
                .map(|started| started + RESPONSE_DEADLINE)
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
            tokio::select! {
                command = commands.recv() => {
                    match command {
                        Some(ClientCommand::Refresh) => {
                            if send_health(&mut outgoing, &mut pending).await.is_err() {
                                break;
                            }
                        }
                        Some(ClientCommand::Shutdown) | None => {
                            shutdown_requested = true;
                            break;
                        }
                    }
                }
                message = incoming_messages.recv() => {
                    match message {
                        Some(Ok(LocalIncoming::Response(envelope))) => {
                            if pending.remove(&envelope.request_id).is_none() {
                                break;
                            }
                            if pending_visible {
                                let _ = events.send(AppEvent::Pending(0)).await;
                                pending_visible = false;
                            }
                            match envelope.response {
                                Response::Health(health) if pending.is_empty() && health.validate() => {
                                    healthy = true;
                                    backoff = 0;
                                    let _ = events.send(AppEvent::Health(health)).await;
                                }
                                _ => break,
                            }
                        }
                        Some(Ok(LocalIncoming::Error(_))) => break,
                        Some(Ok(LocalIncoming::Notification(notification))) => {
                            let _ = events.send(AppEvent::Notification(notification)).await;
                        }
                        Some(Err(_)) | None => break,
                    }
                }
                () = tokio::time::sleep_until(pending_deadline), if !pending.is_empty() && !pending_visible => {
                    pending_visible = true;
                    let _ = events.send(AppEvent::Pending(pending.len())).await;
                }
                () = tokio::time::sleep_until(response_deadline), if !pending.is_empty() => break,
            }
        }

        incoming_tasks.abort_all();
        let _ = incoming_tasks.join_next().await;
        let _ = events.send(AppEvent::Pending(0)).await;
        if shutdown_requested {
            return;
        }
        let _ = events.send(AppEvent::Disconnected).await;
        if healthy {
            backoff = 0;
        }
        if wait_or_shutdown(&mut commands, RECONNECT_DELAYS_MS[backoff]).await {
            return;
        }
        backoff = (backoff + 1).min(RECONNECT_DELAYS_MS.len() - 1);
    }
}

async fn wait_or_shutdown(commands: &mut mpsc::Receiver<ClientCommand>, delay_ms: u64) -> bool {
    let delay = tokio::time::sleep(Duration::from_millis(delay_ms));
    tokio::pin!(delay);
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(ClientCommand::Refresh) => continue,
                Some(ClientCommand::Shutdown) | None => return true,
            },
            () = &mut delay => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use evertrace_protocol::{
        LocalServer, ServerOptions,
        command::Command,
        dto::{HealthMode, PROTOCOL_VERSION},
        error::ErrorCode,
        notification::Notification,
        response::{HealthResponse, Response},
    };
    use ratatui::{Terminal, backend::TestBackend};
    use std::{
        fs,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::sync::watch;

    fn health() -> HealthResponse {
        HealthResponse {
            protocol_version: PROTOCOL_VERSION,
            mode: HealthMode::Normal,
            config_version: 1,
            effective_config_hash: "0".repeat(64),
            algorithm_revision: 1,
        }
    }

    fn start_server(
        data: &Path,
    ) -> (
        PathBuf,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<(), evertrace_protocol::error::ProtocolError>>,
    ) {
        let server = LocalServer::bind(data, ServerOptions::new("s30-test")).unwrap();
        let socket = server.socket_path().to_path_buf();
        let (shutdown, receiver) = watch::channel(false);
        let task = tokio::spawn(server.run(receiver, || Ok(health())));
        (socket, shutdown, task)
    }

    #[tokio::test]
    async fn persistent_notification_and_reconnect_replace_health() {
        let data = std::env::temp_dir().join(format!("evertrace-s30-{}", RequestId::new_v7()));
        let (socket, shutdown, server) = start_server(&data);
        let (events, mut receiver) = AppEventSender::channel();
        let (commands, command_receiver) = channel();
        let actor = tokio::spawn(run(socket.clone(), events, command_receiver));

        let first = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(AppEvent::Health(value)) = receiver.recv().await {
                    break value;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(first.config_version, 1);

        shutdown.send(true).unwrap();
        let stopping = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(AppEvent::Notification(Notification::ServerStopping)) =
                    receiver.recv().await
                {
                    break;
                }
            }
        })
        .await;
        assert!(stopping.is_ok());
        server.await.unwrap().unwrap();

        let (_socket, shutdown2, server2) = start_server(&data);
        let reconnected = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if matches!(receiver.recv().await, Some(AppEvent::Health(_))) {
                    break;
                }
            }
        })
        .await;
        assert!(reconnected.is_ok());

        commands.send(ClientCommand::Shutdown).await.unwrap();
        actor.await.unwrap();
        shutdown2.send(true).unwrap();
        server2.await.unwrap().unwrap();
        let _ = fs::remove_dir_all(data);
    }

    #[tokio::test]
    async fn stalled_health_does_not_block_input_or_rendering() {
        let data = std::env::temp_dir().join(format!("evertrace-s30-{}", RequestId::new_v7()));
        let server = LocalServer::bind(&data, ServerOptions::new("s30-stalled")).unwrap();
        let socket = server.socket_path().to_path_buf();
        let (_shutdown, shutdown_receiver) = watch::channel(false);
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        let server_task = tokio::spawn(server.run_dispatch(
            shutdown_receiver,
            move |_request_id, command| {
                let request_count = request_count.clone();
                async move {
                    request_count.fetch_add(1, Ordering::Relaxed);
                    match command {
                        Command::Health => {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            Ok(Response::Health(health()))
                        }
                        _ => Err(ErrorCode::InvalidInput),
                    }
                }
            },
        ));
        let (events, mut receiver) = AppEventSender::channel();
        let input = events.clone();
        let (commands, command_receiver) = channel();
        let actor = tokio::spawn(run(socket, events, command_receiver));
        tokio::time::timeout(Duration::from_millis(300), async {
            loop {
                if matches!(receiver.recv().await, Some(AppEvent::Pending(1))) {
                    break;
                }
            }
        })
        .await
        .unwrap();

        let producer = tokio::spawn(async move {
            input
                .send(AppEvent::Key(KeyEvent::new(
                    KeyCode::Char('2'),
                    KeyModifiers::NONE,
                )))
                .await
                .unwrap();
            for _ in 1..1_000 {
                input.send(AppEvent::Resize(60, 20)).await.unwrap();
            }
        });
        tokio::time::timeout(Duration::from_millis(500), async {
            let mut app = crate::App::new();
            let mut terminal = Terminal::new(TestBackend::new(60, 20)).unwrap();
            for _ in 0..1_000 {
                app.handle(receiver.recv().await.unwrap());
                terminal.draw(|frame| app.render(frame)).unwrap();
            }
            assert_eq!(app.state().route, crate::Route::Explorer);
            let buffer = terminal.backend().buffer();
            let rendered = (0..20)
                .flat_map(|y| (0..60).map(move |x| buffer[(x, y)].symbol()))
                .collect::<String>();
            assert!(rendered.contains("No objects loaded"));
        })
        .await
        .unwrap();
        producer.await.unwrap();

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if matches!(receiver.recv().await, Some(AppEvent::Disconnected)) {
                    break;
                }
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(requests.load(Ordering::Relaxed) >= 2);

        commands.send(ClientCommand::Shutdown).await.unwrap();
        actor.await.unwrap();
        server_task.abort();
        let _ = server_task.await;
        let _ = fs::remove_dir_all(data);
    }
}
