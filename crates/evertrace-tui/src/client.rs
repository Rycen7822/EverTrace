use crate::{AppEvent, AppEventSender, app_event::HumanReadLocator};
use evertrace_domain::ids::RequestId;
use evertrace_protocol::{
    LocalClient, LocalIncoming,
    command::{Command, CommandEnvelope, RequestRecoveryCommand},
    dto::{
        ClientKind, HUMAN_PAGE_LIMIT, HumanActionResult, HumanActionStatus, HumanGovernanceRequest,
        HumanGovernanceResponse, HumanReadRequest, HumanSurface,
    },
    response::Response,
};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio::{sync::mpsc, task::JoinSet, time::Instant};

const MAX_PENDING: usize = 8;
const PENDING_AFTER: Duration = Duration::from_millis(100);
const RESPONSE_DEADLINE: Duration = Duration::from_secs(2);
const RECONNECT_DELAYS_MS: [u64; 5] = [250, 500, 1_000, 2_000, 5_000];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ClientCommand {
    Refresh(HumanSurface),
    Human(HumanGovernanceRequest),
    Recovery(RequestRecoveryCommand),
    Shutdown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingKind {
    Health,
    HumanRead(HumanSurface, HumanReadLocator),
    HumanAction,
    Recovery,
}

async fn send_recovery(
    sender: &mut evertrace_protocol::LocalCommandSender,
    pending: &mut BTreeMap<RequestId, (Instant, PendingKind)>,
    request: RequestRecoveryCommand,
) -> Result<(), evertrace_protocol::error::ProtocolError> {
    if pending.len() >= MAX_PENDING
        || pending
            .values()
            .any(|(_, kind)| matches!(kind, PendingKind::Recovery))
    {
        return Ok(());
    }
    let request_id = RequestId::new_v7();
    sender
        .send(CommandEnvelope {
            request_id,
            command: Command::RequestRecovery(request),
        })
        .await?;
    pending.insert(request_id, (Instant::now(), PendingKind::Recovery));
    Ok(())
}

pub(crate) fn channel() -> (mpsc::Sender<ClientCommand>, mpsc::Receiver<ClientCommand>) {
    mpsc::channel(MAX_PENDING)
}

async fn send_health(
    sender: &mut evertrace_protocol::LocalCommandSender,
    pending: &mut BTreeMap<RequestId, (Instant, PendingKind)>,
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
    pending.insert(request_id, (Instant::now(), PendingKind::Health));
    Ok(())
}

async fn send_human(
    sender: &mut evertrace_protocol::LocalCommandSender,
    pending: &mut BTreeMap<RequestId, (Instant, PendingKind)>,
    request: HumanGovernanceRequest,
) -> Result<(), evertrace_protocol::error::ProtocolError> {
    let kind = match &request {
        HumanGovernanceRequest::Read { request } => match request {
            HumanReadRequest::List { surface, .. } => {
                PendingKind::HumanRead(*surface, HumanReadLocator::List)
            }
            HumanReadRequest::Detail {
                surface,
                object_ref,
                expected_frontier,
                expected_revision_ref,
            } => PendingKind::HumanRead(
                *surface,
                HumanReadLocator::Detail {
                    expected_frontier: *expected_frontier,
                    stable_key: object_ref.clone(),
                    expected_revision_ref: expected_revision_ref.clone(),
                },
            ),
            HumanReadRequest::Related {
                relation,
                source_stable_key,
                expected_source_revision_ref,
                expected_frontier,
                ..
            } => PendingKind::HumanRead(
                HumanSurface::Explorer,
                HumanReadLocator::Related {
                    relation: *relation,
                    source_stable_key: source_stable_key.clone(),
                    expected_source_revision_ref: expected_source_revision_ref.clone(),
                    expected_frontier: *expected_frontier,
                },
            ),
        },
        HumanGovernanceRequest::Act { .. } => PendingKind::HumanAction,
    };
    let request_id = RequestId::new_v7();
    sender
        .send(CommandEnvelope {
            request_id,
            command: Command::HumanGovernance(request),
        })
        .await?;
    pending.insert(request_id, (Instant::now(), kind));
    Ok(())
}

fn human_inflight(pending: &BTreeMap<RequestId, (Instant, PendingKind)>) -> bool {
    pending.values().any(|(_, kind)| {
        matches!(
            kind,
            PendingKind::HumanRead(_, _) | PendingKind::HumanAction
        )
    })
}

fn local_human_rejection(reason: &str) -> AppEvent {
    AppEvent::HumanAction(HumanGovernanceResponse::Action {
        result: HumanActionResult {
            status: HumanActionStatus::Unavailable,
            current_revision_ref: None,
            audit_event_ref: None,
            reason: Some(reason.into()),
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HumanHandoff {
    Sent,
    Queued,
    RejectedInvalid,
    RejectedBusy,
}

fn stage_human(
    pending: &BTreeMap<RequestId, (Instant, PendingKind)>,
    queued_action: &mut Option<HumanGovernanceRequest>,
    latest_read: &mut Option<HumanGovernanceRequest>,
    request: &HumanGovernanceRequest,
) -> HumanHandoff {
    if !request.validate() {
        return HumanHandoff::RejectedInvalid;
    }
    match request {
        HumanGovernanceRequest::Act { .. } => {
            let action_inflight = pending
                .values()
                .any(|(_, kind)| matches!(kind, PendingKind::HumanAction));
            if action_inflight || queued_action.is_some() {
                return HumanHandoff::RejectedBusy;
            }
            if human_inflight(pending) {
                *queued_action = Some(request.clone());
                return HumanHandoff::Queued;
            }
        }
        HumanGovernanceRequest::Read { .. } => {
            if human_inflight(pending) {
                *latest_read = Some(request.clone());
                return HumanHandoff::Queued;
            }
        }
    }
    HumanHandoff::Sent
}

async fn handoff_human(
    sender: &mut evertrace_protocol::LocalCommandSender,
    pending: &mut BTreeMap<RequestId, (Instant, PendingKind)>,
    queued_action: &mut Option<HumanGovernanceRequest>,
    latest_read: &mut Option<HumanGovernanceRequest>,
    events: &AppEventSender,
    request: HumanGovernanceRequest,
) -> Result<HumanHandoff, evertrace_protocol::error::ProtocolError> {
    match stage_human(pending, queued_action, latest_read, &request) {
        HumanHandoff::Sent => {
            send_human(sender, pending, request).await?;
            Ok(HumanHandoff::Sent)
        }
        HumanHandoff::Queued => Ok(HumanHandoff::Queued),
        HumanHandoff::RejectedInvalid => {
            let _ = events
                .send(local_human_rejection("local_invalid_request"))
                .await;
            Ok(HumanHandoff::RejectedInvalid)
        }
        HumanHandoff::RejectedBusy => {
            let _ = events.send(local_human_rejection("local_busy")).await;
            Ok(HumanHandoff::RejectedBusy)
        }
    }
}

async fn flush_human_handoff(
    sender: &mut evertrace_protocol::LocalCommandSender,
    pending: &mut BTreeMap<RequestId, (Instant, PendingKind)>,
    queued_action: &mut Option<HumanGovernanceRequest>,
    latest_read: &mut Option<HumanGovernanceRequest>,
) -> Result<(), evertrace_protocol::error::ProtocolError> {
    if human_inflight(pending) {
        return Ok(());
    }
    if let Some(request) = queued_action.take().or_else(|| latest_read.take()) {
        send_human(sender, pending, request).await?;
    }
    Ok(())
}

fn first_page_request(surface: HumanSurface) -> HumanGovernanceRequest {
    HumanGovernanceRequest::Read {
        request: HumanReadRequest::List {
            surface,
            expected_frontier: None,
            after: None,
            limit: HUMAN_PAGE_LIMIT,
        },
    }
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
                if wait_or_shutdown(&mut commands, &events, RECONNECT_DELAYS_MS[backoff]).await {
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
            if wait_or_shutdown(&mut commands, &events, RECONNECT_DELAYS_MS[backoff]).await {
                return;
            }
            backoff = (backoff + 1).min(RECONNECT_DELAYS_MS.len() - 1);
            continue;
        }
        let mut pending_visible = false;
        let mut healthy = false;
        let mut shutdown_requested = false;
        let mut queued_action = None;
        let mut latest_read = None;

        loop {
            let pending_deadline = pending
                .values()
                .map(|(started, _)| *started)
                .min()
                .map(|started| started + PENDING_AFTER)
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
            let response_deadline = pending
                .values()
                .map(|(started, _)| *started)
                .min()
                .map(|started| started + RESPONSE_DEADLINE)
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
            tokio::select! {
                command = commands.recv() => {
                    match command {
                        Some(ClientCommand::Refresh(surface)) => {
                            if handoff_human(
                                &mut outgoing,
                                &mut pending,
                                &mut queued_action,
                                &mut latest_read,
                                &events,
                                first_page_request(surface),
                            ).await.is_err() {
                                break;
                            }
                        }
                        Some(ClientCommand::Human(request)) => {
                            if handoff_human(
                                &mut outgoing,
                                &mut pending,
                                &mut queued_action,
                                &mut latest_read,
                                &events,
                                request,
                            ).await.is_err() {
                                break;
                            }
                        }
                        Some(ClientCommand::Recovery(request)) => {
                            if send_recovery(&mut outgoing, &mut pending, request).await.is_err() {
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
                            let Some((_, kind)) = pending.remove(&envelope.request_id) else { break; };
                            if pending_visible {
                                let _ = events.send(AppEvent::Pending(pending.len())).await;
                                pending_visible = !pending.is_empty();
                            }
                            let accepted = match (kind, envelope.response) {
                                (PendingKind::Health, Response::Health(health)) if health.validate() => {
                                    healthy = true;
                                    backoff = 0;
                                    let _ = events.send(AppEvent::Health(health)).await;
                                    true
                                }
                                (PendingKind::HumanRead(surface, locator), Response::HumanGovernance(response @ (HumanGovernanceResponse::Snapshot { .. } | HumanGovernanceResponse::Conflict { .. }))) if response.validate() => {
                                    let _ = events.send(AppEvent::HumanRead { surface, locator, response }).await;
                                    true
                                }
                                (PendingKind::HumanAction, Response::HumanGovernance(response @ (HumanGovernanceResponse::Action { .. } | HumanGovernanceResponse::Conflict { .. }))) if response.validate() => {
                                    let _ = events.send(AppEvent::HumanAction(response)).await;
                                    true
                                }
                                (PendingKind::Recovery, Response::RecoveryAction(response)) if response.validate() => {
                                    let _ = events.send(AppEvent::Recovery(response)).await;
                                    true
                                }
                                _ => false,
                            };
                            if !accepted {
                                break;
                            }
                            if flush_human_handoff(
                                &mut outgoing,
                                &mut pending,
                                &mut queued_action,
                                &mut latest_read,
                            ).await.is_err() {
                                break;
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
        if queued_action.take().is_some() {
            let _ = events
                .send(local_human_rejection("local_transport_unavailable"))
                .await;
        }
        let _ = events.send(AppEvent::Disconnected).await;
        if healthy {
            backoff = 0;
        }
        if wait_or_shutdown(&mut commands, &events, RECONNECT_DELAYS_MS[backoff]).await {
            return;
        }
        backoff = (backoff + 1).min(RECONNECT_DELAYS_MS.len() - 1);
    }
}

async fn wait_or_shutdown(
    commands: &mut mpsc::Receiver<ClientCommand>,
    events: &AppEventSender,
    delay_ms: u64,
) -> bool {
    let delay = tokio::time::sleep(Duration::from_millis(delay_ms));
    tokio::pin!(delay);
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(ClientCommand::Refresh(_)) => continue,
                Some(ClientCommand::Human(HumanGovernanceRequest::Act { .. })) => {
                    let _ = events.send(local_human_rejection("local_transport_unavailable")).await;
                }
                Some(ClientCommand::Human(HumanGovernanceRequest::Read { .. })) => continue,
                Some(ClientCommand::Recovery(_)) => {
                    let _ = events.send(AppEvent::Disconnected).await;
                }
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

    fn proposal_action() -> HumanGovernanceRequest {
        HumanGovernanceRequest::Act {
            expected_frontier: 1,
            action: evertrace_protocol::dto::HumanActionRequest::Proposal {
                proposal_id: evertrace_domain::ids::RevisionProposalId::new_v7(),
                expected_revision_id: evertrace_domain::revision::RevisionId::new_v7(),
                expected_fingerprint: "a".repeat(64),
                decision: evertrace_protocol::dto::ProposalHumanDecision::Defer,
                edited_payload: None,
            },
        }
    }

    #[tokio::test]
    async fn human_handoff_preserves_one_write_and_latest_read() {
        let mut pending = BTreeMap::new();
        pending.insert(
            RequestId::new_v7(),
            (
                Instant::now(),
                PendingKind::HumanRead(HumanSurface::Inbox, HumanReadLocator::List),
            ),
        );
        let pending_count = pending.len();
        let mut queued_action = None;
        let mut latest_read = None;

        let action = proposal_action();
        assert_eq!(
            stage_human(&pending, &mut queued_action, &mut latest_read, &action),
            HumanHandoff::Queued
        );
        assert_eq!(pending.len(), pending_count);
        assert_eq!(queued_action.as_ref(), Some(&action));
        assert_eq!(
            stage_human(
                &pending,
                &mut queued_action,
                &mut latest_read,
                &proposal_action()
            ),
            HumanHandoff::RejectedBusy
        );
        assert_eq!(queued_action.as_ref(), Some(&action));

        for surface in [HumanSurface::Explorer, HumanSurface::System] {
            assert_eq!(
                stage_human(
                    &pending,
                    &mut queued_action,
                    &mut latest_read,
                    &first_page_request(surface)
                ),
                HumanHandoff::Queued
            );
        }
        assert_eq!(latest_read, Some(first_page_request(HumanSurface::System)));
        assert_eq!(pending.len(), pending_count);
    }

    #[tokio::test]
    async fn disconnected_handoff_rejects_unsent_write() {
        let (commands, mut command_receiver) = channel();
        let (events, mut event_receiver) = AppEventSender::channel();
        commands
            .send(ClientCommand::Human(proposal_action()))
            .await
            .unwrap();
        assert!(!wait_or_shutdown(&mut command_receiver, &events, 25).await);
        let event = event_receiver.recv().await.unwrap();
        let AppEvent::HumanAction(HumanGovernanceResponse::Action { result }) = event else {
            panic!("expected local action rejection");
        };
        assert_eq!(result.status, HumanActionStatus::Unavailable);
        assert_eq!(
            result.reason.as_deref(),
            Some("local_transport_unavailable")
        );
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
