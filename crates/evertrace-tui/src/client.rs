use crate::app_event::HumanReadFailure;
use crate::{AppEvent, AppEventSender, app_event::HumanReadLocator};
use evertrace_domain::ids::RequestId;
use evertrace_protocol::{
    LocalClient, LocalIncoming,
    command::{Command, CommandEnvelope, RequestRecoveryCommand},
    dto::{
        ClientKind, HUMAN_PAGE_LIMIT, HumanActionResult, HumanActionStatus, HumanGovernanceRequest,
        HumanGovernanceResponse, HumanReadRequest, HumanSurface, HumanSystemListSelection,
    },
    response::Response,
};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio::{sync::mpsc, task::JoinSet, time::Instant};

const MAX_PENDING: usize = 8;
const PENDING_AFTER: Duration = Duration::from_millis(100);
const RESPONSE_DEADLINE: Duration = Duration::from_secs(2);
const HUMAN_READ_HARD_DEADLINE: Duration = Duration::from_secs(30);
const RECONNECT_DELAYS_MS: [u64; 5] = [250, 500, 1_000, 2_000, 5_000];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ClientCommand {
    Refresh(
        HumanSurface,
        Option<HumanSystemListSelection>,
        Option<evertrace_protocol::dto::HumanExplorerListSelection>,
        u64,
    ),
    ReadView {
        request: HumanReadRequest,
        generation: u64,
    },
    Human(HumanGovernanceRequest),
    Recovery(RequestRecoveryCommand),
    ConfigRead,
    ConfigWrite(evertrace_protocol::command::ConfigWriteCommand),
    Shutdown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingKind {
    Health,
    HumanRead(HumanSurface, HumanReadLocator),
    HumanAction,
    Export,
    Recovery,
    ConfigRead,
    ConfigWrite,
}

fn hard_deadline(kind: &PendingKind) -> Duration {
    match kind {
        PendingKind::HumanRead(_, _) => HUMAN_READ_HARD_DEADLINE,
        PendingKind::Export => Duration::from_secs(35),
        PendingKind::ConfigWrite => Duration::from_secs(10),
        _ => RESPONSE_DEADLINE,
    }
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
        HumanGovernanceRequest::Export { .. } => PendingKind::Export,
        HumanGovernanceRequest::Read { request } => match request {
            HumanReadRequest::List { surface, after, .. } => PendingKind::HumanRead(
                *surface,
                after
                    .as_ref()
                    .map_or(HumanReadLocator::List, |after| HumanReadLocator::Page {
                        after: after.clone(),
                    }),
            ),
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
            PendingKind::HumanRead(_, _) | PendingKind::HumanAction | PendingKind::Export
        )
    })
}

pub(super) fn local_human_rejection(request: &HumanGovernanceRequest, reason: &str) -> AppEvent {
    if matches!(request, HumanGovernanceRequest::Export { .. }) {
        return AppEvent::HumanAction(HumanGovernanceResponse::Export {
            result: evertrace_protocol::dto::HumanExportResult {
                status: evertrace_protocol::dto::HumanExportStatus::Failed,
                path: None,
                frontier: 0,
                object_count: 0,
                total_bytes: 0,
                reason: Some(reason.into()),
            },
        });
    }
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
        HumanGovernanceRequest::Act { .. } | HumanGovernanceRequest::Export { .. } => {
            let action_inflight = pending
                .values()
                .any(|(_, kind)| matches!(kind, PendingKind::HumanAction | PendingKind::Export));
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
                .send(local_human_rejection(&request, "local_invalid_request"))
                .await;
            Ok(HumanHandoff::RejectedInvalid)
        }
        HumanHandoff::RejectedBusy => {
            let _ = events
                .send(local_human_rejection(&request, "local_busy"))
                .await;
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

fn first_page_request(
    surface: HumanSurface,
    system_selection: Option<HumanSystemListSelection>,
    explorer_selection: Option<evertrace_protocol::dto::HumanExplorerListSelection>,
) -> HumanGovernanceRequest {
    HumanGovernanceRequest::Read {
        request: HumanReadRequest::List {
            system_selection,
            explorer_selection,
            surface,
            expected_frontier: None,
            after: None,
            limit: HUMAN_PAGE_LIMIT,
        },
    }
}

#[test]
fn system_first_page_preserves_selected_scope() {
    assert!(matches!(
        first_page_request(
            HumanSurface::System,
            Some(HumanSystemListSelection::Jobs),
            None
        ),
        HumanGovernanceRequest::Read {
            request: HumanReadRequest::List {
                surface: HumanSurface::System,
                system_selection: Some(HumanSystemListSelection::Jobs),
                expected_frontier: None,
                after: None,
                ..
            }
        }
    ));
}

#[test]
fn explorer_first_page_preserves_selected_category() {
    use evertrace_protocol::dto::HumanExplorerListSelection;
    for selection in [
        None,
        Some(HumanExplorerListSelection::Memories),
        Some(HumanExplorerListSelection::Capture),
    ] {
        let request = first_page_request(HumanSurface::Explorer, None, selection);
        assert!(request.validate());
        let HumanGovernanceRequest::Read {
            request:
                HumanReadRequest::List {
                    explorer_selection,
                    after,
                    expected_frontier,
                    ..
                },
        } = request
        else {
            panic!("list")
        };
        assert_eq!(explorer_selection, selection);
        assert!(after.is_none() && expected_frontier.is_none());
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
        // A slow read still owns its wire request until its terminal response.
        // Keep the existing single human handoff bounded and coalesce newer reads.
        let mut slow_read = None;
        let mut view_generation = None;

        loop {
            let pending_deadline = pending
                .values()
                .map(|(started, _)| *started)
                .min()
                .map(|started| started + PENDING_AFTER)
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
            let response_deadline = pending
                .iter()
                .map(|(id, (started, kind))| {
                    *started
                        + if matches!(kind, PendingKind::HumanRead(_, _)) && Some(*id) != slow_read
                        {
                            RESPONSE_DEADLINE
                        } else {
                            hard_deadline(kind)
                        }
                })
                .min()
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
            tokio::select! {
                command = commands.recv() => {
                    match command {
                        Some(ClientCommand::Refresh(surface, system_selection, explorer_selection, generation)) => {
                            view_generation=(generation>0).then_some(generation);
                            if handoff_human(
                                &mut outgoing,
                                &mut pending,
                                &mut queued_action,
                                &mut latest_read,
                                &events,
                                first_page_request(surface, system_selection, explorer_selection),
                            ).await.is_err() {
                                break;
                            }
                        }
                        Some(ClientCommand::ReadView { request, generation }) => {
                            view_generation=Some(generation);
                            if handoff_human(&mut outgoing,&mut pending,&mut queued_action,&mut latest_read,&events,HumanGovernanceRequest::Read {request}).await.is_err(){break;}
                        }
                        Some(ClientCommand::Human(request)) => {
                            if matches!(request,HumanGovernanceRequest::Read {..}){view_generation=None;}
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
                        Some(config @ (ClientCommand::ConfigRead | ClientCommand::ConfigWrite(_))) => {
                            if pending.len() >= MAX_PENDING || pending.values().any(|(_, kind)| matches!(kind, PendingKind::ConfigRead | PendingKind::ConfigWrite)) {
                                let _ = events.send(AppEvent::ConfigFailed).await;
                                continue;
                            }
                            let (command, kind) = match config {
                                ClientCommand::ConfigWrite(write) => (Command::ConfigWrite(write), PendingKind::ConfigWrite),
                                _ => (Command::ConfigRead, PendingKind::ConfigRead),
                            };
                            let request_id = RequestId::new_v7();
                            if outgoing.send(CommandEnvelope { request_id, command }).await.is_err() { break; }
                            pending.insert(request_id, (Instant::now(), kind));
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
                            if slow_read == Some(envelope.request_id) {
                                slow_read = None;
                            }
                            if pending_visible {
                                let _ = events.send(AppEvent::Pending(pending.len())).await;
                                pending_visible = !pending.is_empty();
                            }
                            let accepted = match (kind, envelope.response) {
                                (PendingKind::ConfigRead, Response::ConfigDocument(document)) if document.source.len() <= 128 * 1024 && document.file_hash.len() == 64 && document.file_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
                                    let _ = events.send(AppEvent::ConfigDocument(document)).await;
                                    true
                                }
                                (PendingKind::ConfigWrite, Response::ConfigReload(result)) => {
                                    let event = match result.outcome {
                                        evertrace_protocol::dto::ConfigReloadOutcome::Applied | evertrace_protocol::dto::ConfigReloadOutcome::RestartRequired => AppEvent::ConfigApplied(result),
                                        _ => AppEvent::ConfigFailed,
                                    };
                                    let _ = events.send(event).await;
                                    true
                                }
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
                                (PendingKind::Export, Response::HumanGovernance(response @ HumanGovernanceResponse::Export { .. })) if response.validate() => {
                                    let _ = events.send(AppEvent::HumanAction(response)).await;
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
                        Some(Ok(LocalIncoming::Error(error))) => {
                            let Some(id) = error.request_id else { break; };
                            let Some((_, kind)) = pending.remove(&id) else { break; };
                            if slow_read == Some(id) { slow_read = None; }
                            match kind {
                                PendingKind::ConfigRead | PendingKind::ConfigWrite => {
                                    let _ = events.send(AppEvent::ConfigFailed).await;
                                }
                                PendingKind::HumanRead(surface, locator) => {
                                    let _ = events.send(AppEvent::HumanReadFailed { surface, locator, code: HumanReadFailure::Rejected(error.code) }).await;
                                }
                                _ => break,
                            }
                            if pending_visible {
                                let _ = events.send(AppEvent::Pending(pending.len())).await;
                                pending_visible = !pending.is_empty();
                            }
                            if flush_human_handoff(&mut outgoing, &mut pending, &mut queued_action, &mut latest_read).await.is_err() { break; }
                        }
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
                () = tokio::time::sleep_until(response_deadline), if !pending.is_empty() => {
                    // Hard expiration wins even when a read's soft threshold is also due.
                    if let Some((_, (_, kind))) = pending.iter().find(|(_, (started, kind))| *started + hard_deadline(kind) <= Instant::now()) {
                        if let PendingKind::HumanRead(surface, locator) = kind {
                            let _ = events.send(AppEvent::HumanReadFailed { surface: *surface, locator: locator.clone(), code: HumanReadFailure::TimedOut }).await;
                        }
                        break;
                    }
                    let expired_read = pending.iter().find(|(id, (started, kind))| {
                        Some(**id) != slow_read && matches!(kind, PendingKind::HumanRead(_, _))
                            && *started + RESPONSE_DEADLINE <= Instant::now()
                    });
                    if let Some((id, (_, PendingKind::HumanRead(surface, locator)))) = expired_read {
                        slow_read = Some(*id);
                        let _ = events.send(AppEvent::HumanReadFailed { surface: *surface, locator: locator.clone(), code: HumanReadFailure::Slow }).await;
                    } else { break; }
                },
            }
            if let Some(generation) = view_generation {
                for (_, kind) in pending.values_mut() {
                    if let PendingKind::HumanRead(_, locator) = kind
                        && !matches!(locator, HumanReadLocator::View { .. })
                    {
                        *locator = HumanReadLocator::View {
                            generation,
                            request: Box::new(locator.clone()),
                        };
                    }
                }
            }
        }

        incoming_tasks.abort_all();
        let _ = incoming_tasks.join_next().await;
        let _ = events.send(AppEvent::Pending(0)).await;
        if shutdown_requested {
            return;
        }
        if let Some(request) = queued_action.take() {
            let _ = events
                .send(local_human_rejection(
                    &request,
                    "local_transport_unavailable",
                ))
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
                Some(ClientCommand::Refresh(_, _, _, _) | ClientCommand::ReadView { .. }) => continue,
                Some(ClientCommand::Human(request @ (HumanGovernanceRequest::Act { .. } | HumanGovernanceRequest::Export { .. }))) => {
                    let _ = events.send(local_human_rejection(&request, "local_transport_unavailable")).await;
                }
                Some(ClientCommand::Human(HumanGovernanceRequest::Read { .. })) => continue,
                Some(ClientCommand::Recovery(_)) => {
                    let _ = events.send(AppEvent::Disconnected).await;
                }
                Some(ClientCommand::ConfigRead | ClientCommand::ConfigWrite(_)) => {
                    let _ = events.send(AppEvent::ConfigFailed).await;
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
            host_canary: None,
        }
    }

    #[tokio::test]
    async fn ordinary_read_failure_and_slow_response_keep_connection() {
        let data = std::env::temp_dir().join(format!("evertrace-read-{}", RequestId::new_v7()));
        let server = LocalServer::bind(&data, ServerOptions::new("read-test")).unwrap();
        let socket = server.socket_path().to_path_buf();
        let (shutdown, stop) = watch::channel(false);
        let server_task = tokio::spawn(server.run_dispatch(stop, |_, command| async move {
            match command {
                Command::Health => Ok(Response::Health(health())),
                Command::HumanGovernance(HumanGovernanceRequest::Read { request }) => {
                    if matches!(
                        request,
                        HumanReadRequest::List {
                            surface: HumanSurface::System,
                            ..
                        }
                    ) {
                        tokio::time::sleep(Duration::from_millis(2300)).await;
                        return Ok(Response::HumanGovernance(
                            HumanGovernanceResponse::Conflict {
                                current_frontier: 1,
                                current_revision_ref: None,
                            },
                        ));
                    }
                    Err(ErrorCode::InvalidInput)
                }
                _ => Err(ErrorCode::InvalidInput),
            }
        }));
        let (events, mut receiver) = AppEventSender::channel();
        let (commands, command_receiver) = channel();
        let actor = tokio::spawn(run(socket, events, command_receiver));
        assert!(matches!(receiver.recv().await, Some(AppEvent::Health(_))));
        let mut saw_slow = false;
        let mut saw_pending = false;
        let mut saw_view = false;
        for surface in [
            HumanSurface::Inbox,
            HumanSurface::System,
            HumanSurface::Explorer,
        ] {
            commands
                .send(if surface == HumanSurface::System {
                    ClientCommand::ReadView {
                        request: HumanReadRequest::List {
                            explorer_selection: None,
                            system_selection: None,
                            surface,
                            expected_frontier: None,
                            after: None,
                            limit: HUMAN_PAGE_LIMIT,
                        },
                        generation: 7,
                    }
                } else {
                    ClientCommand::Refresh(surface, None, None, 0)
                })
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(4), async {
                loop {
                    match receiver.recv().await {
                        Some(AppEvent::HumanReadFailed {
                            surface: actual,
                            code: HumanReadFailure::Rejected(ErrorCode::InvalidInput),
                            ..
                        }) if actual == surface => break,
                        Some(AppEvent::HumanReadFailed {
                            surface: HumanSurface::System,
                            code: HumanReadFailure::Slow,
                            ..
                        }) => saw_slow = true,
                        Some(AppEvent::Pending(1)) => saw_pending = true,
                        Some(AppEvent::HumanRead {
                            surface: HumanSurface::System,
                            locator,
                            ..
                        }) if surface == HumanSurface::System => {
                            assert!(saw_slow && saw_pending);
                            assert!(matches!(locator,HumanReadLocator::View {generation:7,request} if matches!(*request,HumanReadLocator::List)));
                            saw_view=true;
                            break;
                        }
                        Some(AppEvent::Disconnected) | None => panic!("ordinary read disconnected"),
                        _ => {}
                    }
                }
            })
            .await
            .unwrap();
        }
        assert!(saw_slow && saw_pending && saw_view);
        commands.send(ClientCommand::Shutdown).await.unwrap();
        actor.await.unwrap();
        shutdown.send(true).unwrap();
        server_task.await.unwrap().unwrap();
        fs::remove_dir_all(data).unwrap();
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
    async fn stalled_read_has_fixed_hard_deadline_and_does_not_replay_write() {
        for config_write in [false, true] {
            let data = std::env::temp_dir().join(format!("evertrace-read-{}", RequestId::new_v7()));
            let server = LocalServer::bind(&data, ServerOptions::new("read-timeout")).unwrap();
            let socket = server.socket_path().to_path_buf();
            let (_shutdown, stop) = watch::channel(false);
            let writes = Arc::new(AtomicUsize::new(0));
            let observed_writes = writes.clone();
            let server_task = tokio::spawn(server.run_dispatch(stop, move |_, command| {
                let writes = observed_writes.clone();
                async move {
                    match command {
                        Command::Health => Ok(Response::Health(health())),
                        Command::HumanGovernance(HumanGovernanceRequest::Read { .. }) => {
                            std::future::pending().await
                        }
                        _ => {
                            writes.fetch_add(1, Ordering::Relaxed);
                            Err(ErrorCode::InvalidInput)
                        }
                    }
                }
            }));
            let (events, mut receiver) = AppEventSender::channel();
            let (commands, command_receiver) = channel();
            let actor = tokio::spawn(run(socket, events, command_receiver));
            assert!(matches!(receiver.recv().await, Some(AppEvent::Health(_))));
            let started = Instant::now();
            commands
                .send(ClientCommand::Refresh(HumanSurface::Inbox, None, None, 0))
                .await
                .unwrap();
            commands
                .send(ClientCommand::Human(proposal_action()))
                .await
                .unwrap();
            if config_write {
                commands
                    .send(ClientCommand::ConfigWrite(
                        evertrace_protocol::command::ConfigWriteCommand {
                            source: String::new(),
                            expected_file_hash: "0".repeat(64),
                        },
                    ))
                    .await
                    .unwrap();
            }
            let mut refresh = tokio::time::interval(Duration::from_millis(200));
            let mut timed_out = false;
            let mut disconnected = false;
            let mut rejected_unsent = false;
            let expected_deadline = if config_write {
                Duration::from_secs(10)
            } else {
                HUMAN_READ_HARD_DEADLINE
            };
            tokio::time::timeout(expected_deadline + Duration::from_secs(3), async {
            loop {
                tokio::select! {
                    _ = refresh.tick(), if !disconnected => {
                        commands.send(ClientCommand::Refresh(HumanSurface::System, None, None, 0)).await.unwrap();
                    }
                    event = receiver.recv() => match event {
                        Some(AppEvent::HumanReadFailed { code: HumanReadFailure::TimedOut, surface: HumanSurface::Inbox, .. }) => {
                            assert!(started.elapsed() >= HUMAN_READ_HARD_DEADLINE);
                            timed_out = true;
                        }
                        Some(AppEvent::HumanAction(HumanGovernanceResponse::Action { result })) => {
                            assert_eq!(result.reason.as_deref(), Some("local_transport_unavailable"));
                            rejected_unsent = true;
                        }
                        Some(AppEvent::Disconnected) => {
                            assert_eq!(timed_out, !config_write);
                            assert!(started.elapsed() >= expected_deadline);
                            disconnected = true;
                        }
                        Some(AppEvent::Health(_)) => {
                            assert!(disconnected && rejected_unsent);
                            break;
                        }
                        None => panic!("actor stopped"),
                        _ => {}
                    }
                }
            }
        }).await.unwrap();
            assert_eq!(writes.load(Ordering::Relaxed), 0);
            commands.send(ClientCommand::Shutdown).await.unwrap();
            actor.await.unwrap();
            server_task.abort();
            let _ = server_task.await;
            fs::remove_dir_all(data).unwrap();
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

        let export = HumanGovernanceRequest::Export {
            selections: vec![evertrace_protocol::dto::HumanExportSelection {
                object_ref: "object:work:task:test".into(),
                expected_revision_ref: None,
            }],
        };
        assert_eq!(
            stage_human(&pending, &mut queued_action, &mut latest_read, &export),
            HumanHandoff::RejectedBusy
        );
        let AppEvent::HumanAction(HumanGovernanceResponse::Export { result }) =
            local_human_rejection(&export, "local_busy")
        else {
            panic!("unsent export rejection");
        };
        assert_eq!(
            result.status,
            evertrace_protocol::dto::HumanExportStatus::Failed
        );
        assert_eq!(result.reason.as_deref(), Some("local_busy"));

        for surface in [HumanSurface::Explorer, HumanSurface::System] {
            assert_eq!(
                stage_human(
                    &pending,
                    &mut queued_action,
                    &mut latest_read,
                    &first_page_request(surface, None, None)
                ),
                HumanHandoff::Queued
            );
        }
        assert_eq!(
            latest_read,
            Some(first_page_request(HumanSurface::System, None, None))
        );
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

        // An idle TUI must outlive the server's two-second frame deadline.
        // Keep the existing notification/reconnect assertions on this same connection.
        assert!(
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if matches!(receiver.recv().await, Some(AppEvent::Disconnected) | None) {
                        break;
                    }
                }
            })
            .await
            .is_err()
        );

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
            assert!(rendered.contains("Loading this page"));
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
