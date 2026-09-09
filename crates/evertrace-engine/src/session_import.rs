//! Bounded, host-probe-qualified session catalog reads.

mod frozen_memory_export;

pub use frozen_memory_export::{
    FrozenMemoryExportImportError, FrozenMemoryExportImportOutcome,
    FrozenMemoryExportMigrationService, FrozenMemoryExportProvenance,
};

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use evertrace_capture::{
    CasDigest, ConfinedEntryType, ConfinedFileIdentity, ConfinedReadError, ConfinedRoot,
};
use evertrace_codex::{
    HostProbeReport,
    adapter_manifest::SessionCatalogRootKind,
    policy::RepositoryTrustState,
    source_catalog::{SessionCatalogRootError, qualify_requested_session_root},
};
use evertrace_domain::{
    evidence::SourceRevision,
    ids::{CommandId, JobId, RequestId},
};
use evertrace_store::{
    BodyStateReason, DurableJob, EventScope, JobBudget, JobStatus, JobTerminalAudit,
    JobTerminalOutcome, JobTerminalReason, JournalCommand, JournalEventDraft, JournalPayload,
    MetadataState, SessionAccessDecision, SessionBodyState, SessionImportCurrent,
    SessionImportCurrentView, SessionImportEvent, SessionImportEventKind, SessionMetadata,
    SourceKind, WorkspaceResolutionKind, repository::RepositoryCurrentView,
};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

use crate::{WriterActorError, WriterHandle, repository::read_report_repository_trust_before};

pub(crate) use evertrace_codex::session_import::MAX_RECORD_BYTES;
const SOURCE_FORMAT: &str = "codex_rollout_jsonl_v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionCatalogBudget {
    pub max_entries: usize,
    pub max_metadata_bytes: usize,
    pub deadline: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogedSession {
    pub session_id: String,
    pub source_instance_id: String,
    pub metadata: SessionMetadata,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionCatalogError {
    #[error("session catalog authority is unavailable")]
    Unavailable,
    #[error("session catalog layout is unsupported")]
    Unsupported,
    #[error("session catalog budget is exhausted")]
    Budget,
    #[error("session catalog changed during the read")]
    Changed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionImportAdminAction {
    QueueImport,
    RevokeAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionImportAdminOutcome {
    Queued,
    Revoked,
    NoDelta,
    Partial {
        changed: u32,
        unavailable: u32,
        remaining: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionImportServiceError {
    #[error("session import scope or authority is unavailable")]
    Unavailable,
    #[error("session import state is corrupt")]
    Corrupt,
    #[error("session import writer failed")]
    Writer,
    #[error("session import command is invalid")]
    InvalidCommand,
    #[error("session import frontier changed")]
    StaleFrontier,
}

#[derive(Clone)]
pub struct SessionImportAdminService {
    writer: WriterHandle,
    report: Arc<RwLock<Option<HostProbeReport>>>,
    effective_config_hash: [u8; 32],
}

#[derive(Clone)]
pub struct SessionCatalogService {
    writer: WriterHandle,
    effective_config_hash: [u8; 32],
    cursor: Arc<Mutex<CatalogCursor>>,
}

#[derive(Clone, Default)]
struct CatalogCursor {
    after: Option<String>,
    round_root: Option<(u64, u64)>,
    recovery: BTreeMap<String, SourceObservation>,
    recovery_after: Option<String>,
}

#[derive(Clone, Default)]
struct SourceObservation {
    unique: Option<CatalogedSession>,
    conflicting: bool,
}

impl SourceObservation {
    fn observe(&mut self, item: &CatalogedSession) {
        if let Some(previous) = &self.unique {
            if previous.metadata.source_path != item.metadata.source_path
                || previous.metadata.source_fingerprint != item.metadata.source_fingerprint
            {
                self.conflicting = true;
            }
        } else {
            self.unique = Some(item.clone());
        }
    }
}

impl CatalogCursor {
    fn begin_round(&mut self, current: &SessionImportCurrentView, root: ConfinedFileIdentity) {
        let identity = (root.device, root.inode);
        if self.after.is_some() {
            if self.round_root != Some(identity) {
                self.invalidate();
            }
            return;
        }
        self.round_root = Some(identity);
        self.recovery.clear();
        // The same small source bound as an admin batch; rotate the starting
        // source so an unresolved group cannot monopolize later scan rounds.
        let eligible = current.sessions.iter().filter(|(_, source)| {
            source.metadata.workspace_resolution_kind == WorkspaceResolutionKind::Unavailable
        });
        let mut last = None;
        for (key, _) in eligible
            .clone()
            .filter(|(key, _)| {
                self.recovery_after
                    .as_ref()
                    .is_none_or(|after| *key > after)
            })
            .chain(eligible.filter(|(key, _)| {
                self.recovery_after
                    .as_ref()
                    .is_some_and(|after| *key <= after)
            }))
            .take(16)
        {
            self.recovery
                .insert(key.clone(), SourceObservation::default());
            last = Some(key.clone());
        }
        if last.is_some() {
            self.recovery_after = last;
        }
    }

    fn invalidate(&mut self) {
        self.recovery.clear();
        self.round_root = None;
    }
}

impl SessionCatalogService {
    pub fn for_config(&self, config: &evertrace_domain::config::EffectiveConfig) -> Self {
        let mut operation = self.clone();
        operation.effective_config_hash = config.hash();
        operation
    }

    pub fn new(writer: WriterHandle, effective_config_hash: [u8; 32]) -> Self {
        Self {
            writer,
            effective_config_hash,
            cursor: Arc::new(Mutex::new(CatalogCursor::default())),
        }
    }

    pub async fn refresh(
        &self,
        report: &HostProbeReport,
    ) -> Result<usize, SessionImportServiceError> {
        let mut cursor = self.cursor.lock().await;
        let snapshot = self.writer.project().await.map_err(map_writer)?;
        let repositories = RepositoryCurrentView::from_snapshot(&snapshot)
            .map_err(|_| SessionImportServiceError::Corrupt)?;
        let current = SessionImportCurrentView::from_snapshot(&snapshot)
            .map_err(|_| SessionImportServiceError::Corrupt)?;
        let path = report
            .session_catalog_roots()
            .iter()
            .find(|root| root.root_kind == SessionCatalogRootKind::CodexSessions)
            .and_then(|root| root.canonical_absolute_path.as_deref())
            .map(PathBuf::from)
            .ok_or(SessionImportServiceError::Unavailable)?;
        let mut page = catalog_codex_sessions_after(
            report,
            &path,
            &repositories,
            SessionCatalogBudget {
                max_entries: 4096,
                max_metadata_bytes: 4 * 1024 * 1024,
                deadline: Instant::now() + std::time::Duration::from_millis(250),
            },
            cursor.after.as_deref(),
            64,
        )
        .map_err(|_| {
            cursor.invalidate();
            SessionImportServiceError::Unavailable
        })?;
        let mut next_cursor = cursor.clone();
        let updates = reconcile_catalog_page(&mut page, &repositories, &current, &mut next_cursor)
            .map_err(|_| {
                cursor.invalidate();
                SessionImportServiceError::Unavailable
            })?;
        let occurred_at_us = now_us().map_err(|_| SessionImportServiceError::Corrupt)?;
        let mut payloads = Vec::new();
        for (source_key, item) in updates {
            let old = current.sessions.get(&source_key);
            if old.is_some_and(|old| old.metadata == item.metadata) {
                continue;
            }
            metadata_events(
                old,
                item.session_id,
                old.map_or_else(
                    || Some(item.source_instance_id),
                    |old| old.source_instance_id.clone(),
                ),
                item.metadata,
                occurred_at_us,
                &mut payloads,
            )?;
        }
        if payloads.is_empty() {
            *cursor = next_cursor;
            return if page.unavailable {
                Err(SessionImportServiceError::Unavailable)
            } else {
                Ok(usize::from(page.has_more))
            };
        }
        let terminal_sessions = payloads
            .iter()
            .filter_map(|payload| match payload {
                JournalPayload::SessionImportEventRecorded(event)
                    if matches!(
                        event.event,
                        SessionImportEventKind::BodyStateAdvanced { .. }
                    ) =>
                {
                    match &event.event {
                        SessionImportEventKind::BodyStateAdvanced {
                            body_state: SessionBodyState::SourceReplaced,
                            ..
                        } => Some((event.source_key(), JobTerminalReason::SourceReplaced)),
                        SessionImportEventKind::BodyStateAdvanced {
                            body_state: SessionBodyState::BlockedScopeUnresolved,
                            ..
                        } => Some((event.source_key(), JobTerminalReason::SourceUnavailable)),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for (session_id, reason) in terminal_sessions {
            if let Some(mut job) = active_import_job(&snapshot, &session_id)? {
                job.state = JobStatus::Failed;
                job.lease_until_us = None;
                job.terminal = Some(Box::new(JobTerminalAudit {
                    outcome: JobTerminalOutcome::Failed,
                    reason,
                    result_ref: Some(format!("session_import:{session_id}")),
                }));
                payloads.push(JournalPayload::JobState(job));
            }
        }
        let requeued = payloads
            .iter()
            .filter_map(|payload| match payload {
                JournalPayload::SessionImportEventRecorded(event)
                    if matches!(
                        event.event,
                        SessionImportEventKind::BodyStateAdvanced {
                            body_state: SessionBodyState::Queued,
                            ..
                        }
                    ) =>
                {
                    Some((event.source_key(), event.revision))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for (session_id, generation) in requeued {
            let current = current
                .sessions
                .get(&session_id)
                .ok_or(SessionImportServiceError::Corrupt)?;
            payloads.push(JournalPayload::JobState(DurableJob {
                job_id: JobId::new_v7(),
                idempotency_key: format!("session_import:{session_id}"),
                target_revision: current.metadata.source_revision.as_str().to_owned(),
                target_watermark: current.source_event_seq,
                target_generation: generation,
                kind: "session_import_v1".into(),
                algorithm_revision: "session_import_v1".into(),
                model_id: None,
                priority: 0,
                state: JobStatus::Queued,
                attempt: 1,
                backoff_until_us: None,
                config_hash: self.effective_config_hash,
                budget: session_import_job_budget(),
                terminal: None,
                lease_until_us: None,
            }));
        }
        let count = payloads
            .iter()
            .filter(|payload| {
                matches!(payload, JournalPayload::SessionImportEventRecorded(event)
                if matches!(event.event, SessionImportEventKind::MetadataObserved { .. }))
            })
            .count();
        let request_id = RequestId::new_v7();
        let command = command(
            request_id,
            "session_catalog_refresh",
            occurred_at_us,
            self.effective_config_hash,
            SourceKind::System,
            payloads,
        )?;
        self.writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
            .map_err(|error| {
                cursor.invalidate();
                map_writer(error)
            })?;
        *cursor = next_cursor;
        if page.unavailable {
            Err(SessionImportServiceError::Unavailable)
        } else {
            Ok(count)
        }
    }
}

impl SessionImportAdminService {
    pub fn for_config(&self, config: &evertrace_domain::config::EffectiveConfig) -> Self {
        let mut operation = self.clone();
        operation.effective_config_hash = config.hash();
        operation
    }

    pub const fn new(
        writer: WriterHandle,
        report: Arc<RwLock<Option<HostProbeReport>>>,
        effective_config_hash: [u8; 32],
    ) -> Self {
        Self {
            writer,
            report,
            effective_config_hash,
        }
    }

    pub async fn handle(
        &self,
        request_id: RequestId,
        session_id: &str,
        action: SessionImportAdminAction,
        occurred_at_us: i64,
    ) -> Result<SessionImportAdminOutcome, SessionImportServiceError> {
        if !valid_session_id(session_id) || occurred_at_us < 0 {
            return Err(SessionImportServiceError::Unavailable);
        }
        let command_id = CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| SessionImportServiceError::Corrupt)?;
        if let Some(committed) = self
            .writer
            .committed_command(command_id)
            .await
            .map_err(map_writer)?
        {
            let matches = committed.payloads.iter().any(|payload| {
                let JournalPayload::SessionImportEventRecorded(event) = payload else {
                    return false;
                };
                event.session_id == session_id
                    && matches!(
                        (&event.event, action),
                        (
                            SessionImportEventKind::BodyStateAdvanced {
                                body_state: SessionBodyState::Queued,
                                ..
                            },
                            SessionImportAdminAction::QueueImport
                        ) | (
                            SessionImportEventKind::AccessDecision {
                                decision: SessionAccessDecision::Revoked,
                                ..
                            },
                            SessionImportAdminAction::RevokeAccess
                        )
                    )
            });
            return if matches {
                Ok(SessionImportAdminOutcome::NoDelta)
            } else {
                Err(SessionImportServiceError::Corrupt)
            };
        }
        let report = Arc::clone(&self.report).read_owned().await;
        let snapshot = self.writer.project().await.map_err(map_writer)?;
        let sessions = SessionImportCurrentView::from_snapshot(&snapshot)
            .map_err(|_| SessionImportServiceError::Corrupt)?;
        if !sessions
            .sessions
            .values()
            .any(|current| current.session_id == session_id)
        {
            return Err(SessionImportServiceError::Unavailable);
        }
        let sources = sessions.sessions.values().filter(|current| {
            current.session_id == session_id
                && match action {
                    SessionImportAdminAction::QueueImport => !matches!(
                        current.body_state,
                        SessionBodyState::Queued
                            | SessionBodyState::Importing
                            | SessionBodyState::Imported
                            | SessionBodyState::Partial
                    ),
                    SessionImportAdminAction::RevokeAccess => {
                        current.access_decision != Some(SessionAccessDecision::Revoked)
                    }
                }
        });
        let repositories = RepositoryCurrentView::from_snapshot(&snapshot)
            .map_err(|_| SessionImportServiceError::Corrupt)?;
        let mut events = Vec::new();
        let mut unavailable = 0;
        let mut changed = 0;
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        let mut remaining = 0_u32;
        for current in sources {
            if changed == 16 || Instant::now() >= deadline {
                remaining = remaining.saturating_add(1);
                continue;
            }
            let prepared = match action {
                SessionImportAdminAction::QueueImport => {
                    if matches!(
                        current.body_state,
                        SessionBodyState::Queued
                            | SessionBodyState::Importing
                            | SessionBodyState::Imported
                            | SessionBodyState::Partial
                    ) {
                        continue;
                    }
                    match current.metadata.workspace_resolution_kind {
                        WorkspaceResolutionKind::Repository => {
                            if !current
                                .metadata
                                .resolved_worktree_instance_id
                                .zip(report.as_ref())
                                .is_some_and(|(worktree_id, report)| {
                                    read_report_repository_trust_before(
                                        report,
                                        &repositories,
                                        worktree_id,
                                        deadline,
                                    )
                                    .state
                                        == RepositoryTrustState::Trusted
                                })
                            {
                                unavailable += 1;
                                continue;
                            }
                        }
                        WorkspaceResolutionKind::NonRepository => {}
                        WorkspaceResolutionKind::Ambiguous
                        | WorkspaceResolutionKind::Unavailable => {
                            unavailable += 1;
                            continue;
                        }
                    }
                    queue_command(
                        request_id,
                        current,
                        occurred_at_us,
                        self.effective_config_hash,
                    )?
                }
                SessionImportAdminAction::RevokeAccess => {
                    if current.metadata.workspace_resolution_kind
                        != WorkspaceResolutionKind::NonRepository
                    {
                        unavailable += 1;
                        continue;
                    }
                    if current.access_decision == Some(SessionAccessDecision::Revoked) {
                        continue;
                    }
                    revoke_command(
                        request_id,
                        current,
                        active_import_job(&snapshot, &current.source_key())?,
                        occurred_at_us,
                        self.effective_config_hash,
                    )?
                }
            };
            events.extend_from_slice(prepared.events());
            changed += 1;
        }
        if !events.is_empty() {
            let command = JournalCommand::new(
                CommandId::from_uuid(request_id.as_uuid())
                    .map_err(|_| SessionImportServiceError::Corrupt)?,
                events,
            )
            .map_err(|_| SessionImportServiceError::Corrupt)?;
            self.writer
                .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
                .await
                .map_err(map_writer)?;
        }
        if unavailable > 0 && changed == 0 && remaining == 0 {
            return Err(SessionImportServiceError::Unavailable);
        }
        if unavailable > 0 || remaining > 0 {
            return Ok(SessionImportAdminOutcome::Partial {
                changed,
                unavailable,
                remaining,
            });
        }
        if changed == 0 {
            return Ok(SessionImportAdminOutcome::NoDelta);
        }
        Ok(match action {
            SessionImportAdminAction::QueueImport => SessionImportAdminOutcome::Queued,
            SessionImportAdminAction::RevokeAccess => SessionImportAdminOutcome::Revoked,
        })
    }
}

pub fn catalog_codex_sessions(
    report: &HostProbeReport,
    requested_root: &Path,
    repositories: &RepositoryCurrentView,
    budget: SessionCatalogBudget,
) -> Result<Vec<CatalogedSession>, SessionCatalogError> {
    let page =
        catalog_codex_sessions_after(report, requested_root, repositories, budget, None, 256)?;
    if page.unavailable {
        return Err(SessionCatalogError::Unsupported);
    }
    let mut sources: BTreeMap<String, CatalogedSession> = BTreeMap::new();
    for item in page.sessions {
        if let Some(old) = sources.get_mut(&item.source_instance_id) {
            old.metadata = unavailable_metadata(&old.metadata);
        } else {
            sources.insert(item.source_instance_id.clone(), item);
        }
    }
    let mut sessions = sources.into_values().collect::<Vec<_>>();
    sessions.sort_by(|left, right| left.metadata.source_path.cmp(&right.metadata.source_path));
    Ok(sessions)
}

struct CatalogPage {
    root: ConfinedRoot,
    sessions: Vec<CatalogedSession>,
    last_scanned: Option<String>,
    has_more: bool,
    unavailable: bool,
    remaining: SessionCatalogBudget,
}

fn catalog_codex_sessions_after(
    report: &HostProbeReport,
    requested_root: &Path,
    repositories: &RepositoryCurrentView,
    budget: SessionCatalogBudget,
    after: Option<&str>,
    max_sessions: usize,
) -> Result<CatalogPage, SessionCatalogError> {
    if budget.max_entries == 0 || budget.max_metadata_bytes == 0 {
        return Err(SessionCatalogError::Budget);
    }
    let qualified = qualify_requested_session_root(
        report,
        SessionCatalogRootKind::CodexSessions,
        requested_root,
    )
    .map_err(map_root)?;
    let root = ConfinedRoot::open_external_source(qualified.path()).map_err(map_read)?;
    let mut reader = CatalogReader {
        root: &root,
        repositories,
        budget,
        seen_entries: 0,
        read_bytes: 0,
        sessions: Vec::new(),
        after,
        max_sessions,
        last_scanned: None,
        has_more: false,
        unavailable: false,
    };
    reader.walk()?;
    qualified.revalidate().map_err(map_root)?;
    reader
        .sessions
        .sort_by(|left, right| left.metadata.source_path.cmp(&right.metadata.source_path));
    Ok(CatalogPage {
        sessions: reader.sessions,
        last_scanned: reader.last_scanned,
        has_more: reader.has_more,
        unavailable: reader.unavailable,
        remaining: SessionCatalogBudget {
            max_entries: budget.max_entries - reader.seen_entries,
            max_metadata_bytes: budget.max_metadata_bytes - reader.read_bytes,
            deadline: budget.deadline,
        },
        root,
    })
}

struct CatalogReader<'a> {
    root: &'a ConfinedRoot,
    repositories: &'a RepositoryCurrentView,
    budget: SessionCatalogBudget,
    seen_entries: usize,
    read_bytes: usize,
    sessions: Vec<CatalogedSession>,
    after: Option<&'a str>,
    max_sessions: usize,
    last_scanned: Option<String>,
    has_more: bool,
    unavailable: bool,
}

fn current_catalog_source<'a>(
    current: &'a SessionImportCurrentView,
    item: &CatalogedSession,
) -> Option<&'a SessionImportCurrent> {
    current
        .sessions
        .get(&item.session_id)
        .filter(|old| {
            Path::new(&old.metadata.source_path)
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| evertrace_codex::session_import::rollout_ids_from_name(name).ok())
                .is_some_and(|(thread, rollout)| {
                    item.source_instance_id == format!("session-rollout:{thread}:{rollout}")
                })
        })
        .or_else(|| current.sessions.get(&item.source_instance_id))
}

fn unavailable_metadata(metadata: &SessionMetadata) -> SessionMetadata {
    let mut metadata = metadata.clone();
    metadata.workspace_resolution_kind = WorkspaceResolutionKind::Unavailable;
    metadata.resolved_repository_instance_id = None;
    metadata.resolved_worktree_instance_id = None;
    metadata
}

impl CatalogPage {
    fn probe(
        &mut self,
        relative: &str,
        repositories: &RepositoryCurrentView,
    ) -> Result<Option<CatalogedSession>, SessionCatalogError> {
        self.remaining.max_entries = self
            .remaining
            .max_entries
            .checked_sub(1)
            .ok_or(SessionCatalogError::Budget)?;
        let Some(identity) = self
            .root
            .probe_regular_file(Path::new(relative), self.remaining.deadline)
            .map_err(map_read)?
        else {
            return Ok(None);
        };
        let mut reader = CatalogReader {
            root: &self.root,
            repositories,
            budget: self.remaining,
            seen_entries: 0,
            read_bytes: 0,
            sessions: Vec::new(),
            after: None,
            max_sessions: 1,
            last_scanned: None,
            has_more: false,
            unavailable: false,
        };
        let result = reader.read_header(PathBuf::from(relative), identity);
        self.remaining.max_metadata_bytes -= reader.read_bytes;
        result.map(Some)
    }
}

fn reconcile_catalog_page(
    page: &mut CatalogPage,
    repositories: &RepositoryCurrentView,
    current: &SessionImportCurrentView,
    cursor: &mut CatalogCursor,
) -> Result<BTreeMap<String, CatalogedSession>, SessionCatalogError> {
    cursor.begin_round(current, page.root.identity());
    if page.unavailable {
        cursor.invalidate();
    }
    let mut updates: BTreeMap<String, CatalogedSession> = BTreeMap::new();
    for mut item in std::mem::take(&mut page.sessions) {
        let old = current_catalog_source(current, &item);
        let key = old.map_or_else(
            || item.source_instance_id.clone(),
            |old| old.source_key().to_owned(),
        );
        if let Some(observation) = cursor.recovery.get_mut(&key) {
            observation.observe(&item);
        }
        if let Some(previous) = updates.get_mut(&key) {
            if previous.metadata.source_path != item.metadata.source_path {
                previous.metadata =
                    unavailable_metadata(old.map_or(&previous.metadata, |old| &old.metadata));
            }
            continue;
        }
        if let Some(old) = old {
            let mut unavailable =
                old.metadata.workspace_resolution_kind == WorkspaceResolutionKind::Unavailable;
            if old.metadata.source_path != item.metadata.source_path {
                match page.probe(&old.metadata.source_path, repositories) {
                    Ok(None) => {}
                    Ok(Some(_)) => unavailable = true,
                    Err(_) => {
                        unavailable = true;
                        page.unavailable = true;
                        cursor.invalidate();
                    }
                }
            }
            if unavailable {
                // A successful page cannot erase a conflict observed elsewhere
                // in the round (or lost on restart). Keep the incumbent intact.
                item.metadata = unavailable_metadata(&old.metadata);
            }
        }
        updates.insert(key, item);
    }
    if !page.has_more && !page.unavailable {
        let mut recovered = Vec::new();
        for (key, observation) in &cursor.recovery {
            let Some(item) = &observation.unique else {
                continue;
            };
            if observation.conflicting
                || (updates.len() + recovered.len() >= 64 && !updates.contains_key(key))
            {
                continue;
            }
            let old = &current.sessions[key];
            let result = (|| {
                let confirmed = page
                    .probe(&item.metadata.source_path, repositories)?
                    .ok_or(SessionCatalogError::Changed)?;
                if confirmed.source_instance_id != item.source_instance_id
                    || confirmed.metadata.source_fingerprint != item.metadata.source_fingerprint
                {
                    return Err(SessionCatalogError::Changed);
                }
                if old.metadata.source_path != item.metadata.source_path
                    && page
                        .probe(&old.metadata.source_path, repositories)?
                        .is_some()
                {
                    return Ok(None);
                }
                Ok(Some(confirmed))
            })();
            match result {
                Ok(Some(item)) => recovered.push((key.clone(), item)),
                Ok(None) => {}
                Err(_) => {
                    page.unavailable = true;
                    break;
                }
            }
        }
        if !page.unavailable {
            updates.extend(recovered);
        }
    }
    for (key, item) in &mut updates {
        if let Some(old) = current.sessions.get(key) {
            let metadata = &mut item.metadata;
            if metadata.workspace_resolution_kind == WorkspaceResolutionKind::Unavailable {
                *metadata = unavailable_metadata(&old.metadata);
            } else if metadata.source_fingerprint == old.metadata.source_fingerprint
                || metadata.file_size > old.metadata.file_size
                || (metadata.source_path != old.metadata.source_path
                    && metadata.file_size == old.metadata.file_size)
            {
                // A verified relocation retains the logical revision. The body
                // worker still validates the original protected prefix.
                metadata.source_revision = old.metadata.source_revision.clone();
            } else {
                metadata.source_revision =
                    SourceRevision::parse(metadata.source_fingerprint.clone())
                        .map_err(|_| SessionCatalogError::Unsupported)?;
            }
        }
    }
    page.root.revalidate().map_err(map_read)?;
    cursor.after = if page.has_more {
        page.last_scanned.clone()
    } else {
        None
    };
    if page.unavailable || !page.has_more {
        cursor.invalidate();
    }
    Ok(updates)
}

impl CatalogReader<'_> {
    fn walk(&mut self) -> Result<(), SessionCatalogError> {
        for year in self.directory(None)? {
            require_directory_component(&year.name, 4, &year.entry_type)?;
            if self.completed_directory(&year.name) {
                continue;
            }
            let year_path = PathBuf::from(&year.name);
            for month in self.directory(Some(&year_path))? {
                require_directory_component(&month.name, 2, &month.entry_type)?;
                let month_path = year_path.join(&month.name);
                if self.completed_directory(&month_path.to_string_lossy()) {
                    continue;
                }
                for day in self.directory(Some(&month_path))? {
                    require_directory_component(&day.name, 2, &day.entry_type)?;
                    let day_path = month_path.join(&day.name);
                    if self.completed_directory(&day_path.to_string_lossy()) {
                        continue;
                    }
                    let mut files = self.directory(Some(&day_path))?.into_iter().peekable();
                    while let Some(file) = files.next() {
                        if file.entry_type != ConfinedEntryType::File {
                            return Err(SessionCatalogError::Unsupported);
                        }
                        let relative = day_path.join(&file.name);
                        let key = relative.to_string_lossy().into_owned();
                        if self.after.is_some_and(|after| key.as_str() <= after) {
                            continue;
                        }
                        self.last_scanned = Some(key);
                        match self.read_header(relative, file.identity) {
                            Ok(item) => self.sessions.push(item),
                            Err(SessionCatalogError::Unsupported) => self.unavailable = true,
                            Err(error) => return Err(error),
                        }
                        if self.sessions.len() == self.max_sessions {
                            // Do not open the next date just to look ahead: it
                            // may exceed this page's directory-entry budget.
                            self.has_more = true;
                            if files.peek().is_none() {
                                self.last_scanned =
                                    Some(format!("{}/", day_path.to_string_lossy()));
                            }
                            return Ok(());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn completed_directory(&self, path: &str) -> bool {
        self.after.is_some_and(|after| {
            path < after
                && after
                    .strip_prefix(path)
                    .is_none_or(|tail| tail == "/" || !tail.starts_with('/'))
        })
    }

    fn directory(
        &mut self,
        relative: Option<&Path>,
    ) -> Result<Vec<evertrace_capture::ConfinedDirectoryEntry>, SessionCatalogError> {
        let remaining = self
            .budget
            .max_entries
            .checked_sub(self.seen_entries)
            .filter(|value| *value != 0)
            .ok_or(SessionCatalogError::Budget)?;
        let entries = self
            .root
            .list_directory(relative, remaining, self.budget.deadline)
            .map_err(map_read)?;
        self.seen_entries = self
            .seen_entries
            .checked_add(entries.len())
            .ok_or(SessionCatalogError::Budget)?;
        Ok(entries)
    }

    fn read_header(
        &mut self,
        relative: PathBuf,
        identity: ConfinedFileIdentity,
    ) -> Result<CatalogedSession, SessionCatalogError> {
        let session_id = session_id_from_name(
            relative
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(SessionCatalogError::Unsupported)?,
        )?;
        let mut remaining = self
            .budget
            .max_metadata_bytes
            .checked_sub(self.read_bytes)
            .filter(|value| *value != 0)
            .ok_or(SessionCatalogError::Budget)?;
        let result = read_session_header(
            self.root,
            &relative,
            identity,
            &mut remaining,
            self.budget.deadline,
        );
        self.read_bytes = self.budget.max_metadata_bytes - remaining;
        let header = result?;
        let workspace = header.payload.cwd.as_deref();
        let (resolution, repository_id, worktree_id) =
            resolve_workspace(workspace, &header.payload.git, self.repositories)?;
        let fingerprint = session_source_fingerprint(identity);
        let source_revision =
            session_source_revision(identity).map_err(|_| SessionCatalogError::Unsupported)?;
        Ok(CatalogedSession {
            source_instance_id: {
                let name = relative
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(SessionCatalogError::Unsupported)?;
                let (thread, rollout) =
                    evertrace_codex::session_import::rollout_ids_from_name(name)
                        .map_err(|_| SessionCatalogError::Unsupported)?;
                format!("session-rollout:{thread}:{rollout}")
            },
            session_id,
            metadata: SessionMetadata {
                source_path: relative.to_string_lossy().into_owned(),
                source_format: SOURCE_FORMAT.into(),
                started_at_us: None,
                ended_at_us: None,
                host: header.payload.originator,
                model_profile: header.payload.model_provider,
                workspace_hint: workspace.map(ToOwned::to_owned),
                repository_hint: None,
                worktree_hint: None,
                workspace_resolution_kind: resolution,
                resolved_repository_instance_id: repository_id,
                resolved_worktree_instance_id: worktree_id,
                file_size: identity.size,
                file_mtime_us: identity
                    .mtime_seconds
                    .checked_mul(1_000_000)
                    .and_then(|value| {
                        value.checked_add(i64::try_from(identity.mtime_nanoseconds / 1_000).ok()?)
                    })
                    .ok_or(SessionCatalogError::Unsupported)?,
                source_fingerprint: fingerprint.to_string(),
                source_revision,
                parser_version: 1,
                metadata_state: MetadataState::Indexed,
            },
        })
    }
}

use evertrace_codex::session_import::{SessionGit, SessionMetaRecord};
#[cfg(test)]
use evertrace_codex::session_import::{SessionGitObject, SessionMetaPayload};

fn resolve_workspace(
    workspace: Option<&str>,
    git: &SessionGit,
    repositories: &RepositoryCurrentView,
) -> Result<
    (
        WorkspaceResolutionKind,
        Option<evertrace_domain::ids::RepositoryId>,
        Option<evertrace_domain::ids::WorktreeId>,
    ),
    SessionCatalogError,
> {
    let Some(workspace) = workspace else {
        return Ok((WorkspaceResolutionKind::Unavailable, None, None));
    };
    let mut matches = repositories
        .worktrees
        .values()
        .filter(|worktree| worktree.current_path.as_deref() == Some(workspace));
    let Some(worktree) = matches.next() else {
        return Ok(match git {
            SessionGit::Null => (WorkspaceResolutionKind::NonRepository, None, None),
            SessionGit::Object(object) => {
                let _ = (&object.commit_hash, &object.branch, &object.repository_url);
                (WorkspaceResolutionKind::Ambiguous, None, None)
            }
            SessionGit::Missing => (WorkspaceResolutionKind::Unavailable, None, None),
        });
    };
    if matches.next().is_some()
        || !repositories
            .repositories
            .contains_key(&worktree.repository_instance_id)
        || matches!(git, SessionGit::Null | SessionGit::Missing)
    {
        return Ok((WorkspaceResolutionKind::Ambiguous, None, None));
    }
    Ok((
        WorkspaceResolutionKind::Repository,
        Some(worktree.repository_instance_id),
        Some(worktree.worktree_instance_id),
    ))
}

pub(crate) fn session_id_from_name(name: &str) -> Result<String, SessionCatalogError> {
    evertrace_codex::session_import::session_id_from_name(name)
        .map_err(|_| SessionCatalogError::Unsupported)
}

pub(crate) fn read_session_header(
    root: &ConfinedRoot,
    relative: &Path,
    identity: ConfinedFileIdentity,
    remaining: &mut usize,
    deadline: Instant,
) -> Result<SessionMetaRecord, SessionCatalogError> {
    let name = relative
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(SessionCatalogError::Unsupported)?;
    session_id_from_name(name)?;
    let bytes = root
        .read_first_record(relative, identity, MAX_RECORD_BYTES, remaining, deadline)
        .map_err(map_read)?;
    evertrace_codex::session_import::parse_session_header(name, &bytes)
        .map_err(|_| SessionCatalogError::Unsupported)
}

fn require_directory_component(
    value: &str,
    length: usize,
    entry_type: &ConfinedEntryType,
) -> Result<(), SessionCatalogError> {
    if *entry_type != ConfinedEntryType::Directory
        || value.len() != length
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SessionCatalogError::Unsupported);
    }
    Ok(())
}

fn map_root(error: SessionCatalogRootError) -> SessionCatalogError {
    match error {
        SessionCatalogRootError::Unavailable | SessionCatalogRootError::Mismatch => {
            SessionCatalogError::Unavailable
        }
        SessionCatalogRootError::UnsafeIdentity => SessionCatalogError::Changed,
    }
}

fn map_read(error: ConfinedReadError) -> SessionCatalogError {
    match error {
        ConfinedReadError::Deadline | ConfinedReadError::LimitExceeded { .. } => {
            SessionCatalogError::Budget
        }
        ConfinedReadError::Changed => SessionCatalogError::Changed,
        _ => SessionCatalogError::Unsupported,
    }
}

pub(crate) fn session_source_fingerprint(identity: ConfinedFileIdentity) -> CasDigest {
    CasDigest::for_protected_bytes(
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            identity.device,
            identity.inode,
            identity.size,
            identity.mtime_seconds,
            identity.mtime_nanoseconds,
            identity.ctime_seconds,
            identity.ctime_nanoseconds
        )
        .as_bytes(),
    )
}

fn session_source_revision(identity: ConfinedFileIdentity) -> Result<SourceRevision, ()> {
    SourceRevision::parse(
        CasDigest::for_protected_bytes(
            format!("{}:{}", identity.device, identity.inode).as_bytes(),
        )
        .to_string(),
    )
    .map_err(|_| ())
}

fn queue_command(
    request_id: RequestId,
    current: &SessionImportCurrent,
    occurred_at_us: i64,
    config_hash: [u8; 32],
) -> Result<JournalCommand, SessionImportServiceError> {
    let mut revision = current.revision;
    let mut payloads = Vec::new();
    if current.metadata.workspace_resolution_kind == WorkspaceResolutionKind::NonRepository
        && current.access_decision != Some(SessionAccessDecision::Approved)
    {
        revision += 1;
        payloads.push(JournalPayload::SessionImportEventRecorded(Box::new(
            SessionImportEvent {
                source_instance_id: current.source_instance_id.clone(),
                session_id: current.session_id.clone(),
                revision,
                predecessor_revision: Some(revision - 1),
                occurred_at_us,
                event: SessionImportEventKind::AccessDecision {
                    decision: SessionAccessDecision::Approved,
                    local_request_ref: request_id,
                    provenance_refs: vec![format!("local_cli:{request_id}")],
                },
            },
        )));
    }
    revision += 1;
    payloads.push(JournalPayload::SessionImportEventRecorded(Box::new(
        SessionImportEvent {
            source_instance_id: current.source_instance_id.clone(),
            session_id: current.session_id.clone(),
            revision,
            predecessor_revision: Some(revision - 1),
            occurred_at_us,
            event: SessionImportEventKind::BodyStateAdvanced {
                body_state: SessionBodyState::Queued,
                reason: BodyStateReason::Requested,
            },
        },
    )));
    payloads.push(JournalPayload::JobState(DurableJob {
        job_id: if current.source_instance_id.is_some() {
            JobId::new_v7()
        } else {
            JobId::from_uuid(request_id.as_uuid())
                .map_err(|_| SessionImportServiceError::Corrupt)?
        },
        idempotency_key: format!("session_import:{}", current.source_key()),
        target_revision: current.metadata.source_revision.as_str().to_owned(),
        target_watermark: current.source_event_seq,
        target_generation: revision,
        kind: "session_import_v1".into(),
        algorithm_revision: "session_import_v1".into(),
        model_id: None,
        priority: 0,
        state: JobStatus::Queued,
        attempt: 1,
        backoff_until_us: None,
        config_hash,
        budget: session_import_job_budget(),
        terminal: None,
        lease_until_us: None,
    }));
    command(
        request_id,
        &current.session_id,
        occurred_at_us,
        config_hash,
        SourceKind::Manual,
        payloads,
    )
}

fn revoke_command(
    request_id: RequestId,
    current: &SessionImportCurrent,
    active_job: Option<DurableJob>,
    occurred_at_us: i64,
    config_hash: [u8; 32],
) -> Result<JournalCommand, SessionImportServiceError> {
    let mut revision = current.revision;
    let mut payloads = Vec::new();
    if matches!(
        current.body_state,
        SessionBodyState::Queued
            | SessionBodyState::Importing
            | SessionBodyState::Imported
            | SessionBodyState::Partial
    ) {
        revision += 1;
        payloads.push(JournalPayload::SessionImportEventRecorded(Box::new(
            SessionImportEvent {
                source_instance_id: current.source_instance_id.clone(),
                session_id: current.session_id.clone(),
                revision,
                predecessor_revision: Some(revision - 1),
                occurred_at_us,
                event: SessionImportEventKind::BodyStateAdvanced {
                    body_state: SessionBodyState::BlockedUnapproved,
                    reason: BodyStateReason::ApprovalUnavailable,
                },
            },
        )));
    }
    revision += 1;
    payloads.push(JournalPayload::SessionImportEventRecorded(Box::new(
        SessionImportEvent {
            source_instance_id: current.source_instance_id.clone(),
            session_id: current.session_id.clone(),
            revision,
            predecessor_revision: Some(revision - 1),
            occurred_at_us,
            event: SessionImportEventKind::AccessDecision {
                decision: SessionAccessDecision::Revoked,
                local_request_ref: request_id,
                provenance_refs: vec![format!("local_cli:{request_id}")],
            },
        },
    )));
    if let Some(mut job) = active_job {
        job.state = JobStatus::Failed;
        job.lease_until_us = None;
        job.terminal = Some(Box::new(JobTerminalAudit {
            outcome: JobTerminalOutcome::Failed,
            reason: JobTerminalReason::Revoked,
            result_ref: Some(format!("session_import:{}", current.source_key())),
        }));
        payloads.push(JournalPayload::JobState(job));
    }
    command(
        request_id,
        &current.session_id,
        occurred_at_us,
        config_hash,
        SourceKind::Manual,
        payloads,
    )
}

pub(crate) fn session_import_job_budget() -> JobBudget {
    JobBudget {
        max_items: 16,
        max_bytes: Some(256 * 1024),
        max_input_tokens: None,
        max_output_tokens: None,
        max_calls: None,
        max_wall_time_ms: 250,
    }
}

pub(crate) fn active_import_job(
    snapshot: &evertrace_store::ProjectionSnapshot,
    session_id: &str,
) -> Result<Option<DurableJob>, SessionImportServiceError> {
    let key = format!("session_import:{session_id}");
    let mut jobs = snapshot.data_rows().filter_map(|row| {
        let json = row.payload_json.as_deref()?;
        let Ok(JournalPayload::JobState(job)) = serde_json::from_str(json) else {
            return None;
        };
        (job.idempotency_key == key && matches!(job.state, JobStatus::Queued | JobStatus::Leased))
            .then_some(job)
    });
    let job = jobs.next();
    if jobs.next().is_some() {
        return Err(SessionImportServiceError::Corrupt);
    }
    Ok(job)
}

fn command(
    request_id: RequestId,
    session_id: &str,
    occurred_at_us: i64,
    config_hash: [u8; 32],
    source_kind: SourceKind,
    payloads: Vec<JournalPayload>,
) -> Result<JournalCommand, SessionImportServiceError> {
    let events = payloads
        .into_iter()
        .map(|payload| {
            let event_session_id = match &payload {
                JournalPayload::SessionImportEventRecorded(event) => event.session_id.clone(),
                _ => session_id.to_owned(),
            };
            JournalEventDraft {
                occurred_at_us,
                source_kind,
                scope: EventScope {
                    session_id: Some(event_session_id),
                    ..EventScope::default()
                },
                causation_id: None,
                correlation_id: Some(request_id.to_string()),
                effective_config_hash: config_hash,
                algorithm_revision: "session_import_admin_v1".into(),
                payload,
            }
        })
        .collect();
    JournalCommand::new(
        CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| SessionImportServiceError::Corrupt)?,
        events,
    )
    .map_err(|_| SessionImportServiceError::Corrupt)
}

fn metadata_events(
    old: Option<&SessionImportCurrent>,
    session_id: String,
    source_instance_id: Option<String>,
    metadata: SessionMetadata,
    occurred_at_us: i64,
    payloads: &mut Vec<JournalPayload>,
) -> Result<(), SessionImportServiceError> {
    let mut revision = old.map_or(0, |value| value.revision);
    if let Some(old) = old {
        let source_changed = old.metadata.source_revision != metadata.source_revision
            || metadata.file_size < old.metadata.file_size
            || (metadata.source_path == old.metadata.source_path
                && metadata.file_size == old.metadata.file_size
                && metadata.file_mtime_us != old.metadata.file_mtime_us);
        let scope_unavailable = matches!(
            metadata.workspace_resolution_kind,
            WorkspaceResolutionKind::Ambiguous | WorkspaceResolutionKind::Unavailable
        );
        let transition = if source_changed
            && !matches!(
                old.body_state,
                SessionBodyState::NotImported | SessionBodyState::SourceReplaced
            ) {
            Some((
                SessionBodyState::SourceReplaced,
                BodyStateReason::SourceReplaced,
            ))
        } else if scope_unavailable
            && !matches!(
                old.body_state,
                SessionBodyState::NotImported
                    | SessionBodyState::BlockedScopeUnresolved
                    | SessionBodyState::Failed
                    | SessionBodyState::SourceReplaced
            )
        {
            Some((
                SessionBodyState::BlockedScopeUnresolved,
                BodyStateReason::ScopeUnresolved,
            ))
        } else {
            None
        };
        if let Some((body_state, reason)) = transition {
            revision += 1;
            payloads.push(JournalPayload::SessionImportEventRecorded(Box::new(
                SessionImportEvent {
                    source_instance_id: source_instance_id.clone(),
                    session_id: session_id.clone(),
                    revision,
                    predecessor_revision: Some(revision - 1),
                    occurred_at_us,
                    event: SessionImportEventKind::BodyStateAdvanced { body_state, reason },
                },
            )));
        }
    }
    let append_arrived = old.is_some_and(|old| {
        old.metadata.source_revision == metadata.source_revision
            && metadata.file_size > old.metadata.file_size
            && old.body_state == SessionBodyState::Imported
    });
    revision += 1;
    payloads.push(JournalPayload::SessionImportEventRecorded(Box::new(
        SessionImportEvent {
            source_instance_id: source_instance_id.clone(),
            session_id: session_id.clone(),
            revision,
            predecessor_revision: revision.checked_sub(1).filter(|value| *value != 0),
            occurred_at_us,
            event: SessionImportEventKind::MetadataObserved {
                metadata: Box::new(metadata),
            },
        },
    )));
    if append_arrived {
        revision += 1;
        payloads.push(JournalPayload::SessionImportEventRecorded(Box::new(
            SessionImportEvent {
                source_instance_id: source_instance_id.clone(),
                session_id,
                revision,
                predecessor_revision: Some(revision - 1),
                occurred_at_us,
                event: SessionImportEventKind::BodyStateAdvanced {
                    body_state: SessionBodyState::Queued,
                    reason: BodyStateReason::Requested,
                },
            },
        )));
    }
    Ok(())
}

fn map_writer(error: WriterActorError) -> SessionImportServiceError {
    match error {
        WriterActorError::InvalidInput | WriterActorError::IdempotencyConflict => {
            SessionImportServiceError::InvalidCommand
        }
        WriterActorError::StaleFrontier => SessionImportServiceError::StaleFrontier,
        WriterActorError::Stopped | WriterActorError::StoreCorrupt | WriterActorError::Store => {
            SessionImportServiceError::Writer
        }
    }
}

fn valid_session_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn now_us() -> Result<i64, ()> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_micros()).ok())
        .ok_or(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        time::{Duration, SystemTime},
    };

    use crate::repository::observe_session_catalog_report;

    use super::*;

    fn temp_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("evertrace-s28-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn metadata_catalog_reads_only_closed_header_from_qualified_root() {
        let adapter = temp_root();
        let sessions = adapter.join("sessions");
        let dated = sessions.join("2026/08/30");
        fs::create_dir_all(&dated).unwrap();
        for path in [
            &adapter,
            &sessions,
            &sessions.join("2026"),
            &sessions.join("2026/08"),
            &dated,
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let session_id = "019d0000-0000-7000-8000-000000000001";
        let transcript = dated.join(format!("rollout-2026-08-30T00-00-00-{session_id}.jsonl"));
        let header = serde_json::json!({
            "timestamp": "2026-08-30T00:00:00Z",
            "type": "session_meta",
            "payload": {
                "id": session_id,
                "session_id": session_id,
                "cwd": "/not-a-current-repository",
                "originator": "codex_cli_rs",
                "model_provider": "openai",
                "timestamp": "2026-08-30T00:00:00Z",
                "agent_nickname": null,
                "agent_path": null,
                "context_window": 258400,
                "history_mode": "save-all",
                "multi_agent_version": "1",
                "parent_thread_id": null,
                "thread_source": "cli",
                "git": null
            }
        });
        fs::write(
            &transcript,
            format!("{header}\nBODY_CANARY_MUST_NOT_BE_METADATA\n"),
        )
        .unwrap();
        fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
        let report =
            observe_session_catalog_report(transcript.to_str(), session_id, "tool-use-s28", None)
                .unwrap();
        let catalog = catalog_codex_sessions(
            &report,
            &sessions,
            &RepositoryCurrentView::default(),
            SessionCatalogBudget {
                max_entries: 8,
                max_metadata_bytes: 4096,
                deadline: Instant::now() + Duration::from_secs(1),
            },
        )
        .unwrap();
        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog[0].session_id, session_id);
        assert_eq!(
            catalog[0].metadata.workspace_resolution_kind,
            WorkspaceResolutionKind::NonRepository
        );
        let encoded = serde_json::to_string(&catalog[0].metadata).unwrap();
        assert!(!encoded.contains("BODY_CANARY"));
        let rollout = "019d0000-0000-7000-8000-000000000002";
        let second = dated.join(format!(
            "rollout-2026-08-30T00-00-01-{session_id}_{rollout}.jsonl"
        ));
        fs::write(&second, format!("{header}\n")).unwrap();
        fs::set_permissions(&second, fs::Permissions::from_mode(0o600)).unwrap();
        let budget = || SessionCatalogBudget {
            max_entries: 16,
            max_metadata_bytes: 4096,
            deadline: Instant::now() + Duration::from_secs(1),
        };
        let first = catalog_codex_sessions_after(
            &report,
            &sessions,
            &RepositoryCurrentView::default(),
            budget(),
            None,
            1,
        )
        .unwrap();
        let next = catalog_codex_sessions_after(
            &report,
            &sessions,
            &RepositoryCurrentView::default(),
            budget(),
            first.last_scanned.as_deref(),
            1,
        )
        .unwrap();
        assert_eq!(first.sessions[0].session_id, next.sessions[0].session_id);
        assert_ne!(
            first.sessions[0].source_instance_id,
            next.sessions[0].source_instance_id
        );
        let duplicate = dated.join(format!("rollout-2026-08-30T00-00-02-{session_id}.jsonl"));
        fs::write(&duplicate, format!("{header}\n")).unwrap();
        fs::set_permissions(&duplicate, fs::Permissions::from_mode(0o600)).unwrap();
        let conflict = catalog_codex_sessions_after(
            &report,
            &sessions,
            &RepositoryCurrentView::default(),
            budget(),
            None,
            1,
        )
        .unwrap();
        assert_eq!(
            conflict.sessions[0].metadata.workspace_resolution_kind,
            WorkspaceResolutionKind::NonRepository
        );
        let next = catalog_codex_sessions_after(
            &report,
            &sessions,
            &RepositoryCurrentView::default(),
            budget(),
            conflict.last_scanned.as_deref(),
            1,
        )
        .unwrap();
        assert_eq!(
            next.sessions[0].metadata.workspace_resolution_kind,
            WorkspaceResolutionKind::NonRepository
        );
        fs::remove_dir_all(adapter).unwrap();
    }

    #[test]
    fn native_header_binds_child_and_current_rollout_with_bounded_metadata() {
        let adapter = temp_root();
        let sessions = adapter.join("sessions");
        let dated = sessions.join("2026/09/09");
        fs::create_dir_all(&dated).unwrap();
        for path in [
            &adapter,
            &sessions,
            &sessions.join("2026"),
            &sessions.join("2026/09"),
            &dated,
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let session = "019d0000-0000-7000-8000-000000000001";
        let thread = "019d0000-0000-7000-8000-000000000002";
        let rollout = "019d0000-0000-7000-8000-000000000003";
        let transcript = dated.join(format!(
            "rollout-2026-09-09T12-00-00-{thread}_{rollout}.jsonl"
        ));
        // Synthetic fixed-format metadata: object source and instructions are ignored.
        let mut header = serde_json::json!({"ordinal":0, "timestamp":"2026-09-09T12:00:00Z", "type":"session_meta",
            "payload":{"id":thread, "session_id":session, "source":{"subagent":{"thread_spawn":{"parent_thread_id":session}}},
                "base_instructions":{"text":"PRIVATE_INSTRUCTIONS".repeat(1200)},
                "history_base":{"thread_id":session,"ordinal":4}, "agent_role":"worker"}});
        let encoded = format!("{header}\nBODY_NOT_METADATA\n");
        assert!(encoded.len() > 16 * 1024 && encoded.len() < MAX_RECORD_BYTES);
        fs::write(&transcript, &encoded).unwrap();
        fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
        let report =
            observe_session_catalog_report(transcript.to_str(), session, "child", Some(thread))
                .unwrap();
        assert!(
            observe_session_catalog_report(transcript.to_str(), session, "child", None).is_ok()
        );
        assert!(
            observe_session_catalog_report(
                transcript.to_str(),
                thread,
                "wrong-session",
                Some(thread)
            )
            .is_err()
        );
        assert!(
            observe_session_catalog_report(
                transcript.to_str(),
                session,
                "wrong-agent",
                Some(session)
            )
            .is_err()
        );
        let budget = |bytes| SessionCatalogBudget {
            max_entries: 32,
            max_metadata_bytes: bytes,
            deadline: Instant::now() + Duration::from_secs(2),
        };
        let catalog = catalog_codex_sessions(
            &report,
            &sessions,
            &RepositoryCurrentView::default(),
            budget(MAX_RECORD_BYTES),
        )
        .unwrap();
        assert_eq!(catalog[0].session_id, thread);
        assert!(
            !serde_json::to_string(&catalog[0].metadata)
                .unwrap()
                .contains("PRIVATE_INSTRUCTIONS")
        );
        assert!(matches!(
            catalog_codex_sessions(
                &report,
                &sessions,
                &RepositoryCurrentView::default(),
                budget(16 * 1024)
            ),
            Err(SessionCatalogError::Budget)
        ));
        let original = dated.join(format!("rollout-2026-09-09T12-00-00-{thread}.jsonl"));
        fs::write(&original, &encoded).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
        let both = catalog_codex_sessions(
            &report,
            &sessions,
            &RepositoryCurrentView::default(),
            budget(2 * MAX_RECORD_BYTES),
        )
        .unwrap();
        assert_eq!(both.len(), 2);
        assert_eq!(both[0].session_id, both[1].session_id);
        assert_ne!(both[0].source_instance_id, both[1].source_instance_id);
        fs::remove_file(&original).unwrap();
        header["ordinal"] = "0".into();
        fs::write(&transcript, format!("{header}\n")).unwrap();
        assert!(
            observe_session_catalog_report(transcript.to_str(), session, "invalid-ordinal", None)
                .is_err()
        );
        header["ordinal"] = 0.into();
        header["payload"]["id"] = session.into();
        fs::write(&transcript, format!("{header}\n")).unwrap();
        assert!(
            observe_session_catalog_report(transcript.to_str(), session, "wrong-thread", None)
                .is_err()
        );
        header["payload"]["id"] = thread.into();
        let mut boundary = header.to_string().into_bytes();
        boundary.resize(MAX_RECORD_BYTES, b' ');
        boundary.push(b'\n');
        fs::write(&transcript, &boundary).unwrap();
        assert!(
            observe_session_catalog_report(transcript.to_str(), session, "record-boundary", None)
                .is_ok()
        );
        boundary.insert(MAX_RECORD_BYTES, b' ');
        fs::write(&transcript, &boundary).unwrap();
        assert!(
            observe_session_catalog_report(
                transcript.to_str(),
                session,
                "record-over-boundary",
                None
            )
            .is_err()
        );
        fs::write(&transcript, header.to_string()).unwrap();
        assert!(
            observe_session_catalog_report(transcript.to_str(), session, "truncated", None)
                .is_err()
        );
        header["payload"]["base_instructions"] =
            serde_json::json!({"text":"x".repeat(MAX_RECORD_BYTES)});
        fs::write(&transcript, format!("{header}\n")).unwrap();
        assert!(
            observe_session_catalog_report(transcript.to_str(), session, "oversized", None)
                .is_err()
        );
        fs::remove_file(&transcript).unwrap();
        std::os::unix::fs::symlink("/dev/null", &transcript).unwrap();
        assert!(
            observe_session_catalog_report(transcript.to_str(), session, "symlink", None).is_err()
        );
        assert!(
            session_id_from_name(&format!("rollout-2026-02-30T12-00-00-{thread}.jsonl")).is_err()
        );
        fs::remove_dir_all(adapter).unwrap();
    }

    #[test]
    fn repository_candidate_does_not_fall_back_to_non_repository() {
        let payload = SessionMetaPayload {
            id: "session".into(),
            session_id: None,
            _forked_from_id: None,
            _forked_from_ordinal_exclusive: None,
            _agent_role: None,
            _dynamic_tools: None,
            _selected_capability_roots: None,
            _memory_mode: None,
            _history_base: None,
            _subagent_history_start_ordinal: None,
            cwd: Some("/unmatched".into()),
            originator: None,
            _cli_version: None,
            _source: None,
            model_provider: None,
            _payload_timestamp: None,
            _agent_nickname: None,
            _agent_path: None,
            _context_window: None,
            _history_mode: None,
            _multi_agent_version: None,
            _parent_thread_id: None,
            _thread_source: None,
            _base_instructions: None,
            _instructions: None,
            git: SessionGit::Object(SessionGitObject {
                commit_hash: Some("abc".into()),
                branch: Some("main".into()),
                repository_url: None,
            }),
        };
        assert_eq!(
            resolve_workspace(
                payload.cwd.as_deref(),
                &payload.git,
                &RepositoryCurrentView::default()
            )
            .unwrap()
            .0,
            WorkspaceResolutionKind::Ambiguous
        );
        let unknown = serde_json::from_value::<SessionMetaRecord>(serde_json::json!({
            "timestamp": "2026-08-30T00:00:00Z",
            "type": "session_meta",
            "payload": { "id": "session", "git": null, "future": true }
        }));
        assert!(unknown.is_err());
    }

    #[test]
    fn catalog_conflicts_across_dates_require_a_complete_valid_recovery_round() {
        let adapter = temp_root();
        let sessions = adapter.join("sessions");
        let thread = "019d0000-0000-7000-8000-000000000001";
        let rollout_b = "019d0000-0000-7000-8000-000000000002";
        let source = format!("session-rollout:{thread}:{thread}");
        let source_b = format!("session-rollout:{thread}:{rollout_b}");
        let a = sessions.join(format!(
            "2026/08/28/rollout-2026-08-28T00-00-00-{thread}.jsonl"
        ));
        let b = sessions.join(format!(
            "2026/08/29/rollout-2026-08-29T00-00-00-{thread}_{rollout_b}.jsonl"
        ));
        let duplicate = sessions.join(format!(
            "2026/08/30/rollout-2026-08-30T00-00-00-{thread}.jsonl"
        ));
        let header = format!(
            "{}\n",
            serde_json::json!({
                "timestamp": "2026-08-30T00:00:00Z", "type": "session_meta",
                "payload": { "id": thread, "session_id": thread, "cwd": "/nonrepo", "git": null }
            })
        );
        fs::create_dir_all(&adapter).unwrap();
        fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700)).unwrap();
        for path in [&a, &b, &duplicate] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, &header).unwrap();
        }
        let report =
            observe_session_catalog_report(a.to_str(), thread, "cross-page", None).unwrap();
        let mut cursor = CatalogCursor::default();
        let mut current = SessionImportCurrentView {
            frontier: 0,
            sessions: BTreeMap::new(),
        };
        // The real bounded reader and reconciliation owner are exercised here;
        // Store/admin/worker integration is covered by the S28 fixture.
        let scan = |cursor: &mut CatalogCursor, current: &mut SessionImportCurrentView, bytes| {
            let page = catalog_codex_sessions_after(
                &report,
                &sessions,
                &RepositoryCurrentView::default(),
                SessionCatalogBudget {
                    max_entries: 32,
                    max_metadata_bytes: bytes,
                    deadline: Instant::now() + Duration::from_secs(1),
                },
                cursor.after.as_deref(),
                1,
            );
            let mut page = match page {
                Ok(page) => page,
                Err(error) => {
                    cursor.invalidate();
                    return Err(error);
                }
            };
            let updates = reconcile_catalog_page(
                &mut page,
                &RepositoryCurrentView::default(),
                current,
                cursor,
            )?;
            let mut changed = 0;
            for (key, item) in updates {
                match current.sessions.get_mut(&key) {
                    Some(old) if old.metadata != item.metadata => {
                        old.metadata = item.metadata;
                        old.revision += 1;
                        changed += 1;
                    }
                    Some(_) => {}
                    None => {
                        current.sessions.insert(
                            key,
                            SessionImportCurrent {
                                session_id: item.session_id,
                                source_instance_id: Some(item.source_instance_id),
                                revision: 1,
                                metadata: item.metadata,
                                access_decision: None,
                                body_state: SessionBodyState::NotImported,
                                source_event_seq: 0,
                            },
                        );
                        changed += 1;
                    }
                }
            }
            if page.unavailable {
                Err(SessionCatalogError::Unavailable)
            } else {
                Ok(changed)
            }
        };
        for _ in 0..4 {
            scan(&mut cursor, &mut current, 8192).unwrap();
        }
        let incumbent = current.sessions[&source].clone();
        assert_eq!(
            incumbent.metadata.workspace_resolution_kind,
            WorkspaceResolutionKind::Unavailable
        );
        assert_eq!(
            incumbent.metadata.source_path,
            a.strip_prefix(&sessions).unwrap().to_str().unwrap()
        );
        assert_eq!(
            current.sessions[&source_b]
                .metadata
                .workspace_resolution_kind,
            WorkspaceResolutionKind::NonRepository
        );
        for _ in 0..4 {
            assert_eq!(scan(&mut cursor, &mut current, 8192).unwrap(), 0);
        }
        assert_eq!(current.sessions[&source], incumbent);

        fs::remove_file(&duplicate).unwrap();
        cursor = CatalogCursor::default(); // restart loses the opposite locator
        assert_eq!(scan(&mut cursor, &mut current, 8192).unwrap(), 0);
        assert_eq!(current.sessions[&source], incumbent); // a half round is no proof
        assert_eq!(
            scan(&mut cursor, &mut current, 1),
            Err(SessionCatalogError::Budget)
        );
        scan(&mut cursor, &mut current, 8192).unwrap();
        scan(&mut cursor, &mut current, 8192).unwrap();
        assert_eq!(current.sessions[&source], incumbent); // interrupted round cannot recover
        for _ in 0..3 {
            scan(&mut cursor, &mut current, 8192).unwrap();
        }
        assert_eq!(
            current.sessions[&source].metadata.workspace_resolution_kind,
            WorkspaceResolutionKind::NonRepository
        );
        assert_eq!(current.sessions[&source].access_decision, None);

        fs::write(&duplicate, &header).unwrap();
        for _ in 0..4 {
            scan(&mut cursor, &mut current, 8192).unwrap();
        }
        assert_eq!(
            current.sessions[&source].metadata.workspace_resolution_kind,
            WorkspaceResolutionKind::Unavailable
        );
        cursor = CatalogCursor::default();
        scan(&mut cursor, &mut current, 8192).unwrap(); // already passed incumbent date
        fs::set_permissions(&a, fs::Permissions::from_mode(0o666)).unwrap();
        scan(&mut cursor, &mut current, 8192).unwrap();
        assert_eq!(
            scan(&mut cursor, &mut current, 8192),
            Err(SessionCatalogError::Unavailable)
        );
        assert_eq!(
            current.sessions[&source].metadata.source_path,
            incumbent.metadata.source_path
        );
        fs::set_permissions(&a, fs::Permissions::from_mode(0o600)).unwrap();
        scan(&mut cursor, &mut current, 8192).unwrap();
        fs::remove_file(&a).unwrap();
        cursor = CatalogCursor::default();
        scan(&mut cursor, &mut current, 8192).unwrap();
        scan(&mut cursor, &mut current, 8192).unwrap();
        assert_eq!(
            current.sessions[&source].metadata.workspace_resolution_kind,
            WorkspaceResolutionKind::Unavailable
        );
        // A changed observation at the round endpoint also fails closed.
        fs::write(&duplicate, format!("{header}\n")).unwrap();
        assert_eq!(
            scan(&mut cursor, &mut current, 8192),
            Err(SessionCatalogError::Unavailable)
        );
        for _ in 0..3 {
            scan(&mut cursor, &mut current, 8192).unwrap();
        }
        let relocated = &current.sessions[&source];
        assert_eq!(
            relocated.metadata.workspace_resolution_kind,
            WorkspaceResolutionKind::NonRepository
        );
        assert_eq!(
            relocated.metadata.source_path,
            duplicate.strip_prefix(&sessions).unwrap().to_str().unwrap()
        );
        assert_eq!(
            relocated.metadata.source_revision,
            incumbent.metadata.source_revision
        );
        assert_eq!(relocated.access_decision, None);
        assert_eq!(current.sessions[&source_b].revision, 1);
        fs::remove_dir_all(adapter).unwrap();
    }

    #[test]
    fn catalog_cursor_eventually_visits_more_than_256_sessions() {
        let adapter = temp_root();
        let sessions = adapter.join("sessions");
        let dated = sessions.join("2026/08/30");
        fs::create_dir_all(&dated).unwrap();
        for path in [
            &adapter,
            &sessions,
            &sessions.join("2026"),
            &sessions.join("2026/08"),
            &dated,
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut transcript = None;
        for index in 0..300_u32 {
            let session_id = format!("019d0000-0000-7000-8000-{index:012}");
            let path = dated.join(format!("rollout-2026-08-30T00-00-00-{session_id}.jsonl"));
            let header = serde_json::json!({
                "timestamp": "2026-08-30T00:00:00Z",
                "type": "session_meta",
                "payload": { "id": session_id, "session_id": session_id, "cwd": "/nonrepo", "git": null }
            });
            fs::write(&path, format!("{header}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            transcript.get_or_insert(path);
        }
        let first_id = "019d0000-0000-7000-8000-000000000000";
        let report = observe_session_catalog_report(
            transcript.as_ref().unwrap().to_str(),
            first_id,
            "tool-use-page",
            None,
        )
        .unwrap();
        let mut cursor = None;
        let mut visited = Vec::new();
        loop {
            let page = catalog_codex_sessions_after(
                &report,
                &sessions,
                &RepositoryCurrentView::default(),
                SessionCatalogBudget {
                    max_entries: 1024,
                    max_metadata_bytes: 1024 * 1024,
                    deadline: Instant::now() + Duration::from_secs(10),
                },
                cursor.as_deref(),
                64,
            )
            .unwrap();
            visited.extend(page.sessions.into_iter().map(|item| item.session_id));
            if !page.has_more {
                break;
            }
            cursor = page.last_scanned;
        }
        assert_eq!(visited.len(), 300);
        assert!(visited.windows(2).all(|pair| pair[0] < pair[1]));
        fs::remove_dir_all(adapter).unwrap();
    }

    #[test]
    fn catalog_cursor_pages_headers_with_complete_bounded_identity_enumeration() {
        let adapter = temp_root();
        let sessions = adapter.join("sessions");
        let mut transcript = None;
        for (day, suffix) in [("28", 1_u64), ("29", 2), ("30", 3)] {
            let dated = sessions.join(format!("2026/08/{day}"));
            fs::create_dir_all(&dated).unwrap();
            let session_id = format!("019d0000-0000-7000-8000-{suffix:012}");
            let path = dated.join(format!("rollout-2026-08-{day}T00-00-00-{session_id}.jsonl"));
            let header = serde_json::json!({
                "timestamp": "2026-08-30T00:00:00Z",
                "type": "session_meta",
                "payload": { "id": session_id, "session_id": session_id, "cwd": "/nonrepo", "git": null }
            });
            fs::write(&path, format!("{header}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            transcript.get_or_insert((path, session_id));
        }
        for path in [
            &adapter,
            &sessions,
            &sessions.join("2026"),
            &sessions.join("2026/08"),
            &sessions.join("2026/08/28"),
            &sessions.join("2026/08/29"),
            &sessions.join("2026/08/30"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let (transcript, session_id) = transcript.unwrap();
        let report = observe_session_catalog_report(
            transcript.to_str(),
            &session_id,
            "tool-use-cross-day",
            None,
        )
        .unwrap();
        let mut cursor = None;
        let mut visited = 0;
        let mut page_index = 0;
        loop {
            let page = catalog_codex_sessions_after(
                &report,
                &sessions,
                &RepositoryCurrentView::default(),
                SessionCatalogBudget {
                    max_entries: 6,
                    max_metadata_bytes: 4096,
                    deadline: Instant::now() + Duration::from_secs(1),
                },
                cursor.as_deref(),
                1,
            )
            .unwrap_or_else(|error| panic!("page {page_index} failed: {error:?}"));
            page_index += 1;
            visited += page.sessions.len();
            if !page.has_more {
                break;
            }
            cursor = page.last_scanned;
        }
        assert_eq!(visited, 3);
        fs::remove_dir_all(adapter).unwrap();
    }
}
