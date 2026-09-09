//! Bounded, host-probe-qualified session catalog reads.

mod frozen_memory_export;

pub use frozen_memory_export::{
    FrozenMemoryExportImportError, FrozenMemoryExportImportOutcome,
    FrozenMemoryExportMigrationService, FrozenMemoryExportProvenance,
};

use std::{
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
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

use crate::{WriterActorError, WriterHandle, repository::read_report_repository_trust};

pub(crate) const MAX_RECORD_BYTES: usize = 64 * 1024;
const HEADER_CHUNK_BYTES: usize = 4 * 1024;
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
    cursor: Arc<Mutex<Option<String>>>,
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
            cursor: Arc::new(Mutex::new(None)),
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
        let path = report
            .session_catalog_roots()
            .iter()
            .find(|root| root.root_kind == SessionCatalogRootKind::CodexSessions)
            .and_then(|root| root.canonical_absolute_path.as_deref())
            .map(PathBuf::from)
            .ok_or(SessionImportServiceError::Unavailable)?;
        let page = catalog_codex_sessions_after(
            report,
            &path,
            &repositories,
            SessionCatalogBudget {
                max_entries: 4096,
                max_metadata_bytes: 4 * 1024 * 1024,
                deadline: Instant::now() + std::time::Duration::from_millis(250),
            },
            cursor.as_deref(),
            256,
        )
        .map_err(|_| SessionImportServiceError::Unavailable)?;
        let current = SessionImportCurrentView::from_snapshot(&snapshot)
            .map_err(|_| SessionImportServiceError::Corrupt)?;
        let occurred_at_us = now_us().map_err(|_| SessionImportServiceError::Corrupt)?;
        let mut payloads = Vec::new();
        let mut last_examined = cursor.clone();
        let mut changed = 0_usize;
        for item in page.sessions {
            let old = current.sessions.get(&item.session_id);
            let mut metadata = item.metadata;
            if let Some(old) = old {
                if old.metadata.source_path == metadata.source_path
                    && metadata.file_size > old.metadata.file_size
                {
                    metadata.source_revision = old.metadata.source_revision.clone();
                } else if old.metadata.source_path == metadata.source_path
                    && (metadata.file_size < old.metadata.file_size
                        || (metadata.file_size == old.metadata.file_size
                            && metadata.file_mtime_us != old.metadata.file_mtime_us))
                {
                    metadata.source_revision =
                        SourceRevision::parse(metadata.source_fingerprint.clone())
                            .map_err(|_| SessionImportServiceError::Corrupt)?;
                }
                if old.metadata == metadata {
                    last_examined = Some(metadata.source_path.clone());
                    continue;
                }
            }
            metadata_events(
                old,
                item.session_id,
                metadata,
                occurred_at_us,
                &mut payloads,
            )?;
            changed += 1;
            last_examined = payloads.iter().rev().find_map(|payload| match payload {
                JournalPayload::SessionImportEventRecorded(event) => match &event.event {
                    SessionImportEventKind::MetadataObserved { metadata } => {
                        Some(metadata.source_path.clone())
                    }
                    _ => None,
                },
                _ => None,
            });
            if changed == 64 {
                break;
            }
        }
        if payloads.is_empty() {
            *cursor = if page.has_more {
                page.last_scanned
            } else {
                None
            };
            return Ok(usize::from(page.has_more));
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
                        } => Some((event.session_id.clone(), JobTerminalReason::SourceReplaced)),
                        SessionImportEventKind::BodyStateAdvanced {
                            body_state: SessionBodyState::BlockedScopeUnresolved,
                            ..
                        } => Some((
                            event.session_id.clone(),
                            JobTerminalReason::SourceUnavailable,
                        )),
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
                    Some((event.session_id.clone(), event.revision))
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
            .map_err(map_writer)?;
        *cursor = if changed == 64 || page.has_more {
            last_examined
        } else {
            None
        };
        Ok(count)
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
        let report = Arc::clone(&self.report).read_owned().await;
        let snapshot = self.writer.project().await.map_err(map_writer)?;
        let sessions = SessionImportCurrentView::from_snapshot(&snapshot)
            .map_err(|_| SessionImportServiceError::Corrupt)?;
        let current = sessions
            .sessions
            .get(session_id)
            .ok_or(SessionImportServiceError::Unavailable)?;
        match action {
            SessionImportAdminAction::QueueImport => {
                if matches!(
                    current.body_state,
                    SessionBodyState::Queued
                        | SessionBodyState::Importing
                        | SessionBodyState::Imported
                        | SessionBodyState::Partial
                ) {
                    return Ok(SessionImportAdminOutcome::NoDelta);
                }
                match current.metadata.workspace_resolution_kind {
                    WorkspaceResolutionKind::Repository => {
                        let worktree_id = current
                            .metadata
                            .resolved_worktree_instance_id
                            .ok_or(SessionImportServiceError::Unavailable)?;
                        let repositories = RepositoryCurrentView::from_snapshot(&snapshot)
                            .map_err(|_| SessionImportServiceError::Corrupt)?;
                        let report = report
                            .as_ref()
                            .ok_or(SessionImportServiceError::Unavailable)?;
                        if read_report_repository_trust(report, &repositories, worktree_id).state
                            != RepositoryTrustState::Trusted
                        {
                            return Err(SessionImportServiceError::Unavailable);
                        }
                    }
                    WorkspaceResolutionKind::NonRepository => {}
                    WorkspaceResolutionKind::Ambiguous | WorkspaceResolutionKind::Unavailable => {
                        return Err(SessionImportServiceError::Unavailable);
                    }
                }
                let command = queue_command(
                    request_id,
                    current,
                    occurred_at_us,
                    self.effective_config_hash,
                )?;
                self.writer
                    .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
                    .await
                    .map_err(map_writer)?;
                Ok(SessionImportAdminOutcome::Queued)
            }
            SessionImportAdminAction::RevokeAccess => {
                if current.metadata.workspace_resolution_kind
                    != WorkspaceResolutionKind::NonRepository
                {
                    return Err(SessionImportServiceError::Unavailable);
                }
                if current.access_decision == Some(SessionAccessDecision::Revoked) {
                    return Ok(SessionImportAdminOutcome::NoDelta);
                }
                let command = revoke_command(
                    request_id,
                    current,
                    active_import_job(&snapshot, session_id)?,
                    occurred_at_us,
                    self.effective_config_hash,
                )?;
                self.writer
                    .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
                    .await
                    .map_err(map_writer)?;
                Ok(SessionImportAdminOutcome::Revoked)
            }
        }
    }
}

pub fn catalog_codex_sessions(
    report: &HostProbeReport,
    requested_root: &Path,
    repositories: &RepositoryCurrentView,
    budget: SessionCatalogBudget,
) -> Result<Vec<CatalogedSession>, SessionCatalogError> {
    Ok(
        catalog_codex_sessions_after(report, requested_root, repositories, budget, None, 256)?
            .sessions,
    )
}

struct CatalogPage {
    sessions: Vec<CatalogedSession>,
    last_scanned: Option<String>,
    has_more: bool,
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
    let root = ConfinedRoot::open_owned_private(qualified.path()).map_err(map_read)?;
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
    };
    reader.walk()?;
    qualified.revalidate().map_err(map_root)?;
    reader
        .sessions
        .sort_by(|left, right| left.session_id.cmp(&right.session_id));
    if reader
        .sessions
        .windows(2)
        .any(|pair| pair[0].session_id == pair[1].session_id)
    {
        return Err(SessionCatalogError::Unsupported);
    }
    Ok(CatalogPage {
        sessions: reader.sessions,
        last_scanned: reader.last_scanned,
        has_more: reader.has_more,
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
}

impl CatalogReader<'_> {
    fn walk(&mut self) -> Result<(), SessionCatalogError> {
        let after = self
            .after
            .map(|value| {
                let mut parts = value.split('/');
                let parsed = [parts.next(), parts.next(), parts.next(), parts.next()];
                if parsed.iter().any(|part| part.is_none()) || parts.next().is_some() {
                    return Err(SessionCatalogError::Unsupported);
                }
                Ok(parsed.map(Option::unwrap))
            })
            .transpose()?;
        'catalog: for year in self.directory(None)? {
            require_directory_component(&year.name, 4, &year.entry_type)?;
            if after.is_some_and(|parts| year.name.as_str() < parts[0]) {
                continue;
            }
            let year_path = PathBuf::from(&year.name);
            for month in self.directory(Some(&year_path))? {
                require_directory_component(&month.name, 2, &month.entry_type)?;
                if after.is_some_and(|parts| {
                    year.name.as_str() == parts[0] && month.name.as_str() < parts[1]
                }) {
                    continue;
                }
                let month_path = year_path.join(&month.name);
                for day in self.directory(Some(&month_path))? {
                    require_directory_component(&day.name, 2, &day.entry_type)?;
                    if after.is_some_and(|parts| {
                        year.name.as_str() == parts[0]
                            && month.name.as_str() == parts[1]
                            && (day.name.as_str() < parts[2]
                                || (day.name.as_str() == parts[2] && parts[3].is_empty()))
                    }) {
                        continue;
                    }
                    let day_path = month_path.join(&day.name);
                    for file in self.directory(Some(&day_path))? {
                        if file.entry_type != ConfinedEntryType::File {
                            return Err(SessionCatalogError::Unsupported);
                        }
                        let relative = day_path.join(&file.name);
                        let key = relative.to_string_lossy().into_owned();
                        if self.after.is_some_and(|after| key.as_str() <= after) {
                            continue;
                        }
                        if self.sessions.len() == self.max_sessions {
                            self.has_more = true;
                            break 'catalog;
                        }
                        self.last_scanned = Some(key);
                        self.read_header(relative, file.identity)?;
                    }
                    if self.sessions.len() == self.max_sessions {
                        self.last_scanned = Some(format!("{}/", day_path.to_string_lossy()));
                        self.has_more = true;
                        break 'catalog;
                    }
                }
            }
        }
        Ok(())
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
    ) -> Result<(), SessionCatalogError> {
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
        self.sessions.push(CatalogedSession {
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
        });
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionMetaRecord {
    #[serde(rename = "timestamp")]
    _timestamp: String,
    #[serde(rename = "type")]
    record_type: String,
    pub(crate) payload: SessionMetaPayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionMetaPayload {
    pub(crate) id: String,
    #[serde(rename = "session_id")]
    pub(crate) session_id: Option<String>,
    cwd: Option<String>,
    originator: Option<String>,
    #[serde(rename = "cli_version")]
    _cli_version: Option<String>,
    #[serde(rename = "source")]
    _source: Option<serde::de::IgnoredAny>,
    model_provider: Option<String>,
    #[serde(rename = "timestamp")]
    _payload_timestamp: Option<String>,
    #[serde(rename = "agent_nickname")]
    _agent_nickname: Option<serde::de::IgnoredAny>,
    #[serde(rename = "agent_path")]
    _agent_path: Option<serde::de::IgnoredAny>,
    #[serde(rename = "context_window")]
    _context_window: Option<serde::de::IgnoredAny>,
    #[serde(rename = "history_mode")]
    _history_mode: Option<serde::de::IgnoredAny>,
    #[serde(rename = "multi_agent_version")]
    _multi_agent_version: Option<serde::de::IgnoredAny>,
    #[serde(rename = "parent_thread_id")]
    _parent_thread_id: Option<serde::de::IgnoredAny>,
    #[serde(rename = "thread_source")]
    _thread_source: Option<serde::de::IgnoredAny>,
    #[serde(rename = "base_instructions")]
    _base_instructions: Option<serde::de::IgnoredAny>,
    #[serde(rename = "instructions")]
    _instructions: Option<serde::de::IgnoredAny>,
    #[serde(rename = "forked_from_id")]
    _forked_from_id: Option<serde::de::IgnoredAny>,
    #[serde(rename = "forked_from_ordinal_exclusive")]
    _forked_from_ordinal_exclusive: Option<serde::de::IgnoredAny>,
    #[serde(rename = "agent_role", alias = "agent_type")]
    _agent_role: Option<serde::de::IgnoredAny>,
    #[serde(rename = "dynamic_tools")]
    _dynamic_tools: Option<serde::de::IgnoredAny>,
    #[serde(rename = "selected_capability_roots")]
    _selected_capability_roots: Option<serde::de::IgnoredAny>,
    #[serde(rename = "memory_mode")]
    _memory_mode: Option<serde::de::IgnoredAny>,
    #[serde(rename = "history_base")]
    _history_base: Option<serde::de::IgnoredAny>,
    #[serde(rename = "subagent_history_start_ordinal")]
    _subagent_history_start_ordinal: Option<serde::de::IgnoredAny>,
    #[serde(default, deserialize_with = "deserialize_session_git")]
    git: SessionGit,
}

#[derive(Default)]
enum SessionGit {
    #[default]
    Missing,
    Object(SessionGitObject),
    Null,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionGitObject {
    commit_hash: Option<String>,
    branch: Option<String>,
    repository_url: Option<String>,
}

fn deserialize_session_git<'de, D>(deserializer: D) -> Result<SessionGit, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<SessionGitObject>::deserialize(deserializer)
        .map(|value| value.map_or(SessionGit::Null, SessionGit::Object))
}

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

// Fixed rust-v0.153.4 rollout basename. The catalog key remains the thread,
// not the optional distinct rollout suffix and not the shared Hook session.
pub(crate) fn session_id_from_name(name: &str) -> Result<String, SessionCatalogError> {
    let core = name
        .strip_prefix("rollout-")
        .and_then(|value| value.strip_suffix(".jsonl"))
        .ok_or(SessionCatalogError::Unsupported)?;
    let timestamp = core.get(..19).ok_or(SessionCatalogError::Unsupported)?;
    if !valid_rollout_timestamp(timestamp) || core.get(19..20) != Some("-") {
        return Err(SessionCatalogError::Unsupported);
    }
    let ids = core.get(20..).ok_or(SessionCatalogError::Unsupported)?;
    let (thread, rollout) = ids.split_once('_').unwrap_or((ids, ids));
    if !native_uuid(thread) || !native_uuid(rollout) {
        return Err(SessionCatalogError::Unsupported);
    }
    Ok(thread.to_owned())
}

fn native_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn valid_rollout_timestamp(value: &str) -> bool {
    if value.len() != 19
        || !value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 | 13 | 16 => byte == b'-',
            10 => byte == b'T',
            _ => byte.is_ascii_digit(),
        })
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| value[range].parse::<u32>().unwrap_or(u32::MAX);
    let year = number(0..4);
    let month = number(5..7);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&number(8..10))
        && number(11..13) < 24
        && number(14..16) < 60
        && number(17..19) < 60
}

pub(crate) fn read_session_header(
    root: &ConfinedRoot,
    relative: &Path,
    identity: ConfinedFileIdentity,
    remaining: &mut usize,
    deadline: Instant,
) -> Result<SessionMetaRecord, SessionCatalogError> {
    let thread = session_id_from_name(
        relative
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(SessionCatalogError::Unsupported)?,
    )?;
    let mut bytes = Vec::new();
    loop {
        let limit = HEADER_CHUNK_BYTES
            .min(*remaining)
            // The record bound excludes its required newline; read budget does not.
            .min(MAX_RECORD_BYTES + 1 - bytes.len());
        if limit == 0 {
            return Err(SessionCatalogError::Budget);
        }
        let chunk = root
            .read_range(relative, identity, bytes.len() as u64, limit, deadline)
            .map_err(map_read)?;
        *remaining -= chunk.bytes.len();
        if let Some(newline) = chunk.bytes.iter().position(|byte| *byte == b'\n') {
            bytes.extend_from_slice(&chunk.bytes[..newline]);
            let header: SessionMetaRecord =
                serde_json::from_slice(&bytes).map_err(|_| SessionCatalogError::Unsupported)?;
            if Instant::now() >= deadline {
                return Err(SessionCatalogError::Budget);
            }
            if header.record_type != "session_meta"
                || header.payload.id != thread
                || header
                    .payload
                    .session_id
                    .as_deref()
                    .is_some_and(|id| !native_uuid(id))
            {
                return Err(SessionCatalogError::Unsupported);
            }
            return Ok(header);
        }
        if bytes.len() + chunk.bytes.len() > MAX_RECORD_BYTES {
            return Err(SessionCatalogError::Budget);
        }
        if chunk.eof {
            return Err(SessionCatalogError::Unsupported);
        }
        bytes.extend_from_slice(&chunk.bytes);
    }
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
        job_id: JobId::from_uuid(request_id.as_uuid())
            .map_err(|_| SessionImportServiceError::Corrupt)?,
        idempotency_key: format!("session_import:{}", current.session_id),
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
            result_ref: Some(format!("session_import:{}", current.session_id)),
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
    metadata: SessionMetadata,
    occurred_at_us: i64,
    payloads: &mut Vec<JournalPayload>,
) -> Result<(), SessionImportServiceError> {
    let mut revision = old.map_or(0, |value| value.revision);
    if let Some(old) = old {
        let source_changed = old.metadata.source_path != metadata.source_path
            || old.metadata.source_revision != metadata.source_revision
            || metadata.file_size < old.metadata.file_size
            || (metadata.file_size == old.metadata.file_size
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
        old.metadata.source_path == metadata.source_path
            && old.metadata.source_revision == metadata.source_revision
            && metadata.file_size > old.metadata.file_size
            && old.body_state == SessionBodyState::Imported
    });
    revision += 1;
    payloads.push(JournalPayload::SessionImportEventRecorded(Box::new(
        SessionImportEvent {
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
        let mut header = serde_json::json!({"timestamp":"2026-09-09T12:00:00Z", "type":"session_meta",
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
        assert!(matches!(
            catalog_codex_sessions(
                &report,
                &sessions,
                &RepositoryCurrentView::default(),
                budget(2 * MAX_RECORD_BYTES)
            ),
            Err(SessionCatalogError::Unsupported)
        ));
        fs::remove_file(&original).unwrap();
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
    fn catalog_cursor_skips_completed_days_under_one_shared_entry_budget() {
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
