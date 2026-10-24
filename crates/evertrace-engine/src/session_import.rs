//! Bounded, host-probe-qualified session catalog reads.

mod frozen_memory_export;

pub use frozen_memory_export::{
    FrozenMemoryExportImportError, FrozenMemoryExportImportOutcome,
    FrozenMemoryExportMigrationService, FrozenMemoryExportProvenance,
};

use std::{
    collections::{BTreeMap, BTreeSet},
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
    MetadataState, ProspectiveSourceOrigin, SessionAccessDecision, SessionBodyState,
    SessionImportCurrent, SessionImportCurrentView, SessionImportEvent, SessionImportEventKind,
    SessionMetadata, SourceKind, SourceObservationGuard, SourceObservationGuardInput,
    SourceObservationGuardSelector, SourceObservationProgress, SourceObservationRepositorySelector,
    SourceObservationS11Facts, SourceObservationS11Selector, WorkspaceResolutionKind,
    repository::RepositoryCurrentView,
};
use thiserror::Error;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};
#[cfg(test)]
use tokio::sync::{Semaphore, mpsc};

use crate::{WriterActorError, WriterHandle};

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
    #[cfg(test)]
    observation_commit_seam: Option<Arc<ObservationCommitSeam>>,
}

pub struct SourceObservationPermit {
    _cursor: OwnedMutexGuard<CatalogCursor>,
    deadline: Instant,
}

#[cfg(test)]
#[derive(Clone)]
struct ObservationCommitSeam {
    prepared: mpsc::UnboundedSender<u64>,
    release: Arc<Semaphore>,
}

#[cfg(test)]
impl ObservationCommitSeam {
    async fn pause(&self, frontier: u64) {
        let _ = self.prepared.send(frontier);
        self.release
            .acquire()
            .await
            .expect("observation test seam remains open")
            .forget();
    }
}

#[derive(Clone, Default)]
struct CatalogCursor {
    after: Option<String>,
    live_after: Option<String>,
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
            #[cfg(test)]
            observation_commit_seam: None,
        }
    }

    #[cfg(test)]
    fn with_observation_commit_seam(mut self, seam: ObservationCommitSeam) -> Self {
        self.observation_commit_seam = Some(Arc::new(seam));
        self
    }

    pub async fn acquire_source_observation_permit(
        &self,
        deadline: Instant,
    ) -> Result<SourceObservationPermit, SessionImportServiceError> {
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            Arc::clone(&self.cursor).lock_owned(),
        )
        .await
        .map(|cursor| SourceObservationPermit {
            _cursor: cursor,
            deadline,
        })
        .map_err(|_| SessionImportServiceError::Unavailable)
    }

    pub async fn observe_native_session_source(
        &self,
        request_id: RequestId,
        report: &HostProbeReport,
        session_id: &str,
        transcript_path: &str,
        source_reference: &str,
        deadline: Instant,
    ) -> Result<bool, SessionImportServiceError> {
        let permit = self.acquire_source_observation_permit(deadline).await?;
        self.observe_native_session_source_with_permit(
            request_id,
            report,
            session_id,
            transcript_path,
            source_reference,
            permit,
        )
        .await
    }

    pub async fn observe_native_session_source_with_permit(
        &self,
        request_id: RequestId,
        report: &HostProbeReport,
        session_id: &str,
        transcript_path: &str,
        source_reference: &str,
        permit: SourceObservationPermit,
    ) -> Result<bool, SessionImportServiceError> {
        let deadline = permit.deadline;
        if Instant::now() >= deadline {
            return Err(SessionImportServiceError::Unavailable);
        }
        let budget = SessionCatalogBudget {
            max_entries: 8,
            max_metadata_bytes: 4 * 1024 * 1024,
            deadline,
        };
        let (expected_root, relative) =
            evertrace_codex::session_import::native_session_path(transcript_path)
                .map_err(|_| SessionImportServiceError::Unavailable)?;
        let qualified = qualify_requested_session_root(
            report,
            SessionCatalogRootKind::CodexSessions,
            &expected_root,
        )
        .map_err(|_| SessionImportServiceError::Unavailable)?;
        let catalog = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.writer.session_catalog_current_context(),
        )
        .await
        .map_err(|_| SessionImportServiceError::Unavailable)?
        .map_err(map_writer)?;
        let frontier = catalog.frontier;
        let mut repositories = catalog.repositories;
        let mut page = CatalogPage {
            root: ConfinedRoot::open_external_source(qualified.path())
                .map_err(|_| SessionImportServiceError::Unavailable)?,
            sessions: Vec::new(),
            last_scanned: None,
            has_more: false,
            unavailable: false,
            remaining: budget,
        };
        let relative = relative.to_string_lossy().into_owned();
        let item = page
            .probe(&relative, &repositories)
            .map_err(|_| SessionImportServiceError::Unavailable)?
            .filter(|candidate| {
                candidate.session_id == session_id
                    && Path::new(&candidate.metadata.source_path) == Path::new(&relative)
            })
            .ok_or(SessionImportServiceError::Unavailable)?;
        let had_catalog_source = current_catalog_source(&catalog.sessions, &item).is_some();
        drop(catalog.sessions);
        let source_instance_id =
            evertrace_domain::evidence::SourceInstanceId::parse(item.source_instance_id.clone())
                .map_err(|_| SessionImportServiceError::Unavailable)?;
        let mut source_revision = item.metadata.source_revision.clone();
        let source_keys =
            BTreeSet::from([item.session_id.clone(), item.source_instance_id.clone()]);
        let mut raw_contexts = BTreeMap::new();
        let mut source_slots = BTreeMap::new();
        let mut source_progress = Vec::new();
        for key in source_keys {
            let context = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.writer.session_import_context(&key),
            )
            .await
            .map_err(|_| SessionImportServiceError::Unavailable)?
            .map_err(map_writer)?;
            let Some(context) = context else {
                source_slots.insert(key, None);
                continue;
            };
            if context.current.source_key() != key {
                return Err(SessionImportServiceError::Corrupt);
            }
            let current = context.current.clone();
            let source = evertrace_domain::evidence::SourceInstanceId::parse(
                current.source_instance().to_owned(),
            )
            .map_err(|_| SessionImportServiceError::Corrupt)?;
            source_progress.push(SourceObservationProgress {
                source_instance_id: source,
                source_revision: current.metadata.source_revision.clone(),
                watermark: context.watermark.clone(),
                recorded_prefix_end: context.recorded_prefix_end,
            });
            source_slots.insert(key.clone(), Some(current));
            raw_contexts.insert(key, context);
        }
        let raw_sources = SessionImportCurrentView {
            frontier,
            sessions: raw_contexts
                .keys()
                .filter_map(|key| {
                    source_slots
                        .get(key)
                        .and_then(Option::as_ref)
                        .map(|current| (key.clone(), current.clone()))
                })
                .collect(),
        };
        let old = current_catalog_source(&raw_sources, &item).cloned();
        drop(raw_sources);
        if had_catalog_source && old.is_none() {
            return Err(SessionImportServiceError::Unavailable);
        }
        let command_id = CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| SessionImportServiceError::Corrupt)?;
        if let Some(committed) = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.writer.committed_command(command_id),
        )
        .await
        .map_err(|_| SessionImportServiceError::Unavailable)?
        .map_err(map_writer)?
        {
            return if compatible_source_observation_replay(
                &committed,
                command_id,
                session_id,
                &source_instance_id,
                source_reference,
            ) {
                Ok(false)
            } else {
                Err(SessionImportServiceError::Corrupt)
            };
        }
        let mut retained_repository_ids = BTreeSet::new();
        if let Some(old) = &old {
            let context = raw_contexts
                .get(&old.source_key())
                .ok_or(SessionImportServiceError::Corrupt)?;
            if !matches!(
                old.body_state,
                SessionBodyState::NotImported | SessionBodyState::SourceReplaced
            ) || old.access_decision == Some(SessionAccessDecision::Revoked)
                || old.metadata.prospective_origin.is_some()
            {
                return Ok(false);
            }
            retained_repository_ids.extend(old.metadata.read_restrictions());
            if let Some(id) = old.metadata.resolved_repository_instance_id {
                retained_repository_ids.insert(id);
            }
            if context.watermark.is_some() || context.recorded_prefix_end.is_some() {
                return Ok(false);
            }
        }
        drop(raw_contexts);

        let mut metadata = item.metadata.clone();
        let location = workspace_location(&metadata, deadline)
            .map_err(|_| SessionImportServiceError::Unavailable)?
            .ok_or(SessionImportServiceError::Unavailable)?;
        if crate::repository::read_report_path_trust_before(
            report,
            location.worktree_path.to_str(),
            deadline,
        )
        .state
            != RepositoryTrustState::Trusted
        {
            return Ok(false);
        }

        let mut workspace_hints = BTreeSet::new();
        if let Some(workspace) = metadata.workspace_hint.as_ref() {
            workspace_hints.insert(workspace.clone());
        }
        if let Some(old_workspace) = old
            .as_ref()
            .and_then(|current| current.metadata.workspace_hint.as_ref())
        {
            workspace_hints.insert(old_workspace.clone());
        }
        let repository_selector = SourceObservationRepositorySelector {
            identity: location.common_dir_filesystem,
            root_path: location.worktree_path.to_string_lossy().into_owned(),
            workspace_hints,
            retained_repository_ids,
        };
        let raw_repositories = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.writer
                .source_observation_authority_context(repository_selector.clone()),
        )
        .await
        .map_err(|_| SessionImportServiceError::Unavailable)?
        .map_err(map_writer)?;
        if repository_selector
            .retained_repository_ids
            .iter()
            .any(|id| !raw_repositories.repositories.contains_key(id))
        {
            return Err(SessionImportServiceError::Unavailable);
        }
        for (id, repository) in &raw_repositories.repositories {
            if !crate::repository::repository_read_gate(
                repository,
                raw_repositories.purged.contains(id),
            ) {
                return Ok(false);
            }
        }

        let occurred_at_us = now_us().map_err(|_| SessionImportServiceError::Corrupt)?;
        let mut payloads = Vec::new();
        let mut s11_preimage = None;
        crate::repository::with_probe_deadline(deadline, || {
            discover_source_repository(
                &metadata,
                &item.source_instance_id,
                RepositoryDiscoveryContext {
                    current: &mut repositories,
                    incomplete_history: &[],
                    occurred_at_us,
                    deadline,
                    payloads: &mut payloads,
                    location: Some(&location),
                    source_reference: Some(source_reference),
                    source_observation: Some(RepositoryDiscoverySourceObservation {
                        repository: &repository_selector,
                        selected: &mut s11_preimage,
                    }),
                },
            )
        })?;
        let snapshot = payloads.iter().find_map(|payload| match payload {
            JournalPayload::WorktreeSnapshotRecorded(snapshot)
                if snapshot.captured_at_us == occurred_at_us
                    && snapshot
                        .evidence_refs
                        .iter()
                        .any(|reference| reference == source_reference) =>
            {
                Some(snapshot.as_ref().clone())
            }
            _ => None,
        });
        let Some(snapshot) = snapshot else {
            return Ok(false);
        };
        let Some(snapshot_worktree) = repositories
            .worktrees
            .get(&snapshot.worktree_instance_id)
            .filter(|worktree| {
                worktree.lifecycle == evertrace_domain::repository::WorktreeLifecycle::Active
                    && worktree.current_path.as_deref() == location.worktree_path.to_str()
            })
            .cloned()
        else {
            return Ok(false);
        };
        if crate::repository::read_report_path_trust_before(
            report,
            location.worktree_path.to_str(),
            deadline,
        )
        .state
            != RepositoryTrustState::Trusted
        {
            return Ok(false);
        }
        let expected_source_instance = item.source_instance_id.clone();
        let final_item = page
            .probe(&relative, &repositories)
            .map_err(|_| SessionImportServiceError::Unavailable)?
            .filter(|candidate| {
                candidate.session_id == session_id
                    && candidate.source_instance_id == expected_source_instance
            })
            .ok_or(SessionImportServiceError::Unavailable)?;
        if final_item.source_instance_id != item.source_instance_id
            || final_item.metadata.source_path != item.metadata.source_path
        {
            return Err(SessionImportServiceError::Unavailable);
        }
        qualified
            .revalidate()
            .map_err(|_| SessionImportServiceError::Unavailable)?;
        let identity = page
            .root
            .probe_regular_file(Path::new(&relative), deadline)
            .map_err(|_| SessionImportServiceError::Unavailable)?
            .ok_or(SessionImportServiceError::Unavailable)?;
        // Do not combine a header/S11 observation with a replacement file's
        // identity. A transient race may be observed again; it grants nothing.
        if final_item.metadata.source_revision != item.metadata.source_revision
            || final_item.metadata.workspace_hint != item.metadata.workspace_hint
            || final_item.metadata.source_fingerprint
                != session_source_fingerprint(identity).to_string()
        {
            return Err(SessionImportServiceError::Unavailable);
        }
        metadata = final_item.metadata;
        metadata.source_fingerprint = session_source_fingerprint(identity).to_string();
        metadata.source_revision = session_source_revision(identity)
            .map_err(|_| SessionImportServiceError::Unavailable)?;
        if metadata.source_revision != source_revision {
            return Err(SessionImportServiceError::Unavailable);
        }
        metadata.file_size = identity.size;
        metadata.file_mtime_us = identity
            .mtime_seconds
            .checked_mul(1_000_000)
            .and_then(|value| {
                value.checked_add(i64::try_from(identity.mtime_nanoseconds / 1_000).ok()?)
            })
            .ok_or(SessionImportServiceError::Unavailable)?;
        if let Some(old) = &old {
            reconcile_source_revision(&old.metadata, &mut metadata)
                .map_err(|_| SessionImportServiceError::Unavailable)?;
            if metadata.source_revision == old.metadata.source_revision {
                metadata.workspace_resolution_kind = old.metadata.workspace_resolution_kind;
                metadata.resolved_repository_instance_id =
                    old.metadata.resolved_repository_instance_id;
                metadata.resolved_worktree_instance_id = old.metadata.resolved_worktree_instance_id;
            }
        }
        source_revision = metadata.source_revision.clone();
        retain_read_restrictions(
            &mut metadata,
            old.as_ref().map(|current| &current.metadata),
            &repositories,
            Some(&location),
        )?;
        let record_start =
            prospective_record_start(&page.root, &relative, identity, identity.size, deadline)?;
        metadata.prospective_origin = Some(ProspectiveSourceOrigin {
            snapshot_ref: snapshot.worktree_snapshot_id,
            observed_end: identity.size,
            record_start,
            closed: false,
        });
        let final_location = workspace_location(&metadata, deadline)
            .map_err(|_| SessionImportServiceError::Unavailable)?
            .ok_or(SessionImportServiceError::Unavailable)?;
        let selected_repository = repositories
            .repositories
            .get(&snapshot_worktree.repository_instance_id)
            .ok_or(SessionImportServiceError::Unavailable)?;
        if crate::repository::read_report_path_trust_before(
            report,
            final_location.worktree_path.to_str(),
            deadline,
        )
        .state
            != RepositoryTrustState::Trusted
            || final_location.common_dir_filesystem != location.common_dir_filesystem
            || final_location.git_dir != location.git_dir
            || final_location.worktree_path != location.worktree_path
            || selected_repository.common_dir_filesystem
                != Some(final_location.common_dir_filesystem)
            || snapshot_worktree
                .git_admin_path_history
                .last()
                .is_none_or(|path| Path::new(&path.path) != final_location.git_dir)
        {
            return Err(SessionImportServiceError::Unavailable);
        }
        page.root
            .revalidate_file(Path::new(&relative), identity)
            .map_err(|_| SessionImportServiceError::Unavailable)?;
        if old.as_ref().is_some_and(|old| old.metadata == metadata) {
            return Ok(false);
        }
        let target_revision_has_facts = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.writer.source_observation_revision_has_facts(
                source_instance_id.clone(),
                source_revision.clone(),
            ),
        )
        .await
        .map_err(|_| SessionImportServiceError::Unavailable)?
        .map_err(map_writer)?;
        if target_revision_has_facts {
            return Ok(false);
        }
        metadata_events(
            old.as_ref(),
            item.session_id.clone(),
            Some(item.source_instance_id.clone()),
            metadata.clone(),
            occurred_at_us,
            &mut payloads,
        )?;
        // N is this file's observed EOF: no eligible suffix exists yet.
        // A later bounded live refresh queues the first complete new record.
        let command = command(
            request_id,
            &item.session_id,
            occurred_at_us,
            self.effective_config_hash,
            SourceKind::System,
            payloads,
        )?;
        let (s11_selector, s11_facts) =
            s11_preimage.ok_or(SessionImportServiceError::Unavailable)?;
        let guard = SourceObservationGuard::from_preparation(
            SourceObservationGuardInput {
                selector: SourceObservationGuardSelector {
                    session_id: item.session_id.clone(),
                    source_instance_id,
                    source_revision,
                    command_id,
                    s11: s11_selector,
                },
                source_slots,
                source_progress,
                target_revision_has_facts,
                raw_repositories,
            },
            s11_facts,
        )
        .map_err(|_| SessionImportServiceError::Corrupt)?;
        drop(repositories);
        drop(page);
        drop(qualified);
        #[cfg(test)]
        if let Some(seam) = &self.observation_commit_seam {
            seam.pause(frontier).await;
        }
        if Instant::now() >= deadline {
            return Err(SessionImportServiceError::Unavailable);
        }
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.writer
                .commit_source_observation(command, occurred_at_us, guard),
        )
        .await
        .map_err(|_| SessionImportServiceError::Unavailable)?
        .map_err(map_writer)?;
        Ok(true)
    }

    pub async fn native_session_source_observed(
        &self,
        session_id: &str,
        transcript_path: &str,
        report: Option<&HostProbeReport>,
        deadline: Instant,
    ) -> Result<bool, SessionImportServiceError> {
        let (root, relative) =
            evertrace_codex::session_import::native_session_path(transcript_path)
                .map_err(|_| SessionImportServiceError::Unavailable)?;
        // An immutable origin cannot substitute for the daemon's transient
        // current namespace evidence after restart or a root change.
        let Some(report) = report else {
            return Ok(false);
        };
        let qualified = match qualify_requested_session_root(
            report,
            SessionCatalogRootKind::CodexSessions,
            &root,
        ) {
            Ok(qualified) => qualified,
            Err(_) => return Ok(false),
        };
        let name = relative
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(SessionImportServiceError::Unavailable)?;
        let (thread, rollout) = evertrace_codex::session_import::rollout_ids_from_name(name)
            .map_err(|_| SessionImportServiceError::Unavailable)?;
        if thread != session_id {
            return Ok(false);
        }
        let source_key = format!("session-rollout:{thread}:{rollout}");
        let context = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.writer.session_import_context(&source_key),
        )
        .await
        .map_err(|_| SessionImportServiceError::Unavailable)?
        .map_err(map_writer)?;
        let Some(context) = context else {
            return Ok(false);
        };
        qualified
            .revalidate()
            .map_err(|_| SessionImportServiceError::Unavailable)?;
        // This shortcut establishes no new origin or scope. Check the actual
        // known header/file against this one source; do not materialize the
        // complete catalog and repository history on every normal prompt.
        Ok(context.current.session_id == session_id
            && Path::new(&context.current.metadata.source_path) == relative
            && context.current.metadata.prospective_origin.is_some()
            && source_header_current(
                report,
                &context.current,
                deadline.min(Instant::now() + std::time::Duration::from_millis(250)),
            )
            .is_some())
    }

    pub async fn refresh(
        &self,
        report: &HostProbeReport,
    ) -> Result<usize, SessionImportServiceError> {
        let mut cursor = self
            .cursor
            .try_lock()
            .map_err(|_| SessionImportServiceError::Unavailable)?;
        let catalog = self
            .writer
            .session_catalog_current_context()
            .await
            .map_err(map_writer)?;
        let frontier = catalog.frontier;
        let mut repositories = catalog.repositories;
        let current = catalog.sessions;
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
        let preflight_deadline = Instant::now() + std::time::Duration::from_millis(250);
        for (source_key, mut item) in updates {
            let old = current.sessions.get(&source_key);
            if let Some(old) = old
                && old.metadata.source_revision == item.metadata.source_revision
            {
                item.metadata.workspace_resolution_kind = old.metadata.workspace_resolution_kind;
                item.metadata.resolved_repository_instance_id =
                    old.metadata.resolved_repository_instance_id;
                item.metadata.resolved_worktree_instance_id =
                    old.metadata.resolved_worktree_instance_id;
                item.metadata.repository_read_restrictions =
                    old.metadata.repository_read_restrictions.clone();
                item.metadata.prospective_origin = old.metadata.prospective_origin.clone();
                if let Some(origin) = item.metadata.prospective_origin.as_mut()
                    && !origin.closed
                    && origin.record_start.is_none()
                {
                    let identity = page
                        .root
                        .probe_regular_file(
                            Path::new(&item.metadata.source_path),
                            preflight_deadline,
                        )
                        .map_err(|_| SessionImportServiceError::Unavailable)?
                        .ok_or(SessionImportServiceError::Unavailable)?;
                    origin.record_start = prospective_record_start(
                        &page.root,
                        &item.metadata.source_path,
                        identity,
                        origin.observed_end,
                        preflight_deadline,
                    )?;
                }
            }
            let location = workspace_location(&item.metadata, preflight_deadline)
                .ok()
                .flatten();
            discover_source_repository(
                &item.metadata,
                &item.source_instance_id,
                RepositoryDiscoveryContext {
                    current: &mut repositories,
                    incomplete_history: &[],
                    occurred_at_us,
                    deadline: preflight_deadline,
                    payloads: &mut payloads,
                    location: location.as_ref(),
                    source_reference: None,
                    source_observation: None,
                },
            )?;
            retain_read_restrictions(
                &mut item.metadata,
                old.map(|old| &old.metadata),
                &repositories,
                location.as_ref(),
            )?;
            if old.is_some_and(|old| old.metadata == item.metadata) {
                continue;
            }
            let complete_live_append = old.is_some_and(|old| {
                let Some(origin) = old.metadata.prospective_origin.as_ref() else {
                    return false;
                };
                if origin.closed
                    || item.metadata.source_revision != old.metadata.source_revision
                    || item.metadata.file_size <= old.metadata.file_size
                {
                    return false;
                }
                let Some(start) = item
                    .metadata
                    .prospective_origin
                    .as_ref()
                    .and_then(|origin| origin.record_start)
                else {
                    return false;
                };
                let Ok(Some(identity)) = page
                    .root
                    .probe_regular_file(Path::new(&item.metadata.source_path), preflight_deadline)
                else {
                    return false;
                };
                item.metadata.file_size == identity.size
                    && has_complete_record_after(
                        &page.root,
                        &item.metadata.source_path,
                        identity,
                        start.max(old.metadata.file_size),
                        preflight_deadline,
                    )
            });
            let active_job = if let Some(old) = old {
                self.writer
                    .session_import_context(&old.source_key())
                    .await
                    .map_err(map_writer)?
                    .and_then(|current| current.job)
                    .is_some_and(|job| matches!(job.state, JobStatus::Queued | JobStatus::Leased))
            } else {
                false
            };
            metadata_events_internal(
                old,
                item.session_id,
                old.map_or_else(
                    || Some(item.source_instance_id),
                    |old| old.source_instance_id.clone(),
                ),
                item.metadata,
                occurred_at_us,
                complete_live_append && !active_job,
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
            let current = self
                .writer
                .session_import_context(&session_id)
                .await
                .map_err(map_writer)?;
            if let Some(mut job) = current
                .filter(|current| !current.repository_purged)
                .and_then(|current| current.job)
            {
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
        append_queued_import_jobs(&mut payloads, frontier, self.effective_config_hash)?;
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
            .commit_if_frontier(command, occurred_at_us, frontier)
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

    pub async fn refresh_active(
        &self,
        report: &HostProbeReport,
    ) -> Result<usize, SessionImportServiceError> {
        let mut cursor = self
            .cursor
            .try_lock()
            .map_err(|_| SessionImportServiceError::Unavailable)?;
        let catalog = self
            .writer
            .session_catalog_current_context()
            .await
            .map_err(map_writer)?;
        let frontier = catalog.frontier;
        let root_path = report
            .session_catalog_roots()
            .iter()
            .find(|root| root.root_kind == SessionCatalogRootKind::CodexSessions)
            .and_then(|root| root.canonical_absolute_path.as_deref())
            .map(PathBuf::from)
            .ok_or(SessionImportServiceError::Unavailable)?;
        let qualified = qualify_requested_session_root(
            report,
            SessionCatalogRootKind::CodexSessions,
            &root_path,
        )
        .map_err(|_| SessionImportServiceError::Unavailable)?;
        let deadline = Instant::now() + std::time::Duration::from_millis(250);
        let mut page = CatalogPage {
            root: ConfinedRoot::open_external_source(qualified.path())
                .map_err(|_| SessionImportServiceError::Unavailable)?,
            sessions: Vec::new(),
            last_scanned: None,
            has_more: false,
            unavailable: false,
            remaining: SessionCatalogBudget {
                max_entries: 4096,
                max_metadata_bytes: 4 * 1024 * 1024,
                deadline,
            },
        };
        let eligible = catalog.sessions.sessions.iter().filter(|(_, current)| {
            current
                .metadata
                .prospective_origin
                .as_ref()
                .is_some_and(|origin| {
                    !origin.closed
                        && matches!(
                            current.body_state,
                            SessionBodyState::Queued
                                | SessionBodyState::Importing
                                | SessionBodyState::NotImported
                                | SessionBodyState::Imported
                                | SessionBodyState::Partial
                                | SessionBodyState::Failed
                                | SessionBodyState::SourceReplaced
                        )
                        && current.access_decision != Some(SessionAccessDecision::Revoked)
                })
        });
        let live_after = cursor.live_after.clone();
        let selected = eligible
            .clone()
            .filter(|(key, _)| live_after.as_ref().is_none_or(|after| *key > after))
            .chain(
                eligible.filter(|(key, _)| live_after.as_ref().is_some_and(|after| *key <= after)),
            )
            .take(64)
            .map(|(key, current)| (key.clone(), current.clone()))
            .collect::<Vec<_>>();
        let mut payloads = Vec::new();
        let occurred_at_us = now_us().map_err(|_| SessionImportServiceError::Corrupt)?;
        for (source_key, old) in selected {
            if Instant::now() >= deadline {
                break;
            }
            // Selection is not progress: do not skip the unattempted tail
            // when the shared quantum expires partway through this page.
            cursor.live_after = Some(source_key.clone());
            let context = self
                .writer
                .session_import_context(&source_key)
                .await
                .map_err(map_writer)?;
            let Some(context) = context else {
                continue;
            };
            if context.repository_purged
                || context.current != old
                || context.current.access_decision == Some(SessionAccessDecision::Revoked)
            {
                continue;
            }
            let Some(mut item) = page
                .probe(&old.metadata.source_path, &catalog.repositories)
                .map_err(|_| SessionImportServiceError::Unavailable)?
            else {
                continue;
            };
            if item.source_instance_id != old.source_instance() {
                continue;
            }
            reconcile_source_revision(&old.metadata, &mut item.metadata)
                .map_err(|_| SessionImportServiceError::Unavailable)?;
            let same_revision = old.metadata.source_revision == item.metadata.source_revision;
            if same_revision {
                item.metadata.workspace_resolution_kind = old.metadata.workspace_resolution_kind;
                item.metadata.resolved_repository_instance_id =
                    old.metadata.resolved_repository_instance_id;
                item.metadata.resolved_worktree_instance_id =
                    old.metadata.resolved_worktree_instance_id;
                item.metadata.repository_read_restrictions =
                    old.metadata.repository_read_restrictions.clone();
                item.metadata.prospective_origin = old.metadata.prospective_origin.clone();
                if let Some(origin) = item.metadata.prospective_origin.as_mut()
                    && origin.record_start.is_none()
                {
                    let identity = page
                        .root
                        .probe_regular_file(Path::new(&item.metadata.source_path), deadline)
                        .map_err(|_| SessionImportServiceError::Unavailable)?
                        .ok_or(SessionImportServiceError::Unavailable)?;
                    origin.record_start = prospective_record_start(
                        &page.root,
                        &item.metadata.source_path,
                        identity,
                        origin.observed_end,
                        deadline,
                    )?;
                }
            }
            let origin = old.metadata.prospective_origin.as_ref();
            let has_complete_append = same_revision
                && origin.is_some_and(|origin| !origin.closed)
                && item
                    .metadata
                    .prospective_origin
                    .as_ref()
                    .and_then(|origin| origin.record_start)
                    .is_some_and(|start| {
                        let identity = page
                            .root
                            .probe_regular_file(Path::new(&item.metadata.source_path), deadline)
                            .ok()
                            .flatten();
                        identity.is_some_and(|identity| {
                            let after = start.max(old.metadata.file_size);
                            identity.size == item.metadata.file_size
                                && item.metadata.file_size > old.metadata.file_size
                                && has_complete_record_after(
                                    &page.root,
                                    &item.metadata.source_path,
                                    identity,
                                    after,
                                    deadline,
                                )
                        })
                    });
            if old.metadata == item.metadata && !has_complete_append {
                continue;
            }
            let has_active_job = context
                .job
                .as_ref()
                .is_some_and(|job| matches!(job.state, JobStatus::Queued | JobStatus::Leased));
            metadata_events_internal(
                Some(&old),
                item.session_id,
                old.source_instance_id.clone(),
                item.metadata,
                occurred_at_us,
                !has_active_job && has_complete_append,
                &mut payloads,
            )?;
        }
        qualified
            .revalidate()
            .map_err(|_| SessionImportServiceError::Unavailable)?;
        if payloads.is_empty() {
            return Ok(0);
        }
        append_queued_import_jobs(&mut payloads, frontier, self.effective_config_hash)?;
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
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for (session_id, reason) in terminal_sessions {
            if let Some(mut job) = self
                .writer
                .session_import_context(&session_id)
                .await
                .map_err(map_writer)?
                .and_then(|current| current.job)
                .filter(|job| matches!(job.state, JobStatus::Queued | JobStatus::Leased))
            {
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
        let count = payloads
            .iter()
            .filter(|payload| {
                matches!(payload, JournalPayload::SessionImportEventRecorded(event)
                    if matches!(event.event, SessionImportEventKind::MetadataObserved { .. }))
            })
            .count();
        let command = command(
            RequestId::new_v7(),
            "session_catalog_live_refresh",
            occurred_at_us,
            self.effective_config_hash,
            SourceKind::System,
            payloads,
        )?;
        self.writer
            .commit_if_frontier(command, occurred_at_us, frontier)
            .await
            .map_err(map_writer)?;
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
        let facts = self
            .writer
            .project_current(true)
            .await
            .map_err(map_writer)?;
        let sessions = SessionImportCurrentView::from_rows(facts.frontier(), facts.other_rows())
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
                    ),
                    SessionImportAdminAction::RevokeAccess => {
                        current.access_decision != Some(SessionAccessDecision::Revoked)
                    }
                }
        });
        let repositories = RepositoryCurrentView::from_rows(facts.frontier(), facts.other_rows())
            .map_err(|_| SessionImportServiceError::Corrupt)?;
        let purges = evertrace_store::purge::ScopePurgeCurrentView::from_rows(
            facts.frontier(),
            facts.other_rows(),
        )
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
                    ) {
                        continue;
                    }
                    let mut prepared_current = current.clone();
                    let location = workspace_location(&current.metadata, deadline)
                        .ok()
                        .flatten();
                    retain_read_restrictions(
                        &mut prepared_current.metadata,
                        Some(&current.metadata),
                        &repositories,
                        location.as_ref(),
                    )?;
                    if current.metadata.repository_read_restrictions.is_none() {
                        prepared_current.metadata.workspace_resolution_kind =
                            WorkspaceResolutionKind::Ambiguous;
                        prepared_current.metadata.resolved_repository_instance_id = None;
                        prepared_current.metadata.resolved_worktree_instance_id = None;
                    }
                    if prepared_current.metadata.read_restrictions().any(|id| {
                        repositories
                            .repositories
                            .get(&id)
                            .zip(report.as_ref())
                            .is_none_or(|(repository, report)| {
                                crate::repository::read_report_path_trust_before(
                                    report,
                                    Some(repository_trust_path(
                                        &prepared_current.metadata,
                                        repository,
                                        location.as_ref(),
                                        repositories.worktrees.values(),
                                    )),
                                    deadline,
                                )
                                .state
                                    != RepositoryTrustState::Trusted
                            })
                    }) || purges.events.keys().any(|id| {
                        prepared_current
                            .metadata
                            .read_restrictions()
                            .any(|restriction| restriction == *id)
                    }) {
                        unavailable += 1;
                        continue;
                    }
                    if prepared_current.metadata != current.metadata {
                        prepared_current.revision += 1;
                        events.push(JournalEventDraft::runtime(
                            occurred_at_us,
                            self.effective_config_hash,
                            "session_import_preflight",
                            JournalPayload::SessionImportEventRecorded(Box::new(
                                SessionImportEvent {
                                    source_instance_id: current.source_instance_id.clone(),
                                    session_id: current.session_id.clone(),
                                    revision: prepared_current.revision,
                                    predecessor_revision: Some(current.revision),
                                    occurred_at_us,
                                    event: SessionImportEventKind::MetadataObserved {
                                        metadata: Box::new(prepared_current.metadata.clone()),
                                    },
                                },
                            )),
                        ));
                    }
                    queue_command(
                        request_id,
                        &prepared_current,
                        occurred_at_us,
                        self.effective_config_hash,
                    )?
                }
                SessionImportAdminAction::RevokeAccess => {
                    if current.access_decision.is_none() {
                        let has_prospective_admission =
                            current.metadata.prospective_origin.is_some();
                        let archived = has_prospective_admission
                            || self
                                .writer
                                .session_import_context(&current.source_key())
                                .await
                                .map_err(map_writer)?
                                .is_some_and(|context| {
                                    context.watermark.is_some()
                                        || context.previous_revision.is_some()
                                });
                        if !archived {
                            unavailable += 1;
                            continue;
                        }
                    }
                    if current.access_decision == Some(SessionAccessDecision::Revoked) {
                        continue;
                    }
                    let mut prepared_current = current.clone();
                    if current.metadata.repository_read_restrictions.is_none() {
                        retain_read_restrictions(
                            &mut prepared_current.metadata,
                            Some(&current.metadata),
                            &repositories,
                            None,
                        )?;
                        prepared_current.revision += 1;
                        events.push(JournalEventDraft::runtime(
                            occurred_at_us,
                            self.effective_config_hash,
                            "session_import_preflight",
                            JournalPayload::SessionImportEventRecorded(Box::new(
                                SessionImportEvent {
                                    session_id: current.session_id.clone(),
                                    source_instance_id: current.source_instance_id.clone(),
                                    revision: prepared_current.revision,
                                    predecessor_revision: Some(current.revision),
                                    occurred_at_us,
                                    event: SessionImportEventKind::MetadataObserved {
                                        metadata: Box::new(prepared_current.metadata.clone()),
                                    },
                                },
                            )),
                        ));
                    }
                    revoke_command(
                        request_id,
                        &prepared_current,
                        active_import_job(facts.other_rows(), &current.source_key())?,
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
                .commit_if_frontier(command, occurred_at_us, facts.frontier())
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

fn compatible_source_observation_replay(
    committed: &evertrace_store::CommittedCommand,
    command_id: CommandId,
    session_id: &str,
    source: &evertrace_domain::evidence::SourceInstanceId,
    source_reference: &str,
) -> bool {
    if committed.command_id != command_id {
        return false;
    }
    let mut origin_ref = None;
    let mut metadata_events = 0;
    let mut boundary_snapshots = 0;
    let mut replacement_transition = None;
    let mut metadata_revision = None;
    let mut metadata_predecessor_revision = None;
    for payload in &committed.payloads {
        match payload {
            JournalPayload::SessionImportEventRecorded(event) => {
                if event.session_id != session_id
                    || event.source_instance_id.as_deref() != Some(source.as_str())
                {
                    return false;
                }
                let SessionImportEventKind::MetadataObserved { metadata } = &event.event else {
                    if matches!(
                        &event.event,
                        SessionImportEventKind::BodyStateAdvanced {
                            body_state: SessionBodyState::SourceReplaced,
                            reason: BodyStateReason::SourceReplaced,
                        }
                    ) && replacement_transition.is_none()
                    {
                        replacement_transition = Some((event.revision, event.predecessor_revision));
                        continue;
                    }
                    return false;
                };
                let Some(origin) = metadata.prospective_origin.as_ref() else {
                    return false;
                };
                if origin.closed
                    || origin_ref.is_some_and(|snapshot| snapshot != origin.snapshot_ref)
                {
                    return false;
                }
                origin_ref = Some(origin.snapshot_ref);
                metadata_events += 1;
                metadata_revision = Some(event.revision);
                metadata_predecessor_revision = event.predecessor_revision;
            }
            JournalPayload::WorktreeSnapshotRecorded(snapshot) => {
                if snapshot
                    .evidence_refs
                    .iter()
                    .any(|reference| reference == source_reference)
                {
                    boundary_snapshots += 1;
                    if origin_ref.is_some_and(|origin| origin != snapshot.worktree_snapshot_id) {
                        return false;
                    }
                    origin_ref = Some(snapshot.worktree_snapshot_id);
                }
            }
            JournalPayload::RepositoryInstanceRecorded(_)
            | JournalPayload::WorktreeInstanceRecorded(_)
            | JournalPayload::WorktreeTransitionRecorded(_)
            | JournalPayload::IntegrationEventRecorded(_) => {}
            _ => return false,
        }
    }
    let replacement_transition_matches =
        replacement_transition.is_none_or(|(transition_revision, predecessor)| {
            predecessor
                .is_some_and(|predecessor| predecessor.checked_add(1) == Some(transition_revision))
                && metadata_predecessor_revision == Some(transition_revision)
                && transition_revision.checked_add(1) == metadata_revision
        });
    metadata_events == 1
        && boundary_snapshots == 1
        && origin_ref.is_some()
        && replacement_transition_matches
}

fn unavailable_metadata(metadata: &SessionMetadata) -> SessionMetadata {
    let mut metadata = metadata.clone();
    metadata.workspace_resolution_kind = WorkspaceResolutionKind::Unavailable;
    metadata.resolved_repository_instance_id = None;
    metadata.resolved_worktree_instance_id = None;
    metadata.metadata_state = MetadataState::Partial;
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

fn prospective_record_start(
    root: &ConfinedRoot,
    relative: &str,
    identity: ConfinedFileIdentity,
    observed_end: u64,
    deadline: Instant,
) -> Result<Option<u64>, SessionImportServiceError> {
    if observed_end > identity.size {
        return Err(SessionImportServiceError::Unavailable);
    }
    if observed_end == 0 {
        return Ok(Some(0));
    }
    let previous = root
        .read_range(Path::new(relative), identity, observed_end - 1, 1, deadline)
        .map_err(|_| SessionImportServiceError::Unavailable)?;
    if previous.bytes.as_slice() == b"\n" {
        return Ok(Some(observed_end));
    }
    let mut offset = observed_end;
    let mut remaining = usize::try_from(identity.size.saturating_sub(observed_end))
        .unwrap_or(usize::MAX)
        .min(MAX_RECORD_BYTES + 1);
    while remaining > 0 && Instant::now() < deadline {
        let count = remaining.min(16 * 1024);
        let chunk = root
            .read_range(Path::new(relative), identity, offset, count, deadline)
            .map_err(|_| SessionImportServiceError::Unavailable)?;
        if let Some(index) = chunk.bytes.iter().position(|byte| *byte == b'\n') {
            return Ok(Some(
                offset
                    .checked_add(
                        u64::try_from(index + 1).map_err(|_| SessionImportServiceError::Corrupt)?,
                    )
                    .ok_or(SessionImportServiceError::Corrupt)?,
            ));
        }
        if chunk.bytes.is_empty() {
            break;
        }
        let consumed = chunk.bytes.len();
        offset = chunk.next_offset;
        remaining = remaining.saturating_sub(consumed);
    }
    Ok(None)
}

fn has_complete_record_after(
    root: &ConfinedRoot,
    relative: &str,
    identity: ConfinedFileIdentity,
    start: u64,
    deadline: Instant,
) -> bool {
    let mut offset = start;
    let mut remaining = usize::try_from(identity.size.saturating_sub(start))
        .unwrap_or(usize::MAX)
        .min(MAX_RECORD_BYTES + 1);
    while remaining > 0 && Instant::now() < deadline {
        let count = remaining.min(16 * 1024);
        let Ok(chunk) = root.read_range(Path::new(relative), identity, offset, count, deadline)
        else {
            return false;
        };
        if chunk.bytes.contains(&b'\n') {
            return true;
        }
        if chunk.bytes.is_empty() {
            return false;
        }
        remaining = remaining.saturating_sub(chunk.bytes.len());
        offset = chunk.next_offset;
    }
    false
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
            } else {
                // A verified relocation/append retains the logical revision.
                // The body worker still validates the protected prefix.
                reconcile_source_revision(&old.metadata, metadata)?;
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

fn reconcile_source_revision(
    old: &SessionMetadata,
    candidate: &mut SessionMetadata,
) -> Result<(), SessionCatalogError> {
    if candidate.source_fingerprint == old.source_fingerprint
        || candidate.file_size > old.file_size
        || (candidate.source_path != old.source_path && candidate.file_size == old.file_size)
    {
        candidate.source_revision = old.source_revision.clone();
    } else {
        candidate.source_revision = SourceRevision::parse(candidate.source_fingerprint.clone())
            .map_err(|_| SessionCatalogError::Unsupported)?;
    }
    Ok(())
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
        let (_, rollout) = evertrace_codex::session_import::rollout_ids_from_name(
            relative
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(SessionCatalogError::Unsupported)?,
        )
        .map_err(|_| SessionCatalogError::Unsupported)?;
        let source_instance = format!("session-rollout:{session_id}:{rollout}");
        let started_at_us = source_timestamp_us(&header._timestamp);
        let (resolution, repository_id, worktree_id) = resolve_workspace(
            workspace,
            &header.payload.git,
            started_at_us.map(|time| (source_instance.as_str(), time)),
            self.repositories,
        )?;
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
                started_at_us,
                ended_at_us: None,
                host: header.payload.originator,
                model_profile: header.payload.model_provider,
                workspace_hint: workspace.map(ToOwned::to_owned),
                repository_hint: None,
                worktree_hint: None,
                workspace_resolution_kind: resolution,
                resolved_repository_instance_id: repository_id,
                resolved_worktree_instance_id: worktree_id,
                repository_read_restrictions: None,
                prospective_origin: None,
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

fn retain_read_restrictions(
    metadata: &mut SessionMetadata,
    old: Option<&SessionMetadata>,
    repositories: &RepositoryCurrentView,
    location: Option<&crate::repository::WorkspaceGitLocation>,
) -> Result<(), SessionImportServiceError> {
    let mut restrictions = metadata
        .read_restrictions()
        .collect::<std::collections::BTreeSet<_>>();
    let candidates = old
        .into_iter()
        .flat_map(SessionMetadata::read_restrictions)
        .chain(repositories.repositories.values().filter_map(|repository| {
            repository_candidate_at(metadata, repository, location)
                .then_some(repository.repository_id)
        }))
        .chain(repositories.worktrees.values().filter_map(|worktree| {
            worktree
                .path_history
                .iter()
                .any(|path| {
                    location.map_or_else(
                        || metadata.workspace_matches_path(&path.path),
                        |location| Path::new(&path.path) == location.worktree_path,
                    )
                })
                .then_some(worktree.repository_instance_id)
        }));
    for id in candidates {
        restrictions.insert(id);
        if restrictions.len() > evertrace_store::MAX_REPOSITORY_READ_RESTRICTIONS {
            return Err(SessionImportServiceError::Unavailable);
        }
    }
    metadata.repository_read_restrictions = Some(restrictions.into_iter().collect());
    Ok(())
}

fn workspace_location(
    metadata: &SessionMetadata,
    deadline: Instant,
) -> Result<
    Option<crate::repository::WorkspaceGitLocation>,
    evertrace_domain::repository::ProbeUnavailableReason,
> {
    metadata
        .workspace_hint
        .as_deref()
        .map(|workspace| crate::repository::workspace_git_location(Path::new(workspace), deadline))
        .unwrap_or(Ok(None))
}

fn repository_candidate_at(
    metadata: &SessionMetadata,
    repository: &evertrace_domain::repository::RepositoryInstance,
    location: Option<&crate::repository::WorkspaceGitLocation>,
) -> bool {
    location.map_or_else(
        || metadata.repository_candidate(repository),
        |location| {
            repository.common_dir_filesystem == Some(location.common_dir_filesystem)
                || Path::new(&repository.current_path) == location.worktree_path
                || repository
                    .path_history
                    .iter()
                    .any(|path| Path::new(&path.path) == location.worktree_path)
        },
    )
}

fn workspace_registered<'a>(
    location: &crate::repository::WorkspaceGitLocation,
    repository: &evertrace_domain::repository::RepositoryInstance,
    mut worktrees: impl Iterator<Item = &'a evertrace_domain::repository::WorktreeInstance>,
) -> bool {
    repository.common_dir_filesystem == Some(location.common_dir_filesystem)
        && worktrees.any(|worktree| {
            worktree.repository_instance_id == repository.repository_id
                && worktree.current_path.as_deref().map(Path::new)
                    == Some(location.worktree_path.as_path())
                && worktree
                    .git_admin_path_history
                    .last()
                    .is_some_and(|path| Path::new(&path.path) == location.git_dir)
        })
}

fn prospective_origin_matches_current_instance<'a>(
    metadata: &SessionMetadata,
    location: &crate::repository::WorkspaceGitLocation,
    repository: impl Fn(
        &evertrace_domain::ids::RepositoryId,
    ) -> Option<&'a evertrace_domain::repository::RepositoryInstance>,
    worktree: impl Fn(
        &evertrace_domain::ids::WorktreeId,
    ) -> Option<&'a evertrace_domain::repository::WorktreeInstance>,
    snapshot: impl Fn(
        &evertrace_domain::ids::WorktreeSnapshotId,
    ) -> Option<&'a evertrace_domain::repository::WorktreeSnapshot>,
    worktrees: impl Iterator<Item = &'a evertrace_domain::repository::WorktreeInstance>,
) -> Option<bool> {
    let origin = metadata.prospective_origin.as_ref()?;
    let snapshot = snapshot(&origin.snapshot_ref)?;
    let saved_worktree = worktree(&snapshot.worktree_instance_id)?;
    let saved_repository = repository(&saved_worktree.repository_instance_id)?;
    if saved_repository.common_dir_filesystem != Some(location.common_dir_filesystem) {
        return Some(false);
    }
    let mut current = worktrees.filter(|worktree| {
        worktree.lifecycle == evertrace_domain::repository::WorktreeLifecycle::Active
            && worktree.current_path.as_deref().map(Path::new)
                == Some(location.worktree_path.as_path())
            && worktree
                .git_admin_path_history
                .last()
                .is_some_and(|path| Path::new(&path.path) == location.git_dir)
            && repository(&worktree.repository_instance_id).is_some_and(|repository| {
                repository.common_dir_filesystem == Some(location.common_dir_filesystem)
            })
    });
    let actual = current.next()?;
    if current.next().is_some() {
        return None;
    }
    Some(
        actual.worktree_instance_id == snapshot.worktree_instance_id
            && actual.repository_instance_id == saved_worktree.repository_instance_id,
    )
}

fn repository_trust_path<'a>(
    metadata: &SessionMetadata,
    repository: &'a evertrace_domain::repository::RepositoryInstance,
    location: Option<&'a crate::repository::WorkspaceGitLocation>,
    worktrees: impl Iterator<Item = &'a evertrace_domain::repository::WorktreeInstance>,
) -> &'a str {
    if let Some(location) = location
        .filter(|location| repository.common_dir_filesystem == Some(location.common_dir_filesystem))
        && let Some(path) = location.worktree_path.to_str()
    {
        return path;
    }
    worktrees
        .filter(|worktree| worktree.repository_instance_id == repository.repository_id)
        .flat_map(|worktree| worktree.path_history.iter())
        .filter(|path| metadata.workspace_matches_path(&path.path))
        .max_by_key(|path| path.path.len())
        .map_or(repository.current_path.as_str(), |path| path.path.as_str())
}

struct RepositoryDiscoveryContext<'a> {
    current: &'a mut RepositoryCurrentView,
    incomplete_history: &'a [evertrace_domain::ids::RepositoryId],
    occurred_at_us: i64,
    deadline: Instant,
    payloads: &'a mut Vec<JournalPayload>,
    location: Option<&'a crate::repository::WorkspaceGitLocation>,
    source_reference: Option<&'a str>,
    source_observation: Option<RepositoryDiscoverySourceObservation<'a>>,
}

struct RepositoryDiscoverySourceObservation<'a> {
    repository: &'a SourceObservationRepositorySelector,
    selected: &'a mut Option<(SourceObservationS11Selector, SourceObservationS11Facts)>,
}

fn discover_source_repository(
    metadata: &SessionMetadata,
    source: &str,
    context: RepositoryDiscoveryContext<'_>,
) -> Result<(), SessionImportServiceError> {
    let RepositoryDiscoveryContext {
        current: repositories,
        incomplete_history,
        occurred_at_us,
        deadline,
        payloads,
        location,
        source_reference,
        mut source_observation,
    } = context;
    let Some(workspace) = metadata.workspace_hint.as_deref() else {
        return Ok(());
    };
    let Some(location) = location else {
        return Ok(());
    };
    if Instant::now() >= deadline
        || (source_reference.is_none()
            && repositories.repositories.values().any(|repository| {
                workspace_registered(location, repository, repositories.worktrees.values())
            }))
    {
        return Ok(());
    }
    let Ok(root) = ConfinedRoot::open_external_source(Path::new(workspace)) else {
        return Ok(());
    };
    // Probe current HEADs first. Historical snapshot count must not consume
    // the Git quantum before current positive continuity can be considered.
    let identity_candidates = repositories
        .repositories
        .values()
        .filter(|repository| {
            repository.common_dir_filesystem == Some(location.common_dir_filesystem)
        })
        .map(|repository| repository.repository_id)
        .collect::<std::collections::BTreeSet<_>>();
    let heads = repositories
        .worktrees
        .values()
        .filter(|tree| identity_candidates.contains(&tree.repository_instance_id))
        .filter_map(|tree| tree.current_snapshot_id)
        .filter_map(|id| repositories.snapshots.get(&id))
        .filter_map(|snapshot| snapshot.head_oid.as_ref())
        .filter_map(|head| crate::repository::GitOid::parse(head).ok())
        .take(64)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut incomplete_history = incomplete_history
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    for snapshot in repositories.snapshots.values() {
        if let Some(head) = snapshot.head_oid.as_ref()
            && !heads.iter().any(|probed| probed.as_str() == head)
            && let Some(tree) = repositories.worktrees.get(&snapshot.worktree_instance_id)
        {
            incomplete_history.insert(tree.repository_instance_id);
        }
    }
    let evidence_refs = source_reference.map_or_else(
        || vec![format!("session_import_preflight:{source}")],
        |reference| vec![reference.to_owned()],
    );
    let known_admin_paths = if let Some(observation) = source_observation.as_ref() {
        let selector = SourceObservationS11Selector {
            repository: observation.repository.clone(),
            source_reference: source_reference.unwrap_or_default().to_owned(),
            worktree_entry_paths: BTreeSet::new(),
        };
        SourceObservationS11Facts::select(repositories, &selector)
            .worktrees
            .values()
            .filter(|worktree| !worktree.lifecycle.is_terminal())
            .filter_map(|worktree| {
                worktree
                    .git_admin_path_history
                    .last()
                    .map(|path| path.path.clone())
            })
            .collect::<Vec<_>>()
    } else {
        repositories.known_admin_paths()
    };
    let evidence = if source_reference.is_some() {
        crate::repository::probe_repository(
            Path::new(workspace),
            crate::repository::HostTrustDecision::Trusted,
            &evidence_refs,
            occurred_at_us,
            &crate::repository::ProbeLimits::default(),
            &known_admin_paths,
            &heads,
        )
    } else {
        crate::repository::probe_repository_identity(
            Path::new(workspace),
            &evidence_refs,
            occurred_at_us,
            deadline,
            &heads,
        )
    }
    .map_err(|_| SessionImportServiceError::Unavailable)?;
    if root.revalidate().is_err()
        || evidence.unavailable_reason.is_some()
        || evidence.common_dir_filesystem != Some(location.common_dir_filesystem)
        || evidence.git_dir.as_deref().map(Path::new) != Some(location.git_dir.as_path())
    {
        return Ok(());
    }
    if let Some(observation) = source_observation.as_mut() {
        let selector = SourceObservationS11Selector {
            repository: observation.repository.clone(),
            source_reference: source_reference.unwrap_or_default().to_owned(),
            worktree_entry_paths: evidence
                .worktree_entries
                .iter()
                .map(|entry| entry.path.clone())
                .collect(),
        };
        let facts = SourceObservationS11Facts::select(repositories, &selector);
        *observation.selected = Some((selector, facts));
    }
    let input = crate::repository::RepositoryResolveInput {
        view: repositories,
        evidence: &evidence,
        derived_from_hint: None,
    };
    let resolution = if let Some(reference) = source_reference {
        crate::repository::resolve_repository_source_start(&input, reference)
    } else {
        input.resolve_with_incomplete_history(&incomplete_history)
    }
    .map_err(|_| SessionImportServiceError::Unavailable)?;
    payloads.extend(resolution.payloads());
    for repository in resolution.repositories {
        repositories
            .repositories
            .insert(repository.repository_id, repository);
    }
    for worktree in resolution.worktrees {
        repositories
            .worktrees
            .insert(worktree.worktree_instance_id, worktree);
    }
    for snapshot in resolution.snapshots {
        repositories
            .snapshots
            .insert(snapshot.worktree_snapshot_id, snapshot);
    }
    for transition in resolution.transitions {
        repositories
            .transitions
            .insert(transition.worktree_transition_id, transition);
    }
    for integration in resolution.integrations {
        repositories
            .integrations
            .insert(integration.integration_event_id, integration);
    }
    Ok(())
}

/// Current restrictions for already durable receipts. Source-file availability
/// and approval for a newer revision do not authorize or invalidate old CAS.
pub(crate) fn source_read_allowed(
    report: &HostProbeReport,
    context: &evertrace_store::SessionImportContext,
    deadline: Instant,
) -> bool {
    source_read_decision(report, context, deadline).0
}

fn source_read_decision(
    report: &HostProbeReport,
    context: &evertrace_store::SessionImportContext,
    deadline: Instant,
) -> (bool, Vec<evertrace_domain::repository::RepositoryInstance>) {
    let current = &context.current;
    let restrictions = current
        .metadata
        .read_restrictions()
        .collect::<std::collections::BTreeSet<_>>();
    let Ok(location) = workspace_location(&current.metadata, deadline) else {
        return (false, Vec::new());
    };
    let owner = location.as_ref().and_then(|location| {
        let mut matches = context.read_repositories.iter().filter(|repository| {
            workspace_registered(location, repository, context.read_worktrees.iter())
        });
        let owner = matches.next()?;
        matches.next().is_none().then_some(owner.repository_id)
    });
    let mut allowed = !(location.is_some() && owner.is_none())
        && !context.repository_purged
        && current.access_decision != Some(SessionAccessDecision::Revoked);
    let mut revoked = Vec::new();
    for repository in context.read_repositories.iter().filter(|repository| {
        restrictions.contains(&repository.repository_id)
            || repository_candidate_at(&current.metadata, repository, location.as_ref())
            || (location.is_none()
                && context.read_worktrees.iter().any(|worktree| {
                    worktree.repository_instance_id == repository.repository_id
                        && worktree
                            .path_history
                            .iter()
                            .any(|path| current.metadata.workspace_matches_path(&path.path))
                }))
    }) {
        let trust_path = repository_trust_path(
            &current.metadata,
            repository,
            location.as_ref(),
            context.read_worktrees.iter(),
        );
        let trust =
            crate::repository::read_report_path_trust_before(report, Some(trust_path), deadline)
                .state;
        if trust == RepositoryTrustState::Untrusted
            && !context.repository_purged
            && !repository
                .capability_state
                .as_ref()
                .is_some_and(|state| state.trust_revoked)
        {
            revoked.push(repository.clone());
        }
        if !restrictions.contains(&repository.repository_id)
            || !crate::repository::repository_read_gate(repository, context.repository_purged)
            || trust != RepositoryTrustState::Trusted
        {
            allowed = false;
        }
    }
    (allowed && Instant::now() < deadline, revoked)
}

pub(crate) fn source_ingest_read_allowed(
    report: &HostProbeReport,
    context: &evertrace_store::SessionImportContext,
    deadline: Instant,
) -> bool {
    let current = &context.current;
    if current.metadata.repository_read_restrictions.is_none()
        || current.metadata.metadata_state != MetadataState::Indexed
        || (current.metadata.workspace_resolution_kind != WorkspaceResolutionKind::Repository
            && current.access_decision != Some(SessionAccessDecision::Approved)
            && !current
                .metadata
                .prospective_origin
                .as_ref()
                .is_some_and(|origin| !origin.closed && origin.record_start.is_some()))
        || !source_read_allowed(report, context, deadline)
    {
        return false;
    }
    // Only new automatic future reads require a positively matching current
    // instance. Unknown evidence defers; it neither grants nor closes origin.
    // Closed-origin historical reads retain their original permission gate.
    if current
        .metadata
        .prospective_origin
        .as_ref()
        .is_some_and(|origin| !origin.closed)
    {
        let Ok(Some(location)) = workspace_location(&current.metadata, deadline) else {
            return false;
        };
        if prospective_origin_matches_current_instance(
            &current.metadata,
            &location,
            |id| {
                context
                    .read_repositories
                    .iter()
                    .find(|value| &value.repository_id == id)
            },
            |id| {
                context
                    .read_worktrees
                    .iter()
                    .find(|value| &value.worktree_instance_id == id)
            },
            |id| {
                context
                    .read_snapshots
                    .iter()
                    .find(|value| &value.worktree_snapshot_id == id)
            },
            context.read_worktrees.iter(),
        ) != Some(true)
        {
            return false;
        }
    }
    source_header_current(report, current, deadline).is_some_and(|header| {
        !matches!(header.payload.git, SessionGit::Object(_))
            || !context.read_repositories.is_empty()
    })
}

fn source_header_current(
    report: &HostProbeReport,
    current: &SessionImportCurrent,
    deadline: Instant,
) -> Option<SessionMetaRecord> {
    let path = report
        .session_catalog_roots()
        .iter()
        .find(|root| root.root_kind == SessionCatalogRootKind::CodexSessions)
        .and_then(|root| root.canonical_absolute_path.as_deref())?;
    let Ok(qualified) = qualify_requested_session_root(
        report,
        SessionCatalogRootKind::CodexSessions,
        Path::new(path),
    ) else {
        return None;
    };
    let Ok(root) = ConfinedRoot::open_external_source(qualified.path()) else {
        return None;
    };
    let relative = Path::new(&current.metadata.source_path);
    let Ok(Some(identity)) = root.probe_regular_file(relative, deadline) else {
        return None;
    };
    if session_source_fingerprint(identity).to_string() != current.metadata.source_fingerprint {
        return None;
    }
    let mut remaining = MAX_RECORD_BYTES;
    let Ok(header) = read_session_header(&root, relative, identity, &mut remaining, deadline)
    else {
        return None;
    };
    if header.payload.id != current.session_id || Instant::now() >= deadline {
        return None;
    }
    Some(header)
}

/// The explicit job can finish source preflight even when optional metadata
/// backfill is disabled. Only this source's bounded admission context is used.
pub(crate) async fn preflight_import_context(
    writer: &WriterHandle,
    report: &HostProbeReport,
    context: &evertrace_store::SessionImportContext,
    config_hash: [u8; 32],
) -> Result<bool, SessionImportServiceError> {
    let prepare_started = Instant::now();
    let allowance = std::time::Duration::from_millis(250);
    let location = workspace_location(&context.current.metadata, prepare_started + allowance)
        .map_err(|_| SessionImportServiceError::Unavailable)?;
    let needs_discovery = location.as_ref().is_some_and(|location| {
        !context.read_repositories.iter().any(|repository| {
            workspace_registered(location, repository, context.read_worktrees.iter())
        })
    });
    let preparation_time = prepare_started.elapsed();
    let located_context = if needs_discovery {
        let location = location
            .as_ref()
            .ok_or(SessionImportServiceError::Unavailable)?;
        let fresh = writer
            .session_import_context_with_repository(
                &context.current.source_key(),
                location.common_dir_filesystem,
                location
                    .common_dir
                    .to_str()
                    .ok_or(SessionImportServiceError::Unavailable)?,
            )
            .await
            .map_err(map_writer)?
            .ok_or(SessionImportServiceError::Unavailable)?;
        if fresh.current != context.current || fresh.job != context.job {
            return Ok(true);
        }
        Some(fresh)
    } else {
        None
    };
    let context = located_context.as_ref().unwrap_or(context);
    let current = &context.current;
    let (_, revoked) = source_read_decision(
        report,
        context,
        Instant::now() + allowance.saturating_sub(preparation_time),
    );
    if crate::repository::record_trust_revocations(writer, revoked, config_hash)
        .await
        .map_err(map_writer)?
    {
        return Ok(true);
    }
    if context.repository_purged || current.access_decision == Some(SessionAccessDecision::Revoked)
    {
        return Ok(false);
    }
    let mut repositories = RepositoryCurrentView {
        frontier: context.frontier,
        repositories: context
            .read_repositories
            .iter()
            .cloned()
            .map(|value| (value.repository_id, value))
            .collect(),
        worktrees: context
            .read_worktrees
            .iter()
            .cloned()
            .map(|value| (value.worktree_instance_id, value))
            .collect(),
        snapshots: context
            .read_snapshots
            .iter()
            .cloned()
            .map(|value| (value.worktree_snapshot_id, value))
            .collect(),
        ..RepositoryCurrentView::default()
    };
    let deadline = Instant::now() + allowance.saturating_sub(preparation_time);
    let mut metadata = current.metadata.clone();
    retain_read_restrictions(
        &mut metadata,
        Some(&current.metadata),
        &repositories,
        location.as_ref(),
    )?;
    let has_historical_permission = (current.metadata.workspace_resolution_kind
        == WorkspaceResolutionKind::Repository
        || current.access_decision == Some(SessionAccessDecision::Approved))
        && source_read_allowed(report, context, deadline);
    let resolve_closed_fence = has_historical_permission
        && metadata
            .prospective_origin
            .as_ref()
            .is_some_and(|origin| origin.closed && origin.record_start.is_none());
    if !needs_discovery && metadata == current.metadata && !resolve_closed_fence {
        return Ok(false);
    }
    let header = source_header_current(report, current, deadline)
        .ok_or(SessionImportServiceError::Unavailable)?;
    if resolve_closed_fence {
        let root_path = report
            .session_catalog_roots()
            .iter()
            .find(|root| root.root_kind == SessionCatalogRootKind::CodexSessions)
            .and_then(|root| root.canonical_absolute_path.as_deref())
            .ok_or(SessionImportServiceError::Unavailable)?;
        let qualified = qualify_requested_session_root(
            report,
            SessionCatalogRootKind::CodexSessions,
            Path::new(root_path),
        )
        .map_err(|_| SessionImportServiceError::Unavailable)?;
        let source_root = ConfinedRoot::open_external_source(qualified.path())
            .map_err(|_| SessionImportServiceError::Unavailable)?;
        let relative = Path::new(&current.metadata.source_path);
        let identity = source_root
            .probe_regular_file(relative, deadline)
            .map_err(|_| SessionImportServiceError::Unavailable)?
            .ok_or(SessionImportServiceError::Unavailable)?;
        if session_source_fingerprint(identity).to_string() != current.metadata.source_fingerprint
            || header.payload.id != current.session_id
        {
            return Err(SessionImportServiceError::Unavailable);
        }
        let origin = metadata
            .prospective_origin
            .as_mut()
            .ok_or(SessionImportServiceError::Unavailable)?;
        if let Some(fence) = prospective_record_start(
            &source_root,
            current.metadata.source_path.as_str(),
            identity,
            origin.observed_end,
            deadline,
        )? {
            source_root
                .revalidate_file(relative, identity)
                .map_err(|_| SessionImportServiceError::Unavailable)?;
            origin.record_start = Some(fence);
        } else {
            return Ok(false);
        }
    }
    let occurred = now_us().map_err(|_| SessionImportServiceError::Corrupt)?;
    let mut payloads = Vec::new();
    discover_source_repository(
        &metadata,
        &current.source_instance(),
        RepositoryDiscoveryContext {
            current: &mut repositories,
            incomplete_history: &context.incomplete_repository_history,
            occurred_at_us: occurred,
            deadline,
            payloads: &mut payloads,
            location: location.as_ref(),
            source_reference: None,
            source_observation: None,
        },
    )?;
    if let Some(location) = location.as_ref()
        && prospective_origin_matches_current_instance(
            &metadata,
            location,
            |id| repositories.repositories.get(id),
            |id| repositories.worktrees.get(id),
            |id| repositories.snapshots.get(id),
            repositories.worktrees.values(),
        ) == Some(false)
        && let Some(origin) = metadata.prospective_origin.as_mut()
    {
        origin.closed = true;
    }
    retain_read_restrictions(
        &mut metadata,
        Some(&current.metadata),
        &repositories,
        location.as_ref(),
    )?;
    if current.metadata.repository_read_restrictions.is_none() {
        metadata.started_at_us = source_timestamp_us(&header._timestamp);
        let source = current.source_instance();
        let (kind, repository, worktree) = resolve_workspace(
            metadata.workspace_hint.as_deref(),
            &header.payload.git,
            metadata.started_at_us.map(|at| (source.as_str(), at)),
            &repositories,
        )
        .map_err(|_| SessionImportServiceError::Unavailable)?;
        metadata.workspace_resolution_kind = kind;
        metadata.resolved_repository_instance_id = repository;
        metadata.resolved_worktree_instance_id = worktree;
    }
    if metadata != current.metadata {
        metadata_events(
            Some(current),
            current.session_id.clone(),
            current.source_instance_id.clone(),
            metadata,
            occurred,
            &mut payloads,
        )?;
    }
    if payloads.is_empty() {
        return Ok(false);
    }
    if payloads.iter().any(|payload| matches!(payload, JournalPayload::SessionImportEventRecorded(event)
        if matches!(event.event, SessionImportEventKind::BodyStateAdvanced { body_state: SessionBodyState::BlockedScopeUnresolved, .. })))
        && let Some(mut job) = context.job.clone()
    {
        job.state = JobStatus::Failed;
        job.lease_until_us = None;
        job.terminal = Some(Box::new(JobTerminalAudit { outcome: JobTerminalOutcome::Failed, reason: JobTerminalReason::SourceUnavailable, result_ref: Some(format!("session_import:{}", current.source_key())) }));
        payloads.push(JournalPayload::JobState(job));
    }
    let command = command(
        RequestId::new_v7(),
        "session_import_preflight",
        occurred,
        config_hash,
        SourceKind::System,
        payloads,
    )?;
    writer
        .commit_if_frontier(command, occurred, context.frontier)
        .await
        .map_err(map_writer)?;
    Ok(true)
}

/// Validate only selected archived message records; never reopen a source path
/// or require its historical revision to equal today's catalog revision.
pub(crate) fn source_summary_receipts(
    current: &evertrace_store::projections::CurrentFacts,
    source: &evertrace_domain::semantic::SemanticSourceTarget,
    after_sequence: u64,
    through_sequence: u64,
    refs: &[String],
) -> Result<Vec<evertrace_domain::evidence::SourceReceipt>, SessionImportServiceError> {
    if refs.is_empty()
        || refs.len() > 64
        || !refs.windows(2).all(|pair| pair[0] < pair[1])
        || !evertrace_store::is_session_import_source(source.source_instance_id.as_str())
    {
        return Err(SessionImportServiceError::Corrupt);
    }
    let mut observations = BTreeMap::new();
    let mut receipts = Vec::with_capacity(refs.len());
    for reference in refs {
        let observation_id = reference
            .parse::<evertrace_domain::ids::SourceObservationId>()
            .map_err(|_| SessionImportServiceError::Corrupt)?;
        let (observation, _) = current
            .source_observation(observation_id)
            .ok_or(SessionImportServiceError::Corrupt)?;
        let receipt_id = observation.source_receipt_ref;
        observations.insert(
            receipt_id.to_string(),
            Box::new(observation.as_ref().clone()),
        );
        let (receipt, _) = current
            .source_receipt(receipt_id)
            .ok_or(SessionImportServiceError::Corrupt)?;
        receipts.push(receipt.as_ref().clone());
    }
    let suppressed =
        evertrace_store::ObjectDeletionCandidateAdmissionView::for_source_refs_current(
            current, refs,
        )
        .and_then(|view| view.source_refs_suppressed(refs))
        .map_err(|_| SessionImportServiceError::Corrupt)?;
    validate_source_summary_receipts(
        source,
        after_sequence,
        through_sequence,
        refs,
        observations,
        receipts,
        suppressed,
    )
}

pub(crate) fn source_summary_receipts_rows(
    rows: &[evertrace_store::ObjectRow],
    source: &evertrace_domain::semantic::SemanticSourceTarget,
    after_sequence: u64,
    through_sequence: u64,
    refs: &[String],
) -> Result<Vec<evertrace_domain::evidence::SourceReceipt>, SessionImportServiceError> {
    if refs.is_empty()
        || refs.len() > 64
        || !refs.windows(2).all(|pair| pair[0] < pair[1])
        || !evertrace_store::is_session_import_source(source.source_instance_id.as_str())
    {
        return Err(SessionImportServiceError::Corrupt);
    }
    let mut observations = BTreeMap::new();
    for row in rows.iter().filter(|row| {
        row.object_kind.as_deref() == Some("source_observation")
            && row
                .object_id
                .as_ref()
                .is_some_and(|id| refs.binary_search(id).is_ok())
    }) {
        let JournalPayload::SourceObservationRecorded(observation) = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(SessionImportServiceError::Corrupt)?,
        )
        .map_err(|_| SessionImportServiceError::Corrupt)?
        else {
            return Err(SessionImportServiceError::Corrupt);
        };
        observations.insert(observation.source_receipt_ref.to_string(), observation);
    }
    let mut receipts = Vec::new();
    for row in rows.iter().filter(|row| {
        row.object_kind.as_deref() == Some("source_receipt")
            && row
                .object_id
                .as_ref()
                .is_some_and(|id| observations.contains_key(id))
    }) {
        let JournalPayload::SourceReceiptRecorded(receipt) = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(SessionImportServiceError::Corrupt)?,
        )
        .map_err(|_| SessionImportServiceError::Corrupt)?
        else {
            return Err(SessionImportServiceError::Corrupt);
        };
        receipts.push(*receipt);
    }
    let suppressed =
        evertrace_store::ObjectDeletionCandidateAdmissionView::for_source_refs_rows(rows, refs)
            .and_then(|view| view.source_refs_suppressed(refs))
            .map_err(|_| SessionImportServiceError::Corrupt)?;
    validate_source_summary_receipts(
        source,
        after_sequence,
        through_sequence,
        refs,
        observations,
        receipts,
        suppressed,
    )
}

pub(crate) fn validate_source_summary_receipts(
    source: &evertrace_domain::semantic::SemanticSourceTarget,
    after_sequence: u64,
    through_sequence: u64,
    refs: &[String],
    observations: BTreeMap<String, Box<evertrace_domain::evidence::SourceObservation>>,
    mut receipts: Vec<evertrace_domain::evidence::SourceReceipt>,
    suppressed: bool,
) -> Result<Vec<evertrace_domain::evidence::SourceReceipt>, SessionImportServiceError> {
    if refs.is_empty()
        || refs.len() > 64
        || !refs.windows(2).all(|pair| pair[0] < pair[1])
        || !evertrace_store::is_session_import_source(source.source_instance_id.as_str())
    {
        return Err(SessionImportServiceError::Corrupt);
    }
    for receipt in &receipts {
        let observation = observations
            .get(&receipt.source_receipt_id.to_string())
            .ok_or(SessionImportServiceError::Corrupt)?;
        if refs
            .binary_search(&observation.source_observation_id.to_string())
            .is_err()
            || !source.contains_message(receipt, observation, after_sequence, through_sequence)
        {
            return Err(SessionImportServiceError::Corrupt);
        }
    }
    receipts.sort_by_key(|receipt| receipt.source_sequence);
    if receipts.len() != refs.len()
        || receipts.last().map(|receipt| receipt.source_sequence) != Some(through_sequence)
        || !receipts
            .windows(2)
            .all(|pair| pair[0].source_sequence < pair[1].source_sequence)
    {
        return Err(SessionImportServiceError::Corrupt);
    }
    if suppressed {
        return Err(SessionImportServiceError::Unavailable);
    }
    Ok(receipts)
}

pub(crate) async fn blocked_source_rows(
    writer: &WriterHandle,
    report: Option<&HostProbeReport>,
    snapshot: &evertrace_store::ProjectionSnapshot,
    rows: &[&evertrace_store::ObjectRow],
    config_hash: [u8; 32],
) -> Result<std::collections::BTreeSet<String>, SessionImportServiceError> {
    if rows.len() > 64 {
        return Err(SessionImportServiceError::Unavailable);
    }
    blocked_source_rows_before(writer, report, snapshot, rows, config_hash, None, None).await
}

/// Request-scoped batch entry: one borrowed projection index, one permission
/// decision per source, and no deadline renewal for individual candidates.
pub(crate) async fn blocked_source_rows_before(
    writer: &WriterHandle,
    report: Option<&HostProbeReport>,
    snapshot: &evertrace_store::ProjectionSnapshot,
    rows: &[&evertrace_store::ObjectRow],
    config_hash: [u8; 32],
    lookup: Option<&BTreeMap<&str, &evertrace_store::ObjectRow>>,
    deadline: Option<Instant>,
) -> Result<std::collections::BTreeSet<String>, SessionImportServiceError> {
    blocked_source_rows_from_rows_before(
        writer,
        report,
        &snapshot.rows,
        rows,
        config_hash,
        lookup,
        deadline,
    )
    .await
}

/// Typed background admission for a bounded source observation cohort. Search
/// and detail readers continue to use the row-based path below.
pub(crate) async fn blocked_source_observations(
    writer: &WriterHandle,
    report: Option<&HostProbeReport>,
    current: &evertrace_store::projections::CurrentFacts,
    refs: &[String],
    config_hash: [u8; 32],
) -> Result<std::collections::BTreeSet<String>, SessionImportServiceError> {
    if refs.len() > 64 || !refs.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(SessionImportServiceError::Unavailable);
    }
    let mut sources = BTreeMap::new();
    for reference in refs {
        let id = reference
            .parse::<evertrace_domain::ids::SourceObservationId>()
            .map_err(|_| SessionImportServiceError::Corrupt)?;
        let (observation, _) = current
            .source_observation(id)
            .ok_or(SessionImportServiceError::Corrupt)?;
        sources.insert(
            reference.clone(),
            observation.source_instance_id.as_str().to_owned(),
        );
    }
    blocked_source_instances(writer, report, sources, config_hash, None).await
}

/// The source gate over a named request-local closure.  It intentionally
/// shares the same source-summary, Host report, and revocation logic as the
/// full-projection wrapper above.
pub(crate) async fn blocked_source_rows_from_rows_before(
    writer: &WriterHandle,
    report: Option<&HostProbeReport>,
    all_rows: &[evertrace_store::ObjectRow],
    rows: &[&evertrace_store::ObjectRow],
    config_hash: [u8; 32],
    lookup: Option<&BTreeMap<&str, &evertrace_store::ObjectRow>>,
    deadline: Option<Instant>,
) -> Result<std::collections::BTreeSet<String>, SessionImportServiceError> {
    let mut sources = BTreeMap::new();
    let mut observations = BTreeMap::new();
    let mut blocked = std::collections::BTreeSet::new();
    for row in rows {
        if !matches!(
            row.object_kind.as_deref(),
            Some("source_receipt" | "source_observation" | "evidence_surface" | "semantic_digest")
        ) {
            continue;
        }
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(SessionImportServiceError::Corrupt)?,
        )
        .map_err(|_| SessionImportServiceError::Corrupt)?;
        match payload {
            JournalPayload::SemanticDigestRecorded(digest) => {
                let Some(source) = &digest.source_target else {
                    continue;
                };
                digest
                    .validate()
                    .map_err(|_| SessionImportServiceError::Corrupt)?;
                if source_summary_receipts_rows(
                    all_rows,
                    source,
                    digest.from_watermark,
                    digest.to_watermark,
                    &digest.selected_direct_refs,
                )
                .is_err()
                {
                    blocked.insert(row.row_id.clone());
                    continue;
                }
                sources.insert(
                    row.row_id.clone(),
                    source.source_instance_id.as_str().to_owned(),
                );
            }
            JournalPayload::SourceReceiptRecorded(receipt) => {
                sources.insert(
                    row.row_id.clone(),
                    receipt.source_instance_id.as_str().to_owned(),
                );
            }
            JournalPayload::SourceObservationRecorded(observation) => {
                sources.insert(
                    row.row_id.clone(),
                    observation.source_instance_id.as_str().to_owned(),
                );
            }
            JournalPayload::EvidenceSurfaceRecorded(surface) => {
                observations.insert(
                    format!(
                        "object:evidence:source_observation:{}",
                        surface.source_observation_revision_ref
                    ),
                    row.row_id.clone(),
                );
            }
            _ => return Err(SessionImportServiceError::Corrupt),
        }
    }
    let observation_rows = match lookup {
        Some(lookup) => observations
            .keys()
            .filter_map(|id| lookup.get(id.as_str()).copied())
            .collect::<Vec<_>>(),
        None => all_rows
            .iter()
            .filter(|row| observations.contains_key(&row.row_id))
            .collect(),
    };
    for row in observation_rows {
        let Some(target) = observations.get(&row.row_id) else {
            continue;
        };
        let JournalPayload::SourceObservationRecorded(observation) = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(SessionImportServiceError::Corrupt)?,
        )
        .map_err(|_| SessionImportServiceError::Corrupt)?
        else {
            return Err(SessionImportServiceError::Corrupt);
        };
        sources.insert(
            target.clone(),
            observation.source_instance_id.as_str().to_owned(),
        );
    }
    if observations
        .values()
        .any(|target| !sources.contains_key(target))
    {
        return Err(SessionImportServiceError::Corrupt);
    }
    blocked.extend(blocked_source_instances(writer, report, sources, config_hash, deadline).await?);
    Ok(blocked)
}

pub(crate) async fn blocked_source_instances(
    writer: &WriterHandle,
    report: Option<&HostProbeReport>,
    sources: BTreeMap<String, String>,
    config_hash: [u8; 32],
    deadline: Option<Instant>,
) -> Result<std::collections::BTreeSet<String>, SessionImportServiceError> {
    let mut contexts = BTreeMap::new();
    for source in sources
        .values()
        .filter(|source| evertrace_store::is_session_import_source(source))
    {
        if contexts.contains_key(source) {
            continue;
        }
        let key = source.strip_prefix("codex-session:").unwrap_or(source);
        let context = writer
            .session_import_context(key)
            .await
            .map_err(map_writer)?;
        contexts.insert(source.clone(), context);
    }
    // Context collection is control-plane preparation. The standalone wrapper
    // starts its filesystem quantum here; a request-scoped caller retains its
    // existing deadline, including when admission waited. Neither path renews
    // the deadline for an individual source.
    let deadline =
        deadline.unwrap_or_else(|| Instant::now() + crate::repository::SESSION_ROOT_PROBE_BUDGET);
    let mut revoked = Vec::new();
    let permissions = contexts
        .into_iter()
        .map(|(source, context)| {
            let allowed = context
                .as_ref()
                .zip(report)
                .is_some_and(|(context, report)| {
                    if context.current.source_instance() != source {
                        return false;
                    }
                    let (allowed, observations) = source_read_decision(report, context, deadline);
                    revoked.extend(observations);
                    allowed
                });
            (source, allowed)
        })
        .collect::<BTreeMap<_, _>>();
    crate::repository::record_trust_revocations(writer, revoked, config_hash)
        .await
        .map_err(map_writer)?;
    Ok(sources
        .into_iter()
        .filter_map(|(row, source)| (permissions.get(&source) == Some(&false)).then_some(row))
        .collect())
}

fn resolve_workspace(
    workspace: Option<&str>,
    git: &SessionGit,
    source_time: Option<(&str, i64)>,
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
    let (SessionGit::Object(object), Some((source, at))) = (git, source_time) else {
        return Ok((WorkspaceResolutionKind::Ambiguous, None, None));
    };
    let Some(head) = object.commit_hash.as_deref() else {
        return Ok((WorkspaceResolutionKind::Ambiguous, None, None));
    };
    // A current locator/HEAD (even an ancestor) does not identify the old
    // instance. Require source-linked, source-time S11 path and snapshot proof.
    let mut matches = repositories.worktrees.values().filter(|worktree| {
        worktree.path_history.iter().any(|path| {
            path.path == workspace
                && path.first_observed_at_us <= at
                && path.last_observed_at_us >= at
                && path
                    .evidence_refs
                    .iter()
                    .any(|reference| reference == source)
        }) && repositories.snapshots.values().any(|snapshot| {
            snapshot.worktree_instance_id == worktree.worktree_instance_id
                && snapshot.head_oid.as_deref() == Some(head)
                && snapshot.captured_at_us == at
                && snapshot
                    .evidence_refs
                    .iter()
                    .any(|reference| reference == source)
        })
    });
    let Some(worktree) = matches.next() else {
        return Ok((WorkspaceResolutionKind::Ambiguous, None, None));
    };
    if matches.next().is_some()
        || !repositories
            .repositories
            .contains_key(&worktree.repository_instance_id)
    {
        return Ok((WorkspaceResolutionKind::Ambiguous, None, None));
    }
    Ok((
        WorkspaceResolutionKind::Repository,
        Some(worktree.repository_instance_id),
        Some(worktree.worktree_instance_id),
    ))
}

fn source_timestamp_us(value: &str) -> Option<i64> {
    let value = value.strip_suffix('Z')?;
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.len() != 19
        || whole.get(4..5)? != "-"
        || whole.get(7..8)? != "-"
        || whole.get(10..11)? != "T"
        || whole.get(13..14)? != ":"
        || whole.get(16..17)? != ":"
        || fraction.len() > 6
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let number = |start, end| whole.get(start..end)?.parse::<i64>().ok();
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > months[usize::try_from(month - 1).ok()?]
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..60).contains(&second)
    {
        return None;
    }
    let leap_days = |year: i64| year / 4 - year / 100 + year / 400;
    let days = 365 * (year - 1970) + leap_days(year - 1) - leap_days(1969)
        + months[..usize::try_from(month - 1).ok()?]
            .iter()
            .sum::<i64>()
        + day
        - 1;
    let micros = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<i64>().ok()? * 10_i64.pow(u32::try_from(6 - fraction.len()).ok()?)
    };
    Some(((days * 24 + hour) * 60 * 60 + minute * 60 + second) * 1_000_000 + micros)
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
    if current.metadata.workspace_resolution_kind != WorkspaceResolutionKind::Repository
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
    rows: &[evertrace_store::ObjectRow],
    session_id: &str,
) -> Result<Option<DurableJob>, SessionImportServiceError> {
    let key = format!("session_import:{session_id}");
    let mut jobs = rows
        .iter()
        .filter(|row| row.row_kind == evertrace_store::ObjectRowKind::Data)
        .filter_map(|row| {
            let json = row.payload_json.as_deref()?;
            let Ok(JournalPayload::JobState(job)) = serde_json::from_str(json) else {
                return None;
            };
            (job.idempotency_key == key
                && matches!(job.state, JobStatus::Queued | JobStatus::Leased))
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
    metadata_events_internal(
        old,
        session_id,
        source_instance_id,
        metadata,
        occurred_at_us,
        false,
        payloads,
    )
}

fn metadata_events_internal(
    old: Option<&SessionImportCurrent>,
    session_id: String,
    source_instance_id: Option<String>,
    metadata: SessionMetadata,
    occurred_at_us: i64,
    complete_live_append: bool,
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
            && (metadata.repository_read_restrictions.is_none()
                || old.access_decision != Some(SessionAccessDecision::Approved))
            && !metadata
                .prospective_origin
                .as_ref()
                .is_some_and(|origin| origin.record_start.is_some())
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
            && match old.metadata.prospective_origin.as_ref() {
                Some(origin) if origin.closed => false,
                Some(_) => {
                    complete_live_append
                        && matches!(
                            old.body_state,
                            SessionBodyState::NotImported
                                | SessionBodyState::Partial
                                | SessionBodyState::Imported
                                | SessionBodyState::Failed
                                | SessionBodyState::SourceReplaced
                        )
                }
                None => old.body_state == SessionBodyState::Imported,
            }
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

fn append_queued_import_jobs(
    payloads: &mut Vec<JournalPayload>,
    frontier: u64,
    config_hash: [u8; 32],
) -> Result<(), SessionImportServiceError> {
    let mut queued = Vec::new();
    for (queued_index, payload) in payloads.iter().enumerate() {
        let JournalPayload::SessionImportEventRecorded(event) = payload else {
            continue;
        };
        if !matches!(
            event.event,
            SessionImportEventKind::BodyStateAdvanced {
                body_state: SessionBodyState::Queued,
                ..
            }
        ) {
            continue;
        }
        let source_key = event.source_key();
        let metadata = payloads
            .iter()
            .take(queued_index)
            .rev()
            .find_map(|previous| match previous {
                JournalPayload::SessionImportEventRecorded(previous)
                    if previous.source_key() == source_key =>
                {
                    match &previous.event {
                        SessionImportEventKind::MetadataObserved { metadata } => {
                            Some(metadata.as_ref().clone())
                        }
                        _ => None,
                    }
                }
                _ => None,
            })
            .ok_or(SessionImportServiceError::Corrupt)?;
        let event_offset = u64::try_from(queued_index)
            .map_err(|_| SessionImportServiceError::Corrupt)?
            .checked_add(1)
            .ok_or(SessionImportServiceError::Corrupt)?;
        let target_watermark = frontier
            .checked_add(event_offset)
            .ok_or(SessionImportServiceError::Corrupt)?;
        queued.push((
            source_key,
            event.revision,
            metadata.source_revision.as_str().to_owned(),
            target_watermark,
        ));
    }
    for (source_key, generation, target_revision, target_watermark) in queued {
        payloads.push(JournalPayload::JobState(DurableJob {
            job_id: JobId::new_v7(),
            idempotency_key: format!("session_import:{source_key}"),
            target_revision,
            target_watermark,
            target_generation: generation,
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

    use crate::repository::{observe_session_catalog_report, observe_session_source_report};

    use super::*;

    fn temp_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("evertrace-s28-{}-{nonce}", std::process::id()))
    }

    struct SourceObservationFixture {
        root: PathBuf,
        workspace: PathBuf,
        sessions_root: PathBuf,
        dated: PathBuf,
        head: String,
        writer: WriterHandle,
        task: crate::WriterTask,
    }

    impl SourceObservationFixture {
        async fn new() -> Self {
            let root = temp_root();
            fs::create_dir_all(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let workspace = root.join("repository");
            fs::create_dir(&workspace).unwrap();
            fixture_git(&workspace, &["init", "-q", "-b", "main"]);
            fixture_git(&workspace, &["commit", "--allow-empty", "-qm", "initial"]);
            let head = fixture_git(&workspace, &["rev-parse", "HEAD"]);
            let adapter = root.join("adapter");
            let sessions_root = adapter.join("sessions");
            let dated = sessions_root.join("2026/10/18");
            fs::create_dir_all(&dated).unwrap();
            for path in [
                adapter.clone(),
                sessions_root.clone(),
                sessions_root.join("2026"),
                sessions_root.join("2026/10"),
                dated.clone(),
            ] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            fs::write(
                adapter.join("config.toml"),
                format!(
                    "[projects.{}]\ntrust_level = \"trusted\"\n",
                    serde_json::to_string(workspace.to_str().unwrap()).unwrap()
                ),
            )
            .unwrap();
            fs::set_permissions(
                adapter.join("config.toml"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let journal = crate::open_writer(&root.join("data")).await.unwrap();
            let (writer, task) = crate::spawn_writer(journal, 8).unwrap();
            Self {
                root,
                workspace,
                sessions_root,
                dated,
                head,
                writer,
                task,
            }
        }

        fn write_source(&self, session_id: &str) -> PathBuf {
            self.write_source_in(session_id, &self.workspace, &self.head)
        }

        fn write_source_in(&self, session_id: &str, workspace: &Path, head: &str) -> PathBuf {
            let transcript = self.dated.join(format!(
                "rollout-2026-10-18T00-00-00-{session_id}_{session_id}.jsonl"
            ));
            let header = serde_json::json!({
                "timestamp": "2026-10-18T00:00:00Z",
                "type": "session_meta",
                "payload": {
                    "id": session_id,
                    "session_id": session_id,
                    "cwd": workspace,
                    "originator": "codex_cli_rs",
                    "model_provider": "openai",
                    "timestamp": "2026-10-18T00:00:00Z",
                    "agent_nickname": null,
                    "agent_path": null,
                    "context_window": 258400,
                    "history_mode": "save-all",
                    "multi_agent_version": "1",
                    "parent_thread_id": null,
                    "thread_source": "cli",
                    "git": { "commit_hash": head }
                }
            });
            fs::write(&transcript, format!("{header}\n")).unwrap();
            fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
            transcript
        }

        fn report(&self, transcript: &Path, session_id: &str) -> HostProbeReport {
            observe_session_catalog_report(
                transcript.to_str(),
                session_id,
                "r491-source-observation",
                None,
            )
            .unwrap()
        }

        async fn commit_unrelated_metadata(
            &self,
            report: &HostProbeReport,
            session_id: &str,
        ) -> u64 {
            let items = catalog_codex_sessions(
                report,
                &self.sessions_root,
                &RepositoryCurrentView::default(),
                SessionCatalogBudget {
                    max_entries: 32,
                    max_metadata_bytes: 4 * 1024 * 1024,
                    deadline: Instant::now() + Duration::from_secs(2),
                },
            )
            .unwrap();
            let item = items
                .into_iter()
                .find(|item| item.session_id == session_id)
                .unwrap();
            let mut payloads = Vec::new();
            let occurred_at_us = now_us().unwrap();
            metadata_events(
                None,
                item.session_id.clone(),
                Some(item.source_instance_id.clone()),
                item.metadata,
                occurred_at_us,
                &mut payloads,
            )
            .unwrap();
            assert_eq!(payloads.len(), 1);
            let request_id = RequestId::new_v7();
            let prepared = command(
                request_id,
                session_id,
                occurred_at_us,
                [0; 32],
                SourceKind::System,
                payloads,
            )
            .unwrap();
            self.writer.commit(prepared, occurred_at_us).await.unwrap();
            self.writer
                .session_catalog_current_context()
                .await
                .unwrap()
                .frontier
        }

        async fn close(self) {
            self.task.shutdown_and_join().await.unwrap();
            drop(self.writer);
            fs::remove_dir_all(self.root).unwrap();
        }
    }

    fn fixture_git(path: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(path)
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
            ])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[tokio::test]
    async fn native_source_observation_commits_across_unrelated_writer_and_cancelled_waiter() {
        let fixture = SourceObservationFixture::new().await;
        let target_id = "019d0000-0000-7000-8000-0000000000a1";
        let unrelated_id = "019d0000-0000-7000-8000-0000000000a2";
        let cancelled_id = "019d0000-0000-7000-8000-0000000000a3";
        let live_id = "019d0000-0000-7000-8000-0000000000a4";
        let transcript = fixture.write_source(target_id);
        let unrelated_transcript = fixture.write_source(unrelated_id);
        let cancelled_transcript = fixture.write_source(cancelled_id);
        let live_transcript = fixture.write_source(live_id);
        let invocation_started = Instant::now();
        let deadline = invocation_started + Duration::from_secs(2);
        let report = fixture.report(&transcript, target_id);
        let request_id = RequestId::new_v7();
        let command_id = CommandId::from_uuid(request_id.as_uuid()).unwrap();
        let source_reference = format!("native_session_source_observation:{request_id}");
        let initial_frontier = fixture
            .writer
            .session_catalog_current_context()
            .await
            .unwrap()
            .frontier;
        let (prepared, mut prepared_rx) = mpsc::unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        let service = SessionCatalogService::new(fixture.writer.clone(), [0; 32])
            .with_observation_commit_seam(ObservationCommitSeam {
                prepared,
                release: Arc::clone(&release),
            });
        let service_for_first = service.clone();
        let session = target_id.to_owned();
        let transcript_path = transcript.clone();
        let first_report = report.clone();
        let first_reference = source_reference.clone();
        let observation = tokio::spawn(async move {
            service_for_first
                .observe_native_session_source(
                    request_id,
                    &first_report,
                    &session,
                    transcript_path.to_str().unwrap(),
                    &first_reference,
                    deadline,
                )
                .await
        });
        let observed_frontier = prepared_rx.recv().await.unwrap();
        let cancelled_request = RequestId::new_v7();
        let cancelled_deadline = Instant::now() + Duration::from_secs(2);
        let cancelled_report = fixture.report(&cancelled_transcript, cancelled_id);
        let cancelled_session = cancelled_id.to_owned();
        let cancelled_path = cancelled_transcript.clone();
        let cancelled_reference = format!("native_session_source_observation:{cancelled_request}");
        let cancelled_service = service.clone();
        let cancelled = tokio::spawn(async move {
            cancelled_service
                .observe_native_session_source(
                    cancelled_request,
                    &cancelled_report,
                    &cancelled_session,
                    cancelled_path.to_str().unwrap(),
                    &cancelled_reference,
                    cancelled_deadline,
                )
                .await
        });
        tokio::task::yield_now().await;
        assert!(
            !cancelled.is_finished(),
            "queued observation should wait for the permit"
        );
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        assert!(
            fixture
                .writer
                .session_import_context(&format!("session-rollout:{cancelled_id}:{cancelled_id}"))
                .await
                .unwrap()
                .is_none()
        );

        let live_request = RequestId::new_v7();
        let live_started = Instant::now();
        let live_deadline = live_started + Duration::from_secs(2);
        let live_report = fixture.report(&live_transcript, live_id);
        let live_session = live_id.to_owned();
        let live_path = live_transcript.clone();
        let live_reference = format!("native_session_source_observation:{live_request}");
        let expected_live_reference = live_reference.clone();
        let live_service = service.clone();
        let live = tokio::spawn(async move {
            let result = live_service
                .observe_native_session_source(
                    live_request,
                    &live_report,
                    &live_session,
                    live_path.to_str().unwrap(),
                    &live_reference,
                    live_deadline,
                )
                .await;
            (live_started.elapsed(), result)
        });
        let refresh_result = service.refresh(&report).await;
        let active_refresh_result = service.refresh_active(&report).await;
        let unrelated_frontier = fixture
            .commit_unrelated_metadata(
                &fixture.report(&unrelated_transcript, unrelated_id),
                unrelated_id,
            )
            .await;
        let interleaving_is_real =
            observed_frontier == initial_frontier && unrelated_frontier > observed_frontier;
        release.add_permits(1);
        let result = observation.await.unwrap();
        let live_frontier = prepared_rx.recv().await.unwrap();
        assert!(live_frontier >= unrelated_frontier);
        release.add_permits(1);
        let (live_elapsed, live_result) = live.await.unwrap();
        let committed = fixture.writer.committed_command(command_id).await.unwrap();
        let snapshot = fixture.writer.project().await.unwrap();
        let source_key = format!("session-rollout:{target_id}:{target_id}");
        let current = fixture
            .writer
            .session_import_context(&source_key)
            .await
            .unwrap();
        let live_key = format!("session-rollout:{live_id}:{live_id}");
        let live_current = fixture
            .writer
            .session_import_context(&live_key)
            .await
            .unwrap();
        let view = RepositoryCurrentView::from_snapshot(&snapshot).unwrap();
        let observed_end = fs::metadata(&transcript).unwrap().len();
        fixture.close().await;
        assert!(interleaving_is_real);
        assert_eq!(result, Ok(true));
        assert_eq!(refresh_result, Err(SessionImportServiceError::Unavailable));
        assert_eq!(
            active_refresh_result,
            Err(SessionImportServiceError::Unavailable)
        );
        assert!(live_elapsed < Duration::from_secs(2));
        assert_eq!(live_result, Ok(true));
        let counts = committed
            .unwrap()
            .payloads
            .iter()
            .fold([0; 4], |mut counts, payload| {
                let family = match payload {
                    JournalPayload::SessionImportEventRecorded(_) => Some(0),
                    JournalPayload::RepositoryInstanceRecorded(_) => Some(1),
                    JournalPayload::WorktreeInstanceRecorded(_) => Some(2),
                    JournalPayload::WorktreeSnapshotRecorded(_) => Some(3),
                    _ => None,
                };
                if let Some(family) = family {
                    counts[family] += 1;
                }
                counts
            });
        assert_eq!(counts, [1; 4], "S11 and metadata must commit atomically");
        let current = current.unwrap();
        assert_eq!(current.current.access_decision, None);
        assert_eq!(
            current.current.metadata.resolved_repository_instance_id,
            None
        );
        assert_eq!(current.current.metadata.resolved_worktree_instance_id, None);
        let origin = current.current.metadata.prospective_origin.unwrap();
        assert_eq!(origin.observed_end, observed_end);
        assert!(view.snapshots.contains_key(&origin.snapshot_ref));
        assert_eq!(
            (
                view.repositories.len(),
                view.worktrees.len(),
                view.snapshots.len()
            ),
            (1, 1, 2)
        );
        assert!(
            view.snapshots[&origin.snapshot_ref]
                .evidence_refs
                .contains(&source_reference)
        );
        let live_origin = live_current
            .unwrap()
            .current
            .metadata
            .prospective_origin
            .unwrap();
        assert_ne!(origin.snapshot_ref, live_origin.snapshot_ref);
        assert!(
            view.snapshots[&live_origin.snapshot_ref]
                .evidence_refs
                .contains(&expected_live_reference)
        );
        assert!(current.job.is_none());
        assert!(invocation_started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn native_source_observation_rejects_raw_revocation_after_preparation() {
        let fixture = SourceObservationFixture::new().await;
        let session_id = "019d0000-0000-7000-8000-0000000000b1";
        let transcript = fixture.write_source(session_id);
        let request_id = RequestId::new_v7();
        let command_id = CommandId::from_uuid(request_id.as_uuid()).unwrap();
        let source_reference = format!("native_session_source_observation:{request_id}");
        let catalog = SessionCatalogService::new(fixture.writer.clone(), [0; 32]);
        let initial_catalog_report = fixture.report(&transcript, session_id);
        catalog.refresh(&initial_catalog_report).await.unwrap();
        let repository_before = fixture
            .writer
            .session_catalog_current_context()
            .await
            .unwrap()
            .repositories;
        let deadline = Instant::now() + Duration::from_secs(2);
        let report = observe_session_source_report(
            transcript.to_str().unwrap(),
            session_id,
            None,
            &source_reference,
            deadline,
        )
        .unwrap();
        let source_key = format!("session-rollout:{session_id}:{session_id}");
        let before = fixture
            .writer
            .session_import_context(&source_key)
            .await
            .unwrap()
            .unwrap();
        assert!(before.current.metadata.prospective_origin.is_none());
        assert_eq!(before.current.access_decision, None);
        let initial_frontier = before.frontier;

        let (prepared, mut prepared_rx) = mpsc::unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        let catalog = catalog.with_observation_commit_seam(ObservationCommitSeam {
            prepared,
            release: Arc::clone(&release),
        });
        let transcript_path = transcript.clone();
        let session_id_owned = session_id.to_owned();
        let source_reference_owned = source_reference.clone();
        let observation = tokio::spawn(async move {
            catalog
                .observe_native_session_source(
                    request_id,
                    &report,
                    &session_id_owned,
                    transcript_path.to_str().unwrap(),
                    &source_reference_owned,
                    deadline,
                )
                .await
        });
        let prepared_frontier = prepared_rx.recv().await.unwrap();
        let occurred_at_us = now_us().unwrap();
        let revoke = revoke_command(
            RequestId::new_v7(),
            &before.current,
            None,
            occurred_at_us,
            [0; 32],
        )
        .unwrap();
        fixture
            .writer
            .commit_if_frontier(revoke, occurred_at_us, before.frontier)
            .await
            .unwrap();
        let revoked_frontier = fixture
            .writer
            .session_catalog_current_context()
            .await
            .unwrap()
            .frontier;
        release.add_permits(1);
        let result = observation.await.unwrap();
        let current = fixture
            .writer
            .session_import_context(&source_key)
            .await
            .unwrap()
            .unwrap();
        let snapshot = fixture.writer.project().await.unwrap();
        let repository_view = RepositoryCurrentView::from_snapshot(&snapshot).unwrap();
        assert_eq!(prepared_frontier, initial_frontier);
        assert!(revoked_frontier > prepared_frontier);
        assert_eq!(result, Err(SessionImportServiceError::StaleFrontier));
        assert_eq!(
            current.current.access_decision,
            Some(SessionAccessDecision::Revoked)
        );
        assert!(current.current.metadata.prospective_origin.is_none());
        assert_eq!(current.current.body_state, SessionBodyState::NotImported);
        assert!(current.job.is_none());
        assert!(current.watermark.is_none());
        assert!(current.recorded_prefix_end.is_none());
        assert_eq!(
            repository_view,
            RepositoryCurrentView {
                frontier: snapshot.frontier,
                ..repository_before
            }
        );
        assert!(
            fixture
                .writer
                .committed_command(command_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(prepared_rx.try_recv().is_err());
        fixture.close().await;
    }

    #[tokio::test]
    async fn native_source_observation_detects_purge_hidden_repository_aba() {
        let fixture = SourceObservationFixture::new().await;
        let session_id = "019d0000-0000-7000-8000-0000000000c2";
        let transcript = fixture.write_source(session_id);
        let report = fixture.report(&transcript, session_id);
        let request_id = RequestId::new_v7();
        let command_id = CommandId::from_uuid(request_id.as_uuid()).unwrap();
        let source_reference = format!("native_session_source_observation:{request_id}");
        let invocation_started = Instant::now();
        let deadline = invocation_started + Duration::from_secs(2);
        let (prepared, mut prepared_rx) = mpsc::unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        let catalog = SessionCatalogService::new(fixture.writer.clone(), [0; 32])
            .with_observation_commit_seam(ObservationCommitSeam {
                prepared,
                release: Arc::clone(&release),
            });
        let transcript_path = transcript.clone();
        let session = session_id.to_owned();
        let source_ref = source_reference.clone();
        let observation = tokio::spawn(async move {
            catalog
                .observe_native_session_source(
                    request_id,
                    &report,
                    &session,
                    transcript_path.to_str().unwrap(),
                    &source_ref,
                    deadline,
                )
                .await
        });
        let prepared_frontier = prepared_rx.recv().await.unwrap();

        let items = catalog_codex_sessions(
            &fixture.report(&transcript, session_id),
            &fixture.sessions_root,
            &RepositoryCurrentView::default(),
            SessionCatalogBudget {
                max_entries: 8,
                max_metadata_bytes: 4 * 1024 * 1024,
                deadline,
            },
        )
        .unwrap();
        let item = items
            .into_iter()
            .find(|item| item.session_id == session_id)
            .unwrap();
        let location = workspace_location(&item.metadata, deadline)
            .unwrap()
            .unwrap();
        let mut repositories = RepositoryCurrentView::default();
        let mut payloads = Vec::new();
        let create_at_us = now_us().unwrap();
        discover_source_repository(
            &item.metadata,
            &item.source_instance_id,
            RepositoryDiscoveryContext {
                current: &mut repositories,
                incomplete_history: &[],
                occurred_at_us: create_at_us,
                deadline,
                payloads: &mut payloads,
                location: Some(&location),
                source_reference: None,
                source_observation: None,
            },
        )
        .unwrap();
        assert!(
            !payloads.is_empty(),
            "legal S11 create must produce product facts"
        );
        let create = command(
            RequestId::new_v7(),
            session_id,
            create_at_us,
            [0; 32],
            SourceKind::System,
            payloads,
        )
        .unwrap();
        fixture.writer.commit(create, create_at_us).await.unwrap();
        let created = fixture.writer.project().await.unwrap();
        let created_view = RepositoryCurrentView::from_snapshot(&created).unwrap();
        assert_eq!(created_view.repositories.len(), 1);
        let (repository_id, repository) = created_view.repositories.iter().next().unwrap();
        let identity = repository.common_dir_filesystem.unwrap();
        let preview = evertrace_store::projections::repository_scope_purge_preview(
            &created,
            *repository_id,
            repository.repository_revision,
        )
        .unwrap();
        assert!(
            preview.blockers.is_empty(),
            "purge blockers: {:?}",
            preview.blockers
        );
        let purge_at_us = now_us().unwrap();
        let purge_command = crate::purge::pending_repository_purge_command(
            RequestId::new_v7(),
            &preview,
            preview.deletion_generation,
            purge_at_us,
            created.frontier,
            [0; 32],
        )
        .unwrap();
        fixture
            .writer
            .commit_if_frontier(purge_command, purge_at_us, created.frontier)
            .await
            .unwrap();
        let purge_frontier = fixture
            .writer
            .session_catalog_current_context()
            .await
            .unwrap()
            .frontier;
        let source_instance =
            evertrace_domain::evidence::SourceInstanceId::parse(item.source_instance_id).unwrap();
        let mut workspace_hints = BTreeSet::new();
        workspace_hints.insert(item.metadata.workspace_hint.unwrap());
        let raw_repositories = fixture
            .writer
            .source_observation_authority_context(SourceObservationRepositorySelector {
                identity,
                root_path: location.worktree_path.to_string_lossy().into_owned(),
                workspace_hints,
                retained_repository_ids: BTreeSet::new(),
            })
            .await
            .unwrap();
        assert!(
            !fixture
                .writer
                .source_observation_revision_has_facts(
                    source_instance,
                    item.metadata.source_revision,
                )
                .await
                .unwrap()
        );
        assert_eq!(raw_repositories.repositories.len(), 1);
        assert!(raw_repositories.repositories.contains_key(repository_id));
        assert!(raw_repositories.purged.contains(repository_id));
        assert!(purge_frontier > prepared_frontier);
        release.add_permits(1);
        let result = observation.await.unwrap();
        assert_eq!(result, Err(SessionImportServiceError::StaleFrontier));

        let source_key = format!("session-rollout:{session_id}:{session_id}");
        assert!(
            fixture
                .writer
                .session_import_context(&source_key)
                .await
                .unwrap()
                .is_none()
        );
        let after = fixture.writer.project().await.unwrap();
        let after_view = RepositoryCurrentView::from_snapshot(&after).unwrap();
        assert!(
            after_view.repositories.is_empty()
                && after_view.worktrees.is_empty()
                && after_view.snapshots.is_empty(),
            "purge must keep product rows hidden"
        );
        assert_eq!(
            after.frontier, purge_frontier,
            "rejection must not write a replacement identity"
        );
        assert!(
            fixture
                .writer
                .committed_command(command_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(invocation_started.elapsed() < Duration::from_secs(2));
        fixture.close().await;
    }

    #[tokio::test]
    async fn native_source_observation_orders_five_same_and_cross_directory_sources() {
        let fixture = SourceObservationFixture::new().await;
        let second_workspace = fixture.root.join("repository-two");
        fs::create_dir(&second_workspace).unwrap();
        fixture_git(&second_workspace, &["init", "-q", "-b", "main"]);
        fixture_git(
            &second_workspace,
            &["commit", "--allow-empty", "-qm", "initial"],
        );
        let second_head = fixture_git(&second_workspace, &["rev-parse", "HEAD"]);
        let config_path = fixture.root.join("adapter/config.toml");
        let mut config = fs::read_to_string(&config_path).unwrap();
        config.push_str(&format!(
            "\n[projects.{}]\ntrust_level = \"trusted\"\n",
            serde_json::to_string(second_workspace.to_str().unwrap()).unwrap()
        ));
        fs::write(&config_path, config).unwrap();

        let session_ids = [
            "019d0000-0000-7000-8000-0000000000d1",
            "019d0000-0000-7000-8000-0000000000d2",
            "019d0000-0000-7000-8000-0000000000d3",
            "019d0000-0000-7000-8000-0000000000d4",
            "019d0000-0000-7000-8000-0000000000d5",
        ];
        let transcripts = session_ids
            .iter()
            .enumerate()
            .map(|(index, session)| {
                if index < 3 {
                    fixture.write_source(session)
                } else {
                    fixture.write_source_in(session, &second_workspace, &second_head)
                }
            })
            .collect::<Vec<_>>();
        let unrelated_id = "019d0000-0000-7000-8000-0000000000d6";
        let unrelated_transcript = fixture.write_source(unrelated_id);
        let unrelated_report = fixture.report(&unrelated_transcript, unrelated_id);
        let requests = session_ids
            .iter()
            .map(|_| RequestId::new_v7())
            .collect::<Vec<_>>();
        let source_references = requests
            .iter()
            .map(|request| format!("native_session_source_observation:{request}"))
            .collect::<Vec<_>>();
        let (prepared, mut prepared_rx) = mpsc::unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        let catalog = SessionCatalogService::new(fixture.writer.clone(), [0; 32])
            .with_observation_commit_seam(ObservationCommitSeam {
                prepared,
                release: Arc::clone(&release),
            });
        let mut observations = Vec::new();
        for (((session_id, transcript), request_id), source_reference) in session_ids
            .into_iter()
            .zip(transcripts.iter().cloned())
            .zip(requests.iter().copied())
            .zip(source_references.iter().cloned())
        {
            let service = catalog.clone();
            let report = fixture.report(&transcript, session_id);
            let session = session_id.to_owned();
            observations.push(tokio::spawn(async move {
                let started = Instant::now();
                let deadline = started + Duration::from_secs(2);
                let result = service
                    .observe_native_session_source(
                        request_id,
                        &report,
                        &session,
                        transcript.to_str().unwrap(),
                        &source_reference,
                        deadline,
                    )
                    .await;
                (
                    started.elapsed(),
                    session,
                    request_id,
                    source_reference,
                    result,
                )
            }));
        }
        let first_prepared_frontier = prepared_rx.recv().await.unwrap();
        let unrelated_frontier = fixture
            .commit_unrelated_metadata(&unrelated_report, unrelated_id)
            .await;
        assert!(unrelated_frontier > first_prepared_frontier);
        let mut prepared_frontiers = vec![first_prepared_frontier];
        release.add_permits(1);
        for _ in 1..session_ids.len() {
            prepared_frontiers.push(prepared_rx.recv().await.unwrap());
            release.add_permits(1);
        }
        let mut results = Vec::with_capacity(observations.len());
        for observation in observations {
            results.push(observation.await.unwrap());
        }
        let snapshot = fixture.writer.project().await.unwrap();
        let repository_view = RepositoryCurrentView::from_snapshot(&snapshot).unwrap();
        assert_eq!(prepared_frontiers.len(), 5);
        assert!(prepared_frontiers.windows(2).all(|pair| pair[1] >= pair[0]));
        assert!(repository_view.repositories.len() == 2);
        assert!(repository_view.worktrees.len() == 2);
        assert!(repository_view.snapshots.len() == 5);
        let mut boundary_counts = BTreeMap::new();
        let mut worktree_counts = BTreeMap::new();
        for (elapsed, session_id, request_id, source_reference, result) in results {
            eprintln!(
                "native_source_observation_five_source_elapsed session={session_id} elapsed_us={}",
                elapsed.as_micros()
            );
            assert!(
                elapsed < Duration::from_secs(2),
                "deadline includes permit wait"
            );
            assert_eq!(result, Ok(true));
            let command_id = CommandId::from_uuid(request_id.as_uuid()).unwrap();
            let committed = fixture
                .writer
                .committed_command(command_id)
                .await
                .unwrap()
                .unwrap();
            let source_key = format!("session-rollout:{session_id}:{session_id}");
            let current = fixture
                .writer
                .session_import_context(&source_key)
                .await
                .unwrap()
                .unwrap();
            let origin = current.current.metadata.prospective_origin.unwrap();
            let boundary = repository_view.snapshots.get(&origin.snapshot_ref).unwrap();
            assert!(boundary.evidence_refs.contains(&source_reference));
            *boundary_counts
                .entry(boundary.worktree_instance_id)
                .or_insert(0usize) += 1;
            assert_eq!(current.current.access_decision, None);
            assert!(current.job.is_none());
            assert!(committed.payloads.iter().any(|payload| matches!(
                payload,
                JournalPayload::SessionImportEventRecorded(event)
                    if event.session_id == session_id
                        && event.source_instance_id.as_deref()
                            == Some(format!("session-rollout:{session_id}:{session_id}").as_str())
            )));
            let worktree = repository_view
                .worktrees
                .get(&boundary.worktree_instance_id)
                .unwrap();
            *worktree_counts
                .entry(worktree.repository_instance_id)
                .or_insert(0usize) += 1;
        }
        let mut boundary_group_sizes = boundary_counts.values().copied().collect::<Vec<_>>();
        boundary_group_sizes.sort_unstable();
        assert_eq!(boundary_group_sizes, [2, 3]);
        let mut worktree_group_sizes = worktree_counts.values().copied().collect::<Vec<_>>();
        worktree_group_sizes.sort_unstable();
        assert_eq!(worktree_group_sizes, [2, 3]);
        for (repository_id, repository) in &repository_view.repositories {
            let worktree = repository_view
                .worktrees
                .values()
                .find(|worktree| worktree.repository_instance_id == *repository_id)
                .unwrap();
            let source_count = *worktree_counts.get(repository_id).unwrap();
            assert_eq!(
                u32::try_from(source_count).unwrap(),
                worktree.worktree_revision
            );
            assert_eq!(
                worktree.predecessor_revision,
                (source_count > 1).then_some(u32::try_from(source_count - 1).unwrap())
            );
            assert!(repository.common_dir_filesystem.is_some());
        }
        assert!(prepared_rx.try_recv().is_err());
        fixture.close().await;
    }

    #[tokio::test]
    async fn empty_typed_source_permission_set_is_a_noop() {
        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let journal = crate::open_writer(&root).await.unwrap();
        let (writer, task) = crate::spawn_writer(journal, 8).unwrap();
        let current = writer.project_current(true).await.unwrap();
        let typed = blocked_source_observations(&writer, None, &current, &[], [0; 32])
            .await
            .unwrap();
        let snapshot = writer.project().await.unwrap();
        let rows = blocked_source_rows(&writer, None, &snapshot, &[], [0; 32])
            .await
            .unwrap();
        assert_eq!(typed, rows);
        assert!(typed.is_empty());
        task.shutdown_and_join().await.unwrap();
        drop(writer);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prospective_appends_require_open_origin_and_complete_new_records() {
        let source = "session-rollout:019d0000-0000-7000-8000-000000000001:019d0000-0000-7000-8000-000000000001";
        let origin = ProspectiveSourceOrigin {
            snapshot_ref: evertrace_domain::ids::WorktreeSnapshotId::new_v7(),
            observed_end: 100,
            record_start: Some(100),
            closed: true,
        };
        let metadata = SessionMetadata {
            source_path: "2026/10/06/rollout-2026-10-06T00-00-00-session.jsonl".into(),
            source_format: SOURCE_FORMAT.into(),
            started_at_us: None,
            ended_at_us: None,
            host: None,
            model_profile: None,
            workspace_hint: None,
            repository_hint: None,
            worktree_hint: None,
            workspace_resolution_kind: WorkspaceResolutionKind::Ambiguous,
            resolved_repository_instance_id: None,
            resolved_worktree_instance_id: None,
            repository_read_restrictions: Some(Vec::new()),
            prospective_origin: Some(origin),
            file_size: 100,
            file_mtime_us: 1,
            source_fingerprint: "fingerprint-before-append".into(),
            source_revision: SourceRevision::parse("same-logical-revision").unwrap(),
            parser_version: 1,
            metadata_state: MetadataState::Indexed,
        };
        let mut old = SessionImportCurrent {
            session_id: "019d0000-0000-7000-8000-000000000001".into(),
            source_instance_id: Some(source.into()),
            revision: 1,
            metadata: metadata.clone(),
            access_decision: Some(SessionAccessDecision::Approved),
            body_state: SessionBodyState::Imported,
            source_event_seq: 1,
        };
        let mut appended = metadata;
        appended.file_size = 200;
        appended.file_mtime_us = 2;
        appended.source_fingerprint = "fingerprint-after-append".into();
        let mut payloads = Vec::new();
        metadata_events_internal(
            Some(&old),
            old.session_id.clone(),
            old.source_instance_id.clone(),
            appended.clone(),
            2,
            true,
            &mut payloads,
        )
        .unwrap();
        assert!(!payloads.iter().any(|payload| matches!(
            payload,
            JournalPayload::SessionImportEventRecorded(event)
                if matches!(event.event, SessionImportEventKind::BodyStateAdvanced {
                    body_state: SessionBodyState::Queued,
                    ..
                })
        )));
        append_queued_import_jobs(&mut payloads, 0, [0; 32]).unwrap();
        assert!(
            !payloads
                .iter()
                .any(|payload| matches!(payload, JournalPayload::JobState(_)))
        );
        assert!(payloads.iter().any(|payload| matches!(
            payload,
            JournalPayload::SessionImportEventRecorded(event)
                if matches!(&event.event, SessionImportEventKind::MetadataObserved { metadata }
                    if metadata.prospective_origin.as_ref().is_some_and(|origin|
                        origin.closed && origin.record_start == Some(100)))
        )));

        old.body_state = SessionBodyState::Failed;
        old.access_decision = None;
        old.metadata.prospective_origin.as_mut().unwrap().closed = false;
        appended.prospective_origin = old.metadata.prospective_origin.clone();
        payloads.clear();
        metadata_events_internal(
            Some(&old),
            old.session_id.clone(),
            old.source_instance_id.clone(),
            appended.clone(),
            3,
            true,
            &mut payloads,
        )
        .unwrap();
        assert!(payloads.iter().any(|payload| matches!(
            payload, JournalPayload::SessionImportEventRecorded(event)
                if matches!(event.event, SessionImportEventKind::BodyStateAdvanced {
                    body_state: SessionBodyState::Queued, ..
                })
        )));
        assert!(!payloads.iter().any(|payload| matches!(
            payload, JournalPayload::SessionImportEventRecorded(event)
                if matches!(event.event, SessionImportEventKind::AccessDecision { .. })
        )));
        payloads.clear();
        metadata_events_internal(
            Some(&old),
            old.session_id.clone(),
            old.source_instance_id.clone(),
            appended,
            4,
            false,
            &mut payloads,
        )
        .unwrap();
        assert!(!payloads.iter().any(|payload| matches!(
            payload, JournalPayload::SessionImportEventRecorded(event)
                if matches!(event.event, SessionImportEventKind::BodyStateAdvanced {
                    body_state: SessionBodyState::Queued, ..
                })
        )));
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
            WorkspaceResolutionKind::Ambiguous
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
            WorkspaceResolutionKind::Ambiguous
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
            WorkspaceResolutionKind::Ambiguous
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
            _runtime_workspace_roots: None,
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
                None,
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
        for git in [SessionGit::Missing, SessionGit::Null] {
            assert_eq!(
                resolve_workspace(
                    Some("/missing"),
                    &git,
                    None,
                    &RepositoryCurrentView::default()
                )
                .unwrap(),
                (WorkspaceResolutionKind::Ambiguous, None, None)
            );
        }
        assert_eq!(
            source_timestamp_us("1970-01-01T00:00:01.001Z"),
            Some(1_001_000)
        );
        assert_eq!(source_timestamp_us("2026-02-29T00:00:00Z"), None);
        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for args in [
            vec!["init", "-q"],
            vec![
                "-c",
                "user.name=Probe",
                "-c",
                "user.email=probe@invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "seed",
            ],
        ] {
            assert!(
                std::process::Command::new("git")
                    .args(args)
                    .current_dir(&root)
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let source = "session-rollout:session:019d0000-0000-7000-8000-000000000029";
        let at = source_timestamp_us("2026-08-30T00:00:00Z").unwrap();
        let evidence = crate::repository::probe_repository_identity(
            &root,
            &[source.into()],
            at,
            Instant::now() + Duration::from_secs(1),
            &[],
        )
        .unwrap();
        assert!(evidence.unavailable_reason.is_none());
        assert!(evidence.tracked_diff_digest.is_none() && evidence.index_digest.is_none());
        let resolution =
            crate::repository::resolve_repository(&crate::repository::RepositoryResolveInput {
                view: &RepositoryCurrentView::default(),
                evidence: &evidence,
                derived_from_hint: None,
            })
            .unwrap();
        let mut view = RepositoryCurrentView::default();
        for repository in resolution.repositories {
            view.repositories
                .insert(repository.repository_id, repository);
        }
        for worktree in resolution.worktrees {
            view.worktrees
                .insert(worktree.worktree_instance_id, worktree);
        }
        for snapshot in resolution.snapshots {
            view.snapshots
                .insert(snapshot.worktree_snapshot_id, snapshot);
        }
        let repository = *view.repositories.keys().next().unwrap();
        let incomplete = std::collections::BTreeSet::from([repository]);
        let resolve_bounded =
            |view: &RepositoryCurrentView,
             evidence: &crate::repository::GitProbeEvidence,
             incomplete: &std::collections::BTreeSet<_>| {
                crate::repository::RepositoryResolveInput {
                    view,
                    evidence,
                    derived_from_hint: None,
                }
                .resolve_with_incomplete_history(incomplete)
                .unwrap()
            };
        assert_eq!(
            resolve_bounded(&view, &evidence, &incomplete).kind,
            Some(crate::repository::ResolutionKind::NoDelta)
        );
        let mut negative = evidence.clone();
        let foreign = crate::repository::GitOid::parse(&"f".repeat(40)).unwrap();
        negative.head_oid = Some(foreign.clone());
        negative.head_ancestors.clear();
        negative.ref_tips = vec![("refs/heads/foreign".into(), foreign)];
        let refused = resolve_bounded(&view, &negative, &incomplete);
        assert_eq!(
            refused.kind,
            Some(crate::repository::ResolutionKind::Ambiguous)
        );
        assert!(refused.payloads().is_empty());
        let mut competing = view.clone();
        let mut other = competing.repositories[&repository].clone();
        other.repository_id = evertrace_domain::ids::RepositoryId::new_v7();
        let other_id = other.repository_id;
        competing.repositories.insert(other_id, other);
        let refused = resolve_bounded(
            &competing,
            &evidence,
            &std::collections::BTreeSet::from([other_id]),
        );
        assert_eq!(
            refused.kind,
            Some(crate::repository::ResolutionKind::Ambiguous)
        );
        assert!(refused.payloads().is_empty());
        // A represented old HEAD is still positive evidence even when the
        // current snapshot has changed and other history remains unexamined.
        let mut historical = view.clone();
        let snapshot = historical.snapshots.values_mut().next().unwrap();
        let mut old = snapshot.clone();
        old.worktree_snapshot_id = evertrace_domain::ids::WorktreeSnapshotId::new_v7();
        snapshot.head_oid = negative
            .head_oid
            .as_ref()
            .map(|head| head.as_str().to_owned());
        historical.snapshots.insert(old.worktree_snapshot_id, old);
        let selected = resolve_bounded(&historical, &evidence, &incomplete);
        assert!(selected.repositories.is_empty());
        assert_ne!(
            selected.kind,
            Some(crate::repository::ResolutionKind::Ambiguous)
        );
        let git = SessionGit::Object(SessionGitObject {
            commit_hash: evidence.head_oid.map(|head| head.as_str().to_owned()),
            branch: None,
            repository_url: None,
        });
        assert_eq!(
            resolve_workspace(root.to_str(), &git, None, &view)
                .unwrap()
                .0,
            WorkspaceResolutionKind::Ambiguous
        );
        assert_eq!(
            resolve_workspace(root.to_str(), &git, Some(("different-source", at)), &view)
                .unwrap()
                .0,
            WorkspaceResolutionKind::Ambiguous
        );
        assert_eq!(
            resolve_workspace(root.to_str(), &git, Some((source, at + 1)), &view)
                .unwrap()
                .0,
            WorkspaceResolutionKind::Ambiguous
        );
        let resolved = resolve_workspace(root.to_str(), &git, Some((source, at)), &view).unwrap();
        assert_eq!(resolved.0, WorkspaceResolutionKind::Repository);
        assert!(resolved.1.is_some() && resolved.2.is_some());
        fs::remove_dir_all(&root).unwrap();
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
            WorkspaceResolutionKind::Ambiguous
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
            WorkspaceResolutionKind::Ambiguous
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
            WorkspaceResolutionKind::Ambiguous
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
