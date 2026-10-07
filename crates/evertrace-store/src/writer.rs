use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, DirBuilder, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use fs2::FileExt;
use lancedb::{Connection, Table};

use crate::{
    command::{CommitOutcome, JournalCommand, JournalPayload, StoreError, prepare_command},
    connection::StoreReadHandle,
    journal::{
        JournalRow, replay_outcome, rows_for_append, validate_complete_command,
        validate_journal_rows,
    },
    migrations::{L0002, MigrationOutcome},
    objects::{ObjectRow, checkpoint_from_rows},
    projections::{
        CatchUpOutcome, JournalAdmissionState, ProjectionSnapshot, ProjectionWorker,
        ReconciliationArtifactDescriptor, ReconciliationArtifactFrontier, ReconciliationFrontier,
    },
    query::L0002ProjectionWorker,
    search::SEARCH_TABLE,
    sqlite_state::{SqliteHandle, SqliteStamp, SqliteState},
};

/// Existing native handles only: no replay, projection repair, or content verification.
pub struct NativeDiagnostics {
    pub tables: [NativeDiagnosticTable; 4],
    pub fts_index_present: Option<bool>,
    pub objects: Option<ProjectionSnapshot>,
}

pub struct NativeDiagnosticTable {
    pub schema_matches: Option<bool>,
    pub version: Option<u64>,
    pub checkpoint: Option<u64>,
}

pub(crate) struct GcAuthority {
    references: std::collections::BTreeSet<String>,
    backup_root: Option<evertrace_capture::confined_read::ConfinedRoot>,
    backup_names: Vec<String>,
    backups: Vec<crate::backup::BackupVerification>,
}

impl GcAuthority {
    pub(crate) fn revalidate(&self, data_dir: &Path) -> Result<(), StoreError> {
        // A shared deadline and total metadata budget, not one budget per backup.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
        let mut remaining = 100_000;
        let path = data_dir.join("backups");
        if let Some(root) = &self.backup_root {
            root.revalidate_stable()
                .map_err(|_| StoreError::StoreCorrupt)?;
            let names = root
                .list_directory(None, 64, deadline)
                .map_err(|_| StoreError::StoreCorrupt)?
                .into_iter()
                .map(|entry| entry.name)
                .collect::<Vec<_>>();
            if names != self.backup_names {
                return Err(StoreError::StoreCorrupt);
            }
            for backup in &self.backups {
                backup
                    .revalidate_gc_inputs(deadline, &mut remaining)
                    .map_err(|_| StoreError::StoreCorrupt)?;
            }
            root.revalidate_stable()
                .map_err(|_| StoreError::StoreCorrupt)?;
        } else if !matches!(fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound)
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedCommand {
    pub command_id: evertrace_domain::ids::CommandId,
    pub event_ids: Vec<String>,
    pub payloads: Vec<JournalPayload>,
}

/// A named, request-local selection for ordinary MCP Search.  It carries only
/// the control and exact dependency rows consumed by that request; it is not a
/// partial `ProjectionSnapshot` and cannot be reused after the call returns.
#[derive(Debug)]
pub struct NormalSearchReadContext {
    pub frontier: u64,
    pub scope: crate::projections::ScopeCurrentContext,
    pub rows: Vec<ObjectRow>,
}

/// Candidate identifiers and the concrete scope needed to expand the finite
/// route closure for a normal Search request.
#[derive(Debug)]
pub struct NormalSearchCandidateRequest {
    pub identifiers: Vec<String>,
    pub task_id: Option<evertrace_domain::ids::TaskId>,
    pub repository_id: Option<evertrace_domain::ids::RepositoryId>,
    pub worktree_id: Option<evertrace_domain::ids::WorktreeId>,
    pub include_procedure_route: bool,
    /// A selected candidate is backed by an admission-derived family whose
    /// exact row is not addressable without its existing reducer.  Ordinary
    /// evidence and directly-addressable object candidates leave this false,
    /// so their finite verification never rebuilds unrelated derived rows.
    pub include_derived_candidate_rows: bool,
}

/// A transient replay read bound, not a persistent journal index.
pub const MAX_COMMITTED_COMMAND_READ: usize = 64;

const NORMAL_SEARCH_CLOSURE_ROUNDS: usize = 8;

fn normal_search_validate_candidate_request(
    candidate: &NormalSearchCandidateRequest,
) -> Result<(), StoreError> {
    if candidate.identifiers.is_empty()
        || candidate.identifiers.len() > 65
        || candidate.identifiers.iter().any(|value| value.is_empty())
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}

fn normal_search_dedup_rows(rows: &mut Vec<ObjectRow>) -> Result<(), StoreError> {
    let mut by_id = BTreeMap::new();
    for row in std::mem::take(rows) {
        if let Some(previous) = by_id.get(&row.row_id) {
            if previous != &row {
                return Err(StoreError::StoreCorrupt);
            }
        } else {
            by_id.insert(row.row_id.clone(), row);
        }
    }
    *rows = by_id.into_values().collect();
    Ok(())
}

fn normal_search_has_reference(rows: &[ObjectRow], reference: &str) -> bool {
    rows.iter().any(|row| {
        row.row_id == reference
            || row.object_id.as_deref() == Some(reference)
            || row.current_revision_id.as_deref() == Some(reference)
    })
}

fn normal_search_proposal_references(rows: &[ObjectRow]) -> Result<BTreeSet<String>, StoreError> {
    let mut references = BTreeSet::new();
    for row in rows
        .iter()
        .filter(|row| row.object_kind.as_deref() == Some("revision_proposal_revision"))
    {
        let JournalPayload::RevisionProposalRecorded(proposal) = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?
        else {
            return Err(StoreError::StoreCorrupt);
        };
        references.extend(proposal.source_cohort_refs.iter().cloned());
        references.extend(proposal.evidence_refs.iter().cloned());
        if let evertrace_domain::semantic::ProposalPayload::Procedure(payload) = &proposal.payload {
            references.extend(payload.draft().evidence_refs.iter().cloned());
        }
    }
    Ok(references)
}

fn normal_search_permission_scope_references(
    rows: &[ObjectRow],
    candidate: Option<&NormalSearchCandidateRequest>,
) -> BTreeSet<String> {
    let identifiers = candidate
        .map(|candidate| candidate.identifiers.iter().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    rows.iter()
        .filter(|row| {
            matches!(
                row.object_kind.as_deref(),
                Some(
                    "source_receipt"
                        | "source_observation"
                        | "evidence_surface"
                        | "semantic_digest"
                        | "revision_proposal_revision"
                )
            ) || identifiers.contains(&row.row_id)
                || row
                    .object_id
                    .as_ref()
                    .is_some_and(|id| identifiers.contains(id))
                || row
                    .current_revision_id
                    .as_ref()
                    .is_some_and(|id| identifiers.contains(id))
        })
        .flat_map(|row| [row.task_id.as_deref(), row.worktree_id.as_deref()])
        .flatten()
        .map(str::to_owned)
        .collect()
}

fn normal_search_linked_references(
    rows: &[ObjectRow],
    include_route: bool,
    candidate_identifiers: Option<&BTreeSet<String>>,
) -> Result<BTreeSet<String>, StoreError> {
    let mut references = normal_search_proposal_references(rows)?;
    // Route evaluation already gets its task/workstream/episode closure from
    // the scoped read below. It consumes the current procedure usage reducer,
    // not historical Operation/ScopeEffect/HostOccurrence chains; those
    // families are neither materialized by this exact-reference reader nor
    // inputs to route_search_rows or begin_procedure_usage.
    for row in rows
        .iter()
        .filter(|row| row.row_kind == crate::ObjectRowKind::Data)
    {
        if candidate_identifiers.is_some_and(|identifiers| {
            identifiers.contains(&row.row_id)
                || row
                    .object_id
                    .as_ref()
                    .is_some_and(|id| identifiers.contains(id))
                || row
                    .current_revision_id
                    .as_ref()
                    .is_some_and(|id| identifiers.contains(id))
        }) && let Some(object_id) = &row.object_id
        {
            // A current Search result may name a historical revision.  Fetch
            // that object's complete lineage so the existing current/tie
            // reduction never treats an old body as current.
            references.insert(object_id.clone());
        }
        let Some(payload) = row.payload_json.as_deref() else {
            continue;
        };
        let payload: JournalPayload =
            serde_json::from_str(payload).map_err(|_| StoreError::StoreCorrupt)?;
        match payload {
            JournalPayload::SourceObservationRecorded(value) => {
                references.insert(value.source_receipt_ref.to_string());
            }
            JournalPayload::EvidenceSurfaceRecorded(value) => {
                references.insert(value.source_observation_revision_ref.to_string());
            }
            JournalPayload::SemanticDigestRecorded(value) => {
                references.extend(value.selected_direct_refs.iter().cloned());
            }
            JournalPayload::WorkEpisodeRecorded(value) if include_route => {
                references.extend(value.checkpoint_refs.iter().cloned());
            }
            JournalPayload::AttemptRecorded(value) if include_route => {
                references.extend(value.experiment_run_ids.iter().map(ToString::to_string));
                references.extend(value.outcome_refs.iter().cloned());
            }
            JournalPayload::ExperimentRunRecorded(value) if include_route => {
                references.insert(value.run_id.to_string());
            }
            JournalPayload::ResultEvidenceRecorded(value) if include_route => {
                references.insert(value.result_evidence_id.to_string());
                references.insert(value.experiment_run_id.to_string());
            }
            _ => {}
        }
    }
    Ok(references)
}

fn normal_search_expand_dependencies(
    state: &crate::projections::JournalAdmissionState,
    rows: &mut Vec<ObjectRow>,
    candidate: Option<&NormalSearchCandidateRequest>,
) -> Result<(), StoreError> {
    let include_route = candidate.is_some_and(|candidate| candidate.include_procedure_route);
    let candidate_identifiers = candidate.map(|candidate| {
        candidate
            .identifiers
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
    });
    for _ in 0..NORMAL_SEARCH_CLOSURE_ROUNDS {
        let mut references =
            normal_search_linked_references(rows, include_route, candidate_identifiers.as_ref())?;
        references.retain(|reference| !normal_search_has_reference(rows, reference));
        if references.is_empty() {
            return Ok(());
        }
        let before = rows.len();
        // The selected candidate, including a reducer-backed family, was
        // materialized before this closure walk. Every later reference came
        // from that bounded payload and therefore uses direct current-state
        // reads rather than another all-derived-family pass.
        rows.extend(state.normal_search_reference_rows(&references, false)?);
        normal_search_dedup_rows(rows)?;
        if rows.len() == before {
            return Ok(());
        }
    }
    Ok(())
}

fn decode_committed_command(
    mut rows: Vec<crate::JournalRow>,
) -> Result<CommittedCommand, StoreError> {
    validate_complete_command(&rows)?;
    rows.sort_by_key(|row| row.ordinal);
    Ok(CommittedCommand {
        command_id: rows[0].command_id,
        event_ids: rows.iter().map(|row| row.event_id.clone()).collect(),
        payloads: rows
            .iter()
            .map(|row| row.payload())
            .collect::<Result<Vec<_>, _>>()?,
    })
}

#[derive(Debug)]
pub struct SiblingWriterLock {
    data_dir: PathBuf,
    lock_path: PathBuf,
    file: File,
    parent_file: File,
    data_identity: (u64, u64),
}

impl SiblingWriterLock {
    pub fn acquire(data_dir: &Path) -> Result<Self, StoreError> {
        validate_lexical_data_dir(data_dir)?;
        let parent = data_dir.parent().ok_or(StoreError::InvalidPath)?;
        validate_parent(parent)?;
        let parent_file = File::open(parent).map_err(|_| StoreError::Io)?;
        let lock_path = sibling_lock_path(data_dir)?;
        let existed = match fs::symlink_metadata(&lock_path) {
            Ok(metadata) => {
                validate_lock_metadata(&metadata)?;
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(_) => return Err(StoreError::Io),
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|_| StoreError::Io)?;
        validate_lock_identity(&lock_path, &file)?;
        if !existed {
            file.sync_all().map_err(|_| StoreError::Io)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| StoreError::Io)?;
        }
        FileExt::try_lock_exclusive(&file).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                StoreError::WriterAlreadyRunning
            } else {
                StoreError::Io
            }
        })?;
        validate_lock_identity(&lock_path, &file)?;
        ensure_data_root(data_dir, parent)?;
        let data_metadata = fs::symlink_metadata(data_dir).map_err(|_| StoreError::Io)?;
        Ok(Self {
            data_dir: data_dir.to_owned(),
            lock_path,
            file,
            parent_file,
            data_identity: (data_metadata.dev(), data_metadata.ino()),
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    pub fn inode_identity(&self) -> Result<(u64, u64), StoreError> {
        let metadata = self.file.metadata().map_err(|_| StoreError::Io)?;
        Ok((metadata.dev(), metadata.ino()))
    }

    fn validate_parent_and_lock(&self) -> Result<(), StoreError> {
        validate_lock_identity(&self.lock_path, &self.file)?;
        let parent = self.data_dir.parent().ok_or(StoreError::InvalidPath)?;
        validate_parent(parent)?;
        let located = fs::symlink_metadata(parent).map_err(|_| StoreError::Io)?;
        let held = self.parent_file.metadata().map_err(|_| StoreError::Io)?;
        if (located.dev(), located.ino()) != (held.dev(), held.ino()) {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    pub(crate) fn validate_held(&self) -> Result<(), StoreError> {
        self.validate_parent_and_lock()?;
        let metadata = fs::symlink_metadata(&self.data_dir).map_err(|_| StoreError::Io)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.dev(), metadata.ino()) != self.data_identity
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    pub(crate) fn rebind_restored_root(&mut self, expected: (u64, u64)) -> Result<(), StoreError> {
        self.validate_parent_and_lock()?;
        let metadata = fs::symlink_metadata(&self.data_dir).map_err(|_| StoreError::Io)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.dev(), metadata.ino()) != expected
        {
            return Err(StoreError::StoreCorrupt);
        }
        self.data_identity = expected;
        self.parent_file.sync_all().map_err(|_| StoreError::Io)?;
        self.validate_held()
    }
}

#[derive(Debug)]
pub struct ClosedJournalWriter {
    readers: StoreReadHandle,
    /// Held from physical close until the reopened writer is installed; it
    /// blocks new readers for the whole closed backup window.
    guard: Option<tokio::sync::OwnedRwLockWriteGuard<()>>,
    // Declared last: the sibling lock outlives the closed read binding.
    pub(crate) lock: SiblingWriterLock,
}

const MAX_PROJECTION_HANDOFF_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
struct ProjectionValidation {
    // The physical stamp already binds the connection incarnation, observed
    // external data_version, every family's successful commit epoch and the
    // real committed checkpoints/generations.
    stamp: SqliteStamp,
    // Full-projection stamps additionally bind the real search native version.
    search_version: u64,
    frontier: u64,
    has_failed_job: bool,
    // Private level: this exact physical stamp, the derived-family
    // checkpoints and the real search version were established by a
    // completed full L0002 derive whose persisted relations and search rows
    // were read back equal. It is not a persisted certificate and is never
    // upgraded by a checkpoint-only no-delta read.
    content_proven: bool,
    // Last confirmed append, not a claim that the old objects or indexes have
    // advanced. Each retained successor is bound to the input stamp plus the
    // committed frontier it appended.
    appended_through: Option<(SqliteStamp, u64)>,
    // At most one small typed delta. Multiple appends use the ordinary
    // journal delta read without retaining or concatenating their rows.
    appended_rows: Option<Vec<crate::JournalRow>>,
}

impl ProjectionValidation {
    fn objects_bound(&self, other: &SqliteStamp) -> bool {
        self.stamp.incarnation == other.incarnation
            && self.stamp.data_version == other.data_version
            && self.stamp.journal_epoch == other.journal_epoch
            && self.stamp.frontier == other.frontier
            && self.stamp.objects_epoch == other.objects_epoch
            && self.stamp.object_checkpoint == other.object_checkpoint
            && self.stamp.object_generation == other.object_generation
    }

    fn appended_successor_bound(&self, other: &SqliteStamp) -> bool {
        self.appended_through
            .as_ref()
            .is_some_and(|(input, frontier)| {
                input.incarnation == other.incarnation
                    && input.data_version == other.data_version
                    && input.objects_epoch == other.objects_epoch
                    && input.object_checkpoint == other.object_checkpoint
                    && input.object_generation == other.object_generation
                    && *frontier == other.frontier
            })
    }

    /// A confirmed closed single append descending from a proven complete
    /// content frontier whose derived families still sit on that same base
    /// and search version. One append is bound by the retained rows, the
    /// journal epoch and the unchanged objects/relations/search state.
    fn capture_successor_bound(&self, other: &SqliteStamp, search_version: u64) -> bool {
        self.content_proven
            && self.appended_rows.is_some()
            && self.search_version == search_version
            && self.stamp.frontier == self.stamp.object_checkpoint
            && self.stamp.relations_epoch == other.relations_epoch
            && self.stamp.relation_checkpoint == other.relation_checkpoint
            && other.journal_epoch == self.stamp.journal_epoch.saturating_add(1)
            && self.appended_successor_bound(other)
    }
}

pub struct JournalWriter {
    sqlite: SqliteHandle,
    search: Table,
    connection: Connection,
    readers: StoreReadHandle,
    next_seq: u64,
    admission_state: JournalAdmissionState,
    migration_outcome: MigrationOutcome,
    // Keep the search table directory inode alive so replacement cannot reuse
    // its identity. The SQLite side revalidates its own file/directory.
    projection_directories: Vec<(PathBuf, File)>,
    // Objects and all mandatory projections have separate successful stamps.
    projection_validation: Mutex<[Option<ProjectionValidation>; 2]>,
    // Test-only observation of real selections. No production consumer reads
    // it and it carries no projection content or state.
    #[cfg(test)]
    capture_delta_selections: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    fused_delta_selections: std::sync::atomic::AtomicU64,
    // Declared last: the sibling lock must be released only after the native
    // and SQLite bindings of this writer have been dropped.
    _lock: SiblingWriterLock,
}

impl JournalWriter {
    /// The persisted committed frontier. Reserved sequence numbers are not a
    /// frontier and may leave legal gaps.
    pub fn frontier(&self) -> u64 {
        self.admission_state.committed_frontier()
    }

    pub fn projection_worker(&self) -> ProjectionWorker {
        ProjectionWorker::new(Arc::clone(&self.sqlite))
    }

    pub(crate) fn l0002_projection_worker(&self) -> L0002ProjectionWorker {
        L0002ProjectionWorker::new(Arc::clone(&self.sqlite), self.search.clone())
    }

    pub fn read_handle(&self) -> StoreReadHandle {
        self.readers.clone()
    }

    /// Select GC candidates from already validated journal admission state.
    /// Actual GC claims and authority checks still use their normal write path.
    pub fn queued_gc_jobs(&self) -> Vec<crate::DurableJob> {
        self.admission_state.queued_gc_jobs()
    }

    pub fn recall_current_contexts(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::projections::RecallCurrentContext>, StoreError> {
        self.admission_state
            .recall_current_contexts(self.frontier(), limit)
    }

    pub fn session_import_context(
        &self,
        source: &str,
    ) -> Result<Option<crate::SessionImportContext>, StoreError> {
        self.admission_state
            .session_import_context(self.frontier(), source)
    }

    /// Read the catalog resolver's complete typed closure without formatting
    /// unrelated captured payloads into a `ProjectionSnapshot`.
    pub async fn session_catalog_current_context(
        &self,
    ) -> Result<crate::SessionCatalogCurrentContext, StoreError> {
        self.validated_current_read(|state, _| state.session_catalog_current_context())
            .await
    }

    pub fn repository_read_context(
        &self,
        ids: &std::collections::BTreeSet<evertrace_domain::ids::RepositoryId>,
    ) -> Result<crate::projections::RepositoryReadContext, StoreError> {
        self.admission_state.repository_read_context(ids)
    }

    pub fn inventory_context(
        &self,
        context: &evertrace_domain::inventory::InventoryContext,
        job_id: Option<evertrace_domain::ids::JobId>,
    ) -> Result<crate::projections::InventoryCurrentContext, StoreError> {
        self.admission_state.inventory_context(context, job_id)
    }

    pub fn session_import_contexts(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<crate::SessionImportSelection, StoreError> {
        self.admission_state
            .session_import_contexts(self.frontier(), after, limit)
    }

    pub fn session_import_prefix_page(
        &self,
        request: &crate::SessionImportPrefixRequest,
    ) -> Result<crate::SessionImportPrefixPage, StoreError> {
        self.admission_state
            .session_import_prefix_page(self.frontier(), request)
    }

    pub fn session_import_context_with_repository(
        &self,
        source: &str,
        identity: evertrace_domain::repository::FilesystemIdentity,
        common_dir: &str,
    ) -> Result<Option<crate::SessionImportContext>, StoreError> {
        if common_dir.len() > 4096 || !std::path::Path::new(common_dir).is_absolute() {
            return Err(StoreError::InvalidInput);
        }
        self.admission_state.session_import_context_with_repository(
            self.frontier(),
            source,
            Some((identity, common_dir)),
        )
    }

    pub async fn open(data_dir: &Path) -> Result<Self, StoreError> {
        let lock = SiblingWriterLock::acquire(data_dir)?;
        let readers = StoreReadHandle::open(data_dir);
        Self::open_with_lock(lock, readers).await
    }

    /// Reopen the same store on a lock and read handle carried across a closed
    /// backup window; the new physical incarnation replaces the old one.
    pub(crate) async fn open_with_lock(
        lock: SiblingWriterLock,
        readers: StoreReadHandle,
    ) -> Result<Self, StoreError> {
        let data_dir = lock.data_dir().to_owned();
        crate::restore::reject_retained_upgrade_candidate(&data_dir)
            .map_err(|_| StoreError::UpgradeRequired)?;
        crate::connection::prepare_native_root(&data_dir)?;
        lock.validate_held()?;
        let session = crate::connection::native_session();
        let connection = lancedb::connect(
            crate::connection::native_root(&data_dir)
                .to_str()
                .ok_or(StoreError::InvalidPath)?,
        )
        .session(session.clone())
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
        let writer = Self::open_on_connection(lock, &data_dir, connection, readers).await?;
        // Startup validates the entire native history. Keep its metadata from
        // occupying the long-lived writer cache after that work is complete.
        session.file_metadata_cache().clear().await;
        Ok(writer)
    }

    /// Whether the physical store database exists at all, without creating it.
    pub(crate) fn store_database_exists(data_dir: &Path) -> Result<bool, StoreError> {
        let path = crate::connection::sqlite_path(data_dir);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(StoreError::Io),
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                Err(StoreError::StoreCorrupt)
            }
            Ok(_) => Ok(true),
        }
    }

    pub(crate) async fn open_at_with_lock(
        lock: SiblingWriterLock,
        data_dir: &Path,
        readers: StoreReadHandle,
    ) -> Result<Self, StoreError> {
        lock.validate_held()?;
        let connection = lancedb::connect(
            crate::connection::native_root(data_dir)
                .to_str()
                .ok_or(StoreError::InvalidPath)?,
        )
        .session(crate::connection::native_session())
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
        Self::open_on_connection(lock, data_dir, connection, readers).await
    }

    async fn open_on_connection(
        lock: SiblingWriterLock,
        data_dir: &Path,
        connection: Connection,
        readers: StoreReadHandle,
    ) -> Result<Self, StoreError> {
        lock.validate_held()?;
        let sqlite = SqliteState::open(data_dir)?.handle();
        let migration_outcome = L0002::apply(&sqlite, &connection).await?;
        let search = connection
            .open_table(SEARCH_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        crate::search::read_search_rows(&search).await?;
        let native_dir = crate::connection::native_root(data_dir);
        let path = native_dir.join(format!("{SEARCH_TABLE}.lance"));
        let located = fs::symlink_metadata(&path).map_err(|_| StoreError::StoreCorrupt)?;
        let file = File::open(&path).map_err(|_| StoreError::StoreCorrupt)?;
        let held = file.metadata().map_err(|_| StoreError::StoreCorrupt)?;
        if !located.is_dir()
            || located.file_type().is_symlink()
            || (located.dev(), located.ino()) != (held.dev(), held.ino())
        {
            return Err(StoreError::StoreCorrupt);
        }
        let projection_directories = vec![(path, file)];
        let (admission_state, next_seq) = {
            let state = sqlite.lock().map_err(|_| StoreError::StoreCorrupt)?;
            let rows = state.rows()?;
            let admission_state = JournalAdmissionState::from_journal_rows(&rows)?;
            let next_seq = rows
                .last()
                .map(|row| row.seq)
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(StoreError::StoreCorrupt)?;
            (admission_state, next_seq)
        };
        readers.publish_writer_binding(connection.clone(), &sqlite)?;
        Ok(Self {
            _lock: lock,
            sqlite,
            search,
            connection,
            readers,
            next_seq,
            admission_state,
            migration_outcome,
            projection_directories,
            projection_validation: Mutex::new([None, None]),
            #[cfg(test)]
            capture_delta_selections: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            fused_delta_selections: std::sync::atomic::AtomicU64::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn projection_handle(&self) -> crate::sqlite_state::SqliteHandle {
        self.sqlite.clone()
    }

    fn lock_sqlite(&self) -> Result<MutexGuard<'_, SqliteState>, StoreError> {
        self.sqlite.lock().map_err(|_| StoreError::StoreCorrupt)
    }

    fn physical_stamp(&self) -> Result<SqliteStamp, StoreError> {
        self.lock_sqlite()?.stamp()
    }

    pub async fn read_diagnostics(&self) -> NativeDiagnostics {
        let journal_checkpoint = self.physical_stamp().map(|stamp| stamp.frontier);
        let validated_objects = self.lock_sqlite().and_then(|state| state.object_rows());
        let object_checkpoint = match &validated_objects {
            Ok(rows) => checkpoint_from_rows(rows),
            Err(_) => self
                .lock_sqlite()
                .and_then(|state| state.object_checkpoint_row())
                .map(|checkpoint| checkpoint.map(|(frontier, _)| frontier).unwrap_or(0)),
        };
        let relation_checkpoint = self
            .lock_sqlite()
            .and_then(|state| state.relation_checkpoint_row())
            .map(|checkpoint| checkpoint.map(|(frontier, _)| frontier).unwrap_or(0));
        let search_checkpoint = crate::search::read_search_checkpoint(&self.search).await;
        let search_version = self.search.version().await.ok();
        let search_schema = self.search.schema().await.ok();
        let tables = vec![
            NativeDiagnosticTable {
                schema_matches: Some(true),
                version: None,
                checkpoint: journal_checkpoint.ok(),
            },
            NativeDiagnosticTable {
                schema_matches: Some(true),
                version: None,
                checkpoint: object_checkpoint.ok(),
            },
            NativeDiagnosticTable {
                schema_matches: Some(true),
                version: None,
                checkpoint: relation_checkpoint.ok(),
            },
            NativeDiagnosticTable {
                schema_matches: search_schema
                    .map(|schema| schema == crate::search::search_schema()),
                version: search_version,
                checkpoint: search_checkpoint.ok(),
            },
        ];
        let objects = tables[1].checkpoint.and_then(|frontier| {
            validated_objects
                .ok()
                .map(|rows| ProjectionSnapshot { frontier, rows })
        });
        let fts_index_present = self.search.list_indices().await.ok().map(|indices| {
            indices.len() == 1
                && indices[0].columns == ["text"]
                && matches!(indices[0].index_type, lancedb::index::IndexType::FTS)
        });
        NativeDiagnostics {
            tables: tables
                .try_into()
                .unwrap_or_else(|_| unreachable!("four fixed native tables")),
            fts_index_present,
            objects,
        }
    }

    pub async fn backup_table_states(&self) -> Result<crate::BackupTableStates, StoreError> {
        let stamp = self.physical_stamp()?;
        let search_checkpoint = crate::search::read_search_checkpoint(&self.search).await?;
        let search_version = self
            .search
            .version()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let relation_generation = self
            .lock_sqlite()?
            .relation_checkpoint_row()?
            .map(|(_, generation)| generation)
            .unwrap_or(1);
        Ok(crate::BackupTableStates {
            journal: crate::BackupTableState {
                version: None,
                checkpoint: stamp.frontier,
                projection_generation: None,
            },
            objects: crate::BackupTableState {
                version: None,
                checkpoint: stamp.object_checkpoint,
                projection_generation: Some(stamp.object_generation),
            },
            relations: Some(crate::BackupTableState {
                version: None,
                checkpoint: stamp.relation_checkpoint,
                projection_generation: Some(relation_generation),
            }),
            search: Some(crate::BackupTableState {
                version: Some(search_version),
                checkpoint: search_checkpoint,
                projection_generation: Some(crate::search::SEARCH_PROJECTION_GENERATION),
            }),
        })
    }

    /// Drain every external reader lease, checkpoint the WAL with TRUNCATE and
    /// actually close the physical connection. `Some(guard)` means the store is
    /// confirmed closed and the guard must be held until the reopened writer is
    /// installed. `None` means SQLite explicitly reported the checkpoint busy:
    /// this backup failed, but the writer keeps its open database, published
    /// read binding and Lance connection. An unknown checkpoint/close/identity
    /// failure revokes the binding and fails closed.
    pub async fn quiesce_for_backup(
        &mut self,
    ) -> Result<Option<tokio::sync::OwnedRwLockWriteGuard<()>>, StoreError> {
        let guard = self.readers.quiesce().await;
        match self
            .lock_sqlite()
            .and_then(|mut state| state.checkpoint_and_close())
        {
            Ok(true) => {
                // Only a confirmed physical close revokes the binding; readers
                // that arrive during the closed window are still blocked by the
                // guard and bind again when the reopened writer publishes its
                // new incarnation.
                self.readers.revoke();
                Ok(Some(guard))
            }
            Ok(false) => {
                // A known-busy checkpoint is one ordinary failed backup: the
                // open connection, its binding and the native handle stay
                // usable for later commands and backups.
                drop(guard);
                Ok(None)
            }
            Err(error) => {
                // Unknown physical state: no reader may keep observing it.
                self.readers.revoke();
                drop(guard);
                Err(error)
            }
        }
    }

    /// Terminal cleanup for the writer actor. Wait for every real reader (and
    /// block new ones), revoke the read binding, close the physical SQLite
    /// connection without a normal checkpoint, release the native handles, and
    /// only then release the sibling lock. This is not a backup path: the
    /// closed-backup window uses `quiesce_for_backup`/`close_for_backup`.
    pub async fn shutdown(self) -> Result<(), StoreError> {
        let guard = self.readers.quiesce().await;
        let Self {
            sqlite,
            search,
            connection,
            readers,
            next_seq,
            admission_state,
            migration_outcome,
            projection_directories,
            projection_validation,
            #[cfg(test)]
                capture_delta_selections: _,
            #[cfg(test)]
                fused_delta_selections: _,
            _lock,
        } = self;
        readers.revoke();
        let closed = match sqlite.lock() {
            Ok(mut state) => state.close_connection(),
            Err(_) => Err(StoreError::StoreCorrupt),
        };
        // Drop the native and SQLite bindings while the fence is still held;
        // the sibling lock is released last.
        drop((
            search,
            connection,
            next_seq,
            admission_state,
            migration_outcome,
            projection_directories,
            projection_validation,
        ));
        drop(sqlite);
        drop(readers);
        drop(guard);
        drop(_lock);
        closed
    }

    pub fn close_for_backup(
        self,
        guard: tokio::sync::OwnedRwLockWriteGuard<()>,
    ) -> Result<ClosedJournalWriter, StoreError> {
        let Self {
            _lock: lock,
            sqlite,
            search,
            connection,
            readers,
            next_seq,
            admission_state,
            migration_outcome,
            projection_directories,
            projection_validation,
            #[cfg(test)]
                capture_delta_selections: _,
            #[cfg(test)]
                fused_delta_selections: _,
        } = self;
        readers.revoke();
        drop((
            search,
            connection,
            next_seq,
            admission_state,
            migration_outcome,
            projection_directories,
            projection_validation,
        ));
        let state = Arc::try_unwrap(sqlite)
            .map_err(|_| StoreError::Io)?
            .into_inner()
            .map_err(|_| StoreError::StoreCorrupt)?;
        if state.has_open_connection() {
            return Err(StoreError::Io);
        }
        drop(state);
        Ok(ClosedJournalWriter {
            lock,
            readers,
            guard: Some(guard),
        })
    }

    pub const fn migration_outcome(&self) -> MigrationOutcome {
        self.migration_outcome
    }

    pub fn lock_path(&self) -> &Path {
        self._lock.lock_path()
    }

    pub fn lock_inode_identity(&self) -> Result<(u64, u64), StoreError> {
        self._lock.inode_identity()
    }

    pub(crate) fn validate_restore_lock(&self) -> Result<(), StoreError> {
        self._lock.validate_held()
    }

    pub(crate) async fn rebuild_restore_projections(&self) -> Result<(), StoreError> {
        *self
            .projection_validation
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)? = [None, None];
        self.validate_restore_lock()?;
        let objects = self.projection_worker().rebuild_for_restore().await?;
        self.l0002_projection_worker()
            .rebuild_for_restore(&objects)
            .await?;
        self.validate_restore_lock()
    }

    pub(crate) async fn import_restore_ledger(
        &mut self,
        current: &crate::restore::CurrentLedger,
        occurred_at_us: i64,
        config_hash: [u8; 32],
    ) -> Result<(), StoreError> {
        *self
            .projection_validation
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)? = [None, None];
        for command in current.commands(self, occurred_at_us, config_hash)? {
            let command = command?;
            let prepared = prepare_command(&command)?;
            let rows = rows_for_append(&prepared, self.next_seq, occurred_at_us)?;
            let admission = self
                .admission_state
                .apply_row_batch(&rows.iter().collect::<Vec<_>>())?;
            self.validate_restore_lock()?;
            reserve_range(&mut self.next_seq, prepared.event_count)?;
            self.lock_sqlite()?.append_command_rows(&rows)?;
            self._lock.validate_held()?;
            self.admission_state = admission;
        }
        Ok(())
    }

    pub async fn commit(
        &mut self,
        command: &JournalCommand,
        ingested_at_us: i64,
    ) -> Result<CommitOutcome, StoreError> {
        self.commit_inner(command, ingested_at_us, None).await
    }

    pub async fn commit_if_frontier(
        &mut self,
        command: &JournalCommand,
        ingested_at_us: i64,
        expected_frontier: u64,
    ) -> Result<CommitOutcome, StoreError> {
        self.commit_inner(command, ingested_at_us, Some(expected_frontier))
            .await
    }

    pub async fn committed_command(
        &self,
        command_id: evertrace_domain::ids::CommandId,
    ) -> Result<Option<CommittedCommand>, StoreError> {
        let rows = self.existing_command_rows(command_id)?;
        if rows.is_empty() {
            return Ok(None);
        }
        decode_committed_command(rows).map(Some)
    }

    pub async fn committed_commands(
        &self,
        command_ids: &[evertrace_domain::ids::CommandId],
    ) -> Result<BTreeMap<evertrace_domain::ids::CommandId, CommittedCommand>, StoreError> {
        if command_ids.len() > MAX_COMMITTED_COMMAND_READ {
            return Err(StoreError::StoreCorrupt);
        }
        // The journal is the SQL index: no retained in-memory id set and no
        // separate command index to keep in sync.
        let ids = command_ids.iter().copied().collect::<BTreeSet<_>>();
        let state = self.lock_sqlite()?;
        let mut grouped = BTreeMap::<_, Vec<_>>::new();
        for id in ids {
            let rows = state.committed_rows(id)?;
            if !rows.is_empty() {
                grouped.insert(id, rows);
            }
        }
        drop(state);
        grouped
            .into_iter()
            .map(|(id, rows)| Ok((id, decode_committed_command(rows)?)))
            .collect()
    }

    fn existing_command_rows(
        &self,
        command_id: evertrace_domain::ids::CommandId,
    ) -> Result<Vec<crate::JournalRow>, StoreError> {
        // Positive/replay reads still validate actual persisted rows, not a
        // cached payload or acknowledgement.
        self.lock_sqlite()?.committed_rows(command_id)
    }

    async fn commit_inner(
        &mut self,
        command: &JournalCommand,
        ingested_at_us: i64,
        expected_frontier: Option<u64>,
    ) -> Result<CommitOutcome, StoreError> {
        if ingested_at_us < 0
            || command
                .events()
                .iter()
                .any(|event| event.algorithm_revision == crate::restore::LEDGER_REVISION)
        {
            return Err(StoreError::InvalidInput);
        }
        let prepared = prepare_command(command)?;
        // Persisted replay still requires a live, identity-bound store. Keep
        // replay ahead of the logical expected-frontier comparison, but do
        // not acknowledge rows through a replaced root or poisoned handle.
        let live = self.physical_stamp()?;
        let existing = self.existing_command_rows(prepared.command_id)?;
        if let Some(outcome) = replay_outcome(&existing, &prepared)? {
            return Ok(outcome);
        }
        if let Some(expected) = expected_frontier
            && live.frontier != expected
        {
            return Err(StoreError::StaleFrontier);
        }
        let next_admission_state = self.admission_state.apply_command(command, self.next_seq)?;
        let first_seq = reserve_range(&mut self.next_seq, prepared.event_count)?;
        let rows = rows_for_append(&prepared, first_seq, ingested_at_us)?;
        let last_seq = rows.last().ok_or(StoreError::StoreCorrupt)?.seq;
        let validated_input = {
            let mut stamps = self
                .projection_validation
                .lock()
                .map_err(|_| StoreError::StoreCorrupt)?;
            // Clear before the commit, including uncertain failures. Only a
            // confirmed direct successor may retain proof of the unchanged OLD
            // objects input, never of the new frontier or synchronized indexes.
            let input = stamps[0].take();
            stamps[1] = None;
            input
        };
        let handoff = validated_input
            .as_ref()
            .filter(|stamp| {
                stamp.appended_through.is_none()
                    && rows.iter().map(|row| row.payload_json.len()).sum::<usize>()
                        <= MAX_PROJECTION_HANDOFF_BYTES
            })
            .map(|_| rows.clone());
        {
            let mut state = self.lock_sqlite()?;
            state.append_command_rows(&rows)?;
        }
        self._lock.validate_held()?;
        self.admission_state = next_admission_state;
        if let Some(mut input) = validated_input {
            input.appended_through = Some((input.stamp, last_seq));
            input.appended_rows = handoff;
            self.projection_validation
                .lock()
                .map_err(|_| StoreError::StoreCorrupt)?[0] = Some(input);
        }
        Ok(CommitOutcome {
            command_id: prepared.command_id,
            first_seq,
            last_seq,
            event_ids: rows.into_iter().map(|row| row.event_id).collect(),
            replayed: false,
        })
    }

    /// Restore and validate current objects without driving unrelated indexes.
    pub async fn project_objects(&self) -> Result<ProjectionSnapshot, StoreError> {
        self.project_validated(false, true)
            .await?
            .1
            .ok_or(StoreError::StoreCorrupt)
    }

    /// Synchronize objects without returning their rows to the caller.
    pub async fn sync_objects_frontier(&self) -> Result<u64, StoreError> {
        Ok(self.project_validated(false, false).await?.0)
    }

    pub async fn inbox_current_context(
        &self,
        after: Option<&str>,
        limit: usize,
        proof_limit: usize,
    ) -> Result<crate::projections::InboxCurrentContext, StoreError> {
        self.validated_current_read(|state, stamp| {
            state.inbox_current_context(after, limit, proof_limit, stamp.has_failed_job)
        })
        .await
    }

    pub async fn memories_current_context(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<crate::projections::MemoriesCurrentContext, StoreError> {
        self.validated_current_read(|state, stamp| {
            state.memories_current_context(after, limit, stamp.has_failed_job)
        })
        .await
    }

    pub async fn capture_current_context(
        &self,
        after: Option<&str>,
        exact: Option<&str>,
        limit: usize,
    ) -> Result<crate::projections::CaptureCurrentContext, StoreError> {
        self.validated_current_read(|state, stamp| {
            state.capture_current_context(after, exact, limit, stamp.has_failed_job)
        })
        .await
    }

    pub async fn scope_current_context(
        &self,
        request: &crate::projections::ScopeCurrentRequest,
    ) -> Result<crate::projections::ScopeCurrentContext, StoreError> {
        self.validated_current_read(|state, _| state.scope_current_context(request))
            .await
    }

    /// Select the compact control closure ordinary Search needs before its
    /// native FTS pin.  Full `project()` callers retain their existing path.
    pub async fn normal_search_current_context(
        &self,
        request: &crate::projections::ScopeCurrentRequest,
    ) -> Result<NormalSearchReadContext, StoreError> {
        self.normal_search_context(request, None).await
    }

    /// Re-read only selected Search candidates and their concrete dependency
    /// closure at the writer's current validated stamp.  This is deliberately
    /// a request-local fresh read, not a cache or a partial projection.
    pub async fn normal_search_candidate_context(
        &self,
        request: &crate::projections::ScopeCurrentRequest,
        candidate: &NormalSearchCandidateRequest,
    ) -> Result<NormalSearchReadContext, StoreError> {
        self.normal_search_context(request, Some(candidate)).await
    }

    async fn normal_search_context(
        &self,
        request: &crate::projections::ScopeCurrentRequest,
        candidate: Option<&NormalSearchCandidateRequest>,
    ) -> Result<NormalSearchReadContext, StoreError> {
        // This bounded read does not open every objects row, but it still has
        // to bind its in-memory stamp to the writer's held physical identity.
        // Otherwise an external replacement could reuse the old epochs while
        // Search pins new native text.
        self.validate_projection_directories(false)?;
        // Startup (and an uncertain append) has no reusable proof yet. Recover
        // it through the ordinary validated path before using admission facts;
        // steady requests avoid that full projection round trip.
        if self
            .projection_validation
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?[0]
            .is_none()
        {
            self.project_validated(false, false).await?;
        }
        // Route facts are the one bounded Search closure read directly from
        // the persisted objects table. A Procedure candidate can arrive after
        // an intervening committed command: admission is already current then,
        // while those rows may only carry the old confirmed input. Bring them
        // to the held frontier before selecting route rows. On an unchanged
        // stamp this is the existing no-row validation hit; ordinary evidence
        // Search never takes this branch.
        if candidate.is_some_and(|candidate| candidate.include_procedure_route) {
            self.project_validated(false, false).await?;
        }
        let frontier = self.normal_search_admission_frontier()?;
        let scope = self.admission_state.scope_current_context(request)?;
        let mut rows = self.admission_state.normal_search_control_rows()?;
        if let Some(candidate) = candidate {
            normal_search_validate_candidate_request(candidate)?;
            let references = candidate.identifiers.iter().cloned().collect();
            rows.extend(self.admission_state.normal_search_reference_rows(
                &references,
                candidate.include_derived_candidate_rows,
            )?);
            if candidate.include_procedure_route {
                rows.extend(self.lock_sqlite()?.normal_search_route_scope_rows(
                    candidate.task_id,
                    candidate.repository_id,
                    candidate.worktree_id,
                )?);
            }
        }
        normal_search_dedup_rows(&mut rows)?;
        normal_search_expand_dependencies(&self.admission_state, &mut rows, candidate)?;
        let scope_references = normal_search_permission_scope_references(&rows, candidate);
        rows.extend(
            self.admission_state
                .normal_search_reference_rows(&scope_references, false)?,
        );
        normal_search_dedup_rows(&mut rows)?;
        if self.normal_search_admission_frontier()? != frontier {
            return Err(StoreError::StoreCorrupt);
        }
        // Match `project_validated`'s post-read identity boundary without a
        // full read. A replacement during the selected route read must fail
        // closed instead of mixing its text with the admission facts above.
        self.validate_projection_directories(false)?;
        Ok(NormalSearchReadContext {
            frontier,
            scope,
            rows,
        })
    }

    /// Bind ordinary Search's request-local admission facts without reopening
    /// the entire objects projection. The exclusive writer has either kept a
    /// fully validated stamp at this frontier, or retained a confirmed
    /// successor proof for an append whose old objects input is unchanged.
    /// Any uncertain append clears that proof before committing.
    ///
    /// SearchIndex still pins and checks the authoritative journal frontier
    /// after its native read, so this does not treat the admission state as a
    /// substitute for search-index freshness.
    fn normal_search_admission_frontier(&self) -> Result<u64, StoreError> {
        let stamp = self
            .projection_validation
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?[0]
            .clone()
            .ok_or(StoreError::StoreCorrupt)?;
        let live = self.physical_stamp()?;
        let frontier = self.admission_state.committed_frontier();
        if (stamp.objects_bound(&live) && stamp.frontier == frontier)
            || (stamp.appended_successor_bound(&live) && live.frontier == frontier)
        {
            return Ok(frontier);
        }
        Err(StoreError::StoreCorrupt)
    }

    pub async fn passive_source_current_context(
        &self,
        selection: &crate::projections::PassiveSourceSelection,
    ) -> Result<crate::projections::PassiveSourceCurrentContext, StoreError> {
        self.validated_current_read(|state, _| state.passive_source_current_context(selection))
            .await
    }

    async fn validated_current_read<T>(
        &self,
        read: impl FnOnce(
            &crate::projections::JournalAdmissionState,
            &ProjectionValidation,
        ) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.project_validated(false, false).await?;
        let result = async {
            let stamp = self
                .projection_validation
                .lock()
                .map_err(|_| StoreError::StoreCorrupt)?[0]
                .clone()
                .ok_or(StoreError::StoreCorrupt)?;
            let live = self.physical_stamp()?;
            if !(stamp.objects_bound(&live) || stamp.appended_successor_bound(&live))
                || live.frontier != self.admission_state.committed_frontier()
            {
                return Err(StoreError::StoreCorrupt);
            }
            let context = read(&self.admission_state, &stamp)?;
            if self.physical_stamp()? != live {
                return Err(StoreError::StoreCorrupt);
            }
            Ok(context)
        }
        .await;
        if result.is_err() {
            *self
                .projection_validation
                .lock()
                .map_err(|_| StoreError::StoreCorrupt)? = [None, None];
        }
        result
    }

    /// Synchronize all mandatory projections to the actual committed journal.
    /// Reserved sequence numbers are not a committed frontier. All projection
    /// validation and per-family commits must succeed before this returns.
    pub async fn sync_frontier(&self) -> Result<u64, StoreError> {
        Ok(self.project_validated(true, false).await?.0)
    }

    #[cfg(test)]
    pub(crate) fn capture_delta_selections(&self) -> u64 {
        self.capture_delta_selections
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn fused_delta_selections(&self) -> u64 {
        self.fused_delta_selections
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn project(&self) -> Result<ProjectionSnapshot, StoreError> {
        self.project_validated(true, true)
            .await?
            .1
            .ok_or(StoreError::StoreCorrupt)
    }

    fn validate_projection_directories(&self, indexes: bool) -> Result<(), StoreError> {
        self._lock.validate_held()?;
        self.lock_sqlite()?.revalidate()?;
        if indexes {
            for (path, file) in &self.projection_directories {
                let located = fs::symlink_metadata(path).map_err(|_| StoreError::StoreCorrupt)?;
                let held = file.metadata().map_err(|_| StoreError::StoreCorrupt)?;
                if !located.is_dir()
                    || located.file_type().is_symlink()
                    || (located.dev(), located.ino()) != (held.dev(), held.ino())
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
        Ok(())
    }

    async fn project_validated(
        &self,
        indexes: bool,
        return_rows: bool,
    ) -> Result<(u64, Option<ProjectionSnapshot>), StoreError> {
        let result = async {
            self.validate_projection_directories(indexes)?;
            let before = self.physical_stamp()?;
            let before_search = if indexes {
                self.search
                    .version()
                    .await
                    .map_err(|_| StoreError::LanceDb)?
            } else {
                0
            };
            let stamps = self
                .projection_validation
                .lock()
                .map_err(|_| StoreError::StoreCorrupt)?
                .clone();
            let objects = stamps[0]
                .as_ref()
                .filter(|stamp| stamp.objects_bound(&before));
            let validated_input = stamps[0]
                .as_ref()
                .filter(|stamp| stamp.appended_successor_bound(&before));
            let validated_current = validated_input.map(|stamp| {
                (
                    stamp.stamp.objects_epoch,
                    stamp.stamp.object_checkpoint,
                    before.frontier,
                )
            });
            let capture_input = validated_input.filter(|stamp| {
                indexes && !return_rows && stamp.capture_successor_bound(&before, before_search)
            });
            let all = indexes
                .then_some(stamps[1].as_ref())
                .flatten()
                .filter(|stamp| stamp.stamp == before && stamp.search_version == before_search);
            let hit = if indexes { all } else { objects };
            let (frontier, snapshot, has_failed_job, search_version, content_proven) =
                if let Some(stamp) = hit {
                    let snapshot = if return_rows {
                        Some(ProjectionSnapshot {
                            frontier: stamp.frontier,
                            rows: self.lock_sqlite()?.object_rows()?,
                        })
                    } else {
                        None
                    };
                    (
                        stamp.frontier,
                        snapshot,
                        stamp.has_failed_job,
                        stamp.search_version,
                        stamp.content_proven && (indexes || stamp.stamp == before),
                    )
                } else {
                    let capture_update = match capture_input {
                        Some(stamp) => {
                            self.projection_worker()
                                .catch_up_capture_delta(
                                    (
                                        stamp.stamp.objects_epoch,
                                        stamp.stamp.object_checkpoint,
                                        before.frontier,
                                    ),
                                    stamp
                                        .appended_rows
                                        .as_deref()
                                        .ok_or(StoreError::StoreCorrupt)?,
                                )
                                .await?
                        }
                        None => None,
                    };
                    if let Some(update) = capture_update {
                        let objects_stamp = self.physical_stamp()?;
                        if objects_stamp.objects_epoch != update.objects_epoch
                            || objects_stamp.incarnation != before.incarnation
                            || objects_stamp.journal_epoch != before.journal_epoch
                            || objects_stamp.frontier != before.frontier
                        {
                            return Err(StoreError::StoreCorrupt);
                        }
                        let versions = self
                            .l0002_projection_worker()
                            .catch_up_capture_delta(
                                update.frontier,
                                update.base_frontier,
                                &update.changed_rows,
                                update.delta,
                            )
                            .await?;
                        if self.physical_stamp()?.relations_epoch != versions[0] {
                            return Err(StoreError::StoreCorrupt);
                        }
                        let search_version = self
                            .search
                            .version()
                            .await
                            .map_err(|_| StoreError::LanceDb)?;
                        if search_version != versions[1] {
                            return Err(StoreError::StoreCorrupt);
                        }
                        let has_failed_job = crate::projections::RuntimeSchedulerView::from_rows(
                            update.frontier,
                            &update.runtime_rows,
                        )?
                        .jobs
                        .iter()
                        .any(|job| job.state == crate::JobStatus::Failed);
                        #[cfg(test)]
                        self.capture_delta_selections
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        (update.frontier, None, has_failed_job, search_version, true)
                    } else {
                        let appended =
                            validated_input.and_then(|stamp| stamp.appended_rows.as_deref());
                        let outcome = if let Some(stamp) = objects {
                            CatchUpOutcome::Complete {
                                snapshot: ProjectionSnapshot {
                                    frontier: stamp.frontier,
                                    rows: self.lock_sqlite()?.object_rows()?,
                                },
                                objects_epoch: stamp.stamp.objects_epoch,
                                delta: None,
                            }
                        } else {
                            let accumulator = (indexes && !return_rows)
                                .then(|| Box::new(crate::query::L0002RowAccumulator::default()));
                            self.projection_worker()
                                .catch_up_inner(false, validated_current, appended, accumulator)
                                .await?
                        };
                        let objects_epoch = match &outcome {
                            CatchUpOutcome::Complete { objects_epoch, .. }
                            | CatchUpOutcome::Consumed { objects_epoch, .. } => *objects_epoch,
                        };
                        let objects_stamp = self.physical_stamp()?;
                        if objects_stamp.objects_epoch != objects_epoch
                            || objects_stamp.incarnation != before.incarnation
                            || objects_stamp.journal_epoch != before.journal_epoch
                            || objects_stamp.frontier != before.frontier
                        {
                            return Err(StoreError::StoreCorrupt);
                        }
                        match outcome {
                            CatchUpOutcome::Complete {
                                snapshot, delta, ..
                            } => {
                                let (search_version, content_proven) = if indexes {
                                    let (_, versions, derived) = self
                                        .l0002_projection_worker()
                                        .catch_up_validated_proof(&snapshot, delta)
                                        .await?;
                                    (self.check_l0002_versions(versions).await?, derived)
                                } else {
                                    (0, false)
                                };
                                let has_failed_job =
                                    crate::projections::RuntimeSchedulerView::from_snapshot(
                                        &snapshot,
                                    )?
                                    .jobs
                                    .iter()
                                    .any(|job| job.state == crate::JobStatus::Failed);
                                (
                                    snapshot.frontier,
                                    return_rows.then_some(snapshot),
                                    has_failed_job,
                                    search_version,
                                    content_proven,
                                )
                            }
                            CatchUpOutcome::Consumed {
                                frontier,
                                delta,
                                runtime_rows,
                                l0002,
                                ..
                            } => {
                                #[cfg(test)]
                                self.fused_delta_selections
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let (versions, derived) = self
                                    .l0002_projection_worker()
                                    .catch_up_fused_handoff(frontier, Some(delta), l0002)
                                    .await?;
                                let search_version = self.check_l0002_versions(versions).await?;
                                let has_failed_job =
                                    crate::projections::RuntimeSchedulerView::from_rows(
                                        frontier,
                                        &runtime_rows,
                                    )?
                                    .jobs
                                    .iter()
                                    .any(|job| job.state == crate::JobStatus::Failed);
                                (frontier, None, has_failed_job, search_version, derived)
                            }
                        }
                    }
                };
            self.validate_projection_directories(indexes)?;
            let after = self.physical_stamp()?;
            if after.incarnation != before.incarnation
                || after.data_version != before.data_version
                || after.frontier != before.frontier
                || after.journal_epoch != before.journal_epoch
            {
                return Err(StoreError::StoreCorrupt);
            }
            let search_version = if indexes {
                self.search
                    .version()
                    .await
                    .map_err(|_| StoreError::LanceDb)?
            } else {
                search_version
            };
            {
                let stamp = Some(ProjectionValidation {
                    stamp: after,
                    search_version,
                    frontier,
                    has_failed_job,
                    content_proven,
                    appended_through: None,
                    appended_rows: None,
                });
                let mut stamps = self
                    .projection_validation
                    .lock()
                    .map_err(|_| StoreError::StoreCorrupt)?;
                stamps[0] = stamp.clone();
                if indexes {
                    stamps[1] = stamp;
                } else if stamps[1]
                    .as_ref()
                    .is_some_and(|stamp| !stamp.objects_bound(&after))
                {
                    stamps[1] = None;
                }
            }
            Ok((frontier, snapshot))
        }
        .await;
        if result.is_err() {
            *self
                .projection_validation
                .lock()
                .map_err(|_| StoreError::StoreCorrupt)? = [None, None];
        }
        result
    }

    async fn check_l0002_versions(&self, versions: [u64; 2]) -> Result<u64, StoreError> {
        if self.physical_stamp()?.relations_epoch != versions[0] {
            return Err(StoreError::StoreCorrupt);
        }
        let search_version = self
            .search
            .version()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        if search_version != versions[1] {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(search_version)
    }

    pub async fn reconciliation_frontier(
        &self,
        limit: usize,
    ) -> Result<ReconciliationFrontier, StoreError> {
        self.project_objects().await?.reconciliation_frontier(limit)
    }

    pub async fn reconciliation_artifact_context(
        &self,
        descriptors: &[ReconciliationArtifactDescriptor],
        limit: usize,
    ) -> Result<ReconciliationArtifactFrontier, StoreError> {
        self.project_objects()
            .await?
            .reconciliation_artifact_context(descriptors, limit)
    }

    pub async fn full_projection(&self) -> Result<ProjectionSnapshot, StoreError> {
        ProjectionWorker::new(Arc::clone(&self.sqlite))
            .full_snapshot()
            .await
    }

    pub async fn journal_rows(&self) -> Result<Vec<crate::JournalRow>, StoreError> {
        self.lock_sqlite()?.rows()
    }

    pub async fn project_at_frontier(
        &self,
        frontier: u64,
    ) -> Result<ProjectionSnapshot, StoreError> {
        self.projection_worker().project_at_frontier(frontier).await
    }

    pub async fn mark_gc(
        &self,
        runtime: &evertrace_capture::RuntimeSnapshot,
        shard: u8,
    ) -> Result<crate::optimize::GcRound, StoreError> {
        Ok(self
            .mark_gc_page(runtime, evertrace_capture::cas::CasGcCursor::new(shard))
            .await?
            .round)
    }

    pub async fn mark_gc_page(
        &self,
        runtime: &evertrace_capture::RuntimeSnapshot,
        mut cursor: evertrace_capture::cas::CasGcCursor,
    ) -> Result<crate::optimize::GcScanPage, StoreError> {
        if runtime.data_dir().map_err(|_| StoreError::InvalidInput)? != self._lock.data_dir() {
            return Err(StoreError::InvalidInput);
        }
        self._lock.validate_held()?;
        let guard = evertrace_capture::MaintenanceFence::open(self._lock.data_dir())
            .and_then(|fence| fence.exclusive())
            .map_err(|_| StoreError::Io)?;
        let cas = evertrace_capture::CasStore::open_existing(runtime.cas_dir.clone())
            .map_err(|_| StoreError::StoreCorrupt)?;
        let candidates = cas
            .gc_candidates(
                &guard,
                &mut cursor,
                crate::optimize::GC_MAX_FILES,
                crate::optimize::GC_MAX_BYTES,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
        drop(guard);
        cas.verify_gc_candidates(&candidates)
            .map_err(|_| StoreError::StoreCorrupt)?;
        let ids = candidates
            .iter()
            .map(|candidate| candidate.digest.as_hex())
            .collect();
        let authority = self.gc_authority(runtime, &ids).await?;
        self._lock.validate_held()?;
        let guard = evertrace_capture::MaintenanceFence::open(self._lock.data_dir())
            .and_then(|fence| fence.exclusive())
            .map_err(|_| StoreError::Io)?;
        authority.revalidate(self._lock.data_dir())?;
        evertrace_capture::CasStore::validate_gc_candidates(&guard, &candidates)
            .map_err(|_| StoreError::StoreCorrupt)?;
        let mut references = authority.references;
        references.extend(self.gc_spool_references(runtime, &ids)?);
        Ok(crate::optimize::GcScanPage {
            cursor,
            round: crate::optimize::GcRound::mark(
                candidates,
                &references,
                self.frontier(),
                std::time::Instant::now(),
            ),
        })
    }

    pub async fn historical_cas_refs_intersect(
        &self,
        candidates: &std::collections::BTreeSet<String>,
    ) -> Result<std::collections::BTreeSet<String>, StoreError> {
        crate::optimize::historical_cas_refs(&self.sqlite, self.frontier(), candidates).await
    }

    pub async fn sweep_gc(
        &self,
        runtime: &evertrace_capture::RuntimeSnapshot,
        job_id: evertrace_domain::ids::JobId,
        round: &crate::optimize::GcRound,
    ) -> Result<crate::optimize::GcReport, StoreError> {
        if runtime.data_dir().map_err(|_| StoreError::InvalidInput)? != self._lock.data_dir() {
            return Err(StoreError::InvalidInput);
        }
        self._lock.validate_held()?;
        let ids = round.candidates();
        let authority = self.gc_authority(runtime, &ids).await?;
        self._lock.validate_held()?;
        let guard = evertrace_capture::MaintenanceFence::open(self._lock.data_dir())
            .and_then(|fence| fence.exclusive())
            .map_err(|_| StoreError::Io)?;
        authority.revalidate(self._lock.data_dir())?;
        let mut references = authority.references;
        references.extend(self.gc_spool_references(runtime, &ids)?);
        let candidates = round.sweep_candidates(&guard, &references, std::time::Instant::now())?;
        let report = crate::optimize::delete_and_report(
            self._lock.data_dir(),
            &guard,
            job_id,
            round,
            &candidates,
            self.frontier(),
        )?;
        drop(guard);
        self._lock.validate_held()?;
        crate::optimize::conservative_prune(self._lock.data_dir(), &self.search, report).await
    }

    pub(crate) async fn gc_authority(
        &self,
        runtime: &evertrace_capture::RuntimeSnapshot,
        candidates: &std::collections::BTreeSet<String>,
    ) -> Result<GcAuthority, StoreError> {
        if runtime.data_dir().map_err(|_| StoreError::InvalidInput)? != self._lock.data_dir() {
            return Err(StoreError::InvalidInput);
        }
        let mut refs = self.historical_cas_refs_intersect(candidates).await?;
        refs.extend(self.project().await?.live_cas_refs_intersect(candidates)?);
        let mut authority = GcAuthority {
            references: refs,
            backup_root: None,
            backup_names: Vec::new(),
            backups: Vec::new(),
        };
        let backups = self._lock.data_dir().join("backups");
        let backups_present = match std::fs::symlink_metadata(&backups) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(StoreError::Io),
        };
        if backups_present {
            let root = evertrace_capture::confined_read::ConfinedRoot::open_owned_private(&backups)
                .map_err(|_| StoreError::StoreCorrupt)?;
            let entries = root
                .list_directory(
                    None,
                    64,
                    std::time::Instant::now() + std::time::Duration::from_secs(5),
                )
                .map_err(|_| StoreError::StoreCorrupt)?;
            for entry in entries {
                let id = entry
                    .name
                    .strip_prefix("backup-")
                    .ok_or(StoreError::StoreCorrupt)?
                    .parse()
                    .map_err(|_| StoreError::StoreCorrupt)?;
                let verification =
                    crate::backup::prepare_backup_verification(self._lock.data_dir(), id)
                        .map_err(|_| StoreError::StoreCorrupt)?;
                crate::backup::complete_backup_verification_ref(&verification)
                    .await
                    .map_err(|_| StoreError::StoreCorrupt)?;
                authority
                    .references
                    .extend(verification.cas_refs_intersect(candidates));
                authority.backup_names.push(entry.name);
                authority.backups.push(verification);
            }
            root.revalidate_stable()
                .map_err(|_| StoreError::StoreCorrupt)?;
            authority.backup_root = Some(root);
        }
        Ok(authority)
    }

    fn gc_spool_references(
        &self,
        runtime: &evertrace_capture::RuntimeSnapshot,
        candidates: &std::collections::BTreeSet<String>,
    ) -> Result<std::collections::BTreeSet<String>, StoreError> {
        let limits = runtime
            .spool_limits()
            .map_err(|_| StoreError::InvalidInput)?;
        let spool =
            evertrace_capture::DurableSpool::open_read_only(runtime.spool_dir.clone(), limits)
                .map_err(|_| StoreError::StoreCorrupt)?;
        spool
            .gc_cas_refs_intersect(
                candidates,
                limits.max_main_files as usize,
                limits.high_watermark_bytes,
            )
            .map_err(|_| StoreError::StoreCorrupt)
    }

    pub async fn object_rows(&self) -> Result<Vec<crate::ObjectRow>, StoreError> {
        self.lock_sqlite()?.object_rows()
    }

    pub async fn relation_rows(&self) -> Result<Vec<crate::RelationProjectionRow>, StoreError> {
        self.lock_sqlite()?.relation_rows()
    }

    pub async fn search_rows(&self) -> Result<Vec<crate::SearchProjectionRow>, StoreError> {
        crate::read_search_rows(&self.search).await
    }

    /// The retired three Lance tables are gone; the native connection only
    /// serves the search projection.
    pub async fn table_names(&self) -> Result<Vec<String>, StoreError> {
        self.connection
            .table_names()
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)
    }
}

impl ClosedJournalWriter {
    pub fn stage_backup(
        self,
        config_path: PathBuf,
        runtime: evertrace_capture::RuntimeSnapshot,
        backup_job_id: evertrace_domain::ids::JobId,
        snapshot: ProjectionSnapshot,
        table_states: crate::BackupTableStates,
        boundary: crate::backup::BackupFrozenBoundary,
    ) -> (
        Self,
        Result<crate::backup::BackupStaging, crate::BackupError>,
    ) {
        if self.lock.validate_held().is_err() {
            return (self, Err(crate::BackupError::IdentityChanged));
        }
        let data_dir = match runtime.data_dir() {
            Ok(data_dir) => data_dir.to_owned(),
            Err(_) => return (self, Err(crate::BackupError::InvalidInput)),
        };
        let result = crate::backup::prepare_backup(
            (&data_dir, &crate::connection::native_root(&data_dir)),
            (&config_path, &runtime),
            backup_job_id,
            &snapshot,
            table_states,
            crate::backup::BackupShape::Current,
            boundary,
        )
        .and_then(crate::backup::stage_backup);
        if self.lock.validate_held().is_err() {
            if let Ok(staging) = &result {
                let _ = crate::backup::discard_backup(staging);
            }
            return (self, Err(crate::BackupError::IdentityChanged));
        }
        (self, result)
    }

    pub async fn verify_staged_backup(
        &self,
        staging: &crate::backup::BackupStaging,
    ) -> Result<crate::BackupSummary, crate::BackupError> {
        if self.lock.validate_held().is_err() {
            return Err(crate::BackupError::IdentityChanged);
        }
        let result = crate::backup::verify_staged_backup(staging).await;
        if self.lock.validate_held().is_err() {
            return Err(crate::BackupError::IdentityChanged);
        }
        result
    }

    pub fn publish_staged_backup(
        self,
        staging: crate::backup::BackupStaging,
        summary: crate::BackupSummary,
    ) -> (Self, Result<crate::BackupSummary, crate::BackupError>) {
        if self.lock.validate_held().is_err() {
            return (self, Err(crate::BackupError::IdentityChanged));
        }
        let result = crate::backup::publish_backup(staging, summary);
        if self.lock.validate_held().is_err() {
            return (self, Err(crate::BackupError::IdentityChanged));
        }
        (self, result)
    }

    pub fn discard_staged_backup(
        &self,
        staging: &crate::backup::BackupStaging,
    ) -> Result<(), crate::backup::BackupError> {
        crate::backup::discard_backup(staging)
    }

    pub async fn reopen(mut self) -> Result<JournalWriter, StoreError> {
        let writer = JournalWriter::open_with_lock(self.lock, self.readers.clone()).await?;
        drop(self.guard.take());
        Ok(writer)
    }

    pub(crate) async fn open_restore_candidate(
        mut self,
        candidate: &Path,
    ) -> Result<JournalWriter, StoreError> {
        self.lock.validate_held()?;
        if candidate.parent() != self.lock.data_dir.parent() {
            return Err(StoreError::InvalidPath);
        }
        crate::connection::prepare_native_root(candidate)?;
        // The candidate is a different directory: it gets its own read binding
        // rooted at the candidate path. The live handle stays revoked, so no
        // reader can observe candidate rows under the live root identity.
        let readers = StoreReadHandle::open(candidate);
        let writer = JournalWriter::open_at_with_lock(self.lock, candidate, readers).await?;
        drop(self.guard.take());
        Ok(writer)
    }
}

/// The retired physical layouts accepted by the one-shot offline converter.
/// The caller owns the candidate custody and the original sibling lock; this
/// type never grants access to a live store.
pub(crate) enum LegacyCandidate {
    /// `<root>/store/` is the native directory (offline restore copy layout).
    StateRoot(PathBuf),
    /// The directory itself is the native directory (upgrade candidate).
    Native(PathBuf),
}

impl LegacyCandidate {
    fn open_state(&self) -> Result<SqliteState, StoreError> {
        match self {
            Self::StateRoot(root) => SqliteState::open(root),
            Self::Native(native) => SqliteState::open_native(native),
        }
    }

    fn native_dir(&self) -> PathBuf {
        match self {
            Self::StateRoot(root) => crate::connection::native_root(root),
            Self::Native(native) => native.clone(),
        }
    }
}

/// Import one already-validated retired journal into a fresh candidate SQLite
/// database, retire the copied old tables, then run the approved L0002
/// migration/rebuild/FTS. This is the only bypass of writer admission and it is
/// crate-private to the offline converter; it never renumbers markers or seq.
pub(crate) async fn bootstrap_legacy_candidate(
    candidate: &LegacyCandidate,
    custody: &evertrace_capture::ConfinedRoot,
    rows: &[JournalRow],
) -> Result<(), StoreError> {
    validate_journal_rows(rows)?;
    let batches = ordered_legacy_commands(rows)?;
    for batch in &batches {
        validate_complete_command(batch)?;
    }
    JournalAdmissionState::from_journal_rows(rows)?;
    let native = candidate.native_dir();
    let mut state = candidate.open_state()?;
    for batch in &batches {
        state.append_command_rows(batch)?;
    }
    if state.rows()? != rows {
        return Err(StoreError::StoreCorrupt);
    }
    if !state.checkpoint_and_close()? {
        return Err(StoreError::Io);
    }
    drop(state);
    retire_legacy_tables(&native, custody)?;
    let connection = lancedb::connect(native.to_str().ok_or(StoreError::InvalidPath)?)
        .session(crate::connection::native_session())
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let state = candidate.open_state()?;
    let handle = state.handle();
    crate::migrations::L0002::apply(&handle, &connection).await?;
    let mut state = Arc::try_unwrap(handle)
        .map_err(|_| StoreError::Io)?
        .into_inner()
        .map_err(|_| StoreError::StoreCorrupt)?;
    if !state.has_open_connection() || !state.checkpoint_and_close()? {
        return Err(StoreError::Io);
    }
    Ok(())
}

fn ordered_legacy_commands(rows: &[JournalRow]) -> Result<Vec<Vec<JournalRow>>, StoreError> {
    let mut by_command: BTreeMap<evertrace_domain::ids::CommandId, Vec<&JournalRow>> =
        BTreeMap::new();
    for row in rows {
        by_command.entry(row.command_id).or_default().push(row);
    }
    let mut batches = Vec::with_capacity(by_command.len());
    for mut batch in by_command.into_values() {
        batch.sort_by_key(|row| row.ordinal);
        let first = batch
            .first()
            .map(|row| row.seq)
            .ok_or(StoreError::StoreCorrupt)?;
        if batch
            .iter()
            .enumerate()
            .any(|(index, row)| row.seq != first + index as u64)
        {
            return Err(StoreError::StoreCorrupt);
        }
        batches.push(batch.into_iter().cloned().collect::<Vec<_>>());
    }
    batches.sort_by_key(|batch| batch.first().map(|row| row.seq).unwrap_or(0));
    Ok(batches)
}

/// Remove only the retired tables copied into this candidate. Every path is
/// revalidated through its own held directory; nothing is guessed by name.
fn retire_legacy_tables(
    native: &Path,
    custody: &evertrace_capture::ConfinedRoot,
) -> Result<(), StoreError> {
    custody
        .revalidate_stable()
        .map_err(|_| StoreError::StoreCorrupt)?;
    for name in [
        crate::JOURNAL_TABLE,
        crate::OBJECTS_TABLE,
        crate::RELATIONS_TABLE,
    ] {
        let path = native.join(format!("{name}.lance"));
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(StoreError::StoreCorrupt);
                }
                let table = evertrace_capture::ConfinedRoot::open_owned_private(&path)
                    .map_err(|_| StoreError::StoreCorrupt)?;
                table
                    .revalidate_stable()
                    .map_err(|_| StoreError::StoreCorrupt)?;
                let held = table.proc_cwd_path().map_err(|_| StoreError::Io)?;
                for entry in std::fs::read_dir(&held).map_err(|_| StoreError::Io)? {
                    let entry = entry.map_err(|_| StoreError::Io)?;
                    let metadata =
                        std::fs::symlink_metadata(entry.path()).map_err(|_| StoreError::Io)?;
                    if metadata.is_dir() && !metadata.file_type().is_symlink() {
                        std::fs::remove_dir_all(entry.path()).map_err(|_| StoreError::Io)?;
                    } else {
                        std::fs::remove_file(entry.path()).map_err(|_| StoreError::Io)?;
                    }
                }
                std::fs::remove_dir(&path).map_err(|_| StoreError::Io)?;
                File::open(native)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| StoreError::Io)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Io),
        }
    }
    custody
        .revalidate_stable()
        .map_err(|_| StoreError::StoreCorrupt)
}

pub(crate) fn journal_profile(
    rows: &[crate::JournalRow],
) -> Result<Option<&'static str>, StoreError> {
    let populated = !rows.is_empty();
    let mut profile = None;
    for row in rows {
        if let JournalPayload::MigrationApplied(migration) = row.payload()? {
            match migration.migration_id.as_str() {
                "L0001" if profile.is_none() => profile = Some("L0001"),
                "L0002" if profile == Some("L0001") => profile = Some("L0002"),
                _ => return Err(StoreError::StoreCorrupt),
            }
        }
    }
    if populated && profile.is_none() {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(profile)
}

fn reserve_range(next_seq: &mut u64, count: u16) -> Result<u64, StoreError> {
    if count == 0 {
        return Err(StoreError::InvalidInput);
    }
    let first = *next_seq;
    *next_seq = next_seq
        .checked_add(u64::from(count))
        .ok_or(StoreError::StoreCorrupt)?;
    Ok(first)
}

fn validate_lexical_data_dir(path: &Path) -> Result<(), StoreError> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(StoreError::InvalidPath);
    }
    Ok(())
}

fn validate_parent(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StoreError::InvalidType);
    }
    Ok(())
}

fn ensure_data_root(path: &Path, parent: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_data_root_metadata(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder
                .mode(0o700)
                .create(path)
                .map_err(|_| StoreError::Io)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| StoreError::Io)?;
            validate_data_root_metadata(&fs::symlink_metadata(path).map_err(|_| StoreError::Io)?)
        }
        Err(_) => Err(StoreError::Io),
    }
}

fn validate_data_root_metadata(metadata: &fs::Metadata) -> Result<(), StoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StoreError::InvalidType);
    }
    if metadata.uid() != current_uid()? {
        return Err(StoreError::WrongOwner);
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(StoreError::InvalidPermissions);
    }
    Ok(())
}

fn sibling_lock_path(data_dir: &Path) -> Result<PathBuf, StoreError> {
    let parent = data_dir.parent().ok_or(StoreError::InvalidPath)?;
    let mut name = OsString::from(data_dir.file_name().ok_or(StoreError::InvalidPath)?);
    name.push(".writer.lock");
    Ok(parent.join(name))
}

fn validate_lock_metadata(metadata: &fs::Metadata) -> Result<(), StoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StoreError::InvalidType);
    }
    if metadata.uid() != current_uid()? {
        return Err(StoreError::WrongOwner);
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(StoreError::InvalidPermissions);
    }
    Ok(())
}

fn validate_lock_identity(path: &Path, file: &File) -> Result<(), StoreError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| StoreError::Io)?;
    let file_metadata = file.metadata().map_err(|_| StoreError::Io)?;
    validate_lock_metadata(&path_metadata)?;
    validate_lock_metadata(&file_metadata)?;
    if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino() {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn current_uid() -> Result<u32, StoreError> {
    fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .map_err(|_| StoreError::Io)
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use evertrace_domain::{
        evidence::{IdentityStrength, SourceInstanceId, SourceRevision},
        ids::{CaptureReceiptId, CommandId, ExecutionLaneId, RepositoryId},
        repository::{FilesystemIdentity, GitObjectFormat, PathObservation, RepositoryInstance},
        work::{
            AdmissionFailureObservability, CaptureReceipt, CoverageLevel, ExecutionLane,
            LaneStatus, LivenessState, OrderingIntegrity, PairingIntegrity, PayloadIntegrity,
            SourceCoverage,
        },
    };

    use super::*;
    use crate::{
        DirtyTarget, DirtyTargetKind, JournalEventDraft, JournalPayload, SourceCloseRange,
        SourceCloseReconciliation, reduce_journal,
    };

    /// The single SQLite state replaces the former Lance journal. This view
    /// mirrors `StartupJournal`: it binds the validated rows to the observed
    /// physical journal epoch and revalidates identity, structural
    /// completeness and (when required) admission on refresh.
    struct StartupJournal {
        sqlite: SqliteHandle,
        rows: Vec<crate::JournalRow>,
        version: u64,
        requires_admission_validation: bool,
    }

    impl StartupJournal {
        fn read(sqlite: SqliteHandle) -> Result<Self, StoreError> {
            let (rows, version) = {
                let mut state = sqlite.lock().map_err(|_| StoreError::StoreCorrupt)?;
                let rows = state.rows()?;
                let version = state.stamp()?.journal_epoch;
                (rows, version)
            };
            crate::journal::validate_journal_rows(&rows)?;
            Ok(Self {
                sqlite,
                rows,
                version,
                requires_admission_validation: false,
            })
        }

        async fn refresh(&mut self) -> Result<(), StoreError> {
            let mut state = self.sqlite.lock().map_err(|_| StoreError::StoreCorrupt)?;
            state.revalidate()?;
            let version = state.stamp()?.journal_epoch;
            if version != self.version {
                let rows = state.rows()?;
                crate::journal::validate_journal_rows(&rows)?;
                if self.requires_admission_validation {
                    drop(JournalAdmissionState::from_journal_rows(&rows)?);
                }
                self.rows = rows;
                self.version = version;
            }
            Ok(())
        }
    }

    impl JournalWriter {
        fn journal_profile(
            startup: &mut StartupJournal,
        ) -> Result<Option<&'static str>, StoreError> {
            drop(JournalAdmissionState::from_journal_rows(&startup.rows)?);
            startup.requires_admission_validation = true;
            super::journal_profile(&startup.rows)
        }
    }

    async fn read_journal_frontier(sqlite: &SqliteHandle) -> Result<u64, StoreError> {
        Ok(sqlite
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?
            .rows()?
            .last()
            .map(|row| row.seq)
            .unwrap_or(0))
    }

    async fn append_rows(
        sqlite: &SqliteHandle,
        rows: &[crate::JournalRow],
    ) -> Result<(), StoreError> {
        sqlite
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?
            .append_rows_for_test(rows)
    }

    async fn overwrite_rows(
        sqlite: &SqliteHandle,
        rows: &[crate::JournalRow],
    ) -> Result<(), StoreError> {
        sqlite
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?
            .overwrite_rows_for_test(rows)
    }

    async fn read_command_rows(
        sqlite: &SqliteHandle,
        command_id: CommandId,
    ) -> Result<Vec<crate::JournalRow>, StoreError> {
        sqlite
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?
            .committed_rows(command_id)
    }

    async fn clear_object_rows(sqlite: &SqliteHandle) -> Result<(), StoreError> {
        sqlite
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?
            .clear_object_rows_for_test()
    }

    async fn insert_object_row(sqlite: &SqliteHandle, row: &ObjectRow) -> Result<(), StoreError> {
        sqlite
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?
            .insert_object_row_for_test(row)
    }

    fn validation_versions(validation: &ProjectionValidation) -> [u64; 4] {
        [
            validation.stamp.journal_epoch,
            validation.stamp.objects_epoch,
            validation.stamp.relations_epoch,
            validation.search_version,
        ]
    }

    async fn projection_versions(writer: &JournalWriter) -> Result<[u64; 4], StoreError> {
        let stamp = {
            let handle = writer.projection_handle();
            let mut state = handle.lock().map_err(|_| StoreError::StoreCorrupt)?;
            state.stamp()?
        };
        Ok([
            stamp.journal_epoch,
            stamp.objects_epoch,
            stamp.relations_epoch,
            writer
                .search
                .version()
                .await
                .map_err(|_| StoreError::LanceDb)?,
        ])
    }

    #[tokio::test]
    async fn startup_admission_failure_precedes_missing_objects_repair() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let writer = JournalWriter::open(&root).await.unwrap();
        let mut startup = StartupJournal::read(writer.projection_handle()).unwrap();
        assert_eq!(
            JournalWriter::journal_profile(&mut startup),
            Ok(Some("L0002"))
        );
        let (lane, _) = capture_pair(
            ExecutionLaneId::new_v7(),
            CaptureReceiptId::new_v7(),
            1,
            None,
        );
        let command = capture_command("01890f47-6a4a-7cc1-98b9-01890f476a82", lane, None);
        let rows =
            rows_for_append(&prepare_command(&command).unwrap(), writer.next_seq, 0).unwrap();
        // This command is structurally complete, but its required receipt is
        // missing. Only admission replay detects the corruption.
        crate::journal::validate_journal_rows(&rows).unwrap();
        append_rows(&writer.projection_handle(), &rows)
            .await
            .unwrap();
        // Revalidation must still reject semantic corruption after the
        // precheck's temporary admission state has been released.
        assert_eq!(startup.refresh().await, Err(StoreError::StoreCorrupt));
        drop(startup);
        let journal_before = writer.journal_rows().await.unwrap();
        // The former test renamed the objects table away so a repair would
        // have to rebuild it. Objects now live in the same SQLite file, so the
        // analogue is clearing the persisted objects family.
        clear_object_rows(&writer.projection_handle())
            .await
            .unwrap();
        drop(writer);
        assert!(matches!(
            JournalWriter::open(&root).await,
            Err(StoreError::StoreCorrupt)
        ));
        // Nothing was repaired: the journal did not gain a migration row and
        // the objects family was not projected to the corrupt frontier.
        let state = SqliteState::open(&root).unwrap();
        assert_eq!(state.rows().unwrap(), journal_before);
        assert_eq!(state.object_checkpoint_row().unwrap(), Some((0, 1)));
        assert_eq!(state.object_rows().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn projection_stamp_rejects_replaced_native_directory_with_same_versions() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let writer = JournalWriter::open(&root).await.unwrap();
        let mut startup = StartupJournal::read(writer.projection_handle()).unwrap();
        writer.sync_frontier().await.unwrap();
        assert!(writer.projection_validation.lock().unwrap()[1].is_some());
        assert_eq!(
            writer.read_diagnostics().await.tables[0].checkpoint,
            Some(writer.frontier())
        );
        let versions = projection_versions(&writer).await.unwrap();
        let native = crate::connection::native_root(&root);
        let moved = root.join("previous-store");
        fs::rename(&native, &moved).unwrap();
        DirBuilder::new().mode(0o700).create(&native).unwrap();
        // Reuse the very same derived search directory under a new root and
        // copy the SQLite database byte-for-byte: identity must still reject it.
        let search = format!("{SEARCH_TABLE}.lance");
        fs::rename(moved.join(&search), native.join(search)).unwrap();
        let database = native.join(crate::sqlite_state::SQLITE_FILE_NAME);
        fs::copy(moved.join(crate::sqlite_state::SQLITE_FILE_NAME), &database).unwrap();
        assert_eq!(
            fs::read(&database).unwrap(),
            fs::read(moved.join(crate::sqlite_state::SQLITE_FILE_NAME)).unwrap()
        );
        assert_eq!(writer.search.version().await.unwrap(), versions[3]);
        // Identity binding, not content or version reuse, is the authority
        // every validated path checks.
        assert_eq!(
            writer.projection_handle().lock().unwrap().revalidate(),
            Err(StoreError::StoreCorrupt)
        );
        assert_eq!(startup.refresh().await, Err(StoreError::StoreCorrupt));
        // A valid in-memory stamp alone must not authorize normal Search after
        // the held native root has been replaced with same-content state.
        assert!(matches!(
            writer
                .normal_search_current_context(&Default::default())
                .await,
            Err(StoreError::StoreCorrupt)
        ));
        assert!(matches!(
            writer.reconciliation_frontier(8).await,
            Err(StoreError::StoreCorrupt)
        ));
        assert!(matches!(
            writer.reconciliation_artifact_context(&[], 8).await,
            Err(StoreError::StoreCorrupt)
        ));
        assert_eq!(writer.sync_frontier().await, Err(StoreError::StoreCorrupt));
        assert!(matches!(
            writer.capture_current_context(None, None, 8).await,
            Err(StoreError::StoreCorrupt)
        ));
        assert!(
            writer
                .scope_current_context(&Default::default())
                .await
                .is_err()
        );
        assert!(
            writer
                .passive_source_current_context(&crate::PassiveSourceSelection::Session(
                    "missing".into()
                ))
                .await
                .is_err()
        );
        assert!(
            writer
                .projection_validation
                .lock()
                .unwrap()
                .iter()
                .all(Option::is_none)
        );
        assert_eq!(
            writer.project_objects().await,
            Err(StoreError::StoreCorrupt)
        );
        // Even the stamp entry point must reject the replaced root, rather
        // than exposing the old connection's epochs as reusable proof.
        assert_eq!(
            projection_versions(&writer).await,
            Err(StoreError::StoreCorrupt)
        );
    }

    #[tokio::test]
    async fn diagnostics_read_existing_tables_without_repair() {
        let temp = tempfile::tempdir().unwrap();
        let writer = JournalWriter::open(&temp.path().join("data"))
            .await
            .unwrap();
        let before = writer.backup_table_states().await.unwrap();
        let read = writer.read_diagnostics().await;
        assert!(
            read.tables
                .iter()
                .all(|table| table.schema_matches == Some(true))
        );
        assert_eq!(read.fts_index_present, Some(true));
        assert!(read.objects.is_some());
        assert_eq!(writer.backup_table_states().await.unwrap(), before);
        writer.sync_frontier().await.unwrap();
        assert!(writer.projection_validation.lock().unwrap()[1].is_some());
        let index = writer.search.list_indices().await.unwrap().remove(0);
        writer.search.drop_index(&index.name).await.unwrap();
        assert_eq!(
            writer.read_diagnostics().await.fts_index_present,
            Some(false)
        );
        // Corrupt only this disposable derived checkpoint; diagnostics must not rebuild it.
        writer.search.delete("true").await.unwrap();
        assert!(writer.sync_frontier().await.is_err());
        assert!(
            writer
                .projection_validation
                .lock()
                .unwrap()
                .iter()
                .all(Option::is_none)
        );
        let version = writer.search.version().await.unwrap();
        let read = writer.read_diagnostics().await;
        assert_eq!(read.tables[3].checkpoint, None);
        assert_eq!(writer.search.version().await.unwrap(), version);
        assert!(
            crate::search::read_search_checkpoint(&writer.search)
                .await
                .is_err()
        );
        // Human object reads still validate objects, without repairing indexes.
        let objects = writer.project_objects().await.unwrap();
        assert_eq!(objects.frontier, writer.frontier());
        assert_eq!(writer.search.version().await.unwrap(), version);
        // A checkpoint advanced without a matching projection is the objects
        // analogue of the disposable search checkpoint above: diagnostics must
        // report it from the existing family without rebuilding it, while
        // every validated read fails closed on the logical gap.
        let checkpoint = writer
            .object_rows()
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.row_id == crate::objects::OBJECTS_CHECKPOINT_ID)
            .unwrap();
        writer
            .projection_handle()
            .lock()
            .unwrap()
            .advance_object_checkpoint_for_test()
            .unwrap();
        let read = writer.read_diagnostics().await;
        assert_eq!(read.tables[1].checkpoint, Some(objects.frontier + 1));
        assert!(read.objects.is_some());
        assert_eq!(
            writer.sync_objects_frontier().await,
            Err(StoreError::StoreCorrupt)
        );
        assert_eq!(
            writer
                .projection_handle()
                .lock()
                .unwrap()
                .object_checkpoint()
                .0,
            objects.frontier + 1
        );
        // Put the checkpoint back so the malformed-row case starts from a
        // consistent family.
        insert_object_row(&writer.projection_handle(), &checkpoint)
            .await
            .unwrap();
        // The former test appended an unvalidated Arrow row that normalized to
        // generation 0. The SQLite table accepts the same unvalidated shape
        // through a raw upsert, and validation must reject it on read.
        let mut malformed = ObjectRow::checkpoint(0, 1);
        malformed.row_id = "diagnostic:malformed".into();
        malformed.row_kind = crate::objects::ObjectRowKind::Data;
        malformed.row_class = Some(crate::objects::ObjectRowClass::Runtime);
        malformed.payload_json = Some("{}".into());
        malformed.projection_generation = 0;
        insert_object_row(&writer.projection_handle(), &malformed)
            .await
            .unwrap();
        let read = writer.read_diagnostics().await;
        assert_eq!(read.tables[1].checkpoint, Some(objects.frontier));
        assert!(read.objects.is_none());
        clear_object_rows(&writer.projection_handle())
            .await
            .unwrap();
        assert!(writer.project_objects().await.is_err());
    }

    fn capture_pair(
        lane_id: ExecutionLaneId,
        receipt_id: CaptureReceiptId,
        lane_revision: u32,
        predecessor_receipt: Option<CaptureReceiptId>,
    ) -> (ExecutionLane, CaptureReceipt) {
        let lane = ExecutionLane {
            execution_lane_id: lane_id,
            lane_revision,
            predecessor_revision: lane_revision.checked_sub(1).filter(|_| lane_revision > 1),
            host_session_id: "session-a".into(),
            agent_id: "agent-a".into(),
            host_lane_key: "lane-a".into(),
            incarnation_ref: "incarnation-a".into(),
            parent_lane_id: None,
            parent_host_lane_key: None,
            spawn_event_ref: Some("spawn-a".into()),
            terminal_event_ref: None,
            termination_evidence_refs: Vec::new(),
            delegated_goal_ref: None,
            delegated_target_refs: Vec::new(),
            delegated_acceptance_refs: Vec::new(),
            status: LaneStatus::Active,
            terminal_kind: None,
            liveness_state: LivenessState::Live,
            liveness_probe_refs: Vec::new(),
            finalized: false,
            event_watermark: 0,
            adapter_manifest_ids: vec!["manifest-a".into()],
            active_capture_receipt_revision_id: receipt_id,
            coverage_level: CoverageLevel::Opaque,
            source_coverage: SourceCoverage::Open,
            pairing_integrity: PairingIntegrity::Unavailable,
            payload_integrity: PayloadIntegrity::Unavailable,
            ordering_integrity: OrderingIntegrity::Unavailable,
            reasoning_visibility: Vec::new(),
            operation_ids: Vec::new(),
            correction_reason: None,
        };
        let receipt = CaptureReceipt {
            capture_receipt_revision_id: receipt_id,
            execution_lane_id: lane_id,
            predecessor_revision_id: predecessor_receipt,
            adapter_manifest_ids: vec!["manifest-a".into()],
            eligible_event_manifest_refs: Vec::new(),
            source_revision_refs: Vec::new(),
            source_close_watermark_refs: Vec::new(),
            source_close_reconciliation_refs: Vec::new(),
            admission_failure_evidence_refs: Vec::new(),
            admission_failure_observability: AdmissionFailureObservability::Unavailable,
            identity_strength: IdentityStrength::SynthesizedBestEffort,
            delegation_start_seen: false,
            child_session_linked: false,
            child_session_id: None,
            parent_session_end_seen: false,
            lifecycle_end_seen: false,
            terminal_event_kind: None,
            terminal_event_ref: None,
            termination_evidence_refs: Vec::new(),
            source_closed_refs: Vec::new(),
            liveness_probe_refs: Vec::new(),
            finalization_reason: None,
            first_sequence: None,
            last_sequence: None,
            sequence_gaps: Vec::new(),
            capture_gap_marker_refs: Vec::new(),
            capture_outage_interval_refs: Vec::new(),
            tool_calls_seen: Vec::new(),
            tool_results_seen: Vec::new(),
            unmatched_tool_call_ids: Vec::new(),
            unmatched_tool_result_ids: Vec::new(),
            payload_truncations: Vec::new(),
            redaction_refs: Vec::new(),
            corrupt_payload_refs: Vec::new(),
            unsupported_record_types: Vec::new(),
            import_watermark: 0,
            finalized: false,
            coverage_level: CoverageLevel::Opaque,
            source_coverage: SourceCoverage::Open,
            pairing_integrity: PairingIntegrity::Unavailable,
            payload_integrity: PayloadIntegrity::Unavailable,
            ordering_integrity: OrderingIntegrity::Unavailable,
            reasoning_visibility: Vec::new(),
            exact_byte_replay: false,
            resolver_version: 1,
        };
        (lane, receipt)
    }

    fn capture_command(
        command_id: &str,
        lane: ExecutionLane,
        receipt: Option<CaptureReceipt>,
    ) -> JournalCommand {
        let mut events = vec![JournalEventDraft::runtime(
            1,
            [1; 32],
            "capture-v1",
            JournalPayload::ExecutionLaneRecorded(Box::new(lane)),
        )];
        if let Some(receipt) = receipt {
            events.push(JournalEventDraft::runtime(
                1,
                [1; 32],
                "capture-v1",
                JournalPayload::CaptureReceiptRecorded(Box::new(receipt)),
            ));
        }
        JournalCommand::new(CommandId::from_str(command_id).unwrap(), events).unwrap()
    }

    #[test]
    fn reserved_sequences_may_leave_gaps_without_reuse_in_one_writer() {
        let mut next = 10;
        assert_eq!(reserve_range(&mut next, 2), Ok(10));
        assert_eq!(next, 12);
        assert_eq!(reserve_range(&mut next, 1), Ok(12));
        assert_eq!(next, 13);
    }

    #[tokio::test]
    async fn injected_precommit_and_lost_ack_boundaries_are_retry_safe() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let command = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a7a").unwrap(),
            vec![JournalEventDraft::runtime(
                1,
                [1; 32],
                "objects-v1",
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::ObjectsProjection,
                    target_id: "fault-boundary".into(),
                    algorithm_revision: "objects-v1".into(),
                    source_watermark: 1,
                }),
            )],
        )
        .unwrap();
        let prepared = prepare_command(&command).unwrap();

        assert!(
            writer
                .committed_command(command.command_id())
                .await
                .unwrap()
                .is_none()
        );
        let abandoned = reserve_range(&mut writer.next_seq, prepared.event_count).unwrap();
        let committed_frontier = read_journal_frontier(&writer.projection_handle())
            .await
            .unwrap();
        // A reservation is not a committed frontier: the next sequence moved
        // but the persisted and validated frontier did not.
        assert!(writer.next_seq > abandoned);
        assert_eq!(writer.frontier(), committed_frontier);
        assert_eq!(
            writer.read_diagnostics().await.tables[0].checkpoint,
            Some(committed_frontier)
        );
        assert_eq!(
            writer.sync_objects_frontier().await.unwrap(),
            committed_frontier
        );
        assert_eq!(writer.sync_frontier().await.unwrap(), committed_frontier);
        let first_seq = reserve_range(&mut writer.next_seq, prepared.event_count).unwrap();
        assert_eq!(first_seq, abandoned + u64::from(prepared.event_count));
        let rows = rows_for_append(&prepared, first_seq, 2).unwrap();
        append_rows(&writer.projection_handle(), &rows)
            .await
            .unwrap();
        assert_eq!(
            writer.read_diagnostics().await.tables[0].checkpoint,
            Some(first_seq)
        );
        // A direct native successor is not proof of an append by this writer.
        let old_version = writer.projection_validation.lock().unwrap()[0]
            .as_ref()
            .unwrap()
            .stamp
            .journal_epoch;
        assert_eq!(
            writer.projection_handle().lock().unwrap().journal_epoch(),
            old_version + 1
        );
        assert_eq!(
            writer.projection_validation.lock().unwrap()[0]
                .as_ref()
                .unwrap()
                .stamp
                .journal_epoch,
            old_version
        );
        assert_eq!(writer.sync_objects_frontier().await.unwrap(), first_seq);
        // The first catch-up validates its own committed version immediately.
        assert_eq!(
            writer.projection_validation.lock().unwrap()[0]
                .as_ref()
                .unwrap()
                .frontier,
            first_seq
        );
        assert!(writer.projection_validation.lock().unwrap()[1].is_none());
        assert_eq!(writer.sync_objects_frontier().await.unwrap(), first_seq);
        assert!(writer.projection_validation.lock().unwrap()[0].is_some());
        assert!(writer.projection_validation.lock().unwrap()[1].is_none());
        let stale_indexes =
            L0002ProjectionWorker::new(writer.sqlite.clone(), writer.search.clone())
                .current()
                .await
                .unwrap();
        assert!(stale_indexes.frontier < first_seq);
        assert_eq!(writer.sync_frontier().await.unwrap(), first_seq);
        let indexes = L0002ProjectionWorker::new(writer.sqlite.clone(), writer.search.clone())
            .current()
            .await
            .unwrap();
        assert_eq!(indexes.frontier, first_seq);
        assert_eq!(
            writer.project_objects().await.unwrap(),
            writer.full_projection().await.unwrap()
        );
        // The command was absent from the startup set. A read of the actual
        // persisted rows must see the commit, not a stale negative hint.
        assert!(
            writer
                .committed_command(command.command_id())
                .await
                .unwrap()
                .is_some()
        );
        drop(writer);

        let mut reopened = JournalWriter::open(&root).await.unwrap();
        let replay = reopened.commit(&command, 3).await.unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.first_seq, first_seq);
        assert_eq!(replay.last_seq, first_seq);
        let inspected = reopened
            .committed_command(command.command_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inspected.command_id, command.command_id());
        assert_eq!(inspected.event_ids, replay.event_ids);
        assert_eq!(inspected.payloads.len(), 1);
        assert_eq!(reopened.journal_rows().await.unwrap().len(), 3);
        let absent = CommandId::new_v7();
        let batch = reopened
            .committed_commands(&[absent, command.command_id(), command.command_id()])
            .await
            .unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[&command.command_id()], inspected);
        // A batch is not merely an existence hint: partial command corruption
        // must fail exactly as the original single read does.
        let mut partial = rows[0].clone();
        partial.ordinal = 1;
        partial.command_event_count = 2;
        partial.event_id.push_str("-partial");
        partial.seq = 100;
        append_rows(&reopened.projection_handle(), &[partial])
            .await
            .unwrap();
        assert!(
            reopened
                .committed_commands(&[command.command_id()])
                .await
                .is_err()
        );
        assert!(
            reopened
                .committed_command(command.command_id())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn conditional_commit_is_replay_first_and_compare_before_append() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let initial_frontier = writer.project().await.unwrap().frontier;
        let initial = writer.projection_validation.lock().unwrap()[0]
            .clone()
            .unwrap();
        let first = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a7b").unwrap(),
            vec![JournalEventDraft::runtime(
                1,
                [1; 32],
                "objects-v1",
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::ObjectsProjection,
                    target_id: "conditional-first".into(),
                    algorithm_revision: "objects-v1".into(),
                    source_watermark: initial_frontier,
                }),
            )],
        )
        .unwrap();
        let second = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a7c").unwrap(),
            vec![JournalEventDraft::runtime(
                1,
                [1; 32],
                "objects-v1",
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::ObjectsProjection,
                    target_id: "conditional-second".into(),
                    algorithm_revision: "objects-v1".into(),
                    source_watermark: initial_frontier,
                }),
            )],
        )
        .unwrap();

        let committed = writer
            .commit_if_frontier(&first, 1, initial_frontier)
            .await
            .unwrap();
        assert!(!committed.replayed);
        assert_eq!(
            writer.projection_handle().lock().unwrap().journal_epoch(),
            initial.stamp.journal_epoch + 1
        );
        assert_eq!(
            read_command_rows(&writer.projection_handle(), first.command_id())
                .await
                .unwrap()
                .len(),
            1
        );
        let stamps = writer.projection_validation.lock().unwrap().clone();
        let old_input = stamps[0].as_ref().unwrap();
        assert_eq!(old_input.stamp, initial.stamp);
        assert_eq!(old_input.frontier, initial_frontier);
        assert_ne!(old_input.frontier, committed.last_seq);
        assert!(stamps[1].is_none());
        let handoff = old_input.appended_rows.as_ref().unwrap();
        assert!(
            handoff
                .iter()
                .map(|row| row.payload_json.len())
                .sum::<usize>()
                <= MAX_PROJECTION_HANDOFF_BYTES
        );
        assert_eq!(
            handoff,
            &read_command_rows(&writer.projection_handle(), first.command_id())
                .await
                .unwrap()
        );
        assert!(writer.commit(&first, 1).await.unwrap().replayed);
        assert_eq!(writer.sync_frontier().await.unwrap(), committed.last_seq);
        let validated = writer.projection_validation.lock().unwrap()[1]
            .clone()
            .unwrap();
        assert!(validated.appended_rows.is_none());
        assert_eq!(
            validation_versions(&validated),
            projection_versions(&writer).await.unwrap()
        );
        assert_eq!(validated.frontier, committed.last_seq);
        assert_eq!(
            writer.project_objects().await.unwrap(),
            writer.full_projection().await.unwrap()
        );
        assert_eq!(
            writer.commit(&second, -1).await,
            Err(StoreError::InvalidInput)
        );
        assert_eq!(
            validation_versions(
                writer.projection_validation.lock().unwrap()[1]
                    .as_ref()
                    .unwrap()
            ),
            validation_versions(&validated)
        );
        let replayed = writer
            .commit_if_frontier(&first, 2, initial_frontier)
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.first_seq, committed.first_seq);
        assert_eq!(
            validation_versions(
                writer.projection_validation.lock().unwrap()[1]
                    .as_ref()
                    .unwrap()
            ),
            validation_versions(&validated)
        );
        assert_eq!(
            writer
                .commit_if_frontier(&second, 2, initial_frontier)
                .await,
            Err(StoreError::StaleFrontier)
        );
        assert_eq!(
            validation_versions(
                writer.projection_validation.lock().unwrap()[1]
                    .as_ref()
                    .unwrap()
            ),
            validation_versions(&validated)
        );
        assert_eq!(writer.sync_frontier().await.unwrap(), committed.last_seq);
        assert_eq!(
            projection_versions(&writer).await.unwrap(),
            validation_versions(&validated)
        );
        assert_eq!(writer.journal_rows().await.unwrap().len(), 3);
        reserve_range(&mut writer.next_seq, 2).unwrap();
        assert_eq!(writer.frontier(), committed.last_seq);
        assert!(writer.next_seq > writer.frontier());
        let capture = writer.capture_current_context(None, None, 8).await.unwrap();
        assert_eq!(capture.frontier, committed.last_seq);
        assert!(capture.items.is_empty());
        let memories = writer.memories_current_context(None, 8).await.unwrap();
        assert_eq!(memories.frontier, committed.last_seq);
        assert!(memories.items.is_empty());
        let inbox = writer.inbox_current_context(None, 8, 64).await.unwrap();
        assert_eq!(inbox.frontier, committed.last_seq);
        assert!(inbox.items.is_empty());
        assert!(
            writer
                .scope_current_context(&Default::default())
                .await
                .unwrap()
                .facts
                .is_empty()
        );
        assert!(
            writer
                .passive_source_current_context(&crate::PassiveSourceSelection::Session(
                    "missing".into()
                ))
                .await
                .unwrap()
                .items
                .is_empty()
        );
        assert_eq!(
            projection_versions(&writer).await.unwrap(),
            validation_versions(&validated)
        );
        let appended = writer.commit(&second, 3).await.unwrap();
        reserve_range(&mut writer.next_seq, 2).unwrap();
        assert_eq!(writer.frontier(), appended.last_seq);
        assert!(writer.next_seq > writer.frontier());
        assert_eq!(
            writer.sync_objects_frontier().await.unwrap(),
            appended.last_seq
        );
        assert_eq!(
            writer.project_objects().await.unwrap(),
            writer.full_projection().await.unwrap()
        );
        // The in-memory admission proof must agree with the physical journal
        // version; a version this writer never admitted fails closed.
        let journal_before = writer.journal_rows().await.unwrap();
        let lagging = journal_before[..journal_before.len() - 1].to_vec();
        overwrite_rows(&writer.projection_handle(), &lagging)
            .await
            .unwrap();
        assert!(matches!(
            writer.inbox_current_context(None, 8, 64).await,
            Err(StoreError::StoreCorrupt)
        ));
        assert!(matches!(
            writer.memories_current_context(None, 8).await,
            Err(StoreError::StoreCorrupt)
        ));
        assert!(
            writer
                .scope_current_context(&Default::default())
                .await
                .is_err()
        );
        assert!(
            writer
                .passive_source_current_context(&crate::PassiveSourceSelection::Session(
                    "missing".into()
                ))
                .await
                .is_err()
        );
        assert!(matches!(
            writer.capture_current_context(None, None, 8).await,
            Err(StoreError::StoreCorrupt)
        ));
        overwrite_rows(&writer.projection_handle(), &journal_before)
            .await
            .unwrap();
        assert!(writer.capture_current_context(None, None, 8).await.is_ok());
        overwrite_rows(&writer.projection_handle(), &lagging)
            .await
            .unwrap();
        assert!(matches!(
            writer.capture_current_context(None, None, 8).await,
            Err(StoreError::StoreCorrupt)
        ));
    }

    #[tokio::test]
    async fn normal_search_candidate_context_accepts_an_unrelated_append_at_its_fresh_stamp() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let initial = writer
            .normal_search_current_context(&Default::default())
            .await
            .unwrap();
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                1,
                [1; 32],
                "normal-search-test-v1",
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::ObjectsProjection,
                    target_id: "unrelated-normal-search-work".into(),
                    algorithm_revision: "normal-search-test-v1".into(),
                    source_watermark: 1,
                }),
            )],
        )
        .unwrap();
        let appended = writer.commit(&command, 2).await.unwrap();
        let fresh = writer
            .normal_search_candidate_context(
                &Default::default(),
                &NormalSearchCandidateRequest {
                    identifiers: vec!["not-a-current-object".into()],
                    task_id: None,
                    repository_id: None,
                    worktree_id: None,
                    include_procedure_route: false,
                    include_derived_candidate_rows: false,
                },
            )
            .await
            .unwrap();

        // The second read is bound to its own validated stamp.  It must not
        // reject an unrelated command merely because the pre-pin context was
        // older; candidate-specific facts are checked at this fresh frontier.
        assert!(fresh.frontier > initial.frontier);
        assert_eq!(fresh.frontier, appended.last_seq);
        assert!(fresh.rows.is_empty());
    }

    #[tokio::test]
    async fn normal_search_procedure_candidate_syncs_intervening_native_route_input() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        writer
            .normal_search_current_context(&Default::default())
            .await
            .unwrap();
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                1,
                [1; 32],
                "normal-search-test-v1",
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::ObjectsProjection,
                    target_id: "procedure-route-interleaving".into(),
                    algorithm_revision: "normal-search-test-v1".into(),
                    source_watermark: 1,
                }),
            )],
        )
        .unwrap();
        let appended = writer.commit(&command, 2).await.unwrap();
        assert!(
            writer.projection_validation.lock().unwrap()[0]
                .as_ref()
                .unwrap()
                .appended_through
                .is_some()
        );

        let fresh = writer
            .normal_search_candidate_context(
                &Default::default(),
                &NormalSearchCandidateRequest {
                    identifiers: vec!["not-a-current-procedure".into()],
                    task_id: None,
                    repository_id: None,
                    worktree_id: None,
                    include_procedure_route: true,
                    include_derived_candidate_rows: false,
                },
            )
            .await
            .unwrap();

        let stamp = writer.projection_validation.lock().unwrap()[0]
            .clone()
            .unwrap();
        assert_eq!(fresh.frontier, appended.last_seq);
        assert_eq!(stamp.frontier, appended.last_seq);
        assert!(stamp.appended_through.is_none());
    }

    #[tokio::test]
    async fn normal_search_candidate_context_rechecks_a_related_repository_successor() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let repository_id = RepositoryId::new_v7();
        let path = temp.path().join("repository").display().to_string();
        let repository = RepositoryInstance {
            repository_id,
            repository_revision: 1,
            predecessor_revision: None,
            current_path: path.clone(),
            path_history: vec![PathObservation {
                path: path.clone(),
                first_observed_at_us: 1,
                last_observed_at_us: 1,
                evidence_refs: vec!["normal-search-repository-evidence".into()],
            }],
            git_common_dir_path: Some(format!("{path}/.git")),
            common_dir_filesystem: Some(FilesystemIdentity {
                device: 1,
                inode: 1,
            }),
            object_format: Some(GitObjectFormat::Sha1),
            remote_fingerprints: Vec::new(),
            derived_from: None,
            identity_evidence_refs: vec!["normal-search-repository-identity".into()],
            recorded_at_us: 1,
            user_disabled: false,
            capability_state: None,
        };
        writer
            .commit(
                &JournalCommand::new(
                    CommandId::new_v7(),
                    vec![JournalEventDraft::runtime(
                        1,
                        [1; 32],
                        "normal-search-test-v1",
                        JournalPayload::RepositoryInstanceRecorded(Box::new(repository.clone())),
                    )],
                )
                .unwrap(),
                1,
            )
            .await
            .unwrap();
        let initial = writer
            .normal_search_current_context(&Default::default())
            .await
            .unwrap();
        let mut disabled = repository;
        disabled.repository_revision = 2;
        disabled.predecessor_revision = Some(1);
        disabled.recorded_at_us = 2;
        disabled.user_disabled = true;
        let mut disabled_event = JournalEventDraft::runtime(
            2,
            [1; 32],
            "normal-search-test-v1",
            JournalPayload::RepositoryInstanceRecorded(Box::new(disabled)),
        );
        disabled_event.source_kind = crate::command::SourceKind::Manual;
        let appended = writer
            .commit(
                &JournalCommand::new(CommandId::new_v7(), vec![disabled_event]).unwrap(),
                2,
            )
            .await
            .unwrap();
        let fresh = writer
            .normal_search_candidate_context(
                &Default::default(),
                &NormalSearchCandidateRequest {
                    identifiers: vec![repository_id.to_string()],
                    task_id: None,
                    repository_id: Some(repository_id),
                    worktree_id: None,
                    include_procedure_route: false,
                    include_derived_candidate_rows: false,
                },
            )
            .await
            .unwrap();
        let current = fresh
            .rows
            .iter()
            .find(|row| row.object_id.as_deref() == Some(repository_id.to_string().as_str()))
            .unwrap();
        let JournalPayload::RepositoryInstanceRecorded(current) =
            serde_json::from_str(current.payload_json.as_deref().unwrap()).unwrap()
        else {
            panic!("repository candidate expected");
        };

        assert!(fresh.frontier > initial.frontier);
        assert_eq!(fresh.frontier, appended.last_seq);
        assert!(current.user_disabled);
        assert_eq!(current.repository_revision, 2);
    }

    #[tokio::test]
    async fn consecutive_commits_reuse_only_the_validated_old_projection_input() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let mut last_seq = writer.sync_frontier().await.unwrap();
        let initial = writer.projection_validation.lock().unwrap()[0]
            .clone()
            .unwrap();
        for ordinal in 1..=3 {
            let command = JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    1,
                    [1; 32],
                    "objects-v1",
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::ObjectsProjection,
                        target_id: format!("consecutive-{ordinal}"),
                        algorithm_revision: "objects-v1".into(),
                        source_watermark: last_seq,
                    }),
                )],
            )
            .unwrap();
            let committed = writer.commit(&command, 2).await.unwrap();
            last_seq = committed.last_seq;
            let version = writer.projection_handle().lock().unwrap().journal_epoch();
            assert_eq!(version, initial.stamp.journal_epoch + ordinal);
            assert_eq!(
                writer.projection_handle().lock().unwrap().objects_epoch(),
                initial.stamp.objects_epoch
            );
            let stamps = writer.projection_validation.lock().unwrap().clone();
            let input = stamps[0].as_ref().unwrap();
            assert_eq!(input.stamp, initial.stamp);
            assert_eq!(input.frontier, initial.frontier);
            assert_eq!(input.appended_through, Some((initial.stamp, last_seq)));
            assert_eq!(input.appended_rows.is_some(), ordinal == 1);
            assert!(stamps[1].is_none());
            assert!(writer.commit(&command, 3).await.unwrap().replayed);
            if ordinal == 1 {
                // Reserved gaps are not a committed frontier.
                reserve_range(&mut writer.next_seq, 2).unwrap();
            }
        }
        let projected = writer.project().await.unwrap();
        assert_eq!(projected.frontier, last_seq);
        assert_eq!(projected, writer.full_projection().await.unwrap());
        let versions = projection_versions(&writer).await.unwrap();
        for stamp in writer.projection_validation.lock().unwrap().iter() {
            let stamp = stamp.as_ref().unwrap();
            assert_eq!(validation_versions(stamp), versions);
            assert_eq!(stamp.frontier, last_seq);
            assert!(stamp.appended_through.is_none());
            assert!(stamp.appended_rows.is_none());
        }
    }

    #[tokio::test]
    async fn large_committed_batch_is_not_retained_for_projection() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        writer.sync_objects_frontier().await.unwrap();
        let command = JournalCommand::new(
            CommandId::new_v7(),
            (1..=4096)
                .map(|value| {
                    JournalEventDraft::runtime(
                        1,
                        [1; 32],
                        "objects-v1",
                        JournalPayload::DirtyTarget(DirtyTarget {
                            target_kind: DirtyTargetKind::ObjectsProjection,
                            target_id: format!("batch-{value:0>250}"),
                            algorithm_revision: "objects-v1".into(),
                            source_watermark: value,
                        }),
                    )
                })
                .collect(),
        )
        .unwrap();
        let committed = writer.commit(&command, 2).await.unwrap();
        assert_eq!(committed.event_ids.len(), 4096);
        assert!(
            writer.projection_validation.lock().unwrap()[0]
                .as_ref()
                .unwrap()
                .appended_rows
                .is_none()
        );
        assert_eq!(
            writer.sync_objects_frontier().await.unwrap(),
            committed.last_seq
        );
        assert_eq!(
            writer.project_objects().await.unwrap(),
            writer.full_projection().await.unwrap()
        );
    }

    #[tokio::test]
    async fn capture_transitions_are_validated_before_journal_append() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let lane_id = ExecutionLaneId::new_v7();
        let first_receipt_id = CaptureReceiptId::new_v7();
        let (first_lane, first_receipt) = capture_pair(lane_id, first_receipt_id, 1, None);

        let orphan = capture_command(
            "01890f47-6a4a-7cc1-98b9-01890f476a7d",
            first_lane.clone(),
            None,
        );
        assert_eq!(
            writer.commit(&orphan, 1).await,
            Err(StoreError::InvalidInput)
        );
        assert_eq!(writer.journal_rows().await.unwrap().len(), 2);

        let initial = capture_command(
            "01890f47-6a4a-7cc1-98b9-01890f476a7e",
            first_lane.clone(),
            Some(first_receipt.clone()),
        );
        writer.commit(&initial, 1).await.unwrap();
        let after_initial = writer.journal_rows().await.unwrap().len();

        let repeated = capture_command(
            "01890f47-6a4a-7cc1-98b9-01890f476a7f",
            first_lane,
            Some(first_receipt),
        );
        assert_eq!(
            writer.commit(&repeated, 2).await,
            Err(StoreError::InvalidInput)
        );
        assert_eq!(writer.journal_rows().await.unwrap().len(), after_initial);

        let second_receipt_id = CaptureReceiptId::new_v7();
        let (mut successor_lane, successor_receipt) =
            capture_pair(lane_id, second_receipt_id, 2, Some(first_receipt_id));
        successor_lane.active_capture_receipt_revision_id = first_receipt_id;
        let mismatched = capture_command(
            "01890f47-6a4a-7cc1-98b9-01890f476a80",
            successor_lane,
            Some(successor_receipt),
        );
        assert_eq!(
            writer.commit(&mismatched, 2).await,
            Err(StoreError::InvalidInput)
        );
        assert_eq!(writer.journal_rows().await.unwrap().len(), after_initial);

        let third_receipt_id = CaptureReceiptId::new_v7();
        let (successor_lane, mut dangling_receipt) =
            capture_pair(lane_id, third_receipt_id, 2, Some(first_receipt_id));
        dangling_receipt.capture_gap_marker_refs = vec!["missing-gap".into()];
        let dangling = capture_command(
            "01890f47-6a4a-7cc1-98b9-01890f476a81",
            successor_lane,
            Some(dangling_receipt),
        );
        assert_eq!(
            writer.commit(&dangling, 2).await,
            Err(StoreError::InvalidInput)
        );
        assert_eq!(writer.journal_rows().await.unwrap().len(), after_initial);
    }

    #[test]
    fn restart_replay_rejects_cross_command_capture_pairing_and_proof_before_source() {
        let lane_id = ExecutionLaneId::new_v7();
        let receipt_id = CaptureReceiptId::new_v7();
        let (lane, receipt) = capture_pair(lane_id, receipt_id, 1, None);
        let lane_only = capture_command("01890f47-6a4a-7cc1-98b9-01890f476a82", lane.clone(), None);
        let receipt_only = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a83").unwrap(),
            vec![JournalEventDraft::runtime(
                1,
                [1; 32],
                "capture-v1",
                JournalPayload::CaptureReceiptRecorded(Box::new(receipt.clone())),
            )],
        )
        .unwrap();
        let mut split_rows = rows_for_append(&prepare_command(&lane_only).unwrap(), 1, 0).unwrap();
        split_rows.extend(rows_for_append(&prepare_command(&receipt_only).unwrap(), 2, 0).unwrap());
        assert!(matches!(
            JournalAdmissionState::from_journal_rows(&split_rows),
            Err(StoreError::StoreCorrupt)
        ));
        assert_eq!(reduce_journal(&split_rows), Err(StoreError::StoreCorrupt));

        let paired = capture_command("01890f47-6a4a-7cc1-98b9-01890f476a84", lane, Some(receipt));
        let proof = SourceCloseReconciliation::new(
            "close-proof-before-source",
            lane_id,
            vec![SourceCloseRange {
                source_instance_id: SourceInstanceId::parse("source-before").unwrap(),
                source_revision: SourceRevision::parse("revision-before").unwrap(),
                eligible_event_manifest_refs: vec!["eligible-before".into()],
                first_sequence: 1,
                close_watermark: 1,
                observed_through_sequence: 1,
                admission_failure_observability: AdmissionFailureObservability::Complete,
                independent_reconciliation: None,
            }],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let proof_command = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a85").unwrap(),
            vec![JournalEventDraft::runtime(
                1,
                [1; 32],
                "capture-v1",
                JournalPayload::SourceCloseReconciliation(proof),
            )],
        )
        .unwrap();
        let mut proof_rows = rows_for_append(&prepare_command(&paired).unwrap(), 1, 0).unwrap();
        proof_rows
            .extend(rows_for_append(&prepare_command(&proof_command).unwrap(), 3, 0).unwrap());
        assert!(matches!(
            JournalAdmissionState::from_journal_rows(&proof_rows),
            Err(StoreError::StoreCorrupt)
        ));
        assert_eq!(reduce_journal(&proof_rows), Err(StoreError::StoreCorrupt));
    }
    fn private_store_root(temp: &tempfile::TempDir) -> PathBuf {
        let root = temp.path().join("store");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn chmod_private(path: &std::path::Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    async fn read_frontier(readers: &StoreReadHandle) -> Result<u64, StoreError> {
        readers
            .read(|connection, _| crate::sqlite_state::read_persisted_frontier(connection))
            .await
    }

    #[tokio::test]
    async fn backup_close_and_reopen_publish_a_new_writer_incarnation() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_store_root(&temp);
        chmod_private(temp.path());
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let readers = writer.read_handle();
        let first = readers.incarnation();
        assert_ne!(first, 0);
        read_frontier(&readers).await.unwrap();
        drop(readers.search_lease().await.unwrap());

        let guard = writer
            .quiesce_for_backup()
            .await
            .unwrap()
            .expect("no external reader holds the WAL");
        let closed = writer.close_for_backup(guard).unwrap();
        // The closed window revokes the binding and fences readers: a read
        // waits instead of silently observing the previous incarnation.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), read_frontier(&readers))
                .await
                .is_err()
        );

        let reopened = closed.reopen().await.unwrap();
        let second = readers.incarnation();
        assert_ne!(second, first);
        read_frontier(&readers).await.unwrap();
        drop(readers.search_lease().await.unwrap());
        assert_eq!(reopened.frontier(), reopened.frontier());
        drop(reopened);
    }

    #[tokio::test]
    async fn healthy_busy_checkpoint_keeps_the_writer_binding_usable() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_store_root(&temp);
        chmod_private(temp.path());
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let readers = writer.read_handle();
        let incarnation = readers.incarnation();
        let command = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a7b").unwrap(),
            vec![JournalEventDraft::runtime(
                1,
                [1; 32],
                "objects-v1",
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::ObjectsProjection,
                    target_id: "busy-checkpoint".into(),
                    algorithm_revision: "objects-v1".into(),
                    source_watermark: 1,
                }),
            )],
        )
        .unwrap();
        writer.commit(&command, 1).await.unwrap();

        // A live WAL read transaction makes the TRUNCATE checkpoint busy.
        let path = crate::connection::sqlite_path(&root);
        let reader = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let _: i64 = reader
            .query_row("SELECT COUNT(*) FROM journal_events", [], |row| row.get(0))
            .unwrap();
        assert!(writer.quiesce_for_backup().await.unwrap().is_none());
        // A known-busy checkpoint is an ordinary backup failure: the writer,
        // its binding and its search connection stay usable.
        writer.project().await.unwrap();
        assert_eq!(readers.incarnation(), incarnation);
        readers
            .read(|connection, _| crate::sqlite_state::read_persisted_frontier(connection))
            .await
            .unwrap();
        drop(readers.search_lease().await.unwrap());
        drop(reader);

        let frontier = writer.frontier();
        let guard = writer
            .quiesce_for_backup()
            .await
            .unwrap()
            .expect("the external transaction is gone");
        let writer = writer
            .close_for_backup(guard)
            .unwrap()
            .reopen()
            .await
            .unwrap();
        assert_eq!(writer.frontier(), frontier);
        drop(writer);
    }

    #[tokio::test]
    async fn external_sqlite_commit_prevents_backup_close() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_store_root(&temp);
        chmod_private(temp.path());
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let readers = writer.read_handle();
        let external = rusqlite::Connection::open(crate::connection::sqlite_path(&root)).unwrap();
        external.execute_batch("PRAGMA user_version = 0").unwrap();
        drop(external);
        assert!(matches!(
            writer.quiesce_for_backup().await,
            Err(StoreError::StoreCorrupt)
        ));
        assert!(readers.journal_rows().await.is_err());
    }

    #[tokio::test]
    async fn failed_reopen_refuses_reads_until_a_new_binding_is_published() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_store_root(&temp);
        chmod_private(temp.path());
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let readers = writer.read_handle();
        let guard = writer
            .quiesce_for_backup()
            .await
            .unwrap()
            .expect("nothing holds the WAL");
        let closed = writer.close_for_backup(guard).unwrap();
        // Corrupt the closed database: reopen must fail before publishing.
        fs::write(crate::connection::sqlite_path(&root), b"not a database").unwrap();
        assert!(closed.reopen().await.is_err());
        assert!(
            readers
                .read(|connection, _| crate::sqlite_state::read_persisted_frontier(connection))
                .await
                .is_err()
        );
    }
}
