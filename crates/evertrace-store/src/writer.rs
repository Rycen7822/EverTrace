use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, DirBuilder, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::Mutex,
};

use fs2::FileExt;
use lancedb::{Connection, Table};

use crate::{
    command::{CommitOutcome, JournalCommand, JournalPayload, StoreError, prepare_command},
    journal::{
        JOURNAL_TABLE, StartupJournal, append_rows, read_all_journal_rows, read_command_rows,
        read_commands_rows, read_journal_frontier, replay_outcome, rows_for_append,
        validate_complete_command,
    },
    migrations::{L0002, MigrationOutcome},
    objects::{OBJECTS_TABLE, read_object_checkpoint, read_object_rows, validate_objects_table},
    projections::{
        JournalAdmissionState, ProjectionSnapshot, ProjectionWorker,
        ReconciliationArtifactDescriptor, ReconciliationArtifactFrontier, ReconciliationFrontier,
    },
    query::L0002ProjectionWorker,
    relations::RELATIONS_TABLE,
    search::SEARCH_TABLE,
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

/// A transient replay read bound, not a persistent journal index.
pub const MAX_COMMITTED_COMMAND_READ: usize = 64;

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
    pub(crate) lock: SiblingWriterLock,
}

const MAX_PROJECTION_HANDOFF_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
struct ProjectionValidation {
    // These versions bind the checkpoint/generation and full rows validated by
    // the existing workers. No full current-row set or reducer state is retained.
    versions: [u64; 4],
    frontier: u64,
    has_failed_job: bool,
    // Last confirmed append, not a claim that the old objects or indexes have
    // advanced. Each retained successor is bound to its committed frontier.
    appended_through: Option<(u64, u64)>,
    // At most one small immutable batch. Multiple appends use the ordinary
    // journal delta read without retaining or concatenating their batches.
    appended_batch: Option<arrow_array::RecordBatch>,
}

pub struct JournalWriter {
    _lock: SiblingWriterLock,
    connection: Connection,
    journal: Table,
    objects: Table,
    relations: Table,
    search: Table,
    next_seq: u64,
    admission_state: JournalAdmissionState,
    // Negative lookups only, derived from the journal already validated at open.
    // A changed table version or uncertain append falls back to the journal.
    command_ids: Option<(u64, BTreeSet<evertrace_domain::ids::CommandId>)>,
    migration_outcome: MigrationOutcome,
    // Keep directory inodes alive so replacement cannot reuse their identity.
    projection_directories: Vec<(PathBuf, File)>,
    // Objects and all mandatory projections have separate successful stamps.
    projection_validation: Mutex<[Option<ProjectionValidation>; 2]>,
}

impl JournalWriter {
    pub const fn frontier(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    pub fn projection_worker(&self) -> ProjectionWorker {
        ProjectionWorker::new(self.journal.clone(), self.objects.clone())
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
            .recall_current_contexts(self.next_seq.saturating_sub(1), limit)
    }

    pub fn session_import_context(
        &self,
        source: &str,
    ) -> Result<Option<crate::SessionImportContext>, StoreError> {
        self.admission_state
            .session_import_context(self.frontier(), source)
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
        Self::open_with_lock(lock).await
    }

    pub(crate) async fn open_with_lock(lock: SiblingWriterLock) -> Result<Self, StoreError> {
        let data_dir = lock.data_dir().to_owned();
        crate::restore::reject_retained_upgrade_candidate(&data_dir)
            .map_err(|_| StoreError::UpgradeRequired)?;
        crate::connection::prepare_native_root(&data_dir)?;
        let native = crate::connection::native_root(&data_dir);
        lock.validate_held()?;
        let connection = lancedb::connect(native.to_str().ok_or(StoreError::InvalidPath)?)
            .session(crate::connection::native_session())
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let mut startup = Self::read_existing_journal(&connection, &native).await?;
        if let Some(journal) = &mut startup
            && Self::journal_profile(journal)? == Some("L0001")
        {
            return Err(StoreError::UpgradeRequired);
        }
        Self::open_on_connection(lock, &native, connection, startup).await
    }

    pub(crate) async fn existing_profile(
        data_dir: &Path,
    ) -> Result<Option<&'static str>, StoreError> {
        if !Self::journal_exists(data_dir)? {
            return Ok(None);
        }
        let connection = lancedb::connect(data_dir.to_str().ok_or(StoreError::InvalidPath)?)
            .session(crate::connection::native_session())
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        match Self::read_existing_journal(&connection, data_dir).await? {
            Some(mut journal) => Self::journal_profile(&mut journal),
            None => Ok(None),
        }
    }

    async fn read_existing_journal(
        connection: &Connection,
        data_dir: &Path,
    ) -> Result<Option<StartupJournal>, StoreError> {
        if !Self::journal_exists(data_dir)? {
            return Ok(None);
        }
        let journal = connection
            .open_table(JOURNAL_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        Ok(Some(StartupJournal::read(journal).await?))
    }

    fn journal_exists(data_dir: &Path) -> Result<bool, StoreError> {
        let path = data_dir.join(format!("{JOURNAL_TABLE}.lance"));
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(StoreError::Io),
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                Err(StoreError::StoreCorrupt)
            }
            Ok(_) => Ok(true),
        }
    }

    fn journal_profile(journal: &mut StartupJournal) -> Result<Option<&'static str>, StoreError> {
        let rows = &journal.rows;
        drop(JournalAdmissionState::from_journal_rows(rows)?);
        journal.requires_admission_validation = true;
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

    async fn open_at_with_lock(
        lock: SiblingWriterLock,
        native_dir: &Path,
    ) -> Result<Self, StoreError> {
        lock.validate_held()?;
        let connection = lancedb::connect(native_dir.to_str().ok_or(StoreError::InvalidPath)?)
            .session(crate::connection::native_session())
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        Self::open_on_connection(lock, native_dir, connection, None).await
    }

    async fn open_on_connection(
        lock: SiblingWriterLock,
        native_dir: &Path,
        connection: Connection,
        mut startup: Option<StartupJournal>,
    ) -> Result<Self, StoreError> {
        lock.validate_held()?;
        let migration_outcome = L0002::apply_with_journal(&connection, &mut startup).await?;
        let mut projection_directories = Vec::with_capacity(5);
        for path in std::iter::once(native_dir.to_owned()).chain(
            [JOURNAL_TABLE, OBJECTS_TABLE, RELATIONS_TABLE, SEARCH_TABLE]
                .map(|table| native_dir.join(format!("{table}.lance"))),
        ) {
            let located = fs::symlink_metadata(&path).map_err(|_| StoreError::StoreCorrupt)?;
            let file = File::open(&path).map_err(|_| StoreError::StoreCorrupt)?;
            let held = file.metadata().map_err(|_| StoreError::StoreCorrupt)?;
            if !located.is_dir()
                || located.file_type().is_symlink()
                || (located.dev(), located.ino()) != (held.dev(), held.ino())
            {
                return Err(StoreError::StoreCorrupt);
            }
            projection_directories.push((path, file));
        }
        let mut startup = startup.ok_or(StoreError::StoreCorrupt)?;
        startup.refresh().await?;
        let journal = startup.table.clone();
        let objects = connection
            .open_table(OBJECTS_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let relations = connection
            .open_table(RELATIONS_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let search = connection
            .open_table(SEARCH_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        validate_objects_table(&objects).await?;
        let admission_state = JournalAdmissionState::from_journal_rows(&startup.rows)?;
        let journal_rows = &startup.rows;
        let command_ids = Some((
            startup.version,
            journal_rows.iter().map(|row| row.command_id).collect(),
        ));
        let next_seq = journal_rows
            .iter()
            .map(|row| row.seq)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StoreError::StoreCorrupt)?;
        let journal_version = startup.version;
        drop(startup);
        let writer = Self {
            _lock: lock,
            connection,
            journal,
            objects,
            relations,
            search,
            next_seq,
            admission_state,
            command_ids,
            migration_outcome,
            projection_directories,
            projection_validation: Mutex::new([None, None]),
        };
        if writer.projection_versions(true).await?[0] != journal_version {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(writer)
    }

    pub async fn read_diagnostics(&self) -> NativeDiagnostics {
        let mut tables = Vec::with_capacity(4);
        for (table, expected, checkpoint) in [
            (
                &self.journal,
                crate::journal::journal_schema(),
                read_journal_frontier(&self.journal).await,
            ),
            (
                &self.objects,
                crate::objects::objects_schema(),
                read_object_checkpoint(&self.objects).await,
            ),
            (
                &self.relations,
                crate::relations::relations_schema(),
                crate::relations::read_relation_checkpoint(&self.relations).await,
            ),
            (
                &self.search,
                crate::search::search_schema(),
                crate::search::read_search_checkpoint(&self.search).await,
            ),
        ] {
            tables.push(NativeDiagnosticTable {
                schema_matches: table.schema().await.ok().map(|schema| schema == expected),
                version: table.version().await.ok(),
                checkpoint: checkpoint.ok(),
            });
        }
        let objects = match tables[1].checkpoint {
            Some(frontier) => validate_objects_table(&self.objects)
                .await
                .ok()
                .map(|rows| ProjectionSnapshot { frontier, rows }),
            None => None,
        };
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
        let journal_checkpoint = read_journal_frontier(&self.journal).await?;
        let object_checkpoint = read_object_checkpoint(&self.objects).await?;
        let relation_checkpoint =
            crate::relations::read_relation_checkpoint(&self.relations).await?;
        let search_checkpoint = crate::search::read_search_checkpoint(&self.search).await?;
        Ok(crate::BackupTableStates {
            journal: crate::BackupTableState {
                version: self
                    .journal
                    .version()
                    .await
                    .map_err(|_| StoreError::LanceDb)?,
                checkpoint: journal_checkpoint,
            },
            objects: crate::BackupTableState {
                version: self
                    .objects
                    .version()
                    .await
                    .map_err(|_| StoreError::LanceDb)?,
                checkpoint: object_checkpoint,
            },
            relations: Some(crate::BackupTableState {
                version: self
                    .relations
                    .version()
                    .await
                    .map_err(|_| StoreError::LanceDb)?,
                checkpoint: relation_checkpoint,
            }),
            search: Some(crate::BackupTableState {
                version: self
                    .search
                    .version()
                    .await
                    .map_err(|_| StoreError::LanceDb)?,
                checkpoint: search_checkpoint,
            }),
        })
    }

    pub fn close_for_backup(self) -> ClosedJournalWriter {
        let Self {
            _lock: lock,
            connection,
            journal,
            objects,
            relations,
            search,
            next_seq,
            admission_state,
            command_ids,
            migration_outcome,
            projection_directories,
            projection_validation,
        } = self;
        drop((
            connection,
            journal,
            objects,
            relations,
            search,
            next_seq,
            admission_state,
            command_ids,
            migration_outcome,
            projection_directories,
            projection_validation,
        ));
        ClosedJournalWriter { lock }
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
        crate::query::L0002ProjectionWorker::new(
            self.journal.clone(),
            self.relations.clone(),
            self.search.clone(),
        )
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
            self.command_ids = None;
            append_rows(&self.journal, &rows).await?;
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
        let rows = self.existing_command_rows(command_id).await?;
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
        let mut ids = command_ids.iter().copied().collect::<BTreeSet<_>>();
        if let Some((version, known)) = &self.command_ids
            && self
                .journal
                .version()
                .await
                .map_err(|_| StoreError::LanceDb)?
                == *version
        {
            ids.retain(|id| known.contains(id));
        }
        let rows =
            read_commands_rows(&self.journal, &ids.iter().copied().collect::<Vec<_>>()).await?;
        let mut grouped = BTreeMap::<_, Vec<_>>::new();
        for row in rows {
            grouped.entry(row.command_id).or_default().push(row);
        }
        grouped
            .into_iter()
            .map(|(id, rows)| Ok((id, decode_committed_command(rows)?)))
            .collect()
    }

    async fn existing_command_rows(
        &self,
        command_id: evertrace_domain::ids::CommandId,
    ) -> Result<Vec<crate::JournalRow>, StoreError> {
        if let Some((version, ids)) = &self.command_ids
            && !ids.contains(&command_id)
            && self
                .journal
                .version()
                .await
                .map_err(|_| StoreError::LanceDb)?
                == *version
        {
            return Ok(Vec::new());
        }
        // Positive/replay reads still validate actual persisted rows, not a
        // cached payload or acknowledgement.
        read_command_rows(&self.journal, command_id).await
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
        let existing = self.existing_command_rows(prepared.command_id).await?;
        if let Some(outcome) = replay_outcome(&existing, &prepared)? {
            return Ok(outcome);
        }
        if let Some(expected) = expected_frontier
            && read_journal_frontier(&self.journal).await? != expected
        {
            return Err(StoreError::StaleFrontier);
        }
        let next_admission_state = self.admission_state.apply_command(command, self.next_seq)?;
        let first_seq = reserve_range(&mut self.next_seq, prepared.event_count)?;
        let rows = rows_for_append(&prepared, first_seq, ingested_at_us)?;
        let version = self
            .journal
            .version()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let known = self
            .command_ids
            .take()
            .filter(|(known, _)| *known == version);
        let stamps = self
            .projection_validation
            .get_mut()
            .map_err(|_| StoreError::StoreCorrupt)?;
        let validated_input = stamps[0]
            .as_ref()
            .filter(|stamp| {
                let (input_version, input_frontier) = stamp
                    .appended_through
                    .unwrap_or((stamp.versions[0], stamp.frontier));
                known.is_some()
                    && input_version == version
                    && input_frontier == self.admission_state.committed_frontier()
            })
            .cloned();
        // Clear before the await, including uncertain append failures. Only a
        // confirmed direct successor may retain proof of the unchanged OLD
        // objects input, never of the new frontier or synchronized indexes.
        *stamps = [None, None];
        let (committed_version, batch) = append_rows(&self.journal, &rows).await?;
        if version.checked_add(1) == Some(committed_version)
            && let Some(mut stamp) = validated_input
        {
            stamp.appended_batch = (stamp.appended_through.is_none()
                && batch.get_array_memory_size() <= MAX_PROJECTION_HANDOFF_BYTES)
                .then_some(batch);
            stamp.appended_through =
                Some((committed_version, next_admission_state.committed_frontier()));
            stamps[0] = Some(stamp);
        }
        self.admission_state = next_admission_state;
        if let Some((_, mut ids)) = known {
            ids.insert(prepared.command_id);
            // The native append already reports its committed version. A
            // second, fallible read must not discard this successful proof.
            self.command_ids = Some((committed_version, ids));
        }
        Ok(CommitOutcome {
            command_id: prepared.command_id,
            first_seq,
            last_seq: rows.last().ok_or(StoreError::StoreCorrupt)?.seq,
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
            if self.command_ids.as_ref().map(|(version, _)| *version) != Some(stamp.versions[0])
                || self.admission_state.committed_frontier() != stamp.frontier
            {
                return Err(StoreError::StoreCorrupt);
            }
            let context = read(&self.admission_state, &stamp)?;
            if self.projection_versions(false).await? != stamp.versions {
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
    /// validation and per-table commits must succeed before this returns.
    pub async fn sync_frontier(&self) -> Result<u64, StoreError> {
        Ok(self.project_validated(true, false).await?.0)
    }

    pub async fn project(&self) -> Result<ProjectionSnapshot, StoreError> {
        self.project_validated(true, true)
            .await?
            .1
            .ok_or(StoreError::StoreCorrupt)
    }

    fn validate_projection_directories(&self, indexes: bool) -> Result<(), StoreError> {
        self._lock.validate_held()?;
        for (path, file) in self
            .projection_directories
            .iter()
            .take(if indexes { 5 } else { 3 })
        {
            let located = fs::symlink_metadata(path).map_err(|_| StoreError::StoreCorrupt)?;
            let held = file.metadata().map_err(|_| StoreError::StoreCorrupt)?;
            if !located.is_dir()
                || located.file_type().is_symlink()
                || (located.dev(), located.ino()) != (held.dev(), held.ino())
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Ok(())
    }

    async fn projection_versions(&self, indexes: bool) -> Result<[u64; 4], StoreError> {
        self.validate_projection_directories(indexes)?;
        let mut versions = [0; 4];
        for (index, table) in [&self.journal, &self.objects, &self.relations, &self.search]
            .into_iter()
            .take(if indexes { 4 } else { 2 })
            .enumerate()
        {
            table
                .checkout_latest()
                .await
                .map_err(|_| StoreError::LanceDb)?;
            versions[index] = table.version().await.map_err(|_| StoreError::LanceDb)?;
        }
        self.validate_projection_directories(indexes)?;
        Ok(versions)
    }

    async fn project_validated(
        &self,
        indexes: bool,
        return_rows: bool,
    ) -> Result<(u64, Option<ProjectionSnapshot>), StoreError> {
        let result = async {
            let before = self.projection_versions(indexes).await?;
            let stamps = self
                .projection_validation
                .lock()
                .map_err(|_| StoreError::StoreCorrupt)?
                .clone();
            let objects = stamps[0]
                .as_ref()
                .filter(|stamp| stamp.versions[..2] == before[..2]);
            let validated_input = stamps[0].as_ref().filter(|stamp| {
                stamp.appended_through
                    == Some((before[0], self.admission_state.committed_frontier()))
                    && stamp.versions[1] == before[1]
                    && self
                        .command_ids
                        .as_ref()
                        .is_some_and(|(version, _)| *version == before[0])
            });
            let validated_current = validated_input.map(|stamp| {
                (
                    stamp.versions[1],
                    stamp.frontier,
                    self.admission_state.committed_frontier(),
                )
            });
            let all = indexes
                .then_some(stamps[1].as_ref())
                .flatten()
                .filter(|stamp| stamp.versions == before);
            let hit = if indexes { all } else { objects };
            let mut validated_versions = before;
            let (frontier, snapshot, has_failed_job) = if let Some(stamp) = hit {
                let snapshot = if return_rows {
                    Some(ProjectionSnapshot {
                        frontier: stamp.frontier,
                        rows: read_object_rows(&self.objects).await?,
                    })
                } else {
                    None
                };
                (stamp.frontier, snapshot, stamp.has_failed_job)
            } else {
                let (snapshot, delta) = if let Some(stamp) = objects {
                    (
                        ProjectionSnapshot {
                            frontier: stamp.frontier,
                            rows: read_object_rows(&self.objects).await?,
                        },
                        None,
                    )
                } else {
                    let (snapshot, version, delta) = self
                        .projection_worker()
                        .catch_up_validated(
                            validated_current,
                            validated_input.and_then(|stamp| stamp.appended_batch.as_ref()),
                        )
                        .await?;
                    validated_versions[1] = version;
                    (snapshot, delta)
                };
                if indexes {
                    let (_, versions) = L0002ProjectionWorker::new(
                        self.journal.clone(),
                        self.relations.clone(),
                        self.search.clone(),
                    )
                    .catch_up_validated(&snapshot, delta)
                    .await?;
                    validated_versions[2..].copy_from_slice(&versions);
                } else {
                    drop(delta);
                }
                let has_failed_job =
                    crate::projections::RuntimeSchedulerView::from_snapshot(&snapshot)?
                        .jobs
                        .iter()
                        .any(|job| job.state == crate::JobStatus::Failed);
                (
                    snapshot.frontier,
                    return_rows.then_some(snapshot),
                    has_failed_job,
                )
            };
            let after = self.projection_versions(indexes).await?;
            if validated_versions != after {
                return Err(StoreError::StoreCorrupt);
            }
            // Workers bind validated rows to a full readback version or an
            // ordinary objects upsert's verified native commit version.
            // The journal must remain at the version used on entry;
            // latest versions and held directory identities are checked above.
            {
                let stamp = Some(ProjectionValidation {
                    versions: validated_versions,
                    frontier,
                    has_failed_job,
                    appended_through: None,
                    appended_batch: None,
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
                    .is_some_and(|stamp| stamp.versions[..2] != after[..2])
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
        ProjectionWorker::new(self.journal.clone(), self.objects.clone())
            .full_snapshot()
            .await
    }

    pub async fn journal_rows(&self) -> Result<Vec<crate::JournalRow>, StoreError> {
        read_all_journal_rows(&self.journal).await
    }

    pub fn llm_budget_page(
        &self,
        day_start_us: i64,
        after: u64,
        frontier: u64,
    ) -> impl std::future::Future<Output = Result<Vec<crate::JournalRow>, StoreError>> + Send + use<>
    {
        let journal = self.journal.clone();
        let frontier = frontier.min(self.frontier());
        async move {
            crate::journal::read_llm_budget_page(&journal, day_start_us, after, frontier).await
        }
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
        crate::optimize::historical_cas_refs(&self.journal, self.frontier(), candidates).await
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
        crate::optimize::conservative_prune(
            self._lock.data_dir(),
            [&self.journal, &self.objects, &self.relations, &self.search],
            report,
        )
        .await
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
        read_object_rows(&self.objects).await
    }

    pub async fn relation_rows(&self) -> Result<Vec<crate::RelationProjectionRow>, StoreError> {
        crate::read_relation_rows(&self.relations).await
    }

    pub async fn search_rows(&self) -> Result<Vec<crate::SearchProjectionRow>, StoreError> {
        crate::read_search_rows(&self.search).await
    }

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
            &config_path,
            &runtime,
            backup_job_id,
            &snapshot,
            table_states,
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
    ) -> Result<(), crate::BackupError> {
        crate::backup::discard_backup(staging)
    }

    pub async fn reopen(self) -> Result<JournalWriter, StoreError> {
        JournalWriter::open_with_lock(self.lock).await
    }

    pub(crate) async fn open_restore_candidate(
        self,
        candidate: &Path,
    ) -> Result<JournalWriter, StoreError> {
        self.lock.validate_held()?;
        if candidate.parent() != self.lock.data_dir.parent() {
            return Err(StoreError::InvalidPath);
        }
        crate::connection::prepare_native_root(candidate)?;
        JournalWriter::open_at_with_lock(self.lock, &crate::connection::native_root(candidate))
            .await
    }
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
    use std::str::FromStr;

    use evertrace_domain::{
        evidence::{IdentityStrength, SourceInstanceId, SourceRevision},
        ids::{CaptureReceiptId, CommandId, ExecutionLaneId},
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

    #[tokio::test]
    async fn startup_admission_failure_precedes_missing_objects_repair() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let writer = JournalWriter::open(&root).await.unwrap();
        let mut startup = StartupJournal::read(writer.journal.clone()).await.unwrap();
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
        append_rows(&writer.journal, &rows).await.unwrap();
        // Revalidation must still reject semantic corruption after the
        // precheck's temporary admission state has been released.
        assert_eq!(startup.refresh().await, Err(StoreError::StoreCorrupt));
        drop(startup);
        drop(writer);
        let objects = crate::connection::native_root(&root).join(format!("{OBJECTS_TABLE}.lance"));
        fs::rename(&objects, temp.path().join("saved-objects")).unwrap();
        assert!(matches!(
            JournalWriter::open(&root).await,
            Err(StoreError::StoreCorrupt)
        ));
        assert!(
            !objects.exists(),
            "admission must fail before migration writes"
        );
    }

    #[tokio::test]
    async fn projection_stamp_rejects_replaced_native_directory_with_same_versions() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let writer = JournalWriter::open(&root).await.unwrap();
        let mut startup = StartupJournal::read(writer.journal.clone()).await.unwrap();
        writer.sync_frontier().await.unwrap();
        assert!(writer.projection_validation.lock().unwrap()[1].is_some());
        let versions = writer.projection_versions(true).await.unwrap();
        let native = crate::connection::native_root(&root);
        let moved = root.join("previous-store");
        fs::rename(&native, &moved).unwrap();
        DirBuilder::new().mode(0o700).create(&native).unwrap();
        // Reuse the very same table directories/versions under a new native root.
        for table in [JOURNAL_TABLE, OBJECTS_TABLE, RELATIONS_TABLE, SEARCH_TABLE] {
            let name = format!("{table}.lance");
            fs::rename(moved.join(&name), native.join(name)).unwrap();
        }
        assert_eq!(writer.objects.version().await.unwrap(), versions[1]);
        assert_eq!(startup.refresh().await, Err(StoreError::StoreCorrupt));
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
        writer.objects.delete("true").await.unwrap();
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
        let committed_frontier = read_journal_frontier(&writer.journal).await.unwrap();
        assert!(writer.frontier() > committed_frontier);
        assert_eq!(
            writer.sync_objects_frontier().await.unwrap(),
            committed_frontier
        );
        assert_eq!(writer.sync_frontier().await.unwrap(), committed_frontier);
        let first_seq = reserve_range(&mut writer.next_seq, prepared.event_count).unwrap();
        assert_eq!(first_seq, abandoned + u64::from(prepared.event_count));
        let rows = rows_for_append(&prepared, first_seq, 2).unwrap();
        append_rows(&writer.journal, &rows).await.unwrap();
        // A direct native successor is not proof of an append by this writer.
        let old_version = writer.projection_validation.lock().unwrap()[0]
            .as_ref()
            .unwrap()
            .versions[0];
        assert_eq!(writer.journal.version().await.unwrap(), old_version + 1);
        assert_eq!(writer.command_ids.as_ref().unwrap().0, old_version);
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
        let stale_indexes = L0002ProjectionWorker::new(
            writer.journal.clone(),
            writer.relations.clone(),
            writer.search.clone(),
        )
        .current()
        .await
        .unwrap();
        assert!(stale_indexes.frontier < first_seq);
        assert_eq!(writer.sync_frontier().await.unwrap(), first_seq);
        let indexes = L0002ProjectionWorker::new(
            writer.journal.clone(),
            writer.relations.clone(),
            writer.search.clone(),
        )
        .current()
        .await
        .unwrap();
        assert_eq!(indexes.frontier, first_seq);
        assert_eq!(
            writer.project_objects().await.unwrap(),
            writer.full_projection().await.unwrap()
        );
        // The command was absent from the startup set. A changed journal
        // version must bypass that negative hint and read the actual commit.
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
        // A batch is not merely an existence hint: duplicate/partial command
        // corruption must fail exactly as the original single read does.
        append_rows(&reopened.journal, &rows).await.unwrap();
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
        let (version, ids) = writer.command_ids.as_ref().unwrap();
        assert_eq!(*version, writer.journal.version().await.unwrap());
        assert!(ids.contains(&first.command_id()));
        let stamps = writer.projection_validation.lock().unwrap().clone();
        let old_input = stamps[0].as_ref().unwrap();
        assert_eq!(old_input.versions, initial.versions);
        assert_eq!(old_input.frontier, initial_frontier);
        assert_ne!(old_input.frontier, committed.last_seq);
        assert!(stamps[1].is_none());
        let batch = old_input.appended_batch.as_ref().unwrap();
        assert!(batch.get_array_memory_size() <= MAX_PROJECTION_HANDOFF_BYTES);
        assert_eq!(
            crate::journal::rows_from_batch(batch).unwrap(),
            read_command_rows(&writer.journal, first.command_id())
                .await
                .unwrap()
        );
        assert!(writer.commit(&first, 1).await.unwrap().replayed);
        assert_eq!(writer.sync_frontier().await.unwrap(), committed.last_seq);
        let validated = writer.projection_validation.lock().unwrap()[1]
            .clone()
            .unwrap();
        assert!(validated.appended_batch.is_none());
        assert_eq!(
            validated.versions,
            writer.projection_versions(true).await.unwrap()
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
            writer.projection_validation.lock().unwrap()[1]
                .as_ref()
                .unwrap()
                .versions,
            validated.versions
        );
        let replayed = writer
            .commit_if_frontier(&first, 2, initial_frontier)
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.first_seq, committed.first_seq);
        assert_eq!(
            writer.projection_validation.lock().unwrap()[1]
                .as_ref()
                .unwrap()
                .versions,
            validated.versions
        );
        assert_eq!(
            writer
                .commit_if_frontier(&second, 2, initial_frontier)
                .await,
            Err(StoreError::StaleFrontier)
        );
        assert_eq!(
            writer.projection_validation.lock().unwrap()[1]
                .as_ref()
                .unwrap()
                .versions,
            validated.versions
        );
        assert_eq!(writer.sync_frontier().await.unwrap(), committed.last_seq);
        assert_eq!(
            writer.projection_versions(true).await.unwrap(),
            validated.versions
        );
        assert_eq!(writer.journal_rows().await.unwrap().len(), 3);
        reserve_range(&mut writer.next_seq, 2).unwrap();
        assert!(writer.frontier() > committed.last_seq);
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
            writer.projection_versions(true).await.unwrap(),
            validated.versions
        );
        let appended = writer.commit(&second, 3).await.unwrap();
        reserve_range(&mut writer.next_seq, 2).unwrap();
        assert!(writer.frontier() > appended.last_seq);
        assert_eq!(
            writer.sync_objects_frontier().await.unwrap(),
            appended.last_seq
        );
        assert_eq!(
            writer.project_objects().await.unwrap(),
            writer.full_projection().await.unwrap()
        );
        let proof = writer.command_ids.take();
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
        writer.command_ids = proof;
        assert!(writer.capture_current_context(None, None, 8).await.is_ok());
        writer.command_ids.as_mut().unwrap().0 += 1;
        assert!(matches!(
            writer.capture_current_context(None, None, 8).await,
            Err(StoreError::StoreCorrupt)
        ));
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
            let version = writer.journal.version().await.unwrap();
            assert_eq!(version, initial.versions[0] + ordinal);
            assert_eq!(writer.objects.version().await.unwrap(), initial.versions[1]);
            let stamps = writer.projection_validation.lock().unwrap().clone();
            let input = stamps[0].as_ref().unwrap();
            assert_eq!(input.versions, initial.versions);
            assert_eq!(input.frontier, initial.frontier);
            assert_eq!(input.appended_through, Some((version, last_seq)));
            assert_eq!(input.appended_batch.is_some(), ordinal == 1);
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
        let versions = writer.projection_versions(true).await.unwrap();
        for stamp in writer.projection_validation.lock().unwrap().iter() {
            let stamp = stamp.as_ref().unwrap();
            assert_eq!(stamp.versions, versions);
            assert_eq!(stamp.frontier, last_seq);
            assert!(stamp.appended_through.is_none());
            assert!(stamp.appended_batch.is_none());
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
                        JournalPayload::WatermarkAdvanced(crate::WatermarkAdvanced {
                            kind: crate::WatermarkKind::RuntimeJobs,
                            value,
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
                .appended_batch
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
}
