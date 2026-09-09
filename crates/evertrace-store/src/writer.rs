use std::{
    ffi::OsString,
    fs::{self, DirBuilder, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use fs2::FileExt;
use lancedb::{Connection, Table};

use crate::{
    command::{CommitOutcome, JournalCommand, JournalPayload, StoreError, prepare_command},
    journal::{
        JOURNAL_TABLE, append_rows, read_all_journal_rows, read_command_rows,
        read_journal_frontier, replay_outcome, rows_for_append, validate_complete_command,
        validate_journal_table,
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

pub struct JournalWriter {
    _lock: SiblingWriterLock,
    connection: Connection,
    journal: Table,
    objects: Table,
    relations: Table,
    search: Table,
    next_seq: u64,
    admission_state: JournalAdmissionState,
    migration_outcome: MigrationOutcome,
}

impl JournalWriter {
    pub const fn frontier(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    pub fn projection_worker(&self) -> ProjectionWorker {
        ProjectionWorker::new(self.journal.clone(), self.objects.clone())
    }

    pub fn recall_current_contexts(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::projections::RecallCurrentContext>, StoreError> {
        self.admission_state
            .recall_current_contexts(self.next_seq.saturating_sub(1), limit)
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
        if Self::existing_profile(&native).await? == Some("L0001") {
            return Err(StoreError::UpgradeRequired);
        }
        Self::open_at_with_lock(lock, &native).await
    }

    pub(crate) async fn existing_profile(
        data_dir: &Path,
    ) -> Result<Option<&'static str>, StoreError> {
        let path = data_dir.join(format!("{JOURNAL_TABLE}.lance"));
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::Io),
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                return Err(StoreError::StoreCorrupt);
            }
            Ok(_) => {}
        }
        let connection = lancedb::connect(data_dir.to_str().ok_or(StoreError::InvalidPath)?)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let journal = connection
            .open_table(JOURNAL_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        validate_journal_table(&journal).await?;
        let rows = read_all_journal_rows(&journal).await?;
        JournalAdmissionState::from_journal_rows(&rows)?;
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
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let migration_outcome = L0002::apply(&connection).await?;
        let journal = connection
            .open_table(JOURNAL_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
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
        validate_journal_table(&journal).await?;
        validate_objects_table(&objects).await?;
        let journal_rows = read_all_journal_rows(&journal).await?;
        let admission_state = JournalAdmissionState::from_journal_rows(&journal_rows)?;
        let next_seq = journal_rows
            .iter()
            .map(|row| row.seq)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StoreError::StoreCorrupt)?;
        Ok(Self {
            _lock: lock,
            connection,
            journal,
            objects,
            relations,
            search,
            next_seq,
            admission_state,
            migration_outcome,
        })
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
            migration_outcome,
        } = self;
        drop((
            connection,
            journal,
            objects,
            relations,
            search,
            next_seq,
            admission_state,
            migration_outcome,
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
        for command in current.commands(self, occurred_at_us, config_hash)? {
            let command = command?;
            let prepared = prepare_command(&command)?;
            let rows = rows_for_append(&prepared, self.next_seq, occurred_at_us)?;
            let admission = self
                .admission_state
                .apply_row_batch(&rows.iter().collect::<Vec<_>>())?;
            self.validate_restore_lock()?;
            reserve_range(&mut self.next_seq, prepared.event_count)?;
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
        let mut rows = read_command_rows(&self.journal, command_id).await?;
        if rows.is_empty() {
            return Ok(None);
        }
        validate_complete_command(&rows)?;
        rows.sort_by_key(|row| row.ordinal);
        let event_ids = rows.iter().map(|row| row.event_id.clone()).collect();
        let payloads = rows
            .iter()
            .map(|row| row.payload())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(CommittedCommand {
            command_id,
            event_ids,
            payloads,
        }))
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
        let existing = read_command_rows(&self.journal, prepared.command_id).await?;
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
        append_rows(&self.journal, &rows).await?;
        self.admission_state = next_admission_state;
        Ok(CommitOutcome {
            command_id: prepared.command_id,
            first_seq,
            last_seq: rows.last().ok_or(StoreError::StoreCorrupt)?.seq,
            event_ids: rows.into_iter().map(|row| row.event_id).collect(),
            replayed: false,
        })
    }

    pub async fn project(&self) -> Result<ProjectionSnapshot, StoreError> {
        let snapshot = ProjectionWorker::new(self.journal.clone(), self.objects.clone())
            .catch_up()
            .await?;
        L0002ProjectionWorker::new(
            self.journal.clone(),
            self.relations.clone(),
            self.search.clone(),
        )
        .catch_up(&snapshot)
        .await?;
        Ok(snapshot)
    }

    pub async fn reconciliation_frontier(
        &self,
        limit: usize,
    ) -> Result<ReconciliationFrontier, StoreError> {
        ProjectionWorker::new(self.journal.clone(), self.objects.clone())
            .reconciliation_frontier(limit)
            .await
    }

    pub async fn reconciliation_artifact_context(
        &self,
        descriptors: &[ReconciliationArtifactDescriptor],
        limit: usize,
    ) -> Result<ReconciliationArtifactFrontier, StoreError> {
        ProjectionWorker::new(self.journal.clone(), self.objects.clone())
            .reconciliation_artifact_context(descriptors, limit)
            .await
    }

    pub async fn full_projection(&self) -> Result<ProjectionSnapshot, StoreError> {
        ProjectionWorker::new(self.journal.clone(), self.objects.clone())
            .full_snapshot()
            .await
    }

    pub async fn journal_rows(&self) -> Result<Vec<crate::JournalRow>, StoreError> {
        read_all_journal_rows(&self.journal).await
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

        let abandoned = reserve_range(&mut writer.next_seq, prepared.event_count).unwrap();
        let first_seq = reserve_range(&mut writer.next_seq, prepared.event_count).unwrap();
        assert_eq!(first_seq, abandoned + u64::from(prepared.event_count));
        let rows = rows_for_append(&prepared, first_seq, 2).unwrap();
        append_rows(&writer.journal, &rows).await.unwrap();
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
    }

    #[tokio::test]
    async fn conditional_commit_is_replay_first_and_compare_before_append() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let initial_frontier = writer.project().await.unwrap().frontier;
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
        let replayed = writer
            .commit_if_frontier(&first, 2, initial_frontier)
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.first_seq, committed.first_seq);
        assert_eq!(
            writer
                .commit_if_frontier(&second, 2, initial_frontier)
                .await,
            Err(StoreError::StaleFrontier)
        );
        assert_eq!(writer.journal_rows().await.unwrap().len(), 3);
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
