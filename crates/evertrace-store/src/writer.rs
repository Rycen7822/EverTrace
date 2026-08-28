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
    command::{CommitOutcome, JournalCommand, StoreError, prepare_command},
    journal::{
        JOURNAL_TABLE, append_rows, read_all_journal_rows, read_command_rows,
        read_journal_frontier, replay_outcome, rows_for_append, validate_journal_table,
    },
    migrations::{L0002, MigrationOutcome},
    objects::{OBJECTS_TABLE, read_object_rows, validate_objects_table},
    projections::{
        JournalAdmissionState, ProjectionSnapshot, ProjectionWorker,
        ReconciliationArtifactDescriptor, ReconciliationArtifactFrontier, ReconciliationFrontier,
    },
    query::L0002ProjectionWorker,
    relations::RELATIONS_TABLE,
    search::SEARCH_TABLE,
};

#[derive(Debug)]
pub struct SiblingWriterLock {
    data_dir: PathBuf,
    lock_path: PathBuf,
    file: File,
}

impl SiblingWriterLock {
    pub fn acquire(data_dir: &Path) -> Result<Self, StoreError> {
        validate_lexical_data_dir(data_dir)?;
        let parent = data_dir.parent().ok_or(StoreError::InvalidPath)?;
        validate_parent(parent)?;
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
        Ok(Self {
            data_dir: data_dir.to_owned(),
            lock_path,
            file,
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
    pub async fn open(data_dir: &Path) -> Result<Self, StoreError> {
        let lock = SiblingWriterLock::acquire(data_dir)?;
        let connection = lancedb::connect(data_dir.to_str().ok_or(StoreError::InvalidPath)?)
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

    pub const fn migration_outcome(&self) -> MigrationOutcome {
        self.migration_outcome
    }

    pub fn lock_path(&self) -> &Path {
        self._lock.lock_path()
    }

    pub fn lock_inode_identity(&self) -> Result<(u64, u64), StoreError> {
        self._lock.inode_identity()
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

    async fn commit_inner(
        &mut self,
        command: &JournalCommand,
        ingested_at_us: i64,
        expected_frontier: Option<u64>,
    ) -> Result<CommitOutcome, StoreError> {
        if ingested_at_us < 0 {
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
