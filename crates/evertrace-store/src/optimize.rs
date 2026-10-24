//! Bounded retention maintenance. A mark is process-local and never survives restart.

use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use evertrace_capture::{CasStore, MaintenanceGuard, cas::CasGcCandidate};

use crate::{JournalPayload, StoreError};

/// Scan the authoritative append-only payloads, including revisions suppressed
/// from product projections. The writer owns the table and serializes this scan.
pub(crate) async fn historical_cas_refs(
    journal: &lancedb::Table,
    frontier: u64,
    candidates: &BTreeSet<String>,
) -> Result<BTreeSet<String>, StoreError> {
    let mut retained = BTreeSet::new();
    let mut after = 0_u64;
    let version = journal.version().await.map_err(|_| StoreError::LanceDb)?;
    let mut pending = Vec::<crate::JournalRow>::new();
    let mut pending_bytes = 0_u64;
    let mut seen_commands = BTreeSet::new();
    loop {
        let rows = crate::journal::read_journal_page(journal, after, frontier).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            if row.seq <= after
                || row.seq > frontier
                || row.command_event_count == 0
                || usize::from(row.ordinal) != pending.len()
                || pending.first().is_some_and(|first| {
                    first.command_id != row.command_id
                        || first.command_event_count != row.command_event_count
                        || first.seq.checked_add(pending.len() as u64) != Some(row.seq)
                })
            {
                return Err(StoreError::StoreCorrupt);
            }
            if pending.is_empty()
                && (!seen_commands.insert(row.command_id)
                    || seen_commands.len() > GC_MAX_BYTES as usize / 64)
            {
                return Err(StoreError::StoreCorrupt);
            }
            after = row.seq;
            pending_bytes = pending_bytes
                .checked_add(row.payload_json.len() as u64)
                .filter(|bytes| *bytes <= GC_MAX_BYTES)
                .ok_or(StoreError::StoreCorrupt)?;
            pending.push(row);
            if pending.len() != usize::from(pending[0].command_event_count) {
                continue;
            }
            crate::journal::validate_complete_command(&pending)?;
            for row in pending.drain(..) {
                let payload = row.payload()?;
                let mut refs = BTreeSet::new();
                match payload {
                    JournalPayload::SourceReceiptRecorded(value) => {
                        refs.insert(value.cas_ref);
                    }
                    JournalPayload::WorkArtifactRecorded(value) => {
                        if let Some(id) = value.revision.content_blob_ref {
                            refs.insert(crate::projections::cas_ref_string(id));
                        }
                    }
                    JournalPayload::ResultEvidenceRecorded(value) => {
                        refs.extend(
                            value
                                .raw_cas_refs
                                .iter()
                                .copied()
                                .map(crate::projections::cas_ref_string),
                        );
                    }
                    JournalPayload::RecoveryBundleRecorded(value) => {
                        crate::projections::extend_recovery_bundle_cas_refs(&mut refs, &value);
                    }
                    JournalPayload::RecoveryApplicationRecorded(value) => {
                        refs.extend(
                            value
                                .selected_cas_refs
                                .iter()
                                .copied()
                                .map(crate::projections::cas_ref_string),
                        );
                    }
                    _ => {}
                }
                retained.extend(refs.into_iter().filter(|value| candidates.contains(value)));
            }
            pending_bytes = 0;
        }
    }
    if !pending.is_empty()
        || frontier != 0 && after != frontier
        || journal.version().await.map_err(|_| StoreError::LanceDb)? != version
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(retained)
}

pub const GC_ALGORITHM_REVISION: &str = "two_pass_gc_v1";
pub const GC_GRACE: Duration = Duration::from_secs(24 * 60 * 60);
pub const GC_MAX_FILES: usize = 256;
pub const GC_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const PRUNE_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConservativePruneResult {
    pub table: String,
    pub bytes_removed: Option<u64>,
    pub old_versions: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GcDeletionState {
    Unknown,
    Deleted,
    Missing,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcDeletion {
    pub cas_ref: String,
    pub bytes: u64,
    pub state: GcDeletionState,
}

/// The sole durable result of a GC job. Unknown entries are never inferred to
/// have been deleted by this job merely because their paths are now absent.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcReport {
    pub algorithm_revision: String,
    pub job_id: evertrace_domain::ids::JobId,
    pub mark_watermark: u64,
    pub sweep_watermark: u64,
    pub examined_files: usize,
    pub marked_candidates: usize,
    pub entries: Vec<GcDeletion>,
    pub conservative_prune: Vec<ConservativePruneResult>,
    pub checksum: String,
}

impl GcReport {
    pub fn unknown_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.state == GcDeletionState::Unknown)
            .count()
    }
    pub fn deleted_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.state == GcDeletionState::Deleted)
            .count()
    }
    pub fn deleted_bytes(&self) -> u64 {
        self.entries
            .iter()
            .filter(|entry| entry.state == GcDeletionState::Deleted)
            .map(|entry| entry.bytes)
            .sum()
    }
    fn entries_checksum(&self) -> Result<String, StoreError> {
        // The checksum covers exactly this ordered tuple, excluding itself.
        let bytes = serde_json::to_vec(&(
            &self.algorithm_revision,
            self.job_id,
            self.mark_watermark,
            self.sweep_watermark,
            self.examined_files,
            self.marked_candidates,
            &self.entries,
            &self.conservative_prune,
        ))
        .map_err(|_| StoreError::StoreCorrupt)?;
        evertrace_capture::copy_exact_sha256_hex(
            &mut std::io::Cursor::new(&bytes),
            &mut std::io::sink(),
            bytes.len() as u64,
        )
        .map_err(|_| StoreError::StoreCorrupt)
    }
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.algorithm_revision != GC_ALGORITHM_REVISION
            || self.mark_watermark > self.sweep_watermark
            || self.entries.len() > GC_MAX_FILES
            || self.examined_files > GC_MAX_FILES
            || self.marked_candidates > self.examined_files
            || self.entries.len() > self.marked_candidates
            || self
                .entries
                .windows(2)
                .any(|pair| pair[0].cas_ref >= pair[1].cas_ref)
            || self
                .entries
                .iter()
                .try_fold(0_u64, |sum, entry| sum.checked_add(entry.bytes))
                .is_none_or(|bytes| bytes > GC_MAX_BYTES)
            || self
                .entries
                .iter()
                .any(|entry| CasStore::parse_digest(&entry.cas_ref).is_err())
            || !self.conservative_prune.is_empty()
                && self
                    .conservative_prune
                    .iter()
                    .map(|entry| entry.table.as_str())
                    .ne([
                        crate::JOURNAL_TABLE,
                        crate::OBJECTS_TABLE,
                        crate::RELATIONS_TABLE,
                        crate::SEARCH_TABLE,
                    ])
            || self
                .conservative_prune
                .iter()
                .any(|entry| entry.bytes_removed.is_some() != entry.old_versions.is_some())
            || self.checksum != self.entries_checksum()?
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }
}

pub fn read_gc_report(
    data_dir: &std::path::Path,
    job_id: evertrace_domain::ids::JobId,
) -> Result<GcReport, StoreError> {
    use std::io::Read;
    let root = evertrace_capture::confined_read::ConfinedRoot::open_owned_private(data_dir)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut file = root
        .open_regular_file(
            &std::path::PathBuf::from("maintenance").join(format!("gc-{job_id}.json")),
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::Io)?;
    if bytes.len() > 128 * 1024 {
        return Err(StoreError::StoreCorrupt);
    }
    let report: GcReport = serde_json::from_slice(&bytes).map_err(|_| StoreError::StoreCorrupt)?;
    report.validate()?;
    if report.job_id != job_id {
        return Err(StoreError::StoreCorrupt);
    }
    root.revalidate_stable()
        .map_err(|_| StoreError::StoreCorrupt)?;
    Ok(report)
}

fn publish_report(
    root: &evertrace_capture::confined_read::ConfinedRoot,
    report: &GcReport,
    replace: bool,
) -> Result<(), StoreError> {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};
    report.validate()?;
    root.revalidate_stable()
        .map_err(|_| StoreError::StoreCorrupt)?;
    let directory = root.proc_cwd_path().map_err(|_| StoreError::Io)?;
    let target = directory.join(format!("gc-{}.json", report.job_id));
    if !replace {
        match std::fs::symlink_metadata(&target) {
            Ok(_) => return Err(StoreError::InvalidInput),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Io),
        }
    }
    let temporary = directory.join(format!(".gc-{}.tmp", report.job_id));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| StoreError::Io)?;
    let bytes = serde_json::to_vec(report).map_err(|_| StoreError::StoreCorrupt)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| StoreError::Io)?;
    root.revalidate_stable()
        .map_err(|_| StoreError::StoreCorrupt)?;
    std::fs::rename(&temporary, &target).map_err(|_| StoreError::Io)?;
    std::fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| StoreError::Io)
}

pub(crate) fn delete_and_report(
    data_dir: &std::path::Path,
    guard: &MaintenanceGuard,
    job_id: evertrace_domain::ids::JobId,
    round: &GcRound,
    candidates: &[CasGcCandidate],
    watermark: u64,
) -> Result<GcReport, StoreError> {
    delete_and_report_inner(
        data_dir,
        guard,
        job_id,
        round,
        candidates,
        watermark,
        || Ok(()),
    )
}

fn delete_and_report_inner(
    data_dir: &std::path::Path,
    guard: &MaintenanceGuard,
    job_id: evertrace_domain::ids::JobId,
    round: &GcRound,
    candidates: &[CasGcCandidate],
    watermark: u64,
    after_unlink: impl FnOnce() -> Result<(), StoreError>,
) -> Result<GcReport, StoreError> {
    use std::os::unix::fs::DirBuilderExt;
    guard
        .require_exclusive_for(data_dir)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let directory = data_dir.join("maintenance");
    match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {
            std::fs::File::open(data_dir)
                .and_then(|file| file.sync_all())
                .map_err(|_| StoreError::Io)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(StoreError::Io),
    }
    let root = evertrace_capture::confined_read::ConfinedRoot::open_owned_private(&directory)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut report = GcReport {
        algorithm_revision: GC_ALGORITHM_REVISION.into(),
        job_id,
        mark_watermark: round.mark_watermark,
        sweep_watermark: watermark,
        examined_files: round.examined_files,
        marked_candidates: round.candidate_count(),
        entries: candidates
            .iter()
            .map(|candidate| GcDeletion {
                cas_ref: candidate.digest.as_hex(),
                bytes: candidate.bytes,
                state: GcDeletionState::Unknown,
            })
            .collect(),
        conservative_prune: Vec::new(),
        checksum: String::new(),
    };
    report.entries.sort_by(|a, b| a.cas_ref.cmp(&b.cas_ref));
    report.checksum = report.entries_checksum()?;
    publish_report(&root, &report, false)?;
    CasStore::validate_gc_candidates(guard, candidates).map_err(|_| StoreError::StoreCorrupt)?;
    let digests = report
        .entries
        .iter()
        .map(|entry| CasStore::parse_digest(&entry.cas_ref))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::StoreCorrupt)?;
    let outcomes = CasStore::delete_guarded_batch(guard, &digests).map_err(|_| StoreError::Io)?;
    after_unlink()?;
    for (entry, outcome) in report.entries.iter_mut().zip(outcomes) {
        entry.state = match outcome {
            evertrace_capture::cas::CasDeleteOutcome::Deleted => GcDeletionState::Deleted,
            evertrace_capture::cas::CasDeleteOutcome::Missing => GcDeletionState::Missing,
        };
    }
    report.checksum = report.entries_checksum()?;
    publish_report(&root, &report, true)?;
    Ok(report)
}

pub(crate) async fn conservative_prune(
    data_dir: &std::path::Path,
    tables: [&lancedb::Table; 4],
    mut report: GcReport,
) -> Result<GcReport, StoreError> {
    let root = evertrace_capture::confined_read::ConfinedRoot::open_owned_private(
        &data_dir.join("maintenance"),
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    report.conservative_prune = [
        crate::JOURNAL_TABLE,
        crate::OBJECTS_TABLE,
        crate::RELATIONS_TABLE,
        crate::SEARCH_TABLE,
    ]
    .into_iter()
    .map(|table| ConservativePruneResult {
        table: table.into(),
        bytes_removed: None,
        old_versions: None,
    })
    .collect();
    report.checksum = report.entries_checksum()?;
    publish_report(&root, &report, true)?;
    for (index, table) in tables.into_iter().enumerate() {
        let stats = table
            .optimize(lancedb::table::OptimizeAction::Prune {
                older_than: Some(
                    lancedb::table::Duration::from_std(PRUNE_RETENTION)
                        .map_err(|_| StoreError::InvalidInput)?,
                ),
                delete_unverified: Some(false),
                error_if_tagged_old_versions: Some(true),
            })
            .await
            .map_err(|_| StoreError::LanceDb)?
            .prune
            .ok_or(StoreError::StoreCorrupt)?;
        report.conservative_prune[index].bytes_removed = Some(stats.bytes_removed);
        report.conservative_prune[index].old_versions = Some(stats.old_versions);
        report.checksum = report.entries_checksum()?;
        publish_report(&root, &report, true)?;
    }
    Ok(report)
}

/// Only the writer-owned maintenance path constructs a mark after collecting
/// authoritative journal, spool and managed-backup references under the fence.
pub struct GcRound {
    candidates: Vec<CasGcCandidate>,
    marked_at: Instant,
    pub(crate) mark_watermark: u64,
    examined_files: usize,
}

pub struct GcScanPage {
    pub cursor: evertrace_capture::cas::CasGcCursor,
    pub round: GcRound,
}

impl GcRound {
    pub(crate) fn mark(
        candidates: Vec<CasGcCandidate>,
        references: &BTreeSet<String>,
        watermark: u64,
        now: Instant,
    ) -> Self {
        Self {
            examined_files: candidates.len(),
            candidates: candidates
                .into_iter()
                .filter(|candidate| !references.contains(&candidate.digest.as_hex()))
                .collect(),
            marked_at: now,
            mark_watermark: watermark,
        }
    }

    pub fn ready_at(&self) -> Instant {
        self.marked_at + GC_GRACE
    }

    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    pub(crate) fn candidates(&self) -> BTreeSet<String> {
        self.candidates
            .iter()
            .map(|candidate| candidate.digest.as_hex())
            .collect()
    }

    pub(crate) fn sweep_candidates(
        &self,
        guard: &MaintenanceGuard,
        references: &BTreeSet<String>,
        now: Instant,
    ) -> Result<Vec<CasGcCandidate>, StoreError> {
        if !self.candidates.is_empty() && now < self.ready_at() {
            return Err(StoreError::InvalidInput);
        }
        let candidates = self
            .candidates
            .iter()
            .filter(|candidate| !references.contains(&candidate.digest.as_hex()))
            .cloned()
            .collect::<Vec<_>>();
        CasStore::validate_gc_candidates(guard, &candidates)
            .map_err(|_| StoreError::StoreCorrupt)?;
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use evertrace_capture::{DeviceKeyStore, DurableSpool, RuntimeSnapshot};
    use evertrace_domain::ids::JobId;

    async fn fixture() -> (
        tempfile::TempDir,
        crate::JournalWriter,
        RuntimeSnapshot,
        CasStore,
    ) {
        let temporary = tempfile::TempDir::new().unwrap();
        let data = temporary.path().join("data");
        let writer = crate::JournalWriter::open(&data).await.unwrap();
        let runtime = runtime_for(&data);
        let cas = CasStore::open(runtime.cas_dir.clone()).unwrap();
        DurableSpool::open(runtime.spool_dir.clone(), runtime.spool_limits().unwrap()).unwrap();
        (temporary, writer, runtime, cas)
    }

    fn runtime_for(data: &std::path::Path) -> RuntimeSnapshot {
        RuntimeSnapshot {
            snapshot_version: evertrace_capture::runtime_snapshot::RUNTIME_SNAPSHOT_VERSION,
            generation: 1,
            device_key_dir: data.join("keys"),
            cas_dir: data.join("cas"),
            spool_dir: data.join("spool"),
            main_high_watermark_bytes: 4 * 1024 * 1024,
            main_low_watermark_bytes: 64 * 1024,
            max_main_files: 16,
            emergency_slots: 2,
            recovery_gate: evertrace_capture::runtime_snapshot::RecoveryGateMode::Disabled,
            recovery_socket_path: data.join("runtime/evertraced-v1.sock"),
            recovery_preflight_timeout_ms: 250,
            effective_config_hash: [1; 32],
            recovery_adapter_manifest_id: None,
            recovery_classifier_revision: 1,
            recovery_max_bundle_bytes: 4 << 20,
            recovery_max_untracked_file_bytes: 1 << 20,
            recovery_max_untracked_total_bytes: 2 << 20,
            recall_cue_gate: evertrace_capture::runtime_snapshot::RecallCueGateMode::Disabled,
            recall_cue_adapter_manifest_id: None,
            recall_cues: Vec::new(),
        }
    }

    fn blob(
        runtime: &RuntimeSnapshot,
        cas: &CasStore,
        bytes: &[u8],
    ) -> evertrace_capture::CasDigest {
        let key = DeviceKeyStore::new(runtime.device_key_dir.clone())
            .load_or_create()
            .unwrap();
        cas.put(&evertrace_capture::protect::protect(bytes, &key).unwrap())
            .unwrap()
    }

    #[tokio::test]
    async fn l0001_requires_upgrade_and_has_an_independently_verifiable_backup() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let temporary = tempfile::TempDir::new().unwrap();
        let data = temporary.path().join("data");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&data)
            .unwrap();
        let connection = lancedb::connect(data.to_str().unwrap())
            .execute()
            .await
            .unwrap();
        crate::migrations::L0001::apply(&connection).await.unwrap();
        drop(connection);
        assert!(matches!(
            crate::JournalWriter::open(&data).await,
            Err(StoreError::UpgradeRequired)
        ));
        assert!(
            !data
                .join(format!("{}.lance", crate::RELATIONS_TABLE))
                .exists()
        );
        let _lock = crate::SiblingWriterLock::acquire(&data).unwrap();
        let (states, snapshot) = crate::backup::read_verified_store_tables(&data)
            .await
            .unwrap();
        assert!(states.relations.is_none() && states.search.is_none());
        let mut runtime = runtime_for(&data);
        let config = evertrace_domain::config::EffectiveConfig::default();
        runtime.effective_config_hash = config.hash();
        runtime
            .publish(&RuntimeSnapshot::snapshot_path(&data))
            .unwrap();
        let config_path = temporary.path().join("config.toml");
        std::fs::write(&config_path, config.to_toml().unwrap()).unwrap();
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        CasStore::open(runtime.cas_dir.clone()).unwrap();
        let (mut spool, _) =
            DurableSpool::open(runtime.spool_dir.clone(), runtime.spool_limits().unwrap()).unwrap();
        let fence = evertrace_capture::MaintenanceFence::open(&data).unwrap();
        let guard = fence.exclusive().unwrap();
        let boundary = crate::backup::BackupFrozenBoundary {
            spool: spool
                .freeze_backup_boundary(&guard, runtime.generation)
                .unwrap(),
            hook: crate::backup::BackupHookBoundary {
                current_generation: None,
                retained_generations: Vec::new(),
                pin_count: 0,
                pinned_generation_count: 0,
                files: Vec::new(),
            },
        };
        drop(guard);
        let id = JobId::new_v7();
        let plan = crate::backup::prepare_backup(
            (&data, &data),
            &config_path,
            &runtime,
            id,
            &snapshot,
            states,
            boundary,
        )
        .unwrap();
        let staging = crate::backup::stage_backup(plan).unwrap();
        let summary = crate::backup::verify_staged_backup(&staging).await.unwrap();
        crate::backup::publish_backup(staging, summary).unwrap();
        let backup = data.join(format!("backups/backup-{id}"));
        let isolated = temporary.path().join("independent-backup");
        std::fs::rename(backup, &isolated).unwrap();
        drop((spool, fence, _lock));
        std::fs::rename(&data, temporary.path().join("old-live")).unwrap();
        let verified = crate::backup::prepare_verification_directory(&isolated, Some(id)).unwrap();
        let summary = crate::backup::complete_backup_verification(verified)
            .await
            .unwrap();
        assert!(summary.table_states.relations.is_none() && summary.table_states.search.is_none());
    }

    #[tokio::test]
    async fn real_gc_grace_restart_delete_report_and_conservative_prune() {
        let (_temporary, writer, runtime, cas) = fixture().await;
        let digest = blob(&runtime, &cas, b"unreferenced pre-transaction orphan");
        let bytes = cas.encoded_blob_length(&digest).unwrap();
        let round = writer.mark_gc(&runtime, 0).await.unwrap();
        assert!(
            writer
                .sweep_gc(&runtime, JobId::new_v7(), &round)
                .await
                .is_err()
        );
        assert!(cas.read(&digest).is_ok());
        let old_ready = round.ready_at();
        drop(round);
        drop(writer);
        let writer = crate::JournalWriter::open(runtime.data_dir().unwrap())
            .await
            .unwrap();
        let connection = lancedb::connect(
            crate::connection::native_root(runtime.data_dir().unwrap())
                .to_str()
                .unwrap(),
        )
        .execute()
        .await
        .unwrap();
        let journal = connection
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        let version = journal.version().await.unwrap();
        journal
            .tags()
            .await
            .unwrap()
            .create("retention-test-pin", version)
            .await
            .unwrap();
        let versions_before = journal.list_versions().await.unwrap().len();
        let mut restarted = writer.mark_gc(&runtime, 0).await.unwrap();
        assert!(restarted.ready_at() > old_ready);
        assert!(
            writer
                .sweep_gc(&runtime, JobId::new_v7(), &restarted)
                .await
                .is_err()
        );
        // Private test-only clock seam; production always uses Instant::now.
        restarted.marked_at = Instant::now() - GC_GRACE;
        let job = JobId::new_v7();
        let report = writer.sweep_gc(&runtime, job, &restarted).await.unwrap();
        assert!(matches!(
            cas.read(&digest),
            Err(evertrace_capture::CasError::NotFound)
        ));
        assert_eq!(
            (
                report.deleted_count(),
                report.deleted_bytes(),
                report.unknown_count()
            ),
            (1, bytes, 0)
        );
        assert_eq!(report.conservative_prune.len(), 4);
        assert!(
            report
                .conservative_prune
                .iter()
                .all(|result| result.old_versions == Some(0))
        );
        assert_eq!(
            journal.list_versions().await.unwrap().len(),
            versions_before
        );
        journal.checkout_tag("retention-test-pin").await.unwrap();
        assert_eq!(journal.version().await.unwrap(), version);
        assert_eq!(
            read_gc_report(runtime.data_dir().unwrap(), job).unwrap(),
            report
        );
        writer.full_projection().await.unwrap();
    }

    #[tokio::test]
    async fn gc_cursor_consumes_oversize_entries_without_blocking_small_files() {
        let (_temporary, _writer, runtime, cas) = fixture().await;
        let oversized = blob(&runtime, &cas, &vec![b'x'; 1024]);
        let small = blob(&runtime, &cas, b"small");
        let guard = evertrace_capture::MaintenanceFence::open(runtime.data_dir().unwrap())
            .unwrap()
            .exclusive()
            .unwrap();
        assert_ne!(oversized.as_bytes()[0], small.as_bytes()[0]);
        let mut cursor = evertrace_capture::cas::CasGcCursor::new(oversized.as_bytes()[0]);
        assert!(
            cas.gc_candidates(&guard, &mut cursor, 1, 128)
                .unwrap()
                .is_empty()
        );
        assert!(!cursor.finished());
        let mut selected = Vec::new();
        for _ in 0..3 {
            selected.extend(cas.gc_candidates(&guard, &mut cursor, 1, 128).unwrap());
            if cursor.finished() {
                break;
            }
        }
        assert!(cursor.finished());
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].digest, small);
        assert!(cas.read(&oversized).is_ok());
    }

    #[tokio::test]
    async fn gc_envelope_work_is_cumulatively_bounded_and_allows_shared_capture() {
        let (_temporary, _writer, runtime, cas) = fixture().await;
        blob(&runtime, &cas, &vec![b'x'; 1024]);
        blob(&runtime, &cas, &vec![b'y'; 1024]);
        let fence = evertrace_capture::MaintenanceFence::open(runtime.data_dir().unwrap()).unwrap();
        let guard = fence.exclusive().unwrap();
        let candidates = cas
            .gc_candidates(
                &guard,
                &mut evertrace_capture::cas::CasGcCursor::new(0),
                256,
                1500,
            )
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].bytes < 1500);
        drop(guard);
        let shared = fence.shared().unwrap();
        cas.verify_gc_candidates(&candidates).unwrap();
        drop(shared);
        let guard = fence.exclusive().unwrap();
        CasStore::validate_gc_candidates(&guard, &candidates).unwrap();
    }

    #[tokio::test]
    async fn gc_backup_authority_is_verified_without_exclusive_and_rejects_changed_inputs() {
        use std::os::unix::fs::PermissionsExt;
        let (_temporary, mut writer, mut runtime, cas) = fixture().await;
        let config = evertrace_domain::config::EffectiveConfig::default();
        runtime.effective_config_hash = config.hash();
        runtime
            .publish(&RuntimeSnapshot::snapshot_path(runtime.data_dir().unwrap()))
            .unwrap();
        let config_path = runtime.data_dir().unwrap().join("config.toml");
        std::fs::write(&config_path, config.to_toml().unwrap()).unwrap();
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        writer
            .commit(
                &crate::JournalCommand::new(
                    evertrace_domain::ids::CommandId::new_v7(),
                    vec![crate::JournalEventDraft::runtime(
                        1,
                        config.hash(),
                        "objects-projection-v1",
                        JournalPayload::DirtyTarget(crate::DirtyTarget {
                            target_kind: crate::DirtyTargetKind::ObjectsProjection,
                            target_id: "gc-backup-authority".into(),
                            algorithm_revision: "objects-projection-v1".into(),
                            source_watermark: 1,
                        }),
                    )],
                )
                .unwrap(),
                1,
            )
            .await
            .unwrap();
        writer.rebuild_restore_projections().await.unwrap();
        let snapshot = writer.project().await.unwrap();
        let states = writer.backup_table_states().await.unwrap();
        let fence = evertrace_capture::MaintenanceFence::open(runtime.data_dir().unwrap()).unwrap();
        let guard = fence.exclusive().unwrap();
        let mut spool = DurableSpool::open_read_only(
            runtime.spool_dir.clone(),
            runtime.spool_limits().unwrap(),
        )
        .unwrap();
        let boundary = crate::backup::BackupFrozenBoundary {
            spool: spool
                .freeze_backup_boundary(&guard, runtime.generation)
                .unwrap(),
            hook: crate::backup::BackupHookBoundary {
                current_generation: None,
                retained_generations: Vec::new(),
                pin_count: 0,
                pinned_generation_count: 0,
                files: Vec::new(),
            },
        };
        drop(guard);
        let backup_id = JobId::new_v7();
        let (closed, staging) = writer.close_for_backup().stage_backup(
            config_path,
            runtime.clone(),
            backup_id,
            snapshot,
            states,
            boundary,
        );
        let staging = staging.unwrap();
        let summary = closed.verify_staged_backup(&staging).await.unwrap();
        let (closed, result) = closed.publish_staged_backup(staging, summary);
        result.unwrap();
        let writer = closed.reopen().await.unwrap();
        let orphan = blob(&runtime, &cas, b"not in the verified backup");
        let ids = BTreeSet::from([orphan.as_hex()]);
        // The actual complete journal/backup authority path runs while a Hook
        // shared fence is held; no timing assumption or shortened clock.
        let shared = fence.shared().unwrap();
        let authority = writer.gc_authority(&runtime, &ids).await.unwrap();
        drop(shared);
        let guard = fence.exclusive().unwrap();
        authority.revalidate(runtime.data_dir().unwrap()).unwrap();
        let backup = runtime
            .data_dir()
            .unwrap()
            .join(format!("backups/backup-{backup_id}"));
        let config = backup.join("config/config.toml");
        let bytes = std::fs::read(&config).unwrap();
        std::fs::write(&config, b"changed after verification").unwrap();
        assert!(authority.revalidate(runtime.data_dir().unwrap()).is_err());
        drop(guard);
        std::fs::write(&config, &bytes).unwrap();
        let authority = writer.gc_authority(&runtime, &ids).await.unwrap();
        let saved = config.with_extension("saved");
        std::fs::rename(&config, &saved).unwrap();
        std::fs::write(&config, &bytes).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(authority.revalidate(runtime.data_dir().unwrap()).is_err());
        std::fs::remove_file(&config).unwrap();
        std::fs::rename(saved, &config).unwrap();
        let authority = writer.gc_authority(&runtime, &ids).await.unwrap();
        std::fs::create_dir(runtime.data_dir().unwrap().join("backups/new-staging")).unwrap();
        assert!(authority.revalidate(runtime.data_dir().unwrap()).is_err());
        assert!(cas.read(&orphan).is_ok());
    }

    #[tokio::test]
    async fn gc_rechecks_identity_and_unknown_report_survives_unlink_failure_boundary() {
        let (_temporary, writer, runtime, cas) = fixture().await;
        let digest = blob(&runtime, &cas, b"gc identity candidate");
        let mut round = writer.mark_gc(&runtime, 0).await.unwrap();
        round.marked_at = Instant::now() - GC_GRACE;
        let path = cas.blob_path(&digest);
        std::fs::rename(&path, path.with_extension("held")).unwrap();
        blob(&runtime, &cas, b"gc identity candidate");
        assert!(
            writer
                .sweep_gc(&runtime, JobId::new_v7(), &round)
                .await
                .is_err()
        );
        assert!(cas.read(&digest).is_ok());
        std::fs::remove_file(path.with_extension("held")).unwrap();
        let mut round = writer.mark_gc(&runtime, 0).await.unwrap();
        round.marked_at = Instant::now() - GC_GRACE;
        let data = runtime.data_dir().unwrap();
        let guard = evertrace_capture::MaintenanceFence::open(data)
            .unwrap()
            .exclusive()
            .unwrap();
        let candidates = round
            .sweep_candidates(&guard, &BTreeSet::new(), Instant::now())
            .unwrap();
        let job = JobId::new_v7();
        assert!(
            delete_and_report_inner(
                data,
                &guard,
                job,
                &round,
                &candidates,
                writer.frontier(),
                || Err(StoreError::Io)
            )
            .is_err()
        );
        drop(guard);
        assert!(!path.exists());
        drop(writer);
        let writer = crate::JournalWriter::open(data).await.unwrap();
        let report = read_gc_report(data, job).unwrap();
        assert_eq!(
            (
                report.deleted_count(),
                report.deleted_bytes(),
                report.unknown_count()
            ),
            (0, 0, 1)
        );
        let restarted = writer.mark_gc(&runtime, 0).await.unwrap();
        assert!(Instant::now() < restarted.ready_at());
        assert_eq!(read_gc_report(data, job).unwrap(), report);
    }

    #[tokio::test]
    async fn historical_scan_validates_complete_commands_across_pages_and_rejects_bad_hash() {
        let (_temporary, mut writer, runtime, _cas) = fixture().await;
        let events = (0..257)
            .map(|index| {
                crate::JournalEventDraft::runtime(
                    1,
                    [1; 32],
                    "objects-projection-v1",
                    JournalPayload::DirtyTarget(crate::DirtyTarget {
                        target_kind: crate::DirtyTargetKind::ObjectsProjection,
                        target_id: format!("gc-page-{index}"),
                        algorithm_revision: "objects-projection-v1".into(),
                        source_watermark: 1,
                    }),
                )
            })
            .collect();
        writer
            .commit(
                &crate::JournalCommand::new(evertrace_domain::ids::CommandId::new_v7(), events)
                    .unwrap(),
                1,
            )
            .await
            .unwrap();
        writer
            .historical_cas_refs_intersect(&BTreeSet::new())
            .await
            .unwrap();
        let frontier = writer.frontier();
        let mut rows = writer.journal_rows().await.unwrap();
        drop(writer);
        let connection = lancedb::connect(
            crate::connection::native_root(runtime.data_dir().unwrap())
                .to_str()
                .unwrap(),
        )
        .execute()
        .await
        .unwrap();
        let journal = connection
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        rows.last_mut().unwrap().content_hash[0] ^= 1;
        journal.delete("true").await.unwrap();
        crate::journal::append_rows(&journal, &rows).await.unwrap();
        assert!(
            historical_cas_refs(&journal, frontier, &BTreeSet::new())
                .await
                .is_err()
        );
    }
}
