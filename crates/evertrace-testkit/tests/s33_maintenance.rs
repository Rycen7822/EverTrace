//! S33 Repository physical purge authority, bounded CAS deletion, and restart proof.

use std::{
    collections::BTreeSet, io::Cursor, os::unix::fs::PermissionsExt, path::Path, process::Command,
    sync::Arc, time::Duration,
};

use evertrace_capture::{
    CaptureOutcome, CaptureRecordInput, CaptureRuntime, CasError, CasStore, DeviceKeyStore,
    DurableSpool, RUNTIME_SNAPSHOT_VERSION, RecallCueGateMode, RecoveryGateMode, RuntimeSnapshot,
    SpoolLimits, copy_exact_sha256_hex,
};
use evertrace_codex::install::{HookGeneration, StableLauncher};
use evertrace_domain::{
    config::{DreamingConfig, EffectiveConfig, GlobalPromotionConfig, LlmConfig},
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceObservation,
        SourceReceipt, SourceRevision, SourceRevisionMode, SourceRole,
    },
    ids::{
        CasId, CommandId, ExecutionLaneId, JobId, PresentationAttemptId, RepositoryId, RequestId,
        TaskId, WorkArtifactId, WorkstreamId, WorktreeId,
    },
    recall::RecallCueSnapshot,
    repository::{
        FilesystemIdentity, GitObjectFormat, GitRegistrationState, PathObservation,
        RepositoryInstance, WorktreeInstance, WorktreeKind, WorktreeLifecycle,
    },
    revision::RevisionId,
    semantic::{
        ApplicabilityExpr, AtomDraft, AtomKind, AtomProposalPayload, AtomProvenance, AtomScope,
        AtomValue, ConstraintExpr, ConstraintField, ConstraintValue, EpistemicStatus,
        ProposalCreatedBy, ProposalEligibility, ProposalOperation, ProposalPayload,
        ProposalTargetKind, SemanticQualifier, ValidityInterval,
    },
    work::{
        ArtifactDerivability, ArtifactPayloadStatus, ArtifactRetention, ArtifactRevision,
        ArtifactScope, PhaseContract, PhaseKind, Task, TaskIdentityConfidence, TaskLifecycle,
        TaskScopeMembership, WorkArtifact, WorkArtifactKind, Workstream, WorkstreamStatus,
    },
};
use evertrace_engine::repository::{
    HostTrustDecision, ProbeLimits, RepositoryResolveInput, probe_repository, resolve_repository,
};
use evertrace_engine::semantic::{
    AtomAcceptanceContext, ProposalCommandContext, ProposalResolution, RevisionProposalService,
    SubmitProposalRequest,
};
use evertrace_engine::session_import::SessionCatalogService;
use evertrace_engine::{
    BackgroundScheduler, EvidenceIngestor, HumanActionOutcome, HumanGovernanceService,
    HumanSurface, HumanSystemDetail, SessionImportWorker, SynthesisPlanner, spawn_writer,
    work::{WorkCommandContext, activate_episode, new_episode},
};
use evertrace_store::{
    BackupManifest, DurableJob, JobBudget, JobLease, JobStatus, JobTerminalReason, JournalCommand,
    JournalEventDraft, JournalPayload, JournalWriter, QUIESCED_BACKUP_CREATE_JOB_KIND,
    RuntimeSchedulerView, ScopePurgeCurrentView, SemanticCurrentView, SessionBodyState,
    SessionImportCurrentView, StoreError,
    repository::RepositoryCurrentView,
    session_import::{
        BodyStateReason, MetadataState, SessionImportEvent, SessionImportEventKind,
        SessionMetadata, WorkspaceResolutionKind,
    },
    verify_backup,
};
use tempfile::TempDir;
use tokio::sync::{RwLock, mpsc};

const CONFIG: [u8; 32] = [0x73; 32];
const ALGORITHM: &str = "s33-test-v1";

#[tokio::test]
async fn offline_restore_imports_current_pending_scope_without_reviving_candidate_rows() {
    let root = TempDir::new().unwrap();
    let data = root.path().join("data");
    let mut config_file = EffectiveConfig::default().config().clone();
    config_file.runtime.data_dir = data.to_str().unwrap().to_owned();
    let effective = EffectiveConfig::new(config_file).unwrap();
    let config = root.path().join("config.toml");
    std::fs::write(&config, effective.to_toml().unwrap()).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let writer = JournalWriter::open(&data).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 8).unwrap();
    let mut runtime = runtime_snapshot(&data);
    runtime.effective_config_hash = effective.hash();
    let old_key = DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    let old_tag =
        evertrace_capture::protect::mcp_call_auth_tag(b"restore-keyed-authority", &old_key)
            .unwrap();
    let old_cache_identity =
        evertrace_capture::protect::recovery_path_token(b"restore-keyed-cache", &old_key).unwrap();
    runtime
        .publish(&RuntimeSnapshot::snapshot_path(&data))
        .unwrap();
    let _ = DurableSpool::open(runtime.spool_dir.clone(), runtime.spool_limits().unwrap()).unwrap();
    CasStore::open(runtime.cas_dir.clone()).unwrap();
    let repository_id = RepositoryId::new_v7();
    handle
        .commit(
            repository_command(repository(repository_id, "/restore-target", 1), 1),
            1,
        )
        .await
        .unwrap();
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    let CaptureOutcome::Durable { cas_digest, .. } = capture
        .capture(capture_input(
            "restore-deleted",
            repository_id,
            b"restore deleted evidence",
        ))
        .unwrap()
    else {
        panic!("durable capture required")
    };
    EvidenceIngestor::new(runtime.clone(), handle.clone(), effective.hash(), ALGORITHM)
        .unwrap()
        .drain_once()
        .await
        .unwrap();
    drop(capture);
    let stale_job_id = JobId::new_v7();
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    1,
                    effective.hash(),
                    "objects-projection-v1",
                    JournalPayload::JobState(DurableJob {
                        job_id: stale_job_id,
                        kind: "objects_projection".into(),
                        idempotency_key: "objects_projection:obsolete-restore-target".into(),
                        target_revision: "obsolete-restore-target".into(),
                        target_watermark: 1,
                        target_generation: 1,
                        algorithm_revision: "objects-projection-v1".into(),
                        model_id: None,
                        config_hash: effective.hash(),
                        budget: JobBudget {
                            max_items: 1,
                            max_bytes: None,
                            max_input_tokens: None,
                            max_output_tokens: None,
                            max_calls: None,
                            max_wall_time_ms: 250,
                        },
                        state: JobStatus::Queued,
                        priority: 1,
                        attempt: 1,
                        lease_until_us: None,
                        backoff_until_us: None,
                        terminal: None,
                    }),
                )],
            )
            .unwrap(),
            1,
        )
        .await
        .unwrap();
    let backup_id = JobId::new_v7();
    handle
        .create_backup(backup_id, config.clone(), runtime.clone())
        .await
        .unwrap()
        .unwrap();
    let before = handle.project().await.unwrap();
    let preview =
        evertrace_store::repository_scope_purge_preview(&before, repository_id, 1).unwrap();
    let command = evertrace_engine::purge::pending_repository_purge_command(
        RequestId::new_v7(),
        &preview,
        preview.deletion_generation,
        2,
        before.frontier,
        CONFIG,
    )
    .unwrap();
    handle.commit(command, 2).await.unwrap();
    let current = ScopePurgeCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();
    let backup = root.path().join("external-backup");
    std::fs::rename(
        data.join("backups").join(format!("backup-{backup_id}")),
        &backup,
    )
    .unwrap();
    let manifest_before = std::fs::read(backup.join("manifest.json")).unwrap();
    let entries_before = std::fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<BTreeSet<_>>();
    // Invalid command time fails after the verified copy, not before candidate creation.
    assert!(matches!(
        evertrace_store::restore::prepare(&data, &backup, -1, CONFIG).await,
        Err(evertrace_store::restore::RestoreError::Store(
            StoreError::InvalidInput
        ))
    ));
    assert_eq!(
        std::fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>(),
        entries_before
    );
    assert_eq!(
        std::fs::read(backup.join("manifest.json")).unwrap(),
        manifest_before
    );
    let prepared = evertrace_store::restore::prepare(&data, &backup, 3, CONFIG)
        .await
        .unwrap();
    let evertrace_store::restore::RestorePreparation::Candidate(candidate) = prepared else {
        panic!("validated current ledger must prepare a candidate");
    };
    assert!(matches!(
        JournalWriter::open(&data).await,
        Err(StoreError::WriterAlreadyRunning)
    ));
    let full = candidate.full_projection().await.unwrap();
    let restored = ScopePurgeCurrentView::from_snapshot(&full).unwrap();
    let previous = current.events.get(&repository_id).unwrap();
    let terminal = restored.events.get(&repository_id).unwrap();
    assert_eq!(
        terminal.stage,
        evertrace_domain::purge::ScopePurgeStage::Purged
    );
    assert_eq!(terminal.target, previous.target);
    assert_eq!(terminal.deletion_generation, previous.deletion_generation);
    assert_eq!(
        terminal.confirmation_frontier,
        previous.confirmation_frontier
    );
    assert_eq!(terminal.purge_job_id, previous.purge_job_id);
    let digest = CasStore::parse_digest(&cas_digest).unwrap();
    assert!(
        !CasStore::open(candidate.path().join("cas"))
            .unwrap()
            .blob_path(&digest)
            .exists()
    );
    assert!(
        CasStore::open(data.join("cas"))
            .unwrap()
            .blob_path(&digest)
            .exists()
    );
    assert!(
        !full
            .data_rows()
            .any(|row| row.object_id.as_deref() == Some(repository_id.to_string().as_str()))
    );
    assert_eq!(
        std::fs::read(backup.join("manifest.json")).unwrap(),
        manifest_before
    );
    drop(candidate);
    let mut live = JournalWriter::open(&data).await.unwrap();
    let reserved = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            4,
            CONFIG,
            "offline_restore_ledger_v1",
            JournalPayload::RepositoryInstanceRecorded(Box::new(repository(
                RepositoryId::new_v7(),
                "/forged",
                4,
            ))),
        )],
    )
    .unwrap();
    assert_eq!(
        live.commit(&reserved, 4).await,
        Err(StoreError::InvalidInput)
    );
    let (handle, actor) = spawn_writer(live, 8).unwrap();
    let background = scheduler(handle.clone(), runtime);
    background.run_once().await.unwrap();
    background.run_once().await.unwrap();
    let interrupted =
        ScopePurgeCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let progress = interrupted.events.get(&repository_id).unwrap();
    assert_eq!(
        progress.stage,
        evertrace_domain::purge::ScopePurgeStage::PhysicalDeleting
    );
    assert_eq!(progress.next_ordinal, 1);
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();
    let prepared =
        evertrace_store::restore::prepare(&data, &backup, progress.recorded_at_us + 1, CONFIG)
            .await
            .unwrap();
    let evertrace_store::restore::RestorePreparation::Candidate(candidate) = prepared else {
        panic!("intermediate deletion must prepare a candidate");
    };
    assert!(
        !CasStore::open(candidate.path().join("cas"))
            .unwrap()
            .blob_path(&digest)
            .exists()
    );
    let restored =
        ScopePurgeCurrentView::from_snapshot(&candidate.full_projection().await.unwrap()).unwrap();
    assert_eq!(
        restored.events.get(&repository_id).unwrap().stage,
        evertrace_domain::purge::ScopePurgeStage::Purged
    );
    // The second post-swap validation fails after configuration publication.
    // Both names must return to their original identity/content under one lock.
    let old_config = std::fs::read(&config).unwrap();
    let external_config_root =
        TempDir::new_in("/dev/shm").unwrap_or_else(|_| TempDir::new().unwrap());
    if std::os::unix::fs::MetadataExt::dev(&external_config_root.path().metadata().unwrap())
        == std::os::unix::fs::MetadataExt::dev(&root.path().metadata().unwrap())
    {
        eprintln!(
            "cross-filesystem configuration proof unavailable: temporary directories share a device"
        );
    }
    let external_config = external_config_root.path().join("config.toml");
    std::fs::write(&external_config, &old_config).unwrap();
    std::fs::set_permissions(&external_config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let replacement_config = [old_config.as_slice(), b"\n# restored configuration\n"].concat();
    let validations = std::cell::Cell::new(0);
    let failure = candidate
        .activate(&external_config, &replacement_config, |root| {
            assert_child_fence_busy(root, "writer");
            assert_child_fence_busy(root, "shared");
            validations.set(validations.get() + 1);
            if validations.get() == 2 {
                assert_eq!(std::fs::read(&external_config).unwrap(), replacement_config);
                Err(evertrace_store::restore::RestoreError::Io)
            } else {
                Ok(())
            }
        })
        .await;
    assert!(failure.is_err());
    assert_eq!(validations.get(), 2);
    assert_eq!(std::fs::read(&config).unwrap(), old_config);
    assert_eq!(std::fs::read(&external_config).unwrap(), old_config);
    let live = JournalWriter::open(&data).await.unwrap();
    assert_eq!(
        ScopePurgeCurrentView::from_snapshot(&live.full_projection().await.unwrap())
            .unwrap()
            .events
            .get(&repository_id)
            .unwrap()
            .stage,
        evertrace_domain::purge::ScopePurgeStage::PhysicalDeleting
    );
    drop(live);
    let config_failure_parent = root.path().join("config-publish-failure");
    std::fs::create_dir(&config_failure_parent).unwrap();
    std::fs::set_permissions(
        &config_failure_parent,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let unwritable_config = config_failure_parent.join("config.toml");
    std::fs::write(&unwritable_config, &old_config).unwrap();
    std::fs::set_permissions(&unwritable_config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let evertrace_store::restore::RestorePreparation::Candidate(candidate) =
        evertrace_store::restore::prepare(&data, &backup, progress.recorded_at_us + 1, CONFIG)
            .await
            .unwrap()
    else {
        panic!("candidate required")
    };
    let failure = candidate
        .activate(&unwritable_config, &old_config, |_| {
            std::fs::set_permissions(
                &config_failure_parent,
                std::fs::Permissions::from_mode(0o500),
            )
            .unwrap();
            Ok(())
        })
        .await;
    std::fs::set_permissions(
        &config_failure_parent,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let Err(evertrace_store::restore::RestoreError::ResidualConfiguration {
        temporary, saved, ..
    }) = failure
    else {
        panic!("unwritable configuration staging must report its retained locators");
    };
    assert_eq!(temporary.parent(), Some(config_failure_parent.as_path()));
    assert_eq!(saved.parent(), Some(config_failure_parent.as_path()));
    assert!(temporary.exists() && saved.exists());
    assert_eq!(std::fs::read(&unwritable_config).unwrap(), old_config);
    let live = JournalWriter::open(&data).await.unwrap();
    assert_eq!(
        ScopePurgeCurrentView::from_snapshot(&live.full_projection().await.unwrap())
            .unwrap()
            .events
            .get(&repository_id)
            .unwrap()
            .stage,
        evertrace_domain::purge::ScopePurgeStage::PhysicalDeleting
    );
    drop(live);
    let binaries = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let output = Command::new(binaries.join("evertrace"))
        .current_dir(root.path())
        .arg("--config")
        .arg(&external_config)
        .arg("restore")
        .arg("external-backup")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("restored="));
    let live = JournalWriter::open(&data).await.unwrap();
    let snapshot = live.full_projection().await.unwrap();
    let jobs = RuntimeSchedulerView::from_snapshot(&snapshot).unwrap();
    let stale = jobs
        .jobs
        .iter()
        .find(|job| job.job_id == stale_job_id)
        .unwrap();
    assert_eq!(stale.state, JobStatus::Failed);
    assert_eq!(
        stale.attempt, 1,
        "stale restored work must never acquire an execution lease"
    );
    assert_eq!(
        stale.terminal.as_ref().unwrap().reason,
        JobTerminalReason::StaleGeneration
    );
    assert_eq!(
        ScopePurgeCurrentView::from_snapshot(&snapshot)
            .unwrap()
            .events
            .get(&repository_id)
            .unwrap()
            .stage,
        evertrace_domain::purge::ScopePurgeStage::Purged
    );
    assert!(
        !CasStore::open(data.join("cas"))
            .unwrap()
            .blob_path(&digest)
            .exists()
    );
    assert_eq!(
        std::fs::read(backup.join("manifest.json")).unwrap(),
        manifest_before
    );
    assert!(
        RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&data))
            .unwrap()
            .recall_cues
            .is_empty()
    );
    StableLauncher::validate_restored_package(&data, &data).unwrap();
    let restored_key = DeviceKeyStore::new(data.join("keys")).load().unwrap();
    assert_ne!(
        old_cache_identity,
        evertrace_capture::protect::recovery_path_token(b"restore-keyed-cache", &restored_key)
            .unwrap()
    );
    assert!(
        !evertrace_capture::protect::verify_mcp_call_auth_tag(
            b"restore-keyed-authority",
            &restored_key,
            &old_tag
        )
        .unwrap()
    );
    let runtime = RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&data)).unwrap();
    let (handle, actor) = spawn_writer(live, 8).unwrap();
    let scheduler = scheduler(handle.clone(), runtime);
    let new_repository = RepositoryId::new_v7();
    handle
        .commit(
            repository_command(repository(new_repository, "/restore-new-work", 1), 4),
            4,
        )
        .await
        .unwrap();
    let watermark = handle.project().await.unwrap().frontier;
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    4,
                    effective.hash(),
                    ALGORITHM,
                    JournalPayload::DirtyTarget(evertrace_store::DirtyTarget {
                        target_kind: evertrace_store::DirtyTargetKind::ObjectsProjection,
                        target_id: new_repository.to_string(),
                        algorithm_revision: ALGORITHM.into(),
                        source_watermark: watermark,
                    }),
                )],
            )
            .unwrap(),
            4,
        )
        .await
        .unwrap();
    scheduler.run_once().await.unwrap();
    let jobs = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    assert!(jobs.jobs.iter().any(|job| job.kind == "objects_projection"
        && job.job_id != stale_job_id
        && job.state == JobStatus::Succeeded));
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();
    // A second root has no current deletion authority: the same valid backup
    // must remain historical, not become an empty-ledger activation.
    let historical_data = root.path().join("without-current-ledger");
    let mut historical_config = effective.config().clone();
    historical_config.runtime.data_dir = historical_data.to_str().unwrap().to_owned();
    let historical_config = EffectiveConfig::new(historical_config)
        .unwrap()
        .to_toml()
        .unwrap();
    let historical_config_path = root.path().join("historical.toml");
    std::fs::write(&historical_config_path, &historical_config).unwrap();
    std::fs::set_permissions(
        &historical_config_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let output = Command::new(binaries.join("evertrace"))
        .arg("--config")
        .arg(&historical_config_path)
        .arg("restore")
        .arg(&backup)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("historical_only="));
    assert!(!historical_data.join("journal.lance").exists());
    assert_eq!(
        std::fs::read_to_string(&historical_config_path).unwrap(),
        historical_config
    );
}

#[tokio::test]
async fn retention_gc_marks_real_spool_backup_receipts_and_waits_without_a_lease() {
    let root = TempDir::new().unwrap();
    let data = root.path().join("data");
    let writer = JournalWriter::open(&data).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 8).unwrap();
    let mut runtime = runtime_snapshot(&data);
    runtime.effective_config_hash = EffectiveConfig::default().hash();
    runtime
        .publish(&RuntimeSnapshot::snapshot_path(&data))
        .unwrap();
    DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    DurableSpool::open(runtime.spool_dir.clone(), runtime.spool_limits().unwrap()).unwrap();
    CasStore::open(runtime.cas_dir.clone()).unwrap();
    let config = root.path().join("config.toml");
    std::fs::write(&config, EffectiveConfig::default().to_toml().unwrap()).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let repository_id = RepositoryId::new_v7();
    handle
        .commit(
            repository_command(repository(repository_id, "/gc-test", 1), 1),
            1,
        )
        .await
        .unwrap();
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    let CaptureOutcome::Durable { cas_digest, .. } = capture
        .capture(capture_input("gc-spool", repository_id, b"backup-only pin"))
        .unwrap()
    else {
        panic!("durable capture");
    };
    capture.seal_active().unwrap();
    drop(capture);
    assert_eq!(
        handle
            .mark_gc(runtime.clone(), 0)
            .await
            .unwrap()
            .candidate_count(),
        0
    );
    let backup_id = JobId::new_v7();
    handle
        .create_backup(backup_id, config, runtime.clone())
        .await
        .unwrap()
        .unwrap();
    // Isolate the backup pin: simulate loss of the live spool in this disposable
    // fixture, without adding a journal receipt for these backed-up bytes.
    let spool =
        DurableSpool::open_read_only(runtime.spool_dir.clone(), runtime.spool_limits().unwrap())
            .unwrap();
    for segment in spool.sealed_segments(16).unwrap() {
        let frames = segment.frames().len();
        spool.acknowledge_segment(segment, frames).unwrap();
    }
    assert_eq!(
        handle
            .mark_gc(runtime.clone(), 0)
            .await
            .unwrap()
            .candidate_count(),
        0
    );
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    capture
        .capture(capture_input(
            "gc-receipt",
            repository_id,
            b"journal receipt pin",
        ))
        .unwrap();
    capture.seal_active().unwrap();
    drop(capture);
    EvidenceIngestor::new(
        runtime.clone(),
        handle.clone(),
        runtime.effective_config_hash,
        ALGORITHM,
    )
    .unwrap()
    .drain_once()
    .await
    .unwrap();
    assert_eq!(
        handle
            .mark_gc(runtime.clone(), 0)
            .await
            .unwrap()
            .candidate_count(),
        0
    );
    let key = DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    let cas = CasStore::open(runtime.cas_dir.clone()).unwrap();
    let orphan = cas
        .put(&evertrace_capture::protect::protect(b"gc orphan", &key).unwrap())
        .unwrap();
    let before_reference = handle.mark_gc(runtime.clone(), 0).await.unwrap();
    assert_eq!(before_reference.candidate_count(), 1);
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    let CaptureOutcome::Durable {
        cas_digest: newly_pinned,
        ..
    } = capture
        .capture(capture_input("gc-after-mark", repository_id, b"gc orphan"))
        .unwrap()
    else {
        panic!("durable capture");
    };
    assert_eq!(newly_pinned, orphan.as_hex());
    capture.seal_active().unwrap();
    drop(capture);
    EvidenceIngestor::new(
        runtime.clone(),
        handle.clone(),
        runtime.effective_config_hash,
        ALGORITHM,
    )
    .unwrap()
    .drain_once()
    .await
    .unwrap();
    assert_eq!(
        handle
            .mark_gc(runtime.clone(), 0)
            .await
            .unwrap()
            .candidate_count(),
        0
    );
    let unknown = runtime.spool_dir.join("quarantine/unknown-evidence");
    std::fs::write(&unknown, b"unknown").unwrap();
    assert!(handle.mark_gc(runtime.clone(), 0).await.is_err());
    std::fs::remove_file(&unknown).unwrap();
    // A fully pinned EOF now completes without grace. Keep a real unreferenced
    // candidate here so the scheduler/restart assertion exercises the wait.
    cas.put(&evertrace_capture::protect::protect(b"gc waiting candidate", &key).unwrap())
        .unwrap();
    let governance = HumanGovernanceService::new(handle.clone(), runtime.effective_config_hash);
    let request = RequestId::new_v7();
    let job_id = JobId::from_uuid(request.as_uuid()).unwrap();
    let frontier = handle.project().await.unwrap().frontier;
    assert!(matches!(
        governance.collect_garbage(request, frontier).await.unwrap(),
        HumanActionOutcome::Applied { .. }
    ));
    let background = scheduler(handle.clone(), runtime.clone());
    background.run_once().await.unwrap();
    drop(background);
    scheduler(handle.clone(), runtime.clone())
        .run_once()
        .await
        .unwrap();
    let jobs = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let job = jobs.jobs.iter().find(|job| job.job_id == job_id).unwrap();
    assert_eq!(
        (job.state, job.attempt, job.lease_until_us),
        (JobStatus::Queued, 1, None)
    );
    assert!(
        cas.read(&orphan).is_ok()
            && cas
                .read(&CasStore::parse_digest(&cas_digest).unwrap())
                .is_ok()
    );
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();
}

#[tokio::test]
async fn retention_gc_continues_past_a_full_pinned_shard_page() {
    let root = TempDir::new().unwrap();
    let data = root.path().join("data");
    let writer = JournalWriter::open(&data).await.unwrap();
    let runtime = runtime_snapshot(&data);
    let key = DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    let cas = CasStore::open(runtime.cas_dir.clone()).unwrap();
    DurableSpool::open(runtime.spool_dir.clone(), runtime.spool_limits().unwrap()).unwrap();
    let mut payloads = std::collections::BTreeMap::new();
    for number in 0_u64.. {
        let bytes = format!("retention page payload {number}").into_bytes();
        let protected = evertrace_capture::protect::protect(&bytes, &key).unwrap();
        let digest = evertrace_capture::CasDigest::for_protected_bytes(protected.protected_bytes());
        if digest.as_bytes()[0] == 0 {
            cas.put(&protected).unwrap();
            payloads.insert(digest.as_hex(), bytes);
            if payloads.len() == 257 {
                break;
            }
        }
    }
    let guard = evertrace_capture::MaintenanceFence::open(&data)
        .unwrap()
        .exclusive()
        .unwrap();
    let first = cas
        .gc_candidates(
            &guard,
            &mut evertrace_capture::cas::CasGcCursor::new(0),
            256,
            64 << 20,
        )
        .unwrap();
    assert_eq!(first.len(), 256);
    drop(guard);
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    for (index, candidate) in first.iter().enumerate() {
        assert!(matches!(
            capture
                .capture(capture_input(
                    &format!("pinned-page-{index}"),
                    RepositoryId::new_v7(),
                    &payloads[&candidate.digest.as_hex()],
                ))
                .unwrap(),
            CaptureOutcome::Durable { .. }
        ));
    }
    capture.seal_active().unwrap();
    drop(capture);
    let first = writer
        .mark_gc_page(&runtime, evertrace_capture::cas::CasGcCursor::new(0))
        .await
        .unwrap();
    assert_eq!(first.round.candidate_count(), 0);
    assert!(!first.cursor.finished());
    let second = writer.mark_gc_page(&runtime, first.cursor).await.unwrap();
    assert_eq!(second.round.candidate_count(), 1);
    assert!(second.cursor.finished());
    assert!(
        writer
            .sweep_gc(&runtime, JobId::new_v7(), &second.round)
            .await
            .is_err()
    );
}

fn file_sha256(bytes: &[u8]) -> String {
    copy_exact_sha256_hex(
        &mut Cursor::new(bytes),
        &mut std::io::sink(),
        u64::try_from(bytes.len()).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn isolated_upgrade_publishes_native_container_without_moving_durable_inputs() {
    use evertrace_store::restore::NativeUpgradeOutcome;
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let root = TempDir::new().unwrap();
    let data = root.path().join("data");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&data)
        .unwrap();
    let connection = evertrace_store::connection::CompatibilityStore::connect_local(&data)
        .await
        .unwrap();
    evertrace_store::L0001::apply(connection.connection())
        .await
        .unwrap();
    drop(connection);
    assert!(matches!(
        JournalWriter::open(&data).await,
        Err(evertrace_store::StoreError::UpgradeRequired)
    ));
    assert!(!data.join("store").exists());
    let mut configured = EffectiveConfig::default().config().clone();
    configured.runtime.data_dir = data.to_str().unwrap().into();
    let effective = EffectiveConfig::new(configured).unwrap();
    let config = root.path().join("config.toml");
    std::fs::write(&config, effective.to_toml().unwrap()).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut runtime = runtime_snapshot(&data);
    runtime.effective_config_hash = effective.hash();
    runtime
        .publish(&RuntimeSnapshot::snapshot_path(&data))
        .unwrap();
    DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    let repository_id = RepositoryId::new_v7();
    let CaptureOutcome::Durable { cas_digest, .. } = capture
        .capture(capture_input(
            "upgrade-before",
            repository_id,
            b"before backup",
        ))
        .unwrap()
    else {
        panic!("durable capture required")
    };
    let paths = [
        &runtime.cas_dir,
        &runtime.spool_dir,
        &runtime.device_key_dir,
    ];
    let identities: Vec<_> = paths
        .iter()
        .map(|path| {
            let metadata = std::fs::metadata(path).unwrap();
            (metadata.dev(), metadata.ino())
        })
        .collect();
    let binaries = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    std::fs::write(data.join("unknown-user-asset"), b"keep").unwrap();
    let output = Command::new(binaries.join("evertrace"))
        .arg("--config")
        .arg(&config)
        .arg("upgrade")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("upgrade=L0001_to_L0002"));
    assert_eq!(
        std::fs::read(data.join("unknown-user-asset")).unwrap(),
        b"keep"
    );
    let backup = std::fs::read_dir(data.join("backups"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(
        data.join("store")
            .join(format!("{}.lance", evertrace_store::JOURNAL_TABLE))
            .is_dir()
    );
    assert!(
        !data
            .join(format!("{}.lance", evertrace_store::OBJECTS_TABLE))
            .exists()
    );
    assert!(
        !data
            .join(format!("{}.lance", evertrace_store::JOURNAL_TABLE))
            .exists()
    );
    for (path, identity) in paths.iter().zip(identities) {
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), identity);
    }
    assert!(
        CasStore::open(runtime.cas_dir.clone())
            .unwrap()
            .read(&cas_digest.parse().unwrap())
            .is_ok()
    );
    let CaptureOutcome::Durable { .. } = capture
        .capture(capture_input(
            "upgrade-after",
            repository_id,
            b"after publication",
        ))
        .unwrap()
    else {
        panic!("held capture runtime must remain usable")
    };
    let writer = JournalWriter::open(&data).await.unwrap();
    assert_eq!(writer.full_projection().await.unwrap().frontier, 2);
    drop(writer);
    assert!(matches!(
        evertrace_engine::maintenance::upgrade_offline(&data, &config)
            .await
            .unwrap(),
        NativeUpgradeOutcome::Noop { retained_native } if retained_native.is_empty()
    ));
    let mut hook_correlation = correlation();
    hook_correlation.pairing_role = ObservationRole::Result;
    let hook_input = serde_json::json!({
        "input_version": evertrace_codex::hook_input::CAPTURE_HOOK_INPUT_VERSION,
        "spool_record_id": "upgrade-real-hook", "source_observation_id_hint": null,
        "source_instance_id": "upgrade-real-hook", "source_revision": "revision-1",
        "source_record_identity": "upgrade-real-hook", "identity_strength": "stable_native",
        "source_kind": "codex_hook", "identity_domain": "codex-hook-v1",
        "adapter_manifest_ref": "adapter-s33", "eligible_event_manifest_ref": "eligible-s33",
        "source_revision_mode": "append", "previous_source_revision": null,
        "source_ref": "upgrade-real-hook", "session_id": "upgrade-real-hook",
        "turn_id": null, "tool_use_id": null, "event_kind": "post_tool_use",
        "correlation": hook_correlation, "scope_effect_claims": [], "lifecycle": null,
        "source_sequence": 1, "source_sequence_origin": null, "task_id": null,
        "repository_instance_id": null, "worktree_instance_id": null,
        "event_time_us": 1, "payload": "upgrade real hook evidence"
    });
    let bytes = serde_json::to_vec(&hook_input).unwrap();
    evertrace_codex::hook_input::CaptureHookInput::from_json(&bytes).unwrap();
    {
        let mut child = Command::new(binaries.join("evertrace-hook"))
            .arg("--runtime-snapshot")
            .arg(RuntimeSnapshot::snapshot_path(&data))
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
        assert!(child.wait().unwrap().success());
    }
    drop(capture);
    let (mut spool, _) =
        DurableSpool::open(runtime.spool_dir.clone(), runtime.spool_limits().unwrap()).unwrap();
    spool.seal_active(runtime.generation).unwrap();
    let replay = spool
        .sealed_segments(16)
        .unwrap()
        .into_iter()
        .map(|segment| {
            (
                segment.path().to_owned(),
                std::fs::read(segment.path()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    drop(spool);
    let writer = JournalWriter::open(&data).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 32).unwrap();
    let ingestor =
        EvidenceIngestor::new(runtime.clone(), handle.clone(), effective.hash(), ALGORITHM)
            .unwrap();
    let drained = ingestor.drain_once().await.unwrap();
    assert!(drained.committed_frames >= 3, "{drained:?}");
    let snapshot = handle.project().await.unwrap();
    let (_, receipt) = source_pair_for_instance(&snapshot, "upgrade-real-hook");
    assert_eq!(receipt.source_instance_id.as_str(), "upgrade-real-hook");
    let frontier = snapshot.frontier;
    // Simulate an acknowledgement lost after commit by restoring the exact
    // durable input bytes, not by issuing a new Hook capture/command identity.
    for (path, bytes) in replay {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
    }
    let replayed = ingestor.drain_once().await.unwrap();
    assert_eq!(replayed.replayed_frames, drained.committed_frames);
    assert_eq!(replayed.committed_frames, replayed.replayed_frames);
    assert_eq!(handle.project().await.unwrap().frontier, frontier);
    drop(ingestor);
    drop(handle);
    actor.await.unwrap().unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(backup.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["schema_revision"], "L0001");
    assert!(manifest["table_states"]["relations"].is_null());
}

#[tokio::test]
async fn isolated_upgrade_converts_flat_l0002_without_an_extra_migration() {
    use evertrace_store::restore::NativeUpgradeOutcome;
    use std::os::unix::fs::DirBuilderExt;
    let root = TempDir::new().unwrap();
    let data = root.path().join("data");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&data)
        .unwrap();
    let connection = evertrace_store::connection::CompatibilityStore::connect_local(&data)
        .await
        .unwrap();
    evertrace_store::L0002::apply(connection.connection())
        .await
        .unwrap();
    drop(connection);
    assert!(matches!(
        JournalWriter::open(&data).await,
        Err(evertrace_store::StoreError::UpgradeRequired)
    ));
    let effective = EffectiveConfig::default();
    let config = root.path().join("config.toml");
    std::fs::write(&config, effective.to_toml().unwrap()).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut runtime = runtime_snapshot(&data);
    runtime.effective_config_hash = effective.hash();
    runtime
        .publish(&RuntimeSnapshot::snapshot_path(&data))
        .unwrap();
    CasStore::open(runtime.cas_dir.clone()).unwrap();
    DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    let repository_id = RepositoryId::new_v7();
    let outcome = evertrace_store::restore::upgrade_native(
        &data,
        &config,
        || {
            assert!(
                StableLauncher::freeze_backup_snapshot(&data)
                    .unwrap()
                    .files
                    .is_empty()
            );
            // The Store has already frozen its backup spool boundary. This new
            // durable input must survive publication despite not belonging to it.
            assert!(matches!(
                capture
                    .capture(capture_input(
                        "upgrade-boundary",
                        repository_id,
                        b"after backup boundary"
                    ))
                    .unwrap(),
                CaptureOutcome::Durable { .. }
            ));
            Ok(evertrace_store::backup::BackupHookBoundary {
                current_generation: None,
                retained_generations: Vec::new(),
                pin_count: 0,
                pinned_generation_count: 0,
                files: Vec::new(),
            })
        },
        |path, _| {
            StableLauncher::verify_backup_snapshot(path)
                .map_err(|_| evertrace_store::BackupError::Corrupt)?;
            Ok(())
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        NativeUpgradeOutcome::Published {
            migrated: false,
            ref retained_native,
            ..
        } if retained_native.is_empty()
    ));
    for table in [
        evertrace_store::OBJECTS_TABLE,
        evertrace_store::JOURNAL_TABLE,
        evertrace_store::RELATIONS_TABLE,
        evertrace_store::SEARCH_TABLE,
    ] {
        assert!(!data.join(format!("{table}.lance")).exists());
    }
    drop(capture);
    let writer = JournalWriter::open(&data).await.unwrap();
    assert_eq!(writer.full_projection().await.unwrap().frontier, 2);
    let (handle, actor) = spawn_writer(writer, 32).unwrap();
    let ingestor =
        EvidenceIngestor::new(runtime.clone(), handle.clone(), effective.hash(), ALGORITHM)
            .unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 1);
    source_pair_for_instance(&handle.project().await.unwrap(), "hook-upgrade-boundary");
    drop(ingestor);
    drop(handle);
    actor.await.unwrap().unwrap();
    let flat = evertrace_store::connection::CompatibilityStore::connect_local(&data)
        .await
        .unwrap();
    evertrace_store::L0002::apply(flat.connection())
        .await
        .unwrap();
    drop(flat);
    std::fs::remove_dir_all(
        data.join("store")
            .join(format!("{}.lance", evertrace_store::JOURNAL_TABLE)),
    )
    .unwrap();
    assert!(
        JournalWriter::open(&data).await.is_err(),
        "corrupt canonical must never fall back to complete flat source"
    );
    assert!(
        evertrace_engine::maintenance::upgrade_offline(&data, &config)
            .await
            .is_err()
    );
}

fn runtime_snapshot(root: &Path) -> RuntimeSnapshot {
    let limits = SpoolLimits {
        high_watermark_bytes: 4 * 1024 * 1024,
        low_watermark_bytes: 64 * 1024,
        max_main_files: 16,
        emergency_slots: 2,
    };
    RuntimeSnapshot {
        snapshot_version: RUNTIME_SNAPSHOT_VERSION,
        generation: 1,
        device_key_dir: root.join("keys"),
        cas_dir: root.join("cas"),
        spool_dir: root.join("spool"),
        main_high_watermark_bytes: limits.high_watermark_bytes,
        main_low_watermark_bytes: limits.low_watermark_bytes,
        max_main_files: limits.max_main_files,
        emergency_slots: limits.emergency_slots,
        recovery_gate: RecoveryGateMode::Disabled,
        recovery_socket_path: root.join("runtime/evertraced-v1.sock"),
        recovery_preflight_timeout_ms: 250,
        effective_config_hash: CONFIG,
        recovery_adapter_manifest_id: None,
        recovery_classifier_revision: 1,
        recovery_max_bundle_bytes: 4 << 20,
        recovery_max_untracked_file_bytes: 1 << 20,
        recovery_max_untracked_total_bytes: 2 << 20,
        recall_cue_gate: RecallCueGateMode::Disabled,
        recall_cue_adapter_manifest_id: None,
        recall_cues: Vec::new(),
    }
}

fn scheduler(
    handle: evertrace_engine::WriterHandle,
    runtime: RuntimeSnapshot,
) -> BackgroundScheduler {
    let report = Arc::new(RwLock::new(None::<evertrace_codex::HostProbeReport>));
    BackgroundScheduler::new(
        handle.clone(),
        SessionCatalogService::new(handle.clone(), CONFIG),
        SessionImportWorker::new(handle, runtime.clone(), Arc::clone(&report)).unwrap(),
        report,
        runtime,
        SynthesisPlanner::new(LlmConfig {
            enabled: false,
            ..LlmConfig::default()
        }),
        DreamingConfig::default(),
    )
}

fn repository(id: RepositoryId, path: &str, at: i64) -> RepositoryInstance {
    RepositoryInstance {
        user_disabled: false,
        capability_state: None,
        repository_id: id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: path.into(),
        path_history: vec![PathObservation {
            path: path.into(),
            first_observed_at_us: at,
            last_observed_at_us: at,
            evidence_refs: vec![format!("repository-evidence-{id}")],
        }],
        git_common_dir_path: Some(format!("{path}/.git")),
        common_dir_filesystem: Some(FilesystemIdentity {
            device: 1,
            inode: id.as_uuid().as_u128() as u64,
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: Vec::new(),
        derived_from: None,
        identity_evidence_refs: vec![format!("repository-identity-{id}")],
        recorded_at_us: at,
    }
}

fn repository_command(value: RepositoryInstance, at: i64) -> JournalCommand {
    JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            at,
            CONFIG,
            ALGORITHM,
            JournalPayload::RepositoryInstanceRecorded(Box::new(value)),
        )],
    )
    .unwrap()
}

fn worktree(repository_id: RepositoryId, worktree_id: WorktreeId, path: &str) -> WorktreeInstance {
    let observation = PathObservation {
        path: path.into(),
        first_observed_at_us: 1,
        last_observed_at_us: 1,
        evidence_refs: vec![format!("worktree-evidence-{worktree_id}")],
    };
    WorktreeInstance {
        worktree_instance_id: worktree_id,
        worktree_revision: 1,
        predecessor_revision: None,
        repository_instance_id: repository_id,
        kind: WorktreeKind::Main,
        lifecycle: WorktreeLifecycle::Active,
        current_path: Some(path.into()),
        path_history: vec![observation.clone()],
        git_admin_path_history: vec![observation],
        git_registration_state: GitRegistrationState::Registered,
        current_snapshot_id: None,
        created_event_ref: format!("worktree-created-{worktree_id}"),
        terminal_event_ref: None,
        recreated_from_worktree_instance_id: None,
        recorded_at_us: 1,
    }
}

fn repository_episode(
    repository_id: RepositoryId,
    worktree_id: WorktreeId,
) -> (Task, Workstream, evertrace_domain::work::WorkEpisode) {
    let task = Task {
        task_id: TaskId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec!["request:s33-purge-job".into()],
        canonical_goal: "verify repository producer revocation".into(),
        scope_memberships: vec![TaskScopeMembership {
            repository_instance_id: Some(repository_id),
            worktree_instance_ids: vec![worktree_id],
        }],
        identity_confidence: TaskIdentityConfidence::Explicit,
        lifecycle: TaskLifecycle::Active,
        continuation_of_task_id: None,
        split_from_task_id: None,
        split_into_task_ids: Vec::new(),
        merged_from_task_ids: Vec::new(),
        merged_into_task_id: None,
        created_at_us: 1,
        closed_at_us: None,
        source_watermark: 1,
    };
    let workstream = Workstream {
        workstream_id: WorkstreamId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        task_id: task.task_id,
        repository_instance_id: Some(repository_id),
        worktree_instance_ids: vec![worktree_id],
        active_worktree_instance_id: Some(worktree_id),
        worktree_lineage_refs: Vec::new(),
        parent_workstream_id: None,
        dependency_workstream_ids: Vec::new(),
        status: WorkstreamStatus::Active,
        root_goal: "repository purge".into(),
        workstream_goal: "stop repository producers".into(),
        target_family: "repository".into(),
        hypothesis_or_failure_family: "producer race".into(),
        acceptance_boundary: "all target producers revoked".into(),
        phase_contract: PhaseContract {
            local_goal: "close repository producer work".into(),
            phase_kind: PhaseKind::Implement,
            phase_label: "repository-purge".into(),
            primary_targets: vec!["repository".into()],
            entry_conditions: vec!["repository active".into()],
            acceptance_boundary: "producer jobs revoked".into(),
            expected_state_transition: "repository pending".into(),
        },
        active_episode_id: None,
        execution_lane_ids: Vec::new(),
        source_watermark: 1,
    };
    let episode = new_episode(&workstream, None, 1).unwrap();
    (task, workstream, episode)
}

fn correlation() -> HostCorrelationEvidence {
    HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: None,
        host_trace_lineage_id: None,
        host_lane_key: None,
        canonical_event_family: None,
        native_request_id: None,
        physical_execution_ordinal: None,
        pairing_role: ObservationRole::Message,
        field_provenance: Vec::new(),
        adapter_manifest_ref: "adapter-s33".into(),
        adapter_revision: 1,
        strong_gate_receipt_ref: None,
        admission: CorrelationAdmission::Unavailable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    }
}

fn capture_input(label: &str, repository_id: RepositoryId, payload: &[u8]) -> CaptureRecordInput {
    CaptureRecordInput {
        source_local_evidence: None,
        spool_record_id: Some(format!("spool-{label}")),
        source_observation_id_hint: None,
        source_instance_id: format!("hook-{label}"),
        source_revision: "revision-1".into(),
        source_record_identity: Some(format!("record-{label}")),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        source_ref: format!("source-{label}"),
        session_ref: format!("session-{label}"),
        turn_ref: None,
        tool_ref: None,
        source_sequence: 1,
        source_sequence_origin: None,
        task_id: None,
        repository_instance_id: Some(repository_id.to_string()),
        worktree_instance_id: None,
        source_byte_range: None,
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: None,
        observation_role: ObservationRole::Message,
        correlation: correlation(),
        scope_effect_claims: Vec::new(),
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: SourceRole::User,
        content_trust: ContentTrust::UserStatement,
        capture_completeness: CaptureCompleteness::Complete,
        surface_eligible: true,
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-s33".into(),
        eligible_event_manifest_ref: "eligible-s33".into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: Some(1),
        raw_payload: payload.to_vec(),
    }
}

fn source_pair(
    snapshot: &evertrace_store::ProjectionSnapshot,
) -> (SourceObservation, SourceReceipt) {
    source_pair_optional(snapshot).unwrap()
}

fn source_pair_optional(
    snapshot: &evertrace_store::ProjectionSnapshot,
) -> Option<(SourceObservation, SourceReceipt)> {
    let mut observation = None;
    let mut receipt = None;
    for row in snapshot.data_rows() {
        let Some(json) = row.payload_json.as_deref() else {
            continue;
        };
        let Ok(payload) = serde_json::from_str::<JournalPayload>(json) else {
            continue;
        };
        match payload {
            JournalPayload::SourceObservationRecorded(value) => observation = Some(*value),
            JournalPayload::SourceReceiptRecorded(value) => receipt = Some(*value),
            _ => {}
        }
    }
    observation.zip(receipt)
}

fn source_pair_for_instance(
    snapshot: &evertrace_store::ProjectionSnapshot,
    source_instance: &str,
) -> (SourceObservation, SourceReceipt) {
    let receipts = snapshot
        .data_rows()
        .filter_map(|row| row.payload_json.as_deref())
        .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
        .filter_map(|payload| match payload {
            JournalPayload::SourceReceiptRecorded(value)
                if value.source_instance_id.as_str() == source_instance =>
            {
                Some(*value)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [receipt] = receipts.as_slice() else {
        panic!("one source receipt expected for {source_instance}")
    };
    let observation = snapshot
        .data_rows()
        .filter_map(|row| row.payload_json.as_deref())
        .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
        .find_map(|payload| match payload {
            JournalPayload::SourceObservationRecorded(value)
                if value.source_observation_id == receipt.source_observation_id =>
            {
                Some(*value)
            }
            _ => None,
        })
        .unwrap();
    (observation, receipt.clone())
}

fn atom_draft(
    scope: AtomScope,
    observation: &SourceObservation,
    receipt: &SourceReceipt,
) -> AtomDraft {
    AtomDraft {
        kind: AtomKind::Constraint,
        epistemic_status: EpistemicStatus::NotApplicable,
        value: AtomValue {
            text: "repository-derived global constraint".into(),
            subject: "constraint".into(),
            predicate: "retain".into(),
            object: Some("evidence".into()),
            qualifiers: vec![SemanticQualifier {
                name: "scope".into(),
                value: "global".into(),
            }],
            critical_revision_refs: Vec::new(),
        },
        scope,
        applicability_expr: ApplicabilityExpr::Constraint(ConstraintExpr::Eq {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text("active".into()),
        }),
        future_cue_lifecycle_exprs: None,
        validity_interval: ValidityInterval {
            valid_from_us: 1,
            valid_until_us: None,
        },
        provenance: vec![AtomProvenance::AgentClaimed],
        source_observation_refs: vec![observation.source_observation_id],
        evidence_refs: vec![receipt.source_receipt_id.to_string()],
        supersedes_revision_refs: Vec::new(),
        supports_revision_refs: Vec::new(),
        contradicts_revision_refs: Vec::new(),
    }
}

fn proposal_context(at: i64) -> ProposalCommandContext {
    ProposalCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: ALGORITHM.into(),
    }
}

#[tokio::test]
async fn repository_derived_global_proposal_blocks_repository_purge() {
    let root = TempDir::new().unwrap();
    let data_root = root.path().join("data");
    std::fs::create_dir(&data_root).unwrap();
    let runtime = runtime_snapshot(&data_root);
    DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    let writer = JournalWriter::open(&data_root.join("store")).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 16).unwrap();
    let repository_id = RepositoryId::new_v7();
    handle
        .commit(
            repository_command(
                repository(
                    repository_id,
                    &root.path().join("repository").display().to_string(),
                    1,
                ),
                1,
            ),
            1,
        )
        .await
        .unwrap();
    assert!(matches!(
        capture
            .capture(capture_input(
                "proposal",
                repository_id,
                b"proposal evidence"
            ))
            .unwrap(),
        CaptureOutcome::Durable { .. }
    ));
    EvidenceIngestor::new(runtime.clone(), handle.clone(), CONFIG, ALGORITHM)
        .unwrap()
        .drain_once()
        .await
        .unwrap();
    let source_snapshot = handle.project().await.unwrap();
    let (observation, receipt) = source_pair(&source_snapshot);
    let proposal_service = RevisionProposalService;
    let ProposalResolution::Revision { command, .. } = proposal_service
        .submit(
            &SemanticCurrentView::from_snapshot(&source_snapshot).unwrap(),
            proposal_context(2),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                    draft: atom_draft(
                        AtomScope::Repository {
                            repository_instance_id: repository_id,
                        },
                        &observation,
                        &receipt,
                    ),
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("proposal revision expected")
    };
    handle.commit(command, 2).await.unwrap();
    let repository_local = handle.project().await.unwrap();
    let local_preview =
        evertrace_store::repository_scope_purge_preview(&repository_local, repository_id, 1)
            .unwrap();
    assert_eq!(local_preview.repository_derived_global_dependency_count, 0);
    assert!(!local_preview.blockers.contains(
        &evertrace_domain::purge::RepositoryPurgeBlocker::RepositoryDerivedGlobalDependency
    ));
    let ProposalResolution::Revision { value, command } = proposal_service
        .submit(
            &SemanticCurrentView::from_snapshot(&repository_local).unwrap(),
            proposal_context(2),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                    draft: atom_draft(AtomScope::Global, &observation, &receipt),
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("proposal revision expected")
    };
    handle.commit(command, 2).await.unwrap();
    let before_purge = handle.project().await.unwrap();
    let preview =
        evertrace_store::repository_scope_purge_preview(&before_purge, repository_id, 1).unwrap();
    assert!(preview.blockers.contains(
        &evertrace_domain::purge::RepositoryPurgeBlocker::RepositoryDerivedGlobalDependency
    ));
    let governance = HumanGovernanceService::new(handle.clone(), CONFIG);
    assert!(matches!(
        governance
            .purge_repository(
                RequestId::new_v7(),
                before_purge.frontier,
                repository_id,
                &repository_id.to_string(),
                1,
                preview.deletion_generation,
            )
            .await
            .unwrap(),
        HumanActionOutcome::Unavailable { .. }
    ));
    let blocked = handle.project().await.unwrap();
    assert!(
        SemanticCurrentView::from_snapshot(&blocked)
            .unwrap()
            .proposals
            .contains_key(&value.proposal_id)
    );
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();
    let rebuilt = JournalWriter::open(&data_root.join("store"))
        .await
        .unwrap()
        .full_projection()
        .await
        .unwrap();
    assert_eq!(blocked, rebuilt);
}

#[tokio::test]
async fn repository_pending_revokes_target_producers_and_rejects_successors() {
    let root = TempDir::new().unwrap();
    let data = root.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let runtime = runtime_snapshot(&data);
    DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    let writer = JournalWriter::open(&data.join("store")).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 16).unwrap();
    let repository_id = RepositoryId::new_v7();
    let worktree_id = WorktreeId::new_v7();
    let path = root.path().join("repository").display().to_string();
    let repository_events = vec![
        JournalEventDraft::runtime(
            1,
            CONFIG,
            ALGORITHM,
            JournalPayload::RepositoryInstanceRecorded(Box::new(repository(
                repository_id,
                &path,
                1,
            ))),
        ),
        JournalEventDraft::runtime(
            1,
            CONFIG,
            ALGORITHM,
            JournalPayload::WorktreeInstanceRecorded(Box::new(worktree(
                repository_id,
                worktree_id,
                &path,
            ))),
        ),
    ];
    handle
        .commit(
            JournalCommand::new(CommandId::new_v7(), repository_events).unwrap(),
            1,
        )
        .await
        .unwrap();

    assert!(matches!(
        capture
            .capture(capture_input(
                "producer-job-target",
                repository_id,
                b"target producer evidence",
            ))
            .unwrap(),
        CaptureOutcome::Durable { .. }
    ));
    EvidenceIngestor::new(runtime.clone(), handle.clone(), CONFIG, ALGORITHM)
        .unwrap()
        .drain_once()
        .await
        .unwrap();
    let (target_observation, _) = source_pair(&handle.project().await.unwrap());
    let (task, workstream, episode) = repository_episode(repository_id, worktree_id);
    let target_task_id = task.task_id;
    let work_command = JournalCommand::new(
        CommandId::new_v7(),
        vec![
            JournalEventDraft::runtime(
                2,
                CONFIG,
                ALGORITHM,
                JournalPayload::TaskRecorded(Box::new(task)),
            ),
            JournalEventDraft::runtime(
                2,
                CONFIG,
                ALGORITHM,
                JournalPayload::WorkstreamRecorded(Box::new(workstream.clone())),
            ),
        ],
    )
    .unwrap();
    handle.commit(work_command, 2).await.unwrap();
    handle
        .commit(
            activate_episode(
                WorkCommandContext {
                    command_id: CommandId::new_v7(),
                    occurred_at_us: 2,
                    effective_config_hash: CONFIG,
                    algorithm_revision: ALGORITHM,
                },
                &workstream,
                episode.clone(),
                Vec::new(),
                Vec::new(),
            )
            .unwrap(),
            2,
        )
        .await
        .unwrap();

    let mut exact_input = capture_input(
        "task-local-exact",
        repository_id,
        b"task-local exact instruction",
    );
    exact_input.task_id = Some(target_task_id.to_string());
    assert!(matches!(
        capture.capture(exact_input).unwrap(),
        CaptureOutcome::Durable { .. }
    ));
    EvidenceIngestor::new(runtime, handle.clone(), CONFIG, ALGORITHM)
        .unwrap()
        .drain_once()
        .await
        .unwrap();
    let (exact_observation, exact_receipt) =
        source_pair_for_instance(&handle.project().await.unwrap(), "hook-task-local-exact");
    let proposal_service = RevisionProposalService;
    let semantic = handle.project().await.unwrap();
    let task_draft = AtomDraft {
        kind: AtomKind::Constraint,
        epistemic_status: EpistemicStatus::NotApplicable,
        value: AtomValue {
            text: "task-local exact instruction".into(),
            subject: "current_task".into(),
            predicate: "must_follow_user_message".into(),
            object: None,
            qualifiers: Vec::new(),
            critical_revision_refs: Vec::new(),
        },
        scope: AtomScope::Task {
            task_id: target_task_id,
        },
        applicability_expr: ApplicabilityExpr::Always,
        future_cue_lifecycle_exprs: None,
        validity_interval: ValidityInterval {
            valid_from_us: 1,
            valid_until_us: Some(10),
        },
        provenance: vec![AtomProvenance::UserAsserted],
        source_observation_refs: vec![exact_observation.source_observation_id],
        evidence_refs: vec![exact_receipt.source_receipt_id.to_string()],
        supersedes_revision_refs: Vec::new(),
        supports_revision_refs: Vec::new(),
        contradicts_revision_refs: Vec::new(),
    };
    let ProposalResolution::Revision {
        value: local_proposal,
        command,
    } = proposal_service
        .submit(
            &SemanticCurrentView::from_snapshot(&semantic).unwrap(),
            proposal_context(3),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                    draft: task_draft,
                })),
                evidence_refs: vec![exact_receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![exact_receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("task-local proposal expected")
    };
    handle.commit(command, 3).await.unwrap();
    let submitted = handle.project().await.unwrap();
    let accepted = proposal_service
        .accept(
            &SemanticCurrentView::from_snapshot(&submitted).unwrap(),
            proposal_context(3),
            local_proposal.proposal_id,
            AtomAcceptanceContext::CurrentTaskExactMessage {
                observation: Box::new(exact_observation),
                receipt: Box::new(exact_receipt),
                canonical_message: "task-local exact instruction".into(),
            },
        )
        .unwrap();
    let atom_payload = accepted
        .command
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::AtomRecorded(value) => Some(value.clone()),
            _ => None,
        })
        .unwrap();
    let accepted_atom_id = accepted.atom.atom_id;
    handle.commit(accepted.command, 3).await.unwrap();

    let session_id = "session-import-purge-race";
    let source_revision = SourceRevision::parse("ab".repeat(32)).unwrap();
    let metadata = SessionMetadata {
        source_path: "/session-import-purge-race.jsonl".into(),
        source_format: "codex_jsonl_v1".into(),
        started_at_us: Some(1),
        ended_at_us: None,
        host: None,
        model_profile: None,
        workspace_hint: Some(path.clone()),
        repository_hint: None,
        worktree_hint: None,
        workspace_resolution_kind: WorkspaceResolutionKind::Repository,
        resolved_repository_instance_id: Some(repository_id),
        resolved_worktree_instance_id: Some(worktree_id),
        repository_read_restrictions: None,
        file_size: 128,
        file_mtime_us: 1,
        source_fingerprint: "cd".repeat(32),
        source_revision: source_revision.clone(),
        parser_version: 1,
        metadata_state: MetadataState::Indexed,
    };
    let metadata_event = SessionImportEvent {
        source_instance_id: None,
        session_id: session_id.into(),
        revision: 1,
        predecessor_revision: None,
        occurred_at_us: 2,
        event: SessionImportEventKind::MetadataObserved {
            metadata: Box::new(metadata.clone()),
        },
    };
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    2,
                    CONFIG,
                    ALGORITHM,
                    JournalPayload::SessionImportEventRecorded(Box::new(metadata_event)),
                )],
            )
            .unwrap(),
            2,
        )
        .await
        .unwrap();
    let job_id = JobId::new_v7();
    let queued = SessionImportEvent {
        source_instance_id: None,
        session_id: session_id.into(),
        revision: 2,
        predecessor_revision: Some(1),
        occurred_at_us: 3,
        event: SessionImportEventKind::BodyStateAdvanced {
            body_state: SessionBodyState::Queued,
            reason: BodyStateReason::Requested,
        },
    };
    let job_frontier = handle.project().await.unwrap().frontier;
    let job = DurableJob {
        job_id,
        idempotency_key: format!("session_import:{session_id}"),
        target_revision: source_revision.as_str().into(),
        target_watermark: job_frontier,
        target_generation: 1,
        kind: "session_import_v1".into(),
        algorithm_revision: "session-import-v1".into(),
        model_id: None,
        priority: 0,
        state: JobStatus::Queued,
        attempt: 1,
        backoff_until_us: None,
        config_hash: CONFIG,
        budget: JobBudget {
            max_items: 16,
            max_bytes: Some(64 * 1024),
            max_input_tokens: None,
            max_output_tokens: None,
            max_calls: None,
            max_wall_time_ms: 1_000,
        },
        terminal: None,
        lease_until_us: None,
    };
    let synthesis_job_id = JobId::new_v7();
    let synthesis_job = DurableJob {
        job_id: synthesis_job_id,
        idempotency_key: format!("semantic_synthesis:{}:0:1", episode.revision_id),
        target_revision: episode.revision_id.to_string(),
        target_watermark: 1,
        target_generation: episode.revision_generation,
        kind: "semantic_synthesis_v1".into(),
        algorithm_revision: "semantic_synthesis_v1".into(),
        model_id: Some("test-model".into()),
        priority: 0,
        state: JobStatus::Queued,
        attempt: 1,
        backoff_until_us: None,
        config_hash: CONFIG,
        budget: JobBudget {
            max_items: 16,
            max_bytes: Some(64 * 1024),
            max_input_tokens: Some(1_024),
            max_output_tokens: Some(1_024),
            max_calls: Some(1),
            max_wall_time_ms: 1_000,
        },
        terminal: None,
        lease_until_us: None,
    };
    let physical_job_id = JobId::new_v7();
    let physical_job = DurableJob {
        job_id: physical_job_id,
        idempotency_key: format!(
            "physical_normalization:{}",
            target_observation.source_observation_id
        ),
        target_revision: target_observation.source_observation_id.to_string(),
        target_watermark: job_frontier,
        target_generation: 1,
        kind: "physical_normalization".into(),
        algorithm_revision: "physical-normalization-v1".into(),
        model_id: None,
        priority: 0,
        state: JobStatus::Queued,
        attempt: 1,
        backoff_until_us: None,
        config_hash: CONFIG,
        budget: JobBudget {
            max_items: 16,
            max_bytes: Some(64 * 1024),
            max_input_tokens: None,
            max_output_tokens: None,
            max_calls: None,
            max_wall_time_ms: 1_000,
        },
        terminal: None,
        lease_until_us: None,
    };
    let reconciliation_job_id = JobId::new_v7();
    let reconciliation_job = DurableJob {
        job_id: reconciliation_job_id,
        idempotency_key: format!(
            "capture_reconciliation:{}",
            target_observation.source_observation_id
        ),
        kind: "capture_reconciliation".into(),
        algorithm_revision: "capture-reconciliation-v1".into(),
        ..physical_job.clone()
    };
    let global_job_id = JobId::new_v7();
    let global_job = DurableJob {
        job_id: global_job_id,
        idempotency_key: "support_closure:global".into(),
        target_revision: "global-support".into(),
        kind: "support_closure".into(),
        algorithm_revision: "support-closure-v1".into(),
        ..physical_job.clone()
    };
    let non_target_job_id = JobId::new_v7();
    let non_target_revision = RevisionId::new_v7();
    let non_target_job = DurableJob {
        job_id: non_target_job_id,
        idempotency_key: format!("semantic_synthesis:{non_target_revision}:0:1"),
        target_revision: non_target_revision.to_string(),
        ..synthesis_job.clone()
    };
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![
                    JournalEventDraft::runtime(
                        3,
                        CONFIG,
                        ALGORITHM,
                        JournalPayload::SessionImportEventRecorded(Box::new(queued)),
                    ),
                    JournalEventDraft::runtime(
                        3,
                        CONFIG,
                        ALGORITHM,
                        JournalPayload::JobState(job.clone()),
                    ),
                    JournalEventDraft::runtime(
                        3,
                        CONFIG,
                        ALGORITHM,
                        JournalPayload::JobState(synthesis_job.clone()),
                    ),
                    JournalEventDraft::runtime(
                        3,
                        CONFIG,
                        ALGORITHM,
                        JournalPayload::JobState(physical_job.clone()),
                    ),
                    JournalEventDraft::runtime(
                        3,
                        CONFIG,
                        ALGORITHM,
                        JournalPayload::JobState(reconciliation_job.clone()),
                    ),
                    JournalEventDraft::runtime(
                        3,
                        CONFIG,
                        ALGORITHM,
                        JournalPayload::JobState(global_job),
                    ),
                    JournalEventDraft::runtime(
                        3,
                        CONFIG,
                        ALGORITHM,
                        JournalPayload::JobState(non_target_job),
                    ),
                ],
            )
            .unwrap(),
            3,
        )
        .await
        .unwrap();

    let before = handle.project().await.unwrap();
    let preview =
        evertrace_store::repository_scope_purge_preview(&before, repository_id, 1).unwrap();
    assert!(preview.blockers.is_empty());
    assert_eq!(preview.affected_session_count, 1);
    assert_eq!(preview.repository_derived_global_dependency_count, 0);
    assert_eq!(preview.affected_atom_count, 1);
    let purge_request_id = RequestId::new_v7();
    let command = evertrace_engine::purge::pending_repository_purge_command(
        purge_request_id,
        &preview,
        preview.deletion_generation,
        4,
        before.frontier,
        CONFIG,
    )
    .unwrap();
    handle.commit(command, 4).await.unwrap();
    let pending = handle.project().await.unwrap();
    assert!(
        SessionImportCurrentView::from_snapshot(&pending)
            .unwrap()
            .sessions
            .is_empty()
    );
    let semantic = SemanticCurrentView::from_snapshot(&pending).unwrap();
    assert!(!semantic.atoms.contains_key(&accepted_atom_id));
    assert!(!semantic.proposals.contains_key(&local_proposal.proposal_id));
    let scheduled = RuntimeSchedulerView::from_snapshot(&pending).unwrap();
    for revoked_job_id in [
        job_id,
        synthesis_job_id,
        physical_job_id,
        reconciliation_job_id,
    ] {
        assert!(
            !scheduled
                .jobs
                .iter()
                .any(|candidate| candidate.job_id == revoked_job_id)
        );
    }
    for retained_job_id in [global_job_id, non_target_job_id] {
        assert!(
            scheduled
                .jobs
                .iter()
                .any(|candidate| candidate.job_id == retained_job_id)
        );
    }
    let committed = handle
        .committed_command(CommandId::from_uuid(purge_request_id.as_uuid()).unwrap())
        .await
        .unwrap()
        .unwrap();
    let revoked = committed
        .payloads
        .into_iter()
        .filter_map(|payload| match payload {
            JournalPayload::JobState(job)
                if job
                    .terminal
                    .as_deref()
                    .is_some_and(|terminal| terminal.reason == JobTerminalReason::Revoked) =>
            {
                assert_eq!(job.state, JobStatus::Failed);
                Some(job.job_id)
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        revoked,
        BTreeSet::from([
            job_id,
            synthesis_job_id,
            physical_job_id,
            reconciliation_job_id,
        ])
    );

    let metadata_successor = SessionImportEvent {
        source_instance_id: None,
        session_id: session_id.into(),
        revision: 3,
        predecessor_revision: Some(2),
        occurred_at_us: 4,
        event: SessionImportEventKind::MetadataObserved {
            metadata: Box::new(metadata),
        },
    };
    let successor = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            4,
            CONFIG,
            ALGORITHM,
            JournalPayload::SessionImportEventRecorded(Box::new(metadata_successor)),
        )],
    )
    .unwrap();
    assert_eq!(
        handle.commit(successor, 4).await,
        Err(evertrace_engine::WriterActorError::InvalidInput)
    );
    let mut replacement_job = job;
    replacement_job.job_id = JobId::new_v7();
    let replacement = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            4,
            CONFIG,
            ALGORITHM,
            JournalPayload::JobState(replacement_job),
        )],
    )
    .unwrap();
    assert_eq!(
        handle.commit(replacement, 4).await,
        Err(evertrace_engine::WriterActorError::InvalidInput)
    );
    let mut replacement_synthesis = synthesis_job;
    replacement_synthesis.job_id = JobId::new_v7();
    let replacement = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            4,
            CONFIG,
            ALGORITHM,
            JournalPayload::JobState(replacement_synthesis),
        )],
    )
    .unwrap();
    assert_eq!(
        handle.commit(replacement, 4).await,
        Err(evertrace_engine::WriterActorError::InvalidInput)
    );
    let mut replacement_capture = reconciliation_job;
    replacement_capture.job_id = JobId::new_v7();
    let replacement = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            4,
            CONFIG,
            ALGORITHM,
            JournalPayload::JobState(replacement_capture),
        )],
    )
    .unwrap();
    assert_eq!(
        handle.commit(replacement, 4).await,
        Err(evertrace_engine::WriterActorError::InvalidInput)
    );
    let replacement_atom = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            4,
            CONFIG,
            ALGORITHM,
            JournalPayload::AtomRecorded(atom_payload),
        )],
    )
    .unwrap();
    assert_eq!(
        handle.commit(replacement_atom, 4).await,
        Err(evertrace_engine::WriterActorError::InvalidInput)
    );
    let mut dependent_workstream = workstream.clone();
    dependent_workstream.workstream_id = WorkstreamId::new_v7();
    dependent_workstream.revision_id = RevisionId::new_v7();
    dependent_workstream.predecessor_revision_id = None;
    dependent_workstream.parent_workstream_id = None;
    dependent_workstream.dependency_workstream_ids = vec![workstream.workstream_id];
    dependent_workstream.validate().unwrap();
    let replacement_workstream = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            4,
            CONFIG,
            ALGORITHM,
            JournalPayload::WorkstreamRecorded(Box::new(dependent_workstream)),
        )],
    )
    .unwrap();
    assert_eq!(
        handle.commit(replacement_workstream, 4).await,
        Err(evertrace_engine::WriterActorError::InvalidInput)
    );
    let lease = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            4,
            CONFIG,
            ALGORITHM,
            JournalPayload::JobLease(JobLease {
                job_id,
                target_generation: 1,
                attempt: 1,
                lease_until_us: 5,
            }),
        )],
    )
    .unwrap();
    assert_eq!(
        handle.commit(lease, 4).await,
        Err(evertrace_engine::WriterActorError::InvalidInput)
    );
    let normal = handle.project().await.unwrap();
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();
    assert_eq!(
        normal,
        JournalWriter::open(&data.join("store"))
            .await
            .unwrap()
            .full_projection()
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn late_purged_hook_retains_shared_digest_beyond_sixty_four_segments() {
    let root = TempDir::new().unwrap();
    let data = root.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let mut runtime = runtime_snapshot(&data);
    runtime.max_main_files = 80;
    DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    let writer = JournalWriter::open(&data.join("store")).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 16).unwrap();
    let target_id = RepositoryId::new_v7();
    let other_id = RepositoryId::new_v7();
    handle
        .commit(
            repository_command(repository(target_id, "/repository/target", 1), 1),
            1,
        )
        .await
        .unwrap();
    handle
        .commit(
            repository_command(repository(other_id, "/repository/other", 2), 2),
            2,
        )
        .await
        .unwrap();
    let before = handle.project().await.unwrap();
    let preview = evertrace_store::repository_scope_purge_preview(&before, target_id, 1).unwrap();
    let request_id = RequestId::new_v7();
    handle
        .commit(
            evertrace_engine::purge::pending_repository_purge_command(
                request_id,
                &preview,
                preview.deletion_generation,
                3,
                before.frontier,
                CONFIG,
            )
            .unwrap(),
            3,
        )
        .await
        .unwrap();

    let shared_payload = b"shared after sixty-four sealed segments";
    let mut stale_digest = None;
    for index in 0..65 {
        let CaptureOutcome::Durable { cas_digest, .. } = capture
            .capture(capture_input(
                &format!("late-stale-{index:02}"),
                target_id,
                shared_payload,
            ))
            .unwrap()
        else {
            panic!("durable stale capture expected")
        };
        stale_digest.get_or_insert(cas_digest);
        capture.seal_active().unwrap().unwrap();
    }
    let CaptureOutcome::Durable {
        cas_digest: live_digest,
        ..
    } = capture
        .capture(capture_input("late-live-65", other_id, shared_payload))
        .unwrap()
    else {
        panic!("durable live capture expected")
    };
    capture.seal_active().unwrap().unwrap();
    assert_eq!(stale_digest.as_deref(), Some(live_digest.as_str()));

    let drained = EvidenceIngestor::new(runtime.clone(), handle.clone(), CONFIG, ALGORITHM)
        .unwrap()
        .drain_once()
        .await
        .unwrap();
    assert_eq!(drained.committed_frames, 0);
    assert_eq!(drained.sealed_segments, 16);
    let cas = CasStore::open(runtime.cas_dir).unwrap();
    assert!(
        cas.read(&CasStore::parse_digest(&live_digest).unwrap())
            .is_ok()
    );
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();
}

#[tokio::test]
async fn normal_ingest_fence_orders_commit_ack_before_exclusive_delete_planning() {
    let root = TempDir::new().unwrap();
    let data = root.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let runtime = runtime_snapshot(&data);
    DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    let writer = JournalWriter::open(&data.join("store")).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 16).unwrap();
    let repository_id = RepositoryId::new_v7();
    handle
        .commit(
            repository_command(repository(repository_id, "/repository/normal", 1), 1),
            1,
        )
        .await
        .unwrap();
    let CaptureOutcome::Durable { cas_digest, .. } = capture
        .capture(capture_input(
            "normal-fence",
            repository_id,
            b"normal fenced evidence",
        ))
        .unwrap()
    else {
        panic!("durable normal capture expected")
    };
    capture.seal_active().unwrap().unwrap();

    let fence = evertrace_capture::MaintenanceFence::open(&data).unwrap();
    let exclusive = fence.exclusive().unwrap();
    let blocked = EvidenceIngestor::new(runtime.clone(), handle.clone(), CONFIG, ALGORITHM)
        .unwrap()
        .drain_once()
        .await;
    assert!(blocked.is_err());
    assert!(source_pair_optional(&handle.project().await.unwrap()).is_none());
    drop(exclusive);

    let drained = EvidenceIngestor::new(runtime.clone(), handle.clone(), CONFIG, ALGORITHM)
        .unwrap()
        .drain_once()
        .await
        .unwrap();
    assert_eq!(drained.committed_frames, 1);
    assert_eq!(drained.sealed_segments, 1);
    let live = handle.project().await.unwrap();
    let (_, receipt) = source_pair(&live);
    assert_eq!(receipt.cas_ref, cas_digest);
    assert_eq!(
        live.live_cas_refs_intersect(&BTreeSet::from([cas_digest.clone()]))
            .unwrap(),
        BTreeSet::from([cas_digest])
    );
    let _exclusive = fence.exclusive().unwrap();

    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();
}

#[tokio::test]
async fn repository_purge_closes_immediately_batches_cas_and_resumes_after_reopen() {
    let root = TempDir::new().unwrap();
    let data_root = root.path().join("data");
    std::fs::create_dir(&data_root).unwrap();
    let runtime = runtime_snapshot(&data_root);
    let store = data_root.join("store");
    DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    let writer = JournalWriter::open(&store).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 16).unwrap();
    let target_id = RepositoryId::new_v7();
    let other_id = RepositoryId::new_v7();
    let target_path = root.path().join("target").display().to_string();
    let other_path = root.path().join("other").display().to_string();
    std::fs::create_dir(&target_path).unwrap();
    assert!(
        Command::new("git")
            .arg("init")
            .arg("--quiet")
            .arg(&target_path)
            .status()
            .unwrap()
            .success()
    );
    handle
        .commit(
            repository_command(repository(target_id, &target_path, 1), 1),
            1,
        )
        .await
        .unwrap();
    handle
        .commit(
            repository_command(repository(other_id, &other_path, 2), 2),
            2,
        )
        .await
        .unwrap();

    let mut exclusive = Vec::new();
    for index in 0..257 {
        let outcome = capture
            .capture(capture_input(
                &format!("exclusive-{index}"),
                target_id,
                format!("exclusive payload {index}").as_bytes(),
            ))
            .unwrap();
        let CaptureOutcome::Durable { cas_digest, .. } = outcome else {
            panic!("durable target capture expected")
        };
        exclusive.push(cas_digest);
    }
    let shared_payload = b"shared repository evidence";
    let target_shared = capture
        .capture(capture_input("target-shared", target_id, shared_payload))
        .unwrap();
    let other_shared = capture
        .capture(capture_input("other-shared", other_id, shared_payload))
        .unwrap();
    let (
        CaptureOutcome::Durable {
            cas_digest: target_shared,
            ..
        },
        CaptureOutcome::Durable {
            cas_digest: other_shared,
            ..
        },
    ) = (target_shared, other_shared)
    else {
        panic!("durable shared captures expected")
    };
    assert_eq!(target_shared, other_shared);
    EvidenceIngestor::new(runtime.clone(), handle.clone(), CONFIG, ALGORITHM)
        .unwrap()
        .drain_once()
        .await
        .unwrap();

    let target_observation_id = handle
        .project()
        .await
        .unwrap()
        .data_rows()
        .filter_map(|row| row.payload_json.as_deref())
        .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
        .find_map(|payload| match payload {
            JournalPayload::SourceReceiptRecorded(receipt)
                if receipt.repository_instance_id == Some(target_id) =>
            {
                Some(receipt.source_observation_id)
            }
            _ => None,
        })
        .unwrap();
    let other_observation_id = handle
        .project()
        .await
        .unwrap()
        .data_rows()
        .filter_map(|row| row.payload_json.as_deref())
        .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
        .find_map(|payload| match payload {
            JournalPayload::SourceReceiptRecorded(receipt)
                if receipt.repository_instance_id == Some(other_id) =>
            {
                Some(receipt.source_observation_id)
            }
            _ => None,
        })
        .unwrap();
    let key = DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    let cas = CasStore::open(runtime.cas_dir.clone()).unwrap();
    let historical_digest = cas
        .put(&evertrace_capture::protect::protect(b"historical artifact revision", &key).unwrap())
        .unwrap();
    let current_digest = cas
        .put(&evertrace_capture::protect::protect(b"current artifact revision", &key).unwrap())
        .unwrap();
    let artifact_id = WorkArtifactId::new_v7();
    let first_revision_id = RevisionId::new_v7();
    let artifact = |revision_id, parent_revision_id, digest, created_at_us| WorkArtifact {
        work_artifact_id: artifact_id,
        revision: ArtifactRevision {
            revision_id,
            parent_revision_id,
            kind: WorkArtifactKind::ExperimentOutput,
            logical_name: "historical-purge-proof.bin".into(),
            scope: ArtifactScope::Repository {
                repository_instance_id: target_id,
            },
            media_type: "application/octet-stream".into(),
            content_blob_ref: Some(digest),
            external_reference: None,
            content_fingerprint: Some(digest),
            payload_status: ArtifactPayloadStatus::Degraded,
            produced_by_refs: Vec::new(),
            consumed_by_refs: Vec::new(),
            source_observation_refs: vec![target_observation_id],
            derivability: ArtifactDerivability::Original,
            retention: ArtifactRetention::Repository,
            created_at_us,
        },
    };
    for (index, value) in [
        artifact(
            first_revision_id,
            None,
            CasId::from_digest(*historical_digest.as_bytes()),
            4,
        ),
        artifact(
            RevisionId::new_v7(),
            Some(first_revision_id),
            CasId::from_digest(*current_digest.as_bytes()),
            5,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        value.validate().unwrap();
        handle
            .commit(
                JournalCommand::new(
                    CommandId::new_v7(),
                    vec![JournalEventDraft::runtime(
                        value.revision.created_at_us,
                        CONFIG,
                        ALGORITHM,
                        JournalPayload::WorkArtifactRecorded(Box::new(value)),
                    )],
                )
                .unwrap(),
                5,
            )
            .await
            .unwrap_or_else(|error| panic!("artifact revision {index}: {error:?}"));
    }

    let native_reader = evertrace_store::connection::CompatibilityStore::connect_local(
        &evertrace_store::connection::native_root(&store),
    )
    .await
    .unwrap();
    let held_objects = native_reader
        .connection()
        .open_table(evertrace_store::OBJECTS_TABLE)
        .execute()
        .await
        .unwrap();
    let held_version = held_objects.version().await.unwrap();
    held_objects.checkout(held_version).await.unwrap();
    let held_rows = held_objects.count_rows(None).await.unwrap();
    assert!(held_rows > 0);
    assert!(
        held_objects
            .count_rows(Some(format!("object_id = '{target_id}'")))
            .await
            .unwrap()
            > 0
    );
    let before = handle.project().await.unwrap();
    let unavailable_space = HumanGovernanceService::new(handle.clone(), CONFIG)
        .detail(
            HumanSurface::Explorer,
            &target_id.to_string(),
            before.frontier,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        unavailable_space.items[0]
            .repository_purge_preview
            .as_ref()
            .unwrap()
            .estimated_reclaimable_bytes,
        None
    );
    let service = HumanGovernanceService::with_acceptance(
        handle.clone(),
        CONFIG,
        runtime.clone(),
        Default::default(),
    );
    let store_preview =
        evertrace_store::repository_scope_purge_preview(&before, target_id, 1).unwrap();
    let detail = service
        .detail(
            HumanSurface::Explorer,
            &target_id.to_string(),
            before.frontier,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    let preview = detail.items[0].repository_purge_preview.as_ref().unwrap();
    assert_eq!(
        preview.planned_exclusive_cas_count,
        store_preview.physical_item_count().unwrap()
    );
    assert_eq!(preview.planned_exclusive_cas_count, 259);
    assert_eq!(preview.shared_cas_retained_count, 1);
    assert_eq!(preview.affected_artifact_count, 1);
    let cas = CasStore::open(runtime.cas_dir.clone()).unwrap();
    let encoded_exclusive_bytes = store_preview
        .exclusive_cas_refs
        .iter()
        .map(|reference| {
            std::fs::metadata(cas.blob_path(&CasStore::parse_digest(reference).unwrap()))
                .unwrap()
                .len()
        })
        .sum();
    assert_eq!(
        preview.estimated_reclaimable_bytes,
        Some(encoded_exclusive_bytes)
    );
    assert!(
        store_preview
            .exclusive_cas_refs
            .contains(&historical_digest.as_hex())
    );
    assert!(
        store_preview
            .exclusive_cas_refs
            .contains(&current_digest.as_hex())
    );
    let mut malformed = before.clone();
    malformed
        .rows
        .iter_mut()
        .find(|row| row.object_kind.as_deref() == Some("work_artifact"))
        .unwrap()
        .payload_json = Some("{".into());
    assert_eq!(
        malformed.live_cas_refs_intersect(&BTreeSet::from([historical_digest.as_hex()])),
        Err(StoreError::StoreCorrupt)
    );
    let request_id = RequestId::new_v7();
    assert!(matches!(
        service
            .purge_repository(
                request_id,
                before.frontier,
                target_id,
                &target_id.to_string(),
                1,
                1,
            )
            .await
            .unwrap(),
        HumanActionOutcome::Applied { .. }
    ));
    let mut referenced_artifact = artifact(
        RevisionId::new_v7(),
        None,
        CasId::from_digest(*current_digest.as_bytes()),
        6,
    );
    referenced_artifact.work_artifact_id = WorkArtifactId::new_v7();
    referenced_artifact.revision.scope = ArtifactScope::Global;
    referenced_artifact.revision.content_blob_ref = None;
    referenced_artifact.revision.content_fingerprint = None;
    referenced_artifact.revision.payload_status = ArtifactPayloadStatus::MetadataOnly;
    referenced_artifact.revision.retention = ArtifactRetention::Retained;
    referenced_artifact.validate().unwrap();
    let referenced = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            6,
            CONFIG,
            ALGORITHM,
            JournalPayload::WorkArtifactRecorded(Box::new(referenced_artifact.clone())),
        )],
    )
    .unwrap();
    assert_eq!(
        handle.commit(referenced, 6).await,
        Err(evertrace_engine::WriterActorError::InvalidInput)
    );
    referenced_artifact.work_artifact_id = WorkArtifactId::new_v7();
    referenced_artifact.revision.revision_id = RevisionId::new_v7();
    referenced_artifact.revision.source_observation_refs = vec![other_observation_id];
    referenced_artifact.validate().unwrap();
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    6,
                    CONFIG,
                    ALGORITHM,
                    JournalPayload::WorkArtifactRecorded(Box::new(referenced_artifact)),
                )],
            )
            .unwrap(),
            6,
        )
        .await
        .unwrap();
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();
    let pending_writer = JournalWriter::open(&store).await.unwrap();
    let pending = pending_writer.project().await.unwrap();
    assert_eq!(pending, pending_writer.full_projection().await.unwrap());
    assert!(!pending.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("repository")
            && row.object_id.as_deref() == Some(target_id.to_string().as_str())
    }));
    drop(pending_writer);

    let stale_missing = capture
        .capture(capture_input(
            "post-pending-stale-missing",
            target_id,
            b"post-pending stale only",
        ))
        .unwrap();
    let CaptureOutcome::Durable {
        cas_digest: stale_missing_digest,
        ..
    } = stale_missing
    else {
        panic!("durable stale capture expected")
    };
    let stale_shared = capture
        .capture(capture_input(
            "post-pending-stale-shared",
            target_id,
            b"exclusive payload 0",
        ))
        .unwrap();
    let CaptureOutcome::Durable {
        cas_digest: stale_shared_digest,
        ..
    } = stale_shared
    else {
        panic!("durable stale shared capture expected")
    };
    assert_eq!(stale_shared_digest, exclusive[0]);
    let late_share = capture
        .capture(capture_input(
            "late-share",
            other_id,
            b"exclusive payload 0",
        ))
        .unwrap();
    let CaptureOutcome::Durable {
        cas_digest: late_shared_digest,
        ..
    } = late_share
    else {
        panic!("durable late shared capture expected")
    };
    assert_eq!(late_shared_digest, exclusive[0]);
    let fence = evertrace_capture::MaintenanceFence::open(&data_root).unwrap();
    let guard = fence.exclusive().unwrap();
    assert_eq!(
        CasStore::delete_guarded_batch(
            &guard,
            &[CasStore::parse_digest(&stale_missing_digest).unwrap()]
        )
        .unwrap(),
        [evertrace_capture::CasDeleteOutcome::Deleted]
    );
    drop(guard);
    let writer = JournalWriter::open(&store).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 8).unwrap();
    let drain = EvidenceIngestor::new(runtime.clone(), handle.clone(), CONFIG, ALGORITHM)
        .unwrap()
        .drain_once()
        .await
        .unwrap();
    assert_eq!(drain.committed_frames, 1);
    let cas = CasStore::open(runtime.cas_dir.clone()).unwrap();
    assert_eq!(
        cas.read(&CasStore::parse_digest(&stale_missing_digest).unwrap()),
        Err(CasError::NotFound)
    );
    assert!(
        cas.read(&CasStore::parse_digest(&stale_shared_digest).unwrap())
            .is_ok()
    );
    let missing_before_progress = CasStore::parse_digest(
        store_preview
            .exclusive_cas_refs
            .iter()
            .find(|reference| *reference != &exclusive[0])
            .expect("purge plan must contain an unpinned digest"),
    )
    .unwrap();
    let fence = evertrace_capture::MaintenanceFence::open(&data_root).unwrap();
    let guard = fence.exclusive().unwrap();
    assert_eq!(
        CasStore::delete_guarded_batch(&guard, &[missing_before_progress]).unwrap(),
        [evertrace_capture::CasDeleteOutcome::Deleted]
    );
    drop(guard);
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();

    let writer = JournalWriter::open(&store).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 8).unwrap();
    let background = scheduler(handle.clone(), runtime.clone());
    background.run_once().await.unwrap();
    background.run_once().await.unwrap();
    let interrupted = handle.project().await.unwrap();
    let progress = ScopePurgeCurrentView::from_snapshot(&interrupted).unwrap();
    let progress = progress.events.get(&target_id).unwrap();
    assert_eq!(
        progress.stage,
        evertrace_domain::purge::ScopePurgeStage::PhysicalDeleting
    );
    assert_eq!(progress.next_ordinal, 256);
    assert_eq!(cas.read(&missing_before_progress), Err(CasError::NotFound));
    let progress = progress.clone();
    let purge_job = RuntimeSchedulerView::from_snapshot(&interrupted)
        .unwrap()
        .jobs
        .into_iter()
        .find(|job| job.job_id == progress.purge_job_id)
        .unwrap();
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();

    let plan_len = store_preview.physical_item_count().unwrap();
    let remaining_refs = store_preview
        .exclusive_cas_refs
        .iter()
        .skip(usize::try_from(progress.next_ordinal).unwrap())
        .cloned()
        .collect::<BTreeSet<_>>();
    let pinned = interrupted
        .live_cas_refs_intersect(&remaining_refs)
        .unwrap();
    let remaining = remaining_refs
        .difference(&pinned)
        .map(|reference| CasStore::parse_digest(reference).unwrap())
        .collect::<Vec<_>>();
    let mut writer = JournalWriter::open(&store).await.unwrap();
    let lease_at = progress.recorded_at_us.checked_add(1).unwrap();
    let lease_until_us = lease_at
        .checked_add(i64::try_from(purge_job.budget.max_wall_time_ms).unwrap() * 1_000)
        .unwrap();
    let lease = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            lease_at,
            CONFIG,
            ALGORITHM,
            JournalPayload::JobLease(JobLease {
                job_id: purge_job.job_id,
                target_generation: purge_job.target_generation,
                attempt: purge_job.attempt.checked_add(1).unwrap(),
                lease_until_us,
            }),
        )],
    )
    .unwrap();
    writer.commit(&lease, lease_at).await.unwrap();
    let leased_job = RuntimeSchedulerView::from_snapshot(&writer.project().await.unwrap())
        .unwrap()
        .jobs
        .into_iter()
        .find(|job| job.job_id == progress.purge_job_id)
        .unwrap();
    assert_eq!(leased_job.state, JobStatus::Leased);
    let fence = evertrace_capture::MaintenanceFence::open(&data_root).unwrap();
    let guard = fence.exclusive().unwrap();
    assert!(!remaining.is_empty());
    CasStore::delete_guarded_batch(&guard, &remaining).unwrap();
    let lost_ack_at = lease_at.checked_add(1).unwrap();
    let lost_ack_command = evertrace_engine::purge::advance_repository_purge_command(
        CommandId::new_v7(),
        &progress,
        &leased_job,
        evertrace_domain::purge::ScopePurgeStage::PhysicalDeleting,
        u64::from(plan_len),
        lost_ack_at,
        CONFIG,
    )
    .unwrap();
    let _durable_without_executor_ack =
        writer.commit(&lost_ack_command, lost_ack_at).await.unwrap();
    let durable = writer.project().await.unwrap();
    assert_eq!(
        ScopePurgeCurrentView::from_snapshot(&durable)
            .unwrap()
            .events
            .get(&target_id)
            .unwrap()
            .next_ordinal,
        u64::from(plan_len)
    );
    drop(guard);
    drop(writer);

    let writer = JournalWriter::open(&store).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 8).unwrap();
    let background = scheduler(handle.clone(), runtime.clone());
    background.run_once().await.unwrap();
    let terminal_frontier = handle.project().await.unwrap().frontier;
    let service = HumanGovernanceService::new(handle.clone(), CONFIG);
    let detail = service
        .detail(
            HumanSurface::System,
            &format!("runtime:job:{}", purge_job.job_id),
            terminal_frontier,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    let Some(HumanSystemDetail::Job { detail }) = detail.items[0].system_detail.as_ref() else {
        panic!("purge job detail");
    };
    assert_eq!(detail.state, evertrace_engine::HumanJobState::Succeeded);
    assert_eq!(
        detail.terminal_reason,
        Some(evertrace_engine::HumanJobTerminalReason::Completed)
    );
    assert_eq!(detail.native_history_cleanup_availability, Some(evertrace_engine::HumanNativeHistoryCleanupAvailability::ExternalReaderExclusionUnverified));
    assert_eq!(held_objects.count_rows(None).await.unwrap(), held_rows);
    assert_eq!(held_objects.version().await.unwrap(), held_version);
    assert!(
        held_objects
            .count_rows(Some(format!("object_id = '{target_id}'")))
            .await
            .unwrap()
            > 0
    );
    drop(held_objects);
    drop(native_reader);
    let after_release = service
        .detail(
            HumanSurface::System,
            &format!("runtime:job:{}", purge_job.job_id),
            terminal_frontier,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    let Some(HumanSystemDetail::Job {
        detail: after_release,
    }) = after_release.items[0].system_detail.as_ref()
    else {
        panic!("purge job detail");
    };
    assert_eq!(after_release, detail);
    background.run_once().await.unwrap();
    assert_eq!(handle.project().await.unwrap().frontier, terminal_frontier);
    let projected = handle.project().await.unwrap();
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();
    let rebuilt = JournalWriter::open(&store)
        .await
        .unwrap()
        .full_projection()
        .await
        .unwrap();
    assert_eq!(projected, rebuilt);
    let progress = ScopePurgeCurrentView::from_snapshot(&projected).unwrap();
    assert_eq!(
        progress.events.get(&target_id).unwrap().stage,
        evertrace_domain::purge::ScopePurgeStage::Purged
    );
    let cas = CasStore::open(runtime.cas_dir.clone()).unwrap();
    assert!(
        cas.read(&CasStore::parse_digest(&exclusive[0]).unwrap())
            .is_ok()
    );
    for digest in &exclusive[1..] {
        assert_eq!(
            cas.read(&CasStore::parse_digest(digest).unwrap()),
            Err(CasError::NotFound)
        );
    }
    assert!(
        cas.read(&CasStore::parse_digest(&target_shared).unwrap())
            .is_ok()
    );
    assert_eq!(cas.read(&historical_digest), Err(CasError::NotFound));
    assert_eq!(cas.read(&current_digest), Err(CasError::NotFound));
    let writer = JournalWriter::open(&store).await.unwrap();
    // GC's authoritative scan includes historical revisions even though normal
    // product projections correctly suppress the explicitly purged object.
    assert_eq!(
        writer
            .historical_cas_refs_intersect(&BTreeSet::from([
                historical_digest.as_hex(),
                current_digest.as_hex()
            ]))
            .await
            .unwrap(),
        BTreeSet::from([historical_digest.as_hex(), current_digest.as_hex()])
    );
    let (handle, actor) = spawn_writer(writer, 8).unwrap();
    let service = HumanGovernanceService::new(handle.clone(), CONFIG);
    let terminal_frontier = handle.project().await.unwrap().frontier;
    assert!(matches!(
        service
            .purge_repository(
                request_id,
                before.frontier,
                target_id,
                &target_id.to_string(),
                1,
                1,
            )
            .await
            .unwrap(),
        HumanActionOutcome::Applied { .. }
    ));
    assert_eq!(handle.project().await.unwrap().frontier, terminal_frontier);
    assert_eq!(
        handle
            .commit(
                repository_command(repository(target_id, &target_path, 3), 3),
                3
            )
            .await,
        Err(evertrace_engine::WriterActorError::InvalidInput)
    );
    let current = handle.project().await.unwrap();
    let repository_view = RepositoryCurrentView::from_snapshot(&current).unwrap();
    let evidence = probe_repository(
        Path::new(&target_path),
        HostTrustDecision::Trusted,
        &["same-path-post-purge-probe".into()],
        4,
        &ProbeLimits::default(),
        &[],
        &[],
    )
    .unwrap();
    let resolution = resolve_repository(&RepositoryResolveInput {
        view: &repository_view,
        evidence: &evidence,
        derived_from_hint: None,
    })
    .unwrap();
    let replacement_id = resolution.repositories[0].repository_id;
    assert_ne!(replacement_id, target_id);
    let replacement_command = resolution
        .journal_command(4, CONFIG, ALGORITHM)
        .unwrap()
        .unwrap();
    handle.commit(replacement_command, 4).await.unwrap();
    let final_snapshot = handle.project().await.unwrap();
    assert!(final_snapshot.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("repository")
            && row.object_id.as_deref() == Some(replacement_id.to_string().as_str())
    }));
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();
}

#[tokio::test]
async fn quiesced_backup_create_verify_preserves_post_boundary_hook_and_reopens_writer() {
    let root = TempDir::new().unwrap();
    let data_dir = root.path().join("data");
    let writer = JournalWriter::open(&data_dir).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 32).unwrap();

    let effective = EffectiveConfig::default();
    // Ordinary native catalog current is not a JournalPayload, but must survive
    // both backup watermark collection and independent backup verification.
    let catalog_root = root.path().join("host");
    let dated = catalog_root.join("sessions/2026/09/09");
    std::fs::create_dir_all(&dated).unwrap();
    std::fs::set_permissions(&catalog_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let session = "019d0000-0000-7000-8000-000000000033";
    let transcript = dated.join(format!("rollout-2026-09-09T00-00-00-{session}.jsonl"));
    let header = serde_json::json!({"ordinal":0,"timestamp":"2026-09-09T00:00:00Z","type":"session_meta","payload":{"id":session,"session_id":session,"cwd":"/not-a-repository","originator":"codex_cli_rs","model_provider":"local","git":null}});
    std::fs::write(&transcript, format!("{header}\n")).unwrap();
    let report = evertrace_engine::repository::observe_session_catalog_report(
        transcript.to_str(),
        session,
        "catalog-backup",
        None,
    )
    .unwrap();
    assert_eq!(
        evertrace_engine::session_import::SessionCatalogService::new(
            handle.clone(),
            effective.hash()
        )
        .refresh(&report)
        .await
        .unwrap(),
        1
    );
    let config_path = root.path().join("config.toml");
    std::fs::write(&config_path, effective.to_toml().unwrap()).unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut runtime = runtime_snapshot(&data_dir);
    runtime.effective_config_hash = effective.hash();
    runtime.recall_cue_gate = RecallCueGateMode::Active;
    runtime.recall_cue_adapter_manifest_id = Some("adapter:s33-backup".into());
    runtime.recall_cues = vec![
        RecallCueSnapshot {
            session_id: "session:private-live-cue".into(),
            execution_lane_id: ExecutionLaneId::new_v7(),
            host_lane_key: "lane:private-live-cue".into(),
            adapter_manifest_id: "adapter:s33-backup".into(),
            runtime_generation: runtime.generation,
            recall_need_hash: [0x4c; 32],
            presentation_attempt_id: PresentationAttemptId::new_v7(),
            expires_at_us: i64::MAX,
            checksum: [0; 32],
        }
        .seal()
        .unwrap(),
    ];
    DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    runtime
        .publish(&RuntimeSnapshot::snapshot_path(&data_dir))
        .unwrap();
    let absent_hook = StableLauncher::freeze_backup_snapshot(&data_dir).unwrap();
    assert_eq!(absent_hook.current_generation, None);
    assert!(absent_hook.files.is_empty());
    std::fs::write(data_dir.join("hook-v1"), b"partial-install").unwrap();
    std::fs::set_permissions(
        data_dir.join("hook-v1"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(StableLauncher::freeze_backup_snapshot(&data_dir).is_err());
    std::fs::remove_file(data_dir.join("hook-v1")).unwrap();
    let launcher = StableLauncher::open(&data_dir).unwrap();
    for generation in 1..=2_u64 {
        let directory = data_dir.join(format!("hooks/generations/{generation}"));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let executable = directory.join("evertrace-hook");
        std::fs::write(&executable, format!("hook-generation-{generation}")).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let generation_runtime = directory.join("hook-runtime-v1.json");
        let mut snapshot = runtime.clone();
        snapshot.generation += generation;
        for cue in &mut snapshot.recall_cues {
            cue.runtime_generation = snapshot.generation;
            *cue = cue.clone().seal().unwrap();
        }
        snapshot.publish(&generation_runtime).unwrap();
        launcher
            .publish_generation(HookGeneration {
                generation,
                protocol_version: 1,
                executable,
                runtime_snapshot: generation_runtime,
                compatible: true,
            })
            .unwrap();
        if generation == 1 {
            assert_eq!(
                launcher
                    .resolve_for_session("session-backup-old")
                    .unwrap()
                    .generation,
                1
            );
        }
    }
    launcher
        .install_launcher_binary(&data_dir.join("hooks/generations/2/evertrace-hook"))
        .unwrap();

    let repository_id = RepositoryId::new_v7();
    let mut payload = vec![0_u8; 1024 * 1024];
    let mut value = 0x9e37_79b9_u32;
    for byte in &mut payload {
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        *byte = value as u8;
    }
    let pre_boundary = CaptureRuntime::open(runtime.clone())
        .unwrap()
        .capture(capture_input("backup-pre", repository_id, &payload))
        .unwrap();
    let CaptureOutcome::Durable {
        cas_digest: pre_digest,
        ..
    } = pre_boundary
    else {
        panic!("pre-boundary capture must be durable");
    };
    let mut second_pre_input = capture_input("backup-pre-second", repository_id, b"second");
    second_pre_input.source_instance_id = "hook-backup-pre".into();
    second_pre_input.source_revision = "revision-1".into();
    second_pre_input.source_sequence = 2;
    let CaptureOutcome::Durable {
        cas_digest: second_pre_digest,
        ..
    } = CaptureRuntime::open(runtime.clone())
        .unwrap()
        .capture(second_pre_input)
        .unwrap()
    else {
        panic!("second pre-boundary capture must be durable");
    };
    drop(payload);

    let governance = HumanGovernanceService::with_acceptance(
        handle.clone(),
        effective.hash(),
        runtime.clone(),
        GlobalPromotionConfig::default(),
    );
    let frontier = handle.project().await.unwrap().frontier;
    let request_id = RequestId::new_v7();
    let backup_job_id = JobId::from_uuid(request_id.as_uuid()).unwrap();
    assert!(matches!(
        governance
            .create_backup(request_id, frontier)
            .await
            .unwrap(),
        HumanActionOutcome::Applied { .. }
    ));

    let report = Arc::new(RwLock::new(None::<evertrace_codex::HostProbeReport>));
    let (backup_tx, mut backup_rx) = mpsc::channel(1);
    let scheduler = BackgroundScheduler::new(
        handle.clone(),
        SessionCatalogService::new(handle.clone(), effective.hash()),
        SessionImportWorker::new(handle.clone(), runtime.clone(), Arc::clone(&report)).unwrap(),
        report,
        runtime.clone(),
        SynthesisPlanner::new(LlmConfig {
            enabled: false,
            ..LlmConfig::default()
        }),
        DreamingConfig::default(),
    )
    .with_backup_requests(backup_tx);
    let scheduler_task = tokio::spawn(async move { scheduler.run_once().await });
    let request = backup_rx.recv().await.unwrap();
    assert_eq!(request.backup_job_id(), backup_job_id);
    handle
        .commit(
            repository_command(
                repository(
                    RepositoryId::new_v7(),
                    "/repository/backup-frontier-lag",
                    12,
                ),
                12,
            ),
            12,
        )
        .await
        .unwrap();
    let backup_handle = handle.clone();
    let backup_runtime = runtime.clone();
    let backup_config = config_path.clone();
    let backup_task = tokio::spawn(async move {
        let result = backup_handle
            .create_backup(backup_job_id, backup_config, backup_runtime)
            .await
            .expect("writer actor must remain available");
        let observed = result.clone();
        request.complete(result);
        observed
    });
    let staging = data_dir
        .join("backups")
        .join(format!(".staging-{backup_job_id}"));
    tokio::time::timeout(Duration::from_secs(10), async {
        while !staging.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("streaming backup must expose its private staging interval");
    assert_eq!(
        launcher
            .resolve_for_session("session-backup-after-boundary")
            .unwrap()
            .generation,
        2
    );
    let post_boundary = CaptureRuntime::open(runtime.clone())
        .unwrap()
        .capture(capture_input(
            "backup-post",
            repository_id,
            b"post-boundary",
        ))
        .unwrap();
    let CaptureOutcome::Durable {
        cas_digest: post_digest,
        ..
    } = post_boundary
    else {
        panic!("post-boundary capture must be durable");
    };
    backup_task.await.unwrap().unwrap();
    let progress = scheduler_task.await.unwrap().unwrap();
    assert_eq!(progress.completed, 1);

    let backup_dir = data_dir
        .join("backups")
        .join(format!("backup-{backup_job_id}"));
    assert!(!staging.exists());
    let manifest: BackupManifest =
        serde_json::from_slice(&std::fs::read(backup_dir.join("manifest.json")).unwrap()).unwrap();
    assert!(manifest.committed_source_watermarks.is_empty());
    assert_eq!(manifest.spool_source_watermarks.len(), 1);
    assert_eq!(
        manifest.spool_source_watermarks[0]
            .source_instance_id
            .as_str(),
        "hook-backup-pre"
    );
    assert_eq!(manifest.spool_source_watermarks[0].source_sequence, 2);
    assert!(manifest.spool_cas_refs.contains(&pre_digest));
    assert!(manifest.spool_cas_refs.contains(&second_pre_digest));
    assert_eq!(manifest.table_states.journal.checkpoint, manifest.frontier);
    assert_eq!(manifest.table_states.objects.checkpoint, manifest.frontier);
    assert!(manifest.table_states.relations.as_ref().unwrap().checkpoint < manifest.frontier);
    assert!(manifest.table_states.search.as_ref().unwrap().checkpoint < manifest.frontier);
    assert_eq!(
        manifest.index_generation,
        evertrace_store::SEARCH_PROJECTION_GENERATION
    );
    assert_eq!(manifest.compiler_watermark, manifest.frontier);
    assert_eq!(manifest.hook_current_generation, Some(2));
    assert_eq!(manifest.hook_retained_generations, [1, 2]);
    assert_eq!(manifest.hook_pin_count, 1);
    assert_eq!(manifest.session_pinned_hook_artifact_count, 1);
    for required in [
        "hook-v1",
        "hooks/registry-v1.json",
        "hooks/pins/session-backup-old.pin",
        "hooks/generations/1/evertrace-hook",
        "hooks/generations/1/hook-runtime-v1.json",
        "hooks/generations/2/evertrace-hook",
        "hooks/generations/2/hook-runtime-v1.json",
    ] {
        assert!(
            manifest
                .files
                .iter()
                .any(|file| file.relative_path == required)
        );
    }
    assert!(!manifest.files.iter().any(|file| {
        file.relative_path == "hooks/pins/session-backup-after-boundary.pin"
            || file.relative_path == "hooks/registry.lock"
    }));
    let backed_up_runtime =
        RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&backup_dir)).unwrap();
    assert!(backed_up_runtime.recall_cues.is_empty());
    for generation in 1..=2 {
        let relative = format!("hooks/generations/{generation}/hook-runtime-v1.json");
        let live = RuntimeSnapshot::load(&data_dir.join(&relative)).unwrap();
        let saved = RuntimeSnapshot::load(&backup_dir.join(&relative)).unwrap();
        assert_eq!(saved, live.sanitized_for_backup().unwrap());
        assert_eq!(saved.generation, runtime.generation + generation);
        assert_eq!(live.recall_cues.len(), 1);
    }
    assert_eq!(
        RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&data_dir))
            .unwrap()
            .recall_cues
            .len(),
        1
    );
    assert!(manifest.files.iter().any(|file| {
        file.relative_path == format!("cas/blobs/{}/{}", &pre_digest[..2], &pre_digest[2..])
    }));
    assert!(manifest.files.iter().any(|file| {
        file.relative_path
            == format!(
                "cas/blobs/{}/{}",
                &second_pre_digest[..2],
                &second_pre_digest[2..]
            )
    }));
    assert!(!manifest.files.iter().any(|file| {
        file.relative_path == format!("cas/blobs/{}/{}", &post_digest[..2], &post_digest[2..])
            || file.relative_path.starts_with("keys/")
            || file.relative_path.starts_with("backups/")
            || file.relative_path.contains(".staging-")
    }));
    let offline_launcher = root.path().join("offline-hook-v1");
    let offline_hooks = root.path().join("offline-hooks");
    std::fs::rename(data_dir.join("hook-v1"), &offline_launcher).unwrap();
    std::fs::rename(data_dir.join("hooks"), &offline_hooks).unwrap();
    assert_eq!(
        verify_backup(&data_dir, backup_job_id)
            .await
            .unwrap()
            .backup_job_id,
        backup_job_id
    );
    let verify_frontier = handle.project().await.unwrap().frontier;
    let verify_request_id = RequestId::new_v7();
    let verify_job_id = JobId::from_uuid(verify_request_id.as_uuid()).unwrap();
    assert!(matches!(
        governance
            .verify_backup(verify_request_id, verify_frontier, backup_job_id)
            .await
            .unwrap(),
        HumanActionOutcome::Applied { .. }
    ));
    let report = Arc::new(RwLock::new(None::<evertrace_codex::HostProbeReport>));
    let verify_scheduler = BackgroundScheduler::new(
        handle.clone(),
        SessionCatalogService::new(handle.clone(), effective.hash()),
        SessionImportWorker::new(handle.clone(), runtime.clone(), Arc::clone(&report)).unwrap(),
        report,
        runtime.clone(),
        SynthesisPlanner::new(LlmConfig {
            enabled: false,
            ..LlmConfig::default()
        }),
        DreamingConfig::default(),
    );
    assert_eq!(verify_scheduler.run_once().await.unwrap().completed, 1);
    let detail_frontier = handle.project().await.unwrap().frontier;
    let detail = governance
        .detail(
            HumanSurface::System,
            &format!("runtime:job:{backup_job_id}"),
            detail_frontier,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    let Some(HumanSystemDetail::Job { detail }) = detail.items[0].system_detail.as_ref() else {
        panic!("backup job detail must remain typed");
    };
    let summary = detail
        .backup_summary
        .as_ref()
        .expect("completed backup detail must read the small manifest summary");
    assert_eq!(summary.frontier, manifest.frontier);
    assert_eq!(
        summary.journal.frontier,
        manifest.table_states.journal.checkpoint
    );
    assert_eq!(
        summary.objects.frontier,
        manifest.table_states.objects.checkpoint
    );
    assert_eq!(
        summary.relations.as_ref().unwrap().frontier,
        manifest.table_states.relations.as_ref().unwrap().checkpoint
    );
    assert_eq!(
        summary.search.as_ref().unwrap().frontier,
        manifest.table_states.search.as_ref().unwrap().checkpoint
    );
    assert_eq!(
        summary.index_generation,
        evertrace_store::SEARCH_PROJECTION_GENERATION
    );
    assert_eq!(summary.compiler_watermark, summary.frontier);
    assert_eq!(summary.spool_source_watermark_count, 1);
    assert_eq!(summary.hook_current_generation, Some(2));
    assert_eq!(summary.hook_retained_generations, [1, 2]);
    assert_eq!(summary.hook_pin_count, 1);
    assert_eq!(summary.session_pinned_hook_artifact_count, 1);
    assert_eq!(
        handle
            .create_backup(backup_job_id, config_path.clone(), runtime.clone())
            .await
            .unwrap()
            .unwrap()
            .backup_job_id,
        backup_job_id
    );
    assert_eq!(
        std::fs::read_dir(data_dir.join("backups"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| { entry.file_name().to_string_lossy().starts_with("backup-") })
            .count(),
        1
    );
    std::fs::rename(&offline_launcher, data_dir.join("hook-v1")).unwrap();
    std::fs::rename(&offline_hooks, data_dir.join("hooks")).unwrap();

    let generation_runtime = data_dir.join("hooks/generations/1/hook-runtime-v1.json");
    let original_runtime = std::fs::read(&generation_runtime).unwrap();
    std::fs::write(&generation_runtime, b"malformed-runtime").unwrap();
    let malformed_job = JobId::new_v7();
    assert!(
        handle
            .create_backup(malformed_job, config_path.clone(), runtime.clone())
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        !data_dir
            .join("backups")
            .join(format!("backup-{malformed_job}"))
            .exists()
    );
    std::fs::write(&generation_runtime, original_runtime).unwrap();

    let missing_reference_job_id = JobId::new_v7();
    let old_pin = data_dir.join("hooks/pins/session-backup-old.pin");
    std::fs::write(&old_pin, b"3").unwrap();
    assert!(
        handle
            .create_backup(
                missing_reference_job_id,
                config_path.clone(),
                runtime.clone(),
            )
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        !data_dir
            .join("backups")
            .join(format!("backup-{missing_reference_job_id}"))
            .exists()
    );
    std::fs::write(old_pin, b"1").unwrap();

    let spool =
        DurableSpool::open_read_only(runtime.spool_dir.clone(), runtime.spool_limits().unwrap())
            .unwrap();
    let records = spool
        .read_durable_records(
            usize::try_from(runtime.max_main_files).unwrap(),
            runtime.main_high_watermark_bytes,
        )
        .unwrap();
    assert!(
        records
            .iter()
            .any(|record| record.cas_refs == [post_digest.clone()])
    );
    let drained = EvidenceIngestor::new(
        runtime.clone(),
        handle.clone(),
        effective.hash(),
        "s33-backup-ingest-v1",
    )
    .unwrap()
    .drain_once()
    .await
    .unwrap();
    assert!(drained.committed_frames >= 3);
    assert!(handle.project().await.is_ok());

    let manifest_path = backup_dir.join("manifest.json");
    let canonical_manifest_bytes = std::fs::read(&manifest_path).unwrap();
    let canonical_manifest: BackupManifest =
        serde_json::from_slice(&canonical_manifest_bytes).unwrap();
    let runtime_relative = "hooks/generations/1/hook-runtime-v1.json";
    let saved_runtime_path = backup_dir.join(runtime_relative);
    let clean_runtime = std::fs::read(&saved_runtime_path).unwrap();
    let cue_runtime = std::fs::read(data_dir.join(runtime_relative)).unwrap();
    for tampered_runtime in [cue_runtime, b"malformed-runtime".to_vec()] {
        std::fs::write(&saved_runtime_path, &tampered_runtime).unwrap();
        let mut tampered = canonical_manifest.clone();
        let entry = tampered
            .files
            .iter_mut()
            .find(|file| file.relative_path == runtime_relative)
            .unwrap();
        entry.size = u64::try_from(tampered_runtime.len()).unwrap();
        entry.sha256 = Some(file_sha256(&tampered_runtime));
        std::fs::write(&manifest_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(verify_backup(&data_dir, backup_job_id).await.is_err());
    }
    std::fs::write(&saved_runtime_path, clean_runtime).unwrap();
    std::fs::write(&manifest_path, &canonical_manifest_bytes).unwrap();
    let hook_registry_relative = "hooks/registry-v1.json";
    let hook_registry_path = backup_dir.join(hook_registry_relative);
    let canonical_hook_registry = std::fs::read(&hook_registry_path).unwrap();
    let mut tampered_hook_registry: serde_json::Value =
        serde_json::from_slice(&canonical_hook_registry).unwrap();
    tampered_hook_registry["current_generation"] = serde_json::Value::from(1_u64);
    let tampered_hook_registry = serde_json::to_vec(&tampered_hook_registry).unwrap();
    std::fs::write(&hook_registry_path, &tampered_hook_registry).unwrap();
    let mut tampered_hook_manifest = canonical_manifest.clone();
    let hook_registry_entry = tampered_hook_manifest
        .files
        .iter_mut()
        .find(|file| file.relative_path == hook_registry_relative)
        .unwrap();
    hook_registry_entry.size = u64::try_from(tampered_hook_registry.len()).unwrap();
    hook_registry_entry.sha256 = Some(file_sha256(&tampered_hook_registry));
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&tampered_hook_manifest).unwrap(),
    )
    .unwrap();
    assert!(
        handle
            .create_backup(backup_job_id, config_path.clone(), runtime.clone())
            .await
            .unwrap()
            .is_err()
    );
    std::fs::write(&hook_registry_path, &canonical_hook_registry).unwrap();
    std::fs::write(&manifest_path, &canonical_manifest_bytes).unwrap();

    let copied_generation = backup_dir.join("hooks/generations/1/evertrace-hook");
    let copied_generation_bytes = std::fs::read(&copied_generation).unwrap();
    std::fs::remove_file(&copied_generation).unwrap();
    assert!(
        handle
            .create_backup(backup_job_id, config_path.clone(), runtime.clone())
            .await
            .unwrap()
            .is_err()
    );
    std::fs::write(&copied_generation, &copied_generation_bytes).unwrap();
    std::fs::set_permissions(&copied_generation, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cas_relative = canonical_manifest
        .files
        .iter()
        .find(|file| {
            file.relative_path == format!("cas/blobs/{}/{}", &pre_digest[..2], &pre_digest[2..])
        })
        .unwrap()
        .relative_path
        .clone();
    let cas_path = backup_dir.join(&cas_relative);
    let canonical_cas = std::fs::read(&cas_path).unwrap();
    let mut tampered_cas = canonical_cas.clone();
    *tampered_cas.last_mut().unwrap() ^= 0x5a;
    std::fs::write(&cas_path, &tampered_cas).unwrap();
    let mut tampered_manifest = canonical_manifest.clone();
    tampered_manifest
        .files
        .iter_mut()
        .find(|file| file.relative_path == cas_relative)
        .unwrap()
        .sha256 = Some(file_sha256(&tampered_cas));
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&tampered_manifest).unwrap(),
    )
    .unwrap();
    assert!(verify_backup(&data_dir, backup_job_id).await.is_err());
    std::fs::write(&cas_path, &canonical_cas).unwrap();
    std::fs::write(&manifest_path, &canonical_manifest_bytes).unwrap();

    let spool_relative = canonical_manifest
        .spool_files
        .iter()
        .find(|file| {
            file.kind == evertrace_store::backup::BackupSpoolFileKind::Normal
                || file.kind == evertrace_store::backup::BackupSpoolFileKind::Isolated
        })
        .unwrap()
        .relative_path
        .clone();
    let spool_path = backup_dir.join(&spool_relative);
    let canonical_spool = std::fs::read(&spool_path).unwrap();
    let mut tampered_spool = canonical_spool.clone();
    tampered_spool[0] ^= 0x7f;
    std::fs::write(&spool_path, &tampered_spool).unwrap();
    let mut tampered_manifest = canonical_manifest.clone();
    tampered_manifest
        .files
        .iter_mut()
        .find(|file| file.relative_path == spool_relative)
        .unwrap()
        .sha256 = Some(file_sha256(&tampered_spool));
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&tampered_manifest).unwrap(),
    )
    .unwrap();
    assert!(verify_backup(&data_dir, backup_job_id).await.is_err());
    std::fs::write(&spool_path, &canonical_spool).unwrap();
    std::fs::write(&manifest_path, &canonical_manifest_bytes).unwrap();

    let mut forged_table_manifest = canonical_manifest.clone();
    forged_table_manifest.table_states.journal.version += 1;
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&forged_table_manifest).unwrap(),
    )
    .unwrap();
    assert!(verify_backup(&data_dir, backup_job_id).await.is_err());
    std::fs::write(&manifest_path, &canonical_manifest_bytes).unwrap();

    let mut ahead_checkpoint_manifest = canonical_manifest.clone();
    ahead_checkpoint_manifest
        .table_states
        .relations
        .as_mut()
        .unwrap()
        .checkpoint = ahead_checkpoint_manifest.frontier + 1;
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&ahead_checkpoint_manifest).unwrap(),
    )
    .unwrap();
    assert!(verify_backup(&data_dir, backup_job_id).await.is_err());
    std::fs::write(&manifest_path, &canonical_manifest_bytes).unwrap();

    let exports_dir = backup_dir.join("exports");
    std::fs::create_dir(&exports_dir).unwrap();
    std::fs::set_permissions(&exports_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let excluded_file = exports_dir.join("extra");
    std::fs::write(&excluded_file, b"excluded").unwrap();
    std::fs::set_permissions(&excluded_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut excluded_manifest = canonical_manifest.clone();
    excluded_manifest
        .files
        .push(evertrace_store::backup::BackupFileManifest {
            relative_path: "exports".into(),
            kind: evertrace_store::backup::BackupFileKind::Directory,
            size: 0,
            sha256: None,
        });
    excluded_manifest
        .files
        .push(evertrace_store::backup::BackupFileManifest {
            relative_path: "exports/extra".into(),
            kind: evertrace_store::backup::BackupFileKind::Regular,
            size: 8,
            sha256: Some(file_sha256(b"excluded")),
        });
    excluded_manifest
        .files
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&excluded_manifest).unwrap(),
    )
    .unwrap();
    assert!(verify_backup(&data_dir, backup_job_id).await.is_err());
    std::fs::remove_file(excluded_file).unwrap();
    std::fs::remove_dir(exports_dir).unwrap();
    std::fs::write(&manifest_path, &canonical_manifest_bytes).unwrap();

    let missing_job_id = JobId::new_v7();
    let crash_staging = data_dir
        .join("backups")
        .join(format!(".staging-{missing_job_id}"));
    std::fs::create_dir(&crash_staging).unwrap();
    std::fs::set_permissions(&crash_staging, std::fs::Permissions::from_mode(0o700)).unwrap();
    let crash_residue = crash_staging.join("partial");
    std::fs::write(&crash_residue, b"interrupted-before-publish").unwrap();
    std::fs::set_permissions(&crash_residue, std::fs::Permissions::from_mode(0o600)).unwrap();
    handle
        .create_backup(missing_job_id, config_path.clone(), runtime.clone())
        .await
        .unwrap()
        .unwrap();
    assert!(!crash_staging.exists());
    let missing_dir = data_dir
        .join("backups")
        .join(format!("backup-{missing_job_id}"));
    std::fs::remove_file(missing_dir.join("config/config.toml")).unwrap();
    assert!(verify_backup(&data_dir, missing_job_id).await.is_err());

    let symlink_job_id = JobId::new_v7();
    handle
        .create_backup(symlink_job_id, config_path.clone(), runtime.clone())
        .await
        .unwrap()
        .unwrap();
    let symlink_dir = data_dir
        .join("backups")
        .join(format!("backup-{symlink_job_id}"));
    let symlink_manifest_path = symlink_dir.join("manifest.json");
    let canonical_manifest = std::fs::read(&symlink_manifest_path).unwrap();
    let mut malicious_manifest: BackupManifest =
        serde_json::from_slice(&canonical_manifest).unwrap();
    malicious_manifest.files[0].relative_path = "../escape".into();
    std::fs::write(
        &symlink_manifest_path,
        serde_json::to_vec(&malicious_manifest).unwrap(),
    )
    .unwrap();
    assert!(verify_backup(&data_dir, symlink_job_id).await.is_err());
    let mut duplicate_manifest: BackupManifest =
        serde_json::from_slice(&canonical_manifest).unwrap();
    duplicate_manifest.files[1].relative_path = duplicate_manifest.files[0].relative_path.clone();
    std::fs::write(
        &symlink_manifest_path,
        serde_json::to_vec(&duplicate_manifest).unwrap(),
    )
    .unwrap();
    assert!(verify_backup(&data_dir, symlink_job_id).await.is_err());
    std::fs::write(&symlink_manifest_path, canonical_manifest).unwrap();
    let symlink_config = symlink_dir.join("config/config.toml");
    std::fs::remove_file(&symlink_config).unwrap();
    std::os::unix::fs::symlink(&config_path, &symlink_config).unwrap();
    assert!(verify_backup(&data_dir, symlink_job_id).await.is_err());

    std::fs::write(backup_dir.join("config/config.toml"), b"tampered").unwrap();
    assert!(verify_backup(&data_dir, backup_job_id).await.is_err());
    let projected = handle.project().await.unwrap();
    let jobs = RuntimeSchedulerView::from_snapshot(&projected).unwrap();
    let terminal = jobs
        .jobs
        .iter()
        .find(|job| job.job_id == backup_job_id)
        .unwrap();
    assert_eq!(terminal.kind, QUIESCED_BACKUP_CREATE_JOB_KIND);
    assert_eq!(terminal.state, JobStatus::Succeeded);
    assert_eq!(
        jobs.jobs
            .iter()
            .find(|job| job.job_id == verify_job_id)
            .unwrap()
            .state,
        JobStatus::Succeeded
    );
    handle.shutdown().await.unwrap();
    actor.await.unwrap().unwrap();
}

#[test]
fn maintenance_fence_child() {
    let Some(root) = std::env::var_os("EVERTRACE_S33_FENCE_CHILD_ROOT") else {
        return;
    };
    if std::env::var("EVERTRACE_S33_FENCE_CHILD_MODE").unwrap() == "writer" {
        assert!(matches!(
            evertrace_store::SiblingWriterLock::acquire(Path::new(&root)),
            Err(StoreError::WriterAlreadyRunning)
        ));
        return;
    }
    let fence = evertrace_capture::MaintenanceFence::open(Path::new(&root)).unwrap();
    let result = match std::env::var("EVERTRACE_S33_FENCE_CHILD_MODE")
        .unwrap()
        .as_str()
    {
        "shared" => fence.shared().map(drop),
        "exclusive" => fence.exclusive().map(drop),
        _ => panic!("unknown child fence mode"),
    };
    assert_eq!(result, Err(CasError::LockBusy));
}

fn assert_child_fence_busy(root: &Path, mode: &str) {
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("maintenance_fence_child")
        .arg("--nocapture")
        .env("EVERTRACE_S33_FENCE_CHILD_ROOT", root)
        .env("EVERTRACE_S33_FENCE_CHILD_MODE", mode)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn maintenance_fence_is_cross_process_and_identity_safe() {
    let root = TempDir::new().unwrap();
    let data = root.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let original_cas = CasStore::open(data.join("cas")).unwrap();
    let key = DeviceKeyStore::new(data.join("keys"))
        .load_or_create()
        .unwrap();
    let protected = evertrace_capture::protect::protect(b"pinned-root-blob", &key).unwrap();
    let digest = original_cas.put(&protected).unwrap();

    let original_fence = evertrace_capture::MaintenanceFence::open(&data).unwrap();
    let sibling_data = root.path().join("data-b");
    std::fs::create_dir(&sibling_data).unwrap();
    CasStore::open(sibling_data.join("cas")).unwrap();
    let sibling_fence = evertrace_capture::MaintenanceFence::open(&sibling_data).unwrap();
    {
        let exclusive = original_fence.exclusive().unwrap();
        sibling_fence.shared().unwrap();
        sibling_fence.exclusive().unwrap();
        assert_child_fence_busy(&data, "shared");
        drop(exclusive);
    }
    let shared = original_fence.shared().unwrap();
    assert_eq!(
        CasStore::delete_guarded_batch(&shared, &[digest]),
        Err(CasError::ExclusiveMaintenanceRequired)
    );
    assert!(original_cas.read(&digest).is_ok());
    assert_child_fence_busy(&data, "exclusive");
    drop(shared);

    let fence = evertrace_capture::MaintenanceFence::open(&data).unwrap();
    let exclusive = fence.exclusive().unwrap();
    assert_child_fence_busy(&data, "shared");
    let displaced = root.path().join("displaced");
    std::fs::rename(&data, &displaced).unwrap();
    std::fs::create_dir(&data).unwrap();
    let replacement_cas = CasStore::open(data.join("cas")).unwrap();
    replacement_cas.put(&protected).unwrap();

    assert_eq!(
        CasStore::delete_guarded_batch(&exclusive, &[digest]).unwrap(),
        [evertrace_capture::CasDeleteOutcome::Deleted]
    );
    let displaced_cas = CasStore::open(displaced.join("cas")).unwrap();
    assert_eq!(displaced_cas.read(&digest), Err(CasError::NotFound));
    assert!(replacement_cas.read(&digest).is_ok());
}
