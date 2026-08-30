use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::PathBuf,
    str::FromStr,
};

use evertrace_domain::ids::{CommandId, JobId};
use evertrace_engine::{
    JobResultDisposition, WriterActorError, classify_job_result, expired_leases, open_writer,
    pending_dirty, pending_outbox, spawn_writer,
};
use evertrace_store::{
    CommitOutcome, CompatibilityStore, ConfigAudit, DirtyTarget, DirtyTargetKind, DurableJob,
    JOURNAL_TABLE, JobBudget, JobLease, JobStatus, JournalCommand, JournalEventDraft,
    JournalPayload, JournalWriter, L0001, MigrationOutcome, OBJECTS_TABLE, ObjectRowKind,
    OutboxEntry, SiblingWriterLock, StaleGenerationAudit, StoreError, WatermarkAdvanced,
    WatermarkKind, journal_schema, objects_schema, reduce_journal,
};
use tempfile::TempDir;

const CONFIG_HASH: [u8; 32] = [0x5a; 32];

fn command_id(suffix: u8) -> CommandId {
    CommandId::from_str(&format!("01890f47-6a4a-7cc1-98b9-01890f476a{suffix:02x}")).unwrap()
}

fn job_id() -> JobId {
    JobId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a80").unwrap()
}

fn dirty(watermark: u64) -> DirtyTarget {
    DirtyTarget {
        target_kind: DirtyTargetKind::ObjectsProjection,
        target_id: "evertrace_objects".into(),
        algorithm_revision: "objects-v1".into(),
        source_watermark: watermark,
    }
}

fn draft(payload: JournalPayload) -> JournalEventDraft {
    JournalEventDraft::runtime(10, CONFIG_HASH, "objects-v1", payload)
}

fn command(suffix: u8, payloads: Vec<JournalPayload>) -> JournalCommand {
    JournalCommand::new(
        command_id(suffix),
        payloads.into_iter().map(draft).collect(),
    )
    .unwrap()
}

#[tokio::test]
async fn l0001_bootstrap_reopen_is_noop_and_creates_only_authorized_tables() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let writer = JournalWriter::open(&root).await.unwrap();
    assert_eq!(writer.migration_outcome(), MigrationOutcome::Applied);
    assert_eq!(
        writer.table_names().await.unwrap(),
        vec![
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search",
        ]
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), 2);
    let objects = writer.object_rows().await.unwrap();
    assert_eq!(
        objects
            .iter()
            .filter(|row| row.row_kind == ObjectRowKind::Checkpoint)
            .count(),
        1
    );
    assert!(
        objects
            .iter()
            .any(|row| row.row_id == "projection:migration:L0001")
    );
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(writer.lock_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(writer);

    let reopened = JournalWriter::open(&root).await.unwrap();
    assert_eq!(reopened.migration_outcome(), MigrationOutcome::Noop);
    assert_eq!(reopened.journal_rows().await.unwrap().len(), 2);
}

#[tokio::test]
async fn l0001_reconciles_valid_tables_with_missing_event_once() {
    let temp = TempDir::new().unwrap();
    let store = CompatibilityStore::connect_local(temp.path())
        .await
        .unwrap();
    store
        .connection()
        .create_empty_table(JOURNAL_TABLE, journal_schema())
        .execute()
        .await
        .unwrap();
    store
        .connection()
        .create_empty_table(OBJECTS_TABLE, objects_schema())
        .execute()
        .await
        .unwrap();
    assert_eq!(
        L0001::apply(store.connection()).await,
        Ok(MigrationOutcome::Reconciled)
    );
    assert_eq!(
        L0001::apply(store.connection()).await,
        Ok(MigrationOutcome::Noop)
    );
}

#[tokio::test]
async fn sibling_lock_refuses_second_writer_and_survives_root_swap() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let writer = JournalWriter::open(&root).await.unwrap();
    let lock_path = writer.lock_path().to_owned();
    let identity = writer.lock_inode_identity().unwrap();
    assert!(matches!(
        JournalWriter::open(&root).await,
        Err(StoreError::WriterAlreadyRunning)
    ));

    let old_root = temp.path().join("store-before-swap");
    fs::rename(&root, &old_root).unwrap();
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(&root).unwrap();
    assert!(matches!(
        JournalWriter::open(&root).await,
        Err(StoreError::WriterAlreadyRunning)
    ));
    assert_eq!(writer.lock_path(), lock_path);
    assert_eq!(writer.lock_inode_identity().unwrap(), identity);
    drop(writer);
    assert!(lock_path.exists());
    assert!(JournalWriter::open(&root).await.is_ok());
}

#[test]
fn sibling_lock_and_data_root_reject_symlink_type_and_permissions() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let lock = temp.path().join("store.writer.lock");
    let target = temp.path().join("lock-target");
    fs::write(&target, []).unwrap();
    symlink(&target, &lock).unwrap();
    assert!(matches!(
        SiblingWriterLock::acquire(&root),
        Err(StoreError::InvalidType)
    ));
    fs::remove_file(&lock).unwrap();

    fs::write(&lock, []).unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        SiblingWriterLock::acquire(&root),
        Err(StoreError::InvalidPermissions)
    ));
    fs::remove_file(&lock).unwrap();

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o755).create(&root).unwrap();
    assert!(matches!(
        SiblingWriterLock::acquire(&root),
        Err(StoreError::InvalidPermissions)
    ));
}

#[tokio::test]
async fn command_commit_retry_conflict_and_lost_ack_reopen_are_strict() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let mut writer = JournalWriter::open(&root).await.unwrap();
    let original = command(
        0x81,
        vec![
            JournalPayload::DirtyTarget(dirty(11)),
            JournalPayload::OutboxEnqueued(OutboxEntry {
                outbox_id: "outbox-command-81".into(),
                dirty: dirty(11),
            }),
        ],
    );
    let first = writer.commit(&original, 20).await.unwrap();
    assert!(!first.replayed);
    let replay = writer.commit(&original, 99).await.unwrap();
    assert_replay(&first, &replay);
    assert_eq!(writer.journal_rows().await.unwrap().len(), 4);
    drop(writer);

    let mut reopened = JournalWriter::open(&root).await.unwrap();
    let lost_ack_retry = reopened.commit(&original, 100).await.unwrap();
    assert_replay(&first, &lost_ack_retry);
    let conflict = command(0x81, vec![JournalPayload::DirtyTarget(dirty(12))]);
    assert_eq!(
        reopened.commit(&conflict, 101).await,
        Err(StoreError::IdempotencyConflict)
    );
    assert_eq!(reopened.journal_rows().await.unwrap().len(), 4);
}

#[tokio::test]
async fn preflight_failure_has_no_partial_command_and_fixed_retry_sequence_is_stable() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let mut writer = JournalWriter::open(&root).await.unwrap();
    let invalid = JournalCommand::new(
        command_id(0x82),
        vec![JournalEventDraft::runtime(
            0,
            CONFIG_HASH,
            "",
            JournalPayload::DirtyTarget(dirty(1)),
        )],
    )
    .unwrap();
    assert_eq!(
        writer.commit(&invalid, 1).await,
        Err(StoreError::InvalidInput)
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), 2);
    let unpaired_outbox = command(
        0x83,
        vec![JournalPayload::OutboxEnqueued(OutboxEntry {
            outbox_id: "unpaired".into(),
            dirty: dirty(2),
        })],
    );
    assert_eq!(
        writer.commit(&unpaired_outbox, 2).await,
        Err(StoreError::InvalidInput)
    );
    assert_eq!(
        writer
            .commit(
                &command(0x84, vec![JournalPayload::DirtyTarget(dirty(3))]),
                -1,
            )
            .await,
        Err(StoreError::InvalidInput)
    );

    for index in 0..8_u8 {
        let value = command(
            0x90 + index,
            vec![JournalPayload::DirtyTarget(dirty(u64::from(index)))],
        );
        let first = writer.commit(&value, 10 + i64::from(index)).await.unwrap();
        if index % 2 == 0 {
            assert_replay(
                &first,
                &writer.commit(&value, 100 + i64::from(index)).await.unwrap(),
            );
        }
    }
    let rows = writer.journal_rows().await.unwrap();
    assert_eq!(rows.len(), 10);
    let mut seqs = rows.iter().map(|row| row.seq).collect::<Vec<_>>();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs.len(), rows.len());
    let mut gapped = rows;
    gapped.sort_by_key(|row| row.seq);
    for row in gapped.iter_mut().skip(4) {
        row.seq += 9;
    }
    let snapshot = reduce_journal(&gapped).unwrap();
    assert_eq!(snapshot.frontier, gapped.last().unwrap().seq);
    assert_eq!(snapshot.data_rows().count(), 10);
}

#[tokio::test]
async fn dirty_outbox_projection_is_incremental_and_full_rebuild_is_identical() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let mut writer = JournalWriter::open(&root).await.unwrap();
    let payloads = vec![
        JournalPayload::DirtyTarget(dirty(7)),
        JournalPayload::OutboxEnqueued(OutboxEntry {
            outbox_id: "outbox-7".into(),
            dirty: dirty(7),
        }),
    ];
    writer
        .commit(&command(0xa1, payloads.clone()), 10)
        .await
        .unwrap();
    writer.project().await.unwrap();
    let reader = CompatibilityStore::connect_local(&root).await.unwrap();
    let objects = reader
        .connection()
        .open_table(OBJECTS_TABLE)
        .execute()
        .await
        .unwrap();
    let before_no_delta = objects.version().await.unwrap();
    writer.project().await.unwrap();
    assert_eq!(objects.version().await.unwrap(), before_no_delta);
    writer.commit(&command(0xa2, payloads), 11).await.unwrap();
    let incremental = writer.project().await.unwrap();
    assert_eq!(
        pending_dirty(&incremental.rows, incremental.frontier)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        pending_outbox(&incremental.rows, incremental.frontier)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(incremental, writer.full_projection().await.unwrap());
    drop(writer);

    fs::remove_dir_all(root.join("evertrace_objects.lance")).unwrap();
    let rebuilt = JournalWriter::open(&root).await.unwrap();
    assert_eq!(
        rebuilt.migration_outcome(),
        MigrationOutcome::RebuiltObjects
    );
    assert_eq!(rebuilt.object_rows().await.unwrap(), incremental.rows);
}

#[tokio::test]
async fn job_lease_recovery_watermark_config_and_stale_audit_rebuild() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let mut writer = JournalWriter::open(&root).await.unwrap();
    let job = DurableJob {
        job_id: job_id(),
        idempotency_key: "job-runtime-1".into(),
        target_revision: "revision-7".into(),
        target_watermark: 7,
        target_generation: 4,
        kind: "objects_projection".into(),
        algorithm_revision: "objects_projection_v1".into(),
        model_id: None,
        priority: 5,
        state: JobStatus::Queued,
        attempt: 1,
        backoff_until_us: Some(40),
        config_hash: CONFIG_HASH,
        budget: JobBudget {
            max_items: 1,
            max_bytes: None,
            max_input_tokens: None,
            max_output_tokens: None,
            max_calls: None,
            max_wall_time_ms: 250,
        },
        terminal: None,
        lease_until_us: None,
    };
    writer
        .commit(
            &command(
                0xb1,
                vec![
                    JournalPayload::JobState(job.clone()),
                    JournalPayload::JobLease(JobLease {
                        job_id: job.job_id,
                        target_generation: 4,
                        attempt: 2,
                        lease_until_us: 60,
                    }),
                    JournalPayload::WatermarkAdvanced(WatermarkAdvanced {
                        kind: WatermarkKind::RuntimeJobs,
                        value: 7,
                    }),
                    JournalPayload::ConfigAudit(ConfigAudit {
                        config_version: 1,
                        effective_config_hash: CONFIG_HASH,
                    }),
                ],
            ),
            20,
        )
        .await
        .unwrap();
    let before_stale = writer.project().await.unwrap();
    assert!(
        expired_leases(&before_stale.rows, 59, before_stale.frontier)
            .unwrap()
            .is_empty()
    );
    let recovery = expired_leases(&before_stale.rows, 60, before_stale.frontier).unwrap();
    assert_eq!(recovery.len(), 1);
    assert_eq!(recovery[0].next_attempt, 3);
    let JobResultDisposition::StaleAudit(stale) = classify_job_result(&job, 5) else {
        panic!("generation mismatch must become an audit")
    };
    writer
        .commit(
            &command(
                0xb2,
                vec![JournalPayload::StaleGenerationAudit(stale.clone())],
            ),
            21,
        )
        .await
        .unwrap();
    let after_stale = writer.project().await.unwrap();
    let job_row_id = format!("runtime:job:{}", job.job_id);
    assert_eq!(
        before_stale.row(&job_row_id).unwrap(),
        after_stale.row(&job_row_id).unwrap()
    );
    let expected_stale_json = JournalPayload::StaleGenerationAudit(StaleGenerationAudit {
        job_id: stale.job_id,
        expected_generation: stale.expected_generation,
        observed_generation: stale.observed_generation,
    })
    .canonical_json()
    .unwrap();
    assert!(after_stale.rows.iter().any(|row| {
        row.row_id.starts_with("projection:audit:stale:")
            && row.payload_json.as_deref() == Some(expected_stale_json.as_str())
    }));
    assert!(after_stale.row("runtime:watermark:runtime_jobs").is_some());
    assert!(after_stale.row("runtime:config:current").is_some());
    assert_eq!(after_stale, writer.full_projection().await.unwrap());
    drop(writer);

    fs::remove_dir_all(root.join("evertrace_objects.lance")).unwrap();
    let rebuilt = JournalWriter::open(&root).await.unwrap();
    assert_eq!(
        rebuilt.migration_outcome(),
        MigrationOutcome::RebuiltObjects
    );
    assert_eq!(rebuilt.object_rows().await.unwrap(), after_stale.rows);
    let recovered = expired_leases(&after_stale.rows, 60, after_stale.frontier).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].next_attempt, 3);
}

#[tokio::test]
async fn daemon_writer_assembly_holds_lock_commits_drains_and_releases() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let writer = open_writer(&root).await.unwrap();
    let (handle, task) = spawn_writer(writer, 2).unwrap();
    assert!(matches!(
        JournalWriter::open(&root).await,
        Err(StoreError::WriterAlreadyRunning)
    ));
    let outcome = handle
        .commit(
            command(0xc1, vec![JournalPayload::DirtyTarget(dirty(1))]),
            1,
        )
        .await
        .unwrap();
    assert!(!outcome.replayed);
    assert!(handle.project().await.unwrap().frontier >= outcome.last_seq);
    handle.shutdown().await.unwrap();
    assert_eq!(task.await.unwrap(), Ok(()));
    assert!(JournalWriter::open(&root).await.is_ok());
    assert_eq!(
        WriterActorError::Stopped.to_string(),
        "writer actor stopped"
    );
}

#[test]
fn hook_manifest_has_no_store_or_runtime_database_dependency() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = fs::read_to_string(root.join("crates/evertrace-hook/Cargo.toml")).unwrap();
    let manifest: toml::Value = toml::from_str(&manifest).unwrap();
    let dependencies = manifest["dependencies"].as_table().unwrap();
    for forbidden in [
        "evertrace-store",
        "lancedb",
        "arrow-array",
        "arrow-schema",
        "tokio",
    ] {
        assert!(!dependencies.contains_key(forbidden), "{forbidden}");
    }
}

fn assert_replay(first: &CommitOutcome, replay: &CommitOutcome) {
    assert!(replay.replayed);
    assert_eq!(replay.command_id, first.command_id);
    assert_eq!(replay.first_seq, first.first_seq);
    assert_eq!(replay.last_seq, first.last_seq);
    assert_eq!(replay.event_ids, first.event_ids);
}
