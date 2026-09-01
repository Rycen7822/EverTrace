use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::Arc,
    time::{Duration, Instant},
};

use evertrace_capture::{
    DeviceKeyStore, RUNTIME_SNAPSHOT_VERSION, RecallCueGateMode, RecoveryGateMode, RuntimeSnapshot,
};
use evertrace_domain::{ids::RequestId, semantic::ProposalStatus};
use evertrace_engine::{
    SessionImportBudget, SessionImportWorker, open_writer,
    repository::observe_session_catalog_report,
    session_import::{
        FrozenMemoryExportMigrationService, SessionCatalogService, SessionImportAdminAction,
        SessionImportAdminOutcome, SessionImportAdminService,
    },
    spawn_writer,
};
use evertrace_store::{
    JobStatus, JournalPayload, JournalWriter, SemanticCurrentView, SessionBodyState,
    SessionImportCurrentView,
};
use tempfile::TempDir;
use tokio::sync::RwLock;

const CONFIG: [u8; 32] = [28; 32];

fn runtime(root: &std::path::Path) -> RuntimeSnapshot {
    RuntimeSnapshot {
        snapshot_version: RUNTIME_SNAPSHOT_VERSION,
        generation: 1,
        device_key_dir: root.join("keys"),
        cas_dir: root.join("cas"),
        spool_dir: root.join("spool"),
        main_high_watermark_bytes: 2 * 1024 * 1024,
        main_low_watermark_bytes: 64 * 1024,
        max_main_files: 16,
        emergency_slots: 2,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn frozen_memory_export_maps_to_l0_pending_proposal_and_provenance() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let data_dir = temp.path().join("data");
    let writer = open_writer(&data_dir).await.unwrap();
    let (handle, task) = spawn_writer(writer, 32).unwrap();
    let service =
        FrozenMemoryExportMigrationService::new(handle.clone(), runtime(temp.path())).unwrap();
    let export = serde_json::to_vec(&serde_json::json!({
        "version": "0.9.29",
        "exportedAt": "2026-08-30T00:00:00Z",
        "sessions": [{
            "id": "session-a", "project": "project-a", "cwd": "/repo",
            "startedAt": "2026-08-30T00:00:00Z", "endedAt": "2026-08-30T00:00:04Z",
            "status": "completed", "observationCount": 1
        }],
        "observations": {"session-a": [{
            "id": "observation-a", "sessionId": "session-a",
            "timestamp": "2026-08-30T00:00:01Z", "type": "decision",
            "title": "legacy decision", "facts": ["untrusted fact"],
            "narrative": "legacy imported claim", "concepts": ["legacy"],
            "files": [], "importance": 0.8
        }]},
        "memories": [
            {
                "id": "memory-a", "createdAt": "2026-08-30T00:00:02Z",
                "updatedAt": "2026-08-30T00:00:03Z", "type": "fact",
                "title": "legacy memory", "content": "review before accepting",
                "concepts": ["legacy"], "files": [], "sessionIds": ["session-a"],
                "strength": 0.7, "version": 1, "isLatest": true,
                "sourceObservationIds": ["observation-a"]
            },
            {
                "id": "memory-b", "createdAt": "2026-08-30T00:00:02Z",
                "updatedAt": "2026-08-30T00:00:03Z", "type": "fact",
                "title": "second legacy memory", "content": "also requires review",
                "concepts": ["legacy"], "files": [], "sessionIds": ["session-a"],
                "strength": 0.6, "version": 1, "isLatest": true,
                "sourceObservationIds": ["observation-a"]
            }
        ],
        "summaries": [],
        "graphNodes": [{
            "id": "node-a", "type": "concept", "name": "legacy",
            "properties": {}, "sourceObservationIds": ["observation-a"],
            "createdAt": "2026-08-30T00:00:04Z"
        }],
        "graphEdges": []
    }))
    .unwrap();
    let first = service.import_export(&export, 28).await.unwrap();
    assert_eq!(
        (first.observations, first.memory_evidence, first.proposals),
        (1, 2, 2)
    );
    assert_eq!(first.graph_provenance.len(), 1);
    let projected = handle.project().await.unwrap();
    let semantic = SemanticCurrentView::from_snapshot(&projected).unwrap();
    assert_eq!(semantic.proposals.len(), 2);
    assert!(
        semantic
            .proposals
            .values()
            .all(|proposal| proposal.status == ProposalStatus::Pending)
    );
    assert!(semantic.atoms.is_empty());
    let second = service.import_export(&export, 29).await.unwrap();
    assert_eq!(second.proposals, 0);
    let replayed = handle.project().await.unwrap();
    assert_eq!(
        replayed
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("source_observation"))
            .count(),
        4
    );
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let reopened = JournalWriter::open(&data_dir).await.unwrap();
    assert_eq!(reopened.project().await.unwrap(), replayed);
    reopened.full_projection().await.unwrap();
    assert_eq!(reopened.project().await.unwrap(), replayed);
    assert_eq!(
        reopened.table_names().await.unwrap(),
        [
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search"
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn qualified_catalog_admin_and_streaming_body_rebuild_from_four_tables() {
    let temp = TempDir::new().unwrap();
    let adapter = temp.path().join("adapter");
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
    let session_id = "019d0000-0000-7000-8000-000000000028";
    let transcript = dated.join(format!("rollout-2026-08-30T00-00-00-{session_id}.jsonl"));
    let header = serde_json::json!({
        "timestamp": "2026-08-30T00:00:00Z",
        "type": "session_meta",
        "payload": {
            "id": session_id,
            "cwd": "/not-a-repository",
            "originator": "codex_cli_rs",
            "model_provider": "openai",
            "git": null
        }
    });
    let visible = serde_json::json!({
        "timestamp": "2026-08-30T00:00:01Z",
        "type": "event_msg",
        "payload": {"type": "user_message", "message": "bounded import proof"}
    });
    let extra_records = (0..32)
        .map(|index| {
            serde_json::json!({
                "timestamp": "2026-08-30T00:00:01Z",
                "type": "event_msg",
                "payload": {"type": "agent_message", "message": format!("record-{index}")}
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    let base = format!("{header}\n{visible}\n{extra_records}\n");
    fs::write(&transcript, &base).unwrap();
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    let report =
        observe_session_catalog_report(transcript.to_str(), session_id, "tool-use-s28").unwrap();

    let data_dir = temp.path().join("data");
    let writer = open_writer(&data_dir).await.unwrap();
    let (handle, task) = spawn_writer(writer, 32).unwrap();
    let catalog = SessionCatalogService::new(handle.clone(), CONFIG);
    assert_eq!(catalog.refresh(&report).await.unwrap(), 1);
    let debug_projection = handle.project().await;
    assert!(
        debug_projection.is_ok(),
        "catalog projection: {debug_projection:?}"
    );

    let report = Arc::new(RwLock::new(Some(report)));
    let admin = SessionImportAdminService::new(handle.clone(), Arc::clone(&report), CONFIG);
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                session_id,
                SessionImportAdminAction::QueueImport,
                10,
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                session_id,
                SessionImportAdminAction::QueueImport,
                11,
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::NoDelta
    );

    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let worker =
        SessionImportWorker::new(handle.clone(), runtime(temp.path()), Arc::clone(&report))
            .unwrap();
    let mut imported = 0;
    for (checkpoint, expected_complete) in [false, false, true].into_iter().enumerate() {
        let progress = worker
            .process_checkpoint(
                session_id,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    deadline: Instant::now() + Duration::from_secs(2),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("initial checkpoint {checkpoint} failed: {error:?}"));
        imported += progress.records;
        assert_eq!(progress.completed, expected_complete);
    }
    assert_eq!(imported, 34);
    let projected = handle.project().await.unwrap();
    let current = SessionImportCurrentView::from_snapshot(&projected).unwrap();
    assert_eq!(
        current.sessions[session_id].body_state,
        SessionBodyState::Imported
    );
    assert_eq!(
        projected
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("source_observation"))
            .count(),
        34
    );
    assert!(projected.data_rows().any(|row| {
        row.payload_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<JournalPayload>(json).ok())
            .is_some_and(|payload| matches!(
                payload,
                JournalPayload::SourceIngestWatermark(value)
                    if value.source_instance_id.as_str() == format!("codex-session:{session_id}")
                        && value.confirmed_prefix_digest.is_some()
            ))
    }));

    let appended = serde_json::json!({
        "timestamp": "2026-08-30T00:00:02Z",
        "type": "response_item",
        "payload": {"type": "message", "text": "append-only checkpoint"}
    });
    fs::write(&transcript, format!("{base}{appended}\n")).unwrap();
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    let append_report =
        observe_session_catalog_report(transcript.to_str(), session_id, "tool-use-s28-append")
            .unwrap();
    *report.write().await = Some(append_report.clone());
    assert_eq!(catalog.refresh(&append_report).await.unwrap(), 1);
    assert_eq!(
        SessionImportCurrentView::from_snapshot(&handle.project().await.unwrap())
            .unwrap()
            .sessions[session_id]
            .body_state,
        SessionBodyState::Queued
    );
    assert_eq!(
        worker
            .process_checkpoint(
                session_id,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    deadline: Instant::now() + Duration::from_secs(2),
                },
            )
            .await
            .unwrap()
            .records,
        1
    );

    let changed_visible = serde_json::json!({
        "timestamp": "2026-08-30T00:00:01Z",
        "type": "event_msg",
        "payload": {"type": "user_message", "message": "rewritten prefix is longer"}
    });
    let extra = serde_json::json!({
        "timestamp": "2026-08-30T00:00:03Z",
        "type": "response_item",
        "payload": {"type": "message", "text": "growth cannot hide rewrite"}
    });
    fs::write(
        &transcript,
        format!("{header}\n{changed_visible}\n{extra_records}\n{appended}\n{extra}\n"),
    )
    .unwrap();
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    let rewrite_grow_report = observe_session_catalog_report(
        transcript.to_str(),
        session_id,
        "tool-use-s28-rewrite-grow",
    )
    .unwrap();
    *report.write().await = Some(rewrite_grow_report.clone());
    assert_eq!(catalog.refresh(&rewrite_grow_report).await.unwrap(), 1);
    assert!(
        worker
            .process_checkpoint(
                session_id,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    deadline: Instant::now() + Duration::from_secs(2),
                },
            )
            .await
            .is_err()
    );
    let replaced = SessionImportCurrentView::from_snapshot(&handle.project().await.unwrap())
        .unwrap()
        .sessions
        .remove(session_id)
        .unwrap();
    assert_eq!(replaced.body_state, SessionBodyState::SourceReplaced);
    assert!(replaced.access_decision.is_none());
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                session_id,
                SessionImportAdminAction::QueueImport,
                12,
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );
    for (checkpoint, expected_completed) in [false, false, true].into_iter().enumerate() {
        let progress = worker
            .process_checkpoint(
                session_id,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    deadline: Instant::now() + Duration::from_secs(2),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("checkpoint {checkpoint} failed: {error:?}"));
        assert_eq!(progress.completed, expected_completed);
    }

    fs::write(&transcript, format!("{header}\n{visible}\n")).unwrap();
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    let rewrite_report =
        observe_session_catalog_report(transcript.to_str(), session_id, "tool-use-s28-rewrite")
            .unwrap();
    *report.write().await = Some(rewrite_report.clone());
    assert_eq!(catalog.refresh(&rewrite_report).await.unwrap(), 1);
    assert_eq!(
        SessionImportCurrentView::from_snapshot(&handle.project().await.unwrap())
            .unwrap()
            .sessions[session_id]
            .body_state,
        SessionBodyState::SourceReplaced
    );
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                session_id,
                SessionImportAdminAction::QueueImport,
                13,
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );
    assert!(
        worker
            .process_checkpoint(
                session_id,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    deadline: Instant::now() + Duration::from_secs(2),
                },
            )
            .await
            .unwrap()
            .completed
    );
    let projected = handle.project().await.unwrap();
    assert_eq!(
        projected
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("source_observation"))
            .count(),
        73
    );

    let invalid = "not-json";
    fs::write(&transcript, format!("{header}\n{visible}\n{invalid}\n")).unwrap();
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    let appended_report =
        observe_session_catalog_report(transcript.to_str(), session_id, "tool-use-s28-invalid")
            .unwrap();
    *report.write().await = Some(appended_report.clone());
    assert_eq!(catalog.refresh(&appended_report).await.unwrap(), 1);
    let changed_visible = serde_json::json!({
        "timestamp": "2026-08-30T00:00:01Z",
        "type": "event_msg",
        "payload": {"type": "user_message", "message": "x"}
    });
    fs::write(
        &transcript,
        format!("{header}\n{changed_visible}\n{invalid}\n"),
    )
    .unwrap();
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    let replaced_report = observe_session_catalog_report(
        transcript.to_str(),
        session_id,
        "tool-use-s28-active-replacement",
    )
    .unwrap();
    *report.write().await = Some(replaced_report.clone());
    assert_eq!(catalog.refresh(&replaced_report).await.unwrap(), 1);
    let replaced_projection = handle.project().await.unwrap();
    assert_eq!(
        SessionImportCurrentView::from_snapshot(&replaced_projection)
            .unwrap()
            .sessions[session_id]
            .body_state,
        SessionBodyState::SourceReplaced
    );
    assert_eq!(
        replaced_projection
            .data_rows()
            .filter_map(|row| row.payload_json.as_deref())
            .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
            .filter(|payload| {
                matches!(payload, JournalPayload::JobState(job)
                    if job.idempotency_key == format!("session_import:{session_id}")
                        && matches!(job.state, JobStatus::Queued | JobStatus::Leased))
            })
            .count(),
        0
    );
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                session_id,
                SessionImportAdminAction::QueueImport,
                14,
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );
    assert_eq!(
        worker
            .process_queued_once(
                32,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    deadline: Instant::now() + Duration::from_secs(2),
                },
            )
            .await
            .unwrap(),
        (1, false)
    );
    let projected = handle.project().await.unwrap();
    assert_eq!(
        SessionImportCurrentView::from_snapshot(&projected)
            .unwrap()
            .sessions[session_id]
            .body_state,
        SessionBodyState::Failed
    );

    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let reopened = JournalWriter::open(&data_dir).await.unwrap();
    assert_eq!(reopened.project().await.unwrap(), projected);
    reopened.full_projection().await.unwrap();
    assert_eq!(reopened.project().await.unwrap(), projected);
    assert_eq!(
        reopened.table_names().await.unwrap(),
        [
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search"
        ]
    );
}
