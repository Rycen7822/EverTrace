use std::{fs, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};

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
async fn source_only_archive_later_restriction_closes_reads_and_purge_after_restart() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let workspace = temp.path().join("workspace");
    let adapter = temp.path().join("adapter");
    let dated = adapter.join("sessions/2026/08/30");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&dated).unwrap();
    let session = "019d0000-0000-7000-8000-000000000029";
    let source = format!("session-rollout:{session}:{session}");
    let transcript = dated.join(format!("rollout-2026-08-30T00-00-00-{session}.jsonl"));
    let header = serde_json::json!({"timestamp":"2026-08-30T00:00:00Z", "type":"session_meta", "payload":{"id":session,"session_id":session,"cwd":workspace}});
    let message = serde_json::json!({"timestamp":"2026-08-30T00:00:01Z", "type":"event_msg", "payload":{"type":"user_message","message":"source-only preserved claim"}});
    let body = format!("{header}\n{message}\n");
    fs::write(&transcript, &body).unwrap();
    let report_value =
        observe_session_catalog_report(transcript.to_str(), session, "source-only", None).unwrap();
    let report = Arc::new(RwLock::new(Some(report_value.clone())));
    let data = temp.path().join("data");
    let (writer, task) = spawn_writer(open_writer(&data).await.unwrap(), 32).unwrap();
    let catalog = SessionCatalogService::new(writer.clone(), CONFIG);
    assert_eq!(catalog.refresh(&report_value).await.unwrap(), 1);
    let initial = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        initial.current.metadata.repository_read_restrictions,
        Some(Vec::new())
    );
    assert_eq!(
        initial.current.metadata.resolved_repository_instance_id,
        None
    );
    assert_eq!(initial.current.access_decision, None);
    let mut unknown = initial.current.metadata.clone();
    unknown.repository_read_restrictions =
        Some(vec![evertrace_domain::ids::RepositoryId::new_v7()]);
    let invalid = evertrace_store::JournalCommand::new(
        evertrace_domain::ids::CommandId::new_v7(),
        vec![evertrace_store::JournalEventDraft::runtime(
            9,
            CONFIG,
            "session_import_preflight",
            JournalPayload::SessionImportEventRecorded(Box::new(
                evertrace_store::SessionImportEvent {
                    session_id: session.into(),
                    source_instance_id: Some(source.clone()),
                    revision: initial.current.revision + 1,
                    predecessor_revision: Some(initial.current.revision),
                    occurred_at_us: 9,
                    event: evertrace_store::SessionImportEventKind::MetadataObserved {
                        metadata: Box::new(unknown),
                    },
                },
            )),
        )],
    )
    .unwrap();
    assert!(
        writer
            .commit_if_frontier(invalid, 9, initial.frontier)
            .await
            .is_err()
    );
    assert_eq!(
        writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap(),
        initial
    );
    let admin = SessionImportAdminService::new(writer.clone(), Arc::clone(&report), CONFIG);
    let request = RequestId::new_v7();
    assert_eq!(
        admin
            .handle(request, session, SessionImportAdminAction::QueueImport, 10)
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let worker =
        SessionImportWorker::new(writer.clone(), runtime(temp.path()), Arc::clone(&report))
            .unwrap()
            .for_config(Arc::new(
                evertrace_domain::config::EffectiveConfig::default(),
            ))
            .unwrap();
    let budget = SessionImportBudget {
        max_bytes: 64 * 1024,
        max_records: 2,
        max_work_time: Duration::from_millis(250),
    };
    let mut records = 0;
    for _ in 0..2 {
        let progress = worker
            .process_checkpoint(
                &source,
                SessionImportBudget {
                    max_records: 2 - records,
                    ..budget
                },
            )
            .await
            .unwrap();
        assert!(progress.records > 0);
        records += progress.records;
        if progress.completed {
            break;
        }
    }
    assert_eq!(records, 2);
    let snapshot = writer.project().await.unwrap();
    let originals = snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("source_receipt"))
        .map(|row| (row.row_id.clone(), row.payload_json.clone().unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(originals.len(), 2);
    let human = evertrace_engine::HumanGovernanceService::new(writer.clone(), CONFIG)
        .with_session_report(Arc::clone(&report));
    let detail = human
        .detail(
            evertrace_engine::HumanSurface::Explorer,
            &originals[0].0,
            snapshot.frontier,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(detail.items[0].evidence_detail.is_some());
    assert!(originals.iter().all(|(_, raw)| {
        matches!(serde_json::from_str::<JournalPayload>(raw).unwrap(), JournalPayload::SourceReceiptRecorded(receipt)
            if receipt.repository_instance_id.is_none() && receipt.worktree_instance_id.is_none())
    }));
    let bindings = evertrace_engine::McpBindingAuthority::new(
        DeviceKeyStore::new(temp.path().join("keys"))
            .load_or_create()
            .unwrap(),
    );
    let mcp = evertrace_engine::McpActionService::open(
        bindings.clone(),
        &data,
        writer.clone(),
        runtime(temp.path()),
    )
    .await
    .unwrap()
    .with_session_report(Arc::clone(&report));
    let read = |restricted: bool| {
        let mcp = &mcp;
        let bindings = &bindings;
        let report_value = &report_value;
        let workspace = &workspace;
        let originals = &originals;
        let human = &human;
        let writer = &writer;
        async move {
            let mut texts = Vec::new();
            for (action, input) in [
                (
                    evertrace_engine::McpServiceAction::Get,
                    originals[0]
                        .0
                        .strip_prefix("object:evidence:source_receipt:")
                        .unwrap(),
                ),
                (evertrace_engine::McpServiceAction::Search, "source-only"),
            ] {
                let grant = bindings
                    .issue_with_report(
                        evertrace_engine::McpBindingIssue {
                            session_id: session.into(),
                            turn_id: "turn".into(),
                            tool_use_id: "source-only".into(),
                            agent_id: None,
                            action: if action == evertrace_engine::McpServiceAction::Get {
                                "get"
                            } else {
                                "search"
                            }
                            .into(),
                            workspace: "@active".into(),
                            input: input.into(),
                            refs: vec![],
                            launcher_protocol_revision: 1,
                        },
                        Some(Arc::new(report_value.clone())),
                    )
                    .unwrap();
                let result = mcp
                    .handle(
                        "source-only-read",
                        evertrace_engine::McpServiceRequest {
                            request_id: RequestId::new_v7(),
                            action,
                            workspace: grant.bound_workspace,
                            input: input.into(),
                            refs: vec![],
                            client_cwd: workspace.to_str().unwrap().into(),
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    result.items.is_empty(),
                    restricted,
                    "{action:?}: {result:?}"
                );
                assert!(result.items.iter().all(|item| item.content_trust
                    == evertrace_domain::evidence::ContentTrust::ImportedClaim));
                texts.extend(
                    result
                        .items
                        .into_iter()
                        .map(|item| (item.object_ref, item.text)),
                );
            }
            let snapshot = writer.project().await.unwrap();
            let detail = human
                .detail(
                    evertrace_engine::HumanSurface::Explorer,
                    &originals[0].0,
                    snapshot.frontier,
                    None,
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(detail.items[0].evidence_detail.is_none(), restricted);
            texts
        }
    };
    let archived_output = read(false).await;
    let cas = evertrace_capture::CasStore::open_existing(temp.path().join("cas")).unwrap();
    let JournalPayload::SourceReceiptRecorded(receipt) =
        serde_json::from_str(&originals[0].1).unwrap()
    else {
        panic!("receipt")
    };
    let digest = evertrace_capture::CasStore::parse_digest(&receipt.cas_ref).unwrap();
    let archived_bytes = cas.read(&digest).unwrap();
    fs::write(&transcript, format!("{body}{message}\n")).unwrap();
    assert_eq!(read(false).await, archived_output);
    assert!(worker.process_checkpoint(&source, budget).await.is_err());
    let moved = temp.path().join("moved.jsonl");
    fs::rename(&transcript, &moved).unwrap();
    assert_eq!(read(false).await, archived_output);
    fs::remove_file(&moved).unwrap();
    assert_eq!(read(false).await, archived_output);
    assert_eq!(cas.read(&digest).unwrap(), archived_bytes);
    assert!(worker.process_checkpoint(&source, budget).await.is_err());
    // Restore the source as a replacement revision, never restore approval.
    fs::write(&transcript, &body).unwrap();
    assert_eq!(catalog.refresh(&report_value).await.unwrap(), 1);
    let replaced = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replaced.current.access_decision, None);
    assert_eq!(read(false).await, archived_output);
    assert!(worker.process_checkpoint(&source, budget).await.is_err());
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                session,
                SessionImportAdminAction::RevokeAccess,
                11
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Revoked
    );
    read(true).await;
    fs::write(&transcript, format!("{header}\n")).unwrap();
    assert_eq!(catalog.refresh(&report_value).await.unwrap(), 1);
    assert_eq!(
        writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap()
            .current
            .access_decision,
        Some(evertrace_store::SessionAccessDecision::Revoked)
    );
    read(true).await;
    fs::write(&transcript, &body).unwrap();
    catalog.refresh(&report_value).await.unwrap();
    // Explicit new-revision consent is independent of the unchanged old CAS.
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                session,
                SessionImportAdminAction::QueueImport,
                12
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );
    fs::remove_dir(&workspace).unwrap();
    read(false).await;
    fs::create_dir(&workspace).unwrap();

    // The same original Missing source is now associated with a current,
    // normally discovered unborn repository. No manual registration or approval.
    fs::write(&transcript, format!("{body}{message}\n")).unwrap();
    assert_eq!(catalog.refresh(&report_value).await.unwrap(), 1);
    let status = std::process::Command::new("git")
        .args(["init", "-q", "--initial-branch=main"])
        .current_dir(&workspace)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success());
    fs::write(
        adapter.join("config.toml"),
        format!(
            "[projects.{}]\ntrust_level = \"untrusted\"\n",
            serde_json::to_string(workspace.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    let preflight = worker.process_checkpoint(&source, budget).await.unwrap();
    assert_eq!(
        (preflight.records, preflight.bytes, preflight.completed),
        (0, 0, false)
    );
    let restricted = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    let repository = restricted
        .current
        .metadata
        .repository_read_restrictions
        .as_ref()
        .unwrap()[0];
    assert_eq!(
        restricted.current.metadata.resolved_repository_instance_id,
        None
    );
    assert_eq!(
        restricted.current.metadata.resolved_worktree_instance_id,
        None
    );
    assert_eq!(
        restricted.current.access_decision,
        Some(evertrace_store::SessionAccessDecision::Approved)
    );
    assert_eq!(catalog.refresh(&report_value).await.unwrap(), 0);
    assert_eq!(
        writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap()
            .frontier,
        restricted.frontier
    );
    assert_eq!(
        admin
            .handle(request, session, SessionImportAdminAction::QueueImport, 10)
            .await
            .unwrap(),
        SessionImportAdminOutcome::NoDelta
    );
    let before = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.current.body_state, SessionBodyState::Queued);
    assert!(worker.process_checkpoint(&source, budget).await.is_err());
    let after = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before, after);
    let snapshot = writer.project().await.unwrap();
    let detail = human
        .detail(
            evertrace_engine::HumanSurface::Explorer,
            &originals[0].0,
            snapshot.frontier,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(detail.items[0].evidence_detail.is_none());
    read(true).await;
    let repository_revision = before
        .read_repositories
        .iter()
        .find(|value| value.repository_id == repository)
        .unwrap()
        .repository_revision;
    let preview = evertrace_store::projections::repository_scope_purge_preview(
        &snapshot,
        repository,
        repository_revision,
    )
    .unwrap();
    assert_eq!(preview.affected_session_count, 1);
    assert_eq!(preview.exclusive_cas_refs.len(), 2);
    assert!(preview.affected_evidence_receipt_capture_count >= 4);
    // Pure closure negative: a source-wide restriction must not erase a
    // receipt carrying an independent historical repository scope. This
    // synthetic view is never committed or used by the real-input oracle.
    let mut foreign_scope = snapshot.clone();
    let row = foreign_scope
        .rows
        .iter_mut()
        .find(|row| row.row_id == originals[0].0)
        .unwrap();
    let JournalPayload::SourceReceiptRecorded(mut receipt) =
        serde_json::from_str(row.payload_json.as_ref().unwrap()).unwrap()
    else {
        unreachable!()
    };
    let foreign = evertrace_domain::ids::RepositoryId::new_v7();
    receipt.repository_instance_id = Some(foreign);
    row.repository_id = Some(foreign.to_string());
    row.payload_json =
        Some(serde_json::to_string(&JournalPayload::SourceReceiptRecorded(receipt)).unwrap());
    assert!(
        evertrace_store::projections::repository_scope_purge_preview(
            &foreign_scope,
            repository,
            repository_revision,
        )
        .unwrap()
        .blockers
        .contains(&evertrace_domain::purge::RepositoryPurgeBlocker::CrossScopeDependency)
    );
    for (id, raw) in &originals {
        assert_eq!(snapshot.row(id).unwrap().payload_json.as_ref(), Some(raw));
    }
    writer.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let reopened = JournalWriter::open(&data).await.unwrap();
    assert_eq!(
        reopened.session_import_context(&source).unwrap().unwrap(),
        after
    );
    assert_eq!(reopened.project().await.unwrap(), snapshot);
    reopened.full_projection().await.unwrap();
    assert_eq!(reopened.project().await.unwrap(), snapshot);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nearest_git_restricts_nested_source_and_external_linked_worktree_converges() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let main = temp.path().join("main");
    let nested = main.join("nested");
    let linked = temp.path().join("external");
    fs::create_dir_all(&nested).unwrap();
    let git = |path: &std::path::Path, args: &[&str]| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(path)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&main, &["init", "-q", "--initial-branch=main"]);
    git(
        &main,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "initial",
        ],
    );
    let adapter = temp.path().join("adapter");
    let dated = adapter.join("sessions/2026/08/30");
    fs::create_dir_all(&dated).unwrap();
    let trust_config = format!(
        "[projects.{}]\ntrust_level = \"trusted\"\n[projects.{}]\ntrust_level = \"untrusted\"\n[projects.{}]\ntrust_level = \"trusted\"\n",
        serde_json::to_string(main.to_str().unwrap()).unwrap(),
        serde_json::to_string(nested.to_str().unwrap()).unwrap(),
        serde_json::to_string(linked.to_str().unwrap()).unwrap(),
    );
    fs::write(adapter.join("config.toml"), &trust_config).unwrap();
    let session = "019d0000-0000-7000-8000-000000000030";
    let mut files = Vec::new();
    let mut sources = Vec::new();
    for (ordinal, workspace) in [&main, &nested, &linked].into_iter().enumerate() {
        let rollout = format!("019d0000-0000-7000-8000-00000000003{ordinal}");
        let path = dated.join(format!(
            "rollout-2026-08-30T00-00-00-{session}_{rollout}.jsonl"
        ));
        let header = serde_json::json!({"timestamp":"2026-08-30T00:00:00Z", "type":"session_meta", "payload":{"id":session,"session_id":session,"cwd":workspace}});
        let message = serde_json::json!({"timestamp":"2026-08-30T00:00:01Z", "type":"event_msg", "payload":{"type":"user_message","message":"nested source archived claim"}});
        fs::write(&path, format!("{header}\n{message}\n")).unwrap();
        files.push(path);
        sources.push(format!("session-rollout:{session}:{rollout}"));
    }
    let report_value =
        observe_session_catalog_report(files[0].to_str(), session, "nearest-git", None).unwrap();
    let report = Arc::new(RwLock::new(Some(report_value.clone())));
    let data = temp.path().join("data");
    let (writer, task) = spawn_writer(open_writer(&data).await.unwrap(), 32).unwrap();
    let catalog = SessionCatalogService::new(writer.clone(), CONFIG);
    assert_eq!(catalog.refresh(&report_value).await.unwrap(), 3);
    let initial = writer
        .session_import_context(&sources[1])
        .await
        .unwrap()
        .unwrap();
    let repository_a = initial
        .current
        .metadata
        .repository_read_restrictions
        .as_ref()
        .unwrap()[0];
    assert_eq!(
        initial.current.metadata.resolved_repository_instance_id,
        None
    );
    let admin = SessionImportAdminService::new(writer.clone(), Arc::clone(&report), CONFIG);
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                session,
                SessionImportAdminAction::QueueImport,
                10
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let worker =
        SessionImportWorker::new(writer.clone(), runtime(temp.path()), Arc::clone(&report))
            .unwrap()
            .for_config(Arc::new(
                evertrace_domain::config::EffectiveConfig::default(),
            ))
            .unwrap();
    let budget = SessionImportBudget {
        max_bytes: 64 * 1024,
        max_records: 2,
        max_work_time: Duration::from_millis(250),
    };
    let mut records = 0;
    for _ in 0..2 {
        let progress = worker
            .process_checkpoint(
                &sources[1],
                SessionImportBudget {
                    max_records: 2 - records,
                    ..budget
                },
            )
            .await
            .unwrap();
        assert!(progress.records > 0);
        records += progress.records;
        if records == 2 {
            break;
        }
    }
    assert_eq!(records, 2);
    let old_context = writer
        .session_import_context(&sources[1])
        .await
        .unwrap()
        .unwrap();
    let snapshot = writer.project().await.unwrap();
    let receipt_row = snapshot
        .data_rows()
        .find(|row| row.object_kind.as_deref() == Some("source_receipt"))
        .unwrap()
        .row_id
        .clone();
    let human = evertrace_engine::HumanGovernanceService::new(writer.clone(), CONFIG)
        .with_session_report(Arc::clone(&report));
    assert!(
        human
            .detail(
                evertrace_engine::HumanSurface::Explorer,
                &receipt_row,
                snapshot.frontier,
                None
            )
            .await
            .unwrap()
            .unwrap()
            .items[0]
            .evidence_detail
            .is_some()
    );
    let body = fs::read_to_string(&files[1]).unwrap();
    fs::write(&files[1], format!("{body}{{\"type\":\"event_msg\",\"payload\":{{\"type\":\"user_message\",\"message\":\"later\"}}}}\n")).unwrap();
    assert_eq!(catalog.refresh(&report_value).await.unwrap(), 1);
    git(&nested, &["init", "-q", "--initial-branch=main"]);
    git(
        &main,
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            linked.to_str().unwrap(),
        ],
    );
    let before = writer
        .session_import_context(&sources[1])
        .await
        .unwrap()
        .unwrap();
    assert!(
        human
            .detail(
                evertrace_engine::HumanSurface::Explorer,
                &receipt_row,
                before.frontier,
                None
            )
            .await
            .unwrap()
            .unwrap()
            .items[0]
            .evidence_detail
            .is_none()
    );
    assert_eq!(
        writer
            .session_import_context(&sources[1])
            .await
            .unwrap()
            .unwrap(),
        before
    );
    let preflight = worker
        .process_checkpoint(&sources[1], budget)
        .await
        .unwrap();
    assert_eq!((preflight.records, preflight.bytes), (0, 0));
    let restricted = writer
        .session_import_context(&sources[1])
        .await
        .unwrap()
        .unwrap();
    let restrictions = restricted
        .current
        .metadata
        .repository_read_restrictions
        .as_ref()
        .unwrap();
    assert_eq!(restrictions.len(), 2);
    assert!(restrictions.contains(&repository_a));
    assert_eq!(restricted.watermark, old_context.watermark);
    assert!(
        worker
            .process_checkpoint(&sources[1], budget)
            .await
            .is_err()
    );
    // The source was catalogued before this external worktree existed. Its
    // preflight must locate the already-known common-dir identity, not allocate
    // a duplicate repository from its initially empty path-candidate context.
    // Synthetic historical snapshots go through the real journal; the current
    // snapshot and its positive real-Git HEAD evidence remain untouched.
    let history = (1..=65)
        .map(|ordinal| {
            let mut historical = initial.read_snapshots[0].clone();
            historical.worktree_snapshot_id = evertrace_domain::ids::WorktreeSnapshotId::new_v7();
            historical.head_oid = Some(format!("{ordinal:040x}"));
            historical.evidence_refs = vec![format!("test:old-snapshot:{ordinal}")];
            evertrace_store::JournalEventDraft::runtime(
                historical.captured_at_us,
                CONFIG,
                "test_history",
                JournalPayload::WorktreeSnapshotRecorded(Box::new(historical)),
            )
        })
        .collect();
    let command =
        evertrace_store::JournalCommand::new(evertrace_domain::ids::CommandId::new_v7(), history)
            .unwrap();
    let before_history = writer.project().await.unwrap();
    writer
        .commit_if_frontier(command, 20, before_history.frontier)
        .await
        .unwrap();
    let repository = &initial.read_repositories[0];
    let bounded = writer
        .session_import_context_with_repository(
            &sources[2],
            repository.common_dir_filesystem.unwrap(),
            repository.git_common_dir_path.as_deref().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(bounded.read_snapshots.len() <= 64);
    assert!(
        bounded
            .read_snapshots
            .iter()
            .any(|snapshot| snapshot.worktree_snapshot_id
                == initial.read_snapshots[0].worktree_snapshot_id)
    );
    assert!(
        bounded
            .incomplete_repository_history
            .contains(&repository_a)
    );
    // Its own Host trust is authoritative, not the main worktree's trust.
    fs::write(
        adapter.join("config.toml"),
        trust_config.replacen("\"trusted\"", "\"untrusted\"", 1),
    )
    .unwrap();
    let preflight = worker
        .process_checkpoint(&sources[2], budget)
        .await
        .unwrap();
    assert_eq!((preflight.records, preflight.bytes), (0, 0));
    let external = writer
        .session_import_context(&sources[2])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        external.current.metadata.repository_read_restrictions,
        Some(vec![repository_a])
    );
    assert_eq!(
        external.current.metadata.resolved_repository_instance_id,
        None
    );
    assert_eq!(
        external.current.metadata.resolved_worktree_instance_id,
        None
    );
    assert_eq!(
        external
            .read_repositories
            .iter()
            .find(|repo| repo.repository_id == repository_a)
            .unwrap()
            .current_path,
        main.to_str().unwrap()
    );
    let mut records = 0;
    for _ in 0..2 {
        let progress = worker
            .process_checkpoint(
                &sources[2],
                SessionImportBudget {
                    max_records: 2 - records,
                    ..budget
                },
            )
            .await
            .unwrap();
        assert!(progress.records > 0);
        records += progress.records;
        if records == 2 {
            break;
        }
    }
    assert_eq!(records, 2);
    let snapshot = writer.project().await.unwrap();
    let external_receipt = snapshot.data_rows().find(|row| {
        row.object_kind.as_deref() == Some("source_receipt")
            && row.payload_json.as_ref().is_some_and(|raw| matches!(serde_json::from_str::<JournalPayload>(raw).unwrap(), JournalPayload::SourceReceiptRecorded(receipt) if receipt.source_instance_id.as_str() == sources[2]))
    }).unwrap();
    assert!(
        human
            .detail(
                evertrace_engine::HumanSurface::Explorer,
                &external_receipt.row_id,
                snapshot.frontier,
                None
            )
            .await
            .unwrap()
            .unwrap()
            .items[0]
            .evidence_detail
            .is_some()
    );
    let repositories =
        evertrace_store::repository::RepositoryCurrentView::from_snapshot(&snapshot).unwrap();
    assert_eq!(repositories.repositories.len(), 2);
    assert!(repositories.snapshots.len() > 64);
    assert_eq!(
        repositories
            .worktrees
            .values()
            .find(|tree| tree.current_path.as_deref() == linked.to_str())
            .unwrap()
            .repository_instance_id,
        repository_a
    );
    assert_eq!(catalog.refresh(&report_value).await.unwrap(), 0);
    // The catalog's full history view must also avoid spending its Git quantum
    // on every historical HEAD before recognizing this same current identity.
    let another_linked = temp.path().join("another-external");
    git(
        &main,
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            another_linked.to_str().unwrap(),
        ],
    );
    let rollout = "019d0000-0000-7000-8000-000000000033";
    let header = serde_json::json!({"timestamp":"2026-08-30T00:00:00Z", "type":"session_meta", "payload":{"id":session,"session_id":session,"cwd":another_linked}});
    fs::write(
        dated.join(format!(
            "rollout-2026-08-30T00-00-00-{session}_{rollout}.jsonl"
        )),
        format!("{header}\n"),
    )
    .unwrap();
    assert_eq!(catalog.refresh(&report_value).await.unwrap(), 1);
    let newly_catalogued = writer
        .session_import_context(&format!("session-rollout:{session}:{rollout}"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        newly_catalogued
            .current
            .metadata
            .repository_read_restrictions,
        Some(vec![repository_a])
    );
    assert_eq!(
        newly_catalogued
            .current
            .metadata
            .resolved_repository_instance_id,
        None
    );
    assert_eq!(newly_catalogued.current.access_decision, None);
    let final_snapshot = writer.project().await.unwrap();
    let final_repositories =
        evertrace_store::repository::RepositoryCurrentView::from_snapshot(&final_snapshot).unwrap();
    assert_eq!(final_repositories.repositories.len(), 2);
    assert!(
        final_repositories
            .worktrees
            .values()
            .any(
                |tree| tree.current_path.as_deref() == another_linked.to_str()
                    && tree.repository_instance_id == repository_a
            )
    );
    drop(worker);
    drop(admin);
    drop(catalog);
    drop(human);
    drop(writer);
    task.await.unwrap().unwrap();
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
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if path == &adapter { 0o700 } else { 0o755 }),
        )
        .unwrap();
    }
    let session_id = "019d0000-0000-7000-8000-000000000028";
    let transcript = dated.join(format!("rollout-2026-08-30T00-00-00-{session_id}.jsonl"));
    let header = serde_json::json!({
        "ordinal": 0,
        "timestamp": "2026-08-30T00:00:00Z",
        "type": "session_meta",
        "payload": {
            "id": session_id,
            "session_id": session_id,
            "cwd": "/not-a-repository",
            "originator": "codex_cli_rs",
            "model_provider": "openai",
            "git": null
        }
    });
    let visible = serde_json::json!({
        "ordinal": 1,
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
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o644)).unwrap();
    let report =
        observe_session_catalog_report(transcript.to_str(), session_id, "tool-use-s28", None)
            .unwrap();

    let data_dir = temp.path().join("data");
    let writer = open_writer(&data_dir).await.unwrap();
    let (handle, task) = spawn_writer(writer, 32).unwrap();
    let catalog = SessionCatalogService::new(handle.clone(), CONFIG);
    assert_eq!(catalog.refresh(&report).await.unwrap(), 1);
    let catalog_snapshot = handle.project().await.unwrap();
    assert!(evertrace_store::RuntimeSchedulerView::from_snapshot(&catalog_snapshot).is_ok());
    let mut invalid_current = catalog_snapshot.clone();
    invalid_current
        .rows
        .iter_mut()
        .find(|row| row.object_kind.as_deref() == Some("session_import_current"))
        .unwrap()
        .payload_json = Some("{}".into());
    assert!(evertrace_store::RuntimeSchedulerView::from_snapshot(&invalid_current).is_err());
    for snapshot in [&catalog_snapshot, &invalid_current] {
        let valid = std::ptr::eq(snapshot, &catalog_snapshot);
        assert_eq!(
            evertrace_store::projections::RecoveryCurrentView::from_snapshot(snapshot).is_ok(),
            valid
        );
        assert_eq!(
            evertrace_engine::expired_leases(&snapshot.rows, 10, snapshot.frontier).is_ok(),
            valid
        );
        assert_eq!(
            evertrace_engine::pending_outbox(&snapshot.rows, snapshot.frontier).is_ok(),
            valid
        );
        assert_eq!(
            evertrace_engine::pending_dirty(&snapshot.rows, snapshot.frontier).is_ok(),
            valid
        );
    }
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
    fs::set_permissions(&adapter, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        worker
            .process_checkpoint(
                &format!("session-rollout:{session_id}:{session_id}"),
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
                }
            )
            .await,
        Err(evertrace_engine::SessionImportError::Unavailable)
    ));
    let before_import = handle.project().await.unwrap();
    assert_eq!(
        SessionImportCurrentView::from_snapshot(&before_import)
            .unwrap()
            .sessions[&format!("session-rollout:{session_id}:{session_id}")]
            .body_state,
        SessionBodyState::Queued
    );
    assert!(
        !before_import
            .data_rows()
            .any(|row| row.object_kind.as_deref() == Some("source_observation"))
    );
    fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700)).unwrap();
    let mut imported = 0;
    for (checkpoint, expected_complete) in [false, false, true].into_iter().enumerate() {
        let progress = worker
            .process_checkpoint(
                &format!("session-rollout:{session_id}:{session_id}"),
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
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
        current.sessions[&format!("session-rollout:{session_id}:{session_id}")].body_state,
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
                    if value.source_instance_id.as_str() == format!("session-rollout:{session_id}:{session_id}")
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
    let append_report = observe_session_catalog_report(
        transcript.to_str(),
        session_id,
        "tool-use-s28-append",
        None,
    )
    .unwrap();
    *report.write().await = Some(append_report.clone());
    assert_eq!(catalog.refresh(&append_report).await.unwrap(), 1);
    assert_eq!(
        SessionImportCurrentView::from_snapshot(&handle.project().await.unwrap())
            .unwrap()
            .sessions[&format!("session-rollout:{session_id}:{session_id}")]
            .body_state,
        SessionBodyState::Queued
    );
    // The appended file invalidates the old full-file proof. Revalidate its
    // committed 34-record prefix in three bounded, read-only work units.
    let source_a = format!("session-rollout:{session_id}:{session_id}");
    let before_prefix = handle
        .session_import_context(&source_a)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..3 {
        let prefix = worker
            .process_checkpoint(
                &source_a,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
                },
            )
            .await
            .unwrap();
        assert_eq!(prefix.records, 0);
        assert!(prefix.bytes > 0 && !prefix.completed);
        assert_eq!(
            handle
                .session_import_context(&source_a)
                .await
                .unwrap()
                .unwrap(),
            before_prefix
        );
    }
    assert_eq!(
        worker
            .process_checkpoint(
                &format!("session-rollout:{session_id}:{session_id}"),
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
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
        None,
    )
    .unwrap();
    *report.write().await = Some(rewrite_grow_report.clone());
    assert_eq!(catalog.refresh(&rewrite_grow_report).await.unwrap(), 1);
    assert!(
        worker
            .process_checkpoint(
                &format!("session-rollout:{session_id}:{session_id}"),
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
                },
            )
            .await
            .is_err()
    );
    let replaced = SessionImportCurrentView::from_snapshot(&handle.project().await.unwrap())
        .unwrap()
        .sessions
        .remove(&format!("session-rollout:{session_id}:{session_id}"))
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
                &format!("session-rollout:{session_id}:{session_id}"),
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("checkpoint {checkpoint} failed: {error:?}"));
        assert_eq!(progress.completed, expected_completed);
    }

    fs::write(&transcript, format!("{header}\n{visible}\n")).unwrap();
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    let rewrite_report = observe_session_catalog_report(
        transcript.to_str(),
        session_id,
        "tool-use-s28-rewrite",
        None,
    )
    .unwrap();
    *report.write().await = Some(rewrite_report.clone());
    assert_eq!(catalog.refresh(&rewrite_report).await.unwrap(), 1);
    assert_eq!(
        SessionImportCurrentView::from_snapshot(&handle.project().await.unwrap())
            .unwrap()
            .sessions[&format!("session-rollout:{session_id}:{session_id}")]
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
                &format!("session-rollout:{session_id}:{session_id}"),
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
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
    let appended_report = observe_session_catalog_report(
        transcript.to_str(),
        session_id,
        "tool-use-s28-invalid",
        None,
    )
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
        None,
    )
    .unwrap();
    *report.write().await = Some(replaced_report.clone());
    assert_eq!(catalog.refresh(&replaced_report).await.unwrap(), 1);
    let replaced_projection = handle.project().await.unwrap();
    assert_eq!(
        SessionImportCurrentView::from_snapshot(&replaced_projection)
            .unwrap()
            .sessions[&format!("session-rollout:{session_id}:{session_id}")]
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
                    if job.idempotency_key == format!("session_import:session-rollout:{session_id}:{session_id}")
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
                    max_work_time: Duration::from_millis(250),
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
            .sessions[&format!("session-rollout:{session_id}:{session_id}")]
            .body_state,
        SessionBodyState::Failed
    );

    // A second real-format rollout remains the same logical session, but owns
    // its approval, job, physical byte positions and protected-prefix chain.
    let rollout_b = "019d0000-0000-7000-8000-000000000029";
    let source_b = format!("session-rollout:{session_id}:{rollout_b}");
    let second = dated.join(format!(
        "rollout-2026-08-30T00-00-01-{session_id}_{rollout_b}.jsonl"
    ));
    let unknown = serde_json::json!({"ordinal": 1, "type": "event_msg", "payload": {"type": "unrecognized_history_event"}});
    fs::write(&second, format!("{header}\n{unknown}\n{visible}\n")).unwrap();
    fs::set_permissions(&second, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(catalog.refresh(&replaced_report).await.unwrap(), 1);
    assert_eq!(catalog.refresh(&replaced_report).await.unwrap(), 0);
    let sources =
        SessionImportCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    assert_eq!(sources.sessions.len(), 2);
    assert!(sources.sessions[&source_b].access_decision.is_none());
    assert_eq!(sources.sessions[&source_b].session_id, session_id);
    let request = RequestId::new_v7();
    assert_eq!(
        admin
            .handle(
                request,
                session_id,
                SessionImportAdminAction::QueueImport,
                20
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );
    let queued = handle.project().await.unwrap();
    let ids = queued
        .data_rows()
        .filter_map(|row| row.payload_json.as_deref())
        .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
        .filter_map(|payload| match payload {
            JournalPayload::JobState(job)
                if job.kind == "session_import_v1" && job.state == JobStatus::Queued =>
            {
                Some(job.job_id)
            }
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 2);
    assert_eq!(
        admin
            .handle(
                request,
                session_id,
                SessionImportAdminAction::QueueImport,
                21
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::NoDelta
    );
    assert_eq!(handle.project().await.unwrap().frontier, queued.frontier);
    let partial = worker
        .process_checkpoint(
            &source_b,
            SessionImportBudget {
                max_bytes: 64 * 1024,
                max_records: 1,
                max_work_time: Duration::from_millis(250),
            },
        )
        .await
        .unwrap();
    assert!(!partial.completed);
    assert!(partial.records > 0);
    let moved_date = sessions.join("2026/08/31");
    fs::create_dir(&moved_date).unwrap();
    fs::set_permissions(&moved_date, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(&second, moved_date.join(second.file_name().unwrap())).unwrap();
    assert_eq!(catalog.refresh(&replaced_report).await.unwrap(), 1);
    let moved = SessionImportCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    assert_eq!(
        moved.sessions[&source_b].metadata.source_revision,
        sources.sessions[&source_b].metadata.source_revision
    );
    assert_eq!(
        moved.sessions[&source_b].body_state,
        SessionBodyState::Partial
    );
    assert_eq!(
        moved.sessions[&source_b].access_decision,
        Some(evertrace_store::SessionAccessDecision::Approved)
    );
    let before_moved_prefix = handle
        .session_import_context(&source_b)
        .await
        .unwrap()
        .unwrap();
    let prefix = worker
        .process_checkpoint(
            &source_b,
            SessionImportBudget {
                max_bytes: 64 * 1024,
                max_records: 16,
                max_work_time: Duration::from_millis(250),
            },
        )
        .await
        .unwrap();
    assert_eq!(prefix.records, 0);
    assert!(prefix.bytes > 0 && !prefix.completed);
    assert_eq!(
        handle
            .session_import_context(&source_b)
            .await
            .unwrap()
            .unwrap(),
        before_moved_prefix
    );
    let complete = worker
        .process_checkpoint(
            &source_b,
            SessionImportBudget {
                max_bytes: 64 * 1024,
                max_records: 16,
                max_work_time: Duration::from_millis(250),
            },
        )
        .await
        .unwrap();
    assert!(complete.completed);
    let sources =
        SessionImportCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    assert_eq!(
        sources.sessions[&source_b].body_state,
        SessionBodyState::Imported
    );
    assert_eq!(
        sources.sessions[&format!("session-rollout:{session_id}:{session_id}")].body_state,
        SessionBodyState::Queued
    );
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                session_id,
                SessionImportAdminAction::RevokeAccess,
                22
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Revoked
    );
    let projected = handle.project().await.unwrap();
    assert!(
        SessionImportCurrentView::from_snapshot(&projected)
            .unwrap()
            .sessions
            .values()
            .all(|source| source.access_decision
                == Some(evertrace_store::SessionAccessDecision::Revoked))
    );
    let detail = evertrace_engine::HumanGovernanceService::new(handle.clone(), CONFIG)
        .detail(
            evertrace_engine::HumanSurface::System,
            &evertrace_store::session_import::session_import_row_id(&source_b),
            projected.frontier,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(detail.items[0].system_detail.as_ref(), Some(evertrace_engine::HumanSystemDetail::SessionImport { session_id: actual, source_instance_id, access, .. }) if actual == session_id && source_instance_id == &source_b && access == "Revoked")
    );
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let reopened = JournalWriter::open(&data_dir).await.unwrap();
    let tables_before_context = reopened.backup_table_states().await.unwrap();
    let point = reopened.session_import_context(&source_b).unwrap().unwrap();
    assert_eq!(point.frontier, projected.frontier);
    assert_eq!(
        point.current,
        SessionImportCurrentView::from_snapshot(&projected)
            .unwrap()
            .sessions[&source_b]
    );
    assert_eq!(
        point.watermark.unwrap().source_sequence,
        fs::metadata(moved_date.join(second.file_name().unwrap()))
            .unwrap()
            .len()
    );
    assert_eq!(
        reopened.backup_table_states().await.unwrap(),
        tables_before_context
    );
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
