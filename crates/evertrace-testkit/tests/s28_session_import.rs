#[path = "../src/provider.rs"]
#[allow(dead_code)]
mod provider_stub;

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
async fn imported_messages_use_normal_synthesis_and_mcp_without_work_objects() {
    Box::pin(imported_messages_scenario(false, false, None, false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imported_methods_use_scheduler_and_cross_session_mcp_without_work_objects() {
    Box::pin(imported_messages_scenario(true, false, None, false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imported_method_terminal_status_excludes_stale_references() {
    Box::pin(imported_messages_scenario(true, true, None, false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imported_method_inflight_source_revocation_discards_result() {
    Box::pin(imported_messages_scenario(true, false, Some(false), false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imported_method_inflight_repository_purge_discards_result() {
    Box::pin(imported_messages_scenario(true, false, Some(true), false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imported_method_independent_append_remains_live_after_first_proposal() {
    Box::pin(imported_messages_scenario(true, false, None, true)).await;
}

async fn imported_messages_scenario(
    method: bool,
    terminal: bool,
    interruption: Option<bool>,
    independent: bool,
) {
    async fn read(
        mcp: &evertrace_engine::McpActionService,
        bindings: &evertrace_engine::McpBindingAuthority,
        report: &evertrace_codex::HostProbeReport,
        workspace: &std::path::Path,
        session: &str,
        action: evertrace_engine::McpServiceAction,
        input: String,
    ) -> evertrace_engine::McpServiceResult {
        let grant = bindings
            .issue_with_report(
                evertrace_engine::McpBindingIssue {
                    session_id: session.into(),
                    turn_id: "turn".into(),
                    tool_use_id: "source-summary".into(),
                    agent_id: None,
                    action: if action == evertrace_engine::McpServiceAction::Get {
                        "get"
                    } else {
                        "search"
                    }
                    .into(),
                    workspace: "@active".into(),
                    input: input.clone(),
                    refs: vec![],
                    launcher_protocol_revision: 1,
                },
                Some(Arc::new(report.clone())),
            )
            .unwrap();
        Box::pin(mcp.handle(
            "source-summary-read",
            evertrace_engine::McpServiceRequest {
                request_id: RequestId::new_v7(),
                action,
                workspace: grant.bound_workspace,
                input,
                refs: vec![],
                client_cwd: workspace.to_str().unwrap().into(),
            },
        ))
        .await
        .unwrap()
    }
    async fn read_methods(
        mcp: &evertrace_engine::McpActionService,
        binding: &evertrace_engine::McpBindingAuthority,
        report: &evertrace_codex::HostProbeReport,
        workspace: &std::path::Path,
        session: &str,
        expected: &[(String, String)],
    ) {
        let (mcp, binding, report, workspace, session, expected) = (
            mcp.clone(),
            binding.clone(),
            report.clone(),
            workspace.to_owned(),
            session.to_owned(),
            expected.to_vec(),
        );
        tokio::spawn(async move {
            for (id, revision) in expected {
                let result = Box::pin(read(
                    &mcp,
                    &binding,
                    &report,
                    &workspace,
                    &session,
                    evertrace_engine::McpServiceAction::Get,
                    id,
                ))
                .await;
                assert!(
                    result
                        .items
                        .iter()
                        .any(|item| item.object_revision_ref.as_ref() == Some(&revision))
                );
            }
            let result = Box::pin(read(
                &mcp,
                &binding,
                &report,
                &workspace,
                &session,
                evertrace_engine::McpServiceAction::Search,
                "Saffron".into(),
            ))
            .await;
            assert!(result.items.iter().any(|item| {
                item.text
                    .as_deref()
                    .is_some_and(|text| text.contains("Saffron"))
            }));
        })
        .await
        .unwrap();
    }
    use evertrace_domain::{
        config::{DreamingConfig, DurationValue, EpisodeEnrichment, LlmConfig, ValidatedBaseUrl},
        evidence::{ContentTrust, ObservationRole},
        semantic::{SemanticCompleteness, SemanticStructuredDelta},
    };
    use evertrace_engine::{BackgroundScheduler, SynthesisPlanner};
    use provider_stub::ProviderStub;

    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let workspace = temp.path().join("workspace");
    let adapter = temp.path().join("adapter");
    let dated = adapter.join("sessions/2026/09/10");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&dated).unwrap();
    fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&workspace)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "initial"
            ])
            .current_dir(&workspace)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap()
            .success()
    );
    let head = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&workspace)
        .output()
        .unwrap();
    assert!(head.status.success());
    let head = String::from_utf8(head.stdout).unwrap().trim().to_owned();
    let clock = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ %s"])
        .output()
        .unwrap();
    assert!(clock.status.success());
    let clock = String::from_utf8(clock.stdout).unwrap();
    let (timestamp, seconds) = clock.trim().split_once(' ').unwrap();
    let observed_at_us = seconds.parse::<i64>().unwrap() * 1_000_000;
    fs::write(
        adapter.join("config.toml"),
        format!(
            "[projects.{}]\ntrust_level = \"trusted\"\n",
            serde_json::to_string(workspace.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    let session = "019d0000-0000-7000-8000-000000000061";
    let source = format!("session-rollout:{session}:{session}");
    let transcript = dated.join(format!("rollout-2026-09-10T00-00-00-{session}.jsonl"));
    let header = serde_json::json!({"timestamp":timestamp,"type":"session_meta","payload":{"id":session,"session_id":session,"cwd":workspace,"git":{"commit_hash":head}}});
    // Fixed source 3d2ee51ca2d5db578f328aa75e20aa22c0197c9a:
    // rollout/src/policy.rs persists ItemCompleted for Paginated history;
    // history/src/rollout_payload.rs retains the separate raw response envelope.
    let message_text = if method {
        "Marigold journal recovery method: when a transaction acknowledgement is lost after journal append, first read the original command identity and compare its exact payload against committed events. If it is committed, resume from that receipt without reissuing the mutation; if absent, retry the same command with a fresh current frontier. Verify that replay contains one commit and that current projection matches its receipt. Abort if the payload differs. Reuse this only for ambiguous acknowledgement in this repository's single writer.".to_owned()
    } else {
        format!(
            "marigold descriptive source memory {}",
            "bounded context ".repeat(300)
        )
    };
    let raw_message = serde_json::json!({"type":"response_item","metadata":{"client_authored":false,"fallback_token_limit_override":8192},"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":message_text}]}});
    let message = serde_json::json!({"timestamp":"2026-09-10T00:00:01Z","type":"event_msg","payload":{"type":"item_completed","thread_id":session,"turn_id":"turn","item":{"type":"UserMessage","id":"user-1","content":[{"type":"text","text":message_text,"text_elements":[]}]},"completed_at_ms":1788998401000i64}});
    fs::write(&transcript, format!("{header}\n{raw_message}\n{message}\n")).unwrap();
    let report_value =
        observe_session_catalog_report(transcript.to_str(), session, "source-summary", None)
            .unwrap();
    let report = Arc::new(RwLock::new(Some(report_value.clone())));
    let data = temp.path().join("data");
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let (writer, task) = spawn_writer(open_writer(&data).await.unwrap(), 32).unwrap();
    // The source's repository attribution is an input to this package: retain
    // the existing source-time S11 proof gate using an actual local Git probe.
    // No Task, Episode, lane or binding is created by this registration.
    let evidence = evertrace_engine::repository::probe_repository(
        &workspace,
        evertrace_engine::repository::HostTrustDecision::Trusted,
        std::slice::from_ref(&source),
        observed_at_us,
        &evertrace_engine::repository::ProbeLimits::default(),
        &[],
        &[],
    )
    .unwrap();
    let repositories = evertrace_store::repository::RepositoryCurrentView::default();
    let registration = evertrace_engine::repository::resolve_repository(
        &evertrace_engine::repository::RepositoryResolveInput {
            view: &repositories,
            evidence: &evidence,
            derived_from_hint: None,
        },
    )
    .unwrap();
    writer
        .commit(
            registration
                .journal_command(observed_at_us, CONFIG, "source-attribution")
                .unwrap()
                .unwrap(),
            observed_at_us,
        )
        .await
        .unwrap();
    let catalog = SessionCatalogService::new(writer.clone(), CONFIG);
    catalog.refresh(&report_value).await.unwrap();
    let context = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    let repository = context
        .current
        .metadata
        .resolved_repository_instance_id
        .unwrap();
    let worktree = context
        .current
        .metadata
        .resolved_worktree_instance_id
        .unwrap();
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
    let worker =
        SessionImportWorker::new(writer.clone(), runtime(temp.path()), Arc::clone(&report))
            .unwrap();
    let mut imported = 0;
    for _ in 0..4 {
        let progress = worker
            .process_checkpoint(
                &source,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
                },
            )
            .await
            .unwrap();
        imported += progress.records;
        if progress.completed {
            break;
        }
    }
    assert_eq!(imported, 3);
    let snapshot = writer.project().await.unwrap();
    {
        let cas = evertrace_capture::CasStore::open_existing(temp.path().join("cas")).unwrap();
        assert!(snapshot.data_rows().any(|row| {
            let Some(json) = row.payload_json.as_deref() else {
                return false;
            };
            let Ok(JournalPayload::SourceReceiptRecorded(receipt)) = serde_json::from_str(json)
            else {
                return false;
            };
            receipt.observation_role == ObservationRole::Other
                && receipt.unsupported_record_classification.is_none()
                && cas
                    .read(&evertrace_capture::CasStore::parse_digest(&receipt.cas_ref).unwrap())
                    .unwrap()
                    == raw_message.to_string().as_bytes()
        }));
    }
    let receipt = snapshot
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SourceReceiptRecorded(receipt)
                    if receipt.observation_role == ObservationRole::Message =>
                {
                    Some(receipt)
                }
                _ => None,
            }
        })
        .next()
        .unwrap();
    if method {
        Box::pin(async move {
        let content = serde_json::json!({"title":"Marigold journal acknowledgement recovery","summary":"A reusable hypothesis for recovering ambiguous journal acknowledgements; effectiveness remains unverified.","procedure_kind":"diagnostic",
            "when":{"goals":["Recover an ambiguous commit acknowledgement"],"targets":["repository journal"],"signals":["acknowledgement lost"],"stage":"recover","requires":["Original command identity and payload are available"],"excludes":["Changed command payload"]},
            "applicability_expr":{"op":"exists","field":"failure_signature"},"avoid_expr":{"op":"eq","field":"phase","value":{"kind":"text","value":"unknown"}},"completion_expr":{"op":"eq","field":"verifier_state","value":{"kind":"text","value":"passed"}},
            "actions":{"stages":["Look up the original command and compare its exact payload","Resume from the committed receipt, or retry the same absent command at the current frontier"],"branches":[],"avoid":["Never mint another command identity for a lost acknowledgement"]},
            "done":{"success":["One matching commit and consistent projection"],"abort":["Payload differs"],"verify":["Replay and count the original command commit, then compare projection with its receipt"]},"pitfalls":["A missing acknowledgement does not establish that the transaction failed"]});
        let body = serde_json::to_vec(&serde_json::json!({"choices":[{"message":{"content":serde_json::json!({"operation":"create","content":content,"direct_refs":[receipt.source_observation_id.to_string()]}).to_string()}}],"usage":{"prompt_tokens":17,"completion_tokens":5}})).unwrap();
        // Both independent consumers run. This method response deliberately
        // fails the closed summary schema while the method can still commit.
        let (stub, release) = if interruption.is_some() {
            let (stub, release) = ProviderStub::once_paused(200, body).await;
            (stub, Some(release))
        } else { (ProviderStub::repeat(200, body, 2).await, None) };
        let llm = LlmConfig { base_url: ValidatedBaseUrl::parse(&stub.base_url).unwrap(), api_key_env: "PATH".into(),
            episode_enrichment: EpisodeEnrichment::Off, ..Default::default() };
        let dreaming = DreamingConfig { idle_after: DurationValue::from_seconds(1).unwrap(), ..Default::default() };
        let scheduler = BackgroundScheduler::new(writer.clone(), catalog.clone(), worker.clone(), Arc::clone(&report),
            runtime(temp.path()), SynthesisPlanner::new(llm.clone()), dreaming.clone());
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Some(release) = release {
            let mut running = Box::pin(scheduler.run_once());
            tokio::select! {
                _ = stub.wait_received() => {},
                result = &mut running => panic!("producer finished before provider gate: {result:?}"),
            }
            if interruption == Some(true) {
                let claimed = writer.project().await.unwrap();
                let current = evertrace_store::repository::RepositoryCurrentView::from_snapshot(&claimed).unwrap();
                let preview = evertrace_store::projections::repository_scope_purge_preview(&claimed, repository, current.repositories[&repository].repository_revision).unwrap();
                assert!(preview.blockers.is_empty());
                let command = evertrace_engine::purge::pending_repository_purge_command(RequestId::new_v7(), &preview,
                    preview.deletion_generation, observed_at_us + 5, claimed.frontier, CONFIG).unwrap();
                assert!(command.events().iter().any(|event| matches!(&event.payload,
                    JournalPayload::JobState(job) if job.kind == "procedure_review_v1" && job.state == JobStatus::Failed && job.lease_until_us.is_none())));
                writer.commit_if_frontier(command, observed_at_us + 5, claimed.frontier).await.unwrap();
            } else {
                admin.handle(RequestId::new_v7(), session, SessionImportAdminAction::RevokeAccess, 10).await.unwrap();
            }
            release.send(()).unwrap();
            running.await.unwrap();
            assert!(SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap().proposals.is_empty());
            let request = stub.finish().await;
            assert!(String::from_utf8_lossy(&request).contains("Extract at most one nontrivial reusable method"));
            drop(scheduler); drop(worker); drop(admin); drop(catalog); drop(writer);
            task.await.unwrap().unwrap();
            assert!(SemanticCurrentView::from_snapshot(&open_writer(&data).await.unwrap().project().await.unwrap()).unwrap().proposals.is_empty());
            return;
        }
        Box::pin(scheduler.run_once()).await.unwrap();
        let snapshot = writer.project().await.unwrap();
        let proposals = SemanticCurrentView::from_snapshot(&snapshot).unwrap();
        assert_eq!(proposals.proposals.len(), 1, "{:?}", evertrace_store::RuntimeSchedulerView::from_snapshot(&snapshot).unwrap().jobs);
        let proposal = proposals.proposals.values().next().unwrap().clone();
        assert_eq!(proposal.status, ProposalStatus::Pending);
        assert_eq!(proposal.eligibility, evertrace_domain::semantic::ProposalEligibility::ManualRequired);
        assert!(!snapshot.data_rows().any(|row| matches!(row.object_kind.as_deref(), Some("task" | "work_episode" | "procedure_revision" | "semantic_digest" | "procedure_usage"))));
        let requests = stub.finish_all().await;
        assert_eq!(requests.len(), 2);
        Box::pin(scheduler.run_once()).await.unwrap();
        let binding = evertrace_engine::McpBindingAuthority::new(DeviceKeyStore::new(temp.path().join("keys")).load_or_create().unwrap());
        let mcp = evertrace_engine::McpActionService::open(binding.clone(), &data, writer.clone(), runtime(temp.path())).await.unwrap()
            .with_session_report(Arc::clone(&report));
        let cross_session = "019d0000-0000-7000-8000-000000000099";
        for (action, input) in [(evertrace_engine::McpServiceAction::Search, "Marigold".into()),
            (evertrace_engine::McpServiceAction::Get, proposal.proposal_id.to_string())] {
            let result = read(&mcp, &binding, &report_value, &workspace, cross_session, action, input).await;
            let item = result.items.iter().find(|item| item.object_ref.as_deref() == Some(proposal.proposal_id.to_string().as_str()))
                .unwrap_or_else(|| panic!("method reference missing: {result:?}"));
            assert_eq!(item.partition, evertrace_engine::McpItemPartition::Evidence);
            assert_eq!(item.content_trust, ContentTrust::AgentClaim);
            assert_eq!(item.instruction_authority, evertrace_domain::evidence::InstructionAuthority::None);
            assert!(item.applicability.as_deref().unwrap().contains("unverified"));
            assert!(result.items.iter().all(|item| item.partition != evertrace_engine::McpItemPartition::Procedure));
        }
        assert_eq!(SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap().proposals.len(), 1);
        let other = temp.path().join("other-workspace");
        fs::create_dir(&other).unwrap();
        assert!(std::process::Command::new("git").args(["init", "-q"]).current_dir(&other).status().unwrap().success());
        let evidence = evertrace_engine::repository::probe_repository(&other, evertrace_engine::repository::HostTrustDecision::Trusted,
            std::slice::from_ref(&source), observed_at_us, &evertrace_engine::repository::ProbeLimits::default(), &[], &[]).unwrap();
        let repositories = evertrace_store::repository::RepositoryCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
        let registration = evertrace_engine::repository::resolve_repository(&evertrace_engine::repository::RepositoryResolveInput {
            view: &repositories, evidence: &evidence, derived_from_hint: None }).unwrap();
        writer.commit(registration.journal_command(observed_at_us, CONFIG, "other-attribution").unwrap().unwrap(), observed_at_us).await.unwrap();
        let repositories = evertrace_store::repository::RepositoryCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
        let other_id = repositories.repositories.values().find(|value| value.current_path == other.to_str().unwrap()).unwrap().repository_id;
        use std::io::Write;
        writeln!(fs::OpenOptions::new().append(true).open(adapter.join("config.toml")).unwrap(), "[projects.{}]\ntrust_level = \"trusted\"", serde_json::to_string(other.to_str().unwrap()).unwrap()).unwrap();
        let other_scope = evertrace_codex::binding::PublicWorkspace::Repository(other_id).canonical();
        for action in [evertrace_engine::McpServiceAction::Search, evertrace_engine::McpServiceAction::Get] {
            let input = if action == evertrace_engine::McpServiceAction::Search { "Marigold".into() } else { proposal.proposal_id.to_string() };
            let grant = binding.issue_with_report(evertrace_engine::McpBindingIssue { session_id: cross_session.into(), turn_id: "other".into(), tool_use_id: "other".into(), agent_id: None,
                action: if action == evertrace_engine::McpServiceAction::Search { "search" } else { "get" }.into(), workspace: other_scope.clone(), input: input.clone(), refs: vec![], launcher_protocol_revision: 1 }, Some(Arc::new(report_value.clone()))).unwrap();
            let result = Box::pin(mcp.handle("method-other-repository", evertrace_engine::McpServiceRequest { request_id: RequestId::new_v7(), action,
                workspace: grant.bound_workspace, input, refs: vec![], client_cwd: workspace.to_str().unwrap().into() })).await.unwrap();
            assert!(result.items.iter().all(|item| item.object_ref != Some(proposal.proposal_id.to_string())));
        }
        if independent {
            Box::pin(async move {
            Box::pin(async {
                let appendix = serde_json::json!({"timestamp":timestamp,"type":"event_msg","payload":{"type":"item_completed","thread_id":session,"turn_id":"independent","item":{"type":"UserMessage","id":"independent-method","content":[{"type":"text","text":"Saffron cache replacement method: when rebuilding a repository cache, preserve the live cache while writing the complete replacement into a sibling temporary directory. Validate its manifest and every referenced entry before one atomic rename. Abort on a missing entry; afterward reopen the live cache and compare its manifest against the replacement. This is a reusable suggested method, not proof of successful execution.","text_elements":[]}]},"completed_at_ms":1788998402000i64}});
                writeln!(fs::OpenOptions::new().append(true).open(&transcript).unwrap(), "{appendix}").unwrap();
                catalog.refresh(&report_value).await.unwrap();
                admin.handle(RequestId::new_v7(), session, SessionImportAdminAction::QueueImport, 10).await.unwrap();
                for _ in 0..4 {
                    if Box::pin(worker.process_checkpoint(&source, SessionImportBudget { max_bytes: 64 * 1024, max_records: 16, max_work_time: Duration::from_millis(250) })).await.unwrap().completed { break; }
                }
                let snapshot = writer.project().await.unwrap();
                let reference = snapshot.data_rows().filter_map(|row| {
                    if row.object_kind.as_deref() != Some("source_receipt") { return None; }
                    match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref().unwrap()).unwrap() {
                        JournalPayload::SourceReceiptRecorded(value) if value.observation_role == ObservationRole::Message => Some(value), _ => None,
                    }
                }).max_by_key(|value| value.source_sequence).unwrap().source_observation_id;
                let mut second = content.clone();
                second["title"] = serde_json::json!("Saffron validated atomic cache replacement");
                second["summary"] = serde_json::json!("Build and validate a sibling replacement before changing the live cache; effectiveness unverified.");
                second["when"]["goals"] = serde_json::json!(["Replace a repository cache without exposing a partial build"]);
                second["when"]["requires"] = serde_json::json!(["A sibling temporary directory and expected manifest are available"]);
                second["actions"]["stages"] = serde_json::json!(["Build a complete sibling cache while preserving the live cache", "Validate the manifest and all entries, then atomically rename the replacement"]);
                second["done"]["verify"] = serde_json::json!(["Reopen the live cache and compare its manifest with the validated replacement"]);
                let response = |value: serde_json::Value| serde_json::to_vec(&serde_json::json!({"choices":[{"message":{"content":value.to_string()}}],"usage":{"prompt_tokens":17,"completion_tokens":5}})).unwrap();
                let stub = ProviderStub::methods(response(serde_json::json!({"operation":"create","content":second,"direct_refs":[reference.to_string()]})), response(serde_json::json!({"operation":"no_op"})), response(serde_json::json!({"operation":"no_op"})), 3).await;
                let llm = LlmConfig { base_url: ValidatedBaseUrl::parse(&stub.base_url).unwrap(), ..llm.clone() };
                let runner = BackgroundScheduler::new(writer.clone(), catalog.clone(), worker.clone(), Arc::clone(&report), runtime(temp.path()), SynthesisPlanner::new(llm), dreaming.clone());
                tokio::time::sleep(Duration::from_secs(1)).await;
                Box::pin(runner.run_once()).await.unwrap();
                let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
                assert_eq!(view.proposals.len(), 2, "a previous method must not consume an entire session forever");
                assert_eq!(view.proposals[&proposal.proposal_id], proposal);
                assert!(view.proposals.values().any(|value| value.evidence_refs.contains(&reference.to_string())));
                let requests = stub.finish_all().await;
                assert_eq!(requests.len(), 3);
                assert_eq!(requests.iter().filter(|request| String::from_utf8_lossy(request).contains("Extract at most one nontrivial reusable method")).count(), 1);
                assert_eq!(requests.iter().filter(|request| String::from_utf8_lossy(request).contains("Review one Procedure")).count(), 1);
                let expected = view.proposals.values().map(|proposal| (proposal.proposal_id.to_string(), proposal.proposal_revision_id.to_string())).collect::<Vec<_>>();
                Box::pin(read_methods(&mcp, &binding, &report_value, &workspace, cross_session, &expected)).await;
                let jobs_before = evertrace_store::RuntimeSchedulerView::from_snapshot(&writer.project().await.unwrap()).unwrap().jobs;
                Box::pin(runner.run_once()).await.unwrap();
                assert_eq!(SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap().proposals, view.proposals);
                assert_eq!(evertrace_store::RuntimeSchedulerView::from_snapshot(&writer.project().await.unwrap()).unwrap().jobs, jobs_before);
            }).await;
            drop(mcp); drop(scheduler); drop(worker); drop(admin); drop(catalog); drop(writer);
            task.await.unwrap().unwrap();
            let (writer, task) = spawn_writer(open_writer(&data).await.unwrap(), 32).unwrap();
            let catalog = SessionCatalogService::new(writer.clone(), CONFIG);
            let worker = SessionImportWorker::new(writer.clone(), runtime(temp.path()), Arc::clone(&report)).unwrap();
            let runner = BackgroundScheduler::new(writer.clone(), catalog, worker, Arc::clone(&report), runtime(temp.path()), SynthesisPlanner::new(llm), dreaming);
            let before = writer.project().await.unwrap();
            Box::pin(runner.run_once()).await.unwrap();
            let after = writer.project().await.unwrap();
            assert_eq!(SemanticCurrentView::from_snapshot(&after).unwrap().proposals.len(), 2);
            assert_eq!(evertrace_store::RuntimeSchedulerView::from_snapshot(&before).unwrap().jobs, evertrace_store::RuntimeSchedulerView::from_snapshot(&after).unwrap().jobs);
            drop(runner); drop(writer); task.await.unwrap().unwrap();
            }).await;
            return;
        }
        Box::pin(async {
        let jobs_before_tool = evertrace_store::RuntimeSchedulerView::from_snapshot(&writer.project().await.unwrap()).unwrap()
            .jobs.into_iter().filter(|job| job.kind == "procedure_review_v1").count();
        let tool = serde_json::json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"method-tool-1","output":"A tool result is not a new method-review message"}});
        writeln!(fs::OpenOptions::new().append(true).open(&transcript).unwrap(), "{tool}").unwrap();
        catalog.refresh(&report_value).await.unwrap();
        admin.handle(RequestId::new_v7(), session, SessionImportAdminAction::QueueImport, 10).await.unwrap();
        for _ in 0..4 {
            if Box::pin(worker.process_checkpoint(&source, SessionImportBudget { max_bytes: 64 * 1024, max_records: 16,
                max_work_time: Duration::from_millis(250) })).await.unwrap().completed { break; }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        Box::pin(scheduler.run_once()).await.unwrap();
        assert_eq!(evertrace_store::RuntimeSchedulerView::from_snapshot(&writer.project().await.unwrap()).unwrap()
            .jobs.into_iter().filter(|job| job.kind == "procedure_review_v1").count(), jobs_before_tool);
        }).await;
        // A new, related source message triggers the existing review consumer;
        // the producer's own proposal and repeated idle ticks did not.
        let appendix = serde_json::json!({"timestamp":timestamp,"type":"event_msg","payload":{"type":"item_completed","thread_id":session,"turn_id":"next","item":{"type":"UserMessage","id":"user-2","content":[{"type":"text","text":"Marigold refinement: before counting commits during acknowledgement recovery, wait for the authoritative journal read to finish; a partial read cannot establish absence.","text_elements":[]}]},"completed_at_ms":1788998402000i64}});
        writeln!(fs::OpenOptions::new().append(true).open(&transcript).unwrap(), "{appendix}").unwrap();
        catalog.refresh(&report_value).await.unwrap();
        admin.handle(RequestId::new_v7(), session, SessionImportAdminAction::QueueImport, 10).await.unwrap();
        for _ in 0..4 {
            if Box::pin(worker.process_checkpoint(&source, SessionImportBudget { max_bytes: 64 * 1024, max_records: 16,
                max_work_time: Duration::from_millis(250) })).await.unwrap().completed { break; }
        }
        let mut revised = content.clone();
        revised["summary"] = serde_json::json!("Marigold ambiguous acknowledgement recovery requires a complete authoritative read before treating a command as absent; effectiveness unverified.");
        revised["pitfalls"].as_array_mut().unwrap().push(serde_json::json!("A partial journal read cannot establish command absence"));
        let review_body = serde_json::to_vec(&serde_json::json!({"choices":[{"message":{"content":serde_json::json!({"operation":"revise","content":revised}).to_string()}}],"usage":{"prompt_tokens":17,"completion_tokens":5}})).unwrap();
        let no_op = serde_json::to_vec(&serde_json::json!({"choices":[{"message":{"content":"{\"operation\":\"no_op\"}"}}],"usage":{"prompt_tokens":17,"completion_tokens":5}})).unwrap();
        let review_stub = ProviderStub::methods(no_op.clone(), review_body, no_op, 3).await;
        let review_llm = LlmConfig { base_url: ValidatedBaseUrl::parse(&review_stub.base_url).unwrap(), ..llm.clone() };
        let reviewer = BackgroundScheduler::new(writer.clone(), catalog.clone(), worker.clone(), Arc::clone(&report),
            runtime(temp.path()), SynthesisPlanner::new(review_llm.clone()), dreaming.clone());
        tokio::time::sleep(Duration::from_secs(1)).await;
        Box::pin(reviewer.run_once()).await.unwrap();
        let reviewed = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
        assert_eq!(reviewed.proposals.len(), 1);
        let successor = reviewed.proposals[&proposal.proposal_id].clone();
        assert_ne!(successor.proposal_revision_id, proposal.proposal_revision_id);
        assert_eq!(successor.parent_proposal_revision_id, Some(proposal.proposal_revision_id));
        assert!(successor.source_cohort_refs.len() > proposal.source_cohort_refs.len());
        let review_requests = review_stub.finish_all().await;
        assert_eq!(review_requests.len(), 3);
        assert_eq!(review_requests.iter().filter(|request| String::from_utf8_lossy(request)
            .contains("Extract at most one nontrivial reusable method")).count(), 1);
        assert_eq!(review_requests.iter().filter(|request| String::from_utf8_lossy(request)
            .contains("Review one Procedure")).count(), 1);
        assert!(review_requests.iter().all(|request| !String::from_utf8_lossy(request)
            .contains("A tool result is not a new method-review message")));
        Box::pin(reviewer.run_once()).await.unwrap();
        assert_eq!(SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap().proposals[&proposal.proposal_id], successor);
        drop(reviewer);
        drop(mcp); drop(scheduler); drop(worker); drop(admin); drop(catalog); drop(writer);
        task.await.unwrap().unwrap();
        let (writer, task) = spawn_writer(open_writer(&data).await.unwrap(), 32).unwrap();
        let catalog = SessionCatalogService::new(writer.clone(), CONFIG);
        let worker = SessionImportWorker::new(writer.clone(), runtime(temp.path()), Arc::clone(&report)).unwrap();
        let off = BackgroundScheduler::new(writer.clone(), catalog.clone(), worker.clone(), Arc::clone(&report), runtime(temp.path()),
            SynthesisPlanner::new(LlmConfig { enabled: false, ..review_llm }), dreaming);
        Box::pin(off.run_once()).await.unwrap();
        assert_eq!(SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap().proposals[&proposal.proposal_id], successor);
        let mcp = evertrace_engine::McpActionService::open(binding.clone(), &data, writer.clone(), runtime(temp.path())).await.unwrap().with_session_report(Arc::clone(&report));
        let result = read(&mcp, &binding, &report_value, &workspace, cross_session, evertrace_engine::McpServiceAction::Get, proposal.proposal_id.to_string()).await;
        assert!(result.items.iter().any(|item| item.object_revision_ref == Some(successor.proposal_revision_id.to_string())));
        let admin = SessionImportAdminService::new(writer.clone(), Arc::clone(&report), CONFIG);
        if !terminal {
        admin.handle(RequestId::new_v7(), session, SessionImportAdminAction::RevokeAccess, 10).await.unwrap();
        for (action, input) in [(evertrace_engine::McpServiceAction::Search, "Marigold".into()), (evertrace_engine::McpServiceAction::Get, proposal.proposal_id.to_string()), (evertrace_engine::McpServiceAction::Get, proposal.proposal_revision_id.to_string())] {
            let result = read(&mcp, &binding, &report_value, &workspace, cross_session, action, input).await;
            assert!(result.items.iter().all(|item| item.object_ref != Some(proposal.proposal_id.to_string())));
        }
        } else {
        let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
        let at = observed_at_us + 20_000_000;
        let evertrace_engine::semantic::ProposalResolution::Revision { command, .. } = evertrace_engine::semantic::RevisionProposalService.revise_status(&view,
            evertrace_engine::semantic::ProposalCommandContext { command_id: evertrace_domain::ids::CommandId::new_v7(), occurred_at_us: at, effective_config_hash: CONFIG, algorithm_revision: "method-reference-test".into() },
            proposal.proposal_id, ProposalStatus::Rejected, vec![], Some("Not accepted for execution".into())).unwrap() else { panic!("missing status transition") };
        writer.commit(command, at).await.unwrap();
        for (action, input) in [(evertrace_engine::McpServiceAction::Search, "Marigold".into()), (evertrace_engine::McpServiceAction::Get, successor.proposal_revision_id.to_string())] {
            let result = read(&mcp, &binding, &report_value, &workspace, cross_session, action, input).await;
            assert!(result.items.iter().all(|item| item.object_ref != Some(proposal.proposal_id.to_string())));
        }
        assert_eq!(SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap().proposals[&proposal.proposal_id].status, ProposalStatus::Rejected);
        }
        drop(mcp); drop(off); drop(worker); drop(admin); drop(catalog); drop(writer);
        task.await.unwrap().unwrap();
        }).await;
        return;
    }
    let application = evertrace_engine::provider::ProviderSemanticApplication {
        progress_delta: vec![SemanticStructuredDelta {
            label: "message claim".into(),
            value: "marigold descriptive source memory".into(),
            direct_refs: vec![receipt.source_observation_id.to_string()],
        }],
        decision_delta: vec![],
        failed_routes: vec![],
        resolved_items: vec![],
        open_loops: vec![],
        outcome_delta: vec![],
        omissions: vec![],
        candidates: vec![],
        completeness: SemanticCompleteness::Complete,
    };
    let stub = ProviderStub::recovering(serde_json::to_vec(&serde_json::json!({"choices":[{"message":{"content":serde_json::to_string(&application).unwrap()}}],"usage":{"prompt_tokens":17,"completion_tokens":5}})).unwrap()).await;
    let llm = LlmConfig {
        base_url: ValidatedBaseUrl::parse(&stub.base_url).unwrap(),
        api_key_env: "PATH".into(),
        episode_enrichment: EpisodeEnrichment::Off,
        ..Default::default()
    };
    // Only accelerate the existing idle clock for this local scheduler test;
    // production configuration still validates its existing five-minute minimum.
    let dreaming = DreamingConfig {
        idle_after: DurationValue::from_seconds(1).unwrap(),
        ..Default::default()
    };
    let scheduler = BackgroundScheduler::new(
        writer.clone(),
        catalog.clone(),
        worker.clone(),
        Arc::clone(&report),
        runtime(temp.path()),
        SynthesisPlanner::new(llm.clone()),
        dreaming.clone(),
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    Box::pin(scheduler.run_once()).await.unwrap();
    let failed_snapshot = writer.project().await.unwrap();
    let failed = evertrace_store::RuntimeSchedulerView::from_snapshot(&failed_snapshot)
        .unwrap()
        .jobs
        .into_iter()
        .find(|job| job.kind == "semantic_synthesis_v1")
        .unwrap();
    assert_eq!(failed.state, JobStatus::Failed);
    assert!(failed.backoff_until_us.is_some());
    assert!(
        !failed_snapshot
            .data_rows()
            .any(|row| row.object_kind.as_deref() == Some("semantic_digest"))
    );
    Box::pin(scheduler.run_once()).await.unwrap();
    assert_eq!(
        evertrace_store::RuntimeSchedulerView::from_snapshot(&writer.project().await.unwrap())
            .unwrap()
            .jobs
            .into_iter()
            .filter(|job| job.kind == "semantic_synthesis_v1")
            .collect::<Vec<_>>(),
        std::slice::from_ref(&failed)
    );
    // The same provider/config and immutable job recover after real backoff.
    tokio::time::sleep(Duration::from_secs(5)).await;
    Box::pin(scheduler.run_once()).await.unwrap();
    let snapshot = writer.project().await.unwrap();
    let source_jobs = evertrace_store::RuntimeSchedulerView::from_snapshot(&snapshot)
        .unwrap()
        .jobs
        .into_iter()
        .filter(|job| job.kind == "semantic_synthesis_v1")
        .collect::<Vec<_>>();
    assert_eq!(source_jobs.len(), 1);
    let succeeded = &source_jobs[0];
    assert_eq!(succeeded.job_id, failed.job_id);
    assert_eq!(
        (succeeded.state, succeeded.attempt),
        (JobStatus::Succeeded, failed.attempt + 2)
    );
    let digests = snapshot
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SemanticDigestRecorded(digest) => Some(digest),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        digests.len(),
        1,
        "source synthesis did not commit: {:?}",
        evertrace_store::RuntimeSchedulerView::from_snapshot(&snapshot)
            .unwrap()
            .jobs
    );
    let digest = &digests[0];
    assert!(digest.episode_id.is_none() && digest.task_id.is_none());
    assert_eq!(
        (digest.repository_id, digest.worktree_id),
        (Some(repository), Some(worktree))
    );
    assert!(digest.application.candidates.is_empty());
    assert_eq!(
        digest.application.completeness,
        SemanticCompleteness::Partial
    );
    assert!(digest.application.omissions.iter().any(|omission| {
        omission.category == "source_input_budget"
            && omission.direct_refs == vec![receipt.source_observation_id.to_string()]
    }));
    assert!(!snapshot.data_rows().any(|row| matches!(
        row.object_kind.as_deref(),
        Some(
            "task" | "work_episode" | "execution_lane" | "binding_resolution" | "revision_proposal"
        )
    )));
    let mut requests = stub.finish_all().await;
    assert!(requests.iter().any(|request| {
        String::from_utf8_lossy(request).contains("Extract at most one nontrivial reusable method")
    }));
    requests.retain(|request| {
        !String::from_utf8_lossy(request).contains("Extract at most one nontrivial reusable method")
    });
    assert_eq!(requests.len(), 2);
    let request = requests.pop().unwrap();
    let boundary = request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    let request: serde_json::Value = serde_json::from_slice(&request[boundary..]).unwrap();
    let input: serde_json::Value =
        serde_json::from_str(request["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert!(input.get("episode_id").is_none() && input.get("stage_trace").is_none());
    assert_eq!(
        input["source_refs"],
        serde_json::json!([receipt.source_observation_id.to_string()])
    );
    assert!(!input.to_string().contains("client_authored"));
    assert!(!input.to_string().contains("fallback_token_limit_override"));
    assert_eq!(
        input["source_target"]["source_revision"],
        receipt.source_revision.as_str()
    );
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
    for (action, input) in [
        (
            evertrace_engine::McpServiceAction::Search,
            "marigold".to_owned(),
        ),
        (
            evertrace_engine::McpServiceAction::Get,
            digest.semantic_digest_id.to_string(),
        ),
    ] {
        let result = read(
            &mcp,
            &bindings,
            &report_value,
            &workspace,
            session,
            action,
            input,
        )
        .await;
        let item = result
            .items
            .iter()
            .find(|item| item.object_ref == Some(digest.semantic_digest_id.to_string()))
            .unwrap_or_else(|| panic!("MCP must return the digest: {action:?} {result:?}"));
        assert_eq!(item.content_trust, ContentTrust::AgentClaim);
        assert_eq!(item.authority.as_deref(), Some("agent_inferred"));
        assert_eq!(
            item.instruction_authority,
            evertrace_domain::evidence::InstructionAuthority::None
        );
        assert!(item.text.as_ref().unwrap().contains("marigold"));
    }
    let other_workspace = temp.path().join("other-workspace");
    fs::create_dir(&other_workspace).unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&other_workspace)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap()
            .success()
    );
    let other_session = "019d0000-0000-7000-8000-000000000062";
    let other_path = dated.join(format!("rollout-2026-09-10T00-00-00-{other_session}.jsonl"));
    fs::write(&other_path,format!("{}\n",serde_json::json!({"timestamp":timestamp,"type":"session_meta","payload":{"id":other_session,"session_id":other_session,"cwd":other_workspace}}))).unwrap();
    let other_report =
        observe_session_catalog_report(other_path.to_str(), other_session, "source-summary", None)
            .unwrap();
    catalog.refresh(&other_report).await.unwrap();
    assert!(
        read(
            &mcp,
            &bindings,
            &other_report,
            &other_workspace,
            other_session,
            evertrace_engine::McpServiceAction::Search,
            "marigold".into()
        )
        .await
        .items
        .is_empty()
    );
    Box::pin(scheduler.run_once()).await.unwrap();
    let final_snapshot = writer.project().await.unwrap();
    assert_eq!(
        final_snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("semantic_digest"))
            .count(),
        1
    );
    let old_id = digest.semantic_digest_id.to_string();
    // Normal append keeps the logical revision and advances only the new
    // imported message interval. Disabling the LLM does not hide old memory.
    let body = fs::read_to_string(&transcript).unwrap();
    let raw_delta = serde_json::json!({"type":"response_item","metadata":{},"payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"marigold appended claim"}],"phase":"final_answer"}});
    let delta = serde_json::json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":session,"turn_id":"turn","item":{"type":"AgentMessage","id":"agent-1","content":[{"type":"Text","text":"marigold appended claim"}],"phase":"final_answer","memory_citation":{"entries":[{"path":"notes.md","lineStart":1,"lineEnd":2,"note":"source claim"}],"rolloutIds":["prior-rollout"]},"delivery":"async","questions":[{"title":"Continue?","options":["yes","no"]}]},"started_at_ms":1788998401000i64,"completed_at_ms":1788998402000i64}});
    fs::write(&transcript, format!("{body}{raw_delta}\n{delta}\n")).unwrap();
    catalog.refresh(&report_value).await.unwrap();
    let mut imported_delta = 0;
    for _ in 0..3 {
        let progress = worker
            .process_checkpoint(
                &source,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
                },
            )
            .await
            .unwrap();
        imported_delta += progress.records;
        if progress.completed {
            break;
        }
    }
    assert_eq!(imported_delta, 2);
    let appended = writer.project().await.unwrap();
    let second = appended
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SourceReceiptRecorded(value)
                    if value.observation_role == ObservationRole::Message
                        && value.source_observation_id != receipt.source_observation_id =>
                {
                    Some(value)
                }
                _ => None,
            }
        })
        .next()
        .unwrap();
    assert_eq!(second.source_revision, receipt.source_revision);
    let disabled = BackgroundScheduler::new(
        writer.clone(),
        catalog.clone(),
        worker.clone(),
        Arc::clone(&report),
        runtime(temp.path()),
        SynthesisPlanner::new(LlmConfig {
            enabled: false,
            ..llm.clone()
        }),
        dreaming.clone(),
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    Box::pin(disabled.run_once()).await.unwrap();
    assert_eq!(
        writer
            .project()
            .await
            .unwrap()
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("semantic_digest"))
            .count(),
        1
    );
    assert!(
        read(
            &mcp,
            &bindings,
            &report_value,
            &workspace,
            session,
            evertrace_engine::McpServiceAction::Get,
            old_id.clone()
        )
        .await
        .items
        .iter()
        .any(|item| item.object_ref.as_deref() == Some(&old_id))
    );
    let mut second_application = application.clone();
    second_application.progress_delta[0].direct_refs =
        vec![second.source_observation_id.to_string()];
    second_application.progress_delta[0].value = "marigold appended claim".into();
    let (second_stub, release) = ProviderStub::once_paused(200, serde_json::to_vec(&serde_json::json!({"choices":[{"message":{"content":serde_json::to_string(&second_application).unwrap()}}],"usage":{"prompt_tokens":17,"completion_tokens":5}})).unwrap()).await;
    let second_scheduler = BackgroundScheduler::new(
        writer.clone(),
        catalog.clone(),
        worker.clone(),
        Arc::clone(&report),
        runtime(temp.path()),
        SynthesisPlanner::new(LlmConfig {
            base_url: ValidatedBaseUrl::parse(&second_stub.base_url).unwrap(),
            ..llm.clone()
        }),
        dreaming.clone(),
    );
    let running = tokio::spawn({
        let scheduler = second_scheduler.clone();
        async move { Box::pin(scheduler.run_once()).await }
    });
    tokio::time::timeout(Duration::from_secs(5), second_stub.wait_received())
        .await
        .unwrap();
    // Append while the provider owns a frozen interval; this non-message is
    // not another LLM trigger and does not invalidate archived input.
    let body = fs::read_to_string(&transcript).unwrap();
    let non_messages = [
        serde_json::json!({"type":"response_item","metadata":null,"payload":{"type":"function_call","name":"example","arguments":"{}","call_id":"call-1"}}),
        serde_json::json!({"type":"response_item","metadata":{"client_authored":false},"payload":{"type":"function_call_output","call_id":"call-1","output":"archived tool output"}}),
        serde_json::json!({"type":"response_item","payload":{"type":"reasoning","summary":[],"encrypted_content":"opaque"}}),
        serde_json::json!({"type":"response_item","payload":{"type":"agent_message","author":"agent-a","recipient":"agent-b","content":[{"type":"input_text","text":"separate cross-agent representation"}]}}),
        serde_json::json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":session,"turn_id":"turn","item":{"type":"Reasoning","id":"reasoning-1","summary_text":[],"raw_content":["not visible reasoning"]},"completed_at_ms":1788998403000i64}}),
        serde_json::json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":session,"turn_id":"turn","item":{"type":"Plan","id":"plan-1","text":"not a message trigger"},"completed_at_ms":1788998403000i64}}),
        serde_json::json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":session,"turn_id":"turn","item":{"type":"UserMessage","id":"image-1","content":[{"type":"image","image_url":"data:image/png;base64,AA=="}]},"completed_at_ms":1788998403000i64}}),
    ];
    fs::write(
        &transcript,
        format!(
            "{body}{}\n",
            non_messages
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        ),
    )
    .unwrap();
    catalog.refresh(&report_value).await.unwrap();
    for _ in 0..3 {
        if worker
            .process_checkpoint(
                &source,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
                },
            )
            .await
            .unwrap()
            .completed
        {
            break;
        }
    }
    {
        let snapshot = writer.project().await.unwrap();
        let cas = evertrace_capture::CasStore::open_existing(temp.path().join("cas")).unwrap();
        let archived = snapshot
            .data_rows()
            .filter_map(|row| {
                let JournalPayload::SourceReceiptRecorded(receipt) =
                    serde_json::from_str(row.payload_json.as_deref()?).ok()?
                else {
                    return None;
                };
                (receipt.observation_role == ObservationRole::Other).then(|| {
                    cas.read(&evertrace_capture::CasStore::parse_digest(&receipt.cas_ref).unwrap())
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        assert!(
            non_messages
                .iter()
                .all(|record| archived.contains(&record.to_string().into_bytes()))
        );
    }
    release.send(()).unwrap();
    running.await.unwrap().unwrap();
    let second_request = second_stub.finish().await;
    let boundary = second_request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    let second_request: serde_json::Value =
        serde_json::from_slice(&second_request[boundary..]).unwrap();
    let second_input: serde_json::Value =
        serde_json::from_str(second_request["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(
        second_input["source_refs"],
        serde_json::json!([second.source_observation_id.to_string()])
    );
    assert_eq!(
        writer
            .project()
            .await
            .unwrap()
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("semantic_digest"))
            .count(),
        2
    );
    drop((disabled, second_scheduler, catalog, worker));
    drop((scheduler, mcp));
    writer.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let (writer, task) = spawn_writer(open_writer(&data).await.unwrap(), 32).unwrap();
    let mcp = evertrace_engine::McpActionService::open(
        bindings.clone(),
        &data,
        writer.clone(),
        runtime(temp.path()),
    )
    .await
    .unwrap()
    .with_session_report(Arc::clone(&report));
    assert!(
        read(
            &mcp,
            &bindings,
            &report_value,
            &workspace,
            session,
            evertrace_engine::McpServiceAction::Get,
            old_id.clone()
        )
        .await
        .items
        .iter()
        .any(|item| item.object_ref.as_deref() == Some(&old_id))
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let restarted = BackgroundScheduler::new(
        writer.clone(),
        SessionCatalogService::new(writer.clone(), CONFIG),
        SessionImportWorker::new(writer.clone(), runtime(temp.path()), Arc::clone(&report))
            .unwrap(),
        Arc::clone(&report),
        runtime(temp.path()),
        SynthesisPlanner::new(LlmConfig {
            base_url: ValidatedBaseUrl::parse(&format!(
                "http://{}/v1",
                listener.local_addr().unwrap()
            ))
            .unwrap(),
            model: "changed-model".into(),
            ..llm.clone()
        }),
        dreaming.clone(),
    );
    Box::pin(restarted.run_once()).await.unwrap();
    Box::pin(restarted.run_once()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(
        writer
            .project()
            .await
            .unwrap()
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("semantic_digest"))
            .count(),
        2
    );
    // Keep the lifecycle's independent negative phase off the positive
    // phase's debug-build poll stack; do not enlarge thread/resource limits.
    tokio::spawn(async move {
    drop(restarted);
    let catalog = SessionCatalogService::new(writer.clone(), CONFIG);
    let worker =
        SessionImportWorker::new(writer.clone(), runtime(temp.path()), Arc::clone(&report))
            .unwrap();
    let admin = SessionImportAdminService::new(writer.clone(), Arc::clone(&report), CONFIG);
    // A true rewrite has a separate source revision. Its old protected archive
    // and descriptive digest remain readable without consulting the old JSONL.
    let rewritten = serde_json::json!({"type":"event_msg","payload":{"type":"user_message","message":"marigold replacement claim"}});
    fs::write(&transcript, format!("{header}\n{rewritten}\n")).unwrap();
    catalog.refresh(&report_value).await.unwrap();
    admin
        .handle(
            RequestId::new_v7(),
            session,
            SessionImportAdminAction::QueueImport,
            observed_at_us + 1,
        )
        .await
        .unwrap();
    for _ in 0..4 {
        if worker
            .process_checkpoint(
                &source,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
                },
            )
            .await
            .unwrap()
            .completed
        {
            break;
        }
    }
    let rewritten_snapshot = writer.project().await.unwrap();
    let replacement = rewritten_snapshot
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SourceReceiptRecorded(value)
                    if value.observation_role == ObservationRole::Message
                        && value.source_revision != receipt.source_revision =>
                {
                    Some(value)
                }
                _ => None,
            }
        })
        .next()
        .unwrap();
    assert!(
        read(
            &mcp,
            &bindings,
            &report_value,
            &workspace,
            session,
            evertrace_engine::McpServiceAction::Get,
            old_id.clone()
        )
        .await
        .items
        .iter()
        .any(|item| item.object_ref.as_deref() == Some(&old_id))
    );
    let target = evertrace_domain::semantic::SemanticSourceTarget {
        source_instance_id: replacement.source_instance_id.clone(),
        source_revision: replacement.source_revision.clone(),
        repository_id: repository,
        worktree_id: worktree,
    };
    let mut mixed = vec![
        receipt.source_observation_id.to_string(),
        replacement.source_observation_id.to_string(),
    ];
    mixed.sort();
    assert!(
        Box::pin(SynthesisPlanner::new(llm.clone())
            .execute(evertrace_engine::jobs::SynthesisRequest {
                snapshot: &rewritten_snapshot,
                target: evertrace_engine::jobs::SynthesisTarget::Source {
                    source: target,
                    after_sequence: 0,
                    through_sequence: replacement.source_sequence
                },
                trigger: evertrace_domain::semantic::SemanticDigestTrigger::SourceMessages,
                direct_delta: vec![evertrace_engine::provider::ProtectedDeltaItem {
                    kind: evertrace_engine::provider::ProtectedDeltaKind::Progress,
                    value: "descriptive fixture".into(),
                    direct_refs: mixed.clone()
                }],
                selected_direct_refs: mixed,
                command_id: evertrace_domain::ids::CommandId::new_v7(),
                occurred_at_us: observed_at_us + 2,
                algorithm_revision: "semantic_synthesis_v1".into(),
                effective_config_hash: CONFIG,
            }))
            .await
            .is_err()
    );
    let mut replacement_application = application.clone();
    replacement_application.progress_delta[0].direct_refs =
        vec![replacement.source_observation_id.to_string()];
    replacement_application.progress_delta[0].value = "marigold replacement claim".into();
    let response = |application: &evertrace_engine::provider::ProviderSemanticApplication| {
        serde_json::to_vec(&serde_json::json!({"choices":[{"message":{"content":serde_json::to_string(application).unwrap()}}],"usage":{"prompt_tokens":17,"completion_tokens":5}})).unwrap()
    };
    let (revoked_stub, release) =
        ProviderStub::once_paused(200, response(&replacement_application)).await;
    let revoking = BackgroundScheduler::new(
        writer.clone(),
        catalog.clone(),
        worker.clone(),
        Arc::clone(&report),
        runtime(temp.path()),
        SynthesisPlanner::new(LlmConfig {
            base_url: ValidatedBaseUrl::parse(&revoked_stub.base_url).unwrap(),
            ..llm.clone()
        }),
        dreaming.clone(),
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let running = tokio::spawn({
        let scheduler = revoking.clone();
        async move { Box::pin(scheduler.run_once()).await }
    });
    tokio::time::timeout(Duration::from_secs(5), revoked_stub.wait_received())
        .await
        .unwrap();
    admin
        .handle(
            RequestId::new_v7(),
            session,
            SessionImportAdminAction::RevokeAccess,
            observed_at_us + 3,
        )
        .await
        .unwrap();
    release.send(()).unwrap();
    running.await.unwrap().unwrap();
    revoked_stub.finish().await;
    assert_eq!(
        writer
            .project()
            .await
            .unwrap()
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("semantic_digest"))
            .count(),
        2
    );
    for (action, input) in [
        (evertrace_engine::McpServiceAction::Get, old_id.clone()),
        (
            evertrace_engine::McpServiceAction::Search,
            "marigold".into(),
        ),
    ] {
        assert!(
            read(
                &mcp,
                &bindings,
                &report_value,
                &workspace,
                session,
                action,
                input
            )
            .await
            .items
            .is_empty()
        );
    }
    drop((revoking, catalog, worker, admin, mcp));
    writer.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let (writer, task) = spawn_writer(open_writer(&data).await.unwrap(), 32).unwrap();
    let catalog = SessionCatalogService::new(writer.clone(), CONFIG);
    let worker =
        SessionImportWorker::new(writer.clone(), runtime(temp.path()), Arc::clone(&report))
            .unwrap();
    let mcp = evertrace_engine::McpActionService::open(
        bindings.clone(),
        &data,
        writer.clone(),
        runtime(temp.path()),
    )
    .await
    .unwrap()
    .with_session_report(Arc::clone(&report));
    let quiet = BackgroundScheduler::new(
        writer.clone(),
        catalog.clone(),
        worker.clone(),
        Arc::clone(&report),
        runtime(temp.path()),
        SynthesisPlanner::new(llm.clone()),
        dreaming.clone(),
    );
    Box::pin(quiet.run_once()).await.unwrap();
    assert!(
        read(
            &mcp,
            &bindings,
            &report_value,
            &workspace,
            session,
            evertrace_engine::McpServiceAction::Get,
            old_id.clone()
        )
        .await
        .items
        .is_empty()
    );
    assert!(
        !evertrace_store::RuntimeSchedulerView::from_snapshot(&writer.project().await.unwrap())
            .unwrap()
            .jobs
            .iter()
            .any(|job| job.kind == "semantic_synthesis_v1"
                && matches!(job.state, JobStatus::Queued | JobStatus::Leased))
    );
    // Revocation remains closed. A separate normally admitted source in this
    // same real repository tests purge while its claim is in flight.
    let purge_session="019d0000-0000-7000-8000-000000000063";
    let purge_source=format!("session-rollout:{purge_session}:{purge_session}");
    let purge_path=transcript.parent().unwrap().join(format!("rollout-2026-09-10T00-00-00-{purge_session}.jsonl"));
    let purge_workspace=workspace.parent().unwrap().join("purge-worktree");
    assert!(std::process::Command::new("git").args(["worktree","add","-q","--detach",purge_workspace.to_str().unwrap()])
        .current_dir(&workspace).env("GIT_CONFIG_GLOBAL","/dev/null").env("GIT_CONFIG_NOSYSTEM","1").status().unwrap().success());
    let config_path=adapter.join("config.toml");
    let config=fs::read_to_string(&config_path).unwrap();
    fs::write(config_path,format!("{config}\n[projects.{}]\ntrust_level = \"trusted\"\n",serde_json::to_string(purge_workspace.to_str().unwrap()).unwrap())).unwrap();
    let clock=std::process::Command::new("date").args(["-u","+%Y-%m-%dT%H:%M:%SZ %s"]).output().unwrap();
    assert!(clock.status.success());
    let clock=String::from_utf8(clock.stdout).unwrap();
    let (timestamp,seconds)=clock.trim().split_once(' ').unwrap();
    let purge_at=seconds.parse::<i64>().unwrap()*1_000_000;
    let mut purge_header=header.clone();
    purge_header["timestamp"]=timestamp.into();
    purge_header["payload"]["id"]=purge_session.into();
    purge_header["payload"]["session_id"]=purge_session.into();
    purge_header["payload"]["cwd"]=purge_workspace.to_str().unwrap().into();
    let final_message=serde_json::json!({"type":"event_msg","payload":{"type":"user_message","message":"marigold purge claim"}});
    fs::write(&purge_path,format!("{purge_header}\n{final_message}\n")).unwrap();
    let current=evertrace_store::repository::RepositoryCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let known_heads=current.snapshots.values().filter_map(|snapshot|snapshot.head_oid.as_deref()).map(|head|evertrace_engine::repository::GitOid::parse(head).unwrap()).collect::<Vec<_>>();
    let probe=evertrace_engine::repository::probe_repository(&purge_workspace,evertrace_engine::repository::HostTrustDecision::Trusted,std::slice::from_ref(&purge_source),purge_at,&evertrace_engine::repository::ProbeLimits::default(),&current.known_admin_paths(),&known_heads).unwrap();
    let registration=evertrace_engine::repository::resolve_repository(&evertrace_engine::repository::RepositoryResolveInput {view:&current,evidence:&probe,derived_from_hint:None}).unwrap();
    writer.commit(registration.journal_command(purge_at,CONFIG,"source-attribution").unwrap().unwrap(),purge_at).await.unwrap();
    catalog.refresh(&report_value).await.unwrap();
    let admin = SessionImportAdminService::new(writer.clone(), Arc::clone(&report), CONFIG);
    admin
        .handle(
            RequestId::new_v7(),
            purge_session,
            SessionImportAdminAction::QueueImport,
            observed_at_us + 4,
        )
        .await
        .unwrap();
    for _ in 0..4 {
        if worker
            .process_checkpoint(
                &purge_source,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
                },
            )
            .await
            .unwrap()
            .completed
        {
            break;
        }
    }
    let final_snapshot = writer.project().await.unwrap();
    let final_receipt = final_snapshot
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SourceReceiptRecorded(value)
                    if value.observation_role == ObservationRole::Message
                        && value.source_instance_id.as_str() == purge_source =>
                {
                    Some(value)
                }
                _ => None,
            }
        })
        .next()
        .unwrap();
    replacement_application.progress_delta[0].direct_refs =
        vec![final_receipt.source_observation_id.to_string()];
    assert_eq!(final_receipt.repository_instance_id, Some(repository));
    assert!(final_receipt.worktree_instance_id.is_some());
    let (purged_stub, release) =
        ProviderStub::once_paused(200, response(&replacement_application)).await;
    let purging = BackgroundScheduler::new(
        writer.clone(),
        catalog,
        worker,
        Arc::clone(&report),
        runtime(temp.path()),
        SynthesisPlanner::new(LlmConfig {
            base_url: ValidatedBaseUrl::parse(&purged_stub.base_url).unwrap(),
            ..llm
        }),
        dreaming,
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let running = tokio::spawn({
        let scheduler = purging.clone();
        async move { Box::pin(scheduler.run_once()).await }
    });
    tokio::time::timeout(Duration::from_secs(5), purged_stub.wait_received())
        .await
        .unwrap();
    let claimed = writer.project().await.unwrap();
    let current =
        evertrace_store::repository::RepositoryCurrentView::from_snapshot(&claimed).unwrap();
    let preview = evertrace_store::projections::repository_scope_purge_preview(
        &claimed,
        repository,
        current.repositories[&repository].repository_revision,
    )
    .unwrap();
    assert!(preview.blockers.is_empty());
    let command = evertrace_engine::purge::pending_repository_purge_command(
        RequestId::new_v7(),
        &preview,
        preview.deletion_generation,
        observed_at_us + 5,
        claimed.frontier,
        CONFIG,
    )
    .unwrap();
    assert!(command.events().iter().any(|event|matches!(&event.payload,JournalPayload::JobState(job) if job.kind=="semantic_synthesis_v1" && job.state==JobStatus::Failed)));
    writer
        .commit_if_frontier(command, observed_at_us + 5, claimed.frontier)
        .await
        .unwrap();
    let pending = writer.project().await.expect("purge pending projection");
    evertrace_store::RuntimeSchedulerView::from_snapshot(&pending).expect("purge pending jobs");
    release.send(()).unwrap();
    running.await.unwrap().unwrap();
    purged_stub.finish().await;
    assert_eq!(
        writer
            .project()
            .await
            .unwrap()
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("semantic_digest"))
            .count(),
        0
    );
    assert!(
        read(
            &mcp,
            &bindings,
            &report_value,
            &workspace,
            session,
            evertrace_engine::McpServiceAction::Get,
            old_id.clone()
        )
        .await
        .items
        .is_empty()
    );
    drop((quiet, purging, mcp, admin));
    writer.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let (writer, task) = spawn_writer(open_writer(&data).await.unwrap(), 32).unwrap();
    let mcp = evertrace_engine::McpActionService::open(
        bindings.clone(),
        &data,
        writer.clone(),
        runtime(temp.path()),
    )
    .await
    .unwrap()
    .with_session_report(Arc::clone(&report));
    assert!(
        read(
            &mcp,
            &bindings,
            &report_value,
            &workspace,
            session,
            evertrace_engine::McpServiceAction::Search,
            "marigold".into()
        )
        .await
        .items
        .is_empty()
    );
    assert!(
        !evertrace_store::RuntimeSchedulerView::from_snapshot(&writer.project().await.unwrap())
            .unwrap()
            .jobs
            .iter()
            .any(|job| job.kind == "semantic_synthesis_v1"
                && matches!(job.state, JobStatus::Queued | JobStatus::Leased))
    );
    drop(mcp);
    writer.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    }).await.unwrap();
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
    let revoked = worker.process_checkpoint(&source, budget).await.unwrap();
    assert_eq!(
        (revoked.records, revoked.bytes, revoked.completed),
        (0, 0, false)
    );
    assert!(worker.process_checkpoint(&source, budget).await.is_err());
    let after = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.current, after.current);
    assert_eq!(before.watermark, after.watermark);
    assert!(after.read_repositories.iter().any(|value| {
        value.repository_id == repository
            && value
                .capability_state
                .as_ref()
                .is_some_and(|state| state.trust_revoked)
    }));
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
    let repository_revision = after
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
    let revoked = worker
        .process_checkpoint(&sources[1], budget)
        .await
        .unwrap();
    assert_eq!(
        (revoked.records, revoked.bytes, revoked.completed),
        (0, 0, false)
    );
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
    // A read quantum may yield after either remaining record. Keep the real
    // 250 ms bound and require progress, rather than assume fixed throughput.
    let mut moved_records = 0;
    let mut moved_completed = false;
    for _ in 0..3 {
        let complete = worker
            .process_checkpoint(
                &source_b,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: (2_usize - moved_records).max(1),
                    max_work_time: Duration::from_millis(250),
                },
            )
            .await
            .unwrap();
        assert!(complete.records > 0 || complete.completed);
        moved_records += complete.records;
        assert!(moved_records <= 2);
        if complete.completed {
            moved_completed = true;
            break;
        }
    }
    assert!(moved_completed);
    assert_eq!(moved_records, 2);
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
