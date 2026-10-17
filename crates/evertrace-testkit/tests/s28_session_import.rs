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
    CurrentFacts, JobStatus, JournalPayload, JournalWriter, RuntimeSchedulerView,
    SemanticCurrentView, SessionBodyState, SessionImportCurrentView,
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
    Box::pin(imported_messages_scenario(
        true,
        false,
        Some(InflightInterruption::Revoke),
        false,
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imported_method_inflight_repository_purge_discards_result() {
    Box::pin(imported_messages_scenario(
        true,
        false,
        Some(InflightInterruption::Purge),
        false,
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imported_method_inflight_shutdown_drains_without_success() {
    Box::pin(imported_messages_scenario(
        true,
        false,
        Some(InflightInterruption::Shutdown),
        false,
    ))
    .await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InflightInterruption {
    Revoke,
    Purge,
    Shutdown,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imported_method_independent_append_remains_live_after_first_proposal() {
    Box::pin(imported_messages_scenario(true, false, None, true)).await;
}

async fn imported_messages_scenario(
    method: bool,
    terminal: bool,
    interruption: Option<InflightInterruption>,
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
        let mcp = mcp.clone();
        let connection = format!("source-summary-read:{}", workspace.display());
        let request = evertrace_engine::McpServiceRequest {
            request_id: RequestId::new_v7(),
            action,
            workspace: grant.bound_workspace,
            input,
            refs: vec![],
            client_cwd: workspace.to_str().unwrap().into(),
        };
        // Poll request dispatch outside the large scenario's nested debug
        // future frames, as the daemon does for a request task.
        tokio::spawn(async move { mcp.handle(&connection, request).await })
            .await
            .unwrap()
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
    drop(snapshot);
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
            if interruption == Some(InflightInterruption::Shutdown) {
                // Shutdown drives scheduler.run, a separate lifecycle from run_once.
                Box::pin(async move {
                let (_wake, wake) = tokio::sync::watch::channel(0);
                let (stop, stopping) = tokio::sync::watch::channel(false);
                let running = tokio::spawn(scheduler.clone().run(wake, stopping));
                tokio::time::timeout(Duration::from_secs(10), stub.wait_received()).await.unwrap();
                stop.send(true).unwrap();
                tokio::time::timeout(Duration::from_secs(2), running).await.unwrap().unwrap().unwrap();
                release.send(()).unwrap();
                stub.finish().await;
                let current = writer.project().await.unwrap();
                assert!(SemanticCurrentView::from_snapshot(&current).unwrap().proposals.is_empty());
                assert!(evertrace_store::RuntimeSchedulerView::from_snapshot(&current).unwrap().jobs.iter()
                    .any(|job| job.kind == "procedure_review_v1" && job.state == JobStatus::Leased && job.terminal.is_none()));
                drop(current);
                drop(scheduler); drop(worker); drop(admin); drop(catalog);
                writer.shutdown().await.unwrap();
                task.await.unwrap().unwrap();
                }).await;
                return;
            }
            let mut running = Box::pin(scheduler.run_once());
            tokio::select! {
                _ = stub.wait_received() => {},
                result = &mut running => panic!("producer finished before provider gate: {result:?}"),
            }
            if interruption == Some(InflightInterruption::Purge) {
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
                let running = runner.clone();
                tokio::spawn(async move { running.run_once().await })
                    .await
                    .unwrap()
                    .unwrap();
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
    drop(failed_snapshot);
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
    drop(snapshot);
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
    let human = evertrace_engine::HumanGovernanceService::new(writer.clone(), CONFIG)
        .with_session_report(Arc::clone(&report));
    let memories = human
        .list_selected(
            evertrace_engine::HumanSurface::Explorer,
            None,
            None,
            64,
            Some(evertrace_engine::HumanExplorerListSelection::Memories),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        memories
            .items
            .iter()
            .any(|item| item.object_kind == "semantic_digest"
                && item.object_ref == Some(digest.semantic_digest_id.to_string()))
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
        for caller_cwd in [workspace.as_path(), temp.path()] {
            let result = read(
                &mcp,
                &bindings,
                &report_value,
                caller_cwd,
                session,
                action,
                input.clone(),
            )
            .await;
            if caller_cwd == temp.path() {
                assert_eq!(result.scope, "explicit_work_evidence");
            }
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
    drop(final_snapshot);
    // Normal append keeps the logical revision and advances only the new
    // imported message interval. Disabling the LLM does not hide old memory.
    let body = fs::read_to_string(&transcript).unwrap();
    let raw_delta = serde_json::json!({"type":"response_item","metadata":{},"payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"marigold appended claim"}],"phase":"final_answer"}});
    let delta = serde_json::json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":session,"turn_id":"turn","item":{"type":"AgentMessage","id":"agent-1","content":[{"type":"Text","text":"marigold appended claim"}],"phase":"final_answer","memory_citation":{"entries":[{"path":"notes.md","lineStart":1,"lineEnd":2,"note":"source claim"}],"rolloutIds":["prior-rollout"]},"delivery":"async","questions":[{"title":"Continue?","options":["yes","no"]}]},"started_at_ms":1788998401000i64,"completed_at_ms":1788998402000i64}});
    fs::write(&transcript, format!("{body}{raw_delta}\n")).unwrap();
    catalog.refresh(&report_value).await.unwrap();
    let refreshed = writer.project().await.unwrap();
    let refreshed_current = SessionImportCurrentView::from_snapshot(&refreshed).unwrap();
    let refreshed_source = &refreshed_current.sessions[&source];
    assert_eq!(refreshed_source.body_state, SessionBodyState::Queued);
    assert_eq!(
        refreshed_source.metadata.file_size,
        fs::metadata(&transcript).unwrap().len()
    );
    drop(refreshed);
    {
        use std::io::Write as _;
        let mut transcript_file = fs::OpenOptions::new()
            .append(true)
            .open(&transcript)
            .unwrap();
        writeln!(transcript_file, "{delta}").unwrap();
    }
    let frontier_before_stale_read = writer.project().await.unwrap().frontier;
    assert!(matches!(
        worker
            .process_checkpoint(
                &source,
                SessionImportBudget {
                    max_bytes: 64 * 1024,
                    max_records: 16,
                    max_work_time: Duration::from_millis(250),
                },
            )
            .await,
        Err(evertrace_engine::SessionImportError::Unavailable)
    ));
    assert_eq!(
        writer.project().await.unwrap().frontier,
        frontier_before_stale_read
    );
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
    drop(appended);
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
    // A real new message during the provider wait must neither enter the
    // already-sent interval nor invalidate it; its later delta stays live.
    let body = fs::read_to_string(&transcript).unwrap();
    let new_message = serde_json::json!({"type":"event_msg","payload":{"type":"user_message","message":"marigold next independent message"}});
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
            "{body}{new_message}\n{}\n",
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
    assert_eq!(second_input["to_watermark"], second.source_sequence);
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
    // Keep this added lifecycle phase off the shared scenario's debug poll stack.
    Box::pin(async {
    let third = writer.project().await.unwrap().data_rows().filter_map(|row| {
        match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
            JournalPayload::SourceReceiptRecorded(value) if value.observation_role == ObservationRole::Message
                && value.source_sequence > second.source_sequence => Some(value),
            _ => None,
        }
    }).next().unwrap();
    let mut third_application = application.clone();
    third_application.progress_delta[0].direct_refs = vec![third.source_observation_id.to_string()];
    third_application.progress_delta[0].value = "marigold next independent message".into();
    let third_stub = ProviderStub::once(200, serde_json::to_vec(&serde_json::json!({"choices":[{"message":{"content":serde_json::to_string(&third_application).unwrap()}}],"usage":{"prompt_tokens":17,"completion_tokens":5}})).unwrap()).await;
    let third_scheduler = BackgroundScheduler::new(writer.clone(), catalog.clone(), worker.clone(), Arc::clone(&report), runtime(temp.path()),
        SynthesisPlanner::new(LlmConfig { base_url: ValidatedBaseUrl::parse(&third_stub.base_url).unwrap(), ..llm.clone() }), dreaming.clone());
    tokio::time::sleep(Duration::from_secs(1)).await;
    Box::pin(third_scheduler.run_once()).await.unwrap();
    third_stub.finish().await;
    let successful = writer.project().await.unwrap().data_rows().filter_map(|row| {
        match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
            JournalPayload::SemanticDigestRecorded(value) => Some(value),
            _ => None,
        }
    }).collect::<Vec<_>>();
    assert_eq!(successful.len(), 3);
    assert_eq!(successful.iter().filter(|value| value.to_watermark == second.source_sequence).count(), 1);
    assert!(successful.iter().any(|value| value.selected_direct_refs == vec![third.source_observation_id.to_string()]));
    drop(third_scheduler);
    }).await;
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
        3
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
    // The finite passive consumer must retain the same lawful old archive
    // after source replacement; current catalog revision is not an access gate.
    let passive_old = read(&mcp, &bindings, &report_value, temp.path(), session,
        evertrace_engine::McpServiceAction::Get, old_id.clone()).await;
    assert_eq!(passive_old.scope, "explicit_work_evidence");
    assert!(passive_old.items.iter().any(|item| item.object_ref.as_deref() == Some(&old_id)));
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
    let current = CurrentFacts::try_from(rewritten_snapshot.clone()).unwrap();
    assert!(
        Box::pin(SynthesisPlanner::new(llm.clone())
            .execute(evertrace_engine::jobs::SynthesisRequest {
                current: &current,
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
        3
    );
    for (action, input) in [
        (evertrace_engine::McpServiceAction::Get, old_id.clone()),
        (
            evertrace_engine::McpServiceAction::Search,
            "marigold".into(),
        ),
    ] {
        for caller_cwd in [workspace.as_path(), temp.path()] {
        assert!(
            read(
                &mcp,
                &bindings,
                &report_value,
                caller_cwd,
                session,
                action,
                input.clone()
            )
            .await
            .items
            .is_empty()
        );
        }
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
    let human = evertrace_engine::HumanGovernanceService::new(writer.clone(), CONFIG)
        .with_session_report(Arc::clone(&report));
    let mut expected = Vec::new();
    let mut cursor = None;
    loop {
        let page = human.list(evertrace_engine::HumanSurface::Explorer, Some(pending.frontier), cursor.as_deref(), 64)
            .await.unwrap().unwrap();
        expected.extend(page.items.into_iter().filter(|item| matches!(item.object_kind.as_str(),
            "semantic_digest" | "atom_revision" | "procedure_revision" | "core_membership" | "revision_proposal_revision")));
        cursor = page.next_cursor;
        if cursor.is_none() { break; }
    }
    let mut actual = Vec::new();
    loop {
        let page = human.list_selected(evertrace_engine::HumanSurface::Explorer, Some(pending.frontier), cursor.as_deref(), 64,
            Some(evertrace_engine::HumanExplorerListSelection::Memories)).await.unwrap().unwrap();
        actual.extend(page.items);
        cursor = page.next_cursor;
        if cursor.is_none() { break; }
    }
    assert_eq!(actual, expected);
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
    assert_eq!(reopened.table_names().await.unwrap(), ["evertrace_search"]);
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
    row.payload_json = Some(
        serde_json::to_string(&JournalPayload::SourceReceiptRecorded(receipt))
            .unwrap()
            .into(),
    );
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
    let catalog_context = handle.session_catalog_current_context().await.unwrap();
    let catalog_snapshot = handle.project().await.unwrap();
    assert_eq!(catalog_context.frontier, catalog_snapshot.frontier);
    assert_eq!(
        catalog_context.repositories,
        evertrace_store::repository::RepositoryCurrentView::from_snapshot(&catalog_snapshot)
            .unwrap()
    );
    assert_eq!(
        catalog_context.sessions,
        SessionImportCurrentView::from_snapshot(&catalog_snapshot).unwrap()
    );
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
    // Public readability below the private TempDir ancestor is a valid
    // read-only Host source. Make the root group/other writable instead so
    // the negative checkpoint exercises an actual unsafe-identity revocation.
    fs::set_permissions(&adapter, fs::Permissions::from_mode(0o777)).unwrap();
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
    assert_eq!(reopened.table_names().await.unwrap(), ["evertrace_search"]);
}

/// The source-start boundary factory is exactly the input the catalog
/// resolution consumes: with one ordinary registration already durable, a
/// second source stays `Repository`-resolved at its own start instant with the
/// expected IDs and read scope, while sources without that durable closure
/// (wrong source, wrong instant) never receive a resolved scope.
#[derive(Clone)]
struct DualProofMutationFixture {
    writer: evertrace_engine::WriterHandle,
    report: Arc<RwLock<Option<evertrace_codex::HostProbeReport>>>,
    worker: SessionImportWorker,
    configured_runtime: RuntimeSnapshot,
    revoke_session: String,
    revoke_source: String,
    revoke_transcript: std::path::PathBuf,
    workspace: std::path::PathBuf,
    replacement_head: String,
}

async fn prefix_mutation_phase(fixture: DualProofMutationFixture) {
    let DualProofMutationFixture {
        writer,
        report,
        worker,
        configured_runtime,
        revoke_session,
        revoke_source,
        revoke_transcript,
        workspace,
        replacement_head,
    } = fixture;
    use std::io::Write as _;
    let catalog = SessionCatalogService::new(writer.clone(), CONFIG);
    let admin = SessionImportAdminService::new(writer.clone(), Arc::clone(&report), CONFIG);
    let revoke_session = revoke_session.as_str();

    // Reuse this already trusted native source for two independent physical
    // rewrite continuations. Each starts from durable receipts in both legs;
    // the body work left pending after the rewrite is in the opposite leg.
    let mutation_line = |id: &str, text: &str| {
        serde_json::json!({
        "timestamp":"2026-10-06T00:08:00Z",
        "type":"event_msg",
        "payload":{"type":"item_completed","thread_id":revoke_session,"turn_id":id,"item":{"type":"UserMessage","id":id,"content":[{"type":"text","text":text,"text_elements":[]}]},"completed_at_ms":1_791_245_280_000_i64}
    })
    .to_string()
    };
    let mutation_header = serde_json::json!({
    "timestamp":"2026-10-06T00:08:00Z",
    "type":"session_meta",
    "payload":{"id":revoke_session,"session_id":revoke_session,"cwd":workspace,"git":{"commit_hash":replacement_head}}
})
.to_string();
    let prefix_lines = [
        mutation_line("dual-prefix-one", "prefix-marker-A stays historical"),
        mutation_line("dual-prefix-two", "second historical chain record"),
        mutation_line("dual-prefix-three", "third historical chain record"),
    ];
    let prefix_body = format!("{mutation_header}\n{}\n", prefix_lines.join("\n"));
    fs::write(&revoke_transcript, &prefix_body).unwrap();
    let mutation_catalog_report = observe_session_catalog_report(
        revoke_transcript.to_str(),
        revoke_session,
        "source-start-dual-proof-prefix-replacement",
        None,
    )
    .unwrap();
    catalog.refresh(&mutation_catalog_report).await.unwrap();
    let mutation_request = RequestId::new_v7();
    let mutation_reference = format!("native_session_source_observation:{mutation_request}");
    let mutation_start_report = evertrace_engine::repository::observe_session_source_report(
        revoke_transcript.to_str().unwrap(),
        revoke_session,
        None,
        &mutation_reference,
    )
    .unwrap();
    assert!(
        catalog
            .observe_native_session_source(
                mutation_request,
                &mutation_start_report,
                revoke_session,
                revoke_transcript.to_str().unwrap(),
                &mutation_reference,
            )
            .await
            .unwrap()
    );
    *report.write().await = Some(mutation_start_report.clone());
    let prefix_observed = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        prefix_observed.current.body_state,
        SessionBodyState::NotImported | SessionBodyState::SourceReplaced
    ));
    assert!(prefix_observed.current.access_decision.is_none());
    assert!(
        prefix_observed
            .current
            .metadata
            .prospective_origin
            .is_some()
    );
    let mutation_fence = prefix_observed
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .unwrap()
        .record_start
        .unwrap();
    assert_eq!(mutation_fence, prefix_body.len() as u64);
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                revoke_session,
                SessionImportAdminAction::QueueImport,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_micros() as i64,
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );

    let prefix_suffix_lines = (0..8)
        .map(|index| {
            mutation_line(
                &format!("dual-prefix-suffix-{index}"),
                &format!("suffix backlog remains after prefix completion {index}"),
            )
        })
        .collect::<Vec<_>>();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&revoke_transcript)
        .unwrap();
    for line in &prefix_suffix_lines {
        writeln!(file, "{line}").unwrap();
    }
    file.write_all(b"{\"type\":\"unfinished-suffix-tail")
        .unwrap();
    drop(file);
    catalog.refresh(&mutation_start_report).await.unwrap();
    let prefix_revision = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap()
        .current
        .metadata
        .source_revision
        .clone();
    let prefix_full_suffix_end = fs::metadata(&revoke_transcript).unwrap().len()
        - b"{\"type\":\"unfinished-suffix-tail".len() as u64;
    let mutation_budget = SessionImportBudget {
        max_bytes: 64 * 1024,
        max_records: 1,
        max_work_time: Duration::from_millis(250),
    };
    let mut both_prefix_and_suffix_progress = false;
    for _ in 0..64 {
        let context = writer
            .session_import_context(&revoke_source)
            .await
            .unwrap()
            .unwrap();
        let watermark = context.watermark.as_ref();
        let earlier_end = watermark
            .and_then(|value| value.earlier_prefix.as_ref())
            .map_or(0, |prefix| prefix.through_byte);
        let suffix_end = watermark.map_or(mutation_fence, |value| {
            if value.confirmed_prefix_digest.is_some() {
                value.source_sequence
            } else {
                mutation_fence
            }
        });
        if earlier_end == mutation_fence
            && suffix_end > mutation_fence
            && suffix_end < prefix_full_suffix_end
        {
            both_prefix_and_suffix_progress = true;
            break;
        }
        let progress = worker
            .process_checkpoint(&revoke_source, mutation_budget)
            .await
            .unwrap();
        assert!(
            !progress.completed,
            "the unfinished suffix tail must keep the job Partial"
        );
        assert!(progress.records <= 1);
    }
    assert!(
        both_prefix_and_suffix_progress,
        "older H must drain while E keeps a nonempty backlog and incomplete tail"
    );
    let prefix_proven = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap();
    let prefix_watermark = prefix_proven.watermark.clone().unwrap();
    assert_eq!(
        prefix_watermark
            .earlier_prefix
            .as_ref()
            .unwrap()
            .through_byte,
        mutation_fence
    );
    assert!(prefix_watermark.source_sequence < prefix_full_suffix_end);
    assert_eq!(prefix_proven.job.as_ref().unwrap().state, JobStatus::Queued);
    assert!(prefix_proven.job.as_ref().unwrap().terminal.is_none());
    let prefix_page = writer
        .session_import_prefix_page(evertrace_store::SessionImportPrefixRequest {
            source: revoke_source.clone(),
            revision: prefix_revision.clone(),
            after: 0,
            end: mutation_fence,
            max_records: 16,
            max_bytes: 1024 * 1024,
        })
        .await
        .unwrap();
    let suffix_page = writer
        .session_import_prefix_page(evertrace_store::SessionImportPrefixRequest {
            source: revoke_source.clone(),
            revision: prefix_revision.clone(),
            after: mutation_fence,
            end: prefix_watermark.source_sequence,
            max_records: 16,
            max_bytes: 1024 * 1024,
        })
        .await
        .unwrap();
    assert_eq!(prefix_page.records.first().unwrap().start, 0);
    assert_eq!(prefix_page.records.last().unwrap().end, mutation_fence);
    assert_eq!(suffix_page.records.first().unwrap().start, mutation_fence);
    assert_eq!(
        suffix_page.records.last().unwrap().end,
        prefix_watermark.source_sequence
    );
    let cas =
        evertrace_capture::CasStore::open_existing(configured_runtime.cas_dir.clone()).unwrap();
    for record in prefix_page.records.iter().chain(&suffix_page.records) {
        let protected = cas
            .read(&evertrace_capture::CasStore::parse_digest(&record.cas_ref).unwrap())
            .unwrap();
        assert_eq!(
            evertrace_capture::CasDigest::for_protected_bytes(&protected).as_hex(),
            record.cas_ref
        );
    }
    let prefix_receipts_before = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| {
            receipt.source_instance_id.as_str() == revoke_source
                && receipt.source_revision == prefix_revision
        })
        .map(|receipt| {
            (
                receipt.source_sequence,
                receipt.cas_ref,
                receipt.source_observation_id.to_string(),
            )
        })
        .collect::<Vec<_>>();
    let prefix_watermarks_before = writer
        .project()
        .await
        .unwrap()
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SourceIngestWatermark(watermark)
                    if watermark.source_instance_id.as_str() == revoke_source
                        && watermark.source_revision == prefix_revision =>
                {
                    Some(watermark)
                }
                _ => None,
            }
        })
        .collect::<Vec<_>>();

    let mut rewritten_prefix = fs::read_to_string(&revoke_transcript).unwrap();
    rewritten_prefix = rewritten_prefix.replacen("prefix-marker-A", "prefix-marker-B", 1);
    assert_eq!(
        rewritten_prefix.len(),
        fs::metadata(&revoke_transcript).unwrap().len() as usize
    );
    let rewritten_prefix = format!(
        "{}{}\n",
        rewritten_prefix.trim_end_matches("{\"type\":\"unfinished-suffix-tail"),
        mutation_line(
            "prefix-mutation-append",
            "append after the rewritten nonselected H chain"
        )
    );
    fs::write(&revoke_transcript, rewritten_prefix).unwrap();
    catalog.refresh(&mutation_start_report).await.unwrap();
    let mut rejected_prefix_mutation = None;
    for _ in 0..16 {
        match worker
            .process_checkpoint(&revoke_source, mutation_budget)
            .await
        {
            Ok(progress) => {
                assert_eq!(progress.records, 0, "proof-only work cannot add a receipt");
                assert!(!progress.completed);
            }
            Err(error) => {
                let detail = format!("{error:?}");
                assert!(
                    detail.contains("Changed"),
                    "unexpected fail-closed result: {detail}"
                );
                rejected_prefix_mutation = Some(detail);
                break;
            }
        }
    }
    assert!(
        rejected_prefix_mutation.is_some(),
        "the changed nonselected processed prefix must fail its real protected-chain proof"
    );
    let after_prefix_rewrite = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        after_prefix_rewrite.current.metadata.source_revision,
        prefix_revision
    );
    assert_eq!(
        after_prefix_rewrite.current.body_state,
        SessionBodyState::SourceReplaced
    );
    assert!(
        after_prefix_rewrite
            .current
            .metadata
            .prospective_origin
            .is_none()
    );
    assert!(after_prefix_rewrite.watermark.is_none());
    let prefix_receipts_after_worker = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| {
            receipt.source_instance_id.as_str() == revoke_source
                && receipt.source_revision == prefix_revision
        })
        .map(|receipt| {
            (
                receipt.source_sequence,
                receipt.cas_ref,
                receipt.source_observation_id.to_string(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(prefix_receipts_after_worker, prefix_receipts_before);
    let prefix_watermarks_after_worker = writer
        .project()
        .await
        .unwrap()
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SourceIngestWatermark(watermark)
                    if watermark.source_instance_id.as_str() == revoke_source
                        && watermark.source_revision == prefix_revision =>
                {
                    Some(watermark)
                }
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(prefix_watermarks_after_worker, prefix_watermarks_before);
}

async fn suffix_mutation_phase(fixture: DualProofMutationFixture) {
    let DualProofMutationFixture {
        writer,
        report,
        worker,
        configured_runtime,
        revoke_session,
        revoke_source,
        revoke_transcript,
        ..
    } = fixture;
    use std::io::Write as _;
    let catalog = SessionCatalogService::new(writer.clone(), CONFIG);
    let admin = SessionImportAdminService::new(writer.clone(), Arc::clone(&report), CONFIG);
    let revoke_session = revoke_session.as_str();
    let mutation_line = |id: &str, text: &str| {
        serde_json::json!({
            "timestamp":"2026-10-06T00:08:00Z",
            "type":"event_msg",
            "payload":{"type":"item_completed","thread_id":revoke_session,"turn_id":id,"item":{"type":"UserMessage","id":id,"content":[{"type":"text","text":text,"text_elements":[]}]},"completed_at_ms":1_791_245_280_000_i64}
        })
        .to_string()
    };
    let mutation_budget = SessionImportBudget {
        max_bytes: 64 * 1024,
        max_records: 1,
        max_work_time: Duration::from_millis(250),
    };
    let cas =
        evertrace_capture::CasStore::open_existing(configured_runtime.cas_dir.clone()).unwrap();
    let mutation_start_report = report
        .read()
        .await
        .clone()
        .expect("the current source report remains installed");

    // Reobserve the genuinely new revision. One prefix record and one suffix
    // record then create independent durable proof chains; suffix is the
    // nonselected processed leg while the older prefix still has body work.
    catalog.refresh(&mutation_start_report).await.unwrap();
    let suffix_mutation_request = RequestId::new_v7();
    let suffix_mutation_reference =
        format!("native_session_source_observation:{suffix_mutation_request}");
    let suffix_mutation_report = evertrace_engine::repository::observe_session_source_report(
        revoke_transcript.to_str().unwrap(),
        revoke_session,
        None,
        &suffix_mutation_reference,
    )
    .unwrap();
    assert!(
        catalog
            .observe_native_session_source(
                suffix_mutation_request,
                &suffix_mutation_report,
                revoke_session,
                revoke_transcript.to_str().unwrap(),
                &suffix_mutation_reference,
            )
            .await
            .unwrap()
    );
    *report.write().await = Some(suffix_mutation_report.clone());
    let suffix_mutation_observed = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        suffix_mutation_observed.current.body_state,
        SessionBodyState::SourceReplaced
    );
    assert!(suffix_mutation_observed.current.access_decision.is_none());
    let suffix_mutation_fence = suffix_mutation_observed
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .unwrap()
        .record_start
        .unwrap();
    assert_eq!(
        suffix_mutation_fence,
        fs::metadata(&revoke_transcript).unwrap().len()
    );
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                revoke_session,
                SessionImportAdminAction::QueueImport,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_micros() as i64,
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );
    let second_suffix_lines = [
        mutation_line("dual-suffix-one", "suffix-marker-A is already admitted"),
        mutation_line("dual-suffix-two", "second suffix remains pending"),
        mutation_line("dual-suffix-three", "third suffix remains pending"),
    ];
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&revoke_transcript)
        .unwrap();
    for line in &second_suffix_lines {
        writeln!(file, "{line}").unwrap();
    }
    file.write_all(b"{\"type\":\"unfinished-suffix-tail")
        .unwrap();
    drop(file);
    catalog.refresh(&suffix_mutation_report).await.unwrap();
    let suffix_revision = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap()
        .current
        .metadata
        .source_revision
        .clone();
    let prefix_turn = worker
        .process_checkpoint(&revoke_source, mutation_budget)
        .await
        .unwrap();
    assert_eq!(prefix_turn.records, 1);
    let suffix_turn = worker
        .process_checkpoint(&revoke_source, mutation_budget)
        .await
        .unwrap();
    assert_eq!(suffix_turn.records, 1);
    let suffix_proven = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap();
    let suffix_watermark = suffix_proven.watermark.clone().unwrap();
    let suffix_earlier = suffix_watermark.earlier_prefix.as_ref().unwrap();
    assert!(suffix_earlier.through_byte > 0 && suffix_earlier.through_byte < suffix_mutation_fence);
    assert!(suffix_watermark.source_sequence > suffix_mutation_fence);
    assert!(suffix_watermark.source_sequence < fs::metadata(&revoke_transcript).unwrap().len());
    let suffix_prefix_page = writer
        .session_import_prefix_page(evertrace_store::SessionImportPrefixRequest {
            source: revoke_source.clone(),
            revision: suffix_revision.clone(),
            after: 0,
            end: suffix_earlier.through_byte,
            max_records: 16,
            max_bytes: 1024 * 1024,
        })
        .await
        .unwrap();
    let suffix_records_page = writer
        .session_import_prefix_page(evertrace_store::SessionImportPrefixRequest {
            source: revoke_source.clone(),
            revision: suffix_revision.clone(),
            after: suffix_mutation_fence,
            end: suffix_watermark.source_sequence,
            max_records: 16,
            max_bytes: 1024 * 1024,
        })
        .await
        .unwrap();
    assert_eq!(
        suffix_prefix_page.records.last().unwrap().end,
        suffix_earlier.through_byte
    );
    assert_eq!(
        suffix_records_page.records.first().unwrap().start,
        suffix_mutation_fence
    );
    assert_eq!(
        suffix_records_page.records.last().unwrap().end,
        suffix_watermark.source_sequence
    );
    for record in suffix_prefix_page
        .records
        .iter()
        .chain(&suffix_records_page.records)
    {
        let protected = cas
            .read(&evertrace_capture::CasStore::parse_digest(&record.cas_ref).unwrap())
            .unwrap();
        assert_eq!(
            evertrace_capture::CasDigest::for_protected_bytes(&protected).as_hex(),
            record.cas_ref
        );
    }
    let suffix_receipts_before = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| {
            receipt.source_instance_id.as_str() == revoke_source
                && receipt.source_revision == suffix_revision
        })
        .map(|receipt| {
            (
                receipt.source_sequence,
                receipt.cas_ref,
                receipt.source_observation_id.to_string(),
            )
        })
        .collect::<Vec<_>>();
    let suffix_watermarks_before = writer
        .project()
        .await
        .unwrap()
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SourceIngestWatermark(watermark)
                    if watermark.source_instance_id.as_str() == revoke_source
                        && watermark.source_revision == suffix_revision =>
                {
                    Some(watermark)
                }
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    let mut rewritten_suffix = fs::read_to_string(&revoke_transcript).unwrap();
    rewritten_suffix = rewritten_suffix.replacen("suffix-marker-A", "suffix-marker-B", 1);
    assert_eq!(
        rewritten_suffix.len(),
        fs::metadata(&revoke_transcript).unwrap().len() as usize
    );
    let rewritten_suffix = format!(
        "{}{}\n",
        rewritten_suffix.trim_end_matches("{\"type\":\"unfinished-suffix-tail"),
        mutation_line(
            "suffix-mutation-append",
            "append after the rewritten nonselected E chain"
        )
    );
    fs::write(&revoke_transcript, rewritten_suffix).unwrap();
    catalog.refresh(&suffix_mutation_report).await.unwrap();
    let mut rejected_suffix_mutation = None;
    for _ in 0..16 {
        match worker
            .process_checkpoint(&revoke_source, mutation_budget)
            .await
        {
            Ok(progress) => {
                assert_eq!(progress.records, 0, "proof-only work cannot add a receipt");
                assert!(!progress.completed);
            }
            Err(error) => {
                let detail = format!("{error:?}");
                assert!(
                    detail.contains("Changed"),
                    "unexpected fail-closed result: {detail}"
                );
                rejected_suffix_mutation = Some(detail);
                break;
            }
        }
    }
    assert!(
        rejected_suffix_mutation.is_some(),
        "the changed nonselected processed suffix must fail its real protected-chain proof"
    );
    let after_suffix_rewrite = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        after_suffix_rewrite.current.metadata.source_revision,
        suffix_revision
    );
    assert_eq!(
        after_suffix_rewrite.current.body_state,
        SessionBodyState::SourceReplaced
    );
    assert!(
        after_suffix_rewrite
            .current
            .metadata
            .prospective_origin
            .is_none()
    );
    assert!(after_suffix_rewrite.watermark.is_none());
    let suffix_receipts_after = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| {
            receipt.source_instance_id.as_str() == revoke_source
                && receipt.source_revision == suffix_revision
        })
        .map(|receipt| {
            (
                receipt.source_sequence,
                receipt.cas_ref,
                receipt.source_observation_id.to_string(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(suffix_receipts_after, suffix_receipts_before);
    let suffix_watermarks_after = writer
        .project()
        .await
        .unwrap()
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SourceIngestWatermark(watermark)
                    if watermark.source_instance_id.as_str() == revoke_source
                        && watermark.source_revision == suffix_revision =>
                {
                    Some(watermark)
                }
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(suffix_watermarks_after, suffix_watermarks_before);
}

fn dual_proof_mutation_phases(
    fixture: DualProofMutationFixture,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move {
        prefix_mutation_phase(fixture.clone()).await;
        suffix_mutation_phase(fixture).await;
    })
}

struct SourceStartFixture {
    temp: TempDir,
    workspace: std::path::PathBuf,
    dated: std::path::PathBuf,
    writer: evertrace_engine::WriterHandle,
    task: evertrace_engine::WriterTask,
    repository: evertrace_domain::ids::RepositoryId,
    worktree: evertrace_domain::ids::WorktreeId,
    cases: [(&'static str, &'static str, bool); 3],
}

fn source_fixture_git(dir: &std::path::Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn projected_source_receipts(
    snapshot: &evertrace_store::ProjectionSnapshot,
) -> impl Iterator<Item = Box<evertrace_domain::evidence::SourceReceipt>> + '_ {
    snapshot.data_rows().filter_map(|row| {
        match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
            JournalPayload::SourceReceiptRecorded(receipt) => Some(receipt),
            _ => None,
        }
    })
}

async fn source_start_fixture() -> SourceStartFixture {
    use evertrace_engine::repository::{
        HostTrustDecision, ProbeLimits, RepositoryResolveInput, ResolutionKind, probe_repository,
        resolve_repository, resolve_repository_source_start,
    };
    use evertrace_store::{WorkspaceResolutionKind, repository::RepositoryCurrentView};

    fn write_transcript(
        path: &std::path::Path,
        session: &str,
        stamp: &str,
        workspace: &std::path::Path,
        head: &str,
    ) {
        let header = serde_json::json!({"timestamp":stamp,"type":"session_meta","payload":{"id":session,"session_id":session,"cwd":workspace,"git":{"commit_hash":head}}});
        let raw = serde_json::json!({"type":"response_item","metadata":{"client_authored":false,"fallback_token_limit_override":8192},"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"marigold source start boundary"}]}});
        let message = serde_json::json!({"timestamp":stamp,"type":"event_msg","payload":{"type":"item_completed","thread_id":session,"turn_id":"turn","item":{"type":"UserMessage","id":"user-1","content":[{"type":"text","text":"marigold source start boundary","text_elements":[]}]},"completed_at_ms":1791244801000i64}});
        fs::write(path, format!("{header}\n{raw}\n{message}\n")).unwrap();
    }

    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    source_fixture_git(&workspace, &["init", "-q", "-b", "main"]);
    source_fixture_git(&workspace, &["commit", "--allow-empty", "-qm", "initial"]);
    let workspace = fs::canonicalize(workspace).unwrap();
    let head = source_fixture_git(&workspace, &["rev-parse", "HEAD"]);
    let adapter = temp.path().join("adapter");
    let dated = adapter.join("sessions/2026/10/06");
    fs::create_dir_all(&dated).unwrap();
    fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&dated, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        adapter.join("config.toml"),
        format!(
            "[projects.{}]\ntrust_level = \"trusted\"\n",
            serde_json::to_string(workspace.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    let (writer, task) =
        spawn_writer(open_writer(&temp.path().join("data")).await.unwrap(), 32).unwrap();

    let at = 1_791_244_801_000_000;
    let start = "2026-10-06T00:00:01Z";
    let cases = [
        ("019d0000-0000-7000-8000-0000000000a1", start, true),
        ("019d0000-0000-7000-8000-0000000000a2", start, false),
        (
            "019d0000-0000-7000-8000-0000000000a3",
            "2026-10-06T00:01:01Z",
            false,
        ),
    ];
    let evidence = probe_repository(
        &workspace,
        HostTrustDecision::Trusted,
        &["register:source-start".into()],
        at - 1_000_000,
        &ProbeLimits::default(),
        &[],
        &[],
    )
    .unwrap();
    let registration = resolve_repository(&RepositoryResolveInput {
        view: &RepositoryCurrentView::default(),
        evidence: &evidence,
        derived_from_hint: None,
    })
    .unwrap();
    assert_eq!(registration.kind, Some(ResolutionKind::Create));
    let repository = registration.repositories[0].repository_id;
    let worktree = registration.worktrees[0].worktree_instance_id;
    writer
        .commit(
            registration
                .journal_command(at - 1_000_000, CONFIG, "source-attribution")
                .unwrap()
                .unwrap(),
            at - 1_000_000,
        )
        .await
        .unwrap();

    for index in [0, 2] {
        let session = cases[index].0;
        let source = format!("session-rollout:{session}:{session}");
        let projected = writer.project().await.unwrap();
        let current = RepositoryCurrentView::from_snapshot(&projected).unwrap();
        let evidence = probe_repository(
            &workspace,
            HostTrustDecision::Trusted,
            std::slice::from_ref(&source),
            at,
            &ProbeLimits::default(),
            &current.known_admin_paths(),
            &[],
        )
        .unwrap();
        let boundary = resolve_repository_source_start(
            &RepositoryResolveInput {
                view: &current,
                evidence: &evidence,
                derived_from_hint: None,
            },
            &source,
        )
        .unwrap();
        assert_eq!(boundary.kind, Some(ResolutionKind::Successor));
        writer
            .commit_if_frontier(
                boundary
                    .journal_command(at, CONFIG, "source-start-boundary")
                    .unwrap()
                    .unwrap(),
                at,
                current.frontier,
            )
            .await
            .unwrap();
    }
    let catalog = SessionCatalogService::new(writer.clone(), CONFIG);
    for (session, stamp, resolved) in cases {
        let source = format!("session-rollout:{session}:{session}");
        let transcript = dated.join(format!("rollout-2026-10-06T00-00-01-{session}.jsonl"));
        write_transcript(&transcript, session, stamp, &workspace, &head);
        let report =
            observe_session_catalog_report(transcript.to_str(), session, "source-summary", None)
                .unwrap();
        catalog.refresh(&report).await.unwrap();
        let context = writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap();
        let metadata = &context.current.metadata;
        if resolved {
            assert_eq!(
                metadata.workspace_resolution_kind,
                WorkspaceResolutionKind::Repository
            );
            assert_eq!(metadata.resolved_repository_instance_id, Some(repository));
            assert_eq!(metadata.resolved_worktree_instance_id, Some(worktree));
            assert!(metadata.read_restrictions().any(|id| id == repository));
            assert!(
                context
                    .read_repositories
                    .iter()
                    .any(|value| value.repository_id == repository)
            );
            let current_snapshot = context
                .worktree
                .as_ref()
                .unwrap()
                .current_snapshot_id
                .unwrap();
            assert!(context.read_snapshots.iter().any(|snapshot| {
                snapshot.worktree_instance_id == worktree
                    && snapshot.worktree_snapshot_id == current_snapshot
            }));
            let durable =
                RepositoryCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
            assert!(durable.snapshots.values().any(|snapshot| {
                snapshot.worktree_instance_id == worktree
                    && snapshot.captured_at_us == at
                    && snapshot.evidence_refs.contains(&source)
            }));
        } else {
            assert_eq!(
                metadata.workspace_resolution_kind,
                WorkspaceResolutionKind::Ambiguous
            );
            assert!(metadata.resolved_repository_instance_id.is_none());
            assert!(metadata.resolved_worktree_instance_id.is_none());
        }
    }
    drop(catalog);

    SourceStartFixture {
        temp,
        workspace,
        dated,
        writer,
        task,
        repository,
        worktree,
        cases,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dual_proofs_reject_mutation_of_each_nonselected_leg() {
    use evertrace_engine::repository::{
        HostTrustDecision, ProbeLimits, RepositoryResolveInput, probe_repository,
        resolve_repository, resolve_repository_source_start,
    };
    use evertrace_store::repository::RepositoryCurrentView;

    let git = source_fixture_git;

    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    git(&workspace, &["init", "-q", "-b", "main"]);
    git(&workspace, &["commit", "--allow-empty", "-qm", "initial"]);
    let workspace = fs::canonicalize(workspace).unwrap();
    let head = git(&workspace, &["rev-parse", "HEAD"]);

    let adapter = temp.path().join("adapter");
    let dated = adapter.join("sessions/2026/10/06");
    fs::create_dir_all(&dated).unwrap();
    fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&dated, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        adapter.join("config.toml"),
        format!(
            "[projects.{}]\ntrust_level = \"trusted\"\n",
            serde_json::to_string(workspace.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();

    let session = "019d0000-0000-7000-8000-0000000000a1";
    let source = format!("session-rollout:{session}:{session}");
    let transcript = dated.join(format!("rollout-2026-10-06T00-00-01-{session}.jsonl"));
    let start = "2026-10-06T00:00:01Z";
    let header = serde_json::json!({
        "timestamp": start,
        "type": "session_meta",
        "payload": {"id": session, "session_id": session, "cwd": workspace, "git": {"commit_hash": head}}
    });
    let initial_message = serde_json::json!({
        "timestamp": start,
        "type": "event_msg",
        "payload": {
            "type": "item_completed",
            "thread_id": session,
            "turn_id": "initial-dual-proof-record",
            "item": {"type": "UserMessage", "id": "initial-dual-proof-record", "content": [{"type": "text", "text": "initial historical evidence", "text_elements": []}]},
            "completed_at_ms": 1_791_244_801_000_i64
        }
    });
    fs::write(&transcript, format!("{header}\n{initial_message}\n")).unwrap();

    let at = 1_791_244_801_000_000;
    let (writer, task) =
        spawn_writer(open_writer(&temp.path().join("data")).await.unwrap(), 32).unwrap();
    let initial_evidence = probe_repository(
        &workspace,
        HostTrustDecision::Trusted,
        &["register:dual-proof-source".into()],
        at - 1_000_000,
        &ProbeLimits::default(),
        &[],
        &[],
    )
    .unwrap();
    let registration = resolve_repository(&RepositoryResolveInput {
        view: &RepositoryCurrentView::default(),
        evidence: &initial_evidence,
        derived_from_hint: None,
    })
    .unwrap();
    let worktree = registration.worktrees[0].worktree_instance_id;
    writer
        .commit(
            registration
                .journal_command(at - 1_000_000, CONFIG, "dual-proof-registration")
                .unwrap()
                .unwrap(),
            at - 1_000_000,
        )
        .await
        .unwrap();
    let repository_view =
        RepositoryCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let source_evidence = probe_repository(
        &workspace,
        HostTrustDecision::Trusted,
        std::slice::from_ref(&source),
        at,
        &ProbeLimits::default(),
        &repository_view.known_admin_paths(),
        &[],
    )
    .unwrap();
    let source_start = resolve_repository_source_start(
        &RepositoryResolveInput {
            view: &repository_view,
            evidence: &source_evidence,
            derived_from_hint: None,
        },
        &source,
    )
    .unwrap();
    writer
        .commit_if_frontier(
            source_start
                .journal_command(at, CONFIG, "dual-proof-source-start")
                .unwrap()
                .unwrap(),
            at,
            repository_view.frontier,
        )
        .await
        .unwrap();

    let catalog = SessionCatalogService::new(writer.clone(), CONFIG);
    let initial_catalog_report = observe_session_catalog_report(
        transcript.to_str(),
        session,
        "dual-proof-initial-source",
        None,
    )
    .unwrap();
    catalog.refresh(&initial_catalog_report).await.unwrap();
    let initial_request = RequestId::new_v7();
    let initial_reference = format!("native_session_source_observation:{initial_request}");
    let report = evertrace_engine::repository::observe_session_source_report(
        transcript.to_str().unwrap(),
        session,
        None,
        &initial_reference,
    )
    .unwrap();
    let trust = evertrace_engine::repository::read_report_repository_trust(
        &report,
        &RepositoryCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap(),
        worktree,
    );
    assert_eq!(
        trust.state,
        evertrace_codex::policy::RepositoryTrustState::Trusted
    );

    let data_dir = temp.path().join("data");
    let mut config_file = evertrace_domain::config::ConfigFile::default();
    config_file.runtime.data_dir = data_dir.to_str().unwrap().to_owned();
    config_file.session_import.historical_metadata_backfill = false;
    let effective = evertrace_domain::config::EffectiveConfig::new(config_file).unwrap();
    let config_toml = effective.to_toml().unwrap();
    let config_path = temp.path().join("daemon.toml");
    fs::write(&config_path, &config_toml).unwrap();
    let engine = Arc::new(
        evertrace_engine::EngineService::from_toml(
            &config_toml,
            evertrace_engine::RuntimeMode::Normal,
        )
        .unwrap(),
    );
    let config_reload =
        evertrace_engine::ConfigReloadService::new(engine, writer.clone(), data_dir, config_path)
            .unwrap();
    let configured_runtime = config_reload.initialize_runtime().await.unwrap();
    evertrace_capture::DurableSpool::open(
        configured_runtime.spool_dir.clone(),
        configured_runtime.spool_limits().unwrap(),
    )
    .unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let report = Arc::new(RwLock::new(Some(report)));
    let worker = SessionImportWorker::new(
        writer.clone(),
        configured_runtime.clone(),
        Arc::clone(&report),
    )
    .unwrap();

    dual_proof_mutation_phases(DualProofMutationFixture {
        writer: writer.clone(),
        report,
        worker,
        configured_runtime,
        revoke_session: session.to_owned(),
        revoke_source: source,
        revoke_transcript: transcript,
        workspace,
        replacement_head: head,
    })
    .await;
    drop(catalog);
    drop(config_reload);
    drop(writer);
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_source_replacement_observation_does_not_inherit_historical_scope() {
    use evertrace_store::{WorkspaceResolutionKind, repository::RepositoryCurrentView};
    use std::os::unix::fs::MetadataExt as _;

    let SourceStartFixture {
        temp: _temp,
        workspace,
        dated,
        writer,
        task,
        repository,
        worktree,
        cases,
    } = source_start_fixture().await;
    let session = cases[0].0;
    let source = format!("session-rollout:{session}:{session}");
    let transcript = dated.join(format!("rollout-2026-10-06T00-00-01-{session}.jsonl"));
    let before = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        before.current.metadata.workspace_resolution_kind,
        WorkspaceResolutionKind::Repository
    );
    assert_eq!(
        before.current.metadata.resolved_repository_instance_id,
        Some(repository)
    );
    assert_eq!(
        before.current.metadata.resolved_worktree_instance_id,
        Some(worktree)
    );
    assert_eq!(before.current.body_state, SessionBodyState::NotImported);
    assert!(before.current.metadata.prospective_origin.is_none());
    assert!(before.current.access_decision.is_none());
    assert!(before.watermark.is_none());
    assert!(before.recorded_prefix_end.is_none());
    let prior_projection = writer.project().await.unwrap();
    assert!(
        projected_source_receipts(&prior_projection)
            .all(|receipt| receipt.source_instance_id.as_str() != source)
    );

    let old_inode = fs::metadata(&transcript).unwrap().ino();
    let replacement_header = serde_json::json!({
        "timestamp":"2026-10-06T00:02:01Z",
        "type":"session_meta",
        "payload":{"id":session,"session_id":session,"cwd":workspace,"git":{"commit_hash":source_fixture_git(&workspace, &["rev-parse", "HEAD"])}}
    });
    let replacement_content = format!("{replacement_header}\n");
    let replacement_path = dated.join(format!(".{session}.replacement"));
    fs::write(&replacement_path, &replacement_content).unwrap();
    assert!(replacement_content.len() < fs::metadata(&transcript).unwrap().len() as usize);
    let replacement_inode = fs::metadata(&replacement_path).unwrap().ino();
    assert_ne!(replacement_inode, old_inode);
    fs::rename(&replacement_path, &transcript).unwrap();
    let replacement_identity = fs::metadata(&transcript).unwrap();
    assert_eq!(replacement_identity.ino(), replacement_inode);
    assert!(replacement_identity.len() < before.current.metadata.file_size);

    let request_id = RequestId::new_v7();
    let source_reference = format!("native_session_source_observation:{request_id}");
    let report = evertrace_engine::repository::observe_session_source_report(
        transcript.to_str().unwrap(),
        session,
        None,
        &source_reference,
    )
    .unwrap();
    let current_repositories =
        RepositoryCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert_eq!(
        evertrace_engine::repository::read_report_repository_trust(
            &report,
            &current_repositories,
            worktree,
        )
        .state,
        evertrace_codex::policy::RepositoryTrustState::Trusted
    );
    let catalog = SessionCatalogService::new(writer.clone(), CONFIG);
    let observed = catalog
        .observe_native_session_source(
            request_id,
            &report,
            session,
            transcript.to_str().unwrap(),
            &source_reference,
        )
        .await;
    assert!(
        observed.as_ref().is_ok_and(|changed| *changed),
        "{observed:?}"
    );

    let after = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        after.current.metadata.source_revision,
        before.current.metadata.source_revision
    );
    assert_eq!(after.current.body_state, SessionBodyState::NotImported);
    assert!(after.current.access_decision.is_none());
    assert!(after.watermark.is_none());
    assert!(after.recorded_prefix_end.is_none());
    assert_eq!(
        after.current.metadata.workspace_resolution_kind,
        WorkspaceResolutionKind::Ambiguous
    );
    assert!(
        after
            .current
            .metadata
            .resolved_repository_instance_id
            .is_none()
    );
    assert!(
        after
            .current
            .metadata
            .resolved_worktree_instance_id
            .is_none()
    );
    let origin = after
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .expect("the replacement revision receives the actual new source origin");
    assert!(!origin.closed);
    let after_projection = writer.project().await.unwrap();
    assert!(
        projected_source_receipts(&after_projection)
            .all(|receipt| receipt.source_instance_id.as_str() != source)
    );
    let repositories = RepositoryCurrentView::from_snapshot(&after_projection).unwrap();
    let forwarded_snapshot = repositories
        .snapshots
        .get(&origin.snapshot_ref)
        .expect("the new origin points to the current source-observation snapshot");
    assert_eq!(forwarded_snapshot.worktree_instance_id, worktree);
    assert!(forwarded_snapshot.evidence_refs.contains(&source_reference));
    assert_eq!(
        repositories
            .worktrees
            .get(&worktree)
            .unwrap()
            .repository_instance_id,
        repository
    );

    drop(catalog);
    drop(writer);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn source_start_boundary_is_the_catalog_resolution_input() {
    Box::pin(source_start_boundary_is_the_catalog_resolution_input_body()).await;
}

async fn source_start_boundary_is_the_catalog_resolution_input_body() {
    Box::pin(async move {
    use evertrace_domain::config::{ConfigFile, EffectiveConfig, LlmConfig, ValidatedBaseUrl};
    use evertrace_domain::evidence::ObservationRole;
    use evertrace_engine::{
        BackgroundScheduler, ConfigReloadService, EngineService, RuntimeMode,
        jobs::SynthesisPlanner,
    };
    use evertrace_store::{WorkspaceResolutionKind, repository::RepositoryCurrentView};
    use provider_stub::ProviderStub;
    use std::io::Write as _;

    let SourceStartFixture {
        temp,
        workspace,
        dated,
        writer,
        task,
        repository,
        worktree,
        cases,
        ..
    } = source_start_fixture().await;
    let catalog = SessionCatalogService::new(writer.clone(), CONFIG);

    // Exercise the live native-source path on the unresolved a3 catalog row:
    // SessionStart stores only metadata and its current S11 origin; a later
    // normal scheduler refresh discovers the append with historical backfill
    // disabled, imports only its suffix, and explicit permission admits prefix.
    let session = cases[2].0;
    let source = format!("session-rollout:{session}:{session}");
    let transcript = dated.join(format!("rollout-2026-10-06T00-00-01-{session}.jsonl"));
    let crossing_line = serde_json::json!({
        "timestamp": "2026-10-06T00:01:01Z",
        "type": "event_msg",
        "payload": {
            "type": "item_completed",
            "thread_id": session,
            "turn_id": "turn-crossing-start",
            "item": {
                "type": "UserMessage",
                "id": "user-crossing-start",
                "content": [{"type":"text","text":"must stay before the observed fence","text_elements":[]}]
            },
            "completed_at_ms": 1_791_244_861_000_i64
        }
    })
    .to_string();
    let split = crossing_line.len() / 2;
    let (crossing_prefix, crossing_suffix) = crossing_line.split_at(split);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap();
    file.write_all(crossing_prefix.as_bytes()).unwrap();
    drop(file);
    let observed_end = fs::metadata(&transcript).unwrap().len();
    let start_request = RequestId::new_v7();
    let start_reference = format!("native_session_source_observation:{start_request}");
    let start_report = evertrace_engine::repository::observe_session_source_report(
        transcript.to_str().unwrap(),
        session,
        None,
        &start_reference,
    )
    .unwrap();
    let source_trust = evertrace_engine::repository::read_report_repository_trust(
        &start_report,
        &RepositoryCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap(),
        worktree,
    );
    assert_eq!(
        source_trust.state,
        evertrace_codex::policy::RepositoryTrustState::Trusted,
        "source observer report did not retain the fixture's trusted repository: {source_trust:?}"
    );
    let observed = catalog
        .observe_native_session_source(
            start_request,
            &start_report,
            session,
            transcript.to_str().unwrap(),
            &start_reference,
        )
        .await;
    assert!(
        observed.as_ref().is_ok_and(|observed| *observed),
        "observer: {observed:?}"
    );
    let started = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert!(
        catalog
            .native_session_source_observed(
                session,
                transcript.to_str().unwrap(),
                Some(&start_report)
            )
            .await
            .unwrap()
    );
    assert!(
        !catalog
            .native_session_source_observed(session, transcript.to_str().unwrap(), None)
            .await
            .unwrap(),
        "an archived origin must not bypass rebuilding the daemon's current report"
    );
    let origin = started
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .unwrap();
    assert_eq!(origin.record_start, None);
    assert_eq!(origin.observed_end, observed_end);
    assert_eq!(started.current.body_state, SessionBodyState::NotImported);
    assert!(started.current.access_decision.is_none());
    assert_eq!(started.current.metadata.file_size, observed_end);
    assert_eq!(
        started.current.metadata.workspace_resolution_kind,
        WorkspaceResolutionKind::Ambiguous
    );
    assert!(
        started
            .current
            .metadata
            .read_restrictions()
            .any(|id| id == repository)
    );
    assert!(started.job.is_none());
    let source_snapshot = RepositoryCurrentView::from_snapshot(&writer.project().await.unwrap())
        .unwrap()
        .snapshots
        .into_values()
        .find(|snapshot| {
            snapshot.worktree_instance_id == worktree
                && snapshot.evidence_refs.contains(&start_reference)
        })
        .expect("the prospective origin is a source-linked current snapshot");
    assert_eq!(
        Some(source_snapshot.worktree_snapshot_id),
        started
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .map(|origin| origin.snapshot_ref)
    );

    let data_dir = temp.path().join("data");
    let mut config_file = ConfigFile::default();
    config_file.runtime.data_dir = data_dir.to_str().unwrap().to_owned();
    config_file.session_import.historical_metadata_backfill = false;
    let effective = EffectiveConfig::new(config_file).unwrap();
    assert!(
        !effective
            .config()
            .session_import
            .historical_metadata_backfill
    );
    let config_toml = effective.to_toml().unwrap();
    let config_path = temp.path().join("daemon.toml");
    fs::write(&config_path, &config_toml).unwrap();
    let engine = Arc::new(EngineService::from_toml(&config_toml, RuntimeMode::Normal).unwrap());
    let config_reload =
        Arc::new(ConfigReloadService::new(engine, writer.clone(), data_dir, config_path).unwrap());
    let configured_runtime = config_reload.initialize_runtime().await.unwrap();
    evertrace_capture::DurableSpool::open(
        configured_runtime.spool_dir.clone(),
        configured_runtime.spool_limits().unwrap(),
    )
    .unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let report = Arc::new(RwLock::new(Some(start_report.clone())));
    let worker = SessionImportWorker::new(
        writer.clone(),
        configured_runtime.clone(),
        Arc::clone(&report),
    )
    .unwrap();
    let budget = SessionImportBudget {
        max_bytes: 1024 * 1024,
        max_records: 1,
        max_work_time: Duration::from_millis(250),
    };
    let scheduler = BackgroundScheduler::new(
        writer.clone(),
        catalog.clone(),
        worker.clone(),
        Arc::clone(&report),
        configured_runtime.clone(),
        SynthesisPlanner::new(LlmConfig {
            enabled: false,
            ..LlmConfig::default()
        }),
        effective.config().dreaming.clone(),
    )
    .with_config(Arc::clone(&config_reload));

    let unchanged_revision = started.current.revision;
    let running_scheduler = scheduler.clone();
    tokio::spawn(async move { running_scheduler.run_once().await })
        .await
        .unwrap()
        .unwrap();
    let unchanged = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.current.revision, unchanged_revision);
    assert_eq!(unchanged.current.body_state, SessionBodyState::NotImported);
    assert!(unchanged.job.is_none());

    let appended_line = serde_json::json!({
        "timestamp": "2026-10-06T00:02:01Z",
        "type": "event_msg",
        "payload": {
            "type": "item_completed",
            "thread_id": session,
            "turn_id": "turn-after-start",
            "item": {
                "type": "UserMessage",
                "id": "user-after-start",
                "content": [{"type":"text","text":"Saffron cache replacement: preserve the live repository cache while writing a complete replacement into a sibling temporary directory. Validate the manifest and every referenced entry before one atomic rename. Abort on a missing entry, then reopen the live cache and compare its manifest to the validated replacement; effectiveness remains unverified.","text_elements":[]}]
            },
            "completed_at_ms": 1_791_244_921_000_i64
        }
    })
    .to_string();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap();
    file.write_all(crossing_suffix.as_bytes()).unwrap();
    file.write_all(b"\n").unwrap();
    writeln!(file, "{appended_line}").unwrap();
    drop(file);
    let appended_end = fs::metadata(&transcript).unwrap().len();
    assert!(
        !catalog
            .native_session_source_observed(
                session,
                transcript.to_str().unwrap(),
                Some(&start_report)
            )
            .await
            .unwrap(),
        "a stale source fingerprint must fall through to ordinary catalog refresh"
    );
    catalog.refresh(&start_report).await.unwrap();
    assert!(
        catalog
            .native_session_source_observed(
                session,
                transcript.to_str().unwrap(),
                Some(&start_report)
            )
            .await
            .unwrap()
    );
    let first_body_attempt = worker.process_checkpoint(&source, budget).await;
    assert!(
        first_body_attempt.is_ok(),
        "direct worker attempt after ordinary refresh failed: {first_body_attempt:?}"
    );
    let running_scheduler = scheduler.clone();
    tokio::spawn(async move { running_scheduler.run_once().await })
        .await
        .unwrap()
        .unwrap();
    let queued = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    let fence = queued
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .unwrap()
        .record_start
        .unwrap();
    assert!(fence > observed_end);
    assert!(appended_end > fence);
    assert_eq!(fence, observed_end + crossing_suffix.len() as u64 + 1);
    assert_eq!(queued.current.metadata.file_size, appended_end);
    assert_eq!(
        queued
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .record_start,
        Some(fence)
    );
    let mut suffix_only = queued;
    for _ in 0..8 {
        if suffix_only.current.body_state == SessionBodyState::Partial
            && suffix_only.job.is_none()
            && suffix_only
                .watermark
                .as_ref()
                .is_some_and(|watermark| watermark.source_sequence == appended_end)
        {
            break;
        }
        let running_scheduler = scheduler.clone();
        tokio::spawn(async move { running_scheduler.run_once().await })
            .await
            .unwrap()
            .unwrap();
        suffix_only = writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(suffix_only.current.body_state, SessionBodyState::Partial);
    assert!(suffix_only.job.is_none());
    assert_eq!(
        suffix_only.watermark.as_ref().unwrap().source_sequence,
        appended_end
    );
    let suffix_jobs = RuntimeSchedulerView::from_snapshot(&writer.project().await.unwrap())
        .unwrap()
        .jobs;
    let suffix_job = suffix_jobs
        .iter()
        .find(|job| job.idempotency_key == format!("session_import:{source}"))
        .unwrap();
    assert_eq!(
        suffix_job.state,
        JobStatus::Succeeded,
        "terminal={:?}; context={suffix_only:?}",
        suffix_job.terminal
    );
    assert_eq!(
        suffix_job.terminal.as_ref().unwrap().reason,
        evertrace_store::JobTerminalReason::Completed
    );
    assert!(suffix_only.current.access_decision.is_none());
    let suffix_page = writer
        .session_import_prefix_page(evertrace_store::SessionImportPrefixRequest {
            source: source.clone(),
            revision: suffix_only.current.metadata.source_revision.clone(),
            after: fence,
            end: appended_end,
            max_records: 16,
            max_bytes: 1024 * 1024,
        })
        .await
        .unwrap();
    assert_eq!(suffix_page.records.len(), 1);
    assert_eq!(
        (suffix_page.records[0].start, suffix_page.records[0].end),
        (fence, appended_end)
    );
    let prefix_before_approval = writer
        .session_import_prefix_page(evertrace_store::SessionImportPrefixRequest {
            source: source.clone(),
            revision: suffix_only.current.metadata.source_revision.clone(),
            after: 0,
            end: fence,
            max_records: 16,
            max_bytes: 1024 * 1024,
        })
        .await
        .unwrap();
    assert!(prefix_before_approval.records.is_empty());

    let drained_revision = suffix_only.current.revision;
    let running_scheduler = scheduler.clone();
    tokio::spawn(async move { running_scheduler.run_once().await })
        .await
        .unwrap()
        .unwrap();
    let drained = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(drained.current.revision, drained_revision);
    assert!(drained.job.is_none());

    // An unapproved source can still feed the existing independent semantic
    // and method consumers from its admitted suffix. The no-op summary
    // response proves that the method does not depend on a summary object.
    let first_suffix_receipts = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| {
            receipt.observation_role == ObservationRole::Message
                && receipt.source_sequence > fence
                && receipt.source_sequence <= appended_end
        })
        .collect::<Vec<_>>();
    assert_eq!(first_suffix_receipts.len(), 1);
    let first_suffix_ref = first_suffix_receipts[0].source_observation_id.to_string();
    let method_content = serde_json::json!({
        "title": "Saffron atomic cache replacement",
        "summary": "A reusable cache replacement hypothesis; effectiveness remains unverified.",
        "procedure_kind": "workflow",
        "when": {
            "goals": ["Replace a repository cache without exposing a partial build"],
            "targets": ["repository cache"],
            "signals": ["cache rebuild"],
            "stage": "replace",
            "requires": ["A sibling temporary directory and expected manifest are available"],
            "excludes": ["The live cache must be overwritten in place"]
        },
        "applicability_expr": {"op":"exists","field":"failure_signature"},
        "avoid_expr": {"op":"eq","field":"phase","value":{"kind":"text","value":"unknown"}},
        "completion_expr": {"op":"eq","field":"verifier_state","value":{"kind":"text","value":"passed"}},
        "actions": {
            "stages": [
                "Build a complete sibling cache while preserving the live cache",
                "Validate the manifest and every referenced entry, then atomically rename the replacement"
            ],
            "branches": [],
            "avoid": ["Do not report success when an entry is missing"]
        },
        "done": {
            "success": ["The live cache matches the validated replacement"],
            "abort": ["A referenced entry is missing"],
            "verify": ["Reopen the live cache and compare its manifest with the validated replacement"]
        },
        "pitfalls": ["A source claim is not proof of successful execution"]
    });
    let response = |content: serde_json::Value| {
        serde_json::to_vec(&serde_json::json!({
            "choices": [{"message": {"content": content.to_string()}}],
            "usage": {"prompt_tokens": 17, "completion_tokens": 5}
        }))
        .unwrap()
    };
    let no_op = response(serde_json::json!({"operation":"no_op"}));
    let method_body = response(serde_json::json!({
        "operation":"create",
        "content":method_content,
        "direct_refs":[first_suffix_ref.clone()]
    }));
    let method_stub = ProviderStub::methods(method_body, no_op.clone(), no_op.clone(), 2).await;
    let method_llm = LlmConfig {
        base_url: ValidatedBaseUrl::parse(&method_stub.base_url).unwrap(),
        api_key_env: "PATH".into(),
        ..LlmConfig::default()
    };
    let dreaming = evertrace_domain::config::DreamingConfig {
        idle_after: evertrace_domain::config::DurationValue::from_seconds(1).unwrap(),
        ..Default::default()
    };
    let method_scheduler = BackgroundScheduler::new(
        writer.clone(),
        catalog.clone(),
        worker.clone(),
        Arc::clone(&report),
        configured_runtime.clone(),
        SynthesisPlanner::new(method_llm),
        dreaming.clone(),
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let running_scheduler = method_scheduler.clone();
    let method_run = tokio::spawn(async move { running_scheduler.run_once().await })
        .await
        .unwrap();
    assert!(
        method_run.is_ok(),
        "source-start provider cycle failed: {method_run:?}; jobs={:?}",
        RuntimeSchedulerView::from_snapshot(&writer.project().await.unwrap())
            .unwrap()
            .jobs
    );
    let method_snapshot = writer.project().await.unwrap();
    let methods = SemanticCurrentView::from_snapshot(&method_snapshot).unwrap();
    assert_eq!(methods.proposals.len(), 1);
    let proposal = methods.proposals.values().next().unwrap();
    let proposal_id = proposal.proposal_id;
    assert_eq!(proposal.status, ProposalStatus::Pending);
    assert_eq!(
        proposal.eligibility,
        evertrace_domain::semantic::ProposalEligibility::ManualRequired
    );
    assert!(proposal.evidence_refs.contains(&first_suffix_ref));
    assert!(
        !method_snapshot
            .data_rows()
            .any(|row| { row.object_kind.as_deref() == Some("semantic_digest") })
    );
    drop(method_snapshot);
    let after_method = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_method.current.body_state, SessionBodyState::Partial);
    assert!(after_method.current.access_decision.is_none());
    assert_eq!(
        after_method.current.metadata.workspace_resolution_kind,
        WorkspaceResolutionKind::Ambiguous
    );
    let method_requests = method_stub.finish_all().await;
    assert_eq!(method_requests.len(), 2);
    assert!(method_requests.iter().any(|request| {
        String::from_utf8_lossy(request).contains("Extract at most one nontrivial reusable method")
    }));
    assert!(method_requests.iter().all(|request| {
        let request = String::from_utf8_lossy(request);
        !request.contains("must stay before the observed fence")
            && !request.contains("turn-crossing-start")
    }));

    let bindings = evertrace_engine::McpBindingAuthority::new(
        DeviceKeyStore::new(temp.path().join("keys"))
            .load_or_create()
            .unwrap(),
    );
    let mcp = evertrace_engine::McpActionService::open(
        bindings.clone(),
        &temp.path().join("data"),
        writer.clone(),
        configured_runtime.clone(),
    )
    .await
    .unwrap()
    .with_session_report(Arc::clone(&report));
    let cross_session = "019d0000-0000-7000-8000-000000000098";
    for (action, input) in [
        (evertrace_engine::McpServiceAction::Search, "Saffron".into()),
        (
            evertrace_engine::McpServiceAction::Get,
            proposal_id.to_string(),
        ),
    ] {
        let grant = bindings
            .issue_with_report(
                evertrace_engine::McpBindingIssue {
                    session_id: cross_session.into(),
                    turn_id: "source-start-cross-session".into(),
                    tool_use_id: "source-suffix-read".into(),
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
                Some(Arc::new(start_report.clone())),
            )
            .unwrap();
        let request = evertrace_engine::McpServiceRequest {
            request_id: RequestId::new_v7(),
            action,
            workspace: grant.bound_workspace,
            input,
            refs: vec![],
            client_cwd: workspace.to_str().unwrap().into(),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            mcp.handle("source-start-cross-session", request),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(result.items.iter().any(|item| {
            item.object_ref == Some(proposal_id.to_string())
                && item.content_trust == evertrace_domain::evidence::ContentTrust::AgentClaim
        }));
    }
    drop(method_scheduler);

    let first_suffix_end = appended_end;
    let next_line = serde_json::json!({
        "timestamp": "2026-10-06T00:03:01Z",
        "type": "event_msg",
        "payload": {
            "type": "item_completed",
            "thread_id": session,
            "turn_id": "turn-after-start-2",
            "item": {
                "type": "UserMessage",
                "id": "user-after-start-2",
                "content": [{"type":"text","text":"Saffron verification note: after replacing the live repository cache, reopen it and compare its manifest against the validated sibling before reporting completion; effectiveness remains unverified.","text_elements":[]}]
            },
            "completed_at_ms": 1_791_244_981_000_i64
        }
    })
    .to_string();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap();
    writeln!(file, "{next_line}").unwrap();
    drop(file);
    let appended_end = fs::metadata(&transcript).unwrap().len();
    let running_scheduler = scheduler.clone();
    tokio::spawn(async move { running_scheduler.run_once().await })
        .await
        .unwrap()
        .unwrap();
    let requeued = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(requeued.current.metadata.file_size, appended_end);
    assert_eq!(requeued.current.body_state, SessionBodyState::Queued);
    assert_eq!(requeued.job.as_ref().unwrap().state, JobStatus::Queued);
    let mut next_suffix_records = 0;
    let mut next_suffix_completed = false;
    for _ in 0..8 {
        let progress = worker.process_checkpoint(&source, budget).await.unwrap();
        next_suffix_records += progress.records;
        next_suffix_completed = progress.completed;
        if next_suffix_completed {
            break;
        }
    }
    assert!(next_suffix_completed);
    assert_eq!(next_suffix_records, 1);
    let drained_again = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(drained_again.current.body_state, SessionBodyState::Partial);
    assert!(drained_again.job.is_none());

    let second_suffix_receipts = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| {
            receipt.observation_role == ObservationRole::Message
                && receipt.source_sequence > first_suffix_end
                && receipt.source_sequence <= appended_end
        })
        .collect::<Vec<_>>();
    assert_eq!(second_suffix_receipts.len(), 1);
    let second_suffix_ref = second_suffix_receipts[0].source_observation_id.to_string();
    let summary_application = serde_json::json!({
        "progress_delta": [{
            "label":"cache replacement verification",
            "value":"The source proposes reopening the live cache and comparing its manifest with a validated sibling; execution and effectiveness remain unverified.",
            "direct_refs":[second_suffix_ref.clone()]
        }],
        "decision_delta":[],
        "failed_routes":[],
        "resolved_items":[],
        "open_loops":[],
        "outcome_delta":[],
        "omissions":[],
        "candidates":[],
        "completeness":"partial"
    });
    let summary_stub = ProviderStub::methods(
        no_op.clone(),
        no_op.clone(),
        response(summary_application),
        3,
    )
    .await;
    let summary_scheduler = BackgroundScheduler::new(
        writer.clone(),
        catalog.clone(),
        worker.clone(),
        Arc::clone(&report),
        configured_runtime.clone(),
        SynthesisPlanner::new(LlmConfig {
            base_url: ValidatedBaseUrl::parse(&summary_stub.base_url).unwrap(),
            api_key_env: "PATH".into(),
            ..LlmConfig::default()
        }),
        dreaming.clone(),
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let running_scheduler = summary_scheduler.clone();
    tokio::spawn(async move { running_scheduler.run_once().await })
        .await
        .unwrap()
        .unwrap();
    let summary_requests = summary_stub.finish_all().await;
    let summary_snapshot = writer.project().await.unwrap();
    let source_summary_requests = summary_requests
        .iter()
        .filter(|request| {
            String::from_utf8_lossy(request)
                .contains("describing only the supplied archived messages")
        })
        .collect::<Vec<_>>();
    assert_eq!(source_summary_requests.len(), 1);
    let source_request = &source_summary_requests[0];
    let body_offset = source_request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    let source_request: serde_json::Value =
        serde_json::from_slice(&source_request[body_offset..]).unwrap();
    let source_input: serde_json::Value =
        serde_json::from_str(source_request["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(
        source_input["source_refs"],
        serde_json::json!([second_suffix_ref])
    );
    assert!(
        !source_input
            .to_string()
            .contains("must stay before the observed fence")
    );
    assert!(!source_input.to_string().contains("turn-crossing-start"));
    let suffix_summary = summary_snapshot
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SemanticDigestRecorded(digest)
                    if digest
                        .application
                        .progress_delta
                        .iter()
                        .any(|delta| delta.direct_refs.contains(&second_suffix_ref)) =>
                {
                    Some(digest)
                }
                _ => None,
            }
        })
        .next()
        .expect("source-summary did not commit the new suffix");
    assert!(suffix_summary.application.candidates.is_empty());
    assert!(
        suffix_summary
            .application
            .progress_delta
            .iter()
            .all(|delta| {
                delta
                    .direct_refs
                    .iter()
                    .all(|reference| reference == &second_suffix_ref)
            })
    );
    assert!(
        !suffix_summary
            .application
            .progress_delta
            .iter()
            .any(|delta| { delta.value.contains("must stay before the observed fence") })
    );
    drop(summary_snapshot);
    let after_summary = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_summary.current.body_state, SessionBodyState::Partial);
    assert!(after_summary.current.access_decision.is_none());
    assert!(after_summary.current.metadata.prospective_origin.is_some());
    assert_eq!(summary_requests.len(), 3);
    assert!(summary_requests.iter().all(|request| {
        let request = String::from_utf8_lossy(request);
        !request.contains("must stay before the observed fence")
            && !request.contains("turn-crossing-start")
    }));
    assert_eq!(
        methods.proposals.get(&proposal_id).unwrap().status,
        ProposalStatus::Pending
    );
    drop(methods);

    tokio::spawn(async move {
    let admin = SessionImportAdminService::new(writer.clone(), Arc::clone(&report), CONFIG);

    // Keep a second prospective source runnable while the main source builds
    // real receipts in both the historical-prefix and suffix lanes.
    let provider_session = cases[1].0;
    let provider_source = format!("session-rollout:{provider_session}:{provider_session}");
    let provider_transcript = dated.join(format!(
        "rollout-2026-10-06T00-00-01-{provider_session}.jsonl"
    ));
    let provider_request = RequestId::new_v7();
    let provider_observation = format!("native_session_source_observation:{provider_request}");
    let provider_report = evertrace_engine::repository::observe_session_source_report(
        provider_transcript.to_str().unwrap(),
        provider_session,
        None,
        &provider_observation,
    )
    .unwrap();
    assert!(
        catalog
            .observe_native_session_source(
                provider_request,
                &provider_report,
                provider_session,
                provider_transcript.to_str().unwrap(),
                &provider_observation,
            )
            .await
            .unwrap()
    );
    let provider_origin = writer
        .session_import_context(&provider_source)
        .await
        .unwrap()
        .unwrap();
    assert!(provider_origin.current.access_decision.is_none());
    let provider_fence = provider_origin
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .unwrap()
        .record_start
        .unwrap();
    let provider_line = serde_json::json!({
        "timestamp":"2026-10-06T00:02:30Z",
        "type":"event_msg",
        "payload":{"type":"item_completed","thread_id":provider_session,"turn_id":"provider-revoke-1","item":{"type":"UserMessage","id":"provider-revoke-1","content":[{"type":"text","text":"A prospective provider candidate must be discarded if access is revoked while generation is pending.","text_elements":[]}]},"completed_at_ms":1_791_244_951_000_i64}
    })
    .to_string();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&provider_transcript)
        .unwrap();
    writeln!(file, "{provider_line}").unwrap();
    drop(file);
    catalog.refresh(&provider_report).await.unwrap();
    for _ in 0..4 {
        if worker
            .process_checkpoint(&provider_source, budget)
            .await
            .unwrap()
            .completed
        {
            break;
        }
    }
    let provider_ready = writer
        .session_import_context(&provider_source)
        .await
        .unwrap()
        .unwrap();
    assert!(provider_ready.current.access_decision.is_none());
    assert!(provider_ready.watermark.as_ref().unwrap().source_sequence > provider_fence);
    let first_provider_reference = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| {
            receipt.source_instance_id.as_str() == provider_source
                && receipt.source_sequence > provider_fence
                && receipt.observation_role == ObservationRole::Message
        })
        .map(|receipt| receipt.source_observation_id.to_string())
        .next()
        .unwrap();
    let provider_backlog_line = serde_json::json!({
        "timestamp":"2026-10-06T00:03:00Z",
        "type":"event_msg",
        "payload":{"type":"item_completed","thread_id":provider_session,"turn_id":"provider-revoke-backlog","item":{"type":"UserMessage","id":"provider-revoke-backlog","content":[{"type":"text","text":"A second prospective source record remains queued until a later body quantum.","text_elements":[]}]},"completed_at_ms":1_791_244_981_000_i64}
    })
    .to_string();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&provider_transcript)
        .unwrap();
    writeln!(file, "{provider_backlog_line}").unwrap();
    drop(file);
    let provider_refresh = catalog.refresh_active(&provider_report).await.unwrap();
    let provider_backlog = writer
        .session_import_context(&provider_source)
        .await
        .unwrap()
        .unwrap();
    assert!(
        provider_refresh > 0
            && provider_backlog
                .job
                .as_ref()
                .is_some_and(|job| job.state == JobStatus::Queued),
        "active refresh must queue the complete append on a drained prospective source: refreshed={provider_refresh}, body={:?}, metadata_size={}, job={:?}",
        provider_backlog.current.body_state,
        provider_backlog.current.metadata.file_size,
        provider_backlog.job
    );
    assert!(provider_backlog.current.access_decision.is_none());
    // The next existing record arrives in two writes. Metadata must catch up
    // while this job is queued, without granting a read of the incomplete tail.
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&provider_transcript)
        .unwrap();
    file.write_all(b"{").unwrap();
    drop(file);
    let provider_followup_size = fs::metadata(&provider_transcript).unwrap().len();
    assert!(provider_followup_size > provider_backlog.current.metadata.file_size);
    let refresh_while_queued = catalog.refresh_active(&provider_report).await.unwrap();
    let provider_refreshed = writer
        .session_import_context(&provider_source)
        .await
        .unwrap()
        .unwrap();
    assert!(refresh_while_queued > 0);
    assert_eq!(
        provider_refreshed.current.metadata.file_size,
        provider_followup_size
    );
    assert_eq!(
        provider_refreshed.current.body_state,
        provider_backlog.current.body_state
    );
    assert!(provider_refreshed.current.access_decision.is_none());
    assert_eq!(
        provider_refreshed.current.metadata.prospective_origin,
        provider_backlog.current.metadata.prospective_origin
    );
    assert_eq!(provider_refreshed.watermark, provider_backlog.watermark);
    let refreshed_job = provider_refreshed.job.as_ref().unwrap();
    assert_eq!(
        refreshed_job.job_id,
        provider_backlog.job.as_ref().unwrap().job_id
    );
    assert_eq!(refreshed_job.state, JobStatus::Queued);

    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                session,
                SessionImportAdminAction::QueueImport,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_micros() as i64,
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );
    let mut suffix_lines = Vec::new();
    for index in 0..12 {
        suffix_lines.push(
            serde_json::json!({
                "timestamp":"2026-10-06T00:04:00Z",
                "type":"event_msg",
                "payload":{"type":"item_completed","thread_id":session,"turn_id":format!("dual-backlog-{index}"),"item":{"type":"UserMessage","id":format!("dual-backlog-{index}"),"content":[{"type":"text","text":format!("admitted suffix backlog item {index}"),"text_elements":[]}]},"completed_at_ms":1_791_245_040_000_i64 + index}
            })
            .to_string(),
        );
    }
    let missing_git_line = serde_json::json!({
        "timestamp":"2026-10-06T00:05:00Z",
        "type":"event_msg",
        "payload":{"type":"item_completed","thread_id":session,"turn_id":"missing-git-append","item":{"type":"UserMessage","id":"missing-git-append","content":[{"type":"text","text":"This append is admitted only after the original Git evidence returns.","text_elements":[]}]},"completed_at_ms":1_791_245_100_000_i64}
    })
    .to_string();
    let missing_git_split = missing_git_line.len() / 2;
    let before_missing_git = &missing_git_line[..missing_git_split];
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap();
    for line in &suffix_lines {
        writeln!(file, "{line}").unwrap();
    }
    let full_suffix_end = file.metadata().unwrap().len();
    file.write_all(before_missing_git.as_bytes()).unwrap();
    drop(file);
    catalog.refresh(&start_report).await.unwrap();
    let queued_dual = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        queued_dual.current.access_decision,
        Some(evertrace_store::SessionAccessDecision::Approved)
    );
    assert!(queued_dual.current.metadata.file_size > full_suffix_end);
    assert_eq!(queued_dual.current.body_state, SessionBodyState::Queued);
    let mut saw_prefix_progress = false;
    let mut saw_suffix_progress = false;
    let mut saw_prefix_eof_with_suffix_pending = false;
    let mut other_source_advanced_during_body = false;
    for _ in 0..32 {
        let before = writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap();
        let previous_watermark = before.watermark.clone().unwrap();
        let progress = worker.process_checkpoint(&source, budget).await.unwrap();
        let after = writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap();
        let current_watermark = after.watermark.as_ref().unwrap();
        let prefix_before = previous_watermark
            .earlier_prefix
            .as_ref()
            .map_or(0, |prefix| prefix.through_byte);
        let prefix_after = current_watermark
            .earlier_prefix
            .as_ref()
            .map_or(0, |prefix| prefix.through_byte);
        if prefix_after > prefix_before {
            saw_prefix_progress = true;
        }
        if current_watermark.source_sequence > previous_watermark.source_sequence {
            saw_suffix_progress = true;
        }
        if progress.records > 0 && !other_source_advanced_during_body {
            for _ in 0..8 {
                let other = worker
                    .process_checkpoint(&provider_source, budget)
                    .await
                    .unwrap();
                if other.records > 0 {
                    other_source_advanced_during_body = true;
                    break;
                }
            }
        }
        if prefix_after == fence && current_watermark.source_sequence < full_suffix_end {
            assert!(
                !progress.completed,
                "one finished lane cannot finish the whole job"
            );
            saw_prefix_eof_with_suffix_pending = true;
            break;
        }
        assert!(!progress.completed || current_watermark.source_sequence >= full_suffix_end);
    }
    assert!(saw_prefix_progress && saw_suffix_progress);
    assert!(saw_prefix_eof_with_suffix_pending);
    assert!(
        other_source_advanced_during_body,
        "the other prospective source must advance while the dual-leg suffix backlog remains nonempty"
    );
    let dual_progress = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    let dual_watermark = dual_progress.watermark.as_ref().unwrap();
    assert_eq!(
        dual_watermark.earlier_prefix.as_ref().unwrap().through_byte,
        fence
    );
    assert!(dual_watermark.source_sequence < full_suffix_end);
    assert_eq!(dual_progress.job.as_ref().unwrap().state, JobStatus::Queued);
    assert!(dual_progress.job.as_ref().unwrap().terminal.is_none());

    let cold_proof_provider_line = serde_json::json!({
        "timestamp":"2026-10-06T00:03:30Z",
        "type":"event_msg",
        "payload":{"type":"item_completed","thread_id":provider_session,"turn_id":"provider-cold-proof-runnable","item":{"type":"UserMessage","id":"provider-cold-proof-runnable","content":[{"type":"text","text":"A second source remains runnable throughout cold dual-proof pages.","text_elements":[]}]},"completed_at_ms":1_791_245_011_000_i64}
    })
    .to_string();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&provider_transcript)
        .unwrap();
    writeln!(
        file,
        "{}",
        cold_proof_provider_line.strip_prefix('{').unwrap()
    )
    .unwrap();
    drop(file);
    let provider_refresh = catalog.refresh_active(&provider_report).await.unwrap();
    let provider_cold_pending = writer
        .session_import_context(&provider_source)
        .await
        .unwrap()
        .unwrap();
    assert!(
        provider_refresh > 0
            && provider_cold_pending
                .job
                .as_ref()
                .is_some_and(|job| job.state == JobStatus::Queued),
        "a fresh complete append must leave the other source runnable for cold proof"
    );

    let cold_worker = SessionImportWorker::new(
        writer.clone(),
        configured_runtime.clone(),
        Arc::clone(&report),
    )
    .unwrap();
    let receipts_before_cold_proof = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| receipt.source_instance_id.as_str() == source)
        .count();
    let watermark_before_cold_proof = dual_progress.watermark.clone();
    let mut cold_proof_pages = 0;
    let mut other_source_advanced = false;
    let mut body_after_proofs = 0;
    for _ in 0..24 {
        let progress = cold_worker
            .process_checkpoint(&source, budget)
            .await
            .unwrap();
        if progress.records > 0 || progress.completed {
            body_after_proofs = progress.records;
            break;
        }
        cold_proof_pages += usize::from(progress.bytes > 0);
        let current = writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.watermark, watermark_before_cold_proof);
        assert_eq!(current.job.as_ref().unwrap().state, JobStatus::Queued);
        assert!(current.job.as_ref().unwrap().terminal.is_none());
        let receipts_during_proof = projected_source_receipts(&writer.project().await.unwrap())
            .filter(|receipt| receipt.source_instance_id.as_str() == source)
            .count();
        assert_eq!(
            receipts_during_proof, receipts_before_cold_proof,
            "proof-only checkpoints cannot append selected-source receipts"
        );
        if !other_source_advanced {
            for _ in 0..4 {
                let other = worker
                    .process_checkpoint(&provider_source, budget)
                    .await
                    .unwrap();
                if other.records > 0 {
                    other_source_advanced = true;
                    break;
                }
            }
        }
    }
    assert!(
        cold_proof_pages >= 2,
        "both committed legs need bounded proof pages"
    );
    assert!(
        other_source_advanced,
        "the other runnable source must advance during cold proof"
    );
    assert_eq!(
        body_after_proofs, 1,
        "one body record is allowed after proofs"
    );

    tokio::spawn(async move {
    // This independent source has no source-time S11 identity. The positive
    // a1 historical-resolution fixture is intentionally not reused here.
    let revoke_session = "019d0000-0000-7000-8000-0000000000a4";
    let revoke_source = format!("session-rollout:{revoke_session}:{revoke_session}");
    let revoke_transcript = dated.join(format!(
        "rollout-2026-10-06T00-00-01-{revoke_session}.jsonl"
    ));
    let historical_line = serde_json::json!({
        "timestamp":"2026-10-06T00:00:30Z",
        "type":"event_msg",
        "payload":{"type":"item_completed","thread_id":revoke_session,"turn_id":"closed-unknown-fence","item":{"type":"UserMessage","id":"closed-unknown-fence","content":[{"type":"text","text":"historical record completed after the origin closed","text_elements":[]}]},"completed_at_ms":1_791_244_831_000_i64}
    })
    .to_string();
    let historical_split = historical_line.len() / 2;
    let (historical_prefix, historical_suffix) = historical_line.split_at(historical_split);
    let historical_header = serde_json::json!({
        "timestamp":"2026-10-06T00:00:01Z",
        "type":"session_meta",
        "payload":{"id":revoke_session,"session_id":revoke_session,"cwd":workspace,
            "git":{"commit_hash":source_fixture_git(&workspace, &["rev-parse", "HEAD"])}}
    });
    fs::write(&revoke_transcript, format!("{historical_header}\n{historical_prefix}")).unwrap();
    let revoke_request = RequestId::new_v7();
    let revoke_reference = format!("native_session_source_observation:{revoke_request}");
    let revoke_report = evertrace_engine::repository::observe_session_source_report(
        revoke_transcript.to_str().unwrap(),
        revoke_session,
        None,
        &revoke_reference,
    )
    .unwrap();
    assert!(
        catalog
            .observe_native_session_source(
                revoke_request,
                &revoke_report,
                revoke_session,
                revoke_transcript.to_str().unwrap(),
                &revoke_reference,
            )
            .await
            .unwrap()
    );
    let unapproved = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap();
    assert!(unapproved.current.access_decision.is_none());
    assert!(unapproved.current.metadata.resolved_repository_instance_id.is_none());
    assert!(unapproved.current.metadata.resolved_worktree_instance_id.is_none());
    assert!(unapproved.current.metadata.prospective_origin.is_some());
    assert_eq!(unapproved.current.body_state, SessionBodyState::NotImported);
    assert_eq!(
        unapproved
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .record_start,
        None,
        "the live observation ended inside a transcript record"
    );

    // The second prospective source remains live with an incomplete suffix tail.
    // Its most recent committed receipt drives the paused provider request.
    let provider_ready = writer
        .session_import_context(&provider_source)
        .await
        .unwrap()
        .unwrap();
    assert!(provider_ready.current.access_decision.is_none());
    assert!(
        provider_ready
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .is_some_and(|origin| !origin.closed)
    );
    let provider_reference = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| {
            receipt.source_instance_id.as_str() == provider_source
                && receipt.observation_role == ObservationRole::Message
        })
        .map(|receipt| {
            (
                receipt.source_sequence,
                receipt.source_observation_id.to_string(),
            )
        })
        .max_by_key(|(sequence, _)| *sequence)
        .unwrap()
        .1;
    assert_ne!(
        first_provider_reference, provider_reference,
        "the independently runnable source must have durable progress beyond its first receipt"
    );
    let provider_method_body = response(serde_json::json!({
        "operation":"create",
        "content":method_content.clone(),
        "direct_refs":[provider_reference.clone()]
    }));
    let (revoked_stub, release_provider) =
        ProviderStub::methods_once_paused(provider_method_body, no_op.clone(), no_op.clone(), 2)
            .await;
    let revoking_scheduler = BackgroundScheduler::new(
        writer.clone(),
        catalog.clone(),
        worker.clone(),
        Arc::clone(&report),
        configured_runtime.clone(),
        SynthesisPlanner::new(LlmConfig {
            base_url: ValidatedBaseUrl::parse(&revoked_stub.base_url).unwrap(),
            api_key_env: "PATH".into(),
            ..LlmConfig::default()
        }),
        dreaming.clone(),
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let running_revocation = tokio::spawn({
        let scheduler = revoking_scheduler.clone();
        async move { scheduler.run_once().await }
    });
    tokio::time::timeout(Duration::from_secs(5), revoked_stub.wait_received())
        .await
        .expect("method provider did not reach the controlled in-flight point");

    let prior_main_watermark = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap()
        .watermark
        .unwrap();
    let mut concurrent_progress = None;
    for _ in 0..16 {
        let progress = worker.process_checkpoint(&source, budget).await.unwrap();
        if progress.records > 0 {
            concurrent_progress = Some(progress);
            break;
        }
    }
    assert!(
        concurrent_progress.is_some(),
        "the live main source must keep progressing while the other provider request is pending"
    );
    let main_advanced = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        main_advanced.current.access_decision,
        Some(evertrace_store::SessionAccessDecision::Approved)
    );
    assert!(
        main_advanced.watermark.as_ref().unwrap().source_sequence
            > prior_main_watermark.source_sequence
    );

    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                provider_session,
                SessionImportAdminAction::RevokeAccess,
                11,
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Revoked
    );
    assert_eq!(
        writer
            .session_import_context(&provider_source)
            .await
            .unwrap()
            .unwrap()
            .current
            .access_decision,
        Some(evertrace_store::SessionAccessDecision::Revoked)
    );
    release_provider.send(()).unwrap();
    running_revocation.await.unwrap().unwrap();
    let revoked_requests = revoked_stub.finish_all().await;
    assert!(revoked_requests.iter().any(|request| {
        String::from_utf8_lossy(request).contains("Extract at most one nontrivial reusable method")
    }));
    let after_revoked_provider =
        SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert!(
        after_revoked_provider
            .proposals
            .values()
            .all(|proposal| { !proposal.evidence_refs.contains(&provider_reference) })
    );

    // A missing Git locator is ambiguity, not proof of a replacement. Appending
    // while the evidence is unavailable cannot claim or import the new bytes.
    let receipt_count_before_missing_git =
        projected_source_receipts(&writer.project().await.unwrap())
            .filter(|receipt| receipt.source_instance_id.as_str() == source)
        .count();
    let open_before_missing = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    let origin_before_missing = open_before_missing
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .unwrap()
        .clone();
    let job_before_missing = open_before_missing.job.clone();
    let job_id_before_missing = job_before_missing.as_ref().unwrap().job_id;
    let watermark_before_missing = open_before_missing.watermark.clone();
    let leases_before_missing = writer
        .project()
        .await
        .unwrap()
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::JobLease(lease) if lease.job_id == job_id_before_missing => {
                    Some(())
                }
                _ => None,
            }
        })
        .count();
    let git_dir = workspace.join(".git");
    let held_git_dir = temp.path().join("held-origin-git");
    let missing_git_line = serde_json::json!({
        "timestamp":"2026-10-06T00:05:00Z",
        "type":"event_msg",
        "payload":{"type":"item_completed","thread_id":session,"turn_id":"missing-git-append","item":{"type":"UserMessage","id":"missing-git-append","content":[{"type":"text","text":"This append is admitted only after the original Git evidence returns.","text_elements":[]}]},"completed_at_ms":1_791_245_100_000_i64}
    })
    .to_string();
    let missing_git_split = missing_git_line.len() / 2;
    let (before_missing_git, after_missing_git) = missing_git_line.split_at(missing_git_split);
    fs::rename(&git_dir, &held_git_dir).unwrap();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap();
    file.write_all(before_missing_git.as_bytes()).unwrap();
    drop(file);
    let incomplete_tail_end = fs::metadata(&transcript).unwrap().len();
    let missing_git_attempt = worker.process_checkpoint(&source, budget).await;
    assert!(missing_git_attempt.is_err() || missing_git_attempt.unwrap().records == 0);
    let still_open = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    let still_open_origin = still_open
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .unwrap();
    assert!(!still_open_origin.closed);
    assert_eq!(
        still_open_origin.snapshot_ref,
        origin_before_missing.snapshot_ref
    );
    assert_eq!(
        still_open_origin.record_start,
        origin_before_missing.record_start
    );
    assert_eq!(still_open.watermark, watermark_before_missing);
    let leases_after_missing = writer
        .project()
        .await
        .unwrap()
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::JobLease(lease) if lease.job_id == job_id_before_missing => {
                    Some(())
                }
                _ => None,
            }
        })
        .count();
    assert_eq!(
        leases_after_missing, leases_before_missing,
        "missing evidence cannot claim a new body lease"
    );
    assert!(still_open.current.metadata.file_size < incomplete_tail_end);
    assert_eq!(
        projected_source_receipts(&writer.project().await.unwrap())
            .filter(|receipt| receipt.source_instance_id.as_str() == source)
            .count(),
        receipt_count_before_missing_git
    );
    fs::rename(&held_git_dir, &git_dir).unwrap();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap();
    file.write_all(after_missing_git.as_bytes()).unwrap();
    file.write_all(b"\n").unwrap();
    drop(file);
    let missing_git_end = fs::metadata(&transcript).unwrap().len();
    catalog.refresh(&start_report).await.unwrap();
    let restored_evidence = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    let restored_origin = restored_evidence
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .unwrap();
    assert!(!restored_origin.closed);
    assert_eq!(
        restored_origin.snapshot_ref,
        origin_before_missing.snapshot_ref
    );
    assert_eq!(
        restored_origin.record_start,
        origin_before_missing.record_start
    );
    assert_eq!(
        restored_evidence.current.metadata.file_size,
        missing_git_end
    );
    let watermark_before_resume = still_open.watermark.as_ref().unwrap().source_sequence;
    let mut resumed_progress = None;
    for _ in 0..24 {
        let progress = worker.process_checkpoint(&source, budget).await.unwrap();
        let resumed = writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap();
        if resumed
            .watermark
            .as_ref()
            .is_some_and(|watermark| watermark.source_sequence > watermark_before_resume)
        {
            resumed_progress = Some(progress);
            break;
        }
    }
    let resumed = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert!(resumed_progress.is_some_and(|progress| progress.records > 0));
    let resumed_watermark = resumed.watermark.as_ref().unwrap();
    assert!(resumed_watermark.source_sequence > watermark_before_resume);
    assert!(resumed_watermark.source_sequence < missing_git_end);
    assert_eq!(resumed.job.as_ref().unwrap().state, JobStatus::Queued);
    assert_eq!(resumed.current.body_state, SessionBodyState::Partial);
    assert_eq!(
        resumed
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .snapshot_ref,
        origin_before_missing.snapshot_ref
    );
    assert_eq!(
        resumed
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .record_start,
        origin_before_missing.record_start
    );
    assert!(
        !resumed
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .closed
    );

    let receipt_count_before_close = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| receipt.source_instance_id.as_str() == source)
        .count();

    fs::rename(&git_dir, &held_git_dir).unwrap();
    source_fixture_git(&workspace, &["init", "-q", "-b", "main"]);
    source_fixture_git(
        &workspace,
        &["commit", "--allow-empty", "-qm", "replacement"],
    );
    use std::os::unix::fs::MetadataExt as _;
    assert_ne!(
        fs::metadata(&held_git_dir).unwrap().ino(),
        fs::metadata(&git_dir).unwrap().ino(),
        "the test must install a distinct Git instance at the original path"
    );
    let close_progress = worker
        .process_checkpoint(&source, budget)
        .await
        .expect("positive Git-instance replacement should persist source closure");
    assert_eq!(close_progress.records, 0);
    let closure_worker = SessionImportWorker::new(
        writer.clone(),
        configured_runtime.clone(),
        Arc::clone(&report),
    )
    .unwrap();
    let watermark_before_close_finalization = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap()
        .watermark;
    let mut close_finalized = false;
    for _ in 0..32 {
        let progress = closure_worker
            .process_checkpoint(&source, budget)
            .await
            .unwrap();
        assert_eq!(
            progress.records, 0,
            "closed-source finalization is proof/terminal work only"
        );
        let current = writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.watermark, watermark_before_close_finalization);
        if progress.completed {
            close_finalized = true;
            break;
        }
    }
    assert!(
        close_finalized,
        "closed admitted ranges must finish after both durable proofs"
    );
    let closed = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    let closed_origin = closed.current.metadata.prospective_origin.as_ref().unwrap();
    assert!(closed_origin.closed);
    assert_eq!(
        closed_origin.snapshot_ref,
        source_snapshot.worktree_snapshot_id
    );
    assert_eq!(closed_origin.record_start, Some(fence));
    assert!(
        closed
            .current
            .metadata
            .read_restrictions()
            .any(|id| id == repository)
    );
    assert_eq!(closed.current.body_state, SessionBodyState::Partial);
    assert!(closed.job.is_none());
    assert_eq!(
        projected_source_receipts(&writer.project().await.unwrap())
            .filter(|receipt| receipt.source_instance_id.as_str() == source)
            .count(),
        receipt_count_before_close,
        "positive discontinuity must close before a new receipt is admitted"
    );

    let unknown_close = worker.process_checkpoint(&revoke_source, budget).await;
    assert!(
        unknown_close.is_ok_and(|progress| progress.records == 0),
        "the independent origin must close without importing its unobserved tail: {unknown_close:?}"
    );
    let closed_unknown = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap();
    let closed_unknown_origin = closed_unknown
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .unwrap();
    assert!(closed_unknown_origin.closed);
    assert_eq!(closed_unknown_origin.record_start, None);
    assert!(closed_unknown.watermark.is_none());
    assert!(closed_unknown.current.access_decision.is_none());

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&revoke_transcript)
        .unwrap();
    file.write_all(historical_suffix.as_bytes()).unwrap();
    file.write_all(b"\n").unwrap();
    drop(file);
    let unknown_tail_end = fs::metadata(&revoke_transcript).unwrap().len();
    catalog.refresh(&revoke_report).await.unwrap();
    let still_unknown = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_unknown.current.metadata.file_size, unknown_tail_end);
    assert_eq!(
        still_unknown
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .record_start,
        None,
        "catalog refresh must not resolve a closed origin before historical approval"
    );
    assert!(
        still_unknown
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .closed
    );

    assert!(still_unknown.current.metadata.resolved_repository_instance_id.is_none());
    assert!(still_unknown.current.metadata.resolved_worktree_instance_id.is_none());
    // Archived-read trust is not permission to read unapproved source bytes.
    // A closed origin must retain an unknown fence until historical approval.
    let unapproved_preflight = Box::pin(worker.process_checkpoint(&revoke_source, budget))
        .await
        .unwrap();
    assert_eq!(unapproved_preflight.records, 0);
    let after_unapproved = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after_unapproved.current.metadata.prospective_origin,
        still_unknown.current.metadata.prospective_origin,
        "trust alone must not resolve a closed source's unapproved historical framing"
    );
    assert!(after_unapproved.watermark.is_none());

    let approved_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                revoke_session,
                SessionImportAdminAction::QueueImport,
                approved_at,
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );
    let receipts_before_unknown_preflight = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| receipt.source_instance_id.as_str() == revoke_source)
        .count();
    let first_unknown_preflight = worker
        .process_checkpoint(
            &revoke_source,
            SessionImportBudget {
                max_records: 1,
                ..budget
            },
        )
        .await
        .unwrap();
    assert_eq!(first_unknown_preflight.records, 0);
    assert!(!first_unknown_preflight.completed);
    let resolved_unknown = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap();
    let resolved_origin = resolved_unknown
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .unwrap();
    assert!(resolved_origin.closed);
    let resolved_fence = resolved_origin.record_start.unwrap();
    assert_eq!(resolved_fence, unknown_tail_end);
    assert!(resolved_unknown.watermark.is_none());
    assert_eq!(
        projected_source_receipts(&writer.project().await.unwrap())
            .filter(|receipt| receipt.source_instance_id.as_str() == revoke_source)
            .count(),
        receipts_before_unknown_preflight,
        "the bounded metadata preflight cannot create a body receipt"
    );
    let mut unknown_progress = None;
    for _ in 0..8 {
        let progress = worker
            .process_checkpoint(
                &revoke_source,
                SessionImportBudget {
                    max_records: 1,
                    ..budget
                },
            )
            .await
            .unwrap();
        if progress.completed {
            unknown_progress = Some(progress);
            break;
        }
    }
    let historical_imported = writer
        .session_import_context(&revoke_source)
        .await
        .unwrap()
        .unwrap();
    assert!(unknown_progress.is_some());
    assert_eq!(
        historical_imported.current.body_state,
        SessionBodyState::Partial
    );
    assert!(
        historical_imported
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .closed
    );
    let historical_watermark = historical_imported.watermark.as_ref().unwrap();
    assert_eq!(historical_watermark.source_sequence, resolved_fence);
    assert!(historical_watermark.confirmed_prefix_digest.is_none());
    let historical_prefix = historical_watermark.earlier_prefix.as_ref().unwrap();
    assert_eq!(historical_prefix.fence_byte, resolved_fence);
    assert_eq!(historical_prefix.through_byte, resolved_fence);
    assert!(historical_prefix.digest.is_some());
    assert!(
        projected_source_receipts(&writer.project().await.unwrap())
            .filter(|receipt| receipt.source_instance_id.as_str() == revoke_source)
            .all(|receipt| receipt.source_sequence <= resolved_fence),
        "the first receipt after close is restricted to the resolved historical fence"
    );

    let closed_archive = writer.project().await.unwrap();
    let closed_semantics = SemanticCurrentView::from_snapshot(&closed_archive).unwrap();
    let archived_proposal = closed_semantics
        .proposals
        .get(&proposal_id)
        .expect("origin closure must not delete the admitted archive output");
    assert_eq!(archived_proposal.status, ProposalStatus::Pending);
    assert!(archived_proposal.evidence_refs.contains(&first_suffix_ref));
    drop(closed_archive);

    tokio::spawn(async move {
    // Restore the original R1 Git directory only for the ordinary archive
    // caller. The origin remains closed; this proves its archived proposal is
    // still readable by its original legal scope, without granting R2 access.
    let replacement_git_dir = temp.path().join("held-replacement-git");
    let replacement_report = evertrace_engine::repository::observe_session_source_report(
        transcript.to_str().unwrap(),
        session,
        None,
        "archived-replacement-scope-denied",
    )
    .unwrap();
    *report.write().await = Some(replacement_report.clone());
    let replacement_grant = bindings
        .issue_with_report(
            evertrace_engine::McpBindingIssue {
                session_id: session.into(),
                turn_id: "closed-origin-r2-scope".into(),
                tool_use_id: "archived-proposal-get-r2".into(),
                agent_id: None,
                action: "get".into(),
                workspace: "@active".into(),
                input: proposal_id.to_string(),
                refs: vec![],
                launcher_protocol_revision: 1,
            },
            Some(Arc::new(replacement_report.clone())),
        )
        .unwrap();
    let replacement_get = tokio::time::timeout(
        Duration::from_secs(2),
        mcp.handle(
            "source-start-cross-session",
            evertrace_engine::McpServiceRequest {
                request_id: RequestId::new_v7(),
                action: evertrace_engine::McpServiceAction::Get,
                workspace: replacement_grant.bound_workspace,
                input: proposal_id.to_string(),
                refs: vec![],
                client_cwd: workspace.to_str().unwrap().into(),
            },
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        replacement_get.items.is_empty(),
        "the R2 replacement caller must not inherit archived R1 scope: {:?}",
        replacement_get.items
    );
    fs::rename(&git_dir, &replacement_git_dir).unwrap();
    fs::rename(&held_git_dir, &git_dir).unwrap();
    let archive_report = evertrace_engine::repository::observe_session_source_report(
        transcript.to_str().unwrap(),
        session,
        None,
        "archived-original-scope-read",
    )
    .unwrap();
    catalog.refresh(&archive_report).await.unwrap();
    let archive_state = writer.project().await.unwrap();
    let archive_repository_view = RepositoryCurrentView::from_snapshot(&archive_state).unwrap();
    let active_archive_worktrees = archive_repository_view
        .worktrees
        .values()
        .filter(|value| {
            value.lifecycle == evertrace_domain::repository::WorktreeLifecycle::Active
                && value.current_path.as_deref() == workspace.to_str()
        })
        .map(|value| (value.worktree_instance_id, value.repository_instance_id))
        .collect::<Vec<_>>();
    let archive_receipt = projected_source_receipts(&archive_state)
        .find(|receipt| receipt.source_observation_id.to_string() == first_suffix_ref)
        .unwrap();
    assert_eq!(active_archive_worktrees.len(), 2);
    let original_archive_repository = archive_receipt
        .repository_instance_id
        .expect("the original receipt retains its repository identity");
    let original_archive_worktree = archive_receipt
        .worktree_instance_id
        .expect("the original receipt retains its worktree identity");
    assert!(
        active_archive_worktrees
            .contains(&(original_archive_worktree, original_archive_repository))
    );
    assert!(archive_receipt.worktree_instance_id.is_some_and(|id| {
        evertrace_engine::repository::read_report_repository_trust(
            &archive_report,
            &archive_repository_view,
            id,
        )
        .state
            == evertrace_codex::policy::RepositoryTrustState::Trusted
    }));
    drop(archive_state);
    *report.write().await = Some(archive_report.clone());
    let archive_get = tokio::time::timeout(
        Duration::from_secs(2),
        mcp.handle(
            "source-start-cross-session",
            evertrace_engine::McpServiceRequest {
                request_id: RequestId::new_v7(),
                action: evertrace_engine::McpServiceAction::Get,
                workspace: original_archive_worktree.to_string(),
                input: proposal_id.to_string(),
                refs: vec![],
                client_cwd: workspace.to_str().unwrap().into(),
            },
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(archive_get.scope, original_archive_worktree.to_string());
    fs::rename(&git_dir, &held_git_dir).unwrap();
    fs::rename(&replacement_git_dir, &git_dir).unwrap();
    *report.write().await = Some(replacement_report);
    assert!(
        archive_get.items.iter().any(|item| {
            item.object_ref == Some(proposal_id.to_string())
                && item.content_trust == evertrace_domain::evidence::ContentTrust::AgentClaim
        }),
        "R1 archived Get returned: {archive_get:?}"
    );
    assert!(
        writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap()
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .closed,
        "archived Get must not reopen the closed origin"
    );

    let closed_append = serde_json::json!({
        "timestamp": "2026-10-06T00:04:01Z",
        "type": "event_msg",
        "payload": {
            "type": "item_completed",
            "thread_id": session,
            "turn_id": "turn-after-origin-close",
            "item": {
                "type": "UserMessage",
                "id": "user-after-origin-close",
                "content": [{"type":"text","text":"must remain outside the closed prospective source","text_elements":[]}]
            },
            "completed_at_ms": 1_791_245_041_000_i64
        }
    })
    .to_string();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap();
    writeln!(file, "{closed_append}").unwrap();
    drop(file);
    let after_close_end = fs::metadata(&transcript).unwrap().len();
    assert!(after_close_end > appended_end);
    catalog.refresh(&start_report).await.unwrap();
    let closed_after_append = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        closed_after_append.current.metadata.file_size,
        after_close_end
    );
    assert!(
        closed_after_append
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .closed
    );
    assert_eq!(
        closed_after_append
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .record_start,
        Some(fence)
    );
    assert_eq!(
        closed_after_append.current.body_state,
        SessionBodyState::Partial
    );
    assert!(closed_after_append.job.is_none());
    assert_eq!(
        projected_source_receipts(&writer.project().await.unwrap())
            .filter(|receipt| receipt.source_instance_id.as_str() == source)
            .count(),
        receipt_count_before_close,
        "an append observed after closure must not auto-admit future body bytes"
    );

    let watermark_before_closed_queue = closed_after_append.watermark.clone();
    let receipts_before_closed_queue = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| receipt.source_instance_id.as_str() == source)
        .count();
    assert_eq!(
        admin
            .handle(
                RequestId::new_v7(),
                session,
                SessionImportAdminAction::QueueImport,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_micros() as i64,
            )
            .await
            .unwrap(),
        SessionImportAdminOutcome::Queued
    );
    let mut requeued_records = 0;
    let mut requeued_completed = false;
    for _ in 0..24 {
        let progress = worker.process_checkpoint(&source, budget).await.unwrap();
        requeued_records += progress.records;
        if progress.completed {
            requeued_completed = true;
            break;
        }
    }
    assert!(
        requeued_completed,
        "a closed admitted source can finalize again"
    );
    assert_eq!(
        requeued_records, 0,
        "an explicit queue cannot import bytes appended after origin closure"
    );
    let completed = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.current.body_state, SessionBodyState::Partial);
    assert_eq!(completed.current.metadata.file_size, after_close_end);
    assert!(
        completed
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .closed
    );
    assert_eq!(
        completed.current.access_decision,
        Some(evertrace_store::SessionAccessDecision::Approved)
    );
    assert!(completed.job.is_none());
    assert_eq!(completed.watermark, watermark_before_closed_queue);
    let completed_jobs = RuntimeSchedulerView::from_snapshot(&writer.project().await.unwrap())
        .unwrap()
        .jobs;
    let completed_job = completed_jobs
        .iter()
        .find(|job| job.idempotency_key == format!("session_import:{source}"))
        .unwrap();
    assert_eq!(completed_job.state, JobStatus::Succeeded);
    assert_eq!(
        projected_source_receipts(&writer.project().await.unwrap())
            .filter(|receipt| receipt.source_instance_id.as_str() == source)
            .count(),
        receipts_before_closed_queue,
        "closed-source requeue must not append a receipt"
    );
    let watermark = completed.watermark.as_ref().unwrap();
    let earlier = watermark.earlier_prefix.as_ref().unwrap();
    assert_eq!(earlier.fence_byte, fence);
    assert_eq!(earlier.through_byte, fence);
    assert!(earlier.digest.is_some());
    let prefix_page = writer
        .session_import_prefix_page(evertrace_store::SessionImportPrefixRequest {
            source: source.clone(),
            revision: completed.current.metadata.source_revision.clone(),
            after: 0,
            end: fence,
            max_records: 16,
            max_bytes: 1024 * 1024,
        })
        .await
        .unwrap();
    assert_eq!(prefix_page.records.first().unwrap().start, 0);
    assert_eq!(prefix_page.records.last().unwrap().end, fence);
    assert!(
        prefix_page
            .records
            .windows(2)
            .all(|pair| pair[0].end == pair[1].start)
    );
    assert_eq!(suffix_page.records[0].start, fence);
    let archived_receipts = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| receipt.observation_role == ObservationRole::Message)
        .collect::<Vec<_>>();
    let source_receipts = archived_receipts
        .iter()
        .filter(|receipt| receipt.source_instance_id.as_str() == source)
        .collect::<Vec<_>>();
    assert!(
        source_receipts
            .iter()
            .all(|receipt| receipt.source_sequence <= watermark.source_sequence)
    );
    let historical_receipts = archived_receipts
        .iter()
        .filter(|receipt| {
            receipt.source_instance_id.as_str() == source && receipt.source_sequence <= fence
        })
        .collect::<Vec<_>>();
    assert!(!historical_receipts.is_empty());
    assert!(historical_receipts.iter().all(|receipt| {
        receipt.repository_instance_id.is_none() && receipt.worktree_instance_id.is_none()
    }));

    // A physical transcript replacement is a new source revision, not an
    // extension of the closed origin. Its first post-observation record must
    // still flow through the normal catalog refresh and worker.
    let before_replacement = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    let old_revision = before_replacement.current.metadata.source_revision.clone();
    let old_restrictions = before_replacement
        .current
        .metadata
        .read_restrictions()
        .collect::<Vec<_>>();
    let old_origin_snapshot = before_replacement
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .unwrap()
        .snapshot_ref;
    let replacement_head = source_fixture_git(&workspace, &["rev-parse", "HEAD"]);
    let replacement_header = serde_json::json!({
        "timestamp":"2026-10-06T00:06:00Z",
        "type":"session_meta",
        "payload":{"id":session,"session_id":session,"cwd":workspace,"git":{"commit_hash":replacement_head}}
    })
    .to_string();
    let staged_transcript = dated.join(format!("replacement-{session}.jsonl"));
    fs::write(&staged_transcript, format!("{replacement_header}\n")).unwrap();
    fs::rename(&staged_transcript, &transcript).unwrap();
    let replacement_catalog_report = observe_session_catalog_report(
        transcript.to_str(),
        session,
        "source-start-transcript-replacement",
        None,
    )
    .unwrap();
    catalog.refresh(&replacement_catalog_report).await.unwrap();
    let replaced = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(replaced.current.metadata.source_revision, old_revision);
    assert_eq!(
        replaced.current.body_state,
        SessionBodyState::SourceReplaced
    );
    assert!(replaced.current.metadata.prospective_origin.is_none());
    assert!(replaced.watermark.is_none());
    assert!(old_restrictions.iter().all(|restriction| {
        replaced
            .current
            .metadata
            .read_restrictions()
            .any(|current| current == *restriction)
    }));
    let replacement_observation = RequestId::new_v7();
    let replacement_observation_ref =
        format!("native_session_source_observation:{replacement_observation}");
    let replacement_start_report = evertrace_engine::repository::observe_session_source_report(
        transcript.to_str().unwrap(),
        session,
        None,
        &replacement_observation_ref,
    )
    .unwrap();
    assert!(
        catalog
            .observe_native_session_source(
                replacement_observation,
                &replacement_start_report,
                session,
                transcript.to_str().unwrap(),
                &replacement_observation_ref,
            )
            .await
            .unwrap()
    );
    let newly_observed = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    let new_origin = newly_observed
        .current
        .metadata
        .prospective_origin
        .as_ref()
        .expect("the actual new source observation establishes the replacement origin");
    let replacement_fence = replacement_header.len() as u64 + 1;
    assert!(!new_origin.closed);
    assert_ne!(new_origin.snapshot_ref, old_origin_snapshot);
    assert_eq!(new_origin.observed_end, replacement_fence);
    assert_eq!(new_origin.record_start, Some(replacement_fence));
    let replacement_snapshot =
        RepositoryCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert!(replacement_snapshot.snapshots.values().any(|snapshot| {
        snapshot.worktree_snapshot_id == new_origin.snapshot_ref
            && snapshot
                .evidence_refs
                .contains(&replacement_observation_ref)
    }));
    let replacement_message = serde_json::json!({
        "timestamp":"2026-10-06T00:07:00Z",
        "type":"event_msg",
        "payload":{"type":"item_completed","thread_id":session,"turn_id":"replacement-first-full-record","item":{"type":"UserMessage","id":"replacement-first-full-record","content":[{"type":"text","text":"The first complete record belongs only to the replacement transcript revision.","text_elements":[]}]},"completed_at_ms":1_791_245_220_000_i64}
    })
    .to_string();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap();
    writeln!(file, "{replacement_message}").unwrap();
    drop(file);
    let replacement_end = fs::metadata(&transcript).unwrap().len();
    *report.write().await = Some(replacement_start_report.clone());
    catalog.refresh(&replacement_start_report).await.unwrap();
    let appended_replacement = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        appended_replacement.current.metadata.file_size,
        replacement_end
    );
    assert_eq!(
        appended_replacement
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap()
            .record_start,
        Some(replacement_fence)
    );
    let mut replacement_complete = false;
    for _ in 0..8 {
        if worker
            .process_checkpoint(&source, budget)
            .await
            .unwrap()
            .completed
        {
            replacement_complete = true;
            break;
        }
    }
    assert!(
        replacement_complete,
        "the normal worker imports the first full suffix record"
    );
    let after_replacement_import = writer
        .session_import_context(&source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after_replacement_import.current.metadata.source_revision,
        replaced.current.metadata.source_revision
    );
    assert_eq!(
        after_replacement_import
            .watermark
            .as_ref()
            .unwrap()
            .source_sequence,
        replacement_end
    );
    assert_eq!(
        after_replacement_import
            .watermark
            .as_ref()
            .unwrap()
            .earlier_prefix
            .as_ref()
            .unwrap()
            .fence_byte,
        replacement_fence
    );
    let replacement_receipts = projected_source_receipts(&writer.project().await.unwrap())
        .filter(|receipt| {
            receipt.source_instance_id.as_str() == source
                && receipt.source_revision == replaced.current.metadata.source_revision
        })
        .collect::<Vec<_>>();
    assert_eq!(replacement_receipts.len(), 1);
    assert_eq!(replacement_receipts[0].source_sequence, replacement_end);
    assert!(
        replacement_receipts[0]
            .source_byte_range
            .as_ref()
            .is_some_and(|range| range.start >= replacement_fence)
    );
    assert_ne!(
        replacement_receipts[0].source_observation_id.to_string(),
        first_suffix_ref
    );
    let replacement_revision_events = writer
        .project()
        .await
        .unwrap()
        .data_rows()
        .filter_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SourceRevisionRecorded(event)
                    if event.source_instance_id.as_str() == source
                        && event.source_revision == replaced.current.metadata.source_revision =>
                {
                    Some(event)
                }
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(replacement_revision_events.len(), 1);
    assert_eq!(
        replacement_revision_events[0].mode,
        evertrace_domain::evidence::SourceRevisionMode::Replacement
    );
    let replacement_semantics =
        SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert!(
        replacement_semantics
            .proposals
            .get(&proposal_id)
            .is_some_and(|value| {
                value.status == ProposalStatus::Pending
                    && value.evidence_refs.contains(&first_suffix_ref)
            })
    );

    drop(admin);
    drop(mcp);
    drop(summary_scheduler);
    drop(revoking_scheduler);
    drop(scheduler);
    drop(config_reload);
    drop(cold_worker);
    drop(closure_worker);
    drop(worker);
    drop(catalog);
    drop(writer);
    task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
    })
    .await
    .unwrap();
    })
    .await
    .unwrap();
    })
    .await;
}
