use std::{collections::BTreeSet, path::Path, sync::Arc, time::Duration};

use evertrace_capture::{
    CaptureRecordInput, CaptureRuntime, DeviceKeyStore, RUNTIME_SNAPSHOT_VERSION, RecoveryGateMode,
    RuntimeSnapshot,
};
use evertrace_codex::binding::{BINDING_PROTOCOL_REVISION, CanonicalBindingCall, PublicWorkspace};
use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceInstanceId,
        SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole,
        source_observation_id,
    },
    ids::{CommandId, RepositoryId, RequestId, TaskId},
    query::{
        FacetParseStatus, LifecycleBoundary, Polarity, QuantityConstraint, QueryFacetSet,
        RetrievalBudget, SearchContext, SearchIntent, SuppressionSnapshot, TemporalMode,
    },
    repository::{FilesystemIdentity, GitObjectFormat, PathObservation, RepositoryInstance},
    revision::RevisionId,
    semantic::{
        ApplicabilityExpr, AtomDraft, AtomKind, AtomProvenance, AtomScope, AtomValue,
        ConstraintExpr, ConstraintField, EpistemicStatus, SemanticQualifier, ValidityInterval,
    },
    work::{Task, TaskIdentityConfidence, TaskLifecycle, TaskScopeMembership},
};
use evertrace_engine::{
    EvidenceIngestor, McpActionService, McpBindingAuthority, McpBindingIssue, McpScopeMechanism,
    McpServiceAction, McpServiceRequest, McpServiceStatus, open_writer,
    search::ProductionSearch,
    semantic::{AtomAuthorityBasis, AtomMaterialization, materialize_atom},
    spawn_writer,
    work::{WorkCommandContext, task::create_task},
};
use evertrace_protocol::{
    LocalServer, ServerOptions,
    command::{Command, McpBindingIssueCommand},
    dto::ClientKind,
    error::ErrorCode,
    mcp::{
        MCP_PROTOCOL_VERSION, MCP_TOOL_DESCRIPTION, MCP_TOOL_NAME, McpAction, McpToolInput,
        tool_definition,
    },
    request_mcp_binding_sync,
    response::{McpBindingIssuedResponse, Response},
};
use evertrace_store::{JournalCommand, JournalEventDraft, JournalPayload, SearchIndex};
use tempfile::TempDir;
use tokio::sync::watch;

fn call(workspace: &str, input: &str, refs: &[&str]) -> CanonicalBindingCall {
    CanonicalBindingCall {
        action: "search".into(),
        workspace: workspace.into(),
        input: input.into(),
        refs: refs.iter().map(|value| (*value).into()).collect(),
    }
}

fn issue(call: &CanonicalBindingCall, session: &str) -> McpBindingIssue {
    McpBindingIssue {
        session_id: session.into(),
        turn_id: "turn".into(),
        tool_use_id: "tool".into(),
        agent_id: None,
        action: call.action.clone(),
        workspace: call.workspace.clone(),
        input: call.input.clone(),
        refs: call.refs.clone(),
        launcher_protocol_revision: BINDING_PROTOCOL_REVISION,
    }
}

fn authority(root: &std::path::Path) -> McpBindingAuthority {
    McpBindingAuthority::new(DeviceKeyStore::new(root).load_or_create().unwrap())
}

fn tool_input(call: &CanonicalBindingCall) -> McpToolInput {
    McpToolInput {
        action: McpAction::Search,
        workspace: call.workspace.clone(),
        input: call.input.clone(),
        refs: call.refs.clone(),
    }
}

fn runtime_snapshot(root: &Path) -> RuntimeSnapshot {
    RuntimeSnapshot {
        snapshot_version: RUNTIME_SNAPSHOT_VERSION,
        generation: 1,
        device_key_dir: root.join("keys"),
        cas_dir: root.join("cas"),
        spool_dir: root.join("spool"),
        main_high_watermark_bytes: 2 << 20,
        main_low_watermark_bytes: 64 << 10,
        max_main_files: 16,
        emergency_slots: 2,
        effective_config_hash: [0x20; 32],
        recovery_gate: RecoveryGateMode::Disabled,
        recovery_adapter_manifest_id: None,
        recovery_classifier_revision: 1,
        recovery_socket_path: root.join("runtime/evertraced-v1.sock"),
        recovery_preflight_timeout_ms: 250,
        recovery_max_bundle_bytes: 4 << 20,
        recovery_max_untracked_file_bytes: 1 << 20,
        recovery_max_untracked_total_bytes: 2 << 20,
    }
}

fn repository(id: RepositoryId, path: &str) -> RepositoryInstance {
    RepositoryInstance {
        repository_id: id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: path.into(),
        path_history: vec![PathObservation {
            path: path.into(),
            first_observed_at_us: 1,
            last_observed_at_us: 1,
            evidence_refs: vec!["repo-evidence".into()],
        }],
        git_common_dir_path: Some(format!("{path}/.git")),
        common_dir_filesystem: Some(FilesystemIdentity {
            device: 1,
            inode: 1,
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: Vec::new(),
        derived_from: None,
        identity_evidence_refs: vec!["repo-identity".into()],
        recorded_at_us: 1,
    }
}

fn task(id: TaskId, repository_id: RepositoryId) -> Task {
    Task {
        task_id: id,
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec!["request:s20".into()],
        canonical_goal: "task-route needle-s20".into(),
        scope_memberships: vec![TaskScopeMembership {
            repository_instance_id: Some(repository_id),
            worktree_instance_ids: Vec::new(),
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
    }
}

fn atom_command(
    label: &str,
    text: &str,
    scope: AtomScope,
    occurred_at_us: i64,
) -> (JournalCommand, RevisionId) {
    let observation = source_observation_id(
        &SourceInstanceId::parse("source-s20").unwrap(),
        &SourceRevision::parse("revision-s20").unwrap(),
        &SourceRecordIdentity::parse(label).unwrap(),
    )
    .unwrap();
    let atom = materialize_atom(
        AtomMaterialization {
            draft: AtomDraft {
                kind: AtomKind::Claim,
                epistemic_status: EpistemicStatus::Unverified,
                value: AtomValue {
                    text: text.into(),
                    subject: "s20".into(),
                    predicate: "records".into(),
                    object: None,
                    qualifiers: vec![SemanticQualifier {
                        name: "suite".into(),
                        value: "s20".into(),
                    }],
                    critical_revision_refs: Vec::new(),
                },
                scope,
                applicability_expr: ApplicabilityExpr::Constraint(ConstraintExpr::Exists {
                    field: ConstraintField::Phase,
                }),
                validity_interval: ValidityInterval {
                    valid_from_us: 1,
                    valid_until_us: None,
                },
                provenance: vec![AtomProvenance::AgentClaimed],
                source_observation_refs: vec![observation],
                evidence_refs: vec![observation.to_string()],
                supersedes_revision_refs: Vec::new(),
                supports_revision_refs: Vec::new(),
                contradicts_revision_refs: Vec::new(),
            },
            authority_basis: AtomAuthorityBasis::AgentInferred,
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: occurred_at_us,
        },
        None,
    )
    .unwrap();
    let revision = atom.revision_id;
    (
        JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                occurred_at_us,
                [0x20; 32],
                "s20-test-v1",
                JournalPayload::AtomRecorded(Box::new(atom)),
            )],
        )
        .unwrap(),
        revision,
    )
}

fn capture_input(
    label: &str,
    sequence: u64,
    task_id: Option<TaskId>,
    repository_id: Option<RepositoryId>,
) -> CaptureRecordInput {
    CaptureRecordInput {
        spool_record_id: Some(format!("s20-{label}")),
        source_observation_id_hint: None,
        source_instance_id: "source-s20".into(),
        source_revision: "revision-s20".into(),
        source_record_identity: Some(label.into()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: "s20-test".into(),
        source_ref: "source-s20".into(),
        session_ref: "session-s20".into(),
        turn_ref: Some(format!("turn-{sequence}")),
        tool_ref: None,
        source_sequence: sequence,
        source_sequence_origin: Some(1),
        task_id: task_id.map(|value| value.to_string()),
        repository_instance_id: repository_id.map(|value| value.to_string()),
        worktree_instance_id: None,
        source_byte_range: None,
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: None,
        observation_role: ObservationRole::Result,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            pairing_role: ObservationRole::Result,
            field_provenance: Vec::new(),
            adapter_manifest_ref: "s20-test".into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: Vec::new(),
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: SourceRole::Assistant,
        content_trust: ContentTrust::AgentClaim,
        capture_completeness: CaptureCompleteness::Complete,
        surface_eligible: true,
        adapter_revision: 1,
        adapter_manifest_ref: "s20-test".into(),
        eligible_event_manifest_ref: "s20-test".into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: Some(i64::try_from(sequence).unwrap()),
        raw_payload: format!("needle-s20 {label}").into_bytes(),
    }
}

#[test]
fn one_tool_schema_and_workspace_forms_are_closed() {
    assert_eq!(MCP_PROTOCOL_VERSION, "2025-11-25");
    let tool = tool_definition();
    assert_eq!(tool["name"], MCP_TOOL_NAME);
    assert_eq!(tool["description"], MCP_TOOL_DESCRIPTION);
    assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    assert_eq!(
        tool["inputSchema"]["properties"]["input"]["maxLength"],
        4096
    );
    assert_eq!(tool["inputSchema"]["properties"]["refs"]["maxItems"], 32);
    assert!(
        serde_json::from_value::<McpToolInput>(serde_json::json!({
            "action": "Forget", "workspace": "@active", "input": "x"
        }))
        .is_err()
    );
    assert!(PublicWorkspace::parse("@active").is_ok());
    assert!(PublicWorkspace::parse("path_hint:/trusted/workspace").is_ok());
    assert!(PublicWorkspace::parse("path_hint:relative").is_err());
    assert!(PublicWorkspace::parse("@bound:v1:01234567890123456789012345678901").is_err());
}

#[test]
fn claim_is_atomic_exact_replay_safe_and_leaves_no_connection_authority() {
    let temp = TempDir::new().unwrap();
    let authority = Arc::new(authority(&temp.path().join("device")));
    let original = call("@active", "query", &["atom:a", "atom:b"]);
    let grant = authority.issue(issue(&original, "session-a")).unwrap();
    let bound = call(&grant.bound_workspace, "query", &["atom:a", "atom:b"]);
    let left = Arc::clone(&authority);
    let left_call = bound.clone();
    let right = Arc::clone(&authority);
    let right_call = bound.clone();
    let first = std::thread::spawn(move || left.resolve(&left_call));
    let second = std::thread::spawn(move || right.resolve(&right_call));
    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        authority
            .resolve(&call("@active", "next", &[]))
            .unwrap()
            .mechanism,
        McpScopeMechanism::CwdOnly
    );
    assert_eq!(
        authority
            .resolve(&call("@active", "next", &[]))
            .unwrap()
            .mechanism,
        McpScopeMechanism::CwdOnly
    );

    let reordered = authority.issue(issue(&original, "session-b")).unwrap();
    assert!(
        authority
            .resolve(&call(
                &reordered.bound_workspace,
                "query",
                &["atom:b", "atom:a"]
            ))
            .is_err()
    );
    assert!(
        authority
            .resolve(&call(
                &reordered.bound_workspace,
                "query",
                &["atom:a", "atom:b"]
            ))
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hook_sync_issue_uses_existing_uds_handshake_and_hook_client_kind() {
    let temp = TempDir::new().unwrap();
    let authority = authority(&temp.path().join("device"));
    let server = LocalServer::bind(temp.path(), ServerOptions::new("s20-test")).unwrap();
    let socket = server.socket_path().to_path_buf();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_authority = authority.clone();
    let task = tokio::spawn(server.run_dispatch_with_context(
        shutdown_rx,
        move |context, _request_id, command| {
            let authority = server_authority.clone();
            async move {
                if context.client_kind != ClientKind::Hook {
                    return Err(ErrorCode::Untrusted);
                }
                let Command::IssueMcpBinding(issue) = command else {
                    return Err(ErrorCode::InvalidInput);
                };
                let grant = authority
                    .issue(McpBindingIssue {
                        session_id: issue.session_id,
                        turn_id: issue.turn_id,
                        tool_use_id: issue.tool_use_id,
                        agent_id: issue.agent_id,
                        action: issue.original_input.action.as_str().into(),
                        workspace: issue.original_input.workspace,
                        input: issue.original_input.input,
                        refs: issue.original_input.refs,
                        launcher_protocol_revision: issue.launcher_protocol_revision,
                    })
                    .map_err(|_| ErrorCode::Untrusted)?;
                Ok(Response::McpBindingIssued(McpBindingIssuedResponse {
                    bound_workspace: grant.bound_workspace,
                    expires_at_us: grant.expires_at_us,
                }))
            }
        },
    ));
    let original = call("@active", "query", &[]);
    let wire_issue = McpBindingIssueCommand {
        session_id: "session-wire".into(),
        turn_id: "turn-wire".into(),
        tool_use_id: "tool-wire".into(),
        agent_id: None,
        original_input: tool_input(&original),
        launcher_protocol_revision: BINDING_PROTOCOL_REVISION,
    };
    let response = tokio::task::spawn_blocking(move || {
        request_mcp_binding_sync(&socket, "s20-hook", wire_issue, Duration::from_secs(1))
    })
    .await
    .unwrap()
    .unwrap();
    assert!(response.bound_workspace.starts_with("@bound:v1:"));
    assert!(
        authority
            .resolve(&call(&response.bound_workspace, "query", &[]))
            .is_ok()
    );
    shutdown_tx.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_store_scope_union_and_four_actions_preserve_authority_boundaries() {
    let temp = TempDir::new().unwrap();
    let runtime = runtime_snapshot(temp.path());
    let store = temp.path().join("store");
    let writer = open_writer(&store).await.unwrap();
    let (handle, writer_task) = spawn_writer(writer, 8).unwrap();
    let repository_id = RepositoryId::new_v7();
    let other_repository = RepositoryId::new_v7();
    let task_id = TaskId::new_v7();
    let other_task = TaskId::new_v7();
    for (sequence, payload) in [
        (
            1,
            JournalPayload::RepositoryInstanceRecorded(Box::new(repository(
                repository_id,
                "/s20/repository",
            ))),
        ),
        (
            2,
            JournalPayload::RepositoryInstanceRecorded(Box::new(repository(
                other_repository,
                "/s20/other",
            ))),
        ),
    ] {
        handle
            .commit(
                JournalCommand::new(
                    CommandId::new_v7(),
                    vec![JournalEventDraft::runtime(
                        sequence,
                        [0x20; 32],
                        "s20-test-v1",
                        payload,
                    )],
                )
                .unwrap(),
                sequence,
            )
            .await
            .unwrap();
    }
    for (sequence, value) in [
        (3, task(task_id, repository_id)),
        (4, task(other_task, other_repository)),
    ] {
        handle
            .commit(
                create_task(
                    WorkCommandContext {
                        command_id: CommandId::new_v7(),
                        occurred_at_us: sequence,
                        effective_config_hash: [0x20; 32],
                        algorithm_revision: "s20-test-v1",
                    },
                    value,
                )
                .unwrap(),
                sequence,
            )
            .await
            .unwrap();
    }
    let key = DeviceKeyStore::new(&runtime.device_key_dir)
        .load_or_create()
        .unwrap();
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    capture
        .capture(capture_input(
            "task-route",
            1,
            Some(task_id),
            Some(repository_id),
        ))
        .unwrap();
    capture
        .capture(capture_input("repo-route", 2, None, Some(repository_id)))
        .unwrap();
    capture
        .capture(capture_input(
            "unrelated",
            3,
            Some(other_task),
            Some(other_repository),
        ))
        .unwrap();
    drop(capture);
    assert_eq!(
        EvidenceIngestor::new(runtime.clone(), handle.clone(), [0x20; 32], "s20-test-v1")
            .unwrap()
            .drain_once()
            .await
            .unwrap()
            .committed_frames,
        3
    );
    let (task_atom, task_revision) = atom_command(
        "task-route",
        "needle-s20 task continuity",
        AtomScope::Task { task_id },
        5,
    );
    let (repo_atom, repo_revision) = atom_command(
        "repo-route",
        "needle-s20 repository memory",
        AtomScope::Repository {
            repository_instance_id: repository_id,
        },
        6,
    );
    let (unrelated_atom, unrelated_revision) = atom_command(
        "unrelated",
        "needle-s20 unrelated",
        AtomScope::Task {
            task_id: other_task,
        },
        7,
    );
    for (sequence, command) in [(5, task_atom), (6, repo_atom), (7, unrelated_atom)] {
        handle.commit(command, sequence).await.unwrap();
    }
    let projected = handle.project().await.unwrap();
    assert!(
        projected
            .rows
            .iter()
            .any(|row| row.current_revision_id.as_deref()
                == Some(task_revision.to_string().as_str())),
        "{:?}",
        projected
            .rows
            .iter()
            .map(|row| (&row.object_kind, &row.current_revision_id))
            .collect::<Vec<_>>()
    );

    let search_index = SearchIndex::open(&store).await.unwrap();
    let search_rows = search_index.all().await.unwrap();
    assert!(
        search_rows
            .iter()
            .any(|row| row.candidate_id.as_deref() == Some(task_revision.to_string().as_str())),
        "{:?}",
        search_rows
            .iter()
            .map(|row| (
                &row.candidate_id,
                &row.text,
                &row.task_id,
                &row.repository_id,
                &row.lifecycle
            ))
            .collect::<Vec<_>>()
    );
    let task_search_row = search_rows
        .iter()
        .find(|row| row.candidate_id.as_deref() == Some(task_revision.to_string().as_str()))
        .unwrap();
    assert_eq!(
        task_search_row.task_id.as_deref(),
        Some(task_id.to_string().as_str())
    );
    let repo_search_row = search_rows
        .iter()
        .find(|row| row.candidate_id.as_deref() == Some(repo_revision.to_string().as_str()))
        .unwrap();
    assert_eq!(
        repo_search_row.repository_id.as_deref(),
        Some(repository_id.to_string().as_str())
    );
    let search = ProductionSearch::new(search_index)
        .search(SearchContext {
            intent: SearchIntent::StageAssistance,
            raw_query: "needle".into(),
            query_facets: QueryFacetSet {
                parse_status: FacetParseStatus::Complete,
                exact_identifiers: Vec::new(),
                condition_literals: Vec::new(),
                relation_requirements: Vec::new(),
                polarity: Polarity::Positive,
                explicit_exclusions: Vec::new(),
                temporal_mode: TemporalMode::Current,
                temporal_qualifiers: Vec::new(),
                quantity_constraints: vec![QuantityConstraint::ResultLimit { limit: 3 }],
                scope_boundary: None,
                source_boundary: None,
                answer_shape: None,
                lifecycle_boundary: LifecycleBoundary::Any,
            },
            task_id: Some(task_id),
            repository_id: Some(repository_id),
            worktree_id: None,
            suppression: SuppressionSnapshot::Current {
                generation: 0,
                ref_hashes: BTreeSet::new(),
            },
            budget: RetrievalBudget {
                candidates_remaining: 3,
                tokens_remaining: 1_200,
                latency_us_remaining: 30_000_000,
                hops_remaining: 0,
                follow_ups_remaining: 0,
            },
        })
        .await
        .unwrap();
    let candidates = search
        .candidates
        .iter()
        .map(|candidate| candidate.candidate_id.as_str())
        .collect::<BTreeSet<_>>();
    assert!(
        candidates.contains(task_revision.to_string().as_str()),
        "candidates={candidates:?} result={search:?}"
    );
    assert!(
        candidates.contains(repo_revision.to_string().as_str()),
        "{candidates:?}"
    );
    assert!(!candidates.contains(unrelated_revision.to_string().as_str()));

    let service = McpActionService::open(
        McpBindingAuthority::new(key),
        &store,
        handle.clone(),
        runtime.clone(),
    )
    .await
    .unwrap();
    let workspace = repository_id.to_string();
    for (case, action, case_workspace, input, refs) in [
        (
            "explicit_add_without_task",
            McpServiceAction::Add,
            workspace.clone(),
            "unbound annotation".to_owned(),
            Vec::new(),
        ),
        (
            "cwd_add_without_task",
            McpServiceAction::Add,
            "@active".to_owned(),
            "unbound annotation".to_owned(),
            Vec::new(),
        ),
        (
            "foreign_task",
            McpServiceAction::Add,
            workspace.clone(),
            "foreign task annotation".to_owned(),
            vec![other_task.to_string()],
        ),
        (
            "multiple_tasks",
            McpServiceAction::Add,
            workspace.clone(),
            "ambiguous task annotation".to_owned(),
            vec![task_id.to_string(), other_task.to_string()],
        ),
        (
            "explicit_due",
            McpServiceAction::Search,
            workspace.clone(),
            "@due".to_owned(),
            Vec::new(),
        ),
        (
            "cwd_due",
            McpServiceAction::Search,
            "@active".to_owned(),
            "@due".to_owned(),
            Vec::new(),
        ),
    ] {
        let before = handle.project().await.unwrap();
        let rejected = service
            .handle(
                "connection-actions",
                McpServiceRequest {
                    request_id: RequestId::new_v7(),
                    action,
                    workspace: case_workspace,
                    input,
                    refs,
                    client_cwd: "/s20/repository".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            rejected.status,
            McpServiceStatus::ScopeUnresolved,
            "{case}: {rejected:?}"
        );
        assert_eq!(
            handle.project().await.unwrap(),
            before,
            "{case} wrote state"
        );
    }
    let oversized = service
        .handle(
            "connection-actions",
            McpServiceRequest {
                request_id: RequestId::new_v7(),
                action: McpServiceAction::Search,
                workspace: workspace.clone(),
                input: "x".repeat(4_097),
                refs: Vec::new(),
                client_cwd: "/s20/repository".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(oversized.status, McpServiceStatus::InvalidInput);
    let action_search = service
        .handle(
            "connection-actions",
            McpServiceRequest {
                request_id: RequestId::new_v7(),
                action: McpServiceAction::Search,
                workspace: workspace.clone(),
                input: "needle".into(),
                refs: Vec::new(),
                client_cwd: "/s20/repository".into(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        action_search.status,
        McpServiceStatus::Ok | McpServiceStatus::Partial
    ));
    assert!(action_search.items.iter().any(|item| {
        item.object_revision_ref.as_deref() == Some(repo_revision.to_string().as_str())
            && item.partition == evertrace_engine::McpItemPartition::Evidence
            && item.authority.as_deref() == Some("agent_inferred")
    }));
    assert!(!action_search.items.iter().any(|item| {
        item.object_revision_ref.as_deref() == Some(unrelated_revision.to_string().as_str())
    }));
    assert!(action_search.next_refs.len() <= 32);
    let projected = handle.project().await.unwrap();
    let base = projected
        .rows
        .iter()
        .find(|row| row.current_revision_id.as_deref() == Some(repo_revision.to_string().as_str()))
        .and_then(|row| row.payload_json.as_deref())
        .and_then(|payload| serde_json::from_str::<JournalPayload>(payload).ok())
        .and_then(|payload| match payload {
            JournalPayload::AtomRecorded(atom) => Some(*atom),
            _ => None,
        })
        .unwrap();
    let repo_atom_id = base.atom_id;
    let mut successor = base.clone();
    successor.revision_id = RevisionId::new_v7();
    successor.parent_revision_id = Some(base.revision_id);
    successor.value.text = "needle-s20 repository memory successor".into();
    successor.created_at_us = 8;
    base.validate_successor(&successor).unwrap();
    let successor_revision = successor.revision_id;
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    8,
                    [0x20; 32],
                    "s20-test-v1",
                    JournalPayload::AtomRecorded(Box::new(successor)),
                )],
            )
            .unwrap(),
            8,
        )
        .await
        .unwrap();
    let get = service
        .handle(
            "connection-actions",
            McpServiceRequest {
                request_id: RequestId::new_v7(),
                action: McpServiceAction::Get,
                workspace: workspace.clone(),
                input: repo_revision.to_string(),
                refs: Vec::new(),
                client_cwd: "/s20/repository".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(get.status, McpServiceStatus::Ok);
    assert_eq!(get.items.len(), 1);
    assert_eq!(
        get.items[0].partition,
        evertrace_engine::McpItemPartition::Evidence
    );
    assert_eq!(
        get.items[0].object_revision_ref.as_deref(),
        Some(repo_revision.to_string().as_str())
    );
    assert!(
        get.items[0]
            .text
            .as_deref()
            .unwrap()
            .contains("repository memory")
    );
    assert!(!get.items[0].text.as_deref().unwrap().contains("successor"));
    let stable_get = service
        .handle(
            "connection-actions",
            McpServiceRequest {
                request_id: RequestId::new_v7(),
                action: McpServiceAction::Get,
                workspace: workspace.clone(),
                input: repo_atom_id.to_string(),
                refs: Vec::new(),
                client_cwd: "/s20/repository".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(stable_get.status, McpServiceStatus::Ok);
    assert_eq!(stable_get.items.len(), 1);
    assert_eq!(
        stable_get.items[0].object_revision_ref.as_deref(),
        Some(successor_revision.to_string().as_str())
    );
    assert!(
        stable_get.items[0]
            .text
            .as_deref()
            .unwrap()
            .contains("repository memory successor")
    );

    let before_add = handle.project().await.unwrap();
    let atom_count = before_add
        .rows
        .iter()
        .filter(|row| row.object_kind.as_deref() == Some("atom_revision"))
        .count();
    let add = service
        .handle(
            "connection-actions",
            McpServiceRequest {
                request_id: RequestId::new_v7(),
                action: McpServiceAction::Add,
                workspace: workspace.clone(),
                input: "agent annotation only".into(),
                refs: vec![task_id.to_string()],
                client_cwd: "/s20/repository".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(add.status, McpServiceStatus::Ok);
    assert_eq!(add.completeness, "l0_only");
    assert_eq!(
        add.items[0].text.as_deref(),
        Some("{\"authorization_status\":\"unverified\",\"proposal_created\":false}")
    );
    assert!(
        !add.items[0]
            .text
            .as_deref()
            .unwrap()
            .contains("agent annotation only")
    );
    assert!(
        add.items[0]
            .source_revision_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("mcp-v1-"))
    );
    let observation_ref = add.items[0].object_ref.clone().unwrap();
    let after_add = handle.project().await.unwrap();
    assert!(after_add.rows.iter().any(|row| {
        row.object_kind.as_deref() == Some("source_observation")
            && row.object_id.as_deref() == Some(observation_ref.as_str())
    }));
    assert!(after_add.rows.iter().any(|row| {
        row.payload_json
            .as_deref()
            .and_then(|value| serde_json::from_str::<JournalPayload>(value).ok())
            .is_some_and(|payload| {
                matches!(payload,
                JournalPayload::SourceReceiptRecorded(receipt)
                    if receipt.source_observation_id.to_string() == observation_ref
                        && receipt.task_id == Some(task_id)
                        && receipt.repository_instance_id == Some(repository_id))
            })
    }));
    assert_eq!(
        after_add
            .rows
            .iter()
            .filter(|row| row.object_kind.as_deref() == Some("atom_revision"))
            .count(),
        atom_count
    );

    let raw_get = service
        .handle(
            "connection-actions",
            McpServiceRequest {
                request_id: RequestId::new_v7(),
                action: McpServiceAction::Get,
                workspace: workspace.clone(),
                input: observation_ref.clone(),
                refs: Vec::new(),
                client_cwd: "/s20/repository".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(raw_get.status, McpServiceStatus::Ok);
    let raw_metadata = raw_get.items[0].text.as_deref().unwrap();
    assert!(raw_metadata.contains("source_observation_recorded"));
    assert!(raw_metadata.contains("agent_claim"));
    assert!(!raw_metadata.contains("agent annotation only"));
    assert_eq!(
        raw_get.items[0].capture_completeness.as_deref(),
        Some("complete")
    );
    assert!(
        raw_get.items[0]
            .source_revision_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("mcp-v1-"))
    );

    let organize_input = format!(
        "{{\"v\":1,\"op\":\"deprecate\",\"target\":\"{repo_atom_id}\",\"expected_revision\":\"{successor_revision}\",\"patch\":{{}},\"reason\":\"manual review\"}}"
    );
    let before_protected = handle.project().await.unwrap();
    let protected = service
        .handle(
            "connection-actions",
            McpServiceRequest {
                request_id: RequestId::new_v7(),
                action: McpServiceAction::Organize,
                workspace: workspace.clone(),
                input: format!(
                    "{{\"v\":1,\"op\":\"deprecate\",\"target\":\"{repo_atom_id}\",\"expected_revision\":\"{successor_revision}\",\"patch\":{{\"nested\":{{\"authority\":\"user_explicit\"}}}},\"reason\":\"malicious\"}}"
                ),
                refs: vec![observation_ref.clone()],
                client_cwd: "/s20/repository".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(protected.status, McpServiceStatus::Conflict);
    assert_eq!(handle.project().await.unwrap(), before_protected);
    let before_organize = handle.project().await.unwrap();
    let organize = service
        .handle(
            "connection-actions",
            McpServiceRequest {
                request_id: RequestId::new_v7(),
                action: McpServiceAction::Organize,
                workspace: workspace.clone(),
                input: organize_input.clone(),
                refs: vec![observation_ref.clone()],
                client_cwd: "/s20/repository".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(organize.status, McpServiceStatus::Ok, "{organize:?}");
    assert_eq!(organize.completeness, "proposal_only");
    let proposal_ref = organize.items[0].object_ref.clone().unwrap();
    let proposal_revision_ref = organize.items[0].object_revision_ref.clone().unwrap();
    assert_eq!(
        organize.items[0].text.as_deref(),
        Some(
            format!(
                "{{\"target\":\"{repo_atom_id}\",\"operation\":\"deprecate\",\"status\":\"pending\"}}"
            )
            .as_str()
        )
    );
    let after_organize = handle.project().await.unwrap();
    assert!(after_organize.rows.iter().any(|row| {
        row.object_kind.as_deref() == Some("revision_proposal_revision")
            && row.object_id.as_deref() == Some(proposal_ref.as_str())
            && row.current_revision_id.as_deref() == Some(proposal_revision_ref.as_str())
            && row.lifecycle.as_deref() == Some("pending")
    }));
    let duplicate = service
        .handle(
            "connection-actions",
            McpServiceRequest {
                request_id: RequestId::new_v7(),
                action: McpServiceAction::Organize,
                workspace: workspace.clone(),
                input: organize_input,
                refs: vec![observation_ref.clone()],
                client_cwd: "/s20/repository".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(duplicate.status, McpServiceStatus::Ok, "{duplicate:?}");
    assert_eq!(duplicate.completeness, "no_delta");
    assert!(duplicate.items.is_empty());
    assert_eq!(duplicate.warnings, ["proposal_no_delta"]);
    assert_eq!(
        handle.project().await.unwrap().frontier,
        after_organize.frontier
    );
    assert_eq!(
        after_organize
            .rows
            .iter()
            .filter(|row| row.object_kind.as_deref() == Some("atom_revision"))
            .count(),
        atom_count
    );
    assert_eq!(
        before_organize
            .rows
            .iter()
            .filter(|row| row.object_kind.as_deref() == Some("atom_revision"))
            .count(),
        atom_count
    );

    handle.shutdown().await.unwrap();
    writer_task.await.unwrap().unwrap();
    let reopened = open_writer(&store).await.unwrap();
    let snapshot = reopened.project().await.unwrap();
    assert!(snapshot.rows.iter().any(|row| {
        row.object_kind.as_deref() == Some("source_observation")
            && row.object_id.as_deref() == Some(observation_ref.as_str())
    }));
    assert!(snapshot.rows.iter().any(|row| {
        row.object_kind.as_deref() == Some("revision_proposal_revision")
            && row.object_id.as_deref() == Some(proposal_ref.as_str())
            && row.current_revision_id.as_deref() == Some(proposal_revision_ref.as_str())
    }));
}
