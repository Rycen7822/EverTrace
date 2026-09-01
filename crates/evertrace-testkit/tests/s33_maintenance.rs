//! S33 Repository physical purge authority, bounded CAS deletion, and restart proof.

use std::{collections::BTreeSet, path::Path, process::Command, sync::Arc};

use evertrace_capture::{
    CaptureOutcome, CaptureRecordInput, CaptureRuntime, CasError, CasStore, DeviceKeyStore,
    RUNTIME_SNAPSHOT_VERSION, RecallCueGateMode, RecoveryGateMode, RuntimeSnapshot, SpoolLimits,
};
use evertrace_domain::{
    config::{DreamingConfig, LlmConfig},
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceObservation,
        SourceReceipt, SourceRevision, SourceRevisionMode, SourceRole,
    },
    ids::{
        CasId, CommandId, JobId, RepositoryId, RequestId, TaskId, WorkArtifactId, WorkstreamId,
        WorktreeId,
    },
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
    HumanSurface, SessionImportWorker, SynthesisPlanner, spawn_writer,
    work::{WorkCommandContext, activate_episode, new_episode},
};
use evertrace_store::{
    DurableJob, JobBudget, JobLease, JobStatus, JobTerminalReason, JournalCommand,
    JournalEventDraft, JournalPayload, JournalWriter, RuntimeSchedulerView, ScopePurgeCurrentView,
    SemanticCurrentView, SessionBodyState, SessionImportCurrentView, StoreError,
    repository::RepositoryCurrentView,
    session_import::{
        BodyStateReason, MetadataState, SessionImportEvent, SessionImportEventKind,
        SessionMetadata, WorkspaceResolutionKind,
    },
};
use tempfile::TempDir;
use tokio::sync::RwLock;

const CONFIG: [u8; 32] = [0x73; 32];
const ALGORITHM: &str = "s33-test-v1";

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
        file_size: 128,
        file_mtime_us: 1,
        source_fingerprint: "cd".repeat(32),
        source_revision: source_revision.clone(),
        parser_version: 1,
        metadata_state: MetadataState::Indexed,
    };
    let metadata_event = SessionImportEvent {
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

#[test]
fn maintenance_fence_child() {
    let Some(root) = std::env::var_os("EVERTRACE_S33_FENCE_CHILD_ROOT") else {
        return;
    };
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
