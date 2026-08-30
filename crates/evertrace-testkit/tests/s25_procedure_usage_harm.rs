use std::{future::Future, path::PathBuf, pin::Pin};

use evertrace_domain::{
    config::{GlobalPromotionConfig, PromotionLevel},
    evidence::{
        CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
        CorrelationField, CorrelationFieldClaim, EvidenceByteRange, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceArchiveMode,
        SourceInstanceId, SourceObservation, SourceReceipt, SourceRecordIdentity, SourceRevision,
        SourceRevisionMode, SourceRole, payload_fingerprint, source_observation_id,
        source_receipt_id,
    },
    ids::{
        CasId, CommandId, DuplicateGroupId, OperationId, ProcedureNegativeEvidenceId,
        ProcedureUsageId, RepositoryId, TaskId, WorkBindingRevisionId, WorkstreamId, WorktreeId,
        WorktreeSnapshotId,
    },
    procedure::{
        ProcedureActions, ProcedureAttributionBasis, ProcedureCorrelationState, ProcedureDone,
        ProcedureDraft, ProcedureKind, ProcedureLocalContext, ProcedureNegativeDecisionSource,
        ProcedureNegativeEvidence, ProcedureNegativeLevel, ProcedureNegativeReviewStatus,
        ProcedurePublicationState, ProcedureScope, ProcedureStateEvent, ProcedureStateReason,
        ProcedureTruth, ProcedureUsagePhase, ProcedureUsageRevision, ProcedureUsageRouteDecision,
        ProcedureUsageStage, ProcedureWhen,
    },
    query::{
        AnswerShape, FacetParseStatus, LifecycleBoundary, Polarity, QueryFacetSet, RetrievalBudget,
        SearchContext, SearchIntent, SuppressionSnapshot, TemporalMode,
    },
    repository::{
        FilesystemIdentity, GitObjectFormat, GitOperation, GitRegistrationState, PathObservation,
        RepositoryInstance, SnapshotCaptureStatus, WorktreeInstance, WorktreeKind,
        WorktreeLifecycle, WorktreeSnapshot,
    },
    revision::RevisionId,
    semantic::{
        ConstraintBinding, ConstraintExpr, ConstraintField, ConstraintState, ConstraintValue,
        EvidenceCompleteness, MetricValue, ParserFailureCode, ParserReceipt, ParserStatus,
        ProcedureProposalPayload, ProposalCreatedBy, ProposalEligibility, ProposalOperation,
        ProposalPayload, ProposalTargetId, ProposalTargetKind, ResultEvidence, ResultFailure,
        ResultScope, TUI_ACCEPTANCE_EVENT_MANIFEST_REF, VerifierFailureCode, VerifierReceipt,
        VerifierStatus, tui_acceptance_event_payload,
    },
    work::{
        AssignmentStatus, AttemptAdoptionStatus, AttemptOutcomeState, AttemptVerification,
        ContractField, MultiCasMetricPolicy, PhaseContract, PhaseKind, PrimaryWorkBinding,
        SeedPolicy, StrategyContract, Task, TaskIdentityConfidence, TaskLifecycle,
        TaskScopeMembership, VariableDeclaration, WorkBindingRevision, Workstream,
        WorkstreamStatus,
    },
};
use evertrace_engine::{
    PhysicalNormalizer,
    autoresearch::{RunCreateInput, create_experiment_run},
    procedure::{
        ProcedureAcceptanceContext, ProcedureAcceptanceResolution, ProcedureCandidate,
        ProcedureDecision, ProcedureNegativeRequest, ProcedureNegativeResolution,
        ProcedureNegativeReviewProof, ProcedurePhase, ProcedureRouter, ProcedureUsageAdvance,
        ProcedureUsageCurrentView, ProcedureUsageResolution, RoutedProcedure, accept_procedure,
        advance_procedure_usage, begin_procedure_usage, record_procedure_negative,
        review_procedure_negative, route_procedures_with_quarantine,
    },
    semantic::{
        AtomAcceptanceContext, ProposalCommandContext, ProposalResolution, RevisionProposalService,
        SubmitProposalRequest,
    },
    work::{
        WorkCommandContext,
        attempt::new_attempt,
        episode::{activate_episode, new_episode},
    },
};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload, JournalWriter,
    SemanticCurrentView, SourceIngestWatermark,
};
use tempfile::TempDir;

const CONFIG: [u8; 32] = [25; 32];

fn command(at: i64, payloads: Vec<JournalPayload>) -> JournalCommand {
    JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, CONFIG, "s25-test-v1", payload))
            .collect(),
    )
    .unwrap()
}

fn source(
    label: &str,
    payload: &str,
    at: i64,
    repository_id: RepositoryId,
) -> (SourceReceipt, SourceObservation) {
    let instance = SourceInstanceId::parse(format!("s25-{label}")).unwrap();
    let revision = SourceRevision::parse("revision-1").unwrap();
    let record = SourceRecordIdentity::parse(format!("record-{label}")).unwrap();
    let observation_id = source_observation_id(&instance, &revision, &record).unwrap();
    let receipt_id = source_receipt_id(&instance, &revision, &record).unwrap();
    let digest =
        evertrace_domain::evidence::hex(&payload_fingerprint(1, payload.as_bytes(), None).unwrap());
    let receipt = SourceReceipt {
        source_receipt_id: receipt_id,
        source_observation_id: observation_id,
        source_instance_id: instance.clone(),
        source_kind: EvidenceSourceKind::CodexSessionJsonl,
        identity_domain: "codex-session-v1".into(),
        source_ref: format!("source-{label}"),
        source_session_ref: format!("session-{label}"),
        source_revision: revision.clone(),
        source_record_identity: record.clone(),
        identity_strength: IdentityStrength::StableNative,
        source_sequence: 1,
        source_sequence_origin: None,
        task_id: None,
        repository_instance_id: Some(repository_id),
        worktree_instance_id: None,
        source_byte_range: None,
        spool_byte_range: EvidenceByteRange { start: 1, end: 2 },
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: Some(1),
        observation_role: ObservationRole::Message,
        unsupported_record_classification: None,
        capture_completeness: CaptureCompleteness::Complete,
        archive_mode: SourceArchiveMode::Exact,
        cas_ref: digest.clone(),
        protected_length: payload.len() as u64,
        original_length: payload.len() as u64,
        protected_secret_digest: None,
        redaction_spans: Vec::new(),
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-s25".into(),
        eligible_event_manifest_ref: TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        detector_revision: 1,
        redaction_revision: 1,
        protection_key_generation: 1,
        event_time_us: at,
        recorded_at_us: at,
        lifecycle: None,
    };
    let observation = SourceObservation {
        source_observation_id: observation_id,
        source_instance_id: instance,
        source_revision: revision,
        source_record_identity: record,
        observation_role: ObservationRole::Message,
        identity_strength: IdentityStrength::StableNative,
        payload_fingerprint: digest,
        source_receipt_ref: receipt_id,
        source_role: SourceRole::User,
        content_trust: ContentTrust::UserStatement,
        capture_completeness: CaptureCompleteness::Complete,
        adapter_revision: 1,
        parser_revision: 1,
        canonicalization_revision: 1,
        detector_revision: 1,
        redaction_revision: 1,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            pairing_role: ObservationRole::Message,
            field_provenance: Vec::new(),
            adapter_manifest_ref: "adapter-s25".into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: Vec::new(),
    };
    (receipt, observation)
}

fn source_payloads(receipt: SourceReceipt, observation: SourceObservation) -> Vec<JournalPayload> {
    let target = observation.source_observation_id.to_string();
    vec![
        JournalPayload::SourceReceiptRecorded(Box::new(receipt.clone())),
        JournalPayload::SourceObservationRecorded(Box::new(observation)),
        JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
            source_instance_id: receipt.source_instance_id,
            source_revision: receipt.source_revision,
            source_sequence: 1,
            confirmed_prefix_digest: None,
        }),
        JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::EvidenceSurface,
            target_id: target.clone(),
            algorithm_revision: "s25-test-v1".into(),
            source_watermark: 1,
        }),
        JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::PhysicalNormalization,
            target_id: target,
            algorithm_revision: "s25-test-v1".into(),
            source_watermark: 1,
        }),
    ]
}

fn repository(repository_id: RepositoryId) -> RepositoryInstance {
    RepositoryInstance {
        repository_id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: "/tmp/evertrace-s25-repo".into(),
        path_history: vec![PathObservation {
            path: "/tmp/evertrace-s25-repo".into(),
            first_observed_at_us: 1,
            last_observed_at_us: 1,
            evidence_refs: vec!["repository-path".into()],
        }],
        git_common_dir_path: Some("/tmp/evertrace-s25-repo/.git".into()),
        common_dir_filesystem: Some(FilesystemIdentity {
            device: 25,
            inode: 1,
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: Vec::new(),
        derived_from: None,
        identity_evidence_refs: vec!["repository-identity".into()],
        recorded_at_us: 1,
    }
}

fn worktree(
    repository_id: RepositoryId,
    worktree_id: WorktreeId,
    snapshot_id: WorktreeSnapshotId,
) -> (WorktreeInstance, WorktreeSnapshot) {
    let path = "/tmp/evertrace-s25-repo";
    (
        WorktreeInstance {
            worktree_instance_id: worktree_id,
            worktree_revision: 1,
            predecessor_revision: None,
            repository_instance_id: repository_id,
            kind: WorktreeKind::Main,
            lifecycle: WorktreeLifecycle::Active,
            current_path: Some(path.into()),
            path_history: vec![PathObservation {
                path: path.into(),
                first_observed_at_us: 1,
                last_observed_at_us: 1,
                evidence_refs: vec!["worktree-path".into()],
            }],
            git_admin_path_history: vec![PathObservation {
                path: format!("{path}/.git"),
                first_observed_at_us: 1,
                last_observed_at_us: 1,
                evidence_refs: vec!["worktree-admin".into()],
            }],
            git_registration_state: GitRegistrationState::Registered,
            current_snapshot_id: Some(snapshot_id),
            created_event_ref: "worktree-created".into(),
            terminal_event_ref: None,
            recreated_from_worktree_instance_id: None,
            recorded_at_us: 1,
        },
        WorktreeSnapshot {
            worktree_snapshot_id: snapshot_id,
            worktree_instance_id: worktree_id,
            head_oid: None,
            tree_oid: None,
            branch_ref: None,
            detached_head: false,
            tracked_diff_digest: None,
            index_digest: None,
            untracked_manifest_digest: None,
            relevant_anchor_digests: Vec::new(),
            dependency_fingerprints: Vec::new(),
            toolchain_fingerprint: None,
            git_operation: GitOperation::None,
            captured_at_us: 1,
            evidence_refs: vec!["snapshot".into()],
            capture_status: SnapshotCaptureStatus::Complete,
            omission_reasons: Vec::new(),
        },
    )
}

fn physical_source(
    label: &str,
    role: ObservationRole,
    repository_id: RepositoryId,
    worktree_id: WorktreeId,
) -> (SourceReceipt, SourceObservation) {
    let (mut receipt, mut observation) = source(label, "physical", 8, repository_id);
    let fields = [
        CorrelationField::HostInstanceId,
        CorrelationField::HostTraceLineageId,
        CorrelationField::HostLaneKey,
        CorrelationField::CanonicalEventFamily,
        CorrelationField::NativeRequestId,
        CorrelationField::PhysicalExecutionOrdinal,
    ];
    receipt.source_kind = EvidenceSourceKind::CodexHook;
    receipt.source_session_ref = "session-s25-physical".into();
    receipt.worktree_instance_id = Some(worktree_id);
    receipt.observation_role = role;
    receipt.eligible_event_manifest_ref = "eligible-s25".into();
    observation.observation_role = role;
    observation.source_role = SourceRole::Tool;
    observation.content_trust = ContentTrust::Observed;
    let occurrence_group = label
        .strip_suffix("-intent")
        .or_else(|| label.strip_suffix("-result"))
        .unwrap_or(label);
    observation.correlation = HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: Some("host-s25".into()),
        host_trace_lineage_id: Some(format!("trace-s25-{occurrence_group}")),
        host_lane_key: Some("lane-s25".into()),
        canonical_event_family: Some(CanonicalEventFamily::Mutate),
        native_request_id: Some(format!("request-s25-{occurrence_group}")),
        physical_execution_ordinal: Some(1),
        pairing_role: role,
        field_provenance: fields
            .into_iter()
            .map(|field| CorrelationFieldClaim {
                field,
                source_ref: format!("source-{label}"),
                evidence_ref: format!("evidence-{field:?}-{label}"),
            })
            .collect(),
        adapter_manifest_ref: "adapter-s25".into(),
        adapter_revision: 1,
        strong_gate_receipt_ref: Some("strong-gate-s25".into()),
        admission: CorrelationAdmission::ExactCapable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    };
    receipt.validate().unwrap();
    observation.validate().unwrap();
    (receipt, observation)
}

fn procedure_draft(repository_id: RepositoryId, evidence: String) -> ProcedureDraft {
    ProcedureDraft {
        scope: ProcedureScope::Repository { repository_id },
        title: "Recover deterministic verification".into(),
        summary: "Use the objective verifier for a recoverable failure".into(),
        kind: ProcedureKind::Diagnostic,
        when: ProcedureWhen {
            goals: vec!["verification".into()],
            targets: vec!["artifact".into()],
            signals: vec!["verifier failed".into()],
            stage: "verify".into(),
            requires: vec!["objective verifier available".into()],
            excludes: vec!["already verified".into()],
        },
        condition_ir_version: 1,
        applicability_expr: ConstraintExpr::Eq {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text("verify".into()),
        },
        avoid_expr: ConstraintExpr::Eq {
            field: ConstraintField::VerifierState,
            value: ConstraintValue::Text("passed".into()),
        },
        completion_expr: ConstraintExpr::Eq {
            field: ConstraintField::ArtifactKind,
            value: ConstraintValue::Text("release".into()),
        },
        actions: ProcedureActions {
            stages: vec!["run fixed verifier".into()],
            branches: Vec::new(),
            avoid: vec!["do not publish first".into()],
        },
        done: ProcedureDone {
            success: vec!["verifier passes".into()],
            abort: vec!["stop on mismatch".into()],
            verify: vec!["record verifier result".into()],
        },
        pitfalls: vec!["stale artifacts".into()],
        evidence_refs: vec![evidence],
        support_revision_refs: Vec::new(),
    }
}

fn proposal_context(at: i64) -> ProposalCommandContext {
    ProposalCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: "s25-test-v1".into(),
    }
}

fn work_context(at: i64) -> WorkCommandContext {
    WorkCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: "s25-test-v1",
    }
}

fn task(repository_id: RepositoryId, worktree_id: WorktreeId, at: i64) -> Task {
    Task {
        task_id: TaskId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec![format!("request:s25:{at}")],
        canonical_goal: "verify the current artifact".into(),
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
        created_at_us: at,
        closed_at_us: None,
        source_watermark: at as u64,
    }
}

fn workstream(
    task_id: TaskId,
    repository_id: RepositoryId,
    worktree_id: WorktreeId,
    at: i64,
) -> Workstream {
    Workstream {
        workstream_id: WorkstreamId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        task_id,
        repository_instance_id: Some(repository_id),
        worktree_instance_ids: vec![worktree_id],
        active_worktree_instance_id: Some(worktree_id),
        worktree_lineage_refs: Vec::new(),
        parent_workstream_id: None,
        dependency_workstream_ids: Vec::new(),
        status: WorkstreamStatus::Active,
        root_goal: "verify artifact".into(),
        workstream_goal: "run deterministic verification".into(),
        target_family: "artifact".into(),
        hypothesis_or_failure_family: "verification".into(),
        acceptance_boundary: "procedure-use-boundary".into(),
        phase_contract: PhaseContract {
            local_goal: "verify artifact".into(),
            phase_kind: PhaseKind::Verify,
            phase_label: "verify".into(),
            primary_targets: vec!["artifact".into()],
            entry_conditions: vec!["verifier failed".into()],
            acceptance_boundary: "procedure-use-boundary".into(),
            expected_state_transition: "verified".into(),
        },
        active_episode_id: None,
        execution_lane_ids: Vec::new(),
        source_watermark: at as u64,
    }
}

async fn activate_additional_exposure(
    writer: &mut JournalWriter,
    procedure: &evertrace_domain::procedure::ProcedureRevision,
    task_id: TaskId,
    repository_id: RepositoryId,
    worktree_id: WorktreeId,
    snapshot_id: WorktreeSnapshotId,
    at: i64,
) -> (WorkstreamId, RevisionId) {
    let stream = workstream(task_id, repository_id, worktree_id, at);
    let initial = new_attempt(
        task_id,
        stream.workstream_id,
        Some(repository_id),
        vec![worktree_id],
        Vec::new(),
        StrategyContract {
            hypothesis: "fixed verifier resolves the failure".into(),
            intervention: "run fixed verifier".into(),
            intervention_family: "procedure".into(),
            search_policy_ref: Some(procedure.revision_id.to_string()),
            objective_ref: Some("objective:verification".into()),
            expected_effect: "verification passes".into(),
            target_refs: vec!["artifact".into()],
            acceptance_boundary_ref: stream.phase_contract.acceptance_boundary.clone(),
        },
        at as u64,
    )
    .unwrap();
    writer
        .commit(
            &command(
                at,
                vec![
                    JournalPayload::WorkstreamRecorded(Box::new(stream.clone())),
                    JournalPayload::AttemptRecorded(Box::new(initial.clone())),
                ],
            ),
            at,
        )
        .await
        .unwrap();
    let mut episode = new_episode(&stream, Some(snapshot_id), at as u64).unwrap();
    let exposure_revision_id = episode.revision_id;
    let mut adopted = initial.clone();
    adopted.revision_id = RevisionId::new_v7();
    adopted.predecessor_revision_id = Some(initial.revision_id);
    adopted.revision_generation = 2;
    adopted.episode_id = Some(episode.episode_id);
    adopted.adoption_status = AttemptAdoptionStatus::Selected;
    adopted.source_watermark = initial.source_watermark + 1;
    episode.attempt_ids = vec![adopted.attempt_id];
    episode.validate().unwrap();
    writer
        .commit(
            &activate_episode(
                work_context(at),
                &stream,
                episode,
                vec![adopted],
                Vec::new(),
            )
            .unwrap(),
            at,
        )
        .await
        .unwrap();
    (stream.workstream_id, exposure_revision_id)
}

struct ActiveProcedureFixture {
    _temp: TempDir,
    store_path: PathBuf,
    writer: JournalWriter,
    repository_id: RepositoryId,
    worktree_id: WorktreeId,
    snapshot_id: WorktreeSnapshotId,
    evidence_receipt: SourceReceipt,
    procedure: Box<evertrace_domain::procedure::ProcedureRevision>,
    config: GlobalPromotionConfig,
}

async fn active_procedure_fixture(label: &str, context_unbounded: bool) -> ActiveProcedureFixture {
    let temp = TempDir::new().unwrap();
    let store_path = temp.path().join(format!("procedure-{label}"));
    let mut writer = JournalWriter::open(&store_path).await.unwrap();
    let repository_id = RepositoryId::new_v7();
    let worktree_id = WorktreeId::new_v7();
    let snapshot_id = WorktreeSnapshotId::new_v7();
    let (worktree, worktree_snapshot) = worktree(repository_id, worktree_id, snapshot_id);
    let (evidence_receipt, evidence_observation) = source(
        &format!("{label}-evidence"),
        "procedure evidence",
        1,
        repository_id,
    );
    let mut initial = vec![
        JournalPayload::RepositoryInstanceRecorded(Box::new(repository(repository_id))),
        JournalPayload::WorktreeInstanceRecorded(Box::new(worktree)),
        JournalPayload::WorktreeSnapshotRecorded(Box::new(worktree_snapshot)),
    ];
    initial.extend(source_payloads(
        evidence_receipt.clone(),
        evidence_observation,
    ));
    writer.commit(&command(1, initial), 1).await.unwrap();
    let service = RevisionProposalService;
    let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: proposal,
        command: submitted,
    } = service
        .submit(
            &view,
            proposal_context(2),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Procedure,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Create {
                    draft: {
                        let mut draft = procedure_draft(
                            repository_id,
                            evidence_receipt.source_receipt_id.to_string(),
                        );
                        if context_unbounded {
                            draft.applicability_expr = ConstraintExpr::Eq {
                                field: ConstraintField::Toolchain,
                                value: ConstraintValue::Text("toolchain-s25".into()),
                            };
                        }
                        draft
                    },
                })),
                evidence_refs: vec![evidence_receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![evidence_receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("proposal must be created")
    };
    writer.commit(&submitted, 2).await.unwrap();
    let acceptance_payload = tui_acceptance_event_payload(
        proposal.proposal_id,
        proposal.proposal_revision_id,
        &proposal.fingerprint,
    );
    let (acceptance_receipt, acceptance_observation) = source(
        &format!("{label}-acceptance"),
        &acceptance_payload,
        3,
        repository_id,
    );
    writer
        .commit(
            &command(
                3,
                source_payloads(acceptance_receipt.clone(), acceptance_observation.clone()),
            ),
            3,
        )
        .await
        .unwrap();
    let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let config = GlobalPromotionConfig {
        atom: PromotionLevel::Manual,
        procedure: PromotionLevel::Manual,
        core_membership: PromotionLevel::Manual,
    };
    let ProcedureAcceptanceResolution::Command {
        procedure,
        command: accepted,
        ..
    } = accept_procedure(
        &view,
        proposal_context(4),
        proposal.proposal_id,
        ProcedureAcceptanceContext::Manual(AtomAcceptanceContext::RepositoryTui {
            observation: Box::new(acceptance_observation),
            receipt: Box::new(acceptance_receipt),
        }),
        None,
        None,
        &config,
    )
    .unwrap()
    else {
        panic!("procedure acceptance must produce a command")
    };
    writer.commit(&accepted, 4).await.unwrap();
    ActiveProcedureFixture {
        _temp: temp,
        store_path,
        writer,
        repository_id,
        worktree_id,
        snapshot_id,
        evidence_receipt,
        procedure,
        config,
    }
}

#[derive(Clone, Copy)]
enum PhysicalEvidenceCase {
    Exact,
    PossibleDuplicate,
    Conflicted,
}

#[derive(Clone, Copy)]
enum ResultEvidenceCase {
    Passed,
    NeutralFailure,
    ReplayViolation,
}

struct PreparedUsageEvidence {
    begun_usage: ProcedureUsageRevision,
    usage: ProcedureUsageRevision,
    command: JournalCommand,
    result: ResultEvidence,
    routed: RoutedProcedure,
    workstream_id: WorkstreamId,
    exposure_revision_id: RevisionId,
    route_search: SearchContext,
    route_constraints: ConstraintState,
}

#[allow(clippy::too_many_arguments)]
async fn prepare_usage_evidence(
    writer: &mut JournalWriter,
    procedure: &evertrace_domain::procedure::ProcedureRevision,
    publication: ProcedurePublicationState,
    repository_id: RepositoryId,
    worktree_id: WorktreeId,
    snapshot_id: WorktreeSnapshotId,
    task: Task,
    record_task: bool,
    related_task: Option<Task>,
    physical_case: PhysicalEvidenceCase,
    result_case: ResultEvidenceCase,
    at: i64,
    label: &str,
) -> PreparedUsageEvidence {
    task.validate().unwrap();
    let stream = workstream(task.task_id, repository_id, worktree_id, at);
    let strategy = StrategyContract {
        hypothesis: "fixed verifier resolves the failure".into(),
        intervention: "run fixed verifier".into(),
        intervention_family: "procedure".into(),
        search_policy_ref: Some(procedure.revision_id.to_string()),
        objective_ref: Some("objective:verification".into()),
        expected_effect: "verification passes".into(),
        target_refs: vec!["artifact".into()],
        acceptance_boundary_ref: stream.phase_contract.acceptance_boundary.clone(),
    };
    let initial_attempt = new_attempt(
        task.task_id,
        stream.workstream_id,
        Some(repository_id),
        vec![worktree_id],
        Vec::new(),
        strategy,
        at as u64,
    )
    .unwrap();
    let mut task_payloads = Vec::with_capacity(4);
    if let Some(related_task) = related_task {
        task_payloads.push(JournalPayload::TaskRecorded(Box::new(related_task)));
    }
    if record_task {
        task_payloads.push(JournalPayload::TaskRecorded(Box::new(task.clone())));
    }
    task_payloads.extend([
        JournalPayload::WorkstreamRecorded(Box::new(stream.clone())),
        JournalPayload::AttemptRecorded(Box::new(initial_attempt.clone())),
    ]);
    writer
        .commit(&command(at, task_payloads), at)
        .await
        .unwrap_or_else(|error| panic!("{label} task setup failed: {error:?}"));
    let mut episode = new_episode(&stream, Some(snapshot_id), at as u64).unwrap();
    let exposure_revision_id = episode.revision_id;
    let mut adopted = initial_attempt.clone();
    adopted.revision_id = RevisionId::new_v7();
    adopted.predecessor_revision_id = Some(initial_attempt.revision_id);
    adopted.revision_generation = 2;
    adopted.episode_id = Some(episode.episode_id);
    adopted.adoption_status = AttemptAdoptionStatus::Selected;
    adopted.source_watermark = initial_attempt.source_watermark + 1;
    episode.attempt_ids = vec![adopted.attempt_id];
    episode.validate().unwrap();
    let activation = activate_episode(
        work_context(at),
        &stream,
        episode,
        vec![adopted.clone()],
        Vec::new(),
    )
    .unwrap();
    writer.commit(&activation, at).await.unwrap();

    let snapshot = writer.project().await.unwrap();
    let constraints = ConstraintState {
        bindings: vec![
            ConstraintBinding {
                field: ConstraintField::Toolchain,
                value: ConstraintValue::Text("toolchain-s25".into()),
            },
            ConstraintBinding {
                field: ConstraintField::ArtifactKind,
                value: ConstraintValue::Text("pending".into()),
            },
            ConstraintBinding {
                field: ConstraintField::VerifierState,
                value: ConstraintValue::Text("failed".into()),
            },
            ConstraintBinding {
                field: ConstraintField::Phase,
                value: ConstraintValue::Text("verify".into()),
            },
        ],
    };
    let search = SearchContext {
        intent: SearchIntent::FailureRecovery,
        raw_query: "verifier failed".into(),
        query_facets: QueryFacetSet {
            parse_status: FacetParseStatus::Complete,
            exact_identifiers: Vec::new(),
            condition_literals: Vec::new(),
            relation_requirements: Vec::new(),
            polarity: Polarity::Positive,
            explicit_exclusions: Vec::new(),
            temporal_mode: TemporalMode::Any,
            temporal_qualifiers: Vec::new(),
            quantity_constraints: Vec::new(),
            scope_boundary: None,
            source_boundary: None,
            answer_shape: Some(AnswerShape::EntityList),
            lifecycle_boundary: LifecycleBoundary::Active,
        },
        task_id: Some(task.task_id),
        repository_id: Some(repository_id),
        worktree_id: Some(worktree_id),
        suppression: SuppressionSnapshot::Current {
            generation: 0,
            ref_hashes: Default::default(),
        },
        budget: RetrievalBudget {
            candidates_remaining: 8,
            tokens_remaining: 512,
            latency_us_remaining: 100_000,
            hops_remaining: 2,
            follow_ups_remaining: 1,
        },
    };
    let routed = ProcedureRouter::route(
        &search,
        vec![ProcedureCandidate {
            revision: procedure.clone(),
            publication,
            global_support: None,
            phase: ProcedurePhase::AtEntry,
            lexical_rank: 1,
        }],
        &constraints,
        None,
        true,
        false,
        false,
        true,
    );
    let routed_item = routed.items[0].clone();
    let view = ProcedureUsageCurrentView::from_snapshot(&snapshot).unwrap();
    let ProcedureUsageResolution::Command {
        usage,
        command: begun,
    } = begin_procedure_usage(
        &view,
        proposal_context(at),
        &routed_item,
        stream.workstream_id,
        exposure_revision_id,
    )
    .unwrap()
    else {
        panic!("independent exposure must create one usage")
    };
    writer.commit(&begun, at).await.unwrap();

    let (intent_receipt, mut intent) = physical_source(
        &format!("{label}-intent"),
        ObservationRole::Intent,
        repository_id,
        worktree_id,
    );
    let (result_receipt, mut result_observation) = physical_source(
        &format!("{label}-result"),
        ObservationRole::Result,
        repository_id,
        worktree_id,
    );
    match physical_case {
        PhysicalEvidenceCase::Exact => {}
        PhysicalEvidenceCase::PossibleDuplicate => {
            let group: DuplicateGroupId = format!("dup:{}", RevisionId::new_v7()).parse().unwrap();
            for observation in [&mut intent, &mut result_observation] {
                observation.correlation.admission = CorrelationAdmission::Ambiguous;
                observation.correlation.strong_gate_receipt_ref = None;
                observation.correlation.partial_correlation_ref =
                    Some(format!("partial-s25-{label}"));
                observation.correlation.possible_duplicate_group_id = Some(group);
                observation.validate().unwrap();
            }
        }
        PhysicalEvidenceCase::Conflicted => {
            for observation in [&mut intent, &mut result_observation] {
                observation.correlation.admission = CorrelationAdmission::Conflicted;
                observation.correlation.strong_gate_receipt_ref = None;
                observation.validate().unwrap();
            }
        }
    }
    writer
        .commit(
            &command(at, source_payloads(intent_receipt.clone(), intent.clone())),
            at,
        )
        .await
        .unwrap();
    writer
        .commit(
            &command(
                at,
                source_payloads(result_receipt, result_observation.clone()),
            ),
            at,
        )
        .await
        .unwrap();
    let normalized = PhysicalNormalizer::new(1)
        .unwrap()
        .normalize(&[intent.clone(), result_observation], None)
        .unwrap();
    let operation_id = normalized.operations[0].operation_id;
    writer
        .commit(
            &normalized
                .journal_command(CommandId::new_v7(), at, CONFIG, "s25-test-v1")
                .unwrap(),
            at,
        )
        .await
        .unwrap();

    let binding_id = WorkBindingRevisionId::new_v7();
    let mut successful = adopted.clone();
    successful.revision_id = RevisionId::new_v7();
    successful.predecessor_revision_id = Some(adopted.revision_id);
    successful.revision_generation = 3;
    successful.verification = match result_case {
        ResultEvidenceCase::Passed => AttemptVerification::Passed,
        ResultEvidenceCase::NeutralFailure | ResultEvidenceCase::ReplayViolation => {
            AttemptVerification::Failed
        }
    };
    successful.outcome_state = AttemptOutcomeState::Known;
    successful.failure_signature = (!matches!(result_case, ResultEvidenceCase::Passed))
        .then(|| "objective_verifier_failed".into());
    successful.work_binding_revision_refs = vec![binding_id];
    successful.source_watermark = adopted.source_watermark + 1;
    let run = create_experiment_run(
        &successful,
        RunCreateInput {
            workstream_id: stream.workstream_id,
            source_receipt_refs: vec![intent_receipt.source_receipt_id],
            code_snapshot_id: snapshot_id,
            data_fingerprint: format!("data-{label}"),
            normalized_config: vec![ContractField {
                name: "mode".into(),
                value: "fixed".into(),
            }],
            variable_declaration: VariableDeclaration {
                varied: Vec::new(),
                fixed: vec!["mode".into()],
                uncontrolled: Vec::new(),
            },
            seed_policy: SeedPolicy::Fixed,
            seed_values: vec![label.into()],
            nondeterministic: false,
            metric_definition: "verification".into(),
            metric_extractor_version: "evertrace.result_metric.v1".into(),
            multi_cas_metric_policy: MultiCasMetricPolicy::RejectMultipleParsed,
            environment_fingerprint: format!("environment-{label}"),
            created_at_us: at,
        },
    )
    .unwrap();
    let cas_id: CasId = format!("cas:{}", "cd".repeat(32)).parse().unwrap();
    let result = ResultEvidence {
        result_evidence_id: evertrace_domain::ids::ResultEvidenceId::new_v7(),
        revision_id: RevisionId::new_v7(),
        parent_revision_id: None,
        experiment_run_id: run.run_id,
        experiment_run_revision_id: run.revision_id,
        result_scope: ResultScope::Partial,
        raw_artifact_refs: Vec::new(),
        raw_cas_refs: vec![cas_id],
        parsed_metric: Some(MetricValue {
            decimal: "1".into(),
            unit: "boolean".into(),
            uncertainty_decimal: None,
        }),
        parser_receipt: ParserReceipt {
            parser_version: "evertrace.result_metric.v1".into(),
            input_artifact_refs: Vec::new(),
            input_cas_refs: vec![cas_id],
            status: ParserStatus::Parsed,
            failure_code: None,
        },
        verifier_receipt: match result_case {
            ResultEvidenceCase::Passed => Some(VerifierReceipt {
                verifier_version: "evertrace.result_reparse.v1".into(),
                status: VerifierStatus::Passed,
                failure_code: None,
            }),
            ResultEvidenceCase::NeutralFailure => None,
            ResultEvidenceCase::ReplayViolation => Some(VerifierReceipt {
                verifier_version: "evertrace.result_reparse.v1".into(),
                status: VerifierStatus::Failed,
                failure_code: Some(VerifierFailureCode::DeterministicReparseMismatch),
            }),
        },
        completeness: if matches!(result_case, ResultEvidenceCase::Passed) {
            EvidenceCompleteness::Complete
        } else {
            EvidenceCompleteness::Incomplete
        },
        failure: matches!(result_case, ResultEvidenceCase::ReplayViolation).then_some(
            ResultFailure::Verifier(VerifierFailureCode::DeterministicReparseMismatch),
        ),
        created_at_us: at,
    };
    let result_revision_id = result.revision_id;
    let result_ref = result_revision_id.to_string();
    successful.parent_verification_refs = vec![result_ref.clone()];
    successful.outcome_refs = vec![result_ref.clone()];
    adopted.validate_successor(&successful).unwrap();
    let binding = WorkBindingRevision {
        work_binding_revision_id: binding_id,
        operation_id,
        revision_generation: 1,
        predecessor_revision_id: None,
        primary_binding: PrimaryWorkBinding {
            task_id: Some(task.task_id),
            workstream_id: Some(stream.workstream_id),
            episode_id: successful.episode_id,
            attempt_id: Some(successful.attempt_id),
            experiment_run_id: Some(run.run_id),
            competing_group_id: None,
        },
        secondary_bindings: Vec::new(),
        scope_effect_refs: Vec::new(),
        assignment_status: AssignmentStatus::Resolved,
        evidence_refs: vec![intent.source_observation_id.to_string()],
        resolver_version: 1,
    };
    writer
        .commit(
            &command(
                at,
                vec![
                    JournalPayload::AttemptRecorded(Box::new(successful.clone())),
                    JournalPayload::WorkBindingRecorded(Box::new(binding)),
                    JournalPayload::ExperimentRunRecorded(Box::new(run)),
                    JournalPayload::ResultEvidenceRecorded(Box::new(result.clone())),
                ],
            ),
            at,
        )
        .await
        .unwrap();
    let before_outcome = writer.project().await.unwrap();
    let view = ProcedureUsageCurrentView::from_snapshot(&before_outcome).unwrap();
    let (outcome, outcome_command) = advance_procedure_usage(
        &view,
        proposal_context(at),
        ProcedureUsageAdvance {
            usage_id: usage.procedure_usage_id,
            stage: if matches!(result_case, ResultEvidenceCase::Passed) {
                ProcedureUsageStage::Outcome
            } else {
                ProcedureUsageStage::Completion
            },
            attempt_ids: vec![successful.attempt_id],
            action_episode_revision_ids: vec![exposure_revision_id],
            verification_episode_revision_ids: vec![exposure_revision_id],
            action_operation_refs: vec![operation_id],
            verification_operation_refs: vec![operation_id],
            work_binding_revision_refs: vec![binding_id],
            scope_effect_refs: Vec::new(),
            evidence_refs: vec![result_ref],
        },
        &ConstraintState {
            bindings: vec![ConstraintBinding {
                field: ConstraintField::ArtifactKind,
                value: ConstraintValue::Text(
                    if matches!(result_case, ResultEvidenceCase::Passed) {
                        "release"
                    } else {
                        "pending"
                    }
                    .into(),
                ),
            }],
        },
        None,
    )
    .unwrap();
    if matches!(result_case, ResultEvidenceCase::Passed)
        && matches!(physical_case, PhysicalEvidenceCase::Exact)
    {
        assert_eq!(outcome.outcome_supported, ProcedureTruth::True);
    } else {
        assert_ne!(outcome.outcome_supported, ProcedureTruth::True);
    }
    PreparedUsageEvidence {
        begun_usage: usage,
        usage: outcome,
        command: outcome_command,
        result,
        routed: routed_item,
        workstream_id: stream.workstream_id,
        exposure_revision_id,
        route_search: search,
        route_constraints: constraints,
    }
}

#[allow(clippy::too_many_arguments)]
fn record_independent_success<'a>(
    writer: &'a mut JournalWriter,
    procedure: &'a evertrace_domain::procedure::ProcedureRevision,
    publication: ProcedurePublicationState,
    repository_id: RepositoryId,
    worktree_id: WorktreeId,
    snapshot_id: WorktreeSnapshotId,
    at: i64,
    label: &'a str,
) -> Pin<Box<dyn Future<Output = (ProcedureUsageRevision, JournalCommand, RevisionId)> + 'a>> {
    let mut task = task(repository_id, worktree_id, at);
    task.request_root_refs = vec![format!("request:s25:{at}:{label}")];
    Box::pin(async move {
        let prepared = prepare_usage_evidence(
            writer,
            procedure,
            publication,
            repository_id,
            worktree_id,
            snapshot_id,
            task,
            true,
            None,
            PhysicalEvidenceCase::Exact,
            ResultEvidenceCase::Passed,
            at,
            label,
        )
        .await;
        (
            prepared.usage,
            prepared.command,
            prepared.result.revision_id,
        )
    })
}

fn objective_success_state(
    procedure_revision_id: RevisionId,
    usages: &[&ProcedureUsageRevision],
    at: i64,
) -> ProcedureStateEvent {
    let mut evidence_refs = usages
        .iter()
        .map(|usage| usage.usage_revision_id.to_string())
        .collect::<Vec<_>>();
    evidence_refs.sort();
    ProcedureStateEvent {
        state_event_id: RevisionId::new_v7(),
        procedure_revision_id,
        from_state: Some(ProcedurePublicationState::ActiveProbationary),
        to_state: ProcedurePublicationState::ActiveStable,
        reason: ProcedureStateReason::ObjectiveSuccesses,
        resume_state: None,
        evidence_refs,
        created_at_us: at,
    }
}

fn has_objective_success_state(command: &JournalCommand) -> bool {
    command.events().iter().any(|event| {
        matches!(
            &event.payload,
            JournalPayload::ProcedureStateRecorded(value)
                if value.to_state == ProcedurePublicationState::ActiveStable
                    && value.reason == ProcedureStateReason::ObjectiveSuccesses
        )
    })
}

fn returned_usage() -> ProcedureUsageRevision {
    ProcedureUsageRevision {
        procedure_usage_id: ProcedureUsageId::new_v7(),
        usage_revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        revision_generation: 1,
        procedure_revision_id: RevisionId::new_v7(),
        task_id: TaskId::new_v7(),
        workstream_id: WorkstreamId::new_v7(),
        exposure_episode_revision_id: RevisionId::new_v7(),
        decision_boundary_ref: "decision-boundary".into(),
        route_decision: ProcedureUsageRouteDecision::Apply,
        stage: ProcedureUsageStage::Returned,
        attempt_ids: Vec::new(),
        action_episode_revision_ids: Vec::new(),
        verification_episode_revision_ids: Vec::new(),
        action_operation_refs: Vec::new(),
        verification_operation_refs: Vec::new(),
        work_binding_revision_refs: Vec::new(),
        scope_effect_refs: Vec::new(),
        correlation_state: ProcedureCorrelationState::Resolved,
        eligible: ProcedureTruth::True,
        action_aligned: ProcedureTruth::False,
        verifier_aligned: ProcedureTruth::Unknown,
        outcome_supported: ProcedureTruth::Unknown,
        local_context: ProcedureLocalContext {
            repository_id: None,
            worktree_id: None,
            phase: ProcedureUsagePhase::AtEntry,
            failure_signature: None,
        },
        source_watermark: 1,
        evidence_refs: vec!["exposure".into()],
        created_at_us: 1,
    }
}

#[test]
fn returned_defer_and_weak_failure_never_become_usage_success_or_confirmed_harm() {
    let returned = returned_usage();
    assert!(returned.validate());
    assert_ne!(returned.action_aligned, ProcedureTruth::True);
    assert_ne!(returned.outcome_supported, ProcedureTruth::True);

    let mut deferred = returned.clone();
    deferred.route_decision = ProcedureUsageRouteDecision::Defer;
    deferred.stage = ProcedureUsageStage::Action;
    deferred.action_operation_refs = vec![OperationId::new_v7()];
    deferred.action_aligned = ProcedureTruth::True;
    assert!(!deferred.validate());

    let mut weak = ProcedureNegativeEvidence {
        negative_evidence_id: ProcedureNegativeEvidenceId::new_v7(),
        level: ProcedureNegativeLevel::SuspectedHarm,
        procedure_revision_id: returned.procedure_revision_id,
        procedure_usage_id: returned.procedure_usage_id,
        task_id: returned.task_id,
        session_id: "session".into(),
        evidence_refs: vec!["non-zero".into()],
        observed_effect: "ordinary failure".into(),
        expected_effect: "success".into(),
        confounders: vec!["interruption".into()],
        attribution_basis: ProcedureAttributionBasis::ContextUnbounded,
        decision_source: ProcedureNegativeDecisionSource::AdoptedAttemptFailed,
        local_context: None,
        created_at_us: 2,
    };
    assert!(weak.validate());
    weak.level = ProcedureNegativeLevel::ConfirmedHarm;
    assert!(!weak.validate());
}

#[test]
fn late_unique_physical_action_and_verifier_can_strengthen_an_immutable_successor() {
    let returned = returned_usage();
    let mut outcome = returned.clone();
    outcome.usage_revision_id = RevisionId::new_v7();
    outcome.predecessor_revision_id = Some(returned.usage_revision_id);
    outcome.revision_generation = 2;
    outcome.stage = ProcedureUsageStage::Outcome;
    outcome.action_operation_refs = vec![OperationId::new_v7()];
    outcome.verification_operation_refs = vec![OperationId::new_v7()];
    outcome.action_aligned = ProcedureTruth::True;
    outcome.verifier_aligned = ProcedureTruth::True;
    outcome.outcome_supported = ProcedureTruth::True;
    outcome.source_watermark = 2;
    outcome.evidence_refs.push("verifier".into());
    outcome.evidence_refs.sort();
    assert!(returned.validate_successor(&outcome));

    let mut ambiguous = outcome.clone();
    ambiguous.usage_revision_id = RevisionId::new_v7();
    ambiguous.predecessor_revision_id = Some(outcome.usage_revision_id);
    ambiguous.revision_generation = 3;
    ambiguous.correlation_state = ProcedureCorrelationState::Ambiguous;
    assert!(!ambiguous.validate());
}

#[tokio::test]
async fn s25_keeps_the_production_store_at_four_tables() {
    let temp = TempDir::new().unwrap();
    let writer = JournalWriter::open(&temp.path().join("procedure-store"))
        .await
        .unwrap();
    assert_eq!(
        writer.table_names().await.unwrap(),
        vec![
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search",
        ]
    );
}

#[tokio::test]
async fn promotion_cohort_is_exact_but_stable_success_batches_remain_legal() {
    let ActiveProcedureFixture {
        _temp,
        mut writer,
        repository_id,
        worktree_id,
        snapshot_id,
        procedure,
        ..
    } = active_procedure_fixture("exact-cohort", false).await;
    for (at, label) in [(30, "cohort-first"), (31, "cohort-second")] {
        let (_, success, _) = record_independent_success(
            &mut writer,
            &procedure,
            ProcedurePublicationState::ActiveProbationary,
            repository_id,
            worktree_id,
            snapshot_id,
            at,
            label,
        )
        .await;
        writer.commit(&success, at).await.unwrap();
    }

    let (mut extra_usage, extra_command, _) = record_independent_success(
        &mut writer,
        &procedure,
        ProcedurePublicationState::ActiveProbationary,
        repository_id,
        worktree_id,
        snapshot_id,
        32,
        "cohort-extra-real-task",
    )
    .await;
    let (trigger_usage, promotion_command, _) = record_independent_success(
        &mut writer,
        &procedure,
        ProcedurePublicationState::ActiveProbationary,
        repository_id,
        worktree_id,
        snapshot_id,
        33,
        "cohort-trigger-real-task",
    )
    .await;
    assert_ne!(extra_usage.task_id, trigger_usage.task_id);
    assert!(has_objective_success_state(&extra_command));
    assert!(has_objective_success_state(&promotion_command));
    let stable = promotion_command
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::ProcedureStateRecorded(value) => Some(value.as_ref().clone()),
            _ => None,
        })
        .unwrap();
    let promotion_frontier = writer.project().await.unwrap().frontier;
    extra_usage.source_watermark = promotion_frontier;
    let extra_cohort = command(
        33,
        vec![
            JournalPayload::ProcedureUsageRecorded(Box::new(extra_usage.clone())),
            JournalPayload::ProcedureUsageRecorded(Box::new(trigger_usage)),
            JournalPayload::ProcedureStateRecorded(Box::new(stable)),
        ],
    );
    assert!(writer.commit(&extra_cohort, 33).await.is_err());
    assert_eq!(writer.project().await.unwrap().frontier, promotion_frontier);
    writer
        .commit_if_frontier(&promotion_command, 33, promotion_frontier)
        .await
        .unwrap();

    let (fifth_usage, fifth_command, _) = record_independent_success(
        &mut writer,
        &procedure,
        ProcedurePublicationState::ActiveStable,
        repository_id,
        worktree_id,
        snapshot_id,
        34,
        "stable-batch-fifth",
    )
    .await;
    assert!(!has_objective_success_state(&fifth_command));
    extra_usage.source_watermark = writer.project().await.unwrap().frontier;
    writer
        .commit(
            &command(
                34,
                vec![
                    JournalPayload::ProcedureUsageRecorded(Box::new(extra_usage)),
                    JournalPayload::ProcedureUsageRecorded(Box::new(fifth_usage)),
                ],
            ),
            34,
        )
        .await
        .unwrap();
    assert_eq!(
        writer.project().await.unwrap(),
        writer.full_projection().await.unwrap()
    );
}

#[tokio::test]
async fn conflicted_and_possible_duplicate_physical_evidence_never_support_outcome() {
    let ActiveProcedureFixture {
        _temp,
        mut writer,
        repository_id,
        worktree_id,
        snapshot_id,
        procedure,
        ..
    } = active_procedure_fixture("nonexact", false).await;

    for (offset, (physical_case, label)) in [
        (
            PhysicalEvidenceCase::PossibleDuplicate,
            "possible-duplicate",
        ),
        (PhysicalEvidenceCase::Conflicted, "conflicted"),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 40 + offset as i64;
        let mut use_task = task(repository_id, worktree_id, at);
        use_task.request_root_refs = vec![format!("request:s25:{label}")];
        let prepared = prepare_usage_evidence(
            &mut writer,
            &procedure,
            ProcedurePublicationState::ActiveProbationary,
            repository_id,
            worktree_id,
            snapshot_id,
            use_task,
            true,
            None,
            physical_case,
            ResultEvidenceCase::Passed,
            at,
            label,
        )
        .await;
        let outcome = prepared.usage;
        let authentic = prepared.command;
        assert_ne!(outcome.outcome_supported, ProcedureTruth::True);
        assert!(!has_objective_success_state(&authentic));

        let mut forged = outcome.clone();
        forged.correlation_state = ProcedureCorrelationState::Resolved;
        forged.action_aligned = ProcedureTruth::True;
        forged.verifier_aligned = ProcedureTruth::True;
        forged.outcome_supported = ProcedureTruth::True;
        assert!(forged.validate());
        let before = writer.project().await.unwrap().frontier;
        assert!(
            writer
                .commit(
                    &command(
                        at,
                        vec![JournalPayload::ProcedureUsageRecorded(Box::new(forged))],
                    ),
                    at,
                )
                .await
                .is_err()
        );
        assert_eq!(writer.project().await.unwrap().frontier, before);
        writer.commit(&authentic, at).await.unwrap();
    }
    assert_eq!(
        writer.project().await.unwrap(),
        writer.full_projection().await.unwrap()
    );
}

#[tokio::test]
async fn same_continuation_split_and_overlapping_root_tasks_cannot_promote() {
    for case in ["same-task", "continuation", "split", "overlapping-root"] {
        let ActiveProcedureFixture {
            _temp,
            mut writer,
            repository_id,
            worktree_id,
            snapshot_id,
            procedure,
            ..
        } = active_procedure_fixture(case, false).await;
        let mut first_task = task(repository_id, worktree_id, 50);
        first_task.request_root_refs = vec![format!("request:s25:{case}:first")];
        let first_prepared = prepare_usage_evidence(
            &mut writer,
            &procedure,
            ProcedurePublicationState::ActiveProbationary,
            repository_id,
            worktree_id,
            snapshot_id,
            first_task.clone(),
            true,
            None,
            PhysicalEvidenceCase::Exact,
            ResultEvidenceCase::Passed,
            50,
            &format!("{case}-first"),
        )
        .await;
        let first = first_prepared.usage;
        let first_command = first_prepared.command;
        writer.commit(&first_command, 50).await.unwrap();

        let mut second_task = task(repository_id, worktree_id, 51);
        second_task.request_root_refs = vec![format!("request:s25:{case}:second")];
        let second_prepared = prepare_usage_evidence(
            &mut writer,
            &procedure,
            ProcedurePublicationState::ActiveProbationary,
            repository_id,
            worktree_id,
            snapshot_id,
            second_task,
            true,
            None,
            PhysicalEvidenceCase::Exact,
            ResultEvidenceCase::Passed,
            51,
            &format!("{case}-second"),
        )
        .await;
        let second = second_prepared.usage;
        let second_command = second_prepared.command;
        writer.commit(&second_command, 51).await.unwrap();

        let (candidate_task, record_task, related_task) = match case {
            "same-task" => (first_task.clone(), false, None),
            "continuation" => {
                let mut candidate = task(repository_id, worktree_id, 52);
                candidate.request_root_refs = vec![format!("request:s25:{case}:candidate")];
                candidate.continuation_of_task_id = Some(first_task.task_id);
                (candidate, true, None)
            }
            "split" => {
                let mut candidate = task(repository_id, worktree_id, 52);
                candidate.request_root_refs = vec![format!("request:s25:{case}:candidate")];
                candidate.split_from_task_id = Some(first_task.task_id);
                let mut source = first_task.clone();
                source.revision_id = RevisionId::new_v7();
                source.predecessor_revision_id = Some(first_task.revision_id);
                source.split_into_task_ids = vec![candidate.task_id];
                source.lifecycle = TaskLifecycle::Superseded;
                source.closed_at_us = Some(52);
                source.source_watermark += 1;
                (candidate, true, Some(source))
            }
            "overlapping-root" => {
                let mut candidate = task(repository_id, worktree_id, 52);
                candidate.request_root_refs = first_task.request_root_refs.clone();
                (candidate, true, None)
            }
            _ => unreachable!(),
        };
        let candidate_prepared = prepare_usage_evidence(
            &mut writer,
            &procedure,
            ProcedurePublicationState::ActiveProbationary,
            repository_id,
            worktree_id,
            snapshot_id,
            candidate_task,
            record_task,
            related_task,
            PhysicalEvidenceCase::Exact,
            ResultEvidenceCase::Passed,
            52,
            &format!("{case}-candidate"),
        )
        .await;
        let candidate = candidate_prepared.usage;
        let candidate_command = candidate_prepared.command;
        assert!(!has_objective_success_state(&candidate_command));

        let stable =
            objective_success_state(procedure.revision_id, &[&first, &second, &candidate], 52);
        let before = writer.project().await.unwrap().frontier;
        assert!(
            writer
                .commit(
                    &command(
                        52,
                        vec![
                            JournalPayload::ProcedureUsageRecorded(Box::new(candidate.clone())),
                            JournalPayload::ProcedureStateRecorded(Box::new(stable)),
                        ],
                    ),
                    52,
                )
                .await
                .is_err(),
            "{case} must not pass the store-side independence proof"
        );
        assert_eq!(writer.project().await.unwrap().frontier, before);
        writer
            .commit(&candidate_command, 52)
            .await
            .unwrap_or_else(|error| panic!("{case} authentic command failed: {error:?}"));
        let projected = writer.project().await.unwrap();
        assert!(!projected.data_rows().any(|row| {
            row.current_revision_id.as_deref() == Some(procedure.revision_id.to_string().as_str())
                && row.publication_state.as_deref() == Some("active_stable")
        }));
        assert_eq!(projected, writer.full_projection().await.unwrap());
    }
}

#[tokio::test]
async fn local_harm_quarantines_new_apply_and_delays_promotion_until_next_success() {
    let ActiveProcedureFixture {
        _temp,
        mut writer,
        repository_id,
        worktree_id,
        snapshot_id,
        procedure,
        ..
    } = active_procedure_fixture("pre-stable-harm", false).await;
    let (first, first_command, _) = record_independent_success(
        &mut writer,
        &procedure,
        ProcedurePublicationState::ActiveProbationary,
        repository_id,
        worktree_id,
        snapshot_id,
        60,
        "pre-stable-first",
    )
    .await;
    writer.commit(&first_command, 60).await.unwrap();
    let (second, second_command, _) = record_independent_success(
        &mut writer,
        &procedure,
        ProcedurePublicationState::ActiveProbationary,
        repository_id,
        worktree_id,
        snapshot_id,
        61,
        "pre-stable-second",
    )
    .await;
    writer.commit(&second_command, 61).await.unwrap();

    let mut third_task = task(repository_id, worktree_id, 62);
    third_task.request_root_refs = vec!["request:s25:pre-stable-third".into()];
    let third_prepared = prepare_usage_evidence(
        &mut writer,
        &procedure,
        ProcedurePublicationState::ActiveProbationary,
        repository_id,
        worktree_id,
        snapshot_id,
        third_task,
        true,
        None,
        PhysicalEvidenceCase::Exact,
        ResultEvidenceCase::Passed,
        62,
        "pre-stable-third",
    )
    .await;

    let mut harm_task = task(repository_id, worktree_id, 63);
    harm_task.request_root_refs = vec!["request:s25:pre-stable-harm".into()];
    let harm_prepared = prepare_usage_evidence(
        &mut writer,
        &procedure,
        ProcedurePublicationState::ActiveProbationary,
        repository_id,
        worktree_id,
        snapshot_id,
        harm_task,
        true,
        None,
        PhysicalEvidenceCase::Exact,
        ResultEvidenceCase::NeutralFailure,
        63,
        "pre-stable-harm",
    )
    .await;
    writer.commit(&harm_prepared.command, 63).await.unwrap();
    let harm_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProcedureNegativeResolution::Command {
        level: ProcedureNegativeLevel::SuspectedHarm,
        command: localized,
    } = record_procedure_negative(
        &harm_view,
        proposal_context(64),
        ProcedureNegativeRequest {
            procedure_usage_id: harm_prepared.usage.procedure_usage_id,
            session_id: "session-s25-pre-stable-harm".into(),
            result_revision_ids: vec![harm_prepared.result.revision_id],
        },
    )
    .unwrap()
    else {
        panic!("the compatible failed usage must produce local suspected harm")
    };
    assert!(localized.events().iter().any(|event| {
        matches!(
            &event.payload,
            JournalPayload::ProcedureNegativeEvidenceRecorded(value)
                if value.attribution_basis == ProcedureAttributionBasis::ResolvedLocalized
                    && value.local_context.as_ref().is_some_and(|context| {
                        context.compatible(&harm_prepared.usage.local_context)
                    })
        )
    }));
    assert!(
        !localized
            .events()
            .iter()
            .any(|event| { matches!(event.payload, JournalPayload::ProcedureStateRecorded(_)) })
    );
    let localized_id = localized
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::ProcedureNegativeEvidenceRecorded(value) => {
                Some(value.negative_evidence_id)
            }
            _ => None,
        })
        .unwrap();
    writer.commit(&localized, 64).await.unwrap();

    let quarantined_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProcedureUsageResolution::NoDelta(retried) = begin_procedure_usage(
        &quarantined_view,
        proposal_context(64),
        &third_prepared.routed,
        third_prepared.workstream_id,
        third_prepared.exposure_revision_id,
    )
    .unwrap() else {
        panic!("an exact pre-harm begin must remain naturally idempotent")
    };
    assert_eq!(
        retried.usage_revision_id,
        third_prepared.begun_usage.usage_revision_id
    );

    let (new_workstream_id, new_exposure_revision_id) = activate_additional_exposure(
        &mut writer,
        &procedure,
        third_prepared.usage.task_id,
        repository_id,
        worktree_id,
        snapshot_id,
        65,
    )
    .await;
    let quarantined_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let candidates = || {
        vec![ProcedureCandidate {
            revision: (*procedure).clone(),
            publication: ProcedurePublicationState::ActiveProbationary,
            global_support: None,
            phase: ProcedurePhase::AtEntry,
            lexical_rank: 1,
        }]
    };
    let raw = ProcedureRouter::route(
        &third_prepared.route_search,
        candidates(),
        &third_prepared.route_constraints,
        None,
        true,
        false,
        false,
        true,
    );
    assert_eq!(raw.items[0].decision, ProcedureDecision::Apply);
    assert!(
        begin_procedure_usage(
            &quarantined_view,
            proposal_context(65),
            &raw.items[0],
            new_workstream_id,
            new_exposure_revision_id,
        )
        .is_err(),
        "a new raw APPLY anchor must not bypass compatible local quarantine"
    );
    let deferred = route_procedures_with_quarantine(
        &quarantined_view,
        &third_prepared.usage.local_context,
        &third_prepared.route_search,
        candidates(),
        &third_prepared.route_constraints,
        None,
        true,
        false,
        false,
        true,
    );
    assert_eq!(deferred.items[0].decision, ProcedureDecision::Defer);
    assert!(deferred.items[0].actions.is_none());
    assert!(
        deferred.items[0]
            .done
            .as_ref()
            .is_some_and(|done| done.success.is_empty())
    );
    let ProcedureUsageResolution::Command {
        usage: deferred_usage,
        command: deferred_command,
    } = begin_procedure_usage(
        &quarantined_view,
        proposal_context(65),
        &deferred.items[0],
        new_workstream_id,
        new_exposure_revision_id,
    )
    .unwrap()
    else {
        panic!("the sealed guardrail-only DEFER must create a Returned usage")
    };
    assert_eq!(deferred_usage.stage, ProcedureUsageStage::Returned);
    assert_eq!(
        deferred_usage.route_decision,
        ProcedureUsageRouteDecision::Defer
    );
    let mut forged_apply = deferred_usage.clone();
    forged_apply.route_decision = ProcedureUsageRouteDecision::Apply;
    assert!(forged_apply.validate());
    let before_forged_apply = writer.project().await.unwrap().frontier;
    assert!(
        writer
            .commit(
                &command(
                    65,
                    vec![JournalPayload::ProcedureUsageRecorded(Box::new(
                        forged_apply,
                    ))],
                ),
                65,
            )
            .await
            .is_err()
    );
    assert_eq!(
        writer.project().await.unwrap().frontier,
        before_forged_apply
    );
    writer.commit(&deferred_command, 65).await.unwrap();

    let active_harm_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let (third, third_command) = advance_procedure_usage(
        &active_harm_view,
        proposal_context(66),
        ProcedureUsageAdvance {
            usage_id: third_prepared.usage.procedure_usage_id,
            stage: ProcedureUsageStage::Outcome,
            attempt_ids: third_prepared.usage.attempt_ids.clone(),
            action_episode_revision_ids: third_prepared.usage.action_episode_revision_ids.clone(),
            verification_episode_revision_ids: third_prepared
                .usage
                .verification_episode_revision_ids
                .clone(),
            action_operation_refs: third_prepared.usage.action_operation_refs.clone(),
            verification_operation_refs: third_prepared.usage.verification_operation_refs.clone(),
            work_binding_revision_refs: third_prepared.usage.work_binding_revision_refs.clone(),
            scope_effect_refs: third_prepared.usage.scope_effect_refs.clone(),
            evidence_refs: third_prepared.usage.evidence_refs.clone(),
        },
        &ConstraintState {
            bindings: vec![ConstraintBinding {
                field: ConstraintField::ArtifactKind,
                value: ConstraintValue::Text("release".into()),
            }],
        },
        None,
    )
    .unwrap();
    assert_eq!(third.outcome_supported, ProcedureTruth::True);
    assert!(!has_objective_success_state(&third_command));
    let stable = objective_success_state(procedure.revision_id, &[&first, &second, &third], 66);
    let before = writer.project().await.unwrap().frontier;
    assert!(
        writer
            .commit(
                &command(
                    66,
                    vec![
                        JournalPayload::ProcedureUsageRecorded(Box::new(third.clone())),
                        JournalPayload::ProcedureStateRecorded(Box::new(stable)),
                    ],
                ),
                66,
            )
            .await
            .is_err()
    );
    assert_eq!(writer.project().await.unwrap().frontier, before);
    writer.commit(&third_command, 66).await.unwrap();
    let projected = writer.project().await.unwrap();
    assert!(!projected.data_rows().any(|row| {
        row.current_revision_id.as_deref() == Some(procedure.revision_id.to_string().as_str())
            && row.publication_state.as_deref() == Some("active_stable")
    }));

    let mut post_negative_replay = harm_prepared.result.clone();
    post_negative_replay.result_evidence_id = evertrace_domain::ids::ResultEvidenceId::new_v7();
    post_negative_replay.revision_id = RevisionId::new_v7();
    post_negative_replay.parent_revision_id = None;
    post_negative_replay.verifier_receipt = Some(VerifierReceipt {
        verifier_version: "evertrace.result_reparse.v1".into(),
        status: VerifierStatus::Passed,
        failure_code: None,
    });
    post_negative_replay.completeness = EvidenceCompleteness::Complete;
    post_negative_replay.failure = None;
    post_negative_replay.created_at_us = 67;
    post_negative_replay.validate().unwrap();
    writer
        .commit(
            &command(
                67,
                vec![JournalPayload::ResultEvidenceRecorded(Box::new(
                    post_negative_replay.clone(),
                ))],
            ),
            67,
        )
        .await
        .unwrap();
    let replay_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let dismissed = review_procedure_negative(
        &replay_view,
        proposal_context(68),
        localized_id,
        ProcedureNegativeReviewProof::ReplayDismissed {
            result_revision_ids: vec![post_negative_replay.revision_id],
        },
    )
    .unwrap();
    writer.commit(&dismissed, 68).await.unwrap();

    let (fourth, fourth_command, _) = record_independent_success(
        &mut writer,
        &procedure,
        ProcedurePublicationState::ActiveProbationary,
        repository_id,
        worktree_id,
        snapshot_id,
        69,
        "post-dismiss-fourth",
    )
    .await;
    let stable = fourth_command
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::ProcedureStateRecorded(value)
                if value.to_state == ProcedurePublicationState::ActiveStable =>
            {
                Some(value.as_ref())
            }
            _ => None,
        })
        .expect("the next independent success after dismissal must promote");
    assert_eq!(stable.evidence_refs.len(), 3);
    assert!(
        stable
            .evidence_refs
            .contains(&fourth.usage_revision_id.to_string())
    );
    writer.commit(&fourth_command, 69).await.unwrap();
    let projected = writer.project().await.unwrap();
    assert!(projected.data_rows().any(|row| {
        row.current_revision_id.as_deref() == Some(procedure.revision_id.to_string().as_str())
            && row.publication_state.as_deref() == Some("active_stable")
    }));
    assert_eq!(projected, writer.full_projection().await.unwrap());
}

#[tokio::test]
async fn review_hold_and_suspended_accept_later_negative_ledgers_without_same_state_events() {
    let ActiveProcedureFixture {
        _temp,
        mut writer,
        repository_id,
        worktree_id,
        snapshot_id,
        procedure,
        ..
    } = active_procedure_fixture("held-negatives", true).await;
    let mut prepared = Vec::new();
    for (offset, result_case) in [
        ResultEvidenceCase::NeutralFailure,
        ResultEvidenceCase::NeutralFailure,
        ResultEvidenceCase::ReplayViolation,
        ResultEvidenceCase::NeutralFailure,
    ]
    .into_iter()
    .enumerate()
    {
        let at = 70 + offset as i64;
        let label = format!("held-negative-{offset}");
        let mut harm_task = task(repository_id, worktree_id, at);
        harm_task.request_root_refs = vec![format!("request:s25:{label}")];
        let prepared_usage = prepare_usage_evidence(
            &mut writer,
            &procedure,
            ProcedurePublicationState::ActiveProbationary,
            repository_id,
            worktree_id,
            snapshot_id,
            harm_task,
            true,
            None,
            PhysicalEvidenceCase::Exact,
            result_case,
            at,
            &label,
        )
        .await;
        writer.commit(&prepared_usage.command, at).await.unwrap();
        prepared.push(prepared_usage);
    }

    let view = ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProcedureNegativeResolution::Command {
        level: ProcedureNegativeLevel::SuspectedHarm,
        command: first,
    } = record_procedure_negative(
        &view,
        proposal_context(80),
        ProcedureNegativeRequest {
            procedure_usage_id: prepared[0].usage.procedure_usage_id,
            session_id: "session-s25-review-hold-first".into(),
            result_revision_ids: vec![prepared[0].result.revision_id],
        },
    )
    .unwrap()
    else {
        panic!("context-unbounded suspected harm must be recorded")
    };
    assert!(first.events().iter().any(|event| {
        matches!(
            &event.payload,
            JournalPayload::ProcedureStateRecorded(value)
                if value.to_state == ProcedurePublicationState::ReviewHold
                    && value.reason == ProcedureStateReason::SuspectedHarm
        )
    }));
    writer.commit(&first, 80).await.unwrap();

    let held_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProcedureUsageResolution::NoDelta(retried) = begin_procedure_usage(
        &held_view,
        proposal_context(80),
        &prepared[0].routed,
        prepared[0].workstream_id,
        prepared[0].exposure_revision_id,
    )
    .unwrap() else {
        panic!("an exact committed begin must remain idempotent after ReviewHold")
    };
    assert_eq!(
        retried.usage_revision_id,
        prepared[0].usage.usage_revision_id
    );
    let ProcedureNegativeResolution::Command {
        level: ProcedureNegativeLevel::SuspectedHarm,
        command: second,
    } = record_procedure_negative(
        &held_view,
        proposal_context(81),
        ProcedureNegativeRequest {
            procedure_usage_id: prepared[1].usage.procedure_usage_id,
            session_id: "session-s25-review-hold-second".into(),
            result_revision_ids: vec![prepared[1].result.revision_id],
        },
    )
    .unwrap()
    else {
        panic!("ReviewHold must still accept a distinct negative ledger")
    };
    assert!(second.events().iter().any(|event| {
        matches!(
            &event.payload,
            JournalPayload::ProcedureNegativeReviewRecorded(value)
                if value.status == ProcedureNegativeReviewStatus::Pending
        )
    }));
    assert!(
        !second
            .events()
            .iter()
            .any(|event| { matches!(event.payload, JournalPayload::ProcedureStateRecorded(_)) })
    );
    writer.commit(&second, 81).await.unwrap();
    assert_eq!(
        writer.project().await.unwrap(),
        writer.full_projection().await.unwrap()
    );

    let held_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProcedureNegativeResolution::Command {
        level: ProcedureNegativeLevel::ConfirmedHarm,
        command: confirmed,
    } = record_procedure_negative(
        &held_view,
        proposal_context(82),
        ProcedureNegativeRequest {
            procedure_usage_id: prepared[2].usage.procedure_usage_id,
            session_id: "session-s25-review-hold-confirmed".into(),
            result_revision_ids: vec![prepared[2].result.revision_id],
        },
    )
    .unwrap()
    else {
        panic!("confirmed harm must upgrade ReviewHold to Suspended")
    };
    assert!(confirmed.events().iter().any(|event| {
        matches!(
            &event.payload,
            JournalPayload::ProcedureStateRecorded(value)
                if value.to_state == ProcedurePublicationState::Suspended
                    && value.reason == ProcedureStateReason::ConfirmedHarm
        )
    }));
    writer.commit(&confirmed, 82).await.unwrap();

    let suspended_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProcedureNegativeResolution::Command {
        level: ProcedureNegativeLevel::SuspectedHarm,
        command: after_suspended,
    } = record_procedure_negative(
        &suspended_view,
        proposal_context(83),
        ProcedureNegativeRequest {
            procedure_usage_id: prepared[3].usage.procedure_usage_id,
            session_id: "session-s25-suspended-negative".into(),
            result_revision_ids: vec![prepared[3].result.revision_id],
        },
    )
    .unwrap()
    else {
        panic!("Suspended must retain later weaker negative evidence")
    };
    assert!(after_suspended.events().iter().any(|event| {
        matches!(
            &event.payload,
            JournalPayload::ProcedureNegativeReviewRecorded(value)
                if value.status == ProcedureNegativeReviewStatus::Pending
        )
    }));
    assert!(
        !after_suspended
            .events()
            .iter()
            .any(|event| { matches!(event.payload, JournalPayload::ProcedureStateRecorded(_)) })
    );
    writer.commit(&after_suspended, 83).await.unwrap();
    assert_eq!(
        writer.project().await.unwrap(),
        writer.full_projection().await.unwrap()
    );
}

#[tokio::test]
async fn real_router_usage_outcome_quarantine_review_and_confirmed_harm_chain() {
    let ActiveProcedureFixture {
        _temp,
        store_path,
        mut writer,
        repository_id,
        worktree_id,
        snapshot_id,
        evidence_receipt,
        procedure,
        config,
    } = active_procedure_fixture("real", false).await;
    let service = RevisionProposalService;
    let task = task(repository_id, worktree_id, 5);
    let stream = workstream(task.task_id, repository_id, worktree_id, 5);
    writer
        .commit(
            &command(
                5,
                vec![
                    JournalPayload::TaskRecorded(Box::new(task.clone())),
                    JournalPayload::WorkstreamRecorded(Box::new(stream.clone())),
                ],
            ),
            5,
        )
        .await
        .unwrap();
    let (intent_receipt, intent) = physical_source(
        "physical-intent",
        ObservationRole::Intent,
        repository_id,
        worktree_id,
    );
    let (result_receipt, result_observation) = physical_source(
        "physical-result",
        ObservationRole::Result,
        repository_id,
        worktree_id,
    );
    writer
        .commit(
            &command(6, source_payloads(intent_receipt.clone(), intent.clone())),
            6,
        )
        .await
        .unwrap();
    writer
        .commit(
            &command(
                7,
                source_payloads(result_receipt, result_observation.clone()),
            ),
            7,
        )
        .await
        .unwrap();
    let normalized = PhysicalNormalizer::new(1)
        .unwrap()
        .normalize(&[intent.clone(), result_observation], None)
        .unwrap();
    let operation_id = normalized.operations[0].operation_id;
    writer
        .commit(
            &normalized
                .journal_command(CommandId::new_v7(), 8, CONFIG, "s25-test-v1")
                .unwrap(),
            8,
        )
        .await
        .unwrap();
    let strategy = StrategyContract {
        hypothesis: "fixed verifier resolves the failure".into(),
        intervention: "run fixed verifier".into(),
        intervention_family: "procedure".into(),
        search_policy_ref: Some(procedure.revision_id.to_string()),
        objective_ref: Some("objective:verification".into()),
        expected_effect: "verification passes".into(),
        target_refs: vec!["artifact".into()],
        acceptance_boundary_ref: stream.phase_contract.acceptance_boundary.clone(),
    };
    let initial_attempt = new_attempt(
        task.task_id,
        stream.workstream_id,
        Some(repository_id),
        vec![worktree_id],
        Vec::new(),
        strategy.clone(),
        8,
    )
    .unwrap();
    writer
        .commit(
            &command(
                8,
                vec![JournalPayload::AttemptRecorded(Box::new(
                    initial_attempt.clone(),
                ))],
            ),
            8,
        )
        .await
        .unwrap();
    let episode = new_episode(&stream, Some(snapshot_id), 9).unwrap();
    let exposure_revision_id = episode.revision_id;
    let binding_id = WorkBindingRevisionId::new_v7();
    let mut adopted = initial_attempt.clone();
    adopted.revision_id = RevisionId::new_v7();
    adopted.predecessor_revision_id = Some(initial_attempt.revision_id);
    adopted.revision_generation = 2;
    adopted.episode_id = Some(episode.episode_id);
    adopted.adoption_status = AttemptAdoptionStatus::Selected;
    adopted.verification = AttemptVerification::Passed;
    adopted.work_binding_revision_refs = vec![binding_id];
    adopted.source_watermark = 9;
    let run = create_experiment_run(
        &adopted,
        RunCreateInput {
            workstream_id: stream.workstream_id,
            source_receipt_refs: vec![intent_receipt.source_receipt_id],
            code_snapshot_id: snapshot_id,
            data_fingerprint: "data-s25".into(),
            normalized_config: vec![ContractField {
                name: "mode".into(),
                value: "fixed".into(),
            }],
            variable_declaration: VariableDeclaration {
                varied: Vec::new(),
                fixed: vec!["mode".into()],
                uncontrolled: Vec::new(),
            },
            seed_policy: SeedPolicy::Fixed,
            seed_values: vec!["25".into()],
            nondeterministic: false,
            metric_definition: "verification".into(),
            metric_extractor_version: "evertrace.result_metric.v1".into(),
            multi_cas_metric_policy: MultiCasMetricPolicy::RejectMultipleParsed,
            environment_fingerprint: "environment-s25".into(),
            created_at_us: 9,
        },
    )
    .unwrap();
    let cas_id: CasId = format!("cas:{}", "ab".repeat(32)).parse().unwrap();
    let result = ResultEvidence {
        result_evidence_id: evertrace_domain::ids::ResultEvidenceId::new_v7(),
        revision_id: RevisionId::new_v7(),
        parent_revision_id: None,
        experiment_run_id: run.run_id,
        experiment_run_revision_id: run.revision_id,
        result_scope: ResultScope::Partial,
        raw_artifact_refs: Vec::new(),
        raw_cas_refs: vec![cas_id],
        parsed_metric: Some(MetricValue {
            decimal: "1".into(),
            unit: "boolean".into(),
            uncertainty_decimal: None,
        }),
        parser_receipt: ParserReceipt {
            parser_version: "evertrace.result_metric.v1".into(),
            input_artifact_refs: Vec::new(),
            input_cas_refs: vec![cas_id],
            status: ParserStatus::Parsed,
            failure_code: None,
        },
        verifier_receipt: Some(VerifierReceipt {
            verifier_version: "evertrace.result_reparse.v1".into(),
            status: VerifierStatus::Passed,
            failure_code: None,
        }),
        completeness: EvidenceCompleteness::Complete,
        failure: None,
        created_at_us: 9,
    };
    let result_ref = result.revision_id.to_string();
    adopted.parent_verification_refs = vec![result_ref.clone()];
    adopted.outcome_refs = vec![result_ref.clone()];
    adopted.outcome_state = AttemptOutcomeState::Known;
    adopted.validate().unwrap();
    let binding = WorkBindingRevision {
        work_binding_revision_id: binding_id,
        operation_id,
        revision_generation: 1,
        predecessor_revision_id: None,
        primary_binding: PrimaryWorkBinding {
            task_id: Some(task.task_id),
            workstream_id: Some(stream.workstream_id),
            episode_id: Some(episode.episode_id),
            attempt_id: Some(adopted.attempt_id),
            experiment_run_id: Some(run.run_id),
            competing_group_id: None,
        },
        secondary_bindings: Vec::new(),
        scope_effect_refs: Vec::new(),
        assignment_status: AssignmentStatus::Resolved,
        evidence_refs: vec![intent.source_observation_id.to_string()],
        resolver_version: 1,
    };
    let mut episode = episode;
    episode.attempt_ids = vec![adopted.attempt_id];
    episode.validate().unwrap();
    let activation = activate_episode(
        work_context(9),
        &stream,
        episode,
        vec![adopted.clone()],
        vec![binding.clone()],
    )
    .unwrap();
    let mut activation_events = activation.events().to_vec();
    activation_events.extend([
        JournalEventDraft::runtime(
            9,
            CONFIG,
            "s25-test-v1",
            JournalPayload::ExperimentRunRecorded(Box::new(run.clone())),
        ),
        JournalEventDraft::runtime(
            9,
            CONFIG,
            "s25-test-v1",
            JournalPayload::ResultEvidenceRecorded(Box::new(result.clone())),
        ),
    ]);
    writer
        .commit(
            &JournalCommand::new(CommandId::new_v7(), activation_events).unwrap(),
            9,
        )
        .await
        .unwrap();
    let snapshot = writer.project().await.unwrap();
    assert!(snapshot.data_rows().any(|row| {
        row.current_revision_id.as_deref() == Some(procedure.revision_id.to_string().as_str())
            && row.publication_state.as_deref() == Some("active_probationary")
    }));
    let search = SearchContext {
        intent: SearchIntent::FailureRecovery,
        raw_query: "verifier failed".into(),
        query_facets: QueryFacetSet {
            parse_status: FacetParseStatus::Complete,
            exact_identifiers: Vec::new(),
            condition_literals: Vec::new(),
            relation_requirements: Vec::new(),
            polarity: Polarity::Positive,
            explicit_exclusions: Vec::new(),
            temporal_mode: TemporalMode::Any,
            temporal_qualifiers: Vec::new(),
            quantity_constraints: Vec::new(),
            scope_boundary: None,
            source_boundary: None,
            answer_shape: Some(AnswerShape::EntityList),
            lifecycle_boundary: LifecycleBoundary::Active,
        },
        task_id: Some(task.task_id),
        repository_id: Some(repository_id),
        worktree_id: Some(worktree_id),
        suppression: SuppressionSnapshot::Current {
            generation: 0,
            ref_hashes: Default::default(),
        },
        budget: RetrievalBudget {
            candidates_remaining: 8,
            tokens_remaining: 512,
            latency_us_remaining: 100_000,
            hops_remaining: 2,
            follow_ups_remaining: 1,
        },
    };
    let bindings = vec![
        ConstraintBinding {
            field: ConstraintField::ArtifactKind,
            value: ConstraintValue::Text("pending".into()),
        },
        ConstraintBinding {
            field: ConstraintField::VerifierState,
            value: ConstraintValue::Text("failed".into()),
        },
        ConstraintBinding {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text("verify".into()),
        },
    ];
    let constraints = ConstraintState { bindings };
    let routed = ProcedureRouter::route(
        &search,
        vec![ProcedureCandidate {
            revision: (*procedure).clone(),
            publication: ProcedurePublicationState::ActiveProbationary,
            global_support: None,
            phase: ProcedurePhase::AtEntry,
            lexical_rank: 1,
        }],
        &constraints,
        None,
        true,
        false,
        false,
        true,
    );
    assert_eq!(routed.items[0].decision, ProcedureDecision::Apply);
    let usage_view = ProcedureUsageCurrentView::from_snapshot(&snapshot).unwrap();
    let mut forged_phase = routed.items[0].clone();
    forged_phase.phase = ProcedurePhase::InProgress;
    assert!(
        begin_procedure_usage(
            &usage_view,
            proposal_context(7),
            &forged_phase,
            stream.workstream_id,
            exposure_revision_id,
        )
        .is_err(),
        "the public route fields cannot override the sealed router proof"
    );
    let ProcedureUsageResolution::Command {
        usage,
        command: usage_command,
    } = begin_procedure_usage(
        &usage_view,
        proposal_context(7),
        &routed.items[0],
        stream.workstream_id,
        exposure_revision_id,
    )
    .unwrap()
    else {
        panic!("first exact route exposure must create usage")
    };
    writer.commit(&usage_command, 7).await.unwrap();
    let (post_intent_receipt, post_intent) = physical_source(
        "post-intent",
        ObservationRole::Intent,
        repository_id,
        worktree_id,
    );
    let (post_result_receipt, post_result_observation) = physical_source(
        "post-result",
        ObservationRole::Result,
        repository_id,
        worktree_id,
    );
    writer
        .commit(
            &command(
                10,
                source_payloads(post_intent_receipt, post_intent.clone()),
            ),
            10,
        )
        .await
        .unwrap();
    writer
        .commit(
            &command(
                11,
                source_payloads(post_result_receipt, post_result_observation.clone()),
            ),
            11,
        )
        .await
        .unwrap();
    let post_normalized = PhysicalNormalizer::new(1)
        .unwrap()
        .normalize(&[post_intent.clone(), post_result_observation], None)
        .unwrap();
    let post_operation_id = post_normalized.operations[0].operation_id;
    writer
        .commit(
            &post_normalized
                .journal_command(CommandId::new_v7(), 12, CONFIG, "s25-test-v1")
                .unwrap(),
            12,
        )
        .await
        .unwrap();
    let post_binding_id = WorkBindingRevisionId::new_v7();
    let mut post_attempt = adopted.clone();
    post_attempt.revision_id = RevisionId::new_v7();
    post_attempt.predecessor_revision_id = Some(adopted.revision_id);
    post_attempt.revision_generation = 3;
    post_attempt.source_watermark = 13;
    post_attempt
        .work_binding_revision_refs
        .push(post_binding_id);
    post_attempt.work_binding_revision_refs.sort();
    let mut post_result = result.clone();
    post_result.result_evidence_id = evertrace_domain::ids::ResultEvidenceId::new_v7();
    post_result.revision_id = RevisionId::new_v7();
    post_result.created_at_us = 13;
    let post_result_ref = post_result.revision_id.to_string();
    post_attempt
        .parent_verification_refs
        .push(post_result_ref.clone());
    post_attempt.parent_verification_refs.sort();
    post_attempt.outcome_refs.push(post_result_ref.clone());
    post_attempt.outcome_refs.sort();
    adopted.validate_successor(&post_attempt).unwrap();
    let post_binding = WorkBindingRevision {
        work_binding_revision_id: post_binding_id,
        operation_id: post_operation_id,
        revision_generation: 1,
        predecessor_revision_id: None,
        primary_binding: PrimaryWorkBinding {
            task_id: Some(task.task_id),
            workstream_id: Some(stream.workstream_id),
            episode_id: adopted.episode_id,
            attempt_id: Some(post_attempt.attempt_id),
            experiment_run_id: Some(run.run_id),
            competing_group_id: None,
        },
        secondary_bindings: Vec::new(),
        scope_effect_refs: Vec::new(),
        assignment_status: AssignmentStatus::Resolved,
        evidence_refs: vec![post_intent.source_observation_id.to_string()],
        resolver_version: 1,
    };
    writer
        .commit(
            &command(
                13,
                vec![
                    JournalPayload::AttemptRecorded(Box::new(post_attempt.clone())),
                    JournalPayload::WorkBindingRecorded(Box::new(post_binding.clone())),
                    JournalPayload::ResultEvidenceRecorded(Box::new(post_result)),
                ],
            ),
            13,
        )
        .await
        .unwrap();
    let snapshot = writer.project().await.unwrap();
    assert!(snapshot.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("procedure_usage_revision")
            && row.object_id.as_deref() == Some(usage.procedure_usage_id.to_string().as_str())
    }));
    let replay_view = ProcedureUsageCurrentView::from_snapshot(&snapshot).unwrap();
    assert!(matches!(
        begin_procedure_usage(
            &replay_view,
            proposal_context(8),
            &routed.items[0],
            stream.workstream_id,
            exposure_revision_id,
        )
        .unwrap(),
        ProcedureUsageResolution::NoDelta(_)
    ));
    let view = ProcedureUsageCurrentView::from_snapshot(&snapshot).unwrap();
    let completion_bindings = vec![ConstraintBinding {
        field: ConstraintField::ArtifactKind,
        value: ConstraintValue::Text("release".into()),
    }];
    let (outcome, outcome_command) = advance_procedure_usage(
        &view,
        proposal_context(14),
        ProcedureUsageAdvance {
            usage_id: usage.procedure_usage_id,
            stage: ProcedureUsageStage::Outcome,
            attempt_ids: vec![post_attempt.attempt_id],
            action_episode_revision_ids: vec![exposure_revision_id],
            verification_episode_revision_ids: vec![exposure_revision_id],
            action_operation_refs: vec![post_operation_id],
            verification_operation_refs: vec![post_operation_id],
            work_binding_revision_refs: vec![post_binding_id],
            scope_effect_refs: Vec::new(),
            evidence_refs: vec![post_result_ref.clone()],
        },
        &ConstraintState {
            bindings: completion_bindings,
        },
        None,
    )
    .unwrap();
    assert_eq!(outcome.outcome_supported, ProcedureTruth::True);
    writer.commit(&outcome_command, 14).await.unwrap();
    let projected = writer.project().await.unwrap();
    assert!(projected.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("procedure_usage_revision")
            && row.current_revision_id.as_deref()
                == Some(outcome.usage_revision_id.to_string().as_str())
    }));
    let relations = writer.relation_rows().await.unwrap();
    assert!(relations.iter().any(|row| {
        row.relation_kind.as_deref() == Some("procedure_usage_to_action_operation")
            && row.target_id.as_deref() == Some(post_operation_id.to_string().as_str())
    }));
    let mut run_successor = run.clone();
    run_successor.revision_id = RevisionId::new_v7();
    run_successor.parent_revision_id = Some(run.revision_id);
    run_successor
        .source_receipt_refs
        .push(evidence_receipt.source_receipt_id);
    run_successor.source_receipt_refs.sort();
    run.validate_successor(&run_successor).unwrap();
    let run_successor_id = run_successor.revision_id;
    writer
        .commit(
            &command(
                14,
                vec![JournalPayload::ExperimentRunRecorded(Box::new(
                    run_successor,
                ))],
            ),
            14,
        )
        .await
        .unwrap();
    assert_eq!(
        writer.project().await.unwrap(),
        writer.full_projection().await.unwrap(),
        "a later Run revision cannot corrupt historical Result linkage"
    );
    let stale_result_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert!(
        advance_procedure_usage(
            &stale_result_view,
            proposal_context(14),
            ProcedureUsageAdvance {
                usage_id: outcome.procedure_usage_id,
                stage: ProcedureUsageStage::Outcome,
                attempt_ids: outcome.attempt_ids.clone(),
                action_episode_revision_ids: outcome.action_episode_revision_ids.clone(),
                verification_episode_revision_ids: outcome
                    .verification_episode_revision_ids
                    .clone(),
                action_operation_refs: outcome.action_operation_refs.clone(),
                verification_operation_refs: outcome.verification_operation_refs.clone(),
                work_binding_revision_refs: outcome.work_binding_revision_refs.clone(),
                scope_effect_refs: outcome.scope_effect_refs.clone(),
                evidence_refs: outcome.evidence_refs.clone(),
            },
            &ConstraintState {
                bindings: vec![ConstraintBinding {
                    field: ConstraintField::ArtifactKind,
                    value: ConstraintValue::Text("release".into()),
                }],
            },
            None,
        )
        .is_err()
    );
    let mut occurrence_successor = post_normalized.occurrences[0].clone();
    occurrence_successor.normalization_revision += 1;
    occurrence_successor.previous_normalization_revision =
        Some(post_normalized.occurrences[0].normalization_revision);
    let mut operation_successor = post_normalized.operations[0].clone();
    operation_successor.operation_revision += 1;
    operation_successor.previous_operation_revision =
        Some(post_normalized.operations[0].operation_revision);
    operation_successor.operation_resolver_version += 1;
    let mut binding_successor = post_binding.clone();
    binding_successor.work_binding_revision_id = WorkBindingRevisionId::new_v7();
    binding_successor.revision_generation += 1;
    binding_successor.predecessor_revision_id = Some(post_binding_id);
    binding_successor.resolver_version += 1;
    post_binding.validate_successor(&binding_successor).unwrap();
    let binding_successor_id = binding_successor.work_binding_revision_id;
    let mut successor_normalization = post_normalized.clone();
    successor_normalization.occurrences[0] = occurrence_successor;
    successor_normalization.operations[0] = operation_successor;
    let successor_normalization_command = successor_normalization
        .journal_command(CommandId::new_v7(), 14, CONFIG, "s25-test-v1")
        .unwrap();
    writer
        .commit(&successor_normalization_command, 14)
        .await
        .unwrap();
    let mut post_attempt_successor = post_attempt.clone();
    post_attempt_successor.revision_id = RevisionId::new_v7();
    post_attempt_successor.predecessor_revision_id = Some(post_attempt.revision_id);
    post_attempt_successor.revision_generation += 1;
    post_attempt_successor.source_watermark += 1;
    post_attempt_successor
        .work_binding_revision_refs
        .push(binding_successor_id);
    post_attempt_successor.work_binding_revision_refs.sort();
    post_attempt
        .validate_successor(&post_attempt_successor)
        .unwrap();
    writer
        .commit(
            &command(
                14,
                vec![
                    JournalPayload::AttemptRecorded(Box::new(post_attempt_successor)),
                    JournalPayload::WorkBindingRecorded(Box::new(binding_successor)),
                ],
            ),
            14,
        )
        .await
        .unwrap();
    assert_eq!(
        writer.project().await.unwrap(),
        writer.full_projection().await.unwrap(),
        "legal physical successors cannot retroactively invalidate usage"
    );
    let stale_binding_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert!(
        advance_procedure_usage(
            &stale_binding_view,
            proposal_context(14),
            ProcedureUsageAdvance {
                usage_id: outcome.procedure_usage_id,
                stage: ProcedureUsageStage::Outcome,
                attempt_ids: outcome.attempt_ids.clone(),
                action_episode_revision_ids: outcome.action_episode_revision_ids.clone(),
                verification_episode_revision_ids: outcome
                    .verification_episode_revision_ids
                    .clone(),
                action_operation_refs: outcome.action_operation_refs.clone(),
                verification_operation_refs: outcome.verification_operation_refs.clone(),
                work_binding_revision_refs: outcome.work_binding_revision_refs.clone(),
                scope_effect_refs: outcome.scope_effect_refs.clone(),
                evidence_refs: outcome.evidence_refs.clone(),
            },
            &ConstraintState {
                bindings: vec![ConstraintBinding {
                    field: ConstraintField::ArtifactKind,
                    value: ConstraintValue::Text("release".into()),
                }],
            },
            None,
        )
        .is_err()
    );
    let mut adverse = result.clone();
    adverse.result_evidence_id = evertrace_domain::ids::ResultEvidenceId::new_v7();
    adverse.revision_id = RevisionId::new_v7();
    adverse.experiment_run_revision_id = run_successor_id;
    adverse.parsed_metric = None;
    adverse.parser_receipt.status = ParserStatus::Failed;
    adverse.parser_receipt.failure_code = Some(ParserFailureCode::MetricParseFailed);
    adverse.verifier_receipt = None;
    adverse.completeness = EvidenceCompleteness::Incomplete;
    adverse.failure = Some(ResultFailure::Parser(ParserFailureCode::MetricParseFailed));
    adverse.created_at_us = 15;
    adverse.validate().unwrap();
    writer
        .commit(
            &command(
                15,
                vec![JournalPayload::ResultEvidenceRecorded(Box::new(
                    adverse.clone(),
                ))],
            ),
            15,
        )
        .await
        .unwrap();
    let adverse_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert!(matches!(
        record_procedure_negative(
            &adverse_view,
            proposal_context(16),
            ProcedureNegativeRequest {
                procedure_usage_id: outcome.procedure_usage_id,
                session_id: "session-s25-parser-only".into(),
                result_revision_ids: vec![adverse.revision_id],
            },
        )
        .unwrap(),
        ProcedureNegativeResolution::NoDelta
    ));

    let (_second_success, second_success_command, second_result_id) = record_independent_success(
        &mut writer,
        &procedure,
        ProcedurePublicationState::ActiveProbationary,
        repository_id,
        worktree_id,
        snapshot_id,
        15,
        "promotion-second",
    )
    .await;
    assert!(
        !second_success_command
            .events()
            .iter()
            .any(|event| matches!(event.payload, JournalPayload::ProcedureStateRecorded(_)))
    );
    writer.commit(&second_success_command, 15).await.unwrap();
    let wrong_link_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert!(
        record_procedure_negative(
            &wrong_link_view,
            proposal_context(15),
            ProcedureNegativeRequest {
                procedure_usage_id: outcome.procedure_usage_id,
                session_id: "wrong-attempt-link".into(),
                result_revision_ids: vec![second_result_id],
            },
        )
        .is_err()
    );
    let promotion_frontier = writer.project().await.unwrap().frontier;
    let (_third_success, third_success_command, _) = record_independent_success(
        &mut writer,
        &procedure,
        ProcedurePublicationState::ActiveProbationary,
        repository_id,
        worktree_id,
        snapshot_id,
        16,
        "promotion-third",
    )
    .await;
    assert_eq!(
        third_success_command
            .events()
            .iter()
            .filter(|event| matches!(event.payload, JournalPayload::ProcedureStateRecorded(_)))
            .count(),
        1
    );
    let third_frontier = writer.project().await.unwrap().frontier;
    let trigger_usage = third_success_command
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::ProcedureUsageRecorded(value) => Some(value.as_ref().clone()),
            _ => None,
        })
        .unwrap();
    let stable_event = third_success_command
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::ProcedureStateRecorded(value) => Some(value.as_ref().clone()),
            _ => None,
        })
        .unwrap();
    let usage_only = command(
        16,
        vec![JournalPayload::ProcedureUsageRecorded(Box::new(
            trigger_usage.clone(),
        ))],
    );
    assert!(writer.commit(&usage_only, 16).await.is_err());
    assert_eq!(writer.project().await.unwrap().frontier, third_frontier);
    let state_only = command(
        16,
        vec![JournalPayload::ProcedureStateRecorded(Box::new(
            stable_event.clone(),
        ))],
    );
    assert!(writer.commit(&state_only, 16).await.is_err());
    assert_eq!(writer.project().await.unwrap().frontier, third_frontier);
    let promoted = writer
        .commit_if_frontier(&third_success_command, 16, third_frontier)
        .await
        .unwrap();
    let replayed = writer.commit(&third_success_command, 16).await.unwrap();
    assert_eq!(promoted.first_seq, replayed.first_seq);
    assert_eq!(promoted.last_seq, replayed.last_seq);
    assert_eq!(promoted.event_ids, replayed.event_ids);
    assert!(
        replayed.replayed,
        "lost acknowledgement must replay exactly"
    );
    assert!(writer.project().await.unwrap().frontier > promotion_frontier);
    assert_eq!(
        writer.project().await.unwrap(),
        writer.full_projection().await.unwrap()
    );
    let (_fourth_success, fourth_success_command, _) = record_independent_success(
        &mut writer,
        &procedure,
        ProcedurePublicationState::ActiveStable,
        repository_id,
        worktree_id,
        snapshot_id,
        16,
        "stable-fourth",
    )
    .await;
    assert!(
        !fourth_success_command
            .events()
            .iter()
            .any(|event| matches!(event.payload, JournalPayload::ProcedureStateRecorded(_)))
    );
    writer.commit(&fourth_success_command, 16).await.unwrap();

    let harm_task = self::task(repository_id, worktree_id, 17);
    let harm_stream = workstream(harm_task.task_id, repository_id, worktree_id, 17);
    let harm_initial_attempt = new_attempt(
        harm_task.task_id,
        harm_stream.workstream_id,
        Some(repository_id),
        vec![worktree_id],
        Vec::new(),
        strategy,
        17,
    )
    .unwrap();
    writer
        .commit(
            &command(
                17,
                vec![
                    JournalPayload::TaskRecorded(Box::new(harm_task.clone())),
                    JournalPayload::WorkstreamRecorded(Box::new(harm_stream.clone())),
                    JournalPayload::AttemptRecorded(Box::new(harm_initial_attempt.clone())),
                ],
            ),
            17,
        )
        .await
        .unwrap();
    let mut harm_episode = new_episode(&harm_stream, Some(snapshot_id), 18).unwrap();
    let harm_exposure_revision_id = harm_episode.revision_id;
    let mut harm_adopted = harm_initial_attempt.clone();
    harm_adopted.revision_id = RevisionId::new_v7();
    harm_adopted.predecessor_revision_id = Some(harm_initial_attempt.revision_id);
    harm_adopted.revision_generation = 2;
    harm_adopted.episode_id = Some(harm_episode.episode_id);
    harm_adopted.adoption_status = AttemptAdoptionStatus::Selected;
    harm_adopted.source_watermark = 18;
    harm_episode.attempt_ids = vec![harm_adopted.attempt_id];
    harm_episode.validate().unwrap();
    let harm_activation = activate_episode(
        work_context(18),
        &harm_stream,
        harm_episode,
        vec![harm_adopted.clone()],
        Vec::new(),
    )
    .unwrap();
    writer.commit(&harm_activation, 18).await.unwrap();

    let mut harm_search = search.clone();
    harm_search.task_id = Some(harm_task.task_id);
    let harm_routed = ProcedureRouter::route(
        &harm_search,
        vec![ProcedureCandidate {
            revision: (*procedure).clone(),
            publication: ProcedurePublicationState::ActiveStable,
            global_support: None,
            phase: ProcedurePhase::AtEntry,
            lexical_rank: 1,
        }],
        &constraints,
        None,
        true,
        false,
        false,
        true,
    );
    let harm_snapshot = writer.project().await.unwrap();
    let harm_view = ProcedureUsageCurrentView::from_snapshot(&harm_snapshot).unwrap();
    let ProcedureUsageResolution::Command {
        usage: harm_usage,
        command: harm_begin,
    } = begin_procedure_usage(
        &harm_view,
        proposal_context(19),
        &harm_routed.items[0],
        harm_stream.workstream_id,
        harm_exposure_revision_id,
    )
    .unwrap()
    else {
        panic!("the independent failed attempt needs one sealed exposure")
    };
    let committed_harm_usage = writer
        .commit_if_frontier(&harm_begin, 19, harm_snapshot.frontier)
        .await
        .unwrap();
    assert!(!committed_harm_usage.replayed);
    let replayed_harm_usage = writer.commit(&harm_begin, 19).await.unwrap();
    assert!(replayed_harm_usage.replayed);
    assert_eq!(
        replayed_harm_usage.first_seq,
        committed_harm_usage.first_seq
    );
    assert_eq!(
        replayed_harm_usage.event_ids,
        committed_harm_usage.event_ids
    );

    let (harm_intent_receipt, harm_intent) = physical_source(
        "harm-intent",
        ObservationRole::Intent,
        repository_id,
        worktree_id,
    );
    let (harm_result_receipt, harm_result_observation) = physical_source(
        "harm-result",
        ObservationRole::Result,
        repository_id,
        worktree_id,
    );
    writer
        .commit(
            &command(
                20,
                source_payloads(harm_intent_receipt.clone(), harm_intent.clone()),
            ),
            20,
        )
        .await
        .unwrap();
    writer
        .commit(
            &command(
                21,
                source_payloads(harm_result_receipt, harm_result_observation.clone()),
            ),
            21,
        )
        .await
        .unwrap();
    let harm_normalized = PhysicalNormalizer::new(1)
        .unwrap()
        .normalize(&[harm_intent.clone(), harm_result_observation], None)
        .unwrap();
    let harm_operation_id = harm_normalized.operations[0].operation_id;
    writer
        .commit(
            &harm_normalized
                .journal_command(CommandId::new_v7(), 22, CONFIG, "s25-test-v1")
                .unwrap(),
            22,
        )
        .await
        .unwrap();

    let harm_binding_id = WorkBindingRevisionId::new_v7();
    let mut failed_attempt = harm_adopted.clone();
    failed_attempt.revision_id = RevisionId::new_v7();
    failed_attempt.predecessor_revision_id = Some(harm_adopted.revision_id);
    failed_attempt.revision_generation = 3;
    failed_attempt.verification = AttemptVerification::Failed;
    failed_attempt.outcome_state = AttemptOutcomeState::Known;
    failed_attempt.failure_signature = Some("objective_verifier_failed".into());
    failed_attempt.work_binding_revision_refs = vec![harm_binding_id];
    failed_attempt.source_watermark = 23;
    let harm_run = create_experiment_run(
        &failed_attempt,
        RunCreateInput {
            workstream_id: harm_stream.workstream_id,
            source_receipt_refs: vec![harm_intent_receipt.source_receipt_id],
            code_snapshot_id: snapshot_id,
            data_fingerprint: "data-s25-harm".into(),
            normalized_config: vec![ContractField {
                name: "mode".into(),
                value: "failed".into(),
            }],
            variable_declaration: VariableDeclaration {
                varied: Vec::new(),
                fixed: vec!["mode".into()],
                uncontrolled: Vec::new(),
            },
            seed_policy: SeedPolicy::Fixed,
            seed_values: vec!["2525".into()],
            nondeterministic: false,
            metric_definition: "verification".into(),
            metric_extractor_version: "evertrace.result_metric.v1".into(),
            multi_cas_metric_policy: MultiCasMetricPolicy::RejectMultipleParsed,
            environment_fingerprint: "environment-s25".into(),
            created_at_us: 23,
        },
    )
    .unwrap();
    let result_for = |revision_id: RevisionId,
                      verifier_receipt: Option<VerifierReceipt>,
                      failure: Option<ResultFailure>| {
        let completeness = if failure.is_none()
            && verifier_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.status == VerifierStatus::Passed)
        {
            EvidenceCompleteness::Complete
        } else {
            EvidenceCompleteness::Incomplete
        };
        ResultEvidence {
            result_evidence_id: evertrace_domain::ids::ResultEvidenceId::new_v7(),
            revision_id,
            parent_revision_id: None,
            experiment_run_id: harm_run.run_id,
            experiment_run_revision_id: harm_run.revision_id,
            result_scope: ResultScope::Partial,
            raw_artifact_refs: Vec::new(),
            raw_cas_refs: vec![cas_id],
            parsed_metric: Some(MetricValue {
                decimal: "0".into(),
                unit: "boolean".into(),
                uncertainty_decimal: None,
            }),
            parser_receipt: ParserReceipt {
                parser_version: "evertrace.result_metric.v1".into(),
                input_artifact_refs: Vec::new(),
                input_cas_refs: vec![cas_id],
                status: ParserStatus::Parsed,
                failure_code: None,
            },
            verifier_receipt,
            completeness,
            failure,
            created_at_us: 23,
        }
    };
    let neutral_result = result_for(RevisionId::new_v7(), None, None);
    let replay_pass = result_for(
        RevisionId::new_v7(),
        Some(VerifierReceipt {
            verifier_version: "evertrace.result_reparse.v1".into(),
            status: VerifierStatus::Passed,
            failure_code: None,
        }),
        None,
    );
    let replay_violation = result_for(
        RevisionId::new_v7(),
        Some(VerifierReceipt {
            verifier_version: "evertrace.result_reparse.v1".into(),
            status: VerifierStatus::Failed,
            failure_code: Some(VerifierFailureCode::DeterministicReparseMismatch),
        }),
        Some(ResultFailure::Verifier(
            VerifierFailureCode::DeterministicReparseMismatch,
        )),
    );
    let mut harm_result_refs = vec![
        neutral_result.revision_id.to_string(),
        replay_pass.revision_id.to_string(),
        replay_violation.revision_id.to_string(),
    ];
    harm_result_refs.sort();
    failed_attempt.parent_verification_refs = harm_result_refs.clone();
    failed_attempt.outcome_refs = harm_result_refs;
    harm_adopted.validate_successor(&failed_attempt).unwrap();
    let harm_binding = WorkBindingRevision {
        work_binding_revision_id: harm_binding_id,
        operation_id: harm_operation_id,
        revision_generation: 1,
        predecessor_revision_id: None,
        primary_binding: PrimaryWorkBinding {
            task_id: Some(harm_task.task_id),
            workstream_id: Some(harm_stream.workstream_id),
            episode_id: failed_attempt.episode_id,
            attempt_id: Some(failed_attempt.attempt_id),
            experiment_run_id: Some(harm_run.run_id),
            competing_group_id: None,
        },
        secondary_bindings: Vec::new(),
        scope_effect_refs: Vec::new(),
        assignment_status: AssignmentStatus::Resolved,
        evidence_refs: vec![harm_intent.source_observation_id.to_string()],
        resolver_version: 1,
    };
    writer
        .commit(
            &command(
                23,
                vec![
                    JournalPayload::AttemptRecorded(Box::new(failed_attempt.clone())),
                    JournalPayload::WorkBindingRecorded(Box::new(harm_binding)),
                    JournalPayload::ExperimentRunRecorded(Box::new(harm_run.clone())),
                    JournalPayload::ResultEvidenceRecorded(Box::new(neutral_result.clone())),
                    JournalPayload::ResultEvidenceRecorded(Box::new(replay_pass.clone())),
                    JournalPayload::ResultEvidenceRecorded(Box::new(replay_violation.clone())),
                ],
            ),
            23,
        )
        .await
        .unwrap();
    let harm_snapshot = writer.project().await.unwrap();
    let harm_view = ProcedureUsageCurrentView::from_snapshot(&harm_snapshot).unwrap();
    let (harm_action, harm_advance) = advance_procedure_usage(
        &harm_view,
        proposal_context(24),
        ProcedureUsageAdvance {
            usage_id: harm_usage.procedure_usage_id,
            stage: ProcedureUsageStage::Completion,
            attempt_ids: vec![failed_attempt.attempt_id],
            action_episode_revision_ids: vec![harm_exposure_revision_id],
            verification_episode_revision_ids: vec![harm_exposure_revision_id],
            action_operation_refs: vec![harm_operation_id],
            verification_operation_refs: vec![harm_operation_id],
            work_binding_revision_refs: vec![harm_binding_id],
            scope_effect_refs: Vec::new(),
            evidence_refs: vec![neutral_result.revision_id.to_string()],
        },
        &ConstraintState {
            bindings: vec![ConstraintBinding {
                field: ConstraintField::ArtifactKind,
                value: ConstraintValue::Text("pending".into()),
            }],
        },
        None,
    )
    .unwrap();
    assert_eq!(harm_action.action_aligned, ProcedureTruth::True);
    assert_ne!(harm_action.outcome_supported, ProcedureTruth::True);
    writer
        .commit_if_frontier(&harm_advance, 24, harm_snapshot.frontier)
        .await
        .unwrap();
    let harm_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProcedureNegativeResolution::Command {
        level: ProcedureNegativeLevel::SuspectedHarm,
        command: localized,
    } = record_procedure_negative(
        &harm_view,
        proposal_context(25),
        ProcedureNegativeRequest {
            procedure_usage_id: harm_action.procedure_usage_id,
            session_id: "session-s25-physical".into(),
            result_revision_ids: vec![neutral_result.revision_id],
        },
    )
    .unwrap()
    else {
        panic!("the exact adopted failed Attempt must derive suspected harm")
    };
    let localized_id = localized
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::ProcedureNegativeEvidenceRecorded(value) => {
                Some(value.negative_evidence_id)
            }
            _ => None,
        })
        .unwrap();
    assert!(
        !localized
            .events()
            .iter()
            .any(|event| matches!(event.payload, JournalPayload::ProcedureStateRecorded(_)))
    );
    let forged_payloads = localized
        .events()
        .iter()
        .map(|event| match event.payload.clone() {
            JournalPayload::ProcedureNegativeEvidenceRecorded(mut value) => {
                value.level = ProcedureNegativeLevel::ConfirmedHarm;
                value.attribution_basis = ProcedureAttributionBasis::ReplayInvariantViolation;
                value.decision_source = ProcedureNegativeDecisionSource::TypedReplayInvariant;
                value.confounders.clear();
                JournalPayload::ProcedureNegativeEvidenceRecorded(value)
            }
            payload => payload,
        })
        .collect();
    assert!(
        writer
            .commit(&command(25, forged_payloads), 25)
            .await
            .is_err()
    );
    writer.commit(&localized, 25).await.unwrap();
    let retry_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert!(matches!(
        record_procedure_negative(
            &retry_view,
            proposal_context(25),
            ProcedureNegativeRequest {
                procedure_usage_id: harm_action.procedure_usage_id,
                session_id: "session-s25-physical".into(),
                result_revision_ids: vec![neutral_result.revision_id],
            },
        )
        .unwrap(),
        ProcedureNegativeResolution::NoDelta
    ));
    let quarantined_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let quarantined = route_procedures_with_quarantine(
        &quarantined_view,
        &harm_action.local_context,
        &harm_search,
        vec![ProcedureCandidate {
            revision: (*procedure).clone(),
            publication: ProcedurePublicationState::ActiveProbationary,
            global_support: None,
            phase: ProcedurePhase::AtEntry,
            lexical_rank: 1,
        }],
        &constraints,
        None,
        true,
        false,
        false,
        true,
    );
    assert_eq!(quarantined.items[0].decision, ProcedureDecision::Defer);
    assert!(quarantined.items[0].actions.is_none());
    let dismissed = review_procedure_negative(
        &quarantined_view,
        proposal_context(26),
        localized_id,
        ProcedureNegativeReviewProof::ReplayDismissed {
            result_revision_ids: vec![replay_pass.revision_id],
        },
    );
    assert!(
        dismissed.is_err(),
        "pre-negative replay cannot close review"
    );
    let post_negative_replay = result_for(
        RevisionId::new_v7(),
        Some(VerifierReceipt {
            verifier_version: "evertrace.result_reparse.v1".into(),
            status: VerifierStatus::Passed,
            failure_code: None,
        }),
        None,
    );
    writer
        .commit(
            &command(
                26,
                vec![JournalPayload::ResultEvidenceRecorded(Box::new(
                    post_negative_replay.clone(),
                ))],
            ),
            26,
        )
        .await
        .unwrap();
    let post_replay_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let dismissed = review_procedure_negative(
        &post_replay_view,
        proposal_context(27),
        localized_id,
        ProcedureNegativeReviewProof::ReplayDismissed {
            result_revision_ids: vec![post_negative_replay.revision_id],
        },
    )
    .unwrap();
    let mut stale_review_events = dismissed.events().to_vec();
    for event in &mut stale_review_events {
        if let JournalPayload::ProcedureNegativeReviewRecorded(value) = &mut event.payload {
            value.evidence_refs = vec![replay_pass.revision_id.to_string()];
        }
    }
    let stale_review = JournalCommand::new(CommandId::new_v7(), stale_review_events).unwrap();
    let before_review = writer.project().await.unwrap().frontier;
    assert!(writer.commit(&stale_review, 27).await.is_err());
    assert_eq!(writer.project().await.unwrap().frontier, before_review);
    writer.commit(&dismissed, 27).await.unwrap();
    let dismissed_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert!(!dismissed_view.local_quarantined(
        harm_action.procedure_revision_id,
        &harm_action.local_context
    ));
    let (_post_review_usage, post_review_command) = advance_procedure_usage(
        &dismissed_view,
        proposal_context(27),
        ProcedureUsageAdvance {
            usage_id: harm_action.procedure_usage_id,
            stage: ProcedureUsageStage::Completion,
            attempt_ids: vec![failed_attempt.attempt_id],
            action_episode_revision_ids: vec![harm_exposure_revision_id],
            verification_episode_revision_ids: vec![harm_exposure_revision_id],
            action_operation_refs: vec![harm_operation_id],
            verification_operation_refs: vec![harm_operation_id],
            work_binding_revision_refs: vec![harm_binding_id],
            scope_effect_refs: Vec::new(),
            evidence_refs: vec![neutral_result.revision_id.to_string()],
        },
        &ConstraintState {
            bindings: vec![ConstraintBinding {
                field: ConstraintField::ArtifactKind,
                value: ConstraintValue::Text("pending".into()),
            }],
        },
        None,
    )
    .unwrap();
    writer.commit(&post_review_command, 27).await.unwrap();
    assert_eq!(
        writer.project().await.unwrap(),
        writer.full_projection().await.unwrap(),
        "later usage successors cannot corrupt the earlier review"
    );
    let second_neutral = result_for(RevisionId::new_v7(), None, None);
    let second_neutral_ref = second_neutral.revision_id.to_string();
    let mut later_failed_attempt = failed_attempt.clone();
    later_failed_attempt.revision_id = RevisionId::new_v7();
    later_failed_attempt.predecessor_revision_id = Some(failed_attempt.revision_id);
    later_failed_attempt.revision_generation += 1;
    later_failed_attempt.source_watermark += 1;
    later_failed_attempt
        .parent_verification_refs
        .push(second_neutral_ref.clone());
    later_failed_attempt.parent_verification_refs.sort();
    later_failed_attempt.outcome_refs.push(second_neutral_ref);
    later_failed_attempt.outcome_refs.sort();
    failed_attempt
        .validate_successor(&later_failed_attempt)
        .unwrap();
    writer
        .commit(
            &command(
                28,
                vec![
                    JournalPayload::AttemptRecorded(Box::new(later_failed_attempt.clone())),
                    JournalPayload::ResultEvidenceRecorded(Box::new(second_neutral.clone())),
                ],
            ),
            28,
        )
        .await
        .unwrap();
    assert_eq!(
        writer.project().await.unwrap(),
        writer.full_projection().await.unwrap(),
        "later Attempt revisions cannot corrupt the first negative/review"
    );
    let second_negative_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProcedureNegativeResolution::Command {
        level: ProcedureNegativeLevel::SuspectedHarm,
        command: second_localized,
    } = record_procedure_negative(
        &second_negative_view,
        proposal_context(29),
        ProcedureNegativeRequest {
            procedure_usage_id: harm_action.procedure_usage_id,
            session_id: "session-s25-physical".into(),
            result_revision_ids: vec![second_neutral.revision_id],
        },
    )
    .unwrap()
    else {
        panic!("new typed evidence may append a distinct negative")
    };
    let second_localized_id = second_localized
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::ProcedureNegativeEvidenceRecorded(value) => {
                Some(value.negative_evidence_id)
            }
            _ => None,
        })
        .unwrap();
    writer.commit(&second_localized, 29).await.unwrap();
    let replay_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProcedureNegativeResolution::Command {
        level: ProcedureNegativeLevel::ConfirmedHarm,
        command: confirmed,
    } = record_procedure_negative(
        &replay_view,
        proposal_context(30),
        ProcedureNegativeRequest {
            procedure_usage_id: harm_action.procedure_usage_id,
            session_id: "session-s25-physical".into(),
            result_revision_ids: vec![replay_violation.revision_id],
        },
    )
    .unwrap()
    else {
        panic!("deterministic replay mismatch must derive confirmed harm")
    };
    assert!(confirmed.events().iter().any(|event| matches!(
        &event.payload,
        JournalPayload::ProcedureStateRecorded(value)
            if value.to_state == ProcedurePublicationState::Suspended
    )));
    writer.commit(&confirmed, 30).await.unwrap();
    let suspended_routes = ProcedureRouter::route(
        &search,
        vec![ProcedureCandidate {
            revision: (*procedure).clone(),
            publication: ProcedurePublicationState::Suspended,
            global_support: None,
            phase: ProcedurePhase::AtEntry,
            lexical_rank: 1,
        }],
        &constraints,
        None,
        true,
        false,
        false,
        true,
    );
    assert!(suspended_routes.items.is_empty());

    let semantic_view =
        SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let mut replacement_draft = procedure.draft.clone();
    replacement_draft.summary = "Run the corrected deterministic verifier".into();
    let ProposalResolution::Revision {
        value: replacement_proposal,
        command: replacement_submitted,
    } = service
        .submit(
            &semantic_view,
            proposal_context(31),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Procedure,
                target_id: Some(ProposalTargetId::Procedure(procedure.procedure_id)),
                base_revision_id: Some(procedure.revision_id),
                operation: ProposalOperation::Replace,
                payload: ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Replace {
                    draft: replacement_draft,
                })),
                evidence_refs: vec![evidence_receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![evidence_receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("replacement proposal must persist")
    };
    writer.commit(&replacement_submitted, 31).await.unwrap();
    let replacement_acceptance_payload = tui_acceptance_event_payload(
        replacement_proposal.proposal_id,
        replacement_proposal.proposal_revision_id,
        &replacement_proposal.fingerprint,
    );
    let (replacement_acceptance_receipt, replacement_acceptance_observation) = source(
        "replacement-acceptance",
        &replacement_acceptance_payload,
        32,
        repository_id,
    );
    writer
        .commit(
            &command(
                32,
                source_payloads(
                    replacement_acceptance_receipt.clone(),
                    replacement_acceptance_observation.clone(),
                ),
            ),
            32,
        )
        .await
        .unwrap();
    let semantic_view =
        SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProcedureAcceptanceResolution::Command {
        procedure: replacement,
        command: replacement_accepted,
        ..
    } = accept_procedure(
        &semantic_view,
        proposal_context(33),
        replacement_proposal.proposal_id,
        ProcedureAcceptanceContext::Manual(AtomAcceptanceContext::RepositoryTui {
            observation: Box::new(replacement_acceptance_observation),
            receipt: Box::new(replacement_acceptance_receipt),
        }),
        Some(&procedure),
        Some(ProcedurePublicationState::Suspended),
        &config,
    )
    .unwrap()
    else {
        panic!("changed behavior revision must be accepted")
    };
    writer.commit(&replacement_accepted, 33).await.unwrap();
    let (replacement_success, replacement_success_command, replacement_result_id) =
        record_independent_success(
            &mut writer,
            &replacement,
            ProcedurePublicationState::ActiveProbationary,
            repository_id,
            worktree_id,
            snapshot_id,
            34,
            "replacement-success",
        )
        .await;
    assert!(
        !replacement_success_command
            .events()
            .iter()
            .any(|event| matches!(event.payload, JournalPayload::ProcedureStateRecorded(_))),
        "a new behavior revision starts its success count at zero"
    );
    writer
        .commit(&replacement_success_command, 34)
        .await
        .unwrap();
    let supersede_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let superseded = review_procedure_negative(
        &supersede_view,
        proposal_context(35),
        second_localized_id,
        ProcedureNegativeReviewProof::SuccessorSuperseded {
            successor_usage_id: replacement_success.procedure_usage_id,
            result_revision_ids: vec![replacement_result_id],
        },
    )
    .unwrap();
    writer.commit(&superseded, 35).await.unwrap();
    let superseded_view =
        ProcedureUsageCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert!(!superseded_view.local_quarantined(
        harm_action.procedure_revision_id,
        &harm_action.local_context
    ));
    assert!(writer.project().await.unwrap().data_rows().any(|row| {
        row.object_kind.as_deref() == Some("procedure_negative_evidence")
            && row.object_id.as_deref() == Some(second_localized_id.to_string().as_str())
    }));
    let (_later_replacement_usage, later_replacement_command) = advance_procedure_usage(
        &superseded_view,
        proposal_context(36),
        ProcedureUsageAdvance {
            usage_id: replacement_success.procedure_usage_id,
            stage: ProcedureUsageStage::Outcome,
            attempt_ids: replacement_success.attempt_ids.clone(),
            action_episode_revision_ids: replacement_success.action_episode_revision_ids.clone(),
            verification_episode_revision_ids: replacement_success
                .verification_episode_revision_ids
                .clone(),
            action_operation_refs: replacement_success.action_operation_refs.clone(),
            verification_operation_refs: replacement_success.verification_operation_refs.clone(),
            work_binding_revision_refs: replacement_success.work_binding_revision_refs.clone(),
            scope_effect_refs: replacement_success.scope_effect_refs.clone(),
            evidence_refs: replacement_success.evidence_refs.clone(),
        },
        &ConstraintState {
            bindings: vec![ConstraintBinding {
                field: ConstraintField::ArtifactKind,
                value: ConstraintValue::Text("release".into()),
            }],
        },
        None,
    )
    .unwrap();
    writer.commit(&later_replacement_command, 36).await.unwrap();
    let final_projection = writer.project().await.unwrap();
    assert_eq!(final_projection, writer.full_projection().await.unwrap());
    let effect_rows = final_projection
        .rows
        .iter()
        .filter(|row| row.object_kind.as_deref() == Some("procedure_context_effect"))
        .collect::<Vec<_>>();
    assert!(!effect_rows.is_empty());
    assert!(effect_rows.iter().all(|row| {
        serde_json::from_str::<
            evertrace_domain::procedure::ProcedureContextEffectProjection,
        >(row.payload_json.as_deref().unwrap())
        .is_ok_and(|effect| {
            effect.evidence_class
                == evertrace_domain::procedure::ProcedureEffectEvidenceClass::ObservationalAssociation
                && !effect.context.complete_for(&std::collections::BTreeSet::from([
                    ConstraintField::Phase,
                ]))
        })
    }));
    let terminal_review_watermark = final_projection
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("procedure_negative_review"))
        .filter(|row| {
            serde_json::from_str::<JournalPayload>(row.payload_json.as_deref().unwrap()).is_ok_and(
                |payload| {
                    matches!(
                        payload,
                        JournalPayload::ProcedureNegativeReviewRecorded(review)
                            if matches!(
                                review.status,
                                ProcedureNegativeReviewStatus::Dismissed
                                    | ProcedureNegativeReviewStatus::Superseded
                            )
                    )
                },
            )
        })
        .map(|row| row.source_event_seq)
        .max()
        .unwrap();
    assert!(
        effect_rows
            .iter()
            .any(|row| row.source_event_seq >= terminal_review_watermark)
    );
    assert!(effect_rows.iter().all(|row| {
        serde_json::from_str::<evertrace_domain::procedure::ProcedureContextEffectProjection>(
            row.payload_json.as_deref().unwrap(),
        )
        .is_ok_and(|effect| effect.effect != evertrace_domain::procedure::ProcedureEffect::Negative)
    }));
    assert!(
        writer
            .search_rows()
            .await
            .unwrap()
            .iter()
            .all(|row| { row.object_kind.as_deref() != Some("procedure_context_effect") })
    );
    let relation_rows = writer.relation_rows().await.unwrap();
    assert!(
        relation_rows.iter().all(|row| {
            row.relation_kind.as_deref() != Some("procedure_context_effect_authority")
        })
    );
    for expected in [
        "procedure_usage_to_revision",
        "procedure_usage_to_task",
        "procedure_usage_to_workstream",
        "procedure_usage_to_exposure_episode",
        "procedure_usage_to_attempt",
        "procedure_usage_to_action_operation",
        "procedure_usage_to_verification_operation",
        "procedure_usage_to_binding_revision",
        "procedure_negative_to_usage",
        "procedure_negative_to_revision",
        "procedure_negative_to_task",
        "procedure_review_to_negative",
    ] {
        assert!(
            relation_rows
                .iter()
                .any(|row| row.relation_kind.as_deref() == Some(expected))
        );
    }
    drop(writer);
    let reopened = JournalWriter::open(&store_path).await.unwrap();
    assert_eq!(final_projection, reopened.project().await.unwrap());
}
