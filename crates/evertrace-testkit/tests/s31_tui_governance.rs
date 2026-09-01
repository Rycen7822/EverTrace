use std::{
    collections::BTreeSet, fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::Path,
};

use evertrace_capture::{
    CaptureRecordInput, DeviceKeyStore, DurableSpool, RUNTIME_SNAPSHOT_VERSION, RecallCueGateMode,
    RecoveryGateMode, RuntimeSnapshot, SpoolLimits,
};
use evertrace_domain::{
    config::{GlobalPromotionConfig, PromotionLevel},
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceByteRange,
        EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength, ObservationRole,
        SourceArchiveMode, SourceInstanceId, SourceObservation, SourceReceipt,
        SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole, payload_fingerprint,
        source_observation_id, source_receipt_id,
    },
    ids::{
        AttemptId, CaptureReceiptId, CommandId, ExecutionLaneId, JobId, RepositoryId, RequestId,
        RevisionProposalId, TaskId, WorkstreamId, WorktreeId,
    },
    procedure::{
        ProcedureActions, ProcedureDone, ProcedureDraft, ProcedureKind, ProcedureScope,
        ProcedureStateReason, ProcedureWhen,
    },
    repository::{
        FilesystemIdentity, GitObjectFormat, GitRegistrationState, PathObservation,
        RepositoryInstance, WorktreeInstance, WorktreeKind, WorktreeLifecycle,
    },
    revision::RevisionId,
    semantic::{
        ApplicabilityExpr, AtomDraft, AtomKind, AtomProposalPayload, AtomProvenance, AtomScope,
        AtomValue, ConstraintExpr, ConstraintField, ConstraintValue, CoreMembershipProposalPayload,
        CoreScopeIdentity, EpistemicStatus, GlobalSupportState, GlobalSupportValidationEvent,
        ProcedureProposalPayload, ProposalCreatedBy, ProposalEligibility, ProposalOperation,
        ProposalPayload, ProposalStatus, ProposalTargetId, ProposalTargetKind, RevisionProposal,
        SemanticQualifier, TUI_ACCEPTANCE_EVENT_MANIFEST_REF, ValidityInterval,
        tui_acceptance_event_payload,
    },
    work::{
        AdmissionFailureObservability, CaptureResolverInput, CoverageLevel, InterruptionReason,
        LivenessState, PhaseContract, PhaseKind, ResumeStateAssessment, StrategyContract, Task,
        TaskIdentityConfidence, TaskLifecycle, TaskScopeMembership, TerminalKind, Workstream,
        WorkstreamStatus, resolve_capture,
    },
};
use evertrace_engine::{
    HumanGovernanceError, HumanGovernanceService, HumanProposalDecision, HumanRelatedRequest,
    HumanRelationKind, HumanSurface, HumanSystemDetail, open_writer,
    procedure::{
        ProcedureAcceptanceContext, ProcedureAcceptanceResolution, accept_procedure,
        publication_event,
    },
    semantic::{
        AtomAcceptanceContext, ProposalCommandContext, ProposalResolution, RevisionProposalService,
        SubmitProposalRequest, mark_support_pending,
    },
    spawn_writer,
    work::attempt::{create_resume_attempt, new_attempt},
};
use evertrace_protocol::dto::{
    HUMAN_PAGE_LIMIT, HumanActionRequest, HumanDegradedReason, HumanGovernanceRequest,
    HumanGovernanceResponse, HumanItemCategory, HumanItemKind, HumanObjectFamily, HumanReadRequest,
    HumanRowClass, HumanSnapshotItem, HumanSnapshotStatus, HumanSupportDetail,
    HumanSurface as WireSurface, NegativeReviewDecision,
};
use evertrace_store::{
    AttemptCurrentView, ConfigAudit, DirtyTarget, DirtyTargetKind, DurableJob, JobBudget,
    JobStatus, JobTerminalAudit, JobTerminalOutcome, JobTerminalReason, JournalCommand,
    JournalEventDraft, JournalPayload, SemanticCurrentView, SourceIngestWatermark, SourceKind,
};
use evertrace_tui::{App, AppEvent};
use tempfile::TempDir;

const CONFIG: [u8; 32] = [31; 32];
type SupportReplayProof = Box<(RequestId, u64, RevisionId, String, String)>;
type SupportProofFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = SupportReplayProof> + 'a>>;

fn runtime_snapshot(root: &Path) -> RuntimeSnapshot {
    let limits = SpoolLimits {
        high_watermark_bytes: 2 * 1024 * 1024,
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

fn interrupted_capture_pair(
    lane_id: ExecutionLaneId,
) -> (
    evertrace_domain::work::ExecutionLane,
    evertrace_domain::work::CaptureReceipt,
) {
    resolve_capture(CaptureResolverInput {
        execution_lane_id: lane_id,
        capture_receipt_revision_id: CaptureReceiptId::new_v7(),
        previous_lane: None,
        previous_receipt: None,
        host_session_id: "session-s31-mark-new".into(),
        agent_id: "agent-s31-mark-new".into(),
        host_lane_key: "lane-s31-mark-new".into(),
        incarnation_ref: "incarnation-s31-mark-new".into(),
        parent_lane_id: None,
        parent_host_lane_key: None,
        spawn_event_ref: Some("spawn-s31-mark-new".into()),
        terminal_event_ref: Some("terminal-s31-mark-new".into()),
        terminal_kind: Some(TerminalKind::Cancelled),
        host_final_return: false,
        parent_session_end_seen: false,
        liveness_state: LivenessState::Absent,
        liveness_probe_refs: vec!["liveness-s31-mark-new".into()],
        all_sources_closed: false,
        source_closed_refs: Vec::new(),
        source_close_watermark_refs: Vec::new(),
        source_close_reconciliation_refs: Vec::new(),
        source_reconciliation_complete: false,
        adapter_manifest_ids: vec!["manifest-s31-mark-new".into()],
        eligible_event_manifest_refs: vec!["eligible-s31-mark-new".into()],
        source_revision_refs: Vec::new(),
        manifest_coverage: vec![CoverageLevel::Full],
        required_for_full: BTreeSet::new(),
        observed_capabilities: BTreeSet::new(),
        admission_failure_observability: AdmissionFailureObservability::Complete,
        independent_reconciliation: false,
        admission_failure_evidence_refs: Vec::new(),
        identity_strength: IdentityStrength::StableNative,
        child_session_id: Some("child-s31-mark-new".into()),
        first_sequence: None,
        last_sequence: None,
        sequence_gaps: Vec::new(),
        capture_gap_marker_refs: Vec::new(),
        unresolved_gap_marker_refs: Vec::new(),
        capture_outage_interval_refs: Vec::new(),
        unresolved_outage_interval_refs: Vec::new(),
        tool_calls_seen: Vec::new(),
        tool_results_seen: Vec::new(),
        unmatched_tool_call_ids: Vec::new(),
        unmatched_tool_result_ids: Vec::new(),
        payload_truncations: Vec::new(),
        redaction_refs: Vec::new(),
        corrupt_payload_refs: Vec::new(),
        unavailable_payload_refs: Vec::new(),
        unsupported_record_types: Vec::new(),
        causal_race: false,
        ordering_best_effort: false,
        reasoning_visibility: Vec::new(),
        import_watermark: 1,
        delegated_goal_ref: Some("goal-s31-mark-new".into()),
        delegated_target_refs: vec!["target-s31-mark-new".into()],
        delegated_acceptance_refs: vec!["accept-s31-mark-new".into()],
        operation_ids: Vec::new(),
        correction_reason: None,
    })
    .unwrap()
}

fn mark_new_strategy() -> StrategyContract {
    StrategyContract {
        hypothesis: "resume from interrupted source with unknown state".into(),
        intervention: "start a clean attempt".into(),
        intervention_family: "typed-attempt".into(),
        search_policy_ref: Some("policy:bounded".into()),
        objective_ref: Some("objective:correctness".into()),
        expected_effect: "preserve source and create one clean child".into(),
        target_refs: vec!["target:attempt".into()],
        acceptance_boundary_ref: "acceptance:human-mark-new".into(),
    }
}

fn source(
    label: &str,
    task_id: TaskId,
    repository_id: RepositoryId,
) -> (SourceReceipt, SourceObservation) {
    let instance = SourceInstanceId::parse(format!("source-{label}")).unwrap();
    let revision = SourceRevision::parse("revision-1").unwrap();
    let record = SourceRecordIdentity::parse(format!("record-{label}")).unwrap();
    let observation_id = source_observation_id(&instance, &revision, &record).unwrap();
    let receipt_id = source_receipt_id(&instance, &revision, &record).unwrap();
    let fingerprint = evertrace_domain::evidence::hex(
        &payload_fingerprint(1, b"reviewed evidence", None).unwrap(),
    );
    let receipt = SourceReceipt {
        source_receipt_id: receipt_id,
        source_observation_id: observation_id,
        source_instance_id: instance.clone(),
        source_kind: EvidenceSourceKind::CodexSessionJsonl,
        identity_domain: "codex-session-v1".into(),
        source_ref: format!("source-ref-{label}"),
        source_session_ref: format!("session-{label}"),
        source_revision: revision.clone(),
        source_record_identity: record.clone(),
        identity_strength: IdentityStrength::StableNative,
        source_sequence: 1,
        source_sequence_origin: None,
        task_id: Some(task_id),
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
        cas_ref: fingerprint.clone(),
        protected_length: 17,
        original_length: 17,
        protected_secret_digest: None,
        redaction_spans: Vec::new(),
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-s31".into(),
        eligible_event_manifest_ref: "eligible-s31".into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        detector_revision: 1,
        redaction_revision: 1,
        protection_key_generation: 1,
        event_time_us: 1,
        recorded_at_us: 1,
        lifecycle: None,
    };
    let observation = SourceObservation {
        source_observation_id: observation_id,
        source_instance_id: instance,
        source_revision: revision,
        source_record_identity: record,
        observation_role: ObservationRole::Message,
        identity_strength: IdentityStrength::StableNative,
        payload_fingerprint: fingerprint,
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
            adapter_manifest_ref: "adapter-s31".into(),
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

fn proposal_context(at: i64) -> ProposalCommandContext {
    ProposalCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: "s31-test-v1".into(),
    }
}

fn isolated_acceptance_input(
    proposal: &RevisionProposal,
    payload: &str,
    task_id: TaskId,
    repository_id: RepositoryId,
) -> CaptureRecordInput {
    let record_id = format!(
        "tui-accept-{}-{}",
        proposal.proposal_id, proposal.proposal_revision_id
    );
    CaptureRecordInput {
        spool_record_id: Some(record_id.clone()),
        source_observation_id_hint: None,
        source_instance_id: format!("tui-acceptance:{}", proposal.proposal_id),
        source_revision: proposal.proposal_revision_id.to_string(),
        source_record_identity: Some(record_id),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into(),
        source_ref: proposal.proposal_id.to_string(),
        session_ref: "human-governance".into(),
        turn_ref: None,
        tool_ref: None,
        source_sequence: 1,
        source_sequence_origin: Some(1),
        task_id: Some(task_id.to_string()),
        repository_instance_id: Some(repository_id.to_string()),
        worktree_instance_id: None,
        source_byte_range: None,
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: None,
        observation_role: ObservationRole::Message,
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
            adapter_manifest_ref: TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: Vec::new(),
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: SourceRole::User,
        content_trust: ContentTrust::UserStatement,
        capture_completeness: CaptureCompleteness::Complete,
        surface_eligible: true,
        adapter_revision: 1,
        adapter_manifest_ref: TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into(),
        eligible_event_manifest_ref: TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: None,
        raw_payload: payload.as_bytes().to_vec(),
    }
}

fn typed_tui_source(
    label: &str,
    proposal: &RevisionProposal,
    task_id: TaskId,
    repository_id: RepositoryId,
) -> (SourceReceipt, SourceObservation) {
    let (mut receipt, mut observation) = source(label, task_id, repository_id);
    let canonical = tui_acceptance_event_payload(
        proposal.proposal_id,
        proposal.proposal_revision_id,
        &proposal.fingerprint,
    );
    let fingerprint = evertrace_domain::evidence::hex(
        &payload_fingerprint(1, canonical.as_bytes(), None).unwrap(),
    );
    receipt.cas_ref = fingerprint.clone();
    receipt.protected_length = canonical.len() as u64;
    receipt.original_length = canonical.len() as u64;
    receipt.eligible_event_manifest_ref = TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into();
    receipt.event_time_us = proposal.created_at_us;
    receipt.recorded_at_us = proposal.created_at_us + 1;
    observation.payload_fingerprint = fingerprint;
    (receipt, observation)
}

fn atom_draft(
    repository_id: RepositoryId,
    receipt: &SourceReceipt,
    observation: &SourceObservation,
) -> AtomDraft {
    AtomDraft {
        kind: AtomKind::Constraint,
        epistemic_status: EpistemicStatus::NotApplicable,
        value: AtomValue {
            text: "preserve reviewed evidence".into(),
            subject: "evidence".into(),
            predicate: "preserve".into(),
            object: Some("reviewed".into()),
            qualifiers: vec![SemanticQualifier {
                name: "scope".into(),
                value: "repository".into(),
            }],
            critical_revision_refs: Vec::new(),
        },
        scope: AtomScope::Repository {
            repository_instance_id: repository_id,
        },
        applicability_expr: ApplicabilityExpr::Always,
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

fn make_edit_candidate(
    original: &RevisionProposal,
    payload: ProposalPayload,
    created_at_us: i64,
) -> RevisionProposal {
    let mut candidate = RevisionProposal {
        proposal_id: RevisionProposalId::new_v7(),
        proposal_revision_id: RevisionId::new_v7(),
        parent_proposal_revision_id: None,
        target_kind: original.target_kind,
        target_id: original.target_id,
        base_revision_id: original.base_revision_id,
        operation: original.operation,
        payload,
        evidence_refs: original.evidence_refs.clone(),
        source_cohort_refs: original.source_cohort_refs.clone(),
        source_cohort_hash: original.source_cohort_hash,
        fingerprint: [0; 32],
        eligibility: ProposalEligibility::ManualRequired,
        status: ProposalStatus::Pending,
        waiting_on: Vec::new(),
        review_reason: None,
        created_by: ProposalCreatedBy::User,
        acceptance: None,
        created_at_us,
        reviewed_at_us: None,
    };
    candidate.fingerprint = candidate.recompute_fingerprint().unwrap();
    original.validate_edit_candidate(&candidate).unwrap();
    candidate
}

fn procedure_draft(repository_id: RepositoryId, evidence: String) -> ProcedureDraft {
    ProcedureDraft {
        scope: ProcedureScope::Repository { repository_id },
        title: "Verify reviewed repository evidence".into(),
        summary: "Use the objective verifier before publishing".into(),
        kind: ProcedureKind::Diagnostic,
        when: ProcedureWhen {
            goals: vec!["release".into()],
            targets: vec!["artifact".into()],
            signals: vec!["verification requested".into()],
            stage: "verify".into(),
            requires: vec!["objective verifier".into()],
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
            stages: vec!["run the verifier".into()],
            branches: Vec::new(),
            avoid: vec!["do not publish early".into()],
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

#[test]
fn human_wire_is_closed_and_tui_renders_daemon_snapshot() {
    let request = HumanGovernanceRequest::Read {
        request: HumanReadRequest::List {
            surface: WireSurface::Inbox,
            expected_frontier: Some(7),
            after: Some("object:a".into()),
            limit: HUMAN_PAGE_LIMIT,
        },
    };
    let json = serde_json::to_string(&request).unwrap();
    assert_eq!(
        serde_json::from_str::<HumanGovernanceRequest>(&json).unwrap(),
        request
    );
    assert!(serde_json::from_str::<HumanGovernanceRequest>(
        r#"{"operation":"read","request":{"kind":"list","surface":"inbox","expected_frontier":null,"after":null,"limit":1,"authority":true}}"#,
    )
    .is_err());

    let edit_payload = Box::new(ProposalPayload::Atom(Box::new(
        AtomProposalPayload::Deprecate {
            reason: "edited reason".into(),
        },
    )));
    let edit_document =
        evertrace_protocol::dto::proposal_payload_pretty_document(&edit_payload).unwrap();
    assert_eq!(
        evertrace_protocol::dto::parse_proposal_payload_document(&edit_document).unwrap(),
        *edit_payload
    );
    let mut unknown_document = serde_json::from_str::<serde_json::Value>(&edit_document).unwrap();
    unknown_document
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), serde_json::Value::Bool(true));
    assert!(
        evertrace_protocol::dto::parse_proposal_payload_document(
            &serde_json::to_string(&unknown_document).unwrap()
        )
        .is_err()
    );
    let edit_request = HumanGovernanceRequest::Act {
        expected_frontier: 7,
        action: HumanActionRequest::Proposal {
            proposal_id: RevisionProposalId::new_v7(),
            expected_revision_id: RevisionId::new_v7(),
            expected_fingerprint: "b".repeat(64),
            decision: evertrace_protocol::dto::ProposalHumanDecision::EditAndAccept,
            edited_payload: Some(edit_payload.clone()),
        },
    };
    assert!(edit_request.validate());
    assert_eq!(
        serde_json::from_str::<HumanGovernanceRequest>(
            &serde_json::to_string(&edit_request).unwrap()
        )
        .unwrap(),
        edit_request
    );
    let support_edit_payload =
        ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Replace {
            draft: procedure_draft(RepositoryId::new_v7(), "evidence:one".into()),
        }));
    let support_replacement = HumanGovernanceRequest::Act {
        expected_frontier: 7,
        action: HumanActionRequest::SupportReplacement {
            expected_validation_revision_id: RevisionId::new_v7(),
            edited_payload: Box::new(support_edit_payload),
        },
    };
    assert!(support_replacement.validate());
    let support_json = serde_json::to_value(&support_replacement).unwrap();
    let action = support_json["action"].as_object().unwrap();
    assert_eq!(
        action.keys().map(String::as_str).collect::<Vec<_>>(),
        ["edited_payload", "expected_validation_revision_id", "kind"]
    );
    for forbidden in [
        "target_id",
        "base_revision_id",
        "evidence_refs",
        "source_cohort_refs",
    ] {
        assert!(!action.contains_key(forbidden));
    }
    let support_deprecate = HumanGovernanceRequest::Act {
        expected_frontier: 7,
        action: HumanActionRequest::SupportDeprecate {
            expected_validation_revision_id: RevisionId::new_v7(),
            reason: "support cannot be restored".into(),
        },
    };
    assert!(support_deprecate.validate());
    let support_json = serde_json::to_value(&support_deprecate).unwrap();
    let action = support_json["action"].as_object().unwrap();
    assert_eq!(
        action.keys().map(String::as_str).collect::<Vec<_>>(),
        ["expected_validation_revision_id", "kind", "reason"]
    );
    for forbidden in [
        "target_id",
        "base_revision_id",
        "evidence_refs",
        "source_cohort_refs",
    ] {
        assert!(!action.contains_key(forbidden));
    }
    let competing = HumanGovernanceRequest::Act {
        expected_frontier: 7,
        action: HumanActionRequest::ResolveCompetingSelected {
            expected_group_revision_id: RevisionId::new_v7(),
            chosen_attempt_id: AttemptId::new_v7(),
        },
    };
    assert!(competing.validate());
    let competing_json = serde_json::to_value(&competing).unwrap();
    let action = competing_json["action"].as_object().unwrap();
    assert_eq!(
        action.keys().map(String::as_str).collect::<Vec<_>>(),
        ["chosen_attempt_id", "expected_group_revision_id", "kind"]
    );
    for forbidden in [
        "status",
        "source_watermark",
        "integration_event_refs",
        "result_evidence_refs",
        "evidence_refs",
    ] {
        assert!(!action.contains_key(forbidden));
    }
    let expected_attempt_revision_id = RevisionId::new_v7();
    let mark_new = HumanGovernanceRequest::Act {
        expected_frontier: 7,
        action: HumanActionRequest::MarkNewAttempt {
            expected_attempt_revision_id,
        },
    };
    assert!(mark_new.validate());
    let mark_new_json = serde_json::to_value(&mark_new).unwrap();
    let action = mark_new_json["action"].as_object().unwrap();
    assert_eq!(
        action.keys().map(String::as_str).collect::<Vec<_>>(),
        ["expected_attempt_revision_id", "kind"]
    );
    assert_eq!(action["kind"], "mark_new_attempt");
    for forbidden in [
        "attempt_id",
        "strategy_contract",
        "execution_status",
        "execution_lane_ids",
        "source_watermark",
        "resume_event_refs",
    ] {
        assert!(!action.contains_key(forbidden));
    }
    assert!(
        !HumanGovernanceRequest::Act {
            expected_frontier: 7,
            action: HumanActionRequest::Proposal {
                proposal_id: RevisionProposalId::new_v7(),
                expected_revision_id: RevisionId::new_v7(),
                expected_fingerprint: "b".repeat(64),
                decision: evertrace_protocol::dto::ProposalHumanDecision::Accept,
                edited_payload: Some(edit_payload),
            },
        }
        .validate()
    );
    assert!(
        !HumanGovernanceRequest::Act {
            expected_frontier: 7,
            action: HumanActionRequest::Proposal {
                proposal_id: RevisionProposalId::new_v7(),
                expected_revision_id: RevisionId::new_v7(),
                expected_fingerprint: "b".repeat(64),
                decision: evertrace_protocol::dto::ProposalHumanDecision::EditAndAccept,
                edited_payload: None,
            },
        }
        .validate()
    );

    let proposal_id = evertrace_domain::ids::RevisionProposalId::new_v7();
    let revision_id = evertrace_domain::revision::RevisionId::new_v7();
    let proposal = evertrace_protocol::dto::HumanProposalMetadata {
        proposal_id,
        current_revision_id: revision_id,
        fingerprint: "a".repeat(64),
        target_kind: ProposalTargetKind::Atom,
        target_id: None,
        operation: ProposalOperation::Create,
        base_revision_id: None,
        source_cohort_refs: vec!["source:one".into()],
        eligibility: ProposalEligibility::ManualRequired,
        status: ProposalStatus::Pending,
    };
    let proposal_item = HumanSnapshotItem {
        item_kind: HumanItemKind::RevisionProposal,
        proposal: Some(proposal),
        proposal_review: None,
        support_detail: None,
        competing_detail: None,
        negative_review: None,
        recovery_detail: None,
        worktree_detail: None,
        execution_integrity_detail: None,
        system_detail: None,
        stable_key: "proposal-row".into(),
        row_class: HumanRowClass::Object,
        family: HumanObjectFamily::RevisionProposal,
        category: HumanItemCategory::Proposal,
        object_kind: "revision_proposal_revision".into(),
        object_ref: Some(proposal_id.to_string()),
        revision_ref: Some(revision_id.to_string()),
        lifecycle: Some("pending".into()),
        epistemic: None,
        authority: Some("user".into()),
        publication_state: None,
        support_state: None,
        scope_ref: Some("task:one".into()),
        source_event_seq: 7,
    };
    let mut mismatched_item = proposal_item.clone();
    mismatched_item.object_ref = Some(RevisionProposalId::new_v7().to_string());
    let mismatched = HumanGovernanceResponse::Snapshot {
        frontier: 1,
        status: HumanSnapshotStatus::Ready,
        degraded_reasons: Vec::new(),
        items: vec![mismatched_item],
        next_cursor: None,
    };
    assert!(!mismatched.validate());
    assert!(
        !HumanGovernanceResponse::Snapshot {
            frontier: 1,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: vec![HumanDegradedReason::CurrentJobFailed],
            items: vec![proposal_item.clone()],
            next_cursor: None,
        }
        .validate()
    );
    let support_contract = RevisionId::new_v7();
    let support_validation = RevisionId::new_v7();
    let mut support_refs = vec![RevisionId::new_v7(), RevisionId::new_v7()];
    support_refs.sort();
    let mut support_item = proposal_item.clone();
    support_item.item_kind = HumanItemKind::Generic;
    support_item.proposal = None;
    support_item.family = HumanObjectFamily::Atom;
    support_item.category = HumanItemCategory::Support;
    support_item.object_kind = "global_support_validation".into();
    support_item.object_ref = Some(support_contract.to_string());
    support_item.revision_ref = Some(support_validation.to_string());
    support_item.lifecycle = Some("valid".into());
    support_item.support_detail = Some(HumanSupportDetail {
        support_contract_revision_id: support_contract,
        successor_ref: RevisionId::new_v7().to_string(),
        validation_revision_id: support_validation,
        state: GlobalSupportState::Valid,
        dependency_generation: 1,
        provenance_degraded: true,
        threshold: evertrace_domain::semantic::SupportThresholdSnapshot {
            minimum_surviving_support: 1,
            require_authorization: false,
        },
        support_revision_refs: support_refs.clone(),
        authorization_revision_refs: Vec::new(),
        surviving_support_refs: vec![support_refs[0]],
        invalid_or_missing_refs: vec![support_refs[1]],
        trigger_refs: Vec::new(),
        initial_replacement_payload: None,
        deprecate_available: false,
    });
    let support_response = |item| HumanGovernanceResponse::Snapshot {
        frontier: 1,
        status: HumanSnapshotStatus::Ready,
        degraded_reasons: Vec::new(),
        items: vec![item],
        next_cursor: None,
    };
    assert!(support_response(support_item.clone()).validate());
    let mut inconsistent = support_item.clone();
    inconsistent
        .support_detail
        .as_mut()
        .unwrap()
        .provenance_degraded = false;
    assert!(!support_response(inconsistent).validate());
    let mut insufficient = support_item.clone();
    insufficient.support_detail.as_mut().unwrap().state = GlobalSupportState::Insufficient;
    insufficient.lifecycle = Some("insufficient".into());
    assert!(!support_response(insufficient).validate());
    let mut invalidated = support_item.clone();
    invalidated.support_detail.as_mut().unwrap().state = GlobalSupportState::Invalidated;
    invalidated.lifecycle = Some("invalidated".into());
    assert!(!support_response(invalidated).validate());
    let mut pending = support_response(support_item.clone());
    let HumanGovernanceResponse::Snapshot { items, .. } = &mut pending else {
        unreachable!()
    };
    let pending_item = &mut items[0];
    let pending_detail = pending_item.support_detail.as_mut().unwrap();
    pending_detail.state = GlobalSupportState::RevalidationPending;
    pending_detail.provenance_degraded = false;
    pending_detail.surviving_support_refs.clear();
    pending_detail.invalid_or_missing_refs.clear();
    pending_item.lifecycle = Some("revalidation_pending".into());
    assert!(pending.validate());
    assert!(
        !HumanGovernanceResponse::Snapshot {
            frontier: 1,
            status: HumanSnapshotStatus::Degraded,
            degraded_reasons: vec![
                HumanDegradedReason::CurrentJobFailed,
                HumanDegradedReason::CurrentJobFailed,
            ],
            items: vec![proposal_item.clone()],
            next_cursor: None,
        }
        .validate()
    );
    let mut zero_sequence = proposal_item.clone();
    zero_sequence.source_event_seq = 0;
    assert!(
        !HumanGovernanceResponse::Snapshot {
            frontier: 1,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![zero_sequence],
            next_cursor: None,
        }
        .validate()
    );
    for (category, object_kind) in [
        (HumanItemCategory::Assignment, "work_binding"),
        (
            HumanItemCategory::CompetingResolution,
            "competing_attempt_group",
        ),
        (HumanItemCategory::AttemptResume, "attempt"),
        (HumanItemCategory::LaneLifecycle, "execution_lane"),
        (HumanItemCategory::CaptureIntegrity, "capture_receipt"),
        (HumanItemCategory::WorktreeLineage, "worktree_transition"),
        (HumanItemCategory::SegmentationCorrection, "work_episode"),
        (
            HumanItemCategory::RecoveryCorrection,
            "recovery_capture_request_revision",
        ),
    ] {
        let mut item = proposal_item.clone();
        item.item_kind = HumanItemKind::Generic;
        item.proposal = None;
        item.family = HumanObjectFamily::Work;
        item.category = category;
        item.object_kind = object_kind.into();
        item.object_ref = Some(format!("object:{object_kind}"));
        item.revision_ref = None;
        assert!(
            HumanGovernanceResponse::Snapshot {
                frontier: 1,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![item.clone()],
                next_cursor: None,
            }
            .validate()
        );
        item.object_kind.push_str("_history");
        assert!(
            !HumanGovernanceResponse::Snapshot {
                frontier: 1,
                status: HumanSnapshotStatus::Ready,
                degraded_reasons: Vec::new(),
                items: vec![item],
                next_cursor: None,
            }
            .validate()
        );
    }
    assert!(serde_json::from_str::<HumanGovernanceResponse>(
        r#"{"kind":"snapshot","frontier":1,"status":"ready","items":[{"item_kind":"generic","proposal":null,"stable_key":"x","row_class":"object","family":"work","category":"future_family","object_kind":"task","object_ref":null,"revision_ref":null,"lifecycle":null,"epistemic":null,"authority":null,"publication_state":null,"support_state":null,"scope_ref":null,"source_event_seq":1}],"next_cursor":null}"#,
    )
    .is_err());
    let negative_action = HumanActionRequest::NegativeReview {
        negative_evidence_id: evertrace_domain::ids::ProcedureNegativeEvidenceId::new_v7(),
        expected_review_revision_id: RevisionId::new_v7(),
        decision: NegativeReviewDecision::DismissAttribution,
    };
    let encoded = serde_json::to_value(&negative_action).unwrap();
    assert!(encoded.get("result_revision_ids").is_none());
    assert!(encoded.get("successor_usage_id").is_none());
    for (decision, encoded) in [
        (
            NegativeReviewDecision::ResolveAsIneffective,
            "resolve_as_ineffective",
        ),
        (
            NegativeReviewDecision::DismissAttribution,
            "dismiss_attribution",
        ),
        (NegativeReviewDecision::ConfirmHarm, "confirm_harm"),
        (NegativeReviewDecision::RequestRevision, "request_revision"),
    ] {
        assert_eq!(serde_json::to_value(decision).unwrap(), encoded);
    }
    for removed in ["dismiss", "uphold", "supersede"] {
        assert!(serde_json::from_value::<NegativeReviewDecision>(removed.into()).is_err());
    }

    let mut attempt_item = proposal_item.clone();
    attempt_item.item_kind = HumanItemKind::Generic;
    attempt_item.proposal = None;
    attempt_item.family = HumanObjectFamily::Work;
    attempt_item.category = HumanItemCategory::AttemptResume;
    attempt_item.object_kind = "attempt".into();
    attempt_item.object_ref = Some(AttemptId::new_v7().to_string());
    attempt_item.revision_ref = Some(RevisionId::new_v7().to_string());
    attempt_item.lifecycle = Some("interrupted".into());
    let mut app = App::new();
    app.handle(AppEvent::HumanRead {
        surface: WireSurface::Inbox,
        locator: evertrace_tui::HumanReadLocator::List,
        response: HumanGovernanceResponse::Snapshot {
            frontier: 7,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![proposal_item.clone()],
            next_cursor: None,
        },
    });
    app.handle(AppEvent::HumanRead {
        surface: WireSurface::Inbox,
        locator: evertrace_tui::HumanReadLocator::Detail {
            expected_frontier: 7,
            stable_key: "proposal-row".into(),
            expected_revision_ref: Some(revision_id.to_string()),
        },
        response: HumanGovernanceResponse::Snapshot {
            frontier: 7,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![proposal_item],
            next_cursor: None,
        },
    });
    assert!(app.state().human.is_some());
    assert!(app.state().detail.is_some());
    app.dispatch(evertrace_tui::UiCommand::CancelModal);
    assert!(app.state().detail.is_none());
    assert_eq!(app.state().selection, 0);
    app.handle(AppEvent::HumanRead {
        surface: WireSurface::Inbox,
        locator: evertrace_tui::HumanReadLocator::List,
        response: HumanGovernanceResponse::Snapshot {
            frontier: 8,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![attempt_item.clone()],
            next_cursor: None,
        },
    });
    app.handle(AppEvent::HumanRead {
        surface: WireSurface::Inbox,
        locator: evertrace_tui::HumanReadLocator::Detail {
            expected_frontier: 8,
            stable_key: attempt_item.stable_key.clone(),
            expected_revision_ref: attempt_item.revision_ref.clone(),
        },
        response: HumanGovernanceResponse::Snapshot {
            frontier: 8,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![attempt_item],
            next_cursor: None,
        },
    });
    assert_eq!(
        app.dispatch(evertrace_tui::UiCommand::PrepareMarkNewAttempt),
        evertrace_tui::UiCommand::PrepareMarkNewAttempt
    );
    assert_eq!(
        app.dispatch(evertrace_tui::UiCommand::Detail),
        evertrace_tui::UiCommand::ConfirmProposal
    );
    app.dispatch(evertrace_tui::UiCommand::CancelModal);
}

#[tokio::test]
async fn bounded_system_pages_are_frontier_consistent_and_restart_rebuildable() {
    let root = TempDir::new().unwrap();
    let store = root.path().join("store");
    let writer = open_writer(&store).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let job_id = JobId::new_v7();
    let job = DurableJob {
        job_id,
        idempotency_key: "s31-job-key".into(),
        target_revision: "object:target".into(),
        target_watermark: 70,
        target_generation: 1,
        kind: "objects_projection".into(),
        algorithm_revision: "s31-test-v1".into(),
        model_id: None,
        priority: 3,
        state: JobStatus::Queued,
        attempt: 1,
        backoff_until_us: None,
        config_hash: CONFIG,
        budget: JobBudget {
            max_items: 4,
            max_bytes: None,
            max_input_tokens: None,
            max_output_tokens: None,
            max_calls: None,
            max_wall_time_ms: 100,
        },
        terminal: None,
        lease_until_us: None,
    };
    let mut events: Vec<_> = (0..70_u64)
        .map(|index| {
            JournalEventDraft::runtime(
                1,
                CONFIG,
                "s31-test-v1",
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::ObjectsProjection,
                    target_id: format!("object-{index:03}"),
                    algorithm_revision: "s31-test-v1".into(),
                    source_watermark: index + 1,
                }),
            )
        })
        .collect();
    events.extend([
        JournalEventDraft::runtime(
            1,
            CONFIG,
            "s31-test-v1",
            JournalPayload::ConfigAudit(ConfigAudit {
                config_version: 1,
                effective_config_hash: CONFIG,
            }),
        ),
        JournalEventDraft::runtime(
            1,
            CONFIG,
            "s31-test-v1",
            JournalPayload::JobState(job.clone()),
        ),
    ]);
    let command = JournalCommand::new(CommandId::new_v7(), events).unwrap();
    handle.commit(command, 1).await.unwrap();
    let mut failed_job = job;
    failed_job.state = JobStatus::Failed;
    failed_job.terminal = Some(Box::new(JobTerminalAudit {
        outcome: JobTerminalOutcome::Failed,
        reason: JobTerminalReason::Unsupported,
        result_ref: None,
    }));
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    2,
                    CONFIG,
                    "s31-test-v1",
                    JournalPayload::JobState(failed_job),
                )],
            )
            .unwrap(),
            2,
        )
        .await
        .unwrap();

    let service = HumanGovernanceService::new(handle.clone(), CONFIG);
    let first = service
        .list(HumanSurface::System, None, None, HUMAN_PAGE_LIMIT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        first.status,
        evertrace_engine::HumanSnapshotStatus::Degraded
    );
    assert_eq!(
        first.degraded_reasons,
        vec![evertrace_engine::HumanDegradedReason::CurrentJobFailed]
    );
    assert_eq!(first.items.len(), usize::from(HUMAN_PAGE_LIMIT));
    let cursor = first.next_cursor.clone().unwrap();
    assert!(first.items.iter().all(|item| item.category
        == evertrace_engine::HumanItemCategory::Runtime
        && item.system_detail.is_none()));
    let generic_item = first
        .items
        .iter()
        .find(|item| item.stable_key.starts_with("runtime:dirty:"))
        .unwrap();
    let detail = service
        .detail(
            HumanSurface::System,
            &generic_item.stable_key,
            first.frontier,
            generic_item.revision_ref.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.status, first.status);
    assert_eq!(detail.degraded_reasons, first.degraded_reasons);
    assert_eq!(detail.items.as_slice(), std::slice::from_ref(generic_item));
    let second = service
        .list(
            HumanSurface::System,
            Some(first.frontier),
            Some(&cursor),
            HUMAN_PAGE_LIMIT,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.items.len(), 8);
    assert!(second.next_cursor.is_none());
    let system_items: Vec<_> = first.items.iter().chain(&second.items).collect();
    let config_item = system_items
        .iter()
        .find(|item| item.stable_key == "runtime:config:current")
        .unwrap();
    let job_item = system_items
        .iter()
        .find(|item| item.stable_key == format!("runtime:job:{job_id}"))
        .unwrap();
    let config_detail = service
        .detail(
            HumanSurface::System,
            &config_item.stable_key,
            first.frontier,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        config_detail.items[0].system_detail,
        Some(HumanSystemDetail::Config {
            config_version: 1,
            effective_config_hash: CONFIG,
        })
    ));
    let job_detail = service
        .detail(
            HumanSurface::System,
            &job_item.stable_key,
            first.frontier,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        &job_detail.items[0].system_detail,
        Some(HumanSystemDetail::Job { detail })
            if detail.job_id == job_id && detail.target_watermark == 70
    ));
    assert_eq!(
        service
            .detail(
                HumanSurface::System,
                &first.items[0].stable_key,
                first.frontier + 1,
                None,
            )
            .await
            .unwrap(),
        Err((first.frontier, None))
    );
    assert_eq!(
        service
            .list(HumanSurface::System, Some(first.frontier + 1), None, 1)
            .await
            .unwrap(),
        Err(first.frontier)
    );

    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let reopened = open_writer(&store).await.unwrap();
    let (handle, task) = spawn_writer(reopened, 8).unwrap();
    let rebuilt = HumanGovernanceService::new(handle.clone(), CONFIG)
        .list(HumanSurface::System, None, None, HUMAN_PAGE_LIMIT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rebuilt.items, first.items);
    assert_eq!(rebuilt.status, first.status);
    assert_eq!(rebuilt.degraded_reasons, first.degraded_reasons);
    let rebuilt_job = HumanGovernanceService::new(handle.clone(), CONFIG)
        .detail(
            HumanSurface::System,
            &format!("runtime:job:{job_id}"),
            rebuilt.frontier,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rebuilt_job.items, job_detail.items);
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn mark_new_attempt_creates_one_unknown_child_and_replays_after_reopen() {
    let root = TempDir::new().unwrap();
    let store = root.path().join("store");
    let writer = open_writer(&store).await.unwrap();
    let (handle, writer_task) = spawn_writer(writer, 8).unwrap();
    let task_id = TaskId::new_v7();
    let task = Task {
        task_id,
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec!["request:s31-mark-new".into()],
        canonical_goal: "represent a human-marked unknown resume".into(),
        scope_memberships: vec![TaskScopeMembership {
            repository_instance_id: None,
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
    };
    let lane_id = ExecutionLaneId::new_v7();
    let (lane, capture_receipt) = interrupted_capture_pair(lane_id);
    let workstream_id = WorkstreamId::new_v7();
    let workstream = Workstream {
        workstream_id,
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        task_id,
        repository_instance_id: None,
        worktree_instance_ids: Vec::new(),
        active_worktree_instance_id: None,
        worktree_lineage_refs: Vec::new(),
        parent_workstream_id: None,
        dependency_workstream_ids: Vec::new(),
        status: WorkstreamStatus::Active,
        root_goal: "resolve interrupted execution honestly".into(),
        workstream_goal: "create one clean unknown child".into(),
        target_family: "attempt".into(),
        hypothesis_or_failure_family: "unknown resume state".into(),
        acceptance_boundary: "human mark-new decision".into(),
        phase_contract: PhaseContract {
            local_goal: "record unknown child".into(),
            phase_kind: PhaseKind::Implement,
            phase_label: "s31-mark-new".into(),
            primary_targets: vec!["attempt".into()],
            entry_conditions: vec!["source interrupted".into()],
            acceptance_boundary: "one manual child".into(),
            expected_state_transition: "new proposed attempt".into(),
        },
        active_episode_id: None,
        execution_lane_ids: vec![lane_id],
        source_watermark: 1,
    };
    let mut source_attempt = new_attempt(
        task_id,
        workstream_id,
        None,
        Vec::new(),
        vec![lane_id],
        mark_new_strategy(),
        1,
    )
    .unwrap();
    source_attempt.execution_status = evertrace_domain::work::AttemptExecutionStatus::Interrupted;
    source_attempt.interruption_refs = vec!["interrupt:s31-mark-new".into()];
    source_attempt.interruption_reason = Some(InterruptionReason::Cancelled);
    source_attempt.validate().unwrap();
    let initial = JournalCommand::new(
        CommandId::new_v7(),
        [
            JournalPayload::TaskRecorded(Box::new(task)),
            JournalPayload::WorkstreamRecorded(Box::new(workstream)),
            JournalPayload::ExecutionLaneRecorded(Box::new(lane)),
            JournalPayload::CaptureReceiptRecorded(Box::new(capture_receipt)),
            JournalPayload::AttemptRecorded(Box::new(source_attempt.clone())),
        ]
        .into_iter()
        .map(|payload| JournalEventDraft::runtime(1, CONFIG, "s31-test-v1", payload))
        .collect(),
    )
    .unwrap();
    handle.commit(initial, 1).await.unwrap();
    let service = HumanGovernanceService::new(handle.clone(), CONFIG);
    let action_frontier = handle.project().await.unwrap().frontier;
    let source_ref = source_attempt.attempt_id.to_string();
    assert!(
        service
            .list(HumanSurface::Inbox, None, None, HUMAN_PAGE_LIMIT)
            .await
            .unwrap()
            .unwrap()
            .items
            .iter()
            .any(|item| item.object_ref.as_deref() == Some(source_ref.as_str()))
    );

    let mut forged_child = new_attempt(
        task_id,
        workstream_id,
        None,
        Vec::new(),
        Vec::new(),
        source_attempt.strategy_contract.clone(),
        action_frontier,
    )
    .unwrap();
    forged_child.resume_event_refs = vec![source_attempt.revision_id.to_string()];
    let mut forged_child = create_resume_attempt(
        forged_child,
        &source_attempt,
        ResumeStateAssessment::Unknown,
    )
    .unwrap();
    forged_child.source_watermark += 1;
    let mut forged_event = JournalEventDraft::runtime(
        2,
        CONFIG,
        "s31-test-v1",
        JournalPayload::AttemptRecorded(Box::new(forged_child)),
    );
    forged_event.source_kind = SourceKind::Manual;
    assert!(
        handle
            .commit(
                JournalCommand::new(CommandId::new_v7(), vec![forged_event]).unwrap(),
                2,
            )
            .await
            .is_err()
    );
    assert_eq!(handle.project().await.unwrap().frontier, action_frontier);

    let request_id = RequestId::new_v7();
    let evertrace_engine::HumanActionOutcome::Applied {
        current_revision_ref,
        audit_event_ref,
    } = service
        .mark_new_attempt(request_id, action_frontier, source_attempt.revision_id)
        .await
        .unwrap()
    else {
        panic!("mark-new must apply one child")
    };
    let child_revision_id = current_revision_ref.parse::<RevisionId>().unwrap();
    let snapshot = handle.project().await.unwrap();
    let after_frontier = snapshot.frontier;
    let view = AttemptCurrentView::from_snapshot(&snapshot).unwrap();
    let child = view
        .attempts
        .values()
        .find(|attempt| attempt.revision_id == child_revision_id)
        .unwrap();
    assert_eq!(
        child.resumes_from_attempt_id,
        Some(source_attempt.attempt_id)
    );
    assert_eq!(
        child.resume_state_assessment,
        Some(ResumeStateAssessment::Unknown)
    );
    assert_eq!(
        child.resume_event_refs,
        vec![source_attempt.revision_id.to_string()]
    );
    assert_eq!(
        child.execution_status,
        evertrace_domain::work::AttemptExecutionStatus::Proposed
    );
    assert!(child.execution_lane_ids.is_empty());
    assert!(child.interruption_refs.is_empty());
    assert_eq!(view.attempts[&source_attempt.attempt_id], source_attempt);
    assert!(
        service
            .list(HumanSurface::Inbox, None, None, HUMAN_PAGE_LIMIT)
            .await
            .unwrap()
            .unwrap()
            .items
            .iter()
            .all(|item| item.object_ref.as_deref() != Some(source_ref.as_str()))
    );
    assert_eq!(
        service
            .mark_new_attempt(request_id, action_frontier, source_attempt.revision_id,)
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Applied {
            current_revision_ref: child_revision_id.to_string(),
            audit_event_ref: audit_event_ref.clone(),
        }
    );
    assert_eq!(
        service
            .mark_new_attempt(
                RequestId::new_v7(),
                after_frontier,
                source_attempt.revision_id,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::NoDelta {
            current_revision_ref: child_revision_id.to_string(),
        }
    );
    assert!(matches!(
        service
            .mark_new_attempt(
                RequestId::new_v7(),
                action_frontier,
                source_attempt.revision_id,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Conflict { .. }
    ));
    assert!(matches!(
        service
            .mark_new_attempt(RequestId::new_v7(), after_frontier, child_revision_id)
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Unavailable { .. }
    ));
    assert_eq!(handle.project().await.unwrap().frontier, after_frontier);

    let mut system_child = new_attempt(
        task_id,
        workstream_id,
        None,
        Vec::new(),
        Vec::new(),
        source_attempt.strategy_contract.clone(),
        after_frontier,
    )
    .unwrap();
    system_child.resume_event_refs = vec![source_attempt.revision_id.to_string()];
    let system_child = create_resume_attempt(
        system_child,
        &source_attempt,
        ResumeStateAssessment::Unknown,
    )
    .unwrap();
    let system_child_revision_id = system_child.revision_id;
    let selected_child_revision_id = if child.attempt_id < system_child.attempt_id {
        child_revision_id
    } else {
        system_child_revision_id
    };
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    3,
                    CONFIG,
                    "s31-test-v1",
                    JournalPayload::AttemptRecorded(Box::new(system_child)),
                )],
            )
            .unwrap(),
            3,
        )
        .await
        .unwrap();
    let multiple_children_frontier = handle.project().await.unwrap().frontier;
    assert_eq!(
        service
            .mark_new_attempt(
                RequestId::new_v7(),
                multiple_children_frontier,
                source_attempt.revision_id,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::NoDelta {
            current_revision_ref: selected_child_revision_id.to_string(),
        }
    );
    assert_eq!(
        handle.project().await.unwrap().frontier,
        multiple_children_frontier
    );

    handle.shutdown().await.unwrap();
    writer_task.await.unwrap().unwrap();
    let reopened = open_writer(&store).await.unwrap();
    let (reopened_handle, reopened_task) = spawn_writer(reopened, 8).unwrap();
    let reopened_service = HumanGovernanceService::new(reopened_handle.clone(), CONFIG);
    assert_eq!(
        reopened_service
            .mark_new_attempt(request_id, after_frontier, source_attempt.revision_id)
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Applied {
            current_revision_ref: child_revision_id.to_string(),
            audit_event_ref,
        }
    );
    assert_eq!(
        reopened_handle.project().await.unwrap().frontier,
        multiple_children_frontier
    );
    reopened_handle.shutdown().await.unwrap();
    reopened_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn plain_accept_uses_one_real_command_for_atom_procedure_and_core() {
    let root = TempDir::new().unwrap();
    let runtime = runtime_snapshot(root.path());
    DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    drop(evertrace_capture::CaptureRuntime::open(runtime.clone()).unwrap());
    let repository_id = RepositoryId::new_v7();
    let worktree_id = WorktreeId::new_v7();
    let task_id = TaskId::new_v7();
    let repository_path = root.path().join("repo").display().to_string();
    let path_observation = PathObservation {
        path: repository_path.clone(),
        first_observed_at_us: 1,
        last_observed_at_us: 1,
        evidence_refs: vec!["path:s31".into()],
    };
    let repository = RepositoryInstance {
        repository_id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: repository_path.clone(),
        path_history: vec![path_observation.clone()],
        git_common_dir_path: Some(format!("{repository_path}/.git")),
        common_dir_filesystem: Some(FilesystemIdentity {
            device: 31,
            inode: 1,
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: Vec::new(),
        derived_from: None,
        identity_evidence_refs: vec!["repository:s31".into()],
        recorded_at_us: 1,
    };
    let worktree = WorktreeInstance {
        worktree_instance_id: worktree_id,
        worktree_revision: 1,
        predecessor_revision: None,
        repository_instance_id: repository_id,
        kind: WorktreeKind::Main,
        lifecycle: WorktreeLifecycle::Active,
        current_path: Some(repository_path.clone()),
        path_history: vec![path_observation.clone()],
        git_admin_path_history: vec![PathObservation {
            path: format!("{repository_path}/.git"),
            ..path_observation
        }],
        git_registration_state: GitRegistrationState::Registered,
        current_snapshot_id: None,
        created_event_ref: "worktree:s31".into(),
        terminal_event_ref: None,
        recreated_from_worktree_instance_id: None,
        recorded_at_us: 1,
    };
    let task_value = Task {
        task_id,
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec!["request:s31".into()],
        canonical_goal: "exercise atomic human acceptance".into(),
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
    let (receipt, observation) = source("governance", task_id, repository_id);
    let target = observation.source_observation_id.to_string();
    let initial = JournalCommand::new(
        CommandId::new_v7(),
        vec![
            JournalPayload::SourceReceiptRecorded(Box::new(receipt.clone())),
            JournalPayload::SourceObservationRecorded(Box::new(observation.clone())),
            JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
                source_instance_id: receipt.source_instance_id.clone(),
                source_revision: receipt.source_revision.clone(),
                source_sequence: 1,
                confirmed_prefix_digest: None,
            }),
            JournalPayload::DirtyTarget(DirtyTarget {
                target_kind: DirtyTargetKind::EvidenceSurface,
                target_id: target.clone(),
                algorithm_revision: "s31-test-v1".into(),
                source_watermark: 1,
            }),
            JournalPayload::DirtyTarget(DirtyTarget {
                target_kind: DirtyTargetKind::PhysicalNormalization,
                target_id: target,
                algorithm_revision: "s31-test-v1".into(),
                source_watermark: 1,
            }),
            JournalPayload::RepositoryInstanceRecorded(Box::new(repository)),
            JournalPayload::WorktreeInstanceRecorded(Box::new(worktree)),
            JournalPayload::TaskRecorded(Box::new(task_value)),
        ]
        .into_iter()
        .map(|payload| JournalEventDraft::runtime(1, CONFIG, "s31-test-v1", payload))
        .collect(),
    )
    .unwrap();
    let store = root.path().join("store");
    let writer = open_writer(&store).await.unwrap();
    let (handle, writer_task) = spawn_writer(writer, 8).unwrap();
    handle.commit(initial, 1).await.unwrap();
    let proposals = RevisionProposalService;

    let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: atom_proposal,
        command: atom_submit,
    } = proposals
        .submit(
            &view,
            proposal_context(2),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                    draft: atom_draft(repository_id, &receipt, &observation),
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("atom proposal must be new")
    };
    handle.commit(atom_submit, 2).await.unwrap();
    let service = HumanGovernanceService::with_acceptance(
        handle.clone(),
        CONFIG,
        runtime.clone(),
        GlobalPromotionConfig {
            atom: PromotionLevel::Manual,
            procedure: PromotionLevel::Manual,
            core_membership: PromotionLevel::Manual,
        },
    );
    assert!(matches!(
        service
            .resolve_competing_selected(
                RequestId::new_v7(),
                handle.project().await.unwrap().frontier.saturating_sub(1),
                RevisionId::new_v7(),
                AttemptId::new_v7(),
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Conflict {
            current_revision_ref: None
        }
    ));
    let atom_page = service
        .list(HumanSurface::Inbox, None, None, HUMAN_PAGE_LIMIT)
        .await
        .unwrap()
        .unwrap();
    let atom_item = atom_page
        .items
        .iter()
        .find(|item| {
            item.proposal
                .as_ref()
                .is_some_and(|proposal| proposal.proposal_id == atom_proposal.proposal_id)
        })
        .unwrap();
    assert!(atom_item.proposal_review.is_none());
    let atom_detail = service
        .detail(
            HumanSurface::Inbox,
            &atom_item.stable_key,
            atom_page.frontier,
            atom_item.revision_ref.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        atom_detail.items[0]
            .proposal_review
            .as_ref()
            .is_some_and(|review| review.plain_accept_eligible
                && matches!(&review.proposal.payload, ProposalPayload::Atom(_)))
    );
    let atom_frontier = handle.project().await.unwrap().frontier;
    let atom_request = RequestId::new_v7();
    let atom_outcome = service
        .decide_proposal(
            atom_request,
            atom_frontier,
            atom_proposal.proposal_id,
            atom_proposal.proposal_revision_id,
            &evertrace_domain::evidence::hex(&atom_proposal.fingerprint),
            HumanProposalDecision::Accept,
        )
        .await
        .unwrap();
    assert!(matches!(
        atom_outcome,
        evertrace_engine::HumanActionOutcome::Applied { .. }
    ));
    let atom_command = handle
        .committed_command(CommandId::from_uuid(atom_request.as_uuid()).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        atom_command
            .payloads
            .iter()
            .any(|payload| matches!(payload, JournalPayload::SourceReceiptRecorded(_)))
    );
    assert!(
        atom_command
            .payloads
            .iter()
            .any(|payload| matches!(payload, JournalPayload::SourceObservationRecorded(_)))
    );
    assert!(atom_command.payloads.iter().any(|payload| matches!(payload, JournalPayload::RevisionProposalRecorded(value) if value.status == ProposalStatus::Accepted)));
    let accepted_atom_revision =
        SemanticCurrentView::from_snapshot(&handle.project().await.unwrap())
            .unwrap()
            .proposals[&atom_proposal.proposal_id]
            .acceptance
            .as_ref()
            .unwrap()
            .accepted_atom()
            .unwrap()
            .1;

    let first_atom = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap())
        .unwrap()
        .atom_revisions[&accepted_atom_revision]
        .clone();

    fn prove_support_replacement<'a>(
        handle: &'a evertrace_engine::WriterHandle,
        service: &'a HumanGovernanceService,
        proposals: &'a RevisionProposalService,
        first_atom: &'a evertrace_domain::semantic::Atom,
        repository_id: RepositoryId,
        receipt: &'a SourceReceipt,
        observation: &'a SourceObservation,
    ) -> SupportProofFuture<'a> {
        Box::pin(async move {
            let mut global_atom_draft = atom_draft(repository_id, receipt, observation);
            global_atom_draft.scope = AtomScope::Global;
            global_atom_draft.value.text = "global successor before support correction".into();
            global_atom_draft.supports_revision_refs = vec![first_atom.revision_id];
            let view =
                SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
            let ProposalResolution::Revision {
                value: global_atom_proposal,
                command: global_atom_submit,
            } = proposals
                .submit(
                    &view,
                    proposal_context(3),
                    SubmitProposalRequest {
                        target_kind: ProposalTargetKind::Atom,
                        target_id: None,
                        base_revision_id: None,
                        operation: ProposalOperation::Create,
                        payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                            draft: global_atom_draft,
                        })),
                        evidence_refs: vec![receipt.source_receipt_id.to_string()],
                        source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                        eligibility: ProposalEligibility::ManualRequired,
                        created_by: ProposalCreatedBy::Agent,
                    },
                )
                .unwrap()
            else {
                panic!("global atom proposal must be new")
            };
            handle.commit(global_atom_submit, 3).await.unwrap();
            let global_atom_accept = RequestId::new_v7();
            let frontier = handle.project().await.unwrap().frontier;
            assert!(matches!(
                service
                    .decide_proposal(
                        global_atom_accept,
                        frontier,
                        global_atom_proposal.proposal_id,
                        global_atom_proposal.proposal_revision_id,
                        &evertrace_domain::evidence::hex(&global_atom_proposal.fingerprint),
                        HumanProposalDecision::Accept,
                    )
                    .await
                    .unwrap(),
                evertrace_engine::HumanActionOutcome::Applied { .. }
            ));
            let global_atom_accept_command = handle
                .committed_command(CommandId::from_uuid(global_atom_accept.as_uuid()).unwrap())
                .await
                .unwrap()
                .unwrap();
            let global_atom_valid = global_atom_accept_command
                .payloads
                .iter()
                .find_map(|payload| match payload {
                    JournalPayload::GlobalSupportValidationRecorded(value) => Some(value.as_ref()),
                    _ => None,
                })
                .unwrap();
            let valid_frontier = handle.project().await.unwrap().frontier;
            let valid_detail = service
                .detail(
                    HumanSurface::Explorer,
                    &format!(
                        "object:atom:global_support_validation:{}",
                        global_atom_valid.validation_revision_id
                    ),
                    valid_frontier,
                    Some(&global_atom_valid.validation_revision_id.to_string()),
                )
                .await
                .unwrap()
                .unwrap();
            assert!(
                valid_detail.items[0]
                    .support_detail
                    .as_ref()
                    .is_some_and(|detail| detail.initial_replacement_payload.is_none())
            );
            assert!(matches!(
                service
                    .submit_support_replacement(
                        RequestId::new_v7(),
                        valid_frontier,
                        global_atom_valid.validation_revision_id,
                        global_atom_proposal.payload.clone(),
                    )
                    .await
                    .unwrap(),
                evertrace_engine::HumanActionOutcome::Unavailable {
                    reason: "support_replacement_requires_non_valid_support"
                }
            ));
            assert_eq!(handle.project().await.unwrap().frontier, valid_frontier);
            let atom_pending_payloads = mark_support_pending(
                global_atom_valid,
                vec!["support:atom-edit".into()],
                CONFIG,
                5,
            )
            .unwrap();
            let atom_pending = atom_pending_payloads
                .iter()
                .find_map(|payload| match payload {
                    JournalPayload::GlobalSupportValidationRecorded(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap();
            handle
                .commit(
                    JournalCommand::new(
                        CommandId::new_v7(),
                        atom_pending_payloads
                            .into_iter()
                            .map(|payload| {
                                JournalEventDraft::runtime(5, CONFIG, "s31-test-v1", payload)
                            })
                            .collect(),
                    )
                    .unwrap(),
                    5,
                )
                .await
                .unwrap();
            let atom_support_frontier = handle.project().await.unwrap().frontier;
            let atom_support_detail = service
                .detail(
                    HumanSurface::Inbox,
                    &format!(
                        "object:atom:global_support_validation:{}",
                        atom_pending.validation_revision_id
                    ),
                    atom_support_frontier,
                    Some(&atom_pending.validation_revision_id.to_string()),
                )
                .await
                .unwrap()
                .unwrap();
            let mut atom_replacement = atom_support_detail.items[0]
                .support_detail
                .as_ref()
                .unwrap()
                .initial_replacement_payload
                .as_ref()
                .unwrap()
                .as_ref()
                .clone();
            let ProposalPayload::Atom(atom_replacement_payload) = &mut atom_replacement else {
                unreachable!()
            };
            let AtomProposalPayload::Replace { draft } = atom_replacement_payload.as_mut() else {
                unreachable!()
            };
            draft.value.text = "global successor after support correction".into();
            let atom_replacement_request = RequestId::new_v7();
            let atom_replacement_outcome = service
                .submit_support_replacement(
                    atom_replacement_request,
                    atom_support_frontier,
                    atom_pending.validation_revision_id,
                    atom_replacement.clone(),
                )
                .await
                .unwrap();
            let evertrace_engine::HumanActionOutcome::Applied {
                current_revision_ref: atom_replacement_revision,
                audit_event_ref: atom_replacement_audit_ref,
            } = atom_replacement_outcome
            else {
                panic!("atom support replacement must apply")
            };
            let atom_replacement_revision =
                atom_replacement_revision.parse::<RevisionId>().unwrap();
            let atom_replacement_proposal =
                SemanticCurrentView::from_snapshot(&handle.project().await.unwrap())
                    .unwrap()
                    .proposal_revisions[&atom_replacement_revision]
                    .clone();
            let atom_replacement_command = handle
                .committed_command(
                    CommandId::from_uuid(atom_replacement_request.as_uuid()).unwrap(),
                )
                .await
                .unwrap()
                .unwrap();
            let atom_replacement_ordinal = atom_replacement_command
                .payloads
                .iter()
                .position(|payload| {
                    matches!(
                        payload,
                        JournalPayload::RevisionProposalRecorded(proposal)
                            if proposal.proposal_id == atom_replacement_proposal.proposal_id
                                && proposal.proposal_revision_id
                                    == atom_replacement_proposal.proposal_revision_id
                    )
                })
                .unwrap();
            assert_eq!(
                atom_replacement_command.event_ids[atom_replacement_ordinal],
                atom_replacement_audit_ref
            );
            assert_eq!(atom_replacement_proposal.status, ProposalStatus::Pending);
            assert_eq!(
                atom_replacement_proposal.evidence_refs,
                [atom_pending.validation_revision_id.to_string()]
            );
            assert_eq!(
                atom_replacement_proposal.source_cohort_refs,
                atom_replacement_proposal.evidence_refs
            );
            let after_atom_replacement = handle.project().await.unwrap().frontier;
            assert!(matches!(
                service
                    .submit_support_replacement(
                        RequestId::new_v7(),
                        after_atom_replacement,
                        atom_pending.validation_revision_id,
                        atom_replacement.clone(),
                    )
                    .await
                    .unwrap(),
                evertrace_engine::HumanActionOutcome::NoDelta { .. }
            ));
            assert_eq!(
                handle.project().await.unwrap().frontier,
                after_atom_replacement
            );
            assert!(matches!(
                service
                    .decide_proposal(
                        RequestId::new_v7(),
                        after_atom_replacement,
                        atom_replacement_proposal.proposal_id,
                        atom_replacement_proposal.proposal_revision_id,
                        &evertrace_domain::evidence::hex(&atom_replacement_proposal.fingerprint),
                        HumanProposalDecision::Reject,
                    )
                    .await
                    .unwrap(),
                evertrace_engine::HumanActionOutcome::Applied { .. }
            ));
            let rejected_snapshot = handle.project().await.unwrap();
            let rejected_view = SemanticCurrentView::from_snapshot(&rejected_snapshot).unwrap();
            let rejected = rejected_view.proposals[&atom_replacement_proposal.proposal_id].clone();
            assert_eq!(rejected.status, ProposalStatus::Rejected);
            let proposal_revision_count = rejected_view.proposal_revisions.len();
            assert!(matches!(
                service
                    .submit_support_replacement(
                        RequestId::new_v7(),
                        rejected_snapshot.frontier,
                        atom_pending.validation_revision_id,
                        atom_replacement.clone(),
                    )
                    .await
                    .unwrap(),
                evertrace_engine::HumanActionOutcome::NoDelta {
                    current_revision_ref
                } if current_revision_ref == rejected.proposal_revision_id.to_string()
            ));
            let after_rejected_retry = handle.project().await.unwrap();
            assert_eq!(after_rejected_retry.frontier, rejected_snapshot.frontier);
            assert_eq!(
                SemanticCurrentView::from_snapshot(&after_rejected_retry)
                    .unwrap()
                    .proposal_revisions
                    .len(),
                proposal_revision_count
            );
            let mut forged = atom_replacement_proposal.clone();
            forged.proposal_id = RevisionProposalId::new_v7();
            forged.proposal_revision_id = RevisionId::new_v7();
            let ProposalPayload::Atom(payload) = &mut forged.payload else {
                unreachable!()
            };
            let AtomProposalPayload::Replace { draft } = payload.as_mut() else {
                unreachable!()
            };
            draft.source_observation_refs.clear();
            forged.fingerprint = forged.recompute_fingerprint().unwrap();
            let before_forged = handle.project().await.unwrap().frontier;
            assert!(
                handle
                    .commit(
                        JournalCommand::new(
                            CommandId::new_v7(),
                            vec![JournalEventDraft::runtime(
                                6,
                                CONFIG,
                                "s31-test-v1",
                                JournalPayload::RevisionProposalRecorded(Box::new(forged)),
                            )],
                        )
                        .unwrap(),
                        6,
                    )
                    .await
                    .is_err()
            );
            assert_eq!(handle.project().await.unwrap().frontier, before_forged);

            let (replacement_atom, replacement_valid, downstream_valid) = Box::pin(async {
                let mut accepted_replacement = atom_replacement.clone();
                let ProposalPayload::Atom(payload) = &mut accepted_replacement else {
                    unreachable!()
                };
                let AtomProposalPayload::Replace { draft } = payload.as_mut() else {
                    unreachable!()
                };
                draft.value.text = "accepted global support replacement".into();
                let accepted_replacement_request = RequestId::new_v7();
                let accepted_replacement_frontier = handle.project().await.unwrap().frontier;
                assert!(matches!(
                    service
                        .submit_support_replacement(
                            accepted_replacement_request,
                            accepted_replacement_frontier,
                            atom_pending.validation_revision_id,
                            accepted_replacement,
                        )
                        .await
                        .unwrap(),
                    evertrace_engine::HumanActionOutcome::Applied { .. }
                ));
                let accepted_replacement_proposal =
                    SemanticCurrentView::from_snapshot(&handle.project().await.unwrap())
                        .unwrap()
                        .proposals
                        .values()
                        .find(|proposal| {
                            proposal.operation == ProposalOperation::Replace
                                && proposal.evidence_refs
                                    == [atom_pending.validation_revision_id.to_string()]
                                && proposal.status == ProposalStatus::Pending
                                && proposal.proposal_id != atom_replacement_proposal.proposal_id
                        })
                        .unwrap()
                        .clone();
                let accept_replacement_request = RequestId::new_v7();
                let accept_replacement_frontier = handle.project().await.unwrap().frontier;
                assert!(matches!(
                    service
                        .decide_proposal(
                            accept_replacement_request,
                            accept_replacement_frontier,
                            accepted_replacement_proposal.proposal_id,
                            accepted_replacement_proposal.proposal_revision_id,
                            &evertrace_domain::evidence::hex(
                                &accepted_replacement_proposal.fingerprint,
                            ),
                            HumanProposalDecision::Accept,
                        )
                        .await
                        .unwrap(),
                    evertrace_engine::HumanActionOutcome::Applied { .. }
                ));
                let replacement_accept_command = handle
                    .committed_command(
                        CommandId::from_uuid(accept_replacement_request.as_uuid()).unwrap(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                let replacement_atom = replacement_accept_command
                    .payloads
                    .iter()
                    .find_map(|payload| match payload {
                        JournalPayload::AtomRecorded(value)
                            if value.parent_revision_id
                                == accepted_replacement_proposal.base_revision_id =>
                        {
                            Some(value.as_ref())
                        }
                        _ => None,
                    })
                    .unwrap()
                    .clone();
                let replacement_valid = replacement_accept_command
                    .payloads
                    .iter()
                    .find_map(|payload| match payload {
                        JournalPayload::GlobalSupportValidationRecorded(value)
                            if value.successor_ref == replacement_atom.revision_id.to_string()
                                && value.state == GlobalSupportState::Valid =>
                        {
                            Some(value.as_ref())
                        }
                        _ => None,
                    })
                    .unwrap()
                    .clone();
                assert_eq!(
                    replacement_accept_command
                        .payloads
                        .iter()
                        .filter(|payload| matches!(
                            payload,
                            JournalPayload::GlobalSupportContractRecorded(value)
                                if value.successor_revision_or_membership_ref
                                    == replacement_atom.revision_id.to_string()
                        ))
                        .count(),
                    1
                );

                let mut downstream_draft = atom_draft(repository_id, receipt, observation);
                downstream_draft.scope = AtomScope::Global;
                downstream_draft.value.text = "downstream support consumer".into();
                downstream_draft.supports_revision_refs = vec![replacement_atom.revision_id];
                let view =
                    SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
                let ProposalResolution::Revision {
                    value: downstream_proposal,
                    command: downstream_submit,
                } = proposals
                    .submit(
                        &view,
                        proposal_context(7),
                        SubmitProposalRequest {
                            target_kind: ProposalTargetKind::Atom,
                            target_id: None,
                            base_revision_id: None,
                            operation: ProposalOperation::Create,
                            payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                                draft: downstream_draft,
                            })),
                            evidence_refs: vec![receipt.source_receipt_id.to_string()],
                            source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                            eligibility: ProposalEligibility::ManualRequired,
                            created_by: ProposalCreatedBy::Agent,
                        },
                    )
                    .unwrap()
                else {
                    panic!("downstream proposal must be new")
                };
                handle.commit(downstream_submit, 7).await.unwrap();
                let downstream_accept_request = RequestId::new_v7();
                assert!(matches!(
                    service
                        .decide_proposal(
                            downstream_accept_request,
                            handle.project().await.unwrap().frontier,
                            downstream_proposal.proposal_id,
                            downstream_proposal.proposal_revision_id,
                            &evertrace_domain::evidence::hex(&downstream_proposal.fingerprint),
                            HumanProposalDecision::Accept,
                        )
                        .await
                        .unwrap(),
                    evertrace_engine::HumanActionOutcome::Applied { .. }
                ));
                let downstream_accept_command = handle
                    .committed_command(
                        CommandId::from_uuid(downstream_accept_request.as_uuid()).unwrap(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                let downstream_valid = downstream_accept_command
                    .payloads
                    .iter()
                    .find_map(|payload| match payload {
                        JournalPayload::GlobalSupportValidationRecorded(value)
                            if value.state == GlobalSupportState::Valid =>
                        {
                            Some(value.as_ref())
                        }
                        _ => None,
                    })
                    .unwrap()
                    .clone();

                (replacement_atom, replacement_valid, downstream_valid)
            })
            .await;

            let (
                deprecate_submit_request_id,
                deprecate_submit_frontier,
                deprecate_validation_revision_id,
                deprecate_reason,
                deprecate_submit_audit,
            ) = Box::pin(async {
                let replacement_pending_payloads = mark_support_pending(
                    &replacement_valid,
                    vec!["support:deprecate".into()],
                    CONFIG,
                    8,
                )
                .unwrap();
                let replacement_pending = replacement_pending_payloads
                    .iter()
                    .find_map(|payload| match payload {
                        JournalPayload::GlobalSupportValidationRecorded(value) => {
                            Some(value.as_ref())
                        }
                        _ => None,
                    })
                    .unwrap()
                    .clone();
                handle
                    .commit(
                        JournalCommand::new(
                            CommandId::new_v7(),
                            replacement_pending_payloads
                                .into_iter()
                                .map(|payload| {
                                    JournalEventDraft::runtime(8, CONFIG, "s31-test-v1", payload)
                                })
                                .collect(),
                        )
                        .unwrap(),
                        8,
                    )
                    .await
                    .unwrap();
                let deprecate_submit_frontier = handle.project().await.unwrap().frontier;
                assert!(matches!(
                    service
                        .submit_support_deprecate(
                            RequestId::new_v7(),
                            deprecate_submit_frontier - 1,
                            replacement_pending.validation_revision_id,
                            "support cannot be restored".into(),
                        )
                        .await
                        .unwrap(),
                    evertrace_engine::HumanActionOutcome::Conflict { .. }
                ));
                let deprecate_submit_request_id = RequestId::new_v7();
                let deprecate_reason = "support cannot be restored".to_owned();
                let evertrace_engine::HumanActionOutcome::Applied {
                    audit_event_ref: deprecate_submit_audit,
                    ..
                } = service
                    .submit_support_deprecate(
                        deprecate_submit_request_id,
                        deprecate_submit_frontier,
                        replacement_pending.validation_revision_id,
                        deprecate_reason.clone(),
                    )
                    .await
                    .unwrap()
                else {
                    panic!("support deprecate must create a proposal")
                };
                let after_deprecate_submit = handle.project().await.unwrap();
                assert!(matches!(
                    service
                        .submit_support_deprecate(
                            deprecate_submit_request_id,
                            deprecate_submit_frontier,
                            replacement_pending.validation_revision_id,
                            deprecate_reason.clone(),
                        )
                        .await
                        .unwrap(),
                    evertrace_engine::HumanActionOutcome::Applied {
                        ref audit_event_ref,
                        ..
                    } if audit_event_ref == &deprecate_submit_audit
                ));
                assert_eq!(handle.project().await.unwrap(), after_deprecate_submit);
                assert!(matches!(
                    service
                        .submit_support_deprecate(
                            RequestId::new_v7(),
                            after_deprecate_submit.frontier,
                            replacement_pending.validation_revision_id,
                            deprecate_reason.clone(),
                        )
                        .await
                        .unwrap(),
                    evertrace_engine::HumanActionOutcome::NoDelta { .. }
                ));
                let deprecate_proposal =
                    SemanticCurrentView::from_snapshot(&handle.project().await.unwrap())
                        .unwrap()
                        .proposals
                        .values()
                        .find(|proposal| {
                            proposal.operation == ProposalOperation::Deprecate
                                && proposal.evidence_refs
                                    == [replacement_pending.validation_revision_id.to_string()]
                        })
                        .unwrap()
                        .clone();
                assert_eq!(
                    deprecate_proposal.source_cohort_refs,
                    deprecate_proposal.evidence_refs
                );
                let deprecate_accept_request = RequestId::new_v7();
                assert!(matches!(
                    service
                        .decide_proposal(
                            deprecate_accept_request,
                            handle.project().await.unwrap().frontier,
                            deprecate_proposal.proposal_id,
                            deprecate_proposal.proposal_revision_id,
                            &evertrace_domain::evidence::hex(&deprecate_proposal.fingerprint),
                            HumanProposalDecision::Accept,
                        )
                        .await
                        .unwrap(),
                    evertrace_engine::HumanActionOutcome::Applied { .. }
                ));
                let deprecate_accept_command = handle
                    .committed_command(
                        CommandId::from_uuid(deprecate_accept_request.as_uuid()).unwrap(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                let deprecated = deprecate_accept_command
                    .payloads
                    .iter()
                    .find_map(|payload| match payload {
                        JournalPayload::AtomRecorded(value)
                            if value.parent_revision_id == Some(replacement_atom.revision_id) =>
                        {
                            Some(value.as_ref())
                        }
                        _ => None,
                    })
                    .unwrap();
                assert_eq!(
                    deprecated.lifecycle_status,
                    evertrace_domain::semantic::AtomLifecycleStatus::Deprecated
                );
                assert!(!deprecate_accept_command.payloads.iter().any(|payload| {
                    matches!(
                        payload,
                        JournalPayload::GlobalSupportContractRecorded(value)
                            if value.successor_revision_or_membership_ref
                                == deprecated.revision_id.to_string()
                    )
                }));
                let downstream_pending = deprecate_accept_command
                    .payloads
                    .iter()
                    .find_map(|payload| match payload {
                        JournalPayload::GlobalSupportValidationRecorded(value)
                            if value.support_contract_ref
                                == downstream_valid.support_contract_ref =>
                        {
                            Some(value.as_ref())
                        }
                        _ => None,
                    })
                    .unwrap();
                assert_eq!(
                    downstream_pending.state,
                    GlobalSupportState::RevalidationPending
                );
                assert_eq!(
                    downstream_pending.dependency_generation,
                    downstream_valid.dependency_generation + 1
                );
                assert_eq!(
                    downstream_pending.trigger_refs,
                    [replacement_atom.revision_id.to_string()]
                );
                assert!(deprecate_accept_command.payloads.iter().any(|payload| {
                    matches!(
                        payload,
                        JournalPayload::JobState(job)
                            if job.target_generation == downstream_pending.dependency_generation
                                && job.idempotency_key == format!(
                                    "support:{}:{}",
                                    downstream_pending.support_contract_ref,
                                    downstream_pending.dependency_generation
                                )
                    )
                }));
                (
                    deprecate_submit_request_id,
                    deprecate_submit_frontier,
                    replacement_pending.validation_revision_id,
                    deprecate_reason,
                    deprecate_submit_audit,
                )
            })
            .await;

            let atom_valid_after_pending = GlobalSupportValidationEvent {
                validation_revision_id: RevisionId::new_v7(),
                state: GlobalSupportState::Valid,
                trigger_refs: Vec::new(),
                created_at_us: 7,
                ..atom_pending.as_ref().clone()
            };
            handle
                .commit(
                    JournalCommand::new(
                        CommandId::new_v7(),
                        vec![JournalEventDraft::runtime(
                            7,
                            CONFIG,
                            "s31-test-v1",
                            JournalPayload::GlobalSupportValidationRecorded(Box::new(
                                atom_valid_after_pending.clone(),
                            )),
                        )],
                    )
                    .unwrap(),
                    7,
                )
                .await
                .unwrap();
            assert!(matches!(
                service
                    .submit_support_replacement(
                        RequestId::new_v7(),
                        before_forged,
                        atom_valid_after_pending.validation_revision_id,
                        atom_replacement.clone(),
                    )
                    .await
                    .unwrap(),
                evertrace_engine::HumanActionOutcome::Conflict {
                    current_revision_ref: Some(current_revision_ref)
                } if current_revision_ref
                    == atom_valid_after_pending.validation_revision_id.to_string()
            ));

            let mut global_procedure_draft =
                procedure_draft(repository_id, receipt.source_receipt_id.to_string());
            global_procedure_draft.scope = ProcedureScope::Global;
            global_procedure_draft.support_revision_refs = vec![first_atom.revision_id];
            let view =
                SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
            let ProposalResolution::Revision {
                value: global_procedure_proposal,
                command: global_procedure_submit,
            } = proposals
                .submit(
                    &view,
                    proposal_context(7),
                    SubmitProposalRequest {
                        target_kind: ProposalTargetKind::Procedure,
                        target_id: None,
                        base_revision_id: None,
                        operation: ProposalOperation::Create,
                        payload: ProposalPayload::Procedure(Box::new(
                            ProcedureProposalPayload::Create {
                                draft: global_procedure_draft,
                            },
                        )),
                        evidence_refs: vec![receipt.source_receipt_id.to_string()],
                        source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                        eligibility: ProposalEligibility::ManualRequired,
                        created_by: ProposalCreatedBy::Agent,
                    },
                )
                .unwrap()
            else {
                panic!("global procedure proposal must be new")
            };
            handle.commit(global_procedure_submit, 7).await.unwrap();
            let global_procedure_accept = RequestId::new_v7();
            let frontier = handle.project().await.unwrap().frontier;
            assert!(matches!(
                service
                    .decide_proposal(
                        global_procedure_accept,
                        frontier,
                        global_procedure_proposal.proposal_id,
                        global_procedure_proposal.proposal_revision_id,
                        &evertrace_domain::evidence::hex(&global_procedure_proposal.fingerprint),
                        HumanProposalDecision::Accept,
                    )
                    .await
                    .unwrap(),
                evertrace_engine::HumanActionOutcome::Applied { .. }
            ));
            let global_procedure_accept_command = handle
                .committed_command(CommandId::from_uuid(global_procedure_accept.as_uuid()).unwrap())
                .await
                .unwrap()
                .unwrap();
            let global_procedure_valid = global_procedure_accept_command
                .payloads
                .iter()
                .find_map(|payload| match payload {
                    JournalPayload::GlobalSupportValidationRecorded(value) => Some(value.as_ref()),
                    _ => None,
                })
                .unwrap();
            let procedure_pending_payloads = mark_support_pending(
                global_procedure_valid,
                vec!["support:procedure-edit".into()],
                CONFIG,
                9,
            )
            .unwrap();
            let procedure_pending = procedure_pending_payloads
                .iter()
                .find_map(|payload| match payload {
                    JournalPayload::GlobalSupportValidationRecorded(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap();
            handle
                .commit(
                    JournalCommand::new(
                        CommandId::new_v7(),
                        procedure_pending_payloads
                            .into_iter()
                            .map(|payload| {
                                JournalEventDraft::runtime(9, CONFIG, "s31-test-v1", payload)
                            })
                            .collect(),
                    )
                    .unwrap(),
                    9,
                )
                .await
                .unwrap();
            let procedure_support_frontier = handle.project().await.unwrap().frontier;
            let procedure_support_detail = service
                .detail(
                    HumanSurface::Inbox,
                    &format!(
                        "object:atom:global_support_validation:{}",
                        procedure_pending.validation_revision_id
                    ),
                    procedure_support_frontier,
                    Some(&procedure_pending.validation_revision_id.to_string()),
                )
                .await
                .unwrap()
                .unwrap();
            let mut procedure_replacement = procedure_support_detail.items[0]
                .support_detail
                .as_ref()
                .unwrap()
                .initial_replacement_payload
                .as_ref()
                .unwrap()
                .as_ref()
                .clone();
            let ProposalPayload::Procedure(procedure_payload) = &mut procedure_replacement else {
                unreachable!()
            };
            let ProcedureProposalPayload::Replace { draft } = procedure_payload.as_mut() else {
                unreachable!()
            };
            draft.title = "Corrected global support procedure".into();
            let procedure_replacement_outcome = service
                .submit_support_replacement(
                    RequestId::new_v7(),
                    procedure_support_frontier,
                    procedure_pending.validation_revision_id,
                    procedure_replacement,
                )
                .await
                .unwrap();
            let evertrace_engine::HumanActionOutcome::Applied {
                current_revision_ref: procedure_replacement_revision,
                ..
            } = procedure_replacement_outcome
            else {
                panic!("procedure support replacement must apply")
            };
            let procedure_replacement_revision = procedure_replacement_revision
                .parse::<RevisionId>()
                .unwrap();
            let procedure_replacement_proposal =
                SemanticCurrentView::from_snapshot(&handle.project().await.unwrap())
                    .unwrap()
                    .proposal_revisions[&procedure_replacement_revision]
                    .clone();
            assert_eq!(
                procedure_replacement_proposal.evidence_refs,
                [procedure_pending.validation_revision_id.to_string()]
            );
            assert!(matches!(
                procedure_replacement_proposal.payload,
                ProposalPayload::Procedure(payload)
                    if matches!(payload.as_ref(), ProcedureProposalPayload::Replace { .. })
            ));
            Box::new((
                deprecate_submit_request_id,
                deprecate_submit_frontier,
                deprecate_validation_revision_id,
                deprecate_reason,
                deprecate_submit_audit,
            ))
        })
    }
    let deprecate_replay = prove_support_replacement(
        &handle,
        &service,
        &proposals,
        &first_atom,
        repository_id,
        &receipt,
        &observation,
    )
    .await;

    let mut reviewed_edit_draft = atom_draft(repository_id, &receipt, &observation);
    reviewed_edit_draft.value.text = "reviewed text before edit".into();
    reviewed_edit_draft.provenance = first_atom.provenance.clone();
    reviewed_edit_draft.source_observation_refs = first_atom.source_observation_refs.clone();
    reviewed_edit_draft.evidence_refs = first_atom.evidence_refs.clone();
    reviewed_edit_draft.supersedes_revision_refs = first_atom.supersedes_revision_refs.clone();
    reviewed_edit_draft.supports_revision_refs = first_atom.supports_revision_refs.clone();
    reviewed_edit_draft.contradicts_revision_refs = first_atom.contradicts_revision_refs.clone();
    let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: edit_proposal,
        command: edit_submit,
    } = proposals
        .submit(
            &view,
            proposal_context(3),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: Some(ProposalTargetId::Atom(first_atom.atom_id)),
                base_revision_id: Some(first_atom.revision_id),
                operation: ProposalOperation::Replace,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Replace {
                    draft: reviewed_edit_draft.clone(),
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("edit source proposal must be new")
    };
    handle.commit(edit_submit, 3).await.unwrap();
    let edit_frontier = handle.project().await.unwrap().frontier;
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                edit_frontier,
                edit_proposal.proposal_id,
                edit_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&edit_proposal.fingerprint),
                HumanProposalDecision::EditAndAccept(Box::new(edit_proposal.payload.clone())),
            )
            .await,
        Err(HumanGovernanceError::InvalidInput)
    ));
    let mut edited_draft = reviewed_edit_draft.clone();
    edited_draft.value.text = "edited text accepted atomically".into();
    let edited_payload = ProposalPayload::Atom(Box::new(AtomProposalPayload::Replace {
        draft: edited_draft.clone(),
    }));
    let mut forged_payload = edited_payload.clone();
    let ProposalPayload::Atom(forged_atom) = &mut forged_payload else {
        unreachable!()
    };
    let AtomProposalPayload::Replace { draft } = forged_atom.as_mut() else {
        unreachable!()
    };
    draft.source_observation_refs.clear();
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                edit_frontier,
                edit_proposal.proposal_id,
                edit_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&edit_proposal.fingerprint),
                HumanProposalDecision::EditAndAccept(Box::new(forged_payload)),
            )
            .await,
        Err(HumanGovernanceError::InvalidInput)
    ));
    let mut missing_proof_payload = edited_payload.clone();
    let ProposalPayload::Atom(missing_proof_atom) = &mut missing_proof_payload else {
        unreachable!()
    };
    let AtomProposalPayload::Replace { draft } = missing_proof_atom.as_mut() else {
        unreachable!()
    };
    draft.evidence_refs.clear();
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                edit_frontier,
                edit_proposal.proposal_id,
                edit_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&edit_proposal.fingerprint),
                HumanProposalDecision::EditAndAccept(Box::new(missing_proof_payload)),
            )
            .await,
        Err(HumanGovernanceError::InvalidInput)
    ));
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                edit_frontier - 1,
                edit_proposal.proposal_id,
                edit_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&edit_proposal.fingerprint),
                HumanProposalDecision::EditAndAccept(Box::new(edited_payload.clone())),
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Conflict { .. }
    ));
    let edit_candidate = make_edit_candidate(&edit_proposal, edited_payload.clone(), 4);
    let edit_canonical = edit_proposal.edit_intent_toml(&edit_candidate).unwrap();
    assert!(
        RevisionProposal::parse_edit_intent_toml(&format!("{edit_canonical}unknown_field = 1\n"))
            .is_err()
    );
    let mut forged_cohort_candidate = edit_candidate.clone();
    forged_cohort_candidate.source_cohort_refs = vec![RevisionId::new_v7().to_string()];
    forged_cohort_candidate.source_cohort_hash = forged_cohort_candidate
        .recompute_source_cohort_hash()
        .unwrap();
    forged_cohort_candidate.fingerprint = forged_cohort_candidate.recompute_fingerprint().unwrap();
    assert!(
        edit_proposal
            .validate_edit_candidate(&forged_cohort_candidate)
            .is_err()
    );
    let failed_edit_candidate = make_edit_candidate(&edit_proposal, edited_payload.clone(), 4);
    let failed_edit_canonical = edit_proposal
        .edit_intent_toml(&failed_edit_candidate)
        .unwrap();
    let failed_edit_request = RequestId::new_v7();
    let failed_command_id = CommandId::from_uuid(failed_edit_request.as_uuid()).unwrap();
    let mut capture = evertrace_capture::CaptureRuntime::open(runtime.clone()).unwrap();
    let failed_isolated = capture
        .capture_isolated(
            isolated_acceptance_input(
                &edit_proposal,
                &failed_edit_canonical,
                task_id,
                repository_id,
            ),
            failed_command_id,
            &format!("tui-{}", edit_proposal.proposal_id.as_uuid().hyphenated()),
        )
        .unwrap();
    let failed_edit_path = failed_isolated.segment.path().to_path_buf();
    drop(failed_isolated);
    handle
        .commit(
            JournalCommand::new(
                failed_command_id,
                vec![JournalEventDraft::runtime(
                    4,
                    CONFIG,
                    "s31-test-v1",
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::ObjectsProjection,
                        target_id: "edit-commit-conflict".into(),
                        algorithm_revision: "s31-test-v1".into(),
                        source_watermark: 1,
                    }),
                )],
            )
            .unwrap(),
            4,
        )
        .await
        .unwrap();
    assert!(matches!(
        service
            .decide_proposal(
                failed_edit_request,
                handle.project().await.unwrap().frontier,
                edit_proposal.proposal_id,
                edit_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&edit_proposal.fingerprint),
                HumanProposalDecision::EditAndAccept(Box::new(edited_payload.clone())),
            )
            .await,
        Err(HumanGovernanceError::Store)
    ));
    assert!(failed_edit_path.exists());
    let failed_spool =
        DurableSpool::open_read_only(runtime.spool_dir.clone(), runtime.spool_limits().unwrap())
            .unwrap();
    let failed_segment = failed_spool
        .isolated_segments(16)
        .unwrap()
        .into_iter()
        .find(|segment| segment.path() == failed_edit_path)
        .unwrap();
    failed_spool.acknowledge_segment(failed_segment, 1).unwrap();
    let edit_request = RequestId::new_v7();
    let mut capture = evertrace_capture::CaptureRuntime::open(runtime.clone()).unwrap();
    let isolated = capture
        .capture_isolated(
            isolated_acceptance_input(&edit_proposal, &edit_canonical, task_id, repository_id),
            CommandId::from_uuid(edit_request.as_uuid()).unwrap(),
            &format!("tui-{}", edit_proposal.proposal_id.as_uuid().hyphenated()),
        )
        .unwrap();
    let edit_sealed_path = isolated.segment.path().to_path_buf();
    let edit_sealed_bytes = std::fs::read(&edit_sealed_path).unwrap();
    drop(isolated);
    assert!(matches!(
        service
            .decide_proposal(
                edit_request,
                handle.project().await.unwrap().frontier,
                edit_proposal.proposal_id,
                edit_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&edit_proposal.fingerprint),
                HumanProposalDecision::EditAndAccept(Box::new(edited_payload.clone())),
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Applied { .. }
    ));
    assert!(!edit_sealed_path.exists());
    let edit_command = handle
        .committed_command(CommandId::from_uuid(edit_request.as_uuid()).unwrap())
        .await
        .unwrap()
        .unwrap();
    let edit_receipt = edit_command
        .payloads
        .iter()
        .find_map(|payload| match payload {
            JournalPayload::SourceReceiptRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        edit_receipt.source_ref,
        edit_proposal.proposal_id.to_string()
    );
    assert_eq!(
        edit_receipt.source_revision.as_str(),
        edit_proposal.proposal_revision_id.to_string()
    );
    let edit_view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    assert_eq!(
        edit_view.proposals[&edit_proposal.proposal_id].status,
        ProposalStatus::Superseded
    );
    let accepted_edit = &edit_view.proposals[&edit_candidate.proposal_id];
    assert_eq!(accepted_edit.status, ProposalStatus::Accepted);
    let (edited_atom_id, edited_atom_revision_id, _) = accepted_edit
        .acceptance
        .as_ref()
        .unwrap()
        .accepted_atom()
        .unwrap();
    assert_eq!(edited_atom_id, first_atom.atom_id);
    assert_eq!(
        edit_view.atom_revisions[&edited_atom_revision_id]
            .value
            .text,
        edited_draft.value.text
    );
    let retry_frontier = handle.project().await.unwrap().frontier;
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                retry_frontier,
                edit_proposal.proposal_id,
                edit_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&edit_proposal.fingerprint),
                HumanProposalDecision::EditAndAccept(Box::new(edited_payload)),
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::NoDelta { .. }
    ));
    assert_eq!(handle.project().await.unwrap().frontier, retry_frontier);
    let mut restored_edit = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&edit_sealed_path)
        .unwrap();
    restored_edit.write_all(&edit_sealed_bytes).unwrap();
    restored_edit.sync_all().unwrap();
    drop(restored_edit);
    handle.shutdown().await.unwrap();
    writer_task.await.unwrap().unwrap();
    let writer = open_writer(&store).await.unwrap();
    let (handle, writer_task) = spawn_writer(writer, 8).unwrap();
    let service = HumanGovernanceService::with_acceptance(
        handle.clone(),
        CONFIG,
        runtime.clone(),
        GlobalPromotionConfig {
            atom: PromotionLevel::Manual,
            procedure: PromotionLevel::Manual,
            core_membership: PromotionLevel::Manual,
        },
    );
    Box::pin(async {
        let before_deprecate_submit_retry = handle.project().await.unwrap();
        let evertrace_engine::HumanActionOutcome::Applied {
            audit_event_ref: reopened_deprecate_audit,
            ..
        } = service
            .submit_support_deprecate(
                deprecate_replay.0,
                deprecate_replay.1,
                deprecate_replay.2,
                deprecate_replay.3.clone(),
            )
            .await
            .unwrap()
        else {
            panic!("committed support deprecate must replay after reopen")
        };
        assert_eq!(reopened_deprecate_audit, deprecate_replay.4);
        assert_eq!(
            handle.project().await.unwrap(),
            before_deprecate_submit_retry
        );
    })
    .await;
    let before_edit_reconcile = handle.project().await.unwrap();
    service.reconcile_reserved_once().await.unwrap();
    let after_edit_reconcile = handle.project().await.unwrap();
    assert_eq!(
        after_edit_reconcile.frontier,
        before_edit_reconcile.frontier
    );
    assert_eq!(
        after_edit_reconcile.rows.len(),
        before_edit_reconcile.rows.len()
    );
    assert!(!edit_sealed_path.exists());
    let first_atom = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap())
        .unwrap()
        .atom_revisions[&edited_atom_revision_id]
        .clone();

    let mut second_draft = atom_draft(repository_id, &receipt, &observation);
    second_draft.value.text = "second merge input".into();
    let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: second_atom_proposal,
        command: second_atom_submit,
    } = proposals
        .submit(
            &view,
            proposal_context(2),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                    draft: second_draft,
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("second atom proposal must be new")
    };
    handle.commit(second_atom_submit, 2).await.unwrap();
    let second_atom_request = RequestId::new_v7();
    assert!(matches!(
        service
            .decide_proposal(
                second_atom_request,
                handle.project().await.unwrap().frontier,
                second_atom_proposal.proposal_id,
                second_atom_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&second_atom_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Applied { .. }
    ));
    let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let second_atom_revision = view.proposals[&second_atom_proposal.proposal_id]
        .acceptance
        .as_ref()
        .unwrap()
        .accepted_atom()
        .unwrap()
        .1;
    let second_atom = view.atom_revisions[&second_atom_revision].clone();
    let mut merged_revision_refs = vec![first_atom.revision_id, second_atom_revision];
    merged_revision_refs.sort();
    let mut merge_draft = atom_draft(repository_id, &receipt, &observation);
    merge_draft.value = first_atom.value.clone();
    merge_draft.source_observation_refs = first_atom.source_observation_refs.clone();
    merge_draft.evidence_refs = first_atom.evidence_refs.clone();
    merge_draft.supports_revision_refs = first_atom.supports_revision_refs.clone();
    merge_draft.contradicts_revision_refs = first_atom.contradicts_revision_refs.clone();
    merge_draft.supersedes_revision_refs = merged_revision_refs.clone();
    let ProposalResolution::Revision {
        value: merge_proposal,
        command: merge_submit,
    } = proposals
        .submit(
            &view,
            proposal_context(2),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: Some(ProposalTargetId::Atom(first_atom.atom_id)),
                base_revision_id: Some(first_atom.revision_id),
                operation: ProposalOperation::Merge,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Merge {
                    draft: merge_draft,
                    merged_revision_refs: merged_revision_refs.clone(),
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("merge proposal must be new")
    };
    handle.commit(merge_submit, 2).await.unwrap();
    let merge_page = service
        .list(HumanSurface::Inbox, None, None, HUMAN_PAGE_LIMIT)
        .await
        .unwrap()
        .unwrap();
    let merge_item = merge_page
        .items
        .iter()
        .find(|item| {
            item.proposal
                .as_ref()
                .is_some_and(|proposal| proposal.proposal_id == merge_proposal.proposal_id)
        })
        .unwrap();
    let merge_detail = service
        .detail(
            HumanSurface::Inbox,
            &merge_item.stable_key,
            merge_page.frontier,
            merge_item.revision_ref.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(merge_detail.items[0]
        .proposal_review
        .as_ref()
        .is_some_and(|review| !review.plain_accept_eligible
            && review.merge_and_accept_eligible));
    let before_plain_merge = handle.project().await.unwrap().frontier;
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                before_plain_merge,
                merge_proposal.proposal_id,
                merge_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&merge_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Unavailable {
            reason: "atomic_plain_acceptance_unavailable"
        }
    ));
    assert_eq!(handle.project().await.unwrap().frontier, before_plain_merge);
    let merge_request = RequestId::new_v7();
    assert!(matches!(
        service
            .decide_proposal(
                merge_request,
                handle.project().await.unwrap().frontier,
                merge_proposal.proposal_id,
                merge_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&merge_proposal.fingerprint),
                HumanProposalDecision::MergeAndAccept,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Applied { .. }
    ));
    let merge_command = handle
        .committed_command(CommandId::from_uuid(merge_request.as_uuid()).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        merge_command
            .payloads
            .iter()
            .any(|payload| matches!(payload, JournalPayload::SourceObservationRecorded(_)))
    );
    assert_eq!(
        merge_command
            .payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::AtomRecorded(_)))
            .count(),
        1
    );
    let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let merged_atom = &view.atoms[&first_atom.atom_id];
    assert_eq!(merged_atom.parent_revision_id, Some(first_atom.revision_id));
    assert_eq!(merged_atom.kind, first_atom.kind);
    assert_eq!(merged_atom.value, first_atom.value);
    assert_eq!(merged_atom.scope, first_atom.scope);
    assert_eq!(
        merged_atom.applicability_expr,
        first_atom.applicability_expr
    );
    assert_eq!(merged_atom.validity_interval, first_atom.validity_interval);
    assert_eq!(merged_atom.supersedes_revision_refs, merged_revision_refs);
    assert_eq!(view.atoms[&second_atom.atom_id], second_atom);

    let mut invalid_draft = atom_draft(repository_id, &receipt, &observation);
    invalid_draft.value.text = "invalid merge".into();
    invalid_draft.supersedes_revision_refs = vec![merged_atom.revision_id];
    let mut invalid_refs = vec![merged_atom.revision_id, second_atom.revision_id];
    invalid_refs.sort();
    let ProposalResolution::Revision {
        value: invalid_merge,
        command: invalid_merge_submit,
    } = proposals
        .submit(
            &view,
            proposal_context(2),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: Some(ProposalTargetId::Atom(merged_atom.atom_id)),
                base_revision_id: Some(merged_atom.revision_id),
                operation: ProposalOperation::Merge,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Merge {
                    draft: invalid_draft,
                    merged_revision_refs: invalid_refs,
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("invalid merge proposal must remain reviewable")
    };
    handle.commit(invalid_merge_submit, 2).await.unwrap();
    let before_invalid = handle.project().await.unwrap().frontier;
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                before_invalid,
                invalid_merge.proposal_id,
                invalid_merge.proposal_revision_id,
                &evertrace_domain::evidence::hex(&invalid_merge.fingerprint),
                HumanProposalDecision::MergeAndAccept,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Unavailable { .. }
    ));
    assert_eq!(handle.project().await.unwrap().frontier, before_invalid);

    let procedure = procedure_draft(repository_id, receipt.source_receipt_id.to_string());
    let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: procedure_proposal,
        command: procedure_submit,
    } = proposals
        .submit(
            &view,
            proposal_context(3),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Procedure,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Create {
                    draft: procedure.clone(),
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("procedure proposal must be new")
    };
    let mut edited_create_draft = procedure.clone();
    edited_create_draft.summary = "edited procedure create".into();
    let procedure_create_edit = make_edit_candidate(
        &procedure_proposal,
        ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Create {
            draft: edited_create_draft,
        })),
        4,
    );
    procedure_proposal
        .validate_edit_candidate(&procedure_create_edit)
        .unwrap();
    drop(procedure_create_edit);
    handle.commit(procedure_submit, 3).await.unwrap();
    let procedure_page = service
        .list(HumanSurface::Inbox, None, None, HUMAN_PAGE_LIMIT)
        .await
        .unwrap()
        .unwrap();
    let procedure_item = procedure_page
        .items
        .iter()
        .find(|item| {
            item.proposal
                .as_ref()
                .is_some_and(|proposal| proposal.proposal_id == procedure_proposal.proposal_id)
        })
        .unwrap();
    assert!(procedure_item.proposal_review.is_none());
    let procedure_detail = service
        .detail(
            HumanSurface::Inbox,
            &procedure_item.stable_key,
            procedure_page.frontier,
            procedure_item.revision_ref.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        procedure_detail.items[0]
            .proposal_review
            .as_ref()
            .is_some_and(|review| review.plain_accept_eligible
                && matches!(&review.proposal.payload, ProposalPayload::Procedure(_)))
    );
    let procedure_frontier = handle.project().await.unwrap().frontier;
    let procedure_request = RequestId::new_v7();
    assert!(matches!(
        service
            .decide_proposal(
                procedure_request,
                procedure_frontier,
                procedure_proposal.proposal_id,
                procedure_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&procedure_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Applied { .. }
    ));
    let procedure_command = handle
        .committed_command(CommandId::from_uuid(procedure_request.as_uuid()).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        procedure_command
            .payloads
            .iter()
            .any(|payload| matches!(payload, JournalPayload::SourceReceiptRecorded(_)))
    );
    assert!(
        procedure_command
            .payloads
            .iter()
            .any(|payload| matches!(payload, JournalPayload::ProcedureRevisionRecorded(_)))
    );
    let procedure_view =
        SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let accepted_procedure = procedure_view.proposals[&procedure_proposal.proposal_id]
        .acceptance
        .as_ref()
        .unwrap();
    let (procedure_id, procedure_revision_id) = match accepted_procedure.accepted_target {
        evertrace_domain::semantic::AcceptedProposalTarget::Procedure {
            procedure_id,
            procedure_revision_id,
            ..
        } => (procedure_id, procedure_revision_id),
        _ => panic!("procedure target expected"),
    };

    let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let mut ack_loss_draft = atom_draft(repository_id, &receipt, &observation);
    ack_loss_draft.value.text = "preserve ack-loss evidence".into();
    let ProposalResolution::Revision {
        value: identical_proposal,
        command: identical_submit,
    } = proposals
        .submit(
            &view,
            proposal_context(4),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Procedure,
                target_id: Some(ProposalTargetId::Procedure(procedure_id)),
                base_revision_id: Some(procedure_revision_id),
                operation: ProposalOperation::Replace,
                payload: ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Replace {
                    draft: procedure,
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("identical replacement proposal must be new")
    };
    handle.commit(identical_submit, 4).await.unwrap();
    let before_identical = handle.project().await.unwrap();
    assert!(before_identical.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("procedure_revision")
            && row.object_id.as_deref() == Some(&procedure_id.to_string())
            && row.current_revision_id.as_deref() == Some(&procedure_revision_id.to_string())
            && row.publication_state.as_deref() == Some("active_probationary")
    }));
    let existing_procedure_rows = before_identical
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("procedure_revision"))
        .count();
    let identical_request = RequestId::new_v7();
    assert!(matches!(
        service
            .decide_proposal(
                identical_request,
                before_identical.frontier,
                identical_proposal.proposal_id,
                identical_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&identical_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Applied { .. }
    ));
    let identical_command = handle
        .committed_command(CommandId::from_uuid(identical_request.as_uuid()).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(!identical_command.payloads.iter().any(|payload| matches!(
        payload,
        JournalPayload::ProcedureRevisionRecorded(_) | JournalPayload::ProcedureStateRecorded(_)
    )));
    assert_eq!(
        handle
            .project()
            .await
            .unwrap()
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("procedure_revision"))
            .count(),
        existing_procedure_rows
    );

    let (
        procedure_edit_original_id,
        procedure_edit_candidate_id,
        edited_procedure_id,
        accepted_procedure_revision_id,
    ) = Box::pin(async {
        let base_procedure = procedure_command
            .payloads
            .iter()
            .find_map(|payload| match payload {
                JournalPayload::ProcedureRevisionRecorded(value) => Some(value.as_ref().clone()),
                _ => None,
            })
            .unwrap();
        let mut reviewed_procedure_draft = base_procedure.draft.clone();
        reviewed_procedure_draft.summary = "reviewed procedure before edit".into();
        let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
        let ProposalResolution::Revision {
            value: procedure_edit_original,
            command: procedure_edit_submit,
        } = proposals
            .submit(
                &view,
                proposal_context(11),
                SubmitProposalRequest {
                    target_kind: ProposalTargetKind::Procedure,
                    target_id: Some(ProposalTargetId::Procedure(base_procedure.procedure_id)),
                    base_revision_id: Some(base_procedure.revision_id),
                    operation: ProposalOperation::Replace,
                    payload: ProposalPayload::Procedure(Box::new(
                        ProcedureProposalPayload::Replace {
                            draft: reviewed_procedure_draft.clone(),
                        },
                    )),
                    evidence_refs: vec![receipt.source_receipt_id.to_string()],
                    source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                    eligibility: ProposalEligibility::ManualRequired,
                    created_by: ProposalCreatedBy::Agent,
                },
            )
            .unwrap()
        else {
            panic!("procedure edit original must be new")
        };
        handle.commit(procedure_edit_submit, 11).await.unwrap();
        let mut edited_procedure_draft = reviewed_procedure_draft;
        edited_procedure_draft.summary = "procedure edited and accepted atomically".into();
        let edited_procedure_payload =
            ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Replace {
                draft: edited_procedure_draft.clone(),
            }));
        let procedure_edit_candidate = make_edit_candidate(
            &procedure_edit_original,
            edited_procedure_payload.clone(),
            12,
        );
        let mut forged_procedure_candidate = procedure_edit_candidate.clone();
        let ProposalPayload::Procedure(forged_payload) = &mut forged_procedure_candidate.payload
        else {
            unreachable!()
        };
        let ProcedureProposalPayload::Replace { draft } = forged_payload.as_mut() else {
            unreachable!()
        };
        draft
            .evidence_refs
            .push("source:forged-procedure-edit".into());
        draft.evidence_refs.sort();
        forged_procedure_candidate.fingerprint =
            forged_procedure_candidate.recompute_fingerprint().unwrap();
        assert!(
            procedure_edit_original
                .validate_edit_candidate(&forged_procedure_candidate)
                .is_err()
        );
        let procedure_edit_request = RequestId::new_v7();
        let procedure_edit_intent = procedure_edit_original
            .edit_intent_toml(&procedure_edit_candidate)
            .unwrap();
        let mut capture = evertrace_capture::CaptureRuntime::open(runtime.clone()).unwrap();
        drop(
            capture
                .capture_isolated(
                    isolated_acceptance_input(
                        &procedure_edit_original,
                        &procedure_edit_intent,
                        task_id,
                        repository_id,
                    ),
                    CommandId::from_uuid(procedure_edit_request.as_uuid()).unwrap(),
                    &format!(
                        "tui-{}",
                        procedure_edit_original.proposal_id.as_uuid().hyphenated()
                    ),
                )
                .unwrap(),
        );
        assert!(matches!(
            service
                .decide_proposal(
                    procedure_edit_request,
                    handle.project().await.unwrap().frontier,
                    procedure_edit_original.proposal_id,
                    procedure_edit_original.proposal_revision_id,
                    &evertrace_domain::evidence::hex(&procedure_edit_original.fingerprint),
                    HumanProposalDecision::EditAndAccept(Box::new(edited_procedure_payload)),
                )
                .await
                .unwrap(),
            evertrace_engine::HumanActionOutcome::Applied { .. }
        ));
        let procedure_edit_command = handle
            .committed_command(CommandId::from_uuid(procedure_edit_request.as_uuid()).unwrap())
            .await
            .unwrap()
            .unwrap();
        let accepted_procedure_edit = procedure_edit_command
            .payloads
            .iter()
            .find_map(|payload| match payload {
                JournalPayload::RevisionProposalRecorded(value)
                    if value.proposal_id == procedure_edit_candidate.proposal_id
                        && value.status == ProposalStatus::Accepted =>
                {
                    Some(value.as_ref().clone())
                }
                _ => None,
            })
            .unwrap();
        assert!(procedure_edit_command.payloads.iter().any(|payload| {
            matches!(payload, JournalPayload::RevisionProposalRecorded(value)
            if value.proposal_id == procedure_edit_original.proposal_id
                && value.status == ProposalStatus::Superseded)
        }));
        let accepted_procedure_revision_id = match accepted_procedure_edit
            .acceptance
            .as_ref()
            .unwrap()
            .accepted_target
        {
            evertrace_domain::semantic::AcceptedProposalTarget::Procedure {
                procedure_id: accepted_id,
                procedure_revision_id,
                ..
            } if accepted_id == base_procedure.procedure_id => procedure_revision_id,
            _ => panic!("edited procedure target expected"),
        };
        assert!(procedure_edit_command.payloads.iter().any(|payload| {
            matches!(payload, JournalPayload::ProcedureRevisionRecorded(value)
            if value.procedure_id == base_procedure.procedure_id
                && value.revision_id == accepted_procedure_revision_id
                && value.draft == edited_procedure_draft)
        }));
        (
            procedure_edit_original.proposal_id,
            procedure_edit_candidate.proposal_id,
            base_procedure.procedure_id,
            accepted_procedure_revision_id,
        )
    })
    .await;

    let current_procedure = procedure_command
        .payloads
        .iter()
        .find_map(|payload| match payload {
            JournalPayload::ProcedureRevisionRecorded(value) => Some(value.as_ref().clone()),
            _ => None,
        })
        .unwrap();
    let mut suspended_draft = current_procedure.draft.clone();
    suspended_draft.title = "Suspend an independent reviewed procedure".into();
    let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: suspended_create_proposal,
        command: suspended_create_submit,
    } = proposals
        .submit(
            &view,
            proposal_context(5),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Procedure,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Create {
                    draft: suspended_draft,
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("independent procedure proposal must be new")
    };
    handle.commit(suspended_create_submit, 5).await.unwrap();
    let suspended_create_request = RequestId::new_v7();
    assert!(matches!(
        service
            .decide_proposal(
                suspended_create_request,
                handle.project().await.unwrap().frontier,
                suspended_create_proposal.proposal_id,
                suspended_create_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&suspended_create_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Applied { .. }
    ));
    let suspended_create_command = handle
        .committed_command(CommandId::from_uuid(suspended_create_request.as_uuid()).unwrap())
        .await
        .unwrap()
        .unwrap();
    let current_procedure = suspended_create_command
        .payloads
        .iter()
        .find_map(|payload| match payload {
            JournalPayload::ProcedureRevisionRecorded(value) => Some(value.as_ref().clone()),
            _ => None,
        })
        .unwrap();
    let suspended_procedure_id = current_procedure.procedure_id;
    let suspended_procedure_revision_id = current_procedure.revision_id;
    let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: suspended_proposal,
        command: suspended_submit,
    } = proposals
        .submit(
            &view,
            proposal_context(6),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Procedure,
                target_id: Some(ProposalTargetId::Procedure(suspended_procedure_id)),
                base_revision_id: Some(suspended_procedure_revision_id),
                operation: ProposalOperation::Replace,
                payload: ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Replace {
                    draft: current_procedure.draft.clone(),
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("suspended-target proposal must be new")
    };
    handle.commit(suspended_submit, 6).await.unwrap();
    let (suspended_receipt, suspended_observation) =
        typed_tui_source("suspended", &suspended_proposal, task_id, repository_id);
    let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let ProcedureAcceptanceResolution::AcceptedExisting {
        command: stale_acceptance,
        ..
    } = accept_procedure(
        &view,
        ProposalCommandContext {
            command_id: CommandId::new_v7(),
            occurred_at_us: 8,
            effective_config_hash: CONFIG,
            algorithm_revision: "s31-test-v1".into(),
        },
        suspended_proposal.proposal_id,
        ProcedureAcceptanceContext::Manual(AtomAcceptanceContext::RepositoryTui {
            observation: Box::new(suspended_observation.clone()),
            receipt: Box::new(suspended_receipt.clone()),
        }),
        Some(&current_procedure),
        Some(evertrace_domain::procedure::ProcedurePublicationState::ActiveProbationary),
        &GlobalPromotionConfig {
            atom: PromotionLevel::Manual,
            procedure: PromotionLevel::Manual,
            core_membership: PromotionLevel::Manual,
        },
    )
    .unwrap()
    else {
        panic!("active exact target must build proposal-only acceptance")
    };
    let mut support_adulterated_events = vec![
        JournalPayload::SourceReceiptRecorded(Box::new(suspended_receipt.clone())),
        JournalPayload::SourceObservationRecorded(Box::new(suspended_observation.clone())),
        JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
            source_instance_id: suspended_receipt.source_instance_id.clone(),
            source_revision: suspended_receipt.source_revision.clone(),
            source_sequence: 1,
            confirmed_prefix_digest: None,
        }),
        JournalPayload::GlobalSupportValidationRecorded(Box::new(GlobalSupportValidationEvent {
            validation_revision_id: RevisionId::new_v7(),
            support_contract_ref: RevisionId::new_v7(),
            successor_ref: suspended_procedure_revision_id.to_string(),
            dependency_generation: 1,
            state: GlobalSupportState::RevalidationPending,
            provenance_degraded: false,
            surviving_support_refs: Vec::new(),
            invalid_or_missing_refs: Vec::new(),
            trigger_refs: Vec::new(),
            validator_revision: 1,
            created_at_us: 7,
        })),
    ]
    .into_iter()
    .map(|payload| JournalEventDraft::runtime(7, CONFIG, "s31-test-v1", payload))
    .collect::<Vec<_>>();
    support_adulterated_events.extend(stale_acceptance.events().iter().cloned());
    let support_adulterated =
        JournalCommand::new(stale_acceptance.command_id(), support_adulterated_events).unwrap();
    let before_support_adulteration = handle.project().await.unwrap().frontier;
    assert!(handle.commit(support_adulterated, 7).await.is_err());
    assert_eq!(
        handle.project().await.unwrap().frontier,
        before_support_adulteration
    );
    let suspended = publication_event(
        &current_procedure,
        evertrace_domain::procedure::ProcedurePublicationState::ActiveProbationary,
        evertrace_domain::procedure::ProcedurePublicationState::Suspended,
        ProcedureStateReason::Manual,
        None,
        vec![receipt.source_receipt_id.to_string()],
        7,
    )
    .unwrap();
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    7,
                    CONFIG,
                    "s31-test-v1",
                    JournalPayload::ProcedureStateRecorded(Box::new(suspended)),
                )],
            )
            .unwrap(),
            7,
        )
        .await
        .unwrap();
    let mut stale_events = vec![
        JournalPayload::SourceReceiptRecorded(Box::new(suspended_receipt.clone())),
        JournalPayload::SourceObservationRecorded(Box::new(suspended_observation.clone())),
        JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
            source_instance_id: suspended_receipt.source_instance_id.clone(),
            source_revision: suspended_receipt.source_revision.clone(),
            source_sequence: 1,
            confirmed_prefix_digest: None,
        }),
    ]
    .into_iter()
    .map(|payload| JournalEventDraft::runtime(8, CONFIG, "s31-test-v1", payload))
    .collect::<Vec<_>>();
    stale_events.extend(stale_acceptance.events().iter().cloned());
    let stale_command = JournalCommand::new(stale_acceptance.command_id(), stale_events).unwrap();
    let before_stale_acceptance = handle.project().await.unwrap().frontier;
    assert!(handle.commit(stale_command, 8).await.is_err());
    assert_eq!(
        handle.project().await.unwrap().frontier,
        before_stale_acceptance
    );

    let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: core_proposal,
        command: core_submit,
    } = proposals
        .submit(
            &view,
            proposal_context(10),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::CoreMembership,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::CoreMembership(Box::new(
                    CoreMembershipProposalPayload::Create {
                        atom_revision_id: accepted_atom_revision,
                        scope_identity: CoreScopeIdentity::Repository(repository_id),
                    },
                )),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("core proposal must be new")
    };
    handle.commit(core_submit, 10).await.unwrap();
    let core_page = service
        .list(HumanSurface::Inbox, None, None, HUMAN_PAGE_LIMIT)
        .await
        .unwrap()
        .unwrap();
    let core_item = core_page
        .items
        .iter()
        .find(|item| {
            item.proposal
                .as_ref()
                .is_some_and(|proposal| proposal.proposal_id == core_proposal.proposal_id)
        })
        .unwrap();
    assert!(core_item.proposal_review.is_none());
    let core_detail = service
        .detail(
            HumanSurface::Inbox,
            &core_item.stable_key,
            core_page.frontier,
            core_item.revision_ref.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        core_detail.items[0]
            .proposal_review
            .as_ref()
            .is_some_and(|review| review.plain_accept_eligible
                && matches!(&review.proposal.payload, ProposalPayload::CoreMembership(_)))
    );
    let core_frontier = handle.project().await.unwrap().frontier;
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                core_frontier,
                core_proposal.proposal_id,
                core_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&core_proposal.fingerprint),
                HumanProposalDecision::EditAndAccept(Box::new(core_proposal.payload.clone())),
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Unavailable {
            reason: "atomic_edit_and_accept_unavailable"
        }
    ));
    assert_eq!(handle.project().await.unwrap().frontier, core_frontier);
    let core_request = RequestId::new_v7();
    assert!(matches!(
        service
            .decide_proposal(
                core_request,
                core_frontier,
                core_proposal.proposal_id,
                core_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&core_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Applied { .. }
    ));
    let core_command = handle
        .committed_command(CommandId::from_uuid(core_request.as_uuid()).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        core_command
            .payloads
            .iter()
            .any(|payload| matches!(payload, JournalPayload::SourceReceiptRecorded(_)))
    );
    assert!(
        core_command
            .payloads
            .iter()
            .any(|payload| matches!(payload, JournalPayload::CoreMembershipRecorded(_)))
    );
    let core_valid = core_command
        .payloads
        .iter()
        .find_map(|payload| match payload {
            JournalPayload::GlobalSupportValidationRecorded(value) => Some(value.clone()),
            _ => None,
        })
        .unwrap();
    fn prove_core_support_replacement_unavailable<'a>(
        handle: &'a evertrace_engine::WriterHandle,
        service: &'a HumanGovernanceService,
        current: &'a GlobalSupportValidationEvent,
        edited_payload: ProposalPayload,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
        Box::pin(async move {
            let payloads =
                mark_support_pending(current, vec!["support:core-edit".into()], CONFIG, 11)
                    .unwrap();
            let pending = payloads
                .iter()
                .find_map(|payload| match payload {
                    JournalPayload::GlobalSupportValidationRecorded(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap();
            handle
                .commit(
                    JournalCommand::new(
                        CommandId::new_v7(),
                        payloads
                            .into_iter()
                            .map(|payload| {
                                JournalEventDraft::runtime(11, CONFIG, "s31-test-v1", payload)
                            })
                            .collect(),
                    )
                    .unwrap(),
                    11,
                )
                .await
                .unwrap();
            let frontier = handle.project().await.unwrap().frontier;
            let detail = service
                .detail(
                    HumanSurface::Inbox,
                    &format!(
                        "object:atom:global_support_validation:{}",
                        pending.validation_revision_id
                    ),
                    frontier,
                    Some(&pending.validation_revision_id.to_string()),
                )
                .await
                .unwrap()
                .unwrap();
            assert!(
                detail.items[0]
                    .support_detail
                    .as_ref()
                    .is_some_and(|support| support.initial_replacement_payload.is_none())
            );
            assert!(matches!(
                service
                    .submit_support_replacement(
                        RequestId::new_v7(),
                        frontier,
                        pending.validation_revision_id,
                        edited_payload,
                    )
                    .await
                    .unwrap(),
                evertrace_engine::HumanActionOutcome::Unavailable {
                    reason: "support_replacement_target_unavailable"
                }
            ));
            assert_eq!(handle.project().await.unwrap().frontier, frontier);
        })
    }
    prove_core_support_replacement_unavailable(
        &handle,
        &service,
        &core_valid,
        core_proposal.payload.clone(),
    )
    .await;
    let replay_frontier = handle.project().await.unwrap().frontier;
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                replay_frontier,
                core_proposal.proposal_id,
                core_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&core_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::NoDelta { .. }
    ));
    assert_eq!(handle.project().await.unwrap().frontier, replay_frontier);
    assert!(
        std::fs::read_dir(runtime.spool_dir.join("main"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("isolated-tui"))
    );

    let forged_request = RequestId::new_v7();
    let mut capture = evertrace_capture::CaptureRuntime::open(runtime.clone()).unwrap();
    drop(
        capture
            .capture_isolated(
                isolated_acceptance_input(
                    &core_proposal,
                    "forged canonical acceptance payload",
                    task_id,
                    repository_id,
                ),
                CommandId::from_uuid(forged_request.as_uuid()).unwrap(),
                &format!("tui-{}", core_proposal.proposal_id.as_uuid().hyphenated()),
            )
            .unwrap(),
    );
    assert!(service.reconcile_reserved_once().await.is_err());
    let spool =
        DurableSpool::open_read_only(runtime.spool_dir.clone(), runtime.spool_limits().unwrap())
            .unwrap();
    let forged_segments = spool.isolated_segments(16).unwrap();
    assert_eq!(forged_segments.len(), 1);
    for segment in forged_segments {
        spool.acknowledge_segment(segment, 1).unwrap();
    }

    let view = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: ack_loss_proposal,
        command: ack_loss_submit,
    } = proposals
        .submit(
            &view,
            proposal_context(6),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                    draft: ack_loss_draft,
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("ack-loss proposal must be new")
    };
    handle.commit(ack_loss_submit, 6).await.unwrap();
    let ack_request = RequestId::new_v7();
    let canonical = tui_acceptance_event_payload(
        ack_loss_proposal.proposal_id,
        ack_loss_proposal.proposal_revision_id,
        &ack_loss_proposal.fingerprint,
    );
    let mut capture = evertrace_capture::CaptureRuntime::open(runtime.clone()).unwrap();
    let isolated = capture
        .capture_isolated(
            isolated_acceptance_input(&ack_loss_proposal, &canonical, task_id, repository_id),
            CommandId::from_uuid(ack_request.as_uuid()).unwrap(),
            &format!(
                "tui-{}",
                ack_loss_proposal.proposal_id.as_uuid().hyphenated()
            ),
        )
        .unwrap();
    let sealed_path = isolated.segment.path().to_path_buf();
    let sealed_bytes = std::fs::read(&sealed_path).unwrap();
    drop(isolated);
    assert!(matches!(
        service
            .decide_proposal(
                ack_request,
                handle.project().await.unwrap().frontier,
                ack_loss_proposal.proposal_id,
                ack_loss_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&ack_loss_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::NoDelta { .. }
    ));
    assert!(!sealed_path.exists());
    let mut restored = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&sealed_path)
        .unwrap();
    restored.write_all(&sealed_bytes).unwrap();
    restored.sync_all().unwrap();
    drop(restored);

    let inbox = service
        .list(HumanSurface::Inbox, None, None, HUMAN_PAGE_LIMIT)
        .await
        .unwrap()
        .unwrap();
    assert!(!inbox.items.iter().any(|item| {
        item.proposal
            .as_ref()
            .is_some_and(|proposal| proposal.status == ProposalStatus::Accepted)
    }));
    let mut explorer = service
        .list(HumanSurface::Explorer, None, None, HUMAN_PAGE_LIMIT)
        .await
        .unwrap()
        .unwrap();
    let current_atom_proposal_revision =
        SemanticCurrentView::from_snapshot(&handle.project().await.unwrap())
            .unwrap()
            .proposals[&atom_proposal.proposal_id]
            .proposal_revision_id;
    let proposal_id_ref = atom_proposal.proposal_id.to_string();
    let proposal_revision_ref = current_atom_proposal_revision.to_string();
    while !explorer.items.iter().any(|item| {
        item.object_ref.as_deref() == Some(proposal_id_ref.as_str())
            && item.revision_ref.as_deref() == Some(proposal_revision_ref.as_str())
    }) {
        let cursor = explorer.next_cursor.clone().unwrap();
        explorer = service
            .list(
                HumanSurface::Explorer,
                Some(explorer.frontier),
                Some(cursor.as_str()),
                HUMAN_PAGE_LIMIT,
            )
            .await
            .unwrap()
            .unwrap();
    }
    let proposal_item = explorer
        .items
        .iter()
        .find(|item| {
            item.object_ref.as_deref() == Some(proposal_id_ref.as_str())
                && item.revision_ref.as_deref() == Some(proposal_revision_ref.as_str())
        })
        .unwrap();
    let proposal_related = service
        .related(HumanRelatedRequest {
            relation: HumanRelationKind::ProposalEvidence,
            source_stable_key: &proposal_item.stable_key,
            expected_source_revision_ref: proposal_item.revision_ref.as_deref().unwrap(),
            expected_frontier: explorer.frontier,
            after: None,
            limit: HUMAN_PAGE_LIMIT,
        })
        .await
        .unwrap()
        .unwrap();
    assert!(proposal_related.items.iter().any(|item| {
        item.object_ref.as_deref() == Some(receipt.source_receipt_id.to_string().as_str())
    }));
    assert!(matches!(
        service
            .related(HumanRelatedRequest {
                relation: HumanRelationKind::SupportDependencies,
                source_stable_key: &proposal_item.stable_key,
                expected_source_revision_ref: proposal_item.revision_ref.as_deref().unwrap(),
                expected_frontier: explorer.frontier,
                after: None,
                limit: HUMAN_PAGE_LIMIT,
            })
            .await,
        Err(HumanGovernanceError::InvalidInput)
    ));
    let mut explorer_items = explorer.items.clone();
    let mut next_cursor = explorer.next_cursor.clone();
    while let Some(after) = next_cursor {
        let next = service
            .list(
                HumanSurface::Explorer,
                Some(explorer.frontier),
                Some(&after),
                HUMAN_PAGE_LIMIT,
            )
            .await
            .unwrap()
            .unwrap();
        next_cursor = next.next_cursor;
        explorer_items.extend(next.items);
    }
    assert!(explorer_items.iter().any(|item| {
        item.category == evertrace_engine::HumanItemCategory::Repository
            && item.object_kind == "repository"
    }));
    assert!(explorer_items.iter().any(|item| {
        item.category == evertrace_engine::HumanItemCategory::Work && item.object_kind == "task"
    }));
    let worktree_item = explorer_items
        .iter()
        .find(|item| item.object_kind == "worktree")
        .unwrap();
    assert!(worktree_item.worktree_detail.is_none());
    let worktree_detail = service
        .detail(
            HumanSurface::Explorer,
            &worktree_item.stable_key,
            explorer.frontier,
            worktree_item.revision_ref.as_deref(),
        )
        .await
        .unwrap()
        .unwrap();
    let [detail] = worktree_detail.items.as_slice() else {
        panic!("worktree detail must contain exactly one current row")
    };
    assert_eq!(detail.worktree_detail.unwrap().worktree_id, worktree_id);
    assert!(detail.recovery_detail.is_none());
    let system = service
        .list(HumanSurface::System, None, None, HUMAN_PAGE_LIMIT)
        .await
        .unwrap()
        .unwrap();
    assert!(system.items.iter().any(|item| {
        matches!(
            item.category,
            evertrace_engine::HumanItemCategory::Runtime
                | evertrace_engine::HumanItemCategory::Projection
        )
    }));
    handle.shutdown().await.unwrap();
    writer_task.await.unwrap().unwrap();
    let reopened = open_writer(&store).await.unwrap();
    let (reopened_handle, reopened_task) = spawn_writer(reopened, 8).unwrap();
    let before_reconcile = reopened_handle.project().await.unwrap();
    let reopened_service = HumanGovernanceService::with_acceptance(
        reopened_handle.clone(),
        CONFIG,
        runtime.clone(),
        GlobalPromotionConfig {
            atom: PromotionLevel::Manual,
            procedure: PromotionLevel::Manual,
            core_membership: PromotionLevel::Manual,
        },
    );
    reopened_service.reconcile_reserved_once().await.unwrap();
    let rebuilt = reopened_handle.project().await.unwrap();
    assert_eq!(rebuilt.frontier, before_reconcile.frontier);
    assert_eq!(rebuilt.rows.len(), before_reconcile.rows.len());
    assert!(!sealed_path.exists());
    assert!(!edit_sealed_path.exists());
    let rebuilt_view = SemanticCurrentView::from_snapshot(&rebuilt).unwrap();
    assert_eq!(
        rebuilt_view.proposals[&atom_proposal.proposal_id].status,
        ProposalStatus::Accepted
    );
    assert_eq!(
        rebuilt_view.proposals[&procedure_proposal.proposal_id].status,
        ProposalStatus::Accepted
    );
    assert_eq!(
        rebuilt_view.proposals[&core_proposal.proposal_id].status,
        ProposalStatus::Accepted
    );
    assert_eq!(
        rebuilt_view.proposals[&ack_loss_proposal.proposal_id].status,
        ProposalStatus::Accepted
    );
    assert_eq!(
        rebuilt_view.proposals[&edit_proposal.proposal_id].status,
        ProposalStatus::Superseded
    );
    assert_eq!(
        rebuilt_view.proposals[&edit_candidate.proposal_id].status,
        ProposalStatus::Accepted
    );
    assert_eq!(
        rebuilt_view.proposals[&procedure_edit_original_id].status,
        ProposalStatus::Superseded
    );
    assert_eq!(
        rebuilt_view.proposals[&procedure_edit_candidate_id].status,
        ProposalStatus::Accepted
    );
    assert!(rebuilt.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("procedure_revision")
            && row.object_id.as_deref() == Some(&edited_procedure_id.to_string())
            && row.current_revision_id.as_deref()
                == Some(&accepted_procedure_revision_id.to_string())
            && row.payload_json.as_deref().is_some_and(|payload| {
                matches!(
                    serde_json::from_str::<JournalPayload>(payload),
                    Ok(JournalPayload::ProcedureRevisionRecorded(value))
                        if value.draft.summary == "procedure edited and accepted atomically"
                )
            })
    }));

    let current_atom = rebuilt_view.atoms[&first_atom.atom_id].clone();
    let mut wrong_source_reviewed_draft = atom_draft(repository_id, &receipt, &observation);
    wrong_source_reviewed_draft.value.text = "wrong-source reviewed text".into();
    wrong_source_reviewed_draft.provenance = current_atom.provenance.clone();
    wrong_source_reviewed_draft.source_observation_refs =
        current_atom.source_observation_refs.clone();
    wrong_source_reviewed_draft.evidence_refs = current_atom.evidence_refs.clone();
    wrong_source_reviewed_draft.supersedes_revision_refs =
        current_atom.supersedes_revision_refs.clone();
    wrong_source_reviewed_draft.supports_revision_refs =
        current_atom.supports_revision_refs.clone();
    wrong_source_reviewed_draft.contradicts_revision_refs =
        current_atom.contradicts_revision_refs.clone();
    let ProposalResolution::Revision {
        value: wrong_source_original,
        command: wrong_source_original_command,
    } = proposals
        .submit(
            &rebuilt_view,
            proposal_context(20),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: Some(ProposalTargetId::Atom(current_atom.atom_id)),
                base_revision_id: Some(current_atom.revision_id),
                operation: ProposalOperation::Replace,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Replace {
                    draft: wrong_source_reviewed_draft.clone(),
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("wrong-source original must be new")
    };
    reopened_handle
        .commit(wrong_source_original_command, 20)
        .await
        .unwrap();
    let mut wrong_source_edited_draft = wrong_source_reviewed_draft;
    wrong_source_edited_draft.value.text = "wrong-source accepted text".into();
    let wrong_source_payload = ProposalPayload::Atom(Box::new(AtomProposalPayload::Replace {
        draft: wrong_source_edited_draft,
    }));
    let view =
        SemanticCurrentView::from_snapshot(&reopened_handle.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: wrong_source_reviewed,
        command: wrong_source_reviewed_command,
    } = proposals
        .submit(
            &view,
            proposal_context(21),
            SubmitProposalRequest {
                target_kind: wrong_source_original.target_kind,
                target_id: wrong_source_original.target_id,
                base_revision_id: wrong_source_original.base_revision_id,
                operation: wrong_source_original.operation,
                payload: wrong_source_payload.clone(),
                evidence_refs: wrong_source_original.evidence_refs.clone(),
                source_cohort_refs: wrong_source_original.source_cohort_refs.clone(),
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::User,
            },
        )
        .unwrap()
    else {
        panic!("wrong-source reviewed proposal must be new")
    };
    wrong_source_original
        .validate_edit_candidate(&wrong_source_reviewed)
        .unwrap();
    reopened_handle
        .commit(wrong_source_reviewed_command, 21)
        .await
        .unwrap();
    assert!(matches!(
        reopened_service
            .decide_proposal(
                RequestId::new_v7(),
                reopened_handle.project().await.unwrap().frontier,
                wrong_source_original.proposal_id,
                wrong_source_original.proposal_revision_id,
                &evertrace_domain::evidence::hex(&wrong_source_original.fingerprint),
                HumanProposalDecision::Reject,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Applied { .. }
    ));
    let wrong_source_accept_request = RequestId::new_v7();
    assert!(matches!(
        reopened_service
            .decide_proposal(
                wrong_source_accept_request,
                reopened_handle.project().await.unwrap().frontier,
                wrong_source_reviewed.proposal_id,
                wrong_source_reviewed.proposal_revision_id,
                &evertrace_domain::evidence::hex(&wrong_source_reviewed.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Applied { .. }
    ));
    let wrong_source_accept_command = reopened_handle
        .committed_command(CommandId::from_uuid(wrong_source_accept_request.as_uuid()).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(wrong_source_accept_command.payloads.iter().any(|payload| {
        matches!(payload, JournalPayload::SourceReceiptRecorded(value)
            if value.source_ref == wrong_source_reviewed.proposal_id.to_string()
                && value.source_ref != wrong_source_original.proposal_id.to_string())
    }));

    let wrong_source_intent = wrong_source_original
        .edit_intent_toml(&wrong_source_reviewed)
        .unwrap();
    let wrong_source_edit_request = RequestId::new_v7();
    let mut capture = evertrace_capture::CaptureRuntime::open(runtime.clone()).unwrap();
    let isolated = capture
        .capture_isolated(
            isolated_acceptance_input(
                &wrong_source_original,
                &wrong_source_intent,
                task_id,
                repository_id,
            ),
            CommandId::from_uuid(wrong_source_edit_request.as_uuid()).unwrap(),
            &format!(
                "tui-{}",
                wrong_source_original.proposal_id.as_uuid().hyphenated()
            ),
        )
        .unwrap();
    let stale_edit_path = isolated.segment.path().to_path_buf();
    drop(isolated);
    assert!(matches!(
        reopened_service
            .decide_proposal(
                wrong_source_edit_request,
                reopened_handle.project().await.unwrap().frontier,
                wrong_source_original.proposal_id,
                wrong_source_original.proposal_revision_id,
                &evertrace_domain::evidence::hex(&wrong_source_original.fingerprint),
                HumanProposalDecision::EditAndAccept(Box::new(wrong_source_payload)),
            )
            .await
            .unwrap(),
        evertrace_engine::HumanActionOutcome::Conflict { .. }
    ));
    assert!(stale_edit_path.exists());
    let before_stale_reconcile = reopened_handle.project().await.unwrap();
    reopened_service.reconcile_reserved_once().await.unwrap();
    let after_stale_reconcile = reopened_handle.project().await.unwrap();
    assert_eq!(
        after_stale_reconcile.frontier,
        before_stale_reconcile.frontier
    );
    assert!(!stale_edit_path.exists());
    reopened_handle.shutdown().await.unwrap();
    reopened_task.await.unwrap().unwrap();
}
