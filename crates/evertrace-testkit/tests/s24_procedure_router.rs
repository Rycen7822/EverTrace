use evertrace_domain::{
    config::{GlobalPromotionConfig, PromotionLevel},
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceByteRange,
        EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength, ObservationRole,
        SourceArchiveMode, SourceInstanceId, SourceObservation, SourceReceipt,
        SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole, payload_fingerprint,
        source_observation_id, source_receipt_id,
    },
    ids::{CommandId, TaskId},
    procedure::{
        ProcedureActions, ProcedureDone, ProcedureDraft, ProcedureEligibilityEvidence,
        ProcedureKind, ProcedurePublicationState, ProcedureScope, ProcedureStateReason,
        ProcedureWhen,
    },
    query::{
        AnswerShape, FacetParseStatus, LifecycleBoundary, Polarity, QueryFacetSet, RetrievalBudget,
        SearchContext, SearchIntent, SuppressionSnapshot, TemporalMode,
    },
    revision::RevisionId,
    semantic::{
        ApplicabilityExpr, AtomDraft, AtomKind, AtomProvenance, AtomScope, AtomValue,
        ConstraintBinding, ConstraintExpr, ConstraintField, ConstraintState, ConstraintValue,
        EpistemicStatus, ProcedureProposalPayload, ProposalCreatedBy, ProposalEligibility,
        ProposalOperation, ProposalPayload, ProposalTargetId, ProposalTargetKind,
        TUI_ACCEPTANCE_EVENT_MANIFEST_REF, ValidityInterval, tui_acceptance_event_payload,
    },
    work::{Task, TaskIdentityConfidence, TaskLifecycle},
};
use evertrace_engine::{
    procedure::{
        ProcedureAcceptanceContext, ProcedureAcceptanceResolution, ProcedureCandidate,
        ProcedureDecision, ProcedureGuidanceMode, ProcedurePhase, ProcedureRouter,
        accept_procedure, publication_event,
    },
    semantic::{
        AtomAcceptanceContext, AtomAuthorityBasis, AtomMaterialization, ProposalCommandContext,
        ProposalResolution, RevisionProposalService, SubmitProposalRequest, materialize_atom,
    },
};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload, JournalWriter,
    SearchIndex, SemanticCurrentView, SourceIngestWatermark,
};
use tempfile::TempDir;

const CONFIG: [u8; 32] = [24; 32];

fn source(label: &str, payload: &str, at: i64) -> (SourceReceipt, SourceObservation) {
    let instance = SourceInstanceId::parse(format!("s24-{label}")).unwrap();
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
        repository_instance_id: None,
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
        adapter_manifest_ref: "adapter-s24".into(),
        eligible_event_manifest_ref: TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        detector_revision: 1,
        redaction_revision: 1,
        protection_key_generation: 1,
        event_time_us: 0,
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
            adapter_manifest_ref: "adapter-s24".into(),
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

fn command(at: i64, payloads: Vec<JournalPayload>) -> JournalCommand {
    JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, CONFIG, "s24-test-v1", payload))
            .collect(),
    )
    .unwrap()
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
            algorithm_revision: "s24-test-v1".into(),
            source_watermark: 1,
        }),
        JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::PhysicalNormalization,
            target_id: target,
            algorithm_revision: "s24-test-v1".into(),
            source_watermark: 1,
        }),
    ]
}

fn procedure_draft(evidence: String, support: RevisionId) -> ProcedureDraft {
    ProcedureDraft {
        scope: ProcedureScope::Global,
        title: "Recover deterministic release verification".into(),
        summary: "Use objective verification after a recoverable release failure".into(),
        kind: ProcedureKind::Diagnostic,
        when: ProcedureWhen {
            goals: vec!["release".into()],
            targets: vec!["artifact".into()],
            signals: vec!["release verifier failed".into()],
            stage: "verify".into(),
            requires: vec!["objective verifier available".into()],
            excludes: vec!["artifact already verified".into()],
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
            stages: vec!["run the fixed release verifier".into()],
            branches: Vec::new(),
            avoid: vec!["do not publish before verification".into()],
        },
        done: ProcedureDone {
            success: vec!["release verifier passes".into()],
            abort: vec!["stop on evidence mismatch".into()],
            verify: vec!["record the objective verifier result".into()],
        },
        pitfalls: vec!["stale artifacts can look verified".into()],
        evidence_refs: vec![evidence],
        support_revision_refs: vec![support],
    }
}

fn proposal_context(at: i64) -> ProposalCommandContext {
    ProposalCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: "s24-test-v1".into(),
    }
}

fn full_evidence(
    observation: evertrace_domain::ids::SourceObservationId,
) -> ProcedureEligibilityEvidence {
    ProcedureEligibilityEvidence {
        independent_successes: 3,
        retrospective_contrasts: 1,
        objective_verifier_present: true,
        evidence_complete: true,
        non_triviality_passed: true,
        when_done_contract_complete: true,
        unresolved_contradictions: 0,
        redundancy_check_passed: true,
        distinct_applicability_contexts: 2,
        confirmed_harm: 0,
        unresolved_suspected_harm: 0,
        applicability_expr_complete: true,
        verifier_observation_ref: Some(observation),
    }
}

#[tokio::test]
async fn auto_full_acceptance_is_atomic_probationary_rebuildable_and_fts_visible() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("procedure-store");
    let mut writer = JournalWriter::open(&root).await.unwrap();
    let (mut receipt, mut observation) = source("evidence", "objective procedure evidence", 1);
    receipt.observation_role = ObservationRole::Result;
    observation.observation_role = ObservationRole::Result;
    observation.source_role = SourceRole::Tool;
    observation.content_trust = ContentTrust::Observed;
    observation.correlation.pairing_role = ObservationRole::Result;
    writer
        .commit(
            &command(1, source_payloads(receipt.clone(), observation.clone())),
            1,
        )
        .await
        .unwrap();
    let task_id = TaskId::new_v7();
    let task = Task {
        task_id,
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec!["request:s24".into()],
        canonical_goal: "provide procedure support".into(),
        scope_memberships: Vec::new(),
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
    let support = materialize_atom(
        AtomMaterialization {
            draft: AtomDraft {
                kind: AtomKind::Fact,
                epistemic_status: EpistemicStatus::Unverified,
                value: AtomValue {
                    text: "objective verifier succeeded".into(),
                    subject: "verifier".into(),
                    predicate: "succeeded".into(),
                    object: Some("true".into()),
                    qualifiers: Vec::new(),
                    critical_revision_refs: Vec::new(),
                },
                scope: AtomScope::Task { task_id },
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
            },
            authority_basis: AtomAuthorityBasis::AgentInferred,
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 2,
        },
        None,
    )
    .unwrap();
    writer
        .commit(
            &command(
                2,
                vec![
                    JournalPayload::TaskRecorded(Box::new(task)),
                    JournalPayload::AtomRecorded(Box::new(support.clone())),
                ],
            ),
            2,
        )
        .await
        .unwrap();
    let service = RevisionProposalService;
    let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: proposal,
        command: submit,
    } = service
        .submit(
            &view,
            proposal_context(3),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Procedure,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Create {
                    draft: procedure_draft(
                        receipt.source_receipt_id.to_string(),
                        support.revision_id,
                    ),
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::AutoEligibleFull,
                created_by: ProposalCreatedBy::System,
            },
        )
        .unwrap()
    else {
        panic!("procedure proposal must persist")
    };
    writer.commit(&submit, 3).await.unwrap();
    let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let config = GlobalPromotionConfig {
        atom: PromotionLevel::SemiAuto,
        procedure: PromotionLevel::FullAuto,
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
        ProcedureAcceptanceContext::AutoFull(full_evidence(observation.source_observation_id)),
        None,
        None,
        &config,
    )
    .unwrap()
    else {
        panic!("create is not no-delta")
    };
    assert!(accepted.events().iter().any(|event| matches!(
        &event.payload,
        JournalPayload::ProcedureStateRecorded(value)
            if value.to_state == ProcedurePublicationState::ActiveProbationary
    )));
    assert!(accepted.events().iter().any(|event| matches!(
        event.payload,
        JournalPayload::GlobalSupportContractRecorded(_)
    )));
    assert!(accepted.events().iter().any(|event| matches!(
        &event.payload,
        JournalPayload::RevisionProposalRecorded(value)
            if value.status == evertrace_domain::semantic::ProposalStatus::Accepted
                && value.review_reason.as_deref() == Some("automatic_acceptance")
                && matches!(value.acceptance.as_ref().map(|acceptance| &acceptance.accepted_target),
                    Some(evertrace_domain::semantic::AcceptedProposalTarget::Procedure {
                        auto_full_audit: Some(audit), ..
                    }) if audit.eligible
                        && audit.eligibility == full_evidence(observation.source_observation_id))
    )));
    let mut tampered_audit_events = accepted.events().to_vec();
    for event in &mut tampered_audit_events {
        if let JournalPayload::RevisionProposalRecorded(value) = &mut event.payload
            && let Some(evertrace_domain::semantic::AcceptedProposalTarget::Procedure {
                auto_full_audit: Some(audit),
                ..
            }) = value
                .acceptance
                .as_mut()
                .map(|acceptance| &mut acceptance.accepted_target)
        {
            audit.eligible = false;
        }
    }
    let tampered_audit = JournalCommand::new(CommandId::new_v7(), tampered_audit_events).unwrap();
    let before_tamper = writer.project().await.unwrap().frontier;
    assert!(writer.commit(&tampered_audit, 4).await.is_err());
    assert_eq!(writer.project().await.unwrap().frontier, before_tamper);
    let mut mismatched_draft_events = accepted.events().to_vec();
    for event in &mut mismatched_draft_events {
        if let JournalPayload::ProcedureRevisionRecorded(value) = &mut event.payload {
            value.draft.summary = "materialized draft differs from proposal".into();
        }
    }
    let mismatched_draft =
        JournalCommand::new(CommandId::new_v7(), mismatched_draft_events).unwrap();
    assert!(writer.commit(&mismatched_draft, 4).await.is_err());
    assert_eq!(writer.project().await.unwrap().frontier, before_tamper);
    let extra_new_state = publication_event(
        &procedure,
        ProcedurePublicationState::ActiveProbationary,
        ProcedurePublicationState::ActiveStable,
        ProcedureStateReason::ObjectiveSuccesses,
        None,
        vec![receipt.source_receipt_id.to_string()],
        4,
    )
    .unwrap();
    let mut extra_new_state_events = accepted.events().to_vec();
    extra_new_state_events.push(JournalEventDraft::runtime(
        4,
        CONFIG,
        "s24-test-v1",
        JournalPayload::ProcedureStateRecorded(Box::new(extra_new_state)),
    ));
    let extra_new_state_command =
        JournalCommand::new(CommandId::new_v7(), extra_new_state_events).unwrap();
    assert!(writer.commit(&extra_new_state_command, 4).await.is_err());
    assert_eq!(writer.project().await.unwrap().frontier, before_tamper);
    let partial = JournalCommand::new(
        CommandId::new_v7(),
        accepted
            .events()
            .iter()
            .filter(|event| !matches!(event.payload, JournalPayload::ProcedureStateRecorded(_)))
            .cloned()
            .collect(),
    )
    .unwrap();
    let before = writer.project().await.unwrap().frontier;
    assert!(writer.commit(&partial, 4).await.is_err());
    assert_eq!(writer.project().await.unwrap().frontier, before);
    let orphan = command(
        4,
        vec![JournalPayload::ProcedureRevisionRecorded(procedure.clone())],
    );
    assert!(writer.commit(&orphan, 4).await.is_err());
    assert_eq!(writer.project().await.unwrap().frontier, before);
    let mut duplicate_events = accepted.events().to_vec();
    duplicate_events.push(JournalEventDraft::runtime(
        4,
        CONFIG,
        "s24-test-v1",
        JournalPayload::ProcedureRevisionRecorded(procedure.clone()),
    ));
    let duplicate = JournalCommand::new(CommandId::new_v7(), duplicate_events).unwrap();
    assert!(writer.commit(&duplicate, 4).await.is_err());
    assert_eq!(writer.project().await.unwrap().frontier, before);
    writer.commit(&accepted, 4).await.unwrap();
    assert!(writer.commit(&accepted, 5).await.unwrap().replayed);
    let snapshot = writer.project().await.unwrap();
    let procedure_revision_id = procedure.revision_id.to_string();
    assert!(snapshot.rows.iter().any(|row| {
        row.object_kind.as_deref() == Some("procedure_revision")
            && row.current_revision_id.as_deref() == Some(procedure_revision_id.as_str())
            && row.publication_state.as_deref() == Some("active_probationary")
            && row.support_state.as_deref() == Some("valid")
    }));
    let hold = publication_event(
        &procedure,
        ProcedurePublicationState::ActiveProbationary,
        ProcedurePublicationState::ReviewHold,
        ProcedureStateReason::IrConflict,
        Some(ProcedurePublicationState::ActiveProbationary),
        vec![receipt.source_receipt_id.to_string()],
        5,
    )
    .unwrap();
    writer
        .commit(
            &command(
                5,
                vec![JournalPayload::ProcedureStateRecorded(Box::new(hold))],
            ),
            5,
        )
        .await
        .unwrap();
    let snapshot = writer.project().await.unwrap();
    assert!(snapshot.rows.iter().any(|row| {
        row.object_kind.as_deref() == Some("procedure_revision")
            && row.current_revision_id.as_deref() == Some(procedure_revision_id.as_str())
            && row.publication_state.as_deref() == Some("review_hold")
    }));
    let view = SemanticCurrentView::from_snapshot(&snapshot).unwrap();
    let mut replacement_draft = procedure.draft.clone();
    replacement_draft.summary =
        "Use objective verification and retain the failed evidence boundary".into();
    replacement_draft.pitfalls = (0..5)
        .map(|index| format!("pitfall-{index}-{}", "x".repeat(1_790)))
        .collect();
    assert!(
        replacement_draft
            .pitfalls
            .iter()
            .map(String::len)
            .sum::<usize>()
            > 8 * 1024
    );
    let ProposalResolution::Revision {
        value: replacement_proposal,
        command: replacement_submit,
    } = service
        .submit(
            &view,
            proposal_context(6),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Procedure,
                target_id: Some(ProposalTargetId::Procedure(procedure.procedure_id)),
                base_revision_id: Some(procedure.revision_id),
                operation: ProposalOperation::Replace,
                payload: ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Replace {
                    draft: replacement_draft,
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("replacement proposal must persist")
    };
    writer.commit(&replacement_submit, 6).await.unwrap();
    let acceptance_payload = tui_acceptance_event_payload(
        replacement_proposal.proposal_id,
        replacement_proposal.proposal_revision_id,
        &replacement_proposal.fingerprint,
    );
    let (acceptance_receipt, acceptance_observation) =
        source("manual-acceptance", &acceptance_payload, 7);
    writer
        .commit(
            &command(
                7,
                source_payloads(acceptance_receipt.clone(), acceptance_observation.clone()),
            ),
            7,
        )
        .await
        .unwrap();
    let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProcedureAcceptanceResolution::Command {
        procedure: replacement,
        command: replacement_accept,
        ..
    } = accept_procedure(
        &view,
        proposal_context(8),
        replacement_proposal.proposal_id,
        ProcedureAcceptanceContext::Manual(AtomAcceptanceContext::GlobalTui {
            observation: Box::new(acceptance_observation),
            receipt: Box::new(acceptance_receipt),
        }),
        Some(&procedure),
        Some(ProcedurePublicationState::ReviewHold),
        &config,
    )
    .unwrap()
    else {
        panic!("changed replacement cannot be no-delta")
    };
    assert!(replacement_accept.events().iter().any(|event| matches!(
        &event.payload,
        JournalPayload::ProcedureStateRecorded(value)
            if value.procedure_revision_id == procedure.revision_id
                && value.to_state == ProcedurePublicationState::Superseded
    )));
    let mut wrong_parent_events = replacement_accept.events().to_vec();
    for event in &mut wrong_parent_events {
        if let JournalPayload::ProcedureStateRecorded(value) = &mut event.payload
            && value.to_state == ProcedurePublicationState::Superseded
        {
            value.procedure_revision_id = RevisionId::new_v7();
        }
    }
    let wrong_parent = JournalCommand::new(CommandId::new_v7(), wrong_parent_events).unwrap();
    let before_replacement = writer.project().await.unwrap().frontier;
    assert!(writer.commit(&wrong_parent, 8).await.is_err());
    assert_eq!(writer.project().await.unwrap().frontier, before_replacement);
    let extra_parent_state = publication_event(
        &procedure,
        ProcedurePublicationState::ReviewHold,
        ProcedurePublicationState::ActiveProbationary,
        ProcedureStateReason::SupportRestored,
        None,
        vec![receipt.source_receipt_id.to_string()],
        8,
    )
    .unwrap();
    let mut extra_parent_state_events = replacement_accept.events().to_vec();
    let superseded_index = extra_parent_state_events
        .iter()
        .position(|event| {
            matches!(&event.payload, JournalPayload::ProcedureStateRecorded(value)
                if value.procedure_revision_id == procedure.revision_id
                    && value.to_state == ProcedurePublicationState::Superseded)
        })
        .unwrap();
    if let JournalPayload::ProcedureStateRecorded(value) =
        &mut extra_parent_state_events[superseded_index].payload
    {
        value.from_state = Some(ProcedurePublicationState::ActiveProbationary);
    }
    extra_parent_state_events.insert(
        superseded_index,
        JournalEventDraft::runtime(
            8,
            CONFIG,
            "s24-test-v1",
            JournalPayload::ProcedureStateRecorded(Box::new(extra_parent_state)),
        ),
    );
    let extra_parent_state_command =
        JournalCommand::new(CommandId::new_v7(), extra_parent_state_events).unwrap();
    assert!(writer.commit(&extra_parent_state_command, 8).await.is_err());
    assert_eq!(writer.project().await.unwrap().frontier, before_replacement);
    writer.commit(&replacement_accept, 8).await.unwrap();
    let snapshot = writer.project().await.unwrap();
    let replacement_revision_id = replacement.revision_id.to_string();
    assert!(snapshot.rows.iter().any(|row| {
        row.object_kind.as_deref() == Some("procedure_revision")
            && row.current_revision_id.as_deref() == Some(replacement_revision_id.as_str())
            && row.publication_state.as_deref() == Some("active_probationary")
    }));
    let index = SearchIndex::open(&root).await.unwrap();
    assert!(
        index
            .fts("release verification")
            .await
            .unwrap()
            .iter()
            .any(|row| {
                row.object_kind.as_deref() == Some("procedure_revision")
                    && row.text.contains("title:Recover deterministic")
            })
    );
    assert!(
        !index
            .fts("objective verifier available")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        !index
            .fts("stop on evidence mismatch")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        writer.table_names().await.unwrap(),
        vec![
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search",
        ]
    );
    drop(writer);
    let reopened = JournalWriter::open(&root).await.unwrap();
    assert_eq!(snapshot, reopened.project().await.unwrap());
}

#[test]
fn eligibility_publication_and_router_gates_are_closed_and_bounded() {
    let (_, observation) = source("unit-verifier", "verifier", 1);
    let observation = observation.source_observation_id;
    let full = full_evidence(observation);
    assert!(full.auto_eligible_full(false, false));
    assert!(full.auto_eligible_full(true, true));
    let mut failed = full.clone();
    failed.redundancy_check_passed = false;
    assert!(!failed.auto_eligible_full(false, true));
    failed = full.clone();
    failed.distinct_applicability_contexts = 1;
    assert!(!failed.auto_eligible_full(true, true));
    for failed in [
        ProcedureEligibilityEvidence {
            independent_successes: 1,
            ..full.clone()
        },
        ProcedureEligibilityEvidence {
            retrospective_contrasts: 0,
            ..full.clone()
        },
        ProcedureEligibilityEvidence {
            objective_verifier_present: false,
            ..full.clone()
        },
        ProcedureEligibilityEvidence {
            evidence_complete: false,
            ..full.clone()
        },
        ProcedureEligibilityEvidence {
            non_triviality_passed: false,
            ..full.clone()
        },
        ProcedureEligibilityEvidence {
            when_done_contract_complete: false,
            ..full.clone()
        },
        ProcedureEligibilityEvidence {
            unresolved_contradictions: 1,
            ..full.clone()
        },
        ProcedureEligibilityEvidence {
            redundancy_check_passed: false,
            ..full.clone()
        },
    ] {
        assert!(!failed.auto_eligible_full(false, true));
    }
    for failed in [
        ProcedureEligibilityEvidence {
            distinct_applicability_contexts: 1,
            ..full.clone()
        },
        ProcedureEligibilityEvidence {
            confirmed_harm: 1,
            ..full.clone()
        },
        ProcedureEligibilityEvidence {
            unresolved_suspected_harm: 1,
            ..full.clone()
        },
        ProcedureEligibilityEvidence {
            applicability_expr_complete: false,
            ..full.clone()
        },
    ] {
        assert!(!failed.auto_eligible_full(true, true));
    }
    assert!(!full.auto_eligible_full(true, false));

    let support = RevisionId::new_v7();
    let revision = evertrace_domain::procedure::ProcedureRevision {
        procedure_id: evertrace_domain::ids::ProcedureId::new_v7(),
        revision_id: RevisionId::new_v7(),
        parent_revision_id: None,
        revision_generation: 1,
        draft: procedure_draft("receipt:evidence".into(), support),
        source_watermark: 1,
        created_at_us: 1,
    };
    revision.validate().unwrap();
    assert_eq!(revision.procedure_id.as_uuid().get_version_num(), 7);
    assert_eq!(revision.revision_id.as_uuid().get_version_num(), 7);
    let mut unknown = serde_json::to_value(&revision.draft).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("script".into(), serde_json::json!("rm -rf /"));
    assert!(serde_json::from_value::<ProcedureDraft>(unknown).is_err());
    let mut no_op_successor = revision.clone();
    no_op_successor.revision_id = RevisionId::new_v7();
    no_op_successor.parent_revision_id = Some(revision.revision_id);
    no_op_successor.revision_generation = 2;
    no_op_successor.created_at_us = 2;
    assert!(revision.validate_successor(&no_op_successor).is_err());
    let mut repository_revision = revision.clone();
    repository_revision.draft.scope = ProcedureScope::Repository {
        repository_id: evertrace_domain::ids::RepositoryId::new_v7(),
    };
    let mut widened = repository_revision.clone();
    widened.revision_id = RevisionId::new_v7();
    widened.parent_revision_id = Some(repository_revision.revision_id);
    widened.revision_generation = 2;
    widened.draft.scope = ProcedureScope::Global;
    widened.created_at_us = 2;
    assert!(repository_revision.validate_successor(&widened).is_err());
    let mut repository_without_support = repository_revision.draft.clone();
    repository_without_support.support_revision_refs.clear();
    assert!(repository_without_support.validate().is_ok());
    let mut worktree_without_support = repository_without_support.clone();
    worktree_without_support.scope = ProcedureScope::Worktree {
        repository_id: evertrace_domain::ids::RepositoryId::new_v7(),
        worktree_id: evertrace_domain::ids::WorktreeId::new_v7(),
    };
    assert!(worktree_without_support.validate().is_ok());
    let mut global_without_support = repository_without_support;
    global_without_support.scope = ProcedureScope::Global;
    assert!(global_without_support.validate().is_err());
    for scope in [
        ProcedureScope::Repository {
            repository_id: evertrace_domain::ids::RepositoryId::new_v7(),
        },
        ProcedureScope::Worktree {
            repository_id: evertrace_domain::ids::RepositoryId::new_v7(),
            worktree_id: evertrace_domain::ids::WorktreeId::new_v7(),
        },
    ] {
        let mut draft = revision.draft.clone();
        draft.scope = scope;
        draft.support_revision_refs.clear();
        let request = SubmitProposalRequest {
            target_kind: ProposalTargetKind::Procedure,
            target_id: None,
            base_revision_id: None,
            operation: ProposalOperation::Create,
            payload: ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Create {
                draft,
            })),
            evidence_refs: vec!["receipt:evidence".into()],
            source_cohort_refs: vec!["receipt:evidence".into()],
            eligibility: ProposalEligibility::AutoEligibleFull,
            created_by: ProposalCreatedBy::System,
        };
        let ProposalResolution::Revision {
            value: proposal, ..
        } = RevisionProposalService
            .submit(
                &SemanticCurrentView::default(),
                proposal_context(3),
                request,
            )
            .unwrap()
        else {
            panic!("ordinary procedure proposal must persist")
        };
        let mut view = SemanticCurrentView::default();
        view.proposals
            .insert(proposal.proposal_id, (*proposal).clone());
        assert!(matches!(
            accept_procedure(
                &view,
                proposal_context(4),
                proposal.proposal_id,
                ProcedureAcceptanceContext::AutoFull(full.clone()),
                None,
                None,
                &GlobalPromotionConfig {
                    atom: PromotionLevel::Manual,
                    procedure: PromotionLevel::SemiAuto,
                    core_membership: PromotionLevel::Manual,
                },
            ),
            Ok(ProcedureAcceptanceResolution::Command { ref command, .. })
                if !command.events().iter().any(|event| matches!(
                    event.payload,
                    JournalPayload::GlobalSupportContractRecorded(_)
                )) && command.events().iter().any(|event| matches!(
                    &event.payload,
                    JournalPayload::RevisionProposalRecorded(value)
                        if matches!(value.acceptance.as_ref().map(|acceptance| &acceptance.accepted_target),
                            Some(evertrace_domain::semantic::AcceptedProposalTarget::Procedure {
                                auto_full_audit: Some(audit), ..
                            }) if audit.procedure_promotion_level == PromotionLevel::SemiAuto
                                && audit.validate(false).is_ok())
                ))
        ));
    }
    let ProposalResolution::Revision {
        value: global_proposal,
        ..
    } = RevisionProposalService
        .submit(
            &SemanticCurrentView::default(),
            proposal_context(3),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Procedure,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Create {
                    draft: revision.draft.clone(),
                })),
                evidence_refs: vec!["receipt:evidence".into()],
                source_cohort_refs: vec!["receipt:evidence".into()],
                eligibility: ProposalEligibility::AutoEligibleFull,
                created_by: ProposalCreatedBy::System,
            },
        )
        .unwrap()
    else {
        panic!("global procedure proposal must persist")
    };
    let mut global_view = SemanticCurrentView::default();
    global_view
        .proposals
        .insert(global_proposal.proposal_id, (*global_proposal).clone());
    assert!(
        accept_procedure(
            &global_view,
            proposal_context(4),
            global_proposal.proposal_id,
            ProcedureAcceptanceContext::AutoFull(full.clone()),
            None,
            None,
            &GlobalPromotionConfig {
                atom: PromotionLevel::Manual,
                procedure: PromotionLevel::SemiAuto,
                core_membership: PromotionLevel::Manual,
            },
        )
        .is_err()
    );
    let hold = publication_event(
        &revision,
        ProcedurePublicationState::ActiveProbationary,
        ProcedurePublicationState::ReviewHold,
        ProcedureStateReason::IrConflict,
        Some(ProcedurePublicationState::ActiveProbationary),
        vec!["receipt:evidence".into()],
        2,
    )
    .unwrap();
    assert_eq!(hold.to_state, ProcedurePublicationState::ReviewHold);

    let state = ConstraintState {
        bindings: vec![
            ConstraintBinding {
                field: ConstraintField::ArtifactKind,
                value: ConstraintValue::Text("candidate".into()),
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
    let context = SearchContext {
        intent: SearchIntent::FailureRecovery,
        raw_query: "release verifier failed".into(),
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
        task_id: None,
        repository_id: None,
        worktree_id: None,
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
    let stable = ProcedureCandidate {
        revision: revision.clone(),
        publication: ProcedurePublicationState::ActiveStable,
        global_support: Some(evertrace_domain::semantic::GlobalSupportState::Valid),
        phase: ProcedurePhase::AtEntry,
        lexical_rank: 2,
    };
    let mut probationary = stable.clone();
    probationary.revision.procedure_id = evertrace_domain::ids::ProcedureId::new_v7();
    probationary.revision.revision_id = RevisionId::new_v7();
    probationary.publication = ProcedurePublicationState::ActiveProbationary;
    probationary.lexical_rank = 1;
    let normal = ProcedureRouter::route(
        &context,
        vec![probationary.clone(), stable.clone()],
        &state,
        None,
        true,
        false,
        false,
        false,
    );
    assert_eq!(normal.items.len(), 1);
    assert_eq!(normal.items[0].procedure_id, stable.revision.procedure_id);
    assert_eq!(normal.items[0].decision, ProcedureDecision::Apply);
    let guardrail = ProcedureRouter::route(
        &context,
        vec![stable.clone()],
        &state,
        None,
        true,
        true,
        false,
        false,
    );
    assert_eq!(
        guardrail.items[0].mode,
        ProcedureGuidanceMode::GuardrailOnly
    );
    assert!(guardrail.items[0].actions.is_none());
    assert_eq!(guardrail.items[0].avoid, revision.draft.actions.avoid);
    assert!(guardrail.items[0].done.as_ref().unwrap().success.is_empty());
    assert_eq!(
        guardrail.items[0].done.as_ref().unwrap().abort,
        revision.draft.done.abort
    );
    assert_eq!(
        guardrail.items[0].done.as_ref().unwrap().verify,
        revision.draft.done.verify
    );
    let stale = ProcedureRouter::route(
        &context,
        vec![stable.clone()],
        &state,
        None,
        false,
        false,
        false,
        false,
    );
    assert_eq!(stale.items[0].decision, ProcedureDecision::Defer);
    assert_eq!(stale.items[0].reason, "insufficient_context");
    assert!(stale.items[0].actions.is_none());
    assert!(stale.items[0].done.is_none());
    let stale_guardrail = ProcedureRouter::route(
        &context,
        vec![stable.clone()],
        &state,
        None,
        false,
        true,
        false,
        false,
    );
    assert_eq!(stale_guardrail.items[0].decision, ProcedureDecision::Defer);
    assert_eq!(
        stale_guardrail.items[0].mode,
        ProcedureGuidanceMode::GuardrailOnly
    );
    assert!(stale_guardrail.items[0].actions.is_none());
    assert_eq!(stale_guardrail.items[0].avoid, revision.draft.actions.avoid);
    assert_eq!(
        stale_guardrail.items[0].excludes,
        revision.draft.when.excludes
    );
    assert_eq!(stale_guardrail.items[0].pitfalls, revision.draft.pitfalls);
    let stale_done = stale_guardrail.items[0].done.as_ref().unwrap();
    assert!(stale_done.success.is_empty());
    assert_eq!(stale_done.abort, revision.draft.done.abort);
    assert_eq!(stale_done.verify, revision.draft.done.verify);

    let mut applicability_false = state.clone();
    applicability_false.bindings[2].value = ConstraintValue::Text("other".into());
    let mut avoid_true = state.clone();
    avoid_true.bindings[1].value = ConstraintValue::Text("passed".into());
    let mut completion_true = state.clone();
    completion_true.bindings[0].value = ConstraintValue::Text("release".into());
    for incompatible in [applicability_false, avoid_true, completion_true] {
        assert_eq!(
            ProcedureRouter::route(
                &context,
                vec![stable.clone()],
                &incompatible,
                None,
                true,
                false,
                false,
                false,
            )
            .status,
            "no_applicable_procedure"
        );
    }

    let mut unsupported = probationary.clone();
    unsupported.global_support =
        Some(evertrace_domain::semantic::GlobalSupportState::RevalidationPending);
    assert_eq!(
        ProcedureRouter::route(
            &context,
            vec![unsupported],
            &state,
            None,
            true,
            false,
            false,
            false,
        )
        .status,
        "no_applicable_procedure"
    );
    let mut history = context;
    history.intent = SearchIntent::HistoryLookup;
    assert_eq!(
        ProcedureRouter::route(
            &history,
            vec![probationary],
            &state,
            None,
            true,
            false,
            false,
            false,
        )
        .status,
        "history_lookup_bypass"
    );
}
