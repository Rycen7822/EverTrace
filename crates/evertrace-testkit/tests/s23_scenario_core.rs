use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceByteRange,
        EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength, ObservationRole,
        SourceArchiveMode, SourceInstanceId, SourceObservation, SourceReceipt,
        SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole, payload_fingerprint,
        source_observation_id, source_receipt_id,
    },
    ids::{CommandId, CoreMembershipId, TaskId, WorkstreamId},
    revision::RevisionId,
    semantic::{
        ActiveScenarioLineage, ApplicabilityExpr, AtomDraft, AtomKind, AtomProposalPayload,
        AtomProvenance, AtomScope, AtomValue, ConstraintExpr, ConstraintField, ConstraintValue,
        CoreMembershipProposalPayload, CoreScopeIdentity, EpistemicStatus, FutureCueLifecycleExprs,
        GlobalSupportState, GlobalSupportValidationEvent, ProposalCreatedBy, ProposalEligibility,
        ProposalOperation, ProposalPayload, ProposalTargetKind, RevisionProposal, Scenario,
        ScenarioScope, ScenarioStatus, ScenarioWorkstream, SemanticQualifier,
        SupportThresholdSnapshot, TUI_ACCEPTANCE_EVENT_MANIFEST_REF, ValidityInterval,
        tui_acceptance_event_payload,
    },
    work::{PhaseKind, Task, TaskIdentityConfidence, TaskLifecycle},
};
use evertrace_engine::semantic::{
    AtomAcceptanceContext, AtomAuthorityBasis, AtomMaterialization,
    CoreMembershipAcceptanceContext, ProposalCommandContext, ProposalResolution,
    RevisionProposalService, ScenarioCompiler, SubmitProposalRequest, accept_core_membership,
    mark_support_pending, materialize_atom, submit_core_conflict_proposal,
};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload, JournalWriter,
    SemanticCurrentView, SourceIngestWatermark,
};
use tempfile::TempDir;

const CONFIG: [u8; 32] = [23; 32];

fn scenario(
    scope: ScenarioScope,
    previous: Option<&Scenario>,
    status: ScenarioStatus,
    watermark: u64,
) -> Scenario {
    let revision_id = RevisionId::new_v7();
    let workstream_id = WorkstreamId::new_v7();
    Scenario {
        scenario_id: scope.scenario_id().unwrap(),
        revision_id,
        predecessor_revision_id: previous.map(|value| value.revision_id),
        revision_generation: previous.map_or(1, |value| value.revision_generation + 1),
        scope,
        active_worktree_snapshot_id: None,
        worktree_lineage_refs: vec!["lineage:main".into()],
        status,
        goal: "deliver the verified change".into(),
        current_state: vec!["outcome:integrated-passed".into()],
        active_lineage: ActiveScenarioLineage {
            active_workstream_id: Some(workstream_id),
            active_episode_id: None,
            active_attempt_id: None,
            unresolved_competing_group_ids: Vec::new(),
        },
        active_workstreams: vec![ScenarioWorkstream {
            workstream_id,
            phase_kind: PhaseKind::Verify,
            open_episode_id: None,
        }],
        running_experiment_refs: Vec::new(),
        constraints: Vec::new(),
        decisions: Vec::new(),
        open_loops: vec!["verify:release".into()],
        active_failures: Vec::new(),
        completed_outcomes: vec!["outcome:integrated-passed".into()],
        relevant_artifacts: Vec::new(),
        support_atom_ids: Vec::new(),
        source_watermark: watermark,
    }
}

fn source(label: &str, payload: &str, at: i64) -> (SourceReceipt, SourceObservation) {
    let instance = SourceInstanceId::parse(format!("s23-{label}")).unwrap();
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
        adapter_manifest_ref: "adapter-s23".into(),
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
            adapter_manifest_ref: "adapter-s23".into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: Vec::new(),
    };
    receipt.validate().unwrap();
    observation.validate().unwrap();
    (receipt, observation)
}

fn tui_source(
    proposal: &RevisionProposal,
    payload: &str,
    at: i64,
) -> (SourceReceipt, SourceObservation) {
    let label = proposal.proposal_id.as_uuid().hyphenated().to_string();
    let (mut receipt, mut observation) = source(&label, payload, at);
    let instance =
        SourceInstanceId::parse(format!("tui-acceptance:{}", proposal.proposal_id)).unwrap();
    let revision = SourceRevision::parse(proposal.proposal_revision_id.to_string()).unwrap();
    let record = SourceRecordIdentity::parse(format!(
        "tui-accept-{}-{}",
        proposal.proposal_id, proposal.proposal_revision_id
    ))
    .unwrap();
    let observation_id = source_observation_id(&instance, &revision, &record).unwrap();
    let receipt_id = source_receipt_id(&instance, &revision, &record).unwrap();
    receipt.source_receipt_id = receipt_id;
    receipt.source_observation_id = observation_id;
    receipt.source_instance_id = instance.clone();
    receipt.source_kind = EvidenceSourceKind::Other;
    receipt.identity_domain = TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into();
    receipt.source_ref = proposal.proposal_id.to_string();
    receipt.source_session_ref = "human-governance".into();
    receipt.source_revision = revision.clone();
    receipt.source_record_identity = record.clone();
    receipt.source_sequence_origin = Some(1);
    receipt.close_watermark = None;
    receipt.adapter_manifest_ref = TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into();
    observation.source_observation_id = observation_id;
    observation.source_instance_id = instance;
    observation.source_revision = revision;
    observation.source_record_identity = record;
    observation.source_receipt_ref = receipt_id;
    observation.correlation.adapter_manifest_ref = TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into();
    receipt.validate().unwrap();
    observation.validate().unwrap();
    (receipt, observation)
}

fn event_command(at: i64, payloads: Vec<JournalPayload>) -> JournalCommand {
    JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, CONFIG, "s23-test-v1", payload))
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
            algorithm_revision: "s23-test-v1".into(),
            source_watermark: 1,
        }),
        JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::PhysicalNormalization,
            target_id: target,
            algorithm_revision: "s23-test-v1".into(),
            source_watermark: 1,
        }),
    ]
}

fn proposal_context(at: i64) -> ProposalCommandContext {
    ProposalCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: "s23-test-v1".into(),
    }
}

fn support_validation(
    snapshot: &evertrace_store::ProjectionSnapshot,
    successor: &str,
) -> GlobalSupportValidationEvent {
    snapshot
        .rows
        .iter()
        .filter_map(|row| row.payload_json.as_deref())
        .filter_map(|payload| serde_json::from_str::<JournalPayload>(payload).ok())
        .filter_map(|payload| match payload {
            JournalPayload::GlobalSupportValidationRecorded(value)
                if value.successor_ref == successor =>
            {
                Some(*value)
            }
            _ => None,
        })
        .max_by_key(|value| value.dependency_generation)
        .unwrap()
}

fn tamper_initial_validation(
    command: &JournalCommand,
    mutate: impl FnOnce(&mut GlobalSupportValidationEvent),
) -> JournalCommand {
    let mut events = command.events().to_vec();
    let validation = events
        .iter_mut()
        .find_map(|event| match &mut event.payload {
            JournalPayload::GlobalSupportValidationRecorded(value) => Some(value.as_mut()),
            _ => None,
        })
        .unwrap();
    mutate(validation);
    JournalCommand::new(CommandId::new_v7(), events).unwrap()
}

fn tamper_membership(
    command: &JournalCommand,
    mutate: impl FnOnce(&mut evertrace_domain::semantic::CoreMembership),
) -> JournalCommand {
    let mut events = command.events().to_vec();
    let membership = events
        .iter_mut()
        .find_map(|event| match &mut event.payload {
            JournalPayload::CoreMembershipRecorded(value) => Some(value.as_mut()),
            _ => None,
        })
        .expect("accepted membership cohort has a membership");
    mutate(membership);
    JournalCommand::new(CommandId::new_v7(), events).unwrap()
}

#[tokio::test]
async fn scenario_successors_rebuild_with_four_tables_and_safe_search_text() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let scope = ScenarioScope {
        task_id: TaskId::new_v7(),
        repository_instance_id: None,
        worktree_instance_id: None,
    };
    let first = scenario(scope.clone(), None, ScenarioStatus::Active, 1);
    first.validate().unwrap();
    let second = scenario(scope, Some(&first), ScenarioStatus::Closed, 2);
    second.validate_successor(&second).unwrap_err();
    first.validate_successor(&second).unwrap();

    let mut writer = JournalWriter::open(&root).await.unwrap();
    let first_command =
        ScenarioCompiler::journal_command(CommandId::new_v7(), first.clone(), CONFIG, 1).unwrap();
    writer.commit(&first_command, 1).await.unwrap();
    writer.full_projection().await.unwrap();
    let second_command =
        ScenarioCompiler::journal_command(CommandId::new_v7(), second.clone(), CONFIG, 2).unwrap();
    writer.commit(&second_command, 2).await.unwrap();
    let snapshot = writer.project().await.unwrap();

    let scenario_rows = snapshot
        .rows
        .iter()
        .filter(|row| row.object_kind.as_deref() == Some("scenario"))
        .collect::<Vec<_>>();
    assert_eq!(scenario_rows.len(), 2);
    let current_revision = second.revision_id.to_string();
    assert_eq!(
        scenario_rows
            .iter()
            .filter(|row| row.current_revision_id.as_deref() == Some(current_revision.as_str()))
            .count(),
        1
    );
    assert!(writer.search_rows().await.unwrap().iter().any(|row| {
        row.object_kind.as_deref() == Some("scenario")
            && row.text.contains("deliver the verified change")
            && row.text.contains("outcome:integrated-passed")
    }));
    assert_eq!(
        writer.table_names().await.unwrap(),
        vec![
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search"
        ]
    );
    drop(writer);

    let reopened = JournalWriter::open(&root).await.unwrap();
    assert_eq!(snapshot, reopened.project().await.unwrap());
    assert_eq!(
        reopened
            .object_rows()
            .await
            .unwrap()
            .iter()
            .filter(|row| row.object_kind.as_deref() == Some("scenario"))
            .count(),
        2
    );
}

#[tokio::test]
async fn global_atom_and_independent_core_membership_accept_as_atomic_cohorts() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("core-store");
    let mut writer = JournalWriter::open(&root).await.unwrap();
    let (evidence_receipt, evidence_observation) = source("evidence", "global evidence", 1);
    writer
        .commit(
            &event_command(
                1,
                source_payloads(evidence_receipt.clone(), evidence_observation.clone()),
            ),
            1,
        )
        .await
        .unwrap();
    let support_task_id = TaskId::new_v7();
    let support_task = Task {
        task_id: support_task_id,
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec!["request:s23-support".into()],
        canonical_goal: "provide a persisted support revision".into(),
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
    let support_draft = AtomDraft {
        kind: AtomKind::Fact,
        epistemic_status: EpistemicStatus::Unverified,
        value: AtomValue {
            text: "verified evidence must remain attributable".into(),
            subject: "evidence".into(),
            predicate: "is_attributable".into(),
            object: Some("true".into()),
            qualifiers: Vec::new(),
            critical_revision_refs: Vec::new(),
        },
        scope: AtomScope::Task {
            task_id: support_task_id,
        },
        applicability_expr: ApplicabilityExpr::Always,
        future_cue_lifecycle_exprs: None,
        validity_interval: ValidityInterval {
            valid_from_us: 1,
            valid_until_us: None,
        },
        provenance: vec![AtomProvenance::AgentClaimed],
        source_observation_refs: vec![evidence_observation.source_observation_id],
        evidence_refs: vec![evidence_receipt.source_receipt_id.to_string()],
        supersedes_revision_refs: Vec::new(),
        supports_revision_refs: Vec::new(),
        contradicts_revision_refs: Vec::new(),
    };
    let support_atom = materialize_atom(
        AtomMaterialization {
            draft: support_draft.clone(),
            authority_basis: AtomAuthorityBasis::AgentInferred,
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 2,
        },
        None,
    )
    .unwrap();
    let mut self_supported = support_atom.clone();
    self_supported.supports_revision_refs = vec![self_supported.revision_id];
    assert!(self_supported.validate().is_err());
    writer
        .commit(
            &event_command(
                2,
                vec![
                    JournalPayload::TaskRecorded(Box::new(support_task)),
                    JournalPayload::AtomRecorded(Box::new(support_atom.clone())),
                ],
            ),
            2,
        )
        .await
        .unwrap();
    let mut support_successor_draft = support_draft;
    support_successor_draft.value.object = Some("current".into());
    let current_support_atom = materialize_atom(
        AtomMaterialization {
            draft: support_successor_draft,
            authority_basis: AtomAuthorityBasis::AgentInferred,
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 2,
        },
        Some(&support_atom),
    )
    .unwrap();
    writer
        .commit(
            &event_command(
                2,
                vec![JournalPayload::AtomRecorded(Box::new(
                    current_support_atom.clone(),
                ))],
            ),
            2,
        )
        .await
        .unwrap();
    let draft = AtomDraft {
        kind: AtomKind::Constraint,
        epistemic_status: EpistemicStatus::NotApplicable,
        value: AtomValue {
            text: "always preserve verified evidence".into(),
            subject: "evidence".into(),
            predicate: "preserve".into(),
            object: Some("verified".into()),
            qualifiers: vec![SemanticQualifier {
                name: "scope".into(),
                value: "global".into(),
            }],
            critical_revision_refs: Vec::new(),
        },
        scope: AtomScope::Global,
        applicability_expr: ApplicabilityExpr::Constraint(ConstraintExpr::Eq {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text("deliver".into()),
        }),
        future_cue_lifecycle_exprs: Some(FutureCueLifecycleExprs {
            suppress_expr: ConstraintExpr::Eq {
                field: ConstraintField::VerifierState,
                value: ConstraintValue::Text("blocked".into()),
            },
            resolve_expr: ConstraintExpr::Eq {
                field: ConstraintField::ArtifactKind,
                value: ConstraintValue::Text("release".into()),
            },
        }),
        validity_interval: ValidityInterval {
            valid_from_us: 1,
            valid_until_us: None,
        },
        provenance: vec![AtomProvenance::AgentClaimed],
        source_observation_refs: vec![evidence_observation.source_observation_id],
        evidence_refs: vec![evidence_receipt.source_receipt_id.to_string()],
        supersedes_revision_refs: Vec::new(),
        supports_revision_refs: vec![current_support_atom.revision_id],
        contradicts_revision_refs: Vec::new(),
    };
    let service = RevisionProposalService;
    let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let mut unsupported_draft = draft.clone();
    unsupported_draft.supports_revision_refs.clear();
    let ProposalResolution::Revision {
        value: unsupported_proposal,
        command: submit_unsupported,
    } = service
        .submit(
            &view,
            proposal_context(2),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                    draft: unsupported_draft,
                })),
                evidence_refs: vec![evidence_receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![evidence_receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("unsupported proposal must remain auditable")
    };
    writer.commit(&submit_unsupported, 2).await.unwrap();
    let unsupported_acceptance_payload = tui_acceptance_event_payload(
        unsupported_proposal.proposal_id,
        unsupported_proposal.proposal_revision_id,
        &unsupported_proposal.fingerprint,
    );
    let (unsupported_receipt, unsupported_observation) =
        tui_source(&unsupported_proposal, &unsupported_acceptance_payload, 2);
    writer
        .commit(
            &event_command(
                2,
                source_payloads(unsupported_receipt.clone(), unsupported_observation.clone()),
            ),
            2,
        )
        .await
        .unwrap();
    let unsupported_view =
        SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let before_unsupported_accept = unsupported_view.frontier;
    assert!(matches!(
        service.accept(
            &unsupported_view,
            proposal_context(2),
            unsupported_proposal.proposal_id,
            AtomAcceptanceContext::GlobalTui {
                observation: Box::new(unsupported_observation),
                receipt: Box::new(unsupported_receipt),
            },
        ),
        Err(evertrace_engine::semantic::SemanticServiceError::InvalidInput)
    ));
    assert_eq!(
        writer.project().await.unwrap().frontier,
        before_unsupported_accept
    );
    let stale_view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let mut stale_draft = draft.clone();
    stale_draft.supports_revision_refs = vec![support_atom.revision_id];
    let ProposalResolution::Revision {
        value: stale_proposal,
        command: submit_stale,
    } = service
        .submit(
            &stale_view,
            proposal_context(2),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                    draft: stale_draft,
                })),
                evidence_refs: vec![evidence_receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![evidence_receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("stale support proposal must remain auditable")
    };
    writer.commit(&submit_stale, 2).await.unwrap();
    let stale_acceptance_payload = tui_acceptance_event_payload(
        stale_proposal.proposal_id,
        stale_proposal.proposal_revision_id,
        &stale_proposal.fingerprint,
    );
    let (stale_receipt, stale_observation) =
        tui_source(&stale_proposal, &stale_acceptance_payload, 2);
    writer
        .commit(
            &event_command(
                2,
                source_payloads(stale_receipt.clone(), stale_observation.clone()),
            ),
            2,
        )
        .await
        .unwrap();
    let stale_view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let before_stale_accept = stale_view.frontier;
    assert!(matches!(
        service.accept(
            &stale_view,
            proposal_context(2),
            stale_proposal.proposal_id,
            AtomAcceptanceContext::GlobalTui {
                observation: Box::new(stale_observation),
                receipt: Box::new(stale_receipt),
            },
        ),
        Err(evertrace_engine::semantic::SemanticServiceError::InvalidInput)
    ));
    assert_eq!(
        writer.project().await.unwrap().frontier,
        before_stale_accept
    );
    let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: atom_proposal,
        command: submit_atom,
    } = service
        .submit(
            &view,
            proposal_context(2),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create { draft })),
                evidence_refs: vec![evidence_receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![evidence_receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("global atom proposal must persist")
    };
    writer.commit(&submit_atom, 2).await.unwrap();
    let atom_acceptance_payload = tui_acceptance_event_payload(
        atom_proposal.proposal_id,
        atom_proposal.proposal_revision_id,
        &atom_proposal.fingerprint,
    );
    let (atom_acceptance_receipt, atom_acceptance_observation) =
        tui_source(&atom_proposal, &atom_acceptance_payload, 3);
    writer
        .commit(
            &event_command(
                3,
                source_payloads(
                    atom_acceptance_receipt.clone(),
                    atom_acceptance_observation.clone(),
                ),
            ),
            3,
        )
        .await
        .unwrap();
    let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let accepted_atom = service
        .accept(
            &view,
            proposal_context(4),
            atom_proposal.proposal_id,
            AtomAcceptanceContext::GlobalTui {
                observation: Box::new(atom_acceptance_observation),
                receipt: Box::new(atom_acceptance_receipt),
            },
        )
        .unwrap();
    let global_contract = accepted_atom
        .command
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::GlobalSupportContractRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        global_contract.support_revision_refs,
        vec![current_support_atom.revision_id]
    );
    assert_eq!(
        global_contract.authorization_revision_refs,
        vec![accepted_atom.proposal.proposal_revision_id]
    );
    let before_tamper = writer.project().await.unwrap().frontier;
    let unknown = RevisionId::new_v7();
    for tampered in [
        tamper_initial_validation(&accepted_atom.command, |value| {
            value.surviving_support_refs = vec![unknown];
        }),
        tamper_initial_validation(&accepted_atom.command, |value| {
            value.surviving_support_refs.clear();
            value.invalid_or_missing_refs = vec![current_support_atom.revision_id];
        }),
        tamper_initial_validation(&accepted_atom.command, |value| {
            value.provenance_degraded = true;
        }),
    ] {
        assert!(writer.commit(&tampered, 4).await.is_err());
        assert_eq!(writer.project().await.unwrap().frontier, before_tamper);
    }
    let partial_global = JournalCommand::new(
        CommandId::new_v7(),
        accepted_atom
            .command
            .events()
            .iter()
            .filter(|event| {
                !matches!(
                    event.payload,
                    JournalPayload::GlobalSupportValidationRecorded(_)
                )
            })
            .cloned()
            .collect(),
    )
    .unwrap();
    let before_partial_global = writer.project().await.unwrap().frontier;
    assert!(writer.commit(&partial_global, 4).await.is_err());
    assert_eq!(
        writer.project().await.unwrap().frontier,
        before_partial_global
    );
    let atom_outcome = writer.commit(&accepted_atom.command, 4).await.unwrap();
    assert!(
        writer
            .commit(&accepted_atom.command, 5)
            .await
            .unwrap()
            .replayed
    );

    let direct_snapshot = writer.project().await.unwrap();
    assert!(
        direct_snapshot
            .rows
            .iter()
            .any(|row| row.object_kind.as_deref() == Some("recall_trigger_index"))
    );
    let direct = support_validation(
        &direct_snapshot,
        &accepted_atom.atom.revision_id.to_string(),
    );
    let pending_payloads =
        mark_support_pending(&direct, vec!["dependency:direct".into()], CONFIG, 5).unwrap();
    let pending_direct = pending_payloads
        .iter()
        .find_map(|payload| match payload {
            JournalPayload::GlobalSupportValidationRecorded(value) => Some(value.as_ref().clone()),
            _ => None,
        })
        .unwrap();
    writer
        .commit(&event_command(5, pending_payloads), 5)
        .await
        .unwrap();
    let pending_snapshot = writer.project().await.unwrap();
    let accepted_atom_revision = accepted_atom.atom.revision_id.to_string();
    assert!(pending_snapshot.rows.iter().any(|row| {
        row.current_revision_id.as_deref() == Some(accepted_atom_revision.as_str())
            && row.support_state.as_deref() == Some("revalidation_pending")
    }));
    assert!(
        !pending_snapshot
            .rows
            .iter()
            .any(|row| row.object_kind.as_deref() == Some("recall_trigger_index"))
    );
    let before_forged_terminal = pending_snapshot.frontier;
    for (surviving_support_refs, invalid_or_missing_refs, state) in [
        (
            vec![RevisionId::new_v7()],
            Vec::new(),
            GlobalSupportState::Valid,
        ),
        (Vec::new(), Vec::new(), GlobalSupportState::Insufficient),
    ] {
        let mut forged = pending_direct.clone();
        forged.validation_revision_id = RevisionId::new_v7();
        forged.state = state;
        forged.provenance_degraded = false;
        forged.surviving_support_refs = surviving_support_refs;
        forged.invalid_or_missing_refs = invalid_or_missing_refs;
        forged.created_at_us = 6;
        assert!(
            writer
                .commit(
                    &event_command(
                        6,
                        vec![JournalPayload::GlobalSupportValidationRecorded(Box::new(
                            forged,
                        ))],
                    ),
                    6,
                )
                .await
                .is_err()
        );
        assert_eq!(
            writer.project().await.unwrap().frontier,
            before_forged_terminal
        );
    }
    let mut direct_valid = pending_direct;
    direct_valid.validation_revision_id = RevisionId::new_v7();
    direct_valid.state = GlobalSupportState::Valid;
    direct_valid.created_at_us = 6;
    writer
        .commit(
            &event_command(
                6,
                vec![JournalPayload::GlobalSupportValidationRecorded(Box::new(
                    direct_valid,
                ))],
            ),
            6,
        )
        .await
        .unwrap();

    let restored_direct_snapshot = writer.project().await.unwrap();
    assert!(
        restored_direct_snapshot
            .rows
            .iter()
            .any(|row| row.object_kind.as_deref() == Some("recall_trigger_index"))
    );
    let view = SemanticCurrentView::from_snapshot(&restored_direct_snapshot).unwrap();
    let ProposalResolution::Revision {
        value: core_proposal,
        command: submit_core,
    } = service
        .submit(
            &view,
            proposal_context(6),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::CoreMembership,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::CoreMembership(Box::new(
                    CoreMembershipProposalPayload::Create {
                        atom_revision_id: accepted_atom.atom.revision_id,
                        scope_identity: CoreScopeIdentity::Global,
                    },
                )),
                evidence_refs: vec![evidence_receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![evidence_receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("core proposal must persist")
    };
    writer.commit(&submit_core, 6).await.unwrap();
    let core_acceptance_payload = tui_acceptance_event_payload(
        core_proposal.proposal_id,
        core_proposal.proposal_revision_id,
        &core_proposal.fingerprint,
    );
    let (core_receipt, core_observation) = tui_source(&core_proposal, &core_acceptance_payload, 7);
    writer
        .commit(
            &event_command(
                7,
                source_payloads(core_receipt.clone(), core_observation.clone()),
            ),
            7,
        )
        .await
        .unwrap();
    let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let membership = accept_core_membership(
        &view,
        proposal_context(8),
        core_proposal.proposal_id,
        CoreMembershipAcceptanceContext::Tui(AtomAcceptanceContext::GlobalTui {
            observation: Box::new(core_observation.clone()),
            receipt: Box::new(core_receipt.clone()),
        }),
        &accepted_atom.atom,
        CoreMembershipId::new_v7(),
        SupportThresholdSnapshot {
            minimum_surviving_support: 1,
            require_authorization: true,
        },
    )
    .unwrap();
    let membership_contract = membership
        .command
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::GlobalSupportContractRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        membership_contract.support_revision_refs,
        vec![accepted_atom.atom.revision_id]
    );
    assert_eq!(
        membership_contract.authorization_revision_refs,
        vec![membership.proposal.proposal_revision_id]
    );
    assert_eq!(
        membership.membership.authorization_revision_refs,
        membership_contract.authorization_revision_refs
    );
    let before_membership_tamper = writer.project().await.unwrap().frontier;
    for tampered in [
        tamper_membership(&membership.command, |value| {
            value.authorization_revision_refs = vec![RevisionId::new_v7()];
        }),
        tamper_membership(&membership.command, |value| {
            value.support_contract_ref = RevisionId::new_v7();
        }),
    ] {
        assert!(writer.commit(&tampered, 8).await.is_err());
        assert_eq!(
            writer.project().await.unwrap().frontier,
            before_membership_tamper
        );
    }
    let partial_core = JournalCommand::new(
        CommandId::new_v7(),
        membership
            .command
            .events()
            .iter()
            .filter(|event| {
                !matches!(
                    event.payload,
                    JournalPayload::GlobalSupportContractRecorded(_)
                )
            })
            .cloned()
            .collect(),
    )
    .unwrap();
    let before_partial_core = writer.project().await.unwrap().frontier;
    assert!(writer.commit(&partial_core, 8).await.is_err());
    assert_eq!(
        writer.project().await.unwrap().frontier,
        before_partial_core
    );
    let core_outcome = writer.commit(&membership.command, 8).await.unwrap();
    assert!(
        writer
            .commit(&membership.command, 9)
            .await
            .unwrap()
            .replayed
    );
    assert!(core_outcome.last_seq > atom_outcome.last_seq);
    let snapshot = writer.project().await.unwrap();
    assert!(
        snapshot
            .rows
            .iter()
            .any(|row| row.object_kind.as_deref() == Some("l3_core_projection"))
    );
    assert!(
        snapshot
            .rows
            .iter()
            .any(|row| row.object_kind.as_deref() == Some("recall_trigger_index"))
    );
    let membership_revision = membership.membership.membership_revision_id.to_string();
    let membership_support = support_validation(&snapshot, &membership_revision);
    writer
        .commit(
            &event_command(
                10,
                mark_support_pending(
                    &membership_support,
                    vec!["dependency:membership".into()],
                    CONFIG,
                    10,
                )
                .unwrap(),
            ),
            10,
        )
        .await
        .unwrap();
    let pending_membership_snapshot = writer.project().await.unwrap();
    assert!(pending_membership_snapshot.rows.iter().any(|row| {
        row.current_revision_id.as_deref() == Some(accepted_atom_revision.as_str())
            && row.support_state.as_deref() == Some("revalidation_pending")
    }));
    assert!(
        !pending_membership_snapshot
            .rows
            .iter()
            .any(|row| row.object_kind.as_deref() == Some("l3_core_projection"))
    );
    assert!(
        !pending_membership_snapshot
            .rows
            .iter()
            .any(|row| row.object_kind.as_deref() == Some("recall_trigger_index"))
    );
    assert_eq!(writer.table_names().await.unwrap().len(), 4);
    let view = SemanticCurrentView::from_snapshot(&pending_membership_snapshot).unwrap();
    let conflict = submit_core_conflict_proposal(
        &view,
        proposal_context(10),
        accepted_atom.atom.revision_id,
        RevisionId::new_v7(),
        CoreScopeIdentity::Global,
        vec![evidence_receipt.source_receipt_id.to_string()],
    )
    .unwrap();
    let ProposalResolution::Revision {
        value,
        command: conflict_command,
    } = conflict
    else {
        panic!("typed conflict must create a manual proposal")
    };
    assert_eq!(value.eligibility, ProposalEligibility::ManualRequired);
    assert!(matches!(value.payload, ProposalPayload::CoreMembership(_)));
    writer.commit(&conflict_command, 11).await.unwrap();
    let conflict_view =
        SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert!(matches!(
        accept_core_membership(
            &conflict_view,
            proposal_context(12),
            value.proposal_id,
            CoreMembershipAcceptanceContext::Tui(AtomAcceptanceContext::GlobalTui {
                observation: Box::new(core_observation),
                receipt: Box::new(core_receipt),
            }),
            &accepted_atom.atom,
            CoreMembershipId::new_v7(),
            SupportThresholdSnapshot {
                minimum_surviving_support: 1,
                require_authorization: true,
            },
        ),
        Err(evertrace_engine::semantic::SemanticServiceError::UnsupportedTarget)
    ));
    let final_snapshot = writer.project().await.unwrap();
    drop(writer);
    let reopened = JournalWriter::open(&root).await.unwrap();
    assert_eq!(final_snapshot, reopened.full_projection().await.unwrap());
}
