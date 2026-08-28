use std::collections::BTreeMap;

use evertrace_domain::{
    evidence::{
        CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
        CorrelationField, CorrelationFieldClaim, CorrelationStrength, EvidenceByteRange,
        EvidenceSourceKind, FieldProvenanceEntry, HostCorrelationEvidence, HostOccurrence,
        HostOccurrenceExactKey, IdentityStrength, NormalizationState, ObservationRole, Operation,
        OperationKind, PairingState, SourceArchiveMode, SourceInstanceId, SourceObservation,
        SourceReceipt, SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole,
        host_occurrence_id_for_exact, payload_fingerprint, source_observation_id,
        source_receipt_id,
    },
    ids::{
        CaptureReceiptId, CommandId, CompetingAttemptGroupId, ExecutionLaneId, OperationId, TaskId,
        WorkBindingRevisionId, WorkEpisodeId, WorkstreamId,
    },
    revision::RevisionId,
    work::{
        AdmissionFailureObservability, AssignmentStatus, BoundaryStatus, CaptureReceipt,
        CheckpointReason, CheckpointVerifierState, CorrectionKind, CoverageLevel, EpisodeLifecycle,
        ExecutionLane, LaneStatus, LivenessState, OrderingIntegrity, PairingIntegrity,
        PayloadIntegrity, PhaseContract, PhaseKind, PrimaryWorkBinding, SegmentationCorrection,
        SourceCoverage, StrategyContract, Task, TaskIdentityConfidence, TaskLifecycle,
        TaskScopeMembership, WorkBindingRevision, Workstream, WorkstreamStatus,
    },
};
use evertrace_engine::{
    segmentation::{
        BoundaryEvidence, CheckpointResolution, IncrementalSegmentationStep, IncrementalSegmenter,
        SegmentOutcome, SegmentationFacts, StateDeltaKind, VerifierTransition, build_checkpoint,
        capture_summary,
    },
    work::{
        WorkCommandContext, activate_episode, attempt::new_attempt,
        close_episode_and_optionally_open, confirm_episode_boundary, link_attempt_to_episode,
        new_episode, record_episode_correction, save_checkpoint, save_segmentation_update,
    },
};
use evertrace_store::relations::{OperationBurstRelationKind, build_operation_burst_relation_rows};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, EpisodeCurrentView, JournalCommand, JournalEventDraft,
    JournalPayload, JournalWriter, ObjectRow, ObjectRowKind, OperationBurstCurrentView,
    ProjectionSnapshot, SegmentationCurrentState, SegmentationCurrentView, SourceIngestWatermark,
    reduce_journal,
};
use tempfile::TempDir;

const CONFIG: [u8; 32] = [0x15; 32];
const SOURCE_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn source_evidence(sequence: u64) -> (SourceReceipt, SourceObservation) {
    let instance = SourceInstanceId::parse(format!("source-s15-{sequence}")).unwrap();
    let revision = SourceRevision::parse("revision-1").unwrap();
    let record_identity = SourceRecordIdentity::parse(format!("record-s15-{sequence}")).unwrap();
    let observation_id = source_observation_id(&instance, &revision, &record_identity).unwrap();
    let receipt_id = source_receipt_id(&instance, &revision, &record_identity).unwrap();
    let fields = [
        CorrelationField::HostInstanceId,
        CorrelationField::HostTraceLineageId,
        CorrelationField::HostLaneKey,
        CorrelationField::CanonicalEventFamily,
        CorrelationField::NativeRequestId,
        CorrelationField::PhysicalExecutionOrdinal,
    ];
    let correlation = HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: Some("host-s15".into()),
        host_trace_lineage_id: Some("trace-s15".into()),
        host_lane_key: Some(format!("lane-{sequence}")),
        canonical_event_family: Some(CanonicalEventFamily::Mutate),
        native_request_id: Some(format!("request-{sequence}")),
        physical_execution_ordinal: Some(1),
        pairing_role: ObservationRole::Intent,
        field_provenance: fields
            .into_iter()
            .map(|field| CorrelationFieldClaim {
                field,
                source_ref: "source-s15".into(),
                evidence_ref: "evidence-s15".into(),
            })
            .collect(),
        adapter_manifest_ref: "adapter-manifest-s15".into(),
        adapter_revision: 1,
        strong_gate_receipt_ref: Some("strong-gate-s15".into()),
        admission: CorrelationAdmission::ExactCapable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    };
    let receipt = SourceReceipt {
        source_receipt_id: receipt_id,
        source_observation_id: observation_id,
        source_instance_id: instance.clone(),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        source_ref: format!("source-ref-{sequence}"),
        source_session_ref: "session-s15".into(),
        source_revision: revision.clone(),
        source_record_identity: record_identity.clone(),
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
        observation_role: ObservationRole::Intent,
        unsupported_record_classification: None,
        capture_completeness: CaptureCompleteness::Complete,
        archive_mode: SourceArchiveMode::Exact,
        cas_ref: SOURCE_DIGEST.into(),
        protected_length: 1,
        original_length: 1,
        protected_secret_digest: None,
        redaction_spans: vec![],
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-manifest-s15".into(),
        eligible_event_manifest_ref: "eligible-events-s15".into(),
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
        source_record_identity: record_identity,
        observation_role: ObservationRole::Intent,
        identity_strength: IdentityStrength::StableNative,
        payload_fingerprint: evertrace_domain::evidence::hex(
            &payload_fingerprint(1, b"x", None).unwrap(),
        ),
        source_receipt_ref: receipt_id,
        source_role: SourceRole::Tool,
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Complete,
        adapter_revision: 1,
        parser_revision: 1,
        canonicalization_revision: 1,
        detector_revision: 1,
        redaction_revision: 1,
        correlation,
        scope_effect_claims: vec![],
    };
    (receipt, observation)
}

fn evidence_command(receipt: SourceReceipt, observation: SourceObservation) -> JournalCommand {
    let target = observation.source_observation_id.to_string();
    command(
        1,
        vec![
            JournalPayload::SourceReceiptRecorded(Box::new(receipt.clone())),
            JournalPayload::SourceObservationRecorded(Box::new(observation)),
            JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
                source_instance_id: receipt.source_instance_id,
                source_revision: receipt.source_revision,
                source_sequence: receipt.source_sequence,
            }),
            JournalPayload::DirtyTarget(DirtyTarget {
                target_kind: DirtyTargetKind::EvidenceSurface,
                target_id: target.clone(),
                algorithm_revision: "s15-physical-v1".into(),
                source_watermark: 1,
            }),
            JournalPayload::DirtyTarget(DirtyTarget {
                target_kind: DirtyTargetKind::PhysicalNormalization,
                target_id: target,
                algorithm_revision: "s15-physical-v1".into(),
                source_watermark: 1,
            }),
        ],
    )
}

fn context(at: i64) -> WorkCommandContext {
    WorkCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: "s15-episode-v1",
    }
}

fn phase(kind: PhaseKind) -> PhaseContract {
    PhaseContract {
        local_goal: "incrementally segment work".into(),
        phase_kind: kind,
        phase_label: format!("{kind:?}"),
        primary_targets: vec!["episode".into()],
        entry_conditions: vec!["resolved binding".into()],
        acceptance_boundary: "objective verifier".into(),
        expected_state_transition: "episode current advances".into(),
    }
}

fn task() -> Task {
    Task {
        task_id: TaskId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec!["request:s15".into()],
        canonical_goal: "deterministic episodes".into(),
        scope_memberships: vec![TaskScopeMembership {
            repository_instance_id: None,
            worktree_instance_ids: vec![],
        }],
        identity_confidence: TaskIdentityConfidence::Explicit,
        lifecycle: TaskLifecycle::Active,
        continuation_of_task_id: None,
        split_from_task_id: None,
        split_into_task_ids: vec![],
        merged_from_task_ids: vec![],
        merged_into_task_id: None,
        created_at_us: 1,
        closed_at_us: None,
        source_watermark: 1,
    }
}

fn stream(task_id: TaskId, watermark: u64) -> Workstream {
    Workstream {
        workstream_id: WorkstreamId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        task_id,
        repository_instance_id: None,
        worktree_instance_ids: vec![],
        active_worktree_instance_id: None,
        worktree_lineage_refs: vec![],
        parent_workstream_id: None,
        dependency_workstream_ids: vec![],
        status: WorkstreamStatus::Active,
        root_goal: "deterministic episodes".into(),
        workstream_goal: "segment one workstream".into(),
        target_family: "episode".into(),
        hypothesis_or_failure_family: "phase transition".into(),
        acceptance_boundary: "s15 proof".into(),
        phase_contract: phase(PhaseKind::Implement),
        active_episode_id: None,
        execution_lane_ids: vec![],
        source_watermark: watermark,
    }
}

fn token(
    episode: &evertrace_domain::work::WorkEpisode,
    sequence: u64,
    session: &str,
) -> ObservedOperation {
    token_with(episode, sequence, session, None, |_| {})
}

fn token_with(
    episode: &evertrace_domain::work::WorkEpisode,
    sequence: u64,
    session: &str,
    attempt_id: Option<evertrace_domain::ids::AttemptId>,
    alter: impl FnOnce(&mut SegmentationFacts),
) -> ObservedOperation {
    try_token_with(episode, sequence, session, attempt_id, alter, None).unwrap()
}

#[derive(Clone, Copy)]
enum TokenFault {
    OccurrenceConflict,
    OperationOccurrence,
    BindingOperation,
    BindingUnresolved,
    LaneReverse,
    ReceiptLane,
}

#[derive(Clone)]
struct ObservedOperation {
    view: SegmentationCurrentState,
    rows: Vec<ObjectRow>,
    operation_id: OperationId,
    facts: SegmentationFacts,
    receipt: CaptureReceipt,
}

impl ObservedOperation {
    fn corrected_successor(&self, sequence: u64) -> Self {
        let mut rows = self.rows.clone();
        let mut successor_row = None;
        for row in &rows {
            if row.object_kind.as_deref() != Some("operation") {
                continue;
            }
            let mut payload: JournalPayload =
                serde_json::from_str(row.payload_json.as_deref().unwrap()).unwrap();
            let JournalPayload::OperationDerived(operation) = &mut payload else {
                unreachable!();
            };
            operation.previous_operation_revision = Some(operation.operation_revision);
            operation.operation_revision += 1;
            successor_row = Some(current_row("operation", &payload));
        }
        rows.push(successor_row.expect("operation row"));
        let view = SegmentationCurrentState::from_snapshot(&ProjectionSnapshot {
            frontier: 101,
            rows: rows.clone(),
        })
        .unwrap();
        let mut facts = self.facts.clone();
        facts.sequence = sequence;
        facts.source_watermark = sequence + 2;
        Self {
            view,
            rows,
            operation_id: self.operation_id,
            facts,
            receipt: self.receipt.clone(),
        }
    }
}

fn try_token_with(
    episode: &evertrace_domain::work::WorkEpisode,
    sequence: u64,
    session: &str,
    attempt_id: Option<evertrace_domain::ids::AttemptId>,
    alter: impl FnOnce(&mut SegmentationFacts),
    fault: Option<TokenFault>,
) -> Result<ObservedOperation, evertrace_engine::segmentation::DetectorError> {
    let source = source_evidence(sequence).1.source_observation_id;
    let key = HostOccurrenceExactKey {
        occurrence_schema_version: 1,
        host_instance_id: "host-s15".into(),
        host_trace_lineage_id: "trace-s15".into(),
        host_lane_key: format!("lane-{sequence}"),
        canonical_event_family: CanonicalEventFamily::Mutate,
        native_request_id: format!("request-{sequence}"),
        physical_execution_ordinal: 1,
    };
    let mut occurrence = HostOccurrence {
        host_occurrence_id: host_occurrence_id_for_exact(&key).unwrap(),
        exact_key: Some(key.clone()),
        host_instance_id: Some(key.host_instance_id.clone()),
        host_trace_lineage_id: Some(key.host_trace_lineage_id.clone()),
        host_lane_key: Some(key.host_lane_key.clone()),
        canonical_event_family: Some(key.canonical_event_family),
        native_request_id: Some(key.native_request_id.clone()),
        physical_execution_ordinal: Some(1),
        correlation_strength: CorrelationStrength::Exact,
        source_observation_refs: vec![source],
        field_provenance: [
            CorrelationField::HostInstanceId,
            CorrelationField::HostTraceLineageId,
            CorrelationField::HostLaneKey,
            CorrelationField::CanonicalEventFamily,
            CorrelationField::NativeRequestId,
            CorrelationField::PhysicalExecutionOrdinal,
        ]
        .into_iter()
        .map(|field| FieldProvenanceEntry {
            field,
            source_observation_ref: source,
            source_ref: "source-s15".into(),
            evidence_ref: "evidence-s15".into(),
        })
        .collect(),
        normalization_state: NormalizationState::SingleSource,
        pairing_state: PairingState::UnmatchedIntent,
        possible_duplicate_group_id: None,
        correlation_resolver_version: 1,
        normalization_revision: 1,
        previous_normalization_revision: None,
    };
    let lane_id = if session == "other-lane" {
        "lane:01900000-0000-7000-8000-000000000016"
    } else {
        "lane:01900000-0000-7000-8000-000000000015"
    }
    .parse()
    .unwrap();
    let mut operation = Operation {
        operation_id: OperationId::new_v7(),
        host_occurrence_id: occurrence.host_occurrence_id,
        execution_lane_id: Some(lane_id),
        operation_kind: OperationKind::Mutate,
        input_source_observation_refs: vec![source],
        result_source_observation_refs: vec![],
        pairing_state: PairingState::UnmatchedIntent,
        scope_effect_ids: vec![],
        artifact_refs: vec![],
        operation_resolver_version: 1,
        operation_revision: 1,
        previous_operation_revision: None,
    };
    let mut receipt = receipt_for(lane_id, sequence + 2);
    let mut lane = lane_for(lane_id, operation.operation_id, &receipt, session);
    let mut binding = WorkBindingRevision {
        work_binding_revision_id: WorkBindingRevisionId::new_v7(),
        operation_id: operation.operation_id,
        revision_generation: 1,
        predecessor_revision_id: None,
        primary_binding: PrimaryWorkBinding {
            task_id: Some(episode.task_id),
            workstream_id: Some(episode.workstream_id),
            episode_id: Some(episode.episode_id),
            attempt_id,
            ..PrimaryWorkBinding::default()
        },
        secondary_bindings: vec![],
        scope_effect_refs: vec![],
        assignment_status: AssignmentStatus::Resolved,
        evidence_refs: vec!["binding-s15".into()],
        resolver_version: 1,
    };
    match fault {
        Some(TokenFault::OccurrenceConflict) => {
            occurrence.normalization_state = NormalizationState::NormalizationConflicted;
        }
        Some(TokenFault::OperationOccurrence) => {
            operation.host_occurrence_id =
                evertrace_domain::ids::HostOccurrenceId::from_digest([0x44; 32]);
        }
        Some(TokenFault::BindingOperation) => binding.operation_id = OperationId::new_v7(),
        Some(TokenFault::BindingUnresolved) => {
            binding.assignment_status = AssignmentStatus::Unresolved;
        }
        Some(TokenFault::LaneReverse) => lane.operation_ids.clear(),
        Some(TokenFault::ReceiptLane) => {
            receipt.execution_lane_id = ExecutionLaneId::new_v7();
        }
        None => {}
    }
    let mut facts = SegmentationFacts {
        sequence,
        source_watermark: sequence + 2,
        target_family: "episode".into(),
        state_delta: StateDeltaKind::Modified,
        error_signature: None,
        verifier_transition: VerifierTransition::None,
        observed_phase_kind: Some(PhaseKind::Implement),
        boundary_evidence: BoundaryEvidence::None,
        evidence_refs: vec![source],
    };
    alter(&mut facts);
    let mut current_stream = stream(episode.task_id, episode.source_watermark);
    current_stream.workstream_id = episode.workstream_id;
    current_stream.phase_contract = episode.phase_contract.clone();
    let initial_stream = current_stream.clone();
    current_stream.revision_id = RevisionId::new_v7();
    current_stream.predecessor_revision_id = Some(initial_stream.revision_id);
    current_stream.active_episode_id = Some(episode.episode_id);
    current_stream.execution_lane_ids = vec![lane_id];
    current_stream.validate().unwrap();
    let receipt_copy = receipt.clone();
    let mut payloads = vec![
        (
            "host_occurrence",
            JournalPayload::HostOccurrenceNormalized(Box::new(occurrence)),
        ),
        (
            "operation",
            JournalPayload::OperationDerived(Box::new(operation.clone())),
        ),
        (
            "work_binding",
            JournalPayload::WorkBindingRecorded(Box::new(binding)),
        ),
        (
            "execution_lane",
            JournalPayload::ExecutionLaneRecorded(Box::new(lane)),
        ),
        (
            "capture_receipt",
            JournalPayload::CaptureReceiptRecorded(Box::new(receipt)),
        ),
        (
            "work_episode",
            JournalPayload::WorkEpisodeRecorded(Box::new(episode.clone())),
        ),
        (
            "workstream",
            JournalPayload::WorkstreamRecorded(Box::new(initial_stream)),
        ),
        (
            "workstream",
            JournalPayload::WorkstreamRecorded(Box::new(current_stream)),
        ),
    ];
    if episode.revision_generation == 2 {
        let mut predecessor = episode.clone();
        predecessor.revision_id = episode.predecessor_revision_id.unwrap();
        predecessor.predecessor_revision_id = None;
        predecessor.revision_generation = 1;
        predecessor.boundary_status = BoundaryStatus::Provisional;
        predecessor.boundary_candidate = None;
        predecessor.confirmation_watermark = 0;
        predecessor.pending_semantic_delta =
            Some(evertrace_domain::work::PendingSemanticInterval {
                after_watermark: predecessor.semantic_watermark,
                through_watermark: predecessor.source_watermark,
            });
        payloads.push((
            "work_episode",
            JournalPayload::WorkEpisodeRecorded(Box::new(predecessor)),
        ));
    }
    if let Some(attempt_id) = attempt_id {
        let strategy = StrategyContract {
            hypothesis: "segmentation attempt".into(),
            intervention: "typed operation".into(),
            intervention_family: "implementation".into(),
            search_policy_ref: None,
            objective_ref: Some("objective:s15".into()),
            expected_effect: "advance".into(),
            target_refs: vec!["episode".into()],
            acceptance_boundary_ref: "objective:s15".into(),
        };
        let mut initial = new_attempt(
            episode.task_id,
            episode.workstream_id,
            None,
            vec![],
            vec![lane_id],
            strategy,
            episode.source_watermark,
        )
        .unwrap();
        initial.attempt_id = attempt_id;
        let mut current = initial.clone();
        current.revision_id = RevisionId::new_v7();
        current.predecessor_revision_id = Some(initial.revision_id);
        current.revision_generation = 2;
        current.episode_id = Some(episode.episode_id);
        current.source_watermark = current.source_watermark.saturating_add(1);
        current.validate().unwrap();
        payloads.push((
            "attempt",
            JournalPayload::AttemptRecorded(Box::new(initial)),
        ));
        payloads.push((
            "attempt",
            JournalPayload::AttemptRecorded(Box::new(current)),
        ));
    }
    let rows: Vec<ObjectRow> = payloads
        .into_iter()
        .map(|(kind, payload)| current_row(kind, &payload))
        .collect();
    let operation_id = operation.operation_id;
    let view = SegmentationCurrentState::from_snapshot(&ProjectionSnapshot {
        frontier: 100,
        rows: rows.clone(),
    })
    .map_err(|_| evertrace_engine::segmentation::DetectorError::Ineligible)?;
    Ok(ObservedOperation {
        view,
        rows,
        operation_id,
        facts,
        receipt: receipt_copy,
    })
}

fn current_row(kind: &str, payload: &JournalPayload) -> ObjectRow {
    let row_id = match payload {
        JournalPayload::WorkBindingRecorded(value) => {
            format!(
                "object:work:work_binding:{}",
                value.work_binding_revision_id
            )
        }
        JournalPayload::WorkEpisodeRecorded(value) => {
            format!("object:work:work_episode:{}", value.revision_id)
        }
        JournalPayload::WorkstreamRecorded(value) => {
            format!("object:work:workstream:{}", value.workstream_id)
        }
        JournalPayload::AttemptRecorded(value) => {
            format!("object:work:attempt:{}", value.revision_id)
        }
        JournalPayload::OperationBurstRecorded(value) => {
            format!("object:work:operation_burst:{}", value.revision_id)
        }
        _ => format!("test:{kind}"),
    };
    ObjectRow {
        row_id,
        row_kind: ObjectRowKind::Data,
        row_class: None,
        object_family: None,
        object_kind: Some(kind.into()),
        object_id: None,
        current_revision_id: None,
        lifecycle: None,
        epistemic: None,
        authority: None,
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: None,
        worktree_id: None,
        task_id: None,
        workstream_id: None,
        session_id: None,
        payload_json: Some(serde_json::to_string(payload).unwrap()),
        source_event_seq: 1,
        projection_generation: 1,
    }
}

fn push_token(
    segmenter: &mut IncrementalSegmenter,
    observed: ObservedOperation,
) -> Result<IncrementalSegmentationStep, evertrace_engine::segmentation::DetectorError> {
    match segmenter.observe(&observed.view, observed.operation_id, observed.facts)? {
        SegmentOutcome::Delta(step) => Ok(*step),
        SegmentOutcome::NoDelta => panic!("expected a segmentation delta"),
    }
}

fn episode_successor_from_step(
    current: &evertrace_domain::work::WorkEpisode,
    step: &IncrementalSegmentationStep,
    receipts: &[CaptureReceipt],
) -> evertrace_domain::work::WorkEpisode {
    let command = save_segmentation_update(context(90), current, step, receipts).unwrap();
    command
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::WorkEpisodeRecorded(value) => Some((**value).clone()),
            _ => None,
        })
        .unwrap()
}

fn state_with_history(
    observed: &ObservedOperation,
    episodes: &[evertrace_domain::work::WorkEpisode],
    bursts: &[evertrace_domain::work::OperationBurst],
    frontier: u64,
) -> SegmentationCurrentState {
    let mut rows = observed
        .rows
        .iter()
        .filter(|row| row.object_kind.as_deref() != Some("work_episode"))
        .cloned()
        .collect::<Vec<_>>();
    let episode_revisions = episodes
        .iter()
        .cloned()
        .map(|episode| (episode.revision_id, episode))
        .collect::<BTreeMap<_, _>>();
    rows.extend(episode_revisions.into_values().map(|episode| {
        current_row(
            "work_episode",
            &JournalPayload::WorkEpisodeRecorded(Box::new(episode)),
        )
    }));
    let burst_revisions = bursts
        .iter()
        .cloned()
        .map(|burst| (burst.revision_id, burst))
        .collect::<BTreeMap<_, _>>();
    rows.extend(burst_revisions.into_values().map(|burst| {
        current_row(
            "operation_burst",
            &JournalPayload::OperationBurstRecorded(Box::new(burst)),
        )
    }));
    SegmentationCurrentState::from_snapshot(&ProjectionSnapshot { frontier, rows }).unwrap()
}

#[test]
fn incremental_segmenter_folds_ordered_members_and_exact_replay_is_no_delta() {
    let root = task();
    let stream = stream(root.task_id, 2);
    let episode = new_episode(&stream, None, 2).unwrap();
    let first = token(&episode, 1, "same-lane");
    let first_state = state_with_history(&first, std::slice::from_ref(&episode), &[], 100);
    let mut segmenter = IncrementalSegmenter::new(&first_state, episode.episode_id).unwrap();
    let first_step = push_token(&mut segmenter, first.clone()).unwrap();
    assert!(first_step.started_new_burst());
    assert_eq!(first_step.current_burst().members.len(), 1);
    let first_episode =
        episode_successor_from_step(&episode, &first_step, std::slice::from_ref(&first.receipt));
    let mut second = token(&episode, 2, "same-lane");
    let second_state = state_with_history(
        &second,
        &[episode.clone(), first_episode.clone()],
        std::slice::from_ref(first_step.current_burst()),
        101,
    );
    let mut segmenter = IncrementalSegmenter::restore(&second_state, episode.episode_id).unwrap();
    second.view = second_state.clone();
    let second_step = push_token(&mut segmenter, second.clone()).unwrap();
    assert_eq!(second_step.current_burst().members.len(), 2);
    assert!(
        second_step.current_burst().members[0].sequence
            < second_step.current_burst().members[1].sequence
    );
    let owner = episode_successor_from_step(
        &first_episode,
        &second_step,
        std::slice::from_ref(&second.receipt),
    );
    assert!(
        build_operation_burst_relation_rows(
            std::slice::from_ref(&owner),
            std::slice::from_ref(second_step.current_burst()),
        )
        .is_ok()
    );
    let mut reversed = second_step.current_burst().clone();
    reversed.members.reverse();
    assert!(reversed.validate().is_err());
    let mut mismatched_primary = second_step.current_burst().clone();
    mismatched_primary.primary_binding.attempt_id =
        Some(evertrace_domain::ids::AttemptId::new_v7());
    assert!(mismatched_primary.validate().is_err());
    let mut second_owner = owner.clone();
    second_owner.episode_id = WorkEpisodeId::new_v7();
    second_owner.revision_id = RevisionId::new_v7();
    second_owner.predecessor_revision_id = None;
    second_owner.revision_generation = 1;
    assert!(
        build_operation_burst_relation_rows(
            &[owner.clone(), second_owner],
            std::slice::from_ref(second_step.current_burst()),
        )
        .is_err()
    );
    assert_eq!(
        IncrementalSegmenter::restore(
            &state_with_history(
                &second,
                &[episode.clone(), first_episode.clone(), owner.clone()],
                &[
                    first_step.current_burst().clone(),
                    second_step.current_burst().clone()
                ],
                102,
            ),
            episode.episode_id,
        )
        .unwrap()
        .observe(
            &state_with_history(
                &second,
                &[episode.clone(), first_episode.clone(), owner.clone()],
                &[
                    first_step.current_burst().clone(),
                    second_step.current_burst().clone()
                ],
                102,
            ),
            second.operation_id,
            second.facts.clone(),
        )
        .unwrap(),
        SegmentOutcome::NoDelta
    );
    let mut corrected = second.corrected_successor(3);
    let corrected_state = state_with_history(
        &corrected,
        &[episode.clone(), first_episode.clone(), owner.clone()],
        &[
            first_step.current_burst().clone(),
            second_step.current_burst().clone(),
        ],
        103,
    );
    let mut segmenter =
        IncrementalSegmenter::restore(&corrected_state, episode.episode_id).unwrap();
    corrected.view = corrected_state.clone();
    let corrected_step = push_token(&mut segmenter, corrected.clone()).unwrap();
    assert!(corrected_step.started_new_burst());
    assert_eq!(
        corrected_step.current_burst().members[0].operation_revision,
        2
    );
    let corrected_owner = episode_successor_from_step(
        &owner,
        &corrected_step,
        std::slice::from_ref(&corrected.receipt),
    );
    let restarted_state = state_with_history(
        &first,
        &[episode.clone(), first_episode, owner, corrected_owner],
        &[
            first_step.current_burst().clone(),
            second_step.current_burst().clone(),
            corrected_step.closed_burst().unwrap().clone(),
            corrected_step.current_burst().clone(),
        ],
        104,
    );
    let mut restarted =
        IncrementalSegmenter::restore(&restarted_state, episode.episode_id).unwrap();
    assert_eq!(
        restarted
            .observe(&restarted_state, first.operation_id, first.facts.clone())
            .unwrap(),
        SegmentOutcome::NoDelta
    );
    let mut regressed = second.clone();
    regressed.facts.sequence = 4;
    regressed.facts.source_watermark = 6;
    assert!(
        restarted
            .observe(&restarted_state, regressed.operation_id, regressed.facts)
            .is_err()
    );
}

#[test]
fn fixed_member_capacity_rolls_burst_without_creating_an_episode_boundary() {
    let root = task();
    let stream = stream(root.task_id, 2);
    let base = new_episode(&stream, None, 2).unwrap();
    let mut current = base.clone();
    let mut episode_revisions = vec![base.clone()];
    let mut burst_revisions = Vec::new();

    for sequence in 1..=65 {
        let mut observed = token(&base, sequence, "fixed-capacity");
        let state = state_with_history(
            &observed,
            &episode_revisions,
            &burst_revisions,
            200 + sequence,
        );
        let mut segmenter = if sequence == 1 {
            IncrementalSegmenter::new(&state, base.episode_id).unwrap()
        } else {
            IncrementalSegmenter::restore(&state, base.episode_id).unwrap()
        };
        observed.view = state;
        let step = push_token(&mut segmenter, observed.clone()).unwrap();

        if sequence == 64 {
            assert_eq!(step.current_burst().members.len(), 64);
            assert!(!step.started_new_burst());
            assert!(step.closed_burst().is_none());
        } else if sequence == 65 {
            assert_eq!(step.current_burst().members.len(), 1);
            assert!(step.started_new_burst());
            assert_eq!(step.closed_burst().unwrap().members.len(), 64);
            assert_eq!(step.candidate_kind(), None);
        }

        if let Some(closed) = step.closed_burst() {
            burst_revisions.push(closed.clone());
        }
        burst_revisions.push(step.current_burst().clone());
        current =
            episode_successor_from_step(&current, &step, std::slice::from_ref(&observed.receipt));
        assert_eq!(current.lifecycle_status, EpisodeLifecycle::Open);
        assert_eq!(current.boundary_status, BoundaryStatus::Provisional);
        assert_eq!(current.confirmation_watermark, 0);
        assert!(current.boundary_candidate.is_none());
        episode_revisions.push(current.clone());
    }

    assert_eq!(current.operation_burst_refs.len(), 2);
    assert_eq!(current.semantic_watermark, base.semantic_watermark);
    let current_bursts = burst_revisions
        .into_iter()
        .fold(BTreeMap::new(), |mut values, burst| {
            let replace = values.get(&burst.operation_burst_id).is_none_or(
                |current: &evertrace_domain::work::OperationBurst| {
                    current.revision_generation < burst.revision_generation
                },
            );
            if replace {
                values.insert(burst.operation_burst_id, burst);
            }
            values
        })
        .into_values()
        .collect::<Vec<_>>();
    assert_eq!(
        current_bursts
            .iter()
            .map(|burst| burst.members.len())
            .sum::<usize>(),
        65
    );
    let binding_ids = current_bursts
        .iter()
        .flat_map(|burst| {
            burst
                .members
                .iter()
                .map(|member| member.work_binding_revision_id)
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(binding_ids.len(), 65);
    let relations =
        build_operation_burst_relation_rows(std::slice::from_ref(&current), &current_bursts)
            .unwrap();
    assert_eq!(
        relations
            .iter()
            .filter(|row| row.kind == OperationBurstRelationKind::BurstToBindingRevision)
            .count(),
        65
    );
}

#[tokio::test]
async fn exact_replay_cannot_advance_journal_or_object_projection() {
    use evertrace_engine::NormalizationSnapshot;

    let root = task();
    let mut stream = stream(root.task_id, 2);
    let episode = new_episode(&stream, None, 2).unwrap();
    let mut observed = token(&episode, 1, "replay");
    let operation = observed
        .view
        .authority()
        .operation(observed.operation_id)
        .unwrap()
        .clone();
    let occurrence = observed
        .view
        .authority()
        .occurrence(operation.host_occurrence_id)
        .unwrap()
        .clone();
    let lane = observed
        .view
        .authority()
        .lane(operation.execution_lane_id.unwrap())
        .unwrap()
        .clone();
    let mut binding = observed
        .view
        .authority()
        .binding(observed.operation_id)
        .unwrap()
        .clone();
    let mut initial_binding = binding.clone();
    initial_binding.work_binding_revision_id = WorkBindingRevisionId::new_v7();
    initial_binding.predecessor_revision_id = None;
    initial_binding.revision_generation = 1;
    initial_binding.primary_binding.episode_id = None;
    initial_binding.validate().unwrap();
    binding.predecessor_revision_id = Some(initial_binding.work_binding_revision_id);
    binding.revision_generation = 2;
    binding.validate().unwrap();
    episode.validate().unwrap();
    stream.execution_lane_ids = vec![lane.execution_lane_id];
    stream.validate().unwrap();

    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let (source_receipt, source_observation) = source_evidence(1);
    let source_revision_ref = format!(
        "{}@{}",
        source_receipt.source_instance_id.as_str(),
        source_receipt.source_revision.as_str()
    );
    observed.receipt.source_revision_refs = vec![source_revision_ref.clone()];
    observed.receipt.source_close_watermark_refs = vec![format!("{source_revision_ref}:1")];
    observed.receipt.source_close_reconciliation_refs.clear();
    observed.receipt.source_coverage = SourceCoverage::Partial;
    observed.receipt.coverage_level = CoverageLevel::Partial;
    observed.receipt.validate().unwrap();
    writer
        .commit(&evidence_command(source_receipt, source_observation), 1)
        .await
        .unwrap();
    writer
        .commit(
            &NormalizationSnapshot {
                occurrences: vec![occurrence.clone()],
                operations: vec![operation.clone()],
                scope_effects: vec![],
            }
            .journal_command(CommandId::new_v7(), 2, CONFIG, "s15-physical-v1")
            .unwrap(),
            2,
        )
        .await
        .unwrap();
    writer
        .commit(
            &command(
                3,
                vec![
                    JournalPayload::TaskRecorded(Box::new(root)),
                    JournalPayload::WorkstreamRecorded(Box::new(stream.clone())),
                ],
            ),
            3,
        )
        .await
        .unwrap();
    writer
        .commit(
            &command(
                4,
                vec![JournalPayload::WorkBindingRecorded(Box::new(
                    initial_binding,
                ))],
            ),
            4,
        )
        .await
        .unwrap();
    writer
        .commit(
            &command(
                5,
                vec![
                    JournalPayload::ExecutionLaneRecorded(Box::new(lane)),
                    JournalPayload::CaptureReceiptRecorded(Box::new(observed.receipt.clone())),
                ],
            ),
            5,
        )
        .await
        .unwrap();
    writer
        .commit(
            &activate_episode(context(6), &stream, episode.clone(), vec![], vec![binding]).unwrap(),
            6,
        )
        .await
        .unwrap();
    let authority = writer.project().await.unwrap();
    observed.view = SegmentationCurrentState::from_snapshot(&authority).unwrap();
    let mut segmenter = IncrementalSegmenter::new(&observed.view, episode.episode_id).unwrap();
    let step = push_token(&mut segmenter, observed.clone()).unwrap();
    let save_context = context(10);
    let prepared = save_segmentation_update(
        save_context,
        &episode,
        &step,
        std::slice::from_ref(&observed.receipt),
    )
    .unwrap();
    assert_eq!(
        segmenter
            .observe(
                &observed.view,
                observed.operation_id,
                observed.facts.clone(),
            )
            .unwrap(),
        SegmentOutcome::Delta(Box::new(step.clone()))
    );
    assert_eq!(
        prepared,
        save_segmentation_update(
            save_context,
            &episode,
            &step,
            std::slice::from_ref(&observed.receipt),
        )
        .unwrap()
    );
    let different = token(&episode, 2, "replay");
    assert!(
        segmenter
            .observe(&different.view, different.operation_id, different.facts)
            .is_err()
    );
    assert_eq!(writer.project().await.unwrap(), authority);
    let committed = writer.commit(&prepared, 7).await.unwrap();
    assert!(!committed.replayed);
    let after_commit = writer.project().await.unwrap();
    assert!(after_commit.frontier > authority.frontier);
    assert!(after_commit.rows.len() > authority.rows.len());
    assert!(writer.commit(&prepared, 8).await.unwrap().replayed);
    assert_eq!(writer.project().await.unwrap(), after_commit);
    let current_episode = EpisodeCurrentView::from_snapshot(&after_commit)
        .unwrap()
        .episodes[&episode.episode_id]
        .clone();
    let current_burst = OperationBurstCurrentView::from_snapshot(&after_commit)
        .unwrap()
        .recent_for_episode(&current_episode)
        .unwrap()
        .pop()
        .unwrap();
    let mut closed_burst = current_burst.clone();
    closed_burst.revision_id = RevisionId::new_v7();
    closed_burst.predecessor_revision_id = Some(current_burst.revision_id);
    closed_burst.revision_generation += 1;
    closed_burst.lifecycle = evertrace_domain::work::OperationBurstLifecycle::Closed;
    current_burst.validate_successor(&closed_burst).unwrap();
    let mut duplicate_burst = current_burst.clone();
    duplicate_burst.operation_burst_id = evertrace_domain::ids::OperationBurstId::new_v7();
    duplicate_burst.revision_id = RevisionId::new_v7();
    duplicate_burst.predecessor_revision_id = None;
    duplicate_burst.revision_generation = 1;
    let mut forged_episode = current_episode.clone();
    forged_episode.revision_id = RevisionId::new_v7();
    forged_episode.predecessor_revision_id = Some(current_episode.revision_id);
    forged_episode.revision_generation += 1;
    forged_episode
        .operation_burst_refs
        .push(duplicate_burst.operation_burst_id);
    forged_episode.operation_burst_refs.sort();
    current_episode.validate_successor(&forged_episode).unwrap();
    assert!(
        writer
            .commit(
                &command(
                    9,
                    vec![
                        JournalPayload::OperationBurstRecorded(Box::new(closed_burst)),
                        JournalPayload::OperationBurstRecorded(Box::new(duplicate_burst)),
                        JournalPayload::WorkEpisodeRecorded(Box::new(forged_episode)),
                    ],
                ),
                9,
            )
            .await
            .is_err()
    );
    assert_eq!(writer.project().await.unwrap(), after_commit);
    let current_view = SegmentationCurrentState::from_snapshot(&after_commit).unwrap();
    assert!(
        segmenter
            .acknowledge_committed(&observed.view, &step)
            .is_err()
    );
    let missing_burst = SegmentationCurrentState::from_snapshot(&ProjectionSnapshot {
        frontier: after_commit.frontier,
        rows: after_commit
            .rows
            .iter()
            .filter(|row| row.object_kind.as_deref() != Some("operation_burst"))
            .cloned()
            .collect(),
    })
    .unwrap();
    assert!(
        segmenter
            .acknowledge_committed(&missing_burst, &step)
            .is_err()
    );
    let stale_episode = SegmentationCurrentState::from_snapshot(&ProjectionSnapshot {
        frontier: after_commit.frontier,
        rows: after_commit
            .rows
            .iter()
            .filter(|row| {
                if row.object_kind.as_deref() != Some("work_episode") {
                    return true;
                }
                let payload: JournalPayload =
                    serde_json::from_str(row.payload_json.as_deref().unwrap()).unwrap();
                !matches!(payload, JournalPayload::WorkEpisodeRecorded(value) if value.revision_id == current_episode.revision_id)
            })
            .cloned()
            .collect(),
    })
    .unwrap();
    assert!(
        segmenter
            .acknowledge_committed(&stale_episode, &step)
            .is_err()
    );
    segmenter
        .acknowledge_committed(&current_view, &step)
        .unwrap();
    assert!(
        segmenter
            .observe(
                &observed.view,
                observed.operation_id,
                observed.facts.clone(),
            )
            .is_err()
    );
    assert_eq!(
        segmenter
            .observe(&current_view, observed.operation_id, observed.facts.clone(),)
            .unwrap(),
        SegmentOutcome::NoDelta
    );
    let mut restarted =
        IncrementalSegmenter::restore(&current_view, current_episode.episode_id).unwrap();
    assert_eq!(
        restarted
            .observe(&current_view, observed.operation_id, observed.facts.clone())
            .unwrap(),
        SegmentOutcome::NoDelta
    );
    assert_eq!(writer.project().await.unwrap(), after_commit);

    let mut operation_successor = operation;
    operation_successor.previous_operation_revision = Some(operation_successor.operation_revision);
    operation_successor.operation_revision += 1;
    writer
        .commit(
            &NormalizationSnapshot {
                occurrences: vec![occurrence],
                operations: vec![operation_successor],
                scope_effects: vec![],
            }
            .journal_command(CommandId::new_v7(), 10, CONFIG, "s15-physical-v1")
            .unwrap(),
            10,
        )
        .await
        .unwrap();
    let next_projection = writer.project().await.unwrap();
    assert_eq!(
        next_projection
            .rows
            .iter()
            .filter(|row| row.object_kind.as_deref() == Some("operation"))
            .count(),
        2
    );
    assert!(
        next_projection
            .rows
            .iter()
            .all(|row| row.object_kind.as_deref() != Some("operation_revision"))
    );
    let next_view = SegmentationCurrentState::from_snapshot(&next_projection).unwrap();
    let mut next_facts = observed.facts;
    next_facts.sequence += 1;
    next_facts.source_watermark += 1;
    assert!(matches!(
        segmenter
            .observe(&next_view, observed.operation_id, next_facts)
            .unwrap(),
        SegmentOutcome::Delta(_)
    ));
}

#[test]
fn checked_current_authority_rejects_each_forged_input() {
    let root = task();
    let stream = stream(root.task_id, 2);
    let episode = new_episode(&stream, None, 2).unwrap();
    for fault in [
        TokenFault::OccurrenceConflict,
        TokenFault::OperationOccurrence,
        TokenFault::BindingOperation,
        TokenFault::BindingUnresolved,
        TokenFault::LaneReverse,
        TokenFault::ReceiptLane,
    ] {
        let Ok(observed) = try_token_with(&episode, 1, "a", None, |_| {}, Some(fault)) else {
            continue;
        };
        let mut segmenter = IncrementalSegmenter::new(&observed.view, episode.episode_id).unwrap();
        assert!(
            segmenter
                .observe(&observed.view, observed.operation_id, observed.facts)
                .is_err()
        );
    }
}

#[test]
fn typed_current_view_folds_three_generation_chains_independent_of_row_order() {
    let root = task();
    let stream = stream(root.task_id, 2);
    let episode = new_episode(&stream, None, 2).unwrap();
    let observed = token(&episode, 1, "three-generation");
    let mut rows = observed.rows.clone();
    for kind in ["host_occurrence", "operation", "execution_lane"] {
        let original = rows
            .iter()
            .find(|row| row.object_kind.as_deref() == Some(kind))
            .unwrap();
        let mut previous: JournalPayload =
            serde_json::from_str(original.payload_json.as_deref().unwrap()).unwrap();
        for revision in 2..=3 {
            let mut next = previous.clone();
            match &mut next {
                JournalPayload::HostOccurrenceNormalized(value) => {
                    value.previous_normalization_revision = Some(value.normalization_revision);
                    value.normalization_revision = revision;
                }
                JournalPayload::OperationDerived(value) => {
                    value.previous_operation_revision = Some(value.operation_revision);
                    value.operation_revision = revision;
                }
                JournalPayload::ExecutionLaneRecorded(value) => {
                    value.predecessor_revision = Some(value.lane_revision);
                    value.lane_revision = revision;
                }
                _ => unreachable!(),
            }
            rows.push(current_row(kind, &next));
            previous = next;
        }
    }
    rows.reverse();
    let view = SegmentationCurrentView::from_snapshot(&ProjectionSnapshot {
        frontier: 300,
        rows: rows.clone(),
    })
    .unwrap();
    let operation = view.operation(observed.operation_id).unwrap();
    assert_eq!(operation.operation_revision, 3);
    assert_eq!(
        view.occurrence(operation.host_occurrence_id)
            .unwrap()
            .normalization_revision,
        3
    );
    assert_eq!(
        view.lane(operation.execution_lane_id.unwrap())
            .unwrap()
            .lane_revision,
        3
    );

    let mut gap = rows.clone();
    gap.retain(|row| {
        if row.object_kind.as_deref() != Some("operation") {
            return true;
        }
        let payload: JournalPayload =
            serde_json::from_str(row.payload_json.as_deref().unwrap()).unwrap();
        !matches!(payload, JournalPayload::OperationDerived(value) if value.operation_revision == 2)
    });
    assert!(
        SegmentationCurrentView::from_snapshot(&ProjectionSnapshot {
            frontier: 300,
            rows: gap,
        })
        .is_err()
    );
    let mut obsolete_kind = rows.clone();
    let mut obsolete_row = obsolete_kind
        .iter()
        .find(|row| row.object_kind.as_deref() == Some("operation"))
        .unwrap()
        .clone();
    obsolete_row.object_kind = Some("operation_revision".into());
    obsolete_kind.push(obsolete_row);
    assert!(
        SegmentationCurrentView::from_snapshot(&ProjectionSnapshot {
            frontier: 300,
            rows: obsolete_kind,
        })
        .is_err()
    );
    let fork_row = rows
        .iter()
        .find(|row| {
            row.object_kind.as_deref() == Some("execution_lane")
                && serde_json::from_str::<JournalPayload>(row.payload_json.as_deref().unwrap())
                    .is_ok_and(|payload| matches!(payload, JournalPayload::ExecutionLaneRecorded(value) if value.lane_revision == 3))
        })
        .unwrap()
        .clone();
    rows.push(fork_row);
    assert!(
        SegmentationCurrentView::from_snapshot(&ProjectionSnapshot {
            frontier: 300,
            rows,
        })
        .is_err()
    );
}

#[test]
fn ambiguous_attempt_group_context_fails_closed_without_a_primary_binding_ref() {
    let root = task();
    let stream = stream(root.task_id, 2);
    let mut episode = new_episode(&stream, None, 2).unwrap();
    let attempt_id = evertrace_domain::ids::AttemptId::new_v7();
    episode.attempt_ids = vec![attempt_id];
    let mut observed = token_with(&episode, 1, "group", Some(attempt_id), |_| {});
    let mut groups = vec![
        CompetingAttemptGroupId::new_v7(),
        CompetingAttemptGroupId::new_v7(),
    ];
    groups.sort();
    for row in &mut observed.rows {
        if row.object_kind.as_deref() != Some("attempt") {
            continue;
        }
        let mut payload: JournalPayload =
            serde_json::from_str(row.payload_json.as_deref().unwrap()).unwrap();
        let JournalPayload::AttemptRecorded(attempt) = &mut payload else {
            unreachable!();
        };
        attempt.competing_group_ids = groups.clone();
        row.payload_json = Some(serde_json::to_string(&payload).unwrap());
    }
    observed.view = SegmentationCurrentState::from_snapshot(&ProjectionSnapshot {
        frontier: 100,
        rows: observed.rows.clone(),
    })
    .unwrap();
    let mut segmenter = IncrementalSegmenter::new(&observed.view, episode.episode_id).unwrap();
    assert!(
        segmenter
            .observe(&observed.view, observed.operation_id, observed.facts)
            .is_err()
    );
}

#[test]
fn structured_surprise_is_derived_and_restores_from_bounded_bursts() {
    let root = task();
    let stream = stream(root.task_id, 2);
    let base = new_episode(&stream, None, 2).unwrap();
    let mut current = base.clone();
    let mut episode_revisions = vec![base.clone()];
    let mut receipts = BTreeMap::new();
    let mut burst_revisions = Vec::new();
    for sequence in 1..=6 {
        let session = if sequence % 2 == 0 {
            "other-lane"
        } else {
            "same-lane"
        };
        let mut observed = token(&base, sequence, session);
        receipts.insert(observed.receipt.execution_lane_id, observed.receipt.clone());
        let state = state_with_history(
            &observed,
            &episode_revisions,
            &burst_revisions,
            100 + sequence,
        );
        let mut segmenter = if burst_revisions.is_empty() {
            IncrementalSegmenter::new(&state, base.episode_id).unwrap()
        } else {
            IncrementalSegmenter::restore(&state, base.episode_id).unwrap()
        };
        observed.view = state.clone();
        let step = push_token(&mut segmenter, observed).unwrap();
        if let Some(closed) = step.closed_burst() {
            burst_revisions.push(closed.clone());
        }
        burst_revisions.push(step.current_burst().clone());
        current = episode_successor_from_step(
            &current,
            &step,
            &receipts.values().cloned().collect::<Vec<_>>(),
        );
        episode_revisions.push(current.clone());
    }
    let mut surprising = token_with(&base, 7, "same-lane", None, |facts| {
        facts.state_delta = StateDeltaKind::Failed;
        facts.error_signature = Some("typed-failure".into());
    });
    receipts.insert(
        surprising.receipt.execution_lane_id,
        surprising.receipt.clone(),
    );
    let surprising_state =
        state_with_history(&surprising, &episode_revisions, &burst_revisions, 107);
    let mut segmenter = IncrementalSegmenter::restore(&surprising_state, base.episode_id).unwrap();
    surprising.view = surprising_state.clone();
    let step = push_token(&mut segmenter, surprising).unwrap();
    assert_eq!(
        step.candidate_kind(),
        Some(evertrace_domain::work::BoundaryCandidateKind::StructuredSurprise)
    );
    if let Some(closed) = step.closed_burst() {
        burst_revisions.push(closed.clone());
    }
    burst_revisions.push(step.current_burst().clone());
    current = episode_successor_from_step(
        &current,
        &step,
        &receipts.values().cloned().collect::<Vec<_>>(),
    );
    episode_revisions.push(current.clone());
    assert_eq!(current.lifecycle_status, EpisodeLifecycle::Open);
    let mut returned_left = token(&base, 8, "same-lane");
    let returned_state =
        state_with_history(&returned_left, &episode_revisions, &burst_revisions, 108);
    let mut retracting = IncrementalSegmenter::restore(&returned_state, base.episode_id).unwrap();
    returned_left.view = returned_state.clone();
    assert!(retracting.rolling_len() <= 64);
    let retract_step = push_token(&mut retracting, returned_left).unwrap();
    assert!(retract_step.candidate_retracted());
    assert_eq!(retract_step.boundary_status(), BoundaryStatus::Provisional);

    let mut objective = token_with(&base, 8, "same-lane", None, |facts| {
        facts.state_delta = StateDeltaKind::Failed;
        facts.error_signature = Some("typed-failure".into());
        facts.observed_phase_kind = Some(PhaseKind::Verify);
        facts.boundary_evidence = BoundaryEvidence::PhaseTransition;
    });
    receipts.insert(
        objective.receipt.execution_lane_id,
        objective.receipt.clone(),
    );
    let objective_state = state_with_history(&objective, &episode_revisions, &burst_revisions, 108);
    let mut objective_segmenter =
        IncrementalSegmenter::restore(&objective_state, base.episode_id).unwrap();
    objective.view = objective_state.clone();
    let objective_step = push_token(&mut objective_segmenter, objective).unwrap();
    assert_eq!(
        objective_step.candidate_kind(),
        Some(evertrace_domain::work::BoundaryCandidateKind::Objective)
    );
    assert_eq!(objective_step.boundary_status(), BoundaryStatus::Candidate);
    let objective_candidate = episode_successor_from_step(
        &current,
        &objective_step,
        &receipts.values().cloned().collect::<Vec<_>>(),
    );
    episode_revisions.push(objective_candidate.clone());
    if let Some(closed) = objective_step.closed_burst() {
        burst_revisions.push(closed.clone());
    }
    burst_revisions.push(objective_step.current_burst().clone());
    let mut supporting = token_with(&base, 9, "same-lane", None, |facts| {
        facts.state_delta = StateDeltaKind::Failed;
        facts.error_signature = Some("typed-failure".into());
        facts.observed_phase_kind = Some(PhaseKind::Verify);
        facts.boundary_evidence = BoundaryEvidence::ObjectiveOutcomeClosure;
    });
    receipts.insert(
        supporting.receipt.execution_lane_id,
        supporting.receipt.clone(),
    );
    let supporting_state =
        state_with_history(&supporting, &episode_revisions, &burst_revisions, 109);
    let mut supporting_segmenter =
        IncrementalSegmenter::restore(&supporting_state, base.episode_id).unwrap();
    supporting.view = supporting_state.clone();
    let supporting_step = push_token(&mut supporting_segmenter, supporting).unwrap();
    assert_eq!(supporting_step.boundary_status(), BoundaryStatus::Confirmed);
    assert!(
        confirm_episode_boundary(
            &objective_candidate,
            &supporting_step,
            None,
            &receipts.values().cloned().collect::<Vec<_>>(),
        )
        .is_ok()
    );
}

#[test]
fn confirmed_close_atomically_closes_the_current_burst() {
    let root = task();
    let initial_stream = stream(root.task_id, 2);
    let base = new_episode(&initial_stream, None, 2).unwrap();
    let mut stream = initial_stream.clone();
    stream.revision_id = RevisionId::new_v7();
    stream.predecessor_revision_id = Some(initial_stream.revision_id);
    stream.active_episode_id = Some(base.episode_id);
    stream.validate().unwrap();
    let mut objective = token_with(&base, 1, "close", None, |facts| {
        facts.observed_phase_kind = Some(PhaseKind::Verify);
        facts.boundary_evidence = BoundaryEvidence::PhaseTransition;
    });
    let objective_state = state_with_history(&objective, std::slice::from_ref(&base), &[], 100);
    let mut segmenter = IncrementalSegmenter::new(&objective_state, base.episode_id).unwrap();
    objective.view = objective_state.clone();
    let objective_step = push_token(&mut segmenter, objective.clone()).unwrap();
    let candidate = episode_successor_from_step(
        &base,
        &objective_step,
        std::slice::from_ref(&objective.receipt),
    );
    let mut supporting = token_with(&base, 2, "close", None, |facts| {
        facts.observed_phase_kind = Some(PhaseKind::Verify);
        facts.boundary_evidence = BoundaryEvidence::ObjectiveOutcomeClosure;
    });
    let supporting_state = state_with_history(
        &supporting,
        &[base.clone(), candidate.clone()],
        std::slice::from_ref(objective_step.current_burst()),
        101,
    );
    let mut segmenter = IncrementalSegmenter::restore(&supporting_state, base.episode_id).unwrap();
    supporting.view = supporting_state.clone();
    let supporting_step = push_token(&mut segmenter, supporting.clone()).unwrap();
    let closed = confirm_episode_boundary(
        &candidate,
        &supporting_step,
        None,
        std::slice::from_ref(&supporting.receipt),
    )
    .unwrap();
    let command = close_episode_and_optionally_open(
        context(5),
        &stream,
        &candidate,
        closed,
        Some(&supporting_step),
        None,
        vec![],
        vec![],
    )
    .unwrap();
    assert!(command.events().iter().any(|event| {
        matches!(
            &event.payload,
            JournalPayload::OperationBurstRecorded(value)
                if value.lifecycle == evertrace_domain::work::OperationBurstLifecycle::Closed
        )
    }));
}

fn command(at: i64, payloads: Vec<JournalPayload>) -> JournalCommand {
    JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, CONFIG, "s15-episode-v1", payload))
            .collect(),
    )
    .unwrap()
}

#[test]
fn episode_successor_rejects_generation_overflow_counters_and_fact_shrinkage() {
    let root = task();
    let stream = stream(root.task_id, 2);
    let mut episode = new_episode(&stream, None, 2).unwrap();
    episode.revision_generation = u64::MAX;
    episode.predecessor_revision_id = Some(RevisionId::new_v7());
    episode.session_ids = vec!["session-a".into()];
    episode.failure_refs = vec!["failure-a".into()];
    episode.validate().unwrap();
    let mut overflow = episode.clone();
    overflow.revision_id = RevisionId::new_v7();
    overflow.predecessor_revision_id = Some(episode.revision_id);
    overflow.source_watermark += 1;
    overflow.pending_semantic_delta = Some(evertrace_domain::work::PendingSemanticInterval {
        after_watermark: 0,
        through_watermark: overflow.source_watermark,
    });
    assert!(episode.validate_successor(&overflow).is_err());

    let mut normal = new_episode(&stream, None, 2).unwrap();
    normal.session_ids = vec!["session-a".into()];
    normal.failure_refs = vec!["failure-a".into()];
    normal.pending_delta_stats.selected_token_count = u32::MAX;
    normal.validate().unwrap();
    let checked = token(&normal, 1, "session-b");
    let mut segmenter = IncrementalSegmenter::new(&checked.view, normal.episode_id).unwrap();
    let step = push_token(&mut segmenter, checked.clone()).unwrap();
    assert!(
        save_segmentation_update(
            context(3),
            &normal,
            &step,
            std::slice::from_ref(&checked.receipt),
        )
        .is_err()
    );
    let mut shrunk = normal.clone();
    shrunk.revision_id = RevisionId::new_v7();
    shrunk.predecessor_revision_id = Some(normal.revision_id);
    shrunk.revision_generation += 1;
    shrunk.source_watermark += 1;
    shrunk.session_ids.clear();
    shrunk.failure_refs.clear();
    shrunk.pending_semantic_delta = Some(evertrace_domain::work::PendingSemanticInterval {
        after_watermark: 0,
        through_watermark: shrunk.source_watermark,
    });
    assert!(normal.validate_successor(&shrunk).is_err());
}

#[test]
fn binding_episode_link_is_once_only_and_cannot_switch_or_clear() {
    let root = task();
    let stream = stream(root.task_id, 2);
    let episode = new_episode(&stream, None, 2).unwrap();
    let current = WorkBindingRevision {
        work_binding_revision_id: WorkBindingRevisionId::new_v7(),
        operation_id: OperationId::new_v7(),
        revision_generation: 1,
        predecessor_revision_id: None,
        primary_binding: PrimaryWorkBinding {
            task_id: Some(root.task_id),
            workstream_id: Some(stream.workstream_id),
            ..PrimaryWorkBinding::default()
        },
        secondary_bindings: vec![],
        scope_effect_refs: vec![],
        assignment_status: AssignmentStatus::Resolved,
        evidence_refs: vec!["resolved-binding".into()],
        resolver_version: 1,
    };
    current.validate().unwrap();
    let mut linked = current.clone();
    linked.work_binding_revision_id = WorkBindingRevisionId::new_v7();
    linked.predecessor_revision_id = Some(current.work_binding_revision_id);
    linked.revision_generation = 2;
    linked.primary_binding.episode_id = Some(episode.episode_id);
    current.validate_successor(&linked).unwrap();

    let mut stable = linked.clone();
    stable.work_binding_revision_id = WorkBindingRevisionId::new_v7();
    stable.predecessor_revision_id = Some(linked.work_binding_revision_id);
    stable.revision_generation = 3;
    linked.validate_successor(&stable).unwrap();
    let mut switched = stable.clone();
    switched.primary_binding.episode_id = Some(WorkEpisodeId::new_v7());
    assert!(linked.validate_successor(&switched).is_err());
    let mut cleared = stable;
    cleared.primary_binding.episode_id = None;
    assert!(linked.validate_successor(&cleared).is_err());
}

#[test]
fn workstream_activation_watermark_overflow_fails_closed() {
    let root = task();
    let stream = stream(root.task_id, u64::MAX);
    let episode = new_episode(&stream, None, u64::MAX).unwrap();
    assert!(activate_episode(context(2), &stream, episode, vec![], vec![]).is_err());
}

#[test]
fn checkpoint_has_natural_idempotency_and_never_changes_episode_boundary() {
    let root = task();
    let stream = stream(root.task_id, 2);
    let episode = new_episode(&stream, None, 2).unwrap();
    let checkpoint =
        match build_checkpoint(&episode, &[], None, CheckpointReason::Stop, None).unwrap() {
            CheckpointResolution::Checkpoint(value) => *value,
            CheckpointResolution::NoDelta => panic!("first checkpoint must materialize"),
        };
    assert!(
        !serde_json::to_string(&checkpoint)
            .unwrap()
            .contains("narrative")
    );
    assert_eq!(
        build_checkpoint(
            &episode,
            &[],
            None,
            CheckpointReason::Stop,
            Some(&checkpoint)
        )
        .unwrap(),
        CheckpointResolution::NoDelta
    );
    for reason in [
        CheckpointReason::SessionEnd,
        CheckpointReason::Compact,
        CheckpointReason::Idle,
        CheckpointReason::Manual,
    ] {
        let value = build_checkpoint(&episode, &[], None, reason, None).unwrap();
        assert!(matches!(value, CheckpointResolution::Checkpoint(_)));
    }
    assert_eq!(episode.lifecycle_status, EpisodeLifecycle::Open);
    assert_eq!(episode.boundary_status, BoundaryStatus::Provisional);
    assert_eq!(episode.semantic_watermark, 0);
}

#[test]
fn checkpoint_attempt_refs_are_exact_and_mixed_verification_is_inconclusive() {
    let root = task();
    let stream = stream(root.task_id, 2);
    let strategy = StrategyContract {
        hypothesis: "checkpoint evidence".into(),
        intervention: "verify".into(),
        intervention_family: "verification".into(),
        search_policy_ref: None,
        objective_ref: Some("objective:s15".into()),
        expected_effect: "typed verifier".into(),
        target_refs: vec!["episode".into()],
        acceptance_boundary_ref: "objective:s15".into(),
    };
    let first = new_attempt(
        root.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        strategy.clone(),
        2,
    )
    .unwrap();
    let second = new_attempt(
        root.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        strategy,
        2,
    )
    .unwrap();
    let mut episode = new_episode(&stream, None, 2).unwrap();
    episode.attempt_ids = vec![first.attempt_id, second.attempt_id];
    episode.attempt_ids.sort();
    let mut passed = link_attempt_to_episode(&first, &episode, 3).unwrap();
    passed.verification = evertrace_domain::work::AttemptVerification::Passed;
    passed.parent_verification_refs = vec!["verifier:passed".into()];
    passed.validate().unwrap();
    let mut failed = link_attempt_to_episode(&second, &episode, 3).unwrap();
    failed.verification = evertrace_domain::work::AttemptVerification::Failed;
    failed.parent_verification_refs = vec!["verifier:failed".into()];
    failed.validate().unwrap();
    let checkpoint = match build_checkpoint(
        &episode,
        &[passed.clone(), failed.clone()],
        None,
        CheckpointReason::Manual,
        None,
    )
    .unwrap()
    {
        CheckpointResolution::Checkpoint(value) => *value,
        CheckpointResolution::NoDelta => unreachable!(),
    };
    assert_eq!(
        checkpoint.verifier_state,
        CheckpointVerifierState::Inconclusive
    );
    assert_eq!(checkpoint.attempt_revision_refs.len(), 2);
    assert!(
        build_checkpoint(
            &episode,
            &[passed.clone(), passed],
            None,
            CheckpointReason::Manual,
            None,
        )
        .is_err()
    );
}

#[test]
fn capture_summary_degrades_each_integrity_dimension() {
    let full = receipt();
    assert_eq!(
        capture_summary(std::slice::from_ref(&full))
            .unwrap()
            .minimum_coverage_level,
        CoverageLevel::Full
    );
    for mutate in [
        |value: &mut CaptureReceipt| value.source_coverage = SourceCoverage::Partial,
        |value: &mut CaptureReceipt| value.pairing_integrity = PairingIntegrity::Unmatched,
        |value: &mut CaptureReceipt| {
            value.payload_integrity = PayloadIntegrity::Truncated;
            value.exact_byte_replay = false;
        },
        |value: &mut CaptureReceipt| value.ordering_integrity = OrderingIntegrity::Gapped,
    ] {
        let mut degraded = full.clone();
        mutate(&mut degraded);
        assert_eq!(
            capture_summary(&[degraded]).unwrap().minimum_coverage_level,
            CoverageLevel::Partial
        );
    }
    let mut opaque = full;
    opaque.coverage_level = CoverageLevel::Opaque;
    assert_eq!(
        capture_summary(&[opaque]).unwrap().minimum_coverage_level,
        CoverageLevel::Opaque
    );
}

#[test]
fn receipt_replacement_is_one_per_lane_and_capture_frontier_is_minimum() {
    let root = task();
    let stream = stream(root.task_id, 2);
    let mut episode = new_episode(&stream, None, 3).unwrap();
    let old_token = token(&episode, 1, "capture-min");
    let other_lane = ExecutionLaneId::new_v7();
    let other_receipt = receipt_for(other_lane, 1);
    episode.execution_lane_ids = vec![old_token.receipt.execution_lane_id, other_lane];
    episode.execution_lane_ids.sort();
    episode.capture_receipt_revision_ids = vec![
        old_token.receipt.capture_receipt_revision_id,
        other_receipt.capture_receipt_revision_id,
    ];
    episode.capture_receipt_revision_ids.sort();
    episode.capture_summary =
        capture_summary(&[old_token.receipt.clone(), other_receipt.clone()]).unwrap();
    episode.capture_watermark = 1;
    episode.validate().unwrap();

    let replacement = token(&episode, 2, "capture-min");
    let mut segmenter = IncrementalSegmenter::new(&replacement.view, episode.episode_id).unwrap();
    let step = push_token(&mut segmenter, replacement.clone()).unwrap();
    let revised = episode_successor_from_step(
        &episode,
        &step,
        &[replacement.receipt.clone(), other_receipt],
    );
    assert_eq!(revised.capture_receipt_revision_ids.len(), 2);
    assert!(
        !revised
            .capture_receipt_revision_ids
            .contains(&old_token.receipt.capture_receipt_revision_id)
    );
    assert!(
        revised
            .capture_receipt_revision_ids
            .contains(&replacement.receipt.capture_receipt_revision_id)
    );
    assert_eq!(revised.capture_watermark, 1);
}

#[tokio::test]
async fn atomic_activation_checkpoint_replay_and_four_table_restart_are_stable() {
    let temp = TempDir::new().unwrap();
    let root = task();
    let stream = stream(root.task_id, 2);
    let strategy = StrategyContract {
        hypothesis: "same episode strategy".into(),
        intervention: "edit".into(),
        intervention_family: "implementation".into(),
        search_policy_ref: None,
        objective_ref: Some("objective:s15".into()),
        expected_effect: "pass".into(),
        target_refs: vec!["episode".into()],
        acceptance_boundary_ref: "objective:s15".into(),
    };
    let attempt = new_attempt(
        root.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        strategy,
        2,
    )
    .unwrap();
    let mut episode = new_episode(&stream, None, 2).unwrap();
    episode.attempt_ids = vec![attempt.attempt_id];
    episode.validate().unwrap();
    let linked = link_attempt_to_episode(&attempt, &episode, 3).unwrap();

    let store = temp.path().join("store");
    let mut writer = JournalWriter::open(&store).await.unwrap();
    let before_forged = writer.project().await.unwrap();
    let mut forged_initial = stream.clone();
    forged_initial.active_episode_id = Some(episode.episode_id);
    let forged_command = command(
        1,
        vec![
            JournalPayload::TaskRecorded(Box::new(root.clone())),
            JournalPayload::WorkstreamRecorded(Box::new(forged_initial)),
            JournalPayload::WorkEpisodeRecorded(Box::new(episode.clone())),
        ],
    );
    assert!(writer.commit(&forged_command, 1).await.is_err());
    assert_eq!(writer.project().await.unwrap(), before_forged);
    writer
        .commit(
            &command(
                1,
                vec![
                    JournalPayload::TaskRecorded(Box::new(root)),
                    JournalPayload::WorkstreamRecorded(Box::new(stream.clone())),
                    JournalPayload::AttemptRecorded(Box::new(attempt)),
                ],
            ),
            1,
        )
        .await
        .unwrap();
    writer
        .commit(
            &activate_episode(
                context(2),
                &stream,
                episode.clone(),
                vec![linked.clone()],
                vec![],
            )
            .unwrap(),
            2,
        )
        .await
        .unwrap();
    let snapshot = writer.project().await.unwrap();
    let current = EpisodeCurrentView::from_snapshot(&snapshot)
        .unwrap()
        .episodes[&episode.episode_id]
        .clone();
    assert_eq!(current.episode_id, episode.episode_id);
    let checkpoint = match build_checkpoint(
        &current,
        std::slice::from_ref(&linked),
        None,
        CheckpointReason::Stop,
        None,
    )
    .unwrap()
    {
        CheckpointResolution::Checkpoint(value) => *value,
        CheckpointResolution::NoDelta => unreachable!(),
    };
    let orphan = command(
        3,
        vec![JournalPayload::WorkCheckpointRecorded(Box::new(
            checkpoint.clone(),
        ))],
    );
    assert!(writer.commit(&orphan, 3).await.is_err());
    let mut cross_episode = checkpoint.clone();
    cross_episode.episode_id = WorkEpisodeId::new_v7();
    let forged = command(
        3,
        vec![JournalPayload::WorkCheckpointRecorded(Box::new(
            cross_episode,
        ))],
    );
    assert!(writer.commit(&forged, 3).await.is_err());
    let save = save_checkpoint(context(3), &current, checkpoint, None)
        .unwrap()
        .unwrap();
    let committed = writer.commit(&save, 3).await.unwrap();
    assert!(writer.commit(&save, 4).await.unwrap().replayed);
    assert!(committed.first_seq > 0);
    let incremental = writer.project().await.unwrap();
    let full = reduce_journal(&writer.journal_rows().await.unwrap()).unwrap();
    assert_eq!(incremental, full);
    assert_eq!(writer.table_names().await.unwrap().len(), 4);
    drop(writer);
    let writer = JournalWriter::open(&store).await.unwrap();
    assert_eq!(writer.project().await.unwrap(), full);
}

#[tokio::test]
async fn one_session_keeps_two_workstreams_in_distinct_open_episodes() {
    let temp = TempDir::new().unwrap();
    let root = task();
    let first = stream(root.task_id, 2);
    let second = stream(root.task_id, 2);
    let mut first_episode = new_episode(&first, None, 2).unwrap();
    first_episode.session_ids = vec!["shared-session".into()];
    first_episode.validate().unwrap();
    let mut second_episode = new_episode(&second, None, 2).unwrap();
    second_episode.session_ids = vec!["shared-session".into()];
    second_episode.validate().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    writer
        .commit(
            &command(
                1,
                vec![
                    JournalPayload::TaskRecorded(Box::new(root)),
                    JournalPayload::WorkstreamRecorded(Box::new(first.clone())),
                    JournalPayload::WorkstreamRecorded(Box::new(second.clone())),
                ],
            ),
            1,
        )
        .await
        .unwrap();
    writer
        .commit(
            &activate_episode(context(2), &first, first_episode.clone(), vec![], vec![]).unwrap(),
            2,
        )
        .await
        .unwrap();
    writer
        .commit(
            &activate_episode(context(3), &second, second_episode.clone(), vec![], vec![]).unwrap(),
            3,
        )
        .await
        .unwrap();
    let snapshot = writer.project().await.unwrap();
    let episodes = EpisodeCurrentView::from_snapshot(&snapshot)
        .unwrap()
        .episodes;
    assert_eq!(episodes.len(), 2);
    assert_ne!(first_episode.episode_id, second_episode.episode_id);
    assert_eq!(
        episodes[&first_episode.episode_id].session_ids,
        vec!["shared-session"]
    );
    assert_eq!(
        episodes[&second_episode.episode_id].session_ids,
        vec!["shared-session"]
    );
}

#[tokio::test]
async fn correction_is_successor_only_rebuildable_and_rejects_a_lineage_fork() {
    let temp = TempDir::new().unwrap();
    let root = task();
    let stream = stream(root.task_id, 2);
    let episode = new_episode(&stream, None, 2).unwrap();
    let store = temp.path().join("store");
    let mut writer = JournalWriter::open(&store).await.unwrap();
    writer
        .commit(
            &command(
                1,
                vec![
                    JournalPayload::TaskRecorded(Box::new(root)),
                    JournalPayload::WorkstreamRecorded(Box::new(stream.clone())),
                ],
            ),
            1,
        )
        .await
        .unwrap();
    writer
        .commit(
            &activate_episode(context(2), &stream, episode.clone(), vec![], vec![]).unwrap(),
            2,
        )
        .await
        .unwrap();

    let first = SegmentationCorrection {
        correction_revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        kind: CorrectionKind::Retract,
        source_episode_ids: vec![episode.episode_id],
        replacement_episode_ids: vec![],
        evidence_refs: vec!["late-source-revision-1".into()],
        source_watermark: 3,
    };
    let mut successor = episode.clone();
    successor.revision_id = RevisionId::new_v7();
    successor.predecessor_revision_id = Some(episode.revision_id);
    successor.revision_generation = 2;
    successor.source_watermark = 3;
    successor.pending_semantic_delta = Some(evertrace_domain::work::PendingSemanticInterval {
        after_watermark: 0,
        through_watermark: 3,
    });
    successor.segmentation_correction_refs = vec![first.correction_revision_id];
    episode.validate_successor(&successor).unwrap();
    writer
        .commit(
            &record_episode_correction(context(3), first.clone(), vec![successor.clone()], vec![])
                .unwrap(),
            3,
        )
        .await
        .unwrap();

    let child = SegmentationCorrection {
        correction_revision_id: RevisionId::new_v7(),
        predecessor_revision_id: Some(first.correction_revision_id),
        kind: CorrectionKind::Retract,
        source_episode_ids: vec![episode.episode_id],
        replacement_episode_ids: vec![],
        evidence_refs: vec!["late-source-revision-2".into()],
        source_watermark: 4,
    };
    let mut child_successor = successor.clone();
    child_successor.revision_id = RevisionId::new_v7();
    child_successor.predecessor_revision_id = Some(successor.revision_id);
    child_successor.revision_generation = 3;
    child_successor.source_watermark = 4;
    child_successor.pending_semantic_delta =
        Some(evertrace_domain::work::PendingSemanticInterval {
            after_watermark: 0,
            through_watermark: 4,
        });
    child_successor
        .segmentation_correction_refs
        .push(child.correction_revision_id);
    child_successor.segmentation_correction_refs.sort();
    successor.validate_successor(&child_successor).unwrap();
    writer
        .commit(
            &record_episode_correction(context(4), child, vec![child_successor.clone()], vec![])
                .unwrap(),
            4,
        )
        .await
        .unwrap();

    let fork = SegmentationCorrection {
        correction_revision_id: RevisionId::new_v7(),
        predecessor_revision_id: Some(first.correction_revision_id),
        kind: CorrectionKind::Retract,
        source_episode_ids: vec![episode.episode_id],
        replacement_episode_ids: vec![],
        evidence_refs: vec!["late-source-revision-fork".into()],
        source_watermark: 5,
    };
    let mut fork_successor = child_successor.clone();
    fork_successor.revision_id = RevisionId::new_v7();
    fork_successor.predecessor_revision_id = Some(child_successor.revision_id);
    fork_successor.revision_generation = 4;
    fork_successor.source_watermark = 5;
    fork_successor.pending_semantic_delta = Some(evertrace_domain::work::PendingSemanticInterval {
        after_watermark: 0,
        through_watermark: 5,
    });
    fork_successor
        .segmentation_correction_refs
        .push(fork.correction_revision_id);
    fork_successor.segmentation_correction_refs.sort();
    let fork_command =
        record_episode_correction(context(5), fork, vec![fork_successor], vec![]).unwrap();
    assert!(writer.commit(&fork_command, 5).await.is_err());

    let incremental = writer.project().await.unwrap();
    let full = reduce_journal(&writer.journal_rows().await.unwrap()).unwrap();
    assert_eq!(incremental, full);
    drop(writer);
    let writer = JournalWriter::open(&store).await.unwrap();
    assert_eq!(writer.project().await.unwrap(), full);
}

#[tokio::test]
async fn episode_pins_receipt_revision_across_capture_successor_and_restart() {
    let temp = TempDir::new().unwrap();
    let root = task();
    let mut stream = stream(root.task_id, 2);
    let lane_id = ExecutionLaneId::new_v7();
    let operation_id = OperationId::new_v7();
    let mut old_receipt = receipt_for(lane_id, 2);
    old_receipt.lifecycle_end_seen = false;
    old_receipt.terminal_event_kind = None;
    old_receipt.terminal_event_ref = None;
    old_receipt.termination_evidence_refs.clear();
    old_receipt.source_revision_refs.clear();
    old_receipt.source_close_watermark_refs.clear();
    old_receipt.source_close_reconciliation_refs.clear();
    old_receipt.source_closed_refs.clear();
    old_receipt.finalization_reason = None;
    old_receipt.finalized = false;
    old_receipt.coverage_level = CoverageLevel::Opaque;
    old_receipt.source_coverage = SourceCoverage::Partial;
    old_receipt.ordering_integrity = OrderingIntegrity::Unavailable;
    old_receipt.validate().unwrap();
    let mut old_lane = lane_for(lane_id, operation_id, &old_receipt, "capture-session");
    old_lane.status = LaneStatus::Active;
    old_lane.terminal_kind = None;
    old_lane.terminal_event_ref = None;
    old_lane.termination_evidence_refs.clear();
    old_lane.liveness_state = LivenessState::Live;
    old_lane.finalized = false;
    old_lane.operation_ids.clear();
    old_lane.validate().unwrap();
    stream.execution_lane_ids = vec![lane_id];
    let mut episode = new_episode(&stream, None, 2).unwrap();
    episode.execution_lane_ids = vec![lane_id];
    episode.capture_receipt_revision_ids = vec![old_receipt.capture_receipt_revision_id];
    episode.capture_summary = capture_summary(std::slice::from_ref(&old_receipt)).unwrap();
    episode.capture_watermark = 2;
    episode.validate().unwrap();

    let store = temp.path().join("store");
    let mut writer = JournalWriter::open(&store).await.unwrap();
    writer
        .commit(
            &command(
                1,
                vec![
                    JournalPayload::ExecutionLaneRecorded(Box::new(old_lane.clone())),
                    JournalPayload::CaptureReceiptRecorded(Box::new(old_receipt.clone())),
                ],
            ),
            1,
        )
        .await
        .unwrap();
    writer
        .commit(
            &command(
                2,
                vec![
                    JournalPayload::TaskRecorded(Box::new(root)),
                    JournalPayload::WorkstreamRecorded(Box::new(stream.clone())),
                ],
            ),
            2,
        )
        .await
        .unwrap();
    writer
        .commit(
            &activate_episode(context(3), &stream, episode.clone(), vec![], vec![]).unwrap(),
            3,
        )
        .await
        .unwrap();

    let mut new_receipt = old_receipt.clone();
    new_receipt.capture_receipt_revision_id = CaptureReceiptId::new_v7();
    new_receipt.predecessor_revision_id = Some(old_receipt.capture_receipt_revision_id);
    new_receipt.import_watermark = 3;
    new_receipt.validate().unwrap();
    let mut new_lane = old_lane;
    new_lane.lane_revision = 2;
    new_lane.predecessor_revision = Some(1);
    new_lane.event_watermark = 3;
    new_lane.active_capture_receipt_revision_id = new_receipt.capture_receipt_revision_id;
    new_lane.validate().unwrap();
    writer
        .commit(
            &command(
                4,
                vec![
                    JournalPayload::ExecutionLaneRecorded(Box::new(new_lane)),
                    JournalPayload::CaptureReceiptRecorded(Box::new(new_receipt)),
                ],
            ),
            4,
        )
        .await
        .unwrap();

    let incremental = writer.project().await.unwrap();
    let current_episode = &EpisodeCurrentView::from_snapshot(&incremental)
        .unwrap()
        .episodes[&episode.episode_id];
    assert_eq!(
        current_episode.capture_receipt_revision_ids,
        vec![old_receipt.capture_receipt_revision_id]
    );
    let full = reduce_journal(&writer.journal_rows().await.unwrap()).unwrap();
    assert_eq!(incremental, full);
    drop(writer);
    let writer = JournalWriter::open(&store).await.unwrap();
    assert_eq!(writer.project().await.unwrap(), full);
}

#[test]
fn watermark_phase_drift_and_typed_correction_fail_closed_or_preserve_lineage() {
    let root = task();
    let stream = stream(root.task_id, 2);
    let episode = new_episode(&stream, None, 2).unwrap();
    let mut bad = episode.clone();
    bad.revision_id = RevisionId::new_v7();
    bad.predecessor_revision_id = Some(episode.revision_id);
    bad.revision_generation = 2;
    bad.source_watermark = 3;
    bad.phase_contract.phase_kind = PhaseKind::Verify;
    bad.pending_semantic_delta = Some(evertrace_domain::work::PendingSemanticInterval {
        after_watermark: 0,
        through_watermark: 3,
    });
    assert!(episode.validate_successor(&bad).is_err());
    let mut candidate_ahead = episode.clone();
    candidate_ahead.boundary_status = BoundaryStatus::Candidate;
    candidate_ahead.boundary_candidate = Some(evertrace_domain::work::BoundaryCandidateState {
        candidate_phase_kind: Some(PhaseKind::Verify),
        candidate_watermark: episode.source_watermark + 1,
        evidence_refs: vec![source_evidence(99).1.source_observation_id],
        kind: evertrace_domain::work::BoundaryCandidateKind::Objective,
        refinement_progress: 0,
    });
    assert!(candidate_ahead.validate().is_err());
    let mut provisional_confirmed = episode.clone();
    provisional_confirmed.confirmation_watermark = 1;
    assert!(provisional_confirmed.validate().is_err());
    let correction = SegmentationCorrection {
        correction_revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        kind: CorrectionKind::Retract,
        source_episode_ids: vec![episode.episode_id],
        replacement_episode_ids: vec![],
        evidence_refs: vec!["late-source-revision".into()],
        source_watermark: 4,
    };
    correction.validate().unwrap();
    let replacement_a = WorkEpisodeId::new_v7();
    let replacement_b = WorkEpisodeId::new_v7();
    for (kind, sources, replacements) in [
        (
            CorrectionKind::Split,
            vec![episode.episode_id],
            vec![replacement_a, replacement_b],
        ),
        (
            CorrectionKind::Merge,
            vec![episode.episode_id, replacement_a],
            vec![replacement_b],
        ),
        (
            CorrectionKind::Reattach,
            vec![episode.episode_id],
            vec![replacement_a],
        ),
    ] {
        SegmentationCorrection {
            correction_revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            kind,
            source_episode_ids: sources,
            replacement_episode_ids: replacements,
            evidence_refs: vec!["typed-correction-shape".into()],
            source_watermark: 4,
        }
        .validate()
        .unwrap();
    }
    let invalid_split = SegmentationCorrection {
        correction_revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        kind: CorrectionKind::Split,
        source_episode_ids: vec![episode.episode_id],
        replacement_episode_ids: vec![WorkEpisodeId::new_v7()],
        evidence_refs: vec!["invalid-shape".into()],
        source_watermark: 4,
    };
    assert!(invalid_split.validate().is_err());
}

fn receipt() -> CaptureReceipt {
    receipt_for(ExecutionLaneId::new_v7(), 2)
}

fn receipt_for(execution_lane_id: ExecutionLaneId, import_watermark: u64) -> CaptureReceipt {
    CaptureReceipt {
        capture_receipt_revision_id: CaptureReceiptId::new_v7(),
        execution_lane_id,
        predecessor_revision_id: None,
        adapter_manifest_ids: vec!["adapter".into()],
        eligible_event_manifest_refs: vec!["manifest".into()],
        source_revision_refs: vec!["source".into()],
        source_close_watermark_refs: vec!["close".into()],
        source_close_reconciliation_refs: vec!["reconcile".into()],
        admission_failure_evidence_refs: vec![],
        admission_failure_observability: AdmissionFailureObservability::Complete,
        identity_strength: IdentityStrength::StableNative,
        delegation_start_seen: true,
        child_session_linked: true,
        child_session_id: Some("child".into()),
        parent_session_end_seen: false,
        lifecycle_end_seen: true,
        terminal_event_kind: Some(evertrace_domain::work::TerminalKind::Normal),
        terminal_event_ref: Some("terminal".into()),
        termination_evidence_refs: vec!["terminal".into()],
        source_closed_refs: vec!["closed".into()],
        liveness_probe_refs: vec![],
        finalization_reason: Some("normal".into()),
        first_sequence: Some(1),
        last_sequence: Some(2),
        sequence_gaps: vec![],
        capture_gap_marker_refs: vec![],
        capture_outage_interval_refs: vec![],
        tool_calls_seen: vec!["call".into()],
        tool_results_seen: vec!["call".into()],
        unmatched_tool_call_ids: vec![],
        unmatched_tool_result_ids: vec![],
        payload_truncations: vec![],
        redaction_refs: vec![],
        corrupt_payload_refs: vec![],
        unsupported_record_types: vec![],
        import_watermark,
        finalized: true,
        coverage_level: CoverageLevel::Full,
        source_coverage: SourceCoverage::Complete,
        pairing_integrity: PairingIntegrity::Complete,
        payload_integrity: PayloadIntegrity::Complete,
        ordering_integrity: OrderingIntegrity::Complete,
        reasoning_visibility: vec![],
        exact_byte_replay: true,
        resolver_version: 1,
    }
}

fn lane_for(
    execution_lane_id: ExecutionLaneId,
    operation_id: OperationId,
    receipt: &CaptureReceipt,
    session: &str,
) -> ExecutionLane {
    ExecutionLane {
        execution_lane_id,
        lane_revision: 1,
        predecessor_revision: None,
        host_session_id: session.into(),
        agent_id: "agent-s15".into(),
        host_lane_key: "host-lane-s15".into(),
        incarnation_ref: "incarnation-s15".into(),
        parent_lane_id: None,
        parent_host_lane_key: None,
        spawn_event_ref: None,
        terminal_event_ref: Some("terminal".into()),
        termination_evidence_refs: vec!["terminal".into()],
        delegated_goal_ref: None,
        delegated_target_refs: vec![],
        delegated_acceptance_refs: vec![],
        status: LaneStatus::Returned,
        terminal_kind: Some(evertrace_domain::work::TerminalKind::Normal),
        liveness_state: LivenessState::Absent,
        liveness_probe_refs: vec![],
        finalized: true,
        event_watermark: receipt.import_watermark,
        adapter_manifest_ids: receipt.adapter_manifest_ids.clone(),
        active_capture_receipt_revision_id: receipt.capture_receipt_revision_id,
        coverage_level: receipt.coverage_level,
        source_coverage: receipt.source_coverage,
        pairing_integrity: receipt.pairing_integrity,
        payload_integrity: receipt.payload_integrity,
        ordering_integrity: receipt.ordering_integrity,
        reasoning_visibility: receipt.reasoning_visibility.clone(),
        operation_ids: vec![operation_id],
        correction_reason: None,
    }
}
