use std::collections::BTreeSet;

use evertrace_domain::{
    evidence::{
        CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
        CorrelationField, CorrelationFieldClaim, EvidenceByteRange, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceArchiveMode,
        SourceInstanceId, SourceObservation, SourceReceipt, SourceRecordIdentity, SourceRevision,
        SourceRevisionMode, SourceRole, payload_fingerprint, source_observation_id,
        source_receipt_id,
    },
    ids::{
        CaptureReceiptId, CommandId, CompetingAttemptGroupId, IntegrationEventId, RepositoryId,
        TaskId, WorkBindingRevisionId, WorkstreamId, WorktreeId, WorktreeSnapshotId,
        WorktreeTransitionId,
    },
    repository::{
        FilesystemIdentity, GitObjectFormat, GitOperation, GitRegistrationState, IntegrationEvent,
        IntegrationKind, LineageAssessment, PathObservation, RepositoryInstance,
        SnapshotCaptureStatus, TransitionKind, WorktreeInstance, WorktreeKind, WorktreeLifecycle,
        WorktreeSnapshot, WorktreeTransition,
    },
    revision::RevisionId,
    work::{
        AdmissionFailureObservability, AssignmentStatus, AttemptAdoptionStatus,
        AttemptExecutionStatus, AttemptVerification, CaptureResolverInput, CompetingAttemptGroup,
        CompetingConflictKind, CompetingResolutionStatus, CoverageLevel, InterruptionReason,
        LaneStatus, LivenessState, PhaseContract, PhaseKind, PrimaryWorkBinding, StrategyContract,
        Task, TaskIdentityConfidence, TaskLifecycle, TaskScopeMembership, TerminalKind,
        WorkBindingRevision, Workstream, WorkstreamStatus, resolve_capture,
    },
};
use evertrace_engine::{
    PhysicalNormalizer,
    work::attempt::{
        AttemptResolution, new_attempt, resume_same_attempt, revise_adoption, revise_execution,
        revise_verification,
    },
};
use evertrace_store::{
    AttemptCurrentView, DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft,
    JournalPayload, JournalWriter, SourceIngestWatermark, StoreError,
    relations::{AttemptRelationKind, build_attempt_relation_rows},
};
use tempfile::TempDir;

const CONFIG: [u8; 32] = [0x14; 32];
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn contract(label: &str) -> StrategyContract {
    StrategyContract {
        hypothesis: format!("hypothesis-{label}"),
        intervention: format!("intervention-{label}"),
        intervention_family: "typed-attempt".into(),
        search_policy_ref: Some("policy:bounded".into()),
        objective_ref: Some("objective:correctness".into()),
        expected_effect: "closed state transition".into(),
        target_refs: vec!["target:attempt".into()],
        acceptance_boundary_ref: "acceptance:objective-verifier".into(),
    }
}

fn task() -> Task {
    Task {
        task_id: TaskId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec!["request:s14".into()],
        canonical_goal: "represent strategy attempts".into(),
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

fn stream(task_id: TaskId) -> Workstream {
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
        root_goal: "represent strategy attempts".into(),
        workstream_goal: "implement s14".into(),
        target_family: "attempt".into(),
        hypothesis_or_failure_family: "strategy identity".into(),
        acceptance_boundary: "s14 proof".into(),
        phase_contract: PhaseContract {
            local_goal: "record attempts".into(),
            phase_kind: PhaseKind::Implement,
            phase_label: "s14".into(),
            primary_targets: vec!["attempt".into()],
            entry_conditions: vec!["s13 complete".into()],
            acceptance_boundary: "objective verifier".into(),
            expected_state_transition: "attempt current".into(),
        },
        active_episode_id: None,
        execution_lane_ids: vec![],
        source_watermark: 2,
    }
}

fn command(at: i64, payloads: Vec<JournalPayload>) -> JournalCommand {
    JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, CONFIG, "s14-attempt-v1", payload))
            .collect(),
    )
    .unwrap()
}

fn capture_pair(
    label: &str,
    terminal_kind: Option<TerminalKind>,
    previous: Option<(
        evertrace_domain::work::ExecutionLane,
        evertrace_domain::work::CaptureReceipt,
    )>,
) -> (
    evertrace_domain::work::ExecutionLane,
    evertrace_domain::work::CaptureReceipt,
) {
    let lane_id = previous
        .as_ref()
        .map_or_else(evertrace_domain::ids::ExecutionLaneId::new_v7, |value| {
            value.0.execution_lane_id
        });
    let input = CaptureResolverInput {
        execution_lane_id: lane_id,
        capture_receipt_revision_id: CaptureReceiptId::new_v7(),
        previous_lane: previous.as_ref().map(|value| value.0.clone()),
        previous_receipt: previous.as_ref().map(|value| value.1.clone()),
        host_session_id: format!("session-s14-{label}"),
        agent_id: format!("agent-s14-{label}"),
        host_lane_key: format!("lane-s14-{label}"),
        incarnation_ref: format!("incarnation-s14-{label}"),
        parent_lane_id: None,
        parent_host_lane_key: None,
        spawn_event_ref: Some(format!("spawn-s14-{label}")),
        terminal_event_ref: terminal_kind.map(|_| format!("terminal-s14-{label}")),
        terminal_kind,
        host_final_return: false,
        parent_session_end_seen: false,
        liveness_state: if terminal_kind.is_some() {
            LivenessState::Absent
        } else {
            LivenessState::Live
        },
        liveness_probe_refs: vec![format!("liveness-s14-{label}")],
        all_sources_closed: false,
        source_closed_refs: vec![],
        source_close_watermark_refs: vec![],
        source_close_reconciliation_refs: vec![],
        source_reconciliation_complete: false,
        adapter_manifest_ids: vec![format!("manifest-s14-{label}")],
        eligible_event_manifest_refs: vec![format!("eligible-s14-{label}")],
        source_revision_refs: vec![],
        manifest_coverage: vec![CoverageLevel::Full],
        required_for_full: BTreeSet::new(),
        observed_capabilities: BTreeSet::new(),
        admission_failure_observability: AdmissionFailureObservability::Complete,
        independent_reconciliation: false,
        admission_failure_evidence_refs: vec![],
        identity_strength: IdentityStrength::StableNative,
        child_session_id: Some(format!("child-s14-{label}")),
        first_sequence: None,
        last_sequence: None,
        sequence_gaps: vec![],
        capture_gap_marker_refs: vec![],
        unresolved_gap_marker_refs: vec![],
        capture_outage_interval_refs: vec![],
        unresolved_outage_interval_refs: vec![],
        tool_calls_seen: vec![],
        tool_results_seen: vec![],
        unmatched_tool_call_ids: vec![],
        unmatched_tool_result_ids: vec![],
        payload_truncations: vec![],
        redaction_refs: vec![],
        corrupt_payload_refs: vec![],
        unavailable_payload_refs: vec![],
        unsupported_record_types: vec![],
        causal_race: false,
        ordering_best_effort: false,
        reasoning_visibility: vec![],
        import_watermark: previous
            .as_ref()
            .map_or(1, |value| value.0.event_watermark + 1),
        delegated_goal_ref: Some(format!("goal-s14-{label}")),
        delegated_target_refs: vec![format!("target-s14-{label}")],
        delegated_acceptance_refs: vec![format!("accept-s14-{label}")],
        operation_ids: vec![],
        correction_reason: previous
            .as_ref()
            .map(|_| format!("late-terminal-s14-{label}")),
    };
    resolve_capture(input).unwrap()
}

struct Topology {
    repository: RepositoryInstance,
    source_worktree: WorktreeInstance,
    target_worktree: WorktreeInstance,
    source_snapshot: WorktreeSnapshot,
    target_snapshot: WorktreeSnapshot,
    transition: WorktreeTransition,
}

fn topology() -> Topology {
    let repository_id = RepositoryId::new_v7();
    let source_id = WorktreeId::new_v7();
    let target_id = WorktreeId::new_v7();
    let source_snapshot_id = WorktreeSnapshotId::new_v7();
    let target_snapshot_id = WorktreeSnapshotId::new_v7();
    let observation = |path: &str, evidence: &str| PathObservation {
        path: path.into(),
        first_observed_at_us: 1,
        last_observed_at_us: 1,
        evidence_refs: vec![evidence.into()],
    };
    let repository = RepositoryInstance {
        repository_id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: "/tmp/evertrace-s14-repo".into(),
        path_history: vec![observation("/tmp/evertrace-s14-repo", "repo-path")],
        git_common_dir_path: Some("/tmp/evertrace-s14-repo/.git".into()),
        common_dir_filesystem: Some(FilesystemIdentity {
            device: 14,
            inode: 1,
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: vec![],
        derived_from: None,
        identity_evidence_refs: vec!["repo-identity".into()],
        recorded_at_us: 1,
    };
    let worktree = |id, snapshot_id, path: &str, kind| WorktreeInstance {
        worktree_instance_id: id,
        worktree_revision: 1,
        predecessor_revision: None,
        repository_instance_id: repository_id,
        kind,
        lifecycle: WorktreeLifecycle::Active,
        current_path: Some(path.into()),
        path_history: vec![observation(path, "worktree-path")],
        git_admin_path_history: vec![observation(&format!("{path}/.git"), "worktree-admin")],
        git_registration_state: GitRegistrationState::Registered,
        current_snapshot_id: Some(snapshot_id),
        created_event_ref: "worktree-created".into(),
        terminal_event_ref: None,
        recreated_from_worktree_instance_id: None,
        recorded_at_us: 1,
    };
    let snapshot = |id, worktree_id, at| WorktreeSnapshot {
        worktree_snapshot_id: id,
        worktree_instance_id: worktree_id,
        head_oid: None,
        tree_oid: None,
        branch_ref: None,
        detached_head: false,
        tracked_diff_digest: None,
        index_digest: None,
        untracked_manifest_digest: None,
        relevant_anchor_digests: vec![],
        dependency_fingerprints: vec![],
        toolchain_fingerprint: None,
        git_operation: GitOperation::None,
        captured_at_us: at,
        evidence_refs: vec![format!("snapshot-{at}")],
        capture_status: SnapshotCaptureStatus::Complete,
        omission_reasons: vec![],
    };
    let source_worktree = worktree(
        source_id,
        source_snapshot_id,
        "/tmp/evertrace-s14-repo",
        WorktreeKind::Main,
    );
    let target_worktree = worktree(
        target_id,
        target_snapshot_id,
        "/tmp/evertrace-s14-linked",
        WorktreeKind::Linked,
    );
    let source_snapshot = snapshot(source_snapshot_id, source_id, 1);
    let target_snapshot = snapshot(target_snapshot_id, target_id, 2);
    let transition = WorktreeTransition {
        worktree_transition_id: WorktreeTransitionId::new_v7(),
        transition_revision: 1,
        predecessor_revision: None,
        from_worktree_instance_id: source_id,
        from_snapshot_id: Some(source_snapshot_id),
        to_worktree_instance_id: target_id,
        to_snapshot_id: Some(target_snapshot_id),
        kind: TransitionKind::PatchTransferred,
        lineage_assessment: LineageAssessment::Proven,
        correction_reason: None,
        source_watermark: 2,
        evidence_refs: vec!["transition-proof".into()],
    };
    Topology {
        repository,
        source_worktree,
        target_worktree,
        source_snapshot,
        target_snapshot,
        transition,
    }
}

fn exact_observation() -> (SourceReceipt, SourceObservation) {
    let instance = SourceInstanceId::parse("source-s14").unwrap();
    let revision = SourceRevision::parse("revision-1").unwrap();
    let record = SourceRecordIdentity::parse("record-s14").unwrap();
    let observation_id = source_observation_id(&instance, &revision, &record).unwrap();
    let receipt_id = source_receipt_id(&instance, &revision, &record).unwrap();
    let fields = [
        CorrelationField::HostInstanceId,
        CorrelationField::HostTraceLineageId,
        CorrelationField::HostLaneKey,
        CorrelationField::CanonicalEventFamily,
        CorrelationField::NativeRequestId,
        CorrelationField::PhysicalExecutionOrdinal,
    ];
    let receipt = SourceReceipt {
        source_receipt_id: receipt_id,
        source_observation_id: observation_id,
        source_instance_id: instance.clone(),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        source_ref: "source-ref-s14".into(),
        source_session_ref: "session-s14-operation".into(),
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
        observation_role: ObservationRole::Result,
        unsupported_record_classification: None,
        capture_completeness: CaptureCompleteness::Complete,
        archive_mode: SourceArchiveMode::Exact,
        cas_ref: DIGEST.into(),
        protected_length: 1,
        original_length: 1,
        protected_secret_digest: None,
        redaction_spans: vec![],
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-manifest-s14".into(),
        eligible_event_manifest_ref: "eligible-events-s14".into(),
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
        observation_role: ObservationRole::Result,
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
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: Some("host-s14".into()),
            host_trace_lineage_id: Some("trace-s14".into()),
            host_lane_key: Some("lane-operation-s14".into()),
            canonical_event_family: Some(CanonicalEventFamily::Mutate),
            native_request_id: Some("request-s14".into()),
            physical_execution_ordinal: Some(1),
            pairing_role: ObservationRole::Result,
            field_provenance: fields
                .into_iter()
                .map(|field| CorrelationFieldClaim {
                    field,
                    source_ref: "source-s14".into(),
                    evidence_ref: format!("canary-{field:?}"),
                })
                .collect(),
            adapter_manifest_ref: "adapter-manifest-s14".into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: Some("strong-gate-s14".into()),
            admission: CorrelationAdmission::ExactCapable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
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
                confirmed_prefix_digest: None,
            }),
            JournalPayload::DirtyTarget(DirtyTarget {
                target_kind: DirtyTargetKind::EvidenceSurface,
                target_id: target.clone(),
                algorithm_revision: "s14-attempt-v1".into(),
                source_watermark: 1,
            }),
            JournalPayload::DirtyTarget(DirtyTarget {
                target_kind: DirtyTargetKind::PhysicalNormalization,
                target_id: target,
                algorithm_revision: "s14-attempt-v1".into(),
                source_watermark: 1,
            }),
        ],
    )
}

#[tokio::test]
async fn create_successor_no_delta_replay_rebuild_and_restart_are_equivalent() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let mut writer = JournalWriter::open(&root).await.unwrap();
    let task = task();
    let stream = stream(task.task_id);
    let attempt = new_attempt(
        task.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("a"),
        3,
    )
    .unwrap();
    let first = command(
        1,
        vec![
            JournalPayload::TaskRecorded(Box::new(task)),
            JournalPayload::WorkstreamRecorded(Box::new(stream)),
            JournalPayload::AttemptRecorded(Box::new(attempt.clone())),
        ],
    );
    writer.commit(&first, 1).await.unwrap();
    let rows = writer.journal_rows().await.unwrap().len();
    assert!(writer.commit(&first, 1).await.unwrap().replayed);
    assert_eq!(writer.journal_rows().await.unwrap().len(), rows);
    assert_eq!(
        revise_execution(
            &attempt,
            AttemptExecutionStatus::Proposed,
            vec![],
            vec![],
            None,
            vec![],
            4
        )
        .unwrap(),
        AttemptResolution::NoDelta
    );
    let candidate =
        match revise_adoption(&attempt, AttemptAdoptionStatus::Candidate, vec![], 4).unwrap() {
            AttemptResolution::Revision(value) => *value,
            AttemptResolution::NoDelta => panic!(),
        };
    writer
        .commit(
            &command(
                2,
                vec![JournalPayload::AttemptRecorded(Box::new(candidate.clone()))],
            ),
            2,
        )
        .await
        .unwrap();
    let passed = match revise_verification(
        &candidate,
        AttemptVerification::Passed,
        vec!["verifier:objective".into()],
        5,
    )
    .unwrap()
    {
        AttemptResolution::Revision(value) => *value,
        AttemptResolution::NoDelta => panic!(),
    };
    writer
        .commit(
            &command(
                3,
                vec![JournalPayload::AttemptRecorded(Box::new(passed.clone()))],
            ),
            3,
        )
        .await
        .unwrap();
    let incremental = writer.project().await.unwrap();
    assert_eq!(incremental, writer.full_projection().await.unwrap());
    let view = AttemptCurrentView::from_snapshot(&incremental).unwrap();
    assert_eq!(view.attempts[&attempt.attempt_id], passed);
    assert_eq!(
        incremental
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("attempt"))
            .count(),
        3
    );
    assert_eq!(
        writer.table_names().await.unwrap(),
        vec![
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search"
        ]
    );
    let mut gap = incremental.clone();
    gap.rows.retain(|row| {
        row.current_revision_id.as_deref() != Some(candidate.revision_id.to_string().as_str())
    });
    assert_eq!(
        AttemptCurrentView::from_snapshot(&gap),
        Err(StoreError::StoreCorrupt)
    );
    let mut rollback = incremental.clone();
    let passed_revision = passed.revision_id.to_string();
    let mut row = rollback
        .rows
        .iter()
        .find(|row| row.current_revision_id.as_deref() == Some(passed_revision.as_str()))
        .unwrap()
        .clone();
    let mut payload: JournalPayload =
        serde_json::from_str(row.payload_json.as_deref().unwrap()).unwrap();
    let JournalPayload::AttemptRecorded(value) = &mut payload else {
        panic!()
    };
    value.predecessor_revision_id = Some(passed.revision_id);
    value.revision_id = RevisionId::new_v7();
    value.revision_generation = 4;
    value.source_watermark = 6;
    value.verification = AttemptVerification::Unverified;
    value.parent_verification_refs.clear();
    row.row_id = format!("object:work:attempt:{}", value.revision_id);
    row.current_revision_id = Some(value.revision_id.to_string());
    row.payload_json = Some(payload.canonical_json().unwrap());
    rollback.rows.push(row);
    assert_eq!(
        AttemptCurrentView::from_snapshot(&rollback),
        Err(StoreError::StoreCorrupt)
    );
    let before_forgery = writer.journal_rows().await.unwrap().len();
    let mut forged = passed.clone();
    forged.revision_generation += 1;
    forged.predecessor_revision_id = Some(passed.revision_id);
    forged.revision_id = RevisionId::new_v7();
    forged.source_watermark += 1;
    forged.strategy_contract = contract("material-change");
    forged.strategy_contract_fingerprint = forged.strategy_contract.fingerprint().unwrap();
    assert!(
        writer
            .commit(
                &command(4, vec![JournalPayload::AttemptRecorded(Box::new(forged))]),
                4,
            )
            .await
            .is_err()
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), before_forgery);
    assert_eq!(writer.project().await.unwrap(), incremental);
    drop(writer);
    let writer = JournalWriter::open(&root).await.unwrap();
    assert_eq!(
        AttemptCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap(),
        view
    );
}

#[tokio::test]
async fn active_lane_blocks_interruption_and_completion_until_real_terminal_evidence() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let (active_lane, active_receipt) = capture_pair("interrupt", None, None);
    assert_eq!(active_lane.status, LaneStatus::Active);
    let task = task();
    let mut stream = stream(task.task_id);
    stream.execution_lane_ids = vec![active_lane.execution_lane_id];
    let mut attempt = new_attempt(
        task.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![active_lane.execution_lane_id],
        contract("lane-active"),
        3,
    )
    .unwrap();
    attempt.execution_status = AttemptExecutionStatus::Active;
    writer
        .commit(
            &command(
                1,
                vec![
                    JournalPayload::ExecutionLaneRecorded(Box::new(active_lane.clone())),
                    JournalPayload::CaptureReceiptRecorded(Box::new(active_receipt.clone())),
                    JournalPayload::TaskRecorded(Box::new(task)),
                    JournalPayload::WorkstreamRecorded(Box::new(stream)),
                    JournalPayload::AttemptRecorded(Box::new(attempt.clone())),
                ],
            ),
            1,
        )
        .await
        .unwrap();
    let interrupted = match revise_execution(
        &attempt,
        AttemptExecutionStatus::Interrupted,
        vec![],
        vec!["terminal:crash".into()],
        Some(InterruptionReason::Crashed),
        vec![],
        4,
    )
    .unwrap()
    {
        AttemptResolution::Revision(value) => *value,
        AttemptResolution::NoDelta => panic!(),
    };
    let frontier = writer.journal_rows().await.unwrap().len();
    assert!(
        writer
            .commit(
                &command(
                    2,
                    vec![JournalPayload::AttemptRecorded(Box::new(
                        interrupted.clone()
                    ))]
                ),
                2,
            )
            .await
            .is_err()
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), frontier);
    let completed = match revise_execution(
        &attempt,
        AttemptExecutionStatus::Completed,
        vec![],
        vec![],
        None,
        vec![],
        4,
    )
    .unwrap()
    {
        AttemptResolution::Revision(value) => *value,
        AttemptResolution::NoDelta => panic!(),
    };
    assert!(
        writer
            .commit(
                &command(
                    3,
                    vec![JournalPayload::AttemptRecorded(Box::new(completed))]
                ),
                2
            )
            .await
            .is_err()
    );

    let (terminal_lane, terminal_receipt) = capture_pair(
        "interrupt",
        Some(TerminalKind::Crashed),
        Some((active_lane, active_receipt)),
    );
    assert_eq!(terminal_lane.status, LaneStatus::Interrupted);
    writer
        .commit(
            &command(
                4,
                vec![
                    JournalPayload::ExecutionLaneRecorded(Box::new(terminal_lane)),
                    JournalPayload::CaptureReceiptRecorded(Box::new(terminal_receipt)),
                    JournalPayload::AttemptRecorded(Box::new(interrupted.clone())),
                ],
            ),
            2,
        )
        .await
        .unwrap();
    assert_eq!(interrupted.verification, AttemptVerification::Unverified);
}

#[tokio::test]
async fn normal_lane_terminal_allows_completed_without_implying_adoption_or_verification() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let (active_lane, active_receipt) = capture_pair("complete", None, None);
    let task = task();
    let mut stream = stream(task.task_id);
    stream.execution_lane_ids = vec![active_lane.execution_lane_id];
    let mut attempt = new_attempt(
        task.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![active_lane.execution_lane_id],
        contract("normal-complete"),
        3,
    )
    .unwrap();
    attempt.execution_status = AttemptExecutionStatus::Active;
    writer
        .commit(
            &command(
                1,
                vec![
                    JournalPayload::ExecutionLaneRecorded(Box::new(active_lane.clone())),
                    JournalPayload::CaptureReceiptRecorded(Box::new(active_receipt.clone())),
                    JournalPayload::TaskRecorded(Box::new(task)),
                    JournalPayload::WorkstreamRecorded(Box::new(stream)),
                    JournalPayload::AttemptRecorded(Box::new(attempt.clone())),
                ],
            ),
            1,
        )
        .await
        .unwrap();
    let completed = match revise_execution(
        &attempt,
        AttemptExecutionStatus::Completed,
        vec![],
        vec![],
        None,
        vec![],
        4,
    )
    .unwrap()
    {
        AttemptResolution::Revision(value) => *value,
        AttemptResolution::NoDelta => panic!(),
    };
    let (stopped_lane, stopped_receipt) = capture_pair(
        "complete",
        Some(TerminalKind::Normal),
        Some((active_lane, active_receipt)),
    );
    assert_eq!(stopped_lane.status, LaneStatus::Stopped);
    writer
        .commit(
            &command(
                2,
                vec![
                    JournalPayload::ExecutionLaneRecorded(Box::new(stopped_lane)),
                    JournalPayload::CaptureReceiptRecorded(Box::new(stopped_receipt)),
                    JournalPayload::AttemptRecorded(Box::new(completed.clone())),
                ],
            ),
            2,
        )
        .await
        .unwrap();
    assert_eq!(completed.adoption_status, AttemptAdoptionStatus::None);
    assert_eq!(completed.verification, AttemptVerification::Unverified);
}

#[tokio::test]
async fn interrupted_attempt_reopens_only_through_compatible_same_instance_resume() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let topology = topology();
    let (old_lane, old_receipt) = capture_pair("same-old", Some(TerminalKind::Crashed), None);
    let mut task = task();
    task.scope_memberships = vec![TaskScopeMembership {
        repository_instance_id: Some(topology.repository.repository_id),
        worktree_instance_ids: vec![topology.source_worktree.worktree_instance_id],
    }];
    let mut stream = stream(task.task_id);
    stream.repository_instance_id = Some(topology.repository.repository_id);
    stream.worktree_instance_ids = vec![topology.source_worktree.worktree_instance_id];
    stream.active_worktree_instance_id = Some(topology.source_worktree.worktree_instance_id);
    stream.execution_lane_ids = vec![old_lane.execution_lane_id];
    let mut attempt = new_attempt(
        task.task_id,
        stream.workstream_id,
        stream.repository_instance_id,
        stream.worktree_instance_ids.clone(),
        vec![old_lane.execution_lane_id],
        contract("same-resume"),
        3,
    )
    .unwrap();
    attempt.execution_status = AttemptExecutionStatus::Interrupted;
    attempt.interruption_refs = vec!["terminal:same-old".into()];
    attempt.interruption_reason = Some(InterruptionReason::Crashed);
    writer
        .commit(
            &command(
                1,
                vec![
                    JournalPayload::RepositoryInstanceRecorded(Box::new(topology.repository)),
                    JournalPayload::WorktreeInstanceRecorded(Box::new(topology.source_worktree)),
                    JournalPayload::WorktreeSnapshotRecorded(Box::new(
                        topology.source_snapshot.clone(),
                    )),
                    JournalPayload::ExecutionLaneRecorded(Box::new(old_lane)),
                    JournalPayload::CaptureReceiptRecorded(Box::new(old_receipt)),
                    JournalPayload::TaskRecorded(Box::new(task)),
                    JournalPayload::WorkstreamRecorded(Box::new(stream.clone())),
                    JournalPayload::AttemptRecorded(Box::new(attempt.clone())),
                ],
            ),
            1,
        )
        .await
        .unwrap();
    assert!(
        revise_execution(
            &attempt,
            AttemptExecutionStatus::Active,
            vec![],
            vec![],
            None,
            vec![],
            4
        )
        .is_err()
    );
    let (new_lane, new_receipt) = capture_pair("same-new", None, None);
    let resumed = resume_same_attempt(
        &attempt,
        new_lane.execution_lane_id,
        evertrace_domain::work::ResumeStateAssessment::CompatibleSameInstance,
        vec!["resume:same-instance".into()],
        Some(topology.source_snapshot.worktree_snapshot_id),
        topology.source_snapshot.worktree_snapshot_id,
        vec![],
        4,
    )
    .unwrap();
    let mut stream_successor = stream;
    stream_successor.predecessor_revision_id = Some(stream_successor.revision_id);
    stream_successor.revision_id = RevisionId::new_v7();
    stream_successor
        .execution_lane_ids
        .push(new_lane.execution_lane_id);
    stream_successor.execution_lane_ids.sort();
    stream_successor.source_watermark = 4;
    writer
        .commit(
            &command(
                2,
                vec![
                    JournalPayload::ExecutionLaneRecorded(Box::new(new_lane)),
                    JournalPayload::CaptureReceiptRecorded(Box::new(new_receipt)),
                    JournalPayload::WorkstreamRecorded(Box::new(stream_successor)),
                    JournalPayload::AttemptRecorded(Box::new(resumed.clone())),
                ],
            ),
            2,
        )
        .await
        .unwrap();
    assert_eq!(resumed.attempt_id, attempt.attempt_id);
    assert_eq!(resumed.execution_status, AttemptExecutionStatus::Active);
}

#[tokio::test]
async fn lineage_transfer_resume_requires_forward_snapshot_transition_topology() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let topology = topology();
    let (old_lane, old_receipt) = capture_pair("lineage-old", Some(TerminalKind::Crashed), None);
    let mut task = task();
    let mut task_worktrees = vec![
        topology.source_worktree.worktree_instance_id,
        topology.target_worktree.worktree_instance_id,
    ];
    task_worktrees.sort();
    task.scope_memberships = vec![TaskScopeMembership {
        repository_instance_id: Some(topology.repository.repository_id),
        worktree_instance_ids: task_worktrees.clone(),
    }];
    let mut stream = stream(task.task_id);
    stream.repository_instance_id = Some(topology.repository.repository_id);
    stream.worktree_instance_ids = vec![topology.source_worktree.worktree_instance_id];
    stream.active_worktree_instance_id = Some(topology.source_worktree.worktree_instance_id);
    stream.execution_lane_ids = vec![old_lane.execution_lane_id];
    let mut attempt = new_attempt(
        task.task_id,
        stream.workstream_id,
        stream.repository_instance_id,
        stream.worktree_instance_ids.clone(),
        vec![old_lane.execution_lane_id],
        contract("lineage-resume"),
        3,
    )
    .unwrap();
    attempt.execution_status = AttemptExecutionStatus::Interrupted;
    attempt.interruption_refs = vec!["terminal:lineage-old".into()];
    attempt.interruption_reason = Some(InterruptionReason::Crashed);
    writer
        .commit(
            &command(
                1,
                vec![
                    JournalPayload::RepositoryInstanceRecorded(Box::new(topology.repository)),
                    JournalPayload::WorktreeInstanceRecorded(Box::new(
                        topology.source_worktree.clone(),
                    )),
                    JournalPayload::WorktreeInstanceRecorded(Box::new(
                        topology.target_worktree.clone(),
                    )),
                    JournalPayload::WorktreeSnapshotRecorded(Box::new(
                        topology.source_snapshot.clone(),
                    )),
                    JournalPayload::WorktreeSnapshotRecorded(Box::new(
                        topology.target_snapshot.clone(),
                    )),
                    JournalPayload::WorktreeTransitionRecorded(Box::new(
                        topology.transition.clone(),
                    )),
                    JournalPayload::ExecutionLaneRecorded(Box::new(old_lane)),
                    JournalPayload::CaptureReceiptRecorded(Box::new(old_receipt)),
                    JournalPayload::TaskRecorded(Box::new(task)),
                    JournalPayload::WorkstreamRecorded(Box::new(stream.clone())),
                    JournalPayload::AttemptRecorded(Box::new(attempt.clone())),
                ],
            ),
            1,
        )
        .await
        .unwrap();
    let (new_lane, new_receipt) = capture_pair("lineage-new", None, None);
    let mut resumed = resume_same_attempt(
        &attempt,
        new_lane.execution_lane_id,
        evertrace_domain::work::ResumeStateAssessment::CompatibleLineageTransfer,
        vec!["resume:lineage".into()],
        Some(topology.source_snapshot.worktree_snapshot_id),
        topology.target_snapshot.worktree_snapshot_id,
        vec![topology.transition.worktree_transition_id],
        4,
    )
    .unwrap();
    resumed.worktree_instance_ids = task_worktrees.clone();
    let mut stream_successor = stream.clone();
    stream_successor.predecessor_revision_id = Some(stream.revision_id);
    stream_successor.revision_id = RevisionId::new_v7();
    stream_successor.worktree_instance_ids = task_worktrees;
    stream_successor.active_worktree_instance_id =
        Some(topology.target_worktree.worktree_instance_id);
    stream_successor.worktree_lineage_refs =
        vec![topology.transition.worktree_transition_id.to_string()];
    stream_successor
        .execution_lane_ids
        .push(new_lane.execution_lane_id);
    stream_successor.execution_lane_ids.sort();
    stream_successor.source_watermark = 4;
    let mut reversed = resumed.clone();
    reversed.resume_source_snapshot_id = Some(topology.target_snapshot.worktree_snapshot_id);
    reversed.resume_target_snapshot_id = Some(topology.source_snapshot.worktree_snapshot_id);
    let frontier = writer.journal_rows().await.unwrap().len();
    assert!(
        writer
            .commit(
                &command(
                    2,
                    vec![
                        JournalPayload::ExecutionLaneRecorded(Box::new(new_lane.clone())),
                        JournalPayload::CaptureReceiptRecorded(Box::new(new_receipt.clone())),
                        JournalPayload::WorkstreamRecorded(Box::new(stream_successor.clone())),
                        JournalPayload::AttemptRecorded(Box::new(reversed))
                    ]
                ),
                2
            )
            .await
            .is_err()
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), frontier);
    writer
        .commit(
            &command(
                3,
                vec![
                    JournalPayload::ExecutionLaneRecorded(Box::new(new_lane)),
                    JournalPayload::CaptureReceiptRecorded(Box::new(new_receipt)),
                    JournalPayload::WorkstreamRecorded(Box::new(stream_successor)),
                    JournalPayload::AttemptRecorded(Box::new(resumed)),
                ],
            ),
            2,
        )
        .await
        .unwrap();
}

#[test]
fn strategy_fingerprint_excludes_run_variables_and_axes_are_independent() {
    let task = task();
    let stream = stream(task.task_id);
    let attempt = new_attempt(
        task.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("same"),
        1,
    )
    .unwrap();
    assert_eq!(
        attempt.strategy_contract_fingerprint,
        attempt.strategy_contract.fingerprint().unwrap()
    );
    let candidate =
        match revise_adoption(&attempt, AttemptAdoptionStatus::Candidate, vec![], 2).unwrap() {
            AttemptResolution::Revision(value) => *value,
            _ => panic!(),
        };
    assert_eq!(candidate.execution_status, AttemptExecutionStatus::Proposed);
    assert_eq!(candidate.verification, AttemptVerification::Unverified);
    let passed = match revise_verification(
        &candidate,
        AttemptVerification::Passed,
        vec!["verifier:objective".into()],
        3,
    )
    .unwrap()
    {
        AttemptResolution::Revision(value) => *value,
        _ => panic!(),
    };
    assert_eq!(passed.adoption_status, AttemptAdoptionStatus::Candidate);
    assert_ne!(passed.adoption_status, AttemptAdoptionStatus::Integrated);
    assert!(revise_verification(&attempt, AttemptVerification::Passed, vec![], 2).is_err());
    assert!(
        serde_json::to_string(&attempt)
            .unwrap()
            .find("seed")
            .is_none()
    );
    assert!(attempt.experiment_run_ids.is_empty());
}

#[tokio::test]
async fn open_group_is_candidate_only_and_current_history_is_closed() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let task = task();
    let stream = stream(task.task_id);
    let group_id = CompetingAttemptGroupId::new_v7();
    let mut a = new_attempt(
        task.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("a"),
        3,
    )
    .unwrap();
    let mut b = new_attempt(
        task.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("b"),
        3,
    )
    .unwrap();
    a.competing_group_ids = vec![group_id];
    b.competing_group_ids = vec![group_id];
    let mut members = vec![a.attempt_id, b.attempt_id];
    members.sort();
    let group = CompetingAttemptGroup {
        competing_group_id: group_id,
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        revision_generation: 1,
        task_id: task.task_id,
        decision_boundary_ref: "decision:s14".into(),
        comparison_contract_ref: Some("comparison:objective".into()),
        origin_workstream_id: Some(stream.workstream_id),
        origin_episode_id: None,
        member_workstream_ids: vec![stream.workstream_id],
        member_attempt_ids: members,
        candidate_snapshot_refs: vec![],
        target_refs: vec!["target:attempt".into()],
        conflict_kind: CompetingConflictKind::AlternativeStrategy,
        resolution_status: CompetingResolutionStatus::Open,
        selected_attempt_id: None,
        partially_integrated_attempt_ids: vec![],
        resolution_evidence_refs: vec![],
        source_watermark: 4,
    };
    writer
        .commit(
            &command(
                1,
                vec![
                    JournalPayload::TaskRecorded(Box::new(task)),
                    JournalPayload::WorkstreamRecorded(Box::new(stream)),
                    JournalPayload::AttemptRecorded(Box::new(a.clone())),
                    JournalPayload::AttemptRecorded(Box::new(b.clone())),
                    JournalPayload::CompetingAttemptGroupRecorded(Box::new(group.clone())),
                ],
            ),
            1,
        )
        .await
        .unwrap();
    let view = AttemptCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert_eq!(
        view.competing_groups[&group_id].resolution_status,
        CompetingResolutionStatus::Open
    );
    let relations = build_attempt_relation_rows(&[a, b], &[group]).unwrap();
    assert_eq!(
        relations
            .iter()
            .filter(|row| row.kind == AttemptRelationKind::GroupToCandidateMember)
            .count(),
        2
    );
    assert!(
        !relations
            .iter()
            .any(|row| row.kind == AttemptRelationKind::GroupToSelectedAttempt)
    );
    let mut one_way = view.attempts.values().cloned().collect::<Vec<_>>();
    one_way[0].competing_group_ids.clear();
    assert!(
        build_attempt_relation_rows(
            &one_way,
            &view.competing_groups.values().cloned().collect::<Vec<_>>()
        )
        .is_err()
    );
}

#[test]
fn partially_integrated_group_can_converge_to_objectively_selected_member() {
    let task = task();
    let stream = stream(task.task_id);
    let group_id = CompetingAttemptGroupId::new_v7();
    let mut a = new_attempt(
        task.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("partial-a"),
        1,
    )
    .unwrap();
    let mut b = new_attempt(
        task.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("partial-b"),
        1,
    )
    .unwrap();
    a.competing_group_ids = vec![group_id];
    b.competing_group_ids = vec![group_id];
    a.adoption_status = AttemptAdoptionStatus::PartiallyIntegrated;
    a.integration_event_refs = vec![evertrace_domain::ids::IntegrationEventId::new_v7()];
    let mut members = vec![a.attempt_id, b.attempt_id];
    members.sort();
    let open = CompetingAttemptGroup {
        competing_group_id: group_id,
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        revision_generation: 1,
        task_id: task.task_id,
        decision_boundary_ref: "decision:partial".into(),
        comparison_contract_ref: Some("comparison:objective".into()),
        origin_workstream_id: Some(stream.workstream_id),
        origin_episode_id: None,
        member_workstream_ids: vec![stream.workstream_id],
        member_attempt_ids: members,
        candidate_snapshot_refs: vec![],
        target_refs: vec!["target:partial".into()],
        conflict_kind: CompetingConflictKind::AlternativeStrategy,
        resolution_status: CompetingResolutionStatus::Open,
        selected_attempt_id: None,
        partially_integrated_attempt_ids: vec![],
        resolution_evidence_refs: vec![],
        source_watermark: 2,
    };
    let partial = CompetingAttemptGroup {
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: Some(open.revision_id),
        revision_generation: 2,
        resolution_status: CompetingResolutionStatus::PartiallyIntegrated,
        partially_integrated_attempt_ids: vec![a.attempt_id],
        resolution_evidence_refs: vec!["integration:partial-a".into()],
        source_watermark: 3,
        ..open.clone()
    };
    open.validate_successor(&partial).unwrap();
    a.adoption_status = AttemptAdoptionStatus::Integrated;
    a.verification = AttemptVerification::Passed;
    a.parent_verification_refs = vec!["verifier:objective-a".into()];
    let selected = CompetingAttemptGroup {
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: Some(partial.revision_id),
        revision_generation: 3,
        resolution_status: CompetingResolutionStatus::Selected,
        selected_attempt_id: Some(a.attempt_id),
        partially_integrated_attempt_ids: vec![],
        resolution_evidence_refs: vec![
            "integration:partial-a".into(),
            "verifier:objective-a".into(),
        ],
        source_watermark: 4,
        ..partial.clone()
    };
    partial.validate_successor(&selected).unwrap();
    assert!(build_attempt_relation_rows(&[a, b], &[selected]).is_ok());
}

#[tokio::test]
async fn prospective_group_partial_then_selected_uses_current_attempt_evidence() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let topology = topology();
    let mut task = task();
    let mut worktree_ids = vec![
        topology.source_worktree.worktree_instance_id,
        topology.target_worktree.worktree_instance_id,
    ];
    worktree_ids.sort();
    task.scope_memberships = vec![TaskScopeMembership {
        repository_instance_id: Some(topology.repository.repository_id),
        worktree_instance_ids: worktree_ids.clone(),
    }];
    let mut stream = stream(task.task_id);
    stream.repository_instance_id = Some(topology.repository.repository_id);
    stream.worktree_instance_ids = worktree_ids.clone();
    stream.active_worktree_instance_id = Some(topology.target_worktree.worktree_instance_id);
    let group_id = CompetingAttemptGroupId::new_v7();
    let mut selected = new_attempt(
        task.task_id,
        stream.workstream_id,
        stream.repository_instance_id,
        worktree_ids.clone(),
        vec![],
        contract("prospective-selected"),
        1,
    )
    .unwrap();
    selected.adoption_status = AttemptAdoptionStatus::Selected;
    selected.competing_group_ids = vec![group_id];
    let mut alternate = new_attempt(
        task.task_id,
        stream.workstream_id,
        stream.repository_instance_id,
        worktree_ids,
        vec![],
        contract("prospective-alternate"),
        1,
    )
    .unwrap();
    alternate.competing_group_ids = vec![group_id];
    let mut member_ids = vec![selected.attempt_id, alternate.attempt_id];
    member_ids.sort();
    let open = CompetingAttemptGroup {
        competing_group_id: group_id,
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        revision_generation: 1,
        task_id: task.task_id,
        decision_boundary_ref: "decision:prospective".into(),
        comparison_contract_ref: Some("comparison:objective".into()),
        origin_workstream_id: Some(stream.workstream_id),
        origin_episode_id: None,
        member_workstream_ids: vec![stream.workstream_id],
        member_attempt_ids: member_ids,
        candidate_snapshot_refs: vec![],
        target_refs: vec!["target:prospective".into()],
        conflict_kind: CompetingConflictKind::AlternativeStrategy,
        resolution_status: CompetingResolutionStatus::Open,
        selected_attempt_id: None,
        partially_integrated_attempt_ids: vec![],
        resolution_evidence_refs: vec![],
        source_watermark: 1,
    };
    writer
        .commit(
            &command(
                1,
                vec![
                    JournalPayload::RepositoryInstanceRecorded(Box::new(topology.repository)),
                    JournalPayload::WorktreeInstanceRecorded(Box::new(
                        topology.source_worktree.clone(),
                    )),
                    JournalPayload::WorktreeInstanceRecorded(Box::new(
                        topology.target_worktree.clone(),
                    )),
                    JournalPayload::WorktreeSnapshotRecorded(Box::new(
                        topology.source_snapshot.clone(),
                    )),
                    JournalPayload::WorktreeSnapshotRecorded(Box::new(
                        topology.target_snapshot.clone(),
                    )),
                    JournalPayload::TaskRecorded(Box::new(task)),
                    JournalPayload::WorkstreamRecorded(Box::new(stream)),
                    JournalPayload::AttemptRecorded(Box::new(selected.clone())),
                    JournalPayload::AttemptRecorded(Box::new(alternate)),
                    JournalPayload::CompetingAttemptGroupRecorded(Box::new(open.clone())),
                ],
            ),
            1,
        )
        .await
        .unwrap();

    let integration_id = IntegrationEventId::new_v7();
    let integration = IntegrationEvent {
        integration_event_id: integration_id,
        repository_instance_id: topology.source_worktree.repository_instance_id,
        source_worktree_instance_id: topology.source_worktree.worktree_instance_id,
        source_snapshot_id: topology.source_snapshot.worktree_snapshot_id,
        destination_worktree_instance_id: topology.target_worktree.worktree_instance_id,
        destination_snapshot_id: topology.target_snapshot.worktree_snapshot_id,
        kind: IntegrationKind::ManualPatch,
        commit_refs: vec![],
        patch_equivalence_refs: vec!["patch:prospective".into()],
        conflict_resolution_detected: false,
        integrated_attempt_ids: vec![selected.attempt_id],
        revalidated_anchor_refs: vec![],
        evidence_refs: vec!["integration:prospective".into()],
        assessment: LineageAssessment::Proven,
    };
    let partial_attempt = match revise_adoption(
        &selected,
        AttemptAdoptionStatus::PartiallyIntegrated,
        vec![integration_id],
        2,
    )
    .unwrap()
    {
        AttemptResolution::Revision(value) => *value,
        AttemptResolution::NoDelta => panic!("expected partial attempt successor"),
    };
    let partial_group = CompetingAttemptGroup {
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: Some(open.revision_id),
        revision_generation: 2,
        resolution_status: CompetingResolutionStatus::PartiallyIntegrated,
        partially_integrated_attempt_ids: vec![selected.attempt_id],
        resolution_evidence_refs: vec!["integration:prospective".into()],
        source_watermark: 2,
        ..open
    };
    writer
        .commit(
            &command(
                2,
                vec![
                    JournalPayload::IntegrationEventRecorded(Box::new(integration)),
                    JournalPayload::AttemptRecorded(Box::new(partial_attempt.clone())),
                    JournalPayload::CompetingAttemptGroupRecorded(Box::new(partial_group.clone())),
                ],
            ),
            2,
        )
        .await
        .unwrap();
    let integrated_attempt = match revise_adoption(
        &partial_attempt,
        AttemptAdoptionStatus::Integrated,
        vec![integration_id],
        3,
    )
    .unwrap()
    {
        AttemptResolution::Revision(value) => *value,
        AttemptResolution::NoDelta => panic!("expected integrated attempt successor"),
    };
    writer
        .commit(
            &command(
                3,
                vec![JournalPayload::AttemptRecorded(Box::new(
                    integrated_attempt.clone(),
                ))],
            ),
            3,
        )
        .await
        .unwrap();
    let passed_attempt = match revise_verification(
        &integrated_attempt,
        AttemptVerification::Passed,
        vec!["verifier:prospective".into()],
        4,
    )
    .unwrap()
    {
        AttemptResolution::Revision(value) => *value,
        AttemptResolution::NoDelta => panic!("expected passed attempt successor"),
    };
    let selected_group = CompetingAttemptGroup {
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: Some(partial_group.revision_id),
        revision_generation: 3,
        resolution_status: CompetingResolutionStatus::Selected,
        selected_attempt_id: Some(selected.attempt_id),
        partially_integrated_attempt_ids: vec![],
        resolution_evidence_refs: vec![
            "integration:prospective".into(),
            "verifier:prospective".into(),
        ],
        source_watermark: 3,
        ..partial_group
    };
    writer
        .commit(
            &command(
                4,
                vec![
                    JournalPayload::AttemptRecorded(Box::new(passed_attempt)),
                    JournalPayload::CompetingAttemptGroupRecorded(Box::new(selected_group)),
                ],
            ),
            4,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn atomic_s13_binding_cross_links_are_symmetric_and_fail_before_append() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let (receipt, observation) = exact_observation();
    writer
        .commit(&evidence_command(receipt, observation.clone()), 1)
        .await
        .unwrap();
    let physical = PhysicalNormalizer::new(1)
        .unwrap()
        .normalize(&[observation], None)
        .unwrap();
    writer
        .commit(
            &physical
                .journal_command(CommandId::new_v7(), 2, CONFIG, "s14-attempt-v1")
                .unwrap(),
            2,
        )
        .await
        .unwrap();
    let operation_id = physical.operations[0].operation_id;
    let task_record = task();
    let stream_record = stream(task_record.task_id);
    let group_id = CompetingAttemptGroupId::new_v7();
    let binding_id = WorkBindingRevisionId::new_v7();
    let mut a = new_attempt(
        task_record.task_id,
        stream_record.workstream_id,
        None,
        vec![],
        vec![],
        contract("binding-a"),
        3,
    )
    .unwrap();
    let mut b = new_attempt(
        task_record.task_id,
        stream_record.workstream_id,
        None,
        vec![],
        vec![],
        contract("binding-b"),
        3,
    )
    .unwrap();
    a.competing_group_ids = vec![group_id];
    a.work_binding_revision_refs = vec![binding_id];
    b.competing_group_ids = vec![group_id];
    let mut members = vec![a.attempt_id, b.attempt_id];
    members.sort();
    let group = CompetingAttemptGroup {
        competing_group_id: group_id,
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        revision_generation: 1,
        task_id: task_record.task_id,
        decision_boundary_ref: "decision:binding".into(),
        comparison_contract_ref: None,
        origin_workstream_id: Some(stream_record.workstream_id),
        origin_episode_id: None,
        member_workstream_ids: vec![stream_record.workstream_id],
        member_attempt_ids: members,
        candidate_snapshot_refs: vec![],
        target_refs: vec![],
        conflict_kind: CompetingConflictKind::AlternativeStrategy,
        resolution_status: CompetingResolutionStatus::Open,
        selected_attempt_id: None,
        partially_integrated_attempt_ids: vec![],
        resolution_evidence_refs: vec![],
        source_watermark: 4,
    };
    let binding = WorkBindingRevision {
        work_binding_revision_id: binding_id,
        operation_id,
        revision_generation: 1,
        predecessor_revision_id: None,
        primary_binding: PrimaryWorkBinding {
            task_id: Some(task_record.task_id),
            workstream_id: Some(stream_record.workstream_id),
            episode_id: None,
            attempt_id: Some(a.attempt_id),
            experiment_run_id: None,
            competing_group_id: Some(group_id),
        },
        secondary_bindings: vec![],
        scope_effect_refs: vec![],
        assignment_status: AssignmentStatus::Resolved,
        evidence_refs: vec!["binding:atomic".into()],
        resolver_version: 1,
    };
    writer
        .commit(
            &command(
                3,
                vec![
                    JournalPayload::TaskRecorded(Box::new(task_record.clone())),
                    JournalPayload::WorkstreamRecorded(Box::new(stream_record.clone())),
                    JournalPayload::AttemptRecorded(Box::new(a.clone())),
                    JournalPayload::AttemptRecorded(Box::new(b)),
                    JournalPayload::CompetingAttemptGroupRecorded(Box::new(group)),
                    JournalPayload::WorkBindingRecorded(Box::new(binding.clone())),
                ],
            ),
            3,
        )
        .await
        .unwrap();
    let frontier = writer.journal_rows().await.unwrap().len();
    let successor = |primary: PrimaryWorkBinding, evidence: &str| WorkBindingRevision {
        work_binding_revision_id: WorkBindingRevisionId::new_v7(),
        operation_id,
        revision_generation: 2,
        predecessor_revision_id: Some(binding_id),
        primary_binding: primary,
        secondary_bindings: vec![],
        scope_effect_refs: vec![],
        assignment_status: AssignmentStatus::Resolved,
        evidence_refs: vec![evidence.into()],
        resolver_version: 1,
    };
    let dangling = successor(
        PrimaryWorkBinding {
            task_id: Some(task_record.task_id),
            workstream_id: Some(stream_record.workstream_id),
            episode_id: None,
            attempt_id: Some(evertrace_domain::ids::AttemptId::new_v7()),
            experiment_run_id: None,
            competing_group_id: None,
        },
        "binding:dangling",
    );
    assert!(
        writer
            .commit(
                &command(
                    4,
                    vec![JournalPayload::WorkBindingRecorded(Box::new(dangling))]
                ),
                4
            )
            .await
            .is_err()
    );
    let dangling_group = successor(
        PrimaryWorkBinding {
            task_id: Some(task_record.task_id),
            workstream_id: Some(stream_record.workstream_id),
            episode_id: None,
            attempt_id: None,
            experiment_run_id: None,
            competing_group_id: Some(CompetingAttemptGroupId::new_v7()),
        },
        "binding:dangling-group",
    );
    assert!(
        writer
            .commit(
                &command(
                    41,
                    vec![JournalPayload::WorkBindingRecorded(Box::new(
                        dangling_group
                    ))]
                ),
                4
            )
            .await
            .is_err()
    );
    let asymmetric = successor(
        PrimaryWorkBinding {
            task_id: Some(task_record.task_id),
            workstream_id: Some(stream_record.workstream_id),
            episode_id: None,
            attempt_id: Some(a.attempt_id),
            experiment_run_id: None,
            competing_group_id: None,
        },
        "binding:asymmetric",
    );
    assert!(
        writer
            .commit(
                &command(
                    5,
                    vec![JournalPayload::WorkBindingRecorded(Box::new(asymmetric))]
                ),
                4
            )
            .await
            .is_err()
    );
    let provisional = WorkBindingRevision {
        assignment_status: AssignmentStatus::Provisional,
        ..successor(
            PrimaryWorkBinding {
                task_id: Some(task_record.task_id),
                workstream_id: Some(stream_record.workstream_id),
                episode_id: None,
                attempt_id: Some(a.attempt_id),
                experiment_run_id: None,
                competing_group_id: None,
            },
            "binding:provisional",
        )
    };
    assert!(
        writer
            .commit(
                &command(
                    6,
                    vec![JournalPayload::WorkBindingRecorded(Box::new(provisional))]
                ),
                4
            )
            .await
            .is_err()
    );
    let task_two = task();
    let stream_two = stream(task_two.task_id);
    let cross = successor(
        PrimaryWorkBinding {
            task_id: Some(task_two.task_id),
            workstream_id: Some(stream_two.workstream_id),
            episode_id: None,
            attempt_id: Some(a.attempt_id),
            experiment_run_id: None,
            competing_group_id: None,
        },
        "binding:cross-task",
    );
    assert!(
        writer
            .commit(
                &command(
                    7,
                    vec![
                        JournalPayload::TaskRecorded(Box::new(task_two)),
                        JournalPayload::WorkstreamRecorded(Box::new(stream_two)),
                        JournalPayload::WorkBindingRecorded(Box::new(cross))
                    ]
                ),
                4
            )
            .await
            .is_err()
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), frontier);
}

#[test]
fn composition_rejects_cross_task_sources_and_cycles() {
    let first_task = task();
    let first_stream = stream(first_task.task_id);
    let second_task = task();
    let second_stream = stream(second_task.task_id);
    let a = new_attempt(
        first_task.task_id,
        first_stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("cycle-a"),
        1,
    )
    .unwrap();
    let b = new_attempt(
        first_task.task_id,
        first_stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("cycle-b"),
        1,
    )
    .unwrap();
    let foreign = new_attempt(
        second_task.task_id,
        second_stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("foreign"),
        1,
    )
    .unwrap();
    let candidate = new_attempt(
        first_task.task_id,
        first_stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("cross-task-composed"),
        2,
    )
    .unwrap();
    assert!(
        evertrace_engine::work::attempt::compose_attempt(candidate, &[a.clone(), foreign]).is_err()
    );

    let mut x = new_attempt(
        first_task.task_id,
        first_stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("cycle-x"),
        2,
    )
    .unwrap();
    let mut y = new_attempt(
        first_task.task_id,
        first_stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("cycle-y"),
        2,
    )
    .unwrap();
    x.composed_from_attempt_ids = {
        let mut ids = vec![a.attempt_id, y.attempt_id];
        ids.sort();
        ids
    };
    y.composed_from_attempt_ids = {
        let mut ids = vec![b.attempt_id, x.attempt_id];
        ids.sort();
        ids
    };
    assert!(build_attempt_relation_rows(&[a, b, x, y], &[]).is_err());
}

#[test]
fn group_resolution_and_composition_shapes_fail_closed() {
    let task = task();
    let stream = stream(task.task_id);
    let a = new_attempt(
        task.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("a"),
        1,
    )
    .unwrap();
    let b = new_attempt(
        task.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("b"),
        1,
    )
    .unwrap();
    let mut composed = new_attempt(
        task.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        contract("composed"),
        2,
    )
    .unwrap();
    composed = evertrace_engine::work::attempt::compose_attempt(composed, &[a.clone(), b.clone()])
        .unwrap();
    assert_ne!(composed.attempt_id, a.attempt_id);
    assert_eq!(composed.composed_from_attempt_ids.len(), 2);
    assert!(evertrace_engine::work::attempt::compose_attempt(composed.clone(), &[a]).is_err());
    let same_strategy = new_attempt(
        task.task_id,
        stream.workstream_id,
        None,
        vec![],
        vec![],
        b.strategy_contract.clone(),
        2,
    )
    .unwrap();
    assert!(
        evertrace_engine::work::attempt::compose_attempt(
            same_strategy,
            &[b.clone(), composed.clone()]
        )
        .is_err()
    );
    let mut invalid = CompetingAttemptGroup {
        competing_group_id: CompetingAttemptGroupId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        revision_generation: 1,
        task_id: task.task_id,
        decision_boundary_ref: "decision".into(),
        comparison_contract_ref: None,
        origin_workstream_id: None,
        origin_episode_id: None,
        member_workstream_ids: vec![stream.workstream_id],
        member_attempt_ids: {
            let mut ids = vec![b.attempt_id, composed.attempt_id];
            ids.sort();
            ids
        },
        candidate_snapshot_refs: vec![],
        target_refs: vec![],
        conflict_kind: CompetingConflictKind::AlternativeStrategy,
        resolution_status: CompetingResolutionStatus::Selected,
        selected_attempt_id: Some(b.attempt_id),
        partially_integrated_attempt_ids: vec![],
        resolution_evidence_refs: vec![],
        source_watermark: 1,
    };
    assert!(invalid.validate().is_err());
    invalid.resolution_evidence_refs = vec!["agent:summary".into()];
    assert!(invalid.validate().is_ok());
    assert!(build_attempt_relation_rows(&[b, composed], &[invalid]).is_err());
}
