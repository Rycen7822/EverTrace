use evertrace_capture::{
    DeviceKeyStore, RecallCueGateMode, RecoveryGateMode, RecoverySnapshotSettings, RuntimeSnapshot,
    SpoolLimits,
};
use evertrace_codex::binding::BINDING_PROTOCOL_REVISION;
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
        CaptureReceiptId, CommandId, ExecutionLaneId, OperationId, PresentationAttemptId,
        RecallNeedId, RequestId, TaskId, WorkBindingRevisionId, WorkstreamId,
    },
    recall::{
        RecallAgentResponse, RecallCueSnapshot, RecallDeliveryState, RecallLedgerEvent, RecallNeed,
        RecallObligationState, RecallPlan, RecallTriggerState, TriggerFamily,
    },
    revision::RevisionId,
    work::{
        AdmissionFailureObservability, AssignmentStatus, CaptureReceipt, CheckpointReason,
        CheckpointVerifierState, CoverageLevel, ExecutionLane, LaneStatus, LivenessState,
        OrderingIntegrity, PairingIntegrity, PayloadIntegrity, PhaseContract, PhaseKind,
        PrimaryWorkBinding, SourceCoverage, Task, TaskIdentityConfidence, TaskLifecycle,
        TaskScopeMembership, WorkBindingRevision, Workstream, WorkstreamStatus,
    },
};
use evertrace_engine::{
    McpActionService, McpBindingAuthority, McpBindingIssue, McpServiceAction, McpServiceRequest,
    McpServiceStatus, PhysicalNormalizer, RecallCueOutcome, RecallCueService, open_writer,
    recall::spawn_recall_worker,
    segmentation::{CheckpointResolution, build_checkpoint, capture_summary},
    spawn_writer,
    work::{WorkCommandContext, activate_episode, new_episode, save_checkpoint},
};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload,
    SourceIngestWatermark,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;

const CONFIG: [u8; 32] = [0x22; 32];
const MANIFEST: &str = "adapter-manifest-s22";
const SESSION: &str = "session-s22-real";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn command(at: i64, payloads: Vec<JournalPayload>) -> JournalCommand {
    JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, CONFIG, "s22-test-v1", payload))
            .collect(),
    )
    .unwrap()
}

fn work_context(at: i64) -> WorkCommandContext {
    WorkCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: "s22-test-v1",
    }
}

fn evidence() -> (SourceReceipt, SourceObservation) {
    let instance = SourceInstanceId::parse("source-s22").unwrap();
    let revision = SourceRevision::parse("revision-1").unwrap();
    let record = SourceRecordIdentity::parse("record-s22").unwrap();
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
    let correlation = HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: Some("host-s22".into()),
        host_trace_lineage_id: Some("trace-s22".into()),
        host_lane_key: Some("host-lane-s22".into()),
        canonical_event_family: Some(CanonicalEventFamily::Mutate),
        native_request_id: Some("request-s22".into()),
        physical_execution_ordinal: Some(1),
        pairing_role: ObservationRole::Intent,
        field_provenance: fields
            .into_iter()
            .map(|field| CorrelationFieldClaim {
                field,
                source_ref: "source-s22".into(),
                evidence_ref: format!("evidence-{field:?}"),
            })
            .collect(),
        adapter_manifest_ref: MANIFEST.into(),
        adapter_revision: 1,
        strong_gate_receipt_ref: Some("strong-gate-s22".into()),
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
        source_ref: "source-ref-s22".into(),
        source_session_ref: SESSION.into(),
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
        observation_role: ObservationRole::Intent,
        unsupported_record_classification: None,
        capture_completeness: CaptureCompleteness::Complete,
        archive_mode: SourceArchiveMode::Exact,
        cas_ref: DIGEST.into(),
        protected_length: 1,
        original_length: 1,
        protected_secret_digest: None,
        redaction_spans: Vec::new(),
        adapter_revision: 1,
        adapter_manifest_ref: MANIFEST.into(),
        eligible_event_manifest_ref: "eligible-s22".into(),
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
        scope_effect_claims: Vec::new(),
    };
    receipt.validate().unwrap();
    observation.validate().unwrap();
    (receipt, observation)
}

fn task() -> Task {
    Task {
        task_id: TaskId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec!["request-s22".into()],
        canonical_goal: "prove recall delivery".into(),
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
        source_watermark: 3,
    }
}

fn phase() -> PhaseContract {
    PhaseContract {
        local_goal: "prove recall delivery".into(),
        phase_kind: PhaseKind::Verify,
        phase_label: "verify".into(),
        primary_targets: vec!["recall".into()],
        entry_conditions: vec!["open episode".into()],
        acceptance_boundary: "real worker".into(),
        expected_state_transition: "recall need".into(),
    }
}

fn workstream(task_id: TaskId, lane_id: ExecutionLaneId) -> Workstream {
    Workstream {
        workstream_id: WorkstreamId::new_v7(),
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
        root_goal: "prove recall delivery".into(),
        workstream_goal: "run one episode".into(),
        target_family: "recall".into(),
        hypothesis_or_failure_family: "delivery".into(),
        acceptance_boundary: "real worker".into(),
        phase_contract: phase(),
        active_episode_id: None,
        execution_lane_ids: vec![lane_id],
        source_watermark: 3,
    }
}

fn capture_receipt(lane_id: ExecutionLaneId, source_ref: String) -> CaptureReceipt {
    CaptureReceipt {
        capture_receipt_revision_id: CaptureReceiptId::new_v7(),
        execution_lane_id: lane_id,
        predecessor_revision_id: None,
        adapter_manifest_ids: vec![MANIFEST.into()],
        eligible_event_manifest_refs: vec!["eligible-s22".into()],
        source_revision_refs: vec![source_ref],
        source_close_watermark_refs: vec!["source-s22@revision-1:1".into()],
        source_close_reconciliation_refs: Vec::new(),
        admission_failure_evidence_refs: Vec::new(),
        admission_failure_observability: AdmissionFailureObservability::Complete,
        identity_strength: IdentityStrength::StableNative,
        delegation_start_seen: false,
        child_session_linked: false,
        child_session_id: None,
        parent_session_end_seen: false,
        lifecycle_end_seen: false,
        terminal_event_kind: None,
        terminal_event_ref: None,
        termination_evidence_refs: Vec::new(),
        source_closed_refs: Vec::new(),
        liveness_probe_refs: Vec::new(),
        finalization_reason: None,
        first_sequence: Some(1),
        last_sequence: Some(1),
        sequence_gaps: Vec::new(),
        capture_gap_marker_refs: Vec::new(),
        capture_outage_interval_refs: Vec::new(),
        tool_calls_seen: Vec::new(),
        tool_results_seen: Vec::new(),
        unmatched_tool_call_ids: Vec::new(),
        unmatched_tool_result_ids: Vec::new(),
        payload_truncations: Vec::new(),
        redaction_refs: Vec::new(),
        corrupt_payload_refs: Vec::new(),
        unsupported_record_types: Vec::new(),
        import_watermark: 1,
        finalized: false,
        coverage_level: CoverageLevel::Partial,
        source_coverage: SourceCoverage::Partial,
        pairing_integrity: PairingIntegrity::Complete,
        payload_integrity: PayloadIntegrity::Complete,
        ordering_integrity: OrderingIntegrity::Complete,
        reasoning_visibility: Vec::new(),
        exact_byte_replay: true,
        resolver_version: 1,
    }
}

fn lane(
    lane_id: ExecutionLaneId,
    operation_id: OperationId,
    receipt: &CaptureReceipt,
) -> ExecutionLane {
    ExecutionLane {
        execution_lane_id: lane_id,
        lane_revision: 1,
        predecessor_revision: None,
        host_session_id: SESSION.into(),
        agent_id: "agent-s22".into(),
        host_lane_key: "host-lane-s22".into(),
        incarnation_ref: "incarnation-s22".into(),
        parent_lane_id: None,
        parent_host_lane_key: None,
        spawn_event_ref: None,
        terminal_event_ref: None,
        termination_evidence_refs: Vec::new(),
        delegated_goal_ref: None,
        delegated_target_refs: Vec::new(),
        delegated_acceptance_refs: Vec::new(),
        status: LaneStatus::Active,
        terminal_kind: None,
        liveness_state: LivenessState::Live,
        liveness_probe_refs: Vec::new(),
        finalized: false,
        event_watermark: 1,
        adapter_manifest_ids: vec![MANIFEST.into()],
        active_capture_receipt_revision_id: receipt.capture_receipt_revision_id,
        coverage_level: receipt.coverage_level,
        source_coverage: receipt.source_coverage,
        pairing_integrity: receipt.pairing_integrity,
        payload_integrity: receipt.payload_integrity,
        ordering_integrity: receipt.ordering_integrity,
        reasoning_visibility: Vec::new(),
        operation_ids: vec![operation_id],
        correction_reason: None,
    }
}

fn runtime(data_dir: &std::path::Path) -> RuntimeSnapshot {
    let runtime_dir = data_dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    RuntimeSnapshot::for_data_dir(
        data_dir,
        1,
        SpoolLimits {
            high_watermark_bytes: 1024,
            low_watermark_bytes: 512,
            max_main_files: 4,
            emergency_slots: 2,
        },
        RecoverySnapshotSettings {
            gate: RecoveryGateMode::Disabled,
            preflight_timeout_ms: 100,
            effective_config_hash: CONFIG,
            adapter_manifest_id: None,
            classifier_revision: 1,
            max_bundle_bytes: 4096,
            max_untracked_file_bytes: 1024,
            max_untracked_total_bytes: 2048,
            recall_cue_gate: RecallCueGateMode::Active,
            recall_cue_adapter_manifest_id: Some(MANIFEST.into()),
        },
    )
    .unwrap()
}

struct RunningRecall {
    _root: TempDir,
    handle: evertrace_engine::WriterHandle,
    writer_task: tokio::task::JoinHandle<Result<(), evertrace_engine::WriterActorError>>,
    worker: tokio::task::JoinHandle<()>,
    data_dir: std::path::PathBuf,
    current_episode_revision: RevisionId,
}

async fn commit_quick(handle: &evertrace_engine::WriterHandle, value: JournalCommand, at: i64) {
    tokio::time::timeout(Duration::from_secs(1), handle.commit(value, at))
        .await
        .expect("source commit must not wait for recall")
        .unwrap();
}

async fn start_real_recall(root: TempDir) -> RunningRecall {
    let data_dir = root.path().join("data");
    let writer = open_writer(&data_dir).await.unwrap();
    let (handle, writer_task) = spawn_writer(writer, 8).unwrap();
    let runtime = runtime(&data_dir);
    runtime
        .publish(&RuntimeSnapshot::snapshot_path(&data_dir))
        .unwrap();
    let worker = spawn_recall_worker(handle.clone(), runtime, data_dir.clone());

    let (source_receipt, observation) = evidence();
    let target = observation.source_observation_id.to_string();
    commit_quick(
        &handle,
        command(
            1,
            vec![
                JournalPayload::SourceReceiptRecorded(Box::new(source_receipt.clone())),
                JournalPayload::SourceObservationRecorded(Box::new(observation.clone())),
                JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
                    source_instance_id: source_receipt.source_instance_id.clone(),
                    source_revision: source_receipt.source_revision.clone(),
                    source_sequence: 1,
                    confirmed_prefix_digest: None,
                }),
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::EvidenceSurface,
                    target_id: target.clone(),
                    algorithm_revision: "s22-test-v1".into(),
                    source_watermark: 1,
                }),
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::PhysicalNormalization,
                    target_id: target,
                    algorithm_revision: "s22-test-v1".into(),
                    source_watermark: 1,
                }),
            ],
        ),
        1,
    )
    .await;
    let physical = PhysicalNormalizer::new(1)
        .unwrap()
        .normalize(std::slice::from_ref(&observation), None)
        .unwrap();
    let operation_id = physical.operations[0].operation_id;
    commit_quick(
        &handle,
        physical
            .journal_command(CommandId::new_v7(), 2, CONFIG, "s22-test-v1")
            .unwrap(),
        2,
    )
    .await;

    let lane_id = ExecutionLaneId::new_v7();
    let source_ref = format!(
        "{}@{}",
        source_receipt.source_instance_id.as_str(),
        source_receipt.source_revision.as_str()
    );
    let receipt = capture_receipt(lane_id, source_ref);
    let execution_lane = lane(lane_id, operation_id, &receipt);
    let task = task();
    let stream = workstream(task.task_id, lane_id);
    commit_quick(
        &handle,
        command(
            3,
            vec![
                JournalPayload::TaskRecorded(Box::new(task.clone())),
                JournalPayload::WorkstreamRecorded(Box::new(stream.clone())),
                JournalPayload::ExecutionLaneRecorded(Box::new(execution_lane)),
                JournalPayload::CaptureReceiptRecorded(Box::new(receipt.clone())),
            ],
        ),
        3,
    )
    .await;

    let mut episode = new_episode(&stream, None, 4).unwrap();
    episode.session_ids = vec![SESSION.into()];
    episode.execution_lane_ids = vec![lane_id];
    episode.capture_receipt_revision_ids = vec![receipt.capture_receipt_revision_id];
    episode.capture_summary = capture_summary(std::slice::from_ref(&receipt)).unwrap();
    episode.capture_watermark = receipt.import_watermark;
    episode.open_loops = vec!["finish s22 proof".into()];
    episode.validate().unwrap();
    let binding = WorkBindingRevision {
        work_binding_revision_id: WorkBindingRevisionId::new_v7(),
        operation_id,
        revision_generation: 1,
        predecessor_revision_id: None,
        primary_binding: PrimaryWorkBinding {
            task_id: Some(task.task_id),
            workstream_id: Some(stream.workstream_id),
            episode_id: Some(episode.episode_id),
            ..PrimaryWorkBinding::default()
        },
        secondary_bindings: Vec::new(),
        scope_effect_refs: Vec::new(),
        assignment_status: AssignmentStatus::Resolved,
        evidence_refs: vec![observation.source_observation_id.to_string()],
        resolver_version: 1,
    };
    commit_quick(
        &handle,
        activate_episode(
            work_context(4),
            &stream,
            episode.clone(),
            Vec::new(),
            vec![binding],
        )
        .unwrap(),
        4,
    )
    .await;

    let checkpoint =
        match build_checkpoint(&episode, &[], None, CheckpointReason::Compact, None).unwrap() {
            CheckpointResolution::Checkpoint(value) => *value,
            CheckpointResolution::NoDelta => panic!("first checkpoint must be a delta"),
        };
    let checkpoint_command = save_checkpoint(work_context(5), &episode, checkpoint, None)
        .unwrap()
        .unwrap();
    let current_episode_revision = checkpoint_command
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::WorkEpisodeRecorded(value) => Some(value.revision_id),
            _ => None,
        })
        .unwrap();
    commit_quick(&handle, checkpoint_command, 5).await;
    RunningRecall {
        _root: root,
        handle,
        writer_task,
        worker,
        data_dir,
        current_episode_revision,
    }
}

async fn wait_for_need_and_cue(
    running: &RunningRecall,
) -> (evertrace_store::RecallCurrentContext, RecallCueSnapshot) {
    let mut changes = running.handle.subscribe_recall_frontier();
    for _ in 0..6 {
        let contexts = running.handle.recall_current_contexts(32).await.unwrap();
        if let Some(context) = contexts
            .iter()
            .find(|value| !value.needs.is_empty())
            .cloned()
        {
            let cue = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    tokio::task::yield_now().await;
                    let snapshot =
                        RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&running.data_dir))
                            .unwrap();
                    if let Some(cue) = snapshot.recall_cues.first() {
                        break cue.clone();
                    }
                }
            })
            .await
            .expect("recall worker cue publication");
            return (context, cue);
        }
        tokio::time::timeout(Duration::from_secs(2), changes.changed())
            .await
            .expect("recall worker notification")
            .unwrap();
    }
    panic!("recall worker did not publish a need and cue")
}

fn need() -> RecallNeed {
    let source = RevisionId::new_v7();
    RecallNeed {
        recall_need_id: RecallNeedId::new_v7(),
        revision_id: RevisionId::new_v7(),
        parent_revision_id: None,
        recall_need_hash: [0; 32],
        trigger_family: TriggerFamily::ProspectiveObligation,
        source_revision_ids: vec![source],
        matched_contract_ids: vec![[7; 32]],
        session_id: "session-s22".into(),
        execution_lane_id: ExecutionLaneId::new_v7(),
        task_id: TaskId::new_v7(),
        workstream_id: WorkstreamId::new_v7(),
        episode_revision_id: RevisionId::new_v7(),
        repository_id: None,
        worktree_id: None,
        boundary_event_ref: "boundary:s22".into(),
        trigger_state: RecallTriggerState {
            phase_kind: PhaseKind::Deliver,
            verifier_state: CheckpointVerifierState::Passed,
            attempt_ids: Vec::new(),
            worktree_snapshot_id: None,
            binding_revision_id: None,
            scope_effect_refs: Vec::new(),
        },
        source_watermark: 9,
        recall_plan_fingerprint: [0; 32],
        recall_plan: RecallPlan {
            reason: "prospective_obligation".into(),
            normative_constraint_refs: vec![source.to_string()],
            relevant_episode_revision: None,
            applicable_procedure_revision: None,
            open_loops: Vec::new(),
            stale_delivered_objects: Vec::new(),
            supporting_evidence_refs: Vec::new(),
        },
        delivery_state: RecallDeliveryState::Detected,
        agent_response: RecallAgentResponse::NotRetrieved,
        obligation_state: RecallObligationState::Active,
        created_at_us: 1,
        presentation_expires_at_us: 10,
        obligation_expires_at_us: None,
        active_presentation_attempt_id: None,
        active_retrieval_request_id: None,
    }
    .seal()
    .unwrap()
}

#[test]
fn closed_ledger_family_and_cue_snapshot_reject_tamper() {
    let need = need();
    let payload = JournalPayload::RecallLedgerRecorded(Box::new(RecallLedgerEvent::NeedRecorded {
        need: Box::new(need.clone()),
    }));
    payload.validate().unwrap();
    let command = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            1,
            [9; 32],
            "s22-recall-v1",
            payload,
        )],
    )
    .unwrap();
    assert_eq!(command.events().len(), 1);
    assert_eq!(
        command.events()[0].payload.event_type(),
        "recall_ledger_recorded_v1"
    );

    let mut cue = RecallCueSnapshot {
        session_id: need.session_id,
        execution_lane_id: need.execution_lane_id,
        host_lane_key: "lane:s22".into(),
        adapter_manifest_id: "adapter:s22".into(),
        runtime_generation: 1,
        recall_need_hash: need.recall_need_hash,
        presentation_attempt_id: PresentationAttemptId::new_v7(),
        expires_at_us: 10,
        checksum: [0; 32],
    }
    .seal()
    .unwrap();
    assert!(cue.validate());
    cue.session_id.push_str("-tamper");
    assert!(!cue.validate());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_cue_authorize_fences_before_fixed_emit_and_acks_on_one_connection() {
    let root = TempDir::new().unwrap();
    let server = evertrace_protocol::LocalServer::bind(
        root.path(),
        evertrace_protocol::ServerOptions::new("s22-test"),
    )
    .unwrap();
    let socket = server.socket_path().to_owned();
    let claimed = Arc::new(AtomicBool::new(false));
    let connection = Arc::new(Mutex::new(None::<String>));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handler_claimed = Arc::clone(&claimed);
    let handler_connection = Arc::clone(&connection);
    let server_task = tokio::spawn(server.run_dispatch_with_context(
        shutdown_rx,
        move |context, _request_id, command| {
            let claimed = Arc::clone(&handler_claimed);
            let connection = Arc::clone(&handler_connection);
            async move {
                match command {
                    evertrace_protocol::command::Command::RecallCue(
                        evertrace_protocol::command::RecallCueCommand::Authorize { snapshot },
                    ) => {
                        *connection.lock().unwrap() = Some(context.connection_id);
                        assert!(snapshot.validate());
                        claimed.store(true, Ordering::SeqCst);
                        Ok(evertrace_protocol::response::Response::RecallCue(
                            evertrace_protocol::response::RecallCueResponse::Authorized,
                        ))
                    }
                    evertrace_protocol::command::Command::RecallCue(
                        evertrace_protocol::command::RecallCueCommand::Outcome {
                            snapshot,
                            outcome,
                        },
                    ) => {
                        assert!(snapshot.validate());
                        assert_eq!(
                            outcome,
                            evertrace_domain::recall::PresentationAttemptState::Emitted
                        );
                        assert_eq!(
                            connection.lock().unwrap().as_deref(),
                            Some(context.connection_id.as_str())
                        );
                        Ok(evertrace_protocol::response::Response::RecallCue(
                            evertrace_protocol::response::RecallCueResponse::OutcomeAccepted,
                        ))
                    }
                    _ => Err(evertrace_protocol::error::ErrorCode::InvalidInput),
                }
            }
        },
    ));
    let emit_claimed = Arc::clone(&claimed);
    let snapshot = RecallCueSnapshot {
        session_id: "session-s22".into(),
        execution_lane_id: ExecutionLaneId::new_v7(),
        host_lane_key: "lane:s22".into(),
        adapter_manifest_id: "adapter:s22".into(),
        runtime_generation: 1,
        recall_need_hash: [8; 32],
        presentation_attempt_id: PresentationAttemptId::new_v7(),
        expires_at_us: i64::MAX,
        checksum: [0; 32],
    }
    .seal()
    .unwrap();
    let emitted = tokio::task::spawn_blocking(move || {
        evertrace_protocol::request_recall_cue_sync(
            &socket,
            "s22-test",
            snapshot,
            Duration::from_secs(2),
            |_| {
                assert!(emit_claimed.load(Ordering::SeqCst));
                evertrace_domain::recall::PresentationAttemptState::Emitted
            },
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert!(emitted);
    shutdown_tx.send(true).unwrap();
    server_task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_worker_detects_checkpoint_lineage_and_keeps_four_tables() {
    let running = start_real_recall(TempDir::new().unwrap()).await;
    let (context, cue) = wait_for_need_and_cue(&running).await;
    assert_eq!(
        context.episode.revision_id,
        running.current_episode_revision
    );
    assert_eq!(
        context.checkpoint.episode_revision_id,
        context.episode.predecessor_revision_id.unwrap()
    );
    assert!(context.previous_checkpoint.is_none());
    assert_eq!(context.needs.len(), 1);
    let need = &context.needs[0];
    assert_eq!(need.trigger_family, TriggerFamily::ExplicitOrRecovery);
    assert!(need.matched_contract_ids.is_empty());
    assert_eq!(
        need.source_revision_ids,
        vec![running.current_episode_revision]
    );
    assert_eq!(need.recall_plan.open_loops, vec!["finish s22 proof"]);
    assert_eq!(cue.recall_need_hash, need.recall_need_hash);
    assert_eq!(cue.session_id, SESSION);

    let authority = McpBindingAuthority::new(
        DeviceKeyStore::new(running.data_dir.join("device-key"))
            .load_or_create()
            .unwrap(),
    );
    let grant = authority
        .issue(McpBindingIssue {
            session_id: SESSION.into(),
            turn_id: "turn-s22-due".into(),
            tool_use_id: "tool-s22-due".into(),
            agent_id: Some("agent-s22".into()),
            action: "search".into(),
            workspace: "@active".into(),
            input: "@due".into(),
            refs: Vec::new(),
            launcher_protocol_revision: BINDING_PROTOCOL_REVISION,
        })
        .unwrap();
    let service = McpActionService::open(
        authority,
        &running.data_dir,
        running.handle.clone(),
        runtime(&running.data_dir),
    )
    .await
    .unwrap();
    let due = service
        .handle(
            "connection-s22-due",
            McpServiceRequest {
                request_id: RequestId::new_v7(),
                action: McpServiceAction::Search,
                workspace: grant.bound_workspace,
                input: "@due".into(),
                refs: Vec::new(),
                client_cwd: "/s22".into(),
            },
        )
        .await
        .unwrap();
    assert!(
        matches!(due.status, McpServiceStatus::Ok | McpServiceStatus::Partial),
        "{due:?}"
    );
    assert!(!due.items.is_empty(), "@due must return the mandatory plan");
    let after_due = running.handle.recall_current_contexts(32).await.unwrap();
    let retrieved = after_due
        .iter()
        .flat_map(|value| &value.needs)
        .find(|value| value.recall_need_id == need.recall_need_id)
        .unwrap();
    assert_eq!(
        retrieved.agent_response,
        RecallAgentResponse::RetrievalReturned
    );

    let mut changes = running.handle.subscribe_recall_frontier();
    let next_checkpoint = match build_checkpoint(
        &context.episode,
        &[],
        None,
        CheckpointReason::Manual,
        Some(&context.checkpoint),
    )
    .unwrap()
    {
        CheckpointResolution::Checkpoint(value) => *value,
        CheckpointResolution::NoDelta => panic!("different checkpoint reason must be a delta"),
    };
    let next_command = save_checkpoint(
        work_context(6),
        &context.episode,
        next_checkpoint,
        Some(&context.checkpoint),
    )
    .unwrap()
    .unwrap();
    let next_episode_revision = next_command
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::WorkEpisodeRecorded(value) => Some(value.revision_id),
            _ => None,
        })
        .unwrap();
    commit_quick(&running.handle, next_command, 6).await;
    let advanced = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            changes.changed().await.unwrap();
            let contexts = running.handle.recall_current_contexts(32).await.unwrap();
            if let Some(context) = contexts
                .into_iter()
                .find(|value| value.episode.revision_id == next_episode_revision)
                && context.needs.is_empty()
            {
                break context;
            }
        }
    })
    .await
    .expect("worker terminalizes the stale need");
    assert_eq!(
        advanced.checkpoint.episode_revision_id,
        context.episode.revision_id
    );
    assert_eq!(
        advanced
            .previous_checkpoint
            .as_ref()
            .unwrap()
            .episode_revision_id,
        context.checkpoint.episode_revision_id
    );
    assert_eq!(advanced.checkpoint.created_reason, CheckpointReason::Manual);
    assert_eq!(
        advanced.previous_checkpoint.unwrap().created_reason,
        CheckpointReason::Compact
    );

    running.worker.abort();
    let _ = running.worker.await;
    running.handle.shutdown().await.unwrap();
    running.writer_task.await.unwrap().unwrap();
    let reopened = evertrace_store::JournalWriter::open(&running.data_dir)
        .await
        .unwrap();
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
async fn real_cue_service_has_one_authorize_winner_and_idempotent_outcome() {
    let running = start_real_recall(TempDir::new().unwrap()).await;
    let (_, cue) = wait_for_need_and_cue(&running).await;
    running.worker.abort();
    let _ = running.worker.await;
    let service = RecallCueService::new(
        running.handle.clone(),
        RecallCueGateMode::Active,
        Some(MANIFEST.into()),
        1,
        CONFIG,
        &running.data_dir,
    );
    let (first, second) = tokio::join!(service.authorize(&cue), service.authorize(&cue));
    assert_eq!(
        [first, second]
            .into_iter()
            .filter(|value| *value == Ok(RecallCueOutcome::Authorized))
            .count(),
        1
    );
    let claimed = running.handle.recall_current_contexts(32).await.unwrap();
    assert_eq!(
        claimed[0].needs[0].delivery_state,
        RecallDeliveryState::ClaimedForBoundary
    );
    assert_eq!(
        claimed[0].needs[0].active_presentation_attempt_id,
        Some(cue.presentation_attempt_id)
    );
    let (first_outcome, replayed_outcome) = tokio::join!(
        service.outcome(
            &cue,
            evertrace_domain::recall::PresentationAttemptState::Emitted
        ),
        service.outcome(
            &cue,
            evertrace_domain::recall::PresentationAttemptState::Emitted
        )
    );
    assert_eq!(first_outcome, Ok(RecallCueOutcome::OutcomeAccepted));
    assert_eq!(replayed_outcome, Ok(RecallCueOutcome::OutcomeAccepted));
    let before_replay = running.handle.recall_current_contexts(32).await.unwrap()[0].frontier;
    assert_eq!(
        service
            .outcome(
                &cue,
                evertrace_domain::recall::PresentationAttemptState::Emitted,
            )
            .await,
        Ok(RecallCueOutcome::OutcomeAccepted)
    );
    let after_replay = running.handle.recall_current_contexts(32).await.unwrap()[0].frontier;
    assert_eq!(before_replay, after_replay);
    assert!(
        service
            .outcome(
                &cue,
                evertrace_domain::recall::PresentationAttemptState::PresentationUnknown,
            )
            .await
            .is_err()
    );
    running.handle.shutdown().await.unwrap();
    running.writer_task.await.unwrap().unwrap();
}
