use std::{path::Path, sync::Arc};

#[allow(dead_code)]
#[path = "../src/provider.rs"]
mod provider_stub;

use evertrace_capture::{
    CaptureAdmissionState, CaptureRecordInput, CaptureRuntime, DeviceKeyStore,
    RUNTIME_SNAPSHOT_VERSION, RecallCueGateMode, RecoveryGateMode, RuntimeSnapshot,
};
use evertrace_codex::{
    EvidenceSourceKind as ProbeEvidenceSourceKind, HostProbeReport, ProbeContext, ProbeEvidence,
    adapter_manifest::AdapterKind,
};
use evertrace_domain::{
    config::{DreamingConfig, DurationValue, LlmConfig, ValidatedBaseUrl},
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission,
        EvidenceSourceKind as DomainEvidenceSourceKind, HostCorrelationEvidence, IdentityStrength,
        InstructionAuthority, ObservationRole, Operation, OperationKind, PairingState,
        SourceRevisionMode, SourceRole, evidence_span_hash, hex,
    },
    ids::{
        CommandId, HostOccurrenceId, JobId, OperationId, SemanticDerivationRunId,
        SourceObservationId, TaskId, WorkBindingRevisionId, WorkstreamId,
    },
    revision::RevisionId,
    semantic::{
        DerivationQuotaUsage, DerivationRunStatus, SemanticCompleteness, SemanticDerivationRun,
        SemanticDigestTrigger, job_fingerprint,
    },
    work::{
        AssignmentStatus, LaneLifecycleEvidence, LivenessState, PhaseContract, PhaseKind,
        PrimaryWorkBinding, WorkBindingRevision, Workstream, WorkstreamStatus,
    },
};
use evertrace_engine::provider::ProviderSemanticApplication;
use evertrace_engine::{
    BackgroundLane, BackgroundScheduler, EvidenceIngestor, JobResultDisposition,
    SessionImportWorker, SynthesisPlanner, WriterActorError, WriterHandle,
    capture::{ReconcileInput, reconcile_observations_once},
    classify_job_result, open_writer, select_jobs,
    session_import::SessionCatalogService,
    spawn_writer,
    work::new_episode,
};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, DurableJob, JobBudget, JobLease, JobStatus, JobTerminalAudit,
    JobTerminalOutcome, JobTerminalReason, JournalCommand, JournalEventDraft, JournalPayload,
    JournalWriter, ObjectRow, ObjectRowClass, ObjectRowKind, ProjectionSnapshot,
    RuntimeSchedulerView,
};
use tempfile::TempDir;
use tokio::sync::RwLock;

use provider_stub::ProviderStub;

const CONFIG: [u8; 32] = [29; 32];

fn budget() -> JobBudget {
    JobBudget {
        max_items: 4,
        max_bytes: Some(4096),
        max_input_tokens: None,
        max_output_tokens: None,
        max_calls: None,
        max_wall_time_ms: 250,
    }
}

fn job(kind: &str, key: &str, generation: u64, priority: i16) -> DurableJob {
    let mut budget = budget();
    if kind == "semantic_synthesis_v1" {
        budget.max_input_tokens = Some(1024);
        budget.max_output_tokens = Some(1024);
        budget.max_calls = Some(1);
    }
    DurableJob {
        job_id: JobId::new_v7(),
        idempotency_key: key.into(),
        target_revision: format!("revision-{generation}"),
        target_watermark: generation,
        target_generation: generation,
        kind: kind.into(),
        algorithm_revision: format!("{kind}-v1"),
        model_id: (kind == "semantic_synthesis_v1").then(|| "model-a".into()),
        priority,
        state: JobStatus::Queued,
        attempt: 1,
        backoff_until_us: None,
        config_hash: [7; 32],
        budget,
        terminal: None,
        lease_until_us: None,
    }
}

fn runtime(root: &Path) -> RuntimeSnapshot {
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
        effective_config_hash: CONFIG,
        recovery_gate: RecoveryGateMode::Disabled,
        recovery_adapter_manifest_id: None,
        recovery_classifier_revision: 1,
        recovery_socket_path: root.join("runtime/evertraced-v1.sock"),
        recovery_preflight_timeout_ms: 250,
        recovery_max_bundle_bytes: 4 << 20,
        recovery_max_untracked_file_bytes: 1 << 20,
        recovery_max_untracked_total_bytes: 2 << 20,
        recall_cue_gate: RecallCueGateMode::Disabled,
        recall_cue_adapter_manifest_id: None,
        recall_cues: Vec::new(),
    }
}

fn make_scheduler(
    writer: WriterHandle,
    runtime: RuntimeSnapshot,
    report: Arc<RwLock<Option<HostProbeReport>>>,
) -> BackgroundScheduler {
    make_scheduler_with_interval(
        writer,
        runtime,
        report,
        std::time::Duration::from_secs(3_600),
    )
}

fn make_scheduler_with_interval(
    writer: WriterHandle,
    runtime: RuntimeSnapshot,
    report: Arc<RwLock<Option<HostProbeReport>>>,
    integrity_sweep_interval: std::time::Duration,
) -> BackgroundScheduler {
    let dreaming = DreamingConfig {
        integrity_sweep_interval: DurationValue::from_seconds(integrity_sweep_interval.as_secs())
            .unwrap(),
        ..DreamingConfig::default()
    };
    BackgroundScheduler::new(
        writer.clone(),
        SessionCatalogService::new(writer.clone(), CONFIG),
        SessionImportWorker::new(writer, runtime.clone(), Arc::clone(&report)).unwrap(),
        report,
        runtime,
        SynthesisPlanner::new(LlmConfig {
            enabled: false,
            ..LlmConfig::default()
        }),
        dreaming,
    )
}

fn synthetic_report() -> HostProbeReport {
    HostProbeReport::evaluate(
        &ProbeContext {
            adapter_kind: AdapterKind::CodexHook,
            adapter_revision: "s29-synthetic-hook-v1".into(),
            observed_host_version_range: "s29-test".into(),
            eligible_event_manifest_ref: "s29-capture-events-v1".into(),
            evidence_source: ProbeEvidenceSourceKind::SyntheticFixture,
        },
        &ProbeEvidence::empty(),
    )
    .unwrap()
}

fn capture_input(report: &HostProbeReport) -> CaptureRecordInput {
    let manifest = report.manifest();
    let role = ObservationRole::Lifecycle;
    CaptureRecordInput {
        spool_record_id: Some("s29-capture-record".into()),
        source_observation_id_hint: None,
        source_instance_id: "s29-capture-source".into(),
        source_revision: "revision-v1".into(),
        source_record_identity: Some("record-1".into()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: DomainEvidenceSourceKind::CodexSessionJsonl,
        identity_domain: "s29-capture-v1".into(),
        source_ref: "source:s29-capture".into(),
        session_ref: "session-s29".into(),
        turn_ref: None,
        tool_ref: None,
        source_sequence: 1,
        source_sequence_origin: None,
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        source_byte_range: None,
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: None,
        observation_role: role,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            pairing_role: role,
            field_provenance: Vec::new(),
            adapter_manifest_ref: manifest.adapter_manifest_id.clone(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: Vec::new(),
        lifecycle: Some(LaneLifecycleEvidence {
            host_session_id: "session-s29".into(),
            agent_id: "agent-s29".into(),
            incarnation_ref: Some("incarnation-s29".into()),
            child_session_id: None,
            host_lane_key: "lane-s29".into(),
            parent_host_lane_key: None,
            spawn_event_ref: None,
            terminal_event_ref: None,
            terminal_kind: None,
            host_final_return: false,
            source_close_ref: None,
            parent_session_end_ref: None,
            liveness_probe_ref: Some("liveness-s29".into()),
            liveness_state: LivenessState::Live,
            lane_sequence: 1,
            adapter_manifest_ref: manifest.adapter_manifest_id.clone(),
            eligible_event_manifest_ref: manifest.eligible_event_manifest_refs[0].clone(),
            delegated_goal_ref: None,
            delegated_target_refs: Vec::new(),
            delegated_acceptance_refs: Vec::new(),
            reasoning_visibility: Vec::new(),
        }),
        unsupported_record_classification: None,
        source_role: SourceRole::Host,
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Complete,
        surface_eligible: false,
        adapter_revision: 1,
        adapter_manifest_ref: manifest.adapter_manifest_id.clone(),
        eligible_event_manifest_ref: manifest.eligible_event_manifest_refs[0].clone(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: Some(1),
        raw_payload: b"s29 capture lifecycle".to_vec(),
    }
}

fn runtime_row(payload: JournalPayload, seq: u64) -> ObjectRow {
    let key = match &payload {
        JournalPayload::JobState(job) => format!("runtime:job:{}", job.job_id),
        JournalPayload::DirtyTarget(dirty) => format!("runtime:dirty:{}", dirty.stable_key()),
        _ => panic!("unsupported runtime row"),
    };
    ObjectRow {
        row_id: key,
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Runtime),
        object_family: None,
        object_kind: None,
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
        payload_json: Some(payload.canonical_json().unwrap()),
        source_event_seq: seq,
        projection_generation: 1,
    }
}

fn synthesis_episode_row(watermark: u64) -> ObjectRow {
    synthesis_episode_row_for_task(watermark, TaskId::new_v7())
}

fn synthesis_episode_row_for_task(watermark: u64, task_id: TaskId) -> ObjectRow {
    let workstream = Workstream {
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
        root_goal: "s29 synthesis selection".into(),
        workstream_goal: "select uncovered episode".into(),
        target_family: "semantic digest".into(),
        hypothesis_or_failure_family: "covered tuple".into(),
        acceptance_boundary: "ninth episode is selected".into(),
        phase_contract: PhaseContract {
            local_goal: "select one delta".into(),
            phase_kind: PhaseKind::Analyze,
            phase_label: "analyze".into(),
            primary_targets: vec!["semantic digest".into()],
            entry_conditions: vec!["pending delta".into()],
            acceptance_boundary: "bounded durable job".into(),
            expected_state_transition: "semantic watermark advances".into(),
        },
        active_episode_id: None,
        execution_lane_ids: Vec::new(),
        source_watermark: 0,
    };
    let mut episode = new_episode(&workstream, None, watermark).unwrap();
    episode.pending_delta_stats.selected_token_count = 1024;
    episode.validate().unwrap();
    let episode_id = episode.episode_id.to_string();
    let revision_id = episode.revision_id.to_string();
    let payload = JournalPayload::WorkEpisodeRecorded(Box::new(episode));
    ObjectRow {
        row_id: format!("object:work:work_episode:{revision_id}"),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Object),
        object_family: None,
        object_kind: Some("work_episode".into()),
        object_id: Some(episode_id),
        current_revision_id: Some(revision_id),
        lifecycle: None,
        epistemic: None,
        authority: None,
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: None,
        worktree_id: None,
        task_id: Some(task_id.to_string()),
        workstream_id: Some(workstream.workstream_id.to_string()),
        session_id: None,
        payload_json: Some(payload.canonical_json().unwrap()),
        source_event_seq: watermark,
        projection_generation: 1,
    }
}

fn bound_operation_rows(episode_row: &ObjectRow, surface_row: &ObjectRow) -> [ObjectRow; 2] {
    let episode_payload: JournalPayload =
        serde_json::from_str(episode_row.payload_json.as_deref().unwrap()).unwrap();
    let JournalPayload::WorkEpisodeRecorded(episode) = episode_payload else {
        panic!("expected work episode")
    };
    let surface_payload: JournalPayload =
        serde_json::from_str(surface_row.payload_json.as_deref().unwrap()).unwrap();
    let JournalPayload::EvidenceSurfaceRecorded(surface) = surface_payload else {
        panic!("expected evidence surface")
    };
    let operation_id = OperationId::new_v7();
    let operation = Operation {
        operation_id,
        host_occurrence_id: HostOccurrenceId::from_digest([0x39; 32]),
        execution_lane_id: None,
        operation_kind: OperationKind::Observe,
        input_source_observation_refs: vec![surface.source_observation_revision_ref],
        result_source_observation_refs: Vec::new(),
        pairing_state: PairingState::UnmatchedIntent,
        scope_effect_ids: Vec::new(),
        artifact_refs: Vec::new(),
        operation_resolver_version: 1,
        operation_revision: 1,
        previous_operation_revision: None,
    };
    operation.validate().unwrap();
    let binding = WorkBindingRevision {
        work_binding_revision_id: WorkBindingRevisionId::new_v7(),
        operation_id,
        revision_generation: 1,
        predecessor_revision_id: None,
        primary_binding: PrimaryWorkBinding {
            task_id: Some(episode.task_id),
            workstream_id: Some(episode.workstream_id),
            episode_id: Some(episode.episode_id),
            ..PrimaryWorkBinding::default()
        },
        secondary_bindings: Vec::new(),
        scope_effect_refs: Vec::new(),
        assignment_status: AssignmentStatus::Resolved,
        evidence_refs: vec![surface.source_observation_revision_ref.to_string()],
        resolver_version: 1,
    };
    binding.validate().unwrap();
    let operation_payload = JournalPayload::OperationDerived(Box::new(operation));
    let binding_payload = JournalPayload::WorkBindingRecorded(Box::new(binding.clone()));
    [
        ObjectRow {
            row_id: format!("object:evidence:operation:{operation_id}"),
            row_kind: ObjectRowKind::Data,
            row_class: Some(ObjectRowClass::Object),
            object_family: None,
            object_kind: Some("operation".into()),
            object_id: Some(operation_id.to_string()),
            current_revision_id: Some(format!("{operation_id}:1")),
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
            payload_json: Some(operation_payload.canonical_json().unwrap()),
            source_event_seq: surface_row.source_event_seq,
            projection_generation: 1,
        },
        ObjectRow {
            row_id: format!(
                "object:work:work_binding:{}",
                binding.work_binding_revision_id
            ),
            row_kind: ObjectRowKind::Data,
            row_class: Some(ObjectRowClass::Object),
            object_family: None,
            object_kind: Some("work_binding".into()),
            object_id: Some(binding.work_binding_revision_id.to_string()),
            current_revision_id: None,
            lifecycle: None,
            epistemic: None,
            authority: None,
            publication_state: None,
            support_state: None,
            project_id: None,
            repository_id: None,
            worktree_id: None,
            task_id: Some(episode.task_id.to_string()),
            workstream_id: Some(episode.workstream_id.to_string()),
            session_id: None,
            payload_json: Some(binding_payload.canonical_json().unwrap()),
            source_event_seq: surface_row.source_event_seq,
            projection_generation: 1,
        },
    ]
}

fn evidence_surface_row(episode_row: &ObjectRow, protected_text: &str, seq: u64) -> ObjectRow {
    let payload: JournalPayload =
        serde_json::from_str(episode_row.payload_json.as_deref().unwrap()).unwrap();
    let JournalPayload::WorkEpisodeRecorded(episode) = payload else {
        panic!("expected work episode")
    };
    let observation_id = SourceObservationId::from_digest([0x29; 32]);
    let surface = evertrace_domain::evidence::EvidenceSurface {
        source_observation_revision_ref: observation_id,
        source_role: SourceRole::Host,
        content_trust: ContentTrust::Observed,
        instruction_authority: InstructionAuthority::None,
        task_id: Some(episode.task_id),
        repository_instance_id: None,
        worktree_instance_id: None,
        event_time_us: 1,
        recorded_at_us: 1,
        source_sequence: seq,
        capture_completeness: CaptureCompleteness::Complete,
        canonicalization_version: 1,
        span_hash: hex(&evidence_span_hash(observation_id, 1, protected_text).unwrap()),
        projection_generation: 1,
        protected_text: protected_text.into(),
    };
    surface.validate().unwrap();
    ObjectRow {
        row_id: format!("projection:evidence_surface:{observation_id}"),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Projection),
        object_family: None,
        object_kind: Some("evidence_surface".into()),
        object_id: None,
        current_revision_id: Some(observation_id.to_string()),
        lifecycle: None,
        epistemic: Some("evidence".into()),
        authority: Some("none".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: None,
        worktree_id: None,
        task_id: Some(episode.task_id.to_string()),
        workstream_id: None,
        session_id: None,
        payload_json: Some(
            JournalPayload::EvidenceSurfaceRecorded(Box::new(surface))
                .canonical_json()
                .unwrap(),
        ),
        source_event_seq: seq,
        projection_generation: 1,
    }
}

fn provider_response() -> Vec<u8> {
    let application = ProviderSemanticApplication {
        progress_delta: Vec::new(),
        decision_delta: Vec::new(),
        failed_routes: Vec::new(),
        resolved_items: Vec::new(),
        open_loops: Vec::new(),
        outcome_delta: Vec::new(),
        omissions: Vec::new(),
        candidates: Vec::new(),
        completeness: SemanticCompleteness::Complete,
    };
    serde_json::to_vec(&serde_json::json!({
        "choices": [{"message": {"content": serde_json::to_string(&application).unwrap()}}],
        "usage": {"prompt_tokens": 17, "completion_tokens": 5}
    }))
    .unwrap()
}

fn provider_config(base_url: &str) -> LlmConfig {
    LlmConfig {
        base_url: ValidatedBaseUrl::parse(base_url).unwrap(),
        api_key_env: "PATH".into(),
        ..LlmConfig::default()
    }
}

fn view(jobs: Vec<DurableJob>, dirty: Vec<DirtyTarget>) -> RuntimeSchedulerView {
    let rows = jobs
        .into_iter()
        .map(JournalPayload::JobState)
        .chain(dirty.into_iter().map(JournalPayload::DirtyTarget))
        .enumerate()
        .map(|(index, payload)| runtime_row(payload, index as u64 + 1))
        .collect();
    RuntimeSchedulerView::from_snapshot(&ProjectionSnapshot {
        frontier: 100,
        rows,
    })
    .unwrap()
}

#[test]
fn durable_job_audit_is_closed_and_terminal_state_is_exact() {
    let queued = job("support_closure", "support:1", 1, 0);
    JournalPayload::JobState(queued.clone()).validate().unwrap();

    let mut succeeded = queued.clone();
    succeeded.state = JobStatus::Succeeded;
    assert!(
        JournalPayload::JobState(succeeded.clone())
            .validate()
            .is_err()
    );
    succeeded.terminal = Some(Box::new(JobTerminalAudit {
        outcome: JobTerminalOutcome::Succeeded,
        reason: JobTerminalReason::Completed,
        result_ref: Some("support-validation:1".into()),
    }));
    JournalPayload::JobState(succeeded.clone())
        .validate()
        .unwrap();

    succeeded.terminal.as_mut().unwrap().outcome = JobTerminalOutcome::Failed;
    assert!(JournalPayload::JobState(succeeded).validate().is_err());
    let mut invalid_budget = queued;
    invalid_budget.budget.max_items = 0;
    assert!(JournalPayload::JobState(invalid_budget).validate().is_err());

    let mut forged_lease = job("support_closure", "support:lease", 1, 0);
    forged_lease.state = JobStatus::Leased;
    assert!(
        JournalPayload::JobState(forged_lease.clone())
            .validate()
            .is_err()
    );
    forged_lease.lease_until_us = Some(10);
    JournalPayload::JobState(forged_lease).validate().unwrap();
}

#[test]
fn scheduler_priority_bounds_coalescing_and_pressure_are_deterministic() {
    let mut jobs = Vec::new();
    for index in 0..10 {
        jobs.push(job("support_closure", &format!("support:{index}"), 1, 0));
        jobs.push(job("session_import_v1", &format!("import:{index}"), 1, 0));
        jobs.push(job(
            "semantic_synthesis_v1",
            &format!("semantic:{index}"),
            1,
            0,
        ));
    }
    let selected = select_jobs(&view(jobs, Vec::new()), CaptureAdmissionState::Normal).unwrap();
    assert_eq!(selected.len(), 24);
    assert_eq!(
        selected
            .iter()
            .filter(|item| item.lane == BackgroundLane::Critical)
            .count(),
        8
    );
    assert_eq!(
        selected
            .iter()
            .filter(|item| item.lane == BackgroundLane::Import)
            .count(),
        8
    );
    assert_eq!(
        selected
            .iter()
            .filter(|item| item.lane == BackgroundLane::Synthesis)
            .count(),
        8
    );
    assert!(selected.windows(2).all(|pair| pair[0].lane <= pair[1].lane));

    let pressure = select_jobs(
        &view(
            vec![
                job("support_closure", "support", 1, 0),
                job("capture_reconciliation", "capture-critical", 1, 0),
                job("physical_normalization", "capture-optional", 1, 0),
                job("objects_projection", "objects", 1, 0),
                job("session_import_v1", "import", 1, 0),
                job("semantic_synthesis_v1", "semantic", 1, 0),
            ],
            Vec::new(),
        ),
        CaptureAdmissionState::Pressure,
    )
    .unwrap();
    assert_eq!(pressure.len(), 3);
    assert!(
        pressure
            .iter()
            .all(|item| item.lane == BackgroundLane::Critical
                || item.job.kind == "objects_projection")
    );
    assert!(
        pressure
            .iter()
            .all(|item| item.job.kind != "physical_normalization")
    );

    let older = job("session_import_v1", "same", 1, 0);
    let newer = job("session_import_v1", "same", 2, 0);
    let coalesced = select_jobs(
        &view(vec![older, newer.clone()], Vec::new()),
        CaptureAdmissionState::Normal,
    )
    .unwrap();
    assert_eq!(coalesced.len(), 1);
    assert_eq!(coalesced[0].job.job_id, newer.job_id);
}

#[test]
fn stale_results_keep_dirty_and_forbidden_synthesis_triggers_do_not_exist() {
    let dirty = DirtyTarget {
        target_kind: DirtyTargetKind::RuntimeJob,
        target_id: "support-contract".into(),
        algorithm_revision: "support-closure-v1".into(),
        source_watermark: 9,
    };
    let job = job("support_closure", "support", 8, 0);
    let current = view(vec![job.clone()], vec![dirty.clone()]);
    assert!(matches!(
        classify_job_result(&job, 9),
        JobResultDisposition::StaleAudit(_)
    ));
    assert_eq!(current.dirty, vec![dirty]);

    for forbidden in ["stop", "session_end", "compact", "idle"] {
        assert!(
            serde_json::from_str::<SemanticDigestTrigger>(&format!("\"{forbidden}\"")).is_err()
        );
    }
}

#[test]
fn unsupported_work_is_not_selected_or_silently_consumed() {
    let unsupported = [
        "manual_maintenance",
        "gc_sweep",
        "index_rebuild",
        "cue_rebuild",
        "runtime_outbox",
        "projection_rebuild",
        "unknown_kind",
    ]
    .into_iter()
    .map(|kind| job(kind, &format!("unsupported:{kind}"), 1, 0))
    .collect();
    let selected = select_jobs(
        &view(unsupported, Vec::new()),
        CaptureAdmissionState::Normal,
    )
    .unwrap();
    assert!(selected.is_empty());
}

#[tokio::test]
async fn real_scheduler_completes_objects_projection_once_across_restart() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let runtime = runtime(temp.path());
    CaptureRuntime::open(runtime.clone()).unwrap();
    let store = temp.path().join("store");
    let writer = open_writer(&store).await.unwrap();
    let (handle, task) = spawn_writer(writer, 16).unwrap();
    let before = handle.project().await.unwrap();
    let target_watermark = before.frontier + 1;
    let dirty = DirtyTarget {
        target_kind: DirtyTargetKind::ObjectsProjection,
        target_id: "evertrace_objects".into(),
        algorithm_revision: "objects-projection-v1".into(),
        source_watermark: target_watermark,
    };
    let mut old_config_job = job(
        "objects_projection",
        &dirty.stable_key(),
        target_watermark.max(1),
        0,
    );
    old_config_job.target_revision = dirty.target_id.clone();
    old_config_job.target_watermark = target_watermark;
    old_config_job.algorithm_revision = dirty.algorithm_revision.clone();
    let old_config_job_id = old_config_job.job_id;
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![
                    JournalEventDraft::runtime(
                        10,
                        CONFIG,
                        "objects-projection-v1",
                        JournalPayload::DirtyTarget(dirty),
                    ),
                    JournalEventDraft::runtime(
                        10,
                        old_config_job.config_hash,
                        old_config_job.algorithm_revision.clone(),
                        JournalPayload::JobState(old_config_job),
                    ),
                ],
            )
            .unwrap(),
            10,
        )
        .await
        .unwrap();
    let report = Arc::new(RwLock::new(None));
    let scheduler = make_scheduler(handle.clone(), runtime.clone(), report);
    assert_eq!(scheduler.run_once().await.unwrap().completed, 1);
    let projected = handle.project().await.unwrap();
    let jobs = RuntimeSchedulerView::from_snapshot(&projected)
        .unwrap()
        .jobs;
    let [completed] = jobs.as_slice() else {
        panic!("expected one durable objects projection job")
    };
    assert_eq!(completed.kind, "objects_projection");
    assert_eq!(completed.job_id, old_config_job_id);
    assert_eq!(completed.config_hash, [7; 32]);
    assert_eq!(completed.state, JobStatus::Succeeded);
    assert_eq!(completed.attempt, 2);
    assert_eq!(
        completed.terminal.as_deref().map(|audit| audit.reason),
        Some(JobTerminalReason::Completed)
    );
    let job_id = completed.job_id;
    assert_eq!(scheduler.run_once().await.unwrap().completed, 0);
    drop(scheduler);
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();

    let reopened = JournalWriter::open(&store).await.unwrap();
    let lifecycle = reopened
        .journal_rows()
        .await
        .unwrap()
        .into_iter()
        .filter_map(|row| match row.payload().unwrap() {
            JournalPayload::JobState(job) if job.job_id == job_id => {
                Some(format!("{:?}:{}", job.state, job.attempt))
            }
            JournalPayload::JobLease(lease) if lease.job_id == job_id => {
                Some(format!("Leased:{}", lease.attempt))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(lifecycle, ["Queued:1", "Leased:2", "Succeeded:2"]);
    drop(reopened);

    let writer = open_writer(&store).await.unwrap();
    let (handle, task) = spawn_writer(writer, 16).unwrap();
    let scheduler = make_scheduler(handle.clone(), runtime, Arc::new(RwLock::new(None)));
    assert_eq!(scheduler.run_once().await.unwrap().completed, 0);
    let restarted = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    assert_eq!(restarted.jobs.len(), 1);
    assert_eq!(restarted.jobs[0].job_id, job_id);
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn scheduler_wakes_for_future_lease_then_returns_to_configured_integrity_interval() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let runtime = runtime(temp.path());
    CaptureRuntime::open(runtime.clone()).unwrap();
    let writer = open_writer(&temp.path().join("store")).await.unwrap();
    let (handle, writer_task) = spawn_writer(writer, 16).unwrap();
    let queued = job("manual_maintenance", "future-lease", 1, 0);
    let job_id = queued.job_id;
    let occurred_at_us = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    let lease_until_us = occurred_at_us + 300_000;
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![
                    JournalEventDraft::runtime(
                        occurred_at_us,
                        queued.config_hash,
                        queued.algorithm_revision.clone(),
                        JournalPayload::JobState(queued.clone()),
                    ),
                    JournalEventDraft::runtime(
                        occurred_at_us,
                        queued.config_hash,
                        queued.algorithm_revision.clone(),
                        JournalPayload::JobLease(JobLease {
                            job_id,
                            target_generation: queued.target_generation,
                            attempt: 2,
                            lease_until_us,
                        }),
                    ),
                ],
            )
            .unwrap(),
            occurred_at_us,
        )
        .await
        .unwrap();
    let scheduler = make_scheduler_with_interval(
        handle.clone(),
        runtime,
        Arc::new(RwLock::new(None)),
        std::time::Duration::from_secs(3_600),
    );
    let (wakeup_tx, wakeup_rx) = tokio::sync::watch::channel(0_u64);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let scheduler_task = tokio::spawn(scheduler.run(wakeup_rx, shutdown_rx));

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let before_expiry = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap())
        .unwrap()
        .jobs
        .into_iter()
        .find(|job| job.job_id == job_id)
        .unwrap();
    assert_eq!(
        (before_expiry.state, before_expiry.attempt),
        (JobStatus::Leased, 2)
    );

    let reclaimed_frontier = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let snapshot = handle.project().await.unwrap();
            let current = RuntimeSchedulerView::from_snapshot(&snapshot)
                .unwrap()
                .jobs
                .into_iter()
                .find(|job| job.job_id == job_id)
                .unwrap();
            if (current.state, current.attempt) == (JobStatus::Queued, 3) {
                break snapshot.frontier;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(handle.project().await.unwrap().frontier, reclaimed_frontier);

    shutdown_tx.send(true).unwrap();
    scheduler_task.await.unwrap().unwrap();
    drop(wakeup_tx);
    handle.shutdown().await.unwrap();
    writer_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn config_replacement_claims_old_jobs_and_keeps_one_active_import() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let runtime = runtime(temp.path());
    CaptureRuntime::open(runtime.clone()).unwrap();
    let store = temp.path().join("store");
    let writer = open_writer(&store).await.unwrap();
    let (handle, task) = spawn_writer(writer, 16).unwrap();
    let import = job("session_import_v1", "session_import:old", 1, 0);
    let synthesis = job("semantic_synthesis_v1", "semantic_synthesis:old", 1, 0);
    let import_id = import.job_id;
    let synthesis_id = synthesis.job_id;
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                [import, synthesis]
                    .into_iter()
                    .map(|job| {
                        JournalEventDraft::runtime(
                            10,
                            job.config_hash,
                            job.algorithm_revision.clone(),
                            JournalPayload::JobState(job),
                        )
                    })
                    .collect(),
            )
            .unwrap(),
            10,
        )
        .await
        .unwrap();
    let scheduler = make_scheduler(handle.clone(), runtime, Arc::new(RwLock::new(None)));
    scheduler.run_once().await.unwrap();
    let jobs = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap())
        .unwrap()
        .jobs;
    for old_id in [import_id, synthesis_id] {
        let old = jobs.iter().find(|job| job.job_id == old_id).unwrap();
        assert_eq!(old.state, JobStatus::Failed);
        assert_eq!(old.attempt, 1);
        assert_eq!(
            old.terminal.as_deref().map(|audit| audit.reason),
            Some(JobTerminalReason::Unsupported)
        );
    }
    let active = jobs
        .iter()
        .filter(|job| matches!(job.state, JobStatus::Queued | JobStatus::Leased))
        .collect::<Vec<_>>();
    let [replacement] = active.as_slice() else {
        panic!("expected one active replacement")
    };
    assert_eq!(replacement.kind, "session_import_v1");
    assert_eq!(replacement.config_hash, CONFIG);
    let replacement_id = replacement.job_id;
    drop(scheduler);
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();

    let reopened = JournalWriter::open(&store).await.unwrap();
    let command_ids = reopened
        .journal_rows()
        .await
        .unwrap()
        .into_iter()
        .filter_map(|row| {
            let relevant = match row.payload().unwrap() {
                JournalPayload::JobLease(lease) => {
                    lease.job_id == import_id || lease.job_id == synthesis_id
                }
                JournalPayload::JobState(job) => {
                    (job.job_id == import_id || job.job_id == synthesis_id)
                        && job.state == JobStatus::Failed
                        || job.job_id == replacement_id
                }
                _ => false,
            };
            relevant.then_some(row.command_id)
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(command_ids.len(), 1);
    assert!(reopened.journal_rows().await.unwrap().into_iter().all(
        |row| !matches!(row.payload().unwrap(), JournalPayload::JobLease(lease)
                if lease.job_id == import_id || lease.job_id == synthesis_id)
    ));
}

#[tokio::test]
async fn capture_frontier_is_targeted_and_terminal_preserves_unresolved_dirty() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let runtime = runtime(temp.path());
    let report = synthetic_report();
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    capture.capture(capture_input(&report)).unwrap();
    capture.seal_active().unwrap();
    let store = temp.path().join("store");
    let writer = open_writer(&store).await.unwrap();
    let (handle, task) = spawn_writer(writer, 16).unwrap();
    let ingestor = EvidenceIngestor::new(
        runtime.clone(),
        handle.clone(),
        CONFIG,
        "s29-capture-ingest-v1",
    )
    .unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 1);
    let initial = handle.project().await.unwrap();
    let frontier = initial.reconciliation_frontier(8).unwrap();
    assert!(!frontier.items.is_empty());
    let observation = frontier.items[0].target_id.clone();
    assert!(
        frontier
            .items
            .iter()
            .all(|item| item.target_id == observation)
    );
    let report = Arc::new(RwLock::new(Some(report)));
    let scheduler = make_scheduler(handle.clone(), runtime.clone(), Arc::clone(&report));
    scheduler.run_once().await.unwrap();
    let projected = handle.project().await.unwrap();
    let view = RuntimeSchedulerView::from_snapshot(&projected).unwrap();
    let capture_jobs = view
        .jobs
        .iter()
        .filter(|job| job.target_revision == observation)
        .collect::<Vec<_>>();
    let [capture_job] = capture_jobs.as_slice() else {
        panic!("expected one coalesced targeted capture job")
    };
    assert_eq!(capture_job.attempt, 2);
    let remaining = projected
        .reconciliation_frontier_for_observations(&[observation.parse().unwrap()])
        .unwrap()
        .items;
    assert_eq!(capture_job.state, JobStatus::Failed);
    assert!(!remaining.is_empty());
    assert_eq!(
        capture_job.terminal.as_deref().map(|audit| audit.reason),
        Some(JobTerminalReason::SourceUnavailable)
    );
    assert_eq!(scheduler.run_once().await.unwrap().completed, 0);
    let unchanged = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let unchanged = unchanged
        .jobs
        .iter()
        .filter(|job| job.target_revision == observation)
        .collect::<Vec<_>>();
    assert_eq!(unchanged.len(), 1);
    assert_eq!(unchanged[0].attempt, 2);

    let mut second_input = {
        let guard = report.read().await;
        capture_input(guard.as_ref().unwrap())
    };
    second_input.spool_record_id = Some("s29-capture-record-2".into());
    second_input.source_record_identity = Some("record-2".into());
    second_input.source_sequence = 2;
    second_input.raw_payload = b"s29 second capture lifecycle".to_vec();
    capture.capture(second_input).unwrap();
    capture.seal_active().unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 1);
    let second_frontier = handle
        .project()
        .await
        .unwrap()
        .reconciliation_frontier(8)
        .unwrap();
    let second_item = second_frontier
        .items
        .iter()
        .filter(|item| item.target_id != observation)
        .max_by_key(|item| item.target_kind == DirtyTargetKind::CaptureReconciliation)
        .unwrap()
        .clone();
    let kind = match second_item.target_kind {
        DirtyTargetKind::CaptureReconciliation => "capture_reconciliation",
        DirtyTargetKind::PhysicalNormalization => "physical_normalization",
        _ => panic!("unexpected capture frontier kind"),
    };
    let pending = DurableJob {
        job_id: JobId::new_v7(),
        idempotency_key: format!("{kind}:{}", second_item.target_id),
        target_revision: second_item.target_id.clone(),
        target_watermark: second_item.source_event_seq,
        target_generation: second_item.source_event_seq.max(1),
        kind: kind.into(),
        algorithm_revision: "capture-reconciliation-v1".into(),
        model_id: None,
        priority: 0,
        state: JobStatus::Queued,
        attempt: 1,
        backoff_until_us: None,
        config_hash: CONFIG,
        budget: JobBudget {
            max_items: 1,
            max_bytes: None,
            max_input_tokens: None,
            max_output_tokens: None,
            max_calls: None,
            max_wall_time_ms: 250,
        },
        terminal: None,
        lease_until_us: None,
    };
    let pending_id = pending.job_id;
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    30,
                    CONFIG,
                    "capture-reconciliation-v1",
                    JournalPayload::JobState(pending),
                )],
            )
            .unwrap(),
            30,
        )
        .await
        .unwrap();
    let saved_report = report.write().await.take().unwrap();
    scheduler.run_once().await.unwrap();
    let missing = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let missing = missing
        .jobs
        .iter()
        .find(|job| job.job_id == pending_id)
        .unwrap();
    assert_eq!((missing.state, missing.attempt), (JobStatus::Queued, 1));
    *report.write().await = Some(saved_report);
    scheduler.run_once().await.unwrap();
    let resolved = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let matching = resolved
        .jobs
        .iter()
        .filter(|job| job.target_revision == second_item.target_id)
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].attempt, 2);
    assert_eq!(matching[0].state, JobStatus::Failed);

    let mut third_input = {
        let guard = report.read().await;
        capture_input(guard.as_ref().unwrap())
    };
    third_input.spool_record_id = Some("s29-capture-record-3".into());
    third_input.source_instance_id = "s29-physical-source".into();
    third_input.source_revision = "physical-revision-v1".into();
    third_input.source_record_identity = Some("physical-record-1".into());
    third_input.source_ref = "source:s29-physical".into();
    third_input.source_sequence = 1;
    third_input.lifecycle = None;
    third_input.raw_payload = b"s29 physical normalization".to_vec();
    capture.capture(third_input).unwrap();
    capture.seal_active().unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 1);
    let physical_item = handle
        .project()
        .await
        .unwrap()
        .reconciliation_frontier(8)
        .unwrap()
        .items
        .into_iter()
        .find(|item| {
            item.target_kind == DirtyTargetKind::PhysicalNormalization
                && item.target_id != observation
                && item.target_id != second_item.target_id
        })
        .unwrap();
    let physical_id: SourceObservationId = physical_item.target_id.parse().unwrap();
    let queued_after_dirty = DurableJob {
        job_id: JobId::new_v7(),
        idempotency_key: format!("physical_normalization:{}", physical_item.target_id),
        target_revision: physical_item.target_id.clone(),
        target_watermark: physical_item.source_event_seq,
        target_generation: physical_item.source_event_seq.max(1),
        kind: "physical_normalization".into(),
        algorithm_revision: "capture-reconciliation-v1".into(),
        model_id: None,
        priority: 0,
        state: JobStatus::Queued,
        attempt: 1,
        backoff_until_us: None,
        config_hash: CONFIG,
        budget: JobBudget {
            max_items: 1,
            max_bytes: None,
            max_input_tokens: None,
            max_output_tokens: None,
            max_calls: None,
            max_wall_time_ms: 250,
        },
        terminal: None,
        lease_until_us: None,
    };
    let queued_after_dirty_id = queued_after_dirty.job_id;
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    40,
                    CONFIG,
                    "capture-reconciliation-v1",
                    JournalPayload::JobState(queued_after_dirty),
                )],
            )
            .unwrap(),
            40,
        )
        .await
        .unwrap();
    let manifest = report.read().await.as_ref().unwrap().manifest().clone();
    reconcile_observations_once(
        ReconcileInput {
            runtime_snapshot: runtime,
            adapter_manifests: vec![manifest],
            liveness: Vec::new(),
            reconciled_gaps: Vec::new(),
            reconciled_outages: Vec::new(),
            independent_source_reconciliations: Vec::new(),
            effective_config_hash: CONFIG,
            algorithm_revision: "capture-reconciliation-v1".into(),
            occurred_at_us: 41,
            max_items: 1,
        },
        &handle,
        &[physical_id],
    )
    .await
    .unwrap();
    assert!(
        handle
            .project()
            .await
            .unwrap()
            .reconciliation_frontier_for_observations(&[physical_id])
            .unwrap()
            .items
            .is_empty()
    );
    report.write().await.take();
    scheduler.run_once().await.unwrap();
    let cleared = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let cleared = cleared
        .jobs
        .iter()
        .find(|job| job.job_id == queued_after_dirty_id)
        .unwrap();
    assert_eq!((cleared.state, cleared.attempt), (JobStatus::Succeeded, 2));
    assert_eq!(scheduler.run_once().await.unwrap().completed, 0);
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let reopened = JournalWriter::open(&store).await.unwrap();
    let lifecycle = reopened
        .journal_rows()
        .await
        .unwrap()
        .into_iter()
        .filter_map(|row| match row.payload().unwrap() {
            JournalPayload::JobState(job) if job.job_id == queued_after_dirty_id => {
                Some(format!("{:?}:{}", job.state, job.attempt))
            }
            JournalPayload::JobLease(lease) if lease.job_id == queued_after_dirty_id => {
                Some(format!("Leased:{}", lease.attempt))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(lifecycle, ["Queued:1", "Leased:2", "Succeeded:2"]);
}

#[tokio::test]
async fn capture_round_robin_retries_and_reaches_the_next_page() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let runtime = runtime(temp.path());
    let report = synthetic_report();
    let mut capture = CaptureRuntime::open(runtime.clone()).unwrap();
    for index in 0..41_u64 {
        let mut input = capture_input(&report);
        input.spool_record_id = Some(format!("s29-fair-capture-{index}"));
        input.source_instance_id = format!("s29-fair-source-{index}");
        input.source_revision = format!("s29-fair-revision-{index}");
        input.source_record_identity = Some(format!("s29-fair-record-{index}"));
        input.source_ref = format!("source:s29-fair-{index}");
        input.source_sequence = 1;
        input.lifecycle = None;
        input.raw_payload = format!("s29 fair physical {index}").into_bytes();
        capture.capture(input).unwrap();
    }
    capture.seal_active().unwrap();
    let writer = open_writer(&temp.path().join("store")).await.unwrap();
    let (handle, task) = spawn_writer(writer, 64).unwrap();
    let ingestor = EvidenceIngestor::new(
        runtime.clone(),
        handle.clone(),
        CONFIG,
        "s29-fair-capture-ingest-v1",
    )
    .unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 41);
    let frontier = handle
        .project()
        .await
        .unwrap()
        .reconciliation_frontier(128)
        .unwrap();
    let physical = frontier
        .items
        .into_iter()
        .filter(|item| item.target_kind == DirtyTargetKind::PhysicalNormalization)
        .collect::<Vec<_>>();
    assert_eq!(physical.len(), 41);
    let target = physical[40].target_id.clone();
    let mut filler = capture_input(&report);
    filler.spool_record_id = Some("s29-fair-pressure-filler".into());
    filler.source_instance_id = "s29-fair-pressure-source".into();
    filler.source_revision = "s29-fair-pressure-revision".into();
    filler.source_record_identity = Some("s29-fair-pressure-record".into());
    filler.source_ref = "source:s29-fair-pressure".into();
    filler.lifecycle = None;
    filler.raw_payload = vec![b'x'; 128];
    capture.capture(filler).unwrap();
    capture.seal_active().unwrap();
    let mut scheduler_runtime = runtime;
    scheduler_runtime.main_high_watermark_bytes = 64;
    scheduler_runtime.main_low_watermark_bytes = 32;
    let current_report = Arc::new(RwLock::new(None));
    let scheduler = make_scheduler(
        handle.clone(),
        scheduler_runtime,
        Arc::clone(&current_report),
    );
    assert!(scheduler.run_once().await.unwrap().retryable);
    let first_page = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    assert!(
        first_page
            .jobs
            .iter()
            .all(|job| job.target_revision != target)
    );
    *current_report.write().await = Some(report);
    scheduler.run_once().await.unwrap();
    let after = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let target_jobs = after
        .jobs
        .iter()
        .filter(|job| job.target_revision == target)
        .collect::<Vec<_>>();
    let [target_job] = target_jobs.as_slice() else {
        panic!("expected the next capture page to be materialized")
    };
    assert_eq!(
        (target_job.state, target_job.attempt),
        (JobStatus::Queued, 1)
    );
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[test]
fn synthesis_filters_covered_tuples_before_the_queue_limit() {
    let rows = (1..=9).map(synthesis_episode_row).collect::<Vec<_>>();
    let snapshot = ProjectionSnapshot {
        frontier: 100,
        rows,
    };
    let planner = SynthesisPlanner::new(LlmConfig::default());
    let first = planner
        .durable_jobs(
            &snapshot,
            CONFIG,
            &Default::default(),
            8,
            std::time::Duration::from_secs(600),
        )
        .unwrap();
    assert_eq!(first.len(), 8);
    let covered = first
        .iter()
        .map(|job| {
            (
                job.idempotency_key.clone(),
                job.target_generation,
                job.config_hash,
            )
        })
        .collect();
    let ninth = planner
        .durable_jobs(
            &snapshot,
            CONFIG,
            &covered,
            8,
            std::time::Duration::from_secs(600),
        )
        .unwrap();
    assert_eq!(ninth.len(), 1);
    assert!(
        !first
            .iter()
            .any(|covered| covered.target_revision == ninth[0].target_revision)
    );

    let old_config_covered = first
        .iter()
        .map(|job| (job.idempotency_key.clone(), job.target_generation, [7; 32]))
        .collect();
    assert_eq!(
        planner
            .durable_jobs(
                &snapshot,
                CONFIG,
                &old_config_covered,
                8,
                std::time::Duration::from_secs(600),
            )
            .unwrap()
            .len(),
        8
    );
}

#[tokio::test]
async fn synthesis_uses_only_validated_evidence_surface_text_for_provider_input() {
    let episode = synthesis_episode_row(9);
    let surface = evidence_surface_row(&episode, "protected-s29-canary", 9);
    let bound = bound_operation_rows(&episode, &surface);
    let mut raw = surface.clone();
    raw.row_id = "object:work:operation:raw-canary".into();
    raw.row_class = Some(ObjectRowClass::Object);
    raw.object_kind = Some("work_artifact".into());
    raw.object_id = Some("work-artifact-raw-canary".into());
    raw.current_revision_id = Some("work-artifact-raw-canary-revision".into());
    raw.payload_json = Some(
        serde_json::json!({
            "payload_json_secret_canary": "must-never-reach-provider"
        })
        .to_string(),
    );
    raw.source_event_seq = 8;
    let snapshot = ProjectionSnapshot {
        frontier: 9,
        rows: vec![episode, raw, surface, bound[0].clone(), bound[1].clone()],
    };
    let stub = ProviderStub::once(200, provider_response()).await;
    let planner = SynthesisPlanner::new(provider_config(&stub.base_url));
    let mut durable = planner
        .durable_jobs(
            &snapshot,
            CONFIG,
            &Default::default(),
            1,
            std::time::Duration::from_secs(600),
        )
        .unwrap()
        .remove(0);
    durable.state = JobStatus::Leased;
    durable.attempt = 2;
    durable.lease_until_us = Some(100);
    let command = planner
        .execute_durable_job(
            &snapshot,
            &durable,
            CONFIG,
            2,
            std::time::Duration::from_secs(600),
        )
        .await
        .unwrap();
    assert!(command.events().iter().any(|event| {
        matches!(&event.payload, JournalPayload::JobState(job)
            if job.job_id == durable.job_id
                && matches!(job.state, JobStatus::Succeeded | JobStatus::Failed))
    }));
    let request = String::from_utf8_lossy(&stub.finish().await).into_owned();
    assert!(request.contains("protected-s29-canary"));
    assert!(!request.contains("must-never-reach-provider"));
    assert!(!request.contains("payload_json_secret_canary"));
}

#[tokio::test]
async fn synthesis_without_eligible_surface_fails_without_calling_provider_or_requeueing() {
    let episode = synthesis_episode_row(9);
    let mut raw = episode.clone();
    raw.row_id = "object:work:operation:no-surface".into();
    raw.object_kind = Some("work_artifact".into());
    raw.object_id = Some("work-artifact-no-surface".into());
    raw.current_revision_id = Some("work-artifact-no-surface-revision".into());
    raw.payload_json = Some(serde_json::json!({"raw": "not-selected"}).to_string());
    raw.source_event_seq = 8;
    let snapshot = ProjectionSnapshot {
        frontier: 9,
        rows: vec![episode, raw],
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let planner = SynthesisPlanner::new(provider_config(&base_url));
    let mut durable = planner
        .durable_jobs(
            &snapshot,
            CONFIG,
            &Default::default(),
            1,
            std::time::Duration::from_secs(600),
        )
        .unwrap()
        .remove(0);
    durable.state = JobStatus::Leased;
    durable.attempt = 2;
    durable.lease_until_us = Some(100);
    let command = planner
        .execute_durable_job(
            &snapshot,
            &durable,
            CONFIG,
            2,
            std::time::Duration::from_secs(600),
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    let terminal = command
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::JobState(job) => Some(job.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!((terminal.state, terminal.attempt), (JobStatus::Failed, 2));
    assert_eq!(
        terminal.terminal.as_deref().map(|audit| audit.reason),
        Some(JobTerminalReason::Unsupported)
    );
    let covered = [(
        terminal.idempotency_key.clone(),
        terminal.target_generation,
        terminal.config_hash,
    )]
    .into_iter()
    .collect();
    assert!(
        planner
            .durable_jobs(
                &snapshot,
                CONFIG,
                &covered,
                1,
                std::time::Duration::from_secs(600),
            )
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn synthesis_rejects_same_task_surface_bound_to_a_different_episode() {
    let task_id = TaskId::new_v7();
    let episode = synthesis_episode_row_for_task(9, task_id);
    let other_episode = synthesis_episode_row_for_task(9, task_id);
    let other_surface = evidence_surface_row(&other_episode, "wrong-episode-canary", 9);
    let other_bound = bound_operation_rows(&other_episode, &other_surface);
    let snapshot = ProjectionSnapshot {
        frontier: 9,
        rows: vec![
            episode.clone(),
            other_episode,
            other_surface,
            other_bound[0].clone(),
            other_bound[1].clone(),
        ],
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let planner = SynthesisPlanner::new(provider_config(&base_url));
    let mut durable = planner
        .durable_jobs(
            &snapshot,
            CONFIG,
            &Default::default(),
            8,
            std::time::Duration::from_secs(600),
        )
        .unwrap()
        .into_iter()
        .find(|job| job.target_revision == episode.current_revision_id.as_deref().unwrap())
        .unwrap();
    durable.state = JobStatus::Leased;
    durable.attempt = 2;
    durable.lease_until_us = Some(100);
    let command = planner
        .execute_durable_job(
            &snapshot,
            &durable,
            CONFIG,
            2,
            std::time::Duration::from_secs(600),
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    assert!(command.events().iter().any(|event| {
        matches!(&event.payload, JournalPayload::JobState(job)
            if job.job_id == durable.job_id
                && job.state == JobStatus::Failed
                && job.terminal.as_deref().map(|audit| audit.reason)
                    == Some(JobTerminalReason::Unsupported))
    }));
}

#[tokio::test]
async fn synthesis_job_budget_stays_current_after_prior_wall_usage() {
    let first_episode = synthesis_episode_row(9);
    let second_episode = synthesis_episode_row(9);
    let surface = evidence_surface_row(&second_episode, "static-budget-canary", 9);
    let bound = bound_operation_rows(&second_episode, &surface);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let mut llm = provider_config(&base_url);
    llm.daily_wall_time_budget = DurationValue::from_seconds(1).unwrap();
    let model = llm.model.clone();
    let planner = SynthesisPlanner::new(llm);
    let initial = ProjectionSnapshot {
        frontier: 9,
        rows: vec![
            first_episode.clone(),
            second_episode.clone(),
            surface,
            bound[0].clone(),
            bound[1].clone(),
        ],
    };
    let jobs = planner
        .durable_jobs(
            &initial,
            CONFIG,
            &Default::default(),
            8,
            std::time::Duration::from_secs(600),
        )
        .unwrap();
    assert_eq!(jobs.len(), 2);
    let mut second = jobs
        .into_iter()
        .find(|job| job.target_revision == second_episode.current_revision_id.as_deref().unwrap())
        .unwrap();
    let first_payload: JournalPayload =
        serde_json::from_str(first_episode.payload_json.as_deref().unwrap()).unwrap();
    let JournalPayload::WorkEpisodeRecorded(first) = first_payload else {
        panic!("expected first episode")
    };
    let mut prior = SemanticDerivationRun {
        derivation_run_id: SemanticDerivationRunId::new_v7(),
        episode_id: first.episode_id,
        episode_revision_id: first.revision_id,
        from_watermark: first.semantic_watermark,
        to_watermark: first.source_watermark,
        selected_direct_refs: vec!["source:prior-wall-usage".into()],
        job_fingerprint: [0x29; 32],
        status: DerivationRunStatus::ProviderFailed,
        quota_usage: DerivationQuotaUsage {
            calls: 1,
            wall_time_us: 1_000_000,
            ..DerivationQuotaUsage::default()
        },
        model_id: model,
        prompt_hash: [0x39; 32],
        schema_version: 1,
        algorithm_revision: "semantic_synthesis_v1".into(),
        effective_config_hash: CONFIG,
        created_at_us: 2,
    };
    prior.job_fingerprint = job_fingerprint(
        prior.episode_id,
        prior.episode_revision_id,
        prior.from_watermark,
        prior.to_watermark,
        &prior.selected_direct_refs,
        &prior.model_id,
        &prior.prompt_hash,
        prior.schema_version,
        &prior.algorithm_revision,
        &prior.effective_config_hash,
    )
    .unwrap();
    prior.validate().unwrap();
    let prior_id = prior.derivation_run_id.to_string();
    let mut used = initial;
    used.frontier = 10;
    used.rows.push(ObjectRow {
        row_id: format!("object:semantic:semantic_derivation_run:{prior_id}"),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Object),
        object_family: None,
        object_kind: Some("semantic_derivation_run".into()),
        object_id: Some(prior_id.clone()),
        current_revision_id: Some(prior_id),
        lifecycle: None,
        epistemic: None,
        authority: None,
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: None,
        worktree_id: None,
        task_id: Some(first.task_id.to_string()),
        workstream_id: Some(first.workstream_id.to_string()),
        session_id: None,
        payload_json: Some(
            JournalPayload::SemanticDerivationRunRecorded(Box::new(prior))
                .canonical_json()
                .unwrap(),
        ),
        source_event_seq: 10,
        projection_generation: 1,
    });
    let recreated = planner
        .durable_jobs(
            &used,
            CONFIG,
            &Default::default(),
            8,
            std::time::Duration::from_secs(600),
        )
        .unwrap()
        .into_iter()
        .find(|job| job.target_revision == second.target_revision)
        .unwrap();
    assert_eq!(second.budget, recreated.budget);
    second.state = JobStatus::Leased;
    second.attempt = 2;
    second.lease_until_us = Some(100);
    let command = planner
        .execute_durable_job(
            &used,
            &second,
            CONFIG,
            2,
            std::time::Duration::from_secs(600),
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    assert!(command.events().iter().any(|event| {
        matches!(&event.payload, JournalPayload::JobState(job)
            if job.job_id == second.job_id
                && job.attempt == 2
                && job.state == JobStatus::Failed
                && job.terminal.as_deref().map(|audit| audit.reason)
                    == Some(JobTerminalReason::BudgetExhausted))
    }));
}

#[tokio::test]
async fn zero_llm_tasks_per_run_never_claims_or_calls_the_provider() {
    let episode = synthesis_episode_row(9);
    let planning_snapshot = ProjectionSnapshot {
        frontier: 9,
        rows: vec![episode],
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let planner = SynthesisPlanner::new(provider_config(&base_url));
    let queued = planner
        .durable_jobs(
            &planning_snapshot,
            CONFIG,
            &Default::default(),
            1,
            std::time::Duration::from_secs(600),
        )
        .unwrap()
        .remove(0);
    let job_id = queued.job_id;

    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let runtime = runtime(temp.path());
    CaptureRuntime::open(runtime.clone()).unwrap();
    let writer = open_writer(&temp.path().join("store")).await.unwrap();
    let (handle, task) = spawn_writer(writer, 16).unwrap();
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    2,
                    CONFIG,
                    "semantic_synthesis_v1",
                    JournalPayload::JobState(queued),
                )],
            )
            .unwrap(),
            2,
        )
        .await
        .unwrap();
    let report = Arc::new(RwLock::new(Some(synthetic_report())));
    let dreaming = DreamingConfig {
        max_llm_tasks_per_run: 0,
        ..DreamingConfig::default()
    };
    let scheduler = BackgroundScheduler::new(
        handle.clone(),
        SessionCatalogService::new(handle.clone(), CONFIG),
        SessionImportWorker::new(handle.clone(), runtime.clone(), Arc::clone(&report)).unwrap(),
        report,
        runtime,
        planner,
        dreaming,
    );
    scheduler.run_once().await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    let current = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap())
        .unwrap()
        .jobs
        .into_iter()
        .find(|job| job.job_id == job_id)
        .unwrap();
    assert_eq!((current.state, current.attempt), (JobStatus::Queued, 1));
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_cancels_an_inflight_run_without_forging_a_terminal() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let runtime = runtime(temp.path());
    CaptureRuntime::open(runtime.clone()).unwrap();
    let writer = open_writer(&temp.path().join("store")).await.unwrap();
    let (handle, writer_task) = spawn_writer(writer, 16).unwrap();
    let queued = job("manual_maintenance", "shutdown-inflight", 1, 0);
    let job_id = queued.job_id;
    let occurred_at_us = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![
                    JournalEventDraft::runtime(
                        occurred_at_us,
                        queued.config_hash,
                        queued.algorithm_revision.clone(),
                        JournalPayload::JobState(queued.clone()),
                    ),
                    JournalEventDraft::runtime(
                        occurred_at_us,
                        queued.config_hash,
                        queued.algorithm_revision.clone(),
                        JournalPayload::JobLease(JobLease {
                            job_id,
                            target_generation: queued.target_generation,
                            attempt: 2,
                            lease_until_us: occurred_at_us + 60_000_000,
                        }),
                    ),
                ],
            )
            .unwrap(),
            occurred_at_us,
        )
        .await
        .unwrap();
    let report = Arc::new(RwLock::new(Some(synthetic_report())));
    let scheduler = make_scheduler(handle.clone(), runtime, Arc::clone(&report));
    let report_guard = report.write().await;
    let (wakeup_tx, wakeup_rx) = tokio::sync::watch::channel(0_u64);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let scheduler_task = tokio::spawn(scheduler.run(wakeup_rx, shutdown_rx));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_millis(500), scheduler_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(report_guard);
    let current = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap())
        .unwrap()
        .jobs
        .into_iter()
        .find(|job| job.job_id == job_id)
        .unwrap();
    assert_eq!((current.state, current.attempt), (JobStatus::Leased, 2));
    assert!(current.terminal.is_none());
    drop(wakeup_tx);
    handle.shutdown().await.unwrap();
    writer_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn forged_terminal_and_nonfresh_lease_are_rejected_by_the_writer() {
    let temp = TempDir::new().unwrap();
    let store = temp.path().join("store");
    let writer = open_writer(&store).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let queued = job("objects_projection", "objects:forged", 1, 0);
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    10,
                    queued.config_hash,
                    queued.algorithm_revision.clone(),
                    JournalPayload::JobState(queued.clone()),
                )],
            )
            .unwrap(),
            10,
        )
        .await
        .unwrap();
    let mut forged_terminal = queued.clone();
    forged_terminal.state = JobStatus::Succeeded;
    forged_terminal.terminal = Some(Box::new(JobTerminalAudit {
        outcome: JobTerminalOutcome::Succeeded,
        reason: JobTerminalReason::Completed,
        result_ref: Some("objects:forged".into()),
    }));
    let frontier = handle.project().await.unwrap().frontier;
    let terminal_error = handle
        .commit_if_frontier(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    20,
                    queued.config_hash,
                    queued.algorithm_revision.clone(),
                    JournalPayload::JobState(forged_terminal),
                )],
            )
            .unwrap(),
            20,
            frontier,
        )
        .await
        .unwrap_err();
    assert_eq!(terminal_error, WriterActorError::InvalidInput);
    let stale_lease_error = handle
        .commit_if_frontier(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    20,
                    queued.config_hash,
                    queued.algorithm_revision.clone(),
                    JournalPayload::JobLease(JobLease {
                        job_id: queued.job_id,
                        target_generation: queued.target_generation,
                        attempt: 2,
                        lease_until_us: 20,
                    }),
                )],
            )
            .unwrap(),
            20,
            frontier,
        )
        .await
        .unwrap_err();
    assert_eq!(stale_lease_error, WriterActorError::InvalidInput);
    for reason in [
        JobTerminalReason::BudgetExhausted,
        JobTerminalReason::IntegrityFailure,
    ] {
        let mut forged_failure = queued.clone();
        forged_failure.state = JobStatus::Failed;
        forged_failure.terminal = Some(Box::new(JobTerminalAudit {
            outcome: JobTerminalOutcome::Failed,
            reason,
            result_ref: Some("objects:forged".into()),
        }));
        let error = handle
            .commit_if_frontier(
                JournalCommand::new(
                    CommandId::new_v7(),
                    vec![JournalEventDraft::runtime(
                        21,
                        queued.config_hash,
                        queued.algorithm_revision.clone(),
                        JournalPayload::JobState(forged_failure),
                    )],
                )
                .unwrap(),
                21,
                frontier,
            )
            .await
            .unwrap_err();
        assert_eq!(error, WriterActorError::InvalidInput);
    }
    let mut cancelled = queued.clone();
    cancelled.state = JobStatus::Failed;
    cancelled.terminal = Some(Box::new(JobTerminalAudit {
        outcome: JobTerminalOutcome::Failed,
        reason: JobTerminalReason::Unsupported,
        result_ref: Some("objects:forged".into()),
    }));
    handle
        .commit_if_frontier(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    22,
                    queued.config_hash,
                    queued.algorithm_revision.clone(),
                    JournalPayload::JobState(cancelled),
                )],
            )
            .unwrap(),
            22,
            frontier,
        )
        .await
        .unwrap();
    let current = RuntimeSchedulerView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let cancelled = current
        .jobs
        .iter()
        .find(|job| job.job_id == queued.job_id)
        .unwrap();
    assert_eq!((cancelled.state, cancelled.attempt), (JobStatus::Failed, 1));
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let reopened = JournalWriter::open(&store).await.unwrap();
    let rebuilt = RuntimeSchedulerView::from_snapshot(&reopened.project().await.unwrap()).unwrap();
    let rebuilt = rebuilt
        .jobs
        .iter()
        .find(|job| job.job_id == queued.job_id)
        .unwrap();
    assert_eq!((rebuilt.state, rebuilt.attempt), (JobStatus::Failed, 1));
    assert!(reopened.journal_rows().await.unwrap().iter().all(
        |row| !matches!(row.payload().unwrap(), JournalPayload::JobLease(lease)
                if lease.job_id == queued.job_id)
    ));
}
