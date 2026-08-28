use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::Path,
};

use evertrace_capture::{
    CaptureGapMarker, CaptureRecordInput, CaptureRuntime, DeviceKeyStore, DurableSpool, GapReason,
    RUNTIME_SNAPSHOT_VERSION, RuntimeSnapshot, SpoolError, SpoolLimits,
};
use evertrace_codex::{
    adapter_manifest::{
        AdapterCapabilityManifest, AdapterKind,
        AdmissionFailureObservability as ManifestObservability, CaptureGuarantee, CueBoundary,
        EventIdentity, ObservableCapability, RecoveryOrdering, SubagentTrace, TrustReadback,
    },
    capability::{McpBindingMechanism, McpSessionBinding},
    hook_input::{CAPTURE_HOOK_INPUT_VERSION, CaptureHookInput, HookEventKind},
    source_catalog::REQUIRED_FOR_FULL,
};
use evertrace_domain::{
    evidence::{
        CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
        CorrelationField, CorrelationFieldClaim, EvidenceSourceKind, HostCorrelationEvidence,
        IdentityStrength, ObservationRole, ReconciliationProvenance, SourceRevisionMode,
        SourceRole,
    },
    ids::{CaptureReceiptId, CommandId, ExecutionLaneId, SourceObservationId},
    work::{
        AdmissionFailureObservability, CaptureResolverInput, CoverageLevel, LaneLifecycleEvidence,
        LaneStatus, LivenessState, OrderingIntegrity, PairingIntegrity, PayloadIntegrity,
        ReasoningVisibility, SequenceGap, SourceCoverage, TerminalKind, WorkError, resolve_capture,
    },
};
use evertrace_engine::{
    EvidenceIngestor,
    capture::{LivenessObservation, ReconcileError, ReconcileInput, reconcile_once},
    open_writer, spawn_writer,
};
use evertrace_store::{
    EventScope, JournalCommand, JournalEventDraft, JournalPayload, JournalWriter, OBJECTS_TABLE,
    SourceKind,
    relations::{CaptureRelationKind, build_capture_relation_rows},
};
use tempfile::TempDir;

const CONFIG_HASH: [u8; 32] = [0x10; 32];
const FINGERPRINT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn refs(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn resolver_input() -> CaptureResolverInput {
    let required: BTreeSet<String> = refs(&[
        "child_session_id",
        "child_tool_call",
        "child_tool_result",
        "child_final_result",
    ])
    .into_iter()
    .collect();
    CaptureResolverInput {
        execution_lane_id: ExecutionLaneId::new_v7(),
        capture_receipt_revision_id: CaptureReceiptId::new_v7(),
        previous_lane: None,
        previous_receipt: None,
        host_session_id: "session-a".into(),
        agent_id: "agent-a".into(),
        host_lane_key: "lane-a".into(),
        incarnation_ref: "incarnation-a".into(),
        parent_lane_id: None,
        parent_host_lane_key: None,
        spawn_event_ref: Some("spawn-a".into()),
        terminal_event_ref: Some("terminal-a".into()),
        terminal_kind: Some(TerminalKind::Normal),
        host_final_return: false,
        parent_session_end_seen: false,
        liveness_state: LivenessState::Absent,
        liveness_probe_refs: refs(&["liveness-a"]),
        all_sources_closed: true,
        source_closed_refs: refs(&["close-a"]),
        source_close_watermark_refs: refs(&["watermark-a"]),
        source_close_reconciliation_refs: refs(&["reconciliation-a"]),
        source_reconciliation_complete: true,
        adapter_manifest_ids: refs(&["manifest-a"]),
        eligible_event_manifest_refs: refs(&["eligible-a"]),
        source_revision_refs: refs(&["source-a"]),
        manifest_coverage: vec![CoverageLevel::Full],
        required_for_full: required.clone(),
        observed_capabilities: required,
        admission_failure_observability: AdmissionFailureObservability::Complete,
        independent_reconciliation: false,
        admission_failure_evidence_refs: Vec::new(),
        identity_strength: IdentityStrength::StableNative,
        child_session_id: Some("child-session-a".into()),
        first_sequence: Some(1),
        last_sequence: Some(2),
        sequence_gaps: Vec::new(),
        capture_gap_marker_refs: Vec::new(),
        unresolved_gap_marker_refs: Vec::new(),
        capture_outage_interval_refs: Vec::new(),
        unresolved_outage_interval_refs: Vec::new(),
        tool_calls_seen: refs(&["call-a"]),
        tool_results_seen: refs(&["call-a"]),
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
        import_watermark: 2,
        delegated_goal_ref: Some("goal-ref-a".into()),
        delegated_target_refs: refs(&["target-ref-a"]),
        delegated_acceptance_refs: refs(&["acceptance-ref-a"]),
        operation_ids: Vec::new(),
        correction_reason: None,
    }
}

#[test]
fn full_requires_manifest_events_close_reconciliation_and_independent_integrity() {
    let (_, receipt) = resolve_capture(resolver_input()).unwrap();
    assert_eq!(receipt.coverage_level, CoverageLevel::Full);
    assert_eq!(receipt.source_coverage, SourceCoverage::Complete);
    assert_eq!(receipt.pairing_integrity, PairingIntegrity::Complete);
    assert_eq!(receipt.payload_integrity, PayloadIntegrity::Complete);
    assert_eq!(receipt.ordering_integrity, OrderingIntegrity::Complete);
    assert!(receipt.exact_byte_replay);

    let mut open = resolver_input();
    open.all_sources_closed = false;
    open.source_reconciliation_complete = false;
    open.terminal_event_kind_for_test_none();
    let (_, receipt) = resolve_capture(open).unwrap();
    assert_eq!(receipt.source_coverage, SourceCoverage::Open);
}

trait ResolverTestExt {
    fn terminal_event_kind_for_test_none(&mut self);
}

impl ResolverTestExt for CaptureResolverInput {
    fn terminal_event_kind_for_test_none(&mut self) {
        self.terminal_event_ref = None;
        self.terminal_kind = None;
        self.host_final_return = false;
        self.liveness_state = LivenessState::Live;
    }
}

#[test]
fn opaque_and_redacted_dimensions_do_not_upgrade_each_other() {
    let mut input = resolver_input();
    input.manifest_coverage = vec![CoverageLevel::Opaque];
    input.redaction_refs = refs(&["redaction-a"]);
    input.reasoning_visibility = vec![ReasoningVisibility::Summary];
    let (_, receipt) = resolve_capture(input).unwrap();
    assert_eq!(receipt.coverage_level, CoverageLevel::Opaque);
    assert_eq!(receipt.source_coverage, SourceCoverage::Complete);
    assert_eq!(receipt.payload_integrity, PayloadIntegrity::Redacted);
    assert!(!receipt.exact_byte_replay);
    assert_eq!(
        receipt.reasoning_visibility,
        vec![ReasoningVisibility::Summary]
    );
}

#[test]
fn weakest_identity_observability_and_each_failure_dimension_are_preserved() {
    let mut input = resolver_input();
    input.identity_strength = IdentityStrength::SynthesizedBestEffort;
    input.admission_failure_observability = AdmissionFailureObservability::BestEffort;
    input.unmatched_tool_call_ids = refs(&["call-a"]);
    input.payload_truncations = refs(&["payload-a"]);
    input.sequence_gaps = vec![SequenceGap {
        first_sequence: 2,
        last_sequence: 2,
    }];
    let (_, receipt) = resolve_capture(input).unwrap();
    assert_eq!(
        receipt.identity_strength,
        IdentityStrength::SynthesizedBestEffort
    );
    assert_eq!(receipt.source_coverage, SourceCoverage::Partial);
    assert_eq!(receipt.pairing_integrity, PairingIntegrity::Unmatched);
    assert_eq!(receipt.payload_integrity, PayloadIntegrity::Truncated);
    assert_eq!(receipt.ordering_integrity, OrderingIntegrity::Gapped);

    let mut corrupt = resolver_input();
    corrupt.corrupt_payload_refs = refs(&["corrupt-a"]);
    assert_eq!(
        resolve_capture(corrupt).unwrap().1.payload_integrity,
        PayloadIntegrity::Corrupt
    );
    let mut unsupported = resolver_input();
    unsupported.unsupported_record_types = refs(&["future-record"]);
    assert_eq!(
        resolve_capture(unsupported).unwrap().1.source_coverage,
        SourceCoverage::Partial
    );
}

#[test]
fn explicit_terminal_kinds_and_host_final_return_are_closed() {
    let mut returned = resolver_input();
    returned.host_final_return = true;
    assert_eq!(
        resolve_capture(returned).unwrap().0.status,
        LaneStatus::Returned
    );

    for (kind, expected) in [
        (TerminalKind::Normal, LaneStatus::Stopped),
        (TerminalKind::Timeout, LaneStatus::Interrupted),
        (TerminalKind::Cancelled, LaneStatus::Interrupted),
        (TerminalKind::Crashed, LaneStatus::Interrupted),
    ] {
        let mut input = resolver_input();
        input.terminal_kind = Some(kind);
        let lane = resolve_capture(input).unwrap().0;
        assert_eq!(lane.status, expected);
        assert_eq!(lane.terminal_kind, Some(kind));
        assert!(lane.finalized);
    }
}

#[test]
fn parent_end_idle_and_source_close_obey_deterministic_liveness() {
    let mut parent = resolver_input();
    parent.terminal_event_kind_for_test_none();
    parent.parent_session_end_seen = true;
    parent.all_sources_closed = false;
    assert_eq!(
        resolve_capture(parent).unwrap().0.status,
        LaneStatus::Unresolved
    );

    let mut idle = resolver_input();
    idle.terminal_event_kind_for_test_none();
    idle.all_sources_closed = false;
    let idle_lane = resolve_capture(idle).unwrap().0;
    assert_eq!(idle_lane.status, LaneStatus::Active);
    assert!(!idle_lane.finalized);

    for state in [LivenessState::Live, LivenessState::Unknown] {
        let mut closed = resolver_input();
        closed.terminal_event_kind_for_test_none();
        closed.all_sources_closed = true;
        closed.liveness_state = state;
        let lane = resolve_capture(closed).unwrap().0;
        assert_eq!(lane.status, LaneStatus::Unresolved);
        assert!(!lane.finalized);
    }

    let mut absent = resolver_input();
    absent.terminal_event_kind_for_test_none();
    absent.all_sources_closed = true;
    absent.liveness_state = LivenessState::Absent;
    absent.liveness_probe_refs = refs(&["absent-proof"]);
    let (lane, receipt) = resolve_capture(absent).unwrap();
    assert_eq!(lane.status, LaneStatus::InterruptedUnconfirmed);
    assert_eq!(
        lane.terminal_kind,
        Some(TerminalKind::SourceClosedUnconfirmed)
    );
    assert!(lane.finalized);
    assert_eq!(receipt.terminal_event_ref, None);
    assert!(!receipt.lifecycle_end_seen);
    assert!(
        receipt
            .termination_evidence_refs
            .contains(&"absent-proof".into())
    );
}

#[test]
fn late_terminal_is_a_successor_on_the_same_lane() {
    let mut initial = resolver_input();
    initial.terminal_event_kind_for_test_none();
    initial.all_sources_closed = true;
    initial.liveness_state = LivenessState::Absent;
    initial.liveness_probe_refs = refs(&["absent-proof"]);
    let (old_lane, old_receipt) = resolve_capture(initial).unwrap();
    assert_eq!(old_lane.status, LaneStatus::InterruptedUnconfirmed);

    let mut late = resolver_input();
    late.execution_lane_id = old_lane.execution_lane_id;
    late.previous_lane = Some(old_lane.clone());
    late.previous_receipt = Some(old_receipt.clone());
    late.capture_receipt_revision_id = CaptureReceiptId::new_v7();
    late.correction_reason = Some("late-terminal".into());
    let (successor_lane, successor_receipt) = resolve_capture(late).unwrap();
    assert_eq!(successor_lane.lane_revision, old_lane.lane_revision + 1);
    assert_eq!(
        successor_receipt.predecessor_revision_id,
        Some(old_receipt.capture_receipt_revision_id)
    );
    assert_eq!(old_lane.status, LaneStatus::InterruptedUnconfirmed);
    assert_eq!(successor_lane.status, LaneStatus::Stopped);
}

#[test]
fn new_incarnation_cannot_reuse_a_finalized_lane_identity() {
    let (old_lane, old_receipt) = resolve_capture(resolver_input()).unwrap();
    assert!(old_lane.finalized);

    for observation_id in [
        SourceObservationId::from_digest([1; 32]),
        SourceObservationId::from_digest([2; 32]),
    ] {
        let mut legacy = resolver_input();
        legacy.execution_lane_id = old_lane.execution_lane_id;
        legacy.previous_lane = Some(old_lane.clone());
        legacy.previous_receipt = Some(old_receipt.clone());
        legacy.capture_receipt_revision_id = CaptureReceiptId::new_v7();
        legacy.incarnation_ref = format!("source-observation:{observation_id}");
        assert_eq!(resolve_capture(legacy), Err(WorkError::InvalidLane));
    }

    let mut resumed = resolver_input();
    resumed.execution_lane_id = old_lane.execution_lane_id;
    resumed.previous_lane = Some(old_lane);
    resumed.previous_receipt = Some(old_receipt);
    resumed.capture_receipt_revision_id = CaptureReceiptId::new_v7();
    resumed.incarnation_ref = "incarnation-b".into();
    resumed.spawn_event_ref = Some("spawn-b".into());
    assert_eq!(resolve_capture(resumed), Err(WorkError::InvalidLane));
}

#[test]
fn late_gap_and_outage_reconciliation_strengthens_successor_without_erasing_refs() {
    let mut degraded = resolver_input();
    degraded.capture_gap_marker_refs = refs(&["gap-a"]);
    degraded.unresolved_gap_marker_refs = refs(&["gap-a"]);
    let (old_lane, old_receipt) = resolve_capture(degraded).unwrap();
    assert_eq!(old_receipt.source_coverage, SourceCoverage::Partial);
    assert_eq!(old_receipt.payload_integrity, PayloadIntegrity::Unavailable);

    let mut repaired = resolver_input();
    repaired.execution_lane_id = old_lane.execution_lane_id;
    repaired.previous_lane = Some(old_lane);
    repaired.previous_receipt = Some(old_receipt.clone());
    repaired.capture_receipt_revision_id = CaptureReceiptId::new_v7();
    repaired.capture_gap_marker_refs = refs(&["gap-a"]);
    repaired.admission_failure_evidence_refs = refs(&["gap-a"]);
    repaired.source_close_reconciliation_refs = refs(&["reconciliation-a", "late-source-a"]);
    repaired.independent_reconciliation = true;
    let (_, successor) = resolve_capture(repaired).unwrap();
    assert_eq!(successor.source_coverage, SourceCoverage::Complete);
    assert_eq!(successor.capture_gap_marker_refs, refs(&["gap-a"]));
    assert_eq!(successor.admission_failure_evidence_refs, refs(&["gap-a"]));
    assert_eq!(
        successor.predecessor_revision_id,
        Some(old_receipt.capture_receipt_revision_id)
    );
}

fn event(payload: JournalPayload) -> JournalEventDraft {
    JournalEventDraft {
        occurred_at_us: 1,
        source_kind: SourceKind::System,
        scope: EventScope::default(),
        causation_id: None,
        correlation_id: None,
        effective_config_hash: CONFIG_HASH,
        algorithm_revision: "s10-v1".into(),
        payload,
    }
}

#[tokio::test]
async fn current_projection_rebuild_no_delta_relations_and_table_boundary_hold() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let mut input = resolver_input();
    input.all_sources_closed = false;
    input.source_closed_refs.clear();
    input.source_close_watermark_refs.clear();
    input.source_close_reconciliation_refs.clear();
    input.source_reconciliation_complete = false;
    input.source_revision_refs.clear();
    input.first_sequence = None;
    input.last_sequence = None;
    let (lane, receipt) = resolve_capture(input).unwrap();
    let command = JournalCommand::new(
        CommandId::new_v7(),
        vec![
            event(JournalPayload::ExecutionLaneRecorded(Box::new(
                lane.clone(),
            ))),
            event(JournalPayload::CaptureReceiptRecorded(Box::new(
                receipt.clone(),
            ))),
        ],
    )
    .unwrap();
    writer.commit(&command, 1).await.unwrap();
    let incremental = writer.project().await.unwrap();
    let full = writer.full_projection().await.unwrap();
    assert_eq!(incremental, full);
    let rows_before = writer.object_rows().await.unwrap();
    assert_eq!(writer.project().await.unwrap(), incremental);
    assert_eq!(writer.object_rows().await.unwrap(), rows_before);

    let relations = build_capture_relation_rows(&lane, &receipt).unwrap();
    assert!(
        relations
            .iter()
            .any(|row| { row.kind == CaptureRelationKind::ExecutionLaneToCaptureReceipt })
    );
    assert_eq!(
        writer.table_names().await.unwrap(),
        vec!["evertrace_journal", OBJECTS_TABLE]
    );
}

fn limits() -> SpoolLimits {
    SpoolLimits {
        high_watermark_bytes: 2 * 1024 * 1024,
        low_watermark_bytes: 64 * 1024,
        max_main_files: 16,
        emergency_slots: 4,
    }
}

fn runtime_snapshot(root: &Path) -> RuntimeSnapshot {
    let limits = limits();
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
        recovery_gate: evertrace_capture::RecoveryGateMode::Disabled,
        recovery_socket_path: root.join("runtime/evertraced-v1.sock"),
        recovery_preflight_timeout_ms: 250,
        effective_config_hash: [1; 32],
        recovery_adapter_manifest_id: None,
        recovery_classifier_revision: 1,
        recovery_max_bundle_bytes: 4 << 20,
        recovery_max_untracked_file_bytes: 1 << 20,
        recovery_max_untracked_total_bytes: 2 << 20,
    }
}

fn manifest() -> AdapterCapabilityManifest {
    let mut manifest = AdapterCapabilityManifest {
        adapter_manifest_id: String::new(),
        adapter_kind: AdapterKind::CodexSessionJsonl,
        adapter_version: "s10-test".into(),
        host_version_range: "test".into(),
        eligible_event_manifest_refs: refs(&["eligible-s10"]),
        event_identity: EventIdentity::StableNative,
        capture_guarantee: CaptureGuarantee::Full,
        recovery_ordering: RecoveryOrdering::FencedHost,
        cue_boundary: CueBoundary::Unavailable,
        subagent_trace: SubagentTrace::Full,
        trust_readback: TrustReadback::Unavailable,
        project_policy_surfaces: Vec::new(),
        admission_failure_observability: ManifestObservability::Complete,
        mcp_session_binding: McpSessionBinding::Unavailable,
        mcp_binding_mechanism: McpBindingMechanism::None,
        observable: vec![
            ObservableCapability::DelegationStart,
            ObservableCapability::ChildSessionId,
            ObservableCapability::ChildToolCall,
            ObservableCapability::ChildToolResult,
            ObservableCapability::ChildFinalResult,
            ObservableCapability::DelegationEnd,
        ],
        unavailable_by_design: vec![ObservableCapability::RawHiddenReasoning],
        required_for_full: REQUIRED_FOR_FULL.to_vec(),
    };
    manifest.finalize_content_revision().unwrap();
    manifest
}

fn correlation(role: ObservationRole, manifest_ref: &str) -> HostCorrelationEvidence {
    HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: None,
        host_trace_lineage_id: None,
        host_lane_key: None,
        canonical_event_family: None,
        native_request_id: None,
        physical_execution_ordinal: None,
        pairing_role: role,
        field_provenance: Vec::new(),
        adapter_manifest_ref: manifest_ref.into(),
        adapter_revision: 1,
        strong_gate_receipt_ref: None,
        admission: CorrelationAdmission::Unavailable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    }
}

fn lifecycle(sequence: u64, manifest_ref: &str) -> LaneLifecycleEvidence {
    LaneLifecycleEvidence {
        host_session_id: "session-a".into(),
        agent_id: "child-a".into(),
        incarnation_ref: Some("incarnation-a".into()),
        child_session_id: Some("child-session-a".into()),
        host_lane_key: "host-lane-a".into(),
        parent_host_lane_key: Some("parent-lane-a".into()),
        spawn_event_ref: Some("spawn-a".into()),
        terminal_event_ref: (sequence == 3).then(|| "terminal-a".into()),
        terminal_kind: (sequence == 3).then_some(TerminalKind::Normal),
        host_final_return: sequence == 3,
        source_close_ref: (sequence == 3).then(|| "close-a".into()),
        parent_session_end_ref: None,
        liveness_probe_ref: Some("liveness-a".into()),
        liveness_state: LivenessState::Absent,
        lane_sequence: sequence,
        adapter_manifest_ref: manifest_ref.into(),
        eligible_event_manifest_ref: "eligible-s10".into(),
        delegated_goal_ref: Some("goal-ref-a".into()),
        delegated_target_refs: refs(&["target-ref-a"]),
        delegated_acceptance_refs: refs(&["acceptance-ref-a"]),
        reasoning_visibility: Vec::new(),
    }
}

fn capture_input(sequence: u64, manifest_ref: &str) -> CaptureRecordInput {
    let role = match sequence {
        1 => ObservationRole::Intent,
        2 => ObservationRole::Result,
        _ => ObservationRole::Lifecycle,
    };
    CaptureRecordInput {
        spool_record_id: Some(format!("spool-{sequence}")),
        source_observation_id_hint: None,
        source_instance_id: "source-a".into(),
        source_revision: "revision-a".into(),
        source_record_identity: Some(format!("record-{sequence}")),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::CodexSessionJsonl,
        identity_domain: "session-jsonl-v1".into(),
        source_ref: "session-source-a".into(),
        session_ref: "session-a".into(),
        turn_ref: Some("turn-a".into()),
        tool_ref: (sequence <= 2).then(|| "tool-a".into()),
        source_sequence: sequence,
        source_sequence_origin: None,
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        source_byte_range: None,
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: (sequence == 3).then_some(3),
        observation_role: role,
        correlation: correlation(role, manifest_ref),
        scope_effect_claims: Vec::new(),
        lifecycle: Some(lifecycle(sequence, manifest_ref)),
        unsupported_record_classification: None,
        source_role: if sequence <= 2 {
            SourceRole::Tool
        } else {
            SourceRole::Host
        },
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Complete,
        surface_eligible: sequence <= 2,
        adapter_revision: 1,
        adapter_manifest_ref: manifest_ref.into(),
        eligible_event_manifest_ref: "eligible-s10".into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: Some(sequence as i64),
        raw_payload: format!("payload-{sequence}").into_bytes(),
    }
}

macro_rules! lifecycle_capture_input {
    (
        $source_instance_id:expr,
        $source_revision:expr,
        $source_sequence:expr,
        $lane_sequence:expr,
        $host_session_id:expr,
        $agent_id:expr,
        $host_lane_key:expr,
        $spawn_event_ref:expr,
        $terminal:expr,
        $child_session_id:expr,
        $close_watermark:expr,
        $manifest_ref:expr $(,)?
    ) => {{
        let spawn_event_ref: Option<&str> = $spawn_event_ref;
        let child_session_id: Option<&str> = $child_session_id;
        let close_watermark: Option<u64> = $close_watermark;
        let mut input = capture_input($source_sequence, $manifest_ref);
        input.spool_record_id = Some(format!(
            "spool-{}-{}-{}-{}",
            $source_instance_id, $source_revision, $source_sequence, $lane_sequence
        ));
        input.source_instance_id = $source_instance_id.into();
        input.source_revision = $source_revision.into();
        input.source_record_identity = Some(format!("record-{}", $lane_sequence));
        input.source_ref = format!("source-ref-{}", $source_instance_id);
        input.session_ref = $host_session_id.into();
        input.turn_ref = None;
        input.tool_ref = None;
        input.close_watermark = close_watermark;
        input.observation_role = ObservationRole::Lifecycle;
        input.correlation = correlation(ObservationRole::Lifecycle, $manifest_ref);
        input.source_role = SourceRole::Host;
        input.surface_eligible = false;
        input.event_time_us = Some($lane_sequence as i64);
        input.raw_payload =
            format!("payload-{}-{}", $source_instance_id, $lane_sequence).into_bytes();
        let lifecycle = input.lifecycle.as_mut().unwrap();
        lifecycle.host_session_id = $host_session_id.into();
        lifecycle.agent_id = $agent_id.into();
        lifecycle.incarnation_ref = child_session_id
            .map(|value| format!("child-session:{value}"))
            .or_else(|| spawn_event_ref.map(|value| format!("spawn-event:{value}")))
            .or_else(|| {
                Some(format!(
                    "incarnation:{}:{}:{}",
                    $host_session_id, $agent_id, $host_lane_key
                ))
            });
        lifecycle.child_session_id = child_session_id.map(str::to_owned);
        lifecycle.host_lane_key = $host_lane_key.into();
        lifecycle.parent_host_lane_key = None;
        lifecycle.spawn_event_ref = spawn_event_ref.map(str::to_owned);
        lifecycle.terminal_event_ref = $terminal.then(|| format!("terminal-{}", $lane_sequence));
        lifecycle.terminal_kind = $terminal.then_some(TerminalKind::Normal);
        lifecycle.host_final_return = false;
        lifecycle.source_close_ref =
            close_watermark.map(|_| format!("close-{}", $source_instance_id));
        lifecycle.liveness_probe_ref = None;
        lifecycle.liveness_state = LivenessState::Unknown;
        lifecycle.lane_sequence = $lane_sequence;
        lifecycle.delegated_goal_ref = None;
        lifecycle.delegated_target_refs.clear();
        lifecycle.delegated_acceptance_refs.clear();
        input
    }};
}

fn current_capture_state(
    snapshot: &evertrace_store::ProjectionSnapshot,
) -> (
    Vec<evertrace_domain::work::ExecutionLane>,
    Vec<evertrace_domain::work::CaptureReceipt>,
    Vec<evertrace_domain::evidence::CaptureOutageInterval>,
) {
    let mut lanes = Vec::new();
    let mut receipts = Vec::new();
    let mut outages = Vec::new();
    for row in snapshot.data_rows() {
        let Some(payload_json) = row.payload_json.as_deref() else {
            continue;
        };
        match serde_json::from_str::<JournalPayload>(payload_json).unwrap() {
            JournalPayload::ExecutionLaneRecorded(value) => lanes.push(*value),
            JournalPayload::CaptureReceiptRecorded(value) => receipts.push(*value),
            JournalPayload::CaptureOutageIntervalRecorded(value) => outages.push(*value),
            _ => {}
        }
    }
    (lanes, receipts, outages)
}

fn reconcile_input(
    snapshot: RuntimeSnapshot,
    manifest: AdapterCapabilityManifest,
    liveness: Vec<LivenessObservation>,
    occurred_at_us: i64,
    max_items: usize,
) -> ReconcileInput {
    ReconcileInput {
        runtime_snapshot: snapshot,
        adapter_manifests: vec![manifest],
        liveness,
        reconciled_gaps: Vec::new(),
        reconciled_outages: Vec::new(),
        independent_source_reconciliations: Vec::new(),
        effective_config_hash: CONFIG_HASH,
        algorithm_revision: "s10-v1".into(),
        occurred_at_us,
        max_items,
    }
}

#[tokio::test]
async fn bounded_reconciler_commits_gap_and_retains_unowned_quarantine() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let snapshot = runtime_snapshot(temp.path());
    let manifest = manifest();
    let mut runtime = CaptureRuntime::open(snapshot.clone()).unwrap();
    for sequence in 1..=3 {
        runtime
            .capture(capture_input(sequence, &manifest.adapter_manifest_id))
            .unwrap();
    }
    runtime.seal_active().unwrap();
    let writer = open_writer(&temp.path().join("store")).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ingestor =
        EvidenceIngestor::new(snapshot.clone(), handle.clone(), CONFIG_HASH, "s10-v1").unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 3);

    let (spool, _) = DurableSpool::open(snapshot.spool_dir.clone(), limits()).unwrap();
    spool
        .write_gap_marker(&CaptureGapMarker {
            marker_id: "gap:committed-before-ack".into(),
            source_ref: "session-source-a".into(),
            session_ref: "session-a".into(),
            turn_ref: Some("turn-a".into()),
            tool_ref: Some("tool-a".into()),
            failure_reason: GapReason::MainUnavailable,
            redacted_fingerprint: FINGERPRINT.into(),
            attempted_bytes: 7,
            last_durable_watermark: 3,
        })
        .unwrap();
    let sealed = snapshot.spool_dir.join("main/corrupt-test.sealed");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&sealed)
        .unwrap();
    use std::io::Write;
    file.write_all(b"corrupt-sealed-segment").unwrap();
    file.sync_all().unwrap();
    drop(file);
    let (_, report) = DurableSpool::open(snapshot.spool_dir.clone(), limits()).unwrap();
    assert_eq!(report.gaps.len(), 1);

    let progress = reconcile_once(
        ReconcileInput {
            runtime_snapshot: snapshot.clone(),
            adapter_manifests: vec![manifest.clone()],
            liveness: vec![LivenessObservation {
                host_session_id: "session-a".into(),
                agent_id: "child-a".into(),
                host_lane_key: "host-lane-a".into(),
                incarnation_ref: "child-session:child-session-a".into(),
                state: LivenessState::Absent,
                evidence_ref: "liveness-a".into(),
            }],
            reconciled_gaps: Vec::new(),
            reconciled_outages: Vec::new(),
            independent_source_reconciliations: Vec::new(),
            effective_config_hash: CONFIG_HASH,
            algorithm_revision: "s10-v1".into(),
            occurred_at_us: 10,
            max_items: 16,
        },
        &handle,
    )
    .await
    .unwrap();
    assert_eq!(progress.markers_acknowledged, 1);
    assert_eq!(progress.quarantine_acknowledged, 0);
    assert_eq!(progress.gap_revisions_recorded, 2);
    let (spool, _) = DurableSpool::open(snapshot.spool_dir.clone(), limits()).unwrap();
    assert!(spool.pending_gap_markers().unwrap().is_empty());
    assert_eq!(spool.pending_quarantine(4).unwrap().len(), 1);
    assert_eq!(
        handle
            .project()
            .await
            .unwrap()
            .rows
            .iter()
            .filter(|row| { row.object_kind.as_deref() == Some("capture_gap_marker") })
            .count(),
        2
    );
    assert_eq!(
        handle
            .project()
            .await
            .unwrap()
            .rows
            .iter()
            .filter(|row| row.object_kind.as_deref() == Some("capture_outage_interval"))
            .count(),
        0
    );

    let (spool, _) = DurableSpool::open(snapshot.spool_dir.clone(), limits()).unwrap();
    spool
        .write_gap_marker(&CaptureGapMarker {
            marker_id: "gap:committed-before-ack".into(),
            source_ref: "session-source-a".into(),
            session_ref: "session-a".into(),
            turn_ref: Some("turn-a".into()),
            tool_ref: Some("tool-a".into()),
            failure_reason: GapReason::MainUnavailable,
            redacted_fingerprint: FINGERPRINT.into(),
            attempted_bytes: 7,
            last_durable_watermark: 3,
        })
        .unwrap();
    let replay = reconcile_once(
        ReconcileInput {
            runtime_snapshot: snapshot.clone(),
            adapter_manifests: vec![manifest.clone()],
            liveness: vec![LivenessObservation {
                host_session_id: "session-a".into(),
                agent_id: "child-a".into(),
                host_lane_key: "host-lane-a".into(),
                incarnation_ref: "child-session:child-session-a".into(),
                state: LivenessState::Absent,
                evidence_ref: "liveness-a".into(),
            }],
            reconciled_gaps: Vec::new(),
            reconciled_outages: Vec::new(),
            independent_source_reconciliations: Vec::new(),
            effective_config_hash: CONFIG_HASH,
            algorithm_revision: "s10-v1".into(),
            occurred_at_us: 11,
            max_items: 16,
        },
        &handle,
    )
    .await
    .unwrap();
    assert!(replay.no_delta, "{replay:?}");
    assert_eq!(replay.gap_revisions_recorded, 0);
    assert_eq!(replay.markers_acknowledged, 1);
    let (spool, _) = DurableSpool::open(snapshot.spool_dir.clone(), limits()).unwrap();
    assert!(spool.pending_gap_markers().unwrap().is_empty());

    let mut conflicting = marker("gap:committed-before-ack");
    conflicting.source_ref = "session-source-a".into();
    conflicting.turn_ref = Some("turn-a".into());
    conflicting.tool_ref = Some("tool-a".into());
    conflicting.attempted_bytes = 8;
    conflicting.last_durable_watermark = 3;
    spool.write_gap_marker(&conflicting).unwrap();
    let conflict = reconcile_once(
        reconcile_input(snapshot.clone(), manifest, Vec::new(), 12, 16),
        &handle,
    )
    .await;
    assert_eq!(conflict, Err(ReconcileError::Projection));
    let (spool, _) = DurableSpool::open(snapshot.spool_dir.clone(), limits()).unwrap();
    assert_eq!(spool.pending_gap_markers().unwrap().len(), 1);

    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn real_reconciliation_preserves_typed_identity_and_execution_incarnation() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let snapshot = runtime_snapshot(temp.path());
    let manifest = manifest();
    let mut runtime = CaptureRuntime::open(snapshot.clone()).unwrap();
    runtime
        .capture(lifecycle_capture_input!(
            "source-a",
            "revision-a",
            1,
            1,
            "session-a",
            "agent-a",
            "shared-lane",
            Some("spawn-a"),
            false,
            Some("child-session-a"),
            Some(1),
            &manifest.adapter_manifest_id,
        ))
        .unwrap();
    runtime.seal_active().unwrap();
    let writer = open_writer(&temp.path().join("store")).await.unwrap();
    let (handle, task) = spawn_writer(writer, 16).unwrap();
    let ingestor =
        EvidenceIngestor::new(snapshot.clone(), handle.clone(), CONFIG_HASH, "s10-v1").unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 1);
    reconcile_once(
        reconcile_input(
            snapshot.clone(),
            manifest.clone(),
            vec![LivenessObservation {
                host_session_id: "session-a".into(),
                agent_id: "agent-a".into(),
                host_lane_key: "shared-lane".into(),
                incarnation_ref: "child-session:child-session-a".into(),
                state: LivenessState::Absent,
                evidence_ref: "liveness-a".into(),
            }],
            20,
            16,
        ),
        &handle,
    )
    .await
    .unwrap();
    let (first_lanes, first_receipts, _) = current_capture_state(&handle.project().await.unwrap());
    assert_eq!(first_lanes.len(), 1);
    assert_eq!(first_lanes[0].status, LaneStatus::InterruptedUnconfirmed);
    assert_eq!(first_lanes[0].terminal_event_ref, None);
    assert_eq!(
        first_receipts[0].child_session_id.as_deref(),
        Some("child-session-a")
    );
    assert_ne!(
        first_receipts[0].child_session_id.as_deref(),
        Some("agent-a")
    );
    assert!(!first_receipts[0].lifecycle_end_seen);
    let first_lane_id = first_lanes[0].execution_lane_id;

    runtime
        .capture(lifecycle_capture_input!(
            "source-b",
            "revision-b",
            1,
            2,
            "session-a",
            "agent-a",
            "shared-lane",
            None,
            true,
            Some("child-session-a"),
            Some(1),
            &manifest.adapter_manifest_id,
        ))
        .unwrap();
    runtime.seal_active().unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 1);
    reconcile_once(
        reconcile_input(snapshot.clone(), manifest.clone(), Vec::new(), 21, 16),
        &handle,
    )
    .await
    .unwrap();
    let (late_lanes, _, _) = current_capture_state(&handle.project().await.unwrap());
    assert_eq!(late_lanes.len(), 1);
    assert_eq!(late_lanes[0].execution_lane_id, first_lane_id);
    assert_eq!(late_lanes[0].lane_revision, 2);
    assert_eq!(late_lanes[0].status, LaneStatus::Stopped);

    runtime
        .capture(lifecycle_capture_input!(
            "source-c",
            "revision-c",
            1,
            1,
            "session-a",
            "agent-a",
            "shared-lane",
            Some("spawn-b"),
            false,
            Some("child-session-b"),
            None,
            &manifest.adapter_manifest_id,
        ))
        .unwrap();
    runtime
        .capture(lifecycle_capture_input!(
            "source-c",
            "revision-c",
            2,
            2,
            "session-a",
            "agent-a",
            "shared-lane",
            None,
            true,
            Some("child-session-b"),
            Some(2),
            &manifest.adapter_manifest_id,
        ))
        .unwrap();
    runtime
        .capture(lifecycle_capture_input!(
            "source-d",
            "revision-d",
            1,
            1,
            "session-b",
            "agent-a",
            "shared-lane",
            Some("spawn-d"),
            true,
            Some("child-session-d"),
            Some(1),
            &manifest.adapter_manifest_id,
        ))
        .unwrap();
    runtime
        .capture(lifecycle_capture_input!(
            "source-e",
            "revision-e",
            1,
            1,
            "session-a",
            "agent-b",
            "shared-lane",
            Some("spawn-e"),
            true,
            Some("child-session-e"),
            Some(1),
            &manifest.adapter_manifest_id,
        ))
        .unwrap();
    runtime.seal_active().unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 4);
    reconcile_once(
        reconcile_input(snapshot, manifest, Vec::new(), 22, 32),
        &handle,
    )
    .await
    .unwrap();
    let (lanes, _, _) = current_capture_state(&handle.project().await.unwrap());
    assert_eq!(lanes.len(), 4);
    let resumed = lanes
        .iter()
        .find(|lane| lane.spawn_event_ref.as_deref() == Some("spawn-b"))
        .unwrap();
    assert_ne!(resumed.execution_lane_id, first_lane_id);
    assert!(lanes.iter().any(|lane| {
        lane.host_session_id == "session-b"
            && lane.agent_id == "agent-a"
            && lane.host_lane_key == "shared-lane"
    }));
    assert!(lanes.iter().any(|lane| {
        lane.host_session_id == "session-a"
            && lane.agent_id == "agent-b"
            && lane.host_lane_key == "shared-lane"
    }));
    assert!(lanes.iter().all(|lane| lane.finalized));

    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn liveness_targets_only_the_named_execution_incarnation() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let snapshot = runtime_snapshot(temp.path());
    let manifest = manifest();
    let mut runtime = CaptureRuntime::open(snapshot.clone()).unwrap();
    for input in [
        lifecycle_capture_input!(
            "source-a",
            "revision-a",
            1,
            1,
            "session-a",
            "agent-a",
            "shared-lane",
            Some("spawn-a"),
            false,
            Some("child-a"),
            Some(1),
            &manifest.adapter_manifest_id,
        ),
        lifecycle_capture_input!(
            "source-b",
            "revision-b",
            1,
            1,
            "session-a",
            "agent-a",
            "shared-lane",
            Some("spawn-b"),
            false,
            Some("child-b"),
            Some(1),
            &manifest.adapter_manifest_id,
        ),
    ] {
        runtime.capture(input).unwrap();
    }
    runtime.seal_active().unwrap();
    let writer = open_writer(&temp.path().join("store")).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ingestor =
        EvidenceIngestor::new(snapshot.clone(), handle.clone(), CONFIG_HASH, "s10-v1").unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 2);
    reconcile_once(
        reconcile_input(
            snapshot,
            manifest,
            vec![LivenessObservation {
                host_session_id: "session-a".into(),
                agent_id: "agent-a".into(),
                host_lane_key: "shared-lane".into(),
                incarnation_ref: "child-session:child-a".into(),
                state: LivenessState::Absent,
                evidence_ref: "liveness-a".into(),
            }],
            23,
            16,
        ),
        &handle,
    )
    .await
    .unwrap();
    let (lanes, _, _) = current_capture_state(&handle.project().await.unwrap());
    assert_eq!(lanes.len(), 2);
    assert_eq!(
        lanes
            .iter()
            .find(|lane| lane.incarnation_ref == "child-session:child-a")
            .unwrap()
            .status,
        LaneStatus::InterruptedUnconfirmed
    );
    assert_eq!(
        lanes
            .iter()
            .find(|lane| lane.incarnation_ref == "child-session:child-b")
            .unwrap()
            .status,
        LaneStatus::Unresolved
    );

    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn conflicting_child_session_evidence_degrades_without_agent_substitution() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let snapshot = runtime_snapshot(temp.path());
    let manifest = manifest();
    let mut runtime = CaptureRuntime::open(snapshot.clone()).unwrap();
    let mut first = lifecycle_capture_input!(
        "source-a",
        "revision-a",
        1,
        1,
        "session-a",
        "agent-a",
        "lane-a",
        Some("spawn-a"),
        false,
        Some("child-a"),
        Some(1),
        &manifest.adapter_manifest_id,
    );
    let mut second = lifecycle_capture_input!(
        "source-b",
        "revision-b",
        1,
        2,
        "session-a",
        "agent-a",
        "lane-a",
        None,
        true,
        Some("child-b"),
        Some(1),
        &manifest.adapter_manifest_id,
    );
    first.lifecycle.as_mut().unwrap().incarnation_ref = Some("incarnation-conflict".into());
    second.lifecycle.as_mut().unwrap().incarnation_ref = Some("incarnation-conflict".into());
    for input in [first, second] {
        runtime.capture(input).unwrap();
    }
    runtime.seal_active().unwrap();
    let writer = open_writer(&temp.path().join("store")).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ingestor =
        EvidenceIngestor::new(snapshot.clone(), handle.clone(), CONFIG_HASH, "s10-v1").unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 2);
    reconcile_once(
        reconcile_input(snapshot, manifest, Vec::new(), 25, 16),
        &handle,
    )
    .await
    .unwrap();
    let (_, receipts, _) = current_capture_state(&handle.project().await.unwrap());
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].child_session_id, None);
    assert!(!receipts[0].child_session_linked);
    assert_eq!(receipts[0].coverage_level, CoverageLevel::Partial);

    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn lane_and_source_sequences_are_independent_and_sources_do_not_cross_fill() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let snapshot = runtime_snapshot(temp.path());
    let manifest = manifest();
    let mut runtime = CaptureRuntime::open(snapshot.clone()).unwrap();
    let mut explicit_origin = lifecycle_capture_input!(
        "source-c",
        "revision-c",
        2,
        13,
        "session-a",
        "agent-a",
        "lane-a",
        None,
        false,
        Some("child-a"),
        Some(2),
        &manifest.adapter_manifest_id,
    );
    explicit_origin.source_sequence_origin = Some(1);
    for input in [
        lifecycle_capture_input!(
            "source-a",
            "revision-a",
            1,
            10,
            "session-a",
            "agent-a",
            "lane-a",
            Some("spawn-a"),
            false,
            Some("child-a"),
            None,
            &manifest.adapter_manifest_id,
        ),
        lifecycle_capture_input!(
            "source-a",
            "revision-a",
            3,
            11,
            "session-a",
            "agent-a",
            "lane-a",
            None,
            true,
            Some("child-a"),
            Some(4),
            &manifest.adapter_manifest_id,
        ),
        lifecycle_capture_input!(
            "source-b",
            "revision-b",
            2,
            12,
            "session-a",
            "agent-a",
            "lane-a",
            None,
            false,
            Some("child-a"),
            Some(2),
            &manifest.adapter_manifest_id,
        ),
        explicit_origin,
    ] {
        runtime.capture(input).unwrap();
    }
    runtime.seal_active().unwrap();
    let writer = open_writer(&temp.path().join("store")).await.unwrap();
    let (handle, task) = spawn_writer(writer, 16).unwrap();
    let ingestor =
        EvidenceIngestor::new(snapshot.clone(), handle.clone(), CONFIG_HASH, "s10-v1").unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 4);
    reconcile_once(
        reconcile_input(snapshot, manifest, Vec::new(), 30, 32),
        &handle,
    )
    .await
    .unwrap();
    let projected = handle.project().await.unwrap();
    let (_, receipts, outages) = current_capture_state(&projected);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].first_sequence, Some(10));
    assert_eq!(receipts[0].last_sequence, Some(13));
    assert!(receipts[0].sequence_gaps.is_empty());
    let intervals = outages
        .iter()
        .map(|outage| {
            (
                outage.source_ref.clone(),
                outage.first_missing_sequence,
                outage.last_missing_sequence,
            )
        })
        .collect::<BTreeSet<_>>();
    assert!(intervals.contains(&("source-a@revision-a".into(), 2, 2)));
    assert!(intervals.contains(&("source-a@revision-a".into(), 4, 4)));
    assert!(!intervals.contains(&("source-b@revision-b".into(), 1, 1)));
    assert!(intervals.contains(&("source-c@revision-c".into(), 1, 1)));
    assert_eq!(outages.len(), 3);
    let decisions = projected
        .data_rows()
        .filter_map(|row| row.payload_json.as_deref())
        .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
        .filter_map(|payload| match payload {
            JournalPayload::SourceCloseReconciliation(value) => Some(value.passed()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(decisions, vec![false]);
    assert_eq!(receipts[0].source_close_reconciliation_refs.len(), 1);

    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn late_source_evidence_reconciles_outage_without_erasing_history() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let snapshot = runtime_snapshot(temp.path());
    let manifest = manifest();
    let mut runtime = CaptureRuntime::open(snapshot.clone()).unwrap();
    for input in [
        lifecycle_capture_input!(
            "source-a",
            "revision-a",
            1,
            1,
            "session-a",
            "agent-a",
            "lane-a",
            Some("spawn-a"),
            false,
            Some("child-a"),
            None,
            &manifest.adapter_manifest_id,
        ),
        lifecycle_capture_input!(
            "source-a",
            "revision-a",
            3,
            3,
            "session-a",
            "agent-a",
            "lane-a",
            None,
            true,
            Some("child-a"),
            Some(3),
            &manifest.adapter_manifest_id,
        ),
    ] {
        runtime.capture(input).unwrap();
    }
    runtime.seal_active().unwrap();
    let writer = open_writer(&temp.path().join("store")).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ingestor =
        EvidenceIngestor::new(snapshot.clone(), handle.clone(), CONFIG_HASH, "s10-v1").unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 2);
    reconcile_once(
        reconcile_input(snapshot.clone(), manifest.clone(), Vec::new(), 31, 16),
        &handle,
    )
    .await
    .unwrap();
    let (_, first_receipts, first_outages) =
        current_capture_state(&handle.project().await.unwrap());
    assert_eq!(first_outages.len(), 1);
    assert!(!first_outages[0].reconciled);
    let outage_id = first_outages[0].capture_outage_interval_id;
    assert!(
        first_receipts[0]
            .capture_outage_interval_refs
            .contains(&outage_id)
    );

    runtime
        .capture(lifecycle_capture_input!(
            "source-a",
            "revision-a",
            2,
            2,
            "session-a",
            "agent-a",
            "lane-a",
            None,
            false,
            Some("child-a"),
            None,
            &manifest.adapter_manifest_id,
        ))
        .unwrap();
    runtime.seal_active().unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 1);
    reconcile_once(
        reconcile_input(snapshot, manifest, Vec::new(), 32, 16),
        &handle,
    )
    .await
    .unwrap();
    let (_, receipts, outages) = current_capture_state(&handle.project().await.unwrap());
    assert_eq!(outages.len(), 1);
    assert_eq!(outages[0].capture_outage_interval_id, outage_id);
    assert!(outages[0].reconciled);
    assert!(!outages[0].reconciliation_refs.is_empty());
    assert!(
        receipts[0]
            .capture_outage_interval_refs
            .contains(&outage_id)
    );
    assert_eq!(receipts[0].ordering_integrity, OrderingIntegrity::Complete);

    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn shared_budget_is_strict_and_large_history_makes_bounded_progress() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let snapshot = runtime_snapshot(temp.path());
    let manifest = manifest();
    let mut runtime = CaptureRuntime::open(snapshot.clone()).unwrap();
    runtime
        .capture(lifecycle_capture_input!(
            "owner-source",
            "owner-revision",
            1,
            1,
            "owner-session",
            "owner-agent",
            "owner-lane",
            Some("owner-spawn"),
            true,
            Some("owner-child"),
            Some(1),
            &manifest.adapter_manifest_id,
        ))
        .unwrap();
    for lane_sequence in 1..=65_u64 {
        let source = format!("source-{lane_sequence:03}");
        let revision = format!("revision-{lane_sequence:03}");
        let session = format!("session-{lane_sequence:03}");
        let agent = format!("agent-{lane_sequence:03}");
        let lane = format!("lane-{lane_sequence:03}");
        let spawn = format!("spawn-{lane_sequence:03}");
        let child = format!("child-{lane_sequence:03}");
        runtime
            .capture(lifecycle_capture_input!(
                &source,
                &revision,
                1,
                1,
                &session,
                &agent,
                &lane,
                Some(spawn.as_str()),
                true,
                Some(child.as_str()),
                Some(1),
                &manifest.adapter_manifest_id,
            ))
            .unwrap();
    }
    runtime.seal_active().unwrap();
    let writer = open_writer(&temp.path().join("store")).await.unwrap();
    let (handle, task) = spawn_writer(writer, 16).unwrap();
    let ingestor =
        EvidenceIngestor::new(snapshot.clone(), handle.clone(), CONFIG_HASH, "s10-v1").unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 66);
    reconcile_once(
        reconcile_input(snapshot.clone(), manifest.clone(), Vec::new(), 39, 2),
        &handle,
    )
    .await
    .unwrap();

    let (spool, _) = DurableSpool::open(snapshot.spool_dir.clone(), limits()).unwrap();
    let mut budget_marker = marker("gap:budget-a");
    budget_marker.source_ref = "source-ref-owner-source".into();
    budget_marker.session_ref = "owner-session".into();
    spool.write_gap_marker(&budget_marker).unwrap();
    use std::io::Write;
    for index in 0..65 {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(
                snapshot
                    .spool_dir
                    .join(format!("quarantine/budget-{index:03}.spool")),
            )
            .unwrap();
        file.write_all(format!("budget-corrupt-segment-{index:03}").as_bytes())
            .unwrap();
        file.sync_all().unwrap();
    }
    assert_eq!(spool.pending_quarantine(64).unwrap().len(), 64);
    let stable_start = handle
        .reconciliation_frontier(1)
        .await
        .unwrap()
        .frontier
        .wrapping_add(40);
    let first_window = spool
        .pending_quarantine_from(64, stable_start)
        .unwrap()
        .into_iter()
        .map(|handle| handle.path().to_owned())
        .collect::<Vec<_>>();
    drop(spool);
    let (reopened, _) = DurableSpool::open(snapshot.spool_dir.clone(), limits()).unwrap();
    let restarted_window = reopened
        .pending_quarantine_from(64, stable_start)
        .unwrap()
        .into_iter()
        .map(|handle| handle.path().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(restarted_window, first_window);

    let first = reconcile_once(
        reconcile_input(snapshot.clone(), manifest.clone(), Vec::new(), 40, 1),
        &handle,
    )
    .await
    .unwrap();
    assert_eq!(first.markers_acknowledged, 1);
    assert_eq!(first.quarantine_acknowledged, 0);
    let (spool, _) = DurableSpool::open(snapshot.spool_dir.clone(), limits()).unwrap();
    assert!(spool.pending_gap_markers().unwrap().is_empty());
    assert_eq!(spool.pending_quarantine(2).unwrap().len(), 2);

    let second = reconcile_once(
        reconcile_input(snapshot.clone(), manifest.clone(), Vec::new(), 41, 1),
        &handle,
    )
    .await
    .unwrap();
    assert_eq!(second.markers_acknowledged, 0);
    assert_eq!(second.quarantine_acknowledged, 0);
    let (spool, _) = DurableSpool::open(snapshot.spool_dir.clone(), limits()).unwrap();
    assert!(spool.pending_gap_markers().unwrap().is_empty());
    assert_eq!(spool.pending_quarantine(2).unwrap().len(), 2);

    for occurred_at_us in 42..48 {
        reconcile_once(
            reconcile_input(
                snapshot.clone(),
                manifest.clone(),
                Vec::new(),
                occurred_at_us,
                64,
            ),
            &handle,
        )
        .await
        .unwrap();
    }
    assert!(
        handle
            .reconciliation_frontier(1)
            .await
            .unwrap()
            .items
            .is_empty()
    );
    let projected = handle.project().await.unwrap();
    let imported_quarantines = projected
        .data_rows()
        .filter_map(|row| row.payload_json.as_deref())
        .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
        .filter(|payload| {
            matches!(
                payload,
                JournalPayload::CaptureGapMarkerRecorded(value)
                    if value.provenance == ReconciliationProvenance::QuarantineRecovery
            )
        })
        .count();
    assert_eq!(imported_quarantines, 65);
    let bounded = reconcile_once(
        reconcile_input(snapshot.clone(), manifest, Vec::new(), 50, 1),
        &handle,
    )
    .await
    .unwrap();
    assert!(bounded.no_delta);
    let (spool, _) = DurableSpool::open(snapshot.spool_dir, limits()).unwrap();
    assert!(spool.pending_gap_markers().unwrap().is_empty());
    assert_eq!(spool.pending_quarantine(64).unwrap().len(), 64);

    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn marker_is_not_acknowledged_when_writer_cannot_commit() {
    let temp = TempDir::new().unwrap();
    let snapshot = runtime_snapshot(temp.path());
    let (spool, _) = DurableSpool::open(snapshot.spool_dir.clone(), limits()).unwrap();
    spool
        .write_gap_marker(&marker("gap:commit-failed"))
        .unwrap();
    let writer = open_writer(&temp.path().join("store")).await.unwrap();
    let (handle, task) = spawn_writer(writer, 2).unwrap();
    handle.clone().shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let result = reconcile_once(
        ReconcileInput {
            runtime_snapshot: snapshot.clone(),
            adapter_manifests: Vec::new(),
            liveness: Vec::new(),
            reconciled_gaps: Vec::new(),
            reconciled_outages: Vec::new(),
            independent_source_reconciliations: Vec::new(),
            effective_config_hash: CONFIG_HASH,
            algorithm_revision: "s10-v1".into(),
            occurred_at_us: 10,
            max_items: 4,
        },
        &handle,
    )
    .await;
    assert_eq!(result, Err(ReconcileError::Commit));
    let (spool, _) = DurableSpool::open(snapshot.spool_dir, limits()).unwrap();
    assert_eq!(spool.pending_gap_markers().unwrap().len(), 1);
}

#[test]
fn raw_hook_exact_self_grant_remains_rejected_by_regression_contract() {
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
        host_instance_id: Some("host-a".into()),
        host_trace_lineage_id: Some("trace-a".into()),
        host_lane_key: Some("lane-a".into()),
        canonical_event_family: Some(CanonicalEventFamily::Mutate),
        native_request_id: Some("request-a".into()),
        physical_execution_ordinal: Some(1),
        pairing_role: ObservationRole::Result,
        field_provenance: fields
            .into_iter()
            .map(|field| CorrelationFieldClaim {
                field,
                source_ref: "hook-a".into(),
                evidence_ref: "evidence-a".into(),
            })
            .collect(),
        adapter_manifest_ref: "manifest-a".into(),
        adapter_revision: 1,
        strong_gate_receipt_ref: Some("strong-gate-a".into()),
        admission: CorrelationAdmission::ExactCapable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    };
    correlation.validate().unwrap();
    let hook = CaptureHookInput {
        input_version: CAPTURE_HOOK_INPUT_VERSION,
        spool_record_id: Some("spool-a".into()),
        source_observation_id_hint: None,
        source_instance_id: "source-a".into(),
        source_revision: "revision-a".into(),
        source_record_identity: Some("record-a".into()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "hook-v1".into(),
        adapter_manifest_ref: "manifest-a".into(),
        eligible_event_manifest_ref: "eligible-a".into(),
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        source_ref: "hook-a".into(),
        session_id: "session-a".into(),
        turn_id: Some("turn-a".into()),
        tool_use_id: Some("tool-a".into()),
        event_kind: HookEventKind::PostToolUse,
        correlation,
        scope_effect_claims: Vec::new(),
        lifecycle: None,
        source_sequence: 1,
        source_sequence_origin: None,
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        event_time_us: Some(1),
        payload: "payload".into(),
    };
    assert!(hook.validate().is_err());
}

#[tokio::test]
async fn interruption_persists_only_lane_and_receipt_objects() {
    let mut interrupted = resolver_input();
    interrupted.terminal_kind = Some(TerminalKind::Crashed);
    interrupted.all_sources_closed = false;
    interrupted.source_closed_refs.clear();
    interrupted.source_close_watermark_refs.clear();
    interrupted.source_close_reconciliation_refs.clear();
    interrupted.source_reconciliation_complete = false;
    interrupted.source_revision_refs.clear();
    interrupted.first_sequence = None;
    interrupted.last_sequence = None;
    let (lane, receipt) = resolve_capture(interrupted).unwrap();
    assert_eq!(lane.status, LaneStatus::Interrupted);
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let command = JournalCommand::new(
        CommandId::new_v7(),
        vec![
            event(JournalPayload::ExecutionLaneRecorded(Box::new(lane))),
            event(JournalPayload::CaptureReceiptRecorded(Box::new(receipt))),
        ],
    )
    .unwrap();
    writer.commit(&command, 1).await.unwrap();
    let journal_types = writer
        .journal_rows()
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.payload().unwrap().event_type())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        journal_types,
        [
            "migration_applied_v1",
            "execution_lane_recorded_v1",
            "capture_receipt_recorded_v1",
        ]
        .into_iter()
        .collect()
    );
    let object_kinds = writer
        .project()
        .await
        .unwrap()
        .data_rows()
        .filter_map(|row| row.object_kind.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        object_kinds,
        ["capture_receipt".to_owned(), "execution_lane".to_owned()]
            .into_iter()
            .collect()
    );
}

fn marker(id: &str) -> CaptureGapMarker {
    CaptureGapMarker {
        marker_id: id.into(),
        source_ref: "source-a".into(),
        session_ref: "session-a".into(),
        turn_ref: None,
        tool_ref: None,
        failure_reason: GapReason::MainUnavailable,
        redacted_fingerprint: FINGERPRINT.into(),
        attempted_bytes: 1,
        last_durable_watermark: 0,
    }
}

#[test]
fn marker_ack_revalidates_replacement_permissions_and_symlinks() {
    for case in ["replacement", "permissions", "symlink"] {
        let temp = TempDir::new().unwrap();
        let (spool, _) = DurableSpool::open(temp.path().join("spool"), limits()).unwrap();
        spool
            .write_gap_marker(&marker("gap:identity-safe"))
            .unwrap();
        let handle = spool.pending_gap_marker_handles(1).unwrap().remove(0);
        let path = handle.path().to_path_buf();
        match case {
            "replacement" => {
                let bytes = fs::read(&path).unwrap();
                fs::remove_file(&path).unwrap();
                let mut replacement = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap();
                use std::io::Write;
                replacement.write_all(&bytes).unwrap();
                replacement.sync_all().unwrap();
                assert_eq!(
                    spool.acknowledge_gap_marker_handle(handle),
                    Err(SpoolError::IdentityChanged)
                );
            }
            "permissions" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                assert_eq!(
                    spool.acknowledge_gap_marker_handle(handle),
                    Err(SpoolError::InvalidPermissions)
                );
            }
            "symlink" => {
                let target = temp.path().join("target.marker");
                fs::write(&target, b"not-a-marker").unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
                fs::remove_file(&path).unwrap();
                symlink(&target, &path).unwrap();
                assert_eq!(
                    spool.acknowledge_gap_marker_handle(handle),
                    Err(SpoolError::InvalidType)
                );
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn quarantine_ack_rejects_same_inode_same_length_content_change() {
    let temp = TempDir::new().unwrap();
    let spool_root = temp.path().join("spool");
    let (spool, _) = DurableSpool::open(spool_root.clone(), limits()).unwrap();
    let sealed = spool_root.join("main/content-change.sealed");
    let original = b"corrupt-a";
    let replacement = b"corrupt-b";
    assert_eq!(original.len(), replacement.len());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&sealed)
        .unwrap();
    use std::io::Write;
    file.write_all(original).unwrap();
    file.sync_all().unwrap();
    drop(file);
    drop(spool);

    let (spool, report) = DurableSpool::open(spool_root, limits()).unwrap();
    assert_eq!(report.gaps.len(), 1);
    let handle = spool.pending_quarantine(1).unwrap().remove(0);
    let path = handle.path().to_path_buf();
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.write_all(replacement).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert_eq!(
        spool.acknowledge_quarantine(handle),
        Err(SpoolError::IdentityChanged)
    );
}
