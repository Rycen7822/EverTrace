use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Barrier},
    thread,
};

use evertrace_capture::{
    CaptureAdmissionState, CaptureOutcome, CaptureRecordInput, CaptureRuntime, CasDigest,
    DeviceKeyStore, DurableSpool, RUNTIME_SNAPSHOT_VERSION, RuntimeSnapshot, SpoolError,
    SpoolLimits, SpoolRecord, encode_frame, scan_frames,
};
use evertrace_codex::{
    HookDiagnostic,
    hook_input::{CAPTURE_HOOK_INPUT_VERSION, CaptureHookInput, HookEventKind},
    install::{HookGeneration, StableLauncher, shadow_canary_diagnostic},
};
use evertrace_domain::evidence::{
    CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceSourceKind,
    HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceRevisionMode, SourceRole,
};
use tempfile::TempDir;

fn limits() -> SpoolLimits {
    SpoolLimits {
        high_watermark_bytes: 256 * 1024,
        low_watermark_bytes: 64 * 1024,
        max_main_files: 8,
        emergency_slots: 2,
    }
}

fn record(id: &str, body: &[u8]) -> SpoolRecord {
    SpoolRecord {
        spool_generation: 1,
        spool_record_id: id.into(),
        source_observation_id: format!("obs-{id}"),
        cas_refs: vec![CasDigest::for_protected_bytes(body).as_hex()],
        record_body: body.to_vec(),
    }
}

fn snapshot(root: &Path, limits: SpoolLimits) -> RuntimeSnapshot {
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
    }
}

fn unavailable_correlation() -> HostCorrelationEvidence {
    HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: None,
        host_trace_lineage_id: None,
        host_lane_key: None,
        canonical_event_family: None,
        native_request_id: None,
        physical_execution_ordinal: None,
        pairing_role: ObservationRole::Result,
        field_provenance: Vec::new(),
        adapter_manifest_ref: "adapter-manifest-a".into(),
        adapter_revision: 1,
        strong_gate_receipt_ref: None,
        admission: CorrelationAdmission::Unavailable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    }
}

fn input(id: &str, payload: &str) -> CaptureRecordInput {
    CaptureRecordInput {
        spool_record_id: Some(id.into()),
        source_observation_id_hint: None,
        source_instance_id: format!("source-instance-{id}"),
        source_revision: "revision-1".into(),
        source_record_identity: Some(format!("record-{id}")),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        source_ref: format!("source-{id}"),
        session_ref: "session-a".into(),
        turn_ref: Some("turn-a".into()),
        tool_ref: Some("tool-a".into()),
        source_sequence: 1,
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        source_byte_range: None,
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: None,
        observation_role: ObservationRole::Result,
        correlation: unavailable_correlation(),
        scope_effect_claims: Vec::new(),
        unsupported_record_classification: None,
        source_role: SourceRole::Tool,
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Complete,
        surface_eligible: true,
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-manifest-a".into(),
        eligible_event_manifest_ref: "eligible-events-a".into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: Some(1),
        raw_payload: payload.as_bytes().to_vec(),
    }
}

fn prepared_runtime(root: &Path, limits: SpoolLimits) -> CaptureRuntime {
    DeviceKeyStore::new(root.join("keys"))
        .load_or_create()
        .unwrap();
    CaptureRuntime::open(snapshot(root, limits)).unwrap()
}

#[test]
fn versioned_frame_round_trip_preserves_record_identity_and_commit_boundary() {
    let first = record("record-a", b"same protected payload");
    let second = record("record-b", b"same protected payload");
    let first_bytes = encode_frame(&first).unwrap();
    let second_bytes = encode_frame(&second).unwrap();
    assert_ne!(first_bytes, second_bytes);

    let mut stream = first_bytes.clone();
    stream.extend_from_slice(&second_bytes);
    let scan = scan_frames(&stream).unwrap();
    assert_eq!(scan.frames.len(), 2);
    assert_eq!(scan.frames[0].record, first);
    assert_eq!(scan.frames[1].record, second);
    assert!(!scan.incomplete_tail);

    stream.truncate(stream.len() - 3);
    let scan = scan_frames(&stream).unwrap();
    assert_eq!(scan.frames.len(), 1);
    assert!(scan.incomplete_tail);
    let mut corrupt = first_bytes;
    corrupt[24] ^= 1;
    assert!(scan_frames(&corrupt).is_err());
}

#[test]
fn open_tail_repairs_only_incomplete_frame_and_corruption_becomes_gap_evidence() {
    let temp = TempDir::new().unwrap();
    let (mut spool, initial) = DurableSpool::open(temp.path().join("spool"), limits()).unwrap();
    assert_eq!(initial.repaired_tail_bytes, 0);
    spool.append(&record("one", b"body-one")).unwrap();
    let torn = encode_frame(&record("two", b"body-two")).unwrap();
    OpenOptions::new()
        .append(true)
        .open(spool.active_path())
        .unwrap()
        .write_all(&torn[..torn.len() - 4])
        .unwrap();
    drop(spool);

    let (mut spool, repaired) = DurableSpool::open(temp.path().join("spool"), limits()).unwrap();
    assert!(repaired.repaired_tail_bytes > 0);
    assert_eq!(spool.read_active().unwrap().len(), 1);
    let sealed = spool.seal_active(1).unwrap().unwrap();
    let mut bytes = fs::read(&sealed).unwrap();
    bytes[30] ^= 1;
    fs::write(&sealed, bytes).unwrap();
    drop(spool);

    let (spool, recovered) = DurableSpool::open(temp.path().join("spool"), limits()).unwrap();
    assert_eq!(recovered.gaps.len(), 1);
    let quarantined = recovered.gaps[0].quarantined_file.clone();
    assert!(quarantined.exists());
    drop(spool);

    let (_spool, reopened) = DurableSpool::open(temp.path().join("spool"), limits()).unwrap();
    assert_eq!(reopened.gaps.len(), 1);
    assert_eq!(reopened.gaps[0].quarantined_file, quarantined);
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let mut runtime = CaptureRuntime::open(snapshot(temp.path(), limits())).unwrap();
    assert_eq!(runtime.state(), CaptureAdmissionState::Recovering);
    assert!(runtime.complete_recovery().is_err());
    fs::remove_file(quarantined).unwrap();
    runtime.complete_recovery().unwrap();
    assert_eq!(runtime.state(), CaptureAdmissionState::Normal);
}

#[test]
fn existing_invalid_active_path_fails_recovery_closed() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("spool");
    let (spool, _) = DurableSpool::open(&root, limits()).unwrap();
    let active = spool.active_path();
    drop(spool);
    fs::create_dir(&active).unwrap();
    fs::set_permissions(&active, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        DurableSpool::open(root, limits()),
        Err(SpoolError::InvalidType)
    ));
}

#[test]
fn concurrent_short_hook_writers_do_not_interleave_frames() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("spool");
    DurableSpool::open(&root, limits()).unwrap();
    let barrier = Arc::new(Barrier::new(17));
    let mut writers = Vec::new();
    for index in 0..16 {
        let root = root.clone();
        let barrier = Arc::clone(&barrier);
        writers.push(thread::spawn(move || {
            let (mut spool, _) = DurableSpool::open(root, limits()).unwrap();
            barrier.wait();
            spool
                .append(&record(&format!("concurrent-{index}"), b"body"))
                .unwrap();
        }));
    }
    barrier.wait();
    for writer in writers {
        writer.join().unwrap();
    }
    let (spool, report) = DurableSpool::open(root, limits()).unwrap();
    assert!(report.gaps.is_empty());
    assert_eq!(spool.read_active().unwrap().len(), 16);
}

#[test]
fn hook_path_is_daemon_independent_secret_safe_and_shadow_only() {
    let temp = TempDir::new().unwrap();
    let mut runtime = prepared_runtime(temp.path(), limits());
    let secret = "api_key=secret-canary-value";
    let hook_input = CaptureHookInput {
        input_version: CAPTURE_HOOK_INPUT_VERSION,
        spool_record_id: Some("record-a".into()),
        source_observation_id_hint: None,
        source_instance_id: "source-instance-a".into(),
        source_revision: "revision-1".into(),
        source_record_identity: Some("record-a".into()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        adapter_manifest_ref: "adapter-manifest-a".into(),
        eligible_event_manifest_ref: "eligible-events-a".into(),
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        source_ref: "source-record-a".into(),
        session_id: "session-a".into(),
        turn_id: Some("turn-a".into()),
        tool_use_id: Some("tool-a".into()),
        event_kind: HookEventKind::PostToolUse,
        correlation: unavailable_correlation(),
        scope_effect_claims: Vec::new(),
        source_sequence: 1,
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        event_time_us: Some(1),
        payload: secret.into(),
    };
    assert!(!format!("{hook_input:?}").contains(secret));
    let parsed = CaptureHookInput::from_json(&hook_input.to_json().unwrap()).unwrap();
    let outcome = runtime
        .capture(CaptureRecordInput {
            spool_record_id: parsed.spool_record_id,
            source_observation_id_hint: parsed.source_observation_id_hint,
            source_instance_id: parsed.source_instance_id,
            source_revision: parsed.source_revision,
            source_record_identity: parsed.source_record_identity,
            identity_strength: parsed.identity_strength,
            source_kind: parsed.source_kind,
            identity_domain: parsed.identity_domain,
            source_ref: parsed.source_ref,
            session_ref: parsed.session_id,
            turn_ref: parsed.turn_id,
            tool_ref: parsed.tool_use_id,
            source_sequence: parsed.source_sequence,
            task_id: parsed.task_id,
            repository_instance_id: parsed.repository_instance_id,
            worktree_instance_id: parsed.worktree_instance_id,
            source_byte_range: None,
            source_revision_mode: parsed.source_revision_mode,
            previous_source_revision: parsed.previous_source_revision,
            close_watermark: None,
            observation_role: ObservationRole::Result,
            correlation: parsed.correlation,
            scope_effect_claims: parsed.scope_effect_claims,
            unsupported_record_classification: None,
            source_role: SourceRole::Tool,
            content_trust: ContentTrust::Observed,
            capture_completeness: CaptureCompleteness::Complete,
            surface_eligible: true,
            adapter_revision: 1,
            adapter_manifest_ref: parsed.adapter_manifest_ref,
            eligible_event_manifest_ref: parsed.eligible_event_manifest_ref,
            parser_revision: 1,
            canonicalization_revision: 1,
            event_time_us: parsed.event_time_us,
            raw_payload: parsed.payload.into_bytes(),
        })
        .unwrap();
    let CaptureOutcome::Durable { cas_digest, .. } = outcome else {
        panic!("capture should be durable")
    };
    assert_eq!(runtime.state(), CaptureAdmissionState::Normal);
    let frames = runtime.spool().read_active().unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].record.cas_refs, vec![cas_digest.clone()]);
    assert!(
        !frames[0]
            .record
            .record_body
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    );
    let durable_frame_observed = frames.len() == 1
        && frames[0].record.spool_record_id == "record-a"
        && frames[0].record.source_observation_id.starts_with("obs:")
        && frames[0].record.cas_refs == vec![cas_digest];
    assert_eq!(shadow_canary_diagnostic(durable_frame_observed), None);
    assert_eq!(
        shadow_canary_diagnostic(false),
        Some(HookDiagnostic::WiredUnobserved)
    );
}

#[test]
fn repaired_tail_enters_recovering_until_explicit_low_watermark_check() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let (mut spool, _) = DurableSpool::open(temp.path().join("spool"), limits()).unwrap();
    spool.append(&record("durable", b"body")).unwrap();
    let torn = encode_frame(&record("torn", b"body")).unwrap();
    OpenOptions::new()
        .append(true)
        .open(spool.active_path())
        .unwrap()
        .write_all(&torn[..torn.len() - 1])
        .unwrap();
    drop(spool);

    let mut runtime = CaptureRuntime::open(snapshot(temp.path(), limits())).unwrap();
    assert_eq!(runtime.state(), CaptureAdmissionState::Recovering);
    runtime.complete_recovery().unwrap();
    assert_eq!(runtime.state(), CaptureAdmissionState::Normal);
}

#[test]
fn byte_inode_readonly_and_emergency_exhaustion_fail_closed_for_completeness() {
    let temp = TempDir::new().unwrap();
    let pressure_limits = SpoolLimits {
        high_watermark_bytes: 1,
        low_watermark_bytes: 1,
        max_main_files: 1,
        emergency_slots: 1,
    };
    let mut runtime = prepared_runtime(temp.path(), pressure_limits);
    let first = runtime.capture(input("pressure-a", "payload-a")).unwrap();
    assert!(matches!(first, CaptureOutcome::GapRecorded { .. }));
    assert_eq!(runtime.state(), CaptureAdmissionState::Pressure);
    let second = runtime.capture(input("pressure-b", "payload-b")).unwrap();
    assert_eq!(second, CaptureOutcome::CompletenessLost);
    assert_eq!(runtime.spool().pending_gap_markers().unwrap().len(), 1);
    assert!(
        runtime
            .spool()
            .acknowledge_gap_marker("gap:pressure-a")
            .unwrap()
    );

    let third = runtime.capture(input("pressure-c", "payload-c")).unwrap();
    assert!(matches!(third, CaptureOutcome::GapRecorded { .. }));

    let readonly = TempDir::new().unwrap();
    let mut runtime = prepared_runtime(readonly.path(), limits());
    let main_dir = readonly.path().join("spool/main");
    fs::set_permissions(&main_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let outcome = runtime.capture(input("readonly", "payload")).unwrap();
    assert!(matches!(outcome, CaptureOutcome::GapRecorded { .. }));
    assert_eq!(runtime.state(), CaptureAdmissionState::Unavailable);
    fs::set_permissions(main_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let inode = TempDir::new().unwrap();
    let inode_limits = SpoolLimits {
        high_watermark_bytes: 1024 * 1024,
        low_watermark_bytes: 64 * 1024,
        max_main_files: 1,
        emergency_slots: 1,
    };
    let (mut spool, _) = DurableSpool::open(inode.path().join("spool"), inode_limits).unwrap();
    spool.append(&record("inode-a", b"body")).unwrap();
    spool.append(&record("inode-b", b"body")).unwrap();
    assert_eq!(spool.read_active().unwrap().len(), 2);
    spool.seal_active(1).unwrap();
    assert_eq!(
        spool.append(&record("inode-c", b"body")),
        Err(SpoolError::Pressure)
    );
}

#[test]
fn cas_failure_is_unavailable_and_emergency_exhaustion_loses_completeness() {
    let temp = TempDir::new().unwrap();
    let failure_limits = SpoolLimits {
        emergency_slots: 1,
        ..limits()
    };
    let mut runtime = prepared_runtime(temp.path(), failure_limits);
    let blobs = temp.path().join("cas/blobs");
    fs::remove_dir(&blobs).unwrap();
    fs::write(&blobs, b"not-a-directory").unwrap();
    fs::set_permissions(&blobs, fs::Permissions::from_mode(0o600)).unwrap();

    let first_payload = "cas-failure-payload";
    let first = runtime
        .capture(input("cas-failure-a", first_payload))
        .unwrap();
    let CaptureOutcome::GapRecorded { marker_path } = first else {
        panic!("CAS failure should write emergency evidence")
    };
    assert_eq!(runtime.state(), CaptureAdmissionState::Unavailable);
    assert!(
        !fs::read(marker_path)
            .unwrap()
            .windows(first_payload.len())
            .any(|window| window == first_payload.as_bytes())
    );

    assert_eq!(
        runtime
            .capture(input("cas-failure-b", "second-payload"))
            .unwrap(),
        CaptureOutcome::CompletenessLost
    );
    assert_eq!(runtime.state(), CaptureAdmissionState::Unavailable);
}

#[test]
fn runtime_snapshot_is_private_atomic_and_rejects_invalid_records() {
    let temp = TempDir::new().unwrap();
    let value = snapshot(temp.path(), limits());
    let path = temp.path().join("runtime/snapshot-v1");
    value.publish(&path).unwrap();
    assert_eq!(RuntimeSnapshot::load(&path).unwrap(), value);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    fs::write(&path, b"corrupt").unwrap();
    assert!(RuntimeSnapshot::load(&path).is_err());
}

#[test]
fn generation_registry_pins_old_sessions_and_retains_previous_compatible() {
    let temp = TempDir::new().unwrap();
    let launcher = StableLauncher::open(temp.path().join("install")).unwrap();
    let generation = |number| {
        let executable = temp.path().join(format!("hook-{number}"));
        let runtime_snapshot = temp.path().join(format!("snapshot-{number}"));
        fs::write(&executable, b"binary").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&runtime_snapshot, b"snapshot").unwrap();
        fs::set_permissions(&runtime_snapshot, fs::Permissions::from_mode(0o600)).unwrap();
        HookGeneration {
            generation: number,
            protocol_version: 1,
            executable,
            runtime_snapshot,
            compatible: true,
        }
    };
    launcher.publish_generation(generation(1)).unwrap();
    assert_eq!(
        launcher
            .resolve_for_session("session-old")
            .unwrap()
            .generation,
        1
    );
    launcher.publish_generation(generation(2)).unwrap();
    assert_eq!(
        launcher
            .resolve_for_session("session-old")
            .unwrap()
            .generation,
        1
    );
    assert_eq!(
        launcher
            .resolve_for_session("session-new")
            .unwrap()
            .generation,
        2
    );
    assert_eq!(launcher.retained_generations().unwrap(), vec![1, 2]);
    launcher
        .install_launcher_binary(&temp.path().join("hook-2"))
        .unwrap();
    assert_eq!(
        fs::metadata(launcher.launcher_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn corrupt_generation_registry_is_not_overwritten_on_publish() {
    let temp = TempDir::new().unwrap();
    let launcher = StableLauncher::open(temp.path().join("install")).unwrap();
    let generation = |number| {
        let executable = temp.path().join(format!("hook-{number}"));
        let runtime_snapshot = temp.path().join(format!("snapshot-{number}"));
        fs::write(&executable, b"binary").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&runtime_snapshot, b"snapshot").unwrap();
        fs::set_permissions(&runtime_snapshot, fs::Permissions::from_mode(0o600)).unwrap();
        HookGeneration {
            generation: number,
            protocol_version: 1,
            executable,
            runtime_snapshot,
            compatible: true,
        }
    };
    launcher.publish_generation(generation(1)).unwrap();
    let registry = temp.path().join("install/generations.json");
    let corrupt = b"{not-valid-json";
    fs::write(&registry, corrupt).unwrap();
    assert!(launcher.publish_generation(generation(2)).is_err());
    assert_eq!(fs::read(registry).unwrap(), corrupt);
}

#[test]
fn hook_input_is_closed_bounded_and_carries_explicit_identity() {
    let input = CaptureHookInput {
        input_version: CAPTURE_HOOK_INPUT_VERSION,
        spool_record_id: Some("record-a".into()),
        source_observation_id_hint: None,
        source_instance_id: "source-instance-a".into(),
        source_revision: "revision-a".into(),
        source_record_identity: Some("record-a".into()),
        identity_strength: Some(IdentityStrength::StableSourceSequence),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        adapter_manifest_ref: "adapter-manifest-a".into(),
        eligible_event_manifest_ref: "eligible-events-a".into(),
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        source_ref: "source-a".into(),
        session_id: "session-a".into(),
        turn_id: Some("turn-a".into()),
        tool_use_id: Some("tool-a".into()),
        event_kind: HookEventKind::PostToolUse,
        correlation: unavailable_correlation(),
        scope_effect_claims: Vec::new(),
        source_sequence: 9,
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        event_time_us: Some(1),
        payload: "payload".into(),
    };
    let bytes = input.to_json().unwrap();
    assert_eq!(CaptureHookInput::from_json(&bytes).unwrap(), input);
    let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["unknown"] = true.into();
    assert!(CaptureHookInput::from_json(&serde_json::to_vec(&json).unwrap()).is_err());
}
