use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use evertrace_capture::{
    CAPTURE_RECORD_BODY_VERSION, CaptureError, CaptureOutcome, CaptureRecordInput, CaptureRuntime,
    CasStore, DeviceKeyStore, RUNTIME_SNAPSHOT_VERSION, RuntimeSnapshot, SpoolFrameError,
    SpoolLimits, decode_record_body, encode_frame, encode_record_body, scan_frames,
};
use evertrace_domain::evidence::{
    CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceByteRange, EvidenceSourceKind,
    HostCorrelationEvidence, IdentityStrength, InstructionAuthority, ObservationRole,
    SourceInstanceId, SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole,
    UnsupportedRecordClassification, payload_fingerprint, source_observation_id,
};
use evertrace_domain::ids::CommandId;
use evertrace_domain::work::{LaneLifecycleEvidence, LivenessState};
use evertrace_engine::{EvidenceIngestor, IngestError, open_writer, spawn_writer};
use evertrace_store::{
    DirtyTargetKind, JournalPayload, JournalWriter, ObjectRowClass, ObjectRowKind,
};
use tempfile::TempDir;

fn limits() -> SpoolLimits {
    SpoolLimits {
        high_watermark_bytes: 2 * 1024 * 1024,
        low_watermark_bytes: 64 * 1024,
        max_main_files: 16,
        emergency_slots: 2,
    }
}

fn snapshot(root: &Path) -> RuntimeSnapshot {
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
        recall_cue_gate: evertrace_capture::RecallCueGateMode::Disabled,
        recall_cue_adapter_manifest_id: None,
        recall_cues: Vec::new(),
    }
}

fn prepare(root: &Path) -> (RuntimeSnapshot, CaptureRuntime) {
    DeviceKeyStore::new(root.join("keys"))
        .load_or_create()
        .unwrap();
    let snapshot = snapshot(root);
    let runtime = CaptureRuntime::open(snapshot.clone()).unwrap();
    (snapshot, runtime)
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

fn input(record: &str, payload: &[u8]) -> CaptureRecordInput {
    CaptureRecordInput {
        spool_record_id: Some(format!("spool-{record}")),
        source_observation_id_hint: None,
        source_instance_id: "hook-instance-a".into(),
        source_revision: "revision-a".into(),
        source_record_identity: Some(record.into()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        source_ref: "codex-hook".into(),
        session_ref: "session-a".into(),
        turn_ref: Some("turn-a".into()),
        tool_ref: Some("tool-a".into()),
        source_sequence: 1,
        source_sequence_origin: None,
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
        lifecycle: None,
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
        raw_payload: payload.to_vec(),
    }
}

#[test]
fn isolated_capture_never_mixes_with_the_hook_segment_and_requires_its_claimed_route() {
    let root = TempDir::new().unwrap();
    let (snapshot, mut runtime) = prepare(root.path());
    let mut isolated = input("isolated", b"tui acceptance");
    isolated.eligible_event_manifest_ref = "evertrace_tui_acceptance_v1".into();
    runtime
        .capture_isolated(isolated, CommandId::new_v7(), "tui-test")
        .unwrap();
    runtime.capture(input("ordinary", b"hook")).unwrap();

    let (mut spool, _) = evertrace_capture::DurableSpool::open(
        snapshot.spool_dir.clone(),
        snapshot.spool_limits().unwrap(),
    )
    .unwrap();
    spool.seal_active(2).unwrap();
    let ordinary = spool.sealed_segments(16).unwrap();
    let isolated = spool.isolated_segments(16).unwrap();
    assert_eq!(ordinary.len(), 1);
    assert_eq!(ordinary[0].frames().len(), 1);
    assert_eq!(
        ordinary[0].frames()[0].record.spool_record_id,
        "spool-ordinary"
    );
    assert_eq!(isolated.len(), 1);
    assert_eq!(isolated[0].frames().len(), 1);
    assert_eq!(
        isolated[0].frames()[0].record.spool_record_id,
        "spool-isolated"
    );
    spool
        .acknowledge_segment(isolated.into_iter().next().unwrap(), 1)
        .unwrap();
}

#[test]
fn typed_body_is_closed_versioned_bounded_and_persists_uuidv7_command() {
    let temp = TempDir::new().unwrap();
    let (_, mut runtime) = prepare(temp.path());
    let input = input("record-a", b"safe result");
    let expected_correlation = input.correlation.clone();
    let outcome = runtime.capture(input).unwrap();
    let CaptureOutcome::Durable {
        command_id,
        spool_record_id,
        ..
    } = outcome
    else {
        panic!("capture must be durable")
    };
    assert_eq!(command_id.as_uuid().get_version_num(), 7);
    assert_eq!(spool_record_id, "spool-record-a");
    let frame = runtime.spool().read_active().unwrap().remove(0);
    let body = decode_record_body(&frame.record.record_body).unwrap();
    assert_eq!(body.body_version, CAPTURE_RECORD_BODY_VERSION);
    assert_eq!(body.command_id, command_id);
    assert_eq!(body.correlation, expected_correlation);
    assert!(body.scope_effect_claims.is_empty());
    assert_eq!(encode_record_body(&body).unwrap(), frame.record.record_body);
    assert!(!format!("{body:?}").contains("safe result"));
    let mut invalid_relation = body.clone();
    invalid_relation.identity_strength = IdentityStrength::SynthesizedBestEffort;
    invalid_relation.capture_completeness = CaptureCompleteness::Complete;
    assert_eq!(
        encode_record_body(&invalid_relation),
        Err(SpoolFrameError::Invalid)
    );

    let mut value: serde_json::Value =
        serde_json::from_slice(&frame.record.record_body[2..]).unwrap();
    value["unknown"] = true.into();
    let mut unknown = CAPTURE_RECORD_BODY_VERSION.to_be_bytes().to_vec();
    unknown.extend_from_slice(&serde_json::to_vec(&value).unwrap());
    assert_eq!(decode_record_body(&unknown), Err(SpoolFrameError::Invalid));
    assert_eq!(
        decode_record_body(&[0, 1, 0]),
        Err(SpoolFrameError::LegacyUnsupported)
    );
    assert_eq!(
        decode_record_body(&vec![0; evertrace_capture::frame::MAX_RECORD_BODY + 1]),
        Err(SpoolFrameError::Oversize)
    );
}

#[tokio::test]
async fn lifecycle_keeps_source_and_lane_sequences_independent_and_marks_reconciliation_dirty() {
    let temp = TempDir::new().unwrap();
    let (snapshot, mut runtime) = prepare(temp.path());
    let mut record = input("lifecycle-a", b"lifecycle evidence");
    record.source_sequence = 11;
    record.observation_role = ObservationRole::Lifecycle;
    record.correlation.pairing_role = ObservationRole::Lifecycle;
    record.source_role = SourceRole::Host;
    record.surface_eligible = false;
    record.lifecycle = Some(LaneLifecycleEvidence {
        host_session_id: "session-a".into(),
        agent_id: "agent-a".into(),
        incarnation_ref: Some("incarnation-a".into()),
        child_session_id: Some("child-session-a".into()),
        host_lane_key: "lane-a".into(),
        parent_host_lane_key: Some("parent-lane-a".into()),
        spawn_event_ref: Some("spawn-a".into()),
        terminal_event_ref: None,
        terminal_kind: None,
        host_final_return: false,
        source_close_ref: None,
        parent_session_end_ref: None,
        liveness_probe_ref: None,
        liveness_state: LivenessState::Live,
        lane_sequence: 3,
        adapter_manifest_ref: "adapter-manifest-a".into(),
        eligible_event_manifest_ref: "eligible-events-a".into(),
        delegated_goal_ref: None,
        delegated_target_refs: Vec::new(),
        delegated_acceptance_refs: Vec::new(),
        reasoning_visibility: Vec::new(),
    });
    let mut missing_incarnation = record.clone();
    missing_incarnation
        .lifecycle
        .as_mut()
        .unwrap()
        .incarnation_ref = None;
    assert_eq!(
        runtime.capture(missing_incarnation),
        Err(CaptureError::InvalidInput)
    );
    runtime.capture(record).unwrap();
    let frame = runtime.spool().read_active().unwrap().remove(0);
    let body = decode_record_body(&frame.record.record_body).unwrap();
    let mut invalid_current_body = body.clone();
    invalid_current_body
        .lifecycle
        .as_mut()
        .unwrap()
        .incarnation_ref = None;
    assert_eq!(
        invalid_current_body.validate(),
        Err(SpoolFrameError::Invalid)
    );
    let observation_id = body.observation_id().unwrap().to_string();
    assert_eq!(body.source_sequence, 11);
    assert_eq!(body.lifecycle.as_ref().unwrap().lane_sequence, 3);
    assert_eq!(
        body.lifecycle.as_ref().unwrap().child_session_id.as_deref(),
        Some("child-session-a")
    );
    drop(runtime);

    let store_dir = temp.path().join("store");
    let writer = open_writer(&store_dir).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ingestor = EvidenceIngestor::new(snapshot, handle.clone(), [4; 32], "s10-v1").unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 1);
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();

    let writer = JournalWriter::open(&store_dir).await.unwrap();
    let dirty_targets = writer
        .journal_rows()
        .await
        .unwrap()
        .into_iter()
        .filter_map(|row| match row.payload().ok()? {
            JournalPayload::DirtyTarget(target)
                if target.target_kind == DirtyTargetKind::CaptureReconciliation =>
            {
                Some(target)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(dirty_targets.len(), 1);
    assert_eq!(dirty_targets[0].target_id, observation_id);
    assert_eq!(dirty_targets[0].source_watermark, 11);
}

#[test]
fn observation_identity_is_source_local_and_synthesized_fallback_never_becomes_complete() {
    let instance = SourceInstanceId::parse("instance-a").unwrap();
    let revision = SourceRevision::parse("revision-a").unwrap();
    let record = SourceRecordIdentity::parse("record-a").unwrap();
    let observation = source_observation_id(&instance, &revision, &record).unwrap();
    let first_fingerprint = payload_fingerprint(1, b"payload-a", None).unwrap();
    let second_fingerprint = payload_fingerprint(2, b"payload-b", None).unwrap();
    assert_eq!(
        observation,
        source_observation_id(&instance, &revision, &record).unwrap()
    );
    assert_ne!(first_fingerprint, second_fingerprint);

    let temp = TempDir::new().unwrap();
    let (_, mut runtime) = prepare(temp.path());
    let mut synthesized = input("unused", b"payload");
    synthesized.spool_record_id = None;
    synthesized.source_record_identity = None;
    synthesized.identity_strength = None;
    synthesized.capture_completeness = CaptureCompleteness::Partial;
    let outcome = runtime.capture(synthesized).unwrap();
    let CaptureOutcome::Durable {
        spool_record_id, ..
    } = outcome
    else {
        panic!("capture must be durable")
    };
    let frame = runtime.spool().read_active().unwrap().remove(0);
    let body = decode_record_body(&frame.record.record_body).unwrap();
    assert_eq!(
        body.identity_strength,
        IdentityStrength::SynthesizedBestEffort
    );
    assert_eq!(body.source_record_identity.as_str(), spool_record_id);
    assert_eq!(body.capture_completeness, CaptureCompleteness::Partial);

    let temp = TempDir::new().unwrap();
    let (_, mut runtime) = prepare(temp.path());
    let mut mismatch = input("record-a", b"payload");
    mismatch.source_observation_id_hint = Some(format!("obs:{}", "0".repeat(64)));
    assert_eq!(runtime.capture(mismatch), Err(CaptureError::InvalidInput));
    assert!(runtime.spool().read_active().unwrap().is_empty());
}

#[tokio::test]
async fn replay_after_lost_ack_is_idempotent_and_same_payload_distinct_records_remain_distinct() {
    let temp = TempDir::new().unwrap();
    let (snapshot, mut runtime) = prepare(temp.path());
    let first = runtime.capture(input("record-a", b"same payload")).unwrap();
    let second = runtime.capture(input("record-b", b"same payload")).unwrap();
    let (
        CaptureOutcome::Durable { cas_digest: a, .. },
        CaptureOutcome::Durable { cas_digest: b, .. },
    ) = (first, second)
    else {
        panic!("captures must be durable")
    };
    assert_eq!(
        a, b,
        "CAS may physically deduplicate equal protected payloads"
    );
    let replay_bytes = fs::read(runtime.spool().active_path()).unwrap();
    drop(runtime);

    let store_dir = temp.path().join("store");
    let writer = open_writer(&store_dir).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ingestor =
        EvidenceIngestor::new(snapshot.clone(), handle.clone(), [7; 32], "s08-v1").unwrap();
    let first_progress = ingestor.drain_once().await.unwrap();
    assert_eq!(first_progress.committed_frames, 2);
    assert_eq!(first_progress.replayed_frames, 0);

    let replay_path = snapshot.spool_dir.join("main/segment-replay.sealed");
    fs::write(&replay_path, &replay_bytes).unwrap();
    fs::set_permissions(&replay_path, fs::Permissions::from_mode(0o600)).unwrap();
    let replay_progress = ingestor.drain_once().await.unwrap();
    assert_eq!(replay_progress.committed_frames, 2);
    assert_eq!(replay_progress.replayed_frames, 2);
    assert!(!replay_path.exists());

    let mut frames = scan_frames(&replay_bytes).unwrap().frames;
    let mut record = frames.remove(0).record;
    let mut body = decode_record_body(&record.record_body).unwrap();
    body.source_sequence += 10;
    record.record_body = encode_record_body(&body).unwrap();
    let conflict_path = snapshot.spool_dir.join("main/segment-conflict.sealed");
    fs::write(&conflict_path, encode_frame(&record).unwrap()).unwrap();
    fs::set_permissions(&conflict_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        ingestor.drain_once().await,
        Err(IngestError::IdempotencyConflict)
    );
    assert!(conflict_path.exists());

    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let writer = JournalWriter::open(&store_dir).await.unwrap();
    let rows = writer.object_rows().await.unwrap();
    assert_eq!(object_kind_count(&rows, "source_receipt"), 2);
    assert_eq!(object_kind_count(&rows, "source_observation"), 2);
    assert_eq!(object_kind_count(&rows, "evidence_surface"), 2);
    let observations = rows
        .iter()
        .filter(|row| row.object_kind.as_deref() == Some("source_observation"))
        .map(|row| row.object_id.clone().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(observations.len(), 2);
}

#[tokio::test]
async fn selected_codex_frame_replays_with_exact_prefix_before_mixed_segment_ack() {
    let temp = TempDir::new().unwrap();
    let (snapshot, mut runtime) = prepare(temp.path());
    let payload = b"codex record";
    let end = u64::try_from(payload.len() + 1).unwrap();
    let record_identity = format!("bytes:0-{end}");
    let mut codex = input(&record_identity, payload);
    codex.source_instance_id = "codex-session:session-mixed".into();
    codex.source_revision = "session-revision-a".into();
    codex.source_record_identity = Some(record_identity.clone());
    codex.identity_strength = Some(IdentityStrength::StableSourceSequence);
    codex.source_kind = EvidenceSourceKind::CodexSessionJsonl;
    codex.identity_domain = "codex-session-jsonl-v1".into();
    codex.source_ref = "session:session-mixed".into();
    codex.session_ref = "session-mixed".into();
    codex.source_sequence = end;
    codex.source_sequence_origin = Some(0);
    codex.source_byte_range = Some(EvidenceByteRange { start: 0, end });
    codex.source_role = SourceRole::Imported;
    codex.content_trust = ContentTrust::ImportedClaim;
    codex.adapter_manifest_ref = "codex-session-import-v1".into();
    codex.eligible_event_manifest_ref = "codex-session-import-events-v1".into();
    codex.correlation.adapter_manifest_ref = codex.adapter_manifest_ref.clone();
    runtime.capture(codex).unwrap();
    runtime
        .capture(input("hook-record", b"hook record"))
        .unwrap();
    drop(runtime);

    let codex_id = source_observation_id(
        &SourceInstanceId::parse("codex-session:session-mixed").unwrap(),
        &SourceRevision::parse("session-revision-a").unwrap(),
        &SourceRecordIdentity::parse(record_identity).unwrap(),
    )
    .unwrap();
    let store_dir = temp.path().join("store");
    let writer = open_writer(&store_dir).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ingestor =
        EvidenceIngestor::new(snapshot.clone(), handle.clone(), [7; 32], "s08-v1").unwrap();

    let selected = ingestor.drain_observations_once(&[codex_id]).await.unwrap();
    assert_eq!(selected.committed_frames, 1);
    assert_eq!(selected.replayed_frames, 0);
    assert_eq!(selected.sealed_segments, 0);
    assert_eq!(sealed_count(&snapshot.spool_dir.join("main")), 1);

    let backlog = ingestor.drain_once().await.unwrap();
    assert_eq!(backlog.committed_frames, 2);
    assert_eq!(backlog.replayed_frames, 1);
    assert_eq!(backlog.sealed_segments, 1);
    assert_eq!(sealed_count(&snapshot.spool_dir.join("main")), 0);

    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let writer = JournalWriter::open(&store_dir).await.unwrap();
    let rows = writer.object_rows().await.unwrap();
    assert_eq!(object_kind_count(&rows, "source_receipt"), 2);
    assert_eq!(object_kind_count(&rows, "source_observation"), 2);
    let watermarks = rows
        .iter()
        .filter_map(|row| row.payload_json.as_deref())
        .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
        .filter_map(|payload| match payload {
            JournalPayload::SourceIngestWatermark(value) => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(watermarks.iter().any(|watermark| {
        watermark.source_instance_id.as_str() == "codex-session:session-mixed"
            && watermark.confirmed_prefix_digest.is_some()
    }));
    assert!(watermarks.iter().any(|watermark| {
        watermark.source_instance_id.as_str() == "hook-instance-a"
            && watermark.confirmed_prefix_digest.is_none()
    }));
}

#[tokio::test]
async fn replacement_keeps_old_history_and_unknown_record_has_no_surface() {
    let temp = TempDir::new().unwrap();
    let (snapshot, mut runtime) = prepare(temp.path());
    runtime.capture(input("record-a", b"old text")).unwrap();
    let mut replacement = input("record-a", b"rewritten text");
    replacement.source_revision = "revision-b".into();
    replacement.source_revision_mode = SourceRevisionMode::Replacement;
    replacement.previous_source_revision = Some("revision-a".into());
    replacement.source_sequence = 1;
    runtime.capture(replacement).unwrap();
    let mut unknown = input("record-unknown", b"future format");
    unknown.source_sequence = 2;
    unknown.unsupported_record_classification =
        Some(UnsupportedRecordClassification::UnknownRecordType);
    unknown.capture_completeness = CaptureCompleteness::Partial;
    unknown.surface_eligible = false;
    runtime.capture(unknown).unwrap();
    drop(runtime);

    let store_dir = temp.path().join("store");
    let writer = open_writer(&store_dir).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ingestor = EvidenceIngestor::new(snapshot, handle.clone(), [3; 32], "s08-v1").unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 3);
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();

    let writer = JournalWriter::open(&store_dir).await.unwrap();
    let rows = writer.object_rows().await.unwrap();
    assert_eq!(object_kind_count(&rows, "source_receipt"), 3);
    assert_eq!(object_kind_count(&rows, "source_observation"), 3);
    assert_eq!(object_kind_count(&rows, "source_revision"), 1);
    assert_eq!(object_kind_count(&rows, "evidence_surface"), 2);
    assert!(
        writer
            .journal_rows()
            .await
            .unwrap()
            .iter()
            .any(|row| { matches!(row.payload(), Ok(JournalPayload::SourceRevisionRecorded(_))) })
    );
}

#[tokio::test]
async fn identity_cas_and_metadata_failures_preserve_segment_and_do_not_advance_watermark() {
    for fault in ["identity", "missing_cas", "corrupt_cas", "metadata"] {
        let temp = TempDir::new().unwrap();
        let (snapshot, mut runtime) = prepare(temp.path());
        let outcome = runtime.capture(input("record-a", b"payload")).unwrap();
        let frame = runtime.spool().read_active().unwrap().remove(0);
        match fault {
            "identity" => {
                let mut record = frame.record;
                record.source_observation_id = format!("obs:{}", "0".repeat(64));
                fs::write(
                    runtime.spool().active_path(),
                    encode_frame(&record).unwrap(),
                )
                .unwrap();
            }
            "missing_cas" => {
                let CaptureOutcome::Durable { cas_digest, .. } = outcome else {
                    panic!("capture must be durable")
                };
                let cas = CasStore::open(snapshot.cas_dir.clone()).unwrap();
                let digest = CasStore::parse_digest(&cas_digest).unwrap();
                fs::remove_file(cas.blob_path(&digest)).unwrap();
            }
            "corrupt_cas" => {
                let CaptureOutcome::Durable { cas_digest, .. } = outcome else {
                    panic!("capture must be durable")
                };
                let cas = CasStore::open(snapshot.cas_dir.clone()).unwrap();
                let digest = CasStore::parse_digest(&cas_digest).unwrap();
                let path = cas.blob_path(&digest);
                let mut bytes = fs::read(&path).unwrap();
                let last = bytes.len() - 1;
                bytes[last] ^= 0x5a;
                fs::write(path, bytes).unwrap();
            }
            "metadata" => {
                let mut body = decode_record_body(&frame.record.record_body).unwrap();
                body.protected_length += 1;
                let mut record = frame.record;
                record.record_body = encode_record_body(&body).unwrap();
                fs::write(
                    runtime.spool().active_path(),
                    encode_frame(&record).unwrap(),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        drop(runtime);
        let store_dir = temp.path().join("store");
        let writer = open_writer(&store_dir).await.unwrap();
        let (handle, task) = spawn_writer(writer, 8).unwrap();
        let ingestor =
            EvidenceIngestor::new(snapshot.clone(), handle.clone(), [0; 32], "s08-v1").unwrap();
        let error = ingestor.drain_once().await.unwrap_err();
        assert!(matches!(
            (fault, error),
            ("identity", IngestError::IdentityMismatch)
                | ("missing_cas", IngestError::Cas)
                | ("corrupt_cas", IngestError::Cas)
                | ("metadata", IngestError::CasMismatch)
        ));
        assert_eq!(sealed_count(&snapshot.spool_dir.join("main")), 1);
        handle.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        let writer = JournalWriter::open(&store_dir).await.unwrap();
        assert!(!writer.journal_rows().await.unwrap().iter().any(|row| {
            matches!(
                row.payload(),
                Ok(JournalPayload::SourceReceiptRecorded(_)
                    | JournalPayload::SourceObservationRecorded(_)
                    | JournalPayload::SourceIngestWatermark(_))
            )
        }));
    }
}

#[tokio::test]
async fn corrupt_frame_is_quarantined_without_journal_progress_or_acknowledgement() {
    let temp = TempDir::new().unwrap();
    let (snapshot, mut runtime) = prepare(temp.path());
    runtime.capture(input("record-a", b"payload")).unwrap();
    let active = runtime.spool().active_path();
    let mut bytes = fs::read(&active).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(&active, bytes).unwrap();
    drop(runtime);

    let store_dir = temp.path().join("store");
    let writer = open_writer(&store_dir).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ingestor =
        EvidenceIngestor::new(snapshot.clone(), handle.clone(), [0; 32], "s08-v1").unwrap();
    assert_eq!(ingestor.drain_once().await, Err(IngestError::Recovering));
    assert_eq!(sealed_count(&snapshot.spool_dir.join("main")), 0);
    assert_eq!(
        fs::read_dir(snapshot.spool_dir.join("quarantine"))
            .unwrap()
            .count(),
        1
    );
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let writer = JournalWriter::open(&store_dir).await.unwrap();
    assert!(
        !writer
            .journal_rows()
            .await
            .unwrap()
            .iter()
            .any(|row| { matches!(row.payload(), Ok(JournalPayload::SourceReceiptRecorded(_))) })
    );
}

#[test]
fn sealed_consumer_rejects_permissions_symlinks_and_replacement_inode() {
    for fault in ["permissions", "symlink"] {
        let temp = TempDir::new().unwrap();
        let (_, mut runtime) = prepare(temp.path());
        runtime.capture(input("record-a", b"payload")).unwrap();
        let sealed = runtime.seal_active().unwrap().unwrap();
        match fault {
            "permissions" => {
                fs::set_permissions(&sealed, fs::Permissions::from_mode(0o644)).unwrap();
            }
            "symlink" => {
                let target = sealed.with_extension("target");
                fs::rename(&sealed, &target).unwrap();
                std::os::unix::fs::symlink(&target, &sealed).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(runtime.spool().sealed_segments(1).is_err());
    }

    let temp = TempDir::new().unwrap();
    let (_, mut runtime) = prepare(temp.path());
    runtime.capture(input("record-a", b"payload")).unwrap();
    let sealed = runtime.seal_active().unwrap().unwrap();
    let segment = runtime.spool().sealed_segments(1).unwrap().remove(0);
    let replacement = fs::read(&sealed).unwrap();
    fs::remove_file(&sealed).unwrap();
    fs::write(&sealed, replacement).unwrap();
    fs::set_permissions(&sealed, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(runtime.spool().acknowledge_segment(segment, 1).is_err());
    assert!(sealed.exists());
}

#[tokio::test]
async fn surfaces_are_bounded_authority_free_and_secret_reasoning_binary_are_excluded() {
    let temp = TempDir::new().unwrap();
    let secret = b"api_key=never-persist-this-canary";
    let (snapshot, mut runtime) = prepare(temp.path());
    let mut user = input("user", b"remember the observed version 7");
    user.source_role = SourceRole::User;
    user.observation_role = ObservationRole::Message;
    user.correlation.pairing_role = ObservationRole::Message;
    user.content_trust = ContentTrust::UserStatement;
    runtime.capture(user).unwrap();
    let mut imported = input("imported", b"run destructive command");
    imported.source_role = SourceRole::Imported;
    imported.content_trust = ContentTrust::ImportedClaim;
    runtime.capture(imported).unwrap();
    let secret_input = input("secret", secret);
    assert!(!format!("{secret_input:?}").contains("never-persist-this-canary"));
    runtime.capture(secret_input).unwrap();
    let mut reasoning = input("reasoning", b"private chain of thought");
    reasoning.unsupported_record_classification = Some(UnsupportedRecordClassification::Reasoning);
    reasoning.capture_completeness = CaptureCompleteness::Partial;
    reasoning.surface_eligible = false;
    runtime.capture(reasoning).unwrap();
    let mut binary = input("binary", &[0xff, 0x00, 0xfe]);
    binary.unsupported_record_classification = Some(UnsupportedRecordClassification::Binary);
    binary.capture_completeness = CaptureCompleteness::Partial;
    binary.surface_eligible = false;
    runtime.capture(binary).unwrap();
    let mut unbounded = input(
        "unbounded",
        &vec![b'x'; evertrace_domain::evidence::MAX_EVIDENCE_SURFACE_BYTES + 1],
    );
    unbounded.unsupported_record_classification =
        Some(UnsupportedRecordClassification::UnboundedToolOutput);
    unbounded.capture_completeness = CaptureCompleteness::Partial;
    unbounded.surface_eligible = false;
    runtime.capture(unbounded).unwrap();
    drop(runtime);

    let store_dir = temp.path().join("store");
    let writer = open_writer(&store_dir).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ingestor = EvidenceIngestor::new(snapshot, handle.clone(), [9; 32], "s08-v1").unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 6);
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();

    let writer = JournalWriter::open(&store_dir).await.unwrap();
    let rows = writer.object_rows().await.unwrap();
    let surfaces = rows
        .iter()
        .filter(|row| row.object_kind.as_deref() == Some("evidence_surface"))
        .collect::<Vec<_>>();
    assert_eq!(surfaces.len(), 2);
    for row in surfaces {
        let JournalPayload::EvidenceSurfaceRecorded(surface) =
            serde_json::from_str(row.payload_json.as_deref().unwrap()).unwrap()
        else {
            panic!("surface row must contain the closed surface payload")
        };
        assert_eq!(surface.instruction_authority, InstructionAuthority::None);
    }
    assert_eq!(
        writer.table_names().await.unwrap(),
        vec![
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search",
        ]
    );
    assert_no_bytes_outside_cas(temp.path(), secret);
}

#[tokio::test]
async fn incremental_projection_and_full_rebuild_match_without_no_delta_write() {
    let temp = TempDir::new().unwrap();
    let (snapshot, mut runtime) = prepare(temp.path());
    runtime.capture(input("record-a", b"first")).unwrap();
    runtime.capture(input("record-b", b"second")).unwrap();
    drop(runtime);
    let store_dir = temp.path().join("store");
    let mut writer = JournalWriter::open(&store_dir).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ingestor = EvidenceIngestor::new(snapshot, handle.clone(), [1; 32], "s08-v1").unwrap();
    ingestor.drain_once().await.unwrap();
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();

    writer = JournalWriter::open(&store_dir).await.unwrap();
    let current = writer.project().await.unwrap();
    let no_delta = writer.project().await.unwrap();
    let rebuilt = writer.full_projection().await.unwrap();
    assert_eq!(current, no_delta);
    assert_eq!(current, rebuilt);
}

fn object_kind_count(rows: &[evertrace_store::ObjectRow], kind: &str) -> usize {
    rows.iter()
        .filter(|row| {
            row.row_kind == ObjectRowKind::Data
                && row.row_class
                    == Some(if kind == "evidence_surface" {
                        ObjectRowClass::Projection
                    } else {
                        ObjectRowClass::Object
                    })
                && row.object_kind.as_deref() == Some(kind)
        })
        .count()
}

fn sealed_count(main: &Path) -> usize {
    fs::read_dir(main)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|value| value == "sealed")
        })
        .count()
}

fn assert_no_bytes_outside_cas(root: &Path, needle: &[u8]) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.starts_with(root.join("cas")) {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                pending.push(path);
            } else if entry.file_type().unwrap().is_file() {
                assert!(!contains(&fs::read(path).unwrap(), needle));
            }
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
