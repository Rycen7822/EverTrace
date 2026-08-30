use std::{collections::BTreeSet, str::FromStr};

use evertrace_codex::{
    HostProbeReport,
    hook_input::{CAPTURE_HOOK_INPUT_VERSION, CaptureHookInput, HookEventKind},
    probe::{
        EvidenceSourceKind as ProbeEvidenceSourceKind, GateResult, NormalizationCanaryEvidence,
    },
};
use evertrace_domain::{
    evidence::{
        CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
        CorrelationField, CorrelationFieldClaim, CorrelationStrength, EffectRole,
        EvidenceByteRange, EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength,
        NormalizationState, ObservationRole, PairingState, ScopeEffectClaim, SourceArchiveMode,
        SourceInstanceId, SourceObservation, SourceReceipt, SourceRecordIdentity, SourceRevision,
        SourceRevisionMode, SourceRole, host_occurrence_id_for_exact, payload_fingerprint,
        source_observation_id, source_receipt_id,
    },
    ids::{CommandId, DuplicateGroupId, RepositoryId, WorktreeId, WorktreeSnapshotId},
};
use evertrace_engine::PhysicalNormalizer;
use evertrace_store::{
    CompatibilityStore, DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft,
    JournalPayload, JournalWriter, OBJECTS_TABLE, SourceIngestWatermark, StoreError,
    reduce_journal,
    relations::{PhysicalRelationKind, build_physical_relation_rows},
};
use tempfile::TempDir;

#[path = "../src/probe.rs"]
mod probe_fixture;

const CONFIG_HASH: [u8; 32] = [0x91; 32];
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn exact_correlation(source: &str, role_family: CanonicalEventFamily) -> HostCorrelationEvidence {
    let fields = [
        CorrelationField::HostInstanceId,
        CorrelationField::HostTraceLineageId,
        CorrelationField::HostLaneKey,
        CorrelationField::CanonicalEventFamily,
        CorrelationField::NativeRequestId,
        CorrelationField::PhysicalExecutionOrdinal,
    ];
    HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: Some("host-a".into()),
        host_trace_lineage_id: Some("trace-a".into()),
        host_lane_key: Some("lane-a".into()),
        canonical_event_family: Some(role_family),
        native_request_id: Some("request-a".into()),
        physical_execution_ordinal: Some(1),
        pairing_role: ObservationRole::Result,
        field_provenance: fields
            .into_iter()
            .map(|field| CorrelationFieldClaim {
                field,
                source_ref: source.into(),
                evidence_ref: format!("canary-{source}"),
            })
            .collect(),
        adapter_manifest_ref: "adapter-manifest-a".into(),
        adapter_revision: 1,
        strong_gate_receipt_ref: Some("strong-gate-a".into()),
        admission: CorrelationAdmission::ExactCapable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    }
}

fn nonexact_correlation(source: &str, admission: CorrelationAdmission) -> HostCorrelationEvidence {
    let mut value = exact_correlation(source, CanonicalEventFamily::Mutate);
    value.admission = admission;
    value.strong_gate_receipt_ref = None;
    value
}

fn observation(
    record: &str,
    role: ObservationRole,
    correlation: HostCorrelationEvidence,
    claims: Vec<ScopeEffectClaim>,
) -> (SourceReceipt, SourceObservation) {
    let mut correlation = correlation;
    correlation.pairing_role = role;
    let instance = SourceInstanceId::parse(format!("source-{record}")).unwrap();
    let revision = SourceRevision::parse("revision-1").unwrap();
    let record_identity = SourceRecordIdentity::parse(format!("record-{record}")).unwrap();
    let observation_id = source_observation_id(&instance, &revision, &record_identity).unwrap();
    let receipt_id = source_receipt_id(&instance, &revision, &record_identity).unwrap();
    let receipt = SourceReceipt {
        source_receipt_id: receipt_id,
        source_observation_id: observation_id,
        source_instance_id: instance.clone(),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        source_ref: format!("source-ref-{record}"),
        source_session_ref: "session-a".into(),
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
        observation_role: role,
        unsupported_record_classification: None,
        capture_completeness: CaptureCompleteness::Complete,
        archive_mode: SourceArchiveMode::Exact,
        cas_ref: DIGEST.into(),
        protected_length: 1,
        original_length: 1,
        protected_secret_digest: None,
        redaction_spans: Vec::new(),
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-manifest-a".into(),
        eligible_event_manifest_ref: "eligible-events-a".into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        detector_revision: 1,
        redaction_revision: 1,
        protection_key_generation: 1,
        event_time_us: 1,
        recorded_at_us: 1,
        lifecycle: None,
    };
    let fingerprint = payload_fingerprint(1, b"x", None).unwrap();
    let observation = SourceObservation {
        source_observation_id: observation_id,
        source_instance_id: instance,
        source_revision: revision,
        source_record_identity: record_identity,
        observation_role: role,
        identity_strength: IdentityStrength::StableNative,
        payload_fingerprint: evertrace_domain::evidence::hex(&fingerprint),
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
        scope_effect_claims: claims,
    };
    receipt.validate().unwrap();
    observation.validate().unwrap();
    (receipt, observation)
}

fn scope_claim(repository: RepositoryId, worktree: WorktreeId) -> ScopeEffectClaim {
    ScopeEffectClaim {
        effect_role: EffectRole::Mutate,
        repository_instance_id: Some(repository),
        worktree_instance_id: Some(worktree),
        pre_snapshot_id: Some(
            WorktreeSnapshotId::from_str("wts:01890f47-6a4a-7cc1-98b9-01890f476a31").unwrap(),
        ),
        post_snapshot_id: Some(
            WorktreeSnapshotId::from_str("wts:01890f47-6a4a-7cc1-98b9-01890f476a32").unwrap(),
        ),
        experiment_run_ids: Vec::new(),
        artifact_refs: Vec::new(),
        evidence_refs: Vec::new(),
    }
}

fn normalizer() -> PhysicalNormalizer {
    PhysicalNormalizer::new(1).unwrap()
}

#[test]
fn hook_input_rejects_raw_exact_and_preserves_complete_nonexact_correlation() {
    let repository = RepositoryId::from_str("repo:01890f47-6a4a-7cc1-98b9-01890f476a51").unwrap();
    let worktree_a = WorktreeId::from_str("wt:01890f47-6a4a-7cc1-98b9-01890f476a52").unwrap();
    let worktree_b = WorktreeId::from_str("wt:01890f47-6a4a-7cc1-98b9-01890f476a53").unwrap();
    let input = CaptureHookInput {
        input_version: CAPTURE_HOOK_INPUT_VERSION,
        spool_record_id: Some("spool-host-a".into()),
        source_observation_id_hint: None,
        source_instance_id: "hook-instance-a".into(),
        source_revision: "revision-a".into(),
        source_record_identity: Some("native-record-a".into()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        adapter_manifest_ref: "adapter-manifest-a".into(),
        eligible_event_manifest_ref: "eligible-events-a".into(),
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        source_ref: "hook-source-a".into(),
        session_id: "session-a".into(),
        turn_id: Some("turn-a".into()),
        tool_use_id: Some("tool-a".into()),
        event_kind: HookEventKind::PostToolUse,
        correlation: exact_correlation("hook-source-a", CanonicalEventFamily::Mutate),
        scope_effect_claims: vec![
            scope_claim(repository, worktree_a),
            scope_claim(repository, worktree_b),
        ],
        lifecycle: None,
        source_sequence: 7,
        source_sequence_origin: None,
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        event_time_us: Some(1),
        payload: "protected input".into(),
    };
    input.correlation.validate().unwrap();
    let raw_exact = serde_json::to_vec(&input).unwrap();
    assert!(CaptureHookInput::from_json(&raw_exact).is_err());
    assert!(input.validate().is_err());

    let mut nonexact = input;
    nonexact.correlation.admission = CorrelationAdmission::Ambiguous;
    assert!(nonexact.correlation.validate().is_err());
    nonexact.correlation.strong_gate_receipt_ref = None;

    let encoded = nonexact.to_json().unwrap();
    let parsed = CaptureHookInput::from_json(&encoded).unwrap();
    assert_eq!(parsed.correlation, nonexact.correlation);
    assert_eq!(parsed.correlation.field_provenance.len(), 6);
    assert!(parsed.correlation.exact_key().is_none());
    assert_eq!(parsed.scope_effect_claims.len(), 2);
}

#[test]
fn exact_cross_source_pairing_keeps_provenance_and_derives_one_operation() {
    let (_, intent) = observation(
        "hook-intent",
        ObservationRole::Intent,
        exact_correlation("hook", CanonicalEventFamily::Mutate),
        Vec::new(),
    );
    let (_, result) = observation(
        "session-result",
        ObservationRole::Result,
        exact_correlation("session", CanonicalEventFamily::Mutate),
        Vec::new(),
    );
    let snapshot = normalizer().normalize(&[intent, result], None).unwrap();
    assert_eq!(snapshot.occurrences.len(), 1);
    assert_eq!(snapshot.operations.len(), 1);
    assert_eq!(snapshot.occurrences[0].source_observation_refs.len(), 2);
    assert_eq!(snapshot.occurrences[0].field_provenance.len(), 12);
    assert_eq!(
        snapshot.occurrences[0].normalization_state,
        NormalizationState::Complemented
    );
    assert_eq!(snapshot.occurrences[0].pairing_state, PairingState::Paired);
    assert_eq!(snapshot.operations[0].pairing_state, PairingState::Paired);
    assert_eq!(
        snapshot.occurrences[0].host_occurrence_id,
        host_occurrence_id_for_exact(snapshot.occurrences[0].exact_key.as_ref().unwrap()).unwrap()
    );
}

#[test]
fn every_exact_identity_dimension_separates_physical_executions() {
    let dimensions: &[fn(&mut HostCorrelationEvidence)] = &[
        |value| value.host_instance_id = Some("host-b".into()),
        |value| value.host_trace_lineage_id = Some("trace-b".into()),
        |value| value.host_lane_key = Some("lane-b".into()),
        |value| value.canonical_event_family = Some(CanonicalEventFamily::Verify),
        |value| value.native_request_id = Some("request-b".into()),
        |value| value.physical_execution_ordinal = Some(2),
    ];
    for (index, change) in dimensions.iter().enumerate() {
        let first = observation(
            &format!("first-{index}"),
            ObservationRole::Result,
            exact_correlation("first", CanonicalEventFamily::Mutate),
            Vec::new(),
        )
        .1;
        let mut correlation = exact_correlation("second", CanonicalEventFamily::Mutate);
        change(&mut correlation);
        let second = observation(
            &format!("second-{index}"),
            ObservationRole::Result,
            correlation,
            Vec::new(),
        )
        .1;
        let snapshot = normalizer().normalize(&[first, second], None).unwrap();
        assert_eq!(snapshot.occurrences.len(), 2, "dimension {index}");
        assert_eq!(snapshot.operations.len(), 2, "dimension {index}");
    }
}

#[test]
fn nonexact_candidates_never_merge_and_partial_groups_require_explicit_evidence() {
    let mut ambiguous = nonexact_correlation("a", CorrelationAdmission::Ambiguous);
    let group = DuplicateGroupId::from_str("dup:01890f47-6a4a-7cc1-98b9-01890f476a40").unwrap();
    ambiguous.partial_correlation_ref = Some("native-partial-a".into());
    ambiguous.possible_duplicate_group_id = Some(group);
    let observations = [
        observation("ambiguous", ObservationRole::Result, ambiguous, Vec::new()).1,
        observation(
            "conflicted",
            ObservationRole::Result,
            nonexact_correlation("b", CorrelationAdmission::Conflicted),
            Vec::new(),
        )
        .1,
        observation(
            "unavailable",
            ObservationRole::Result,
            nonexact_correlation("c", CorrelationAdmission::Unavailable),
            Vec::new(),
        )
        .1,
    ];
    let snapshot = normalizer().normalize(&observations, None).unwrap();
    assert_eq!(snapshot.occurrences.len(), 3);
    assert_eq!(
        snapshot
            .occurrences
            .iter()
            .map(|value| value.correlation_strength)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            CorrelationStrength::Ambiguous,
            CorrelationStrength::Conflicted,
            CorrelationStrength::Unavailable,
        ])
    );
    assert_eq!(
        snapshot
            .occurrences
            .iter()
            .filter(|value| value.possible_duplicate_group_id.is_some())
            .count(),
        1
    );

    let mut invalid = nonexact_correlation("invalid", CorrelationAdmission::Ambiguous);
    invalid.possible_duplicate_group_id = Some(group);
    assert!(invalid.validate().is_err());

    let mut partial_a = nonexact_correlation("partial-a", CorrelationAdmission::Ambiguous);
    partial_a.partial_correlation_ref = Some("native-partial-conflict".into());
    partial_a.possible_duplicate_group_id = Some(group);
    let mut partial_b = nonexact_correlation("partial-b", CorrelationAdmission::Ambiguous);
    partial_b.partial_correlation_ref = Some("native-partial-conflict".into());
    partial_b.possible_duplicate_group_id = Some(group);
    partial_b.host_instance_id = Some("host-conflict".into());
    let conflict = normalizer()
        .normalize(
            &[
                observation("partial-a", ObservationRole::Result, partial_a, Vec::new()).1,
                observation("partial-b", ObservationRole::Result, partial_b, Vec::new()).1,
            ],
            None,
        )
        .unwrap();
    assert_eq!(conflict.occurrences.len(), 2);
    assert!(conflict.occurrences.iter().all(|value| {
        value.correlation_strength == CorrelationStrength::Conflicted
            && value.normalization_state == NormalizationState::NormalizationConflicted
    }));
}

#[test]
fn corroboration_conflict_and_unmatched_pairing_are_explicit() {
    let same_role = [
        observation(
            "a",
            ObservationRole::StateProbe,
            exact_correlation("a", CanonicalEventFamily::Observe),
            Vec::new(),
        )
        .1,
        observation(
            "b",
            ObservationRole::StateProbe,
            exact_correlation("b", CanonicalEventFamily::Observe),
            Vec::new(),
        )
        .1,
    ];
    let corroborated = normalizer().normalize(&same_role, None).unwrap();
    assert_eq!(
        corroborated.occurrences[0].normalization_state,
        NormalizationState::Corroborated
    );
    assert_eq!(
        corroborated.occurrences[0].pairing_state,
        PairingState::NotApplicable
    );

    let near_but_nonexact = [
        observation(
            "near-intent",
            ObservationRole::Intent,
            nonexact_correlation("intent", CorrelationAdmission::Ambiguous),
            Vec::new(),
        )
        .1,
        observation(
            "near-result",
            ObservationRole::Result,
            nonexact_correlation("result", CorrelationAdmission::Ambiguous),
            Vec::new(),
        )
        .1,
    ];
    let unmatched = normalizer().normalize(&near_but_nonexact, None).unwrap();
    assert_eq!(unmatched.occurrences.len(), 2);
    assert!(unmatched.occurrences.iter().all(|value| {
        matches!(
            value.pairing_state,
            PairingState::UnmatchedIntent | PairingState::UnmatchedResult
        )
    }));
}

#[test]
fn late_source_creates_successor_and_scope_does_not_change_physical_identity() {
    let repository = RepositoryId::from_str("repo:01890f47-6a4a-7cc1-98b9-01890f476a21").unwrap();
    let worktree_a = WorktreeId::from_str("wt:01890f47-6a4a-7cc1-98b9-01890f476a22").unwrap();
    let worktree_b = WorktreeId::from_str("wt:01890f47-6a4a-7cc1-98b9-01890f476a23").unwrap();
    let result = observation(
        "late-result",
        ObservationRole::Result,
        exact_correlation("result", CanonicalEventFamily::Mutate),
        vec![
            scope_claim(repository, worktree_a),
            scope_claim(repository, worktree_b),
        ],
    )
    .1;
    let first = normalizer()
        .normalize(std::slice::from_ref(&result), None)
        .unwrap();
    let intent = observation(
        "late-intent",
        ObservationRole::Intent,
        exact_correlation("intent", CanonicalEventFamily::Mutate),
        Vec::new(),
    )
    .1;
    let successor = normalizer()
        .normalize(&[result, intent], Some(&first))
        .unwrap();
    assert_eq!(first.occurrences[0].source_observation_refs.len(), 1);
    assert_eq!(successor.occurrences[0].source_observation_refs.len(), 2);
    assert_eq!(
        successor.occurrences[0].host_occurrence_id,
        first.occurrences[0].host_occurrence_id
    );
    assert_eq!(
        successor.operations[0].operation_id,
        first.operations[0].operation_id
    );
    assert_eq!(successor.occurrences[0].normalization_revision, 2);
    assert_eq!(successor.operations[0].operation_revision, 2);
    assert_eq!(successor.operations.len(), 1);
    assert_eq!(successor.scope_effects.len(), 2);
}

#[test]
fn message_and_lifecycle_do_not_create_operations() {
    let message = observation(
        "message",
        ObservationRole::Message,
        exact_correlation("message", CanonicalEventFamily::Message),
        Vec::new(),
    )
    .1;
    let lifecycle = observation(
        "lifecycle",
        ObservationRole::Lifecycle,
        exact_correlation("lifecycle", CanonicalEventFamily::Lifecycle),
        Vec::new(),
    )
    .1;
    let snapshot = normalizer().normalize(&[message, lifecycle], None).unwrap();
    assert_eq!(snapshot.occurrences.len(), 2);
    assert!(snapshot.operations.is_empty());
    assert!(snapshot.scope_effects.is_empty());
}

fn evidence_command(
    command_id: CommandId,
    receipt: SourceReceipt,
    observation: SourceObservation,
) -> JournalCommand {
    let watermark = SourceIngestWatermark {
        source_instance_id: receipt.source_instance_id.clone(),
        source_revision: receipt.source_revision.clone(),
        source_sequence: receipt.source_sequence,
        confirmed_prefix_digest: None,
    };
    let target = observation.source_observation_id.to_string();
    let payloads = vec![
        JournalPayload::SourceReceiptRecorded(Box::new(receipt)),
        JournalPayload::SourceObservationRecorded(Box::new(observation)),
        JournalPayload::SourceIngestWatermark(watermark),
        JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::EvidenceSurface,
            target_id: target.clone(),
            algorithm_revision: "physical-v1".into(),
            source_watermark: 1,
        }),
        JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::PhysicalNormalization,
            target_id: target,
            algorithm_revision: "physical-v1".into(),
            source_watermark: 1,
        }),
    ];
    JournalCommand::new(
        command_id,
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(1, CONFIG_HASH, "physical-v1", payload))
            .collect(),
    )
    .unwrap()
}

#[tokio::test]
async fn journal_projection_replay_relations_and_no_delta_are_closed() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let mut writer = JournalWriter::open(&root).await.unwrap();
    let (receipt_a, intent) = observation(
        "journal-intent",
        ObservationRole::Intent,
        exact_correlation("hook", CanonicalEventFamily::Mutate),
        Vec::new(),
    );
    let (receipt_b, result) = observation(
        "journal-result",
        ObservationRole::Result,
        exact_correlation("session", CanonicalEventFamily::Mutate),
        Vec::new(),
    );
    writer
        .commit(
            &evidence_command(CommandId::new_v7(), receipt_b, result.clone()),
            1,
        )
        .await
        .unwrap();
    writer.project().await.unwrap();

    let first_normalization = normalizer()
        .normalize(std::slice::from_ref(&result), None)
        .unwrap();
    writer
        .commit(
            &first_normalization
                .journal_command(CommandId::new_v7(), 2, CONFIG_HASH, "physical-v1")
                .unwrap(),
            2,
        )
        .await
        .unwrap();
    writer.project().await.unwrap();

    writer
        .commit(
            &evidence_command(CommandId::new_v7(), receipt_a, intent.clone()),
            3,
        )
        .await
        .unwrap();
    writer.project().await.unwrap();
    let normalized = normalizer()
        .normalize(&[intent, result], Some(&first_normalization))
        .unwrap();
    let normalization_command_id = CommandId::new_v7();
    let command = normalized
        .journal_command(normalization_command_id, 4, CONFIG_HASH, "physical-v1")
        .unwrap();
    let first = writer.commit(&command, 4).await.unwrap();
    assert!(!first.replayed);
    assert!(writer.commit(&command, 4).await.unwrap().replayed);
    let incremental = writer.project().await.unwrap();
    let full = reduce_journal(&writer.journal_rows().await.unwrap()).unwrap();
    assert_eq!(incremental, full);
    let journal = writer.journal_rows().await.unwrap();
    assert_eq!(
        journal
            .iter()
            .filter(|row| matches!(
                row.payload(),
                Ok(JournalPayload::HostOccurrenceNormalized(_))
            ))
            .count(),
        2
    );
    assert_eq!(
        first_normalization.operations[0].operation_id,
        normalized.operations[0].operation_id
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
    let reader = CompatibilityStore::connect_local(&root).await.unwrap();
    let objects = reader
        .connection()
        .open_table(OBJECTS_TABLE)
        .execute()
        .await
        .unwrap();
    let before = objects.version().await.unwrap();
    writer.project().await.unwrap();
    assert_eq!(objects.version().await.unwrap(), before);

    let relations = build_physical_relation_rows(
        &normalized.occurrences,
        &normalized.operations,
        &normalized.scope_effects,
    )
    .unwrap();
    assert_eq!(
        relations
            .iter()
            .filter(|row| row.kind == PhysicalRelationKind::SourceObservationToHostOccurrence)
            .count(),
        2
    );
    assert_eq!(
        relations
            .iter()
            .filter(|row| row.kind == PhysicalRelationKind::HostOccurrenceToOperation)
            .count(),
        1
    );

    let mut changed = normalized.clone();
    changed.occurrences[0].correlation_resolver_version = 2;
    changed.operations[0].operation_resolver_version = 2;
    let conflicting = changed
        .journal_command(normalization_command_id, 4, CONFIG_HASH, "physical-v1")
        .unwrap();
    assert_eq!(
        writer.commit(&conflicting, 4).await,
        Err(StoreError::IdempotencyConflict)
    );
}

#[test]
fn strong_canary_requires_observed_positive_and_all_negative_canaries() {
    let mut evidence = probe_fixture::fixture("complete");
    let normalization = evidence.normalization.as_mut().unwrap();
    for observation in &mut normalization.observations {
        observation.occurrence_schema_version = 1;
        observation.host_instance_id = "host-a".into();
    }
    normalization.canaries = NormalizationCanaryEvidence {
        fork_isolated: true,
        resume_isolated: true,
        retry_ordinal_isolated: true,
        replay_deduplicated: true,
        nonidentity_similarity_not_merged: true,
        missing_field_rejected: true,
        field_conflict_rejected: true,
    };
    let mut context = probe_fixture::fixture_context("complete");
    context.evidence_source = ProbeEvidenceSourceKind::ObservedHostCanary;
    let report = HostProbeReport::evaluate(&context, &evidence).unwrap();
    assert_eq!(report.strong_normalization().result(), GateResult::Enabled);

    for break_canary in [
        |value: &mut NormalizationCanaryEvidence| value.fork_isolated = false,
        |value: &mut NormalizationCanaryEvidence| value.resume_isolated = false,
        |value: &mut NormalizationCanaryEvidence| value.retry_ordinal_isolated = false,
        |value: &mut NormalizationCanaryEvidence| value.replay_deduplicated = false,
        |value: &mut NormalizationCanaryEvidence| {
            value.nonidentity_similarity_not_merged = false;
        },
        |value: &mut NormalizationCanaryEvidence| value.missing_field_rejected = false,
        |value: &mut NormalizationCanaryEvidence| value.field_conflict_rejected = false,
    ] {
        let mut broken = evidence.clone();
        break_canary(&mut broken.normalization.as_mut().unwrap().canaries);
        let report = HostProbeReport::evaluate(&context, &broken).unwrap();
        assert_eq!(report.strong_normalization().result(), GateResult::Disabled);
        assert_eq!(report.capture().result(), GateResult::Enabled);
        assert_eq!(report.recovery().result(), GateResult::Enabled);
        assert_eq!(report.active_search_due().result(), GateResult::Enabled);
        assert_eq!(report.project_policy().result(), GateResult::Enabled);
    }
}

#[test]
fn identical_payload_without_exact_tuple_never_changes_physical_count() {
    let mut observations = Vec::new();
    for record in ["retry", "replay", "fork", "resume", "ordinal"] {
        observations.push(
            observation(
                record,
                ObservationRole::Result,
                nonexact_correlation(record, CorrelationAdmission::Unavailable),
                Vec::new(),
            )
            .1,
        );
    }
    let snapshot = normalizer().normalize(&observations, None).unwrap();
    assert_eq!(snapshot.occurrences.len(), observations.len());
    assert_eq!(snapshot.operations.len(), observations.len());
    assert_eq!(
        snapshot
            .occurrences
            .iter()
            .map(|value| value.host_occurrence_id)
            .collect::<BTreeSet<_>>()
            .len(),
        observations.len()
    );
}
