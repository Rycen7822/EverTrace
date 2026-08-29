use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::Command,
    str::FromStr,
    time::Duration,
};

use evertrace_capture::{
    CasStore, DeviceKeyStore, RecoveryGateMode, RecoverySnapshotSettings, RuntimeSnapshot,
    SpoolLimits, protect,
};
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
        AttemptId, CasId, CommandId, RecoveryBundleId, RecoveryCaptureRequestId, RepositoryId,
        RequestId, SourceReceiptId, TaskId, WorkBindingRevisionId, WorkstreamId, WorktreeId,
        WorktreeSnapshotId,
    },
    repository::{
        DestructiveClass, DestructiveDetectionStatus, FilesystemIdentity, GitObjectFormat,
        GitOperation, GitRegistrationState, OrderingIntegrity, PathObservation,
        RecoveryApplicationKind, RecoveryApplicationStatus, RecoveryBundle, RecoveryCaptureRequest,
        RecoveryCaptureStatus, RecoveryContentRef, RecoveryProtectedRef, RecoveryReasonCode,
        RecoveryRequestStatus, RecoveryVerificationOutcome, RecoveryVerifierReceipt,
        RepositoryInstance, SnapshotCaptureStatus, UntrackedCaptureScope, WorktreeInstance,
        WorktreeKind, WorktreeLifecycle, WorktreeSnapshot,
    },
    revision::RevisionId,
    semantic::{EvidenceCompleteness, ParserStatus, ResultScope, VerifierStatus},
    work::{
        ArtifactActor, ArtifactDerivability, ArtifactPayloadStatus, ArtifactRetention,
        ArtifactRevision, ArtifactScope, AssignmentStatus, ContractField, CoverageLevel,
        MultiCasMetricPolicy, PairingIntegrity, PayloadIntegrity, PhaseContract, PhaseKind,
        PrimaryWorkBinding, RunContractValidity, RunExecutionStatus, RunObservability, SeedPolicy,
        SourceCoverage, StrategyContract, Task, TaskIdentityConfidence, TaskLifecycle,
        TaskScopeMembership, TerminalKind, VariableDeclaration, WorkArtifact, WorkArtifactKind,
        WorkBindingRevision, Workstream, WorkstreamStatus,
    },
};
use evertrace_engine::{
    PhysicalNormalizer, RecoveryActionOutcome, RecoveryActionService, RecoveryBarrierService,
    RecoveryRequest,
    autoresearch::{
        ArtifactService, AutoresearchCommandContext, AutoresearchError, AutoresearchResolution,
        ResultEvidenceService, ResultParseRequest, RunCreateInput, compatible_result_cohort,
        create_experiment_run, run_command,
    },
    spawn_writer,
    work::attempt::new_attempt,
};
use evertrace_protocol::{LocalServer, ServerOptions, request_recovery};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload, JournalWriter,
    NormalizationWatermark, SourceIngestWatermark,
    projections::{AutoresearchCurrentView, RecoveryCurrentView},
};
use tempfile::TempDir;
use tokio::sync::watch;

const CONFIG: [u8; 32] = [0x17; 32];
const PARSER: &str = "evertrace.result_metric.v1";

fn receipt(byte: u8) -> SourceReceiptId {
    SourceReceiptId::from_str(&format!("src:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn strategy(label: &str) -> StrategyContract {
    StrategyContract {
        hypothesis: format!("hypothesis-{label}"),
        intervention: format!("intervention-{label}"),
        intervention_family: "bounded-search".into(),
        search_policy_ref: Some("policy:grid".into()),
        objective_ref: Some("objective:accuracy".into()),
        expected_effect: "metric increases".into(),
        target_refs: vec!["target:model".into()],
        acceptance_boundary_ref: "acceptance:typed-verifier".into(),
    }
}

fn run_input(
    stream: WorkstreamId,
    source: SourceReceiptId,
    snapshot: WorktreeSnapshotId,
    varied_value: &str,
    fixed_value: &str,
    seed: &str,
) -> RunCreateInput {
    RunCreateInput {
        workstream_id: stream,
        source_receipt_refs: vec![source],
        code_snapshot_id: snapshot,
        data_fingerprint: "data-v1".into(),
        normalized_config: vec![
            ContractField {
                name: "optimizer".into(),
                value: fixed_value.into(),
            },
            ContractField {
                name: "learning_rate".into(),
                value: varied_value.into(),
            },
        ],
        variable_declaration: VariableDeclaration {
            varied: vec!["learning_rate".into()],
            fixed: vec!["optimizer".into()],
            uncontrolled: vec![],
        },
        seed_policy: SeedPolicy::Fixed,
        seed_values: vec![seed.into()],
        nondeterministic: false,
        metric_definition: "accuracy".into(),
        metric_extractor_version: PARSER.into(),
        multi_cas_metric_policy: MultiCasMetricPolicy::RejectMultipleParsed,
        environment_fingerprint: "env-v1".into(),
        created_at_us: 10,
    }
}

fn context(at: i64) -> AutoresearchCommandContext {
    AutoresearchCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: "s17-autoresearch-v2",
    }
}

fn command(at: i64, payloads: Vec<JournalPayload>) -> JournalCommand {
    JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, CONFIG, "s17-autoresearch-v2", payload))
            .collect(),
    )
    .unwrap()
}

fn git(root: &std::path::Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn recovery_runtime(root: &std::path::Path) -> RuntimeSnapshot {
    RuntimeSnapshot::for_data_dir(
        root,
        1,
        SpoolLimits {
            high_watermark_bytes: 1 << 20,
            low_watermark_bytes: 1,
            max_main_files: 4,
            emergency_slots: 1,
        },
        RecoverySnapshotSettings {
            gate: RecoveryGateMode::Active,
            preflight_timeout_ms: 10_000,
            effective_config_hash: [7; 32],
            adapter_manifest_id: Some("adapter-s17-recovery".into()),
            classifier_revision: evertrace_codex::recovery::RECOVERY_CLASSIFIER_REVISION,
            max_bundle_bytes: 4 << 20,
            max_untracked_file_bytes: 1 << 20,
            max_untracked_total_bytes: 2 << 20,
            recall_cue_gate: evertrace_capture::RecallCueGateMode::Disabled,
            recall_cue_adapter_manifest_id: None,
        },
    )
    .unwrap()
}

fn put(cas: &CasStore, key: &evertrace_capture::DeviceKey, bytes: &[u8]) -> CasId {
    let digest = cas.put(&protect(bytes, key).unwrap()).unwrap();
    CasId::from_digest(*digest.as_bytes())
}

fn artifact_revision(
    scope: ArtifactScope,
    content: CasId,
    observed: evertrace_domain::ids::SourceObservationId,
) -> ArtifactRevision {
    ArtifactRevision {
        revision_id: RevisionId::new_v7(),
        parent_revision_id: None,
        kind: WorkArtifactKind::ExperimentOutput,
        logical_name: "metrics.json".into(),
        scope,
        media_type: "application/json".into(),
        content_blob_ref: Some(content),
        external_reference: None,
        content_fingerprint: None,
        payload_status: ArtifactPayloadStatus::Available,
        produced_by_refs: vec![],
        consumed_by_refs: vec![],
        source_observation_refs: vec![observed],
        derivability: ArtifactDerivability::Reproducible,
        retention: ArtifactRetention::Repository,
        created_at_us: 40,
    }
}

#[test]
fn run_contract_hashes_are_deterministic_relaxed_and_authority_free() {
    let stream = WorkstreamId::new_v7();
    let attempt = new_attempt(
        TaskId::new_v7(),
        stream,
        None,
        vec![],
        vec![],
        strategy("run"),
        1,
    )
    .unwrap();
    let snapshot = WorktreeSnapshotId::new_v7();
    let first = create_experiment_run(
        &attempt,
        run_input(stream, receipt(1), snapshot, "0.1", "adam", "7"),
    )
    .unwrap();
    let varied = create_experiment_run(
        &attempt,
        run_input(stream, receipt(2), snapshot, "0.2", "adam", "8"),
    )
    .unwrap();
    assert_ne!(first.run_id, varied.run_id);
    assert_ne!(
        first.experiment_contract_fingerprint,
        varied.experiment_contract_fingerprint
    );
    assert_eq!(first.comparison_key, varied.comparison_key);
    let fixed = create_experiment_run(
        &attempt,
        run_input(stream, receipt(3), snapshot, "0.2", "sgd", "8"),
    )
    .unwrap();
    assert_ne!(first.comparison_key, fixed.comparison_key);
    assert_eq!(first.execution_status, RunExecutionStatus::Unknown);
    assert_eq!(first.contract_validity, RunContractValidity::Unknown);

    let mut forged = first.clone();
    forged.comparison_key = [0x44; 32];
    assert!(forged.validate().is_err());
    assert!(run_command(context(10), &forged).is_err());

    let mut duplicate = run_input(stream, receipt(4), snapshot, "0.1", "adam", "7");
    duplicate.normalized_config.push(ContractField {
        name: "learning_rate".into(),
        value: "0.3".into(),
    });
    assert!(matches!(
        create_experiment_run(&attempt, duplicate),
        Err(AutoresearchError::InvalidInput)
    ));
    let mut overlap = run_input(stream, receipt(5), snapshot, "0.1", "adam", "7");
    overlap
        .variable_declaration
        .fixed
        .push("learning_rate".into());
    assert!(matches!(
        create_experiment_run(&attempt, overlap),
        Err(AutoresearchError::InvalidInput)
    ));
}

#[test]
fn result_parser_is_order_independent_revision_bound_and_conflicts_fail_closed() {
    let temp = TempDir::new().unwrap();
    let cas = CasStore::open(temp.path().join("cas")).unwrap();
    let key = DeviceKeyStore::new(temp.path().join("key"))
        .load_or_create()
        .unwrap();
    let metric = br#"{"decimal":"0.75","unit":"ratio","uncertainty_decimal":null}"#;
    let metric_id = put(&cas, &key, metric);
    let failed_id = put(&cas, &key, b"not-json");
    let conflict_id = put(
        &cas,
        &key,
        br#"{"decimal":"0.80","unit":"ratio","uncertainty_decimal":null}"#,
    );
    let precise_a = put(
        &cas,
        &key,
        br#"{"decimal":"0.123456789012345678901","unit":"ratio","uncertainty_decimal":null}"#,
    );
    let precise_b = put(
        &cas,
        &key,
        br#"{"decimal":"0.123456789012345678902","unit":"ratio","uncertainty_decimal":null}"#,
    );
    let stream = WorkstreamId::new_v7();
    let attempt = new_attempt(
        TaskId::new_v7(),
        stream,
        None,
        vec![],
        vec![],
        strategy("result"),
        1,
    )
    .unwrap();
    let run = create_experiment_run(
        &attempt,
        run_input(
            stream,
            receipt(10),
            WorktreeSnapshotId::new_v7(),
            "0.1",
            "adam",
            "7",
        ),
    )
    .unwrap();
    let service = ResultEvidenceService::new(cas);
    let parsed = service
        .parse(
            &run,
            ResultParseRequest {
                scope: ResultScope::Partial,
                raw_cas_refs: vec![metric_id, failed_id, metric_id],
                created_at_us: 20,
            },
        )
        .unwrap();
    assert!(parsed.raw_cas_refs.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(parsed.experiment_run_revision_id, run.revision_id);
    assert_eq!(parsed.parser_receipt.status, ParserStatus::Parsed);
    assert!(matches!(
        service.extend(&run, &parsed, vec![metric_id], 21).unwrap(),
        AutoresearchResolution::NoDelta
    ));
    assert!(matches!(
        service.extend(&run, &parsed, vec![conflict_id], 22),
        Err(AutoresearchError::ImmutableConflict)
    ));
    assert!(matches!(
        service.parse(
            &run,
            ResultParseRequest {
                scope: ResultScope::Partial,
                raw_cas_refs: vec![metric_id, conflict_id],
                created_at_us: 23,
            }
        ),
        Err(AutoresearchError::AmbiguousMetricInput)
    ));
    let verified = match service.verify(&run, &parsed, 24).unwrap() {
        AutoresearchResolution::Revision(value) => *value,
        AutoresearchResolution::NoDelta => panic!(),
    };
    assert_eq!(verified.completeness, EvidenceCompleteness::Complete);
    assert_eq!(
        verified.verifier_receipt.as_ref().unwrap().status,
        VerifierStatus::Passed
    );
    assert!(matches!(
        compatible_result_cohort(&[(&verified, &run)]),
        Err(AutoresearchError::IncompatibleComparison)
    ));
    assert!(compatible_result_cohort(&[(&verified, &run), (&verified, &run)]).is_err());

    let mut identical_policy_run = run.clone();
    identical_policy_run.multi_cas_metric_policy = MultiCasMetricPolicy::AllowIdenticalParsed;
    identical_policy_run.experiment_contract_fingerprint = identical_policy_run
        .recompute_exact_contract_fingerprint()
        .unwrap();
    identical_policy_run.comparison_key = identical_policy_run.recompute_comparison_key().unwrap();
    identical_policy_run.validate().unwrap();
    assert!(matches!(
        service.parse(
            &identical_policy_run,
            ResultParseRequest {
                scope: ResultScope::Partial,
                raw_cas_refs: vec![precise_a, precise_b],
                created_at_us: 25,
            }
        ),
        Err(AutoresearchError::AmbiguousMetricInput)
    ));

    let mut trusted = run.clone();
    trusted.observability = RunObservability::Full;
    trusted.execution_status = RunExecutionStatus::Completed;
    trusted.contract_validity = RunContractValidity::Valid;
    trusted.terminal_evidence_refs = trusted.source_receipt_refs.clone();
    trusted.started_at_us = Some(11);
    trusted.ended_at_us = Some(12);
    trusted.validate().unwrap();
    let mut second_run = trusted.clone();
    second_run.run_id = evertrace_domain::ids::ExperimentRunId::new_v7();
    second_run.revision_id = RevisionId::new_v7();
    let mut second_result = verified.clone();
    second_result.result_evidence_id = evertrace_domain::ids::ResultEvidenceId::new_v7();
    second_result.revision_id = RevisionId::new_v7();
    second_result.parent_revision_id = None;
    second_result.experiment_run_id = second_run.run_id;
    second_result.experiment_run_revision_id = second_run.revision_id;
    second_result.validate().unwrap();
    let cohort = compatible_result_cohort(&[(&verified, &trusted), (&second_result, &second_run)])
        .unwrap()
        .unwrap();
    assert_eq!(cohort.member_result_ids.len(), 2);

    let mut failed_run = second_run.clone();
    failed_run.execution_status = RunExecutionStatus::Failed;
    assert!(
        compatible_result_cohort(&[(&second_result, &failed_run)])
            .unwrap()
            .is_some()
    );
    let mut complete_failed = second_result.clone();
    complete_failed.result_scope = ResultScope::Complete;
    complete_failed.validate().unwrap();
    assert!(compatible_result_cohort(&[(&complete_failed, &failed_run)]).is_err());

    let mut cross_attempt = second_run.clone();
    cross_attempt.attempt_id = Some(AttemptId::new_v7());
    assert!(
        compatible_result_cohort(&[(&verified, &trusted), (&second_result, &cross_attempt),])
            .is_err()
    );
    let mut cross_workstream = second_run.clone();
    cross_workstream.workstream_id = WorkstreamId::new_v7();
    assert!(
        compatible_result_cohort(&[(&verified, &trusted), (&second_result, &cross_workstream),])
            .is_err()
    );
    let mut cross_strategy = second_run;
    cross_strategy.strategy_contract_fingerprint = [0x66; 32];
    cross_strategy.experiment_contract_fingerprint = cross_strategy
        .recompute_exact_contract_fingerprint()
        .unwrap();
    assert!(
        compatible_result_cohort(&[(&verified, &trusted), (&second_result, &cross_strategy),])
            .is_err()
    );
}

#[derive(Clone)]
struct Topology {
    repository: RepositoryInstance,
    worktree: WorktreeInstance,
    snapshot: WorktreeSnapshot,
}

fn topology(root: &std::path::Path) -> Topology {
    let repository_id = evertrace_domain::ids::RepositoryId::new_v7();
    let worktree_id = evertrace_domain::ids::WorktreeId::new_v7();
    let snapshot_id = WorktreeSnapshotId::new_v7();
    let path = root.join("repo").display().to_string();
    let observation = PathObservation {
        path: path.clone(),
        first_observed_at_us: 1,
        last_observed_at_us: 1,
        evidence_refs: vec!["path-observed".into()],
    };
    let repository = RepositoryInstance {
        repository_id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: path.clone(),
        path_history: vec![observation.clone()],
        git_common_dir_path: Some(format!("{path}/.git")),
        common_dir_filesystem: Some(FilesystemIdentity {
            device: 17,
            inode: 1,
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: vec![],
        derived_from: None,
        identity_evidence_refs: vec!["repo-identity".into()],
        recorded_at_us: 1,
    };
    let worktree = WorktreeInstance {
        worktree_instance_id: worktree_id,
        worktree_revision: 1,
        predecessor_revision: None,
        repository_instance_id: repository_id,
        kind: WorktreeKind::Main,
        lifecycle: WorktreeLifecycle::Active,
        current_path: Some(path.clone()),
        path_history: vec![observation.clone()],
        git_admin_path_history: vec![PathObservation {
            path: format!("{path}/.git"),
            ..observation
        }],
        git_registration_state: GitRegistrationState::Registered,
        current_snapshot_id: Some(snapshot_id),
        created_event_ref: "worktree-created".into(),
        terminal_event_ref: None,
        recreated_from_worktree_instance_id: None,
        recorded_at_us: 1,
    };
    let snapshot = WorktreeSnapshot {
        worktree_snapshot_id: snapshot_id,
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
        captured_at_us: 2,
        evidence_refs: vec!["snapshot".into()],
        capture_status: SnapshotCaptureStatus::Complete,
        omission_reasons: vec![],
    };
    Topology {
        repository,
        worktree,
        snapshot,
    }
}

fn task(topology: &Topology) -> Task {
    Task {
        task_id: TaskId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec!["request:s17".into()],
        canonical_goal: "prove autoresearch foundations".into(),
        scope_memberships: vec![TaskScopeMembership {
            repository_instance_id: Some(topology.repository.repository_id),
            worktree_instance_ids: vec![topology.worktree.worktree_instance_id],
        }],
        identity_confidence: TaskIdentityConfidence::Explicit,
        lifecycle: TaskLifecycle::Active,
        continuation_of_task_id: None,
        split_from_task_id: None,
        split_into_task_ids: vec![],
        merged_from_task_ids: vec![],
        merged_into_task_id: None,
        created_at_us: 3,
        closed_at_us: None,
        source_watermark: 3,
    }
}

fn stream(task: &Task, topology: &Topology) -> Workstream {
    Workstream {
        workstream_id: WorkstreamId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        task_id: task.task_id,
        repository_instance_id: Some(topology.repository.repository_id),
        worktree_instance_ids: vec![topology.worktree.worktree_instance_id],
        active_worktree_instance_id: Some(topology.worktree.worktree_instance_id),
        worktree_lineage_refs: vec!["lineage:s17".into()],
        parent_workstream_id: None,
        dependency_workstream_ids: vec![],
        status: WorkstreamStatus::Active,
        root_goal: "prove autoresearch foundations".into(),
        workstream_goal: "record one real run".into(),
        target_family: "autoresearch".into(),
        hypothesis_or_failure_family: "contract".into(),
        acceptance_boundary: "typed immutable evidence".into(),
        phase_contract: PhaseContract {
            local_goal: "record run result artifact".into(),
            phase_kind: PhaseKind::Implement,
            phase_label: "s17".into(),
            primary_targets: vec!["autoresearch".into()],
            entry_conditions: vec!["s16 complete".into()],
            acceptance_boundary: "foundation proof".into(),
            expected_state_transition: "current projections".into(),
        },
        active_episode_id: None,
        execution_lane_ids: vec![],
        source_watermark: 4,
    }
}

fn exact_observation(cas: CasId, bytes: &[u8]) -> (SourceReceipt, SourceObservation) {
    let instance = SourceInstanceId::parse("source-s17").unwrap();
    let revision = SourceRevision::parse("revision-1").unwrap();
    let record = SourceRecordIdentity::parse("record-s17").unwrap();
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
        source_ref: "source-ref-s17".into(),
        source_session_ref: "session-s17".into(),
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
        cas_ref: cas.to_string()[4..].into(),
        protected_length: bytes.len() as u64,
        original_length: bytes.len() as u64,
        protected_secret_digest: None,
        redaction_spans: vec![],
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-manifest-s17".into(),
        eligible_event_manifest_ref: "eligible-events-s17".into(),
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
            &payload_fingerprint(1, bytes, None).unwrap(),
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
            host_instance_id: Some("host-s17".into()),
            host_trace_lineage_id: Some("trace-s17".into()),
            host_lane_key: Some("lane-s17".into()),
            canonical_event_family: Some(CanonicalEventFamily::Mutate),
            native_request_id: Some("request-s17".into()),
            physical_execution_ordinal: Some(1),
            pairing_role: ObservationRole::Result,
            field_provenance: fields
                .into_iter()
                .map(|field| CorrelationFieldClaim {
                    field,
                    source_ref: "source-s17".into(),
                    evidence_ref: format!("canary-{field:?}"),
                })
                .collect(),
            adapter_manifest_ref: "adapter-manifest-s17".into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: Some("strong-gate-s17".into()),
            admission: CorrelationAdmission::ExactCapable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: vec![],
    };
    (receipt, observation)
}

#[tokio::test]
async fn real_four_table_batch_rebuild_restart_and_fail_closed_relations() {
    let temp = TempDir::new().unwrap();
    let cas = CasStore::open(temp.path().join("cas")).unwrap();
    let key = DeviceKeyStore::new(temp.path().join("key"))
        .load_or_create()
        .unwrap();
    let metric_bytes = br#"{"decimal":"0.75","unit":"ratio","uncertainty_decimal":null}"#;
    let metric_id = put(&cas, &key, metric_bytes);
    let second_id = put(
        &cas,
        &key,
        br#"{"decimal":"0.76","unit":"ratio","uncertainty_decimal":null}"#,
    );
    let (receipt, observation) = exact_observation(metric_id, metric_bytes);
    let physical = PhysicalNormalizer::new(1)
        .unwrap()
        .normalize(std::slice::from_ref(&observation), None)
        .unwrap();
    let other_topology = topology(&temp.path().join("other"));
    let other_task = task(&other_topology);
    let topology = topology(temp.path());
    let task = task(&topology);
    let stream = stream(&task, &topology);
    let binding_id = WorkBindingRevisionId::new_v7();
    let mut attempt = new_attempt(
        task.task_id,
        stream.workstream_id,
        Some(topology.repository.repository_id),
        vec![topology.worktree.worktree_instance_id],
        vec![],
        strategy("integration"),
        5,
    )
    .unwrap();
    attempt.work_binding_revision_refs = vec![binding_id];
    attempt.validate().unwrap();
    let mut run = create_experiment_run(
        &attempt,
        run_input(
            stream.workstream_id,
            receipt.source_receipt_id,
            topology.snapshot.worktree_snapshot_id,
            "0.1",
            "adam",
            "7",
        ),
    )
    .unwrap();
    run.revision_id = RevisionId::from_str("01890f47-6a4a-7fff-bfff-ffffffffffff").unwrap();
    let artifact_service = ArtifactService::new(cas.clone());
    let (artifact, mut run_with_artifact, _) = artifact_service
        .create_for_run_command(
            context(40),
            &run,
            artifact_revision(
                ArtifactScope::Worktree {
                    repository_instance_id: topology.repository.repository_id,
                    worktree_instance_id: topology.worktree.worktree_instance_id,
                },
                metric_id,
                observation.source_observation_id,
            ),
        )
        .unwrap();
    run_with_artifact.revision_id =
        RevisionId::from_str("01890f47-6a4a-7000-8000-000000000000").unwrap();
    run_with_artifact.parent_revision_id = Some(run.revision_id);
    run.validate_successor(&run_with_artifact).unwrap();
    assert!(run_with_artifact.revision_id < run.revision_id);
    assert_eq!(artifact.revision.content_fingerprint, Some(metric_id));
    let result_service = ResultEvidenceService::new(cas.clone());
    let result = result_service
        .parse(
            &run,
            ResultParseRequest {
                scope: ResultScope::Partial,
                raw_cas_refs: vec![metric_id],
                created_at_us: 41,
            },
        )
        .unwrap();
    let verified = match result_service.verify(&run, &result, 42).unwrap() {
        AutoresearchResolution::Revision(value) => *value,
        AutoresearchResolution::NoDelta => panic!(),
    };
    let binding = WorkBindingRevision {
        work_binding_revision_id: binding_id,
        operation_id: physical.operations[0].operation_id,
        revision_generation: 1,
        predecessor_revision_id: None,
        primary_binding: PrimaryWorkBinding {
            task_id: Some(task.task_id),
            workstream_id: Some(stream.workstream_id),
            attempt_id: Some(attempt.attempt_id),
            experiment_run_id: Some(run.run_id),
            ..Default::default()
        },
        secondary_bindings: vec![],
        scope_effect_refs: vec![],
        assignment_status: AssignmentStatus::Resolved,
        evidence_refs: vec!["exact-s17".into()],
        resolver_version: 1,
    };

    let evidence_payloads = vec![
        JournalPayload::SourceReceiptRecorded(Box::new(receipt.clone())),
        JournalPayload::SourceObservationRecorded(Box::new(observation.clone())),
        JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
            source_instance_id: receipt.source_instance_id.clone(),
            source_revision: receipt.source_revision.clone(),
            source_sequence: receipt.source_sequence,
        }),
        JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::EvidenceSurface,
            target_id: observation.source_observation_id.to_string(),
            algorithm_revision: "s17-autoresearch-v2".into(),
            source_watermark: 1,
        }),
        JournalPayload::DirtyTarget(DirtyTarget {
            target_kind: DirtyTargetKind::PhysicalNormalization,
            target_id: observation.source_observation_id.to_string(),
            algorithm_revision: "s17-autoresearch-v2".into(),
            source_watermark: 1,
        }),
    ];
    let mut physical_payloads = physical
        .occurrences
        .iter()
        .cloned()
        .map(|value| JournalPayload::HostOccurrenceNormalized(Box::new(value)))
        .collect::<Vec<_>>();
    physical_payloads.push(JournalPayload::NormalizationWatermark(
        NormalizationWatermark {
            source_observation_id: observation.source_observation_id,
            resolver_version: 1,
        },
    ));
    physical_payloads.extend(
        physical
            .operations
            .iter()
            .cloned()
            .map(|value| JournalPayload::OperationDerived(Box::new(value))),
    );
    physical_payloads.extend(
        physical
            .scope_effects
            .iter()
            .cloned()
            .map(|value| JournalPayload::ScopeEffectDerived(Box::new(value))),
    );
    let topology_payloads = vec![
        JournalPayload::RepositoryInstanceRecorded(Box::new(topology.repository.clone())),
        JournalPayload::WorktreeInstanceRecorded(Box::new(topology.worktree.clone())),
        JournalPayload::WorktreeSnapshotRecorded(Box::new(topology.snapshot.clone())),
        JournalPayload::TaskRecorded(Box::new(task.clone())),
        JournalPayload::WorkstreamRecorded(Box::new(stream.clone())),
        JournalPayload::RepositoryInstanceRecorded(Box::new(other_topology.repository.clone())),
        JournalPayload::WorktreeInstanceRecorded(Box::new(other_topology.worktree.clone())),
        JournalPayload::WorktreeSnapshotRecorded(Box::new(other_topology.snapshot.clone())),
        JournalPayload::TaskRecorded(Box::new(other_task.clone())),
    ];
    let payloads = vec![
        JournalPayload::AttemptRecorded(Box::new(attempt.clone())),
        JournalPayload::ExperimentRunRecorded(Box::new(run.clone())),
        JournalPayload::ExperimentRunRecorded(Box::new(run_with_artifact.clone())),
        JournalPayload::WorkArtifactRecorded(Box::new(artifact.clone())),
        JournalPayload::ResultEvidenceRecorded(Box::new(result.clone())),
        JournalPayload::ResultEvidenceRecorded(Box::new(verified.clone())),
        JournalPayload::WorkBindingRecorded(Box::new(binding.clone())),
    ];
    for payload in &payloads {
        payload
            .validate()
            .unwrap_or_else(|error| panic!("{}: {error:?}", payload.event_type()));
    }

    let store_root = temp.path().join("store");
    let mut writer = JournalWriter::open(&store_root).await.unwrap();
    writer
        .commit(&command(10, evidence_payloads), 10)
        .await
        .unwrap();
    writer
        .commit(&command(20, physical_payloads), 20)
        .await
        .unwrap();
    writer
        .commit(&command(30, topology_payloads), 30)
        .await
        .unwrap();
    writer.commit(&command(50, payloads), 50).await.unwrap();
    let incremental = writer.project().await.unwrap();
    assert_eq!(incremental, writer.full_projection().await.unwrap());
    assert_eq!(
        writer.table_names().await.unwrap(),
        vec![
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search",
        ]
    );
    let view = AutoresearchCurrentView::from_snapshot(&incremental).unwrap();
    assert_eq!(view.runs[&run.run_id], run_with_artifact);
    assert_eq!(view.results[&verified.result_evidence_id], verified);
    assert_eq!(view.artifacts[&artifact.work_artifact_id], artifact);
    let journal_len = writer.journal_rows().await.unwrap().len();
    let frontier = incremental.frontier;

    for (at, scope) in [
        (
            57,
            ArtifactScope::Task {
                task_id: other_task.task_id,
            },
        ),
        (
            58,
            ArtifactScope::Repository {
                repository_instance_id: other_topology.repository.repository_id,
            },
        ),
        (
            59,
            ArtifactScope::Worktree {
                repository_instance_id: other_topology.repository.repository_id,
                worktree_instance_id: other_topology.worktree.worktree_instance_id,
            },
        ),
    ] {
        let (_, _, bad_scope_command) = artifact_service
            .create_for_run_command(
                context(at),
                &run_with_artifact,
                artifact_revision(scope, second_id, observation.source_observation_id),
            )
            .unwrap();
        assert!(writer.commit(&bad_scope_command, at).await.is_err());
        assert_eq!(writer.journal_rows().await.unwrap().len(), journal_len);
        assert_eq!(writer.project().await.unwrap().frontier, frontier);
    }

    let mut forged_strategy = run.clone();
    forged_strategy.run_id = evertrace_domain::ids::ExperimentRunId::new_v7();
    forged_strategy.revision_id = RevisionId::new_v7();
    forged_strategy.strategy_contract_fingerprint = [0x44; 32];
    forged_strategy.experiment_contract_fingerprint = forged_strategy
        .recompute_exact_contract_fingerprint()
        .unwrap();
    assert!(
        writer
            .commit(
                &command(
                    51,
                    vec![JournalPayload::ExperimentRunRecorded(Box::new(
                        forged_strategy
                    ))]
                ),
                51
            )
            .await
            .is_err()
    );

    let mut wrong_revision = verified.clone();
    wrong_revision.result_evidence_id = evertrace_domain::ids::ResultEvidenceId::new_v7();
    wrong_revision.revision_id = RevisionId::new_v7();
    wrong_revision.parent_revision_id = None;
    wrong_revision.experiment_run_revision_id = RevisionId::new_v7();
    assert!(
        writer
            .commit(
                &command(
                    52,
                    vec![JournalPayload::ResultEvidenceRecorded(Box::new(
                        wrong_revision
                    ))]
                ),
                52
            )
            .await
            .is_err()
    );

    let mut complete = verified.clone();
    complete.result_evidence_id = evertrace_domain::ids::ResultEvidenceId::new_v7();
    complete.revision_id = RevisionId::new_v7();
    complete.parent_revision_id = None;
    complete.result_scope = ResultScope::Complete;
    assert!(
        writer
            .commit(
                &command(
                    53,
                    vec![JournalPayload::ResultEvidenceRecorded(Box::new(complete))]
                ),
                53
            )
            .await
            .is_err()
    );

    let mut bad_revision = artifact_revision(
        ArtifactScope::Task {
            task_id: task.task_id,
        },
        second_id,
        observation.source_observation_id,
    );
    bad_revision.consumed_by_refs = vec![ArtifactActor::Operation(
        physical.operations[0].operation_id,
    )];
    let bad_artifact = artifact_service.create(bad_revision).unwrap();
    assert!(
        writer
            .commit(
                &command(
                    54,
                    vec![JournalPayload::WorkArtifactRecorded(Box::new(bad_artifact))]
                ),
                54
            )
            .await
            .is_err()
    );
    let mismatched_observation_content = artifact_service
        .create(artifact_revision(
            ArtifactScope::Task {
                task_id: task.task_id,
            },
            second_id,
            observation.source_observation_id,
        ))
        .unwrap();
    assert!(
        writer
            .commit(
                &command(
                    60,
                    vec![JournalPayload::WorkArtifactRecorded(Box::new(
                        mismatched_observation_content,
                    ))],
                ),
                60,
            )
            .await
            .is_err()
    );
    let missing_scope_artifact = artifact_service
        .create(artifact_revision(
            ArtifactScope::Task {
                task_id: TaskId::new_v7(),
            },
            second_id,
            observation.source_observation_id,
        ))
        .unwrap();
    assert!(
        writer
            .commit(
                &command(
                    56,
                    vec![JournalPayload::WorkArtifactRecorded(Box::new(
                        missing_scope_artifact,
                    ))],
                ),
                56,
            )
            .await
            .is_err()
    );

    let second_attempt = new_attempt(
        task.task_id,
        stream.workstream_id,
        Some(topology.repository.repository_id),
        vec![topology.worktree.worktree_instance_id],
        vec![],
        strategy("binding-mismatch"),
        6,
    )
    .unwrap();
    let second_run = create_experiment_run(
        &second_attempt,
        run_input(
            stream.workstream_id,
            receipt.source_receipt_id,
            topology.snapshot.worktree_snapshot_id,
            "0.2",
            "adam",
            "8",
        ),
    )
    .unwrap();
    let mut bad_binding = binding.clone();
    bad_binding.work_binding_revision_id = WorkBindingRevisionId::new_v7();
    bad_binding.predecessor_revision_id = Some(binding.work_binding_revision_id);
    bad_binding.revision_generation = 2;
    bad_binding.primary_binding.experiment_run_id = Some(second_run.run_id);
    let mut attempt_with_binding = attempt.clone();
    attempt_with_binding.revision_id = RevisionId::new_v7();
    attempt_with_binding.predecessor_revision_id = Some(attempt.revision_id);
    attempt_with_binding.revision_generation = 2;
    attempt_with_binding.source_watermark = 6;
    attempt_with_binding
        .work_binding_revision_refs
        .push(bad_binding.work_binding_revision_id);
    attempt_with_binding.work_binding_revision_refs.sort();
    attempt.validate_successor(&attempt_with_binding).unwrap();
    assert!(
        writer
            .commit(
                &command(
                    55,
                    vec![
                        JournalPayload::AttemptRecorded(Box::new(attempt_with_binding)),
                        JournalPayload::AttemptRecorded(Box::new(second_attempt)),
                        JournalPayload::ExperimentRunRecorded(Box::new(second_run)),
                        JournalPayload::WorkBindingRecorded(Box::new(bad_binding)),
                    ],
                ),
                55,
            )
            .await
            .is_err()
    );

    assert_eq!(writer.journal_rows().await.unwrap().len(), journal_len);
    assert_eq!(writer.project().await.unwrap().frontier, frontier);
    drop(writer);
    let writer = JournalWriter::open(&store_root).await.unwrap();
    assert_eq!(
        AutoresearchCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap(),
        view
    );
}

#[tokio::test]
async fn artifact_second_cas_successor_no_delta_and_later_authority_rejected() {
    let temp = TempDir::new().unwrap();
    let cas = CasStore::open(temp.path().join("cas")).unwrap();
    let key = DeviceKeyStore::new(temp.path().join("key"))
        .load_or_create()
        .unwrap();
    let first_id = put(&cas, &key, b"first");
    let second_id = put(&cas, &key, b"second");
    let observed = evertrace_domain::ids::SourceObservationId::from_digest([0x11; 32]);
    let task_id = TaskId::new_v7();
    let service = ArtifactService::new(cas);
    let mut mismatched = artifact_revision(ArtifactScope::Task { task_id }, first_id, observed);
    mismatched.content_fingerprint = Some(second_id);
    assert!(matches!(
        service.create(mismatched),
        Err(AutoresearchError::ImmutableConflict)
    ));
    let artifact = service
        .create(artifact_revision(
            ArtifactScope::Task { task_id },
            first_id,
            observed,
        ))
        .unwrap();
    let mut no_provenance = artifact.revision.clone();
    no_provenance.produced_by_refs.clear();
    no_provenance.source_observation_refs.clear();
    assert!(matches!(
        service.create(no_provenance),
        Err(AutoresearchError::InvalidInput)
    ));
    let mut root_purged = artifact.clone();
    root_purged.work_artifact_id = evertrace_domain::ids::WorkArtifactId::new_v7();
    root_purged.revision.revision_id = RevisionId::new_v7();
    root_purged.revision.parent_revision_id = None;
    root_purged.revision.content_blob_ref = None;
    root_purged.revision.content_fingerprint = None;
    root_purged.revision.payload_status = ArtifactPayloadStatus::SourcePurged;
    assert!(WorkArtifact::validate(&root_purged).is_err());
    assert!(matches!(
        service
            .revise(&artifact, artifact.revision.clone())
            .unwrap(),
        AutoresearchResolution::NoDelta
    ));
    let mut revision = artifact.revision.clone();
    revision.content_blob_ref = Some(second_id);
    revision.content_fingerprint = None;
    revision.created_at_us += 1;
    let successor = match service.revise(&artifact, revision).unwrap() {
        AutoresearchResolution::Revision(value) => *value,
        AutoresearchResolution::NoDelta => panic!(),
    };
    assert_eq!(successor.revision.content_fingerprint, Some(second_id));
    let mut purge = successor.revision.clone();
    purge.content_blob_ref = None;
    purge.payload_status = ArtifactPayloadStatus::SourcePurged;
    assert!(matches!(
        service.revise(&successor, purge),
        Err(AutoresearchError::UnsupportedArtifactAuthority)
    ));
    let mut global = artifact.revision.clone();
    global.scope = ArtifactScope::Global;
    assert!(matches!(
        service.create(global),
        Err(AutoresearchError::UnsupportedArtifactAuthority)
    ));
}

#[tokio::test]
async fn supervised_patch_is_real_at_most_once_and_unsupported_is_zero_delta() {
    let root = TempDir::new().unwrap();
    let worktree_path = root.path().join("worktree");
    fs::create_dir(&worktree_path).unwrap();
    fs::set_permissions(&worktree_path, fs::Permissions::from_mode(0o700)).unwrap();
    git(&worktree_path, &["init", "--quiet"]);
    git(
        &worktree_path,
        &["config", "user.email", "s17@example.invalid"],
    );
    git(&worktree_path, &["config", "user.name", "S17"]);
    fs::write(worktree_path.join("tracked.txt"), b"before\n").unwrap();
    fs::write(worktree_path.join("other.txt"), b"other-before\n").unwrap();
    git(&worktree_path, &["add", "tracked.txt", "other.txt"]);
    git(&worktree_path, &["commit", "--quiet", "-m", "base"]);
    fs::write(worktree_path.join("tracked.txt"), b"after\n").unwrap();
    let patch = Command::new("git")
        .args(["diff", "--binary", "--", "tracked.txt"])
        .current_dir(&worktree_path)
        .output()
        .unwrap();
    assert!(patch.status.success());
    assert!(!patch.stdout.is_empty());
    git(&worktree_path, &["restore", "--", "tracked.txt"]);

    let store_root = root.path().join("store");
    fs::create_dir(&store_root).unwrap();
    fs::set_permissions(&store_root, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = recovery_runtime(&store_root);
    let cas = CasStore::open(runtime.cas_dir.clone()).unwrap();
    let key = DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    let patch_id = put(&cas, &key, &patch.stdout);
    let repository_id = RepositoryId::new_v7();
    let worktree_id = WorktreeId::new_v7();
    let snapshot_id = WorktreeSnapshotId::new_v7();
    let capture_request_id = RecoveryCaptureRequestId::new_v7();
    let bundle_id = RecoveryBundleId::new_v7();
    let canonical_root = fs::canonicalize(&worktree_path).unwrap();
    let git_dir = canonical_root.join(".git");
    let git_metadata = fs::metadata(&git_dir).unwrap();
    let path = canonical_root.to_string_lossy().into_owned();
    let path_observation = PathObservation {
        path: path.clone(),
        first_observed_at_us: 1,
        last_observed_at_us: 1,
        evidence_refs: vec!["s17-recovery-path".into()],
    };
    let repository = RepositoryInstance {
        repository_id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: path.clone(),
        path_history: vec![path_observation.clone()],
        git_common_dir_path: Some(git_dir.to_string_lossy().into_owned()),
        common_dir_filesystem: Some(FilesystemIdentity {
            device: git_metadata.dev(),
            inode: git_metadata.ino(),
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: vec![],
        derived_from: None,
        identity_evidence_refs: vec!["s17-recovery-git-common-dir".into()],
        recorded_at_us: 1,
    };
    let worktree = WorktreeInstance {
        worktree_instance_id: worktree_id,
        worktree_revision: 1,
        predecessor_revision: None,
        repository_instance_id: repository_id,
        kind: WorktreeKind::Main,
        lifecycle: WorktreeLifecycle::Active,
        current_path: Some(path.clone()),
        path_history: vec![path_observation.clone()],
        git_admin_path_history: vec![PathObservation {
            path: git_dir.to_string_lossy().into_owned(),
            evidence_refs: vec!["s17-recovery-git-admin".into()],
            ..path_observation
        }],
        git_registration_state: GitRegistrationState::Registered,
        current_snapshot_id: Some(snapshot_id),
        created_event_ref: "s17-recovery-worktree".into(),
        terminal_event_ref: None,
        recreated_from_worktree_instance_id: None,
        recorded_at_us: 1,
    };
    let snapshot = WorktreeSnapshot {
        worktree_snapshot_id: snapshot_id,
        worktree_instance_id: worktree_id,
        head_oid: Some(git(&worktree_path, &["rev-parse", "HEAD"])),
        tree_oid: Some(git(&worktree_path, &["rev-parse", "HEAD^{tree}"])),
        branch_ref: Some(git(&worktree_path, &["symbolic-ref", "HEAD"])),
        detached_head: false,
        tracked_diff_digest: None,
        index_digest: None,
        untracked_manifest_digest: None,
        relevant_anchor_digests: vec![],
        dependency_fingerprints: vec![],
        toolchain_fingerprint: None,
        git_operation: GitOperation::None,
        captured_at_us: 2,
        evidence_refs: vec!["s17-recovery-pre-snapshot".into()],
        capture_status: SnapshotCaptureStatus::Complete,
        omission_reasons: vec![],
    };
    let pending_revision = RevisionId::new_v7();
    let pending = RecoveryCaptureRequest {
        recovery_capture_request_id: capture_request_id,
        request_revision_id: pending_revision,
        parent_request_revision_id: None,
        trigger_event_id: "s17-recovery-trigger".into(),
        repository_instance_id: repository_id,
        worktree_instance_id: worktree_id,
        pre_operation_snapshot_id: None,
        command_fingerprint: "ab".repeat(32),
        destructive_class: DestructiveClass::GitRestoreDiscard,
        untracked_capture_scope: UntrackedCaptureScope::Standard,
        detection_status: DestructiveDetectionStatus::Matched,
        request_status: RecoveryRequestStatus::Pending,
        recovery_bundle_id: None,
        reason_codes: vec![],
        started_at_us: 3,
        finished_at_us: None,
        effective_config_hash: [7; 32],
    };
    let terminal = RecoveryCaptureRequest {
        request_revision_id: RevisionId::new_v7(),
        parent_request_revision_id: Some(pending_revision),
        pre_operation_snapshot_id: Some(snapshot_id),
        request_status: RecoveryRequestStatus::Complete,
        recovery_bundle_id: Some(bundle_id),
        reason_codes: vec![RecoveryReasonCode::CaptureComplete],
        finished_at_us: Some(4),
        ..pending.clone()
    };
    let bundle = RecoveryBundle {
        recovery_bundle_id: bundle_id,
        source_worktree_instance_id: worktree_id,
        source_snapshot_id: snapshot_id,
        trigger_request_ids: vec![capture_request_id],
        tracked_diff_blob_refs: vec![RecoveryContentRef {
            item_ref: "git:tracked_diff".into(),
            payload: RecoveryProtectedRef {
                cas_ref: patch_id.to_string()[4..].into(),
                protected_length: patch.stdout.len() as u64,
                original_length: patch.stdout.len() as u64,
                protected_secret_digest: None,
                redaction_spans: 0,
            },
            protected_relative_path: None,
        }],
        tracked_file_blob_refs: vec![],
        index_state_refs: vec![],
        untracked_file_blob_refs: vec![],
        untracked_work_artifact_refs: vec![],
        metadata_only_work_artifact_refs: vec![],
        config_and_run_refs: vec![],
        attempt_anchor_ids: vec![],
        attempt_anchor_claims: vec![],
        omissions: vec![],
        capture_status: RecoveryCaptureStatus::Complete,
        ordering_integrity: OrderingIntegrity::Complete,
        adapter_manifest_id: "adapter-s17-recovery".into(),
        eligible_mutation_manifest_version: 1,
        eligible_mutation_domain: evertrace_domain::repository::SUPPORTED_MUTATION_DOMAIN.into(),
        captured_bytes: patch.stdout.len() as u64,
        captured_at_us: 4,
    };
    pending.validate().unwrap();
    terminal.validate().unwrap();
    bundle.validate().unwrap();

    let mut writer = JournalWriter::open(&store_root).await.unwrap();
    for (at, payloads) in [
        (
            1,
            vec![
                JournalPayload::RepositoryInstanceRecorded(Box::new(repository)),
                JournalPayload::WorktreeInstanceRecorded(Box::new(worktree)),
                JournalPayload::WorktreeSnapshotRecorded(Box::new(snapshot)),
            ],
        ),
        (
            3,
            vec![JournalPayload::RecoveryCaptureRequestRecorded(Box::new(
                pending,
            ))],
        ),
        (
            4,
            vec![
                JournalPayload::RecoveryCaptureRequestRecorded(Box::new(terminal)),
                JournalPayload::RecoveryBundleRecorded(Box::new(bundle)),
            ],
        ),
    ] {
        let seed = JournalCommand::new(
            CommandId::new_v7(),
            payloads
                .into_iter()
                .map(|payload| {
                    JournalEventDraft::runtime(at, [7; 32], "s17-supervised-recovery-v1", payload)
                })
                .collect(),
        )
        .unwrap();
        writer.commit(&seed, at).await.unwrap();
    }
    let frontier_before = writer.project().await.unwrap().frontier;
    let (handle, writer_task) = spawn_writer(writer, 16).unwrap();
    let barrier = RecoveryBarrierService::new(runtime.clone(), handle.clone());
    let service = RecoveryActionService::new(runtime, handle.clone(), barrier.mutation_fence());
    let server = LocalServer::bind(&store_root, ServerOptions::new("s17-test")).unwrap();
    let socket = server.socket_path().to_path_buf();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let uds_service = service.clone();
    let server_task = tokio::spawn(server.run_dispatch(shutdown_rx, move |request_id, command| {
        let service = uds_service.clone();
        async move {
            let evertrace_protocol::command::Command::RequestRecovery(request) = command else {
                return Err(evertrace_domain::error::ErrorCode::InvalidInput);
            };
            let outcome = service
                .handle(RecoveryRequest {
                    request_id,
                    recovery_bundle_id: request.recovery_bundle_id,
                    target_worktree_instance_id: request.target_worktree_instance_id,
                    application_kind: request.application_kind,
                })
                .await
                .map_err(|_| evertrace_domain::error::ErrorCode::InvalidInput)?;
            let response = match outcome {
                RecoveryActionOutcome::Application {
                    recovery_application_id,
                    application_status,
                    replayed,
                } => evertrace_protocol::response::RecoveryActionResponse {
                    recovery_application_id: Some(recovery_application_id),
                    application_status: Some(application_status),
                    replayed,
                    unsupported_reason: None,
                },
                RecoveryActionOutcome::Unsupported(_) => {
                    evertrace_protocol::response::RecoveryActionResponse {
                        recovery_application_id: None,
                        application_status: None,
                        replayed: false,
                        unsupported_reason: Some(
                            evertrace_protocol::response::RecoveryUnsupportedReason::UnsupportedApplicationKind,
                        ),
                    }
                }
            };
            Ok(evertrace_protocol::response::Response::RecoveryAction(response))
        }
    }));

    let unsupported_request_id = RequestId::new_v7();
    let unsupported = request_recovery(
        &socket,
        "s17-client",
        unsupported_request_id,
        evertrace_protocol::command::RequestRecoveryCommand {
            recovery_bundle_id: bundle_id,
            target_worktree_instance_id: worktree_id,
            application_kind: RecoveryApplicationKind::FileRestore,
        },
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(
        unsupported.unsupported_reason,
        Some(evertrace_protocol::response::RecoveryUnsupportedReason::UnsupportedApplicationKind)
    );
    assert_eq!(handle.project().await.unwrap().frontier, frontier_before);
    assert_eq!(
        fs::read(worktree_path.join("tracked.txt")).unwrap(),
        b"before\n"
    );

    let request_id = RequestId::new_v7();
    fs::write(worktree_path.join("unrelated.txt"), b"unrelated\n").unwrap();
    fs::write(worktree_path.join("other.txt"), b"other-staged\n").unwrap();
    git(&worktree_path, &["add", "--", "other.txt"]);
    git(
        &worktree_path,
        &["commit", "--quiet", "-m", "unrelated-head-change"],
    );
    let action_request = evertrace_protocol::command::RequestRecoveryCommand {
        recovery_bundle_id: bundle_id,
        target_worktree_instance_id: worktree_id,
        application_kind: RecoveryApplicationKind::Patch,
    };
    let applied = request_recovery(
        &socket,
        "s17-client",
        request_id,
        action_request.clone(),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let recovery_application_id = applied.recovery_application_id.unwrap();
    let application_status = applied.application_status.unwrap();
    let replayed = applied.replayed;
    assert_eq!(recovery_application_id.as_uuid(), request_id.as_uuid());
    assert_eq!(application_status, RecoveryApplicationStatus::Applied);
    assert!(!replayed);
    assert_eq!(
        fs::read(worktree_path.join("tracked.txt")).unwrap(),
        b"after\n"
    );
    assert_eq!(
        fs::read(worktree_path.join("unrelated.txt")).unwrap(),
        b"unrelated\n"
    );
    assert_eq!(
        fs::read(worktree_path.join("other.txt")).unwrap(),
        b"other-staged\n"
    );
    let projection_after = handle.project().await.unwrap();
    let recovery = RecoveryCurrentView::from_snapshot(&projection_after).unwrap();
    let recorded = &recovery.state.applications[&recovery_application_id];
    assert_eq!(
        recorded.application_status,
        RecoveryApplicationStatus::Applied
    );
    assert!(!recorded.has_complete_recorded_lineage_transfer_receipts());
    assert_ne!(recorded.pre_application_snapshot_id, snapshot_id);
    assert_eq!(recorded.input_source_observation_ids.len(), 1);
    assert_eq!(recorded.result_source_observation_ids.len(), 1);
    let forged_result = evertrace_domain::ids::SourceObservationId::from_digest([0xf1; 32]);
    let mut forged_application = recorded.clone();
    forged_application.revision_id = RevisionId::new_v7();
    forged_application.parent_revision_id = Some(recorded.revision_id);
    forged_application
        .result_source_observation_ids
        .push(forged_result);
    forged_application.result_source_observation_ids.sort();
    forged_application
        .verifier_receipts
        .push(RecoveryVerifierReceipt {
            verification_revision: 2,
            verifier_version: 1,
            result_source_observation_id: forged_result,
            post_application_snapshot_id: recorded.post_application_snapshot_id.unwrap(),
            outcome: RecoveryVerificationOutcome::NotApplied,
        });
    forged_application.created_at_us += 1;
    let forged_frontier = projection_after.frontier;
    assert!(
        handle
            .commit(
                JournalCommand::new(
                    CommandId::new_v7(),
                    vec![JournalEventDraft::runtime(
                        forged_application.created_at_us,
                        [7; 32],
                        "s17-supervised-recovery-v1",
                        JournalPayload::RecoveryApplicationRecorded(Box::new(forged_application,)),
                    )],
                )
                .unwrap(),
                recorded.created_at_us + 1,
            )
            .await
            .is_err()
    );
    assert_eq!(handle.project().await.unwrap().frontier, forged_frontier);
    let evidence =
        evertrace_store::RecoveryEvidenceCurrentView::from_snapshot(&projection_after).unwrap();
    let input_receipt = evidence
        .receipt_for_observation(recorded.input_source_observation_ids[0])
        .unwrap();
    let result_receipt = evidence
        .receipt_for_observation(recorded.result_source_observation_ids[0])
        .unwrap();
    assert!(input_receipt.spool_byte_range.start < input_receipt.spool_byte_range.end);
    assert!(result_receipt.spool_byte_range.start < result_receipt.spool_byte_range.end);
    assert!(input_receipt.spool_byte_range.end <= result_receipt.spool_byte_range.start);
    assert_eq!(input_receipt.source_sequence_origin, Some(1));
    assert_eq!(input_receipt.close_watermark, None);
    assert_eq!(result_receipt.source_sequence_origin, Some(1));
    assert_eq!(result_receipt.close_watermark, Some(2));
    assert_eq!(
        input_receipt.adapter_manifest_ref,
        result_receipt.adapter_manifest_ref
    );
    assert_eq!(input_receipt.adapter_manifest_ref.len(), 64);
    assert!(
        input_receipt
            .adapter_manifest_ref
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );
    let segmentation =
        evertrace_store::projections::SegmentationCurrentView::from_snapshot(&projection_after)
            .unwrap();
    let lane = segmentation
        .lane(recorded.execution_lane_id.unwrap())
        .unwrap();
    let capture_receipt = segmentation
        .receipt(recorded.capture_receipt_revision_id.unwrap())
        .unwrap();
    assert_eq!(lane.terminal_kind, Some(TerminalKind::Normal));
    assert!(lane.finalized);
    assert_eq!(capture_receipt.coverage_level, CoverageLevel::Full);
    assert_eq!(capture_receipt.source_coverage, SourceCoverage::Complete);
    assert_eq!(
        capture_receipt.pairing_integrity,
        PairingIntegrity::Complete
    );
    assert_eq!(
        capture_receipt.payload_integrity,
        PayloadIntegrity::Complete
    );
    let admitted_revision = projection_after
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("recovery_application_revision"))
        .filter_map(|row| row.payload_json.as_deref())
        .filter_map(|payload| serde_json::from_str::<JournalPayload>(payload).ok())
        .find_map(|payload| match payload {
            JournalPayload::RecoveryApplicationRecorded(value)
                if value.recovery_application_id == recovery_application_id
                    && value.parent_revision_id.is_none() =>
            {
                Some(value.revision_id.to_string())
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(
        evidence
            .observation(recorded.input_source_observation_ids[0])
            .unwrap()
            .correlation
            .strong_gate_receipt_ref
            .as_deref(),
        Some(admitted_revision.as_str())
    );
    let mut application_history = projection_after
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("recovery_application_revision"))
        .filter_map(|row| row.payload_json.as_deref())
        .filter_map(|payload| serde_json::from_str::<JournalPayload>(payload).ok())
        .filter_map(|payload| match payload {
            JournalPayload::RecoveryApplicationRecorded(value)
                if value.recovery_application_id == recovery_application_id =>
            {
                Some(value.application_status)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    application_history.sort_by_key(|status| match status {
        RecoveryApplicationStatus::Unknown => 0,
        RecoveryApplicationStatus::Applied => 1,
        RecoveryApplicationStatus::PartiallyApplied => 2,
        RecoveryApplicationStatus::Failed => 3,
    });
    assert_eq!(
        application_history,
        vec![
            RecoveryApplicationStatus::Unknown,
            RecoveryApplicationStatus::Unknown,
            RecoveryApplicationStatus::Applied,
        ]
    );

    let replay = request_recovery(
        &socket,
        "s17-client",
        request_id,
        action_request,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert!(replay.replayed);
    assert_eq!(
        handle.project().await.unwrap().frontier,
        projection_after.frontier
    );
    assert_eq!(
        fs::read(worktree_path.join("tracked.txt")).unwrap(),
        b"after\n"
    );
    let repository_view = evertrace_store::repository::RepositoryCurrentView::from_snapshot(
        &handle.project().await.unwrap(),
    )
    .unwrap();
    let mut archived = repository_view.worktrees[&worktree_id].clone();
    archived.predecessor_revision = Some(archived.worktree_revision);
    archived.worktree_revision += 1;
    archived.lifecycle = WorktreeLifecycle::Archived;
    archived.recorded_at_us += 1;
    let archived_at = archived.recorded_at_us;
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    archived_at,
                    [7; 32],
                    "s17-supervised-recovery-v1",
                    JournalPayload::WorktreeInstanceRecorded(Box::new(archived)),
                )],
            )
            .unwrap(),
            archived_at,
        )
        .await
        .unwrap();
    let archived_projection = handle.project().await.unwrap();
    assert_eq!(
        RecoveryCurrentView::from_snapshot(&archived_projection)
            .unwrap()
            .state
            .applications[&recovery_application_id]
            .application_status,
        RecoveryApplicationStatus::Applied
    );
    shutdown_tx.send(true).unwrap();
    server_task.await.unwrap().unwrap();
    handle.shutdown().await.unwrap();
    writer_task.await.unwrap().unwrap();

    let restarted = JournalWriter::open(&store_root).await.unwrap();
    assert_eq!(restarted.project().await.unwrap(), archived_projection);
    assert_eq!(
        restarted.full_projection().await.unwrap(),
        archived_projection
    );
}

#[test]
fn recovery_wire_request_has_no_caller_authority_fields() {
    let request_id = RequestId::new_v7();
    let bundle_id = RecoveryBundleId::new_v7();
    let worktree_id = WorktreeId::new_v7();
    let value = serde_json::json!({
        "request_id": request_id,
        "command": {
            "request_recovery": {
                "recovery_bundle_id": bundle_id,
                "target_worktree_instance_id": worktree_id,
                "application_kind": "patch"
            }
        }
    });
    serde_json::from_value::<evertrace_protocol::command::CommandEnvelope>(value.clone()).unwrap();
    for (field, forged) in [
        ("ticket", serde_json::json!("caller-ticket")),
        ("status", serde_json::json!("applied")),
        (
            "selected_item_refs",
            serde_json::json!(["git:tracked_diff"]),
        ),
        ("success", serde_json::json!(true)),
    ] {
        let mut forged_value = value.clone();
        forged_value["command"]["request_recovery"][field] = forged;
        assert!(
            serde_json::from_value::<evertrace_protocol::command::CommandEnvelope>(forged_value)
                .is_err()
        );
    }
}
