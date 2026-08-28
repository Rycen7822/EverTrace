use std::str::FromStr;

use evertrace_capture::{CasStore, DeviceKeyStore, protect};
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
        AttemptId, CasId, CommandId, SourceReceiptId, TaskId, WorkBindingRevisionId, WorkstreamId,
        WorktreeSnapshotId,
    },
    repository::{
        FilesystemIdentity, GitObjectFormat, GitOperation, GitRegistrationState, PathObservation,
        RepositoryInstance, SnapshotCaptureStatus, WorktreeInstance, WorktreeKind,
        WorktreeLifecycle, WorktreeSnapshot,
    },
    revision::RevisionId,
    semantic::{EvidenceCompleteness, ParserStatus, ResultScope, VerifierStatus},
    work::{
        ArtifactActor, ArtifactDerivability, ArtifactPayloadStatus, ArtifactRetention,
        ArtifactRevision, ArtifactScope, AssignmentStatus, ContractField, MultiCasMetricPolicy,
        PhaseContract, PhaseKind, PrimaryWorkBinding, RunContractValidity, RunExecutionStatus,
        RunObservability, SeedPolicy, StrategyContract, Task, TaskIdentityConfidence,
        TaskLifecycle, TaskScopeMembership, VariableDeclaration, WorkArtifact, WorkArtifactKind,
        WorkBindingRevision, Workstream, WorkstreamStatus,
    },
};
use evertrace_engine::{
    PhysicalNormalizer,
    autoresearch::{
        ArtifactService, AutoresearchCommandContext, AutoresearchError, AutoresearchResolution,
        ResultEvidenceService, ResultParseRequest, RunCreateInput, compatible_result_cohort,
        create_experiment_run, run_command,
    },
    work::attempt::new_attempt,
};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload, JournalWriter,
    NormalizationWatermark, SourceIngestWatermark, projections::AutoresearchCurrentView,
};
use tempfile::TempDir;

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
async fn real_two_table_batch_rebuild_restart_and_fail_closed_relations() {
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
        vec!["evertrace_journal", "evertrace_objects"]
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

#[test]
fn recovery_application_recording_is_not_a_product_payload() {
    assert!(
        serde_json::from_str::<JournalPayload>(
            r#"{"kind":"recovery_application_recorded","value":{}}"#
        )
        .is_err()
    );
}
