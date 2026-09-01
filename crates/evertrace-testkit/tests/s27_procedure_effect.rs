use std::{
    collections::{BTreeSet, HashSet},
    str::FromStr,
};

use evertrace_domain::{
    ids::{CommandId, RepositoryId, TaskId, WorktreeId, WorktreeSnapshotId},
    procedure::{
        ProcedureActions, ProcedureContextAnchor, ProcedureDone, ProcedureDraft, ProcedureEffect,
        ProcedureEffectContext, ProcedureEffectEvidenceClass, ProcedureKind, ProcedureLocalContext,
        ProcedurePublicationState, ProcedureRevision, ProcedureScope, ProcedureUsagePhase,
        ProcedureWhen,
    },
    query::{
        AnswerShape, FacetParseStatus, GateStatus, LifecycleBoundary, Polarity, QueryFacetSet,
        RetrievalBudget, RetrievalLayer, SearchContext, SearchIntent, SuppressionSnapshot,
        TemporalMode,
    },
    revision::RevisionId,
    semantic::{
        ConstraintBinding, ConstraintExpr, ConstraintField, ConstraintState, ConstraintValue,
    },
};
use evertrace_engine::procedure::{
    ProcedureCandidate, ProcedureDecision, ProcedurePhase, ProcedureUsageCurrentView,
    procedure_effect_base_layer, procedure_effect_gate, route_procedures_with_effects,
    route_procedures_with_passed_effects_diagnostic, route_procedures_with_quarantine,
};
use evertrace_store::{JournalCommand, JournalEventDraft, JournalWriter};

fn context(revision_id: RevisionId) -> ProcedureEffectContext {
    let mut bindings = vec![
        ConstraintBinding {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text("verify".into()),
        },
        ConstraintBinding {
            field: ConstraintField::VerifierState,
            value: ConstraintValue::Text("passed".into()),
        },
    ];
    bindings.sort_by_key(|binding| binding.field);
    ProcedureEffectContext::compile(
        revision_id,
        TaskId::new_v7(),
        ProcedureContextAnchor::Repository {
            repository_id: RepositoryId::new_v7(),
            worktree_id: WorktreeId::new_v7(),
            worktree_snapshot_id: WorktreeSnapshotId::new_v7(),
            worktree_lineage: "tree-1".into(),
        },
        &BTreeSet::from([ConstraintField::Phase]),
        &ConstraintState { bindings },
        ProcedureUsagePhase::AtEntry,
        Some("verifier_failed".into()),
        "rust-1.97.1".into(),
        "model-1".into(),
        "harness-1".into(),
        "algorithm-1".into(),
        500,
        "acceptance-boundary-1".into(),
    )
    .unwrap()
}

#[test]
fn context_fingerprint_is_closed_complete_and_operand_filtered() {
    let base = context(RevisionId::new_v7());
    let fields = BTreeSet::from([ConstraintField::Phase]);
    assert!(base.complete_for(&fields));
    assert_eq!(base.operands.len(), 1);
    assert_eq!(base, base.clone());
    assert_eq!(
        base.fingerprint().unwrap(),
        base.clone().fingerprint().unwrap()
    );

    let mut unrelated = ConstraintState {
        bindings: base.operands.clone(),
    };
    unrelated.bindings.push(ConstraintBinding {
        field: ConstraintField::VerifierState,
        value: ConstraintValue::Text("failed".into()),
    });
    unrelated.bindings.sort_by_key(|binding| binding.field);
    let rebuilt = ProcedureEffectContext::compile(
        base.procedure_revision_id,
        base.task_id,
        base.anchor.clone(),
        &BTreeSet::from([ConstraintField::Phase]),
        &unrelated,
        base.phase_kind,
        base.failure_signature.clone(),
        base.toolchain.clone(),
        base.model_revision.clone(),
        base.harness_revision.clone(),
        base.algorithm_revision.clone(),
        base.budget,
        base.acceptance_boundary.clone(),
    )
    .unwrap();
    assert_eq!(base.fingerprint().unwrap(), rebuilt.fingerprint().unwrap());

    let mut fingerprints = HashSet::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut value = base.clone();
            value.$field = $value;
            value.validate().unwrap();
            fingerprints.insert(value.fingerprint().unwrap());
        }};
    }
    changed!(procedure_revision_id, RevisionId::new_v7());
    changed!(task_id, TaskId::new_v7());
    changed!(phase_kind, ProcedureUsagePhase::InProgress);
    changed!(failure_signature, Some("other_failure".into()));
    changed!(toolchain, "rust-other".into());
    changed!(model_revision, "model-other".into());
    changed!(harness_revision, "harness-other".into());
    changed!(algorithm_revision, "algorithm-other".into());
    changed!(budget, 501);
    changed!(acceptance_boundary, "acceptance-boundary-2".into());
    let mut anchor = base.clone();
    let ProcedureContextAnchor::Repository {
        worktree_lineage, ..
    } = &mut anchor.anchor
    else {
        unreachable!()
    };
    *worktree_lineage = "tree-2".into();
    fingerprints.insert(anchor.fingerprint().unwrap());
    assert_eq!(fingerprints.len(), 11);
    assert!(!fingerprints.contains(&base.fingerprint().unwrap()));

    let incomplete = ProcedureEffectContext::compile(
        base.procedure_revision_id,
        base.task_id,
        ProcedureContextAnchor::NonRepository {
            fixture_refs: vec!["artifact-revision-1".into()],
        },
        &BTreeSet::from([ConstraintField::Phase]),
        &ConstraintState {
            bindings: base.operands.clone(),
        },
        base.phase_kind,
        None,
        "unknown".into(),
        base.model_revision.clone(),
        base.harness_revision.clone(),
        base.algorithm_revision.clone(),
        base.budget,
        base.acceptance_boundary.clone(),
    )
    .unwrap();
    assert!(!incomplete.complete_for(&fields));
    assert!(!incomplete.exact_compatible(&incomplete, &fields));

    let mut no_failure = base.clone();
    no_failure.failure_signature = None;
    no_failure.validate().unwrap();
    assert!(no_failure.complete_for(&fields));
    assert!(!no_failure.complete_for(&BTreeSet::from([
        ConstraintField::Phase,
        ConstraintField::VerifierState,
    ])));
    assert!(!no_failure.complete_for(&BTreeSet::from([
        ConstraintField::Phase,
        ConstraintField::FailureSignature,
    ])));
}

#[test]
fn context_fingerprint_has_an_explicit_v1_known_answer() {
    let fields = BTreeSet::from([ConstraintField::Phase]);
    let value = ProcedureEffectContext::compile(
        RevisionId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a11").unwrap(),
        TaskId::from_str("task:01890f47-6a4a-7cc1-98b9-01890f476a12").unwrap(),
        ProcedureContextAnchor::Repository {
            repository_id: RepositoryId::from_str("repo:01890f47-6a4a-7cc1-98b9-01890f476a13")
                .unwrap(),
            worktree_id: WorktreeId::from_str("wt:01890f47-6a4a-7cc1-98b9-01890f476a14").unwrap(),
            worktree_snapshot_id: WorktreeSnapshotId::from_str(
                "wts:01890f47-6a4a-7cc1-98b9-01890f476a15",
            )
            .unwrap(),
            worktree_lineage: "wt:01890f47-6a4a-7cc1-98b9-01890f476a14".into(),
        },
        &fields,
        &ConstraintState {
            bindings: vec![ConstraintBinding {
                field: ConstraintField::Phase,
                value: ConstraintValue::Text("at_entry".into()),
            }],
        },
        ProcedureUsagePhase::AtEntry,
        None,
        "rust-1.97.1".into(),
        "model-v1".into(),
        "harness-v1".into(),
        "algorithm-v1".into(),
        500,
        "acceptance-v1".into(),
    )
    .unwrap();
    assert!(value.complete_for(&fields));
    assert_eq!(
        evertrace_domain::evidence::hex(&value.fingerprint().unwrap()),
        "821114a14b01ab9442942af9c808480b944633f98b6bb695ac5c8f0eb1f7f912"
    );
}

mod controlled_projection_proof {
    use super::*;
    use evertrace_capture::{
        CaptureRecordInput, CaptureRuntime, CasStore, DeviceKeyStore, RUNTIME_SNAPSHOT_VERSION,
        RecallCueGateMode, RecoveryGateMode, RuntimeSnapshot,
    };
    use evertrace_domain::semantic::{
        ProcedureProposalPayload, ProposalCreatedBy, ProposalEligibility, ProposalOperation,
        ProposalPayload, ProposalTargetId, ProposalTargetKind,
    };
    use evertrace_domain::{
        config::{GlobalPromotionConfig, PromotionLevel},
        evidence::{
            CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
            CorrelationField, CorrelationFieldClaim, EvidenceSourceKind, HostCorrelationEvidence,
            IdentityStrength, ObservationRole, SourceInstanceId, SourceRecordIdentity,
            SourceRevision, SourceRevisionMode, SourceRole, source_observation_id,
            source_receipt_id,
        },
        ids::{
            CasId, CompetingAttemptGroupId, IntegrationEventId, ProcedureUsageId, RequestId,
            ResultEvidenceId, SourceReceiptId, WorkBindingRevisionId, WorkstreamId,
        },
        procedure::{
            ProcedureCorrelationState, ProcedureEligibilityEvidence, ProcedureLocalContext,
            ProcedureTruth, ProcedureUsagePhase, ProcedureUsageRevision,
            ProcedureUsageRouteDecision, ProcedureUsageStage,
        },
        repository::{
            FilesystemIdentity, GitObjectFormat, GitOperation, GitRegistrationState,
            IntegrationEvent, IntegrationKind, LineageAssessment, PathObservation,
            RepositoryInstance, SnapshotCaptureStatus, WorktreeInstance, WorktreeKind,
            WorktreeLifecycle, WorktreeSnapshot,
        },
        semantic::{
            EvidenceCompleteness, MetricValue, ParserReceipt, ParserStatus, ResultEvidence,
            ResultScope, VerifierReceipt, VerifierStatus,
        },
        work::{
            AssignmentStatus, AttemptAdoptionStatus, AttemptVerification,
            ComparisonExecutionBinding, CompetingAttemptGroup, CompetingConflictKind,
            CompetingResolutionStatus, ContractField, ControlledRunSourceEnvelope, MetricDirection,
            MultiCasMetricPolicy, PhaseContract, PhaseKind, PrimaryWorkBinding,
            RunContractValidity, RunExecutionStatus, RunObservability, SeedPolicy,
            StrategyContract, Task, TaskIdentityConfidence, TaskLifecycle, TaskScopeMembership,
            VariableDeclaration, WorkBindingRevision, Workstream, WorkstreamStatus,
        },
    };
    use evertrace_engine::{
        EvidenceIngestor, HumanActionOutcome, HumanGovernanceService, HumanSurface,
        autoresearch::{
            AutoresearchCommandContext, ControlledRunCommand, ControlledRunRequest,
            ControlledRunResolver, RunCreateInput, create_experiment_run,
        },
        normalize::PhysicalNormalizer,
        procedure::{
            ProcedureAcceptanceContext, ProcedureAcceptanceResolution, accept_procedure,
            compile_controlled_effect,
        },
        semantic::{
            ProposalCommandContext, ProposalResolution, RevisionProposalService,
            SubmitProposalRequest,
        },
        spawn_writer,
        work::{
            WorkCommandContext, activate_episode, attempt::new_attempt, episode::new_episode,
            link_attempt_to_episode,
        },
    };
    use evertrace_store::{
        AttemptCurrentView, JournalPayload, ObjectRow, ObjectRowKind, ProjectionSnapshot,
        SemanticCurrentView, SourceKind,
    };
    use std::path::Path;

    struct Fixture {
        snapshot: ProjectionSnapshot,
        procedure_revision_id: RevisionId,
        pairs: Vec<ControlledProcedurePair>,
    }

    #[derive(Clone)]
    struct ControlledProcedurePair {
        procedure_experiment_run_id: evertrace_domain::ids::ExperimentRunId,
        procedure_result_revision_id: RevisionId,
        control_experiment_run_id: evertrace_domain::ids::ExperimentRunId,
        control_result_revision_id: RevisionId,
    }

    fn receipt(byte: u8) -> SourceReceiptId {
        SourceReceiptId::from_str(&format!("src:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn binding(exposure: Option<RevisionId>) -> ComparisonExecutionBinding {
        ComparisonExecutionBinding {
            binding_version: 1,
            toolchain_revision: "rust-1.97.1".into(),
            model_revision: "model-v1".into(),
            harness_revision: "harness-v1".into(),
            algorithm_revision: "algorithm-v1".into(),
            budget: 100,
            procedure_exposure_revision_id: exposure,
            metric_direction: MetricDirection::HigherIsBetter,
            metric_unit: "ratio".into(),
            positive_delta_threshold: "0.05".into(),
            negative_delta_threshold: "0.03".into(),
        }
    }

    fn runtime_snapshot(root: &Path) -> RuntimeSnapshot {
        RuntimeSnapshot {
            snapshot_version: RUNTIME_SNAPSHOT_VERSION,
            generation: 1,
            device_key_dir: root.join("keys"),
            cas_dir: root.join("cas"),
            spool_dir: root.join("spool"),
            main_high_watermark_bytes: 2 << 20,
            main_low_watermark_bytes: 64 << 10,
            max_main_files: 16,
            emergency_slots: 2,
            recovery_gate: RecoveryGateMode::Disabled,
            recovery_socket_path: root.join("runtime/evertraced-v1.sock"),
            recovery_preflight_timeout_ms: 250,
            effective_config_hash: [27; 32],
            recovery_adapter_manifest_id: None,
            recovery_classifier_revision: 1,
            recovery_max_bundle_bytes: 4 << 20,
            recovery_max_untracked_file_bytes: 1 << 20,
            recovery_max_untracked_total_bytes: 2 << 20,
            recall_cue_gate: RecallCueGateMode::Disabled,
            recall_cue_adapter_manifest_id: None,
            recall_cues: Vec::new(),
        }
    }

    fn capture_input(
        record: &str,
        sequence: u64,
        role: ObservationRole,
        payload: Vec<u8>,
    ) -> CaptureRecordInput {
        let fields = [
            CorrelationField::HostInstanceId,
            CorrelationField::HostTraceLineageId,
            CorrelationField::HostLaneKey,
            CorrelationField::CanonicalEventFamily,
            CorrelationField::NativeRequestId,
            CorrelationField::PhysicalExecutionOrdinal,
        ];
        CaptureRecordInput {
            spool_record_id: Some(format!("spool-{record}")),
            source_observation_id_hint: None,
            source_instance_id: "s27-controlled-source".into(),
            source_revision: "revision-1".into(),
            source_record_identity: Some(record.into()),
            identity_strength: Some(IdentityStrength::StableNative),
            source_kind: EvidenceSourceKind::CodexExecJsonl,
            identity_domain: "s27-controlled-v1".into(),
            source_ref: "controlled-run-source".into(),
            session_ref: "session-s27".into(),
            turn_ref: Some("turn-s27".into()),
            tool_ref: Some("tool-s27".into()),
            source_sequence: sequence,
            source_sequence_origin: Some(1),
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
                host_instance_id: Some("host-s27".into()),
                host_trace_lineage_id: Some("trace-s27".into()),
                host_lane_key: Some("lane-s27".into()),
                canonical_event_family: Some(CanonicalEventFamily::Launch),
                native_request_id: Some("request-s27-controlled".into()),
                physical_execution_ordinal: Some(1),
                pairing_role: role,
                field_provenance: fields
                    .into_iter()
                    .map(|field| CorrelationFieldClaim {
                        field,
                        source_ref: "controlled-run-source".into(),
                        evidence_ref: format!("evidence-{field:?}"),
                    })
                    .collect(),
                adapter_manifest_ref: "adapter-s27".into(),
                adapter_revision: 1,
                strong_gate_receipt_ref: Some("strong-s27".into()),
                admission: CorrelationAdmission::ExactCapable,
                partial_correlation_ref: None,
                possible_duplicate_group_id: None,
            },
            scope_effect_claims: Vec::new(),
            lifecycle: None,
            unsupported_record_classification: None,
            source_role: SourceRole::Tool,
            content_trust: ContentTrust::Observed,
            capture_completeness: CaptureCompleteness::Complete,
            surface_eligible: true,
            adapter_revision: 1,
            adapter_manifest_ref: "adapter-s27".into(),
            eligible_event_manifest_ref: "eligible-s27".into(),
            parser_revision: 1,
            canonicalization_revision: 1,
            event_time_us: Some(sequence as i64),
            raw_payload: payload,
        }
    }

    fn proposal_context(at: i64) -> ProposalCommandContext {
        ProposalCommandContext {
            command_id: CommandId::new_v7(),
            occurred_at_us: at,
            effective_config_hash: [27; 32],
            algorithm_revision: "s27-controlled-v1".into(),
        }
    }

    fn eligibility(
        observation: evertrace_domain::ids::SourceObservationId,
    ) -> ProcedureEligibilityEvidence {
        ProcedureEligibilityEvidence {
            independent_successes: 3,
            retrospective_contrasts: 1,
            objective_verifier_present: true,
            evidence_complete: true,
            non_triviality_passed: true,
            when_done_contract_complete: true,
            unresolved_contradictions: 0,
            redundancy_check_passed: true,
            distinct_applicability_contexts: 2,
            confirmed_harm: 0,
            unresolved_suspected_harm: 0,
            applicability_expr_complete: true,
            verifier_observation_ref: Some(observation),
        }
    }

    async fn capture_and_ingest(
        snapshot: &RuntimeSnapshot,
        store_root: &Path,
        inputs: Vec<CaptureRecordInput>,
    ) {
        let mut runtime = CaptureRuntime::open(snapshot.clone()).unwrap();
        for input in inputs {
            runtime.capture(input).unwrap();
        }
        drop(runtime);
        let writer = evertrace_engine::open_writer(store_root).await.unwrap();
        let (handle, task) = spawn_writer(writer, 8).unwrap();
        let ingestor = EvidenceIngestor::new(
            snapshot.clone(),
            handle.clone(),
            [27; 32],
            "s27-controlled-v1",
        )
        .unwrap();
        ingestor.drain_once().await.unwrap();
        handle.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    }

    async fn capture_operation(
        snapshot: &RuntimeSnapshot,
        store_root: &Path,
        inputs: Vec<CaptureRecordInput>,
        observation_ids: &[evertrace_domain::ids::SourceObservationId],
        at: i64,
    ) -> evertrace_domain::evidence::Operation {
        capture_and_ingest(snapshot, store_root, inputs).await;
        let mut writer = JournalWriter::open(store_root).await.unwrap();
        let projected = writer.project().await.unwrap();
        let observations = projected
            .data_rows()
            .filter_map(|row| {
                let payload =
                    serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()?;
                match payload {
                    JournalPayload::SourceObservationRecorded(value)
                        if observation_ids.contains(&value.source_observation_id) =>
                    {
                        Some(*value)
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        let physical = PhysicalNormalizer::new(1)
            .unwrap()
            .normalize(&observations, None)
            .unwrap();
        assert_eq!(physical.operations.len(), 1);
        writer
            .commit(
                &physical
                    .journal_command(CommandId::new_v7(), at, [27; 32], "s27-controlled-v1")
                    .unwrap(),
                at,
            )
            .await
            .unwrap();
        physical.operations[0].clone()
    }

    fn journal_command(at: i64, payloads: Vec<JournalPayload>) -> JournalCommand {
        JournalCommand::new(
            CommandId::new_v7(),
            payloads
                .into_iter()
                .map(|payload| {
                    JournalEventDraft::runtime(at, [27; 32], "s27-controlled-v1", payload)
                })
                .collect(),
        )
        .unwrap()
    }

    fn captured_ids(record: &str) -> (evertrace_domain::ids::SourceObservationId, SourceReceiptId) {
        let instance = SourceInstanceId::parse("s27-controlled-source").unwrap();
        let revision = SourceRevision::parse("revision-1").unwrap();
        let record = SourceRecordIdentity::parse(record).unwrap();
        (
            source_observation_id(&instance, &revision, &record).unwrap(),
            source_receipt_id(&instance, &revision, &record).unwrap(),
        )
    }

    fn latest_attempt(
        snapshot: &ProjectionSnapshot,
        attempt_id: evertrace_domain::ids::AttemptId,
    ) -> evertrace_domain::work::Attempt {
        snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("attempt"))
            .filter_map(|row| {
                let payload =
                    serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()?;
                match payload {
                    JournalPayload::AttemptRecorded(value) if value.attempt_id == attempt_id => {
                        Some((row.source_event_seq, *value))
                    }
                    _ => None,
                }
            })
            .max_by_key(|(seq, _)| *seq)
            .map(|(_, value)| value)
            .unwrap()
    }

    #[derive(Clone, Copy)]
    struct CaptureSpec<'a> {
        name: &'a str,
        source_sequence: u64,
        physical_ordinal: u32,
        at: i64,
    }

    async fn bind_operation(
        writer: &mut JournalWriter,
        attempt_id: evertrace_domain::ids::AttemptId,
        operation_id: evertrace_domain::ids::OperationId,
        evidence_id: evertrace_domain::ids::SourceObservationId,
        run_id: Option<evertrace_domain::ids::ExperimentRunId>,
        at: i64,
    ) {
        let current = latest_attempt(&writer.project().await.unwrap(), attempt_id);
        let binding_id = WorkBindingRevisionId::new_v7();
        let binding = WorkBindingRevision {
            work_binding_revision_id: binding_id,
            operation_id,
            revision_generation: 1,
            predecessor_revision_id: None,
            primary_binding: PrimaryWorkBinding {
                task_id: Some(current.task_id),
                workstream_id: Some(current.workstream_id),
                attempt_id: Some(attempt_id),
                experiment_run_id: run_id,
                ..Default::default()
            },
            secondary_bindings: Vec::new(),
            scope_effect_refs: Vec::new(),
            assignment_status: AssignmentStatus::Resolved,
            evidence_refs: vec![evidence_id.to_string()],
            resolver_version: 1,
        };
        let mut next = current.clone();
        next.revision_id = RevisionId::new_v7();
        next.predecessor_revision_id = Some(current.revision_id);
        next.revision_generation += 1;
        next.work_binding_revision_refs.push(binding_id);
        next.work_binding_revision_refs.sort();
        next.source_watermark += 1;
        current.validate_successor(&next).unwrap();
        writer
            .commit(
                &journal_command(
                    at,
                    vec![
                        JournalPayload::WorkBindingRecorded(Box::new(binding)),
                        JournalPayload::AttemptRecorded(Box::new(next)),
                    ],
                ),
                at,
            )
            .await
            .unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_controlled_declaration(
        runtime: &RuntimeSnapshot,
        store_root: &Path,
        resolver: &ControlledRunResolver,
        attempt_id: evertrace_domain::ids::AttemptId,
        procedure_revision_id: RevisionId,
        snapshot_id: WorktreeSnapshotId,
        exposure: Option<RevisionId>,
        capture: CaptureSpec<'_>,
    ) -> (
        evertrace_domain::work::ExperimentRun,
        JournalCommand,
        evertrace_domain::ids::SourceObservationId,
    ) {
        let envelope = ControlledRunSourceEnvelope::Launch {
            version: 1,
            attempt_id,
            procedure_revision_id,
            code_snapshot_id: snapshot_id,
            data_fingerprint: "fixture-v1".into(),
            normalized_config: vec![ContractField {
                name: "dataset".into(),
                value: "fixture-v1".into(),
            }],
            variable_declaration: VariableDeclaration {
                varied: Vec::new(),
                fixed: vec!["dataset".into()],
                uncontrolled: Vec::new(),
            },
            seed_policy: SeedPolicy::Fixed,
            seed_values: vec!["7".into()],
            nondeterministic: false,
            metric_definition: "accuracy".into(),
            metric_extractor_version: "evertrace.result_metric.v1".into(),
            multi_cas_metric_policy: MultiCasMetricPolicy::RejectMultipleParsed,
            environment_fingerprint: "env-v1".into(),
            binding: Box::new(binding(exposure)),
            started_at_us: capture.at,
        };
        let intent_record = format!("{}-launch", capture.name);
        let result_record = format!("{}-launch-ack", capture.name);
        let request = format!("{}-launch-operation", capture.name);
        let mut intent = capture_input(
            &intent_record,
            capture.source_sequence,
            ObservationRole::Intent,
            toml::to_string(&envelope).unwrap().into_bytes(),
        );
        intent.correlation.native_request_id = Some(request.clone());
        intent.correlation.physical_execution_ordinal = Some(capture.physical_ordinal);
        let mut result = capture_input(
            &result_record,
            capture.source_sequence + 1,
            ObservationRole::Result,
            b"launch accepted".to_vec(),
        );
        result.correlation.native_request_id = Some(request);
        result.correlation.physical_execution_ordinal = Some(capture.physical_ordinal);
        let (intent_id, _) = captured_ids(&intent_record);
        let (result_id, _) = captured_ids(&result_record);
        let operation = capture_operation(
            runtime,
            store_root,
            vec![intent, result],
            &[intent_id, result_id],
            capture.at,
        )
        .await;
        let mut writer = JournalWriter::open(store_root).await.unwrap();
        bind_operation(
            &mut writer,
            attempt_id,
            operation.operation_id,
            intent_id,
            None,
            capture.at + 1,
        )
        .await;
        let ControlledRunCommand::Declaration { run, command, .. } = resolver
            .declare(
                &writer.project().await.unwrap(),
                ControlledRunRequest {
                    attempt_id,
                    procedure_revision_id,
                    source_observation_id: intent_id,
                },
                AutoresearchCommandContext {
                    command_id: CommandId::new_v7(),
                    occurred_at_us: capture.at + 2,
                    effective_config_hash: [27; 32],
                    algorithm_revision: "s27-controlled-v1",
                },
            )
            .unwrap()
        else {
            panic!("controlled declaration expected")
        };
        assert_eq!(
            run.comparison_execution_binding
                .as_ref()
                .unwrap()
                .procedure_exposure_revision_id,
            exposure
        );
        (*run, command, intent_id)
    }

    #[allow(clippy::too_many_arguments)]
    async fn declare_controlled_run(
        runtime: &RuntimeSnapshot,
        store_root: &Path,
        resolver: &ControlledRunResolver,
        attempt_id: evertrace_domain::ids::AttemptId,
        procedure_revision_id: RevisionId,
        snapshot_id: WorktreeSnapshotId,
        exposure: Option<RevisionId>,
        capture: CaptureSpec<'_>,
    ) -> evertrace_domain::work::ExperimentRun {
        let (run, command, observation_id) = prepare_controlled_declaration(
            runtime,
            store_root,
            resolver,
            attempt_id,
            procedure_revision_id,
            snapshot_id,
            exposure,
            capture,
        )
        .await;
        let mut writer = JournalWriter::open(store_root).await.unwrap();
        writer.commit(&command, capture.at + 2).await.unwrap();
        let frontier = writer.frontier();
        writer.commit(&command, capture.at + 2).await.unwrap();
        assert_eq!(writer.frontier(), frontier);
        assert!(matches!(
            resolver
                .declare(
                    &writer.project().await.unwrap(),
                    ControlledRunRequest {
                        attempt_id,
                        procedure_revision_id,
                        source_observation_id: observation_id,
                    },
                    AutoresearchCommandContext {
                        command_id: CommandId::new_v7(),
                        occurred_at_us: capture.at + 3,
                        effective_config_hash: [27; 32],
                        algorithm_revision: "s27-controlled-v1",
                    },
                )
                .unwrap(),
            ControlledRunCommand::NoDelta
        ));
        run
    }

    async fn complete_controlled_run(
        runtime: &RuntimeSnapshot,
        store_root: &Path,
        resolver: &ControlledRunResolver,
        run: &evertrace_domain::work::ExperimentRun,
        metric: &str,
        capture: CaptureSpec<'_>,
    ) -> (
        evertrace_domain::work::ExperimentRun,
        evertrace_domain::semantic::ResultEvidence,
    ) {
        let envelope = ControlledRunSourceEnvelope::Terminal {
            version: 1,
            run_id: run.run_id,
            ended_at_us: capture.at,
            metric: MetricValue {
                decimal: metric.into(),
                unit: "ratio".into(),
                uncertainty_decimal: None,
            },
            artifact_refs: Vec::new(),
        };
        let intent_record = format!("{}-terminal-intent", capture.name);
        let result_record = format!("{}-terminal-result", capture.name);
        let request = format!("{}-terminal-operation", capture.name);
        let mut intent = capture_input(
            &intent_record,
            capture.source_sequence,
            ObservationRole::Intent,
            b"collect terminal result".to_vec(),
        );
        intent.correlation.native_request_id = Some(request.clone());
        intent.correlation.physical_execution_ordinal = Some(capture.physical_ordinal);
        let mut result = capture_input(
            &result_record,
            capture.source_sequence + 1,
            ObservationRole::Result,
            toml::to_string(&envelope).unwrap().into_bytes(),
        );
        result.correlation.native_request_id = Some(request);
        result.correlation.physical_execution_ordinal = Some(capture.physical_ordinal);
        let (intent_id, _) = captured_ids(&intent_record);
        let (result_id, _) = captured_ids(&result_record);
        let operation = capture_operation(
            runtime,
            store_root,
            vec![intent, result],
            &[intent_id, result_id],
            capture.at,
        )
        .await;
        let mut writer = JournalWriter::open(store_root).await.unwrap();
        bind_operation(
            &mut writer,
            run.attempt_id.unwrap(),
            operation.operation_id,
            result_id,
            Some(run.run_id),
            capture.at + 1,
        )
        .await;
        let ControlledRunCommand::Terminal {
            run: terminal_run,
            result,
            command,
        } = resolver
            .complete(
                &writer.project().await.unwrap(),
                run.run_id,
                result_id,
                AutoresearchCommandContext {
                    command_id: CommandId::new_v7(),
                    occurred_at_us: capture.at + 2,
                    effective_config_hash: [27; 32],
                    algorithm_revision: "s27-controlled-v1",
                },
            )
            .unwrap()
        else {
            panic!("controlled terminal expected")
        };
        writer.commit(&command, capture.at + 2).await.unwrap();
        let frontier = writer.frontier();
        writer.commit(&command, capture.at + 2).await.unwrap();
        assert_eq!(writer.frontier(), frontier);
        assert!(matches!(
            resolver
                .complete(
                    &writer.project().await.unwrap(),
                    run.run_id,
                    result_id,
                    AutoresearchCommandContext {
                        command_id: CommandId::new_v7(),
                        occurred_at_us: capture.at + 3,
                        effective_config_hash: [27; 32],
                        algorithm_revision: "s27-controlled-v1",
                    },
                )
                .unwrap(),
            ControlledRunCommand::NoDelta
        ));
        (*terminal_run, *result)
    }

    fn row(kind: &str, payload: JournalPayload, seq: u64) -> ObjectRow {
        ObjectRow {
            row_id: format!("s27:{kind}:{seq}"),
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
            payload_json: Some(payload.canonical_json().unwrap()),
            source_event_seq: seq,
            projection_generation: 1,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_result(
        attempt: &evertrace_domain::work::Attempt,
        snapshot_id: WorktreeSnapshotId,
        procedure_revision_id: RevisionId,
        byte: u8,
        exposed: bool,
        metric: &str,
        unit: &str,
        uncertainty: Option<&str>,
        binding_override: Option<Option<ComparisonExecutionBinding>>,
    ) -> (evertrace_domain::work::ExperimentRun, ResultEvidence) {
        let comparison_execution_binding = binding_override
            .unwrap_or_else(|| Some(binding(exposed.then_some(procedure_revision_id))));
        let mut run = create_experiment_run(
            attempt,
            RunCreateInput {
                workstream_id: attempt.workstream_id,
                source_receipt_refs: vec![receipt(byte)],
                code_snapshot_id: snapshot_id,
                data_fingerprint: "data-v1".into(),
                normalized_config: vec![ContractField {
                    name: "dataset".into(),
                    value: "fixture-v1".into(),
                }],
                variable_declaration: VariableDeclaration {
                    varied: Vec::new(),
                    fixed: vec!["dataset".into()],
                    uncontrolled: Vec::new(),
                },
                seed_policy: SeedPolicy::Fixed,
                seed_values: vec!["7".into()],
                nondeterministic: false,
                metric_definition: "accuracy".into(),
                metric_extractor_version: "parser-v1".into(),
                multi_cas_metric_policy: MultiCasMetricPolicy::RejectMultipleParsed,
                environment_fingerprint: "env-v1".into(),
                created_at_us: 10,
            },
        )
        .unwrap();
        run.comparison_execution_binding = comparison_execution_binding;
        run.experiment_contract_fingerprint = run.recompute_exact_contract_fingerprint().unwrap();
        run.comparison_key = run.recompute_comparison_key().unwrap();
        run.observability = RunObservability::Full;
        run.execution_status = RunExecutionStatus::Completed;
        run.contract_validity = RunContractValidity::Valid;
        run.terminal_evidence_refs = vec![receipt(byte)];
        run.started_at_us = Some(11);
        run.ended_at_us = Some(12);
        run.validate().unwrap();
        let cas = CasId::from_digest([byte; 32]);
        let result = ResultEvidence {
            result_evidence_id: ResultEvidenceId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            experiment_run_id: run.run_id,
            experiment_run_revision_id: run.revision_id,
            result_scope: ResultScope::Complete,
            raw_artifact_refs: Vec::new(),
            raw_cas_refs: vec![cas],
            parsed_metric: Some(MetricValue {
                decimal: metric.into(),
                unit: unit.into(),
                uncertainty_decimal: uncertainty.map(str::to_owned),
            }),
            parser_receipt: ParserReceipt {
                parser_version: "parser-v1".into(),
                input_artifact_refs: Vec::new(),
                input_cas_refs: vec![cas],
                status: ParserStatus::Parsed,
                failure_code: None,
            },
            verifier_receipt: Some(VerifierReceipt {
                verifier_version: "verifier-v1".into(),
                status: VerifierStatus::Passed,
                failure_code: None,
            }),
            completeness: EvidenceCompleteness::Complete,
            failure: None,
            created_at_us: 12,
        };
        result.validate().unwrap();
        (run, result)
    }

    fn fixture() -> Fixture {
        let repository_id = RepositoryId::new_v7();
        let worktree_id = WorktreeId::new_v7();
        let snapshot_id = WorktreeSnapshotId::new_v7();
        let procedure_id = evertrace_domain::ids::ProcedureId::new_v7();
        let procedure_revision_id = RevisionId::new_v7();
        let procedure = candidate(procedure_revision_id, procedure_id, repository_id, 1).revision;
        let task = Task {
            task_id: TaskId::new_v7(),
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            request_root_refs: vec!["request:s27".into()],
            canonical_goal: "compare procedure replay".into(),
            scope_memberships: vec![TaskScopeMembership {
                repository_instance_id: Some(repository_id),
                worktree_instance_ids: vec![worktree_id],
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
            source_watermark: 1,
        };
        task.validate().unwrap();
        let stream = Workstream {
            workstream_id: WorkstreamId::new_v7(),
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            task_id: task.task_id,
            repository_instance_id: Some(repository_id),
            worktree_instance_ids: vec![worktree_id],
            active_worktree_instance_id: Some(worktree_id),
            worktree_lineage_refs: Vec::new(),
            parent_workstream_id: None,
            dependency_workstream_ids: Vec::new(),
            status: WorkstreamStatus::Active,
            root_goal: "compare".into(),
            workstream_goal: "paired replay".into(),
            target_family: "procedure".into(),
            hypothesis_or_failure_family: "effect".into(),
            acceptance_boundary: "acceptance:s27".into(),
            phase_contract: PhaseContract {
                local_goal: "compare".into(),
                phase_kind: PhaseKind::Verify,
                phase_label: "verify".into(),
                primary_targets: vec!["procedure".into()],
                entry_conditions: vec!["fixture ready".into()],
                acceptance_boundary: "acceptance:s27".into(),
                expected_state_transition: "classified".into(),
            },
            active_episode_id: None,
            execution_lane_ids: Vec::new(),
            source_watermark: 1,
        };
        stream.validate().unwrap();
        let strategy = StrategyContract {
            hypothesis: "procedure changes metric".into(),
            intervention: "toggle procedure exposure".into(),
            intervention_family: "paired replay".into(),
            search_policy_ref: Some(procedure_revision_id.to_string()),
            objective_ref: Some("objective:accuracy".into()),
            expected_effect: "metric changes".into(),
            target_refs: vec!["target:fixture".into()],
            acceptance_boundary_ref: "acceptance:s27".into(),
        };
        let mut attempts = (0..16)
            .map(|_| {
                new_attempt(
                    task.task_id,
                    stream.workstream_id,
                    Some(repository_id),
                    vec![worktree_id],
                    Vec::new(),
                    strategy.clone(),
                    1,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        attempts.sort_by_key(|attempt| attempt.attempt_id);
        let mut episode = new_episode(&stream, Some(snapshot_id), 1).unwrap();
        episode.attempt_ids = attempts.iter().map(|attempt| attempt.attempt_id).collect();
        episode.attempt_ids.sort();
        episode.validate().unwrap();
        let usage = ProcedureUsageRevision {
            procedure_usage_id: evertrace_domain::ids::ProcedureUsageId::new_v7(),
            usage_revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            revision_generation: 1,
            procedure_revision_id,
            task_id: task.task_id,
            workstream_id: stream.workstream_id,
            exposure_episode_revision_id: episode.revision_id,
            decision_boundary_ref: "acceptance:s27".into(),
            route_decision: ProcedureUsageRouteDecision::Apply,
            stage: ProcedureUsageStage::Eligible,
            attempt_ids: attempts
                .iter()
                .step_by(2)
                .map(|value| value.attempt_id)
                .collect(),
            action_episode_revision_ids: Vec::new(),
            verification_episode_revision_ids: Vec::new(),
            action_operation_refs: Vec::new(),
            verification_operation_refs: Vec::new(),
            work_binding_revision_refs: Vec::new(),
            scope_effect_refs: Vec::new(),
            correlation_state: ProcedureCorrelationState::Resolved,
            eligible: ProcedureTruth::True,
            action_aligned: ProcedureTruth::False,
            verifier_aligned: ProcedureTruth::False,
            outcome_supported: ProcedureTruth::False,
            local_context: ProcedureLocalContext {
                repository_id: Some(repository_id),
                worktree_id: Some(worktree_id),
                phase: ProcedureUsagePhase::AtEntry,
                failure_signature: None,
            },
            source_watermark: 2,
            evidence_refs: vec!["evidence:s27".into()],
            created_at_us: 2,
        };
        assert!(usage.validate());
        let repository = RepositoryInstance {
            repository_id,
            repository_revision: 1,
            predecessor_revision: None,
            current_path: "/tmp/evertrace-s27".into(),
            path_history: vec![PathObservation {
                path: "/tmp/evertrace-s27".into(),
                first_observed_at_us: 1,
                last_observed_at_us: 1,
                evidence_refs: vec!["repository-path".into()],
            }],
            git_common_dir_path: Some("/tmp/evertrace-s27/.git".into()),
            common_dir_filesystem: Some(FilesystemIdentity {
                device: 27,
                inode: 1,
            }),
            object_format: Some(GitObjectFormat::Sha1),
            remote_fingerprints: Vec::new(),
            derived_from: None,
            identity_evidence_refs: vec!["repository-identity".into()],
            recorded_at_us: 1,
        };
        repository.validate().unwrap();
        let worktree = WorktreeInstance {
            worktree_instance_id: worktree_id,
            worktree_revision: 1,
            predecessor_revision: None,
            repository_instance_id: repository_id,
            kind: WorktreeKind::Main,
            lifecycle: WorktreeLifecycle::Active,
            current_path: Some("/tmp/evertrace-s27".into()),
            path_history: vec![PathObservation {
                path: "/tmp/evertrace-s27".into(),
                first_observed_at_us: 1,
                last_observed_at_us: 1,
                evidence_refs: vec!["worktree-path".into()],
            }],
            git_admin_path_history: vec![PathObservation {
                path: "/tmp/evertrace-s27/.git".into(),
                first_observed_at_us: 1,
                last_observed_at_us: 1,
                evidence_refs: vec!["worktree-admin".into()],
            }],
            git_registration_state: GitRegistrationState::Registered,
            current_snapshot_id: Some(snapshot_id),
            created_event_ref: "worktree-created".into(),
            terminal_event_ref: None,
            recreated_from_worktree_instance_id: None,
            recorded_at_us: 1,
        };
        worktree.validate().unwrap();
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
            relevant_anchor_digests: Vec::new(),
            dependency_fingerprints: Vec::new(),
            toolchain_fingerprint: Some("rust-1.97.1".into()),
            git_operation: GitOperation::None,
            captured_at_us: 1,
            evidence_refs: vec!["snapshot:s27".into()],
            capture_status: SnapshotCaptureStatus::Complete,
            omission_reasons: Vec::new(),
        };
        snapshot.validate().unwrap();
        let metrics = [
            ("1.05", "1.00", "ratio", None),
            ("1.10", "1.00", "ratio", None),
            ("0.97", "1.00", "ratio", None),
            ("0.90", "1.00", "ratio", None),
            ("1.02", "1.00", "ratio", None),
            ("1.01", "1.00", "ratio", None),
            ("1.10", "1.00", "other", None),
            ("1.10", "1.00", "ratio", Some("0.01")),
        ];
        let mut rows = vec![
            row(
                "repository_instance",
                JournalPayload::RepositoryInstanceRecorded(Box::new(repository)),
                1,
            ),
            row(
                "workstream",
                JournalPayload::WorkstreamRecorded(Box::new(stream)),
                2,
            ),
            row(
                "procedure_revision",
                JournalPayload::ProcedureRevisionRecorded(Box::new(procedure)),
                1,
            ),
            row("task", JournalPayload::TaskRecorded(Box::new(task)), 2),
            row(
                "worktree",
                JournalPayload::WorktreeInstanceRecorded(Box::new(worktree)),
                3,
            ),
            row(
                "worktree_snapshot",
                JournalPayload::WorktreeSnapshotRecorded(Box::new(snapshot)),
                4,
            ),
            row(
                "work_episode",
                JournalPayload::WorkEpisodeRecorded(Box::new(episode)),
                5,
            ),
            row(
                "procedure_usage_revision",
                JournalPayload::ProcedureUsageRecorded(Box::new(usage)),
                6,
            ),
        ];
        for (index, attempt) in attempts.iter().enumerate() {
            rows.push(row(
                "attempt",
                JournalPayload::AttemptRecorded(Box::new(attempt.clone())),
                10 + index as u64,
            ));
        }
        let mut pairs = Vec::new();
        for (index, (on_metric, off_metric, unit, uncertainty)) in metrics.into_iter().enumerate() {
            let on_attempt = &attempts[index * 2];
            let off_attempt = &attempts[index * 2 + 1];
            let (on_run, on_result) = run_result(
                on_attempt,
                snapshot_id,
                procedure_revision_id,
                30 + index as u8 * 2,
                true,
                on_metric,
                unit,
                uncertainty,
                None,
            );
            let (off_run, off_result) = run_result(
                off_attempt,
                snapshot_id,
                procedure_revision_id,
                31 + index as u8 * 2,
                false,
                off_metric,
                "ratio",
                None,
                None,
            );
            pairs.push(ControlledProcedurePair {
                procedure_experiment_run_id: on_run.run_id,
                procedure_result_revision_id: on_result.revision_id,
                control_experiment_run_id: off_run.run_id,
                control_result_revision_id: off_result.revision_id,
            });
            for (kind, payload) in [
                (
                    "experiment_run",
                    JournalPayload::ExperimentRunRecorded(Box::new(on_run)),
                ),
                (
                    "result_evidence",
                    JournalPayload::ResultEvidenceRecorded(Box::new(on_result)),
                ),
                (
                    "experiment_run",
                    JournalPayload::ExperimentRunRecorded(Box::new(off_run)),
                ),
                (
                    "result_evidence",
                    JournalPayload::ResultEvidenceRecorded(Box::new(off_result)),
                ),
            ] {
                let seq = 40 + rows.len() as u64;
                rows.push(row(kind, payload, seq));
            }
        }
        Fixture {
            snapshot: ProjectionSnapshot {
                frontier: 200,
                rows,
            },
            procedure_revision_id,
            pairs,
        }
    }

    fn mutate_run(
        snapshot: &mut ProjectionSnapshot,
        run_id: evertrace_domain::ids::ExperimentRunId,
        mutate: impl FnOnce(&mut evertrace_domain::work::ExperimentRun),
    ) {
        let mut mutate = Some(mutate);
        for row in &mut snapshot.rows {
            if row.object_kind.as_deref() != Some("experiment_run") {
                continue;
            }
            let JournalPayload::ExperimentRunRecorded(mut run) =
                serde_json::from_str(row.payload_json.as_deref().unwrap()).unwrap()
            else {
                continue;
            };
            if run.run_id != run_id {
                continue;
            }
            mutate.take().unwrap()(&mut run);
            row.payload_json = Some(
                JournalPayload::ExperimentRunRecorded(run)
                    .canonical_json()
                    .unwrap(),
            );
            return;
        }
        panic!("run row not found");
    }

    fn compile_pairs(
        fixture: &Fixture,
        pairs: Vec<ControlledProcedurePair>,
    ) -> Result<
        evertrace_domain::procedure::ProcedureContextEffectProjection,
        evertrace_engine::semantic::SemanticServiceError,
    > {
        compile_snapshot_pairs(&fixture.snapshot, fixture.procedure_revision_id, pairs)
    }

    fn compile_snapshot_pairs(
        source: &ProjectionSnapshot,
        procedure_revision_id: RevisionId,
        pairs: Vec<ControlledProcedurePair>,
    ) -> Result<
        evertrace_domain::procedure::ProcedureContextEffectProjection,
        evertrace_engine::semantic::SemanticServiceError,
    > {
        let run_ids = pairs
            .iter()
            .flat_map(|pair| {
                [
                    pair.procedure_experiment_run_id,
                    pair.control_experiment_run_id,
                ]
            })
            .collect::<std::collections::BTreeSet<_>>();
        let result_revisions = pairs
            .iter()
            .flat_map(|pair| {
                [
                    pair.procedure_result_revision_id,
                    pair.control_result_revision_id,
                ]
            })
            .collect::<std::collections::BTreeSet<_>>();
        let mut snapshot = source.clone();
        snapshot.rows.retain(|row| {
            let Some(payload) = row
                .payload_json
                .as_deref()
                .and_then(|value| serde_json::from_str::<JournalPayload>(value).ok())
            else {
                return true;
            };
            match payload {
                JournalPayload::ExperimentRunRecorded(value) => run_ids.contains(&value.run_id),
                JournalPayload::ResultEvidenceRecorded(value) => {
                    result_revisions.contains(&value.revision_id)
                }
                _ => true,
            }
        });
        let mut effects = compile_controlled_effect(&snapshot, procedure_revision_id)?;
        if effects.len() != 1 {
            return Err(evertrace_engine::semantic::SemanticServiceError::InvalidInput);
        }
        Ok(effects.pop().unwrap())
    }

    #[test]
    fn real_current_facts_derive_thresholds_deduplicate_and_fail_closed() {
        let fixture = fixture();
        let compile = |pairs: Vec<ControlledProcedurePair>| compile_pairs(&fixture, pairs).unwrap();
        let positive = compile(fixture.pairs[0..2].to_vec());
        assert_eq!(
            (positive.effect, positive.valid_pair_count),
            (ProcedureEffect::Positive, 2)
        );
        let negative = compile(fixture.pairs[2..4].to_vec());
        assert_eq!(
            (negative.effect, negative.valid_pair_count),
            (ProcedureEffect::Negative, 2)
        );
        let mixed = compile(vec![fixture.pairs[0].clone(), fixture.pairs[2].clone()]);
        assert_eq!(
            (mixed.effect, mixed.valid_pair_count),
            (ProcedureEffect::Mixed, 2)
        );
        let neutral = compile(fixture.pairs[4..6].to_vec());
        assert_eq!(
            (neutral.effect, neutral.valid_pair_count),
            (ProcedureEffect::Mixed, 2)
        );
        let reversed = ControlledProcedurePair {
            procedure_experiment_run_id: fixture.pairs[0].control_experiment_run_id,
            procedure_result_revision_id: fixture.pairs[0].control_result_revision_id,
            control_experiment_run_id: fixture.pairs[0].procedure_experiment_run_id,
            control_result_revision_id: fixture.pairs[0].procedure_result_revision_id,
        };
        let duplicate = compile(vec![
            fixture.pairs[0].clone(),
            fixture.pairs[0].clone(),
            reversed,
        ]);
        assert_eq!(
            (duplicate.effect, duplicate.valid_pair_count),
            (ProcedureEffect::Insufficient, 1)
        );
        let unit_mismatch = compile(vec![fixture.pairs[6].clone()]);
        assert_eq!(
            (unit_mismatch.effect, unit_mismatch.valid_pair_count),
            (ProcedureEffect::Insufficient, 0)
        );
        let uncertainty = compile(vec![fixture.pairs[7].clone()]);
        assert_eq!(
            (uncertainty.effect, uncertainty.valid_pair_count),
            (ProcedureEffect::Insufficient, 0)
        );
        assert!(
            compile_pairs(
                &fixture,
                vec![ControlledProcedurePair {
                    procedure_result_revision_id: fixture.pairs[1].procedure_result_revision_id,
                    ..fixture.pairs[0].clone()
                }],
            )
            .is_err()
        );

        let mut missing_binding = fixture.snapshot.clone();
        mutate_run(
            &mut missing_binding,
            fixture.pairs[0].procedure_experiment_run_id,
            |run| {
                run.comparison_execution_binding = None;
                run.experiment_contract_fingerprint =
                    run.recompute_exact_contract_fingerprint().unwrap();
                run.comparison_key = run.recompute_comparison_key().unwrap();
            },
        );
        assert!(
            compile_snapshot_pairs(
                &missing_binding,
                fixture.procedure_revision_id,
                vec![fixture.pairs[0].clone()],
            )
            .is_err()
        );

        let mut mismatched_binding = fixture.snapshot.clone();
        mutate_run(
            &mut mismatched_binding,
            fixture.pairs[0].control_experiment_run_id,
            |run| {
                run.comparison_execution_binding
                    .as_mut()
                    .unwrap()
                    .model_revision = "model-v2".into();
                run.experiment_contract_fingerprint =
                    run.recompute_exact_contract_fingerprint().unwrap();
                run.comparison_key = run.recompute_comparison_key().unwrap();
            },
        );
        assert!(
            compile_snapshot_pairs(
                &mismatched_binding,
                fixture.procedure_revision_id,
                vec![fixture.pairs[0].clone()],
            )
            .is_err()
        );

        let mut forged_key = fixture.snapshot.clone();
        mutate_run(
            &mut forged_key,
            fixture.pairs[0].procedure_experiment_run_id,
            |run| run.comparison_key = [0x44; 32],
        );
        assert!(
            compile_snapshot_pairs(
                &forged_key,
                fixture.procedure_revision_id,
                vec![fixture.pairs[0].clone()],
            )
            .is_err()
        );

        let mut with_new_snapshot = fixture.snapshot.clone();
        let mut latest = with_new_snapshot
            .rows
            .iter()
            .find(|row| row.object_kind.as_deref() == Some("worktree_snapshot"))
            .cloned()
            .unwrap();
        let JournalPayload::WorktreeSnapshotRecorded(mut snapshot) =
            serde_json::from_str(latest.payload_json.as_deref().unwrap()).unwrap()
        else {
            unreachable!()
        };
        snapshot.worktree_snapshot_id = WorktreeSnapshotId::new_v7();
        latest.row_id = "s27:new-snapshot".into();
        latest.source_event_seq = 999;
        latest.payload_json = Some(
            JournalPayload::WorktreeSnapshotRecorded(snapshot)
                .canonical_json()
                .unwrap(),
        );
        with_new_snapshot.rows.push(latest);
        let stable = compile_snapshot_pairs(
            &with_new_snapshot,
            fixture.procedure_revision_id,
            fixture.pairs[0..2].to_vec(),
        )
        .unwrap();
        assert_eq!(
            stable.context_fingerprint_hash,
            positive.context_fingerprint_hash
        );

        let mut repository_mismatch = fixture.snapshot.clone();
        for row in &mut repository_mismatch.rows {
            if row.object_kind.as_deref() != Some("worktree") {
                continue;
            }
            let JournalPayload::WorktreeInstanceRecorded(mut worktree) =
                serde_json::from_str(row.payload_json.as_deref().unwrap()).unwrap()
            else {
                unreachable!()
            };
            worktree.repository_instance_id = RepositoryId::new_v7();
            row.payload_json = Some(
                JournalPayload::WorktreeInstanceRecorded(worktree)
                    .canonical_json()
                    .unwrap(),
            );
        }
        assert!(
            compile_snapshot_pairs(
                &repository_mismatch,
                fixture.procedure_revision_id,
                fixture.pairs[0..2].to_vec(),
            )
            .is_err()
        );

        let mut non_repository_global_fixture = fixture.snapshot.clone();
        for row in &mut non_repository_global_fixture.rows {
            let payload: JournalPayload =
                serde_json::from_str(row.payload_json.as_deref().unwrap()).unwrap();
            let replacement = match payload {
                JournalPayload::WorkEpisodeRecorded(mut episode) => {
                    episode.repository_instance_id = None;
                    episode.worktree_instance_id = None;
                    episode.entry_worktree_snapshot_id = None;
                    Some(JournalPayload::WorkEpisodeRecorded(episode))
                }
                JournalPayload::ProcedureUsageRecorded(mut usage) => {
                    usage.local_context.repository_id = None;
                    usage.local_context.worktree_id = None;
                    usage.evidence_refs =
                        vec![fixture.pairs[1].procedure_result_revision_id.to_string()];
                    Some(JournalPayload::ProcedureUsageRecorded(usage))
                }
                JournalPayload::AttemptRecorded(mut attempt) => {
                    attempt.repository_instance_id = None;
                    attempt.worktree_instance_ids.clear();
                    Some(JournalPayload::AttemptRecorded(attempt))
                }
                _ => None,
            };
            if let Some(replacement) = replacement {
                row.payload_json = Some(replacement.canonical_json().unwrap());
            }
        }
        assert!(
            compile_snapshot_pairs(
                &non_repository_global_fixture,
                fixture.procedure_revision_id,
                vec![fixture.pairs[0].clone()],
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn controlled_writer_authority_uses_ingested_exact_surfaces_and_atomic_terminal() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(
            temp.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        DeviceKeyStore::new(temp.path().join("keys"))
            .load_or_create()
            .unwrap();
        let runtime = runtime_snapshot(temp.path());
        let store_root = temp.path().join("store");
        let mut evidence = capture_input(
            "procedure-evidence",
            1,
            ObservationRole::Result,
            b"objective procedure evidence".to_vec(),
        );
        evidence.correlation.native_request_id = Some("procedure-evidence".into());
        evidence.correlation.physical_execution_ordinal = Some(9);
        capture_and_ingest(&runtime, &store_root, vec![evidence]).await;
        let (evidence_observation_id, evidence_receipt_id) = captured_ids("procedure-evidence");

        let repository_id = RepositoryId::new_v7();
        let worktree_id = WorktreeId::new_v7();
        let snapshot_id = WorktreeSnapshotId::new_v7();
        let repository = RepositoryInstance {
            repository_id,
            repository_revision: 1,
            predecessor_revision: None,
            current_path: "/tmp/s27-controlled".into(),
            path_history: vec![PathObservation {
                path: "/tmp/s27-controlled".into(),
                first_observed_at_us: 1,
                last_observed_at_us: 1,
                evidence_refs: vec![evidence_receipt_id.to_string()],
            }],
            git_common_dir_path: Some("/tmp/s27-controlled/.git".into()),
            common_dir_filesystem: Some(FilesystemIdentity {
                device: 27,
                inode: 2,
            }),
            object_format: Some(GitObjectFormat::Sha1),
            remote_fingerprints: Vec::new(),
            derived_from: None,
            identity_evidence_refs: vec![evidence_receipt_id.to_string()],
            recorded_at_us: 2,
        };
        let worktree = WorktreeInstance {
            worktree_instance_id: worktree_id,
            worktree_revision: 1,
            predecessor_revision: None,
            repository_instance_id: repository_id,
            kind: WorktreeKind::Main,
            lifecycle: WorktreeLifecycle::Active,
            current_path: Some("/tmp/s27-controlled".into()),
            path_history: vec![PathObservation {
                path: "/tmp/s27-controlled".into(),
                first_observed_at_us: 1,
                last_observed_at_us: 1,
                evidence_refs: vec![evidence_receipt_id.to_string()],
            }],
            git_admin_path_history: vec![PathObservation {
                path: "/tmp/s27-controlled/.git".into(),
                first_observed_at_us: 1,
                last_observed_at_us: 1,
                evidence_refs: vec![evidence_receipt_id.to_string()],
            }],
            git_registration_state: GitRegistrationState::Registered,
            current_snapshot_id: Some(snapshot_id),
            created_event_ref: evidence_receipt_id.to_string(),
            terminal_event_ref: None,
            recreated_from_worktree_instance_id: None,
            recorded_at_us: 2,
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
            relevant_anchor_digests: Vec::new(),
            dependency_fingerprints: Vec::new(),
            toolchain_fingerprint: Some("rust-1.97.1".into()),
            git_operation: GitOperation::None,
            captured_at_us: 2,
            evidence_refs: vec![evidence_receipt_id.to_string()],
            capture_status: SnapshotCaptureStatus::Complete,
            omission_reasons: Vec::new(),
        };
        let mut writer = JournalWriter::open(&store_root).await.unwrap();
        writer
            .commit(
                &journal_command(
                    2,
                    vec![
                        JournalPayload::RepositoryInstanceRecorded(Box::new(repository)),
                        JournalPayload::WorktreeInstanceRecorded(Box::new(worktree)),
                        JournalPayload::WorktreeSnapshotRecorded(Box::new(snapshot)),
                    ],
                ),
                2,
            )
            .await
            .unwrap();
        let service = RevisionProposalService;
        let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
        let mut draft = candidate(
            RevisionId::new_v7(),
            evertrace_domain::ids::ProcedureId::new_v7(),
            repository_id,
            1,
        )
        .revision
        .draft;
        draft.evidence_refs = vec![evidence_receipt_id.to_string()];
        let ProposalResolution::Revision {
            value: proposal,
            command: submit,
        } = service
            .submit(
                &view,
                proposal_context(3),
                SubmitProposalRequest {
                    target_kind: ProposalTargetKind::Procedure,
                    target_id: None,
                    base_revision_id: None,
                    operation: ProposalOperation::Create,
                    payload: ProposalPayload::Procedure(Box::new(
                        ProcedureProposalPayload::Create { draft },
                    )),
                    evidence_refs: vec![evidence_receipt_id.to_string()],
                    source_cohort_refs: vec![evidence_receipt_id.to_string()],
                    eligibility: ProposalEligibility::AutoEligibleFull,
                    created_by: ProposalCreatedBy::System,
                },
            )
            .unwrap()
        else {
            panic!("proposal must persist")
        };
        writer.commit(&submit, 3).await.unwrap();
        let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
        let config = GlobalPromotionConfig {
            atom: PromotionLevel::Manual,
            procedure: PromotionLevel::FullAuto,
            core_membership: PromotionLevel::Manual,
        };
        let ProcedureAcceptanceResolution::Command {
            procedure,
            command: accepted,
            ..
        } = accept_procedure(
            &view,
            proposal_context(4),
            proposal.proposal_id,
            ProcedureAcceptanceContext::AutoFull(eligibility(evidence_observation_id)),
            None,
            None,
            &config,
        )
        .unwrap()
        else {
            panic!("procedure must be accepted")
        };
        writer.commit(&accepted, 4).await.unwrap();

        let task = Task {
            task_id: TaskId::new_v7(),
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            request_root_refs: vec!["request:s27-controlled".into()],
            canonical_goal: "controlled replay".into(),
            scope_memberships: vec![TaskScopeMembership {
                repository_instance_id: Some(repository_id),
                worktree_instance_ids: vec![worktree_id],
            }],
            identity_confidence: TaskIdentityConfidence::Explicit,
            lifecycle: TaskLifecycle::Active,
            continuation_of_task_id: None,
            split_from_task_id: None,
            split_into_task_ids: Vec::new(),
            merged_from_task_ids: Vec::new(),
            merged_into_task_id: None,
            created_at_us: 5,
            closed_at_us: None,
            source_watermark: 1,
        };
        let stream = Workstream {
            workstream_id: WorkstreamId::new_v7(),
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            task_id: task.task_id,
            repository_instance_id: Some(repository_id),
            worktree_instance_ids: vec![worktree_id],
            active_worktree_instance_id: Some(worktree_id),
            worktree_lineage_refs: Vec::new(),
            parent_workstream_id: None,
            dependency_workstream_ids: Vec::new(),
            status: WorkstreamStatus::Active,
            root_goal: "controlled replay".into(),
            workstream_goal: "measure effect".into(),
            target_family: "procedure".into(),
            hypothesis_or_failure_family: "effect".into(),
            acceptance_boundary: "acceptance:s27".into(),
            phase_contract: PhaseContract {
                local_goal: "compare".into(),
                phase_kind: PhaseKind::Verify,
                phase_label: "verify".into(),
                primary_targets: vec!["procedure".into()],
                entry_conditions: vec!["ready".into()],
                acceptance_boundary: "acceptance:s27".into(),
                expected_state_transition: "measured".into(),
            },
            active_episode_id: None,
            execution_lane_ids: Vec::new(),
            source_watermark: 1,
        };
        let strategy = StrategyContract {
            hypothesis: "procedure changes metric".into(),
            intervention: "toggle procedure exposure".into(),
            intervention_family: "paired replay".into(),
            search_policy_ref: Some(procedure.revision_id.to_string()),
            objective_ref: Some("objective:metric".into()),
            expected_effect: "metric improves".into(),
            target_refs: vec!["target:fixture".into()],
            acceptance_boundary_ref: "acceptance:s27".into(),
        };
        let mut attempts = (0..4)
            .map(|_| {
                new_attempt(
                    task.task_id,
                    stream.workstream_id,
                    Some(repository_id),
                    vec![worktree_id],
                    Vec::new(),
                    strategy.clone(),
                    5,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        attempts.sort_by_key(|value| value.attempt_id);
        writer
            .commit(
                &journal_command(
                    5,
                    std::iter::once(JournalPayload::TaskRecorded(Box::new(task.clone())))
                        .chain(std::iter::once(JournalPayload::WorkstreamRecorded(
                            Box::new(stream.clone()),
                        )))
                        .chain(
                            attempts
                                .iter()
                                .cloned()
                                .map(|value| JournalPayload::AttemptRecorded(Box::new(value))),
                        )
                        .collect(),
                ),
                5,
            )
            .await
            .unwrap();
        let mut episode = new_episode(&stream, Some(snapshot_id), writer.frontier()).unwrap();
        episode.attempt_ids = attempts.iter().map(|value| value.attempt_id).collect();
        episode.attempt_ids.sort();
        episode.validate().unwrap();
        let episode_attempts = attempts
            .iter()
            .map(|attempt| {
                link_attempt_to_episode(attempt, &episode, writer.frontier() + 1).unwrap()
            })
            .collect();
        let activation = activate_episode(
            WorkCommandContext {
                command_id: CommandId::new_v7(),
                occurred_at_us: 6,
                effective_config_hash: [27; 32],
                algorithm_revision: "s27-controlled-v1",
            },
            &stream,
            episode.clone(),
            episode_attempts,
            vec![],
        )
        .unwrap();
        writer.commit(&activation, 6).await.unwrap();
        let initial_usage = ProcedureUsageRevision {
            procedure_usage_id: ProcedureUsageId::new_v7(),
            usage_revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            revision_generation: 1,
            procedure_revision_id: procedure.revision_id,
            task_id: task.task_id,
            workstream_id: stream.workstream_id,
            exposure_episode_revision_id: episode.revision_id,
            decision_boundary_ref: stream.phase_contract.acceptance_boundary.clone(),
            route_decision: ProcedureUsageRouteDecision::Apply,
            stage: ProcedureUsageStage::Returned,
            attempt_ids: Vec::new(),
            action_episode_revision_ids: Vec::new(),
            verification_episode_revision_ids: Vec::new(),
            action_operation_refs: Vec::new(),
            verification_operation_refs: Vec::new(),
            work_binding_revision_refs: Vec::new(),
            scope_effect_refs: Vec::new(),
            correlation_state: ProcedureCorrelationState::Resolved,
            eligible: ProcedureTruth::True,
            action_aligned: ProcedureTruth::False,
            verifier_aligned: ProcedureTruth::Unknown,
            outcome_supported: ProcedureTruth::Unknown,
            local_context: ProcedureLocalContext {
                repository_id: Some(repository_id),
                worktree_id: Some(worktree_id),
                phase: ProcedureUsagePhase::InProgress,
                failure_signature: None,
            },
            source_watermark: writer.frontier(),
            evidence_refs: vec![evidence_receipt_id.to_string()],
            created_at_us: 7,
        };
        writer
            .commit(
                &journal_command(
                    7,
                    vec![JournalPayload::ProcedureUsageRecorded(Box::new(
                        initial_usage.clone(),
                    ))],
                ),
                7,
            )
            .await
            .unwrap();
        let mut claimed_usage = initial_usage.clone();
        claimed_usage.usage_revision_id = RevisionId::new_v7();
        claimed_usage.predecessor_revision_id = Some(initial_usage.usage_revision_id);
        claimed_usage.revision_generation += 1;
        claimed_usage.stage = ProcedureUsageStage::Claimed;
        claimed_usage.attempt_ids = attempts.iter().map(|value| value.attempt_id).collect();
        claimed_usage.attempt_ids.sort();
        claimed_usage.source_watermark = writer.frontier();
        claimed_usage.created_at_us = 8;
        initial_usage
            .validate_successor(&claimed_usage)
            .then_some(())
            .unwrap();
        writer
            .commit(
                &journal_command(
                    8,
                    vec![JournalPayload::ProcedureUsageRecorded(Box::new(
                        claimed_usage,
                    ))],
                ),
                8,
            )
            .await
            .unwrap();
        let resolver = ControlledRunResolver::new(CasStore::open(runtime.cas_dir.clone()).unwrap());
        drop(writer);
        let exposures = [
            Some(procedure.revision_id),
            Some(procedure.revision_id),
            None,
            None,
        ];
        let names = ["on-a", "on-b", "off-a", "off-b"];
        let mut declared = Vec::new();
        for (index, attempt) in attempts.iter().enumerate() {
            declared.push(
                declare_controlled_run(
                    &runtime,
                    &store_root,
                    &resolver,
                    attempt.attempt_id,
                    procedure.revision_id,
                    snapshot_id,
                    exposures[index],
                    CaptureSpec {
                        name: names[index],
                        source_sequence: 2 + index as u64 * 2,
                        physical_ordinal: 2 + index as u32,
                        at: 20 + index as i64 * 10,
                    },
                )
                .await,
            );
        }
        assert_eq!(
            declared
                .iter()
                .map(|value| value.run_id)
                .collect::<BTreeSet<_>>()
                .len(),
            4
        );
        assert_eq!(
            declared
                .iter()
                .filter_map(|value| value.attempt_id)
                .collect::<BTreeSet<_>>()
                .len(),
            4
        );

        let metrics = ["0.95", "0.90", "0.50", "0.45"];
        let mut completed = Vec::new();
        for (index, run) in declared.iter().enumerate() {
            completed.push(
                complete_controlled_run(
                    &runtime,
                    &store_root,
                    &resolver,
                    run,
                    metrics[index],
                    CaptureSpec {
                        name: names[index],
                        source_sequence: 10 + index as u64 * 2,
                        physical_ordinal: 6 + index as u32,
                        at: 60 + index as i64 * 10,
                    },
                )
                .await,
            );
        }
        assert_eq!(
            completed
                .iter()
                .map(|(run, _)| run.run_id)
                .collect::<BTreeSet<_>>()
                .len(),
            4
        );
        assert_eq!(
            completed
                .iter()
                .map(|(_, result)| result.result_evidence_id)
                .collect::<BTreeSet<_>>()
                .len(),
            4
        );
        assert_eq!(
            completed
                .iter()
                .map(|(_, result)| result.revision_id)
                .collect::<BTreeSet<_>>()
                .len(),
            4
        );

        let writer = JournalWriter::open(&store_root).await.unwrap();
        let incremental = writer.project().await.unwrap();
        assert_eq!(incremental, writer.full_projection().await.unwrap());
        drop(writer);
        let writer = JournalWriter::open(&store_root).await.unwrap();
        let reopened_projection = writer.project().await.unwrap();
        assert_eq!(reopened_projection, incremental);
        let facts = reopened_projection
            .procedure_effect_current_facts()
            .unwrap();
        let effects =
            compile_controlled_effect(&reopened_projection, procedure.revision_id).unwrap();
        let effect = effects
            .iter()
            .find(|value| {
                value.context.task_id == task.task_id
                    && matches!(
                        value.context.anchor,
                        ProcedureContextAnchor::Repository {
                            worktree_snapshot_id,
                            ..
                        } if worktree_snapshot_id == snapshot_id
                    )
            })
            .unwrap();
        assert_eq!(effect.effect, ProcedureEffect::Positive);
        assert_eq!(effect.valid_pair_count, 2);
        let evidence_refs = effect
            .evidence_refs
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for (run, result) in &completed {
            assert_eq!(
                facts.runs.get(&run.run_id).unwrap().0.revision_id,
                run.revision_id
            );
            assert_eq!(
                facts.current_results.get(&result.result_evidence_id),
                Some(&result.revision_id)
            );
            for reference in [
                run.run_id.to_string(),
                run.revision_id.to_string(),
                result.result_evidence_id.to_string(),
                result.revision_id.to_string(),
            ] {
                assert!(evidence_refs.contains(&reference));
            }
        }
        let run_ids = completed
            .iter()
            .map(|(run, _)| run.run_id)
            .collect::<BTreeSet<_>>();
        let mut bound_operations = BTreeSet::new();
        let mut bound_revisions = BTreeSet::new();
        for row in reopened_projection.data_rows() {
            let Some(payload) = row
                .payload_json
                .as_deref()
                .and_then(|value| serde_json::from_str::<JournalPayload>(value).ok())
            else {
                continue;
            };
            if let JournalPayload::WorkBindingRecorded(value) = payload
                && value
                    .primary_binding
                    .experiment_run_id
                    .is_some_and(|run_id| run_ids.contains(&run_id))
            {
                bound_operations.insert(value.operation_id);
                bound_revisions.insert(value.work_binding_revision_id);
            }
        }
        assert_eq!(bound_operations.len(), 8);
        assert_eq!(bound_revisions.len(), 8);
        assert_eq!(
            completed
                .iter()
                .flat_map(|(run, _)| run.source_receipt_refs.iter())
                .collect::<BTreeSet<_>>()
                .len(),
            4
        );
        assert_eq!(
            completed
                .iter()
                .flat_map(|(run, _)| run.terminal_evidence_refs.iter())
                .collect::<BTreeSet<_>>()
                .len(),
            4
        );
        assert_eq!(
            completed
                .iter()
                .flat_map(|(_, result)| result.raw_cas_refs.iter())
                .collect::<BTreeSet<_>>()
                .len(),
            4
        );
        assert_eq!(
            writer.table_names().await.unwrap(),
            vec![
                "evertrace_journal",
                "evertrace_objects",
                "evertrace_relations",
                "evertrace_search",
            ]
        );
        drop(writer);

        let gate_d_run = declare_controlled_run(
            &runtime,
            &store_root,
            &resolver,
            attempts[0].attempt_id,
            procedure.revision_id,
            snapshot_id,
            Some(procedure.revision_id),
            CaptureSpec {
                name: "gate-d-run",
                source_sequence: 18,
                physical_ordinal: 10,
                at: 110,
            },
        )
        .await;
        let (delayed_run, delayed_declaration, late_launch_observation_id) =
            prepare_controlled_declaration(
                &runtime,
                &store_root,
                &resolver,
                attempts[0].attempt_id,
                procedure.revision_id,
                snapshot_id,
                Some(procedure.revision_id),
                CaptureSpec {
                    name: "gate-d-delayed",
                    source_sequence: 20,
                    physical_ordinal: 11,
                    at: 120,
                },
            )
            .await;
        assert_ne!(delayed_run.run_id, gate_d_run.run_id);
        let mut writer = JournalWriter::open(&store_root).await.unwrap();

        let semantic_view =
            SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
        let mut replacement_draft = procedure.draft.clone();
        replacement_draft.summary = "Superseding controlled procedure revision".into();
        let ProposalResolution::Revision {
            value: replacement_proposal,
            command: replacement_submitted,
        } = service
            .submit(
                &semantic_view,
                proposal_context(130),
                SubmitProposalRequest {
                    target_kind: ProposalTargetKind::Procedure,
                    target_id: Some(ProposalTargetId::Procedure(procedure.procedure_id)),
                    base_revision_id: Some(procedure.revision_id),
                    operation: ProposalOperation::Replace,
                    payload: ProposalPayload::Procedure(Box::new(
                        ProcedureProposalPayload::Replace {
                            draft: replacement_draft,
                        },
                    )),
                    evidence_refs: vec![evidence_receipt_id.to_string()],
                    source_cohort_refs: vec![evidence_receipt_id.to_string()],
                    eligibility: ProposalEligibility::AutoEligibleFull,
                    created_by: ProposalCreatedBy::System,
                },
            )
            .unwrap()
        else {
            panic!("replacement proposal must persist")
        };
        writer.commit(&replacement_submitted, 130).await.unwrap();
        let semantic_view =
            SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
        let ProcedureAcceptanceResolution::Command {
            procedure: replacement,
            command: replacement_accepted,
            ..
        } = accept_procedure(
            &semantic_view,
            proposal_context(131),
            replacement_proposal.proposal_id,
            ProcedureAcceptanceContext::AutoFull(eligibility(evidence_observation_id)),
            Some(&procedure),
            Some(ProcedurePublicationState::ActiveProbationary),
            &config,
        )
        .unwrap()
        else {
            panic!("replacement procedure must be accepted")
        };
        assert_ne!(replacement.revision_id, procedure.revision_id);
        assert!(replacement_accepted.events().iter().any(|event| matches!(
            &event.payload,
            JournalPayload::ProcedureStateRecorded(value)
                if value.procedure_revision_id == procedure.revision_id
                    && value.to_state == ProcedurePublicationState::Superseded
        )));
        writer.commit(&replacement_accepted, 131).await.unwrap();
        assert!(matches!(
            resolver
                .declare(
                    &writer.project().await.unwrap(),
                    ControlledRunRequest {
                        attempt_id: attempts[0].attempt_id,
                        procedure_revision_id: procedure.revision_id,
                        source_observation_id: late_launch_observation_id,
                    },
                    AutoresearchCommandContext {
                        command_id: CommandId::new_v7(),
                        occurred_at_us: 132,
                        effective_config_hash: [27; 32],
                        algorithm_revision: "s27-controlled-v1",
                    },
                )
                .unwrap(),
            ControlledRunCommand::NoDelta
        ));
        let superseded_frontier = writer.frontier();
        assert!(writer.commit(&delayed_declaration, 132).await.is_err());
        assert_eq!(writer.frontier(), superseded_frontier);
        drop(writer);
        let (terminal_run, result) = complete_controlled_run(
            &runtime,
            &store_root,
            &resolver,
            &gate_d_run,
            "0.95",
            CaptureSpec {
                name: "gate-d-run",
                source_sequence: 22,
                physical_ordinal: 12,
                at: 140,
            },
        )
        .await;
        assert_eq!(terminal_run.execution_status, RunExecutionStatus::Completed);
        assert_eq!(result.experiment_run_revision_id, terminal_run.revision_id);
        let writer = JournalWriter::open(&store_root).await.unwrap();
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
        drop(writer);
        let mut reopened = JournalWriter::open(&store_root).await.unwrap();
        assert_eq!(reopened.project().await.unwrap(), incremental);

        let group_id = CompetingAttemptGroupId::new_v7();
        let current =
            AttemptCurrentView::from_snapshot(&reopened.project().await.unwrap()).unwrap();
        let mut winner = current.attempts[&attempts[0].attempt_id].clone();
        let mut other = current.attempts[&attempts[1].attempt_id].clone();
        for attempt in [&mut winner, &mut other] {
            let predecessor = attempt.clone();
            attempt.revision_id = RevisionId::new_v7();
            attempt.predecessor_revision_id = Some(predecessor.revision_id);
            attempt.revision_generation += 1;
            attempt.competing_group_ids.push(group_id);
            attempt.competing_group_ids.sort();
            attempt.source_watermark = reopened.frontier() + 1;
            predecessor.validate_successor(attempt).unwrap();
        }
        winner.adoption_status = AttemptAdoptionStatus::Selected;
        current.attempts[&attempts[0].attempt_id]
            .validate_successor(&winner)
            .unwrap();
        let mut member_attempt_ids = vec![winner.attempt_id, other.attempt_id];
        member_attempt_ids.sort();
        let group = CompetingAttemptGroup {
            competing_group_id: group_id,
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            revision_generation: 1,
            task_id: task.task_id,
            decision_boundary_ref: "decision:s31-controlled".into(),
            comparison_contract_ref: Some("comparison:s27-controlled".into()),
            origin_workstream_id: Some(stream.workstream_id),
            origin_episode_id: None,
            member_workstream_ids: vec![stream.workstream_id],
            member_attempt_ids,
            candidate_snapshot_refs: Vec::new(),
            target_refs: vec!["target:s27-controlled".into()],
            conflict_kind: CompetingConflictKind::AlternativeStrategy,
            resolution_status: CompetingResolutionStatus::Open,
            selected_attempt_id: None,
            partially_integrated_attempt_ids: Vec::new(),
            resolution_evidence_refs: Vec::new(),
            source_watermark: reopened.frontier() + 1,
        };
        group.validate().unwrap();
        reopened
            .commit(
                &journal_command(
                    150,
                    vec![
                        JournalPayload::AttemptRecorded(Box::new(winner.clone())),
                        JournalPayload::AttemptRecorded(Box::new(other)),
                        JournalPayload::CompetingAttemptGroupRecorded(Box::new(group.clone())),
                    ],
                ),
                150,
            )
            .await
            .unwrap();

        let integration_id = IntegrationEventId::new_v7();
        let integration = IntegrationEvent {
            integration_event_id: integration_id,
            repository_instance_id: repository_id,
            source_worktree_instance_id: worktree_id,
            source_snapshot_id: snapshot_id,
            destination_worktree_instance_id: worktree_id,
            destination_snapshot_id: snapshot_id,
            kind: IntegrationKind::ManualPatch,
            commit_refs: Vec::new(),
            patch_equivalence_refs: vec![evidence_receipt_id.to_string()],
            conflict_resolution_detected: false,
            integrated_attempt_ids: vec![winner.attempt_id],
            revalidated_anchor_refs: Vec::new(),
            evidence_refs: vec![evidence_receipt_id.to_string()],
            assessment: LineageAssessment::Proven,
        };
        integration.validate().unwrap();
        let selected = winner.clone();
        winner.revision_id = RevisionId::new_v7();
        winner.predecessor_revision_id = Some(selected.revision_id);
        winner.revision_generation += 1;
        winner.adoption_status = AttemptAdoptionStatus::Integrated;
        winner.verification = AttemptVerification::Passed;
        winner.integration_event_refs.push(integration_id);
        winner.integration_event_refs.sort();
        winner
            .parent_verification_refs
            .push(completed[0].1.result_evidence_id.to_string());
        winner.parent_verification_refs.sort();
        winner.source_watermark = reopened.frontier() + 1;
        selected.validate_successor(&winner).unwrap();
        reopened
            .commit(
                &journal_command(
                    151,
                    vec![
                        JournalPayload::IntegrationEventRecorded(Box::new(integration)),
                        JournalPayload::AttemptRecorded(Box::new(winner.clone())),
                    ],
                ),
                151,
            )
            .await
            .unwrap();
        let writer = reopened;
        let (handle, task_handle) = spawn_writer(writer, 8).unwrap();
        let service = HumanGovernanceService::new(handle.clone(), [27; 32]);
        let page = service
            .list(HumanSurface::Inbox, None, None, 64)
            .await
            .unwrap()
            .unwrap();
        let item = page
            .items
            .iter()
            .find(|item| item.object_ref.as_deref() == Some(group_id.to_string().as_str()))
            .unwrap();
        let detail = service
            .detail(
                HumanSurface::Inbox,
                &item.stable_key,
                page.frontier,
                item.revision_ref.as_deref(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            detail.items[0]
                .competing_detail
                .as_ref()
                .unwrap()
                .eligible_attempt_ids,
            vec![winner.attempt_id]
        );
        let request_id = RequestId::new_v7();
        let first = service
            .resolve_competing_selected(
                request_id,
                page.frontier,
                group.revision_id,
                winner.attempt_id,
            )
            .await
            .unwrap();
        let (selected_revision_ref, audit_event_ref) = match &first {
            HumanActionOutcome::Applied {
                current_revision_ref,
                audit_event_ref,
            } => (current_revision_ref.clone(), audit_event_ref.clone()),
            _ => panic!("eligible competing winner must be selected"),
        };
        let committed = handle
            .committed_command(CommandId::from_uuid(request_id.as_uuid()).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(committed.payloads.len(), 1);
        assert_eq!(committed.event_ids, vec![audit_event_ref.clone()]);
        let JournalPayload::CompetingAttemptGroupRecorded(selected_group) = &committed.payloads[0]
        else {
            panic!("selected command must contain one group successor")
        };
        let mut expected_evidence_refs = vec![
            integration_id.to_string(),
            completed[0].1.result_evidence_id.to_string(),
        ];
        expected_evidence_refs.sort();
        assert_eq!(
            selected_group.resolution_evidence_refs,
            expected_evidence_refs
        );
        let selected_frontier = handle.project().await.unwrap().frontier;
        assert_eq!(
            service
                .resolve_competing_selected(
                    request_id,
                    page.frontier,
                    group.revision_id,
                    winner.attempt_id,
                )
                .await
                .unwrap(),
            first
        );
        assert_eq!(handle.project().await.unwrap().frontier, selected_frontier);
        handle.shutdown().await.unwrap();
        task_handle.await.unwrap().unwrap();

        let reopened = JournalWriter::open(&store_root).await.unwrap();
        let journal_rows = reopened.journal_rows().await.unwrap().len();
        let (reopened_handle, reopened_task) = spawn_writer(reopened, 8).unwrap();
        let reopened_service = HumanGovernanceService::new(reopened_handle.clone(), [27; 32]);
        assert_eq!(
            reopened_service
                .resolve_competing_selected(
                    request_id,
                    page.frontier,
                    group.revision_id,
                    winner.attempt_id,
                )
                .await
                .unwrap(),
            HumanActionOutcome::Applied {
                current_revision_ref: selected_revision_ref,
                audit_event_ref: audit_event_ref.clone(),
            }
        );
        let reopened_snapshot = reopened_handle.project().await.unwrap();
        assert_eq!(reopened_snapshot.frontier, selected_frontier);
        assert_eq!(
            AttemptCurrentView::from_snapshot(&reopened_snapshot)
                .unwrap()
                .competing_groups[&group_id]
                .resolution_status,
            CompetingResolutionStatus::Selected
        );
        reopened_handle.shutdown().await.unwrap();
        reopened_task.await.unwrap().unwrap();
        let final_writer = JournalWriter::open(&store_root).await.unwrap();
        let final_rows = final_writer.journal_rows().await.unwrap();
        assert_eq!(final_rows.len(), journal_rows);
        assert!(final_rows.iter().any(|row| {
            row.event_id == audit_event_ref && row.source_kind == SourceKind::Manual
        }));
        assert_eq!(
            final_writer.project().await.unwrap(),
            final_writer.full_projection().await.unwrap()
        );
    }

    #[tokio::test]
    async fn isolated_terminal_run_is_rejected_before_frontier() {
        let fixture = fixture();
        let terminal_run = fixture
            .snapshot
            .data_rows()
            .find_map(|row| {
                (row.object_kind.as_deref() == Some("experiment_run")).then(|| {
                    serde_json::from_str::<JournalPayload>(row.payload_json.as_deref().unwrap())
                        .unwrap()
                })
            })
            .unwrap();
        assert_eq!(terminal_run.event_type(), "experiment_run_recorded_v1");
        terminal_run.validate().unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(
            temp.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let mut writer = JournalWriter::open(temp.path()).await.unwrap();
        let before = writer.frontier();
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                1,
                [0x44; 32],
                "s27-controlled-v1",
                terminal_run,
            )],
        )
        .unwrap();
        assert!(writer.commit(&command, 1).await.is_err());
        assert_eq!(writer.frontier(), before);
    }
}

#[test]
fn production_f_gate_is_fixed_off_relative_to_layer_a() {
    assert_eq!(procedure_effect_gate(), GateStatus::NotCharacterized);
    assert_eq!(procedure_effect_base_layer(), RetrievalLayer::A);
}

fn candidate(
    revision_id: RevisionId,
    procedure_id: evertrace_domain::ids::ProcedureId,
    repository_id: RepositoryId,
    lexical_rank: u32,
) -> ProcedureCandidate {
    ProcedureCandidate {
        revision: ProcedureRevision {
            procedure_id,
            revision_id,
            parent_revision_id: None,
            revision_generation: 1,
            draft: ProcedureDraft {
                scope: ProcedureScope::Repository { repository_id },
                title: "Recover verification".into(),
                summary: "Run bounded verification".into(),
                kind: ProcedureKind::Diagnostic,
                when: ProcedureWhen {
                    goals: vec!["recover".into()],
                    targets: vec!["artifact".into()],
                    signals: vec!["verifier failed".into()],
                    stage: "verify".into(),
                    requires: vec!["verifier available".into()],
                    excludes: vec!["already complete".into()],
                },
                condition_ir_version: 1,
                applicability_expr: ConstraintExpr::Eq {
                    field: ConstraintField::Phase,
                    value: ConstraintValue::Text("verify".into()),
                },
                avoid_expr: ConstraintExpr::Eq {
                    field: ConstraintField::VerifierState,
                    value: ConstraintValue::Text("passed".into()),
                },
                completion_expr: ConstraintExpr::Eq {
                    field: ConstraintField::ArtifactKind,
                    value: ConstraintValue::Text("complete".into()),
                },
                actions: ProcedureActions {
                    stages: vec!["run verifier".into()],
                    branches: Vec::new(),
                    avoid: vec!["do not publish".into()],
                },
                done: ProcedureDone {
                    success: vec!["verifier passed".into()],
                    abort: vec!["stop on mismatch".into()],
                    verify: vec!["record result".into()],
                },
                pitfalls: vec!["stale artifact".into()],
                evidence_refs: vec!["evidence-1".into()],
                support_revision_refs: Vec::new(),
            },
            source_watermark: 1,
            created_at_us: 1,
        },
        publication: ProcedurePublicationState::ActiveStable,
        global_support: None,
        phase: ProcedurePhase::AtEntry,
        lexical_rank,
    }
}

fn controlled_projection(
    context: &ProcedureEffectContext,
    effect: ProcedureEffect,
) -> evertrace_domain::procedure::ProcedureContextEffectProjection {
    let value = evertrace_domain::procedure::ProcedureContextEffectProjection {
        procedure_revision_id: context.procedure_revision_id,
        context_fingerprint_version: ProcedureEffectContext::FINGERPRINT_VERSION,
        context_fingerprint_hash: context.fingerprint().unwrap(),
        context: context.clone(),
        evidence_class: ProcedureEffectEvidenceClass::ControlledComparison,
        effect,
        valid_usage_count: 0,
        valid_pair_count: 2,
        practical_threshold_revision: 1,
        evidence_refs: vec!["controlled-evidence".into()],
        source_watermark: 1,
    };
    value.validate().unwrap();
    value
}

#[test]
fn f_off_is_identical_and_trusted_controlled_effects_only_tie_break_or_suppress() {
    let revision_id = RevisionId::new_v7();
    let other_revision_id = RevisionId::new_v7();
    let mut effect_context = context(revision_id);
    let ProcedureContextAnchor::Repository {
        repository_id,
        worktree_id,
        ..
    } = &effect_context.anchor
    else {
        unreachable!()
    };
    let search = SearchContext {
        intent: SearchIntent::FailureRecovery,
        raw_query: "verification failed".into(),
        query_facets: QueryFacetSet {
            parse_status: FacetParseStatus::Complete,
            exact_identifiers: Vec::new(),
            condition_literals: Vec::new(),
            relation_requirements: Vec::new(),
            polarity: Polarity::Positive,
            explicit_exclusions: Vec::new(),
            temporal_mode: TemporalMode::Any,
            temporal_qualifiers: Vec::new(),
            quantity_constraints: Vec::new(),
            scope_boundary: None,
            source_boundary: None,
            answer_shape: Some(AnswerShape::EntityList),
            lifecycle_boundary: LifecycleBoundary::Active,
        },
        task_id: Some(effect_context.task_id),
        repository_id: Some(*repository_id),
        worktree_id: Some(*worktree_id),
        suppression: SuppressionSnapshot::Current {
            generation: 0,
            ref_hashes: Default::default(),
        },
        budget: RetrievalBudget {
            candidates_remaining: 8,
            tokens_remaining: 512,
            latency_us_remaining: 100_000,
            hops_remaining: 2,
            follow_ups_remaining: 1,
        },
    };
    let local = ProcedureLocalContext {
        repository_id: Some(*repository_id),
        worktree_id: Some(*worktree_id),
        phase: ProcedureUsagePhase::AtEntry,
        failure_signature: effect_context.failure_signature.clone(),
    };
    let mut bindings = vec![
        ConstraintBinding {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text("verify".into()),
        },
        ConstraintBinding {
            field: ConstraintField::VerifierState,
            value: ConstraintValue::Text("failed".into()),
        },
        ConstraintBinding {
            field: ConstraintField::ArtifactKind,
            value: ConstraintValue::Text("pending".into()),
        },
    ];
    bindings.sort_by_key(|binding| binding.field);
    let state = ConstraintState { bindings };
    let preferred = candidate(
        revision_id,
        evertrace_domain::ids::ProcedureId::new_v7(),
        *repository_id,
        9,
    );
    let lexical = candidate(
        other_revision_id,
        evertrace_domain::ids::ProcedureId::new_v7(),
        *repository_id,
        1,
    );
    let usage = ProcedureUsageCurrentView::default();
    let direct = route_procedures_with_quarantine(
        &usage,
        &local,
        &search,
        vec![preferred.clone(), lexical.clone()],
        &state,
        None,
        true,
        false,
        false,
        true,
    );
    let production = route_procedures_with_effects(
        &usage,
        &local,
        &search,
        vec![preferred.clone(), lexical.clone()],
        &state,
        None,
        true,
        false,
        false,
        true,
    );
    assert_eq!(production, direct);
    assert_eq!(direct.items[0].revision_id, other_revision_id);

    let positive = controlled_projection(&effect_context, ProcedureEffect::Positive);
    let diagnostic = route_procedures_with_passed_effects_diagnostic(
        &usage,
        &local,
        &effect_context,
        std::slice::from_ref(&positive),
        &search,
        vec![preferred.clone(), lexical],
        &state,
        None,
        true,
        false,
        false,
        true,
    );
    assert_eq!(diagnostic.items[0].revision_id, revision_id);
    assert_eq!(diagnostic.items[0].decision, ProcedureDecision::Apply);

    let negative = controlled_projection(&effect_context, ProcedureEffect::Negative);
    let suppressed = route_procedures_with_passed_effects_diagnostic(
        &usage,
        &local,
        &effect_context,
        std::slice::from_ref(&negative),
        &search,
        vec![preferred.clone()],
        &state,
        None,
        true,
        false,
        false,
        true,
    );
    assert_eq!(suppressed.items[0].decision, ProcedureDecision::Defer);
    assert_eq!(suppressed.items[0].reason, "controlled_negative");

    let conflict_neutral = route_procedures_with_passed_effects_diagnostic(
        &usage,
        &local,
        &effect_context,
        &[positive.clone(), negative.clone()],
        &search,
        vec![
            preferred.clone(),
            candidate(
                other_revision_id,
                evertrace_domain::ids::ProcedureId::new_v7(),
                *repository_id,
                1,
            ),
        ],
        &state,
        None,
        true,
        false,
        false,
        true,
    );
    assert_eq!(conflict_neutral.items[0].revision_id, other_revision_id);

    let mut no_guardrail = preferred.clone();
    no_guardrail.revision.draft.actions.avoid.clear();
    no_guardrail.revision.draft.done.abort.clear();
    no_guardrail.revision.draft.done.verify.clear();
    no_guardrail.revision.draft.when.excludes.clear();
    no_guardrail.revision.draft.pitfalls.clear();
    let rejected = route_procedures_with_passed_effects_diagnostic(
        &usage,
        &local,
        &effect_context,
        &[negative],
        &search,
        vec![no_guardrail],
        &state,
        None,
        true,
        false,
        false,
        true,
    );
    assert!(rejected.items.is_empty());
    assert_eq!(rejected.status, "no_applicable_procedure");

    let mut hard_gate_state = state.clone();
    hard_gate_state
        .bindings
        .iter_mut()
        .find(|binding| binding.field == ConstraintField::Phase)
        .unwrap()
        .value = ConstraintValue::Text("implement".into());
    let hard_gate = route_procedures_with_passed_effects_diagnostic(
        &usage,
        &local,
        &effect_context,
        &[positive],
        &search,
        vec![preferred],
        &hard_gate_state,
        None,
        true,
        false,
        false,
        true,
    );
    assert!(hard_gate.items.is_empty());

    effect_context.task_id = TaskId::new_v7();
    let mismatched = route_procedures_with_passed_effects_diagnostic(
        &usage,
        &local,
        &effect_context,
        &[],
        &search,
        vec![],
        &state,
        None,
        true,
        false,
        false,
        true,
    );
    assert_eq!(mismatched.status, "no_applicable_procedure");
}
