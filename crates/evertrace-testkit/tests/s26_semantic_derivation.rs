#[path = "../src/provider.rs"]
mod provider_stub;

use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    config::{DurationValue, LlmConfig, ValidatedBaseUrl},
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceByteRange,
        EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength, ObservationRole,
        SourceArchiveMode, SourceInstanceId, SourceObservation, SourceReceipt,
        SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole, payload_fingerprint,
        source_observation_id, source_receipt_id,
    },
    ids::{CommandId, RepositoryId, TaskId, WorkEpisodeId, WorkstreamId, WorktreeId},
    procedure::{ProcedureActions, ProcedureDone, ProcedureDraft, ProcedureKind, ProcedureWhen},
    repository::{
        FilesystemIdentity, GitObjectFormat, GitRegistrationState, PathObservation,
        RepositoryInstance, WorktreeInstance, WorktreeKind, WorktreeLifecycle,
    },
    revision::RevisionId,
    semantic::{
        ActiveScenarioLineage, ApplicabilityExpr, AtomDraft, AtomKind, AtomProposalPayload,
        AtomProvenance, AtomScope, ConstraintExpr, ConstraintField, EpistemicStatus,
        ProposalCreatedBy, ProposalEligibility, ProposalOperation, ProposalPayload, ProposalStatus,
        ProposalTargetId, ProposalTargetKind, Scenario, ScenarioScope, ScenarioStatus,
        ScenarioWorkstream, SemanticCandidate, SemanticCompleteness, SemanticDigestTrigger,
        SemanticQualifier, SemanticStructuredDelta, TUI_ACCEPTANCE_EVENT_MANIFEST_REF,
        ValidityInterval, WikiProjection, job_fingerprint, tui_acceptance_event_payload,
    },
    work::{
        BoundaryStatus, EpisodeLifecycle, PhaseContract, PhaseKind, Task, TaskIdentityConfidence,
        TaskLifecycle, TaskScopeMembership, Workstream, WorkstreamStatus,
    },
};
use evertrace_engine::{
    jobs::{SynthesisPlanner, SynthesisRequest, SynthesisResolution},
    provider::{
        OpenAiCompatibleProvider, ProtectedDeltaItem, ProtectedDeltaKind, ProtectedSemanticInput,
        ProviderAtomOperation, ProviderAtomValue, ProviderError, ProviderProcedureContent,
        ProviderProcedureOperation, ProviderSemanticApplication, ProviderSemanticCandidate,
        canonical_prompt_hash, canonical_system_prompt,
    },
    semantic::{
        AtomAcceptanceContext, ProposalCommandContext, ProposalResolution, RevisionProposalService,
        SubmitProposalRequest,
    },
    work::new_episode,
};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload, JournalWriter,
    ProjectionSnapshot, SearchIndex, SemanticCurrentView, SourceIngestWatermark,
    derive_l0002_projections,
};
use provider_stub::ProviderStub;
use tempfile::TempDir;

const CONFIG: [u8; 32] = [0x26; 32];

fn application() -> ProviderSemanticApplication {
    ProviderSemanticApplication {
        progress_delta: vec![],
        decision_delta: vec![],
        failed_routes: vec![],
        resolved_items: vec![],
        open_loops: vec![],
        outcome_delta: vec![],
        omissions: vec![],
        candidates: vec![],
        completeness: SemanticCompleteness::Complete,
    }
}

fn provider_atom_value(text: &str) -> ProviderAtomValue {
    ProviderAtomValue {
        text: text.into(),
        subject: "Semantic Lineage".into(),
        predicate: "records".into(),
        object: Some("bounded writer evidence".into()),
        qualifiers: vec![SemanticQualifier {
            name: "source".into(),
            value: "s26".into(),
        }],
    }
}

fn atom_application(text: &str) -> ProviderSemanticApplication {
    let mut application = application();
    application
        .candidates
        .push(ProviderSemanticCandidate::AtomCandidate {
            operation: ProviderAtomOperation::Create,
            target_id: None,
            base_revision_id: None,
            atom_kind: AtomKind::Fact,
            value: provider_atom_value(text),
            applicability_expr: ApplicabilityExpr::Always,
        });
    application
}

fn procedure_application() -> ProviderSemanticApplication {
    let condition = ConstraintExpr::Exists {
        field: ConstraintField::Phase,
    };
    let mut application = application();
    application
        .candidates
        .push(ProviderSemanticCandidate::ProcedureCandidate {
            operation: ProviderProcedureOperation::Create,
            target_id: None,
            base_revision_id: None,
            content: Box::new(ProviderProcedureContent {
                title: "Verify semantic writer".into(),
                summary: "Use direct evidence before accepting a derived procedure.".into(),
                procedure_kind: ProcedureKind::Guardrail,
                when: ProcedureWhen {
                    goals: vec!["verify writer".into()],
                    targets: vec!["semantic digest".into()],
                    signals: vec!["direct evidence".into()],
                    stage: "verification".into(),
                    requires: vec!["current scope".into()],
                    excludes: vec!["stale target".into()],
                },
                applicability_expr: condition.clone(),
                avoid_expr: condition.clone(),
                completion_expr: condition,
                actions: ProcedureActions {
                    stages: vec!["validate direct evidence".into()],
                    branches: vec![],
                    avoid: vec!["provider authority".into()],
                },
                done: ProcedureDone {
                    success: vec!["writer committed".into()],
                    abort: vec!["scope mismatch".into()],
                    verify: vec!["reopen equality".into()],
                },
                pitfalls: vec!["never trust provider scope".into()],
            }),
        });
    application
}

fn scenario_application(scenario_revision_id: RevisionId) -> ProviderSemanticApplication {
    let mut application = application();
    application
        .candidates
        .push(ProviderSemanticCandidate::ScenarioPatch {
            scenario_revision_id,
            current_state_delta: vec!["state:writer-verified".into()],
            open_loop_delta: vec!["loop:review-proposal".into()],
            outcome_delta: vec!["outcome:direct-evidence-retained".into()],
        });
    application
}

fn response(content: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "choices": [{"message": {"content": serde_json::to_string(&content).unwrap()}}],
        "usage": {"prompt_tokens": 17, "completion_tokens": 5}
    }))
    .unwrap()
}

fn input() -> ProtectedSemanticInput {
    ProtectedSemanticInput {
        episode_id: WorkEpisodeId::new_v7(),
        episode_revision_id: RevisionId::new_v7(),
        task_id: TaskId::new_v7(),
        from_watermark: 3,
        to_watermark: 4,
        trigger: "strategy_pivot",
        direct_delta: vec![ProtectedDeltaItem {
            kind: ProtectedDeltaKind::Decision,
            value: "selected deterministic route".into(),
            direct_refs: vec!["operation:1".into()],
        }],
        source_refs: vec!["operation:1".into()],
    }
}

fn config(base_url: &str) -> LlmConfig {
    LlmConfig {
        base_url: ValidatedBaseUrl::parse(base_url).unwrap(),
        api_key_env: "PATH".into(),
        ..LlmConfig::default()
    }
}

fn task_and_stream(
    root: &std::path::Path,
) -> (RepositoryInstance, WorktreeInstance, Task, Workstream) {
    let repository_id = RepositoryId::new_v7();
    let worktree_id = WorktreeId::new_v7();
    let task = Task {
        task_id: TaskId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec!["request:s26".into()],
        canonical_goal: "derive one bounded semantic delta".into(),
        scope_memberships: vec![TaskScopeMembership {
            repository_instance_id: Some(repository_id),
            worktree_instance_ids: vec![worktree_id],
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
    };
    let stream = Workstream {
        workstream_id: WorkstreamId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        task_id: task.task_id,
        repository_instance_id: Some(repository_id),
        worktree_instance_ids: vec![worktree_id],
        active_worktree_instance_id: Some(worktree_id),
        worktree_lineage_refs: vec![],
        parent_workstream_id: None,
        dependency_workstream_ids: vec![],
        status: WorkstreamStatus::Active,
        root_goal: task.canonical_goal.clone(),
        workstream_goal: "compile the direct delta".into(),
        target_family: "semantic_digest".into(),
        hypothesis_or_failure_family: "bounded synthesis".into(),
        acceptance_boundary: "strict schema".into(),
        phase_contract: PhaseContract {
            local_goal: "compile the direct delta".into(),
            phase_kind: PhaseKind::Implement,
            phase_label: "implement".into(),
            primary_targets: vec!["semantic_digest".into()],
            entry_conditions: vec!["direct source available".into()],
            acceptance_boundary: "strict schema".into(),
            expected_state_transition: "semantic watermark advances".into(),
        },
        active_episode_id: None,
        execution_lane_ids: vec![],
        source_watermark: 1,
    };
    let path = root.join("repo").display().to_string();
    let path_observation = PathObservation {
        path: path.clone(),
        first_observed_at_us: 1,
        last_observed_at_us: 1,
        evidence_refs: vec!["path:s26".into()],
    };
    let repository = RepositoryInstance {
        repository_id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: path.clone(),
        path_history: vec![path_observation.clone()],
        git_common_dir_path: Some(format!("{path}/.git")),
        common_dir_filesystem: Some(FilesystemIdentity {
            device: 26,
            inode: 1,
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: vec![],
        derived_from: None,
        identity_evidence_refs: vec!["repository:s26".into()],
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
            path: format!("{path}/.git"),
            ..path_observation
        }],
        git_registration_state: GitRegistrationState::Registered,
        current_snapshot_id: None,
        created_event_ref: "worktree:s26".into(),
        terminal_event_ref: None,
        recreated_from_worktree_instance_id: None,
        recorded_at_us: 1,
    };
    (repository, worktree, task, stream)
}

fn source(
    label: &str,
    payload: &str,
    task_id: TaskId,
    repository_id: RepositoryId,
    worktree_id: WorktreeId,
) -> (SourceReceipt, SourceObservation) {
    let instance = SourceInstanceId::parse(format!("s26-{label}")).unwrap();
    let revision = SourceRevision::parse("revision-1").unwrap();
    let record = SourceRecordIdentity::parse(format!("record-{label}")).unwrap();
    let observation_id = source_observation_id(&instance, &revision, &record).unwrap();
    let receipt_id = source_receipt_id(&instance, &revision, &record).unwrap();
    let digest =
        evertrace_domain::evidence::hex(&payload_fingerprint(1, payload.as_bytes(), None).unwrap());
    let receipt = SourceReceipt {
        source_receipt_id: receipt_id,
        source_observation_id: observation_id,
        source_instance_id: instance.clone(),
        source_kind: EvidenceSourceKind::CodexSessionJsonl,
        identity_domain: "codex-session-v1".into(),
        source_ref: format!("source-ref-{label}"),
        source_session_ref: format!("session-{label}"),
        source_revision: revision.clone(),
        source_record_identity: record.clone(),
        identity_strength: IdentityStrength::StableNative,
        source_sequence: 1,
        source_sequence_origin: None,
        task_id: Some(task_id),
        repository_instance_id: Some(repository_id),
        worktree_instance_id: Some(worktree_id),
        source_byte_range: None,
        spool_byte_range: EvidenceByteRange { start: 1, end: 2 },
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: Some(1),
        observation_role: ObservationRole::Message,
        unsupported_record_classification: None,
        capture_completeness: CaptureCompleteness::Complete,
        archive_mode: SourceArchiveMode::Exact,
        cas_ref: digest.clone(),
        protected_length: payload.len() as u64,
        original_length: payload.len() as u64,
        protected_secret_digest: None,
        redaction_spans: vec![],
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-s26".into(),
        eligible_event_manifest_ref: "eligible-s26".into(),
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
        observation_role: ObservationRole::Message,
        identity_strength: IdentityStrength::StableNative,
        payload_fingerprint: digest,
        source_receipt_ref: receipt_id,
        source_role: SourceRole::User,
        content_trust: ContentTrust::UserStatement,
        capture_completeness: CaptureCompleteness::Complete,
        adapter_revision: 1,
        parser_revision: 1,
        canonicalization_revision: 1,
        detector_revision: 1,
        redaction_revision: 1,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            pairing_role: ObservationRole::Message,
            field_provenance: vec![],
            adapter_manifest_ref: "adapter-s26".into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: vec![],
    };
    receipt.validate().unwrap();
    observation.validate().unwrap();
    (receipt, observation)
}

fn command(at: i64, payloads: Vec<JournalPayload>) -> JournalCommand {
    JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, CONFIG, "s26-v1", payload))
            .collect(),
    )
    .unwrap()
}

fn mutate_atom_command_drafts(
    payloads: &mut [JournalPayload],
    mut mutate: impl FnMut(&mut AtomDraft),
) {
    for payload in payloads {
        match payload {
            JournalPayload::SemanticDigestRecorded(digest) => {
                for candidate in &mut digest.application.candidates {
                    if let SemanticCandidate::AtomProposal { payload, .. } = candidate {
                        let draft = match payload.as_mut() {
                            AtomProposalPayload::Create { draft }
                            | AtomProposalPayload::Replace { draft }
                            | AtomProposalPayload::Reclassify { draft } => draft,
                            _ => continue,
                        };
                        mutate(draft);
                    }
                }
            }
            JournalPayload::RevisionProposalRecorded(proposal) => {
                if let ProposalPayload::Atom(payload) = &mut proposal.payload {
                    let draft = match payload.as_mut() {
                        AtomProposalPayload::Create { draft }
                        | AtomProposalPayload::Replace { draft }
                        | AtomProposalPayload::Reclassify { draft } => draft,
                        _ => continue,
                    };
                    mutate(draft);
                    proposal.fingerprint = proposal.recompute_fingerprint().unwrap();
                }
            }
            _ => {}
        }
    }
}

fn mutate_procedure_command_drafts(
    payloads: &mut [JournalPayload],
    mut mutate: impl FnMut(&mut ProcedureDraft),
) {
    for payload in payloads {
        match payload {
            JournalPayload::SemanticDigestRecorded(digest) => {
                for candidate in &mut digest.application.candidates {
                    if let SemanticCandidate::ProcedureProposal { payload, .. } = candidate {
                        let draft = match payload.as_mut() {
                            evertrace_domain::semantic::ProcedureProposalPayload::Create {
                                draft,
                            }
                            | evertrace_domain::semantic::ProcedureProposalPayload::Replace {
                                draft,
                            } => draft,
                        };
                        mutate(draft);
                    }
                }
            }
            JournalPayload::RevisionProposalRecorded(proposal) => {
                if let ProposalPayload::Procedure(payload) = &mut proposal.payload {
                    let draft = match payload.as_mut() {
                        evertrace_domain::semantic::ProcedureProposalPayload::Create { draft }
                        | evertrace_domain::semantic::ProcedureProposalPayload::Replace { draft } => {
                            draft
                        }
                    };
                    mutate(draft);
                    proposal.fingerprint = proposal.recompute_fingerprint().unwrap();
                }
            }
            _ => {}
        }
    }
}

fn proposal_context(at: i64) -> ProposalCommandContext {
    ProposalCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: "s26-v1".into(),
    }
}

fn atom_draft(seed: &Seed, text: &str, scope: AtomScope, at: i64) -> AtomDraft {
    AtomDraft {
        kind: AtomKind::Fact,
        epistemic_status: EpistemicStatus::Unverified,
        value: provider_atom_value(text).into(),
        scope,
        applicability_expr: ApplicabilityExpr::Always,
        future_cue_lifecycle_exprs: None,
        validity_interval: ValidityInterval {
            valid_from_us: at,
            valid_until_us: None,
        },
        provenance: vec![AtomProvenance::LlmDerived],
        source_observation_refs: vec![],
        evidence_refs: seed.direct_refs(),
        supersedes_revision_refs: vec![],
        supports_revision_refs: vec![],
        contradicts_revision_refs: vec![],
    }
}

fn tui_acceptance_source(
    label: &str,
    proposal: &evertrace_domain::semantic::RevisionProposal,
    seed: &Seed,
) -> (SourceReceipt, SourceObservation) {
    let payload = tui_acceptance_event_payload(
        proposal.proposal_id,
        proposal.proposal_revision_id,
        &proposal.fingerprint,
    );
    let (mut receipt, observation) = source(
        label,
        &payload,
        seed.task.task_id,
        seed.repository.repository_id,
        seed.worktree.worktree_instance_id,
    );
    receipt.eligible_event_manifest_ref = TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into();
    receipt.event_time_us = 0;
    receipt.recorded_at_us = proposal.created_at_us.checked_add(1).unwrap();
    (receipt, observation)
}

async fn persist_source(
    writer: &mut JournalWriter,
    receipt: &SourceReceipt,
    observation: &SourceObservation,
    at: i64,
) {
    writer
        .commit(
            &command(
                at,
                vec![
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
                        algorithm_revision: "s26-v1".into(),
                        source_watermark: receipt.source_sequence,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::PhysicalNormalization,
                        target_id: observation.source_observation_id.to_string(),
                        algorithm_revision: "s26-v1".into(),
                        source_watermark: receipt.source_sequence,
                    }),
                ],
            ),
            at,
        )
        .await
        .unwrap();
}

struct Seed {
    writer: JournalWriter,
    task: Task,
    episode: evertrace_domain::work::WorkEpisode,
    snapshot: ProjectionSnapshot,
    receipt: SourceReceipt,
    observation: SourceObservation,
    repository: RepositoryInstance,
    worktree: WorktreeInstance,
}

impl Seed {
    fn direct_refs(&self) -> Vec<String> {
        let mut refs = vec![
            self.receipt.source_receipt_id.to_string(),
            self.observation.source_observation_id.to_string(),
        ];
        refs.sort();
        refs
    }
}

fn current_scenario(seed: &Seed) -> Scenario {
    let scope = ScenarioScope {
        task_id: seed.task.task_id,
        repository_instance_id: Some(seed.repository.repository_id),
        worktree_instance_id: Some(seed.worktree.worktree_instance_id),
    };
    let scenario = Scenario {
        scenario_id: scope.scenario_id().unwrap(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        revision_generation: 1,
        scope,
        active_worktree_snapshot_id: None,
        worktree_lineage_refs: vec!["lineage:main".into()],
        status: ScenarioStatus::Active,
        goal: "verify content-only scenario synthesis".into(),
        current_state: vec!["state:direct-evidence".into()],
        active_lineage: ActiveScenarioLineage {
            active_workstream_id: Some(seed.episode.workstream_id),
            active_episode_id: Some(seed.episode.episode_id),
            active_attempt_id: None,
            unresolved_competing_group_ids: vec![],
        },
        active_workstreams: vec![ScenarioWorkstream {
            workstream_id: seed.episode.workstream_id,
            phase_kind: PhaseKind::Implement,
            open_episode_id: Some(seed.episode.episode_id),
        }],
        running_experiment_refs: vec![],
        constraints: vec![],
        decisions: vec![],
        open_loops: vec!["loop:review-proposal".into()],
        active_failures: vec![],
        completed_outcomes: vec![],
        relevant_artifacts: vec![],
        support_atom_ids: vec![],
        source_watermark: seed.episode.source_watermark,
    };
    scenario.validate().unwrap();
    scenario
}

async fn seed_store(path: &std::path::Path) -> Seed {
    seed_store_with_lifecycle(path, EpisodeLifecycle::Open).await
}

async fn seed_closed_store(path: &std::path::Path) -> Seed {
    seed_store_with_lifecycle(path, EpisodeLifecycle::Closed).await
}

async fn seed_store_with_lifecycle(path: &std::path::Path, lifecycle: EpisodeLifecycle) -> Seed {
    let mut writer = JournalWriter::open(path).await.unwrap();
    let (repository, worktree, task, stream) = task_and_stream(path);
    let (receipt, observation) = source(
        "writer-cohort",
        "S26 direct evidence cohort",
        task.task_id,
        repository.repository_id,
        worktree.worktree_instance_id,
    );
    let mut episode = new_episode(&stream, None, 2).unwrap();
    if lifecycle == EpisodeLifecycle::Closed {
        episode.lifecycle_status = EpisodeLifecycle::Closed;
        episode.boundary_status = BoundaryStatus::Confirmed;
        episode.confirmation_watermark = episode.source_watermark;
    }
    writer
        .commit(
            &command(
                1,
                vec![
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
                        algorithm_revision: "s26-v1".into(),
                        source_watermark: 1,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::PhysicalNormalization,
                        target_id: observation.source_observation_id.to_string(),
                        algorithm_revision: "s26-v1".into(),
                        source_watermark: 1,
                    }),
                    JournalPayload::RepositoryInstanceRecorded(Box::new(repository.clone())),
                    JournalPayload::WorktreeInstanceRecorded(Box::new(worktree.clone())),
                    JournalPayload::TaskRecorded(Box::new(task.clone())),
                    JournalPayload::WorkstreamRecorded(Box::new(stream.clone())),
                ],
            ),
            1,
        )
        .await
        .unwrap();
    let mut active_stream = stream.clone();
    active_stream.revision_id = RevisionId::new_v7();
    active_stream.predecessor_revision_id = Some(stream.revision_id);
    active_stream.active_episode_id =
        (lifecycle == EpisodeLifecycle::Open).then_some(episode.episode_id);
    active_stream.source_watermark = 2;
    writer
        .commit(
            &command(
                2,
                vec![
                    JournalPayload::WorkstreamRecorded(Box::new(active_stream.clone())),
                    JournalPayload::WorkEpisodeRecorded(Box::new(episode.clone())),
                ],
            ),
            2,
        )
        .await
        .unwrap();
    let snapshot = writer.project().await.unwrap();
    Seed {
        writer,
        task,
        episode,
        snapshot,
        receipt,
        observation,
        repository,
        worktree,
    }
}

#[tokio::test]
async fn openai_compatible_provider_is_single_bounded_strict_boundary() {
    let stub =
        ProviderStub::once(200, response(serde_json::to_value(application()).unwrap())).await;
    let provider = OpenAiCompatibleProvider::new(&config(&stub.base_url)).unwrap();
    let result = provider.derive(&input()).await.unwrap();
    assert_eq!(result.application, application());
    assert_eq!((result.input_tokens, result.output_tokens), (17, 5));

    let request = stub.finish().await;
    let split = request
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .unwrap();
    let headers = String::from_utf8_lossy(&request[..split]);
    assert!(headers.starts_with("POST /v1/chat/completions HTTP/1.1"));
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("authorization: bearer ")
    );
    let request_json: serde_json::Value = serde_json::from_slice(&request[split + 4..]).unwrap();
    assert_eq!(request_json["stream"], false);
    assert_eq!(request_json["temperature"], 0);
    assert_eq!(request_json["messages"].as_array().unwrap().len(), 2);
    let system_content = request_json["messages"][0]["content"].as_str().unwrap();
    assert_eq!(
        system_content.as_bytes(),
        canonical_system_prompt().as_bytes()
    );
    assert_eq!(
        canonical_prompt_hash(),
        sha256(
            "evertrace.semantic_provider.prompt",
            1,
            &CanonicalValue::Bytes(system_content.as_bytes().to_vec()),
        )
        .unwrap()
    );
    assert!(system_content.contains("Every array field may be empty"));
    assert!(system_content.contains("candidates must be [] or [candidate]"));
    assert!(system_content.contains("create requires target_id=null and base_revision_id=null"));
    assert!(
        system_content
            .contains("replace/reclassify require both target_id and base_revision_id non-null")
    );
}

#[tokio::test]
async fn provider_rejects_non_success_and_authority_injection() {
    let missing = LlmConfig {
        api_key_env: "EVERTRACE_S26_TEST_KEY_MUST_NOT_EXIST".into(),
        ..LlmConfig::default()
    };
    let provider = OpenAiCompatibleProvider::new(&missing).unwrap();
    assert_eq!(
        provider.derive(&input()).await.unwrap_err(),
        ProviderError::MissingSecret
    );
    let disabled = LlmConfig {
        enabled: false,
        ..LlmConfig::default()
    };
    assert!(matches!(
        OpenAiCompatibleProvider::new(&disabled),
        Err(ProviderError::Disabled)
    ));

    let failed = ProviderStub::once(503, b"{}".to_vec()).await;
    let provider = OpenAiCompatibleProvider::new(&config(&failed.base_url)).unwrap();
    assert_eq!(
        provider.derive(&input()).await.unwrap_err(),
        ProviderError::NonSuccess
    );
    let _ = failed.finish().await;

    let mut injected = serde_json::to_value(application()).unwrap();
    injected["authority"] = serde_json::json!("user_explicit");
    let malformed = ProviderStub::once(200, response(injected)).await;
    let provider = OpenAiCompatibleProvider::new(&config(&malformed.base_url)).unwrap();
    assert_eq!(
        provider.derive(&input()).await.unwrap_err(),
        ProviderError::Schema
    );
    let _ = malformed.finish().await;

    let oversized = ProviderStub::once(200, vec![b'x'; 256 * 1024 + 1]).await;
    let provider = OpenAiCompatibleProvider::new(&config(&oversized.base_url)).unwrap();
    assert_eq!(
        provider.derive(&input()).await.unwrap_err(),
        ProviderError::ResponseOversize
    );
    let _ = oversized.finish().await;

    let delayed = ProviderStub::once_delayed(
        200,
        response(serde_json::to_value(application()).unwrap()),
        std::time::Duration::from_secs(2),
    )
    .await;
    let mut timeout_config = config(&delayed.base_url);
    timeout_config.timeout = DurationValue::from_seconds(1).unwrap();
    let provider = OpenAiCompatibleProvider::new(&timeout_config).unwrap();
    assert_eq!(
        provider.derive(&input()).await.unwrap_err(),
        ProviderError::Timeout
    );
    let _ = delayed.finish().await;

    let valid = serde_json::to_value(atom_application("content only")).unwrap();
    let mut injected_scope = valid.clone();
    injected_scope["candidates"][0]["task_id"] = serde_json::json!(TaskId::new_v7());
    assert!(serde_json::from_value::<ProviderSemanticApplication>(injected_scope).is_err());
    let mut injected_authority = valid.clone();
    injected_authority["candidates"][0]["authority"] = serde_json::json!("user_explicit");
    assert!(serde_json::from_value::<ProviderSemanticApplication>(injected_authority).is_err());
    let mut injected_support = valid.clone();
    injected_support["candidates"][0]["supports_revision_refs"] = serde_json::json!([]);
    assert!(serde_json::from_value::<ProviderSemanticApplication>(injected_support).is_err());
    let mut injected_critical = valid;
    injected_critical["candidates"][0]["value"]["critical_revision_refs"] =
        serde_json::json!([RevisionId::new_v7()]);
    assert!(serde_json::from_value::<ProviderSemanticApplication>(injected_critical).is_err());

    let mut invalid_procedure = serde_json::to_value(procedure_application()).unwrap();
    invalid_procedure["candidates"][0]["content"]["condition_ir_version"] = serde_json::json!(99);
    assert!(serde_json::from_value::<ProviderSemanticApplication>(invalid_procedure).is_err());
}

#[tokio::test]
async fn planner_commits_one_atomic_digest_run_and_semantic_episode_successor() {
    let temp = TempDir::new().unwrap();
    let seed = seed_store(&temp.path().join("store")).await;
    let direct_refs = seed.direct_refs();
    let Seed {
        mut writer,
        episode,
        snapshot,
        ..
    } = seed;
    let mut derived = application();
    derived.progress_delta.push(SemanticStructuredDelta {
        label: "progress".into(),
        value: "bounded semantic checkpoint".into(),
        direct_refs: direct_refs.clone(),
    });
    let stub = ProviderStub::once(200, response(serde_json::to_value(derived).unwrap())).await;
    let llm = config(&stub.base_url);
    let planner = SynthesisPlanner::new(llm);
    let resolution = planner
        .execute(SynthesisRequest {
            snapshot: &snapshot,
            episode_revision_id: episode.revision_id,
            trigger: SemanticDigestTrigger::StrategyPivot,
            direct_delta: vec![ProtectedDeltaItem {
                kind: ProtectedDeltaKind::Progress,
                value: "bounded semantic checkpoint".into(),
                direct_refs: direct_refs.clone(),
            }],
            selected_direct_refs: direct_refs,
            command_id: CommandId::new_v7(),
            occurred_at_us: 2,
            algorithm_revision: "s26-v1".into(),
            effective_config_hash: CONFIG,
        })
        .await
        .unwrap();
    let _ = stub.finish().await;
    let SynthesisResolution::Success {
        digest,
        run,
        episode: successor,
        command: success_command,
    } = resolution
    else {
        panic!("strict success must produce the atomic cohort")
    };
    assert_eq!(run.job_fingerprint, digest.job_fingerprint);
    assert_eq!(successor.semantic_watermark, episode.source_watermark);
    let mut mismatched_time_payloads = success_command
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    for payload in &mut mismatched_time_payloads {
        if let JournalPayload::SemanticDigestRecorded(digest) = payload {
            digest.created_at_us += 1;
        }
    }
    let mismatched_time = command(2, mismatched_time_payloads);
    assert!(
        writer
            .commit_if_frontier(&mismatched_time, 2, snapshot.frontier)
            .await
            .is_err()
    );
    assert_eq!(writer.project().await.unwrap().frontier, snapshot.frontier);
    let partial = command(
        2,
        success_command
            .events()
            .iter()
            .filter(|event| {
                !matches!(
                    &event.payload,
                    JournalPayload::SemanticDerivationRunRecorded(_)
                )
            })
            .map(|event| event.payload.clone())
            .collect(),
    );
    assert!(
        writer
            .commit_if_frontier(&partial, 2, snapshot.frontier)
            .await
            .is_err()
    );
    assert_eq!(
        writer.journal_rows().await.unwrap().len() as u64,
        snapshot.frontier
    );
    let committed = writer
        .commit_if_frontier(&success_command, 2, snapshot.frontier)
        .await
        .unwrap();
    assert!(!committed.replayed);
    writer.full_projection().await.unwrap();
    let projected = writer.project().await.unwrap();
    assert!(projected.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("semantic_digest")
            && row.object_id.as_deref() == Some(&digest.semantic_digest_id.to_string())
    }));
    let search = SearchIndex::open(&temp.path().join("store")).await.unwrap();
    assert!(search.fts("checkpoint").await.unwrap().iter().any(|row| {
        row.candidate_id.as_deref() == Some(&digest.semantic_digest_id.to_string())
    }));
    let relation_kinds = writer
        .relation_rows()
        .await
        .unwrap()
        .into_iter()
        .filter_map(|row| row.relation_kind)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(relation_kinds.contains("semantic_digest_to_episode"));
    assert!(relation_kinds.contains("semantic_digest_to_task"));
    assert!(relation_kinds.contains("semantic_digest_to_direct_source"));
    assert_eq!(
        writer.table_names().await.unwrap(),
        vec![
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search",
        ]
    );
    let replay = writer.commit(&success_command, 3).await.unwrap();
    assert!(replay.replayed);
    drop(writer);
    let reopened = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    assert_eq!(reopened.project().await.unwrap(), projected);
}

#[tokio::test]
async fn planner_failures_audit_without_digest_or_watermark_progress() {
    let temp = TempDir::new().unwrap();
    let store_root = temp.path().join("store");
    let seed = seed_store(&store_root).await;
    let reference = seed.receipt.source_receipt_id.to_string();
    let Seed {
        mut writer,
        episode,
        snapshot,
        ..
    } = seed;
    let llm = LlmConfig {
        enabled: false,
        ..LlmConfig::default()
    };
    let command_id = CommandId::new_v7();
    let planner = SynthesisPlanner::new(llm);
    let resolution = planner
        .execute(SynthesisRequest {
            snapshot: &snapshot,
            episode_revision_id: episode.revision_id,
            trigger: SemanticDigestTrigger::StrategyPivot,
            direct_delta: vec![ProtectedDeltaItem {
                kind: ProtectedDeltaKind::Failure,
                value: "provider unavailable".into(),
                direct_refs: vec![reference.clone()],
            }],
            selected_direct_refs: vec![reference.clone()],
            command_id,
            occurred_at_us: 3,
            algorithm_revision: "s26-v1".into(),
            effective_config_hash: CONFIG,
        })
        .await
        .unwrap();
    let SynthesisResolution::Audit {
        run,
        command: audit_command,
    } = resolution
    else {
        panic!("disabled provider must produce only a bounded run audit")
    };
    assert_eq!(
        run.status,
        evertrace_domain::semantic::DerivationRunStatus::ProviderUnavailable
    );
    let mut wrong_episode_payloads = audit_command
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    for payload in &mut wrong_episode_payloads {
        if let JournalPayload::SemanticDerivationRunRecorded(run) = payload {
            run.episode_revision_id = RevisionId::new_v7();
            run.to_watermark += 1;
            run.job_fingerprint = job_fingerprint(
                run.episode_id,
                run.episode_revision_id,
                run.from_watermark,
                run.to_watermark,
                &run.selected_direct_refs,
                &run.model_id,
                &run.prompt_hash,
                run.schema_version,
                &run.algorithm_revision,
                &run.effective_config_hash,
            )
            .unwrap();
        }
    }
    let wrong_episode = command(3, wrong_episode_payloads);
    assert!(
        writer
            .commit_if_frontier(&wrong_episode, 3, snapshot.frontier)
            .await
            .is_err()
    );
    assert_eq!(writer.project().await.unwrap().frontier, snapshot.frontier);
    writer
        .commit_if_frontier(&audit_command, 3, snapshot.frontier)
        .await
        .unwrap();
    let after = writer.project().await.unwrap();
    assert!(
        !after
            .data_rows()
            .any(|row| row.object_kind.as_deref() == Some("semantic_digest"))
    );
    let current_episode: evertrace_domain::work::WorkEpisode = after
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("work_episode"))
        .max_by_key(|row| row.source_event_seq)
        .and_then(|row| row.payload_json.as_deref())
        .and_then(|json| serde_json::from_str::<JournalPayload>(json).ok())
        .and_then(|payload| match payload {
            JournalPayload::WorkEpisodeRecorded(value) => Some(*value),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        current_episode.semantic_watermark,
        episode.semantic_watermark
    );

    let mut recovered_application = application();
    recovered_application
        .failed_routes
        .push(SemanticStructuredDelta {
            label: "failure".into(),
            value: "provider unavailable".into(),
            direct_refs: vec![reference.clone()],
        });
    let recovered_stub = ProviderStub::once(
        200,
        response(serde_json::to_value(recovered_application).unwrap()),
    )
    .await;
    let recovered_planner = SynthesisPlanner::new(config(&recovered_stub.base_url));
    let retry = recovered_planner
        .execute(SynthesisRequest {
            snapshot: &after,
            episode_revision_id: episode.revision_id,
            trigger: SemanticDigestTrigger::StrategyPivot,
            direct_delta: vec![ProtectedDeltaItem {
                kind: ProtectedDeltaKind::Failure,
                value: "provider unavailable".into(),
                direct_refs: vec![reference.clone()],
            }],
            selected_direct_refs: vec![reference.clone()],
            command_id: CommandId::new_v7(),
            occurred_at_us: 4,
            algorithm_revision: "s26-v1".into(),
            effective_config_hash: CONFIG,
        })
        .await
        .unwrap();
    let SynthesisResolution::Success { command, .. } = retry else {
        panic!("a failed fingerprint must remain retryable")
    };
    let _ = recovered_stub.finish().await;
    writer
        .commit_if_frontier(&command, 4, after.frontier)
        .await
        .unwrap();

    let shared_ref = planner
        .execute(SynthesisRequest {
            snapshot: &after,
            episode_revision_id: episode.revision_id,
            trigger: SemanticDigestTrigger::StrategyPivot,
            direct_delta: vec![
                ProtectedDeltaItem {
                    kind: ProtectedDeltaKind::Failure,
                    value: "first".into(),
                    direct_refs: vec![reference.clone()],
                },
                ProtectedDeltaItem {
                    kind: ProtectedDeltaKind::Resolution,
                    value: "second".into(),
                    direct_refs: vec![reference.clone()],
                },
            ],
            selected_direct_refs: vec![reference],
            command_id: CommandId::new_v7(),
            occurred_at_us: 4,
            algorithm_revision: "s26-v1".into(),
            effective_config_hash: CONFIG,
        })
        .await;
    assert!(matches!(shared_ref, Ok(SynthesisResolution::Audit { .. })));

    let too_many_refs = (0..257)
        .map(|index| format!("source:bounded:{index:03}"))
        .collect::<Vec<_>>();
    let bounded = planner
        .execute(SynthesisRequest {
            snapshot: &after,
            episode_revision_id: episode.revision_id,
            trigger: SemanticDigestTrigger::StrategyPivot,
            direct_delta: vec![
                ProtectedDeltaItem {
                    kind: ProtectedDeltaKind::Progress,
                    value: "first bounded half".into(),
                    direct_refs: too_many_refs[..128].to_vec(),
                },
                ProtectedDeltaItem {
                    kind: ProtectedDeltaKind::Progress,
                    value: "second bounded half".into(),
                    direct_refs: too_many_refs[128..].to_vec(),
                },
            ],
            selected_direct_refs: too_many_refs,
            command_id: CommandId::new_v7(),
            occurred_at_us: 4,
            algorithm_revision: "s26-v1".into(),
            effective_config_hash: CONFIG,
        })
        .await;
    assert!(bounded.is_err());
    let projected = writer.project().await.unwrap();
    assert_eq!(projected, writer.full_projection().await.unwrap());
    drop(writer);
    let reopened = JournalWriter::open(&store_root).await.unwrap();
    assert_eq!(reopened.project().await.unwrap(), projected);
}

#[tokio::test]
async fn one_planner_reuses_provider_and_writes_content_only_atom_proposals() {
    let first_temp = TempDir::new().unwrap();
    let second_temp = TempDir::new().unwrap();
    let mut first = seed_store(&first_temp.path().join("store")).await;
    let mut second = seed_store(&second_temp.path().join("store")).await;
    let first_refs = first.direct_refs();
    assert_eq!(first_refs, second.direct_refs());
    let mut atom_response = atom_application("writer atom");
    atom_response.progress_delta.push(SemanticStructuredDelta {
        label: "progress".into(),
        value: "derive a content-only atom".into(),
        direct_refs: first_refs.clone(),
    });
    let body = response(serde_json::to_value(atom_response).unwrap());
    let stub = ProviderStub::repeat(200, body, 2).await;
    let planner = SynthesisPlanner::new(config(&stub.base_url));

    let first_resolution = planner
        .execute(SynthesisRequest {
            snapshot: &first.snapshot,
            episode_revision_id: first.episode.revision_id,
            trigger: SemanticDigestTrigger::AdoptedDecision,
            direct_delta: vec![ProtectedDeltaItem {
                kind: ProtectedDeltaKind::Decision,
                value: "derive a content-only atom".into(),
                direct_refs: first_refs.clone(),
            }],
            selected_direct_refs: first_refs.clone(),
            command_id: CommandId::new_v7(),
            occurred_at_us: 3,
            algorithm_revision: "s26-v1".into(),
            effective_config_hash: CONFIG,
        })
        .await
        .unwrap();
    let second_refs = second.direct_refs();
    let second_resolution = planner
        .execute(SynthesisRequest {
            snapshot: &second.snapshot,
            episode_revision_id: second.episode.revision_id,
            trigger: SemanticDigestTrigger::AdoptedDecision,
            direct_delta: vec![ProtectedDeltaItem {
                kind: ProtectedDeltaKind::Decision,
                value: "derive a content-only atom".into(),
                direct_refs: second_refs,
            }],
            selected_direct_refs: second.direct_refs(),
            command_id: CommandId::new_v7(),
            occurred_at_us: 3,
            algorithm_revision: "s26-v1".into(),
            effective_config_hash: CONFIG,
        })
        .await
        .unwrap();
    let requests = stub.finish_all().await;
    assert_eq!(requests.len(), 2);

    let SynthesisResolution::Success {
        digest,
        command: first_command,
        ..
    } = first_resolution
    else {
        panic!("the first writer cohort must succeed")
    };
    let [SemanticCandidate::AtomProposal { payload, .. }] =
        digest.application.candidates.as_slice()
    else {
        panic!("provider atom content must become one proposal candidate")
    };
    let AtomProposalPayload::Create { draft } = payload.as_ref() else {
        panic!("the provider requested a create candidate")
    };
    assert_eq!(
        draft.scope,
        AtomScope::Task {
            task_id: first.task.task_id
        }
    );
    assert_eq!(draft.epistemic_status, EpistemicStatus::Unverified);
    assert_eq!(draft.provenance, vec![AtomProvenance::LlmDerived]);
    assert_eq!(draft.evidence_refs, first_refs);
    assert!(draft.source_observation_refs.is_empty());
    assert!(draft.supports_revision_refs.is_empty());
    assert!(draft.value.critical_revision_refs.is_empty());
    assert!(draft.future_cue_lifecycle_exprs.is_none());
    let proposals = first_command
        .events()
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::RevisionProposalRecorded(proposal) => Some(proposal.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [proposal] = proposals.as_slice() else {
        panic!("one pending proposal must be in the atomic command")
    };
    assert_eq!(proposal.status, ProposalStatus::Pending);
    assert_eq!(proposal.eligibility, ProposalEligibility::ManualRequired);
    assert_eq!(proposal.created_by, ProposalCreatedBy::Agent);
    assert_eq!(
        proposal.evidence_refs,
        vec![digest.semantic_digest_id.to_string()]
    );
    assert_eq!(proposal.source_cohort_refs, first.direct_refs());
    for mutation in 0..3 {
        let mut forged_payloads = first_command
            .events()
            .iter()
            .map(|event| event.payload.clone())
            .collect::<Vec<_>>();
        let critical_revision = RevisionId::new_v7();
        mutate_atom_command_drafts(&mut forged_payloads, |draft| match mutation {
            0 => draft.provenance = vec![AtomProvenance::AgentClaimed],
            1 => draft.evidence_refs = vec![first_refs[0].clone()],
            2 => draft.value.critical_revision_refs = vec![critical_revision],
            _ => unreachable!(),
        });
        let forged = command(3, forged_payloads);
        assert!(
            first
                .writer
                .commit_if_frontier(&forged, 3, first.snapshot.frontier)
                .await
                .is_err()
        );
        assert_eq!(
            first.writer.project().await.unwrap().frontier,
            first.snapshot.frontier
        );
    }
    first
        .writer
        .commit_if_frontier(&first_command, 3, first.snapshot.frontier)
        .await
        .unwrap();

    let SynthesisResolution::Success {
        command: second_command,
        ..
    } = second_resolution
    else {
        panic!("the same planner must serve the second writer cohort")
    };
    second
        .writer
        .commit_if_frontier(&second_command, 3, second.snapshot.frontier)
        .await
        .unwrap();
    assert_eq!(
        SemanticCurrentView::from_snapshot(&first.writer.project().await.unwrap())
            .unwrap()
            .proposals
            .len(),
        1
    );
    assert_eq!(
        SemanticCurrentView::from_snapshot(&second.writer.project().await.unwrap())
            .unwrap()
            .proposals
            .len(),
        1
    );
}

#[tokio::test]
async fn procedure_scope_ir_and_evidence_are_fixed_by_the_engine() {
    let temp = TempDir::new().unwrap();
    let mut seed = seed_store(&temp.path().join("store")).await;
    let direct_refs = seed.direct_refs();
    let mut provider_application = procedure_application();
    provider_application
        .progress_delta
        .push(SemanticStructuredDelta {
            label: "progress".into(),
            value: "derive a bounded procedure".into(),
            direct_refs: direct_refs.clone(),
        });
    let stub = ProviderStub::once(
        200,
        response(serde_json::to_value(provider_application).unwrap()),
    )
    .await;
    let planner = SynthesisPlanner::new(config(&stub.base_url));
    let resolution = planner
        .execute(SynthesisRequest {
            snapshot: &seed.snapshot,
            episode_revision_id: seed.episode.revision_id,
            trigger: SemanticDigestTrigger::StrategyPivot,
            direct_delta: vec![ProtectedDeltaItem {
                kind: ProtectedDeltaKind::Decision,
                value: "derive a bounded procedure".into(),
                direct_refs: direct_refs.clone(),
            }],
            selected_direct_refs: direct_refs.clone(),
            command_id: CommandId::new_v7(),
            occurred_at_us: 3,
            algorithm_revision: "s26-v1".into(),
            effective_config_hash: CONFIG,
        })
        .await
        .unwrap();
    let _ = stub.finish().await;
    let SynthesisResolution::Success {
        digest,
        command: procedure_command,
        ..
    } = resolution
    else {
        panic!("the procedure candidate must produce an atomic success")
    };
    let [SemanticCandidate::ProcedureProposal { payload, .. }] =
        digest.application.candidates.as_slice()
    else {
        panic!("one procedure proposal is required")
    };
    let draft = payload.draft();
    assert_eq!(
        draft.scope,
        evertrace_domain::procedure::ProcedureScope::Worktree {
            repository_id: seed.repository.repository_id,
            worktree_id: seed.worktree.worktree_instance_id,
        }
    );
    assert_eq!(draft.condition_ir_version, 1);
    assert_eq!(draft.evidence_refs, direct_refs);
    assert!(draft.support_revision_refs.is_empty());
    let mut forged_payloads = procedure_command
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    let support_revision = RevisionId::new_v7();
    mutate_procedure_command_drafts(&mut forged_payloads, |draft| {
        draft.evidence_refs = vec![seed.direct_refs()[0].clone()];
        draft.support_revision_refs = vec![support_revision];
    });
    let forged = command(3, forged_payloads);
    assert!(
        seed.writer
            .commit_if_frontier(&forged, 3, seed.snapshot.frontier)
            .await
            .is_err()
    );
    assert_eq!(
        seed.writer.project().await.unwrap().frontier,
        seed.snapshot.frontier
    );
    seed.writer
        .commit_if_frontier(&procedure_command, 3, seed.snapshot.frontier)
        .await
        .unwrap();
    assert_eq!(
        SemanticCurrentView::from_snapshot(&seed.writer.project().await.unwrap())
            .unwrap()
            .proposals
            .len(),
        1
    );
}

#[tokio::test]
async fn scenario_patch_scope_is_filled_from_the_current_episode() {
    let temp = TempDir::new().unwrap();
    let mut seed = seed_store(&temp.path().join("store")).await;
    let scenario = current_scenario(&seed);
    seed.writer
        .commit_if_frontier(
            &command(
                2,
                vec![JournalPayload::ScenarioRecorded(Box::new(scenario.clone()))],
            ),
            2,
            seed.snapshot.frontier,
        )
        .await
        .unwrap();
    let snapshot = seed.writer.project().await.unwrap();
    let direct_refs = seed.direct_refs();
    let mut provider_application = scenario_application(scenario.revision_id);
    provider_application
        .progress_delta
        .push(SemanticStructuredDelta {
            label: "progress".into(),
            value: "validate the current scenario target".into(),
            direct_refs: direct_refs.clone(),
        });
    let stub = ProviderStub::once(
        200,
        response(serde_json::to_value(provider_application).unwrap()),
    )
    .await;
    let planner = SynthesisPlanner::new(config(&stub.base_url));
    let resolution = planner
        .execute(SynthesisRequest {
            snapshot: &snapshot,
            episode_revision_id: seed.episode.revision_id,
            trigger: SemanticDigestTrigger::StrategyPivot,
            direct_delta: vec![ProtectedDeltaItem {
                kind: ProtectedDeltaKind::Progress,
                value: "validate the current scenario target".into(),
                direct_refs: direct_refs.clone(),
            }],
            selected_direct_refs: direct_refs,
            command_id: CommandId::new_v7(),
            occurred_at_us: 3,
            algorithm_revision: "s26-v1".into(),
            effective_config_hash: CONFIG,
        })
        .await
        .unwrap();
    let _ = stub.finish().await;
    let SynthesisResolution::Success {
        digest, command, ..
    } = resolution
    else {
        panic!("the current scenario patch must pass the deterministic validator")
    };
    let [
        SemanticCandidate::ScenarioPatch {
            scenario_revision_id,
            task_id,
            repository_id,
            worktree_id,
            ..
        },
    ] = digest.application.candidates.as_slice()
    else {
        panic!("one scenario patch is required")
    };
    assert_eq!(*scenario_revision_id, scenario.revision_id);
    assert_eq!(*task_id, seed.task.task_id);
    assert_eq!(*repository_id, Some(seed.repository.repository_id));
    assert_eq!(*worktree_id, Some(seed.worktree.worktree_instance_id));
    seed.writer
        .commit_if_frontier(&command, 3, snapshot.frontier)
        .await
        .unwrap();
}

#[tokio::test]
async fn existing_exact_proposal_skips_a_new_revision_but_commits_digest_run_and_episode() {
    let temp = TempDir::new().unwrap();
    let mut seed = seed_store(&temp.path().join("store")).await;
    let direct_refs = seed.direct_refs();
    let request = SubmitProposalRequest {
        target_kind: ProposalTargetKind::Atom,
        target_id: None,
        base_revision_id: None,
        operation: ProposalOperation::Create,
        payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
            draft: atom_draft(
                &seed,
                "existing exact atom",
                AtomScope::Task {
                    task_id: seed.task.task_id,
                },
                3,
            ),
        })),
        evidence_refs: vec![seed.receipt.source_receipt_id.to_string()],
        source_cohort_refs: direct_refs.clone(),
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::Agent,
    };
    let service = RevisionProposalService;
    let ProposalResolution::Revision {
        command: proposal_command,
        ..
    } = service
        .submit(
            &SemanticCurrentView::from_snapshot(&seed.snapshot).unwrap(),
            proposal_context(2),
            request.clone(),
        )
        .unwrap()
    else {
        panic!("the exact proposal seed must be persisted")
    };
    seed.writer
        .commit_if_frontier(&proposal_command, 2, seed.snapshot.frontier)
        .await
        .unwrap();
    let before = seed.writer.project().await.unwrap();
    let before_view = SemanticCurrentView::from_snapshot(&before).unwrap();
    assert_eq!(before_view.proposals.len(), 1);

    let mut provider_application = atom_application("existing exact atom");
    provider_application
        .progress_delta
        .push(SemanticStructuredDelta {
            label: "progress".into(),
            value: "reuse the exact pending proposal".into(),
            direct_refs: direct_refs.clone(),
        });
    let stub = ProviderStub::once(
        200,
        response(serde_json::to_value(provider_application).unwrap()),
    )
    .await;
    let planner = SynthesisPlanner::new(config(&stub.base_url));
    let resolution = planner
        .execute(SynthesisRequest {
            snapshot: &before,
            episode_revision_id: seed.episode.revision_id,
            trigger: SemanticDigestTrigger::AdoptedDecision,
            direct_delta: vec![ProtectedDeltaItem {
                kind: ProtectedDeltaKind::Decision,
                value: "reuse the exact pending proposal".into(),
                direct_refs: direct_refs.clone(),
            }],
            selected_direct_refs: direct_refs,
            command_id: CommandId::new_v7(),
            occurred_at_us: 3,
            algorithm_revision: "s26-v1".into(),
            effective_config_hash: CONFIG,
        })
        .await
        .unwrap();
    let _ = stub.finish().await;
    let SynthesisResolution::Success {
        digest,
        run,
        command: success_command,
        ..
    } = resolution
    else {
        panic!("the digest must reuse the existing proposal semantic payload")
    };
    assert!(
        success_command
            .events()
            .iter()
            .all(|event| !matches!(&event.payload, JournalPayload::RevisionProposalRecorded(_)))
    );
    let journal_len = seed.writer.journal_rows().await.unwrap().len();
    let mut mismatched_payloads = success_command
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    for payload in &mut mismatched_payloads {
        let JournalPayload::SemanticDigestRecorded(digest) = payload else {
            continue;
        };
        let [SemanticCandidate::AtomProposal { payload, .. }] =
            digest.application.candidates.as_mut_slice()
        else {
            unreachable!()
        };
        let AtomProposalPayload::Create { draft } = payload.as_mut() else {
            unreachable!()
        };
        draft.value.text = "mismatched exact proposal".into();
    }
    assert!(
        seed.writer
            .commit_if_frontier(&command(3, mismatched_payloads), 3, before.frontier)
            .await
            .is_err()
    );
    assert_eq!(seed.writer.journal_rows().await.unwrap().len(), journal_len);

    let ProposalResolution::Revision {
        command: duplicate_root,
        ..
    } = service
        .submit(
            &SemanticCurrentView::default(),
            proposal_context(3),
            request,
        )
        .unwrap()
    else {
        panic!("a stale empty view constructs the conflicting exact root")
    };
    let duplicate_proposal = duplicate_root
        .events()
        .iter()
        .find_map(|event| match &event.payload {
            JournalPayload::RevisionProposalRecorded(proposal) => {
                Some(JournalPayload::RevisionProposalRecorded(proposal.clone()))
            }
            _ => None,
        })
        .unwrap();
    let mut duplicate_payloads = success_command
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    duplicate_payloads.push(duplicate_proposal);
    assert!(
        seed.writer
            .commit_if_frontier(&command(3, duplicate_payloads), 3, before.frontier)
            .await
            .is_err()
    );
    assert_eq!(seed.writer.journal_rows().await.unwrap().len(), journal_len);

    seed.writer
        .commit_if_frontier(&success_command, 3, before.frontier)
        .await
        .unwrap();
    let after = seed.writer.project().await.unwrap();
    assert_eq!(
        SemanticCurrentView::from_snapshot(&after)
            .unwrap()
            .proposals,
        before_view.proposals
    );
    assert!(after.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("semantic_digest")
            && row.object_id.as_deref() == Some(&digest.semantic_digest_id.to_string())
    }));
    assert!(after.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("semantic_derivation_run")
            && row.object_id.as_deref() == Some(&run.derivation_run_id.to_string())
    }));
}

#[tokio::test]
async fn accepted_repository_atom_builds_reopen_safe_wiki_lineage_and_deprecation_removes_it() {
    let temp = TempDir::new().unwrap();
    let store_root = temp.path().join("store");
    let mut seed = seed_closed_store(&store_root).await;
    let direct_refs = seed.direct_refs();
    let mut derived = application();
    derived.progress_delta.push(SemanticStructuredDelta {
        label: "progress".into(),
        value: "compile a repository fact from direct evidence".into(),
        direct_refs: direct_refs.clone(),
    });
    let stub = ProviderStub::once(200, response(serde_json::to_value(derived).unwrap())).await;
    let planner = SynthesisPlanner::new(config(&stub.base_url));
    let resolution = planner
        .execute(SynthesisRequest {
            snapshot: &seed.snapshot,
            episode_revision_id: seed.episode.revision_id,
            trigger: SemanticDigestTrigger::EpisodeFinalization,
            direct_delta: vec![ProtectedDeltaItem {
                kind: ProtectedDeltaKind::Progress,
                value: "compile a repository fact from direct evidence".into(),
                direct_refs: direct_refs.clone(),
            }],
            selected_direct_refs: direct_refs.clone(),
            command_id: CommandId::new_v7(),
            occurred_at_us: 3,
            algorithm_revision: "s26-v1".into(),
            effective_config_hash: CONFIG,
        })
        .await
        .unwrap();
    let _ = stub.finish().await;
    let SynthesisResolution::Success {
        digest,
        episode: semantic_episode,
        command: synthesis_command,
        ..
    } = resolution
    else {
        panic!("the lineage seed digest must succeed")
    };
    seed.writer
        .commit_if_frontier(&synthesis_command, 3, seed.snapshot.frontier)
        .await
        .unwrap();

    let service = RevisionProposalService;
    let closed_snapshot = seed.writer.project().await.unwrap();
    let ProposalResolution::Revision {
        value: repository_proposal,
        command: repository_submit,
    } = service
        .submit(
            &SemanticCurrentView::from_snapshot(&closed_snapshot).unwrap(),
            proposal_context(5),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                    draft: atom_draft(
                        &seed,
                        "writer lineage body",
                        AtomScope::Repository {
                            repository_instance_id: seed.repository.repository_id,
                        },
                        5,
                    ),
                })),
                evidence_refs: vec![digest.semantic_digest_id.to_string()],
                source_cohort_refs: direct_refs.clone(),
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("the repository proposal must persist")
    };
    seed.writer
        .commit_if_frontier(&repository_submit, 5, closed_snapshot.frontier)
        .await
        .unwrap();
    let (acceptance_receipt, acceptance_observation) =
        tui_acceptance_source("wiki-acceptance", &repository_proposal, &seed);
    persist_source(
        &mut seed.writer,
        &acceptance_receipt,
        &acceptance_observation,
        6,
    )
    .await;
    let submitted = seed.writer.project().await.unwrap();
    let accepted = service
        .accept(
            &SemanticCurrentView::from_snapshot(&submitted).unwrap(),
            proposal_context(7),
            repository_proposal.proposal_id,
            AtomAcceptanceContext::RepositoryTui {
                observation: Box::new(acceptance_observation),
                receipt: Box::new(acceptance_receipt),
            },
        )
        .unwrap();
    seed.writer
        .commit_if_frontier(&accepted.command, 7, submitted.frontier)
        .await
        .unwrap();

    let accepted_atom = (*accepted.atom).clone();
    let accepted_snapshot = seed.writer.project().await.unwrap();
    assert_eq!(
        accepted_snapshot,
        seed.writer.full_projection().await.unwrap()
    );
    let wiki = accepted_snapshot
        .data_rows()
        .find(|row| row.object_kind.as_deref() == Some("wiki_projection"))
        .and_then(|row| row.payload_json.as_deref())
        .and_then(|json| serde_json::from_str::<WikiProjection>(json).ok())
        .expect("the reviewed repository atom must compile one Wiki page");
    assert_eq!(wiki.source_atom_ids, vec![accepted_atom.atom_id]);
    assert_eq!(wiki.source_episode_ids, vec![semantic_episode.episode_id]);
    let page_id = wiki.page_id.to_string();
    let search = SearchIndex::open(&store_root).await.unwrap();
    assert!(
        search
            .fts("writer lineage body")
            .await
            .unwrap()
            .iter()
            .any(|row| {
                row.candidate_id.as_deref() == Some(page_id.as_str())
                    && row.object_kind.as_deref() == Some("wiki_projection")
            })
    );
    let wiki_relations = seed
        .writer
        .relation_rows()
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.source_id.as_deref() == Some(page_id.as_str()))
        .map(|row| (row.relation_kind.unwrap(), row.target_id.unwrap()))
        .collect::<std::collections::BTreeSet<_>>();
    assert!(wiki_relations.contains(&(
        "wiki_to_source_atom".into(),
        accepted_atom.atom_id.to_string()
    )));
    assert!(wiki_relations.contains(&(
        "wiki_to_source_episode".into(),
        semantic_episode.episode_id.to_string()
    )));

    let mut missing_atom = accepted_snapshot.clone();
    missing_atom.rows.retain(|row| {
        row.current_revision_id.as_deref() != Some(&accepted_atom.revision_id.to_string())
    });
    assert!(derive_l0002_projections(&missing_atom).is_err());
    let mut mismatched_hash = accepted_snapshot.clone();
    let atom_row = mismatched_hash
        .rows
        .iter_mut()
        .find(|row| {
            row.object_kind.as_deref() == Some("atom_revision")
                && row.current_revision_id.as_deref()
                    == Some(&accepted_atom.revision_id.to_string())
        })
        .unwrap();
    let mut atom_payload: JournalPayload =
        serde_json::from_str(atom_row.payload_json.as_deref().unwrap()).unwrap();
    let JournalPayload::AtomRecorded(atom) = &mut atom_payload else {
        unreachable!()
    };
    atom.value.text = "tampered source content".into();
    atom_row.payload_json = Some(serde_json::to_string(&atom_payload).unwrap());
    assert!(derive_l0002_projections(&mismatched_hash).is_err());

    let task_id = seed.task.task_id;
    let repository_id = seed.repository.repository_id;
    let worktree_id = seed.worktree.worktree_instance_id;
    drop(seed.writer);
    let mut writer = JournalWriter::open(&store_root).await.unwrap();
    assert_eq!(writer.project().await.unwrap(), accepted_snapshot);

    let reopened = writer.project().await.unwrap();
    let ProposalResolution::Revision {
        value: deprecate_proposal,
        command: deprecate_submit,
    } = service
        .submit(
            &SemanticCurrentView::from_snapshot(&reopened).unwrap(),
            proposal_context(8),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: Some(ProposalTargetId::Atom(accepted_atom.atom_id)),
                base_revision_id: Some(accepted_atom.revision_id),
                operation: ProposalOperation::Deprecate,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Deprecate {
                    reason: "the reviewed fact is no longer current".into(),
                })),
                evidence_refs: vec![direct_refs[0].clone()],
                source_cohort_refs: direct_refs,
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("deprecation must be a reviewed successor proposal")
    };
    writer
        .commit_if_frontier(&deprecate_submit, 8, reopened.frontier)
        .await
        .unwrap();
    let deprecate_payload = tui_acceptance_event_payload(
        deprecate_proposal.proposal_id,
        deprecate_proposal.proposal_revision_id,
        &deprecate_proposal.fingerprint,
    );
    let (mut deprecate_receipt, deprecate_observation) = source(
        "wiki-deprecation",
        &deprecate_payload,
        task_id,
        repository_id,
        worktree_id,
    );
    deprecate_receipt.eligible_event_manifest_ref = TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into();
    deprecate_receipt.event_time_us = 0;
    deprecate_receipt.recorded_at_us = deprecate_proposal.created_at_us + 1;
    persist_source(&mut writer, &deprecate_receipt, &deprecate_observation, 9).await;
    let deprecate_submitted = writer.project().await.unwrap();
    let deprecated = service
        .accept(
            &SemanticCurrentView::from_snapshot(&deprecate_submitted).unwrap(),
            proposal_context(10),
            deprecate_proposal.proposal_id,
            AtomAcceptanceContext::RepositoryTui {
                observation: Box::new(deprecate_observation),
                receipt: Box::new(deprecate_receipt),
            },
        )
        .unwrap();
    writer
        .commit_if_frontier(&deprecated.command, 10, deprecate_submitted.frontier)
        .await
        .unwrap();
    assert_eq!(
        deprecated.atom.lifecycle_status,
        evertrace_domain::semantic::AtomLifecycleStatus::Deprecated
    );
    let deprecated_snapshot = writer.project().await.unwrap();
    assert_eq!(deprecated_snapshot, writer.full_projection().await.unwrap());
    assert!(
        !deprecated_snapshot
            .data_rows()
            .any(|row| row.object_kind.as_deref() == Some("wiki_projection"))
    );
    let search = SearchIndex::open(&store_root).await.unwrap();
    assert!(
        search
            .fts("writer lineage body")
            .await
            .unwrap()
            .iter()
            .all(|row| row.candidate_id.as_deref() != Some(page_id.as_str()))
    );
    assert!(
        writer
            .relation_rows()
            .await
            .unwrap()
            .into_iter()
            .all(|row| { row.source_id.as_deref() != Some(page_id.as_str()) })
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
    let reopened = JournalWriter::open(&store_root).await.unwrap();
    assert_eq!(reopened.project().await.unwrap(), deprecated_snapshot);
}
