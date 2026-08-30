use std::str::FromStr;

use evertrace_capture::{CasDigest, CasStore};
use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, EvidenceSurface, Operation, PairingState,
        SourceArchiveMode, SourceObservation, SourceReceipt, SourceRole, hex, payload_fingerprint,
    },
    ids::{
        AttemptId, CasId, CommandId, OperationId, ResultEvidenceId, SourceObservationId,
        SourceReceiptId, WorkArtifactId,
    },
    procedure::{ProcedureRevision, ProcedureUsageRevision},
    repository::{WorktreeInstance, WorktreeSnapshot},
    revision::RevisionId,
    semantic::{
        EvidenceCompleteness, MetricValue, ParserFailureCode, ParserReceipt, ParserStatus,
        ResultEvidence, ResultFailure, ResultScope, VerifierFailureCode, VerifierReceipt,
        VerifierStatus,
    },
    work::{
        ArtifactActor, ArtifactPayloadStatus, ArtifactRevision, ArtifactScope, AssignmentStatus,
        Attempt, AttemptBindingStatus, ContractField, ControlledRunSourceEnvelope, ExperimentRun,
        MultiCasMetricPolicy, RunContractValidity, RunExecutionStatus, RunObservability, RunOrigin,
        SeedPolicy, Task, VariableDeclaration, WorkArtifact, WorkBindingRevision, WorkEpisode,
        Workstream,
    },
};
use evertrace_store::{
    AutoresearchCurrentView, JournalCommand, JournalEventDraft, JournalPayload, ProjectionSnapshot,
};
use serde::Deserialize;
use thiserror::Error;

const RESULT_PARSER_VERSION: &str = "evertrace.result_metric.v1";
const RESULT_VERIFIER_VERSION: &str = "evertrace.result_reparse.v1";
const MAX_COMPARISON_MEMBERS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutoresearchResolution<T> {
    NoDelta,
    Revision(Box<T>),
}

#[derive(Debug)]
pub struct AutoresearchCommandRevision<T> {
    pub value: Box<T>,
    pub command: JournalCommand,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutoresearchCommandContext {
    pub command_id: CommandId,
    pub occurred_at_us: i64,
    pub effective_config_hash: [u8; 32],
    pub algorithm_revision: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCreateInput {
    pub workstream_id: evertrace_domain::ids::WorkstreamId,
    pub source_receipt_refs: Vec<SourceReceiptId>,
    pub code_snapshot_id: evertrace_domain::ids::WorktreeSnapshotId,
    pub data_fingerprint: String,
    pub normalized_config: Vec<ContractField>,
    pub variable_declaration: VariableDeclaration,
    pub seed_policy: SeedPolicy,
    pub seed_values: Vec<String>,
    pub nondeterministic: bool,
    pub metric_definition: String,
    pub metric_extractor_version: String,
    pub multi_cas_metric_policy: MultiCasMetricPolicy,
    pub environment_fingerprint: String,
    pub created_at_us: i64,
}

pub fn create_experiment_run(
    attempt: &Attempt,
    mut input: RunCreateInput,
) -> Result<ExperimentRun, AutoresearchError> {
    if attempt.workstream_id != input.workstream_id {
        return Err(AutoresearchError::StrategyDriftRequiresNewAttempt);
    }
    input
        .normalized_config
        .sort_by(|left, right| left.name.cmp(&right.name));
    input.variable_declaration.varied.sort();
    input.variable_declaration.fixed.sort();
    input.variable_declaration.uncontrolled.sort();
    input.source_receipt_refs.sort();
    input.seed_values.sort();
    let mut run = ExperimentRun {
        run_id: evertrace_domain::ids::ExperimentRunId::new_v7(),
        revision_id: RevisionId::new_v7(),
        parent_revision_id: None,
        workstream_id: input.workstream_id,
        attempt_id: Some(attempt.attempt_id),
        attempt_binding_status: AttemptBindingStatus::Resolved,
        strategy_contract_fingerprint: attempt.strategy_contract_fingerprint,
        origin: RunOrigin::Local,
        external_system_id: None,
        external_run_key: None,
        source_receipt_refs: input.source_receipt_refs,
        observability: RunObservability::Declared,
        execution_status: RunExecutionStatus::Unknown,
        contract_validity: RunContractValidity::Unknown,
        experiment_contract_fingerprint: [0; 32],
        code_snapshot_id: input.code_snapshot_id,
        data_fingerprint: input.data_fingerprint,
        normalized_config: input.normalized_config,
        variable_declaration: input.variable_declaration,
        comparison_key: [0; 32],
        seed_policy: input.seed_policy,
        seed_values: input.seed_values,
        nondeterministic: input.nondeterministic,
        metric_definition: input.metric_definition,
        metric_extractor_version: input.metric_extractor_version,
        multi_cas_metric_policy: input.multi_cas_metric_policy,
        environment_fingerprint: input.environment_fingerprint,
        comparison_execution_binding: None,
        work_artifact_refs: Vec::new(),
        terminal_evidence_refs: Vec::new(),
        created_at_us: input.created_at_us,
        started_at_us: None,
        ended_at_us: None,
    };
    run.experiment_contract_fingerprint = run
        .recompute_exact_contract_fingerprint()
        .map_err(|_| AutoresearchError::InvalidInput)?;
    run.comparison_key = run
        .recompute_comparison_key()
        .map_err(|_| AutoresearchError::InvalidInput)?;
    run.validate()
        .map_err(|_| AutoresearchError::InvalidInput)?;
    Ok(run)
}

pub fn run_command(
    context: AutoresearchCommandContext,
    run: &ExperimentRun,
) -> Result<JournalCommand, AutoresearchError> {
    run.validate()
        .map_err(|_| AutoresearchError::InvalidInput)?;
    if !run.is_declaration_only() {
        return Err(AutoresearchError::UntrustedRunEvidence);
    }
    payload_command(
        context,
        vec![JournalPayload::ExperimentRunRecorded(Box::new(run.clone()))],
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlledRunRequest {
    pub attempt_id: AttemptId,
    pub procedure_revision_id: RevisionId,
    pub source_observation_id: SourceObservationId,
}

#[derive(Debug)]
pub enum ControlledRunCommand {
    NoDelta,
    Declaration {
        run: Box<ExperimentRun>,
        bindings: Vec<WorkBindingRevision>,
        attempt: Option<Box<Attempt>>,
        command: JournalCommand,
    },
    Terminal {
        run: Box<ExperimentRun>,
        result: Box<ResultEvidence>,
        command: JournalCommand,
    },
}

#[derive(Clone, Debug)]
pub struct ControlledRunResolver {
    cas: CasStore,
}

impl ControlledRunResolver {
    pub const fn new(cas: CasStore) -> Self {
        Self { cas }
    }

    pub fn declare(
        &self,
        snapshot: &ProjectionSnapshot,
        request: ControlledRunRequest,
        context: AutoresearchCommandContext,
    ) -> Result<ControlledRunCommand, AutoresearchError> {
        let facts = ControlledFacts::from_snapshot(snapshot)?;
        let Some(attempt) = facts.attempts.get(&request.attempt_id) else {
            return Ok(ControlledRunCommand::NoDelta);
        };
        if facts
            .procedures
            .get(&request.procedure_revision_id)
            .is_none_or(|procedure| {
                facts.current_procedures.get(&procedure.procedure_id)
                    != Some(&procedure.revision_id)
            })
        {
            return Ok(ControlledRunCommand::NoDelta);
        }
        let envelope = match self.witness(&facts, request.source_observation_id) {
            Ok(value) => value,
            Err(AutoresearchError::EvidenceIncomplete | AutoresearchError::Cas) => {
                return Ok(ControlledRunCommand::NoDelta);
            }
            Err(error) => return Err(error),
        };
        let ControlledRunSourceEnvelope::Launch {
            attempt_id,
            procedure_revision_id,
            code_snapshot_id,
            data_fingerprint,
            normalized_config,
            variable_declaration,
            seed_policy,
            seed_values,
            nondeterministic,
            metric_definition,
            metric_extractor_version,
            multi_cas_metric_policy,
            environment_fingerprint,
            binding,
            started_at_us,
            ..
        } = envelope
        else {
            return Err(AutoresearchError::UntrustedRunEvidence);
        };
        if attempt_id != request.attempt_id
            || procedure_revision_id != request.procedure_revision_id
            || attempt.strategy_contract.search_policy_ref.as_deref()
                != Some(procedure_revision_id.to_string()).as_deref()
            || binding
                .procedure_exposure_revision_id
                .is_some_and(|value| value != procedure_revision_id)
            || facts
                .snapshots
                .get(&code_snapshot_id)
                .and_then(|snapshot| snapshot.toolchain_fingerprint.as_deref())
                != Some(binding.toolchain_revision.as_str())
        {
            return Err(AutoresearchError::ImmutableConflict);
        }
        match facts.validate_declaration_anchor(
            request.procedure_revision_id,
            attempt,
            code_snapshot_id,
        ) {
            Ok(()) => {}
            Err(AutoresearchError::EvidenceIncomplete) => {
                return Ok(ControlledRunCommand::NoDelta);
            }
            Err(error) => return Err(error),
        }
        let (run_id, binding_successors) = match exact_bound_run(
            &facts,
            request.source_observation_id,
            attempt.attempt_id,
            attempt.workstream_id,
        ) {
            Ok(value) => value,
            Err(AutoresearchError::EvidenceIncomplete) => {
                return Ok(ControlledRunCommand::NoDelta);
            }
            Err(error) => return Err(error),
        };
        if let Some(existing) = facts.runs.runs.get(&run_id) {
            return if existing.source_receipt_refs
                == vec![
                    facts
                        .receipt(request.source_observation_id)?
                        .source_receipt_id,
                ] {
                Ok(ControlledRunCommand::NoDelta)
            } else {
                Err(AutoresearchError::ImmutableConflict)
            };
        }
        let receipt_id = facts
            .receipt(request.source_observation_id)?
            .source_receipt_id;
        let mut run = ExperimentRun {
            run_id,
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            workstream_id: attempt.workstream_id,
            attempt_id: Some(attempt.attempt_id),
            attempt_binding_status: AttemptBindingStatus::Resolved,
            strategy_contract_fingerprint: attempt.strategy_contract_fingerprint,
            origin: RunOrigin::Local,
            external_system_id: None,
            external_run_key: None,
            source_receipt_refs: vec![receipt_id],
            observability: RunObservability::Declared,
            execution_status: RunExecutionStatus::Unknown,
            contract_validity: RunContractValidity::Unknown,
            experiment_contract_fingerprint: [0; 32],
            code_snapshot_id,
            data_fingerprint,
            normalized_config,
            variable_declaration,
            comparison_key: [0; 32],
            seed_policy,
            seed_values,
            nondeterministic,
            metric_definition,
            metric_extractor_version,
            multi_cas_metric_policy,
            environment_fingerprint,
            comparison_execution_binding: Some(*binding),
            work_artifact_refs: Vec::new(),
            terminal_evidence_refs: Vec::new(),
            created_at_us: context.occurred_at_us.min(started_at_us),
            started_at_us: Some(started_at_us),
            ended_at_us: None,
        };
        run.experiment_contract_fingerprint = run
            .recompute_exact_contract_fingerprint()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        run.comparison_key = run
            .recompute_comparison_key()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        run.validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        let mut payloads = vec![JournalPayload::ExperimentRunRecorded(Box::new(run.clone()))];
        let mut attempt_successor = None;
        if !binding_successors.is_empty() {
            payloads.extend(
                binding_successors
                    .iter()
                    .cloned()
                    .map(|binding| JournalPayload::WorkBindingRecorded(Box::new(binding))),
            );
            let mut next_attempt = attempt.clone();
            next_attempt.revision_id = RevisionId::new_v7();
            next_attempt.predecessor_revision_id = Some(attempt.revision_id);
            next_attempt.revision_generation = attempt.revision_generation.saturating_add(1);
            next_attempt.work_binding_revision_refs.extend(
                binding_successors
                    .iter()
                    .map(|binding| binding.work_binding_revision_id),
            );
            next_attempt.work_binding_revision_refs.sort();
            next_attempt.work_binding_revision_refs.dedup();
            next_attempt.source_watermark = next_attempt.source_watermark.saturating_add(1);
            attempt
                .validate_successor(&next_attempt)
                .map_err(|_| AutoresearchError::ImmutableConflict)?;
            payloads.push(JournalPayload::AttemptRecorded(Box::new(
                next_attempt.clone(),
            )));
            attempt_successor = Some(next_attempt);
        }
        let command = payload_command(context, payloads)?;
        Ok(ControlledRunCommand::Declaration {
            run: Box::new(run),
            bindings: binding_successors,
            attempt: attempt_successor.map(Box::new),
            command,
        })
    }

    pub fn complete(
        &self,
        snapshot: &ProjectionSnapshot,
        run_id: evertrace_domain::ids::ExperimentRunId,
        terminal_observation_id: SourceObservationId,
        context: AutoresearchCommandContext,
    ) -> Result<ControlledRunCommand, AutoresearchError> {
        let facts = ControlledFacts::from_snapshot(snapshot)?;
        let Some(current) = facts.runs.runs.get(&run_id) else {
            return Ok(ControlledRunCommand::NoDelta);
        };
        if current.comparison_execution_binding.is_none() {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        if !current.is_controlled_declaration() {
            return Ok(ControlledRunCommand::NoDelta);
        }
        let envelope = match self.witness(&facts, terminal_observation_id) {
            Ok(value) => value,
            Err(AutoresearchError::EvidenceIncomplete | AutoresearchError::Cas) => {
                return Ok(ControlledRunCommand::NoDelta);
            }
            Err(error) => return Err(error),
        };
        let ControlledRunSourceEnvelope::Terminal {
            run_id: observed_run_id,
            ended_at_us,
            metric,
            artifact_refs,
            ..
        } = envelope
        else {
            return Err(AutoresearchError::UntrustedRunEvidence);
        };
        if observed_run_id != run_id {
            return Err(AutoresearchError::ImmutableConflict);
        }
        let Some(attempt) = facts.attempts.get(
            &current
                .attempt_id
                .ok_or(AutoresearchError::ImmutableConflict)?,
        ) else {
            return Ok(ControlledRunCommand::NoDelta);
        };
        let Some(target_revision_id) = attempt
            .strategy_contract
            .search_policy_ref
            .as_deref()
            .and_then(|value| value.parse::<RevisionId>().ok())
        else {
            return Err(AutoresearchError::ImmutableConflict);
        };
        if !facts.procedures.contains_key(&target_revision_id) {
            return Err(AutoresearchError::ImmutableConflict);
        }
        match require_bound_operations(
            &facts,
            terminal_observation_id,
            false,
            run_id,
            attempt.attempt_id,
            current.workstream_id,
        ) {
            Ok(()) => {}
            Err(AutoresearchError::EvidenceIncomplete) => {
                return Ok(ControlledRunCommand::NoDelta);
            }
            Err(error) => return Err(error),
        }
        if artifact_refs
            .iter()
            .any(|id| !facts.runs.artifacts.contains_key(id))
        {
            return Ok(ControlledRunCommand::NoDelta);
        }
        let receipt = facts.receipt(terminal_observation_id)?;
        let mut next = current.clone();
        next.revision_id = RevisionId::new_v7();
        next.parent_revision_id = Some(current.revision_id);
        next.observability = RunObservability::Full;
        next.execution_status = RunExecutionStatus::Completed;
        next.contract_validity = RunContractValidity::Valid;
        next.work_artifact_refs = artifact_refs.clone();
        next.terminal_evidence_refs = vec![receipt.source_receipt_id];
        next.ended_at_us = Some(ended_at_us);
        next.created_at_us = current.created_at_us;
        current
            .validate_successor(&next)
            .map_err(|_| AutoresearchError::ImmutableConflict)?;
        let cas = CasId::from_digest(
            *CasDigest::from_str(&receipt.cas_ref)
                .map_err(|_| AutoresearchError::Cas)?
                .as_bytes(),
        );
        let result = ResultEvidence {
            result_evidence_id: ResultEvidenceId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            experiment_run_id: run_id,
            experiment_run_revision_id: next.revision_id,
            result_scope: ResultScope::Complete,
            raw_artifact_refs: artifact_refs.clone(),
            raw_cas_refs: vec![cas],
            parsed_metric: Some(metric),
            parser_receipt: ParserReceipt {
                parser_version: RESULT_PARSER_VERSION.into(),
                status: ParserStatus::Parsed,
                failure_code: None,
                input_artifact_refs: artifact_refs,
                input_cas_refs: vec![cas],
            },
            verifier_receipt: Some(VerifierReceipt {
                verifier_version: RESULT_VERIFIER_VERSION.into(),
                status: VerifierStatus::Passed,
                failure_code: None,
            }),
            completeness: EvidenceCompleteness::Complete,
            failure: None,
            created_at_us: context.occurred_at_us,
        };
        result
            .validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        let command = payload_command(
            context,
            vec![
                JournalPayload::ExperimentRunRecorded(Box::new(next.clone())),
                JournalPayload::ResultEvidenceRecorded(Box::new(result.clone())),
            ],
        )?;
        Ok(ControlledRunCommand::Terminal {
            run: Box::new(next),
            result: Box::new(result),
            command,
        })
    }

    fn witness(
        &self,
        facts: &ControlledFacts,
        observation_id: SourceObservationId,
    ) -> Result<ControlledRunSourceEnvelope, AutoresearchError> {
        let receipt = facts.receipt(observation_id)?;
        let observation = facts
            .observations
            .get(&observation_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let surface = facts
            .surfaces
            .get(&observation_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let bytes = read_cas(
            &self.cas,
            &CasId::from_digest(
                *CasDigest::from_str(&receipt.cas_ref)
                    .map_err(|_| AutoresearchError::Cas)?
                    .as_bytes(),
            ),
        )?;
        surface
            .validate()
            .map_err(|_| AutoresearchError::UntrustedRunEvidence)?;
        if bytes != surface.protected_text.as_bytes()
            || receipt.source_observation_id != observation_id
            || receipt.capture_completeness != CaptureCompleteness::Complete
            || observation.capture_completeness != CaptureCompleteness::Complete
            || surface.capture_completeness != CaptureCompleteness::Complete
            || receipt.archive_mode != SourceArchiveMode::Exact
            || receipt.unsupported_record_classification.is_some()
            || receipt.protected_secret_digest.is_some()
            || !receipt.redaction_spans.is_empty()
            || observation.source_receipt_ref != receipt.source_receipt_id
            || receipt.canonicalization_revision != surface.canonicalization_version
            || observation.canonicalization_revision != surface.canonicalization_version
            || observation.source_role != surface.source_role
            || observation.content_trust != surface.content_trust
            || !matches!(surface.source_role, SourceRole::Host | SourceRole::Tool)
            || surface.content_trust != ContentTrust::Observed
            || receipt.cas_ref != CasDigest::for_protected_bytes(&bytes).to_string()
            || observation.payload_fingerprint
                != hex(
                    &payload_fingerprint(surface.canonicalization_version, &bytes, None)
                        .map_err(|_| AutoresearchError::UntrustedRunEvidence)?,
                )
        {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        ControlledRunSourceEnvelope::decode_canonical(&bytes)
            .map_err(|_| AutoresearchError::UntrustedRunEvidence)
    }
}

struct ControlledFacts {
    runs: AutoresearchCurrentView,
    attempts: std::collections::BTreeMap<AttemptId, Attempt>,
    procedures: std::collections::BTreeMap<RevisionId, ProcedureRevision>,
    current_procedures: std::collections::BTreeMap<evertrace_domain::ids::ProcedureId, RevisionId>,
    usages:
        std::collections::BTreeMap<evertrace_domain::ids::ProcedureUsageId, ProcedureUsageRevision>,
    tasks: std::collections::BTreeMap<evertrace_domain::ids::TaskId, Task>,
    workstreams: std::collections::BTreeMap<evertrace_domain::ids::WorkstreamId, Workstream>,
    episodes: std::collections::BTreeMap<RevisionId, WorkEpisode>,
    current_episodes: std::collections::BTreeMap<evertrace_domain::ids::WorkEpisodeId, RevisionId>,
    worktrees: std::collections::BTreeMap<evertrace_domain::ids::WorktreeId, WorktreeInstance>,
    snapshots:
        std::collections::BTreeMap<evertrace_domain::ids::WorktreeSnapshotId, WorktreeSnapshot>,
    receipts: std::collections::BTreeMap<SourceReceiptId, SourceReceipt>,
    observations: std::collections::BTreeMap<SourceObservationId, SourceObservation>,
    surfaces: std::collections::BTreeMap<SourceObservationId, EvidenceSurface>,
    operations: std::collections::BTreeMap<OperationId, Operation>,
    bindings: std::collections::BTreeMap<OperationId, WorkBindingRevision>,
}

impl ControlledFacts {
    fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, AutoresearchError> {
        let mut facts = Self {
            runs: AutoresearchCurrentView::from_snapshot(snapshot)
                .map_err(AutoresearchError::Store)?,
            attempts: Default::default(),
            procedures: Default::default(),
            current_procedures: Default::default(),
            usages: Default::default(),
            tasks: Default::default(),
            workstreams: Default::default(),
            episodes: Default::default(),
            current_episodes: Default::default(),
            worktrees: Default::default(),
            snapshots: Default::default(),
            receipts: Default::default(),
            observations: Default::default(),
            surfaces: Default::default(),
            operations: Default::default(),
            bindings: Default::default(),
        };
        let mut attempt_seq = std::collections::BTreeMap::new();
        let mut operation_seq = std::collections::BTreeMap::new();
        let mut procedure_seq = std::collections::BTreeMap::new();
        let mut episode_seq = std::collections::BTreeMap::new();
        let mut task_seq = std::collections::BTreeMap::new();
        let mut workstream_seq = std::collections::BTreeMap::new();
        let mut worktree_seq = std::collections::BTreeMap::new();
        let mut usage_seq = std::collections::BTreeMap::new();
        for row in snapshot.data_rows() {
            let Some(payload) = row.payload_json.as_deref() else {
                continue;
            };
            let payload = serde_json::from_str::<JournalPayload>(payload)
                .map_err(|_| AutoresearchError::Store(evertrace_store::StoreError::StoreCorrupt))?;
            match payload {
                JournalPayload::AttemptRecorded(value) => {
                    if attempt_seq
                        .get(&value.attempt_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        attempt_seq.insert(value.attempt_id, row.source_event_seq);
                        facts.attempts.insert(value.attempt_id, *value);
                    }
                }
                JournalPayload::ProcedureRevisionRecorded(value) => {
                    if procedure_seq
                        .get(&value.procedure_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        procedure_seq.insert(value.procedure_id, row.source_event_seq);
                        facts
                            .current_procedures
                            .insert(value.procedure_id, value.revision_id);
                    }
                    facts.procedures.insert(value.revision_id, *value);
                }
                JournalPayload::ProcedureUsageRecorded(value) => {
                    if usage_seq
                        .get(&value.procedure_usage_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        usage_seq.insert(value.procedure_usage_id, row.source_event_seq);
                        facts.usages.insert(value.procedure_usage_id, *value);
                    }
                }
                JournalPayload::TaskRecorded(value) => {
                    if task_seq
                        .get(&value.task_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        task_seq.insert(value.task_id, row.source_event_seq);
                        facts.tasks.insert(value.task_id, *value);
                    }
                }
                JournalPayload::WorkstreamRecorded(value) => {
                    if workstream_seq
                        .get(&value.workstream_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        workstream_seq.insert(value.workstream_id, row.source_event_seq);
                        facts.workstreams.insert(value.workstream_id, *value);
                    }
                }
                JournalPayload::WorkEpisodeRecorded(value) => {
                    if episode_seq
                        .get(&value.episode_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        episode_seq.insert(value.episode_id, row.source_event_seq);
                        facts
                            .current_episodes
                            .insert(value.episode_id, value.revision_id);
                    }
                    facts.episodes.insert(value.revision_id, *value);
                }
                JournalPayload::WorktreeInstanceRecorded(value) => {
                    if worktree_seq
                        .get(&value.worktree_instance_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        worktree_seq.insert(value.worktree_instance_id, row.source_event_seq);
                        facts.worktrees.insert(value.worktree_instance_id, *value);
                    }
                }
                JournalPayload::WorktreeSnapshotRecorded(value) => {
                    facts.snapshots.insert(value.worktree_snapshot_id, *value);
                }
                JournalPayload::SourceReceiptRecorded(value) => {
                    facts.receipts.insert(value.source_receipt_id, *value);
                }
                JournalPayload::SourceObservationRecorded(value) => {
                    facts
                        .observations
                        .insert(value.source_observation_id, *value);
                }
                JournalPayload::EvidenceSurfaceRecorded(value) => {
                    facts
                        .surfaces
                        .insert(value.source_observation_revision_ref, *value);
                }
                JournalPayload::OperationDerived(value) => {
                    if operation_seq
                        .get(&value.operation_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        operation_seq.insert(value.operation_id, row.source_event_seq);
                        facts.operations.insert(value.operation_id, *value);
                    }
                }
                JournalPayload::WorkBindingRecorded(value)
                    if facts
                        .bindings
                        .get(&value.operation_id)
                        .is_none_or(|current| {
                            value.revision_generation > current.revision_generation
                        }) =>
                {
                    facts.bindings.insert(value.operation_id, *value);
                }
                _ => {}
            }
        }
        Ok(facts)
    }

    fn receipt(
        &self,
        observation_id: SourceObservationId,
    ) -> Result<&SourceReceipt, AutoresearchError> {
        let observation = self
            .observations
            .get(&observation_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        self.receipts
            .get(&observation.source_receipt_ref)
            .ok_or(AutoresearchError::EvidenceIncomplete)
    }

    fn validate_declaration_anchor(
        &self,
        procedure_revision_id: RevisionId,
        attempt: &Attempt,
        snapshot_id: evertrace_domain::ids::WorktreeSnapshotId,
    ) -> Result<(), AutoresearchError> {
        let mut usages = self.usages.values().filter(|usage| {
            usage.procedure_revision_id == procedure_revision_id
                && usage.attempt_ids.contains(&attempt.attempt_id)
        });
        let usage = usages.next().ok_or(AutoresearchError::EvidenceIncomplete)?;
        if usages.next().is_some() {
            return Err(AutoresearchError::ImmutableConflict);
        }
        let episode = self
            .episodes
            .get(&usage.exposure_episode_revision_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let task = self
            .tasks
            .get(&usage.task_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let workstream = self
            .workstreams
            .get(&usage.workstream_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let repository_id = usage
            .local_context
            .repository_id
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let worktree_id = usage
            .local_context
            .worktree_id
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let snapshot = self
            .snapshots
            .get(&snapshot_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let worktree = self
            .worktrees
            .get(&worktree_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        if self.current_episodes.get(&episode.episode_id) != Some(&episode.revision_id)
            || episode.entry_worktree_snapshot_id != Some(snapshot_id)
            || episode.task_id != task.task_id
            || episode.workstream_id != workstream.workstream_id
            || episode.repository_instance_id != Some(repository_id)
            || episode.worktree_instance_id != Some(worktree_id)
            || attempt.task_id != task.task_id
            || attempt.workstream_id != workstream.workstream_id
            || attempt.repository_instance_id != Some(repository_id)
            || !attempt.worktree_instance_ids.contains(&worktree_id)
            || workstream.task_id != task.task_id
            || workstream.repository_instance_id != Some(repository_id)
            || !workstream.worktree_instance_ids.contains(&worktree_id)
            || snapshot.worktree_instance_id != worktree_id
            || worktree.repository_instance_id != repository_id
        {
            return Err(AutoresearchError::ImmutableConflict);
        }
        Ok(())
    }
}

fn exact_bound_run(
    facts: &ControlledFacts,
    observation_id: SourceObservationId,
    attempt_id: AttemptId,
    workstream_id: evertrace_domain::ids::WorkstreamId,
) -> Result<
    (
        evertrace_domain::ids::ExperimentRunId,
        Vec<WorkBindingRevision>,
    ),
    AutoresearchError,
> {
    let mut selected = Vec::new();
    for operation in facts.operations.values().filter(|operation| {
        operation
            .input_source_observation_refs
            .contains(&observation_id)
    }) {
        if operation.pairing_state != PairingState::Paired {
            return Err(AutoresearchError::EvidenceIncomplete);
        }
        let binding = facts
            .bindings
            .get(&operation.operation_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        if binding.assignment_status != AssignmentStatus::Resolved
            || binding.primary_binding.attempt_id != Some(attempt_id)
            || binding.primary_binding.workstream_id != Some(workstream_id)
        {
            return Err(AutoresearchError::ImmutableConflict);
        }
        selected.push(binding);
    }
    if selected.is_empty() {
        return Err(AutoresearchError::EvidenceIncomplete);
    }
    let existing = selected
        .iter()
        .filter_map(|binding| binding.primary_binding.experiment_run_id)
        .collect::<std::collections::BTreeSet<_>>();
    if existing.len() > 1 || !existing.is_empty() && existing.len() != selected.len() {
        return Err(AutoresearchError::ImmutableConflict);
    }
    let run_id = existing
        .first()
        .copied()
        .unwrap_or_else(evertrace_domain::ids::ExperimentRunId::new_v7);
    if existing.is_empty() {
        let mut successors = Vec::with_capacity(selected.len());
        for current in selected {
            let mut next = current.clone();
            next.work_binding_revision_id = evertrace_domain::ids::WorkBindingRevisionId::new_v7();
            next.revision_generation = current.revision_generation.saturating_add(1);
            next.predecessor_revision_id = Some(current.work_binding_revision_id);
            next.primary_binding.experiment_run_id = Some(run_id);
            next.evidence_refs.push(observation_id.to_string());
            next.evidence_refs.sort();
            next.evidence_refs.dedup();
            current
                .validate_successor(&next)
                .map_err(|_| AutoresearchError::ImmutableConflict)?;
            successors.push(next);
        }
        Ok((run_id, successors))
    } else {
        Ok((run_id, Vec::new()))
    }
}

fn require_bound_operations(
    facts: &ControlledFacts,
    observation_id: SourceObservationId,
    launch: bool,
    run_id: evertrace_domain::ids::ExperimentRunId,
    attempt_id: AttemptId,
    workstream_id: evertrace_domain::ids::WorkstreamId,
) -> Result<(), AutoresearchError> {
    let operations = facts
        .operations
        .values()
        .filter(|operation| {
            let refs = if launch {
                &operation.input_source_observation_refs
            } else {
                &operation.result_source_observation_refs
            };
            refs.contains(&observation_id)
        })
        .collect::<Vec<_>>();
    if operations.is_empty() {
        return Err(AutoresearchError::EvidenceIncomplete);
    }
    if operations.iter().any(|operation| {
        operation.pairing_state != PairingState::Paired
            || facts
                .bindings
                .get(&operation.operation_id)
                .is_none_or(|binding| {
                    binding.assignment_status != AssignmentStatus::Resolved
                        || binding.primary_binding.experiment_run_id != Some(run_id)
                        || binding.primary_binding.attempt_id != Some(attempt_id)
                        || binding.primary_binding.workstream_id != Some(workstream_id)
                })
    }) {
        Err(AutoresearchError::ImmutableConflict)
    } else {
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMetric {
    decimal: String,
    unit: String,
    uncertainty_decimal: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultParseRequest {
    pub scope: ResultScope,
    pub raw_cas_refs: Vec<CasId>,
    pub created_at_us: i64,
}

#[derive(Clone)]
pub struct ResultEvidenceService {
    cas: CasStore,
}

impl ResultEvidenceService {
    pub const fn new(cas: CasStore) -> Self {
        Self { cas }
    }

    pub fn parse(
        &self,
        run: &ExperimentRun,
        mut request: ResultParseRequest,
    ) -> Result<ResultEvidence, AutoresearchError> {
        require_declaration_run(run)?;
        request.raw_cas_refs.sort();
        request.raw_cas_refs.dedup();
        let bytes = self.read_all(&request.raw_cas_refs)?;
        let (status, metric, parser_failure) =
            parse_metric_set(&bytes, run.multi_cas_metric_policy)?;
        let result = ResultEvidence {
            result_evidence_id: ResultEvidenceId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            experiment_run_id: run.run_id,
            experiment_run_revision_id: run.revision_id,
            result_scope: request.scope,
            raw_artifact_refs: Vec::new(),
            raw_cas_refs: request.raw_cas_refs.clone(),
            parsed_metric: metric,
            parser_receipt: ParserReceipt {
                parser_version: RESULT_PARSER_VERSION.into(),
                input_artifact_refs: Vec::new(),
                input_cas_refs: request.raw_cas_refs,
                status,
                failure_code: parser_failure,
            },
            verifier_receipt: None,
            completeness: EvidenceCompleteness::Incomplete,
            failure: parser_failure.map(ResultFailure::Parser),
            created_at_us: request.created_at_us,
        };
        result
            .validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        Ok(result)
    }

    pub fn parse_command(
        &self,
        context: AutoresearchCommandContext,
        run: &ExperimentRun,
        request: ResultParseRequest,
    ) -> Result<(ResultEvidence, JournalCommand), AutoresearchError> {
        let result = self.parse(run, request)?;
        let command = self.validated_command(context, run, &result)?;
        Ok((result, command))
    }

    pub fn extend(
        &self,
        run: &ExperimentRun,
        current: &ResultEvidence,
        additional_cas_refs: Vec<CasId>,
        created_at_us: i64,
    ) -> Result<AutoresearchResolution<ResultEvidence>, AutoresearchError> {
        require_result_run(run, current)?;
        if created_at_us < current.created_at_us {
            return Err(AutoresearchError::ImmutableConflict);
        }
        let mut combined = current.raw_cas_refs.clone();
        combined.extend(additional_cas_refs);
        combined.sort();
        combined.dedup();
        if combined == current.raw_cas_refs {
            return Ok(AutoresearchResolution::NoDelta);
        }
        let bytes = self.read_all(&combined)?;
        let (status, metric, parser_failure) =
            parse_metric_set(&bytes, run.multi_cas_metric_policy).map_err(|error| {
                if current.parsed_metric.is_some() {
                    AutoresearchError::ImmutableConflict
                } else {
                    error
                }
            })?;
        if current.parsed_metric.is_some() && metric != current.parsed_metric {
            return Err(AutoresearchError::ImmutableConflict);
        }
        let mut next = current.clone();
        next.revision_id = RevisionId::new_v7();
        next.parent_revision_id = Some(current.revision_id);
        next.raw_cas_refs = combined.clone();
        next.parser_receipt.input_cas_refs = combined;
        next.parser_receipt.status = status;
        next.parser_receipt.failure_code = parser_failure;
        next.parsed_metric = metric;
        next.verifier_receipt = None;
        next.completeness = EvidenceCompleteness::Incomplete;
        next.failure = parser_failure.map(ResultFailure::Parser);
        next.created_at_us = created_at_us;
        current
            .validate_successor(&next)
            .map_err(|_| AutoresearchError::ImmutableConflict)?;
        Ok(AutoresearchResolution::Revision(Box::new(next)))
    }

    pub fn verify(
        &self,
        run: &ExperimentRun,
        current: &ResultEvidence,
        created_at_us: i64,
    ) -> Result<AutoresearchResolution<ResultEvidence>, AutoresearchError> {
        require_result_run(run, current)?;
        let bytes = self.read_all(&current.raw_cas_refs)?;
        let (parser_status, parsed_metric, parser_failure) =
            parse_metric_set(&bytes, run.multi_cas_metric_policy)
                .map_err(|_| AutoresearchError::ImmutableConflict)?;
        let matches = parser_status == current.parser_receipt.status
            && parsed_metric == current.parsed_metric
            && parser_failure == current.parser_receipt.failure_code;
        let verifier_failure =
            (!matches).then_some(VerifierFailureCode::DeterministicReparseMismatch);
        let verifier = VerifierReceipt {
            verifier_version: RESULT_VERIFIER_VERSION.into(),
            status: if matches {
                VerifierStatus::Passed
            } else {
                VerifierStatus::Failed
            },
            failure_code: verifier_failure,
        };
        let completeness = if matches && parser_status == ParserStatus::Parsed {
            EvidenceCompleteness::Complete
        } else {
            EvidenceCompleteness::Incomplete
        };
        if current.verifier_receipt.as_ref() == Some(&verifier)
            && current.completeness == completeness
        {
            return Ok(AutoresearchResolution::NoDelta);
        }
        if current.verifier_receipt.is_some() || created_at_us < current.created_at_us {
            return Err(AutoresearchError::ImmutableConflict);
        }
        let mut next = current.clone();
        next.revision_id = RevisionId::new_v7();
        next.parent_revision_id = Some(current.revision_id);
        next.verifier_receipt = Some(verifier);
        next.completeness = completeness;
        next.failure = parser_failure
            .map(ResultFailure::Parser)
            .or(verifier_failure.map(ResultFailure::Verifier));
        next.created_at_us = created_at_us;
        current
            .validate_successor(&next)
            .map_err(|_| AutoresearchError::InvalidInput)?;
        Ok(AutoresearchResolution::Revision(Box::new(next)))
    }

    pub fn verify_command(
        &self,
        context: AutoresearchCommandContext,
        run: &ExperimentRun,
        current: &ResultEvidence,
        created_at_us: i64,
    ) -> Result<Option<AutoresearchCommandRevision<ResultEvidence>>, AutoresearchError> {
        match self.verify(run, current, created_at_us)? {
            AutoresearchResolution::NoDelta => Ok(None),
            AutoresearchResolution::Revision(value) => {
                let command = self.validated_command(context, run, &value)?;
                Ok(Some(AutoresearchCommandRevision { value, command }))
            }
        }
    }

    fn validated_command(
        &self,
        context: AutoresearchCommandContext,
        run: &ExperimentRun,
        result: &ResultEvidence,
    ) -> Result<JournalCommand, AutoresearchError> {
        require_result_run(run, result)?;
        self.read_all(&result.raw_cas_refs)?;
        result
            .validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        payload_command(
            context,
            vec![JournalPayload::ResultEvidenceRecorded(Box::new(
                result.clone(),
            ))],
        )
    }

    fn read_all(&self, refs: &[CasId]) -> Result<Vec<Vec<u8>>, AutoresearchError> {
        if refs.is_empty() {
            return Err(AutoresearchError::EvidenceIncomplete);
        }
        refs.iter().map(|id| read_cas(&self.cas, id)).collect()
    }
}

fn require_declaration_run(run: &ExperimentRun) -> Result<(), AutoresearchError> {
    run.validate()
        .map_err(|_| AutoresearchError::InvalidInput)?;
    if !run.is_declaration_only() {
        return Err(AutoresearchError::UntrustedRunEvidence);
    }
    Ok(())
}

fn require_result_run(
    run: &ExperimentRun,
    result: &ResultEvidence,
) -> Result<(), AutoresearchError> {
    require_declaration_run(run)?;
    if result.experiment_run_id != run.run_id
        || result.experiment_run_revision_id != run.revision_id
        || run.metric_extractor_version != RESULT_PARSER_VERSION
    {
        return Err(AutoresearchError::ImmutableConflict);
    }
    Ok(())
}

fn parse_metric(bytes: &[u8]) -> Option<MetricValue> {
    let value = serde_json::from_slice::<RawMetric>(bytes).ok()?;
    let metric = MetricValue {
        decimal: preserve_valid_decimal(&value.decimal)?,
        unit: value.unit,
        uncertainty_decimal: match value.uncertainty_decimal {
            Some(value) => Some(preserve_valid_decimal(&value)?),
            None => None,
        },
    };
    metric.validate().ok().map(|()| metric)
}

fn preserve_valid_decimal(value: &str) -> Option<String> {
    let parsed = value.parse::<f64>().ok()?;
    parsed.is_finite().then(|| value.to_owned())
}

fn parse_metric_set(
    bytes: &[Vec<u8>],
    policy: MultiCasMetricPolicy,
) -> Result<(ParserStatus, Option<MetricValue>, Option<ParserFailureCode>), AutoresearchError> {
    let parsed = bytes
        .iter()
        .filter_map(|value| parse_metric(value))
        .collect::<Vec<_>>();
    match parsed.as_slice() {
        [] => Ok((
            ParserStatus::Failed,
            None,
            Some(ParserFailureCode::MetricParseFailed),
        )),
        [metric] => Ok((ParserStatus::Parsed, Some(metric.clone()), None)),
        [first, rest @ ..]
            if policy == MultiCasMetricPolicy::AllowIdenticalParsed
                && rest.iter().all(|metric| metric == first) =>
        {
            Ok((ParserStatus::Parsed, Some(first.clone()), None))
        }
        _ => Err(AutoresearchError::AmbiguousMetricInput),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibleResultCohort {
    pub member_result_ids: Vec<ResultEvidenceId>,
}

pub fn compatible_result_cohort(
    members: &[(&ResultEvidence, &ExperimentRun)],
) -> Result<Option<CompatibleResultCohort>, AutoresearchError> {
    if members.is_empty() {
        return Ok(None);
    }
    if members.len() > MAX_COMPARISON_MEMBERS {
        return Err(AutoresearchError::IncompatibleComparison);
    }
    let expected = members[0].1.comparison_key;
    let expected_attempt = members[0].1.attempt_id;
    let expected_workstream = members[0].1.workstream_id;
    let expected_strategy = members[0].1.strategy_contract_fingerprint;
    let expected_unit = members[0]
        .0
        .parsed_metric
        .as_ref()
        .ok_or(AutoresearchError::EvidenceIncomplete)?
        .unit
        .clone();
    let mut ids = Vec::with_capacity(members.len());
    for (result, run) in members {
        let terminal_scope_is_compatible = match result.result_scope {
            ResultScope::Complete => run.execution_status == RunExecutionStatus::Completed,
            ResultScope::Partial => matches!(
                run.execution_status,
                RunExecutionStatus::Completed
                    | RunExecutionStatus::Failed
                    | RunExecutionStatus::Interrupted
            ),
        };
        if run.validate().is_err()
            || result.validate().is_err()
            || run.attempt_binding_status != AttemptBindingStatus::Resolved
            || run.attempt_id.is_none()
            || run.attempt_id != expected_attempt
            || run.workstream_id != expected_workstream
            || run.strategy_contract_fingerprint != expected_strategy
            || run.observability != RunObservability::Full
            || run.contract_validity != RunContractValidity::Valid
            || !terminal_scope_is_compatible
            || result.experiment_run_id != run.run_id
            || result.experiment_run_revision_id != run.revision_id
            || result.parser_receipt.parser_version != run.metric_extractor_version
            || run.comparison_key != expected
            || result.completeness != EvidenceCompleteness::Complete
            || result.verifier_receipt.as_ref().is_none_or(|receipt| {
                receipt.status != VerifierStatus::Passed
                    || receipt.verifier_version != RESULT_VERIFIER_VERSION
            })
            || result.parsed_metric.as_ref().map(|metric| &metric.unit) != Some(&expected_unit)
        {
            return Err(AutoresearchError::IncompatibleComparison);
        }
        ids.push(result.result_evidence_id);
    }
    ids.sort();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AutoresearchError::IncompatibleComparison);
    }
    Ok(Some(CompatibleResultCohort {
        member_result_ids: ids,
    }))
}

#[derive(Clone)]
pub struct ArtifactService {
    cas: CasStore,
}

impl ArtifactService {
    pub const fn new(cas: CasStore) -> Self {
        Self { cas }
    }

    pub fn create(
        &self,
        mut revision: ArtifactRevision,
    ) -> Result<WorkArtifact, AutoresearchError> {
        self.prepare_revision(&mut revision)?;
        revision.revision_id = RevisionId::new_v7();
        revision.parent_revision_id = None;
        let artifact = WorkArtifact {
            work_artifact_id: WorkArtifactId::new_v7(),
            revision,
        };
        artifact
            .validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        Ok(artifact)
    }

    pub fn create_command(
        &self,
        context: AutoresearchCommandContext,
        revision: ArtifactRevision,
    ) -> Result<(WorkArtifact, JournalCommand), AutoresearchError> {
        let artifact = self.create(revision)?;
        let command = self.validated_command(context, &artifact)?;
        Ok((artifact, command))
    }

    pub fn create_for_run_command(
        &self,
        context: AutoresearchCommandContext,
        current_run: &ExperimentRun,
        mut revision: ArtifactRevision,
    ) -> Result<(WorkArtifact, ExperimentRun, JournalCommand), AutoresearchError> {
        require_declaration_run(current_run)?;
        revision
            .produced_by_refs
            .push(ArtifactActor::ExperimentRun(current_run.run_id));
        revision.produced_by_refs.sort();
        revision.produced_by_refs.dedup();
        let artifact = self.create(revision)?;
        let mut next_run = current_run.clone();
        next_run.revision_id = RevisionId::new_v7();
        next_run.parent_revision_id = Some(current_run.revision_id);
        next_run.work_artifact_refs.push(artifact.work_artifact_id);
        next_run.work_artifact_refs.sort();
        next_run.created_at_us = next_run.created_at_us.max(artifact.revision.created_at_us);
        current_run
            .validate_successor(&next_run)
            .map_err(|_| AutoresearchError::ImmutableConflict)?;
        let command = payload_command(
            context,
            vec![
                JournalPayload::ExperimentRunRecorded(Box::new(next_run.clone())),
                JournalPayload::WorkArtifactRecorded(Box::new(artifact.clone())),
            ],
        )?;
        Ok((artifact, next_run, command))
    }

    pub fn revise(
        &self,
        current: &WorkArtifact,
        mut revision: ArtifactRevision,
    ) -> Result<AutoresearchResolution<WorkArtifact>, AutoresearchError> {
        revision.revision_id = current.revision.revision_id;
        revision.parent_revision_id = current.revision.parent_revision_id;
        if current.revision == revision {
            return Ok(AutoresearchResolution::NoDelta);
        }
        self.prepare_revision(&mut revision)?;
        revision.revision_id = RevisionId::new_v7();
        revision.parent_revision_id = Some(current.revision.revision_id);
        let next = WorkArtifact {
            work_artifact_id: current.work_artifact_id,
            revision,
        };
        current
            .validate_successor(&next)
            .map_err(|_| AutoresearchError::ImmutableConflict)?;
        Ok(AutoresearchResolution::Revision(Box::new(next)))
    }

    pub fn revise_command(
        &self,
        context: AutoresearchCommandContext,
        current: &WorkArtifact,
        revision: ArtifactRevision,
    ) -> Result<Option<AutoresearchCommandRevision<WorkArtifact>>, AutoresearchError> {
        match self.revise(current, revision)? {
            AutoresearchResolution::NoDelta => Ok(None),
            AutoresearchResolution::Revision(value) => {
                let command = self.validated_command(context, &value)?;
                Ok(Some(AutoresearchCommandRevision { value, command }))
            }
        }
    }

    fn prepare_revision(&self, revision: &mut ArtifactRevision) -> Result<(), AutoresearchError> {
        if revision.scope == ArtifactScope::Global
            || revision.payload_status == ArtifactPayloadStatus::SourcePurged
        {
            return Err(AutoresearchError::UnsupportedArtifactAuthority);
        }
        revision.produced_by_refs.sort();
        revision.produced_by_refs.dedup();
        revision.consumed_by_refs.sort();
        revision.consumed_by_refs.dedup();
        revision.source_observation_refs.sort();
        revision.source_observation_refs.dedup();
        if let Some(id) = revision.content_blob_ref {
            if revision
                .content_fingerprint
                .is_some_and(|value| value != id)
            {
                return Err(AutoresearchError::ImmutableConflict);
            }
            read_cas(&self.cas, &id)?;
            revision.content_fingerprint = Some(id);
        } else {
            revision.content_fingerprint = None;
        }
        Ok(())
    }

    fn validated_command(
        &self,
        context: AutoresearchCommandContext,
        artifact: &WorkArtifact,
    ) -> Result<JournalCommand, AutoresearchError> {
        if artifact.revision.scope == ArtifactScope::Global
            || artifact.revision.payload_status == ArtifactPayloadStatus::SourcePurged
        {
            return Err(AutoresearchError::UnsupportedArtifactAuthority);
        }
        if let Some(id) = artifact.revision.content_blob_ref {
            read_cas(&self.cas, &id)?;
        }
        artifact
            .validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        payload_command(
            context,
            vec![JournalPayload::WorkArtifactRecorded(Box::new(
                artifact.clone(),
            ))],
        )
    }
}

fn payload_command(
    context: AutoresearchCommandContext,
    payloads: Vec<JournalPayload>,
) -> Result<JournalCommand, AutoresearchError> {
    let drafts = payloads
        .into_iter()
        .map(|payload| {
            JournalEventDraft::runtime(
                context.occurred_at_us,
                context.effective_config_hash,
                context.algorithm_revision,
                payload,
            )
        })
        .collect();
    JournalCommand::new(context.command_id, drafts).map_err(AutoresearchError::Store)
}

fn read_cas(cas: &CasStore, id: &CasId) -> Result<Vec<u8>, AutoresearchError> {
    let text = id.to_string();
    let digest = CasDigest::from_str(
        text.strip_prefix("cas:")
            .ok_or(AutoresearchError::InvalidInput)?,
    )
    .map_err(|_| AutoresearchError::InvalidInput)?;
    cas.read(&digest).map_err(|_| AutoresearchError::Cas)
}

#[derive(Debug, Error)]
pub enum AutoresearchError {
    #[error("autoresearch input is invalid")]
    InvalidInput,
    #[error("strategy change requires a new Attempt")]
    StrategyDriftRequiresNewAttempt,
    #[error("typed evidence conflicts with immutable facts")]
    ImmutableConflict,
    #[error("required evidence is incomplete")]
    EvidenceIncomplete,
    #[error("no trusted scheduler or process evidence source is available")]
    UntrustedRunEvidence,
    #[error("result contracts are incompatible")]
    IncompatibleComparison,
    #[error("multiple CAS inputs contain conflicting parsed metrics")]
    AmbiguousMetricInput,
    #[error("artifact authority belongs to a later slice")]
    UnsupportedArtifactAuthority,
    #[error("CAS evidence is unavailable or invalid")]
    Cas,
    #[error(transparent)]
    Store(#[from] evertrace_store::StoreError),
}
