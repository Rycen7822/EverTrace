use std::collections::BTreeMap;

use evertrace_capture::CasDigest;
use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, EvidenceSurface, Operation, PairingState,
        SourceArchiveMode, SourceObservation, SourceReceipt, SourceRole, hex, payload_fingerprint,
    },
    ids::{
        AttemptId, ExperimentRunId, OperationId, ResultEvidenceId, SourceObservationId,
        SourceReceiptId, TaskId, WorkArtifactId, WorkEpisodeId, WorkstreamId, WorktreeId,
        WorktreeSnapshotId,
    },
    repository::{RepositoryInstance, WorktreeInstance, WorktreeSnapshot},
    revision::RevisionId,
    semantic::ResultEvidence,
    work::{
        ArtifactActor, ArtifactScope, AssignmentStatus, Attempt, AttemptBindingStatus,
        ControlledRunSourceEnvelope, ExperimentRun, RunContractValidity, RunExecutionStatus,
        RunObservability, Task, WorkArtifact, WorkBindingRevision, WorkEpisode, Workstream,
    },
};

use crate::{
    JournalPayload,
    command::StoreError,
    projections::{ProjectionSnapshot, current_binding_lineage, procedure::ProcedureState},
};

pub(crate) struct ControlledRunAdmissionView<'a> {
    pub runs: &'a BTreeMap<ExperimentRunId, (ExperimentRun, u64)>,
    pub attempts: &'a BTreeMap<AttemptId, (Attempt, u64)>,
    pub work_bindings:
        &'a BTreeMap<evertrace_domain::ids::WorkBindingRevisionId, (WorkBindingRevision, u64)>,
    pub operations: &'a BTreeMap<OperationId, (Operation, u64)>,
    pub snapshots: &'a BTreeMap<WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
    pub receipts: &'a BTreeMap<SourceReceiptId, (SourceReceipt, u64)>,
    pub observations: &'a BTreeMap<SourceObservationId, (SourceObservation, u64)>,
    pub surfaces: &'a BTreeMap<SourceObservationId, (EvidenceSurface, u64)>,
    pub artifacts: &'a BTreeMap<WorkArtifactId, (WorkArtifact, u64)>,
    pub procedures: &'a ProcedureState,
    pub tasks: &'a BTreeMap<TaskId, (Task, u64)>,
    pub workstreams: &'a BTreeMap<WorkstreamId, (Workstream, u64)>,
    pub episodes: &'a BTreeMap<WorkEpisodeId, (WorkEpisode, u64)>,
    pub episode_revisions: &'a BTreeMap<RevisionId, (WorkEpisode, u64)>,
    pub worktrees: &'a BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
}

pub(crate) fn validate_controlled_command<'a>(
    view: ControlledRunAdmissionView<'_>,
    payloads: impl IntoIterator<Item = &'a JournalPayload>,
    error: StoreError,
) -> Result<(), StoreError> {
    let payloads = payloads.into_iter().collect::<Vec<_>>();
    let runs = payloads
        .iter()
        .filter_map(|payload| match payload {
            JournalPayload::ExperimentRunRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for run in &runs {
        if run.comparison_execution_binding.is_none() && !run.is_declaration_only() {
            return Err(error);
        }
    }
    if !runs
        .iter()
        .any(|run| run.comparison_execution_binding.is_some())
    {
        return Ok(());
    }
    let results = payloads
        .iter()
        .filter_map(|payload| match payload {
            JournalPayload::ResultEvidenceRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let command_artifacts = payloads
        .iter()
        .filter_map(|payload| match payload {
            JournalPayload::WorkArtifactRecorded(value) => Some(value.work_artifact_id),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let mut binding_values = view
        .work_bindings
        .values()
        .map(|(value, _)| value.clone())
        .collect::<Vec<_>>();
    binding_values.extend(payloads.iter().filter_map(|payload| match payload {
        JournalPayload::WorkBindingRecorded(value) => Some(value.as_ref().clone()),
        _ => None,
    }));
    let bindings = current_binding_lineage(binding_values.iter()).map_err(|_| error)?;
    for run in runs {
        let Some(binding) = run.comparison_execution_binding.as_ref() else {
            continue;
        };
        let attempt_id = run.attempt_id.ok_or(error)?;
        let attempt = view.attempts.get(&attempt_id).ok_or(error)?.0.clone();
        if attempt.workstream_id != run.workstream_id
            || attempt.strategy_contract_fingerprint != run.strategy_contract_fingerprint
        {
            return Err(error);
        }
        match view.runs.get(&run.run_id) {
            None => {
                if run.parent_revision_id.is_some() || !run.is_controlled_declaration() {
                    return Err(error);
                }
                let launch = validate_witnesses(
                    run.source_receipt_refs.as_slice(),
                    true,
                    run,
                    &attempt,
                    &bindings,
                    &view,
                    error,
                )?;
                if !launch_matches(run, &attempt, binding, &launch) {
                    return Err(error);
                }
                let ControlledRunSourceEnvelope::Launch {
                    procedure_revision_id,
                    ..
                } = launch
                else {
                    return Err(error);
                };
                if !view
                    .procedures
                    .is_current_revision_id(procedure_revision_id)
                    || view
                        .snapshots
                        .get(&run.code_snapshot_id)
                        .and_then(|(snapshot, _)| snapshot.toolchain_fingerprint.as_deref())
                        != Some(binding.toolchain_revision.as_str())
                {
                    return Err(error);
                }
                validate_declaration_anchor(
                    &view,
                    procedure_revision_id,
                    &attempt,
                    run.code_snapshot_id,
                    error,
                )?;
            }
            Some((current, _)) => {
                if !current.is_controlled_declaration()
                    || run.parent_revision_id != Some(current.revision_id)
                    || run.observability != RunObservability::Full
                    || run.execution_status != RunExecutionStatus::Completed
                    || run.contract_validity != RunContractValidity::Valid
                {
                    return Err(error);
                }
                current.validate_successor(run).map_err(|_| error)?;
                if run.created_at_us != current.created_at_us
                    || run.started_at_us != current.started_at_us
                    || run.source_receipt_refs != current.source_receipt_refs
                    || run.attempt_id != current.attempt_id
                    || run.attempt_binding_status != current.attempt_binding_status
                {
                    return Err(error);
                }
                let terminal = validate_witnesses(
                    run.terminal_evidence_refs.as_slice(),
                    false,
                    run,
                    &attempt,
                    &bindings,
                    &view,
                    error,
                )?;
                let ControlledRunSourceEnvelope::Terminal {
                    ended_at_us,
                    metric,
                    artifact_refs,
                    ..
                } = terminal
                else {
                    return Err(error);
                };
                if run.ended_at_us != Some(ended_at_us)
                    || run.work_artifact_refs != artifact_refs
                    || artifact_refs.iter().any(|id| {
                        !view.artifacts.contains_key(id) && !command_artifacts.contains(id)
                    })
                {
                    return Err(error);
                }
                let matching = results
                    .iter()
                    .filter(|result| {
                        result.experiment_run_id == run.run_id
                            && result.experiment_run_revision_id == run.revision_id
                    })
                    .copied()
                    .collect::<Vec<_>>();
                if matching.len() != 1
                    || matching[0].parsed_metric.as_ref() != Some(&metric)
                    || matching[0].result_scope != evertrace_domain::semantic::ResultScope::Complete
                    || matching[0].completeness
                        != evertrace_domain::semantic::EvidenceCompleteness::Complete
                    || matching[0].failure.is_some()
                {
                    return Err(error);
                }
                let expected_cas = run
                    .terminal_evidence_refs
                    .iter()
                    .map(|id| {
                        let receipt = &view.receipts.get(id).ok_or(error)?.0;
                        let digest = receipt.cas_ref.parse::<CasDigest>().map_err(|_| error)?;
                        Ok(evertrace_domain::ids::CasId::from_digest(
                            *digest.as_bytes(),
                        ))
                    })
                    .collect::<Result<Vec<_>, StoreError>>()?;
                if matching[0].raw_cas_refs != expected_cas
                    || matching[0].raw_artifact_refs != artifact_refs
                {
                    return Err(error);
                }
            }
        }
    }
    for result in results {
        let controlled_in_command = payloads.iter().any(|payload| match payload {
            JournalPayload::ExperimentRunRecorded(run) => {
                run.comparison_execution_binding.is_some()
                    && !run.is_declaration_only()
                    && result.experiment_run_revision_id == run.revision_id
            }
            _ => false,
        });
        if view
            .runs
            .get(&result.experiment_run_id)
            .is_some_and(|(run, _)| run.comparison_execution_binding.is_some())
            && !controlled_in_command
        {
            return Err(error);
        }
    }
    Ok(())
}

fn validate_declaration_anchor(
    view: &ControlledRunAdmissionView<'_>,
    procedure_revision_id: RevisionId,
    attempt: &Attempt,
    snapshot_id: WorktreeSnapshotId,
    error: StoreError,
) -> Result<(), StoreError> {
    let usage = view
        .procedures
        .controlled_usage_anchor(procedure_revision_id, attempt.attempt_id)
        .map_err(|_| error)?
        .ok_or(error)?;
    let episode = &view
        .episode_revisions
        .get(&usage.exposure_episode_revision_id)
        .ok_or(error)?
        .0;
    let current_episode = &view.episodes.get(&episode.episode_id).ok_or(error)?.0;
    let task = &view.tasks.get(&usage.task_id).ok_or(error)?.0;
    let workstream = &view.workstreams.get(&usage.workstream_id).ok_or(error)?.0;
    let repository_id = usage.local_context.repository_id.ok_or(error)?;
    let worktree_id = usage.local_context.worktree_id.ok_or(error)?;
    let snapshot = &view.snapshots.get(&snapshot_id).ok_or(error)?.0;
    let worktree = &view.worktrees.get(&worktree_id).ok_or(error)?.0;
    if current_episode.revision_id != episode.revision_id
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
        return Err(error);
    }
    Ok(())
}

fn validate_witnesses(
    receipt_ids: &[SourceReceiptId],
    launch: bool,
    run: &ExperimentRun,
    attempt: &Attempt,
    bindings: &BTreeMap<OperationId, &WorkBindingRevision>,
    view: &ControlledRunAdmissionView<'_>,
    error: StoreError,
) -> Result<ControlledRunSourceEnvelope, StoreError> {
    let mut selected = None;
    for receipt_id in receipt_ids {
        let receipt = &view.receipts.get(receipt_id).ok_or(error)?.0;
        let observation = &view
            .observations
            .get(&receipt.source_observation_id)
            .ok_or(error)?
            .0;
        let surface = &view
            .surfaces
            .get(&receipt.source_observation_id)
            .ok_or(error)?
            .0;
        if receipt.source_observation_id != observation.source_observation_id
            || observation.source_receipt_ref != receipt.source_receipt_id
            || receipt.capture_completeness != CaptureCompleteness::Complete
            || observation.capture_completeness != CaptureCompleteness::Complete
            || surface.capture_completeness != CaptureCompleteness::Complete
            || receipt.archive_mode != SourceArchiveMode::Exact
            || receipt.unsupported_record_classification.is_some()
            || receipt.protected_secret_digest.is_some()
            || !receipt.redaction_spans.is_empty()
            || receipt.canonicalization_revision != surface.canonicalization_version
            || observation.canonicalization_revision != surface.canonicalization_version
            || observation.source_role != surface.source_role
            || observation.content_trust != surface.content_trust
            || !matches!(surface.source_role, SourceRole::Host | SourceRole::Tool)
            || surface.content_trust != ContentTrust::Observed
            || observation.payload_fingerprint
                != hex(&payload_fingerprint(
                    surface.canonicalization_version,
                    surface.protected_text.as_bytes(),
                    None,
                )
                .map_err(|_| error)?)
            || receipt.cas_ref
                != CasDigest::for_protected_bytes(surface.protected_text.as_bytes()).to_string()
        {
            return Err(error);
        }
        surface.validate().map_err(|_| error)?;
        let envelope =
            ControlledRunSourceEnvelope::decode_canonical(surface.protected_text.as_bytes())
                .map_err(|_| error)?;
        if launch != matches!(envelope, ControlledRunSourceEnvelope::Launch { .. }) {
            return Err(error);
        }
        let operations = view
            .operations
            .values()
            .map(|(operation, _)| operation)
            .filter(|operation| {
                let refs = if launch {
                    &operation.input_source_observation_refs
                } else {
                    &operation.result_source_observation_refs
                };
                refs.contains(&observation.source_observation_id)
            })
            .collect::<Vec<_>>();
        if operations.is_empty()
            || operations.iter().any(|operation| {
                operation.pairing_state != PairingState::Paired
                    || bindings.get(&operation.operation_id).is_none_or(|binding| {
                        binding.assignment_status != AssignmentStatus::Resolved
                            || binding.primary_binding.experiment_run_id != Some(run.run_id)
                            || binding.primary_binding.attempt_id != Some(attempt.attempt_id)
                            || binding.primary_binding.workstream_id != Some(run.workstream_id)
                    })
            })
        {
            return Err(error);
        }
        if selected
            .as_ref()
            .is_some_and(|current| current != &envelope)
        {
            return Err(error);
        }
        selected = Some(envelope);
    }
    selected.ok_or(error)
}

fn launch_matches(
    run: &ExperimentRun,
    attempt: &Attempt,
    binding: &evertrace_domain::work::ComparisonExecutionBinding,
    envelope: &ControlledRunSourceEnvelope,
) -> bool {
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
        binding: source_binding,
        started_at_us,
        ..
    } = envelope
    else {
        return false;
    };
    *attempt_id == attempt.attempt_id
        && binding
            .procedure_exposure_revision_id
            .is_none_or(|value| value == *procedure_revision_id)
        && attempt.strategy_contract.search_policy_ref.as_deref()
            == Some(procedure_revision_id.to_string()).as_deref()
        && run.code_snapshot_id == *code_snapshot_id
        && run.data_fingerprint == *data_fingerprint
        && run.normalized_config == *normalized_config
        && run.variable_declaration == *variable_declaration
        && run.seed_policy == *seed_policy
        && run.seed_values == *seed_values
        && run.nondeterministic == *nondeterministic
        && run.metric_definition == *metric_definition
        && run.metric_extractor_version == *metric_extractor_version
        && run.multi_cas_metric_policy == *multi_cas_metric_policy
        && run.environment_fingerprint == *environment_fingerprint
        && binding == source_binding.as_ref()
        && run.started_at_us == Some(*started_at_us)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AutoresearchCurrentView {
    pub frontier: u64,
    pub runs: BTreeMap<ExperimentRunId, ExperimentRun>,
    pub results: BTreeMap<ResultEvidenceId, ResultEvidence>,
    pub artifacts: BTreeMap<WorkArtifactId, WorkArtifact>,
}

pub(crate) struct AutoresearchRelationInputs<'a> {
    pub runs: &'a BTreeMap<ExperimentRunId, (ExperimentRun, u64)>,
    pub run_revisions: &'a BTreeMap<RevisionId, (ExperimentRun, u64)>,
    pub results: &'a BTreeMap<ResultEvidenceId, (ResultEvidence, u64)>,
    pub artifacts: &'a BTreeMap<WorkArtifactId, (WorkArtifact, u64)>,
    pub attempts: &'a BTreeMap<AttemptId, (Attempt, u64)>,
    pub tasks: &'a BTreeMap<TaskId, (Task, u64)>,
    pub workstreams: &'a BTreeMap<WorkstreamId, (Workstream, u64)>,
    pub operations: &'a BTreeMap<OperationId, (Operation, u64)>,
    pub episodes: &'a BTreeMap<WorkEpisodeId, (WorkEpisode, u64)>,
    pub snapshots: &'a BTreeMap<WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
    pub repositories: &'a BTreeMap<evertrace_domain::ids::RepositoryId, (RepositoryInstance, u64)>,
    pub worktrees: &'a BTreeMap<evertrace_domain::ids::WorktreeId, (WorktreeInstance, u64)>,
    pub source_receipts: &'a BTreeMap<SourceReceiptId, (SourceReceipt, u64)>,
    pub source_observations: &'a BTreeMap<SourceObservationId, (SourceObservation, u64)>,
}

pub(crate) fn validate_relations(input: AutoresearchRelationInputs<'_>) -> Result<(), StoreError> {
    for (run, _) in input.runs.values() {
        let workstream = &input
            .workstreams
            .get(&run.workstream_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        if run
            .source_receipt_refs
            .iter()
            .chain(&run.terminal_evidence_refs)
            .any(|id| !input.source_receipts.contains_key(id))
            || !input.snapshots.contains_key(&run.code_snapshot_id)
        {
            return Err(StoreError::StoreCorrupt);
        }
        if run.attempt_binding_status == AttemptBindingStatus::Resolved {
            let attempt = &input
                .attempts
                .get(&run.attempt_id.ok_or(StoreError::StoreCorrupt)?)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            if attempt.workstream_id != workstream.workstream_id {
                return Err(StoreError::StoreCorrupt);
            }
            if attempt.strategy_contract_fingerprint != run.strategy_contract_fingerprint {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if run
            .work_artifact_refs
            .iter()
            .any(|id| !input.artifacts.contains_key(id))
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for (result, _) in input.results.values() {
        let run = &input
            .run_revisions
            .get(&result.experiment_run_revision_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        if run.run_id != result.experiment_run_id
            || run.metric_extractor_version != "evertrace.result_metric.v1"
            || result.parser_receipt.parser_version != "evertrace.result_metric.v1"
            || result
                .verifier_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.verifier_version != "evertrace.result_reparse.v1")
            || result
                .raw_artifact_refs
                .iter()
                .chain(&result.parser_receipt.input_artifact_refs)
                .any(|id| !input.artifacts.contains_key(id))
            || result.result_scope == evertrace_domain::semantic::ResultScope::Complete
                && !(run.observability == RunObservability::Full
                    && run.execution_status == RunExecutionStatus::Completed
                    && run.contract_validity == RunContractValidity::Valid)
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for (artifact, _) in input.artifacts.values() {
        let revision = &artifact.revision;
        let observations = revision
            .source_observation_refs
            .iter()
            .map(|id| observation_receipt(&input, *id))
            .collect::<Result<Vec<_>, _>>()?;
        if revision
            .produced_by_refs
            .iter()
            .chain(&revision.consumed_by_refs)
            .any(|actor| {
                !actor_matches_scope(&input, actor, &revision.scope, artifact.work_artifact_id)
            })
            || revision.produced_by_refs.is_empty()
                && revision.payload_status
                    == evertrace_domain::work::ArtifactPayloadStatus::Available
                && !revision.content_blob_ref.is_some_and(|content| {
                    let digest = hex(&content.as_digest());
                    observations.iter().any(|receipt| receipt.cas_ref == digest)
                })
        {
            return Err(StoreError::StoreCorrupt);
        }
        match revision.scope {
            ArtifactScope::Task { task_id } => {
                if !input.tasks.contains_key(&task_id) {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ArtifactScope::Repository {
                repository_instance_id,
            } => {
                if !input.repositories.contains_key(&repository_instance_id) {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ArtifactScope::Worktree {
                repository_instance_id,
                worktree_instance_id,
            } => {
                let worktree = &input
                    .worktrees
                    .get(&worktree_instance_id)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0;
                if worktree.repository_instance_id != repository_instance_id
                    || !input.repositories.contains_key(&repository_instance_id)
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ArtifactScope::Global => {}
        }
        for run in input.runs.values().map(|(run, _)| run) {
            let points_to_artifact = run.work_artifact_refs.contains(&artifact.work_artifact_id);
            let artifact_points_to_run = revision
                .produced_by_refs
                .contains(&ArtifactActor::ExperimentRun(run.run_id));
            if points_to_artifact != artifact_points_to_run {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    Ok(())
}

fn observation_receipt<'a>(
    input: &'a AutoresearchRelationInputs<'_>,
    id: SourceObservationId,
) -> Result<&'a SourceReceipt, StoreError> {
    let observation = &input
        .source_observations
        .get(&id)
        .ok_or(StoreError::StoreCorrupt)?
        .0;
    let receipt = &input
        .source_receipts
        .get(&observation.source_receipt_ref)
        .ok_or(StoreError::StoreCorrupt)?
        .0;
    if receipt.source_observation_id != id {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(receipt)
}

fn actor_matches_scope(
    input: &AutoresearchRelationInputs<'_>,
    actor: &ArtifactActor,
    scope: &ArtifactScope,
    artifact_id: WorkArtifactId,
) -> bool {
    match actor {
        ArtifactActor::ExperimentRun(id) => input.runs.get(id).is_some_and(|(run, _)| {
            let snapshot = input
                .snapshots
                .get(&run.code_snapshot_id)
                .map(|value| &value.0);
            let worktree = snapshot
                .and_then(|value| input.worktrees.get(&value.worktree_instance_id))
                .map(|value| &value.0);
            match scope {
                ArtifactScope::Task { task_id } => run
                    .attempt_id
                    .filter(|_| run.attempt_binding_status == AttemptBindingStatus::Resolved)
                    .and_then(|id| input.attempts.get(&id))
                    .is_some_and(|(attempt, _)| attempt.task_id == *task_id),
                ArtifactScope::Repository {
                    repository_instance_id,
                } => worktree
                    .is_some_and(|value| value.repository_instance_id == *repository_instance_id),
                ArtifactScope::Worktree {
                    repository_instance_id,
                    worktree_instance_id,
                } => {
                    snapshot
                        .is_some_and(|value| value.worktree_instance_id == *worktree_instance_id)
                        && worktree.is_some_and(|value| {
                            value.repository_instance_id == *repository_instance_id
                        })
                }
                ArtifactScope::Global => true,
            }
        }),
        ArtifactActor::WorkEpisode(id) => {
            input
                .episodes
                .get(id)
                .is_some_and(|(episode, _)| match scope {
                    ArtifactScope::Task { task_id } => episode.task_id == *task_id,
                    ArtifactScope::Repository {
                        repository_instance_id,
                    } => episode.repository_instance_id == Some(*repository_instance_id),
                    ArtifactScope::Worktree {
                        repository_instance_id,
                        worktree_instance_id,
                    } => {
                        episode.repository_instance_id == Some(*repository_instance_id)
                            && episode.worktree_instance_id == Some(*worktree_instance_id)
                    }
                    ArtifactScope::Global => true,
                })
        }
        ArtifactActor::Operation(id) => input.operations.get(id).is_some_and(|(operation, _)| {
            if !operation.artifact_refs.contains(&artifact_id) {
                return false;
            }
            let Ok(receipts) = operation
                .input_source_observation_refs
                .iter()
                .chain(&operation.result_source_observation_refs)
                .map(|id| observation_receipt(input, *id))
                .collect::<Result<Vec<_>, _>>()
            else {
                return false;
            };
            !receipts.is_empty()
                && match scope {
                    ArtifactScope::Task { task_id } => receipts
                        .iter()
                        .all(|receipt| receipt.task_id == Some(*task_id)),
                    ArtifactScope::Repository {
                        repository_instance_id,
                    } => receipts.iter().all(|receipt| {
                        receipt.repository_instance_id == Some(*repository_instance_id)
                    }),
                    ArtifactScope::Worktree {
                        repository_instance_id,
                        worktree_instance_id,
                    } => receipts.iter().all(|receipt| {
                        receipt.repository_instance_id == Some(*repository_instance_id)
                            && receipt.worktree_instance_id == Some(*worktree_instance_id)
                    }),
                    ArtifactScope::Global => true,
                }
        }),
    }
}

impl AutoresearchCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut run_revisions = BTreeMap::<ExperimentRunId, Vec<ExperimentRun>>::new();
        let mut result_revisions = BTreeMap::<ResultEvidenceId, Vec<ResultEvidence>>::new();
        let mut artifact_revisions = BTreeMap::<WorkArtifactId, Vec<WorkArtifact>>::new();
        for row in snapshot.data_rows() {
            let Some(kind) = row.object_kind.as_deref() else {
                continue;
            };
            let payload_json = row
                .payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?;
            match kind {
                "experiment_run" => {
                    let payload: crate::command::JournalPayload =
                        serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
                    let crate::command::JournalPayload::ExperimentRunRecorded(value) = payload
                    else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    require_row(
                        row,
                        kind,
                        &value.run_id.to_string(),
                        &value.revision_id.to_string(),
                    )?;
                    run_revisions.entry(value.run_id).or_default().push(*value);
                }
                "result_evidence" => {
                    let payload: crate::command::JournalPayload =
                        serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
                    let crate::command::JournalPayload::ResultEvidenceRecorded(value) = payload
                    else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    require_row(
                        row,
                        kind,
                        &value.result_evidence_id.to_string(),
                        &value.revision_id.to_string(),
                    )?;
                    result_revisions
                        .entry(value.result_evidence_id)
                        .or_default()
                        .push(*value);
                }
                "work_artifact" => {
                    let payload: crate::command::JournalPayload =
                        serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
                    let crate::command::JournalPayload::WorkArtifactRecorded(value) = payload
                    else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    require_row(
                        row,
                        kind,
                        &value.work_artifact_id.to_string(),
                        &value.revision.revision_id.to_string(),
                    )?;
                    artifact_revisions
                        .entry(value.work_artifact_id)
                        .or_default()
                        .push(*value);
                }
                _ => {}
            }
        }
        let mut runs = BTreeMap::new();
        for (id, revisions) in run_revisions {
            runs.insert(
                id,
                fold_run_chain(revisions.into_iter().map(|value| (value, 0)).collect())?.0,
            );
        }
        let mut results = BTreeMap::new();
        for (id, revisions) in result_revisions {
            results.insert(
                id,
                fold_result_chain(revisions.into_iter().map(|value| (value, 0)).collect())?.0,
            );
        }
        let mut artifacts = BTreeMap::new();
        for (id, revisions) in artifact_revisions {
            artifacts.insert(
                id,
                fold_artifact_chain(revisions.into_iter().map(|value| (value, 0)).collect())?.0,
            );
        }
        Ok(Self {
            frontier: snapshot.frontier,
            runs,
            results,
            artifacts,
        })
    }
}

fn require_row(
    row: &crate::objects::ObjectRow,
    kind: &str,
    object_id: &str,
    revision_id: &str,
) -> Result<(), StoreError> {
    if row.object_family != Some(crate::command::ObjectFamily::Work)
        || row.row_id != format!("object:work:{kind}:{revision_id}")
        || row.object_id.as_deref() != Some(object_id)
        || row.current_revision_id.as_deref() != Some(revision_id)
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn fold_run_chain(
    mut values: Vec<(ExperimentRun, u64)>,
) -> Result<(ExperimentRun, u64), StoreError> {
    let roots = values
        .iter()
        .enumerate()
        .filter(|(_, (value, _))| value.parent_revision_id.is_none())
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(StoreError::StoreCorrupt);
    }
    let (mut current, mut current_seq) = values.remove(roots[0]);
    current.validate().map_err(|_| StoreError::StoreCorrupt)?;
    if !(current.is_declaration_only() || current.is_controlled_declaration()) {
        return Err(StoreError::StoreCorrupt);
    }
    while !values.is_empty() {
        let matches = values
            .iter()
            .enumerate()
            .filter(|(_, (value, _))| value.parent_revision_id == Some(current.revision_id))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(StoreError::StoreCorrupt);
        }
        let (next, seq) = values.remove(matches[0]);
        current
            .validate_successor(&next)
            .map_err(|_| StoreError::StoreCorrupt)?;
        if !allowed_run_shape(&next) {
            return Err(StoreError::StoreCorrupt);
        }
        current = next;
        current_seq = seq;
    }
    Ok((current, current_seq))
}

fn fold_result_chain(
    mut values: Vec<(ResultEvidence, u64)>,
) -> Result<(ResultEvidence, u64), StoreError> {
    let roots = values
        .iter()
        .enumerate()
        .filter(|(_, (value, _))| value.parent_revision_id.is_none())
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(StoreError::StoreCorrupt);
    }
    let (mut current, mut current_seq) = values.remove(roots[0]);
    current.validate().map_err(|_| StoreError::StoreCorrupt)?;
    while !values.is_empty() {
        let matches = values
            .iter()
            .enumerate()
            .filter(|(_, (value, _))| value.parent_revision_id == Some(current.revision_id))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(StoreError::StoreCorrupt);
        }
        let (next, seq) = values.remove(matches[0]);
        current
            .validate_successor(&next)
            .map_err(|_| StoreError::StoreCorrupt)?;
        current = next;
        current_seq = seq;
    }
    Ok((current, current_seq))
}

fn fold_artifact_chain(
    mut values: Vec<(WorkArtifact, u64)>,
) -> Result<(WorkArtifact, u64), StoreError> {
    let roots = values
        .iter()
        .enumerate()
        .filter(|(_, (value, _))| value.revision.parent_revision_id.is_none())
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(StoreError::StoreCorrupt);
    }
    let (mut current, mut current_seq) = values.remove(roots[0]);
    current.validate().map_err(|_| StoreError::StoreCorrupt)?;
    while !values.is_empty() {
        let matches = values
            .iter()
            .enumerate()
            .filter(|(_, (value, _))| {
                value.revision.parent_revision_id == Some(current.revision.revision_id)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(StoreError::StoreCorrupt);
        }
        let (next, seq) = values.remove(matches[0]);
        current
            .validate_successor(&next)
            .map_err(|_| StoreError::StoreCorrupt)?;
        current = next;
        current_seq = seq;
    }
    Ok((current, current_seq))
}

pub(crate) fn rebuild_runs(
    current: &mut BTreeMap<ExperimentRunId, (ExperimentRun, u64)>,
    revisions: &BTreeMap<RevisionId, (ExperimentRun, u64)>,
) -> Result<(), StoreError> {
    let mut grouped = BTreeMap::<ExperimentRunId, Vec<(ExperimentRun, u64)>>::new();
    for (value, seq) in revisions.values() {
        grouped
            .entry(value.run_id)
            .or_default()
            .push((value.clone(), *seq));
    }
    current.clear();
    for (id, values) in grouped {
        current.insert(id, fold_run_chain(values)?);
    }
    Ok(())
}

pub(crate) fn rebuild_results(
    current: &mut BTreeMap<ResultEvidenceId, (ResultEvidence, u64)>,
    revisions: &BTreeMap<RevisionId, (ResultEvidence, u64)>,
) -> Result<(), StoreError> {
    let mut grouped = BTreeMap::<ResultEvidenceId, Vec<(ResultEvidence, u64)>>::new();
    for (value, seq) in revisions.values() {
        grouped
            .entry(value.result_evidence_id)
            .or_default()
            .push((value.clone(), *seq));
    }
    current.clear();
    for (id, values) in grouped {
        current.insert(id, fold_result_chain(values)?);
    }
    Ok(())
}

pub(crate) fn rebuild_artifacts(
    current: &mut BTreeMap<WorkArtifactId, (WorkArtifact, u64)>,
    revisions: &BTreeMap<RevisionId, (WorkArtifact, u64)>,
) -> Result<(), StoreError> {
    let mut grouped = BTreeMap::<WorkArtifactId, Vec<(WorkArtifact, u64)>>::new();
    for (value, seq) in revisions.values() {
        grouped
            .entry(value.work_artifact_id)
            .or_default()
            .push((value.clone(), *seq));
    }
    current.clear();
    for (id, values) in grouped {
        current.insert(id, fold_artifact_chain(values)?);
    }
    Ok(())
}

pub(crate) fn record_run(
    current: &mut BTreeMap<ExperimentRunId, (ExperimentRun, u64)>,
    revisions: Option<&mut BTreeMap<RevisionId, (ExperimentRun, u64)>>,
    value: ExperimentRun,
    seq: u64,
    error: StoreError,
) -> Result<(), StoreError> {
    if !allowed_run_shape(&value) {
        return Err(error);
    }
    if let Some((existing, _)) = current.get(&value.run_id) {
        if existing == &value {
            return Ok(());
        }
        existing.validate_successor(&value).map_err(|_| error)?;
    } else if value.parent_revision_id.is_some() {
        return Err(error);
    } else {
        value.validate().map_err(|_| error)?;
    }
    if let Some(revisions) = revisions {
        if revisions.contains_key(&value.revision_id) {
            return Err(error);
        }
        revisions.insert(value.revision_id, (value.clone(), seq));
    }
    current.insert(value.run_id, (value, seq));
    Ok(())
}

fn allowed_run_shape(value: &ExperimentRun) -> bool {
    value.is_declaration_only()
        || value.is_controlled_declaration()
        || value.comparison_execution_binding.is_some()
            && value.observability == RunObservability::Full
            && value.execution_status == RunExecutionStatus::Completed
            && value.contract_validity == RunContractValidity::Valid
}

pub(crate) fn record_result(
    current: &mut BTreeMap<ResultEvidenceId, (ResultEvidence, u64)>,
    revisions: Option<&mut BTreeMap<RevisionId, (ResultEvidence, u64)>>,
    value: ResultEvidence,
    seq: u64,
    error: StoreError,
) -> Result<(), StoreError> {
    if let Some((existing, _)) = current.get(&value.result_evidence_id) {
        if existing == &value {
            return Ok(());
        }
        existing.validate_successor(&value).map_err(|_| error)?;
    } else if value.parent_revision_id.is_some() {
        return Err(error);
    } else {
        value.validate().map_err(|_| error)?;
    }
    if let Some(revisions) = revisions {
        if revisions.contains_key(&value.revision_id) {
            return Err(error);
        }
        revisions.insert(value.revision_id, (value.clone(), seq));
    }
    current.insert(value.result_evidence_id, (value, seq));
    Ok(())
}

pub(crate) fn record_artifact(
    current: &mut BTreeMap<WorkArtifactId, (WorkArtifact, u64)>,
    revisions: Option<&mut BTreeMap<RevisionId, (WorkArtifact, u64)>>,
    value: WorkArtifact,
    seq: u64,
    error: StoreError,
) -> Result<(), StoreError> {
    if let Some((existing, _)) = current.get(&value.work_artifact_id) {
        if existing == &value {
            return Ok(());
        }
        existing.validate_successor(&value).map_err(|_| error)?;
    } else if value.revision.parent_revision_id.is_some() {
        return Err(error);
    } else {
        value.validate().map_err(|_| error)?;
    }
    if let Some(revisions) = revisions {
        if revisions.contains_key(&value.revision.revision_id) {
            return Err(error);
        }
        revisions.insert(value.revision.revision_id, (value.clone(), seq));
    }
    current.insert(value.work_artifact_id, (value, seq));
    Ok(())
}
