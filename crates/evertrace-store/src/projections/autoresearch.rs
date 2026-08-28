use std::collections::BTreeMap;

use evertrace_domain::{
    evidence::{Operation, SourceObservation, SourceReceipt, hex},
    ids::{
        AttemptId, ExperimentRunId, OperationId, ResultEvidenceId, SourceObservationId,
        SourceReceiptId, TaskId, WorkArtifactId, WorkEpisodeId, WorkstreamId, WorktreeSnapshotId,
    },
    repository::{RepositoryInstance, WorktreeInstance, WorktreeSnapshot},
    revision::RevisionId,
    semantic::ResultEvidence,
    work::{
        ArtifactActor, ArtifactScope, Attempt, AttemptBindingStatus, ExperimentRun,
        RunContractValidity, RunExecutionStatus, RunObservability, Task, WorkArtifact, WorkEpisode,
        Workstream,
    },
};

use crate::{command::StoreError, projections::ProjectionSnapshot};

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
    if !current.is_declaration_only() {
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
        if !next.is_declaration_only() {
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
    if !value.is_declaration_only() {
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
