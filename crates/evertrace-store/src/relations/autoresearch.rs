//! Pure S17 relation DTOs; these are builders, not a production relation table.

use std::collections::BTreeSet;

use evertrace_domain::{
    semantic::ResultEvidence,
    work::{ArtifactActor, ExperimentRun, WorkArtifact},
};
use serde::{Deserialize, Serialize};

use crate::StoreError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoresearchRelationKind {
    RunToWorkstream,
    RunToAttempt,
    RunToArtifact,
    ResultProducedByRun,
    ResultToRawArtifact,
    ArtifactProducedByOperation,
    ArtifactProducedByRun,
    ArtifactProducedByEpisode,
    ArtifactConsumedByOperation,
    ArtifactConsumedByRun,
    ArtifactConsumedByEpisode,
    ArtifactRevisionSuccessor,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutoresearchRelationRow {
    pub kind: AutoresearchRelationKind,
    pub source_id: String,
    pub target_id: String,
}

pub fn build_autoresearch_relation_rows(
    runs: &[ExperimentRun],
    results: &[ResultEvidence],
    artifacts: &[WorkArtifact],
) -> Result<Vec<AutoresearchRelationRow>, StoreError> {
    let run_ids = runs
        .iter()
        .map(|value| value.run_id)
        .collect::<BTreeSet<_>>();
    let artifact_ids = artifacts
        .iter()
        .map(|value| value.work_artifact_id)
        .collect::<BTreeSet<_>>();
    let result_ids = results
        .iter()
        .map(|value| value.result_evidence_id)
        .collect::<BTreeSet<_>>();
    if run_ids.len() != runs.len()
        || result_ids.len() != results.len()
        || artifact_ids.len() != artifacts.len()
    {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for run in runs {
        run.validate().map_err(|_| StoreError::InvalidInput)?;
        add(
            &mut rows,
            AutoresearchRelationKind::RunToWorkstream,
            run.run_id.to_string(),
            run.workstream_id.to_string(),
        );
        if let Some(attempt_id) = run.attempt_id {
            add(
                &mut rows,
                AutoresearchRelationKind::RunToAttempt,
                run.run_id.to_string(),
                attempt_id.to_string(),
            );
        }
        for artifact_id in &run.work_artifact_refs {
            if !artifact_ids.contains(artifact_id) {
                return Err(StoreError::InvalidInput);
            }
            add(
                &mut rows,
                AutoresearchRelationKind::RunToArtifact,
                run.run_id.to_string(),
                artifact_id.to_string(),
            );
        }
    }
    for result in results {
        result.validate().map_err(|_| StoreError::InvalidInput)?;
        if !run_ids.contains(&result.experiment_run_id)
            || result
                .raw_artifact_refs
                .iter()
                .any(|id| !artifact_ids.contains(id))
        {
            return Err(StoreError::InvalidInput);
        }
        add(
            &mut rows,
            AutoresearchRelationKind::ResultProducedByRun,
            result.result_evidence_id.to_string(),
            result.experiment_run_id.to_string(),
        );
        for artifact_id in &result.raw_artifact_refs {
            add(
                &mut rows,
                AutoresearchRelationKind::ResultToRawArtifact,
                result.result_evidence_id.to_string(),
                artifact_id.to_string(),
            );
        }
    }
    for artifact in artifacts {
        artifact.validate().map_err(|_| StoreError::InvalidInput)?;
        if let Some(parent) = artifact.revision.parent_revision_id {
            add(
                &mut rows,
                AutoresearchRelationKind::ArtifactRevisionSuccessor,
                artifact.revision.revision_id.to_string(),
                parent.to_string(),
            );
        }
        for producer in &artifact.revision.produced_by_refs {
            let (kind, target) = match producer {
                ArtifactActor::Operation(id) => (
                    AutoresearchRelationKind::ArtifactProducedByOperation,
                    id.to_string(),
                ),
                ArtifactActor::ExperimentRun(id) => {
                    if !run_ids.contains(id) {
                        return Err(StoreError::InvalidInput);
                    }
                    (
                        AutoresearchRelationKind::ArtifactProducedByRun,
                        id.to_string(),
                    )
                }
                ArtifactActor::WorkEpisode(id) => (
                    AutoresearchRelationKind::ArtifactProducedByEpisode,
                    id.to_string(),
                ),
            };
            add(
                &mut rows,
                kind,
                artifact.work_artifact_id.to_string(),
                target,
            );
        }
        for consumer in &artifact.revision.consumed_by_refs {
            let (kind, target) = match consumer {
                ArtifactActor::Operation(id) => (
                    AutoresearchRelationKind::ArtifactConsumedByOperation,
                    id.to_string(),
                ),
                ArtifactActor::ExperimentRun(id) => {
                    if !run_ids.contains(id) {
                        return Err(StoreError::InvalidInput);
                    }
                    (
                        AutoresearchRelationKind::ArtifactConsumedByRun,
                        id.to_string(),
                    )
                }
                ArtifactActor::WorkEpisode(id) => (
                    AutoresearchRelationKind::ArtifactConsumedByEpisode,
                    id.to_string(),
                ),
            };
            add(
                &mut rows,
                kind,
                artifact.work_artifact_id.to_string(),
                target,
            );
        }
        for run in runs {
            let forward = run.work_artifact_refs.contains(&artifact.work_artifact_id);
            let reverse = artifact
                .revision
                .produced_by_refs
                .contains(&ArtifactActor::ExperimentRun(run.run_id));
            if forward != reverse {
                return Err(StoreError::InvalidInput);
            }
        }
    }
    Ok(rows.into_iter().collect())
}

fn add(
    rows: &mut BTreeSet<AutoresearchRelationRow>,
    kind: AutoresearchRelationKind,
    source_id: String,
    target_id: String,
) {
    rows.insert(AutoresearchRelationRow {
        kind,
        source_id,
        target_id,
    });
}
