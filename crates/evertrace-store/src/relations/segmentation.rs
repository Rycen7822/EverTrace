use super::*;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperationBurstRelationKind {
    EpisodeToBurst,
    BurstToOperation,
    BurstToHostOccurrence,
    BurstToSourceObservation,
    BurstToScopeEffect,
    BurstToBindingRevision,
    BurstToExecutionLane,
    BurstToAttempt,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OperationBurstRelationRow {
    pub kind: OperationBurstRelationKind,
    pub source_id: String,
    pub target_id: String,
}

pub fn build_operation_burst_relation_rows(
    episodes: &[WorkEpisode],
    bursts: &[OperationBurst],
) -> Result<Vec<OperationBurstRelationRow>, StoreError> {
    let burst_by_id = bursts
        .iter()
        .map(|value| (value.operation_burst_id, value))
        .collect::<std::collections::BTreeMap<_, _>>();
    if burst_by_id.len() != bursts.len() {
        return Err(StoreError::InvalidInput);
    }
    let mut referenced = BTreeSet::new();
    let mut rows = BTreeSet::new();
    for episode in episodes {
        episode.validate().map_err(|_| StoreError::InvalidInput)?;
        for id in &episode.operation_burst_refs {
            let burst = burst_by_id.get(id).ok_or(StoreError::InvalidInput)?;
            if !episode
                .execution_lane_ids
                .contains(&burst.execution_lane_id)
            {
                return Err(StoreError::InvalidInput);
            }
            if !referenced.insert(*id) {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(OperationBurstRelationRow {
                kind: OperationBurstRelationKind::EpisodeToBurst,
                source_id: episode.episode_id.to_string(),
                target_id: id.to_string(),
            });
        }
    }
    if referenced.len() != bursts.len() {
        return Err(StoreError::InvalidInput);
    }
    for burst in bursts {
        burst.validate().map_err(|_| StoreError::InvalidInput)?;
        let source = burst.operation_burst_id.to_string();
        for (kind, targets) in [
            (
                OperationBurstRelationKind::BurstToOperation,
                burst
                    .members
                    .iter()
                    .map(|member| member.operation_id.to_string())
                    .collect::<Vec<_>>(),
            ),
            (
                OperationBurstRelationKind::BurstToHostOccurrence,
                burst
                    .members
                    .iter()
                    .map(|member| member.host_occurrence_id.to_string())
                    .collect::<Vec<_>>(),
            ),
            (
                OperationBurstRelationKind::BurstToSourceObservation,
                burst
                    .members
                    .iter()
                    .flat_map(|member| member.source_observation_refs.iter())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
            (
                OperationBurstRelationKind::BurstToScopeEffect,
                burst
                    .members
                    .iter()
                    .flat_map(|member| member.scope_effect_refs.iter())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
            (
                OperationBurstRelationKind::BurstToBindingRevision,
                burst
                    .members
                    .iter()
                    .map(|member| member.work_binding_revision_id.to_string())
                    .collect::<Vec<_>>(),
            ),
        ] {
            for target_id in targets {
                rows.insert(OperationBurstRelationRow {
                    kind,
                    source_id: source.clone(),
                    target_id,
                });
            }
        }
        rows.insert(OperationBurstRelationRow {
            kind: OperationBurstRelationKind::BurstToExecutionLane,
            source_id: source.clone(),
            target_id: burst.execution_lane_id.to_string(),
        });
        if let Some(attempt_id) = burst.attempt_id {
            rows.insert(OperationBurstRelationRow {
                kind: OperationBurstRelationKind::BurstToAttempt,
                source_id: source,
                target_id: attempt_id.to_string(),
            });
        }
    }
    Ok(rows.into_iter().collect())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SegmentationCorrectionRelationKind {
    CorrectionFromEpisode,
    CorrectionToEpisode,
    CorrectionSuccessor,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SegmentationCorrectionRelationRow {
    pub kind: SegmentationCorrectionRelationKind,
    pub source_id: String,
    pub target_id: String,
}

pub fn build_segmentation_correction_relation_rows(
    corrections: &[SegmentationCorrection],
    episodes: &[WorkEpisode],
) -> Result<Vec<SegmentationCorrectionRelationRow>, StoreError> {
    let episode_ids = episodes
        .iter()
        .map(|episode| episode.episode_id)
        .collect::<BTreeSet<_>>();
    let correction_ids = corrections
        .iter()
        .map(|value| value.correction_revision_id)
        .collect::<BTreeSet<_>>();
    if episode_ids.len() != episodes.len() || correction_ids.len() != corrections.len() {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for correction in corrections {
        correction
            .validate()
            .map_err(|_| StoreError::InvalidInput)?;
        let source = correction.correction_revision_id.to_string();
        for episode_id in &correction.source_episode_ids {
            if !episode_ids.contains(episode_id) {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(SegmentationCorrectionRelationRow {
                kind: SegmentationCorrectionRelationKind::CorrectionFromEpisode,
                source_id: source.clone(),
                target_id: episode_id.to_string(),
            });
        }
        for episode_id in &correction.replacement_episode_ids {
            if !episode_ids.contains(episode_id) {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(SegmentationCorrectionRelationRow {
                kind: SegmentationCorrectionRelationKind::CorrectionToEpisode,
                source_id: source.clone(),
                target_id: episode_id.to_string(),
            });
        }
        if let Some(predecessor) = correction.predecessor_revision_id {
            if !correction_ids.contains(&predecessor) {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(SegmentationCorrectionRelationRow {
                kind: SegmentationCorrectionRelationKind::CorrectionSuccessor,
                source_id: source,
                target_id: predecessor.to_string(),
            });
        }
    }
    Ok(rows.into_iter().collect())
}
