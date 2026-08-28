use std::collections::BTreeSet;

use evertrace_domain::evidence::{HostOccurrence, Operation, ScopeEffect};
use evertrace_domain::repository::{
    IntegrationEvent, RepositoryInstance, WorktreeInstance, WorktreeSnapshot, WorktreeTransition,
};
use evertrace_domain::work::{
    AssignmentStatus, Attempt, AttemptAdoptionStatus, AttemptVerification, CaptureReceipt,
    CompetingAttemptGroup, CompetingResolutionStatus, ExecutionLane, OperationBurst,
    SecondaryBindingTarget, SegmentationCorrection, Task, TaskIdentityConfidence,
    WorkBindingRevision, WorkCheckpoint, WorkEpisode, Workstream,
};
use serde::{Deserialize, Serialize};

use crate::StoreError;

mod segmentation;
pub use segmentation::*;
mod recovery;
pub use recovery::*;
mod autoresearch;
pub use autoresearch::*;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalRelationKind {
    SourceObservationToHostOccurrence,
    HostOccurrenceToOperation,
    OperationToScopeEffect,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AttemptRelationKind {
    AttemptToTask,
    AttemptToWorkstream,
    AttemptToEpisode,
    AttemptToExecutionLane,
    AttemptToBindingRevision,
    AttemptToIntegrationEvidence,
    AttemptToOutcomeEvidence,
    AttemptToVerifierEvidence,
    AttemptResumesFromHistorical,
    AttemptComposedFromHistorical,
    GroupToCandidateMember,
    GroupToComparisonSnapshot,
    GroupToSelectedAttempt,
    GroupToPartiallyIntegratedAttempt,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AttemptRelationRow {
    pub kind: AttemptRelationKind,
    pub source_id: String,
    pub target_id: String,
}

pub fn build_attempt_relation_rows(
    attempts: &[Attempt],
    groups: &[CompetingAttemptGroup],
) -> Result<Vec<AttemptRelationRow>, StoreError> {
    let by_id = attempts
        .iter()
        .map(|attempt| (attempt.attempt_id, attempt))
        .collect::<std::collections::BTreeMap<_, _>>();
    let group_ids = groups
        .iter()
        .map(|group| group.competing_group_id)
        .collect::<BTreeSet<_>>();
    if by_id.len() != attempts.len() || group_ids.len() != groups.len() {
        return Err(StoreError::InvalidInput);
    }
    fn composition_cycle(
        id: evertrace_domain::ids::AttemptId,
        attempts: &std::collections::BTreeMap<evertrace_domain::ids::AttemptId, &Attempt>,
        visiting: &mut BTreeSet<evertrace_domain::ids::AttemptId>,
        visited: &mut BTreeSet<evertrace_domain::ids::AttemptId>,
    ) -> bool {
        if visited.contains(&id) {
            return false;
        }
        if !visiting.insert(id) {
            return true;
        }
        let cyclic = attempts.get(&id).is_some_and(|attempt| {
            attempt
                .composed_from_attempt_ids
                .iter()
                .any(|source| composition_cycle(*source, attempts, visiting, visited))
        });
        visiting.remove(&id);
        visited.insert(id);
        cyclic
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    if by_id
        .keys()
        .copied()
        .any(|id| composition_cycle(id, &by_id, &mut visiting, &mut visited))
    {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for attempt in attempts {
        attempt.validate().map_err(|_| StoreError::InvalidInput)?;
        for source_id in attempt
            .composed_from_attempt_ids
            .iter()
            .chain(attempt.resumes_from_attempt_id.iter())
        {
            let source = by_id.get(source_id).ok_or(StoreError::InvalidInput)?;
            if source.task_id != attempt.task_id
                || (attempt.composed_from_attempt_ids.contains(source_id)
                    && source.strategy_contract_fingerprint
                        == attempt.strategy_contract_fingerprint)
            {
                return Err(StoreError::InvalidInput);
            }
        }
        for group_id in &attempt.competing_group_ids {
            let group = groups
                .iter()
                .find(|group| group.competing_group_id == *group_id)
                .ok_or(StoreError::InvalidInput)?;
            if !group.member_attempt_ids.contains(&attempt.attempt_id) {
                return Err(StoreError::InvalidInput);
            }
        }
        let source = attempt.attempt_id.to_string();
        rows.insert(AttemptRelationRow {
            kind: AttemptRelationKind::AttemptToTask,
            source_id: source.clone(),
            target_id: attempt.task_id.to_string(),
        });
        rows.insert(AttemptRelationRow {
            kind: AttemptRelationKind::AttemptToWorkstream,
            source_id: source.clone(),
            target_id: attempt.workstream_id.to_string(),
        });
        if let Some(id) = attempt.episode_id {
            rows.insert(AttemptRelationRow {
                kind: AttemptRelationKind::AttemptToEpisode,
                source_id: source.clone(),
                target_id: id.to_string(),
            });
        }
        for id in &attempt.execution_lane_ids {
            rows.insert(AttemptRelationRow {
                kind: AttemptRelationKind::AttemptToExecutionLane,
                source_id: source.clone(),
                target_id: id.to_string(),
            });
        }
        for id in &attempt.work_binding_revision_refs {
            rows.insert(AttemptRelationRow {
                kind: AttemptRelationKind::AttemptToBindingRevision,
                source_id: source.clone(),
                target_id: id.to_string(),
            });
        }
        for id in &attempt.integration_event_refs {
            rows.insert(AttemptRelationRow {
                kind: AttemptRelationKind::AttemptToIntegrationEvidence,
                source_id: source.clone(),
                target_id: id.to_string(),
            });
        }
        for id in &attempt.outcome_refs {
            rows.insert(AttemptRelationRow {
                kind: AttemptRelationKind::AttemptToOutcomeEvidence,
                source_id: source.clone(),
                target_id: id.clone(),
            });
        }
        for id in &attempt.parent_verification_refs {
            rows.insert(AttemptRelationRow {
                kind: AttemptRelationKind::AttemptToVerifierEvidence,
                source_id: source.clone(),
                target_id: id.clone(),
            });
        }
        if let Some(id) = attempt.resumes_from_attempt_id {
            rows.insert(AttemptRelationRow {
                kind: AttemptRelationKind::AttemptResumesFromHistorical,
                source_id: source.clone(),
                target_id: id.to_string(),
            });
        }
        for id in &attempt.composed_from_attempt_ids {
            rows.insert(AttemptRelationRow {
                kind: AttemptRelationKind::AttemptComposedFromHistorical,
                source_id: source.clone(),
                target_id: id.to_string(),
            });
        }
    }
    for group in groups {
        group.validate().map_err(|_| StoreError::InvalidInput)?;
        let source = group.competing_group_id.to_string();
        for id in &group.member_attempt_ids {
            let attempt = by_id.get(id).ok_or(StoreError::InvalidInput)?;
            if attempt.task_id != group.task_id
                || !group.member_workstream_ids.contains(&attempt.workstream_id)
                || !attempt
                    .competing_group_ids
                    .contains(&group.competing_group_id)
            {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(AttemptRelationRow {
                kind: AttemptRelationKind::GroupToCandidateMember,
                source_id: source.clone(),
                target_id: id.to_string(),
            });
        }
        for snapshot in &group.candidate_snapshot_refs {
            rows.insert(AttemptRelationRow {
                kind: AttemptRelationKind::GroupToComparisonSnapshot,
                source_id: source.clone(),
                target_id: snapshot.snapshot_id.to_string(),
            });
        }
        if group.resolution_status == CompetingResolutionStatus::Selected {
            let id = group.selected_attempt_id.ok_or(StoreError::InvalidInput)?;
            let selected = by_id.get(&id).ok_or(StoreError::InvalidInput)?;
            if selected.adoption_status != AttemptAdoptionStatus::Integrated
                || selected.verification != AttemptVerification::Passed
                || !selected
                    .parent_verification_refs
                    .iter()
                    .any(|evidence| group.resolution_evidence_refs.contains(evidence))
            {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(AttemptRelationRow {
                kind: AttemptRelationKind::GroupToSelectedAttempt,
                source_id: source.clone(),
                target_id: id.to_string(),
            });
        }
        if group.resolution_status == CompetingResolutionStatus::PartiallyIntegrated {
            for id in &group.partially_integrated_attempt_ids {
                let attempt = by_id.get(id).ok_or(StoreError::InvalidInput)?;
                if !matches!(
                    attempt.adoption_status,
                    AttemptAdoptionStatus::PartiallyIntegrated | AttemptAdoptionStatus::Integrated
                ) {
                    return Err(StoreError::InvalidInput);
                }
                rows.insert(AttemptRelationRow {
                    kind: AttemptRelationKind::GroupToPartiallyIntegratedAttempt,
                    source_id: source.clone(),
                    target_id: id.to_string(),
                });
            }
        }
    }
    Ok(rows.into_iter().collect())
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalRelationRow {
    pub kind: PhysicalRelationKind,
    pub source_id: String,
    pub target_id: String,
}

pub fn build_physical_relation_rows(
    occurrences: &[HostOccurrence],
    operations: &[Operation],
    scope_effects: &[ScopeEffect],
) -> Result<Vec<PhysicalRelationRow>, StoreError> {
    let occurrence_ids = occurrences
        .iter()
        .map(|value| value.host_occurrence_id)
        .collect::<BTreeSet<_>>();
    let operation_ids = operations
        .iter()
        .map(|value| value.operation_id)
        .collect::<BTreeSet<_>>();
    if occurrence_ids.len() != occurrences.len() || operation_ids.len() != operations.len() {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for occurrence in occurrences {
        occurrence
            .validate()
            .map_err(|_| StoreError::InvalidInput)?;
        for observation in &occurrence.source_observation_refs {
            rows.insert(PhysicalRelationRow {
                kind: PhysicalRelationKind::SourceObservationToHostOccurrence,
                source_id: observation.to_string(),
                target_id: occurrence.host_occurrence_id.to_string(),
            });
        }
    }
    for operation in operations {
        operation.validate().map_err(|_| StoreError::InvalidInput)?;
        if !occurrence_ids.contains(&operation.host_occurrence_id) {
            return Err(StoreError::InvalidInput);
        }
        rows.insert(PhysicalRelationRow {
            kind: PhysicalRelationKind::HostOccurrenceToOperation,
            source_id: operation.host_occurrence_id.to_string(),
            target_id: operation.operation_id.to_string(),
        });
    }
    for effect in scope_effects {
        effect.validate().map_err(|_| StoreError::InvalidInput)?;
        if !operation_ids.contains(&effect.operation_id) {
            return Err(StoreError::InvalidInput);
        }
        rows.insert(PhysicalRelationRow {
            kind: PhysicalRelationKind::OperationToScopeEffect,
            source_id: effect.operation_id.to_string(),
            target_id: effect.scope_effect_id.to_string(),
        });
    }
    Ok(rows.into_iter().collect())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WorkBindingRelationKind {
    OperationToBindingRevision,
    BindingToScopeEffect,
    BindingToPrimaryTask,
    BindingToPrimaryWorkstream,
    BindingToPrimaryEpisode,
    BindingToCandidateTask,
    BindingToCandidateWorkstream,
    BindingToSecondaryTarget,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorkBindingRelationRow {
    pub kind: WorkBindingRelationKind,
    pub source_id: String,
    pub target_id: String,
}

pub fn build_work_binding_relation_rows(
    bindings: &[WorkBindingRevision],
    operations: &[Operation],
    scope_effects: &[ScopeEffect],
    tasks: &[Task],
    workstreams: &[Workstream],
) -> Result<Vec<WorkBindingRelationRow>, StoreError> {
    let operation_by_id = operations
        .iter()
        .map(|value| (value.operation_id, value))
        .collect::<std::collections::BTreeMap<_, _>>();
    let effects = scope_effects
        .iter()
        .map(|value| (value.scope_effect_id, value))
        .collect::<std::collections::BTreeMap<_, _>>();
    let tasks_by_id = tasks
        .iter()
        .map(|value| (value.task_id, value))
        .collect::<std::collections::BTreeMap<_, _>>();
    let streams = workstreams
        .iter()
        .map(|value| (value.workstream_id, value))
        .collect::<std::collections::BTreeMap<_, _>>();
    if operation_by_id.len() != operations.len()
        || effects.len() != scope_effects.len()
        || tasks_by_id.len() != tasks.len()
        || streams.len() != workstreams.len()
    {
        return Err(StoreError::InvalidInput);
    }
    for task in tasks {
        task.validate().map_err(|_| StoreError::InvalidInput)?;
    }
    for workstream in workstreams {
        workstream
            .validate()
            .map_err(|_| StoreError::InvalidInput)?;
    }
    let mut rows = BTreeSet::new();
    for binding in bindings {
        binding.validate().map_err(|_| StoreError::InvalidInput)?;
        let operation = operation_by_id
            .get(&binding.operation_id)
            .ok_or(StoreError::InvalidInput)?;
        let source = binding.work_binding_revision_id.to_string();
        rows.insert(WorkBindingRelationRow {
            kind: WorkBindingRelationKind::OperationToBindingRevision,
            source_id: binding.operation_id.to_string(),
            target_id: source.clone(),
        });
        for effect_id in &binding.scope_effect_refs {
            if effects.get(effect_id).is_none_or(|effect| {
                effect.operation_id != binding.operation_id
                    || !operation.scope_effect_ids.contains(effect_id)
            }) {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(WorkBindingRelationRow {
                kind: WorkBindingRelationKind::BindingToScopeEffect,
                source_id: source.clone(),
                target_id: effect_id.to_string(),
            });
        }
        match (
            binding.primary_binding.task_id,
            binding.primary_binding.workstream_id,
        ) {
            (Some(task_id), Some(workstream_id)) => {
                let task = tasks_by_id.get(&task_id).ok_or(StoreError::InvalidInput)?;
                let workstream = streams
                    .get(&workstream_id)
                    .ok_or(StoreError::InvalidInput)?;
                if workstream.task_id != task_id {
                    return Err(StoreError::InvalidInput);
                }
                for effect_id in &binding.scope_effect_refs {
                    let effect = effects[effect_id];
                    if effect.repository_instance_id.is_some_and(|repository_id| {
                        workstream.repository_instance_id != Some(repository_id)
                            || !task.scope_memberships.iter().any(|membership| {
                                membership.repository_instance_id == Some(repository_id)
                                    && effect.worktree_instance_id.is_none_or(|worktree_id| {
                                        membership.worktree_instance_ids.contains(&worktree_id)
                                    })
                            })
                    }) || effect.worktree_instance_id.is_some_and(|worktree_id| {
                        !workstream.worktree_instance_ids.contains(&worktree_id)
                    }) {
                        return Err(StoreError::InvalidInput);
                    }
                }
                let (task_kind, stream_kind) = match binding.assignment_status {
                    AssignmentStatus::Resolved
                        if task.identity_confidence != TaskIdentityConfidence::Provisional =>
                    {
                        (
                            WorkBindingRelationKind::BindingToPrimaryTask,
                            WorkBindingRelationKind::BindingToPrimaryWorkstream,
                        )
                    }
                    AssignmentStatus::Provisional => (
                        WorkBindingRelationKind::BindingToCandidateTask,
                        WorkBindingRelationKind::BindingToCandidateWorkstream,
                    ),
                    _ => return Err(StoreError::InvalidInput),
                };
                rows.insert(WorkBindingRelationRow {
                    kind: task_kind,
                    source_id: source.clone(),
                    target_id: task_id.to_string(),
                });
                if let Some(episode_id) = binding.primary_binding.episode_id {
                    if binding.assignment_status != AssignmentStatus::Resolved {
                        return Err(StoreError::InvalidInput);
                    }
                    rows.insert(WorkBindingRelationRow {
                        kind: WorkBindingRelationKind::BindingToPrimaryEpisode,
                        source_id: source.clone(),
                        target_id: episode_id.to_string(),
                    });
                }
                rows.insert(WorkBindingRelationRow {
                    kind: stream_kind,
                    source_id: source.clone(),
                    target_id: workstream_id.to_string(),
                });
            }
            (None, None)
                if matches!(
                    binding.assignment_status,
                    AssignmentStatus::Provisional
                        | AssignmentStatus::Conflicted
                        | AssignmentStatus::Unresolved
                ) => {}
            _ => return Err(StoreError::InvalidInput),
        }
        for secondary in &binding.secondary_bindings {
            let target_id = match secondary.target_ref {
                SecondaryBindingTarget::Task(id) => id.to_string(),
                SecondaryBindingTarget::Workstream(id) => id.to_string(),
                SecondaryBindingTarget::Episode(id) => id.to_string(),
                SecondaryBindingTarget::Attempt(id) => id.to_string(),
                SecondaryBindingTarget::ExperimentRun(id) => id.to_string(),
                SecondaryBindingTarget::CompetingGroup(id) => id.to_string(),
                SecondaryBindingTarget::Artifact(id) => id.to_string(),
            };
            rows.insert(WorkBindingRelationRow {
                kind: WorkBindingRelationKind::BindingToSecondaryTarget,
                source_id: source.clone(),
                target_id,
            });
        }
    }
    Ok(rows.into_iter().collect())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EpisodeRelationKind {
    EpisodeToTask,
    EpisodeToWorkstream,
    EpisodeToAttempt,
    EpisodeToExecutionLane,
    EpisodeToCheckpoint,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EpisodeRelationRow {
    pub kind: EpisodeRelationKind,
    pub source_id: String,
    pub target_id: String,
}

pub fn build_episode_relation_rows(
    episodes: &[WorkEpisode],
    checkpoints: &[WorkCheckpoint],
) -> Result<Vec<EpisodeRelationRow>, StoreError> {
    let episode_ids = episodes
        .iter()
        .map(|value| value.episode_id)
        .collect::<BTreeSet<_>>();
    if episode_ids.len() != episodes.len() {
        return Err(StoreError::InvalidInput);
    }
    let checkpoint_by_key = checkpoints
        .iter()
        .map(|value| (value.stable_key(), value))
        .collect::<std::collections::BTreeMap<_, _>>();
    if checkpoint_by_key.len() != checkpoints.len() {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for episode in episodes {
        episode.validate().map_err(|_| StoreError::InvalidInput)?;
        let source = episode.episode_id.to_string();
        rows.insert(EpisodeRelationRow {
            kind: EpisodeRelationKind::EpisodeToTask,
            source_id: source.clone(),
            target_id: episode.task_id.to_string(),
        });
        rows.insert(EpisodeRelationRow {
            kind: EpisodeRelationKind::EpisodeToWorkstream,
            source_id: source.clone(),
            target_id: episode.workstream_id.to_string(),
        });
        for id in &episode.attempt_ids {
            rows.insert(EpisodeRelationRow {
                kind: EpisodeRelationKind::EpisodeToAttempt,
                source_id: source.clone(),
                target_id: id.to_string(),
            });
        }
        for id in &episode.execution_lane_ids {
            rows.insert(EpisodeRelationRow {
                kind: EpisodeRelationKind::EpisodeToExecutionLane,
                source_id: source.clone(),
                target_id: id.to_string(),
            });
        }
        for key in &episode.checkpoint_refs {
            if checkpoint_by_key
                .get(key)
                .is_none_or(|checkpoint| checkpoint.episode_id != episode.episode_id)
            {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(EpisodeRelationRow {
                kind: EpisodeRelationKind::EpisodeToCheckpoint,
                source_id: source.clone(),
                target_id: key.clone(),
            });
        }
    }
    Ok(rows.into_iter().collect())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CaptureRelationKind {
    ExecutionLaneToCaptureReceipt,
    ExecutionLaneToOperation,
    CaptureReceiptToSourceRevision,
    CaptureReceiptToGapEvidence,
    CaptureReceiptToOutageEvidence,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CaptureRelationRow {
    pub kind: CaptureRelationKind,
    pub source_id: String,
    pub target_id: String,
}

pub fn build_capture_relation_rows(
    lane: &ExecutionLane,
    receipt: &CaptureReceipt,
) -> Result<Vec<CaptureRelationRow>, StoreError> {
    lane.validate().map_err(|_| StoreError::InvalidInput)?;
    receipt.validate().map_err(|_| StoreError::InvalidInput)?;
    if lane.execution_lane_id != receipt.execution_lane_id
        || lane.active_capture_receipt_revision_id != receipt.capture_receipt_revision_id
    {
        return Err(StoreError::InvalidInput);
    }
    let lane_id = lane.execution_lane_id.to_string();
    let receipt_id = receipt.capture_receipt_revision_id.to_string();
    let mut rows = BTreeSet::new();
    rows.insert(CaptureRelationRow {
        kind: CaptureRelationKind::ExecutionLaneToCaptureReceipt,
        source_id: lane_id.clone(),
        target_id: receipt_id.clone(),
    });
    for operation_id in &lane.operation_ids {
        rows.insert(CaptureRelationRow {
            kind: CaptureRelationKind::ExecutionLaneToOperation,
            source_id: lane_id.clone(),
            target_id: operation_id.to_string(),
        });
    }
    for source_ref in &receipt.source_revision_refs {
        rows.insert(CaptureRelationRow {
            kind: CaptureRelationKind::CaptureReceiptToSourceRevision,
            source_id: receipt_id.clone(),
            target_id: source_ref.clone(),
        });
    }
    for marker_ref in &receipt.capture_gap_marker_refs {
        rows.insert(CaptureRelationRow {
            kind: CaptureRelationKind::CaptureReceiptToGapEvidence,
            source_id: receipt_id.clone(),
            target_id: marker_ref.clone(),
        });
    }
    for outage_ref in &receipt.capture_outage_interval_refs {
        rows.insert(CaptureRelationRow {
            kind: CaptureRelationKind::CaptureReceiptToOutageEvidence,
            source_id: receipt_id.clone(),
            target_id: outage_ref.to_string(),
        });
    }
    Ok(rows.into_iter().collect())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryRelationKind {
    RepositoryToWorktree,
    WorktreeToSnapshot,
    WorktreeTransitionFrom,
    WorktreeTransitionTo,
    IntegrationEventSource,
    IntegrationEventDestination,
    RepositoryDerivedFrom,
    WorktreeRecreatedFrom,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRelationRow {
    pub kind: RepositoryRelationKind,
    pub source_id: String,
    pub target_id: String,
}

/// Pure relation DTO builder for S11 repository objects. It only validates
/// and assembles rows over the given slices; the relation table itself is
/// not opened before L0002.
pub fn build_repository_relation_rows(
    repositories: &[RepositoryInstance],
    worktrees: &[WorktreeInstance],
    snapshots: &[WorktreeSnapshot],
    transitions: &[WorktreeTransition],
    integrations: &[IntegrationEvent],
) -> Result<Vec<RepositoryRelationRow>, StoreError> {
    let repository_ids = repositories
        .iter()
        .map(|value| value.repository_id)
        .collect::<BTreeSet<_>>();
    let worktree_ids = worktrees
        .iter()
        .map(|value| value.worktree_instance_id)
        .collect::<BTreeSet<_>>();
    let snapshot_ids = snapshots
        .iter()
        .map(|value| value.worktree_snapshot_id)
        .collect::<BTreeSet<_>>();
    if repository_ids.len() != repositories.len()
        || worktree_ids.len() != worktrees.len()
        || snapshot_ids.len() != snapshots.len()
    {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for repository in repositories {
        repository
            .validate()
            .map_err(|_| StoreError::InvalidInput)?;
        if let Some(derived_from) = repository.derived_from {
            if !repository_ids.contains(&derived_from) {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(RepositoryRelationRow {
                kind: RepositoryRelationKind::RepositoryDerivedFrom,
                source_id: repository.repository_id.to_string(),
                target_id: derived_from.to_string(),
            });
        }
    }
    for worktree in worktrees {
        worktree.validate().map_err(|_| StoreError::InvalidInput)?;
        if !repository_ids.contains(&worktree.repository_instance_id) {
            return Err(StoreError::InvalidInput);
        }
        rows.insert(RepositoryRelationRow {
            kind: RepositoryRelationKind::RepositoryToWorktree,
            source_id: worktree.repository_instance_id.to_string(),
            target_id: worktree.worktree_instance_id.to_string(),
        });
        if let Some(recreated_from) = worktree.recreated_from_worktree_instance_id {
            if !worktree_ids.contains(&recreated_from) {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(RepositoryRelationRow {
                kind: RepositoryRelationKind::WorktreeRecreatedFrom,
                source_id: worktree.worktree_instance_id.to_string(),
                target_id: recreated_from.to_string(),
            });
        }
    }
    for snapshot in snapshots {
        snapshot.validate().map_err(|_| StoreError::InvalidInput)?;
        if !worktree_ids.contains(&snapshot.worktree_instance_id) {
            return Err(StoreError::InvalidInput);
        }
        rows.insert(RepositoryRelationRow {
            kind: RepositoryRelationKind::WorktreeToSnapshot,
            source_id: snapshot.worktree_instance_id.to_string(),
            target_id: snapshot.worktree_snapshot_id.to_string(),
        });
    }
    for transition in transitions {
        transition
            .validate()
            .map_err(|_| StoreError::InvalidInput)?;
        if !worktree_ids.contains(&transition.from_worktree_instance_id)
            || !worktree_ids.contains(&transition.to_worktree_instance_id)
        {
            return Err(StoreError::InvalidInput);
        }
        rows.insert(RepositoryRelationRow {
            kind: RepositoryRelationKind::WorktreeTransitionFrom,
            source_id: transition.worktree_transition_id.to_string(),
            target_id: transition.from_worktree_instance_id.to_string(),
        });
        rows.insert(RepositoryRelationRow {
            kind: RepositoryRelationKind::WorktreeTransitionTo,
            source_id: transition.worktree_transition_id.to_string(),
            target_id: transition.to_worktree_instance_id.to_string(),
        });
    }
    for integration in integrations {
        integration
            .validate()
            .map_err(|_| StoreError::InvalidInput)?;
        if !repository_ids.contains(&integration.repository_instance_id)
            || !worktree_ids.contains(&integration.source_worktree_instance_id)
            || !worktree_ids.contains(&integration.destination_worktree_instance_id)
            || !snapshot_ids.contains(&integration.source_snapshot_id)
            || !snapshot_ids.contains(&integration.destination_snapshot_id)
        {
            return Err(StoreError::InvalidInput);
        }
        rows.insert(RepositoryRelationRow {
            kind: RepositoryRelationKind::IntegrationEventSource,
            source_id: integration.integration_event_id.to_string(),
            target_id: integration.source_worktree_instance_id.to_string(),
        });
        rows.insert(RepositoryRelationRow {
            kind: RepositoryRelationKind::IntegrationEventDestination,
            source_id: integration.integration_event_id.to_string(),
            target_id: integration.destination_worktree_instance_id.to_string(),
        });
    }
    Ok(rows.into_iter().collect())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkIdentityRelationKind {
    TaskContinues,
    TaskSplitFrom,
    TaskSplitInto,
    TaskMergedFrom,
    TaskMergedInto,
    TaskContainsWorkstream,
    WorkstreamParent,
    WorkstreamDependency,
    WorkstreamRepository,
    WorkstreamWorktree,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkIdentityRelationRow {
    pub kind: WorkIdentityRelationKind,
    pub source_id: String,
    pub target_id: String,
}

pub fn build_work_identity_relation_rows(
    tasks: &[Task],
    workstreams: &[Workstream],
) -> Result<Vec<WorkIdentityRelationRow>, StoreError> {
    let task_ids = tasks
        .iter()
        .map(|task| task.task_id)
        .collect::<BTreeSet<_>>();
    let workstream_ids = workstreams
        .iter()
        .map(|workstream| workstream.workstream_id)
        .collect::<BTreeSet<_>>();
    if task_ids.len() != tasks.len() || workstream_ids.len() != workstreams.len() {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for task in tasks {
        task.validate().map_err(|_| StoreError::InvalidInput)?;
        for (kind, target) in task
            .continuation_of_task_id
            .iter()
            .map(|id| (WorkIdentityRelationKind::TaskContinues, id))
            .chain(
                task.split_from_task_id
                    .iter()
                    .map(|id| (WorkIdentityRelationKind::TaskSplitFrom, id)),
            )
            .chain(
                task.split_into_task_ids
                    .iter()
                    .map(|id| (WorkIdentityRelationKind::TaskSplitInto, id)),
            )
            .chain(
                task.merged_from_task_ids
                    .iter()
                    .map(|id| (WorkIdentityRelationKind::TaskMergedFrom, id)),
            )
            .chain(
                task.merged_into_task_id
                    .iter()
                    .map(|id| (WorkIdentityRelationKind::TaskMergedInto, id)),
            )
        {
            if !task_ids.contains(target) {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(WorkIdentityRelationRow {
                kind,
                source_id: task.task_id.to_string(),
                target_id: target.to_string(),
            });
        }
    }
    for workstream in workstreams {
        workstream
            .validate()
            .map_err(|_| StoreError::InvalidInput)?;
        let task = tasks
            .iter()
            .find(|task| task.task_id == workstream.task_id)
            .ok_or(StoreError::InvalidInput)?;
        if let Some(repository_id) = workstream.repository_instance_id {
            let membership = task
                .scope_memberships
                .iter()
                .find(|membership| membership.repository_instance_id == Some(repository_id))
                .ok_or(StoreError::InvalidInput)?;
            if workstream
                .worktree_instance_ids
                .iter()
                .any(|id| !membership.worktree_instance_ids.contains(id))
            {
                return Err(StoreError::InvalidInput);
            }
        }
        rows.insert(WorkIdentityRelationRow {
            kind: WorkIdentityRelationKind::TaskContainsWorkstream,
            source_id: workstream.task_id.to_string(),
            target_id: workstream.workstream_id.to_string(),
        });
        if let Some(parent) = workstream.parent_workstream_id {
            if !workstream_ids.contains(&parent) {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(WorkIdentityRelationRow {
                kind: WorkIdentityRelationKind::WorkstreamParent,
                source_id: workstream.workstream_id.to_string(),
                target_id: parent.to_string(),
            });
        }
        for dependency in &workstream.dependency_workstream_ids {
            if !workstream_ids.contains(dependency) {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(WorkIdentityRelationRow {
                kind: WorkIdentityRelationKind::WorkstreamDependency,
                source_id: workstream.workstream_id.to_string(),
                target_id: dependency.to_string(),
            });
        }
        if let Some(repository) = workstream.repository_instance_id {
            rows.insert(WorkIdentityRelationRow {
                kind: WorkIdentityRelationKind::WorkstreamRepository,
                source_id: workstream.workstream_id.to_string(),
                target_id: repository.to_string(),
            });
        }
        for worktree in &workstream.worktree_instance_ids {
            rows.insert(WorkIdentityRelationRow {
                kind: WorkIdentityRelationKind::WorkstreamWorktree,
                source_id: workstream.workstream_id.to_string(),
                target_id: worktree.to_string(),
            });
        }
    }
    Ok(rows.into_iter().collect())
}
