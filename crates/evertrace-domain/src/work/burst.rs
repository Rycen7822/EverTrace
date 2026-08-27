use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    evidence::{EffectRole, OperationKind},
    ids::{
        AttemptId, CompetingAttemptGroupId, ExecutionLaneId, ExperimentRunId, HostOccurrenceId,
        IntegrationEventId, OperationBurstId, OperationId, ScopeEffectId, SourceObservationId,
        WorkArtifactId, WorkBindingRevisionId, WorktreeTransitionId,
    },
    revision::RevisionId,
    work::{PhaseKind, PrimaryWorkBinding, WorkError, task::strictly_ordered_unique},
};

const MAX_BURST_MEMBERS: usize = 64;
const MAX_MEMBER_REFS: usize = 64;
const MAX_TEXT: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStateDelta {
    None,
    Observed,
    Modified,
    Verified,
    Failed,
    Recovered,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationVerifierDelta {
    None,
    Started,
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationBurstLifecycle {
    Open,
    Closed,
}

impl OperationBurstLifecycle {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationBurstMember {
    pub sequence: u64,
    pub source_watermark: u64,
    pub operation_id: OperationId,
    pub operation_revision: u32,
    pub host_occurrence_id: HostOccurrenceId,
    pub work_binding_revision_id: WorkBindingRevisionId,
    pub attempt_revision_id: Option<RevisionId>,
    pub source_observation_refs: Vec<SourceObservationId>,
    pub scope_effect_refs: Vec<ScopeEffectId>,
    pub artifact_refs: Vec<WorkArtifactId>,
    pub side_effects: Vec<EffectRole>,
    pub worktree_transition_refs: Vec<WorktreeTransitionId>,
    pub integration_event_refs: Vec<IntegrationEventId>,
}

impl OperationBurstMember {
    fn validate(&self) -> bool {
        self.sequence > 0
            && self.source_watermark > 0
            && self.operation_revision > 0
            && !self.source_observation_refs.is_empty()
            && [
                self.source_observation_refs.len(),
                self.scope_effect_refs.len(),
                self.artifact_refs.len(),
                self.side_effects.len(),
                self.worktree_transition_refs.len(),
                self.integration_event_refs.len(),
            ]
            .into_iter()
            .all(|len| len <= MAX_MEMBER_REFS)
            && strictly_ordered_unique(&self.source_observation_refs)
            && strictly_ordered_unique(&self.scope_effect_refs)
            && strictly_ordered_unique(&self.artifact_refs)
            && strictly_ordered_unique(&self.side_effects)
            && strictly_ordered_unique(&self.worktree_transition_refs)
            && strictly_ordered_unique(&self.integration_event_refs)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationBurst {
    pub operation_burst_id: OperationBurstId,
    pub revision_id: RevisionId,
    pub predecessor_revision_id: Option<RevisionId>,
    pub revision_generation: u64,
    pub lifecycle: OperationBurstLifecycle,
    pub algorithm_revision: u32,
    pub operation_kind: OperationKind,
    pub state_delta: OperationStateDelta,
    pub verifier_delta: OperationVerifierDelta,
    pub phase_candidate: Option<PhaseKind>,
    pub has_objective_boundary: bool,
    pub error_signature: Option<String>,
    pub target_family: String,
    pub target_refs: Vec<String>,
    pub members: Vec<OperationBurstMember>,
    pub execution_lane_id: ExecutionLaneId,
    pub parent_lane_id: Option<ExecutionLaneId>,
    pub subagent_id: Option<String>,
    pub primary_binding: PrimaryWorkBinding,
    pub attempt_id: Option<AttemptId>,
    pub experiment_run_id: Option<ExperimentRunId>,
    pub competing_group_id: Option<CompetingAttemptGroupId>,
    pub worktree_lineage_refs: Vec<String>,
    pub strategy_contract_fingerprint: Option<[u8; 32]>,
    pub source_watermark: u64,
}

impl OperationBurst {
    pub fn validate(&self) -> Result<(), WorkError> {
        let text_lists = [&self.target_refs, &self.worktree_lineage_refs]
            .into_iter()
            .all(|values| {
                values.len() <= MAX_MEMBER_REFS
                    && strictly_ordered_unique(values)
                    && values
                        .iter()
                        .all(|value| !value.trim().is_empty() && value.len() <= MAX_TEXT)
            });
        let ordered_members = !self.members.is_empty()
            && self.members.len() <= MAX_BURST_MEMBERS
            && self.members.iter().all(OperationBurstMember::validate)
            && self.members.windows(2).all(|pair| {
                pair[0].sequence < pair[1].sequence
                    && pair[0].source_watermark < pair[1].source_watermark
            });
        let unique_revisions = self
            .members
            .iter()
            .map(|member| (member.operation_id, member.operation_revision))
            .collect::<BTreeSet<_>>()
            .len()
            == self.members.len();
        if self.revision_generation == 0
            || self.algorithm_revision == 0
            || (self.revision_generation == 1) != self.predecessor_revision_id.is_none()
            || !text_lists
            || self.target_family.trim().is_empty()
            || self.target_family.len() > MAX_TEXT
            || !ordered_members
            || !unique_revisions
            || self.source_watermark
                != self
                    .members
                    .last()
                    .map(|member| member.source_watermark)
                    .unwrap_or(0)
            || self
                .error_signature
                .as_deref()
                .is_some_and(|value| value.trim().is_empty() || value.len() > MAX_TEXT)
            || self
                .subagent_id
                .as_deref()
                .is_some_and(|value| value.trim().is_empty() || value.len() > MAX_TEXT)
            || self.primary_binding.task_id.is_none()
            || self.primary_binding.workstream_id.is_none()
            || self.primary_binding.episode_id.is_none()
            || self.primary_binding.attempt_id != self.attempt_id
            || self.primary_binding.experiment_run_id != self.experiment_run_id
            || self.primary_binding.competing_group_id != self.competing_group_id
            || (self.attempt_id.is_none()
                && (self.experiment_run_id.is_some()
                    || self.competing_group_id.is_some()
                    || self.strategy_contract_fingerprint.is_some()))
            || self.members.iter().any(|member| {
                member.attempt_revision_id.is_some() != self.attempt_id.is_some()
                    || (self.attempt_id.is_none()
                        && (!member.worktree_transition_refs.is_empty()
                            || !member.integration_event_refs.is_empty()))
            })
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), WorkError> {
        self.validate()?;
        next.validate()?;
        if next.operation_burst_id != self.operation_burst_id
            || next.revision_id == self.revision_id
            || next.predecessor_revision_id != Some(self.revision_id)
            || next.revision_generation
                != self
                    .revision_generation
                    .checked_add(1)
                    .ok_or(WorkError::InvalidWorkIdentity)?
            || self.lifecycle == OperationBurstLifecycle::Closed
            || next.algorithm_revision != self.algorithm_revision
            || next.operation_kind != self.operation_kind
            || next.state_delta != self.state_delta
            || next.verifier_delta != self.verifier_delta
            || next.phase_candidate != self.phase_candidate
            || next.has_objective_boundary != self.has_objective_boundary
            || next.error_signature != self.error_signature
            || next.target_family != self.target_family
            || next.target_refs != self.target_refs
            || next.execution_lane_id != self.execution_lane_id
            || next.parent_lane_id != self.parent_lane_id
            || next.subagent_id != self.subagent_id
            || next.primary_binding != self.primary_binding
            || next.attempt_id != self.attempt_id
            || next.experiment_run_id != self.experiment_run_id
            || next.competing_group_id != self.competing_group_id
            || next.worktree_lineage_refs != self.worktree_lineage_refs
            || next.strategy_contract_fingerprint != self.strategy_contract_fingerprint
            || next.source_watermark < self.source_watermark
            || !next.members.starts_with(&self.members)
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }

    pub fn is_meaningful_after(&self, previous: Option<&Self>) -> bool {
        !matches!(
            self.operation_kind,
            OperationKind::Read | OperationKind::Search | OperationKind::Observe
        ) || !matches!(
            self.state_delta,
            OperationStateDelta::None | OperationStateDelta::Observed
        ) || self.error_signature.is_some()
            || self.verifier_delta != OperationVerifierDelta::None
            || self.phase_candidate.is_some()
            || self.has_objective_boundary
            || self.members.iter().any(|member| {
                !member.artifact_refs.is_empty()
                    || !member.worktree_transition_refs.is_empty()
                    || !member.integration_event_refs.is_empty()
                    || member
                        .side_effects
                        .iter()
                        .any(|role| !matches!(role, EffectRole::Read | EffectRole::Observe))
            })
            || previous.is_some_and(|value| {
                value.target_family != self.target_family || value.target_refs != self.target_refs
            })
    }
}
