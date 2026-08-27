use serde::{Deserialize, Serialize};

use crate::{
    ids::{ExecutionLaneId, RepositoryId, TaskId, WorkEpisodeId, WorkstreamId, WorktreeId},
    revision::RevisionId,
    work::{WorkError, task::strictly_ordered_unique},
};

const MAX_ITEMS: usize = 64;
const MAX_TEXT: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseKind {
    Orient,
    Inspect,
    Reproduce,
    Diagnose,
    Design,
    Implement,
    Verify,
    Execute,
    Analyze,
    Recover,
    Deliver,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseContract {
    pub local_goal: String,
    pub phase_kind: PhaseKind,
    pub phase_label: String,
    pub primary_targets: Vec<String>,
    pub entry_conditions: Vec<String>,
    pub acceptance_boundary: String,
    pub expected_state_transition: String,
}

impl PhaseContract {
    pub fn validate(&self) -> Result<(), WorkError> {
        if !bounded(&self.local_goal)
            || !bounded(&self.phase_label)
            || !bounded(&self.acceptance_boundary)
            || !bounded(&self.expected_state_transition)
            || !bounded_strings(&self.primary_targets)
            || !bounded_strings(&self.entry_conditions)
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkstreamStatus {
    Active,
    Paused,
    Closed,
    Superseded,
}

impl WorkstreamStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Superseded)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Closed => "closed",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Workstream {
    pub workstream_id: WorkstreamId,
    pub revision_id: RevisionId,
    pub predecessor_revision_id: Option<RevisionId>,
    pub task_id: TaskId,
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_ids: Vec<WorktreeId>,
    pub active_worktree_instance_id: Option<WorktreeId>,
    pub worktree_lineage_refs: Vec<String>,
    pub parent_workstream_id: Option<WorkstreamId>,
    pub dependency_workstream_ids: Vec<WorkstreamId>,
    pub status: WorkstreamStatus,
    pub root_goal: String,
    pub workstream_goal: String,
    pub target_family: String,
    pub hypothesis_or_failure_family: String,
    pub acceptance_boundary: String,
    pub phase_contract: PhaseContract,
    pub active_episode_id: Option<WorkEpisodeId>,
    pub execution_lane_ids: Vec<ExecutionLaneId>,
    pub source_watermark: u64,
}

impl Workstream {
    pub fn validate(&self) -> Result<(), WorkError> {
        if !bounded(&self.root_goal)
            || !bounded(&self.workstream_goal)
            || !bounded(&self.target_family)
            || !bounded(&self.hypothesis_or_failure_family)
            || !bounded(&self.acceptance_boundary)
            || self.worktree_instance_ids.len() > MAX_ITEMS
            || !strictly_ordered_unique(&self.worktree_instance_ids)
            || self.worktree_lineage_refs.len() > MAX_ITEMS
            || !bounded_strings(&self.worktree_lineage_refs)
            || self.dependency_workstream_ids.len() > MAX_ITEMS
            || !strictly_ordered_unique(&self.dependency_workstream_ids)
            || self.execution_lane_ids.len() > MAX_ITEMS
            || !strictly_ordered_unique(&self.execution_lane_ids)
            || self
                .active_worktree_instance_id
                .is_some_and(|id| !self.worktree_instance_ids.contains(&id))
            || (self.repository_instance_id.is_none() && !self.worktree_instance_ids.is_empty())
            || self.parent_workstream_id == Some(self.workstream_id)
            || self.dependency_workstream_ids.contains(&self.workstream_id)
            || self.active_episode_id.is_some()
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        self.phase_contract.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationEvidenceKind {
    ExplicitTask,
    ExplicitWorkstream,
    Handoff,
    Plan,
    Patch,
    Test,
    Error,
    Hypothesis,
    ExecutionLane,
    Session,
    ParentThread,
    FileSymbolOverlap,
    RecentActivity,
    TimeProximity,
    TextSimilarity,
}

impl CorrelationEvidenceKind {
    pub const fn is_strong(self) -> bool {
        matches!(
            self,
            Self::Handoff | Self::Plan | Self::Patch | Self::Test | Self::Error | Self::Hypothesis
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationEvidence {
    pub kind: CorrelationEvidenceKind,
    pub evidence_ref: String,
    pub candidate_task_ids: Vec<TaskId>,
    pub candidate_workstream_ids: Vec<WorkstreamId>,
}

impl CorrelationEvidence {
    pub fn validate(&self) -> Result<(), WorkError> {
        if !bounded(&self.evidence_ref)
            || self.candidate_task_ids.len() > MAX_ITEMS
            || !strictly_ordered_unique(&self.candidate_task_ids)
            || self.candidate_workstream_ids.len() > MAX_ITEMS
            || !strictly_ordered_unique(&self.candidate_workstream_ids)
            || (self.candidate_task_ids.is_empty() && self.candidate_workstream_ids.is_empty())
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnresolvedWorkstream {
    pub candidate_task_ids: Vec<TaskId>,
    pub candidate_workstream_ids: Vec<WorkstreamId>,
    pub missing_evidence: Vec<String>,
    pub conflict_reason: String,
    pub exit_conditions: Vec<String>,
    pub source_watermark: u64,
}

impl UnresolvedWorkstream {
    pub fn validate(&self) -> Result<(), WorkError> {
        if self.candidate_task_ids.len() > MAX_ITEMS
            || !strictly_ordered_unique(&self.candidate_task_ids)
            || self.candidate_workstream_ids.len() > MAX_ITEMS
            || !strictly_ordered_unique(&self.candidate_workstream_ids)
            || !bounded_strings(&self.missing_evidence)
            || !bounded(&self.conflict_reason)
            || !bounded_strings(&self.exit_conditions)
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorrelationResult {
    Resolved(WorkstreamId),
    Unresolved(UnresolvedWorkstream),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveLineageFoundation {
    pub task_id: TaskId,
    pub task_revision_id: RevisionId,
    pub workstream_id: WorkstreamId,
    pub workstream_revision_id: RevisionId,
    pub repository_instance_id: Option<RepositoryId>,
    pub active_worktree_instance_id: Option<WorktreeId>,
    pub worktree_lineage_refs: Vec<String>,
    pub source_watermark: u64,
}

fn bounded(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT
}

fn bounded_strings(values: &[String]) -> bool {
    values.len() <= MAX_ITEMS
        && values.iter().all(|value| bounded(value))
        && strictly_ordered_unique(values)
}
