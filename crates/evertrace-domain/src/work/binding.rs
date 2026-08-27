use serde::{Deserialize, Serialize};

use crate::{
    ids::{
        AttemptId, CompetingAttemptGroupId, ExperimentRunId, OperationId, ScopeEffectId, TaskId,
        WorkArtifactId, WorkBindingRevisionId, WorkEpisodeId, WorkstreamId,
    },
    work::{WorkError, task::strictly_ordered_unique},
};

const MAX_ITEMS: usize = 64;
const MAX_TEXT: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentStatus {
    Resolved,
    Provisional,
    Conflicted,
    Unresolved,
}

impl AssignmentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Provisional => "provisional",
            Self::Conflicted => "conflicted",
            Self::Unresolved => "unresolved",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrimaryWorkBinding {
    pub task_id: Option<TaskId>,
    pub workstream_id: Option<WorkstreamId>,
    pub episode_id: Option<WorkEpisodeId>,
    pub attempt_id: Option<AttemptId>,
    pub experiment_run_id: Option<ExperimentRunId>,
    pub competing_group_id: Option<CompetingAttemptGroupId>,
}

impl PrimaryWorkBinding {
    pub const fn is_empty(&self) -> bool {
        self.task_id.is_none()
            && self.workstream_id.is_none()
            && self.episode_id.is_none()
            && self.attempt_id.is_none()
            && self.experiment_run_id.is_none()
            && self.competing_group_id.is_none()
    }

    const fn has_future_ref(&self) -> bool {
        self.episode_id.is_some()
            || self.attempt_id.is_some()
            || self.experiment_run_id.is_some()
            || self.competing_group_id.is_some()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecondaryBindingRole {
    Supporting,
    Affected,
    Comparison,
    Integration,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SecondaryBindingTarget {
    Task(TaskId),
    Workstream(WorkstreamId),
    Episode(WorkEpisodeId),
    Attempt(AttemptId),
    ExperimentRun(ExperimentRunId),
    CompetingGroup(CompetingAttemptGroupId),
    Artifact(WorkArtifactId),
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecondaryWorkBinding {
    pub role: SecondaryBindingRole,
    pub target_ref: SecondaryBindingTarget,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkBindingRevision {
    pub work_binding_revision_id: WorkBindingRevisionId,
    pub operation_id: OperationId,
    pub revision_generation: u64,
    pub predecessor_revision_id: Option<WorkBindingRevisionId>,
    pub primary_binding: PrimaryWorkBinding,
    pub secondary_bindings: Vec<SecondaryWorkBinding>,
    pub scope_effect_refs: Vec<ScopeEffectId>,
    pub assignment_status: AssignmentStatus,
    pub evidence_refs: Vec<String>,
    pub resolver_version: u32,
}

impl WorkBindingRevision {
    pub fn validate(&self) -> Result<(), WorkError> {
        let paired_base =
            self.primary_binding.task_id.is_some() && self.primary_binding.workstream_id.is_some();
        let valid_primary = match self.assignment_status {
            AssignmentStatus::Resolved => paired_base && !self.evidence_refs.is_empty(),
            AssignmentStatus::Provisional => {
                self.primary_binding.task_id.is_some()
                    == self.primary_binding.workstream_id.is_some()
            }
            AssignmentStatus::Conflicted | AssignmentStatus::Unresolved => {
                self.primary_binding.is_empty()
            }
        };
        if self.revision_generation == 0
            || self.resolver_version == 0
            || self.secondary_bindings.len() > MAX_ITEMS
            || !strictly_ordered_unique(&self.secondary_bindings)
            || self.scope_effect_refs.len() > MAX_ITEMS
            || !strictly_ordered_unique(&self.scope_effect_refs)
            || self.evidence_refs.len() > MAX_ITEMS
            || self
                .evidence_refs
                .iter()
                .any(|value| value.trim().is_empty() || value.len() > MAX_TEXT)
            || !strictly_ordered_unique(&self.evidence_refs)
            || (self.revision_generation == 1) != self.predecessor_revision_id.is_none()
            || !valid_primary
            || (self.primary_binding.has_future_ref() && !paired_base)
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), WorkError> {
        self.validate()?;
        next.validate()?;
        let generation = self
            .revision_generation
            .checked_add(1)
            .ok_or(WorkError::InvalidWorkIdentity)?;
        let episode_ok = match (
            self.primary_binding.episode_id,
            next.primary_binding.episode_id,
        ) {
            (None, None | Some(_)) => true,
            (Some(old), Some(new)) => old == new,
            (Some(_), None) => false,
        };
        if next.operation_id != self.operation_id
            || next.revision_generation != generation
            || next.predecessor_revision_id != Some(self.work_binding_revision_id)
            || !episode_ok
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }
}

/// Deterministic, read-only current semantic context. Non-resolved bindings
/// deliberately expose no authoritative owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveWorkContext {
    pub operation_id: OperationId,
    pub work_binding_revision_id: WorkBindingRevisionId,
    pub revision_generation: u64,
    pub assignment_status: AssignmentStatus,
    pub task_id: Option<TaskId>,
    pub workstream_id: Option<WorkstreamId>,
    pub secondary_bindings: Vec<SecondaryWorkBinding>,
    pub scope_effect_refs: Vec<ScopeEffectId>,
}

impl ActiveWorkContext {
    pub fn from_current(binding: &WorkBindingRevision) -> Self {
        let resolved = binding.assignment_status == AssignmentStatus::Resolved;
        Self {
            operation_id: binding.operation_id,
            work_binding_revision_id: binding.work_binding_revision_id,
            revision_generation: binding.revision_generation,
            assignment_status: binding.assignment_status,
            task_id: resolved
                .then_some(binding.primary_binding.task_id)
                .flatten(),
            workstream_id: resolved
                .then_some(binding.primary_binding.workstream_id)
                .flatten(),
            secondary_bindings: binding.secondary_bindings.clone(),
            scope_effect_refs: binding.scope_effect_refs.clone(),
        }
    }

    pub const fn is_resolved(&self) -> bool {
        matches!(self.assignment_status, AssignmentStatus::Resolved)
    }
}
