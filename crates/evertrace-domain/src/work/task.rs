use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    ids::{RepositoryId, TaskId, WorktreeId},
    revision::RevisionId,
    work::WorkError,
};

const MAX_REFS: usize = 64;
const MAX_TEXT: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskIdentityConfidence {
    Explicit,
    StronglyInferred,
    Provisional,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskLifecycle {
    Active,
    Paused,
    Completed,
    Abandoned,
    Superseded,
}

impl TaskLifecycle {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Abandoned | Self::Superseded)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Abandoned => "abandoned",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskScopeMembership {
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_ids: Vec<WorktreeId>,
}

impl TaskScopeMembership {
    pub fn validate(&self) -> Result<(), WorkError> {
        if self.worktree_instance_ids.len() > MAX_REFS
            || !strictly_ordered_unique(&self.worktree_instance_ids)
            || (self.repository_instance_id.is_none() && !self.worktree_instance_ids.is_empty())
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub task_id: TaskId,
    pub revision_id: RevisionId,
    pub predecessor_revision_id: Option<RevisionId>,
    pub request_root_refs: Vec<String>,
    pub canonical_goal: String,
    pub scope_memberships: Vec<TaskScopeMembership>,
    pub identity_confidence: TaskIdentityConfidence,
    pub lifecycle: TaskLifecycle,
    pub continuation_of_task_id: Option<TaskId>,
    pub split_from_task_id: Option<TaskId>,
    pub split_into_task_ids: Vec<TaskId>,
    pub merged_from_task_ids: Vec<TaskId>,
    pub merged_into_task_id: Option<TaskId>,
    pub created_at_us: i64,
    pub closed_at_us: Option<i64>,
    pub source_watermark: u64,
}

impl Task {
    pub fn validate(&self) -> Result<(), WorkError> {
        if !bounded_text(&self.canonical_goal)
            || self.request_root_refs.is_empty()
            || !bounded_strings(&self.request_root_refs)
            || self.scope_memberships.len() > MAX_REFS
            || !strictly_ordered_unique(&self.scope_memberships)
            || !ordered_ids(&self.split_into_task_ids)
            || !ordered_ids(&self.merged_from_task_ids)
            || self.created_at_us < 0
            || self
                .closed_at_us
                .is_some_and(|closed| closed < self.created_at_us)
            || (self.lifecycle.is_terminal() != self.closed_at_us.is_some())
            || self.continuation_of_task_id == Some(self.task_id)
            || self.split_from_task_id == Some(self.task_id)
            || self.merged_into_task_id == Some(self.task_id)
            || self.split_into_task_ids.contains(&self.task_id)
            || self.merged_from_task_ids.contains(&self.task_id)
            || (!self.merged_from_task_ids.is_empty()
                && (self.continuation_of_task_id.is_some() || self.split_from_task_id.is_some()))
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        for membership in &self.scope_memberships {
            membership.validate()?;
        }
        Ok(())
    }
}

fn bounded_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT
}

fn bounded_strings(values: &[String]) -> bool {
    values.len() <= MAX_REFS
        && values.iter().all(|value| bounded_text(value))
        && strictly_ordered_unique(values)
}

fn ordered_ids<T: Ord>(values: &[T]) -> bool {
    values.len() <= MAX_REFS && strictly_ordered_unique(values)
}

pub(crate) fn strictly_ordered_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}
