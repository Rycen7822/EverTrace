use std::collections::BTreeSet;

use evertrace_domain::work::{Task, TaskLifecycle};
use evertrace_store::{JournalCommand, JournalEventDraft, JournalPayload};

use super::{TypedTaskChange, WorkCommandContext, WorkIdentityError};

fn event(context: WorkCommandContext, task: Task) -> JournalEventDraft {
    JournalEventDraft::runtime(
        context.occurred_at_us,
        context.effective_config_hash,
        context.algorithm_revision,
        JournalPayload::TaskRecorded(Box::new(task)),
    )
}

fn command(
    context: WorkCommandContext,
    tasks: impl IntoIterator<Item = Task>,
) -> Result<JournalCommand, WorkIdentityError> {
    JournalCommand::new(
        context.command_id,
        tasks.into_iter().map(|task| event(context, task)).collect(),
    )
    .map_err(Into::into)
}

pub fn create_task(
    context: WorkCommandContext,
    task: Task,
) -> Result<JournalCommand, WorkIdentityError> {
    task.validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    if task.predecessor_revision_id.is_some()
        || task.continuation_of_task_id.is_some()
        || task.split_from_task_id.is_some()
        || !task.split_into_task_ids.is_empty()
        || !task.merged_from_task_ids.is_empty()
        || task.merged_into_task_id.is_some()
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    command(context, [task])
}

pub fn revise_task(
    context: WorkCommandContext,
    current: &Task,
    successor: Task,
    _change: TypedTaskChange,
    evidence_refs: &[String],
) -> Result<JournalCommand, WorkIdentityError> {
    successor
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    if evidence_refs.is_empty()
        || successor.task_id != current.task_id
        || successor.predecessor_revision_id != Some(current.revision_id)
        || successor.revision_id == current.revision_id
        || successor.source_watermark <= current.source_watermark
        || current.lifecycle.is_terminal()
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    command(context, [successor])
}

pub fn continue_task(
    context: WorkCommandContext,
    source: &Task,
    continuation: Task,
    evidence_refs: &[String],
) -> Result<JournalCommand, WorkIdentityError> {
    continuation
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    if evidence_refs.is_empty()
        || !matches!(
            source.lifecycle,
            TaskLifecycle::Completed | TaskLifecycle::Abandoned
        )
        || continuation.predecessor_revision_id.is_some()
        || continuation.task_id == source.task_id
        || continuation.continuation_of_task_id != Some(source.task_id)
        || !continuation.scope_memberships.is_empty()
        || !continuation.split_into_task_ids.is_empty()
        || !continuation.merged_from_task_ids.is_empty()
        || continuation.merged_into_task_id.is_some()
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    command(context, [continuation])
}

pub fn split_task(
    context: WorkCommandContext,
    source_successor: Task,
    children: Vec<Task>,
    evidence_refs: &[String],
) -> Result<JournalCommand, WorkIdentityError> {
    if evidence_refs.is_empty()
        || children.len() < 2
        || source_successor.lifecycle != TaskLifecycle::Superseded
        || source_successor.predecessor_revision_id.is_none()
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    let child_ids = children
        .iter()
        .map(|task| task.task_id)
        .collect::<BTreeSet<_>>();
    if child_ids.len() != children.len()
        || source_successor
            .split_into_task_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            != child_ids
        || children.iter().any(|child| {
            child.validate().is_err()
                || child.predecessor_revision_id.is_some()
                || child.split_from_task_id != Some(source_successor.task_id)
                || !child.scope_memberships.is_empty()
        })
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    command(context, std::iter::once(source_successor).chain(children))
}

pub fn merge_tasks(
    context: WorkCommandContext,
    source_successors: Vec<Task>,
    merged: Task,
    evidence_refs: &[String],
) -> Result<JournalCommand, WorkIdentityError> {
    if evidence_refs.is_empty()
        || source_successors.len() < 2
        || merged.predecessor_revision_id.is_some()
        || !merged.scope_memberships.is_empty()
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    let source_ids = source_successors
        .iter()
        .map(|task| task.task_id)
        .collect::<BTreeSet<_>>();
    if source_ids.len() != source_successors.len()
        || merged
            .merged_from_task_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            != source_ids
        || source_successors.iter().any(|source| {
            source.validate().is_err()
                || source.predecessor_revision_id.is_none()
                || source.lifecycle != TaskLifecycle::Superseded
                || source.merged_into_task_id != Some(merged.task_id)
        })
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    command(context, std::iter::once(merged).chain(source_successors))
}
