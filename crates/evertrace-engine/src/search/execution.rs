//! One request's canonical Work state, shared with the existing Procedure route.
use evertrace_domain::{
    ids::TaskId,
    query::{QueryAnchor, QueryBindingStrength, QueryExecution},
    work::{AssignmentStatus, AttemptExecutionStatus, AttemptLifecycleStatus},
};
use evertrace_store::JournalPayload;

pub(crate) fn from_facts(
    frontier: u64,
    facts: &[JournalPayload],
    anchor: &QueryAnchor,
    task_id: Option<TaskId>,
) -> Option<Box<QueryExecution>> {
    if !matches!(
        anchor.binding_strength,
        QueryBindingStrength::Exact | QueryBindingStrength::ConnectionScoped
    ) {
        return None;
    }
    let task = unique(facts.iter().filter_map(|payload| match payload {
        JournalPayload::TaskRecorded(value) if Some(value.task_id) == task_id => {
            Some(value.as_ref())
        }
        _ => None,
    }));
    let stream = unique(facts.iter().filter_map(|payload| match payload {
        JournalPayload::WorkstreamRecorded(value)
            if Some(value.workstream_id) == anchor.workstream_id =>
        {
            Some(value.as_ref())
        }
        _ => None,
    }));
    let episode = unique(facts.iter().filter_map(|payload| match payload {
        JournalPayload::WorkEpisodeRecorded(value)
            if Some(value.revision_id) == anchor.episode_revision_id =>
        {
            Some(value.as_ref())
        }
        _ => None,
    }));
    let (Some(task), Some(stream), Some(episode)) = (task, stream, episode) else {
        return None;
    };
    let mut attempts = std::collections::BTreeMap::new();
    for payload in facts {
        if let JournalPayload::AttemptRecorded(value) = payload
            && episode.attempt_ids.contains(&value.attempt_id)
        {
            let entry = attempts.entry(value.attempt_id).or_insert(value.as_ref());
            if entry.revision_generation < value.revision_generation {
                *entry = value;
            }
        }
    }
    let attempt = unique(attempts.values().copied().filter(|attempt| {
        attempt.task_id == task.task_id
            && attempt.workstream_id == stream.workstream_id
            && attempt.episode_id == Some(episode.episode_id)
            && anchor
                .execution_lane_id
                .is_some_and(|id| attempt.execution_lane_ids.contains(&id))
            && attempt.lifecycle_status == AttemptLifecycleStatus::Active
            && attempt.execution_status == AttemptExecutionStatus::Active
            && attempt.repository_instance_id == episode.repository_instance_id
            && match episode.worktree_instance_id {
                Some(id) => attempt.worktree_instance_ids.contains(&id),
                None => attempt.worktree_instance_ids.is_empty(),
            }
    }));
    let lane = facts
        .iter()
        .filter_map(|payload| match payload {
            JournalPayload::ExecutionLaneRecorded(value)
                if Some(value.execution_lane_id) == anchor.execution_lane_id
                    && Some(value.host_session_id.as_str())
                        == anchor.runtime_session_id.as_deref() =>
            {
                Some(value.as_ref())
            }
            _ => None,
        })
        .max_by_key(|lane| lane.lane_revision);
    let binding = unique(facts.iter().filter_map(|payload| match payload {
        JournalPayload::WorkBindingRecorded(value)
            if value.assignment_status == AssignmentStatus::Resolved
                && lane.is_some_and(|lane| lane.operation_ids.contains(&value.operation_id))
                && value.primary_binding.task_id == Some(task.task_id)
                && value.primary_binding.workstream_id == Some(stream.workstream_id)
                && value.primary_binding.episode_id == Some(episode.episode_id)
                && attempt.is_none_or(|attempt| {
                    value
                        .primary_binding
                        .attempt_id
                        .is_none_or(|id| id == attempt.attempt_id)
                }) =>
        {
            Some(value.as_ref())
        }
        _ => None,
    }));
    let checkpoint = unique(facts.iter().filter_map(|payload| match payload {
        JournalPayload::WorkCheckpointRecorded(value)
            if value.episode_id == episode.episode_id
                && value.source_watermark == episode.source_watermark
                && value.phase_contract == episode.phase_contract
                && episode.checkpoint_refs.contains(&value.stable_key())
                && value.attempt_revision_refs.len() == episode.attempt_ids.len()
                && value.attempt_revision_refs.iter().all(|reference| {
                    attempts
                        .get(&reference.attempt_id)
                        .is_some_and(|attempt| attempt.revision_id == reference.revision_id)
                }) =>
        {
            Some(value.as_ref())
        }
        _ => None,
    }));
    let execution = QueryExecution {
        frontier,
        task: task.clone(),
        workstream: stream.clone(),
        episode: episode.clone(),
        attempt: attempt.cloned(),
        work_binding: binding.cloned(),
        checkpoint: checkpoint.cloned(),
    };
    // A valid payload can still fail to prove this caller's active association.
    // Missing/ambiguous work is unknown, never a guessed most-recent context.
    if execution.validate(anchor, task_id).is_err() {
        return None;
    }
    Some(Box::new(execution))
}

fn unique<T>(mut values: impl Iterator<Item = T>) -> Option<T> {
    let value = values.next()?;
    values.next().is_none().then_some(value)
}
