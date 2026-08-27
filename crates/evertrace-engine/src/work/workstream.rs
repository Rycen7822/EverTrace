use std::collections::BTreeSet;

use evertrace_domain::{
    ids::{RepositoryId, TaskId, WorktreeId},
    repository::WorktreeLifecycle,
    work::{
        ActiveLineageFoundation, CorrelationEvidence, CorrelationEvidenceKind, CorrelationResult,
        Task, TaskIdentityConfidence, UnresolvedWorkstream, Workstream,
    },
};
use evertrace_store::{
    JournalCommand, JournalEventDraft, JournalPayload, WorkIdentityCurrentView,
    repository::RepositoryCurrentView,
};

use super::{TypedWorkstreamChange, WorkCommandContext, WorkIdentityError};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CorrelationScope {
    pub task_id: Option<TaskId>,
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_id: Option<WorktreeId>,
}

fn command(
    context: WorkCommandContext,
    workstream: Workstream,
) -> Result<JournalCommand, WorkIdentityError> {
    JournalCommand::new(
        context.command_id,
        vec![JournalEventDraft::runtime(
            context.occurred_at_us,
            context.effective_config_hash,
            context.algorithm_revision,
            JournalPayload::WorkstreamRecorded(Box::new(workstream)),
        )],
    )
    .map_err(Into::into)
}

fn commands(
    context: WorkCommandContext,
    workstreams: impl IntoIterator<Item = Workstream>,
) -> Result<JournalCommand, WorkIdentityError> {
    JournalCommand::new(
        context.command_id,
        workstreams
            .into_iter()
            .map(|workstream| {
                JournalEventDraft::runtime(
                    context.occurred_at_us,
                    context.effective_config_hash,
                    context.algorithm_revision,
                    JournalPayload::WorkstreamRecorded(Box::new(workstream)),
                )
            })
            .collect(),
    )
    .map_err(Into::into)
}

pub fn create_workstream(
    context: WorkCommandContext,
    task: &Task,
    repository_view: &RepositoryCurrentView,
    workstream: Workstream,
) -> Result<JournalCommand, WorkIdentityError> {
    workstream
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    if workstream.predecessor_revision_id.is_some() {
        return Err(WorkIdentityError::InvalidInput);
    }
    validate_workstream_scope(task, &workstream, repository_view)?;
    command(context, workstream)
}

pub fn validate_workstream_scope(
    task: &Task,
    workstream: &Workstream,
    repository_view: &RepositoryCurrentView,
) -> Result<(), WorkIdentityError> {
    if workstream.task_id != task.task_id {
        return Err(WorkIdentityError::ScopeUnresolved);
    }
    match workstream.repository_instance_id {
        None if workstream.worktree_instance_ids.is_empty() => Ok(()),
        Some(repository_id)
            if repository_view.repositories.contains_key(&repository_id)
                && task.scope_memberships.iter().any(|membership| {
                    membership.repository_instance_id == Some(repository_id)
                        && workstream
                            .worktree_instance_ids
                            .iter()
                            .all(|id| membership.worktree_instance_ids.contains(id))
                })
                && workstream.worktree_instance_ids.iter().all(|id| {
                    repository_view
                        .worktrees
                        .get(id)
                        .is_some_and(|worktree| worktree.repository_instance_id == repository_id)
                }) =>
        {
            Ok(())
        }
        _ => Err(WorkIdentityError::ScopeUnresolved),
    }
}

pub fn revise_workstream(
    context: WorkCommandContext,
    task: &Task,
    repository_view: &RepositoryCurrentView,
    current: &Workstream,
    successor: Workstream,
    change: TypedWorkstreamChange,
    evidence_refs: &[String],
) -> Result<JournalCommand, WorkIdentityError> {
    if change == TypedWorkstreamChange::MaterialGoalReplacement
        || evidence_refs.is_empty()
        || successor.workstream_id != current.workstream_id
        || successor.predecessor_revision_id != Some(current.revision_id)
        || successor.revision_id == current.revision_id
        || successor.source_watermark <= current.source_watermark
        || current.status.is_terminal()
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    successor
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    validate_workstream_scope(task, &successor, repository_view)?;
    command(context, successor)
}

pub fn replace_workstream_for_material_goal(
    context: WorkCommandContext,
    task: &Task,
    repository_view: &RepositoryCurrentView,
    current: &Workstream,
    replacement: Workstream,
    decision_refs: &[String],
) -> Result<JournalCommand, WorkIdentityError> {
    if decision_refs.is_empty()
        || replacement.workstream_id == current.workstream_id
        || replacement.predecessor_revision_id.is_some()
        || replacement.task_id != current.task_id
        || replacement.source_watermark <= current.source_watermark
        || current.status.is_terminal()
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    replacement
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    validate_workstream_scope(task, &replacement, repository_view)?;
    let mut superseded = current.clone();
    superseded.revision_id = evertrace_domain::revision::RevisionId::new_v7();
    superseded.predecessor_revision_id = Some(current.revision_id);
    superseded.status = evertrace_domain::work::WorkstreamStatus::Superseded;
    superseded.source_watermark = replacement.source_watermark;
    commands(context, [superseded, replacement])
}

fn scope_matches(workstream: &Workstream, scope: CorrelationScope) -> bool {
    scope.task_id.is_none_or(|id| workstream.task_id == id)
        && scope
            .repository_instance_id
            .is_none_or(|id| workstream.repository_instance_id == Some(id))
        && scope
            .worktree_instance_id
            .is_none_or(|id| workstream.worktree_instance_ids.contains(&id))
}

pub fn resolve_workstream_candidate(
    view: &WorkIdentityCurrentView,
    scope: CorrelationScope,
    evidence: &[CorrelationEvidence],
    source_watermark: u64,
) -> CorrelationResult {
    let mut authoritative_seen = false;
    let mut invalid_authoritative = false;
    let mut constraints = Vec::<BTreeSet<_>>::new();
    for item in evidence {
        let authoritative = item.kind == CorrelationEvidenceKind::ExplicitTask
            || item.kind == CorrelationEvidenceKind::ExplicitWorkstream
            || item.kind.is_strong();
        if !authoritative {
            continue;
        }
        authoritative_seen = true;
        if item.validate().is_err() {
            invalid_authoritative = true;
            continue;
        }
        let mut candidates = BTreeSet::new();
        match item.kind {
            CorrelationEvidenceKind::ExplicitTask => {
                if !item.candidate_workstream_ids.is_empty() {
                    invalid_authoritative = true;
                    continue;
                }
                for task_id in &item.candidate_task_ids {
                    if !view.tasks.contains_key(task_id)
                        || scope.task_id.is_some_and(|scope_id| scope_id != *task_id)
                    {
                        invalid_authoritative = true;
                        continue;
                    }
                    let matching = view
                        .workstreams
                        .values()
                        .filter(|workstream| {
                            workstream.task_id == *task_id && scope_matches(workstream, scope)
                        })
                        .map(|workstream| workstream.workstream_id)
                        .collect::<BTreeSet<_>>();
                    if matching.is_empty() {
                        invalid_authoritative = true;
                    }
                    candidates.extend(matching);
                }
            }
            CorrelationEvidenceKind::ExplicitWorkstream
            | CorrelationEvidenceKind::Handoff
            | CorrelationEvidenceKind::Plan
            | CorrelationEvidenceKind::Patch
            | CorrelationEvidenceKind::Test
            | CorrelationEvidenceKind::Error
            | CorrelationEvidenceKind::Hypothesis => {
                if !item.candidate_task_ids.is_empty() {
                    invalid_authoritative = true;
                    continue;
                }
                for id in &item.candidate_workstream_ids {
                    if view
                        .workstreams
                        .get(id)
                        .is_none_or(|workstream| !scope_matches(workstream, scope))
                    {
                        invalid_authoritative = true;
                    } else {
                        candidates.insert(*id);
                    }
                }
            }
            _ => unreachable!("weak correlation evidence is filtered above"),
        }
        if candidates.is_empty() {
            invalid_authoritative = true;
        } else {
            constraints.push(candidates);
        }
    }
    let candidates = constraints
        .into_iter()
        .reduce(|left, right| left.intersection(&right).copied().collect())
        .unwrap_or_default();
    if authoritative_seen && !invalid_authoritative && candidates.len() == 1 {
        return CorrelationResult::Resolved(*candidates.first().expect("one candidate"));
    }
    let all_candidates = evidence
        .iter()
        .flat_map(|item| item.candidate_workstream_ids.iter().copied())
        .filter(|id| view.workstreams.contains_key(id))
        .collect::<BTreeSet<_>>();
    let candidate_tasks = evidence
        .iter()
        .flat_map(|item| item.candidate_task_ids.iter().copied())
        .chain(all_candidates.iter().filter_map(|id| {
            view.workstreams
                .get(id)
                .map(|workstream| workstream.task_id)
        }))
        .filter(|id| view.tasks.contains_key(id))
        .collect::<BTreeSet<_>>();
    let unresolved = UnresolvedWorkstream {
        candidate_task_ids: candidate_tasks.into_iter().collect(),
        candidate_workstream_ids: all_candidates.into_iter().collect(),
        missing_evidence: vec!["unique_scope_consistent_exact_or_strong_evidence".into()],
        conflict_reason: if invalid_authoritative || (authoritative_seen && candidates.is_empty()) {
            "authoritative_evidence_conflict".into()
        } else if candidates.len() > 1 {
            "multiple_authoritative_candidates".into()
        } else {
            "weak_or_no_evidence".into()
        },
        exit_conditions: vec!["provide_explicit_id_or_unique_strong_reference".into()],
        source_watermark,
    };
    CorrelationResult::Unresolved(unresolved)
}

pub fn derive_active_lineage(
    task: &Task,
    workstream: &Workstream,
    repository_view: &RepositoryCurrentView,
) -> Result<ActiveLineageFoundation, WorkIdentityError> {
    if task.identity_confidence == TaskIdentityConfidence::Provisional
        || workstream.task_id != task.task_id
        || workstream.status.is_terminal()
    {
        return Err(WorkIdentityError::ScopeUnresolved);
    }
    if let Some(repository_id) = workstream.repository_instance_id
        && (!repository_view.repositories.contains_key(&repository_id)
            || task
                .scope_memberships
                .iter()
                .find(|membership| membership.repository_instance_id == Some(repository_id))
                .is_none_or(|membership| {
                    workstream
                        .worktree_instance_ids
                        .iter()
                        .any(|id| !membership.worktree_instance_ids.contains(id))
                }))
    {
        return Err(WorkIdentityError::ScopeUnresolved);
    }
    if let Some(worktree_id) = workstream.active_worktree_instance_id {
        let worktree = repository_view
            .worktrees
            .get(&worktree_id)
            .ok_or(WorkIdentityError::ScopeUnresolved)?;
        if Some(worktree.repository_instance_id) != workstream.repository_instance_id
            || matches!(
                worktree.lifecycle,
                WorktreeLifecycle::Removed | WorktreeLifecycle::Pruned
            )
        {
            return Err(WorkIdentityError::ScopeUnresolved);
        }
    }
    Ok(ActiveLineageFoundation {
        task_id: task.task_id,
        task_revision_id: task.revision_id,
        workstream_id: workstream.workstream_id,
        workstream_revision_id: workstream.revision_id,
        repository_instance_id: workstream.repository_instance_id,
        active_worktree_instance_id: workstream.active_worktree_instance_id,
        worktree_lineage_refs: workstream.worktree_lineage_refs.clone(),
        source_watermark: task.source_watermark.max(workstream.source_watermark),
    })
}
