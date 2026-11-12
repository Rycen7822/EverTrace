use std::collections::BTreeSet;

use evertrace_domain::{
    ids::{
        OperationId, ScopeEffectId, SourceObservationId, TaskId, WorkBindingRevisionId,
        WorkstreamId,
    },
    revision::RevisionId,
    work::{
        AssignmentStatus, PrimaryWorkBinding, SecondaryWorkBinding, Task, TaskIdentityConfidence,
        TaskLifecycle, TaskScopeMembership, WorkBindingRevision,
    },
};
use evertrace_store::{JournalCommand, JournalEventDraft, JournalPayload, WorkIdentityCurrentView};

use super::{WorkCommandContext, WorkIdentityError};

const MAX_EVIDENCE: usize = 64;

/// Root intent comes from a live publisher witness, never an annotation or a caller-supplied confidence.
pub(crate) fn source_root_task(
    context: WorkCommandContext,
    tasks: &std::collections::BTreeMap<TaskId, Task>,
    root: &evertrace_capture::goal_source::RootGoal,
    source: SourceObservationId,
    scopes: Vec<TaskScopeMembership>,
    watermark: u64,
) -> Result<Option<JournalCommand>, WorkIdentityError> {
    let mut matching = tasks.values().filter(|task| {
        task.request_root_refs
            .iter()
            .any(|key| key == root.source_ref())
    });
    let current = matching.next();
    if matching.next().is_some() {
        return Err(WorkIdentityError::Conflict);
    }
    let mut refs = vec![root.source_ref().to_owned(), source.to_string()];
    refs.sort();
    if let Some(current) = current {
        if current.identity_confidence != TaskIdentityConfidence::Explicit {
            return Err(WorkIdentityError::Conflict);
        }
        if current.lifecycle.is_terminal() || watermark <= current.source_watermark {
            return Ok(None);
        }
        let mut memberships = current.scope_memberships.clone();
        for scope in scopes {
            if let Some(member) = memberships
                .iter_mut()
                .find(|member| member.repository_instance_id == scope.repository_instance_id)
            {
                member
                    .worktree_instance_ids
                    .extend(scope.worktree_instance_ids);
                member.worktree_instance_ids.sort();
                member.worktree_instance_ids.dedup();
            } else {
                memberships.push(scope);
            }
        }
        memberships.sort();
        if current.canonical_goal == root.objective() && current.scope_memberships == memberships {
            return Ok(None);
        }
        refs.extend(current.request_root_refs.iter().cloned());
        refs.sort();
        refs.dedup();
        let mut successor = current.clone();
        successor.scope_memberships = memberships;
        successor.revision_id = RevisionId::new_v7();
        successor.predecessor_revision_id = Some(current.revision_id);
        successor.canonical_goal = root.objective().to_owned();
        successor.request_root_refs = refs;
        successor.source_watermark = watermark;
        return super::task::revise_task(
            context,
            current,
            successor,
            if current.canonical_goal == root.objective() {
                super::TypedTaskChange::Scope
            } else {
                super::TypedTaskChange::Goal
            },
            &[source.to_string()],
        )
        .map(Some);
    }
    let task = Task {
        task_id: TaskId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: refs,
        canonical_goal: root.objective().to_owned(),
        scope_memberships: scopes,
        identity_confidence: TaskIdentityConfidence::Explicit,
        lifecycle: TaskLifecycle::Active,
        continuation_of_task_id: None,
        split_from_task_id: None,
        split_into_task_ids: vec![],
        merged_from_task_ids: vec![],
        merged_into_task_id: None,
        created_at_us: context.occurred_at_us,
        closed_at_us: None,
        source_watermark: watermark,
    };
    super::task::create_task(context, task).map(Some)
}

/// The source resolver has independently verified the publisher, controller and
/// declared Work provenance. This establishes Root Task/Workstream ownership,
/// not an Episode boundary, strategy execution, verifier or ExperimentRun.
pub(crate) fn source_root_workstream(
    view: &WorkIdentityCurrentView,
    stream: &evertrace_domain::work::Workstream,
    operation: OperationId,
    scope: ScopeEffectId,
    current: Option<&WorkBindingRevision>,
    sources: &[String],
) -> Result<BindingResolution, WorkIdentityError> {
    if let Some(current) = current {
        current
            .validate()
            .map_err(|_| WorkIdentityError::InvalidInput)?;
        if current.operation_id != operation {
            return Err(WorkIdentityError::InvalidInput);
        }
        let primary = &current.primary_binding;
        if current.assignment_status == AssignmentStatus::Conflicted
            || (current.assignment_status == AssignmentStatus::Resolved
                && (primary.task_id != Some(stream.task_id)
                    || primary.workstream_id != Some(stream.workstream_id)))
            || (current.assignment_status != AssignmentStatus::Resolved
                && (primary.episode_id.is_some()
                    || primary.attempt_id.is_some()
                    || primary.experiment_run_id.is_some()
                    || primary.competing_group_id.is_some()))
        {
            return Ok(BindingResolution::NoDelta);
        }
        if current.assignment_status == AssignmentStatus::Resolved {
            let mut next = current.clone();
            next.evidence_refs.extend_from_slice(sources);
            next.evidence_refs.sort();
            next.evidence_refs.dedup();
            next.scope_effect_refs.push(scope);
            next.scope_effect_refs.sort();
            next.scope_effect_refs.dedup();
            if next.evidence_refs == current.evidence_refs
                && next.scope_effect_refs == current.scope_effect_refs
            {
                return Ok(BindingResolution::NoDelta);
            }
            next.work_binding_revision_id = WorkBindingRevisionId::new_v7();
            next.revision_generation = current
                .revision_generation
                .checked_add(1)
                .ok_or(WorkIdentityError::InvalidInput)?;
            next.predecessor_revision_id = Some(current.work_binding_revision_id);
            current
                .validate_successor(&next)
                .map_err(|_| WorkIdentityError::InvalidInput)?;
            return Ok(BindingResolution::Revision(Box::new(next)));
        }
    }
    let mut scopes = current.map_or_else(Vec::new, |value| value.scope_effect_refs.clone());
    scopes.push(scope);
    scopes.sort();
    scopes.dedup();
    let evidence = sources
        .iter()
        .map(|source| BindingEvidence {
            strength: BindingEvidenceStrength::Strong,
            evidence_ref: source.clone(),
            task_id: stream.task_id,
            workstream_id: stream.workstream_id,
        })
        .collect::<Vec<_>>();
    resolve_binding(
        view,
        operation,
        current,
        scopes,
        current.map_or_else(Vec::new, |value| value.secondary_bindings.clone()),
        &evidence,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingResolution {
    NoDelta,
    Revision(Box<WorkBindingRevision>),
}

impl BindingResolution {
    pub fn into_revision(self) -> Option<WorkBindingRevision> {
        match self {
            Self::NoDelta => None,
            Self::Revision(revision) => Some(*revision),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BindingEvidenceStrength {
    Exact,
    Strong,
    Weak,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BindingEvidence {
    pub strength: BindingEvidenceStrength,
    pub evidence_ref: String,
    pub task_id: TaskId,
    pub workstream_id: WorkstreamId,
}

enum CandidateAssessment {
    Valid(TaskId, WorkstreamId),
    Unknown,
    Contradictory,
}

fn authoritative_candidate(
    view: &WorkIdentityCurrentView,
    evidence: &BindingEvidence,
) -> CandidateAssessment {
    let (Some(task), Some(workstream)) = (
        view.tasks.get(&evidence.task_id),
        view.workstreams.get(&evidence.workstream_id),
    ) else {
        return CandidateAssessment::Unknown;
    };
    if workstream.task_id == task.task_id {
        CandidateAssessment::Valid(task.task_id, workstream.workstream_id)
    } else {
        CandidateAssessment::Contradictory
    }
}

pub fn resolve_binding(
    view: &WorkIdentityCurrentView,
    operation_id: OperationId,
    current: Option<&WorkBindingRevision>,
    scope_effect_refs: Vec<ScopeEffectId>,
    secondary_bindings: Vec<SecondaryWorkBinding>,
    evidence: &[BindingEvidence],
) -> Result<BindingResolution, WorkIdentityError> {
    if evidence.len() > MAX_EVIDENCE {
        return Err(WorkIdentityError::InvalidInput);
    }
    if let Some(current) = current {
        current
            .validate()
            .map_err(|_| WorkIdentityError::InvalidInput)?;
        if current.operation_id != operation_id {
            return Err(WorkIdentityError::InvalidInput);
        }
    }
    let mut ordered = evidence.to_vec();
    ordered.sort();
    if ordered
        .iter()
        .any(|item| item.evidence_ref.trim().is_empty() || item.evidence_ref.len() > 4096)
    {
        return Err(WorkIdentityError::InvalidInput);
    }

    let authoritative = ordered
        .iter()
        .filter(|item| item.strength != BindingEvidenceStrength::Weak)
        .collect::<Vec<_>>();
    let mut candidates = BTreeSet::new();
    let mut unknown_authoritative = false;
    let mut contradictory_authoritative = false;
    for item in authoritative {
        match authoritative_candidate(view, item) {
            CandidateAssessment::Valid(task, stream) => {
                candidates.insert((task, stream));
            }
            CandidateAssessment::Unknown => unknown_authoritative = true,
            CandidateAssessment::Contradictory => contradictory_authoritative = true,
        }
    }

    let (assignment_status, primary_binding) = if contradictory_authoritative
        || candidates.len() > 1
    {
        (AssignmentStatus::Conflicted, PrimaryWorkBinding::default())
    } else if unknown_authoritative {
        (AssignmentStatus::Unresolved, PrimaryWorkBinding::default())
    } else if let Some((task_id, workstream_id)) = candidates.first().copied() {
        let status =
            if view.tasks[&task_id].identity_confidence == TaskIdentityConfidence::Provisional {
                AssignmentStatus::Provisional
            } else {
                AssignmentStatus::Resolved
            };
        (
            status,
            PrimaryWorkBinding {
                task_id: Some(task_id),
                workstream_id: Some(workstream_id),
                ..PrimaryWorkBinding::default()
            },
        )
    } else {
        (AssignmentStatus::Unresolved, PrimaryWorkBinding::default())
    };

    let evidence_refs = ordered
        .into_iter()
        .map(|value| value.evidence_ref)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(current) = current
        && current.primary_binding == primary_binding
        && current.secondary_bindings == secondary_bindings
        && current.scope_effect_refs == scope_effect_refs
        && current.assignment_status == assignment_status
        && current.evidence_refs == evidence_refs
        && current.resolver_version == 1
    {
        return Ok(BindingResolution::NoDelta);
    }
    let revision_generation = current
        .map_or(Some(1), |value| value.revision_generation.checked_add(1))
        .ok_or(WorkIdentityError::InvalidInput)?;
    let binding = WorkBindingRevision {
        work_binding_revision_id: WorkBindingRevisionId::new_v7(),
        operation_id,
        revision_generation,
        predecessor_revision_id: current.map(|value| value.work_binding_revision_id),
        primary_binding,
        secondary_bindings,
        scope_effect_refs,
        assignment_status,
        evidence_refs,
        resolver_version: 1,
    };
    binding
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(BindingResolution::Revision(Box::new(binding)))
}

pub fn record_binding(
    context: WorkCommandContext,
    binding: WorkBindingRevision,
) -> Result<JournalCommand, WorkIdentityError> {
    binding
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    JournalCommand::new(
        context.command_id,
        vec![JournalEventDraft::runtime(
            context.occurred_at_us,
            context.effective_config_hash,
            context.algorithm_revision,
            JournalPayload::WorkBindingRecorded(Box::new(binding)),
        )],
    )
    .map_err(Into::into)
}
