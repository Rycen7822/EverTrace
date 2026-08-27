use std::collections::BTreeSet;

use evertrace_domain::{
    ids::{OperationId, ScopeEffectId, TaskId, WorkBindingRevisionId, WorkstreamId},
    work::{
        AssignmentStatus, PrimaryWorkBinding, SecondaryWorkBinding, TaskIdentityConfidence,
        WorkBindingRevision,
    },
};
use evertrace_store::{JournalCommand, JournalEventDraft, JournalPayload, WorkIdentityCurrentView};

use super::{WorkCommandContext, WorkIdentityError};

const MAX_EVIDENCE: usize = 64;

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
