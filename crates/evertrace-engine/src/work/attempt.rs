use std::collections::BTreeSet;

use evertrace_domain::{
    ids::{
        AttemptId, ExecutionLaneId, IntegrationEventId, ResultEvidenceId, TaskId, WorkstreamId,
        WorktreeId, WorktreeSnapshotId, WorktreeTransitionId,
    },
    repository::LineageAssessment,
    revision::RevisionId,
    semantic::{EvidenceCompleteness, ParserStatus, ResultScope, VerifierStatus},
    work::{
        Attempt, AttemptAdoptionStatus, AttemptBindingStatus, AttemptExecutionStatus,
        AttemptLifecycleStatus, AttemptOutcomeState, AttemptVerification, CompetingAttemptGroup,
        CompetingResolutionStatus, InterruptionReason, ResumeStateAssessment, RunContractValidity,
        RunExecutionStatus, RunObservability, StrategyContract,
    },
};
use evertrace_store::projections::MarkNewAttemptCurrentView;
use evertrace_store::{
    AttemptCurrentView, CompetingResolutionEvidenceView, JournalCommand, JournalEventDraft,
    JournalPayload, ProjectionSnapshot, SourceKind,
};

use super::{WorkCommandContext, WorkIdentityError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttemptResolution<T> {
    NoDelta,
    Revision(Box<T>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompetingSelectedCandidate {
    pub(crate) attempt_id: AttemptId,
    pub(crate) evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompetingSelectedSelection {
    pub(crate) group: CompetingAttemptGroup,
    pub(crate) candidates: Vec<CompetingSelectedCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CompetingSelectedLookup {
    Available(Box<CompetingSelectedSelection>),
    Conflict { current_revision_id: RevisionId },
    Unavailable { reason: &'static str },
}

#[derive(Clone, Debug)]
pub(crate) enum CompetingSelectedResolution {
    Revision {
        group: Box<CompetingAttemptGroup>,
        command: JournalCommand,
    },
    Conflict {
        current_revision_id: RevisionId,
    },
    Unavailable {
        reason: &'static str,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MarkNewAttemptLookup {
    Available { source: Box<Attempt> },
    Conflict { current_revision_id: RevisionId },
    NoDelta { current_revision_id: RevisionId },
    Unavailable { reason: &'static str },
}

#[derive(Clone, Debug)]
pub(crate) enum MarkNewAttemptResolution {
    Revision {
        child: Box<Attempt>,
        command: JournalCommand,
    },
    Conflict {
        current_revision_id: RevisionId,
    },
    NoDelta {
        current_revision_id: RevisionId,
    },
    Unavailable {
        reason: &'static str,
    },
}

fn attempt_command(
    context: WorkCommandContext,
    attempt: Attempt,
) -> Result<JournalCommand, WorkIdentityError> {
    attempt_command_with_source(context, attempt, SourceKind::System)
}

fn attempt_command_with_source(
    context: WorkCommandContext,
    attempt: Attempt,
    source_kind: SourceKind,
) -> Result<JournalCommand, WorkIdentityError> {
    attempt
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    let mut event = JournalEventDraft::runtime(
        context.occurred_at_us,
        context.effective_config_hash,
        context.algorithm_revision,
        JournalPayload::AttemptRecorded(Box::new(attempt)),
    );
    event.source_kind = source_kind;
    JournalCommand::new(context.command_id, vec![event]).map_err(Into::into)
}

fn group_command(
    context: WorkCommandContext,
    group: CompetingAttemptGroup,
) -> Result<JournalCommand, WorkIdentityError> {
    group_command_with_source(context, group, SourceKind::System)
}

fn group_command_with_source(
    context: WorkCommandContext,
    group: CompetingAttemptGroup,
    source_kind: SourceKind,
) -> Result<JournalCommand, WorkIdentityError> {
    group
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    let mut event = JournalEventDraft::runtime(
        context.occurred_at_us,
        context.effective_config_hash,
        context.algorithm_revision,
        JournalPayload::CompetingAttemptGroupRecorded(Box::new(group)),
    );
    event.source_kind = source_kind;
    JournalCommand::new(context.command_id, vec![event]).map_err(Into::into)
}

pub fn create_attempt(
    context: WorkCommandContext,
    attempt: Attempt,
) -> Result<JournalCommand, WorkIdentityError> {
    if attempt.revision_generation != 1
        || attempt.predecessor_revision_id.is_some()
        || attempt.episode_id.is_some()
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    attempt_command(context, attempt)
}

pub fn record_attempt_revision(
    context: WorkCommandContext,
    current: &Attempt,
    successor: Attempt,
) -> Result<JournalCommand, WorkIdentityError> {
    current
        .validate_successor(&successor)
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    attempt_command(context, successor)
}

fn successor(current: &Attempt, source_watermark: u64) -> Result<Attempt, WorkIdentityError> {
    if source_watermark <= current.source_watermark {
        return Err(WorkIdentityError::InvalidInput);
    }
    let mut next = current.clone();
    next.predecessor_revision_id = Some(current.revision_id);
    next.revision_id = RevisionId::new_v7();
    next.revision_generation = current
        .revision_generation
        .checked_add(1)
        .ok_or(WorkIdentityError::InvalidInput)?;
    next.source_watermark = source_watermark;
    Ok(next)
}

pub fn revise_execution(
    current: &Attempt,
    status: AttemptExecutionStatus,
    lane_ids: Vec<ExecutionLaneId>,
    interruption_refs: Vec<String>,
    interruption_reason: Option<InterruptionReason>,
    explicit_abandon_refs: Vec<String>,
    source_watermark: u64,
) -> Result<AttemptResolution<Attempt>, WorkIdentityError> {
    if current.execution_status == status
        && current.execution_lane_ids == lane_ids
        && current.interruption_refs == interruption_refs
        && current.interruption_reason == interruption_reason
        && current.explicit_abandon_refs == explicit_abandon_refs
    {
        return Ok(AttemptResolution::NoDelta);
    }
    let allowed = matches!(
        (current.execution_status, status),
        (
            AttemptExecutionStatus::Proposed,
            AttemptExecutionStatus::Active | AttemptExecutionStatus::Abandoned
        ) | (
            AttemptExecutionStatus::Active,
            AttemptExecutionStatus::Interrupted
                | AttemptExecutionStatus::Completed
                | AttemptExecutionStatus::Abandoned
        ) | (
            AttemptExecutionStatus::Interrupted,
            AttemptExecutionStatus::Completed | AttemptExecutionStatus::Abandoned
        )
    );
    if !allowed {
        return Err(WorkIdentityError::InvalidInput);
    }
    let mut next = successor(current, source_watermark)?;
    next.execution_status = status;
    next.execution_lane_ids.extend(lane_ids);
    next.execution_lane_ids.sort();
    next.execution_lane_ids.dedup();
    next.interruption_refs.extend(interruption_refs);
    next.interruption_refs.sort();
    next.interruption_refs.dedup();
    next.interruption_reason = interruption_reason.or(current.interruption_reason);
    next.explicit_abandon_refs.extend(explicit_abandon_refs);
    next.explicit_abandon_refs.sort();
    next.explicit_abandon_refs.dedup();
    if status == AttemptExecutionStatus::Interrupted {
        next.outcome_state = AttemptOutcomeState::Unknown;
    }
    next.validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(AttemptResolution::Revision(Box::new(next)))
}

pub fn revise_adoption(
    current: &Attempt,
    status: AttemptAdoptionStatus,
    integration_event_refs: Vec<IntegrationEventId>,
    source_watermark: u64,
) -> Result<AttemptResolution<Attempt>, WorkIdentityError> {
    if current.adoption_status == status && current.integration_event_refs == integration_event_refs
    {
        return Ok(AttemptResolution::NoDelta);
    }
    let allowed = matches!(
        (current.adoption_status, status),
        (
            AttemptAdoptionStatus::None,
            AttemptAdoptionStatus::Candidate
                | AttemptAdoptionStatus::Selected
                | AttemptAdoptionStatus::Rejected
        ) | (
            AttemptAdoptionStatus::Candidate,
            AttemptAdoptionStatus::Selected | AttemptAdoptionStatus::Rejected
        ) | (
            AttemptAdoptionStatus::Selected,
            AttemptAdoptionStatus::PartiallyIntegrated
                | AttemptAdoptionStatus::Integrated
                | AttemptAdoptionStatus::Rejected
        ) | (
            AttemptAdoptionStatus::PartiallyIntegrated,
            AttemptAdoptionStatus::Integrated | AttemptAdoptionStatus::Rejected
        )
    );
    if !allowed {
        return Err(WorkIdentityError::InvalidInput);
    }
    let mut next = successor(current, source_watermark)?;
    next.adoption_status = status;
    next.integration_event_refs.extend(integration_event_refs);
    next.integration_event_refs.sort();
    next.integration_event_refs.dedup();
    next.validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(AttemptResolution::Revision(Box::new(next)))
}

pub fn revise_verification(
    current: &Attempt,
    verification: AttemptVerification,
    objective_verifier_refs: Vec<String>,
    source_watermark: u64,
) -> Result<AttemptResolution<Attempt>, WorkIdentityError> {
    if current.verification == verification
        && current.parent_verification_refs == objective_verifier_refs
    {
        return Ok(AttemptResolution::NoDelta);
    }
    let allowed = matches!(
        (current.verification, verification),
        (
            AttemptVerification::Unverified,
            AttemptVerification::Inconclusive
                | AttemptVerification::Passed
                | AttemptVerification::Failed
        ) | (
            AttemptVerification::Inconclusive,
            AttemptVerification::Passed | AttemptVerification::Failed
        )
    );
    if !allowed {
        return Err(WorkIdentityError::InvalidInput);
    }
    let mut next = successor(current, source_watermark)?;
    next.verification = verification;
    next.parent_verification_refs
        .extend(objective_verifier_refs);
    next.parent_verification_refs.sort();
    next.parent_verification_refs.dedup();
    next.validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(AttemptResolution::Revision(Box::new(next)))
}

pub fn supersede_attempt(
    current: &Attempt,
    evidence_refs: Vec<String>,
    source_watermark: u64,
) -> Result<AttemptResolution<Attempt>, WorkIdentityError> {
    if current.lifecycle_status == AttemptLifecycleStatus::Superseded
        && current.supersede_evidence_refs == evidence_refs
    {
        return Ok(AttemptResolution::NoDelta);
    }
    let mut next = successor(current, source_watermark)?;
    next.lifecycle_status = AttemptLifecycleStatus::Superseded;
    next.supersede_evidence_refs = evidence_refs;
    next.validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(AttemptResolution::Revision(Box::new(next)))
}

#[allow(clippy::too_many_arguments)]
pub fn resume_same_attempt(
    current: &Attempt,
    new_lane_id: ExecutionLaneId,
    assessment: ResumeStateAssessment,
    resume_event_refs: Vec<String>,
    source_snapshot: Option<WorktreeSnapshotId>,
    target_snapshot: WorktreeSnapshotId,
    transitions: Vec<WorktreeTransitionId>,
    source_watermark: u64,
) -> Result<Attempt, WorkIdentityError> {
    if current.execution_status != AttemptExecutionStatus::Interrupted
        || current.verification == AttemptVerification::Failed
        || current.lifecycle_status == AttemptLifecycleStatus::Superseded
        || current.execution_lane_ids.contains(&new_lane_id)
        || !matches!(
            assessment,
            ResumeStateAssessment::CompatibleSameInstance
                | ResumeStateAssessment::CompatibleLineageTransfer
        )
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    let mut next = successor(current, source_watermark)?;
    next.execution_status = AttemptExecutionStatus::Active;
    next.execution_lane_ids.push(new_lane_id);
    next.execution_lane_ids.sort();
    next.execution_lane_ids.dedup();
    next.resume_state_assessment = Some(assessment);
    next.resume_event_refs.extend(resume_event_refs);
    next.resume_event_refs.sort();
    next.resume_event_refs.dedup();
    next.resume_source_snapshot_id = source_snapshot;
    next.resume_target_snapshot_id = Some(target_snapshot);
    next.worktree_transition_refs.extend(transitions);
    next.worktree_transition_refs.sort();
    next.worktree_transition_refs.dedup();
    next.validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(next)
}

pub fn create_resume_attempt(
    mut attempt: Attempt,
    source: &Attempt,
    assessment: ResumeStateAssessment,
) -> Result<Attempt, WorkIdentityError> {
    if !matches!(
        assessment,
        ResumeStateAssessment::Incompatible | ResumeStateAssessment::Unknown
    ) || attempt.attempt_id == source.attempt_id
        || attempt.task_id != source.task_id
        || attempt.revision_generation != 1
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    attempt.resumes_from_attempt_id = Some(source.attempt_id);
    attempt.resume_state_assessment = Some(assessment);
    attempt.strategy_contract_fingerprint = attempt
        .strategy_contract
        .fingerprint()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    attempt
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(attempt)
}

pub fn compose_attempt(
    mut attempt: Attempt,
    sources: &[Attempt],
) -> Result<Attempt, WorkIdentityError> {
    if sources.len() < 2
        || sources.iter().any(|source| {
            source.task_id != attempt.task_id || source.attempt_id == attempt.attempt_id
        })
        || sources.iter().any(|source| {
            source.strategy_contract_fingerprint == attempt.strategy_contract_fingerprint
        })
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    attempt.composed_from_attempt_ids = sources.iter().map(|source| source.attempt_id).collect();
    attempt.composed_from_attempt_ids.sort();
    attempt.composed_from_attempt_ids.dedup();
    if attempt.composed_from_attempt_ids.len() != sources.len() {
        return Err(WorkIdentityError::InvalidInput);
    }
    attempt.strategy_contract_fingerprint = attempt
        .strategy_contract
        .fingerprint()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    attempt
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(attempt)
}

pub fn create_competing_group(
    context: WorkCommandContext,
    group: CompetingAttemptGroup,
) -> Result<JournalCommand, WorkIdentityError> {
    if group.revision_generation != 1 || group.resolution_status != CompetingResolutionStatus::Open
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    group_command(context, group)
}

pub(crate) fn select_mark_new_attempt(
    snapshot: &ProjectionSnapshot,
    expected_revision_id: RevisionId,
) -> Result<MarkNewAttemptLookup, WorkIdentityError> {
    let current = MarkNewAttemptCurrentView::for_expected_source(snapshot, expected_revision_id)?
        .ok_or(WorkIdentityError::InvalidInput)?;
    if current.source.revision_id != expected_revision_id {
        return Ok(MarkNewAttemptLookup::Conflict {
            current_revision_id: current.source.revision_id,
        });
    }
    if let Some(child) = current.existing_child {
        return Ok(MarkNewAttemptLookup::NoDelta {
            current_revision_id: child.revision_id,
        });
    }
    if current.source.lifecycle_status != AttemptLifecycleStatus::Active
        || current.source.execution_status != AttemptExecutionStatus::Interrupted
    {
        return Ok(MarkNewAttemptLookup::Unavailable {
            reason: "attempt_not_active_interrupted",
        });
    }
    Ok(MarkNewAttemptLookup::Available {
        source: Box::new(current.source),
    })
}

pub(crate) fn mark_new_attempt(
    context: WorkCommandContext,
    snapshot: &ProjectionSnapshot,
    expected_revision_id: RevisionId,
) -> Result<MarkNewAttemptResolution, WorkIdentityError> {
    let source = match select_mark_new_attempt(snapshot, expected_revision_id)? {
        MarkNewAttemptLookup::Available { source } => source,
        MarkNewAttemptLookup::Conflict {
            current_revision_id,
        } => {
            return Ok(MarkNewAttemptResolution::Conflict {
                current_revision_id,
            });
        }
        MarkNewAttemptLookup::NoDelta {
            current_revision_id,
        } => {
            return Ok(MarkNewAttemptResolution::NoDelta {
                current_revision_id,
            });
        }
        MarkNewAttemptLookup::Unavailable { reason } => {
            return Ok(MarkNewAttemptResolution::Unavailable { reason });
        }
    };
    let mut child = new_attempt(
        source.task_id,
        source.workstream_id,
        source.repository_instance_id,
        source.worktree_instance_ids.clone(),
        Vec::new(),
        source.strategy_contract.clone(),
        snapshot.frontier,
    )?;
    child.resume_event_refs = vec![source.revision_id.to_string()];
    let child = create_resume_attempt(child, &source, ResumeStateAssessment::Unknown)?;
    let command = attempt_command_with_source(context, child.clone(), SourceKind::Manual)?;
    Ok(MarkNewAttemptResolution::Revision {
        child: Box::new(child),
        command,
    })
}

pub(crate) fn select_competing_selected(
    snapshot: &ProjectionSnapshot,
    expected_revision_id: RevisionId,
) -> Result<CompetingSelectedLookup, WorkIdentityError> {
    let group_id =
        CompetingResolutionEvidenceView::group_id_for_revision(snapshot, expected_revision_id)?
            .ok_or(WorkIdentityError::InvalidInput)?;
    let attempts = AttemptCurrentView::for_competing_group(snapshot, group_id)?;
    let group = attempts
        .competing_groups
        .get(&group_id)
        .ok_or(WorkIdentityError::InvalidInput)?;
    if expected_revision_id != group.revision_id {
        return Ok(CompetingSelectedLookup::Conflict {
            current_revision_id: group.revision_id,
        });
    }
    if !matches!(
        group.resolution_status,
        CompetingResolutionStatus::Open | CompetingResolutionStatus::Unresolved
    ) {
        return Ok(CompetingSelectedLookup::Unavailable {
            reason: "competing_group_not_open",
        });
    }
    let member_attempts = group
        .member_attempt_ids
        .iter()
        .map(|attempt_id| attempts.attempts.get(attempt_id))
        .collect::<Option<Vec<_>>>()
        .ok_or(WorkIdentityError::InvalidInput)?;
    let evidence = CompetingResolutionEvidenceView::for_attempts(snapshot, member_attempts)?;
    let candidates = group
        .member_attempt_ids
        .iter()
        .filter_map(|attempt_id| {
            let attempt = attempts.attempts.get(attempt_id)?;
            let evidence_refs = competing_selected_evidence(attempt, &evidence)?;
            Some(CompetingSelectedCandidate {
                attempt_id: *attempt_id,
                evidence_refs,
            })
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(CompetingSelectedLookup::Unavailable {
            reason: "competing_group_has_no_objective_candidate",
        });
    }
    Ok(CompetingSelectedLookup::Available(Box::new(
        CompetingSelectedSelection {
            group: group.clone(),
            candidates,
        },
    )))
}

fn competing_selected_evidence(
    attempt: &Attempt,
    current: &CompetingResolutionEvidenceView,
) -> Option<Vec<String>> {
    if attempt.adoption_status != AttemptAdoptionStatus::Integrated
        || attempt.verification != AttemptVerification::Passed
    {
        return None;
    }
    let integration_ids = attempt
        .integration_event_refs
        .iter()
        .filter_map(|id| {
            current.integrations.get(id).and_then(|event| {
                (event.assessment == LineageAssessment::Proven
                    && event.integrated_attempt_ids.contains(&attempt.attempt_id))
                .then_some(*id)
            })
        })
        .collect::<BTreeSet<_>>();
    if integration_ids.is_empty() {
        return None;
    }
    let result_ids = attempt
        .parent_verification_refs
        .iter()
        .filter_map(|reference| reference.parse::<ResultEvidenceId>().ok())
        .filter_map(|result_id| current.current_results.get(&result_id))
        .filter(|result| {
            result.result_scope == ResultScope::Complete
                && result.completeness == EvidenceCompleteness::Complete
                && result.parser_receipt.status == ParserStatus::Parsed
                && result
                    .verifier_receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.status == VerifierStatus::Passed)
                && current
                    .run_revisions
                    .get(&result.experiment_run_revision_id)
                    .is_some_and(|run| {
                        run.run_id == result.experiment_run_id
                            && run.attempt_binding_status == AttemptBindingStatus::Resolved
                            && run.attempt_id == Some(attempt.attempt_id)
                            && run.observability == RunObservability::Full
                            && run.execution_status == RunExecutionStatus::Completed
                            && run.contract_validity == RunContractValidity::Valid
                            && run.workstream_id == attempt.workstream_id
                            && run.strategy_contract_fingerprint
                                == attempt.strategy_contract_fingerprint
                    })
        })
        .map(|result| result.result_evidence_id)
        .collect::<BTreeSet<_>>();
    if result_ids.is_empty() {
        return None;
    }
    let mut evidence_refs = integration_ids
        .iter()
        .map(ToString::to_string)
        .chain(result_ids.iter().map(ToString::to_string))
        .collect::<Vec<_>>();
    evidence_refs.sort();
    evidence_refs.dedup();
    Some(evidence_refs)
}

pub(crate) fn resolve_competing_selected(
    context: WorkCommandContext,
    snapshot: &ProjectionSnapshot,
    expected_revision_id: RevisionId,
    chosen_attempt_id: AttemptId,
) -> Result<CompetingSelectedResolution, WorkIdentityError> {
    let selection = match select_competing_selected(snapshot, expected_revision_id)? {
        CompetingSelectedLookup::Available(selection) => selection,
        CompetingSelectedLookup::Conflict {
            current_revision_id,
        } => {
            return Ok(CompetingSelectedResolution::Conflict {
                current_revision_id,
            });
        }
        CompetingSelectedLookup::Unavailable { reason } => {
            return Ok(CompetingSelectedResolution::Unavailable { reason });
        }
    };
    let candidate = selection
        .candidates
        .iter()
        .find(|candidate| candidate.attempt_id == chosen_attempt_id)
        .ok_or(WorkIdentityError::InvalidInput)?;
    let mut evidence_refs = selection.group.resolution_evidence_refs.clone();
    evidence_refs.extend(candidate.evidence_refs.iter().cloned());
    evidence_refs.sort();
    evidence_refs.dedup();
    let command = resolve_competing_group(
        context,
        &selection.group,
        CompetingResolutionStatus::Selected,
        Some(chosen_attempt_id),
        Vec::new(),
        evidence_refs,
        snapshot
            .frontier
            .max(selection.group.source_watermark)
            .checked_add(1)
            .ok_or(WorkIdentityError::InvalidInput)?,
    )?
    .ok_or(WorkIdentityError::Conflict)?;
    let group = command
        .events()
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::CompetingAttemptGroupRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .next()
        .cloned()
        .ok_or(WorkIdentityError::InvalidInput)?;
    let command = group_command_with_source(context, group.clone(), SourceKind::Manual)?;
    Ok(CompetingSelectedResolution::Revision {
        group: Box::new(group),
        command,
    })
}

pub fn resolve_competing_group(
    context: WorkCommandContext,
    current: &CompetingAttemptGroup,
    status: CompetingResolutionStatus,
    selected_attempt_id: Option<AttemptId>,
    partial: Vec<AttemptId>,
    evidence_refs: Vec<String>,
    source_watermark: u64,
) -> Result<Option<JournalCommand>, WorkIdentityError> {
    if current.resolution_status == status
        && current.selected_attempt_id == selected_attempt_id
        && current.partially_integrated_attempt_ids == partial
        && current.resolution_evidence_refs == evidence_refs
    {
        return Ok(None);
    }
    if source_watermark <= current.source_watermark {
        return Err(WorkIdentityError::InvalidInput);
    }
    let mut next = current.clone();
    next.predecessor_revision_id = Some(current.revision_id);
    next.revision_id = RevisionId::new_v7();
    next.revision_generation = current
        .revision_generation
        .checked_add(1)
        .ok_or(WorkIdentityError::InvalidInput)?;
    next.resolution_status = status;
    next.selected_attempt_id = selected_attempt_id;
    next.partially_integrated_attempt_ids = partial;
    next.resolution_evidence_refs = evidence_refs;
    next.source_watermark = source_watermark;
    current
        .validate_successor(&next)
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(Some(group_command(context, next)?))
}

#[allow(clippy::too_many_arguments)]
pub fn new_attempt(
    task_id: TaskId,
    workstream_id: WorkstreamId,
    repository_instance_id: Option<evertrace_domain::ids::RepositoryId>,
    worktree_instance_ids: Vec<WorktreeId>,
    execution_lane_ids: Vec<ExecutionLaneId>,
    strategy_contract: StrategyContract,
    source_watermark: u64,
) -> Result<Attempt, WorkIdentityError> {
    let fingerprint = strategy_contract
        .fingerprint()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    let attempt = Attempt {
        attempt_id: AttemptId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        revision_generation: 1,
        task_id,
        workstream_id,
        episode_id: None,
        repository_instance_id,
        worktree_instance_ids,
        execution_lane_ids,
        competing_group_ids: vec![],
        experiment_run_ids: vec![],
        execution_status: AttemptExecutionStatus::Proposed,
        adoption_status: AttemptAdoptionStatus::None,
        verification: AttemptVerification::Unverified,
        lifecycle_status: AttemptLifecycleStatus::Active,
        strategy_contract,
        strategy_contract_fingerprint: fingerprint,
        resumes_from_attempt_id: None,
        composed_from_attempt_ids: vec![],
        resume_event_refs: vec![],
        resume_state_assessment: None,
        resume_source_snapshot_id: None,
        resume_target_snapshot_id: None,
        worktree_transition_refs: vec![],
        integration_event_refs: vec![],
        recovery_bundle_refs: vec![],
        recovery_application_refs: vec![],
        work_binding_revision_refs: vec![],
        local_outcome_refs: vec![],
        parent_verification_refs: vec![],
        outcome_refs: vec![],
        outcome_state: AttemptOutcomeState::Unknown,
        interruption_refs: vec![],
        interruption_reason: None,
        explicit_abandon_refs: vec![],
        supersede_evidence_refs: vec![],
        failure_signature: None,
        source_watermark,
    };
    attempt
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(attempt)
}

pub fn record_attempt_and_group(
    context: WorkCommandContext,
    attempts: Vec<Attempt>,
    group: CompetingAttemptGroup,
) -> Result<JournalCommand, WorkIdentityError> {
    for attempt in &attempts {
        attempt
            .validate()
            .map_err(|_| WorkIdentityError::InvalidInput)?;
    }
    group
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    let events = attempts
        .into_iter()
        .map(|attempt| {
            JournalEventDraft::runtime(
                context.occurred_at_us,
                context.effective_config_hash,
                context.algorithm_revision,
                JournalPayload::AttemptRecorded(Box::new(attempt)),
            )
        })
        .chain(std::iter::once(JournalEventDraft::runtime(
            context.occurred_at_us,
            context.effective_config_hash,
            context.algorithm_revision,
            JournalPayload::CompetingAttemptGroupRecorded(Box::new(group)),
        )))
        .collect();
    JournalCommand::new(context.command_id, events).map_err(Into::into)
}
