use evertrace_domain::{
    ids::{
        AttemptId, ExecutionLaneId, IntegrationEventId, TaskId, WorkstreamId, WorktreeId,
        WorktreeSnapshotId, WorktreeTransitionId,
    },
    revision::RevisionId,
    work::{
        Attempt, AttemptAdoptionStatus, AttemptExecutionStatus, AttemptLifecycleStatus,
        AttemptOutcomeState, AttemptVerification, CompetingAttemptGroup, CompetingResolutionStatus,
        InterruptionReason, ResumeStateAssessment, StrategyContract,
    },
};
use evertrace_store::{JournalCommand, JournalEventDraft, JournalPayload};

use super::{WorkCommandContext, WorkIdentityError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttemptResolution<T> {
    NoDelta,
    Revision(Box<T>),
}

fn attempt_command(
    context: WorkCommandContext,
    attempt: Attempt,
) -> Result<JournalCommand, WorkIdentityError> {
    attempt
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    JournalCommand::new(
        context.command_id,
        vec![JournalEventDraft::runtime(
            context.occurred_at_us,
            context.effective_config_hash,
            context.algorithm_revision,
            JournalPayload::AttemptRecorded(Box::new(attempt)),
        )],
    )
    .map_err(Into::into)
}

fn group_command(
    context: WorkCommandContext,
    group: CompetingAttemptGroup,
) -> Result<JournalCommand, WorkIdentityError> {
    group
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    JournalCommand::new(
        context.command_id,
        vec![JournalEventDraft::runtime(
            context.occurred_at_us,
            context.effective_config_hash,
            context.algorithm_revision,
            JournalPayload::CompetingAttemptGroupRecorded(Box::new(group)),
        )],
    )
    .map_err(Into::into)
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
