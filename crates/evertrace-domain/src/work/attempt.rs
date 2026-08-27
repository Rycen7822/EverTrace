use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalValue, sha256},
    ids::{
        AttemptId, CompetingAttemptGroupId, ExecutionLaneId, ExperimentRunId, IntegrationEventId,
        RecoveryApplicationId, RecoveryBundleId, RepositoryId, TaskId, WorkBindingRevisionId,
        WorkEpisodeId, WorkstreamId, WorktreeId, WorktreeSnapshotId, WorktreeTransitionId,
    },
    revision::RevisionId,
    work::{WorkError, task::strictly_ordered_unique},
};

const MAX_REFS: usize = 64;
const MAX_TEXT: usize = 4096;
const STRATEGY_FINGERPRINT_TAG: &str = "evertrace_attempt_strategy_contract";
const STRATEGY_FINGERPRINT_VERSION: u32 = 1;

fn bounded(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT
}

fn bounded_refs(values: &[String]) -> bool {
    values.len() <= MAX_REFS
        && values.iter().all(|value| bounded(value))
        && strictly_ordered_unique(values)
}

fn strings(values: &[String]) -> CanonicalValue {
    CanonicalValue::Sequence(
        values
            .iter()
            .map(|value| CanonicalValue::String(value.clone()))
            .collect(),
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyContract {
    pub hypothesis: String,
    pub intervention: String,
    pub intervention_family: String,
    pub search_policy_ref: Option<String>,
    pub objective_ref: Option<String>,
    pub expected_effect: String,
    pub target_refs: Vec<String>,
    pub acceptance_boundary_ref: String,
}

impl StrategyContract {
    pub fn validate(&self) -> Result<(), WorkError> {
        if !bounded(&self.hypothesis)
            || !bounded(&self.intervention)
            || !bounded(&self.intervention_family)
            || !bounded(&self.expected_effect)
            || !bounded(&self.acceptance_boundary_ref)
            || self
                .search_policy_ref
                .as_deref()
                .is_some_and(|value| !bounded(value))
            || self
                .objective_ref
                .as_deref()
                .is_some_and(|value| !bounded(value))
            || !bounded_refs(&self.target_refs)
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }

    /// SHA-256 over exactly the canonical, versioned strategy fields above.
    /// Run parameters, active variables, seeds, execution state and evidence
    /// are deliberately outside this byte range.
    pub fn fingerprint(&self) -> Result<[u8; 32], WorkError> {
        self.validate()?;
        sha256(
            STRATEGY_FINGERPRINT_TAG,
            STRATEGY_FINGERPRINT_VERSION,
            &CanonicalValue::Map(vec![
                (
                    "acceptance_boundary_ref".into(),
                    CanonicalValue::String(self.acceptance_boundary_ref.clone()),
                ),
                (
                    "expected_effect".into(),
                    CanonicalValue::String(self.expected_effect.clone()),
                ),
                (
                    "hypothesis".into(),
                    CanonicalValue::String(self.hypothesis.clone()),
                ),
                (
                    "intervention".into(),
                    CanonicalValue::String(self.intervention.clone()),
                ),
                (
                    "intervention_family".into(),
                    CanonicalValue::String(self.intervention_family.clone()),
                ),
                (
                    "objective_ref".into(),
                    self.objective_ref
                        .clone()
                        .map_or(CanonicalValue::Null, CanonicalValue::String),
                ),
                (
                    "search_policy_ref".into(),
                    self.search_policy_ref
                        .clone()
                        .map_or(CanonicalValue::Null, CanonicalValue::String),
                ),
                ("target_refs".into(), strings(&self.target_refs)),
            ]),
        )
        .map_err(|_| WorkError::InvalidWorkIdentity)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptExecutionStatus {
    Proposed,
    Active,
    Interrupted,
    Completed,
    Abandoned,
}

impl AttemptExecutionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Interrupted => "interrupted",
            Self::Completed => "completed",
            Self::Abandoned => "abandoned",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptAdoptionStatus {
    None,
    Candidate,
    Selected,
    PartiallyIntegrated,
    Integrated,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptVerification {
    Unverified,
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptLifecycleStatus {
    Active,
    Superseded,
}

impl AttemptLifecycleStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcomeState {
    Known,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterruptionReason {
    Timeout,
    Cancelled,
    Crashed,
    SourceClosedUnconfirmed,
    Mixed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeStateAssessment {
    CompatibleSameInstance,
    CompatibleLineageTransfer,
    Incompatible,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub attempt_id: AttemptId,
    pub revision_id: RevisionId,
    pub predecessor_revision_id: Option<RevisionId>,
    pub revision_generation: u64,
    pub task_id: TaskId,
    pub workstream_id: WorkstreamId,
    pub episode_id: Option<WorkEpisodeId>,
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_ids: Vec<WorktreeId>,
    pub execution_lane_ids: Vec<ExecutionLaneId>,
    pub competing_group_ids: Vec<CompetingAttemptGroupId>,
    pub experiment_run_ids: Vec<ExperimentRunId>,
    pub execution_status: AttemptExecutionStatus,
    pub adoption_status: AttemptAdoptionStatus,
    pub verification: AttemptVerification,
    pub lifecycle_status: AttemptLifecycleStatus,
    pub strategy_contract: StrategyContract,
    pub strategy_contract_fingerprint: [u8; 32],
    pub resumes_from_attempt_id: Option<AttemptId>,
    pub composed_from_attempt_ids: Vec<AttemptId>,
    pub resume_event_refs: Vec<String>,
    pub resume_state_assessment: Option<ResumeStateAssessment>,
    pub resume_source_snapshot_id: Option<WorktreeSnapshotId>,
    pub resume_target_snapshot_id: Option<WorktreeSnapshotId>,
    pub worktree_transition_refs: Vec<WorktreeTransitionId>,
    pub integration_event_refs: Vec<IntegrationEventId>,
    pub recovery_bundle_refs: Vec<RecoveryBundleId>,
    pub recovery_application_refs: Vec<RecoveryApplicationId>,
    pub work_binding_revision_refs: Vec<WorkBindingRevisionId>,
    pub local_outcome_refs: Vec<String>,
    pub parent_verification_refs: Vec<String>,
    pub outcome_refs: Vec<String>,
    pub outcome_state: AttemptOutcomeState,
    pub interruption_refs: Vec<String>,
    pub interruption_reason: Option<InterruptionReason>,
    pub explicit_abandon_refs: Vec<String>,
    pub supersede_evidence_refs: Vec<String>,
    pub failure_signature: Option<String>,
    pub source_watermark: u64,
}

impl Attempt {
    pub fn validate(&self) -> Result<(), WorkError> {
        self.strategy_contract.validate()?;
        let lists_ok = self.worktree_instance_ids.len() <= MAX_REFS
            && strictly_ordered_unique(&self.worktree_instance_ids)
            && self.execution_lane_ids.len() <= MAX_REFS
            && strictly_ordered_unique(&self.execution_lane_ids)
            && self.competing_group_ids.len() <= MAX_REFS
            && strictly_ordered_unique(&self.competing_group_ids)
            && self.composed_from_attempt_ids.len() <= MAX_REFS
            && strictly_ordered_unique(&self.composed_from_attempt_ids)
            && self.worktree_transition_refs.len() <= MAX_REFS
            && strictly_ordered_unique(&self.worktree_transition_refs)
            && self.integration_event_refs.len() <= MAX_REFS
            && strictly_ordered_unique(&self.integration_event_refs)
            && self.work_binding_revision_refs.len() <= MAX_REFS
            && strictly_ordered_unique(&self.work_binding_revision_refs)
            && [
                &self.resume_event_refs,
                &self.local_outcome_refs,
                &self.parent_verification_refs,
                &self.outcome_refs,
                &self.interruption_refs,
                &self.explicit_abandon_refs,
                &self.supersede_evidence_refs,
            ]
            .into_iter()
            .all(|v| bounded_refs(v));
        let resume_shape = match self.resume_state_assessment {
            None => {
                self.resumes_from_attempt_id.is_none()
                    && self.resume_event_refs.is_empty()
                    && self.resume_source_snapshot_id.is_none()
                    && self.resume_target_snapshot_id.is_none()
            }
            Some(ResumeStateAssessment::CompatibleSameInstance) => {
                self.resumes_from_attempt_id.is_none()
                    && !self.resume_event_refs.is_empty()
                    && self.resume_target_snapshot_id.is_some()
            }
            Some(ResumeStateAssessment::CompatibleLineageTransfer) => {
                self.resumes_from_attempt_id.is_none()
                    && !self.resume_event_refs.is_empty()
                    && self.resume_source_snapshot_id.is_some()
                    && self.resume_target_snapshot_id.is_some()
                    && !self.worktree_transition_refs.is_empty()
            }
            Some(ResumeStateAssessment::Incompatible | ResumeStateAssessment::Unknown) => {
                self.resumes_from_attempt_id.is_some() && !self.resume_event_refs.is_empty()
            }
        };
        let outcome_shape = match self.outcome_state {
            AttemptOutcomeState::Known => {
                !self.local_outcome_refs.is_empty() || !self.outcome_refs.is_empty()
            }
            AttemptOutcomeState::Unknown => self.outcome_refs.is_empty(),
        };
        if self.revision_generation == 0
            || self.source_watermark == 0
            || (self.revision_generation == 1) != self.predecessor_revision_id.is_none()
            || (self.revision_generation == 1 && self.episode_id.is_some())
            || !self.experiment_run_ids.is_empty()
            || !self.recovery_bundle_refs.is_empty()
            || !self.recovery_application_refs.is_empty()
            || self.strategy_contract_fingerprint != self.strategy_contract.fingerprint()?
            || !lists_ok
            || self.resumes_from_attempt_id == Some(self.attempt_id)
            || self.composed_from_attempt_ids.contains(&self.attempt_id)
            || (!self.composed_from_attempt_ids.is_empty()
                && self.composed_from_attempt_ids.len() < 2)
            || !resume_shape
            || (matches!(
                self.execution_status,
                AttemptExecutionStatus::Active
                    | AttemptExecutionStatus::Interrupted
                    | AttemptExecutionStatus::Completed
            ) && self.execution_lane_ids.is_empty())
            || !outcome_shape
            || (self.execution_status == AttemptExecutionStatus::Interrupted
                && (self.execution_lane_ids.is_empty()
                    || self.outcome_state != AttemptOutcomeState::Unknown
                    || !self.outcome_refs.is_empty()
                    || self.interruption_refs.is_empty()
                    || self.interruption_reason.is_none()
                    || !matches!(
                        self.verification,
                        AttemptVerification::Unverified | AttemptVerification::Inconclusive
                    )))
            || (self.execution_status == AttemptExecutionStatus::Abandoned)
                != !self.explicit_abandon_refs.is_empty()
            || matches!(
                self.verification,
                AttemptVerification::Passed | AttemptVerification::Failed
            ) != !self.parent_verification_refs.is_empty()
            || matches!(
                self.adoption_status,
                AttemptAdoptionStatus::PartiallyIntegrated | AttemptAdoptionStatus::Integrated
            ) != !self.integration_event_refs.is_empty()
            || (self.lifecycle_status == AttemptLifecycleStatus::Superseded)
                != !self.supersede_evidence_refs.is_empty()
            || self
                .failure_signature
                .as_deref()
                .is_some_and(|value| !bounded(value))
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }

    pub fn validate_successor(&self, successor: &Self) -> Result<(), WorkError> {
        self.validate()?;
        successor.validate()?;
        let next_generation = self
            .revision_generation
            .checked_add(1)
            .ok_or(WorkError::InvalidWorkIdentity)?;
        let retains = |old: &[String], new: &[String]| old.iter().all(|item| new.contains(item));
        let execution_ok = self.execution_status == successor.execution_status
            || matches!(
                (self.execution_status, successor.execution_status),
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
                    AttemptExecutionStatus::Active
                        | AttemptExecutionStatus::Completed
                        | AttemptExecutionStatus::Abandoned
                )
            );
        let adoption_ok = self.adoption_status == successor.adoption_status
            || matches!(
                (self.adoption_status, successor.adoption_status),
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
        let verification_ok = self.verification == successor.verification
            || matches!(
                (self.verification, successor.verification),
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
        let lifecycle_ok = self.lifecycle_status == successor.lifecycle_status
            || (self.lifecycle_status == AttemptLifecycleStatus::Active
                && successor.lifecycle_status == AttemptLifecycleStatus::Superseded);
        let reopening = self.execution_status == AttemptExecutionStatus::Interrupted
            && successor.execution_status == AttemptExecutionStatus::Active;
        let added_lane = successor
            .execution_lane_ids
            .iter()
            .any(|id| !self.execution_lane_ids.contains(id));
        let added_resume_evidence = successor
            .resume_event_refs
            .iter()
            .any(|value| !self.resume_event_refs.contains(value));
        let resume_ok = !reopening
            || (added_lane
                && added_resume_evidence
                && successor.resume_target_snapshot_id.is_some()
                && matches!(
                    successor.resume_state_assessment,
                    Some(
                        ResumeStateAssessment::CompatibleSameInstance
                            | ResumeStateAssessment::CompatibleLineageTransfer
                    )
                ));
        let worktree_growth_ok = self
            .worktree_instance_ids
            .iter()
            .all(|id| successor.worktree_instance_ids.contains(id))
            && (self.worktree_instance_ids == successor.worktree_instance_ids || reopening);
        if successor.attempt_id != self.attempt_id
            || successor.revision_generation != next_generation
            || successor.predecessor_revision_id != Some(self.revision_id)
            || successor.revision_id == self.revision_id
            || successor.task_id != self.task_id
            || successor.workstream_id != self.workstream_id
            || !matches!(
                (self.episode_id, successor.episode_id),
                (None, None) | (None, Some(_)) | (Some(_), Some(_))
            )
            || self
                .episode_id
                .zip(successor.episode_id)
                .is_some_and(|(old, new)| old != new)
            || successor.repository_instance_id != self.repository_instance_id
            || successor.strategy_contract != self.strategy_contract
            || successor.strategy_contract_fingerprint != self.strategy_contract_fingerprint
            || successor.resumes_from_attempt_id != self.resumes_from_attempt_id
            || successor.composed_from_attempt_ids != self.composed_from_attempt_ids
            || successor.source_watermark <= self.source_watermark
            || !worktree_growth_ok
            || self
                .execution_lane_ids
                .iter()
                .any(|id| !successor.execution_lane_ids.contains(id))
            || self
                .competing_group_ids
                .iter()
                .any(|id| !successor.competing_group_ids.contains(id))
            || self
                .worktree_transition_refs
                .iter()
                .any(|id| !successor.worktree_transition_refs.contains(id))
            || self
                .integration_event_refs
                .iter()
                .any(|id| !successor.integration_event_refs.contains(id))
            || self
                .work_binding_revision_refs
                .iter()
                .any(|id| !successor.work_binding_revision_refs.contains(id))
            || !retains(&self.resume_event_refs, &successor.resume_event_refs)
            || !retains(&self.local_outcome_refs, &successor.local_outcome_refs)
            || !retains(
                &self.parent_verification_refs,
                &successor.parent_verification_refs,
            )
            || !retains(&self.outcome_refs, &successor.outcome_refs)
            || !retains(&self.interruption_refs, &successor.interruption_refs)
            || !retains(
                &self.explicit_abandon_refs,
                &successor.explicit_abandon_refs,
            )
            || !retains(
                &self.supersede_evidence_refs,
                &successor.supersede_evidence_refs,
            )
            || !execution_ok
            || !adoption_ok
            || !verification_ok
            || !lifecycle_ok
            || !resume_ok
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompetingConflictKind {
    OverlappingChange,
    AlternativeStrategy,
    IncompatibleResult,
    SharedStateRace,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompetingResolutionStatus {
    Open,
    Selected,
    PartiallyIntegrated,
    RejectedAll,
    Unresolved,
}

impl CompetingResolutionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Selected => "selected",
            Self::PartiallyIntegrated => "partially_integrated",
            Self::RejectedAll => "rejected_all",
            Self::Unresolved => "unresolved",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSnapshotRef {
    pub attempt_id: AttemptId,
    pub workstream_id: WorkstreamId,
    pub snapshot_id: WorktreeSnapshotId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompetingAttemptGroup {
    pub competing_group_id: CompetingAttemptGroupId,
    pub revision_id: RevisionId,
    pub predecessor_revision_id: Option<RevisionId>,
    pub revision_generation: u64,
    pub task_id: TaskId,
    pub decision_boundary_ref: String,
    pub comparison_contract_ref: Option<String>,
    pub origin_workstream_id: Option<WorkstreamId>,
    pub origin_episode_id: Option<WorkEpisodeId>,
    pub member_workstream_ids: Vec<WorkstreamId>,
    pub member_attempt_ids: Vec<AttemptId>,
    pub candidate_snapshot_refs: Vec<CandidateSnapshotRef>,
    pub target_refs: Vec<String>,
    pub conflict_kind: CompetingConflictKind,
    pub resolution_status: CompetingResolutionStatus,
    pub selected_attempt_id: Option<AttemptId>,
    pub partially_integrated_attempt_ids: Vec<AttemptId>,
    pub resolution_evidence_refs: Vec<String>,
    pub source_watermark: u64,
}

impl CompetingAttemptGroup {
    pub fn validate(&self) -> Result<(), WorkError> {
        let closed = match self.resolution_status {
            CompetingResolutionStatus::Open
            | CompetingResolutionStatus::Unresolved
            | CompetingResolutionStatus::RejectedAll => {
                self.selected_attempt_id.is_none()
                    && self.partially_integrated_attempt_ids.is_empty()
                    && (self.resolution_status == CompetingResolutionStatus::Open)
                        == self.resolution_evidence_refs.is_empty()
            }
            CompetingResolutionStatus::Selected => {
                self.selected_attempt_id.is_some()
                    && self.partially_integrated_attempt_ids.is_empty()
                    && !self.resolution_evidence_refs.is_empty()
            }
            CompetingResolutionStatus::PartiallyIntegrated => {
                self.selected_attempt_id.is_none()
                    && !self.partially_integrated_attempt_ids.is_empty()
                    && !self.resolution_evidence_refs.is_empty()
            }
        };
        if self.revision_generation == 0
            || self.source_watermark == 0
            || (self.revision_generation == 1) != self.predecessor_revision_id.is_none()
            || !bounded(&self.decision_boundary_ref)
            || self
                .comparison_contract_ref
                .as_deref()
                .is_some_and(|v| !bounded(v))
            || self.origin_episode_id.is_some()
            || self.member_attempt_ids.len() < 2
            || self.member_attempt_ids.len() > MAX_REFS
            || !strictly_ordered_unique(&self.member_attempt_ids)
            || self.member_workstream_ids.len() > MAX_REFS
            || !strictly_ordered_unique(&self.member_workstream_ids)
            || self.candidate_snapshot_refs.len() > MAX_REFS
            || !strictly_ordered_unique(&self.candidate_snapshot_refs)
            || !bounded_refs(&self.target_refs)
            || !bounded_refs(&self.resolution_evidence_refs)
            || !strictly_ordered_unique(&self.partially_integrated_attempt_ids)
            || self
                .partially_integrated_attempt_ids
                .iter()
                .any(|id| !self.member_attempt_ids.contains(id))
            || self
                .selected_attempt_id
                .is_some_and(|id| !self.member_attempt_ids.contains(&id))
            || !closed
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }

    pub fn validate_successor(&self, successor: &Self) -> Result<(), WorkError> {
        self.validate()?;
        successor.validate()?;
        let generation = self
            .revision_generation
            .checked_add(1)
            .ok_or(WorkError::InvalidWorkIdentity)?;
        let from_openish = matches!(
            self.resolution_status,
            CompetingResolutionStatus::Open | CompetingResolutionStatus::Unresolved
        );
        let transition_ok = (from_openish
            && matches!(
                successor.resolution_status,
                CompetingResolutionStatus::Unresolved
                    | CompetingResolutionStatus::PartiallyIntegrated
                    | CompetingResolutionStatus::Selected
                    | CompetingResolutionStatus::RejectedAll
            ))
            || (self.resolution_status == CompetingResolutionStatus::PartiallyIntegrated
                && matches!(
                    successor.resolution_status,
                    CompetingResolutionStatus::PartiallyIntegrated
                        | CompetingResolutionStatus::Selected
                        | CompetingResolutionStatus::RejectedAll
                ));
        let partial_progress = self.resolution_status
            != CompetingResolutionStatus::PartiallyIntegrated
            || successor.resolution_status != CompetingResolutionStatus::PartiallyIntegrated
            || (self
                .partially_integrated_attempt_ids
                .iter()
                .all(|id| successor.partially_integrated_attempt_ids.contains(id))
                && (successor.partially_integrated_attempt_ids.len()
                    > self.partially_integrated_attempt_ids.len()
                    || successor.resolution_evidence_refs.len()
                        > self.resolution_evidence_refs.len()));
        if successor.competing_group_id != self.competing_group_id
            || successor.revision_generation != generation
            || successor.predecessor_revision_id != Some(self.revision_id)
            || successor.revision_id == self.revision_id
            || successor.task_id != self.task_id
            || successor.decision_boundary_ref != self.decision_boundary_ref
            || successor.comparison_contract_ref != self.comparison_contract_ref
            || successor.origin_workstream_id != self.origin_workstream_id
            || successor.origin_episode_id != self.origin_episode_id
            || successor.member_workstream_ids != self.member_workstream_ids
            || successor.member_attempt_ids != self.member_attempt_ids
            || successor.candidate_snapshot_refs != self.candidate_snapshot_refs
            || successor.target_refs != self.target_refs
            || successor.conflict_kind != self.conflict_kind
            || successor.source_watermark <= self.source_watermark
            || self
                .resolution_evidence_refs
                .iter()
                .any(|value| !successor.resolution_evidence_refs.contains(value))
            || !transition_ok
            || !partial_progress
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }
}
