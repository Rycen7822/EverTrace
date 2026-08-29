use serde::{Deserialize, Serialize};

use crate::{
    ids::{
        AttemptId, OperationId, ProcedureNegativeEvidenceId, ProcedureUsageId, RepositoryId,
        ScopeEffectId, TaskId, WorkBindingRevisionId, WorkstreamId, WorktreeId,
    },
    revision::RevisionId,
    semantic::{ResultEvidence, ResultFailure, VerifierFailureCode, VerifierStatus},
    work::{Attempt, AttemptAdoptionStatus, AttemptExecutionStatus, AttemptVerification},
};

const MAX_REFS: usize = 64;
const MAX_TEXT: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureCorrelationState {
    Resolved,
    Ambiguous,
    Conflicted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureTruth {
    False,
    Unknown,
    True,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureUsageStage {
    Eligible,
    Routed,
    Returned,
    Claimed,
    Adopted,
    StageAligned,
    Action,
    Completion,
    Outcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureUsageRouteDecision {
    Defer,
    Apply,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureUsagePhase {
    BeforeEntry,
    AtEntry,
    InProgress,
    RecoverableDeviation,
    AlreadyCompleted,
    Incompatible,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureLocalContext {
    pub repository_id: Option<RepositoryId>,
    pub worktree_id: Option<WorktreeId>,
    pub phase: ProcedureUsagePhase,
    pub failure_signature: Option<String>,
}

impl ProcedureLocalContext {
    pub fn validate(&self) -> bool {
        (self.worktree_id.is_none() || self.repository_id.is_some())
            && self
                .failure_signature
                .as_ref()
                .is_none_or(|value| valid_text(value))
    }

    pub fn compatible(&self, other: &Self) -> bool {
        self.repository_id == other.repository_id
            && self.worktree_id == other.worktree_id
            && self.phase == other.phase
            && self.failure_signature == other.failure_signature
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureUsageRevision {
    pub procedure_usage_id: ProcedureUsageId,
    pub usage_revision_id: RevisionId,
    pub predecessor_revision_id: Option<RevisionId>,
    pub revision_generation: u32,
    pub procedure_revision_id: RevisionId,
    pub task_id: TaskId,
    pub workstream_id: WorkstreamId,
    pub exposure_episode_revision_id: RevisionId,
    pub decision_boundary_ref: String,
    pub route_decision: ProcedureUsageRouteDecision,
    pub stage: ProcedureUsageStage,
    pub attempt_ids: Vec<AttemptId>,
    pub action_episode_revision_ids: Vec<RevisionId>,
    pub verification_episode_revision_ids: Vec<RevisionId>,
    pub action_operation_refs: Vec<OperationId>,
    pub verification_operation_refs: Vec<OperationId>,
    pub work_binding_revision_refs: Vec<WorkBindingRevisionId>,
    pub scope_effect_refs: Vec<ScopeEffectId>,
    pub correlation_state: ProcedureCorrelationState,
    pub eligible: ProcedureTruth,
    pub action_aligned: ProcedureTruth,
    pub verifier_aligned: ProcedureTruth,
    pub outcome_supported: ProcedureTruth,
    pub local_context: ProcedureLocalContext,
    pub source_watermark: u64,
    pub evidence_refs: Vec<String>,
    pub created_at_us: i64,
}

impl ProcedureUsageRevision {
    pub fn accepts_adopted_attempt(&self, attempt: &Attempt) -> bool {
        attempt.task_id == self.task_id
            && attempt.workstream_id == self.workstream_id
            && attempt.strategy_contract.search_policy_ref.as_deref()
                == Some(self.procedure_revision_id.to_string().as_str())
            && attempt.strategy_contract.acceptance_boundary_ref == self.decision_boundary_ref
            && matches!(
                attempt.adoption_status,
                AttemptAdoptionStatus::Selected
                    | AttemptAdoptionStatus::PartiallyIntegrated
                    | AttemptAdoptionStatus::Integrated
            )
    }

    pub fn validate(&self) -> bool {
        self.revision_generation > 0
            && (self.revision_generation == 1) == self.predecessor_revision_id.is_none()
            && valid_text(&self.decision_boundary_ref)
            && self.source_watermark > 0
            && self.created_at_us >= 0
            && self.local_context.validate()
            && valid_ids(&self.attempt_ids)
            && valid_ids(&self.action_episode_revision_ids)
            && valid_ids(&self.verification_episode_revision_ids)
            && valid_ids(&self.action_operation_refs)
            && valid_ids(&self.verification_operation_refs)
            && valid_ids(&self.work_binding_revision_refs)
            && valid_ids(&self.scope_effect_refs)
            && !self.evidence_refs.is_empty()
            && valid_texts(&self.evidence_refs)
            && (self.route_decision != ProcedureUsageRouteDecision::Defer
                || self.stage <= ProcedureUsageStage::Returned)
            && (self.stage >= ProcedureUsageStage::Action
                || self.action_aligned != ProcedureTruth::True)
            && (self.stage >= ProcedureUsageStage::Completion
                || self.verifier_aligned != ProcedureTruth::True)
            && (self.stage == ProcedureUsageStage::Outcome
                || self.outcome_supported != ProcedureTruth::True)
            && (self.outcome_supported != ProcedureTruth::True
                || self.action_aligned == ProcedureTruth::True
                    && self.verifier_aligned == ProcedureTruth::True
                    && self.correlation_state == ProcedureCorrelationState::Resolved)
    }

    pub fn validate_successor(&self, next: &Self) -> bool {
        self.validate()
            && next.validate()
            && self.procedure_usage_id == next.procedure_usage_id
            && self.procedure_revision_id == next.procedure_revision_id
            && self.task_id == next.task_id
            && self.workstream_id == next.workstream_id
            && self.exposure_episode_revision_id == next.exposure_episode_revision_id
            && self.decision_boundary_ref == next.decision_boundary_ref
            && self.route_decision == next.route_decision
            && self.local_context == next.local_context
            && next.predecessor_revision_id == Some(self.usage_revision_id)
            && next.revision_generation == self.revision_generation + 1
            && next.stage >= self.stage
            && next.source_watermark >= self.source_watermark
            && next.created_at_us >= self.created_at_us
            && retains(&self.attempt_ids, &next.attempt_ids)
            && retains(
                &self.action_episode_revision_ids,
                &next.action_episode_revision_ids,
            )
            && retains(
                &self.verification_episode_revision_ids,
                &next.verification_episode_revision_ids,
            )
            && retains(&self.action_operation_refs, &next.action_operation_refs)
            && retains(
                &self.verification_operation_refs,
                &next.verification_operation_refs,
            )
            && retains(
                &self.work_binding_revision_refs,
                &next.work_binding_revision_refs,
            )
            && retains(&self.scope_effect_refs, &next.scope_effect_refs)
            && retains(&self.evidence_refs, &next.evidence_refs)
            && truth_progress(self.eligible, next.eligible)
            && truth_progress(self.action_aligned, next.action_aligned)
            && truth_progress(self.verifier_aligned, next.verifier_aligned)
            && truth_progress(self.outcome_supported, next.outcome_supported)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureNegativeLevel {
    Ineffective,
    SuspectedHarm,
    ConfirmedHarm,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureAttributionBasis {
    NoAdditionalHarm,
    ResolvedLocalized,
    ContextUnbounded,
    CrossContextRepeated,
    ReplayInvariantViolation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureNegativeDecisionSource {
    AttemptNoSupportedOutcome,
    AdoptedAttemptFailed,
    TypedReplayInvariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcedureNegativeClassification {
    pub level: ProcedureNegativeLevel,
    pub attribution_basis: ProcedureAttributionBasis,
    pub decision_source: ProcedureNegativeDecisionSource,
    pub localized: bool,
}

pub const fn derive_negative_classification(
    fact: ProcedureNegativeFact,
    localizable: bool,
    cross_context_repeated: bool,
) -> ProcedureNegativeClassification {
    match fact {
        ProcedureNegativeFact::ReplayInvariantViolation => ProcedureNegativeClassification {
            level: ProcedureNegativeLevel::ConfirmedHarm,
            attribution_basis: ProcedureAttributionBasis::ReplayInvariantViolation,
            decision_source: ProcedureNegativeDecisionSource::TypedReplayInvariant,
            localized: false,
        },
        ProcedureNegativeFact::Ineffective => ProcedureNegativeClassification {
            level: ProcedureNegativeLevel::Ineffective,
            attribution_basis: ProcedureAttributionBasis::NoAdditionalHarm,
            decision_source: ProcedureNegativeDecisionSource::AttemptNoSupportedOutcome,
            localized: false,
        },
        ProcedureNegativeFact::AdoptedAttemptFailed if cross_context_repeated => {
            ProcedureNegativeClassification {
                level: ProcedureNegativeLevel::SuspectedHarm,
                attribution_basis: ProcedureAttributionBasis::CrossContextRepeated,
                decision_source: ProcedureNegativeDecisionSource::AdoptedAttemptFailed,
                localized: false,
            }
        }
        ProcedureNegativeFact::AdoptedAttemptFailed if localizable => {
            ProcedureNegativeClassification {
                level: ProcedureNegativeLevel::SuspectedHarm,
                attribution_basis: ProcedureAttributionBasis::ResolvedLocalized,
                decision_source: ProcedureNegativeDecisionSource::AdoptedAttemptFailed,
                localized: true,
            }
        }
        ProcedureNegativeFact::AdoptedAttemptFailed => ProcedureNegativeClassification {
            level: ProcedureNegativeLevel::SuspectedHarm,
            attribution_basis: ProcedureAttributionBasis::ContextUnbounded,
            decision_source: ProcedureNegativeDecisionSource::AdoptedAttemptFailed,
            localized: false,
        },
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureNegativeReviewStatus {
    Pending,
    Upheld,
    Dismissed,
    Superseded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcedureNegativeFact {
    Ineffective,
    AdoptedAttemptFailed,
    ReplayInvariantViolation,
}

pub fn classify_negative_fact(
    usage: &ProcedureUsageRevision,
    attempt: &Attempt,
    evidence_refs: &[String],
    results: &[&ResultEvidence],
) -> Option<ProcedureNegativeFact> {
    let has_verification = evidence_refs
        .iter()
        .any(|reference| attempt.parent_verification_refs.contains(reference));
    let has_outcome = evidence_refs
        .iter()
        .any(|reference| attempt.outcome_refs.contains(reference));
    let tied = has_outcome
        && evidence_refs.iter().all(|reference| {
            attempt.parent_verification_refs.contains(reference)
                || attempt.outcome_refs.contains(reference)
        });
    if attempt.verification == AttemptVerification::Failed
        && has_verification
        && tied
        && results.iter().all(|result| {
            matches!(
                result.failure,
                Some(ResultFailure::Verifier(
                    VerifierFailureCode::DeterministicReparseMismatch
                ))
            )
        })
    {
        Some(ProcedureNegativeFact::ReplayInvariantViolation)
    } else if attempt.verification == AttemptVerification::Passed
        && usage.outcome_supported != ProcedureTruth::True
        && tied
        && results.iter().all(|result| {
            result.failure.is_none()
                && result
                    .verifier_receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.status == VerifierStatus::Passed)
        })
    {
        Some(ProcedureNegativeFact::Ineffective)
    } else if attempt.verification == AttemptVerification::Failed
        && attempt.execution_status != AttemptExecutionStatus::Interrupted
        && attempt.failure_signature.is_some()
        && has_verification
        && tied
        && results.iter().all(|result| {
            result.failure.is_none()
                && result
                    .verifier_receipt
                    .as_ref()
                    .is_none_or(|receipt| receipt.status != VerifierStatus::Passed)
        })
    {
        Some(ProcedureNegativeFact::AdoptedAttemptFailed)
    } else {
        None
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureNegativeEvidence {
    pub negative_evidence_id: ProcedureNegativeEvidenceId,
    pub level: ProcedureNegativeLevel,
    pub procedure_revision_id: RevisionId,
    pub procedure_usage_id: ProcedureUsageId,
    pub task_id: TaskId,
    pub session_id: String,
    pub evidence_refs: Vec<String>,
    pub observed_effect: String,
    pub expected_effect: String,
    pub confounders: Vec<String>,
    pub attribution_basis: ProcedureAttributionBasis,
    pub decision_source: ProcedureNegativeDecisionSource,
    pub local_context: Option<ProcedureLocalContext>,
    pub created_at_us: i64,
}

impl ProcedureNegativeEvidence {
    pub fn validate(&self) -> bool {
        valid_text(&self.session_id)
            && !self.evidence_refs.is_empty()
            && valid_texts(&self.evidence_refs)
            && valid_text(&self.observed_effect)
            && valid_text(&self.expected_effect)
            && valid_texts(&self.confounders)
            && self.created_at_us >= 0
            && self
                .local_context
                .as_ref()
                .is_none_or(|value| value.validate())
            && match self.level {
                ProcedureNegativeLevel::Ineffective => {
                    self.attribution_basis == ProcedureAttributionBasis::NoAdditionalHarm
                        && self.decision_source
                            == ProcedureNegativeDecisionSource::AttemptNoSupportedOutcome
                        && self.local_context.is_none()
                        && self.confounders.is_empty()
                }
                ProcedureNegativeLevel::SuspectedHarm => {
                    matches!(
                        self.attribution_basis,
                        ProcedureAttributionBasis::ResolvedLocalized
                            | ProcedureAttributionBasis::ContextUnbounded
                            | ProcedureAttributionBasis::CrossContextRepeated
                    ) && self.decision_source
                        == ProcedureNegativeDecisionSource::AdoptedAttemptFailed
                        && !self.confounders.is_empty()
                }
                ProcedureNegativeLevel::ConfirmedHarm => {
                    self.attribution_basis == ProcedureAttributionBasis::ReplayInvariantViolation
                        && self.decision_source
                            == ProcedureNegativeDecisionSource::TypedReplayInvariant
                }
            }
            && (self.attribution_basis == ProcedureAttributionBasis::ResolvedLocalized)
                == self.local_context.is_some()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureNegativeReviewEvent {
    pub review_event_id: RevisionId,
    pub negative_evidence_id: ProcedureNegativeEvidenceId,
    pub predecessor_review_event_id: Option<RevisionId>,
    pub review_generation: u32,
    pub status: ProcedureNegativeReviewStatus,
    pub successor_usage_revision_id: Option<RevisionId>,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub created_at_us: i64,
}

impl ProcedureNegativeReviewEvent {
    pub fn validate(&self) -> bool {
        self.review_generation > 0
            && (self.review_generation == 1) == self.predecessor_review_event_id.is_none()
            && (self.review_generation != 1
                || self.status == ProcedureNegativeReviewStatus::Pending)
            && (self.status == ProcedureNegativeReviewStatus::Superseded)
                == self.successor_usage_revision_id.is_some()
            && valid_text(&self.reason)
            && !self.evidence_refs.is_empty()
            && valid_texts(&self.evidence_refs)
            && self.created_at_us >= 0
    }
}

fn truth_progress(current: ProcedureTruth, next: ProcedureTruth) -> bool {
    current != ProcedureTruth::True || next == ProcedureTruth::True
}

fn valid_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
}

fn valid_texts(values: &[String]) -> bool {
    values.len() <= MAX_REFS
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values.iter().all(|value| valid_text(value))
}

fn valid_ids<T: Ord>(values: &[T]) -> bool {
    values.len() <= MAX_REFS && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn retains<T: Ord>(current: &[T], next: &[T]) -> bool {
    current
        .iter()
        .all(|value| next.binary_search(value).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage() -> ProcedureUsageRevision {
        ProcedureUsageRevision {
            procedure_usage_id: ProcedureUsageId::new_v7(),
            usage_revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            revision_generation: 1,
            procedure_revision_id: RevisionId::new_v7(),
            task_id: TaskId::new_v7(),
            workstream_id: WorkstreamId::new_v7(),
            exposure_episode_revision_id: RevisionId::new_v7(),
            decision_boundary_ref: "boundary".into(),
            route_decision: ProcedureUsageRouteDecision::Apply,
            stage: ProcedureUsageStage::Returned,
            attempt_ids: Vec::new(),
            action_episode_revision_ids: Vec::new(),
            verification_episode_revision_ids: Vec::new(),
            action_operation_refs: Vec::new(),
            verification_operation_refs: Vec::new(),
            work_binding_revision_refs: Vec::new(),
            scope_effect_refs: Vec::new(),
            correlation_state: ProcedureCorrelationState::Resolved,
            eligible: ProcedureTruth::True,
            action_aligned: ProcedureTruth::False,
            verifier_aligned: ProcedureTruth::Unknown,
            outcome_supported: ProcedureTruth::Unknown,
            local_context: ProcedureLocalContext {
                repository_id: None,
                worktree_id: None,
                phase: ProcedureUsagePhase::AtEntry,
                failure_signature: None,
            },
            source_watermark: 1,
            evidence_refs: vec!["exposure".into()],
            created_at_us: 1,
        }
    }

    #[test]
    fn returned_is_not_used_and_late_evidence_can_resolve_outcome() {
        let returned = usage();
        assert!(returned.validate());
        assert_ne!(returned.action_aligned, ProcedureTruth::True);
        assert_ne!(returned.outcome_supported, ProcedureTruth::True);
        let mut outcome = returned.clone();
        outcome.usage_revision_id = RevisionId::new_v7();
        outcome.predecessor_revision_id = Some(returned.usage_revision_id);
        outcome.revision_generation = 2;
        outcome.stage = ProcedureUsageStage::Outcome;
        outcome.action_operation_refs = vec![OperationId::new_v7()];
        outcome.verification_operation_refs = vec![OperationId::new_v7()];
        outcome.action_aligned = ProcedureTruth::True;
        outcome.verifier_aligned = ProcedureTruth::True;
        outcome.outcome_supported = ProcedureTruth::True;
        outcome.source_watermark = 2;
        outcome.evidence_refs.push("verifier".into());
        outcome.evidence_refs.sort();
        assert!(returned.validate_successor(&outcome));
        outcome.route_decision = ProcedureUsageRouteDecision::Defer;
        assert!(!outcome.validate());
    }

    #[test]
    fn confirmed_harm_requires_closed_strong_attribution() {
        let mut negative = ProcedureNegativeEvidence {
            negative_evidence_id: ProcedureNegativeEvidenceId::new_v7(),
            level: ProcedureNegativeLevel::ConfirmedHarm,
            procedure_revision_id: RevisionId::new_v7(),
            procedure_usage_id: ProcedureUsageId::new_v7(),
            task_id: TaskId::new_v7(),
            session_id: "session".into(),
            evidence_refs: vec!["evidence".into()],
            observed_effect: "violation".into(),
            expected_effect: "invariant".into(),
            confounders: Vec::new(),
            attribution_basis: ProcedureAttributionBasis::ReplayInvariantViolation,
            decision_source: ProcedureNegativeDecisionSource::TypedReplayInvariant,
            local_context: None,
            created_at_us: 1,
        };
        assert!(negative.validate());
        negative.attribution_basis = ProcedureAttributionBasis::ResolvedLocalized;
        assert!(!negative.validate());
    }
}
