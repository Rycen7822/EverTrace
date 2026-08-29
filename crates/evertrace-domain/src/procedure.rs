use serde::{Deserialize, Serialize};

mod usage;
pub use usage::*;

use crate::{
    config::PromotionLevel,
    ids::{ProcedureId, RepositoryId, WorktreeId},
    revision::RevisionId,
    semantic::{ConstraintExpr, SemanticError},
};

const MAX_TEXT: usize = 2048;
const MAX_ITEMS: usize = 64;
const MAX_REFS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureKind {
    Workflow,
    Diagnostic,
    Guardrail,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProcedureScope {
    Worktree {
        repository_id: RepositoryId,
        worktree_id: WorktreeId,
    },
    Repository {
        repository_id: RepositoryId,
    },
    Global,
}

impl ProcedureScope {
    pub fn contains(&self, next: &Self) -> bool {
        match (*self, *next) {
            (Self::Global, _) => true,
            (
                Self::Repository { repository_id },
                Self::Repository {
                    repository_id: next_repository,
                }
                | Self::Worktree {
                    repository_id: next_repository,
                    ..
                },
            ) => repository_id.as_uuid() == next_repository.as_uuid(),
            (
                Self::Worktree {
                    repository_id,
                    worktree_id,
                },
                Self::Worktree {
                    repository_id: next_repository,
                    worktree_id: next_worktree,
                },
            ) => {
                repository_id.as_uuid() == next_repository.as_uuid()
                    && worktree_id.as_uuid() == next_worktree.as_uuid()
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureWhen {
    pub goals: Vec<String>,
    pub targets: Vec<String>,
    pub signals: Vec<String>,
    pub stage: String,
    pub requires: Vec<String>,
    pub excludes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureBranch {
    pub label: String,
    pub condition: ConstraintExpr,
    pub stages: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureActions {
    pub stages: Vec<String>,
    pub branches: Vec<ProcedureBranch>,
    pub avoid: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureDone {
    pub success: Vec<String>,
    pub abort: Vec<String>,
    pub verify: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureDraft {
    pub scope: ProcedureScope,
    pub title: String,
    pub summary: String,
    pub kind: ProcedureKind,
    pub when: ProcedureWhen,
    pub condition_ir_version: u32,
    pub applicability_expr: ConstraintExpr,
    pub avoid_expr: ConstraintExpr,
    pub completion_expr: ConstraintExpr,
    pub actions: ProcedureActions,
    pub done: ProcedureDone,
    pub pitfalls: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub support_revision_refs: Vec<RevisionId>,
}

impl ProcedureDraft {
    pub fn validate(&self) -> Result<(), SemanticError> {
        if self.condition_ir_version != 1
            || !text(&self.title)
            || !text(&self.summary)
            || !text(&self.when.stage)
            || !ordered_text(&self.when.goals)
            || !ordered_text(&self.when.targets)
            || !ordered_text(&self.when.signals)
            || !ordered_text(&self.when.requires)
            || !ordered_text(&self.when.excludes)
            || !ordered_text(&self.actions.stages)
            || !ordered_text(&self.actions.avoid)
            || self.actions.stages.is_empty()
            || self.actions.branches.len() > MAX_ITEMS
            || !ordered_text(&self.done.success)
            || !ordered_text(&self.done.abort)
            || !ordered_text(&self.done.verify)
            || self.done.success.is_empty()
            || self.done.abort.is_empty()
            || self.done.verify.is_empty()
            || !ordered_text(&self.pitfalls)
            || self.evidence_refs.is_empty()
            || !sorted_text(&self.evidence_refs)
            || self.support_revision_refs.len() > MAX_REFS
            || !strictly_sorted(&self.support_revision_refs)
            || matches!(self.scope, ProcedureScope::Global) && self.support_revision_refs.is_empty()
        {
            return Err(SemanticError::InvalidProcedure);
        }
        for branch in &self.actions.branches {
            if !text(&branch.label) || branch.stages.is_empty() || !ordered_text(&branch.stages) {
                return Err(SemanticError::InvalidProcedure);
            }
            branch.condition.validate()?;
        }
        self.applicability_expr.validate()?;
        self.avoid_expr.validate()?;
        self.completion_expr.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureRevision {
    pub procedure_id: ProcedureId,
    pub revision_id: RevisionId,
    pub parent_revision_id: Option<RevisionId>,
    pub revision_generation: u32,
    pub draft: ProcedureDraft,
    pub source_watermark: u64,
    pub created_at_us: i64,
}

impl ProcedureRevision {
    pub fn validate(&self) -> Result<(), SemanticError> {
        self.draft.validate()?;
        if self.revision_generation == 0
            || self.source_watermark == 0
            || self.created_at_us < 0
            || self.parent_revision_id.is_some() != (self.revision_generation > 1)
        {
            return Err(SemanticError::InvalidProcedure);
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), SemanticError> {
        next.validate()?;
        if next.procedure_id != self.procedure_id
            || next.parent_revision_id != Some(self.revision_id)
            || next.revision_generation != self.revision_generation.saturating_add(1)
            || !self.draft.scope.contains(&next.draft.scope)
            || next.created_at_us < self.created_at_us
            || self.same_behavior(next)
        {
            return Err(SemanticError::InvalidProcedureSuccessor);
        }
        Ok(())
    }

    pub fn same_behavior(&self, next: &Self) -> bool {
        self.draft == next.draft
    }

    pub fn route_text_fields(&self, max_bytes: usize) -> Vec<String> {
        let mut fields = Vec::new();
        let mut used: usize = 0;
        for (label, values) in [
            ("title", std::slice::from_ref(&self.draft.title)),
            ("summary", std::slice::from_ref(&self.draft.summary)),
            ("stage", std::slice::from_ref(&self.draft.when.stage)),
            ("goal", self.draft.when.goals.as_slice()),
            ("target", self.draft.when.targets.as_slice()),
            ("signal", self.draft.when.signals.as_slice()),
            ("requires", self.draft.when.requires.as_slice()),
            ("excludes", self.draft.when.excludes.as_slice()),
            ("done", self.draft.done.success.as_slice()),
            ("abort", self.draft.done.abort.as_slice()),
            ("verify", self.draft.done.verify.as_slice()),
            ("pitfall", self.draft.pitfalls.as_slice()),
        ] {
            for value in values {
                let bytes = label.len() + 1 + value.len();
                if used.saturating_add(bytes).saturating_add(1) > max_bytes {
                    return fields;
                }
                fields.push(format!("{label}:{value}"));
                used += bytes + 1;
            }
        }
        fields
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedurePublicationState {
    ActiveProbationary,
    ReviewHold,
    ActiveStable,
    Suspended,
    RolledBack,
    Superseded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureStateReason {
    Accepted,
    SupportPending,
    SupportRestored,
    ObjectiveSuccesses,
    IrConflict,
    SuspectedHarm,
    ConfirmedHarm,
    EvidenceInvalidated,
    ContractInvalidated,
    Manual,
    Replaced,
    Rollback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureStateEvent {
    pub state_event_id: RevisionId,
    pub procedure_revision_id: RevisionId,
    pub from_state: Option<ProcedurePublicationState>,
    pub to_state: ProcedurePublicationState,
    pub reason: ProcedureStateReason,
    pub resume_state: Option<ProcedurePublicationState>,
    pub evidence_refs: Vec<String>,
    pub created_at_us: i64,
}

impl ProcedureStateEvent {
    pub fn validate(&self) -> Result<(), SemanticError> {
        if self.created_at_us < 0
            || self.evidence_refs.is_empty()
            || !sorted_text(&self.evidence_refs)
            || self.from_state.is_none()
                && self.to_state != ProcedurePublicationState::ActiveProbationary
            || self.from_state.is_none() && self.reason != ProcedureStateReason::Accepted
            || !self.transition_allowed()
        {
            return Err(SemanticError::InvalidProcedurePublication);
        }
        Ok(())
    }

    fn transition_allowed(&self) -> bool {
        use ProcedurePublicationState as S;
        if self.from_state.is_none() {
            return self.resume_state.is_none();
        }
        let from = self.from_state.expect("checked");
        let allowed = matches!(
            (from, self.to_state),
            (
                S::ActiveProbationary,
                S::ReviewHold | S::ActiveStable | S::Suspended | S::RolledBack | S::Superseded,
            ) | (
                S::ActiveStable,
                S::ReviewHold | S::Suspended | S::RolledBack | S::Superseded
            ) | (
                S::ReviewHold,
                S::ActiveProbationary | S::Suspended | S::Superseded
            ) | (
                S::Suspended,
                S::ActiveProbationary | S::RolledBack | S::Superseded
            ) | (S::RolledBack, S::Superseded)
                | (S::Superseded, S::ActiveProbationary)
        );
        let resume_shape = if self.to_state == S::ReviewHold {
            self.resume_state == Some(from)
        } else {
            self.resume_state.is_none()
        };
        let rollback_restore = from != S::Superseded
            || self.to_state != S::ActiveProbationary
            || self.reason == ProcedureStateReason::Rollback;
        allowed && resume_shape && rollback_restore
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureEligibilityEvidence {
    pub independent_successes: u8,
    pub retrospective_contrasts: u8,
    pub objective_verifier_present: bool,
    pub evidence_complete: bool,
    pub non_triviality_passed: bool,
    pub when_done_contract_complete: bool,
    pub unresolved_contradictions: u8,
    pub redundancy_check_passed: bool,
    pub distinct_applicability_contexts: u8,
    pub confirmed_harm: u8,
    pub unresolved_suspected_harm: u8,
    pub applicability_expr_complete: bool,
    pub verifier_observation_ref: Option<crate::ids::SourceObservationId>,
}

pub const PROCEDURE_ELIGIBILITY_VALIDATOR_REVISION: &str = "s24-procedure-eligibility-v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureAutoFullAudit {
    pub validator_revision: String,
    pub eligibility: ProcedureEligibilityEvidence,
    pub procedure_promotion_level: PromotionLevel,
    pub eligible: bool,
}

impl ProcedureAutoFullAudit {
    pub fn validate(&self, global: bool) -> Result<(), SemanticError> {
        let global_full_auto = self.procedure_promotion_level == PromotionLevel::FullAuto;
        let expected = (!global || global_full_auto)
            && self
                .eligibility
                .auto_eligible_full(global, global_full_auto);
        if self.validator_revision != PROCEDURE_ELIGIBILITY_VALIDATOR_REVISION
            || self.eligible != expected
            || !self.eligible
        {
            return Err(SemanticError::InvalidProposal);
        }
        Ok(())
    }
}

impl ProcedureEligibilityEvidence {
    pub fn auto_eligible_full(&self, global: bool, global_full_auto: bool) -> bool {
        self.independent_successes >= if global { 3 } else { 2 }
            && self.retrospective_contrasts >= 1
            && self.objective_verifier_present
            && self.verifier_observation_ref.is_some()
            && self.evidence_complete
            && self.non_triviality_passed
            && self.when_done_contract_complete
            && self.unresolved_contradictions == 0
            && self.redundancy_check_passed
            && (!global
                || global_full_auto
                    && self.distinct_applicability_contexts >= 2
                    && self.confirmed_harm == 0
                    && self.unresolved_suspected_harm == 0
                    && self.applicability_expr_complete)
    }
}

fn text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT
        && !value.chars().any(|character| character.is_control())
}

fn ordered_text(values: &[String]) -> bool {
    values.len() <= MAX_ITEMS && values.iter().all(|value| text(value))
}

fn sorted_text(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_REFS
        && ordered_text(values)
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted(values: &[RevisionId]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
