use std::collections::{BTreeMap, BTreeSet};

use evertrace_domain::{
    procedure::{
        ProcedureContextAnchor, ProcedureContextEffectProjection, ProcedureEffect,
        ProcedureEffectContext, ProcedureEffectEvidenceClass, ProcedurePublicationState,
    },
    query::{GateStatus, RetrievalLayer, SearchContext, production_retrieval_layer},
    revision::RevisionId,
    semantic::{ConstraintField, ConstraintState, ConstraintTruth},
};
use evertrace_store::ProjectionSnapshot;

use crate::semantic::SemanticServiceError;

use super::{
    ProcedureCandidate, ProcedureDecision, ProcedureGuidanceMode, ProcedurePhase,
    ProcedureRouteResult, ProcedureUsageCurrentView, route_procedures_with_quarantine,
};

pub const fn procedure_effect_gate() -> GateStatus {
    GateStatus::NotCharacterized
}

pub const fn procedure_effect_base_layer() -> RetrievalLayer {
    production_retrieval_layer()
}

pub fn compile_controlled_effect(
    snapshot: &ProjectionSnapshot,
    procedure_revision_id: RevisionId,
) -> Result<Vec<ProcedureContextEffectProjection>, SemanticServiceError> {
    snapshot
        .compile_controlled_procedure_effect(procedure_revision_id)
        .map_err(|_| SemanticServiceError::InvalidInput)
}

#[allow(clippy::too_many_arguments)]
pub fn route_procedures_with_effects(
    usage_view: &ProcedureUsageCurrentView,
    local_context: &evertrace_domain::procedure::ProcedureLocalContext,
    context: &SearchContext,
    candidates: Vec<ProcedureCandidate>,
    current: &ConstraintState,
    previous: Option<&ConstraintState>,
    scenario_fresh: bool,
    unresolved_competing: bool,
    sibling_exploration: bool,
    explicit_reuse: bool,
) -> ProcedureRouteResult {
    route_procedures_with_quarantine(
        usage_view,
        local_context,
        context,
        candidates,
        current,
        previous,
        scenario_fresh,
        unresolved_competing,
        sibling_exploration,
        explicit_reuse,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn route_procedures_with_passed_effects_diagnostic(
    usage_view: &ProcedureUsageCurrentView,
    local_context: &evertrace_domain::procedure::ProcedureLocalContext,
    effect_context: &ProcedureEffectContext,
    effects: &[ProcedureContextEffectProjection],
    context: &SearchContext,
    mut candidates: Vec<ProcedureCandidate>,
    current: &ConstraintState,
    previous: Option<&ConstraintState>,
    scenario_fresh: bool,
    unresolved_competing: bool,
    sibling_exploration: bool,
    explicit_reuse: bool,
) -> ProcedureRouteResult {
    let mut unique = BTreeMap::new();
    for effect in effects {
        if effect.validate().is_err() {
            return route_procedures_with_effects(
                usage_view,
                local_context,
                context,
                candidates,
                current,
                previous,
                scenario_fresh,
                unresolved_competing,
                sibling_exploration,
                explicit_reuse,
            );
        }
        let key = (
            effect.procedure_revision_id,
            effect.context_fingerprint_hash,
            effect.evidence_class,
        );
        unique
            .entry(key)
            .and_modify(|value: &mut Option<&ProcedureContextEffectProjection>| {
                if value.is_some_and(|existing| existing != effect) {
                    *value = None;
                }
            })
            .or_insert(Some(effect));
    }
    for candidate in &mut candidates {
        let fields = candidate
            .revision
            .draft
            .applicability_expr
            .referenced_fields();
        if context_matches(effect_context, &fields, local_context, context, current)
            && hard_eligible(candidate, context, current, previous, scenario_fresh)
            && unique.values().flatten().any(|effect| {
                effect.procedure_revision_id == candidate.revision.revision_id
                    && effect.evidence_class == ProcedureEffectEvidenceClass::ControlledComparison
                    && effect.effect == ProcedureEffect::Positive
                    && effect.exact_compatible(effect_context, &fields)
            })
        {
            candidate.lexical_rank = 0;
        }
    }
    let candidate_fields = candidates
        .iter()
        .map(|candidate| {
            (
                candidate.revision.revision_id,
                candidate
                    .revision
                    .draft
                    .applicability_expr
                    .referenced_fields(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut result = route_procedures_with_quarantine(
        usage_view,
        local_context,
        context,
        candidates,
        current,
        previous,
        scenario_fresh,
        unresolved_competing,
        sibling_exploration,
        explicit_reuse,
    );
    for item in &mut result.items {
        let Some(fields) = candidate_fields.get(&item.revision_id) else {
            continue;
        };
        let negative = unique.values().flatten().any(|effect| {
            effect.procedure_revision_id == item.revision_id
                && effect.evidence_class == ProcedureEffectEvidenceClass::ControlledComparison
                && effect.effect == ProcedureEffect::Negative
                && effect.exact_compatible(effect_context, fields)
        });
        if item.decision != ProcedureDecision::Apply || !negative {
            continue;
        }
        item.actions = None;
        if let Some(done) = &mut item.done {
            done.success.clear();
        }
        if has_guardrail(item) {
            item.decision = ProcedureDecision::Defer;
            item.route_proof.decision = ProcedureDecision::Defer;
            item.mode = ProcedureGuidanceMode::GuardrailOnly;
            item.reason = "controlled_negative";
        } else {
            item.decision = ProcedureDecision::Reject;
            item.route_proof.decision = ProcedureDecision::Reject;
            item.reason = "controlled_negative_no_guardrail";
        }
    }
    result.items.sort_by_key(super::route_rank);
    let apply = result
        .items
        .iter()
        .position(|item| item.decision == ProcedureDecision::Apply)
        .map(|index| result.items.remove(index));
    let apply_probationary = apply
        .as_ref()
        .is_some_and(|item| item.publication == ProcedurePublicationState::ActiveProbationary);
    let defer = result.items.drain(..).find(|item| {
        item.decision == ProcedureDecision::Defer
            && !(apply_probationary
                && item.publication == ProcedurePublicationState::ActiveProbationary)
    });
    result.items.clear();
    result.items.extend(apply);
    result.items.extend(defer);
    if result.items.is_empty() {
        result.status = "no_applicable_procedure";
    }
    result
}

fn context_matches(
    effect: &ProcedureEffectContext,
    fields: &BTreeSet<ConstraintField>,
    local: &evertrace_domain::procedure::ProcedureLocalContext,
    search: &SearchContext,
    current: &ConstraintState,
) -> bool {
    let operands = current
        .bindings
        .iter()
        .filter(|binding| fields.contains(&binding.field))
        .cloned()
        .collect::<Vec<_>>();
    effect.complete_for(fields)
        && effect.operands == operands
        && search.task_id == Some(effect.task_id)
        && local.phase == effect.phase_kind
        && local.failure_signature == effect.failure_signature
        && match effect.anchor {
            ProcedureContextAnchor::Repository {
                repository_id,
                worktree_id,
                ..
            } => {
                search.repository_id == Some(repository_id)
                    && search.worktree_id == Some(worktree_id)
                    && local.repository_id == Some(repository_id)
                    && local.worktree_id == Some(worktree_id)
            }
            ProcedureContextAnchor::NonRepository { .. } => {
                search.repository_id.is_none()
                    && search.worktree_id.is_none()
                    && local.repository_id.is_none()
                    && local.worktree_id.is_none()
            }
        }
}

fn hard_eligible(
    candidate: &ProcedureCandidate,
    context: &SearchContext,
    current: &ConstraintState,
    previous: Option<&ConstraintState>,
    scenario_fresh: bool,
) -> bool {
    scenario_fresh
        && super::scope_matches(candidate.revision.draft.scope, context)
        && matches!(
            candidate.publication,
            ProcedurePublicationState::ActiveProbationary | ProcedurePublicationState::ActiveStable
        )
        && (!matches!(
            candidate.revision.draft.scope,
            evertrace_domain::procedure::ProcedureScope::Global
        ) || candidate.global_support
            == Some(evertrace_domain::semantic::GlobalSupportState::Valid))
        && !matches!(
            candidate.phase,
            ProcedurePhase::AlreadyCompleted | ProcedurePhase::Incompatible
        )
        && candidate
            .revision
            .draft
            .applicability_expr
            .evaluate(current, previous)
            == ConstraintTruth::True
        && candidate
            .revision
            .draft
            .avoid_expr
            .evaluate(current, previous)
            == ConstraintTruth::False
        && candidate
            .revision
            .draft
            .completion_expr
            .evaluate(current, previous)
            == ConstraintTruth::False
}

fn has_guardrail(item: &super::RoutedProcedure) -> bool {
    !item.avoid.is_empty()
        || item
            .done
            .as_ref()
            .is_some_and(|done| !done.abort.is_empty() || !done.verify.is_empty())
        || !item.excludes.is_empty()
        || !item.pitfalls.is_empty()
}
