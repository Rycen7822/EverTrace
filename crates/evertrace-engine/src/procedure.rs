use evertrace_domain::{
    config::{GlobalPromotionConfig, PromotionLevel},
    ids::ProcedureId,
    procedure::{
        PROCEDURE_ELIGIBILITY_VALIDATOR_REVISION, ProcedureActions, ProcedureAutoFullAudit,
        ProcedureDone, ProcedureEligibilityEvidence, ProcedurePublicationState, ProcedureRevision,
        ProcedureScope, ProcedureStateEvent, ProcedureStateReason,
    },
    query::{SearchContext, SearchIntent},
    revision::RevisionId,
    semantic::{
        AcceptedProposalTarget, AtomScope, ConstraintState, ConstraintTruth, GlobalSupportState,
        ProcedureProposalPayload, ProposalAcceptanceAuthority, ProposalEligibility,
        ProposalPayload, ProposalTargetId, ProposalTargetKind,
    },
};
use evertrace_store::{
    JournalCommand, JournalEventDraft, JournalPayload, ProjectionSnapshot, SemanticCurrentView,
};

use crate::semantic::{
    AtomAcceptanceContext, ProposalAcceptanceAudit, ProposalCommandContext, SemanticServiceError,
    accepted_proposal_successor, accepted_proposal_successor_with_audit, global_support_payloads,
    validate_current_support_refs,
};

const S24_ALGORITHM: &str = "s24-procedure-v1";
const MAX_CANDIDATES: usize = 64;

#[derive(Clone, Debug)]
pub enum ProcedureAcceptanceContext {
    Manual(AtomAcceptanceContext),
    AutoFull(ProcedureEligibilityEvidence),
}

#[derive(Debug)]
pub enum ProcedureAcceptanceResolution {
    NoDelta,
    Command {
        proposal: Box<evertrace_domain::semantic::RevisionProposal>,
        procedure: Box<ProcedureRevision>,
        state: Box<ProcedureStateEvent>,
        command: JournalCommand,
    },
}

#[allow(clippy::too_many_arguments)]
pub fn accept_procedure(
    view: &SemanticCurrentView,
    context: ProposalCommandContext,
    proposal_id: evertrace_domain::ids::RevisionProposalId,
    acceptance_context: ProcedureAcceptanceContext,
    current: Option<&ProcedureRevision>,
    current_publication: Option<ProcedurePublicationState>,
    global_config: &GlobalPromotionConfig,
) -> Result<ProcedureAcceptanceResolution, SemanticServiceError> {
    let proposal = view
        .proposals
        .get(&proposal_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    if proposal.target_kind != ProposalTargetKind::Procedure || !proposal.status.is_open() {
        return Err(SemanticServiceError::UnsupportedTarget);
    }
    let ProposalPayload::Procedure(payload) = &proposal.payload else {
        return Err(SemanticServiceError::UnsupportedTarget);
    };
    let draft = payload.draft();
    draft
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    if draft
        .evidence_refs
        .iter()
        .any(|reference| !proposal.evidence_refs.contains(reference))
    {
        return Err(SemanticServiceError::InvalidInput);
    }
    let (procedure_id, generation, parent, old_state) = match payload.as_ref() {
        ProcedureProposalPayload::Create { .. } => {
            if current.is_some()
                || current_publication.is_some()
                || proposal.target_id.is_some()
                || proposal.base_revision_id.is_some()
            {
                return Err(SemanticServiceError::BaseConflict);
            }
            (ProcedureId::new_v7(), 1, None, None)
        }
        ProcedureProposalPayload::Replace { .. } => {
            let current = current.ok_or(SemanticServiceError::BaseConflict)?;
            let publication = current_publication.ok_or(SemanticServiceError::BaseConflict)?;
            if proposal.target_id != Some(ProposalTargetId::Procedure(current.procedure_id))
                || proposal.base_revision_id != Some(current.revision_id)
                || !current.draft.scope.contains(&draft.scope)
            {
                return Err(SemanticServiceError::BaseConflict);
            }
            if current.draft == *draft {
                return Ok(ProcedureAcceptanceResolution::NoDelta);
            }
            (
                current.procedure_id,
                current.revision_generation.saturating_add(1),
                Some(current.revision_id),
                Some((current.revision_id, publication)),
            )
        }
    };
    let revision_id = RevisionId::new_v7();
    let procedure = ProcedureRevision {
        procedure_id,
        revision_id,
        parent_revision_id: parent,
        revision_generation: generation,
        draft: draft.clone(),
        source_watermark: view.frontier.saturating_add(1),
        created_at_us: context.occurred_at_us,
    };
    procedure
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    let (accepted, mut payloads) = match acceptance_context {
        ProcedureAcceptanceContext::Manual(manual) => {
            let evertrace_domain::semantic::ProposalAcceptanceAuthority::TuiAcceptance {
                authorized_scope_ceiling,
                ..
            } = manual.authority_basis()?
            else {
                return Err(SemanticServiceError::InvalidInput);
            };
            if !authorized_scope_ceiling.contains(&scope_as_atom(draft.scope)) {
                return Err(SemanticServiceError::InvalidInput);
            }
            accepted_proposal_successor(
                proposal,
                &context,
                &manual,
                RevisionId::new_v7(),
                AcceptedProposalTarget::Procedure {
                    procedure_id,
                    procedure_revision_id: revision_id,
                    auto_full_audit: None,
                },
            )?
        }
        ProcedureAcceptanceContext::AutoFull(evidence) => {
            let global = matches!(draft.scope, ProcedureScope::Global);
            if proposal.eligibility != ProposalEligibility::AutoEligibleFull
                || global && global_config.procedure != PromotionLevel::FullAuto
                || !evidence
                    .auto_eligible_full(global, global_config.procedure == PromotionLevel::FullAuto)
            {
                return Err(SemanticServiceError::InvalidInput);
            }
            let observation = evidence
                .verifier_observation_ref
                .ok_or(SemanticServiceError::InvalidInput)?;
            accepted_proposal_successor_with_audit(
                proposal,
                &context,
                RevisionId::new_v7(),
                AcceptedProposalTarget::Procedure {
                    procedure_id,
                    procedure_revision_id: revision_id,
                    auto_full_audit: Some(Box::new(ProcedureAutoFullAudit {
                        validator_revision: PROCEDURE_ELIGIBILITY_VALIDATOR_REVISION.into(),
                        eligibility: evidence,
                        procedure_promotion_level: global_config.procedure,
                        eligible: true,
                    })),
                },
                ProposalAcceptanceAudit {
                    reviewer_identity: format!("objective_evidence:{observation}"),
                    acceptance_event_ref: observation.to_string(),
                    authority_basis: ProposalAcceptanceAuthority::ObjectiveEvidence {
                        user_source_observation_ref: observation,
                    },
                },
            )?
        }
    };
    let state = ProcedureStateEvent {
        state_event_id: RevisionId::new_v7(),
        procedure_revision_id: revision_id,
        from_state: None,
        to_state: ProcedurePublicationState::ActiveProbationary,
        reason: ProcedureStateReason::Accepted,
        resume_state: None,
        evidence_refs: proposal.evidence_refs.clone(),
        created_at_us: context.occurred_at_us,
    };
    payloads.extend([
        JournalPayload::ProcedureRevisionRecorded(Box::new(procedure.clone())),
        JournalPayload::ProcedureStateRecorded(Box::new(state.clone())),
    ]);
    if let Some((old_revision, old_publication)) = old_state {
        payloads.push(JournalPayload::ProcedureStateRecorded(Box::new(
            ProcedureStateEvent {
                state_event_id: RevisionId::new_v7(),
                procedure_revision_id: old_revision,
                from_state: Some(old_publication),
                to_state: ProcedurePublicationState::Superseded,
                reason: ProcedureStateReason::Replaced,
                resume_state: None,
                evidence_refs: proposal.evidence_refs.clone(),
                created_at_us: context.occurred_at_us,
            },
        )));
    }
    if !draft.support_revision_refs.is_empty() {
        validate_current_support_refs(view, &draft.support_revision_refs, revision_id)?;
    }
    if matches!(draft.scope, ProcedureScope::Global) {
        payloads.extend(global_support_payloads(
            revision_id.to_string(),
            draft.support_revision_refs.clone(),
            &accepted,
            serde_json::to_string(&draft.applicability_expr)
                .map_err(|_| SemanticServiceError::InvalidInput)?,
            evertrace_domain::semantic::SupportThresholdSnapshot {
                minimum_surviving_support: 1,
                require_authorization: true,
            },
            context.occurred_at_us,
        )?);
    }
    let command = JournalCommand::new(
        context.command_id,
        payloads
            .into_iter()
            .map(|payload| {
                JournalEventDraft::runtime(
                    context.occurred_at_us,
                    context.effective_config_hash,
                    S24_ALGORITHM,
                    payload,
                )
            })
            .collect(),
    )?;
    Ok(ProcedureAcceptanceResolution::Command {
        proposal: Box::new(accepted),
        procedure: Box::new(procedure),
        state: Box::new(state),
        command,
    })
}

pub fn publication_event(
    revision: &ProcedureRevision,
    from: ProcedurePublicationState,
    to: ProcedurePublicationState,
    reason: ProcedureStateReason,
    resume_state: Option<ProcedurePublicationState>,
    evidence_refs: Vec<String>,
    created_at_us: i64,
) -> Result<ProcedureStateEvent, SemanticServiceError> {
    let event = ProcedureStateEvent {
        state_event_id: RevisionId::new_v7(),
        procedure_revision_id: revision.revision_id,
        from_state: Some(from),
        to_state: to,
        reason,
        resume_state,
        evidence_refs,
        created_at_us,
    };
    event
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    Ok(event)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProcedurePhase {
    BeforeEntry,
    AtEntry,
    InProgress,
    RecoverableDeviation,
    AlreadyCompleted,
    Incompatible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcedureGuidanceMode {
    Normal,
    GuardrailOnly,
}

#[derive(Clone, Debug)]
pub struct ProcedureCandidate {
    pub revision: ProcedureRevision,
    pub publication: ProcedurePublicationState,
    pub global_support: Option<GlobalSupportState>,
    pub phase: ProcedurePhase,
    pub lexical_rank: u32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProcedureDecision {
    Reject,
    Defer,
    Apply,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedProcedure {
    pub procedure_id: ProcedureId,
    pub revision_id: RevisionId,
    pub decision: ProcedureDecision,
    pub publication: ProcedurePublicationState,
    pub mode: ProcedureGuidanceMode,
    pub reason: &'static str,
    pub phase: ProcedurePhase,
    pub lexical_rank: u32,
    pub actions: Option<ProcedureActions>,
    pub avoid: Vec<String>,
    pub done: Option<ProcedureDone>,
    pub excludes: Vec<String>,
    pub pitfalls: Vec<String>,
    route_proof: ProcedureRouteProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcedureRouteProof {
    procedure_id: ProcedureId,
    revision_id: RevisionId,
    decision: ProcedureDecision,
    publication: ProcedurePublicationState,
    task_id: Option<evertrace_domain::ids::TaskId>,
    repository_id: Option<evertrace_domain::ids::RepositoryId>,
    worktree_id: Option<evertrace_domain::ids::WorktreeId>,
    phase: ProcedurePhase,
    failure_signature: Option<String>,
    eligibility: ConstraintTruth,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcedureRouteResult {
    pub status: &'static str,
    pub items: Vec<RoutedProcedure>,
}

pub struct ProcedureRouter;

impl ProcedureRouter {
    #[allow(clippy::too_many_arguments)]
    pub fn route(
        context: &SearchContext,
        candidates: Vec<ProcedureCandidate>,
        current: &ConstraintState,
        previous: Option<&ConstraintState>,
        scenario_fresh: bool,
        unresolved_competing: bool,
        sibling_exploration: bool,
        explicit_reuse: bool,
    ) -> ProcedureRouteResult {
        if context.intent == SearchIntent::HistoryLookup {
            return ProcedureRouteResult {
                status: "history_lookup_bypass",
                items: Vec::new(),
            };
        }
        if candidates.len() > MAX_CANDIDATES || context.validate().is_err() {
            return empty();
        }
        let mode = if !explicit_reuse && (unresolved_competing || sibling_exploration) {
            ProcedureGuidanceMode::GuardrailOnly
        } else {
            ProcedureGuidanceMode::Normal
        };
        let mut routed = candidates
            .into_iter()
            .filter_map(|candidate| {
                evaluate_candidate(context, candidate, current, previous, scenario_fresh, mode)
            })
            .collect::<Vec<_>>();
        routed.sort_by_key(route_rank);
        let apply = routed
            .iter()
            .position(|item| item.decision == ProcedureDecision::Apply)
            .map(|index| routed.remove(index));
        let apply_probationary = apply
            .as_ref()
            .is_some_and(|item| item.publication == ProcedurePublicationState::ActiveProbationary);
        let defer = routed.into_iter().find(|item| {
            item.decision == ProcedureDecision::Defer
                && !(apply_probationary
                    && item.publication == ProcedurePublicationState::ActiveProbationary)
        });
        let mut items = Vec::new();
        if let Some(apply) = apply {
            items.push(apply);
        }
        if let Some(defer) = defer {
            items.push(defer);
        }
        if items.is_empty() {
            empty()
        } else {
            ProcedureRouteResult {
                status: "ok",
                items,
            }
        }
    }
}

fn evaluate_candidate(
    context: &SearchContext,
    candidate: ProcedureCandidate,
    current: &ConstraintState,
    previous: Option<&ConstraintState>,
    scenario_fresh: bool,
    mode: ProcedureGuidanceMode,
) -> Option<RoutedProcedure> {
    if !scope_matches(candidate.revision.draft.scope, context)
        || !matches!(
            candidate.publication,
            ProcedurePublicationState::ActiveProbationary | ProcedurePublicationState::ActiveStable
        )
        || matches!(candidate.revision.draft.scope, ProcedureScope::Global)
            && candidate.global_support != Some(GlobalSupportState::Valid)
        || matches!(
            candidate.phase,
            ProcedurePhase::AlreadyCompleted | ProcedurePhase::Incompatible
        )
    {
        return None;
    }
    let applicability = candidate
        .revision
        .draft
        .applicability_expr
        .evaluate(current, previous);
    let avoid = candidate
        .revision
        .draft
        .avoid_expr
        .evaluate(current, previous);
    let completion = candidate
        .revision
        .draft
        .completion_expr
        .evaluate(current, previous);
    if applicability == ConstraintTruth::False
        || avoid == ConstraintTruth::True
        || completion == ConstraintTruth::True
    {
        return None;
    }
    let recoverable = candidate.phase != ProcedurePhase::RecoverableDeviation
        || !candidate.revision.draft.actions.branches.is_empty()
        || !candidate.revision.draft.done.abort.is_empty();
    let (decision, reason) = if !scenario_fresh {
        (ProcedureDecision::Defer, "insufficient_context")
    } else if applicability == ConstraintTruth::Unknown
        || avoid == ConstraintTruth::Unknown
        || completion == ConstraintTruth::Unknown
        || !recoverable
    {
        (ProcedureDecision::Defer, "unknown_condition")
    } else {
        (ProcedureDecision::Apply, "applicable")
    };
    let guardrail = mode == ProcedureGuidanceMode::GuardrailOnly;
    Some(RoutedProcedure {
        procedure_id: candidate.revision.procedure_id,
        revision_id: candidate.revision.revision_id,
        decision,
        publication: candidate.publication,
        mode,
        reason,
        phase: candidate.phase,
        lexical_rank: candidate.lexical_rank,
        actions: (!guardrail && decision == ProcedureDecision::Apply)
            .then(|| candidate.revision.draft.actions.clone()),
        avoid: candidate.revision.draft.actions.avoid.clone(),
        done: (guardrail || decision == ProcedureDecision::Apply).then(|| {
            if guardrail {
                ProcedureDone {
                    success: Vec::new(),
                    abort: candidate.revision.draft.done.abort.clone(),
                    verify: candidate.revision.draft.done.verify.clone(),
                }
            } else {
                candidate.revision.draft.done.clone()
            }
        }),
        excludes: candidate.revision.draft.when.excludes.clone(),
        pitfalls: candidate.revision.draft.pitfalls.clone(),
        route_proof: ProcedureRouteProof {
            procedure_id: candidate.revision.procedure_id,
            revision_id: candidate.revision.revision_id,
            decision,
            publication: candidate.publication,
            task_id: context.task_id,
            repository_id: context.repository_id,
            worktree_id: context.worktree_id,
            phase: candidate.phase,
            failure_signature: current.bindings.iter().find_map(|binding| {
                if binding.field == evertrace_domain::semantic::ConstraintField::FailureSignature
                    && let evertrace_domain::semantic::ConstraintValue::Text(value) = &binding.value
                {
                    Some(value.clone())
                } else {
                    None
                }
            }),
            eligibility: applicability,
        },
    })
}

fn route_rank(value: &RoutedProcedure) -> (u8, u8, ProcedurePhase, u32, ProcedureId) {
    (
        match value.decision {
            ProcedureDecision::Apply => 0,
            ProcedureDecision::Defer => 1,
            ProcedureDecision::Reject => 2,
        },
        if value.publication == ProcedurePublicationState::ActiveStable {
            0
        } else {
            1
        },
        value.phase,
        value.lexical_rank,
        value.procedure_id,
    )
}

fn scope_matches(scope: ProcedureScope, context: &SearchContext) -> bool {
    match scope {
        ProcedureScope::Global => true,
        ProcedureScope::Repository { repository_id } => {
            context.repository_id == Some(repository_id)
        }
        ProcedureScope::Worktree {
            repository_id,
            worktree_id,
        } => {
            context.repository_id == Some(repository_id) && context.worktree_id == Some(worktree_id)
        }
    }
}

fn scope_as_atom(scope: ProcedureScope) -> AtomScope {
    match scope {
        ProcedureScope::Worktree {
            repository_id,
            worktree_id,
        } => AtomScope::Worktree {
            repository_instance_id: repository_id,
            worktree_instance_id: worktree_id,
        },
        ProcedureScope::Repository { repository_id } => AtomScope::Repository {
            repository_instance_id: repository_id,
        },
        ProcedureScope::Global => AtomScope::Global,
    }
}

fn empty() -> ProcedureRouteResult {
    ProcedureRouteResult {
        status: "no_applicable_procedure",
        items: Vec::new(),
    }
}

mod usage;
pub use usage::*;
