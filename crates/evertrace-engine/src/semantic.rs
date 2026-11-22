use thiserror::Error;

mod emission;
pub(crate) mod human_acceptance;
mod proposal;
mod resolver;
mod scenario_core;

pub use emission::{
    AtomAuthorityBasis, AtomEmissionDecision, AtomEmissionGate, AtomMaterialization,
    SparseAtomSignal, SparseNoDeltaReason, VerifiedHumanAcceptance, exact_task_constraint_draft,
    materialize_atom,
};
pub use evertrace_domain::semantic::{HumanAtomAuthoring, HumanAuthoringTarget};
pub use human_acceptance::HumanAcceptanceService;
pub use proposal::{
    AcceptedProposalCommand, AtomAcceptanceContext, DeletionAwareProposalResolution,
    ProposalCommandContext, ProposalResolution, RevisionProposalService, SubmitProposalRequest,
};
pub(crate) use proposal::{
    ProposalAcceptanceAudit, accepted_edited_proposal_successor, accepted_proposal_successor,
    accepted_proposal_successor_with_audit,
};
pub(crate) use resolver::scope_applies;
pub use resolver::{
    CurrentPolicyBinding, DescriptiveFactResolver, DescriptiveResolution,
    DescriptiveResolutionState, NormativeInstructionResolver, NormativeResolution,
    NormativeResolutionState, ResolverContext,
};
pub use scenario_core::{
    AcceptedCoreMembershipCommand, CoreGovernanceDecision, CoreMembershipAcceptanceContext,
    ScenarioCompiler, accept_core_membership, mark_support_pending, submit_core_conflict_proposal,
};
pub(crate) use scenario_core::{
    SupportAtomAcceptance, SupportDeprecateLookup, SupportReplacementLookup,
    compose_support_deprecate, compose_support_replacement, global_support_payloads,
    select_support_atom_acceptance, select_support_deprecate, select_support_replacement,
    validate_current_support_refs, validate_new_atom_supports,
};

#[derive(Debug, Error)]
pub enum SemanticServiceError {
    #[error("semantic request is invalid")]
    InvalidInput,
    #[error("semantic immutable revision conflicts with current state")]
    ImmutableConflict,
    #[error("proposal base revision is stale")]
    BaseConflict,
    #[error("proposal target is outside the S18 acceptance boundary")]
    UnsupportedTarget,
    #[error("semantic store command is invalid")]
    Store(#[from] evertrace_store::StoreError),
}
