use thiserror::Error;

mod emission;
mod proposal;
mod resolver;
mod s23;

pub use emission::{
    AtomAuthorityBasis, AtomEmissionDecision, AtomEmissionGate, AtomMaterialization,
    SparseAtomSignal, SparseNoDeltaReason, VerifiedTuiAcceptance, exact_task_constraint_draft,
    materialize_atom,
};
pub use proposal::{
    AcceptedProposalCommand, AtomAcceptanceContext, DeletionAwareProposalResolution,
    ProposalCommandContext, ProposalResolution, RevisionProposalService, SubmitProposalRequest,
};
pub(crate) use proposal::{
    ProposalAcceptanceAudit, accepted_edited_proposal_successor, accepted_proposal_successor,
    accepted_proposal_successor_with_audit,
};
pub use resolver::{
    CurrentPolicyBinding, DescriptiveFactResolver, DescriptiveResolution,
    DescriptiveResolutionState, NormativeInstructionResolver, NormativeResolution,
    NormativeResolutionState, ResolverContext,
};
pub use s23::{
    AcceptedCoreMembershipCommand, CoreGovernanceDecision, CoreMembershipAcceptanceContext,
    ScenarioCompiler, accept_core_membership, mark_support_pending, submit_core_conflict_proposal,
};
pub(crate) use s23::{
    SupportAtomAcceptance, SupportDeprecateLookup, SupportReplacementLookup,
    compose_support_deprecate, compose_support_replacement, global_support_payloads,
    select_support_atom_acceptance, select_support_deprecate, select_support_replacement,
    validate_current_support_refs,
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
