use thiserror::Error;

mod emission;
mod proposal;
mod resolver;

pub use emission::{
    AtomAuthorityBasis, AtomEmissionDecision, AtomEmissionGate, AtomMaterialization,
    SparseAtomSignal, SparseNoDeltaReason, VerifiedTuiAcceptance, exact_task_constraint_draft,
    materialize_atom,
};
pub use proposal::{
    AcceptedProposalCommand, AtomAcceptanceContext, ProposalCommandContext, ProposalResolution,
    RevisionProposalService, SubmitProposalRequest,
};
pub use resolver::{
    CurrentPolicyBinding, DescriptiveFactResolver, DescriptiveResolution,
    DescriptiveResolutionState, NormativeInstructionResolver, NormativeResolution,
    NormativeResolutionState, ResolverContext,
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
