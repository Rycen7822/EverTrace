use crate::Route;
use evertrace_domain::repository::RecoveryApplicationKind;
use evertrace_protocol::dto::{NegativeReviewDecision, ProposalHumanDecision};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiCommand {
    Navigate(Route),
    Refresh,
    SelectNext,
    SelectPrevious,
    NextPage,
    FirstPage,
    Detail,
    OpenRelated,
    OpenFutureOperationShell,
    OpenProposalEditor,
    OpenSupportDeprecateEditor,
    PrepareProposal(ProposalHumanDecision),
    PrepareNegativeReview(NegativeReviewDecision),
    SelectCompetingPrevious,
    SelectCompetingNext,
    PrepareCompetingSelected,
    PrepareMarkNewAttempt,
    PrepareForgetObject,
    ConfirmProposal,
    PrepareRecovery(RecoveryApplicationKind),
    ConfirmRecovery,
    CancelModal,
    Quit,
    None,
}
