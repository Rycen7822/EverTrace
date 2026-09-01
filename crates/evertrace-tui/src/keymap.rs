use crate::{Route, UiCommand};
use crossterm::event::{KeyCode, KeyEvent};
pub fn command(k: KeyEvent) -> UiCommand {
    match k.code {
        KeyCode::Char('q') => UiCommand::Quit,
        KeyCode::Char('1') => UiCommand::Navigate(Route::Inbox),
        KeyCode::Char('2') => UiCommand::Navigate(Route::Explorer),
        KeyCode::Char('3') => UiCommand::Navigate(Route::System),
        KeyCode::Char('r') => UiCommand::Refresh,
        KeyCode::Char('j') => UiCommand::SelectNext,
        KeyCode::Char('k') => UiCommand::SelectPrevious,
        KeyCode::Char('n') => UiCommand::NextPage,
        KeyCode::Char('b') => UiCommand::FirstPage,
        KeyCode::Char('o') => UiCommand::OpenRelated,
        KeyCode::Char('g') => UiCommand::OpenFutureOperationShell,
        KeyCode::Char('E') => UiCommand::OpenProposalEditor,
        KeyCode::Char('D') => UiCommand::OpenSupportDeprecateEditor,
        KeyCode::Char('d') => {
            UiCommand::PrepareProposal(evertrace_protocol::dto::ProposalHumanDecision::Defer)
        }
        KeyCode::Char('z') => {
            UiCommand::PrepareProposal(evertrace_protocol::dto::ProposalHumanDecision::Reject)
        }
        KeyCode::Char('a') => {
            UiCommand::PrepareProposal(evertrace_protocol::dto::ProposalHumanDecision::Accept)
        }
        KeyCode::Char('m') => UiCommand::PrepareProposal(
            evertrace_protocol::dto::ProposalHumanDecision::MergeAndAccept,
        ),
        KeyCode::Char('x') => UiCommand::PrepareNegativeReview(
            evertrace_protocol::dto::NegativeReviewDecision::DismissAttribution,
        ),
        KeyCode::Char('h') => UiCommand::PrepareNegativeReview(
            evertrace_protocol::dto::NegativeReviewDecision::ConfirmHarm,
        ),
        KeyCode::Char('e') => UiCommand::PrepareNegativeReview(
            evertrace_protocol::dto::NegativeReviewDecision::ResolveAsIneffective,
        ),
        KeyCode::Char('v') => UiCommand::PrepareNegativeReview(
            evertrace_protocol::dto::NegativeReviewDecision::RequestRevision,
        ),
        KeyCode::Char('[') => UiCommand::SelectCompetingPrevious,
        KeyCode::Char(']') => UiCommand::SelectCompetingNext,
        KeyCode::Char('c') => UiCommand::PrepareCompetingSelected,
        KeyCode::Char('A') => UiCommand::PrepareMarkNewAttempt,
        KeyCode::Char('F') => UiCommand::PrepareForgetObject,
        KeyCode::Char('p') => {
            UiCommand::PrepareRecovery(evertrace_domain::repository::RecoveryApplicationKind::Patch)
        }
        KeyCode::Char('f') => UiCommand::PrepareRecovery(
            evertrace_domain::repository::RecoveryApplicationKind::FileRestore,
        ),
        KeyCode::Char('i') => UiCommand::PrepareRecovery(
            evertrace_domain::repository::RecoveryApplicationKind::IndexRestore,
        ),
        KeyCode::Char('M') => {
            UiCommand::PrepareRecovery(evertrace_domain::repository::RecoveryApplicationKind::Mixed)
        }
        KeyCode::Enter => UiCommand::Detail,
        KeyCode::Esc => UiCommand::CancelModal,
        _ => UiCommand::None,
    }
}
