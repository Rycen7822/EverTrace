use evertrace_protocol::{
    command::RequestRecoveryCommand,
    dto::{
        HumanActionRequest, HumanActionResult, HumanGovernanceResponse, HumanProposalReview,
        HumanRelationKind, HumanSnapshotItem,
    },
    response::{HealthResponse, RecoveryActionResponse},
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoverySelection {
    pub(crate) recovery_bundle_id: evertrace_domain::ids::RecoveryBundleId,
    pub(crate) application_kind: evertrace_domain::repository::RecoveryApplicationKind,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RelatedContext {
    pub(crate) relation: HumanRelationKind,
    pub(crate) source_stable_key: String,
    pub(crate) expected_source_revision_ref: String,
    pub(crate) expected_frontier: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FutureOperationShell {
    ForgetAtom(String),
    ForgetProcedure(String),
    ForgetCoreMembership(String),
    Maintenance,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProposalEditContext {
    Proposal(HumanProposalReview),
    SupportReplacement {
        expected_validation_revision_id: evertrace_domain::revision::RevisionId,
        original_payload: Box<evertrace_domain::semantic::ProposalPayload>,
    },
    SupportDeprecate {
        expected_validation_revision_id: evertrace_domain::revision::RevisionId,
        original_payload: Box<evertrace_domain::semantic::ProposalPayload>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProposalEditState {
    pub(crate) frozen_frontier: u64,
    pub(crate) context: ProposalEditContext,
    pub(crate) document: String,
    pub(crate) cursor: usize,
    pub(crate) error: Option<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Inbox,
    Explorer,
    System,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Disconnected,
    ServerStopping,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellSnapshot {
    pub health: Option<HealthResponse>,
    pub connection: ConnectionState,
    pub pending: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppState {
    pub route: Route,
    pub shell: ShellSnapshot,
    pub human: Option<HumanGovernanceResponse>,
    pub detail: Option<HumanSnapshotItem>,
    pub detail_message: Option<String>,
    pub detail_scroll: u16,
    pub selection: usize,
    pub last_action: Option<HumanActionResult>,
    pub read_conflict: Option<u64>,
    pub(crate) related_context: Option<RelatedContext>,
    pub(crate) future_operation_shell: Option<FutureOperationShell>,
    pub proposal_confirmation: Option<(u64, HumanActionRequest, Option<HumanProposalReview>)>,
    pub competing_candidate_selection: usize,
    pub(crate) proposal_edit: Option<ProposalEditState>,
    pub write_queued: bool,
    pub(crate) recovery_selection: Option<RecoverySelection>,
    pub recovery_confirmation: Option<RequestRecoveryCommand>,
    pub recovery_result: Option<RecoveryActionResponse>,
    pub quit: bool,
}
impl Default for AppState {
    fn default() -> Self {
        Self {
            route: Route::Inbox,
            shell: ShellSnapshot {
                health: None,
                connection: ConnectionState::Connecting,
                pending: 0,
            },
            human: None,
            detail: None,
            detail_message: None,
            detail_scroll: 0,
            selection: 0,
            last_action: None,
            read_conflict: None,
            related_context: None,
            future_operation_shell: None,
            proposal_confirmation: None,
            competing_candidate_selection: 0,
            proposal_edit: None,
            write_queued: false,
            recovery_selection: None,
            recovery_confirmation: None,
            recovery_result: None,
            quit: false,
        }
    }
}
