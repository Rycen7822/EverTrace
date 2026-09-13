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
    Configuration {
        file_hash: String,
    },
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryPurgeConfirmationState {
    pub(crate) frozen_frontier: u64,
    pub(crate) preview: evertrace_protocol::dto::HumanRepositoryPurgePreview,
    pub(crate) entered_repository_id: String,
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
    pub language: crate::Language,
    pub(crate) ui: UiState,
    pub route: Route,
    pub shell: ShellSnapshot,
    pub human: Option<HumanGovernanceResponse>,
    pub detail: Option<HumanSnapshotItem>,
    pub(crate) detail_frontier: Option<u64>,
    pub detail_message: Option<String>,
    pub detail_scroll: u16,
    pub selection: usize,
    pub last_action: Option<HumanActionResult>,
    pub export_selections: Vec<evertrace_protocol::dto::HumanExportSelection>,
    pub export_result: Option<evertrace_protocol::dto::HumanExportResult>,
    pub(crate) export_pending: bool,
    pub read_conflict: Option<u64>,
    pub(crate) related_context: Option<RelatedContext>,
    pub(crate) future_operation_shell: Option<FutureOperationShell>,
    pub proposal_confirmation: Option<(u64, HumanActionRequest, Option<HumanProposalReview>)>,
    pub(crate) repository_purge_confirmation: Option<RepositoryPurgeConfirmationState>,
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
            language: crate::Language::English,
            route: Route::System,
            ui: UiState::default(),
            shell: ShellSnapshot {
                health: None,
                connection: ConnectionState::Connecting,
                pending: 0,
            },
            human: None,
            detail: None,
            detail_frontier: None,
            detail_message: None,
            detail_scroll: 0,
            selection: 0,
            last_action: None,
            export_selections: Vec::new(),
            export_result: None,
            export_pending: false,
            read_conflict: None,
            related_context: None,
            future_operation_shell: None,
            proposal_confirmation: None,
            repository_purge_confirmation: None,
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SystemView {
    #[default]
    Overview,
    Jobs,
    Diagnostics,
    Configuration,
    Maintenance,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DetailView {
    #[default]
    Content,
    Sources,
    History,
    Technical,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Focus {
    Tabs,
    Tools,
    #[default]
    List,
    Detail,
    Actions,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NavigationFrame {
    pub result_jump: bool,
    pub page_cursor: Option<String>,
    pub type_filter: Option<String>,
    pub scope_filter: Option<String>,
    pub state_filter: Option<String>,
    pub system_view: SystemView,
    pub read_at: Option<std::time::SystemTime>,
    pub route: Route,
    pub human: Option<HumanGovernanceResponse>,
    pub detail: Option<HumanSnapshotItem>,
    pub detail_frontier: Option<u64>,
    pub selection: usize,
    pub scroll: u16,
    pub offset: usize,
    pub filter: String,
    pub related: Option<RelatedContext>,
    pub detail_view: DetailView,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct UiState {
    pub read_generation: u64,
    pub diagnostic_selection: usize,
    pub diagnostic_detail: bool,
    pub pending_edit: Option<ProposalEditState>,
    pub confirmation_selected: bool,
    pub action_submits_job: bool,
    pub type_filter: Option<String>,
    pub scope_filter: Option<String>,
    pub state_filter: Option<String>,
    pub reference_request: Option<(String, u64)>,
    pub related_loaded: bool,
    pub page_cursor: Option<String>,
    pub focus: Focus,
    pub system_view: SystemView,
    pub detail_view: DetailView,
    pub zoom: bool,
    pub filter: String,
    pub query: String,
    pub query_cursor: usize,
    pub input: Option<bool>, // true: commands; false: local filter/find
    pub palette_selection: usize,
    pub tool_selection: usize,
    pub action_selection: usize,
    pub list_offset: usize,
    pub find: String,
    pub history: Vec<NavigationFrame>,
    pub read_at: Option<std::time::SystemTime>,
    pub read_finished: Option<std::time::Instant>,
    pub reading: bool,
    pub unknown_write: bool,
    pub help: bool,
}
