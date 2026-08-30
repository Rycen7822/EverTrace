use evertrace_domain::{
    ids::{RecoveryApplicationId, RecoveryBundleId, RecoveryCaptureRequestId, RequestId},
    repository::{RecoveryApplicationStatus, RecoveryRequestStatus},
    revision::RevisionId,
};
use serde::{Deserialize, Serialize};

use crate::dto::HealthMode;
use crate::envelope::McpResultEnvelope;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    pub request_id: RequestId,
    pub response: Response,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Health(HealthResponse),
    RecoveryTerminal(RecoveryTerminalResponse),
    RecoveryAction(RecoveryActionResponse),
    McpBindingIssued(McpBindingIssuedResponse),
    McpResult(Box<McpResultEnvelope>),
    RecallCue(RecallCueResponse),
    SessionImportAdmin(SessionImportAdminResponse),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionImportAdminResponse {
    Queued,
    Revoked,
    NoDelta,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecallCueResponse {
    Authorized,
    OutcomeAccepted,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpBindingIssuedResponse {
    pub bound_workspace: String,
    pub expires_at_us: i64,
}

impl std::fmt::Debug for McpBindingIssuedResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpBindingIssuedResponse")
            .field("bound_workspace_redacted", &true)
            .field("expires_at_us", &self.expires_at_us)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryUnsupportedReason {
    UnsupportedApplicationKind,
    AmbiguousPatchContent,
    UnsupportedPatchShape,
    RedactedContent,
    IncompleteBundle,
    TargetUnavailable,
    PatchPreflightFailed,
    PhysicalPreflightUnavailable,
    PhysicalPreflightRaced,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryActionResponse {
    pub recovery_application_id: Option<RecoveryApplicationId>,
    pub application_status: Option<RecoveryApplicationStatus>,
    pub replayed: bool,
    pub unsupported_reason: Option<RecoveryUnsupportedReason>,
}

impl RecoveryActionResponse {
    pub fn validate(&self) -> bool {
        let supported = self.recovery_application_id.is_some()
            && self.application_status.is_some()
            && self.unsupported_reason.is_none();
        let unsupported = self.recovery_application_id.is_none()
            && self.application_status.is_none()
            && self.unsupported_reason.is_some()
            && !self.replayed;
        supported || unsupported
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    pub protocol_version: u32,
    pub mode: HealthMode,
    pub config_version: u32,
    pub effective_config_hash: String,
    pub algorithm_revision: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTerminalResponse {
    pub recovery_capture_request_id: RecoveryCaptureRequestId,
    pub pending_revision_id: RevisionId,
    pub terminal_revision_id: RevisionId,
    pub status: RecoveryRequestStatus,
    pub recovery_bundle_id: Option<RecoveryBundleId>,
    pub durable_terminal_proven: bool,
}

impl RecoveryTerminalResponse {
    pub fn validate(&self) -> bool {
        self.status.is_terminal()
            && self.pending_revision_id != self.terminal_revision_id
            && self.durable_terminal_proven
            && (self.status != RecoveryRequestStatus::Complete || self.recovery_bundle_id.is_some())
    }
}
