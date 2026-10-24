use evertrace_domain::{
    ids::{RecoveryApplicationId, RecoveryBundleId, RecoveryCaptureRequestId, RequestId},
    repository::{RecoveryApplicationStatus, RecoveryRequestStatus},
    revision::RevisionId,
};
use serde::{Deserialize, Serialize};

use crate::dto::{HealthMode, HumanGovernanceResponse, PROTOCOL_VERSION};
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
    ConfigReload(ConfigReloadResponse),
    ConfigDocument(ConfigDocumentResponse),
    HostCanary(crate::dto::HostCanaryDiagnostic),
    RecoveryTerminal(RecoveryTerminalResponse),
    RecoveryAction(RecoveryActionResponse),
    McpBindingIssued(McpBindingIssuedResponse),
    McpResult(Box<McpResultEnvelope>),
    McpReturned,
    RecallCue(RecallCueResponse),
    SessionImportAdmin(SessionImportAdminResponse),
    HumanGovernance(HumanGovernanceResponse),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDocumentResponse {
    pub source: String,
    pub file_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigReloadResponse {
    pub active_hash: [u8; 32],
    pub pending_hash: Option<[u8; 32]>,
    pub outcome: crate::dto::ConfigReloadOutcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionImportAdminResponse {
    Queued,
    Revoked,
    NoDelta,
    Partial {
        changed: u32,
        unavailable: u32,
        remaining: u32,
    },
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_canary: Option<crate::dto::HostCanaryDiagnostic>,
}

impl HealthResponse {
    pub fn validate(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
            && self
                .host_canary
                .as_ref()
                .is_none_or(crate::dto::HostCanaryDiagnostic::validate)
            && self.config_version == 1
            && self.mode == HealthMode::Normal
            && self.algorithm_revision != 0
            && self.effective_config_hash.len() == 64
            && self
                .effective_config_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
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
