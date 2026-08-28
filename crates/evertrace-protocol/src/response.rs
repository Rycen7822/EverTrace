use evertrace_domain::{
    ids::{RecoveryBundleId, RecoveryCaptureRequestId, RequestId},
    repository::RecoveryRequestStatus,
    revision::RevisionId,
};
use serde::{Deserialize, Serialize};

use crate::dto::HealthMode;

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
