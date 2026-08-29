use evertrace_domain::{
    ids::{RecoveryBundleId, RecoveryCaptureRequestId, RequestId, WorktreeId},
    recall::{PresentationAttemptState, RecallCueSnapshot},
    repository::RecoveryApplicationKind,
    revision::RevisionId,
};
use serde::{Deserialize, Serialize};

use crate::mcp::McpToolInput;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandEnvelope {
    pub request_id: RequestId,
    pub command: Command,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    Health,
    RecoveryBarrier(RecoveryBarrierLocator),
    RequestRecovery(RequestRecoveryCommand),
    IssueMcpBinding(McpBindingIssueCommand),
    McpCall(McpCallCommand),
    RecallCue(RecallCueCommand),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecallCueCommand {
    Authorize {
        snapshot: RecallCueSnapshot,
    },
    Outcome {
        snapshot: RecallCueSnapshot,
        outcome: PresentationAttemptState,
    },
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpBindingIssueCommand {
    pub session_id: String,
    pub turn_id: String,
    pub tool_use_id: String,
    pub agent_id: Option<String>,
    pub original_input: McpToolInput,
    pub launcher_protocol_revision: u32,
}

impl std::fmt::Debug for McpBindingIssueCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpBindingIssueCommand")
            .field("binding_fields_redacted", &true)
            .field(
                "launcher_protocol_revision",
                &self.launcher_protocol_revision,
            )
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpCallCommand {
    pub input: McpToolInput,
    pub client_cwd: String,
}

impl std::fmt::Debug for McpCallCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpCallCommand")
            .field("action", &self.input.action)
            .field("private_fields_redacted", &true)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRecoveryCommand {
    pub recovery_bundle_id: RecoveryBundleId,
    pub target_worktree_instance_id: WorktreeId,
    pub application_kind: RecoveryApplicationKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBarrierLocator {
    pub spool_record_id: String,
    pub recovery_capture_request_id: RecoveryCaptureRequestId,
    pub pending_revision_id: RevisionId,
}

impl RecoveryBarrierLocator {
    pub fn validate(&self) -> bool {
        !self.spool_record_id.is_empty()
            && self.spool_record_id.len() <= 256
            && self.spool_record_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.')
            })
    }
}
