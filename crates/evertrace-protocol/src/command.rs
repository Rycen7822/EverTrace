use evertrace_domain::{
    ids::{RecoveryBundleId, RecoveryCaptureRequestId, RequestId, WorktreeId},
    repository::RecoveryApplicationKind,
    revision::RevisionId,
};
use serde::{Deserialize, Serialize};

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
