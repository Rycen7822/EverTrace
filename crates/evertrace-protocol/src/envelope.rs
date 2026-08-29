use serde::{Deserialize, Serialize};

pub use evertrace_domain::evidence::{ContentTrust, InstructionAuthority};
use evertrace_domain::ids::RequestId;

use crate::{
    command::CommandEnvelope,
    error::WireError,
    handshake::{Handshake, HandshakeAck},
    notification::NotificationEnvelope,
    response::ResponseEnvelope,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ClientEnvelope {
    Handshake(Handshake),
    Command(CommandEnvelope),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ServerEnvelope {
    HandshakeAck(HandshakeAck),
    Response(ResponseEnvelope),
    Notification(NotificationEnvelope),
    Error(WireError),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpStatus {
    Ok,
    NoMatch,
    NoRecallNeeded,
    NoApplicableProcedure,
    PendingImport,
    Partial,
    DegradedIndex,
    ScopeUnresolved,
    Untrusted,
    Conflict,
    InvalidInput,
    NotFound,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpItem {
    pub kind: String,
    pub object_ref: Option<String>,
    pub object_revision_ref: Option<String>,
    pub source_revision_ref: Option<String>,
    pub scope: Option<String>,
    pub applicability: Option<String>,
    pub authority: Option<String>,
    pub text: Option<String>,
    pub content_trust: ContentTrust,
    pub capture_completeness: Option<String>,
    pub instruction_authority: InstructionAuthority,
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpItems {
    pub normative_constraints: Vec<McpItem>,
    pub procedures: Vec<McpItem>,
    pub evidence: Vec<McpItem>,
    pub warnings: Vec<McpItem>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpResultEnvelope {
    pub schema_version: u32,
    pub request_id: RequestId,
    pub status: McpStatus,
    pub scope: String,
    pub freshness: String,
    pub completeness: String,
    pub items: McpItems,
    pub warnings: Vec<String>,
    pub truncated: bool,
    pub next_refs: Vec<String>,
    pub audit_ref: Option<String>,
}

impl std::fmt::Debug for McpItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpItem")
            .field("kind", &self.kind)
            .field("object_ref_redacted", &self.object_ref.is_some())
            .field("text_bytes", &self.text.as_ref().map(String::len))
            .field("content_trust", &self.content_trust)
            .field("instruction_authority", &self.instruction_authority)
            .finish()
    }
}

impl std::fmt::Debug for McpItems {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpItems")
            .field("normative_constraints", &self.normative_constraints.len())
            .field("procedures", &self.procedures.len())
            .field("evidence", &self.evidence.len())
            .field("warnings", &self.warnings.len())
            .finish()
    }
}

impl std::fmt::Debug for McpResultEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpResultEnvelope")
            .field("schema_version", &self.schema_version)
            .field("request_id", &self.request_id)
            .field("status", &self.status)
            .field("scope_redacted", &true)
            .field("freshness", &self.freshness)
            .field("completeness", &self.completeness)
            .field("items", &self.items)
            .field("warnings_count", &self.warnings.len())
            .field("truncated", &self.truncated)
            .field("next_refs_count", &self.next_refs.len())
            .field("audit_ref_present", &self.audit_ref.is_some())
            .finish()
    }
}
