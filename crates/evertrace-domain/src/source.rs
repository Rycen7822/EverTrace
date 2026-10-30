//! Read-only human source catalogue contracts; no storage or permission resolver.
use crate::{
    evidence::SourceRevision,
    ids::{JobId, RepositoryId, WorktreeId},
    query::QueryError,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceResolutionKind {
    Repository,
    NonRepository,
    Ambiguous,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataState {
    Discovered,
    Indexed,
    Partial,
    Unsupported,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionBodyState {
    NotImported,
    Queued,
    Importing,
    Imported,
    BlockedUntrusted,
    BlockedUnapproved,
    BlockedScopeUnresolved,
    Partial,
    Failed,
    SourceReplaced,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionAccessDecision {
    Approved,
    Revoked,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCatalogQuery {
    pub session_id: Option<String>,
    pub source_instance_id: Option<String>,
    pub unassigned_only: bool,
}

impl SourceCatalogQuery {
    pub fn validate(&self) -> Result<(), QueryError> {
        if self
            .session_id
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 512 || v.chars().any(char::is_control))
        {
            return Err(QueryError::Invalid);
        }
        if self
            .source_instance_id
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 1024 || v.chars().any(char::is_control))
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCatalogCursor {
    pub frontier: u64,
    pub query: SourceCatalogQuery,
    pub after_source: String,
}

impl SourceCatalogCursor {
    pub fn validate_for(&self, query: &SourceCatalogQuery) -> Result<(), QueryError> {
        query.validate()?;
        if &self.query != query
            || self.after_source.is_empty()
            || self.after_source.len() > 512
            || self.after_source.chars().any(char::is_control)
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCatalogEntry {
    pub key: String,
    pub session_id: String,
    /// Exact catalogue identity, including retained legacy session identities.
    pub source_instance_id: String,
    pub catalog_revision: u64,
    pub source_revision: SourceRevision,
    pub metadata_state: MetadataState,
    pub body_state: SessionBodyState,
    pub access_decision: Option<SessionAccessDecision>,
    pub workspace_resolution_kind: WorkspaceResolutionKind,
    pub resolved_repository_id: Option<RepositoryId>,
    pub resolved_worktree_id: Option<WorktreeId>,
    pub repository_read_restrictions: Option<Vec<RepositoryId>>,
    /// Catalogued hints, never assignment or read authority.
    pub workspace_hint: Option<String>,
    pub source_format: String,
    pub started_at_us: Option<i64>,
    pub ended_at_us: Option<i64>,
    pub file_size: u64,
    pub observed_end: Option<u64>,
    pub record_start: Option<u64>,
    pub origin_closed: Option<bool>,
    pub archived_through: Option<u64>,
    pub earlier_through: Option<u64>,
    pub job_id: Option<JobId>,
    pub job_state: Option<String>,
}

impl SourceCatalogEntry {
    pub fn validate(&self) -> bool {
        let text = |value: &str, limit| {
            !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
        };
        text(&self.key, 512)
            && text(&self.source_instance_id, 1024)
            && crate::evidence::SourceRevision::parse(self.source_revision.as_str()).is_ok()
            && text(&self.session_id, 512)
            && self.catalog_revision > 0
            && text(&self.source_format, 512)
            && self.workspace_hint.as_ref().is_none_or(|v| text(v, 4096))
            && self.started_at_us.is_none_or(|v| v >= 0)
            && self.ended_at_us.is_none_or(|v| v >= 0)
            && self.observed_end.is_some() == self.origin_closed.is_some()
            && self
                .record_start
                .is_none_or(|start| self.observed_end.is_some_and(|end| start >= end))
            && self.job_id.is_some() == self.job_state.is_some()
            && self.job_state.as_ref().is_none_or(|v| text(v, 64))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCatalogPage {
    pub frontier: u64,
    pub query: SourceCatalogQuery,
    pub entries: Vec<SourceCatalogEntry>,
    /// Only the already catalogued native namespace, not a full host scan.
    pub next_cursor: Option<String>,
}
