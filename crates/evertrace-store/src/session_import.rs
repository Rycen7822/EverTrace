use serde::{Deserialize, Serialize};

use crate::ProjectionSnapshot;
use crate::{ObjectRow, ObjectRowClass, ObjectRowKind, StoreError};
use evertrace_capture::CasDigest;
use evertrace_domain::{
    evidence::SourceRevision,
    ids::{RepositoryId, RequestId, WorktreeId},
};
use std::collections::BTreeMap;
use std::str::FromStr;

pub const SESSION_IMPORT_ROW_PREFIX: &str = "runtime:session_import:";
pub const MAX_REPOSITORY_READ_RESTRICTIONS: usize = 16;

/// A source-local read from the writer's committed admission state, not a
/// projection barrier or a partial ProjectionSnapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionImportContext {
    pub frontier: u64,
    pub current: SessionImportCurrent,
    pub job: Option<crate::DurableJob>,
    pub watermark: Option<crate::SourceIngestWatermark>,
    pub previous_revision: Option<SourceRevision>,
    pub recorded_prefix_end: Option<u64>,
    pub repository: Option<evertrace_domain::repository::RepositoryInstance>,
    pub worktree: Option<evertrace_domain::repository::WorktreeInstance>,
    pub repository_purged: bool,
    pub read_repositories: Vec<evertrace_domain::repository::RepositoryInstance>,
    pub read_worktrees: Vec<evertrace_domain::repository::WorktreeInstance>,
    pub read_snapshots: Vec<evertrace_domain::repository::WorktreeSnapshot>,
    /// Repository HEAD history not fully represented by read_snapshots. This
    /// transient query result must never be interpreted as complete negative
    /// continuity evidence; it is not a journal field or projected state.
    pub incomplete_repository_history: Vec<RepositoryId>,
}

#[derive(Clone, Debug)]
pub struct SessionImportSelection {
    pub contexts: Vec<SessionImportContext>,
    pub has_more: bool,
}

#[derive(Clone, Debug)]
pub struct SessionImportPrefixRecord {
    pub start: u64,
    pub end: u64,
    pub cas_ref: String,
}

#[derive(Clone, Debug)]
pub struct SessionImportPrefixRequest {
    pub source: String,
    pub revision: SourceRevision,
    pub after: u64,
    pub end: u64,
    pub max_records: usize,
    pub max_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct SessionImportPrefixPage {
    pub frontier: u64,
    pub records: Vec<SessionImportPrefixRecord>,
    pub has_more: bool,
}

pub fn is_session_import_source(instance: &str) -> bool {
    instance.starts_with("codex-session:") || instance.starts_with("session-rollout:")
}

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyStateReason {
    Requested,
    Started,
    Completed,
    TrustUnavailable,
    ApprovalUnavailable,
    ScopeUnresolved,
    BudgetExhausted,
    ImportFailed,
    SourceReplaced,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMetadata {
    pub source_path: String,
    pub source_format: String,
    pub started_at_us: Option<i64>,
    pub ended_at_us: Option<i64>,
    pub host: Option<String>,
    pub model_profile: Option<String>,
    pub workspace_hint: Option<String>,
    pub repository_hint: Option<String>,
    pub worktree_hint: Option<String>,
    pub workspace_resolution_kind: WorkspaceResolutionKind,
    pub resolved_repository_instance_id: Option<RepositoryId>,
    pub resolved_worktree_instance_id: Option<WorktreeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_read_restrictions: Option<Vec<RepositoryId>>,
    pub file_size: u64,
    pub file_mtime_us: i64,
    pub source_fingerprint: String,
    pub source_revision: SourceRevision,
    pub parser_version: u32,
    pub metadata_state: MetadataState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionImportEventKind {
    MetadataObserved {
        metadata: Box<SessionMetadata>,
    },
    AccessDecision {
        decision: SessionAccessDecision,
        local_request_ref: RequestId,
        provenance_refs: Vec<String>,
    },
    BodyStateAdvanced {
        body_state: SessionBodyState,
        reason: BodyStateReason,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionImportEvent {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_instance_id: Option<String>,
    pub revision: u64,
    pub predecessor_revision: Option<u64>,
    pub occurred_at_us: i64,
    pub event: SessionImportEventKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionImportCurrent {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_instance_id: Option<String>,
    pub revision: u64,
    pub metadata: SessionMetadata,
    pub access_decision: Option<SessionAccessDecision>,
    pub body_state: SessionBodyState,
    pub source_event_seq: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionImportCurrentView {
    pub frontier: u64,
    pub sessions: BTreeMap<String, SessionImportCurrent>,
}

impl SessionImportCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut sessions = BTreeMap::new();
        for row in snapshot.data_rows() {
            let Some(value) = restore_current(row)? else {
                continue;
            };
            if value.source_event_seq > snapshot.frontier
                || sessions.insert(value.source_key(), value).is_some()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Ok(Self {
            frontier: snapshot.frontier,
            sessions,
        })
    }
}

impl SessionImportEvent {
    pub fn source_key(&self) -> String {
        self.source_instance_id
            .clone()
            .unwrap_or_else(|| self.session_id.clone())
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        if !valid_text(&self.session_id, 512)
            || !valid_source_instance(&self.session_id, self.source_instance_id.as_deref())
            || self.revision == 0
            || self.occurred_at_us < 0
            || self.predecessor_revision != self.revision.checked_sub(1).filter(|v| *v != 0)
        {
            return Err(StoreError::InvalidInput);
        }
        match &self.event {
            SessionImportEventKind::MetadataObserved { metadata } => metadata.validate(),
            SessionImportEventKind::AccessDecision {
                provenance_refs, ..
            } => {
                if !valid_refs(provenance_refs) {
                    return Err(StoreError::InvalidInput);
                }
                Ok(())
            }
            SessionImportEventKind::BodyStateAdvanced { body_state, reason }
                if reason_matches(*body_state, *reason) =>
            {
                Ok(())
            }
            SessionImportEventKind::BodyStateAdvanced { .. } => Err(StoreError::InvalidInput),
        }
    }
}

impl SessionImportCurrent {
    pub fn source_key(&self) -> String {
        self.source_instance_id
            .clone()
            .unwrap_or_else(|| self.session_id.clone())
    }

    pub fn source_instance(&self) -> String {
        self.source_instance_id
            .clone()
            .unwrap_or_else(|| format!("codex-session:{}", self.session_id))
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        if !valid_text(&self.session_id, 512)
            || !valid_source_instance(&self.session_id, self.source_instance_id.as_deref())
            || self.revision == 0
            || self.source_event_seq == 0
        {
            return Err(StoreError::InvalidInput);
        }
        self.metadata.validate()?;
        if self.metadata.repository_read_restrictions.is_some() {
            if self.metadata.workspace_resolution_kind != WorkspaceResolutionKind::Repository
                && matches!(
                    self.body_state,
                    SessionBodyState::Queued
                        | SessionBodyState::Importing
                        | SessionBodyState::Partial
                        | SessionBodyState::Imported
                )
                && self.access_decision != Some(SessionAccessDecision::Approved)
            {
                return Err(StoreError::InvalidInput);
            }
            return Ok(());
        }
        match self.metadata.workspace_resolution_kind {
            WorkspaceResolutionKind::Repository => {
                if self.access_decision.is_some() {
                    return Err(StoreError::InvalidInput);
                }
            }
            WorkspaceResolutionKind::NonRepository => {
                if matches!(
                    self.body_state,
                    SessionBodyState::Queued
                        | SessionBodyState::Importing
                        | SessionBodyState::Partial
                        | SessionBodyState::Imported
                ) && self.access_decision != Some(SessionAccessDecision::Approved)
                {
                    return Err(StoreError::InvalidInput);
                }
            }
            WorkspaceResolutionKind::Ambiguous | WorkspaceResolutionKind::Unavailable => {
                if self.access_decision.is_some()
                    || !matches!(
                        self.body_state,
                        SessionBodyState::NotImported
                            | SessionBodyState::BlockedScopeUnresolved
                            | SessionBodyState::Failed
                            | SessionBodyState::SourceReplaced
                    )
                {
                    return Err(StoreError::InvalidInput);
                }
            }
        }
        Ok(())
    }
}

impl SessionMetadata {
    pub fn workspace_matches_path(&self, path: &str) -> bool {
        self.workspace_hint.as_deref().is_some_and(|workspace| {
            std::path::Path::new(workspace).is_absolute()
                && std::path::Path::new(path).is_absolute()
                && std::path::Path::new(workspace).starts_with(path)
        })
    }

    pub fn repository_candidate(
        &self,
        repository: &evertrace_domain::repository::RepositoryInstance,
    ) -> bool {
        self.workspace_matches_path(&repository.current_path)
            || repository
                .path_history
                .iter()
                .any(|path| self.workspace_matches_path(&path.path))
    }

    pub fn read_restrictions(&self) -> impl Iterator<Item = RepositoryId> + '_ {
        self.repository_read_restrictions
            .iter()
            .flatten()
            .copied()
            .chain(self.resolved_repository_instance_id)
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        if let Some(restrictions) = &self.repository_read_restrictions
            && (restrictions.len() > MAX_REPOSITORY_READ_RESTRICTIONS
                || restrictions.windows(2).any(|pair| pair[0] >= pair[1])
                || self
                    .resolved_repository_instance_id
                    .is_some_and(|id| restrictions.binary_search(&id).is_err()))
        {
            return Err(StoreError::InvalidInput);
        }
        if !valid_text(&self.source_path, 4096)
            || !valid_text(&self.source_format, 64)
            || self.file_mtime_us < 0
            || self.parser_version == 0
            || !valid_text(&self.source_fingerprint, 256)
            || CasDigest::from_str(&self.source_fingerprint).is_err()
            || self.started_at_us.is_some_and(|v| v < 0)
            || self.ended_at_us.is_some_and(|v| v < 0)
            || self
                .started_at_us
                .zip(self.ended_at_us)
                .is_some_and(|(a, b)| a > b)
            || [
                self.host.as_deref(),
                self.model_profile.as_deref(),
                self.workspace_hint.as_deref(),
                self.repository_hint.as_deref(),
                self.worktree_hint.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|v| !valid_text(v, 4096))
        {
            return Err(StoreError::InvalidInput);
        }
        SourceRevision::parse(self.source_revision.as_str().to_owned())
            .map_err(|_| StoreError::InvalidInput)?;
        let ids = (
            self.resolved_repository_instance_id.is_some(),
            self.resolved_worktree_instance_id.is_some(),
        );
        if matches!(
            self.workspace_resolution_kind,
            WorkspaceResolutionKind::Repository
        ) != (ids.0 && ids.1)
            || (!matches!(
                self.workspace_resolution_kind,
                WorkspaceResolutionKind::Repository
            ) && (ids.0 || ids.1))
        {
            return Err(StoreError::InvalidInput);
        }
        Ok(())
    }
}

pub fn apply_session_event(
    current: Option<&SessionImportCurrent>,
    event: &SessionImportEvent,
    seq: u64,
) -> Result<SessionImportCurrent, StoreError> {
    event.validate()?;
    match (current, &event.event) {
        (None, SessionImportEventKind::MetadataObserved { metadata }) if event.revision == 1 => {
            let next = SessionImportCurrent {
                session_id: event.session_id.clone(),
                source_instance_id: event.source_instance_id.clone(),
                revision: 1,
                metadata: metadata.as_ref().clone(),
                access_decision: None,
                body_state: SessionBodyState::NotImported,
                source_event_seq: seq,
            };
            next.validate()?;
            Ok(next)
        }
        (None, _) => Err(StoreError::InvalidInput),
        (Some(old), _)
            if old.session_id != event.session_id
                || old.source_instance_id != event.source_instance_id
                || event.predecessor_revision != Some(old.revision) =>
        {
            Err(StoreError::InvalidInput)
        }
        (Some(old), SessionImportEventKind::MetadataObserved { metadata }) => {
            match &metadata.repository_read_restrictions {
                None if old.metadata.repository_read_restrictions.is_some() => {
                    return Err(StoreError::InvalidInput);
                }
                Some(restrictions)
                    if old
                        .metadata
                        .read_restrictions()
                        .any(|id| restrictions.binary_search(&id).is_err()) =>
                {
                    return Err(StoreError::InvalidInput);
                }
                _ => {}
            }
            if &old.metadata == metadata.as_ref() {
                return Err(StoreError::InvalidInput);
            }
            let source_changed = old.metadata.source_revision != metadata.source_revision
                || metadata.file_size < old.metadata.file_size
                || (metadata.source_path == old.metadata.source_path
                    && metadata.file_size == old.metadata.file_size
                    && old.metadata.file_mtime_us != metadata.file_mtime_us);
            if source_changed
                && !matches!(
                    old.body_state,
                    SessionBodyState::NotImported | SessionBodyState::SourceReplaced
                )
            {
                return Err(StoreError::InvalidInput);
            }
            let mut next = old.clone();
            next.revision = event.revision;
            next.metadata = metadata.as_ref().clone();
            next.source_event_seq = seq;
            if (source_changed
                || (metadata.repository_read_restrictions.is_none()
                    && metadata.workspace_resolution_kind
                        != WorkspaceResolutionKind::NonRepository))
                && !(metadata.repository_read_restrictions.is_some()
                    && old.access_decision == Some(SessionAccessDecision::Revoked))
            {
                next.access_decision = None;
            }
            next.validate()?;
            Ok(next)
        }
        (Some(old), SessionImportEventKind::AccessDecision { decision, .. }) => {
            if old.metadata.repository_read_restrictions.is_none()
                && old.metadata.workspace_resolution_kind != WorkspaceResolutionKind::NonRepository
            {
                return Err(StoreError::InvalidInput);
            }
            if old.access_decision == Some(*decision) {
                return Err(StoreError::InvalidInput);
            }
            let mut next = old.clone();
            next.revision = event.revision;
            next.access_decision = Some(*decision);
            next.source_event_seq = seq;
            next.validate()?;
            Ok(next)
        }
        (Some(old), SessionImportEventKind::BodyStateAdvanced { body_state, .. }) => {
            if !body_transition(old.body_state, *body_state) {
                return Err(StoreError::InvalidInput);
            }
            if *body_state == SessionBodyState::Queued
                && old.metadata.workspace_resolution_kind != WorkspaceResolutionKind::Repository
                && old.access_decision != Some(SessionAccessDecision::Approved)
            {
                return Err(StoreError::InvalidInput);
            }
            let mut next = old.clone();
            next.revision = event.revision;
            next.body_state = *body_state;
            next.source_event_seq = seq;
            next.validate()?;
            Ok(next)
        }
    }
}

pub fn session_import_row_id(session_id: &str) -> String {
    format!("{SESSION_IMPORT_ROW_PREFIX}{session_id}")
}

pub fn current_row(value: &SessionImportCurrent, generation: u64) -> Result<ObjectRow, StoreError> {
    value.validate()?;
    Ok(ObjectRow {
        row_id: session_import_row_id(&value.source_key()),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Runtime),
        object_family: None,
        object_kind: Some("session_import_current".into()),
        object_id: None,
        current_revision_id: Some(value.revision.to_string()),
        lifecycle: None,
        epistemic: None,
        authority: None,
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: value
            .metadata
            .resolved_repository_instance_id
            .map(|id| id.to_string()),
        worktree_id: value
            .metadata
            .resolved_worktree_instance_id
            .map(|id| id.to_string()),
        task_id: None,
        workstream_id: None,
        session_id: Some(value.session_id.clone()),
        payload_json: Some(serde_json::to_string(value).map_err(|_| StoreError::Serialization)?),
        source_event_seq: value.source_event_seq,
        projection_generation: generation,
    })
}

pub fn restore_current(row: &ObjectRow) -> Result<Option<SessionImportCurrent>, StoreError> {
    if row.object_kind.as_deref() != Some("session_import_current") {
        return Ok(None);
    }
    let json = row
        .payload_json
        .as_deref()
        .ok_or(StoreError::StoreCorrupt)?;
    let value: SessionImportCurrent =
        serde_json::from_str(json).map_err(|_| StoreError::StoreCorrupt)?;
    if row.row_id != session_import_row_id(&value.source_key())
        || row.row_class != Some(ObjectRowClass::Runtime)
        || row.object_id.is_some()
        || row.current_revision_id.as_deref() != Some(&value.revision.to_string())
        || row.session_id.as_deref() != Some(&value.session_id)
        || row.source_event_seq != value.source_event_seq
        || row.row_kind != ObjectRowKind::Data
        || row.object_family.is_some()
        || row.repository_id
            != value
                .metadata
                .resolved_repository_instance_id
                .map(|id| id.to_string())
        || row.worktree_id
            != value
                .metadata
                .resolved_worktree_instance_id
                .map(|id| id.to_string())
        || row.task_id.is_some()
        || row.workstream_id.is_some()
        || row.lifecycle.is_some()
        || row.epistemic.is_some()
        || row.authority.is_some()
        || row.publication_state.is_some()
        || row.support_state.is_some()
        || row.project_id.is_some()
        || serde_json::to_string(&value).map_err(|_| StoreError::StoreCorrupt)? != json
    {
        return Err(StoreError::StoreCorrupt);
    }
    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
    Ok(Some(value))
}

fn body_transition(from: SessionBodyState, to: SessionBodyState) -> bool {
    use SessionBodyState::*;
    matches!(
        (from, to),
        (
            NotImported,
            Queued | BlockedUntrusted | BlockedUnapproved | BlockedScopeUnresolved
        ) | (
            Queued,
            Importing
                | BlockedUntrusted
                | BlockedUnapproved
                | BlockedScopeUnresolved
                | Failed
                | SourceReplaced
        ) | (
            Importing,
            Imported | Partial | Failed | BlockedUntrusted | BlockedUnapproved | SourceReplaced
        ) | (
            Partial,
            Queued
                | Importing
                | BlockedUntrusted
                | BlockedUnapproved
                | BlockedScopeUnresolved
                | SourceReplaced
        ) | (Failed, Queued)
            | (SourceReplaced, Queued)
            | (BlockedUntrusted, Queued)
            | (BlockedUnapproved, Queued)
            | (BlockedScopeUnresolved, Queued)
            | (
                Imported,
                Queued
                    | BlockedUntrusted
                    | BlockedUnapproved
                    | BlockedScopeUnresolved
                    | SourceReplaced
            )
    )
}

fn reason_matches(state: SessionBodyState, reason: BodyStateReason) -> bool {
    matches!(
        (state, reason),
        (SessionBodyState::Queued, BodyStateReason::Requested)
            | (SessionBodyState::Importing, BodyStateReason::Started)
            | (SessionBodyState::Imported, BodyStateReason::Completed)
            | (
                SessionBodyState::BlockedUntrusted,
                BodyStateReason::TrustUnavailable
            )
            | (
                SessionBodyState::BlockedUnapproved,
                BodyStateReason::ApprovalUnavailable
            )
            | (
                SessionBodyState::BlockedScopeUnresolved,
                BodyStateReason::ScopeUnresolved
            )
            | (SessionBodyState::Partial, BodyStateReason::BudgetExhausted)
            | (SessionBodyState::Failed, BodyStateReason::ImportFailed)
            | (
                SessionBodyState::SourceReplaced,
                BodyStateReason::SourceReplaced
            )
    )
}

fn valid_source_instance(session: &str, source: Option<&str>) -> bool {
    source.is_none_or(|source| {
        source
            .strip_prefix(&format!("session-rollout:{session}:"))
            .is_some_and(|rollout| {
                rollout.len() == 36
                    && rollout.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                        }
                    })
            })
    })
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn valid_refs(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= 32
        && values.windows(2).all(|p| p[0] < p[1])
        && values.iter().all(|v| valid_text(v, 512))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(revision: &str, fingerprint: &str) -> SessionMetadata {
        SessionMetadata {
            source_path: "2026/08/30/rollout-2026-08-30T00-00-00-session-a.jsonl".into(),
            source_format: "codex_rollout_jsonl_v1".into(),
            started_at_us: None,
            ended_at_us: None,
            host: None,
            model_profile: None,
            workspace_hint: None,
            repository_hint: None,
            worktree_hint: None,
            workspace_resolution_kind: WorkspaceResolutionKind::NonRepository,
            resolved_repository_instance_id: None,
            resolved_worktree_instance_id: None,
            repository_read_restrictions: None,
            file_size: 10,
            file_mtime_us: 1,
            source_fingerprint: fingerprint.into(),
            source_revision: SourceRevision::parse(revision).unwrap(),
            parser_version: 1,
            metadata_state: MetadataState::Indexed,
        }
    }

    fn event(revision: u64, event: SessionImportEventKind) -> SessionImportEvent {
        SessionImportEvent {
            source_instance_id: None,
            session_id: "session-a".into(),
            revision,
            predecessor_revision: revision.checked_sub(1).filter(|value| *value != 0),
            occurred_at_us: i64::try_from(revision).unwrap(),
            event,
        }
    }

    #[test]
    fn optional_source_preserves_legacy_bytes_and_separates_rows() {
        let digest = "1".repeat(64);
        let old = event(
            1,
            SessionImportEventKind::MetadataObserved {
                metadata: Box::new(metadata(&digest, &digest)),
            },
        );
        let bytes = serde_json::to_vec(&old).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("source_instance_id"));
        assert!(!String::from_utf8_lossy(&bytes).contains("repository_read_restrictions"));
        let decoded: SessionImportEvent = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
        let legacy = apply_session_event(None, &decoded, 1).unwrap();
        let legacy_row = current_row(&legacy, 1).unwrap();
        assert_eq!(legacy_row.row_id, session_import_row_id("session-a"));
        assert_eq!(legacy.source_instance(), "codex-session:session-a");
        let mut next = old;
        next.source_instance_id =
            Some("session-rollout:session-a:019d0000-0000-7000-8000-000000000002".into());
        let separate = apply_session_event(None, &next, 2).unwrap();
        assert_ne!(current_row(&separate, 1).unwrap().row_id, legacy_row.row_id);
        assert_eq!(restore_current(&legacy_row).unwrap(), Some(legacy));
        next.revision = 2;
        next.predecessor_revision = Some(1);
        assert!(
            apply_session_event(restore_current(&legacy_row).unwrap().as_ref(), &next, 3).is_err()
        );
    }

    #[test]
    fn read_restrictions_are_monotone_without_granting_approval() {
        let digest = "1".repeat(64);
        let mut metadata = metadata(&digest, &digest);
        metadata.workspace_resolution_kind = WorkspaceResolutionKind::Ambiguous;
        let old = apply_session_event(
            None,
            &event(
                1,
                SessionImportEventKind::MetadataObserved {
                    metadata: Box::new(metadata.clone()),
                },
            ),
            1,
        )
        .unwrap();
        metadata.repository_read_restrictions = Some(Vec::new());
        let observed = apply_session_event(
            Some(&old),
            &event(
                2,
                SessionImportEventKind::MetadataObserved {
                    metadata: Box::new(metadata.clone()),
                },
            ),
            2,
        )
        .unwrap();
        assert_eq!(observed.access_decision, None);
        assert_eq!(
            restore_current(&current_row(&observed, 1).unwrap()).unwrap(),
            Some(observed.clone())
        );
        let approved = apply_session_event(
            Some(&observed),
            &event(
                3,
                SessionImportEventKind::AccessDecision {
                    decision: SessionAccessDecision::Approved,
                    local_request_ref: RequestId::new_v7(),
                    provenance_refs: vec!["local_cli:request".into()],
                },
            ),
            3,
        )
        .unwrap();
        let repository = RepositoryId::new_v7();
        metadata.repository_read_restrictions = Some(vec![repository]);
        let restricted_event = event(
            4,
            SessionImportEventKind::MetadataObserved {
                metadata: Box::new(metadata.clone()),
            },
        );
        let restricted = apply_session_event(Some(&approved), &restricted_event, 4).unwrap();
        assert_eq!(
            restricted.access_decision,
            Some(SessionAccessDecision::Approved)
        );
        assert_eq!(restricted.metadata.resolved_repository_instance_id, None);
        assert!(
            apply_session_event(
                Some(&restricted),
                &event(5, restricted_event.event.clone()),
                5
            )
            .is_err()
        );
        for dropped in [None, Some(Vec::new())] {
            let mut invalid = metadata.clone();
            invalid.repository_read_restrictions = dropped;
            assert!(
                apply_session_event(
                    Some(&restricted),
                    &event(
                        5,
                        SessionImportEventKind::MetadataObserved {
                            metadata: Box::new(invalid),
                        }
                    ),
                    5
                )
                .is_err()
            );
        }
        let mut invalid = metadata.clone();
        invalid.repository_read_restrictions = Some(vec![repository, repository]);
        assert!(invalid.validate().is_err());
        let mut reversed = vec![repository, RepositoryId::new_v7()];
        reversed.sort_unstable_by(|a, b| b.cmp(a));
        invalid.repository_read_restrictions = Some(reversed);
        assert!(invalid.validate().is_err());
        metadata.source_revision = SourceRevision::parse("2".repeat(64)).unwrap();
        let replaced = apply_session_event(
            Some(&restricted),
            &event(
                5,
                SessionImportEventKind::MetadataObserved {
                    metadata: Box::new(metadata),
                },
            ),
            5,
        )
        .unwrap();
        assert_eq!(replaced.access_decision, None);
        assert_eq!(
            replaced.metadata.repository_read_restrictions,
            Some(vec![repository])
        );
        let revoked = apply_session_event(
            Some(&replaced),
            &event(
                6,
                SessionImportEventKind::AccessDecision {
                    decision: SessionAccessDecision::Revoked,
                    local_request_ref: RequestId::new_v7(),
                    provenance_refs: vec!["local_cli:revoke".into()],
                },
            ),
            6,
        )
        .unwrap();
        let mut replacement = revoked.metadata.clone();
        replacement.source_revision = SourceRevision::parse("3".repeat(64)).unwrap();
        let still_revoked = apply_session_event(
            Some(&revoked),
            &event(
                7,
                SessionImportEventKind::MetadataObserved {
                    metadata: Box::new(replacement),
                },
            ),
            7,
        )
        .unwrap();
        assert_eq!(
            still_revoked.access_decision,
            Some(SessionAccessDecision::Revoked)
        );
    }

    #[test]
    fn imported_source_rewrite_requires_explicit_replacement_transition() {
        let first = "1111111111111111111111111111111111111111111111111111111111111111";
        let second = "2222222222222222222222222222222222222222222222222222222222222222";
        let mut current = apply_session_event(
            None,
            &event(
                1,
                SessionImportEventKind::MetadataObserved {
                    metadata: Box::new(metadata(first, first)),
                },
            ),
            1,
        )
        .unwrap();
        current.access_decision = Some(SessionAccessDecision::Approved);
        current.body_state = SessionBodyState::Imported;
        current.revision = 3;
        current.source_event_seq = 3;
        current.validate().unwrap();
        let changed = event(
            4,
            SessionImportEventKind::MetadataObserved {
                metadata: Box::new(metadata(second, second)),
            },
        );
        assert_eq!(
            apply_session_event(Some(&current), &changed, 4),
            Err(StoreError::InvalidInput)
        );
        let replaced = apply_session_event(
            Some(&current),
            &event(
                4,
                SessionImportEventKind::BodyStateAdvanced {
                    body_state: SessionBodyState::SourceReplaced,
                    reason: BodyStateReason::SourceReplaced,
                },
            ),
            4,
        )
        .unwrap();
        let changed = event(
            5,
            SessionImportEventKind::MetadataObserved {
                metadata: Box::new(metadata(second, second)),
            },
        );
        let next = apply_session_event(Some(&replaced), &changed, 5).unwrap();
        assert_eq!(next.body_state, SessionBodyState::SourceReplaced);
        assert_eq!(next.metadata.source_revision.as_str(), second);
    }

    #[test]
    fn non_repository_partial_requires_approval_and_revoke_blocks_first() {
        let fingerprint = "1111111111111111111111111111111111111111111111111111111111111111";
        let mut current = apply_session_event(
            None,
            &event(
                1,
                SessionImportEventKind::MetadataObserved {
                    metadata: Box::new(metadata(fingerprint, fingerprint)),
                },
            ),
            1,
        )
        .unwrap();
        current.body_state = SessionBodyState::Partial;
        assert_eq!(current.validate(), Err(StoreError::InvalidInput));
        current.access_decision = Some(SessionAccessDecision::Approved);
        current.validate().unwrap();
        let blocked = apply_session_event(
            Some(&current),
            &event(
                2,
                SessionImportEventKind::BodyStateAdvanced {
                    body_state: SessionBodyState::BlockedUnapproved,
                    reason: BodyStateReason::ApprovalUnavailable,
                },
            ),
            2,
        )
        .unwrap();
        let revoked = apply_session_event(
            Some(&blocked),
            &event(
                3,
                SessionImportEventKind::AccessDecision {
                    decision: SessionAccessDecision::Revoked,
                    local_request_ref: RequestId::new_v7(),
                    provenance_refs: vec!["local-cli".into()],
                },
            ),
            3,
        )
        .unwrap();
        assert_eq!(
            revoked.access_decision,
            Some(SessionAccessDecision::Revoked)
        );
    }

    #[test]
    fn restore_rejects_unused_object_columns() {
        let fingerprint = "1111111111111111111111111111111111111111111111111111111111111111";
        let current = apply_session_event(
            None,
            &event(
                1,
                SessionImportEventKind::MetadataObserved {
                    metadata: Box::new(metadata(fingerprint, fingerprint)),
                },
            ),
            1,
        )
        .unwrap();
        let mut row = current_row(&current, 1).unwrap();
        assert_eq!(restore_current(&row).unwrap(), Some(current));
        row.authority = Some("forged".into());
        assert_eq!(restore_current(&row), Err(StoreError::StoreCorrupt));
    }
}
