//! Canonical source/import metadata and bounded archive reads; no presentation or permission resolver.
use crate::{
    evidence::SourceRevision,
    ids::{JobId, RepositoryId, WorktreeId},
    query::{ExactRecordRef, HumanContentState, MemoryScopeSelection, QueryError},
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
    #[serde(default)]
    pub selection: MemoryScopeSelection,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSelectionBasis {
    Catalogue,
    HistoricalMetadata,
    ProspectiveOrigin,
    RetainedRecord,
    TaskRequest,
    Unassigned,
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
    /// The observed forward interval, never a reassignment of historical metadata.
    pub prospective_repository_id: Option<RepositoryId>,
    pub prospective_worktree_id: Option<WorktreeId>,
    pub selection_basis: SourceSelectionBasis,
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
            && self.prospective_repository_id.is_some() == self.prospective_worktree_id.is_some()
            && self.prospective_repository_id.is_some() == self.observed_end.is_some()
            && self
                .record_start
                .is_none_or(|start| self.observed_end.is_some_and(|end| start >= end))
            && self.job_id.is_some() == self.job_state.is_some()
            && self.job_state.as_ref().is_none_or(|v| text(v, 64))
    }
}

/// Bounded current catalogue facts, not host discovery, session aggregation or import completeness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMetadataPage {
    pub query: SourceCatalogQuery,
    pub records: Vec<SourceCatalogEntry>,
    pub state: HumanContentState,
    /// Native exact Task selection used only for the existing current access gate.
    pub selection_ref: Option<ExactRecordRef>,
    /// Exact source-instance count, unknown for unavailable selection or denied Task inputs.
    pub matching_count: Option<u64>,
    pub next: Option<String>,
}

impl SourceMetadataPage {
    pub fn clear(&mut self, state: HumanContentState) {
        self.state = state;
        self.records.clear();
        self.matching_count = None;
        self.next = None;
        self.selection_ref = None;
    }

    pub fn validate(&self) -> bool {
        self.query.validate().is_ok()
            && if self.state == HumanContentState::Ready {
                self.matching_count
                    .is_some_and(|count| count >= self.records.len() as u64)
            } else {
                self.records.is_empty() && self.matching_count.is_none() && self.next.is_none()
            }
            && match (self.query.selection, &self.selection_ref) {
                (MemoryScopeSelection::Task { task_id }, Some(reference)) => {
                    self.state == HumanContentState::Ready
                        && reference.stable_key == task_id.to_string()
                        && reference.revision_ref.as_ref().is_some_and(|value| {
                            value.parse::<crate::revision::RevisionId>().is_ok()
                        })
                }
                (MemoryScopeSelection::Task { .. }, None) => self.state != HumanContentState::Ready,
                (_, reference) => reference.is_none(),
            }
            && self.records.iter().all(SourceCatalogEntry::validate)
            && self
                .records
                .windows(2)
                .all(|pair| pair[0].key < pair[1].key)
            && self
                .next
                .as_ref()
                .is_none_or(|key| self.records.last().is_some_and(|row| &row.key == key))
    }
}

/// Archive revisions are metadata identities, never a grant to read records.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceArchiveQuery {
    Revisions {
        source_instance_id: String,
    },
    Records {
        source_instance_id: String,
        source_revision: SourceRevision,
        from_sequence: Option<u64>,
        until_sequence: Option<u64>,
    },
}
impl SourceArchiveQuery {
    pub fn source(&self) -> &str {
        match self {
            Self::Revisions { source_instance_id }
            | Self::Records {
                source_instance_id, ..
            } => source_instance_id,
        }
    }
    pub fn validate(&self) -> Result<(), QueryError> {
        if self.source().is_empty()
            || self.source().len() > 1024
            || self.source().chars().any(char::is_control)
        {
            return Err(QueryError::Invalid);
        }
        if let Self::Records {
            source_revision,
            from_sequence,
            until_sequence,
            ..
        } = self
            && (SourceRevision::parse(source_revision.as_str()).is_err()
                || matches!((from_sequence,until_sequence),(Some(from),Some(until)) if from>=until))
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
    pub fn includes(&self, sequence: u64) -> bool {
        matches!(self, Self::Records {from_sequence, until_sequence, ..}
            if from_sequence.is_none_or(|from| sequence >= from)
                && until_sequence.is_none_or(|until| sequence < until))
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceArchivePosition {
    Revision {
        revision: SourceRevision,
    },
    Record {
        sequence: u64,
        receipt: crate::ids::SourceReceiptId,
    },
}
impl SourceArchivePosition {
    pub fn validate_for(&self, query: &SourceArchiveQuery) -> bool {
        query.validate().is_ok()
            && match (query, self) {
                (
                    SourceArchiveQuery::Revisions { .. },
                    SourceArchivePosition::Revision { revision },
                ) => SourceRevision::parse(revision.as_str()).is_ok(),
                (
                    SourceArchiveQuery::Records { .. },
                    SourceArchivePosition::Record { sequence, .. },
                ) => query.includes(*sequence),
                _ => false,
            }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRecordPresentation {
    Inline,
    Preview,
    NonText,
    NotRecorded,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRecordMetadata {
    pub stable_key: String,
    pub observation_id: crate::ids::SourceObservationId,
    pub receipt_id: crate::ids::SourceReceiptId,
    pub record_identity: crate::evidence::SourceRecordIdentity,
    pub sequence: u64,
    pub byte_range: Option<crate::evidence::EvidenceByteRange>,
    pub observation_role: crate::evidence::ObservationRole,
    pub source_role: crate::evidence::SourceRole,
    pub content_trust: crate::evidence::ContentTrust,
    pub completeness: crate::evidence::CaptureCompleteness,
    pub archive_mode: crate::evidence::SourceArchiveMode,
    pub event_time_us: i64,
    pub recorded_at_us: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_time_provenance: Option<crate::evidence::EventTimeProvenance>,
    pub presentation: SourceRecordPresentation,
    pub default_retrieval_suppressed: bool,
}
impl SourceRecordMetadata {
    pub fn from_records(
        receipt: &crate::evidence::SourceReceipt,
        observation: &crate::evidence::SourceObservation,
        default_retrieval_suppressed: bool,
    ) -> Option<Self> {
        use crate::evidence::ProtectedPresentation as P;
        if receipt.source_observation_id != observation.source_observation_id
            || receipt.source_receipt_id != observation.source_receipt_ref
            || receipt.source_instance_id != observation.source_instance_id
            || receipt.source_revision != observation.source_revision
            || receipt.source_record_identity != observation.source_record_identity
        {
            return None;
        }
        Some(Self {
            stable_key: format!(
                "object:evidence:source_observation:{}",
                observation.source_observation_id
            ),
            observation_id: observation.source_observation_id,
            receipt_id: receipt.source_receipt_id,
            record_identity: receipt.source_record_identity.clone(),
            sequence: receipt.source_sequence,
            byte_range: receipt.source_byte_range.clone(),
            observation_role: receipt.observation_role,
            source_role: observation.source_role,
            content_trust: observation.content_trust,
            completeness: receipt.capture_completeness,
            archive_mode: receipt.archive_mode,
            event_time_us: receipt.event_time_us,
            recorded_at_us: receipt.recorded_at_us,
            event_time_provenance: receipt.event_time_provenance,
            default_retrieval_suppressed,
            presentation: match &receipt.protected_presentation {
                Some(P::Inline { .. }) => SourceRecordPresentation::Inline,
                Some(P::Preview { .. }) => SourceRecordPresentation::Preview,
                Some(P::Unavailable { .. }) => SourceRecordPresentation::NonText,
                None => SourceRecordPresentation::NotRecorded,
            },
        })
    }

    pub fn validate(&self) -> bool {
        self.stable_key == format!("object:evidence:source_observation:{}", self.observation_id)
            && self
                .byte_range
                .as_ref()
                .is_none_or(|range| range.end > range.start)
            && self.event_time_us >= 0
            && self.recorded_at_us >= 0
            && self.event_time_provenance.is_none_or(|value| {
                value
                    .validate(self.event_time_us, self.recorded_at_us)
                    .is_ok()
            })
    }
}

/// Exact source-local identities/provenance only; stored text is read via ReadExact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceArchiveMetadataEntries {
    Revisions { revisions: Vec<SourceRevision> },
    Records { records: Vec<SourceRecordMetadata> },
}

/// Committed coordinates and last observed metadata, not current-file access or a capture-gap proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceArchiveProgress {
    pub catalog_source_revision: SourceRevision,
    pub observed_file_bytes: Option<u64>,
    pub metadata_state: Option<MetadataState>,
    pub body_state: Option<SessionBodyState>,
    pub observed_end: Option<u64>,
    pub record_start: Option<u64>,
    pub origin_closed: Option<bool>,
    pub confirmed_through: Option<u64>,
    pub earlier_fence: Option<u64>,
    pub earlier_through: Option<u64>,
    pub forward_commitment: bool,
    pub earlier_commitment: bool,
    pub replacement_recorded: bool,
}

impl SourceArchiveProgress {
    fn validate(&self) -> bool {
        self.observed_file_bytes.is_some() == self.metadata_state.is_some()
            && self.observed_file_bytes.is_some() == self.body_state.is_some()
            && self.observed_end.is_some() == self.origin_closed.is_some()
            && self
                .record_start
                .is_none_or(|start| self.observed_end.is_some_and(|end| start >= end))
            && self.earlier_fence.is_some() == self.earlier_through.is_some()
            && self.earlier_fence.is_none_or(|fence| {
                self.earlier_through.is_some_and(|through| through <= fence)
                    && self
                        .confirmed_through
                        .is_some_and(|through| fence <= through)
            })
            && (!self.forward_commitment || self.confirmed_through.is_some())
            && (!self.earlier_commitment || self.earlier_through.is_some())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceArchiveMetadataPage {
    pub query: SourceArchiveQuery,
    pub state: crate::query::HumanContentState,
    pub entries: SourceArchiveMetadataEntries,
    pub progress: Option<SourceArchiveProgress>,
    /// Exact retained product-visible identities in this instance/revision/range; unknown when denied or missing.
    pub matching_count: Option<u64>,
    pub next: Option<SourceArchivePosition>,
}
impl SourceArchiveMetadataPage {
    pub fn len(&self) -> usize {
        match &self.entries {
            SourceArchiveMetadataEntries::Revisions { revisions } => revisions.len(),
            SourceArchiveMetadataEntries::Records { records } => records.len(),
        }
    }
    pub fn clear(&mut self, state: crate::query::HumanContentState) {
        self.state = state;
        self.progress = None;
        self.matching_count = None;
        self.next = None;
        match &mut self.entries {
            SourceArchiveMetadataEntries::Revisions { revisions } => revisions.clear(),
            SourceArchiveMetadataEntries::Records { records } => records.clear(),
        }
    }
    pub fn validate(&self) -> bool {
        self.query.validate().is_ok()
            && self
                .progress
                .as_ref()
                .is_none_or(SourceArchiveProgress::validate)
            && match (&self.query, &self.entries) {
                (
                    SourceArchiveQuery::Revisions { .. },
                    SourceArchiveMetadataEntries::Revisions { revisions },
                ) => revisions.windows(2).all(|pair| pair[0] < pair[1]),
                (
                    SourceArchiveQuery::Records { .. },
                    SourceArchiveMetadataEntries::Records { records },
                ) => {
                    records
                        .iter()
                        .all(|row| row.validate() && self.query.includes(row.sequence))
                        && records.windows(2).all(|pair| {
                            (pair[0].sequence, pair[0].receipt_id)
                                < (pair[1].sequence, pair[1].receipt_id)
                        })
                }
                _ => false,
            }
            && if self.state == crate::query::HumanContentState::Ready {
                self.matching_count
                    .is_some_and(|count| count >= self.len() as u64)
                    && self.next.as_ref().is_none_or(|key| {
                        key.validate_for(&self.query)
                            && match (&self.entries, key) {
                                (
                                    SourceArchiveMetadataEntries::Revisions { revisions },
                                    SourceArchivePosition::Revision { revision },
                                ) => revisions.last() == Some(revision),
                                (
                                    SourceArchiveMetadataEntries::Records { records },
                                    SourceArchivePosition::Record { sequence, receipt },
                                ) => records.last().is_some_and(|row| {
                                    row.sequence == *sequence && row.receipt_id == *receipt
                                }),
                                _ => false,
                            }
                    })
            } else {
                self.len() == 0
                    && self.matching_count.is_none()
                    && self.next.is_none()
                    && self.progress.is_none()
            }
    }
}
