//! Closed, request-local retrieval contracts.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ids::{RepositoryId, TaskId, WorktreeId};

const MAX_QUERY_BYTES: usize = 8 * 1024;
const MAX_FACET_ITEMS: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FacetParseStatus {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Polarity {
    Positive,
    Negative,
    Mixed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalMode {
    Current,
    AsOf,
    Interval,
    Sequence,
    Any,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchIntent {
    TaskPlanning,
    StageAssistance,
    FailureRecovery,
    HistoryLookup,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScopeBoundary {
    Task { task_id: TaskId },
    Repository { repository_id: RepositoryId },
    Worktree { worktree_id: WorktreeId },
}

impl ScopeBoundary {
    /// Declared human-directory association, not applicability or authorization.
    pub fn directory_parent_of_task(self, task: &crate::work::Task) -> bool {
        task.scope_memberships.iter().any(|membership| match self {
            Self::Repository { repository_id } => {
                membership.repository_instance_id == Some(repository_id)
            }
            Self::Worktree { worktree_id } => {
                membership.worktree_instance_ids.contains(&worktree_id)
            }
            Self::Task { .. } => false,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceBoundary {
    User,
    Assistant,
    Tool,
    Host,
    Imported,
    ProjectPolicy,
    ObjectiveEvidence,
    AgentInferred,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerShape {
    SourceSnippet,
    EntityList,
    Count,
    Timeline,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleBoundary {
    Active,
    Terminal,
    Any,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TemporalQualifier {
    EventTimeAsOf { at_us: i64 },
    EventTimeInterval { start_us: i64, end_us: i64 },
    SourceSequenceAtMost { sequence: u64 },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuantityConstraint {
    ResultLimit { limit: u32 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryFacetSet {
    pub parse_status: FacetParseStatus,
    pub exact_identifiers: Vec<String>,
    pub condition_literals: Vec<String>,
    pub relation_requirements: Vec<String>,
    pub polarity: Polarity,
    pub explicit_exclusions: Vec<String>,
    pub temporal_mode: TemporalMode,
    pub temporal_qualifiers: Vec<TemporalQualifier>,
    pub quantity_constraints: Vec<QuantityConstraint>,
    pub scope_boundary: Option<ScopeBoundary>,
    pub source_boundary: Option<SourceBoundary>,
    pub answer_shape: Option<AnswerShape>,
    pub lifecycle_boundary: LifecycleBoundary,
}

impl QueryFacetSet {
    pub fn validate(&self) -> Result<(), QueryError> {
        for values in [
            &self.exact_identifiers,
            &self.condition_literals,
            &self.relation_requirements,
            &self.explicit_exclusions,
        ] {
            if values.len() > MAX_FACET_ITEMS
                || values.iter().any(|value| value.is_empty())
                || values.iter().collect::<BTreeSet<_>>().len() != values.len()
            {
                return Err(QueryError::Invalid);
            }
        }
        if self.temporal_qualifiers.len() > MAX_FACET_ITEMS
            || self.quantity_constraints.len() > MAX_FACET_ITEMS
            || self
                .temporal_qualifiers
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.temporal_qualifiers.len()
            || self
                .quantity_constraints
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.quantity_constraints.len()
            || self
                .quantity_constraints
                .iter()
                .any(|value| matches!(value, QuantityConstraint::ResultLimit { limit: 0 }))
            || self.temporal_qualifiers.iter().any(|value| match value {
                TemporalQualifier::EventTimeAsOf { at_us } => *at_us < 0,
                TemporalQualifier::EventTimeInterval { start_us, end_us } => {
                    *start_us < 0 || end_us <= start_us
                }
                TemporalQualifier::SourceSequenceAtMost { .. } => false,
            })
        {
            return Err(QueryError::Invalid);
        }
        let temporal_shape = match self.temporal_mode {
            TemporalMode::Current | TemporalMode::Any | TemporalMode::Unknown => {
                self.temporal_qualifiers.is_empty()
            }
            TemporalMode::AsOf => matches!(
                self.temporal_qualifiers.as_slice(),
                [TemporalQualifier::EventTimeAsOf { .. }]
            ),
            TemporalMode::Interval => matches!(
                self.temporal_qualifiers.as_slice(),
                [TemporalQualifier::EventTimeInterval { .. }]
            ),
            TemporalMode::Sequence => matches!(
                self.temporal_qualifiers.as_slice(),
                [TemporalQualifier::SourceSequenceAtMost { .. }]
            ),
        };
        if !temporal_shape {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum SuppressionSnapshot {
    Current {
        generation: u64,
        ref_hashes: BTreeSet<String>,
    },
    Unavailable,
}

impl SuppressionSnapshot {
    pub fn validate(&self) -> Result<(), QueryError> {
        match self {
            Self::Current {
                generation: _,
                ref_hashes,
            } if ref_hashes.iter().all(|value| !value.is_empty()) => Ok(()),
            Self::Unavailable => Ok(()),
            Self::Current { .. } => Err(QueryError::Invalid),
        }
    }

    pub fn suppresses(&self, reference: &str) -> Result<bool, QueryError> {
        match self {
            Self::Current { ref_hashes, .. } => Ok(ref_hashes.contains(reference)),
            Self::Unavailable => Err(QueryError::SuppressionUnavailable),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalCompleteness {
    Complete,
    Partial,
    Conflicted,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingBasis {
    EventTime,
    SourceSequence,
    Validity,
    Supersession,
    RecordedAtFallback,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationKind {
    Quoted,
    Normalized,
    Merged,
    DeterministicDerived,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedGapKind {
    StableObjectId,
    ExactIdentifier,
    AllowlistedRelationSlot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedGap {
    pub kind: NamedGapKind,
    pub identifier: String,
    pub changes_result: bool,
}

impl NamedGap {
    pub fn validate(&self) -> Result<(), QueryError> {
        if self.identifier.is_empty() || !self.changes_result {
            Err(QueryError::Invalid)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateBoundary {
    pub generation: u8,
    pub base_candidate_refs: BTreeSet<String>,
    pub added_candidate_refs: BTreeSet<String>,
    pub candidate_refs: BTreeSet<String>,
}

impl CandidateBoundary {
    pub fn validate(&self) -> Result<(), QueryError> {
        let mut expected = self.base_candidate_refs.clone();
        expected.extend(self.added_candidate_refs.iter().cloned());
        if !matches!(self.generation, 1 | 2)
            || (self.generation == 1 && !self.added_candidate_refs.is_empty())
            || (self.generation == 2 && self.added_candidate_refs.len() != 1)
            || !self
                .base_candidate_refs
                .is_disjoint(&self.added_candidate_refs)
            || expected != self.candidate_refs
            || self.candidate_refs.iter().any(|value| value.is_empty())
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedStatement {
    pub statement: String,
    pub support_refs: BTreeSet<String>,
    pub derivation_kind: DerivationKind,
    pub ordering_basis: OrderingBasis,
    pub content_trust: String,
    pub instruction_authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedEvidenceView {
    pub candidate_set: CandidateBoundary,
    pub active_evidence: Vec<GroundedStatement>,
    pub unresolved_gaps: Vec<NamedGap>,
    pub conflicts: BTreeSet<String>,
    pub completeness: RetrievalCompleteness,
    pub omitted_refs: BTreeSet<String>,
}

impl GroundedEvidenceView {
    pub fn validate(&self) -> Result<(), QueryError> {
        self.candidate_set.validate()?;
        for gap in &self.unresolved_gaps {
            gap.validate()?;
        }
        for statement in &self.active_evidence {
            if statement.statement.is_empty()
                || statement.support_refs.is_empty()
                || !statement
                    .support_refs
                    .is_subset(&self.candidate_set.candidate_refs)
                || statement.content_trust != "untrusted_source_content"
                || statement.instruction_authority != "none"
            {
                return Err(QueryError::Invalid);
            }
        }
        if self.completeness == RetrievalCompleteness::Complete
            && (!self.unresolved_gaps.is_empty()
                || !self.conflicts.is_empty()
                || !self.omitted_refs.is_empty())
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalLayer {
    A,
    B,
    C,
    D,
    E,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Passed,
    NotCharacterized,
    Failed,
}

pub const fn production_retrieval_layer() -> RetrievalLayer {
    RetrievalLayer::A
}

pub const fn retrieval_gate(layer: RetrievalLayer) -> GateStatus {
    match layer {
        RetrievalLayer::A => GateStatus::Passed,
        RetrievalLayer::B | RetrievalLayer::C | RetrievalLayer::D | RetrievalLayer::E => {
            GateStatus::NotCharacterized
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalBudget {
    pub candidates_remaining: u32,
    pub tokens_remaining: u32,
    pub latency_us_remaining: u64,
    pub hops_remaining: u8,
    pub follow_ups_remaining: u8,
}

impl RetrievalBudget {
    pub fn validate(&self) -> Result<(), QueryError> {
        if self.candidates_remaining == 0
            || self.tokens_remaining == 0
            || self.latency_us_remaining == 0
            || self.hops_remaining > 2
            || self.follow_ups_remaining > 1
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }

    pub fn consume_candidate(&mut self) -> Result<(), QueryError> {
        self.candidates_remaining = self
            .candidates_remaining
            .checked_sub(1)
            .ok_or(QueryError::BudgetExhausted)?;
        Ok(())
    }

    pub fn consume_candidate_text(&mut self, bytes: usize) -> Result<(), QueryError> {
        self.consume_candidate()?;
        let tokens = u32::try_from(bytes.saturating_add(3) / 4)
            .map_err(|_| QueryError::BudgetExhausted)?
            .max(1);
        self.tokens_remaining = self
            .tokens_remaining
            .checked_sub(tokens)
            .ok_or(QueryError::BudgetExhausted)?;
        Ok(())
    }

    pub fn consume_latency(&mut self, elapsed_us: u64) -> Result<(), QueryError> {
        if let Some(remaining) = self.latency_us_remaining.checked_sub(elapsed_us) {
            self.latency_us_remaining = remaining;
            Ok(())
        } else {
            self.latency_us_remaining = 0;
            Err(QueryError::BudgetExhausted)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchContext {
    pub intent: SearchIntent,
    pub raw_query: String,
    pub query_facets: QueryFacetSet,
    pub task_id: Option<TaskId>,
    pub repository_id: Option<RepositoryId>,
    pub worktree_id: Option<WorktreeId>,
    pub suppression: SuppressionSnapshot,
    pub budget: RetrievalBudget,
}

impl SearchContext {
    pub fn validate(&self) -> Result<(), QueryError> {
        if self.raw_query.is_empty() || self.raw_query.len() > MAX_QUERY_BYTES {
            return Err(QueryError::Invalid);
        }
        self.query_facets.validate()?;
        self.suppression.validate()?;
        if self
            .query_facets
            .scope_boundary
            .is_some_and(|scope| match scope {
                ScopeBoundary::Task { task_id } => self.task_id.is_some_and(|id| id != task_id),
                ScopeBoundary::Repository { repository_id } => {
                    self.repository_id.is_some_and(|id| id != repository_id)
                }
                ScopeBoundary::Worktree { worktree_id } => {
                    self.worktree_id.is_some_and(|id| id != worktree_id)
                }
            })
        {
            return Err(QueryError::Invalid);
        }
        self.budget.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchCandidateVariant {
    Object,
    EvidenceSurface,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchCandidate {
    pub candidate_id: String,
    pub source_ref: String,
    pub row_variant: SearchCandidateVariant,
    pub object_kind: Option<String>,
    pub text: String,
    pub source_role: Option<String>,
    pub content_trust: Option<String>,
    pub capture_completeness: Option<String>,
    pub retrieval_origins: BTreeSet<String>,
    pub instruction_authority: String,
    pub conflicted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchResult {
    pub layer: RetrievalLayer,
    pub projection_frontier: u64,
    pub authoritative_frontier: u64,
    pub candidates: Vec<SearchCandidate>,
    pub completeness: RetrievalCompleteness,
    pub degraded_reasons: BTreeSet<String>,
    pub omitted_refs: BTreeSet<String>,
    pub budget: RetrievalBudget,
}

/// Metadata browsing is not an alternative text-retrieval pipeline.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryReadingKind {
    #[default]
    All,
    Summaries,
    FactsAndConstraints,
    Methods,
    References,
}

/// Provenance of an existing list excerpt, not a claim about its truth.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySummaryOrigin {
    StoredValue,
    TypeFallback,
    DigestDeterministic,
    DigestLlmEnriched,
    DigestRejectedGeneration,
}

/// Explicit human browsing scope; distinct from applicability/agent binding.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MemoryScopeSelection {
    #[default]
    All,
    Global,
    Unassigned,
    Task {
        task_id: TaskId,
    },
    Repository {
        repository_id: RepositoryId,
    },
    Worktree {
        worktree_id: WorktreeId,
    },
}

impl MemoryScopeSelection {
    pub const fn boundary(self) -> Option<ScopeBoundary> {
        match self {
            Self::Task { task_id } => Some(ScopeBoundary::Task { task_id }),
            Self::Repository { repository_id } => Some(ScopeBoundary::Repository { repository_id }),
            Self::Worktree { worktree_id } => Some(ScopeBoundary::Worktree { worktree_id }),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeDirectoryQuery {
    pub parent: Option<ScopeBoundary>,
    pub name: String,
}

impl ScopeDirectoryQuery {
    pub fn validate(&self) -> Result<(), QueryError> {
        if self.name.len() > 256
            || self.name != self.name.trim()
            || self.name.chars().any(char::is_control)
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeDirectoryCursor {
    pub frontier: u64,
    pub query: ScopeDirectoryQuery,
    pub after_key: String,
}

impl ScopeDirectoryCursor {
    pub fn validate_for(&self, query: &ScopeDirectoryQuery) -> Result<(), QueryError> {
        if self.query != *query
            || self.after_key.is_empty()
            || self.after_key.len() > 512
            || self.after_key.chars().any(char::is_control)
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeTitleState {
    Metadata,
    ContentReady,
    AccessDenied,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeReadRestriction {
    CurrentAccessNotEvaluated,
    UserDisabled,
    TrustRevoked,
    WorktreeNotActive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeDirectoryEntry {
    pub stable_key: String,
    pub selection: MemoryScopeSelection,
    pub label: String,
    pub title_state: ScopeTitleState,
    pub path_hint: Option<String>,
    pub branch_hint: Option<String>,
    pub lifecycle: Option<String>,
    pub restrictions: Vec<ScopeReadRestriction>,
    pub has_children: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeDirectoryPage {
    pub frontier: u64,
    pub query: ScopeDirectoryQuery,
    pub parent_available: bool,
    pub complete: bool,
    pub names_complete: bool,
    pub items: Vec<ScopeDirectoryEntry>,
    pub next_cursor: Option<String>,
}

/// Journal recording order, not a claim about event timestamps.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryBrowseOrder {
    #[default]
    RecordedNewest,
    RecordedOldest,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryBrowseQuery {
    pub selection: MemoryScopeSelection,
    pub include_global: bool,
    pub kind: MemoryReadingKind,
    pub order: MemoryBrowseOrder,
    pub epistemic_status: Option<crate::semantic::EpistemicStatus>,
    pub authority: Option<crate::semantic::AtomAuthority>,
    pub atom_lifecycle: Option<crate::semantic::AtomLifecycleStatus>,
}

impl MemoryBrowseQuery {
    pub fn validate(&self) -> Result<(), QueryError> {
        if self.include_global && self.selection.boundary().is_none() {
            return Err(QueryError::Invalid);
        }
        if !matches!(
            self.kind,
            MemoryReadingKind::All | MemoryReadingKind::FactsAndConstraints
        ) && (self.epistemic_status.is_some()
            || self.authority.is_some()
            || self.atom_lifecycle.is_some())
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

/// Opaque to HTTP clients; the complete query binds every continuation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryBrowseCursor {
    pub frontier: u64,
    pub query: MemoryBrowseQuery,
    pub source_event_seq: u64,
    pub row_id: String,
}

impl MemoryBrowseCursor {
    pub fn validate_for(&self, query: &MemoryBrowseQuery) -> Result<(), QueryError> {
        if self.query != *query
            || self.row_id.is_empty()
            || self.row_id.len() > 512
            || self.row_id.chars().any(char::is_control)
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

/// Opaque continuation for one exact source's same-object revision list.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRevisionsCursor {
    pub frontier: u64,
    pub source_key: String,
    pub source_revision: String,
    pub source_event_seq: u64,
    pub row_id: String,
}

impl ObjectRevisionsCursor {
    pub fn validate_for(
        &self,
        source_key: &str,
        source_revision: &str,
        frontier: u64,
    ) -> Result<(), QueryError> {
        if self.source_key != source_key
            || self.source_revision != source_revision
            || self.frontier != frontier
            || self.row_id.is_empty()
            || self.row_id.len() > 512
            || self.row_id.chars().any(char::is_control)
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

/// Continuation for one exact source/dependency anchor, not another object's page.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLinksCursor {
    pub frontier: u64,
    pub source_key: String,
    pub source_revision: String,
    pub after_key: String,
}

impl SourceLinksCursor {
    pub fn validate_for(
        &self,
        source_key: &str,
        source_revision: &str,
        frontier: u64,
    ) -> Result<(), QueryError> {
        if self.source_key != source_key
            || self.source_revision != source_revision
            || self.frontier != frontier
            || self.after_key.is_empty()
            || self.after_key.len() > 512
            || self.after_key.chars().any(char::is_control)
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

/// Shared read states; used by semantic detail, ranges and revision comparisons.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanContentState {
    Ready,
    TooLarge,
    AccessDenied,
    Missing,
    Unsupported,
    Unavailable,
}

pub const HUMAN_COMPARE_LIMIT: u16 = 32;
pub const HUMAN_COMPARE_VALUE_BYTES: usize = 2048;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRevisionRef {
    pub stable_key: String,
    pub revision_ref: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionCompareQuery {
    pub left: HumanRevisionRef,
    pub right: HumanRevisionRef,
}

impl RevisionCompareQuery {
    pub fn validate(&self) -> Result<(), QueryError> {
        if [&self.left, &self.right].into_iter().all(|reference| {
            [&reference.stable_key, &reference.revision_ref]
                .into_iter()
                .all(|value| {
                    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
                })
        }) {
            Ok(())
        } else {
            Err(QueryError::Invalid)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionCompareCursor {
    pub frontier: u64,
    pub query: RevisionCompareQuery,
    pub after_path: String,
}

impl RevisionCompareCursor {
    pub fn validate_for(
        &self,
        query: &RevisionCompareQuery,
        frontier: u64,
    ) -> Result<(), QueryError> {
        query.validate()?;
        if self.query == *query && self.frontier == frontier && compare_path(&self.after_path) {
            Ok(())
        } else {
            Err(QueryError::Invalid)
        }
    }
}

fn compare_path(value: &str) -> bool {
    if !value.starts_with('/') || value.len() > 1024 || value.chars().any(char::is_control) {
        return false;
    }
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
    }
    true
}

/// Absent differs from an existing JSON null; oversized fields never masquerade
/// as empty values. Full values remain available through exact content ranges.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanComparedValue {
    Absent,
    Ready { json: String },
    TooLarge { original_bytes: u64 },
}

impl HumanComparedValue {
    fn validate(&self) -> bool {
        match self {
            Self::Absent => true,
            Self::Ready { json } => !json.is_empty() && json.len() <= HUMAN_COMPARE_VALUE_BYTES,
            Self::TooLarge { original_bytes } => *original_bytes > HUMAN_COMPARE_VALUE_BYTES as u64,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanFieldChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanFieldChange {
    pub path: String,
    pub change: HumanFieldChangeKind,
    pub left: HumanComparedValue,
    pub right: HumanComparedValue,
}

impl HumanFieldChange {
    fn validate(&self) -> bool {
        use HumanComparedValue::{Absent, Ready};
        compare_path(&self.path)
            && self.left.validate()
            && self.right.validate()
            && match (&self.left, &self.right, self.change) {
                (Absent, Absent, _) => false,
                (Absent, _, HumanFieldChangeKind::Added) => true,
                (_, Absent, HumanFieldChangeKind::Removed) => true,
                (Ready { json: left }, Ready { json: right }, HumanFieldChangeKind::Modified) => {
                    left != right
                }
                (left, right, HumanFieldChangeKind::Modified) => {
                    !matches!(left, Absent) && !matches!(right, Absent)
                }
                _ => false,
            }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanRevisionKind {
    Atom,
    Procedure,
    CoreMembership,
    Proposal,
    Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanComparisonStatus {
    Ready,
    SideUnavailable,
    BudgetExhausted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRevisionComparison {
    pub frontier: u64,
    pub query: RevisionCompareQuery,
    pub object_kind: Option<HumanRevisionKind>,
    pub status: HumanComparisonStatus,
    pub left_state: HumanContentState,
    pub right_state: HumanContentState,
    pub fields: Vec<HumanFieldChange>,
    pub changed_fields: Option<u64>,
    pub next_cursor: Option<String>,
}

impl HumanRevisionComparison {
    pub fn validate(&self) -> bool {
        let ready = self.left_state == HumanContentState::Ready
            && self.right_state == HumanContentState::Ready;
        if self.query.validate().is_err() || self.fields.len() > usize::from(HUMAN_COMPARE_LIMIT) {
            return false;
        }
        if self.status != HumanComparisonStatus::Ready {
            return self.fields.is_empty()
                && self.changed_fields.is_none()
                && self.next_cursor.is_none()
                && match self.status {
                    HumanComparisonStatus::SideUnavailable => !ready,
                    HumanComparisonStatus::BudgetExhausted => ready && self.object_kind.is_some(),
                    HumanComparisonStatus::Ready => false,
                };
        }
        ready
            && self.object_kind.is_some()
            && self
                .changed_fields
                .is_some_and(|count| count >= self.fields.len() as u64)
            && self.fields.iter().all(HumanFieldChange::validate)
            && self
                .fields
                .windows(2)
                .all(|pair| pair[0].path < pair[1].path)
            && self.next_cursor.as_ref().is_none_or(|raw| {
                raw.len() <= 8192
                    && !raw.is_empty()
                    && !self.fields.is_empty()
                    && self
                        .changed_fields
                        .is_some_and(|count| count > self.fields.len() as u64)
            })
    }
}

/// Request-local body representation; never a CAS path or generic RPC selector.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanContentRepresentation {
    Text,
    SemanticJson,
    SourceText,
}

pub const HUMAN_CONTENT_LIMIT: u16 = 8192;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanContentCursor {
    pub object_ref: String,
    pub revision_ref: String,
    pub representation: HumanContentRepresentation,
    pub offset: u64,
    pub backwards: bool,
}

impl HumanContentCursor {
    pub fn validate_for(
        &self,
        object_ref: &str,
        revision_ref: &str,
        representation: HumanContentRepresentation,
    ) -> Result<(), QueryError> {
        if self.object_ref != object_ref
            || self.revision_ref != revision_ref
            || self.representation != representation
            || (self.backwards && self.offset == 0)
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum QueryError {
    #[error("query contract is invalid")]
    Invalid,
    #[error("retrieval budget is exhausted")]
    BudgetExhausted,
    #[error("deletion suppression snapshot is unavailable")]
    SuppressionUnavailable,
    #[error("operator is diagnostic-only")]
    DiagnosticOnly,
    #[error("unsupported retrieval operation")]
    Unsupported,
}
