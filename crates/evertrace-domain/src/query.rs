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
#[serde(deny_unknown_fields)]
pub struct SearchCandidate {
    pub candidate_id: String,
    pub source_ref: String,
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
