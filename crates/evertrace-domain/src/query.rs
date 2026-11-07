//! Closed, request-local retrieval contracts.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    evidence::EvidenceSurface,
    ids::{
        AnyPublicId, ExecutionLaneId, JobId, OperationId, RepositoryId, SourceObservationId,
        TaskId, WorkEpisodeId, WorkstreamId, WorktreeId,
    },
    revision::RevisionId,
    semantic::SemanticResolution,
};

pub const MAX_QUERY_BYTES: usize = 8 * 1024;
const MAX_FACET_ITEMS: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FacetParseStatus {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedFacetKind {
    ExactIdentifier,
    ConditionLiteral,
    Exclusion,
    Relation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedFacet {
    pub kind: ProtectedFacetKind,
    /// Index in the original request vector, before removing protected values.
    pub position: u16,
}

impl ProtectedFacet {
    pub fn locator(self) -> String {
        let field = match self.kind {
            ProtectedFacetKind::ExactIdentifier => "exact_identifiers",
            ProtectedFacetKind::ConditionLiteral => "condition_literals",
            ProtectedFacetKind::Exclusion => "explicit_exclusions",
            ProtectedFacetKind::Relation => "relation_requirements",
        };
        format!("{field}:{}", self.position)
    }

    pub fn blocks_ordinary_evidence(self) -> bool {
        matches!(
            self.kind,
            ProtectedFacetKind::ConditionLiteral | ProtectedFacetKind::Exclusion
        )
    }
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
    Before,
    After,
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
    Latest,
    TemporalComparison,
}

impl AnswerShape {
    pub const fn uses_temporal_order(self) -> bool {
        matches!(
            self,
            Self::Timeline | Self::Latest | Self::TemporalComparison
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementRole {
    ObservedSymptom,
    DesiredOutcome,
    Hypothesis,
    DisputedClaim,
    ExplicitConstraint,
    Other,
    Unknown,
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
    OrderBy {
        domain: TemporalOrdering,
    },
    EventTimeAsOf {
        at_us: i64,
    },
    EventTimeBefore {
        at_us: i64,
    },
    EventTimeAfter {
        at_us: i64,
    },
    EventTimeInterval {
        start_us: i64,
        end_us: i64,
    },
    ValidityAsOf {
        at_us: i64,
    },
    ValidityStartsBefore {
        at_us: i64,
    },
    ValidityStartsAfter {
        at_us: i64,
    },
    ValidityInterval {
        start_us: i64,
        end_us: i64,
    },
    SourceSequenceAtMost {
        source_ref: SourceObservationId,
        sequence: u64,
    },
    SourceSequenceBefore {
        source_ref: SourceObservationId,
        sequence: u64,
    },
    SourceSequenceAfter {
        source_ref: SourceObservationId,
        sequence: u64,
    },
}

/// The requested coordinate, never an authorization or a claim of clock accuracy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalOrdering {
    EventTime,
    SourceSequence,
    ValidityStart,
    Supersession,
}

impl TemporalOrdering {
    fn basis(self) -> OrderingBasis {
        match self {
            Self::EventTime => OrderingBasis::EventTime,
            Self::SourceSequence => OrderingBasis::SourceSequence,
            Self::ValidityStart => OrderingBasis::Validity,
            Self::Supersession => OrderingBasis::Supersession,
        }
    }
}

pub fn requested_ordering(qualifiers: &[TemporalQualifier]) -> Option<TemporalOrdering> {
    match qualifiers {
        [TemporalQualifier::OrderBy { domain }] => Some(*domain),
        _ => None,
    }
}

impl TemporalQualifier {
    pub fn source_sequence_ref(&self) -> Option<SourceObservationId> {
        match self {
            Self::SourceSequenceAtMost { source_ref, .. }
            | Self::SourceSequenceBefore { source_ref, .. }
            | Self::SourceSequenceAfter { source_ref, .. } => Some(*source_ref),
            _ => None,
        }
    }

    pub fn matches_sequence(&self, value: u64) -> Option<bool> {
        match self {
            Self::SourceSequenceAtMost { sequence, .. } => Some(value <= *sequence),
            Self::SourceSequenceBefore { sequence, .. } => Some(value < *sequence),
            Self::SourceSequenceAfter { sequence, .. } => Some(value > *sequence),
            _ => None,
        }
    }

    pub fn is_validity(&self) -> bool {
        matches!(
            self,
            Self::ValidityAsOf { .. }
                | Self::ValidityInterval { .. }
                | Self::ValidityStartsBefore { .. }
                | Self::ValidityStartsAfter { .. }
                | Self::OrderBy {
                    domain: TemporalOrdering::ValidityStart
                }
        )
    }

    pub fn is_event_time(&self) -> bool {
        matches!(
            self,
            Self::EventTimeAsOf { .. }
                | Self::EventTimeInterval { .. }
                | Self::EventTimeBefore { .. }
                | Self::EventTimeAfter { .. }
                | Self::OrderBy {
                    domain: TemporalOrdering::EventTime
                }
        )
    }
}

impl TemporalMode {
    pub fn has_temporal_predicate(self) -> bool {
        matches!(
            self,
            Self::AsOf | Self::Interval | Self::Before | Self::After
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalScope {
    pub mode: TemporalMode,
    pub qualifiers: Vec<TemporalQualifier>,
}

impl TemporalScope {
    fn validate(&self) -> Result<(), QueryError> {
        Self::validate_parts(self.mode, &self.qualifiers)
    }

    fn validate_parts(
        mode: TemporalMode,
        qualifiers: &[TemporalQualifier],
    ) -> Result<(), QueryError> {
        let valid = match (mode, qualifiers) {
            (TemporalMode::Current | TemporalMode::Any | TemporalMode::Unknown, [])
            | (TemporalMode::Current | TemporalMode::Any, [TemporalQualifier::OrderBy { .. }]) => {
                true
            }
            (
                TemporalMode::AsOf,
                [
                    TemporalQualifier::EventTimeAsOf { at_us }
                    | TemporalQualifier::ValidityAsOf { at_us },
                ],
            ) => *at_us >= 0,
            (
                TemporalMode::Interval,
                [
                    TemporalQualifier::EventTimeInterval { start_us, end_us }
                    | TemporalQualifier::ValidityInterval { start_us, end_us },
                ],
            ) => *start_us >= 0 && end_us > start_us,
            (TemporalMode::Sequence, [TemporalQualifier::SourceSequenceAtMost { .. }]) => true,
            (
                TemporalMode::Before,
                [
                    TemporalQualifier::EventTimeBefore { at_us }
                    | TemporalQualifier::ValidityStartsBefore { at_us },
                ],
            )
            | (
                TemporalMode::After,
                [
                    TemporalQualifier::EventTimeAfter { at_us }
                    | TemporalQualifier::ValidityStartsAfter { at_us },
                ],
            ) => *at_us >= 0,
            (TemporalMode::Before, [TemporalQualifier::SourceSequenceBefore { .. }])
            | (TemporalMode::After, [TemporalQualifier::SourceSequenceAfter { .. }]) => true,
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(QueryError::Invalid)
        }
    }
}

/// Existing immutable Operation coordinates are `<public ID>@<positive revision>`.
pub fn parse_operation_revision(value: &str) -> Option<(OperationId, u32)> {
    let (id, revision) = value.rsplit_once('@')?;
    let id = id.parse::<OperationId>().ok()?;
    let revision = revision.parse::<u32>().ok().filter(|value| *value > 0)?;
    (value == format!("{id}@{revision}")).then_some((id, revision))
}

pub fn valid_object_reference(value: &str) -> bool {
    value.parse::<AnyPublicId>().is_ok()
        || value.parse::<RevisionId>().is_ok()
        || parse_operation_revision(value).is_some()
}

fn valid_target(value: &str) -> bool {
    value.len() <= 512
        && (valid_object_reference(value) || EvidenceSurface::parse_candidate_ref(value).is_some())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuantityConstraint {
    ResultLimit { limit: u32 },
    DistinctCount { unit: CountUnit },
}

/// A source record is not a physical execution; revisions are not logical objects.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CountUnit {
    ObjectRevision,
    SourceObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryFacetSet {
    pub parse_status: FacetParseStatus,
    pub target_anchors: Vec<String>,
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
    pub statement_role: StatementRole,
    pub lifecycle_boundary: LifecycleBoundary,
}

impl QueryFacetSet {
    pub fn count_unit(&self) -> Option<CountUnit> {
        self.quantity_constraints
            .iter()
            .find_map(|constraint| match constraint {
                QuantityConstraint::DistinctCount { unit } => Some(*unit),
                QuantityConstraint::ResultLimit { .. } => None,
            })
    }

    pub fn validate(&self) -> Result<(), QueryError> {
        for values in [
            &self.target_anchors,
            &self.exact_identifiers,
            &self.condition_literals,
            &self.relation_requirements,
            &self.explicit_exclusions,
        ] {
            if values.len() > MAX_FACET_ITEMS
                || values
                    .iter()
                    .any(|value| value.is_empty() || value.len() > 512)
                || values.iter().collect::<BTreeSet<_>>().len() != values.len()
            {
                return Err(QueryError::Invalid);
            }
        }
        if self.target_anchors.iter().any(|value| !valid_target(value))
            || self.quantity_constraints.len() > MAX_FACET_ITEMS
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
        {
            return Err(QueryError::Invalid);
        }
        let count_operands = self
            .quantity_constraints
            .iter()
            .filter(|constraint| matches!(constraint, QuantityConstraint::DistinctCount { .. }))
            .count();
        if count_operands > 1
            || (count_operands == 1 && self.answer_shape != Some(AnswerShape::Count))
            || (requested_ordering(&self.temporal_qualifiers).is_some()
                && !self
                    .answer_shape
                    .is_some_and(AnswerShape::uses_temporal_order))
            || (self.answer_shape == Some(AnswerShape::TemporalComparison)
                && (self.target_anchors.len() != 2
                    || requested_ordering(&self.temporal_qualifiers).is_none()))
        {
            return Err(QueryError::Invalid);
        }
        TemporalScope::validate_parts(self.temporal_mode, &self.temporal_qualifiers)
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
    ProtectedFacet,
    TemporalEvidence,
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
pub struct EvidenceNeed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count_unit: Option<CountUnit>,
    pub intent: SearchIntent,
    pub target: Vec<String>,
    pub answer_shape: Option<AnswerShape>,
    pub temporal_scope: TemporalScope,
    pub source_boundary: Option<SourceBoundary>,
    pub statement_role: StatementRole,
    pub parse_status: FacetParseStatus,
}

impl EvidenceNeed {
    pub fn from_context(context: &SearchContext) -> Self {
        let facets = &context.query_facets;
        Self {
            count_unit: facets.count_unit(),
            intent: context.intent,
            target: facets.target_anchors.clone(),
            answer_shape: facets.answer_shape,
            temporal_scope: TemporalScope {
                mode: facets.temporal_mode,
                qualifiers: facets.temporal_qualifiers.clone(),
            },
            source_boundary: facets.source_boundary,
            statement_role: facets.statement_role,
            parse_status: facets.parse_status,
        }
    }

    fn validate(&self) -> Result<(), QueryError> {
        if (self.count_unit.is_some() && self.answer_shape != Some(AnswerShape::Count))
            || (requested_ordering(&self.temporal_scope.qualifiers).is_some()
                && !self
                    .answer_shape
                    .is_some_and(AnswerShape::uses_temporal_order))
            || (self.answer_shape == Some(AnswerShape::TemporalComparison)
                && (self.target.len() != 2
                    || requested_ordering(&self.temporal_scope.qualifiers).is_none()))
            || self.target.len() > MAX_FACET_ITEMS
            || self.target.iter().any(|value| !valid_target(value))
            || self.target.iter().collect::<BTreeSet<_>>().len() != self.target.len()
        {
            return Err(QueryError::Invalid);
        }
        self.temporal_scope.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRole {
    Direct,
    Bridge,
    Update,
    Contrast,
    ConstraintSupport,
}

impl EvidenceRole {
    pub fn for_relation(kind: &str) -> Option<Self> {
        match kind {
            "atom_supersedes" => Some(Self::Update),
            "atom_contradicts" => Some(Self::Contrast),
            "task_contains_workstream"
            | "workstream_parent"
            | "workstream_dependency"
            | "attempt_to_task"
            | "attempt_to_workstream"
            | "attempt_to_episode"
            | "episode_to_task"
            | "episode_to_attempt"
            | "run_to_workstream"
            | "run_to_attempt"
            | "run_to_artifact"
            | "result_produced_by_run"
            | "result_to_raw_artifact"
            | "artifact_produced_by_run"
            | "artifact_produced_by_operation"
            | "operation_to_scope_effect"
            | "binding_to_primary_task"
            | "binding_to_primary_workstream"
            | "atom_from_source_observation"
            | "atom_supports" => Some(Self::Bridge),
            _ => None,
        }
    }

    pub fn ordering_basis(self) -> OrderingBasis {
        match self {
            Self::Update => OrderingBasis::Supersession,
            _ => OrderingBasis::Unknown,
        }
    }
}

pub fn relation_allowed(kind: &str) -> bool {
    EvidenceRole::for_relation(kind).is_some()
}

/// Closed mechanical projection of a validated typed edge, not free prose.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedRelationStatement {
    pub relation_kind: String,
    pub source_ref: String,
    pub target_ref: String,
    pub frontier: u64,
}

/// Resolve the statement, support refs, ordering and trust from active_evidence.
/// Keeping one clause prevents trace metadata from duplicating the answer budget.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedTraceStep {
    pub role: EvidenceRole,
    pub statement_index: u32,
    pub relation: Option<String>,
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
    /// Exact only within candidate_set, never a catalog or physical-event total.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_count: Option<GroundedCount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_latest: Option<GroundedLatest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_comparison: Option<GroundedTemporalComparison>,
    pub evidence_need: EvidenceNeed,
    pub candidate_set: CandidateBoundary,
    pub trace: Vec<GroundedTraceStep>,
    pub active_evidence: Vec<GroundedStatement>,
    pub unresolved_gaps: Vec<NamedGap>,
    pub conflicts: BTreeSet<String>,
    pub completeness: RetrievalCompleteness,
    pub omitted_refs: BTreeSet<String>,
}

/// Versioned mechanical operator over existing trace slots; no duplicated refs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedCount {
    pub operator_revision: u32,
    pub value: Option<u32>,
    pub statement_indices: BTreeSet<u32>,
}

pub const MAX_GROUNDED_COUNT_BYTES: usize = 256;
pub const MAX_GROUNDED_LATEST_BYTES: usize = 512;
pub const MAX_GROUNDED_COMPARISON_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalComparisonRelation {
    Before,
    Equal,
    After,
    Unknown,
}

/// Signed exact decimals avoid JSON/JavaScript precision loss; bounds use i128 arithmetic.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalDeltaMicros {
    pub minimum: String,
    pub maximum: String,
}

impl TemporalDeltaMicros {
    fn bounds(&self) -> Option<(i128, i128)> {
        let minimum = self.minimum.parse::<i128>().ok()?;
        let maximum = self.maximum.parse::<i128>().ok()?;
        (minimum <= maximum
            && self.minimum == minimum.to_string()
            && self.maximum == maximum.to_string())
        .then_some((minimum, maximum))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedTemporalComparison {
    pub operator_revision: u32,
    /// Slots bind evidence_need.target[0] and [1], never an inferred pair.
    pub operand_indices: [Option<u32>; 2],
    pub relation: TemporalComparisonRelation,
    pub ordering_basis: OrderingBasis,
    /// None for sequence/revision coordinates or unknown clocks, never ordinal-to-time conversion.
    pub right_minus_left_us: Option<TemporalDeltaMicros>,
}

fn delta_relation(minimum: i128, maximum: i128) -> TemporalComparisonRelation {
    if minimum > 0 {
        TemporalComparisonRelation::Before
    } else if maximum < 0 {
        TemporalComparisonRelation::After
    } else if minimum == 0 && maximum == 0 {
        TemporalComparisonRelation::Equal
    } else {
        TemporalComparisonRelation::Unknown
    }
}

impl GroundedTemporalComparison {
    fn validate(
        &self,
        need: &EvidenceNeed,
        statements: &[GroundedStatement],
    ) -> Result<(), QueryError> {
        if need.answer_shape != Some(AnswerShape::TemporalComparison)
            || self.operator_revision != 1
            || self.operand_indices.iter().flatten().any(|index| {
                statements
                    .get(*index as usize)
                    .is_none_or(|statement| statement.derivation_kind != DerivationKind::Quoted)
            })
            || serde_json::to_vec(self)
                .map_or(true, |bytes| bytes.len() > MAX_GROUNDED_COMPARISON_BYTES)
        {
            return Err(QueryError::Invalid);
        }
        let domain =
            requested_ordering(&need.temporal_scope.qualifiers).ok_or(QueryError::Invalid)?;
        let resolved = self.operand_indices.iter().all(Option::is_some);
        let relation = match self.ordering_basis {
            OrderingBasis::Unknown if self.right_minus_left_us.is_none() => {
                Some(TemporalComparisonRelation::Unknown)
            }
            OrderingBasis::EventTime | OrderingBasis::Validity => self
                .right_minus_left_us
                .as_ref()
                .and_then(TemporalDeltaMicros::bounds)
                .map(|(minimum, maximum)| delta_relation(minimum, maximum)),
            OrderingBasis::SourceSequence | OrderingBasis::Supersession
                if self.right_minus_left_us.is_none()
                    && self.relation != TemporalComparisonRelation::Unknown =>
            {
                Some(self.relation)
            }
            _ => None,
        };
        if relation != Some(self.relation)
            || (self.ordering_basis != OrderingBasis::Unknown
                && (!resolved || self.ordering_basis != domain.basis()))
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedLatest {
    pub operator_revision: u32,
    pub operand_indices: BTreeSet<u32>,
    /// None: no proven maximum. Some(empty): no matching operands. Ties remain ties.
    /// Recorded-at winners are provisional; they cannot make the view complete.
    pub statement_indices: Option<BTreeSet<u32>>,
    pub ordering_basis: OrderingBasis,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Order within a proven revision domain, never UTC. Objects use admission order;
/// sources use bounded replacement ranks, then source sequence within each rank.
pub struct RevisionOrderPosition {
    pub anchor: String,
    pub sequence: u64,
}

impl RevisionOrderPosition {
    pub fn wire_bytes(&self) -> usize {
        serde_json::to_vec(self).map_or(usize::MAX, |bytes| bytes.len() + 18)
    }
}

impl GroundedEvidenceView {
    fn quoted_operands<'a>(
        &self,
        candidates: &'a [SearchCandidate],
        matching_constraints: &BTreeSet<u32>,
    ) -> Option<Vec<(u32, &'a SearchCandidate)>> {
        let mut operands = Vec::new();
        for step in &self.trace {
            if step.role == EvidenceRole::ConstraintSupport
                && !matching_constraints.contains(&step.statement_index)
            {
                continue;
            }
            let statement = self.active_evidence.get(step.statement_index as usize)?;
            if statement.derivation_kind != DerivationKind::Quoted {
                continue;
            }
            let candidate = candidates
                .iter()
                .find(|candidate| statement.support_refs.contains(&candidate.candidate_id))?;
            if candidate.temporal_match(&self.evidence_need.temporal_scope.qualifiers)
                != Some(false)
            {
                operands.push((step.statement_index, candidate));
            }
        }
        Some(operands)
    }

    pub fn derive_candidate_count(
        &self,
        candidates: &[SearchCandidate],
        matching_constraints: &BTreeSet<u32>,
    ) -> Option<GroundedCount> {
        if self.evidence_need.answer_shape != Some(AnswerShape::Count) {
            return None;
        }
        let unit = self.evidence_need.count_unit?;
        let mut identities = BTreeSet::new();
        let mut statement_indices = BTreeSet::new();
        for (index, candidate) in self.quoted_operands(candidates, matching_constraints)? {
            let identity = match unit {
                CountUnit::ObjectRevision
                    if candidate.row_variant == SearchCandidateVariant::Object =>
                {
                    if candidate.object_kind.as_deref()? == "wiki_projection" {
                        continue;
                    }
                    candidate.candidate_id.as_str()
                }
                CountUnit::SourceObservation
                    if candidate.row_variant == SearchCandidateVariant::EvidenceSurface =>
                {
                    candidate.source_ref.parse::<SourceObservationId>().ok()?;
                    candidate.source_ref.as_str()
                }
                _ => continue,
            };
            identities.insert(identity);
            statement_indices.insert(index);
        }
        Some(GroundedCount {
            operator_revision: 1,
            value: (self.completeness == RetrievalCompleteness::Complete)
                .then(|| u32::try_from(identities.len()).ok())
                .flatten(),
            statement_indices,
        })
    }

    pub fn count_temporal_gaps(&self, candidates: &[SearchCandidate]) -> BTreeSet<String> {
        let mut gaps = BTreeSet::new();
        if self.evidence_need.temporal_scope.qualifiers.is_empty() {
            return gaps;
        }
        if let Some(count) = &self.candidate_count {
            for index in &count.statement_indices {
                if let Some(statement) = self.active_evidence.get(*index as usize) {
                    for candidate in candidates {
                        if statement.support_refs.contains(&candidate.candidate_id)
                            && candidate
                                .temporal_match(&self.evidence_need.temporal_scope.qualifiers)
                                .is_none()
                        {
                            gaps.insert(candidate.source_ref.clone());
                        }
                    }
                }
            }
        }
        gaps
    }

    pub fn ordering_temporal_gaps(&self, candidates: &[SearchCandidate]) -> BTreeSet<String> {
        if self
            .candidate_comparison
            .as_ref()
            .is_some_and(|comparison| comparison.relation == TemporalComparisonRelation::Unknown)
        {
            return self.evidence_need.target.iter().cloned().collect();
        }
        if self.evidence_need.answer_shape == Some(AnswerShape::Timeline)
            && requested_ordering(&self.evidence_need.temporal_scope.qualifiers).is_some()
            && timeline_order(candidates, &self.evidence_need.temporal_scope.qualifiers)
                .is_none_or(|(basis, _)| basis == OrderingBasis::RecordedAtFallback)
        {
            return candidates
                .iter()
                .map(|candidate| candidate.source_ref.clone())
                .collect();
        }
        let mut gaps = BTreeSet::new();
        if let Some(latest) = &self.candidate_latest
            && (latest.statement_indices.is_none()
                || (latest.ordering_basis == OrderingBasis::RecordedAtFallback
                    && requested_ordering(&self.evidence_need.temporal_scope.qualifiers).is_some()))
        {
            for index in &latest.operand_indices {
                for candidate in candidates {
                    if self
                        .active_evidence
                        .get(*index as usize)
                        .is_some_and(|statement| {
                            statement.support_refs.contains(&candidate.candidate_id)
                        })
                    {
                        gaps.insert(candidate.source_ref.clone());
                    }
                }
            }
        }
        gaps
    }

    pub fn latest_source_coverage_complete(&self, candidates: &[SearchCandidate]) -> bool {
        let Some(latest) = &self.candidate_latest else {
            return true;
        };
        let indices = match latest.ordering_basis {
            OrderingBasis::SourceSequence => &latest.operand_indices,
            OrderingBasis::Supersession => match &latest.statement_indices {
                Some(indices) => indices,
                None => return false,
            },
            _ => return true,
        };
        indices.iter().all(|index| {
            self.active_evidence
                .get(*index as usize)
                .is_some_and(|statement| {
                    candidates
                        .iter()
                        .find(|candidate| statement.support_refs.contains(&candidate.candidate_id))
                        .is_some_and(|candidate| {
                            candidate.row_variant != SearchCandidateVariant::EvidenceSurface
                                || candidate
                                    .source_sequence
                                    .as_ref()
                                    .is_some_and(|position| position.coverage_complete)
                        })
                })
        })
    }

    pub fn validate(&self) -> Result<(), QueryError> {
        self.validate_inner(None)
    }

    pub fn validate_at_frontier(&self, frontier: u64) -> Result<(), QueryError> {
        self.validate_inner(Some(frontier))
    }

    fn relation_clauses(&self) -> Vec<GroundedRelationStatement> {
        self.active_evidence
            .iter()
            .filter(|statement| statement.derivation_kind == DerivationKind::DeterministicDerived)
            .filter_map(|statement| serde_json::from_str(&statement.statement).ok())
            .collect()
    }

    pub fn derive_candidate_comparison(
        &self,
        candidates: &[SearchCandidate],
        matching_constraints: &BTreeSet<u32>,
    ) -> Option<GroundedTemporalComparison> {
        if self.evidence_need.answer_shape != Some(AnswerShape::TemporalComparison)
            || self.evidence_need.target.len() != 2
        {
            return None;
        }
        let domain = requested_ordering(&self.evidence_need.temporal_scope.qualifiers)?;
        let operands = self.quoted_operands(candidates, matching_constraints)?;
        let selected: [Option<(u32, &SearchCandidate)>; 2] = std::array::from_fn(|index| {
            let mut matches = operands.iter().filter(|(_, candidate)| {
                candidate.matches_reference(&self.evidence_need.target[index])
            });
            let selected = matches.next().copied()?;
            matches.next().is_none().then_some(selected)
        });
        let mut comparison = GroundedTemporalComparison {
            operator_revision: 1,
            operand_indices: selected.map(|operand| operand.map(|(index, _)| index)),
            relation: TemporalComparisonRelation::Unknown,
            ordering_basis: OrderingBasis::Unknown,
            right_minus_left_us: None,
        };
        let [Some((left_index, left)), Some((right_index, right))] = selected else {
            return Some(comparison);
        };
        if !self.conflicts.is_empty() || left.conflicted || right.conflicted {
            return Some(comparison);
        }
        if left_index == right_index {
            let known = match domain {
                TemporalOrdering::SourceSequence => left.source_sequence.is_some(),
                TemporalOrdering::Supersession => left.revision_order.is_some(),
                TemporalOrdering::ValidityStart => left
                    .validity_interval
                    .as_ref()
                    .is_some_and(|validity| validity.validate().is_ok()),
                TemporalOrdering::EventTime => left.source_time.as_ref().is_some_and(|position| {
                    position.validate()
                        && matches!(
                            position.provenance,
                            Some(crate::evidence::EventTimeProvenance::SourceTimestamp { .. })
                        )
                }),
            };
            if known {
                comparison.ordering_basis = domain.basis();
                comparison.relation = TemporalComparisonRelation::Equal;
                // Both slots cite one immutable coordinate; no clock accuracy is invented.
                if matches!(
                    domain,
                    TemporalOrdering::EventTime | TemporalOrdering::ValidityStart
                ) {
                    comparison.right_minus_left_us = Some(TemporalDeltaMicros {
                        minimum: "0".into(),
                        maximum: "0".into(),
                    });
                }
            }
            return Some(comparison);
        }
        match domain {
            TemporalOrdering::SourceSequence => {
                if let Some((left, right)) = left
                    .source_sequence
                    .as_ref()
                    .zip(right.source_sequence.as_ref())
                    && left.source_anchor == right.source_anchor
                {
                    comparison.ordering_basis = OrderingBasis::SourceSequence;
                    comparison.relation = match left.sequence.cmp(&right.sequence) {
                        std::cmp::Ordering::Less => TemporalComparisonRelation::Before,
                        std::cmp::Ordering::Equal => TemporalComparisonRelation::Equal,
                        std::cmp::Ordering::Greater => TemporalComparisonRelation::After,
                    };
                }
            }
            TemporalOrdering::Supersession => {
                if let Some((basis, winners)) = latest_order(
                    &[left, right],
                    candidates,
                    &self.evidence_need.temporal_scope.qualifiers,
                    &self.relation_clauses(),
                ) {
                    comparison.ordering_basis = basis;
                    comparison.relation = if winners.len() == 2 {
                        TemporalComparisonRelation::Equal
                    } else if winners.contains(left.candidate_id.as_str()) {
                        TemporalComparisonRelation::After
                    } else {
                        TemporalComparisonRelation::Before
                    };
                }
            }
            TemporalOrdering::EventTime | TemporalOrdering::ValidityStart => {
                let window = |candidate: &SearchCandidate| match domain {
                    TemporalOrdering::EventTime => candidate
                        .source_time
                        .as_ref()
                        .filter(|position| position.validate())?
                        .event_window(),
                    TemporalOrdering::ValidityStart => {
                        let validity = candidate.validity_interval.as_ref()?;
                        validity.validate().ok()?;
                        Some((
                            i128::from(validity.valid_from_us),
                            i128::from(validity.valid_from_us),
                        ))
                    }
                    _ => None,
                };
                if let Some(((left_min, left_max), (right_min, right_max))) =
                    window(left).zip(window(right))
                {
                    let minimum = right_min - left_max;
                    let maximum = right_max - left_min;
                    comparison.ordering_basis = domain.basis();
                    comparison.relation = delta_relation(minimum, maximum);
                    comparison.right_minus_left_us = Some(TemporalDeltaMicros {
                        minimum: minimum.to_string(),
                        maximum: maximum.to_string(),
                    });
                }
            }
        }
        Some(comparison)
    }

    pub fn derive_candidate_latest(
        &self,
        candidates: &[SearchCandidate],
        matching_constraints: &BTreeSet<u32>,
    ) -> Option<GroundedLatest> {
        if self.evidence_need.answer_shape != Some(AnswerShape::Latest) {
            return None;
        }
        let (indices, operands): (Vec<_>, Vec<_>) = self
            .quoted_operands(candidates, matching_constraints)?
            .into_iter()
            .unzip();
        let relations = self.relation_clauses();
        let order = self
            .conflicts
            .is_empty()
            .then(|| {
                latest_order(
                    &operands,
                    candidates,
                    &self.evidence_need.temporal_scope.qualifiers,
                    &relations,
                )
            })
            .flatten();
        Some(GroundedLatest {
            operator_revision: 1,
            operand_indices: indices.iter().copied().collect(),
            statement_indices: order.as_ref().map(|(_, winners)| {
                indices
                    .iter()
                    .zip(&operands)
                    .filter(|(_, candidate)| winners.contains(candidate.candidate_id.as_str()))
                    .map(|(index, _)| *index)
                    .collect()
            }),
            ordering_basis: order.map_or(OrderingBasis::Unknown, |(basis, _)| basis),
        })
    }

    fn validate_inner(&self, frontier: Option<u64>) -> Result<(), QueryError> {
        self.evidence_need.validate()?;
        if let Some(comparison) = &self.candidate_comparison {
            comparison.validate(&self.evidence_need, &self.active_evidence)?;
        }
        if let Some(latest) = &self.candidate_latest {
            if self.evidence_need.answer_shape != Some(AnswerShape::Latest)
                || latest.operator_revision != 1
                || latest.operand_indices.iter().any(|index| {
                    self.active_evidence
                        .get(*index as usize)
                        .is_none_or(|statement| statement.derivation_kind != DerivationKind::Quoted)
                })
                || latest
                    .statement_indices
                    .as_ref()
                    .is_some_and(|indices| !indices.is_subset(&latest.operand_indices))
                || serde_json::to_vec(latest)
                    .map_or(true, |bytes| bytes.len() > MAX_GROUNDED_LATEST_BYTES)
            {
                return Err(QueryError::Invalid);
            }
        }
        self.candidate_set.validate()?;
        if let Some(count) = &self.candidate_count {
            if self.evidence_need.answer_shape != Some(AnswerShape::Count)
                || self.evidence_need.count_unit.is_none()
                || count.operator_revision != 1
                || count.value.is_some() != (self.completeness == RetrievalCompleteness::Complete)
                || count.statement_indices.iter().any(|index| {
                    self.active_evidence
                        .get(*index as usize)
                        .is_none_or(|statement| statement.derivation_kind != DerivationKind::Quoted)
                })
                || serde_json::to_vec(count)
                    .map_err(|_| QueryError::Invalid)?
                    .len()
                    > MAX_GROUNDED_COUNT_BYTES
            {
                return Err(QueryError::Invalid);
            }
        }
        let mut covered = BTreeSet::new();
        for step in &self.trace {
            let index = step.statement_index as usize;
            let statement = self.active_evidence.get(index).ok_or(QueryError::Invalid)?;
            if !covered.insert(index) {
                return Err(QueryError::Invalid);
            }
            if let Some(kind) = &step.relation {
                let clause: GroundedRelationStatement =
                    serde_json::from_str(&statement.statement).map_err(|_| QueryError::Invalid)?;
                if Some(step.role) != EvidenceRole::for_relation(kind)
                    || statement.ordering_basis != step.role.ordering_basis()
                    || statement.derivation_kind != DerivationKind::DeterministicDerived
                    || clause.relation_kind != *kind
                    || statement.support_refs
                        != BTreeSet::from([clause.source_ref, clause.target_ref])
                    || frontier.is_some_and(|expected| clause.frontier != expected)
                {
                    return Err(QueryError::Invalid);
                }
            }
        }
        if covered.len() != self.active_evidence.len() {
            return Err(QueryError::Invalid);
        }
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
            && (self.evidence_need.parse_status != FacetParseStatus::Complete
                || !self.unresolved_gaps.is_empty()
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryBindingStrength {
    Exact,
    ConnectionScoped,
    CwdOnly,
    Unavailable,
}

/// Native caller continuity, not a source-session or permission filter.
/// Requested scope remains in the context's scope fields and query facets.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryAnchor {
    pub runtime_session_id: Option<String>,
    pub turn_id: Option<String>,
    pub execution_lane_id: Option<ExecutionLaneId>,
    pub workstream_id: Option<WorkstreamId>,
    pub episode_id: Option<WorkEpisodeId>,
    pub episode_revision_id: Option<RevisionId>,
    pub binding_strength: QueryBindingStrength,
}

impl QueryAnchor {
    pub const fn unavailable() -> Self {
        Self {
            runtime_session_id: None,
            turn_id: None,
            execution_lane_id: None,
            workstream_id: None,
            episode_id: None,
            episode_revision_id: None,
            binding_strength: QueryBindingStrength::Unavailable,
        }
    }

    pub fn validate(&self) -> Result<(), QueryError> {
        if [&self.runtime_session_id, &self.turn_id]
            .into_iter()
            .flatten()
            .any(|value| {
                value.is_empty() || value.len() > 512 || value.chars().any(char::is_control)
            })
        {
            return Err(QueryError::Invalid);
        }
        let execution_fields = [
            self.execution_lane_id.is_some(),
            self.workstream_id.is_some(),
            self.episode_id.is_some(),
            self.episode_revision_id.is_some(),
        ];
        match self.binding_strength {
            QueryBindingStrength::Exact | QueryBindingStrength::ConnectionScoped => {
                if self.runtime_session_id.is_none() || execution_fields.contains(&false) {
                    return Err(QueryError::Invalid);
                }
            }
            QueryBindingStrength::CwdOnly | QueryBindingStrength::Unavailable => {
                if execution_fields.contains(&true)
                    || self.turn_id.is_some()
                    || (self.binding_strength == QueryBindingStrength::Unavailable
                        && self.runtime_session_id.is_some())
                {
                    return Err(QueryError::Invalid);
                }
            }
        }
        Ok(())
    }
}

/// Canonical primary-shard observations, not a permission or trust grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRepositoryState {
    pub repository: crate::repository::RepositoryInstance,
    pub worktree: Option<crate::repository::WorktreeInstance>,
    pub snapshot: Option<crate::repository::WorktreeSnapshot>,
}

impl QueryRepositoryState {
    pub fn validate(&self, episode: &crate::work::WorkEpisode) -> Result<(), QueryError> {
        self.repository
            .validate()
            .map_err(|_| QueryError::Invalid)?;
        if episode.repository_instance_id != Some(self.repository.repository_id) {
            return Err(QueryError::Invalid);
        }
        if let Some(worktree) = &self.worktree {
            worktree.validate().map_err(|_| QueryError::Invalid)?;
            if Some(worktree.worktree_instance_id) != episode.worktree_instance_id
                || worktree.repository_instance_id != self.repository.repository_id
            {
                return Err(QueryError::Invalid);
            }
        }
        if let Some(snapshot) = &self.snapshot {
            snapshot.validate().map_err(|_| QueryError::Invalid)?;
            let worktree = self.worktree.as_ref().ok_or(QueryError::Invalid)?;
            if worktree.current_snapshot_id != Some(snapshot.worktree_snapshot_id)
                || snapshot.worktree_instance_id != worktree.worktree_instance_id
            {
                return Err(QueryError::Invalid);
            }
        }
        Ok(())
    }
}

/// Receipt-derived metadata, not an execution or permission grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryCaptureContext {
    pub relevant_lane_ids: Vec<ExecutionLaneId>,
    pub relevant_capture_receipt_revision_ids: Vec<crate::ids::CaptureReceiptId>,
    pub unavailable_lane_ids: Vec<ExecutionLaneId>,
    pub summary: crate::work::CaptureSummary,
    /// Distinct declared gap ranges/markers/outages, not physical event count.
    /// None means a relevant lane's receipt could not be read.
    pub unresolved_gap_count: Option<u64>,
}

impl QueryCaptureContext {
    pub fn validate(
        &self,
        episode: &crate::work::WorkEpisode,
        anchor: &QueryAnchor,
    ) -> Result<(), QueryError> {
        use crate::work::{
            CoverageLevel, OrderingIntegrity, PairingIntegrity, PayloadIntegrity, SourceCoverage,
        };
        let mut expected = episode.execution_lane_ids.clone();
        expected.extend(anchor.execution_lane_id);
        expected.sort();
        expected.dedup();
        self.summary.validate().map_err(|_| QueryError::Invalid)?;
        if expected.is_empty()
            || self.relevant_lane_ids != expected
            || !self
                .unavailable_lane_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || self
                .unavailable_lane_ids
                .iter()
                .any(|id| expected.binary_search(id).is_err())
            || !self
                .relevant_capture_receipt_revision_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || self.relevant_capture_receipt_revision_ids.len() + self.unavailable_lane_ids.len()
                != expected.len()
            || self.unavailable_lane_ids.is_empty() != self.unresolved_gap_count.is_some()
        {
            return Err(QueryError::Invalid);
        }
        if !self.unavailable_lane_ids.is_empty()
            && (self.summary.minimum_coverage_level != CoverageLevel::Opaque
                || !self
                    .summary
                    .source_coverage_states
                    .contains(&SourceCoverage::Unavailable)
                || !self
                    .summary
                    .pairing_integrity_states
                    .contains(&PairingIntegrity::Unavailable)
                || !self
                    .summary
                    .payload_integrity_states
                    .contains(&PayloadIntegrity::Unavailable)
                || !self
                    .summary
                    .ordering_integrity_states
                    .contains(&OrderingIntegrity::Unavailable))
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStateConfidence {
    Candidate,
    /// The state operand has qualified observations, not proof of success or APPLY.
    Confirmed,
}

/// One canonical Run and the current binding that selected it, not APPLY authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryExperimentState {
    pub run: crate::work::ExperimentRun,
    pub source: QueryExperimentSource,
    pub confidence: QueryStateConfidence,
}

/// Native observation links, without copying protected source bodies into a query.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryExperimentSource {
    pub work_binding_revision_id: crate::ids::WorkBindingRevisionId,
    pub operation_revision: Option<u32>,
    /// Only complete, visible receipts from an exact-physical paired Operation.
    pub receipt_refs: Vec<crate::ids::SourceReceiptId>,
}

/// Native provenance from the current lane or its explicitly linked parent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryVerificationSource {
    pub attempt_revision_id: RevisionId,
    pub caller_lane_id: crate::ids::ExecutionLaneId,
    pub verification_lane_id: crate::ids::ExecutionLaneId,
    pub result_id: crate::ids::ResultEvidenceId,
    pub result_revision_id: RevisionId,
    pub run_revision_id: RevisionId,
    pub work_binding_revision_id: crate::ids::WorkBindingRevisionId,
    pub operation_id: crate::ids::OperationId,
    pub operation_revision: u32,
    pub receipt_refs: Vec<crate::ids::SourceReceiptId>,
}

/// The explicit Attempt decision and its provenance, never a metric-to-pass conversion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryVerificationState {
    pub value: crate::work::AttemptVerification,
    pub confidence: QueryStateConfidence,
    pub source: Option<Box<QueryVerificationSource>>,
}

/// A declared dependency is a reference, never another primary current state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRelatedScopeShard {
    pub workstream_id: WorkstreamId,
    pub declared_by_revision_id: RevisionId,
    /// Missing or product-invisible targets retain only the already-declared ID.
    pub target: Option<QueryRelatedScopeTarget>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRelatedScopeTarget {
    pub workstream_revision_id: RevisionId,
    pub task_id: TaskId,
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_id: Option<WorktreeId>,
}

/// Canonical Work revisions pinned to one read, never another state store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryExecution {
    pub frontier: u64,
    pub repository_state: Option<Box<QueryRepositoryState>>,
    pub capture_context: Option<Box<QueryCaptureContext>>,
    pub related_scope_shards: Vec<QueryRelatedScopeShard>,
    pub task: crate::work::Task,
    pub workstream: crate::work::Workstream,
    pub episode: crate::work::WorkEpisode,
    /// A canonical candidate; execution operands require `resolved_attempt`.
    pub attempt: Option<crate::work::Attempt>,
    pub experiment: Option<Box<QueryExperimentState>>,
    pub verification: Option<QueryVerificationState>,
    pub work_binding: Option<crate::work::WorkBindingRevision>,
    pub checkpoint: Option<crate::work::WorkCheckpoint>,
}

impl QueryExecution {
    /// Resolved execution context, not physical Operation attribution.
    pub fn resolved_attempt(&self) -> Option<&crate::work::Attempt> {
        let attempt = self.attempt.as_ref()?;
        let binding = self.work_binding.as_ref()?;
        let primary = &binding.primary_binding;
        (binding.assignment_status == crate::work::AssignmentStatus::Resolved
            && primary.task_id == Some(self.task.task_id)
            && primary.workstream_id == Some(self.workstream.workstream_id)
            && primary.episode_id == Some(self.episode.episode_id)
            && primary.attempt_id.is_none_or(|id| id == attempt.attempt_id))
        .then_some(attempt)
    }

    pub fn experiment_confidence(
        &self,
        run: &crate::work::ExperimentRun,
        source: &QueryExperimentSource,
    ) -> QueryStateConfidence {
        use crate::work::{
            AttemptBindingStatus, RunContractValidity, RunExecutionStatus, RunObservability,
        };
        // This terminal is compiled by the independent deterministic resolver
        // and admitted with its exact physical/Result cohort, not inferred from
        // the caller lane's capture summary. Ordinary declarations remain candidates.
        if run.comparison_execution_binding.is_some()
            && run.execution_status == RunExecutionStatus::Completed
            && source
                .operation_revision
                .is_some_and(|revision| revision > 0)
            && !source.receipt_refs.is_empty()
            && self.resolved_attempt().is_some_and(|attempt| {
                run.attempt_binding_status == AttemptBindingStatus::Resolved
                    && run.attempt_id == Some(attempt.attempt_id)
                    && run.strategy_contract_fingerprint == attempt.strategy_contract_fingerprint
            })
            && run.observability == RunObservability::Full
            && run.contract_validity == RunContractValidity::Valid
        {
            QueryStateConfidence::Confirmed
        } else {
            QueryStateConfidence::Candidate
        }
    }

    pub fn validate(
        &self,
        anchor: &QueryAnchor,
        task_id: Option<TaskId>,
    ) -> Result<(), QueryError> {
        use crate::work::{AssignmentStatus, EpisodeLifecycle, WorkstreamStatus};
        anchor.validate()?;
        self.task.validate().map_err(|_| QueryError::Invalid)?;
        self.workstream
            .validate()
            .map_err(|_| QueryError::Invalid)?;
        self.episode.validate().map_err(|_| QueryError::Invalid)?;
        if self.related_scope_shards.len() != self.workstream.dependency_workstream_ids.len()
            || self
                .related_scope_shards
                .iter()
                .zip(&self.workstream.dependency_workstream_ids)
                .any(|(related, id)| {
                    related.workstream_id != *id
                        || related.declared_by_revision_id != self.workstream.revision_id
                        || related.target.as_ref().is_some_and(|target| {
                            target.task_id != self.task.task_id
                                || target.repository_instance_id.is_none()
                                    && target.worktree_instance_id.is_some()
                        })
                })
        {
            return Err(QueryError::Invalid);
        }
        if let Some(repository) = &self.repository_state {
            repository.validate(&self.episode)?;
        }
        if let Some(capture) = &self.capture_context {
            capture.validate(&self.episode, anchor)?;
        }
        if self.frontier == 0
            || !matches!(
                anchor.binding_strength,
                QueryBindingStrength::Exact | QueryBindingStrength::ConnectionScoped
            )
            || task_id != Some(self.task.task_id)
            || self.task.lifecycle.is_terminal()
            || self.workstream.task_id != self.task.task_id
            || anchor.workstream_id != Some(self.workstream.workstream_id)
            || self.workstream.status != WorkstreamStatus::Active
            || self.workstream.active_episode_id != Some(self.episode.episode_id)
            || self.episode.task_id != self.task.task_id
            || self.episode.workstream_id != self.workstream.workstream_id
            || anchor.episode_id != Some(self.episode.episode_id)
            || anchor.episode_revision_id != Some(self.episode.revision_id)
            || self.episode.lifecycle_status != EpisodeLifecycle::Open
            || self.episode.repository_instance_id != self.workstream.repository_instance_id
            || !anchor
                .execution_lane_id
                .is_some_and(|id| self.workstream.execution_lane_ids.contains(&id))
        {
            return Err(QueryError::Invalid);
        }
        if let Some(attempt) = &self.attempt {
            attempt.validate().map_err(|_| QueryError::Invalid)?;
            if attempt.task_id != self.task.task_id
                || attempt.workstream_id != self.workstream.workstream_id
                || attempt.episode_id != Some(self.episode.episode_id)
                || attempt.repository_instance_id != self.episode.repository_instance_id
                || !self.episode.attempt_ids.contains(&attempt.attempt_id)
                || !anchor
                    .execution_lane_id
                    .is_some_and(|id| attempt.execution_lane_ids.contains(&id))
                || match self.episode.worktree_instance_id {
                    Some(id) => !attempt.worktree_instance_ids.contains(&id),
                    None => !attempt.worktree_instance_ids.is_empty(),
                }
            {
                return Err(QueryError::Invalid);
            }
        }
        if let Some(binding) = &self.work_binding {
            binding.validate().map_err(|_| QueryError::Invalid)?;
            let primary = &binding.primary_binding;
            if binding.assignment_status != AssignmentStatus::Resolved
                || primary.task_id != Some(self.task.task_id)
                || primary.workstream_id != Some(self.workstream.workstream_id)
                || primary.episode_id != Some(self.episode.episode_id)
                || self.attempt.as_ref().is_some_and(|attempt| {
                    primary
                        .attempt_id
                        .is_some_and(|id| id != attempt.attempt_id)
                })
            {
                return Err(QueryError::Invalid);
            }
        }
        if let Some(verification) = &self.verification {
            let attempt = self.attempt.as_ref().ok_or(QueryError::Invalid)?;
            let confirmed = if let Some(source) = &verification.source {
                if self.resolved_attempt().is_none()
                    || source.attempt_revision_id != attempt.revision_id
                    || anchor.execution_lane_id != Some(source.caller_lane_id)
                    || source.operation_revision == 0
                    || source.receipt_refs.is_empty()
                    || !source.receipt_refs.windows(2).all(|pair| pair[0] < pair[1])
                    || !attempt.parent_verification_refs.iter().any(|reference| {
                        reference == &source.result_id.to_string()
                            || reference == &source.result_revision_id.to_string()
                    })
                    || !matches!(
                        attempt.verification,
                        crate::work::AttemptVerification::Passed
                            | crate::work::AttemptVerification::Failed
                    )
                {
                    return Err(QueryError::Invalid);
                }
                QueryStateConfidence::Confirmed
            } else {
                QueryStateConfidence::Candidate
            };
            if verification.value != attempt.verification || verification.confidence != confirmed {
                return Err(QueryError::Invalid);
            }
        }
        if let Some(experiment) = &self.experiment {
            experiment.run.validate().map_err(|_| QueryError::Invalid)?;
            let binding = self.work_binding.as_ref().ok_or(QueryError::Invalid)?;
            if experiment.source.work_binding_revision_id != binding.work_binding_revision_id
                || experiment.source.operation_revision == Some(0)
                || experiment.source.operation_revision.is_none()
                    && !experiment.source.receipt_refs.is_empty()
                || !experiment
                    .source
                    .receipt_refs
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                || experiment.source.receipt_refs.iter().any(|id| {
                    let receipts = if experiment.run.ended_at_us.is_some() {
                        &experiment.run.terminal_evidence_refs
                    } else {
                        &experiment.run.source_receipt_refs
                    };
                    !receipts.contains(id)
                })
                || Some(experiment.run.run_id) != binding.primary_binding.experiment_run_id
                || experiment.run.workstream_id != self.workstream.workstream_id
                || experiment
                    .run
                    .attempt_id
                    .is_some_and(|id| binding.primary_binding.attempt_id != Some(id))
                || experiment.confidence
                    != self.experiment_confidence(&experiment.run, &experiment.source)
            {
                return Err(QueryError::Invalid);
            }
        }
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate().map_err(|_| QueryError::Invalid)?;
            if checkpoint.episode_id != self.episode.episode_id
                || checkpoint.source_watermark != self.episode.source_watermark
                || checkpoint.phase_contract != self.episode.phase_contract
                || !self
                    .episode
                    .checkpoint_refs
                    .contains(&checkpoint.stable_key())
                || self.attempt.as_ref().is_some_and(|attempt| {
                    !checkpoint.attempt_revision_refs.iter().any(|reference| {
                        reference.attempt_id == attempt.attempt_id
                            && reference.revision_id == attempt.revision_id
                    })
                })
            {
                return Err(QueryError::Invalid);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchContext {
    pub query_anchor: QueryAnchor,
    pub execution: Option<Box<QueryExecution>>,
    pub intent: SearchIntent,
    pub raw_query: String,
    pub protected_query: String,
    pub protected_facets: BTreeSet<ProtectedFacet>,
    pub query_facets: QueryFacetSet,
    pub task_id: Option<TaskId>,
    pub repository_id: Option<RepositoryId>,
    pub worktree_id: Option<WorktreeId>,
    pub suppression: SuppressionSnapshot,
    pub budget: RetrievalBudget,
}

impl SearchContext {
    pub fn unverified_hard_constraint(&self) -> bool {
        self.protected_facets
            .iter()
            .any(|facet| facet.blocks_ordinary_evidence())
    }

    pub fn validate(&self) -> Result<(), QueryError> {
        if self.raw_query.is_empty()
            || self.raw_query.len() > MAX_QUERY_BYTES
            || self.protected_query.is_empty()
            || self.protected_query.len() > MAX_QUERY_BYTES
            || self.protected_facets.len() > MAX_FACET_ITEMS * 4
            || self
                .protected_facets
                .iter()
                .any(|facet| usize::from(facet.position) >= MAX_FACET_ITEMS)
        {
            return Err(QueryError::Invalid);
        }
        self.query_anchor.validate()?;
        if let Some(execution) = &self.execution {
            execution.validate(&self.query_anchor, self.task_id)?;
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

/// Native revision identity at the pinned frontier, not an event timestamp.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchCurrentness {
    Current,
    Historical,
}

impl std::str::FromStr for SearchCurrentness {
    type Err = QueryError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "current" => Ok(Self::Current),
            "historical" => Ok(Self::Historical),
            _ => Err(QueryError::Invalid),
        }
    }
}

/// Position in a source revision identified by a readable source observation.
/// It is neither an event clock nor an ordering across independent sources.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSequencePosition {
    pub source_anchor: SourceObservationId,
    pub sequence: u64,
    /// Canonical archive coverage satisfies this request's source window, not global capture recall.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub coverage_complete: bool,
}

impl SourceSequencePosition {
    pub fn wire_bytes(&self) -> usize {
        serde_json::to_vec(self).map_or(usize::MAX, |bytes| bytes.len() + 19)
    }
}

/// Canonical receipt coordinates, never inferred from an indexed nonzero scalar.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceTimePosition {
    pub event_time_us: i64,
    pub recorded_at_us: i64,
    pub provenance: Option<crate::evidence::EventTimeProvenance>,
}

impl SourceTimePosition {
    pub fn validate(&self) -> bool {
        self.event_time_us >= 0
            && self.recorded_at_us >= 0
            && self.provenance.is_none_or(|value| {
                value
                    .validate(self.event_time_us, self.recorded_at_us)
                    .is_ok()
            })
    }

    fn event_window(&self) -> Option<(i128, i128)> {
        let crate::evidence::EventTimeProvenance::SourceTimestamp {
            uncertainty_us: Some(uncertainty),
            ..
        } = self.provenance?
        else {
            return None;
        };
        let point = i128::from(self.event_time_us);
        Some((
            point - i128::from(uncertainty),
            point + i128::from(uncertainty),
        ))
    }

    /// None is an unresolved predicate, not false and not zero uncertainty.
    pub fn temporal_match(&self, qualifiers: &[TemporalQualifier]) -> Option<bool> {
        if !self.validate() {
            return None;
        }
        if qualifiers.is_empty() || requested_ordering(qualifiers).is_some() {
            return Some(true);
        }
        let (lower, upper) = self.event_window()?;
        match qualifiers {
            [TemporalQualifier::EventTimeAsOf { at_us }] => {
                if upper <= i128::from(*at_us) {
                    Some(true)
                } else if lower > i128::from(*at_us) {
                    Some(false)
                } else {
                    None
                }
            }
            [TemporalQualifier::EventTimeBefore { at_us }] => {
                if upper < i128::from(*at_us) {
                    Some(true)
                } else if lower >= i128::from(*at_us) {
                    Some(false)
                } else {
                    None
                }
            }
            [TemporalQualifier::EventTimeAfter { at_us }] => {
                if lower > i128::from(*at_us) {
                    Some(true)
                } else if upper <= i128::from(*at_us) {
                    Some(false)
                } else {
                    None
                }
            }
            [TemporalQualifier::EventTimeInterval { start_us, end_us }] => {
                let (start, end) = (i128::from(*start_us), i128::from(*end_us));
                if lower >= start && upper < end {
                    Some(true)
                } else if upper < start || lower >= end {
                    Some(false)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn wire_bytes(&self) -> usize {
        // Include the enclosing candidate field name and separator, not just its value.
        serde_json::to_vec(self).map_or(usize::MAX, |bytes| bytes.len() + 15)
    }
}

pub fn validity_match(
    interval: &crate::semantic::ValidityInterval,
    qualifiers: &[TemporalQualifier],
) -> Option<bool> {
    interval.validate().ok()?;
    match qualifiers {
        [TemporalQualifier::ValidityAsOf { at_us }] => Some(interval.contains(*at_us)),
        [TemporalQualifier::ValidityStartsBefore { at_us }] => {
            Some(interval.valid_from_us < *at_us)
        }
        [TemporalQualifier::ValidityStartsAfter { at_us }] => Some(interval.valid_from_us > *at_us),
        [TemporalQualifier::ValidityInterval { start_us, end_us }] => Some(
            interval.valid_from_us < *end_us
                && interval.valid_until_us.is_none_or(|end| end > *start_us),
        ),
        _ => None,
    }
}

impl SearchCandidate {
    pub fn matches_reference(&self, reference: &str) -> bool {
        self.candidate_id == reference
            || (self.source_ref == reference
                && (self.row_variant == SearchCandidateVariant::EvidenceSurface
                    || self.currentness == Some(SearchCurrentness::Current)))
    }

    pub fn temporal_match(&self, qualifiers: &[TemporalQualifier]) -> Option<bool> {
        if requested_ordering(qualifiers).is_some() {
            return Some(true);
        }
        match qualifiers {
            [qualifier] if qualifier.is_validity() => {
                validity_match(self.validity_interval.as_ref()?, qualifiers)
            }
            [qualifier] if qualifier.source_sequence_ref().is_some() => {
                qualifier.matches_sequence(self.source_sequence.as_ref()?.sequence)
            }
            _ => self.source_time.as_ref()?.temporal_match(qualifiers),
        }
    }

    pub fn temporal_wire_bytes(&self) -> usize {
        self.source_time
            .as_ref()
            .map_or(0, SourceTimePosition::wire_bytes)
            + self.validity_interval.as_ref().map_or(0, |interval| {
                serde_json::to_vec(interval).map_or(usize::MAX, |bytes| bytes.len() + 21)
            })
            + self
                .source_sequence
                .as_ref()
                .map_or(0, SourceSequencePosition::wire_bytes)
            + self
                .revision_order
                .as_ref()
                .map_or(0, RevisionOrderPosition::wire_bytes)
    }
}

fn latest_max<'a>(
    candidates: &[&'a SearchCandidate],
    key: impl Fn(&SearchCandidate) -> Option<i128>,
) -> Option<BTreeSet<&'a str>> {
    let values = candidates
        .iter()
        .map(|candidate| key(candidate))
        .collect::<Option<Vec<_>>>()?;
    let maximum = values.iter().max()?;
    Some(
        candidates
            .iter()
            .zip(&values)
            .filter(|(_, value)| *value == maximum)
            .map(|(candidate, _)| candidate.candidate_id.as_str())
            .collect(),
    )
}

fn latest_order<'a>(
    candidates: &[&'a SearchCandidate],
    boundary: &'a [SearchCandidate],
    qualifiers: &[TemporalQualifier],
    relations: &'a [GroundedRelationStatement],
) -> Option<(OrderingBasis, BTreeSet<&'a str>)> {
    if candidates.is_empty() {
        return Some((OrderingBasis::Unknown, BTreeSet::new()));
    }
    if candidates.iter().any(|candidate| candidate.conflicted) {
        return None;
    }
    if matches!(qualifiers, [qualifier] if qualifier.is_validity()) {
        return latest_max(candidates, |candidate| {
            candidate
                .validity_interval
                .as_ref()
                .map(|interval| interval.valid_from_us.into())
        })
        .map(|winners| (OrderingBasis::Validity, winners));
    }
    let first = candidates[0];
    let requested = requested_ordering(qualifiers);
    if (qualifiers.is_empty()
        || requested == Some(TemporalOrdering::SourceSequence)
        || matches!(qualifiers, [qualifier] if qualifier.source_sequence_ref().is_some()))
        && first.source_sequence.is_some()
        && candidates.iter().all(|candidate| {
            candidate
                .source_sequence
                .as_ref()
                .zip(first.source_sequence.as_ref())
                .is_some_and(|(a, b)| a.source_anchor == b.source_anchor)
        })
    {
        return latest_max(candidates, |candidate| {
            candidate
                .source_sequence
                .as_ref()
                .map(|position| position.sequence.into())
        })
        .map(|winners| (OrderingBasis::SourceSequence, winners));
    }
    if requested == Some(TemporalOrdering::SourceSequence)
        || matches!(qualifiers, [qualifier] if qualifier.source_sequence_ref().is_some())
    {
        return None;
    }
    if !qualifiers.is_empty() && requested != Some(TemporalOrdering::Supersession) {
        return latest_clock_order(candidates);
    }
    if first.revision_order.is_some()
        && candidates.iter().all(|candidate| {
            candidate
                .revision_order
                .as_ref()
                .zip(first.revision_order.as_ref())
                .is_some_and(|(a, b)| a.anchor == b.anchor)
        })
    {
        let maximum = candidates
            .iter()
            .map(|candidate| revision_order_key(candidate))
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .max()?;
        return Some((
            OrderingBasis::Supersession,
            candidates
                .iter()
                .filter(|candidate| revision_order_key(candidate) == Some(maximum))
                .map(|candidate| candidate.candidate_id.as_str())
                .collect(),
        ));
    }
    // Only explicit, readable edges, with the same two-hop ceiling as D. A cycle
    // or incomparable roots cannot become a winner through a tie-breaker.
    let mut roots = BTreeSet::new();
    for root in candidates {
        let mut reached = BTreeSet::from([root.candidate_id.as_str()]);
        include_prior_revisions(boundary, &mut reached);
        let mut frontier = reached.clone();
        for _ in 0..2 {
            frontier = relations
                .iter()
                .filter(|relation| {
                    relation.relation_kind == "atom_supersedes"
                        && frontier.contains(relation.source_ref.as_str())
                })
                .map(|relation| relation.target_ref.as_str())
                .collect();
            reached.extend(&frontier);
            include_prior_revisions(boundary, &mut reached);
            frontier = reached.clone();
        }
        if candidates.len() > 1
            && candidates
                .iter()
                .all(|candidate| reached.contains(candidate.candidate_id.as_str()))
        {
            roots.insert(root.candidate_id.as_str());
        }
    }
    if roots.len() == 1 {
        return Some((OrderingBasis::Supersession, roots));
    }
    if requested == Some(TemporalOrdering::Supersession) {
        return None;
    }
    latest_clock_order(candidates)
}

fn revision_order_key(candidate: &SearchCandidate) -> Option<(u64, u64)> {
    Some((
        candidate.revision_order.as_ref()?.sequence,
        match candidate.row_variant {
            SearchCandidateVariant::Object => 0,
            SearchCandidateVariant::EvidenceSurface => candidate.source_sequence.as_ref()?.sequence,
        },
    ))
}

fn include_prior_revisions<'a>(boundary: &'a [SearchCandidate], reached: &mut BTreeSet<&'a str>) {
    let prior = boundary
        .iter()
        .filter(|candidate| {
            boundary.iter().any(|head| {
                reached.contains(head.candidate_id.as_str())
                    && candidate
                        .revision_order
                        .as_ref()
                        .zip(head.revision_order.as_ref())
                        .is_some_and(|(a, b)| a.anchor == b.anchor)
                    && revision_order_key(candidate)
                        .zip(revision_order_key(head))
                        .is_some_and(|(a, b)| a <= b)
            })
        })
        .map(|candidate| candidate.candidate_id.as_str())
        .collect::<Vec<_>>();
    reached.extend(prior);
}

fn latest_clock_order<'a>(
    candidates: &[&'a SearchCandidate],
) -> Option<(OrderingBasis, BTreeSet<&'a str>)> {
    let windows = candidates
        .iter()
        .map(|candidate| candidate.source_time.as_ref()?.event_window())
        .collect::<Option<Vec<_>>>();
    if let Some(windows) = windows {
        let winners = candidates
            .iter()
            .zip(&windows)
            .enumerate()
            .filter(|(index, (_, (lower, upper)))| {
                windows
                    .iter()
                    .enumerate()
                    .all(|(other, (other_lower, other_upper))| {
                        *index == other
                            || lower > other_upper
                            || (lower == upper
                                && other_lower == other_upper
                                && lower == other_lower)
                    })
            })
            .map(|(_, (candidate, _))| candidate.candidate_id.as_str())
            .collect::<BTreeSet<_>>();
        if !winners.is_empty() {
            return Some((OrderingBasis::EventTime, winners));
        }
    }
    latest_max(candidates, |candidate| {
        candidate
            .source_time
            .as_ref()
            .map(|position| position.recorded_at_us.into())
    })
    .map(|winners| (OrderingBasis::RecordedAtFallback, winners))
}

/// This orders a view of a frozen set; it never changes ranking or generation.
pub fn timeline_order<'a>(
    candidates: &'a [SearchCandidate],
    qualifiers: &[TemporalQualifier],
) -> Option<(OrderingBasis, Vec<&'a SearchCandidate>)> {
    let requested = requested_ordering(qualifiers);
    let allows = |basis| requested.is_none_or(|domain| domain.basis() == basis);
    if candidates.is_empty() {
        return None;
    }
    let mut ordered = candidates.iter().collect::<Vec<_>>();
    if allows(OrderingBasis::SourceSequence)
        && let Some(anchor) = candidates[0]
            .source_sequence
            .as_ref()
            .map(|value| value.source_anchor)
        && candidates.iter().all(|candidate| {
            candidate
                .source_sequence
                .as_ref()
                .is_some_and(|value| value.source_anchor == anchor)
        })
    {
        ordered.sort_by_key(|candidate| {
            (
                candidate
                    .source_sequence
                    .as_ref()
                    .map(|value| value.sequence),
                &candidate.candidate_id,
            )
        });
        return Some((OrderingBasis::SourceSequence, ordered));
    }
    if allows(OrderingBasis::Supersession)
        && candidates[0].revision_order.is_some()
        && candidates.iter().all(|candidate| {
            candidate
                .revision_order
                .as_ref()
                .zip(candidates[0].revision_order.as_ref())
                .is_some_and(|(a, b)| a.anchor == b.anchor)
        })
    {
        ordered.sort_by_key(|candidate| (revision_order_key(candidate), &candidate.candidate_id));
        return Some((OrderingBasis::Supersession, ordered));
    }
    if allows(OrderingBasis::Validity)
        && candidates.iter().all(|candidate| {
            candidate
                .validity_interval
                .as_ref()
                .is_some_and(|interval| interval.validate().is_ok())
        })
    {
        ordered.sort_by_key(|candidate| {
            (
                candidate
                    .validity_interval
                    .as_ref()
                    .map(|interval| interval.valid_from_us),
                &candidate.candidate_id,
            )
        });
        return Some((OrderingBasis::Validity, ordered));
    }
    if !allows(OrderingBasis::EventTime)
        || !candidates.iter().all(|candidate| {
            candidate
                .source_time
                .as_ref()
                .is_some_and(SourceTimePosition::validate)
        })
    {
        return None;
    }
    ordered.sort_by_key(|candidate| {
        (
            candidate
                .source_time
                .as_ref()
                .map(|value| value.event_time_us),
            &candidate.candidate_id,
        )
    });
    let windows = ordered
        .iter()
        .map(|candidate| candidate.source_time.as_ref()?.event_window())
        .collect::<Option<Vec<_>>>();
    if windows.is_some_and(|windows| windows.windows(2).all(|pair| pair[0].1 <= pair[1].0)) {
        return Some((OrderingBasis::EventTime, ordered));
    }
    ordered.sort_by_key(|candidate| {
        (
            candidate
                .source_time
                .as_ref()
                .map(|value| value.recorded_at_us),
            &candidate.candidate_id,
        )
    });
    Some((OrderingBasis::RecordedAtFallback, ordered))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchCandidate {
    pub candidate_id: String,
    pub source_sequence: Option<SourceSequencePosition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_time: Option<SourceTimePosition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity_interval: Option<crate::semantic::ValidityInterval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_order: Option<RevisionOrderPosition>,
    pub source_ref: String,
    pub row_variant: SearchCandidateVariant,
    pub currentness: Option<SearchCurrentness>,
    pub object_kind: Option<String>,
    pub text: String,
    pub source_role: Option<String>,
    pub content_trust: Option<String>,
    pub capture_completeness: Option<String>,
    pub retrieval_origins: BTreeSet<String>,
    pub instruction_authority: String,
    pub conflicted: bool,
    pub semantic_resolution: Option<SemanticResolution>,
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

impl std::fmt::Debug for SearchContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SearchContext")
            .field("intent", &self.intent)
            .field("raw_query_bytes", &self.raw_query.len())
            .field("protected_query_bytes", &self.protected_query.len())
            .field("protected_facets", &self.protected_facets)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

/// The already-open database incarnation, not a path supplied by a client.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadDataIdentity {
    pub database_device: u64,
    pub database_inode: u64,
    pub incarnation: u64,
}

/// Kernel facts used by read clients and CLI commands that need a frontier.
/// This does not construct diagnostics, page models or a database snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectReadState {
    pub frontier: u64,
    pub data_identity: ReadDataIdentity,
    pub effective_config_hash: String,
}

pub const METADATA_READ_LIMIT: u16 = 64;
pub const METADATA_BATCH_LIMIT: usize = 8;
pub const METADATA_REPLY_BYTES: usize = 256 * 1024;

impl ObjectReadState {
    pub fn validate(&self) -> bool {
        self.effective_config_hash.len() == 64
            && self
                .effective_config_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
}

/// Only stored job metadata. Selection never admits or starts a job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobsReadQuery {
    pub expected_frontier: Option<u64>,
    pub expected_data_identity: Option<ReadDataIdentity>,
    pub after: Option<JobId>,
    pub job_id: Option<JobId>,
    pub limit: u16,
}

impl JobsReadQuery {
    pub fn validate(&self) -> bool {
        (1..=METADATA_READ_LIMIT).contains(&self.limit)
            && (self.after.is_none()
                || (self.expected_frontier.is_some() && self.expected_data_identity.is_some()))
            && (self.job_id.is_none() || (self.after.is_none() && self.limit == 1))
    }
}

/// Canonical stored job values, not a System page or a display model.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectReadJobs {
    pub state: ObjectReadState,
    /// Exact stored-job count for this selection at the returned frontier, not body readability.
    pub record_count: u64,
    pub records: Vec<serde_json::Value>,
    pub next_cursor: Option<JobId>,
}

/// Native outcome before encoding the existing read response or typed wire error.
#[derive(Debug)]
pub enum MetadataReadOutcome<T> {
    Page(Box<T>),
    Conflict(u64),
    TooLarge,
}

impl ObjectReadJobs {
    pub fn validate(&self) -> bool {
        self.state.validate()
            && self.records.len() <= usize::from(METADATA_READ_LIMIT)
            && self.record_count >= self.records.len() as u64
            && self.records.iter().all(serde_json::Value::is_object)
            && serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() <= METADATA_REPLY_BYTES)
    }
}

/// An immutable stored record needed by the Python reading surfaces, not a path or query expression.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactFieldsQuery {
    pub revision_ref: String,
}

impl ExactFieldsQuery {
    pub fn validate(&self) -> bool {
        self.revision_ref.parse::<RevisionId>().is_ok()
            || self
                .revision_ref
                .parse::<crate::ids::SemanticDigestId>()
                .is_ok()
    }
}

/// Closed modes of the same bounded exact-read interface; no paths or caller-defined selectors.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExactReadQuery {
    Fields(ExactFieldsQuery),
    SourceText(ExactSourceTextQuery),
    Record(ExactRecordQuery),
}

impl ExactReadQuery {
    pub fn validate(&self) -> bool {
        match self {
            Self::Fields(query) => query.validate(),
            Self::SourceText(query) => query.validate(),
            Self::Record(query) => query.validate(),
        }
    }

    pub fn lookup_ref(&self) -> &str {
        match self {
            Self::Fields(query) => &query.revision_ref,
            Self::SourceText(query) => &query.reference.revision_ref,
            Self::Record(query) => query
                .reference
                .revision_ref
                .as_deref()
                .unwrap_or(&query.reference.stable_key),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactSourceTextQuery {
    pub reference: HumanRevisionRef,
    pub range: Option<ExactUtf8Range>,
    pub expected_data_identity: Option<ReadDataIdentity>,
    pub expected_source: Option<ExactSourceIdentity>,
}

impl ExactSourceTextQuery {
    pub fn validate(&self) -> bool {
        let reference = &self.reference;
        !reference.stable_key.is_empty()
            && reference.stable_key.len() <= 512
            && !reference.stable_key.chars().any(char::is_control)
            && (reference
                .revision_ref
                .parse::<crate::ids::SourceObservationId>()
                .is_ok()
                || reference
                    .revision_ref
                    .parse::<crate::ids::SourceReceiptId>()
                    .is_ok())
            && self.range.as_ref().is_none_or(ExactUtf8Range::validate)
            && self
                .expected_source
                .as_ref()
                .is_none_or(ExactSourceIdentity::validate)
    }
}

/// None in a bounded exact request selects current metadata/gates only, not content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactUtf8Range {
    pub offset: u64,
    pub length: u16,
}

impl ExactUtf8Range {
    pub fn validate(&self) -> bool {
        (4..=HUMAN_CONTENT_LIMIT).contains(&self.length)
            && self
                .offset
                .checked_add(u64::from(self.length) + 1)
                .is_some()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactRecordQuery {
    pub reference: ExactRecordRef,
    pub field: Option<ExactRecordField>,
    pub range: Option<ExactUtf8Range>,
    pub expected_data_identity: Option<ReadDataIdentity>,
    pub expected_selection: Option<ExactFieldIdentity>,
}

/// An omitted expected revision binds only a typed public ID to its Native canonical-current revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactRecordRef {
    pub stable_key: String,
    pub revision_ref: Option<String>,
}

impl ExactRecordQuery {
    pub fn validate(&self) -> bool {
        let reference = &self.reference;
        let identity = match &reference.revision_ref {
            Some(revision) => {
                (ExactFieldsQuery {
                    revision_ref: revision.clone(),
                })
                .validate()
                    || revision.parse::<crate::ids::CaptureReceiptId>().is_ok()
                    || parse_operation_revision(revision).is_some()
            }
            None => {
                let key = &reference.stable_key;
                key.parse::<crate::ids::AtomId>().is_ok()
                    || key.parse::<crate::ids::ProcedureId>().is_ok()
                    || key.parse::<crate::ids::CoreMembershipId>().is_ok()
                    || key.parse::<crate::ids::RevisionProposalId>().is_ok()
                    || key.parse::<crate::ids::SemanticDigestId>().is_ok()
                    || key.parse::<crate::ids::WorkEpisodeId>().is_ok()
            }
        };
        identity
            && !reference.stable_key.is_empty()
            && reference.stable_key.len() <= 512
            && !reference.stable_key.chars().any(char::is_control)
            && self.field.is_some() == self.range.is_some()
            && self.range.as_ref().is_none_or(ExactUtf8Range::validate)
            && self.expected_selection.as_ref().is_none_or(|selected| {
                [
                    &selected.object_ref,
                    &selected.revision_ref,
                    &selected.object_kind,
                ]
                .iter()
                .all(|value| {
                    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
                })
            })
    }
}

/// Closed stored-record fields, not an arbitrary JSON path or display algorithm.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExactRecordField {
    Json,
    Text,
    Goal,
    OpenLoop { index: u32 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExactRecordInfo {
    Semantic {
        text_bytes: Option<u64>,
    },
    Work {
        goal_bytes: u64,
        open_loop_bytes: Vec<u64>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactRecordWindow {
    pub state: ObjectReadState,
    pub selection: Option<ExactFieldIdentity>,
    pub metadata: Option<serde_json::Value>,
    pub content_state: HumanContentState,
    pub info: Option<ExactRecordInfo>,
    pub window: Option<ExactUtf8Window>,
}

impl ExactRecordWindow {
    pub fn validate(&self) -> bool {
        self.state.validate()
            && self.metadata.as_ref().is_none_or(|row| {
                row.is_object()
                    && row.get("payload_json").is_none()
                    && self.selection.as_ref().is_some_and(|selected| {
                        row["object_kind"].as_str() == Some(selected.object_kind.as_str())
                            && row["object_id"].as_str() == Some(selected.object_ref.as_str())
                            && row["current_revision_id"].as_str()
                                == Some(selected.revision_ref.as_str())
                            && row["source_event_seq"].as_u64() == Some(selected.source_event_seq)
                    })
                    && serde_json::to_vec(row)
                        .is_ok_and(|bytes| bytes.len() <= METADATA_REPLY_BYTES)
            })
            && if self.content_state == HumanContentState::Ready {
                self.selection.is_some()
                    && self.metadata.is_some()
                    && self.info.as_ref().is_some_and(|info| match info {
                        ExactRecordInfo::Semantic { .. } => true,
                        ExactRecordInfo::Work {
                            open_loop_bytes, ..
                        } => open_loop_bytes.len() <= 64,
                    })
                    && self.window.as_ref().is_none_or(|window| {
                        window.start <= window.end
                            && window.end <= window.total_bytes
                            && window.end - window.start == window.text.len() as u64
                            && window.text.len() <= usize::from(HUMAN_CONTENT_LIMIT)
                    })
            } else {
                self.info.is_none() && self.window.is_none()
            }
    }
}

/// Existing immutable source coordinates; no CAS locator or transferable authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactSourceIdentity {
    pub observation_ref: crate::ids::SourceObservationId,
    pub receipt_ref: crate::ids::SourceReceiptId,
    pub source_instance_ref: crate::evidence::SourceInstanceId,
    pub source_revision: crate::evidence::SourceRevision,
    pub source_record_identity: crate::evidence::SourceRecordIdentity,
    pub payload_fingerprint: String,
    pub protected_bytes: u64,
    pub original_bytes: u64,
}

impl ExactSourceIdentity {
    pub fn validate(&self) -> bool {
        self.protected_bytes > 0
            && crate::evidence::SourceInstanceId::parse(self.source_instance_ref.as_str()).is_ok()
            && crate::evidence::SourceRevision::parse(self.source_revision.as_str()).is_ok()
            && crate::evidence::SourceRecordIdentity::parse(self.source_record_identity.as_str())
                .is_ok()
            && self.payload_fingerprint.len() == 64
            && self
                .payload_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
}

/// UTF-8 boundaries are data facts; direction and next/previous cursors belong to Python.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactUtf8Window {
    pub start: u64,
    pub end: u64,
    pub total_bytes: u64,
    pub start_boundary: bool,
    pub end_boundary: bool,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactSourceWindow {
    pub state: ObjectReadState,
    pub selection: Option<ExactFieldIdentity>,
    pub content_state: HumanContentState,
    pub source: Option<ExactSourceIdentity>,
    pub window: Option<ExactUtf8Window>,
}

impl ExactSourceWindow {
    pub fn validate(&self) -> bool {
        self.state.validate()
            && match self.content_state {
                HumanContentState::Ready => {
                    self.selection.is_some()
                        && self
                            .source
                            .as_ref()
                            .is_some_and(ExactSourceIdentity::validate)
                        && self.window.as_ref().is_none_or(|window| {
                            window.start <= window.end
                                && window.end <= window.total_bytes
                                && window.end - window.start == window.text.len() as u64
                                && window.text.len() <= usize::from(HUMAN_CONTENT_LIMIT)
                        })
                }
                _ => self.source.is_none() && self.window.is_none(),
            }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactFieldIdentity {
    pub object_kind: String,
    pub object_ref: String,
    pub revision_ref: String,
    pub source_event_seq: u64,
}

/// No field or source reference is disclosed when the access state is not ready.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactStoredFields {
    pub state: ObjectReadState,
    pub selection: Option<ExactFieldIdentity>,
    pub content_state: HumanContentState,
    pub fields: Option<serde_json::Value>,
    pub fields_complete: bool,
    pub truncated_fields: Vec<String>,
    pub source_observation_refs: Vec<String>,
}

impl ExactStoredFields {
    pub fn validate(&self) -> bool {
        self.state.validate()
            && match self.content_state {
                HumanContentState::Ready => {
                    self.selection.is_some()
                        && (self.fields_complete == self.truncated_fields.is_empty())
                        && self.fields.as_ref().is_some_and(|fields| {
                            serde_json::to_vec(fields)
                                .is_ok_and(|bytes| bytes.len() <= usize::from(HUMAN_CONTENT_LIMIT))
                        })
                }
                _ => {
                    self.fields.is_none()
                        && !self.fields_complete
                        && self.truncated_fields.is_empty()
                        && self.source_observation_refs.is_empty()
                }
            }
    }
}

/// Two individually gated immutable values selected under one Native data binding; no field diff.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionPairFields {
    pub query: RevisionCompareQuery,
    pub object_kind: Option<HumanRevisionKind>,
    pub left: ExactStoredFields,
    pub right: ExactStoredFields,
}

impl RevisionPairFields {
    pub fn validate(&self) -> bool {
        self.query.validate().is_ok()
            && self.left.validate()
            && self.right.validate()
            && self.left.state == self.right.state
            && ((self.left.content_state == HumanContentState::Ready
                && self.right.content_state == HumanContentState::Ready)
                == self.object_kind.is_some())
            && serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() <= METADATA_REPLY_BYTES)
    }
}

/// Closed metadata reads of current memory, work, review and job facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MetadataReadQuery {
    Work {
        query: Box<MemoryOverviewQuery>,
    },
    Review {
        query: Box<MemoryOverviewQuery>,
    },
    Memories {
        query: Box<MemoryBrowseQuery>,
        after: Option<String>,
        limit: u16,
    },
    Jobs {
        after: Option<JobId>,
        job_id: Option<JobId>,
        limit: u16,
    },
}

impl MetadataReadQuery {
    pub fn limit(&self) -> u16 {
        match self {
            Self::Work { query } | Self::Review { query } => query.limit,
            Self::Memories { limit, .. } | Self::Jobs { limit, .. } => *limit,
        }
    }

    fn validate(&self, batch: &MetadataBatchQuery) -> bool {
        match self {
            Self::Work { query } | Self::Review { query } => query.validate().is_ok(),
            Self::Memories { query, after, .. } => {
                query.validate().is_ok()
                    && after.as_ref().is_none_or(|raw| {
                        raw.len() <= 2048
                            && batch.expected_data_identity.is_some()
                            && serde_json::from_str::<MemoryBrowseCursor>(raw).is_ok_and(|cursor| {
                                Some(cursor.frontier) == batch.expected_frontier
                                    && cursor.validate_for(query).is_ok()
                            })
                    })
            }
            Self::Jobs {
                after,
                job_id,
                limit,
            } => JobsReadQuery {
                expected_frontier: batch.expected_frontier,
                expected_data_identity: batch.expected_data_identity,
                after: *after,
                job_id: *job_id,
                limit: *limit,
            }
            .validate(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataBatchQuery {
    pub expected_frontier: Option<u64>,
    pub expected_data_identity: Option<ReadDataIdentity>,
    pub items: Vec<MetadataReadQuery>,
}

impl MetadataBatchQuery {
    pub fn validate(&self) -> bool {
        (1..=METADATA_BATCH_LIMIT).contains(&self.items.len())
            && self.items.iter().all(|item| {
                (1..=METADATA_READ_LIMIT).contains(&item.limit()) && item.validate(self)
            })
            && self
                .items
                .iter()
                .map(|item| u32::from(item.limit()))
                .sum::<u32>()
                <= u32::from(METADATA_READ_LIMIT)
    }
}

/// Only stored metadata columns. Payload, body and support-reference values are not read out.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryMetadataPage {
    pub query: Box<MemoryBrowseQuery>,
    pub records: Vec<serde_json::Value>,
    pub total_count: Option<u64>,
    pub matching_count: Option<u64>,
    pub scope_available: bool,
    pub counts_complete: bool,
    pub unresolved_scope_count: u64,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MetadataReadPage {
    Memories { page: Box<MemoryMetadataPage> },
    Jobs { page: Box<ObjectReadJobs> },
    Work { page: Box<ScopedWorkMetadata> },
    Review { page: Box<ScopedReviewMetadata> },
}

/// Scoped domain counts and the original input-matching derivation record, not generation explanations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedWorkMetadata {
    pub records: Vec<serde_json::Value>,
    pub scope_available: bool,
    pub counts_complete: bool,
    pub work_count: Option<u64>,
    pub open_work_count: Option<u64>,
    pub loop_count: Option<u64>,
    pub no_inputs: bool,
    pub last_run: Option<serde_json::Value>,
    pub llm_enabled: Option<bool>,
    pub episode_enrichment_enabled: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedReviewMetadata {
    pub records: Vec<serde_json::Value>,
    pub metadata_only_refs: Vec<String>,
    pub scope_available: bool,
    pub counts_complete: bool,
    pub matching_count: Option<u64>,
    pub reasons: std::collections::BTreeMap<String, InboxReviewReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectReadBatch {
    pub state: ObjectReadState,
    pub items: Vec<MetadataReadPage>,
}

impl ObjectReadBatch {
    pub fn validate(&self) -> bool {
        let mut count = 0;
        self.state.validate()
            && (1..=METADATA_BATCH_LIMIT).contains(&self.items.len())
            && self.items.iter().all(|item| match item {
                MetadataReadPage::Jobs { page } => {
                    count += page.records.len();
                    page.state == self.state && page.validate()
                }
                MetadataReadPage::Memories { page } => {
                    count += page.records.len();
                    page.query.validate().is_ok() && valid_metadata_records(&page.records)
                }
                MetadataReadPage::Work { page } => {
                    count += page.records.len();
                    valid_metadata_records(&page.records)
                        && page
                            .last_run
                            .as_ref()
                            .is_none_or(serde_json::Value::is_object)
                }
                MetadataReadPage::Review { page } => {
                    count += page.records.len();
                    valid_metadata_records(&page.records)
                }
            })
            && count <= usize::from(METADATA_READ_LIMIT)
            && serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() <= METADATA_REPLY_BYTES)
    }
}

fn valid_metadata_records(records: &[serde_json::Value]) -> bool {
    records
        .iter()
        .all(|record| record.is_object() && record.get("payload_json").is_none())
}

/// Literal search plus explicitly supplied typed intent. No access grants,
/// budgets, candidate boundary or completeness proof comes from the client.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSearchQuery {
    pub text: String,
    pub selection: MemoryScopeSelection,
    pub facets: QueryFacetSet,
    pub limit: u16,
}
impl std::fmt::Debug for HumanSearchQuery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HumanSearchQuery")
            .field("text_bytes", &self.text.len())
            .field("selection", &self.selection)
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl HumanSearchQuery {
    pub fn validate(&self) -> Result<(), QueryError> {
        self.facets.validate()?;
        if self.text.trim().is_empty()
            || self.text.len() > MAX_QUERY_BYTES
            || !(1..=32).contains(&self.limit)
            || self.selection == MemoryScopeSelection::Unassigned
            || self.facets.scope_boundary != self.selection.boundary()
            || self
                .facets
                .quantity_constraints
                .iter()
                .filter_map(|constraint| match constraint {
                    QuantityConstraint::ResultLimit { limit } => Some(*limit),
                    QuantityConstraint::DistinctCount { .. } => None,
                })
                .collect::<Vec<_>>()
                != vec![u32::from(self.limit)]
            || [
                &self.facets.exact_identifiers,
                &self.facets.condition_literals,
                &self.facets.explicit_exclusions,
            ]
            .into_iter()
            .flatten()
            .any(|value| value.len() > 512 || !self.text.contains(value))
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSearchPage {
    pub result: SearchResult,
    pub grounded_view: Option<GroundedEvidenceView>,
}
impl HumanSearchPage {
    pub fn validate(&self) -> bool {
        let refs = self
            .result
            .candidates
            .iter()
            .map(|candidate| candidate.candidate_id.clone())
            .collect::<BTreeSet<_>>();
        self.result.projection_frontier <= self.result.authoritative_frontier
            && refs.len() == self.result.candidates.len()
            && refs.len() <= 32
            && self.result.candidates.iter().all(|candidate| {
                !candidate.candidate_id.is_empty()
                    && !candidate.source_ref.is_empty()
                    && !candidate.text.is_empty()
                    && candidate.text.len() <= 16 * 1024
                    && candidate.instruction_authority == "none"
                    && match candidate.row_variant {
                        SearchCandidateVariant::Object => {
                            candidate.currentness.is_some()
                                && candidate.source_sequence.is_none()
                                && candidate.source_time.is_none()
                        }
                        SearchCandidateVariant::EvidenceSurface => {
                            candidate.currentness.is_none() && candidate.validity_interval.is_none()
                        }
                    }
            })
            && self.grounded_view.as_ref().is_none_or(|view| {
                view.validate_at_frontier(self.result.projection_frontier)
                    .is_ok()
                    && view.candidate_set.candidate_refs == refs
                    && view.completeness == self.result.completeness
                    && self.count_derivation_valid(view)
                    && self.latest_derivation_valid(view)
                    && self.comparison_derivation_valid(view)
            })
            && self.quoted_statements_valid()
            && self.timeline_order_valid()
            && self.sequence_positions_valid()
            && self.time_positions_valid()
    }

    fn count_derivation_valid(&self, view: &GroundedEvidenceView) -> bool {
        if view.evidence_need.count_unit.is_none() {
            return view.candidate_count.is_none()
                && (view.evidence_need.answer_shape != Some(AnswerShape::Count)
                    || view.completeness != RetrievalCompleteness::Complete);
        }
        let Some(count) = &view.candidate_count else {
            return false;
        };
        if view.completeness == RetrievalCompleteness::Complete
            && !view.count_temporal_gaps(&self.result.candidates).is_empty()
        {
            return false;
        }
        // Ordinary answer evidence is required. Constraint-only matches are
        // declared by the Native protected-IR predicate, not inferred from prose.
        view.derive_candidate_count(&self.result.candidates, &count.statement_indices)
            .as_ref()
            == Some(count)
    }

    fn latest_derivation_valid(&self, view: &GroundedEvidenceView) -> bool {
        if view.evidence_need.answer_shape != Some(AnswerShape::Latest) {
            return view.candidate_latest.is_none();
        }
        let Some(latest) = &view.candidate_latest else {
            return false;
        };
        if view
            .derive_candidate_latest(&self.result.candidates, &latest.operand_indices)
            .as_ref()
            != Some(latest)
        {
            return false;
        }
        if view.completeness == RetrievalCompleteness::Complete {
            if latest.statement_indices.is_none()
                || latest.ordering_basis == OrderingBasis::RecordedAtFallback
            {
                return false;
            }
            if !view.latest_source_coverage_complete(&self.result.candidates) {
                return false;
            }
        }
        true
    }

    fn comparison_derivation_valid(&self, view: &GroundedEvidenceView) -> bool {
        if view.evidence_need.answer_shape != Some(AnswerShape::TemporalComparison) {
            return view.candidate_comparison.is_none();
        }
        let Some(comparison) = &view.candidate_comparison else {
            return false;
        };
        let operands = comparison
            .operand_indices
            .iter()
            .flatten()
            .copied()
            .collect();
        view.derive_candidate_comparison(&self.result.candidates, &operands)
            .as_ref()
            == Some(comparison)
            && (view.completeness != RetrievalCompleteness::Complete
                || comparison.relation != TemporalComparisonRelation::Unknown)
    }

    fn quoted_statements_valid(&self) -> bool {
        self.grounded_view.as_ref().is_none_or(|view| {
            view.active_evidence.iter().all(|statement| {
                statement.derivation_kind != DerivationKind::Quoted
                    || (statement.support_refs.len() == 1
                        && self.result.candidates.iter().any(|candidate| {
                            statement.support_refs.contains(&candidate.candidate_id)
                                && statement.statement == candidate.text
                        }))
            })
        })
    }

    fn timeline_order_valid(&self) -> bool {
        let Some(view) = &self.grounded_view else {
            return true;
        };
        if view.evidence_need.answer_shape != Some(AnswerShape::Timeline) {
            return true;
        }
        let Some((basis, ordered)) = timeline_order(
            &self.result.candidates,
            &view.evidence_need.temporal_scope.qualifiers,
        ) else {
            return view.completeness != RetrievalCompleteness::Complete
                && view.active_evidence.iter().all(|statement| {
                    !matches!(
                        statement.ordering_basis,
                        OrderingBasis::EventTime
                            | OrderingBasis::RecordedAtFallback
                            | OrderingBasis::Validity
                    ) && (statement.derivation_kind != DerivationKind::Quoted
                        || statement.ordering_basis == OrderingBasis::Unknown)
                });
        };
        if view.completeness == RetrievalCompleteness::Complete
            && (basis == OrderingBasis::RecordedAtFallback
                || (basis == OrderingBasis::Supersession
                    && self.result.candidates.iter().any(|candidate| {
                        candidate.row_variant == SearchCandidateVariant::EvidenceSurface
                            && candidate
                                .source_sequence
                                .as_ref()
                                .is_none_or(|position| !position.coverage_complete)
                    })))
        {
            return false;
        }
        let mut previous = None;
        for step in &view.trace {
            let Some(statement) = view.active_evidence.get(step.statement_index as usize) else {
                return false;
            };
            if statement.derivation_kind != DerivationKind::Quoted {
                continue;
            }
            let Some(rank) = ordered
                .iter()
                .position(|candidate| statement.support_refs.contains(&candidate.candidate_id))
            else {
                return false;
            };
            if statement.ordering_basis != basis || previous.is_some_and(|old| old >= rank) {
                return false;
            }
            previous = Some(rank);
        }
        true
    }

    fn time_positions_valid(&self) -> bool {
        let view = self.grounded_view.as_ref();
        let chronology = view.is_some_and(|view| {
            view.evidence_need
                .answer_shape
                .is_some_and(AnswerShape::uses_temporal_order)
                && (view.evidence_need.temporal_scope.qualifiers.is_empty()
                    || requested_ordering(&view.evidence_need.temporal_scope.qualifiers).is_some())
        });
        for candidate in &self.result.candidates {
            if let Some(position) = &candidate.revision_order {
                let object = candidate.row_variant == SearchCandidateVariant::Object
                    && candidate.object_kind.as_deref() != Some("wiki_projection")
                    && position.anchor == candidate.source_ref
                    && position.sequence > 0
                    && position.sequence <= self.result.projection_frontier
                    && view.is_some_and(|view| {
                        matches!(
                            view.evidence_need.answer_shape,
                            Some(AnswerShape::Latest | AnswerShape::TemporalComparison)
                        ) || requested_ordering(&view.evidence_need.temporal_scope.qualifiers)
                            == Some(TemporalOrdering::Supersession)
                    });
                let source = candidate.row_variant == SearchCandidateVariant::EvidenceSurface
                    && position.sequence
                        <= 2_u64.saturating_sub(u64::from(self.result.budget.hops_remaining))
                    && candidate.source_sequence.is_some()
                    && position.anchor.parse::<SourceObservationId>().is_ok()
                    && self.result.candidates.iter().any(|value| {
                        value.row_variant == SearchCandidateVariant::EvidenceSurface
                            && value.source_ref == position.anchor
                    })
                    && self.result.candidates.iter().all(|other| {
                        let Some(order) = other
                            .revision_order
                            .as_ref()
                            .filter(|order| order.anchor == position.anchor)
                        else {
                            return true;
                        };
                        other.row_variant == SearchCandidateVariant::EvidenceSurface
                            && candidate
                                .source_sequence
                                .as_ref()
                                .zip(other.source_sequence.as_ref())
                                .is_some_and(|(a, b)| {
                                    (a.source_anchor == b.source_anchor)
                                        == (position.sequence == order.sequence)
                                })
                    });
                if (!object && !source) || !chronology {
                    return false;
                }
            }
            if let Some(position) = &candidate.source_time {
                if !position.validate()
                    || candidate.row_variant != SearchCandidateVariant::EvidenceSurface
                    || view.is_none_or(|view| {
                        !matches!(
                            view.evidence_need.temporal_scope.qualifiers.as_slice(),
                            [qualifier] if qualifier.is_event_time()
                        ) && !chronology
                    })
                {
                    return false;
                }
            }
            if let Some(interval) = &candidate.validity_interval {
                if interval.validate().is_err()
                    || candidate.source_time.is_some()
                    || candidate.row_variant != SearchCandidateVariant::Object
                    || candidate.object_kind.as_deref() != Some("atom_revision")
                    || view.is_none_or(|view| {
                        !matches!(
                            view.evidence_need.temporal_scope.qualifiers.as_slice(),
                            [qualifier] if qualifier.is_validity()
                        ) && !chronology
                    })
                {
                    return false;
                }
            }
            if let Some(view) = view {
                if candidate.temporal_match(&view.evidence_need.temporal_scope.qualifiers)
                    == Some(false)
                {
                    let active = candidate.semantic_resolution
                        == Some(crate::semantic::SemanticResolution::Normative(
                            crate::semantic::NormativeResolutionState::Active,
                        ));
                    let target = view.evidence_need.target.iter().any(|reference| {
                        *reference == candidate.candidate_id || *reference == candidate.source_ref
                    });
                    if !active && !target {
                        return false;
                    }
                    if view.trace.iter().any(|step| {
                        view.active_evidence
                            .get(step.statement_index as usize)
                            .is_some_and(|statement| {
                                statement.derivation_kind == DerivationKind::Quoted
                                    && statement.support_refs.contains(&candidate.candidate_id)
                                    && step.role
                                        != if active {
                                            EvidenceRole::ConstraintSupport
                                        } else {
                                            EvidenceRole::Contrast
                                        }
                            })
                    }) {
                        return false;
                    }
                }
            }
        }
        let Some(view) = view else {
            return true;
        };
        let temporal = view
            .evidence_need
            .temporal_scope
            .mode
            .has_temporal_predicate()
            && !view
                .evidence_need
                .temporal_scope
                .qualifiers
                .iter()
                .any(|qualifier| qualifier.source_sequence_ref().is_some());
        let mut expected = if temporal {
            self.result
                .candidates
                .iter()
                .filter(|candidate| {
                    candidate
                        .temporal_match(&view.evidence_need.temporal_scope.qualifiers)
                        .is_none()
                })
                .map(|candidate| candidate.source_ref.clone())
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        expected.extend(view.count_temporal_gaps(&self.result.candidates));
        expected.extend(view.ordering_temporal_gaps(&self.result.candidates));
        let gaps = view
            .unresolved_gaps
            .iter()
            .filter(|gap| gap.kind == NamedGapKind::TemporalEvidence)
            .collect::<Vec<_>>();
        if gaps.len() != expected.len()
            || gaps
                .iter()
                .map(|gap| gap.identifier.clone())
                .collect::<BTreeSet<_>>()
                != expected
        {
            return false;
        }
        if !expected.is_empty() && view.completeness == RetrievalCompleteness::Complete {
            return false;
        }
        view.active_evidence.iter().all(|statement| {
            !matches!(
                statement.ordering_basis,
                OrderingBasis::EventTime
                    | OrderingBasis::RecordedAtFallback
                    | OrderingBasis::Validity
            ) || (view.evidence_need.answer_shape == Some(AnswerShape::Timeline)
                && statement.derivation_kind == DerivationKind::Quoted
                && statement.support_refs.iter().all(|reference| {
                    self.result.candidates.iter().any(|candidate| {
                        candidate.candidate_id == *reference
                            && match statement.ordering_basis {
                                OrderingBasis::Validity => candidate.validity_interval.is_some(),
                                _ => candidate.source_time.is_some(),
                            }
                    })
                }))
        })
    }

    fn sequence_positions_valid(&self) -> bool {
        let Some(view) = &self.grounded_view else {
            return self
                .result
                .candidates
                .iter()
                .all(|candidate| candidate.source_sequence.is_none());
        };
        let sequence = view
            .evidence_need
            .temporal_scope
            .qualifiers
            .first()
            .filter(|qualifier| qualifier.source_sequence_ref().is_some());
        let sequence_mode = sequence.is_some();
        let automatic = view
            .evidence_need
            .answer_shape
            .is_some_and(AnswerShape::uses_temporal_order)
            && (view.evidence_need.temporal_scope.qualifiers.is_empty()
                || matches!(
                    requested_ordering(&view.evidence_need.temporal_scope.qualifiers),
                    Some(TemporalOrdering::SourceSequence | TemporalOrdering::Supersession)
                ));
        for candidate in &self.result.candidates {
            let Some(position) = &candidate.source_sequence else {
                if sequence_mode && candidate.row_variant == SearchCandidateVariant::EvidenceSurface
                {
                    return false;
                }
                continue;
            };
            if sequence_mode {
                let Some(qualifier) = sequence else {
                    return false;
                };
                if qualifier.matches_sequence(position.sequence) != Some(true)
                    || Some(position.source_anchor) != qualifier.source_sequence_ref()
                {
                    return false;
                }
            } else if automatic {
                let anchor = position.source_anchor.to_string();
                if !self
                    .result
                    .candidates
                    .iter()
                    .any(|candidate| candidate.source_ref == anchor)
                {
                    return false;
                }
            } else {
                return false;
            }
        }
        let sequence_order = automatic
            && view.evidence_need.answer_shape != Some(AnswerShape::TemporalComparison)
            && matches!(
                timeline_order(
                    &self.result.candidates,
                    &view.evidence_need.temporal_scope.qualifiers
                ),
                Some((OrderingBasis::SourceSequence, _))
            );
        if (sequence_mode || sequence_order)
            && self.result.completeness == RetrievalCompleteness::Complete
            && self.result.candidates.iter().any(|candidate| {
                candidate
                    .source_sequence
                    .as_ref()
                    .is_some_and(|position| !position.coverage_complete)
            })
        {
            return false;
        }
        view.active_evidence.iter().all(|statement| {
            let positioned = statement.support_refs.iter().all(|reference| {
                self.result.candidates.iter().any(|candidate| {
                    candidate.candidate_id == *reference && candidate.source_sequence.is_some()
                })
            });
            if statement.ordering_basis == OrderingBasis::SourceSequence {
                (sequence_mode || sequence_order)
                    && positioned
                    && statement.derivation_kind == DerivationKind::Quoted
            } else {
                !sequence_mode || !positioned || statement.derivation_kind != DerivationKind::Quoted
            }
        })
    }
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

/// Recording sequence and canonical native event clocks are distinct orders.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryBrowseOrder {
    #[default]
    RecordedNewest,
    RecordedOldest,
    EventNewest,
    EventOldest,
}

impl MemoryBrowseOrder {
    pub fn uses_event_time(self) -> bool {
        matches!(self, Self::EventNewest | Self::EventOldest)
    }
}

/// Time on the canonical native event, not a source message timestamp or
/// the generated revision's created_at_us.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTimeBasis {
    Event,
    Recorded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryTimeRange {
    pub basis: MemoryTimeBasis,
    pub from_us: Option<i64>,
    pub until_us: Option<i64>,
}

impl MemoryTimeRange {
    pub fn validate(&self) -> Result<(), QueryError> {
        if (self.from_us.is_none() && self.until_us.is_none())
            || matches!((self.from_us, self.until_us), (Some(from), Some(until)) if from >= until)
        {
            Err(QueryError::Invalid)
        } else {
            Ok(())
        }
    }
    pub fn contains(&self, occurred_at_us: i64, ingested_at_us: i64) -> bool {
        let value = match self.basis {
            MemoryTimeBasis::Event => occurred_at_us,
            MemoryTimeBasis::Recorded => ingested_at_us,
        };
        self.from_us.is_none_or(|from| value >= from)
            && self.until_us.is_none_or(|until| value < until)
    }
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
    #[serde(default)]
    pub time_range: Option<MemoryTimeRange>,
}

/// A scoped overview is a read; it never requests summary generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryOverviewQuery {
    pub selection: MemoryScopeSelection,
    pub include_global: bool,
    pub time_range: Option<MemoryTimeRange>,
    pub limit: u16,
}

/// Current compiler output has provenance watermarks, never an asset revision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledProjectionKind {
    Wiki,
    Core,
}
impl CompiledProjectionKind {
    pub fn object_kind(self) -> &'static str {
        match self {
            Self::Wiki => "wiki_projection",
            Self::Core => "l3_core_projection",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledProjectionQuery {
    Directory {
        selection: MemoryScopeSelection,
        include_global: bool,
        projection: CompiledProjectionKind,
    },
    Entries {
        reference: String,
        selection: MemoryScopeSelection,
        include_global: bool,
    },
}
impl CompiledProjectionQuery {
    pub fn validate(&self) -> Result<(), QueryError> {
        match self {
            Self::Directory {
                selection,
                include_global,
                ..
            } => MemoryBrowseQuery {
                selection: *selection,
                include_global: *include_global,
                ..MemoryBrowseQuery::default()
            }
            .validate(),
            Self::Entries {
                reference,
                selection,
                include_global,
            } => {
                MemoryBrowseQuery {
                    selection: *selection,
                    include_global: *include_global,
                    ..MemoryBrowseQuery::default()
                }
                .validate()?;
                let valid = reference
                    .strip_prefix("projection:wiki:")
                    .is_some_and(|id| id.parse::<crate::ids::WikiProjectionId>().is_ok())
                    || reference
                        .strip_prefix("projection:core:")
                        .is_some_and(|id| id.parse::<crate::ids::CoreProjectionId>().is_ok());
                if valid {
                    Ok(())
                } else {
                    Err(QueryError::Invalid)
                }
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledProjectionMetadata {
    pub reference: String,
    pub kind: CompiledProjectionKind,
    pub compiler_version: Option<u32>,
    pub source_watermark: u64,
    /// Original inputs: Atom/episode references, or Core membership-to-Atom pairs.
    pub source_count: u64,
    /// Existing compiler identity; this does not assert a materialized CAS body.
    pub render_identity: Option<crate::ids::CasId>,
}

/// Recorded reasons from the original Inbox selector; not new approval policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InboxReviewReason {
    Proposal {
        status: crate::semantic::ProposalStatus,
        eligibility: crate::semantic::ProposalEligibility,
    },
    Support {
        state: crate::semantic::GlobalSupportState,
    },
    Negative {
        status: crate::procedure::ProcedureNegativeReviewStatus,
    },
    PublicationHold,
    Segmentation,
    Assignment {
        status: crate::work::AssignmentStatus,
    },
    Competition {
        status: crate::work::CompetingResolutionStatus,
    },
    AttemptResume,
    Lane {
        status: crate::work::LaneStatus,
        liveness: crate::work::LivenessState,
        coverage: crate::work::CoverageLevel,
        source: crate::work::SourceCoverage,
        pairing: crate::work::PairingIntegrity,
        payload: crate::work::PayloadIntegrity,
        ordering: crate::work::OrderingIntegrity,
    },
    Capture {
        coverage: crate::work::CoverageLevel,
        source: crate::work::SourceCoverage,
        pairing: crate::work::PairingIntegrity,
        payload: crate::work::PayloadIntegrity,
        ordering: crate::work::OrderingIntegrity,
        admission: crate::work::AdmissionFailureObservability,
    },
    Lineage {
        assessment: crate::repository::LineageAssessment,
    },
    Recovery {
        status: crate::repository::RecoveryRequestStatus,
    },
}

impl InboxReviewReason {
    /// Textual proposal/work previews still require their original body-read gate.
    pub fn is_metadata_only(&self) -> bool {
        !matches!(self, Self::Proposal { .. } | Self::Segmentation)
    }

    pub fn object_kind(&self) -> &'static str {
        match self {
            Self::Proposal { .. } => "revision_proposal_revision",
            Self::Support { .. } => "global_support_validation",
            Self::Negative { .. } => "procedure_negative_review",
            Self::PublicationHold => "procedure_state_event",
            Self::Segmentation => "work_episode",
            Self::Assignment { .. } => "work_binding",
            Self::Competition { .. } => "competing_attempt_group",
            Self::AttemptResume => "attempt",
            Self::Lane { .. } => "execution_lane",
            Self::Capture { .. } => "capture_receipt",
            Self::Lineage { .. } => "worktree_transition",
            Self::Recovery { .. } => "recovery_capture_request_revision",
        }
    }
}

impl MemoryOverviewQuery {
    pub fn validate(&self) -> Result<(), QueryError> {
        if !(1..=64).contains(&self.limit) {
            return Err(QueryError::Invalid);
        }
        self.browse(MemoryReadingKind::All).validate()
    }

    pub fn browse(&self, kind: MemoryReadingKind) -> MemoryBrowseQuery {
        MemoryBrowseQuery {
            selection: self.selection,
            include_global: self.include_global,
            kind,
            order: if self
                .time_range
                .as_ref()
                .is_some_and(|range| range.basis == MemoryTimeBasis::Event)
            {
                MemoryBrowseOrder::EventNewest
            } else {
                MemoryBrowseOrder::RecordedNewest
            },
            epistemic_status: None,
            authority: None,
            atom_lifecycle: None,
            time_range: self.time_range.clone(),
        }
    }
}

impl MemoryBrowseQuery {
    pub fn validate(&self) -> Result<(), QueryError> {
        if let Some(range) = &self.time_range {
            range.validate()?;
        }
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
    pub event_time_us: Option<i64>,
    pub source_event_seq: u64,
    pub row_id: String,
}

impl MemoryBrowseCursor {
    pub fn validate_for(&self, query: &MemoryBrowseQuery) -> Result<(), QueryError> {
        if self.query != *query
            || query.order.uses_event_time() != self.event_time_us.is_some()
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanRevisionKind {
    Atom,
    Procedure,
    CoreMembership,
    Proposal,
    Digest,
}

pub const HUMAN_CONTENT_LIMIT: u16 = 8192;

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
