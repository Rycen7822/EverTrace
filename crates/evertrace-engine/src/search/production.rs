//! Deterministic, deletion-first retrieval. Production is permanently layer A.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use evertrace_domain::query::{
    FacetParseStatus, LifecycleBoundary, Polarity, QuantityConstraint, QueryError,
    RetrievalCompleteness, RetrievalLayer, ScopeBoundary, SearchCandidate, SearchContext,
    SearchResult, SourceBoundary, SuppressionSnapshot, TemporalMode, TemporalQualifier,
    production_retrieval_layer,
};
use evertrace_store::{SearchHardFilter, SearchIndex, SearchProjectionRow, StoreError};
use thiserror::Error;

pub struct ProductionSearch {
    index: SearchIndex,
}

impl ProductionSearch {
    pub const fn new(index: SearchIndex) -> Self {
        Self { index }
    }

    pub async fn search(&self, context: SearchContext) -> Result<SearchResult, SearchError> {
        self.search_inner(context, false).await
    }

    pub async fn search_with_diagnostic_fts_failure(
        &self,
        context: SearchContext,
        _failure: DiagnosticFtsFailure,
    ) -> Result<SearchResult, SearchError> {
        self.search_inner(context, true).await
    }

    async fn search_inner(
        &self,
        mut context: SearchContext,
        force_fts_failure: bool,
    ) -> Result<SearchResult, SearchError> {
        let started = Instant::now();
        context.validate()?;
        if matches!(context.suppression, SuppressionSnapshot::Unavailable) {
            return Ok(SearchResult {
                layer: production_retrieval_layer(),
                projection_frontier: 0,
                authoritative_frontier: 0,
                candidates: Vec::new(),
                completeness: RetrievalCompleteness::Unknown,
                degraded_reasons: BTreeSet::from(["suppression_unavailable".into()]),
                omitted_refs: BTreeSet::new(),
                budget: context.budget,
            });
        }
        if context.query_facets.polarity == Polarity::Negative
            && context.query_facets.explicit_exclusions.is_empty()
        {
            return Ok(SearchResult {
                layer: RetrievalLayer::A,
                projection_frontier: 0,
                authoritative_frontier: 0,
                candidates: Vec::new(),
                completeness: RetrievalCompleteness::Unknown,
                degraded_reasons: BTreeSet::from(["negative_without_exact_exclusion".into()]),
                omitted_refs: BTreeSet::new(),
                budget: context.budget,
            });
        }
        let deadline = RequestDeadline::new(started, context.budget.latency_us_remaining);
        let snapshot = match deadline.run(self.index.snapshot()).await {
            Ok(Ok(snapshot)) => snapshot,
            Ok(Err(error)) => return Err(error.into()),
            Err(()) => {
                return Ok(deadline_result(
                    context,
                    "snapshot_deadline_exhausted",
                    0,
                    0,
                ));
            }
        };
        let suppressed_hashes = match &context.suppression {
            SuppressionSnapshot::Current { ref_hashes, .. } => ref_hashes.clone(),
            SuppressionSnapshot::Unavailable => unreachable!("handled above"),
        };
        let (source_role, authority) = source_filter(context.query_facets.source_boundary);
        let filter = SearchHardFilter {
            task_id: context.task_id.map(|id| id.to_string()),
            repository_id: context.repository_id.map(|id| id.to_string()),
            worktree_id: context.worktree_id.map(|id| id.to_string()),
            source_kind: None,
            source_role,
            authority,
            lifecycle: match context.query_facets.lifecycle_boundary {
                LifecycleBoundary::Active => Some("active".into()),
                LifecycleBoundary::Terminal => Some("terminal".into()),
                LifecycleBoundary::Any => None,
            },
            object_only: true,
            current_only: context.intent != evertrace_domain::query::SearchIntent::HistoryLookup
                && matches!(
                    context.query_facets.temporal_mode,
                    TemporalMode::Current | TemporalMode::Any | TemporalMode::Unknown
                ),
            suppressed_refs: suppressed_hashes.clone(),
            suppressed_hashes,
            event_time_as_of: match context.query_facets.temporal_qualifiers.as_slice() {
                [TemporalQualifier::EventTimeAsOf { at_us }] => Some(*at_us),
                _ => None,
            },
            event_time_interval: match context.query_facets.temporal_qualifiers.as_slice() {
                [TemporalQualifier::EventTimeInterval { start_us, end_us }] => {
                    Some((*start_us, *end_us))
                }
                _ => None,
            },
            source_sequence_at_most: match context.query_facets.temporal_qualifiers.as_slice() {
                [TemporalQualifier::SourceSequenceAtMost { sequence }] => Some(*sequence),
                _ => None,
            },
        };
        let requested_limit = context
            .query_facets
            .quantity_constraints
            .iter()
            .map(|constraint| match constraint {
                QuantityConstraint::ResultLimit { limit } => *limit,
            })
            .min()
            .unwrap_or(context.budget.candidates_remaining)
            .min(context.budget.candidates_remaining);
        let limit = usize::try_from(requested_limit).map_err(|_| SearchError::Unsupported)?;
        let mut exact_identifiers = context.query_facets.exact_identifiers.clone();
        exact_identifiers.push(context.raw_query.clone());
        exact_identifiers.sort();
        exact_identifiers.dedup();
        let structured = match deadline
            .run(snapshot.structured(&exact_identifiers, &filter, limit))
            .await
        {
            Ok(Ok(rows)) => rows,
            Ok(Err(error)) => return Err(error.into()),
            Err(()) => {
                return Ok(deadline_result(
                    context,
                    "structured_deadline_exhausted",
                    snapshot.frontier(),
                    snapshot.authoritative_frontier(),
                ));
            }
        };
        let mut degraded_reasons = BTreeSet::new();
        let fts_result = if force_fts_failure {
            Err(StoreError::LanceDb)
        } else {
            match deadline
                .run(snapshot.fts(&context.raw_query, &filter, limit))
                .await
            {
                Ok(result) => result,
                Err(()) => {
                    context.budget.latency_us_remaining = 0;
                    degraded_reasons.insert("fts_deadline_exhausted".into());
                    Ok(Vec::new())
                }
            }
        };
        let fts = match fts_result {
            Ok(rows) => rows,
            Err(_) => {
                degraded_reasons.insert("fts_unavailable".into());
                Vec::new()
            }
        };
        let fts_ids = fts
            .iter()
            .map(|row| row.row_id.clone())
            .collect::<BTreeSet<_>>();
        let mut rows = structured;
        rows.extend(fts);
        rows.sort();
        rows.dedup_by(|left, right| left.row_id == right.row_id);
        let mut selected = BTreeMap::<String, (u8, SearchCandidate, &SearchProjectionRow)>::new();
        for row in &rows {
            if row.candidate_id.is_none() || !hard_compatible(row, &context)? {
                continue;
            }
            let exact = context
                .query_facets
                .exact_identifiers
                .iter()
                .any(|identifier| {
                    row.candidate_id.as_deref() == Some(identifier) || row.text.contains(identifier)
                });
            let stable = row
                .candidate_id
                .as_deref()
                .is_some_and(|id| id == context.raw_query);
            let origin = if exact || stable {
                "exact"
            } else if fts_ids.contains(&row.row_id) {
                "fts"
            } else {
                continue;
            };
            if context
                .budget
                .consume_candidate_text(row.text.len())
                .is_err()
            {
                break;
            }
            let candidate_id = row.candidate_id.clone().ok_or(SearchError::Corrupt)?;
            let entry = selected.entry(candidate_id.clone()).or_insert_with(|| {
                (
                    if exact || stable { 0 } else { 3 },
                    SearchCandidate {
                        candidate_id,
                        source_ref: row.source_ref.clone().unwrap_or_default(),
                        text: row.text.clone(),
                        source_role: row.source_role.clone(),
                        content_trust: row.content_trust.clone(),
                        capture_completeness: row.capture_completeness.clone(),
                        retrieval_origins: BTreeSet::new(),
                        instruction_authority: "none".into(),
                        conflicted: false,
                    },
                    row,
                )
            });
            entry.0 = entry.0.min(if exact || stable { 0 } else { 3 });
            entry.1.retrieval_origins.insert(origin.into());
        }
        let mut candidates = selected.into_values().collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.candidate_id.cmp(&right.1.candidate_id))
        });
        let conflicted = mark_conservative_conflicts(&mut candidates, &context);
        let temporal_partial = temporal_is_partial(&candidates, &context, &mut degraded_reasons);
        let mut completeness = if conflicted {
            RetrievalCompleteness::Conflicted
        } else if temporal_partial
            || context.query_facets.parse_status != FacetParseStatus::Complete
        {
            RetrievalCompleteness::Partial
        } else {
            RetrievalCompleteness::Complete
        };
        if snapshot.frontier() < snapshot.authoritative_frontier() {
            degraded_reasons.insert("search_projection_stale".into());
            if completeness == RetrievalCompleteness::Complete {
                completeness = RetrievalCompleteness::Partial;
            }
        }
        let elapsed = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        if context.budget.consume_latency(elapsed).is_err() {
            context.budget.latency_us_remaining = 0;
            degraded_reasons.insert("latency_budget_exhausted".into());
        }
        Ok(SearchResult {
            layer: RetrievalLayer::A,
            projection_frontier: snapshot.frontier(),
            authoritative_frontier: snapshot.authoritative_frontier(),
            candidates: candidates
                .into_iter()
                .map(|(_, candidate, _)| candidate)
                .collect(),
            completeness,
            degraded_reasons,
            omitted_refs: BTreeSet::new(),
            budget: context.budget,
        })
    }
}

struct RequestDeadline {
    at: Instant,
}

impl RequestDeadline {
    fn new(started: Instant, latency_us: u64) -> Self {
        Self {
            at: started + Duration::from_micros(latency_us),
        }
    }

    fn remaining(&self) -> Option<Duration> {
        self.at.checked_duration_since(Instant::now())
    }

    async fn run<F: std::future::Future>(&self, future: F) -> Result<F::Output, ()> {
        let remaining = self
            .remaining()
            .filter(|value| !value.is_zero())
            .ok_or(())?;
        tokio::time::timeout(remaining, future)
            .await
            .map_err(|_| ())
    }
}

fn deadline_result(
    mut context: SearchContext,
    reason: &str,
    projection_frontier: u64,
    authoritative_frontier: u64,
) -> SearchResult {
    context.budget.latency_us_remaining = 0;
    SearchResult {
        layer: RetrievalLayer::A,
        projection_frontier,
        authoritative_frontier,
        candidates: Vec::new(),
        completeness: RetrievalCompleteness::Unknown,
        degraded_reasons: BTreeSet::from([reason.into()]),
        omitted_refs: BTreeSet::new(),
        budget: context.budget,
    }
}

pub struct DiagnosticFtsFailure {
    _diagnostic_only: (),
}

impl DiagnosticFtsFailure {
    pub const fn for_characterization() -> Self {
        Self {
            _diagnostic_only: (),
        }
    }
}

fn source_filter(boundary: Option<SourceBoundary>) -> (Option<String>, Option<String>) {
    match boundary {
        None => (None, None),
        Some(SourceBoundary::User) => (None, Some("user_explicit".into())),
        Some(SourceBoundary::Assistant | SourceBoundary::AgentInferred) => {
            (None, Some("agent_inferred".into()))
        }
        Some(SourceBoundary::Imported) => (None, Some("imported_claim".into())),
        Some(SourceBoundary::ProjectPolicy) => (None, Some("project_policy".into())),
        Some(SourceBoundary::ObjectiveEvidence | SourceBoundary::Tool | SourceBoundary::Host) => {
            (None, Some("objective_evidence".into()))
        }
    }
}

pub(super) fn hard_compatible(
    row: &SearchProjectionRow,
    context: &SearchContext,
) -> Result<bool, QueryError> {
    if let Some(hash) = row.suppression_ref_hash.as_deref()
        && context.suppression.suppresses(hash)?
    {
        return Ok(false);
    }
    if context
        .task_id
        .is_some_and(|id| row.task_id.as_deref() != Some(id.to_string().as_str()))
        || context
            .repository_id
            .is_some_and(|id| row.repository_id.as_deref() != Some(id.to_string().as_str()))
        || context
            .worktree_id
            .is_some_and(|id| row.worktree_id.as_deref() != Some(id.to_string().as_str()))
        || !source_compatible(row, context.query_facets.source_boundary)
        || row.row_variant == "object"
            && context.intent != evertrace_domain::query::SearchIntent::HistoryLookup
            && matches!(
                context.query_facets.temporal_mode,
                TemporalMode::Current | TemporalMode::Any | TemporalMode::Unknown
            )
            && row.currentness.as_deref() != Some("current")
        || row.row_variant == "object"
            && match context.query_facets.lifecycle_boundary {
                LifecycleBoundary::Active => row.lifecycle.as_deref() != Some("active"),
                LifecycleBoundary::Terminal => row.lifecycle.as_deref() != Some("terminal"),
                LifecycleBoundary::Any => false,
            }
        || context
            .query_facets
            .scope_boundary
            .is_some_and(|boundary| match boundary {
                ScopeBoundary::Task { task_id } => {
                    row.task_id.as_deref() != Some(task_id.to_string().as_str())
                }
                ScopeBoundary::Repository { repository_id } => {
                    row.repository_id.as_deref() != Some(repository_id.to_string().as_str())
                }
                ScopeBoundary::Worktree { worktree_id } => {
                    row.worktree_id.as_deref() != Some(worktree_id.to_string().as_str())
                }
            })
        || context
            .query_facets
            .explicit_exclusions
            .iter()
            .any(|value| row.text.contains(value))
        || !temporal_compatible(row, context)
        || context
            .suppression
            .suppresses(row.candidate_id.as_deref().unwrap_or_default())?
        || context
            .suppression
            .suppresses(row.source_ref.as_deref().unwrap_or_default())?
    {
        return Ok(false);
    }
    Ok(true)
}

fn source_compatible(row: &SearchProjectionRow, boundary: Option<SourceBoundary>) -> bool {
    match row.row_variant.as_str() {
        "evidence_surface" => match boundary {
            None => true,
            Some(SourceBoundary::User) => row.source_role.as_deref() == Some("user"),
            Some(SourceBoundary::Assistant | SourceBoundary::AgentInferred) => {
                row.source_role.as_deref() == Some("assistant")
            }
            Some(SourceBoundary::Tool) => row.source_role.as_deref() == Some("tool"),
            Some(SourceBoundary::Host) => row.source_role.as_deref() == Some("host"),
            Some(SourceBoundary::Imported) => row.source_role.as_deref() == Some("imported"),
            Some(SourceBoundary::ProjectPolicy | SourceBoundary::ObjectiveEvidence) => false,
        },
        "object" => {
            let (_, authority) = source_filter(boundary);
            authority.is_none_or(|value| row.authority.as_ref() == Some(&value))
        }
        _ => false,
    }
}

pub(super) fn temporal_is_partial(
    candidates: &[(u8, SearchCandidate, &SearchProjectionRow)],
    context: &SearchContext,
    degraded: &mut BTreeSet<String>,
) -> bool {
    let required_domain = match context.query_facets.temporal_qualifiers.as_slice() {
        [] => return false,
        [TemporalQualifier::EventTimeAsOf { .. } | TemporalQualifier::EventTimeInterval { .. }] => {
            "event_time"
        }
        [TemporalQualifier::SourceSequenceAtMost { .. }] => "source_sequence",
        _ => {
            degraded.insert("temporal_qualifier_unknown".into());
            return true;
        }
    };
    if candidates.is_empty()
        || candidates
            .iter()
            .any(|(_, _, row)| row.time_domain != required_domain)
    {
        degraded.insert("temporal_domain_incomplete".into());
        true
    } else {
        false
    }
}

fn temporal_compatible(row: &SearchProjectionRow, context: &SearchContext) -> bool {
    match context.query_facets.temporal_qualifiers.as_slice() {
        [] => true,
        [TemporalQualifier::EventTimeAsOf { at_us }] => {
            row.time_domain == "event_time" && row.event_time_us <= *at_us
        }
        [TemporalQualifier::EventTimeInterval { start_us, end_us }] => {
            row.time_domain == "event_time"
                && row.event_time_us >= *start_us
                && row.event_time_us < *end_us
        }
        [TemporalQualifier::SourceSequenceAtMost { sequence }] => {
            row.time_domain == "source_sequence" && row.source_sequence <= *sequence
        }
        _ => false,
    }
}

fn mark_conservative_conflicts(
    candidates: &mut [(u8, SearchCandidate, &SearchProjectionRow)],
    context: &SearchContext,
) -> bool {
    let mut conflicted = false;
    for identifier in &context.query_facets.exact_identifiers {
        let matching = candidates
            .iter()
            .enumerate()
            .filter(|(_, (_, candidate, _))| candidate.text.contains(identifier))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matching.len() > 1 {
            let texts = matching
                .iter()
                .map(|index| candidates[*index].1.text.as_str())
                .collect::<BTreeSet<_>>();
            let refs = matching
                .iter()
                .map(|index| candidates[*index].1.source_ref.as_str())
                .collect::<BTreeSet<_>>();
            if texts.len() > 1 && refs.len() > 1 {
                conflicted = true;
                for index in matching {
                    candidates[index].1.conflicted = true;
                }
            }
        }
    }
    conflicted
}
#[derive(Debug, Error)]
pub enum SearchError {
    #[error("query contract failed")]
    Query(#[from] QueryError),
    #[error("search store failed")]
    Store(#[from] StoreError),
    #[error("search projection is corrupt")]
    Corrupt,
    #[error("unsupported retrieval operation")]
    Unsupported,
}
