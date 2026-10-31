//! Deterministic, deletion-first production retrieval over one pinned snapshot.

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
    procedure_revisions: Option<BTreeSet<String>>,
    method_proposal_revisions: BTreeSet<String>,
    validated_frontier: Option<u64>,
    readable_refs: Option<(u64, BTreeSet<String>)>,
    semantics: Option<super::resolution::SemanticSearchResolution>,
}

impl ProductionSearch {
    pub const fn new(index: SearchIndex) -> Self {
        Self {
            index,
            procedure_revisions: None,
            method_proposal_revisions: BTreeSet::new(),
            validated_frontier: None,
            readable_refs: None,
            semantics: None,
        }
    }

    pub fn with_procedure_revisions(mut self, revisions: BTreeSet<String>) -> Self {
        self.procedure_revisions = Some(revisions);
        self
    }

    pub(crate) fn with_method_proposals(mut self, revisions: BTreeSet<String>) -> Self {
        self.method_proposal_revisions = revisions;
        self
    }

    /// A current `WriterHandle::project` result can avoid a duplicate
    /// pre-pin frontier scan while the store still validates after pinning.
    pub(crate) fn with_validated_frontier(mut self, frontier: u64) -> Self {
        self.validated_frontier = Some(frontier);
        self
    }

    /// Grants come from the native canonical access owner at this frontier,
    /// never caller-built authority or an unversioned Web allowlist.
    #[must_use]
    pub fn with_readable_refs(mut self, frontier: u64, refs: BTreeSet<String>) -> Self {
        self.readable_refs = Some((frontier, refs));
        self
    }

    pub(crate) fn with_semantic_resolution(
        mut self,
        semantics: super::resolution::SemanticSearchResolution,
    ) -> Self {
        self.semantics = Some(semantics);
        self
    }

    fn hard_filter(&self, context: &SearchContext, object_only: bool) -> SearchHardFilter {
        let suppressed_hashes = match &context.suppression {
            SuppressionSnapshot::Current { ref_hashes, .. } => ref_hashes.clone(),
            SuppressionSnapshot::Unavailable => unreachable!("handled above"),
        };
        let (source_role, authority) = source_filter(context.query_facets.source_boundary);
        SearchHardFilter {
            readable_refs: self.readable_refs.as_ref().map(|(_, refs)| refs.clone()),
            // A is a candidate channel; C owns positive facet compatibility.
            condition_literals: Vec::new(),
            excluded_identifiers: context.query_facets.explicit_exclusions.clone(),
            procedure_revisions: self.procedure_revisions.clone(),
            method_proposal_revisions: self.method_proposal_revisions.clone(),
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
            object_only,
            global_only: false,
            current_only: match context.query_facets.temporal_mode {
                TemporalMode::Current => true,
                TemporalMode::Any | TemporalMode::Unknown => {
                    context.intent != evertrace_domain::query::SearchIntent::HistoryLookup
                }
                TemporalMode::AsOf | TemporalMode::Interval | TemporalMode::Sequence => false,
            },
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
        }
    }

    pub(crate) async fn retrieve(
        &self,
        context: SearchContext,
        global_only: bool,
    ) -> Result<evertrace_domain::query::HumanSearchPage, SearchError> {
        use evertrace_domain::query::{HumanSearchPage, SourceBoundary};
        context.validate()?;
        if self.readable_refs.is_none() {
            return Err(SearchError::Unsupported);
        }
        if matches!(context.suppression, SuppressionSnapshot::Unavailable)
            || (context.query_facets.polarity != Polarity::Positive
                && context.query_facets.explicit_exclusions.is_empty())
        {
            return Ok(HumanSearchPage {
                result: self.search(context).await?,
                grounded_view: None,
            });
        }
        let deadline = RequestDeadline::new(Instant::now(), context.budget.latency_us_remaining);
        let snapshot = match deadline
            .run(
                self.index
                    .snapshot_after_validated_frontier(self.validated_frontier.unwrap_or(0)),
            )
            .await
        {
            Ok(snapshot) => snapshot?,
            Err(()) => {
                return Ok(HumanSearchPage {
                    result: deadline_result(context, "snapshot_deadline_exhausted", 0, 0),
                    grounded_view: None,
                });
            }
        };
        let mut objects = self.hard_filter(&context, true);
        objects.global_only = global_only;
        let evidence = match context.query_facets.source_boundary {
            Some(SourceBoundary::ProjectPolicy | SourceBoundary::ObjectiveEvidence) => None,
            role => {
                let mut filter = self.hard_filter(&context, false);
                filter.global_only = global_only;
                filter.current_only = false;
                filter.lifecycle = None;
                filter.authority = None;
                filter.source_kind = Some("evidence_surface".into());
                filter.source_role = match role {
                    None => None,
                    Some(SourceBoundary::User) => Some("user"),
                    Some(SourceBoundary::Assistant | SourceBoundary::AgentInferred) => {
                        Some("assistant")
                    }
                    Some(SourceBoundary::Tool) => Some("tool"),
                    Some(SourceBoundary::Host) => Some("host"),
                    Some(SourceBoundary::Imported) => Some("imported"),
                    _ => unreachable!(),
                }
                .map(str::to_owned);
                Some(filter)
            }
        };
        let result = self
            .search_snapshot(
                context.clone(),
                false,
                &snapshot,
                &deadline,
                global_only,
                evidence.as_ref(),
            )
            .await?;
        super::retrieval::NativeRetrieval {
            snapshot: &snapshot,
            context: &context,
            result,
            objects,
            evidence,
            deadline: &deadline,
            semantics: self.semantics.as_ref(),
        }
        .run()
        .await
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
        context: SearchContext,
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
        let snapshot = match deadline
            .run(async {
                if let Some(frontier) = self.validated_frontier {
                    self.index.snapshot_after_validated_frontier(frontier).await
                } else {
                    self.index.snapshot().await
                }
            })
            .await
        {
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
        self.search_snapshot(
            context,
            force_fts_failure,
            &snapshot,
            &deadline,
            false,
            None,
        )
        .await
    }

    async fn search_snapshot(
        &self,
        mut context: SearchContext,
        force_fts_failure: bool,
        snapshot: &evertrace_store::SearchSnapshot,
        deadline: &RequestDeadline,
        global_only: bool,
        anchor_evidence: Option<&SearchHardFilter>,
    ) -> Result<SearchResult, SearchError> {
        let started = deadline.started;
        if self.readable_refs.as_ref().is_some_and(|(frontier, _)| {
            *frontier != snapshot.frontier() || *frontier != snapshot.authoritative_frontier()
        }) || self
            .semantics
            .as_ref()
            .is_some_and(|value| value.frontier != snapshot.frontier())
        {
            return Ok(SearchResult {
                layer: RetrievalLayer::A,
                projection_frontier: snapshot.frontier(),
                authoritative_frontier: snapshot.authoritative_frontier(),
                candidates: Vec::new(),
                completeness: RetrievalCompleteness::Unknown,
                degraded_reasons: BTreeSet::from(["read_access_frontier_changed".into()]),
                omitted_refs: BTreeSet::new(),
                budget: context.budget,
            });
        }
        let mut filter = self.hard_filter(&context, true);
        filter.global_only = global_only;
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
        let fetch_limit = if limit >= 32 {
            limit
        } else {
            limit.saturating_mul(4).min(32)
        };
        let mut exact_identifiers = context.query_facets.exact_identifiers.clone();
        exact_identifiers.push(context.raw_query.clone());
        exact_identifiers.sort();
        exact_identifiers.dedup();
        let mut structured = Vec::new();
        let mut degraded_reasons = BTreeSet::new();
        let mut omitted_refs = BTreeSet::new();
        if let Some(semantics) = &self.semantics {
            if semantics.incomplete {
                degraded_reasons.insert("normative_resolution_incomplete".into());
            }
            let references = semantics.active_references();
            if !references.is_empty() {
                match deadline
                    .run(snapshot.structured(&references, &filter, 33))
                    .await
                {
                    Ok(Ok(mut rows)) => {
                        if rows.len() > 32 {
                            omitted_refs.extend(
                                rows[32..].iter().filter_map(|row| row.candidate_id.clone()),
                            );
                            rows.truncate(32);
                            degraded_reasons.insert("normative_candidate_budget_exhausted".into());
                        }
                        structured.extend(rows);
                    }
                    Ok(Err(_)) => {
                        degraded_reasons.insert("normative_channel_unavailable".into());
                    }
                    Err(()) => {
                        degraded_reasons.insert("normative_deadline_exhausted".into());
                    }
                }
            }
        }
        // Pin object and original-evidence targets before text channels. Both
        // use the existing native filters; neither is a new access grant.
        if !context.query_facets.target_anchors.is_empty() {
            for anchor_filter in std::iter::once(&filter).chain(anchor_evidence) {
                match deadline
                    .run(snapshot.structured(
                        &context.query_facets.target_anchors,
                        anchor_filter,
                        32,
                    ))
                    .await
                {
                    Ok(Ok(rows)) => structured.extend(rows),
                    Ok(Err(_)) => {
                        degraded_reasons.insert("target_anchor_channel_unavailable".into());
                    }
                    Err(()) => {
                        degraded_reasons.insert("target_anchor_deadline_exhausted".into());
                    }
                }
            }
        }
        match deadline
            .run(snapshot.structured(&exact_identifiers, &filter, fetch_limit))
            .await
        {
            Ok(Ok(rows)) => structured.extend(rows),
            Ok(Err(error)) => return Err(error.into()),
            Err(()) => {
                return Ok(deadline_result(
                    context,
                    "structured_deadline_exhausted",
                    snapshot.frontier(),
                    snapshot.authoritative_frontier(),
                ));
            }
        }
        let fts_result = if force_fts_failure {
            Err(StoreError::LanceDb)
        } else {
            match deadline
                .run(snapshot.fts(&context.raw_query, &filter, fetch_limit))
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
        let fts_ranks = fts
            .iter()
            .enumerate()
            .map(|(position, row)| (row.row_id.clone(), position))
            .collect::<BTreeMap<_, _>>();
        let mut rows = structured;
        rows.extend(fts);
        rows.sort();
        rows.dedup_by(|left, right| left.row_id == right.row_id);
        let mut ranked = Vec::with_capacity(rows.len());
        for row in &rows {
            if row.candidate_id.is_none() || !hard_compatible(row, &context)? {
                continue;
            }
            let exact = context
                .query_facets
                .exact_identifiers
                .iter()
                .any(|identifier| {
                    row.candidate_id.as_deref() == Some(identifier)
                        || row.source_ref.as_deref() == Some(identifier)
                        || row.text.contains(identifier)
                });
            let stable = row
                .candidate_id
                .as_deref()
                .is_some_and(|id| id == context.raw_query)
                || row.source_ref.as_deref() == Some(context.raw_query.as_str());
            let anchor_position = context.query_facets.target_anchors.iter().position(|id| {
                row.candidate_id.as_deref() == Some(id) || row.source_ref.as_deref() == Some(id)
            });
            let active = row
                .candidate_id
                .as_ref()
                .and_then(|id| self.semantics.as_ref()?.states.get(id))
                == Some(&evertrace_domain::semantic::SemanticResolution::Normative(
                    evertrace_domain::semantic::NormativeResolutionState::Active,
                ));
            let rank = if active {
                (0, 0)
            } else if let Some(position) = anchor_position {
                (1, position)
            } else if exact || stable {
                (2, 0)
            } else if let Some(position) = fts_ranks.get(&row.row_id) {
                (3, *position)
            } else {
                continue;
            };
            ranked.push((rank, row, exact || stable));
        }
        ranked.sort_by(|(left_rank, left, _), (right_rank, right, _)| {
            left_rank
                .cmp(right_rank)
                .then_with(|| left.candidate_id.cmp(&right.candidate_id))
        });
        let mut selected =
            BTreeMap::<String, ((u8, usize), SearchCandidate, &SearchProjectionRow)>::new();
        for (row_index, (rank, row, explicit_exact)) in ranked.iter().enumerate() {
            let candidate_id = row.candidate_id.clone().ok_or(SearchError::Corrupt)?;
            let origin = match rank.0 {
                0 => "normative",
                1 => "target_anchor",
                2 => "exact",
                _ => "fts",
            };
            let mut origins = BTreeSet::from([origin.to_owned()]);
            if rank.0 <= 1 && *explicit_exact {
                origins.insert("exact".into());
            }
            if rank.0 == 0
                && context.query_facets.target_anchors.iter().any(|id| {
                    row.candidate_id.as_deref() == Some(id) || row.source_ref.as_deref() == Some(id)
                })
            {
                origins.insert("target_anchor".into());
            }
            if fts_ranks.contains_key(&row.row_id) {
                origins.insert("fts".into());
            }
            if let Some(entry) = selected.get_mut(&candidate_id) {
                entry.1.retrieval_origins.extend(origins);
                continue;
            }
            if context
                .budget
                .consume_candidate_text(row.text.len())
                .is_err()
            {
                omitted_refs.extend(
                    ranked[row_index..]
                        .iter()
                        .filter_map(|(_, value, _)| value.candidate_id.as_ref())
                        .filter(|id| !selected.contains_key(*id))
                        .cloned(),
                );
                break;
            }
            let row_variant = match row.row_variant.as_str() {
                "object" => evertrace_domain::query::SearchCandidateVariant::Object,
                "evidence_surface" => {
                    evertrace_domain::query::SearchCandidateVariant::EvidenceSurface
                }
                _ => return Err(SearchError::Corrupt),
            };
            let semantic_resolution = self
                .semantics
                .as_ref()
                .and_then(|value| value.states.get(&candidate_id))
                .copied();
            let candidate = SearchCandidate {
                candidate_id: candidate_id.clone(),
                source_ref: row.source_ref.clone().unwrap_or_default(),
                row_variant,
                currentness: row
                    .currentness
                    .as_deref()
                    .map(str::parse)
                    .transpose()
                    .map_err(|_| SearchError::Corrupt)?,
                object_kind: row.object_kind.clone(),
                text: row.text.clone(),
                source_role: row.source_role.clone(),
                content_trust: row.content_trust.clone(),
                capture_completeness: row.capture_completeness.clone(),
                retrieval_origins: origins,
                instruction_authority: "none".into(),
                conflicted: semantic_resolution
                    == Some(evertrace_domain::semantic::SemanticResolution::Descriptive(
                        evertrace_domain::semantic::DescriptiveResolutionState::Disputed,
                    )),
                semantic_resolution,
            };
            selected.insert(candidate_id, (*rank, candidate, *row));
        }
        let mut candidates = selected.into_values().collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.candidate_id.cmp(&right.1.candidate_id))
        });
        if candidates.len() > limit {
            omitted_refs.extend(
                candidates[limit..]
                    .iter()
                    .map(|(_, candidate, _)| candidate.candidate_id.clone()),
            );
            candidates.truncate(limit);
        }
        let conflicted = mark_conservative_conflicts(&mut candidates, &context)
            || candidates
                .iter()
                .any(|(_, candidate, _)| candidate.conflicted);
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
            omitted_refs,
            budget: context.budget,
        })
    }
}

pub(super) struct RequestDeadline {
    started: Instant,
    at: Instant,
}

impl RequestDeadline {
    fn new(started: Instant, latency_us: u64) -> Self {
        Self {
            started,
            at: started + Duration::from_micros(latency_us),
        }
    }

    pub(super) fn remaining(&self) -> Option<Duration> {
        self.at.checked_duration_since(Instant::now())
    }

    pub(super) async fn run<F: std::future::Future>(&self, future: F) -> Result<F::Output, ()> {
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
    let has_route = context.task_id.is_some()
        || context.repository_id.is_some()
        || context.worktree_id.is_some();
    let route_matches = context
        .task_id
        .is_some_and(|id| row.task_id.as_deref() == Some(id.to_string().as_str()))
        || context
            .repository_id
            .is_some_and(|id| row.repository_id.as_deref() == Some(id.to_string().as_str()))
        || context
            .worktree_id
            .is_some_and(|id| row.worktree_id.as_deref() == Some(id.to_string().as_str()));
    if has_route && !route_matches
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
            .any(|value| {
                row.candidate_id.as_deref() == Some(value)
                    || row.source_ref.as_deref() == Some(value)
                    || row.text.contains(value)
            })
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
    candidates: &[((u8, usize), SearchCandidate, &SearchProjectionRow)],
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
    candidates: &mut [((u8, usize), SearchCandidate, &SearchProjectionRow)],
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
