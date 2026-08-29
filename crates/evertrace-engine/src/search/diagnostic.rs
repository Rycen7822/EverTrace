//! Request-local, characterization-only B-E retrieval operators.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use evertrace_domain::query::{
    CandidateBoundary, DerivationKind, GroundedEvidenceView, GroundedStatement, NamedGap,
    NamedGapKind, OrderingBasis, RetrievalCompleteness, RetrievalLayer, SearchCandidate,
    SearchContext, SearchResult,
};
use evertrace_store::{
    RelationProjectionRow, SearchProjectionRow, relations::RELATIONS_CHECKPOINT_ID,
    search::SEARCH_CHECKPOINT_ID,
};

use super::production::{SearchError, hard_compatible};

pub struct DiagnosticRetrieval {
    _diagnostic_only: (),
}

impl DiagnosticRetrieval {
    pub const fn for_characterization() -> Self {
        Self {
            _diagnostic_only: (),
        }
    }

    pub fn begin(
        &self,
        result: SearchResult,
        context: SearchContext,
    ) -> Result<DiagnosticSession, SearchError> {
        context.validate()?;
        if result.layer != RetrievalLayer::A
            || result.projection_frontier == 0
            || result.authoritative_frontier < result.projection_frontier
        {
            return Err(SearchError::Unsupported);
        }
        let deadline = Instant::now() + Duration::from_micros(result.budget.latency_us_remaining);
        Ok(DiagnosticSession {
            frontier: result.projection_frontier,
            context,
            result,
            deadline,
            generation_one_exact_refs: None,
            followed_up: false,
        })
    }
}

pub struct DiagnosticSession {
    result: SearchResult,
    context: SearchContext,
    deadline: Instant,
    frontier: u64,
    generation_one_exact_refs: Option<BTreeSet<String>>,
    followed_up: bool,
}

impl DiagnosticSession {
    pub const fn result(&self) -> &SearchResult {
        &self.result
    }

    pub fn finish(self) -> SearchResult {
        self.result
    }

    pub fn evidence_surface(
        &mut self,
        rows: &[SearchProjectionRow],
    ) -> Result<&SearchResult, SearchError> {
        self.require_layer(RetrievalLayer::A)?;
        self.validate_search_frontier(rows)?;
        for row in rows
            .iter()
            .filter(|row| row.source_kind.as_deref() == Some("evidence_surface"))
        {
            if !self.work_point() {
                return Err(SearchError::Unsupported);
            }
            if !hard_compatible(row, &self.context)? || !relevant(row, &self.context) {
                continue;
            }
            if self
                .result
                .budget
                .consume_candidate_text(row.text.len())
                .is_err()
            {
                break;
            }
            push_candidate(&mut self.result, row, "evidence_surface")?;
        }
        self.result.layer = RetrievalLayer::B;
        Ok(&self.result)
    }

    pub fn facets(&mut self) -> Result<&SearchResult, SearchError> {
        self.require_layer(RetrievalLayer::B)?;
        if !self.work_point() {
            return Err(SearchError::Unsupported);
        }
        self.result.candidates.retain(|candidate| {
            self.context
                .query_facets
                .condition_literals
                .iter()
                .all(|value| candidate.text.contains(value))
        });
        self.result.layer = RetrievalLayer::C;
        Ok(&self.result)
    }

    pub fn expand(
        &mut self,
        relations: &[RelationProjectionRow],
        rows: &[SearchProjectionRow],
        requested_hops: u8,
    ) -> Result<&SearchResult, SearchError> {
        self.require_layer(RetrievalLayer::C)?;
        if requested_hops > 2 {
            return Err(SearchError::Unsupported);
        }
        self.validate_search_frontier(rows)?;
        self.validate_relation_frontier(relations)?;
        let mut by_ref = BTreeMap::new();
        for row in rows.iter().filter(|row| row.row_variant == "object") {
            if !self.work_point() {
                return Err(SearchError::Unsupported);
            }
            if !hard_compatible(row, &self.context)? {
                continue;
            }
            for reference in [row.source_ref.as_deref(), row.candidate_id.as_deref()]
                .into_iter()
                .flatten()
            {
                if by_ref
                    .insert(reference, row)
                    .is_some_and(|other| other != row)
                {
                    return Err(SearchError::Unsupported);
                }
            }
        }
        let mut frontier = self
            .result
            .candidates
            .iter()
            .flat_map(|candidate| [candidate.source_ref.clone(), candidate.candidate_id.clone()])
            .collect::<BTreeSet<_>>();
        for _ in 0..requested_hops {
            if !self.work_point() {
                return Err(SearchError::Unsupported);
            }
            if self.result.budget.hops_remaining == 0 {
                break;
            }
            self.result.budget.hops_remaining -= 1;
            let mut targets = BTreeSet::new();
            for edge in relations {
                if !self.work_point() {
                    return Err(SearchError::Unsupported);
                }
                if edge.relation_kind.as_deref().is_some_and(relation_allowed)
                    && edge
                        .source_id
                        .as_ref()
                        .is_some_and(|source| frontier.contains(source))
                {
                    targets.extend(edge.target_id.clone());
                }
            }
            frontier.clear();
            for target in targets {
                if !self.work_point() {
                    return Err(SearchError::Unsupported);
                }
                let Some(row) = by_ref.get(target.as_str()) else {
                    continue;
                };
                if !hard_compatible(row, &self.context)? {
                    continue;
                }
                if self
                    .result
                    .budget
                    .consume_candidate_text(row.text.len())
                    .is_err()
                {
                    break;
                }
                if let Some(reference) = row.source_ref.clone() {
                    frontier.insert(reference);
                }
                if let Some(reference) = row.candidate_id.clone() {
                    frontier.insert(reference);
                }
                push_candidate(&mut self.result, row, "typed_relation")?;
            }
        }
        self.result.layer = RetrievalLayer::D;
        self.generation_one_exact_refs = Some(exact_refs(&self.result));
        Ok(&self.result)
    }

    pub fn named_gap(
        &mut self,
        gap: Option<&NamedGap>,
        rows: &[SearchProjectionRow],
    ) -> Result<&SearchResult, SearchError> {
        self.named_gaps(&gap.into_iter().cloned().collect::<Vec<_>>(), rows)
    }

    pub fn named_gaps(
        &mut self,
        gaps: &[NamedGap],
        rows: &[SearchProjectionRow],
    ) -> Result<&SearchResult, SearchError> {
        self.require_layer(RetrievalLayer::D)?;
        self.validate_search_frontier(rows)?;
        let [gap] = gaps else {
            return Err(SearchError::Unsupported);
        };
        gap.validate()?;
        if self.followed_up
            || self.result.budget.follow_ups_remaining == 0
            || !self.work_point()
            || matches!(gap.kind, NamedGapKind::AllowlistedRelationSlot)
        {
            return Err(SearchError::Unsupported);
        }
        let mut matches = Vec::new();
        for row in rows {
            if !self.work_point() {
                return Err(SearchError::Unsupported);
            }
            if match gap.kind {
                NamedGapKind::ExactIdentifier => {
                    row.candidate_id.as_deref() == Some(gap.identifier.as_str())
                }
                NamedGapKind::StableObjectId => {
                    row.row_variant == "object"
                        && row.currentness.as_deref() == Some("current")
                        && row.source_ref.as_deref() == Some(gap.identifier.as_str())
                }
                NamedGapKind::AllowlistedRelationSlot => false,
            } {
                matches.push(row);
            }
        }
        let [row] = matches.as_slice() else {
            return Err(SearchError::Unsupported);
        };
        if !hard_compatible(row, &self.context)? {
            return Err(SearchError::Unsupported);
        }
        let candidate_id = row.candidate_id.as_ref().ok_or(SearchError::Corrupt)?;
        let exact_boundary = self
            .generation_one_exact_refs
            .as_ref()
            .ok_or(SearchError::Unsupported)?;
        if exact_boundary.contains(candidate_id) {
            return Err(SearchError::Unsupported);
        }
        self.result.budget.consume_candidate_text(row.text.len())?;
        push_candidate(&mut self.result, row, "named_gap_follow_up")?;
        self.result.budget.follow_ups_remaining -= 1;
        self.followed_up = true;
        self.result.layer = RetrievalLayer::E;
        Ok(&self.result)
    }

    pub fn grounded_view(
        &mut self,
        unresolved_gaps: Vec<NamedGap>,
    ) -> Result<GroundedEvidenceView, SearchError> {
        if !matches!(self.result.layer, RetrievalLayer::D | RetrievalLayer::E) {
            return Err(SearchError::Unsupported);
        }
        if !self.work_point() {
            return Err(SearchError::Unsupported);
        }
        let mut candidate_refs = BTreeSet::new();
        for index in 0..self.result.candidates.len() {
            if !self.work_point() {
                return Err(SearchError::Unsupported);
            }
            let candidate = &self.result.candidates[index];
            candidate_refs.insert(candidate.candidate_id.clone());
        }
        let added_candidate_refs = if self.result.layer == RetrievalLayer::E {
            self.result
                .candidates
                .iter()
                .filter(|candidate| candidate.retrieval_origins.contains("named_gap_follow_up"))
                .map(|candidate| candidate.candidate_id.clone())
                .collect()
        } else {
            BTreeSet::new()
        };
        if self.result.layer == RetrievalLayer::E && added_candidate_refs.len() != 1 {
            return Err(SearchError::Unsupported);
        }
        let base_candidate_refs = candidate_refs
            .difference(&added_candidate_refs)
            .cloned()
            .collect::<BTreeSet<_>>();
        let conflicts = self
            .result
            .candidates
            .iter()
            .filter(|candidate| candidate.conflicted)
            .map(|candidate| candidate.candidate_id.clone())
            .collect::<BTreeSet<_>>();
        let completeness = if self.result.completeness == RetrievalCompleteness::Complete
            && (!unresolved_gaps.is_empty()
                || !conflicts.is_empty()
                || !self.result.omitted_refs.is_empty())
        {
            RetrievalCompleteness::Partial
        } else {
            self.result.completeness
        };
        let mut active_evidence = Vec::with_capacity(self.result.candidates.len());
        for index in 0..self.result.candidates.len() {
            if !self.work_point() {
                return Err(SearchError::Unsupported);
            }
            let candidate = &self.result.candidates[index];
            active_evidence.push(GroundedStatement {
                statement: candidate.text.clone(),
                support_refs: BTreeSet::from([candidate.candidate_id.clone()]),
                derivation_kind: DerivationKind::Quoted,
                ordering_basis: OrderingBasis::Unknown,
                content_trust: "untrusted_source_content".into(),
                instruction_authority: "none".into(),
            });
        }
        let view = GroundedEvidenceView {
            candidate_set: CandidateBoundary {
                generation: if self.result.layer == RetrievalLayer::E {
                    2
                } else {
                    1
                },
                base_candidate_refs,
                added_candidate_refs,
                candidate_refs,
            },
            active_evidence,
            unresolved_gaps,
            conflicts,
            completeness,
            omitted_refs: self.result.omitted_refs.clone(),
        };
        view.validate()?;
        Ok(view)
    }

    fn require_layer(&self, layer: RetrievalLayer) -> Result<(), SearchError> {
        if self.result.layer == layer {
            Ok(())
        } else {
            Err(SearchError::Unsupported)
        }
    }

    fn work_point(&mut self) -> bool {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .map(|value| u64::try_from(value.as_micros()).unwrap_or(u64::MAX))
            .unwrap_or(0)
            .min(self.result.budget.latency_us_remaining);
        self.result.budget.latency_us_remaining = remaining;
        if remaining > 0 && self.result.budget.consume_latency(1).is_ok() {
            return true;
        }
        self.result.budget.latency_us_remaining = 0;
        self.result.completeness = RetrievalCompleteness::Unknown;
        self.result
            .degraded_reasons
            .insert("diagnostic_deadline_exhausted".into());
        false
    }

    fn validate_search_frontier(
        &mut self,
        rows: &[SearchProjectionRow],
    ) -> Result<(), SearchError> {
        let mut row_ids = BTreeSet::new();
        let mut checkpoints = 0usize;
        for row in rows {
            if !self.work_point() {
                return Err(SearchError::Unsupported);
            }
            row.validate().map_err(|_| SearchError::Corrupt)?;
            if !row_ids.insert(row.row_id.as_str()) || row.source_event_seq > self.frontier {
                return Err(SearchError::Unsupported);
            }
            if row.row_id == SEARCH_CHECKPOINT_ID {
                checkpoints += 1;
                if row.source_event_seq != self.frontier {
                    return Err(SearchError::Unsupported);
                }
            }
        }
        if checkpoints != 1 {
            return Err(SearchError::Unsupported);
        }
        Ok(())
    }

    fn validate_relation_frontier(
        &mut self,
        rows: &[RelationProjectionRow],
    ) -> Result<(), SearchError> {
        let mut row_ids = BTreeSet::new();
        let mut checkpoints = 0usize;
        for row in rows {
            if !self.work_point() {
                return Err(SearchError::Unsupported);
            }
            row.validate().map_err(|_| SearchError::Corrupt)?;
            if !row_ids.insert(row.row_id.as_str()) || row.source_event_seq > self.frontier {
                return Err(SearchError::Unsupported);
            }
            if row.row_id == RELATIONS_CHECKPOINT_ID {
                checkpoints += 1;
                if row.source_event_seq != self.frontier {
                    return Err(SearchError::Unsupported);
                }
            }
        }
        if checkpoints != 1 {
            return Err(SearchError::Unsupported);
        }
        Ok(())
    }
}

fn push_candidate(
    result: &mut SearchResult,
    row: &SearchProjectionRow,
    origin: &str,
) -> Result<(), SearchError> {
    let candidate_id = row.candidate_id.clone().ok_or(SearchError::Corrupt)?;
    if result
        .candidates
        .iter()
        .any(|candidate| candidate.candidate_id == candidate_id)
    {
        return Ok(());
    }
    result.candidates.push(SearchCandidate {
        candidate_id,
        source_ref: row.source_ref.clone().ok_or(SearchError::Corrupt)?,
        row_variant: match row.row_variant.as_str() {
            "object" => evertrace_domain::query::SearchCandidateVariant::Object,
            "evidence_surface" => evertrace_domain::query::SearchCandidateVariant::EvidenceSurface,
            _ => return Err(SearchError::Corrupt),
        },
        object_kind: row.object_kind.clone(),
        text: row.text.clone(),
        source_role: row.source_role.clone(),
        content_trust: row.content_trust.clone(),
        capture_completeness: row.capture_completeness.clone(),
        retrieval_origins: BTreeSet::from([origin.into()]),
        instruction_authority: "none".into(),
        conflicted: false,
    });
    Ok(())
}

fn exact_refs(result: &SearchResult) -> BTreeSet<String> {
    result
        .candidates
        .iter()
        .map(|candidate| candidate.candidate_id.clone())
        .collect()
}

fn relevant(row: &SearchProjectionRow, context: &SearchContext) -> bool {
    row.text.contains(&context.raw_query)
        || context
            .query_facets
            .exact_identifiers
            .iter()
            .any(|value| row.text.contains(value))
        || context
            .query_facets
            .condition_literals
            .iter()
            .any(|value| row.text.contains(value))
}

fn relation_allowed(kind: &str) -> bool {
    matches!(
        kind,
        "task_contains_workstream"
            | "workstream_parent"
            | "workstream_dependency"
            | "attempt_to_task"
            | "attempt_to_workstream"
            | "atom_supports"
            | "atom_contradicts"
            | "atom_supersedes"
    )
}
