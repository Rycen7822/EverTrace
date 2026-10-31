//! Request-local production retrieval. All channels borrow one native snapshot;
//! this does not consume the characterization session or create another index.
use std::collections::BTreeSet;

use evertrace_domain::query::*;
use evertrace_store::{SearchHardFilter, SearchProjectionRow, SearchSnapshot};

use super::{
    SearchError,
    production::{RequestDeadline, hard_compatible},
};

fn relation_allowed(kind: &str) -> bool {
    matches!(
        kind,
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
            | "atom_supports"
            | "atom_contradicts"
            | "atom_supersedes"
    )
}

pub(super) struct NativeRetrieval<'a> {
    pub snapshot: &'a SearchSnapshot,
    pub context: &'a SearchContext,
    pub result: SearchResult,
    pub objects: SearchHardFilter,
    pub evidence: Option<SearchHardFilter>,
    pub deadline: &'a RequestDeadline,
    pub semantics: Option<&'a super::resolution::SemanticSearchResolution>,
}

impl NativeRetrieval<'_> {
    fn degraded(&mut self, reason: &str) {
        self.result.degraded_reasons.insert(reason.into());
    }
    fn remaining(&self) -> usize {
        self.result.budget.candidates_remaining.min(32) as usize
    }
    fn references(&self) -> BTreeSet<String> {
        self.result
            .candidates
            .iter()
            .flat_map(|candidate| [candidate.candidate_id.clone(), candidate.source_ref.clone()])
            .collect()
    }
    fn admit(&mut self, rows: Vec<SearchProjectionRow>, origin: &str) -> Result<(), SearchError> {
        for row in rows {
            if !hard_compatible(&row, self.context)? {
                continue;
            }
            let id = row.candidate_id.clone().ok_or(SearchError::Corrupt)?;
            if let Some(candidate) = self
                .result
                .candidates
                .iter_mut()
                .find(|value| value.candidate_id == id)
            {
                candidate.retrieval_origins.insert(origin.into());
                continue;
            }
            if self.deadline.remaining().is_none() {
                self.degraded("retrieval_deadline_exhausted");
                break;
            }
            let mut budget = self.result.budget.clone();
            if budget.consume_candidate_text(row.text.len()).is_err() {
                self.result.omitted_refs.insert(id);
                self.degraded("retrieval_budget_exhausted");
                continue;
            }
            self.result.budget = budget;
            if row.retrieval_completeness != "complete" {
                self.degraded("source_retrieval_partial");
            }
            if self.context.query_facets.temporal_mode != TemporalMode::Any
                && row.time_domain == "none"
            {
                self.degraded("temporal_provenance_unknown");
            }
            let semantic_resolution = self
                .semantics
                .and_then(|value| value.states.get(&id))
                .copied();
            self.result.candidates.push(SearchCandidate {
                candidate_id: id,
                source_ref: row.source_ref.ok_or(SearchError::Corrupt)?,
                row_variant: if row.row_variant == "object" {
                    SearchCandidateVariant::Object
                } else {
                    SearchCandidateVariant::EvidenceSurface
                },
                object_kind: row.object_kind,
                text: row.text,
                source_role: row.source_role,
                content_trust: row.content_trust,
                capture_completeness: row.capture_completeness,
                retrieval_origins: BTreeSet::from([origin.into()]),
                instruction_authority: "none".into(),
                conflicted: semantic_resolution
                    == Some(evertrace_domain::semantic::SemanticResolution::Descriptive(
                        evertrace_domain::semantic::DescriptiveResolutionState::Disputed,
                    )),
                semantic_resolution,
            });
        }
        Ok(())
    }
    async fn lookup(&mut self, identifiers: &[String], origin: &str) -> Result<(), SearchError> {
        let limit = self.remaining();
        if limit == 0 {
            self.degraded("retrieval_budget_exhausted");
            return Ok(());
        }
        let mut filters = vec![self.objects.clone()];
        if let Some(filter) = &self.evidence {
            filters.push(filter.clone());
        }
        for filter in filters {
            let limit = self.remaining();
            if limit == 0 {
                self.degraded("retrieval_budget_exhausted");
                break;
            }
            match self
                .deadline
                .run(
                    self.snapshot
                        .structured(identifiers, &filter, limit.min(32)),
                )
                .await
            {
                Ok(Ok(rows)) => self.admit(rows, origin)?,
                Ok(Err(_)) => self.degraded("structured_channel_unavailable"),
                Err(()) => self.degraded("retrieval_deadline_exhausted"),
            }
        }
        Ok(())
    }
    fn gaps(&self, witnessed: &BTreeSet<String>) -> Vec<NamedGap> {
        let mut gaps = Vec::new();
        for anchor in &self.context.query_facets.target_anchors {
            if !self.result.candidates.iter().any(|candidate| {
                candidate.candidate_id == *anchor || candidate.source_ref == *anchor
            }) {
                gaps.push(NamedGap {
                    kind: NamedGapKind::StableObjectId,
                    identifier: anchor.clone(),
                    changes_result: true,
                });
            }
        }
        for identifier in &self.context.query_facets.exact_identifiers {
            if self
                .context
                .query_facets
                .target_anchors
                .contains(identifier)
            {
                continue;
            }
            if !self.result.candidates.iter().any(|candidate| {
                candidate.candidate_id == *identifier
                    || candidate.source_ref == *identifier
                    || candidate.text.contains(identifier)
            }) {
                gaps.push(NamedGap {
                    kind: NamedGapKind::ExactIdentifier,
                    identifier: identifier.clone(),
                    changes_result: true,
                });
            }
        }
        for kind in &self.context.query_facets.relation_requirements {
            if relation_allowed(kind) && !witnessed.contains(kind) {
                gaps.push(NamedGap {
                    kind: NamedGapKind::AllowlistedRelationSlot,
                    identifier: kind.clone(),
                    changes_result: true,
                });
            }
        }
        gaps
    }
    pub(super) async fn run(mut self) -> Result<HumanSearchPage, SearchError> {
        if self.result.completeness == RetrievalCompleteness::Unknown {
            return Ok(HumanSearchPage {
                result: self.result,
                grounded_view: None,
            });
        }
        // B: original EvidenceSurface, not object metadata relabelled as evidence.
        self.result.layer = RetrievalLayer::B;
        if let Some(filter) = self.evidence.clone() {
            let limit = self.remaining();
            if limit == 0 {
                self.degraded("evidence_channel_budget_exhausted");
            } else {
                match self
                    .deadline
                    .run(self.snapshot.structured(
                        &self.context.query_facets.exact_identifiers,
                        &filter,
                        limit,
                    ))
                    .await
                {
                    Ok(Ok(rows)) => self.admit(rows, "evidence_exact")?,
                    Ok(Err(_)) => self.degraded("evidence_structured_unavailable"),
                    Err(()) => self.degraded("retrieval_deadline_exhausted"),
                }
                let limit = self.remaining();
                if limit > 0 {
                    match self
                        .deadline
                        .run(self.snapshot.fts(&self.context.raw_query, &filter, limit))
                        .await
                    {
                        Ok(Ok(rows)) => self.admit(rows, "evidence_fts")?,
                        Ok(Err(_)) => self.degraded("evidence_fts_unavailable"),
                        Err(()) => self.degraded("retrieval_deadline_exhausted"),
                    }
                }
            }
        }
        // C: preserve permission-checked bridge rows for D. Literal conditions
        // constrain answer evidence, not the existence of a connecting object.
        self.result.layer = RetrievalLayer::C;
        let facet_match = |candidate: &SearchCandidate| {
            super::resolution::active_rule(candidate)
                || self
                    .context
                    .query_facets
                    .condition_literals
                    .iter()
                    .all(|literal| candidate.text.contains(literal))
        };
        if self.context.query_facets.relation_requirements.is_empty() {
            self.result.candidates.retain(facet_match);
        }
        let kinds = self.context.query_facets.relation_requirements.clone();
        if kinds.iter().any(|kind| !relation_allowed(kind)) {
            self.degraded("relation_not_allowlisted");
        }
        let kinds: Vec<_> = kinds
            .into_iter()
            .filter(|kind| relation_allowed(kind))
            .collect();
        let mut witnessed = BTreeSet::new();
        let mut relation_links = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut frontier = self.references();
        self.result.layer = RetrievalLayer::D;
        for _ in 0..self.result.budget.hops_remaining {
            if kinds.is_empty() || frontier.is_empty() {
                break;
            }
            if self.remaining() == 0 {
                self.degraded("relation_candidate_budget_exhausted");
                break;
            }
            self.result.budget.hops_remaining -= 1;
            let sources: Vec<_> = frontier.difference(&visited).take(64).cloned().collect();
            visited.extend(sources.iter().cloned());
            let edges = match self
                .deadline
                .run(self.snapshot.adjacent_relations(&sources, &kinds, 65))
                .await
            {
                Ok(Ok(Some(rows))) => rows,
                Ok(Ok(None)) => return Ok(self.invalidated("canonical_frontier_changed")),
                Ok(Err(_)) => {
                    self.degraded("relation_channel_unavailable");
                    break;
                }
                Err(()) => {
                    self.degraded("retrieval_deadline_exhausted");
                    break;
                }
            };
            if edges.len() > 64 {
                self.degraded("relation_fanout_truncated");
            }
            let edges: Vec<_> = edges.into_iter().take(64).collect();
            let targets = edges
                .iter()
                .filter_map(|edge| {
                    if edge
                        .source_id
                        .as_ref()
                        .is_some_and(|id| sources.contains(id))
                    {
                        edge.target_id.clone()
                    } else {
                        edge.source_id.clone()
                    }
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            self.lookup(&targets, "typed_relation").await?;
            let refs = self.references();
            for edge in &edges {
                if edge.source_id.as_ref().is_some_and(|id| refs.contains(id))
                    && edge.target_id.as_ref().is_some_and(|id| refs.contains(id))
                {
                    if let Some(kind) = &edge.relation_kind {
                        witnessed.insert(kind.clone());
                        relation_links.insert((
                            edge.source_id.clone().ok_or(SearchError::Corrupt)?,
                            edge.target_id.clone().ok_or(SearchError::Corrupt)?,
                            kind.clone(),
                        ));
                    }
                    if edge.relation_kind.as_deref() == Some("atom_contradicts") {
                        for candidate in &mut self.result.candidates {
                            if [edge.source_id.as_ref(), edge.target_id.as_ref()]
                                .into_iter()
                                .flatten()
                                .any(|id| {
                                    id == &candidate.candidate_id || id == &candidate.source_ref
                                })
                            {
                                candidate.conflicted = true;
                            }
                        }
                    }
                }
            }
            frontier = refs.difference(&visited).cloned().collect();
        }
        // Required slots refer to original rows, never gaps invented by snippet truncation.
        let pending_gaps = self.gaps(&witnessed);
        // Freeze generation 1 after D, before the one named, result-changing gap.
        self.pack();
        let base: BTreeSet<_> = self
            .result
            .candidates
            .iter()
            .map(|candidate| candidate.candidate_id.clone())
            .collect();
        let mut added = BTreeSet::new();
        if let [gap] = pending_gaps.as_slice()
            && gap.kind == NamedGapKind::ExactIdentifier
            && self.result.budget.follow_ups_remaining > 0
            && self.remaining() >= (if self.evidence.is_some() { 4 } else { 2 })
            && self.result.candidates.len() < self.output_limit()
        {
            self.result.budget.follow_ups_remaining -= 1;
            let mut matches = Vec::new();
            let mut filters = vec![self.objects.clone()];
            if let Some(filter) = &self.evidence {
                filters.push(filter.clone());
            }
            for mut filter in filters {
                filter
                    .condition_literals
                    .extend(self.context.query_facets.condition_literals.iter().cloned());
                filter.condition_literals.push(gap.identifier.clone());
                match self
                    .deadline
                    .run(
                        self.snapshot
                            .fts(&gap.identifier, &filter, self.remaining().min(2)),
                    )
                    .await
                {
                    Ok(Ok(rows)) => matches.extend(rows),
                    Ok(Err(_)) => self.degraded("named_gap_channel_unavailable"),
                    Err(()) => self.degraded("retrieval_deadline_exhausted"),
                }
            }
            matches.sort_by(|a, b| a.candidate_id.cmp(&b.candidate_id));
            matches.dedup_by(|a, b| a.candidate_id == b.candidate_id);
            matches.retain(|row| {
                row.candidate_id
                    .as_ref()
                    .is_some_and(|id| !base.contains(id))
                    && self
                        .context
                        .query_facets
                        .condition_literals
                        .iter()
                        .all(|literal| row.text.contains(literal))
            });
            if matches.len() == 1 {
                // Do not admit a candidate if packaging would alter the frozen base.
                let bytes: usize = self
                    .result
                    .candidates
                    .iter()
                    .map(|candidate| candidate.text.len())
                    .sum();
                if bytes + matches[0].text.len().min(512) <= 2400 {
                    self.admit(matches, "named_exact_gap")?;
                    added = self
                        .result
                        .candidates
                        .iter()
                        .map(|candidate| candidate.candidate_id.clone())
                        .filter(|id| !base.contains(id))
                        .collect();
                    if added.len() == 1 {
                        self.result.layer = RetrievalLayer::E;
                    }
                } else {
                    self.degraded("answer_pack_budget_exhausted");
                }
            } else if matches.len() > 1 {
                // Ambiguity consumes the same original inspection budget even
                // though none of these rows enters generation 2.
                for row in matches {
                    if self
                        .result
                        .budget
                        .consume_candidate_text(row.text.len())
                        .is_err()
                    {
                        self.result.budget.candidates_remaining = 0;
                        self.result.budget.tokens_remaining = 0;
                        self.degraded("named_gap_budget_exhausted");
                        break;
                    }
                }
                self.degraded("named_gap_ambiguous");
            }
        }
        self.pack();
        let still_missing = self.gaps(&witnessed);
        let gaps = pending_gaps
            .into_iter()
            .filter(|gap| still_missing.contains(gap))
            .collect::<Vec<_>>();
        let mut projected = Vec::new();
        let mut answer_bytes = self
            .result
            .candidates
            .iter()
            .map(|candidate| candidate.text.len() * 2)
            .sum::<usize>();
        for (source, target, kind) in relation_links {
            let resolve = |reference: &str| {
                let mut matches = self.result.candidates.iter().filter(|candidate| {
                    candidate.candidate_id == reference || candidate.source_ref == reference
                });
                let first = matches.next()?;
                matches.next().is_none().then(|| first.candidate_id.clone())
            };
            let endpoints = (resolve(&source), resolve(&target));
            if let (Some(source_ref), Some(target_ref)) = endpoints {
                let statement = serde_json::json!({
                    "relation_kind": kind,
                    "source_ref": source_ref,
                    "target_ref": target_ref,
                    "frontier": self.result.projection_frontier,
                })
                .to_string();
                if answer_bytes + statement.len() > 4800 {
                    self.degraded("relation_trace_pack_budget_exhausted");
                    continue;
                }
                answer_bytes += statement.len();
                projected.push(GroundedStatement {
                    statement,
                    support_refs: BTreeSet::from([source_ref, target_ref]),
                    derivation_kind: DerivationKind::DeterministicDerived,
                    ordering_basis: OrderingBasis::Unknown,
                    content_trust: "untrusted_source_content".into(),
                    instruction_authority: "none".into(),
                });
            } else {
                self.degraded("relation_endpoint_omitted_or_ambiguous");
            }
        }
        let conflicts: BTreeSet<_> = self
            .result
            .candidates
            .iter()
            .filter(|candidate| candidate.conflicted)
            .map(|candidate| candidate.candidate_id.clone())
            .collect();
        if !conflicts.is_empty() {
            self.result.completeness = RetrievalCompleteness::Conflicted;
        } else if self.result.completeness != RetrievalCompleteness::Complete
            || !gaps.is_empty()
            || !self.result.omitted_refs.is_empty()
            || !self.result.degraded_reasons.is_empty()
        {
            self.result.completeness = RetrievalCompleteness::Partial;
        }
        match self.deadline.run(self.snapshot.is_current()).await {
            Ok(Ok(true)) => {}
            _ => return Ok(self.invalidated("canonical_frontier_changed")),
        }
        self.result.budget.latency_us_remaining =
            self.deadline.remaining().map_or(0, |remaining| {
                u64::try_from(remaining.as_micros()).unwrap_or(u64::MAX)
            });
        let refs = self
            .result
            .candidates
            .iter()
            .map(|candidate| candidate.candidate_id.clone())
            .collect();
        let view = GroundedEvidenceView {
            candidate_set: CandidateBoundary {
                generation: if added.is_empty() { 1 } else { 2 },
                base_candidate_refs: base,
                added_candidate_refs: added,
                candidate_refs: refs,
            },
            active_evidence: self
                .result
                .candidates
                .iter()
                .filter(|candidate| {
                    super::resolution::active_rule(candidate)
                        || self
                            .context
                            .query_facets
                            .condition_literals
                            .iter()
                            .all(|literal| candidate.text.contains(literal))
                })
                .map(|candidate| GroundedStatement {
                    statement: candidate.text.clone(),
                    support_refs: BTreeSet::from([candidate.candidate_id.clone()]),
                    derivation_kind: DerivationKind::Quoted,
                    ordering_basis: OrderingBasis::Unknown,
                    content_trust: "untrusted_source_content".into(),
                    instruction_authority: "none".into(),
                })
                .chain(projected)
                .collect(),
            unresolved_gaps: gaps,
            conflicts,
            completeness: self.result.completeness,
            omitted_refs: self.result.omitted_refs.clone(),
        };
        view.validate()?;
        Ok(HumanSearchPage {
            result: self.result,
            grounded_view: Some(view),
        })
    }
    fn output_limit(&self) -> usize {
        self.context
            .query_facets
            .quantity_constraints
            .iter()
            .map(|constraint| match constraint {
                QuantityConstraint::ResultLimit { limit } => *limit as usize,
            })
            .min()
            .unwrap_or(32)
            .min(32)
    }
    fn pack(&mut self) {
        let limit = self.output_limit();
        let mut bytes = 0;
        let mut kept = Vec::new();
        for mut candidate in std::mem::take(&mut self.result.candidates) {
            if candidate.text.len() > 512 {
                let mut end = 509;
                while !candidate.text.is_char_boundary(end) {
                    end -= 1;
                }
                candidate.text.truncate(end);
                candidate.text.push('…');
                self.degraded("source_snippet_truncated");
            }
            if kept.len() >= limit || bytes + candidate.text.len() > 2400 {
                self.result.omitted_refs.insert(candidate.candidate_id);
                self.degraded("answer_pack_budget_exhausted");
            } else {
                bytes += candidate.text.len();
                kept.push(candidate);
            }
        }
        self.result.candidates = kept;
        if self.context.query_facets.temporal_mode != TemporalMode::Any
            || !self.context.query_facets.temporal_qualifiers.is_empty()
        {
            self.degraded("ordering_provenance_not_verified");
        }
        if matches!(
            self.context.query_facets.answer_shape,
            Some(AnswerShape::Count | AnswerShape::Timeline)
        ) {
            self.degraded("answer_shape_not_derived");
        }
    }
    fn invalidated(mut self, reason: &str) -> HumanSearchPage {
        self.result.candidates.clear();
        self.result.omitted_refs.clear();
        self.result.completeness = RetrievalCompleteness::Unknown;
        self.degraded(reason);
        HumanSearchPage {
            result: self.result,
            grounded_view: None,
        }
    }
}
