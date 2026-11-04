//! Request-local production retrieval. All channels borrow one native snapshot;
//! this does not consume the characterization session or create another index.
use std::collections::BTreeSet;

use evertrace_domain::query::*;
use evertrace_store::{SearchHardFilter, SearchProjectionRow, SearchSnapshot};

use super::{
    SearchError,
    production::{RequestDeadline, hard_compatible},
};

// Only the evidence FTS tier uses this preference; it is neither a grant nor
// a truth/authority upgrade. Existing exact and normative candidates stay first.
fn preferred_evidence_filter(
    context: &SearchContext,
    filter: &SearchHardFilter,
) -> Option<SearchHardFilter> {
    if context.unverified_hard_constraint() {
        return None;
    }
    let (roles, trust): (&[&str], &str) = match context.query_facets.statement_role {
        StatementRole::ObservedSymptom => (&["tool", "host"], "observed"),
        StatementRole::DesiredOutcome | StatementRole::ExplicitConstraint => {
            (&["user"], "user_statement")
        }
        _ => return None,
    };
    if filter
        .source_role
        .as_deref()
        .is_some_and(|role| !roles.contains(&role))
    {
        return None;
    }
    let mut preferred = filter.clone();
    preferred.source_roles = roles.iter().map(|role| (*role).to_owned()).collect();
    preferred.content_trust = Some(trust.into());
    // Soft provenance priority must not consume the pool with rows that cannot
    // satisfy the answer. The general tier still preserves relation bridges.
    preferred
        .condition_literals
        .extend(context.query_facets.condition_literals.iter().cloned());
    Some(preferred)
}

pub(super) struct NativeRetrieval<'a> {
    pub snapshot: &'a SearchSnapshot,
    pub context: &'a SearchContext,
    pub result: SearchResult,
    pub objects: SearchHardFilter,
    pub evidence: Option<SearchHardFilter>,
    pub deadline: &'a RequestDeadline,
    pub semantics: Option<&'a super::resolution::SemanticSearchResolution>,
    pub sequence_scope: Option<&'a super::SourceSequenceScope>,
    pub time_scope: Option<&'a super::TemporalReadScope<'a>>,
}

impl NativeRetrieval<'_> {
    fn degraded(&mut self, reason: &str) {
        self.result.degraded_reasons.insert(reason.into());
    }
    fn remaining(&self) -> usize {
        self.result.budget.candidates_remaining.min(32) as usize
    }
    async fn evidence_fts(&mut self, filter: &SearchHardFilter) -> Result<(), SearchError> {
        // Retained hits occupy fetch slots, not new budget. One further hit
        // proves truncation; exact-fit duplicate hits must not invent omission.
        let retained = self
            .result
            .candidates
            .iter()
            .filter(|candidate| candidate.row_variant == SearchCandidateVariant::EvidenceSurface)
            .count();
        if self.remaining() == 0 && retained == 0 {
            self.degraded("evidence_channel_budget_exhausted");
            return Ok(());
        }
        if self.deadline.remaining().is_none() {
            self.degraded("retrieval_deadline_exhausted");
            return Ok(());
        }
        let limit = (self.remaining() + retained).min(32) + 1;
        match self
            .deadline
            .run(
                self.snapshot
                    .fts(&self.context.protected_query, filter, limit),
            )
            .await
        {
            Ok(Ok(rows)) => self.admit(rows, "evidence_fts")?,
            Ok(Err(_)) => self.degraded("evidence_fts_unavailable"),
            Err(()) => self.degraded("retrieval_deadline_exhausted"),
        }
        Ok(())
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
            if !hard_compatible(&row, self.context, self.time_scope)? {
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
            let temporal = self
                .time_scope
                .map(|scope| scope.position(&row))
                .transpose()?
                .flatten();
            let source_time = temporal
                .as_ref()
                .and_then(super::production::TemporalPosition::source);
            let validity_interval = temporal
                .as_ref()
                .and_then(super::production::TemporalPosition::validity);
            let source_sequence = self
                .sequence_scope
                .map(|scope| scope.position(&row))
                .transpose()?
                .flatten()
                .or_else(|| {
                    temporal
                        .as_ref()
                        .and_then(|position| position.sequence(&self.context.query_facets))
                });
            let time_bytes = temporal
                .as_ref()
                .map_or(0, super::production::TemporalPosition::wire_bytes)
                .saturating_add(
                    source_sequence
                        .as_ref()
                        .map_or(0, |position| position.wire_bytes()),
                );
            let mut budget = self.result.budget.clone();
            if budget
                .consume_candidate_text(row.text.len().saturating_add(time_bytes))
                .is_err()
            {
                self.result.omitted_refs.insert(id);
                self.degraded("retrieval_budget_exhausted");
                continue;
            }
            self.result.budget = budget;
            if row.retrieval_completeness != "complete" {
                self.degraded("source_retrieval_partial");
            }
            if !matches!(
                self.context.query_facets.temporal_mode,
                TemporalMode::Any | TemporalMode::Current
            ) && row.time_domain == "none"
            {
                self.degraded("temporal_provenance_unknown");
            }
            let semantic_resolution = self
                .semantics
                .and_then(|value| value.states.get(&id))
                .copied();
            self.result.candidates.push(SearchCandidate {
                source_sequence,
                source_time,
                validity_interval,
                candidate_id: id,
                source_ref: row.source_ref.ok_or(SearchError::Corrupt)?,
                row_variant: if row.row_variant == "object" {
                    SearchCandidateVariant::Object
                } else {
                    SearchCandidateVariant::EvidenceSurface
                },
                currentness: row
                    .currentness
                    .as_deref()
                    .map(str::parse)
                    .transpose()
                    .map_err(|_| SearchError::Corrupt)?,
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
                        .structured(identifiers, &filter, limit.min(32) + 1),
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
        let mut gaps = self
            .context
            .protected_facets
            .iter()
            .map(|facet| NamedGap {
                kind: NamedGapKind::ProtectedFacet,
                identifier: facet.locator(),
                changes_result: true,
            })
            .collect::<Vec<_>>();
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
        if matches!(
            self.context.query_facets.temporal_mode,
            TemporalMode::AsOf | TemporalMode::Interval
        ) {
            let unresolved = self
                .result
                .candidates
                .iter()
                .filter(|candidate| {
                    candidate
                        .temporal_match(&self.context.query_facets.temporal_qualifiers)
                        .is_none()
                })
                .map(|candidate| candidate.source_ref.clone())
                .collect::<BTreeSet<_>>();
            gaps.extend(unresolved.into_iter().map(|identifier| NamedGap {
                kind: NamedGapKind::TemporalEvidence,
                identifier,
                changes_result: true,
            }));
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
                if let Some(mut preferred) = preferred_evidence_filter(self.context, &filter) {
                    preferred.capture_completeness = Some("complete".into());
                    self.evidence_fts(&preferred).await?;
                    preferred.capture_completeness = None;
                    self.evidence_fts(&preferred).await?;
                }
                self.evidence_fts(&filter).await?;
            }
        }
        // C: preserve permission-checked bridge rows for D. Literal conditions
        // constrain answer evidence, not the existence of a connecting object.
        self.result.layer = RetrievalLayer::C;
        let facet_match = |candidate: &SearchCandidate| {
            super::resolution::active_rule(candidate)
                || (!self.context.unverified_hard_constraint()
                    && self
                        .context
                        .query_facets
                        .condition_literals
                        .iter()
                        .all(|literal| candidate.text.contains(literal)))
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
        self.pack()?;
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
                    .map(|candidate| {
                        candidate.text.len() + candidate.temporal_wire_bytes().div_ceil(2)
                    })
                    .sum();
                let temporal = self
                    .time_scope
                    .map(|scope| scope.position(&matches[0]))
                    .transpose()?
                    .flatten();
                let sequence = self
                    .sequence_scope
                    .map(|scope| scope.position(&matches[0]))
                    .transpose()?
                    .flatten()
                    .or_else(|| {
                        temporal
                            .as_ref()
                            .and_then(|position| position.sequence(&self.context.query_facets))
                    });
                let metadata_bytes = temporal
                    .as_ref()
                    .map_or(0, super::production::TemporalPosition::wire_bytes)
                    .saturating_add(
                        sequence
                            .as_ref()
                            .map_or(0, SourceSequencePosition::wire_bytes),
                    );
                let delta_bytes = matches[0].text.len().min(512) + metadata_bytes.div_ceil(2);
                if bytes + delta_bytes <= self.answer_text_limit() {
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
        self.pack()?;
        self.check_temporal_completeness();
        let still_missing = self.gaps(&witnessed);
        let mut gaps = pending_gaps
            .into_iter()
            .filter(|gap| still_missing.contains(gap))
            .collect::<Vec<_>>();
        for gap in still_missing {
            if gap.kind == NamedGapKind::TemporalEvidence && !gaps.contains(&gap) {
                gaps.push(gap);
            }
        }
        let mut projected = Vec::new();
        let mut answer_bytes = self
            .result
            .candidates
            .iter()
            .map(|candidate| candidate.text.len() * 2 + candidate.temporal_wire_bytes())
            .sum::<usize>();
        let answer_limit = self.answer_text_limit() * 2;
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
                let statement = serde_json::to_string(&GroundedRelationStatement {
                    relation_kind: kind.clone(),
                    source_ref: source_ref.clone(),
                    target_ref: target_ref.clone(),
                    frontier: self.result.projection_frontier,
                })
                .map_err(|_| SearchError::Corrupt)?;
                if answer_bytes + statement.len() > answer_limit {
                    self.degraded("relation_trace_pack_budget_exhausted");
                    continue;
                }
                answer_bytes += statement.len();
                let role = EvidenceRole::for_relation(&kind).ok_or(SearchError::Corrupt)?;
                let ordering_basis = role.ordering_basis();
                projected.push((
                    GroundedStatement {
                        statement,
                        support_refs: BTreeSet::from([source_ref, target_ref]),
                        derivation_kind: DerivationKind::DeterministicDerived,
                        ordering_basis,
                        content_trust: "untrusted_source_content".into(),
                        instruction_authority: "none".into(),
                    },
                    role,
                    kind,
                ));
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
        let mut active_evidence = Vec::new();
        let mut trace = Vec::new();
        let mut matching_constraints = BTreeSet::new();
        let mut quoted_candidates = self.result.candidates.iter().collect::<Vec<_>>();
        let time_order = (self.context.query_facets.answer_shape == Some(AnswerShape::Timeline))
            .then(|| timeline_order(&self.result.candidates))
            .flatten();
        let ordering_basis = time_order.as_ref().map(|(basis, _)| *basis);
        if let Some((_, ordered)) = time_order {
            quoted_candidates = ordered;
        }
        for candidate in quoted_candidates {
            let rule = super::resolution::active_rule(candidate);
            let compatible = !self.context.unverified_hard_constraint()
                && self
                    .context
                    .query_facets
                    .condition_literals
                    .iter()
                    .all(|literal| candidate.text.contains(literal));
            if !rule && !compatible {
                continue;
            }
            let role = if rule {
                EvidenceRole::ConstraintSupport
            } else if candidate.temporal_match(&self.context.query_facets.temporal_qualifiers)
                == Some(false)
            {
                EvidenceRole::Contrast
            } else if candidate.retrieval_origins.len() == 1
                && candidate.retrieval_origins.contains("typed_relation")
            {
                EvidenceRole::Bridge
            } else {
                EvidenceRole::Direct
            };
            if rule
                && compatible
                && candidate.temporal_match(&self.context.query_facets.temporal_qualifiers)
                    != Some(false)
            {
                matching_constraints.insert(active_evidence.len() as u32);
            }
            trace.push(GroundedTraceStep {
                role,
                statement_index: active_evidence.len() as u32,
                relation: None,
            });
            active_evidence.push(GroundedStatement {
                statement: candidate.text.clone(),
                support_refs: BTreeSet::from([candidate.candidate_id.clone()]),
                derivation_kind: DerivationKind::Quoted,
                ordering_basis: ordering_basis.unwrap_or_else(|| {
                    if self.context.query_facets.temporal_mode == TemporalMode::Sequence
                        && candidate.source_sequence.is_some()
                    {
                        OrderingBasis::SourceSequence
                    } else {
                        OrderingBasis::Unknown
                    }
                }),
                content_trust: "untrusted_source_content".into(),
                instruction_authority: "none".into(),
            });
        }
        for (statement, role, relation) in projected {
            trace.push(GroundedTraceStep {
                role,
                statement_index: active_evidence.len() as u32,
                relation: Some(relation),
            });
            active_evidence.push(statement);
        }
        let mut view = GroundedEvidenceView {
            candidate_count: None,
            evidence_need: EvidenceNeed::from_context(self.context),
            candidate_set: CandidateBoundary {
                generation: if added.is_empty() { 1 } else { 2 },
                base_candidate_refs: base,
                added_candidate_refs: added,
                candidate_refs: refs,
            },
            trace,
            active_evidence,
            unresolved_gaps: gaps,
            conflicts,
            completeness: self.result.completeness,
            omitted_refs: self.result.omitted_refs.clone(),
        };
        view.candidate_count =
            view.derive_candidate_count(&self.result.candidates, &matching_constraints);
        view.validate_at_frontier(self.result.projection_frontier)?;
        Ok(HumanSearchPage {
            result: self.result,
            grounded_view: Some(view),
        })
    }
    fn output_limit(&self) -> usize {
        if self.context.query_facets.count_unit().is_some() {
            // Count has one answer; display pagination must not define its operands.
            return 32;
        }
        self.context
            .query_facets
            .quantity_constraints
            .iter()
            .filter_map(|constraint| match constraint {
                QuantityConstraint::ResultLimit { limit } => Some(*limit as usize),
                QuantityConstraint::DistinctCount { .. } => None,
            })
            .min()
            .unwrap_or(32)
            .min(32)
    }
    fn answer_text_limit(&self) -> usize {
        // A quote occurs twice; metadata and the count operator occur once.
        2400 - if self.context.query_facets.count_unit().is_some() {
            MAX_GROUNDED_COUNT_BYTES / 2
        } else {
            0
        }
    }

    fn pack(&mut self) -> Result<(), SearchError> {
        if self.context.unverified_hard_constraint() {
            self.result
                .candidates
                .retain(super::resolution::active_rule);
            self.result.omitted_refs.retain(|reference| {
                self.semantics.is_some_and(|semantics| {
                    semantics.states.get(reference)
                        == Some(&evertrace_domain::semantic::SemanticResolution::Normative(
                            evertrace_domain::semantic::NormativeResolutionState::Active,
                        ))
                })
            });
        }
        let limit = self.output_limit();
        let text_limit = self.answer_text_limit();
        let mut bytes: usize = 0;
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
            let time_bytes = candidate.temporal_wire_bytes().div_ceil(2);
            let candidate_bytes = candidate.text.len().saturating_add(time_bytes);
            if kept.len() >= limit || bytes.saturating_add(candidate_bytes) > text_limit {
                self.result.omitted_refs.insert(candidate.candidate_id);
                self.degraded("answer_pack_budget_exhausted");
            } else {
                bytes += candidate_bytes;
                kept.push(candidate);
            }
        }
        self.result.candidates = kept;
        if self.sequence_scope.is_none()
            && self.context.query_facets.answer_shape == Some(AnswerShape::Timeline)
            && self.context.query_facets.temporal_qualifiers.is_empty()
            && let Some(scope) = self.time_scope
        {
            scope.align_sequence_domain(&mut self.result.candidates, self.deadline)?;
        }
        Ok(())
    }

    fn check_temporal_completeness(&mut self) {
        let sequence_order = self.context.query_facets.answer_shape == Some(AnswerShape::Timeline)
            && matches!(
                timeline_order(&self.result.candidates),
                Some((OrderingBasis::SourceSequence, _))
            );
        let coverage_complete = self.sequence_scope.map_or_else(
            || {
                self.result.candidates.iter().all(|candidate| {
                    candidate
                        .source_sequence
                        .as_ref()
                        .is_some_and(|position| position.coverage_complete)
                })
            },
            |scope| scope.coverage_complete,
        );
        if (self.sequence_scope.is_some() || sequence_order) && !coverage_complete {
            self.degraded("source_sequence_coverage_unverified");
        } else if matches!(
            self.context.query_facets.temporal_mode,
            TemporalMode::AsOf | TemporalMode::Interval
        ) && self.result.candidates.iter().any(|candidate| {
            candidate
                .temporal_match(&self.context.query_facets.temporal_qualifiers)
                .is_none()
        }) {
            let reason = if self.time_scope.is_some_and(|scope| !scope.source_domain) {
                "validity_interval_unverified"
            } else {
                "event_clock_provenance_unverified"
            };
            self.degraded(reason);
        }
        match self.context.query_facets.answer_shape {
            Some(AnswerShape::Count) if self.context.query_facets.count_unit().is_none() => {
                self.degraded("count_unit_unspecified")
            }
            Some(AnswerShape::Timeline) => match timeline_order(&self.result.candidates) {
                Some((OrderingBasis::RecordedAtFallback, _)) => {
                    self.degraded("recorded_at_fallback")
                }
                Some(_) => {}
                None => self.degraded("timeline_ordering_unavailable"),
            },
            _ => {}
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
