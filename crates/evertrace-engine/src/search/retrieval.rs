//! Request-local production retrieval. All channels use the same canonical frontier.
use std::collections::{BTreeMap, BTreeSet};

use evertrace_domain::error::ErrorCode;
use evertrace_domain::query::*;
use evertrace_store::{
    SearchHardFilter, SearchIndex, SearchProjectionRow, SearchSnapshot, search::RelationDirection,
};

use super::{
    SearchError,
    production::{
        RelationSources, RequestDeadline, candidate_limit, exact_query_reference,
        exact_slot_primary, hard_compatible, identifier_only_comparison,
    },
    read_context::{ATTEMPT_RUN_RELATION, RUN_RESULT_RELATION, SearchReadAccess},
};

pub(super) struct ScopedCandidateRead<'a> {
    pub index: &'a SearchIndex,
    pub access: &'a SearchReadAccess<'a>,
    pub checks_remaining: usize,
}

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

#[derive(Clone, Copy)]
pub(super) enum ExactEvidence {
    Lexical,
    Counted,
    Ordered,
}

pub(super) struct NativeRetrieval<'a> {
    pub context: &'a SearchContext,
    pub result: SearchResult,
    pub objects: SearchHardFilter,
    pub evidence: Option<SearchHardFilter>,
    pub deadline: &'a RequestDeadline,
    pub semantics: Option<&'a super::resolution::SemanticSearchResolution>,
    pub sequence_scope: Option<&'a super::SourceSequenceScope>,
    pub time_scope: Option<&'a super::TemporalReadScope<'a>>,
    pub relation_sources: Option<RelationSources<'a>>,
    pub relation_read: Option<&'a super::read_context::RelationRead>,
    pub include_hit_window: bool,
}

fn snippet_end(text: &str) -> usize {
    if text.len() <= 512 {
        return text.len();
    }
    text.floor_char_boundary(512 - '…'.len_utf8())
}

fn exact_excerpt(text: &str, identifier: &str) -> Option<String> {
    let offset = text.find(identifier)?;
    let capacity = 512 - 2 * '…'.len_utf8();
    let padding = capacity.checked_sub(identifier.len())? / 2;
    let start = text.ceil_char_boundary(offset.saturating_sub(padding));
    let end = text.floor_char_boundary((start + capacity).min(text.len()));
    let slice = text.get(start..end)?;
    if !slice.contains(identifier) {
        return None;
    }
    let leading = if start == 0 { "" } else { "…" };
    let trailing = if end == text.len() { "" } else { "…" };
    Some(format!("{leading}{slice}{trailing}"))
}

impl NativeRetrieval<'_> {
    fn degraded(&mut self, reason: &str) {
        self.result.degraded_reasons.insert(reason.into());
    }
    fn remaining(&self) -> usize {
        self.result.budget.candidates_remaining.min(32) as usize
    }
    async fn evidence_fts(
        &mut self,
        snapshot: &SearchSnapshot,
        text: &str,
        filter: &SearchHardFilter,
    ) -> Result<(), SearchError> {
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
        match self.deadline.run(snapshot.fts(text, filter, limit)).await {
            Ok(Ok(rows)) => self.admit(rows, "evidence_fts")?,
            Ok(Err(_)) => self.degraded("evidence_fts_unavailable"),
            Err(()) => self.degraded("retrieval_deadline_exhausted"),
        }
        Ok(())
    }
    fn references(&self) -> BTreeSet<String> {
        let mut references = BTreeSet::new();
        for candidate in &self.result.candidates {
            references.insert(candidate.candidate_id.clone());
            if candidate.matches_reference(&candidate.source_ref) {
                references.insert(candidate.source_ref.clone());
            }
        }
        references
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
            let revision_order = temporal
                .as_ref()
                .and_then(super::production::TemporalPosition::revision_order);
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
                revision_order,
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
    async fn lookup_relation_targets(
        &mut self,
        snapshot: &SearchSnapshot,
        identifiers: &[String],
        canonical_targets: &[String],
    ) -> Result<(), SearchError> {
        let sources = match (self.objects.readable_refs.as_ref(), self.relation_sources) {
            (Some(refs), Some(read)) if !canonical_targets.is_empty() => {
                match read(canonical_targets, refs) {
                    Ok(sources) => sources,
                    Err(_) => {
                        self.degraded("relation_source_unavailable");
                        Vec::new()
                    }
                }
            }
            _ => Vec::new(),
        };
        for (filter, sources) in [
            (Some(self.objects.clone()), sources.as_slice()),
            (self.evidence.clone(), &[]),
        ] {
            let Some(filter) = filter else { continue };
            let limit = self.remaining();
            if limit == 0 {
                if identifiers.iter().any(|id| {
                    !self
                        .result
                        .candidates
                        .iter()
                        .any(|candidate| candidate.candidate_id == *id)
                }) {
                    self.degraded("retrieval_budget_exhausted");
                }
                break;
            }
            match self
                .deadline
                .run(snapshot.structured_with_sources(identifiers, &filter, limit + 1, sources))
                .await
            {
                Ok(Ok(rows)) => self.admit(rows, "typed_relation")?,
                Ok(Err(_)) => self.degraded("structured_channel_unavailable"),
                Err(()) => self.degraded("retrieval_deadline_exhausted"),
            }
        }
        Ok(())
    }
    async fn admit_scoped_targets(
        &mut self,
        snapshot: SearchSnapshot,
        access: &mut ScopedCandidateRead<'_>,
        targets: Vec<String>,
    ) -> Result<Option<SearchSnapshot>, SearchError> {
        let targets: Vec<_> = targets
            .into_iter()
            .filter(|target| {
                !self
                    .result
                    .candidates
                    .iter()
                    .any(|item| item.matches_reference(target))
            })
            .collect();
        if targets.is_empty() {
            return Ok(Some(snapshot));
        }
        let mut filter = self.objects.clone();
        filter.object_kind = Some("atom_revision".into());
        filter.object_access = None; // The exact neighbors below need their own live grant.
        let cap = access.checks_remaining;
        let rows = match self
            .deadline
            .run(snapshot.structured(&targets, &filter, cap + 1))
            .await
        {
            Ok(Ok(rows)) => rows,
            Ok(Err(_)) => {
                self.degraded("relation_target_channel_unavailable");
                return Ok(Some(snapshot));
            }
            Err(()) => {
                self.degraded("retrieval_deadline_exhausted");
                return Ok(Some(snapshot));
            }
        };
        if rows.len() > cap {
            self.degraded("search_access_window_exhausted");
        }
        let Some((snapshot, admitted)) = self
            .scope_rows(snapshot, access, rows.into_iter().take(cap).collect())
            .await?
        else {
            return Ok(None);
        };
        self.admit(admitted, "typed_relation")?;
        Ok(Some(snapshot))
    }

    async fn scope_rows(
        &mut self,
        snapshot: SearchSnapshot,
        access: &mut ScopedCandidateRead<'_>,
        rows: Vec<SearchProjectionRow>,
    ) -> Result<Option<(SearchSnapshot, Vec<SearchProjectionRow>)>, SearchError> {
        if rows.len() > access.checks_remaining {
            self.degraded("search_access_window_exhausted");
            return Ok(Some((snapshot, Vec::new())));
        }
        if rows.is_empty() {
            return Ok(Some((snapshot, rows)));
        }
        // Live source admission itself takes a reader. Never wait for it while holding the index lease.
        let frontier = snapshot.frontier();
        drop(snapshot);
        let mut admitted = Vec::new();
        for row in rows {
            access.checks_remaining -= 1;
            let source = row.source_ref.as_deref().ok_or(SearchError::Corrupt)?;
            let verified = if row.row_variant == "evidence_surface" {
                access.access.check_evidence(source).await
            } else if row.object_kind.as_deref() == Some("atom_revision") {
                let revision = row.candidate_id.as_deref().ok_or(SearchError::Corrupt)?;
                if self.objects.current_only {
                    access
                        .access
                        .check_current(source, revision, "atom_revision")
                        .await
                } else {
                    access.access.check_revision(revision).await
                }
            } else {
                return Err(SearchError::Corrupt);
            };
            match verified {
                Ok(()) => admitted.push(row),
                Err(ErrorCode::Untrusted) => self.degraded("source_read_restricted"),
                Err(_) => self.degraded("search_access_unavailable"),
            }
            if self.deadline.remaining().is_none() {
                return Ok(None);
            }
        }
        let Ok(Ok(snapshot)) = self
            .deadline
            .run(access.index.snapshot_after_validated_frontier(frontier))
            .await
        else {
            return Ok(None);
        };
        if snapshot.frontier() != frontier || snapshot.authoritative_frontier() != frontier {
            return Ok(None);
        }
        Ok(Some((snapshot, admitted)))
    }

    fn gaps(
        &self,
        witnessed: &BTreeSet<String>,
        clipped_exact: &BTreeMap<String, BTreeSet<String>>,
    ) -> Vec<NamedGap> {
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
        let facets = &self.context.query_facets;
        let references = facets
            .target_anchors
            .iter()
            .map(String::as_str)
            .chain(exact_query_reference(self.context))
            .chain(
                facets
                    .exact_identifiers
                    .iter()
                    .map(String::as_str)
                    .filter(|id| valid_target_reference(id)),
            )
            .collect::<BTreeSet<_>>();
        for reference in references {
            if !self
                .result
                .candidates
                .iter()
                .any(|candidate| candidate.matches_reference(reference))
            {
                gaps.push(NamedGap {
                    kind: NamedGapKind::StableObjectId,
                    identifier: reference.to_owned(),
                    changes_result: true,
                });
            }
        }
        for identifier in facets
            .exact_identifiers
            .iter()
            .filter(|id| !valid_target_reference(id))
        {
            if !self.result.candidates.iter().any(|candidate| {
                candidate.matches_reference(identifier)
                    || candidate.text.contains(identifier)
                    || clipped_exact
                        .get(identifier)
                        .is_some_and(|refs| refs.contains(&candidate.candidate_id))
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
        if self
            .context
            .query_facets
            .temporal_mode
            .has_temporal_predicate()
            && !self
                .context
                .query_facets
                .temporal_qualifiers
                .iter()
                .any(|qualifier| qualifier.source_sequence_ref().is_some())
        {
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
        if let Some((endpoint, _)) = self.time_scope.and_then(|scope| {
            scope.missing_revision_bridge(&self.result.candidates, &self.deadline)
        }) {
            gaps.push(NamedGap {
                kind: NamedGapKind::TemporalEvidence,
                identifier: endpoint.to_owned(),
                changes_result: true,
            });
        }
        gaps
    }

    pub(super) async fn read_exact_evidence(
        &mut self,
        snapshot: &SearchSnapshot,
        identifiers: &[String],
        selection: ExactEvidence,
    ) -> Result<(), SearchError> {
        self.result.layer = RetrievalLayer::B;
        if let Some(filter) = self.evidence.as_ref() {
            let limit = self.remaining();
            if limit == 0 {
                self.degraded("evidence_channel_budget_exhausted");
            } else {
                match self
                    .deadline
                    .run(snapshot.structured(
                        identifiers,
                        filter,
                        limit + usize::from(!matches!(selection, ExactEvidence::Lexical)),
                    ))
                    .await
                {
                    Ok(Ok(mut rows)) => {
                        if rows.len() > limit {
                            self.degraded("evidence_channel_budget_exhausted");
                            return Ok(()); // A prefix cannot prove that a requested source resolves uniquely.
                        }
                        if matches!(selection, ExactEvidence::Ordered) {
                            let ambiguous: Vec<_> = identifiers
                                .iter()
                                .filter(|id| {
                                    rows.iter()
                                        .filter(|row| {
                                            row.candidate_id.as_ref() == Some(*id)
                                                || row.source_ref.as_ref() == Some(*id)
                                        })
                                        .nth(1)
                                        .is_some()
                                })
                                .collect();
                            if !ambiguous.is_empty() {
                                self.degraded("temporal_operand_ambiguous");
                                rows.retain(|row| {
                                    !ambiguous.iter().any(|id| {
                                        row.candidate_id.as_ref() == Some(*id)
                                            || row.source_ref.as_ref() == Some(*id)
                                    })
                                });
                            }
                        }
                        self.admit(rows, "evidence_exact")?;
                    }
                    Ok(Err(_)) => self.degraded("evidence_structured_unavailable"),
                    Err(()) => self.degraded("retrieval_deadline_exhausted"),
                }
            }
        }
        Ok(())
    }

    pub(super) async fn read_evidence(
        &mut self,
        snapshot: &SearchSnapshot,
        text: &str,
        identifiers: &[String],
    ) -> Result<(), SearchError> {
        // B: original EvidenceSurface, not object metadata relabelled as evidence.
        if identifier_only_comparison(self.context) {
            return self
                .read_exact_evidence(
                    snapshot,
                    &self.context.query_facets.target_anchors,
                    ExactEvidence::Ordered,
                )
                .await;
        }
        if let Some(reference) = exact_query_reference(self.context) {
            let mut identifiers = identifiers.to_vec();
            identifiers.push(reference.to_owned());
            return self
                .read_exact_evidence(snapshot, &identifiers, ExactEvidence::Lexical)
                .await;
        }
        let had_room = self.remaining() != 0;
        self.read_exact_evidence(snapshot, identifiers, ExactEvidence::Lexical)
            .await?;
        if had_room && let Some(filter) = self.evidence.clone() {
            if let Some(mut preferred) = preferred_evidence_filter(self.context, &filter) {
                preferred.capture_completeness = Some("complete".into());
                self.evidence_fts(snapshot, text, &preferred).await?;
                preferred.capture_completeness = None;
                self.evidence_fts(snapshot, text, &preferred).await?;
            }
            self.evidence_fts(snapshot, text, &filter).await?;
        }
        Ok(())
    }

    pub(super) async fn run(
        mut self,
        snapshot: SearchSnapshot,
    ) -> Result<HumanSearchPage, SearchError> {
        if self.result.completeness == RetrievalCompleteness::Unknown {
            return Ok(HumanSearchPage {
                result: self.result,
                grounded_view: None,
                hit_window: None,
                hit_page: None,
            });
        }
        if self
            .sequence_scope
            .is_none_or(|scope| scope.source_prefix_ranges.is_none())
        {
            self.read_evidence(
                &snapshot,
                exact_slot_primary(self.context),
                &self.context.query_facets.exact_identifiers,
            )
            .await?;
        }
        self.finish(snapshot, None).await
    }

    pub(super) async fn finish(
        mut self,
        mut snapshot: SearchSnapshot,
        mut access: Option<ScopedCandidateRead<'_>>,
    ) -> Result<HumanSearchPage, SearchError> {
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
        let mut kinds = self.context.query_facets.relation_requirements.clone();
        if matches!(
            self.context.query_facets.answer_shape,
            Some(AnswerShape::Latest | AnswerShape::TemporalComparison)
        ) && self
            .result
            .candidates
            .iter()
            .any(|candidate| candidate.object_kind.as_deref() == Some("atom_revision"))
        {
            // Latest must not ignore an explicit contradiction while choosing an update.
            for (kind, needed) in [
                (
                    super::ATOM_SUPERSEDES,
                    self.context.query_facets.temporal_qualifiers.is_empty()
                        || requested_ordering(&self.context.query_facets.temporal_qualifiers)
                            == Some(TemporalOrdering::Supersession),
                ),
                ("atom_contradicts", true),
            ] {
                if needed && !kinds.iter().any(|existing| existing == kind) {
                    kinds.push(kind.into());
                }
            }
        }
        if kinds.is_empty() {
            self.result.candidates.retain(facet_match);
        }
        if kinds.iter().any(|kind| !relation_allowed(kind)) {
            self.degraded("relation_not_allowlisted");
        }
        let kinds: Vec<_> = kinds
            .into_iter()
            .filter(|kind| relation_allowed(kind))
            .collect();
        let persisted_kinds = kinds
            .iter()
            .filter(|kind| {
                !super::read_context::LINEAGE_RELATIONS.contains(&kind.as_str())
                    && !matches!(
                        kind.as_str(),
                        SNAPSHOT_VERIFICATION_RESULT
                            | evertrace_domain::query::SUCCESSOR_SUPPORT_CONTRACT
                            | evertrace_domain::query::SUPPORT_CONTRACT_EVIDENCE
                    )
            })
            .cloned()
            .collect::<Vec<_>>();
        // A historical predecessor request follows declared updates backwards in time,
        // not every revision that happens to point to the same operand.
        let predecessors = self.context.intent == SearchIntent::HistoryLookup
            && !self.objects.current_only
            && !self.context.query_facets.target_anchors.is_empty()
            && kinds.as_slice() == [super::ATOM_SUPERSEDES];
        let direction = if predecessors {
            RelationDirection::Outgoing
        } else {
            RelationDirection::Adjacent
        };
        let mut relation_links = BTreeSet::new();
        let mut incomplete = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut frontier = self.references();
        if predecessors {
            // Independent constraints may be displayed but are not roots of this history.
            frontier.retain(|id| self.context.query_facets.target_anchors.contains(id));
        }
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
            let mut edges = match self
                .deadline
                .run(snapshot.adjacent_relations(&sources, &persisted_kinds, direction, 65))
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
            if let Some(read) = self.relation_read {
                edges.extend(
                    read.edges
                        .iter()
                        .filter(|edge| sources.contains(&edge.0) && kinds.contains(&edge.2))
                        .map(|(source, target, kind)| {
                            evertrace_store::relations::RelationProjectionRow::edge(
                                kind,
                                snapshot.frontier(),
                                source.clone(),
                                target.clone(),
                            )
                        }),
                );
            }
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
            // These current inverse endpoints have no FTS row; historical reads never resolve today's alias.
            let canonical_targets = if self.objects.current_only {
                edges
                    .iter()
                    .filter_map(|edge| {
                        (matches!(
                            edge.relation_kind.as_deref(),
                            Some("episode_to_workstream" | "binding_to_scope_effect")
                        ) && edge
                            .target_id
                            .as_ref()
                            .is_some_and(|id| sources.contains(id)))
                        .then(|| edge.source_id.clone())
                        .flatten()
                    })
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            if let Some(access) = access.as_mut() {
                let Some(reopened) = self.admit_scoped_targets(snapshot, access, targets).await?
                else {
                    return Ok(self.invalidated("canonical_frontier_changed"));
                };
                snapshot = reopened;
            } else {
                self.lookup_relation_targets(&snapshot, &targets, &canonical_targets)
                    .await?;
            }
            let refs = self.references();
            for edge in &edges {
                if edge.source_id.as_ref().is_some_and(|id| refs.contains(id))
                    && edge.target_id.as_ref().is_some_and(|id| refs.contains(id))
                {
                    if let Some(kind) = &edge.relation_kind {
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
                } else if let Some(kind) = &edge.relation_kind {
                    if access.is_some()
                        || matches!(kind.as_str(), ATTEMPT_RUN_RELATION | RUN_RESULT_RELATION)
                    {
                        incomplete.insert(kind.clone());
                    }
                }
            }
            frontier = if predecessors {
                edges
                    .into_iter()
                    .filter_map(|edge| edge.target_id)
                    .filter(|target| refs.contains(target) && !visited.contains(target))
                    .collect()
            } else {
                refs.difference(&visited).cloned().collect()
            };
        }
        if kinds.iter().any(|kind| kind == RUN_RESULT_RELATION) {
            let verified_runs: BTreeSet<_> = relation_links
                .iter()
                .filter_map(|(_, run, kind)| (kind == RUN_RESULT_RELATION).then_some(run))
                .collect();
            if relation_links
                .iter()
                .any(|(run, _, kind)| kind == ATTEMPT_RUN_RELATION && !verified_runs.contains(run))
            {
                incomplete.insert(RUN_RESULT_RELATION.into());
            }
        }
        let revision_bridge = self.time_scope.and_then(|scope| {
            scope.missing_revision_bridge(&self.result.candidates, &self.deadline)
        });
        // The hit stream is independent of display and quote packing; GEV keeps its own compact base.
        let mut hit_window = self.include_hit_window.then(Vec::new);
        let mut clipped_exact = BTreeMap::new();
        self.pack(&mut clipped_exact, hit_window.as_mut())?;
        // A slot is supported only if every admitted edge of that kind fits in the reply.
        let mut witnessed = BTreeSet::new();
        let mut projected = Vec::new();
        let candidate_bytes: usize = self
            .result
            .candidates
            .iter()
            .map(|candidate| candidate.text.len() * 2 + candidate.temporal_wire_bytes())
            .sum::<usize>();
        let answer_limit = self.answer_text_limit() * 2;
        let mut relation_bytes = 0usize;
        for (source, target, kind) in relation_links {
            let exact_support = matches!(
                kind.as_str(),
                evertrace_domain::query::SUCCESSOR_SUPPORT_CONTRACT
                    | evertrace_domain::query::SUPPORT_CONTRACT_EVIDENCE
            );
            let resolve = |reference: &str| {
                let mut matches = self.result.candidates.iter().filter(|candidate| {
                    if exact_support {
                        candidate.candidate_id == reference
                    } else {
                        candidate.matches_reference(reference)
                    }
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
                if candidate_bytes + relation_bytes + statement.len() > answer_limit {
                    incomplete.insert(kind);
                    self.degraded("relation_trace_pack_budget_exhausted");
                    continue;
                }
                relation_bytes += statement.len();
                let role = EvidenceRole::for_relation(&kind).ok_or(SearchError::Corrupt)?;
                let ordering_basis = role.ordering_basis();
                witnessed.insert(kind.clone());
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
                incomplete.insert(kind);
                self.degraded("relation_endpoint_omitted_or_ambiguous");
            }
        }
        if let Some(read) = self.relation_read {
            incomplete.extend(read.missing.iter().map(|kind| (*kind).to_owned()));
        }
        if incomplete.contains(ATTEMPT_RUN_RELATION)
            && kinds.iter().any(|kind| kind == RUN_RESULT_RELATION)
        {
            incomplete.insert(RUN_RESULT_RELATION.into());
        }
        witnessed.retain(|kind| !incomplete.contains(kind));
        let pending_gaps = self.gaps(&witnessed, &clipped_exact);
        let base: BTreeSet<_> = self
            .result
            .candidates
            .iter()
            .map(|candidate| candidate.candidate_id.clone())
            .collect();
        let mut added = BTreeSet::new();
        let mut follow_up_gap = None;
        if let [gap] = pending_gaps.as_slice()
            && (gap.kind == NamedGapKind::ExactIdentifier
                || (gap.kind == NamedGapKind::TemporalEvidence
                    && revision_bridge.is_some_and(|(endpoint, _)| endpoint == gap.identifier)
                    && self.result.budget.hops_remaining >= 2))
            && gap.validate_follow_up().is_ok()
            // Packing must not manufacture a missing operand or a unique delta.
            && (hit_window.is_none() || self.result.omitted_refs.is_empty())
            && self.result.budget.follow_ups_remaining > 0
            && access.as_ref().is_none_or(|access| {
                access.checks_remaining >= 2
                    && ![
                        "search_access_window_exhausted",
                        "search_access_unavailable",
                        "source_read_restricted",
                    ]
                    .iter()
                    .any(|reason| self.result.degraded_reasons.contains(*reason))
            })
            && self.remaining()
                >= (if access.is_none()
                    && gap.kind == NamedGapKind::ExactIdentifier
                    && self.evidence.is_some()
                {
                    4
                } else {
                    2
                })
            && self.result.candidates.len() < self.output_limit()
        {
            self.result.budget.follow_ups_remaining -= 1;
            let revision_witnesses = (gap.kind == NamedGapKind::TemporalEvidence)
                .then(|| revision_bridge.map(|(_, witnesses)| witnesses))
                .flatten();
            let identifiers =
                revision_witnesses.map(|witnesses| witnesses.iter().cloned().collect::<Vec<_>>());
            let mut matches = Vec::new();
            let mut complete_lookup = true;
            let mut objects = self.objects.clone();
            if access.is_some() {
                // Scoped E may discover new rows only in native channels with a live admission check.
                objects.object_kind = Some("atom_revision".into());
                objects.object_access = None;
            }
            let evidence = self.evidence.clone().map(|mut filter| {
                if access.is_some() {
                    filter.readable_refs = None; // Admit any newly discovered source before interpretation.
                }
                filter
            });
            for mut filter in revision_witnesses
                .is_none()
                .then_some(objects)
                .into_iter()
                .chain(evidence)
            {
                if identifiers.is_none() {
                    filter
                        .condition_literals
                        .extend(self.context.query_facets.condition_literals.iter().cloned());
                    filter.condition_literals.push(gap.identifier.clone());
                }
                // These refs attest one immutable revision, not competing fact entities.
                let limit = if identifiers.is_some() {
                    1
                } else {
                    self.remaining().min(2)
                };
                let lookup = async {
                    if let Some(identifiers) = &identifiers {
                        snapshot.structured(identifiers, &filter, limit).await
                    } else {
                        snapshot.fts(&gap.identifier, &filter, limit).await
                    }
                };
                match self.deadline.run(lookup).await {
                    Ok(Ok(rows)) => matches.extend(rows),
                    Ok(Err(_)) => {
                        complete_lookup = false;
                        self.degraded("named_gap_channel_unavailable");
                    }
                    Err(()) => {
                        complete_lookup = false;
                        self.degraded("retrieval_deadline_exhausted");
                    }
                }
            }
            matches.sort_by(|a, b| a.candidate_id.cmp(&b.candidate_id));
            matches.dedup_by(|a, b| a.candidate_id == b.candidate_id);
            matches.retain(|row| {
                row.candidate_id
                    .as_ref()
                    .is_some_and(|id| !base.contains(id))
                    && if let Some(witnesses) = revision_witnesses {
                        row.source_ref
                            .as_ref()
                            .is_some_and(|reference| witnesses.contains(reference))
                    } else {
                        self.context
                            .query_facets
                            .condition_literals
                            .iter()
                            .all(|literal| row.text.contains(literal))
                    }
            });
            if !complete_lookup {
                matches.clear();
            }
            if let Some(access) = access.as_mut() {
                let offered = matches.len();
                let Some((reopened, allowed)) = self.scope_rows(snapshot, access, matches).await?
                else {
                    return Ok(self.invalidated("canonical_frontier_changed"));
                };
                snapshot = reopened;
                // A restricted or unverified hit cannot prove uniqueness of the answer.
                matches = if allowed.len() == offered {
                    allowed
                } else {
                    Vec::new()
                };
            }
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
                let text = &matches[0].text;
                let needs_excerpt = gap.kind == NamedGapKind::ExactIdentifier
                    && !text[..snippet_end(text)].contains(&gap.identifier);
                let excerpt = needs_excerpt
                    .then(|| exact_excerpt(text, &gap.identifier))
                    .flatten()
                    .filter(|quote| {
                        self.context
                            .query_facets
                            .condition_literals
                            .iter()
                            .all(|literal| quote.contains(literal))
                    });
                let snippet_bytes = excerpt
                    .as_ref()
                    .map_or_else(|| text.len().min(512), String::len);
                let delta_bytes = snippet_bytes + metadata_bytes.div_ceil(2);
                let trigger_bytes = serde_json::to_vec(gap)
                    .map_err(|_| SearchError::Corrupt)?
                    .len()
                    + 17;
                if needs_excerpt && excerpt.is_none() {
                    self.degraded("named_gap_witness_clipped");
                } else if bytes + delta_bytes + (relation_bytes + trigger_bytes).div_ceil(2)
                    <= self.answer_text_limit()
                {
                    self.admit(matches, "named_exact_gap")?;
                    added = self
                        .result
                        .candidates
                        .iter()
                        .map(|candidate| candidate.candidate_id.clone())
                        .filter(|id| !base.contains(id))
                        .collect();
                    if added.len() == 1 {
                        if let Some(excerpt) = excerpt
                            && let Some(last) = self.result.candidates.last_mut()
                        {
                            last.text = excerpt;
                            self.degraded("source_snippet_truncated");
                        }
                        follow_up_gap = Some(gap.clone());
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
        self.pack(&mut clipped_exact, None)?;
        if let Some(scope) = self.time_scope {
            scope.align_revision_domain(
                &mut self.result.candidates,
                &self.context.query_facets,
                &mut self.result.budget,
                &self.deadline,
            )?;
        }
        self.check_temporal_completeness();
        let gaps = self.gaps(&witnessed, &clipped_exact);
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
        match self.deadline.run(snapshot.is_current()).await {
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
        let qualifiers = &self.context.query_facets.temporal_qualifiers;
        let timeline = self.context.query_facets.answer_shape == Some(AnswerShape::Timeline);
        let time_order = timeline
            .then(|| timeline_order(&self.result.candidates, qualifiers))
            .flatten();
        let ordering_basis = time_order.as_ref().map(|(basis, _)| *basis);
        let mut quoted_candidates = self.result.candidates.iter().collect::<Vec<_>>();
        if let Some((_, mut ordered)) = time_order {
            ordered.extend(
                quoted_candidates
                    .into_iter()
                    .filter(|candidate| candidate.is_source_order_context(qualifiers)),
            );
            quoted_candidates = ordered;
        }
        for candidate in quoted_candidates {
            if candidate.object_kind.as_deref() == Some("wiki_projection") {
                continue; // A compiled navigation page is not a direct evidence statement.
            }
            let rule = super::resolution::active_rule(candidate);
            let compatible = !self.context.unverified_hard_constraint()
                && self
                    .context
                    .query_facets
                    .condition_literals
                    .iter()
                    .all(|literal| candidate.text.contains(literal));
            let revision_bridge = !self.context.unverified_hard_constraint()
                && self
                    .time_scope
                    .and_then(|scope| scope.revision_bridge)
                    .is_some_and(|(_, witnesses)| witnesses.contains(&candidate.source_ref));
            if !rule && !compatible && !revision_bridge {
                continue;
            }
            let role = if rule {
                EvidenceRole::ConstraintSupport
            } else if candidate.temporal_match(&self.context.query_facets.temporal_qualifiers)
                == Some(false)
            {
                EvidenceRole::Contrast
            } else if revision_bridge
                || (candidate.retrieval_origins.len() == 1
                    && candidate.retrieval_origins.contains("typed_relation"))
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
                ordering_basis: if timeline {
                    ordering_basis
                        .filter(|_| !candidate.is_source_order_context(qualifiers))
                        .unwrap_or(OrderingBasis::Unknown)
                } else if qualifiers
                    .iter()
                    .any(|qualifier| qualifier.source_sequence_ref().is_some())
                    && candidate.source_sequence.is_some()
                {
                    OrderingBasis::SourceSequence
                } else {
                    OrderingBasis::Unknown
                },
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
            entity_list: None,
            candidate_latest: None,
            candidate_comparison: None,
            evidence_need: EvidenceNeed::from_context(self.context),
            candidate_set: CandidateBoundary {
                generation: if added.is_empty() { 1 } else { 2 },
                base_candidate_refs: base,
                added_candidate_refs: added,
                candidate_refs: refs,
            },
            follow_up_gap,
            trace,
            active_evidence,
            unresolved_gaps: gaps,
            conflicts,
            completeness: self.result.completeness,
            omitted_refs: self.result.omitted_refs.clone(),
        };
        view.entity_list = view.derive_entity_list(&self.result.candidates);
        if view.entity_list.as_ref().is_some_and(|list| list.truncated) {
            self.degraded("entity_list_budget_exhausted");
            if self.result.completeness == RetrievalCompleteness::Complete {
                self.result.completeness = RetrievalCompleteness::Partial;
                view.completeness = RetrievalCompleteness::Partial;
            }
        }
        let mut count_budget = self.result.budget.clone();
        if let Some(ranges) = self
            .sequence_scope
            .and_then(|scope| scope.source_prefix_ranges.as_ref())
            // Two u64 decimal endpoints plus JSON delimiters per authorized receipt.
            && ranges.iter().all(|_| count_budget.consume_candidate_text(44).is_ok())
            && view.set_source_prefix_count(ranges.clone())
        {
            self.result.budget = count_budget;
        } else {
            view.candidate_count =
                view.derive_candidate_count(&self.result.candidates, &matching_constraints);
        }
        let count_gaps = view.count_temporal_gaps(&self.result.candidates);
        let count_domain_unverified = view.candidate_count.as_ref().is_some_and(|count| {
            count.source_prefix_ranges.is_none()
                && (view.evidence_need.target.is_empty()
                    || (view.completeness == RetrievalCompleteness::Complete
                        && count.value.is_none()))
        });
        if count_domain_unverified {
            self.degraded("count_domain_unverified");
        }
        if !count_gaps.is_empty() || count_domain_unverified {
            if !count_gaps.is_empty() {
                self.degraded("count_temporal_evidence_unverified");
            }
            for identifier in count_gaps {
                let gap = NamedGap {
                    kind: NamedGapKind::TemporalEvidence,
                    identifier,
                    changes_result: true,
                };
                if !view.unresolved_gaps.contains(&gap) {
                    view.unresolved_gaps.push(gap);
                }
            }
            if self.result.completeness == RetrievalCompleteness::Complete {
                self.result.completeness = RetrievalCompleteness::Partial;
            }
            view.completeness = self.result.completeness;
            if let Some(count) = &mut view.candidate_count {
                count.value = None;
            }
        }
        view.candidate_latest =
            view.derive_candidate_latest(&self.result.candidates, &matching_constraints);
        if let Some(latest) = &view.candidate_latest {
            if latest.statement_indices.is_none() {
                self.degraded("latest_ordering_unavailable");
            } else if latest.ordering_basis == OrderingBasis::RecordedAtFallback {
                self.degraded("recorded_at_fallback");
            } else if !view.latest_source_coverage_complete(&self.result.candidates) {
                self.degraded("source_sequence_coverage_unverified");
            }
            if self.result.completeness == RetrievalCompleteness::Complete
                && (!self.result.degraded_reasons.is_empty() || !view.unresolved_gaps.is_empty())
            {
                self.result.completeness = RetrievalCompleteness::Partial;
            }
            view.completeness = self.result.completeness;
        }
        view.candidate_comparison =
            view.derive_candidate_comparison(&self.result.candidates, &matching_constraints);
        if view
            .candidate_comparison
            .as_ref()
            .is_some_and(|comparison| comparison.relation == TemporalComparisonRelation::Unknown)
        {
            self.degraded("temporal_comparison_unverified");
        }
        let ordering_gaps = view.ordering_temporal_gaps(&self.result.candidates);
        if !ordering_gaps.is_empty() {
            self.degraded("temporal_ordering_unverified");
            for identifier in ordering_gaps {
                let gap = NamedGap {
                    kind: NamedGapKind::TemporalEvidence,
                    identifier,
                    changes_result: true,
                };
                if !view.unresolved_gaps.contains(&gap) {
                    view.unresolved_gaps.push(gap);
                }
            }
            if self.result.completeness == RetrievalCompleteness::Complete {
                self.result.completeness = RetrievalCompleteness::Partial;
            }
            view.completeness = self.result.completeness;
        }
        view.validate_at_frontier(self.result.projection_frontier)?;
        Ok(HumanSearchPage {
            result: self.result,
            grounded_view: Some(view),
            hit_window,
            hit_page: None,
        })
    }
    fn output_limit(&self) -> usize {
        candidate_limit(&self.context.query_facets, 32) as usize
    }
    fn answer_text_limit(&self) -> usize {
        // A quote occurs twice; metadata and the typed operator occur once.
        2400 - if self.context.query_facets.answer_shape == Some(AnswerShape::TemporalComparison) {
            MAX_GROUNDED_COMPARISON_BYTES / 2
        } else if self.context.query_facets.answer_shape == Some(AnswerShape::EntityList) {
            MAX_GROUNDED_ENTITY_LIST_BYTES / 2
        } else if self.context.query_facets.answer_shape == Some(AnswerShape::Latest) {
            MAX_GROUNDED_LATEST_BYTES / 2
        } else if self.context.query_facets.count_unit().is_some() {
            MAX_GROUNDED_COUNT_BYTES / 2
        } else {
            0
        }
    }

    fn pack(
        &mut self,
        clipped_exact: &mut BTreeMap<String, BTreeSet<String>>,
        hit_window: Option<&mut Vec<HumanSearchHit>>,
    ) -> Result<(), SearchError> {
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
        if let Some(window) = hit_window {
            window.extend(
                self.result
                    .candidates
                    .iter()
                    .map(HumanSearchHit::from_candidate),
            );
        }
        let limit = self.output_limit();
        let text_limit = self.answer_text_limit();
        let mut bytes: usize = 0;
        let mut kept = Vec::new();
        for mut candidate in std::mem::take(&mut self.result.candidates) {
            let clipped = candidate.text.len() > 512;
            let end = snippet_end(&candidate.text);
            if clipped {
                self.degraded("source_snippet_truncated");
            }
            let snippet_bytes = if clipped { end + '…'.len_utf8() } else { end };
            let time_bytes = candidate.temporal_wire_bytes().div_ceil(2);
            let candidate_bytes = snippet_bytes.saturating_add(time_bytes);
            if kept.len() >= limit || bytes.saturating_add(candidate_bytes) > text_limit {
                self.result.omitted_refs.insert(candidate.candidate_id);
                self.degraded("answer_pack_budget_exhausted");
                continue;
            }
            if clipped {
                // A kept reference witnesses the full source; an omitted one cannot close the gap.
                for identifier in &self.context.query_facets.exact_identifiers {
                    if !candidate.text[..end].contains(identifier)
                        && candidate.text.contains(identifier)
                    {
                        clipped_exact
                            .entry(identifier.clone())
                            .or_default()
                            .insert(candidate.candidate_id.clone());
                    }
                }
                candidate.text.truncate(end);
                candidate.text.push('…');
            }
            bytes += candidate_bytes;
            kept.push(candidate);
        }
        self.result.candidates = kept;
        if self.sequence_scope.is_none()
            && self
                .context
                .query_facets
                .answer_shape
                .is_some_and(AnswerShape::uses_temporal_order)
            && (self.context.query_facets.temporal_qualifiers.is_empty()
                || matches!(
                    requested_ordering(&self.context.query_facets.temporal_qualifiers),
                    Some(TemporalOrdering::SourceSequence | TemporalOrdering::Supersession)
                ))
            && let Some(scope) = self.time_scope
        {
            scope.align_sequence_domain(&mut self.result.candidates, self.deadline)?;
        }
        Ok(())
    }

    fn check_temporal_completeness(&mut self) {
        let sequence_order = self.context.query_facets.answer_shape == Some(AnswerShape::Timeline)
            && matches!(
                timeline_order(
                    &self.result.candidates,
                    &self.context.query_facets.temporal_qualifiers
                ),
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
        } else if self
            .context
            .query_facets
            .temporal_mode
            .has_temporal_predicate()
            && !self
                .context
                .query_facets
                .temporal_qualifiers
                .iter()
                .any(|qualifier| qualifier.source_sequence_ref().is_some())
            && self.result.candidates.iter().any(|candidate| {
                candidate
                    .temporal_match(&self.context.query_facets.temporal_qualifiers)
                    .is_none()
            })
        {
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
            Some(AnswerShape::Timeline) => match timeline_order(
                &self.result.candidates,
                &self.context.query_facets.temporal_qualifiers,
            ) {
                Some((OrderingBasis::RecordedAtFallback, _)) => {
                    self.degraded("recorded_at_fallback")
                }
                Some((OrderingBasis::Supersession, _))
                    if self.result.candidates.iter().any(|candidate| {
                        candidate.row_variant == SearchCandidateVariant::EvidenceSurface
                            && candidate
                                .source_sequence
                                .as_ref()
                                .is_none_or(|position| !position.coverage_complete)
                    }) =>
                {
                    self.degraded("source_sequence_coverage_unverified")
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
            hit_window: None,
            hit_page: None,
        }
    }
}
