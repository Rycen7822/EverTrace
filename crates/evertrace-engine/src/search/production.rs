//! Deterministic, deletion-first production retrieval over one pinned snapshot.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use evertrace_domain::query::{
    AnswerShape, CountUnit, FacetParseStatus, HumanSearchPage, LifecycleBoundary, Polarity,
    QuantityConstraint, QueryError, RetrievalCompleteness, RetrievalLayer, ScopeBoundary,
    SearchCandidate, SearchContext, SearchResult, SourceBoundary, SuppressionSnapshot,
    TemporalMode, TemporalOrdering, TemporalQualifier, production_retrieval_layer,
    requested_ordering,
};
use evertrace_domain::{error::ErrorCode, evidence::SourceRevision};
use evertrace_store::{SearchHardFilter, SearchIndex, SearchProjectionRow, StoreError};
use thiserror::Error;

use super::retrieval::{ExactEvidence, ScopedCandidateRead};

/// One canonical source revision, resolved after the native read gate.
pub(crate) struct SourceSequenceScope {
    pub source_anchor: evertrace_domain::ids::SourceObservationId,
    pub positions: BTreeMap<String, u64>,
    pub coverage_complete: bool,
}

impl SourceSequenceScope {
    pub fn position(
        &self,
        row: &SearchProjectionRow,
    ) -> Result<Option<evertrace_domain::query::SourceSequencePosition>, SearchError> {
        if row.row_variant != "evidence_surface" {
            return Ok(None);
        }
        let sequence = self
            .positions
            .get(row.source_ref.as_deref().ok_or(SearchError::Corrupt)?)
            .ok_or(SearchError::Corrupt)?;
        if *sequence != row.source_sequence {
            return Err(SearchError::Corrupt);
        }
        Ok(Some(evertrace_domain::query::SourceSequencePosition {
            source_anchor: self.source_anchor,
            sequence: *sequence,
            coverage_complete: self.coverage_complete,
        }))
    }
}
/// Canonical metadata only; current resolver state is not recomputed at a historical clock.
pub(crate) enum TemporalPosition {
    Source {
        receipt: Box<evertrace_domain::evidence::SourceReceipt>,
        coverage_complete: bool,
        previous_revision: Option<evertrace_domain::evidence::SourceRevision>,
        revision_order: Option<evertrace_domain::query::RevisionOrderPosition>,
    },
    Object {
        validity: Option<evertrace_domain::semantic::ValidityInterval>,
        revision_order: Option<evertrace_domain::query::RevisionOrderPosition>,
        contextual: bool,
    },
}

impl TemporalPosition {
    pub fn source(&self) -> Option<evertrace_domain::query::SourceTimePosition> {
        match self {
            Self::Source { receipt: value, .. } => {
                Some(evertrace_domain::query::SourceTimePosition {
                    event_time_us: value.event_time_us,
                    recorded_at_us: value.recorded_at_us,
                    provenance: value.event_time_provenance,
                })
            }
            _ => None,
        }
    }
    pub fn sequence(
        &self,
        facets: &evertrace_domain::query::QueryFacetSet,
    ) -> Option<evertrace_domain::query::SourceSequencePosition> {
        if !facets
            .answer_shape
            .is_some_and(evertrace_domain::query::AnswerShape::uses_temporal_order)
            || (!facets.temporal_qualifiers.is_empty()
                && !matches!(
                    requested_ordering(&facets.temporal_qualifiers),
                    Some(TemporalOrdering::SourceSequence | TemporalOrdering::Supersession)
                ))
        {
            return None;
        }
        match self {
            Self::Source {
                receipt: value,
                coverage_complete,
                ..
            } => Some(evertrace_domain::query::SourceSequencePosition {
                source_anchor: value.source_observation_id,
                sequence: value.source_sequence,
                coverage_complete: *coverage_complete,
            }),
            _ => None,
        }
    }
    pub fn validity(&self) -> Option<evertrace_domain::semantic::ValidityInterval> {
        match self {
            Self::Object { validity, .. } => validity.clone(),
            _ => None,
        }
    }
    pub fn revision_order(&self) -> Option<evertrace_domain::query::RevisionOrderPosition> {
        match self {
            Self::Object { revision_order, .. } | Self::Source { revision_order, .. } => {
                revision_order.clone()
            }
        }
    }
    pub fn matches(&self, qualifiers: &[TemporalQualifier]) -> Option<bool> {
        match self {
            Self::Source { .. } => self
                .source()
                .and_then(|value| value.temporal_match(qualifiers)),
            Self::Object { validity, .. } => validity
                .as_ref()
                .and_then(|validity| evertrace_domain::query::validity_match(validity, qualifiers)),
        }
    }
    pub fn contextual(&self) -> bool {
        matches!(
            self,
            Self::Object {
                contextual: true,
                ..
            }
        )
    }
    pub fn wire_bytes(&self) -> usize {
        match self {
            Self::Source { revision_order, .. } => {
                self.source().map_or(0, |value| value.wire_bytes())
                    + revision_order
                        .as_ref()
                        .map_or(0, |value| value.wire_bytes())
            }
            Self::Object {
                validity,
                revision_order,
                ..
            } => {
                validity.as_ref().map_or(0, |value| {
                    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len() + 21)
                }) + revision_order
                    .as_ref()
                    .map_or(0, |value| value.wire_bytes())
            }
        }
    }
}

/// Borrow canonical facts at the pinned frontier; do not mirror a source/authority catalogue.
pub(crate) struct TemporalReadScope<'a> {
    /// Original endpoint and same-revision witnesses, not grants or prequalified rows.
    pub revision_bridge: Option<(&'a str, &'a BTreeSet<String>)>,
    pub frontier: u64,
    pub read: &'a (dyn Fn(&str) -> Option<TemporalPosition> + Sync),
    pub readable_refs: Option<&'a BTreeSet<String>>,
    pub source_domain: bool,
}

impl TemporalReadScope<'_> {
    pub fn position(
        &self,
        row: &SearchProjectionRow,
    ) -> Result<Option<TemporalPosition>, SearchError> {
        let reference = if row.row_variant == "evidence_surface" {
            &row.source_ref
        } else {
            &row.candidate_id
        };
        let position = (self.read)(reference.as_deref().ok_or(SearchError::Corrupt)?);
        match &position {
            Some(TemporalPosition::Source { receipt: value, .. })
                if row.row_variant == "evidence_surface" =>
            {
                if value.validate().is_err()
                    || value.event_time_us != row.event_time_us
                    || value.recorded_at_us != row.recorded_at_us
                    || value.source_sequence != row.source_sequence
                {
                    return Err(SearchError::Corrupt);
                }
            }
            Some(TemporalPosition::Object {
                validity,
                revision_order,
                ..
            }) if row.row_variant == "object" => {
                if let Some(validity) = validity {
                    if row.object_kind.as_deref() != Some("atom_revision") {
                        return Err(SearchError::Corrupt);
                    }
                    validity.validate().map_err(|_| SearchError::Corrupt)?;
                }
                if revision_order.as_ref().is_some_and(|position| {
                    row.source_ref.as_ref() != Some(&position.anchor)
                        || row.source_event_seq != position.sequence
                        || position.sequence == 0
                        || position.sequence > self.frontier
                }) {
                    return Err(SearchError::Corrupt);
                }
            }
            None if !self.source_domain || row.row_variant != "evidence_surface" => {}
            _ => return Err(SearchError::Corrupt),
        }
        Ok(position)
    }

    pub(super) fn missing_revision_bridge(
        &self,
        candidates: &[SearchCandidate],
        deadline: &RequestDeadline,
    ) -> Option<(&str, &BTreeSet<String>)> {
        let plan = self.revision_bridge?;
        let TemporalPosition::Source {
            receipt: bridge, ..
        } = (self.read)(plan.1.first()?)?
        else {
            return None;
        };
        for candidate in candidates {
            if deadline.remaining().is_none() {
                return None;
            }
            if let Some(TemporalPosition::Source { receipt, .. }) =
                (self.read)(&candidate.source_ref)
                && receipt.source_instance_id == bridge.source_instance_id
                && receipt.source_revision == bridge.source_revision
            {
                return None;
            }
        }
        Some(plan)
    }

    /// Align only returned coordinates, never filter a broad query to one source.
    pub(super) fn align_sequence_domain(
        &self,
        candidates: &mut [SearchCandidate],
        deadline: &RequestDeadline,
    ) -> Result<(), SearchError> {
        for candidate in candidates.iter_mut() {
            if let Some(position) = &mut candidate.source_sequence {
                position.source_anchor = candidate
                    .source_ref
                    .parse()
                    .map_err(|_| SearchError::Corrupt)?;
            }
        }
        let mut domains = BTreeMap::new();
        let mut members = Vec::new();
        for (index, candidate) in candidates.iter().enumerate() {
            let Some(position) = &candidate.source_sequence else {
                // Object context has no source sequence; it still cannot join a global Timeline order.
                continue;
            };
            if deadline.remaining().is_none() {
                return Ok(());
            }
            let Some(TemporalPosition::Source { receipt, .. }) = (self.read)(&candidate.source_ref)
            else {
                return Err(SearchError::Corrupt);
            };
            if receipt.source_sequence != position.sequence
                || receipt.source_observation_id != position.source_anchor
            {
                return Err(SearchError::Corrupt);
            }
            let domain = (receipt.source_instance_id, receipt.source_revision);
            let anchor = domains
                .entry(domain.clone())
                .or_insert(position.source_anchor);
            *anchor = (*anchor).min(position.source_anchor);
            members.push((index, domain));
        }
        for (index, domain) in members {
            if let Some(position) = &mut candidates[index].source_sequence {
                position.source_anchor = domains[&domain];
            }
        }
        Ok(())
    }

    pub(super) fn align_revision_domain(
        &self,
        candidates: &mut [SearchCandidate],
        facets: &evertrace_domain::query::QueryFacetSet,
        budget: &mut evertrace_domain::query::RetrievalBudget,
        deadline: &RequestDeadline,
    ) -> Result<(), SearchError> {
        let comparison =
            facets.answer_shape == Some(evertrace_domain::query::AnswerShape::TemporalComparison);
        let mut instance = None;
        let mut targets = BTreeSet::new();
        if comparison {
            if requested_ordering(&facets.temporal_qualifiers)
                != Some(TemporalOrdering::Supersession)
            {
                return Ok(());
            }
            for candidate in candidates.iter().filter(|candidate| {
                facets
                    .target_anchors
                    .iter()
                    .any(|target| candidate.matches_reference(target))
            }) {
                if deadline.remaining().is_none() {
                    return Ok(());
                }
                if candidate.revision_order.is_none() {
                    continue;
                }
                if let Some(TemporalPosition::Source { receipt, .. }) =
                    (self.read)(&candidate.source_ref)
                {
                    if instance
                        .as_ref()
                        .is_some_and(|value| value != &receipt.source_instance_id)
                    {
                        return Ok(());
                    }
                    instance = Some(receipt.source_instance_id);
                    targets.insert(receipt.source_revision);
                }
            }
            if targets.is_empty() {
                return Ok(());
            }
        }
        let mut revisions = BTreeMap::new();
        let mut members = Vec::new();
        for (index, candidate) in candidates.iter().enumerate() {
            if candidate.row_variant
                != evertrace_domain::query::SearchCandidateVariant::EvidenceSurface
                || candidate.revision_order.is_none()
            {
                continue;
            }
            if deadline.remaining().is_none() {
                return Ok(());
            }
            let Some(TemporalPosition::Source {
                receipt,
                previous_revision,
                ..
            }) = (self.read)(&candidate.source_ref)
            else {
                return Err(SearchError::Corrupt);
            };
            if instance
                .as_ref()
                .is_some_and(|value| value != &receipt.source_instance_id)
            {
                if comparison {
                    continue;
                }
                return Ok(());
            }
            instance = Some(receipt.source_instance_id);
            let revision = receipt.source_revision;
            if revisions
                .get(&revision)
                .is_some_and(|value| value != &previous_revision)
            {
                return Err(SearchError::Corrupt);
            }
            revisions.insert(revision.clone(), previous_revision);
            members.push((index, revision, receipt.source_observation_id));
        }
        if comparison {
            let Some(path) = comparison_revision_path(&revisions, &targets) else {
                return Ok(());
            };
            revisions.retain(|revision, _| path.contains(revision));
        }
        if !(1..=3).contains(&revisions.len()) {
            return Ok(());
        }
        let mut roots = revisions.iter().filter(|(_, previous)| {
            previous
                .as_ref()
                .is_none_or(|value| !revisions.contains_key(value))
        });
        let Some((root, _)) = roots.next() else {
            return Ok(());
        };
        if roots.next().is_some() {
            return Ok(());
        }
        let mut ranks = BTreeMap::from([(root.clone(), 0_u64)]);
        let mut current = root;
        for rank in 1..revisions.len() {
            let mut next = revisions
                .iter()
                .filter(|(_, previous)| previous.as_ref() == Some(current));
            let Some((revision, _)) = next.next() else {
                return Ok(());
            };
            if next.next().is_some() || ranks.contains_key(revision) {
                return Ok(());
            }
            ranks.insert(revision.clone(), rank as u64);
            current = revision;
        }
        let hops = (revisions.len() - 1) as u8;
        if deadline.remaining().is_none() || budget.hops_remaining < hops {
            return Ok(());
        }
        let anchor = members
            .iter()
            .filter(|(_, revision, _)| ranks.contains_key(revision))
            .map(|(_, _, observation)| *observation)
            .min()
            .ok_or(SearchError::Corrupt)?
            .to_string();
        for (index, revision, _) in members {
            if let Some(rank) = ranks.get(&revision) {
                candidates[index].revision_order =
                    Some(evertrace_domain::query::RevisionOrderPosition {
                        anchor: anchor.clone(),
                        sequence: *rank,
                    });
            }
        }
        budget.hops_remaining -= hops;
        Ok(())
    }
}

// Only paths already present in the frozen candidate cohort can bridge two targets.
fn comparison_revision_path(
    revisions: &BTreeMap<SourceRevision, Option<SourceRevision>>,
    targets: &BTreeSet<SourceRevision>,
) -> Option<BTreeSet<SourceRevision>> {
    if !(1..=2).contains(&targets.len()) {
        return None;
    }
    let mut selected = None;
    for head in targets {
        let mut current = head;
        let mut path = BTreeSet::from([head.clone()]);
        for depth in 0..=2 {
            if targets.is_subset(&path) {
                if selected.is_some() {
                    return None;
                }
                selected = Some(path);
                break;
            }
            if depth == 2 {
                break;
            }
            let Some(previous) = revisions.get(current).and_then(Option::as_ref) else {
                break;
            };
            if !revisions.contains_key(previous) || !path.insert(previous.clone()) {
                break;
            }
            current = previous;
        }
    }
    selected
}

pub(crate) type RelationSources<'a> = &'a (
        dyn Fn(&[String], &BTreeSet<String>) -> Result<Vec<SearchProjectionRow>, SearchError> + Sync
    );

const SEARCH_ACCESS_WINDOW: usize = 32;

struct CandidateGrants {
    frontiers: (u64, u64),
    atom_revisions: BTreeSet<String>,
    evidence_sources: BTreeSet<String>,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
enum OfferedRead {
    Atom { revision: String, atom: String },
    Evidence(String),
}

pub struct ProductionSearch {
    index: SearchIndex,
    sequence_scope: Option<SourceSequenceScope>,
    procedure_revisions: Option<BTreeSet<String>>,
    method_proposal_revisions: BTreeSet<String>,
    validated_frontier: Option<u64>,
    readable_refs: Option<(u64, BTreeSet<String>)>,
    candidate_grants: Option<CandidateGrants>,
    semantics: Option<std::sync::Arc<super::resolution::SemanticSearchResolution>>,
    canonical_sources: Option<(u64, Vec<SearchProjectionRow>)>,
    recall_sources: BTreeSet<String>,
    matched_sources: BTreeSet<String>,
    matched_contexts: BTreeSet<String>,
}

impl ProductionSearch {
    pub const fn new(index: SearchIndex) -> Self {
        Self {
            index,
            sequence_scope: None,
            procedure_revisions: None,
            method_proposal_revisions: BTreeSet::new(),
            validated_frontier: None,
            readable_refs: None,
            candidate_grants: None,
            semantics: None,
            canonical_sources: None,
            recall_sources: BTreeSet::new(),
            matched_sources: BTreeSet::new(),
            matched_contexts: BTreeSet::new(),
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
        semantics: std::sync::Arc<super::resolution::SemanticSearchResolution>,
    ) -> Self {
        self.semantics = Some(semantics);
        self
    }

    pub(crate) fn with_matched_sources(
        mut self,
        refs: BTreeSet<String>,
        contexts: BTreeSet<String>,
    ) -> Self {
        self.matched_sources = refs;
        self.matched_contexts = contexts;
        self
    }

    pub(crate) fn with_recall_sources(mut self, refs: BTreeSet<String>) -> Self {
        self.recall_sources = refs;
        self
    }

    pub(crate) fn with_canonical_sources(
        mut self,
        frontier: u64,
        rows: Vec<SearchProjectionRow>,
    ) -> Self {
        self.canonical_sources = Some((frontier, rows));
        self
    }

    pub(crate) fn with_sequence_scope(mut self, scope: Option<SourceSequenceScope>) -> Self {
        self.sequence_scope = scope;
        self
    }

    fn hard_filter(
        &self,
        context: &SearchContext,
        object_only: bool,
        time_scope: Option<&TemporalReadScope<'_>>,
    ) -> SearchHardFilter {
        let suppressed_hashes = match &context.suppression {
            SuppressionSnapshot::Current { ref_hashes, .. } => ref_hashes.clone(),
            SuppressionSnapshot::Unavailable => unreachable!("handled above"),
        };
        let (source_role, authority) = source_filter(context.query_facets.source_boundary);
        SearchHardFilter {
            readable_refs: time_scope
                .and_then(|scope| scope.readable_refs)
                .cloned()
                .or_else(|| self.readable_refs.as_ref().map(|(_, refs)| refs.clone())),
            // A is a candidate channel; C owns positive facet compatibility.
            condition_literals: Vec::new(),
            excluded_identifiers: context.query_facets.explicit_exclusions.clone(),
            procedure_revisions: self.procedure_revisions.clone(),
            method_proposal_revisions: self.method_proposal_revisions.clone(),
            object_kind: None,
            atom_revisions: self
                .candidate_grants
                .as_ref()
                .map(|grants| grants.atom_revisions.clone()),
            task_id: context.task_id.map(|id| id.to_string()),
            repository_id: context.repository_id.map(|id| id.to_string()),
            worktree_id: context.worktree_id.map(|id| id.to_string()),
            source_kind: None,
            source_role,
            source_roles: BTreeSet::new(),
            content_trust: None,
            capture_completeness: None,
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
                TemporalMode::AsOf
                | TemporalMode::Interval
                | TemporalMode::Sequence
                | TemporalMode::Before
                | TemporalMode::After => false,
            },
            suppressed_refs: suppressed_hashes.clone(),
            suppressed_hashes,
            event_time_as_of: match context.query_facets.temporal_qualifiers.as_slice() {
                [TemporalQualifier::EventTimeAsOf { at_us }] if time_scope.is_none() => {
                    Some(*at_us)
                }
                _ => None,
            },
            event_time_interval: match context.query_facets.temporal_qualifiers.as_slice() {
                [TemporalQualifier::EventTimeInterval { start_us, end_us }]
                    if time_scope.is_none() =>
                {
                    Some((*start_us, *end_us))
                }
                _ => None,
            },
        }
    }

    fn evidence_filter(
        &self,
        context: &SearchContext,
        global_only: bool,
        time_scope: Option<&TemporalReadScope<'_>>,
    ) -> Option<SearchHardFilter> {
        use evertrace_domain::query::SourceBoundary;
        match context.query_facets.source_boundary {
            Some(SourceBoundary::ProjectPolicy | SourceBoundary::ObjectiveEvidence) => None,
            role => {
                let mut filter = self.hard_filter(context, false, time_scope);
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
                if let Some(grants) = &self.candidate_grants {
                    filter.readable_refs = Some(grants.evidence_sources.clone());
                }
                if let Some(scope) = &self.sequence_scope
                    && let Some(refs) = &mut filter.readable_refs
                {
                    refs.retain(|reference| scope.positions.contains_key(reference));
                }
                Some(filter)
            }
        }
    }

    pub(crate) async fn retrieve(
        &self,
        context: SearchContext,
        global_only: bool,
        time_scope: Option<&TemporalReadScope<'_>>,
        relation_sources: RelationSources<'_>,
    ) -> Result<evertrace_domain::query::HumanSearchPage, SearchError> {
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
        let snapshot = if let Some((frontier, rows)) = &self.canonical_sources
            && *frontier == snapshot.frontier()
            && *frontier == snapshot.authoritative_frontier()
        {
            snapshot.with_canonical_sources(*frontier, rows.clone())?
        } else {
            snapshot
        };
        let mut objects = self.hard_filter(&context, true, time_scope);
        objects.global_only = global_only;
        let evidence = self.evidence_filter(&context, global_only, time_scope);
        let result = self
            .search_snapshot(
                context.clone(),
                false,
                &snapshot,
                &deadline,
                global_only,
                evidence.as_ref(),
                time_scope,
            )
            .await?;
        super::retrieval::NativeRetrieval {
            context: &context,
            result,
            objects,
            evidence,
            deadline: &deadline,
            semantics: self.semantics.as_deref(),
            sequence_scope: self.sequence_scope.as_ref(),
            time_scope,
            relation_sources: Some(relation_sources),
        }
        .run(snapshot)
        .await
    }

    pub async fn search(&self, context: SearchContext) -> Result<SearchResult, SearchError> {
        self.search_inner(context, false).await
    }

    /// Resolve the scoped lexical access window outside the native read lease.
    /// Both ranking channels apply their admitted immutable references before top-k.
    pub(crate) async fn search_with_access(
        mut self,
        mut context: SearchContext,
        access: &super::read_context::SearchReadAccess<'_>,
    ) -> Result<HumanSearchPage, SearchError> {
        context.validate()?;
        if matches!(context.suppression, SuppressionSnapshot::Unavailable) {
            return self.search(context).await.map(ungrounded);
        }
        let atom_relation = !context.query_facets.relation_requirements.is_empty();
        let source_order = context
            .query_facets
            .answer_shape
            .filter(|shape| shape.uses_temporal_order())
            .and_then(|_| requested_ordering(&context.query_facets.temporal_qualifiers));
        let count_unit = context.query_facets.count_unit();
        let source_only =
            source_order.is_some() || count_unit == Some(CountUnit::SourceObservation);
        let atoms_only = atom_relation || count_unit == Some(CountUnit::ObjectRevision);
        let discover = async {
            let snapshot = self
                .index
                .snapshot_after_validated_frontier(access.frontier)
                .await?;
            let frontiers = (snapshot.frontier(), snapshot.authoritative_frontier());
            if frontiers.1 != access.frontier {
                return Ok((frontiers, Vec::new(), false));
            }
            let mut atoms = self.hard_filter(&context, true, None);
            atoms.object_kind = Some("atom_revision".into());
            // The existing lagging-index path is limited to revalidated current objects.
            let evidence = (!atoms_only && frontiers.0 == frontiers.1)
                .then(|| self.evidence_filter(&context, false, None))
                .flatten();
            let limit = SEARCH_ACCESS_WINDOW + 1;
            let mut identifiers = context.query_facets.target_anchors.clone();
            if !source_only && count_unit.is_none() {
                identifiers.extend(exact_identifiers(&context));
            }
            identifiers.sort();
            identifiers.dedup();
            let mut offered = Vec::new();
            let mut incomplete = false;
            let channels = std::iter::once((0, atoms))
                .filter(|_| !source_only)
                .chain(evidence.map(|filter| (1, filter)));
            for (channel, filter) in channels {
                let exact = snapshot.structured(&identifiers, &filter, limit).await?;
                let fts = if atoms_only || source_only {
                    Vec::new() // Explicit operands are not lexical queries.
                } else {
                    snapshot
                        .fts(scoped_lexical_query(&context), &filter, limit)
                        .await
                        .unwrap_or_else(|_| {
                            incomplete = true;
                            Vec::new()
                        })
                };
                for (tier, rows) in [exact, fts].into_iter().enumerate() {
                    for (rank, row) in rows.into_iter().enumerate() {
                        let order = target_anchor_position(&context, &row)
                            .map_or((tier + 1, rank, channel, 0), |position| {
                                (0, position, channel, rank)
                            });
                        let reference = row.source_ref.ok_or(StoreError::StoreCorrupt)?;
                        let read = if channel == 0 {
                            OfferedRead::Atom {
                                revision: row.candidate_id.ok_or(StoreError::StoreCorrupt)?,
                                atom: reference,
                            }
                        } else {
                            OfferedRead::Evidence(reference)
                        };
                        offered.push((order, read));
                    }
                }
            }
            // Explicit targets, then exact and FTS share the same bounded access window.
            offered.sort_unstable_by_key(|(order, _)| *order);
            let mut seen = BTreeSet::new();
            let ordered = offered
                .into_iter()
                .map(|(_, read)| read)
                .filter(|read| seen.insert(read.clone()))
                .take(limit)
                .collect();
            Ok::<_, StoreError>((frontiers, ordered, incomplete))
        };
        let Ok(discovered) =
            tokio::time::timeout_at(tokio::time::Instant::from_std(access.deadline), discover)
                .await
        else {
            return Ok(ungrounded(deadline_result(
                context,
                "search_access_window_exhausted",
                0,
                0,
            )));
        };
        let (frontiers, offered, mut unavailable) = discovered?;
        if frontiers.1 != access.frontier {
            return Ok(ungrounded(deadline_result(
                context,
                "execution_context_frontier_changed",
                frontiers.0,
                frontiers.1,
            )));
        }
        let mut grants = CandidateGrants {
            frontiers,
            atom_revisions: BTreeSet::new(),
            evidence_sources: BTreeSet::new(),
        };
        let mut temporal_sources = BTreeMap::new();
        let mut restricted = false;
        let checks_remaining = SEARCH_ACCESS_WINDOW.saturating_sub(offered.len());
        let exhausted = offered.len() > SEARCH_ACCESS_WINDOW;
        for read in offered.into_iter().take(SEARCH_ACCESS_WINDOW) {
            let (verified, reference, target) = match read {
                OfferedRead::Atom { revision, atom } => (
                    access.check_current(&atom, &revision).await,
                    revision,
                    &mut grants.atom_revisions,
                ),
                OfferedRead::Evidence(source) => {
                    let verified = if source_order.is_some() {
                        access.checked_source_receipt(&source).await.map(|receipt| {
                            temporal_sources.insert(source.clone(), receipt);
                        })
                    } else {
                        access.check_evidence(&source).await
                    };
                    (verified, source, &mut grants.evidence_sources)
                }
            };
            match verified {
                Ok(()) => {
                    target.insert(reference);
                }
                Err(ErrorCode::Untrusted) => restricted = true,
                Err(_) => unavailable = true,
            }
            if Instant::now() >= access.deadline {
                return Ok(ungrounded(deadline_result(
                    context,
                    "search_access_window_exhausted",
                    frontiers.0,
                    frontiers.1,
                )));
            }
        }
        self.candidate_grants = Some(grants);
        context.budget.latency_us_remaining = access
            .deadline
            .saturating_duration_since(Instant::now())
            .as_micros()
            .try_into()
            .unwrap_or(u64::MAX);
        if (source_only || count_unit.is_some()) && frontiers.0 != frontiers.1 {
            return Ok(ungrounded(deadline_result(
                context,
                "search_projection_stale",
                frontiers.0,
                frontiers.1,
            )));
        }
        let exact_followup = context.budget.follow_ups_remaining > 0;
        let view_context = (atom_relation || source_only || exact_followup || count_unit.is_some())
            .then(|| context.clone());
        let mut result = if source_only {
            SearchResult {
                layer: RetrievalLayer::B,
                candidates: Vec::new(),
                projection_frontier: frontiers.0,
                authoritative_frontier: frontiers.1,
                completeness: RetrievalCompleteness::Complete,
                omitted_refs: BTreeSet::new(),
                degraded_reasons: BTreeSet::new(),
                budget: context.budget,
            }
        } else {
            self.search(context).await?
        };
        if self
            .candidate_grants
            .as_ref()
            .is_some_and(|grants| !grants.atom_revisions.is_disjoint(&result.omitted_refs))
        {
            result
                .degraded_reasons
                .insert("retrieval_budget_exhausted".into());
            if result.completeness == RetrievalCompleteness::Complete {
                result.completeness = RetrievalCompleteness::Partial;
            }
        }
        for (present, reason) in [
            (restricted, "source_read_restricted"),
            (exhausted, "search_access_window_exhausted"),
            (unavailable, "search_access_unavailable"),
            (
                source_order == Some(TemporalOrdering::SourceSequence),
                "source_sequence_coverage_unverified",
            ),
        ] {
            if present {
                result.degraded_reasons.insert(reason.into());
                if result.completeness == RetrievalCompleteness::Complete {
                    result.completeness = RetrievalCompleteness::Partial;
                }
            }
        }
        if let Some(context) = view_context {
            let read = (atom_relation || exact_followup).then_some(ScopedCandidateRead {
                index: &self.index,
                access,
                checks_remaining,
            });
            let position = |reference: &str| {
                temporal_sources
                    .get(reference)
                    .cloned()
                    .map(|receipt| TemporalPosition::Source {
                        receipt,
                        coverage_complete: false,
                        previous_revision: None,
                        revision_order: None,
                    })
            };
            let time = source_order.map(|_| TemporalReadScope {
                revision_bridge: None,
                frontier: frontiers.1,
                read: &position,
                readable_refs: None, // The exact evidence filter uses these same-frontier access grants.
                source_domain: true,
            });
            if let Some(page) = self
                .finish_mcp_view(
                    &context,
                    result.clone(),
                    access.deadline,
                    read,
                    time.as_ref(),
                )
                .await
            {
                return Ok(page);
            }
        }
        Ok(ungrounded(result))
    }

    /// Ordinary MCP can group already reviewed evidence without reopening the candidate pool.
    pub(crate) async fn ground_reviewed(
        &self,
        context: &SearchContext,
        mut result: SearchResult,
        approved_refs: &BTreeSet<&str>,
        expires: Instant,
    ) -> Option<evertrace_domain::query::GroundedEvidenceView> {
        result
            .candidates
            .retain(|candidate| approved_refs.contains(candidate.candidate_id.as_str()));
        if result.candidates.is_empty() {
            return None;
        }
        // Unreturned references did not pass the final output review.
        result.omitted_refs.clear();
        result.budget.hops_remaining = 0;
        result.budget.follow_ups_remaining = 0;
        self.finish_mcp_view(context, result, expires, None, None)
            .await?
            .grounded_view
    }

    async fn finish_mcp_view(
        &self,
        context: &SearchContext,
        result: SearchResult,
        expires: Instant,
        access: Option<ScopedCandidateRead<'_>>,
        time_scope: Option<&TemporalReadScope<'_>>,
    ) -> Option<HumanSearchPage> {
        if result.projection_frontier != result.authoritative_frontier
            || result.completeness == RetrievalCompleteness::Unknown
        {
            return None;
        }
        let started = Instant::now();
        let latency = expires
            .checked_duration_since(started)?
            .as_micros()
            .try_into()
            .ok()?;
        let deadline = RequestDeadline::new(started, latency);
        let snapshot = deadline
            .run(
                self.index
                    .snapshot_after_validated_frontier(result.projection_frontier),
            )
            .await
            .ok()?
            .ok()?;
        if snapshot.frontier() != result.projection_frontier
            || snapshot.authoritative_frontier() != result.authoritative_frontier
        {
            return None;
        }
        let source_count = context.query_facets.count_unit() == Some(CountUnit::SourceObservation);
        let evidence =
            (source_count || time_scope.is_some() || result.budget.follow_ups_remaining > 0)
                .then(|| self.evidence_filter(context, false, time_scope))
                .flatten();
        let mut retrieval = super::retrieval::NativeRetrieval {
            context,
            result,
            objects: self.hard_filter(context, true, time_scope),
            evidence,
            deadline: &deadline,
            semantics: None,
            sequence_scope: None,
            time_scope,
            relation_sources: None,
        };
        if source_count || time_scope.is_some() {
            let mode = if source_count {
                ExactEvidence::Counted
            } else {
                ExactEvidence::Ordered
            };
            retrieval
                .read_exact_evidence(&snapshot, &context.query_facets.target_anchors, mode)
                .await
                .ok()?;
        }
        let page = retrieval.finish(snapshot, access).await.ok()?;
        page.validate().then_some(page)
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
        let evidence = self
            .candidate_grants
            .as_ref()
            .filter(|grants| !grants.evidence_sources.is_empty())
            .and_then(|_| self.evidence_filter(&context, false, None));
        let Some(evidence) = evidence else {
            return self
                .search_snapshot(
                    context,
                    force_fts_failure,
                    &snapshot,
                    &deadline,
                    false,
                    None,
                    None,
                )
                .await;
        };
        let result = self
            .search_snapshot(
                context.clone(),
                force_fts_failure,
                &snapshot,
                &deadline,
                false,
                Some(&evidence),
                None,
            )
            .await?;
        if result.completeness == RetrievalCompleteness::Unknown {
            return Ok(result);
        }
        let mut retrieval = super::retrieval::NativeRetrieval {
            context: &context,
            result,
            objects: self.hard_filter(&context, true, None),
            evidence: Some(evidence),
            deadline: &deadline,
            semantics: self.semantics.as_deref(),
            sequence_scope: self.sequence_scope.as_ref(),
            time_scope: None,
            relation_sources: None,
        };
        let has_unread_source = self.candidate_grants.as_ref().is_some_and(|grants| {
            grants.evidence_sources.iter().any(|id| {
                !retrieval.result.candidates.iter().any(|candidate| {
                    candidate.row_variant
                        == evertrace_domain::query::SearchCandidateVariant::EvidenceSurface
                        && &candidate.source_ref == id
                })
            })
        });
        if has_unread_source {
            retrieval
                .read_evidence(&snapshot, scoped_lexical_query(&context), &[])
                .await?;
        }
        if !matches!(deadline.run(snapshot.is_current()).await, Ok(Ok(true))) {
            return Ok(deadline_result(
                context,
                "read_access_frontier_changed",
                snapshot.frontier(),
                snapshot.authoritative_frontier(),
            ));
        }
        let mut result = retrieval.result;
        result.budget.latency_us_remaining = deadline.remaining().map_or(0, |remaining| {
            remaining.as_micros().try_into().unwrap_or(u64::MAX)
        });
        if result.completeness == RetrievalCompleteness::Complete
            && (!result.degraded_reasons.is_empty() || !result.omitted_refs.is_empty())
        {
            result.completeness = RetrievalCompleteness::Partial;
        }
        Ok(result)
    }

    async fn search_snapshot(
        &self,
        mut context: SearchContext,
        force_fts_failure: bool,
        snapshot: &evertrace_store::SearchSnapshot,
        deadline: &RequestDeadline,
        global_only: bool,
        anchor_evidence: Option<&SearchHardFilter>,
        time_scope: Option<&TemporalReadScope<'_>>,
    ) -> Result<SearchResult, SearchError> {
        let started = deadline.started;
        let mut changed_frontiers = BTreeSet::new();
        let frontiers = (snapshot.frontier(), snapshot.authoritative_frontier());
        if self
            .candidate_grants
            .as_ref()
            .is_some_and(|grants| grants.frontiers != frontiers)
            || self
                .readable_refs
                .as_ref()
                .is_some_and(|(frontier, _)| (*frontier, *frontier) != frontiers)
            || self
                .semantics
                .as_ref()
                .is_some_and(|value| value.frontier != snapshot.frontier())
        {
            changed_frontiers.insert("read_access_frontier_changed".into());
        }
        if self
            .canonical_sources
            .as_ref()
            .is_some_and(|(frontier, _)| {
                *frontier != snapshot.frontier() || *frontier != snapshot.authoritative_frontier()
            })
        {
            changed_frontiers.insert("canonical_source_frontier_changed".into());
        }
        if context.execution.as_ref().is_some_and(|execution| {
            execution.frontier != snapshot.frontier()
                || execution.frontier != snapshot.authoritative_frontier()
        }) {
            changed_frontiers.insert("execution_context_frontier_changed".into());
        }
        if context
            .query_facets
            .temporal_qualifiers
            .iter()
            .any(|qualifier| qualifier.source_sequence_ref().is_some())
            && self.sequence_scope.is_none()
        {
            changed_frontiers.insert("source_sequence_scope_unresolved".into());
        }
        if time_scope.is_some_and(|scope| scope.frontier != snapshot.frontier()) {
            changed_frontiers.insert("source_time_frontier_changed".into());
        }
        if !changed_frontiers.is_empty() {
            return Ok(SearchResult {
                layer: RetrievalLayer::A,
                projection_frontier: snapshot.frontier(),
                authoritative_frontier: snapshot.authoritative_frontier(),
                candidates: Vec::new(),
                completeness: RetrievalCompleteness::Unknown,
                degraded_reasons: changed_frontiers,
                omitted_refs: BTreeSet::new(),
                budget: context.budget,
            });
        }
        let mut filter = self.hard_filter(&context, true, time_scope);
        filter.global_only = global_only;
        let exact_atom_only = self.candidate_grants.is_some()
            && (!context.query_facets.relation_requirements.is_empty()
                || context.query_facets.count_unit() == Some(CountUnit::ObjectRevision));
        if exact_atom_only {
            filter.object_kind = Some("atom_revision".into());
        }
        let requested_limit = if context.query_facets.count_unit().is_some()
            || context.query_facets.answer_shape
                == Some(evertrace_domain::query::AnswerShape::TemporalComparison)
        {
            context.budget.candidates_remaining
        } else {
            context
                .query_facets
                .quantity_constraints
                .iter()
                .filter_map(|constraint| match constraint {
                    QuantityConstraint::ResultLimit { limit } => Some(*limit),
                    QuantityConstraint::DistinctCount { .. } => None,
                })
                .min()
                .unwrap_or(context.budget.candidates_remaining)
                .min(context.budget.candidates_remaining)
        };
        let limit = usize::try_from(requested_limit).map_err(|_| SearchError::Unsupported)?;
        let fetch_limit = if limit >= 32 {
            limit
        } else {
            limit.saturating_mul(4).min(32)
        };
        let exact_identifiers = exact_identifiers(&context);
        let mut structured = Vec::new();
        let mut degraded_reasons = BTreeSet::new();
        if context.raw_query != context.protected_query {
            degraded_reasons.insert("query_redacted".into());
        }
        if !context.protected_facets.is_empty() {
            degraded_reasons.insert("protected_facet_unverifiable".into());
        }
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
        let primary_sources = self
            .recall_sources
            .union(&self.matched_sources)
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut source_rows = Vec::new();
        // A matching contract must not be displaced by its supporting Episodes
        // before fusion. Both groups share one 32-row window and one lookahead.
        for references in [
            primary_sources.iter().cloned().collect::<Vec<_>>(),
            self.matched_contexts
                .difference(&primary_sources)
                .cloned()
                .collect(),
        ] {
            if source_rows.len() == 33 {
                break;
            }
            if references.is_empty() {
                continue;
            }
            match deadline
                .run(snapshot.structured(&references, &filter, 33 - source_rows.len()))
                .await
            {
                Ok(Ok(rows)) => source_rows.extend(rows),
                Ok(Err(_)) => {
                    degraded_reasons.insert("recall_source_channel_unavailable".into());
                }
                Err(()) => {
                    degraded_reasons.insert("recall_source_deadline_exhausted".into());
                }
            }
        }
        if source_rows.len() > 32 {
            omitted_refs.extend(
                source_rows[32..]
                    .iter()
                    .filter_map(|row| row.candidate_id.clone()),
            );
            source_rows.truncate(32);
            degraded_reasons.insert("recall_source_budget_exhausted".into());
        }
        structured.extend(source_rows);
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
        // Explicit source coordinates must compete as exact hits, before an object FTS window spends the shared budget.
        if let Some(evidence) = anchor_evidence.filter(|_| self.candidate_grants.is_some()) {
            match deadline
                .run(snapshot.structured(&exact_identifiers, evidence, fetch_limit))
                .await
            {
                Ok(Ok(rows)) => structured.extend(rows),
                Ok(Err(_)) => {
                    degraded_reasons.insert("evidence_structured_unavailable".into());
                }
                Err(()) => {
                    degraded_reasons.insert("evidence_structured_deadline_exhausted".into());
                }
            }
        }
        let fts_result = if exact_atom_only {
            Ok(Vec::new())
        } else if force_fts_failure {
            Err(StoreError::LanceDb)
        } else {
            match deadline
                .run(snapshot.fts(
                    if self.candidate_grants.is_some() {
                        scoped_lexical_query(&context)
                    } else {
                        &context.protected_query
                    },
                    &filter,
                    fetch_limit,
                ))
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
            if row.candidate_id.is_none() || !hard_compatible(row, &context, time_scope)? {
                continue;
            }
            let exact = row.candidate_id.as_deref() == Some(context.protected_query.as_str())
                || row.source_ref.as_deref() == Some(context.protected_query.as_str())
                || context
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
                .is_some_and(|id| id == context.protected_query)
                || row.source_ref.as_deref() == Some(context.protected_query.as_str());
            let anchor_position = target_anchor_position(&context, row);
            let active = row
                .candidate_id
                .as_ref()
                .and_then(|id| self.semantics.as_ref()?.states.get(id))
                == Some(&evertrace_domain::semantic::SemanticResolution::Normative(
                    evertrace_domain::semantic::NormativeResolutionState::Active,
                ));
            let recall = row.candidate_id.as_ref().is_some_and(|id| {
                self.recall_sources.contains(id) || self.matched_sources.contains(id)
            });
            let rank = if active {
                (0, 0)
            } else if recall {
                (0, 1)
            } else if row
                .candidate_id
                .as_ref()
                .is_some_and(|id| self.matched_contexts.contains(id))
            {
                (0, 2)
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
            let matched = self.matched_sources.contains(&candidate_id)
                || self.matched_contexts.contains(&candidate_id);
            let origin = match rank.0 {
                0 if rank.1 == 0 => "normative",
                0 if matched => "future_cue_match",
                0 => "recall_source",
                1 => "target_anchor",
                2 => "exact",
                _ => "fts",
            };
            let mut origins = BTreeSet::from([origin.to_owned()]);
            if self.recall_sources.contains(&candidate_id) {
                origins.insert("recall_source".into());
            }
            if matched {
                origins.insert("future_cue_match".into());
            }
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
            let temporal = time_scope
                .map(|scope| scope.position(row))
                .transpose()?
                .flatten();
            let source_time = temporal.as_ref().and_then(TemporalPosition::source);
            let validity_interval = temporal.as_ref().and_then(TemporalPosition::validity);
            let revision_order = temporal.as_ref().and_then(TemporalPosition::revision_order);
            let source_sequence = self
                .sequence_scope
                .as_ref()
                .map(|scope| scope.position(row))
                .transpose()?
                .flatten()
                .or_else(|| {
                    temporal
                        .as_ref()
                        .and_then(|position| position.sequence(&context.query_facets))
                });
            let time_bytes = temporal
                .as_ref()
                .map_or(0, TemporalPosition::wire_bytes)
                .saturating_add(
                    source_sequence
                        .as_ref()
                        .map_or(0, |position| position.wire_bytes()),
                );
            if context
                .budget
                .consume_candidate_text(row.text.len().saturating_add(time_bytes))
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
                source_sequence,
                source_time,
                validity_interval,
                revision_order,
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
        if context.unverified_hard_constraint() {
            candidates.retain(|(_, candidate, _)| super::resolution::active_rule(candidate));
            omitted_refs.retain(|reference| {
                self.semantics.as_ref().is_some_and(|semantics| {
                    semantics.states.get(reference)
                        == Some(&evertrace_domain::semantic::SemanticResolution::Normative(
                            evertrace_domain::semantic::NormativeResolutionState::Active,
                        ))
                })
            });
        }
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
        let temporal_partial =
            temporal_is_partial(&candidates, &context, time_scope, &mut degraded_reasons);
        let mut completeness = if conflicted {
            RetrievalCompleteness::Conflicted
        } else if temporal_partial
            || context.query_facets.parse_status != FacetParseStatus::Complete
            || context.raw_query != context.protected_query
            || !context.protected_facets.is_empty()
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

fn target_anchor_position(context: &SearchContext, row: &SearchProjectionRow) -> Option<usize> {
    context
        .query_facets
        .target_anchors
        .iter()
        .position(|id| row.candidate_id.as_ref() == Some(id) || row.source_ref.as_ref() == Some(id))
}

fn scoped_lexical_query(context: &SearchContext) -> &str {
    if context.query_facets.answer_shape == Some(AnswerShape::EntityList)
        && let Some(topic) = super::entity_list_topic(&context.protected_query)
    {
        return topic;
    }
    // The explicit slots stay in protected IR; only the primary clause is ranked as lexical text.
    if context.budget.follow_ups_remaining != 0
        && let Some((primary, _)) = context
            .protected_query
            .split_once(super::EXACT_SLOT_SEPARATOR)
    {
        return primary.trim();
    }
    &context.protected_query
}

fn exact_identifiers(context: &SearchContext) -> Vec<String> {
    let mut refs = context.query_facets.exact_identifiers.clone();
    refs.push(context.protected_query.clone());
    refs.sort();
    refs.dedup();
    refs
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

fn ungrounded(result: SearchResult) -> HumanSearchPage {
    HumanSearchPage {
        result,
        grounded_view: None,
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
    time_scope: Option<&TemporalReadScope<'_>>,
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
        || !temporal_compatible(row, context, time_scope)?
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
    time_scope: Option<&TemporalReadScope<'_>>,
    degraded: &mut BTreeSet<String>,
) -> bool {
    let required_domain = match context.query_facets.temporal_qualifiers.as_slice() {
        [] => return false,
        [TemporalQualifier::OrderBy { .. }] => return false,
        [qualifier] if qualifier.is_event_time() || qualifier.is_validity() => "event_time",
        // The caller has already pinned a canonical source revision and its
        // readable references. Event timestamps do not invalidate its sequence.
        [qualifier] if qualifier.source_sequence_ref().is_some() => return false,
        _ => {
            degraded.insert("temporal_qualifier_unknown".into());
            return true;
        }
    };
    if time_scope.is_some() {
        let partial = candidates.iter().any(|(_, candidate, _)| {
            candidate
                .temporal_match(&context.query_facets.temporal_qualifiers)
                .is_none()
        });
        if partial {
            let reason = if time_scope.is_some_and(|scope| !scope.source_domain) {
                "validity_interval_unverified"
            } else {
                "event_clock_provenance_unverified"
            };
            degraded.insert(reason.into());
        }
        return partial;
    }
    if candidates.is_empty()
        || candidates
            .iter()
            .any(|(_, _, row)| row.time_domain != required_domain)
    {
        degraded.insert("temporal_domain_incomplete".into());
    } else {
        // An indexed scalar/domain does not attest clock origin or uncertainty.
        degraded.insert("event_clock_provenance_unverified".into());
    }
    true
}

fn temporal_compatible(
    row: &SearchProjectionRow,
    context: &SearchContext,
    time_scope: Option<&TemporalReadScope<'_>>,
) -> Result<bool, QueryError> {
    if row.row_variant == "object"
        && context
            .query_facets
            .temporal_qualifiers
            .iter()
            .any(|qualifier| qualifier.source_sequence_ref().is_some())
    {
        return time_scope.map_or(Ok(false), |scope| {
            scope
                .position(row)
                .map_err(|_| QueryError::Invalid)
                .map(|position| position.is_some_and(|position| position.contextual()))
        });
    }
    if let Some(scope) = time_scope
        && matches!(
            context.query_facets.temporal_qualifiers.as_slice(),
            [qualifier] if qualifier.is_event_time() || qualifier.is_validity()
        )
    {
        return Ok(scope
            .position(row)
            .map_err(|_| QueryError::Invalid)?
            .is_none_or(|position| {
                position.matches(&context.query_facets.temporal_qualifiers) != Some(false)
                    || position.contextual()
                    || context.query_facets.target_anchors.iter().any(|reference| {
                        row.candidate_id.as_ref() == Some(reference)
                            || row.source_ref.as_ref() == Some(reference)
                    })
            }));
    }
    Ok(match context.query_facets.temporal_qualifiers.as_slice() {
        [] | [TemporalQualifier::OrderBy { .. }] => true,
        [TemporalQualifier::EventTimeAsOf { at_us }] => {
            row.time_domain == "event_time" && row.event_time_us <= *at_us
        }
        [TemporalQualifier::EventTimeInterval { start_us, end_us }] => {
            row.time_domain == "event_time"
                && row.event_time_us >= *start_us
                && row.event_time_us < *end_us
        }
        [qualifier] if qualifier.source_sequence_ref().is_some() => {
            row.row_variant == "evidence_surface"
                && qualifier.matches_sequence(row.source_sequence) == Some(true)
        }
        _ => false,
    })
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
