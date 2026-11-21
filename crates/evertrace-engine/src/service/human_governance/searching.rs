use super::*;
use crate::repository::RepositoryReadAuthority;
use evertrace_domain::{
    query::*,
    semantic::{NormativeResolutionState, SemanticResolution},
};

use crate::search::read_context::{
    RelationArchiveBudget, check_relation_archive, current_operation_binding,
    operation_binding_sources,
};

const SEARCH_HIT_ORDER_REVISION: u32 = 11;

type SearchPolicy = Option<(String, Option<evertrace_codex::policy::PolicyEvidence>)>;

fn search_policy(report: Option<&evertrace_codex::HostProbeReport>) -> SearchPolicy {
    report.map(|value| {
        (
            value.manifest().adapter_manifest_id.clone(),
            value.current_project_policy_evidence(),
        )
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchHitCursor {
    frontier: u64,
    data_identity: ReadDataIdentity,
    projection_version: u64,
    policy: SearchPolicy,
    inherited_repository: Option<RepositoryId>,
    blocked_task_shards: Option<BTreeSet<RepositoryId>>,
    relation_archive_budget: RelationArchiveBudget,
    wiki_inputs: std::collections::BTreeMap<String, BTreeSet<String>>,
    after: Option<HumanSearchHit>,
    remaining: Vec<HumanSearchHit>,
    layer: RetrievalLayer,
    completeness: RetrievalCompleteness,
    reasons: BTreeSet<String>,
    budget: RetrievalBudget,
}

impl SearchHitCursor {
    fn open(
        key: &evertrace_capture::DeviceKey,
        binding: &[u8],
        token: &str,
    ) -> Result<Self, HumanGovernanceError> {
        // Query validation has already bounded and checked the lowercase hex envelope.
        let mut bytes = token
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte| {
                    if byte <= b'9' {
                        byte - b'0'
                    } else {
                        byte - b'a' + 10
                    }
                };
                digit(pair[0]) << 4 | digit(pair[1])
            })
            .collect::<Vec<_>>();
        let plaintext = key
            .open_search_continuation(binding, &mut bytes)
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        serde_json::from_slice(plaintext).map_err(|_| HumanGovernanceError::InvalidInput)
    }

    fn take_page(
        &mut self,
        selection: MemoryScopeSelection,
        limit: u16,
        key: &evertrace_capture::DeviceKey,
        binding: &[u8],
    ) -> Result<Option<(Vec<HumanSearchHit>, HumanSearchHitPage)>, HumanGovernanceError> {
        let split = self.remaining.len().min(usize::from(limit));
        let rest = self.remaining.split_off(split);
        let hits = std::mem::replace(&mut self.remaining, rest);
        self.after = hits.last().cloned();
        self.wiki_inputs.retain(|id, _| {
            self.after
                .iter()
                .chain(&self.remaining)
                .any(|hit| hit.candidate_id == *id)
        });
        let next_cursor = if self.remaining.is_empty() {
            None
        } else {
            let bytes = serde_json::to_vec(&self).map_err(|_| HumanGovernanceError::Store)?;
            let sealed = key
                .seal_search_continuation(binding, &bytes)
                .map_err(|_| HumanGovernanceError::Store)?;
            use std::fmt::Write;
            let mut token = String::with_capacity(sealed.len() * 2);
            for byte in sealed {
                write!(token, "{byte:02x}").map_err(|_| HumanGovernanceError::Store)?;
            }
            if !valid_search_cursor(&token) {
                return Ok(None);
            }
            Some(token)
        };
        Ok(Some((
            hits,
            HumanSearchHitPage {
                selection,
                data_identity: self.data_identity,
                projection_version: self.projection_version,
                next_cursor,
            },
        )))
    }
}

fn cursor_unavailable(frontier: u64, reason: &str) -> HumanSearchPage {
    HumanSearchPage {
        result: SearchResult {
            layer: RetrievalLayer::A,
            projection_frontier: 0,
            authoritative_frontier: frontier,
            candidates: Vec::new(),
            completeness: RetrievalCompleteness::Unknown,
            degraded_reasons: BTreeSet::from([reason.into()]),
            omitted_refs: BTreeSet::new(),
            budget: RetrievalBudget {
                candidates_remaining: 0,
                tokens_remaining: 0,
                latency_us_remaining: 0,
                hops_remaining: 0,
                follow_ups_remaining: 0,
            },
        },
        grounded_view: None,
        hit_window: None,
        hit_page: None,
    }
}

fn source_sequence_scope(
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    readable: &BTreeSet<String>,
    facets: &QueryFacetSet,
    prefix_count_limit: Option<u32>,
    deadline: std::time::Instant,
) -> Option<crate::search::SourceSequenceScope> {
    let [qualifier] = facets.temporal_qualifiers.as_slice() else {
        return None;
    };
    let source_ref = qualifier.source_sequence_ref()?;
    let reference = source_ref.to_string();
    if !readable.contains(&reference) || std::time::Instant::now() >= deadline {
        return None;
    }
    let anchor = source_receipt(index, &reference)?;
    let mut positions = std::collections::BTreeMap::new();
    let mut count_ranges = prefix_count_limit.map(|_| Vec::new());
    for reference in readable {
        if std::time::Instant::now() >= deadline {
            return None;
        }
        let Some(receipt) = source_receipt(index, reference) else {
            continue;
        };
        if receipt.source_instance_id == anchor.source_instance_id
            && receipt.source_revision == anchor.source_revision
            && qualifier.matches_sequence(receipt.source_sequence) == Some(true)
        {
            positions.insert(reference.clone(), receipt.source_sequence);
            if let Some(ranges) = &mut count_ranges {
                if receipt.source_kind == anchor.source_kind
                    && receipt.source_sequence_origin == Some(0)
                    && let Some(range) = receipt.source_byte_range
                    && range.start < range.end
                    && range.end == receipt.source_sequence
                    && ranges.len() < prefix_count_limit.unwrap_or(0) as usize
                {
                    ranges.push([range.start, range.end]);
                } else {
                    count_ranges = None;
                }
            }
        }
    }
    let through = match qualifier {
        TemporalQualifier::SourceSequenceAtMost { sequence, .. } => Some(*sequence),
        TemporalQualifier::SourceSequenceBefore { sequence, .. } => {
            Some(sequence.saturating_sub(1))
        }
        TemporalQualifier::SourceSequenceAfter { .. } => None,
        _ => return None,
    };
    let coverage_complete = source_coverage_complete(index, &anchor, through);
    let source_prefix_ranges = count_ranges
        .filter(|_| coverage_complete)
        .and_then(|mut ranges| {
            // The watermark proves ingestion, not permission or current visibility for each receipt.
            ranges.sort_unstable();
            (ranges.first().is_none_or(|range| range[0] == 0)
                && ranges.windows(2).all(|pair| pair[0][1] == pair[1][0])
                && Some(ranges.last().map_or(0, |range| range[1])) == through)
                .then_some(ranges)
        });
    Some(crate::search::SourceSequenceScope {
        source_anchor: source_ref,
        positions,
        coverage_complete,
        source_prefix_ranges,
    })
}

fn prefix_count_limit(selection: MemoryScopeSelection, context: &SearchContext) -> Option<u32> {
    let facets = &context.query_facets;
    // This exact metadata domain has no lexical, relation, lifecycle, or shard predicate.
    (selection == MemoryScopeSelection::All
        && facets.count_unit() == Some(CountUnit::SourceObservation)
        && matches!(facets.temporal_qualifiers.as_slice(),
            [TemporalQualifier::SourceSequenceAtMost { source_ref, .. }]
                if context.protected_query == source_ref.to_string())
        && facets.parse_status == FacetParseStatus::Complete
        && facets.polarity == Polarity::Positive
        && facets.source_boundary.is_none()
        && facets.statement_role == StatementRole::Unknown
        && facets.lifecycle_boundary == LifecycleBoundary::Any
        && facets.target_anchors.is_empty()
        && facets.exact_identifiers.is_empty()
        && facets.condition_literals.is_empty()
        && facets.explicit_exclusions.is_empty()
        && facets.relation_requirements.is_empty()
        && context.protected_facets.is_empty()
        && context.raw_query == context.protected_query)
        .then_some(context.budget.candidates_remaining)
}

fn source_receipt(
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    reference: &str,
) -> Option<Box<evertrace_domain::evidence::SourceReceipt>> {
    crate::search::read_context::source_receipt(reference, |key| {
        let [row] = index.get(key)?.as_slice() else {
            return None;
        };
        Some(*row)
    })
}
// Only an explicitly selected and readable source can explain absent searchable text.
fn unavailable_exact_source_text(
    query: &HumanSearchQuery,
    protected_query: &str,
    readable: &BTreeSet<String>,
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
) -> Option<String> {
    if query.facets.answer_shape != Some(AnswerShape::SourceSnippet) {
        return None;
    }
    let reference = protected_query.trim();
    reference
        .parse::<evertrace_domain::ids::SourceObservationId>()
        .ok()?;
    if !readable.contains(reference) {
        return None;
    }
    let receipt = source_receipt(index, reference)?;
    let in_scope = match query.selection {
        MemoryScopeSelection::All => true,
        MemoryScopeSelection::Global => {
            receipt.task_id.is_none()
                && receipt.repository_instance_id.is_none()
                && receipt.worktree_instance_id.is_none()
        }
        MemoryScopeSelection::Task { task_id } => receipt.task_id == Some(task_id),
        MemoryScopeSelection::Repository { repository_id } => {
            receipt.repository_instance_id == Some(repository_id)
        }
        MemoryScopeSelection::Worktree { worktree_id } => {
            receipt.worktree_instance_id == Some(worktree_id)
        }
        MemoryScopeSelection::Unassigned => false,
    };
    use evertrace_domain::evidence::ProtectedPresentation;
    (in_scope
        && (receipt.unsupported_record_classification.is_some()
            || matches!(
                receipt.protected_presentation,
                Some(ProtectedPresentation::Unavailable { .. })
            )))
    .then(|| reference.to_owned())
}

fn source_predecessor(
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    receipt: &evertrace_domain::evidence::SourceReceipt,
) -> Option<evertrace_domain::evidence::SourceRevision> {
    let rows = index.get(receipt.source_revision.as_str())?;
    if rows.len() > 64 {
        return None;
    }
    let mut previous = None;
    for row in rows {
        if row.object_kind.as_deref() != Some("source_revision") {
            continue;
        }
        let JournalPayload::SourceRevisionRecorded(value) =
            serde_json::from_str(row.payload_json.as_deref()?).ok()?
        else {
            continue;
        };
        if value.source_instance_id != receipt.source_instance_id
            || value.source_revision != receipt.source_revision
        {
            continue;
        }
        if value.mode != evertrace_domain::evidence::SourceRevisionMode::Replacement {
            return None;
        }
        let parent = value.previous_source_revision?;
        if parent == receipt.source_revision || previous.as_ref().is_some_and(|old| old != &parent)
        {
            return None;
        }
        previous = Some(parent);
    }
    previous
}

/// Find one revision's canonical witnesses; Native selects only after every request hard gate.
fn source_revision_bridge(
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    readable: &BTreeSet<String>,
    facets: &QueryFacetSet,
    deadline: std::time::Instant,
) -> Option<(String, BTreeSet<String>)> {
    use evertrace_domain::evidence::EvidenceSurface;

    if facets.answer_shape != Some(AnswerShape::TemporalComparison)
        || requested_ordering(&facets.temporal_qualifiers) != Some(TemporalOrdering::Supersession)
        || facets.target_anchors.len() != 2
    {
        return None;
    }
    let targets = facets
        .target_anchors
        .iter()
        .map(|target| {
            let reference = EvidenceSurface::parse_candidate_ref(target)
                .map_or_else(|| target.clone(), |(id, _, _)| id.to_string());
            readable
                .contains(&reference)
                .then(|| source_receipt(index, &reference))
                .flatten()
        })
        .collect::<Option<Vec<_>>>()?;
    if targets[0].source_instance_id != targets[1].source_instance_id
        || targets[0].source_revision == targets[1].source_revision
    {
        return None;
    }
    let parents = targets
        .iter()
        .map(|receipt| source_predecessor(index, receipt))
        .collect::<Vec<_>>();
    if parents.iter().all(Option::is_none)
        || parents
            .iter()
            .enumerate()
            .any(|(i, parent)| parent.as_ref() == Some(&targets[1 - i].source_revision))
    {
        return None;
    }
    let mut witnesses: [BTreeSet<String>; 2] = Default::default();
    for reference in readable {
        if std::time::Instant::now() >= deadline {
            return None;
        }
        let Some(receipt) = source_receipt(index, reference) else {
            continue;
        };
        for i in 0..2 {
            if receipt.source_instance_id == targets[i].source_instance_id
                && Some(&receipt.source_revision) == parents[i].as_ref()
            {
                witnesses[i].insert(receipt.source_observation_id.to_string());
            }
        }
    }
    let mut plans = witnesses
        .into_iter()
        .enumerate()
        .filter_map(|(i, witnesses)| {
            let receipt = source_receipt(index, witnesses.first()?)?;
            (source_predecessor(index, &receipt).as_ref() == Some(&targets[1 - i].source_revision))
                .then(|| (facets.target_anchors[i].clone(), witnesses))
        })
        .collect::<Vec<_>>();
    if plans.len() == 1 { plans.pop() } else { None }
}

/// Admission verified each contiguous byte/CAS leg; this reader never computes a second digest.
fn source_coverage_complete(
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    receipt: &evertrace_domain::evidence::SourceReceipt,
    through: Option<u64>,
) -> bool {
    use evertrace_domain::{
        evidence::EvidenceSourceKind,
        source::{MetadataState, SessionBodyState},
    };
    if receipt.source_kind != EvidenceSourceKind::CodexSessionJsonl
        || receipt.source_sequence_origin != Some(0)
        || receipt
            .source_byte_range
            .as_ref()
            .is_none_or(|range| range.end != receipt.source_sequence)
    {
        return false;
    }
    let key = evertrace_store::SourceIngestWatermark {
        source_instance_id: receipt.source_instance_id.clone(),
        source_revision: receipt.source_revision.clone(),
        source_sequence: 0,
        confirmed_prefix_digest: None,
        earlier_prefix: None,
    }
    .stable_key();
    let key = format!("runtime:watermark:source:{key}");
    let Some([row]) = index.get(key.as_str()).map(Vec::as_slice) else {
        return false;
    };
    let Some(Ok(JournalPayload::SourceIngestWatermark(watermark))) = row
        .payload_json
        .as_ref()
        .map(|json| serde_json::from_str(json))
    else {
        return false;
    };
    if watermark.source_instance_id != receipt.source_instance_id
        || watermark.source_revision != receipt.source_revision
        || receipt.source_sequence > watermark.source_sequence
        || watermark.confirmed_prefix_digest.is_none()
    {
        return false;
    }
    // An admitted earlier prefix remains usable even while a later gap is open.
    let contiguous_through = watermark
        .earlier_prefix
        .as_ref()
        .filter(|prefix| prefix.through_byte < prefix.fence_byte)
        .map_or(watermark.source_sequence, |prefix| prefix.through_byte);
    if through.is_some_and(|bound| bound <= contiguous_through) {
        return true;
    }
    if contiguous_through != watermark.source_sequence {
        return false;
    }
    let key = evertrace_store::session_import_row_id(receipt.source_instance_id.as_str());
    let fallback = evertrace_store::session_import_row_id(&receipt.source_session_ref);
    let Some([row]) = index
        .get(key.as_str())
        .or_else(|| index.get(fallback.as_str()))
        .map(Vec::as_slice)
    else {
        return false;
    };
    let Ok(Some(current)) = evertrace_store::session_import::restore_current(row) else {
        return false;
    };
    current.source_instance() == receipt.source_instance_id.as_str()
        && current.metadata.source_revision == receipt.source_revision
        && current.body_state == SessionBodyState::Imported
        && current.metadata.metadata_state == MetadataState::Indexed
        && watermark.source_sequence == current.metadata.file_size
}

fn atom_validity(
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    reference: &str,
) -> Option<evertrace_domain::semantic::ValidityInterval> {
    let mut rows = index.get(reference)?.iter().filter(|row| {
        row.object_kind.as_deref() == Some("atom_revision")
            && row.current_revision_id.as_deref() == Some(reference)
    });
    let row = rows.next()?;
    if rows.next().is_some() {
        return None;
    }
    let JournalPayload::AtomRecorded(atom) =
        serde_json::from_str(row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    if atom.revision_id.to_string() != reference
        || row.object_id.as_deref() != Some(atom.atom_id.to_string().as_str())
        || atom.validate().is_err()
    {
        return None;
    }
    Some(atom.validity_interval)
}

fn object_revision_order(
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    reference: &str,
) -> Option<evertrace_domain::query::RevisionOrderPosition> {
    let mut rows = index.get(reference)?.iter().filter(|row| {
        row.row_class == Some(ObjectRowClass::Object)
            && row.current_revision_id.as_deref() == Some(reference)
            && row
                .object_kind
                .as_deref()
                .is_some_and(evertrace_store::search::is_searchable_object_kind)
    });
    let row = rows.next()?;
    if rows.any(|other| other.row_id != row.row_id) || row.source_event_seq == 0 {
        return None;
    }
    Some(evertrace_domain::query::RevisionOrderPosition {
        anchor: row.object_id.clone()?,
        sequence: row.source_event_seq,
    })
}

fn canonical_episode_sources(
    frontier: u64,
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    readable: &BTreeSet<String>,
    references: &[String],
    deadline: std::time::Instant,
    open_heads_only: bool,
) -> Result<Vec<evertrace_store::SearchProjectionRow>, HumanGovernanceError> {
    use evertrace_store::projections::{READ_DEPENDENCY_BYTES, READ_DEPENDENCY_LIMIT};
    let mut lineage = std::collections::BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut bytes = 0u64;
    for reference in references {
        for row in index.get(reference.as_str()).into_iter().flatten() {
            if std::time::Instant::now() >= deadline {
                return Err(HumanGovernanceError::Store);
            }
            if row.object_kind.as_deref() == Some("work_episode")
                && row
                    .current_revision_id
                    .as_ref()
                    .is_some_and(|id| readable.contains(id))
            {
                for ancestor in row
                    .object_id
                    .as_deref()
                    .filter(|id| seen.insert(*id))
                    .and_then(|id| index.get(id))
                    .into_iter()
                    .flatten()
                {
                    if std::time::Instant::now() >= deadline {
                        return Err(HumanGovernanceError::Store);
                    }
                    if ancestor.object_kind.as_deref() == Some("work_episode")
                        && !lineage.contains_key(&ancestor.row_id)
                    {
                        bytes = bytes.saturating_add(
                            ancestor.payload_json.as_ref().map_or(0, |raw| raw.len()) as u64,
                        );
                        if lineage.len() >= READ_DEPENDENCY_LIMIT || bytes > READ_DEPENDENCY_BYTES {
                            return Err(HumanGovernanceError::Store);
                        }
                        lineage.insert(ancestor.row_id.clone(), (*ancestor).clone());
                    }
                }
            }
        }
    }
    let heads = evertrace_store::EpisodeCurrentView::from_rows(
        frontier,
        &lineage.into_values().collect::<Vec<_>>(),
    )
    .map_err(|_| HumanGovernanceError::Store)?;
    let mut sources = std::collections::BTreeMap::new();
    for reference in references {
        let Some(rows) = index.get(reference.as_str()) else {
            continue;
        };
        for row in rows {
            if row.object_kind.as_deref() != Some("work_episode")
                || !row
                    .current_revision_id
                    .as_ref()
                    .is_some_and(|id| readable.contains(id))
            {
                continue;
            }
            let id = row
                .object_id
                .as_deref()
                .ok_or(HumanGovernanceError::Store)?
                .parse()
                .map_err(|_| HumanGovernanceError::Store)?;
            let head = heads.episodes.get(&id).ok_or(HumanGovernanceError::Store)?;
            let current =
                row.current_revision_id.as_deref() == Some(head.revision_id.to_string().as_str());
            if open_heads_only
                && (!current
                    || head.lifecycle_status != evertrace_domain::work::EpisodeLifecycle::Open)
            {
                continue;
            }
            if std::time::Instant::now() >= deadline {
                return Err(HumanGovernanceError::Store);
            }
            let source = evertrace_store::query::canonical_work_episode_source(row, current)
                .map_err(|_| HumanGovernanceError::Store)?;
            sources.insert(source.row_id.clone(), source);
        }
    }
    Ok(sources.into_values().collect())
}

fn wiki_navigation_sources(
    snapshot: &ProjectionSnapshot,
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    readable: &BTreeSet<String>,
    now: i64,
    deadline: std::time::Instant,
) -> Result<std::collections::BTreeMap<String, BTreeSet<String>>, HumanGovernanceError> {
    use evertrace_domain::semantic::{AtomAuthority, AtomScope};
    let current = |reference: &str, kind: &str| {
        index
            .get(reference)?
            .iter()
            .copied()
            .filter(|row| {
                row.row_class == Some(ObjectRowClass::Object)
                    && row.object_kind.as_deref() == Some(kind)
            })
            .max_by_key(|row| row.source_event_seq)
    };
    let mut output = std::collections::BTreeMap::new();
    'pages: for row in snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("wiki_projection"))
    {
        export::check_deadline(deadline).map_err(|_| HumanGovernanceError::Store)?;
        let wiki = evertrace_store::projections::wiki_projection(row)
            .map_err(|_| HumanGovernanceError::Store)?
            .ok_or(HumanGovernanceError::Store)?;
        if wiki.compiler_version != 1 || wiki.source_watermark > snapshot.frontier {
            continue;
        }
        let mut sources = BTreeSet::new();
        for reference in &wiki.source_atom_ids {
            export::check_deadline(deadline).map_err(|_| HumanGovernanceError::Store)?;
            let Some(row) = current(&reference.to_string(), "atom_revision") else {
                continue 'pages;
            };
            let Some(revision) = row
                .current_revision_id
                .as_ref()
                .filter(|id| readable.contains(*id))
            else {
                continue 'pages;
            };
            let JournalPayload::AtomRecorded(atom) = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(HumanGovernanceError::Store)?,
            )
            .map_err(|_| HumanGovernanceError::Store)?
            else {
                return Err(HumanGovernanceError::Store);
            };
            // The search row has no shard coordinates. This is explicit all-repository navigation,
            // not the global support/policy channel and not a contextual instruction.
            if !matches!(atom.scope, AtomScope::Repository { .. })
                || atom.authority == AtomAuthority::ProjectPolicy
                || row.lifecycle.as_deref() != Some("active")
                || row.source_event_seq > wiki.source_watermark
                || !atom.validity_interval.contains(now)
                || !atom
                    .applicability_expr
                    .evaluate(&Default::default(), None)
                    .allows_enforcement()
            {
                continue 'pages;
            }
            sources.insert(revision.clone());
        }
        for reference in &wiki.source_episode_ids {
            export::check_deadline(deadline).map_err(|_| HumanGovernanceError::Store)?;
            let Some(row) = current(&reference.to_string(), "work_episode") else {
                continue 'pages;
            };
            let Some(revision) = row
                .current_revision_id
                .as_ref()
                .filter(|id| readable.contains(*id))
            else {
                continue 'pages;
            };
            if row.lifecycle.as_deref() != Some("closed")
                || row.source_event_seq > wiki.source_watermark
            {
                continue 'pages;
            }
            sources.insert(revision.clone());
        }
        output.insert(wiki.page_id.to_string(), sources);
    }
    Ok(output)
}

#[derive(Default)]
struct MatchedSources {
    references: BTreeSet<String>,
    contexts: BTreeSet<String>,
    checks: BTreeSet<String>,
    omitted: BTreeSet<String>,
    unknown: bool,
}

fn selected_shard_repository(
    selection: MemoryScopeSelection,
    snapshot: &ProjectionSnapshot,
) -> Result<Option<RepositoryId>, &'static str> {
    const UNRESOLVED: &str = "scope_unresolved";
    match selection {
        MemoryScopeSelection::Repository { repository_id } => Ok(Some(repository_id)),
        MemoryScopeSelection::Worktree { worktree_id } => {
            let key = evertrace_store::repository::worktree_row_id(&worktree_id);
            let mut rows = snapshot.data_rows().filter(|row| row.row_id == key);
            let row = rows.next().ok_or(UNRESOLVED)?;
            if rows.next().is_some() {
                return Err(UNRESOLVED);
            }
            let JournalPayload::WorktreeInstanceRecorded(tree) =
                serde_json::from_str(row.payload_json.as_deref().ok_or(UNRESOLVED)?)
                    .map_err(|_| UNRESOLVED)?
            else {
                return Err(UNRESOLVED);
            };
            if tree.worktree_instance_id != worktree_id || tree.validate().is_err() {
                return Err(UNRESOLVED);
            }
            // The retained identity authorizes the scope only. It says nothing about live Git state.
            Ok(Some(tree.repository_instance_id))
        }
        _ => Ok(None),
    }
}

fn task_search_shards(
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    id: evertrace_domain::ids::TaskId,
) -> Option<Vec<evertrace_domain::ids::RepositoryId>> {
    let [row] = index.get(id.to_string().as_str())?.as_slice() else {
        return None;
    };
    let JournalPayload::TaskRecorded(task) =
        serde_json::from_str(row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    if task.task_id != id || task.validate().is_err() {
        return None;
    }
    Some(
        task.scope_memberships
            .iter()
            .filter_map(|membership| membership.repository_instance_id)
            .collect(),
    )
}

impl HumanGovernanceService {
    async fn search_shards_readable(
        &self,
        repositories: &[evertrace_domain::ids::RepositoryId],
        authority: RepositoryReadAuthority<'_>,
        deadline: std::time::Instant,
    ) -> Result<bool, HumanGovernanceError> {
        Ok(self
            .blocked_search_shards(repositories, authority, deadline)
            .await?
            .is_some_and(|blocked| blocked.is_empty()))
    }

    async fn blocked_search_shards(
        &self,
        repositories: &[RepositoryId],
        authority: RepositoryReadAuthority<'_>,
        deadline: std::time::Instant,
    ) -> Result<Option<BTreeSet<RepositoryId>>, HumanGovernanceError> {
        let mut blocked = BTreeSet::new();
        for batch in repositories.chunks(usize::from(METADATA_READ_LIMIT)) {
            if std::time::Instant::now() >= deadline {
                return Ok(None);
            }
            let (denied, _) = crate::repository::repository_read_assessment(
                &self.writer,
                batch.iter().copied().collect(),
                &authority,
                deadline,
            )
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
            blocked.extend(denied);
        }
        Ok((std::time::Instant::now() < deadline).then_some(blocked))
    }

    async fn blocked_task_shards(
        &self,
        index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
        selection: MemoryScopeSelection,
        report: Option<&evertrace_codex::HostProbeReport>,
        deadline: std::time::Instant,
    ) -> Result<Option<BTreeSet<RepositoryId>>, HumanGovernanceError> {
        let MemoryScopeSelection::Task { task_id } = selection else {
            return Ok(None);
        };
        let Some(shards) = task_search_shards(index, task_id) else {
            return Ok(None);
        };
        self.blocked_search_shards(&shards, RepositoryReadAuthority::retained(report), deadline)
            .await
    }

    async fn source_dependency_access(
        &self,
        snapshot: &ProjectionSnapshot,
        index: &export::SearchReadIndex<'_>,
        dependencies: &BTreeSet<String>,
        deadline: std::time::Instant,
    ) -> Option<BTreeSet<String>> {
        let mut checks = BTreeSet::new();
        for reference in dependencies {
            let current = index
                .get(reference.as_str())?
                .iter()
                .filter(|row| row.row_class == Some(ObjectRowClass::Object))
                .max_by_key(|row| row.source_event_seq)?;
            self.readable_search_row(snapshot, current, index, deadline)
                .await
                .ok()?;
            checks.insert(current.row_id.clone());
        }
        Some(checks)
    }

    async fn matched_cue_sources(
        &self,
        snapshot: &ProjectionSnapshot,
        index: &export::SearchReadIndex<'_>,
        readable: &BTreeSet<String>,
        context: &SearchContext,
        deadline: std::time::Instant,
    ) -> Result<MatchedSources, HumanGovernanceError> {
        let triggers = crate::recall::RecallTriggerIndex::from_snapshot(snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let mut result = MatchedSources::default();
        if !triggers
            .entries
            .iter()
            .any(|entry| readable.contains(&entry.contract.source_revision_id.to_string()))
        {
            return Ok(result);
        }
        let episodes = evertrace_store::EpisodeCurrentView::from_snapshot(snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let mut remaining = (context.budget.candidates_remaining as usize).min(32);
        for episode in episodes.episodes.values() {
            if episode.lifecycle_status != evertrace_domain::work::EpisodeLifecycle::Open
                || !readable.contains(&episode.revision_id.to_string())
                || context.task_id.is_some_and(|id| id != episode.task_id)
                || context
                    .repository_id
                    .is_some_and(|id| Some(id) != episode.repository_instance_id)
                || context.worktree_id.is_some_and(|id| {
                    episode
                        .worktree_instance_id
                        .is_some_and(|current| current != id)
                })
            {
                continue;
            }
            let read = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.writer
                    .recall_source_contexts(episode.revision_id, remaining + 1),
            )
            .await;
            let Ok(Ok(mut contexts)) = read else {
                result.unknown = true;
                break;
            };
            let overflow = contexts.len() > remaining;
            if overflow {
                result.checks.insert(episode.revision_id.to_string());
                result.omitted.insert(episode.revision_id.to_string());
                contexts.truncate(remaining);
            }
            remaining -= contexts.len();
            for source in contexts {
                if source.frontier != snapshot.frontier {
                    result.unknown = true;
                    continue;
                }
                let (matches, unknown) = triggers.read_matches(&source, readable);
                if matches.is_empty() && !unknown {
                    continue;
                }
                let mut dependencies = matches
                    .iter()
                    .map(ToString::to_string)
                    .collect::<BTreeSet<_>>();
                dependencies.extend([
                    source.task.task_id.to_string(),
                    source.workstream.workstream_id.to_string(),
                    source.execution_lane.execution_lane_id.to_string(),
                    source.episode.revision_id.to_string(),
                    source.checkpoint.stable_key(),
                    source.binding.work_binding_revision_id.to_string(),
                ]);
                dependencies.extend(
                    source
                        .previous_checkpoint
                        .as_ref()
                        .map(|checkpoint| checkpoint.stable_key()),
                );
                dependencies.extend(
                    source
                        .checkpoint
                        .active_attempt_ids
                        .iter()
                        .map(ToString::to_string),
                );
                dependencies.extend(source.checkpoint.verifier_refs.iter().cloned());
                dependencies.extend(
                    source
                        .workstream
                        .active_worktree_instance_id
                        .map(|id| id.to_string()),
                );
                dependencies.extend(
                    source
                        .binding
                        .scope_effect_refs
                        .iter()
                        .map(ToString::to_string),
                );
                let Some(checks) = self
                    .source_dependency_access(snapshot, index, &dependencies, deadline)
                    .await
                else {
                    result.unknown = true;
                    continue;
                };
                result.checks.extend(checks);
                result.unknown |= unknown;
                if !matches.is_empty() {
                    result
                        .references
                        .extend(matches.iter().map(ToString::to_string));
                    result
                        .contexts
                        .insert(source.episode.revision_id.to_string());
                }
            }
            if overflow {
                break;
            }
        }
        Ok(result)
    }

    async fn recall_source_refs(
        &self,
        snapshot: &ProjectionSnapshot,
        index: &export::SearchReadIndex<'_>,
        readable: &BTreeSet<String>,
        deadline: std::time::Instant,
    ) -> Result<(BTreeSet<String>, BTreeSet<String>, bool), HumanGovernanceError> {
        let mut sources = BTreeSet::new();
        let mut checks = BTreeSet::new();
        let mut incomplete = false;
        for row in snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("recall_need"))
        {
            if std::time::Instant::now() >= deadline {
                return Err(HumanGovernanceError::Store);
            }
            let need = evertrace_store::projections::recall_need(row)
                .map_err(|_| HumanGovernanceError::Store)?
                .ok_or(HumanGovernanceError::Store)?;
            if need.obligation_state != evertrace_domain::recall::RecallObligationState::Active
                || !need
                    .source_revision_ids
                    .iter()
                    .all(|id| readable.contains(&id.to_string()))
            {
                continue;
            }
            let mut dependencies = need
                .source_revision_ids
                .iter()
                .map(ToString::to_string)
                .collect::<BTreeSet<_>>();
            dependencies.extend([
                need.task_id.to_string(),
                need.workstream_id.to_string(),
                need.execution_lane_id.to_string(),
                need.boundary_event_ref.clone(),
            ]);
            dependencies.extend(
                need.trigger_state
                    .binding_revision_id
                    .map(|id| id.to_string()),
            );
            dependencies.extend(
                need.trigger_state
                    .worktree_snapshot_id
                    .map(|id| id.to_string()),
            );
            dependencies.extend(
                need.trigger_state
                    .attempt_ids
                    .iter()
                    .map(ToString::to_string),
            );
            dependencies.extend(
                need.trigger_state
                    .scope_effect_refs
                    .iter()
                    .map(ToString::to_string),
            );
            dependencies.extend(need.recall_plan.supporting_evidence_refs.iter().cloned());
            let Some(dependency_checks) = self
                .source_dependency_access(snapshot, index, &dependencies, deadline)
                .await
            else {
                incomplete = true;
                continue;
            };
            checks.extend(dependency_checks);
            match crate::recall::revalidate_need(snapshot, &need, now_us()?)
                .map_err(|_| HumanGovernanceError::Store)?
            {
                crate::recall::RecallNeedValidity::Valid => {
                    sources.extend(need.source_revision_ids.iter().map(ToString::to_string));
                }
                crate::recall::RecallNeedValidity::Unavailable => incomplete = true,
                crate::recall::RecallNeedValidity::Terminal(_) => {}
            }
        }
        Ok((sources, checks, incomplete))
    }

    async fn search_checks_readable(
        &self,
        snapshot: &ProjectionSnapshot,
        index: &export::SearchReadIndex<'_>,
        checks: &BTreeSet<String>,
        archive_budget: &mut RelationArchiveBudget,
        deadline: std::time::Instant,
    ) -> bool {
        let mut verify_relation_archive = false;
        for reference in checks {
            let rows = index
                .get(reference.as_str())
                .into_iter()
                .flatten()
                .filter(|row| row.row_class == Some(ObjectRowClass::Object));
            let mut found = false;
            for row in rows {
                found = true;
                if self
                    .readable_search_row(snapshot, row, index, deadline)
                    .await
                    .is_err()
                {
                    return false;
                }
                if row.object_kind.as_deref() == Some("work_binding") {
                    let (Some(sources), Some(runtime)) = (
                        operation_binding_sources(row, index),
                        &self.runtime_snapshot,
                    ) else {
                        return false;
                    };
                    if !check_relation_archive(
                        &sources,
                        &self.writer,
                        &runtime.cas_dir,
                        index,
                        archive_budget,
                        deadline,
                    )
                    .await
                    {
                        return false;
                    }
                }
                verify_relation_archive |= index
                    .live_episode
                    .as_ref()
                    .is_some_and(|proof| proof.contains(row));
            }
            if !found {
                return false;
            }
        }
        if verify_relation_archive {
            let (Some(proof), Some(runtime)) = (&index.live_episode, &self.runtime_snapshot) else {
                return false;
            };
            return proof
                .check_archive(
                    &self.writer,
                    &runtime.cas_dir,
                    index,
                    archive_budget,
                    deadline,
                )
                .await;
        }
        true
    }

    async fn search_report(&self) -> Option<evertrace_codex::HostProbeReport> {
        match &self.session_report {
            Some(value) => value.read().await.clone(),
            None => None,
        }
    }

    async fn resume_hits(
        &self,
        query: &HumanSearchQuery,
        paging: &HumanSearchPaging,
        key: &evertrace_capture::DeviceKey,
        binding: &[u8],
        mut cursor: SearchHitCursor,
        started: std::time::Instant,
    ) -> Result<HumanSearchPage, HumanGovernanceError> {
        let reader = self.writer.read_handle();
        let state = (cursor.frontier, cursor.data_identity);
        let exhausted = "search_cursor_budget_exhausted";
        let deadline =
            started + std::time::Duration::from_micros(cursor.budget.latency_us_remaining);
        let run = async {
            const CONFLICT: &str = "search_cursor_conflict";
            let observed = reader
                .state()
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
            if observed != state {
                return Ok(cursor_unavailable(observed.0, CONFLICT));
            }
            let conflict = || Ok(cursor_unavailable(observed.0, CONFLICT));
            let Some(snapshot) = self
                .writer
                .current_objects_for_read()
                .await
                .map_err(|_| HumanGovernanceError::Store)?
            else {
                return conflict();
            };
            if snapshot.frontier != cursor.frontier {
                return conflict();
            }
            let report = self.search_report().await;
            if search_policy(report.as_ref()) != cursor.policy {
                return conflict();
            }
            let Ok(selected_repository) = selected_shard_repository(query.selection, &snapshot)
            else {
                return conflict();
            };
            if let Some(repository) = selected_repository
                && !self
                    .search_shards_readable(
                        &[repository],
                        RepositoryReadAuthority::retained(report.as_ref()),
                        deadline,
                    )
                    .await?
            {
                return conflict();
            }
            let index =
                export::SearchReadIndex::new(&snapshot, &query.facets, query.selection, deadline)
                    .map_err(|_| HumanGovernanceError::Store)?;
            let mut checks = BTreeSet::new();
            for hit in cursor.after.iter().chain(&cursor.remaining) {
                if let Some(deps) = cursor.wiki_inputs.get(&hit.candidate_id) {
                    checks.extend(deps.iter().cloned());
                } else {
                    checks.insert(hit.access_reference().to_owned());
                }
            }
            if !self
                .search_checks_readable(
                    &snapshot,
                    &index,
                    &checks,
                    &mut cursor.relation_archive_budget,
                    deadline,
                )
                .await
            {
                return conflict();
            }
            if !cursor.wiki_inputs.is_empty() {
                let readable =
                    wiki_navigation_sources(&snapshot, &index, &checks, now_us()?, deadline)?;
                if cursor
                    .wiki_inputs
                    .iter()
                    .any(|(id, inputs)| readable.get(id) != Some(inputs))
                {
                    return conflict();
                }
            }
            if let Some(repository) = cursor.inherited_repository
                && !self
                    .search_shards_readable(
                        &[repository],
                        RepositoryReadAuthority::observed(report.as_ref()),
                        deadline,
                    )
                    .await?
            {
                return conflict();
            }
            let current_report = self.search_report().await;
            // Hit checks cannot detect changes to shards that contributed no hits.
            if search_policy(current_report.as_ref()) != cursor.policy
                || self
                    .blocked_task_shards(&index, query.selection, current_report.as_ref(), deadline)
                    .await?
                    != cursor.blocked_task_shards
            {
                return conflict();
            }
            if reader
                .state()
                .await
                .map_err(|_| HumanGovernanceError::Store)?
                != state
            {
                return conflict();
            }
            let runtime = self
                .runtime_snapshot
                .as_ref()
                .ok_or(HumanGovernanceError::Store)?;
            let stamp = evertrace_store::SearchIndex::current_stamp(
                runtime
                    .data_dir()
                    .map_err(|_| HumanGovernanceError::Store)?,
                reader,
            )
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
            if stamp != (cursor.projection_version, cursor.frontier, cursor.frontier) {
                return Ok(cursor_unavailable(stamp.2, CONFLICT));
            }
            let remaining = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_micros();
            cursor.budget.latency_us_remaining = u64::try_from(remaining).unwrap_or_default();
            if cursor.budget.latency_us_remaining == 0 {
                return Ok(cursor_unavailable(cursor.frontier, exhausted));
            }
            let Some((hits, hit_page)) =
                cursor.take_page(query.selection, paging.limit, key, binding)?
            else {
                return Ok(cursor_unavailable(
                    cursor.frontier,
                    "search_cursor_size_exhausted",
                ));
            };
            let page = HumanSearchPage {
                result: SearchResult {
                    layer: cursor.layer,
                    projection_frontier: cursor.frontier,
                    authoritative_frontier: cursor.frontier,
                    candidates: Vec::new(),
                    completeness: cursor.completeness,
                    degraded_reasons: cursor.reasons,
                    omitted_refs: BTreeSet::new(),
                    budget: cursor.budget,
                },
                grounded_view: None,
                hit_window: Some(hits),
                hit_page: Some(hit_page),
            };
            if !page.validate() {
                return Err(HumanGovernanceError::Store);
            }
            Ok(page)
        };
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), run).await {
            Ok(result) => result,
            Err(_) => Ok(cursor_unavailable(state.0, exhausted)),
        }
    }

    /// Native read-only entry: no MCP binding, usage, cue, Returned or journal.
    pub async fn search(
        &self,
        query: Box<HumanSearchQuery>,
    ) -> Result<HumanSearchPage, HumanGovernanceError> {
        query
            .validate()
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let runtime = self
            .runtime_snapshot
            .as_ref()
            .ok_or(HumanGovernanceError::Store)?;
        let started = std::time::Instant::now();
        let deadline = started + presentation::READ_DEADLINE;
        // Load an existing key only. Reading never installs a key or imports data.
        let key = evertrace_capture::DeviceKeyStore::new(runtime.device_key_dir.clone())
            .load()
            .map_err(|_| HumanGovernanceError::Store)?;
        let binding = query
            .paging
            .as_ref()
            .map(|paging| {
                // Query bytes are authenticated in memory; the cursor carries neither query nor digest.
                serde_json::to_vec(&(
                    SEARCH_HIT_ORDER_REVISION,
                    &query.text,
                    &query.facets,
                    query.selection,
                    query.limit,
                    paging.limit,
                    self.effective_config_hash,
                ))
            })
            .transpose()
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if let (Some(paging), Some(binding)) = (&query.paging, binding.as_ref())
            && let Some(after) = &paging.after
        {
            let cursor = SearchHitCursor::open(&key, binding, after)?;
            return self
                .resume_hits(&query, paging, &key, binding, cursor, started)
                .await;
        }
        let protected = crate::search::protection::prepare(&query.text, &query.facets, &key)
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let future = async {
            let start_state = if binding.is_some() {
                Some(
                    self.writer
                        .read_handle()
                        .state()
                        .await
                        .map_err(|_| HumanGovernanceError::Store)?,
                )
            } else {
                None
            };
            let snapshot = self
                .writer
                .current_objects_for_read()
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
            let search = evertrace_store::SearchIndex::open_with_read_handle(
                runtime
                    .data_dir()
                    .map_err(|_| HumanGovernanceError::Store)?,
                self.writer.read_handle(),
            )
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
            let budget = || RetrievalBudget {
                candidates_remaining: 32,
                tokens_remaining: 16_384,
                latency_us_remaining: u64::try_from(
                    deadline
                        .saturating_duration_since(std::time::Instant::now())
                        .as_micros(),
                )
                .unwrap_or(u64::MAX),
                hops_remaining: 2,
                follow_ups_remaining: 1,
            };
            let Some(snapshot) = snapshot else {
                let pinned = search
                    .snapshot()
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?;
                let mut degraded_reasons = BTreeSet::from(["current_objects_unavailable".into()]);
                if pinned.frontier() != pinned.authoritative_frontier() {
                    degraded_reasons.insert("search_projection_stale".into());
                }
                return Ok(HumanSearchPage {
                    result: SearchResult {
                        layer: RetrievalLayer::A,
                        projection_frontier: pinned.frontier(),
                        authoritative_frontier: pinned.authoritative_frontier(),
                        candidates: Vec::new(),
                        completeness: RetrievalCompleteness::Unknown,
                        degraded_reasons,
                        omitted_refs: BTreeSet::new(),
                        budget: budget(),
                    },
                    grounded_view: None,
                    hit_window: None,
                    hit_page: None,
                });
            };
            let report = self.search_report().await;
            let selected_repository = selected_shard_repository(query.selection, &snapshot);
            let scope_gap = match selected_repository {
                Err(reason) => Some(reason),
                Ok(Some(repository)) => (!self
                    .search_shards_readable(
                        &[repository],
                        RepositoryReadAuthority::retained(report.as_ref()),
                        deadline,
                    )
                    .await?)
                    .then_some("source_read_restricted"),
                Ok(None) => None,
            };
            if let Some(reason) = scope_gap {
                // Report inaccessible selection, not whether any hidden candidate matches the query.
                let pinned = search
                    .snapshot_after_validated_frontier(snapshot.frontier)
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?;
                let mut page = cursor_unavailable(pinned.authoritative_frontier(), reason);
                page.result.projection_frontier = pinned.frontier();
                if pinned.frontier() != pinned.authoritative_frontier() {
                    page.result
                        .degraded_reasons
                        .insert("search_projection_stale".into());
                }
                return Ok(page);
            }
            let index = export::SearchReadIndex::new(
                &snapshot,
                &protected.facets,
                query.selection,
                deadline,
            )
            .map_err(|_| HumanGovernanceError::Store)?;
            let mut refs = BTreeSet::new();
            let mut proposals = BTreeSet::new();
            let mut unavailable = false;
            for row in snapshot.data_rows() {
                let kind = row.object_kind.as_deref().unwrap_or_default();
                if kind == "wiki_projection"
                    || !matches!(kind, "source_observation" | "work_episode")
                        && !evertrace_store::search::is_searchable_object_kind(kind)
                {
                    continue;
                }
                if std::time::Instant::now() >= deadline {
                    return Err(HumanGovernanceError::Store);
                }
                match self
                    .readable_search_row(&snapshot, row, &index, deadline)
                    .await
                {
                    Ok(()) => {
                        let id = if kind == "source_observation" {
                            row.object_id.as_ref()
                        } else {
                            row.current_revision_id.as_ref().or(row.object_id.as_ref())
                        };
                        if let Some(id) = id {
                            refs.insert(id.clone());
                            if kind == "revision_proposal_revision" {
                                proposals.insert(id.clone());
                            }
                        } else {
                            unavailable = true;
                        }
                    }
                    Err(export::Failure::Denied) => {}
                    Err(_) => unavailable = true,
                }
            }
            let mut relation_archive_budget = RelationArchiveBudget::default();
            let mut relation_archive_gap = false;
            if let Some(proof) = &index.live_episode
                && proof.admitted(&refs)
                && !proof
                    .check_archive(
                        &self.writer,
                        &runtime.cas_dir,
                        &index,
                        &mut relation_archive_budget,
                        deadline,
                    )
                    .await
            {
                proof.withhold(&mut refs);
                relation_archive_gap = true;
            }
            let mut binding_source = None;
            if query.selection == MemoryScopeSelection::All
                && let Some(row) = current_operation_binding(
                    &search,
                    &index,
                    &protected.facets,
                    snapshot.frontier,
                    deadline,
                )
                .await
                && self
                    .readable_search_row(&snapshot, row, &index, deadline)
                    .await
                    .is_ok()
                && let Some(sources) = operation_binding_sources(row, &index)
            {
                if check_relation_archive(
                    &sources,
                    &self.writer,
                    &runtime.cas_dir,
                    &index,
                    &mut relation_archive_budget,
                    deadline,
                )
                .await
                {
                    let source = evertrace_store::query::canonical_work_binding_source(row)
                        .map_err(|_| HumanGovernanceError::Store)?;
                    refs.extend(source.candidate_id.iter().cloned());
                    binding_source = Some(source);
                } else {
                    relation_archive_gap = true;
                }
            }
            let suppression = ObjectDeletionCurrentView::from_snapshot(&snapshot)
                .map_err(|_| HumanGovernanceError::Store)?;
            let boundary = query.selection.boundary();
            let (task_id, repository_id, worktree_id) = match boundary {
                Some(ScopeBoundary::Task { task_id }) => (Some(task_id), None, None),
                Some(ScopeBoundary::Repository { repository_id }) => {
                    (None, Some(repository_id), None)
                }
                Some(ScopeBoundary::Worktree { worktree_id }) => (None, None, Some(worktree_id)),
                None => (None, None, None),
            };
            let blocked_task_shards = self
                .blocked_task_shards(&index, query.selection, report.as_ref(), deadline)
                .await?;
            // A Task may have readable local work even with an unavailable repository shard.
            let task_restricted = task_id.is_some()
                && blocked_task_shards
                    .as_ref()
                    .is_none_or(|blocked| !blocked.is_empty());
            let budget = budget();
            if budget.latency_us_remaining == 0 {
                return Err(HumanGovernanceError::Store);
            }
            let exact_text_gap =
                unavailable_exact_source_text(&query, &protected.text, &refs, &index);
            let context = SearchContext {
                query_anchor: QueryAnchor::unavailable(),
                execution: None,
                intent: SearchIntent::HistoryLookup,
                raw_query: query.text,
                protected_query: protected.text,
                protected_facets: protected.protected_facets,
                query_facets: protected.facets,
                task_id,
                repository_id,
                worktree_id,
                suppression: SuppressionSnapshot::Current {
                    generation: suppression.generation,
                    ref_hashes: suppression.suppression_ref_hashes(),
                },
                budget,
            };
            let (mut semantics, mut checks) =
                crate::search::SemanticSearchResolution::for_human_read(
                    &snapshot,
                    &refs,
                    &index,
                    &context,
                    report.as_ref(),
                    now_us()?,
                    deadline,
                )
                .map_err(|_| HumanGovernanceError::Store)?;
            let mut inherited_repository = repository_id.filter(|_| {
                !semantics.inherited_global_constraints.is_empty()
                    && !context.query_facets.temporal_mode.has_temporal_predicate()
            });
            // The selection was already checked. Only an observed authority may
            // additionally supply inherited normative context.
            if inherited_repository.is_some() && report.is_none() {
                semantics.incomplete = true;
                inherited_repository = None;
            }
            if inherited_repository.is_none() {
                semantics.inherited_global_constraints.clear();
            }
            let semantics = std::sync::Arc::new(semantics);
            let facets = &context.query_facets;
            let wiki = if query.selection == MemoryScopeSelection::All
                && facets.answer_shape.is_none()
                && facets.relation_requirements.is_empty()
                && facets.temporal_qualifiers.is_empty()
                && !facets.temporal_mode.has_temporal_predicate()
                && facets.statement_role == StatementRole::Unknown
            {
                wiki_navigation_sources(&snapshot, &index, &refs, now_us()?, deadline)?
            } else {
                Default::default()
            };
            refs.extend(wiki.keys().cloned());
            let sequence_scope = source_sequence_scope(
                &index,
                &refs,
                &context.query_facets,
                prefix_count_limit(query.selection, &context),
                deadline,
            );
            if let Some(scope) = &sequence_scope {
                checks.insert(scope.source_anchor.to_string());
                if scope.source_prefix_ranges.is_some() {
                    checks.extend(scope.positions.keys().cloned());
                }
            }
            let (recall_sources, recall_checks, recall_incomplete) = self
                .recall_source_refs(&snapshot, &index, &refs, deadline)
                .await?;
            checks.extend(recall_checks);
            let matched = self
                .matched_cue_sources(&snapshot, &index, &refs, &context, deadline)
                .await?;
            checks.extend(matched.checks.iter().cloned());
            let mut source_references = context.query_facets.target_anchors.clone();
            source_references.extend(context.query_facets.exact_identifiers.iter().cloned());
            if index.contains_key(context.protected_query.as_str()) {
                source_references.push(context.protected_query.clone());
            }
            source_references.extend(recall_sources.iter().cloned());
            source_references.extend(matched.references.iter().chain(&matched.contexts).cloned());
            let canonical_sources = canonical_episode_sources(
                snapshot.frontier,
                &index,
                &refs,
                &source_references,
                deadline,
                false,
            )?;
            let relation_sources = |targets: &[String], readable: &BTreeSet<String>| {
                let mut sources = canonical_episode_sources(
                    snapshot.frontier,
                    &index,
                    readable,
                    targets,
                    deadline,
                    true,
                )
                .map_err(|_| crate::search::SearchError::Corrupt)?;
                if let Some(binding) = &binding_source
                    && binding
                        .candidate_id
                        .as_ref()
                        .is_some_and(|id| targets.contains(id) && readable.contains(id))
                {
                    sources.push(binding.clone());
                }
                Ok(sources)
            };
            let validity_query = matches!(context.query_facets.temporal_qualifiers.as_slice(), [qualifier] if qualifier.is_validity());
            let validity_timeline = context.query_facets.answer_shape
                == Some(AnswerShape::Timeline)
                && context.query_facets.temporal_qualifiers.is_empty();
            let latest = context.query_facets.answer_shape == Some(AnswerShape::Latest);
            let unqualified_latest = latest && context.query_facets.temporal_qualifiers.is_empty();
            let ordering = requested_ordering(&context.query_facets.temporal_qualifiers);
            let supersession_order = ordering == Some(TemporalOrdering::Supersession);
            let sequence_order = ordering == Some(TemporalOrdering::SourceSequence);
            let sequence_query = context
                .query_facets
                .temporal_qualifiers
                .iter()
                .any(|qualifier| qualifier.source_sequence_ref().is_some());
            let time_reader = |reference: &str| {
                let contextual = semantics.states.get(reference)
                    == Some(&SemanticResolution::Normative(
                        NormativeResolutionState::Active,
                    ));
                if sequence_query {
                    return contextual.then_some(crate::search::TemporalPosition::Object {
                        validity: None,
                        revision_order: None,
                        contextual,
                    });
                }
                if !validity_query && let Some(receipt) = source_receipt(&index, reference) {
                    let coverage_complete = (validity_timeline
                        || unqualified_latest
                        || supersession_order
                        || sequence_order)
                        && source_coverage_complete(&index, &receipt, None);
                    let revision_order = (validity_timeline
                        || unqualified_latest
                        || supersession_order)
                        .then(|| RevisionOrderPosition {
                            anchor: receipt.source_observation_id.to_string(),
                            sequence: 0,
                        });
                    let previous_revision = revision_order
                        .as_ref()
                        .and_then(|_| source_predecessor(&index, &receipt));
                    return Some(crate::search::TemporalPosition::Source {
                        receipt,
                        coverage_complete,
                        previous_revision,
                        revision_order,
                    });
                }
                let validity = (validity_query || validity_timeline)
                    .then(|| atom_validity(&index, reference))
                    .flatten();
                let revision_order = (unqualified_latest || supersession_order)
                    .then(|| object_revision_order(&index, reference))
                    .flatten();
                (validity.is_some() || revision_order.is_some()).then(|| {
                    crate::search::TemporalPosition::Object {
                        validity,
                        revision_order,
                        contextual,
                    }
                })
            };
            let time_query = sequence_query
                || context.query_facets.temporal_mode.has_temporal_predicate()
                || context
                    .query_facets
                    .answer_shape
                    .is_some_and(AnswerShape::uses_temporal_order);
            let mut time_refs: Option<BTreeSet<String>> = None;
            if context.query_facets.temporal_mode.has_temporal_predicate() && !sequence_query {
                for reference in &refs {
                    if std::time::Instant::now() >= deadline {
                        return Err(HumanGovernanceError::Store);
                    }
                    if time_reader(reference).is_some_and(|position| {
                        position.matches(&context.query_facets.temporal_qualifiers) == Some(false)
                            && !position.contextual()
                            && !context.query_facets.target_anchors.iter().any(|target| {
                                target == reference
                                    || index.get(reference.as_str()).is_some_and(|rows| {
                                        rows.iter()
                                            .any(|row| row.object_id.as_ref() == Some(target))
                                    })
                            })
                    }) {
                        time_refs
                            .get_or_insert_with(|| refs.clone())
                            .remove(reference);
                    }
                }
            }
            let revision_bridge =
                source_revision_bridge(&index, &refs, &context.query_facets, deadline);
            let time_scope = time_query.then_some(crate::search::TemporalReadScope {
                revision_bridge: revision_bridge
                    .as_ref()
                    .map(|(anchor, witnesses)| (anchor.as_str(), witnesses)),
                frontier: snapshot.frontier,
                read: &time_reader,
                readable_refs: time_refs.as_ref(),
                source_domain: !validity_query && !sequence_query,
            });
            let (mut page, projection_version) =
                crate::search::ProductionSearch::new(search.clone())
                    .with_canonical_sources(snapshot.frontier, canonical_sources)
                    .with_recall_sources(recall_sources)
                    .with_matched_sources(matched.references, matched.contexts)
                    .with_sequence_scope(sequence_scope)
                    .with_semantic_resolution(std::sync::Arc::clone(&semantics))
                    .with_validated_frontier(snapshot.frontier)
                    .with_method_proposals(proposals)
                    .with_readable_refs(snapshot.frontier, refs)
                    .retrieve(
                        context,
                        query.selection == MemoryScopeSelection::Global,
                        time_scope.as_ref(),
                        &relation_sources,
                    )
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?;
            if matched.unknown {
                page.result
                    .degraded_reasons
                    .insert("matched_cue_condition_unknown".into());
            }
            if !matched.omitted.is_empty() {
                page.result
                    .degraded_reasons
                    .insert("matched_cue_context_budget_exhausted".into());
                page.result
                    .omitted_refs
                    .extend(matched.omitted.iter().cloned());
            }
            // The empty-result explanation is neither a hit nor a paging operand.
            let exact_text_gap = exact_text_gap.filter(|_| {
                page.result.candidates.is_empty()
                    && page.hit_window.as_ref().is_none_or(Vec::is_empty)
            });
            checks.extend(exact_text_gap.iter().cloned());
            // Trust/report state can change without a new journal event. Recheck
            // returned and interpretation dependencies before exposing fields.
            let mut recheck = |id: &str| {
                if let Some(inputs) = wiki.get(id) {
                    checks.extend(inputs.iter().cloned());
                } else {
                    checks.insert(id.to_owned());
                }
            };
            let quoted = page.result.candidates.iter().map(|candidate| {
                if candidate.row_variant == SearchCandidateVariant::EvidenceSurface {
                    candidate.source_ref.as_str()
                } else {
                    candidate.candidate_id.as_str()
                }
            });
            for reference in quoted.chain(
                page.hit_window
                    .iter()
                    .flatten()
                    .map(HumanSearchHit::access_reference),
            ) {
                recheck(reference);
            }
            for id in &page.result.omitted_refs {
                if let Some((source, _, _)) =
                    evertrace_domain::evidence::EvidenceSurface::parse_candidate_ref(id)
                {
                    recheck(&source.to_string());
                } else {
                    recheck(id);
                }
            }
            let mut access_changed = !self
                .search_checks_readable(
                    &snapshot,
                    &index,
                    &checks,
                    &mut relation_archive_budget,
                    deadline,
                )
                .await;
            let current_report = self.search_report().await;
            if let Ok(Some(repository)) = selected_repository
                && !self
                    .search_shards_readable(
                        &[repository],
                        RepositoryReadAuthority::retained(current_report.as_ref()),
                        deadline,
                    )
                    .await?
            {
                access_changed = true;
            }
            access_changed |= self
                .blocked_task_shards(&index, query.selection, current_report.as_ref(), deadline)
                .await?
                != blocked_task_shards;
            if let Some(before) = start_state {
                let state = self
                    .writer
                    .read_handle()
                    .state()
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?;
                if before != state || before.0 != snapshot.frontier {
                    return Ok(cursor_unavailable(state.0, "search_cursor_conflict"));
                }
            }
            // The writer's authority read above must not wait while a search snapshot lease is held.
            let current = search
                .snapshot_after_validated_frontier(snapshot.frontier)
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
            let policy = search_policy(current_report.as_ref());
            if binding.is_some()
                && projection_version.is_some_and(|version| current.version() != version)
            {
                return Ok(cursor_unavailable(
                    current.authoritative_frontier(),
                    "search_cursor_conflict",
                ));
            }
            let boundary_changed = access_changed
                || policy != search_policy(report.as_ref())
                || current.frontier() != snapshot.frontier
                || current.authoritative_frontier() != snapshot.frontier;
            if boundary_changed {
                page.result.candidates.clear();
                page.result.omitted_refs.clear();
                page.result.completeness = RetrievalCompleteness::Unknown;
                page.result
                    .degraded_reasons
                    .insert("read_access_changed".into());
                page.grounded_view = None;
                page.hit_window = None;
            }
            if recall_incomplete {
                page.result
                    .degraded_reasons
                    .insert("recall_source_context_unavailable".into());
            }
            let projection_gap =
                unavailable || recall_incomplete || matched.unknown || !matched.omitted.is_empty();
            if projection_gap {
                page.result
                    .degraded_reasons
                    .insert("some_projection_access_unavailable".into());
            }
            let text_gap = !boundary_changed && exact_text_gap.is_some();
            if text_gap {
                page.result
                    .degraded_reasons
                    .insert("search_source_text_unavailable".into());
            }
            let task_restricted = task_restricted && !boundary_changed;
            if task_restricted {
                page.result
                    .degraded_reasons
                    .insert("source_read_restricted".into());
            }
            if relation_archive_gap {
                page.result
                    .degraded_reasons
                    .insert("search_relation_source_unavailable".into());
            }
            if projection_gap || text_gap || task_restricted || relation_archive_gap {
                if page.result.completeness == RetrievalCompleteness::Complete {
                    page.result.completeness = RetrievalCompleteness::Partial;
                }
                if let Some(view) = &mut page.grounded_view {
                    view.completeness = page.result.completeness;
                    if let Some(count) = &mut view.candidate_count {
                        count.value = None;
                        if count.source_prefix_ranges.is_some() {
                            view.candidate_count = view
                                .derive_candidate_count(&page.result.candidates, &BTreeSet::new());
                        }
                    }
                }
            }
            page.result.budget.latency_us_remaining = page.result.budget.latency_us_remaining.min(
                u64::try_from(
                    deadline
                        .saturating_duration_since(std::time::Instant::now())
                        .as_micros(),
                )
                .unwrap_or(u64::MAX),
            );
            if let (
                Some(paging),
                Some(binding),
                Some((frontier, data_identity)),
                Some(projection_version),
            ) = (
                query.paging.as_ref(),
                binding.as_ref(),
                start_state,
                projection_version,
            ) && let Some(remaining) = page.hit_window.take()
            {
                let wiki_inputs = remaining
                    .iter()
                    .filter_map(|hit| {
                        wiki.get(&hit.candidate_id)
                            .map(|inputs| (hit.candidate_id.clone(), inputs.clone()))
                    })
                    .collect();
                let mut cursor = SearchHitCursor {
                    frontier,
                    data_identity,
                    projection_version,
                    policy,
                    inherited_repository,
                    blocked_task_shards,
                    relation_archive_budget,
                    wiki_inputs,
                    after: None,
                    remaining,
                    layer: page.result.layer,
                    completeness: page.result.completeness,
                    reasons: page.result.degraded_reasons.clone(),
                    budget: page.result.budget.clone(),
                };
                let Some((hits, hit_page)) =
                    cursor.take_page(query.selection, paging.limit, &key, binding)?
                else {
                    return Ok(cursor_unavailable(frontier, "search_cursor_size_exhausted"));
                };
                page.hit_window = Some(hits);
                page.hit_page = Some(hit_page);
            }
            if !page.validate() {
                return Err(HumanGovernanceError::Store);
            }
            Ok(page)
        };
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
    }
}
