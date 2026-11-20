use super::*;
use evertrace_domain::{
    query::*,
    semantic::{NormativeResolutionState, SemanticResolution},
};

fn source_sequence_scope(
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    readable: &BTreeSet<String>,
    facets: &QueryFacetSet,
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
    Some(crate::search::SourceSequenceScope {
        source_anchor: source_ref,
        positions,
        coverage_complete: source_coverage_complete(index, &anchor, through),
    })
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

#[derive(Default)]
struct MatchedSources {
    references: BTreeSet<String>,
    contexts: BTreeSet<String>,
    checks: BTreeSet<String>,
    omitted: BTreeSet<String>,
    unknown: bool,
}

impl HumanGovernanceService {
    async fn source_dependency_access(
        &self,
        snapshot: &ProjectionSnapshot,
        index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
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
            self.readable_indexed_row(snapshot, current, index, deadline)
                .await
                .ok()?;
            checks.insert(current.row_id.clone());
        }
        Some(checks)
    }

    async fn matched_cue_sources(
        &self,
        snapshot: &ProjectionSnapshot,
        index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
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
        index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
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
        let deadline = std::time::Instant::now() + presentation::READ_DEADLINE;
        // Load an existing key only. Reading never installs a key or imports data.
        let key = evertrace_capture::DeviceKeyStore::new(runtime.device_key_dir.clone())
            .load()
            .map_err(|_| HumanGovernanceError::Store)?;
        let protected = crate::search::protection::prepare(&query.text, &query.facets, &key)
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let future = async {
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
                });
            };
            let index = export::presentation_index(&snapshot, deadline)
                .map_err(|_| HumanGovernanceError::Store)?;
            let mut refs = BTreeSet::new();
            let mut proposals = BTreeSet::new();
            let mut unavailable = false;
            for row in snapshot.data_rows() {
                let kind = row.object_kind.as_deref().unwrap_or_default();
                if !matches!(kind, "source_observation" | "work_episode")
                    && !evertrace_store::search::is_searchable_object_kind(kind)
                {
                    continue;
                }
                if std::time::Instant::now() >= deadline {
                    return Err(HumanGovernanceError::Store);
                }
                match self
                    .readable_indexed_row(&snapshot, row, &index, deadline)
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
            let budget = budget();
            if budget.latency_us_remaining == 0 {
                return Err(HumanGovernanceError::Store);
            }
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
            let report = match &self.session_report {
                Some(value) => value.read().await.clone(),
                None => None,
            };
            let (semantics, mut checks) = crate::search::SemanticSearchResolution::for_human_read(
                &snapshot,
                &refs,
                &index,
                &context,
                report.as_ref(),
                now_us()?,
            )
            .map_err(|_| HumanGovernanceError::Store)?;
            let semantics = std::sync::Arc::new(semantics);
            let sequence_scope =
                source_sequence_scope(&index, &refs, &context.query_facets, deadline);
            if let Some(scope) = &sequence_scope {
                checks.insert(scope.source_anchor.to_string());
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
                canonical_episode_sources(
                    snapshot.frontier,
                    &index,
                    readable,
                    targets,
                    deadline,
                    true,
                )
                .map_err(|_| crate::search::SearchError::Corrupt)
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
            let mut page = crate::search::ProductionSearch::new(search.clone())
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
            // Trust/report state can change without a new journal event. Recheck
            // returned and interpretation dependencies before exposing fields.
            let mut access_changed = false;
            checks.extend(page.result.candidates.iter().map(|candidate| {
                if candidate.row_variant == SearchCandidateVariant::EvidenceSurface {
                    candidate.source_ref.clone()
                } else {
                    candidate.candidate_id.clone()
                }
            }));
            for reference in &checks {
                let Some(rows) = index.get(reference.as_str()).filter(|rows| {
                    rows.iter()
                        .any(|row| row.row_class == Some(ObjectRowClass::Object))
                }) else {
                    access_changed = true;
                    break;
                };
                for row in rows
                    .iter()
                    .filter(|row| row.row_class == Some(ObjectRowClass::Object))
                {
                    if self
                        .readable_indexed_row(&snapshot, row, &index, deadline)
                        .await
                        .is_err()
                    {
                        access_changed = true;
                        break;
                    }
                }
                if access_changed {
                    break;
                }
            }
            let current = search
                .snapshot_after_validated_frontier(snapshot.frontier)
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
            let current_report = match &self.session_report {
                Some(value) => value.read().await.clone(),
                None => None,
            };
            let policy = |value: Option<&evertrace_codex::HostProbeReport>| {
                value.map(|value| {
                    (
                        value.manifest().adapter_manifest_id.clone(),
                        value.current_project_policy_evidence(),
                    )
                })
            };
            if access_changed
                || policy(current_report.as_ref()) != policy(report.as_ref())
                || current.frontier() != snapshot.frontier
                || current.authoritative_frontier() != snapshot.frontier
            {
                page.result.candidates.clear();
                page.result.omitted_refs.clear();
                page.result.completeness = RetrievalCompleteness::Unknown;
                page.result
                    .degraded_reasons
                    .insert("read_access_changed".into());
                page.grounded_view = None;
            }
            if recall_incomplete {
                page.result
                    .degraded_reasons
                    .insert("recall_source_context_unavailable".into());
            }
            if unavailable || recall_incomplete || matched.unknown || !matched.omitted.is_empty() {
                page.result
                    .degraded_reasons
                    .insert("some_projection_access_unavailable".into());
                if page.result.completeness == RetrievalCompleteness::Complete {
                    page.result.completeness = RetrievalCompleteness::Partial;
                }
                if let Some(view) = &mut page.grounded_view {
                    view.completeness = page.result.completeness;
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
