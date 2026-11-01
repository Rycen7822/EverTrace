use super::*;
use evertrace_domain::query::*;

fn source_sequence_scope(
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    readable: &BTreeSet<String>,
    facets: &QueryFacetSet,
    deadline: std::time::Instant,
) -> Option<crate::search::SourceSequenceScope> {
    let [TemporalQualifier::SourceSequenceAtMost { source_ref, .. }] =
        facets.temporal_qualifiers.as_slice()
    else {
        return None;
    };
    let reference = source_ref.to_string();
    if facets.temporal_mode != TemporalMode::Sequence
        || !readable.contains(&reference)
        || std::time::Instant::now() >= deadline
    {
        return None;
    }
    let anchor = sequence_receipt(index, &reference)?;
    let mut positions = std::collections::BTreeMap::new();
    for reference in readable {
        if std::time::Instant::now() >= deadline {
            return None;
        }
        let Some(receipt) = sequence_receipt(index, reference) else {
            continue;
        };
        if receipt.source_instance_id == anchor.source_instance_id
            && receipt.source_revision == anchor.source_revision
        {
            positions.insert(reference.clone(), receipt.source_sequence);
        }
    }
    Some(crate::search::SourceSequenceScope {
        source_anchor: *source_ref,
        positions,
    })
}

fn sequence_receipt(
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    reference: &str,
) -> Option<Box<evertrace_domain::evidence::SourceReceipt>> {
    // Revision aliases also name derived surfaces; resolve the canonical fact.
    let key = format!("object:evidence:source_observation:{reference}");
    let [row] = index.get(key.as_str())?.as_slice() else {
        return None;
    };
    let JournalPayload::SourceObservationRecorded(observation) =
        serde_json::from_str(row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    let key = format!(
        "object:evidence:source_receipt:{}",
        observation.source_receipt_ref
    );
    let [row] = index.get(key.as_str())?.as_slice() else {
        return None;
    };
    let JournalPayload::SourceReceiptRecorded(receipt) =
        serde_json::from_str(row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    if receipt.source_observation_id.to_string() != reference
        || receipt.source_receipt_id != observation.source_receipt_ref
        || receipt.source_instance_id != observation.source_instance_id
        || receipt.source_revision != observation.source_revision
    {
        return None;
    }
    Some(receipt)
}

fn canonical_episode_sources(
    frontier: u64,
    index: &std::collections::BTreeMap<&str, Vec<&ObjectRow>>,
    readable: &BTreeSet<String>,
    references: &[String],
) -> Result<Vec<evertrace_store::SearchProjectionRow>, HumanGovernanceError> {
    let mut lineage = std::collections::BTreeMap::new();
    for reference in references {
        for row in index.get(reference.as_str()).into_iter().flatten() {
            if row.object_kind.as_deref() == Some("work_episode") {
                for ancestor in row
                    .object_id
                    .as_deref()
                    .and_then(|id| index.get(id))
                    .into_iter()
                    .flatten()
                {
                    if ancestor.object_kind.as_deref() == Some("work_episode") {
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
            let source = evertrace_store::query::canonical_work_episode_source(row, current)
                .map_err(|_| HumanGovernanceError::Store)?;
            sources.insert(source.row_id.clone(), source);
        }
    }
    Ok(sources.into_values().collect())
}

impl HumanGovernanceService {
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
            let mut available = true;
            let mut dependency_checks = BTreeSet::new();
            for reference in &dependencies {
                let current = index
                    .get(reference.as_str())
                    .and_then(|rows| rows.iter().max_by_key(|row| row.source_event_seq));
                let Some(current) = current else {
                    available = false;
                    break;
                };
                if self
                    .readable_indexed_row(snapshot, current, index, deadline)
                    .await
                    .is_err()
                {
                    available = false;
                    break;
                }
                dependency_checks.insert(current.row_id.clone());
            }
            if !available {
                incomplete = true;
                continue;
            }
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
                .project_objects()
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
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
            let latency = u64::try_from(
                deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .as_micros(),
            )
            .unwrap_or(u64::MAX);
            if latency == 0 {
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
                budget: RetrievalBudget {
                    candidates_remaining: 32,
                    tokens_remaining: 16_384,
                    latency_us_remaining: latency,
                    hops_remaining: 2,
                    follow_ups_remaining: 1,
                },
            };
            let search = evertrace_store::SearchIndex::open_with_read_handle(
                runtime
                    .data_dir()
                    .map_err(|_| HumanGovernanceError::Store)?,
                self.writer.read_handle(),
            )
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
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
            let sequence_scope =
                source_sequence_scope(&index, &refs, &context.query_facets, deadline);
            if let Some(scope) = &sequence_scope {
                checks.insert(scope.source_anchor.to_string());
            }
            let (recall_sources, recall_checks, recall_incomplete) = self
                .recall_source_refs(&snapshot, &index, &refs, deadline)
                .await?;
            checks.extend(recall_checks);
            let mut source_references = context.query_facets.target_anchors.clone();
            source_references.extend(context.query_facets.exact_identifiers.iter().cloned());
            if index.contains_key(context.protected_query.as_str()) {
                source_references.push(context.protected_query.clone());
            }
            source_references.extend(recall_sources.iter().cloned());
            let canonical_sources =
                canonical_episode_sources(snapshot.frontier, &index, &refs, &source_references)?;
            let mut page = crate::search::ProductionSearch::new(search.clone())
                .with_canonical_sources(snapshot.frontier, canonical_sources)
                .with_recall_sources(recall_sources)
                .with_sequence_scope(sequence_scope)
                .with_semantic_resolution(semantics)
                .with_validated_frontier(snapshot.frontier)
                .with_method_proposals(proposals)
                .with_readable_refs(snapshot.frontier, refs)
                .retrieve(context, query.selection == MemoryScopeSelection::Global)
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
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
                let Some(rows) = index.get(reference.as_str()) else {
                    access_changed = true;
                    break;
                };
                for row in rows {
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
            if unavailable || recall_incomplete {
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
