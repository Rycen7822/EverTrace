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

impl HumanGovernanceService {
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
                if kind != "source_observation"
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
            let mut page = crate::search::ProductionSearch::new(search.clone())
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
            if unavailable {
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
