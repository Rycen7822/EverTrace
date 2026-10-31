use super::*;
use evertrace_domain::query::*;

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
        // Load an existing key only. Reading never installs a key or imports data.
        let key = evertrace_capture::DeviceKeyStore::new(runtime.device_key_dir.clone())
            .load()
            .map_err(|_| HumanGovernanceError::Store)?;
        let protected = evertrace_capture::protect(query.text.as_bytes(), &key)
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if protected.protected_bytes() != query.text.as_bytes() {
            // Raw secret text cannot enter a Native query, log, cursor or ledger.
            // Protected-query facet remapping remains required before enabling it.
            return Err(HumanGovernanceError::InvalidInput);
        }
        let deadline = std::time::Instant::now() + presentation::READ_DEADLINE;
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
                intent: SearchIntent::HistoryLookup,
                raw_query: query.text,
                query_facets: query.facets,
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
            let mut page = crate::search::ProductionSearch::new(search.clone())
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
