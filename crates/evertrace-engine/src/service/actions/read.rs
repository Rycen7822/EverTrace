use std::{collections::BTreeMap, future::Future, pin::Pin};

use super::*;

struct SearchCandidateReview {
    items: Vec<McpServiceItem>,
    omitted: BTreeSet<String>,
    unreadable_methods: BTreeSet<String>,
}

// Both normal Search and the legacy complete-snapshot consumers share the
// candidate classification, authorization, route accounting, and response
// presentation path. This is deliberately a request-local argument bundle,
// not another snapshot or reusable read abstraction: only preparation of the
// rows differs between the two callers.
struct SearchCandidateReviewInput<'a> {
    request_id: &'a RequestId,
    label: &'a str,
    anchor: &'a McpQueryAnchor,
    frontier: u64,
    rows: &'a [ObjectRow],
    context: &'a SearchContext,
    candidates: &'a [evertrace_domain::query::SearchCandidate],
    methods: &'a BTreeSet<String>,
    blocked_candidates: &'a BTreeSet<String>,
    unavailable_current: &'a BTreeSet<String>,
}

impl McpActionService {
    pub(super) async fn blocked_read_rows(
        &self,
        report: Option<&evertrace_codex::HostProbeReport>,
        snapshot: &ProjectionSnapshot,
        rows: &[&ObjectRow],
        repository_context: Option<evertrace_domain::ids::RepositoryId>,
    ) -> Result<BTreeSet<String>, McpServiceError> {
        self.blocked_read_rows_from_rows(report, &snapshot.rows, rows, repository_context, None)
            .await
    }

    async fn blocked_read_rows_from_rows(
        &self,
        report: Option<&evertrace_codex::HostProbeReport>,
        all_rows: &[ObjectRow],
        rows: &[&ObjectRow],
        repository_context: Option<evertrace_domain::ids::RepositoryId>,
        deadline: Option<std::time::Instant>,
    ) -> Result<BTreeSet<String>, McpServiceError> {
        let lookup = all_rows
            .iter()
            .map(|row| (row.row_id.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        let mut blocked = crate::session_import::blocked_source_rows_from_rows_before(
            &self.writer,
            report,
            all_rows,
            rows,
            self.runtime_snapshot.effective_config_hash,
            Some(&lookup),
            deadline,
        )
        .await
        .map_err(|_| McpServiceError::Store)?;
        let scopes = crate::repository::row_repository_contexts_from_scopes(all_rows.iter(), rows)
            .map_err(|_| McpServiceError::Store)?;
        let mut ids = scopes.values().flatten().copied().collect::<BTreeSet<_>>();
        ids.extend(repository_context);
        let repositories = match deadline {
            Some(deadline) => {
                crate::repository::blocked_repositories_before(
                    &self.writer,
                    ids,
                    report,
                    self.runtime_snapshot.effective_config_hash,
                    deadline,
                )
                .await
            }
            None => {
                crate::repository::blocked_repositories(
                    &self.writer,
                    ids,
                    report,
                    self.runtime_snapshot.effective_config_hash,
                )
                .await
            }
        }
        .map_err(|_| McpServiceError::Store)?;
        if repository_context.is_some_and(|id| repositories.contains(&id)) {
            blocked.extend(rows.iter().map(|row| row.row_id.clone()));
            return Ok(blocked);
        }
        blocked.extend(
            scopes
                .into_iter()
                .filter(|(_, ids)| !ids.is_disjoint(&repositories))
                .map(|(row, _)| row.to_owned()),
        );
        Ok(blocked)
    }

    pub(super) fn normal_search(
        &self,
        request_id: RequestId,
        scope: NormalSearchScope,
        query: String,
    ) -> Pin<Box<dyn Future<Output = Result<McpServiceResult, McpServiceError>> + Send + '_>> {
        Box::pin(self.normal_search_inner(request_id, scope, query, false))
    }

    async fn normal_search_inner(
        &self,
        request_id: RequestId,
        scope: NormalSearchScope,
        query: String,
        retried_anchor: bool,
    ) -> Result<McpServiceResult, McpServiceError> {
        let label = scope_label_for_binding(&scope.binding);
        let remaining = scope
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        let latency_us = u64::try_from(remaining.as_micros()).unwrap_or(u64::MAX);
        if latency_us == 0 {
            return Ok(empty_result(
                request_id,
                McpServiceStatus::Partial,
                &label,
                "partial",
                ["search_deadline_exhausted"],
            ));
        }
        let context = SearchContext {
            intent: SearchIntent::StageAssistance,
            raw_query: query.clone(),
            query_facets: QueryFacetSet {
                parse_status: FacetParseStatus::Unknown,
                exact_identifiers: Vec::new(),
                condition_literals: Vec::new(),
                relation_requirements: Vec::new(),
                polarity: Polarity::Positive,
                explicit_exclusions: Vec::new(),
                temporal_mode: TemporalMode::Current,
                temporal_qualifiers: Vec::new(),
                quantity_constraints: vec![QuantityConstraint::ResultLimit { limit: 3 }],
                scope_boundary: None,
                source_boundary: None,
                answer_shape: None,
                lifecycle_boundary: LifecycleBoundary::Active,
            },
            task_id: scope.anchor.task_id,
            repository_id: scope.anchor.repository_id,
            worktree_id: scope.anchor.worktree_id,
            suppression: deletion_suppression_rows(scope.context.frontier, &scope.context.rows)?,
            budget: RetrievalBudget {
                candidates_remaining: 3,
                tokens_remaining: 1_200,
                latency_us_remaining: latency_us,
                hops_remaining: 0,
                follow_ups_remaining: 0,
            },
        };
        let include_probationary = self.operation_config.as_ref().map_or_else(
            || evertrace_domain::config::ProcedureConfig::default().include_probationary,
            |config| config.config().procedure.include_probationary,
        );
        let searchable_procedure_revisions =
            crate::procedure::ProcedureUsageCurrentView::from_promotion_rows(
                scope.context.frontier,
                &scope.context.rows,
            )
            .map_err(|_| McpServiceError::Store)?
            .searchable_procedure_revisions(include_probationary);
        let report = match &self.session_report {
            Some(report) => report.read().await.clone(),
            None => None,
        };
        let method_deadline = scope.deadline;
        let methods = crate::jobs::procedure::readable_revisions_from_rows(
            &self.writer,
            &scope.context.rows,
            scope
                .binding
                .repository_report
                .as_deref()
                .or(report.as_ref()),
            self.runtime_snapshot.effective_config_hash,
            (scope.anchor.repository_id, scope.anchor.worktree_id),
            None,
            method_deadline,
        )
        .await
        .map_err(|_| McpServiceError::Store)?;
        let found = ProductionSearch::new(self.search_index.clone())
            .with_validated_frontier(scope.context.frontier)
            .with_method_proposals(methods)
            .with_procedure_revisions(searchable_procedure_revisions)
            .search(context.clone())
            .await
            .map_err(|_| McpServiceError::Store)?;
        let selected_candidates = found.candidates.iter().take(3).collect::<Vec<_>>();
        let candidate_ids = selected_candidates
            .iter()
            .map(|candidate| candidate.candidate_id.clone())
            // Reserve room for each selected candidate's source reference in
            // the bounded writer read below.
            .chain(found.omitted_refs.iter().take(59).cloned())
            .collect::<BTreeSet<_>>();
        let mut candidate_references = candidate_ids.clone();
        candidate_references.extend(
            selected_candidates
                .iter()
                .map(|candidate| candidate.source_ref.clone()),
        );
        let has_procedure = selected_candidates
            .iter()
            .any(|candidate| candidate.object_kind.as_deref() == Some("procedure_revision"));
        let candidate_context = if candidate_ids.is_empty() {
            None
        } else {
            Some(
                self.writer
                    .normal_search_candidate_context(
                        scope.request.clone(),
                        evertrace_store::NormalSearchCandidateRequest {
                            identifiers: candidate_references.iter().cloned().collect(),
                            task_id: scope.anchor.task_id,
                            repository_id: scope.anchor.repository_id,
                            worktree_id: scope.anchor.worktree_id,
                            include_procedure_route: has_procedure,
                            include_derived_candidate_rows: selected_candidates.iter().any(
                                |candidate| {
                                    matches!(
                                        candidate.object_kind.as_deref(),
                                        Some(
                                            "scenario"
                                                | "core_membership"
                                                | "global_support_contract"
                                                | "global_support_validation"
                                                | "wiki_projection"
                                        )
                                    )
                                },
                            ),
                        },
                    )
                    .await
                    .map_err(|_| McpServiceError::Store)?,
            )
        };
        if let Some(fresh) = &candidate_context {
            let fresh_anchor = super::super::scope::resolve_current_anchor(
                &fresh.scope,
                &scope.binding,
                &scope.client_cwd,
            );
            if fresh_anchor.as_ref() != Some(&scope.anchor) {
                if !retried_anchor && let Some(anchor) = fresh_anchor {
                    return Box::pin(self.normal_search_inner(
                        request_id,
                        NormalSearchScope {
                            binding: scope.binding,
                            anchor,
                            client_cwd: scope.client_cwd,
                            deadline: scope.deadline,
                            request: scope.request,
                            context: candidate_context.expect("checked above"),
                        },
                        query,
                        true,
                    ))
                    .await;
                }
                return Ok(scope_unresolved(request_id));
            }
        }
        let stale_current_candidate = candidate_context.as_ref().is_some_and(|fresh| {
            found.candidates.iter().take(3).any(|candidate| {
                candidate.row_variant == evertrace_domain::query::SearchCandidateVariant::Object
                    && !matches!(
                        select_object_row_rows(&fresh.rows, &candidate.candidate_id),
                        Ok(Some((_, true)))
                    )
            })
        });
        if stale_current_candidate && !retried_anchor {
            return Box::pin(self.normal_search_inner(
                request_id,
                NormalSearchScope {
                    binding: scope.binding,
                    anchor: scope.anchor,
                    client_cwd: scope.client_cwd,
                    deadline: scope.deadline,
                    request: scope.request,
                    context: candidate_context.expect("checked above"),
                },
                query,
                true,
            ))
            .await;
        }
        let mut blocked_candidates = BTreeSet::new();
        let mut methods = BTreeSet::new();
        let mut unavailable_current = BTreeSet::new();
        if let Some(candidate_context) = &candidate_context {
            let selected = candidate_context
                .rows
                .iter()
                .filter(|row| {
                    candidate_references.contains(&row.row_id)
                        || row
                            .object_id
                            .as_deref()
                            .is_some_and(|id| candidate_references.contains(id))
                        || row
                            .current_revision_id
                            .as_deref()
                            .is_some_and(|id| candidate_references.contains(id))
                })
                .take(65)
                .collect::<Vec<_>>();
            let blocked = self
                .blocked_read_rows_from_rows(
                    scope
                        .binding
                        .repository_report
                        .as_deref()
                        .or(report.as_ref()),
                    &candidate_context.rows,
                    &selected,
                    scope.anchor.repository_id,
                    Some(method_deadline),
                )
                .await?;
            let reviewed_candidates = selected_candidates
                .iter()
                .filter(|candidate| {
                    selected
                        .iter()
                        .any(|row| normal_search_candidate_matches_row(candidate, row))
                })
                .map(|candidate| candidate.candidate_id.clone())
                .collect::<BTreeSet<_>>();
            blocked_candidates = selected_candidates
                .iter()
                .filter(|candidate| {
                    selected.iter().any(|row| {
                        normal_search_candidate_matches_row(candidate, row)
                            && blocked.contains(&row.row_id)
                    })
                })
                .map(|candidate| candidate.candidate_id.clone())
                .collect();
            // Continuations that were not part of the bounded current review
            // never become a permission bypass.
            blocked_candidates.extend(
                candidate_ids
                    .iter()
                    .filter(|reference| !reviewed_candidates.contains(*reference))
                    .cloned(),
            );
            let method_hits = found
                .candidates
                .iter()
                .take(3)
                .filter(|candidate| {
                    candidate.object_kind.as_deref() == Some("revision_proposal_revision")
                })
                .map(|candidate| candidate.candidate_id.clone())
                .collect::<BTreeSet<_>>();
            if !method_hits.is_empty() {
                methods = crate::jobs::procedure::readable_revisions_from_rows(
                    &self.writer,
                    &candidate_context.rows,
                    scope
                        .binding
                        .repository_report
                        .as_deref()
                        .or(report.as_ref()),
                    self.runtime_snapshot.effective_config_hash,
                    (scope.anchor.repository_id, scope.anchor.worktree_id),
                    Some(&method_hits),
                    method_deadline,
                )
                .await
                .map_err(|_| McpServiceError::Store)?;
            }
            unavailable_current.extend(
                found
                    .candidates
                    .iter()
                    .take(3)
                    .filter(|candidate| {
                        candidate.row_variant
                            == evertrace_domain::query::SearchCandidateVariant::Object
                            && !matches!(
                                select_object_row_rows(
                                    &candidate_context.rows,
                                    &candidate.candidate_id,
                                ),
                                Ok(Some((_, true)))
                            )
                    })
                    .map(|candidate| candidate.candidate_id.clone()),
            );
        }
        let (review_frontier, review_rows) = candidate_context
            .as_ref()
            .map(|context| (context.frontier, context.rows.as_slice()))
            .unwrap_or((scope.context.frontier, scope.context.rows.as_slice()));
        let mut review = self
            .classify_search_candidates(SearchCandidateReviewInput {
                request_id: &request_id,
                label: &label,
                anchor: &scope.anchor,
                frontier: review_frontier,
                rows: review_rows,
                context: &context,
                candidates: &found.candidates,
                methods: &methods,
                blocked_candidates: &blocked_candidates,
                unavailable_current: &unavailable_current,
            })
            .await?;
        // The original normal path reports an unreadable method proposal as
        // truncated rather than presenting it; keep that output contract
        // while sharing the selection and route implementation above.
        review.omitted.extend(review.unreadable_methods);
        Ok(Self::search_result_from_review(
            request_id,
            label,
            scope.anchor.cwd_only,
            found,
            review.items,
            review.omitted,
            blocked_candidates,
        ))
    }

    async fn classify_search_candidates(
        &self,
        input: SearchCandidateReviewInput<'_>,
    ) -> Result<SearchCandidateReview, McpServiceError> {
        let SearchCandidateReviewInput {
            request_id,
            label,
            anchor,
            frontier,
            rows,
            context,
            candidates,
            methods,
            blocked_candidates,
            unavailable_current,
        } = input;
        let now = unix_time_us_for_mcp();
        let mut items = Vec::new();
        let mut omitted = BTreeSet::new();
        let mut unreadable_methods = BTreeSet::new();
        let mut procedure_revisions = Vec::new();
        for candidate in candidates.iter().take(3) {
            if candidate.object_kind.as_deref() == Some("revision_proposal_revision")
                && !methods.contains(&candidate.candidate_id)
            {
                unreadable_methods.insert(candidate.candidate_id.clone());
                continue;
            }
            if blocked_candidates.contains(candidate.candidate_id.as_str()) {
                continue;
            }
            if unavailable_current.contains(&candidate.candidate_id) {
                // A bounded recomputation handles a newly stale current
                // candidate once.  If it remains unprovable, never present
                // an old body as current.
                omitted.insert(candidate.candidate_id.clone());
                continue;
            }
            if candidate.object_kind.as_deref() == Some("procedure_revision") {
                procedure_revisions.push(candidate.candidate_id.clone());
                continue;
            }
            match classify_search_candidate_rows(rows, label, candidate, now) {
                Some(item) => items.push(item),
                None => {
                    omitted.insert(candidate.candidate_id.clone());
                }
            }
        }
        if !procedure_revisions.is_empty() {
            let procedure_view =
                crate::procedure::ProcedureUsageCurrentView::from_rows(frontier, rows)
                    .map_err(|_| McpServiceError::Store)?;
            let routed = procedure_view
                .route_search_rows(rows, anchor, context, &procedure_revisions)
                .map_err(|_| McpServiceError::Store)?;
            omitted.extend(procedure_revisions);
            let command_id =
                CommandId::from_uuid(request_id.as_uuid()).map_err(|_| McpServiceError::Store)?;
            let mut route_events = Vec::new();
            for item in routed.items {
                let (Some(workstream), Some(episode)) =
                    (anchor.workstream_id, anchor.episode_revision_id)
                else {
                    continue;
                };
                let route_context = ProposalCommandContext {
                    command_id,
                    occurred_at_us: now,
                    effective_config_hash: self.runtime_snapshot.effective_config_hash,
                    algorithm_revision: "s34-mcp-procedure-route-v1".into(),
                };
                let resolution = crate::procedure::begin_procedure_usage(
                    &procedure_view,
                    route_context.clone(),
                    &item,
                    workstream,
                    episode,
                )
                .map_err(|_| McpServiceError::Store)?;
                match resolution {
                    crate::procedure::ProcedureUsageResolution::Command { command, .. } => {
                        route_events.extend_from_slice(command.events())
                    }
                    crate::procedure::ProcedureUsageResolution::NoDelta(usage)
                        if usage.stage
                            == evertrace_domain::procedure::ProcedureUsageStage::Routed =>
                    {
                        let command = procedure_view
                            .reroute_pending_usage(route_context, &usage)
                            .map_err(|_| McpServiceError::Store)?;
                        route_events.extend_from_slice(command.events());
                    }
                    crate::procedure::ProcedureUsageResolution::NoDelta(_)
                    | crate::procedure::ProcedureUsageResolution::HistoricalRouteMismatch
                    | crate::procedure::ProcedureUsageResolution::UnprovenContext => {}
                }
                let apply = item.decision == crate::procedure::ProcedureDecision::Apply;
                let mut presentation = serde_json::json!({
                    "decision": if apply { "APPLY" } else { "DEFER" },
                    "reason": item.reason,
                    "guardrail_only": item.mode == crate::procedure::ProcedureGuidanceMode::GuardrailOnly,
                    "avoid": item.avoid,
                    "excludes": item.excludes,
                    "pitfalls": item.pitfalls,
                });
                if apply && item.mode == crate::procedure::ProcedureGuidanceMode::Normal {
                    presentation["actions"] =
                        serde_json::to_value(&item.actions).map_err(|_| McpServiceError::Store)?;
                    presentation["done"] =
                        serde_json::to_value(&item.done).map_err(|_| McpServiceError::Store)?;
                }
                let text =
                    serde_json::to_string(&presentation).map_err(|_| McpServiceError::Store)?;
                omitted.remove(&item.revision_id.to_string());
                items.push(McpServiceItem {
                    partition: McpItemPartition::Procedure,
                    kind: "procedure_revision".into(),
                    object_ref: Some(item.procedure_id.to_string()),
                    object_revision_ref: Some(item.revision_id.to_string()),
                    source_revision_ref: None,
                    scope: Some(label.into()),
                    applicability: Some(if apply { "apply" } else { "defer" }.into()),
                    authority: Some("none".into()),
                    content_trust: ContentTrust::UntrustedSourceContent,
                    capture_completeness: None,
                    instruction_authority: InstructionAuthority::None,
                    text: Some(text),
                });
            }
            if !route_events.is_empty() {
                let command = JournalCommand::new(command_id, route_events)
                    .map_err(|_| McpServiceError::Store)?;
                self.writer
                    .commit_if_frontier(command, now, frontier)
                    .await
                    .map_err(|_| McpServiceError::Store)?;
            }
        }
        Ok(SearchCandidateReview {
            items,
            omitted,
            unreadable_methods,
        })
    }

    fn search_result_from_review(
        request_id: RequestId,
        label: String,
        cwd_only: bool,
        found: evertrace_domain::query::SearchResult,
        items: Vec<McpServiceItem>,
        classification_omitted: BTreeSet<String>,
        blocked_candidates: BTreeSet<String>,
    ) -> McpServiceResult {
        let mut completeness = match found.completeness {
            RetrievalCompleteness::Complete => "complete",
            RetrievalCompleteness::Partial => "partial",
            RetrievalCompleteness::Conflicted => "conflicted",
            RetrievalCompleteness::Unknown => "unknown",
        };
        let mut status = if found.candidates.is_empty() {
            McpServiceStatus::NoMatch
        } else if found.degraded_reasons.contains("search_projection_stale") {
            McpServiceStatus::Partial
        } else if found.degraded_reasons.is_empty() {
            McpServiceStatus::Ok
        } else {
            McpServiceStatus::DegradedIndex
        };
        let mut omitted_refs = found.omitted_refs;
        omitted_refs.extend(classification_omitted);
        omitted_refs.retain(|reference| !blocked_candidates.contains(reference.as_str()));
        if !blocked_candidates.is_empty() && items.is_empty() && omitted_refs.is_empty() {
            status = McpServiceStatus::NoMatch;
        }
        if !omitted_refs.is_empty() {
            status = McpServiceStatus::Partial;
            completeness = "partial";
        }
        McpServiceResult {
            request_id,
            status,
            scope: label,
            freshness: if found.projection_frontier == found.authoritative_frontier {
                "current".into()
            } else {
                "stale".into()
            },
            completeness: completeness.into(),
            items,
            warnings: {
                let mut warnings = found.degraded_reasons.into_iter().collect::<Vec<_>>();
                if cwd_only {
                    warnings.push("cwd_only_scope".into());
                }
                if !blocked_candidates.is_empty() {
                    warnings.push("source_read_restricted".into());
                }
                warnings
            },
            truncated: !omitted_refs.is_empty(),
            next_refs: omitted_refs.into_iter().take(32).collect(),
        }
    }

    pub(super) async fn search(
        &self,
        request_id: RequestId,
        scope: McpRequestScope,
        query: String,
    ) -> Result<McpServiceResult, McpServiceError> {
        if query == "@due" {
            return self.search_due(request_id, scope).await;
        }
        let context = SearchContext {
            intent: SearchIntent::StageAssistance,
            raw_query: query,
            query_facets: QueryFacetSet {
                parse_status: FacetParseStatus::Unknown,
                exact_identifiers: Vec::new(),
                condition_literals: Vec::new(),
                relation_requirements: Vec::new(),
                polarity: Polarity::Positive,
                explicit_exclusions: Vec::new(),
                temporal_mode: TemporalMode::Current,
                temporal_qualifiers: Vec::new(),
                quantity_constraints: vec![QuantityConstraint::ResultLimit { limit: 3 }],
                scope_boundary: None,
                source_boundary: None,
                answer_shape: None,
                lifecycle_boundary: LifecycleBoundary::Active,
            },
            task_id: scope.anchor.task_id,
            repository_id: scope.anchor.repository_id,
            worktree_id: scope.anchor.worktree_id,
            suppression: deletion_suppression(&scope.snapshot)?,
            budget: RetrievalBudget {
                candidates_remaining: 3,
                tokens_remaining: 1_200,
                latency_us_remaining: 750_000,
                hops_remaining: 0,
                follow_ups_remaining: 0,
            },
        };
        let include_probationary = self.operation_config.as_ref().map_or_else(
            || evertrace_domain::config::ProcedureConfig::default().include_probationary,
            |config| config.config().procedure.include_probationary,
        );
        let searchable_procedure_revisions =
            crate::procedure::ProcedureUsageCurrentView::from_promotion_snapshot(&scope.snapshot)
                .map_err(|_| McpServiceError::Store)?
                .searchable_procedure_revisions(include_probationary);
        let report = match &self.session_report {
            Some(report) => report.read().await.clone(),
            None => None,
        };
        let method_deadline = std::time::Instant::now()
            + std::time::Duration::from_micros(context.budget.latency_us_remaining);
        let methods = crate::jobs::procedure::readable_revisions(
            &self.writer,
            &scope.snapshot,
            scope
                .binding
                .repository_report
                .as_deref()
                .or(report.as_ref()),
            self.runtime_snapshot.effective_config_hash,
            (scope.anchor.repository_id, scope.anchor.worktree_id),
            None,
            method_deadline,
        )
        .await
        .map_err(|_| McpServiceError::Store)?;
        let found = ProductionSearch::new(self.search_index.clone())
            .with_validated_frontier(scope.snapshot.frontier)
            .with_method_proposals(methods)
            .with_procedure_revisions(searchable_procedure_revisions)
            .search(context.clone())
            .await
            .map_err(|_| McpServiceError::Store)?;
        let candidate_ids = found
            .candidates
            .iter()
            .take(3)
            .map(|candidate| candidate.candidate_id.as_str())
            .chain(found.omitted_refs.iter().map(String::as_str))
            .collect::<BTreeSet<_>>();
        let selected = scope
            .snapshot
            .data_rows()
            .filter(|row| {
                candidate_ids.contains(row.row_id.as_str())
                    || row
                        .object_id
                        .as_deref()
                        .is_some_and(|id| candidate_ids.contains(id))
                    || row
                        .current_revision_id
                        .as_deref()
                        .is_some_and(|id| candidate_ids.contains(id))
            })
            .take(65)
            .collect::<Vec<_>>();
        let report = match &self.session_report {
            Some(report) => report.read().await.clone(),
            None => None,
        };
        let blocked = self
            .blocked_read_rows(
                scope
                    .binding
                    .repository_report
                    .as_deref()
                    .or(report.as_ref()),
                &scope.snapshot,
                &selected,
                scope.anchor.repository_id,
            )
            .await
            .map_err(|_| McpServiceError::Store)?;
        let reviewed_candidates = selected
            .iter()
            .flat_map(|row| {
                [
                    row.object_id.as_deref(),
                    row.current_revision_id.as_deref(),
                    Some(row.row_id.as_str()),
                ]
            })
            .flatten()
            .collect::<BTreeSet<_>>();
        let mut blocked_candidates = selected
            .iter()
            .filter(|row| blocked.contains(&row.row_id))
            .flat_map(|row| {
                [
                    row.object_id.as_deref(),
                    row.current_revision_id.as_deref(),
                    Some(row.row_id.as_str()),
                ]
            })
            .flatten()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        // The bounded review must not turn unchecked continuation refs into
        // an alternate path around source access checks.
        blocked_candidates.extend(
            candidate_ids
                .difference(&reviewed_candidates)
                .map(|reference| (*reference).to_owned()),
        );
        let method_hits = found
            .candidates
            .iter()
            .take(3)
            .filter(|candidate| {
                candidate.object_kind.as_deref() == Some("revision_proposal_revision")
            })
            .map(|candidate| candidate.candidate_id.clone())
            .collect::<BTreeSet<_>>();
        let methods = if method_hits.is_empty() {
            BTreeSet::new()
        } else {
            let fresh = self
                .writer
                .project()
                .await
                .map_err(|_| McpServiceError::Store)?;
            crate::jobs::procedure::readable_revisions(
                &self.writer,
                &fresh,
                scope
                    .binding
                    .repository_report
                    .as_deref()
                    .or(report.as_ref()),
                self.runtime_snapshot.effective_config_hash,
                (scope.anchor.repository_id, scope.anchor.worktree_id),
                Some(&method_hits),
                method_deadline,
            )
            .await
            .map_err(|_| McpServiceError::Store)?
        };
        let label = scope_label(&scope);
        let unavailable_current = BTreeSet::new();
        let review = self
            .classify_search_candidates(SearchCandidateReviewInput {
                request_id: &request_id,
                label: &label,
                anchor: &scope.anchor,
                frontier: scope.snapshot.frontier,
                rows: &scope.snapshot.rows,
                context: &context,
                candidates: &found.candidates,
                methods: &methods,
                blocked_candidates: &blocked_candidates,
                unavailable_current: &unavailable_current,
            })
            .await?;
        Ok(Self::search_result_from_review(
            request_id,
            label,
            scope.anchor.cwd_only,
            found,
            review.items,
            review.omitted,
            blocked_candidates,
        ))
    }

    async fn search_due(
        &self,
        request_id: RequestId,
        mut scope: McpRequestScope,
    ) -> Result<McpServiceResult, McpServiceError> {
        if !matches!(
            scope.anchor.mechanism,
            McpScopeMechanism::ExactClaim | McpScopeMechanism::ConnectionScoped
        ) || scope.anchor.session_id.is_none()
            || scope.anchor.execution_lane_id.is_none()
            || scope.anchor.episode_revision_id.is_none()
        {
            return Ok(empty_result(
                request_id,
                McpServiceStatus::ScopeUnresolved,
                &scope_label(&scope),
                "unknown",
                ["scope_unresolved"],
            ));
        }
        let blocked = crate::repository::blocked_repositories(
            &self.writer,
            scope.anchor.repository_id.into_iter().collect(),
            scope.binding.repository_report.as_deref(),
            self.runtime_snapshot.effective_config_hash,
        )
        .await
        .map_err(|_| McpServiceError::Store)?;
        if !blocked.is_empty() {
            return Ok(empty_result(
                request_id,
                McpServiceStatus::NoMatch,
                &scope_label(&scope),
                "current",
                ["repository_read_restricted"],
            ));
        }
        let now = unix_time_us_for_mcp();
        let request_ref = request_id.to_string();
        let mut stale_retries = 0;
        for _ in 0..3 {
            let matching = scope
                .snapshot
                .data_rows()
                .filter(|row| {
                    row.object_kind.as_deref() == Some("recall_need")
                        && row.session_id.as_deref() == scope.anchor.session_id.as_deref()
                })
                .map(evertrace_store::projections::recall_need)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| McpServiceError::Store)?
                .into_iter()
                .flatten()
                .filter(|need| {
                    Some(need.session_id.as_str()) == scope.anchor.session_id.as_deref()
                        && Some(need.execution_lane_id) == scope.anchor.execution_lane_id
                        && Some(need.episode_revision_id) == scope.anchor.episode_revision_id
                        && need.obligation_state == RecallObligationState::Active
                        && need
                            .obligation_expires_at_us
                            .is_none_or(|expiry| expiry > now)
                        && (need.agent_response == RecallAgentResponse::NotRetrieved
                            || need.active_retrieval_request_id.as_deref()
                                == Some(request_ref.as_str())
                                && matches!(
                                    need.agent_response,
                                    RecallAgentResponse::RetrievalClaimed
                                        | RecallAgentResponse::RetrievalReturned
                                ))
                })
                .take(3)
                .collect::<Vec<_>>();
            let Some(need) = (matching.len() == 1).then(|| matching[0].clone()) else {
                return Ok(if matching.is_empty() {
                    empty_result(
                        request_id,
                        McpServiceStatus::NoRecallNeeded,
                        &scope_label(&scope),
                        "current",
                        [],
                    )
                } else {
                    empty_result(
                        request_id,
                        McpServiceStatus::ScopeUnresolved,
                        &scope_label(&scope),
                        "current",
                        ["ambiguous_recall_need"],
                    )
                });
            };
            match crate::recall::revalidate_need(&scope.snapshot, &need, now)
                .map_err(|_| McpServiceError::Store)?
            {
                crate::recall::RecallNeedValidity::Valid => {}
                crate::recall::RecallNeedValidity::Unavailable => {
                    return Ok(empty_result(
                        request_id,
                        McpServiceStatus::NoRecallNeeded,
                        &scope_label(&scope),
                        "current",
                        ["recall_need_not_current"],
                    ));
                }
                crate::recall::RecallNeedValidity::Terminal(state) => {
                    let event = crate::recall::terminal_need_event(&need, state)
                        .map_err(|_| McpServiceError::Store)?;
                    let command = recall_ledger_command(
                        event,
                        now,
                        self.runtime_snapshot.effective_config_hash,
                    )?;
                    match self
                        .writer
                        .commit_if_frontier(command, now, scope.snapshot.frontier)
                        .await
                    {
                        Ok(_) => {
                            return Ok(empty_result(
                                request_id,
                                McpServiceStatus::NoRecallNeeded,
                                &scope_label(&scope),
                                "current",
                                [],
                            ));
                        }
                        Err(WriterActorError::StaleFrontier) if stale_retries == 0 => {
                            stale_retries += 1;
                            scope.snapshot = self
                                .writer
                                .project()
                                .await
                                .map_err(|_| McpServiceError::Store)?;
                            continue;
                        }
                        Err(_) => return Err(McpServiceError::Store),
                    }
                }
            }
            if need.active_retrieval_request_id.as_deref() == Some(request_ref.as_str()) {
                if need.agent_response == RecallAgentResponse::RetrievalReturned {
                    return self.due_result(request_id, &scope, need).await;
                }
                let result = match self.due_result(request_id, &scope, need.clone()).await {
                    Ok(value) => value,
                    Err(error) => {
                        let unknown = evertrace_domain::recall::RecallRetrievalOutcome {
                            request_id: request_ref.clone(),
                            recall_need_id: need.recall_need_id,
                            recall_need_hash: need.recall_need_hash,
                            state: RetrievalOutcomeState::Unknown,
                            occurred_at_us: now,
                        };
                        if let Ok(command) = recall_retrieval_command(
                            unknown,
                            now,
                            self.runtime_snapshot.effective_config_hash,
                        ) {
                            let _ = self
                                .writer
                                .commit_if_frontier(command, now, scope.snapshot.frontier)
                                .await;
                        }
                        return Err(error);
                    }
                };
                let returned = evertrace_domain::recall::RecallRetrievalOutcome {
                    request_id: request_ref.clone(),
                    recall_need_id: need.recall_need_id,
                    recall_need_hash: need.recall_need_hash,
                    state: RetrievalOutcomeState::Returned,
                    occurred_at_us: now,
                };
                let command = recall_retrieval_command(
                    returned,
                    now,
                    self.runtime_snapshot.effective_config_hash,
                )?;
                match self
                    .writer
                    .commit_if_frontier(command, now, scope.snapshot.frontier)
                    .await
                {
                    Ok(_) => return Ok(result),
                    Err(WriterActorError::StaleFrontier) if stale_retries == 0 => {
                        stale_retries += 1;
                        scope.snapshot = self
                            .writer
                            .project()
                            .await
                            .map_err(|_| McpServiceError::Store)?;
                        continue;
                    }
                    Err(_) => return Err(McpServiceError::Store),
                }
            }
            let outcome = evertrace_domain::recall::RecallRetrievalOutcome {
                request_id: request_ref.clone(),
                recall_need_id: need.recall_need_id,
                recall_need_hash: need.recall_need_hash,
                state: RetrievalOutcomeState::Claimed,
                occurred_at_us: now,
            };
            let command = recall_retrieval_command(
                outcome,
                now,
                self.runtime_snapshot.effective_config_hash,
            )?;
            match self
                .writer
                .commit_if_frontier(command, now, scope.snapshot.frontier)
                .await
            {
                Ok(_) => {
                    scope.snapshot = self
                        .writer
                        .project()
                        .await
                        .map_err(|_| McpServiceError::Store)?;
                }
                Err(WriterActorError::StaleFrontier) if stale_retries == 0 => {
                    stale_retries += 1;
                    scope.snapshot = self
                        .writer
                        .project()
                        .await
                        .map_err(|_| McpServiceError::Store)?;
                }
                Err(_) => return Err(McpServiceError::Store),
            }
        }
        Err(McpServiceError::Store)
    }

    pub(super) async fn get(
        &self,
        request_id: RequestId,
        scope: McpRequestScope,
        identifier: String,
    ) -> Result<McpServiceResult, McpServiceError> {
        let selected = select_object_row(&scope.snapshot, &identifier);
        let Some((row, is_current)) = (match selected {
            Ok(value) => value,
            Err(()) => {
                return Ok(empty_result(
                    request_id,
                    McpServiceStatus::InvalidInput,
                    &scope_label(&scope),
                    "unknown",
                    ["ambiguous_identifier"],
                ));
            }
        }) else {
            return Ok(empty_result(
                request_id,
                McpServiceStatus::NotFound,
                &scope_label(&scope),
                "current",
                [],
            ));
        };
        let report = match &self.session_report {
            Some(report) => report.read().await.clone(),
            None => None,
        };
        if row.object_kind.as_deref() == Some("revision_proposal_revision") {
            let selected = row.current_revision_id.iter().cloned().collect();
            let fresh = self
                .writer
                .project()
                .await
                .map_err(|_| McpServiceError::Store)?;
            let methods = crate::jobs::procedure::readable_revisions(
                &self.writer,
                &fresh,
                scope
                    .binding
                    .repository_report
                    .as_deref()
                    .or(report.as_ref()),
                self.runtime_snapshot.effective_config_hash,
                (scope.anchor.repository_id, scope.anchor.worktree_id),
                Some(&selected),
                std::time::Instant::now() + std::time::Duration::from_micros(750_000),
            )
            .await
            .map_err(|_| McpServiceError::Store)?;
            if !is_current
                || !row
                    .current_revision_id
                    .as_ref()
                    .is_some_and(|id| methods.contains(id))
            {
                return Ok(empty_result(
                    request_id,
                    McpServiceStatus::NotFound,
                    &scope_label(&scope),
                    "current",
                    [],
                ));
            }
        }
        if !self
            .blocked_read_rows(
                scope
                    .binding
                    .repository_report
                    .as_deref()
                    .or(report.as_ref()),
                &scope.snapshot,
                &[row],
                scope.anchor.repository_id,
            )
            .await
            .map_err(|_| McpServiceError::Store)?
            .is_empty()
        {
            return Ok(empty_result(
                request_id,
                McpServiceStatus::NotFound,
                &scope_label(&scope),
                "current",
                ["source_read_restricted"],
            ));
        }
        let payload = if row.object_kind.as_deref() == Some("source_receipt") {
            let receipt = match row
                .payload_json
                .as_deref()
                .and_then(|value| serde_json::from_str::<JournalPayload>(value).ok())
            {
                Some(JournalPayload::SourceReceiptRecorded(receipt)) => receipt,
                _ => return Err(McpServiceError::Store),
            };
            receipt.validate().map_err(|_| McpServiceError::Store)?;
            Some(
                serde_json::to_string(&serde_json::json!({
                    "cas_ref": receipt.cas_ref,
                    "original_length": receipt.original_length,
                    "protected_length": receipt.protected_length,
                    "protected_presentation": receipt.protected_presentation,
                }))
                .map_err(|_| McpServiceError::Store)?,
            )
        } else {
            row.payload_json
                .clone()
                .filter(|payload| payload.len() <= 8_192)
        };
        let payload_omitted = payload.is_none();
        let retained_forgotten_source = retained_forgotten_source(&scope.snapshot, row)?;
        let mut warnings = payload_omitted
            .then_some("payload_available_by_local_object_ref".into())
            .into_iter()
            .collect::<Vec<_>>();
        if retained_forgotten_source {
            warnings.push("source_retained_object_forgotten".into());
        }
        Ok(McpServiceResult {
            request_id,
            status: McpServiceStatus::Ok,
            scope: scope_label(&scope),
            freshness: "current".into(),
            completeness: "complete".into(),
            items: vec![classify_object_row(
                row,
                payload,
                is_current,
                unix_time_us_for_mcp(),
            )],
            warnings,
            truncated: payload_omitted,
            next_refs: Vec::new(),
        })
    }
}

pub(super) fn retained_forgotten_source(
    snapshot: &ProjectionSnapshot,
    row: &ObjectRow,
) -> Result<bool, McpServiceError> {
    let observation_id = match row.object_kind.as_deref() {
        Some("evidence_surface") => row
            .payload_json
            .as_deref()
            .and_then(|value| serde_json::from_str::<JournalPayload>(value).ok())
            .and_then(|payload| match payload {
                JournalPayload::EvidenceSurfaceRecorded(surface) => {
                    Some(surface.source_observation_revision_ref)
                }
                _ => None,
            }),
        Some("source_observation") => row
            .object_id
            .as_deref()
            .and_then(|value| value.parse().ok()),
        Some("source_receipt") => row
            .payload_json
            .as_deref()
            .and_then(|value| serde_json::from_str::<JournalPayload>(value).ok())
            .and_then(|payload| match payload {
                JournalPayload::SourceReceiptRecorded(receipt) => {
                    Some(receipt.source_observation_id)
                }
                _ => None,
            }),
        _ => None,
    };
    let Some(observation_id) = observation_id else {
        return Ok(false);
    };
    let mut surface = None;
    let mut observation = None;
    let mut receipt = None;
    let observation_text =
        serde_json::to_string(&observation_id).map_err(|_| McpServiceError::Store)?;
    for candidate in snapshot.data_rows() {
        if !matches!(
            candidate.object_kind.as_deref(),
            Some("evidence_surface" | "source_observation" | "source_receipt")
        ) {
            continue;
        }
        if candidate
            .payload_json
            .as_deref()
            .is_none_or(|json| !json.contains(&observation_text))
        {
            continue;
        }
        let payload = match candidate.payload_json.as_deref() {
            Some(value) => {
                serde_json::from_str::<JournalPayload>(value).map_err(|_| McpServiceError::Store)?
            }
            None => continue,
        };
        match payload {
            JournalPayload::EvidenceSurfaceRecorded(value)
                if value.source_observation_revision_ref == observation_id =>
            {
                surface = Some(*value);
            }
            JournalPayload::SourceObservationRecorded(value)
                if value.source_observation_id == observation_id =>
            {
                observation = Some(*value);
            }
            JournalPayload::SourceReceiptRecorded(value)
                if value.source_observation_id == observation_id =>
            {
                receipt = Some(*value);
            }
            _ => {}
        }
    }
    let (Some(surface), Some(observation), Some(receipt)) = (surface, observation, receipt) else {
        return Ok(false);
    };
    if observation.source_receipt_ref != receipt.source_receipt_id {
        return Err(McpServiceError::Store);
    }
    let suppressed = ObjectDeletionCurrentView::from_snapshot(snapshot)
        .map_err(|_| McpServiceError::Store)?
        .suppression_ref_hashes();
    for generation in [
        evertrace_store::DefaultRetrievalSuppressionGeneration::ObservationSpanV1,
        evertrace_store::DefaultRetrievalSuppressionGeneration::ContentSpanV2,
    ] {
        let reference =
            evertrace_store::default_retrieval_suppression_ref_hash(&surface, &receipt, generation)
                .map_err(|_| McpServiceError::Store)?;
        if suppressed.contains(&reference) {
            return Ok(true);
        }
    }
    Ok(false)
}

impl McpActionService {
    async fn due_result(
        &self,
        request_id: RequestId,
        scope: &McpRequestScope,
        need: evertrace_domain::recall::RecallNeed,
    ) -> Result<McpServiceResult, McpServiceError> {
        let plan_text =
            serde_json::to_string(&need.recall_plan).map_err(|_| McpServiceError::Store)?;
        let mut items = vec![McpServiceItem {
            partition: McpItemPartition::Evidence,
            kind: "recall_brief".into(),
            object_ref: Some(need.recall_need_id.to_string()),
            object_revision_ref: Some(need.revision_id.to_string()),
            source_revision_ref: need.source_revision_ids.first().map(ToString::to_string),
            scope: Some(scope_label(scope)),
            applicability: Some("revalidated_current".into()),
            authority: Some("derived_runtime_ledger".into()),
            content_trust: ContentTrust::Observed,
            capture_completeness: Some("complete".into()),
            instruction_authority: InstructionAuthority::None,
            text: Some(plan_text),
        }];
        let exact_identifiers = need
            .source_revision_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let query = exact_identifiers.join(" ");
        let supplemental = ProductionSearch::new(self.search_index.clone())
            .with_procedure_revisions(BTreeSet::new())
            .search(SearchContext {
                intent: SearchIntent::FailureRecovery,
                raw_query: query,
                query_facets: QueryFacetSet {
                    parse_status: FacetParseStatus::Complete,
                    exact_identifiers,
                    condition_literals: Vec::new(),
                    relation_requirements: Vec::new(),
                    polarity: Polarity::Positive,
                    explicit_exclusions: Vec::new(),
                    temporal_mode: TemporalMode::Current,
                    temporal_qualifiers: Vec::new(),
                    quantity_constraints: vec![QuantityConstraint::ResultLimit { limit: 2 }],
                    scope_boundary: None,
                    source_boundary: None,
                    answer_shape: None,
                    lifecycle_boundary: LifecycleBoundary::Active,
                },
                task_id: scope.anchor.task_id,
                repository_id: scope.anchor.repository_id,
                worktree_id: scope.anchor.worktree_id,
                suppression: deletion_suppression(&scope.snapshot)?,
                budget: RetrievalBudget {
                    candidates_remaining: 2,
                    tokens_remaining: 600,
                    latency_us_remaining: 250_000,
                    hops_remaining: 0,
                    follow_ups_remaining: 0,
                },
            })
            .await;
        let mut warnings = Vec::new();
        let mut next_refs = need.recall_plan.supporting_evidence_refs;
        let mut completeness = "complete";
        match supplemental {
            Ok(found) => {
                let now = unix_time_us_for_mcp();
                for candidate in found.candidates.into_iter().take(2) {
                    if let Some(item) = classify_search_candidate(scope, &candidate, now) {
                        items.push(item);
                    } else {
                        next_refs.push(candidate.candidate_id);
                        completeness = "partial";
                    }
                }
                if !found.degraded_reasons.is_empty() || !found.omitted_refs.is_empty() {
                    completeness = "partial";
                }
                warnings.extend(found.degraded_reasons);
                next_refs.extend(found.omitted_refs);
            }
            Err(_) => {
                completeness = "partial";
                warnings.push("recall_supplement_unavailable".into());
            }
        }
        next_refs.sort();
        next_refs.dedup();
        Ok(McpServiceResult {
            request_id,
            status: if completeness == "complete" {
                McpServiceStatus::Ok
            } else {
                McpServiceStatus::Partial
            },
            scope: scope_label(scope),
            freshness: "current".into(),
            completeness: completeness.into(),
            items,
            warnings,
            truncated: !next_refs.is_empty(),
            next_refs,
        })
    }
}

fn deletion_suppression(
    snapshot: &ProjectionSnapshot,
) -> Result<SuppressionSnapshot, McpServiceError> {
    deletion_suppression_rows(snapshot.frontier, &snapshot.rows)
}

fn deletion_suppression_rows(
    frontier: u64,
    rows: &[ObjectRow],
) -> Result<SuppressionSnapshot, McpServiceError> {
    let ledger = ObjectDeletionCurrentView::from_rows(frontier, rows.iter())
        .map_err(|_| McpServiceError::Store)?;
    Ok(SuppressionSnapshot::Current {
        generation: ledger.generation,
        ref_hashes: ledger.suppression_ref_hashes(),
    })
}

fn recall_retrieval_command(
    outcome: evertrace_domain::recall::RecallRetrievalOutcome,
    now: i64,
    config_hash: [u8; 32],
) -> Result<JournalCommand, McpServiceError> {
    recall_ledger_command(
        RecallLedgerEvent::RetrievalOutcome { outcome },
        now,
        config_hash,
    )
}

fn recall_ledger_command(
    event: RecallLedgerEvent,
    now: i64,
    config_hash: [u8; 32],
) -> Result<JournalCommand, McpServiceError> {
    JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            now,
            config_hash,
            "s22-recall-v1",
            JournalPayload::RecallLedgerRecorded(Box::new(event)),
        )],
    )
    .map_err(|_| McpServiceError::Store)
}

fn classify_search_candidate(
    scope: &McpRequestScope,
    candidate: &evertrace_domain::query::SearchCandidate,
    now: i64,
) -> Option<McpServiceItem> {
    classify_search_candidate_rows(&scope.snapshot.rows, &scope_label(scope), candidate, now)
}

fn normal_search_candidate_matches_row(
    candidate: &evertrace_domain::query::SearchCandidate,
    row: &ObjectRow,
) -> bool {
    match candidate.row_variant {
        evertrace_domain::query::SearchCandidateVariant::Object => {
            row.row_id == candidate.candidate_id
                || row.object_id.as_deref() == Some(candidate.candidate_id.as_str())
                || row.current_revision_id.as_deref() == Some(candidate.candidate_id.as_str())
        }
        evertrace_domain::query::SearchCandidateVariant::EvidenceSurface => {
            row.object_kind.as_deref() == Some("evidence_surface")
                && row.current_revision_id.as_deref() == Some(candidate.source_ref.as_str())
        }
    }
}

fn classify_search_candidate_rows(
    rows: &[ObjectRow],
    scope: &str,
    candidate: &evertrace_domain::query::SearchCandidate,
    now: i64,
) -> Option<McpServiceItem> {
    match candidate.row_variant {
        evertrace_domain::query::SearchCandidateVariant::Object => {
            let (row, is_current) = select_object_row_rows(rows, &candidate.candidate_id)
                .ok()
                .flatten()?;
            if row.object_kind.as_deref() == Some("procedure_revision") {
                return None;
            }
            Some(classify_object_row(
                row,
                Some(candidate.text.clone()),
                is_current,
                now,
            ))
        }
        evertrace_domain::query::SearchCandidateVariant::EvidenceSurface
            if candidate.object_kind.as_deref() == Some("evidence_surface") =>
        {
            let content_trust = match candidate.content_trust.as_deref()? {
                "user_statement" => ContentTrust::UserStatement,
                "observed" => ContentTrust::Observed,
                "agent_claim" => ContentTrust::AgentClaim,
                "imported_claim" => ContentTrust::ImportedClaim,
                "untrusted_source_content" => ContentTrust::UntrustedSourceContent,
                _ => return None,
            };
            let completeness = match candidate.capture_completeness.as_deref()? {
                "complete" | "partial" | "opaque" => candidate.capture_completeness.clone(),
                _ => return None,
            };
            (candidate.instruction_authority == "none").then(|| McpServiceItem {
                partition: McpItemPartition::Evidence,
                kind: "evidence_surface".into(),
                object_ref: Some(candidate.source_ref.clone()),
                object_revision_ref: Some(candidate.candidate_id.clone()),
                source_revision_ref: Some(candidate.source_ref.clone()),
                scope: Some(scope.into()),
                applicability: None,
                authority: None,
                content_trust,
                capture_completeness: completeness,
                instruction_authority: InstructionAuthority::None,
                text: Some(candidate.text.clone()),
            })
        }
        evertrace_domain::query::SearchCandidateVariant::EvidenceSurface => None,
    }
}
