use std::{collections::BTreeMap, future::Future, pin::Pin};

use crate::search::read_context::{RelationArchiveBudget, SearchReadAccess};

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
    fn protect_search_context(&self, context: &mut SearchContext) -> Result<(), McpServiceError> {
        let key =
            evertrace_capture::DeviceKeyStore::new(self.runtime_snapshot.device_key_dir.clone())
                .load()
                .map_err(|_| McpServiceError::Store)?;
        let protected =
            crate::search::protection::prepare(&context.raw_query, &context.query_facets, &key)
                .map_err(|_| McpServiceError::Store)?;
        context.protected_query = protected.text;
        context.protected_facets = protected.protected_facets;
        context.query_facets = protected.facets;
        Ok(())
    }

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
        let relation = crate::search::explicit_atom_relation(&query, &scope.target_anchors);
        let atom_relation = relation.is_some();
        let physical = crate::search::explicit_operation_binding(&query, &scope.target_anchors);
        let mut relation_requirements: Vec<String> =
            relation.map(|(_, kind)| kind.into()).into_iter().collect();
        if physical.is_some() {
            relation_requirements.extend([
                "operation_to_scope_effect".into(),
                "binding_to_scope_effect".into(),
            ]);
        }
        let source_shape = crate::search::explicit_source_shape(&query, &scope.target_anchors);
        let count_unit = crate::search::explicit_count_unit(&query, &scope.target_anchors);
        let exact_shape = source_shape.is_some() || count_unit.is_some();
        let entity_list = crate::search::entity_list_topic(&query).is_some();
        let exact_slots = if entity_list {
            None
        } else {
            crate::search::explicit_exact_slots(&query, &scope.target_anchors)
        };
        let explicit_exact = exact_slots.is_some();
        let explicit_view = atom_relation || physical.is_some() || exact_shape || explicit_exact;
        // A typed Episode target asks for stored work evidence, not stage guidance. Do not infer that intent from prose.
        let episode = (!explicit_view && !entity_list)
            .then(|| match scope.target_anchors.as_slice() {
                [] => query.trim(),
                [target] => target.as_str(),
                _ => "",
            })
            .and_then(|reference| {
                reference
                    .parse::<evertrace_domain::ids::WorkEpisodeId>()
                    .ok()
            });
        let episode_history = episode.is_some();
        let mut quantity = vec![QuantityConstraint::ResultLimit { limit: 3 }];
        if let Some(unit) = count_unit {
            quantity.push(QuantityConstraint::DistinctCount { unit });
        }
        let mut context = SearchContext {
            query_anchor: scope.anchor.search_anchor(),
            intent: if episode_history {
                SearchIntent::HistoryLookup
            } else {
                SearchIntent::StageAssistance
            },
            raw_query: query.clone(),
            protected_query: String::new(),
            protected_facets: BTreeSet::new(),
            execution: scope
                .anchor
                .execution_context(scope.context.frontier, &scope.context.scope),
            query_facets: QueryFacetSet {
                statement_role: evertrace_domain::query::StatementRole::Unknown,
                parse_status: if atom_relation
                    || physical.is_some()
                    || exact_shape
                    || episode_history
                {
                    FacetParseStatus::Complete
                } else {
                    FacetParseStatus::Unknown
                },
                target_anchors: relation.map_or_else(
                    || {
                        episode
                            .map_or_else(|| scope.target_anchors.clone(), |id| vec![id.to_string()])
                    },
                    |(target, _)| vec![target.into()],
                ),
                exact_identifiers: exact_slots.unwrap_or_default(),
                condition_literals: Vec::new(),
                relation_requirements,
                polarity: Polarity::Positive,
                explicit_exclusions: Vec::new(),
                temporal_mode: TemporalMode::Current,
                temporal_qualifiers: source_shape
                    .map(
                        |(_, domain)| evertrace_domain::query::TemporalQualifier::OrderBy {
                            domain,
                        },
                    )
                    .into_iter()
                    .collect(),
                quantity_constraints: quantity,
                scope_boundary: None,
                source_boundary: None,
                answer_shape: if let Some((shape, _)) = source_shape {
                    Some(shape)
                } else if count_unit.is_some() {
                    Some(evertrace_domain::query::AnswerShape::Count)
                } else if entity_list {
                    Some(evertrace_domain::query::AnswerShape::EntityList)
                } else {
                    (atom_relation || physical.is_some())
                        .then_some(evertrace_domain::query::AnswerShape::SourceSnippet)
                },
                lifecycle_boundary: if episode_history {
                    LifecycleBoundary::Terminal
                } else {
                    LifecycleBoundary::Active
                },
            },
            task_id: scope.anchor.task_id,
            repository_id: scope.anchor.repository_id,
            worktree_id: scope.anchor.worktree_id,
            suppression: deletion_suppression_rows(scope.context.frontier, &scope.context.rows)?,
            budget: RetrievalBudget {
                candidates_remaining: 3,
                tokens_remaining: 1_200,
                latency_us_remaining: latency_us,
                hops_remaining: if atom_relation || physical.is_some() {
                    2
                } else {
                    0
                },
                follow_ups_remaining: u8::from(explicit_exact),
            },
        };
        self.protect_search_context(&mut context)?;
        context.budget.latency_us_remaining = u64::try_from(
            scope
                .deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_micros(),
        )
        .unwrap_or(u64::MAX);
        if context.budget.latency_us_remaining == 0 {
            return Ok(empty_result(
                request_id,
                McpServiceStatus::Partial,
                &label,
                "partial",
                ["search_deadline_exhausted"],
            ));
        }
        let report = match &self.session_report {
            Some(report) => report.read().await.clone(),
            None => None,
        };
        let method_deadline = scope.deadline;
        let repository_report = scope
            .binding
            .repository_report
            .as_deref()
            .or(report.as_ref());
        let read_access = SearchReadAccess {
            writer: &self.writer,
            authority: crate::repository::RepositoryReadAuthority::observed(repository_report),
            frontier: scope.context.frontier,
            config_hash: self.runtime_snapshot.effective_config_hash,
            deadline: method_deadline,
        };
        let mut search = ProductionSearch::new(self.search_index.clone())
            .with_validated_frontier(scope.context.frontier);
        if episode_history {
            search = search.with_exact_object_kind("work_episode");
        } else if physical.is_none() {
            let include_probationary = self.operation_config.as_ref().map_or_else(
                || evertrace_domain::config::ProcedureConfig::default().include_probationary,
                |config| config.config().procedure.include_probationary,
            );
            let procedures = crate::procedure::ProcedureUsageCurrentView::from_promotion_rows(
                scope.context.frontier,
                &scope.context.rows,
            )
            .map_err(|_| McpServiceError::Store)?
            .searchable_procedure_revisions(include_probationary);
            let methods = crate::jobs::procedure::readable_revisions_from_rows(
                &self.writer,
                &scope.context.rows,
                repository_report,
                self.runtime_snapshot.effective_config_hash,
                (scope.anchor.repository_id, scope.anchor.worktree_id),
                None,
                method_deadline,
            )
            .await
            .map_err(|_| McpServiceError::Store)?;
            search = search
                .with_method_proposals(methods)
                .with_procedure_revisions(procedures);
        }
        let mut archive_budget = RelationArchiveBudget::default();
        let page = if let Some(operation) = physical {
            let Some(page) = self
                .physical_binding_page(
                    &scope,
                    &read_access,
                    operation,
                    &mut archive_budget,
                    search,
                    context.clone(),
                )
                .await?
            else {
                return Ok(empty_result(
                    request_id,
                    McpServiceStatus::Partial,
                    &label,
                    "partial",
                    ["search_relation_unresolved"],
                ));
            };
            page
        } else {
            search
                .search_with_access(context.clone(), &read_access)
                .await
                .map_err(|_| McpServiceError::Store)?
        };
        let mut found = page.result;
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
        let execution_changed = found
            .degraded_reasons
            .contains("execution_context_frontier_changed");
        let candidate_context = if execution_changed {
            Some(
                self.writer
                    .normal_search_current_context(scope.request.clone())
                    .await
                    .map_err(|_| McpServiceError::Store)?,
            )
        } else if candidate_ids.is_empty() {
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
            if fresh_anchor.as_ref() != Some(&scope.anchor) || execution_changed {
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
                            target_anchors: scope.target_anchors,
                        },
                        query,
                        true,
                    ))
                    .await;
                }
                if execution_changed {
                    return Ok(empty_result(
                        request_id,
                        McpServiceStatus::Partial,
                        &label,
                        "partial",
                        ["execution_context_frontier_changed"],
                    ));
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
                    target_anchors: scope.target_anchors,
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
            let fresh_access = SearchReadAccess {
                frontier: candidate_context.frontier,
                ..read_access
            };
            for candidate in &selected_candidates {
                if blocked_candidates.contains(&candidate.candidate_id) {
                    continue;
                }
                let proof = match candidate.row_variant {
                    evertrace_domain::query::SearchCandidateVariant::EvidenceSurface => {
                        fresh_access.check_evidence(&candidate.source_ref).await
                    }
                    _ => {
                        let Some(kind) = candidate.object_kind.as_deref().filter(|kind| {
                            crate::search::read_context::SCOPED_OBJECT_KINDS.contains(kind)
                        }) else {
                            continue;
                        };
                        fresh_access
                            .check_current(&candidate.source_ref, &candidate.candidate_id, kind)
                            .await
                    }
                };
                if proof.is_err() {
                    blocked_candidates.insert(candidate.candidate_id.clone());
                }
            }
            if let Some(operation) = physical {
                let rechecked = if fresh_access.frontier == read_access.frontier {
                    Box::pin(self.physical_binding_operands(
                        &scope,
                        &fresh_access,
                        operation,
                        &mut archive_budget,
                    ))
                    .await
                } else {
                    None
                };
                if rechecked.as_ref().is_none_or(|(_, binding)| {
                    binding.is_none()
                        && selected_candidates.iter().any(|candidate| {
                            candidate.object_kind.as_deref() == Some("work_binding")
                        })
                }) {
                    blocked_candidates.extend(candidate_ids.iter().cloned());
                }
            }
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
        if let Some(current) = &candidate_context {
            context.execution = scope
                .anchor
                .execution_context(current.frontier, &current.scope);
        }
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
        // Only references in the final, authorized answer can close an explicit target.
        let targets_resolved = context.query_facets.target_anchors.iter().all(|target| {
            review.items.iter().any(|item| {
                [
                    item.object_ref.as_ref(),
                    item.object_revision_ref.as_ref(),
                    item.source_revision_ref.as_ref(),
                ]
                .into_iter()
                .flatten()
                .any(|reference| reference == target)
            })
        });
        if !targets_resolved {
            found
                .degraded_reasons
                .insert("search_target_unresolved".into());
            if found.completeness == RetrievalCompleteness::Complete {
                found.completeness = RetrievalCompleteness::Partial;
            }
        }
        let overflowed = [
            "retrieval_budget_exhausted",
            "evidence_channel_budget_exhausted",
        ]
        .iter()
        .any(|reason| found.degraded_reasons.contains(*reason));
        let mut view = None;
        if targets_resolved
            && found.authoritative_frontier == review_frontier
            && (explicit_view || overflowed || entity_list)
        {
            let reviewed = review
                .items
                .iter()
                .filter(|item| {
                    item.partition == McpItemPartition::Evidence
                        && (matches!(item.kind.as_str(), "atom_revision" | "evidence_surface")
                            || physical.is_some()
                                && matches!(
                                    item.kind.as_str(),
                                    "operation" | "scope_effect" | "work_binding"
                                ))
                })
                .filter_map(|item| item.object_revision_ref.as_deref())
                .collect::<BTreeSet<_>>();
            if explicit_view {
                if let Some(mut grounded) = page.grounded_view
                    && !grounded.candidate_set.candidate_refs.is_empty()
                    && grounded
                        .candidate_set
                        .candidate_refs
                        .iter()
                        .all(|id| reviewed.contains(id.as_str()))
                {
                    if exact_shape && grounded.completeness != RetrievalCompleteness::Complete {
                        found
                            .degraded_reasons
                            .insert("search_bounded_operator_partial".into());
                    }
                    if explicit_exact
                        || ((atom_relation || physical.is_some())
                            && !grounded.unresolved_gaps.is_empty())
                    {
                        let reason = if explicit_exact {
                            "search_exact_request_partial"
                        } else {
                            "search_relation_unresolved"
                        };
                        found.degraded_reasons.insert(reason.into());
                    }
                    grounded
                        .omitted_refs
                        .retain(|id| !blocked_candidates.contains(id));
                    view = Some(Box::new(grounded));
                }
            } else {
                view = ProductionSearch::new(self.search_index.clone())
                    .ground_reviewed(&context, found.clone(), &reviewed, scope.deadline)
                    .await
                    .map(Box::new);
            }
        }
        if entity_list && !review.items.is_empty() {
            found
                .degraded_reasons
                .insert("search_entity_list_partial".into());
            if found.completeness == RetrievalCompleteness::Complete {
                found.completeness = RetrievalCompleteness::Partial;
            }
        }
        if (explicit_view || (entity_list && !review.items.is_empty())) && view.is_none() {
            found
                .degraded_reasons
                .insert("grounded_view_unavailable".into());
            if found.completeness != RetrievalCompleteness::Unknown {
                found.completeness = RetrievalCompleteness::Partial;
            }
        }
        let mut result = Self::search_result_from_review(
            request_id,
            label,
            scope.anchor.cwd_only,
            found,
            review.items,
            review.omitted,
            blocked_candidates,
        );
        result.grounded_view = view;
        Ok(result)
    }

    // Keep the explicit relation retrieval future off the common Search stack.
    fn physical_binding_page<'a>(
        &'a self,
        scope: &'a NormalSearchScope,
        access: &'a SearchReadAccess<'_>,
        operation: evertrace_domain::ids::OperationId,
        archive_budget: &'a mut RelationArchiveBudget,
        search: ProductionSearch,
        context: SearchContext,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Option<evertrace_domain::query::HumanSearchPage>,
                        McpServiceError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let Some((operands, binding)) = self
                .physical_binding_operands(scope, access, operation, archive_budget)
                .await
            else {
                return Ok(None);
            };
            let refs = operands
                .iter()
                .chain(binding.iter())
                .filter_map(|row| row.candidate_id.clone())
                .collect();
            let sources = |targets: &[String], readable: &BTreeSet<String>| {
                Ok(binding
                    .iter()
                    .filter(|row| {
                        row.candidate_id
                            .as_ref()
                            .is_some_and(|id| targets.contains(id) && readable.contains(id))
                    })
                    .cloned()
                    .collect())
            };
            let (mut page, _) = search
                .with_readable_refs(access.frontier, refs)
                .with_canonical_sources(access.frontier, operands)
                .retrieve(context, false, None, &sources)
                .await
                .map_err(|_| McpServiceError::Store)?;
            if binding.is_none() {
                page.result
                    .degraded_reasons
                    .insert("search_relation_source_unavailable".into());
            }
            Ok(Some(page))
        })
    }

    async fn physical_binding_operands(
        &self,
        scope: &NormalSearchScope,
        access: &SearchReadAccess<'_>,
        operation: evertrace_domain::ids::OperationId,
        archive_budget: &mut RelationArchiveBudget,
    ) -> Option<(
        Vec<evertrace_store::SearchProjectionRow>,
        Option<evertrace_store::SearchProjectionRow>,
    )> {
        use crate::search::read_context::{
            check_relation_archive, operation_binding_read, operation_binding_references,
            physical_read_index, select_operation_binding,
        };
        use evertrace_domain::query::MemoryScopeSelection as Selection;
        let read = async {
            let operation_key = operation.to_string();
            let references =
                operation_binding_references(&self.search_index, &operation_key, access.frontier)
                    .await?;
            if references.is_empty() || references.len() >= 64 {
                return None;
            }
            let anchor = &scope.anchor;
            let selected_scope = if let Some(worktree_id) = anchor.worktree_id {
                Selection::Worktree { worktree_id }
            } else if let Some(repository_id) = anchor.repository_id {
                Selection::Repository { repository_id }
            } else {
                Selection::Task {
                    task_id: anchor.task_id?,
                }
            };
            let loaded = self
                .writer
                .normal_search_candidate_context(
                    scope.request.clone(),
                    evertrace_store::NormalSearchCandidateRequest {
                        identifiers: std::iter::once(operation_key)
                            .chain(references.iter().cloned())
                            .collect(),
                        task_id: anchor.task_id,
                        repository_id: anchor.repository_id,
                        worktree_id: anchor.worktree_id,
                        include_procedure_route: false,
                        include_derived_candidate_rows: false,
                    },
                )
                .await
                .ok()?;
            if loaded.frontier != access.frontier {
                return None;
            }
            let index = physical_read_index(&loaded.rows);
            let row = select_operation_binding(
                operation,
                &references,
                &index,
                loaded.frontier,
                access.deadline,
            )?;
            let mut binding = evertrace_store::query::canonical_work_binding_source(row).ok()?;
            let reference = binding.candidate_id.as_deref()?;
            let closure = access
                .check_record(reference, reference, "work_binding")
                .await
                .ok()?;
            let row = closure.selected.as_ref()?;
            let index = physical_read_index(&closure.rows);
            let proof = operation_binding_read(row, &index)?;
            let mut operands = proof.scoped_operands(selected_scope, &mut binding)?;
            if operands.len() != 2 {
                return None;
            }
            if anchor
                .task_id
                .is_some_and(|id| binding.task_id.as_deref() != Some(id.to_string().as_str()))
                || anchor.repository_id.is_some_and(|id| {
                    binding.repository_id.as_deref() != Some(id.to_string().as_str())
                })
            {
                return None;
            }
            for operand in &operands {
                access
                    .check_current(
                        operand.source_ref.as_deref()?,
                        operand.candidate_id.as_deref()?,
                        operand.object_kind.as_deref()?,
                    )
                    .await
                    .ok()?;
            }
            if !check_relation_archive(
                &proof.physical_sources,
                &self.writer,
                &self.runtime_snapshot.cas_dir,
                &index,
                archive_budget,
                access.deadline,
            )
            .await
            {
                return None;
            }
            let assignment_sources = proof
                .sources
                .difference(&proof.physical_sources)
                .cloned()
                .collect::<BTreeSet<_>>();
            if assignment_sources.is_empty()
                || check_relation_archive(
                    &assignment_sources,
                    &self.writer,
                    &self.runtime_snapshot.cas_dir,
                    &index,
                    archive_budget,
                    access.deadline,
                )
                .await
            {
                return Some((operands, Some(binding)));
            }
            // Only the physical effect establishes the repository/worktree. Do not use missing assignment
            // evidence to ascribe the independently verifiable prefix to a Task, even when a repository is selected.
            if anchor.task_id.is_some() || anchor.repository_id.is_none() {
                return None;
            }
            for operand in &mut operands {
                operand.task_id = None;
            }
            Some((operands, None))
        };
        tokio::time::timeout_at(tokio::time::Instant::from_std(access.deadline), read)
            .await
            .ok()
            .flatten()
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
        let trimmed = [
            "search_access_window_exhausted",
            "evidence_channel_budget_exhausted",
            "retrieval_budget_exhausted",
            "relation_candidate_budget_exhausted",
            "relation_fanout_truncated",
        ]
        .iter()
        .any(|reason| found.degraded_reasons.contains(*reason));
        let unproven = trimmed
            || [
                "search_target_unresolved",
                "search_relation_unresolved",
                "search_exact_request_partial",
                "search_entity_list_partial",
                "search_bounded_operator_partial",
                "source_sequence_coverage_unverified",
                "grounded_view_unavailable",
                "search_access_unavailable",
                "source_read_restricted",
            ]
            .iter()
            .any(|reason| found.degraded_reasons.contains(*reason))
            || found
                .degraded_reasons
                .contains("read_access_frontier_changed")
            || found.projection_frontier < found.authoritative_frontier;
        let mut status = if unproven {
            McpServiceStatus::Partial
        } else if found.candidates.is_empty() {
            McpServiceStatus::NoMatch
        } else if found.degraded_reasons.is_empty() {
            McpServiceStatus::Ok
        } else {
            McpServiceStatus::DegradedIndex
        };
        let mut omitted_refs = found.omitted_refs;
        omitted_refs.extend(classification_omitted);
        omitted_refs.retain(|reference| !blocked_candidates.contains(reference.as_str()));
        if !unproven
            && !blocked_candidates.is_empty()
            && items.is_empty()
            && omitted_refs.is_empty()
        {
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
            grounded_view: None,
            warnings: {
                let mut warnings = found.degraded_reasons.into_iter().collect::<Vec<_>>();
                if cwd_only {
                    warnings.push("cwd_only_scope".into());
                }
                if !blocked_candidates.is_empty()
                    && !warnings
                        .iter()
                        .any(|reason| reason == "source_read_restricted")
                {
                    warnings.push("source_read_restricted".into());
                }
                warnings
            },
            truncated: trimmed || !omitted_refs.is_empty(),
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
        let mut context = SearchContext {
            query_anchor: scope.anchor.search_anchor(),
            intent: SearchIntent::StageAssistance,
            raw_query: query,
            protected_query: String::new(),
            protected_facets: BTreeSet::new(),
            execution: None,
            query_facets: QueryFacetSet {
                statement_role: evertrace_domain::query::StatementRole::Unknown,
                parse_status: FacetParseStatus::Unknown,
                target_anchors: Vec::new(),
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
        self.protect_search_context(&mut context)?;
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
        let repository_report = scope
            .binding
            .repository_report
            .as_deref()
            .or(report.as_ref());
        let deadline = std::time::Instant::now() + std::time::Duration::from_micros(750_000);
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
                repository_report,
                self.runtime_snapshot.effective_config_hash,
                (scope.anchor.repository_id, scope.anchor.worktree_id),
                Some(&selected),
                deadline,
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
        let restricted = !self
            .blocked_read_rows(
                repository_report,
                &scope.snapshot,
                &[row],
                scope.anchor.repository_id,
            )
            .await?
            .is_empty();
        let read_access = SearchReadAccess {
            writer: &self.writer,
            authority: crate::repository::RepositoryReadAuthority::observed(repository_report),
            frontier: scope.snapshot.frontier,
            config_hash: self.runtime_snapshot.effective_config_hash,
            deadline,
        };
        let field_restricted = if restricted {
            true
        } else if let Some(
            kind @ ("atom_revision" | "revision_proposal_revision" | "semantic_digest"),
        ) = row.object_kind.as_deref()
        {
            let revision = row
                .current_revision_id
                .as_deref()
                .ok_or(McpServiceError::Store)?;
            if kind == "atom_revision" {
                read_access.check_revision(revision).await.is_err()
            } else {
                let key = row.object_id.as_deref().ok_or(McpServiceError::Store)?;
                read_access
                    .check_current(key, revision, kind)
                    .await
                    .is_err()
            }
        } else {
            false
        };
        if field_restricted {
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
                .as_ref()
                .filter(|payload| payload.len() <= 8_192)
                .map(|payload| payload.to_owned_string())
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
            grounded_view: None,
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
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
        let supplemental = ProductionSearch::new(self.search_index.clone())
            .with_validated_frontier(scope.snapshot.frontier)
            .with_procedure_revisions(BTreeSet::new())
            .search(SearchContext {
                query_anchor: scope.anchor.search_anchor(),
                intent: SearchIntent::FailureRecovery,
                protected_query: query.clone(),
                protected_facets: BTreeSet::new(),
                raw_query: query,
                execution: None,
                query_facets: QueryFacetSet {
                    statement_role: evertrace_domain::query::StatementRole::Unknown,
                    parse_status: FacetParseStatus::Complete,
                    target_anchors: Vec::new(),
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
            Ok(found)
                if found.projection_frontier == scope.snapshot.frontier
                    && found.authoritative_frontier == scope.snapshot.frontier =>
            {
                let mut candidates = Vec::new();
                for candidate in found.candidates.iter().take(2) {
                    let mut matching = scope
                        .snapshot
                        .data_rows()
                        .filter(|row| normal_search_candidate_matches_row(candidate, row));
                    if let Some(row) = matching.next()
                        && matching.next().is_none()
                    {
                        candidates.push((candidate, row));
                    } else {
                        completeness = "partial";
                    }
                }
                if !candidates.is_empty() {
                    let rows = candidates.iter().map(|(_, row)| *row).collect::<Vec<_>>();
                    let report = match &self.session_report {
                        Some(report) => report.read().await.clone(),
                        None => None,
                    };
                    let bound_report = scope
                        .binding
                        .repository_report
                        .as_deref()
                        .or(report.as_ref());
                    let blocked = self
                        .blocked_read_rows_from_rows(
                            bound_report,
                            &scope.snapshot.rows,
                            &rows,
                            scope.anchor.repository_id,
                            Some(deadline),
                        )
                        .await;
                    let now = unix_time_us_for_mcp();
                    let label = scope_label(scope);
                    for (candidate, row) in candidates {
                        if std::time::Instant::now() < deadline
                            && blocked
                                .as_ref()
                                .is_ok_and(|refs| !refs.contains(&row.row_id))
                            && let Some(item) = classify_search_candidate_rows(
                                &scope.snapshot.rows,
                                &label,
                                candidate,
                                now,
                            )
                        {
                            items.push(item);
                        } else {
                            completeness = "partial";
                        }
                    }
                }
                // Unreviewed supplement references must not leave through continuation hints.
                if !found.degraded_reasons.is_empty() || !found.omitted_refs.is_empty() {
                    completeness = "partial";
                }
                warnings.extend(found.degraded_reasons);
            }
            _ => {
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
            grounded_view: None,
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
                && matches!(
                    row.payload_json.as_deref().and_then(|json| serde_json::from_str::<JournalPayload>(json).ok()),
                    Some(JournalPayload::EvidenceSurfaceRecorded(surface))
                        if surface.candidate_ref() == candidate.candidate_id && surface.protected_text == candidate.text
                )
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
            let text = if candidate.object_kind.as_deref() == Some("work_episode") {
                let JournalPayload::WorkEpisodeRecorded(episode) =
                    serde_json::from_str(row.payload_json.as_deref()?).ok()?
                else {
                    return None;
                };
                if episode.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Closed {
                    let mut label = "[CLOSED EPISODE]".to_owned();
                    if let Some(worktree_id) = &row.worktree_id {
                        let tree = rows.iter().find(|r| {
                            r.object_kind.as_deref() == Some("worktree")
                                && r.object_id.as_ref() == Some(worktree_id)
                        })?;
                        let JournalPayload::WorktreeInstanceRecorded(tree) =
                            serde_json::from_str(tree.payload_json.as_deref()?).ok()?
                        else {
                            return None;
                        };
                        let pinned = episode
                            .exit_worktree_snapshot_id
                            .or(episode.entry_worktree_snapshot_id);
                        if let Some(snapshot) = pinned {
                            label.push_str(&format!(
                                " [WORKTREE {:?}; SNAPSHOT {snapshot}]",
                                tree.lifecycle
                            ));
                        } else if tree.lifecycle
                            != evertrace_domain::repository::WorktreeLifecycle::Active
                        {
                            return None;
                        }
                    }
                    format!("{label} {}", candidate.text)
                } else {
                    candidate.text.clone()
                }
            } else {
                candidate.text.clone()
            };
            Some(classify_object_row(row, Some(text), is_current, now))
        }
        evertrace_domain::query::SearchCandidateVariant::EvidenceSurface => {
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
    }
}
