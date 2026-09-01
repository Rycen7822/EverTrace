use super::*;

impl McpActionService {
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
        let found = ProductionSearch::new(self.search_index.clone())
            .search(context)
            .await
            .map_err(|_| McpServiceError::Store)?;
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
        let mut classified = Vec::new();
        let mut classification_omitted = BTreeSet::new();
        let now = unix_time_us_for_mcp();
        for candidate in found.candidates.into_iter().take(3) {
            match classify_search_candidate(&scope, &candidate, now) {
                Some(item) => classified.push(item),
                None => {
                    classification_omitted.insert(candidate.candidate_id);
                }
            }
        }
        let mut omitted_refs = found.omitted_refs;
        omitted_refs.extend(classification_omitted);
        if !omitted_refs.is_empty() {
            status = McpServiceStatus::Partial;
            completeness = "partial";
        }
        Ok(McpServiceResult {
            request_id,
            status,
            scope: scope_label(&scope),
            freshness: if found.projection_frontier == found.authoritative_frontier {
                "current".into()
            } else {
                "stale".into()
            },
            completeness: completeness.into(),
            items: classified,
            warnings: {
                let mut warnings = found.degraded_reasons.into_iter().collect::<Vec<_>>();
                if scope.anchor.cwd_only {
                    warnings.push("cwd_only_scope".into());
                }
                warnings
            },
            truncated: !omitted_refs.is_empty(),
            next_refs: omitted_refs.into_iter().take(32).collect(),
        })
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
        let payload = row
            .payload_json
            .clone()
            .filter(|payload| payload.len() <= 8_192);
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

fn retained_forgotten_source(
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
    for candidate in snapshot.data_rows() {
        if !matches!(
            candidate.object_kind.as_deref(),
            Some("evidence_surface" | "source_observation" | "source_receipt")
        ) {
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
    let ledger =
        ObjectDeletionCurrentView::from_snapshot(snapshot).map_err(|_| McpServiceError::Store)?;
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
    match candidate.row_variant {
        evertrace_domain::query::SearchCandidateVariant::Object => {
            let (row, is_current) = select_object_row(&scope.snapshot, &candidate.candidate_id)
                .ok()
                .flatten()?;
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
                scope: Some(scope_label(scope)),
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
