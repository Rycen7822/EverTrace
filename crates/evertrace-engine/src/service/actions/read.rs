use super::*;

impl McpActionService {
    pub(super) async fn search(
        &self,
        request_id: RequestId,
        scope: McpRequestScope,
        query: String,
    ) -> Result<McpServiceResult, McpServiceError> {
        if query == "@due" {
            return Ok(
                if matches!(
                    scope.anchor.mechanism,
                    McpScopeMechanism::ExactClaim | McpScopeMechanism::ConnectionScoped
                ) {
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
                        "unknown",
                        ["scope_unresolved"],
                    )
                },
            );
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
            suppression: SuppressionSnapshot::Current {
                generation: PRE_DELETION_SUPPRESSION_GENERATION,
                ref_hashes: BTreeSet::new(),
            },
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
            warnings: payload_omitted
                .then_some("payload_available_by_local_object_ref".into())
                .into_iter()
                .collect(),
            truncated: payload_omitted,
            next_refs: Vec::new(),
        })
    }
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
