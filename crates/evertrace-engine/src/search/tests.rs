#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use evertrace_domain::query::{
        AnswerShape, FacetParseStatus, LifecycleBoundary, NamedGap, NamedGapKind, Polarity,
        QueryFacetSet, RetrievalBudget, RetrievalCompleteness, RetrievalLayer, SearchCandidate,
        SearchContext, SearchIntent, SearchResult, SourceBoundary, SuppressionSnapshot,
        TemporalMode, TemporalQualifier,
    };
    use evertrace_store::{RelationProjectionRow, SearchProjectionRow};

    use super::{DiagnosticRetrieval, production::{hard_compatible, temporal_is_partial}};

    const BASE_REVISION: &str = "01890f47-6a4a-7cc1-98b9-01890f476a00";
    const BASE_ENTITY: &str = "01890f47-6a4a-7cc1-98b9-01890f476a01";

    fn context() -> SearchContext {
        SearchContext {
            intent: SearchIntent::StageAssistance,
            raw_query: "needle".into(),
            query_facets: QueryFacetSet {
                parse_status: FacetParseStatus::Complete,
                exact_identifiers: Vec::new(),
                condition_literals: Vec::new(),
                relation_requirements: Vec::new(),
                polarity: Polarity::Positive,
                explicit_exclusions: Vec::new(),
                temporal_mode: TemporalMode::Any,
                temporal_qualifiers: Vec::new(),
                quantity_constraints: Vec::new(),
                scope_boundary: None,
                source_boundary: None,
                answer_shape: Some(AnswerShape::SourceSnippet),
                lifecycle_boundary: LifecycleBoundary::Active,
            },
            task_id: None,
            repository_id: None,
            worktree_id: None,
            suppression: SuppressionSnapshot::Current {
                generation: 0,
                ref_hashes: BTreeSet::new(),
            },
            budget: RetrievalBudget {
                candidates_remaining: 16,
                tokens_remaining: 1024,
                latency_us_remaining: 1_000_000,
                hops_remaining: 2,
                follow_ups_remaining: 1,
            },
        }
    }

    fn a_result(frontier: u64) -> SearchResult {
        SearchResult {
            layer: RetrievalLayer::A,
            projection_frontier: frontier,
            authoritative_frontier: frontier,
            candidates: vec![SearchCandidate {
                candidate_id: BASE_REVISION.into(),
                source_ref: BASE_ENTITY.into(),
                row_variant: evertrace_domain::query::SearchCandidateVariant::Object,
                object_kind: Some("atom_revision".into()),
                text: "needle base".into(),
                source_role: None,
                content_trust: None,
                capture_completeness: None,
                retrieval_origins: BTreeSet::from(["exact".into()]),
                instruction_authority: "none".into(),
                conflicted: false,
            }],
            completeness: RetrievalCompleteness::Complete,
            degraded_reasons: BTreeSet::new(),
            omitted_refs: BTreeSet::new(),
            budget: context().budget,
        }
    }

    fn object_row(
        candidate: &str,
        entity: &str,
        currentness: &str,
        text: &str,
    ) -> SearchProjectionRow {
        SearchProjectionRow {
            row_id: format!("search:object:{candidate}"),
            row_variant: "object".into(),
            candidate_id: Some(candidate.into()),
            source_ref: Some(entity.into()),
            source_kind: Some("object_projection".into()),
            text: text.into(),
            source_role: None,
            content_trust: None,
            capture_completeness: None,
            instruction_authority: "none".into(),
            object_kind: Some("atom_revision".into()),
            currentness: Some(currentness.into()),
            lifecycle: Some("active".into()),
            epistemic: Some("unverified".into()),
            authority: Some("agent_inferred".into()),
            task_id: None,
            repository_id: None,
            worktree_id: None,
            event_time_us: 7,
            recorded_at_us: 0,
            source_sequence: 0,
            time_domain: "event_time".into(),
            retrieval_completeness: "complete".into(),
            suppression_ref_hash: None,
            source_event_seq: 1,
            projection_generation: 1,
        }
    }

    fn evidence_row(frontier: u64, role: &str) -> SearchProjectionRow {
        let mut row = object_row(
            "01890f47-6a4a-7cc1-98b9-01890f476b00",
            "01890f47-6a4a-7cc1-98b9-01890f476b01",
            "current",
            "needle evidence",
        );
        let hash = "11".repeat(32);
        row.row_id = format!("search:evidence:{}:{hash}", row.source_ref.as_deref().unwrap());
        row.row_variant = "evidence_surface".into();
        row.candidate_id = Some(format!(
            "{}:1:{hash}",
            row.source_ref.as_deref().unwrap()
        ));
        row.source_kind = Some("evidence_surface".into());
        row.source_role = Some(role.into());
        row.content_trust = Some("user_statement".into());
        row.capture_completeness = Some("complete".into());
        row.object_kind = None;
        row.currentness = None;
        row.lifecycle = None;
        row.epistemic = None;
        row.authority = None;
        row.suppression_ref_hash = Some("22".repeat(32));
        row.source_event_seq = frontier;
        row
    }

    fn search_rows(frontier: u64, mut data: Vec<SearchProjectionRow>) -> Vec<SearchProjectionRow> {
        data.push(SearchProjectionRow::checkpoint(frontier));
        data
    }

    fn relation_rows(frontier: u64, mut data: Vec<RelationProjectionRow>) -> Vec<RelationProjectionRow> {
        data.push(RelationProjectionRow::checkpoint(frontier));
        data
    }

    #[test]
    fn two_sessions_keep_deadlines_context_and_frontiers_request_local() {
        let diagnostic = DiagnosticRetrieval::for_characterization();
        let mut first_context = context();
        first_context.query_facets.source_boundary = Some(SourceBoundary::User);
        let second_context = context();
        let mut first = diagnostic.begin(a_result(7), first_context).unwrap();
        let mut second = diagnostic.begin(a_result(9), second_context).unwrap();
        let first_rows = search_rows(7, vec![evidence_row(7, "user")]);
        let second_rows = search_rows(9, vec![evidence_row(9, "assistant")]);
        assert!(first.evidence_surface(&second_rows).is_err());
        first.evidence_surface(&first_rows).unwrap();
        second.evidence_surface(&second_rows).unwrap();
        assert_eq!(first.result().projection_frontier, 7);
        assert_eq!(second.result().projection_frontier, 9);
        assert!(first
            .result()
            .candidates
            .iter()
            .any(|candidate| candidate.source_role.as_deref() == Some("user")));
        assert!(second
            .result()
            .candidates
            .iter()
            .all(|candidate| candidate.source_role.as_deref() != Some("user")));
        let mut tiny = a_result(11);
        tiny.budget.latency_us_remaining = 1;
        let mut exhausted = diagnostic.begin(tiny, context()).unwrap();
        let mut exhausted_rows = Vec::new();
        for index in 0..256u64 {
            let candidate = format!("01890f47-6a4a-7cc1-98b9-{index:012x}");
            exhausted_rows.push(object_row(&candidate, &candidate, "current", "needle"));
        }
        let exhausted_rows = search_rows(11, exhausted_rows);
        assert!(exhausted.evidence_surface(&exhausted_rows).is_err());
        assert_eq!(exhausted.result().budget.latency_us_remaining, 0);
        assert_eq!(exhausted.result().completeness, RetrievalCompleteness::Unknown);
        assert!(second.result().budget.latency_us_remaining > 0);
    }

    #[test]
    fn cross_frontier_search_and_relation_inputs_are_rejected() {
        let diagnostic = DiagnosticRetrieval::for_characterization();
        let mut session = diagnostic.begin(a_result(7), context()).unwrap();
        let rows = search_rows(7, Vec::new());
        session.evidence_surface(&rows).unwrap();
        session.facets().unwrap();
        assert!(session
            .expand(&relation_rows(8, Vec::new()), &rows, 1)
            .is_err());
        let missing_checkpoint = vec![object_row(
            BASE_REVISION,
            BASE_ENTITY,
            "current",
            "needle",
        )];
        let mut other = diagnostic.begin(a_result(7), context()).unwrap();
        assert!(other.evidence_surface(&missing_checkpoint).is_err());

        let mut duplicate = search_rows(7, Vec::new());
        duplicate.push(SearchProjectionRow::checkpoint(7));
        let mut other = diagnostic.begin(a_result(7), context()).unwrap();
        assert!(other.evidence_surface(&duplicate).is_err());

        let mut ahead = object_row(BASE_REVISION, BASE_ENTITY, "current", "needle");
        ahead.source_event_seq = 8;
        let ahead = search_rows(7, vec![ahead]);
        let mut other = diagnostic.begin(a_result(7), context()).unwrap();
        assert!(other.evidence_surface(&ahead).is_err());

        let mut duplicate_relations = relation_rows(7, Vec::new());
        duplicate_relations.push(RelationProjectionRow::checkpoint(7));
        let mut other = diagnostic.begin(a_result(7), context()).unwrap();
        other.evidence_surface(&rows).unwrap();
        other.facets().unwrap();
        assert!(other.expand(&duplicate_relations, &rows, 1).is_err());

        let ahead_relation = RelationProjectionRow::edge(
            "atom_supports",
            8,
            BASE_REVISION.into(),
            BASE_ENTITY.into(),
        );
        let mut other = diagnostic.begin(a_result(7), context()).unwrap();
        other.evidence_surface(&rows).unwrap();
        other.facets().unwrap();
        assert!(other
            .expand(&relation_rows(7, vec![ahead_relation]), &rows, 1)
            .is_err());
    }

    #[test]
    fn stable_gap_selects_unique_current_successor_and_uses_exact_boundary_refs() {
        let diagnostic = DiagnosticRetrieval::for_characterization();
        let entity = "01890f47-6a4a-7cc1-98b9-01890f476c00";
        let historical = "01890f47-6a4a-7cc1-98b9-01890f476c01";
        let current = "01890f47-6a4a-7cc1-98b9-01890f476c02";
        let rows = search_rows(
            7,
            vec![
                object_row(historical, entity, "historical", "needle old"),
                object_row(current, entity, "current", "needle current"),
            ],
        );
        let relations = relation_rows(7, Vec::new());
        let mut historical_base = a_result(7);
        historical_base.candidates[0].candidate_id = historical.into();
        historical_base.candidates[0].source_ref = entity.into();
        let mut session = diagnostic.begin(historical_base, context()).unwrap();
        session.evidence_surface(&rows).unwrap();
        session.facets().unwrap();
        session.expand(&relations, &rows, 0).unwrap();
        let slot = NamedGap {
            kind: NamedGapKind::AllowlistedRelationSlot,
            identifier: "ordinary-text".into(),
            changes_result: true,
        };
        assert!(session.named_gap(Some(&slot), &rows).is_err());
        let gap = NamedGap {
            kind: NamedGapKind::StableObjectId,
            identifier: entity.into(),
            changes_result: true,
        };
        session.named_gap(Some(&gap), &rows).unwrap();
        let view = session.grounded_view(Vec::new()).unwrap();
        assert_eq!(
            view.candidate_set.added_candidate_refs,
            BTreeSet::from([current.into()])
        );
        assert!(view
            .active_evidence
            .iter()
            .all(|statement| statement.support_refs.is_subset(&view.candidate_set.candidate_refs)));
        assert!(session.named_gap(Some(&gap), &rows).is_err());

        let mut no_delta_result = a_result(7);
        no_delta_result.candidates[0].candidate_id = current.into();
        no_delta_result.candidates[0].source_ref = entity.into();
        let mut no_delta = diagnostic.begin(no_delta_result, context()).unwrap();
        no_delta.evidence_surface(&rows).unwrap();
        no_delta.facets().unwrap();
        no_delta.expand(&relations, &rows, 0).unwrap();
        assert!(no_delta.named_gap(Some(&gap), &rows).is_err());

        let mut ambiguous_rows = rows.clone();
        ambiguous_rows.insert(
            0,
            object_row(
                "01890f47-6a4a-7cc1-98b9-01890f476c03",
                entity,
                "current",
                "needle ambiguous",
            ),
        );
        let mut ambiguous = diagnostic.begin(a_result(7), context()).unwrap();
        ambiguous.evidence_surface(&ambiguous_rows).unwrap();
        ambiguous.facets().unwrap();
        assert!(ambiguous.expand(&relations, &ambiguous_rows, 0).is_err());
    }

    #[test]
    fn large_diagnostic_slice_and_gev_stop_on_the_request_deadline() {
        let diagnostic = DiagnosticRetrieval::for_characterization();
        let mut result = a_result(7);
        result.budget.latency_us_remaining = 10_000;
        result.candidates.clear();
        for index in 0..20_000u64 {
            let candidate = format!("01890f47-6a4a-7cc1-98b9-{index:012x}");
            result.candidates.push(SearchCandidate {
                candidate_id: candidate.clone(),
                source_ref: candidate,
                row_variant: evertrace_domain::query::SearchCandidateVariant::Object,
                object_kind: Some("atom_revision".into()),
                text: "needle".into(),
                source_role: None,
                content_trust: None,
                capture_completeness: None,
                retrieval_origins: BTreeSet::from(["exact".into()]),
                instruction_authority: "none".into(),
                conflicted: false,
            });
        }
        let rows = search_rows(7, Vec::new());
        let relations = relation_rows(7, Vec::new());
        let mut session = diagnostic.begin(result, context()).unwrap();
        session.evidence_surface(&rows).unwrap();
        session.facets().unwrap();
        session.expand(&relations, &rows, 0).unwrap();
        assert!(session.grounded_view(Vec::new()).is_err());
        assert_eq!(session.result().completeness, RetrievalCompleteness::Unknown);
        assert_eq!(session.result().budget.latency_us_remaining, 0);
        assert!(
            session
                .result()
                .degraded_reasons
                .contains("diagnostic_deadline_exhausted")
        );
    }

    #[test]
    fn source_boundary_and_temporal_domains_remain_variant_aware() {
        let mut user = context();
        user.query_facets.source_boundary = Some(SourceBoundary::User);
        let mut object = object_row(BASE_REVISION, BASE_ENTITY, "current", "needle");
        object.authority = Some("user_explicit".into());
        assert!(hard_compatible(&object, &user).unwrap());
        object.authority = Some("agent_inferred".into());
        assert!(!hard_compatible(&object, &user).unwrap());
        let evidence = evidence_row(7, "user");
        assert!(hard_compatible(&evidence, &user).unwrap());

        let candidate = a_result(7).candidates.remove(0);
        let mut temporal = context();
        temporal.query_facets.temporal_mode = TemporalMode::AsOf;
        temporal.query_facets.temporal_qualifiers =
            vec![TemporalQualifier::EventTimeAsOf { at_us: 8 }];
        let mut reasons = BTreeSet::new();
        assert!(!temporal_is_partial(
            &[(0, candidate.clone(), &object)],
            &temporal,
            &mut reasons
        ));
        object.time_domain = "none".into();
        assert!(temporal_is_partial(
            &[(0, candidate, &object)],
            &temporal,
            &mut reasons
        ));
    }
}
