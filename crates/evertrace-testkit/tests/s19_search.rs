use std::{collections::BTreeSet, path::Path};

use evertrace_capture::{
    CaptureRecordInput, CaptureRuntime, DeviceKeyStore, RUNTIME_SNAPSHOT_VERSION, RecoveryGateMode,
    RuntimeSnapshot, SpoolLimits,
};
use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceInstanceId,
        SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole,
        source_observation_id,
    },
    ids::{CommandId, WorkArtifactId},
    query::{
        AnswerShape, CandidateBoundary, FacetParseStatus, GateStatus, LifecycleBoundary, NamedGap,
        NamedGapKind, Polarity, QuantityConstraint, QueryFacetSet, RetrievalBudget,
        RetrievalCompleteness, RetrievalLayer, ScopeBoundary, SearchContext, SearchIntent,
        SourceBoundary, SuppressionSnapshot, TemporalMode, TemporalQualifier,
        production_retrieval_layer, retrieval_gate,
    },
    revision::RevisionId,
    semantic::{
        ApplicabilityExpr, Atom, AtomDraft, AtomKind, AtomProvenance, AtomScope, AtomValue,
        ConstraintExpr, ConstraintField, EpistemicStatus, SemanticQualifier, ValidityInterval,
    },
    work::{
        ArtifactDerivability, ArtifactPayloadStatus, ArtifactRetention, ArtifactRevision,
        ArtifactScope, WorkArtifact, WorkArtifactKind,
    },
};
use evertrace_engine::{
    EvidenceIngestor, open_writer,
    search::{DiagnosticFtsFailure, DiagnosticRetrieval, ProductionSearch},
    semantic::{AtomAuthorityBasis, AtomMaterialization, materialize_atom},
    spawn_writer,
};
use evertrace_store::{
    JournalCommand, JournalEventDraft, JournalPayload, JournalWriter, MigrationOutcome,
    SearchHardFilter, SearchIndex, derive_l0002_projections, object_projection_hash,
};
use tempfile::TempDir;

fn snapshot(root: &Path) -> RuntimeSnapshot {
    let limits = SpoolLimits {
        high_watermark_bytes: 2 << 20,
        low_watermark_bytes: 64 << 10,
        max_main_files: 16,
        emergency_slots: 2,
    };
    RuntimeSnapshot {
        snapshot_version: RUNTIME_SNAPSHOT_VERSION,
        generation: 1,
        device_key_dir: root.join("keys"),
        cas_dir: root.join("cas"),
        spool_dir: root.join("spool"),
        main_high_watermark_bytes: limits.high_watermark_bytes,
        main_low_watermark_bytes: limits.low_watermark_bytes,
        max_main_files: limits.max_main_files,
        emergency_slots: limits.emergency_slots,
        recovery_gate: RecoveryGateMode::Disabled,
        recovery_socket_path: root.join("runtime/evertraced-v1.sock"),
        recovery_preflight_timeout_ms: 250,
        effective_config_hash: [0x19; 32],
        recovery_adapter_manifest_id: None,
        recovery_classifier_revision: 1,
        recovery_max_bundle_bytes: 4 << 20,
        recovery_max_untracked_file_bytes: 1 << 20,
        recovery_max_untracked_total_bytes: 2 << 20,
        recall_cue_gate: evertrace_capture::RecallCueGateMode::Disabled,
        recall_cue_adapter_manifest_id: None,
        recall_cues: Vec::new(),
    }
}

fn input(record: &str, sequence: u64, text: &str, role: SourceRole) -> CaptureRecordInput {
    CaptureRecordInput {
        spool_record_id: Some(format!("s19-{record}")),
        source_observation_id_hint: None,
        source_instance_id: "source-s19".into(),
        source_revision: "revision-s19".into(),
        source_record_identity: Some(record.into()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        source_ref: "source-s19".into(),
        session_ref: "session-s19".into(),
        turn_ref: Some(format!("turn-{sequence}")),
        tool_ref: None,
        source_sequence: sequence,
        source_sequence_origin: Some(1),
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        source_byte_range: None,
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: None,
        observation_role: ObservationRole::Result,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            pairing_role: ObservationRole::Result,
            field_provenance: Vec::new(),
            adapter_manifest_ref: "adapter-s19".into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: Vec::new(),
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: role,
        content_trust: match role {
            SourceRole::User => ContentTrust::UserStatement,
            SourceRole::Assistant => ContentTrust::AgentClaim,
            SourceRole::Imported => ContentTrust::ImportedClaim,
            SourceRole::Tool | SourceRole::Host => ContentTrust::Observed,
        },
        capture_completeness: CaptureCompleteness::Complete,
        surface_eligible: true,
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-s19".into(),
        eligible_event_manifest_ref: "eligible-s19".into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: Some(i64::try_from(sequence).unwrap()),
        raw_payload: text.as_bytes().to_vec(),
    }
}

fn context(query: &str, exact: &[&str], suppression: SuppressionSnapshot) -> SearchContext {
    SearchContext {
        intent: SearchIntent::StageAssistance,
        raw_query: query.into(),
        query_facets: QueryFacetSet {
            parse_status: FacetParseStatus::Complete,
            exact_identifiers: exact.iter().map(|value| (*value).into()).collect(),
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
        suppression,
        budget: RetrievalBudget {
            candidates_remaining: 16,
            tokens_remaining: 1200,
            latency_us_remaining: 1_000_000,
            hops_remaining: 2,
            follow_ups_remaining: 1,
        },
    }
}

fn atom_command(
    record: &str,
    text: &str,
    at_us: i64,
    supports_revision_refs: Vec<RevisionId>,
) -> (JournalCommand, RevisionId) {
    let observation = source_observation_id(
        &SourceInstanceId::parse("source-s19").unwrap(),
        &SourceRevision::parse("revision-s19").unwrap(),
        &SourceRecordIdentity::parse(record).unwrap(),
    )
    .unwrap();
    let atom = materialize_atom(
        AtomMaterialization {
            draft: AtomDraft {
                kind: AtomKind::Claim,
                epistemic_status: EpistemicStatus::Unverified,
                value: AtomValue {
                    text: text.into(),
                    subject: "s19 retrieval".into(),
                    predicate: "reports".into(),
                    object: None,
                    qualifiers: vec![SemanticQualifier {
                        name: "suite".into(),
                        value: "s19".into(),
                    }],
                    critical_revision_refs: Vec::new(),
                },
                scope: AtomScope::Global,
                applicability_expr: ApplicabilityExpr::Constraint(ConstraintExpr::Exists {
                    field: ConstraintField::Phase,
                }),
                future_cue_lifecycle_exprs: None,
                validity_interval: ValidityInterval {
                    valid_from_us: 1,
                    valid_until_us: Some(100),
                },
                provenance: vec![AtomProvenance::AgentClaimed],
                source_observation_refs: vec![observation],
                evidence_refs: vec![observation.to_string()],
                supersedes_revision_refs: Vec::new(),
                supports_revision_refs,
                contradicts_revision_refs: Vec::new(),
            },
            authority_basis: AtomAuthorityBasis::AgentInferred,
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: at_us,
        },
        None,
    )
    .unwrap();
    let revision_id = atom.revision_id;
    let command = JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft::runtime(
            at_us,
            [0x19; 32],
            "s19-search-v2",
            JournalPayload::AtomRecorded(Box::new(atom)),
        )],
    )
    .unwrap();
    (command, revision_id)
}

fn atom_successor(record: &str, text: &str, at_us: i64, current: Option<&Atom>) -> Atom {
    let observation = source_observation_id(
        &SourceInstanceId::parse("source-s19").unwrap(),
        &SourceRevision::parse("revision-s19").unwrap(),
        &SourceRecordIdentity::parse(record).unwrap(),
    )
    .unwrap();
    materialize_atom(
        AtomMaterialization {
            draft: AtomDraft {
                kind: AtomKind::Claim,
                epistemic_status: EpistemicStatus::Unverified,
                value: AtomValue {
                    text: text.into(),
                    subject: "s19 successor".into(),
                    predicate: "reports".into(),
                    object: None,
                    qualifiers: Vec::new(),
                    critical_revision_refs: Vec::new(),
                },
                scope: AtomScope::Global,
                applicability_expr: ApplicabilityExpr::Constraint(ConstraintExpr::Exists {
                    field: ConstraintField::Phase,
                }),
                future_cue_lifecycle_exprs: None,
                validity_interval: ValidityInterval {
                    valid_from_us: 1,
                    valid_until_us: Some(100),
                },
                provenance: vec![AtomProvenance::AgentClaimed],
                source_observation_refs: vec![observation],
                evidence_refs: vec![observation.to_string()],
                supersedes_revision_refs: current
                    .map(|value| vec![value.revision_id])
                    .unwrap_or_default(),
                supports_revision_refs: Vec::new(),
                contradicts_revision_refs: Vec::new(),
            },
            authority_basis: AtomAuthorityBasis::AgentInferred,
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: at_us,
        },
        current,
    )
    .unwrap()
}

#[tokio::test]
async fn l0002_real_fts_latest_delta_deletion_first_and_diagnostic_gates() {
    let temp = TempDir::new().unwrap();
    DeviceKeyStore::new(temp.path().join("keys"))
        .load_or_create()
        .unwrap();
    let runtime_snapshot = snapshot(temp.path());
    let mut runtime = CaptureRuntime::open(runtime_snapshot.clone()).unwrap();
    runtime
        .capture(input(
            "english",
            1,
            "Rust memory retrieval exact-19",
            SourceRole::User,
        ))
        .unwrap();
    runtime
        .capture(input(
            "conflict-user",
            3,
            "conflict19 enabled",
            SourceRole::User,
        ))
        .unwrap();
    runtime
        .capture(input(
            "conflict-assistant",
            4,
            "conflict19 disabled",
            SourceRole::Assistant,
        ))
        .unwrap();
    runtime
        .capture(input(
            "chinese",
            2,
            "中文记忆检索 stable-19",
            SourceRole::Tool,
        ))
        .unwrap();

    let store = temp.path().join("store");
    let writer = open_writer(&store).await.unwrap();
    assert_eq!(writer.migration_outcome(), MigrationOutcome::Applied);
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ingestor =
        EvidenceIngestor::new(runtime_snapshot, handle.clone(), [0x19; 32], "s19-v1").unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 4);
    let mut revisions = Vec::new();
    for (record, text, at_us, supports) in [
        ("english", "Rust memory retrieval exact-19", 10, Vec::new()),
        ("conflict-user", "conflict19 enabled", 11, Vec::new()),
        ("conflict-assistant", "conflict19 disabled", 12, Vec::new()),
        ("chinese", "中文记忆检索 stable-19", 13, Vec::new()),
    ] {
        let (command, revision_id) = atom_command(record, text, at_us, supports);
        handle.commit(command, at_us).await.unwrap();
        revisions.push(revision_id);
    }
    let stale_atom = atom_successor("english", "stale successor value", 16, None);
    let stale_revision = stale_atom.revision_id;
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    16,
                    [0x19; 32],
                    "s19-successor-v1",
                    JournalPayload::AtomRecorded(Box::new(stale_atom.clone())),
                )],
            )
            .unwrap(),
            16,
        )
        .await
        .unwrap();
    let current_atom = atom_successor("english", "current successor value", 17, Some(&stale_atom));
    let current_revision = current_atom.revision_id;
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    17,
                    [0x19; 32],
                    "s19-successor-v2",
                    JournalPayload::AtomRecorded(Box::new(current_atom)),
                )],
            )
            .unwrap(),
            17,
        )
        .await
        .unwrap();
    let secret_canary = "S19_SECRET_CANARY_external_reference";
    let artifact_observation = source_observation_id(
        &SourceInstanceId::parse("source-s19").unwrap(),
        &SourceRevision::parse("revision-s19").unwrap(),
        &SourceRecordIdentity::parse("english").unwrap(),
    )
    .unwrap();
    let artifact = WorkArtifact {
        work_artifact_id: WorkArtifactId::new_v7(),
        revision: ArtifactRevision {
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            kind: WorkArtifactKind::ExperimentOutput,
            logical_name: "safe-metrics.json".into(),
            scope: ArtifactScope::Global,
            media_type: "application/json".into(),
            content_blob_ref: None,
            external_reference: Some(secret_canary.into()),
            content_fingerprint: None,
            payload_status: ArtifactPayloadStatus::MetadataOnly,
            produced_by_refs: Vec::new(),
            consumed_by_refs: Vec::new(),
            source_observation_refs: vec![artifact_observation],
            derivability: ArtifactDerivability::Reproducible,
            retention: ArtifactRetention::Repository,
            created_at_us: 18,
        },
    };
    artifact.validate().unwrap();
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    18,
                    [0x19; 32],
                    "s19-artifact-canary-v1",
                    JournalPayload::WorkArtifactRecorded(Box::new(artifact)),
                )],
            )
            .unwrap(),
            18,
        )
        .await
        .unwrap();
    handle.project().await.unwrap();

    let index = SearchIndex::open(&store).await.unwrap();
    assert_eq!(index.fts("Rust").await.unwrap().len(), 2);
    assert_eq!(index.fts("检索").await.unwrap().len(), 2);
    assert!(index.fts(secret_canary).await.unwrap().is_empty());
    assert!(
        index
            .all()
            .await
            .unwrap()
            .iter()
            .all(|row| !row.text.contains(secret_canary))
    );

    runtime
        .capture(input("latest", 5, "latest 检索 delta-19", SourceRole::Tool))
        .unwrap();
    assert_eq!(ingestor.drain_once().await.unwrap().committed_frames, 1);
    let (latest_command, latest_revision) =
        atom_command("latest", "latest 检索 delta-19", 14, vec![revisions[3]]);
    handle.commit(latest_command, 14).await.unwrap();
    let (followup_command, _) = atom_command(
        "latest",
        "chain-followup diagnostic root",
        15,
        vec![latest_revision],
    );
    handle.commit(followup_command, 15).await.unwrap();
    let stale_service = ProductionSearch::new(index.clone());
    let stale_result = stale_service
        .search(context(
            "Rust",
            &["exact-19"],
            SuppressionSnapshot::Current {
                generation: 0,
                ref_hashes: BTreeSet::new(),
            },
        ))
        .await
        .unwrap();
    assert!(stale_result.projection_frontier < stale_result.authoritative_frontier);
    assert_eq!(stale_result.completeness, RetrievalCompleteness::Partial);
    assert!(
        stale_result
            .degraded_reasons
            .contains("search_projection_stale")
    );
    assert!(!stale_result.candidates.is_empty());
    handle.project().await.unwrap();
    let caught_up_result = stale_service
        .search(context(
            "Rust",
            &["exact-19"],
            SuppressionSnapshot::Current {
                generation: 0,
                ref_hashes: BTreeSet::new(),
            },
        ))
        .await
        .unwrap();
    assert_eq!(
        caught_up_result.projection_frontier,
        caught_up_result.authoritative_frontier
    );
    assert_eq!(
        caught_up_result.completeness,
        RetrievalCompleteness::Complete
    );
    assert_eq!(
        index.fts("检索").await.unwrap().len(),
        4,
        "default FTS must include the latest unindexed delta"
    );
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    drop(runtime);
    let reopened = JournalWriter::open(&store).await.unwrap();
    let relation_rows = reopened.relation_rows().await.unwrap();

    let service = ProductionSearch::new(index.clone());
    let current = SuppressionSnapshot::Current {
        generation: 1,
        ref_hashes: BTreeSet::new(),
    };
    let mut deadline_context = context("retrieval", &["exact-19"], current.clone());
    deadline_context.budget.latency_us_remaining = 1;
    let deadline_result = service.search(deadline_context).await.unwrap();
    assert_eq!(deadline_result.completeness, RetrievalCompleteness::Unknown);
    assert_eq!(deadline_result.budget.latency_us_remaining, 0);
    assert!(
        deadline_result
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("deadline_exhausted"))
    );
    let result = service
        .search(context("retrieval", &["exact-19"], current.clone()))
        .await
        .unwrap();
    assert_eq!(result.layer, RetrievalLayer::A);
    assert!(
        result
            .candidates
            .iter()
            .any(|candidate| candidate.text.contains("exact-19")
                && candidate.instruction_authority == "none")
    );
    let stale_revision_text = stale_revision.to_string();
    let mut history_context = context(
        "stale successor value",
        &[stale_revision_text.as_str()],
        current.clone(),
    );
    history_context.intent = SearchIntent::HistoryLookup;
    let history = service.search(history_context).await.unwrap();
    assert_eq!(history.layer, RetrievalLayer::A);
    assert!(
        history
            .candidates
            .iter()
            .any(|candidate| candidate.candidate_id == stale_revision_text)
    );
    let mut history_with_surface = context("Rust memory retrieval", &[], current.clone());
    history_with_surface.intent = SearchIntent::HistoryLookup;
    let history_with_surface = service.search(history_with_surface).await.unwrap();
    assert_eq!(history_with_surface.layer, RetrievalLayer::A);
    assert!(
        history_with_surface
            .candidates
            .iter()
            .all(|candidate| candidate.source_role.is_none())
    );
    assert!(
        service
            .search(context(
                "stale successor value",
                &[stale_revision_text.as_str()],
                current.clone(),
            ))
            .await
            .unwrap()
            .candidates
            .iter()
            .all(|candidate| candidate.candidate_id != stale_revision_text)
    );
    let mut successor_as_of = context(
        "stale successor value",
        &[stale_revision_text.as_str()],
        current.clone(),
    );
    successor_as_of.query_facets.temporal_mode = TemporalMode::AsOf;
    successor_as_of.query_facets.temporal_qualifiers =
        vec![TemporalQualifier::EventTimeAsOf { at_us: 16 }];
    let successor_as_of = service.search(successor_as_of).await.unwrap();
    assert!(
        successor_as_of
            .candidates
            .iter()
            .any(|candidate| candidate.candidate_id == stale_revision_text)
    );
    let conflict = service
        .search(context("conflict19", &["conflict19"], current.clone()))
        .await
        .unwrap();
    assert_eq!(conflict.completeness, RetrievalCompleteness::Conflicted);
    assert_eq!(
        conflict
            .candidates
            .iter()
            .filter(|candidate| candidate.conflicted)
            .count(),
        2
    );

    let mut excluded_context = context("conflict19", &["conflict19"], current.clone());
    excluded_context
        .query_facets
        .explicit_exclusions
        .push("disabled".into());
    assert!(
        service
            .search(excluded_context)
            .await
            .unwrap()
            .candidates
            .iter()
            .all(|candidate| !candidate.text.contains("disabled"))
    );
    let mut quantity_context = context("retrieval", &[], current.clone());
    quantity_context
        .query_facets
        .quantity_constraints
        .push(QuantityConstraint::ResultLimit { limit: 1 });
    assert!(
        service
            .search(quantity_context)
            .await
            .unwrap()
            .candidates
            .len()
            <= 1
    );
    let mut source_context = context("retrieval", &[], current.clone());
    source_context.query_facets.source_boundary = Some(SourceBoundary::User);
    assert!(
        service
            .search(source_context)
            .await
            .unwrap()
            .candidates
            .is_empty()
    );
    let mut agent_source_context = context("retrieval", &[], current.clone());
    agent_source_context.query_facets.source_boundary = Some(SourceBoundary::AgentInferred);
    assert!(
        !service
            .search(agent_source_context)
            .await
            .unwrap()
            .candidates
            .is_empty()
    );
    let mut scope_context = context("retrieval", &[], current.clone());
    scope_context.query_facets.scope_boundary = Some(ScopeBoundary::Repository {
        repository_id: evertrace_domain::ids::RepositoryId::new_v7(),
    });
    assert!(
        service
            .search(scope_context)
            .await
            .unwrap()
            .candidates
            .is_empty()
    );
    let mut negative_context = context("retrieval", &[], current.clone());
    negative_context.query_facets.polarity = Polarity::Negative;
    let negative = service.search(negative_context).await.unwrap();
    assert!(negative.candidates.is_empty());
    assert_eq!(negative.completeness, RetrievalCompleteness::Unknown);
    let mut current_context = context("retrieval", &[], current.clone());
    current_context.query_facets.temporal_mode = TemporalMode::Current;
    assert_eq!(
        service.search(current_context).await.unwrap().completeness,
        RetrievalCompleteness::Complete
    );
    let mut as_of_context = context("conflict19", &["conflict19"], current.clone());
    as_of_context.query_facets.temporal_mode = TemporalMode::AsOf;
    as_of_context.query_facets.temporal_qualifiers =
        vec![TemporalQualifier::EventTimeAsOf { at_us: 11 }];
    let as_of = service.search(as_of_context).await.unwrap();
    assert_eq!(as_of.layer, RetrievalLayer::A);
    assert!(
        as_of
            .candidates
            .iter()
            .all(|candidate| candidate.source_role.is_none())
    );
    assert!(
        as_of
            .candidates
            .iter()
            .any(|candidate| candidate.text.contains("enabled"))
    );
    assert!(
        as_of
            .candidates
            .iter()
            .all(|candidate| !candidate.text.contains("disabled"))
    );
    let mut terminal_context = context("retrieval", &[], current.clone());
    terminal_context.query_facets.lifecycle_boundary = LifecycleBoundary::Terminal;
    assert!(
        service
            .search(terminal_context)
            .await
            .unwrap()
            .candidates
            .is_empty()
    );

    let rows = index.all().await.unwrap();
    assert!(rows.iter().any(|row| {
        row.row_variant == "object"
            && row.candidate_id.as_deref() == Some(current_revision.to_string().as_str())
            && row.currentness.as_deref() == Some("current")
    }));
    assert!(rows.iter().any(|row| {
        row.candidate_id.as_deref() == Some(stale_revision.to_string().as_str())
            && row.currentness.as_deref() == Some("historical")
    }));
    let pinned = index.snapshot().await.unwrap();
    assert!(pinned.frontier() > 0);
    assert!(pinned.authoritative_frontier() >= pinned.frontier());
    let bounded_filter = SearchHardFilter {
        current_only: true,
        lifecycle: Some("active".into()),
        ..SearchHardFilter::default()
    };
    assert!(
        pinned
            .fts("retrieval", &bounded_filter, 1)
            .await
            .unwrap()
            .len()
            <= 1
    );
    let exact_candidate = rows
        .iter()
        .find(|row| row.row_variant == "object" && row.text.contains("exact-19"))
        .and_then(|row| row.candidate_id.clone())
        .unwrap();
    let exact_fallback = service
        .search_with_diagnostic_fts_failure(
            context("(", &[exact_candidate.as_str()], current.clone()),
            DiagnosticFtsFailure::for_characterization(),
        )
        .await
        .unwrap();
    assert!(
        exact_fallback
            .candidates
            .iter()
            .any(|candidate| candidate.candidate_id == exact_candidate)
    );
    assert!(exact_fallback.degraded_reasons.contains("fts_unavailable"));
    let suppressed = rows
        .iter()
        .find(|row| row.row_variant == "object" && row.text.contains("exact-19"))
        .and_then(|row| row.source_ref.clone())
        .unwrap();
    let suppressed_surface = rows
        .iter()
        .find(|row| row.row_variant == "evidence_surface" && row.text.contains("exact-19"))
        .and_then(|row| row.suppression_ref_hash.clone())
        .unwrap();
    let alternate = rows
        .iter()
        .find(|row| {
            row.row_variant == "object"
                && row.source_ref.as_deref() != Some(suppressed.as_str())
                && row.text.contains("conflict19")
        })
        .unwrap();
    let prelimit_filter = SearchHardFilter {
        current_only: true,
        lifecycle: Some("active".into()),
        suppressed_refs: BTreeSet::from([suppressed.clone()]),
        ..SearchHardFilter::default()
    };
    let prelimit = pinned
        .structured(
            &[
                exact_candidate.clone(),
                alternate.candidate_id.clone().unwrap(),
            ],
            &prelimit_filter,
            1,
        )
        .await
        .unwrap();
    assert_eq!(prelimit.len(), 1);
    assert_ne!(prelimit[0].source_ref.as_deref(), Some(suppressed.as_str()));
    let temporal_prelimit = pinned
        .structured(
            &[current_revision.to_string(), stale_revision.to_string()],
            &SearchHardFilter {
                event_time_as_of: Some(16),
                ..SearchHardFilter::default()
            },
            1,
        )
        .await
        .unwrap();
    assert_eq!(temporal_prelimit.len(), 1);
    assert_eq!(
        temporal_prelimit[0].candidate_id.as_deref(),
        Some(stale_revision.to_string().as_str())
    );
    let evidence_candidate = rows
        .iter()
        .find(|row| row.row_variant == "evidence_surface" && row.text.contains("exact-19"))
        .and_then(|row| row.candidate_id.clone())
        .unwrap();
    let object_only_prelimit = pinned
        .structured(
            &[evidence_candidate, exact_candidate.clone()],
            &SearchHardFilter {
                object_only: true,
                ..SearchHardFilter::default()
            },
            1,
        )
        .await
        .unwrap();
    assert_eq!(object_only_prelimit.len(), 1);
    assert_eq!(object_only_prelimit[0].row_variant, "object");
    let suppression_set = BTreeSet::from([suppressed.clone(), suppressed_surface]);
    let denied = service
        .search(context(
            "retrieval",
            &["exact-19"],
            SuppressionSnapshot::Current {
                generation: 2,
                ref_hashes: suppression_set.clone(),
            },
        ))
        .await
        .unwrap();
    assert!(
        denied
            .candidates
            .iter()
            .all(|candidate| !candidate.text.contains("exact-19"))
    );
    assert!(!denied.omitted_refs.contains(&exact_candidate));
    let mut excluded_context = context("retrieval", &["exact-19"], current.clone());
    excluded_context
        .query_facets
        .explicit_exclusions
        .push(exact_candidate.clone());
    excluded_context.budget.tokens_remaining = 1;
    let excluded = service.search(excluded_context).await.unwrap();
    assert!(!excluded.omitted_refs.contains(&exact_candidate));
    let diagnostic = DiagnosticRetrieval::for_characterization();
    let mut user_surface_context = context("Rust memory retrieval", &[], current.clone());
    user_surface_context.query_facets.source_boundary = Some(SourceBoundary::User);
    let user_surface_a = service.search(user_surface_context.clone()).await.unwrap();
    let mut user_session = diagnostic
        .begin(user_surface_a, user_surface_context.clone())
        .unwrap();
    user_session.evidence_surface(&rows).unwrap();
    let user_surface_b = user_session.result();
    assert!(
        user_surface_b
            .candidates
            .iter()
            .any(|candidate| candidate.source_role.as_deref() == Some("user"))
    );
    let mut assistant_surface_context = user_surface_context.clone();
    assistant_surface_context.query_facets.source_boundary = Some(SourceBoundary::Assistant);
    let assistant_surface_a = service
        .search(assistant_surface_context.clone())
        .await
        .unwrap();
    let mut assistant_session = diagnostic
        .begin(assistant_surface_a, assistant_surface_context.clone())
        .unwrap();
    assistant_session.evidence_surface(&rows).unwrap();
    let assistant_surface_b = assistant_session.result();
    assert!(
        assistant_surface_b
            .candidates
            .iter()
            .all(|candidate| candidate.source_role.as_deref() != Some("user"))
    );
    let denied_context = context(
        "retrieval",
        &["exact-19"],
        SuppressionSnapshot::Current {
            generation: 2,
            ref_hashes: suppression_set,
        },
    );
    let mut denied_session = diagnostic.begin(denied, denied_context).unwrap();
    denied_session.evidence_surface(&rows).unwrap();
    let denied_b = denied_session.result();
    assert!(
        denied_b
            .candidates
            .iter()
            .all(|candidate| !candidate.text.contains("exact-19"))
    );
    let unavailable = service
        .search(context("retrieval", &[], SuppressionSnapshot::Unavailable))
        .await
        .unwrap();
    assert!(unavailable.candidates.is_empty());
    assert_eq!(unavailable.completeness, RetrievalCompleteness::Unknown);

    assert_eq!(production_retrieval_layer(), RetrievalLayer::A);
    assert_eq!(retrieval_gate(RetrievalLayer::A), GateStatus::Passed);
    for layer in [
        RetrievalLayer::B,
        RetrievalLayer::C,
        RetrievalLayer::D,
        RetrievalLayer::E,
    ] {
        assert_eq!(retrieval_gate(layer), GateStatus::NotCharacterized);
    }
    let mut c_context = context("Rust", &[], current.clone());
    c_context
        .query_facets
        .condition_literals
        .push("no-such-condition".into());
    let base = service.search(c_context.clone()).await.unwrap();
    let mut c_session = diagnostic.begin(base, c_context).unwrap();
    c_session.evidence_surface(&rows).unwrap();
    let b_count = c_session.result().candidates.len();
    assert_eq!(
        b_count, 2,
        "B adds only the query-relevant evidence surface"
    );
    c_session.facets().unwrap();
    assert!(
        c_session.result().candidates.len() < b_count,
        "C must have a deterministic delta"
    );

    let d_context = context("chain-followup", &[], current);
    let d_a = service.search(d_context.clone()).await.unwrap();
    let mut d_session = diagnostic.begin(d_a, d_context.clone()).unwrap();
    d_session.evidence_surface(&rows).unwrap();
    d_session.facets().unwrap();
    let before_expand = d_session.result().candidates.len();
    d_session.expand(&relation_rows, &rows, 2).unwrap();
    let d = d_session.result().clone();
    assert!(d.candidates.len() >= before_expand + 2);
    let fresh_a = service.search(d_context.clone()).await.unwrap();
    let mut fresh_session = diagnostic.begin(fresh_a, d_context).unwrap();
    fresh_session.evidence_surface(&rows).unwrap();
    fresh_session.facets().unwrap();
    assert!(fresh_session.expand(&relation_rows, &rows, 3).is_err());
    let existing_refs = d
        .candidates
        .iter()
        .map(|candidate| candidate.source_ref.as_str())
        .collect::<BTreeSet<_>>();
    let gap_id = rows
        .iter()
        .find(|row| {
            row.row_variant == "object"
                && row
                    .source_ref
                    .as_deref()
                    .is_some_and(|reference| !existing_refs.contains(reference))
        })
        .and_then(|row| row.candidate_id.as_deref())
        .unwrap();
    let gap = NamedGap {
        kind: NamedGapKind::ExactIdentifier,
        identifier: gap_id.into(),
        changes_result: true,
    };
    let no_delta_gap = NamedGap {
        kind: NamedGapKind::StableObjectId,
        identifier: d.candidates[0].source_ref.clone(),
        changes_result: true,
    };
    assert!(d_session.named_gap(Some(&no_delta_gap), &rows).is_err());
    assert!(
        d_session
            .named_gaps(&[gap.clone(), no_delta_gap], &rows)
            .is_err()
    );
    assert!(
        serde_json::from_value::<NamedGap>(serde_json::json!({
            "kind": "free_text",
            "identifier": "anything",
            "changes_result": true
        }))
        .is_err()
    );
    d_session.named_gap(Some(&gap), &rows).unwrap();
    assert_eq!(d_session.result().layer, RetrievalLayer::E);
    assert!(
        d_session
            .result()
            .candidates
            .iter()
            .all(|candidate| candidate.instruction_authority == "none")
    );
    assert!(d_session.named_gap(Some(&gap), &rows).is_err());
    let gev = d_session.grounded_view(Vec::new()).unwrap();
    assert_eq!(gev.candidate_set.added_candidate_refs.len(), 1);
    assert!(
        gev.active_evidence
            .iter()
            .all(|statement| statement.instruction_authority == "none")
    );

    assert_eq!(reopened.migration_outcome(), MigrationOutcome::Noop);
    assert_eq!(
        reopened.table_names().await.unwrap(),
        [
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search"
        ]
    );
    let incremental = reopened.project().await.unwrap();
    let full = reopened.full_projection().await.unwrap();
    assert_eq!(incremental, full);
    assert_eq!(
        object_projection_hash(&incremental).unwrap(),
        object_projection_hash(&full).unwrap()
    );
    let incremental_l0002 = derive_l0002_projections(&incremental).unwrap();
    let full_l0002 = derive_l0002_projections(&full).unwrap();
    assert_eq!(
        incremental_l0002.relation_hash().unwrap(),
        full_l0002.relation_hash().unwrap()
    );
    assert_eq!(
        incremental_l0002.search_hash().unwrap(),
        full_l0002.search_hash().unwrap()
    );
    assert_eq!(
        reopened.relation_rows().await.unwrap(),
        incremental_l0002.relations
    );
    assert_eq!(
        reopened.search_rows().await.unwrap(),
        incremental_l0002.search
    );
}

#[test]
fn budget_deadline_exhaustion_is_visible_and_irreversible_in_request_state() {
    let mut budget = RetrievalBudget {
        candidates_remaining: 1,
        tokens_remaining: 1,
        latency_us_remaining: 1,
        hops_remaining: 0,
        follow_ups_remaining: 0,
    };
    assert!(budget.consume_latency(2).is_err());
    assert_eq!(budget.latency_us_remaining, 0);
}

#[test]
fn candidate_boundary_requires_frozen_generation_one_and_one_generation_two_delta() {
    let base = BTreeSet::from(["01890f47-6a4a-7cc1-98b9-01890f476b00".into()]);
    assert!(
        CandidateBoundary {
            generation: 1,
            base_candidate_refs: base.clone(),
            added_candidate_refs: BTreeSet::new(),
            candidate_refs: base.clone(),
        }
        .validate()
        .is_ok()
    );
    assert!(
        CandidateBoundary {
            generation: 2,
            base_candidate_refs: base.clone(),
            added_candidate_refs: BTreeSet::new(),
            candidate_refs: base,
        }
        .validate()
        .is_err()
    );
    let overlap = BTreeSet::from(["01890f47-6a4a-7cc1-98b9-01890f476b00".into()]);
    assert!(
        CandidateBoundary {
            generation: 2,
            base_candidate_refs: overlap.clone(),
            added_candidate_refs: overlap.clone(),
            candidate_refs: overlap,
        }
        .validate()
        .is_err()
    );
}

#[test]
fn relation_slot_gap_is_not_a_free_text_identifier() {
    let gap = NamedGap {
        kind: NamedGapKind::AllowlistedRelationSlot,
        identifier: "ordinary-text".into(),
        changes_result: true,
    };
    assert!(
        gap.validate().is_ok(),
        "syntax is closed but operator evidence decides eligibility"
    );
    let diagnostic = DiagnosticRetrieval::for_characterization();
    let result = evertrace_domain::query::SearchResult {
        layer: RetrievalLayer::D,
        projection_frontier: 1,
        authoritative_frontier: 1,
        candidates: Vec::new(),
        completeness: RetrievalCompleteness::Partial,
        degraded_reasons: BTreeSet::new(),
        omitted_refs: BTreeSet::new(),
        budget: context(
            "ordinary-text",
            &[],
            SuppressionSnapshot::Current {
                generation: 0,
                ref_hashes: BTreeSet::new(),
            },
        )
        .budget,
    };
    assert!(
        diagnostic
            .begin(
                result,
                context(
                    "ordinary-text",
                    &[],
                    SuppressionSnapshot::Current {
                        generation: 0,
                        ref_hashes: BTreeSet::new(),
                    },
                ),
            )
            .is_err()
    );
}
