use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceByteRange,
        EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength, ObservationRole,
        SourceArchiveMode, SourceInstanceId, SourceObservation, SourceReceipt,
        SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole, payload_fingerprint,
        source_observation_id, source_receipt_id,
    },
    ids::{AtomId, CommandId, RepositoryId, TaskId, WorktreeId},
    repository::{
        FilesystemIdentity, GitObjectFormat, GitRegistrationState, PathObservation,
        RepositoryInstance, WorktreeInstance, WorktreeKind, WorktreeLifecycle,
    },
    revision::RevisionId,
    semantic::{
        ApplicabilityExpr, Atom, AtomDraft, AtomKind, AtomProposalPayload, AtomProvenance,
        AtomScope, AtomValue, ConstraintBinding, ConstraintExpr, ConstraintField, ConstraintState,
        ConstraintTruth, ConstraintValue, EpistemicStatus, FutureCueLifecycleExprs,
        ProposalCreatedBy, ProposalEligibility, ProposalOperation, ProposalPayload,
        ProposalTargetId, ProposalTargetKind, SemanticQualifier, TUI_ACCEPTANCE_EVENT_MANIFEST_REF,
        ValidityInterval, tui_acceptance_event_payload,
    },
    work::{Task, TaskIdentityConfidence, TaskLifecycle, TaskScopeMembership},
};
use evertrace_engine::{
    recall::{FutureCueCompiler, RecallTriggerIndex},
    semantic::{
        AtomAcceptanceContext, ProposalCommandContext, ProposalResolution, RevisionProposalService,
        SubmitProposalRequest,
    },
};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload, JournalWriter,
    ObjectFamily, ObjectRow, ObjectRowClass, ObjectRowKind, SemanticCurrentView,
    SourceIngestWatermark,
};
use tempfile::TempDir;

#[derive(Clone)]
struct ScopeFixture {
    repository: RepositoryInstance,
    worktree: WorktreeInstance,
    task: Task,
}

fn scope_fixture(root: &std::path::Path) -> ScopeFixture {
    let repository_id = RepositoryId::new_v7();
    let worktree_id = WorktreeId::new_v7();
    let task_id = TaskId::new_v7();
    let path = root.join("repo").display().to_string();
    let observation = PathObservation {
        path: path.clone(),
        first_observed_at_us: 1,
        last_observed_at_us: 1,
        evidence_refs: vec!["path:s21".into()],
    };
    ScopeFixture {
        repository: RepositoryInstance {
            repository_id,
            repository_revision: 1,
            predecessor_revision: None,
            current_path: path.clone(),
            path_history: vec![observation.clone()],
            git_common_dir_path: Some(format!("{path}/.git")),
            common_dir_filesystem: Some(FilesystemIdentity {
                device: 21,
                inode: 1,
            }),
            object_format: Some(GitObjectFormat::Sha1),
            remote_fingerprints: vec![],
            derived_from: None,
            identity_evidence_refs: vec!["repository:s21".into()],
            recorded_at_us: 1,
        },
        worktree: WorktreeInstance {
            worktree_instance_id: worktree_id,
            worktree_revision: 1,
            predecessor_revision: None,
            repository_instance_id: repository_id,
            kind: WorktreeKind::Main,
            lifecycle: WorktreeLifecycle::Active,
            current_path: Some(path.clone()),
            path_history: vec![observation.clone()],
            git_admin_path_history: vec![PathObservation {
                path: format!("{path}/.git"),
                ..observation
            }],
            git_registration_state: GitRegistrationState::Registered,
            current_snapshot_id: None,
            created_event_ref: "worktree:s21".into(),
            terminal_event_ref: None,
            recreated_from_worktree_instance_id: None,
            recorded_at_us: 1,
        },
        task: Task {
            task_id,
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            request_root_refs: vec!["request:s21".into()],
            canonical_goal: "compile a structured future obligation".into(),
            scope_memberships: vec![TaskScopeMembership {
                repository_instance_id: Some(repository_id),
                worktree_instance_ids: vec![worktree_id],
            }],
            identity_confidence: TaskIdentityConfidence::Explicit,
            lifecycle: TaskLifecycle::Active,
            continuation_of_task_id: None,
            split_from_task_id: None,
            split_into_task_ids: vec![],
            merged_from_task_ids: vec![],
            merged_into_task_id: None,
            created_at_us: 1,
            closed_at_us: None,
            source_watermark: 1,
        },
    }
}

fn user_source(
    label: &str,
    payload: &str,
    scope: &ScopeFixture,
) -> (SourceReceipt, SourceObservation) {
    let instance = SourceInstanceId::parse(format!("source-{label}")).unwrap();
    let revision = SourceRevision::parse("revision-1").unwrap();
    let record = SourceRecordIdentity::parse(format!("record-{label}")).unwrap();
    let observation_id = source_observation_id(&instance, &revision, &record).unwrap();
    let receipt_id = source_receipt_id(&instance, &revision, &record).unwrap();
    let digest =
        evertrace_domain::evidence::hex(&payload_fingerprint(1, payload.as_bytes(), None).unwrap());
    let receipt = SourceReceipt {
        source_receipt_id: receipt_id,
        source_observation_id: observation_id,
        source_instance_id: instance.clone(),
        source_kind: EvidenceSourceKind::CodexSessionJsonl,
        identity_domain: "codex-session-v1".into(),
        source_ref: format!("source-ref-{label}"),
        source_session_ref: format!("session-{label}"),
        source_revision: revision.clone(),
        source_record_identity: record.clone(),
        identity_strength: IdentityStrength::StableNative,
        source_sequence: 1,
        source_sequence_origin: None,
        task_id: Some(scope.task.task_id),
        repository_instance_id: Some(scope.repository.repository_id),
        worktree_instance_id: Some(scope.worktree.worktree_instance_id),
        source_byte_range: None,
        spool_byte_range: EvidenceByteRange { start: 1, end: 2 },
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: Some(1),
        observation_role: ObservationRole::Message,
        unsupported_record_classification: None,
        capture_completeness: CaptureCompleteness::Complete,
        archive_mode: SourceArchiveMode::Exact,
        cas_ref: digest.clone(),
        protected_length: payload.len() as u64,
        original_length: payload.len() as u64,
        protected_secret_digest: None,
        redaction_spans: vec![],
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-s21".into(),
        eligible_event_manifest_ref: "eligible-s21".into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        detector_revision: 1,
        redaction_revision: 1,
        protection_key_generation: 1,
        event_time_us: 1,
        recorded_at_us: 1,
        lifecycle: None,
    };
    let observation = SourceObservation {
        source_observation_id: observation_id,
        source_instance_id: instance,
        source_revision: revision,
        source_record_identity: record,
        observation_role: ObservationRole::Message,
        identity_strength: IdentityStrength::StableNative,
        payload_fingerprint: digest,
        source_receipt_ref: receipt_id,
        source_role: SourceRole::User,
        content_trust: ContentTrust::UserStatement,
        capture_completeness: CaptureCompleteness::Complete,
        adapter_revision: 1,
        parser_revision: 1,
        canonicalization_revision: 1,
        detector_revision: 1,
        redaction_revision: 1,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            pairing_role: ObservationRole::Message,
            field_provenance: vec![],
            adapter_manifest_ref: "adapter-s21".into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: vec![],
    };
    receipt.validate().unwrap();
    observation.validate().unwrap();
    (receipt, observation)
}

fn command(at: i64, payloads: Vec<JournalPayload>) -> JournalCommand {
    JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, [0x21; 32], "s21-v1", payload))
            .collect(),
    )
    .unwrap()
}

fn context(at: i64) -> ProposalCommandContext {
    ProposalCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: [0x21; 32],
        algorithm_revision: "s21-v1".into(),
    }
}

fn draft(observation: &SourceObservation, receipt: &SourceReceipt, task_id: TaskId) -> AtomDraft {
    AtomDraft {
        kind: AtomKind::Constraint,
        epistemic_status: EpistemicStatus::NotApplicable,
        value: AtomValue {
            text: "words intentionally unrelated to delivery".into(),
            subject: "future obligation".into(),
            predicate: "applies".into(),
            object: None,
            qualifiers: vec![SemanticQualifier {
                name: "structured".into(),
                value: "true".into(),
            }],
            critical_revision_refs: vec![],
        },
        scope: AtomScope::Task { task_id },
        applicability_expr: ApplicabilityExpr::Constraint(ConstraintExpr::Eq {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text("deliver".into()),
        }),
        future_cue_lifecycle_exprs: Some(FutureCueLifecycleExprs {
            suppress_expr: ConstraintExpr::Eq {
                field: ConstraintField::VerifierState,
                value: ConstraintValue::Text("blocked".into()),
            },
            resolve_expr: ConstraintExpr::Eq {
                field: ConstraintField::ArtifactKind,
                value: ConstraintValue::Text("release".into()),
            },
        }),
        validity_interval: ValidityInterval {
            valid_from_us: 1,
            valid_until_us: None,
        },
        provenance: vec![AtomProvenance::AgentClaimed],
        source_observation_refs: vec![observation.source_observation_id],
        evidence_refs: vec![receipt.source_receipt_id.to_string()],
        supersedes_revision_refs: vec![],
        supports_revision_refs: vec![],
        contradicts_revision_refs: vec![],
    }
}

fn successor_draft(atom: &Atom) -> AtomDraft {
    AtomDraft {
        kind: atom.kind,
        epistemic_status: atom.epistemic_status,
        value: atom.value.clone(),
        scope: atom.scope.clone(),
        applicability_expr: atom.applicability_expr.clone(),
        future_cue_lifecycle_exprs: atom.future_cue_lifecycle_exprs.clone(),
        validity_interval: atom.validity_interval.clone(),
        provenance: atom.provenance.clone(),
        source_observation_refs: atom.source_observation_refs.clone(),
        evidence_refs: atom.evidence_refs.clone(),
        supersedes_revision_refs: atom.supersedes_revision_refs.clone(),
        supports_revision_refs: atom.supports_revision_refs.clone(),
        contradicts_revision_refs: atom.contradicts_revision_refs.clone(),
    }
}

#[tokio::test]
async fn structured_atom_compiles_and_rebuilds_future_cue_contract() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let (receipt, observation) = user_source("candidate", "opaque candidate text", &scope);
    let mut legacy_draft = draft(&observation, &receipt, scope.task.task_id);
    legacy_draft.future_cue_lifecycle_exprs = None;
    let legacy_json = serde_json::to_value(&legacy_draft).unwrap();
    assert!(legacy_json.get("future_cue_lifecycle_exprs").is_none());
    let decoded_legacy: AtomDraft = serde_json::from_value(legacy_json).unwrap();
    assert_eq!(decoded_legacy.future_cue_lifecycle_exprs, None);
    assert_eq!(
        decoded_legacy.semantic_digest().unwrap(),
        legacy_draft.semantic_digest().unwrap()
    );
    let mut unauthorized_descriptive = draft(&observation, &receipt, scope.task.task_id);
    unauthorized_descriptive.kind = AtomKind::Fact;
    unauthorized_descriptive.epistemic_status = EpistemicStatus::Unverified;
    unauthorized_descriptive.applicability_expr = ApplicabilityExpr::Always;
    assert!(unauthorized_descriptive.validate_unprivileged().is_err());
    let store_root = temp.path().join("store");
    let mut writer = JournalWriter::open(&store_root).await.unwrap();
    writer
        .commit(
            &command(
                1,
                vec![
                    JournalPayload::SourceReceiptRecorded(Box::new(receipt.clone())),
                    JournalPayload::SourceObservationRecorded(Box::new(observation.clone())),
                    JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
                        source_instance_id: receipt.source_instance_id.clone(),
                        source_revision: receipt.source_revision.clone(),
                        source_sequence: 1,
                        confirmed_prefix_digest: None,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::EvidenceSurface,
                        target_id: observation.source_observation_id.to_string(),
                        algorithm_revision: "s21-v1".into(),
                        source_watermark: 1,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::PhysicalNormalization,
                        target_id: observation.source_observation_id.to_string(),
                        algorithm_revision: "s21-v1".into(),
                        source_watermark: 1,
                    }),
                    JournalPayload::RepositoryInstanceRecorded(Box::new(scope.repository.clone())),
                    JournalPayload::WorktreeInstanceRecorded(Box::new(scope.worktree.clone())),
                    JournalPayload::TaskRecorded(Box::new(scope.task.clone())),
                ],
            ),
            1,
        )
        .await
        .unwrap();

    let service = RevisionProposalService;
    let request = SubmitProposalRequest {
        target_kind: ProposalTargetKind::Atom,
        target_id: None,
        base_revision_id: None,
        operation: ProposalOperation::Create,
        payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
            draft: draft(&observation, &receipt, scope.task.task_id),
        })),
        evidence_refs: vec![receipt.source_receipt_id.to_string()],
        source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::Agent,
    };
    let view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: proposal,
        command: submit,
    } = service.submit(&view, context(2), request).unwrap()
    else {
        panic!("proposal must persist")
    };
    writer.commit(&submit, 2).await.unwrap();
    let acceptance_payload = tui_acceptance_event_payload(
        proposal.proposal_id,
        proposal.proposal_revision_id,
        &proposal.fingerprint,
    );
    let (mut acceptance_receipt, acceptance_observation) =
        user_source("acceptance", &acceptance_payload, &scope);
    acceptance_receipt.eligible_event_manifest_ref = TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into();
    acceptance_receipt.event_time_us = 0;
    acceptance_receipt.recorded_at_us = 3;
    writer
        .commit(
            &command(
                3,
                vec![
                    JournalPayload::SourceReceiptRecorded(Box::new(acceptance_receipt.clone())),
                    JournalPayload::SourceObservationRecorded(Box::new(
                        acceptance_observation.clone(),
                    )),
                    JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
                        source_instance_id: acceptance_receipt.source_instance_id.clone(),
                        source_revision: acceptance_receipt.source_revision.clone(),
                        source_sequence: 1,
                        confirmed_prefix_digest: None,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::EvidenceSurface,
                        target_id: acceptance_observation.source_observation_id.to_string(),
                        algorithm_revision: "s21-v1".into(),
                        source_watermark: 1,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::PhysicalNormalization,
                        target_id: acceptance_observation.source_observation_id.to_string(),
                        algorithm_revision: "s21-v1".into(),
                        source_watermark: 1,
                    }),
                ],
            ),
            3,
        )
        .await
        .unwrap();
    let submitted = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let accepted = service
        .accept(
            &submitted,
            context(4),
            proposal.proposal_id,
            AtomAcceptanceContext::TaskTui {
                observation: Box::new(acceptance_observation),
                receipt: Box::new(acceptance_receipt),
            },
        )
        .unwrap();
    writer.commit(&accepted.command, 4).await.unwrap();

    let mut legacy_atom = (*accepted.atom).clone();
    legacy_atom.future_cue_lifecycle_exprs = None;
    let legacy_atom_json = serde_json::to_value(&legacy_atom).unwrap();
    assert!(legacy_atom_json.get("future_cue_lifecycle_exprs").is_none());
    let decoded_legacy_atom: Atom = serde_json::from_value(legacy_atom_json).unwrap();
    assert_eq!(decoded_legacy_atom.future_cue_lifecycle_exprs, None);
    decoded_legacy_atom.validate().unwrap();

    let snapshot = writer.project().await.unwrap();
    let report = FutureCueCompiler::compile(&snapshot).unwrap();
    assert_eq!(report.contracts.len(), 1);
    assert!(report.diagnostics.is_empty());
    let contract = &report.contracts[0];
    let state = ConstraintState {
        bindings: vec![
            ConstraintBinding {
                field: ConstraintField::ArtifactKind,
                value: ConstraintValue::Text("release".into()),
            },
            ConstraintBinding {
                field: ConstraintField::VerifierState,
                value: ConstraintValue::Text("blocked".into()),
            },
            ConstraintBinding {
                field: ConstraintField::Phase,
                value: ConstraintValue::Text("deliver".into()),
            },
        ],
    };
    state.validate().unwrap();
    assert_eq!(contract.evaluate_match(&state, None), ConstraintTruth::True);
    assert_eq!(
        contract.evaluate_suppress(&state, None),
        ConstraintTruth::True
    );
    assert_eq!(
        contract.evaluate_resolve(&state, None),
        ConstraintTruth::True
    );
    let match_only = ConstraintState {
        bindings: vec![ConstraintBinding {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text("deliver".into()),
        }],
    };
    assert_eq!(
        contract.evaluate_match(&match_only, None),
        ConstraintTruth::True
    );
    assert_eq!(
        contract.evaluate_suppress(&match_only, None),
        ConstraintTruth::Unknown
    );
    assert_eq!(
        contract.evaluate_resolve(&match_only, None),
        ConstraintTruth::Unknown
    );
    let suppress_only = ConstraintState {
        bindings: vec![ConstraintBinding {
            field: ConstraintField::VerifierState,
            value: ConstraintValue::Text("blocked".into()),
        }],
    };
    assert_eq!(
        contract.evaluate_suppress(&suppress_only, None),
        ConstraintTruth::True
    );
    assert_eq!(
        contract.evaluate_match(&suppress_only, None),
        ConstraintTruth::Unknown
    );
    let resolve_only = ConstraintState {
        bindings: vec![ConstraintBinding {
            field: ConstraintField::ArtifactKind,
            value: ConstraintValue::Text("release".into()),
        }],
    };
    assert_eq!(
        contract.evaluate_resolve(&resolve_only, None),
        ConstraintTruth::True
    );
    assert_eq!(
        contract.evaluate_match(&resolve_only, None),
        ConstraintTruth::Unknown
    );
    let mut descriptive = (*accepted.atom).clone();
    descriptive.atom_id = AtomId::new_v7();
    descriptive.revision_id = RevisionId::new_v7();
    descriptive.kind = AtomKind::Fact;
    descriptive.epistemic_status = EpistemicStatus::Unverified;
    descriptive.applicability_expr = ApplicabilityExpr::Always;
    assert!(descriptive.validate().is_err());
    descriptive.future_cue_lifecycle_exprs = None;
    descriptive.validate().unwrap();
    let descriptive_payload = JournalPayload::AtomRecorded(Box::new(descriptive.clone()));
    let mut noisy = snapshot.clone();
    noisy.rows.push(ObjectRow {
        row_id: format!("object:atom:atom_revision:{}", descriptive.revision_id),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Object),
        object_family: Some(ObjectFamily::Atom),
        object_kind: Some("atom_revision".into()),
        object_id: Some(descriptive.atom_id.to_string()),
        current_revision_id: Some(descriptive.revision_id.to_string()),
        lifecycle: Some(descriptive.lifecycle_status.as_str().into()),
        epistemic: Some(descriptive.epistemic_status.as_str().into()),
        authority: Some(descriptive.authority.as_str().into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: None,
        worktree_id: None,
        task_id: Some(scope.task.task_id.to_string()),
        workstream_id: None,
        session_id: None,
        payload_json: Some(descriptive_payload.canonical_json().unwrap()),
        source_event_seq: snapshot.frontier,
        projection_generation: 1,
    });
    let noisy_report = FutureCueCompiler::compile(&noisy).unwrap();
    assert_eq!(noisy_report.contracts, report.contracts);
    assert_eq!(noisy_report.diagnostics, report.diagnostics);
    let index = RecallTriggerIndex::from_snapshot(&snapshot).unwrap();
    assert_eq!(index.entries.len(), 1);
    assert_eq!(index.entries[0].contract, report.contracts[0]);
    let rebuilt = writer.full_projection().await.unwrap();
    assert_eq!(snapshot, rebuilt);
    assert_eq!(index, RecallTriggerIndex::from_snapshot(&rebuilt).unwrap());
    assert!(
        writer
            .relation_rows()
            .await
            .unwrap()
            .iter()
            .all(|row| { row.relation_kind.as_deref() != Some("recall_trigger_index") })
    );
    assert!(
        writer
            .search_rows()
            .await
            .unwrap()
            .iter()
            .all(|row| { row.object_kind.as_deref() != Some("recall_trigger_index") })
    );

    assert_eq!(
        writer.table_names().await.unwrap(),
        vec![
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search"
        ]
    );
    let object_rows = writer.object_rows().await.unwrap();
    let relation_rows = writer.relation_rows().await.unwrap();
    let search_rows = writer.search_rows().await.unwrap();
    assert_eq!(writer.project().await.unwrap(), snapshot);
    assert_eq!(writer.object_rows().await.unwrap(), object_rows);
    assert_eq!(writer.relation_rows().await.unwrap(), relation_rows);
    assert_eq!(writer.search_rows().await.unwrap(), search_rows);
    drop(writer);
    let mut reopened = JournalWriter::open(&store_root).await.unwrap();
    assert_eq!(snapshot, reopened.project().await.unwrap());
    assert_eq!(RecallTriggerIndex::from_snapshot(&snapshot).unwrap(), index);

    let current = SemanticCurrentView::from_snapshot(&snapshot).unwrap();
    let mut rescheduled_draft = successor_draft(&accepted.atom);
    rescheduled_draft.applicability_expr = ApplicabilityExpr::Constraint(ConstraintExpr::Eq {
        field: ConstraintField::Phase,
        value: ConstraintValue::Text("publish".into()),
    });
    rescheduled_draft.future_cue_lifecycle_exprs = Some(FutureCueLifecycleExprs {
        suppress_expr: ConstraintExpr::Eq {
            field: ConstraintField::VerifierState,
            value: ConstraintValue::Text("paused".into()),
        },
        resolve_expr: ConstraintExpr::Eq {
            field: ConstraintField::ArtifactKind,
            value: ConstraintValue::Text("published_release".into()),
        },
    });
    let reschedule_request = SubmitProposalRequest {
        target_kind: ProposalTargetKind::Atom,
        target_id: Some(ProposalTargetId::Atom(accepted.atom.atom_id)),
        base_revision_id: Some(accepted.atom.revision_id),
        operation: ProposalOperation::Replace,
        payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Replace {
            draft: rescheduled_draft,
        })),
        evidence_refs: vec![receipt.source_receipt_id.to_string()],
        source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::Agent,
    };
    let ProposalResolution::Revision {
        value: reschedule,
        command: submit_reschedule,
    } = service
        .submit(&current, context(5), reschedule_request)
        .unwrap()
    else {
        panic!("reschedule must enter review")
    };
    reopened.commit(&submit_reschedule, 5).await.unwrap();
    let reschedule_payload = tui_acceptance_event_payload(
        reschedule.proposal_id,
        reschedule.proposal_revision_id,
        &reschedule.fingerprint,
    );
    let (mut reschedule_receipt, reschedule_observation) =
        user_source("reschedule", &reschedule_payload, &scope);
    reschedule_receipt.eligible_event_manifest_ref = TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into();
    reschedule_receipt.event_time_us = 0;
    reschedule_receipt.recorded_at_us = 6;
    reopened
        .commit(
            &command(
                6,
                vec![
                    JournalPayload::SourceReceiptRecorded(Box::new(reschedule_receipt.clone())),
                    JournalPayload::SourceObservationRecorded(Box::new(
                        reschedule_observation.clone(),
                    )),
                    JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
                        source_instance_id: reschedule_receipt.source_instance_id.clone(),
                        source_revision: reschedule_receipt.source_revision.clone(),
                        source_sequence: 1,
                        confirmed_prefix_digest: None,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::EvidenceSurface,
                        target_id: reschedule_observation.source_observation_id.to_string(),
                        algorithm_revision: "s21-v1".into(),
                        source_watermark: 1,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::PhysicalNormalization,
                        target_id: reschedule_observation.source_observation_id.to_string(),
                        algorithm_revision: "s21-v1".into(),
                        source_watermark: 1,
                    }),
                ],
            ),
            6,
        )
        .await
        .unwrap();
    let reschedule_view =
        SemanticCurrentView::from_snapshot(&reopened.project().await.unwrap()).unwrap();
    let accepted_reschedule = service
        .accept(
            &reschedule_view,
            context(7),
            reschedule.proposal_id,
            AtomAcceptanceContext::TaskTui {
                observation: Box::new(reschedule_observation),
                receipt: Box::new(reschedule_receipt),
            },
        )
        .unwrap();
    reopened
        .commit(&accepted_reschedule.command, 7)
        .await
        .unwrap();
    let rescheduled = reopened.project().await.unwrap();
    let rescheduled_index = RecallTriggerIndex::from_snapshot(&rescheduled).unwrap();
    assert_eq!(rescheduled_index.entries.len(), 1);
    assert_eq!(
        rescheduled_index.entries[0].contract.source_revision_id,
        accepted_reschedule.atom.revision_id
    );
    assert_ne!(
        rescheduled_index.entries[0].contract.future_cue_contract_id,
        index.entries[0].contract.future_cue_contract_id
    );

    let current = SemanticCurrentView::from_snapshot(&rescheduled).unwrap();
    let deprecate_request = SubmitProposalRequest {
        target_kind: ProposalTargetKind::Atom,
        target_id: Some(ProposalTargetId::Atom(accepted_reschedule.atom.atom_id)),
        base_revision_id: Some(accepted_reschedule.atom.revision_id),
        operation: ProposalOperation::Deprecate,
        payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Deprecate {
            reason: "obligation resolved".into(),
        })),
        evidence_refs: vec![receipt.source_receipt_id.to_string()],
        source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::Agent,
    };
    let ProposalResolution::Revision {
        value: deprecation,
        command: submit_deprecation,
    } = service
        .submit(&current, context(8), deprecate_request)
        .unwrap()
    else {
        panic!("deprecation must enter review")
    };
    reopened.commit(&submit_deprecation, 5).await.unwrap();
    let deprecation_payload = tui_acceptance_event_payload(
        deprecation.proposal_id,
        deprecation.proposal_revision_id,
        &deprecation.fingerprint,
    );
    let (mut deprecation_receipt, deprecation_observation) =
        user_source("deprecation", &deprecation_payload, &scope);
    deprecation_receipt.eligible_event_manifest_ref = TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into();
    deprecation_receipt.event_time_us = 0;
    deprecation_receipt.recorded_at_us = 9;
    reopened
        .commit(
            &command(
                9,
                vec![
                    JournalPayload::SourceReceiptRecorded(Box::new(deprecation_receipt.clone())),
                    JournalPayload::SourceObservationRecorded(Box::new(
                        deprecation_observation.clone(),
                    )),
                    JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
                        source_instance_id: deprecation_receipt.source_instance_id.clone(),
                        source_revision: deprecation_receipt.source_revision.clone(),
                        source_sequence: 1,
                        confirmed_prefix_digest: None,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::EvidenceSurface,
                        target_id: deprecation_observation.source_observation_id.to_string(),
                        algorithm_revision: "s21-v1".into(),
                        source_watermark: 1,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::PhysicalNormalization,
                        target_id: deprecation_observation.source_observation_id.to_string(),
                        algorithm_revision: "s21-v1".into(),
                        source_watermark: 1,
                    }),
                ],
            ),
            9,
        )
        .await
        .unwrap();
    let deprecation_view =
        SemanticCurrentView::from_snapshot(&reopened.project().await.unwrap()).unwrap();
    let accepted_deprecation = service
        .accept(
            &deprecation_view,
            context(10),
            deprecation.proposal_id,
            AtomAcceptanceContext::TaskTui {
                observation: Box::new(deprecation_observation),
                receipt: Box::new(deprecation_receipt),
            },
        )
        .unwrap();
    reopened
        .commit(&accepted_deprecation.command, 10)
        .await
        .unwrap();
    let inactive = reopened.project().await.unwrap();
    assert!(
        RecallTriggerIndex::from_snapshot(&inactive)
            .unwrap()
            .entries
            .is_empty()
    );
    assert_eq!(inactive, reopened.full_projection().await.unwrap());
}
