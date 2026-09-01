use std::path::Path;

use evertrace_capture::{
    DeviceKeyStore, RUNTIME_SNAPSHOT_VERSION, RecallCueGateMode, RecoveryGateMode, RuntimeSnapshot,
    SpoolLimits,
};
use evertrace_domain::{
    config::{GlobalPromotionConfig, PromotionLevel},
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, CorrelationStrength,
        EvidenceByteRange, EvidenceSourceKind, EvidenceSurface, HostCorrelationEvidence,
        HostOccurrence, IdentityStrength, InstructionAuthority, NormalizationState,
        ObservationRole, PairingState, SourceArchiveMode, SourceInstanceId, SourceObservation,
        SourceReceipt, SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole,
        evidence_span_hash, host_occurrence_id_for_nonexact, payload_fingerprint,
        source_observation_id, source_receipt_id,
    },
    ids::{CommandId, CoreMembershipId, RepositoryId, RequestId, RevisionProposalId},
    procedure::{
        ProcedureActions, ProcedureDone, ProcedureDraft, ProcedureKind, ProcedureScope,
        ProcedureWhen,
    },
    purge::{ObjectDeletionGuards, ObjectDeletionPhase, ObjectDeletionTarget},
    repository::{FilesystemIdentity, GitObjectFormat, PathObservation, RepositoryInstance},
    semantic::{
        AcceptedProposalTarget, ApplicabilityExpr, AtomDraft, AtomKind, AtomProposalPayload,
        AtomProvenance, AtomScope, AtomValue, ConstraintExpr, ConstraintField, ConstraintValue,
        CoreMembershipProposalPayload, CoreScopeIdentity, EpistemicStatus,
        ProcedureProposalPayload, ProposalCreatedBy, ProposalEligibility, ProposalOperation,
        ProposalPayload, ProposalTargetKind, SemanticQualifier, ValidityInterval,
    },
};
use evertrace_engine::{
    HumanActionOutcome, HumanGovernanceService, HumanProposalDecision, open_writer,
    semantic::{
        ProposalCommandContext, ProposalResolution, RevisionProposalService, SubmitProposalRequest,
    },
    spawn_writer,
};
use evertrace_store::{
    DefaultRetrievalSuppressionGeneration, JournalCommand, JournalEventDraft, JournalPayload,
    NormalizationWatermark, ObjectDeletionCurrentView, ProjectionSnapshot, SemanticCurrentView,
    SourceIngestWatermark, default_retrieval_suppression_ref_hash, object_deletion_preview,
};
use tempfile::TempDir;

const CONFIG: [u8; 32] = [32; 32];

fn proposal_visible(snapshot: &ProjectionSnapshot, proposal_id: RevisionProposalId) -> bool {
    snapshot.data_rows().any(|row| {
        row.payload_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<JournalPayload>(json).ok())
            .is_some_and(|payload| {
                matches!(
                    payload,
                    JournalPayload::RevisionProposalRecorded(value)
                        if value.proposal_id == proposal_id
                )
            })
    })
}

fn runtime_snapshot(root: &Path) -> RuntimeSnapshot {
    let limits = SpoolLimits {
        high_watermark_bytes: 2 * 1024 * 1024,
        low_watermark_bytes: 64 * 1024,
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
        effective_config_hash: CONFIG,
        recovery_adapter_manifest_id: None,
        recovery_classifier_revision: 1,
        recovery_max_bundle_bytes: 4 << 20,
        recovery_max_untracked_file_bytes: 1 << 20,
        recovery_max_untracked_total_bytes: 2 << 20,
        recall_cue_gate: RecallCueGateMode::Disabled,
        recall_cue_adapter_manifest_id: None,
        recall_cues: Vec::new(),
    }
}

fn source(
    label: &str,
    repository_id: RepositoryId,
) -> (SourceReceipt, SourceObservation, EvidenceSurface) {
    let instance = SourceInstanceId::parse(format!("source-{label}")).unwrap();
    let revision = SourceRevision::parse("revision-1").unwrap();
    let stable_record = if label == "rewritten" {
        "exclusive"
    } else {
        label
    };
    let record = SourceRecordIdentity::parse(format!("record-{stable_record}")).unwrap();
    let observation_id = source_observation_id(&instance, &revision, &record).unwrap();
    let receipt_id = source_receipt_id(&instance, &revision, &record).unwrap();
    let text = "reviewed evidence";
    let fingerprint =
        evertrace_domain::evidence::hex(&payload_fingerprint(1, text.as_bytes(), None).unwrap());
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
        task_id: None,
        repository_instance_id: Some(repository_id),
        worktree_instance_id: None,
        source_byte_range: None,
        spool_byte_range: EvidenceByteRange { start: 1, end: 2 },
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: Some(1),
        observation_role: ObservationRole::Message,
        unsupported_record_classification: None,
        capture_completeness: CaptureCompleteness::Complete,
        archive_mode: SourceArchiveMode::Exact,
        cas_ref: fingerprint.clone(),
        protected_length: text.len() as u64,
        original_length: text.len() as u64,
        protected_secret_digest: None,
        redaction_spans: Vec::new(),
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-s32".into(),
        eligible_event_manifest_ref: "eligible-s32".into(),
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
        payload_fingerprint: fingerprint,
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
            field_provenance: Vec::new(),
            adapter_manifest_ref: "adapter-s32".into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: Vec::new(),
    };
    let surface = EvidenceSurface {
        source_observation_revision_ref: observation_id,
        source_role: SourceRole::User,
        content_trust: ContentTrust::UserStatement,
        instruction_authority: InstructionAuthority::None,
        task_id: None,
        repository_instance_id: Some(repository_id),
        worktree_instance_id: None,
        event_time_us: 1,
        recorded_at_us: 1,
        source_sequence: 1,
        capture_completeness: CaptureCompleteness::Complete,
        canonicalization_version: 1,
        span_hash: evertrace_domain::evidence::hex(
            &evidence_span_hash(observation_id, 1, text).unwrap(),
        ),
        projection_generation: 1,
        protected_text: text.into(),
    };
    receipt.validate().unwrap();
    observation.validate().unwrap();
    surface.validate().unwrap();
    (receipt, observation, surface)
}

fn context(at: i64) -> ProposalCommandContext {
    ProposalCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: "s32-test-v1".into(),
    }
}

fn atom_draft(
    receipt: &SourceReceipt,
    observation: &SourceObservation,
    repository_id: RepositoryId,
) -> AtomDraft {
    AtomDraft {
        kind: AtomKind::Constraint,
        epistemic_status: EpistemicStatus::NotApplicable,
        value: AtomValue {
            text: "retain an independently reviewed constraint".into(),
            subject: "constraint".into(),
            predicate: "retain".into(),
            object: Some("reviewed".into()),
            qualifiers: vec![SemanticQualifier {
                name: "scope".into(),
                value: "global".into(),
            }],
            critical_revision_refs: Vec::new(),
        },
        scope: AtomScope::Repository {
            repository_instance_id: repository_id,
        },
        applicability_expr: ApplicabilityExpr::Always,
        future_cue_lifecycle_exprs: None,
        validity_interval: ValidityInterval {
            valid_from_us: 1,
            valid_until_us: None,
        },
        provenance: vec![AtomProvenance::AgentClaimed],
        source_observation_refs: vec![observation.source_observation_id],
        evidence_refs: vec![receipt.source_receipt_id.to_string()],
        supersedes_revision_refs: Vec::new(),
        supports_revision_refs: Vec::new(),
        contradicts_revision_refs: Vec::new(),
    }
}

fn procedure_draft(
    evidence: String,
    repository_id: RepositoryId,
    support_revision_refs: Vec<evertrace_domain::revision::RevisionId>,
) -> ProcedureDraft {
    ProcedureDraft {
        scope: ProcedureScope::Repository { repository_id },
        title: "Verify reviewed evidence".into(),
        summary: "Use the objective verifier before publishing".into(),
        kind: ProcedureKind::Diagnostic,
        when: ProcedureWhen {
            goals: vec!["release".into()],
            targets: vec!["artifact".into()],
            signals: vec!["verification requested".into()],
            stage: "verify".into(),
            requires: vec!["objective verifier".into()],
            excludes: vec!["already verified".into()],
        },
        condition_ir_version: 1,
        applicability_expr: ConstraintExpr::Eq {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text("verify".into()),
        },
        avoid_expr: ConstraintExpr::Eq {
            field: ConstraintField::VerifierState,
            value: ConstraintValue::Text("passed".into()),
        },
        completion_expr: ConstraintExpr::Eq {
            field: ConstraintField::ArtifactKind,
            value: ConstraintValue::Text("release".into()),
        },
        actions: ProcedureActions {
            stages: vec!["run the verifier".into()],
            branches: Vec::new(),
            avoid: vec!["do not publish early".into()],
        },
        done: ProcedureDone {
            success: vec!["verifier passes".into()],
            abort: vec!["stop on mismatch".into()],
            verify: vec!["record verifier result".into()],
        },
        pitfalls: vec!["stale artifacts".into()],
        evidence_refs: vec![evidence],
        support_revision_refs,
    }
}

fn submit(
    service: &RevisionProposalService,
    view: &SemanticCurrentView,
    at: i64,
    target_kind: ProposalTargetKind,
    payload: ProposalPayload,
    evidence: String,
) -> (
    Box<evertrace_domain::semantic::RevisionProposal>,
    JournalCommand,
) {
    let ProposalResolution::Revision { value, command } = service
        .submit(
            view,
            context(at),
            SubmitProposalRequest {
                target_kind,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload,
                evidence_refs: vec![evidence.clone()],
                source_cohort_refs: vec![evidence],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("new proposal expected")
    };
    (value, command)
}

#[tokio::test]
async fn object_forget_closes_three_targets_and_replays_without_resurrection() {
    let root = TempDir::new().unwrap();
    let runtime = runtime_snapshot(root.path());
    DeviceKeyStore::new(runtime.device_key_dir.clone())
        .load_or_create()
        .unwrap();
    drop(evertrace_capture::CaptureRuntime::open(runtime.clone()).unwrap());
    let store = root.path().join("store");
    let writer = open_writer(&store).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let repository_id = RepositoryId::new_v7();
    let repository_path = root.path().join("repo").display().to_string();
    let repository = RepositoryInstance {
        repository_id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: repository_path.clone(),
        path_history: vec![PathObservation {
            path: repository_path.clone(),
            first_observed_at_us: 1,
            last_observed_at_us: 1,
            evidence_refs: vec!["path:s32".into()],
        }],
        git_common_dir_path: Some(format!("{repository_path}/.git")),
        common_dir_filesystem: Some(FilesystemIdentity {
            device: 32,
            inode: 1,
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: Vec::new(),
        derived_from: None,
        identity_evidence_refs: vec!["repository:s32".into()],
        recorded_at_us: 1,
    };
    let (receipt, observation, surface) = source("shared", repository_id);
    let (host_shared_receipt, host_shared_observation, host_shared_surface) =
        source("host-shared", repository_id);
    let (exclusive_receipt, exclusive_observation, exclusive_surface) =
        source("exclusive", repository_id);
    let host_occurrence = HostOccurrence {
        host_occurrence_id: host_occurrence_id_for_nonexact(
            host_shared_observation.source_observation_id,
            CorrelationStrength::Unavailable,
        )
        .unwrap(),
        exact_key: None,
        host_instance_id: None,
        host_trace_lineage_id: None,
        host_lane_key: None,
        canonical_event_family: None,
        native_request_id: None,
        physical_execution_ordinal: None,
        correlation_strength: CorrelationStrength::Unavailable,
        source_observation_refs: vec![host_shared_observation.source_observation_id],
        field_provenance: Vec::new(),
        normalization_state: NormalizationState::SingleSource,
        pairing_state: PairingState::NotApplicable,
        possible_duplicate_group_id: None,
        correlation_resolver_version: 1,
        normalization_revision: 1,
        previous_normalization_revision: None,
    };
    host_occurrence.validate().unwrap();
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![
                    JournalPayload::SourceReceiptRecorded(Box::new(exclusive_receipt.clone())),
                    JournalPayload::SourceObservationRecorded(Box::new(
                        exclusive_observation.clone(),
                    )),
                    JournalPayload::EvidenceSurfaceRecorded(Box::new(exclusive_surface.clone())),
                    JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
                        source_instance_id: exclusive_receipt.source_instance_id.clone(),
                        source_revision: exclusive_receipt.source_revision.clone(),
                        source_sequence: 1,
                        confirmed_prefix_digest: None,
                    }),
                    JournalPayload::DirtyTarget(evertrace_store::DirtyTarget {
                        target_kind: evertrace_store::DirtyTargetKind::EvidenceSurface,
                        target_id: exclusive_observation.source_observation_id.to_string(),
                        algorithm_revision: "s32-test-v1".into(),
                        source_watermark: 1,
                    }),
                    JournalPayload::DirtyTarget(evertrace_store::DirtyTarget {
                        target_kind: evertrace_store::DirtyTargetKind::PhysicalNormalization,
                        target_id: exclusive_observation.source_observation_id.to_string(),
                        algorithm_revision: "s32-test-v1".into(),
                        source_watermark: 1,
                    }),
                ]
                .into_iter()
                .map(|payload| JournalEventDraft::runtime(1, CONFIG, "s32-test-v1", payload))
                .collect(),
            )
            .unwrap(),
            1,
        )
        .await
        .unwrap();
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![
                    JournalPayload::SourceReceiptRecorded(Box::new(host_shared_receipt.clone())),
                    JournalPayload::SourceObservationRecorded(Box::new(
                        host_shared_observation.clone(),
                    )),
                    JournalPayload::EvidenceSurfaceRecorded(Box::new(host_shared_surface.clone())),
                    JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
                        source_instance_id: host_shared_receipt.source_instance_id.clone(),
                        source_revision: host_shared_receipt.source_revision.clone(),
                        source_sequence: 1,
                        confirmed_prefix_digest: None,
                    }),
                    JournalPayload::DirtyTarget(evertrace_store::DirtyTarget {
                        target_kind: evertrace_store::DirtyTargetKind::EvidenceSurface,
                        target_id: host_shared_observation.source_observation_id.to_string(),
                        algorithm_revision: "s32-test-v1".into(),
                        source_watermark: 1,
                    }),
                    JournalPayload::HostOccurrenceNormalized(Box::new(host_occurrence.clone())),
                    JournalPayload::NormalizationWatermark(NormalizationWatermark {
                        source_observation_id: host_shared_observation.source_observation_id,
                        resolver_version: 1,
                    }),
                    JournalPayload::DirtyTarget(evertrace_store::DirtyTarget {
                        target_kind: evertrace_store::DirtyTargetKind::PhysicalNormalization,
                        target_id: host_shared_observation.source_observation_id.to_string(),
                        algorithm_revision: "s32-test-v1".into(),
                        source_watermark: 1,
                    }),
                ]
                .into_iter()
                .map(|payload| JournalEventDraft::runtime(1, CONFIG, "s32-test-v1", payload))
                .collect(),
            )
            .unwrap(),
            1,
        )
        .await
        .unwrap();
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![
                    JournalPayload::SourceReceiptRecorded(Box::new(receipt.clone())),
                    JournalPayload::SourceObservationRecorded(Box::new(observation.clone())),
                    JournalPayload::EvidenceSurfaceRecorded(Box::new(surface.clone())),
                    JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
                        source_instance_id: receipt.source_instance_id.clone(),
                        source_revision: receipt.source_revision.clone(),
                        source_sequence: 1,
                        confirmed_prefix_digest: None,
                    }),
                    JournalPayload::DirtyTarget(evertrace_store::DirtyTarget {
                        target_kind: evertrace_store::DirtyTargetKind::EvidenceSurface,
                        target_id: observation.source_observation_id.to_string(),
                        algorithm_revision: "s32-test-v1".into(),
                        source_watermark: 1,
                    }),
                    JournalPayload::RepositoryInstanceRecorded(Box::new(repository)),
                    JournalPayload::DirtyTarget(evertrace_store::DirtyTarget {
                        target_kind: evertrace_store::DirtyTargetKind::PhysicalNormalization,
                        target_id: observation.source_observation_id.to_string(),
                        algorithm_revision: "s32-test-v1".into(),
                        source_watermark: 1,
                    }),
                ]
                .into_iter()
                .map(|payload| JournalEventDraft::runtime(1, CONFIG, "s32-test-v1", payload))
                .collect(),
            )
            .unwrap(),
            1,
        )
        .await
        .unwrap();
    let proposals = RevisionProposalService;
    let service = HumanGovernanceService::with_acceptance(
        handle.clone(),
        CONFIG,
        runtime.clone(),
        GlobalPromotionConfig {
            atom: PromotionLevel::Manual,
            procedure: PromotionLevel::Manual,
            core_membership: PromotionLevel::Manual,
        },
    );
    let (atom_proposal, atom_submit) = submit(
        &proposals,
        &SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap(),
        2,
        ProposalTargetKind::Atom,
        ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
            draft: atom_draft(&receipt, &observation, repository_id),
        })),
        receipt.source_receipt_id.to_string(),
    );
    handle.commit(atom_submit, 2).await.unwrap();
    let atom_frontier = handle.project().await.unwrap().frontier;
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                atom_frontier,
                atom_proposal.proposal_id,
                atom_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&atom_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        HumanActionOutcome::Applied { .. }
    ));
    let atom = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap())
        .unwrap()
        .atoms
        .into_values()
        .find(|atom| atom.accepted_proposal_id == Some(atom_proposal.proposal_id))
        .unwrap();

    let mut target_draft = atom_draft(
        &host_shared_receipt,
        &host_shared_observation,
        repository_id,
    );
    target_draft.scope = AtomScope::Global;
    target_draft.source_observation_refs = vec![
        host_shared_observation.source_observation_id,
        exclusive_observation.source_observation_id,
    ];
    target_draft.source_observation_refs.sort();
    target_draft.evidence_refs = vec![
        host_shared_receipt.source_receipt_id.to_string(),
        exclusive_receipt.source_receipt_id.to_string(),
    ];
    target_draft.evidence_refs.sort();
    target_draft.supports_revision_refs = vec![atom.revision_id];
    let (target_proposal, target_submit) = submit(
        &proposals,
        &SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap(),
        3,
        ProposalTargetKind::Atom,
        ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
            draft: target_draft,
        })),
        exclusive_receipt.source_receipt_id.to_string(),
    );
    handle.commit(target_submit, 3).await.unwrap();
    let target_frontier = handle.project().await.unwrap().frontier;
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                target_frontier,
                target_proposal.proposal_id,
                target_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&target_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        HumanActionOutcome::Applied { .. }
    ));
    let target_atom = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap())
        .unwrap()
        .atoms
        .into_values()
        .find(|value| value.accepted_proposal_id == Some(target_proposal.proposal_id))
        .unwrap();
    let canonical_payload =
        evertrace_domain::evidence::hex(&target_atom.semantic_structure_hash().unwrap());
    let mut rebuilt = target_atom.clone();
    rebuilt.atom_id = evertrace_domain::ids::AtomId::new_v7();
    rebuilt.revision_id = evertrace_domain::revision::RevisionId::new_v7();
    rebuilt.parent_revision_id = Some(evertrace_domain::revision::RevisionId::new_v7());
    rebuilt.accepted_proposal_id = Some(evertrace_domain::ids::RevisionProposalId::new_v7());
    rebuilt.accepted_proposal_revision_id = Some(evertrace_domain::revision::RevisionId::new_v7());
    rebuilt.created_at_us += 1_000;
    let rebuilt_payload =
        evertrace_domain::evidence::hex(&rebuilt.semantic_structure_hash().unwrap());
    assert_eq!(canonical_payload, rebuilt_payload);
    let mut changed = rebuilt;
    changed.value.text.push_str(" changed");
    let changed_payload =
        evertrace_domain::evidence::hex(&changed.semantic_structure_hash().unwrap());
    let guard = |payload: String| {
        ObjectDeletionGuards::derive(
            ObjectDeletionTarget::Atom {
                atom_id: target_atom.atom_id,
            },
            "constraint",
            &[payload],
            "global",
            &["source-revision".into()],
        )
        .unwrap()
        .canonical_payload_hash
    };
    assert_eq!(guard(canonical_payload), guard(rebuilt_payload));
    assert_ne!(
        guard(changed_payload),
        guard(evertrace_domain::evidence::hex(
            &target_atom.semantic_structure_hash().unwrap()
        ))
    );

    let mut downstream_draft = atom_draft(&receipt, &observation, repository_id);
    downstream_draft.scope = AtomScope::Global;
    downstream_draft.supports_revision_refs = vec![target_atom.revision_id];
    let (downstream_proposal, downstream_submit) = submit(
        &proposals,
        &SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap(),
        4,
        ProposalTargetKind::Atom,
        ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
            draft: downstream_draft,
        })),
        receipt.source_receipt_id.to_string(),
    );
    handle.commit(downstream_submit, 4).await.unwrap();
    let downstream_frontier = handle.project().await.unwrap().frontier;
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                downstream_frontier,
                downstream_proposal.proposal_id,
                downstream_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&downstream_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        HumanActionOutcome::Applied { .. }
    ));
    let downstream_atom = SemanticCurrentView::from_snapshot(&handle.project().await.unwrap())
        .unwrap()
        .atoms
        .into_values()
        .find(|value| value.accepted_proposal_id == Some(downstream_proposal.proposal_id))
        .unwrap();

    let (procedure_proposal, procedure_submit) = submit(
        &proposals,
        &SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap(),
        5,
        ProposalTargetKind::Procedure,
        ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Create {
            draft: procedure_draft(
                receipt.source_receipt_id.to_string(),
                repository_id,
                vec![target_atom.revision_id],
            ),
        })),
        receipt.source_receipt_id.to_string(),
    );
    handle.commit(procedure_submit, 5).await.unwrap();
    let procedure_frontier = handle.project().await.unwrap().frontier;
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                procedure_frontier,
                procedure_proposal.proposal_id,
                procedure_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&procedure_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        HumanActionOutcome::Applied { .. }
    ));
    let (procedure_id, procedure_revision_id) =
        match SemanticCurrentView::from_snapshot(&handle.project().await.unwrap())
            .unwrap()
            .proposals
            .get(&procedure_proposal.proposal_id)
            .and_then(|proposal| proposal.acceptance.as_ref())
            .map(|acceptance| &acceptance.accepted_target)
            .unwrap()
        {
            AcceptedProposalTarget::Procedure {
                procedure_id,
                procedure_revision_id,
                ..
            } => (*procedure_id, *procedure_revision_id),
            _ => panic!("procedure target expected"),
        };

    let (core_proposal, core_submit) = submit(
        &proposals,
        &SemanticCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap(),
        7,
        ProposalTargetKind::CoreMembership,
        ProposalPayload::CoreMembership(Box::new(CoreMembershipProposalPayload::Create {
            atom_revision_id: atom.revision_id,
            scope_identity: CoreScopeIdentity::Repository(repository_id),
        })),
        receipt.source_receipt_id.to_string(),
    );
    handle.commit(core_submit, 7).await.unwrap();
    let core_frontier = handle.project().await.unwrap().frontier;
    assert!(matches!(
        service
            .decide_proposal(
                RequestId::new_v7(),
                core_frontier,
                core_proposal.proposal_id,
                core_proposal.proposal_revision_id,
                &evertrace_domain::evidence::hex(&core_proposal.fingerprint),
                HumanProposalDecision::Accept,
            )
            .await
            .unwrap(),
        HumanActionOutcome::Applied { .. }
    ));
    let membership_id = CoreMembershipId::from_uuid(core_proposal.proposal_id.as_uuid()).unwrap();
    let core_target = ObjectDeletionTarget::CoreMembership {
        core_membership_id: membership_id,
    };
    let core_snapshot = handle.project().await.unwrap();
    let core_preview = object_deletion_preview(&core_snapshot, core_target).unwrap();
    let core_request = RequestId::new_v7();
    let core_result = service
        .forget_object(
            core_request,
            core_snapshot.frontier,
            core_target,
            core_preview.exact_revision_ids.clone(),
            core_preview.deletion_generation,
        )
        .await;
    let core_audit = match core_result.unwrap() {
        HumanActionOutcome::Applied {
            audit_event_ref, ..
        } => audit_event_ref,
        other => panic!("core forget must apply, got {other:?}"),
    };
    let after_core = handle.project().await.unwrap();
    assert!(!after_core.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("core_membership")
            && row.object_id.as_deref() == Some(membership_id.to_string().as_str())
    }));
    assert!(!proposal_visible(&after_core, core_proposal.proposal_id));
    assert!(after_core.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("atom_revision")
            && row.object_id.as_deref() == Some(atom.atom_id.to_string().as_str())
    }));
    let replay_frontier = after_core.frontier;
    match service
        .forget_object(
            core_request,
            core_snapshot.frontier,
            core_target,
            core_preview.exact_revision_ids.clone(),
            core_preview.deletion_generation,
        )
        .await
        .unwrap()
    {
        HumanActionOutcome::Applied {
            audit_event_ref, ..
        } => assert_eq!(audit_event_ref, core_audit),
        other => panic!("core forget retry must replay, got {other:?}"),
    }
    assert_eq!(handle.project().await.unwrap().frontier, replay_frontier);

    let atom_target = ObjectDeletionTarget::Atom {
        atom_id: target_atom.atom_id,
    };
    let before_pending = handle.project().await.unwrap();
    let current_atoms = SemanticCurrentView::from_snapshot(&before_pending)
        .unwrap()
        .atoms;
    assert_eq!(
        current_atoms
            .values()
            .filter(|atom| atom
                .source_observation_refs
                .contains(&host_shared_observation.source_observation_id))
            .map(|atom| atom.atom_id)
            .collect::<Vec<_>>(),
        vec![target_atom.atom_id]
    );
    let atom_preview = object_deletion_preview(&before_pending, atom_target).unwrap();
    assert_eq!(atom_preview.shared_source_count, 1);
    assert_eq!(atom_preview.suppressed_source_count, 2);
    assert_eq!(atom_preview.suppression_ref_count, 4);
    assert_eq!(atom_preview.downstream_support_impacts.len(), 1);
    assert_eq!(atom_preview.dependent_procedure_impacts.len(), 1);
    let support_contracts = before_pending
        .data_rows()
        .filter_map(|row| {
            let payload: JournalPayload =
                serde_json::from_str(row.payload_json.as_deref()?).ok()?;
            let JournalPayload::GlobalSupportContractRecorded(contract) = payload else {
                return None;
            };
            Some(*contract)
        })
        .collect::<Vec<_>>();
    let target_owned_contract = support_contracts
        .iter()
        .find(|contract| {
            contract.successor_revision_or_membership_ref == target_atom.revision_id.to_string()
        })
        .unwrap()
        .support_contract_revision_id;
    let downstream_contract = support_contracts
        .iter()
        .find(|contract| {
            contract.successor_revision_or_membership_ref == downstream_atom.revision_id.to_string()
        })
        .unwrap()
        .support_contract_revision_id;
    let downstream_contracts = atom_preview
        .downstream_support_impacts
        .iter()
        .map(|impact| impact.current_validation.support_contract_ref)
        .collect::<Vec<_>>();
    assert!(downstream_contracts.contains(&downstream_contract));
    let target_owned_outbox_ids = before_pending
        .data_rows()
        .filter_map(|row| {
            let payload: JournalPayload =
                serde_json::from_str(row.payload_json.as_deref()?).ok()?;
            let JournalPayload::OutboxEnqueued(outbox) = payload else {
                return None;
            };
            (outbox.dirty.target_id == target_owned_contract.to_string())
                .then_some(outbox.outbox_id)
        })
        .collect::<Vec<_>>();
    assert!(!target_owned_outbox_ids.is_empty());
    let target_owned_job_ids = before_pending
        .data_rows()
        .filter_map(|row| {
            let payload: JournalPayload =
                serde_json::from_str(row.payload_json.as_deref()?).ok()?;
            let JournalPayload::JobState(job) = payload else {
                return None;
            };
            target_owned_outbox_ids
                .contains(&job.idempotency_key)
                .then_some(job.job_id)
        })
        .collect::<Vec<_>>();
    let pending_request = RequestId::new_v7();
    let pending_command = evertrace_engine::purge::pending_object_forget_command(
        pending_request,
        &atom_preview,
        &atom_preview.exact_revision_ids,
        atom_preview.deletion_generation,
        9,
        before_pending.frontier,
        CONFIG,
    )
    .unwrap();
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let mut pending_writer = open_writer(&store).await.unwrap();
    let mut missing_fanout = pending_command.events().to_vec();
    let missing_index = missing_fanout
        .iter()
        .position(|event| {
            matches!(
                &event.payload,
                JournalPayload::GlobalSupportValidationRecorded(_)
            )
        })
        .unwrap();
    missing_fanout.remove(missing_index);
    let forged = JournalCommand::new(CommandId::new_v7(), missing_fanout).unwrap();
    assert!(
        pending_writer
            .commit_if_frontier(&forged, 9, before_pending.frontier)
            .await
            .is_err()
    );
    assert_eq!(
        pending_writer.project().await.unwrap().frontier,
        before_pending.frontier
    );
    pending_writer
        .commit_if_frontier(&pending_command, 9, before_pending.frontier)
        .await
        .unwrap();
    let pending_snapshot = pending_writer.project().await.unwrap();
    assert!(!pending_snapshot.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("atom_revision")
            && row.object_id.as_deref() == Some(target_atom.atom_id.to_string().as_str())
    }));
    assert!(!proposal_visible(
        &pending_snapshot,
        target_proposal.proposal_id
    ));
    assert!(!pending_snapshot.data_rows().any(|row| {
        let Some(json) = row.payload_json.as_deref() else {
            return false;
        };
        match serde_json::from_str::<JournalPayload>(json) {
            Ok(JournalPayload::DirtyTarget(dirty)) => {
                dirty.target_id == target_owned_contract.to_string()
            }
            Ok(JournalPayload::OutboxEnqueued(outbox)) => {
                target_owned_outbox_ids.contains(&outbox.outbox_id)
            }
            Ok(JournalPayload::JobState(job)) => target_owned_job_ids.contains(&job.job_id),
            _ => false,
        }
    }));
    assert_eq!(
        ObjectDeletionCurrentView::from_snapshot(&pending_snapshot)
            .unwrap()
            .events[&atom_target]
            .phase,
        ObjectDeletionPhase::Pending
    );
    assert!(!pending_snapshot.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("global_support_contract")
            && row.current_revision_id.as_deref()
                == Some(target_owned_contract.to_string().as_str())
    }));
    for downstream_contract in downstream_contracts {
        let downstream_successor = support_contracts
            .iter()
            .find(|contract| contract.support_contract_revision_id == downstream_contract)
            .unwrap()
            .successor_revision_or_membership_ref
            .clone();
        assert!(pending_snapshot.data_rows().any(|row| {
            row.object_kind.as_deref() == Some("global_support_contract")
                && row.current_revision_id.as_deref()
                    == Some(downstream_contract.to_string().as_str())
        }));
        assert!(pending_snapshot.data_rows().any(|row| {
            let Some(payload_json) = row.payload_json.as_deref() else {
                return false;
            };
            matches!(
                serde_json::from_str::<JournalPayload>(payload_json),
                Ok(JournalPayload::GlobalSupportValidationRecorded(validation))
                    if validation.support_contract_ref == downstream_contract
                        && validation.successor_ref == downstream_successor
                        && validation.state
                            == evertrace_domain::semantic::GlobalSupportState::RevalidationPending
            )
        }));
        let pending_generation = pending_snapshot
            .data_rows()
            .filter_map(|row| {
                let payload: JournalPayload =
                    serde_json::from_str(row.payload_json.as_deref()?).ok()?;
                let JournalPayload::GlobalSupportValidationRecorded(validation) = payload else {
                    return None;
                };
                (validation.support_contract_ref == downstream_contract
                    && validation.state
                        == evertrace_domain::semantic::GlobalSupportState::RevalidationPending)
                    .then_some(validation.dependency_generation)
            })
            .max()
            .unwrap();
        let pending_key = format!("support:{downstream_contract}:{pending_generation}");
        assert!(pending_snapshot.data_rows().any(|row| {
            let Some(json) = row.payload_json.as_deref() else {
                return false;
            };
            matches!(
                serde_json::from_str::<JournalPayload>(json),
                Ok(JournalPayload::OutboxEnqueued(outbox)) if outbox.outbox_id == pending_key
            )
        }));
        assert!(pending_snapshot.data_rows().any(|row| {
            let Some(json) = row.payload_json.as_deref() else {
                return false;
            };
            matches!(
                serde_json::from_str::<JournalPayload>(json),
                Ok(JournalPayload::JobState(job))
                    if job.idempotency_key == pending_key
                        && job.kind == "support_closure"
                        && job.target_revision == downstream_successor
                        && job.state == evertrace_store::JobStatus::Queued
            )
        }));
    }
    assert!(pending_snapshot.data_rows().any(|row| {
        let Some(payload_json) = row.payload_json.as_deref() else {
            return false;
        };
        matches!(
            serde_json::from_str::<JournalPayload>(payload_json),
            Ok(JournalPayload::ProcedureStateRecorded(state))
                if state.procedure_revision_id == procedure_revision_id
                    && state.to_state
                        == evertrace_domain::procedure::ProcedurePublicationState::ReviewHold
        )
    }));
    assert_eq!(
        pending_writer.full_projection().await.unwrap(),
        pending_snapshot
    );
    drop(pending_writer);
    let restarted_writer = open_writer(&store).await.unwrap();
    let (handle, task) = spawn_writer(restarted_writer, 8).unwrap();
    let purged = handle.project().await.unwrap();
    let ledger = ObjectDeletionCurrentView::from_snapshot(&purged).unwrap();
    assert_eq!(
        ledger.events[&atom_target].phase,
        ObjectDeletionPhase::Purged
    );
    assert!(purged.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("repository")
            && row.object_id.as_deref() == Some(repository_id.to_string().as_str())
    }));
    assert!(
        ledger.suppression_ref_hashes().contains(
            &default_retrieval_suppression_ref_hash(
                &exclusive_surface,
                &exclusive_receipt,
                DefaultRetrievalSuppressionGeneration::ContentSpanV2,
            )
            .unwrap()
        )
    );
    assert!(
        !ledger.suppression_ref_hashes().contains(
            &default_retrieval_suppression_ref_hash(
                &host_shared_surface,
                &host_shared_receipt,
                DefaultRetrievalSuppressionGeneration::ContentSpanV2,
            )
            .unwrap()
        )
    );

    let (_, _, rewritten_surface) = source("rewritten", repository_id);
    let (rewritten_receipt, _, _) = source("rewritten", repository_id);
    assert_ne!(exclusive_surface.span_hash, rewritten_surface.span_hash);
    assert_eq!(
        default_retrieval_suppression_ref_hash(
            &exclusive_surface,
            &exclusive_receipt,
            DefaultRetrievalSuppressionGeneration::ContentSpanV2,
        )
        .unwrap(),
        default_retrieval_suppression_ref_hash(
            &rewritten_surface,
            &rewritten_receipt,
            DefaultRetrievalSuppressionGeneration::ContentSpanV2,
        )
        .unwrap()
    );

    let restarted_service = HumanGovernanceService::with_acceptance(
        handle.clone(),
        CONFIG,
        runtime.clone(),
        GlobalPromotionConfig {
            atom: PromotionLevel::Manual,
            procedure: PromotionLevel::Manual,
            core_membership: PromotionLevel::Manual,
        },
    );
    let procedure_target = ObjectDeletionTarget::Procedure { procedure_id };
    let stale_snapshot = handle.project().await.unwrap();
    let stale_preview = object_deletion_preview(&stale_snapshot, procedure_target).unwrap();
    handle
        .commit(
            JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    10,
                    CONFIG,
                    "s32-test-v1",
                    JournalPayload::DirtyTarget(evertrace_store::DirtyTarget {
                        target_kind: evertrace_store::DirtyTargetKind::RuntimeJob,
                        target_id: "s32-frontier-bump".into(),
                        algorithm_revision: "s32-test-v1".into(),
                        source_watermark: stale_snapshot.frontier,
                    }),
                )],
            )
            .unwrap(),
            10,
        )
        .await
        .unwrap();
    assert!(matches!(
        restarted_service
            .forget_object(
                RequestId::new_v7(),
                stale_snapshot.frontier,
                procedure_target,
                stale_preview.exact_revision_ids,
                stale_preview.deletion_generation,
            )
            .await
            .unwrap(),
        HumanActionOutcome::Conflict { .. }
    ));
    let current = handle.project().await.unwrap();
    let procedure_preview = object_deletion_preview(&current, procedure_target).unwrap();
    assert!(matches!(
        restarted_service
            .forget_object(
                RequestId::new_v7(),
                current.frontier,
                procedure_target,
                procedure_preview.exact_revision_ids,
                procedure_preview.deletion_generation,
            )
            .await
            .unwrap(),
        HumanActionOutcome::Applied { .. }
    ));
    let expected = handle.project().await.unwrap();
    assert!(!proposal_visible(&expected, procedure_proposal.proposal_id));
    assert!(expected.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("evidence_surface")
            && row.current_revision_id.as_deref()
                == Some(
                    host_shared_observation
                        .source_observation_id
                        .to_string()
                        .as_str(),
                )
    }));
    assert!(expected.data_rows().any(|row| {
        row.object_kind.as_deref() == Some("host_occurrence")
            && row.object_id.as_deref()
                == Some(host_occurrence.host_occurrence_id.to_string().as_str())
    }));
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let reopened = open_writer(&store).await.unwrap();
    let journal_rows = reopened.journal_rows().await.unwrap();
    for proposal_id in [
        target_proposal.proposal_id,
        procedure_proposal.proposal_id,
        core_proposal.proposal_id,
    ] {
        assert!(journal_rows.iter().any(|row| {
            matches!(
                row.payload(),
                Ok(JournalPayload::RevisionProposalRecorded(value))
                    if value.proposal_id == proposal_id
            )
        }));
    }
    assert_eq!(reopened.table_names().await.unwrap().len(), 4);
    assert_eq!(reopened.project().await.unwrap(), expected);
    assert_eq!(reopened.full_projection().await.unwrap(), expected);
    let (reopened_handle, reopened_task) = spawn_writer(reopened, 8).unwrap();
    let reopened_service = HumanGovernanceService::with_acceptance(
        reopened_handle.clone(),
        CONFIG,
        runtime,
        GlobalPromotionConfig {
            atom: PromotionLevel::Manual,
            procedure: PromotionLevel::Manual,
            core_membership: PromotionLevel::Manual,
        },
    );
    match reopened_service
        .forget_object(
            core_request,
            core_snapshot.frontier,
            core_target,
            core_preview.exact_revision_ids,
            core_preview.deletion_generation,
        )
        .await
        .unwrap()
    {
        HumanActionOutcome::Applied {
            audit_event_ref, ..
        } => assert_eq!(audit_event_ref, core_audit),
        other => panic!("reopened core retry must replay, got {other:?}"),
    }
    assert_eq!(reopened_handle.project().await.unwrap(), expected);
    reopened_handle.shutdown().await.unwrap();
    reopened_task.await.unwrap().unwrap();
}
