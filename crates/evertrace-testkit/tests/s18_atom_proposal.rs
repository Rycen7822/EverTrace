use std::collections::BTreeSet;

use evertrace_codex::{
    HostProbeReport,
    adapter_manifest::{AdapterKind, MaxHostResolvedScope},
    policy::{PolicyCandidateOrigin, PolicyEvidence},
    probe::{EvidenceSourceKind as ProbeEvidenceSourceKind, ProbeContext, ProbeEvidence},
};
use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceByteRange,
        EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength, ObservationRole,
        SourceArchiveMode, SourceInstanceId, SourceObservation, SourceReceipt,
        SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole, payload_fingerprint,
        source_observation_id, source_receipt_id,
    },
    ids::{CommandId, RepositoryId, RevisionProposalId, TaskId, WorktreeId},
    repository::{
        FilesystemIdentity, GitObjectFormat, GitRegistrationState, PathObservation,
        RepositoryInstance, WorktreeInstance, WorktreeKind, WorktreeLifecycle,
    },
    revision::RevisionId,
    semantic::{
        ApplicabilityExpr, AtomAuthority, AtomDraft, AtomKind, AtomLifecycleStatus,
        AtomProposalPayload, AtomProvenance, AtomScope, AtomValue, ConstraintBinding,
        ConstraintExpr, ConstraintField, ConstraintState, ConstraintTruth, ConstraintValue,
        EpistemicStatus, PolicyAuthorityProvenance, PolicyHostScope, ProposalAcceptanceAuthority,
        ProposalCreatedBy, ProposalEligibility, ProposalOperation, ProposalPayload, ProposalStatus,
        ProposalTargetId, ProposalTargetKind, ProposalWaitingOn, SemanticQualifier,
        TUI_ACCEPTANCE_EVENT_MANIFEST_REF, UserAuthorizationMode, ValidityInterval,
        tui_acceptance_event_payload,
    },
    work::{Task, TaskIdentityConfidence, TaskLifecycle, TaskScopeMembership},
};
use evertrace_engine::semantic::{
    AtomAcceptanceContext, AtomAuthorityBasis, AtomEmissionDecision, AtomEmissionGate,
    AtomMaterialization, CurrentPolicyBinding, DescriptiveFactResolver, DescriptiveResolutionState,
    NormativeInstructionResolver, NormativeResolutionState, ProposalCommandContext,
    ProposalResolution, ResolverContext, RevisionProposalService, SemanticServiceError,
    SparseAtomSignal, SparseNoDeltaReason, SubmitProposalRequest, exact_task_constraint_draft,
    materialize_atom,
};
use evertrace_store::relations::{SemanticRelationKind, build_semantic_relation_rows};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload, JournalWriter,
    SemanticCurrentView, SourceIngestWatermark,
};
use tempfile::TempDir;

#[derive(Clone)]
struct ScopeFixture {
    repository: RepositoryInstance,
    worktree: WorktreeInstance,
    task: Task,
}

#[derive(Clone)]
struct VerifiedPolicyFixture {
    receipt: SourceReceipt,
    observation: SourceObservation,
    evidence: PolicyEvidence,
    context: ProbeContext,
    report: HostProbeReport,
    provenance: PolicyAuthorityProvenance,
    binding: CurrentPolicyBinding,
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
        evidence_refs: vec!["path:s18".into()],
    };
    let repository = RepositoryInstance {
        repository_id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: path.clone(),
        path_history: vec![observation.clone()],
        git_common_dir_path: Some(format!("{path}/.git")),
        common_dir_filesystem: Some(FilesystemIdentity {
            device: 18,
            inode: 1,
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: vec![],
        derived_from: None,
        identity_evidence_refs: vec!["repository:s18".into()],
        recorded_at_us: 1,
    };
    let worktree = WorktreeInstance {
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
        created_event_ref: "worktree:s18".into(),
        terminal_event_ref: None,
        recreated_from_worktree_instance_id: None,
        recorded_at_us: 1,
    };
    let task = Task {
        task_id,
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec!["request:s18".into()],
        canonical_goal: "exercise atom and proposal contracts".into(),
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
    };
    ScopeFixture {
        repository,
        worktree,
        task,
    }
}

fn user_source(
    label: &str,
    payload: &str,
    task_id: TaskId,
    repository_id: RepositoryId,
    worktree_id: WorktreeId,
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
        task_id: Some(task_id),
        repository_instance_id: Some(repository_id),
        worktree_instance_id: Some(worktree_id),
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
        adapter_manifest_ref: "adapter-s18".into(),
        eligible_event_manifest_ref: "eligible-s18".into(),
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
            adapter_manifest_ref: "adapter-s18".into(),
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

fn verified_policy_source(
    label: &str,
    payload: &str,
    scope: &ScopeFixture,
    resolved_scope: MaxHostResolvedScope,
) -> VerifiedPolicyFixture {
    let (mut receipt, mut observation) = user_source(
        label,
        payload,
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let policy_source_kind = format!("host_policy_{label}");
    receipt.source_ref = policy_source_kind.clone();
    receipt.observation_role = ObservationRole::StateProbe;
    observation.observation_role = ObservationRole::StateProbe;
    observation.correlation.pairing_role = ObservationRole::StateProbe;
    observation.source_role = SourceRole::Host;
    observation.content_trust = ContentTrust::Observed;
    let mut evidence_refs = vec![
        receipt.source_receipt_id.to_string(),
        observation.source_observation_id.to_string(),
    ];
    evidence_refs.sort();
    let evidence = PolicyEvidence {
        policy_source_kind: policy_source_kind.clone(),
        origin: PolicyCandidateOrigin::HostPolicySurface,
        host_loaded: true,
        readback_supported: true,
        readback_matches: true,
        source_revision: observation.source_revision.as_str().into(),
        content_digest: observation.payload_fingerprint.clone(),
        resolved_scope: Some(resolved_scope),
        current_trust: true,
        current: true,
        revoked: false,
        evidence_refs,
    };
    let context = ProbeContext {
        adapter_kind: AdapterKind::CodexSessionJsonl,
        adapter_revision: format!("policy-probe-{label}"),
        observed_host_version_range: "s18-observed".into(),
        eligible_event_manifest_ref: "s18_policy_event_manifest".into(),
        evidence_source: ProbeEvidenceSourceKind::ObservedHostCanary,
    };
    let report = HostProbeReport::evaluate(
        &context,
        &ProbeEvidence {
            policy: Some(evidence.clone()),
            ..ProbeEvidence::empty()
        },
    )
    .unwrap();
    receipt.adapter_manifest_ref = report.manifest().adapter_manifest_id.clone();
    observation.correlation.adapter_manifest_ref = report.manifest().adapter_manifest_id.clone();
    let provenance = PolicyAuthorityProvenance {
        policy_source_kind,
        policy_source_revision_ref: observation.source_revision.as_str().into(),
        policy_content_hash: payload_fingerprint(
            observation.canonicalization_revision,
            payload.as_bytes(),
            None,
        )
        .unwrap(),
        host_resolved_scope: match resolved_scope {
            MaxHostResolvedScope::Worktree => PolicyHostScope::Worktree {
                repository_instance_id: scope.repository.repository_id,
                worktree_instance_id: scope.worktree.worktree_instance_id,
            },
            MaxHostResolvedScope::Repository => PolicyHostScope::Repository {
                repository_instance_id: scope.repository.repository_id,
            },
        },
        adapter_manifest_id: report.manifest().adapter_manifest_id.clone(),
    };
    let binding = CurrentPolicyBinding::from_verified_host_probe(
        &report,
        &evidence,
        provenance.clone(),
        &observation,
        &receipt,
    )
    .unwrap();
    VerifiedPolicyFixture {
        receipt,
        observation,
        evidence,
        context,
        report,
        provenance,
        binding,
    }
}

fn tui_acceptance_source(
    label: &str,
    proposal: &evertrace_domain::semantic::RevisionProposal,
    scope: &ScopeFixture,
) -> (SourceReceipt, SourceObservation) {
    let payload = tui_acceptance_event_payload(
        proposal.proposal_id,
        proposal.proposal_revision_id,
        &proposal.fingerprint,
    );
    let (mut receipt, observation) = user_source(
        label,
        &payload,
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    receipt.eligible_event_manifest_ref = TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into();
    let event_at_us = proposal.created_at_us.checked_add(1).unwrap();
    receipt.event_time_us = 0;
    receipt.recorded_at_us = event_at_us;
    (receipt, observation)
}

fn value(text: &str) -> AtomValue {
    AtomValue {
        text: text.into(),
        subject: "subject".into(),
        predicate: "predicate".into(),
        object: Some("object".into()),
        qualifiers: vec![SemanticQualifier {
            name: "qualifier".into(),
            value: "value".into(),
        }],
        critical_revision_refs: vec![],
    }
}

fn draft(
    scope: AtomScope,
    kind: AtomKind,
    epistemic_status: EpistemicStatus,
    observation: &SourceObservation,
    receipt: &SourceReceipt,
) -> AtomDraft {
    AtomDraft {
        kind,
        epistemic_status,
        value: value("semantic value"),
        scope,
        applicability_expr: ApplicabilityExpr::Always,
        future_cue_lifecycle_exprs: None,
        validity_interval: ValidityInterval {
            valid_from_us: 1,
            valid_until_us: Some(100),
        },
        provenance: vec![AtomProvenance::AgentClaimed],
        source_observation_refs: vec![observation.source_observation_id],
        evidence_refs: vec![receipt.source_receipt_id.to_string()],
        supersedes_revision_refs: vec![],
        supports_revision_refs: vec![],
        contradicts_revision_refs: vec![],
    }
}

fn command_context(at: i64) -> ProposalCommandContext {
    ProposalCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: [0x18; 32],
        algorithm_revision: "s18-semantic-v1".into(),
    }
}

fn command(at: i64, payloads: Vec<JournalPayload>) -> JournalCommand {
    JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, [0x18; 32], "s18-semantic-v1", payload))
            .collect(),
    )
    .unwrap()
}

async fn initialized_writer(
    store_root: &std::path::Path,
    scope: &ScopeFixture,
    receipt: &SourceReceipt,
    observation: &SourceObservation,
) -> JournalWriter {
    let mut writer = JournalWriter::open(store_root).await.unwrap();
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
                        source_sequence: receipt.source_sequence,
                        confirmed_prefix_digest: None,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::EvidenceSurface,
                        target_id: observation.source_observation_id.to_string(),
                        algorithm_revision: "s18-semantic-v1".into(),
                        source_watermark: 1,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::PhysicalNormalization,
                        target_id: observation.source_observation_id.to_string(),
                        algorithm_revision: "s18-semantic-v1".into(),
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
    writer
}

async fn persist_source(
    writer: &mut JournalWriter,
    receipt: &SourceReceipt,
    observation: &SourceObservation,
    at: i64,
) {
    writer
        .commit(
            &command(
                at,
                vec![
                    JournalPayload::SourceReceiptRecorded(Box::new(receipt.clone())),
                    JournalPayload::SourceObservationRecorded(Box::new(observation.clone())),
                    JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
                        source_instance_id: receipt.source_instance_id.clone(),
                        source_revision: receipt.source_revision.clone(),
                        source_sequence: receipt.source_sequence,
                        confirmed_prefix_digest: None,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::EvidenceSurface,
                        target_id: observation.source_observation_id.to_string(),
                        algorithm_revision: "s18-semantic-v1".into(),
                        source_watermark: receipt.source_sequence,
                    }),
                    JournalPayload::DirtyTarget(DirtyTarget {
                        target_kind: DirtyTargetKind::PhysicalNormalization,
                        target_id: observation.source_observation_id.to_string(),
                        algorithm_revision: "s18-semantic-v1".into(),
                        source_watermark: receipt.source_sequence,
                    }),
                ],
            ),
            at,
        )
        .await
        .unwrap();
}

#[test]
fn constraint_expr_is_closed_bounded_and_three_valued() {
    let current = ConstraintState {
        bindings: vec![
            ConstraintBinding {
                field: ConstraintField::RevisionActive,
                value: ConstraintValue::Boolean(true),
            },
            ConstraintBinding {
                field: ConstraintField::Phase,
                value: ConstraintValue::Text("verify".into()),
            },
        ],
    };
    let previous = ConstraintState {
        bindings: vec![
            ConstraintBinding {
                field: ConstraintField::RevisionActive,
                value: ConstraintValue::Boolean(true),
            },
            ConstraintBinding {
                field: ConstraintField::Phase,
                value: ConstraintValue::Text("implement".into()),
            },
        ],
    };
    let expr = ConstraintExpr::All {
        terms: vec![
            ConstraintExpr::Eq {
                field: ConstraintField::RevisionActive,
                value: ConstraintValue::Boolean(true),
            },
            ConstraintExpr::In {
                field: ConstraintField::Phase,
                values: vec![
                    ConstraintValue::Text("test".into()),
                    ConstraintValue::Text("verify".into()),
                ],
            },
            ConstraintExpr::Exists {
                field: ConstraintField::Phase,
            },
            ConstraintExpr::Changed {
                field: ConstraintField::Phase,
            },
            ConstraintExpr::Transitioned {
                field: ConstraintField::Phase,
                from: ConstraintValue::Text("implement".into()),
                to: ConstraintValue::Text("verify".into()),
            },
            ConstraintExpr::Not {
                term: Box::new(ConstraintExpr::Eq {
                    field: ConstraintField::Phase,
                    value: ConstraintValue::Text("release".into()),
                }),
            },
            ConstraintExpr::Any {
                terms: vec![
                    ConstraintExpr::Eq {
                        field: ConstraintField::Phase,
                        value: ConstraintValue::Text("verify".into()),
                    },
                    ConstraintExpr::Exists {
                        field: ConstraintField::FailureSignature,
                    },
                ],
            },
        ],
    };
    assert_eq!(
        expr.evaluate(&current, Some(&previous)),
        ConstraintTruth::True
    );
    assert_eq!(
        ConstraintExpr::Changed {
            field: ConstraintField::Phase
        }
        .evaluate(&current, None),
        ConstraintTruth::Unknown
    );
    assert_eq!(
        ConstraintExpr::Eq {
            field: ConstraintField::FailureSignature,
            value: ConstraintValue::Text("missing".into()),
        }
        .evaluate(&current, Some(&previous)),
        ConstraintTruth::Unknown
    );
    assert_eq!(
        ConstraintExpr::Exists {
            field: ConstraintField::FailureSignature,
        }
        .evaluate(&current, Some(&previous)),
        ConstraintTruth::Unknown
    );
    let invalid_transition = ConstraintExpr::Transitioned {
        field: ConstraintField::AgentKind,
        from: ConstraintValue::Text("a".into()),
        to: ConstraintValue::Text("b".into()),
    };
    assert!(invalid_transition.validate().is_err());
    assert_eq!(
        invalid_transition.evaluate(&current, Some(&previous)),
        ConstraintTruth::Unknown
    );
    let invalid_operand = ConstraintExpr::Eq {
        field: ConstraintField::AgentKind,
        value: ConstraintValue::Boolean(true),
    };
    assert!(invalid_operand.validate().is_err());
    assert_eq!(
        invalid_operand.evaluate(&current, Some(&previous)),
        ConstraintTruth::Unknown
    );
    let mut json = serde_json::to_value(&expr).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("regex".into(), serde_json::json!(".*"));
    assert!(serde_json::from_value::<ConstraintExpr>(json).is_err());
}

#[test]
fn authority_axes_and_exact_message_boundaries_fail_closed() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let message = "Keep the exact task boundary.";
    let (receipt, observation) = user_source(
        "axes",
        message,
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let exact = exact_task_constraint_draft(
        message.into(),
        scope.task.task_id,
        observation.source_observation_id,
        receipt.source_receipt_id,
        1,
        99,
    );
    let atom = materialize_atom(
        AtomMaterialization {
            draft: exact.clone(),
            authority_basis: AtomAuthorityBasis::CurrentTaskExactMessage {
                observation: Box::new(observation.clone()),
                receipt: Box::new(receipt.clone()),
                canonical_message: message.into(),
            },
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 2,
        },
        None,
    )
    .unwrap();
    assert_eq!(atom.authority, AtomAuthority::UserExplicit);
    assert_eq!(
        atom.user_authorization_provenance.as_ref().unwrap().mode,
        UserAuthorizationMode::CurrentTaskExactMessage
    );
    let mut atom_json = serde_json::to_value(&atom).unwrap();
    atom_json
        .as_object_mut()
        .unwrap()
        .insert("open_extension".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<evertrace_domain::semantic::Atom>(atom_json).is_err());

    for changed in ["Keep the boundary.", "保持精确任务边界。"] {
        let mut invalid = exact.clone();
        invalid.value.text = changed.into();
        assert!(
            materialize_atom(
                AtomMaterialization {
                    draft: invalid,
                    authority_basis: AtomAuthorityBasis::CurrentTaskExactMessage {
                        observation: Box::new(observation.clone()),
                        receipt: Box::new(receipt.clone()),
                        canonical_message: message.into(),
                    },
                    accepted_proposal_id: None,
                    accepted_proposal_revision_id: None,
                    created_at_us: 2,
                },
                None,
            )
            .is_err()
        );
    }
    let mut unrelated_observation = observation.clone();
    unrelated_observation.payload_fingerprint = evertrace_domain::evidence::hex(
        &payload_fingerprint(1, b"different message", None).unwrap(),
    );
    assert!(
        materialize_atom(
            AtomMaterialization {
                draft: exact.clone(),
                authority_basis: AtomAuthorityBasis::CurrentTaskExactMessage {
                    observation: Box::new(unrelated_observation),
                    receipt: Box::new(receipt.clone()),
                    canonical_message: message.into(),
                },
                accepted_proposal_id: None,
                accepted_proposal_revision_id: None,
                created_at_us: 2,
            },
            None,
        )
        .is_err()
    );
    let mut partial_observation = observation.clone();
    partial_observation.capture_completeness = CaptureCompleteness::Partial;
    let mut partial_receipt = receipt.clone();
    partial_receipt.capture_completeness = CaptureCompleteness::Partial;
    assert!(
        materialize_atom(
            AtomMaterialization {
                draft: exact.clone(),
                authority_basis: AtomAuthorityBasis::CurrentTaskExactMessage {
                    observation: Box::new(partial_observation),
                    receipt: Box::new(partial_receipt),
                    canonical_message: message.into(),
                },
                accepted_proposal_id: None,
                accepted_proposal_revision_id: None,
                created_at_us: 2,
            },
            None,
        )
        .is_err()
    );
    let mut supplemented = exact.clone();
    supplemented.value.qualifiers.push(SemanticQualifier {
        name: "hidden_condition".into(),
        value: "expanded_interpretation".into(),
    });
    assert!(
        materialize_atom(
            AtomMaterialization {
                draft: supplemented,
                authority_basis: AtomAuthorityBasis::CurrentTaskExactMessage {
                    observation: Box::new(observation.clone()),
                    receipt: Box::new(receipt.clone()),
                    canonical_message: message.into(),
                },
                accepted_proposal_id: None,
                accepted_proposal_revision_id: None,
                created_at_us: 2,
            },
            None,
        )
        .is_err()
    );
    let mut expanded = exact;
    expanded.scope = AtomScope::Repository {
        repository_instance_id: scope.repository.repository_id,
    };
    assert!(
        materialize_atom(
            AtomMaterialization {
                draft: expanded,
                authority_basis: AtomAuthorityBasis::CurrentTaskExactMessage {
                    observation: Box::new(observation.clone()),
                    receipt: Box::new(receipt.clone()),
                    canonical_message: message.into(),
                },
                accepted_proposal_id: None,
                accepted_proposal_revision_id: None,
                created_at_us: 2,
            },
            None,
        )
        .is_err()
    );

    let mut statement = draft(
        AtomScope::Task {
            task_id: scope.task.task_id,
        },
        AtomKind::Fact,
        EpistemicStatus::Unverified,
        &observation,
        &receipt,
    );
    statement.value.text = message.into();
    statement.provenance = vec![AtomProvenance::UserAsserted];
    let statement_atom = materialize_atom(
        AtomMaterialization {
            draft: statement,
            authority_basis: AtomAuthorityBasis::UserStatement {
                observation: Box::new(observation.clone()),
                receipt: Box::new(receipt.clone()),
            },
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 2,
        },
        None,
    )
    .unwrap();
    assert_eq!(statement_atom.epistemic_status, EpistemicStatus::Unverified);

    let mut objective = draft(
        AtomScope::Task {
            task_id: scope.task.task_id,
        },
        AtomKind::Constraint,
        EpistemicStatus::NotApplicable,
        &observation,
        &receipt,
    );
    objective.provenance = vec![AtomProvenance::ObservedExec];
    assert!(
        materialize_atom(
            AtomMaterialization {
                draft: objective,
                authority_basis: AtomAuthorityBasis::ObjectiveEvidence,
                accepted_proposal_id: None,
                accepted_proposal_revision_id: None,
                created_at_us: 2,
            },
            None,
        )
        .is_err()
    );

    let mut agent_supported = draft(
        AtomScope::Task {
            task_id: scope.task.task_id,
        },
        AtomKind::Fact,
        EpistemicStatus::Supported,
        &observation,
        &receipt,
    );
    agent_supported.provenance = vec![AtomProvenance::AgentClaimed];
    assert!(
        materialize_atom(
            AtomMaterialization {
                draft: agent_supported,
                authority_basis: AtomAuthorityBasis::AgentInferred,
                accepted_proposal_id: None,
                accepted_proposal_revision_id: None,
                created_at_us: 2,
            },
            None,
        )
        .is_err()
    );
    let mut imported_supported = draft(
        AtomScope::Task {
            task_id: scope.task.task_id,
        },
        AtomKind::Claim,
        EpistemicStatus::Supported,
        &observation,
        &receipt,
    );
    imported_supported.provenance = vec![AtomProvenance::ObservedExec];
    assert!(
        materialize_atom(
            AtomMaterialization {
                draft: imported_supported,
                authority_basis: AtomAuthorityBasis::ImportedClaim,
                accepted_proposal_id: None,
                accepted_proposal_revision_id: None,
                created_at_us: 2,
            },
            None,
        )
        .is_err()
    );
}

#[test]
fn sparse_emission_is_formally_no_delta_for_ordinary_signals() {
    let gate = AtomEmissionGate;
    for (signal, reason) in [
        (
            SparseAtomSignal::OrdinaryToolEvent,
            SparseNoDeltaReason::OrdinaryToolEvent,
        ),
        (
            SparseAtomSignal::IntermediatePlan,
            SparseNoDeltaReason::IntermediateState,
        ),
        (
            SparseAtomSignal::TemporaryTodo,
            SparseNoDeltaReason::IntermediateState,
        ),
        (
            SparseAtomSignal::UnadoptedOption,
            SparseNoDeltaReason::UnadoptedOption,
        ),
        (
            SparseAtomSignal::UnusedGuess,
            SparseNoDeltaReason::UnusedGuess,
        ),
        (
            SparseAtomSignal::RecoverableFromCode,
            SparseNoDeltaReason::RecoverableFromCode,
        ),
        (
            SparseAtomSignal::MissingEvidence,
            SparseNoDeltaReason::MissingEvidence,
        ),
        (
            SparseAtomSignal::MissingScope,
            SparseNoDeltaReason::MissingScope,
        ),
        (
            SparseAtomSignal::NoCrossEpisodeValue,
            SparseNoDeltaReason::NoCrossEpisodeValue,
        ),
    ] {
        assert_eq!(
            gate.evaluate(signal, &[]).unwrap(),
            AtomEmissionDecision::NothingToSave(reason)
        );
    }
}

#[test]
fn sparse_emission_positive_signals_are_closed_and_exact_deduped() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let message = "Preserve this complete task instruction.";
    let (receipt, observation) = user_source(
        "sparse-positive",
        message,
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let materialization = AtomMaterialization {
        draft: exact_task_constraint_draft(
            message.into(),
            scope.task.task_id,
            observation.source_observation_id,
            receipt.source_receipt_id,
            1,
            90,
        ),
        authority_basis: AtomAuthorityBasis::CurrentTaskExactMessage {
            observation: Box::new(observation),
            receipt: Box::new(receipt),
            canonical_message: message.into(),
        },
        accepted_proposal_id: None,
        accepted_proposal_revision_id: None,
        created_at_us: 2,
    };
    let gate = AtomEmissionGate;
    let AtomEmissionDecision::Atom(atom) = gate
        .evaluate(
            SparseAtomSignal::ExactCurrentUserConstraint(materialization.clone()),
            &[],
        )
        .unwrap()
    else {
        panic!("exact current message must emit one Atom");
    };
    assert_eq!(
        gate.evaluate(
            SparseAtomSignal::ExactCurrentUserConstraint(materialization.clone()),
            &[(*atom).clone()],
        )
        .unwrap(),
        AtomEmissionDecision::NothingToSave(SparseNoDeltaReason::ExactEquivalent)
    );
    assert!(
        gate.evaluate(SparseAtomSignal::AdoptedDecision(materialization), &[],)
            .is_err()
    );
}

#[test]
fn sparse_no_delta_compares_the_complete_semantic_state() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let message = "Keep the exact reviewed constraint.";
    let (receipt, observation) = user_source(
        "semantic-delta",
        message,
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let materialization = AtomMaterialization {
        draft: exact_task_constraint_draft(
            message.into(),
            scope.task.task_id,
            observation.source_observation_id,
            receipt.source_receipt_id,
            1,
            90,
        ),
        authority_basis: AtomAuthorityBasis::CurrentTaskExactMessage {
            observation: Box::new(observation),
            receipt: Box::new(receipt),
            canonical_message: message.into(),
        },
        accepted_proposal_id: None,
        accepted_proposal_revision_id: None,
        created_at_us: 2,
    };
    let gate = AtomEmissionGate;
    let AtomEmissionDecision::Atom(atom) = gate
        .evaluate(
            SparseAtomSignal::ExactCurrentUserConstraint(materialization.clone()),
            &[],
        )
        .unwrap()
    else {
        panic!("exact constraint must materialize");
    };

    let mut changed_text = (*atom).clone();
    changed_text.value.text = "Different reviewed constraint.".into();
    changed_text
        .user_authorization_provenance
        .as_mut()
        .unwrap()
        .exact_value_hash = changed_text.value.exact_hash().unwrap();
    assert!(changed_text.validate().is_ok());
    let mut changed_evidence = (*atom).clone();
    changed_evidence
        .evidence_refs
        .push("evidence:additional".into());
    changed_evidence.evidence_refs.sort();
    assert!(changed_evidence.validate().is_ok());
    let mut changed_applicability = (*atom).clone();
    changed_applicability.validity_interval.valid_until_us = Some(91);
    assert!(changed_applicability.validate().is_ok());

    for changed in [changed_text, changed_evidence, changed_applicability] {
        assert!(!atom.same_semantic_state(&changed));
        assert!(matches!(
            gate.evaluate(
                SparseAtomSignal::ExactCurrentUserConstraint(materialization.clone()),
                &[changed],
            )
            .unwrap(),
            AtomEmissionDecision::Atom(_)
        ));
    }
    let mut changed_epistemic = (*atom).clone();
    changed_epistemic.epistemic_status = EpistemicStatus::Unverified;
    let mut changed_authority = (*atom).clone();
    changed_authority.authority = AtomAuthority::AgentInferred;
    let mut changed_lineage = (*atom).clone();
    changed_lineage.accepted_proposal_id = Some(RevisionProposalId::new_v7());
    changed_lineage.accepted_proposal_revision_id = Some(RevisionId::new_v7());
    assert!(atom.same_semantic_state(&changed_lineage));
    assert!(!atom.same_semantic_state(&changed_epistemic));
    assert!(!atom.same_semantic_state(&changed_authority));

    let (fact_receipt, fact_observation) = user_source(
        "semantic-axis-delta",
        "observed failure",
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let mut supported_failure = draft(
        AtomScope::Task {
            task_id: scope.task.task_id,
        },
        AtomKind::Failure,
        EpistemicStatus::Supported,
        &fact_observation,
        &fact_receipt,
    );
    supported_failure.provenance = vec![AtomProvenance::ObservedExec];
    let objective_materialization = AtomMaterialization {
        draft: supported_failure.clone(),
        authority_basis: AtomAuthorityBasis::ObjectiveEvidence,
        accepted_proposal_id: None,
        accepted_proposal_revision_id: None,
        created_at_us: 3,
    };
    let mut unverified_failure = supported_failure;
    unverified_failure.epistemic_status = EpistemicStatus::Unverified;
    unverified_failure.provenance = vec![AtomProvenance::AgentClaimed];
    let agent_atom = materialize_atom(
        AtomMaterialization {
            draft: unverified_failure,
            authority_basis: AtomAuthorityBasis::AgentInferred,
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 3,
        },
        None,
    )
    .unwrap();
    assert!(matches!(
        gate.evaluate(
            SparseAtomSignal::MaterialObjectiveFailure(objective_materialization),
            &[agent_atom],
        )
        .unwrap(),
        AtomEmissionDecision::Atom(_)
    ));

    let decision_draft = draft(
        AtomScope::Task {
            task_id: scope.task.task_id,
        },
        AtomKind::Decision,
        EpistemicStatus::NotApplicable,
        &fact_observation,
        &fact_receipt,
    );
    let decision_materialization = AtomMaterialization {
        draft: decision_draft,
        authority_basis: AtomAuthorityBasis::AgentInferred,
        accepted_proposal_id: None,
        accepted_proposal_revision_id: None,
        created_at_us: 4,
    };
    let decision = materialize_atom(decision_materialization.clone(), None).unwrap();
    let mut conditional_decision = decision.clone();
    conditional_decision.applicability_expr =
        ApplicabilityExpr::Constraint(ConstraintExpr::Exists {
            field: ConstraintField::AgentKind,
        });
    assert!(conditional_decision.validate().is_ok());
    assert!(matches!(
        gate.evaluate(
            SparseAtomSignal::AdoptedDecision(decision_materialization),
            &[conditional_decision],
        )
        .unwrap(),
        AtomEmissionDecision::Atom(_)
    ));
}

#[test]
fn resolvers_preserve_normative_shadow_and_descriptive_conflict() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let (receipt, observation) = user_source(
        "resolver",
        "Use the task-specific constraint.",
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let policy_fixture = verified_policy_source(
        "resolver-policy",
        "Use the task-specific constraint.",
        &scope,
        MaxHostResolvedScope::Repository,
    );
    let mut policy_draft = draft(
        AtomScope::Repository {
            repository_instance_id: scope.repository.repository_id,
        },
        AtomKind::Constraint,
        EpistemicStatus::NotApplicable,
        &policy_fixture.observation,
        &policy_fixture.receipt,
    );
    policy_draft
        .evidence_refs
        .push(policy_fixture.observation.source_observation_id.to_string());
    policy_draft.evidence_refs.sort();
    policy_draft.provenance = vec![AtomProvenance::ObservedHost];
    policy_draft.value.subject = "current_task".into();
    policy_draft.value.predicate = "must_follow_user_message".into();
    policy_draft.value.object = None;
    policy_draft.value.qualifiers.clear();
    let mut policy_decision_draft = policy_draft.clone();
    policy_decision_draft.kind = AtomKind::Decision;
    let policy = materialize_atom(
        AtomMaterialization {
            draft: policy_draft,
            authority_basis: AtomAuthorityBasis::ProjectPolicy {
                binding: policy_fixture.binding.clone(),
                observation: Box::new(policy_fixture.observation.clone()),
                receipt: Box::new(policy_fixture.receipt.clone()),
            },
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 2,
        },
        None,
    )
    .unwrap();
    let policy_decision = materialize_atom(
        AtomMaterialization {
            draft: policy_decision_draft,
            authority_basis: AtomAuthorityBasis::ProjectPolicy {
                binding: policy_fixture.binding.clone(),
                observation: Box::new(policy_fixture.observation.clone()),
                receipt: Box::new(policy_fixture.receipt.clone()),
            },
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 2,
        },
        None,
    )
    .unwrap();
    let exact_draft = exact_task_constraint_draft(
        "Use the task-specific constraint.".into(),
        scope.task.task_id,
        observation.source_observation_id,
        receipt.source_receipt_id,
        1,
        90,
    );
    let exact = materialize_atom(
        AtomMaterialization {
            draft: exact_draft,
            authority_basis: AtomAuthorityBasis::CurrentTaskExactMessage {
                observation: Box::new(observation.clone()),
                receipt: Box::new(receipt.clone()),
                canonical_message: "Use the task-specific constraint.".into(),
            },
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 2,
        },
        None,
    )
    .unwrap();
    let context = ResolverContext {
        task_id: Some(scope.task.task_id),
        repository_instance_id: Some(scope.repository.repository_id),
        worktree_instance_id: Some(scope.worktree.worktree_instance_id),
        now_us: 10,
        current_policy_bindings: BTreeSet::from([policy_fixture.binding.clone()]),
        ..ResolverContext::default()
    };
    let normative = NormativeInstructionResolver
        .resolve(&[policy.clone(), exact.clone(), policy_decision], &context);
    assert_eq!(normative[0].state, NormativeResolutionState::Shadowed);
    assert_eq!(normative[1].state, NormativeResolutionState::Active);
    assert_eq!(normative[2].state, NormativeResolutionState::Active);
    let mut changed_policy_context = context.clone();
    let changed_policy = verified_policy_source(
        "resolver-changed",
        "Use the changed policy constraint.",
        &scope,
        MaxHostResolvedScope::Repository,
    );
    changed_policy_context.current_policy_bindings = BTreeSet::from([changed_policy.binding]);
    assert_eq!(
        NormativeInstructionResolver
            .resolve(std::slice::from_ref(&policy), &changed_policy_context,)[0]
            .state,
        NormativeResolutionState::SupportUnavailable
    );
    let mut stale_context = context.clone();
    stale_context.current_policy_bindings.clear();
    assert_eq!(
        NormativeInstructionResolver.resolve(std::slice::from_ref(&policy), &stale_context)[0]
            .state,
        NormativeResolutionState::SupportUnavailable
    );
    let mut unknown = policy;
    unknown.revision_id = RevisionId::new_v7();
    unknown.parent_revision_id = None;
    unknown.applicability_expr = ApplicabilityExpr::Constraint(ConstraintExpr::Eq {
        field: ConstraintField::FailureSignature,
        value: ConstraintValue::Text("failure".into()),
    });
    assert_eq!(
        NormativeInstructionResolver.resolve(&[unknown], &context)[0].state,
        NormativeResolutionState::ApplicabilityUnknown
    );

    let mut left_draft = draft(
        AtomScope::Task {
            task_id: scope.task.task_id,
        },
        AtomKind::Fact,
        EpistemicStatus::Supported,
        &observation,
        &receipt,
    );
    left_draft.provenance = vec![AtomProvenance::ObservedExec];
    let left = materialize_atom(
        AtomMaterialization {
            draft: left_draft,
            authority_basis: AtomAuthorityBasis::ObjectiveEvidence,
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 2,
        },
        None,
    )
    .unwrap();
    let mut right_draft = draft(
        AtomScope::Task {
            task_id: scope.task.task_id,
        },
        AtomKind::Fact,
        EpistemicStatus::Supported,
        &observation,
        &receipt,
    );
    right_draft.value.text = "opposite semantic value".into();
    right_draft.provenance = vec![AtomProvenance::ObservedExec];
    right_draft.contradicts_revision_refs = vec![left.revision_id];
    let right = materialize_atom(
        AtomMaterialization {
            draft: right_draft,
            authority_basis: AtomAuthorityBasis::ObjectiveEvidence,
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 3,
        },
        None,
    )
    .unwrap();
    let descriptive = DescriptiveFactResolver.resolve(&[left, right], &context);
    assert!(
        descriptive
            .iter()
            .all(|result| result.state == DescriptiveResolutionState::Disputed)
    );
}

#[test]
fn project_policy_requires_the_exact_current_host_probe_surface() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let verified = verified_policy_source(
        "policy-gate",
        "repository policy body",
        &scope,
        MaxHostResolvedScope::Repository,
    );
    assert!(
        CurrentPolicyBinding::from_verified_host_probe(
            &verified.report,
            &verified.evidence,
            verified.provenance.clone(),
            &verified.observation,
            &verified.receipt,
        )
        .is_ok()
    );
    for evidence_source in [
        ProbeEvidenceSourceKind::SyntheticFixture,
        ProbeEvidenceSourceKind::OfficialCodexHookContract,
        ProbeEvidenceSourceKind::NoHostEvidence,
    ] {
        let mut context = verified.context.clone();
        context.evidence_source = evidence_source;
        let report = HostProbeReport::evaluate(
            &context,
            &ProbeEvidence {
                policy: Some(verified.evidence.clone()),
                ..ProbeEvidence::empty()
            },
        )
        .unwrap();
        let mut provenance = verified.provenance.clone();
        provenance.adapter_manifest_id = report.manifest().adapter_manifest_id.clone();
        let mut receipt = verified.receipt.clone();
        receipt.adapter_manifest_ref = report.manifest().adapter_manifest_id.clone();
        let mut observation = verified.observation.clone();
        observation.correlation.adapter_manifest_ref =
            report.manifest().adapter_manifest_id.clone();
        assert!(
            CurrentPolicyBinding::from_verified_host_probe(
                &report,
                &verified.evidence,
                provenance,
                &observation,
                &receipt,
            )
            .is_err()
        );
    }
    let mut changed_declared_scope = verified.evidence.clone();
    changed_declared_scope.resolved_scope = Some(MaxHostResolvedScope::Worktree);
    assert!(
        verified
            .report
            .verify_project_policy_evidence(&changed_declared_scope)
            .is_err()
    );

    for origin in [
        PolicyCandidateOrigin::RepositoryTrust,
        PolicyCandidateOrigin::Readme,
        PolicyCandidateOrigin::Agents,
        PolicyCandidateOrigin::OrdinaryText,
    ] {
        let mut candidate = verified.clone();
        candidate.evidence.origin = origin;
        assert!(
            CurrentPolicyBinding::from_verified_host_probe(
                &candidate.report,
                &candidate.evidence,
                candidate.provenance,
                &candidate.observation,
                &candidate.receipt,
            )
            .is_err()
        );
    }
    for mutate in [
        |evidence: &mut PolicyEvidence| evidence.host_loaded = false,
        |evidence: &mut PolicyEvidence| evidence.readback_matches = false,
        |evidence: &mut PolicyEvidence| evidence.current_trust = false,
        |evidence: &mut PolicyEvidence| evidence.current = false,
        |evidence: &mut PolicyEvidence| evidence.revoked = true,
    ] {
        let mut candidate = verified.clone();
        mutate(&mut candidate.evidence);
        assert!(
            CurrentPolicyBinding::from_verified_host_probe(
                &candidate.report,
                &candidate.evidence,
                candidate.provenance,
                &candidate.observation,
                &candidate.receipt,
            )
            .is_err()
        );
    }

    let mut ordinary_tool = verified.clone();
    ordinary_tool.observation.source_role = SourceRole::Tool;
    ordinary_tool.observation.observation_role = ObservationRole::Result;
    ordinary_tool.observation.correlation.pairing_role = ObservationRole::Result;
    ordinary_tool.receipt.observation_role = ObservationRole::Result;
    assert!(
        CurrentPolicyBinding::from_verified_host_probe(
            &ordinary_tool.report,
            &ordinary_tool.evidence,
            ordinary_tool.provenance,
            &ordinary_tool.observation,
            &ordinary_tool.receipt,
        )
        .is_err()
    );

    let mut wrong_manifest = verified.clone();
    wrong_manifest.receipt.adapter_manifest_ref = "different-manifest".into();
    assert!(
        CurrentPolicyBinding::from_verified_host_probe(
            &wrong_manifest.report,
            &wrong_manifest.evidence,
            wrong_manifest.provenance,
            &wrong_manifest.observation,
            &wrong_manifest.receipt,
        )
        .is_err()
    );
    let mut wrong_kind = verified.clone();
    wrong_kind.provenance.policy_source_kind = "different_policy_kind".into();
    assert!(
        CurrentPolicyBinding::from_verified_host_probe(
            &wrong_kind.report,
            &wrong_kind.evidence,
            wrong_kind.provenance,
            &wrong_kind.observation,
            &wrong_kind.receipt,
        )
        .is_err()
    );
    let mut wrong_digest = verified.clone();
    wrong_digest.provenance.policy_content_hash[0] ^= 0xff;
    assert!(
        CurrentPolicyBinding::from_verified_host_probe(
            &wrong_digest.report,
            &wrong_digest.evidence,
            wrong_digest.provenance,
            &wrong_digest.observation,
            &wrong_digest.receipt,
        )
        .is_err()
    );
    let mut missing_readback_ref = verified.clone();
    missing_readback_ref.evidence.evidence_refs = vec![
        missing_readback_ref
            .observation
            .source_observation_id
            .to_string(),
    ];
    assert!(
        CurrentPolicyBinding::from_verified_host_probe(
            &missing_readback_ref.report,
            &missing_readback_ref.evidence,
            missing_readback_ref.provenance,
            &missing_readback_ref.observation,
            &missing_readback_ref.receipt,
        )
        .is_err()
    );

    let mut overwide = verified_policy_source(
        "policy-worktree",
        "worktree-only policy body",
        &scope,
        MaxHostResolvedScope::Worktree,
    );
    overwide.provenance.host_resolved_scope = PolicyHostScope::Repository {
        repository_instance_id: scope.repository.repository_id,
    };
    assert!(
        CurrentPolicyBinding::from_verified_host_probe(
            &overwide.report,
            &overwide.evidence,
            overwide.provenance,
            &overwide.observation,
            &overwide.receipt,
        )
        .is_err()
    );
}

#[tokio::test]
async fn store_rechecks_persisted_project_policy_evidence() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let verified = verified_policy_source(
        "policy-store",
        "durable repository policy",
        &scope,
        MaxHostResolvedScope::Repository,
    );
    let store_root = temp.path().join("store");
    let mut writer = initialized_writer(
        &store_root,
        &scope,
        &verified.receipt,
        &verified.observation,
    )
    .await;
    let mut policy_draft = draft(
        AtomScope::Repository {
            repository_instance_id: scope.repository.repository_id,
        },
        AtomKind::Constraint,
        EpistemicStatus::NotApplicable,
        &verified.observation,
        &verified.receipt,
    );
    policy_draft.provenance = vec![AtomProvenance::ObservedHost];
    policy_draft
        .evidence_refs
        .push(verified.observation.source_observation_id.to_string());
    policy_draft.evidence_refs.sort();
    let policy_atom = materialize_atom(
        AtomMaterialization {
            draft: policy_draft,
            authority_basis: AtomAuthorityBasis::ProjectPolicy {
                binding: verified.binding.clone(),
                observation: Box::new(verified.observation.clone()),
                receipt: Box::new(verified.receipt.clone()),
            },
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 2,
        },
        None,
    )
    .unwrap();

    let before = writer.journal_rows().await.unwrap().len();
    let mut wrong_digest = policy_atom.clone();
    wrong_digest
        .policy_authority_provenance
        .as_mut()
        .unwrap()
        .policy_content_hash[0] ^= 0xff;
    assert!(
        writer
            .commit(
                &command(
                    2,
                    vec![JournalPayload::AtomRecorded(Box::new(wrong_digest))],
                ),
                2,
            )
            .await
            .is_err()
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), before);

    let (mut tool_receipt, mut tool_observation) = user_source(
        "ordinary-policy-tool",
        "ordinary tool output",
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    tool_observation.source_role = SourceRole::Tool;
    tool_observation.content_trust = ContentTrust::Observed;
    tool_observation.observation_role = ObservationRole::Result;
    tool_observation.correlation.pairing_role = ObservationRole::Result;
    tool_receipt.observation_role = ObservationRole::Result;
    persist_source(&mut writer, &tool_receipt, &tool_observation, 3).await;
    let mut ordinary_tool = policy_atom.clone();
    ordinary_tool.source_observation_refs = vec![tool_observation.source_observation_id];
    ordinary_tool.evidence_refs = vec![
        tool_receipt.source_receipt_id.to_string(),
        tool_observation.source_observation_id.to_string(),
    ];
    ordinary_tool.evidence_refs.sort();
    let forged_policy = ordinary_tool.policy_authority_provenance.as_mut().unwrap();
    forged_policy.policy_source_kind = tool_receipt.source_ref.clone();
    forged_policy.policy_source_revision_ref = tool_observation.source_revision.as_str().into();
    forged_policy.policy_content_hash = payload_fingerprint(
        tool_observation.canonicalization_revision,
        b"ordinary tool output",
        None,
    )
    .unwrap();
    forged_policy.adapter_manifest_id = tool_receipt.adapter_manifest_ref.clone();
    let before_tool_forge = writer.journal_rows().await.unwrap().len();
    assert!(
        writer
            .commit(
                &command(
                    4,
                    vec![JournalPayload::AtomRecorded(Box::new(ordinary_tool))],
                ),
                4,
            )
            .await
            .is_err()
    );
    assert_eq!(
        writer.journal_rows().await.unwrap().len(),
        before_tool_forge
    );

    writer
        .commit(
            &command(
                5,
                vec![JournalPayload::AtomRecorded(Box::new(policy_atom.clone()))],
            ),
            5,
        )
        .await
        .unwrap();
    let snapshot = writer.project().await.unwrap();
    assert_eq!(snapshot, writer.full_projection().await.unwrap());
    drop(writer);
    let restarted = JournalWriter::open(&store_root).await.unwrap();
    let restored = SemanticCurrentView::from_snapshot(&restarted.project().await.unwrap()).unwrap();
    assert_eq!(restored.atoms[&policy_atom.atom_id], policy_atom);
}

#[test]
fn atom_successors_cannot_expand_scope_or_resurrect_terminal_state() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let (receipt, observation) = user_source(
        "successor",
        "semantic value",
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let base = materialize_atom(
        AtomMaterialization {
            draft: draft(
                AtomScope::Task {
                    task_id: scope.task.task_id,
                },
                AtomKind::Fact,
                EpistemicStatus::Unverified,
                &observation,
                &receipt,
            ),
            authority_basis: AtomAuthorityBasis::AgentInferred,
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 2,
        },
        None,
    )
    .unwrap();
    let mut expanded = base.clone();
    expanded.revision_id = RevisionId::new_v7();
    expanded.parent_revision_id = Some(base.revision_id);
    expanded.scope = AtomScope::Global;
    expanded.created_at_us = 3;
    assert!(base.validate_successor(&expanded).is_err());
    let mut supported = draft(
        base.scope.clone(),
        AtomKind::Fact,
        EpistemicStatus::Supported,
        &observation,
        &receipt,
    );
    supported.provenance = vec![AtomProvenance::ObservedExec];
    let promoted = materialize_atom(
        AtomMaterialization {
            draft: supported,
            authority_basis: AtomAuthorityBasis::ObjectiveEvidence,
            accepted_proposal_id: Some(RevisionProposalId::new_v7()),
            accepted_proposal_revision_id: Some(RevisionId::new_v7()),
            created_at_us: 3,
        },
        Some(&base),
    )
    .unwrap();
    assert_eq!(promoted.parent_revision_id, Some(base.revision_id));
    assert_eq!(promoted.authority, AtomAuthority::ObjectiveEvidence);
    let mut terminal = base.clone();
    terminal.lifecycle_status = AtomLifecycleStatus::Deprecated;
    let mut resurrected = terminal.clone();
    resurrected.revision_id = RevisionId::new_v7();
    resurrected.parent_revision_id = Some(terminal.revision_id);
    resurrected.lifecycle_status = AtomLifecycleStatus::Active;
    resurrected.created_at_us = 4;
    assert!(terminal.validate_successor(&resurrected).is_err());
}

#[test]
fn proposal_submit_dedupes_and_terminal_or_stale_transitions_fail_closed() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let (receipt, observation) = user_source(
        "proposal",
        "semantic value",
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let request = SubmitProposalRequest {
        target_kind: ProposalTargetKind::Atom,
        target_id: None,
        base_revision_id: None,
        operation: ProposalOperation::Create,
        payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
            draft: draft(
                AtomScope::Task {
                    task_id: scope.task.task_id,
                },
                AtomKind::Annotation,
                EpistemicStatus::Unverified,
                &observation,
                &receipt,
            ),
        })),
        evidence_refs: vec![receipt.source_receipt_id.to_string()],
        source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::Agent,
    };
    let service = RevisionProposalService;
    let ProposalResolution::Revision { value: first, .. } = service
        .submit(
            &SemanticCurrentView::default(),
            command_context(2),
            request.clone(),
        )
        .unwrap()
    else {
        panic!("first submission must persist");
    };
    let mut view = SemanticCurrentView::default();
    view.proposals.insert(first.proposal_id, (*first).clone());
    let mut meaningless_successor = (*first).clone();
    meaningless_successor.proposal_revision_id = RevisionId::new_v7();
    meaningless_successor.parent_proposal_revision_id = Some(first.proposal_revision_id);
    meaningless_successor.created_at_us = 3;
    assert!(first.validate_successor(&meaningless_successor).is_err());
    assert!(matches!(
        service
            .submit(&view, command_context(3), request.clone())
            .unwrap(),
        ProposalResolution::NoDelta
    ));
    let mut new_evidence = request;
    new_evidence
        .evidence_refs
        .push(observation.source_observation_id.to_string());
    let ProposalResolution::Revision {
        value: successor, ..
    } = service
        .submit(&view, command_context(4), new_evidence)
        .unwrap()
    else {
        panic!("new evidence must revise the same proposal");
    };
    assert_eq!(successor.proposal_id, first.proposal_id);
    assert_eq!(
        successor.parent_proposal_revision_id,
        Some(first.proposal_revision_id)
    );
    let mut validating = (*successor).clone();
    validating.proposal_revision_id = RevisionId::new_v7();
    validating.parent_proposal_revision_id = Some(successor.proposal_revision_id);
    validating.status = ProposalStatus::Validating;
    validating.created_at_us = 5;
    successor.validate_successor(&validating).unwrap();
    let mut validating_with_evidence = validating.clone();
    validating_with_evidence.proposal_revision_id = RevisionId::new_v7();
    validating_with_evidence.parent_proposal_revision_id = Some(validating.proposal_revision_id);
    validating_with_evidence
        .evidence_refs
        .push("obs:2020202020202020202020202020202020202020202020202020202020202020".into());
    validating_with_evidence.evidence_refs.sort();
    validating_with_evidence.created_at_us = 6;
    validating
        .validate_successor(&validating_with_evidence)
        .unwrap();

    view.proposals
        .insert(successor.proposal_id, (*successor).clone());
    let ProposalResolution::Revision {
        value: deferred, ..
    } = service
        .revise_status(
            &view,
            command_context(5),
            successor.proposal_id,
            ProposalStatus::Deferred,
            vec![ProposalWaitingOn::NewEvidence],
            Some("waiting for evidence".into()),
        )
        .unwrap()
    else {
        panic!("defer must create a successor");
    };
    view.proposals
        .insert(deferred.proposal_id, (*deferred).clone());
    let ProposalResolution::Revision { value: resumed, .. } = service
        .resume_deferred(
            &view,
            command_context(6),
            deferred.proposal_id,
            vec!["obs:1919191919191919191919191919191919191919191919191919191919191919".into()],
            None,
        )
        .unwrap()
    else {
        panic!("changed evidence must resume by successor");
    };
    assert_eq!(resumed.status, ProposalStatus::Pending);
    view.proposals
        .insert(resumed.proposal_id, (*resumed).clone());
    let ProposalResolution::Revision {
        value: rejected, ..
    } = service
        .revise_status(
            &view,
            command_context(7),
            resumed.proposal_id,
            ProposalStatus::Rejected,
            vec![],
            Some("not accepted".into()),
        )
        .unwrap()
    else {
        panic!("rejection must be immutable successor state");
    };
    view.proposals
        .insert(rejected.proposal_id, (*rejected).clone());
    assert!(
        service
            .revise_status(
                &view,
                command_context(8),
                rejected.proposal_id,
                ProposalStatus::Validating,
                vec![],
                None,
            )
            .is_err()
    );
    assert!(matches!(
        service
            .submit(
                &view,
                command_context(8),
                SubmitProposalRequest {
                    target_kind: rejected.target_kind,
                    target_id: rejected.target_id,
                    base_revision_id: rejected.base_revision_id,
                    operation: rejected.operation,
                    payload: rejected.payload.clone(),
                    evidence_refs: rejected.evidence_refs.clone(),
                    source_cohort_refs: rejected.source_cohort_refs.clone(),
                    eligibility: rejected.eligibility,
                    created_by: rejected.created_by,
                },
            )
            .unwrap(),
        ProposalResolution::NoDelta
    ));

    let stale = SubmitProposalRequest {
        target_kind: ProposalTargetKind::Atom,
        target_id: Some(ProposalTargetId::Atom(
            evertrace_domain::ids::AtomId::new_v7(),
        )),
        base_revision_id: Some(RevisionId::new_v7()),
        operation: ProposalOperation::Replace,
        payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Replace {
            draft: match &resumed.payload {
                ProposalPayload::Atom(payload) => match payload.as_ref() {
                    AtomProposalPayload::Create { draft } => draft.clone(),
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            },
        })),
        evidence_refs: resumed.evidence_refs.clone(),
        source_cohort_refs: resumed.source_cohort_refs.clone(),
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::Agent,
    };
    assert!(matches!(
        service.submit(&view, command_context(9), stale),
        Err(SemanticServiceError::BaseConflict)
    ));

    let mut payload_json = serde_json::to_value(&resumed.payload).unwrap();
    payload_json
        .as_object_mut()
        .unwrap()
        .insert("authority".into(), serde_json::json!("user_explicit"));
    assert!(serde_json::from_value::<ProposalPayload>(payload_json).is_err());
}

#[tokio::test]
async fn store_enforces_one_unfinished_proposal_per_fingerprint() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let (receipt, observation) = user_source(
        "proposal-uniqueness",
        "proposal evidence",
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let store_root = temp.path().join("store");
    let mut writer = initialized_writer(&store_root, &scope, &receipt, &observation).await;
    let request = SubmitProposalRequest {
        target_kind: ProposalTargetKind::Atom,
        target_id: None,
        base_revision_id: None,
        operation: ProposalOperation::Create,
        payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
            draft: draft(
                AtomScope::Task {
                    task_id: scope.task.task_id,
                },
                AtomKind::Annotation,
                EpistemicStatus::Unverified,
                &observation,
                &receipt,
            ),
        })),
        evidence_refs: vec![receipt.source_receipt_id.to_string()],
        source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::Agent,
    };
    let service = RevisionProposalService;
    let stale_view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: first,
        command: first_command,
    } = service
        .submit(&stale_view, command_context(2), request.clone())
        .unwrap()
    else {
        panic!("first root must persist");
    };
    let ProposalResolution::Revision {
        value: second,
        command: stale_second_command,
    } = service
        .submit(&stale_view, command_context(2), request.clone())
        .unwrap()
    else {
        panic!("the stale caller cannot yet see the first root");
    };
    assert_ne!(first.proposal_id, second.proposal_id);
    assert_eq!(first.fingerprint, second.fingerprint);
    writer.commit(&first_command, 2).await.unwrap();
    let after_first = writer.journal_rows().await.unwrap().len();
    assert!(writer.commit(&stale_second_command, 2).await.is_err());
    assert_eq!(writer.journal_rows().await.unwrap().len(), after_first);

    let current = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let ProposalResolution::Revision {
        value: deferred,
        command: defer_command,
    } = service
        .revise_status(
            &current,
            command_context(3),
            first.proposal_id,
            ProposalStatus::Deferred,
            vec![ProposalWaitingOn::NewEvidence],
            Some("awaiting_new_evidence".into()),
        )
        .unwrap()
    else {
        panic!("proposal must defer");
    };
    writer.commit(&defer_command, 3).await.unwrap();
    let deferred_view =
        SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert!(matches!(
        service
            .submit(&deferred_view, command_context(4), request)
            .unwrap(),
        ProposalResolution::NoDelta
    ));

    let ProposalResolution::Revision {
        value: resumed,
        command: resume_command,
    } = service
        .resume_deferred(
            &deferred_view,
            command_context(5),
            deferred.proposal_id,
            vec![observation.source_observation_id.to_string()],
            None,
        )
        .unwrap()
    else {
        panic!("new evidence must explicitly resume the same logical proposal");
    };
    assert_eq!(resumed.proposal_id, deferred.proposal_id);
    assert_eq!(
        resumed.parent_proposal_revision_id,
        Some(deferred.proposal_revision_id)
    );
    writer.commit(&resume_command, 5).await.unwrap();
    let final_view = SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    assert_eq!(final_view.proposals.len(), 1);
    assert_eq!(
        final_view.proposals[&first.proposal_id].status,
        ProposalStatus::Pending
    );
}

#[tokio::test]
async fn task_and_repository_acceptance_are_atomic_restart_safe_and_four_table_only() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let message = "Honor the exact current task instruction.";
    let (receipt, observation) = user_source(
        "store",
        message,
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let store_root = temp.path().join("store");
    let mut writer = initialized_writer(&store_root, &scope, &receipt, &observation).await;

    let service = RevisionProposalService;
    let task_request = SubmitProposalRequest {
        target_kind: ProposalTargetKind::Atom,
        target_id: None,
        base_revision_id: None,
        operation: ProposalOperation::Create,
        payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
            draft: exact_task_constraint_draft(
                message.into(),
                scope.task.task_id,
                observation.source_observation_id,
                receipt.source_receipt_id,
                1,
                90,
            ),
        })),
        evidence_refs: vec![receipt.source_receipt_id.to_string()],
        source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::Agent,
    };
    let initial = writer.project().await.unwrap();
    let initial_view = SemanticCurrentView::from_snapshot(&initial).unwrap();
    let ProposalResolution::Revision {
        value: task_proposal,
        command: submit_command,
    } = service
        .submit(&initial_view, command_context(2), task_request.clone())
        .unwrap()
    else {
        panic!("submission must persist");
    };
    let ProposalResolution::Revision {
        value: stale_task_proposal,
        command: stale_task_submit,
    } = service
        .submit(&initial_view, command_context(4), task_request.clone())
        .unwrap()
    else {
        panic!("the stale view must construct a distinct root");
    };
    assert_ne!(task_proposal.proposal_id, stale_task_proposal.proposal_id);
    assert_eq!(task_proposal.fingerprint, stale_task_proposal.fingerprint);
    writer.commit(&submit_command, 2).await.unwrap();
    let submitted = writer.project().await.unwrap();
    let accepted = service
        .accept(
            &SemanticCurrentView::from_snapshot(&submitted).unwrap(),
            command_context(3),
            task_proposal.proposal_id,
            AtomAcceptanceContext::CurrentTaskExactMessage {
                observation: Box::new(observation.clone()),
                receipt: Box::new(receipt.clone()),
                canonical_message: message.into(),
            },
        )
        .unwrap();
    let mut forged_payloads = accepted
        .command
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    for payload in &mut forged_payloads {
        if let JournalPayload::RevisionProposalRecorded(proposal) = payload
            && proposal.status == ProposalStatus::Accepted
        {
            proposal.acceptance.as_mut().unwrap().authority_basis =
                ProposalAcceptanceAuthority::ObjectiveEvidence {
                    user_source_observation_ref: observation.source_observation_id,
                };
        }
    }
    let before_forge = writer.journal_rows().await.unwrap().len();
    assert!(
        writer
            .commit(&command(3, forged_payloads), 3)
            .await
            .is_err()
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), before_forge);
    let mut forged_text_payloads = accepted
        .command
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    let mut forged_structure_hash = None;
    for payload in &mut forged_text_payloads {
        if let JournalPayload::AtomRecorded(atom) = payload {
            atom.value.text = "forged narrowed instruction".into();
            atom.user_authorization_provenance
                .as_mut()
                .unwrap()
                .exact_value_hash = atom.value.exact_hash().unwrap();
            forged_structure_hash = Some(atom.semantic_structure_hash().unwrap());
        }
    }
    for payload in &mut forged_text_payloads {
        if let JournalPayload::RevisionProposalRecorded(proposal) = payload
            && proposal.status == ProposalStatus::Accepted
        {
            let evertrace_domain::semantic::AcceptedProposalTarget::Atom { structure_hash, .. } =
                &mut proposal.acceptance.as_mut().unwrap().accepted_target
            else {
                panic!("expected atom acceptance")
            };
            *structure_hash = forged_structure_hash.unwrap();
        }
    }
    assert!(
        writer
            .commit(&command(3, forged_text_payloads), 3)
            .await
            .is_err()
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), before_forge);
    writer.commit(&accepted.command, 3).await.unwrap();

    let task_snapshot = writer.project().await.unwrap();
    let task_view = SemanticCurrentView::from_snapshot(&task_snapshot).unwrap();
    assert_eq!(task_view.atoms[&accepted.atom.atom_id], *accepted.atom);
    assert_eq!(
        task_view.proposals[&task_proposal.proposal_id].status,
        ProposalStatus::Accepted
    );
    assert_eq!(task_snapshot, writer.full_projection().await.unwrap());
    assert!(matches!(
        service
            .submit(&task_view, command_context(4), task_request.clone())
            .unwrap(),
        ProposalResolution::NoDelta
    ));
    let mut changed_payload = task_request.clone();
    let ProposalPayload::Atom(payload) = &mut changed_payload.payload else {
        unreachable!()
    };
    let AtomProposalPayload::Create {
        draft: changed_draft,
    } = payload.as_mut()
    else {
        unreachable!()
    };
    changed_draft.value.text = "A materially different candidate.".into();
    assert!(matches!(
        service
            .submit(&task_view, command_context(4), changed_payload)
            .unwrap(),
        ProposalResolution::Revision { .. }
    ));
    let mut changed_cohort = task_request.clone();
    changed_cohort
        .source_cohort_refs
        .push("cohort:additional".into());
    assert!(matches!(
        service
            .submit(&task_view, command_context(4), changed_cohort)
            .unwrap(),
        ProposalResolution::Revision { .. }
    ));
    let before_stale_append = writer.journal_rows().await.unwrap().len();
    let before_stale_snapshot = writer.project().await.unwrap();
    assert!(writer.commit(&stale_task_submit, 4).await.is_err());
    assert_eq!(
        writer.journal_rows().await.unwrap().len(),
        before_stale_append
    );
    assert_eq!(writer.project().await.unwrap(), before_stale_snapshot);
    let accepted_draft = match &task_proposal.payload {
        ProposalPayload::Atom(payload) => match payload.as_ref() {
            AtomProposalPayload::Create { draft } => draft.clone(),
            _ => unreachable!(),
        },
        _ => unreachable!(),
    };
    assert!(matches!(
        service.submit(
            &task_view,
            command_context(4),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: Some(ProposalTargetId::Atom(accepted.atom.atom_id)),
                base_revision_id: Some(accepted.atom.revision_id),
                operation: ProposalOperation::Replace,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                    draft: accepted_draft,
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        ),
        Err(SemanticServiceError::InvalidInput)
    ));

    let repository_request = SubmitProposalRequest {
        target_kind: ProposalTargetKind::Atom,
        target_id: None,
        base_revision_id: None,
        operation: ProposalOperation::Create,
        payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
            draft: draft(
                AtomScope::Repository {
                    repository_instance_id: scope.repository.repository_id,
                },
                AtomKind::Constraint,
                EpistemicStatus::NotApplicable,
                &observation,
                &receipt,
            ),
        })),
        evidence_refs: vec![receipt.source_receipt_id.to_string()],
        source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::Agent,
    };
    let ProposalResolution::Revision {
        value: repository_proposal,
        command: repository_submit,
    } = service
        .submit(&task_view, command_context(4), repository_request)
        .unwrap()
    else {
        panic!("repository proposal must persist");
    };
    writer.commit(&repository_submit, 4).await.unwrap();
    let (tui_receipt, tui_observation) =
        tui_acceptance_source("repository-tui", &repository_proposal, &scope);
    persist_source(&mut writer, &tui_receipt, &tui_observation, 5).await;
    let repository_submitted = writer.project().await.unwrap();
    let repository_accepted = service
        .accept(
            &SemanticCurrentView::from_snapshot(&repository_submitted).unwrap(),
            command_context(6),
            repository_proposal.proposal_id,
            AtomAcceptanceContext::RepositoryTui {
                observation: Box::new(tui_observation.clone()),
                receipt: Box::new(tui_receipt.clone()),
            },
        )
        .unwrap();
    let before_tui_forge = writer.journal_rows().await.unwrap().len();
    let mut wrong_reviewed_revision = repository_accepted
        .command
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    for payload in &mut wrong_reviewed_revision {
        if let JournalPayload::RevisionProposalRecorded(proposal) = payload
            && proposal.status == ProposalStatus::Accepted
        {
            proposal
                .acceptance
                .as_mut()
                .unwrap()
                .reviewed_proposal_revision_id = RevisionId::new_v7();
        }
    }
    assert!(
        writer
            .commit(&command(6, wrong_reviewed_revision), 6)
            .await
            .is_err()
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), before_tui_forge);

    let mut wrong_reviewed_fingerprint = repository_accepted
        .command
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    for payload in &mut wrong_reviewed_fingerprint {
        if let JournalPayload::RevisionProposalRecorded(proposal) = payload
            && proposal.status == ProposalStatus::Accepted
        {
            proposal.acceptance.as_mut().unwrap().reviewed_fingerprint[0] ^= 0xff;
        }
    }
    assert!(
        writer
            .commit(&command(6, wrong_reviewed_fingerprint), 6)
            .await
            .is_err()
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), before_tui_forge);

    let mut ordinary_message_forge = repository_accepted
        .command
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    let ordinary_message_hash = payload_fingerprint(1, message.as_bytes(), None).unwrap();
    let mut forged_atom_hash = None;
    for payload in &mut ordinary_message_forge {
        if let JournalPayload::AtomRecorded(atom) = payload {
            atom.source_observation_refs
                .retain(|id| *id != tui_observation.source_observation_id);
            let user = atom.user_authorization_provenance.as_mut().unwrap();
            user.user_source_observation_ref = observation.source_observation_id;
            user.source_message_hash = ordinary_message_hash;
            user.acceptance_event_ref = Some(observation.source_observation_id.to_string());
            forged_atom_hash = Some(atom.semantic_structure_hash().unwrap());
        }
    }
    for payload in &mut ordinary_message_forge {
        if let JournalPayload::RevisionProposalRecorded(proposal) = payload
            && proposal.status == ProposalStatus::Accepted
        {
            let acceptance = proposal.acceptance.as_mut().unwrap();
            acceptance.acceptance_event_ref = observation.source_observation_id.to_string();
            acceptance.reviewer_identity =
                format!("user_source:{}", observation.source_observation_id);
            acceptance.authority_basis = ProposalAcceptanceAuthority::TuiAcceptance {
                user_source_observation_ref: observation.source_observation_id,
                authorized_scope_ceiling: AtomScope::Repository {
                    repository_instance_id: scope.repository.repository_id,
                },
            };
            let evertrace_domain::semantic::AcceptedProposalTarget::Atom { structure_hash, .. } =
                &mut acceptance.accepted_target
            else {
                panic!("expected atom acceptance")
            };
            *structure_hash = forged_atom_hash.unwrap();
        }
    }
    assert!(
        writer
            .commit(&command(6, ordinary_message_forge), 6)
            .await
            .is_err()
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), before_tui_forge);
    writer
        .commit(&repository_accepted.command, 6)
        .await
        .unwrap();
    let final_snapshot = writer.project().await.unwrap();
    assert_eq!(final_snapshot, writer.full_projection().await.unwrap());
    let before_no_delta = writer.journal_rows().await.unwrap().len();
    assert_eq!(writer.project().await.unwrap(), final_snapshot);
    assert_eq!(writer.journal_rows().await.unwrap().len(), before_no_delta);
    assert_eq!(
        writer.table_names().await.unwrap(),
        vec![
            "evertrace_journal",
            "evertrace_objects",
            "evertrace_relations",
            "evertrace_search",
        ]
    );

    let atoms = SemanticCurrentView::from_snapshot(&final_snapshot).unwrap();
    assert_eq!(atoms.atoms.len(), 2);
    let relation_rows = build_semantic_relation_rows(
        &atoms.atom_revisions.values().cloned().collect::<Vec<_>>(),
        &atoms
            .proposal_revisions
            .values()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(!relation_rows.is_empty());
    assert!(
        relation_rows
            .iter()
            .any(|row| row.kind == SemanticRelationKind::ProposalReviewedRevision)
    );

    let journal_before_forge = writer.journal_rows().await.unwrap().len();
    let forged = command(
        7,
        vec![JournalPayload::RevisionProposalRecorded(
            repository_accepted.proposal.clone(),
        )],
    );
    assert!(writer.commit(&forged, 7).await.is_err());
    assert_eq!(
        writer.journal_rows().await.unwrap().len(),
        journal_before_forge
    );
    drop(writer);
    let restarted = JournalWriter::open(&store_root).await.unwrap();
    let restarted_snapshot = restarted.project().await.unwrap();
    assert_eq!(restarted_snapshot, final_snapshot);
    assert_eq!(restarted.full_projection().await.unwrap(), final_snapshot);
    assert!(matches!(
        service
            .submit(
                &SemanticCurrentView::from_snapshot(&restarted_snapshot).unwrap(),
                command_context(8),
                task_request,
            )
            .unwrap(),
        ProposalResolution::NoDelta
    ));
}

#[tokio::test]
async fn store_rejects_objective_authority_without_objective_evidence() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let (receipt, observation) = user_source(
        "objective-forge",
        "semantic value",
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let store_root = temp.path().join("store");
    let mut writer = initialized_writer(&store_root, &scope, &receipt, &observation).await;
    let mut unsupported = draft(
        AtomScope::Task {
            task_id: scope.task.task_id,
        },
        AtomKind::Fact,
        EpistemicStatus::Supported,
        &observation,
        &receipt,
    );
    unsupported.provenance = vec![AtomProvenance::ObservedExec];
    let service = RevisionProposalService;
    let ProposalResolution::Revision {
        value: proposal,
        command: submit,
    } = service
        .submit(
            &SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap(),
            command_context(2),
            SubmitProposalRequest {
                target_kind: ProposalTargetKind::Atom,
                target_id: None,
                base_revision_id: None,
                operation: ProposalOperation::Create,
                payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                    draft: unsupported,
                })),
                evidence_refs: vec![receipt.source_receipt_id.to_string()],
                source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
                eligibility: ProposalEligibility::ManualRequired,
                created_by: ProposalCreatedBy::Agent,
            },
        )
        .unwrap()
    else {
        panic!("proposal must enter the durable inbox");
    };
    writer.commit(&submit, 2).await.unwrap();
    let (tui_receipt, tui_observation) =
        tui_acceptance_source("objective-forge-tui", &proposal, &scope);
    persist_source(&mut writer, &tui_receipt, &tui_observation, 3).await;
    let user_acceptance = service
        .accept(
            &SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap(),
            command_context(4),
            proposal.proposal_id,
            AtomAcceptanceContext::TaskTui {
                observation: Box::new(tui_observation.clone()),
                receipt: Box::new(tui_receipt.clone()),
            },
        )
        .unwrap();
    let before = writer.journal_rows().await.unwrap().len();
    assert!(writer.commit(&user_acceptance.command, 4).await.is_err());
    assert_eq!(writer.journal_rows().await.unwrap().len(), before);
    let acceptance = service
        .accept(
            &SemanticCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap(),
            command_context(4),
            proposal.proposal_id,
            AtomAcceptanceContext::ObjectiveEvidence {
                observation: Box::new(tui_observation),
                receipt: Box::new(tui_receipt),
            },
        )
        .unwrap();
    assert!(writer.commit(&acceptance.command, 4).await.is_err());
    assert_eq!(writer.journal_rows().await.unwrap().len(), before);
}

#[test]
fn tui_acceptance_adds_a_distinct_user_event_without_rewriting_candidate_provenance() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let (candidate_receipt, mut candidate_observation) = user_source(
        "agent-candidate",
        "candidate content",
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    candidate_observation.source_role = SourceRole::Tool;
    candidate_observation.content_trust = ContentTrust::Observed;
    let request = SubmitProposalRequest {
        target_kind: ProposalTargetKind::Atom,
        target_id: None,
        base_revision_id: None,
        operation: ProposalOperation::Create,
        payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
            draft: draft(
                AtomScope::Task {
                    task_id: scope.task.task_id,
                },
                AtomKind::Annotation,
                EpistemicStatus::Unverified,
                &candidate_observation,
                &candidate_receipt,
            ),
        })),
        evidence_refs: vec![candidate_receipt.source_receipt_id.to_string()],
        source_cohort_refs: vec![candidate_receipt.source_receipt_id.to_string()],
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::Agent,
    };
    let service = RevisionProposalService;
    let ProposalResolution::Revision { value, .. } = service
        .submit(&SemanticCurrentView::default(), command_context(1), request)
        .unwrap()
    else {
        panic!("candidate must enter the inbox");
    };
    let (acceptance_receipt, acceptance_observation) =
        tui_acceptance_source("tui-acceptance", &value, &scope);
    let mut view = SemanticCurrentView::default();
    view.proposals.insert(value.proposal_id, (*value).clone());
    let accepted = service
        .accept(
            &view,
            command_context(2),
            value.proposal_id,
            AtomAcceptanceContext::TaskTui {
                observation: Box::new(acceptance_observation.clone()),
                receipt: Box::new(acceptance_receipt),
            },
        )
        .unwrap();
    assert!(
        accepted
            .atom
            .source_observation_refs
            .contains(&candidate_observation.source_observation_id)
    );
    assert!(
        accepted
            .atom
            .source_observation_refs
            .contains(&acceptance_observation.source_observation_id)
    );
}

#[test]
fn tui_acceptance_is_bound_to_one_current_proposal_revision() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let (receipt, observation) = user_source(
        "tui-binding-candidate",
        "candidate evidence",
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let request = SubmitProposalRequest {
        target_kind: ProposalTargetKind::Atom,
        target_id: None,
        base_revision_id: None,
        operation: ProposalOperation::Create,
        payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
            draft: draft(
                AtomScope::Task {
                    task_id: scope.task.task_id,
                },
                AtomKind::Annotation,
                EpistemicStatus::Unverified,
                &observation,
                &receipt,
            ),
        })),
        evidence_refs: vec![receipt.source_receipt_id.to_string()],
        source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::Agent,
    };
    let service = RevisionProposalService;
    let ProposalResolution::Revision { value: first, .. } = service
        .submit(
            &SemanticCurrentView::default(),
            command_context(1),
            request.clone(),
        )
        .unwrap()
    else {
        panic!("first proposal must persist");
    };
    let mut second_request = request.clone();
    let ProposalPayload::Atom(second_payload) = &mut second_request.payload else {
        unreachable!()
    };
    let AtomProposalPayload::Create { draft } = second_payload.as_mut() else {
        unreachable!()
    };
    draft.value.text = "different candidate".into();
    let ProposalResolution::Revision { value: second, .. } = service
        .submit(
            &SemanticCurrentView::default(),
            command_context(1),
            second_request,
        )
        .unwrap()
    else {
        panic!("second proposal must persist");
    };
    let mut view = SemanticCurrentView::default();
    view.proposals.insert(first.proposal_id, (*first).clone());
    view.proposals.insert(second.proposal_id, (*second).clone());

    let (ordinary_receipt, ordinary_observation) = user_source(
        "ordinary-accept-message",
        "Accept the reviewed candidate.",
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    assert!(matches!(
        service.accept(
            &view,
            command_context(2),
            first.proposal_id,
            AtomAcceptanceContext::TaskTui {
                observation: Box::new(ordinary_observation),
                receipt: Box::new(ordinary_receipt),
            },
        ),
        Err(SemanticServiceError::InvalidInput)
    ));

    let (first_acceptance_receipt, first_acceptance_observation) =
        tui_acceptance_source("first-tui-binding", &first, &scope);
    assert!(
        service
            .accept(
                &view,
                command_context(2),
                first.proposal_id,
                AtomAcceptanceContext::TaskTui {
                    observation: Box::new(first_acceptance_observation.clone()),
                    receipt: Box::new(first_acceptance_receipt.clone()),
                },
            )
            .is_ok()
    );
    let mut invalid_recorded_time = first_acceptance_receipt.clone();
    invalid_recorded_time.recorded_at_us = 0;
    assert!(matches!(
        service.accept(
            &view,
            command_context(2),
            first.proposal_id,
            AtomAcceptanceContext::TaskTui {
                observation: Box::new(first_acceptance_observation.clone()),
                receipt: Box::new(invalid_recorded_time),
            },
        ),
        Err(SemanticServiceError::InvalidInput)
    ));
    assert!(matches!(
        service.accept(
            &view,
            command_context(2),
            second.proposal_id,
            AtomAcceptanceContext::TaskTui {
                observation: Box::new(first_acceptance_observation.clone()),
                receipt: Box::new(first_acceptance_receipt.clone()),
            },
        ),
        Err(SemanticServiceError::InvalidInput)
    ));

    let mut revised_request = request;
    revised_request
        .evidence_refs
        .push(observation.source_observation_id.to_string());
    let ProposalResolution::Revision { value: revised, .. } = service
        .submit(&view, command_context(3), revised_request)
        .unwrap()
    else {
        panic!("new evidence must revise the first proposal");
    };
    assert_eq!(revised.proposal_id, first.proposal_id);
    view.proposals
        .insert(revised.proposal_id, (*revised).clone());
    assert!(matches!(
        service.accept(
            &view,
            command_context(4),
            revised.proposal_id,
            AtomAcceptanceContext::TaskTui {
                observation: Box::new(first_acceptance_observation),
                receipt: Box::new(first_acceptance_receipt),
            },
        ),
        Err(SemanticServiceError::InvalidInput)
    ));
    let (revised_receipt, revised_observation) =
        tui_acceptance_source("revised-tui-binding", &revised, &scope);
    let accepted = service
        .accept(
            &view,
            command_context(4),
            revised.proposal_id,
            AtomAcceptanceContext::TaskTui {
                observation: Box::new(revised_observation),
                receipt: Box::new(revised_receipt),
            },
        )
        .unwrap();
    assert_eq!(
        accepted
            .proposal
            .acceptance
            .as_ref()
            .unwrap()
            .reviewed_proposal_revision_id,
        revised.proposal_revision_id
    );
}

#[test]
fn worktree_and_global_atom_proposals_remain_manual_but_unacceptable_in_s18() {
    let temp = TempDir::new().unwrap();
    let scope = scope_fixture(temp.path());
    let (receipt, observation) = user_source(
        "scope-boundary",
        "objective semantic value",
        scope.task.task_id,
        scope.repository.repository_id,
        scope.worktree.worktree_instance_id,
    );
    let mut worktree_draft = draft(
        AtomScope::Worktree {
            repository_instance_id: scope.repository.repository_id,
            worktree_instance_id: scope.worktree.worktree_instance_id,
        },
        AtomKind::Fact,
        EpistemicStatus::Supported,
        &observation,
        &receipt,
    );
    worktree_draft.provenance = vec![AtomProvenance::ObservedExec];
    let mut global_draft = worktree_draft.clone();
    global_draft.scope = AtomScope::Global;
    global_draft.applicability_expr = ApplicabilityExpr::Constraint(ConstraintExpr::Exists {
        field: ConstraintField::AgentKind,
    });

    let service = RevisionProposalService;
    for (index, candidate) in [worktree_draft, global_draft].into_iter().enumerate() {
        let request = SubmitProposalRequest {
            target_kind: ProposalTargetKind::Atom,
            target_id: None,
            base_revision_id: None,
            operation: ProposalOperation::Create,
            payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                draft: candidate,
            })),
            evidence_refs: vec![receipt.source_receipt_id.to_string()],
            source_cohort_refs: vec![receipt.source_receipt_id.to_string()],
            eligibility: ProposalEligibility::ManualRequired,
            created_by: ProposalCreatedBy::Agent,
        };
        let ProposalResolution::Revision { value, .. } = service
            .submit(
                &SemanticCurrentView::default(),
                command_context(10 + index as i64),
                request,
            )
            .unwrap()
        else {
            panic!("S18 must preserve the proposal for later owners");
        };
        let mut view = SemanticCurrentView::default();
        view.proposals.insert(value.proposal_id, (*value).clone());
        assert!(matches!(
            service.accept(
                &view,
                command_context(20 + index as i64),
                value.proposal_id,
                AtomAcceptanceContext::ObjectiveEvidence {
                    observation: Box::new(observation.clone()),
                    receipt: Box::new(receipt.clone()),
                },
            ),
            Err(SemanticServiceError::UnsupportedTarget)
        ));
    }
}

#[test]
fn serde_models_reject_unknown_fields_and_reserved_procedure_payloads() {
    let payload = ProposalPayload::ReservedTarget {
        schema_version: 1,
        summary: "future procedure candidate".into(),
    };
    let mut json = serde_json::to_value(&payload).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("reviewer_identity".into(), serde_json::json!("forged"));
    assert!(serde_json::from_value::<ProposalPayload>(json).is_err());
    let request = SubmitProposalRequest {
        target_kind: ProposalTargetKind::Procedure,
        target_id: None,
        base_revision_id: None,
        operation: ProposalOperation::Create,
        payload,
        evidence_refs: vec![
            "src:1818181818181818181818181818181818181818181818181818181818181818".into(),
        ],
        source_cohort_refs: vec![
            "src:1818181818181818181818181818181818181818181818181818181818181818".into(),
        ],
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::Agent,
    };
    let service = RevisionProposalService;
    assert!(matches!(
        service.submit(&SemanticCurrentView::default(), command_context(1), request),
        Err(SemanticServiceError::InvalidInput)
    ));
}
