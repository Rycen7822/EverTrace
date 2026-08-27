use evertrace_domain::{
    evidence::{
        CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
        CorrelationField, CorrelationFieldClaim, EffectRole, EvidenceByteRange, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, PairingState, ScopeEffectClaim,
        SourceArchiveMode, SourceInstanceId, SourceObservation, SourceReceipt,
        SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole, payload_fingerprint,
        source_observation_id, source_receipt_id,
    },
    ids::{
        CommandId, CompetingAttemptGroupId, OperationId, RepositoryId, TaskId,
        WorkBindingRevisionId, WorkstreamId, WorktreeId,
    },
    revision::RevisionId,
    work::{
        AssignmentStatus, PhaseContract, PhaseKind, SecondaryBindingRole, SecondaryBindingTarget,
        SecondaryWorkBinding, Task, TaskIdentityConfidence, TaskLifecycle, TaskScopeMembership,
        WorkBindingRevision, Workstream, WorkstreamStatus,
    },
};
use evertrace_engine::{
    PhysicalNormalizer,
    work::{
        WorkCommandContext,
        binding::{
            BindingEvidence, BindingEvidenceStrength, BindingResolution, record_binding,
            resolve_binding,
        },
        task::create_task,
        workstream::create_workstream,
    },
};
use evertrace_store::{
    CompatibilityStore, DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft,
    JournalPayload, JournalWriter, OBJECTS_TABLE, SourceIngestWatermark, StoreError,
    WorkBindingCurrentView, WorkIdentityCurrentView,
    relations::{WorkBindingRelationKind, build_work_binding_relation_rows},
    repository::RepositoryCurrentView,
};
use tempfile::TempDir;

const CONFIG: [u8; 32] = [0x13; 32];
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn context(at: i64) -> WorkCommandContext {
    WorkCommandContext {
        command_id: CommandId::new_v7(),
        occurred_at_us: at,
        effective_config_hash: CONFIG,
        algorithm_revision: "s13-binding-v1",
    }
}

fn task(confidence: TaskIdentityConfidence, watermark: u64) -> Task {
    Task {
        task_id: TaskId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        request_root_refs: vec![format!("request-{watermark}")],
        canonical_goal: "bind immutable operation".into(),
        scope_memberships: vec![TaskScopeMembership {
            repository_instance_id: None,
            worktree_instance_ids: Vec::new(),
        }],
        identity_confidence: confidence,
        lifecycle: TaskLifecycle::Active,
        continuation_of_task_id: None,
        split_from_task_id: None,
        split_into_task_ids: Vec::new(),
        merged_from_task_ids: Vec::new(),
        merged_into_task_id: None,
        created_at_us: i64::try_from(watermark).unwrap(),
        closed_at_us: None,
        source_watermark: watermark,
    }
}

fn workstream(task_id: TaskId, watermark: u64) -> Workstream {
    Workstream {
        workstream_id: WorkstreamId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        task_id,
        repository_instance_id: None,
        worktree_instance_ids: Vec::new(),
        active_worktree_instance_id: None,
        worktree_lineage_refs: Vec::new(),
        parent_workstream_id: None,
        dependency_workstream_ids: Vec::new(),
        status: WorkstreamStatus::Active,
        root_goal: "bind immutable operation".into(),
        workstream_goal: "implement s13".into(),
        target_family: "work_binding".into(),
        hypothesis_or_failure_family: "semantic_assignment".into(),
        acceptance_boundary: "dedicated proof passes".into(),
        phase_contract: PhaseContract {
            local_goal: "record binding".into(),
            phase_kind: PhaseKind::Implement,
            phase_label: "s13".into(),
            primary_targets: vec!["binding".into()],
            entry_conditions: vec!["s12_complete".into()],
            acceptance_boundary: "binding persisted".into(),
            expected_state_transition: "binding current".into(),
        },
        active_episode_id: None,
        execution_lane_ids: Vec::new(),
        source_watermark: watermark,
    }
}

fn exact_observation() -> (SourceReceipt, SourceObservation) {
    let instance = SourceInstanceId::parse("source-s13").unwrap();
    let revision = SourceRevision::parse("revision-1").unwrap();
    let record = SourceRecordIdentity::parse("record-s13").unwrap();
    let observation_id = source_observation_id(&instance, &revision, &record).unwrap();
    let receipt_id = source_receipt_id(&instance, &revision, &record).unwrap();
    let fields = [
        CorrelationField::HostInstanceId,
        CorrelationField::HostTraceLineageId,
        CorrelationField::HostLaneKey,
        CorrelationField::CanonicalEventFamily,
        CorrelationField::NativeRequestId,
        CorrelationField::PhysicalExecutionOrdinal,
    ];
    let receipt = SourceReceipt {
        source_receipt_id: receipt_id,
        source_observation_id: observation_id,
        source_instance_id: instance.clone(),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        source_ref: "source-ref-s13".into(),
        source_session_ref: "session-s13".into(),
        source_revision: revision.clone(),
        source_record_identity: record.clone(),
        identity_strength: IdentityStrength::StableNative,
        source_sequence: 1,
        source_sequence_origin: None,
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        source_byte_range: None,
        spool_byte_range: EvidenceByteRange { start: 1, end: 2 },
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: Some(1),
        observation_role: ObservationRole::Result,
        unsupported_record_classification: None,
        capture_completeness: CaptureCompleteness::Complete,
        archive_mode: SourceArchiveMode::Exact,
        cas_ref: DIGEST.into(),
        protected_length: 1,
        original_length: 1,
        protected_secret_digest: None,
        redaction_spans: Vec::new(),
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-manifest-s13".into(),
        eligible_event_manifest_ref: "eligible-events-s13".into(),
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
        observation_role: ObservationRole::Result,
        identity_strength: IdentityStrength::StableNative,
        payload_fingerprint: evertrace_domain::evidence::hex(
            &payload_fingerprint(1, b"x", None).unwrap(),
        ),
        source_receipt_ref: receipt_id,
        source_role: SourceRole::Tool,
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Complete,
        adapter_revision: 1,
        parser_revision: 1,
        canonicalization_revision: 1,
        detector_revision: 1,
        redaction_revision: 1,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: Some("host-s13".into()),
            host_trace_lineage_id: Some("trace-s13".into()),
            host_lane_key: Some("lane-s13".into()),
            canonical_event_family: Some(CanonicalEventFamily::Mutate),
            native_request_id: Some("request-s13".into()),
            physical_execution_ordinal: Some(1),
            pairing_role: ObservationRole::Result,
            field_provenance: fields
                .into_iter()
                .map(|field| CorrelationFieldClaim {
                    field,
                    source_ref: "source-s13".into(),
                    evidence_ref: format!("canary-{field:?}"),
                })
                .collect(),
            adapter_manifest_ref: "adapter-manifest-s13".into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: Some("strong-gate-s13".into()),
            admission: CorrelationAdmission::ExactCapable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: Vec::new(),
    };
    (receipt, observation)
}

fn evidence_command(receipt: SourceReceipt, observation: SourceObservation) -> JournalCommand {
    let target = observation.source_observation_id.to_string();
    JournalCommand::new(
        CommandId::new_v7(),
        vec![
            JournalPayload::SourceReceiptRecorded(Box::new(receipt.clone())),
            JournalPayload::SourceObservationRecorded(Box::new(observation)),
            JournalPayload::SourceIngestWatermark(SourceIngestWatermark {
                source_instance_id: receipt.source_instance_id,
                source_revision: receipt.source_revision,
                source_sequence: receipt.source_sequence,
            }),
            JournalPayload::DirtyTarget(DirtyTarget {
                target_kind: DirtyTargetKind::EvidenceSurface,
                target_id: target.clone(),
                algorithm_revision: "s13-binding-v1".into(),
                source_watermark: 1,
            }),
            JournalPayload::DirtyTarget(DirtyTarget {
                target_kind: DirtyTargetKind::PhysicalNormalization,
                target_id: target,
                algorithm_revision: "s13-binding-v1".into(),
                source_watermark: 1,
            }),
        ]
        .into_iter()
        .map(|payload| JournalEventDraft::runtime(1, CONFIG, "s13-binding-v1", payload))
        .collect(),
    )
    .unwrap()
}

async fn seed(writer: &mut JournalWriter) -> (Task, Workstream, OperationId) {
    let (receipt, observation) = exact_observation();
    writer
        .commit(&evidence_command(receipt, observation.clone()), 1)
        .await
        .unwrap();
    let physical = PhysicalNormalizer::new(1)
        .unwrap()
        .normalize(&[observation], None)
        .unwrap();
    writer
        .commit(
            &physical
                .journal_command(CommandId::new_v7(), 2, CONFIG, "s13-binding-v1")
                .unwrap(),
            2,
        )
        .await
        .unwrap();
    let task = task(TaskIdentityConfidence::Explicit, 3);
    writer
        .commit(&create_task(context(3), task.clone()).unwrap(), 3)
        .await
        .unwrap();
    let stream = workstream(task.task_id, 4);
    writer
        .commit(
            &create_workstream(
                context(4),
                &task,
                &RepositoryCurrentView::default(),
                stream.clone(),
            )
            .unwrap(),
            4,
        )
        .await
        .unwrap();
    (task, stream, physical.operations[0].operation_id)
}

fn evidence(task: &Task, stream: &Workstream, name: &str) -> BindingEvidence {
    BindingEvidence {
        strength: BindingEvidenceStrength::Exact,
        evidence_ref: name.into(),
        task_id: task.task_id,
        workstream_id: stream.workstream_id,
    }
}

#[tokio::test]
async fn resolved_successor_replay_projection_restart_and_two_tables_are_closed() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("store");
    let mut writer = JournalWriter::open(&root).await.unwrap();
    let (task, stream, operation_id) = seed(&mut writer).await;
    let view = WorkIdentityCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let first = resolve_binding(
        &view,
        operation_id,
        None,
        Vec::new(),
        Vec::new(),
        &[evidence(&task, &stream, "exact-a")],
    )
    .unwrap()
    .into_revision()
    .unwrap();
    let command = record_binding(context(5), first.clone()).unwrap();
    let committed = writer.commit(&command, 5).await.unwrap();
    assert!(!committed.replayed);
    let row_count = writer.journal_rows().await.unwrap().len();
    assert!(writer.commit(&command, 5).await.unwrap().replayed);
    assert_eq!(writer.journal_rows().await.unwrap().len(), row_count);

    let projected = writer.project().await.unwrap();
    let current_view = WorkIdentityCurrentView::from_snapshot(&projected).unwrap();
    let binding_view = WorkBindingCurrentView::from_snapshot(&projected).unwrap();
    let first_context = binding_view.active_context(operation_id).unwrap();
    assert!(first_context.is_resolved());
    assert_eq!(first_context.operation_id, operation_id);
    assert_eq!(first_context.task_id, Some(task.task_id));
    let reader = CompatibilityStore::connect_local(&root).await.unwrap();
    let objects = reader
        .connection()
        .open_table(OBJECTS_TABLE)
        .execute()
        .await
        .unwrap();
    let object_version = objects.version().await.unwrap();
    assert_eq!(
        resolve_binding(
            &current_view,
            operation_id,
            Some(&binding_view.bindings[&operation_id]),
            Vec::new(),
            Vec::new(),
            &[evidence(&task, &stream, "exact-a")],
        )
        .unwrap(),
        BindingResolution::NoDelta
    );
    let no_delta_rows = writer.journal_rows().await.unwrap().len();
    let no_delta_projection = writer.project().await.unwrap();
    assert_eq!(writer.journal_rows().await.unwrap().len(), no_delta_rows);
    assert_eq!(no_delta_projection, projected);
    assert_eq!(objects.version().await.unwrap(), object_version);

    let successor = resolve_binding(
        &current_view,
        operation_id,
        Some(&first),
        Vec::new(),
        Vec::new(),
        &[evidence(&task, &stream, "exact-correction")],
    )
    .unwrap()
    .into_revision()
    .unwrap();
    writer
        .commit(&record_binding(context(6), successor.clone()).unwrap(), 6)
        .await
        .unwrap();
    let incremental = writer.project().await.unwrap();
    let rebuilt = writer.full_projection().await.unwrap();
    assert_eq!(incremental, rebuilt);
    let binding_rows = rebuilt
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("work_binding"))
        .count();
    assert_eq!(binding_rows, 2);
    let view = WorkBindingCurrentView::from_snapshot(&rebuilt).unwrap();
    assert_eq!(view.bindings[&operation_id], successor);
    assert_eq!(writer.project().await.unwrap(), rebuilt);
    let mut forked = rebuilt.clone();
    let mut fork_row = forked
        .data_rows()
        .find(|row| row.object_kind.as_deref() == Some("work_binding"))
        .unwrap()
        .clone();
    let mut fork_revision = successor.clone();
    fork_revision.work_binding_revision_id = WorkBindingRevisionId::new_v7();
    fork_row.row_id = format!(
        "object:work:work_binding:{}",
        fork_revision.work_binding_revision_id
    );
    fork_row.payload_json = Some(
        JournalPayload::WorkBindingRecorded(Box::new(fork_revision))
            .canonical_json()
            .unwrap(),
    );
    forked.rows.push(fork_row);
    assert_eq!(
        WorkBindingCurrentView::from_snapshot(&forked),
        Err(StoreError::StoreCorrupt)
    );
    assert_eq!(
        writer.table_names().await.unwrap(),
        vec!["evertrace_journal", "evertrace_objects"]
    );
    drop(writer);
    let writer = JournalWriter::open(&root).await.unwrap();
    let restart_snapshot = writer.project().await.unwrap();
    let restarted = WorkBindingCurrentView::from_snapshot(&restart_snapshot).unwrap();
    assert_eq!(
        restarted.active_context(operation_id),
        view.active_context(operation_id)
    );
    let identity = WorkIdentityCurrentView::from_snapshot(&restart_snapshot).unwrap();
    let restart_rows = writer.journal_rows().await.unwrap().len();
    let restart_reader = CompatibilityStore::connect_local(&root).await.unwrap();
    let restart_objects = restart_reader
        .connection()
        .open_table(OBJECTS_TABLE)
        .execute()
        .await
        .unwrap();
    let restart_version = restart_objects.version().await.unwrap();
    assert_eq!(
        resolve_binding(
            &identity,
            operation_id,
            Some(&restarted.bindings[&operation_id]),
            vec![],
            vec![],
            &[evidence(&task, &stream, "exact-correction")],
        )
        .unwrap(),
        BindingResolution::NoDelta
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), restart_rows);
    assert_eq!(writer.project().await.unwrap(), restart_snapshot);
    assert_eq!(restart_objects.version().await.unwrap(), restart_version);
}

#[test]
fn weak_and_conflicting_evidence_never_select_an_owner_and_order_is_stable() {
    let task_a = task(TaskIdentityConfidence::Explicit, 1);
    let stream_a = workstream(task_a.task_id, 1);
    let task_b = task(TaskIdentityConfidence::Explicit, 2);
    let stream_b = workstream(task_b.task_id, 2);
    let view = WorkIdentityCurrentView {
        frontier: 0,
        tasks: [
            (task_a.task_id, task_a.clone()),
            (task_b.task_id, task_b.clone()),
        ]
        .into_iter()
        .collect(),
        workstreams: [
            (stream_a.workstream_id, stream_a.clone()),
            (stream_b.workstream_id, stream_b.clone()),
        ]
        .into_iter()
        .collect(),
    };
    let operation_id = OperationId::new_v7();
    let weak = BindingEvidence {
        strength: BindingEvidenceStrength::Weak,
        evidence_ref: "cwd-or-time".into(),
        task_id: task_a.task_id,
        workstream_id: stream_a.workstream_id,
    };
    let unresolved = resolve_binding(&view, operation_id, None, vec![], vec![], &[weak])
        .unwrap()
        .into_revision()
        .unwrap();
    assert_eq!(unresolved.assignment_status, AssignmentStatus::Unresolved);
    let context = evertrace_domain::work::ActiveWorkContext::from_current(&unresolved);
    assert_eq!((context.task_id, context.workstream_id), (None, None));

    let candidates = vec![
        evidence(&task_a, &stream_a, "exact-a"),
        evidence(&task_b, &stream_b, "exact-b"),
    ];
    let mut reversed = candidates.clone();
    reversed.reverse();
    let left = resolve_binding(&view, operation_id, None, vec![], vec![], &candidates)
        .unwrap()
        .into_revision()
        .unwrap();
    let right = resolve_binding(&view, operation_id, None, vec![], vec![], &reversed)
        .unwrap()
        .into_revision()
        .unwrap();
    assert_eq!(left.assignment_status, AssignmentStatus::Conflicted);
    assert_eq!(left.primary_binding, right.primary_binding);
    assert_eq!(left.evidence_refs, right.evidence_refs);
    assert_eq!(left.primary_binding.task_id, None);

    let unknown = BindingEvidence {
        strength: BindingEvidenceStrength::Exact,
        evidence_ref: "unknown-exact".into(),
        task_id: TaskId::new_v7(),
        workstream_id: WorkstreamId::new_v7(),
    };
    let unknown = resolve_binding(&view, operation_id, None, vec![], vec![], &[unknown])
        .unwrap()
        .into_revision()
        .unwrap();
    assert_eq!(unknown.assignment_status, AssignmentStatus::Unresolved);
}

#[test]
fn non_resolved_primary_and_half_provisional_payloads_fail_closed() {
    let operation_id = OperationId::new_v7();
    let mut binding = WorkBindingRevision {
        work_binding_revision_id: WorkBindingRevisionId::new_v7(),
        operation_id,
        revision_generation: 1,
        predecessor_revision_id: None,
        primary_binding: Default::default(),
        secondary_bindings: vec![],
        scope_effect_refs: vec![],
        assignment_status: AssignmentStatus::Unresolved,
        evidence_refs: vec![],
        resolver_version: 1,
    };
    binding.primary_binding.task_id = Some(TaskId::new_v7());
    assert!(binding.validate().is_err());
    assert!(record_binding(context(1), binding.clone()).is_err());
    binding.assignment_status = AssignmentStatus::Conflicted;
    assert!(binding.validate().is_err());
    binding.assignment_status = AssignmentStatus::Provisional;
    assert!(binding.validate().is_err());

    let empty_view = WorkIdentityCurrentView::default();
    let oversized = (0..65)
        .map(|index| BindingEvidence {
            strength: BindingEvidenceStrength::Weak,
            evidence_ref: format!("weak-{index:02}"),
            task_id: TaskId::new_v7(),
            workstream_id: WorkstreamId::new_v7(),
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        resolve_binding(&empty_view, operation_id, None, vec![], vec![], &oversized),
        Err(evertrace_engine::work::WorkIdentityError::InvalidInput)
    ));

    let current = WorkBindingRevision {
        work_binding_revision_id: WorkBindingRevisionId::new_v7(),
        operation_id,
        revision_generation: u64::MAX,
        predecessor_revision_id: Some(WorkBindingRevisionId::new_v7()),
        primary_binding: Default::default(),
        secondary_bindings: vec![],
        scope_effect_refs: vec![],
        assignment_status: AssignmentStatus::Unresolved,
        evidence_refs: vec![],
        resolver_version: 1,
    };
    assert!(matches!(
        resolve_binding(
            &empty_view,
            operation_id,
            Some(&current),
            vec![],
            vec![],
            &[BindingEvidence {
                strength: BindingEvidenceStrength::Weak,
                evidence_ref: "new-weak".into(),
                task_id: TaskId::new_v7(),
                workstream_id: WorkstreamId::new_v7(),
            }],
        ),
        Err(evertrace_engine::work::WorkIdentityError::InvalidInput)
    ));
    assert!(matches!(
        resolve_binding(
            &empty_view,
            OperationId::new_v7(),
            Some(&current),
            vec![],
            vec![],
            &[],
        ),
        Err(evertrace_engine::work::WorkIdentityError::InvalidInput)
    ));
}

#[tokio::test]
async fn forged_scope_task_workstream_and_lineage_fail_before_frontier_advances() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let (bound_task, stream, operation_id) = seed(&mut writer).await;
    let view = WorkIdentityCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let valid = resolve_binding(
        &view,
        operation_id,
        None,
        vec![],
        vec![],
        &[evidence(&bound_task, &stream, "exact")],
    )
    .unwrap()
    .into_revision()
    .unwrap();
    writer
        .commit(&record_binding(context(5), valid.clone()).unwrap(), 5)
        .await
        .unwrap();
    let rows = writer.journal_rows().await.unwrap().len();

    let mut forged_scope = valid.clone();
    forged_scope.work_binding_revision_id = WorkBindingRevisionId::new_v7();
    forged_scope.revision_generation = 2;
    forged_scope.predecessor_revision_id = Some(valid.work_binding_revision_id);
    forged_scope.scope_effect_refs = vec![evertrace_domain::ids::ScopeEffectId::new_v7()];
    assert_eq!(
        writer
            .commit(&record_binding(context(6), forged_scope).unwrap(), 6)
            .await,
        Err(StoreError::InvalidInput)
    );

    let other_task = task(TaskIdentityConfidence::Explicit, 7);
    let mut forged_owner = valid.clone();
    forged_owner.work_binding_revision_id = WorkBindingRevisionId::new_v7();
    forged_owner.revision_generation = 2;
    forged_owner.predecessor_revision_id = Some(valid.work_binding_revision_id);
    forged_owner.primary_binding.task_id = Some(other_task.task_id);
    assert_eq!(
        writer
            .commit(&record_binding(context(7), forged_owner).unwrap(), 6)
            .await,
        Err(StoreError::InvalidInput)
    );

    let mut forged_lineage = valid.clone();
    forged_lineage.work_binding_revision_id = WorkBindingRevisionId::new_v7();
    forged_lineage.revision_generation = 3;
    forged_lineage.predecessor_revision_id = Some(valid.work_binding_revision_id);
    assert_eq!(
        writer
            .commit(&record_binding(context(8), forged_lineage).unwrap(), 6)
            .await,
        Err(StoreError::InvalidInput)
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), rows);
}

#[tokio::test]
async fn repository_worktree_scope_outside_work_membership_fails_before_append() {
    let temp = TempDir::new().unwrap();
    let mut writer = JournalWriter::open(&temp.path().join("store"))
        .await
        .unwrap();
    let (receipt, mut observation) = exact_observation();
    observation.scope_effect_claims = vec![ScopeEffectClaim {
        effect_role: EffectRole::Mutate,
        repository_instance_id: Some(RepositoryId::new_v7()),
        worktree_instance_id: Some(WorktreeId::new_v7()),
        pre_snapshot_id: None,
        post_snapshot_id: None,
        experiment_run_ids: vec![],
        artifact_refs: vec![],
        evidence_refs: vec![],
    }];
    writer
        .commit(&evidence_command(receipt, observation.clone()), 1)
        .await
        .unwrap();
    let physical = PhysicalNormalizer::new(1)
        .unwrap()
        .normalize(&[observation], None)
        .unwrap();
    writer
        .commit(
            &physical
                .journal_command(CommandId::new_v7(), 2, CONFIG, "s13-binding-v1")
                .unwrap(),
            2,
        )
        .await
        .unwrap();
    let task = task(TaskIdentityConfidence::Explicit, 3);
    writer
        .commit(&create_task(context(3), task.clone()).unwrap(), 3)
        .await
        .unwrap();
    let stream = workstream(task.task_id, 4);
    writer
        .commit(
            &create_workstream(
                context(4),
                &task,
                &RepositoryCurrentView::default(),
                stream.clone(),
            )
            .unwrap(),
            4,
        )
        .await
        .unwrap();
    let view = WorkIdentityCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let binding = resolve_binding(
        &view,
        physical.operations[0].operation_id,
        None,
        physical.operations[0].scope_effect_ids.clone(),
        vec![],
        &[evidence(&task, &stream, "exact")],
    )
    .unwrap()
    .into_revision()
    .unwrap();
    let rows = writer.journal_rows().await.unwrap().len();
    assert_eq!(
        writer
            .commit(&record_binding(context(5), binding).unwrap(), 5)
            .await,
        Err(StoreError::InvalidInput)
    );
    assert_eq!(writer.journal_rows().await.unwrap().len(), rows);
}

#[test]
fn multi_scope_relation_dto_keeps_one_operation_and_typed_competing_target() {
    let task = task(TaskIdentityConfidence::Explicit, 1);
    let stream = workstream(task.task_id, 1);
    let operation_id = OperationId::new_v7();
    let effect_a = evertrace_domain::evidence::ScopeEffect {
        scope_effect_id: evertrace_domain::ids::ScopeEffectId::new_v7(),
        operation_id,
        effect_role: EffectRole::Read,
        repository_instance_id: None,
        worktree_instance_id: None,
        pre_snapshot_id: None,
        post_snapshot_id: None,
        experiment_run_ids: vec![],
        artifact_refs: vec![],
        evidence_refs: vec![],
    };
    let mut effect_b = effect_a.clone();
    effect_b.scope_effect_id = evertrace_domain::ids::ScopeEffectId::new_v7();
    effect_b.effect_role = EffectRole::Mutate;
    let operation = evertrace_domain::evidence::Operation {
        operation_id,
        host_occurrence_id: evertrace_domain::ids::HostOccurrenceId::from_digest([1; 32]),
        execution_lane_id: None,
        operation_kind: evertrace_domain::evidence::OperationKind::Mutate,
        input_source_observation_refs: vec![],
        result_source_observation_refs: vec![
            evertrace_domain::ids::SourceObservationId::from_digest([2; 32]),
        ],
        scope_effect_ids: vec![effect_a.scope_effect_id, effect_b.scope_effect_id],
        artifact_refs: vec![],
        operation_resolver_version: 1,
        pairing_state: PairingState::UnmatchedResult,
        operation_revision: 1,
        previous_operation_revision: None,
    };
    let binding = WorkBindingRevision {
        work_binding_revision_id: WorkBindingRevisionId::new_v7(),
        operation_id,
        revision_generation: 1,
        predecessor_revision_id: None,
        primary_binding: evertrace_domain::work::PrimaryWorkBinding {
            task_id: Some(task.task_id),
            workstream_id: Some(stream.workstream_id),
            ..Default::default()
        },
        secondary_bindings: vec![SecondaryWorkBinding {
            role: SecondaryBindingRole::Comparison,
            target_ref: SecondaryBindingTarget::CompetingGroup(
                "cmp:01890f47-6a4a-7cc1-98b9-01890f476a99"
                    .parse::<CompetingAttemptGroupId>()
                    .unwrap(),
            ),
        }],
        scope_effect_refs: vec![effect_a.scope_effect_id, effect_b.scope_effect_id],
        assignment_status: AssignmentStatus::Resolved,
        evidence_refs: vec!["exact".into()],
        resolver_version: 1,
    };
    let rows = build_work_binding_relation_rows(
        std::slice::from_ref(&binding),
        std::slice::from_ref(&operation),
        &[effect_a.clone(), effect_b.clone()],
        std::slice::from_ref(&task),
        std::slice::from_ref(&stream),
    )
    .unwrap();
    assert_eq!(
        rows.iter()
            .filter(|row| row.kind == WorkBindingRelationKind::OperationToBindingRevision)
            .count(),
        1
    );
    assert_eq!(
        rows.iter()
            .filter(|row| row.kind == WorkBindingRelationKind::BindingToScopeEffect)
            .count(),
        2
    );
    assert_eq!(
        rows.iter()
            .filter(|row| row.kind == WorkBindingRelationKind::BindingToSecondaryTarget)
            .count(),
        1
    );

    let mut provisional_task = task.clone();
    provisional_task.identity_confidence = TaskIdentityConfidence::Provisional;
    let mut provisional = binding.clone();
    provisional.work_binding_revision_id = WorkBindingRevisionId::new_v7();
    provisional.assignment_status = AssignmentStatus::Provisional;
    let candidate_rows = build_work_binding_relation_rows(
        std::slice::from_ref(&provisional),
        std::slice::from_ref(&operation),
        &[effect_a.clone(), effect_b.clone()],
        &[provisional_task.clone()],
        std::slice::from_ref(&stream),
    )
    .unwrap();
    assert!(
        candidate_rows
            .iter()
            .any(|row| { row.kind == WorkBindingRelationKind::BindingToCandidateTask })
    );
    assert!(!candidate_rows.iter().any(|row| {
        matches!(
            row.kind,
            WorkBindingRelationKind::BindingToPrimaryTask
                | WorkBindingRelationKind::BindingToPrimaryWorkstream
        )
    }));

    let mut wrongly_resolved = provisional.clone();
    wrongly_resolved.assignment_status = AssignmentStatus::Resolved;
    assert_eq!(
        build_work_binding_relation_rows(
            &[wrongly_resolved],
            std::slice::from_ref(&operation),
            &[effect_a.clone(), effect_b.clone()],
            &[provisional_task],
            std::slice::from_ref(&stream),
        ),
        Err(StoreError::InvalidInput)
    );

    let mut forged_effect = effect_a.clone();
    forged_effect.scope_effect_id = evertrace_domain::ids::ScopeEffectId::new_v7();
    let mut forged_binding = binding;
    forged_binding.work_binding_revision_id = WorkBindingRevisionId::new_v7();
    forged_binding.scope_effect_refs = vec![forged_effect.scope_effect_id];
    assert_eq!(
        build_work_binding_relation_rows(
            &[forged_binding],
            std::slice::from_ref(&operation),
            &[forged_effect],
            std::slice::from_ref(&task),
            std::slice::from_ref(&stream),
        ),
        Err(StoreError::InvalidInput)
    );

    let mut outside_effect = effect_a;
    outside_effect.scope_effect_id = evertrace_domain::ids::ScopeEffectId::new_v7();
    outside_effect.repository_instance_id = Some(RepositoryId::new_v7());
    outside_effect.worktree_instance_id = Some(WorktreeId::new_v7());
    let mut outside_operation = operation;
    outside_operation.scope_effect_ids = vec![outside_effect.scope_effect_id];
    let mut outside_binding = provisional;
    outside_binding.work_binding_revision_id = WorkBindingRevisionId::new_v7();
    outside_binding.assignment_status = AssignmentStatus::Resolved;
    outside_binding.scope_effect_refs = vec![outside_effect.scope_effect_id];
    assert_eq!(
        build_work_binding_relation_rows(
            &[outside_binding],
            &[outside_operation],
            &[outside_effect],
            &[task],
            &[stream],
        ),
        Err(StoreError::InvalidInput)
    );
}
