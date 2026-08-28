use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use evertrace_capture::{
    CaptureOutcome, CaptureRecordInput, CaptureRuntime, CasDigest, CasStore, DeviceKeyStore,
    DurableSpool, RecoveryGateMode, RecoveryPreflightCandidate, RuntimeSnapshot, SpoolError,
    SpoolLimits, SpoolRecord,
};
use evertrace_codex::recovery::{
    DestructiveCommandInput, ProtectedPath, ProtectedPathKind, classify_codex_pretool_candidate,
    classify_codex_pretool_payload, classify_destructive_command,
};
use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceRevisionMode, SourceRole,
    },
    ids::{
        CommandId, RecoveryApplicationId, RecoveryCaptureRequestId, RepositoryId, WorktreeId,
        WorktreeSnapshotId,
    },
    repository::{
        DestructiveClass, DestructiveDetectionStatus, FilesystemIdentity, GitObjectFormat,
        GitOperation, GitRegistrationState, OrderingIntegrity, PathObservation,
        RecoveryApplication, RecoveryApplicationKind, RecoveryApplicationStatus,
        RecoveryCaptureRequest, RecoveryCaptureStatus, RecoveryOmissionReason, RecoveryReasonCode,
        RecoveryRequestStatus, RepositoryInstance, SnapshotCaptureStatus, UntrackedCaptureScope,
        WorktreeInstance, WorktreeKind, WorktreeLifecycle, WorktreeSnapshot,
    },
    revision::RevisionId,
};
use evertrace_engine::{
    RecoveryBarrierService, RecoveryBudget, RecoveryCaptureFacts, RecoveryCaptureItem,
    RecoveryItemKind, RecoveryTicketIssueRequest, RecoveryTicketService, capture_recovery_bundle,
    pending_request_command, publish_recovery_runtime,
    repository::{ProbeLimits, probe_recovery_capture, probe_recovery_capture_scoped},
    spawn_writer, terminal_capture_command,
};
use evertrace_protocol::{
    LocalServer, ServerOptions,
    command::RecoveryBarrierLocator,
    dto::{MAX_FRAME_SIZE, PROTOCOL_VERSION},
    envelope::{ClientEnvelope, ServerEnvelope},
    error::SyncProtocolError,
    frame::{read_frame_sync, write_frame_sync},
    handshake::HandshakeAck,
    request_recovery_barrier_sync,
    response::{RecoveryTerminalResponse, Response},
};
use evertrace_store::{
    EventScope, JournalCommand, JournalEventDraft, JournalPayload, JournalWriter, SourceKind,
    projections::{RecoveryCurrentState, RecoveryCurrentView},
    repository::RepositoryCurrentView,
};
use tempfile::TempDir;

fn revision() -> RevisionId {
    RevisionId::new_v7()
}

fn repository_id() -> RepositoryId {
    RepositoryId::from_uuid(revision().as_uuid()).unwrap()
}

fn worktree_id() -> WorktreeId {
    WorktreeId::from_uuid(revision().as_uuid()).unwrap()
}

fn snapshot_id() -> WorktreeSnapshotId {
    WorktreeSnapshotId::from_uuid(revision().as_uuid()).unwrap()
}

fn request_id() -> RecoveryCaptureRequestId {
    RecoveryCaptureRequestId::from_uuid(revision().as_uuid()).unwrap()
}

fn application_id() -> RecoveryApplicationId {
    RecoveryApplicationId::from_uuid(revision().as_uuid()).unwrap()
}

fn runtime_snapshot(
    root: &Path,
    generation: u64,
    limits: SpoolLimits,
    gate: RecoveryGateMode,
    timeout_ms: u32,
) -> RuntimeSnapshot {
    RuntimeSnapshot::for_data_dir(
        root,
        generation,
        limits,
        evertrace_capture::RecoverySnapshotSettings {
            gate,
            preflight_timeout_ms: timeout_ms,
            effective_config_hash: [7; 32],
            adapter_manifest_id: (gate == RecoveryGateMode::Active).then(|| "adapter-s16".into()),
            classifier_revision: evertrace_codex::recovery::RECOVERY_CLASSIFIER_REVISION,
            max_bundle_bytes: 4 << 20,
            max_untracked_file_bytes: 1 << 20,
            max_untracked_total_bytes: 2 << 20,
        },
    )
    .unwrap()
}

fn pending() -> RecoveryCaptureRequest {
    RecoveryCaptureRequest {
        recovery_capture_request_id: request_id(),
        request_revision_id: revision(),
        parent_request_revision_id: None,
        trigger_event_id: "tool-use-a".into(),
        repository_instance_id: repository_id(),
        worktree_instance_id: worktree_id(),
        pre_operation_snapshot_id: None,
        command_fingerprint: "ab".repeat(32),
        destructive_class: DestructiveClass::GitResetHard,
        untracked_capture_scope: UntrackedCaptureScope::Standard,
        detection_status: DestructiveDetectionStatus::Matched,
        request_status: RecoveryRequestStatus::Pending,
        recovery_bundle_id: None,
        reason_codes: Vec::new(),
        started_at_us: 10,
        finished_at_us: None,
        effective_config_hash: [7; 32],
    }
}

fn preflight(request: &RecoveryCaptureRequest, cwd: &Path) -> RecoveryPreflightCandidate {
    RecoveryPreflightCandidate {
        pending_command_id: CommandId::new_v7(),
        recovery_capture_request_id: request.recovery_capture_request_id,
        pending_revision_id: request.request_revision_id,
        observed_cwd: cwd.to_string_lossy().into_owned(),
        classifier_revision: evertrace_codex::recovery::RECOVERY_CLASSIFIER_REVISION,
        adapter_manifest_id: "adapter-s16".into(),
    }
}

fn repository_seed_command(request: &RecoveryCaptureRequest, path: &Path) -> JournalCommand {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    let path = path.to_string_lossy().into_owned();
    let git_metadata = std::fs::metadata(format!("{path}/.git")).ok();
    let observation = |value: &str, evidence: &str| PathObservation {
        path: value.into(),
        first_observed_at_us: 1,
        last_observed_at_us: 1,
        evidence_refs: vec![evidence.into()],
    };
    let repository = RepositoryInstance {
        repository_id: request.repository_instance_id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: path.clone(),
        path_history: vec![observation(&path, "repo-path")],
        git_common_dir_path: Some(format!("{path}/.git")),
        common_dir_filesystem: Some(FilesystemIdentity {
            #[cfg(unix)]
            device: git_metadata.as_ref().map_or(1, MetadataExt::dev),
            #[cfg(not(unix))]
            device: 1,
            #[cfg(unix)]
            inode: git_metadata.as_ref().map_or(1, MetadataExt::ino),
            #[cfg(not(unix))]
            inode: 1,
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: Vec::new(),
        derived_from: None,
        identity_evidence_refs: vec!["repo-identity".into()],
        recorded_at_us: 1,
    };
    let worktree = WorktreeInstance {
        worktree_instance_id: request.worktree_instance_id,
        worktree_revision: 1,
        predecessor_revision: None,
        repository_instance_id: request.repository_instance_id,
        kind: WorktreeKind::Main,
        lifecycle: WorktreeLifecycle::Active,
        current_path: Some(path.clone()),
        path_history: vec![observation(&path, "worktree-path")],
        git_admin_path_history: vec![observation(&format!("{path}/.git"), "worktree-admin")],
        git_registration_state: GitRegistrationState::Registered,
        current_snapshot_id: None,
        created_event_ref: "worktree-created".into(),
        terminal_event_ref: None,
        recreated_from_worktree_instance_id: None,
        recorded_at_us: 1,
    };
    let event = |payload| JournalEventDraft {
        occurred_at_us: 1,
        source_kind: SourceKind::System,
        scope: EventScope {
            repository_id: Some(request.repository_instance_id.to_string()),
            worktree_id: Some(request.worktree_instance_id.to_string()),
            ..EventScope::default()
        },
        causation_id: None,
        correlation_id: None,
        effective_config_hash: request.effective_config_hash,
        algorithm_revision: "s16-test-seed".into(),
        payload,
    };
    JournalCommand::new(
        CommandId::new_v7(),
        vec![
            event(JournalPayload::RepositoryInstanceRecorded(Box::new(
                repository,
            ))),
            event(JournalPayload::WorktreeInstanceRecorded(Box::new(worktree))),
        ],
    )
    .unwrap()
}

fn linked_worktree_seed_command(
    request: &RecoveryCaptureRequest,
    worktree_instance_id: WorktreeId,
    path: &Path,
    git_admin_path: &str,
) -> JournalCommand {
    let path = path.to_string_lossy().into_owned();
    let observation = |value: &str, evidence: &str| PathObservation {
        path: value.into(),
        first_observed_at_us: 2,
        last_observed_at_us: 2,
        evidence_refs: vec![evidence.into()],
    };
    let worktree = WorktreeInstance {
        worktree_instance_id,
        worktree_revision: 1,
        predecessor_revision: None,
        repository_instance_id: request.repository_instance_id,
        kind: WorktreeKind::Linked,
        lifecycle: WorktreeLifecycle::Active,
        current_path: Some(path.clone()),
        path_history: vec![observation(&path, "linked-worktree-path")],
        git_admin_path_history: vec![observation(git_admin_path, "linked-worktree-admin")],
        git_registration_state: GitRegistrationState::Registered,
        current_snapshot_id: None,
        created_event_ref: "linked-worktree-created".into(),
        terminal_event_ref: None,
        recreated_from_worktree_instance_id: None,
        recorded_at_us: 2,
    };
    JournalCommand::new(
        CommandId::new_v7(),
        vec![JournalEventDraft {
            occurred_at_us: 2,
            source_kind: SourceKind::System,
            scope: EventScope {
                repository_id: Some(request.repository_instance_id.to_string()),
                worktree_id: Some(worktree_instance_id.to_string()),
                ..EventScope::default()
            },
            causation_id: None,
            correlation_id: None,
            effective_config_hash: request.effective_config_hash,
            algorithm_revision: "s16-linked-seed".into(),
            payload: JournalPayload::WorktreeInstanceRecorded(Box::new(worktree)),
        }],
    )
    .unwrap()
}

fn snapshot(worktree_instance_id: WorktreeId) -> WorktreeSnapshot {
    WorktreeSnapshot {
        worktree_snapshot_id: snapshot_id(),
        worktree_instance_id,
        head_oid: None,
        tree_oid: None,
        branch_ref: None,
        detached_head: false,
        tracked_diff_digest: None,
        index_digest: None,
        untracked_manifest_digest: None,
        relevant_anchor_digests: Vec::new(),
        dependency_fingerprints: Vec::new(),
        toolchain_fingerprint: None,
        git_operation: GitOperation::None,
        captured_at_us: 20,
        evidence_refs: vec!["pre-operation-probe".into()],
        capture_status: SnapshotCaptureStatus::Complete,
        omission_reasons: Vec::new(),
    }
}

fn unavailable_correlation() -> HostCorrelationEvidence {
    HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: None,
        host_trace_lineage_id: None,
        host_lane_key: None,
        canonical_event_family: None,
        native_request_id: None,
        physical_execution_ordinal: None,
        pairing_role: ObservationRole::Intent,
        field_provenance: Vec::new(),
        adapter_manifest_ref: "adapter-s16".into(),
        adapter_revision: 1,
        strong_gate_receipt_ref: None,
        admission: CorrelationAdmission::Unavailable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    }
}

fn capture_input(request: &RecoveryCaptureRequest) -> CaptureRecordInput {
    CaptureRecordInput {
        spool_record_id: Some("physical-spool-record".into()),
        source_observation_id_hint: None,
        source_instance_id: "source-s16".into(),
        source_revision: "revision-1".into(),
        source_record_identity: Some("pretool-request-1".into()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::CodexHook,
        identity_domain: "codex-hook-v1".into(),
        source_ref: "source-s16".into(),
        session_ref: "session-s16".into(),
        turn_ref: Some("turn-s16".into()),
        tool_ref: Some("tool-s16".into()),
        source_sequence: 1,
        source_sequence_origin: None,
        task_id: None,
        repository_instance_id: Some(request.repository_instance_id.to_string()),
        worktree_instance_id: Some(request.worktree_instance_id.to_string()),
        source_byte_range: None,
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: None,
        observation_role: ObservationRole::Intent,
        correlation: unavailable_correlation(),
        scope_effect_claims: Vec::new(),
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: SourceRole::Tool,
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Partial,
        surface_eligible: true,
        adapter_revision: 1,
        adapter_manifest_ref: "adapter-s16".into(),
        eligible_event_manifest_ref: "eligible-s16".into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: Some(10),
        raw_payload: br#"{"program":"git","args":["reset","--hard"],"cwd":"/tmp/worktree"}"#
            .to_vec(),
    }
}

fn capture_input_at(request: &RecoveryCaptureRequest, cwd: &Path) -> CaptureRecordInput {
    capture_input_for_git(request, cwd, &["reset", "--hard"])
}

fn capture_input_for_git(
    request: &RecoveryCaptureRequest,
    cwd: &Path,
    args: &[&str],
) -> CaptureRecordInput {
    let mut input = capture_input(request);
    input.raw_payload = serde_json::to_vec(&serde_json::json!({
        "program": "git",
        "args": args,
        "cwd": cwd.to_string_lossy(),
    }))
    .unwrap();
    input
}

#[tokio::test]
async fn clean_scopes_flow_through_barrier_into_exact_protected_cas_payloads() {
    let scenarios = [
        (
            vec!["clean", "-fd"],
            vec![("ordinary.txt", b"ordinary".as_slice())],
        ),
        (
            vec!["clean", "-fdx"],
            vec![
                ("ordinary.txt", b"ordinary".as_slice()),
                ("ignored.txt", b"ignored".as_slice()),
            ],
        ),
        (
            vec!["clean", "-fdX"],
            vec![("ignored.txt", b"ignored".as_slice())],
        ),
    ];
    for (args, expected) in scenarios {
        let root = TempDir::new().unwrap();
        std::fs::set_permissions(root.path(), PermissionsExt::from_mode(0o700)).unwrap();
        DeviceKeyStore::new(root.path().join("keys"))
            .load_or_create()
            .unwrap();
        let worktree = root.path().join("worktree");
        std::fs::create_dir(&worktree).unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(&worktree)
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(worktree.join(".gitignore"), b"ignored.txt\n").unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["add", ".gitignore"])
                .current_dir(&worktree)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("git")
                .args([
                    "-c",
                    "user.name=EverTrace",
                    "-c",
                    "user.email=evertrace@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "base",
                ])
                .current_dir(&worktree)
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(worktree.join("ordinary.txt"), b"ordinary").unwrap();
        std::fs::write(worktree.join("ignored.txt"), b"ignored").unwrap();

        let snapshot = runtime_snapshot(
            root.path(),
            1,
            SpoolLimits {
                high_watermark_bytes: 1 << 20,
                low_watermark_bytes: 1,
                max_main_files: 4,
                emergency_slots: 1,
            },
            RecoveryGateMode::Active,
            10_000,
        );
        let mut request = pending();
        request.started_at_us = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros(),
        )
        .unwrap();
        let input = capture_input_for_git(&request, &worktree, &args);
        let mut runtime = CaptureRuntime::open(snapshot.clone()).unwrap();
        let outcome = runtime
            .capture_with_recovery_preflight(input, preflight(&request, &worktree))
            .unwrap();
        let CaptureOutcome::Durable {
            spool_record_id,
            recovery_preflight: Some(locator),
            ..
        } = outcome
        else {
            panic!("clean preflight must be durable")
        };
        drop(runtime);
        let mut writer = JournalWriter::open(root.path()).await.unwrap();
        writer
            .commit(&repository_seed_command(&request, &worktree), 1)
            .await
            .unwrap();
        let (handle, task) = spawn_writer(writer, 8).unwrap();
        let ack = RecoveryBarrierService::new(snapshot, handle.clone())
            .handle(evertrace_engine::RecoveryBarrierLocator {
                spool_record_id,
                recovery_capture_request_id: locator.request_id,
                pending_revision_id: locator.pending_revision_id,
            })
            .await
            .unwrap();
        assert_eq!(ack.status, RecoveryRequestStatus::Complete);
        let current = RecoveryCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
        let bundle = &current.state.bundles[&ack.recovery_bundle_id.unwrap()];
        assert!(!serde_json::to_string(bundle).unwrap().contains("/proc/"));
        assert!(
            !serde_json::to_string(current.terminal_request(locator.request_id).unwrap())
                .unwrap()
                .contains("/proc/")
        );
        let cas = CasStore::open(root.path().join("cas")).unwrap();
        let mut restored = bundle
            .untracked_file_blob_refs
            .iter()
            .map(|reference| {
                let path = cas
                    .read(
                        &CasDigest::from_str(
                            &reference.protected_relative_path.as_ref().unwrap().cas_ref,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                let payload = cas
                    .read(&CasDigest::from_str(&reference.payload.cas_ref).unwrap())
                    .unwrap();
                (String::from_utf8(path).unwrap(), payload)
            })
            .collect::<Vec<_>>();
        restored.sort_by(|left, right| left.0.cmp(&right.0));
        let mut expected = expected
            .into_iter()
            .map(|(path, payload)| (path.to_owned(), payload.to_vec()))
            .collect::<Vec<_>>();
        expected.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(restored, expected, "args={args:?}");
        let projected = handle.project().await.unwrap();
        let repositories = RepositoryCurrentView::from_snapshot(&projected).unwrap();
        let source_worktree = repositories.worktrees[&bundle.source_worktree_instance_id].clone();
        let source_snapshot = repositories.snapshots[&bundle.source_snapshot_id].clone();
        let target_worktree_id = WorktreeId::new_v7();
        let target_snapshot_id = WorktreeSnapshotId::new_v7();
        let target_path = root
            .path()
            .join("ticket-target")
            .to_string_lossy()
            .into_owned();
        let target_observation = |path: String, evidence: &str| PathObservation {
            path,
            first_observed_at_us: 30,
            last_observed_at_us: 30,
            evidence_refs: vec![evidence.into()],
        };
        let target_worktree = WorktreeInstance {
            worktree_instance_id: target_worktree_id,
            worktree_revision: 1,
            predecessor_revision: None,
            repository_instance_id: source_worktree.repository_instance_id,
            kind: WorktreeKind::Linked,
            lifecycle: WorktreeLifecycle::Active,
            current_path: Some(target_path.clone()),
            path_history: vec![target_observation(
                target_path.clone(),
                "ticket-target-path",
            )],
            git_admin_path_history: vec![target_observation(
                format!("{target_path}/.git"),
                "ticket-target-admin",
            )],
            git_registration_state: GitRegistrationState::Registered,
            current_snapshot_id: Some(target_snapshot_id),
            created_event_ref: "ticket-target-created".into(),
            terminal_event_ref: None,
            recreated_from_worktree_instance_id: None,
            recorded_at_us: 30,
        };
        let mut target_snapshot = source_snapshot.clone();
        target_snapshot.worktree_snapshot_id = target_snapshot_id;
        target_snapshot.worktree_instance_id = target_worktree_id;
        target_snapshot.captured_at_us = 30;
        target_snapshot.evidence_refs = vec!["ticket-target-snapshot".into()];
        let target_event = |payload| JournalEventDraft {
            occurred_at_us: 30,
            source_kind: SourceKind::System,
            scope: EventScope {
                repository_id: Some(source_worktree.repository_instance_id.to_string()),
                worktree_id: Some(target_worktree_id.to_string()),
                ..EventScope::default()
            },
            causation_id: None,
            correlation_id: None,
            effective_config_hash: [7; 32],
            algorithm_revision: "s16-ticket-target".into(),
            payload,
        };
        let target_command = JournalCommand::new(
            CommandId::new_v7(),
            vec![
                target_event(JournalPayload::WorktreeInstanceRecorded(Box::new(
                    target_worktree.clone(),
                ))),
                target_event(JournalPayload::WorktreeSnapshotRecorded(Box::new(
                    target_snapshot.clone(),
                ))),
            ],
        )
        .unwrap();
        handle.commit(target_command, 30).await.unwrap();
        let ticket_request = RecoveryTicketIssueRequest {
            recovery_bundle_id: bundle.recovery_bundle_id,
            target_worktree_instance_id: target_worktree_id,
            pre_application_snapshot_id: target_snapshot_id,
            application_kind: RecoveryApplicationKind::FileRestore,
            selected_item_refs: bundle
                .untracked_file_blob_refs
                .iter()
                .map(|value| value.item_ref.clone())
                .collect(),
        };
        let keys = DeviceKeyStore::new(root.path().join("keys"));
        let invalid_config_tickets =
            RecoveryTicketService::new(handle.clone(), cas.clone(), keys.clone(), [0; 32]);
        assert!(
            invalid_config_tickets
                .issue(ticket_request.clone())
                .await
                .is_err()
        );
        let tickets =
            RecoveryTicketService::new(handle.clone(), cas.clone(), keys.clone(), [7; 32]);
        let before_ticket = handle.project().await.unwrap();
        let ticket = tickets.issue(ticket_request.clone()).await.unwrap();
        let second_ticket = tickets.issue(ticket_request.clone()).await.unwrap();
        assert_eq!(before_ticket, handle.project().await.unwrap());
        assert_eq!(ticket.claims.selected_content_refs.len(), expected.len());
        assert_eq!(ticket.claims.effective_config_hash, [7; 32]);
        assert_eq!(
            ticket.claims.algorithm_revision,
            evertrace_engine::RECOVERY_ALGORITHM_REVISION
        );
        assert!(ticket.claims.issued_at_us >= bundle.captured_at_us);
        assert!(ticket.claims.issued_at_us >= target_snapshot.captured_at_us);
        assert_eq!(
            ticket
                .claims
                .prospective_recovery_application_id
                .as_uuid()
                .get_version_num(),
            7
        );
        assert_ne!(
            ticket.claims.prospective_recovery_application_id,
            second_ticket.claims.prospective_recovery_application_id
        );
        assert!(worktree.join("ordinary.txt").exists());
        let after_first = handle.project().await.unwrap();
        assert_eq!(tickets.verify(&ticket).await.unwrap(), ticket.claims);
        assert_eq!(tickets.verify(&ticket).await.unwrap(), ticket.claims);
        assert_eq!(after_first, handle.project().await.unwrap());
        let mut conflict = ticket_request.clone();
        conflict.application_kind = RecoveryApplicationKind::Patch;
        assert!(tickets.issue(conflict).await.is_err());
        let mut missing_bundle = ticket_request.clone();
        missing_bundle.recovery_bundle_id = evertrace_domain::ids::RecoveryBundleId::new_v7();
        assert!(tickets.issue(missing_bundle).await.is_err());
        let mut noncurrent_target_snapshot = ticket_request.clone();
        noncurrent_target_snapshot.pre_application_snapshot_id = bundle.source_snapshot_id;
        assert!(tickets.issue(noncurrent_target_snapshot).await.is_err());

        let cross_repository_id = RepositoryId::new_v7();
        let cross_worktree_id = WorktreeId::new_v7();
        let cross_snapshot_id = WorktreeSnapshotId::new_v7();
        let mut cross_repository =
            repositories.repositories[&source_worktree.repository_instance_id].clone();
        cross_repository.repository_id = cross_repository_id;
        cross_repository.repository_revision = 1;
        cross_repository.predecessor_revision = None;
        cross_repository.current_path = format!("{target_path}-cross-repository");
        cross_repository.path_history = vec![target_observation(
            cross_repository.current_path.clone(),
            "cross-repository-path",
        )];
        cross_repository.recorded_at_us = 31;
        let mut cross_worktree = target_worktree.clone();
        cross_worktree.worktree_instance_id = cross_worktree_id;
        cross_worktree.repository_instance_id = cross_repository_id;
        cross_worktree.current_snapshot_id = Some(cross_snapshot_id);
        cross_worktree.current_path = Some(format!("{target_path}-cross-worktree"));
        cross_worktree.path_history = vec![target_observation(
            cross_worktree.current_path.clone().unwrap(),
            "cross-worktree-path",
        )];
        cross_worktree.git_admin_path_history = vec![target_observation(
            format!("{target_path}-cross-worktree/.git"),
            "cross-worktree-admin",
        )];
        cross_worktree.recorded_at_us = 31;
        let mut cross_snapshot = target_snapshot.clone();
        cross_snapshot.worktree_snapshot_id = cross_snapshot_id;
        cross_snapshot.worktree_instance_id = cross_worktree_id;
        cross_snapshot.captured_at_us = 31;
        let cross_event = |payload| JournalEventDraft {
            occurred_at_us: 31,
            source_kind: SourceKind::System,
            scope: EventScope {
                repository_id: Some(cross_repository_id.to_string()),
                worktree_id: Some(cross_worktree_id.to_string()),
                ..EventScope::default()
            },
            causation_id: None,
            correlation_id: None,
            effective_config_hash: [7; 32],
            algorithm_revision: "s16-ticket-cross-repository".into(),
            payload,
        };
        let cross_command = JournalCommand::new(
            CommandId::new_v7(),
            vec![
                cross_event(JournalPayload::RepositoryInstanceRecorded(Box::new(
                    cross_repository,
                ))),
                cross_event(JournalPayload::WorktreeInstanceRecorded(Box::new(
                    cross_worktree,
                ))),
                cross_event(JournalPayload::WorktreeSnapshotRecorded(Box::new(
                    cross_snapshot,
                ))),
            ],
        )
        .unwrap();
        handle.commit(cross_command, 31).await.unwrap();
        let mut cross_repository_target = ticket_request.clone();
        cross_repository_target.target_worktree_instance_id = cross_worktree_id;
        cross_repository_target.pre_application_snapshot_id = cross_snapshot_id;
        assert!(tickets.issue(cross_repository_target).await.is_err());
        let mut duplicate = ticket
            .claims
            .selected_content_refs
            .iter()
            .map(|value| value.item_ref.clone())
            .collect::<Vec<_>>();
        duplicate.push(duplicate[0].clone());
        assert!(
            tickets
                .issue(RecoveryTicketIssueRequest {
                    selected_item_refs: duplicate,
                    recovery_bundle_id: bundle.recovery_bundle_id,
                    application_kind: RecoveryApplicationKind::FileRestore,
                    target_worktree_instance_id: target_worktree_id,
                    pre_application_snapshot_id: target_snapshot_id,
                })
                .await
                .is_err()
        );
        let mut tampered = ticket.clone();
        tampered.authentication_tag[0] ^= 1;
        assert!(tickets.verify(&tampered).await.is_err());
        let mut wrong_target = ticket.clone();
        wrong_target.claims.target_worktree_instance_id = WorktreeId::new_v7();
        assert!(tickets.verify(&wrong_target).await.is_err());
        let mut wrong_cas = ticket.clone();
        wrong_cas.claims.selected_content_refs[0].payload.cas_ref = "0".repeat(64);
        assert!(tickets.verify(&wrong_cas).await.is_err());
        let mut wrong_generation = ticket.clone();
        wrong_generation.claims.device_key_generation += 1;
        assert!(tickets.verify(&wrong_generation).await.is_err());
        let mut encoded = serde_json::to_value(&ticket).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<evertrace_engine::RecoveryApplicationTicket>(encoded).is_err()
        );
        let mut archived_target = target_worktree;
        archived_target.worktree_revision = 2;
        archived_target.predecessor_revision = Some(1);
        archived_target.lifecycle = WorktreeLifecycle::Archived;
        archived_target.recorded_at_us = 32;
        let archive_command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft {
                occurred_at_us: 32,
                source_kind: SourceKind::System,
                scope: EventScope {
                    repository_id: Some(source_worktree.repository_instance_id.to_string()),
                    worktree_id: Some(target_worktree_id.to_string()),
                    ..EventScope::default()
                },
                causation_id: None,
                correlation_id: None,
                effective_config_hash: [7; 32],
                algorithm_revision: "s16-ticket-target-archived".into(),
                payload: JournalPayload::WorktreeInstanceRecorded(Box::new(archived_target)),
            }],
        )
        .unwrap();
        handle.commit(archive_command, 32).await.unwrap();
        assert_eq!(tickets.verify(&ticket).await.unwrap(), ticket.claims);
        if args == ["clean", "-fd"] {
            handle.shutdown().await.unwrap();
            task.await.unwrap().unwrap();
            let restarted = JournalWriter::open(root.path()).await.unwrap();
            assert_eq!(
                restarted.table_names().await.unwrap(),
                vec!["evertrace_journal", "evertrace_objects"]
            );
            let (restart_handle, restart_task) = spawn_writer(restarted, 8).unwrap();
            let restarted_tickets = RecoveryTicketService::new(
                restart_handle.clone(),
                cas.clone(),
                keys.clone(),
                [7; 32],
            );
            assert_eq!(
                restarted_tickets.verify(&ticket).await.unwrap(),
                ticket.claims
            );
            keys.rotate().unwrap();
            assert!(restarted_tickets.verify(&ticket).await.is_err());
            restart_handle.shutdown().await.unwrap();
            restart_task.await.unwrap().unwrap();
            continue;
        }
        handle.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn worktree_remove_from_source_subdir_binds_and_captures_the_linked_target() {
    let root = TempDir::new().unwrap();
    std::fs::set_permissions(root.path(), PermissionsExt::from_mode(0o700)).unwrap();
    DeviceKeyStore::new(root.path().join("keys"))
        .load_or_create()
        .unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&source)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(source.join(".gitignore"), b"ignored.txt\n").unwrap();
    std::fs::write(source.join("tracked.txt"), b"base\n").unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["add", ".gitignore", "tracked.txt"])
            .current_dir(&source)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("git")
            .args([
                "-c",
                "user.name=EverTrace",
                "-c",
                "user.email=evertrace@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "base",
            ])
            .current_dir(&source)
            .status()
            .unwrap()
            .success()
    );
    let target = source.join("other");
    assert!(
        std::process::Command::new("git")
            .args(["worktree", "add", "--quiet", "-b", "linked", "other"])
            .current_dir(&source)
            .status()
            .unwrap()
            .success()
    );
    let command_cwd = source.join("subdir");
    std::fs::create_dir(&command_cwd).unwrap();
    std::fs::write(target.join("tracked.txt"), b"modified before remove\n").unwrap();
    std::fs::write(target.join("indexed.txt"), b"indexed before remove\n").unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["add", "indexed.txt"])
            .current_dir(&target)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(target.join("ordinary.txt"), b"ordinary target payload").unwrap();
    std::fs::write(target.join("ignored.txt"), b"ignored target payload").unwrap();
    let git_admin_path = String::from_utf8(
        std::process::Command::new("git")
            .args(["rev-parse", "--absolute-git-dir"])
            .current_dir(&target)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();

    let snapshot = runtime_snapshot(
        root.path(),
        1,
        SpoolLimits {
            high_watermark_bytes: 1 << 20,
            low_watermark_bytes: 1,
            max_main_files: 4,
            emergency_slots: 1,
        },
        RecoveryGateMode::Active,
        10_000,
    );
    let mut request = pending();
    request.started_at_us = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    let target_worktree_id = WorktreeId::new_v7();
    let input = capture_input_for_git(&request, &command_cwd, &["worktree", "remove", "../other"]);
    let mut runtime = CaptureRuntime::open(snapshot.clone()).unwrap();
    let outcome = runtime
        .capture_with_recovery_preflight(input, preflight(&request, &command_cwd))
        .unwrap();
    let CaptureOutcome::Durable {
        spool_record_id,
        recovery_preflight: Some(locator),
        ..
    } = outcome
    else {
        panic!("worktree-remove preflight must be durable")
    };
    drop(runtime);
    let mut writer = JournalWriter::open(root.path()).await.unwrap();
    writer
        .commit(&repository_seed_command(&request, &source), 1)
        .await
        .unwrap();
    writer
        .commit(
            &linked_worktree_seed_command(&request, target_worktree_id, &target, &git_admin_path),
            2,
        )
        .await
        .unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let ack = RecoveryBarrierService::new(snapshot, handle.clone())
        .handle(evertrace_engine::RecoveryBarrierLocator {
            spool_record_id,
            recovery_capture_request_id: locator.request_id,
            pending_revision_id: locator.pending_revision_id,
        })
        .await
        .unwrap();
    assert_eq!(ack.status, RecoveryRequestStatus::Complete);
    let current = RecoveryCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    let terminal = current
        .terminal_request(locator.request_id)
        .expect("terminal request");
    assert_eq!(terminal.worktree_instance_id, target_worktree_id);
    assert_ne!(terminal.worktree_instance_id, request.worktree_instance_id);
    assert_eq!(
        terminal.untracked_capture_scope,
        UntrackedCaptureScope::StandardAndIgnored
    );
    let bundle = &current.state.bundles[&ack.recovery_bundle_id.unwrap()];
    assert_eq!(bundle.source_worktree_instance_id, target_worktree_id);
    assert!(!bundle.tracked_diff_blob_refs.is_empty());
    assert!(!bundle.index_state_refs.is_empty());
    let cas = CasStore::open(root.path().join("cas")).unwrap();
    let restored = bundle
        .untracked_file_blob_refs
        .iter()
        .map(|reference| {
            let path = cas
                .read(
                    &CasDigest::from_str(
                        &reference.protected_relative_path.as_ref().unwrap().cas_ref,
                    )
                    .unwrap(),
                )
                .unwrap();
            let payload = cas
                .read(&CasDigest::from_str(&reference.payload.cas_ref).unwrap())
                .unwrap();
            (String::from_utf8(path).unwrap(), payload)
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(restored["ordinary.txt"], b"ordinary target payload");
    assert_eq!(restored["ignored.txt"], b"ignored target payload");
    assert!(
        target.exists(),
        "recovery must not execute worktree removal"
    );
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[test]
fn classifier_is_closed_and_requires_an_explicit_worktree() {
    let root = Path::new("/tmp/evertrace-s16-worktree").to_path_buf();
    let classify = |program: &str, args: &[&str]| {
        classify_destructive_command(&DestructiveCommandInput {
            program: program.into(),
            args: args.iter().map(|value| (*value).into()).collect(),
            cwd: root.clone(),
            worktree_root: root.clone(),
            known_worktree_roots: vec![root.clone()],
            protected_paths: vec![ProtectedPath {
                path: root.join("tracked.txt"),
                kind: ProtectedPathKind::Tracked,
            }],
        })
    };
    let hard = classify("git", &["reset", "--hard"]);
    assert_eq!(hard.detection_status, DestructiveDetectionStatus::Matched);
    assert_eq!(hard.destructive_class, Some(DestructiveClass::GitResetHard));
    assert_eq!(hard.command_fingerprint.len(), 64);
    assert_eq!(
        classify("git", &["clean", "-fdx"]).untracked_capture_scope,
        Some(UntrackedCaptureScope::StandardAndIgnored)
    );
    assert_eq!(
        classify("git", &["clean", "-fX"]).untracked_capture_scope,
        Some(UntrackedCaptureScope::IgnoredOnly)
    );
    assert_eq!(
        classify("git", &["clean", "-fd"]).untracked_capture_scope,
        Some(UntrackedCaptureScope::Standard)
    );
    assert_eq!(
        classify("git", &["clean", "-fd", "pathspec"]).detection_status,
        DestructiveDetectionStatus::Unsupported
    );
    assert_eq!(
        classify("git", &["status"]).detection_status,
        DestructiveDetectionStatus::Unsupported
    );
    for args in [
        &["--work-tree=/tmp/victim", "clean", "-fdx"][..],
        &["--git-dir=/tmp/other.git", "reset", "--hard"][..],
        &["-C", "/tmp/victim", "clean", "-f"][..],
    ] {
        assert_eq!(
            classify("git", args).detection_status,
            DestructiveDetectionStatus::Unsupported
        );
    }
    let hook_global = serde_json::json!({
        "program": "git",
        "args": ["--work-tree=/tmp/victim", "clean", "-fdx"],
        "cwd": root,
    });
    assert_eq!(
        classify_codex_pretool_candidate(&hook_global.to_string(), &root).detection_status,
        DestructiveDetectionStatus::Unsupported
    );
    let other = root.parent().unwrap().join("evertrace-s16-other");
    let worktree_remove = classify_destructive_command(&DestructiveCommandInput {
        program: "git".into(),
        args: vec![
            "worktree".into(),
            "remove".into(),
            "../evertrace-s16-other".into(),
        ],
        cwd: root.clone(),
        worktree_root: root.clone(),
        known_worktree_roots: vec![root.clone(), other.clone()],
        protected_paths: Vec::new(),
    });
    assert_eq!(worktree_remove.target_worktree, Some(other));
    assert_eq!(
        classify(
            "git",
            &["worktree", "remove", "-ff", "../evertrace-s16-other"]
        )
        .detection_status,
        DestructiveDetectionStatus::Unsupported
    );
    assert_eq!(
        classify("bash", &["-lc", "git reset --hard"]).detection_status,
        DestructiveDetectionStatus::Unknown
    );
    assert_eq!(
        classify("rm", &["../outside"]).detection_status,
        DestructiveDetectionStatus::Unknown
    );
    assert_eq!(
        classify("rm", &["link/../victim"]).detection_status,
        DestructiveDetectionStatus::Unknown
    );
    assert_eq!(
        classify("rm", &["tracked.txt"]).destructive_class,
        Some(DestructiveClass::TrackedFileRemove)
    );
}

#[test]
fn recovery_probe_enumerates_the_closed_git_clean_scopes() {
    let root = TempDir::new().unwrap();
    let worktree = root.path();
    assert!(
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(worktree)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(worktree.join(".gitignore"), b"ignored.txt\n").unwrap();
    std::fs::write(worktree.join("ordinary.txt"), b"ordinary").unwrap();
    std::fs::write(worktree.join("ignored.txt"), b"ignored").unwrap();
    let limits = ProbeLimits::default();
    let standard =
        probe_recovery_capture_scoped(worktree, &limits, UntrackedCaptureScope::Standard).unwrap();
    let all =
        probe_recovery_capture_scoped(worktree, &limits, UntrackedCaptureScope::StandardAndIgnored)
            .unwrap();
    let ignored =
        probe_recovery_capture_scoped(worktree, &limits, UntrackedCaptureScope::IgnoredOnly)
            .unwrap();
    assert!(
        standard
            .untracked_paths
            .contains(&PathBuf::from("ordinary.txt"))
    );
    assert!(
        !standard
            .untracked_paths
            .contains(&PathBuf::from("ignored.txt"))
    );
    assert!(all.untracked_paths.contains(&PathBuf::from("ordinary.txt")));
    assert!(all.untracked_paths.contains(&PathBuf::from("ignored.txt")));
    assert_eq!(ignored.untracked_paths, vec![PathBuf::from("ignored.txt")]);
    assert_ne!(standard.fingerprint, all.fingerprint);
}

#[test]
fn recovery_reason_codes_are_closed_on_the_authoritative_payload() {
    let mut value = serde_json::to_value(pending()).unwrap();
    value["request_status"] = serde_json::json!("failed");
    value["parent_request_revision_id"] = serde_json::json!(RevisionId::new_v7());
    value["finished_at_us"] = serde_json::json!(20);
    value["reason_codes"] = serde_json::json!(["caller_defined_reason"]);
    assert!(serde_json::from_value::<RecoveryCaptureRequest>(value).is_err());
}

#[test]
fn mutation_fingerprint_covers_diff_bytes_and_is_unavailable_on_probe_omission() {
    let root = TempDir::new().unwrap();
    let worktree = root.path();
    assert!(
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(worktree)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(worktree.join("tracked.txt"), b"base\n").unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["add", "tracked.txt"])
            .current_dir(worktree)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("git")
            .args([
                "-c",
                "user.name=EverTrace",
                "-c",
                "user.email=evertrace@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "base",
            ])
            .current_dir(worktree)
            .status()
            .unwrap()
            .success()
    );
    let limits = ProbeLimits::default();
    std::fs::write(worktree.join("tracked.txt"), b"aaaa\n").unwrap();
    let first = probe_recovery_capture(worktree, &limits).unwrap();
    std::fs::write(worktree.join("tracked.txt"), b"bbbb\n").unwrap();
    let second = probe_recovery_capture(worktree, &limits).unwrap();
    assert_eq!(first.index_entries, second.index_entries);
    assert_ne!(first.tracked_diff, second.tracked_diff);
    assert_ne!(first.fingerprint, second.fingerprint);

    let omitted = probe_recovery_capture(
        worktree,
        &ProbeLimits {
            max_diff_bytes: 1,
            ..limits
        },
    )
    .unwrap();
    assert!(omitted.tracked_diff.is_none());
    assert!(omitted.fingerprint.is_none());
}

#[test]
fn protected_bundle_is_bounded_secret_safe_and_race_downgrades() {
    let root = TempDir::new().unwrap();
    let keys = DeviceKeyStore::new(root.path().join("keys"));
    keys.load_or_create().unwrap();
    let cas = CasStore::open(root.path().join("cas")).unwrap();
    let request = pending();
    let facts = RecoveryCaptureFacts {
        snapshot: snapshot(request.worktree_instance_id),
        request_id: request.recovery_capture_request_id,
        adapter_manifest_id: "adapter-s16".into(),
        mutation_manifest_version: 1,
        before_fingerprint: Some("before".into()),
        after_fingerprint: Some("after".into()),
        items: vec![
            RecoveryCaptureItem {
                item_ref: "git:diff".into(),
                kind: RecoveryItemKind::TrackedDiff,
                bytes: b"api_key=abcdefgh".to_vec(),
                relative_path: None,
                critical: true,
                metadata_only: false,
            },
            RecoveryCaptureItem {
                item_ref: "large.bin".into(),
                kind: RecoveryItemKind::UntrackedFile,
                bytes: vec![1; 32],
                relative_path: Some(b"large.bin".to_vec()),
                critical: false,
                metadata_only: false,
            },
        ],
        omissions: Vec::new(),
        artifact_refs: Vec::new(),
        metadata_artifact_refs: Vec::new(),
        config_and_run_refs: Vec::new(),
        attempt_anchor_ids: Vec::new(),
        captured_at_us: 30,
    };
    let unavailable_facts = RecoveryCaptureFacts {
        before_fingerprint: None,
        after_fingerprint: Some("after".into()),
        items: vec![RecoveryCaptureItem {
            item_ref: "git:diff-unavailable-fence".into(),
            kind: RecoveryItemKind::TrackedDiff,
            bytes: b"bounded diff".to_vec(),
            relative_path: None,
            critical: true,
            metadata_only: false,
        }],
        ..facts.clone()
    };
    let bundle = capture_recovery_bundle(
        facts,
        RecoveryBudget {
            max_item_bytes: 24,
            max_untracked_item_bytes: 24,
            max_bundle_bytes: 128,
        },
        &cas,
        &keys,
    )
    .unwrap();
    assert_eq!(bundle.capture_status, RecoveryCaptureStatus::Partial);
    assert_eq!(bundle.ordering_integrity, OrderingIntegrity::Raced);
    assert!(
        bundle.tracked_diff_blob_refs[0]
            .payload
            .protected_secret_digest
            .is_some()
    );
    assert!(
        bundle
            .omissions
            .iter()
            .any(|value| value.item_ref == "large.bin")
    );
    let bytes = cas
        .read(&CasDigest::from_str(&bundle.tracked_diff_blob_refs[0].payload.cas_ref).unwrap())
        .unwrap();
    assert!(!bytes.windows(8).any(|window| window == b"abcdefgh"));
    let mut forged_path_on_diff = bundle.clone();
    forged_path_on_diff.tracked_diff_blob_refs[0].protected_relative_path = Some(
        forged_path_on_diff.tracked_diff_blob_refs[0]
            .payload
            .clone(),
    );
    forged_path_on_diff.captured_bytes += forged_path_on_diff.tracked_diff_blob_refs[0]
        .payload
        .protected_length;
    assert!(forged_path_on_diff.validate().is_err());
    let mut empty_diff = bundle.clone();
    empty_diff.captured_bytes -= empty_diff.tracked_diff_blob_refs[0]
        .payload
        .protected_length;
    empty_diff.tracked_diff_blob_refs[0]
        .payload
        .protected_length = 0;
    empty_diff.tracked_diff_blob_refs[0].payload.original_length = 0;
    empty_diff.tracked_diff_blob_refs[0]
        .payload
        .protected_secret_digest = None;
    empty_diff.tracked_diff_blob_refs[0].payload.redaction_spans = 0;
    assert!(empty_diff.validate().is_err());

    let unavailable = capture_recovery_bundle(
        unavailable_facts,
        RecoveryBudget {
            max_item_bytes: 24,
            max_untracked_item_bytes: 24,
            max_bundle_bytes: 128,
        },
        &cas,
        &keys,
    )
    .unwrap();
    assert_eq!(
        unavailable.ordering_integrity,
        OrderingIntegrity::BestEffort
    );
    assert_eq!(unavailable.capture_status, RecoveryCaptureStatus::Partial);
    assert!(
        unavailable
            .omissions
            .iter()
            .any(|value| value.item_ref == "worktree_mutation_fence")
    );

    let mut forged_complete = bundle.clone();
    forged_complete.capture_status = RecoveryCaptureStatus::Complete;
    forged_complete.ordering_integrity = OrderingIntegrity::Complete;
    assert!(forged_complete.validate().is_err());
    let mut empty_complete = bundle;
    empty_complete.tracked_diff_blob_refs.clear();
    empty_complete.omissions.clear();
    empty_complete.captured_bytes = 0;
    empty_complete.capture_status = RecoveryCaptureStatus::Complete;
    empty_complete.ordering_integrity = OrderingIntegrity::Complete;
    assert!(empty_complete.validate().is_err());
}

#[test]
fn admission_failure_leaves_no_recovery_locator_and_inactive_gate_is_explicit() {
    let root = TempDir::new().unwrap();
    let limits = SpoolLimits {
        high_watermark_bytes: 1,
        low_watermark_bytes: 1,
        max_main_files: 1,
        emergency_slots: 1,
    };
    DeviceKeyStore::new(root.path().join("keys"))
        .load_or_create()
        .unwrap();
    let runtime_snapshot =
        runtime_snapshot(root.path(), 1, limits, RecoveryGateMode::Active, 10_000);
    let mut runtime = CaptureRuntime::open(runtime_snapshot).unwrap();
    let request = pending();
    let outcome = runtime
        .capture_with_recovery_preflight(
            capture_input(&request),
            preflight(&request, Path::new("/tmp/worktree")),
        )
        .unwrap();
    assert!(matches!(
        outcome,
        CaptureOutcome::GapRecorded { .. } | CaptureOutcome::CompletenessLost
    ));

    let config = evertrace_domain::config::EffectiveConfig::new(
        evertrace_domain::config::ConfigFile::default(),
    )
    .unwrap();
    let published = publish_recovery_runtime(root.path(), &config, None).unwrap();
    assert_eq!(published.recovery_gate, RecoveryGateMode::Disabled);
}

#[test]
fn unsupported_recovery_classification_does_not_drop_the_ordinary_capture() {
    let root = TempDir::new().unwrap();
    let limits = SpoolLimits {
        high_watermark_bytes: 1 << 20,
        low_watermark_bytes: 1 << 19,
        max_main_files: 4,
        emergency_slots: 1,
    };
    DeviceKeyStore::new(root.path().join("keys"))
        .load_or_create()
        .unwrap();
    let classification = classify_codex_pretool_payload(
        r#"{"program":"bash","args":["-c","rm tracked.txt"],"cwd":"/tmp/worktree"}"#,
        Path::new("/tmp/worktree"),
    );
    assert_eq!(
        classification.detection_status,
        DestructiveDetectionStatus::Unknown
    );
    let snapshot = runtime_snapshot(root.path(), 1, limits, RecoveryGateMode::Active, 100);
    let mut runtime = CaptureRuntime::open(snapshot).unwrap();
    let outcome = runtime.capture(capture_input(&pending())).unwrap();
    assert!(matches!(
        outcome,
        CaptureOutcome::Durable {
            recovery_preflight: None,
            ..
        }
    ));
}

#[tokio::test]
async fn untracked_capture_is_confined_secret_safe_and_clean_is_skipped() {
    let scenarios = [
        None,
        Some((
            b"ordinary.txt".to_vec(),
            b"ordinary recovery bytes".to_vec(),
            false,
        )),
        Some((b"empty.txt".to_vec(), Vec::new(), false)),
        Some((
            b"Authorization: Bearer pathsecretabcdefgh".to_vec(),
            b"Authorization: Bearer contentsecretabcdefgh".to_vec(),
            true,
        )),
        Some((
            b"nonutf8-\xff.bin".to_vec(),
            b"non utf8 path payload".to_vec(),
            false,
        )),
    ];
    for untracked in scenarios {
        let root = TempDir::new().unwrap();
        std::fs::set_permissions(root.path(), PermissionsExt::from_mode(0o700)).unwrap();
        let limits = SpoolLimits {
            high_watermark_bytes: 1 << 20,
            low_watermark_bytes: 1,
            max_main_files: 4,
            emergency_slots: 1,
        };
        DeviceKeyStore::new(root.path().join("keys"))
            .load_or_create()
            .unwrap();
        let worktree = root.path().join("worktree");
        std::fs::create_dir(&worktree).unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(&worktree)
                .status()
                .unwrap()
                .success()
        );
        let command_cwd = worktree.join("nested");
        std::fs::create_dir(&command_cwd).unwrap();
        if let Some((path, content, _)) = untracked.as_ref() {
            use std::os::unix::ffi::OsStringExt;
            std::fs::write(
                worktree.join(std::ffi::OsString::from_vec(path.clone())),
                content,
            )
            .unwrap();
        }
        let runtime_snapshot =
            runtime_snapshot(root.path(), 1, limits, RecoveryGateMode::Active, 10_000);
        let mut pending = pending();
        pending.started_at_us = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros(),
        )
        .unwrap();
        let input = capture_input_at(&pending, &command_cwd);
        pending.command_fingerprint = classify_codex_pretool_payload(
            std::str::from_utf8(&input.raw_payload).unwrap(),
            &command_cwd,
        )
        .command_fingerprint;
        let mut runtime = CaptureRuntime::open(runtime_snapshot.clone()).unwrap();
        let outcome = runtime
            .capture_with_recovery_preflight(
                capture_input_at(&pending, &command_cwd),
                preflight(&pending, &command_cwd),
            )
            .unwrap();
        let CaptureOutcome::Durable {
            spool_record_id,
            recovery_preflight: Some(locator),
            ..
        } = outcome
        else {
            panic!("recovery pending must be durable");
        };
        drop(runtime);
        let mut writer = JournalWriter::open(root.path()).await.unwrap();
        writer
            .commit(&repository_seed_command(&pending, &worktree), 1)
            .await
            .unwrap();
        let (handle, task) = spawn_writer(writer, 8).unwrap();
        let service = RecoveryBarrierService::new(runtime_snapshot, handle.clone());
        let barrier_locator = evertrace_engine::RecoveryBarrierLocator {
            spool_record_id,
            recovery_capture_request_id: locator.request_id,
            pending_revision_id: locator.pending_revision_id,
        };
        let ack = service.handle(barrier_locator.clone()).await.unwrap();
        let projected = handle.project().await.unwrap();
        let current = RecoveryCurrentView::from_snapshot(&projected).unwrap();
        if let Some((path, content, secret)) = untracked.as_ref() {
            assert_eq!(
                ack.status,
                if *secret {
                    RecoveryRequestStatus::Partial
                } else {
                    RecoveryRequestStatus::Complete
                }
            );
            let bundle_id = ack.recovery_bundle_id.expect("untracked recovery bundle");
            let bundle = &current.state.bundles[&bundle_id];
            assert_eq!(
                bundle.capture_status,
                if *secret {
                    RecoveryCaptureStatus::Partial
                } else {
                    RecoveryCaptureStatus::Complete
                }
            );
            assert!(bundle.captured_bytes > 0 || content.is_empty());
            assert_eq!(bundle.untracked_file_blob_refs.len(), 1);
            let encoded = serde_json::to_string(bundle).unwrap();
            assert!(
                !encoded
                    .as_bytes()
                    .windows(path.len())
                    .any(|value| value == path)
            );
            assert!(
                !encoded
                    .as_bytes()
                    .windows(content.len().max(1))
                    .any(|value| { !content.is_empty() && value == content })
            );
            let reference = &bundle.untracked_file_blob_refs[0];
            let mut missing_path = bundle.clone();
            missing_path.untracked_file_blob_refs[0].protected_relative_path = None;
            assert!(missing_path.validate().is_err());
            let cas = CasStore::open(root.path().join("cas")).unwrap();
            let restored_payload = cas
                .read(&CasDigest::from_str(&reference.payload.cas_ref).unwrap())
                .unwrap();
            let restored_path = cas
                .read(
                    &CasDigest::from_str(
                        &reference
                            .protected_relative_path
                            .as_ref()
                            .expect("file path ref")
                            .cas_ref,
                    )
                    .unwrap(),
                )
                .unwrap();
            if *secret {
                assert_ne!(&restored_payload, content);
                assert_ne!(&restored_path, path);
                assert!(
                    !restored_payload
                        .windows(content.len())
                        .any(|value| value == content)
                );
                assert!(!restored_path.windows(path.len()).any(|value| value == path));
                let mut directories = vec![root.path().join("cas")];
                while let Some(directory) = directories.pop() {
                    for entry in std::fs::read_dir(directory).unwrap() {
                        let entry = entry.unwrap();
                        if entry.file_type().unwrap().is_dir() {
                            directories.push(entry.path());
                        } else if entry.file_type().unwrap().is_file() {
                            let envelope = std::fs::read(entry.path()).unwrap();
                            assert!(
                                !envelope
                                    .windows(content.len())
                                    .any(|value| value == content)
                            );
                            assert!(!envelope.windows(path.len()).any(|value| value == path));
                        }
                    }
                }
            } else {
                assert_eq!(&restored_payload, content);
                assert_eq!(&restored_path, path);
            }
            assert_eq!(
                bundle
                    .omissions
                    .iter()
                    .any(|value| { value.reason == RecoveryOmissionReason::SecretRedacted }),
                *secret
            );
        } else {
            assert_eq!(ack.status, RecoveryRequestStatus::Skipped);
            assert!(ack.recovery_bundle_id.is_none());
            assert!(current.state.bundles.is_empty());
            let displaced = root.path().join("displaced-worktree");
            std::fs::rename(&worktree, &displaced).unwrap();
            std::fs::create_dir(&worktree).unwrap();
            let replay = service.handle(barrier_locator).await.unwrap();
            assert_eq!(replay, ack);
            assert_eq!(projected, handle.project().await.unwrap());
        }
        handle.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn expired_preflight_is_not_admitted_and_creates_no_logical_request() {
    let root = TempDir::new().unwrap();
    std::fs::set_permissions(root.path(), PermissionsExt::from_mode(0o700)).unwrap();
    DeviceKeyStore::new(root.path().join("keys"))
        .load_or_create()
        .unwrap();
    let worktree = root.path().join("worktree");
    std::fs::create_dir(&worktree).unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&worktree)
            .status()
            .unwrap()
            .success()
    );
    let runtime_snapshot = runtime_snapshot(
        root.path(),
        1,
        SpoolLimits {
            high_watermark_bytes: 1 << 20,
            low_watermark_bytes: 1,
            max_main_files: 4,
            emergency_slots: 1,
        },
        RecoveryGateMode::Active,
        1,
    );
    let mut pending = pending();
    pending.started_at_us = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
    .saturating_sub(1_000_000);
    let input = capture_input_at(&pending, &worktree);
    pending.command_fingerprint =
        classify_codex_pretool_payload(std::str::from_utf8(&input.raw_payload).unwrap(), &worktree)
            .command_fingerprint;
    let mut runtime = CaptureRuntime::open(runtime_snapshot.clone()).unwrap();
    let outcome = runtime
        .capture_with_recovery_preflight(
            capture_input_at(&pending, &worktree),
            preflight(&pending, &worktree),
        )
        .unwrap();
    let CaptureOutcome::Durable {
        spool_record_id,
        recovery_preflight: Some(locator),
        ..
    } = outcome
    else {
        panic!("pending must be durable")
    };
    drop(runtime);
    let mut writer = JournalWriter::open(root.path()).await.unwrap();
    writer
        .commit(&repository_seed_command(&pending, &worktree), 1)
        .await
        .unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let result = RecoveryBarrierService::new(runtime_snapshot, handle.clone())
        .handle(evertrace_engine::RecoveryBarrierLocator {
            spool_record_id,
            recovery_capture_request_id: locator.request_id,
            pending_revision_id: locator.pending_revision_id,
        })
        .await;
    assert_eq!(result, Err(evertrace_engine::RecoveryError::NotAdmitted));
    let current = RecoveryCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
    assert!(current.state.requests.is_empty());
    assert!(current.state.bundles.is_empty());
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn immutable_pending_timeout_replays_and_rebuilds_from_fresh_current_view() {
    let root = TempDir::new().unwrap();
    std::fs::set_permissions(
        root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let mut writer = JournalWriter::open(root.path()).await.unwrap();
    let pending = pending();
    writer
        .commit(
            &repository_seed_command(&pending, Path::new("/tmp/worktree")),
            1,
        )
        .await
        .unwrap();
    let command = pending_request_command(CommandId::new_v7(), pending.clone()).unwrap();
    writer.commit(&command, 10).await.unwrap();
    drop(writer);
    DeviceKeyStore::new(root.path().join("keys"))
        .load_or_create()
        .unwrap();
    let writer = JournalWriter::open(root.path()).await.unwrap();
    let (handle, task) = spawn_writer(writer, 8).unwrap();
    let service = RecoveryBarrierService::new(
        runtime_snapshot(
            root.path(),
            1,
            SpoolLimits {
                high_watermark_bytes: 1 << 20,
                low_watermark_bytes: 1,
                max_main_files: 4,
                emergency_slots: 1,
            },
            RecoveryGateMode::Active,
            10_000,
        ),
        handle.clone(),
    );
    service.reconcile_pending_on_startup().await.unwrap();
    let first = handle.project().await.unwrap();
    let current = RecoveryCurrentView::from_snapshot(&first).unwrap();
    let terminal = current
        .terminal_request(pending.recovery_capture_request_id)
        .unwrap();
    assert_eq!(terminal.request_status, RecoveryRequestStatus::TimedOut);
    assert_eq!(
        terminal.parent_request_revision_id,
        Some(pending.request_revision_id)
    );
    service.reconcile_pending_on_startup().await.unwrap();
    assert_eq!(first, handle.project().await.unwrap());
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn durable_complete_wins_over_late_timeout_proposal_without_a_revision_fork() {
    let root = TempDir::new().unwrap();
    std::fs::set_permissions(
        root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    DeviceKeyStore::new(root.path().join("keys"))
        .load_or_create()
        .unwrap();
    let cas = CasStore::open(root.path().join("cas")).unwrap();
    let mut writer = JournalWriter::open(root.path()).await.unwrap();
    let pending = pending();
    writer
        .commit(
            &repository_seed_command(&pending, Path::new("/tmp/worktree")),
            1,
        )
        .await
        .unwrap();
    writer
        .commit(
            &pending_request_command(CommandId::new_v7(), pending.clone()).unwrap(),
            10,
        )
        .await
        .unwrap();
    let current = RecoveryCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
    let source_snapshot = snapshot(pending.worktree_instance_id);
    let bundle = capture_recovery_bundle(
        RecoveryCaptureFacts {
            snapshot: source_snapshot.clone(),
            request_id: pending.recovery_capture_request_id,
            adapter_manifest_id: "adapter-s16".into(),
            mutation_manifest_version: 1,
            before_fingerprint: Some("same".into()),
            after_fingerprint: Some("same".into()),
            items: vec![RecoveryCaptureItem {
                item_ref: "git:tracked_diff".into(),
                kind: RecoveryItemKind::TrackedDiff,
                bytes: b"bounded tracked patch".to_vec(),
                relative_path: None,
                critical: true,
                metadata_only: false,
            }],
            omissions: Vec::new(),
            artifact_refs: Vec::new(),
            metadata_artifact_refs: Vec::new(),
            config_and_run_refs: Vec::new(),
            attempt_anchor_ids: Vec::new(),
            captured_at_us: 20,
        },
        RecoveryBudget {
            max_item_bytes: 1024,
            max_untracked_item_bytes: 1024,
            max_bundle_bytes: 4096,
        },
        &cas,
        &DeviceKeyStore::new(root.path().join("keys")),
    )
    .unwrap();
    let complete = RecoveryCaptureRequest {
        request_revision_id: revision(),
        parent_request_revision_id: Some(pending.request_revision_id),
        pre_operation_snapshot_id: Some(source_snapshot.worktree_snapshot_id),
        request_status: RecoveryRequestStatus::Complete,
        recovery_bundle_id: Some(bundle.recovery_bundle_id),
        reason_codes: vec![RecoveryReasonCode::CaptureComplete],
        finished_at_us: Some(20),
        ..pending.clone()
    };
    complete.validate().unwrap();
    bundle.validate().unwrap();
    let terminal_current = RecoveryCurrentView {
        frontier: current.frontier + 1,
        state: RecoveryCurrentState {
            requests: [(complete.recovery_capture_request_id, complete.clone())]
                .into_iter()
                .collect(),
            bundles: [(bundle.recovery_bundle_id, bundle)].into_iter().collect(),
        },
    };
    let late_timeout = RecoveryCaptureRequest {
        request_revision_id: revision(),
        parent_request_revision_id: Some(pending.request_revision_id),
        request_status: RecoveryRequestStatus::TimedOut,
        recovery_bundle_id: None,
        pre_operation_snapshot_id: None,
        reason_codes: vec![RecoveryReasonCode::LateTimeout],
        finished_at_us: Some(30),
        ..pending
    };
    assert!(
        terminal_capture_command(
            CommandId::new_v7(),
            &terminal_current,
            late_timeout,
            None,
            None,
        )
        .is_err()
    );
    assert_eq!(
        terminal_current
            .terminal_request(complete.recovery_capture_request_id)
            .unwrap()
            .request_revision_id,
        complete.request_revision_id
    );
}

#[test]
fn application_successors_and_lineage_transfer_are_fail_closed() {
    let current = RecoveryApplication {
        recovery_application_id: application_id(),
        revision_id: revision(),
        parent_revision_id: None,
        recovery_bundle_id: evertrace_domain::ids::RecoveryBundleId::new_v7(),
        target_worktree_instance_id: worktree_id(),
        pre_application_snapshot_id: Some(snapshot_id()),
        post_application_snapshot_id: Some(snapshot_id()),
        application_kind: RecoveryApplicationKind::FileRestore,
        application_evidence_refs: vec!["normal-tool-input".into()],
        verification_refs: Vec::new(),
        application_status: RecoveryApplicationStatus::PartiallyApplied,
        created_at_us: 10,
    };
    current.validate().unwrap();
    assert!(!current.supports_compatible_lineage_transfer());
    let no_evidence_progress = RecoveryApplication {
        revision_id: revision(),
        parent_revision_id: Some(current.revision_id),
        created_at_us: 20,
        ..current.clone()
    };
    assert!(!no_evidence_progress.is_successor_of(&current));
    let failed = RecoveryApplication {
        revision_id: revision(),
        parent_revision_id: Some(current.revision_id),
        application_evidence_refs: vec!["normal-tool-input".into(), "typed-result".into()],
        application_status: RecoveryApplicationStatus::Failed,
        created_at_us: 20,
        ..current.clone()
    };
    assert!(failed.is_successor_of(&current));
    let no_terminal_verification = RecoveryApplication {
        revision_id: revision(),
        parent_revision_id: Some(failed.revision_id),
        created_at_us: 30,
        ..failed.clone()
    };
    assert!(!no_terminal_verification.is_successor_of(&failed));
    let verified_terminal = RecoveryApplication {
        revision_id: revision(),
        parent_revision_id: Some(failed.revision_id),
        verification_refs: vec!["typed-verifier".into()],
        created_at_us: 30,
        ..failed.clone()
    };
    assert!(verified_terminal.is_successor_of(&failed));
    let mut forged = failed;
    forged.recovery_bundle_id = evertrace_domain::ids::RecoveryBundleId::new_v7();
    assert!(!forged.is_successor_of(&current));
    assert!(
        serde_json::from_str::<JournalPayload>(r#"{"RecoveryApplicationRecorded":{}}"#).is_err()
    );
}
#[test]
fn runtime_v2_layout_and_spool_lookup_fail_closed() {
    let root = TempDir::new().unwrap();
    let limits = SpoolLimits {
        high_watermark_bytes: 1 << 20,
        low_watermark_bytes: 1 << 19,
        max_main_files: 8,
        emergency_slots: 2,
    };
    let snapshot = runtime_snapshot(root.path(), 1, limits, RecoveryGateMode::Disabled, 100);
    assert_eq!(snapshot.data_dir().unwrap(), root.path());
    let path = RuntimeSnapshot::snapshot_path(root.path());
    snapshot.publish(&path).unwrap();
    let mut old = std::fs::read(&path).unwrap();
    old[8..10].copy_from_slice(&1_u16.to_be_bytes());
    std::fs::write(&path, old).unwrap();
    assert!(RuntimeSnapshot::load(&path).is_err());

    let (mut spool, _) = DurableSpool::open(root.path().join("spool"), limits).unwrap();
    let record = SpoolRecord {
        spool_generation: 1,
        spool_record_id: "locator-a".into(),
        source_observation_id: "observation-a".into(),
        cas_refs: vec![CasDigest::for_protected_bytes(b"body").as_hex()],
        record_body: b"body".to_vec(),
    };
    spool.append(&record).unwrap();
    assert_eq!(
        spool.find_durable_record("locator-a", 2, 1 << 20).unwrap(),
        Some(record.clone())
    );
    assert_eq!(
        spool.find_durable_record("locator-a", 2, 1).unwrap_err(),
        SpoolError::ResourceExhausted
    );
    spool.seal_active(1).unwrap();
    assert_eq!(
        spool.find_durable_record("locator-a", 2, 1 << 20).unwrap(),
        Some(record.clone())
    );
    spool.append(&record).unwrap();
    assert_eq!(
        spool
            .find_durable_record("locator-a", 2, 1 << 20)
            .unwrap_err(),
        SpoolError::DuplicateRecord
    );
}

#[test]
fn sync_hook_barrier_rejects_malicious_ack_and_obeys_deadline() {
    let locator = RecoveryBarrierLocator {
        spool_record_id: "spool-s16".into(),
        recovery_capture_request_id: RecoveryCaptureRequestId::new_v7(),
        pending_revision_id: RevisionId::new_v7(),
    };
    for (invalid_ack, expected) in [
        (true, SyncProtocolError::Negotiation),
        (false, SyncProtocolError::Timeout),
    ] {
        let root = TempDir::new().unwrap();
        let socket = root.path().join("evertraced-v1.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, PermissionsExt::from_mode(0o600)).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _: ClientEnvelope = read_frame_sync(&mut stream, MAX_FRAME_SIZE).unwrap();
            if invalid_ack {
                write_frame_sync(
                    &mut stream,
                    &ServerEnvelope::HandshakeAck(HandshakeAck {
                        protocol_version: PROTOCOL_VERSION,
                        build_id: String::new(),
                        max_frame: MAX_FRAME_SIZE as u32,
                    }),
                    MAX_FRAME_SIZE,
                )
                .unwrap();
            } else {
                std::thread::sleep(Duration::from_millis(75));
            }
        });
        let result = request_recovery_barrier_sync(
            &socket,
            "s16-test",
            locator.clone(),
            Duration::from_millis(20),
        );
        assert_eq!(result.unwrap_err(), expected);
        worker.join().unwrap();
    }
}

#[test]
fn sync_hook_barrier_detects_socket_replacement_after_connect() {
    let root = TempDir::new().unwrap();
    let socket = root.path().join("evertraced-v1.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, PermissionsExt::from_mode(0o600)).unwrap();
    let locator = RecoveryBarrierLocator {
        spool_record_id: "spool-s16".into(),
        recovery_capture_request_id: RecoveryCaptureRequestId::new_v7(),
        pending_revision_id: RevisionId::new_v7(),
    };
    let terminal_revision_id = RevisionId::new_v7();
    let server_locator = locator.clone();
    let server_socket = socket.clone();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _: ClientEnvelope = read_frame_sync(&mut stream, MAX_FRAME_SIZE).unwrap();
        std::fs::remove_file(&server_socket).unwrap();
        let replacement = std::os::unix::net::UnixListener::bind(&server_socket).unwrap();
        std::fs::set_permissions(&server_socket, PermissionsExt::from_mode(0o600)).unwrap();
        write_frame_sync(
            &mut stream,
            &ServerEnvelope::HandshakeAck(HandshakeAck {
                protocol_version: PROTOCOL_VERSION,
                build_id: "daemon-s16".into(),
                max_frame: MAX_FRAME_SIZE as u32,
            }),
            MAX_FRAME_SIZE,
        )
        .unwrap();
        let command: ClientEnvelope = read_frame_sync(&mut stream, MAX_FRAME_SIZE).unwrap();
        let ClientEnvelope::Command(command) = command else {
            panic!("expected recovery command");
        };
        write_frame_sync(
            &mut stream,
            &ServerEnvelope::Response(evertrace_protocol::response::ResponseEnvelope {
                request_id: command.request_id,
                response: evertrace_protocol::response::Response::RecoveryTerminal(
                    evertrace_protocol::response::RecoveryTerminalResponse {
                        recovery_capture_request_id: server_locator.recovery_capture_request_id,
                        pending_revision_id: server_locator.pending_revision_id,
                        terminal_revision_id,
                        status: RecoveryRequestStatus::TimedOut,
                        recovery_bundle_id: None,
                        durable_terminal_proven: true,
                    },
                ),
            }),
            MAX_FRAME_SIZE,
        )
        .unwrap();
        drop(replacement);
    });
    assert_eq!(
        request_recovery_barrier_sync(&socket, "s16-test", locator, Duration::from_secs(1),)
            .unwrap_err(),
        SyncProtocolError::Connect
    );
    worker.join().unwrap();
}

#[tokio::test]
async fn typed_async_dispatcher_serves_the_bounded_sync_hook_client_over_uds() {
    let root = TempDir::new().unwrap();
    std::fs::set_permissions(root.path(), PermissionsExt::from_mode(0o700)).unwrap();
    let server = LocalServer::bind(root.path(), ServerOptions::new("daemon-s16")).unwrap();
    let socket = server.socket_path().to_path_buf();
    let locator = RecoveryBarrierLocator {
        spool_record_id: "spool-s16".into(),
        recovery_capture_request_id: RecoveryCaptureRequestId::new_v7(),
        pending_revision_id: RevisionId::new_v7(),
    };
    let terminal_revision_id = RevisionId::new_v7();
    let expected = locator.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(server.run_dispatch(shutdown_rx, move |command| {
        let expected = expected.clone();
        async move {
            match command {
                evertrace_protocol::command::Command::RecoveryBarrier(value)
                    if value == expected =>
                {
                    Ok(Response::RecoveryTerminal(RecoveryTerminalResponse {
                        recovery_capture_request_id: value.recovery_capture_request_id,
                        pending_revision_id: value.pending_revision_id,
                        terminal_revision_id,
                        status: RecoveryRequestStatus::TimedOut,
                        recovery_bundle_id: None,
                        durable_terminal_proven: true,
                    }))
                }
                _ => Err(evertrace_domain::error::ErrorCode::InvalidInput),
            }
        }
    }));
    let response = tokio::task::spawn_blocking(move || {
        request_recovery_barrier_sync(&socket, "hook-s16", locator, Duration::from_secs(1))
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.terminal_revision_id, terminal_revision_id);
    shutdown_tx.send(true).unwrap();
    server_task.await.unwrap().unwrap();
}
