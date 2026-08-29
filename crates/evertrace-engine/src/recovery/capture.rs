use super::barrier::RecoveryBarrierLocator;
use super::barrier::{RecoveryDeadline, current_time_us};
use super::bundle::capture_recovery_bundle_until;
use super::{
    RecoveryBudget, RecoveryCaptureFacts, RecoveryCaptureItem, RecoveryError, RecoveryItemKind,
};
use evertrace_capture::CasStore;
use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    evidence::hex,
    repository::{
        RecoveryBundle, RecoveryCaptureRequest, RecoveryCaptureStatus, RecoveryOmission,
        RecoveryOmissionReason, RecoveryRequestStatus, WorktreeSnapshot,
    },
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct PreparedRecoveryCapture {
    pub(super) snapshot: Option<WorktreeSnapshot>,
    pub(super) bundle: Option<RecoveryBundle>,
    pub(super) status: RecoveryRequestStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureSyncPoint {
    AfterInitialProbe,
    BeforeFinalRevalidation,
}

pub(super) struct PrepareCaptureContext<'a> {
    pub(super) runtime: &'a evertrace_capture::RuntimeSnapshot,
    pub(super) locator: &'a RecoveryBarrierLocator,
    pub(super) pending: &'a RecoveryCaptureRequest,
    pub(super) adapter_manifest_id: &'a str,
    pub(super) target_path: &'a std::path::Path,
    pub(super) pinned_root: &'a evertrace_capture::ConfinedRoot,
    pub(super) protected_target_paths: Vec<std::path::PathBuf>,
    pub(super) repository_view: &'a evertrace_store::repository::RepositoryCurrentView,
    pub(super) attempt_anchor_ids: Vec<evertrace_domain::ids::AttemptId>,
    pub(super) artifact_refs: Vec<String>,
    pub(super) config_and_run_refs: Vec<String>,
    pub(super) cas: &'a CasStore,
    pub(super) deadline: RecoveryDeadline,
}

pub(super) fn prepare_capture(
    context: PrepareCaptureContext<'_>,
) -> Result<PreparedRecoveryCapture, RecoveryError> {
    prepare_capture_inner(context, |_| {})
}

fn prepare_capture_inner<F>(
    context: PrepareCaptureContext<'_>,
    mut sync: F,
) -> Result<PreparedRecoveryCapture, RecoveryError>
where
    F: FnMut(CaptureSyncPoint),
{
    let PrepareCaptureContext {
        runtime,
        locator,
        pending,
        adapter_manifest_id,
        target_path,
        pinned_root,
        protected_target_paths,
        repository_view,
        attempt_anchor_ids,
        artifact_refs,
        config_and_run_refs,
        cas,
        deadline,
    } = context;
    if deadline.expired() {
        return Ok(PreparedRecoveryCapture {
            snapshot: None,
            bundle: None,
            status: RecoveryRequestStatus::TimedOut,
        });
    }
    let limits = recovery_probe_limits(runtime, deadline)?;
    let pinned_cwd = pinned_root
        .proc_cwd_path()
        .map_err(|_| RecoveryError::NotAdmitted)?;
    let captured_at_us = current_time_us();
    let snapshot_evidence = crate::repository::probe_repository_pinned(
        &pinned_cwd,
        target_path,
        evertrace_domain::repository::FilesystemIdentity {
            device: pinned_root.identity().device,
            inode: pinned_root.identity().inode,
        },
        crate::repository::HostTrustDecision::Trusted,
        &[format!("spool:{}", locator.spool_record_id)],
        captured_at_us,
        &limits,
        &[],
        &[],
    )
    .map_err(|_| RecoveryError::Probe)?;
    validate_recovery_target(repository_view, pending, target_path, &snapshot_evidence)?;
    let pinned_identity = pinned_root.identity();
    if snapshot_evidence.worktree_root_filesystem
        != Some(evertrace_domain::repository::FilesystemIdentity {
            device: pinned_identity.device,
            inode: pinned_identity.inode,
        })
    {
        return Err(RecoveryError::NotAdmitted);
    }
    let protected_targets =
        validate_protected_targets(pinned_root, target_path, &protected_target_paths, deadline)?;
    let before = crate::repository::probe_recovery_capture_scoped_pinned(
        &pinned_cwd,
        evertrace_domain::repository::FilesystemIdentity {
            device: pinned_root.identity().device,
            inode: pinned_root.identity().inode,
        },
        &limits,
        pending.untracked_capture_scope,
    )
    .map_err(|_| RecoveryError::Probe)?;
    sync(CaptureSyncPoint::AfterInitialProbe);
    if deadline.expired() && before.fingerprint.is_none() {
        return Ok(PreparedRecoveryCapture {
            snapshot: None,
            bundle: None,
            status: RecoveryRequestStatus::TimedOut,
        });
    }
    let omission_reasons = snapshot_evidence
        .omissions
        .iter()
        .filter_map(|omission| {
            omission
                .field
                .snapshot_field()
                .map(|field| (field, omission.reason))
        })
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .map(|(field, reason)| evertrace_domain::repository::SnapshotOmission { field, reason })
        .collect::<Vec<_>>();
    let snapshot = WorktreeSnapshot {
        worktree_snapshot_id: evertrace_domain::ids::WorktreeSnapshotId::new_v7(),
        worktree_instance_id: pending.worktree_instance_id,
        head_oid: snapshot_evidence
            .head_oid
            .as_ref()
            .map(|oid| oid.as_str().to_owned()),
        tree_oid: snapshot_evidence
            .tree_oid
            .as_ref()
            .map(|oid| oid.as_str().to_owned()),
        branch_ref: snapshot_evidence.branch_ref.clone(),
        detached_head: snapshot_evidence.detached_head.unwrap_or(false),
        tracked_diff_digest: snapshot_evidence.tracked_diff_digest.clone(),
        index_digest: snapshot_evidence.index_digest.clone(),
        untracked_manifest_digest: snapshot_evidence.untracked_manifest_digest.clone(),
        relevant_anchor_digests: Vec::new(),
        dependency_fingerprints: Vec::new(),
        toolchain_fingerprint: None,
        git_operation: snapshot_evidence.git_operation,
        captured_at_us,
        evidence_refs: snapshot_evidence.evidence_refs.clone(),
        capture_status: if snapshot_evidence.unavailable_reason.is_some() {
            evertrace_domain::repository::SnapshotCaptureStatus::Unavailable
        } else if omission_reasons.is_empty() {
            evertrace_domain::repository::SnapshotCaptureStatus::Complete
        } else {
            evertrace_domain::repository::SnapshotCaptureStatus::Partial
        },
        omission_reasons,
    };
    snapshot.validate().map_err(|_| RecoveryError::Probe)?;

    let mut items = Vec::new();
    if let Some(bytes) = before
        .tracked_diff
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        items.push(RecoveryCaptureItem {
            item_ref: "git:tracked_diff".into(),
            kind: RecoveryItemKind::TrackedDiff,
            bytes: bytes.clone(),
            relative_path: None,
            critical: true,
            metadata_only: false,
        });
    }
    if let Some(bytes) = before.index_diff.as_ref().filter(|value| !value.is_empty()) {
        items.push(RecoveryCaptureItem {
            item_ref: "git:index_diff".into(),
            kind: RecoveryItemKind::IndexState,
            bytes: bytes.clone(),
            relative_path: None,
            critical: true,
            metadata_only: false,
        });
    }
    let mut omissions = git_capture_omissions(&before.omissions);
    let key_store = evertrace_capture::DeviceKeyStore::new(runtime.device_key_dir.clone());
    let key = key_store.load().map_err(|_| RecoveryError::Protection)?;
    let captured_targets = protected_targets
        .into_iter()
        .map(|(relative, identity)| {
            Ok(CapturedProtectedTargetFence {
                item_ref: safe_path_ref("target", &relative, &key)?,
                relative,
                identity,
            })
        })
        .collect::<Result<Vec<_>, RecoveryError>>()?;
    let tracked_bytes = items.iter().try_fold(0_u64, |total, item| {
        total.checked_add(u64::try_from(item.bytes.len()).ok()?)
    });
    let tracked_bytes = tracked_bytes.ok_or(RecoveryError::Budget)?;
    let (untracked_items, untracked_omissions, captured_untracked) = capture_untracked_items(
        pinned_root,
        &before.untracked_paths,
        &key,
        runtime,
        tracked_bytes,
        deadline,
    );
    items.extend(untracked_items);
    omissions.extend(untracked_omissions);
    sync(CaptureSyncPoint::BeforeFinalRevalidation);

    let after = if deadline.expired() || pinned_root.revalidate().is_err() {
        None
    } else {
        Some(
            crate::repository::probe_recovery_capture_scoped_pinned(
                &pinned_cwd,
                evertrace_domain::repository::FilesystemIdentity {
                    device: pinned_root.identity().device,
                    inode: pinned_root.identity().inode,
                },
                &limits,
                pending.untracked_capture_scope,
            )
            .map_err(|_| RecoveryError::Probe)?,
        )
    };
    let before_fingerprint = recovery_fence_fingerprint(
        before.fingerprint.as_deref(),
        &captured_untracked,
        &captured_targets,
    )?;
    let after_untracked = after.as_ref().and_then(|_| {
        let verified =
            verify_untracked_items(pinned_root, &captured_untracked, &key, runtime, deadline)
                .ok()?;
        pinned_root.revalidate().ok()?;
        Some(verified)
    });
    let after_targets = after.as_ref().and_then(|_| {
        let verified = verify_protected_targets(pinned_root, &captured_targets, deadline).ok()?;
        pinned_root.revalidate().ok()?;
        Some(verified)
    });
    let after_fingerprint = match (
        after.as_ref(),
        after_untracked.as_ref(),
        after_targets.as_ref(),
    ) {
        (Some(after), Some(untracked), Some(targets)) => {
            recovery_fence_fingerprint(after.fingerprint.as_deref(), untracked, targets)?
        }
        _ => None,
    };
    if after_targets.is_none() && !captured_targets.is_empty() {
        omissions.extend(captured_targets.iter().map(|target| RecoveryOmission {
            item_ref: target.item_ref.clone(),
            reason: RecoveryOmissionReason::ConcurrentChange,
            metadata_ref: None,
        }));
    }
    if deadline.expired()
        && !omissions
            .iter()
            .any(|value| value.item_ref == "recovery_barrier_deadline")
    {
        omissions.push(RecoveryOmission {
            item_ref: "recovery_barrier_deadline".into(),
            reason: RecoveryOmissionReason::TimeBudgetExceeded,
            metadata_ref: None,
        });
    }
    let should_create_bundle = !items.is_empty()
        || !omissions.is_empty()
        || !artifact_refs.is_empty()
        || !config_and_run_refs.is_empty()
        || before_fingerprint.is_none()
        || after_fingerprint.is_none()
        || before_fingerprint != after_fingerprint;
    let bundle = if should_create_bundle {
        Some(capture_recovery_bundle_until(
            RecoveryCaptureFacts {
                snapshot: snapshot.clone(),
                request_id: pending.recovery_capture_request_id,
                adapter_manifest_id: adapter_manifest_id.into(),
                mutation_manifest_version: 1,
                before_fingerprint,
                after_fingerprint,
                items,
                omissions,
                artifact_refs,
                metadata_artifact_refs: Vec::new(),
                config_and_run_refs,
                attempt_anchor_ids,
                captured_at_us,
            },
            RecoveryBudget {
                max_item_bytes: runtime.recovery_max_bundle_bytes,
                max_untracked_item_bytes: runtime.recovery_max_untracked_file_bytes,
                max_bundle_bytes: runtime.recovery_max_bundle_bytes,
            },
            cas,
            &key_store,
            Some(deadline.0),
        )?)
    } else {
        None
    };
    let status = recovery_terminal_status(deadline.expired(), bundle.as_ref());
    Ok(PreparedRecoveryCapture {
        snapshot: Some(snapshot),
        bundle,
        status,
    })
}

pub(super) fn validate_recovery_target(
    view: &evertrace_store::repository::RepositoryCurrentView,
    pending: &RecoveryCaptureRequest,
    target_path: &std::path::Path,
    probe: &crate::repository::GitProbeEvidence,
) -> Result<(), RecoveryError> {
    use evertrace_domain::repository::WorktreeLifecycle;

    let worktree = view
        .worktrees
        .get(&pending.worktree_instance_id)
        .ok_or(RecoveryError::NotAdmitted)?;
    let repository = view
        .repositories
        .get(&pending.repository_instance_id)
        .ok_or(RecoveryError::NotAdmitted)?;
    let target = target_path.to_str().ok_or(RecoveryError::NotAdmitted)?;
    let latest_admin = worktree
        .git_admin_path_history
        .last()
        .map(|entry| entry.path.as_str());
    let matching_entries = probe
        .worktree_entries
        .iter()
        .filter(|entry| entry.path == target)
        .count();
    if worktree.lifecycle != WorktreeLifecycle::Active
        || worktree.repository_instance_id != pending.repository_instance_id
        || worktree.current_path.as_deref() != Some(target)
        || probe.unavailable_reason.is_some()
        || probe.worktree_root.as_deref() != Some(target)
        || probe.common_dir_filesystem != repository.common_dir_filesystem
        || probe.object_format != repository.object_format
        || !probe.worktree_list_complete
        || matching_entries != 1
        || probe.git_dir.as_deref() != latest_admin
    {
        return Err(RecoveryError::NotAdmitted);
    }
    Ok(())
}

pub(super) fn recovery_terminal_status(
    deadline_exhausted: bool,
    bundle: Option<&RecoveryBundle>,
) -> RecoveryRequestStatus {
    if deadline_exhausted {
        return RecoveryRequestStatus::TimedOut;
    }
    match bundle {
        Some(value) if value.capture_status == RecoveryCaptureStatus::Complete => {
            RecoveryRequestStatus::Complete
        }
        Some(_) => RecoveryRequestStatus::Partial,
        None => RecoveryRequestStatus::Skipped,
    }
}

fn recovery_probe_limits(
    runtime: &evertrace_capture::RuntimeSnapshot,
    deadline: RecoveryDeadline,
) -> Result<crate::repository::ProbeLimits, RecoveryError> {
    Ok(crate::repository::ProbeLimits {
        max_stdout_bytes: usize::try_from(runtime.recovery_max_bundle_bytes)
            .map_err(|_| RecoveryError::Budget)?,
        max_stderr_bytes: 16 << 10,
        max_records: 4096,
        max_untracked_paths: 128,
        max_diff_bytes: usize::try_from(runtime.recovery_max_bundle_bytes)
            .map_err(|_| RecoveryError::Budget)?,
        max_duration_ms: deadline.remaining_ms()?,
    })
}

pub(super) fn tracked_paths(
    root: &std::path::Path,
    index_entries: Option<&[u8]>,
) -> Result<Vec<evertrace_codex::recovery::ProtectedPath>, RecoveryError> {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    let entries = index_entries.ok_or(RecoveryError::NotAdmitted)?;
    let mut paths = BTreeSet::new();
    for record in entries
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(RecoveryError::NotAdmitted)?;
        let raw = &record[tab + 1..];
        if raw.is_empty() {
            return Err(RecoveryError::NotAdmitted);
        }
        #[cfg(unix)]
        let relative = std::path::PathBuf::from(std::ffi::OsString::from_vec(raw.to_vec()));
        #[cfg(not(unix))]
        let relative = std::path::PathBuf::from(
            std::str::from_utf8(raw).map_err(|_| RecoveryError::NotAdmitted)?,
        );
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(RecoveryError::NotAdmitted);
        }
        paths.insert(root.join(relative));
    }
    Ok(paths
        .into_iter()
        .map(|path| evertrace_codex::recovery::ProtectedPath {
            path,
            kind: evertrace_codex::recovery::ProtectedPathKind::Tracked,
        })
        .collect())
}

struct CapturedUntrackedFence {
    relative: std::path::PathBuf,
    item_ref: String,
    identity: evertrace_capture::ConfinedFileIdentity,
    content_token: [u8; 32],
}

struct CapturedProtectedTargetFence {
    relative: std::path::PathBuf,
    item_ref: String,
    identity: evertrace_capture::ConfinedFileIdentity,
}

fn validate_protected_targets(
    root: &evertrace_capture::ConfinedRoot,
    target_root: &std::path::Path,
    targets: &[std::path::PathBuf],
    deadline: RecoveryDeadline,
) -> Result<Vec<(std::path::PathBuf, evertrace_capture::ConfinedFileIdentity)>, RecoveryError> {
    targets
        .iter()
        .map(|target| {
            let relative = target
                .strip_prefix(target_root)
                .map_err(|_| RecoveryError::NotAdmitted)?;
            if relative.as_os_str().is_empty()
                || relative.is_absolute()
                || relative.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::CurDir
                            | std::path::Component::ParentDir
                            | std::path::Component::RootDir
                            | std::path::Component::Prefix(_)
                    )
                })
            {
                return Err(RecoveryError::NotAdmitted);
            }
            let metadata = safe_confined_metadata(root, relative, deadline)
                .ok_or(RecoveryError::NotAdmitted)?;
            Ok((relative.to_path_buf(), metadata.identity))
        })
        .collect()
}

fn verify_protected_targets(
    root: &evertrace_capture::ConfinedRoot,
    before: &[CapturedProtectedTargetFence],
    deadline: RecoveryDeadline,
) -> Result<Vec<CapturedProtectedTargetFence>, RecoveryError> {
    before
        .iter()
        .map(|target| {
            let metadata = safe_confined_metadata(root, &target.relative, deadline)
                .ok_or(RecoveryError::Probe)?;
            Ok(CapturedProtectedTargetFence {
                relative: target.relative.clone(),
                item_ref: target.item_ref.clone(),
                identity: metadata.identity,
            })
        })
        .collect()
}

mod replacement_proof {
    #[cfg(test)]
    use super::*;
    #[cfg(test)]
    use evertrace_capture::{
        CasDigest, ConfinedRoot, DeviceKeyStore, RecoveryGateMode, RuntimeSnapshot,
    };
    #[cfg(test)]
    use evertrace_domain::{
        ids::{RecoveryCaptureRequestId, RepositoryId, WorktreeId},
        repository::{
            DestructiveClass, DestructiveDetectionStatus, FilesystemIdentity, GitObjectFormat,
            GitRegistrationState, PathObservation, RecoveryCaptureRequest, RecoveryRequestStatus,
            RepositoryInstance, UntrackedCaptureScope, WorktreeInstance, WorktreeKind,
            WorktreeLifecycle,
        },
        revision::RevisionId,
    };
    #[cfg(test)]
    use evertrace_store::repository::RepositoryCurrentView;
    #[cfg(test)]
    use std::{
        os::unix::fs::MetadataExt,
        str::FromStr,
        time::{Duration, Instant},
    };

    #[cfg(test)]
    fn git(root: &std::path::Path, args: &[&str]) {
        assert!(
            std::process::Command::new("git")
                .args(args)
                .current_dir(root)
                .status()
                .unwrap()
                .success()
        );
    }

    #[cfg(test)]
    fn run_replacement_capture(restore_original: bool) {
        let base = std::env::temp_dir().join(format!(
            "evertrace-s16-{}-{}",
            restore_original,
            RevisionId::new_v7()
        ));
        let target = base.join("worktree");
        let replacement = base.join("replacement");
        let pinned_location = base.join("pinned-a");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(&replacement).unwrap();
        git(&target, &["init", "--quiet"]);
        git(&target, &["config", "user.name", "EverTrace"]);
        git(
            &target,
            &["config", "user.email", "evertrace@example.invalid"],
        );
        std::fs::write(target.join("tracked"), b"base").unwrap();
        git(&target, &["add", "tracked"]);
        git(&target, &["commit", "--quiet", "-m", "base"]);
        std::fs::write(target.join("payload"), b"pinned-a-bytes").unwrap();
        git(&replacement, &["init", "--quiet"]);
        std::fs::write(replacement.join("payload"), b"replacement-b-bytes").unwrap();

        let key_dir = base.join("keys");
        DeviceKeyStore::new(&key_dir).load_or_create().unwrap();
        let cas_dir = base.join("cas");
        let cas = CasStore::open(&cas_dir).unwrap();
        let pinned = ConfinedRoot::open(&target).unwrap();
        let repository_id = RepositoryId::new_v7();
        let worktree_id = WorktreeId::new_v7();
        let path = target.to_string_lossy().into_owned();
        let git_dir = target.join(".git");
        let git_meta = std::fs::metadata(&git_dir).unwrap();
        let observation = |value: String, evidence: &str| PathObservation {
            path: value,
            first_observed_at_us: 1,
            last_observed_at_us: 1,
            evidence_refs: vec![evidence.into()],
        };
        let repository = RepositoryInstance {
            repository_id,
            repository_revision: 1,
            predecessor_revision: None,
            current_path: path.clone(),
            path_history: vec![observation(path.clone(), "repository-path")],
            git_common_dir_path: Some(git_dir.to_string_lossy().into_owned()),
            common_dir_filesystem: Some(FilesystemIdentity {
                device: git_meta.dev(),
                inode: git_meta.ino(),
            }),
            object_format: Some(GitObjectFormat::Sha1),
            remote_fingerprints: Vec::new(),
            derived_from: None,
            identity_evidence_refs: vec!["repository-identity".into()],
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
            path_history: vec![observation(path.clone(), "worktree-path")],
            git_admin_path_history: vec![observation(
                git_dir.to_string_lossy().into_owned(),
                "git-admin",
            )],
            git_registration_state: GitRegistrationState::Registered,
            current_snapshot_id: None,
            created_event_ref: "created".into(),
            terminal_event_ref: None,
            recreated_from_worktree_instance_id: None,
            recorded_at_us: 1,
        };
        let mut repository_view = RepositoryCurrentView::default();
        repository_view
            .repositories
            .insert(repository_id, repository);
        repository_view.worktrees.insert(worktree_id, worktree);
        let pending = RecoveryCaptureRequest {
            recovery_capture_request_id: RecoveryCaptureRequestId::new_v7(),
            request_revision_id: RevisionId::new_v7(),
            parent_request_revision_id: None,
            trigger_event_id: "replacement-test".into(),
            repository_instance_id: repository_id,
            worktree_instance_id: worktree_id,
            pre_operation_snapshot_id: None,
            command_fingerprint: "ab".repeat(32),
            destructive_class: DestructiveClass::GitClean,
            untracked_capture_scope: UntrackedCaptureScope::Standard,
            detection_status: DestructiveDetectionStatus::Matched,
            request_status: RecoveryRequestStatus::Pending,
            recovery_bundle_id: None,
            reason_codes: Vec::new(),
            started_at_us: current_time_us(),
            finished_at_us: None,
            effective_config_hash: [7; 32],
        };
        let runtime = RuntimeSnapshot {
            snapshot_version: evertrace_capture::RUNTIME_SNAPSHOT_VERSION,
            generation: 1,
            device_key_dir: key_dir,
            cas_dir: cas_dir.clone(),
            spool_dir: base.join("spool"),
            main_high_watermark_bytes: 1 << 20,
            main_low_watermark_bytes: 1,
            max_main_files: 4,
            emergency_slots: 1,
            effective_config_hash: [7; 32],
            recovery_gate: RecoveryGateMode::Active,
            recovery_adapter_manifest_id: Some("adapter-s16".into()),
            recovery_classifier_revision: 1,
            recovery_socket_path: base.join("runtime.sock"),
            recovery_preflight_timeout_ms: 10_000,
            recovery_max_bundle_bytes: 1 << 20,
            recovery_max_untracked_file_bytes: 1 << 16,
            recovery_max_untracked_total_bytes: 1 << 18,
            recall_cue_gate: evertrace_capture::RecallCueGateMode::Disabled,
            recall_cue_adapter_manifest_id: None,
            recall_cues: Vec::new(),
        };
        let locator = RecoveryBarrierLocator {
            spool_record_id: "spool-replacement".into(),
            recovery_capture_request_id: pending.recovery_capture_request_id,
            pending_revision_id: pending.request_revision_id,
        };
        let prepared = prepare_capture_inner(
            PrepareCaptureContext {
                runtime: &runtime,
                locator: &locator,
                pending: &pending,
                adapter_manifest_id: "adapter-s16",
                target_path: &target,
                pinned_root: &pinned,
                protected_target_paths: Vec::new(),
                repository_view: &repository_view,
                attempt_anchor_ids: Vec::new(),
                artifact_refs: Vec::new(),
                config_and_run_refs: Vec::new(),
                cas: &cas,
                deadline: RecoveryDeadline(Instant::now() + Duration::from_secs(10)),
            },
            |point| {
                if point == CaptureSyncPoint::AfterInitialProbe {
                    std::fs::rename(&target, &pinned_location).unwrap();
                    std::fs::rename(&replacement, &target).unwrap();
                    if restore_original {
                        std::fs::rename(&target, &replacement).unwrap();
                        std::fs::rename(&pinned_location, &target).unwrap();
                    }
                }
            },
        )
        .unwrap();
        if !restore_original {
            assert_eq!(prepared.status, RecoveryRequestStatus::Partial);
        }
        let bundle = prepared.bundle.unwrap();
        assert!(!serde_json::to_string(&bundle).unwrap().contains("/proc/"));
        for content_ref in &bundle.untracked_file_blob_refs {
            let payload = cas
                .read(&CasDigest::from_str(&content_ref.payload.cas_ref).unwrap())
                .unwrap();
            assert_ne!(payload, b"replacement-b-bytes");
            if cas
                .read(
                    &CasDigest::from_str(
                        &content_ref
                            .protected_relative_path
                            .as_ref()
                            .unwrap()
                            .cas_ref,
                    )
                    .unwrap(),
                )
                .unwrap()
                == b"payload"
            {
                assert_eq!(payload, b"pinned-a-bytes");
            }
        }
        drop(pinned);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn pinned_capture_replacement_never_publishes_replacement_bytes_as_complete() {
        run_replacement_capture(false);
    }

    #[test]
    fn pinned_capture_aba_reads_only_the_original_open_file_description() {
        run_replacement_capture(true);
    }
}

type UntrackedCaptureResult = (
    Vec<RecoveryCaptureItem>,
    Vec<RecoveryOmission>,
    Vec<CapturedUntrackedFence>,
);

fn capture_untracked_items(
    confined: &evertrace_capture::ConfinedRoot,
    paths: &[std::path::PathBuf],
    key: &evertrace_capture::DeviceKey,
    runtime: &evertrace_capture::RuntimeSnapshot,
    tracked_bytes: u64,
    deadline: RecoveryDeadline,
) -> UntrackedCaptureResult {
    let mut items = Vec::new();
    let mut omissions = Vec::new();
    let mut captured = Vec::new();
    let mut untracked_bytes = 0_u64;
    let mut bundle_bytes = tracked_bytes;
    for relative in paths.iter().take(128) {
        let Ok(item_ref) = safe_untracked_ref(relative, key) else {
            omissions.push(untracked_omission(
                "untracked:unavailable",
                RecoveryOmissionReason::Unreadable,
                None,
            ));
            continue;
        };
        let metadata = safe_confined_metadata(confined, relative, deadline);
        if relative.components().any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some(".git" | "target" | "node_modules" | "build" | "dist")
            )
        }) {
            omissions.push(RecoveryOmission {
                item_ref: item_ref.clone(),
                reason: RecoveryOmissionReason::RegenerableBuildOutput,
                metadata_ref: Some(untracked_metadata_ref(&item_ref, metadata.as_ref())),
            });
            continue;
        }
        if deadline.expired() {
            omissions.push(untracked_omission(
                &item_ref,
                RecoveryOmissionReason::TimeBudgetExceeded,
                metadata.as_ref(),
            ));
            continue;
        }
        let total_remaining = runtime
            .recovery_max_untracked_total_bytes
            .saturating_sub(untracked_bytes);
        let bundle_remaining = runtime
            .recovery_max_bundle_bytes
            .saturating_sub(bundle_bytes);
        match confined.read(
            relative,
            evertrace_capture::ConfinedReadLimits {
                single_file_remaining: runtime.recovery_max_untracked_file_bytes,
                untracked_total_remaining: total_remaining,
                bundle_remaining,
                deadline: deadline.0,
            },
        ) {
            Ok(file) => {
                let Ok(length) = u64::try_from(file.bytes.len()) else {
                    omissions.push(untracked_omission(
                        &item_ref,
                        RecoveryOmissionReason::BundleBudgetExceeded,
                        metadata.as_ref(),
                    ));
                    continue;
                };
                let Ok(content_token) = evertrace_capture::recovery_content_token(&file.bytes, key)
                else {
                    omissions.push(untracked_omission(
                        &item_ref,
                        RecoveryOmissionReason::Unreadable,
                        metadata.as_ref(),
                    ));
                    continue;
                };
                let Some(next_untracked) = untracked_bytes.checked_add(length) else {
                    omissions.push(untracked_omission(
                        &item_ref,
                        RecoveryOmissionReason::BundleBudgetExceeded,
                        metadata.as_ref(),
                    ));
                    continue;
                };
                let Some(next_bundle) = bundle_bytes.checked_add(length) else {
                    omissions.push(untracked_omission(
                        &item_ref,
                        RecoveryOmissionReason::BundleBudgetExceeded,
                        metadata.as_ref(),
                    ));
                    continue;
                };
                untracked_bytes = next_untracked;
                bundle_bytes = next_bundle;
                captured.push(CapturedUntrackedFence {
                    relative: relative.clone(),
                    item_ref: item_ref.clone(),
                    identity: file.identity,
                    content_token,
                });
                items.push(RecoveryCaptureItem {
                    item_ref,
                    kind: RecoveryItemKind::UntrackedFile,
                    bytes: file.bytes,
                    relative_path: Some(relative_path_bytes(relative)),
                    critical: false,
                    metadata_only: false,
                });
            }
            Err(error) => {
                let reason = match error {
                    evertrace_capture::ConfinedReadError::Deadline => {
                        RecoveryOmissionReason::TimeBudgetExceeded
                    }
                    evertrace_capture::ConfinedReadError::LimitExceeded {
                        kind,
                        metadata: safe,
                    } => {
                        let reason = match kind {
                            evertrace_capture::ConfinedLimitKind::SingleFile => {
                                RecoveryOmissionReason::FileTooLarge
                            }
                            evertrace_capture::ConfinedLimitKind::UntrackedTotal => {
                                RecoveryOmissionReason::UntrackedTotalExceeded
                            }
                            evertrace_capture::ConfinedLimitKind::Bundle => {
                                RecoveryOmissionReason::BundleBudgetExceeded
                            }
                        };
                        omissions.push(untracked_omission(&item_ref, reason, Some(&safe)));
                        continue;
                    }
                    evertrace_capture::ConfinedReadError::UnsupportedType
                    | evertrace_capture::ConfinedReadError::InvalidPath => {
                        RecoveryOmissionReason::UnsupportedKind
                    }
                    evertrace_capture::ConfinedReadError::Changed => {
                        RecoveryOmissionReason::ConcurrentChange
                    }
                    _ => RecoveryOmissionReason::Unreadable,
                };
                omissions.push(untracked_omission(&item_ref, reason, metadata.as_ref()));
            }
        }
    }
    (items, omissions, captured)
}

fn safe_confined_metadata(
    root: &evertrace_capture::ConfinedRoot,
    relative: &std::path::Path,
    deadline: RecoveryDeadline,
) -> Option<evertrace_capture::ConfinedFileMetadata> {
    match root.read(
        relative,
        evertrace_capture::ConfinedReadLimits {
            single_file_remaining: 0,
            untracked_total_remaining: 0,
            bundle_remaining: 0,
            deadline: deadline.0,
        },
    ) {
        Ok(file) => Some(evertrace_capture::ConfinedFileMetadata {
            identity: file.identity,
        }),
        Err(evertrace_capture::ConfinedReadError::LimitExceeded { metadata, .. }) => Some(metadata),
        _ => None,
    }
}

fn verify_untracked_items(
    confined: &evertrace_capture::ConfinedRoot,
    before: &[CapturedUntrackedFence],
    key: &evertrace_capture::DeviceKey,
    runtime: &evertrace_capture::RuntimeSnapshot,
    deadline: RecoveryDeadline,
) -> Result<Vec<CapturedUntrackedFence>, RecoveryError> {
    let mut verified = Vec::with_capacity(before.len());
    let mut total = 0_u64;
    for captured in before {
        let file = confined
            .read(
                &captured.relative,
                evertrace_capture::ConfinedReadLimits {
                    single_file_remaining: runtime.recovery_max_untracked_file_bytes,
                    untracked_total_remaining: runtime
                        .recovery_max_untracked_total_bytes
                        .saturating_sub(total),
                    bundle_remaining: runtime.recovery_max_bundle_bytes,
                    deadline: deadline.0,
                },
            )
            .map_err(|_| RecoveryError::Probe)?;
        total = total
            .checked_add(u64::try_from(file.bytes.len()).map_err(|_| RecoveryError::Budget)?)
            .ok_or(RecoveryError::Budget)?;
        let content_token = evertrace_capture::recovery_content_token(&file.bytes, key)
            .map_err(|_| RecoveryError::Protection)?;
        verified.push(CapturedUntrackedFence {
            relative: captured.relative.clone(),
            item_ref: captured.item_ref.clone(),
            identity: file.identity,
            content_token,
        });
    }
    Ok(verified)
}

fn recovery_fence_fingerprint(
    git_fingerprint: Option<&str>,
    untracked: &[CapturedUntrackedFence],
    protected_targets: &[CapturedProtectedTargetFence],
) -> Result<Option<String>, RecoveryError> {
    let Some(git_fingerprint) = git_fingerprint else {
        return Ok(None);
    };
    let entries = untracked
        .iter()
        .map(|value| {
            CanonicalValue::Map(vec![
                (
                    "path_token".into(),
                    CanonicalValue::String(value.item_ref.clone()),
                ),
                (
                    "device".into(),
                    CanonicalValue::Integer(i128::from(value.identity.device)),
                ),
                (
                    "inode".into(),
                    CanonicalValue::Integer(i128::from(value.identity.inode)),
                ),
                (
                    "size".into(),
                    CanonicalValue::Integer(i128::from(value.identity.size)),
                ),
                (
                    "mtime_seconds".into(),
                    CanonicalValue::Integer(i128::from(value.identity.mtime_seconds)),
                ),
                (
                    "mtime_nanoseconds".into(),
                    CanonicalValue::Integer(i128::from(value.identity.mtime_nanoseconds)),
                ),
                (
                    "ctime_seconds".into(),
                    CanonicalValue::Integer(i128::from(value.identity.ctime_seconds)),
                ),
                (
                    "ctime_nanoseconds".into(),
                    CanonicalValue::Integer(i128::from(value.identity.ctime_nanoseconds)),
                ),
                (
                    "content_token".into(),
                    CanonicalValue::Bytes(value.content_token.to_vec()),
                ),
            ])
        })
        .collect();
    let protected_target_entries = protected_targets
        .iter()
        .map(|value| {
            CanonicalValue::Map(vec![
                (
                    "path_token".into(),
                    CanonicalValue::String(value.item_ref.clone()),
                ),
                (
                    "device".into(),
                    CanonicalValue::Integer(i128::from(value.identity.device)),
                ),
                (
                    "inode".into(),
                    CanonicalValue::Integer(i128::from(value.identity.inode)),
                ),
                (
                    "size".into(),
                    CanonicalValue::Integer(i128::from(value.identity.size)),
                ),
                (
                    "mtime_seconds".into(),
                    CanonicalValue::Integer(i128::from(value.identity.mtime_seconds)),
                ),
                (
                    "mtime_nanoseconds".into(),
                    CanonicalValue::Integer(i128::from(value.identity.mtime_nanoseconds)),
                ),
                (
                    "ctime_seconds".into(),
                    CanonicalValue::Integer(i128::from(value.identity.ctime_seconds)),
                ),
                (
                    "ctime_nanoseconds".into(),
                    CanonicalValue::Integer(i128::from(value.identity.ctime_nanoseconds)),
                ),
            ])
        })
        .collect();
    let digest = sha256(
        "recovery_mutation_fence_v2",
        2,
        &CanonicalValue::Map(vec![
            (
                "git_fingerprint".into(),
                CanonicalValue::String(git_fingerprint.into()),
            ),
            ("untracked".into(), CanonicalValue::Sequence(entries)),
            (
                "protected_targets".into(),
                CanonicalValue::Sequence(protected_target_entries),
            ),
        ]),
    )
    .map_err(|_| RecoveryError::Protection)?;
    Ok(Some(format!("recovery-fence-v2:{}", hex(&digest))))
}

fn relative_path_bytes(path: &std::path::Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().as_bytes().to_vec()
    }
}

fn untracked_omission(
    item_ref: &str,
    reason: RecoveryOmissionReason,
    metadata: Option<&evertrace_capture::ConfinedFileMetadata>,
) -> RecoveryOmission {
    RecoveryOmission {
        item_ref: item_ref.into(),
        reason,
        metadata_ref: Some(untracked_metadata_ref(item_ref, metadata)),
    }
}

fn untracked_metadata_ref(
    item_ref: &str,
    metadata: Option<&evertrace_capture::ConfinedFileMetadata>,
) -> String {
    let Some(metadata) = metadata else {
        return format!("meta:v1;token={item_ref};kind=unavailable");
    };
    let modified_us = u64::try_from(metadata.identity.mtime_seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000))
        .and_then(|value| value.checked_add(metadata.identity.mtime_nanoseconds / 1_000));
    modified_us.map_or_else(
        || {
            format!(
                "meta:v1;token={item_ref};kind=file;size={}",
                metadata.identity.size
            )
        },
        |value| {
            format!(
                "meta:v1;token={item_ref};kind=file;size={};mtime_us={value}",
                metadata.identity.size
            )
        },
    )
}

fn safe_untracked_ref(
    relative: &std::path::Path,
    key: &evertrace_capture::DeviceKey,
) -> Result<String, RecoveryError> {
    safe_path_ref("untracked", relative, key)
}

fn safe_path_ref(
    kind: &str,
    relative: &std::path::Path,
    key: &evertrace_capture::DeviceKey,
) -> Result<String, RecoveryError> {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    let raw = relative.as_os_str().as_bytes();
    #[cfg(not(unix))]
    let raw = relative.to_string_lossy().as_bytes();
    let protected = evertrace_capture::recovery_path_token(raw, key)
        .map(|value| hex(&value))
        .map_err(|_| RecoveryError::Protection)?;
    Ok(format!("{kind}:{protected}"))
}

fn git_capture_omissions(
    omissions: &[crate::repository::RecoveryGitCaptureOmission],
) -> Vec<RecoveryOmission> {
    omissions
        .iter()
        .map(|omission| RecoveryOmission {
            item_ref: match omission.item {
                crate::repository::RecoveryGitCaptureItem::WorktreeStatus => "git:status",
                crate::repository::RecoveryGitCaptureItem::TrackedDiff => "git:tracked_diff",
                crate::repository::RecoveryGitCaptureItem::IndexDiff => "git:index_diff",
                crate::repository::RecoveryGitCaptureItem::IndexEntries => "git:index_entries",
                crate::repository::RecoveryGitCaptureItem::UntrackedManifest => {
                    "git:untracked_manifest"
                }
            }
            .into(),
            reason: match omission.reason {
                evertrace_domain::repository::ProbeUnavailableReason::OutputLimitExceeded => {
                    RecoveryOmissionReason::BundleBudgetExceeded
                }
                evertrace_domain::repository::ProbeUnavailableReason::Timeout => {
                    RecoveryOmissionReason::TimeBudgetExceeded
                }
                _ => match omission.item {
                    crate::repository::RecoveryGitCaptureItem::TrackedDiff => {
                        RecoveryOmissionReason::CriticalTrackedStateMissing
                    }
                    crate::repository::RecoveryGitCaptureItem::IndexDiff
                    | crate::repository::RecoveryGitCaptureItem::IndexEntries => {
                        RecoveryOmissionReason::CriticalIndexStateMissing
                    }
                    _ => RecoveryOmissionReason::Unreadable,
                },
            },
            metadata_ref: None,
        })
        .collect()
}
