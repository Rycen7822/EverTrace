#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use evertrace_capture::{
    CasDigest, CasStore, ConfinedFile, ConfinedReadLimits, ConfinedRoot, DeviceKeyStore,
};
use evertrace_domain::{
    ids::{CasId, CommandId, RecoveryApplicationId, RecoveryBundleId, RequestId, WorktreeId},
    repository::{
        OrderingIntegrity, RecoveryApplication, RecoveryApplicationKind, RecoveryApplicationStatus,
        RecoveryCaptureStatus, RecoveryInputDeliveryKind, RecoveryInputDeliveryState,
        RecoveryVerificationOutcome, SnapshotCaptureStatus, WorktreeLifecycle,
    },
    revision::RevisionId,
};
use evertrace_store::{
    JournalCommand, JournalEventDraft, JournalPayload,
    projections::{AttemptCurrentView, RecoveryCurrentView},
    repository::RepositoryCurrentView,
};

use super::{
    RecoveryError, RecoveryTicketIssueRequest, RecoveryTicketService,
    application::RecoveryApplicationTicketClaims,
    barrier::{RecoveryMutationFence, current_time_us},
    patch::strict_patch_target,
};
use crate::{WriterHandle, repository};

mod evidence;

const ACTION_ALGORITHM_REVISION: &str = "s17_supervised_patch_v1";
const OUTPUT_LIMIT: usize = 16 << 10;
const POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryUnsupportedReason {
    UnsupportedApplicationKind,
    AmbiguousPatchContent,
    UnsupportedPatchShape,
    RedactedContent,
    IncompleteBundle,
    TargetUnavailable,
    PatchPreflightFailed,
    PhysicalPreflightUnavailable,
    PhysicalPreflightRaced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryRequest {
    pub request_id: RequestId,
    pub recovery_bundle_id: RecoveryBundleId,
    pub target_worktree_instance_id: WorktreeId,
    pub application_kind: RecoveryApplicationKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryActionOutcome {
    Application {
        recovery_application_id: RecoveryApplicationId,
        application_status: RecoveryApplicationStatus,
        replayed: bool,
    },
    Unsupported(RecoveryUnsupportedReason),
}

#[derive(Clone)]
pub struct RecoveryActionService {
    snapshot: evertrace_capture::RuntimeSnapshot,
    writer: WriterHandle,
    fence: RecoveryMutationFence,
    custody: Arc<ActionCustody>,
    #[cfg(test)]
    faults: Arc<TestFaultState>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestFault {
    AdmissionCommit,
    IntentPersistence,
    TerminalApplicationCommit,
    VerifierUnavailable(u8),
    StallAfterSpawn,
    TimeoutAfterSpawn,
    SkipTerminalCapture,
    RaceAffectedStage,
    RaceAffectedHead,
    RaceAdminLocator,
    RaceRootLocator,
    RaceAffectedDuringPostCapture,
    RaceUnrelatedDuringPostCapture,
    NormalFailureUnchanged,
    NormalFailureVerifierUnavailable(u8),
}

#[cfg(test)]
#[derive(Default)]
struct TestFaultState {
    fault: std::sync::Mutex<Option<TestFault>>,
    spawn_count: AtomicUsize,
    last_child_pid: std::sync::atomic::AtomicU32,
}

struct ActionCustody {
    shutting_down: AtomicBool,
    active: AtomicUsize,
    cancelled: Arc<AtomicBool>,
    active_tx: tokio::sync::watch::Sender<usize>,
}

impl Default for ActionCustody {
    fn default() -> Self {
        let (active_tx, _) = tokio::sync::watch::channel(0);
        Self {
            shutting_down: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            cancelled: Arc::new(AtomicBool::new(false)),
            active_tx,
        }
    }
}

impl ActionCustody {
    fn register(&self) -> bool {
        if self.shutting_down.load(Ordering::Acquire) {
            return false;
        }
        let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
        self.active_tx.send_replace(active);
        if self.shutting_down.load(Ordering::Acquire) {
            self.finish();
            return false;
        }
        true
    }

    fn finish(&self) {
        let previous = self.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
        self.active_tx.send_replace(previous.saturating_sub(1));
    }

    async fn shutdown_and_drain(&self) {
        let mut active_rx = self.active_tx.subscribe();
        self.shutting_down.store(true, Ordering::Release);
        self.cancelled.store(true, Ordering::Release);
        while *active_rx.borrow_and_update() != 0 {
            if active_rx.changed().await.is_err() {
                break;
            }
        }
    }
}

struct ActiveAction(Arc<ActionCustody>);

impl Drop for ActiveAction {
    fn drop(&mut self) {
        self.0.finish();
    }
}

struct PreparedPatch {
    claims: RecoveryApplicationTicketClaims,
    patch: Vec<u8>,
    logical_root: PathBuf,
    pinned_root: ConfinedRoot,
    pinned_cwd: PathBuf,
    repository_id: evertrace_domain::ids::RepositoryId,
    affected_relative_path: PathBuf,
    affected_prestate: ConfinedFile,
    affected_git_prestate: repository::AffectedPathGitProof,
    relevant_attempt_anchor_ids: Vec<evertrace_domain::ids::AttemptId>,
    attempt_anchor_claims: Vec<evertrace_domain::repository::RecoveryAttemptAnchorClaim>,
}

impl RecoveryActionService {
    pub async fn supports_compatible_lineage_transfer(
        &self,
        application_id: RecoveryApplicationId,
    ) -> Result<bool, RecoveryError> {
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let recovery = RecoveryCurrentView::from_snapshot(&projected)?;
        let attempts = AttemptCurrentView::from_snapshot(&projected)?;
        Ok(recovery
            .state
            .applications
            .get(&application_id)
            .is_some_and(|application| {
                evidence::current_lineage_transfer_supported(application, &attempts)
            }))
    }

    pub fn new(
        snapshot: evertrace_capture::RuntimeSnapshot,
        writer: WriterHandle,
        fence: RecoveryMutationFence,
    ) -> Self {
        Self {
            snapshot,
            writer,
            fence,
            custody: Arc::new(ActionCustody::default()),
            #[cfg(test)]
            faults: Arc::new(TestFaultState::default()),
        }
    }

    #[cfg(test)]
    fn set_test_fault(&self, fault: TestFault) {
        *self.faults.fault.lock().unwrap() = Some(fault);
    }

    #[cfg(test)]
    fn take_test_fault(&self, expected: TestFault) -> bool {
        let mut fault = self.faults.fault.lock().unwrap();
        if *fault == Some(expected) {
            *fault = None;
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn verifier_unavailable_for_test(&self) -> bool {
        let mut fault = self.faults.fault.lock().unwrap();
        match *fault {
            Some(TestFault::VerifierUnavailable(remaining)) if remaining > 1 => {
                *fault = Some(TestFault::VerifierUnavailable(remaining - 1));
                true
            }
            Some(TestFault::VerifierUnavailable(1)) => {
                *fault = None;
                true
            }
            Some(TestFault::NormalFailureVerifierUnavailable(remaining)) if remaining > 1 => {
                *fault = Some(TestFault::NormalFailureVerifierUnavailable(remaining - 1));
                true
            }
            Some(TestFault::NormalFailureVerifierUnavailable(1)) => {
                *fault = None;
                true
            }
            _ => false,
        }
    }

    #[cfg(not(test))]
    fn verifier_unavailable_for_test(&self) -> bool {
        false
    }

    fn note_child_spawn_for_test(
        &self,
        pid: u32,
        cancellation: &AtomicBool,
        deadline: Instant,
    ) -> Instant {
        #[cfg(test)]
        {
            self.faults.spawn_count.fetch_add(1, Ordering::AcqRel);
            self.faults.last_child_pid.store(pid, Ordering::Release);
            if self.take_test_fault(TestFault::TimeoutAfterSpawn) {
                return Instant::now();
            }
            if self.take_test_fault(TestFault::StallAfterSpawn) {
                while !cancellation.load(Ordering::Acquire) && Instant::now() < deadline {
                    thread::sleep(POLL_INTERVAL);
                }
            }
        }
        #[cfg(not(test))]
        let _ = (pid, cancellation, deadline);
        deadline
    }

    #[cfg(test)]
    fn inject_post_admission_race_for_test(&self, prepared: &PreparedPatch) {
        if self.take_test_fault(TestFault::RaceAffectedStage) {
            std::fs::write(
                prepared.logical_root.join(&prepared.affected_relative_path),
                b"stage-race\n",
            )
            .unwrap();
            assert!(
                Command::new("git")
                    .args(["add", "--"])
                    .arg(&prepared.affected_relative_path)
                    .current_dir(&prepared.logical_root)
                    .status()
                    .unwrap()
                    .success()
            );
        } else if self.take_test_fault(TestFault::RaceAffectedHead) {
            std::fs::write(
                prepared.logical_root.join(&prepared.affected_relative_path),
                b"head-race\n",
            )
            .unwrap();
            assert!(
                Command::new("git")
                    .args(["add", "--"])
                    .arg(&prepared.affected_relative_path)
                    .current_dir(&prepared.logical_root)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                Command::new("git")
                    .args(["commit", "--quiet", "-m", "head-race"])
                    .current_dir(&prepared.logical_root)
                    .status()
                    .unwrap()
                    .success()
            );
        } else if self.take_test_fault(TestFault::RaceAdminLocator) {
            std::fs::rename(
                prepared.logical_root.join(".git"),
                prepared.logical_root.join(".git-raced"),
            )
            .unwrap();
            std::fs::create_dir(prepared.logical_root.join(".git")).unwrap();
        } else if self.take_test_fault(TestFault::RaceRootLocator) {
            let displaced = prepared.logical_root.with_file_name("worktree-displaced");
            std::fs::rename(&prepared.logical_root, displaced).unwrap();
            std::fs::create_dir(&prepared.logical_root).unwrap();
            std::fs::set_permissions(
                &prepared.logical_root,
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
    }

    #[cfg(test)]
    fn inject_normal_failure_for_test(&self, prepared: &PreparedPatch) -> bool {
        let inject = self.take_test_fault(TestFault::NormalFailureUnchanged)
            || matches!(
                *self.faults.fault.lock().unwrap(),
                Some(TestFault::NormalFailureVerifierUnavailable(_))
            );
        if !inject {
            return false;
        }
        std::fs::write(
            prepared.logical_root.join(&prepared.affected_relative_path),
            b"external-conflict\n",
        )
        .unwrap();
        true
    }

    #[cfg(test)]
    fn restore_after_normal_failure_for_test(&self, prepared: &PreparedPatch, injected: bool) {
        if injected {
            std::fs::write(
                prepared.logical_root.join(&prepared.affected_relative_path),
                &prepared.affected_prestate.bytes,
            )
            .unwrap();
        }
    }

    pub async fn handle(
        &self,
        request: RecoveryRequest,
    ) -> Result<RecoveryActionOutcome, RecoveryError> {
        if !self.custody.register() {
            return Err(RecoveryError::GateInactive);
        }
        let service = self.clone();
        let custody = Arc::clone(&self.custody);
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _active = ActiveAction(custody);
            let result = service.execute_once(request).await;
            let _ = result_tx.send(result);
        });
        result_rx.await.map_err(|_| RecoveryError::Probe)?
    }

    pub async fn shutdown_and_drain(&self) {
        self.custody.shutdown_and_drain().await;
    }

    pub async fn reconcile_pending_on_startup(&self) -> Result<(), RecoveryError> {
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let view = RecoveryCurrentView::from_snapshot(&projected)?;
        let pending = view
            .state
            .applications
            .values()
            .filter(|application| {
                matches!(
                    application.application_status,
                    RecoveryApplicationStatus::Unknown
                        | RecoveryApplicationStatus::PartiallyApplied
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut first_error = None;
        for application in pending {
            let request = RecoveryRequest {
                request_id: RequestId::from_uuid(application.recovery_application_id.as_uuid())
                    .map_err(|_| RecoveryError::InvalidInput)?,
                recovery_bundle_id: application.recovery_bundle_id,
                target_worktree_instance_id: application.target_worktree_instance_id,
                application_kind: application.application_kind,
            };
            if let Err(error) = self
                .reconcile_durable_application(&request, &application, true)
                .await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    async fn execute_once(
        &self,
        request: RecoveryRequest,
    ) -> Result<RecoveryActionOutcome, RecoveryError> {
        if self.snapshot.recovery_gate != evertrace_capture::RecoveryGateMode::Active {
            return Err(RecoveryError::GateInactive);
        }
        let application_id = RecoveryApplicationId::from_uuid(request.request_id.as_uuid())
            .map_err(|_| RecoveryError::InvalidInput)?;
        if let Some(outcome) = self.replay_outcome(application_id, &request).await? {
            return Ok(outcome);
        }
        if request.application_kind != RecoveryApplicationKind::Patch {
            return Ok(RecoveryActionOutcome::Unsupported(
                RecoveryUnsupportedReason::UnsupportedApplicationKind,
            ));
        }
        let _lease = self.fence.acquire(request.target_worktree_instance_id)?;
        let deadline = Instant::now()
            + Duration::from_millis(u64::from(self.snapshot.recovery_preflight_timeout_ms));
        let prepared = match self
            .prepare_patch(&request, application_id, deadline)
            .await?
        {
            Ok(value) => value,
            Err(reason) => return Ok(RecoveryActionOutcome::Unsupported(reason)),
        };
        let admitted = admitted_application(&prepared, request.request_id)?;
        prepared
            .pinned_root
            .revalidate()
            .map_err(|_| RecoveryError::Probe)?;
        if self.action_expired(deadline) {
            return Err(RecoveryError::Deadline);
        }
        let command = application_command(
            CommandId::from_uuid(request.request_id.as_uuid())
                .map_err(|_| RecoveryError::InvalidInput)?,
            &admitted,
            self.snapshot.effective_config_hash,
        )?;
        #[cfg(test)]
        if self.take_test_fault(TestFault::AdmissionCommit) {
            return Err(RecoveryError::Store);
        }
        let committed = self
            .writer
            .commit(command, admitted.created_at_us)
            .await
            .map_err(|_| RecoveryError::Store)?;
        if committed.replayed {
            return self
                .replay_outcome(application_id, &request)
                .await?
                .ok_or(RecoveryError::Store);
        }
        #[cfg(test)]
        self.inject_post_admission_race_for_test(&prepared);
        if self.action_expired(deadline) {
            return Ok(RecoveryActionOutcome::Application {
                recovery_application_id: admitted.recovery_application_id,
                application_status: RecoveryApplicationStatus::Unknown,
                replayed: false,
            });
        }
        if self
            .affected_git_proof(
                &prepared.pinned_root,
                &prepared.affected_relative_path,
                deadline,
            )
            .await?
            .as_ref()
            != Some(&prepared.affected_git_prestate)
            || prepared.pinned_root.revalidate().is_err()
            || read_affected_file(
                &prepared.pinned_root,
                &prepared.affected_relative_path,
                deadline,
                self.snapshot.recovery_max_bundle_bytes,
            )
            .as_ref()
                != Ok(&prepared.affected_prestate)
        {
            return Ok(RecoveryActionOutcome::Application {
                recovery_application_id: admitted.recovery_application_id,
                application_status: RecoveryApplicationStatus::Unknown,
                replayed: false,
            });
        }

        let (supervisor_tx, supervisor_rx) = tokio::sync::oneshot::channel();
        let capture_service = self.clone();
        let spawn_service = self.clone();
        let admitted_for_capture = admitted.clone();
        let cancellation = Arc::clone(&self.custody.cancelled);
        thread::Builder::new()
            .name("evertrace-recovery-patch".into())
            .spawn(move || {
                #[cfg(test)]
                let failure_injected = capture_service.inject_normal_failure_for_test(&prepared);
                let execution = run_git_apply_with_capture(
                    &prepared.pinned_cwd,
                    &prepared.patch,
                    deadline,
                    &cancellation,
                    |pid| spawn_service.note_child_spawn_for_test(pid, &cancellation, deadline),
                    || {
                        capture_service.capture_intent_frame(
                            &request,
                            &admitted_for_capture,
                            &prepared,
                        )
                    },
                );
                #[cfg(test)]
                capture_service.restore_after_normal_failure_for_test(&prepared, failure_injected);
                let _ = supervisor_tx.send((prepared, _lease, execution));
            })
            .map_err(|_| RecoveryError::Probe)?;
        let (prepared, _lease, execution) =
            supervisor_rx.await.map_err(|_| RecoveryError::Probe)?;
        let execution = execution?;
        let affected_before_post = read_affected_file_after_mutation(
            &prepared.pinned_root,
            &prepared.affected_relative_path,
            deadline,
            self.snapshot.recovery_max_bundle_bytes,
        )
        .ok();
        let post_snapshot = self
            .capture_post_snapshot(
                &prepared,
                request.target_worktree_instance_id,
                admitted.pre_application_snapshot_id,
                deadline,
            )
            .await
            .ok()
            .flatten();
        #[cfg(test)]
        if self.take_test_fault(TestFault::RaceAffectedDuringPostCapture) {
            std::fs::write(
                prepared.logical_root.join(&prepared.affected_relative_path),
                b"post-snapshot-race\n",
            )
            .unwrap();
        } else if self.take_test_fault(TestFault::RaceUnrelatedDuringPostCapture) {
            std::fs::write(
                prepared.logical_root.join("unrelated-post-snapshot.txt"),
                b"unrelated\n",
            )
            .unwrap();
        }
        let affected_after_post = read_affected_file_after_mutation(
            &prepared.pinned_root,
            &prepared.affected_relative_path,
            deadline,
            self.snapshot.recovery_max_bundle_bytes,
        )
        .ok();
        let stable_post = affected_before_post
            .zip(affected_after_post)
            .filter(|(before, after)| before == after)
            .filter(|_| prepared.pinned_root.revalidate_stable().is_ok());
        let (post_snapshot, affected_file_identity) = match (post_snapshot, stable_post) {
            (Some(snapshot), Some((_, affected))) => (Some(snapshot), Some(affected.identity)),
            _ => (None, None),
        };
        let verification = post_snapshot.and_then(|_| {
            affected_file_identity.and_then(|_| {
                if self.verifier_unavailable_for_test() {
                    None
                } else {
                    verify_patch_outcome(&prepared, execution, deadline, &self.custody.cancelled)
                        .ok()
                        .flatten()
                }
            })
        });
        #[cfg(test)]
        if self.take_test_fault(TestFault::SkipTerminalCapture) {
            return Ok(RecoveryActionOutcome::Application {
                recovery_application_id: admitted.recovery_application_id,
                application_status: admitted.application_status,
                replayed: false,
            });
        }
        self.persist_terminal_evidence(
            &request,
            &admitted,
            &prepared,
            TerminalCaptureOutcome {
                post_snapshot_id: post_snapshot,
                affected_file_identity,
                execution,
                verification,
            },
        )
        .await
    }

    async fn replay_outcome(
        &self,
        application_id: RecoveryApplicationId,
        request: &RecoveryRequest,
    ) -> Result<Option<RecoveryActionOutcome>, RecoveryError> {
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let view = RecoveryCurrentView::from_snapshot(&projected)?;
        let Some(application) = view.state.applications.get(&application_id).cloned() else {
            return Ok(None);
        };
        if application.recovery_bundle_id != request.recovery_bundle_id
            || application.target_worktree_instance_id != request.target_worktree_instance_id
            || application.application_kind != request.application_kind
        {
            return Err(RecoveryError::InvalidSuccessor);
        }
        let attempts = AttemptCurrentView::from_snapshot(&projected)?;
        if matches!(
            application.application_status,
            RecoveryApplicationStatus::Unknown | RecoveryApplicationStatus::PartiallyApplied
        ) || application.application_status == RecoveryApplicationStatus::Applied
            && !evidence::current_lineage_transfer_supported(&application, &attempts)
        {
            return self
                .reconcile_durable_application(request, &application, true)
                .await
                .map(Some);
        }
        Ok(Some(RecoveryActionOutcome::Application {
            recovery_application_id: application_id,
            application_status: application.application_status,
            replayed: true,
        }))
    }

    async fn prepare_patch(
        &self,
        request: &RecoveryRequest,
        application_id: RecoveryApplicationId,
        deadline: Instant,
    ) -> Result<Result<PreparedPatch, RecoveryUnsupportedReason>, RecoveryError> {
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let recovery = RecoveryCurrentView::from_snapshot(&projected)?;
        let repository = RepositoryCurrentView::from_snapshot(&projected)?;
        let Some(bundle) = recovery.state.bundles.get(&request.recovery_bundle_id) else {
            return Ok(Err(RecoveryUnsupportedReason::IncompleteBundle));
        };
        if bundle.capture_status != RecoveryCaptureStatus::Complete
            || bundle.ordering_integrity != OrderingIntegrity::Complete
            || !bundle.omissions.is_empty()
        {
            return Ok(Err(RecoveryUnsupportedReason::IncompleteBundle));
        }
        let patches = bundle
            .tracked_diff_blob_refs
            .iter()
            .filter(|value| value.item_ref == "git:tracked_diff")
            .collect::<Vec<_>>();
        if patches.len() != 1 || bundle.tracked_diff_blob_refs.len() != 1 {
            return Ok(Err(RecoveryUnsupportedReason::AmbiguousPatchContent));
        }
        let selected = patches[0];
        if selected.payload.redaction_spans != 0
            || selected.payload.protected_secret_digest.is_some()
            || selected.payload.protected_length != selected.payload.original_length
            || selected.protected_relative_path.is_some()
        {
            return Ok(Err(RecoveryUnsupportedReason::RedactedContent));
        }
        let Some(target) = repository
            .worktrees
            .get(&request.target_worktree_instance_id)
        else {
            return Ok(Err(RecoveryUnsupportedReason::TargetUnavailable));
        };
        let Some(source) = repository
            .worktrees
            .get(&bundle.source_worktree_instance_id)
        else {
            return Ok(Err(RecoveryUnsupportedReason::TargetUnavailable));
        };
        let Some(logical_root) = target.current_path.as_deref().map(PathBuf::from) else {
            return Ok(Err(RecoveryUnsupportedReason::TargetUnavailable));
        };
        if target.lifecycle != WorktreeLifecycle::Active
            || target.repository_instance_id != source.repository_instance_id
        {
            return Ok(Err(RecoveryUnsupportedReason::TargetUnavailable));
        }
        let pinned_root =
            ConfinedRoot::open_owned_private(&logical_root).map_err(|_| RecoveryError::Probe)?;
        let pinned_cwd = pinned_root
            .proc_cwd_path()
            .map_err(|_| RecoveryError::Probe)?;
        let pre_snapshot_id = match self
            .refresh_pinned_target(
                request.target_worktree_instance_id,
                target.repository_instance_id,
                &logical_root,
                &pinned_root,
                deadline,
                true,
            )
            .await?
        {
            Ok(id) => id,
            Err(reason) => return Ok(Err(reason)),
        };
        let cas = CasStore::open(self.snapshot.cas_dir.clone()).map_err(|_| RecoveryError::Cas)?;
        let key_store = DeviceKeyStore::new(self.snapshot.device_key_dir.clone());
        let tickets = RecoveryTicketService::new(
            self.writer.clone(),
            cas.clone(),
            key_store,
            self.snapshot.effective_config_hash,
        );
        let ticket = tickets
            .issue_for_application(
                RecoveryTicketIssueRequest {
                    recovery_bundle_id: request.recovery_bundle_id,
                    selected_item_refs: vec![selected.item_ref.clone()],
                    application_kind: request.application_kind,
                    target_worktree_instance_id: request.target_worktree_instance_id,
                    pre_application_snapshot_id: pre_snapshot_id,
                },
                application_id,
            )
            .await?;
        let claims = tickets.verify(&ticket).await?;
        if self.action_expired(deadline) {
            return Err(RecoveryError::Deadline);
        }
        let digest = CasDigest::from_str(&selected.payload.cas_ref)
            .map_err(|_| RecoveryError::InvalidInput)?;
        let patch = cas.read(&digest).map_err(|_| RecoveryError::Cas)?;
        if self.action_expired(deadline) {
            return Err(RecoveryError::Deadline);
        }
        if u64::try_from(patch.len()).ok() != Some(selected.payload.original_length) {
            return Err(RecoveryError::InvalidInput);
        }
        let affected_relative_path = match strict_patch_target(&patch) {
            Some(value) => value,
            None => return Ok(Err(RecoveryUnsupportedReason::UnsupportedPatchShape)),
        };
        let affected_before = match read_affected_file(
            &pinned_root,
            &affected_relative_path,
            deadline,
            self.snapshot.recovery_max_bundle_bytes,
        ) {
            Ok(value) => value,
            Err(()) => return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightUnavailable)),
        };
        let affected_git_before = match self
            .affected_git_proof(&pinned_root, &affected_relative_path, deadline)
            .await?
        {
            Some(value) => value,
            None => return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightUnavailable)),
        };
        let prepared_cwd = pinned_cwd.clone();
        let checked_patch = patch.clone();
        let cancellation = Arc::clone(&self.custody.cancelled);
        let check = tokio::task::spawn_blocking(move || {
            run_git_apply(
                &pinned_cwd,
                &checked_patch,
                PatchMode::Check,
                deadline,
                &cancellation,
            )
        })
        .await
        .map_err(|_| RecoveryError::Probe)??;
        if !check.success || check.timed_out || check.truncated || check.io_error {
            return Ok(Err(RecoveryUnsupportedReason::PatchPreflightFailed));
        }
        let affected_after = match read_affected_file(
            &pinned_root,
            &affected_relative_path,
            deadline,
            self.snapshot.recovery_max_bundle_bytes,
        ) {
            Ok(value) => value,
            Err(()) => return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightRaced)),
        };
        if affected_before != affected_after {
            return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightRaced));
        }
        let affected_git_after = match self
            .affected_git_proof(&pinned_root, &affected_relative_path, deadline)
            .await?
        {
            Some(value) => value,
            None => return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightRaced)),
        };
        if affected_git_before != affected_git_after {
            return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightRaced));
        }
        pinned_root.revalidate().map_err(|_| RecoveryError::Probe)?;
        Ok(Ok(PreparedPatch {
            claims,
            patch,
            logical_root,
            pinned_root,
            pinned_cwd: prepared_cwd,
            repository_id: target.repository_instance_id,
            affected_relative_path,
            affected_prestate: affected_before,
            affected_git_prestate: affected_git_before,
            relevant_attempt_anchor_ids: bundle.attempt_anchor_ids.clone(),
            attempt_anchor_claims: bundle.attempt_anchor_claims.clone(),
        }))
    }

    async fn affected_git_proof(
        &self,
        pinned_root: &ConfinedRoot,
        relative_path: &Path,
        deadline: Instant,
    ) -> Result<Option<repository::AffectedPathGitProof>, RecoveryError> {
        if self.action_expired(deadline) {
            return Ok(None);
        }
        let cwd = pinned_root
            .proc_cwd_path()
            .map_err(|_| RecoveryError::Probe)?;
        let relative_path = relative_path.to_path_buf();
        let identity = evertrace_domain::repository::FilesystemIdentity {
            device: pinned_root.identity().device,
            inode: pinned_root.identity().inode,
        };
        let limits = self.probe_limits(deadline);
        let value = tokio::task::spawn_blocking(move || {
            repository::probe_affected_path_git_proof_pinned(
                &cwd,
                identity,
                &relative_path,
                &limits,
            )
        })
        .await
        .map_err(|_| RecoveryError::Probe)?
        .map_err(|_| RecoveryError::Probe)?;
        if self.action_expired(deadline) {
            return Ok(None);
        }
        Ok(value)
    }

    async fn refresh_pinned_target(
        &self,
        worktree_id: WorktreeId,
        repository_id: evertrace_domain::ids::RepositoryId,
        logical_root: &Path,
        pinned_root: &ConfinedRoot,
        deadline: Instant,
        commit_change: bool,
    ) -> Result<
        Result<evertrace_domain::ids::WorktreeSnapshotId, RecoveryUnsupportedReason>,
        RecoveryError,
    > {
        if self.action_expired(deadline) || pinned_root.revalidate().is_err() {
            return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightUnavailable));
        }
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let view = RepositoryCurrentView::from_snapshot(&projected)?;
        let known_admin = view.known_admin_paths();
        let known_heads = view
            .snapshots
            .values()
            .filter_map(|snapshot| snapshot.head_oid.as_deref())
            .filter_map(|value| repository::GitOid::parse(value).ok())
            .collect::<Vec<_>>();
        let evidence_ref = format!("recovery-preflight:{}", worktree_id);
        let limits = self.probe_limits(deadline);
        let mut evidence = repository::probe_repository_pinned(
            &pinned_root
                .proc_cwd_path()
                .map_err(|_| RecoveryError::Probe)?,
            logical_root,
            evertrace_domain::repository::FilesystemIdentity {
                device: pinned_root.identity().device,
                inode: pinned_root.identity().inode,
            },
            repository::HostTrustDecision::Trusted,
            &[evidence_ref],
            current_time_us(),
            &limits,
            &known_admin,
            &known_heads,
        )
        .map_err(|_| RecoveryError::Probe)?;
        if evidence.unavailable_reason.is_some() || !evidence.omissions.is_empty() {
            return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightUnavailable));
        }
        if let (Some(root), Some(git_dir)) =
            (evidence.worktree_root.as_deref(), evidence.git_dir.clone())
        {
            let Some(candidate) = evidence
                .worktree_entries
                .iter_mut()
                .find(|entry| entry.path == root)
            else {
                return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightUnavailable));
            };
            if candidate.gitdir.is_none() {
                candidate.gitdir = Some(git_dir);
            }
        }
        let resolution = repository::resolve_repository(&repository::RepositoryResolveInput {
            view: &view,
            evidence: &evidence,
            derived_from_hint: None,
        })
        .map_err(|_| RecoveryError::Probe)?;
        if matches!(
            resolution.kind,
            Some(
                repository::ResolutionKind::Create
                    | repository::ResolutionKind::Correction
                    | repository::ResolutionKind::Ambiguous
                    | repository::ResolutionKind::Unavailable
            )
        ) || resolution.repositories.iter().any(|value| {
            value.repository_id != repository_id
                || !view.repositories.contains_key(&value.repository_id)
        }) || resolution
            .worktrees
            .iter()
            .any(|value| !view.worktrees.contains_key(&value.worktree_instance_id))
        {
            return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightUnavailable));
        }
        let candidate_matches = evidence
            .worktree_entries
            .iter()
            .filter(|entry| evidence.worktree_root.as_deref() == Some(entry.path.as_str()))
            .filter_map(|entry| {
                view.worktrees.values().find(|worktree| {
                    worktree.repository_instance_id == repository_id
                        && worktree
                            .git_admin_path_history
                            .last()
                            .map(|path| path.path.as_str())
                            == entry.gitdir.as_deref()
                })
            })
            .map(|worktree| worktree.worktree_instance_id)
            .collect::<std::collections::BTreeSet<_>>();
        if candidate_matches.len() != 1 || !candidate_matches.contains(&worktree_id) {
            return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightUnavailable));
        }
        if !commit_change
            && resolution
                .journal_command(
                    current_time_us(),
                    self.snapshot.effective_config_hash,
                    ACTION_ALGORITHM_REVISION,
                )
                .map_err(|_| RecoveryError::Store)?
                .is_some()
        {
            return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightRaced));
        }
        if commit_change
            && let Some(command) = resolution
                .journal_command(
                    current_time_us(),
                    self.snapshot.effective_config_hash,
                    ACTION_ALGORITHM_REVISION,
                )
                .map_err(|_| RecoveryError::Store)?
        {
            self.writer
                .commit_if_frontier(command, current_time_us(), view.frontier)
                .await
                .map_err(|_| RecoveryError::Store)?;
        }
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let current = RepositoryCurrentView::from_snapshot(&projected)?;
        let Some(target) = current.worktrees.get(&worktree_id) else {
            return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightUnavailable));
        };
        let Some(snapshot_id) = target.current_snapshot_id else {
            return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightUnavailable));
        };
        let Some(snapshot) = current.snapshots.get(&snapshot_id) else {
            return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightUnavailable));
        };
        if target.repository_instance_id != repository_id
            || target.lifecycle != WorktreeLifecycle::Active
            || snapshot.worktree_instance_id != worktree_id
            || snapshot.capture_status != SnapshotCaptureStatus::Complete
        {
            return Ok(Err(RecoveryUnsupportedReason::PhysicalPreflightUnavailable));
        }
        Ok(Ok(snapshot_id))
    }

    fn probe_limits(&self, deadline: Instant) -> repository::ProbeLimits {
        repository::ProbeLimits {
            max_stdout_bytes: usize::try_from(self.snapshot.recovery_max_bundle_bytes)
                .unwrap_or(1 << 20),
            max_stderr_bytes: OUTPUT_LIMIT,
            max_records: 4096,
            max_untracked_paths: 128,
            max_diff_bytes: usize::try_from(self.snapshot.recovery_max_bundle_bytes)
                .unwrap_or(1 << 20),
            max_duration_ms: deadline
                .checked_duration_since(Instant::now())
                .map_or(1, |value| {
                    u64::try_from(value.as_millis()).unwrap_or(u64::MAX).max(1)
                }),
        }
    }

    fn action_expired(&self, deadline: Instant) -> bool {
        Instant::now() >= deadline || self.custody.cancelled.load(Ordering::Acquire)
    }

    async fn capture_post_snapshot(
        &self,
        prepared: &PreparedPatch,
        worktree_id: WorktreeId,
        _pre_snapshot_id: evertrace_domain::ids::WorktreeSnapshotId,
        deadline: Instant,
    ) -> Result<Option<evertrace_domain::ids::WorktreeSnapshotId>, RecoveryError> {
        if self.action_expired(deadline) {
            return Ok(None);
        }
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let view = RepositoryCurrentView::from_snapshot(&projected)?;
        let known_admin = view.known_admin_paths();
        let known_heads = view
            .snapshots
            .values()
            .filter_map(|snapshot| snapshot.head_oid.as_deref())
            .filter_map(|value| repository::GitOid::parse(value).ok())
            .collect::<Vec<_>>();
        let pinned_cwd = prepared.pinned_cwd.clone();
        let logical_root = prepared.logical_root.clone();
        let identity = evertrace_domain::repository::FilesystemIdentity {
            device: prepared.pinned_root.identity().device,
            inode: prepared.pinned_root.identity().inode,
        };
        let limits = repository::ProbeLimits {
            max_stdout_bytes: usize::try_from(self.snapshot.recovery_max_bundle_bytes)
                .unwrap_or(1 << 20),
            max_stderr_bytes: OUTPUT_LIMIT,
            max_records: 4096,
            max_untracked_paths: 128,
            max_diff_bytes: usize::try_from(self.snapshot.recovery_max_bundle_bytes)
                .unwrap_or(1 << 20),
            max_duration_ms: deadline
                .checked_duration_since(Instant::now())
                .map_or(1, |value| {
                    u64::try_from(value.as_millis()).unwrap_or(u64::MAX).max(1)
                }),
        };
        let mut evidence = tokio::task::spawn_blocking(move || {
            repository::probe_repository_pinned(
                &pinned_cwd,
                &logical_root,
                identity,
                repository::HostTrustDecision::Trusted,
                &["recovery:post-snapshot".into()],
                current_time_us(),
                &limits,
                &known_admin,
                &known_heads,
            )
        })
        .await
        .map_err(|_| RecoveryError::Probe)?
        .map_err(|_| RecoveryError::Probe)?;
        if self.action_expired(deadline) {
            return Ok(None);
        }
        if evidence.unavailable_reason.is_some() || !evidence.omissions.is_empty() {
            return Ok(None);
        }
        if let (Some(root), Some(git_dir)) =
            (evidence.worktree_root.as_deref(), evidence.git_dir.clone())
        {
            let candidate = evidence
                .worktree_entries
                .iter_mut()
                .find(|entry| entry.path == root)
                .ok_or(RecoveryError::Probe)?;
            if candidate.gitdir.is_none() {
                candidate.gitdir = Some(git_dir);
            }
        }
        let resolution = repository::resolve_repository(&repository::RepositoryResolveInput {
            view: &view,
            evidence: &evidence,
            derived_from_hint: None,
        })
        .map_err(|_| RecoveryError::Probe)?;
        if let Some(command) = resolution
            .journal_command(
                current_time_us(),
                self.snapshot.effective_config_hash,
                ACTION_ALGORITHM_REVISION,
            )
            .map_err(|_| RecoveryError::Store)?
        {
            self.writer
                .commit_if_frontier(command, current_time_us(), view.frontier)
                .await
                .map_err(|_| RecoveryError::Store)?;
        }
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let current = RepositoryCurrentView::from_snapshot(&projected)?;
        Ok(current
            .worktrees
            .get(&worktree_id)
            .and_then(|value| value.current_snapshot_id))
    }

    /// Re-runs only the fixed read-only verifier for a durable terminal whose
    /// first verification attempt was unavailable. It never executes the
    /// mutation and it refuses to invent a missing post-Snapshot binding.
    async fn fresh_replay_verifier(
        &self,
        current: &RecoveryApplication,
        normal_exit: bool,
        exit_code: Option<i32>,
        affected_file_identity: Option<evidence::TerminalAffectedFileIdentity>,
    ) -> Result<Option<RecoveryVerificationOutcome>, RecoveryError> {
        if !normal_exit || current.application_kind != RecoveryApplicationKind::Patch {
            return Ok(None);
        }
        let Some(post_snapshot_id) = current.post_application_snapshot_id else {
            return Ok(None);
        };
        let Some(affected_file_identity) = affected_file_identity else {
            return Ok(None);
        };
        if self.verifier_unavailable_for_test() {
            return Ok(None);
        }
        let deadline = Instant::now()
            + Duration::from_millis(u64::from(self.snapshot.recovery_preflight_timeout_ms));
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let recovery = RecoveryCurrentView::from_snapshot(&projected)?;
        let repository = RepositoryCurrentView::from_snapshot(&projected)?;
        let Some(bundle) = recovery.state.bundles.get(&current.recovery_bundle_id) else {
            return Ok(None);
        };
        let patches = bundle
            .tracked_diff_blob_refs
            .iter()
            .filter(|value| value.item_ref == "git:tracked_diff")
            .collect::<Vec<_>>();
        if patches.len() != 1 || bundle.tracked_diff_blob_refs.len() != 1 {
            return Ok(None);
        }
        let selected = patches[0];
        let selected_id = cas_id(&selected.payload.cas_ref)?;
        if current.selected_cas_refs.as_slice() != [selected_id] {
            return Err(RecoveryError::InvalidSuccessor);
        }
        let Some(target) = repository
            .worktrees
            .get(&current.target_worktree_instance_id)
        else {
            return Ok(None);
        };
        let Some(logical_root) = target.current_path.as_deref().map(PathBuf::from) else {
            return Ok(None);
        };
        let pinned_root = match ConfinedRoot::open_owned_private(&logical_root) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        let refreshed = self
            .refresh_pinned_target(
                current.target_worktree_instance_id,
                target.repository_instance_id,
                &logical_root,
                &pinned_root,
                deadline,
                true,
            )
            .await?;
        if refreshed.ok().is_none() {
            return Ok(None);
        }
        let digest = CasDigest::from_str(&selected.payload.cas_ref)
            .map_err(|_| RecoveryError::InvalidSuccessor)?;
        let cas = CasStore::open(self.snapshot.cas_dir.clone()).map_err(|_| RecoveryError::Cas)?;
        let patch = cas.read(&digest).map_err(|_| RecoveryError::Cas)?;
        let Some(affected_relative_path) = strict_patch_target(&patch) else {
            return Err(RecoveryError::InvalidSuccessor);
        };
        let Ok(affected_file) = read_affected_file_after_mutation(
            &pinned_root,
            &affected_relative_path,
            deadline,
            self.snapshot.recovery_max_bundle_bytes,
        ) else {
            return Ok(None);
        };
        if !affected_file_identity.matches(affected_file.identity) {
            return Ok(None);
        }
        let mode = if exit_code == Some(0) {
            PatchMode::ReverseCheck
        } else {
            PatchMode::Check
        };
        let check = tokio::task::spawn_blocking({
            let cwd = pinned_root
                .proc_cwd_path()
                .map_err(|_| RecoveryError::Probe)?;
            let cancellation = Arc::clone(&self.custody.cancelled);
            move || run_git_apply(&cwd, &patch, mode, deadline, &cancellation)
        })
        .await
        .map_err(|_| RecoveryError::Probe)??;
        if !check.success
            || check.timed_out
            || check.cancelled
            || check.truncated
            || check.io_error
            || check.signal.is_some()
        {
            return Ok(None);
        }
        if pinned_root.revalidate_stable().is_err() {
            return Ok(None);
        }
        let Ok(final_affected_file) = read_affected_file_after_mutation(
            &pinned_root,
            &affected_relative_path,
            deadline,
            self.snapshot.recovery_max_bundle_bytes,
        ) else {
            return Ok(None);
        };
        if final_affected_file != affected_file || pinned_root.revalidate_stable().is_err() {
            return Ok(None);
        }
        Ok(
            if exit_code == Some(0) && post_snapshot_id != current.pre_application_snapshot_id {
                Some(RecoveryVerificationOutcome::Applied)
            } else if exit_code.is_some_and(|code| code != 0) {
                Some(RecoveryVerificationOutcome::NotApplied)
            } else {
                None
            },
        )
    }
}

fn admitted_application(
    prepared: &PreparedPatch,
    request_id: RequestId,
) -> Result<RecoveryApplication, RecoveryError> {
    let claims = &prepared.claims;
    let mut selected_cas_refs = claims
        .selected_content_refs
        .iter()
        .map(|value| cas_id(&value.payload.cas_ref))
        .collect::<Result<Vec<_>, _>>()?;
    selected_cas_refs.sort();
    selected_cas_refs.dedup();
    let value = RecoveryApplication {
        recovery_application_id: claims.prospective_recovery_application_id,
        revision_id: RevisionId::from_uuid(request_id.as_uuid())
            .map_err(|_| RecoveryError::InvalidInput)?,
        parent_revision_id: None,
        recovery_bundle_id: claims.recovery_bundle_id,
        target_worktree_instance_id: claims.target_worktree_instance_id,
        pre_application_snapshot_id: claims.pre_application_snapshot_id,
        post_application_snapshot_id: None,
        application_kind: claims.application_kind,
        ticket_claims_version: claims.ticket_version,
        selected_cas_refs,
        input_delivery_kind: RecoveryInputDeliveryKind::PatchStdin,
        input_delivery_state: RecoveryInputDeliveryState::Admitted,
        operation_id: None,
        operation_revision: None,
        execution_lane_id: None,
        capture_receipt_revision_id: None,
        scope_effect_ids: vec![],
        input_source_observation_ids: vec![],
        result_source_observation_ids: vec![],
        verifier_receipts: vec![],
        relevant_attempt_anchor_ids: prepared.relevant_attempt_anchor_ids.clone(),
        attempt_anchor_claims: prepared.attempt_anchor_claims.clone(),
        anchor_verifier_receipts: vec![],
        application_status: RecoveryApplicationStatus::Unknown,
        created_at_us: claims.issued_at_us,
    };
    value.validate().map_err(|_| RecoveryError::InvalidInput)?;
    Ok(value)
}

fn cas_id(value: &str) -> Result<CasId, RecoveryError> {
    CasId::from_str(if value.starts_with("cas:") {
        value
    } else {
        return CasId::from_str(&format!("cas:{value}")).map_err(|_| RecoveryError::InvalidInput);
    })
    .map_err(|_| RecoveryError::InvalidInput)
}

fn verify_patch_outcome(
    prepared: &PreparedPatch,
    execution: GitApplyResult,
    deadline: Instant,
    cancellation: &AtomicBool,
) -> Result<Option<RecoveryVerificationOutcome>, RecoveryError> {
    if execution.timed_out
        || execution.cancelled
        || execution.truncated
        || execution.io_error
        || execution.signal.is_some()
    {
        return Ok(None);
    }
    prepared
        .pinned_root
        .revalidate_stable()
        .map_err(|_| RecoveryError::Probe)?;
    let limits = repository::ProbeLimits {
        max_duration_ms: deadline
            .checked_duration_since(Instant::now())
            .map_or(1, |value| {
                u64::try_from(value.as_millis()).unwrap_or(u64::MAX).max(1)
            }),
        ..repository::ProbeLimits::default()
    };
    let current_git = repository::probe_affected_path_git_proof_pinned(
        &prepared.pinned_cwd,
        evertrace_domain::repository::FilesystemIdentity {
            device: prepared.pinned_root.identity().device,
            inode: prepared.pinned_root.identity().inode,
        },
        &prepared.affected_relative_path,
        &limits,
    )
    .map_err(|_| RecoveryError::Probe)?;
    if current_git.as_ref() != Some(&prepared.affected_git_prestate) {
        return Ok(None);
    }
    let mode = if execution.success {
        PatchMode::ReverseCheck
    } else {
        PatchMode::Check
    };
    let check = run_git_apply(
        &prepared.pinned_cwd,
        &prepared.patch,
        mode,
        deadline,
        cancellation,
    )?;
    if !check.success
        || check.timed_out
        || check.truncated
        || check.io_error
        || check.signal.is_some()
    {
        return Ok(None);
    }
    if execution.success {
        return Ok(Some(RecoveryVerificationOutcome::Applied));
    }
    let current = prepared
        .pinned_root
        .read_after_owned_mutation(
            &prepared.affected_relative_path,
            ConfinedReadLimits {
                single_file_remaining: u64::try_from(prepared.affected_prestate.bytes.len())
                    .unwrap_or(u64::MAX),
                untracked_total_remaining: u64::MAX,
                bundle_remaining: u64::MAX,
                deadline,
            },
        )
        .map_err(|_| RecoveryError::Probe)?;
    Ok((current.bytes == prepared.affected_prestate.bytes)
        .then_some(RecoveryVerificationOutcome::NotApplied))
}

fn read_affected_file(
    root: &ConfinedRoot,
    relative: &Path,
    deadline: Instant,
    max_bytes: u64,
) -> Result<ConfinedFile, ()> {
    root.read(
        relative,
        ConfinedReadLimits {
            single_file_remaining: max_bytes,
            untracked_total_remaining: max_bytes,
            bundle_remaining: max_bytes,
            deadline,
        },
    )
    .map_err(|_| ())
}

fn read_affected_file_after_mutation(
    root: &ConfinedRoot,
    relative: &Path,
    deadline: Instant,
    max_bytes: u64,
) -> Result<ConfinedFile, ()> {
    root.read_after_owned_mutation(
        relative,
        ConfinedReadLimits {
            single_file_remaining: max_bytes,
            untracked_total_remaining: max_bytes,
            bundle_remaining: max_bytes,
            deadline,
        },
    )
    .map_err(|_| ())
}

fn application_command(
    command_id: CommandId,
    application: &RecoveryApplication,
    effective_config_hash: [u8; 32],
) -> Result<JournalCommand, RecoveryError> {
    JournalCommand::new(
        command_id,
        vec![JournalEventDraft::runtime(
            application.created_at_us,
            effective_config_hash,
            ACTION_ALGORITHM_REVISION,
            JournalPayload::RecoveryApplicationRecorded(Box::new(application.clone())),
        )],
    )
    .map_err(|_| RecoveryError::Store)
}

#[derive(Clone, Copy)]
enum PatchMode {
    Check,
    ReverseCheck,
}

#[derive(Clone, Copy)]
struct GitApplyResult {
    success: bool,
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    cancelled: bool,
    truncated: bool,
    io_error: bool,
}

struct TerminalCaptureOutcome {
    post_snapshot_id: Option<evertrace_domain::ids::WorktreeSnapshotId>,
    affected_file_identity: Option<evertrace_capture::ConfinedFileIdentity>,
    execution: GitApplyResult,
    verification: Option<RecoveryVerificationOutcome>,
}

fn run_git_apply(
    cwd: &Path,
    patch: &[u8],
    mode: PatchMode,
    deadline: Instant,
    cancellation: &AtomicBool,
) -> Result<GitApplyResult, RecoveryError> {
    let args: &[&str] = match mode {
        PatchMode::Check => &["apply", "--check", "--whitespace=nowarn", "-"],
        PatchMode::ReverseCheck => &["apply", "--reverse", "--check", "--whitespace=nowarn", "-"],
    };
    run_git_apply_inner(
        cwd,
        patch,
        args,
        deadline,
        cancellation,
        |_| deadline,
        || Ok(()),
    )
}

fn run_git_apply_with_capture(
    cwd: &Path,
    patch: &[u8],
    deadline: Instant,
    cancellation: &AtomicBool,
    on_spawn: impl FnOnce(u32) -> Instant,
    before_eof: impl FnOnce() -> Result<(), RecoveryError>,
) -> Result<GitApplyResult, RecoveryError> {
    run_git_apply_inner(
        cwd,
        patch,
        &["apply", "--whitespace=nowarn", "-"],
        deadline,
        cancellation,
        on_spawn,
        before_eof,
    )
}

fn run_git_apply_inner(
    cwd: &Path,
    patch: &[u8],
    args: &[&str],
    deadline: Instant,
    cancellation: &AtomicBool,
    on_spawn: impl FnOnce(u32) -> Instant,
    before_eof: impl FnOnce() -> Result<(), RecoveryError>,
) -> Result<GitApplyResult, RecoveryError> {
    if Instant::now() >= deadline || cancellation.load(Ordering::Acquire) {
        return Err(RecoveryError::Deadline);
    }
    let mut child = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "cat")
        .env("HOME", "/nonexistent")
        .env("PAGER", "cat")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_CONFIG_HOME", "/nonexistent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| RecoveryError::Probe)?;
    let deadline = deadline.min(on_spawn(child.id()));
    let stdout = child.stdout.take().ok_or(RecoveryError::Probe)?;
    let stderr = child.stderr.take().ok_or(RecoveryError::Probe)?;
    let truncated = Arc::new(AtomicBool::new(false));
    let io_error = Arc::new(AtomicBool::new(false));
    let stdout_thread = read_output(stdout, Arc::clone(&truncated), Arc::clone(&io_error));
    let stderr_thread = read_output(stderr, Arc::clone(&truncated), Arc::clone(&io_error));
    let mut stdin = child.stdin.take().ok_or(RecoveryError::Probe)?;
    let input = patch.to_vec();
    let (stdin_tx, stdin_rx) = std::sync::mpsc::sync_channel(1);
    let stdin_thread = thread::spawn(move || {
        let result = stdin.write_all(&input).map(|()| stdin);
        let _ = stdin_tx.send(result);
    });
    let stdin = loop {
        if truncated.load(Ordering::Relaxed)
            || io_error.load(Ordering::Relaxed)
            || Instant::now() >= deadline
            || cancellation.load(Ordering::Acquire)
        {
            let timed_out = Instant::now() >= deadline;
            let cancelled = cancellation.load(Ordering::Acquire);
            terminate(&mut child);
            stdin_thread.join().map_err(|_| RecoveryError::Probe)?;
            stdout_thread.join().map_err(|_| RecoveryError::Probe)?;
            stderr_thread.join().map_err(|_| RecoveryError::Probe)?;
            return Ok(GitApplyResult {
                success: false,
                exit_code: None,
                signal: None,
                timed_out,
                cancelled,
                truncated: truncated.load(Ordering::Relaxed),
                io_error: io_error.load(Ordering::Relaxed),
            });
        }
        match stdin_rx.recv_timeout(POLL_INTERVAL) {
            Ok(Ok(stdin)) => break stdin,
            Ok(Err(_)) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                terminate(&mut child);
                stdin_thread.join().map_err(|_| RecoveryError::Probe)?;
                stdout_thread.join().map_err(|_| RecoveryError::Probe)?;
                stderr_thread.join().map_err(|_| RecoveryError::Probe)?;
                return Ok(GitApplyResult {
                    success: false,
                    exit_code: None,
                    signal: None,
                    timed_out: false,
                    cancelled: false,
                    truncated: truncated.load(Ordering::Relaxed),
                    io_error: true,
                });
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    stdin_thread.join().map_err(|_| RecoveryError::Probe)?;
    if before_eof().is_err() {
        terminate(&mut child);
        stdout_thread.join().map_err(|_| RecoveryError::Probe)?;
        stderr_thread.join().map_err(|_| RecoveryError::Probe)?;
        return Ok(GitApplyResult {
            success: false,
            exit_code: None,
            signal: None,
            timed_out: false,
            cancelled: false,
            truncated: truncated.load(Ordering::Relaxed),
            io_error: true,
        });
    }
    drop(stdin);
    let (status, timed_out, cancelled) = loop {
        if truncated.load(Ordering::Relaxed) || io_error.load(Ordering::Relaxed) {
            terminate(&mut child);
            break (None, false, false);
        }
        if let Some(status) = child.try_wait().map_err(|_| RecoveryError::Probe)? {
            break (Some(status), false, false);
        }
        if Instant::now() >= deadline || cancellation.load(Ordering::Acquire) {
            terminate(&mut child);
            break (
                None,
                Instant::now() >= deadline,
                cancellation.load(Ordering::Acquire),
            );
        }
        thread::sleep(POLL_INTERVAL);
    };
    stdout_thread.join().map_err(|_| RecoveryError::Probe)?;
    stderr_thread.join().map_err(|_| RecoveryError::Probe)?;
    Ok(GitApplyResult {
        success: status
            .as_ref()
            .is_some_and(std::process::ExitStatus::success),
        exit_code: status.as_ref().and_then(std::process::ExitStatus::code),
        signal: status.as_ref().and_then(ExitStatusExt::signal),
        timed_out,
        cancelled,
        truncated: truncated.load(Ordering::Relaxed),
        io_error: io_error.load(Ordering::Relaxed),
    })
}

fn read_output<R: Read + Send + 'static>(
    mut reader: R,
    truncated: Arc<AtomicBool>,
    io_error: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut remaining = OUTPUT_LIMIT;
        let mut buffer = [0_u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Err(_) => {
                    io_error.store(true, Ordering::Relaxed);
                    break;
                }
                Ok(read) if read <= remaining => remaining -= read,
                Ok(_) => {
                    truncated.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    })
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use evertrace_capture::{
        DeviceKeyStore, RecoveryGateMode, RecoverySnapshotSettings, RuntimeSnapshot, SpoolLimits,
        protect,
    };
    use evertrace_domain::{
        ids::{RecoveryCaptureRequestId, RepositoryId, WorktreeSnapshotId},
        repository::{
            DestructiveClass, DestructiveDetectionStatus, FilesystemIdentity, GitObjectFormat,
            GitOperation, GitRegistrationState, PathObservation, RecoveryBundle,
            RecoveryCaptureRequest, RecoveryContentRef, RecoveryProtectedRef, RecoveryReasonCode,
            RecoveryRequestStatus, RepositoryInstance, UntrackedCaptureScope, WorktreeInstance,
            WorktreeKind, WorktreeSnapshot,
        },
    };
    use evertrace_store::JournalWriter;

    struct ActionHarness {
        root: PathBuf,
        worktree: PathBuf,
        store: PathBuf,
        runtime: RuntimeSnapshot,
        handle: WriterHandle,
        writer_task: tokio::task::JoinHandle<Result<(), crate::WriterActorError>>,
        service: RecoveryActionService,
        request: RecoveryRequest,
    }

    impl ActionHarness {
        async fn close(self) {
            self.service.shutdown_and_drain().await;
            self.handle.shutdown().await.unwrap();
            self.writer_task.await.unwrap().unwrap();
            std::fs::remove_dir_all(self.root).unwrap();
        }
    }

    fn git(cwd: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("HOME", "/nonexistent")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    async fn action_harness() -> ActionHarness {
        let root = std::env::temp_dir().join(format!("evertrace-action-{}", CommandId::new_v7()));
        let worktree = root.join("worktree");
        let store = root.join("store");
        std::fs::create_dir_all(&worktree).unwrap();
        std::fs::create_dir_all(&store).unwrap();
        std::fs::set_permissions(&worktree, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        git(&worktree, &["init", "--quiet"]);
        git(
            &worktree,
            &["config", "user.email", "action@example.invalid"],
        );
        git(&worktree, &["config", "user.name", "Action"]);
        std::fs::write(worktree.join("tracked.txt"), b"before\n").unwrap();
        git(&worktree, &["add", "tracked.txt"]);
        git(&worktree, &["commit", "--quiet", "-m", "base"]);
        std::fs::write(worktree.join("tracked.txt"), b"after\n").unwrap();
        let patch = Command::new("git")
            .args(["diff", "--binary", "--", "tracked.txt"])
            .current_dir(&worktree)
            .env_clear()
            .env("HOME", "/nonexistent")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap()
            .stdout;
        git(&worktree, &["restore", "--", "tracked.txt"]);

        let runtime = RuntimeSnapshot::for_data_dir(
            &store,
            1,
            SpoolLimits {
                high_watermark_bytes: 1 << 20,
                low_watermark_bytes: 1,
                max_main_files: 8,
                emergency_slots: 1,
            },
            RecoverySnapshotSettings {
                gate: RecoveryGateMode::Active,
                preflight_timeout_ms: 10_000,
                effective_config_hash: [7; 32],
                adapter_manifest_id: Some("adapter-action-test".into()),
                classifier_revision: evertrace_codex::recovery::RECOVERY_CLASSIFIER_REVISION,
                max_bundle_bytes: 4 << 20,
                max_untracked_file_bytes: 1 << 20,
                max_untracked_total_bytes: 2 << 20,
            },
        )
        .unwrap();
        let cas = CasStore::open(runtime.cas_dir.clone()).unwrap();
        let key = DeviceKeyStore::new(runtime.device_key_dir.clone())
            .load_or_create()
            .unwrap();
        let patch_digest = cas.put(&protect(&patch, &key).unwrap()).unwrap();
        let repository_id = RepositoryId::new_v7();
        let worktree_id = WorktreeId::new_v7();
        let snapshot_id = WorktreeSnapshotId::new_v7();
        let capture_request_id = RecoveryCaptureRequestId::new_v7();
        let bundle_id = RecoveryBundleId::new_v7();
        let canonical = std::fs::canonicalize(&worktree).unwrap();
        let git_dir = canonical.join(".git");
        let git_metadata = std::fs::metadata(&git_dir).unwrap();
        let path = canonical.to_string_lossy().into_owned();
        let path_observation = PathObservation {
            path: path.clone(),
            first_observed_at_us: 1,
            last_observed_at_us: 1,
            evidence_refs: vec!["action-path".into()],
        };
        let repository = RepositoryInstance {
            repository_id,
            repository_revision: 1,
            predecessor_revision: None,
            current_path: path.clone(),
            path_history: vec![path_observation.clone()],
            git_common_dir_path: Some(git_dir.to_string_lossy().into_owned()),
            common_dir_filesystem: Some(FilesystemIdentity {
                device: git_metadata.dev(),
                inode: git_metadata.ino(),
            }),
            object_format: Some(GitObjectFormat::Sha1),
            remote_fingerprints: vec![],
            derived_from: None,
            identity_evidence_refs: vec!["action-common-dir".into()],
            recorded_at_us: 1,
        };
        let worktree_object = WorktreeInstance {
            worktree_instance_id: worktree_id,
            worktree_revision: 1,
            predecessor_revision: None,
            repository_instance_id: repository_id,
            kind: WorktreeKind::Main,
            lifecycle: WorktreeLifecycle::Active,
            current_path: Some(path.clone()),
            path_history: vec![path_observation.clone()],
            git_admin_path_history: vec![PathObservation {
                path: git_dir.to_string_lossy().into_owned(),
                evidence_refs: vec!["action-admin".into()],
                ..path_observation
            }],
            git_registration_state: GitRegistrationState::Registered,
            current_snapshot_id: Some(snapshot_id),
            created_event_ref: "action-worktree".into(),
            terminal_event_ref: None,
            recreated_from_worktree_instance_id: None,
            recorded_at_us: 1,
        };
        let snapshot_object = WorktreeSnapshot {
            worktree_snapshot_id: snapshot_id,
            worktree_instance_id: worktree_id,
            head_oid: Some(git(&worktree, &["rev-parse", "HEAD"])),
            tree_oid: Some(git(&worktree, &["rev-parse", "HEAD^{tree}"])),
            branch_ref: Some(git(&worktree, &["symbolic-ref", "HEAD"])),
            detached_head: false,
            tracked_diff_digest: None,
            index_digest: None,
            untracked_manifest_digest: None,
            relevant_anchor_digests: vec![],
            dependency_fingerprints: vec![],
            toolchain_fingerprint: None,
            git_operation: GitOperation::None,
            captured_at_us: 2,
            evidence_refs: vec!["action-snapshot".into()],
            capture_status: SnapshotCaptureStatus::Complete,
            omission_reasons: vec![],
        };
        let pending_revision = RevisionId::new_v7();
        let pending = RecoveryCaptureRequest {
            recovery_capture_request_id: capture_request_id,
            request_revision_id: pending_revision,
            parent_request_revision_id: None,
            trigger_event_id: "action-trigger".into(),
            repository_instance_id: repository_id,
            worktree_instance_id: worktree_id,
            pre_operation_snapshot_id: None,
            command_fingerprint: "ab".repeat(32),
            destructive_class: DestructiveClass::GitRestoreDiscard,
            untracked_capture_scope: UntrackedCaptureScope::Standard,
            detection_status: DestructiveDetectionStatus::Matched,
            request_status: RecoveryRequestStatus::Pending,
            recovery_bundle_id: None,
            reason_codes: vec![],
            started_at_us: 3,
            finished_at_us: None,
            effective_config_hash: [7; 32],
        };
        let terminal = RecoveryCaptureRequest {
            request_revision_id: RevisionId::new_v7(),
            parent_request_revision_id: Some(pending_revision),
            pre_operation_snapshot_id: Some(snapshot_id),
            request_status: RecoveryRequestStatus::Complete,
            recovery_bundle_id: Some(bundle_id),
            reason_codes: vec![RecoveryReasonCode::CaptureComplete],
            finished_at_us: Some(4),
            ..pending.clone()
        };
        let bundle = RecoveryBundle {
            recovery_bundle_id: bundle_id,
            source_worktree_instance_id: worktree_id,
            source_snapshot_id: snapshot_id,
            trigger_request_ids: vec![capture_request_id],
            tracked_diff_blob_refs: vec![RecoveryContentRef {
                item_ref: "git:tracked_diff".into(),
                payload: RecoveryProtectedRef {
                    cas_ref: patch_digest.to_string(),
                    protected_length: patch.len() as u64,
                    original_length: patch.len() as u64,
                    protected_secret_digest: None,
                    redaction_spans: 0,
                },
                protected_relative_path: None,
            }],
            tracked_file_blob_refs: vec![],
            index_state_refs: vec![],
            untracked_file_blob_refs: vec![],
            untracked_work_artifact_refs: vec![],
            metadata_only_work_artifact_refs: vec![],
            config_and_run_refs: vec![],
            attempt_anchor_ids: vec![],
            attempt_anchor_claims: vec![],
            omissions: vec![],
            capture_status: RecoveryCaptureStatus::Complete,
            ordering_integrity: OrderingIntegrity::Complete,
            adapter_manifest_id: "adapter-action-test".into(),
            eligible_mutation_manifest_version: 1,
            eligible_mutation_domain: evertrace_domain::repository::SUPPORTED_MUTATION_DOMAIN
                .into(),
            captured_bytes: patch.len() as u64,
            captured_at_us: 4,
        };
        let mut writer = JournalWriter::open(&store).await.unwrap();
        for (at, payloads) in [
            (
                1,
                vec![
                    JournalPayload::RepositoryInstanceRecorded(Box::new(repository)),
                    JournalPayload::WorktreeInstanceRecorded(Box::new(worktree_object)),
                    JournalPayload::WorktreeSnapshotRecorded(Box::new(snapshot_object)),
                ],
            ),
            (
                3,
                vec![JournalPayload::RecoveryCaptureRequestRecorded(Box::new(
                    pending,
                ))],
            ),
            (
                4,
                vec![
                    JournalPayload::RecoveryCaptureRequestRecorded(Box::new(terminal)),
                    JournalPayload::RecoveryBundleRecorded(Box::new(bundle)),
                ],
            ),
        ] {
            writer
                .commit(
                    &JournalCommand::new(
                        CommandId::new_v7(),
                        payloads
                            .into_iter()
                            .map(|payload| {
                                JournalEventDraft::runtime(
                                    at,
                                    [7; 32],
                                    ACTION_ALGORITHM_REVISION,
                                    payload,
                                )
                            })
                            .collect(),
                    )
                    .unwrap(),
                    at,
                )
                .await
                .unwrap();
        }
        let (handle, writer_task) = crate::spawn_writer(writer, 16).unwrap();
        let service = RecoveryActionService::new(
            runtime.clone(),
            handle.clone(),
            RecoveryMutationFence::default(),
        );
        ActionHarness {
            root,
            worktree,
            store,
            runtime,
            handle,
            writer_task,
            service,
            request: RecoveryRequest {
                request_id: RequestId::new_v7(),
                recovery_bundle_id: bundle_id,
                target_worktree_instance_id: worktree_id,
                application_kind: RecoveryApplicationKind::Patch,
            },
        }
    }

    async fn current_application(harness: &ActionHarness) -> Option<RecoveryApplication> {
        RecoveryCurrentView::from_snapshot(&harness.handle.project().await.unwrap())
            .unwrap()
            .state
            .applications
            .get(&RecoveryApplicationId::from_uuid(harness.request.request_id.as_uuid()).unwrap())
            .cloned()
    }

    fn action_observation_id(
        request: RecoveryRequest,
        record: &str,
    ) -> evertrace_domain::ids::SourceObservationId {
        evertrace_domain::evidence::source_observation_id(
            &evertrace_domain::evidence::SourceInstanceId::parse(format!(
                "recovery-{}",
                request.request_id
            ))
            .unwrap(),
            &evertrace_domain::evidence::SourceRevision::parse("action-v1").unwrap(),
            &evertrace_domain::evidence::SourceRecordIdentity::parse(record).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn admission_fault_is_zero_spawn_zero_mutation_and_zero_application() {
        let harness = action_harness().await;
        harness.service.set_test_fault(TestFault::AdmissionCommit);
        assert!(matches!(
            harness.service.handle(harness.request).await,
            Err(RecoveryError::Store)
        ));
        assert_eq!(
            harness.service.faults.spawn_count.load(Ordering::Acquire),
            0
        );
        assert_eq!(
            std::fs::read(harness.worktree.join("tracked.txt")).unwrap(),
            b"before\n"
        );
        assert!(current_application(&harness).await.is_none());
        let spool = harness.runtime.spool_dir.join("main");
        assert!(!spool.exists() || std::fs::read_dir(spool).unwrap().next().is_none());
        harness.close().await;
    }

    #[tokio::test]
    async fn intent_fault_reaps_before_eof_and_replay_never_respawns() {
        let harness = action_harness().await;
        harness.service.set_test_fault(TestFault::IntentPersistence);
        let outcome = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            outcome,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Unknown,
                ..
            }
        ));
        assert_eq!(
            harness.service.faults.spawn_count.load(Ordering::Acquire),
            1
        );
        let pid = harness
            .service
            .faults
            .last_child_pid
            .load(Ordering::Acquire);
        assert_ne!(pid, 0);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert_eq!(
            std::fs::read(harness.worktree.join("tracked.txt")).unwrap(),
            b"before\n"
        );
        let current = current_application(&harness).await.unwrap();
        assert_eq!(
            current.input_delivery_state,
            RecoveryInputDeliveryState::Admitted
        );
        assert_eq!(
            current.application_status,
            RecoveryApplicationStatus::Unknown
        );
        let projected = harness.handle.project().await.unwrap();
        let evidence =
            evertrace_store::projections::RecoveryEvidenceCurrentView::from_snapshot(&projected)
                .unwrap();
        assert!(
            evidence
                .receipt_for_observation(action_observation_id(harness.request, "patch-stdin"))
                .is_none()
        );
        assert!(
            evidence
                .receipt_for_observation(action_observation_id(harness.request, "patch-result"))
                .is_some()
        );
        let replay = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            replay,
            RecoveryActionOutcome::Application { replayed: true, .. }
        ));
        assert_eq!(
            harness.service.faults.spawn_count.load(Ordering::Acquire),
            1
        );
        harness.close().await;
    }

    #[tokio::test]
    async fn terminal_commit_fault_recovers_from_journal_evidence_without_respawn() {
        let harness = action_harness().await;
        harness
            .service
            .set_test_fault(TestFault::TerminalApplicationCommit);
        assert!(matches!(
            harness.service.handle(harness.request).await,
            Err(RecoveryError::Store)
        ));
        assert_eq!(
            harness.service.faults.spawn_count.load(Ordering::Acquire),
            1
        );
        assert_eq!(
            std::fs::read(harness.worktree.join("tracked.txt")).unwrap(),
            b"after\n"
        );
        let current = current_application(&harness).await.unwrap();
        assert_eq!(
            current.input_delivery_state,
            RecoveryInputDeliveryState::Admitted
        );

        harness.service.shutdown_and_drain().await;
        harness.handle.shutdown().await.unwrap();
        harness.writer_task.await.unwrap().unwrap();
        let writer = JournalWriter::open(&harness.store).await.unwrap();
        let (handle, writer_task) = crate::spawn_writer(writer, 16).unwrap();
        let service = RecoveryActionService::new(
            harness.runtime.clone(),
            handle.clone(),
            RecoveryMutationFence::default(),
        );
        service.reconcile_pending_on_startup().await.unwrap();
        let restored =
            RecoveryCurrentView::from_snapshot(&handle.project().await.unwrap()).unwrap();
        let application_id =
            RecoveryApplicationId::from_uuid(harness.request.request_id.as_uuid()).unwrap();
        assert_eq!(
            restored.state.applications[&application_id].application_status,
            RecoveryApplicationStatus::Applied
        );
        assert_eq!(service.faults.spawn_count.load(Ordering::Acquire), 0);
        service.shutdown_and_drain().await;
        handle.shutdown().await.unwrap();
        writer_task.await.unwrap().unwrap();
        std::fs::remove_dir_all(harness.root).unwrap();
    }

    #[tokio::test]
    async fn shutdown_cancels_a_real_owned_child_reaps_and_releases_the_fence() {
        let harness = action_harness().await;
        harness.service.set_test_fault(TestFault::StallAfterSpawn);
        let service = harness.service.clone();
        let request = harness.request;
        let action = tokio::spawn(async move { service.handle(request).await });
        while harness.service.faults.spawn_count.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
        harness.service.shutdown_and_drain().await;
        let _ = action.await.unwrap();
        let pid = harness
            .service
            .faults
            .last_child_pid
            .load(Ordering::Acquire);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert!(
            harness
                .service
                .fence
                .acquire(harness.request.target_worktree_instance_id)
                .is_ok()
        );
        assert_eq!(
            std::fs::read(harness.worktree.join("tracked.txt")).unwrap(),
            b"before\n"
        );
        harness.handle.shutdown().await.unwrap();
        harness.writer_task.await.unwrap().unwrap();
        let reopened = JournalWriter::open(&harness.store).await.unwrap();
        drop(reopened);
        std::fs::remove_dir_all(harness.root).unwrap();
    }

    #[tokio::test]
    async fn started_child_timeout_persists_a_real_terminal_result_and_stays_unknown() {
        let mut harness = action_harness().await;
        harness.service.snapshot.recovery_preflight_timeout_ms = 30_000;
        harness.service.set_test_fault(TestFault::TimeoutAfterSpawn);
        let outcome = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            outcome,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Unknown,
                ..
            }
        ));
        assert_eq!(
            harness.service.faults.spawn_count.load(Ordering::Acquire),
            1
        );
        let pid = harness
            .service
            .faults
            .last_child_pid
            .load(Ordering::Acquire);
        assert_ne!(pid, 0);
        let current = current_application(&harness).await.unwrap();
        assert_eq!(
            current.input_delivery_state,
            RecoveryInputDeliveryState::Admitted
        );
        let result_id = action_observation_id(harness.request, "patch-result");
        let projected = harness.handle.project().await.unwrap();
        let evidence =
            evertrace_store::projections::RecoveryEvidenceCurrentView::from_snapshot(&projected)
                .unwrap();
        let receipt = evidence.receipt_for_observation(result_id).unwrap();
        let cas = CasStore::open(harness.runtime.cas_dir.clone()).unwrap();
        let digest = CasDigest::from_str(&receipt.cas_ref).unwrap();
        let terminal = cas.read(&digest).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&terminal).unwrap();
        assert_eq!(value["timed_out"], true);
        assert_eq!(value["normal_exit"], false);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        harness.close().await;
    }

    #[tokio::test]
    async fn normal_child_failure_plus_unchanged_fixed_verifier_is_failed() {
        let harness = action_harness().await;
        harness
            .service
            .set_test_fault(TestFault::NormalFailureUnchanged);
        let outcome = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            outcome,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Failed,
                ..
            }
        ));
        assert_eq!(
            std::fs::read(harness.worktree.join("tracked.txt")).unwrap(),
            b"before\n"
        );
        assert_eq!(
            harness.service.faults.spawn_count.load(Ordering::Acquire),
            1
        );
        let current = current_application(&harness).await.unwrap();
        assert_eq!(
            current.post_application_snapshot_id,
            Some(current.pre_application_snapshot_id)
        );
        assert_eq!(current.verifier_receipts.len(), 1);
        assert_eq!(
            current.verifier_receipts[0].outcome,
            RecoveryVerificationOutcome::NotApplied
        );
        harness.close().await;
    }

    #[tokio::test]
    async fn affected_stage_head_admin_and_root_races_never_spawn_the_mutator() {
        for fault in [
            TestFault::RaceAffectedStage,
            TestFault::RaceAffectedHead,
            TestFault::RaceAdminLocator,
            TestFault::RaceRootLocator,
        ] {
            let harness = action_harness().await;
            harness.service.set_test_fault(fault);
            let outcome = harness.service.handle(harness.request).await.unwrap();
            assert!(matches!(
                outcome,
                RecoveryActionOutcome::Application {
                    application_status: RecoveryApplicationStatus::Unknown,
                    ..
                }
            ));
            assert_eq!(
                harness.service.faults.spawn_count.load(Ordering::Acquire),
                0,
                "{fault:?}"
            );
            let current = current_application(&harness).await.unwrap();
            assert_eq!(
                current.input_delivery_state,
                RecoveryInputDeliveryState::Admitted
            );
            harness.close().await;
        }
    }

    #[tokio::test]
    async fn post_snapshot_and_affected_identity_share_one_stable_interval() {
        let harness = action_harness().await;
        harness
            .service
            .set_test_fault(TestFault::RaceAffectedDuringPostCapture);
        let outcome = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            outcome,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Unknown,
                ..
            }
        ));
        let current = current_application(&harness).await.unwrap();
        assert_eq!(
            current.input_delivery_state,
            RecoveryInputDeliveryState::Delivered
        );
        assert!(current.post_application_snapshot_id.is_none());
        assert!(current.verifier_receipts.is_empty());
        assert_eq!(
            harness.service.faults.spawn_count.load(Ordering::Acquire),
            1
        );
        harness.close().await;

        let harness = action_harness().await;
        harness
            .service
            .set_test_fault(TestFault::RaceUnrelatedDuringPostCapture);
        let outcome = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            outcome,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Applied,
                ..
            }
        ));
        assert_eq!(
            std::fs::read(harness.worktree.join("unrelated-post-snapshot.txt")).unwrap(),
            b"unrelated\n"
        );
        harness.close().await;
    }

    #[test]
    fn malicious_git_environment_is_isolated_in_a_dedicated_test_process() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery::action::tests::git_environment_child_entry",
                "--nocapture",
            ])
            .env("EVERTRACE_GIT_ENV_CHILD", "1")
            .env("GIT_DIR", "/nonexistent/attacker.git")
            .env("GIT_WORK_TREE", "/nonexistent/attacker-worktree")
            .env("GIT_INDEX_FILE", "/nonexistent/attacker-index")
            .env("GIT_OBJECT_DIRECTORY", "/nonexistent/objects")
            .env("GIT_ALTERNATE_OBJECT_DIRECTORIES", "/nonexistent/alternate")
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "core.worktree")
            .env("GIT_CONFIG_VALUE_0", "/nonexistent/config-worktree")
            .env("HOME", "/nonexistent/attacker-home")
            .env("XDG_CONFIG_HOME", "/nonexistent/attacker-xdg")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn git_environment_child_entry() {
        if std::env::var_os("EVERTRACE_GIT_ENV_CHILD").is_none() {
            return;
        }
        let harness = action_harness().await;
        let outcome = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            outcome,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Applied,
                ..
            }
        ));
        assert_eq!(
            std::fs::read(harness.worktree.join("tracked.txt")).unwrap(),
            b"after\n"
        );
        harness.close().await;
    }

    #[tokio::test]
    async fn intent_only_restart_is_unknown_and_late_fixed_verifier_is_event_driven() {
        let harness = action_harness().await;
        harness
            .service
            .set_test_fault(TestFault::SkipTerminalCapture);
        let outcome = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            outcome,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Unknown,
                ..
            }
        ));
        assert_eq!(
            harness.service.faults.spawn_count.load(Ordering::Acquire),
            1
        );
        let frontier = harness.handle.project().await.unwrap().frontier;
        harness
            .service
            .reconcile_pending_on_startup()
            .await
            .unwrap();
        let ingested_frontier = harness.handle.project().await.unwrap().frontier;
        assert!(ingested_frontier > frontier);
        let projected = harness.handle.project().await.unwrap();
        let evidence =
            evertrace_store::projections::RecoveryEvidenceCurrentView::from_snapshot(&projected)
                .unwrap();
        assert!(
            evidence
                .receipt_for_observation(action_observation_id(harness.request, "patch-stdin"))
                .is_some()
        );
        assert!(
            evidence
                .receipt_for_observation(action_observation_id(harness.request, "patch-result"))
                .is_none()
        );
        harness
            .service
            .reconcile_pending_on_startup()
            .await
            .unwrap();
        assert_eq!(
            harness.handle.project().await.unwrap().frontier,
            ingested_frontier
        );
        let replay = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            replay,
            RecoveryActionOutcome::Application { replayed: true, .. }
        ));
        assert_eq!(
            harness.service.faults.spawn_count.load(Ordering::Acquire),
            1
        );
        harness.close().await;

        let harness = action_harness().await;
        harness
            .service
            .set_test_fault(TestFault::VerifierUnavailable(2));
        let first = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            first,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Unknown,
                ..
            }
        ));
        std::fs::rename(
            harness.worktree.join("tracked.txt"),
            harness.worktree.join("tracked-terminal-original.txt"),
        )
        .unwrap();
        std::fs::write(harness.worktree.join("tracked.txt"), b"tampered\n").unwrap();
        let frontier = harness.handle.project().await.unwrap().frontier;
        let replay = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            replay,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Unknown,
                replayed: true,
                ..
            }
        ));
        let tamper_frontier = harness.handle.project().await.unwrap().frontier;
        assert!(tamper_frontier >= frontier);
        let replay = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            replay,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Unknown,
                replayed: true,
                ..
            }
        ));
        assert_eq!(
            harness.handle.project().await.unwrap().frontier,
            tamper_frontier
        );
        assert_eq!(
            harness.service.faults.spawn_count.load(Ordering::Acquire),
            1
        );
        harness.close().await;

        let harness = action_harness().await;
        harness
            .service
            .set_test_fault(TestFault::VerifierUnavailable(2));
        let first = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            first,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Unknown,
                ..
            }
        ));
        let delivered = current_application(&harness).await.unwrap();
        assert_eq!(
            delivered.input_delivery_state,
            RecoveryInputDeliveryState::Delivered
        );
        assert!(delivered.post_application_snapshot_id.is_some());
        assert!(delivered.verifier_receipts.is_empty());
        std::fs::write(harness.worktree.join("unrelated.txt"), b"unrelated\n").unwrap();
        git(&harness.worktree, &["add", "--", "unrelated.txt"]);
        git(
            &harness.worktree,
            &["commit", "--quiet", "-m", "unrelated-after-terminal"],
        );
        let spawn_count = harness.service.faults.spawn_count.load(Ordering::Acquire);
        let verified = harness.service.handle(harness.request).await.unwrap();
        assert!(
            matches!(
                verified,
                RecoveryActionOutcome::Application {
                    application_status: RecoveryApplicationStatus::Applied,
                    replayed: true,
                    ..
                }
            ),
            "{verified:?}"
        );
        assert_eq!(
            harness.service.faults.spawn_count.load(Ordering::Acquire),
            spawn_count
        );
        let verified_frontier = harness.handle.project().await.unwrap().frontier;
        let replay = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            replay,
            RecoveryActionOutcome::Application { replayed: true, .. }
        ));
        assert_eq!(
            harness.handle.project().await.unwrap().frontier,
            verified_frontier
        );
        harness.close().await;

        let harness = action_harness().await;
        harness
            .service
            .set_test_fault(TestFault::NormalFailureVerifierUnavailable(2));
        let first = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            first,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Unknown,
                ..
            }
        ));
        let delivered = current_application(&harness).await.unwrap();
        assert_eq!(
            delivered.post_application_snapshot_id,
            Some(delivered.pre_application_snapshot_id)
        );
        assert!(delivered.verifier_receipts.is_empty());
        let spawn_count = harness.service.faults.spawn_count.load(Ordering::Acquire);
        let verified = harness.service.handle(harness.request).await.unwrap();
        assert!(matches!(
            verified,
            RecoveryActionOutcome::Application {
                application_status: RecoveryApplicationStatus::Failed,
                replayed: true,
                ..
            }
        ));
        assert_eq!(
            harness.service.faults.spawn_count.load(Ordering::Acquire),
            spawn_count
        );
        harness.close().await;
    }

    #[test]
    fn cancellation_after_spawn_kills_and_reaps_the_owned_child() {
        let root =
            std::env::temp_dir().join(format!("evertrace-cancelled-child-{}", CommandId::new_v7()));
        std::fs::create_dir_all(&root).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(&root)
                .status()
                .unwrap()
                .success()
        );
        let cancellation = AtomicBool::new(false);
        let child_pid = std::sync::atomic::AtomicU32::new(0);
        let deadline = Instant::now() + Duration::from_secs(5);
        let result = run_git_apply_inner(
            &root,
            &[b'x'; 1 << 20],
            &["apply", "--whitespace=nowarn", "-"],
            deadline,
            &cancellation,
            |pid| {
                child_pid.store(pid, Ordering::Release);
                cancellation.store(true, Ordering::Release);
                deadline
            },
            || Ok(()),
        )
        .unwrap();
        let pid = child_pid.load(Ordering::Acquire);
        assert_ne!(pid, 0);
        assert!(result.cancelled);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn custody_shutdown_cancels_and_drains_without_a_lost_wakeup() {
        for _ in 0..128 {
            let custody = Arc::new(ActionCustody::default());
            assert!(custody.register());
            let draining = {
                let custody = Arc::clone(&custody);
                tokio::spawn(async move { custody.shutdown_and_drain().await })
            };
            while !custody.cancelled.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            custody.finish();
            draining.await.unwrap();
            assert_eq!(custody.active.load(Ordering::Acquire), 0);
            assert!(!custody.register());
        }
    }
}
