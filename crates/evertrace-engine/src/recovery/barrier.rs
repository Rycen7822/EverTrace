use super::capture::{PrepareCaptureContext, prepare_capture, tracked_paths};
use super::{RecoveryError, pending_request_command, terminal_capture_command};
use evertrace_capture::CasStore;
use evertrace_domain::{
    ids::{CommandId, RecoveryBundleId},
    repository::{RecoveryCaptureRequest, RecoveryReasonCode, RecoveryRequestStatus},
};
use evertrace_store::projections::RecoveryCurrentView;
use std::{
    collections::BTreeSet,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryBarrierLocator {
    pub spool_record_id: String,
    pub recovery_capture_request_id: evertrace_domain::ids::RecoveryCaptureRequestId,
    pub pending_revision_id: evertrace_domain::revision::RevisionId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryTerminalAck {
    pub recovery_capture_request_id: evertrace_domain::ids::RecoveryCaptureRequestId,
    pub pending_revision_id: evertrace_domain::revision::RevisionId,
    pub terminal_revision_id: evertrace_domain::revision::RevisionId,
    pub status: RecoveryRequestStatus,
    pub recovery_bundle_id: Option<RecoveryBundleId>,
}

#[derive(Clone)]
pub struct RecoveryBarrierService {
    snapshot: evertrace_capture::RuntimeSnapshot,
    writer: crate::WriterHandle,
    fence: RecoveryMutationFence,
}

#[derive(Clone, Default)]
pub struct RecoveryMutationFence {
    fenced: Arc<Mutex<BTreeSet<evertrace_domain::ids::WorktreeId>>>,
}

pub(super) struct RecoveryFenceLease {
    fenced: Arc<Mutex<BTreeSet<evertrace_domain::ids::WorktreeId>>>,
    worktree_id: evertrace_domain::ids::WorktreeId,
}

struct CaptureAndCommitContext<'a> {
    locator: &'a RecoveryBarrierLocator,
    pending: &'a RecoveryCaptureRequest,
    adapter_manifest_id: &'a str,
    target_path: &'a std::path::Path,
    protected_target_paths: Vec<std::path::PathBuf>,
    repository_view: &'a evertrace_store::repository::RepositoryCurrentView,
    recovery_view: &'a RecoveryCurrentView,
    attempt_view: &'a evertrace_store::projections::AttemptCurrentView,
    attempt_anchor_ids: Vec<evertrace_domain::ids::AttemptId>,
    artifact_refs: Vec<String>,
    config_and_run_refs: Vec<String>,
    frontier: u64,
    cas: &'a CasStore,
    deadline: RecoveryDeadline,
    lease: RecoveryFenceLease,
    pinned_root: evertrace_capture::ConfinedRoot,
}

impl RecoveryFenceLease {
    fn acquire(
        fenced: Arc<Mutex<BTreeSet<evertrace_domain::ids::WorktreeId>>>,
        worktree_id: evertrace_domain::ids::WorktreeId,
    ) -> Result<Self, RecoveryError> {
        if !fenced
            .lock()
            .map_err(|_| RecoveryError::FenceBusy)?
            .insert(worktree_id)
        {
            return Err(RecoveryError::FenceBusy);
        }
        Ok(Self {
            fenced,
            worktree_id,
        })
    }
}

impl RecoveryMutationFence {
    pub(super) fn acquire(
        &self,
        worktree_id: evertrace_domain::ids::WorktreeId,
    ) -> Result<RecoveryFenceLease, RecoveryError> {
        RecoveryFenceLease::acquire(Arc::clone(&self.fenced), worktree_id)
    }
}

impl Drop for RecoveryFenceLease {
    fn drop(&mut self) {
        if let Ok(mut fenced) = self.fenced.lock() {
            fenced.remove(&self.worktree_id);
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct RecoveryDeadline(pub(super) Instant);

impl RecoveryDeadline {
    fn from_pending(started_at_us: i64, timeout_ms: u32) -> Self {
        let elapsed_us = current_time_us().saturating_sub(started_at_us).max(0) as u64;
        let total_us = u64::from(timeout_ms).saturating_mul(1_000);
        let remaining = total_us.saturating_sub(elapsed_us);
        Self(Instant::now() + Duration::from_micros(remaining))
    }

    pub(super) fn remaining_ms(self) -> Result<u64, RecoveryError> {
        let remaining = self
            .0
            .checked_duration_since(Instant::now())
            .ok_or(RecoveryError::Deadline)?;
        Ok(u64::try_from(remaining.as_millis())
            .unwrap_or(u64::MAX)
            .max(1))
    }

    pub(super) fn expired(self) -> bool {
        Instant::now() >= self.0
    }
}

impl RecoveryBarrierService {
    fn probe_limits(
        &self,
        deadline: RecoveryDeadline,
    ) -> Result<crate::repository::ProbeLimits, RecoveryError> {
        let max_bundle = usize::try_from(self.snapshot.recovery_max_bundle_bytes)
            .map_err(|_| RecoveryError::Budget)?;
        Ok(crate::repository::ProbeLimits {
            max_stdout_bytes: max_bundle,
            max_stderr_bytes: 16 << 10,
            max_records: 4096,
            max_untracked_paths: 128,
            max_diff_bytes: max_bundle,
            max_duration_ms: deadline.remaining_ms()?,
        })
    }

    pub fn new(snapshot: evertrace_capture::RuntimeSnapshot, writer: crate::WriterHandle) -> Self {
        Self {
            snapshot,
            writer,
            fence: RecoveryMutationFence::default(),
        }
    }

    pub fn mutation_fence(&self) -> RecoveryMutationFence {
        self.fence.clone()
    }

    pub async fn handle(
        &self,
        locator: RecoveryBarrierLocator,
    ) -> Result<RecoveryTerminalAck, RecoveryError> {
        if self.snapshot.recovery_gate != evertrace_capture::RecoveryGateMode::Active {
            return Err(RecoveryError::GateInactive);
        }
        let spool = evertrace_capture::DurableSpool::open_read_only(
            self.snapshot.spool_dir.clone(),
            self.snapshot
                .spool_limits()
                .map_err(|_| RecoveryError::Spool)?,
        )
        .map_err(|_| RecoveryError::Spool)?;
        let record = spool
            .find_durable_record(
                &locator.spool_record_id,
                64,
                self.snapshot.main_high_watermark_bytes,
            )
            .map_err(|_| RecoveryError::Spool)?
            .ok_or(RecoveryError::PendingUnavailable)?;
        let body = evertrace_capture::decode_record_body(&record.record_body)
            .map_err(|_| RecoveryError::PendingUnavailable)?;
        let candidate = body
            .recovery_preflight
            .ok_or(RecoveryError::PendingUnavailable)?;
        if candidate.recovery_capture_request_id != locator.recovery_capture_request_id
            || candidate.pending_revision_id != locator.pending_revision_id
            || record.spool_record_id != locator.spool_record_id
        {
            return Err(RecoveryError::PendingUnavailable);
        }
        let deadline = RecoveryDeadline::from_pending(
            body.recorded_at_us,
            self.snapshot.recovery_preflight_timeout_ms,
        );
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let initial_recovery = RecoveryCurrentView::from_snapshot(&projected)?;
        let existing_pending = match initial_recovery
            .state
            .requests
            .get(&locator.recovery_capture_request_id)
        {
            Some(request) if request.request_status.is_terminal() => {
                if request.parent_request_revision_id != Some(locator.pending_revision_id) {
                    return Err(RecoveryError::PendingUnavailable);
                }
                return ack(request, locator.pending_revision_id);
            }
            Some(request)
                if request.request_status == RecoveryRequestStatus::Pending
                    && request.request_revision_id == locator.pending_revision_id
                    && request.parent_request_revision_id.is_none() =>
            {
                Some(request.clone())
            }
            Some(_) => return Err(RecoveryError::PendingUnavailable),
            None => None,
        };
        if let Some(pending) = existing_pending.as_ref() {
            return if deadline.expired() {
                self.commit_timed_out(pending).await
            } else {
                self.commit_failed(pending).await
            };
        }
        let cas = evertrace_capture::CasStore::open(self.snapshot.cas_dir.clone())
            .map_err(|_| RecoveryError::Cas)?;
        let raw = cas
            .read(
                &evertrace_capture::CasDigest::from_str(&body.cas_ref)
                    .map_err(|_| RecoveryError::PendingUnavailable)?,
            )
            .map_err(|_| RecoveryError::PendingUnavailable)?;
        let raw = std::str::from_utf8(&raw).map_err(|_| RecoveryError::NotAdmitted)?;
        let repository_view =
            evertrace_store::repository::RepositoryCurrentView::from_snapshot(&projected)?;
        let source_worktree_id = body
            .worktree_instance_id
            .ok_or(RecoveryError::NotAdmitted)?;
        let source_repository_id = body
            .repository_instance_id
            .ok_or(RecoveryError::NotAdmitted)?;
        let source_worktree = repository_view
            .worktrees
            .get(&source_worktree_id)
            .ok_or(RecoveryError::NotAdmitted)?;
        let source_root = source_worktree
            .current_path
            .as_deref()
            .map(std::path::PathBuf::from)
            .ok_or(RecoveryError::NotAdmitted)?;
        if source_worktree.lifecycle != evertrace_domain::repository::WorktreeLifecycle::Active
            || source_worktree.repository_instance_id != source_repository_id
            || candidate.classifier_revision
                != evertrace_codex::recovery::RECOVERY_CLASSIFIER_REVISION
            || candidate.adapter_manifest_id != body.adapter_manifest_ref
        {
            return Err(RecoveryError::NotAdmitted);
        }
        let command = evertrace_codex::recovery::parse_codex_pretool_payload(raw)
            .ok_or(RecoveryError::NotAdmitted)?;
        if command.cwd != candidate.observed_cwd
            || !std::path::Path::new(&command.cwd).starts_with(&source_root)
        {
            return Err(RecoveryError::NotAdmitted);
        }
        if deadline.expired() {
            return Err(RecoveryError::NotAdmitted);
        }
        let known_worktree_roots = repository_view
            .worktrees
            .values()
            .filter(|value| {
                value.lifecycle == evertrace_domain::repository::WorktreeLifecycle::Active
                    && value.repository_instance_id == source_repository_id
            })
            .filter_map(|value| value.current_path.as_deref())
            .map(std::path::PathBuf::from)
            .collect::<Vec<_>>();
        let preliminary = evertrace_codex::recovery::classify_destructive_command(
            &evertrace_codex::recovery::DestructiveCommandInput {
                program: command.program.clone(),
                args: command.args.clone(),
                cwd: std::path::PathBuf::from(&command.cwd),
                worktree_root: source_root.clone(),
                known_worktree_roots: known_worktree_roots.clone(),
                protected_paths: Vec::new(),
            },
        );
        let target_path = if preliminary.destructive_class
            == Some(evertrace_domain::repository::DestructiveClass::GitWorktreeRemove)
        {
            preliminary
                .target_worktree
                .clone()
                .ok_or(RecoveryError::NotAdmitted)?
        } else {
            source_root
        };
        let target_worktree = repository_view
            .worktrees
            .values()
            .filter(|value| {
                value.lifecycle == evertrace_domain::repository::WorktreeLifecycle::Active
                    && value.repository_instance_id == source_repository_id
                    && value.current_path.as_deref() == target_path.to_str()
            })
            .collect::<Vec<_>>();
        if target_worktree.len() != 1 {
            return Err(RecoveryError::NotAdmitted);
        }
        let target_worktree = target_worktree[0];
        let admission_lease = self.fence.acquire(target_worktree.worktree_instance_id)?;
        let limits = self.probe_limits(deadline)?;
        let probe_path = target_path.clone();
        let untracked_scope = if preliminary.destructive_class
            == Some(evertrace_domain::repository::DestructiveClass::GitWorktreeRemove)
        {
            evertrace_domain::repository::UntrackedCaptureScope::StandardAndIgnored
        } else {
            preliminary
                .untracked_capture_scope
                .unwrap_or(evertrace_domain::repository::UntrackedCaptureScope::Standard)
        };
        let target_probe_path = probe_path.clone();
        let evidence = tokio::task::spawn_blocking(move || {
            let pinned_root = evertrace_capture::ConfinedRoot::open(&probe_path)
                .map_err(|_| crate::repository::RepositoryProbeError::InvalidInput)?;
            let pinned_cwd = pinned_root
                .proc_cwd_path()
                .map_err(|_| crate::repository::RepositoryProbeError::InvalidInput)?;
            let identity = evertrace_domain::repository::FilesystemIdentity {
                device: pinned_root.identity().device,
                inode: pinned_root.identity().inode,
            };
            crate::repository::with_probe_deadline(deadline.0, || {
                let capture = crate::repository::probe_recovery_capture_scoped_pinned(
                    &pinned_cwd,
                    identity,
                    &limits,
                    untracked_scope,
                )?;
                let target = crate::repository::probe_repository_pinned(
                    &pinned_cwd,
                    &target_probe_path,
                    identity,
                    crate::repository::HostTrustDecision::Trusted,
                    &["recovery:admission".into()],
                    current_time_us(),
                    &limits,
                    &[],
                    &[],
                )?;
                Ok::<_, crate::repository::RepositoryProbeError>((
                    capture,
                    target,
                    admission_lease,
                    pinned_root,
                ))
            })
        })
        .await;
        if deadline.expired() {
            return Err(RecoveryError::NotAdmitted);
        }
        let (evidence, target_probe, lease, pinned_root) = evidence
            .map_err(|_| RecoveryError::NotAdmitted)?
            .map_err(|_| RecoveryError::NotAdmitted)?;
        let protected_paths = tracked_paths(&target_path, evidence.index_entries.as_deref());
        if deadline.expired() {
            return Err(RecoveryError::NotAdmitted);
        }
        let protected_paths = protected_paths?;
        let classification = evertrace_codex::recovery::classify_destructive_command(
            &evertrace_codex::recovery::DestructiveCommandInput {
                program: command.program,
                args: command.args,
                cwd: std::path::PathBuf::from(command.cwd),
                worktree_root: target_path.clone(),
                known_worktree_roots,
                protected_paths,
            },
        );
        if deadline.expired() {
            return Err(RecoveryError::NotAdmitted);
        }
        if classification.detection_status
            != evertrace_domain::repository::DestructiveDetectionStatus::Matched
            || classification.target_worktree.as_ref() != Some(&target_path)
        {
            return Err(RecoveryError::NotAdmitted);
        }

        let admitted = RecoveryCaptureRequest {
            recovery_capture_request_id: candidate.recovery_capture_request_id,
            request_revision_id: candidate.pending_revision_id,
            parent_request_revision_id: None,
            trigger_event_id: body.source_record_identity.as_str().to_owned(),
            repository_instance_id: source_repository_id,
            worktree_instance_id: target_worktree.worktree_instance_id,
            pre_operation_snapshot_id: None,
            command_fingerprint: classification.command_fingerprint,
            destructive_class: classification
                .destructive_class
                .ok_or(RecoveryError::NotAdmitted)?,
            untracked_capture_scope: if classification.destructive_class
                == Some(evertrace_domain::repository::DestructiveClass::GitWorktreeRemove)
            {
                evertrace_domain::repository::UntrackedCaptureScope::StandardAndIgnored
            } else {
                classification
                    .untracked_capture_scope
                    .ok_or(RecoveryError::NotAdmitted)?
            },
            detection_status: evertrace_domain::repository::DestructiveDetectionStatus::Matched,
            request_status: RecoveryRequestStatus::Pending,
            recovery_bundle_id: None,
            reason_codes: Vec::new(),
            started_at_us: body.recorded_at_us,
            finished_at_us: None,
            effective_config_hash: self.snapshot.effective_config_hash,
        };
        admitted
            .validate()
            .map_err(|_| RecoveryError::NotAdmitted)?;
        let request = admitted;
        let protected_target_paths = classification.target_paths.clone();
        super::capture::validate_recovery_target(
            &repository_view,
            &request,
            &target_path,
            &target_probe,
        )?;

        if !initial_recovery
            .state
            .requests
            .contains_key(&request.recovery_capture_request_id)
        {
            let pending_command =
                pending_request_command(candidate.pending_command_id, request.clone())?;
            self.writer
                .commit(pending_command, body.recorded_at_us)
                .await
                .map_err(|_| RecoveryError::Store)?;
        }
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let recovery_view = RecoveryCurrentView::from_snapshot(&projected)?;
        if let Some(terminal) = recovery_view
            .state
            .requests
            .get(&locator.recovery_capture_request_id)
            .filter(|request| request.request_status.is_terminal())
        {
            return ack(terminal, locator.pending_revision_id);
        }
        let capture_result = async {
            let repository_view =
                evertrace_store::repository::RepositoryCurrentView::from_snapshot(&projected)?;
            let attempt_view =
                evertrace_store::projections::AttemptCurrentView::from_snapshot(&projected)?;
            let attempt_anchor_ids = attempt_view
                .attempts
                .values()
                .filter(|attempt| {
                    attempt.repository_instance_id == Some(request.repository_instance_id)
                        && attempt
                            .worktree_instance_ids
                            .contains(&request.worktree_instance_id)
                        && attempt.lifecycle_status
                            == evertrace_domain::work::AttemptLifecycleStatus::Active
                        && matches!(
                            attempt.execution_status,
                            evertrace_domain::work::AttemptExecutionStatus::Proposed
                                | evertrace_domain::work::AttemptExecutionStatus::Active
                                | evertrace_domain::work::AttemptExecutionStatus::Interrupted
                        )
                })
                .map(|attempt| attempt.attempt_id)
                .collect::<Vec<_>>();
            let worktree = repository_view
                .worktrees
                .get(&request.worktree_instance_id)
                .ok_or(RecoveryError::PendingUnavailable)?;
            if worktree.current_path.as_deref() != target_path.to_str()
                || worktree.repository_instance_id != request.repository_instance_id
            {
                return Err(RecoveryError::PendingUnavailable);
            }
            self.capture_and_commit(CaptureAndCommitContext {
                locator: &locator,
                pending: &request,
                adapter_manifest_id: &candidate.adapter_manifest_id,
                target_path: &target_path,
                protected_target_paths,
                repository_view: &repository_view,
                recovery_view: &recovery_view,
                attempt_view: &attempt_view,
                attempt_anchor_ids,
                artifact_refs: Vec::new(),
                config_and_run_refs: Vec::new(),
                frontier: projected.frontier,
                cas: &cas,
                deadline,
                lease,
                pinned_root,
            })
            .await
        }
        .await;
        match capture_result {
            Ok(ack) => Ok(ack),
            Err(error @ RecoveryError::Store) => Err(error),
            Err(error) => self.commit_failed(&request).await.map_err(|_| error),
        }
    }

    async fn commit_failed(
        &self,
        pending: &RecoveryCaptureRequest,
    ) -> Result<RecoveryTerminalAck, RecoveryError> {
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let current = RecoveryCurrentView::from_snapshot(&projected)?;
        if let Some(terminal) = current.terminal_request(pending.recovery_capture_request_id) {
            return ack(terminal, pending.request_revision_id);
        }
        let failed = RecoveryCaptureRequest {
            request_revision_id: evertrace_domain::revision::RevisionId::new_v7(),
            parent_request_revision_id: Some(pending.request_revision_id),
            request_status: RecoveryRequestStatus::Failed,
            reason_codes: vec![RecoveryReasonCode::DaemonCaptureFailed],
            finished_at_us: Some(terminal_finished_at(pending.started_at_us)),
            ..pending.clone()
        };
        let command = terminal_capture_command(CommandId::new_v7(), &current, failed, None, None)?;
        self.writer
            .commit_if_frontier(command, current_time_us(), current.frontier)
            .await
            .map_err(|_| RecoveryError::Store)?;
        let fresh = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let fresh = RecoveryCurrentView::from_snapshot(&fresh)?;
        let terminal = fresh
            .terminal_request(pending.recovery_capture_request_id)
            .ok_or(RecoveryError::Store)?;
        ack(terminal, pending.request_revision_id)
    }

    async fn commit_timed_out(
        &self,
        pending: &RecoveryCaptureRequest,
    ) -> Result<RecoveryTerminalAck, RecoveryError> {
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let current = RecoveryCurrentView::from_snapshot(&projected)?;
        if let Some(terminal) = current.terminal_request(pending.recovery_capture_request_id) {
            return ack(terminal, pending.request_revision_id);
        }
        let timed_out = RecoveryCaptureRequest {
            request_revision_id: evertrace_domain::revision::RevisionId::new_v7(),
            parent_request_revision_id: Some(pending.request_revision_id),
            request_status: RecoveryRequestStatus::TimedOut,
            reason_codes: vec![RecoveryReasonCode::DeadlineExhausted],
            finished_at_us: Some(terminal_finished_at(pending.started_at_us)),
            ..pending.clone()
        };
        let command =
            terminal_capture_command(CommandId::new_v7(), &current, timed_out, None, None)?;
        self.writer
            .commit_if_frontier(command, current_time_us(), current.frontier)
            .await
            .map_err(|_| RecoveryError::Store)?;
        let fresh = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let fresh = RecoveryCurrentView::from_snapshot(&fresh)?;
        let terminal = fresh
            .terminal_request(pending.recovery_capture_request_id)
            .ok_or(RecoveryError::Store)?;
        ack(terminal, pending.request_revision_id)
    }

    pub async fn reconcile_pending_on_startup(&self) -> Result<(), RecoveryError> {
        loop {
            let projected = self
                .writer
                .project()
                .await
                .map_err(|_| RecoveryError::Store)?;
            let current = RecoveryCurrentView::from_snapshot(&projected)?;
            let Some(pending) = current
                .state
                .requests
                .values()
                .find(|request| request.request_status == RecoveryRequestStatus::Pending)
                .cloned()
            else {
                return Ok(());
            };
            let timed_out = RecoveryCaptureRequest {
                request_revision_id: evertrace_domain::revision::RevisionId::new_v7(),
                parent_request_revision_id: Some(pending.request_revision_id),
                request_status: RecoveryRequestStatus::TimedOut,
                reason_codes: vec![RecoveryReasonCode::DeadlineExhausted],
                finished_at_us: Some(terminal_finished_at(pending.started_at_us)),
                ..pending
            };
            let command =
                terminal_capture_command(CommandId::new_v7(), &current, timed_out, None, None)?;
            self.writer
                .commit_if_frontier(command, current_time_us(), current.frontier)
                .await
                .map_err(|_| RecoveryError::Store)?;
        }
    }

    async fn capture_and_commit(
        &self,
        context: CaptureAndCommitContext<'_>,
    ) -> Result<RecoveryTerminalAck, RecoveryError> {
        let CaptureAndCommitContext {
            locator,
            pending,
            adapter_manifest_id,
            target_path,
            protected_target_paths,
            repository_view,
            recovery_view,
            attempt_view,
            attempt_anchor_ids,
            artifact_refs,
            config_and_run_refs,
            frontier,
            cas,
            deadline,
            lease,
            pinned_root,
        } = context;
        let snapshot_config = self.snapshot.clone();
        let locator_owned = locator.clone();
        let pending_owned = pending.clone();
        let adapter_manifest_id = adapter_manifest_id.to_owned();
        let target_path = target_path.to_path_buf();
        let repository_view = repository_view.clone();
        let attempt_view = attempt_view.clone();
        let cas = cas.clone();
        let (mut prepared, _lease, pinned_root) = tokio::task::spawn_blocking(move || {
            let mut prepared = crate::repository::with_probe_deadline(deadline.0, || {
                prepare_capture(PrepareCaptureContext {
                    runtime: &snapshot_config,
                    locator: &locator_owned,
                    pending: &pending_owned,
                    adapter_manifest_id: &adapter_manifest_id,
                    target_path: &target_path,
                    pinned_root: &pinned_root,
                    protected_target_paths,
                    repository_view: &repository_view,
                    attempt_anchor_ids,
                    artifact_refs,
                    config_and_run_refs,
                    cas: &cas,
                    deadline,
                })
            })?;
            attach_attempt_anchor_claims(
                &mut prepared,
                &attempt_view,
                &pending_owned,
                &pinned_root,
                &cas,
                &snapshot_config,
                deadline,
            );
            Ok::<_, RecoveryError>((prepared, lease, pinned_root))
        })
        .await
        .map_err(|_| RecoveryError::Probe)??;
        if pinned_root.revalidate().is_err() {
            prepared.status = status_after_root_change(prepared.status);
            if let Some(bundle) = prepared.bundle.as_mut() {
                bundle.capture_status =
                    evertrace_domain::repository::RecoveryCaptureStatus::Partial;
                bundle.ordering_integrity = evertrace_domain::repository::OrderingIntegrity::Raced;
                bundle
                    .omissions
                    .push(evertrace_domain::repository::RecoveryOmission {
                        item_ref: "worktree_root_identity".into(),
                        reason:
                            evertrace_domain::repository::RecoveryOmissionReason::ConcurrentChange,
                        metadata_ref: None,
                    });
                bundle.validate().map_err(|_| RecoveryError::Probe)?;
            }
        }
        let snapshot = prepared.snapshot;
        let bundle = prepared.bundle;
        let status = prepared.status;
        let terminal = RecoveryCaptureRequest {
            request_revision_id: evertrace_domain::revision::RevisionId::new_v7(),
            parent_request_revision_id: Some(pending.request_revision_id),
            pre_operation_snapshot_id: snapshot.as_ref().map(|value| value.worktree_snapshot_id),
            request_status: status,
            recovery_bundle_id: bundle.as_ref().map(|value| value.recovery_bundle_id),
            reason_codes: vec![match status {
                RecoveryRequestStatus::Complete => RecoveryReasonCode::CaptureComplete,
                RecoveryRequestStatus::Partial => RecoveryReasonCode::CapturePartial,
                RecoveryRequestStatus::TimedOut => RecoveryReasonCode::DeadlineExhausted,
                _ => RecoveryReasonCode::NoRecoverableContent,
            }],
            finished_at_us: Some(terminal_finished_at(pending.started_at_us)),
            ..pending.clone()
        };
        let command = terminal_capture_command(
            CommandId::new_v7(),
            recovery_view,
            terminal.clone(),
            snapshot,
            bundle,
        )?;
        self.writer
            .commit_if_frontier(command, current_time_us(), frontier)
            .await
            .map_err(|_| RecoveryError::StaleCurrent)?;
        let fresh = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let view = RecoveryCurrentView::from_snapshot(&fresh)?;
        let durable = view
            .terminal_request(locator.recovery_capture_request_id)
            .ok_or(RecoveryError::StaleCurrent)?;
        let result = ack(durable, locator.pending_revision_id);
        drop(pinned_root);
        result
    }
}

fn attach_attempt_anchor_claims(
    prepared: &mut super::capture::PreparedRecoveryCapture,
    attempts: &evertrace_store::projections::AttemptCurrentView,
    pending: &RecoveryCaptureRequest,
    pinned_root: &evertrace_capture::ConfinedRoot,
    cas: &CasStore,
    runtime: &evertrace_capture::RuntimeSnapshot,
    deadline: RecoveryDeadline,
) {
    let (Some(snapshot), Some(bundle)) = (&prepared.snapshot, &mut prepared.bundle) else {
        return;
    };
    if snapshot.capture_status != evertrace_domain::repository::SnapshotCaptureStatus::Complete
        || !bundle.is_exact_patch_only_anchor_shape()
        || bundle.attempt_anchor_ids.is_empty()
    {
        return;
    }
    let diff = &bundle.tracked_diff_blob_refs[0];
    if diff.payload.redaction_spans != 0 || diff.payload.protected_secret_digest.is_some() {
        return;
    }
    let Ok(digest) = evertrace_capture::CasDigest::from_str(&diff.payload.cas_ref) else {
        return;
    };
    let Ok(patch) = cas.read(&digest) else {
        return;
    };
    let Some(relative_path) = super::patch::strict_patch_target(&patch) else {
        return;
    };
    let Ok(file) = pinned_root.read_after_owned_mutation(
        &relative_path,
        evertrace_capture::ConfinedReadLimits {
            single_file_remaining: runtime.recovery_max_bundle_bytes,
            untracked_total_remaining: runtime.recovery_max_bundle_bytes,
            bundle_remaining: runtime.recovery_max_bundle_bytes,
            deadline: deadline.0,
        },
    ) else {
        return;
    };
    let Ok(key) = evertrace_capture::DeviceKeyStore::new(runtime.device_key_dir.clone()).load()
    else {
        return;
    };
    #[cfg(unix)]
    let raw_path = {
        use std::os::unix::ffi::OsStrExt;
        relative_path.as_os_str().as_bytes()
    };
    #[cfg(not(unix))]
    let raw_path = relative_path.to_string_lossy().as_bytes();
    let Ok(protected_path) = evertrace_capture::protect(raw_path, &key) else {
        return;
    };
    let Ok(path_ref) = super::bundle::protected_ref(&protected_path, cas) else {
        return;
    };
    let Some(captured_bytes) = bundle
        .captured_bytes
        .checked_add(path_ref.protected_length)
        .filter(|value| *value <= runtime.recovery_max_bundle_bytes)
    else {
        return;
    };
    let identity = evertrace_domain::repository::RecoveryConfinedFileIdentity {
        device: file.identity.device,
        inode: file.identity.inode,
        size: file.identity.size,
        mtime_seconds: file.identity.mtime_seconds,
        mtime_nanoseconds: file.identity.mtime_nanoseconds,
        ctime_seconds: file.identity.ctime_seconds,
        ctime_nanoseconds: file.identity.ctime_nanoseconds,
    };
    let mut claims = Vec::new();
    for attempt_id in &bundle.attempt_anchor_ids {
        let Some(attempt) = attempts.attempts.get(attempt_id) else {
            continue;
        };
        let mut competing_groups = Vec::new();
        let mut complete = true;
        for group_id in &attempt.competing_group_ids {
            let Some(group) = attempts
                .competing_groups
                .get(group_id)
                .filter(|group| group.member_attempt_ids.contains(attempt_id))
            else {
                complete = false;
                break;
            };
            competing_groups.push(evertrace_domain::repository::RecoveryCompetingGroupClaim {
                competing_group_id: *group_id,
                revision_id: group.revision_id,
                resolution_status: group.resolution_status,
            });
        }
        if complete {
            claims.push(evertrace_domain::repository::RecoveryAttemptAnchorClaim {
                attempt_id: *attempt_id,
                attempt_revision_id: attempt.revision_id,
                strategy_contract_fingerprint: attempt.strategy_contract_fingerprint,
                source_repository_instance_id: pending.repository_instance_id,
                source_worktree_instance_id: pending.worktree_instance_id,
                source_snapshot_id: snapshot.worktree_snapshot_id,
                affected_relative_path: path_ref.clone(),
                source_file_identity: identity,
                competing_groups,
            });
        }
    }
    if !claims.is_empty() && claims.iter().all(|claim| claim.validate().is_ok()) {
        bundle.attempt_anchor_claims = claims;
        bundle.captured_bytes = captured_bytes;
    }
}

const fn status_after_root_change(status: RecoveryRequestStatus) -> RecoveryRequestStatus {
    match status {
        RecoveryRequestStatus::Complete | RecoveryRequestStatus::Skipped => {
            RecoveryRequestStatus::Partial
        }
        RecoveryRequestStatus::Pending
        | RecoveryRequestStatus::Partial
        | RecoveryRequestStatus::TimedOut
        | RecoveryRequestStatus::Failed => status,
    }
}
fn ack(
    request: &RecoveryCaptureRequest,
    pending_revision_id: evertrace_domain::revision::RevisionId,
) -> Result<RecoveryTerminalAck, RecoveryError> {
    if !request.request_status.is_terminal()
        || request.parent_request_revision_id != Some(pending_revision_id)
    {
        return Err(RecoveryError::StaleCurrent);
    }
    Ok(RecoveryTerminalAck {
        recovery_capture_request_id: request.recovery_capture_request_id,
        pending_revision_id,
        terminal_revision_id: request.request_revision_id,
        status: request.request_status,
        recovery_bundle_id: request.recovery_bundle_id,
    })
}

pub(super) fn current_time_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_micros()).ok())
        .unwrap_or(0)
}

fn terminal_finished_at(started_at_us: i64) -> i64 {
    current_time_us().max(started_at_us)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fence_lease_remains_exclusive_until_owner_drop_and_unwinds_safely() {
        let fenced = Arc::new(Mutex::new(BTreeSet::new()));
        let worktree_id = evertrace_domain::ids::WorktreeId::new_v7();
        let lease = RecoveryFenceLease::acquire(Arc::clone(&fenced), worktree_id).unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            lease
        });
        ready_rx.recv().unwrap();
        assert!(matches!(
            RecoveryFenceLease::acquire(Arc::clone(&fenced), worktree_id),
            Err(RecoveryError::FenceBusy)
        ));
        release_tx.send(()).unwrap();
        let lease = worker.join().unwrap();
        assert!(matches!(
            RecoveryFenceLease::acquire(Arc::clone(&fenced), worktree_id),
            Err(RecoveryError::FenceBusy)
        ));
        let unwind = std::panic::catch_unwind(|| {
            let _owned_until_unwind = lease;
            panic!("lease lifetime probe");
        });
        assert!(unwind.is_err());
        let reacquired = RecoveryFenceLease::acquire(Arc::clone(&fenced), worktree_id).unwrap();
        drop(reacquired);
        assert!(fenced.lock().unwrap().is_empty());
    }

    #[test]
    fn terminal_status_gives_deadline_precedence_without_sleeping() {
        assert_eq!(
            super::super::capture::recovery_terminal_status(true, None),
            RecoveryRequestStatus::TimedOut
        );
        assert_eq!(
            super::super::capture::recovery_terminal_status(false, None),
            RecoveryRequestStatus::Skipped
        );
        assert_eq!(
            status_after_root_change(RecoveryRequestStatus::TimedOut),
            RecoveryRequestStatus::TimedOut
        );
        assert_eq!(
            status_after_root_change(RecoveryRequestStatus::Failed),
            RecoveryRequestStatus::Failed
        );
        assert_eq!(
            status_after_root_change(RecoveryRequestStatus::Complete),
            RecoveryRequestStatus::Partial
        );
        let future_start = current_time_us().saturating_add(1_000_000);
        assert_eq!(terminal_finished_at(future_start), future_start);
    }
}
