//! Finite, event-triggered asset reads for one verified native context.

use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use evertrace_capture::{
    ConfinedFileIdentity, ConfinedReadLimits, ConfinedRoot, DeviceKey, ProtectedPayload, protect,
};
use evertrace_codex::{
    HostProbeReport,
    inventory::{FiniteSourceSelection, source_selection},
};
use evertrace_domain::inventory::{
    CapabilityInventorySnapshot, CapabilitySignature, InventoryAssetKind, InventoryContext,
    InventoryPathIdentity, InventoryPathState, InventorySource, InventorySourceScope,
};
use evertrace_store::JobBudget;

const QUANTUM: Duration = Duration::from_millis(250);
const QUANTUM_ITEMS: usize = 16;
const MAX_SKILL_DEPTH: usize = 6;

use evertrace_capture::{CasStore, DeviceKeyStore, MaintenanceFence, RuntimeSnapshot};
use evertrace_domain::{
    ids::{CommandId, JobId},
    repository::{RepositoryCapabilityState, RepositoryInstance},
};
use evertrace_store::projections::{
    INVENTORY_JOB_KIND, inventory_job_context_ref, inventory_job_worktree,
    inventory_repository_target,
};
use evertrace_store::{
    DurableJob, JobLease, JobStatus, JobTerminalAudit, JobTerminalOutcome, JobTerminalReason,
    JournalCommand, JournalEventDraft, JournalPayload, ProjectionSnapshot,
};

#[derive(Clone)]
pub struct InventoryWorker {
    writer: super::WriterHandle,
    runtime: RuntimeSnapshot,
    bindings: crate::service::McpBindingAuthority,
    state: Arc<tokio::sync::Mutex<InventoryWorkerState>>,
}

#[derive(Default)]
struct InventoryWorkerState {
    slots: BTreeMap<JobId, InventorySlot>,
    after: Option<String>,
}

struct InventorySlot {
    context: InventoryContext,
    session_ref: String,
    host: Arc<crate::repository::NativeHostContext>,
    report: Arc<HostProbeReport>,
    worktree_root: PathBuf,
    repository: RepositoryInstance,
    scan: Option<InventoryScan>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InventoryProgress {
    pub completed: bool,
    pub retryable: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum InventoryWorkerError {
    #[error("inventory operation could not reach a known durable state")]
    Store,
    #[error("inventory current facts changed before admission")]
    StaleFrontier,
}

impl InventoryWorker {
    pub fn new(
        writer: super::WriterHandle,
        runtime: RuntimeSnapshot,
        bindings: crate::service::McpBindingAuthority,
    ) -> Self {
        Self {
            writer,
            runtime,
            bindings,
            state: Arc::new(tokio::sync::Mutex::new(InventoryWorkerState::default())),
        }
    }

    pub(crate) fn for_runtime(&self, runtime: RuntimeSnapshot) -> Self {
        Self {
            runtime,
            ..self.clone()
        }
    }

    pub(crate) async fn procedure_coverage(
        &self,
        snapshot: &ProjectionSnapshot,
        draft: &evertrace_domain::procedure::ProcedureDraft,
        source_refs: &[String],
    ) -> Result<crate::procedure::VerifiedProcedureCoverage, crate::semantic::SemanticServiceError>
    {
        crate::procedure::resolve_procedure_coverage(
            &self.writer,
            &self.bindings,
            &self.runtime,
            snapshot,
            draft,
            source_refs,
        )
        .await
    }

    /// Only the original scheduler calls this planner. It consumes pending
    /// observations in the existing bounded MCP connection entries.
    pub(crate) async fn enqueue_observed(
        &self,
        snapshot: &ProjectionSnapshot,
    ) -> Result<bool, InventoryWorkerError> {
        let after = self.state.lock().await.after.clone();
        let inputs = self
            .bindings
            .pending_inventory_contexts(after.as_deref(), crate::maintenance::PER_LANE_LIMIT);
        if inputs.is_empty() {
            self.state.lock().await.after = None;
            return Ok(false);
        }
        let mut changed = false;
        for (connection, host, report) in inputs {
            self.state.lock().await.after = Some(connection.clone());
            if !host.current() || !host.selections_observed {
                self.bindings.inventory_context_admitted(&connection);
                continue;
            }
            let deadline = Instant::now() + QUANTUM;
            let Some(location) = crate::repository::workspace_git_location(&host.cwd, deadline)
                .ok()
                .flatten()
            else {
                continue;
            };
            let mut repositories = BTreeMap::new();
            let mut worktrees = Vec::new();
            for row in snapshot
                .data_rows()
                .filter(|row| matches!(row.object_kind.as_deref(), Some("repository" | "worktree")))
            {
                match serde_json::from_str::<JournalPayload>(
                    row.payload_json
                        .as_deref()
                        .ok_or(InventoryWorkerError::Store)?,
                )
                .map_err(|_| InventoryWorkerError::Store)?
                {
                    JournalPayload::RepositoryInstanceRecorded(repository) => {
                        repositories.insert(repository.repository_id, *repository);
                    }
                    JournalPayload::WorktreeInstanceRecorded(worktree) => worktrees.push(*worktree),
                    _ => return Err(InventoryWorkerError::Store),
                }
            }
            let mut candidates = worktrees.iter().filter(|worktree| {
                !worktree.lifecycle.is_terminal()
                    && worktree.current_path.as_deref().map(Path::new)
                        == Some(location.worktree_path.as_path())
                    && worktree
                        .git_admin_path_history
                        .last()
                        .is_some_and(|path| Path::new(&path.path) == location.git_dir)
                    && repositories
                        .get(&worktree.repository_instance_id)
                        .is_some_and(|repository| {
                            repository.common_dir_filesystem == Some(location.common_dir_filesystem)
                        })
            });
            let Some(worktree) = candidates.next() else {
                continue;
            };
            if candidates.next().is_some() {
                continue;
            }
            let repository = repositories
                .get(&worktree.repository_instance_id)
                .ok_or(InventoryWorkerError::Store)?;
            let Some(profile) = report.manifest().capability_inventory_profile else {
                continue;
            };
            let context = InventoryContext {
                repository_id: repository.repository_id,
                worktree_id: worktree.worktree_instance_id,
                cwd: host.cwd.to_string_lossy().into_owned(),
                adapter_manifest_id: report.manifest().adapter_manifest_id.clone(),
                profile,
                host_home: host.home.to_string_lossy().into_owned(),
                host_config_root: host.config_root.to_string_lossy().into_owned(),
                host_profile: host.profile.clone(),
            };
            let Some(session_ref) = self.bindings.inventory_session_ref(&host) else {
                continue;
            };
            let current = self
                .writer
                .inventory_context(&context, None)
                .await
                .map_err(|_| InventoryWorkerError::Store)?;
            let Some(repository) = current.repository else {
                continue;
            };
            let trust = crate::repository::read_report_path_trust_before(
                &report,
                worktree.current_path.as_deref(),
                deadline,
            )
            .state;
            if trust == evertrace_codex::policy::RepositoryTrustState::Untrusted {
                self.record_revocation(&repository, current.frontier)
                    .await?;
                self.bindings.inventory_context_admitted(&connection);
                changed = true;
                continue;
            }
            if trust != evertrace_codex::policy::RepositoryTrustState::Trusted
                || !crate::repository::repository_read_gate(
                    &repository,
                    current.purge_pending_or_purged,
                )
            {
                self.bindings.inventory_context_admitted(&connection);
                continue;
            }
            let state = self.state.lock().await;
            if state.slots.values().any(|slot| slot.context == context) {
                self.bindings.inventory_context_admitted(&connection);
                continue;
            }
            if state.slots.len() >= crate::maintenance::PER_LANE_LIMIT {
                break;
            }
            drop(state);
            let job_id = JobId::new_v7();
            let reference = current
                .latest_completion
                .as_ref()
                .map_or_else(|| "new".into(), |fact| fact.job_id.to_string());
            let job = DurableJob {
                job_id,
                idempotency_key: format!(
                    "capability_inventory:scan:{job_id}|{}|{reference}",
                    context.worktree_id
                ),
                target_revision: inventory_repository_target(
                    repository.repository_id,
                    repository.repository_revision,
                ),
                target_watermark: 0,
                target_generation: u64::from(repository.repository_revision),
                kind: INVENTORY_JOB_KIND.into(),
                algorithm_revision: INVENTORY_JOB_KIND.into(),
                model_id: None,
                priority: 0,
                state: JobStatus::Queued,
                attempt: 1,
                backoff_until_us: None,
                config_hash: self.runtime.effective_config_hash,
                budget: inventory_budget(),
                terminal: None,
                lease_until_us: None,
            };
            let now = inventory_now()?;
            let command = inventory_command(
                vec![JournalPayload::JobState(job)],
                now,
                self.runtime.effective_config_hash,
            )?;
            commit_known(&self.writer, command, now, current.frontier).await?;
            self.state.lock().await.slots.insert(
                job_id,
                InventorySlot {
                    context,
                    session_ref,
                    host,
                    report,
                    worktree_root: location.worktree_path,
                    repository,
                    scan: None,
                },
            );
            self.bindings.inventory_context_admitted(&connection);
            changed = true;
        }
        Ok(changed)
    }

    async fn record_revocation(
        &self,
        repository: &RepositoryInstance,
        frontier: u64,
    ) -> Result<(), InventoryWorkerError> {
        if repository
            .capability_state
            .as_ref()
            .is_some_and(|state| state.trust_revoked)
        {
            return Ok(());
        }
        let now = inventory_now()?;
        let mut successor = repository.clone();
        successor.repository_revision = successor
            .repository_revision
            .checked_add(1)
            .ok_or(InventoryWorkerError::Store)?;
        successor.predecessor_revision = Some(repository.repository_revision);
        successor.recorded_at_us = now;
        successor
            .capability_state
            .get_or_insert(RepositoryCapabilityState {
                trust_revoked: false,
                revalidated_inventory_ref: None,
            })
            .trust_revoked = true;
        commit_known(
            &self.writer,
            inventory_command(
                vec![JournalPayload::RepositoryInstanceRecorded(Box::new(
                    successor,
                ))],
                now,
                self.runtime.effective_config_hash,
            )?,
            now,
            frontier,
        )
        .await
    }

    async fn recover_slot(
        &self,
        job: &DurableJob,
    ) -> Result<Option<InventorySlot>, InventoryWorkerError> {
        let Some(worktree_id) = inventory_job_worktree(job) else {
            return Err(InventoryWorkerError::Store);
        };
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| InventoryWorkerError::Store)?;
        let mut repository = None;
        let mut worktree = None;
        let mut previous = None;
        let reference = inventory_job_context_ref(job).ok_or(InventoryWorkerError::Store)?;
        for row in snapshot.data_rows().filter(|row| {
            matches!(
                row.object_kind.as_deref(),
                Some("repository" | "worktree" | "capability_inventory")
            )
        }) {
            match serde_json::from_str::<JournalPayload>(
                row.payload_json
                    .as_deref()
                    .ok_or(InventoryWorkerError::Store)?,
            )
            .map_err(|_| InventoryWorkerError::Store)?
            {
                JournalPayload::WorktreeInstanceRecorded(value)
                    if value.worktree_instance_id == worktree_id =>
                {
                    worktree = Some(*value)
                }
                JournalPayload::RepositoryInstanceRecorded(value)
                    if job
                        .target_revision
                        .starts_with(&format!("{}@", value.repository_id)) =>
                {
                    repository = Some(*value)
                }
                JournalPayload::CapabilityInventoryRecorded(value)
                    if value.job_id.to_string() == reference =>
                {
                    previous = Some(value.context)
                }
                _ => {}
            }
        }
        let Some(repository) = repository else {
            return Ok(None);
        };
        let Some(worktree) = worktree.filter(|worktree| {
            !worktree.lifecycle.is_terminal()
                && worktree.repository_instance_id == repository.repository_id
        }) else {
            return Ok(None);
        };
        let Some(root) = worktree.current_path.as_ref().map(PathBuf::from) else {
            return Ok(None);
        };
        let deadline = Instant::now() + QUANTUM;
        for (host, report) in self.bindings.active_inventory_contexts() {
            if Instant::now() >= deadline {
                break;
            }
            if !host.cwd.starts_with(&root)
                || !host.current_before(deadline)
                || !host.selections_observed
            {
                continue;
            }
            let Some(profile) = report.manifest().capability_inventory_profile else {
                continue;
            };
            let context = InventoryContext {
                repository_id: repository.repository_id,
                worktree_id,
                cwd: host.cwd.to_string_lossy().into_owned(),
                adapter_manifest_id: report.manifest().adapter_manifest_id.clone(),
                profile,
                host_home: host.home.to_string_lossy().into_owned(),
                host_config_root: host.config_root.to_string_lossy().into_owned(),
                host_profile: host.profile.clone(),
            };
            if let Some(previous) = &previous {
                if previous != &context {
                    continue;
                }
            } else if reference == "root" && host.cwd != root {
                continue;
            }
            let Some(session_ref) = self.bindings.inventory_session_ref(&host) else {
                continue;
            };
            return Ok(Some(InventorySlot {
                context,
                session_ref,
                host,
                report,
                worktree_root: root,
                repository,
                scan: None,
            }));
        }
        Ok(None)
    }

    pub(crate) async fn run_job(
        &self,
        selected: &DurableJob,
    ) -> Result<InventoryProgress, InventoryWorkerError> {
        let retained = self.state.lock().await.slots.remove(&selected.job_id);
        let slot = match retained {
            Some(slot) => Some(slot),
            None => self.recover_slot(selected).await?,
        };
        let Some(mut slot) = slot else {
            // A queued enable is still the original user operation. A later
            // ordinary bound call supplies a fresh source observation after
            // disconnect/restart; no second approval or synthetic Host report.
            return Ok(InventoryProgress {
                completed: false,
                retryable: false,
            });
        };
        let current = self
            .writer
            .inventory_context(&slot.context, Some(selected.job_id))
            .await
            .map_err(|_| InventoryWorkerError::Store)?;
        let Some(job) = current
            .job
            .as_ref()
            .filter(|job| job.state == JobStatus::Queued)
        else {
            return Ok(InventoryProgress {
                completed: false,
                retryable: false,
            });
        };
        let Some(repository) = current.repository.as_ref() else {
            return self
                .fail_job(
                    job,
                    JobTerminalReason::SourceUnavailable,
                    Some(current.frontier),
                )
                .await;
        };
        let enable = job
            .idempotency_key
            .starts_with("capability_inventory:enable:");
        let trust = crate::repository::read_report_path_trust_before(
            &slot.report,
            current
                .worktree
                .as_ref()
                .and_then(|worktree| worktree.current_path.as_deref()),
            Instant::now() + QUANTUM,
        )
        .state;
        let location =
            crate::repository::workspace_git_location(&slot.host.cwd, Instant::now() + QUANTUM)
                .ok()
                .flatten();
        let identity_current = current.worktree.as_ref().is_some_and(|worktree| {
            !worktree.lifecycle.is_terminal()
                && worktree.current_path.as_deref().map(Path::new)
                    == Some(slot.worktree_root.as_path())
                && location.as_ref().is_some_and(|location| {
                    location.worktree_path == slot.worktree_root
                        && repository.common_dir_filesystem == Some(location.common_dir_filesystem)
                        && worktree
                            .git_admin_path_history
                            .last()
                            .is_some_and(|path| Path::new(&path.path) == location.git_dir)
                })
        });
        if trust == evertrace_codex::policy::RepositoryTrustState::Untrusted {
            self.record_revocation(repository, current.frontier).await?;
            return self.fail_job(job, JobTerminalReason::Revoked, None).await;
        }
        if !enable
            && slot.host.current()
            && trust == evertrace_codex::policy::RepositoryTrustState::Trusted
            && crate::repository::repository_read_gate(repository, current.purge_pending_or_purged)
            && job.config_hash == self.runtime.effective_config_hash
            && identity_current
            && job.target_revision
                != inventory_repository_target(
                    repository.repository_id,
                    repository.repository_revision,
                )
            && current.worktree.as_ref().is_some_and(|worktree| {
                !worktree.lifecycle.is_terminal()
                    && worktree.current_path.as_deref().map(Path::new)
                        == Some(slot.worktree_root.as_path())
            })
        {
            // A first admission or compatible identity successor may precede
            // another context's scan. Retire the immutable old target and
            // continue ordinary observation against the current revision;
            // never retarget an explicit enable across a concurrent change.
            let mut retired = job.clone();
            retired.state = JobStatus::Failed;
            retired.terminal = Some(Box::new(JobTerminalAudit {
                outcome: JobTerminalOutcome::Failed,
                reason: JobTerminalReason::StaleGeneration,
                result_ref: None,
            }));
            let mut next = job.clone();
            next.job_id = JobId::new_v7();
            let reference = current
                .latest_completion
                .as_ref()
                .map_or_else(|| "new".into(), |fact| fact.job_id.to_string());
            next.idempotency_key = format!(
                "capability_inventory:scan:{}|{}|{reference}",
                next.job_id, slot.context.worktree_id
            );
            next.target_revision = inventory_repository_target(
                repository.repository_id,
                repository.repository_revision,
            );
            next.target_generation = u64::from(repository.repository_revision);
            next.attempt = 1;
            let at = inventory_now()?;
            commit_known(
                &self.writer,
                inventory_command(
                    vec![
                        JournalPayload::JobState(retired),
                        JournalPayload::JobState(next.clone()),
                    ],
                    at,
                    next.config_hash,
                )?,
                at,
                current.frontier,
            )
            .await?;
            slot.repository = repository.clone();
            slot.scan = None;
            self.state.lock().await.slots.insert(next.job_id, slot);
            return Ok(InventoryProgress {
                completed: false,
                retryable: true,
            });
        }
        if !slot.host.current()
            || !identity_current
            || trust != evertrace_codex::policy::RepositoryTrustState::Trusted
            || current.purge_pending_or_purged
            || (!enable && !crate::repository::repository_read_gate(repository, false))
            || job.config_hash != self.runtime.effective_config_hash
            || job.target_revision
                != inventory_repository_target(
                    repository.repository_id,
                    repository.repository_revision,
                )
            || inventory_job_worktree(job) != Some(slot.context.worktree_id)
        {
            return self
                .fail_job(
                    job,
                    JobTerminalReason::StaleGeneration,
                    Some(current.frontier),
                )
                .await;
        }
        if slot.scan.is_none() {
            match InventoryScan::new(
                slot.context.clone(),
                Arc::clone(&slot.host),
                Arc::clone(&slot.report),
                &slot.worktree_root,
                &job.budget,
            ) {
                Ok(scan) => slot.scan = Some(scan),
                Err(error) => {
                    return self
                        .fail_job(job, scan_reason(error), Some(current.frontier))
                        .await;
                }
            }
        }
        let key = DeviceKeyStore::new(self.runtime.device_key_dir.clone())
            .load()
            .map_err(|_| InventoryWorkerError::Store)?;
        let scan = slot.scan.as_mut().ok_or(InventoryWorkerError::Store)?;
        match scan.advance(&key) {
            Ok(false) => {
                self.state.lock().await.slots.insert(job.job_id, slot);
                Ok(InventoryProgress {
                    completed: false,
                    retryable: true,
                })
            }
            Err(error) => {
                self.fail_job(job, scan_reason(error), Some(current.frontier))
                    .await
            }
            Ok(true) => {
                match scan.verify_complete(Instant::now() + QUANTUM) {
                    Ok(false) => {
                        self.state.lock().await.slots.insert(job.job_id, slot);
                        return Ok(InventoryProgress {
                            completed: false,
                            retryable: true,
                        });
                    }
                    Err(error) => {
                        return self
                            .fail_job(job, scan_reason(error), Some(current.frontier))
                            .await;
                    }
                    Ok(true) => {}
                }
                let now = inventory_now()?;
                let lease = inventory_lease(job, now)?;
                commit_known(
                    &self.writer,
                    inventory_command(vec![JournalPayload::JobLease(lease)], now, job.config_hash)?,
                    now,
                    current.frontier,
                )
                .await?;
                let current = self
                    .writer
                    .inventory_context(&slot.context, Some(job.job_id))
                    .await
                    .map_err(|_| InventoryWorkerError::Store)?;
                let leased = current.job.as_ref().ok_or(InventoryWorkerError::Store)?;
                let repository = current
                    .repository
                    .as_ref()
                    .ok_or(InventoryWorkerError::Store)?;
                if repository != &slot.repository
                    || current.purge_pending_or_purged
                    || current.worktree.as_ref().is_none_or(|worktree| {
                        worktree.repository_instance_id != slot.context.repository_id
                            || worktree.lifecycle
                                != evertrace_domain::repository::WorktreeLifecycle::Active
                            || worktree.current_path.as_deref() != slot.worktree_root.to_str()
                    })
                    || !slot.host.current()
                    || leased.state != JobStatus::Leased
                    || leased
                        .lease_until_us
                        .is_none_or(|until| until <= inventory_now().unwrap_or(i64::MAX))
                    || crate::repository::read_report_path_trust_before(
                        &slot.report,
                        Some(&slot.worktree_root.to_string_lossy()),
                        Instant::now() + QUANTUM,
                    )
                    .state
                        != evertrace_codex::policy::RepositoryTrustState::Trusted
                {
                    return self
                        .fail_job(
                            leased,
                            JobTerminalReason::StaleGeneration,
                            Some(current.frontier),
                        )
                        .await;
                }
                let data = self
                    .runtime
                    .data_dir()
                    .map_err(|_| InventoryWorkerError::Store)?;
                let _fence = MaintenanceFence::open(data)
                    .map_err(|_| InventoryWorkerError::Store)?
                    .shared()
                    .map_err(|_| InventoryWorkerError::Store)?;
                let cas = CasStore::open_existing(&self.runtime.cas_dir)
                    .map_err(|_| InventoryWorkerError::Store)?;
                let snapshot_ref =
                    publish_inventory_cas(&cas, &scan.snapshot, &scan.protected, &key)?;
                let current = self
                    .writer
                    .inventory_context(&slot.context, Some(job.job_id))
                    .await
                    .map_err(|_| InventoryWorkerError::Store)?;
                let leased = current.job.as_ref().ok_or(InventoryWorkerError::Store)?;
                let repository = current
                    .repository
                    .as_ref()
                    .ok_or(InventoryWorkerError::Store)?;
                let at = inventory_now()?;
                if repository != &slot.repository
                    || current.purge_pending_or_purged
                    || current.worktree.as_ref().is_none_or(|worktree| {
                        worktree.repository_instance_id != slot.context.repository_id
                            || worktree.lifecycle
                                != evertrace_domain::repository::WorktreeLifecycle::Active
                            || worktree.current_path.as_deref() != slot.worktree_root.to_str()
                    })
                    || leased.state != JobStatus::Leased
                    || !slot.host.current()
                    || !inventory_snapshot_current(&scan.snapshot, Instant::now() + QUANTUM)
                    || crate::repository::read_report_path_trust_before(
                        &slot.report,
                        Some(&slot.worktree_root.to_string_lossy()),
                        Instant::now() + QUANTUM,
                    )
                    .state
                        != evertrace_codex::policy::RepositoryTrustState::Trusted
                    || leased.lease_until_us.is_none_or(|until| until <= at)
                {
                    return self
                        .fail_job(
                            leased,
                            JobTerminalReason::SourceReplaced,
                            Some(current.frontier),
                        )
                        .await;
                }
                let prior = current.latest_completion.filter(|fact| {
                    !enable
                        && fact.snapshot_cas_ref == snapshot_ref
                        && fact.evidence_refs.contains(&slot.session_ref)
                        && inventory_job_context_ref(leased)
                            == Some(fact.job_id.to_string().as_str())
                });
                let result_ref = prior.as_ref().map_or(job.job_id, |fact| fact.job_id);
                let fact = if prior.is_none() {
                    let mut evidence_refs = vec![
                        slot.context.adapter_manifest_id.clone(),
                        slot.session_ref,
                        slot.context.worktree_id.to_string(),
                    ];
                    evidence_refs.sort();
                    evidence_refs.dedup();
                    Some(evertrace_domain::inventory::CapabilityInventoryRecorded {
                        job_id: job.job_id,
                        context: slot.context,
                        repository_revision: repository.repository_revision,
                        snapshot_cas_ref: snapshot_ref,
                        dependency_cas_refs: scan.protected.keys().cloned().collect(),
                        evidence_refs,
                        recorded_at_us: at,
                    })
                } else {
                    None
                };
                commit_known(
                    &self.writer,
                    inventory_completion_command(repository, leased, fact, enable, result_ref, at)?,
                    at,
                    current.frontier,
                )
                .await?;
                Ok(InventoryProgress {
                    completed: true,
                    retryable: false,
                })
            }
        }
    }

    async fn fail_job(
        &self,
        job: &DurableJob,
        reason: JobTerminalReason,
        frontier: Option<u64>,
    ) -> Result<InventoryProgress, InventoryWorkerError> {
        let now = inventory_now()?;
        let mut terminal = job.clone();
        let mut payloads = Vec::new();
        if job.state == JobStatus::Queued {
            let lease = inventory_lease(job, now)?;
            terminal.attempt = lease.attempt;
            payloads.push(JournalPayload::JobLease(lease));
        } else if job.state != JobStatus::Leased {
            return Ok(InventoryProgress {
                completed: false,
                retryable: false,
            });
        }
        terminal.state = JobStatus::Failed;
        terminal.lease_until_us = None;
        terminal.terminal = Some(Box::new(JobTerminalAudit {
            outcome: JobTerminalOutcome::Failed,
            reason,
            result_ref: None,
        }));
        payloads.push(JournalPayload::JobState(terminal));
        let command = inventory_command(payloads, now, job.config_hash)?;
        let frontier = match frontier {
            Some(value) => value,
            None => {
                self.writer
                    .project()
                    .await
                    .map_err(|_| InventoryWorkerError::Store)?
                    .frontier
            }
        };
        commit_known(&self.writer, command, now, frontier).await?;
        Ok(InventoryProgress {
            completed: true,
            retryable: false,
        })
    }
}

async fn commit_known(
    writer: &crate::WriterHandle,
    command: JournalCommand,
    now: i64,
    frontier: u64,
) -> Result<(), InventoryWorkerError> {
    let id = command.command_id();
    let expected = command
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect::<Vec<_>>();
    let result = writer.commit_if_frontier(command, now, frontier).await;
    if result.is_ok() {
        return Ok(());
    }
    if writer
        .committed_command(id)
        .await
        .map_err(|_| InventoryWorkerError::Store)?
        .is_some_and(|command| command.payloads == expected)
    {
        return Ok(());
    }
    if matches!(result, Err(crate::WriterActorError::StaleFrontier)) {
        return Err(InventoryWorkerError::StaleFrontier);
    }
    Err(InventoryWorkerError::Store)
}
fn inventory_completion_command(
    repository: &RepositoryInstance,
    job: &DurableJob,
    fact: Option<evertrace_domain::inventory::CapabilityInventoryRecorded>,
    enable: bool,
    result_ref: JobId,
    at: i64,
) -> Result<JournalCommand, InventoryWorkerError> {
    let mut completed = job.clone();
    completed.state = JobStatus::Succeeded;
    completed.lease_until_us = None;
    completed.terminal = Some(Box::new(JobTerminalAudit {
        outcome: JobTerminalOutcome::Succeeded,
        reason: JobTerminalReason::Completed,
        result_ref: Some(result_ref.to_string()),
    }));
    let mut payloads = Vec::new();
    if let Some(mut fact) = fact {
        let mut repository = repository.clone();
        if enable
            || repository
                .capability_state
                .as_ref()
                .and_then(|state| state.revalidated_inventory_ref)
                .is_none()
        {
            repository.predecessor_revision = Some(repository.repository_revision);
            repository.repository_revision = repository
                .repository_revision
                .checked_add(1)
                .ok_or(InventoryWorkerError::Store)?;
            repository.recorded_at_us = at;
            repository.user_disabled = false;
            repository.capability_state = Some(RepositoryCapabilityState {
                trust_revoked: false,
                revalidated_inventory_ref: Some(job.job_id),
            });
            payloads.push(JournalPayload::RepositoryInstanceRecorded(Box::new(
                repository.clone(),
            )));
        }
        fact.repository_revision = repository.repository_revision;
        payloads.push(JournalPayload::CapabilityInventoryRecorded(Box::new(fact)));
    }
    payloads.push(JournalPayload::JobState(completed));
    inventory_command(payloads, at, job.config_hash)
}

fn publish_inventory_cas(
    cas: &CasStore,
    snapshot: &CapabilityInventorySnapshot,
    payloads: &BTreeMap<String, ProtectedPayload>,
    key: &DeviceKey,
) -> Result<String, InventoryWorkerError> {
    for (expected, payload) in payloads {
        if cas
            .put(payload)
            .map_err(|_| InventoryWorkerError::Store)?
            .to_string()
            != *expected
        {
            return Err(InventoryWorkerError::Store);
        }
    }
    let bytes = serde_json::to_vec(snapshot).map_err(|_| InventoryWorkerError::Store)?;
    let protected = protect(&bytes, key).map_err(|_| InventoryWorkerError::Store)?;
    let reference = cas
        .put(&protected)
        .map_err(|_| InventoryWorkerError::Store)?
        .to_string();
    #[cfg(test)]
    CRASH_AFTER_INVENTORY_CAS.with(|crash| {
        if crash.get() {
            std::process::exit(86);
        }
    });
    Ok(reference)
}

#[cfg(test)]
thread_local! {
    static CRASH_AFTER_INVENTORY_CAS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn inventory_now() -> Result<i64, InventoryWorkerError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| value.as_micros().try_into().ok())
        .ok_or(InventoryWorkerError::Store)
}

pub(crate) fn inventory_budget() -> JobBudget {
    JobBudget {
        max_items: 4096,
        max_bytes: Some(2 * 1024 * 1024),
        max_input_tokens: None,
        max_output_tokens: None,
        max_calls: None,
        max_wall_time_ms: 3000,
    }
}

fn inventory_command(
    payloads: Vec<JournalPayload>,
    at: i64,
    hash: [u8; 32],
) -> Result<JournalCommand, InventoryWorkerError> {
    JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, hash, INVENTORY_JOB_KIND, payload))
            .collect(),
    )
    .map_err(|_| InventoryWorkerError::Store)
}

fn inventory_lease(job: &DurableJob, at: i64) -> Result<JobLease, InventoryWorkerError> {
    Ok(JobLease {
        job_id: job.job_id,
        target_generation: job.target_generation,
        attempt: job
            .attempt
            .checked_add(1)
            .ok_or(InventoryWorkerError::Store)?,
        lease_until_us: at
            .checked_add(5_000_000)
            .ok_or(InventoryWorkerError::Store)?,
    })
}

fn scan_reason(error: InventoryScanError) -> JobTerminalReason {
    match error {
        InventoryScanError::Budget => JobTerminalReason::BudgetExhausted,
        InventoryScanError::Changed => JobTerminalReason::SourceReplaced,
        InventoryScanError::Unavailable => JobTerminalReason::SourceUnavailable,
        InventoryScanError::Protection => JobTerminalReason::IntegrityFailure,
    }
}

struct FileProof {
    path: PathBuf,
    root: ConfinedRoot,
    relative: PathBuf,
    identity: Option<ConfinedFileIdentity>,
}

impl FileProof {
    fn current(&self, deadline: Instant) -> bool {
        self.root.probe_regular_file(&self.relative, deadline).ok() == Some(self.identity)
    }
}

struct DirectoryScan {
    root: ConfinedRoot,
    path: PathBuf,
    entries: fs::ReadDir,
    scope: InventorySourceScope,
    depth: usize,
    identity: InventoryPathIdentity,
}

impl DirectoryScan {
    fn open(
        path: PathBuf,
        scope: InventorySourceScope,
        depth: usize,
    ) -> Result<Self, InventoryScanError> {
        let root = ConfinedRoot::open_external_source(&path)
            .map_err(|_| InventoryScanError::Unavailable)?;
        let identity = file_identity(root.identity());
        let entries = fs::read_dir(
            root.proc_cwd_path()
                .map_err(|_| InventoryScanError::Unavailable)?,
        )
        .map_err(|_| InventoryScanError::Unavailable)?;
        Ok(Self {
            root,
            path,
            entries,
            scope,
            depth,
            identity,
        })
    }

    fn classify(&self, entry: fs::DirEntry) -> Result<Option<ScanItem>, InventoryScanError> {
        let name = entry.file_name();
        let name = name.to_str().ok_or(InventoryScanError::Unavailable)?;
        if name.starts_with('.') {
            return Ok(None);
        }
        let file_type = entry
            .file_type()
            .map_err(|_| InventoryScanError::Unavailable)?;
        let path = self.path.join(name);
        if file_type.is_symlink() {
            return Err(InventoryScanError::Unavailable);
        }
        if file_type.is_dir() {
            if self.depth >= MAX_SKILL_DEPTH {
                return Err(InventoryScanError::Budget);
            }
            Ok(Some(ScanItem::SkillRoot(
                path,
                self.scope.clone(),
                self.depth + 1,
            )))
        } else if file_type.is_file() && name == "SKILL.md" {
            Ok(Some(ScanItem::File(
                path,
                self.scope.clone(),
                InventoryAssetKind::Skill,
            )))
        } else {
            Ok(None)
        }
    }

    fn finish(self) -> Result<DirectoryProof, InventoryScanError> {
        let proof = DirectoryProof {
            path: self.path,
            root: self.root,
            identity: self.identity,
        };
        if !proof.current() {
            return Err(InventoryScanError::Changed);
        }
        Ok(proof)
    }
}

struct DirectoryProof {
    path: PathBuf,
    root: ConfinedRoot,
    identity: InventoryPathIdentity,
}

impl DirectoryProof {
    fn current(&self) -> bool {
        self.root.revalidate_stable().is_ok()
            && self
                .root
                .proc_cwd_path()
                .ok()
                .and_then(|path| fs::metadata(path).ok())
                .and_then(|metadata| metadata_identity(&metadata).ok())
                == Some(self.identity)
    }
}

enum ScanItem {
    RepositoryDirectory(PathBuf),
    Configuration(PathBuf),
    Plugin(String),
    SkillRoot(PathBuf, InventorySourceScope, usize),
    File(PathBuf, InventorySourceScope, InventoryAssetKind),
    Instructions(PathBuf, InventorySourceScope),
}

pub(crate) struct InventoryScan {
    pub(crate) host: Arc<crate::repository::NativeHostContext>,
    pub(crate) snapshot: CapabilityInventorySnapshot,
    pub(crate) protected: BTreeMap<String, ProtectedPayload>,
    selection: FiniteSourceSelection,
    work: VecDeque<ScanItem>,
    directories: Vec<DirectoryScan>,
    directory_proofs: Vec<DirectoryProof>,
    marker_proofs: Vec<InventoryPathState>,
    file_proofs: Vec<FileProof>,
    verified_proofs: usize,
    verified_entries: BTreeMap<String, InventoryPathState>,
    remaining_items: u32,
    remaining_bytes: u64,
    remaining_time: Duration,
    remaining_instruction_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InventoryScanError {
    Unavailable,
    Changed,
    Budget,
    Protection,
}

impl InventoryScan {
    pub(crate) fn new(
        context: InventoryContext,
        host: Arc<crate::repository::NativeHostContext>,
        report: Arc<HostProbeReport>,
        worktree_root: &Path,
        budget: &JobBudget,
    ) -> Result<Self, InventoryScanError> {
        let started = Instant::now();
        let deadline = started + QUANTUM.min(Duration::from_millis(budget.max_wall_time_ms));
        if context.validate().is_err()
            || !host.current()
            || !host.selections_observed
            || budget.max_items == 0
            || budget.max_bytes == Some(0)
            || budget.max_wall_time_ms == 0
            || !host.cwd.starts_with(worktree_root)
            || report.inventory_host().is_none()
        {
            return Err(InventoryScanError::Unavailable);
        }
        let root = ConfinedRoot::open_external_source(&host.config_root)
            .map_err(|_| InventoryScanError::Unavailable)?;
        let config = root
            .read(
                Path::new("config.toml"),
                read_limits(
                    budget.max_bytes.unwrap_or(256 * 1024).min(256 * 1024),
                    deadline,
                ),
            )
            .map_err(|_| InventoryScanError::Unavailable)?;
        let selection = source_selection(&config.bytes, host.profile.as_deref())
            .map_err(|_| InventoryScanError::Unavailable)?;
        if !selection.observed {
            return Err(InventoryScanError::Unavailable);
        }
        for rule in &selection.skill_rules {
            if let evertrace_codex::inventory::SkillSelector::Path(path) = &rule.selector
                && fs::canonicalize(path).is_ok_and(|canonical| canonical != *path)
            {
                // Alias-based selectors need their own currentness proof;
                // this finite profile supports canonical document selectors.
                return Err(InventoryScanError::Unavailable);
            }
        }
        let config_bytes = config.bytes.len() as u64;
        let remaining_instruction_bytes = selection.project_doc_max_bytes;
        let mut scan = Self {
            host: Arc::clone(&host),
            snapshot: CapabilityInventorySnapshot {
                sources: Vec::new(),
                signatures: Vec::new(),
            },
            protected: BTreeMap::new(),
            selection,
            work: VecDeque::new(),
            directories: Vec::new(),
            directory_proofs: Vec::new(),
            marker_proofs: Vec::new(),
            file_proofs: vec![FileProof {
                path: host.config_root.join("config.toml"),
                root,
                relative: PathBuf::from("config.toml"),
                identity: Some(config.identity),
            }],
            verified_proofs: 0,
            verified_entries: BTreeMap::new(),
            remaining_items: budget.max_items - 1,
            remaining_bytes: budget
                .max_bytes
                .unwrap_or(256 * 1024)
                .checked_sub(config_bytes)
                .ok_or(InventoryScanError::Budget)?,
            remaining_time: Duration::from_millis(budget.max_wall_time_ms),
            remaining_instruction_bytes,
        };
        // Extra system/remote/session-selected sources are not an empty set.
        scan.snapshot.sources.push(InventorySource {
            scope: InventorySourceScope::OtherHost,
            root: None,
            observed: false,
            entries: Vec::new(),
        });
        scan.add_source(host.config_root.clone(), InventorySourceScope::User);
        scan.plan_roots(worktree_root, deadline)?;
        scan.remaining_time = scan.remaining_time.saturating_sub(started.elapsed());
        if scan.remaining_time.is_zero() {
            return Err(InventoryScanError::Budget);
        }
        Ok(scan)
    }

    fn plan_roots(&mut self, worktree: &Path, deadline: Instant) -> Result<(), InventoryScanError> {
        let user = InventorySourceScope::User;
        let selectors = self
            .selection
            .skill_rules
            .iter()
            .filter_map(|rule| match &rule.selector {
                evertrace_codex::inventory::SkillSelector::Path(path) => Some(path.clone()),
                evertrace_codex::inventory::SkillSelector::Name(_) => None,
            })
            .collect::<Vec<_>>();
        for path in selectors {
            self.remaining_items = self
                .remaining_items
                .checked_sub(1)
                .ok_or(InventoryScanError::Budget)?;
            let (root, relative) = confined_parent(&path)?;
            let identity = root
                .probe_regular_file(&relative, deadline)
                .map_err(|_| InventoryScanError::Unavailable)?;
            self.add_source(
                path.parent()
                    .ok_or(InventoryScanError::Unavailable)?
                    .to_owned(),
                user.clone(),
            );
            self.file_proofs.push(FileProof {
                path,
                root,
                relative,
                identity,
            });
        }
        self.add_root(self.host.config_root.join("skills"), user.clone());
        self.add_root(self.host.home.join(".agents/skills"), user.clone());
        if let Some(path) = &self.selection.user_instruction_file {
            let path = path.clone();
            self.add_source(
                path.parent()
                    .ok_or(InventoryScanError::Unavailable)?
                    .to_owned(),
                user.clone(),
            );
            self.work
                .push_back(ScanItem::File(path, user, InventoryAssetKind::Instruction));
        }
        let ancestors = self
            .host
            .cwd
            .ancestors()
            .take_while(|path| path.starts_with(worktree))
            .map(Path::to_owned)
            .collect::<Vec<_>>();
        if ancestors.len() > 128 {
            return Err(InventoryScanError::Budget);
        }
        // Selection may depend on missing markers above the selected cwd.
        // This source owns only the finite entries actually inspected below.
        self.add_source(worktree.to_owned(), InventorySourceScope::Repository);
        // Marker selection belongs to the non-project Host config. A custom
        // marker can narrow the finite context, never widen it past Worktree.
        let (boundary, proofs) = select_root_boundary(
            &ancestors,
            &self.selection.root_markers,
            &mut self.remaining_items,
            deadline,
        )?;
        self.marker_proofs.extend(proofs);
        queue_repository_directories(&mut self.work, ancestors, &boundary);
        for (plugin_id, enabled) in &self.selection.enabled_plugins {
            if self.selection.plugins_enabled && *enabled {
                self.work.push_back(ScanItem::Plugin(plugin_id.clone()));
            }
        }
        Ok(())
    }

    fn plan_repository_directory(&mut self, directory: PathBuf) -> Result<(), InventoryScanError> {
        self.add_source(directory.clone(), InventorySourceScope::Repository);
        self.work.push_back(ScanItem::Instructions(
            directory.clone(),
            InventorySourceScope::Repository,
        ));
        self.add_root(
            directory.join(".agents/skills"),
            InventorySourceScope::Repository,
        );
        let config = directory.join(".codex/config.toml");
        let proof = self
            .file_proofs
            .iter()
            .find(|proof| proof.path == config)
            .ok_or(InventoryScanError::Unavailable)?;
        if proof.identity.is_some() {
            self.add_root(
                directory.join(".codex/skills"),
                InventorySourceScope::Repository,
            );
        }
        Ok(())
    }

    fn plan_plugin(
        &mut self,
        plugin_id: String,
        deadline: Instant,
    ) -> Result<(), InventoryScanError> {
        let (name, marketplace) = plugin_id
            .split_once('@')
            .ok_or(InventoryScanError::Unavailable)?;
        let versions = self
            .host
            .config_root
            .join("plugins/cache")
            .join(marketplace)
            .join(name);
        let root = ConfinedRoot::open_external_source(&versions)
            .map_err(|_| InventoryScanError::Unavailable)?;
        let identity = file_identity(root.identity());
        // The fixed Host's explicit local installation wins regardless
        // of how many obsolete version directories are in the cache.
        let local = match fs::symlink_metadata(versions.join("local")) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            _ => return Err(InventoryScanError::Unavailable),
        };
        let entries = if local {
            Vec::new()
        } else {
            root.list_directory(None, self.remaining_items as usize, deadline)
                .map_err(|_| InventoryScanError::Unavailable)?
        };
        self.remaining_items = self
            .remaining_items
            .checked_sub(entries.len() as u32)
            .ok_or(InventoryScanError::Budget)?;
        let names = entries
            .iter()
            .filter(|entry| entry.entry_type == evertrace_capture::ConfinedEntryType::Directory)
            .filter(|entry| {
                entry
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".+-_".contains(&byte))
            })
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        let selected = if local {
            "local"
        } else if names.len() == 1 {
            names[0]
        } else {
            return Err(InventoryScanError::Unavailable);
        };
        let plugin = versions.join(selected);
        let proof = DirectoryProof {
            path: versions,
            root,
            identity,
        };
        if !proof.current() {
            return Err(InventoryScanError::Changed);
        }
        self.directory_proofs.push(proof);
        let manifest = self
            .read_optional(&plugin.join(".codex-plugin/plugin.json"), deadline)?
            .ok_or(InventoryScanError::Unavailable)?;
        // The new Agent Plugin layout has different direct-child rules;
        // absence is proven rather than silently treating it as legacy.
        if self
            .read_optional(&plugin.join("plugin.json"), deadline)?
            .as_deref()
            .is_some_and(evertrace_codex::inventory::is_agent_plugin_manifest)
        {
            return Err(InventoryScanError::Unavailable);
        }
        let paths = match evertrace_codex::inventory::plugin_skill_paths(&manifest, &plugin) {
            Ok(paths) => paths,
            Err(evertrace_codex::inventory::InventoryAssetError::Invalid) => return Ok(()),
            Err(evertrace_codex::inventory::InventoryAssetError::Unsupported) => {
                return Err(InventoryScanError::Unavailable);
            }
        };
        let mut paths = paths;
        let migrated = plugin.join(".codex-plugin/migrated-command-skills");
        match fs::symlink_metadata(&migrated) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                paths.push(migrated)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if self.read_optional(&migrated, deadline)?.is_some() {
                    return Err(InventoryScanError::Changed);
                }
            }
            _ => return Err(InventoryScanError::Unavailable),
        }
        paths.sort();
        paths.dedup();
        for path in paths {
            self.add_root(
                path,
                InventorySourceScope::Plugin {
                    plugin_id: plugin_id.clone(),
                },
            );
        }
        Ok(())
    }

    fn add_source(&mut self, path: PathBuf, scope: InventorySourceScope) {
        let source = InventorySource {
            scope,
            root: Some(path.to_string_lossy().into_owned()),
            observed: true,
            entries: Vec::new(),
        };
        if !self.snapshot.sources.contains(&source) {
            self.snapshot.sources.push(source);
        }
    }

    fn add_root(&mut self, path: PathBuf, scope: InventorySourceScope) {
        self.add_source(path.clone(), scope.clone());
        self.work.push_back(ScanItem::SkillRoot(path, scope, 0));
    }

    fn read_optional(
        &mut self,
        path: &Path,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, InventoryScanError> {
        self.read_optional_prefix(path, None, deadline)
    }

    fn read_optional_prefix(
        &mut self,
        path: &Path,
        prefix_limit: Option<u64>,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, InventoryScanError> {
        let (root, relative) = confined_parent(path)?;
        let identity = root
            .probe_regular_file(&relative, deadline)
            .map_err(|_| InventoryScanError::Unavailable)?;
        let bytes = match identity {
            Some(identity) => {
                let length = prefix_limit.map_or(identity.size, |limit| limit.min(identity.size));
                if length > self.remaining_bytes {
                    return Err(InventoryScanError::Budget);
                }
                let bytes = if prefix_limit.is_some() {
                    let mut bytes = Vec::new();
                    while (bytes.len() as u64) < length {
                        let part = root
                            .read_range(
                                &relative,
                                identity,
                                bytes.len() as u64,
                                (length - bytes.len() as u64) as usize,
                                deadline,
                            )
                            .map_err(|_| InventoryScanError::Changed)?;
                        if part.bytes.is_empty() {
                            return Err(InventoryScanError::Changed);
                        }
                        bytes.extend(part.bytes);
                    }
                    bytes
                } else {
                    let file = root
                        .read(&relative, read_limits(self.remaining_bytes, deadline))
                        .map_err(|_| InventoryScanError::Unavailable)?;
                    if file.identity != identity {
                        return Err(InventoryScanError::Changed);
                    }
                    file.bytes
                };
                self.remaining_bytes = self
                    .remaining_bytes
                    .checked_sub(bytes.len() as u64)
                    .ok_or(InventoryScanError::Budget)?;
                Some(bytes)
            }
            None => None,
        };
        self.file_proofs.push(FileProof {
            path: path.to_owned(),
            root,
            relative,
            identity,
        });
        Ok(bytes)
    }

    pub(crate) fn advance(&mut self, key: &DeviceKey) -> Result<bool, InventoryScanError> {
        if !self.host.current() {
            return Err(InventoryScanError::Changed);
        }
        let start = Instant::now();
        let deadline = start + QUANTUM.min(self.remaining_time);
        let result = self.advance_before(key, deadline);
        self.remaining_time = self.remaining_time.saturating_sub(start.elapsed());
        if !matches!(result, Ok(true)) && self.remaining_time.is_zero() {
            return Err(InventoryScanError::Budget);
        }
        result
    }

    fn advance_before(
        &mut self,
        key: &DeviceKey,
        deadline: Instant,
    ) -> Result<bool, InventoryScanError> {
        for _ in 0..QUANTUM_ITEMS {
            if Instant::now() >= deadline {
                return Ok(false);
            }
            if let Some(directory) = self.directories.last_mut() {
                if let Some(entry) = directory.entries.next() {
                    self.remaining_items = self
                        .remaining_items
                        .checked_sub(1)
                        .ok_or(InventoryScanError::Budget)?;
                    let entry = entry.map_err(|_| InventoryScanError::Unavailable)?;
                    if let Some(item) = directory.classify(entry)? {
                        self.work.push_back(item);
                    }
                    continue;
                }
                let directory = self
                    .directories
                    .pop()
                    .ok_or(InventoryScanError::Unavailable)?;
                self.directory_proofs.push(directory.finish()?);
            }
            let Some(item) = self.work.pop_front() else {
                return Ok(true);
            };
            self.remaining_items = self
                .remaining_items
                .checked_sub(1)
                .ok_or(InventoryScanError::Budget)?;
            match item {
                ScanItem::RepositoryDirectory(path) => self.plan_repository_directory(path)?,
                ScanItem::Configuration(path) => {
                    if let Some(bytes) = self.read_optional(&path, deadline)? {
                        let selection = source_selection(&bytes, None)
                            .map_err(|_| InventoryScanError::Unavailable)?;
                        if selection.source_overrides_present || !selection.observed {
                            return Err(InventoryScanError::Unavailable);
                        }
                    }
                }
                ScanItem::Plugin(id) => self.plan_plugin(id, deadline)?,
                ScanItem::SkillRoot(path, scope, depth) => match fs::symlink_metadata(&path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if self.read_optional(&path, deadline)?.is_some() {
                            return Err(InventoryScanError::Changed);
                        }
                    }
                    Err(_) => return Err(InventoryScanError::Unavailable),
                    Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                        self.directories
                            .push(DirectoryScan::open(path, scope, depth)?);
                    }
                    Ok(_) => return Err(InventoryScanError::Unavailable),
                },
                ScanItem::Instructions(path, scope) => {
                    if self.remaining_instruction_bytes == 0 {
                        continue;
                    }
                    let names = ["AGENTS.override.md".to_owned(), "AGENTS.md".to_owned()]
                        .into_iter()
                        .chain(self.selection.instruction_fallback_names.clone())
                        .collect::<Vec<_>>();
                    for name in names {
                        let candidate = path.join(name);
                        if let Some(bytes) = self.read_optional_prefix(
                            &candidate,
                            Some(self.remaining_instruction_bytes),
                            deadline,
                        )? {
                            if let Some(bytes) =
                                instruction_prefix(&bytes, &mut self.remaining_instruction_bytes)
                            {
                                self.record(
                                    candidate,
                                    scope,
                                    InventoryAssetKind::Instruction,
                                    bytes,
                                    key,
                                )?;
                            }
                            break;
                        }
                    }
                }
                ScanItem::File(path, scope, kind) => {
                    let bytes = self
                        .read_optional(&path, deadline)?
                        .ok_or(InventoryScanError::Changed)?;
                    self.record(path, scope, kind, bytes, key)?;
                }
            }
        }
        Ok(false)
    }

    fn record(
        &mut self,
        path: PathBuf,
        scope: InventorySourceScope,
        asset_kind: InventoryAssetKind,
        bytes: Vec<u8>,
        key: &DeviceKey,
    ) -> Result<(), InventoryScanError> {
        if let Some((signature, payload)) =
            inventory_asset(&path, scope, asset_kind, &bytes, key, &self.selection)?
        {
            self.protected
                .insert(signature.content_cas_ref.clone(), payload);
            self.snapshot.signatures.push(signature);
        }
        Ok(())
    }

    pub(crate) fn verify_complete(
        &mut self,
        deadline: Instant,
    ) -> Result<bool, InventoryScanError> {
        if !self.work.is_empty() || !self.directories.is_empty() || !self.host.current() {
            return Err(InventoryScanError::Changed);
        }
        let started = Instant::now();
        let deadline = deadline.min(started + self.remaining_time);
        let total = self.directory_proofs.len() + self.file_proofs.len() + self.marker_proofs.len();
        for _ in 0..QUANTUM_ITEMS {
            if self.verified_proofs == total {
                for source in &mut self.snapshot.sources {
                    source.entries.clear();
                }
                for entry in self.verified_entries.values() {
                    let source =
                        self.snapshot
                            .sources
                            .iter_mut()
                            .filter(|source| {
                                source.observed
                                    && source.root.as_ref().is_some_and(|root| {
                                        Path::new(&entry.path).starts_with(root)
                                    })
                            })
                            .max_by_key(|source| source.root.as_ref().map_or(0, String::len))
                            .ok_or(InventoryScanError::Unavailable)?;
                    source.entries.push(entry.clone());
                }
                self.snapshot
                    .sources
                    .sort_by(|a, b| (&a.scope, &a.root).cmp(&(&b.scope, &b.root)));
                self.snapshot
                    .signatures
                    .sort_by(|a, b| (&a.scope, &a.source_path).cmp(&(&b.scope, &b.source_path)));
                self.snapshot
                    .validate()
                    .map_err(|_| InventoryScanError::Unavailable)?;
                return Ok(true);
            }
            if Instant::now() >= deadline {
                break;
            }
            let entry = if self.verified_proofs < self.directory_proofs.len() {
                let proof = &self.directory_proofs[self.verified_proofs];
                if !proof.current() {
                    return Err(InventoryScanError::Changed);
                }
                InventoryPathState {
                    path: proof.path.to_string_lossy().into_owned(),
                    directory: true,
                    selection_only: false,
                    identity: Some(proof.identity),
                }
            } else if self.verified_proofs < self.directory_proofs.len() + self.file_proofs.len() {
                let proof = &self.file_proofs[self.verified_proofs - self.directory_proofs.len()];
                if !proof.current(deadline) {
                    return Err(InventoryScanError::Changed);
                }
                InventoryPathState {
                    path: proof.path.to_string_lossy().into_owned(),
                    directory: false,
                    selection_only: false,
                    identity: proof.identity.map(file_identity),
                }
            } else {
                let proof = &self.marker_proofs
                    [self.verified_proofs - self.directory_proofs.len() - self.file_proofs.len()];
                if !marker_current(proof, deadline) {
                    return Err(InventoryScanError::Changed);
                }
                proof.clone()
            };
            if let Some(previous) = self.verified_entries.get(&entry.path) {
                if previous != &entry
                    && !(entry.selection_only
                        && !previous.selection_only
                        && same_marker_identity(previous, &entry))
                {
                    return Err(InventoryScanError::Changed);
                }
            } else {
                self.verified_entries.insert(entry.path.clone(), entry);
            }
            self.verified_proofs += 1;
        }
        self.remaining_time = self.remaining_time.saturating_sub(started.elapsed());
        if self.remaining_time.is_zero() {
            Err(InventoryScanError::Budget)
        } else {
            Ok(false)
        }
    }
}

fn instruction_prefix(bytes: &[u8], remaining: &mut u64) -> Option<Vec<u8>> {
    let bytes = &bytes[..bytes
        .len()
        .min((*remaining).try_into().unwrap_or(usize::MAX))];
    let text = String::from_utf8_lossy(bytes);
    if text.trim().is_empty() {
        return None;
    }
    *remaining -= bytes.len() as u64;
    Some(text.into_owned().into_bytes())
}

fn inventory_asset(
    path: &Path,
    scope: InventorySourceScope,
    asset_kind: InventoryAssetKind,
    bytes: &[u8],
    key: &DeviceKey,
    selection: &FiniteSourceSelection,
) -> Result<Option<(CapabilitySignature, ProtectedPayload)>, InventoryScanError> {
    let fallback = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .ok_or(InventoryScanError::Unavailable)?;
    if asset_kind == InventoryAssetKind::Skill {
        match evertrace_codex::inventory::authored_skill_fields(bytes, fallback) {
            Ok((name, _)) if selection.skill_enabled(path, &name) => {}
            Ok(_) | Err(evertrace_codex::inventory::InventoryAssetError::Invalid) => {
                return Ok(None);
            }
            Err(evertrace_codex::inventory::InventoryAssetError::Unsupported) => {
                return Err(InventoryScanError::Unavailable);
            }
        }
    }
    let payload = protect(bytes, key).map_err(|_| InventoryScanError::Protection)?;
    let content_cas_ref =
        evertrace_capture::CasDigest::for_protected_bytes(payload.protected_bytes()).to_string();
    let (authored_name, authored_description) = if asset_kind == InventoryAssetKind::Skill {
        evertrace_codex::inventory::authored_skill_fields(payload.protected_bytes(), fallback)
            .map(|(name, description)| {
                (
                    Some(name),
                    (description.len() <= 4096).then_some(description),
                )
            })
            .unwrap_or((None, None))
    } else {
        (None, None)
    };
    Ok(Some((
        CapabilitySignature {
            asset_kind,
            source_path: path.to_string_lossy().into_owned(),
            scope,
            content_cas_ref,
            authored_name,
            authored_description,
            triggers: None,
            preconditions: None,
            key_actions: None,
            outputs: None,
            validation: None,
            failure_boundaries: None,
        },
        payload,
    )))
}

pub(crate) fn inventory_snapshot_current(
    snapshot: &CapabilityInventorySnapshot,
    deadline: Instant,
) -> bool {
    if snapshot.validate().is_err() {
        return false;
    }
    let mut count = 0usize;
    for source in &snapshot.sources {
        for entry in &source.entries {
            count += 1;
            if count > inventory_budget().max_items as usize || Instant::now() >= deadline {
                return false;
            }
            let path = Path::new(&entry.path);
            if entry.selection_only {
                if !marker_current(entry, deadline) {
                    return false;
                }
                continue;
            }
            let current = if entry.directory {
                let Ok(root) = ConfinedRoot::open_external_source(path) else {
                    return false;
                };
                let Ok(pinned) = root.proc_cwd_path() else {
                    return false;
                };
                let Ok(metadata) = fs::metadata(pinned) else {
                    return false;
                };
                if root.revalidate_stable().is_err() {
                    return false;
                }
                metadata_identity(&metadata).ok()
            } else {
                let Ok((root, relative)) = confined_parent(path) else {
                    return false;
                };
                let Ok(identity) = root.probe_regular_file(&relative, deadline) else {
                    return false;
                };
                identity.map(file_identity)
            };
            if current != entry.identity {
                return false;
            }
        }
    }
    count > 0
}

fn queue_repository_directories(
    work: &mut VecDeque<ScanItem>,
    mut ancestors: Vec<PathBuf>,
    boundary: &Path,
) {
    ancestors.retain(|path| path.starts_with(boundary));
    ancestors.reverse();
    for directory in ancestors {
        work.push_back(ScanItem::Configuration(
            directory.join(".codex/config.toml"),
        ));
        work.push_back(ScanItem::RepositoryDirectory(directory));
    }
}

fn select_root_boundary(
    ancestors: &[PathBuf],
    markers: &[String],
    remaining: &mut u32,
    deadline: Instant,
) -> Result<(PathBuf, Vec<InventoryPathState>), InventoryScanError> {
    let cwd = ancestors.first().ok_or(InventoryScanError::Unavailable)?;
    let mut proofs = Vec::new();
    for directory in ancestors {
        for name in markers {
            *remaining = remaining.checked_sub(1).ok_or(InventoryScanError::Budget)?;
            let proof = marker_state(&directory.join(name), deadline)?;
            let present = proof.identity.is_some();
            proofs.push(proof);
            if present {
                return Ok((directory.clone(), proofs));
            }
        }
    }
    Ok((cwd.clone(), proofs))
}

fn marker_state(path: &Path, deadline: Instant) -> Result<InventoryPathState, InventoryScanError> {
    if Instant::now() >= deadline {
        return Err(InventoryScanError::Budget);
    }
    let (parent, relative) = confined_parent(path)?;
    let pinned = parent
        .proc_cwd_path()
        .map_err(|_| InventoryScanError::Changed)?;
    let (directory, identity) = match fs::symlink_metadata(pinned.join(&relative)) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            let root = ConfinedRoot::open_external_source(path)
                .map_err(|_| InventoryScanError::Unavailable)?;
            let identity = file_identity(root.identity());
            if identity != metadata_identity(&metadata)? {
                return Err(InventoryScanError::Changed);
            }
            root.revalidate_stable()
                .map_err(|_| InventoryScanError::Changed)?;
            (true, Some(identity))
        }
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let identity = parent
                .probe_regular_file(&relative, deadline)
                .map_err(|_| InventoryScanError::Unavailable)?
                .ok_or(InventoryScanError::Changed)?;
            if file_identity(identity) != metadata_identity(&metadata)? {
                return Err(InventoryScanError::Changed);
            }
            (false, Some(file_identity(identity)))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if parent
                .probe_regular_file(&relative, deadline)
                .map_err(|_| InventoryScanError::Unavailable)?
                .is_some()
            {
                return Err(InventoryScanError::Changed);
            }
            (false, None)
        }
        _ => return Err(InventoryScanError::Unavailable),
    };
    parent
        .revalidate_stable()
        .map_err(|_| InventoryScanError::Changed)?;
    Ok(InventoryPathState {
        path: path.to_string_lossy().into_owned(),
        directory,
        selection_only: true,
        identity,
    })
}

fn same_marker_identity(left: &InventoryPathState, right: &InventoryPathState) -> bool {
    left.directory == right.directory
        && left.identity.map(|value| (value.device, value.inode))
            == right.identity.map(|value| (value.device, value.inode))
}

fn marker_current(proof: &InventoryPathState, deadline: Instant) -> bool {
    marker_state(Path::new(&proof.path), deadline)
        .is_ok_and(|current| same_marker_identity(proof, &current))
}

fn file_identity(value: ConfinedFileIdentity) -> InventoryPathIdentity {
    InventoryPathIdentity {
        device: value.device,
        inode: value.inode,
        size: value.size,
        mtime_seconds: value.mtime_seconds,
        mtime_nanoseconds: value.mtime_nanoseconds,
        ctime_seconds: value.ctime_seconds,
        ctime_nanoseconds: value.ctime_nanoseconds,
    }
}

fn metadata_identity(value: &fs::Metadata) -> Result<InventoryPathIdentity, InventoryScanError> {
    Ok(InventoryPathIdentity {
        device: value.dev(),
        inode: value.ino(),
        size: value.size(),
        mtime_seconds: value.mtime(),
        mtime_nanoseconds: value
            .mtime_nsec()
            .try_into()
            .map_err(|_| InventoryScanError::Changed)?,
        ctime_seconds: value.ctime(),
        ctime_nanoseconds: value
            .ctime_nsec()
            .try_into()
            .map_err(|_| InventoryScanError::Changed)?,
    })
}

fn read_limits(bytes: u64, deadline: Instant) -> ConfinedReadLimits {
    ConfinedReadLimits {
        single_file_remaining: bytes,
        untracked_total_remaining: bytes,
        bundle_remaining: bytes,
        deadline,
    }
}

fn confined_parent(path: &Path) -> Result<(ConfinedRoot, PathBuf), InventoryScanError> {
    let mut parent = path.parent().ok_or(InventoryScanError::Unavailable)?;
    loop {
        match fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                parent = parent.parent().ok_or(InventoryScanError::Unavailable)?;
            }
            _ => return Err(InventoryScanError::Unavailable),
        }
    }
    let root =
        ConfinedRoot::open_external_source(parent).map_err(|_| InventoryScanError::Unavailable)?;
    let relative = path
        .strip_prefix(parent)
        .map_err(|_| InventoryScanError::Unavailable)?
        .to_owned();
    Ok((root, relative))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn inventory_byte_gate_and_raw_eligibility_precede_protected_signatures() {
        let mut budget = 0;
        assert!(instruction_prefix(b"not loaded", &mut budget).is_none());
        budget = 3;
        assert!(instruction_prefix(b"   ", &mut budget).is_none());
        assert_eq!(budget, 3);
        assert_eq!(
            instruction_prefix("aé-more".as_bytes(), &mut budget).unwrap(),
            "aé".as_bytes()
        );
        assert!(instruction_prefix(b"next document", &mut budget).is_none());
        budget = 2;
        assert_eq!(
            instruction_prefix("aé".as_bytes(), &mut budget).unwrap(),
            "a\u{fffd}".as_bytes()
        );
        let root = std::env::temp_dir().join(format!(
            "evertrace-inventory-protection-{}",
            JobId::new_v7()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let key = DeviceKeyStore::new(root.join("keys"))
            .load_or_create()
            .unwrap();
        let selection = source_selection(b"", None).unwrap();
        let asset = |bytes: &[u8]| {
            inventory_asset(
                Path::new("/finite/fallback/SKILL.md"),
                InventorySourceScope::User,
                InventoryAssetKind::Skill,
                bytes,
                &key,
                &selection,
            )
        };
        assert!(
            asset(b"---\nname: absent-description\n---\n")
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            asset(b"---\ndescription: |\n  unsupported block\n---\n"),
            Err(InventoryScanError::Unavailable)
        ));
        let (valid, _) = asset(b"---\ndescription: real authored behavior\n---\n")
            .unwrap()
            .unwrap();
        assert_eq!(valid.authored_name.as_deref(), Some("fallback"));
        let (signature, payload) =
            asset(b"---\ndescription: api_key=inventory-secret-fixture\n---\n")
                .unwrap()
                .unwrap();
        assert!(
            !String::from_utf8_lossy(payload.protected_bytes())
                .contains("inventory-secret-fixture")
        );
        assert!(
            !serde_json::to_string(&signature)
                .unwrap()
                .contains("inventory-secret-fixture")
        );
        // Valid raw syntax can become unsupported authored syntax after
        // protection. That does not retroactively make the loaded asset invalid.
        assert_eq!(signature.asset_kind, InventoryAssetKind::Skill);
        fs::remove_dir_all(&root).unwrap();
    }

    fn scan_test_skill(
        path: &Path,
        key: &DeviceKey,
    ) -> (
        CapabilityInventorySnapshot,
        BTreeMap<String, ProtectedPayload>,
    ) {
        let mut scan =
            DirectoryScan::open(path.to_owned(), InventorySourceScope::Repository, 0).unwrap();
        let mut signatures = Vec::new();
        let mut payloads = BTreeMap::new();
        let mut entries = Vec::new();
        while let Some(entry) = scan.entries.next() {
            let Some(ScanItem::File(path, scope, kind)) = scan.classify(entry.unwrap()).unwrap()
            else {
                continue;
            };
            let (root, relative) = confined_parent(&path).unwrap();
            let file = root
                .read(&relative, read_limits(4096, Instant::now() + QUANTUM))
                .unwrap();
            let (signature, payload) = inventory_asset(
                &path,
                scope,
                kind,
                &file.bytes,
                key,
                &source_selection(b"", None).unwrap(),
            )
            .unwrap()
            .unwrap();
            entries.push(InventoryPathState {
                path: path.to_string_lossy().into_owned(),
                directory: false,
                selection_only: false,
                identity: Some(file_identity(file.identity)),
            });
            payloads.insert(signature.content_cas_ref.clone(), payload);
            signatures.push(signature);
        }
        let proof = scan.finish().unwrap();
        entries.push(InventoryPathState {
            path: path.to_string_lossy().into_owned(),
            directory: true,
            selection_only: false,
            identity: Some(proof.identity),
        });
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let snapshot = CapabilityInventorySnapshot {
            sources: vec![InventorySource {
                scope: InventorySourceScope::Repository,
                root: Some(path.to_string_lossy().into_owned()),
                observed: true,
                entries,
            }],
            signatures,
        };
        assert!(inventory_snapshot_current(
            &snapshot,
            Instant::now() + QUANTUM
        ));
        (snapshot, payloads)
    }

    #[tokio::test]
    async fn inventory_cas_crash_preserves_gates_and_restarts_once() {
        use evertrace_domain::{
            ids::{RepositoryId, WorktreeId},
            inventory::{CapabilityInventoryProfile, CapabilityInventoryRecorded},
            repository::{
                FilesystemIdentity, GitObjectFormat, GitRegistrationState, PathObservation,
                WorktreeInstance, WorktreeKind, WorktreeLifecycle,
            },
        };
        if let Some(root) = std::env::var_os("EVERTRACE_TEST_INVENTORY_CAS_CHILD") {
            let root = PathBuf::from(root);
            // Hold the actual writer open when exiting inside the publisher.
            let _writer = crate::open_writer(&root.join("data")).await.unwrap();
            let key = DeviceKeyStore::new(root.join("keys")).load().unwrap();
            let (snapshot, payloads) = scan_test_skill(&root.join("assets"), &key);
            let cas = CasStore::open_existing(root.join("cas")).unwrap();
            CRASH_AFTER_INVENTORY_CAS.with(|crash| crash.set(true));
            let _ = publish_inventory_cas(&cas, &snapshot, &payloads, &key);
            panic!("CAS fault seam was not reached");
        }
        let root =
            std::env::temp_dir().join(format!("evertrace-inventory-cas-crash-{}", JobId::new_v7()));
        let assets = root.join("assets");
        fs::create_dir_all(&assets).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            assets.join("SKILL.md"),
            "---\nname: bounded\ndescription: initial authored content\n---\n",
        )
        .unwrap();
        let key = DeviceKeyStore::new(root.join("keys"))
            .load_or_create()
            .unwrap();
        let cas = CasStore::open(root.join("cas")).unwrap();
        let observation = PathObservation {
            path: assets.to_string_lossy().into_owned(),
            first_observed_at_us: 1,
            last_observed_at_us: 1,
            evidence_refs: vec!["fixture-probe".into()],
        };
        let mut repository = RepositoryInstance {
            repository_id: RepositoryId::new_v7(),
            repository_revision: 1,
            predecessor_revision: None,
            current_path: observation.path.clone(),
            path_history: vec![observation.clone()],
            git_common_dir_path: Some(assets.join(".git").to_string_lossy().into_owned()),
            common_dir_filesystem: Some(FilesystemIdentity {
                device: 1,
                inode: 2,
            }),
            object_format: Some(GitObjectFormat::Sha1),
            remote_fingerprints: Vec::new(),
            derived_from: None,
            identity_evidence_refs: vec!["fixture-probe".into()],
            recorded_at_us: 1,
            user_disabled: false,
            capability_state: None,
        };
        let worktree = WorktreeInstance {
            worktree_instance_id: WorktreeId::new_v7(),
            worktree_revision: 1,
            predecessor_revision: None,
            repository_instance_id: repository.repository_id,
            kind: WorktreeKind::Main,
            lifecycle: WorktreeLifecycle::Active,
            current_path: Some(observation.path.clone()),
            path_history: vec![observation.clone()],
            git_admin_path_history: vec![PathObservation {
                path: repository.git_common_dir_path.clone().unwrap(),
                ..observation
            }],
            git_registration_state: GitRegistrationState::Registered,
            current_snapshot_id: None,
            created_event_ref: "fixture-probe".into(),
            terminal_event_ref: None,
            recreated_from_worktree_instance_id: None,
            recorded_at_us: 1,
        };
        let context = InventoryContext {
            repository_id: repository.repository_id,
            worktree_id: worktree.worktree_instance_id,
            cwd: repository.current_path.clone(),
            adapter_manifest_id: "d".repeat(64),
            profile: CapabilityInventoryProfile::NativeFiniteAssetsV1,
            host_home: root.to_string_lossy().into_owned(),
            host_config_root: root.to_string_lossy().into_owned(),
            host_profile: None,
        };
        let mut writer = crate::open_writer(&root.join("data")).await.unwrap();
        writer
            .commit(
                &inventory_command(
                    vec![
                        JournalPayload::RepositoryInstanceRecorded(Box::new(repository.clone())),
                        JournalPayload::WorktreeInstanceRecorded(Box::new(worktree)),
                    ],
                    1,
                    [0; 32],
                )
                .unwrap(),
                1,
            )
            .await
            .unwrap();
        repository.repository_revision = 2;
        repository.predecessor_revision = Some(1);
        repository.user_disabled = true;
        repository.recorded_at_us = 2;
        let mut disabled = JournalEventDraft::runtime(
            2,
            [0; 32],
            INVENTORY_JOB_KIND,
            JournalPayload::RepositoryInstanceRecorded(Box::new(repository.clone())),
        );
        disabled.source_kind = evertrace_store::SourceKind::Manual;
        writer
            .commit(
                &JournalCommand::new(CommandId::new_v7(), vec![disabled]).unwrap(),
                2,
            )
            .await
            .unwrap();
        repository.repository_revision = 3;
        repository.predecessor_revision = Some(2);
        repository.recorded_at_us = 3;
        repository.capability_state = Some(RepositoryCapabilityState {
            trust_revoked: true,
            revalidated_inventory_ref: None,
        });
        writer
            .commit(
                &inventory_command(
                    vec![JournalPayload::RepositoryInstanceRecorded(Box::new(
                        repository.clone(),
                    ))],
                    3,
                    [0; 32],
                )
                .unwrap(),
                3,
            )
            .await
            .unwrap();
        let job = DurableJob {
            job_id: JobId::new_v7(),
            idempotency_key: format!(
                "capability_inventory:enable:restore|{}|root",
                context.worktree_id
            ),
            target_revision: inventory_repository_target(
                repository.repository_id,
                repository.repository_revision,
            ),
            target_watermark: 0,
            target_generation: 1,
            kind: INVENTORY_JOB_KIND.into(),
            algorithm_revision: INVENTORY_JOB_KIND.into(),
            model_id: None,
            priority: 0,
            state: JobStatus::Queued,
            attempt: 1,
            backoff_until_us: None,
            config_hash: [0; 32],
            budget: inventory_budget(),
            terminal: None,
            lease_until_us: None,
        };
        let mut enable = JournalEventDraft::runtime(
            4,
            [0; 32],
            INVENTORY_JOB_KIND,
            JournalPayload::JobState(job.clone()),
        );
        enable.source_kind = evertrace_store::SourceKind::Manual;
        writer
            .commit(
                &JournalCommand::new(CommandId::new_v7(), vec![enable]).unwrap(),
                4,
            )
            .await
            .unwrap();
        writer
            .commit(
                &inventory_command(
                    vec![JournalPayload::JobLease(inventory_lease(&job, 5).unwrap())],
                    5,
                    [0; 32],
                )
                .unwrap(),
                5,
            )
            .await
            .unwrap();
        let before = writer.frontier();
        drop(writer);
        let (old_snapshot, old_payloads) = scan_test_skill(&assets, &key);
        let old_bytes = protect(&serde_json::to_vec(&old_snapshot).unwrap(), &key).unwrap();
        let old_digest =
            evertrace_capture::CasDigest::for_protected_bytes(old_bytes.protected_bytes());
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "jobs::inventory::tests::inventory_cas_crash_preserves_gates_and_restarts_once",
                "--test-threads=1",
            ])
            .env("EVERTRACE_TEST_INVENTORY_CAS_CHILD", &root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86));
        assert_eq!(cas.read(&old_digest).unwrap(), old_bytes.protected_bytes());
        for digest in old_payloads.keys() {
            assert!(cas.read(&digest.parse().unwrap()).is_ok());
        }
        let mut writer = crate::open_writer(&root.join("data")).await.unwrap();
        assert_eq!(writer.frontier(), before);
        let current = writer
            .inventory_context(&context, Some(job.job_id))
            .unwrap();
        assert_eq!(current.repository, Some(repository.clone()));
        assert!(
            current.latest_completion.is_none() && current.post_restoration_completion().is_none()
        );
        assert_eq!(current.job.as_ref().unwrap().state, JobStatus::Leased);
        let after_crash = writer.project().await.unwrap();
        assert!(
            !after_crash
                .live_cas_refs()
                .unwrap()
                .contains(&old_digest.to_string())
        );
        let at = current.job.as_ref().unwrap().lease_until_us.unwrap() + 1;
        let actions = crate::expired_leases(&after_crash.rows, at, after_crash.frontier).unwrap();
        assert_eq!(actions.len(), 1);
        let mut retry = actions[0].job.clone();
        retry.state = JobStatus::Queued;
        retry.attempt = actions[0].next_attempt;
        retry.lease_until_us = None;
        writer
            .commit(
                &inventory_command(vec![JournalPayload::JobState(retry.clone())], at, [0; 32])
                    .unwrap(),
                at,
            )
            .await
            .unwrap();
        writer
            .commit(
                &inventory_command(
                    vec![JournalPayload::JobLease(
                        inventory_lease(&retry, at + 1).unwrap(),
                    )],
                    at + 1,
                    [0; 32],
                )
                .unwrap(),
                at + 1,
            )
            .await
            .unwrap();
        fs::write(
            assets.join("SKILL.md"),
            "---\nname: bounded\ndescription: freshly rescanned after interruption\n---\n",
        )
        .unwrap();
        let (snapshot, payloads) = scan_test_skill(&assets, &key);
        assert!(!inventory_snapshot_current(
            &old_snapshot,
            Instant::now() + QUANTUM
        ));
        let snapshot_ref = publish_inventory_cas(&cas, &snapshot, &payloads, &key).unwrap();
        assert_ne!(snapshot_ref, old_digest.to_string());
        let leased = writer
            .inventory_context(&context, Some(job.job_id))
            .unwrap()
            .job
            .unwrap();
        let fact = CapabilityInventoryRecorded {
            job_id: job.job_id,
            context: context.clone(),
            repository_revision: repository.repository_revision,
            snapshot_cas_ref: snapshot_ref.clone(),
            dependency_cas_refs: payloads.keys().cloned().collect(),
            evidence_refs: vec!["fixture-probe".into(), "session:bounded".into()],
            recorded_at_us: at + 2,
        };
        let completion = inventory_completion_command(
            &repository,
            &leased,
            Some(fact.clone()),
            true,
            job.job_id,
            at + 2,
        )
        .unwrap();
        writer.commit(&completion, at + 2).await.unwrap();
        let committed = writer.frontier();
        let source = (
            "session:bounded",
            context.repository_id,
            context.worktree_id,
        );
        assert!(crate::procedure::historical_inventory_at_source(
            &fact,
            committed,
            source,
            (committed, at + 3)
        ));
        assert!(!crate::procedure::historical_inventory_at_source(
            &fact,
            committed,
            source,
            (committed - 1, at + 3)
        ));
        assert!(!crate::procedure::historical_inventory_at_source(
            &fact,
            committed,
            source,
            (committed, at + 1)
        ));
        assert!(!crate::procedure::historical_inventory_at_source(
            &fact,
            committed,
            ("session:other", context.repository_id, context.worktree_id),
            (committed, at + 3)
        ));
        assert!(!crate::procedure::historical_inventory_at_source(
            &fact,
            committed,
            (
                "session:bounded",
                context.repository_id,
                WorktreeId::new_v7()
            ),
            (committed, at + 3)
        ));
        drop(writer); // Simulate a lost acknowledgement, then recover the same command.
        let mut writer = crate::open_writer(&root.join("data")).await.unwrap();
        assert!(writer.commit(&completion, at + 3).await.unwrap().replayed);
        assert_eq!(writer.frontier(), committed);
        let current = writer
            .inventory_context(&context, Some(job.job_id))
            .unwrap();
        assert_eq!(
            current
                .post_restoration_completion()
                .unwrap()
                .snapshot_cas_ref,
            snapshot_ref
        );
        let repository = current.repository.unwrap();
        assert!(
            !repository.user_disabled
                && !repository.capability_state.as_ref().unwrap().trust_revoked
        );
        assert_eq!(
            repository
                .capability_state
                .unwrap()
                .revalidated_inventory_ref,
            Some(job.job_id)
        );
        assert_eq!(repository.repository_revision, 4);
        assert_eq!(current.job.unwrap().state, JobStatus::Succeeded);
        let historical =
            crate::repository::read_inventory_snapshot(&root.join("cas"), &fact).unwrap();
        assert_eq!(historical, snapshot);
        fs::write(
            assets.join("SKILL.md"),
            "---\nname: bounded\ndescription: subsequently installed content\n---\n",
        )
        .unwrap();
        let (new_snapshot, new_payloads) = scan_test_skill(&assets, &key);
        let new_ref = publish_inventory_cas(&cas, &new_snapshot, &new_payloads, &key).unwrap();
        assert_ne!(new_ref, fact.snapshot_cas_ref);
        assert!(!inventory_snapshot_current(
            &historical,
            Instant::now() + QUANTUM
        ));
        // The shared protected-CAS reader never substitutes current source
        // bytes for a previously committed snapshot.
        assert_eq!(
            crate::repository::read_inventory_snapshot(&root.join("cas"), &fact).unwrap(),
            historical
        );
        let mut mismatched = fact.clone();
        mismatched.snapshot_cas_ref = new_ref;
        assert!(
            crate::repository::read_inventory_snapshot(&root.join("cas"), &mismatched).is_err()
        );
        drop(writer);
        fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inventory_concurrent_frontier_is_retryable_and_exact_commit_replays() {
        let root =
            std::env::temp_dir().join(format!("evertrace-inventory-admission-{}", JobId::new_v7()));
        let (writer, task) =
            crate::spawn_writer(crate::open_writer(&root).await.unwrap(), 8).unwrap();
        let old = writer.project().await.unwrap().frontier;
        let make = |target: &str, at| {
            inventory_command(
                vec![JournalPayload::DirtyTarget(evertrace_store::DirtyTarget {
                    target_kind: evertrace_store::DirtyTargetKind::ObjectsProjection,
                    target_id: target.into(),
                    algorithm_revision: "inventory-test-v1".into(),
                    source_watermark: 1,
                })],
                at,
                [0; 32],
            )
            .unwrap()
        };
        writer
            .commit(make("concurrent-capture", 10), 10)
            .await
            .unwrap();
        let operation = make("inventory-work", 20);
        let id = operation.command_id();
        assert!(matches!(
            commit_known(&writer, operation.clone(), 20, old).await,
            Err(InventoryWorkerError::StaleFrontier)
        ));
        assert!(writer.committed_command(id).await.unwrap().is_none());
        let fresh = writer.project().await.unwrap().frontier;
        commit_known(&writer, operation.clone(), 20, fresh)
            .await
            .unwrap();
        let committed = writer.project().await.unwrap().frontier;
        // Exact recovery wins even when the caller retained the old frontier.
        commit_known(&writer, operation, 20, old).await.unwrap();
        assert_eq!(writer.project().await.unwrap().frontier, committed);
        writer.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn inventory_enumeration_keeps_start_identity_and_rejects_depth_truncation() {
        let path = std::env::temp_dir().join(format!(
            "evertrace-inventory-enumeration-{}",
            JobId::new_v7()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let mut scan =
            DirectoryScan::open(path.clone(), InventorySourceScope::Repository, 0).unwrap();
        assert!(scan.entries.next().is_none());
        fs::write(
            path.join("SKILL.md"),
            "---\ndescription: newly added\n---\n",
        )
        .unwrap();
        // Stable inode/permissions alone do not prove the enumeration.
        assert!(scan.root.revalidate_stable().is_ok());
        assert!(matches!(scan.finish(), Err(InventoryScanError::Changed)));
        let mut scan =
            DirectoryScan::open(path.clone(), InventorySourceScope::Repository, 0).unwrap();
        let entry = scan.entries.next().unwrap().unwrap();
        assert!(matches!(
            scan.classify(entry).unwrap(),
            Some(ScanItem::File(_, _, InventoryAssetKind::Skill))
        ));
        assert!(scan.entries.next().is_none());
        let proof = scan.finish().unwrap();
        assert!(proof.current());
        fs::create_dir(path.join("deeper")).unwrap();
        assert!(!proof.current());
        let mut scan = DirectoryScan::open(
            path.clone(),
            InventorySourceScope::Repository,
            MAX_SKILL_DEPTH,
        )
        .unwrap();
        let entry = scan
            .entries
            .by_ref()
            .map(Result::unwrap)
            .find(|entry| entry.file_name() == "deeper")
            .unwrap();
        assert!(matches!(
            scan.classify(entry),
            Err(InventoryScanError::Budget)
        ));
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn inventory_marker_proofs_track_selection_without_git_internal_churn() {
        let path =
            std::env::temp_dir().join(format!("evertrace-inventory-marker-{}", JobId::new_v7()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let cwd = path.join("nested");
        let skills = cwd.join("skills");
        fs::create_dir_all(&skills).unwrap();
        fs::write(
            skills.join("SKILL.md"),
            "---\ndescription: scoped authored content\n---\n",
        )
        .unwrap();
        let marker = path.join(".git");
        fs::create_dir(&marker).unwrap();
        let key = DeviceKeyStore::new(path.join("keys"))
            .load_or_create()
            .unwrap();
        let cas = CasStore::open(path.join("cas")).unwrap();
        let scan_and_publish = || {
            let (boundary, mut proofs) = select_root_boundary(
                &[cwd.clone(), path.clone()],
                &[".git".into()],
                &mut 8,
                Instant::now() + QUANTUM,
            )
            .unwrap();
            let mut work = VecDeque::new();
            queue_repository_directories(&mut work, vec![cwd.clone(), path.clone()], &boundary);
            while let Some(item) = work.pop_front() {
                let ScanItem::Configuration(config) = item else {
                    panic!("configuration must precede its repository directory");
                };
                assert!(
                    matches!(work.pop_front(), Some(ScanItem::RepositoryDirectory(directory))
                    if config == directory.join(".codex/config.toml"))
                );
                let (root, relative) = confined_parent(&config).unwrap();
                let deadline = Instant::now() + QUANTUM;
                let identity = root.probe_regular_file(&relative, deadline).unwrap();
                if let Some(identity) = identity {
                    let file = root.read(&relative, read_limits(4096, deadline)).unwrap();
                    assert_eq!(file.identity, identity);
                    let selection = source_selection(&file.bytes, None).unwrap();
                    assert!(selection.observed && !selection.source_overrides_present);
                }
                proofs.push(InventoryPathState {
                    path: config.to_string_lossy().into_owned(),
                    directory: false,
                    selection_only: false,
                    identity: identity.map(file_identity),
                });
            }
            let (mut snapshot, payloads) = scan_test_skill(&skills, &key);
            snapshot.sources.push(InventorySource {
                scope: InventorySourceScope::Repository,
                root: Some(path.to_string_lossy().into_owned()),
                observed: true,
                entries: proofs,
            });
            let digest = publish_inventory_cas(&cas, &snapshot, &payloads, &key).unwrap();
            let published: CapabilityInventorySnapshot =
                serde_json::from_slice(&cas.read(&digest.parse().unwrap()).unwrap()).unwrap();
            assert!(inventory_snapshot_current(
                &published,
                Instant::now() + QUANTUM
            ));
            (boundary, published)
        };
        let (boundary, published) = scan_and_publish();
        assert_eq!(boundary, path);
        fs::write(marker.join("unrelated-internal-entry"), "changed").unwrap();
        assert!(inventory_snapshot_current(
            &published,
            Instant::now() + QUANTUM
        ));
        let nested_marker = cwd.join(".git");
        fs::create_dir(&nested_marker).unwrap();
        assert!(!inventory_snapshot_current(
            &published,
            Instant::now() + QUANTUM
        ));
        let outside_config = path.join(".codex/config.toml");
        fs::create_dir(path.join(".codex")).unwrap();
        fs::write(&outside_config, "[[").unwrap();
        assert!(source_selection(&fs::read(&outside_config).unwrap(), None).is_err());
        fs::create_dir(cwd.join(".codex")).unwrap();
        fs::write(cwd.join(".codex/config.toml"), "# no source selectors\n").unwrap();
        let (boundary, narrowed) = scan_and_publish();
        assert_eq!(boundary, cwd);
        assert!(
            !narrowed
                .sources
                .iter()
                .flat_map(|source| &source.entries)
                .any(|entry| Path::new(&entry.path) == outside_config)
        );
        fs::write(&outside_config, "[still invalid").unwrap();
        assert!(inventory_snapshot_current(
            &narrowed,
            Instant::now() + QUANTUM
        ));
        fs::remove_dir(&nested_marker).unwrap();
        assert!(!inventory_snapshot_current(
            &narrowed,
            Instant::now() + QUANTUM
        ));
        fs::remove_file(&outside_config).unwrap();
        let (boundary, published) = scan_and_publish();
        assert_eq!(boundary, path);
        fs::rename(&marker, path.join("old-marker")).unwrap();
        assert!(!inventory_snapshot_current(
            &published,
            Instant::now() + QUANTUM
        ));
        fs::create_dir(&marker).unwrap();
        assert!(!inventory_snapshot_current(
            &published,
            Instant::now() + QUANTUM
        ));
        let old = serde_json::json!({"path": marker, "directory": false, "identity": null});
        let parsed: InventoryPathState = serde_json::from_value(old.clone()).unwrap();
        assert!(!parsed.selection_only);
        assert_eq!(serde_json::to_value(parsed).unwrap(), old);
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn inventory_finite_entry_proofs_detect_changed_files_and_added_entries() {
        let root =
            std::env::temp_dir().join(format!("evertrace-inventory-entries-{}", JobId::new_v7()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let file = root.join("AGENTS.md");
        fs::write(&file, "finite instructions").unwrap();
        let snapshot = CapabilityInventorySnapshot {
            sources: vec![InventorySource {
                scope: InventorySourceScope::Repository,
                root: Some(root.to_string_lossy().into_owned()),
                observed: true,
                entries: [&root, &file]
                    .into_iter()
                    .map(|path| {
                        let metadata = fs::metadata(path).unwrap();
                        InventoryPathState {
                            path: path.to_string_lossy().into_owned(),
                            directory: metadata.is_dir(),
                            selection_only: false,
                            identity: Some(metadata_identity(&metadata).unwrap()),
                        }
                    })
                    .collect(),
            }],
            signatures: Vec::new(),
        };
        assert!(inventory_snapshot_current(
            &snapshot,
            Instant::now() + QUANTUM
        ));
        assert!(!inventory_snapshot_current(&snapshot, Instant::now()));
        fs::write(&file, "new instructions of different length").unwrap();
        assert!(!inventory_snapshot_current(
            &snapshot,
            Instant::now() + QUANTUM
        ));
        let mut refreshed = snapshot.clone();
        refreshed.sources[0].entries[1].identity =
            Some(metadata_identity(&fs::metadata(&file).unwrap()).unwrap());
        assert!(inventory_snapshot_current(
            &refreshed,
            Instant::now() + QUANTUM
        ));
        fs::write(root.join("SKILL.md"), "new finite entry").unwrap();
        assert!(!inventory_snapshot_current(
            &refreshed,
            Instant::now() + QUANTUM
        ));
        fs::remove_dir_all(&root).unwrap();
    }
}
