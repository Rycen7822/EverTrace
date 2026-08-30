//! Single bounded owner for durable background work.

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use evertrace_capture::{CaptureAdmissionState, CaptureRuntime, RuntimeSnapshot};
use evertrace_codex::HostProbeReport;
use evertrace_domain::{
    config::DreamingConfig,
    ids::{CommandId, JobId, SourceObservationId},
    semantic::{
        AtomLifecycleStatus, GlobalSuccessorSupportContract, GlobalSupportValidationEvent,
        ProposalStatus,
    },
};
use evertrace_store::{
    DirtyTargetKind, DurableJob, EventScope, JobBudget, JobLease, JobStatus, JobTerminalAudit,
    JobTerminalOutcome, JobTerminalReason, JournalCommand, JournalEventDraft, JournalPayload,
    RuntimeSchedulerView, SourceKind,
};
use thiserror::Error;
use tokio::sync::{OwnedRwLockReadGuard, RwLock, watch};

use crate::{
    SessionImportBudget, SessionImportWorker, WriterActorError, WriterHandle,
    capture::{ReconcileError, ReconcileInput, reconcile_observations_once},
    jobs::{JobResultDisposition, SynthesisPlanner, expired_leases, support_closure_result},
    session_import::{SessionCatalogService, session_import_job_budget},
};

const TOTAL_LIMIT: usize = 32;
const PER_LANE_LIMIT: usize = 8;
const CAPTURE_PROBE_LIMIT: usize = TOTAL_LIMIT + PER_LANE_LIMIT;
const RETRY_DELAY: Duration = Duration::from_secs(5);
const CAPTURE_ALGORITHM_REVISION: &str = "capture-reconciliation-v1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BackgroundLane {
    Critical,
    Deterministic,
    Import,
    Synthesis,
    Maintenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledJob {
    pub lane: BackgroundLane,
    pub job: DurableJob,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BackgroundProgress {
    pub completed: usize,
    pub retryable: bool,
}

struct ClaimedJob {
    snapshot: evertrace_store::ProjectionSnapshot,
    job: DurableJob,
    report: Option<OwnedRwLockReadGuard<Option<HostProbeReport>>>,
}

#[derive(Debug, Error)]
pub enum BackgroundSchedulerError {
    #[error("background scheduler store state is corrupt")]
    Store,
    #[error("background scheduler writer stopped")]
    Writer,
}

#[derive(Clone)]
pub struct BackgroundScheduler {
    writer: WriterHandle,
    catalog: SessionCatalogService,
    import: SessionImportWorker,
    report: Arc<RwLock<Option<HostProbeReport>>>,
    runtime: RuntimeSnapshot,
    synthesis: SynthesisPlanner,
    dreaming: DreamingConfig,
    capture_cursor: Arc<AtomicUsize>,
}

impl BackgroundScheduler {
    pub fn new(
        writer: WriterHandle,
        catalog: SessionCatalogService,
        import: SessionImportWorker,
        report: Arc<RwLock<Option<HostProbeReport>>>,
        runtime: RuntimeSnapshot,
        synthesis: SynthesisPlanner,
        dreaming: DreamingConfig,
    ) -> Self {
        Self {
            writer,
            catalog,
            import,
            report,
            runtime,
            synthesis,
            dreaming,
            capture_cursor: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub async fn run_once(&self) -> Result<BackgroundProgress, BackgroundSchedulerError> {
        let capture_state = CaptureRuntime::open(self.runtime.clone())
            .map(|runtime| runtime.state())
            .unwrap_or(CaptureAdmissionState::Unavailable);
        let optional_allowed = capture_state == CaptureAdmissionState::Normal;
        let mut completed = 0;
        let mut retryable = false;
        if optional_allowed {
            let report = Arc::clone(&self.report).read_owned().await;
            if let Some(report) = report.as_ref() {
                match self.catalog.refresh(report).await {
                    Ok(changed) => completed += changed,
                    Err(_) => retryable = true,
                }
            }
        }

        let mut snapshot = self.writer.project().await.map_err(map_writer)?;
        let recovery_now_us = now_us()?;
        let recovery = expired_leases(&snapshot.rows, recovery_now_us, snapshot.frontier)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        if !recovery.is_empty() {
            let events = recovery
                .into_iter()
                .map(|action| {
                    let mut job = action.job;
                    job.state = JobStatus::Queued;
                    job.attempt = action.next_attempt;
                    job.backoff_until_us = None;
                    job.lease_until_us = None;
                    job.terminal = None;
                    JournalEventDraft {
                        occurred_at_us: recovery_now_us,
                        source_kind: SourceKind::System,
                        scope: EventScope::default(),
                        causation_id: None,
                        correlation_id: None,
                        effective_config_hash: job.config_hash,
                        algorithm_revision: job.algorithm_revision.clone(),
                        payload: JournalPayload::JobState(job),
                    }
                })
                .collect::<Vec<_>>();
            let command = JournalCommand::new(CommandId::new_v7(), events)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            match self
                .writer
                .commit_if_frontier(command, recovery_now_us, snapshot.frontier)
                .await
            {
                Ok(outcome) => {
                    completed += usize::from(!outcome.replayed);
                    snapshot = self.writer.project().await.map_err(map_writer)?;
                }
                Err(WriterActorError::StaleFrontier) => {
                    return Ok(BackgroundProgress {
                        completed,
                        retryable: true,
                    });
                }
                Err(error) => return Err(map_writer(error)),
            }
        }

        let mut view = RuntimeSchedulerView::from_snapshot(&snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let max_synthesis_wall_time = Duration::from_secs(self.dreaming.max_wall_time.seconds());
        let synthesis_budget = self
            .synthesis
            .durable_budget(max_synthesis_wall_time)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let incompatible = view
            .jobs
            .iter()
            .filter(|job| {
                matches!(job.state, JobStatus::Queued | JobStatus::Leased)
                    && (job.kind == "session_import_v1"
                        && !import_job_is_current(job, self.runtime.effective_config_hash)
                        || job.kind == "semantic_synthesis_v1"
                            && (!self
                                .synthesis
                                .job_identity_is_current(job, self.runtime.effective_config_hash)
                                || !self.synthesis.job_is_current(
                                    job,
                                    self.runtime.effective_config_hash,
                                    &synthesis_budget,
                                )))
            })
            .cloned()
            .collect::<Vec<_>>();
        if !incompatible.is_empty() {
            let occurred_at_us = now_us()?;
            let mut events = Vec::new();
            let mut replacement_keys = BTreeSet::new();
            for mut job in incompatible {
                let needs_replacement = job.kind == "session_import_v1"
                    && !view.jobs.iter().any(|current| {
                        current.job_id != job.job_id
                            && matches!(current.state, JobStatus::Queued | JobStatus::Leased)
                            && current.idempotency_key == job.idempotency_key
                            && import_job_is_current(current, self.runtime.effective_config_hash)
                    })
                    && replacement_keys
                        .insert((job.idempotency_key.clone(), job.target_generation));
                let mut replacement = needs_replacement.then(|| {
                    let mut replacement = job.clone();
                    replacement.job_id = JobId::new_v7();
                    replacement.config_hash = self.runtime.effective_config_hash;
                    replacement.algorithm_revision = "session_import_v1".into();
                    replacement.model_id = None;
                    replacement.budget = session_import_job_budget();
                    replacement.state = JobStatus::Queued;
                    replacement.attempt = 1;
                    replacement.lease_until_us = None;
                    replacement.backoff_until_us = None;
                    replacement.terminal = None;
                    replacement
                });
                job.state = JobStatus::Failed;
                job.lease_until_us = None;
                job.terminal = Some(Box::new(JobTerminalAudit {
                    outcome: JobTerminalOutcome::Failed,
                    reason: JobTerminalReason::Unsupported,
                    result_ref: Some(job.target_revision.clone()),
                }));
                events.push(JournalEventDraft {
                    occurred_at_us,
                    source_kind: SourceKind::System,
                    scope: EventScope::default(),
                    causation_id: None,
                    correlation_id: None,
                    effective_config_hash: job.config_hash,
                    algorithm_revision: job.algorithm_revision.clone(),
                    payload: JournalPayload::JobState(job),
                });
                if let Some(job) = replacement.take() {
                    events.push(JournalEventDraft {
                        occurred_at_us,
                        source_kind: SourceKind::System,
                        scope: EventScope::default(),
                        causation_id: None,
                        correlation_id: None,
                        effective_config_hash: job.config_hash,
                        algorithm_revision: job.algorithm_revision.clone(),
                        payload: JournalPayload::JobState(job),
                    });
                }
            }
            let command = JournalCommand::new(CommandId::new_v7(), events)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            match self
                .writer
                .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
                .await
            {
                Ok(outcome) => {
                    completed += usize::from(!outcome.replayed);
                    snapshot = self.writer.project().await.map_err(map_writer)?;
                    view = RuntimeSchedulerView::from_snapshot(&snapshot)
                        .map_err(|_| BackgroundSchedulerError::Store)?;
                }
                Err(WriterActorError::StaleFrontier) => {
                    return Ok(BackgroundProgress {
                        completed,
                        retryable: true,
                    });
                }
                Err(error) => return Err(map_writer(error)),
            }
        }
        let covered = view
            .jobs
            .iter()
            .filter(|job| {
                job.kind == "semantic_synthesis_v1"
                    && self
                        .synthesis
                        .job_identity_is_current(job, self.runtime.effective_config_hash)
                    && (!matches!(job.state, JobStatus::Queued | JobStatus::Leased)
                        || self.synthesis.job_is_current(
                            job,
                            self.runtime.effective_config_hash,
                            &synthesis_budget,
                        ))
            })
            .map(|job| {
                (
                    job.idempotency_key.clone(),
                    job.target_generation,
                    job.config_hash,
                )
            })
            .collect();
        let covered_projections = view
            .jobs
            .iter()
            .filter(|job| job.kind == "objects_projection")
            .map(|job| (job.idempotency_key.clone(), job.target_watermark))
            .collect::<BTreeSet<_>>();
        let projection_jobs = view
            .dirty
            .iter()
            .filter(|dirty| dirty.target_kind == DirtyTargetKind::ObjectsProjection)
            .filter(|dirty| {
                !covered_projections.contains(&(dirty.stable_key(), dirty.source_watermark))
            })
            .take(PER_LANE_LIMIT)
            .map(|dirty| DurableJob {
                job_id: JobId::new_v7(),
                idempotency_key: dirty.stable_key(),
                target_revision: dirty.target_id.clone(),
                target_watermark: dirty.source_watermark,
                target_generation: dirty.source_watermark.max(1),
                kind: "objects_projection".into(),
                algorithm_revision: dirty.algorithm_revision.clone(),
                model_id: None,
                priority: 0,
                state: JobStatus::Queued,
                attempt: 1,
                backoff_until_us: None,
                config_hash: self.runtime.effective_config_hash,
                budget: JobBudget {
                    max_items: 1,
                    max_bytes: None,
                    max_input_tokens: None,
                    max_output_tokens: None,
                    max_calls: None,
                    max_wall_time_ms: 250,
                },
                terminal: None,
                lease_until_us: None,
            })
            .collect::<Vec<_>>();
        if !projection_jobs.is_empty() {
            let occurred_at_us = now_us()?;
            let events = projection_jobs
                .into_iter()
                .map(|job| {
                    JournalEventDraft::runtime(
                        occurred_at_us,
                        job.config_hash,
                        job.algorithm_revision.clone(),
                        JournalPayload::JobState(job),
                    )
                })
                .collect();
            let command = JournalCommand::new(CommandId::new_v7(), events)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            match self
                .writer
                .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
                .await
            {
                Ok(_) => {
                    snapshot = self.writer.project().await.map_err(map_writer)?;
                    view = RuntimeSchedulerView::from_snapshot(&snapshot)
                        .map_err(|_| BackgroundSchedulerError::Store)?;
                }
                Err(WriterActorError::StaleFrontier) => retryable = true,
                Err(error) => return Err(map_writer(error)),
            }
        }
        let mut capture_candidates = BTreeMap::new();
        for dirty in view.dirty.iter().filter(|dirty| {
            matches!(
                dirty.target_kind,
                DirtyTargetKind::PhysicalNormalization | DirtyTargetKind::CaptureReconciliation
            )
        }) {
            let replace = dirty.target_kind == DirtyTargetKind::CaptureReconciliation
                && capture_candidates.get(&dirty.target_id).is_some_and(
                    |current: &evertrace_store::DirtyTarget| {
                        current.target_kind == DirtyTargetKind::PhysicalNormalization
                    },
                );
            if replace || !capture_candidates.contains_key(&dirty.target_id) {
                capture_candidates.insert(dirty.target_id.clone(), dirty.clone());
            }
        }
        let capture_candidates = capture_candidates
            .into_values()
            .filter(|dirty| {
                !capture_target_covered(&view, dirty, self.runtime.effective_config_hash)
            })
            .map(|dirty| {
                SourceObservationId::from_str(&dirty.target_id)
                    .map_err(|_| BackgroundSchedulerError::Store)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut probed = Vec::new();
        let capture_page_incomplete = capture_candidates.len() > CAPTURE_PROBE_LIMIT;
        if !capture_candidates.is_empty() {
            let start = self
                .capture_cursor
                .fetch_add(CAPTURE_PROBE_LIMIT, Ordering::Relaxed)
                % capture_candidates.len();
            probed.extend(
                (0..capture_candidates.len().min(CAPTURE_PROBE_LIMIT))
                    .map(|offset| capture_candidates[(start + offset) % capture_candidates.len()]),
            );
        }
        retryable |= capture_page_incomplete;
        let mut capture_items = BTreeMap::new();
        for chunk in probed.chunks(16) {
            let frontier = snapshot
                .reconciliation_frontier_for_observations(chunk)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            for item in frontier.items {
                let replace = item.target_kind == DirtyTargetKind::CaptureReconciliation
                    && capture_items.get(&item.target_id).is_some_and(
                        |current: &evertrace_store::ReconciliationWorkItem| {
                            current.target_kind == DirtyTargetKind::PhysicalNormalization
                        },
                    );
                if replace || !capture_items.contains_key(&item.target_id) {
                    capture_items.insert(item.target_id.clone(), item);
                }
            }
        }
        let report = self.report.read().await.clone();
        let occurred_at_us = now_us()?;
        let mut capture_jobs = Vec::new();
        for item in capture_items.into_values() {
            let kind = match item.target_kind {
                DirtyTargetKind::PhysicalNormalization => "physical_normalization",
                DirtyTargetKind::CaptureReconciliation => "capture_reconciliation",
                _ => return Err(BackgroundSchedulerError::Store),
            };
            let idempotency_key = format!("{kind}:{}", item.target_id);
            let active = view
                .jobs
                .iter()
                .filter(|job| {
                    is_capture_job(job)
                        && job.target_revision == item.target_id
                        && matches!(job.state, JobStatus::Queued | JobStatus::Leased)
                })
                .collect::<Vec<_>>();
            let current_active = active
                .iter()
                .filter(|existing| {
                    existing.kind == kind
                        && existing.idempotency_key == idempotency_key
                        && existing.target_watermark == item.source_event_seq
                        && existing.target_generation == item.source_event_seq.max(1)
                        && capture_job_is_current(existing, self.runtime.effective_config_hash)
                })
                .count();
            if current_active > 1 {
                return Err(BackgroundSchedulerError::Store);
            }
            for existing in active {
                let exact_tuple = existing.kind == kind
                    && existing.idempotency_key == idempotency_key
                    && existing.target_watermark == item.source_event_seq
                    && existing.target_generation == item.source_event_seq.max(1);
                if exact_tuple
                    && capture_job_is_current(existing, self.runtime.effective_config_hash)
                {
                    continue;
                }
                let mut failed = (*existing).clone();
                failed.state = JobStatus::Failed;
                failed.lease_until_us = None;
                failed.terminal = Some(Box::new(JobTerminalAudit {
                    outcome: JobTerminalOutcome::Failed,
                    reason: if exact_tuple {
                        JobTerminalReason::Unsupported
                    } else {
                        JobTerminalReason::StaleGeneration
                    },
                    result_ref: Some(failed.target_revision.clone()),
                }));
                capture_jobs.push(failed);
            }
            if current_active == 1 {
                continue;
            }
            let covered = view.jobs.iter().any(|job| {
                job.kind == kind
                    && job.idempotency_key == idempotency_key
                    && job.target_watermark == item.source_event_seq
                    && job.target_generation == item.source_event_seq.max(1)
                    && capture_job_is_current(job, self.runtime.effective_config_hash)
            });
            if covered
                || !report
                    .as_ref()
                    .is_some_and(|report| capture_item_manifest_matches(&item, report))
            {
                continue;
            }
            capture_jobs.push(DurableJob {
                job_id: JobId::new_v7(),
                idempotency_key,
                target_revision: item.target_id,
                target_watermark: item.source_event_seq,
                target_generation: item.source_event_seq.max(1),
                kind: kind.into(),
                algorithm_revision: CAPTURE_ALGORITHM_REVISION.into(),
                model_id: None,
                priority: 0,
                state: JobStatus::Queued,
                attempt: 1,
                backoff_until_us: None,
                config_hash: self.runtime.effective_config_hash,
                budget: capture_job_budget(),
                terminal: None,
                lease_until_us: None,
            });
        }
        if !capture_jobs.is_empty() {
            let events = capture_jobs
                .into_iter()
                .map(|job| {
                    JournalEventDraft::runtime(
                        occurred_at_us,
                        job.config_hash,
                        job.algorithm_revision.clone(),
                        JournalPayload::JobState(job),
                    )
                })
                .collect();
            let command = JournalCommand::new(CommandId::new_v7(), events)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            match self
                .writer
                .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
                .await
            {
                Ok(_) => {
                    snapshot = self.writer.project().await.map_err(map_writer)?;
                    view = RuntimeSchedulerView::from_snapshot(&snapshot)
                        .map_err(|_| BackgroundSchedulerError::Store)?;
                }
                Err(WriterActorError::StaleFrontier) => retryable = true,
                Err(error) => return Err(map_writer(error)),
            }
        }
        let synthesis_candidates = if self.dreaming.max_llm_tasks_per_run == 0 {
            Vec::new()
        } else {
            self.synthesis
                .durable_jobs(
                    &snapshot,
                    self.runtime.effective_config_hash,
                    &covered,
                    PER_LANE_LIMIT,
                    max_synthesis_wall_time,
                )
                .map_err(|_| BackgroundSchedulerError::Store)?
        };
        if !synthesis_candidates.is_empty() {
            let occurred_at_us = now_us()?;
            let events = synthesis_candidates
                .into_iter()
                .map(|job| JournalEventDraft {
                    occurred_at_us,
                    source_kind: SourceKind::System,
                    scope: EventScope::default(),
                    causation_id: None,
                    correlation_id: None,
                    effective_config_hash: job.config_hash,
                    algorithm_revision: job.algorithm_revision.clone(),
                    payload: JournalPayload::JobState(job),
                })
                .collect();
            let command = JournalCommand::new(CommandId::new_v7(), events)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            match self
                .writer
                .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
                .await
            {
                Ok(_) => {
                    snapshot = self.writer.project().await.map_err(map_writer)?;
                    view = RuntimeSchedulerView::from_snapshot(&snapshot)
                        .map_err(|_| BackgroundSchedulerError::Store)?;
                }
                Err(WriterActorError::StaleFrontier) => retryable = true,
                Err(error) => return Err(map_writer(error)),
            }
        }
        let selected = select_jobs(&view, capture_state)?;
        let paused_optional_pending = view.jobs.iter().any(|job| {
            matches!(job.state, JobStatus::Queued | JobStatus::Leased)
                && matches!(
                    job.kind.as_str(),
                    "physical_normalization" | "session_import_v1" | "semantic_synthesis_v1"
                )
        });
        drop(snapshot);
        drop(view);
        for selected_job in selected
            .iter()
            .filter(|selected| selected.lane == BackgroundLane::Critical)
        {
            if let Some(claimed) = self.claim_job(&selected_job.job).await? {
                match claimed.job.kind.as_str() {
                    "support_closure" => {
                        completed += self
                            .run_support_closure(&claimed.snapshot, &claimed.job)
                            .await?;
                    }
                    "capture_reconciliation" => {
                        let progress = self.run_capture_reconciliation(claimed).await?;
                        completed += progress.completed;
                        retryable |= progress.retryable;
                    }
                    _ => return Err(BackgroundSchedulerError::Store),
                }
            }
        }
        for selected_job in selected
            .iter()
            .filter(|selected| selected.lane == BackgroundLane::Deterministic)
        {
            if let Some(claimed) = self.claim_job(&selected_job.job).await? {
                if claimed.job.kind == "physical_normalization" {
                    let progress = self.run_capture_reconciliation(claimed).await?;
                    completed += progress.completed;
                    retryable |= progress.retryable;
                    continue;
                }
                if claimed.job.kind != "objects_projection" {
                    return Err(BackgroundSchedulerError::Store);
                }
                if claimed.snapshot.frontier < claimed.job.target_watermark {
                    retryable = true;
                    continue;
                }
                let mut terminal = claimed.job;
                terminal.state = JobStatus::Succeeded;
                terminal.lease_until_us = None;
                terminal.terminal = Some(Box::new(JobTerminalAudit {
                    outcome: JobTerminalOutcome::Succeeded,
                    reason: JobTerminalReason::Completed,
                    result_ref: Some(terminal.target_revision.clone()),
                }));
                let occurred_at_us = now_us()?;
                let command = JournalCommand::new(
                    CommandId::new_v7(),
                    vec![JournalEventDraft::runtime(
                        occurred_at_us,
                        terminal.config_hash,
                        terminal.algorithm_revision.clone(),
                        JournalPayload::JobState(terminal),
                    )],
                )
                .map_err(|_| BackgroundSchedulerError::Store)?;
                match self
                    .writer
                    .commit_if_frontier(command, occurred_at_us, claimed.snapshot.frontier)
                    .await
                {
                    Ok(outcome) => completed += usize::from(!outcome.replayed),
                    Err(WriterActorError::StaleFrontier) => retryable = true,
                    Err(error) => return Err(map_writer(error)),
                }
            }
        }
        retryable |= self.dreaming.max_llm_tasks_per_run != 0
            && selected
                .iter()
                .any(|selected| selected.lane == BackgroundLane::Synthesis);
        retryable |= !optional_allowed && paused_optional_pending;
        if optional_allowed
            && selected
                .iter()
                .any(|selected| selected.lane == BackgroundLane::Import)
        {
            let Some(import_job) = selected
                .iter()
                .find(|selected| selected.lane == BackgroundLane::Import)
            else {
                return Err(BackgroundSchedulerError::Store);
            };
            let max_items = usize::try_from(import_job.job.budget.max_items)
                .unwrap_or(usize::MAX)
                .min(PER_LANE_LIMIT);
            let max_bytes = import_job
                .job
                .budget
                .max_bytes
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(256 * 1024)
                .min(256 * 1024);
            let wall_time_ms = import_job.job.budget.max_wall_time_ms.min(250);
            match self
                .import
                .process_queued_once(
                    max_items,
                    SessionImportBudget {
                        max_bytes,
                        max_records: import_job.job.budget.max_items.min(16) as usize,
                        deadline: std::time::Instant::now() + Duration::from_millis(wall_time_ms),
                    },
                )
                .await
            {
                Ok((processed, pending)) => {
                    completed += processed;
                    retryable |= pending;
                }
                Err(_) => retryable = true,
            }
        }
        if optional_allowed && self.dreaming.max_llm_tasks_per_run != 0 {
            let synthesis_started = std::time::Instant::now();
            for selected_job in selected
                .iter()
                .filter(|selected| selected.lane == BackgroundLane::Synthesis)
                .take(usize::from(self.dreaming.max_llm_tasks_per_run))
            {
                let Some(remaining_wall_time) =
                    max_synthesis_wall_time.checked_sub(synthesis_started.elapsed())
                else {
                    retryable = true;
                    break;
                };
                let Some(claimed) = self.claim_job(&selected_job.job).await? else {
                    retryable = true;
                    continue;
                };
                let job_wall_time = Duration::from_millis(claimed.job.budget.max_wall_time_ms);
                let occurred_at_us = now_us()?;
                let daily_wall_time = self
                    .synthesis
                    .remaining_daily_wall_time(&claimed.snapshot, occurred_at_us)
                    .map_err(|_| BackgroundSchedulerError::Store)?;
                let execution_future = self.synthesis.execute_durable_job(
                    &claimed.snapshot,
                    &claimed.job,
                    self.runtime.effective_config_hash,
                    occurred_at_us,
                    max_synthesis_wall_time,
                );
                let execution = if daily_wall_time.is_zero() {
                    Ok(execution_future.await)
                } else {
                    tokio::time::timeout(
                        remaining_wall_time.min(job_wall_time).min(daily_wall_time),
                        execution_future,
                    )
                    .await
                };
                match execution {
                    Err(_) => {
                        retryable = true;
                        break;
                    }
                    Ok(Ok(command)) => match self
                        .writer
                        .commit_if_frontier(command, now_us()?, claimed.snapshot.frontier)
                        .await
                    {
                        Ok(outcome) => completed += usize::from(!outcome.replayed),
                        Err(WriterActorError::StaleFrontier) => retryable = true,
                        Err(error) => return Err(map_writer(error)),
                    },
                    Ok(Err(_)) => {
                        self.fail_stale(&claimed.job, claimed.snapshot.frontier)
                            .await?;
                        completed += 1;
                    }
                }
            }
        }
        Ok(BackgroundProgress {
            completed,
            retryable,
        })
    }

    pub async fn run(
        self,
        mut wakeup: watch::Receiver<u64>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), BackgroundSchedulerError> {
        let mut durable = self.writer.subscribe_background_frontier();
        let mut run_at = tokio::time::Instant::now();
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                changed = wakeup.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                    run_at = tokio::time::Instant::now();
                }
                changed = durable.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                    run_at = tokio::time::Instant::now();
                }
                _ = tokio::time::sleep_until(run_at) => {
                    let progress = tokio::select! {
                        result = self.run_once() => result?,
                        _ = wait_for_shutdown(&mut shutdown) => return Ok(()),
                    };
                    run_at = tokio::time::Instant::now()
                        + self.next_wake_after(progress.retryable).await?;
                    tokio::task::yield_now().await;
                }
            }
        }
    }

    async fn next_wake_after(&self, retryable: bool) -> Result<Duration, BackgroundSchedulerError> {
        let snapshot = self.writer.project().await.map_err(map_writer)?;
        let view = RuntimeSchedulerView::from_snapshot(&snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let now = now_us()?;
        let lease_delay = view
            .jobs
            .iter()
            .filter(|job| job.state == JobStatus::Leased)
            .filter_map(|job| job.lease_until_us)
            .map(|deadline| {
                Duration::from_micros(u64::try_from(deadline.saturating_sub(now)).unwrap_or(0))
            })
            .min();
        let mut delay = Duration::from_secs(self.dreaming.integrity_sweep_interval.seconds());
        if retryable {
            delay = delay.min(RETRY_DELAY);
        }
        if let Some(lease_delay) = lease_delay {
            delay = delay.min(lease_delay);
        }
        Ok(delay)
    }

    async fn run_support_closure(
        &self,
        snapshot: &evertrace_store::ProjectionSnapshot,
        job: &DurableJob,
    ) -> Result<usize, BackgroundSchedulerError> {
        let (contract, current) = support_context(snapshot, job)?;
        let semantic = evertrace_store::SemanticCurrentView::from_snapshot(snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let current_atom_revisions = semantic
            .atoms
            .values()
            .filter(|atom| atom.lifecycle_status == AtomLifecycleStatus::Active)
            .map(|atom| atom.revision_id)
            .collect::<std::collections::BTreeSet<_>>();
        let mut surviving = Vec::new();
        let mut missing = Vec::new();
        for revision in &contract.support_revision_refs {
            if current_atom_revisions.contains(revision) {
                surviving.push(*revision);
            } else {
                missing.push(*revision);
            }
        }
        let authorization_current = contract.authorization_revision_refs.iter().all(|revision| {
            semantic.proposals.values().any(|proposal| {
                proposal.proposal_revision_id == *revision
                    && proposal.status == ProposalStatus::Accepted
            })
        });
        let action = support_closure_result(
            job,
            &contract,
            &current,
            surviving,
            missing,
            authorization_current,
            now_us()?,
        )
        .map_err(|_| BackgroundSchedulerError::Store)?;
        let mut terminal = job.clone();
        terminal.state = JobStatus::Succeeded;
        terminal.lease_until_us = None;
        let mut payloads = Vec::new();
        match action.disposition {
            JobResultDisposition::Apply => {
                let validation = action.validation.ok_or(BackgroundSchedulerError::Store)?;
                terminal.terminal = Some(Box::new(JobTerminalAudit {
                    outcome: JobTerminalOutcome::Succeeded,
                    reason: JobTerminalReason::Completed,
                    result_ref: Some(validation.validation_revision_id.to_string()),
                }));
                payloads.push(JournalPayload::GlobalSupportValidationRecorded(Box::new(
                    validation,
                )));
            }
            JobResultDisposition::StaleAudit(audit) => {
                terminal.state = JobStatus::Failed;
                terminal.terminal = Some(Box::new(JobTerminalAudit {
                    outcome: JobTerminalOutcome::Failed,
                    reason: JobTerminalReason::StaleGeneration,
                    result_ref: Some(job.target_revision.clone()),
                }));
                payloads.push(JournalPayload::StaleGenerationAudit(audit));
            }
        }
        payloads.push(JournalPayload::JobState(terminal));
        let occurred_at_us = now_us()?;
        let events = payloads
            .into_iter()
            .map(|payload| JournalEventDraft {
                occurred_at_us,
                source_kind: SourceKind::System,
                scope: EventScope::default(),
                causation_id: None,
                correlation_id: None,
                effective_config_hash: job.config_hash,
                algorithm_revision: job.algorithm_revision.clone(),
                payload,
            })
            .collect();
        let command = JournalCommand::new(CommandId::new_v7(), events)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(outcome) => Ok(usize::from(!outcome.replayed)),
            Err(WriterActorError::StaleFrontier) => Ok(0),
            Err(error) => Err(map_writer(error)),
        }
    }

    async fn run_capture_reconciliation(
        &self,
        mut claimed: ClaimedJob,
    ) -> Result<BackgroundProgress, BackgroundSchedulerError> {
        let report_guard = claimed
            .report
            .take()
            .ok_or(BackgroundSchedulerError::Store)?;
        let observation_id = SourceObservationId::from_str(&claimed.job.target_revision)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let expected_kind = match claimed.job.kind.as_str() {
            "physical_normalization" => DirtyTargetKind::PhysicalNormalization,
            "capture_reconciliation" => DirtyTargetKind::CaptureReconciliation,
            _ => return Err(BackgroundSchedulerError::Store),
        };
        let frontier = claimed
            .snapshot
            .reconciliation_frontier_for_observations(&[observation_id])
            .map_err(|_| BackgroundSchedulerError::Store)?;
        if frontier.items.is_empty() {
            return self
                .finish_job(
                    &claimed.job,
                    claimed.snapshot.frontier,
                    JobTerminalOutcome::Succeeded,
                    JobTerminalReason::Completed,
                )
                .await;
        }
        let Some(item) = frontier.items.iter().find(|item| {
            item.target_kind == expected_kind
                && item.source_event_seq == claimed.job.target_watermark
                && item.target_id == claimed.job.target_revision
        }) else {
            return self
                .finish_job(
                    &claimed.job,
                    claimed.snapshot.frontier,
                    JobTerminalOutcome::Failed,
                    JobTerminalReason::StaleGeneration,
                )
                .await;
        };
        if claimed.job.algorithm_revision != CAPTURE_ALGORITHM_REVISION
            || claimed.job.config_hash != self.runtime.effective_config_hash
        {
            return self
                .finish_job(
                    &claimed.job,
                    claimed.snapshot.frontier,
                    JobTerminalOutcome::Failed,
                    JobTerminalReason::Unsupported,
                )
                .await;
        }
        let Some(report) = report_guard
            .as_ref()
            .filter(|report| capture_item_manifest_matches(item, report))
        else {
            return Err(BackgroundSchedulerError::Store);
        };
        let reconciliation = reconcile_observations_once(
            ReconcileInput {
                runtime_snapshot: self.runtime.clone(),
                adapter_manifests: vec![report.manifest().clone()],
                liveness: Vec::new(),
                reconciled_gaps: Vec::new(),
                reconciled_outages: Vec::new(),
                independent_source_reconciliations: Vec::new(),
                effective_config_hash: self.runtime.effective_config_hash,
                algorithm_revision: CAPTURE_ALGORITHM_REVISION.into(),
                occurred_at_us: now_us()?,
                max_items: 1,
            },
            &self.writer,
            &[observation_id],
        )
        .await;
        drop(report_guard);
        let snapshot = self.writer.project().await.map_err(map_writer)?;
        let view = RuntimeSchedulerView::from_snapshot(&snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let current = view
            .jobs
            .into_iter()
            .find(|job| {
                job.job_id == claimed.job.job_id
                    && job.state == JobStatus::Leased
                    && job.attempt == claimed.job.attempt
                    && job.target_generation == claimed.job.target_generation
            })
            .ok_or(BackgroundSchedulerError::Store)?;
        let active = snapshot
            .reconciliation_frontier_for_observations(&[observation_id])
            .map_err(|_| BackgroundSchedulerError::Store)?
            .items;
        let (outcome, reason) = if active.is_empty() {
            (JobTerminalOutcome::Succeeded, JobTerminalReason::Completed)
        } else {
            match reconciliation {
                Ok(_) => (
                    JobTerminalOutcome::Failed,
                    JobTerminalReason::SourceUnavailable,
                ),
                Err(ReconcileError::StaleFrontier) => (
                    JobTerminalOutcome::Failed,
                    JobTerminalReason::StaleGeneration,
                ),
                Err(
                    ReconcileError::InvalidInput
                    | ReconcileError::Spool
                    | ReconcileError::Projection
                    | ReconcileError::Manifest
                    | ReconcileError::Domain
                    | ReconcileError::Commit
                    | ReconcileError::Acknowledgement,
                ) => (
                    JobTerminalOutcome::Failed,
                    JobTerminalReason::IntegrityFailure,
                ),
            }
        };
        self.finish_job(&current, snapshot.frontier, outcome, reason)
            .await
    }

    async fn finish_job(
        &self,
        job: &DurableJob,
        frontier: u64,
        outcome: JobTerminalOutcome,
        reason: JobTerminalReason,
    ) -> Result<BackgroundProgress, BackgroundSchedulerError> {
        if job.state != JobStatus::Leased || job.terminal.is_some() {
            return Err(BackgroundSchedulerError::Store);
        }
        let occurred_at_us = now_us()?;
        let mut terminal = job.clone();
        terminal.state = match outcome {
            JobTerminalOutcome::Succeeded => JobStatus::Succeeded,
            JobTerminalOutcome::Failed => JobStatus::Failed,
        };
        terminal.lease_until_us = None;
        terminal.backoff_until_us = None;
        terminal.terminal = Some(Box::new(JobTerminalAudit {
            outcome,
            reason,
            result_ref: Some(job.target_revision.clone()),
        }));
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                occurred_at_us,
                job.config_hash,
                job.algorithm_revision.clone(),
                JournalPayload::JobState(terminal),
            )],
        )
        .map_err(|_| BackgroundSchedulerError::Store)?;
        match self
            .writer
            .commit_if_frontier(command, occurred_at_us, frontier)
            .await
        {
            Ok(outcome) => Ok(BackgroundProgress {
                completed: usize::from(!outcome.replayed),
                retryable: false,
            }),
            Err(WriterActorError::StaleFrontier) => Ok(BackgroundProgress {
                completed: 0,
                retryable: true,
            }),
            Err(error) => Err(map_writer(error)),
        }
    }

    async fn claim_job(
        &self,
        selected: &DurableJob,
    ) -> Result<Option<ClaimedJob>, BackgroundSchedulerError> {
        let report = if is_capture_job(selected) {
            Some(Arc::clone(&self.report).read_owned().await)
        } else {
            None
        };
        let snapshot = self.writer.project().await.map_err(map_writer)?;
        let view = RuntimeSchedulerView::from_snapshot(&snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let Some(current) = view.jobs.iter().find(|job| job.job_id == selected.job_id) else {
            return Err(BackgroundSchedulerError::Store);
        };
        if current.state != JobStatus::Queued
            || current.target_generation != selected.target_generation
        {
            return Ok(None);
        }
        if let Some(report) = report.as_ref() {
            let observation_id = SourceObservationId::from_str(&current.target_revision)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            let expected_kind = match current.kind.as_str() {
                "physical_normalization" => DirtyTargetKind::PhysicalNormalization,
                "capture_reconciliation" => DirtyTargetKind::CaptureReconciliation,
                _ => return Err(BackgroundSchedulerError::Store),
            };
            let frontier = snapshot
                .reconciliation_frontier_for_observations(&[observation_id])
                .map_err(|_| BackgroundSchedulerError::Store)?;
            if !capture_job_is_current(current, self.runtime.effective_config_hash) {
                return Ok(None);
            }
            if !frontier.items.is_empty()
                && !report.as_ref().is_some_and(|report| {
                    frontier.items.iter().any(|item| {
                        item.target_kind == expected_kind
                            && item.target_id == current.target_revision
                            && item.source_event_seq == current.target_watermark
                            && capture_item_manifest_matches(item, report)
                    })
                })
            {
                return Ok(None);
            }
        }
        let occurred_at_us = now_us()?;
        let lease_until_us = occurred_at_us
            .checked_add(
                i64::try_from(current.budget.max_wall_time_ms.min(5_000))
                    .map_err(|_| BackgroundSchedulerError::Store)?
                    .saturating_mul(1_000),
            )
            .ok_or(BackgroundSchedulerError::Store)?;
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft {
                occurred_at_us,
                source_kind: SourceKind::System,
                scope: EventScope::default(),
                causation_id: None,
                correlation_id: None,
                effective_config_hash: current.config_hash,
                algorithm_revision: current.algorithm_revision.clone(),
                payload: JournalPayload::JobLease(JobLease {
                    job_id: current.job_id,
                    target_generation: current.target_generation,
                    attempt: current
                        .attempt
                        .checked_add(1)
                        .ok_or(BackgroundSchedulerError::Store)?,
                    lease_until_us,
                }),
            }],
        )
        .map_err(|_| BackgroundSchedulerError::Store)?;
        match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(_) => {
                let snapshot = self.writer.project().await.map_err(map_writer)?;
                let view = RuntimeSchedulerView::from_snapshot(&snapshot)
                    .map_err(|_| BackgroundSchedulerError::Store)?;
                let job = view
                    .jobs
                    .into_iter()
                    .find(|job| job.job_id == selected.job_id)
                    .filter(|job| {
                        job.state == JobStatus::Leased
                            && job.target_generation == selected.target_generation
                    })
                    .ok_or(BackgroundSchedulerError::Store)?;
                Ok(Some(ClaimedJob {
                    snapshot,
                    job,
                    report,
                }))
            }
            Err(WriterActorError::StaleFrontier) => Ok(None),
            Err(error) => Err(map_writer(error)),
        }
    }

    async fn fail_stale(
        &self,
        job: &DurableJob,
        frontier: u64,
    ) -> Result<(), BackgroundSchedulerError> {
        let mut failed = job.clone();
        failed.state = JobStatus::Failed;
        failed.lease_until_us = None;
        failed.terminal = Some(Box::new(JobTerminalAudit {
            outcome: JobTerminalOutcome::Failed,
            reason: JobTerminalReason::StaleGeneration,
            result_ref: Some(job.target_revision.clone()),
        }));
        let occurred_at_us = now_us()?;
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft {
                occurred_at_us,
                source_kind: SourceKind::System,
                scope: EventScope::default(),
                causation_id: None,
                correlation_id: None,
                effective_config_hash: job.config_hash,
                algorithm_revision: job.algorithm_revision.clone(),
                payload: JournalPayload::JobState(failed),
            }],
        )
        .map_err(|_| BackgroundSchedulerError::Store)?;
        match self
            .writer
            .commit_if_frontier(command, occurred_at_us, frontier)
            .await
        {
            Ok(_) | Err(WriterActorError::StaleFrontier) => Ok(()),
            Err(error) => Err(map_writer(error)),
        }
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() || shutdown.changed().await.is_err() {
            return;
        }
    }
}

fn import_job_is_current(job: &DurableJob, effective_config_hash: [u8; 32]) -> bool {
    job.kind == "session_import_v1"
        && job.algorithm_revision == "session_import_v1"
        && job.model_id.is_none()
        && job.config_hash == effective_config_hash
        && job.budget == session_import_job_budget()
}

fn capture_job_budget() -> JobBudget {
    JobBudget {
        max_items: 1,
        max_bytes: None,
        max_input_tokens: None,
        max_output_tokens: None,
        max_calls: None,
        max_wall_time_ms: 250,
    }
}

fn capture_job_is_current(job: &DurableJob, effective_config_hash: [u8; 32]) -> bool {
    is_capture_job(job)
        && job.algorithm_revision == CAPTURE_ALGORITHM_REVISION
        && job.model_id.is_none()
        && job.config_hash == effective_config_hash
        && job.budget == capture_job_budget()
}

fn capture_target_covered(
    view: &RuntimeSchedulerView,
    dirty: &evertrace_store::DirtyTarget,
    effective_config_hash: [u8; 32],
) -> bool {
    let kind = match dirty.target_kind {
        DirtyTargetKind::PhysicalNormalization => "physical_normalization",
        DirtyTargetKind::CaptureReconciliation => "capture_reconciliation",
        _ => return false,
    };
    let idempotency_key = format!("{kind}:{}", dirty.target_id);
    let matching = |job: &DurableJob| {
        job.kind == kind
            && job.idempotency_key == idempotency_key
            && job.target_revision == dirty.target_id
            && job.target_watermark == dirty.source_watermark
            && job.target_generation == dirty.source_watermark.max(1)
            && capture_job_is_current(job, effective_config_hash)
    };
    if view.jobs.iter().any(|job| {
        is_capture_job(job)
            && job.target_revision == dirty.target_id
            && matches!(job.state, JobStatus::Queued | JobStatus::Leased)
            && !matching(job)
    }) {
        return false;
    }
    view.jobs.iter().any(matching)
}

fn is_capture_job(job: &DurableJob) -> bool {
    matches!(
        job.kind.as_str(),
        "physical_normalization" | "capture_reconciliation"
    )
}

fn capture_item_manifest_matches(
    item: &evertrace_store::ReconciliationWorkItem,
    report: &HostProbeReport,
) -> bool {
    if report.manifest().validate().is_err() {
        return false;
    }
    let manifest_id = report.manifest().adapter_manifest_id.as_str();
    let receipts = item.dependencies.iter().filter_map(|dependency| {
        if let JournalPayload::SourceReceiptRecorded(receipt) = &dependency.payload {
            Some(receipt.adapter_manifest_ref.as_str())
        } else {
            None
        }
    });
    let mut count = 0_usize;
    for receipt_manifest in receipts {
        count += 1;
        if receipt_manifest != manifest_id {
            return false;
        }
    }
    count != 0
}

pub fn select_jobs(
    view: &RuntimeSchedulerView,
    capture_state: CaptureAdmissionState,
) -> Result<Vec<ScheduledJob>, BackgroundSchedulerError> {
    let mut active = BTreeMap::<(String, String), DurableJob>::new();
    for job in view
        .jobs
        .iter()
        .filter(|job| job.state == JobStatus::Queued && executable_job(job))
    {
        let key = (job.kind.clone(), job.idempotency_key.clone());
        if let Some(existing) = active.get(&key) {
            if existing.target_generation == job.target_generation {
                return Err(BackgroundSchedulerError::Store);
            }
            if existing.target_generation > job.target_generation {
                continue;
            }
        }
        active.insert(key, job.clone());
    }
    let pause_optional = capture_state != CaptureAdmissionState::Normal;
    let mut candidates = active
        .into_values()
        .filter_map(|job| {
            let lane = job_lane(&job);
            (!pause_optional
                || lane == BackgroundLane::Critical
                || job.kind == "objects_projection")
                .then_some(ScheduledJob { lane, job })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.lane
            .cmp(&right.lane)
            .then_with(|| left.job.priority.cmp(&right.job.priority))
            .then_with(|| left.job.idempotency_key.cmp(&right.job.idempotency_key))
            .then_with(|| left.job.job_id.cmp(&right.job.job_id))
    });
    let mut lane_counts = BTreeMap::new();
    let mut selected = Vec::new();
    for candidate in candidates {
        let count = lane_counts.entry(candidate.lane).or_insert(0_usize);
        if *count == PER_LANE_LIMIT {
            continue;
        }
        *count += 1;
        selected.push(candidate);
        if selected.len() == TOTAL_LIMIT {
            break;
        }
    }
    Ok(selected)
}

fn executable_job(job: &DurableJob) -> bool {
    matches!(
        job.kind.as_str(),
        "support_closure"
            | "objects_projection"
            | "physical_normalization"
            | "capture_reconciliation"
            | "session_import_v1"
            | "semantic_synthesis_v1"
    )
}

fn job_lane(job: &DurableJob) -> BackgroundLane {
    match job.kind.as_str() {
        "support_closure" | "capture_reconciliation" => BackgroundLane::Critical,
        "objects_projection" | "physical_normalization" => BackgroundLane::Deterministic,
        "session_import_v1" => BackgroundLane::Import,
        "semantic_synthesis_v1" => BackgroundLane::Synthesis,
        _ => BackgroundLane::Maintenance,
    }
}

fn support_context(
    snapshot: &evertrace_store::ProjectionSnapshot,
    job: &DurableJob,
) -> Result<(GlobalSuccessorSupportContract, GlobalSupportValidationEvent), BackgroundSchedulerError>
{
    let mut contracts = Vec::new();
    let mut validations = Vec::new();
    for row in snapshot.data_rows() {
        let Some(json) = row.payload_json.as_deref() else {
            return Err(BackgroundSchedulerError::Store);
        };
        let payload: JournalPayload =
            serde_json::from_str(json).map_err(|_| BackgroundSchedulerError::Store)?;
        match payload {
            JournalPayload::GlobalSupportContractRecorded(value)
                if value.successor_revision_or_membership_ref == job.target_revision =>
            {
                contracts.push(*value);
            }
            JournalPayload::GlobalSupportValidationRecorded(value)
                if value.successor_ref == job.target_revision =>
            {
                validations.push(*value);
            }
            _ => {}
        }
    }
    let [contract] = contracts.as_slice() else {
        return Err(BackgroundSchedulerError::Store);
    };
    validations.sort_by_key(|value| value.dependency_generation);
    let current = validations.last().ok_or(BackgroundSchedulerError::Store)?;
    if validations.len() > 1
        && validations[validations.len() - 2].dependency_generation == current.dependency_generation
    {
        return Err(BackgroundSchedulerError::Store);
    }
    Ok((contract.clone(), current.clone()))
}

fn now_us() -> Result<i64, BackgroundSchedulerError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| BackgroundSchedulerError::Store)?;
    i64::try_from(duration.as_micros()).map_err(|_| BackgroundSchedulerError::Store)
}

fn map_writer(error: WriterActorError) -> BackgroundSchedulerError {
    match error {
        WriterActorError::Stopped => BackgroundSchedulerError::Writer,
        _ => BackgroundSchedulerError::Store,
    }
}
