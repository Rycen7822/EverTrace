//! Filesystem artifacts use the existing reconciliation reduction and ACK gate.
use super::*;
use crate::capture::{
    absent_capture_artifact_was_propagated, capture_artifact_descriptor, capture_artifact_target,
    pending_capture_artifacts, reconcile_artifact_once,
};
use evertrace_store::{ReconciliationArtifactContext, ReconciliationArtifactOwnership};

pub(super) const CAPTURE_ARTIFACT_JOB_KIND: &str = "capture_artifact_reconciliation_v1";
pub(super) const ARTIFACT_POLL_INTERVAL: Duration = Duration::from_secs(30);

fn retry_delay_us(attempt: u32) -> i64 {
    // Requeue and lease each advance the attempt. Back off 30s, 60s, ...,
    // capped at ten minutes without giving up on a transient lock/frontier.
    let exponent = ((attempt / 2).max(1) - 1).min(5);
    (30_000_000_i64 * (1_i64 << exponent)).min(600_000_000)
}

fn retry_attempt(attempt: u32) -> Result<u32, BackgroundSchedulerError> {
    // Reserve the following lease increment before persisting another queue.
    attempt
        .checked_add(2)
        .map(|leased| leased - 1)
        .ok_or(BackgroundSchedulerError::Store)
}

fn budget() -> JobBudget {
    JobBudget {
        max_items: 16,
        max_bytes: None,
        max_input_tokens: None,
        max_output_tokens: None,
        max_calls: None,
        max_wall_time_ms: 250,
    }
}

pub(super) fn job_is_current(job: &DurableJob, config: [u8; 32]) -> bool {
    job.algorithm_revision == CAPTURE_ARTIFACT_JOB_KIND
        && job.config_hash == config
        && job.model_id.is_none()
        && job.budget == budget()
        && job.target_generation == job.target_watermark.max(1)
        && job.idempotency_key == format!("{CAPTURE_ARTIFACT_JOB_KIND}:{}", job.target_revision)
}

// Reconciliation's own Gap/Lane/Receipt successors do not wake themselves.
// New imported source facts are the attribution/lifecycle input frontier.
fn source_frontier(context: &ReconciliationArtifactContext) -> u64 {
    context
        .dependencies
        .iter()
        .filter(|dependency| matches!(dependency.payload, JournalPayload::SourceReceiptRecorded(_)))
        .map(|dependency| dependency.source_event_seq)
        .max()
        .unwrap_or(0)
}

fn missing_manifest(
    context: &ReconciliationArtifactContext,
    report: Option<&HostProbeReport>,
) -> bool {
    context
        .dependencies
        .iter()
        .any(|dependency| match &dependency.payload {
            JournalPayload::SourceReceiptRecorded(receipt) if receipt.lifecycle.is_some() => report
                .is_none_or(|report| {
                    report.manifest().adapter_manifest_id != receipt.adapter_manifest_ref
                }),
            _ => false,
        })
}

impl BackgroundScheduler {
    pub(super) async fn seed_capture_artifacts(
        &self,
        snapshot: &evertrace_store::ProjectionSnapshot,
        view: &RuntimeSchedulerView,
    ) -> Result<bool, BackgroundSchedulerError> {
        let start = {
            let mut scan = self.artifact_scan.lock().await;
            if scan.2 && tokio::time::Instant::now() < scan.0 {
                return Ok(false);
            }
            scan.0 = tokio::time::Instant::now() + ARTIFACT_POLL_INTERVAL;
            let start = scan.1;
            scan.1 = scan.1.wrapping_add(1);
            start
        };
        let descriptors = pending_capture_artifacts(&self.runtime, start)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        self.artifact_scan.lock().await.2 = !descriptors.is_empty();
        if descriptors.is_empty() {
            return Ok(false);
        }
        let contexts = snapshot
            .reconciliation_artifact_context(&descriptors, descriptors.len())
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let now = now_us()?;
        let report = self.report.read().await.clone();
        let mut events = Vec::new();
        let mut selected_targets = BTreeSet::new();
        for context in contexts.contexts {
            if context.ownership == ReconciliationArtifactOwnership::Conflict {
                return Err(BackgroundSchedulerError::Store);
            }
            let watermark = source_frontier(&context);
            let target = capture_artifact_target(&context.descriptor)
                .ok_or(BackgroundSchedulerError::Store)?;
            if !selected_targets.insert(target.clone()) {
                continue;
            }
            let prior = view
                .jobs
                .iter()
                .filter(|job| {
                    job.kind == CAPTURE_ARTIFACT_JOB_KIND && job.target_revision == target
                })
                .max_by_key(|job| {
                    (
                        job.target_watermark == watermark
                            && job_is_current(job, self.runtime.effective_config_hash),
                        job.job_id,
                    )
                });
            let job = if let Some(prior) = prior.filter(|job| {
                job.target_watermark == watermark
                    && job_is_current(job, self.runtime.effective_config_hash)
            }) {
                if matches!(prior.state, JobStatus::Queued | JobStatus::Leased) {
                    continue;
                }
                let retry = prior.state == JobStatus::Succeeded
                    || prior
                        .terminal
                        .as_deref()
                        .is_some_and(|audit| audit.reason == JobTerminalReason::Unsupported)
                        && !missing_manifest(&context, report.as_ref())
                    || prior.state == JobStatus::Failed
                        && prior.backoff_until_us.is_some_and(|due| due <= now);
                if !retry {
                    continue;
                }
                let mut job = prior.clone();
                job.state = JobStatus::Queued;
                job.attempt = retry_attempt(prior.attempt)?;
                job.backoff_until_us = None;
                job.terminal = None;
                job
            } else {
                if prior
                    .is_some_and(|job| matches!(job.state, JobStatus::Queued | JobStatus::Leased))
                {
                    continue;
                }
                DurableJob {
                    job_id: JobId::new_v7(),
                    idempotency_key: format!("{CAPTURE_ARTIFACT_JOB_KIND}:{target}"),
                    target_revision: target,
                    target_watermark: watermark,
                    target_generation: watermark.max(1),
                    kind: CAPTURE_ARTIFACT_JOB_KIND.into(),
                    algorithm_revision: CAPTURE_ARTIFACT_JOB_KIND.into(),
                    model_id: None,
                    priority: 0,
                    state: JobStatus::Queued,
                    attempt: 1,
                    backoff_until_us: None,
                    config_hash: self.runtime.effective_config_hash,
                    budget: budget(),
                    terminal: None,
                    lease_until_us: None,
                }
            };
            events.push(JournalEventDraft::runtime(
                now,
                job.config_hash,
                job.algorithm_revision.clone(),
                JournalPayload::JobState(job),
            ));
            if events.len() == PER_LANE_LIMIT {
                break;
            }
        }
        if events.is_empty() {
            return Ok(false);
        }
        let command = JournalCommand::new(CommandId::new_v7(), events)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        match self
            .writer
            .commit_if_frontier(command, now, snapshot.frontier)
            .await
        {
            Ok(_) => Ok(true),
            Err(WriterActorError::StaleFrontier) => Ok(false),
            Err(error) => Err(map_writer(error)),
        }
    }

    pub(super) async fn run_capture_artifact(
        &self,
        claimed: ClaimedJob,
    ) -> Result<BackgroundProgress, BackgroundSchedulerError> {
        let _dispatch = match &self.dispatch {
            Some(gate) => Some(gate.read().await),
            None => None,
        };
        let descriptor = capture_artifact_descriptor(&self.runtime, &claimed.job.target_revision)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let mut manifest_missing = false;
        let result = if let Some(descriptor) = &descriptor {
            let context = self
                .writer
                .reconciliation_artifact_context(vec![descriptor.clone()], 1)
                .await
                .map_err(map_writer)?;
            let frontier = context.frontier;
            let context = context
                .contexts
                .first()
                .ok_or(BackgroundSchedulerError::Store)?;
            if context.ownership == ReconciliationArtifactOwnership::Conflict {
                return Err(BackgroundSchedulerError::Store);
            }
            // Copy only the current manifest; never hold a report lock through
            // writer/ACK or lend a weak delivery lifecycle authority.
            if source_frontier(context) != claimed.job.target_watermark {
                return self
                    .finish_job(
                        &claimed.job,
                        frontier,
                        JobTerminalOutcome::Failed,
                        JobTerminalReason::StaleGeneration,
                    )
                    .await;
            }
            let report = self.report.read().await.clone();
            manifest_missing = missing_manifest(context, report.as_ref());
            reconcile_artifact_once(
                ReconcileInput {
                    runtime_snapshot: self.runtime.clone(),
                    adapter_manifests: report
                        .into_iter()
                        .map(|report| report.manifest().clone())
                        .collect(),
                    liveness: Vec::new(),
                    reconciled_gaps: Vec::new(),
                    reconciled_outages: Vec::new(),
                    independent_source_reconciliations: Vec::new(),
                    effective_config_hash: self.runtime.effective_config_hash,
                    algorithm_revision: CAPTURE_ALGORITHM_REVISION.into(),
                    occurred_at_us: now_us()?,
                    max_items: 16,
                },
                &self.writer,
                descriptor,
            )
            .await
        } else {
            if !absent_capture_artifact_was_propagated(&self.writer, &claimed.job.target_revision)
                .await
                .map_err(|_| BackgroundSchedulerError::Store)?
            {
                return Err(BackgroundSchedulerError::Store);
            }
            Ok(crate::capture::ReconcileProgress::default())
        };
        let retry_reason = match result {
            Ok(_) => None,
            Err(ReconcileError::StaleFrontier) => Some(JobTerminalReason::StaleGeneration),
            Err(ReconcileError::Busy) => Some(JobTerminalReason::SourceUnavailable),
            // Missing manifests were retained without creating a receipt by
            // the original reduction. Invalid contracts and real I/O stay fatal.
            Err(_) => return Err(BackgroundSchedulerError::Store),
        };
        let remaining = capture_artifact_descriptor(&self.runtime, &claimed.job.target_revision)
            .map_err(|_| BackgroundSchedulerError::Store)?
            .is_some();
        let snapshot = self.writer.project().await.map_err(map_writer)?;
        let view = RuntimeSchedulerView::from_snapshot(&snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let current = view
            .jobs
            .iter()
            .find(|job| {
                job.job_id == claimed.job.job_id
                    && job.state == JobStatus::Leased
                    && job.attempt == claimed.job.attempt
            })
            .ok_or(BackgroundSchedulerError::Store)?;
        let mut terminal = current.clone();
        terminal.state = if remaining || retry_reason.is_some() {
            JobStatus::Failed
        } else {
            JobStatus::Succeeded
        };
        terminal.lease_until_us = None;
        terminal.backoff_until_us = retry_reason
            .as_ref()
            .map(|_| {
                now_us()?
                    .checked_add(retry_delay_us(terminal.attempt))
                    .ok_or(BackgroundSchedulerError::Store)
            })
            .transpose()?;
        terminal.terminal = Some(Box::new(JobTerminalAudit {
            outcome: if terminal.state == JobStatus::Succeeded {
                JobTerminalOutcome::Succeeded
            } else {
                JobTerminalOutcome::Failed
            },
            reason: retry_reason.unwrap_or(if remaining {
                if manifest_missing {
                    JobTerminalReason::Unsupported
                } else {
                    JobTerminalReason::SourceUnavailable
                }
            } else {
                JobTerminalReason::Completed
            }),
            result_ref: Some(terminal.target_revision.clone()),
        }));
        let now = now_us()?;
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                now,
                terminal.config_hash,
                terminal.algorithm_revision.clone(),
                JournalPayload::JobState(terminal),
            )],
        )
        .map_err(|_| BackgroundSchedulerError::Store)?;
        match self
            .writer
            .commit_if_frontier(command, now, snapshot.frontier)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_retries_cap_delay_not_monotonic_attempts() {
        assert_eq!(
            [2, 4, 6, 8, 10, 12, u32::MAX].map(retry_delay_us),
            [30, 60, 120, 240, 480, 600, 600].map(|seconds| seconds * 1_000_000)
        );
        assert_eq!(retry_attempt(6).unwrap(), 7);
        assert_eq!(retry_attempt(u32::MAX - 2).unwrap(), u32::MAX - 1);
        assert!(retry_attempt(u32::MAX - 1).is_err());
        assert!(retry_attempt(u32::MAX).is_err());
    }
}
