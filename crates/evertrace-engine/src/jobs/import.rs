//! One bounded checkpoint of the durable Codex session import job.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use evertrace_capture::{
    CaptureOutcome, CaptureRecordInput, CaptureRuntime, ConfinedEntryType, ConfinedFileIdentity,
    ConfinedRoot, DeviceKey, DeviceKeyStore, DurableSpool, RuntimeSnapshot, protect,
};
use evertrace_codex::{
    HostProbeReport, adapter_manifest::SessionCatalogRootKind,
    source_catalog::qualify_requested_session_root,
};
use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceByteRange,
        EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength, ObservationRole,
        SourceInstanceId, SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole,
        UnsupportedRecordClassification, source_observation_id,
    },
    ids::{CommandId, RequestId},
};
use evertrace_store::{
    BodyStateReason, DurableJob, EventScope, JobLease, JobStatus, JobTerminalAudit,
    JobTerminalOutcome, JobTerminalReason, JournalCommand, JournalEventDraft, JournalPayload,
    SessionBodyState, SessionImportContext, SessionImportCurrent, SessionImportEvent,
    SessionImportEventKind, SessionImportPrefixRecord, SessionImportPrefixRequest,
    SourceIngestWatermark, SourceKind,
};
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

use crate::{
    EvidenceIngestor, WriterHandle,
    repository::SESSION_ROOT_PROBE_BUDGET,
    session_import::{MAX_RECORD_BYTES, session_source_fingerprint},
};

const CHUNK_BYTES: usize = 16 * 1024;
const MAX_RECORDS: usize = 16;
const PREFIX_TAG: &str = "session_import_confirmed_prefix";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionImportBudget {
    pub max_bytes: usize,
    pub max_records: usize,
    pub max_work_time: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionImportProgress {
    pub records: usize,
    pub bytes: usize,
    pub completed: bool,
}

struct ImportHandoffTarget {
    watermark: Option<SourceIngestWatermark>,
    body_state: SessionBodyState,
    reason: BodyStateReason,
    synced_frontier: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionImportError {
    #[error("session import authority is unavailable")]
    Unavailable,
    #[error("session import source changed")]
    Changed,
    #[error("session import record is unsupported")]
    Unsupported,
    #[error("session import budget is exhausted")]
    Budget,
    #[error("session import persistence failed")]
    Persistence,
}

#[derive(Clone)]
pub struct SessionImportWorker {
    writer: WriterHandle,
    runtime: RuntimeSnapshot,
    report: Arc<RwLock<Option<HostProbeReport>>>,
    verified_prefix: Arc<Mutex<BTreeMap<String, VerifiedPrefix>>>,
    next_session: Arc<Mutex<Option<String>>>,
    operation_config: Option<Arc<evertrace_domain::config::EffectiveConfig>>,
    config: Option<Arc<crate::ConfigReloadService>>,
    #[cfg(test)]
    claim_delay: Duration,
    #[cfg(test)]
    terminal_handoff_pause: Option<Arc<tokio::sync::Notify>>,
}

#[derive(Clone)]
struct ClaimedImportLease {
    lease: JobLease,
    deadline: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedPrefix {
    source_key: String,
    source_revision: SourceRevision,
    identity: ConfinedFileIdentity,
    protection_key: DeviceKey,
    config_hash: [u8; 32],
    main: Option<VerifiedRangeProof>,
    earlier: Option<VerifiedRangeProof>,
    next_body: ImportRangeKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedRangeProof {
    chain_start: u64,
    target_end: u64,
    target_digest: String,
    end: u64,
    digest: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImportRangeKind {
    Whole,
    HistoricalPrefix,
    ProspectiveSuffix,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProofLeg {
    Main,
    Earlier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ImportRange {
    kind: ImportRangeKind,
    start: u64,
    end: u64,
    chain_start: u64,
    committed_end: u64,
    committed_digest: Option<String>,
}

fn proof_leg(kind: ImportRangeKind) -> ProofLeg {
    if kind == ImportRangeKind::HistoricalPrefix {
        ProofLeg::Earlier
    } else {
        ProofLeg::Main
    }
}

fn verified_leg(slot: &VerifiedPrefix, leg: ProofLeg) -> &Option<VerifiedRangeProof> {
    match leg {
        ProofLeg::Main => &slot.main,
        ProofLeg::Earlier => &slot.earlier,
    }
}

fn verified_leg_mut(slot: &mut VerifiedPrefix, leg: ProofLeg) -> &mut Option<VerifiedRangeProof> {
    match leg {
        ProofLeg::Main => &mut slot.main,
        ProofLeg::Earlier => &mut slot.earlier,
    }
}

fn default_body_turn(current: &SessionImportCurrent) -> ImportRangeKind {
    if current.metadata.prospective_origin.is_some() {
        ImportRangeKind::HistoricalPrefix
    } else {
        ImportRangeKind::Whole
    }
}

impl SessionImportWorker {
    pub(crate) fn with_config(mut self, config: Arc<crate::ConfigReloadService>) -> Self {
        self.config = Some(config);
        self
    }

    pub fn for_config(
        &self,
        config: Arc<evertrace_domain::config::EffectiveConfig>,
    ) -> Result<Self, SessionImportError> {
        let mut operation = self.clone();
        operation.runtime = crate::config_reload::operation_runtime(&self.runtime, &config)
            .map_err(|_| SessionImportError::Unavailable)?;
        operation.operation_config = Some(config);
        Ok(operation)
    }

    pub fn new(
        writer: WriterHandle,
        runtime: RuntimeSnapshot,
        report: Arc<RwLock<Option<HostProbeReport>>>,
    ) -> Result<Self, SessionImportError> {
        runtime
            .validate()
            .map_err(|_| SessionImportError::Persistence)?;
        Ok(Self {
            writer,
            runtime,
            report,
            verified_prefix: Arc::new(Mutex::new(BTreeMap::new())),
            #[cfg(test)]
            claim_delay: Duration::ZERO,
            #[cfg(test)]
            terminal_handoff_pause: None,
            next_session: Arc::new(Mutex::new(None)),
            operation_config: None,
            config: None,
        })
    }

    pub async fn process_checkpoint(
        &self,
        session_id: &str,
        budget: SessionImportBudget,
    ) -> Result<SessionImportProgress, SessionImportError> {
        self.process_checkpoint_with_context(session_id, budget, None)
            .await
    }

    async fn process_checkpoint_with_context(
        &self,
        session_id: &str,
        budget: SessionImportBudget,
        context: Option<SessionImportContext>,
    ) -> Result<SessionImportProgress, SessionImportError> {
        if budget.max_bytes == 0
            || budget.max_records == 0
            || budget.max_records > MAX_RECORDS
            || budget.max_work_time.is_zero()
        {
            return Err(SessionImportError::Budget);
        }
        let budget = SessionImportBudget {
            max_work_time: budget.max_work_time.min(Duration::from_millis(250)),
            ..budget
        };
        let context = match context {
            Some(context) => context,
            None => self.context(session_id).await?,
        };
        let report = self
            .report
            .read()
            .await
            .clone()
            .ok_or(SessionImportError::Unavailable)?;
        let current = &context.current;
        if crate::session_import::preflight_import_context(
            &self.writer,
            &report,
            &context,
            self.runtime.effective_config_hash,
        )
        .await
        .map_err(|_| SessionImportError::Unavailable)?
        {
            return Ok(SessionImportProgress {
                records: 0,
                bytes: 0,
                completed: false,
            });
        }
        let proofs = required_import_proofs(&context)?;
        let pending_ranges = import_ranges(&context)?;
        let terminal = finished_import_state(&context)?;
        if proofs.is_empty() && pending_ranges.is_empty() && terminal.is_none() {
            return Ok(SessionImportProgress {
                records: 0,
                bytes: 0,
                completed: false,
            });
        }
        let (root, relative, identity) = match self.authorized_source(
            &report,
            &context,
            Instant::now() + SESSION_ROOT_PROBE_BUDGET,
        ) {
            Ok(value) => value,
            Err(SessionImportError::Changed) => {
                self.advance(
                    current,
                    SessionBodyState::SourceReplaced,
                    BodyStateReason::SourceReplaced,
                )
                .await?;
                return Err(SessionImportError::Changed);
            }
            Err(error) => {
                self.verified_prefix.lock().await.remove(session_id);
                return Err(error);
            }
        };
        let key = DeviceKeyStore::new(self.runtime.device_key_dir.clone())
            .load()
            .map_err(|_| SessionImportError::Persistence)?;
        for proof in &proofs {
            let (ready, proof_bytes) = match self
                .verify_confirmed_range(&context, (&root, &relative, identity), &key, budget, proof)
                .await
            {
                Ok(value) => value,
                Err(SessionImportError::Changed) => {
                    self.mark_source_replaced(current, identity).await?;
                    return Err(SessionImportError::Changed);
                }
                Err(error) => return Err(error),
            };
            // One proof page is one read-only quantum, even if it finishes the
            // selected leg. The next call continues with the other saved leg.
            if !ready || proof_bytes != 0 {
                return Ok(SessionImportProgress {
                    records: 0,
                    bytes: proof_bytes,
                    completed: false,
                });
            }
        }
        let import_range = if pending_ranges.is_empty() {
            None
        } else {
            Some(
                self.choose_import_range(&context, identity, &key, &pending_ranges)
                    .await?,
            )
        };
        let Some(import_range) = import_range else {
            let Some((body_state, reason)) = terminal else {
                return Ok(SessionImportProgress {
                    records: 0,
                    bytes: 0,
                    completed: false,
                });
            };
            // An already-terminal job is never handed off twice.
            if context
                .job
                .as_ref()
                .is_none_or(|job| matches!(job.state, JobStatus::Succeeded | JobStatus::Failed))
            {
                return Ok(SessionImportProgress {
                    records: 0,
                    bytes: 0,
                    completed: true,
                });
            }
            let fresh = self.context(session_id).await?;
            let fresh_report = self
                .report
                .read()
                .await
                .clone()
                .ok_or(SessionImportError::Unavailable)?;
            let (fresh_root, fresh_relative, fresh_identity) = self.authorized_source(
                &fresh_report,
                &fresh,
                Instant::now() + SESSION_ROOT_PROBE_BUDGET,
            )?;
            let fresh_key = DeviceKeyStore::new(self.runtime.device_key_dir.clone())
                .load()
                .map_err(|_| SessionImportError::Persistence)?;
            if fresh.current.metadata != current.metadata
                || fresh.watermark != context.watermark
                || fresh_identity != identity
                || fresh_key != key
                || !import_ranges(&fresh)?.is_empty()
                || finished_import_state(&fresh)? != Some((body_state, reason))
            {
                return Err(SessionImportError::Budget);
            }
            let lease = self.claim_job(&fresh).await?;
            if matches!(
                fresh.current.body_state,
                SessionBodyState::Queued | SessionBodyState::Partial
            ) {
                self.advance(
                    &fresh.current,
                    SessionBodyState::Importing,
                    BodyStateReason::Started,
                )
                .await?;
            }
            self.finish_import_handoff(
                &fresh.current,
                (&fresh_relative, fresh_identity),
                ImportHandoffTarget {
                    watermark: fresh.watermark.clone(),
                    body_state,
                    reason,
                    synced_frontier: None,
                },
                self.writer.subscribe_background_frontier(),
                &lease,
            )
            .await?;
            fresh_root
                .revalidate_file(&fresh_relative, fresh_identity)
                .map_err(map_source_read)?;
            return Ok(SessionImportProgress {
                records: 0,
                bytes: 0,
                completed: true,
            });
        };
        // No report/cache lock crosses a quantum. Re-read all mutable authority
        // and the exact claim frontier after the read-only proof.
        let fresh = self.context(session_id).await?;
        let report = self
            .report
            .read()
            .await
            .clone()
            .ok_or(SessionImportError::Unavailable)?;
        let (root, relative, fresh_identity) =
            self.authorized_source(&report, &fresh, Instant::now() + SESSION_ROOT_PROBE_BUDGET)?;
        let fresh_key = DeviceKeyStore::new(self.runtime.device_key_dir.clone())
            .load()
            .map_err(|_| SessionImportError::Persistence)?;
        let fresh_pending = import_ranges(&fresh)?;
        let fresh_range = if fresh_pending.is_empty() {
            None
        } else {
            Some(
                self.choose_import_range(&fresh, fresh_identity, &fresh_key, &fresh_pending)
                    .await?,
            )
        };
        if fresh.current.metadata != current.metadata
            || fresh.watermark != context.watermark
            || fresh_identity != identity
            || fresh_key != key
            || fresh_range.as_ref() != Some(&import_range)
        {
            self.verified_prefix.lock().await.remove(session_id);
            return Err(SessionImportError::Budget);
        }
        let lease = self.claim_job(&fresh).await?;
        let current = &fresh.current;
        let offset = import_range.start;
        let previous_revision = fresh.previous_revision.clone();
        if matches!(
            current.body_state,
            SessionBodyState::Queued | SessionBodyState::Partial
        ) {
            self.advance(
                current,
                SessionBodyState::Importing,
                BodyStateReason::Started,
            )
            .await?;
        }
        let mut ingestor = EvidenceIngestor::new(
            self.runtime.clone(),
            self.writer.clone(),
            self.runtime.effective_config_hash,
            "session_import_v1",
        )
        .map_err(|_| SessionImportError::Persistence)?;
        if let Some(config) = &self.operation_config {
            ingestor = ingestor.with_operation_config(Arc::clone(config));
        }
        let source_instance = SourceInstanceId::parse(current.source_instance())
            .map_err(|_| SessionImportError::Unsupported)?;
        let mut cursor = offset;
        let mut pending_start = offset;
        let mut pending = Vec::new();
        let mut consumed = 0_usize;
        let mut observations = Vec::new();
        let mut eof = false;
        let deadline = Instant::now() + budget.max_work_time;
        // The body turn is consumed only after the fresh claim succeeds and
        // immediately before the first source-body read attempt.
        self.consume_body_turn(
            &fresh,
            fresh_identity,
            &fresh_key,
            import_range.kind,
            &fresh_pending,
        )
        .await;
        while consumed < budget.max_bytes
            && observations.len() < budget.max_records
            && cursor < import_range.end
        {
            if Instant::now() >= deadline {
                break;
            }
            let remaining = budget.max_bytes - consumed;
            let chunk = root
                .read_range(
                    &relative,
                    identity,
                    cursor,
                    CHUNK_BYTES.min(remaining).min(
                        usize::try_from(import_range.end - cursor)
                            .map_err(|_| SessionImportError::Budget)?,
                    ),
                    deadline,
                )
                .map_err(map_source_read)?;
            if chunk.bytes.is_empty() && !chunk.eof {
                return Err(SessionImportError::Changed);
            }
            consumed += chunk.bytes.len();
            pending.extend_from_slice(&chunk.bytes);
            cursor = chunk.next_offset;
            let mut used = 0_usize;
            while observations.len() < budget.max_records {
                if Instant::now() >= deadline {
                    break;
                }
                let Some(relative_end) = pending[used..].iter().position(|byte| *byte == b'\n')
                else {
                    break;
                };
                let end = used + relative_end;
                if end - used > MAX_RECORD_BYTES {
                    return Err(SessionImportError::Unsupported);
                }
                let line = &pending[used..end];
                let line_start = pending_start
                    .checked_add(u64::try_from(used).map_err(|_| SessionImportError::Budget)?)
                    .ok_or(SessionImportError::Budget)?;
                let line_end = line_start
                    .checked_add(
                        u64::try_from(line.len() + 1).map_err(|_| SessionImportError::Budget)?,
                    )
                    .ok_or(SessionImportError::Budget)?;
                let visibility = classify_record(line)?;
                let record_identity =
                    SourceRecordIdentity::parse(format!("bytes:{line_start}-{line_end}"))
                        .map_err(|_| SessionImportError::Unsupported)?;
                let observation_id = source_observation_id(
                    &source_instance,
                    &current.metadata.source_revision,
                    &record_identity,
                )
                .map_err(|_| SessionImportError::Unsupported)?;
                let spool_record_id = import_record_id(current, line_start, line_end);
                let (spool, _) = DurableSpool::open(
                    self.runtime.spool_dir.clone(),
                    self.runtime
                        .spool_limits()
                        .map_err(|_| SessionImportError::Persistence)?,
                )
                .map_err(|_| SessionImportError::Persistence)?;
                if spool
                    .find_durable_record(
                        &spool_record_id,
                        usize::try_from(self.runtime.max_main_files)
                            .map_err(|_| SessionImportError::Persistence)?,
                        self.runtime
                            .spool_limits()
                            .map_err(|_| SessionImportError::Persistence)?
                            .high_watermark_bytes,
                    )
                    .map_err(|_| SessionImportError::Persistence)?
                    .is_some()
                {
                    observations.push(observation_id);
                    used = end + 1;
                    continue;
                }
                let mode = if fresh.watermark.is_none()
                    && observations.is_empty()
                    && previous_revision.is_some()
                {
                    SourceRevisionMode::Replacement
                } else {
                    SourceRevisionMode::Append
                };
                let byte_range = EvidenceByteRange {
                    start: line_start,
                    end: line_end,
                };
                let (repository_instance_id, worktree_instance_id) =
                    import_scope_for_range(&fresh, &byte_range)?;
                let mut input = capture_input(
                    current,
                    line,
                    line_start,
                    line_end,
                    mode,
                    previous_revision.as_ref(),
                    visibility,
                );
                input.repository_instance_id = repository_instance_id;
                input.worktree_instance_id = worktree_instance_id;
                let outcome = CaptureRuntime::open(self.runtime.clone())
                    .map_err(|_| SessionImportError::Persistence)?
                    .capture(input)
                    .map_err(|_| SessionImportError::Persistence)?;
                if !matches!(outcome, CaptureOutcome::Durable { .. }) {
                    return Err(SessionImportError::Persistence);
                }
                observations.push(observation_id);
                used = end + 1;
            }
            pending.drain(..used);
            if pending.len() > MAX_RECORD_BYTES {
                return Err(SessionImportError::Unsupported);
            }
            pending_start = pending_start
                .checked_add(u64::try_from(used).map_err(|_| SessionImportError::Budget)?)
                .ok_or(SessionImportError::Budget)?;
            if chunk.eof && cursor < import_range.end {
                return Err(SessionImportError::Changed);
            }
            eof = cursor == import_range.end;
            if eof || observations.len() == budget.max_records {
                break;
            }
        }
        if observations.is_empty() {
            if eof && pending.is_empty() {
                let confirmed = self.context(session_id).await?;
                let terminal = finished_import_state(&confirmed)?;
                if let Some((body_state, reason)) = terminal {
                    self.finish_import_handoff(
                        current,
                        (&relative, identity),
                        ImportHandoffTarget {
                            watermark: confirmed.watermark.clone(),
                            body_state,
                            reason,
                            synced_frontier: None,
                        },
                        self.writer.subscribe_background_frontier(),
                        &lease,
                    )
                    .await?;
                } else {
                    self.advance(
                        &confirmed.current,
                        SessionBodyState::Partial,
                        BodyStateReason::BudgetExhausted,
                    )
                    .await?;
                }
                return Ok(SessionImportProgress {
                    records: 0,
                    bytes: consumed,
                    completed: terminal.is_some(),
                });
            }
            return Err(SessionImportError::Budget);
        }
        let background = self.writer.subscribe_background_frontier();
        let progress = ingestor
            .drain_observations_once(&observations)
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        let confirmed = self.context(session_id).await?;
        let (confirmed_end, confirmed_digest) = imported_range_progress(&confirmed, &import_range)?;
        if confirmed_end != pending_start || confirmed_digest.is_none() {
            return Err(SessionImportError::Persistence);
        }
        root.revalidate_file(&relative, identity)
            .map_err(map_source_read)?;
        #[cfg(test)]
        if eof
            && pending.is_empty()
            && finished_import_state(&confirmed)?.is_some()
            && let Some(pause) = self.terminal_handoff_pause.as_ref()
        {
            pause.notify_one();
            std::future::pending::<()>().await;
        }
        let terminal = if eof && pending.is_empty() {
            finished_import_state(&confirmed)?
        } else {
            None
        };
        if let Some((body_state, reason)) = terminal {
            self.finish_import_handoff(
                current,
                (&relative, identity),
                ImportHandoffTarget {
                    watermark: confirmed.watermark.clone(),
                    body_state,
                    reason,
                    synced_frontier: progress.synced_frontier,
                },
                background,
                &lease,
            )
            .await?;
        } else {
            self.advance(
                &confirmed.current,
                SessionBodyState::Partial,
                BodyStateReason::BudgetExhausted,
            )
            .await?;
            root.revalidate_file(&relative, identity)
                .map_err(map_source_read)?;
            self.remember_committed_range(
                &confirmed,
                identity,
                &key,
                &import_range,
                confirmed_end,
                confirmed_digest,
            )
            .await;
        }
        Ok(SessionImportProgress {
            records: observations.len(),
            bytes: consumed,
            completed: terminal.is_some(),
        })
    }

    pub async fn process_queued_once(
        &self,
        limit: usize,
        budget: SessionImportBudget,
    ) -> Result<(usize, bool), SessionImportError> {
        if limit == 0 || limit > 32 {
            return Err(SessionImportError::Budget);
        }
        let cursor = self.next_session.lock().await.clone();
        let selected = self
            .writer
            .session_import_contexts(cursor, limit)
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        let mut processed = 0;
        let mut retryable = selected.has_more;
        let mut remaining_bytes = self.operation_config.as_ref().map_or(usize::MAX, |config| {
            config.config().session_import.max_body_import_mib_per_run as usize * 1024 * 1024
        });
        for context in selected.contexts {
            if budget.max_work_time.is_zero() || remaining_bytes == 0 {
                retryable = true;
                break;
            }
            let session_id = context.current.source_key();
            // Rotate past actual attempts, including prefix-only work units.
            *self.next_session.lock().await = Some(session_id.clone());
            let budget = SessionImportBudget {
                max_bytes: budget.max_bytes.min(remaining_bytes),
                ..budget
            };
            match self
                .process_checkpoint_with_context(&session_id, budget, Some(context))
                .await
            {
                Ok(progress) => {
                    remaining_bytes = remaining_bytes.saturating_sub(progress.bytes);
                    processed += 1;
                    retryable |= !progress.completed;
                }
                Err(SessionImportError::Unsupported) => {
                    let current = self.current(&session_id).await?;
                    self.advance(
                        &current,
                        SessionBodyState::Failed,
                        BodyStateReason::ImportFailed,
                    )
                    .await?;
                    processed += 1;
                }
                Err(
                    SessionImportError::Budget
                    | SessionImportError::Unavailable
                    | SessionImportError::Persistence,
                ) => retryable = true,
                Err(SessionImportError::Changed) => {}
            }
        }
        Ok((processed, retryable))
    }

    async fn current(&self, session_id: &str) -> Result<SessionImportCurrent, SessionImportError> {
        Ok(self.context(session_id).await?.current)
    }

    async fn context(&self, session_id: &str) -> Result<SessionImportContext, SessionImportError> {
        self.writer
            .session_import_context(session_id)
            .await
            .map_err(|_| SessionImportError::Persistence)?
            .ok_or(SessionImportError::Unavailable)
    }

    fn handoff_target_ready(
        context: &SessionImportContext,
        expected: &SessionImportCurrent,
        target_watermark: &Option<SourceIngestWatermark>,
        lease: &ClaimedImportLease,
    ) -> Result<bool, SessionImportError> {
        let current = &context.current;
        if current.source_instance_id != expected.source_instance_id
            || current.metadata.source_revision != expected.metadata.source_revision
        {
            return Err(SessionImportError::Changed);
        }
        if context.repository_purged
            || current.access_decision == Some(evertrace_store::SessionAccessDecision::Revoked)
            || current.body_state != SessionBodyState::Importing
        {
            return Err(SessionImportError::Unavailable);
        }
        let job = context
            .job
            .as_ref()
            .ok_or(SessionImportError::Unavailable)?;
        if job.job_id != lease.lease.job_id
            || job.target_generation != lease.lease.target_generation
            || job.attempt != lease.lease.attempt
            || job.lease_until_us != Some(lease.lease.lease_until_us)
            || job.state != JobStatus::Leased
        {
            return Err(SessionImportError::Unavailable);
        }
        if Instant::now() >= lease.deadline || now_us()? >= lease.lease.lease_until_us {
            return Err(SessionImportError::Budget);
        }
        if let Some(watermark) = &context.watermark
            && (watermark.source_instance_id.as_str() != current.source_instance()
                || watermark.source_revision != current.metadata.source_revision)
        {
            return Err(SessionImportError::Changed);
        }
        Ok(&context.watermark == target_watermark)
    }

    async fn finish_import_handoff(
        &self,
        expected: &SessionImportCurrent,
        source: (&std::path::Path, ConfinedFileIdentity),
        target: ImportHandoffTarget,
        mut background: tokio::sync::watch::Receiver<u64>,
        lease: &ClaimedImportLease,
    ) -> Result<(), SessionImportError> {
        // The watch is only a wakeup. Keep the exact committed evidence, not
        // the old context's repository views, across projection synchronization.
        let (frontier, watermark) = loop {
            let _ = *background.borrow_and_update();
            let context = self.context(&expected.source_key()).await?;
            let ready = Self::handoff_target_ready(&context, expected, &target.watermark, lease)?;
            if ready {
                break (context.frontier, context.watermark);
            }
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(lease.deadline),
                background.changed(),
            )
            .await
            .map_err(|_| SessionImportError::Budget)?
            .map_err(|_| SessionImportError::Unavailable)?;
        };
        if target
            .synced_frontier
            .is_none_or(|synced| synced < frontier)
        {
            if Instant::now() >= lease.deadline {
                return Err(SessionImportError::Budget);
            }
            let synced = self
                .writer
                .sync_frontier()
                .await
                .map_err(|_| SessionImportError::Persistence)?;
            if synced < frontier {
                return Err(SessionImportError::Persistence);
            }
        }
        let report = self
            .report
            .read()
            .await
            .clone()
            .ok_or(SessionImportError::Unavailable)?;
        let checked = self.context(&expected.source_key()).await?;
        if !Self::handoff_target_ready(&checked, expected, &target.watermark, lease)?
            || checked.watermark != watermark
        {
            return Err(SessionImportError::Changed);
        }
        // This read-only check revalidates approval, purge, current repository
        // trust, the host root and exact file identity; no metadata discovery
        // or second preflight command belongs in the completion handoff.
        let (root, fresh_relative, fresh_identity) = self.authorized_source(
            &report,
            &checked,
            lease
                .deadline
                .min(Instant::now() + SESSION_ROOT_PROBE_BUDGET),
        )?;
        if fresh_relative != source.0 || fresh_identity != source.1 {
            return Err(SessionImportError::Changed);
        }
        root.revalidate_file(&fresh_relative, fresh_identity)
            .map_err(map_source_read)?;
        let occurred_at_us = now_us()?;
        let command = self.body_state_command(
            &checked.current,
            checked.job,
            target.body_state,
            target.reason,
            occurred_at_us,
        )?;
        if Instant::now() >= lease.deadline || occurred_at_us >= lease.lease.lease_until_us {
            return Err(SessionImportError::Budget);
        }
        self.writer
            .commit_if_frontier(command, occurred_at_us, checked.frontier)
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        self.verified_prefix
            .lock()
            .await
            .remove(&expected.source_key());
        root.revalidate_file(&fresh_relative, fresh_identity)
            .map_err(map_source_read)?;
        Ok(())
    }

    async fn verify_confirmed_range(
        &self,
        context: &SessionImportContext,
        source: (&ConfinedRoot, &std::path::Path, ConfinedFileIdentity),
        key: &DeviceKey,
        budget: SessionImportBudget,
        range: &ImportRange,
    ) -> Result<(bool, usize), SessionImportError> {
        let current = &context.current;
        let (root, relative, identity) = source;
        let end = range.committed_end;
        if end < range.chain_start || end > range.end {
            return Err(SessionImportError::Changed);
        }
        if end == range.chain_start {
            if range.committed_digest.is_some() {
                return Err(SessionImportError::Changed);
            }
            return Ok((true, 0));
        }
        let target_digest = range
            .committed_digest
            .clone()
            .ok_or(SessionImportError::Changed)?;
        let source_key = current.source_key();
        let slot = self.verified_slot(current, identity, key).await?;
        let leg = proof_leg(range.kind);
        let mut proof = verified_leg(&slot, leg).clone();
        if proof
            .as_ref()
            .is_some_and(|proof| proof.chain_start != range.chain_start)
        {
            self.clear_verified_leg(current, identity, key, leg).await;
            proof = None;
        }
        let mut cached = match proof {
            Some(mut proof) => {
                if proof.target_end > end {
                    return Err(SessionImportError::Budget);
                }
                if proof.target_end == end && proof.target_digest != target_digest {
                    return Err(SessionImportError::Changed);
                }
                proof.target_end = end;
                proof.target_digest = target_digest;
                proof
            }
            None => VerifiedRangeProof {
                chain_start: range.chain_start,
                target_end: end,
                target_digest,
                end: range.chain_start,
                digest: None,
            },
        };
        if cached.end == end {
            return if cached.digest.as_ref() == Some(&cached.target_digest) {
                Ok((true, 0))
            } else {
                Err(SessionImportError::Changed)
            };
        }
        // Actor queue time is preparation, not file work. The returned page is
        // bounded by the same item/byte caps as this single reading quantum.
        let page = self
            .writer
            .session_import_prefix_page(SessionImportPrefixRequest {
                source: source_key.clone(),
                revision: current.metadata.source_revision.clone(),
                after: cached.end,
                end,
                max_records: budget.max_records,
                max_bytes: budget.max_bytes,
            })
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        let deadline = Instant::now() + budget.max_work_time;
        let mut bytes = 0;
        for receipt in &page.records {
            if Instant::now() >= deadline {
                break;
            }
            let length = receipt
                .end
                .checked_sub(receipt.start)
                .ok_or(SessionImportError::Changed)?;
            if receipt.start != cached.end
                || receipt.end > end
                || length == 0
                || length > (MAX_RECORD_BYTES + 1) as u64
            {
                return Err(SessionImportError::Changed);
            }
            let range = match root
                .read_range(
                    relative,
                    identity,
                    receipt.start,
                    usize::try_from(length).map_err(|_| SessionImportError::Budget)?,
                    deadline,
                )
                .map_err(map_source_read)
            {
                Ok(range) => range,
                Err(SessionImportError::Budget) => break,
                Err(error) => return Err(error),
            };
            if range.bytes.len()
                != usize::try_from(length).map_err(|_| SessionImportError::Budget)?
                || range.bytes.last() != Some(&b'\n')
            {
                return Err(SessionImportError::Changed);
            }
            let protected = protect(&range.bytes[..range.bytes.len() - 1], key)
                .map_err(|_| SessionImportError::Persistence)?;
            if evertrace_capture::CasDigest::for_protected_bytes(protected.protected_bytes())
                .as_hex()
                != receipt.cas_ref
            {
                return Err(SessionImportError::Changed);
            }
            cached.digest = Some(extend_prefix_digest(
                current,
                cached.digest.take(),
                receipt,
            )?);
            cached.end = receipt.end;
            bytes += range.bytes.len();
        }
        if cached.end == end && cached.digest.as_ref() != Some(&cached.target_digest) {
            return Err(SessionImportError::Changed);
        }
        if page.records.is_empty() && !page.has_more {
            return Err(SessionImportError::Changed);
        }
        let ready = cached.end == end;
        let accepted = self
            .merge_verified_leg(current, identity, key, leg, cached)
            .await;
        if !accepted {
            return Ok((false, bytes));
        }
        Ok((ready, bytes))
    }

    async fn verified_slot(
        &self,
        current: &SessionImportCurrent,
        identity: ConfinedFileIdentity,
        key: &DeviceKey,
    ) -> Result<VerifiedPrefix, SessionImportError> {
        let source_key = current.source_key();
        if let Some(slot) = self.verified_prefix.lock().await.get(&source_key).cloned()
            && slot.source_revision == current.metadata.source_revision
            && slot.identity == identity
            && slot.protection_key == *key
            && slot.config_hash == self.runtime.effective_config_hash
        {
            return Ok(slot);
        }
        if !self.reserve_prefix_slot(&source_key).await? {
            return Err(SessionImportError::Budget);
        }
        let mut cache = self.verified_prefix.lock().await;
        if let Some(slot) = cache.get(&source_key)
            && slot.source_revision == current.metadata.source_revision
            && slot.identity == identity
            && slot.protection_key == *key
            && slot.config_hash == self.runtime.effective_config_hash
        {
            return Ok(slot.clone());
        }
        let next_body = cache
            .get(&source_key)
            .filter(|slot| slot.source_revision == current.metadata.source_revision)
            .map_or_else(|| default_body_turn(current), |slot| slot.next_body);
        let slot = VerifiedPrefix {
            source_key: source_key.clone(),
            source_revision: current.metadata.source_revision.clone(),
            identity,
            protection_key: key.clone(),
            config_hash: self.runtime.effective_config_hash,
            main: None,
            earlier: None,
            next_body,
        };
        cache.insert(source_key, slot.clone());
        Ok(slot)
    }

    async fn merge_verified_leg(
        &self,
        current: &SessionImportCurrent,
        identity: ConfinedFileIdentity,
        key: &DeviceKey,
        leg: ProofLeg,
        mut proof: VerifiedRangeProof,
    ) -> bool {
        let mut cache = self.verified_prefix.lock().await;
        let Some(slot) = cache.get_mut(&current.source_key()) else {
            return false;
        };
        if slot.source_revision != current.metadata.source_revision
            || slot.identity != identity
            || slot.protection_key != *key
            || slot.config_hash != self.runtime.effective_config_hash
        {
            return false;
        }
        let target = verified_leg_mut(slot, leg);
        if let Some(old) = target {
            if old.chain_start != proof.chain_start
                || old.target_end > proof.target_end
                || (old.target_end == proof.target_end && old.target_digest != proof.target_digest)
            {
                return false;
            }
            if old.end > proof.end {
                if old.end > proof.target_end {
                    return false;
                }
                proof.end = old.end;
                proof.digest = old.digest.clone();
            }
        }
        *target = Some(proof);
        true
    }

    async fn clear_verified_leg(
        &self,
        current: &SessionImportCurrent,
        identity: ConfinedFileIdentity,
        key: &DeviceKey,
        leg: ProofLeg,
    ) {
        let mut cache = self.verified_prefix.lock().await;
        if let Some(slot) = cache.get_mut(&current.source_key())
            && slot.source_revision == current.metadata.source_revision
            && slot.identity == identity
            && slot.protection_key == *key
            && slot.config_hash == self.runtime.effective_config_hash
        {
            *verified_leg_mut(slot, leg) = None;
        }
    }

    async fn choose_import_range(
        &self,
        context: &SessionImportContext,
        identity: ConfinedFileIdentity,
        key: &DeviceKey,
        pending: &[ImportRange],
    ) -> Result<ImportRange, SessionImportError> {
        let slot = self.verified_slot(&context.current, identity, key).await?;
        let preferred = pending
            .iter()
            .find(|range| range.kind == slot.next_body)
            .or_else(|| pending.first())
            .ok_or(SessionImportError::Unavailable)?;
        Ok(preferred.clone())
    }

    async fn consume_body_turn(
        &self,
        context: &SessionImportContext,
        identity: ConfinedFileIdentity,
        key: &DeviceKey,
        selected: ImportRangeKind,
        pending: &[ImportRange],
    ) {
        let Some(other) = pending
            .iter()
            .find(|range| range.kind != selected)
            .map(|range| range.kind)
        else {
            return;
        };
        let mut cache = self.verified_prefix.lock().await;
        if let Some(slot) = cache.get_mut(&context.current.source_key())
            && slot.source_revision == context.current.metadata.source_revision
            && slot.identity == identity
            && slot.protection_key == *key
            && slot.config_hash == self.runtime.effective_config_hash
        {
            slot.next_body = other;
        }
    }

    async fn remember_committed_range(
        &self,
        context: &SessionImportContext,
        identity: ConfinedFileIdentity,
        key: &DeviceKey,
        range: &ImportRange,
        end: u64,
        digest: Option<String>,
    ) {
        if end <= range.chain_start || digest.is_none() {
            return;
        }
        let leg = proof_leg(range.kind);
        let proof = VerifiedRangeProof {
            chain_start: range.chain_start,
            target_end: end,
            target_digest: digest.clone().unwrap_or_default(),
            end,
            digest,
        };
        let _ = self
            .merge_verified_leg(&context.current, identity, key, leg, proof)
            .await;
    }

    async fn reserve_prefix_slot(&self, source: &str) -> Result<bool, SessionImportError> {
        let sources = {
            let cache = self.verified_prefix.lock().await;
            if cache.contains_key(source) || cache.len() < crate::maintenance::PER_LANE_LIMIT {
                return Ok(true);
            }
            cache.keys().cloned().collect::<Vec<_>>()
        };
        // At most the existing lane capacity; never sweep all import history.
        for source in sources {
            let context = self
                .writer
                .session_import_context(&source)
                .await
                .map_err(|_| SessionImportError::Persistence)?;
            if context.is_none_or(|context| {
                context.repository_purged
                    || context.current.access_decision
                        == Some(evertrace_store::SessionAccessDecision::Revoked)
                    || context.job.as_ref().is_none_or(|job| {
                        matches!(job.state, JobStatus::Succeeded | JobStatus::Failed)
                    })
                    || !matches!(
                        context.current.body_state,
                        SessionBodyState::Queued
                            | SessionBodyState::Importing
                            | SessionBodyState::Partial
                    )
            }) {
                self.verified_prefix.lock().await.remove(&source);
            }
        }
        Ok(self.verified_prefix.lock().await.len() < crate::maintenance::PER_LANE_LIMIT)
    }

    async fn claim_job(
        &self,
        context: &SessionImportContext,
    ) -> Result<ClaimedImportLease, SessionImportError> {
        let current = &context.current;
        if let Some(config) = &self.config {
            let current = config
                .admit()
                .await
                .map_err(|_| SessionImportError::Unavailable)?;
            if current.hash() != self.runtime.effective_config_hash {
                // A later session in the batch is a new claim, not permission
                // to keep using the earlier session's configuration.
                return Err(SessionImportError::Unavailable);
            }
        }
        let Some(job) = context.job.as_ref() else {
            return Err(SessionImportError::Unavailable);
        };
        let monotonic_started = Instant::now();
        let now = now_us()?;
        if job.state == JobStatus::Leased
            && job.lease_until_us.is_some_and(|deadline| deadline > now)
        {
            return Err(SessionImportError::Unavailable);
        }
        let attempt = job
            .attempt
            .checked_add(1)
            .ok_or(SessionImportError::Persistence)?;
        let lease_until_us = now
            .checked_add(5_000_000)
            .ok_or(SessionImportError::Persistence)?;
        let lease = JobLease {
            job_id: job.job_id,
            target_generation: job.target_generation,
            attempt,
            lease_until_us,
        };
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft {
                occurred_at_us: now,
                source_kind: SourceKind::System,
                scope: EventScope {
                    session_id: Some(current.session_id.clone()),
                    ..EventScope::default()
                },
                causation_id: None,
                correlation_id: None,
                effective_config_hash: self.runtime.effective_config_hash,
                algorithm_revision: "session_import_v1".into(),
                payload: JournalPayload::JobLease(lease.clone()),
            }],
        )
        .map_err(|_| SessionImportError::Persistence)?;
        #[cfg(test)]
        tokio::time::sleep(self.claim_delay).await;
        self.writer
            .commit_if_frontier(command, now, context.frontier)
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        Ok(ClaimedImportLease {
            lease,
            deadline: monotonic_started + Duration::from_secs(5),
        })
    }

    async fn mark_source_replaced(
        &self,
        current: &SessionImportCurrent,
        identity: ConfinedFileIdentity,
    ) -> Result<(), SessionImportError> {
        let occurred_at_us = now_us()?;
        let mut metadata = current.metadata.clone();
        metadata.source_fingerprint = session_source_fingerprint(identity).to_string();
        metadata.source_revision = SourceRevision::parse(metadata.source_fingerprint.clone())
            .map_err(|_| SessionImportError::Persistence)?;
        metadata.file_size = identity.size;
        metadata.file_mtime_us = identity
            .mtime_seconds
            .checked_mul(1_000_000)
            .and_then(|value| {
                value.checked_add(i64::try_from(identity.mtime_nanoseconds / 1_000).ok()?)
            })
            .ok_or(SessionImportError::Persistence)?;
        if metadata.source_revision != current.metadata.source_revision {
            metadata.prospective_origin = None;
        } else if let Some(origin) = metadata.prospective_origin.as_mut() {
            // If the physical identity contradicted the protected chain but
            // yielded the same logical revision, fail closed instead of
            // grafting a replacement origin onto that revision.
            origin.closed = true;
        }
        let mut payloads = vec![JournalPayload::SessionImportEventRecorded(Box::new(
            SessionImportEvent {
                source_instance_id: current.source_instance_id.clone(),
                session_id: current.session_id.clone(),
                revision: current.revision + 1,
                predecessor_revision: Some(current.revision),
                occurred_at_us,
                event: SessionImportEventKind::BodyStateAdvanced {
                    body_state: SessionBodyState::SourceReplaced,
                    reason: BodyStateReason::SourceReplaced,
                },
            },
        ))];
        payloads.push(JournalPayload::SessionImportEventRecorded(Box::new(
            SessionImportEvent {
                source_instance_id: current.source_instance_id.clone(),
                session_id: current.session_id.clone(),
                revision: current.revision + 2,
                predecessor_revision: Some(current.revision + 1),
                occurred_at_us,
                event: SessionImportEventKind::MetadataObserved {
                    metadata: Box::new(metadata),
                },
            },
        )));
        if let Some(mut job) = self.context(&current.source_key()).await?.job {
            job.state = JobStatus::Failed;
            job.lease_until_us = None;
            job.terminal = Some(Box::new(terminal_audit(
                JobTerminalOutcome::Failed,
                JobTerminalReason::SourceReplaced,
                &current.source_key(),
            )));
            payloads.push(JournalPayload::JobState(job));
        }
        let events = payloads
            .into_iter()
            .map(|payload| JournalEventDraft {
                occurred_at_us,
                source_kind: SourceKind::System,
                scope: EventScope {
                    session_id: Some(current.session_id.clone()),
                    ..EventScope::default()
                },
                causation_id: None,
                correlation_id: None,
                effective_config_hash: self.runtime.effective_config_hash,
                algorithm_revision: "session_import_v1".into(),
                payload,
            })
            .collect();
        let command = JournalCommand::new(CommandId::new_v7(), events)
            .map_err(|_| SessionImportError::Persistence)?;
        self.writer
            .commit(command, occurred_at_us)
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        self.verified_prefix
            .lock()
            .await
            .remove(&current.source_key());
        Ok(())
    }

    async fn advance(
        &self,
        current: &SessionImportCurrent,
        body_state: SessionBodyState,
        reason: BodyStateReason,
    ) -> Result<(), SessionImportError> {
        let job = if body_state == SessionBodyState::Partial
            || matches!(
                body_state,
                SessionBodyState::Imported
                    | SessionBodyState::SourceReplaced
                    | SessionBodyState::Failed
                    | SessionBodyState::BlockedUnapproved
                    | SessionBodyState::BlockedUntrusted
                    | SessionBodyState::BlockedScopeUnresolved
            ) {
            self.context(&current.source_key()).await?.job
        } else {
            None
        };
        let occurred_at_us = now_us()?;
        let command = self.body_state_command(current, job, body_state, reason, occurred_at_us)?;
        self.writer
            .commit(command, occurred_at_us)
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        if !matches!(
            body_state,
            SessionBodyState::Queued | SessionBodyState::Importing | SessionBodyState::Partial
        ) {
            self.verified_prefix
                .lock()
                .await
                .remove(&current.source_key());
        }
        Ok(())
    }

    fn body_state_command(
        &self,
        current: &SessionImportCurrent,
        job: Option<DurableJob>,
        body_state: SessionBodyState,
        reason: BodyStateReason,
        occurred_at_us: i64,
    ) -> Result<JournalCommand, SessionImportError> {
        let request_id = RequestId::new_v7();
        let event = SessionImportEvent {
            source_instance_id: current.source_instance_id.clone(),
            session_id: current.session_id.clone(),
            revision: current.revision + 1,
            predecessor_revision: Some(current.revision),
            occurred_at_us,
            event: SessionImportEventKind::BodyStateAdvanced { body_state, reason },
        };
        let mut payloads = vec![JournalPayload::SessionImportEventRecorded(Box::new(event))];
        let completed_partial = body_state == SessionBodyState::Partial
            && reason == BodyStateReason::ApprovalUnavailable;
        if completed_partial {
            if let Some(mut job) = job {
                job.state = JobStatus::Succeeded;
                job.lease_until_us = None;
                job.terminal = Some(Box::new(terminal_audit(
                    JobTerminalOutcome::Succeeded,
                    JobTerminalReason::Completed,
                    &current.source_key(),
                )));
                payloads.push(JournalPayload::JobState(job));
            }
        } else if body_state == SessionBodyState::Partial {
            if let Some(mut job) = job {
                job.state = JobStatus::Queued;
                job.lease_until_us = None;
                job.terminal = None;
                payloads.push(JournalPayload::JobState(job));
            }
        } else if matches!(
            body_state,
            SessionBodyState::Imported
                | SessionBodyState::SourceReplaced
                | SessionBodyState::Failed
                | SessionBodyState::BlockedUnapproved
                | SessionBodyState::BlockedUntrusted
                | SessionBodyState::BlockedScopeUnresolved
        ) && let Some(mut job) = job
        {
            job.state = if body_state == SessionBodyState::Imported {
                JobStatus::Succeeded
            } else {
                JobStatus::Failed
            };
            job.lease_until_us = None;
            job.terminal = Some(Box::new(terminal_audit(
                if body_state == SessionBodyState::Imported {
                    JobTerminalOutcome::Succeeded
                } else {
                    JobTerminalOutcome::Failed
                },
                match reason {
                    BodyStateReason::Completed => JobTerminalReason::Completed,
                    BodyStateReason::BudgetExhausted => JobTerminalReason::BudgetExhausted,
                    BodyStateReason::SourceReplaced => JobTerminalReason::SourceReplaced,
                    BodyStateReason::ApprovalUnavailable => JobTerminalReason::Revoked,
                    BodyStateReason::ImportFailed => JobTerminalReason::IntegrityFailure,
                    BodyStateReason::TrustUnavailable | BodyStateReason::ScopeUnresolved => {
                        JobTerminalReason::SourceUnavailable
                    }
                    BodyStateReason::Requested | BodyStateReason::Started => {
                        JobTerminalReason::IntegrityFailure
                    }
                },
                &current.source_key(),
            )));
            payloads.push(JournalPayload::JobState(job));
        }
        let events = payloads
            .into_iter()
            .map(|payload| JournalEventDraft {
                occurred_at_us,
                source_kind: SourceKind::System,
                scope: EventScope {
                    session_id: Some(current.session_id.clone()),
                    ..EventScope::default()
                },
                causation_id: None,
                correlation_id: None,
                effective_config_hash: self.runtime.effective_config_hash,
                algorithm_revision: "session_import_v1".into(),
                payload,
            })
            .collect();
        let command = JournalCommand::new(
            CommandId::from_uuid(request_id.as_uuid())
                .map_err(|_| SessionImportError::Persistence)?,
            events,
        )
        .map_err(|_| SessionImportError::Persistence)?;
        Ok(command)
    }

    fn authorized_source(
        &self,
        report: &HostProbeReport,
        context: &SessionImportContext,
        deadline: Instant,
    ) -> Result<(ConfinedRoot, PathBuf, ConfinedFileIdentity), SessionImportError> {
        let current = &context.current;
        if context.repository_purged
            || !matches!(
                current.body_state,
                SessionBodyState::Queued | SessionBodyState::Importing | SessionBodyState::Partial
            )
        {
            return Err(SessionImportError::Unavailable);
        }
        let root_path = report
            .session_catalog_roots()
            .iter()
            .find(|root| root.root_kind == SessionCatalogRootKind::CodexSessions)
            .and_then(|root| root.canonical_absolute_path.as_deref())
            .map(PathBuf::from)
            .ok_or(SessionImportError::Unavailable)?;
        let qualified = qualify_requested_session_root(
            report,
            SessionCatalogRootKind::CodexSessions,
            &root_path,
        )
        .map_err(|_| SessionImportError::Unavailable)?;
        let relative = PathBuf::from(&current.metadata.source_path);
        let parent = relative.parent().ok_or(SessionImportError::Unsupported)?;
        let file_name = relative
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(SessionImportError::Unsupported)?;
        let (thread, rollout) = evertrace_codex::session_import::rollout_ids_from_name(file_name)
            .map_err(|_| SessionImportError::Unavailable)?;
        if thread != current.session_id
            || current
                .source_instance_id
                .as_ref()
                .is_some_and(|source| source != &format!("session-rollout:{thread}:{rollout}"))
        {
            return Err(SessionImportError::Unavailable);
        }
        let root = ConfinedRoot::open_external_source(qualified.path())
            .map_err(|_| SessionImportError::Unavailable)?;
        let entries = root
            .list_directory(Some(parent), 1024, deadline)
            .map_err(map_source_read)?;
        let mut matches = entries
            .iter()
            .filter(|entry| entry.name == file_name && entry.entry_type == ConfinedEntryType::File);
        let identity = matches
            .next()
            .map(|entry| entry.identity)
            .ok_or(SessionImportError::Changed)?;
        if matches.next().is_some()
            || identity.size != current.metadata.file_size
            || session_source_fingerprint(identity).to_string()
                != current.metadata.source_fingerprint
        {
            return Err(SessionImportError::Changed);
        }
        if !crate::session_import::source_ingest_read_allowed(report, context, deadline) {
            return Err(SessionImportError::Unavailable);
        }
        Ok((root, relative, identity))
    }
}

fn import_ranges(context: &SessionImportContext) -> Result<Vec<ImportRange>, SessionImportError> {
    let current = &context.current;
    let watermark = context.watermark.as_ref();
    if let Some(origin) = current.metadata.prospective_origin.as_ref() {
        // Closing future admission does not revoke independent historical
        // permission. Preflight and each record's import_scope still apply.
        let Some(fence) = origin.record_start else {
            return Ok(Vec::new());
        };
        if fence > current.metadata.file_size
            || origin.observed_end > fence
            || watermark.is_some_and(|value| {
                value
                    .earlier_prefix
                    .as_ref()
                    .is_none_or(|prefix| prefix.fence_byte != fence)
            })
        {
            return Err(SessionImportError::Changed);
        }
        let (suffix_end, suffix_digest, prefix_end, prefix_digest) = match watermark {
            Some(value) => {
                let prefix = value
                    .earlier_prefix
                    .as_ref()
                    .ok_or(SessionImportError::Changed)?;
                let suffix_end = if value.confirmed_prefix_digest.is_some() {
                    if value.source_sequence <= fence {
                        return Err(SessionImportError::Changed);
                    }
                    value.source_sequence
                } else {
                    if value.source_sequence != fence {
                        return Err(SessionImportError::Changed);
                    }
                    fence
                };
                (
                    suffix_end,
                    value.confirmed_prefix_digest.clone(),
                    prefix.through_byte,
                    prefix.digest.clone(),
                )
            }
            None => (fence, None, 0, None),
        };
        if suffix_end > current.metadata.file_size || prefix_end > fence {
            return Err(SessionImportError::Changed);
        }
        let mut ranges = Vec::new();
        if suffix_end < current.metadata.file_size && !origin.closed {
            ranges.push(ImportRange {
                kind: ImportRangeKind::ProspectiveSuffix,
                start: suffix_end,
                end: current.metadata.file_size,
                chain_start: fence,
                committed_end: suffix_end,
                committed_digest: suffix_digest,
            });
        }
        if prefix_end < fence && prefix_accessible(current, fence) {
            ranges.push(ImportRange {
                kind: ImportRangeKind::HistoricalPrefix,
                start: prefix_end,
                end: fence,
                chain_start: 0,
                committed_end: prefix_end,
                committed_digest: prefix_digest,
            });
        }
        return Ok(ranges);
    }
    if watermark.is_some_and(|value| value.earlier_prefix.is_some()) {
        return Err(SessionImportError::Changed);
    }
    let committed_end = watermark.map_or(0, |value| value.source_sequence);
    if committed_end > current.metadata.file_size {
        return Err(SessionImportError::Changed);
    }
    if committed_end == current.metadata.file_size {
        return Ok(Vec::new());
    }
    Ok(vec![ImportRange {
        kind: ImportRangeKind::Whole,
        start: committed_end,
        end: current.metadata.file_size,
        chain_start: 0,
        committed_end,
        committed_digest: watermark.and_then(|value| value.confirmed_prefix_digest.clone()),
    }])
}

fn required_import_proofs(
    context: &SessionImportContext,
) -> Result<Vec<ImportRange>, SessionImportError> {
    let current = &context.current;
    let Some(watermark) = context.watermark.as_ref() else {
        return Ok(Vec::new());
    };
    let Some(origin) = current.metadata.prospective_origin.as_ref() else {
        if watermark.earlier_prefix.is_some() {
            return Err(SessionImportError::Changed);
        }
        return Ok((watermark.source_sequence > 0)
            .then(|| ImportRange {
                kind: ImportRangeKind::Whole,
                start: 0,
                end: watermark.source_sequence,
                chain_start: 0,
                committed_end: watermark.source_sequence,
                committed_digest: watermark.confirmed_prefix_digest.clone(),
            })
            .into_iter()
            .collect());
    };
    let fence = origin.record_start.ok_or(SessionImportError::Unavailable)?;
    let prefix = watermark
        .earlier_prefix
        .as_ref()
        .ok_or(SessionImportError::Changed)?;
    if prefix.fence_byte != fence {
        return Err(SessionImportError::Changed);
    }
    let mut proofs = Vec::with_capacity(2);
    // Fixed proof order is earlier-first. Do not read this range unless the
    // original historical permission is currently available.
    if prefix.through_byte > 0 && prefix_accessible(current, fence) {
        proofs.push(ImportRange {
            kind: ImportRangeKind::HistoricalPrefix,
            start: 0,
            end: prefix.through_byte,
            chain_start: 0,
            committed_end: prefix.through_byte,
            committed_digest: prefix.digest.clone(),
        });
    }
    let suffix_end = if watermark.confirmed_prefix_digest.is_some() {
        watermark.source_sequence
    } else {
        fence
    };
    if suffix_end > fence
        && (current.access_decision == Some(evertrace_store::SessionAccessDecision::Approved)
            || (!origin.closed && origin.record_start.is_some()))
    {
        proofs.push(ImportRange {
            kind: ImportRangeKind::ProspectiveSuffix,
            start: fence,
            end: suffix_end,
            chain_start: fence,
            committed_end: suffix_end,
            committed_digest: watermark.confirmed_prefix_digest.clone(),
        });
    }
    Ok(proofs)
}

fn prefix_accessible(current: &SessionImportCurrent, fence: u64) -> bool {
    fence != 0
        && current
            .import_scope(&EvidenceByteRange { start: 0, end: 1 }, None, None)
            .is_ok()
}

fn import_scope_for_range(
    context: &SessionImportContext,
    range: &EvidenceByteRange,
) -> Result<(Option<String>, Option<String>), SessionImportError> {
    let current = &context.current;
    let origin = current.metadata.prospective_origin.as_ref();
    let snapshot = origin.and_then(|origin| {
        context
            .read_snapshots
            .iter()
            .find(|snapshot| snapshot.worktree_snapshot_id == origin.snapshot_ref)
    });
    let worktree = snapshot.and_then(|snapshot| {
        context
            .read_worktrees
            .iter()
            .find(|worktree| worktree.worktree_instance_id == snapshot.worktree_instance_id)
    });
    let (repository, worktree) = current
        .import_scope(range, snapshot, worktree)
        .map_err(|_| SessionImportError::Unavailable)?;
    Ok((
        repository.map(|value| value.to_string()),
        worktree.map(|value| value.to_string()),
    ))
}

fn imported_range_progress(
    context: &SessionImportContext,
    range: &ImportRange,
) -> Result<(u64, Option<String>), SessionImportError> {
    let Some(watermark) = context.watermark.as_ref() else {
        return Ok((0, None));
    };
    match range.kind {
        ImportRangeKind::Whole => Ok((
            watermark.source_sequence,
            watermark.confirmed_prefix_digest.clone(),
        )),
        ImportRangeKind::ProspectiveSuffix => {
            let prefix = watermark
                .earlier_prefix
                .as_ref()
                .filter(|prefix| prefix.fence_byte == range.chain_start)
                .ok_or(SessionImportError::Changed)?;
            if watermark.confirmed_prefix_digest.is_some() {
                Ok((
                    watermark.source_sequence,
                    watermark.confirmed_prefix_digest.clone(),
                ))
            } else if watermark.source_sequence == range.chain_start {
                Ok((range.chain_start, None))
            } else {
                let _ = prefix;
                Err(SessionImportError::Changed)
            }
        }
        ImportRangeKind::HistoricalPrefix => {
            let prefix = watermark
                .earlier_prefix
                .as_ref()
                .filter(|prefix| prefix.fence_byte == range.end)
                .ok_or(SessionImportError::Changed)?;
            Ok((prefix.through_byte, prefix.digest.clone()))
        }
    }
}

fn finished_import_state(
    context: &SessionImportContext,
) -> Result<Option<(SessionBodyState, BodyStateReason)>, SessionImportError> {
    let current = &context.current;
    let watermark = context.watermark.as_ref();
    let Some(origin) = current.metadata.prospective_origin.as_ref() else {
        let end = watermark.map_or(0, |value| value.source_sequence);
        return Ok((end == current.metadata.file_size)
            .then_some((SessionBodyState::Imported, BodyStateReason::Completed)));
    };
    let Some(fence) = origin.record_start else {
        return Ok(None);
    };
    let suffix_end = watermark.map_or(fence, |value| {
        if value.confirmed_prefix_digest.is_some() {
            value.source_sequence
        } else {
            fence
        }
    });
    let prefix_end = watermark
        .and_then(|value| value.earlier_prefix.as_ref())
        .map_or(0, |prefix| prefix.through_byte);
    let suffix_complete = origin.closed || suffix_end == current.metadata.file_size;
    let prefix_complete = prefix_end == fence;
    if suffix_complete && (prefix_complete || !prefix_accessible(current, fence)) {
        let imported = prefix_complete && !origin.closed;
        return Ok(Some((
            if imported {
                SessionBodyState::Imported
            } else {
                SessionBodyState::Partial
            },
            if imported {
                BodyStateReason::Completed
            } else {
                BodyStateReason::ApprovalUnavailable
            },
        )));
    }
    Ok(None)
}

fn map_source_read(error: evertrace_capture::ConfinedReadError) -> SessionImportError {
    match error {
        evertrace_capture::ConfinedReadError::Changed => SessionImportError::Changed,
        evertrace_capture::ConfinedReadError::Deadline
        | evertrace_capture::ConfinedReadError::LimitExceeded { .. } => SessionImportError::Budget,
        _ => SessionImportError::Unavailable,
    }
}

fn terminal_audit(
    outcome: JobTerminalOutcome,
    reason: JobTerminalReason,
    session_id: &str,
) -> JobTerminalAudit {
    JobTerminalAudit {
        outcome,
        reason,
        result_ref: Some(format!("session_import:{session_id}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_runtime(root: &std::path::Path) -> RuntimeSnapshot {
        RuntimeSnapshot {
            snapshot_version: evertrace_capture::RUNTIME_SNAPSHOT_VERSION,
            generation: 1,
            device_key_dir: root.join("keys"),
            cas_dir: root.join("cas"),
            spool_dir: root.join("spool"),
            main_high_watermark_bytes: 2 << 20,
            main_low_watermark_bytes: 64 << 10,
            max_main_files: 16,
            emergency_slots: 2,
            effective_config_hash: [28; 32],
            recovery_gate: evertrace_capture::RecoveryGateMode::Disabled,
            recovery_socket_path: root.join("runtime/evertraced-v1.sock"),
            recovery_preflight_timeout_ms: 250,
            recovery_adapter_manifest_id: None,
            recovery_classifier_revision: 1,
            recovery_max_bundle_bytes: 4 << 20,
            recovery_max_untracked_file_bytes: 1 << 20,
            recovery_max_untracked_total_bytes: 2 << 20,
            recall_cue_gate: evertrace_capture::RecallCueGateMode::Disabled,
            recall_cue_adapter_manifest_id: None,
            recall_cues: Vec::new(),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cold_prefix_rotates_without_leases_and_claim_time_is_not_read_time() {
        use crate::session_import::{
            SessionCatalogService, SessionImportAdminAction, SessionImportAdminService,
        };
        use evertrace_capture::CasStore;
        use std::{fs, os::unix::fs::PermissionsExt};
        let temp =
            std::env::temp_dir().join(format!("evertrace-import-work-{}", RequestId::new_v7()));
        let adapter = temp.join("adapter");
        let dated = adapter.join("sessions/2026/08/30");
        fs::create_dir_all(&dated).unwrap();
        fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700)).unwrap();
        let session = "019d0000-0000-7000-8000-000000000028";
        let second = "019d0000-0000-7000-8000-000000000029";
        let sources = [
            format!("session-rollout:{session}:{session}"),
            format!("session-rollout:{session}:{second}"),
        ];
        let first = dated.join(format!("rollout-2026-08-30T00-00-00-{session}.jsonl"));
        let other = dated.join(format!(
            "rollout-2026-08-30T00-00-00-{session}_{second}.jsonl"
        ));
        let header = serde_json::json!({"timestamp":"2026-08-30T00:00:00Z", "type":"session_meta", "payload":{"id":session,"session_id":session,"originator":"codex_cli_rs","model_provider":"openai","cwd":"/non-repository","git":null}});
        let line = serde_json::json!({"type":"event_msg", "payload":{"type":"item_completed","thread_id":session,"turn_id":"turn","item":{"type":"UserMessage","id":"message","content":[{"type":"text","text":"read quantum"}]}}});
        let content = format!("{header}\n{}", format!("{line}\n").repeat(6));
        fs::write(&first, &content).unwrap();
        fs::write(&other, &content).unwrap();
        let report = crate::repository::observe_session_catalog_report(
            first.to_str(),
            session,
            "import-work-test",
            None,
        )
        .unwrap();
        let (writer, task) =
            crate::spawn_writer(crate::open_writer(&temp.join("data")).await.unwrap(), 16).unwrap();
        SessionCatalogService::new(writer.clone(), [28; 32])
            .refresh(&report)
            .await
            .unwrap();
        let report = Arc::new(RwLock::new(Some(report)));
        let admin = SessionImportAdminService::new(writer.clone(), Arc::clone(&report), [28; 32]);
        admin
            .handle(
                RequestId::new_v7(),
                session,
                SessionImportAdminAction::QueueImport,
                10,
            )
            .await
            .unwrap();
        DeviceKeyStore::new(temp.join("keys"))
            .load_or_create()
            .unwrap();
        // A prior importer has already made the first display record durable
        // as Other, but has not ingested/ACKed it. Reopen must use that frame,
        // not recapture the same identity with the new Message classification.
        let current = writer
            .session_import_context(&sources[0])
            .await
            .unwrap()
            .unwrap()
            .current;
        let header = header.to_string();
        let line = line.to_string();
        let old_end = (header.len() + line.len() + 2) as u64;
        {
            let mut capture = CaptureRuntime::open(test_runtime(&temp)).unwrap();
            capture
                .capture(capture_input(
                    &current,
                    header.as_bytes(),
                    0,
                    header.len() as u64 + 1,
                    SourceRevisionMode::Append,
                    None,
                    classify_record(header.as_bytes()).unwrap(),
                ))
                .unwrap();
            let mut old = capture_input(
                &current,
                line.as_bytes(),
                header.len() as u64 + 1,
                old_end,
                SourceRevisionMode::Append,
                None,
                RecordVisibility {
                    role: ObservationRole::Other,
                    unsupported: Some(UnsupportedRecordClassification::UnknownRecordType),
                    surface_eligible: false,
                },
            );
            old.capture_completeness = evertrace_domain::evidence::CaptureCompleteness::Complete;
            capture.capture(old).unwrap();
            capture.seal_active().unwrap();
        }
        drop(admin);
        writer.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        let (writer, task) =
            crate::spawn_writer(crate::open_writer(&temp.join("data")).await.unwrap(), 16).unwrap();
        let admin = SessionImportAdminService::new(writer.clone(), Arc::clone(&report), [28; 32]);
        let mut worker =
            SessionImportWorker::new(writer.clone(), test_runtime(&temp), Arc::clone(&report))
                .unwrap();
        worker.claim_delay = Duration::from_millis(350);
        let budget = SessionImportBudget {
            max_bytes: 64 * 1024,
            max_records: 5,
            max_work_time: Duration::from_millis(250),
        };
        for source in &sources {
            // A successful 250 ms unit need not finish all five records.
            // Prepare exactly five before testing the cold prefix's ten pages.
            let mut prepared_records = 0;
            for _ in 0..5 {
                let remaining = 5 - prepared_records;
                let start = Instant::now();
                let progress = worker
                    .process_checkpoint(
                        source,
                        SessionImportBudget {
                            max_records: remaining,
                            ..budget
                        },
                    )
                    .await
                    .unwrap();
                assert!(start.elapsed() >= Duration::from_millis(350));
                assert!(progress.records > 0 && progress.records <= remaining);
                assert!(!progress.completed);
                prepared_records += progress.records;
                if prepared_records == 5 {
                    break;
                }
            }
            assert_eq!(prepared_records, 5);
        }
        let snapshot = writer.project().await.unwrap();
        let recovered = snapshot
            .data_rows()
            .find_map(|row| {
                let JournalPayload::SourceReceiptRecorded(receipt) =
                    serde_json::from_str(row.payload_json.as_deref()?).ok()?
                else {
                    return None;
                };
                (receipt.source_instance_id.as_str() == sources[0]
                    && receipt.source_sequence == old_end)
                    .then_some(receipt)
            })
            .unwrap();
        assert_eq!(recovered.observation_role, ObservationRole::Other);
        assert_eq!(
            recovered.unsupported_record_classification,
            Some(UnsupportedRecordClassification::UnknownRecordType)
        );
        assert_eq!(
            CasStore::open(test_runtime(&temp).cas_dir)
                .unwrap()
                .read(&CasStore::parse_digest(&recovered.cas_ref).unwrap())
                .unwrap(),
            line.as_bytes()
        );
        let worker =
            SessionImportWorker::new(writer.clone(), test_runtime(&temp), Arc::clone(&report))
                .unwrap();
        let first_page = writer.session_import_contexts(None, 1).await.unwrap();
        assert!(first_page.has_more);
        assert_eq!(first_page.contexts[0].current.source_key(), sources[0]);
        assert_eq!(
            writer
                .session_import_contexts(Some(sources[0].clone()), 1)
                .await
                .unwrap()
                .contexts[0]
                .current
                .source_key(),
            sources[1]
        );
        let before = writer
            .session_import_contexts(None, 2)
            .await
            .unwrap()
            .contexts;
        let mut purged = before[0].clone();
        purged.repository_purged = true;
        assert!(matches!(
            worker.authorized_source(
                report.read().await.as_ref().unwrap(),
                &purged,
                Instant::now() + SESSION_ROOT_PROBE_BUDGET,
            ),
            Err(SessionImportError::Unavailable)
        ));
        assert_eq!(
            worker
                .process_checkpoint(
                    &sources[0],
                    SessionImportBudget {
                        max_work_time: Duration::ZERO,
                        ..budget
                    }
                )
                .await,
            Err(SessionImportError::Budget)
        );
        let prefix_budget = SessionImportBudget {
            max_records: 1,
            ..budget
        };
        for _ in 0..10 {
            assert_eq!(
                worker.process_queued_once(1, prefix_budget).await.unwrap(),
                (1, true)
            );
            assert_eq!(
                writer
                    .session_import_contexts(None, 2)
                    .await
                    .unwrap()
                    .contexts,
                before
            );
        }
        assert_eq!(worker.verified_prefix.lock().await.len(), 2);
        let overflow_sessions = (0..7)
            .map(|offset| format!("019d0000-0000-7000-8000-{:012x}", 0x2b + offset))
            .collect::<Vec<_>>();
        let overflow_sources = overflow_sessions
            .iter()
            .map(|id| format!("session-rollout:{id}:{id}"))
            .collect::<Vec<_>>();
        for (index, id) in overflow_sessions.iter().enumerate() {
            let path = dated.join(format!("rollout-2026-08-30T00-00-00-{id}.jsonl"));
            let overflow_header = serde_json::json!({
                "timestamp":"2026-08-30T00:00:00Z",
                "type":"session_meta",
                "payload":{"id":id,"session_id":id,"originator":"codex_cli_rs","model_provider":"openai","cwd":"/non-repository","git":null}
            });
            let overflow_line = serde_json::json!({
                "type":"event_msg",
                "payload":{"type":"item_completed","thread_id":id,"turn_id":format!("turn-overflow-{index}"),"item":{"type":"UserMessage","id":format!("message-overflow-{index}"),"content":[{"type":"text","text":"slot-cap work"}]}}
            });
            let overflow_content = format!(
                "{overflow_header}\n{}",
                format!("{overflow_line}\n").repeat(6)
            );
            fs::write(path, overflow_content).unwrap();
        }
        let catalog_report = report.read().await.clone().unwrap();
        SessionCatalogService::new(writer.clone(), [28; 32])
            .refresh(&catalog_report)
            .await
            .unwrap();
        for (index, id) in overflow_sessions.iter().enumerate() {
            admin
                .handle(
                    RequestId::new_v7(),
                    id,
                    SessionImportAdminAction::QueueImport,
                    19 + index as i64,
                )
                .await
                .unwrap();
            let queued = writer
                .session_import_context(&overflow_sources[index])
                .await
                .unwrap()
                .unwrap();
            assert_eq!(queued.job.as_ref().unwrap().state, JobStatus::Queued);
            assert_eq!(queued.watermark, None);
        }
        let preparation_worker =
            SessionImportWorker::new(writer.clone(), test_runtime(&temp), Arc::clone(&report))
                .unwrap();
        for source in &overflow_sources {
            let progress = preparation_worker
                .process_checkpoint(
                    source,
                    SessionImportBudget {
                        max_records: 1,
                        ..budget
                    },
                )
                .await
                .unwrap();
            assert_eq!(progress.records, 1);
            assert!(!progress.completed);
        }
        let capacity_worker =
            SessionImportWorker::new(writer.clone(), test_runtime(&temp), Arc::clone(&report))
                .unwrap();
        for source in sources.iter().chain(overflow_sources.iter().take(6)) {
            let progress = capacity_worker
                .process_checkpoint(source, budget)
                .await
                .unwrap();
            assert!(!progress.completed);
        }
        assert_eq!(
            capacity_worker.verified_prefix.lock().await.len(),
            crate::maintenance::PER_LANE_LIMIT
        );
        let overflow_watermark = writer
            .session_import_context(overflow_sources.last().unwrap())
            .await
            .unwrap()
            .unwrap()
            .watermark
            .unwrap();
        assert!(overflow_watermark.source_sequence > 0);
        assert_eq!(
            capacity_worker
                .process_checkpoint(overflow_sources.last().unwrap(), budget)
                .await,
            Err(SessionImportError::Budget),
            "the eighth active source slot must reject a ninth source"
        );
        assert_eq!(
            capacity_worker.verified_prefix.lock().await.len(),
            crate::maintenance::PER_LANE_LIMIT
        );
        let overflow_after = writer
            .session_import_context(overflow_sources.last().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            overflow_after.job.as_ref().unwrap().state,
            JobStatus::Queued
        );
        assert_eq!(overflow_after.watermark.as_ref(), Some(&overflow_watermark));
        for source in &overflow_sources {
            for _ in 0..5 {
                let progress = preparation_worker
                    .process_checkpoint(
                        source,
                        SessionImportBudget {
                            max_records: 1,
                            ..budget
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(progress.records, 1);
                assert!(!progress.completed);
            }
            assert!(
                preparation_worker
                    .process_checkpoint(source, budget)
                    .await
                    .unwrap()
                    .completed,
                "the independent worker completes one source and releases its slot"
            );
        }
        assert!(preparation_worker.verified_prefix.lock().await.is_empty());
        // Revoke after the proof is complete but before a new body claim.
        admin
            .handle(
                RequestId::new_v7(),
                session,
                SessionImportAdminAction::RevokeAccess,
                30,
            )
            .await
            .unwrap();
        for (source, prior) in sources.iter().zip(&before) {
            assert_eq!(
                worker.process_checkpoint(source, budget).await,
                Err(SessionImportError::Unavailable)
            );
            assert_eq!(
                writer
                    .session_import_context(source)
                    .await
                    .unwrap()
                    .unwrap()
                    .watermark,
                prior.watermark
            );
        }
        assert!(worker.verified_prefix.lock().await.is_empty());
        admin
            .handle(
                RequestId::new_v7(),
                session,
                SessionImportAdminAction::QueueImport,
                31,
            )
            .await
            .unwrap();
        for _ in 0..10 {
            assert_eq!(
                worker.process_queued_once(1, prefix_budget).await.unwrap(),
                (1, true)
            );
        }
        for source in &sources {
            let progress = worker.process_checkpoint(source, budget).await.unwrap();
            assert!(progress.completed);
            assert_eq!(progress.records, 2);
            assert_eq!(
                writer
                    .session_import_context(source)
                    .await
                    .unwrap()
                    .unwrap()
                    .watermark
                    .unwrap()
                    .source_sequence,
                content.len() as u64
            );
        }
        assert!(worker.verified_prefix.lock().await.is_empty());
        writer.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        fs::remove_dir_all(&temp).unwrap();
        fs::remove_file(temp.with_extension("maintenance.lock")).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn durable_last_receipt_recovers_terminal_after_cancel_without_duplicate_commit() {
        use crate::session_import::{
            SessionCatalogService, SessionImportAdminAction, SessionImportAdminService,
        };
        use std::{fs, os::unix::fs::PermissionsExt, time::SystemTime};

        let root =
            std::env::temp_dir().join(format!("evertrace-import-terminal-{}", RequestId::new_v7()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let adapter = root.join("adapter");
        let dated = adapter.join("sessions/2026/08/30");
        fs::create_dir_all(&dated).unwrap();
        fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700)).unwrap();
        let session = "019d0000-0000-7000-8000-00000000002a";
        let source = format!("session-rollout:{session}:{session}");
        let transcript = dated.join(format!("rollout-2026-08-30T00-00-00-{session}.jsonl"));
        let header = serde_json::json!({
            "timestamp":"2026-08-30T00:00:00Z",
            "type":"session_meta",
            "payload":{"id":session,"session_id":session,"originator":"codex_cli_rs","model_provider":"openai","cwd":"/non-repository","git":null}
        });
        let message = |id: &str| {
            serde_json::json!({
                "timestamp":"2026-08-30T00:00:01Z",
                "type":"event_msg",
                "payload":{"type":"item_completed","thread_id":session,"turn_id":id,"item":{"type":"UserMessage","id":id,"content":[{"type":"text","text":format!("terminal handoff recovery {id}")}]}}
            })
        };
        let content = format!("{}\n{}\n{}\n", header, message("last-1"), message("last-2"));
        fs::write(&transcript, &content).unwrap();
        let report = crate::repository::observe_session_catalog_report(
            transcript.to_str(),
            session,
            "terminal-recovery-test",
            None,
        )
        .unwrap();
        let (writer, actor) =
            crate::spawn_writer(crate::open_writer(&root.join("data")).await.unwrap(), 16).unwrap();
        let catalog = SessionCatalogService::new(writer.clone(), [28; 32]);
        catalog.refresh(&report).await.unwrap();
        let report = Arc::new(RwLock::new(Some(report)));
        let admin = SessionImportAdminService::new(writer.clone(), Arc::clone(&report), [28; 32]);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        admin
            .handle(
                RequestId::new_v7(),
                session,
                SessionImportAdminAction::QueueImport,
                now,
            )
            .await
            .unwrap();
        DeviceKeyStore::new(root.join("keys"))
            .load_or_create()
            .unwrap();

        let reached = Arc::new(tokio::sync::Notify::new());
        let mut worker =
            SessionImportWorker::new(writer.clone(), test_runtime(&root), Arc::clone(&report))
                .unwrap();
        worker.terminal_handoff_pause = Some(Arc::clone(&reached));
        let running_worker = worker.clone();
        let budget = SessionImportBudget {
            max_bytes: 64 * 1024,
            max_records: 8,
            max_work_time: Duration::from_millis(250),
        };
        let running =
            tokio::spawn(async move { running_worker.process_checkpoint(&source, budget).await });
        tokio::time::timeout(Duration::from_secs(10), reached.notified())
            .await
            .expect("worker did not stop after its final durable receipt");
        assert!(
            !running.is_finished(),
            "terminal handoff pause must be in flight"
        );
        running.abort();
        assert!(running.await.unwrap_err().is_cancelled());

        let interrupted = writer
            .session_import_context(&format!("session-rollout:{session}:{session}"))
            .await
            .unwrap()
            .unwrap();
        let committed_watermark = interrupted.watermark.clone().unwrap();
        assert_eq!(committed_watermark.source_sequence, content.len() as u64);
        assert_eq!(interrupted.current.body_state, SessionBodyState::Importing);
        let leased = interrupted.job.as_ref().unwrap();
        assert_eq!(leased.state, JobStatus::Leased);
        assert!(leased.terminal.is_none());
        let interrupted_job_id = leased.job_id;
        let interrupted_attempt = leased.attempt;
        let lease_until_us = leased.lease_until_us.unwrap();
        let durable_payloads = writer
            .project()
            .await
            .unwrap()
            .data_rows()
            .filter_map(|row| {
                match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                    JournalPayload::SourceReceiptRecorded(receipt)
                        if receipt.source_instance_id.as_str()
                            == format!("session-rollout:{session}:{session}") =>
                    {
                        Some(serde_json::to_string(&receipt).unwrap())
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(durable_payloads.len(), 3);
        let synced_frontier = writer.sync_frontier().await.unwrap();
        assert!(synced_frontier >= interrupted.frontier);
        drop(admin);
        drop(catalog);
        drop(worker);
        writer.shutdown().await.unwrap();
        actor.await.unwrap().unwrap();

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        if lease_until_us > now {
            tokio::time::sleep(Duration::from_micros(
                (lease_until_us - now) as u64 + 100_000,
            ))
            .await;
        }
        let (writer, actor) =
            crate::spawn_writer(crate::open_writer(&root.join("data")).await.unwrap(), 16).unwrap();
        let resumed_worker =
            SessionImportWorker::new(writer.clone(), test_runtime(&root), Arc::clone(&report))
                .unwrap();
        let recovery_catalog = SessionCatalogService::new(writer.clone(), [28; 32]);
        let recovery_scheduler = crate::BackgroundScheduler::new(
            writer.clone(),
            recovery_catalog,
            resumed_worker.clone(),
            Arc::clone(&report),
            test_runtime(&root),
            crate::SynthesisPlanner::new(evertrace_domain::config::LlmConfig {
                enabled: false,
                ..evertrace_domain::config::LlmConfig::default()
            }),
            evertrace_domain::config::DreamingConfig::default(),
        );
        let mut completed = false;
        for _ in 0..32 {
            recovery_scheduler.run_once().await.unwrap();
            let context = writer
                .session_import_context(&format!("session-rollout:{session}:{session}"))
                .await
                .unwrap()
                .unwrap();
            if context.current.body_state == SessionBodyState::Imported {
                completed = true;
                break;
            }
        }
        assert!(
            completed,
            "restart must finish the durable terminal handoff"
        );
        let recovered = writer
            .session_import_context(&format!("session-rollout:{session}:{session}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.watermark, Some(committed_watermark));
        assert_eq!(recovered.current.body_state, SessionBodyState::Imported);
        let terminal = writer
            .project()
            .await
            .unwrap()
            .data_rows()
            .filter_map(|row| row.payload_json.as_deref())
            .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
            .filter_map(|payload| match payload {
                JournalPayload::JobState(job) if job.job_id == interrupted_job_id => Some(job),
                _ => None,
            })
            .last()
            .expect("terminal job state is durable in the journal");
        assert_eq!(terminal.job_id, interrupted_job_id);
        assert!(terminal.attempt > interrupted_attempt);
        assert_eq!(terminal.state, JobStatus::Succeeded);
        assert!(terminal.lease_until_us.is_none());
        assert!(terminal.terminal.is_some());
        let recovered_project = writer.project().await.unwrap();
        let recovered_payloads = recovered_project
            .data_rows()
            .filter_map(|row| {
                match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                    JournalPayload::SourceReceiptRecorded(receipt)
                        if receipt.source_instance_id.as_str()
                            == format!("session-rollout:{session}:{session}") =>
                    {
                        Some(serde_json::to_string(&receipt).unwrap())
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(recovered_payloads, durable_payloads);
        let completed_frontier = recovered.frontier;
        let successful_job_events = recovered_project
            .data_rows()
            .filter_map(|row| row.payload_json.as_deref())
            .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
            .filter(|payload| {
                matches!(payload, JournalPayload::JobState(job)
                    if job.job_id == interrupted_job_id && job.state == JobStatus::Succeeded)
            })
            .count();
        assert_eq!(successful_job_events, 1);
        recovery_scheduler.run_once().await.unwrap();
        let idempotent_project = writer.project().await.unwrap();
        assert_eq!(idempotent_project.frontier, completed_frontier);
        assert_eq!(
            idempotent_project
                .data_rows()
                .filter_map(|row| row.payload_json.as_deref())
                .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
                .filter(|payload| {
                    matches!(payload, JournalPayload::JobState(job)
                        if job.job_id == interrupted_job_id && job.state == JobStatus::Succeeded)
                })
                .count(),
            successful_job_events
        );
        writer.shutdown().await.unwrap();
        actor.await.unwrap().unwrap();
        fs::remove_dir_all(&root).unwrap();
        fs::remove_file(root.with_extension("maintenance.lock")).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn split_partial_last_receipt_recovers_terminal_after_cancel_without_duplicate_commit() {
        use crate::repository::{
            HostTrustDecision, ProbeLimits, RepositoryResolveInput, ResolutionKind,
            probe_repository, resolve_repository, resolve_repository_source_start,
        };
        use crate::session_import::SessionCatalogService;
        use evertrace_store::repository::RepositoryCurrentView;
        use std::{
            fs, io::Write as _, os::unix::fs::PermissionsExt, process::Command, time::SystemTime,
        };

        fn git(dir: &std::path::Path, args: &[&str]) -> String {
            let output = Command::new("git")
                .arg("-C")
                .arg(dir)
                .args([
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                ])
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_TERMINAL_PROMPT", "0")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        }

        let root =
            std::env::temp_dir().join(format!("evertrace-split-terminal-{}", RequestId::new_v7()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        git(&workspace, &["init", "-q", "-b", "main"]);
        git(
            &workspace,
            &["commit", "--allow-empty", "-qm", "split terminal"],
        );
        let workspace = fs::canonicalize(workspace).unwrap();
        let head = git(&workspace, &["rev-parse", "HEAD"]);
        let adapter = root.join("adapter");
        let dated = adapter.join("sessions/2026/10/06");
        fs::create_dir_all(&dated).unwrap();
        fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&dated, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            adapter.join("config.toml"),
            format!(
                "[projects.{}]\ntrust_level = \"trusted\"\n",
                serde_json::to_string(workspace.to_str().unwrap()).unwrap()
            ),
        )
        .unwrap();

        let session = "019d0000-0000-7000-8000-00000000002c";
        let source = format!("session-rollout:{session}:{session}");
        let transcript = dated.join(format!("rollout-2026-10-06T00-00-01-{session}.jsonl"));
        let header = serde_json::json!({
            "timestamp":"2026-10-06T00:01:01Z",
            "type":"session_meta",
            "payload":{"id":session,"session_id":session,"cwd":workspace,"git":{"commit_hash":head}}
        });
        fs::write(&transcript, format!("{header}\n")).unwrap();

        let at = 1_791_244_801_000_000;
        let (writer, actor) =
            crate::spawn_writer(crate::open_writer(&root.join("data")).await.unwrap(), 16).unwrap();
        let registration_evidence = probe_repository(
            &workspace,
            HostTrustDecision::Trusted,
            &["register:split-terminal-recovery".into()],
            at - 1_000_000,
            &ProbeLimits::default(),
            &[],
            &[],
        )
        .unwrap();
        let registration = resolve_repository(&RepositoryResolveInput {
            view: &RepositoryCurrentView::default(),
            evidence: &registration_evidence,
            derived_from_hint: None,
        })
        .unwrap();
        assert_eq!(registration.kind, Some(ResolutionKind::Create));
        writer
            .commit(
                registration
                    .journal_command(at - 1_000_000, [28; 32], "split-terminal-registration")
                    .unwrap()
                    .unwrap(),
                at - 1_000_000,
            )
            .await
            .unwrap();
        let repository_view =
            RepositoryCurrentView::from_snapshot(&writer.project().await.unwrap()).unwrap();
        let source_evidence = probe_repository(
            &workspace,
            HostTrustDecision::Trusted,
            std::slice::from_ref(&source),
            at,
            &ProbeLimits::default(),
            &repository_view.known_admin_paths(),
            &[],
        )
        .unwrap();
        let source_start = resolve_repository_source_start(
            &RepositoryResolveInput {
                view: &repository_view,
                evidence: &source_evidence,
                derived_from_hint: None,
            },
            &source,
        )
        .unwrap();
        assert_eq!(source_start.kind, Some(ResolutionKind::Successor));
        writer
            .commit_if_frontier(
                source_start
                    .journal_command(at, [28; 32], "split-terminal-source-start")
                    .unwrap()
                    .unwrap(),
                at,
                repository_view.frontier,
            )
            .await
            .unwrap();

        let catalog = SessionCatalogService::new(writer.clone(), [28; 32]);
        let catalog_report = crate::repository::observe_session_catalog_report(
            transcript.to_str(),
            session,
            "split-terminal-catalog",
            None,
        )
        .unwrap();
        catalog.refresh(&catalog_report).await.unwrap();
        let observation_request = RequestId::new_v7();
        let observation_ref = format!("native_session_source_observation:{observation_request}");
        let source_report = crate::repository::observe_session_source_report(
            transcript.to_str().unwrap(),
            session,
            None,
            &observation_ref,
        )
        .unwrap();
        assert!(
            catalog
                .observe_native_session_source(
                    observation_request,
                    &source_report,
                    session,
                    transcript.to_str().unwrap(),
                    &observation_ref,
                )
                .await
                .unwrap()
        );
        let report = Arc::new(RwLock::new(Some(source_report.clone())));
        let started = writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap();
        let origin = started
            .current
            .metadata
            .prospective_origin
            .as_ref()
            .unwrap();
        let fence = origin.record_start.unwrap();
        assert!(!origin.closed);
        assert_eq!(origin.observed_end, fence);
        assert_eq!(started.current.access_decision, None);
        assert_eq!(
            started.current.metadata.workspace_resolution_kind,
            evertrace_store::WorkspaceResolutionKind::Ambiguous
        );
        assert_eq!(started.watermark, None);

        let suffix = ["split-last-1", "split-last-2"]
            .map(|id| {
                serde_json::json!({
                    "timestamp":"2026-10-06T00:01:02Z",
                    "type":"event_msg",
                    "payload":{"type":"item_completed","thread_id":session,"turn_id":id,"item":{"type":"UserMessage","id":id,"content":[{"type":"text","text":format!("split recovery {id}")}]},"completed_at_ms":1_791_244_862_000_i64}
                })
                .to_string()
            })
            .join("\n");
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&transcript)
            .unwrap();
        writeln!(file, "{suffix}").unwrap();
        drop(file);
        let end = fs::metadata(&transcript).unwrap().len();
        assert!(catalog.refresh_active(&source_report).await.unwrap() > 0);
        let queued = writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(queued.current.access_decision, None);
        assert_eq!(queued.job.as_ref().unwrap().state, JobStatus::Queued);
        assert_eq!(queued.current.body_state, SessionBodyState::Queued);

        DeviceKeyStore::new(root.join("keys"))
            .load_or_create()
            .unwrap();
        let reached = Arc::new(tokio::sync::Notify::new());
        let mut worker =
            SessionImportWorker::new(writer.clone(), test_runtime(&root), Arc::clone(&report))
                .unwrap();
        worker.terminal_handoff_pause = Some(Arc::clone(&reached));
        let running_worker = worker.clone();
        let budget = SessionImportBudget {
            max_bytes: 64 * 1024,
            max_records: 8,
            max_work_time: Duration::from_millis(250),
        };
        let running_source = source.clone();
        let running = tokio::spawn(async move {
            for _ in 0..16 {
                let progress = running_worker
                    .process_checkpoint(&running_source, budget)
                    .await?;
                if progress.completed {
                    return Ok(progress);
                }
                tokio::task::yield_now().await;
            }
            Err(SessionImportError::Budget)
        });
        if tokio::time::timeout(Duration::from_secs(10), reached.notified())
            .await
            .is_err()
        {
            let context = writer
                .session_import_context(&source)
                .await
                .unwrap()
                .unwrap();
            let result = if running.is_finished() {
                Some(format!("{:?}", running.await))
            } else {
                None
            };
            panic!(
                "split terminal pause missing: worker={result:?} body={:?} job={:?} watermark={:?} origin={:?}",
                context.current.body_state,
                context.job,
                context.watermark,
                context.current.metadata.prospective_origin
            );
        }
        assert!(!running.is_finished(), "terminal handoff must be paused");
        running.abort();
        assert!(running.await.unwrap_err().is_cancelled());

        let interrupted = writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap();
        let committed_watermark = interrupted.watermark.clone().unwrap();
        assert_eq!(committed_watermark.source_sequence, end);
        assert_eq!(
            committed_watermark
                .earlier_prefix
                .as_ref()
                .map(|prefix| prefix.through_byte),
            Some(0)
        );
        assert_eq!(interrupted.current.body_state, SessionBodyState::Importing);
        assert_eq!(interrupted.current.access_decision, None);
        let leased = interrupted.job.as_ref().unwrap();
        assert_eq!(leased.state, JobStatus::Leased);
        assert!(leased.terminal.is_none());
        let interrupted_job_id = leased.job_id;
        let interrupted_attempt = leased.attempt;
        let lease_until_us = leased.lease_until_us.unwrap();
        let durable_payloads = writer
            .project()
            .await
            .unwrap()
            .data_rows()
            .filter_map(|row| {
                match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                    JournalPayload::SourceReceiptRecorded(receipt)
                        if receipt.source_instance_id.as_str() == source =>
                    {
                        Some(serde_json::to_string(&receipt).unwrap())
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            durable_payloads.len(),
            2,
            "only the two suffix records commit"
        );
        let synced_frontier = writer.sync_frontier().await.unwrap();
        assert!(synced_frontier >= interrupted.frontier);
        drop(catalog);
        drop(worker);
        writer.shutdown().await.unwrap();
        actor.await.unwrap().unwrap();

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        if lease_until_us > now {
            tokio::time::sleep(Duration::from_micros(
                (lease_until_us - now) as u64 + 100_000,
            ))
            .await;
        }
        let (writer, actor) =
            crate::spawn_writer(crate::open_writer(&root.join("data")).await.unwrap(), 16).unwrap();
        let resumed_worker =
            SessionImportWorker::new(writer.clone(), test_runtime(&root), Arc::clone(&report))
                .unwrap();
        let recovery_catalog = SessionCatalogService::new(writer.clone(), [28; 32]);
        let recovery_scheduler = crate::BackgroundScheduler::new(
            writer.clone(),
            recovery_catalog,
            resumed_worker,
            Arc::clone(&report),
            test_runtime(&root),
            crate::SynthesisPlanner::new(evertrace_domain::config::LlmConfig {
                enabled: false,
                ..evertrace_domain::config::LlmConfig::default()
            }),
            evertrace_domain::config::DreamingConfig::default(),
        );
        let mut recovered_partial = false;
        for _ in 0..4 {
            recovery_scheduler.run_once().await.unwrap();
            let context = writer
                .session_import_context(&source)
                .await
                .unwrap()
                .unwrap();
            if context.current.body_state == SessionBodyState::Partial
                && context
                    .job
                    .as_ref()
                    .is_none_or(|job| job.state == JobStatus::Succeeded)
            {
                recovered_partial = true;
                break;
            }
        }
        assert!(
            recovered_partial,
            "restart must finish the split Partial handoff: {:?}",
            writer.session_import_context(&source).await.unwrap()
        );
        let recovered = writer
            .session_import_context(&source)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.watermark, Some(committed_watermark));
        assert_eq!(recovered.current.body_state, SessionBodyState::Partial);
        assert_eq!(recovered.current.access_decision, None);
        let terminal = writer
            .project()
            .await
            .unwrap()
            .data_rows()
            .filter_map(|row| row.payload_json.as_deref())
            .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
            .filter_map(|payload| match payload {
                JournalPayload::JobState(job) if job.job_id == interrupted_job_id => Some(job),
                _ => None,
            })
            .last()
            .expect("split source terminal state is durable");
        assert!(terminal.attempt > interrupted_attempt);
        assert_eq!(terminal.state, JobStatus::Succeeded);
        assert!(terminal.lease_until_us.is_none());
        assert_eq!(
            terminal.terminal.as_ref().unwrap().reason,
            JobTerminalReason::Completed
        );
        let recovered_project = writer.project().await.unwrap();
        let recovered_payloads = recovered_project
            .data_rows()
            .filter_map(|row| {
                match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                    JournalPayload::SourceReceiptRecorded(receipt)
                        if receipt.source_instance_id.as_str() == source =>
                    {
                        Some(serde_json::to_string(&receipt).unwrap())
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(recovered_payloads, durable_payloads);
        assert!(writer.sync_frontier().await.unwrap() >= recovered.frontier);
        let completed_frontier = recovered.frontier;
        let succeeded_events = recovered_project
            .data_rows()
            .filter_map(|row| row.payload_json.as_deref())
            .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
            .filter(|payload| {
                matches!(payload, JournalPayload::JobState(job)
                    if job.job_id == interrupted_job_id && job.state == JobStatus::Succeeded)
            })
            .count();
        assert_eq!(succeeded_events, 1);
        recovery_scheduler.run_once().await.unwrap();
        let idempotent_project = writer.project().await.unwrap();
        assert_eq!(idempotent_project.frontier, completed_frontier);
        assert_eq!(
            idempotent_project
                .data_rows()
                .filter_map(|row| row.payload_json.as_deref())
                .filter_map(|json| serde_json::from_str::<JournalPayload>(json).ok())
                .filter(|payload| {
                    matches!(payload, JournalPayload::JobState(job)
                        if job.job_id == interrupted_job_id && job.state == JobStatus::Succeeded)
                })
                .count(),
            succeeded_events
        );
        writer.shutdown().await.unwrap();
        actor.await.unwrap().unwrap();
        fs::remove_dir_all(&root).unwrap();
        fs::remove_file(root.with_extension("maintenance.lock")).unwrap();
    }

    #[test]
    fn legacy_unsupported_frame_is_narrowed_without_rewriting_input() {
        use evertrace_capture::{
            CaptureRuntime, CasStore, DeviceKeyStore, DurableSpool, SealedFrame,
        };
        use evertrace_domain::evidence::{
            CaptureCompleteness, SourceRevisionMode, UnsupportedRecordClassification,
        };
        use std::{fs, os::unix::fs::PermissionsExt};
        let root = std::env::temp_dir().join(format!(
            "evertrace-import-frame-{}",
            evertrace_domain::ids::RequestId::new_v7()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = test_runtime(&root);
        DeviceKeyStore::new(root.join("keys"))
            .load_or_create()
            .unwrap();
        let current = serde_json::from_value(serde_json::json!({
            "session_id":"019d0000-0000-7000-8000-000000000028", "revision":1,
            "access_decision":null, "body_state":"not_imported", "source_event_seq":1,
            "metadata": {
                "source_path":"2026/08/30/rollout-2026-08-30T00-00-00-019d0000-0000-7000-8000-000000000028.jsonl",
                "source_format":"codex_rollout_jsonl_v1", "started_at_us":null, "ended_at_us":null,
                "host":null, "model_profile":null, "workspace_hint":null, "repository_hint":null,
                "worktree_hint":null, "workspace_resolution_kind":"non_repository",
                "resolved_repository_instance_id":null, "resolved_worktree_instance_id":null,
                "file_size":100, "file_mtime_us":1, "source_fingerprint":"a".repeat(64),
                "source_revision":"a".repeat(64), "parser_version":1, "metadata_state":"indexed"
            }
        })).unwrap();
        for (raw, classification) in [
            (
                br#"{"type":"event_msg","payload":{"type":"unrecognized_history_event"}}"#
                    .as_slice(),
                UnsupportedRecordClassification::UnknownRecordType,
            ),
            (
                br#"{"type":"response_item","payload":{"type":"reasoning","summary":[]}}"#
                    .as_slice(),
                UnsupportedRecordClassification::Reasoning,
            ),
        ] {
            let mut input = super::capture_input(
                &current,
                raw,
                0,
                raw.len() as u64 + 1,
                SourceRevisionMode::Append,
                None,
                super::classify_record(raw).unwrap(),
            );
            assert_eq!(input.capture_completeness, CaptureCompleteness::Partial);
            assert_eq!(
                input.unsupported_record_classification,
                Some(classification)
            );
            // Reproduce the prior producer's durable declaration, without using
            // this synthetic frame as the independent old-binary migration oracle.
            input.capture_completeness = CaptureCompleteness::Complete;
            assert!(matches!(
                CaptureRuntime::open(runtime.clone())
                    .unwrap()
                    .capture(input)
                    .unwrap(),
                evertrace_capture::CaptureOutcome::Durable { .. }
            ));
            let spool = DurableSpool::open_read_only(
                runtime.spool_dir.clone(),
                runtime.spool_limits().unwrap(),
            )
            .unwrap();
            let decoded = spool.read_active().unwrap().pop().unwrap();
            let mut frame = SealedFrame {
                record: decoded.record,
                byte_start: 0,
                byte_end: decoded.frame_length,
            };
            let original = frame.record.record_body.clone();
            let cas = CasStore::open(runtime.cas_dir.clone()).unwrap();
            let verified = crate::capture::verify_capture_frame(&frame, &cas).unwrap();
            assert_eq!(
                verified.body.capture_completeness,
                CaptureCompleteness::Complete
            );
            assert_eq!(
                verified.receipt.capture_completeness,
                CaptureCompleteness::Partial
            );
            assert_eq!(
                verified.observation.capture_completeness,
                CaptureCompleteness::Partial
            );
            assert!(verified.surface.is_none());
            assert_eq!(
                verified.receipt.unsupported_record_classification,
                Some(classification)
            );
            assert_eq!(frame.record.record_body, original);
            let mut other_profile = verified.body.clone();
            other_profile.parser_revision = 2;
            frame.record.record_body =
                evertrace_capture::encode_record_body(&other_profile).unwrap();
            assert!(matches!(
                crate::capture::verify_capture_frame(&frame, &cas),
                Err(crate::ingest::IngestError::InvalidRecord)
            ));
            let mut other_classification = verified.body.clone();
            other_classification.unsupported_record_classification =
                Some(UnsupportedRecordClassification::Binary);
            frame.record.record_body =
                evertrace_capture::encode_record_body(&other_classification).unwrap();
            assert!(matches!(
                crate::capture::verify_capture_frame(&frame, &cas),
                Err(crate::ingest::IngestError::InvalidRecord)
            ));
            let mut surface_claim = verified.body;
            surface_claim.surface_eligible = true;
            frame.record.record_body = serde_json::to_vec(&surface_claim).unwrap();
            assert!(crate::capture::verify_capture_frame(&frame, &cas).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn record_ordinal_is_optional_typed_metadata_only() {
        let mut record = serde_json::json!({"type":"event_msg", "payload":{"type":"user_message", "message":"bounded"}});
        assert!(
            super::classify_record(&serde_json::to_vec(&record).unwrap())
                .unwrap()
                .surface_eligible
        );
        record["ordinal"] = 1.into();
        assert!(
            super::classify_record(&serde_json::to_vec(&record).unwrap())
                .unwrap()
                .surface_eligible
        );
        record["ordinal"] = "1".into();
        assert!(super::classify_record(&serde_json::to_vec(&record).unwrap()).is_err());
    }

    #[test]
    fn response_metadata_is_closed_typed_and_never_a_message() {
        let mut record = serde_json::json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[]}});
        for metadata in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"client_authored":true,"fallback_token_limit_override":4096}),
        ] {
            record["metadata"] = metadata;
            let visibility = classify_record(&serde_json::to_vec(&record).unwrap()).unwrap();
            assert_eq!(visibility.role, ObservationRole::Other);
            assert!(visibility.surface_eligible && visibility.unsupported.is_none());
        }
        for metadata in [
            serde_json::json!({"client_authored":"true"}),
            serde_json::json!({"fallback_token_limit_override":-1}),
            serde_json::json!({"fallback_token_limit_override":"4096"}),
            serde_json::json!({"unknown":true}),
            serde_json::json!([]),
        ] {
            record["metadata"] = metadata;
            assert!(classify_record(&serde_json::to_vec(&record).unwrap()).is_err());
        }
        record["metadata"] = serde_json::Value::Null;
        record["unknown_outer"] = true.into();
        assert!(classify_record(&serde_json::to_vec(&record).unwrap()).is_err());
    }

    #[test]
    fn completed_display_messages_require_exact_text_variants() {
        let mut record = serde_json::json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"019d0000-0000-7000-8000-000000000028","turn_id":"turn","item":null}});
        for item in [
            serde_json::json!({"type":"UserMessage","id":"u","client_id":"client","content":[{"type":"text","text":"text","text_elements":[{"byte_range":{"start":0,"end":4},"placeholder":null}]}]}),
            serde_json::json!({"type":"AgentMessage","id":"a","phase":"commentary","content":[{"type":"Text","text":"text"}]}),
            serde_json::json!({"type":"AgentMessage","id":"a","content":[{"type":"Text","text":"text"}],"memory_citation":null,"delivery":null,"questions":null}),
            serde_json::json!({"type":"AgentMessage","id":"a","content":[{"type":"Text","text":"text"}],"memory_citation":{"entries":[{"path":"notes.md","lineStart":1,"lineEnd":2,"note":"source claim"}],"rolloutIds":["prior-rollout"]},"delivery":"async","questions":[{"title":"Choose","options":["one","two"]},{"title":"Explain","options":null},{"title":"Continue"}]}),
        ] {
            record["payload"]["item"] = item;
            let visibility = classify_record(&serde_json::to_vec(&record).unwrap()).unwrap();
            assert_eq!(visibility.role, ObservationRole::Message);
            assert!(visibility.surface_eligible && visibility.unsupported.is_none());
        }
        for item in [
            serde_json::json!({"type":"agent_message","id":"a","content":[{"type":"Text","text":"text"}]}),
            serde_json::json!({"type":"AgentMessage","id":"a","content":[{"type":"text","text":"text"}]}),
            serde_json::json!({"type":"AgentMessage","id":"a","content":[{"type":"Text","text":7}]}),
            serde_json::json!({"type":"AgentMessage","id":"a","content":[{"type":"Text","text":"text","encrypted_content":"opaque"}]}),
            serde_json::json!({"type":"UserMessage","id":"u","content":[{"type":"text","text":"text"},{"type":"image","image_url":"data:image/png;base64,AA=="}]}),
            serde_json::json!({"type":"UserMessage","id":"u","content":[{"type":"text","text":"text","text_elements":"invalid"}]}),
            serde_json::json!({"type":"AgentMessage","id":"a","content":[]}),
            serde_json::json!({"type":"Reasoning","id":"r","summary_text":[],"raw_content":["not visible"]}),
            serde_json::json!({"type":"FunctionCallOutput","id":"f","name":"tool","output":"not a message"}),
        ] {
            record["payload"]["item"] = item;
            let visibility = classify_record(&serde_json::to_vec(&record).unwrap()).unwrap();
            assert_eq!(visibility.role, ObservationRole::Other);
            assert!(!visibility.surface_eligible && visibility.unsupported.is_some());
        }
        for fields in [
            serde_json::json!({"memory_citation":"opaque"}),
            serde_json::json!({"memory_citation":{"entries":[{"path":"notes.md","lineStart":-1,"lineEnd":2,"note":"claim"}],"rolloutIds":[]}}),
            serde_json::json!({"memory_citation":{"entries":[],"rolloutIds":[7]}}),
            serde_json::json!({"memory_citation":{"entries":[],"rolloutIds":[],"authority":"accepted"}}),
            serde_json::json!({"delivery":"Async"}),
            serde_json::json!({"questions":true}),
            serde_json::json!({"questions":[{"title":7}]}),
            serde_json::json!({"questions":[{"title":"Choose","options":[7]}]}),
            serde_json::json!({"questions":[{"title":"Choose","authority":"accepted"}]}),
            serde_json::json!({"unknown_field":true}),
        ] {
            let mut item = serde_json::json!({"type":"AgentMessage","id":"a","content":[{"type":"Text","text":"text"}]});
            item.as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            record["payload"]["item"] = item;
            let visibility = classify_record(&serde_json::to_vec(&record).unwrap()).unwrap();
            assert_eq!(visibility.role, ObservationRole::Other, "{fields}");
            assert!(!visibility.surface_eligible);
            assert_eq!(
                visibility.unsupported,
                Some(UnsupportedRecordClassification::UnknownRecordType),
                "{fields}"
            );
        }
    }
}

fn extend_prefix_digest(
    current: &SessionImportCurrent,
    previous: Option<String>,
    receipt: &SessionImportPrefixRecord,
) -> Result<String, SessionImportError> {
    let digest = sha256(
        PREFIX_TAG,
        1,
        &CanonicalValue::Sequence(vec![
            CanonicalValue::String(current.source_instance()),
            CanonicalValue::String(current.metadata.source_revision.as_str().to_owned()),
            CanonicalValue::Integer(i128::from(receipt.start)),
            CanonicalValue::Integer(i128::from(receipt.end)),
            previous.map_or(CanonicalValue::Null, CanonicalValue::String),
            CanonicalValue::String(receipt.cas_ref.clone()),
        ]),
    )
    .map_err(|_| SessionImportError::Persistence)?;
    Ok(hex_digest(&digest))
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Clone, Copy)]
struct RecordVisibility {
    role: ObservationRole,
    unsupported: Option<UnsupportedRecordClassification>,
    surface_eligible: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordKind {
    #[serde(rename = "ordinal")]
    _ordinal: Option<u64>,
    #[serde(rename = "type")]
    record_type: String,
    payload: serde_json::Value,
    timestamp: Option<String>,
    metadata: Option<ResponseMetadata>,
}

// Fixed history wire at 3d2ee51ca2d5db578f328aa75e20aa22c0197c9a:
// history/src/{lib,rollout_payload}.rs. These fields are archive metadata only;
// response items remain Other and cannot enter Message-only synthesis.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseMetadata {
    #[serde(default, rename = "client_authored")]
    _client_authored: bool,
    #[serde(rename = "fallback_token_limit_override")]
    _fallback_token_limit_override: Option<usize>,
}

// The supported display-message subset of protocol/src/{protocol,items,user_input}.rs
// at the same fixed source. Unknown/complex content remains an archived Other;
// no raw ResponseItem or other TurnItem becomes a message by resemblance.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedMessageEvent {
    #[serde(rename = "type")]
    _event_type: String,
    #[serde(rename = "thread_id")]
    _thread_id: String,
    #[serde(rename = "turn_id")]
    _turn_id: String,
    item: CompletedMessage,
    #[serde(rename = "started_at_ms")]
    _started_at_ms: Option<i64>,
    #[serde(default, rename = "completed_at_ms")]
    _completed_at_ms: i64,
}

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum CompletedMessage {
    UserMessage {
        #[serde(rename = "id")]
        _id: String,
        #[serde(rename = "client_id")]
        _client_id: Option<String>,
        content: Vec<UserText>,
    },
    AgentMessage {
        #[serde(rename = "id")]
        _id: String,
        content: Vec<AgentText>,
        #[serde(rename = "phase")]
        _phase: Option<MessagePhase>,
        #[serde(rename = "memory_citation")]
        _memory_citation: Option<MessageCitation>,
        #[serde(rename = "delivery")]
        _delivery: Option<MessageDelivery>,
        #[serde(rename = "questions")]
        _questions: Option<Vec<MessageQuestion>>,
    },
}

// Optional display fields are source content, never authority or adoption proof.
// Shapes follow the same fixed protocol/src/{items,memory_citation}.rs wire.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageCitation {
    #[serde(rename = "entries")]
    _entries: Vec<MessageCitationEntry>,
    #[serde(rename = "rolloutIds")]
    _rollout_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageCitationEntry {
    #[serde(rename = "path")]
    _path: String,
    #[serde(rename = "lineStart")]
    _line_start: u32,
    #[serde(rename = "lineEnd")]
    _line_end: u32,
    #[serde(rename = "note")]
    _note: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum MessageDelivery {
    Async,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageQuestion {
    #[serde(rename = "title")]
    _title: String,
    #[serde(rename = "options")]
    _options: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum MessagePhase {
    Commentary,
    FinalAnswer,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum UserText {
    Text {
        text: String,
        #[serde(default, rename = "text_elements")]
        _text_elements: Vec<TextElement>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TextElement {
    #[serde(rename = "byte_range")]
    _byte_range: TextByteRange,
    #[serde(rename = "placeholder")]
    _placeholder: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TextByteRange {
    #[serde(rename = "start")]
    _start: usize,
    #[serde(rename = "end")]
    _end: usize,
}

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum AgentText {
    Text { text: String },
}

fn completed_message_visibility(payload: &serde_json::Value) -> RecordVisibility {
    let message = CompletedMessageEvent::deserialize(payload)
        .ok()
        .is_some_and(|event| match event.item {
            CompletedMessage::UserMessage { content, .. } => content
                .iter()
                .any(|UserText::Text { text, .. }| !text.trim().is_empty()),
            CompletedMessage::AgentMessage { content, .. } => content
                .iter()
                .any(|AgentText::Text { text }| !text.trim().is_empty()),
        });
    RecordVisibility {
        role: if message {
            ObservationRole::Message
        } else {
            ObservationRole::Other
        },
        unsupported: (!message).then_some(
            if payload["item"]["type"].as_str() == Some("Reasoning") {
                UnsupportedRecordClassification::Reasoning
            } else {
                UnsupportedRecordClassification::UnknownRecordType
            },
        ),
        surface_eligible: message,
    }
}

fn classify_record(bytes: &[u8]) -> Result<RecordVisibility, SessionImportError> {
    let record: RecordKind =
        serde_json::from_slice(bytes).map_err(|_| SessionImportError::Unsupported)?;
    let _ = &record.timestamp;
    if record.metadata.is_some() && record.record_type != "response_item" {
        return Err(SessionImportError::Unsupported);
    }
    Ok(match record.record_type.as_str() {
        "session_meta" | "turn_context" => RecordVisibility {
            role: ObservationRole::StateProbe,
            unsupported: None,
            surface_eligible: false,
        },
        "event_msg"
            if matches!(
                record.payload.get("type").and_then(|value| value.as_str()),
                Some("user_message" | "agent_message")
            ) =>
        {
            RecordVisibility {
                role: ObservationRole::Message,
                unsupported: None,
                surface_eligible: true,
            }
        }
        "event_msg" if record.payload["type"].as_str() == Some("item_completed") => {
            completed_message_visibility(&record.payload)
        }
        "event_msg" => RecordVisibility {
            role: ObservationRole::Other,
            unsupported: Some(UnsupportedRecordClassification::UnknownRecordType),
            surface_eligible: false,
        },
        "response_item"
            if record.payload.get("type").and_then(|value| value.as_str()) == Some("reasoning") =>
        {
            RecordVisibility {
                role: ObservationRole::Other,
                unsupported: Some(UnsupportedRecordClassification::Reasoning),
                surface_eligible: false,
            }
        }
        "response_item"
            if matches!(
                record.payload.get("type").and_then(|value| value.as_str()),
                Some("message" | "function_call" | "function_call_output")
            ) =>
        {
            RecordVisibility {
                role: ObservationRole::Other,
                unsupported: None,
                surface_eligible: true,
            }
        }
        "response_item" => RecordVisibility {
            role: ObservationRole::Other,
            unsupported: Some(UnsupportedRecordClassification::UnknownRecordType),
            surface_eligible: false,
        },
        _ => RecordVisibility {
            role: ObservationRole::Other,
            unsupported: Some(UnsupportedRecordClassification::UnknownRecordType),
            surface_eligible: false,
        },
    })
}

fn import_record_id(current: &SessionImportCurrent, start: u64, end: u64) -> String {
    if current.source_instance_id.is_some() {
        format!(
            "session-import-{}-{}-{start}-{end}",
            current.source_instance(),
            current.metadata.source_revision.as_str()
        )
    } else {
        format!("session-import-{}-{start}-{end}", current.session_id)
    }
}

fn capture_input(
    current: &SessionImportCurrent,
    line: &[u8],
    start: u64,
    end: u64,
    mode: SourceRevisionMode,
    previous: Option<&SourceRevision>,
    visibility: RecordVisibility,
) -> CaptureRecordInput {
    CaptureRecordInput {
        source_local_evidence: None,
        spool_record_id: Some(import_record_id(current, start, end)),
        source_observation_id_hint: None,
        source_instance_id: current.source_instance(),
        source_revision: current.metadata.source_revision.as_str().to_owned(),
        source_record_identity: Some(format!("bytes:{start}-{end}")),
        identity_strength: Some(IdentityStrength::StableSourceSequence),
        source_kind: EvidenceSourceKind::CodexSessionJsonl,
        identity_domain: "codex-session-jsonl-v1".into(),
        source_ref: format!("session:{}", current.session_id),
        session_ref: current.session_id.clone(),
        turn_ref: None,
        tool_ref: None,
        source_sequence: end,
        source_sequence_origin: Some(0),
        task_id: None,
        repository_instance_id: current
            .metadata
            .resolved_repository_instance_id
            .map(|id| id.to_string()),
        worktree_instance_id: current
            .metadata
            .resolved_worktree_instance_id
            .map(|id| id.to_string()),
        source_byte_range: Some(EvidenceByteRange { start, end }),
        source_revision_mode: mode,
        previous_source_revision: if mode == SourceRevisionMode::Replacement {
            previous.map(|value| value.as_str().to_owned())
        } else {
            None
        },
        close_watermark: None,
        observation_role: visibility.role,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            pairing_role: visibility.role,
            field_provenance: Vec::new(),
            adapter_manifest_ref: "codex-session-import-v1".into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: Vec::new(),
        lifecycle: None,
        unsupported_record_classification: visibility.unsupported,
        source_role: SourceRole::Imported,
        content_trust: ContentTrust::ImportedClaim,
        capture_completeness: if visibility.unsupported.is_some() {
            CaptureCompleteness::Partial
        } else {
            CaptureCompleteness::Complete
        },
        surface_eligible: visibility.surface_eligible,
        adapter_revision: 1,
        adapter_manifest_ref: "codex-session-import-v1".into(),
        eligible_event_manifest_ref: "codex-session-import-events-v1".into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: None,
        raw_payload: line.to_vec(),
    }
}

fn now_us() -> Result<i64, SessionImportError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_micros()).ok())
        .ok_or(SessionImportError::Persistence)
}
