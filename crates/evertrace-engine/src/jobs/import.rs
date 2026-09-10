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
    BodyStateReason, EventScope, JobLease, JobStatus, JobTerminalAudit, JobTerminalOutcome,
    JobTerminalReason, JournalCommand, JournalEventDraft, JournalPayload, SessionBodyState,
    SessionImportContext, SessionImportCurrent, SessionImportEvent, SessionImportEventKind,
    SessionImportPrefixRecord, SessionImportPrefixRequest, SourceKind,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedPrefix {
    source_key: String,
    source_revision: SourceRevision,
    identity: ConfinedFileIdentity,
    protection_key: DeviceKey,
    config_hash: [u8; 32],
    target_end: u64,
    target_digest: String,
    end: u64,
    digest: Option<String>,
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
        let (ready, prefix_bytes) = match self
            .verify_confirmed_prefix(&context, (&root, &relative, identity), &key, budget)
            .await
        {
            Ok(value) => value,
            Err(SessionImportError::Changed) => {
                self.mark_source_replaced(current, identity).await?;
                return Err(SessionImportError::Changed);
            }
            Err(error) => return Err(error),
        };
        // A prefix page is its own read-only quantum: no body, watermark or
        // empty lease is produced, even when this page finishes the proof.
        if !ready || prefix_bytes != 0 {
            return Ok(SessionImportProgress {
                records: 0,
                bytes: prefix_bytes,
                completed: false,
            });
        }
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
        if fresh.current.metadata != current.metadata
            || fresh.watermark != context.watermark
            || fresh_identity != identity
            || fresh_key != key
        {
            self.verified_prefix.lock().await.remove(session_id);
            return Err(SessionImportError::Budget);
        }
        self.claim_job(&fresh).await?;
        let current = &fresh.current;
        let offset = fresh
            .watermark
            .as_ref()
            .map_or(0, |value| value.source_sequence);
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
        while consumed < budget.max_bytes && observations.len() < budget.max_records {
            if Instant::now() >= deadline {
                break;
            }
            let remaining = budget.max_bytes - consumed;
            let chunk = root
                .read_range(
                    &relative,
                    identity,
                    cursor,
                    CHUNK_BYTES.min(remaining),
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
                let mode = if offset == 0 && observations.is_empty() && previous_revision.is_some()
                {
                    SourceRevisionMode::Replacement
                } else {
                    SourceRevisionMode::Append
                };
                let outcome = CaptureRuntime::open(self.runtime.clone())
                    .map_err(|_| SessionImportError::Persistence)?
                    .capture(capture_input(
                        current,
                        line,
                        line_start,
                        line_end,
                        mode,
                        previous_revision.as_ref(),
                        visibility,
                    ))
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
            eof = chunk.eof;
            if eof || observations.len() == budget.max_records {
                break;
            }
        }
        if observations.is_empty() {
            if eof && pending.is_empty() {
                let latest = self.current(session_id).await?;
                root.revalidate_file(&relative, identity)
                    .map_err(map_source_read)?;
                self.advance(
                    &latest,
                    SessionBodyState::Imported,
                    BodyStateReason::Completed,
                )
                .await?;
                root.revalidate_file(&relative, identity)
                    .map_err(map_source_read)?;
                self.verified_prefix.lock().await.remove(session_id);
                return Ok(SessionImportProgress {
                    records: 0,
                    bytes: consumed,
                    completed: true,
                });
            }
            return Err(SessionImportError::Budget);
        }
        ingestor
            .drain_observations_once(&observations)
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        let confirmed = self.context(session_id).await?;
        let watermark = confirmed
            .watermark
            .as_ref()
            .filter(|watermark| watermark.source_sequence == pending_start)
            .ok_or(SessionImportError::Persistence)?;
        let confirmed_digest = watermark
            .confirmed_prefix_digest
            .clone()
            .ok_or(SessionImportError::Persistence)?;
        let latest = confirmed.current;
        let completed = eof && pending.is_empty();
        root.revalidate_file(&relative, identity)
            .map_err(map_source_read)?;
        self.advance(
            &latest,
            if completed {
                SessionBodyState::Imported
            } else {
                SessionBodyState::Partial
            },
            if completed {
                BodyStateReason::Completed
            } else {
                BodyStateReason::BudgetExhausted
            },
        )
        .await?;
        root.revalidate_file(&relative, identity)
            .map_err(map_source_read)?;
        if completed {
            self.verified_prefix.lock().await.remove(session_id);
        } else {
            self.remember_prefix(VerifiedPrefix {
                source_key: current.source_key(),
                source_revision: current.metadata.source_revision.clone(),
                identity,
                protection_key: key,
                config_hash: self.runtime.effective_config_hash,
                target_end: pending_start,
                target_digest: confirmed_digest.clone(),
                end: pending_start,
                digest: Some(confirmed_digest),
            })
            .await;
        }
        Ok(SessionImportProgress {
            records: observations.len(),
            bytes: consumed,
            completed,
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

    async fn verify_confirmed_prefix(
        &self,
        context: &SessionImportContext,
        source: (&ConfinedRoot, &std::path::Path, ConfinedFileIdentity),
        key: &DeviceKey,
        budget: SessionImportBudget,
    ) -> Result<(bool, usize), SessionImportError> {
        let current = &context.current;
        let (root, relative, identity) = source;
        let end = context
            .watermark
            .as_ref()
            .map_or(0, |value| value.source_sequence);
        if end == 0 {
            if context.recorded_prefix_end.is_some_and(|value| value != 0) {
                return Err(SessionImportError::Changed);
            }
            return Ok((true, 0));
        }
        let target_digest = context
            .watermark
            .as_ref()
            .and_then(|value| value.confirmed_prefix_digest.clone())
            .ok_or(SessionImportError::Changed)?;
        let mut cached = self
            .verified_prefix
            .lock()
            .await
            .get(&current.source_key())
            .cloned()
            .filter(|cached| {
                cached.source_revision == current.metadata.source_revision
                    && cached.identity == identity
                    && &cached.protection_key == key
                    && cached.config_hash == self.runtime.effective_config_hash
                    && cached.target_end <= end
                    && (cached.target_end != end || cached.target_digest == target_digest)
            })
            .unwrap_or_else(|| VerifiedPrefix {
                source_key: current.source_key(),
                source_revision: current.metadata.source_revision.clone(),
                identity,
                protection_key: key.clone(),
                config_hash: self.runtime.effective_config_hash,
                target_end: end,
                target_digest: target_digest.clone(),
                end: 0,
                digest: None,
            });
        cached.target_end = end;
        cached.target_digest = target_digest;
        if cached.end == end {
            return if cached.digest.as_ref() == Some(&cached.target_digest) {
                Ok((true, 0))
            } else {
                Err(SessionImportError::Changed)
            };
        }
        if !self.reserve_prefix_slot(&cached.source_key).await? {
            return Err(SessionImportError::Budget);
        }
        // Actor queue time is preparation, not file work. The returned page is
        // bounded by the same item/byte caps as this single reading quantum.
        let page = self
            .writer
            .session_import_prefix_page(SessionImportPrefixRequest {
                source: cached.source_key.clone(),
                revision: cached.source_revision.clone(),
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
        self.remember_prefix(cached).await;
        Ok((ready, bytes))
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

    async fn remember_prefix(&self, prefix: VerifiedPrefix) {
        let mut cache = self.verified_prefix.lock().await;
        if cache.get(&prefix.source_key).is_some_and(|old| {
            old.source_revision == prefix.source_revision
                && old.identity == prefix.identity
                && old.protection_key == prefix.protection_key
                && old.config_hash == prefix.config_hash
                && old.target_end == prefix.target_end
                && old.target_digest == prefix.target_digest
                && old.end > prefix.end
        }) {
            return;
        }
        if cache.contains_key(&prefix.source_key)
            || cache.len() < crate::maintenance::PER_LANE_LIMIT
        {
            cache.insert(prefix.source_key.clone(), prefix);
        }
    }

    async fn claim_job(&self, context: &SessionImportContext) -> Result<(), SessionImportError> {
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
                payload: JournalPayload::JobLease(JobLease {
                    job_id: job.job_id,
                    target_generation: job.target_generation,
                    attempt,
                    lease_until_us,
                }),
            }],
        )
        .map_err(|_| SessionImportError::Persistence)?;
        #[cfg(test)]
        tokio::time::sleep(self.claim_delay).await;
        self.writer
            .commit_if_frontier(command, now, context.frontier)
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        Ok(())
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
        let occurred_at_us = now_us()?;
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
        if body_state == SessionBodyState::Partial {
            if let Some(mut job) = self.context(&current.source_key()).await?.job {
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
        ) && let Some(mut job) = self.context(&current.source_key()).await?.job
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
        // Revoke after the proof is complete but before a new body claim.
        admin
            .handle(
                RequestId::new_v7(),
                session,
                SessionImportAdminAction::RevokeAccess,
                20,
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
                21,
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
