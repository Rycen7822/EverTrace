//! One bounded checkpoint of the durable Codex session import job.

use std::{path::PathBuf, sync::Arc, time::Instant};

use evertrace_capture::{
    CaptureOutcome, CaptureRecordInput, CaptureRuntime, ConfinedEntryType, ConfinedFileIdentity,
    ConfinedRoot, DeviceKeyStore, DurableSpool, RuntimeSnapshot, protect,
};
use evertrace_codex::{
    HostProbeReport, adapter_manifest::SessionCatalogRootKind, policy::RepositoryTrustState,
    source_catalog::qualify_requested_session_root,
};
use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceByteRange,
        EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength, ObservationRole,
        SourceInstanceId, SourceReceipt, SourceRecordIdentity, SourceRevision, SourceRevisionMode,
        SourceRole, UnsupportedRecordClassification, source_observation_id,
    },
    ids::{CommandId, RequestId},
};
use evertrace_store::{
    BodyStateReason, EventScope, JobLease, JobStatus, JobTerminalAudit, JobTerminalOutcome,
    JobTerminalReason, JournalCommand, JournalEventDraft, JournalPayload, SessionAccessDecision,
    SessionBodyState, SessionImportCurrent, SessionImportCurrentView, SessionImportEvent,
    SessionImportEventKind, SourceIngestWatermark, SourceKind, WorkspaceResolutionKind,
    repository::RepositoryCurrentView,
};
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

use crate::{
    EvidenceIngestor, WriterHandle,
    repository::read_report_repository_trust,
    session_import::{active_import_job, session_source_fingerprint},
};

const CHUNK_BYTES: usize = 16 * 1024;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_RECORDS: usize = 16;
const PREFIX_TAG: &str = "session_import_confirmed_prefix";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionImportBudget {
    pub max_bytes: usize,
    pub max_records: usize,
    pub deadline: Instant,
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
    verified_prefix: Arc<Mutex<Option<VerifiedPrefix>>>,
    next_session: Arc<Mutex<Option<String>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedPrefix {
    source_revision: SourceRevision,
    identity: ConfinedFileIdentity,
    end: u64,
    digest: String,
}

impl SessionImportWorker {
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
            verified_prefix: Arc::new(Mutex::new(None)),
            next_session: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn process_checkpoint(
        &self,
        session_id: &str,
        budget: SessionImportBudget,
    ) -> Result<SessionImportProgress, SessionImportError> {
        if budget.max_bytes == 0 || budget.max_records == 0 || budget.max_records > MAX_RECORDS {
            return Err(SessionImportError::Budget);
        }
        let report_guard = Arc::clone(&self.report).read_owned().await;
        let report = report_guard
            .as_ref()
            .ok_or(SessionImportError::Unavailable)?;
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        let sessions = SessionImportCurrentView::from_snapshot(&snapshot)
            .map_err(|_| SessionImportError::Persistence)?;
        let current = sessions
            .sessions
            .get(session_id)
            .ok_or(SessionImportError::Unavailable)?;
        if !matches!(
            current.body_state,
            SessionBodyState::Queued | SessionBodyState::Importing | SessionBodyState::Partial
        ) {
            return Err(SessionImportError::Unavailable);
        }
        self.claim_job(&snapshot, session_id).await?;
        let (root, relative, identity) =
            match self.authorized_source(report, &snapshot, current, budget.deadline) {
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
                Err(error) => return Err(error),
            };
        let (offset, previous_revision) =
            source_position(&snapshot, session_id, &current.metadata.source_revision)?;
        let prior_digest = match self
            .verify_confirmed_prefix(
                &snapshot,
                current,
                (&root, &relative, identity),
                offset,
                budget.deadline,
            )
            .await
        {
            Ok(value) => value,
            Err(SessionImportError::Changed) => {
                self.mark_source_replaced(current, identity).await?;
                return Err(SessionImportError::Changed);
            }
            Err(SessionImportError::Unavailable) => {
                let blocked = match current.metadata.workspace_resolution_kind {
                    WorkspaceResolutionKind::Repository => Some((
                        SessionBodyState::BlockedUntrusted,
                        BodyStateReason::TrustUnavailable,
                    )),
                    WorkspaceResolutionKind::NonRepository
                        if current.access_decision != Some(SessionAccessDecision::Approved) =>
                    {
                        Some((
                            SessionBodyState::BlockedUnapproved,
                            BodyStateReason::ApprovalUnavailable,
                        ))
                    }
                    WorkspaceResolutionKind::Ambiguous | WorkspaceResolutionKind::Unavailable => {
                        Some((
                            SessionBodyState::BlockedScopeUnresolved,
                            BodyStateReason::ScopeUnresolved,
                        ))
                    }
                    WorkspaceResolutionKind::NonRepository => None,
                };
                if let Some((state, reason)) = blocked {
                    self.advance(current, state, reason).await?;
                }
                return Err(SessionImportError::Unavailable);
            }
            Err(error) => return Err(error),
        };
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
        let ingestor = EvidenceIngestor::new(
            self.runtime.clone(),
            self.writer.clone(),
            self.runtime.effective_config_hash,
            "session_import_v1",
        )
        .map_err(|_| SessionImportError::Persistence)?;
        let source_instance = SourceInstanceId::parse(format!("codex-session:{session_id}"))
            .map_err(|_| SessionImportError::Unsupported)?;
        let mut cursor = offset;
        let mut pending_start = offset;
        let mut pending = Vec::new();
        let mut consumed = 0_usize;
        let mut observations = Vec::new();
        let mut eof = false;
        while consumed < budget.max_bytes && observations.len() < budget.max_records {
            if Instant::now() >= budget.deadline {
                break;
            }
            let remaining = budget.max_bytes - consumed;
            let chunk = root
                .read_range(
                    &relative,
                    identity,
                    cursor,
                    CHUNK_BYTES.min(remaining),
                    budget.deadline,
                )
                .map_err(|_| SessionImportError::Changed)?;
            if chunk.bytes.is_empty() && !chunk.eof {
                return Err(SessionImportError::Changed);
            }
            consumed += chunk.bytes.len();
            pending.extend_from_slice(&chunk.bytes);
            cursor = chunk.next_offset;
            let mut used = 0_usize;
            while observations.len() < budget.max_records {
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
                let spool_record_id = format!(
                    "session-import-{}-{line_start}-{line_end}",
                    current.session_id
                );
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
                self.advance(
                    &latest,
                    SessionBodyState::Imported,
                    BodyStateReason::Completed,
                )
                .await?;
                if let Some(digest) = prior_digest {
                    *self.verified_prefix.lock().await = Some(VerifiedPrefix {
                        source_revision: current.metadata.source_revision.clone(),
                        identity,
                        end: offset,
                        digest,
                    });
                }
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
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        let watermark = latest_watermark(&projected, current)?
            .filter(|watermark| watermark.source_sequence == pending_start)
            .ok_or(SessionImportError::Persistence)?;
        let confirmed_digest = watermark
            .confirmed_prefix_digest
            .clone()
            .ok_or(SessionImportError::Persistence)?;
        let latest = SessionImportCurrentView::from_snapshot(&projected)
            .map_err(|_| SessionImportError::Persistence)?
            .sessions
            .get(session_id)
            .cloned()
            .ok_or(SessionImportError::Unavailable)?;
        let completed = eof && pending.is_empty();
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
        *self.verified_prefix.lock().await = Some(VerifiedPrefix {
            source_revision: current.metadata.source_revision.clone(),
            identity,
            end: pending_start,
            digest: confirmed_digest,
        });
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
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        let sessions = SessionImportCurrentView::from_snapshot(&snapshot)
            .map_err(|_| SessionImportError::Persistence)?;
        let queued = sessions
            .sessions
            .values()
            .filter(|current| {
                matches!(
                    current.body_state,
                    SessionBodyState::Queued
                        | SessionBodyState::Importing
                        | SessionBodyState::Partial
                )
            })
            .map(|current| current.session_id.clone())
            .collect::<Vec<_>>();
        let mut cursor = self.next_session.lock().await;
        let selected = fair_sessions(&queued, cursor.as_deref(), limit);
        if let Some(last) = selected.last() {
            *cursor = Some(last.clone());
        }
        drop(cursor);
        let mut processed = 0;
        let mut retryable = queued.len() > selected.len();
        for session_id in selected {
            if Instant::now() >= budget.deadline {
                retryable = true;
                break;
            }
            match self.process_checkpoint(&session_id, budget).await {
                Ok(progress) => {
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
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        SessionImportCurrentView::from_snapshot(&snapshot)
            .map_err(|_| SessionImportError::Persistence)?
            .sessions
            .remove(session_id)
            .ok_or(SessionImportError::Unavailable)
    }

    async fn verify_confirmed_prefix(
        &self,
        snapshot: &evertrace_store::ProjectionSnapshot,
        current: &SessionImportCurrent,
        source: (&ConfinedRoot, &std::path::Path, ConfinedFileIdentity),
        end: u64,
        deadline: Instant,
    ) -> Result<Option<String>, SessionImportError> {
        let (root, relative, identity) = source;
        if end == 0 {
            return Ok(None);
        }
        if let Some(cached) = self.verified_prefix.lock().await.as_ref()
            && cached.source_revision == current.metadata.source_revision
            && cached.identity == identity
            && cached.end == end
        {
            return Ok(Some(cached.digest.clone()));
        }
        let receipts = prefix_receipts(snapshot, current, end)?;
        let key = DeviceKeyStore::new(self.runtime.device_key_dir.clone())
            .load()
            .map_err(|_| SessionImportError::Persistence)?;
        for receipt in &receipts {
            let length = receipt
                .end
                .checked_sub(receipt.start)
                .ok_or(SessionImportError::Changed)?;
            let range = root
                .read_range(
                    relative,
                    identity,
                    receipt.start,
                    usize::try_from(length).map_err(|_| SessionImportError::Budget)?,
                    deadline,
                )
                .map_err(|_| SessionImportError::Changed)?;
            if range.bytes.len()
                != usize::try_from(length).map_err(|_| SessionImportError::Budget)?
                || range.bytes.last() != Some(&b'\n')
            {
                return Err(SessionImportError::Changed);
            }
            let protected = protect(&range.bytes[..range.bytes.len() - 1], &key)
                .map_err(|_| SessionImportError::Persistence)?;
            if evertrace_capture::CasDigest::for_protected_bytes(protected.protected_bytes())
                .as_hex()
                != receipt.cas_ref
            {
                return Err(SessionImportError::Changed);
            }
        }
        let digest = prefix_digest(current, &receipts)?;
        let stored = latest_watermark(snapshot, current)?.ok_or(SessionImportError::Changed)?;
        if stored.source_sequence != end
            || stored.confirmed_prefix_digest.as_ref() != digest.as_ref()
        {
            return Err(SessionImportError::Changed);
        }
        Ok(digest)
    }

    async fn claim_job(
        &self,
        snapshot: &evertrace_store::ProjectionSnapshot,
        session_id: &str,
    ) -> Result<(), SessionImportError> {
        let Some(job) =
            active_import_job(snapshot, session_id).map_err(|_| SessionImportError::Persistence)?
        else {
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
                    session_id: Some(session_id.to_owned()),
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
        self.writer
            .commit_if_frontier(command, now, snapshot.frontier)
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
                session_id: current.session_id.clone(),
                revision: current.revision + 2,
                predecessor_revision: Some(current.revision + 1),
                occurred_at_us,
                event: SessionImportEventKind::MetadataObserved {
                    metadata: Box::new(metadata),
                },
            },
        )));
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| SessionImportError::Persistence)?;
        if let Some(mut job) = active_import_job(&snapshot, &current.session_id)
            .map_err(|_| SessionImportError::Persistence)?
        {
            job.state = JobStatus::Failed;
            job.lease_until_us = None;
            job.terminal = Some(Box::new(terminal_audit(
                JobTerminalOutcome::Failed,
                JobTerminalReason::SourceReplaced,
                &current.session_id,
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
        *self.verified_prefix.lock().await = None;
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
            session_id: current.session_id.clone(),
            revision: current.revision + 1,
            predecessor_revision: Some(current.revision),
            occurred_at_us,
            event: SessionImportEventKind::BodyStateAdvanced { body_state, reason },
        };
        let mut payloads = vec![JournalPayload::SessionImportEventRecorded(Box::new(event))];
        if body_state == SessionBodyState::Partial {
            let snapshot = self
                .writer
                .project()
                .await
                .map_err(|_| SessionImportError::Persistence)?;
            if let Some(mut job) = active_import_job(&snapshot, &current.session_id)
                .map_err(|_| SessionImportError::Persistence)?
            {
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
        ) {
            let snapshot = self
                .writer
                .project()
                .await
                .map_err(|_| SessionImportError::Persistence)?;
            if let Some(mut job) = active_import_job(&snapshot, &current.session_id)
                .map_err(|_| SessionImportError::Persistence)?
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
                    &current.session_id,
                )));
                payloads.push(JournalPayload::JobState(job));
            }
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
        if body_state == SessionBodyState::SourceReplaced {
            *self.verified_prefix.lock().await = None;
        }
        Ok(())
    }

    fn authorized_source(
        &self,
        report: &HostProbeReport,
        snapshot: &evertrace_store::ProjectionSnapshot,
        current: &SessionImportCurrent,
        deadline: Instant,
    ) -> Result<(ConfinedRoot, PathBuf, ConfinedFileIdentity), SessionImportError> {
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
        match current.metadata.workspace_resolution_kind {
            WorkspaceResolutionKind::Repository => {
                let worktree = current
                    .metadata
                    .resolved_worktree_instance_id
                    .ok_or(SessionImportError::Unavailable)?;
                let repositories = RepositoryCurrentView::from_snapshot(snapshot)
                    .map_err(|_| SessionImportError::Persistence)?;
                if read_report_repository_trust(report, &repositories, worktree).state
                    != RepositoryTrustState::Trusted
                {
                    return Err(SessionImportError::Unavailable);
                }
            }
            WorkspaceResolutionKind::NonRepository
                if current.access_decision == Some(SessionAccessDecision::Approved) => {}
            _ => return Err(SessionImportError::Unavailable),
        }
        let relative = PathBuf::from(&current.metadata.source_path);
        let parent = relative.parent().ok_or(SessionImportError::Unsupported)?;
        let file_name = relative
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(SessionImportError::Unsupported)?;
        let root = ConfinedRoot::open_owned_private(qualified.path())
            .map_err(|_| SessionImportError::Unavailable)?;
        let entries = root
            .list_directory(Some(parent), 1024, deadline)
            .map_err(|_| SessionImportError::Changed)?;
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
        Ok((root, relative, identity))
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

fn fair_sessions(queued: &[String], after: Option<&str>, limit: usize) -> Vec<String> {
    let start = after
        .and_then(|last| queued.iter().position(|session| session.as_str() > last))
        .unwrap_or(0);
    queued
        .iter()
        .cycle()
        .skip(start)
        .take(limit.min(queued.len()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::fair_sessions;

    #[test]
    fn fair_cursor_reaches_sessions_beyond_the_first_batch() {
        let queued = (0..40)
            .map(|value| format!("session-{value:02}"))
            .collect::<Vec<_>>();
        let first = fair_sessions(&queued, None, 32);
        let second = fair_sessions(&queued, first.last().map(String::as_str), 32);
        assert_eq!(first.first().map(String::as_str), Some("session-00"));
        assert_eq!(first.last().map(String::as_str), Some("session-31"));
        assert_eq!(second.first().map(String::as_str), Some("session-32"));
        assert!(second.iter().any(|session| session == "session-39"));
    }
}

#[derive(Clone)]
struct PrefixReceipt {
    start: u64,
    end: u64,
    cas_ref: String,
}

fn prefix_receipts(
    snapshot: &evertrace_store::ProjectionSnapshot,
    current: &SessionImportCurrent,
    end: u64,
) -> Result<Vec<PrefixReceipt>, SessionImportError> {
    let instance = format!("codex-session:{}", current.session_id);
    let mut receipts = snapshot
        .data_rows()
        .filter_map(|row| {
            let json = row.payload_json.as_deref()?;
            let Ok(JournalPayload::SourceReceiptRecorded(receipt)) = serde_json::from_str(json)
            else {
                return None;
            };
            (receipt.source_instance_id.as_str() == instance
                && receipt.source_revision == current.metadata.source_revision)
                .then_some(*receipt)
        })
        .map(|receipt: SourceReceipt| {
            let range = receipt
                .source_byte_range
                .ok_or(SessionImportError::Changed)?;
            Ok(PrefixReceipt {
                start: range.start,
                end: range.end,
                cas_ref: receipt.cas_ref,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    receipts.retain(|receipt| receipt.end <= end);
    receipts.sort_by_key(|receipt| (receipt.start, receipt.end));
    let mut cursor = 0_u64;
    for receipt in &receipts {
        if receipt.start != cursor || receipt.end <= receipt.start {
            return Err(SessionImportError::Changed);
        }
        cursor = receipt.end;
    }
    if cursor != end {
        return Err(SessionImportError::Changed);
    }
    Ok(receipts)
}

fn prefix_digest(
    current: &SessionImportCurrent,
    receipts: &[PrefixReceipt],
) -> Result<Option<String>, SessionImportError> {
    let mut previous: Option<String> = None;
    for receipt in receipts {
        let digest = sha256(
            PREFIX_TAG,
            1,
            &CanonicalValue::Sequence(vec![
                CanonicalValue::String(format!("codex-session:{}", current.session_id)),
                CanonicalValue::String(current.metadata.source_revision.as_str().to_owned()),
                CanonicalValue::Integer(i128::from(receipt.start)),
                CanonicalValue::Integer(i128::from(receipt.end)),
                previous
                    .clone()
                    .map_or(CanonicalValue::Null, CanonicalValue::String),
                CanonicalValue::String(receipt.cas_ref.clone()),
            ]),
        )
        .map_err(|_| SessionImportError::Persistence)?;
        previous = Some(hex_digest(&digest));
    }
    Ok(previous)
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

fn latest_watermark(
    snapshot: &evertrace_store::ProjectionSnapshot,
    current: &SessionImportCurrent,
) -> Result<Option<SourceIngestWatermark>, SessionImportError> {
    let instance = format!("codex-session:{}", current.session_id);
    let mut found: Option<SourceIngestWatermark> = None;
    for row in snapshot.data_rows() {
        let Some(json) = row.payload_json.as_deref() else {
            continue;
        };
        let Ok(JournalPayload::SourceIngestWatermark(value)) = serde_json::from_str(json) else {
            continue;
        };
        if value.source_instance_id.as_str() == instance
            && value.source_revision == current.metadata.source_revision
            && found.as_ref().is_none_or(|old| {
                old.source_sequence < value.source_sequence
                    || (old.source_sequence == value.source_sequence
                        && old.confirmed_prefix_digest.is_none()
                        && value.confirmed_prefix_digest.is_some())
            })
        {
            found = Some(value);
        }
    }
    Ok(found)
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
    #[serde(rename = "type")]
    record_type: String,
    payload: serde_json::Value,
    timestamp: Option<String>,
}

fn classify_record(bytes: &[u8]) -> Result<RecordVisibility, SessionImportError> {
    let record: RecordKind =
        serde_json::from_slice(bytes).map_err(|_| SessionImportError::Unsupported)?;
    let _ = &record.timestamp;
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
        spool_record_id: Some(format!(
            "session-import-{}-{start}-{end}",
            current.session_id
        )),
        source_observation_id_hint: None,
        source_instance_id: format!("codex-session:{}", current.session_id),
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
        capture_completeness: CaptureCompleteness::Complete,
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

fn source_position(
    snapshot: &evertrace_store::ProjectionSnapshot,
    session_id: &str,
    current_revision: &SourceRevision,
) -> Result<(u64, Option<SourceRevision>), SessionImportError> {
    let instance = format!("codex-session:{session_id}");
    let mut current: Option<SourceIngestWatermark> = None;
    let mut previous: Option<SourceIngestWatermark> = None;
    for row in snapshot.data_rows() {
        let Some(json) = row.payload_json.as_deref() else {
            continue;
        };
        let Ok(JournalPayload::SourceIngestWatermark(value)) = serde_json::from_str(json) else {
            continue;
        };
        if value.source_instance_id.as_str() == instance {
            let found = if &value.source_revision == current_revision {
                &mut current
            } else {
                &mut previous
            };
            if found.as_ref().is_some_and(|old| {
                old.source_sequence > value.source_sequence
                    || (old.source_sequence == value.source_sequence
                        && (old.confirmed_prefix_digest.is_some()
                            || value.confirmed_prefix_digest.is_none()))
            }) {
                continue;
            }
            *found = Some(value);
        }
    }
    if current.is_none() {
        let mut ranges = Vec::new();
        for row in snapshot.data_rows() {
            let Some(json) = row.payload_json.as_deref() else {
                continue;
            };
            let Ok(JournalPayload::SourceReceiptRecorded(receipt)) = serde_json::from_str(json)
            else {
                continue;
            };
            if receipt.source_instance_id.as_str() == instance
                && &receipt.source_revision == current_revision
            {
                ranges.push(
                    receipt
                        .source_byte_range
                        .ok_or(SessionImportError::Changed)?,
                );
            }
        }
        ranges.sort_by_key(|range| (range.start, range.end));
        let mut end = 0_u64;
        for range in ranges {
            if range.start != end || range.end <= range.start {
                return Err(SessionImportError::Changed);
            }
            end = range.end;
        }
        if end != 0 {
            return Ok((end, None));
        }
    }
    Ok(match (current, previous) {
        (Some(value), _) => (value.source_sequence, None),
        (None, Some(value)) => (0, Some(value.source_revision)),
        (None, None) => (0, None),
    })
}

fn now_us() -> Result<i64, SessionImportError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_micros()).ok())
        .ok_or(SessionImportError::Persistence)
}
