use evertrace_domain::{
    ids::{CommandId, JobId, RepositoryId, RequestId},
    purge::{
        ObjectDeletionLedgerEvent, ObjectDeletionPhase, ObjectDeletionTarget, ScopePurgeProgress,
        ScopePurgeStage,
    },
    revision::RevisionId,
};
use evertrace_store::{
    DurableJob, EventScope, JobStatus, JournalCommand, JournalEventDraft, JournalPayload,
    OBJECT_DELETION_ALGORITHM_REVISION, ObjectDeletionCurrentView, ObjectDeletionPreview,
    ProjectionSnapshot, REPOSITORY_SCOPE_PURGE_JOB_KIND, RepositoryScopePurgePreview,
    ScopePurgeCurrentView, SourceKind, StoreError, advance_repository_scope_purge,
    object_deletion_preview, pending_object_deletion, pending_repository_scope_purge,
    purged_object_deletion, repository_scope_purge_preview, terminal_repository_scope_purge_job,
};

use crate::{procedure::mark_procedure_support_review_hold, semantic::mark_support_pending};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectForgetLookup {
    Available(ObjectDeletionPreview),
    NoDelta(ObjectDeletionLedgerEvent),
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryPurgeLookup {
    Available(Box<RepositoryScopePurgePreview>),
    NoDelta(ScopePurgeProgress),
    Unavailable,
}

pub fn select_repository_purge(
    snapshot: &ProjectionSnapshot,
    repository_id: RepositoryId,
    expected_revision: u32,
) -> Result<RepositoryPurgeLookup, StoreError> {
    let progress = ScopePurgeCurrentView::from_snapshot(snapshot)?;
    if let Some(value) = progress.events.get(&repository_id) {
        return Ok(RepositoryPurgeLookup::NoDelta(value.clone()));
    }
    match repository_scope_purge_preview(snapshot, repository_id, expected_revision) {
        Ok(preview) => Ok(RepositoryPurgeLookup::Available(Box::new(preview))),
        Err(StoreError::InvalidInput | StoreError::ReconciliationDependencyOverflow) => {
            Ok(RepositoryPurgeLookup::Unavailable)
        }
        Err(error) => Err(error),
    }
}

pub fn select_object_forget(
    snapshot: &ProjectionSnapshot,
    target: ObjectDeletionTarget,
) -> Result<ObjectForgetLookup, StoreError> {
    let ledger = ObjectDeletionCurrentView::from_snapshot(snapshot)?;
    if let Some(event) = ledger.events.get(&target) {
        return Ok(ObjectForgetLookup::NoDelta(event.clone()));
    }
    match object_deletion_preview(snapshot, target) {
        Ok(preview) => Ok(ObjectForgetLookup::Available(preview)),
        Err(StoreError::InvalidInput) => Ok(ObjectForgetLookup::Unavailable),
        Err(error) => Err(error),
    }
}

pub fn pending_object_forget_command(
    request_id: RequestId,
    preview: &ObjectDeletionPreview,
    expected_revision_ids: &[RevisionId],
    expected_deletion_generation: u64,
    occurred_at_us: i64,
    source_watermark: u64,
    effective_config_hash: [u8; 32],
) -> Result<JournalCommand, StoreError> {
    if preview.exact_revision_ids != expected_revision_ids
        || preview.deletion_generation != expected_deletion_generation
    {
        return Err(StoreError::InvalidInput);
    }
    let command_id =
        CommandId::from_uuid(request_id.as_uuid()).map_err(|_| StoreError::InvalidInput)?;
    let job_id = JobId::from_uuid(request_id.as_uuid()).map_err(|_| StoreError::InvalidInput)?;
    let (event, job) = pending_object_deletion(
        preview,
        job_id,
        occurred_at_us,
        source_watermark,
        effective_config_hash,
    )?;
    let mut payloads = vec![
        JournalPayload::ObjectDeletionLedgerRecorded(Box::new(event)),
        JournalPayload::JobState(job),
    ];
    for impact in &preview.downstream_support_impacts {
        payloads.extend(
            mark_support_pending(
                &impact.current_validation,
                impact.trigger_refs.clone(),
                effective_config_hash,
                occurred_at_us,
            )
            .map_err(|_| StoreError::InvalidInput)?,
        );
    }
    for impact in &preview.dependent_procedure_impacts {
        payloads.push(
            mark_procedure_support_review_hold(impact, occurred_at_us)
                .map_err(|_| StoreError::InvalidInput)?,
        );
    }
    JournalCommand::new(
        command_id,
        payloads
            .into_iter()
            .map(|payload| {
                draft(
                    occurred_at_us,
                    SourceKind::Manual,
                    effective_config_hash,
                    Some(request_id.to_string()),
                    payload,
                )
            })
            .collect(),
    )
}

pub fn complete_object_forget_command(
    command_id: CommandId,
    pending: &ObjectDeletionLedgerEvent,
    queued_job: &DurableJob,
    occurred_at_us: i64,
    effective_config_hash: [u8; 32],
) -> Result<JournalCommand, StoreError> {
    if pending.phase != ObjectDeletionPhase::Pending {
        return Err(StoreError::InvalidInput);
    }
    let (event, lease, job) = purged_object_deletion(pending, queued_job, occurred_at_us)?;
    JournalCommand::new(
        command_id,
        vec![
            draft(
                occurred_at_us,
                SourceKind::System,
                effective_config_hash,
                Some(queued_job.job_id.to_string()),
                JournalPayload::ObjectDeletionLedgerRecorded(Box::new(event)),
            ),
            draft(
                occurred_at_us,
                SourceKind::System,
                effective_config_hash,
                Some(queued_job.job_id.to_string()),
                JournalPayload::JobLease(lease),
            ),
            draft(
                occurred_at_us,
                SourceKind::System,
                effective_config_hash,
                Some(queued_job.job_id.to_string()),
                JournalPayload::JobState(job),
            ),
        ],
    )
}

pub fn pending_repository_purge_command(
    request_id: RequestId,
    preview: &RepositoryScopePurgePreview,
    expected_deletion_generation: u64,
    occurred_at_us: i64,
    source_watermark: u64,
    effective_config_hash: [u8; 32],
) -> Result<JournalCommand, StoreError> {
    if preview.deletion_generation != expected_deletion_generation {
        return Err(StoreError::InvalidInput);
    }
    let expected_event_count = usize::from(preview.pending_command_event_count()?);
    let command_id =
        CommandId::from_uuid(request_id.as_uuid()).map_err(|_| StoreError::InvalidInput)?;
    let job_id = JobId::from_uuid(request_id.as_uuid()).map_err(|_| StoreError::InvalidInput)?;
    let (progress, job, revoked_target_jobs) = pending_repository_scope_purge(
        preview,
        job_id,
        source_watermark,
        occurred_at_us,
        effective_config_hash,
    )?;
    let mut payloads = vec![
        JournalPayload::ScopePurgeProgressRecorded(Box::new(progress)),
        JournalPayload::JobState(job),
    ];
    payloads.extend(
        revoked_target_jobs
            .into_iter()
            .map(JournalPayload::JobState),
    );
    for impact in &preview.downstream_support_impacts {
        payloads.extend(
            mark_support_pending(
                &impact.current_validation,
                impact.trigger_refs.clone(),
                effective_config_hash,
                occurred_at_us,
            )
            .map_err(|_| StoreError::InvalidInput)?,
        );
    }
    for impact in &preview.dependent_procedure_impacts {
        payloads.push(
            mark_procedure_support_review_hold(impact, occurred_at_us)
                .map_err(|_| StoreError::InvalidInput)?,
        );
    }
    if payloads.len() != expected_event_count {
        return Err(StoreError::InvalidInput);
    }
    JournalCommand::new(
        command_id,
        payloads
            .into_iter()
            .map(|payload| {
                repository_purge_draft(
                    occurred_at_us,
                    SourceKind::Manual,
                    effective_config_hash,
                    Some(request_id.to_string()),
                    payload,
                )
            })
            .collect(),
    )
}

pub fn advance_repository_purge_command(
    command_id: CommandId,
    current: &ScopePurgeProgress,
    leased_job: &DurableJob,
    next_stage: ScopePurgeStage,
    next_ordinal: u64,
    occurred_at_us: i64,
    effective_config_hash: [u8; 32],
) -> Result<JournalCommand, StoreError> {
    if leased_job.job_id != current.purge_job_id
        || leased_job.state != JobStatus::Leased
        || leased_job.kind != REPOSITORY_SCOPE_PURGE_JOB_KIND
        || leased_job.target_generation != current.deletion_generation
        || leased_job.target_watermark != current.confirmation_frontier
    {
        return Err(StoreError::InvalidInput);
    }
    let progress =
        advance_repository_scope_purge(current, next_stage, next_ordinal, occurred_at_us)?;
    let mut queued_job = leased_job.clone();
    queued_job.state = JobStatus::Queued;
    queued_job.lease_until_us = None;
    queued_job.backoff_until_us = None;
    JournalCommand::new(
        command_id,
        vec![
            repository_purge_draft(
                occurred_at_us,
                SourceKind::System,
                effective_config_hash,
                Some(current.purge_job_id.to_string()),
                JournalPayload::ScopePurgeProgressRecorded(Box::new(progress)),
            ),
            repository_purge_draft(
                occurred_at_us,
                SourceKind::System,
                effective_config_hash,
                Some(current.purge_job_id.to_string()),
                JournalPayload::JobState(queued_job),
            ),
        ],
    )
}

pub fn complete_repository_purge_command(
    command_id: CommandId,
    current: &ScopePurgeProgress,
    leased_job: &DurableJob,
    occurred_at_us: i64,
    effective_config_hash: [u8; 32],
) -> Result<JournalCommand, StoreError> {
    let progress = advance_repository_scope_purge(
        current,
        ScopePurgeStage::Purged,
        current.next_ordinal,
        occurred_at_us,
    )?;
    let job = terminal_repository_scope_purge_job(current, leased_job)?;
    JournalCommand::new(
        command_id,
        vec![progress]
            .into_iter()
            .map(|progress| {
                repository_purge_draft(
                    occurred_at_us,
                    SourceKind::System,
                    effective_config_hash,
                    Some(current.purge_job_id.to_string()),
                    JournalPayload::ScopePurgeProgressRecorded(Box::new(progress)),
                )
            })
            .chain([repository_purge_draft(
                occurred_at_us,
                SourceKind::System,
                effective_config_hash,
                Some(current.purge_job_id.to_string()),
                JournalPayload::JobState(job),
            )])
            .collect(),
    )
}

fn draft(
    occurred_at_us: i64,
    source_kind: SourceKind,
    effective_config_hash: [u8; 32],
    correlation_id: Option<String>,
    payload: JournalPayload,
) -> JournalEventDraft {
    JournalEventDraft {
        occurred_at_us,
        source_kind,
        scope: EventScope::default(),
        causation_id: correlation_id.clone(),
        correlation_id,
        effective_config_hash,
        algorithm_revision: OBJECT_DELETION_ALGORITHM_REVISION.into(),
        payload,
    }
}

fn repository_purge_draft(
    occurred_at_us: i64,
    source_kind: SourceKind,
    effective_config_hash: [u8; 32],
    correlation_id: Option<String>,
    payload: JournalPayload,
) -> JournalEventDraft {
    JournalEventDraft {
        occurred_at_us,
        source_kind,
        scope: EventScope::default(),
        causation_id: correlation_id.clone(),
        correlation_id,
        effective_config_hash,
        algorithm_revision: evertrace_store::REPOSITORY_SCOPE_PURGE_ALGORITHM_REVISION.into(),
        payload,
    }
}
