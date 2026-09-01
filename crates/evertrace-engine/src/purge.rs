use evertrace_domain::{
    ids::{CommandId, JobId, RequestId},
    purge::{ObjectDeletionLedgerEvent, ObjectDeletionPhase, ObjectDeletionTarget},
    revision::RevisionId,
};
use evertrace_store::{
    DurableJob, EventScope, JournalCommand, JournalEventDraft, JournalPayload,
    OBJECT_DELETION_ALGORITHM_REVISION, ObjectDeletionCurrentView, ObjectDeletionPreview,
    ProjectionSnapshot, SourceKind, StoreError, object_deletion_preview, pending_object_deletion,
    purged_object_deletion,
};

use crate::{procedure::mark_procedure_support_review_hold, semantic::mark_support_pending};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectForgetLookup {
    Available(ObjectDeletionPreview),
    NoDelta(ObjectDeletionLedgerEvent),
    Unavailable,
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
