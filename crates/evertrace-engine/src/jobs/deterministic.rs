use evertrace_store::{
    DirtyTarget, DurableJob, JobStatus, JournalPayload, ObjectRow, ObjectRowKind, OutboxEntry,
    StaleGenerationAudit, StoreError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAction {
    pub job: DurableJob,
    pub next_attempt: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobResultDisposition {
    Apply,
    StaleAudit(StaleGenerationAudit),
}

pub fn expired_leases(
    rows: &[ObjectRow],
    now_us: i64,
    journal_frontier: u64,
) -> Result<Vec<RecoveryAction>, StoreError> {
    if now_us < 0 {
        return Err(StoreError::InvalidInput);
    }
    validate_checkpoint(rows, journal_frontier)?;
    let mut actions = Vec::new();
    for row in data_rows_at_frontier(rows, journal_frontier) {
        let Some(payload) = row.payload_json.as_deref() else {
            return Err(StoreError::StoreCorrupt);
        };
        let event: JournalPayload =
            serde_json::from_str(payload).map_err(|_| StoreError::StoreCorrupt)?;
        let JournalPayload::JobState(job) = event else {
            continue;
        };
        if job.state == JobStatus::Leased
            && job
                .lease_until_us
                .is_some_and(|deadline| deadline <= now_us)
        {
            actions.push(RecoveryAction {
                next_attempt: job.attempt.checked_add(1).ok_or(StoreError::StoreCorrupt)?,
                job,
            });
        }
    }
    actions.sort_by_key(|action| action.job.job_id);
    Ok(actions)
}

pub fn pending_outbox(
    rows: &[ObjectRow],
    journal_frontier: u64,
) -> Result<Vec<OutboxEntry>, StoreError> {
    validate_checkpoint(rows, journal_frontier)?;
    let mut entries = Vec::new();
    for row in data_rows_at_frontier(rows, journal_frontier) {
        let event: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        if let JournalPayload::OutboxEnqueued(value) = event {
            entries.push(value);
        }
    }
    entries.sort_by(|left, right| left.outbox_id.cmp(&right.outbox_id));
    Ok(entries)
}

pub fn pending_dirty(
    rows: &[ObjectRow],
    journal_frontier: u64,
) -> Result<Vec<DirtyTarget>, StoreError> {
    validate_checkpoint(rows, journal_frontier)?;
    let mut entries = Vec::new();
    for row in data_rows_at_frontier(rows, journal_frontier) {
        let event: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        if let JournalPayload::DirtyTarget(value) = event {
            entries.push(value);
        }
    }
    entries.sort_by_key(DirtyTarget::stable_key);
    Ok(entries)
}

pub fn classify_job_result(job: &DurableJob, observed_generation: u64) -> JobResultDisposition {
    if job.target_generation == observed_generation {
        JobResultDisposition::Apply
    } else {
        JobResultDisposition::StaleAudit(StaleGenerationAudit {
            job_id: job.job_id,
            expected_generation: job.target_generation,
            observed_generation,
        })
    }
}

fn validate_checkpoint(rows: &[ObjectRow], journal_frontier: u64) -> Result<(), StoreError> {
    let checkpoints = rows
        .iter()
        .filter(|row| row.row_kind == ObjectRowKind::Checkpoint)
        .collect::<Vec<_>>();
    if checkpoints.len() != 1 || checkpoints[0].source_event_seq > journal_frontier {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn data_rows_at_frontier(
    rows: &[ObjectRow],
    journal_frontier: u64,
) -> impl Iterator<Item = &ObjectRow> {
    rows.iter().filter(move |row| {
        row.row_kind == ObjectRowKind::Data && row.source_event_seq <= journal_frontier
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use evertrace_domain::ids::JobId;
    use evertrace_store::ObjectRowClass;

    use super::*;

    fn runtime_row(id: &str, payload: JournalPayload, seq: u64) -> ObjectRow {
        ObjectRow {
            row_id: id.into(),
            row_kind: ObjectRowKind::Data,
            row_class: Some(ObjectRowClass::Runtime),
            object_family: None,
            object_kind: None,
            object_id: None,
            current_revision_id: None,
            lifecycle: None,
            epistemic: None,
            authority: None,
            publication_state: None,
            support_state: None,
            project_id: None,
            repository_id: None,
            worktree_id: None,
            task_id: None,
            workstream_id: None,
            session_id: None,
            payload_json: Some(payload.canonical_json().unwrap()),
            source_event_seq: seq,
            projection_generation: 1,
        }
    }

    #[test]
    fn expired_lease_and_stale_generation_are_deterministic() {
        let job = DurableJob {
            job_id: JobId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a4b").unwrap(),
            idempotency_key: "key".into(),
            target_revision: "revision".into(),
            target_watermark: 3,
            target_generation: 7,
            kind: "projection".into(),
            priority: 1,
            state: JobStatus::Leased,
            attempt: 2,
            backoff_until_us: None,
            config_hash: [1; 32],
            lease_until_us: Some(50),
        };
        let rows = vec![
            ObjectRow::checkpoint(10, 1),
            runtime_row(
                "runtime:job:test",
                JournalPayload::JobState(job.clone()),
                10,
            ),
        ];
        assert!(expired_leases(&rows, 49, 10).unwrap().is_empty());
        assert_eq!(expired_leases(&rows, 50, 10).unwrap()[0].next_attempt, 3);
        assert_eq!(classify_job_result(&job, 7), JobResultDisposition::Apply);
        assert_eq!(
            classify_job_result(&job, 8),
            JobResultDisposition::StaleAudit(StaleGenerationAudit {
                job_id: job.job_id,
                expected_generation: 7,
                observed_generation: 8,
            })
        );
    }
}
