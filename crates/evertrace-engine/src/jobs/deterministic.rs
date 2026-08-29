use evertrace_domain::{
    revision::RevisionId,
    semantic::{GlobalSuccessorSupportContract, GlobalSupportState, GlobalSupportValidationEvent},
};
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportClosureAction {
    pub disposition: JobResultDisposition,
    pub validation: Option<GlobalSupportValidationEvent>,
}

pub fn support_closure_result(
    job: &DurableJob,
    contract: &GlobalSuccessorSupportContract,
    current: &GlobalSupportValidationEvent,
    mut surviving_support_refs: Vec<RevisionId>,
    mut invalid_or_missing_refs: Vec<RevisionId>,
    authorization_current: bool,
    occurred_at_us: i64,
) -> Result<SupportClosureAction, StoreError> {
    if job.kind != "support_closure"
        || job.target_revision != current.successor_ref
        || current.support_contract_ref != contract.support_contract_revision_id
    {
        return Err(StoreError::InvalidInput);
    }
    let disposition = classify_job_result(job, current.dependency_generation);
    if matches!(disposition, JobResultDisposition::StaleAudit(_)) {
        return Ok(SupportClosureAction {
            disposition,
            validation: None,
        });
    }
    surviving_support_refs.sort();
    surviving_support_refs.dedup();
    invalid_or_missing_refs.sort();
    invalid_or_missing_refs.dedup();
    if surviving_support_refs
        .iter()
        .any(|value| invalid_or_missing_refs.contains(value))
    {
        return Err(StoreError::InvalidInput);
    }
    let mut partition = surviving_support_refs.clone();
    partition.extend(invalid_or_missing_refs.iter().copied());
    partition.sort();
    if partition != contract.support_revision_refs {
        return Err(StoreError::InvalidInput);
    }
    let support_sufficient = surviving_support_refs.len()
        >= usize::from(
            contract
                .support_threshold_snapshot
                .minimum_surviving_support,
        );
    let authorization_satisfied =
        !contract.support_threshold_snapshot.require_authorization || authorization_current;
    let validation = GlobalSupportValidationEvent {
        validation_revision_id: RevisionId::new_v7(),
        support_contract_ref: current.support_contract_ref,
        successor_ref: current.successor_ref.clone(),
        dependency_generation: current.dependency_generation,
        state: if support_sufficient && authorization_satisfied {
            GlobalSupportState::Valid
        } else if !authorization_satisfied {
            GlobalSupportState::Invalidated
        } else {
            GlobalSupportState::Insufficient
        },
        provenance_degraded: !invalid_or_missing_refs.is_empty(),
        surviving_support_refs,
        invalid_or_missing_refs,
        trigger_refs: vec![job.idempotency_key.clone()],
        validator_revision: 1,
        created_at_us: occurred_at_us,
    };
    validation
        .validate()
        .map_err(|_| StoreError::InvalidInput)?;
    Ok(SupportClosureAction {
        disposition,
        validation: Some(validation),
    })
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

    use evertrace_domain::{
        ids::JobId,
        semantic::{GlobalSupportState, SupportThresholdSnapshot},
    };
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

    #[test]
    fn support_closure_never_allows_a_stale_generation_to_restore_pending() {
        let support = RevisionId::new_v7();
        let authorization = RevisionId::new_v7();
        let contract_id = RevisionId::new_v7();
        let contract = GlobalSuccessorSupportContract {
            support_contract_revision_id: contract_id,
            successor_revision_or_membership_ref: "coremem:01890f47-6a4a-7cc1-98b9-01890f476a4b"
                .into(),
            support_revision_refs: vec![support],
            authorization_revision_refs: vec![authorization],
            evidence_cohort_hash: [1; 32],
            support_threshold_snapshot: SupportThresholdSnapshot {
                minimum_surviving_support: 1,
                require_authorization: true,
            },
            promotion_proposal_revision_id: RevisionId::new_v7(),
            promotion_validator_revision: 1,
            applicability_contract_hash: [2; 32],
            created_at_us: 1,
        };
        let pending = GlobalSupportValidationEvent {
            validation_revision_id: RevisionId::new_v7(),
            support_contract_ref: contract_id,
            successor_ref: contract.successor_revision_or_membership_ref.clone(),
            dependency_generation: 2,
            state: GlobalSupportState::RevalidationPending,
            provenance_degraded: false,
            surviving_support_refs: vec![support],
            invalid_or_missing_refs: Vec::new(),
            trigger_refs: vec!["dependency:changed".into()],
            validator_revision: 1,
            created_at_us: 2,
        };
        let job = DurableJob {
            job_id: JobId::new_v7(),
            idempotency_key: "support:closure:2".into(),
            target_revision: pending.successor_ref.clone(),
            target_watermark: 2,
            target_generation: 2,
            kind: "support_closure".into(),
            priority: 0,
            state: JobStatus::Queued,
            attempt: 0,
            backoff_until_us: None,
            config_hash: [3; 32],
            lease_until_us: None,
        };
        let applied = support_closure_result(
            &job,
            &contract,
            &pending,
            vec![support],
            Vec::new(),
            true,
            3,
        )
        .unwrap();
        let validation = applied.validation.unwrap();
        assert_eq!(validation.dependency_generation, 2);
        assert_eq!(validation.state, GlobalSupportState::Valid);
        assert!(!validation.provenance_degraded);

        assert!(matches!(
            support_closure_result(
                &job,
                &contract,
                &pending,
                vec![RevisionId::new_v7()],
                Vec::new(),
                true,
                3,
            ),
            Err(StoreError::InvalidInput)
        ));
        assert!(matches!(
            support_closure_result(&job, &contract, &pending, Vec::new(), Vec::new(), true, 3,),
            Err(StoreError::InvalidInput)
        ));
        let duplicate = support_closure_result(
            &job,
            &contract,
            &pending,
            vec![support, support],
            Vec::new(),
            true,
            3,
        )
        .unwrap()
        .validation
        .unwrap();
        assert_eq!(duplicate.state, GlobalSupportState::Valid);
        assert_eq!(duplicate.surviving_support_refs, vec![support]);

        let other_support = RevisionId::new_v7();
        let mut partial_contract = contract.clone();
        partial_contract.support_revision_refs = vec![support, other_support];
        partial_contract.support_revision_refs.sort();
        let surviving = partial_contract.support_revision_refs[0];
        let missing = partial_contract.support_revision_refs[1];
        let partial = support_closure_result(
            &job,
            &partial_contract,
            &pending,
            vec![surviving],
            vec![missing],
            true,
            3,
        )
        .unwrap()
        .validation
        .unwrap();
        assert_eq!(partial.state, GlobalSupportState::Valid);
        assert!(partial.provenance_degraded);

        let mut no_authorization_required = contract.clone();
        no_authorization_required
            .support_threshold_snapshot
            .require_authorization = false;
        let insufficient = support_closure_result(
            &job,
            &no_authorization_required,
            &pending,
            Vec::new(),
            vec![support],
            false,
            3,
        )
        .unwrap()
        .validation
        .unwrap();
        assert_eq!(insufficient.state, GlobalSupportState::Insufficient);
        assert_eq!(insufficient.invalid_or_missing_refs, vec![support]);

        let mut stale_job = job;
        stale_job.target_generation = 1;
        let stale = support_closure_result(
            &stale_job,
            &contract,
            &pending,
            vec![support],
            Vec::new(),
            true,
            4,
        )
        .unwrap();
        assert!(stale.validation.is_none());
        assert!(matches!(
            stale.disposition,
            JobResultDisposition::StaleAudit(_)
        ));
    }
}
