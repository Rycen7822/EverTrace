use std::collections::{BTreeMap, BTreeSet};

use evertrace_domain::{
    evidence::{EvidenceSurface, SourceObservation, SourceReceipt},
    ids::{ProcedureNegativeEvidenceId, SourceObservationId, SourceReceiptId},
    procedure::ProcedureStateEvent,
    purge::{
        OBJECT_DELETION_LEDGER_SCHEMA_VERSION, ObjectDeletionGuards, ObjectDeletionLedgerEvent,
        ObjectDeletionPhase, ObjectDeletionTarget,
    },
    recall::RecallLedgerEvent,
    revision::RevisionId,
    semantic::{GlobalSupportValidationEvent, L3CoreProjection, WikiProjection},
};

use crate::{
    DefaultRetrievalSuppressionGeneration, DirtyTarget, DirtyTargetKind, DurableJob, JobBudget,
    JobLease, JobStatus, JobTerminalAudit, JobTerminalOutcome, JobTerminalReason, JournalPayload,
    ObjectRow, ObjectRowClass, ObjectRowKind, ProjectionSnapshot, StoreError,
    default_retrieval_suppression_ref_hash,
};

pub(crate) const OBJECT_DELETION_LEDGER_KIND: &str = "object_deletion_ledger";
const PROJECTION_GENERATION: u64 = 1;
pub(crate) const OBJECT_DELETION_JOB_KIND: &str = "object_forget_v1";
pub const OBJECT_DELETION_ALGORITHM_REVISION: &str = "s32-object-forget-v1";
const OBJECT_DELETION_LEASE_US: i64 = 30_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectDeletionPreview {
    pub target: ObjectDeletionTarget,
    pub current_revision_id: RevisionId,
    pub exact_revision_ids: Vec<RevisionId>,
    pub guards: ObjectDeletionGuards,
    pub default_retrieval_suppression_ref_hashes: Vec<String>,
    pub deletion_generation: u64,
    pub shared_source_count: u32,
    pub suppressed_source_count: u32,
    pub suppression_ref_count: u32,
    pub downstream_support_impacts: Vec<ObjectDeletionSupportImpact>,
    pub dependent_procedure_impacts: Vec<ObjectDeletionProcedureImpact>,
}

#[derive(Clone, Debug)]
pub(crate) struct ObjectDeletionRevisionFact {
    pub revision_id: RevisionId,
    pub canonical_payload: String,
    pub semantic_kind: String,
    pub scope_identity: String,
    pub source_derivation_refs: Vec<String>,
    pub current: bool,
}

pub(crate) struct ObjectDeletionSourceContext<'a> {
    pub other_live_source_refs: &'a BTreeSet<SourceObservationId>,
    pub source_observations: &'a BTreeMap<SourceObservationId, (SourceObservation, u64)>,
    pub source_receipts: &'a BTreeMap<SourceReceiptId, (SourceReceipt, u64)>,
    pub evidence_surfaces: &'a BTreeMap<SourceObservationId, (EvidenceSurface, u64)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectDeletionSupportImpact {
    pub current_validation: GlobalSupportValidationEvent,
    pub trigger_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectDeletionProcedureImpact {
    pub current_state: ProcedureStateEvent,
    pub trigger_refs: Vec<String>,
}

pub fn pending_object_deletion(
    preview: &ObjectDeletionPreview,
    purge_job_id: evertrace_domain::ids::JobId,
    recorded_at_us: i64,
    source_watermark: u64,
    effective_config_hash: [u8; 32],
) -> Result<(ObjectDeletionLedgerEvent, DurableJob), StoreError> {
    let event = ObjectDeletionLedgerEvent {
        schema_version: OBJECT_DELETION_LEDGER_SCHEMA_VERSION,
        target: preview.target,
        phase: ObjectDeletionPhase::Pending,
        exact_revision_ids: preview.exact_revision_ids.clone(),
        semantic_kind_hash: preview.guards.semantic_kind_hash.clone(),
        canonical_payload_hash: preview.guards.canonical_payload_hash.clone(),
        scope_identity_hash: preview.guards.scope_identity_hash.clone(),
        source_derivation_guard_hash: preview.guards.source_derivation_guard_hash.clone(),
        default_retrieval_suppression_ref_hashes: preview
            .default_retrieval_suppression_ref_hashes
            .clone(),
        deletion_generation: preview.deletion_generation,
        recorded_at_us,
        purge_job_id,
        purge_job_audit_ref: None,
    };
    let job = DurableJob {
        job_id: purge_job_id,
        idempotency_key: format!(
            "object-forget:{}:{}",
            preview.target.object_ref(),
            preview.deletion_generation
        ),
        target_revision: preview.target.object_ref(),
        target_watermark: source_watermark,
        target_generation: preview.deletion_generation,
        kind: OBJECT_DELETION_JOB_KIND.into(),
        algorithm_revision: OBJECT_DELETION_ALGORITHM_REVISION.into(),
        model_id: None,
        priority: 0,
        state: JobStatus::Queued,
        attempt: 1,
        backoff_until_us: None,
        config_hash: effective_config_hash,
        budget: JobBudget {
            max_items: u32::try_from(preview.exact_revision_ids.len())
                .map_err(|_| StoreError::InvalidInput)?,
            max_bytes: None,
            max_input_tokens: None,
            max_output_tokens: None,
            max_calls: None,
            max_wall_time_ms: 30_000,
        },
        terminal: None,
        lease_until_us: None,
    };
    if !event.validate()
        || event.exact_revision_ids.len() != usize::try_from(job.budget.max_items).unwrap_or(0)
    {
        return Err(StoreError::InvalidInput);
    }
    Ok((event, job))
}

pub fn purged_object_deletion(
    pending: &ObjectDeletionLedgerEvent,
    queued_job: &DurableJob,
    recorded_at_us: i64,
) -> Result<(ObjectDeletionLedgerEvent, JobLease, DurableJob), StoreError> {
    if pending.phase != ObjectDeletionPhase::Pending
        || queued_job.job_id != pending.purge_job_id
        || queued_job.state != JobStatus::Queued
        || queued_job.kind != OBJECT_DELETION_JOB_KIND
        || queued_job.target_generation != pending.deletion_generation
        || queued_job.target_revision != pending.target.object_ref()
    {
        return Err(StoreError::InvalidInput);
    }
    let attempt = queued_job
        .attempt
        .checked_add(1)
        .ok_or(StoreError::InvalidInput)?;
    let lease_until_us = recorded_at_us
        .checked_add(OBJECT_DELETION_LEASE_US)
        .ok_or(StoreError::InvalidInput)?;
    let lease = JobLease {
        job_id: queued_job.job_id,
        target_generation: queued_job.target_generation,
        attempt,
        lease_until_us,
    };
    let mut terminal = queued_job.clone();
    terminal.state = JobStatus::Succeeded;
    terminal.attempt = attempt;
    terminal.lease_until_us = None;
    terminal.terminal = Some(Box::new(JobTerminalAudit {
        outcome: JobTerminalOutcome::Succeeded,
        reason: JobTerminalReason::Completed,
        result_ref: Some(queued_job.job_id.to_string()),
    }));
    let mut event = pending.clone();
    event.phase = ObjectDeletionPhase::Purged;
    event.recorded_at_us = recorded_at_us;
    event.purge_job_audit_ref = Some(queued_job.job_id.to_string());
    if !pending.validate_successor(&event) {
        return Err(StoreError::InvalidInput);
    }
    Ok((event, lease, terminal))
}

pub(crate) fn derive_object_deletion_preview(
    target: ObjectDeletionTarget,
    mut revisions: Vec<ObjectDeletionRevisionFact>,
    source_context: ObjectDeletionSourceContext<'_>,
    downstream_support_impacts: Vec<ObjectDeletionSupportImpact>,
    dependent_procedure_impacts: Vec<ObjectDeletionProcedureImpact>,
    deletion_generation: u64,
) -> Result<ObjectDeletionPreview, StoreError> {
    let ObjectDeletionSourceContext {
        other_live_source_refs,
        source_observations,
        source_receipts,
        evidence_surfaces,
    } = source_context;
    if revisions.is_empty() || deletion_generation == 0 {
        return Err(StoreError::InvalidInput);
    }
    revisions.sort_by_key(|fact| fact.revision_id);
    if revisions
        .windows(2)
        .any(|pair| pair[0].revision_id == pair[1].revision_id)
    {
        return Err(StoreError::StoreCorrupt);
    }
    let current = revisions
        .iter()
        .filter(|fact| fact.current)
        .collect::<Vec<_>>();
    let [current] = current.as_slice() else {
        return Err(StoreError::StoreCorrupt);
    };
    let exact_revision_ids = revisions.iter().map(|fact| fact.revision_id).collect();
    let canonical_payloads = revisions
        .iter()
        .map(|fact| fact.canonical_payload.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut source_derivation_refs = revisions
        .iter()
        .flat_map(|fact| fact.source_derivation_refs.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    source_derivation_refs.sort();
    let guards = ObjectDeletionGuards::derive(
        target,
        &current.semantic_kind,
        &canonical_payloads,
        &current.scope_identity,
        &source_derivation_refs,
    )
    .ok_or(StoreError::StoreCorrupt)?;
    if downstream_support_impacts.windows(2).any(|pair| {
        pair[0].current_validation.support_contract_ref
            >= pair[1].current_validation.support_contract_ref
    }) || downstream_support_impacts.iter().any(|impact| {
        impact.trigger_refs.is_empty()
            || !strictly_sorted(&impact.trigger_refs)
            || impact.current_validation.validate().is_err()
    }) || dependent_procedure_impacts.windows(2).any(|pair| {
        pair[0].current_state.procedure_revision_id >= pair[1].current_state.procedure_revision_id
    }) || dependent_procedure_impacts.iter().any(|impact| {
        impact.trigger_refs.is_empty()
            || !strictly_sorted(&impact.trigger_refs)
            || impact.current_state.validate().is_err()
    }) {
        return Err(StoreError::StoreCorrupt);
    }
    let command_payload_count = 2usize
        .checked_add(
            downstream_support_impacts
                .len()
                .checked_mul(4)
                .ok_or(StoreError::InvalidInput)?,
        )
        .and_then(|count| count.checked_add(dependent_procedure_impacts.len()))
        .ok_or(StoreError::InvalidInput)?;
    u16::try_from(command_payload_count).map_err(|_| StoreError::InvalidInput)?;

    let target_source_ids = source_derivation_refs
        .iter()
        .filter_map(|reference| {
            reference
                .parse::<SourceObservationId>()
                .ok()
                .filter(|id| source_observations.contains_key(id))
                .or_else(|| {
                    reference
                        .parse::<SourceReceiptId>()
                        .ok()
                        .and_then(|id| source_receipts.get(&id))
                        .map(|(receipt, _)| receipt.source_observation_id)
                })
        })
        .collect::<BTreeSet<_>>();
    let shared_source_count = u32::try_from(
        target_source_ids
            .intersection(other_live_source_refs)
            .count(),
    )
    .map_err(|_| StoreError::InvalidInput)?;
    let mut suppression = BTreeSet::new();
    let mut suppressed_source_count = 0u32;
    for observation_id in target_source_ids
        .iter()
        .filter(|id| !other_live_source_refs.contains(id))
    {
        let Some((surface, _)) = evidence_surfaces.get(observation_id) else {
            continue;
        };
        let observation = source_observations
            .get(observation_id)
            .ok_or(StoreError::StoreCorrupt)?;
        let receipt = source_receipts
            .get(&observation.0.source_receipt_ref)
            .filter(|(receipt, _)| receipt.source_observation_id == *observation_id)
            .ok_or(StoreError::StoreCorrupt)?;
        suppressed_source_count = suppressed_source_count
            .checked_add(1)
            .ok_or(StoreError::InvalidInput)?;
        for generation in [
            DefaultRetrievalSuppressionGeneration::ObservationSpanV1,
            DefaultRetrievalSuppressionGeneration::ContentSpanV2,
        ] {
            suppression.insert(default_retrieval_suppression_ref_hash(
                surface, &receipt.0, generation,
            )?);
        }
    }
    let default_retrieval_suppression_ref_hashes = suppression.into_iter().collect::<Vec<_>>();
    let suppression_ref_count = u32::try_from(default_retrieval_suppression_ref_hashes.len())
        .map_err(|_| StoreError::InvalidInput)?;
    Ok(ObjectDeletionPreview {
        target,
        current_revision_id: current.revision_id,
        exact_revision_ids,
        guards,
        default_retrieval_suppression_ref_hashes,
        deletion_generation,
        shared_source_count,
        suppressed_source_count,
        suppression_ref_count,
        downstream_support_impacts,
        dependent_procedure_impacts,
    })
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObjectDeletionCurrentView {
    pub frontier: u64,
    pub generation: u64,
    pub events: BTreeMap<ObjectDeletionTarget, ObjectDeletionLedgerEvent>,
}

impl ObjectDeletionCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut view = Self {
            frontier: snapshot.frontier,
            ..Self::default()
        };
        for row in snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some(OBJECT_DELETION_LEDGER_KIND))
        {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            let JournalPayload::ObjectDeletionLedgerRecorded(event) = payload else {
                return Err(StoreError::StoreCorrupt);
            };
            require_ledger_row(row, &event)?;
            view.generation = view.generation.max(event.deletion_generation);
            if view.events.insert(event.target, *event).is_some() {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Ok(view)
    }

    pub fn suppression_ref_hashes(&self) -> BTreeSet<String> {
        self.events
            .values()
            .flat_map(|event| {
                event
                    .default_retrieval_suppression_ref_hashes
                    .iter()
                    .cloned()
            })
            .collect()
    }
}

#[derive(Clone, Default)]
pub(crate) struct ObjectDeletionState {
    events: BTreeMap<ObjectDeletionTarget, (ObjectDeletionLedgerEvent, u64)>,
    generation: u64,
}

impl ObjectDeletionState {
    pub(crate) fn current(
        &self,
        target: ObjectDeletionTarget,
    ) -> Option<&ObjectDeletionLedgerEvent> {
        self.events.get(&target).map(|(event, _)| event)
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn apply(
        &mut self,
        event: ObjectDeletionLedgerEvent,
        seq: u64,
        error: StoreError,
    ) -> Result<(), StoreError> {
        match self.events.get(&event.target) {
            None => {
                if event.phase != ObjectDeletionPhase::Pending
                    || event.deletion_generation != self.generation.checked_add(1).ok_or(error)?
                {
                    return Err(error);
                }
                self.generation = event.deletion_generation;
            }
            Some((current, _)) => {
                if !current.validate_successor(&event) {
                    return Err(error);
                }
            }
        }
        self.events.insert(event.target, (event, seq));
        Ok(())
    }

    pub(crate) fn restore(
        &mut self,
        row: &ObjectRow,
        event: ObjectDeletionLedgerEvent,
    ) -> Result<(), StoreError> {
        require_ledger_row(row, &event)?;
        if self.events.contains_key(&event.target) {
            return Err(StoreError::StoreCorrupt);
        }
        self.generation = self.generation.max(event.deletion_generation);
        self.events
            .insert(event.target, (event, row.source_event_seq));
        Ok(())
    }

    pub(crate) fn rows(&self) -> Result<Vec<ObjectRow>, StoreError> {
        self.events
            .values()
            .map(|(event, seq)| ledger_row(event, *seq))
            .collect()
    }

    pub(crate) fn events(&self) -> impl Iterator<Item = &ObjectDeletionLedgerEvent> {
        self.events.values().map(|(event, _)| event)
    }

    pub(crate) fn validate_restored(&self) -> Result<(), StoreError> {
        let generations = self
            .events()
            .map(|event| event.deletion_generation)
            .collect::<BTreeSet<_>>();
        if generations.len() != self.events.len()
            || generations
                != (1..=u64::try_from(generations.len()).map_err(|_| StoreError::StoreCorrupt)?)
                    .collect()
            || self.generation != u64::try_from(generations.len()).unwrap_or(0)
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }
}

pub(crate) fn filter_product_rows(
    rows: Vec<ObjectRow>,
    deletions: &ObjectDeletionState,
) -> Result<Vec<ObjectRow>, StoreError> {
    if deletions.events.is_empty() {
        return Ok(rows);
    }
    let mut revision_ids = BTreeSet::new();
    let mut atom_ids = BTreeSet::new();
    let mut procedure_ids = BTreeSet::new();
    let mut membership_ids = BTreeSet::new();
    for event in deletions.events() {
        revision_ids.extend(event.exact_revision_ids.iter().copied());
        match event.target {
            ObjectDeletionTarget::Atom { atom_id } => {
                atom_ids.insert(atom_id);
            }
            ObjectDeletionTarget::Procedure { procedure_id } => {
                procedure_ids.insert(procedure_id);
            }
            ObjectDeletionTarget::CoreMembership { core_membership_id } => {
                membership_ids.insert(core_membership_id);
            }
        }
    }
    let mut negative_ids = BTreeSet::<ProcedureNegativeEvidenceId>::new();
    let mut support_contracts = BTreeSet::<RevisionId>::new();
    let mut outboxes = Vec::new();
    let mut jobs = Vec::new();
    for row in &rows {
        let Some(payload) = journal_payload(row)? else {
            continue;
        };
        match payload {
            JournalPayload::ProcedureNegativeEvidenceRecorded(value)
                if revision_ids.contains(&value.procedure_revision_id) =>
            {
                negative_ids.insert(value.negative_evidence_id);
            }
            JournalPayload::CoreMembershipRecorded(value)
                if membership_ids.contains(&value.core_membership_id)
                    || revision_ids.contains(&value.membership_revision_id)
                    || revision_ids.contains(&value.atom_revision_id) =>
            {
                support_contracts.insert(value.support_contract_ref);
            }
            JournalPayload::GlobalSupportContractRecorded(value)
                if value
                    .successor_revision_or_membership_ref
                    .parse::<RevisionId>()
                    .is_ok_and(|revision| revision_ids.contains(&revision)) =>
            {
                support_contracts.insert(value.support_contract_revision_id);
            }
            JournalPayload::OutboxEnqueued(value) => {
                outboxes.push((value.outbox_id.clone(), value.dirty.clone()));
            }
            JournalPayload::JobState(value) => {
                jobs.push((value.job_id, value.idempotency_key.clone()));
            }
            _ => {}
        }
    }
    let owned_outbox_ids = outboxes
        .into_iter()
        .filter_map(|(id, dirty)| {
            dirty_targets_owned_support(&dirty, &support_contracts).then_some(id)
        })
        .collect::<BTreeSet<_>>();
    let owned_job_ids = jobs
        .into_iter()
        .filter_map(|(id, key)| owned_outbox_ids.contains(&key).then_some(id))
        .collect::<BTreeSet<_>>();
    let owned_support_runtime = OwnedSupportRuntime {
        contracts: &support_contracts,
        outbox_ids: &owned_outbox_ids,
        job_ids: &owned_job_ids,
    };
    let mut retained = Vec::with_capacity(rows.len());
    for row in rows {
        let deleted = row.object_kind.as_deref() != Some(OBJECT_DELETION_LEDGER_KIND)
            && row_product_deleted(
                &row,
                &revision_ids,
                &atom_ids,
                &procedure_ids,
                &membership_ids,
                &negative_ids,
                &owned_support_runtime,
            )?;
        if !deleted {
            retained.push(row);
        }
    }
    for row in &retained {
        row.validate()?;
    }
    Ok(retained)
}

fn row_product_deleted(
    row: &ObjectRow,
    revision_ids: &BTreeSet<RevisionId>,
    atom_ids: &BTreeSet<evertrace_domain::ids::AtomId>,
    procedure_ids: &BTreeSet<evertrace_domain::ids::ProcedureId>,
    membership_ids: &BTreeSet<evertrace_domain::ids::CoreMembershipId>,
    negative_ids: &BTreeSet<ProcedureNegativeEvidenceId>,
    owned_support_runtime: &OwnedSupportRuntime<'_>,
) -> Result<bool, StoreError> {
    if row
        .current_revision_id
        .as_deref()
        .and_then(|value| value.parse::<RevisionId>().ok())
        .is_some_and(|revision| revision_ids.contains(&revision))
    {
        return Ok(true);
    }
    match row.object_kind.as_deref() {
        Some("l3_core_projection") => {
            let value: L3CoreProjection = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            return Ok(value
                .atom_revision_ids
                .iter()
                .chain(&value.active_membership_revision_ids)
                .any(|revision| revision_ids.contains(revision)));
        }
        Some("wiki_projection") => {
            let value: WikiProjection = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            return Ok(value.source_atom_ids.iter().any(|id| atom_ids.contains(id)));
        }
        _ => {}
    }
    let Some(payload) = journal_payload(row)? else {
        return Ok(false);
    };
    Ok(match payload {
        JournalPayload::AtomRecorded(value) => atom_ids.contains(&value.atom_id),
        JournalPayload::RevisionProposalRecorded(value) => {
            crate::projections::proposal_targets_deleted(
                &value,
                atom_ids,
                procedure_ids,
                membership_ids,
            )
        }
        JournalPayload::ProcedureRevisionRecorded(value) => {
            procedure_ids.contains(&value.procedure_id)
        }
        JournalPayload::ProcedureStateRecorded(value) => {
            revision_ids.contains(&value.procedure_revision_id)
        }
        JournalPayload::ProcedureUsageRecorded(value) => {
            revision_ids.contains(&value.procedure_revision_id)
        }
        JournalPayload::ProcedureNegativeEvidenceRecorded(value) => {
            revision_ids.contains(&value.procedure_revision_id)
        }
        JournalPayload::ProcedureNegativeReviewRecorded(value) => {
            negative_ids.contains(&value.negative_evidence_id)
        }
        JournalPayload::CoreMembershipRecorded(value) => {
            membership_ids.contains(&value.core_membership_id)
                || revision_ids.contains(&value.atom_revision_id)
        }
        JournalPayload::GlobalSupportContractRecorded(value) => owned_support_runtime
            .contracts
            .contains(&value.support_contract_revision_id),
        JournalPayload::GlobalSupportValidationRecorded(value) => owned_support_runtime
            .contracts
            .contains(&value.support_contract_ref),
        JournalPayload::DirtyTarget(value) => {
            dirty_targets_owned_support(&value, owned_support_runtime.contracts)
        }
        JournalPayload::OutboxEnqueued(value) => {
            owned_support_runtime.outbox_ids.contains(&value.outbox_id)
        }
        JournalPayload::JobState(value) => owned_support_runtime.job_ids.contains(&value.job_id),
        JournalPayload::RecallLedgerRecorded(value) => matches!(
            value.as_ref(),
            RecallLedgerEvent::NeedRecorded { need }
                if need.source_revision_ids.iter().any(|id| revision_ids.contains(id))
                    || need.recall_plan.applicable_procedure_revision
                        .is_some_and(|id| revision_ids.contains(&id))
        ),
        JournalPayload::SemanticDigestRecorded(value) => {
            value.selected_direct_refs.iter().any(|reference| {
                reference
                    .parse::<RevisionId>()
                    .is_ok_and(|id| revision_ids.contains(&id))
            })
        }
        JournalPayload::SemanticDerivationRunRecorded(value) => {
            value.selected_direct_refs.iter().any(|reference| {
                reference
                    .parse::<RevisionId>()
                    .is_ok_and(|id| revision_ids.contains(&id))
            })
        }
        _ => false,
    })
}

struct OwnedSupportRuntime<'a> {
    contracts: &'a BTreeSet<RevisionId>,
    outbox_ids: &'a BTreeSet<String>,
    job_ids: &'a BTreeSet<evertrace_domain::ids::JobId>,
}

fn dirty_targets_owned_support(
    dirty: &DirtyTarget,
    support_contracts: &BTreeSet<RevisionId>,
) -> bool {
    dirty.target_kind == DirtyTargetKind::RuntimeJob
        && dirty
            .target_id
            .parse::<RevisionId>()
            .is_ok_and(|id| support_contracts.contains(&id))
}

fn journal_payload(row: &ObjectRow) -> Result<Option<JournalPayload>, StoreError> {
    if row.row_class == Some(ObjectRowClass::Projection)
        && matches!(
            row.object_kind.as_deref(),
            Some("l3_core_projection" | "wiki_projection" | "procedure_context_effect")
        )
    {
        return Ok(None);
    }
    let Some(payload) = row.payload_json.as_deref() else {
        return Ok(None);
    };
    serde_json::from_str(payload)
        .map(Some)
        .map_err(|_| StoreError::StoreCorrupt)
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn ledger_row(event: &ObjectDeletionLedgerEvent, seq: u64) -> Result<ObjectRow, StoreError> {
    let row = ObjectRow {
        row_id: format!("projection:object_deletion:{}", event.target.object_ref()),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Projection),
        object_family: None,
        object_kind: Some(OBJECT_DELETION_LEDGER_KIND.into()),
        object_id: None,
        current_revision_id: Some(format!("deletion-generation-{}", event.deletion_generation)),
        lifecycle: Some(
            match event.phase {
                ObjectDeletionPhase::Pending => "purge_pending",
                ObjectDeletionPhase::Purged => "purged",
            }
            .into(),
        ),
        epistemic: None,
        authority: Some("human".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: None,
        worktree_id: None,
        task_id: None,
        workstream_id: None,
        session_id: None,
        payload_json: Some(
            JournalPayload::ObjectDeletionLedgerRecorded(Box::new(event.clone()))
                .canonical_json()?,
        ),
        source_event_seq: seq,
        projection_generation: PROJECTION_GENERATION,
    };
    require_ledger_row(&row, event)?;
    Ok(row)
}

fn require_ledger_row(
    row: &ObjectRow,
    event: &ObjectDeletionLedgerEvent,
) -> Result<(), StoreError> {
    if !event.validate()
        || row.row_kind != ObjectRowKind::Data
        || row.row_class != Some(ObjectRowClass::Projection)
        || row.object_family.is_some()
        || row.object_kind.as_deref() != Some(OBJECT_DELETION_LEDGER_KIND)
        || row.row_id != format!("projection:object_deletion:{}", event.target.object_ref())
        || row.object_id.is_some()
        || row.current_revision_id.as_deref()
            != Some(format!("deletion-generation-{}", event.deletion_generation).as_str())
        || row.lifecycle.as_deref()
            != Some(match event.phase {
                ObjectDeletionPhase::Pending => "purge_pending",
                ObjectDeletionPhase::Purged => "purged",
            })
        || row.authority.as_deref() != Some("human")
        || row.source_event_seq == 0
        || row.projection_generation != PROJECTION_GENERATION
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}
