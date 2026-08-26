use std::collections::BTreeMap;

use arrow_array::RecordBatchIterator;
use evertrace_domain::{
    evidence::{
        EvidenceSurface, HostOccurrence, Operation, ScopeEffect, SourceObservation, SourceReceipt,
    },
    ids::{
        HostOccurrenceId, JobId, OperationId, ScopeEffectId, SourceObservationId, SourceReceiptId,
    },
};
use lancedb::Table;

use crate::{
    command::{
        DirtyTarget, DurableJob, JobStatus, JournalPayload, NormalizationWatermark, ObjectFamily,
        OutboxEntry, SourceIngestWatermark, SourceRevisionRecorded, StoreError, WatermarkAdvanced,
    },
    journal::{
        JournalRow, read_all_journal_rows, read_journal_after, read_journal_frontier,
        validate_journal_rows,
    },
    objects::{
        OBJECTS_CHECKPOINT_ID, ObjectRow, ObjectRowClass, ObjectRowKind, objects_batch,
        validate_objects_table,
    },
};

const PROJECTION_GENERATION: u64 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionSnapshot {
    pub frontier: u64,
    pub rows: Vec<ObjectRow>,
}

impl ProjectionSnapshot {
    pub fn data_rows(&self) -> impl Iterator<Item = &ObjectRow> {
        self.rows
            .iter()
            .filter(|row| row.row_kind == ObjectRowKind::Data)
    }

    pub fn row(&self, row_id: &str) -> Option<&ObjectRow> {
        self.rows.iter().find(|row| row.row_id == row_id)
    }
}

#[derive(Clone, Default)]
struct ReducerState {
    migrations: BTreeMap<String, (JournalPayload, u64)>,
    dirty: BTreeMap<String, (DirtyTarget, u64)>,
    outbox: BTreeMap<String, (OutboxEntry, u64)>,
    jobs: BTreeMap<JobId, (DurableJob, u64)>,
    watermarks: BTreeMap<String, (WatermarkAdvanced, u64)>,
    config: Option<(JournalPayload, u64)>,
    stale_audits: BTreeMap<String, (JournalPayload, u64)>,
    source_revisions: BTreeMap<String, (SourceRevisionRecorded, u64)>,
    source_receipts: BTreeMap<SourceReceiptId, (SourceReceipt, u64)>,
    source_observations: BTreeMap<SourceObservationId, (SourceObservation, u64)>,
    source_watermarks: BTreeMap<String, (SourceIngestWatermark, u64)>,
    evidence_surfaces: BTreeMap<SourceObservationId, (EvidenceSurface, u64)>,
    host_occurrences: BTreeMap<HostOccurrenceId, (HostOccurrence, u64)>,
    operations: BTreeMap<OperationId, (Operation, u64)>,
    scope_effects: BTreeMap<ScopeEffectId, (ScopeEffect, u64)>,
    normalization_watermarks: BTreeMap<SourceObservationId, (NormalizationWatermark, u64)>,
}

pub fn reduce_journal(rows: &[JournalRow]) -> Result<ProjectionSnapshot, StoreError> {
    validate_journal_rows(rows)?;
    let mut ordered = rows.to_vec();
    ordered.sort_by(|left, right| {
        left.seq
            .cmp(&right.seq)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let mut state = ReducerState::default();
    for row in &ordered {
        apply_event(&mut state, row)?;
    }
    let frontier = ordered.last().map_or(0, |row| row.seq);
    state.into_snapshot(frontier)
}

fn apply_event(state: &mut ReducerState, row: &JournalRow) -> Result<(), StoreError> {
    let payload = row.payload()?;
    match payload {
        JournalPayload::MigrationApplied(value) => {
            state.migrations.insert(
                value.migration_id.clone(),
                (JournalPayload::MigrationApplied(value), row.seq),
            );
        }
        JournalPayload::DirtyTarget(value) => {
            state.dirty.insert(value.stable_key(), (value, row.seq));
        }
        JournalPayload::OutboxEnqueued(value) => {
            if let Some((existing, _)) = state.outbox.get(&value.outbox_id)
                && existing != &value
            {
                return Err(StoreError::StoreCorrupt);
            }
            state
                .outbox
                .insert(value.outbox_id.clone(), (value, row.seq));
        }
        JournalPayload::JobState(value) => {
            state.jobs.insert(value.job_id, (value, row.seq));
        }
        JournalPayload::JobLease(value) => {
            let (job, source_seq) = state
                .jobs
                .get_mut(&value.job_id)
                .ok_or(StoreError::StoreCorrupt)?;
            if job.target_generation != value.target_generation || value.attempt < job.attempt {
                return Err(StoreError::StoreCorrupt);
            }
            job.state = JobStatus::Leased;
            job.attempt = value.attempt;
            job.lease_until_us = Some(value.lease_until_us);
            *source_seq = row.seq;
        }
        JournalPayload::WatermarkAdvanced(value) => {
            let key = value.kind.as_str().to_owned();
            if state
                .watermarks
                .get(&key)
                .is_some_and(|(current, _)| value.value < current.value)
            {
                return Err(StoreError::StoreCorrupt);
            }
            state.watermarks.insert(key, (value, row.seq));
        }
        JournalPayload::ConfigAudit(value) => {
            state.config = Some((JournalPayload::ConfigAudit(value), row.seq));
        }
        JournalPayload::StaleGenerationAudit(value) => {
            state.stale_audits.insert(
                row.event_id.clone(),
                (JournalPayload::StaleGenerationAudit(value), row.seq),
            );
        }
        JournalPayload::SourceRevisionRecorded(value) => {
            let key = source_revision_key(&value);
            if let Some((existing, _)) = state.source_revisions.get(&key) {
                if existing != &value {
                    return Err(StoreError::StoreCorrupt);
                }
            } else {
                state.source_revisions.insert(key, (value, row.seq));
            }
        }
        JournalPayload::SourceReceiptRecorded(value) => {
            let value = *value;
            if state
                .source_receipts
                .insert(value.source_receipt_id, (value, row.seq))
                .is_some()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        JournalPayload::SourceObservationRecorded(value) => {
            let value = *value;
            let receipt = state
                .source_receipts
                .get(&value.source_receipt_ref)
                .ok_or(StoreError::StoreCorrupt)?;
            if receipt.0.source_observation_id != value.source_observation_id
                || receipt.0.source_instance_id != value.source_instance_id
                || receipt.0.source_revision != value.source_revision
                || receipt.0.source_record_identity != value.source_record_identity
            {
                return Err(StoreError::StoreCorrupt);
            }
            if state
                .source_observations
                .insert(value.source_observation_id, (value, row.seq))
                .is_some()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        JournalPayload::SourceIngestWatermark(value) => {
            let key = value.stable_key();
            if state
                .source_watermarks
                .get(&key)
                .is_some_and(|(current, _)| value.source_sequence < current.source_sequence)
            {
                return Err(StoreError::StoreCorrupt);
            }
            let receipt_exists = state.source_receipts.values().any(|(receipt, _)| {
                receipt.source_instance_id == value.source_instance_id
                    && receipt.source_revision == value.source_revision
                    && receipt.source_sequence == value.source_sequence
            });
            if !receipt_exists {
                return Err(StoreError::StoreCorrupt);
            }
            state.source_watermarks.insert(key, (value, row.seq));
        }
        JournalPayload::EvidenceSurfaceRecorded(value) => {
            let value = *value;
            if !state
                .source_observations
                .contains_key(&value.source_observation_revision_ref)
                || state
                    .evidence_surfaces
                    .insert(value.source_observation_revision_ref, (value, row.seq))
                    .is_some()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        JournalPayload::HostOccurrenceNormalized(value) => {
            let value = *value;
            replace_occurrence(&mut state.host_occurrences, value, row.seq)?;
        }
        JournalPayload::OperationDerived(value) => {
            let value = *value;
            replace_operation(&mut state.operations, value, row.seq)?;
        }
        JournalPayload::ScopeEffectDerived(value) => {
            let value = *value;
            if let Some((existing, _)) = state.scope_effects.get(&value.scope_effect_id)
                && existing != &value
            {
                return Err(StoreError::StoreCorrupt);
            }
            state
                .scope_effects
                .insert(value.scope_effect_id, (value, row.seq));
        }
        JournalPayload::NormalizationWatermark(value) => {
            if !state
                .source_observations
                .contains_key(&value.source_observation_id)
                || state
                    .normalization_watermarks
                    .get(&value.source_observation_id)
                    .is_some_and(|(current, _)| current.resolver_version != value.resolver_version)
            {
                return Err(StoreError::StoreCorrupt);
            }
            state
                .normalization_watermarks
                .insert(value.source_observation_id, (value, row.seq));
        }
    }
    Ok(())
}

fn replace_occurrence(
    values: &mut BTreeMap<HostOccurrenceId, (HostOccurrence, u64)>,
    value: HostOccurrence,
    seq: u64,
) -> Result<(), StoreError> {
    if let Some((current, _)) = values.get(&value.host_occurrence_id)
        && current != &value
        && (value.normalization_revision != current.normalization_revision + 1
            || value.previous_normalization_revision != Some(current.normalization_revision))
    {
        return Err(StoreError::StoreCorrupt);
    }
    values.insert(value.host_occurrence_id, (value, seq));
    Ok(())
}

fn replace_operation(
    values: &mut BTreeMap<OperationId, (Operation, u64)>,
    value: Operation,
    seq: u64,
) -> Result<(), StoreError> {
    if let Some((current, _)) = values.get(&value.operation_id)
        && current != &value
        && (value.operation_revision != current.operation_revision + 1
            || value.previous_operation_revision != Some(current.operation_revision))
    {
        return Err(StoreError::StoreCorrupt);
    }
    values.insert(value.operation_id, (value, seq));
    Ok(())
}

impl ReducerState {
    fn from_current_rows(rows: &[ObjectRow], checkpoint_frontier: u64) -> Result<Self, StoreError> {
        let checkpoints = rows
            .iter()
            .filter(|row| row.row_kind == ObjectRowKind::Checkpoint)
            .collect::<Vec<_>>();
        if checkpoints.len() != 1
            || checkpoints[0].row_id != OBJECTS_CHECKPOINT_ID
            || checkpoints[0].source_event_seq != checkpoint_frontier
            || checkpoints[0].projection_generation != PROJECTION_GENERATION
        {
            return Err(StoreError::StoreCorrupt);
        }

        let mut state = Self::default();
        for row in rows
            .iter()
            .filter(|row| row.row_kind == ObjectRowKind::Data)
        {
            if row.source_event_seq > checkpoint_frontier
                || row.projection_generation != PROJECTION_GENERATION
            {
                return Err(StoreError::StoreCorrupt);
            }
            let payload_json = row
                .payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?;
            let payload: JournalPayload =
                serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
            if payload
                .canonical_json()
                .map_err(|_| StoreError::StoreCorrupt)?
                != payload_json
            {
                return Err(StoreError::StoreCorrupt);
            }
            state.restore_row(row, payload)?;
        }

        state.validate_evidence_relations()?;
        let canonical = state.clone().into_snapshot(checkpoint_frontier)?;
        if canonical.rows != rows {
            return Err(StoreError::Projection);
        }
        Ok(state)
    }

    fn restore_row(&mut self, row: &ObjectRow, payload: JournalPayload) -> Result<(), StoreError> {
        let duplicate = match payload {
            JournalPayload::MigrationApplied(value) => {
                require_row(
                    row,
                    ObjectRowClass::Projection,
                    &format!("projection:migration:{}", value.migration_id),
                )?;
                self.migrations
                    .insert(
                        value.migration_id.clone(),
                        (
                            JournalPayload::MigrationApplied(value),
                            row.source_event_seq,
                        ),
                    )
                    .is_some()
            }
            JournalPayload::DirtyTarget(value) => {
                let key = value.stable_key();
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!("runtime:dirty:{key}"),
                )?;
                self.dirty
                    .insert(key, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::OutboxEnqueued(value) => {
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!("runtime:outbox:{}", value.outbox_id),
                )?;
                self.outbox
                    .insert(value.outbox_id.clone(), (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::JobState(value) => {
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!("runtime:job:{}", value.job_id),
                )?;
                self.jobs
                    .insert(value.job_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::JobLease(_) => return Err(StoreError::StoreCorrupt),
            JournalPayload::WatermarkAdvanced(value) => {
                let key = value.kind.as_str().to_owned();
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!("runtime:watermark:{key}"),
                )?;
                self.watermarks
                    .insert(key, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::ConfigAudit(value) => {
                require_row(row, ObjectRowClass::Runtime, "runtime:config:current")?;
                self.config
                    .replace((JournalPayload::ConfigAudit(value), row.source_event_seq))
                    .is_some()
            }
            JournalPayload::StaleGenerationAudit(value) => {
                let event_id = row
                    .row_id
                    .strip_prefix("projection:audit:stale:")
                    .filter(|value| valid_event_id(value))
                    .ok_or(StoreError::StoreCorrupt)?;
                require_row(
                    row,
                    ObjectRowClass::Projection,
                    &format!("projection:audit:stale:{event_id}"),
                )?;
                self.stale_audits
                    .insert(
                        event_id.to_owned(),
                        (
                            JournalPayload::StaleGenerationAudit(value),
                            row.source_event_seq,
                        ),
                    )
                    .is_some()
            }
            JournalPayload::SourceRevisionRecorded(value) => {
                let key = source_revision_key(&value);
                let fields = evidence_fields(
                    format!("object:evidence:source_revision:{key}"),
                    "source_revision",
                    key.clone(),
                    value.source_revision.as_str().to_owned(),
                    None,
                    None,
                    None,
                );
                require_evidence_object_row(row, &fields)?;
                self.source_revisions
                    .insert(key, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::SourceReceiptRecorded(value) => {
                let value = *value;
                let fields = evidence_fields(
                    format!("object:evidence:source_receipt:{}", value.source_receipt_id),
                    "source_receipt",
                    value.source_receipt_id.to_string(),
                    value.source_receipt_id.to_string(),
                    value.repository_instance_id.map(|id| id.to_string()),
                    value.worktree_instance_id.map(|id| id.to_string()),
                    value.task_id.map(|id| id.to_string()),
                );
                require_evidence_object_row(row, &fields)?;
                self.source_receipts
                    .insert(value.source_receipt_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::SourceObservationRecorded(value) => {
                let value = *value;
                let fields = evidence_fields(
                    format!(
                        "object:evidence:source_observation:{}",
                        value.source_observation_id
                    ),
                    "source_observation",
                    value.source_observation_id.to_string(),
                    value.source_observation_id.to_string(),
                    None,
                    None,
                    None,
                );
                require_evidence_object_row(row, &fields)?;
                self.source_observations
                    .insert(value.source_observation_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::SourceIngestWatermark(value) => {
                let key = value.stable_key();
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!("runtime:watermark:source:{key}"),
                )?;
                self.source_watermarks
                    .insert(key, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::EvidenceSurfaceRecorded(value) => {
                let value = *value;
                require_surface_row(row, &value)?;
                self.evidence_surfaces
                    .insert(
                        value.source_observation_revision_ref,
                        (value, row.source_event_seq),
                    )
                    .is_some()
            }
            JournalPayload::HostOccurrenceNormalized(value) => {
                let value = *value;
                require_physical_row(
                    row,
                    ObjectFamily::Evidence,
                    "host_occurrence",
                    &value.host_occurrence_id.to_string(),
                    &format!(
                        "{}@{}",
                        value.host_occurrence_id, value.normalization_revision
                    ),
                )?;
                self.host_occurrences
                    .insert(value.host_occurrence_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::OperationDerived(value) => {
                let value = *value;
                require_physical_row(
                    row,
                    ObjectFamily::Work,
                    "operation",
                    &value.operation_id.to_string(),
                    &format!("{}@{}", value.operation_id, value.operation_revision),
                )?;
                self.operations
                    .insert(value.operation_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::ScopeEffectDerived(value) => {
                let value = *value;
                require_physical_row(
                    row,
                    ObjectFamily::Work,
                    "scope_effect",
                    &value.scope_effect_id.to_string(),
                    &value.scope_effect_id.to_string(),
                )?;
                self.scope_effects
                    .insert(value.scope_effect_id, (value, row.source_event_seq))
                    .is_some()
            }
            JournalPayload::NormalizationWatermark(value) => {
                require_row(
                    row,
                    ObjectRowClass::Runtime,
                    &format!(
                        "runtime:watermark:normalization:{}",
                        value.source_observation_id
                    ),
                )?;
                self.normalization_watermarks
                    .insert(value.source_observation_id, (value, row.source_event_seq))
                    .is_some()
            }
        };
        if duplicate {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    fn into_snapshot(self, frontier: u64) -> Result<ProjectionSnapshot, StoreError> {
        self.validate_evidence_relations()?;
        let mut rows = self.into_rows()?;
        rows.push(ObjectRow::checkpoint(frontier, PROJECTION_GENERATION));
        rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
        Ok(ProjectionSnapshot { frontier, rows })
    }

    fn into_rows(self) -> Result<Vec<ObjectRow>, StoreError> {
        let mut rows = Vec::new();
        for (migration, (payload, seq)) in self.migrations {
            rows.push(runtime_row(
                format!("projection:migration:{migration}"),
                ObjectRowClass::Projection,
                &payload,
                seq,
            )?);
        }
        for (key, (value, seq)) in self.dirty {
            rows.push(runtime_row(
                format!("runtime:dirty:{key}"),
                ObjectRowClass::Runtime,
                &JournalPayload::DirtyTarget(value),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.outbox {
            rows.push(runtime_row(
                format!("runtime:outbox:{id}"),
                ObjectRowClass::Runtime,
                &JournalPayload::OutboxEnqueued(value),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.jobs {
            rows.push(runtime_row(
                format!("runtime:job:{id}"),
                ObjectRowClass::Runtime,
                &JournalPayload::JobState(value),
                seq,
            )?);
        }
        for (kind, (value, seq)) in self.watermarks {
            rows.push(runtime_row(
                format!("runtime:watermark:{kind}"),
                ObjectRowClass::Runtime,
                &JournalPayload::WatermarkAdvanced(value),
                seq,
            )?);
        }
        if let Some((payload, seq)) = self.config {
            rows.push(runtime_row(
                "runtime:config:current".into(),
                ObjectRowClass::Runtime,
                &payload,
                seq,
            )?);
        }
        for (event_id, (payload, seq)) in self.stale_audits {
            rows.push(runtime_row(
                format!("projection:audit:stale:{event_id}"),
                ObjectRowClass::Projection,
                &payload,
                seq,
            )?);
        }
        for (key, (value, seq)) in self.source_revisions {
            let fields = evidence_fields(
                format!("object:evidence:source_revision:{key}"),
                "source_revision",
                key,
                value.source_revision.as_str().to_owned(),
                None,
                None,
                None,
            );
            rows.push(evidence_object_row(
                fields,
                &JournalPayload::SourceRevisionRecorded(value),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.source_receipts {
            let fields = evidence_fields(
                format!("object:evidence:source_receipt:{id}"),
                "source_receipt",
                id.to_string(),
                id.to_string(),
                value.repository_instance_id.map(|value| value.to_string()),
                value.worktree_instance_id.map(|value| value.to_string()),
                value.task_id.map(|value| value.to_string()),
            );
            rows.push(evidence_object_row(
                fields,
                &JournalPayload::SourceReceiptRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.source_observations {
            let fields = evidence_fields(
                format!("object:evidence:source_observation:{id}"),
                "source_observation",
                id.to_string(),
                id.to_string(),
                None,
                None,
                None,
            );
            rows.push(evidence_object_row(
                fields,
                &JournalPayload::SourceObservationRecorded(Box::new(value)),
                seq,
            )?);
        }
        for (key, (value, seq)) in self.source_watermarks {
            rows.push(runtime_row(
                format!("runtime:watermark:source:{key}"),
                ObjectRowClass::Runtime,
                &JournalPayload::SourceIngestWatermark(value),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.evidence_surfaces {
            rows.push(surface_row(id, value, seq)?);
        }
        for (id, (value, seq)) in self.host_occurrences {
            rows.push(physical_object_row(
                ObjectFamily::Evidence,
                "host_occurrence",
                id.to_string(),
                format!("{}@{}", id, value.normalization_revision),
                &JournalPayload::HostOccurrenceNormalized(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.operations {
            rows.push(physical_object_row(
                ObjectFamily::Work,
                "operation",
                id.to_string(),
                format!("{}@{}", id, value.operation_revision),
                &JournalPayload::OperationDerived(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.scope_effects {
            rows.push(physical_object_row(
                ObjectFamily::Work,
                "scope_effect",
                id.to_string(),
                id.to_string(),
                &JournalPayload::ScopeEffectDerived(Box::new(value)),
                seq,
            )?);
        }
        for (id, (value, seq)) in self.normalization_watermarks {
            rows.push(runtime_row(
                format!("runtime:watermark:normalization:{id}"),
                ObjectRowClass::Runtime,
                &JournalPayload::NormalizationWatermark(value),
                seq,
            )?);
        }
        Ok(rows)
    }

    fn validate_evidence_relations(&self) -> Result<(), StoreError> {
        for (observation, _) in self.source_observations.values() {
            let receipt = self
                .source_receipts
                .get(&observation.source_receipt_ref)
                .ok_or(StoreError::StoreCorrupt)?;
            if receipt.0.source_observation_id != observation.source_observation_id {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for (surface, _) in self.evidence_surfaces.values() {
            if !self
                .source_observations
                .contains_key(&surface.source_observation_revision_ref)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for (occurrence, _) in self.host_occurrences.values() {
            if occurrence
                .source_observation_refs
                .iter()
                .any(|id| !self.source_observations.contains_key(id))
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for (operation, _) in self.operations.values() {
            let Some((occurrence, _)) = self.host_occurrences.get(&operation.host_occurrence_id)
            else {
                return Err(StoreError::StoreCorrupt);
            };
            if operation
                .input_source_observation_refs
                .iter()
                .chain(&operation.result_source_observation_refs)
                .any(|id| !occurrence.source_observation_refs.contains(id))
            {
                return Err(StoreError::StoreCorrupt);
            }
            let actual = self
                .scope_effects
                .values()
                .filter(|(effect, _)| effect.operation_id == operation.operation_id)
                .map(|(effect, _)| effect.scope_effect_id)
                .collect::<std::collections::BTreeSet<_>>();
            if actual != operation.scope_effect_ids.iter().copied().collect() {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for (effect, _) in self.scope_effects.values() {
            let Some((operation, _)) = self.operations.get(&effect.operation_id) else {
                return Err(StoreError::StoreCorrupt);
            };
            let occurrence = self
                .host_occurrences
                .get(&operation.host_occurrence_id)
                .ok_or(StoreError::StoreCorrupt)?;
            if effect
                .evidence_refs
                .iter()
                .any(|id| !occurrence.0.source_observation_refs.contains(id))
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for watermark in self.normalization_watermarks.keys() {
            if !self.source_observations.contains_key(watermark) {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Ok(())
    }
}

fn require_row(
    row: &ObjectRow,
    expected_class: ObjectRowClass,
    expected_id: &str,
) -> Result<(), StoreError> {
    if row.row_class != Some(expected_class) || row.row_id != expected_id {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

struct EvidenceRowFields {
    row_id: String,
    object_kind: String,
    object_id: String,
    revision_id: String,
    repository_id: Option<String>,
    worktree_id: Option<String>,
    task_id: Option<String>,
}

fn evidence_fields(
    row_id: String,
    object_kind: &str,
    object_id: String,
    revision_id: String,
    repository_id: Option<String>,
    worktree_id: Option<String>,
    task_id: Option<String>,
) -> EvidenceRowFields {
    EvidenceRowFields {
        row_id,
        object_kind: object_kind.to_owned(),
        object_id,
        revision_id,
        repository_id,
        worktree_id,
        task_id,
    }
}

fn require_evidence_object_row(
    row: &ObjectRow,
    fields: &EvidenceRowFields,
) -> Result<(), StoreError> {
    if row.row_id != fields.row_id
        || row.row_class != Some(ObjectRowClass::Object)
        || row.object_family != Some(ObjectFamily::Evidence)
        || row.object_kind.as_deref() != Some(fields.object_kind.as_str())
        || row.object_id.as_deref() != Some(fields.object_id.as_str())
        || row.current_revision_id.as_deref() != Some(fields.revision_id.as_str())
        || row.lifecycle.as_deref() != Some("immutable")
        || row.authority.as_deref() != Some("none")
        || row.repository_id != fields.repository_id
        || row.worktree_id != fields.worktree_id
        || row.task_id != fields.task_id
        || row.project_id.is_some()
        || row.workstream_id.is_some()
        || row.session_id.is_some()
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn require_physical_row(
    row: &ObjectRow,
    family: ObjectFamily,
    kind: &str,
    object_id: &str,
    revision_id: &str,
) -> Result<(), StoreError> {
    if row.row_id != format!("object:{}:{kind}:{object_id}", family.as_str())
        || row.row_class != Some(ObjectRowClass::Object)
        || row.object_family != Some(family)
        || row.object_kind.as_deref() != Some(kind)
        || row.object_id.as_deref() != Some(object_id)
        || row.current_revision_id.as_deref() != Some(revision_id)
        || row.lifecycle.as_deref() != Some("immutable")
        || row.authority.as_deref() != Some("none")
        || row.project_id.is_some()
        || row.repository_id.is_some()
        || row.worktree_id.is_some()
        || row.task_id.is_some()
        || row.workstream_id.is_some()
        || row.session_id.is_some()
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn require_surface_row(row: &ObjectRow, surface: &EvidenceSurface) -> Result<(), StoreError> {
    let revision_id = surface.source_observation_revision_ref.to_string();
    if row.row_id
        != format!(
            "projection:evidence_surface:{}",
            surface.source_observation_revision_ref
        )
        || row.row_class != Some(ObjectRowClass::Projection)
        || row.object_family.is_some()
        || row.object_kind.as_deref() != Some("evidence_surface")
        || row.object_id.is_some()
        || row.current_revision_id.as_deref() != Some(revision_id.as_str())
        || row.authority.as_deref() != Some("none")
        || row.repository_id
            != surface
                .repository_instance_id
                .map(|value| value.to_string())
        || row.worktree_id != surface.worktree_instance_id.map(|value| value.to_string())
        || row.task_id != surface.task_id.map(|value| value.to_string())
        || row.project_id.is_some()
        || row.workstream_id.is_some()
        || row.session_id.is_some()
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn valid_event_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn runtime_row(
    row_id: String,
    row_class: ObjectRowClass,
    payload: &JournalPayload,
    source_event_seq: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id,
        row_kind: ObjectRowKind::Data,
        row_class: Some(row_class),
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
        payload_json: Some(payload.canonical_json()?),
        source_event_seq,
        projection_generation: PROJECTION_GENERATION,
    })
}

fn evidence_object_row(
    fields: EvidenceRowFields,
    payload: &JournalPayload,
    source_event_seq: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id: fields.row_id,
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Object),
        object_family: Some(ObjectFamily::Evidence),
        object_kind: Some(fields.object_kind),
        object_id: Some(fields.object_id),
        current_revision_id: Some(fields.revision_id),
        lifecycle: Some("immutable".into()),
        epistemic: Some("observed".into()),
        authority: Some("none".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: fields.repository_id,
        worktree_id: fields.worktree_id,
        task_id: fields.task_id,
        workstream_id: None,
        session_id: None,
        payload_json: Some(payload.canonical_json()?),
        source_event_seq,
        projection_generation: PROJECTION_GENERATION,
    })
}

fn physical_object_row(
    family: ObjectFamily,
    kind: &str,
    object_id: String,
    revision_id: String,
    payload: &JournalPayload,
    source_event_seq: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id: format!("object:{}:{kind}:{object_id}", family.as_str()),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Object),
        object_family: Some(family),
        object_kind: Some(kind.into()),
        object_id: Some(object_id),
        current_revision_id: Some(revision_id),
        lifecycle: Some("immutable".into()),
        epistemic: Some("observed".into()),
        authority: Some("none".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: None,
        worktree_id: None,
        task_id: None,
        workstream_id: None,
        session_id: None,
        payload_json: Some(payload.canonical_json()?),
        source_event_seq,
        projection_generation: PROJECTION_GENERATION,
    })
}

fn surface_row(
    id: SourceObservationId,
    surface: EvidenceSurface,
    source_event_seq: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id: format!("projection:evidence_surface:{id}"),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Projection),
        object_family: None,
        object_kind: Some("evidence_surface".into()),
        object_id: None,
        current_revision_id: Some(id.to_string()),
        lifecycle: None,
        epistemic: Some("evidence".into()),
        authority: Some("none".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: surface
            .repository_instance_id
            .map(|value| value.to_string()),
        worktree_id: surface.worktree_instance_id.map(|value| value.to_string()),
        task_id: surface.task_id.map(|value| value.to_string()),
        workstream_id: None,
        session_id: None,
        payload_json: Some(
            JournalPayload::EvidenceSurfaceRecorded(Box::new(surface)).canonical_json()?,
        ),
        source_event_seq,
        projection_generation: PROJECTION_GENERATION,
    })
}

fn source_revision_key(value: &SourceRevisionRecorded) -> String {
    format!(
        "{}:{}{}:{}",
        value.source_instance_id.as_str().len(),
        value.source_instance_id.as_str(),
        value.source_revision.as_str().len(),
        value.source_revision.as_str()
    )
}

#[derive(Clone)]
pub struct ProjectionWorker {
    journal: Table,
    objects: Table,
}

impl ProjectionWorker {
    pub(crate) fn new(journal: Table, objects: Table) -> Self {
        Self { journal, objects }
    }

    pub async fn catch_up(&self) -> Result<ProjectionSnapshot, StoreError> {
        self.catch_up_inner(false).await
    }

    async fn catch_up_inner(
        &self,
        inject_before_commit_failure: bool,
    ) -> Result<ProjectionSnapshot, StoreError> {
        let current = validate_objects_table(&self.objects).await?;
        let checkpoint = current
            .iter()
            .find(|row| row.row_id == OBJECTS_CHECKPOINT_ID)
            .ok_or(StoreError::StoreCorrupt)?;
        let checkpoint_frontier = checkpoint.source_event_seq;
        let journal_frontier = read_journal_frontier(&self.journal).await?;
        if checkpoint.source_event_seq > journal_frontier {
            return Err(StoreError::StoreCorrupt);
        }
        if checkpoint_frontier == 0 && current.len() == 1 && journal_frontier > 0 {
            let expected = self.full_snapshot().await?;
            if expected.frontier != journal_frontier {
                return Err(StoreError::StoreCorrupt);
            }
            if inject_before_commit_failure {
                return Err(StoreError::Projection);
            }
            self.commit_rows(&expected.rows).await?;
            let persisted = validate_objects_table(&self.objects).await?;
            if persisted != expected.rows {
                return Err(StoreError::Projection);
            }
            return Ok(expected);
        }
        let mut state = ReducerState::from_current_rows(&current, checkpoint_frontier)?;
        let delta = read_journal_after(&self.journal, checkpoint_frontier).await?;
        validate_delta(checkpoint_frontier, journal_frontier, &delta)?;
        if delta.is_empty() {
            return Ok(ProjectionSnapshot {
                frontier: checkpoint_frontier,
                rows: current,
            });
        }
        for row in &delta {
            apply_event(&mut state, row)?;
        }
        let expected = state.into_snapshot(journal_frontier)?;
        let current_by_id = current
            .iter()
            .map(|row| (row.row_id.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        let changed = expected
            .rows
            .iter()
            .filter(|row| {
                row.row_id == OBJECTS_CHECKPOINT_ID
                    || current_by_id.get(row.row_id.as_str()).copied() != Some(*row)
            })
            .cloned()
            .collect::<Vec<_>>();
        if inject_before_commit_failure {
            return Err(StoreError::Projection);
        }
        self.commit_rows(&changed).await?;
        let persisted = validate_objects_table(&self.objects).await?;
        let persisted_snapshot = ProjectionSnapshot {
            frontier: expected.frontier,
            rows: persisted,
        };
        if persisted_snapshot.rows != expected.rows {
            return Err(StoreError::Projection);
        }
        Ok(persisted_snapshot)
    }

    #[cfg(test)]
    async fn catch_up_with_commit_fault(&self) -> Result<ProjectionSnapshot, StoreError> {
        self.catch_up_inner(true).await
    }

    pub async fn full_snapshot(&self) -> Result<ProjectionSnapshot, StoreError> {
        reduce_journal(&read_all_journal_rows(&self.journal).await?)
    }

    async fn commit_rows(&self, rows: &[ObjectRow]) -> Result<(), StoreError> {
        let batch = objects_batch(rows)?;
        let reader: Box<dyn arrow_array::RecordBatchReader + Send> = Box::new(
            RecordBatchIterator::new(vec![Ok(batch)], crate::objects::objects_schema()),
        );
        let mut merge = self.objects.merge_insert(&["row_id"]);
        merge.when_matched_update_all(None);
        merge.when_not_matched_insert_all();
        merge
            .execute(reader)
            .await
            .map_err(|_| StoreError::Projection)?;
        Ok(())
    }
}

fn validate_delta(
    checkpoint_frontier: u64,
    journal_frontier: u64,
    rows: &[JournalRow],
) -> Result<(), StoreError> {
    if rows.is_empty() {
        return if checkpoint_frontier == journal_frontier {
            Ok(())
        } else {
            Err(StoreError::StoreCorrupt)
        };
    }
    if checkpoint_frontier >= journal_frontier
        || rows
            .first()
            .is_none_or(|row| row.seq <= checkpoint_frontier)
        || rows.last().is_none_or(|row| row.seq != journal_frontier)
        || rows.windows(2).any(|pair| pair[0].seq >= pair[1].seq)
    {
        return Err(StoreError::StoreCorrupt);
    }
    validate_journal_rows(rows)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use evertrace_domain::ids::{CommandId, JobId};

    use super::*;
    use crate::{
        command::{
            DirtyTargetKind, JobLease, JournalCommand, JournalEventDraft, MigrationApplied,
            PreparedCommand, prepare_command,
        },
        journal::rows_for_append,
        objects::read_object_rows,
        writer::JournalWriter,
    };

    fn command_id(value: &str) -> CommandId {
        CommandId::from_str(value).unwrap()
    }

    fn job_id() -> JobId {
        JobId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a4b").unwrap()
    }

    fn append(
        command: JournalCommand,
        first_seq: u64,
        rows: &mut Vec<JournalRow>,
    ) -> PreparedCommand {
        let prepared = prepare_command(&command).unwrap();
        rows.extend(rows_for_append(&prepared, first_seq, 0).unwrap());
        prepared
    }

    #[test]
    fn reducer_coalesces_dirty_outbox_and_recovers_lease_with_seq_gaps() {
        let dirty = DirtyTarget {
            target_kind: DirtyTargetKind::ObjectsProjection,
            target_id: "objects".into(),
            algorithm_revision: "v1".into(),
            source_watermark: 9,
        };
        let job = DurableJob {
            job_id: job_id(),
            idempotency_key: "job-key".into(),
            target_revision: "revision-1".into(),
            target_watermark: 9,
            target_generation: 1,
            kind: "projection_rebuild".into(),
            priority: 1,
            state: JobStatus::Queued,
            attempt: 1,
            backoff_until_us: None,
            config_hash: [7; 32],
            lease_until_us: None,
        };
        let mut rows = Vec::new();
        append(
            JournalCommand::new(
                command_id("01890f47-6a4a-7cc1-98b9-01890f476a4a"),
                vec![
                    JournalEventDraft::runtime(
                        0,
                        [0; 32],
                        "v1",
                        JournalPayload::MigrationApplied(MigrationApplied {
                            migration_id: "L0001".into(),
                        }),
                    ),
                    JournalEventDraft::runtime(
                        0,
                        [0; 32],
                        "v1",
                        JournalPayload::DirtyTarget(dirty.clone()),
                    ),
                    JournalEventDraft::runtime(
                        0,
                        [0; 32],
                        "v1",
                        JournalPayload::OutboxEnqueued(OutboxEntry {
                            outbox_id: "outbox-1".into(),
                            dirty: dirty.clone(),
                        }),
                    ),
                    JournalEventDraft::runtime(
                        0,
                        [0; 32],
                        "v1",
                        JournalPayload::JobState(job.clone()),
                    ),
                ],
            )
            .unwrap(),
            1,
            &mut rows,
        );
        let first_len = rows.len();
        append(
            JournalCommand::new(
                command_id("01890f47-6a4a-7cc1-98b9-01890f476a4c"),
                vec![
                    JournalEventDraft::runtime(
                        1,
                        [0; 32],
                        "v1",
                        JournalPayload::DirtyTarget(dirty.clone()),
                    ),
                    JournalEventDraft::runtime(
                        1,
                        [0; 32],
                        "v1",
                        JournalPayload::OutboxEnqueued(OutboxEntry {
                            outbox_id: "outbox-1".into(),
                            dirty,
                        }),
                    ),
                    JournalEventDraft::runtime(
                        1,
                        [0; 32],
                        "v1",
                        JournalPayload::JobLease(JobLease {
                            job_id: job.job_id,
                            target_generation: 1,
                            attempt: 2,
                            lease_until_us: 100,
                        }),
                    ),
                ],
            )
            .unwrap(),
            10,
            &mut rows,
        );
        let snapshot = reduce_journal(&rows).unwrap();
        let first = reduce_journal(&rows[..first_len]).unwrap();
        let mut restored = ReducerState::from_current_rows(&first.rows, first.frontier).unwrap();
        let delta = &rows[first_len..];
        validate_delta(first.frontier, snapshot.frontier, delta).unwrap();
        for row in delta {
            apply_event(&mut restored, row).unwrap();
        }
        assert_eq!(restored.into_snapshot(snapshot.frontier).unwrap(), snapshot);
        assert_eq!(snapshot.frontier, 12);
        assert_eq!(
            snapshot
                .data_rows()
                .filter(|row| row.row_id.starts_with("runtime:dirty:"))
                .count(),
            1
        );
        assert_eq!(
            snapshot
                .data_rows()
                .filter(|row| row.row_id.starts_with("runtime:outbox:"))
                .count(),
            1
        );
        let job_row = snapshot
            .row(&format!("runtime:job:{}", job.job_id))
            .unwrap();
        let projected: JournalPayload =
            serde_json::from_str(job_row.payload_json.as_deref().unwrap()).unwrap();
        let JournalPayload::JobState(projected) = projected else {
            panic!("expected job state")
        };
        assert_eq!(projected.state, JobStatus::Leased);
        assert_eq!(projected.attempt, 2);
        assert_eq!(projected.lease_until_us, Some(100));
    }

    #[tokio::test]
    async fn projection_commit_fault_does_not_advance_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let command = JournalCommand::new(
            command_id("01890f47-6a4a-7cc1-98b9-01890f476a4d"),
            vec![JournalEventDraft::runtime(
                1,
                [0; 32],
                "v1",
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::ObjectsProjection,
                    target_id: "fault".into(),
                    algorithm_revision: "v1".into(),
                    source_watermark: 1,
                }),
            )],
        )
        .unwrap();
        writer.commit(&command, 1).await.unwrap();
        let connection = lancedb::connect(root.to_str().unwrap())
            .execute()
            .await
            .unwrap();
        let journal = connection
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        let objects = connection
            .open_table(crate::OBJECTS_TABLE)
            .execute()
            .await
            .unwrap();
        let before = read_object_rows(&objects).await.unwrap();
        let worker = ProjectionWorker::new(journal, objects.clone());
        assert_eq!(
            worker.catch_up_with_commit_fault().await,
            Err(StoreError::Projection)
        );
        assert_eq!(read_object_rows(&objects).await.unwrap(), before);
        assert_eq!(
            worker.catch_up().await.unwrap(),
            writer.full_projection().await.unwrap()
        );
    }

    #[tokio::test]
    async fn checkpoint_ahead_of_journal_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let writer = JournalWriter::open(&root).await.unwrap();
        let connection = lancedb::connect(root.to_str().unwrap())
            .execute()
            .await
            .unwrap();
        let journal = connection
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        let objects = connection
            .open_table(crate::OBJECTS_TABLE)
            .execute()
            .await
            .unwrap();
        let worker = ProjectionWorker::new(journal, objects);
        worker
            .commit_rows(&[ObjectRow::checkpoint(10_000, PROJECTION_GENERATION)])
            .await
            .unwrap();
        assert_eq!(worker.catch_up().await, Err(StoreError::StoreCorrupt));
        drop(writer);
    }

    #[tokio::test]
    async fn no_delta_is_version_stable_and_corrupt_current_row_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let writer = JournalWriter::open(&root).await.unwrap();
        let connection = lancedb::connect(root.to_str().unwrap())
            .execute()
            .await
            .unwrap();
        let journal = connection
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        let objects = connection
            .open_table(crate::OBJECTS_TABLE)
            .execute()
            .await
            .unwrap();
        let worker = ProjectionWorker::new(journal, objects.clone());
        let before_version = objects.version().await.unwrap();
        worker.catch_up().await.unwrap();
        assert_eq!(objects.version().await.unwrap(), before_version);

        let mut migration = read_object_rows(&objects)
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.row_id == "projection:migration:L0001")
            .unwrap();
        migration.payload_json = Some(
            JournalPayload::ConfigAudit(crate::ConfigAudit {
                config_version: 1,
                effective_config_hash: [0; 32],
            })
            .canonical_json()
            .unwrap(),
        );
        worker.commit_rows(&[migration]).await.unwrap();
        assert!(matches!(
            worker.catch_up().await,
            Err(StoreError::StoreCorrupt | StoreError::Projection)
        ));
        drop(writer);
    }

    #[tokio::test]
    async fn checkpoint_inside_command_makes_delta_partial_and_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let dirty = DirtyTarget {
            target_kind: DirtyTargetKind::ObjectsProjection,
            target_id: "partial".into(),
            algorithm_revision: "v1".into(),
            source_watermark: 1,
        };
        writer
            .commit(
                &JournalCommand::new(
                    command_id("01890f47-6a4a-7cc1-98b9-01890f476a4e"),
                    vec![
                        JournalEventDraft::runtime(
                            1,
                            [0; 32],
                            "v1",
                            JournalPayload::DirtyTarget(dirty.clone()),
                        ),
                        JournalEventDraft::runtime(
                            1,
                            [0; 32],
                            "v1",
                            JournalPayload::OutboxEnqueued(OutboxEntry {
                                outbox_id: "partial".into(),
                                dirty,
                            }),
                        ),
                    ],
                )
                .unwrap(),
                1,
            )
            .await
            .unwrap();
        let connection = lancedb::connect(root.to_str().unwrap())
            .execute()
            .await
            .unwrap();
        let journal = connection
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        let objects = connection
            .open_table(crate::OBJECTS_TABLE)
            .execute()
            .await
            .unwrap();
        let worker = ProjectionWorker::new(journal, objects);
        worker
            .commit_rows(&[ObjectRow::checkpoint(2, PROJECTION_GENERATION)])
            .await
            .unwrap();
        assert_eq!(worker.catch_up().await, Err(StoreError::StoreCorrupt));
    }
}
