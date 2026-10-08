use std::{collections::BTreeMap, sync::Arc};

use arrow_array::{
    Array, FixedSizeBinaryArray, LargeStringArray, RecordBatch, StringArray,
    TimestampMicrosecondArray, UInt16Array, UInt64Array,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use evertrace_domain::ids::CommandId;

use crate::command::{
    EventScope, JOURNAL_PAYLOAD_SCHEMA, JournalCommand, JournalEventDraft, JournalPayload,
    ObjectFamily, PreparedCommand, PreparedEvent, RecordClass, SourceKind, StoreError,
    prepare_command,
};

pub const JOURNAL_TABLE: &str = "evertrace_journal";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRow {
    pub event_id: String,
    pub command_id: CommandId,
    pub command_hash: [u8; 32],
    pub ordinal: u16,
    pub command_event_count: u16,
    pub seq: u64,
    pub event_type: String,
    pub record_class: RecordClass,
    pub object_family: Option<ObjectFamily>,
    pub object_id: Option<String>,
    pub revision_id: Option<String>,
    pub scope: EventScope,
    pub occurred_at_us: i64,
    pub ingested_at_us: i64,
    pub source_kind: SourceKind,
    pub source_ref_json: Option<String>,
    pub payload_schema: u16,
    pub payload_json: String,
    pub content_hash: [u8; 32],
    pub causation_id: Option<String>,
    pub correlation_id: Option<String>,
    pub effective_config_hash: [u8; 32],
    pub algorithm_revision: String,
}

impl JournalRow {
    pub fn payload(&self) -> Result<JournalPayload, StoreError> {
        serde_json::from_str(&self.payload_json).map_err(|_| StoreError::StoreCorrupt)
    }

    fn draft(&self) -> Result<JournalEventDraft, StoreError> {
        if self.object_family.is_some()
            || self.object_id.is_some()
            || self.revision_id.is_some()
            || self.source_ref_json.is_some()
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(JournalEventDraft {
            occurred_at_us: self.occurred_at_us,
            source_kind: self.source_kind,
            scope: self.scope.clone(),
            causation_id: self.causation_id.clone(),
            correlation_id: self.correlation_id.clone(),
            effective_config_hash: self.effective_config_hash,
            algorithm_revision: self.algorithm_revision.clone(),
            payload: self.payload()?,
        })
    }
}

/// Closed logical journal field set. The physical SQLite column definition is
/// the single storage shape; this schema keeps the logical contract and the
/// future converter's read boundary explicit.
pub fn journal_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("event_id", DataType::Utf8, false),
        Field::new("command_id", DataType::Utf8, false),
        Field::new("command_hash", DataType::FixedSizeBinary(32), false),
        Field::new("ordinal", DataType::UInt16, false),
        Field::new("command_event_count", DataType::UInt16, false),
        Field::new("seq", DataType::UInt64, false),
        Field::new("event_type", DataType::Utf8, false),
        Field::new("record_class", DataType::Utf8, false),
        Field::new("object_family", DataType::Utf8, true),
        Field::new("object_id", DataType::Utf8, true),
        Field::new("revision_id", DataType::Utf8, true),
        Field::new("project_id", DataType::Utf8, true),
        Field::new("repository_id", DataType::Utf8, true),
        Field::new("worktree_id", DataType::Utf8, true),
        Field::new("task_id", DataType::Utf8, true),
        Field::new("workstream_id", DataType::Utf8, true),
        Field::new("session_id", DataType::Utf8, true),
        Field::new("execution_lane_id", DataType::Utf8, true),
        Field::new(
            "occurred_at_us",
            DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new(
            "ingested_at_us",
            DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new("source_kind", DataType::Utf8, false),
        Field::new("source_ref_json", DataType::LargeUtf8, true),
        Field::new("payload_schema", DataType::UInt16, false),
        Field::new("payload_json", DataType::LargeUtf8, false),
        Field::new("content_hash", DataType::FixedSizeBinary(32), false),
        Field::new("causation_id", DataType::Utf8, true),
        Field::new("correlation_id", DataType::Utf8, true),
        Field::new(
            "effective_config_hash",
            DataType::FixedSizeBinary(32),
            false,
        ),
        Field::new("algorithm_revision", DataType::Utf8, false),
    ]))
}

pub(crate) fn validate_journal_rows(rows: &[JournalRow]) -> Result<(), StoreError> {
    let mut ordered = rows.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|row| row.seq);
    for pair in ordered.windows(2) {
        if pair[0].seq >= pair[1].seq {
            return Err(StoreError::StoreCorrupt);
        }
    }
    let mut commands: BTreeMap<CommandId, Vec<&JournalRow>> = BTreeMap::new();
    for row in rows {
        commands.entry(row.command_id).or_default().push(row);
    }
    for command_rows in commands.into_values() {
        validate_complete_command_refs(command_rows)?;
    }
    Ok(())
}

pub(crate) fn validate_complete_command(rows: &[JournalRow]) -> Result<(), StoreError> {
    validate_complete_command_refs(rows.iter().collect()).map(|_| ())
}

fn validate_complete_command_refs(
    mut ordered: Vec<&JournalRow>,
) -> Result<Vec<&JournalRow>, StoreError> {
    if ordered.is_empty() {
        return Err(StoreError::StoreCorrupt);
    }
    let expected_count = ordered[0].command_event_count;
    if expected_count == 0 || ordered.len() != usize::from(expected_count) {
        return Err(StoreError::StoreCorrupt);
    }
    let command_id = ordered[0].command_id;
    ordered.sort_by_key(|row| row.ordinal);
    for (index, row) in ordered.iter().enumerate() {
        if row.command_id != command_id
            || row.command_event_count != expected_count
            || usize::from(row.ordinal) != index
            || row.payload_schema != JOURNAL_PAYLOAD_SCHEMA
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    let command = JournalCommand::new(
        command_id,
        ordered
            .iter()
            .map(|row| (*row).draft())
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let prepared = prepare_command(&command)?;
    if ordered
        .iter()
        .any(|row| row.command_hash != prepared.command_hash)
    {
        return Err(StoreError::StoreCorrupt);
    }
    for (row, expected) in ordered.iter().zip(&prepared.events) {
        if row.event_id != expected.event_id
            || row.event_type != expected.event_type
            || row.record_class != expected.record_class
            || row.payload_json != expected.payload_json
            || row.content_hash != expected.content_hash
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    Ok(ordered)
}

pub(crate) fn replay_outcome(
    rows: &[JournalRow],
    prepared: &PreparedCommand,
) -> Result<Option<crate::command::CommitOutcome>, StoreError> {
    if rows.is_empty() {
        return Ok(None);
    }
    let ordered = validate_complete_command_refs(rows.iter().collect())?;
    if rows
        .iter()
        .any(|row| row.command_hash != prepared.command_hash)
    {
        return Err(StoreError::IdempotencyConflict);
    }
    let expected_count = usize::from(prepared.event_count);
    if rows.len() != expected_count {
        return Err(StoreError::IdempotencyConflict);
    }
    for (index, row) in ordered.iter().enumerate() {
        if usize::from(row.ordinal) != index || row.command_event_count != prepared.event_count {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for (row, expected) in ordered.iter().zip(&prepared.events) {
        if row.event_id != expected.event_id {
            return Err(StoreError::StoreCorrupt);
        }
    }
    Ok(Some(crate::command::CommitOutcome {
        command_id: prepared.command_id,
        first_seq: ordered.first().ok_or(StoreError::StoreCorrupt)?.seq,
        last_seq: ordered.last().ok_or(StoreError::StoreCorrupt)?.seq,
        event_ids: ordered
            .into_iter()
            .map(|row| row.event_id.clone())
            .collect(),
        replayed: true,
    }))
}

/// Decode one physical journal batch of the retired Lance layout. The
/// offline converter is the only consumer; normal reads go through SQLite.
pub(crate) fn rows_from_batch(batch: &RecordBatch) -> Result<Vec<JournalRow>, StoreError> {
    if batch.schema().as_ref() != journal_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    let event_ids = array::<StringArray>(batch, 0)?;
    let command_ids = array::<StringArray>(batch, 1)?;
    let command_hashes = array::<FixedSizeBinaryArray>(batch, 2)?;
    let ordinals = array::<UInt16Array>(batch, 3)?;
    let counts = array::<UInt16Array>(batch, 4)?;
    let seqs = array::<UInt64Array>(batch, 5)?;
    let event_types = array::<StringArray>(batch, 6)?;
    let record_classes = array::<StringArray>(batch, 7)?;
    let object_families = array::<StringArray>(batch, 8)?;
    let object_ids = array::<StringArray>(batch, 9)?;
    let revision_ids = array::<StringArray>(batch, 10)?;
    let project_ids = array::<StringArray>(batch, 11)?;
    let repository_ids = array::<StringArray>(batch, 12)?;
    let worktree_ids = array::<StringArray>(batch, 13)?;
    let task_ids = array::<StringArray>(batch, 14)?;
    let workstream_ids = array::<StringArray>(batch, 15)?;
    let session_ids = array::<StringArray>(batch, 16)?;
    let lane_ids = array::<StringArray>(batch, 17)?;
    let occurred = array::<TimestampMicrosecondArray>(batch, 18)?;
    let ingested = array::<TimestampMicrosecondArray>(batch, 19)?;
    let source_kinds = array::<StringArray>(batch, 20)?;
    let source_refs = array::<LargeStringArray>(batch, 21)?;
    let payload_schemas = array::<UInt16Array>(batch, 22)?;
    let payload_json = array::<LargeStringArray>(batch, 23)?;
    let content_hashes = array::<FixedSizeBinaryArray>(batch, 24)?;
    let causation_ids = array::<StringArray>(batch, 25)?;
    let correlation_ids = array::<StringArray>(batch, 26)?;
    let config_hashes = array::<FixedSizeBinaryArray>(batch, 27)?;
    let algorithms = array::<StringArray>(batch, 28)?;
    let mut rows = Vec::with_capacity(batch.num_rows());
    for index in 0..batch.num_rows() {
        rows.push(JournalRow {
            event_id: event_ids.value(index).into(),
            command_id: command_ids
                .value(index)
                .parse()
                .map_err(|_| StoreError::StoreCorrupt)?,
            command_hash: fixed_hash(command_hashes, index)?,
            ordinal: ordinals.value(index),
            command_event_count: counts.value(index),
            seq: seqs.value(index),
            event_type: event_types.value(index).into(),
            record_class: RecordClass::parse(record_classes.value(index))?,
            object_family: optional_string(object_families, index)
                .map(ObjectFamily::parse)
                .transpose()?,
            object_id: optional_owned(object_ids, index),
            revision_id: optional_owned(revision_ids, index),
            scope: EventScope {
                project_id: optional_owned(project_ids, index),
                repository_id: optional_owned(repository_ids, index),
                worktree_id: optional_owned(worktree_ids, index),
                task_id: optional_owned(task_ids, index),
                workstream_id: optional_owned(workstream_ids, index),
                session_id: optional_owned(session_ids, index),
                execution_lane_id: optional_owned(lane_ids, index),
            },
            occurred_at_us: occurred.value(index),
            ingested_at_us: ingested.value(index),
            source_kind: SourceKind::parse(source_kinds.value(index))?,
            source_ref_json: optional_large_owned(source_refs, index),
            payload_schema: payload_schemas.value(index),
            payload_json: payload_json.value(index).into(),
            content_hash: fixed_hash(content_hashes, index)?,
            causation_id: optional_owned(causation_ids, index),
            correlation_id: optional_owned(correlation_ids, index),
            effective_config_hash: fixed_hash(config_hashes, index)?,
            algorithm_revision: algorithms.value(index).into(),
        });
    }
    Ok(rows)
}

fn array<T: Array + 'static>(batch: &RecordBatch, index: usize) -> Result<&T, StoreError> {
    batch
        .column(index)
        .as_any()
        .downcast_ref::<T>()
        .ok_or(StoreError::StoreCorrupt)
}

fn optional_string(array: &StringArray, index: usize) -> Option<&str> {
    (!array.is_null(index)).then(|| array.value(index))
}

fn optional_owned(array: &StringArray, index: usize) -> Option<String> {
    optional_string(array, index).map(str::to_owned)
}

fn optional_large_owned(array: &LargeStringArray, index: usize) -> Option<String> {
    (!array.is_null(index)).then(|| array.value(index).to_owned())
}

fn fixed_hash(array: &FixedSizeBinaryArray, index: usize) -> Result<[u8; 32], StoreError> {
    array
        .value(index)
        .try_into()
        .map_err(|_| StoreError::StoreCorrupt)
}

pub(crate) fn rows_for_append(
    prepared: &PreparedCommand,
    first_seq: u64,
    ingested_at_us: i64,
) -> Result<Vec<JournalRow>, StoreError> {
    if ingested_at_us < 0 {
        return Err(StoreError::InvalidInput);
    }
    prepared
        .events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let offset = u64::try_from(index).map_err(|_| StoreError::InvalidInput)?;
            let seq = first_seq
                .checked_add(offset)
                .ok_or(StoreError::InvalidInput)?;
            Ok(row_from_prepared(prepared, event, seq, ingested_at_us))
        })
        .collect()
}

fn row_from_prepared(
    command: &PreparedCommand,
    event: &PreparedEvent,
    seq: u64,
    ingested_at_us: i64,
) -> JournalRow {
    JournalRow {
        event_id: event.event_id.clone(),
        command_id: command.command_id,
        command_hash: command.command_hash,
        ordinal: event.ordinal,
        command_event_count: command.event_count,
        seq,
        event_type: event.event_type.into(),
        record_class: event.record_class,
        object_family: None,
        object_id: None,
        revision_id: None,
        scope: event.draft.scope.clone(),
        occurred_at_us: event.draft.occurred_at_us,
        ingested_at_us,
        source_kind: event.draft.source_kind,
        source_ref_json: None,
        payload_schema: JOURNAL_PAYLOAD_SCHEMA,
        payload_json: event.payload_json.clone(),
        content_hash: event.content_hash,
        causation_id: event.draft.causation_id.clone(),
        correlation_id: event.draft.correlation_id.clone(),
        effective_config_hash: event.draft.effective_config_hash,
        algorithm_revision: event.draft.algorithm_revision.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{JournalPayload, MigrationApplied};

    const COMMAND: &str = "01890f47-6a4a-7cc1-98b9-01890f476a4a";

    fn valid_rows() -> Vec<JournalRow> {
        let command = JournalCommand::new(
            COMMAND.parse().unwrap(),
            vec![JournalEventDraft::runtime(
                0,
                [0; 32],
                "l0001",
                JournalPayload::MigrationApplied(MigrationApplied {
                    migration_id: "L0001".into(),
                }),
            )],
        )
        .unwrap();
        let prepared = prepare_command(&command).unwrap();
        rows_for_append(&prepared, 1, 0).unwrap()
    }

    #[test]
    fn partial_duplicate_and_mismatched_command_rows_fail_closed() {
        let partial = {
            let mut rows = valid_rows();
            rows[0].command_event_count = 2;
            rows
        };
        assert_eq!(
            validate_complete_command(&partial),
            Err(StoreError::StoreCorrupt)
        );

        let duplicate = {
            let mut rows = valid_rows();
            rows.push(rows[0].clone());
            rows[0].command_event_count = 2;
            rows[1].command_event_count = 2;
            rows
        };
        assert_eq!(
            validate_complete_command(&duplicate),
            Err(StoreError::StoreCorrupt)
        );

        for mutate in [
            |row: &mut JournalRow| row.event_id.push('0'),
            |row: &mut JournalRow| row.command_hash[0] ^= 1,
            |row: &mut JournalRow| row.content_hash[0] ^= 1,
            |row: &mut JournalRow| row.payload_schema += 1,
        ] {
            let mut rows = valid_rows();
            mutate(&mut rows[0]);
            assert_eq!(
                validate_complete_command(&rows),
                Err(StoreError::StoreCorrupt)
            );
        }
    }
}
