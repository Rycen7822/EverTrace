use std::{collections::BTreeMap, sync::Arc};

use arrow_array::{
    Array, ArrayRef, FixedSizeBinaryArray, LargeStringArray, RecordBatch, StringArray,
    TimestampMicrosecondArray, UInt16Array, UInt64Array,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
use evertrace_domain::ids::CommandId;
use lancedb::{
    Table,
    query::{ColumnOrdering, QueryBase, Select},
};

use crate::{
    collect_batches,
    command::{
        CommitOutcome, EventScope, JOURNAL_PAYLOAD_SCHEMA, JournalCommand, JournalEventDraft,
        JournalPayload, ObjectFamily, PreparedCommand, PreparedEvent, RecordClass, SourceKind,
        StoreError, prepare_command,
    },
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
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            false,
        ),
        Field::new(
            "ingested_at_us",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
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

pub(crate) async fn validate_journal_table(table: &Table) -> Result<(), StoreError> {
    let actual = table.schema().await.map_err(|_| StoreError::LanceDb)?;
    if actual.as_ref() != journal_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    validate_journal_rows(&read_all_journal_rows(table).await?)
}

pub async fn read_all_journal_rows(table: &Table) -> Result<Vec<JournalRow>, StoreError> {
    read_query(table.query()).await
}

pub async fn read_journal_after(table: &Table, seq: u64) -> Result<Vec<JournalRow>, StoreError> {
    read_query(
        table
            .query()
            .only_if(format!("seq > {seq}"))
            .order_by(Some(vec![ColumnOrdering::asc_nulls_last("seq".into())])),
    )
    .await
}

pub(crate) async fn read_journal_frontier(table: &Table) -> Result<u64, StoreError> {
    let query = table
        .query()
        .select(Select::columns(&["seq"]))
        .order_by(Some(vec![ColumnOrdering::desc_nulls_last("seq".into())]))
        .limit(1);
    let batches = collect_batches(&query)
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let mut frontier = None;
    for batch in &batches {
        if batch.num_columns() != 1
            || batch.schema().field(0).name() != "seq"
            || batch.schema().field(0).data_type() != &DataType::UInt64
            || batch.schema().field(0).is_nullable()
        {
            return Err(StoreError::StoreCorrupt);
        }
        let values = batch
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or(StoreError::StoreCorrupt)?;
        for index in 0..values.len() {
            if values.is_null(index) || frontier.replace(values.value(index)).is_some() {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    Ok(frontier.unwrap_or(0))
}

pub(crate) async fn read_command_rows(
    table: &Table,
    command_id: CommandId,
) -> Result<Vec<JournalRow>, StoreError> {
    read_query(
        table
            .query()
            .only_if(format!("command_id = '{}'", command_id)),
    )
    .await
}

async fn read_query(query: lancedb::query::Query) -> Result<Vec<JournalRow>, StoreError> {
    let batches = collect_batches(&query)
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let mut rows = Vec::new();
    for batch in &batches {
        rows.extend(rows_from_batch(batch)?);
    }
    Ok(rows)
}

pub(crate) fn validate_journal_rows(rows: &[JournalRow]) -> Result<(), StoreError> {
    let mut ordered = rows.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|row| row.seq);
    for pair in ordered.windows(2) {
        if pair[0].seq >= pair[1].seq {
            return Err(StoreError::StoreCorrupt);
        }
    }
    let mut commands: BTreeMap<CommandId, Vec<JournalRow>> = BTreeMap::new();
    for row in rows {
        commands
            .entry(row.command_id)
            .or_default()
            .push(row.clone());
    }
    for command_rows in commands.values() {
        validate_complete_command(command_rows)?;
    }
    Ok(())
}

pub(crate) fn validate_complete_command(rows: &[JournalRow]) -> Result<(), StoreError> {
    if rows.is_empty() {
        return Err(StoreError::StoreCorrupt);
    }
    let expected_count = rows[0].command_event_count;
    if expected_count == 0 || rows.len() != usize::from(expected_count) {
        return Err(StoreError::StoreCorrupt);
    }
    let command_id = rows[0].command_id;
    let mut ordered = rows.to_vec();
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
            .map(JournalRow::draft)
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
    Ok(())
}

pub(crate) fn replay_outcome(
    rows: &[JournalRow],
    prepared: &PreparedCommand,
) -> Result<Option<CommitOutcome>, StoreError> {
    if rows.is_empty() {
        return Ok(None);
    }
    validate_complete_command(rows)?;
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
    let mut ordered = rows.to_vec();
    ordered.sort_by_key(|row| row.ordinal);
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
    Ok(Some(CommitOutcome {
        command_id: prepared.command_id,
        first_seq: ordered.first().ok_or(StoreError::StoreCorrupt)?.seq,
        last_seq: ordered.last().ok_or(StoreError::StoreCorrupt)?.seq,
        event_ids: ordered.into_iter().map(|row| row.event_id).collect(),
        replayed: true,
    }))
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

pub(crate) async fn append_rows(table: &Table, rows: &[JournalRow]) -> Result<(), StoreError> {
    if rows.is_empty() {
        return Err(StoreError::InvalidInput);
    }
    table
        .add(journal_batch(rows)?)
        .execute()
        .await
        .map(|_| ())
        .map_err(|_| StoreError::LanceDb)
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

fn journal_batch(rows: &[JournalRow]) -> Result<RecordBatch, StoreError> {
    let columns: Vec<ArrayRef> = vec![
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.event_id.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.command_id.to_string()),
        )),
        Arc::new(
            FixedSizeBinaryArray::try_from_iter(rows.iter().map(|row| row.command_hash.as_slice()))
                .map_err(|_| StoreError::Arrow)?,
        ),
        Arc::new(UInt16Array::from_iter_values(
            rows.iter().map(|row| row.ordinal),
        )),
        Arc::new(UInt16Array::from_iter_values(
            rows.iter().map(|row| row.command_event_count),
        )),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|row| row.seq),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.event_type.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.record_class.as_str()),
        )),
        string_options(
            rows.iter()
                .map(|row| row.object_family.map(ObjectFamily::as_str)),
        ),
        string_options(rows.iter().map(|row| row.object_id.as_deref())),
        string_options(rows.iter().map(|row| row.revision_id.as_deref())),
        string_options(rows.iter().map(|row| row.scope.project_id.as_deref())),
        string_options(rows.iter().map(|row| row.scope.repository_id.as_deref())),
        string_options(rows.iter().map(|row| row.scope.worktree_id.as_deref())),
        string_options(rows.iter().map(|row| row.scope.task_id.as_deref())),
        string_options(rows.iter().map(|row| row.scope.workstream_id.as_deref())),
        string_options(rows.iter().map(|row| row.scope.session_id.as_deref())),
        string_options(
            rows.iter()
                .map(|row| row.scope.execution_lane_id.as_deref()),
        ),
        Arc::new(
            TimestampMicrosecondArray::from_iter_values(rows.iter().map(|row| row.occurred_at_us))
                .with_timezone("UTC"),
        ),
        Arc::new(
            TimestampMicrosecondArray::from_iter_values(rows.iter().map(|row| row.ingested_at_us))
                .with_timezone("UTC"),
        ),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.source_kind.as_str()),
        )),
        Arc::new(LargeStringArray::from_iter(
            rows.iter().map(|row| row.source_ref_json.as_deref()),
        )),
        Arc::new(UInt16Array::from_iter_values(
            rows.iter().map(|row| row.payload_schema),
        )),
        Arc::new(LargeStringArray::from_iter_values(
            rows.iter().map(|row| row.payload_json.as_str()),
        )),
        Arc::new(
            FixedSizeBinaryArray::try_from_iter(rows.iter().map(|row| row.content_hash.as_slice()))
                .map_err(|_| StoreError::Arrow)?,
        ),
        string_options(rows.iter().map(|row| row.causation_id.as_deref())),
        string_options(rows.iter().map(|row| row.correlation_id.as_deref())),
        Arc::new(
            FixedSizeBinaryArray::try_from_iter(
                rows.iter().map(|row| row.effective_config_hash.as_slice()),
            )
            .map_err(|_| StoreError::Arrow)?,
        ),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.algorithm_revision.as_str()),
        )),
    ];
    RecordBatch::try_new(journal_schema(), columns).map_err(|_| StoreError::Arrow)
}

fn rows_from_batch(batch: &RecordBatch) -> Result<Vec<JournalRow>, StoreError> {
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

fn string_options<'a>(values: impl Iterator<Item = Option<&'a str>>) -> ArrayRef {
    Arc::new(StringArray::from_iter(values))
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
        let mut partial = valid_rows();
        partial[0].command_event_count = 2;
        assert_eq!(
            validate_complete_command(&partial),
            Err(StoreError::StoreCorrupt)
        );

        let mut duplicate = valid_rows();
        duplicate.push(duplicate[0].clone());
        duplicate[0].command_event_count = 2;
        duplicate[1].command_event_count = 2;
        assert_eq!(
            validate_complete_command(&duplicate),
            Err(StoreError::StoreCorrupt)
        );

        for mutate in [
            |row: &mut JournalRow| row.event_id.push('0'),
            |row: &mut JournalRow| row.command_hash[0] ^= 1,
            |row: &mut JournalRow| row.content_hash[0] ^= 1,
        ] {
            let mut rows = valid_rows();
            mutate(&mut rows[0]);
            assert_eq!(
                validate_complete_command(&rows),
                Err(StoreError::StoreCorrupt)
            );
        }
    }

    #[test]
    fn schema_is_exact_and_partial_schema_is_rejected() {
        let rows = valid_rows();
        let batch = journal_batch(&rows).unwrap();
        assert_eq!(rows_from_batch(&batch).unwrap(), rows);
        let partial = RecordBatch::new_empty(Arc::new(Schema::new(
            journal_schema().fields()[..28].to_vec(),
        )));
        assert_eq!(rows_from_batch(&partial), Err(StoreError::StoreCorrupt));
    }

    #[tokio::test]
    async fn frontier_query_reads_only_the_latest_sequence_and_handles_empty() {
        let temp = tempfile::tempdir().unwrap();
        let connection = lancedb::connect(temp.path().to_str().unwrap())
            .execute()
            .await
            .unwrap();
        let table = connection
            .create_empty_table(JOURNAL_TABLE, journal_schema())
            .execute()
            .await
            .unwrap();
        assert_eq!(read_journal_frontier(&table).await, Ok(0));
        let mut rows = valid_rows();
        rows[0].seq = 37;
        append_rows(&table, &rows).await.unwrap();
        assert_eq!(read_journal_frontier(&table).await, Ok(37));
    }
}
