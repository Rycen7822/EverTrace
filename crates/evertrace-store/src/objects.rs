use std::sync::Arc;

use arrow_array::{Array, ArrayRef, LargeStringArray, RecordBatch, StringArray, UInt64Array};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use lancedb::Table;

use crate::{
    collect_batches,
    command::{ObjectFamily, StoreError},
};

pub const OBJECTS_TABLE: &str = "evertrace_objects";
pub const OBJECTS_CHECKPOINT_ID: &str = "checkpoint:evertrace_objects";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectRowKind {
    Data,
    Checkpoint,
}

impl ObjectRowKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Checkpoint => "checkpoint",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "data" => Ok(Self::Data),
            "checkpoint" => Ok(Self::Checkpoint),
            _ => Err(StoreError::StoreCorrupt),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectRowClass {
    Object,
    Runtime,
    Projection,
}

impl ObjectRowClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::Runtime => "runtime",
            Self::Projection => "projection",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "object" => Ok(Self::Object),
            "runtime" => Ok(Self::Runtime),
            "projection" => Ok(Self::Projection),
            _ => Err(StoreError::StoreCorrupt),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectRow {
    pub row_id: String,
    pub row_kind: ObjectRowKind,
    pub row_class: Option<ObjectRowClass>,
    pub object_family: Option<ObjectFamily>,
    pub object_kind: Option<String>,
    pub object_id: Option<String>,
    pub current_revision_id: Option<String>,
    pub lifecycle: Option<String>,
    pub epistemic: Option<String>,
    pub authority: Option<String>,
    pub publication_state: Option<String>,
    pub support_state: Option<String>,
    pub project_id: Option<String>,
    pub repository_id: Option<String>,
    pub worktree_id: Option<String>,
    pub task_id: Option<String>,
    pub workstream_id: Option<String>,
    pub session_id: Option<String>,
    pub payload_json: Option<String>,
    pub source_event_seq: u64,
    pub projection_generation: u64,
}

impl ObjectRow {
    pub fn checkpoint(frontier: u64, generation: u64) -> Self {
        Self {
            row_id: OBJECTS_CHECKPOINT_ID.into(),
            row_kind: ObjectRowKind::Checkpoint,
            row_class: None,
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
            payload_json: None,
            source_event_seq: frontier,
            projection_generation: generation,
        }
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        if self.row_id.is_empty() || self.projection_generation == 0 {
            return Err(StoreError::StoreCorrupt);
        }
        match self.row_kind {
            ObjectRowKind::Checkpoint => {
                if self.row_id != OBJECTS_CHECKPOINT_ID
                    || self.row_class.is_some()
                    || self.object_family.is_some()
                    || self.object_kind.is_some()
                    || self.object_id.is_some()
                    || self.current_revision_id.is_some()
                    || self.lifecycle.is_some()
                    || self.epistemic.is_some()
                    || self.authority.is_some()
                    || self.publication_state.is_some()
                    || self.support_state.is_some()
                    || self.project_id.is_some()
                    || self.repository_id.is_some()
                    || self.worktree_id.is_some()
                    || self.task_id.is_some()
                    || self.workstream_id.is_some()
                    || self.session_id.is_some()
                    || self.payload_json.is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ObjectRowKind::Data => {
                let class = self.row_class.ok_or(StoreError::StoreCorrupt)?;
                if self.payload_json.is_none() {
                    return Err(StoreError::StoreCorrupt);
                }
                match class {
                    ObjectRowClass::Object => {
                        if self.object_family.is_none() || self.object_id.is_none() {
                            return Err(StoreError::StoreCorrupt);
                        }
                    }
                    ObjectRowClass::Runtime | ObjectRowClass::Projection => {
                        if self.object_family.is_some() || self.object_id.is_some() {
                            return Err(StoreError::StoreCorrupt);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn objects_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("row_id", DataType::Utf8, false),
        Field::new("row_kind", DataType::Utf8, false),
        Field::new("row_class", DataType::Utf8, true),
        Field::new("object_family", DataType::Utf8, true),
        Field::new("object_kind", DataType::Utf8, true),
        Field::new("object_id", DataType::Utf8, true),
        Field::new("current_revision_id", DataType::Utf8, true),
        Field::new("lifecycle", DataType::Utf8, true),
        Field::new("epistemic", DataType::Utf8, true),
        Field::new("authority", DataType::Utf8, true),
        Field::new("publication_state", DataType::Utf8, true),
        Field::new("support_state", DataType::Utf8, true),
        Field::new("project_id", DataType::Utf8, true),
        Field::new("repository_id", DataType::Utf8, true),
        Field::new("worktree_id", DataType::Utf8, true),
        Field::new("task_id", DataType::Utf8, true),
        Field::new("workstream_id", DataType::Utf8, true),
        Field::new("session_id", DataType::Utf8, true),
        Field::new("payload_json", DataType::LargeUtf8, true),
        Field::new("source_event_seq", DataType::UInt64, false),
        Field::new("projection_generation", DataType::UInt64, false),
    ]))
}

pub(crate) async fn validate_objects_table(table: &Table) -> Result<Vec<ObjectRow>, StoreError> {
    let actual = table.schema().await.map_err(|_| StoreError::LanceDb)?;
    if actual.as_ref() != objects_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    let rows = read_object_rows(table).await?;
    let mut checkpoint_count = 0;
    for row in &rows {
        row.validate()?;
        if row.row_kind == ObjectRowKind::Checkpoint {
            checkpoint_count += 1;
        }
    }
    if checkpoint_count != 1 {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(rows)
}

pub async fn read_object_rows(table: &Table) -> Result<Vec<ObjectRow>, StoreError> {
    let batches = collect_batches(&table.query())
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let mut rows = Vec::new();
    for batch in &batches {
        rows.extend(rows_from_batch(batch)?);
    }
    rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    Ok(rows)
}

pub(crate) fn objects_batch(rows: &[ObjectRow]) -> Result<RecordBatch, StoreError> {
    for row in rows {
        row.validate()?;
    }
    let columns: Vec<ArrayRef> = vec![
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.row_id.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.row_kind.as_str()),
        )),
        strings(
            rows.iter()
                .map(|row| row.row_class.map(ObjectRowClass::as_str)),
        ),
        strings(
            rows.iter()
                .map(|row| row.object_family.map(ObjectFamily::as_str)),
        ),
        strings(rows.iter().map(|row| row.object_kind.as_deref())),
        strings(rows.iter().map(|row| row.object_id.as_deref())),
        strings(rows.iter().map(|row| row.current_revision_id.as_deref())),
        strings(rows.iter().map(|row| row.lifecycle.as_deref())),
        strings(rows.iter().map(|row| row.epistemic.as_deref())),
        strings(rows.iter().map(|row| row.authority.as_deref())),
        strings(rows.iter().map(|row| row.publication_state.as_deref())),
        strings(rows.iter().map(|row| row.support_state.as_deref())),
        strings(rows.iter().map(|row| row.project_id.as_deref())),
        strings(rows.iter().map(|row| row.repository_id.as_deref())),
        strings(rows.iter().map(|row| row.worktree_id.as_deref())),
        strings(rows.iter().map(|row| row.task_id.as_deref())),
        strings(rows.iter().map(|row| row.workstream_id.as_deref())),
        strings(rows.iter().map(|row| row.session_id.as_deref())),
        Arc::new(LargeStringArray::from_iter(
            rows.iter().map(|row| row.payload_json.as_deref()),
        )),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|row| row.source_event_seq),
        )),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|row| row.projection_generation),
        )),
    ];
    RecordBatch::try_new(objects_schema(), columns).map_err(|_| StoreError::Arrow)
}

fn rows_from_batch(batch: &RecordBatch) -> Result<Vec<ObjectRow>, StoreError> {
    if batch.schema().as_ref() != objects_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    let row_ids = array::<StringArray>(batch, 0)?;
    let row_kinds = array::<StringArray>(batch, 1)?;
    let row_classes = array::<StringArray>(batch, 2)?;
    let object_families = array::<StringArray>(batch, 3)?;
    let object_kinds = array::<StringArray>(batch, 4)?;
    let object_ids = array::<StringArray>(batch, 5)?;
    let revisions = array::<StringArray>(batch, 6)?;
    let lifecycles = array::<StringArray>(batch, 7)?;
    let epistemics = array::<StringArray>(batch, 8)?;
    let authorities = array::<StringArray>(batch, 9)?;
    let publications = array::<StringArray>(batch, 10)?;
    let supports = array::<StringArray>(batch, 11)?;
    let projects = array::<StringArray>(batch, 12)?;
    let repositories = array::<StringArray>(batch, 13)?;
    let worktrees = array::<StringArray>(batch, 14)?;
    let tasks = array::<StringArray>(batch, 15)?;
    let workstreams = array::<StringArray>(batch, 16)?;
    let sessions = array::<StringArray>(batch, 17)?;
    let payloads = array::<LargeStringArray>(batch, 18)?;
    let source_seqs = array::<UInt64Array>(batch, 19)?;
    let generations = array::<UInt64Array>(batch, 20)?;
    let mut rows = Vec::with_capacity(batch.num_rows());
    for index in 0..batch.num_rows() {
        let row = ObjectRow {
            row_id: row_ids.value(index).into(),
            row_kind: ObjectRowKind::parse(row_kinds.value(index))?,
            row_class: optional(row_classes, index)
                .map(ObjectRowClass::parse)
                .transpose()?,
            object_family: optional(object_families, index)
                .map(ObjectFamily::parse)
                .transpose()?,
            object_kind: owned(object_kinds, index),
            object_id: owned(object_ids, index),
            current_revision_id: owned(revisions, index),
            lifecycle: owned(lifecycles, index),
            epistemic: owned(epistemics, index),
            authority: owned(authorities, index),
            publication_state: owned(publications, index),
            support_state: owned(supports, index),
            project_id: owned(projects, index),
            repository_id: owned(repositories, index),
            worktree_id: owned(worktrees, index),
            task_id: owned(tasks, index),
            workstream_id: owned(workstreams, index),
            session_id: owned(sessions, index),
            payload_json: (!payloads.is_null(index)).then(|| payloads.value(index).to_owned()),
            source_event_seq: source_seqs.value(index),
            projection_generation: generations.value(index),
        };
        row.validate()?;
        rows.push(row);
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

fn strings<'a>(values: impl Iterator<Item = Option<&'a str>>) -> ArrayRef {
    Arc::new(StringArray::from_iter(values))
}

fn optional(array: &StringArray, index: usize) -> Option<&str> {
    (!array.is_null(index)).then(|| array.value(index))
}

fn owned(array: &StringArray, index: usize) -> Option<String> {
    optional(array, index).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_and_schema_are_closed() {
        let row = ObjectRow::checkpoint(0, 1);
        assert_eq!(row.validate(), Ok(()));
        let batch = objects_batch(std::slice::from_ref(&row)).unwrap();
        assert_eq!(rows_from_batch(&batch).unwrap(), vec![row]);
        let mut columns = batch.columns().to_vec();
        columns[3] = Arc::new(StringArray::from(vec![Some("unknown_family")]));
        let invalid_family = RecordBatch::try_new(objects_schema(), columns).unwrap();
        assert_eq!(
            rows_from_batch(&invalid_family),
            Err(StoreError::StoreCorrupt)
        );
        let partial = RecordBatch::new_empty(Arc::new(Schema::new(
            objects_schema().fields()[..20].to_vec(),
        )));
        assert_eq!(rows_from_batch(&partial), Err(StoreError::StoreCorrupt));
    }
}
