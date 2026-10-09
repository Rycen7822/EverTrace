use std::{fmt, ops::Deref, sync::Arc};

use arrow_schema::{DataType, Field, Schema, SchemaRef};

use crate::command::{ObjectFamily, StoreError};

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

    pub(crate) fn parse(value: &str) -> Result<Self, StoreError> {
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

    pub(crate) fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "object" => Ok(Self::Object),
            "runtime" => Ok(Self::Runtime),
            "projection" => Ok(Self::Projection),
            _ => Err(StoreError::StoreCorrupt),
        }
    }
}

pub(crate) const OBJECT_ROW_PAYLOAD_BLOCK_BYTES: usize = 64 * 1024;
const OBJECT_ROW_PAYLOAD_BLOCK_ROWS: usize = 1024;

/// Immutable JSON text carried by an object row.
///
/// Rows decoded or projected together may share a bounded backing string. The
/// range is private so every instance can only expose a complete UTF-8 slice.
#[derive(Clone)]
pub struct RowPayload {
    backing: Arc<String>,
    start: usize,
    end: usize,
}

impl RowPayload {
    fn from_shared(backing: Arc<String>, start: usize, end: usize) -> Self {
        debug_assert!(start <= end && end <= backing.len());
        debug_assert!(backing.is_char_boundary(start) && backing.is_char_boundary(end));
        Self {
            backing,
            start,
            end,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.backing[self.start..self.end]
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn to_owned_string(&self) -> String {
        self.as_str().to_owned()
    }
}

impl From<String> for RowPayload {
    fn from(text: String) -> Self {
        let end = text.len();
        Self::from_shared(Arc::new(text), 0, end)
    }
}

impl From<&str> for RowPayload {
    fn from(text: &str) -> Self {
        Self::from(text.to_owned())
    }
}

impl Deref for RowPayload {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for RowPayload {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for RowPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RowPayload")
            .field(&self.as_str())
            .finish()
    }
}

impl PartialEq for RowPayload {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for RowPayload {}

#[derive(Default)]
pub(crate) struct RowPayloadBlockBuilder {
    open: String,
    pending: Vec<PendingRowPayload>,
}

struct PendingRowPayload {
    row_index: usize,
    start: usize,
    end: usize,
}

impl RowPayloadBlockBuilder {
    pub(crate) fn push_row(
        &mut self,
        rows: &mut Vec<ObjectRow>,
        mut row: ObjectRow,
    ) -> Result<(), StoreError> {
        row.validate()?;
        let Some(payload) = row.payload_json.take() else {
            rows.push(row);
            return Ok(());
        };
        self.push_payload(rows, row, payload)
    }

    pub(crate) fn push_text(
        &mut self,
        rows: &mut Vec<ObjectRow>,
        row: ObjectRow,
        text: &str,
    ) -> Result<(), StoreError> {
        self.push_text_inner(rows, row, text)
    }

    pub(crate) fn finish(mut self, rows: &mut [ObjectRow]) -> Result<(), StoreError> {
        self.seal(rows)
    }

    fn push_payload(
        &mut self,
        rows: &mut Vec<ObjectRow>,
        row: ObjectRow,
        payload: RowPayload,
    ) -> Result<(), StoreError> {
        if payload.len() > OBJECT_ROW_PAYLOAD_BLOCK_BYTES {
            self.seal(rows)?;
            rows.push(ObjectRow {
                payload_json: Some(payload),
                ..row
            });
            return Ok(());
        }
        self.push_text_inner(rows, row, payload.as_str())
    }

    fn push_text_inner(
        &mut self,
        rows: &mut Vec<ObjectRow>,
        row: ObjectRow,
        text: &str,
    ) -> Result<(), StoreError> {
        debug_assert!(row.payload_json.is_none());
        if text.len() > OBJECT_ROW_PAYLOAD_BLOCK_BYTES {
            self.seal(rows)?;
            rows.push(ObjectRow {
                payload_json: Some(RowPayload::from(text)),
                ..row
            });
            return Ok(());
        }
        if self.pending.len() >= OBJECT_ROW_PAYLOAD_BLOCK_ROWS
            || self.open.len().saturating_add(text.len()) > OBJECT_ROW_PAYLOAD_BLOCK_BYTES
        {
            self.seal(rows)?;
        }
        let start = self.open.len();
        self.open.push_str(text);
        let end = self.open.len();
        let row_index = rows.len();
        rows.push(row);
        self.pending.push(PendingRowPayload {
            row_index,
            start,
            end,
        });
        Ok(())
    }

    fn seal(&mut self, rows: &mut [ObjectRow]) -> Result<(), StoreError> {
        if self.pending.is_empty() {
            debug_assert!(self.open.is_empty());
            return Ok(());
        }
        self.open.shrink_to_fit();
        let backing = Arc::new(std::mem::take(&mut self.open));
        for pending in self.pending.drain(..) {
            let row = rows
                .get_mut(pending.row_index)
                .ok_or(StoreError::StoreCorrupt)?;
            row.payload_json = Some(RowPayload::from_shared(
                Arc::clone(&backing),
                pending.start,
                pending.end,
            ));
        }
        Ok(())
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
    pub payload_json: Option<RowPayload>,
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

/// Closed logical field set of the objects family. The physical shape is the
/// single SQLite table; this schema is the logical contract and the future
/// converter's read boundary.
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

pub(crate) fn checkpoint_from_rows(rows: &[ObjectRow]) -> Result<u64, StoreError> {
    let mut matches = rows
        .iter()
        .filter(|row| row.row_id == OBJECTS_CHECKPOINT_ID);
    let Some(checkpoint) = matches.next() else {
        return Err(StoreError::StoreCorrupt);
    };
    if matches.next().is_some() || checkpoint.row_kind != ObjectRowKind::Checkpoint {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(checkpoint.source_event_seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_row(row_id: &str, payload_json: Option<RowPayload>) -> ObjectRow {
        ObjectRow {
            row_id: row_id.into(),
            row_kind: ObjectRowKind::Data,
            row_class: Some(ObjectRowClass::Object),
            object_family: Some(ObjectFamily::Evidence),
            object_kind: Some("test".into()),
            object_id: Some(row_id.into()),
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
            payload_json,
            source_event_seq: 1,
            projection_generation: 1,
        }
    }

    #[test]
    fn checkpoint_identity_is_closed() {
        let row = ObjectRow::checkpoint(0, 1);
        assert_eq!(row.validate(), Ok(()));
        let mut occupied = row.clone();
        occupied.row_kind = ObjectRowKind::Data;
        occupied.row_class = Some(ObjectRowClass::Runtime);
        occupied.payload_json = Some("{}".into());
        assert_eq!(occupied.validate(), Ok(()));
        assert_eq!(
            checkpoint_from_rows(&[row, occupied]),
            Err(StoreError::StoreCorrupt)
        );
        assert_eq!(checkpoint_from_rows(&[]), Err(StoreError::StoreCorrupt));
    }

    #[test]
    fn row_payload_blocks_preserve_bytes_empty_none_and_full_row_equality() {
        let expected = r#"{"escaped":"line\n\"雪"}"#;
        let mut rows = Vec::new();
        let mut blocks = RowPayloadBlockBuilder::default();
        blocks
            .push_text(&mut rows, data_row("escaped", None), expected)
            .unwrap();
        blocks
            .push_row(&mut rows, ObjectRow::checkpoint(9, 1))
            .unwrap();
        blocks
            .push_text(&mut rows, data_row("empty", None), "")
            .unwrap();
        blocks.finish(&mut rows).unwrap();

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].payload_json.as_deref(), Some(expected));
        assert_eq!(
            rows[0].payload_json.as_ref().unwrap().as_bytes(),
            expected.as_bytes()
        );
        assert!(rows[1].payload_json.is_none());
        assert_eq!(rows[1].validate(), Ok(()));
        assert_eq!(rows[2].payload_json.as_deref(), Some(""));
        assert!(rows[2].payload_json.as_ref().unwrap().is_empty());
        assert!(rows.iter().all(|row| row.validate().is_ok()));

        let independent_left = RowPayload::from(expected);
        let independent_right = RowPayload::from(expected.to_owned());
        assert_eq!(independent_left, independent_right);
        assert!(!Arc::ptr_eq(
            &independent_left.backing,
            &independent_right.backing
        ));

        let mut metadata_changed = rows[0].clone();
        metadata_changed.repository_id = Some("different-repository".into());
        assert_ne!(rows[0], metadata_changed);
        assert_eq!(
            data_row("missing", None).validate(),
            Err(StoreError::StoreCorrupt)
        );
    }

    #[test]
    fn one_retained_row_keeps_only_its_bounded_backing_alive() {
        let full_block = "x".repeat(OBJECT_ROW_PAYLOAD_BLOCK_BYTES);
        let oversized = "o".repeat(OBJECT_ROW_PAYLOAD_BLOCK_BYTES + 1);
        let mut rows = Vec::new();
        let mut blocks = RowPayloadBlockBuilder::default();
        blocks
            .push_text(&mut rows, data_row("selected", None), "selected-row")
            .unwrap();
        blocks
            .push_text(&mut rows, data_row("neighbor", None), "neighbor-secret")
            .unwrap();
        blocks
            .push_text(&mut rows, data_row("full-block", None), &full_block)
            .unwrap();
        blocks
            .push_text(&mut rows, data_row("tail", None), "tail")
            .unwrap();
        blocks
            .push_text(&mut rows, data_row("oversized", None), &oversized)
            .unwrap();
        blocks.finish(&mut rows).unwrap();

        let selected_payload = rows[0].payload_json.as_ref().unwrap();
        let neighbor_payload = rows[1].payload_json.as_ref().unwrap();
        let selected_backing = Arc::downgrade(&selected_payload.backing);
        let full_block_backing = Arc::downgrade(&rows[2].payload_json.as_ref().unwrap().backing);
        assert!(Arc::ptr_eq(
            &selected_payload.backing,
            &neighbor_payload.backing
        ));
        assert!(!Arc::ptr_eq(
            &selected_payload.backing,
            &rows[2].payload_json.as_ref().unwrap().backing
        ));
        assert!(!Arc::ptr_eq(
            &rows[2].payload_json.as_ref().unwrap().backing,
            &rows[3].payload_json.as_ref().unwrap().backing
        ));
        assert_eq!(
            rows[2].payload_json.as_ref().unwrap().len(),
            OBJECT_ROW_PAYLOAD_BLOCK_BYTES
        );
        assert_eq!(
            rows[4].payload_json.as_ref().unwrap().len(),
            OBJECT_ROW_PAYLOAD_BLOCK_BYTES + 1
        );
        let debug = format!("{:?}", selected_payload);
        assert!(debug.contains("selected-row"));
        assert!(!debug.contains("neighbor-secret"));

        let retained = rows[0].clone();
        drop(rows);
        assert_eq!(retained.payload_json.as_deref(), Some("selected-row"));
        assert!(selected_backing.upgrade().is_some());
        assert!(full_block_backing.upgrade().is_none());
        drop(retained);
        assert!(selected_backing.upgrade().is_none());
    }
}
