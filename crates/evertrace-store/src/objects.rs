use std::sync::Arc;

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
}
