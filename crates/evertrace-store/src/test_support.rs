//! Existing qualification fixtures and fault injection, excluded from normal builds.
use std::{path::Path, sync::Arc};

use arrow_array::{ArrayRef, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use evertrace_domain::canonical::{CanonicalValue, sha256};
use lancedb::{Connection, Table};

/// Remove the persisted objects family so a reopen must rebuild it from the
/// authoritative journal.
pub fn clear_objects(data_dir: &Path) -> Result<(), crate::StoreError> {
    crate::sqlite_state::SqliteState::open(data_dir)?
        .handle()
        .lock()
        .map_err(|_| crate::StoreError::StoreCorrupt)?
        .clear_object_rows_for_test()
}

/// Advance the persisted objects checkpoint without any projection, so a
/// consumer must detect the logical gap.
pub fn advance_object_checkpoint(data_dir: &Path) -> Result<(), crate::StoreError> {
    crate::sqlite_state::SqliteState::open(data_dir)?
        .handle()
        .lock()
        .map_err(|_| crate::StoreError::StoreCorrupt)?
        .advance_object_checkpoint_for_test()
}

/// Materialize one valid retired layout (`L0001` or `L0002`, canonical or
/// flat) from already-persisted logical journal rows so cross-crate package
/// and maintenance tests can exercise the named offline converter. `root`
/// is a caller-owned empty test container: only the requested tables are
/// created there; no existing store is deleted or converted.
pub async fn write_conversion_fixture(
    root: &Path,
    canonical: bool,
    profile: &str,
    rows: &[crate::JournalRow],
) -> Result<(), crate::StoreError> {
    crate::conversion_input::test_format::write_conversion_fixture(root, canonical, profile, rows)
        .await
}

pub const PROBE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeRow<'a> {
    pub id: i64,
    pub command_id: &'a str,
    pub text: &'a str,
    pub generation: i64,
}

pub fn probe_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("command_id", DataType::Utf8, false),
        Field::new("text", DataType::Utf8, false),
        Field::new("generation", DataType::Int64, false),
    ]))
}

pub fn probe_batch(rows: &[ProbeRow<'_>]) -> Result<RecordBatch, crate::StoreError> {
    let schema = probe_schema();
    let columns: Vec<ArrayRef> = vec![
        Arc::new(Int64Array::from_iter_values(rows.iter().map(|row| row.id))),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.command_id),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|row| row.text),
        )),
        Arc::new(Int64Array::from_iter_values(
            rows.iter().map(|row| row.generation),
        )),
    ];
    RecordBatch::try_new(schema, columns).map_err(|_| crate::StoreError::StoreCorrupt)
}

pub fn schema_fingerprint(schema: &Schema) -> Result<String, crate::StoreError> {
    let fields = schema
        .fields()
        .iter()
        .map(|field| {
            CanonicalValue::Map(vec![
                ("name".into(), CanonicalValue::String(field.name().clone())),
                (
                    "data_type".into(),
                    CanonicalValue::String(format!("{:?}", field.data_type())),
                ),
                ("nullable".into(), CanonicalValue::Bool(field.is_nullable())),
            ])
        })
        .collect();
    let digest = sha256(
        "evertrace.lancedb.probe_schema",
        PROBE_SCHEMA_VERSION,
        &CanonicalValue::Sequence(fields),
    )
    .map_err(|_| crate::StoreError::StoreCorrupt)?;
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[derive(Clone)]
pub struct TestIndexStore {
    connection: Connection,
}

impl TestIndexStore {
    pub async fn connect_local(path: &Path) -> Result<Self, crate::StoreError> {
        if !path.is_absolute() {
            return Err(crate::StoreError::InvalidPath);
        }
        let uri = path.to_str().ok_or(crate::StoreError::InvalidPath)?;
        let connection = lancedb::connect(uri)
            .session(crate::connection::native_session())
            .execute()
            .await
            .map_err(|_| crate::StoreError::LanceDb)?;
        Ok(Self { connection })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub async fn create_probe_table(
        &self,
        name: &str,
        initial: RecordBatch,
    ) -> Result<Table, crate::StoreError> {
        validate_probe_name(name)?;
        self.connection
            .create_table(name, initial)
            .execute()
            .await
            .map_err(|_| crate::StoreError::LanceDb)
    }

    pub async fn open_probe_table(&self, name: &str) -> Result<Table, crate::StoreError> {
        validate_probe_name(name)?;
        self.connection
            .open_table(name)
            .execute()
            .await
            .map_err(|_| crate::StoreError::LanceDb)
    }
}

fn validate_probe_name(value: &str) -> Result<(), crate::StoreError> {
    if !value.starts_with("probe_")
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(crate::StoreError::InvalidInput);
    }
    Ok(())
}
