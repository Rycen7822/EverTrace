use std::sync::Arc;

use arrow_array::{ArrayRef, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use evertrace_domain::canonical::{CanonicalValue, sha256};

use crate::connection::StoreProfileError;

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

pub fn probe_batch(rows: &[ProbeRow<'_>]) -> Result<RecordBatch, StoreProfileError> {
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
    RecordBatch::try_new(schema, columns).map_err(|_| StoreProfileError::Arrow)
}

pub fn schema_fingerprint(schema: &Schema) -> Result<String, StoreProfileError> {
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
    .map_err(|_| StoreProfileError::Fingerprint)?;
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}
