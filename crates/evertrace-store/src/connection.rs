use std::{future::poll_fn, path::Path};

use arrow_array::RecordBatch;
use lancedb::{Connection, Table, query::ExecutableQuery};
use thiserror::Error;

#[derive(Clone)]
pub struct CompatibilityStore {
    connection: Connection,
}

impl CompatibilityStore {
    pub async fn connect_local(path: &Path) -> Result<Self, StoreProfileError> {
        if !path.is_absolute() {
            return Err(StoreProfileError::InvalidPath);
        }
        let uri = path.to_str().ok_or(StoreProfileError::InvalidPath)?;
        let connection = lancedb::connect(uri)
            .execute()
            .await
            .map_err(|_| StoreProfileError::LanceDb)?;
        Ok(Self { connection })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub async fn create_probe_table(
        &self,
        name: &str,
        initial: RecordBatch,
    ) -> Result<Table, StoreProfileError> {
        validate_probe_name(name)?;
        self.connection
            .create_table(name, initial)
            .execute()
            .await
            .map_err(|_| StoreProfileError::LanceDb)
    }

    pub async fn open_probe_table(&self, name: &str) -> Result<Table, StoreProfileError> {
        validate_probe_name(name)?;
        self.connection
            .open_table(name)
            .execute()
            .await
            .map_err(|_| StoreProfileError::LanceDb)
    }
}

pub async fn collect_batches(
    query: &impl ExecutableQuery,
) -> Result<Vec<RecordBatch>, StoreProfileError> {
    let mut stream = query
        .execute()
        .await
        .map_err(|_| StoreProfileError::LanceDb)?;
    let mut batches = Vec::new();
    while let Some(batch) = poll_fn(|context| stream.as_mut().poll_next(context)).await {
        batches.push(batch.map_err(|_| StoreProfileError::LanceDb)?);
    }
    Ok(batches)
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StoreProfileError {
    #[error("store profile path is invalid")]
    InvalidPath,
    #[error("store profile table name is invalid")]
    InvalidTableName,
    #[error("store profile Arrow operation failed")]
    Arrow,
    #[error("store profile schema fingerprint failed")]
    Fingerprint,
    #[error("store profile LanceDB operation failed")]
    LanceDb,
}

fn validate_probe_name(value: &str) -> Result<(), StoreProfileError> {
    if !value.starts_with("probe_")
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(StoreProfileError::InvalidTableName);
    }
    Ok(())
}
