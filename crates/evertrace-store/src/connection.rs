use std::{future::poll_fn, path::Path};

use arrow_array::RecordBatch;
use lancedb::{Connection, Table, query::ExecutableQuery};
use thiserror::Error;

/// The state root owns locks, CAS and spool; only this child is a normal native store.
pub fn native_root(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("store")
}

pub(crate) fn prepare_native_root(data_dir: &Path) -> Result<(), crate::StoreError> {
    use std::os::unix::fs::DirBuilderExt;
    let native = native_root(data_dir);
    match std::fs::symlink_metadata(&native) {
        Ok(_) => {
            evertrace_capture::ConfinedRoot::open_owned_private(&native)
                .map_err(|_| crate::StoreError::StoreCorrupt)?;
            let journal =
                std::fs::symlink_metadata(native.join(format!("{}.lance", crate::JOURNAL_TABLE)))
                    .map_err(|_| crate::StoreError::StoreCorrupt)?;
            if !journal.is_dir() || journal.file_type().is_symlink() {
                return Err(crate::StoreError::StoreCorrupt);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            for table in [
                crate::JOURNAL_TABLE,
                crate::OBJECTS_TABLE,
                crate::RELATIONS_TABLE,
                crate::SEARCH_TABLE,
            ] {
                match std::fs::symlink_metadata(data_dir.join(format!("{table}.lance"))) {
                    Ok(_) => return Err(crate::StoreError::UpgradeRequired),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(crate::StoreError::Io),
                }
            }
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&native)
                .map_err(|_| crate::StoreError::Io)?;
            std::fs::File::open(data_dir)
                .and_then(|file| file.sync_all())
                .map_err(|_| crate::StoreError::Io)?;
        }
        Err(_) => return Err(crate::StoreError::Io),
    }
    Ok(())
}

pub(crate) async fn connect_native(data_dir: &Path) -> Result<Connection, crate::StoreError> {
    let native = native_root(data_dir);
    evertrace_capture::ConfinedRoot::open_owned_private(&native)
        .map_err(|_| crate::StoreError::StoreCorrupt)?;
    lancedb::connect(native.to_str().ok_or(crate::StoreError::InvalidPath)?)
        .execute()
        .await
        .map_err(|_| crate::StoreError::LanceDb)
}

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
