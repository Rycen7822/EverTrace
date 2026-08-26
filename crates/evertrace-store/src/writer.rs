use std::{
    ffi::OsString,
    fs::{self, DirBuilder, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use fs2::FileExt;
use lancedb::{Connection, Table};

use crate::{
    command::{CommitOutcome, JournalCommand, StoreError, prepare_command},
    journal::{
        JOURNAL_TABLE, append_rows, read_all_journal_rows, read_command_rows, replay_outcome,
        rows_for_append, validate_journal_table,
    },
    migrations::{L0001, MigrationOutcome},
    objects::{OBJECTS_TABLE, read_object_rows, validate_objects_table},
    projections::{ProjectionSnapshot, ProjectionWorker},
};

#[derive(Debug)]
pub struct SiblingWriterLock {
    data_dir: PathBuf,
    lock_path: PathBuf,
    file: File,
}

impl SiblingWriterLock {
    pub fn acquire(data_dir: &Path) -> Result<Self, StoreError> {
        validate_lexical_data_dir(data_dir)?;
        let parent = data_dir.parent().ok_or(StoreError::InvalidPath)?;
        validate_parent(parent)?;
        let lock_path = sibling_lock_path(data_dir)?;
        let existed = match fs::symlink_metadata(&lock_path) {
            Ok(metadata) => {
                validate_lock_metadata(&metadata)?;
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(_) => return Err(StoreError::Io),
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|_| StoreError::Io)?;
        validate_lock_identity(&lock_path, &file)?;
        if !existed {
            file.sync_all().map_err(|_| StoreError::Io)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| StoreError::Io)?;
        }
        FileExt::try_lock_exclusive(&file).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                StoreError::WriterAlreadyRunning
            } else {
                StoreError::Io
            }
        })?;
        validate_lock_identity(&lock_path, &file)?;
        ensure_data_root(data_dir, parent)?;
        Ok(Self {
            data_dir: data_dir.to_owned(),
            lock_path,
            file,
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    pub fn inode_identity(&self) -> Result<(u64, u64), StoreError> {
        let metadata = self.file.metadata().map_err(|_| StoreError::Io)?;
        Ok((metadata.dev(), metadata.ino()))
    }
}

pub struct JournalWriter {
    _lock: SiblingWriterLock,
    connection: Connection,
    journal: Table,
    objects: Table,
    next_seq: u64,
    migration_outcome: MigrationOutcome,
}

impl JournalWriter {
    pub async fn open(data_dir: &Path) -> Result<Self, StoreError> {
        let lock = SiblingWriterLock::acquire(data_dir)?;
        let connection = lancedb::connect(data_dir.to_str().ok_or(StoreError::InvalidPath)?)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let migration_outcome = L0001::apply(&connection).await?;
        let journal = connection
            .open_table(JOURNAL_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let objects = connection
            .open_table(OBJECTS_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        validate_journal_table(&journal).await?;
        validate_objects_table(&objects).await?;
        let next_seq = read_all_journal_rows(&journal)
            .await?
            .iter()
            .map(|row| row.seq)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StoreError::StoreCorrupt)?;
        Ok(Self {
            _lock: lock,
            connection,
            journal,
            objects,
            next_seq,
            migration_outcome,
        })
    }

    pub const fn migration_outcome(&self) -> MigrationOutcome {
        self.migration_outcome
    }

    pub fn lock_path(&self) -> &Path {
        self._lock.lock_path()
    }

    pub fn lock_inode_identity(&self) -> Result<(u64, u64), StoreError> {
        self._lock.inode_identity()
    }

    pub async fn commit(
        &mut self,
        command: &JournalCommand,
        ingested_at_us: i64,
    ) -> Result<CommitOutcome, StoreError> {
        if ingested_at_us < 0 {
            return Err(StoreError::InvalidInput);
        }
        let prepared = prepare_command(command)?;
        let existing = read_command_rows(&self.journal, prepared.command_id).await?;
        if let Some(outcome) = replay_outcome(&existing, &prepared)? {
            return Ok(outcome);
        }
        let first_seq = reserve_range(&mut self.next_seq, prepared.event_count)?;
        let rows = rows_for_append(&prepared, first_seq, ingested_at_us)?;
        append_rows(&self.journal, &rows).await?;
        Ok(CommitOutcome {
            command_id: prepared.command_id,
            first_seq,
            last_seq: rows.last().ok_or(StoreError::StoreCorrupt)?.seq,
            event_ids: rows.into_iter().map(|row| row.event_id).collect(),
            replayed: false,
        })
    }

    pub async fn project(&self) -> Result<ProjectionSnapshot, StoreError> {
        ProjectionWorker::new(self.journal.clone(), self.objects.clone())
            .catch_up()
            .await
    }

    pub async fn full_projection(&self) -> Result<ProjectionSnapshot, StoreError> {
        ProjectionWorker::new(self.journal.clone(), self.objects.clone())
            .full_snapshot()
            .await
    }

    pub async fn journal_rows(&self) -> Result<Vec<crate::JournalRow>, StoreError> {
        read_all_journal_rows(&self.journal).await
    }

    pub async fn object_rows(&self) -> Result<Vec<crate::ObjectRow>, StoreError> {
        read_object_rows(&self.objects).await
    }

    pub async fn table_names(&self) -> Result<Vec<String>, StoreError> {
        self.connection
            .table_names()
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)
    }
}

fn reserve_range(next_seq: &mut u64, count: u16) -> Result<u64, StoreError> {
    if count == 0 {
        return Err(StoreError::InvalidInput);
    }
    let first = *next_seq;
    *next_seq = next_seq
        .checked_add(u64::from(count))
        .ok_or(StoreError::StoreCorrupt)?;
    Ok(first)
}

fn validate_lexical_data_dir(path: &Path) -> Result<(), StoreError> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(StoreError::InvalidPath);
    }
    Ok(())
}

fn validate_parent(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StoreError::InvalidType);
    }
    Ok(())
}

fn ensure_data_root(path: &Path, parent: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_data_root_metadata(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder
                .mode(0o700)
                .create(path)
                .map_err(|_| StoreError::Io)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| StoreError::Io)?;
            validate_data_root_metadata(&fs::symlink_metadata(path).map_err(|_| StoreError::Io)?)
        }
        Err(_) => Err(StoreError::Io),
    }
}

fn validate_data_root_metadata(metadata: &fs::Metadata) -> Result<(), StoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StoreError::InvalidType);
    }
    if metadata.uid() != current_uid()? {
        return Err(StoreError::WrongOwner);
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(StoreError::InvalidPermissions);
    }
    Ok(())
}

fn sibling_lock_path(data_dir: &Path) -> Result<PathBuf, StoreError> {
    let parent = data_dir.parent().ok_or(StoreError::InvalidPath)?;
    let mut name = OsString::from(data_dir.file_name().ok_or(StoreError::InvalidPath)?);
    name.push(".writer.lock");
    Ok(parent.join(name))
}

fn validate_lock_metadata(metadata: &fs::Metadata) -> Result<(), StoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StoreError::InvalidType);
    }
    if metadata.uid() != current_uid()? {
        return Err(StoreError::WrongOwner);
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(StoreError::InvalidPermissions);
    }
    Ok(())
}

fn validate_lock_identity(path: &Path, file: &File) -> Result<(), StoreError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| StoreError::Io)?;
    let file_metadata = file.metadata().map_err(|_| StoreError::Io)?;
    validate_lock_metadata(&path_metadata)?;
    validate_lock_metadata(&file_metadata)?;
    if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino() {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn current_uid() -> Result<u32, StoreError> {
    fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .map_err(|_| StoreError::Io)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use evertrace_domain::ids::CommandId;

    use super::*;
    use crate::{DirtyTarget, DirtyTargetKind, JournalEventDraft, JournalPayload};

    #[test]
    fn reserved_sequences_may_leave_gaps_without_reuse_in_one_writer() {
        let mut next = 10;
        assert_eq!(reserve_range(&mut next, 2), Ok(10));
        assert_eq!(next, 12);
        assert_eq!(reserve_range(&mut next, 1), Ok(12));
        assert_eq!(next, 13);
    }

    #[tokio::test]
    async fn injected_precommit_and_lost_ack_boundaries_are_retry_safe() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut writer = JournalWriter::open(&root).await.unwrap();
        let command = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a7a").unwrap(),
            vec![JournalEventDraft::runtime(
                1,
                [1; 32],
                "objects-v1",
                JournalPayload::DirtyTarget(DirtyTarget {
                    target_kind: DirtyTargetKind::ObjectsProjection,
                    target_id: "fault-boundary".into(),
                    algorithm_revision: "objects-v1".into(),
                    source_watermark: 1,
                }),
            )],
        )
        .unwrap();
        let prepared = prepare_command(&command).unwrap();

        let abandoned = reserve_range(&mut writer.next_seq, prepared.event_count).unwrap();
        let first_seq = reserve_range(&mut writer.next_seq, prepared.event_count).unwrap();
        assert_eq!(first_seq, abandoned + u64::from(prepared.event_count));
        let rows = rows_for_append(&prepared, first_seq, 2).unwrap();
        append_rows(&writer.journal, &rows).await.unwrap();
        drop(writer);

        let mut reopened = JournalWriter::open(&root).await.unwrap();
        let replay = reopened.commit(&command, 3).await.unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.first_seq, first_seq);
        assert_eq!(replay.last_seq, first_seq);
        assert_eq!(reopened.journal_rows().await.unwrap().len(), 2);
    }
}
