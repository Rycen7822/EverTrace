use std::str::FromStr;

use evertrace_domain::ids::CommandId;
use lancedb::{
    Connection, Table,
    index::{Index, scalar::FtsIndexBuilder},
};

use crate::{
    JournalCommand, JournalEventDraft, JournalPayload, MigrationApplied, StoreError,
    journal::{rows_for_append, validate_complete_command},
    migrations::{L0001, MigrationOutcome},
    projections::ProjectionWorker,
    query::L0002ProjectionWorker,
    relations::RelationProjectionRow,
    search::{SEARCH_TABLE, SearchProjectionRow, search_batch, search_schema},
    sqlite_state::SqliteHandle,
};

const MIGRATION_ID: &str = "L0002";
const MIGRATION_COMMAND_ID: &str = "01890f47-6a4a-7cc1-98b9-01890f476a41";

pub struct L0002;

impl L0002 {
    /// Crate-private view of the canonical L0002 marker validation for the
    /// offline converter; it does not alter migration bytes or semantics.
    pub(crate) fn validate_marker(
        rows: &[crate::journal::JournalRow],
        require_present: bool,
    ) -> Result<bool, StoreError> {
        validate_l0002_migration_marker(rows, require_present)
    }

    pub(crate) async fn apply(
        sqlite: &SqliteHandle,
        connection: &Connection,
    ) -> Result<MigrationOutcome, StoreError> {
        Self::apply_inner(sqlite, connection, false).await
    }

    #[cfg(test)]
    async fn apply_crash_before_marker(
        sqlite: &SqliteHandle,
        connection: &Connection,
    ) -> Result<MigrationOutcome, StoreError> {
        Self::apply_inner(sqlite, connection, true).await
    }

    async fn apply_inner(
        sqlite: &SqliteHandle,
        connection: &Connection,
        crash_before_marker: bool,
    ) -> Result<MigrationOutcome, StoreError> {
        let initial_names = connection
            .table_names()
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let has_search = initial_names.iter().any(|name| name == SEARCH_TABLE);
        let has_relation = sqlite
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?
            .relation_checkpoint_row()?
            .is_some();
        let base_outcome = L0001::apply_inner(sqlite, has_relation || has_search).await?;
        let mut objects_snapshot = ProjectionWorker::new(std::sync::Arc::clone(sqlite))
            .catch_up()
            .await?;
        let created_relation = !has_relation;
        if created_relation {
            let checkpoint = RelationProjectionRow::checkpoint(0);
            sqlite
                .lock()
                .map_err(|_| StoreError::StoreCorrupt)?
                .commit_relation_rows(std::slice::from_ref(&checkpoint), &[], &checkpoint)?;
        }
        let search = open_or_create_search(connection, has_search).await?;

        let rows = sqlite
            .lock()
            .map_err(|_| StoreError::StoreCorrupt)?
            .rows()?;
        let appended = !validate_l0002_migration_marker(&rows, false)?;
        let worker = L0002ProjectionWorker::new(std::sync::Arc::clone(sqlite), search.clone());
        if appended {
            // L0002 is not durable until every derived family is usable at the
            // exact pre-marker frontier. A crash here leaves no completion marker.
            worker.catch_up(&objects_snapshot).await?;
            ensure_fts(&search).await?;
            if crash_before_marker {
                return Err(StoreError::Migration);
            }
            append_migration(sqlite, rows.last().map(|row| row.seq).unwrap_or(0)).await?;
            // The marker itself advances the authoritative frontier.
            objects_snapshot = ProjectionWorker::new(std::sync::Arc::clone(sqlite))
                .catch_up()
                .await?;
        }

        // Independently committed projections converge to the validated
        // frontier on this run or the next reopen.
        worker.catch_up(&objects_snapshot).await?;
        ensure_fts(&search).await?;

        Ok(if base_outcome == MigrationOutcome::Applied {
            MigrationOutcome::Applied
        } else if base_outcome == MigrationOutcome::RebuiltObjects {
            MigrationOutcome::RebuiltObjects
        } else if appended || created_relation || !has_search {
            MigrationOutcome::Reconciled
        } else {
            MigrationOutcome::Noop
        })
    }
}

async fn open_or_create_search(connection: &Connection, exists: bool) -> Result<Table, StoreError> {
    let table = if exists {
        connection
            .open_table(SEARCH_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?
    } else {
        connection
            .create_empty_table(SEARCH_TABLE, search_schema())
            .execute()
            .await
            .map_err(|_| StoreError::Migration)?
    };
    if table
        .schema()
        .await
        .map_err(|_| StoreError::LanceDb)?
        .as_ref()
        != search_schema().as_ref()
    {
        return Err(StoreError::StoreCorrupt);
    }
    if table
        .count_rows(None)
        .await
        .map_err(|_| StoreError::LanceDb)?
        == 0
    {
        table
            .add(search_batch(&[SearchProjectionRow::checkpoint(0)])?)
            .execute()
            .await
            .map_err(|_| StoreError::Migration)?;
    } else {
        crate::search::read_search_rows(&table).await?;
    }
    Ok(table)
}

async fn ensure_fts(table: &Table) -> Result<(), StoreError> {
    let indices = table
        .list_indices()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    if indices.is_empty() {
        let params = FtsIndexBuilder::default()
            .base_tokenizer("icu".into())
            .stem(false)
            .remove_stop_words(false)
            .ascii_folding(true)
            .with_position(false);
        table
            .create_index(&["text"], Index::FTS(params))
            .execute()
            .await
            .map_err(|_| StoreError::Migration)?;
    } else if indices.len() != 1 || indices[0].columns != ["text"] {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

async fn append_migration(
    sqlite: &SqliteHandle,
    committed_frontier: u64,
) -> Result<(), StoreError> {
    let command = migration_command()?;
    let prepared = crate::prepare_command(&command)?;
    let first_seq = committed_frontier
        .checked_add(1)
        .ok_or(StoreError::Migration)?;
    let rows = rows_for_append(&prepared, first_seq, 0)?;
    validate_complete_command(&rows)?;
    sqlite
        .lock()
        .map_err(|_| StoreError::StoreCorrupt)?
        .append_command_rows(&rows)
}

/// Whether the canonical L0002 command is present in the given history, or
/// whether its ID was forged under another payload. The offline converter
/// reuses this exact validation instead of trusting a profile string.
pub(crate) fn validate_l0002_migration_marker(
    rows: &[crate::journal::JournalRow],
    require_present: bool,
) -> Result<bool, StoreError> {
    let expected = crate::prepare_command(&migration_command()?)?;
    let matches = rows
        .iter()
        .filter_map(|row| match row.payload() {
            Ok(JournalPayload::MigrationApplied(value)) if value.migration_id == MIGRATION_ID => {
                Some(Ok(row))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    if matches.len() > 1
        || matches.first().is_some_and(|row| {
            row.command_id != expected.command_id
                || row.command_hash != expected.command_hash
                || row.command_event_count != 1
                || row.ordinal != 0
                || row.event_id != expected.events[0].event_id
        })
        || (matches.is_empty() && rows.iter().any(|row| row.command_id == expected.command_id))
        || (require_present && matches.is_empty())
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(!matches.is_empty())
}

fn migration_command() -> Result<JournalCommand, StoreError> {
    JournalCommand::new(
        CommandId::from_str(MIGRATION_COMMAND_ID).map_err(|_| StoreError::Migration)?,
        vec![JournalEventDraft::runtime(
            0,
            [0; 32],
            "l0002",
            JournalPayload::MigrationApplied(MigrationApplied {
                migration_id: MIGRATION_ID.into(),
            }),
        )],
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::sqlite_state::SqliteState;

    async fn fixture() -> (tempfile::TempDir, SqliteHandle, Connection) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let sqlite = SqliteState::open(&root).unwrap().handle();
        let connection = evertrace_capture::ConfinedRoot::open_owned_private(
            &crate::connection::native_root(&root),
        )
        .unwrap();
        drop(connection);
        let connection = lancedb::connect(crate::connection::native_root(&root).to_str().unwrap())
            .execute()
            .await
            .unwrap();
        (temp, sqlite, connection)
    }

    fn journal_row_count(sqlite: &SqliteHandle) -> usize {
        sqlite.lock().unwrap().rows().unwrap().len()
    }

    #[tokio::test]
    async fn fresh_store_applies_both_markers_then_noop() {
        let (_temp, sqlite, connection) = fixture().await;
        assert_eq!(
            L0002::apply(&sqlite, &connection).await,
            Ok(MigrationOutcome::Applied)
        );
        assert_eq!(journal_row_count(&sqlite), 2);
        assert_eq!(
            L0002::apply(&sqlite, &connection).await,
            Ok(MigrationOutcome::Noop)
        );
        // Relations, objects and search all carry committed checkpoints.
        sqlite.lock().unwrap().object_rows().unwrap();
        assert!(
            sqlite
                .lock()
                .unwrap()
                .relation_checkpoint_row()
                .unwrap()
                .is_some()
        );
        let search = connection.open_table(SEARCH_TABLE).execute().await.unwrap();
        assert!(!search.list_indices().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn crash_before_marker_is_completed_on_the_next_run() {
        let (_temp, sqlite, connection) = fixture().await;
        assert_eq!(
            L0002::apply_crash_before_marker(&sqlite, &connection).await,
            Err(StoreError::Migration)
        );
        assert_eq!(journal_row_count(&sqlite), 1);
        assert_eq!(
            L0002::apply(&sqlite, &connection).await,
            Ok(MigrationOutcome::Reconciled)
        );
        assert_eq!(journal_row_count(&sqlite), 2);
    }

    #[tokio::test]
    async fn partial_relation_history_without_journal_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let sqlite = SqliteState::open(&root).unwrap().handle();
        let checkpoint = RelationProjectionRow::checkpoint(0);
        sqlite
            .lock()
            .unwrap()
            .commit_relation_rows(std::slice::from_ref(&checkpoint), &[], &checkpoint)
            .unwrap();
        let connection = lancedb::connect(crate::connection::native_root(&root).to_str().unwrap())
            .execute()
            .await
            .unwrap();
        assert_eq!(
            L0002::apply(&sqlite, &connection).await,
            Err(StoreError::StoreCorrupt)
        );
    }

    #[tokio::test]
    async fn wrong_search_schema_is_not_recreated() {
        let (_temp, sqlite, connection) = fixture().await;
        L0002::apply(&sqlite, &connection).await.unwrap();
        connection.drop_table(SEARCH_TABLE, &[]).await.unwrap();
        connection
            .create_empty_table(SEARCH_TABLE, search_schema())
            .execute()
            .await
            .unwrap();
        // Empty table without its checkpoint row is a partial layout that the
        // migration completes rather than rejecting.
        assert_eq!(
            L0002::apply(&sqlite, &connection).await,
            Ok(MigrationOutcome::Noop)
        );
    }
}
