use std::str::FromStr;

use evertrace_domain::ids::CommandId;
use lancedb::{
    Connection, Table,
    index::{Index, scalar::FtsIndexBuilder},
};

use crate::{
    JournalCommand, JournalEventDraft, JournalPayload, MigrationApplied, ProjectionWorker,
    StoreError,
    journal::{append_rows, read_all_journal_rows, rows_for_append, validate_journal_table},
    migrations::{L0001, MigrationOutcome},
    objects::{OBJECTS_TABLE, validate_objects_table},
    query::L0002ProjectionWorker,
    relations::{RELATIONS_TABLE, RelationProjectionRow, relations_batch, relations_schema},
    search::{SEARCH_TABLE, SearchProjectionRow, search_batch, search_schema},
};

const MIGRATION_ID: &str = "L0002";
const MIGRATION_COMMAND_ID: &str = "01890f47-6a4a-7cc1-98b9-01890f476a41";

pub struct L0002;

impl L0002 {
    pub async fn apply(connection: &Connection) -> Result<MigrationOutcome, StoreError> {
        Self::apply_inner(connection, false).await
    }

    #[cfg(test)]
    async fn apply_crash_before_marker(
        connection: &Connection,
    ) -> Result<MigrationOutcome, StoreError> {
        Self::apply_inner(connection, true).await
    }

    async fn apply_inner(
        connection: &Connection,
        crash_before_marker: bool,
    ) -> Result<MigrationOutcome, StoreError> {
        let initial_names = connection
            .table_names()
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let has_relation = initial_names.iter().any(|name| name == RELATIONS_TABLE);
        let has_search = initial_names.iter().any(|name| name == SEARCH_TABLE);
        let base_outcome = if has_relation || has_search {
            L0001::reconcile_for_l0002(connection).await?
        } else {
            L0001::apply(connection).await?
        };
        let journal = connection
            .open_table(crate::JOURNAL_TABLE)
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

        let relations = open_or_create_relations(connection, has_relation).await?;
        let search = open_or_create_search(connection, has_search).await?;

        let before = read_all_journal_rows(&journal).await?;
        let expected = crate::prepare_command(&migration_command()?)?;
        let matches = before
            .iter()
            .filter_map(|row| match row.payload() {
                Ok(JournalPayload::MigrationApplied(value))
                    if value.migration_id == MIGRATION_ID =>
                {
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
            || (matches.is_empty()
                && before
                    .iter()
                    .any(|row| row.command_id == expected.command_id))
        {
            return Err(StoreError::StoreCorrupt);
        }
        let appended = matches.is_empty();
        let worker = L0002ProjectionWorker::new(journal.clone(), relations, search.clone());
        if appended {
            // L0002 is not durable until every derived table is usable at the
            // exact pre-marker frontier. A crash here leaves no completion marker.
            let pre_marker = ProjectionWorker::new(journal.clone(), objects.clone())
                .catch_up()
                .await?;
            worker.catch_up(&pre_marker).await?;
            ensure_fts(&search).await?;
            if crash_before_marker {
                return Err(StoreError::Migration);
            }
            append_migration(&journal, &before).await?;
        }

        // The marker itself advances the authoritative frontier. Independently
        // committed projections converge to it on this run or the next reopen.
        let objects_snapshot = ProjectionWorker::new(journal, objects).catch_up().await?;
        worker.catch_up(&objects_snapshot).await?;
        ensure_fts(&search).await?;

        Ok(if base_outcome == MigrationOutcome::Applied {
            MigrationOutcome::Applied
        } else if base_outcome == MigrationOutcome::RebuiltObjects {
            MigrationOutcome::RebuiltObjects
        } else if appended || !has_relation || !has_search {
            MigrationOutcome::Reconciled
        } else {
            MigrationOutcome::Noop
        })
    }
}

async fn open_or_create_relations(
    connection: &Connection,
    exists: bool,
) -> Result<Table, StoreError> {
    let table = if exists {
        connection
            .open_table(RELATIONS_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?
    } else {
        connection
            .create_empty_table(RELATIONS_TABLE, relations_schema())
            .execute()
            .await
            .map_err(|_| StoreError::Migration)?
    };
    if table
        .schema()
        .await
        .map_err(|_| StoreError::LanceDb)?
        .as_ref()
        != relations_schema().as_ref()
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
            .add(relations_batch(&[RelationProjectionRow::checkpoint(0)])?)
            .execute()
            .await
            .map_err(|_| StoreError::Migration)?;
    } else {
        crate::relations::read_relation_rows(&table).await?;
    }
    Ok(table)
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

async fn append_migration(journal: &Table, rows: &[crate::JournalRow]) -> Result<(), StoreError> {
    let prepared = crate::prepare_command(&migration_command()?)?;
    let first_seq = rows
        .iter()
        .map(|row| row.seq)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(StoreError::Migration)?;
    append_rows(journal, &rows_for_append(&prepared, first_seq, 0)?).await
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
    use std::sync::Arc;

    use arrow_schema::{DataType, Field, Schema};

    use super::*;

    async fn test_connection() -> (tempfile::TempDir, Connection) {
        let temp = tempfile::tempdir().unwrap();
        let connection = lancedb::connect(temp.path().to_str().unwrap())
            .execute()
            .await
            .unwrap();
        (temp, connection)
    }

    #[tokio::test]
    async fn fresh_upgrade_missing_table_and_noop_converge() {
        let (_temp, connection) = test_connection().await;
        assert_eq!(
            L0002::apply(&connection).await,
            Ok(MigrationOutcome::Applied)
        );
        assert_eq!(
            connection.table_names().execute().await.unwrap(),
            [
                "evertrace_journal",
                "evertrace_objects",
                "evertrace_relations",
                "evertrace_search"
            ]
        );
        let relations = connection
            .open_table(RELATIONS_TABLE)
            .execute()
            .await
            .unwrap();
        let search = connection.open_table(SEARCH_TABLE).execute().await.unwrap();
        let versions = (
            relations.version().await.unwrap(),
            search.version().await.unwrap(),
        );
        assert_eq!(L0002::apply(&connection).await, Ok(MigrationOutcome::Noop));
        assert_eq!(
            (
                relations.version().await.unwrap(),
                search.version().await.unwrap()
            ),
            versions
        );
        connection.drop_table(RELATIONS_TABLE, &[]).await.unwrap();
        assert_eq!(
            L0002::apply(&connection).await,
            Ok(MigrationOutcome::Reconciled)
        );
        let rebuilt = connection
            .open_table(RELATIONS_TABLE)
            .execute()
            .await
            .unwrap();
        assert_eq!(
            crate::read_relation_rows(&rebuilt).await.unwrap()[0].source_event_seq,
            2
        );
    }

    #[tokio::test]
    async fn legal_l0001_upgrade_and_wrong_partial_schema_fail_closed() {
        let (_temp, connection) = test_connection().await;
        assert_eq!(
            L0001::apply(&connection).await,
            Ok(MigrationOutcome::Applied)
        );
        assert_eq!(
            L0002::apply(&connection).await,
            Ok(MigrationOutcome::Reconciled)
        );

        let (_temp, corrupt) = test_connection().await;
        L0001::apply(&corrupt).await.unwrap();
        corrupt
            .create_empty_table(
                RELATIONS_TABLE,
                Arc::new(Schema::new(vec![Field::new(
                    "wrong",
                    DataType::Utf8,
                    false,
                )])),
            )
            .execute()
            .await
            .unwrap();
        assert_eq!(L0002::apply(&corrupt).await, Err(StoreError::StoreCorrupt));
        assert!(
            !corrupt
                .table_names()
                .execute()
                .await
                .unwrap()
                .contains(&SEARCH_TABLE.into())
        );
    }

    #[tokio::test]
    async fn crash_before_marker_and_post_marker_reopen_converge_without_false_completion() {
        let (_temp, before_marker) = test_connection().await;
        assert_eq!(
            L0002::apply_crash_before_marker(&before_marker).await,
            Err(StoreError::Migration)
        );
        let journal = before_marker
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        assert!(
            read_all_journal_rows(&journal)
                .await
                .unwrap()
                .iter()
                .all(|row| !matches!(
                    row.payload().unwrap(),
                    JournalPayload::MigrationApplied(MigrationApplied { migration_id })
                        if migration_id == MIGRATION_ID
                ))
        );
        assert_eq!(
            L0002::apply(&before_marker).await,
            Ok(MigrationOutcome::Reconciled)
        );

        let (_temp, after_marker) = test_connection().await;
        assert_eq!(
            L0002::apply_crash_before_marker(&after_marker).await,
            Err(StoreError::Migration)
        );
        let journal = after_marker
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        let rows = read_all_journal_rows(&journal).await.unwrap();
        append_migration(&journal, &rows).await.unwrap();
        assert_eq!(
            L0002::apply(&after_marker).await,
            Ok(MigrationOutcome::Noop)
        );
        let relations = after_marker
            .open_table(RELATIONS_TABLE)
            .execute()
            .await
            .unwrap();
        let search = after_marker
            .open_table(SEARCH_TABLE)
            .execute()
            .await
            .unwrap();
        assert_eq!(
            crate::read_relation_rows(&relations).await.unwrap()[0].source_event_seq,
            2
        );
        assert_eq!(
            crate::read_search_rows(&search).await.unwrap()[0].source_event_seq,
            2
        );
    }

    #[tokio::test]
    async fn l0002_tables_cannot_bypass_the_exact_l0001_base_marker() {
        let (_temp, connection) = test_connection().await;
        connection
            .create_empty_table(crate::JOURNAL_TABLE, crate::journal::journal_schema())
            .execute()
            .await
            .unwrap();
        let objects = connection
            .create_empty_table(OBJECTS_TABLE, crate::objects::objects_schema())
            .execute()
            .await
            .unwrap();
        objects
            .add(
                crate::objects::objects_batch(&[crate::objects::ObjectRow::checkpoint(0, 1)])
                    .unwrap(),
            )
            .execute()
            .await
            .unwrap();
        let relations = connection
            .create_empty_table(RELATIONS_TABLE, relations_schema())
            .execute()
            .await
            .unwrap();
        relations
            .add(relations_batch(&[RelationProjectionRow::checkpoint(0)]).unwrap())
            .execute()
            .await
            .unwrap();
        assert_eq!(
            L0002::apply(&connection).await,
            Err(StoreError::StoreCorrupt)
        );
        assert!(
            !connection
                .table_names()
                .execute()
                .await
                .unwrap()
                .contains(&SEARCH_TABLE.into())
        );
    }
}
