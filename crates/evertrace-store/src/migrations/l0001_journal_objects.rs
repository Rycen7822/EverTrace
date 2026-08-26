use std::str::FromStr;

use evertrace_domain::ids::CommandId;
use lancedb::{Connection, Table};

use crate::{
    command::{
        JournalCommand, JournalEventDraft, JournalPayload, MigrationApplied, StoreError,
        prepare_command,
    },
    journal::{
        JOURNAL_TABLE, append_rows, journal_schema, read_all_journal_rows, rows_for_append,
        validate_journal_table,
    },
    objects::{OBJECTS_TABLE, ObjectRow, objects_batch, objects_schema, validate_objects_table},
    projections::ProjectionWorker,
};

const MIGRATION_ID: &str = "L0001";
const MIGRATION_COMMAND_ID: &str = "01890f47-6a4a-7cc1-98b9-01890f476a40";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationOutcome {
    Applied,
    Reconciled,
    RebuiltObjects,
    Noop,
}

pub struct L0001;

impl L0001 {
    pub async fn apply(connection: &Connection) -> Result<MigrationOutcome, StoreError> {
        let names = connection
            .table_names()
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let journal_exists = names.iter().any(|name| name == JOURNAL_TABLE);
        let objects_exists = names.iter().any(|name| name == OBJECTS_TABLE);

        if !journal_exists && objects_exists {
            let objects = connection
                .open_table(OBJECTS_TABLE)
                .execute()
                .await
                .map_err(|_| StoreError::LanceDb)?;
            if objects
                .count_rows(None)
                .await
                .map_err(|_| StoreError::LanceDb)?
                != 0
            {
                return Err(StoreError::StoreCorrupt);
            }
            validate_empty_objects_schema(&objects).await?;
        }

        let journal = if journal_exists {
            let table = connection
                .open_table(JOURNAL_TABLE)
                .execute()
                .await
                .map_err(|_| StoreError::LanceDb)?;
            validate_journal_table(&table).await?;
            table
        } else {
            connection
                .create_empty_table(JOURNAL_TABLE, journal_schema())
                .execute()
                .await
                .map_err(|_| StoreError::Migration)?
        };

        let mut rebuilt_objects = false;
        let objects = if objects_exists {
            let table = connection
                .open_table(OBJECTS_TABLE)
                .execute()
                .await
                .map_err(|_| StoreError::LanceDb)?;
            if table
                .count_rows(None)
                .await
                .map_err(|_| StoreError::LanceDb)?
                == 0
            {
                validate_empty_objects_schema(&table).await?;
                append_initial_checkpoint(&table).await?;
            } else {
                validate_objects_table(&table).await?;
            }
            table
        } else {
            rebuilt_objects = journal_exists;
            let table = connection
                .create_empty_table(OBJECTS_TABLE, objects_schema())
                .execute()
                .await
                .map_err(|_| StoreError::Migration)?;
            append_initial_checkpoint(&table).await?;
            table
        };

        validate_journal_table(&journal).await?;
        validate_objects_table(&objects).await?;
        let before_rows = read_all_journal_rows(&journal).await?;
        let expected_migration = prepare_command(&migration_command()?)?;
        let migration_rows = before_rows
            .iter()
            .filter_map(|row| match row.payload() {
                Ok(JournalPayload::MigrationApplied(MigrationApplied { migration_id }))
                    if migration_id == MIGRATION_ID =>
                {
                    Some(Ok(row))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if migration_rows.len() > 1
            || migration_rows.first().is_some_and(|row| {
                row.command_id != expected_migration.command_id
                    || row.command_hash != expected_migration.command_hash
                    || row.command_event_count != 1
                    || row.ordinal != 0
                    || row.event_id != expected_migration.events[0].event_id
            })
            || (migration_rows.is_empty()
                && before_rows
                    .iter()
                    .any(|row| row.command_id == expected_migration.command_id))
        {
            return Err(StoreError::StoreCorrupt);
        }
        let appended_event = migration_rows.is_empty();
        if appended_event {
            append_migration_event(&journal, &before_rows).await?;
        }

        let projection = ProjectionWorker::new(journal.clone(), objects);
        projection.catch_up().await?;

        Ok(if !journal_exists && !objects_exists {
            MigrationOutcome::Applied
        } else if rebuilt_objects {
            MigrationOutcome::RebuiltObjects
        } else if appended_event {
            MigrationOutcome::Reconciled
        } else {
            MigrationOutcome::Noop
        })
    }
}

async fn validate_empty_objects_schema(table: &Table) -> Result<(), StoreError> {
    let schema = table.schema().await.map_err(|_| StoreError::LanceDb)?;
    if schema.as_ref() != objects_schema().as_ref() {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

async fn append_initial_checkpoint(table: &Table) -> Result<(), StoreError> {
    table
        .add(objects_batch(&[ObjectRow::checkpoint(0, 1)])?)
        .execute()
        .await
        .map(|_| ())
        .map_err(|_| StoreError::Migration)
}

async fn append_migration_event(
    journal: &Table,
    existing: &[crate::journal::JournalRow],
) -> Result<(), StoreError> {
    let command = migration_command()?;
    let prepared = prepare_command(&command)?;
    let first_seq = existing
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
            "l0001",
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

    async fn connection() -> (tempfile::TempDir, Connection) {
        let temp = tempfile::tempdir().unwrap();
        let connection = lancedb::connect(temp.path().to_str().unwrap())
            .execute()
            .await
            .unwrap();
        (temp, connection)
    }

    #[tokio::test]
    async fn valid_tables_without_event_are_reconciled_once() {
        let (_temp, connection) = connection().await;
        connection
            .create_empty_table(JOURNAL_TABLE, journal_schema())
            .execute()
            .await
            .unwrap();
        let objects = connection
            .create_empty_table(OBJECTS_TABLE, objects_schema())
            .execute()
            .await
            .unwrap();
        append_initial_checkpoint(&objects).await.unwrap();
        assert_eq!(
            L0001::apply(&connection).await,
            Ok(MigrationOutcome::Reconciled)
        );
        assert_eq!(L0001::apply(&connection).await, Ok(MigrationOutcome::Noop));
        let journal = connection
            .open_table(JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        assert_eq!(read_all_journal_rows(&journal).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn migration_rejects_partial_journal_and_event_schema_mismatch() {
        let (_temp, connection) = connection().await;
        connection
            .create_empty_table(
                JOURNAL_TABLE,
                Arc::new(Schema::new(vec![Field::new(
                    "event_id",
                    DataType::Utf8,
                    false,
                )])),
            )
            .execute()
            .await
            .unwrap();
        assert_eq!(
            L0001::apply(&connection).await,
            Err(StoreError::StoreCorrupt)
        );
    }

    #[tokio::test]
    async fn applied_event_with_wrong_objects_schema_fails_closed() {
        let (_temp, connection) = connection().await;
        assert_eq!(
            L0001::apply(&connection).await,
            Ok(MigrationOutcome::Applied)
        );
        connection.drop_table(OBJECTS_TABLE, &[]).await.unwrap();
        connection
            .create_empty_table(
                OBJECTS_TABLE,
                Arc::new(Schema::new(vec![Field::new(
                    "row_id",
                    DataType::Utf8,
                    false,
                )])),
            )
            .execute()
            .await
            .unwrap();
        assert_eq!(
            L0001::apply(&connection).await,
            Err(StoreError::StoreCorrupt)
        );
    }

    #[tokio::test]
    async fn migration_name_under_noncanonical_command_is_corruption() {
        let (_temp, connection) = connection().await;
        let journal = connection
            .create_empty_table(JOURNAL_TABLE, journal_schema())
            .execute()
            .await
            .unwrap();
        let objects = connection
            .create_empty_table(OBJECTS_TABLE, objects_schema())
            .execute()
            .await
            .unwrap();
        append_initial_checkpoint(&objects).await.unwrap();
        let forged = JournalCommand::new(
            CommandId::from_str("01890f47-6a4a-7cc1-98b9-01890f476a41").unwrap(),
            vec![JournalEventDraft::runtime(
                0,
                [0; 32],
                "l0001",
                JournalPayload::MigrationApplied(MigrationApplied {
                    migration_id: MIGRATION_ID.into(),
                }),
            )],
        )
        .unwrap();
        let prepared = prepare_command(&forged).unwrap();
        append_rows(&journal, &rows_for_append(&prepared, 1, 0).unwrap())
            .await
            .unwrap();
        assert_eq!(
            L0001::apply(&connection).await,
            Err(StoreError::StoreCorrupt)
        );
    }

    #[tokio::test]
    async fn journal_missing_with_nonempty_objects_fails_without_replacement() {
        let (_temp, connection) = connection().await;
        let objects = connection
            .create_empty_table(OBJECTS_TABLE, objects_schema())
            .execute()
            .await
            .unwrap();
        append_initial_checkpoint(&objects).await.unwrap();
        assert_eq!(
            L0001::apply(&connection).await,
            Err(StoreError::StoreCorrupt)
        );
        assert_eq!(objects.count_rows(None).await.unwrap(), 1);
        assert_eq!(
            connection.table_names().execute().await.unwrap(),
            vec![OBJECTS_TABLE]
        );
    }
}
