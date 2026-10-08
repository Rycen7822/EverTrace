use std::str::FromStr;

use evertrace_domain::ids::CommandId;

use crate::{
    command::{
        JournalCommand, JournalEventDraft, JournalPayload, MigrationApplied, StoreError,
        prepare_command,
    },
    journal::{rows_for_append, validate_complete_command},
    objects::ObjectRow,
    projections::ProjectionWorker,
    sqlite_state::SqliteHandle,
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
    /// Crate-private view of the canonical L0001 marker validation for the
    /// offline converter; it does not alter migration bytes or semantics.
    pub(crate) fn validate_marker(
        rows: &[crate::journal::JournalRow],
        require_present: bool,
    ) -> Result<bool, StoreError> {
        validate_migration_marker(rows, require_present)
    }

    #[cfg(test)]
    pub(crate) async fn apply(sqlite: &SqliteHandle) -> Result<MigrationOutcome, StoreError> {
        Self::apply_inner(sqlite, false).await
    }

    pub(crate) async fn apply_inner(
        sqlite: &SqliteHandle,
        l0002_tables_present: bool,
    ) -> Result<MigrationOutcome, StoreError> {
        let canonical_command_id = migration_command_id()?;
        let (rows, journal_exists, frontier, object_rows_count, objects_missing, relation_present) = {
            let state = sqlite.lock().map_err(|_| StoreError::StoreCorrupt)?;
            let (rows, journal_exists, frontier) = state.migration_rows(canonical_command_id)?;
            (
                rows,
                journal_exists,
                frontier,
                state.object_row_count()?,
                state.object_checkpoint_row()?.is_none(),
                state.relation_checkpoint_row()?.is_some(),
            )
        };
        if l0002_tables_present && !journal_exists {
            return Err(StoreError::StoreCorrupt);
        }
        let _ = relation_present;

        if !journal_exists && object_rows_count > 0 {
            // Objects without a journal cannot be repaired from history.
            return Err(StoreError::StoreCorrupt);
        }
        if objects_missing && object_rows_count > 0 {
            return Err(StoreError::StoreCorrupt);
        }
        if objects_missing {
            let checkpoint = ObjectRow::checkpoint(0, 1);
            sqlite
                .lock()
                .map_err(|_| StoreError::StoreCorrupt)?
                .commit_object_rows(
                    std::slice::from_ref(&checkpoint),
                    crate::sqlite_state::ObjectReconcile::default(),
                    &checkpoint,
                )?;
        }
        {
            let state = sqlite.lock().map_err(|_| StoreError::StoreCorrupt)?;
            crate::objects::checkpoint_from_rows(&state.object_rows()?)?;
        }

        let appended_event = !validate_migration_marker(&rows, l0002_tables_present)?;
        if appended_event {
            append_migration_event(sqlite, frontier).await?;
        }

        // L0002 performs its own objects catch-up before using the derived
        // families. Standalone L0001 still needs to finish that projection.
        if !l0002_tables_present {
            ProjectionWorker::new(std::sync::Arc::clone(sqlite))
                .catch_up()
                .await?;
        }

        Ok(if !journal_exists && objects_missing {
            MigrationOutcome::Applied
        } else if objects_missing {
            MigrationOutcome::RebuiltObjects
        } else if appended_event {
            MigrationOutcome::Reconciled
        } else {
            MigrationOutcome::Noop
        })
    }
}

pub(crate) fn validate_migration_marker(
    rows: &[crate::journal::JournalRow],
    require_present: bool,
) -> Result<bool, StoreError> {
    let expected = prepare_command(&migration_command()?)?;
    let matches = rows
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

async fn append_migration_event(
    sqlite: &SqliteHandle,
    committed_frontier: u64,
) -> Result<(), StoreError> {
    let command = migration_command()?;
    let prepared = prepare_command(&command)?;
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

fn migration_command_id() -> Result<CommandId, StoreError> {
    CommandId::from_str(MIGRATION_COMMAND_ID).map_err(|_| StoreError::Migration)
}

fn migration_command() -> Result<JournalCommand, StoreError> {
    JournalCommand::new(
        migration_command_id()?,
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
    use std::{os::unix::fs::PermissionsExt, path::Path};

    use super::*;
    use crate::command::{WatermarkAdvanced, WatermarkKind};
    use crate::sqlite_state::SqliteState;

    fn state(root: &Path) -> SqliteHandle {
        std::fs::create_dir(root).unwrap();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        SqliteState::open(root).unwrap().handle()
    }

    fn temp_root() -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        (temp, root)
    }

    #[tokio::test]
    async fn fresh_store_applies_once_and_reconciles_marker() {
        let (_temp, root) = temp_root();
        let sqlite = state(&root);
        assert_eq!(L0001::apply(&sqlite).await, Ok(MigrationOutcome::Applied));
        assert_eq!(L0001::apply(&sqlite).await, Ok(MigrationOutcome::Noop));
        let rows = sqlite.lock().unwrap().rows().unwrap();
        assert_eq!(rows.len(), 1);
        sqlite.lock().unwrap().object_rows().unwrap();
    }

    #[tokio::test]
    async fn migration_name_under_noncanonical_command_is_corruption() {
        let (_temp, root) = temp_root();
        let sqlite = state(&root);
        L0001::apply(&sqlite).await.unwrap();
        // A forged command carrying the same migration id under another
        // command ID is corruption and the store keeps refusing it.
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
        let rows = rows_for_append(&prepared, 2, 0).unwrap();
        sqlite.lock().unwrap().append_command_rows(&rows).unwrap();
        assert_eq!(L0001::apply(&sqlite).await, Err(StoreError::StoreCorrupt));
    }

    #[tokio::test]
    async fn objects_without_journal_fail_without_replacement() {
        let (_temp, root) = temp_root();
        let sqlite = state(&root);
        // A nonempty objects family without any journal history cannot be
        // repaired or replaced.
        let checkpoint = ObjectRow::checkpoint(0, 1);
        sqlite
            .lock()
            .unwrap()
            .commit_object_rows(
                std::slice::from_ref(&checkpoint),
                crate::sqlite_state::ObjectReconcile::default(),
                &checkpoint,
            )
            .unwrap();
        assert_eq!(L0001::apply(&sqlite).await, Err(StoreError::StoreCorrupt));
        assert_eq!(sqlite.lock().unwrap().rows().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn canonical_command_id_with_non_marker_payload_is_corruption() {
        let (_temp, root) = temp_root();
        let sqlite = state(&root);
        let occupied = JournalCommand::new(
            migration_command_id().unwrap(),
            vec![JournalEventDraft::runtime(
                1,
                [0; 32],
                "migration-test-v1",
                JournalPayload::WatermarkAdvanced(WatermarkAdvanced {
                    kind: WatermarkKind::RuntimeJobs,
                    value: 7,
                }),
            )],
        )
        .unwrap();
        let rows = rows_for_append(&prepare_command(&occupied).unwrap(), 1, 0).unwrap();
        sqlite.lock().unwrap().append_command_rows(&rows).unwrap();
        assert_eq!(L0001::apply(&sqlite).await, Err(StoreError::StoreCorrupt));
    }

    #[tokio::test]
    async fn l0001_append_uses_global_frontier_after_non_marker_history() {
        let (_temp, root) = temp_root();
        let sqlite = state(&root);
        let prior = JournalCommand::new(
            "01890f47-6a4a-7cc1-98b9-01890f476a4b".parse().unwrap(),
            vec![JournalEventDraft::runtime(
                1,
                [0; 32],
                "migration-test-v1",
                JournalPayload::WatermarkAdvanced(WatermarkAdvanced {
                    kind: WatermarkKind::RuntimeJobs,
                    value: 7,
                }),
            )],
        )
        .unwrap();
        let rows = rows_for_append(&prepare_command(&prior).unwrap(), 1, 0).unwrap();
        sqlite.lock().unwrap().append_command_rows(&rows).unwrap();

        assert_eq!(
            L0001::apply(&sqlite).await,
            Ok(MigrationOutcome::RebuiltObjects)
        );
        let rows = sqlite.lock().unwrap().rows().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].event_type, "watermark_advanced_v1");
        assert_eq!(rows[1].seq, 2);
        assert_eq!(rows[1].command_id, migration_command_id().unwrap());
    }
}
