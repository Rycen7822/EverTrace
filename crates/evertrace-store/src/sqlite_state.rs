//! Physical SQLite state for one isolated store layout.
//!
//! One private `store/evertrace.sqlite` carries the authoritative journal and
//! the rebuildable objects/runtime and relations families.  This module owns
//! the single writer connection, the physical rows, transactions, file
//! identity and per-family commit epochs.  It is deliberately not a second
//! writer or admission authority: `JournalWriter` keeps the sibling lock,
//! sequence reservation, domain admission and publication order.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use evertrace_domain::ids::CommandId;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params};

use crate::{
    command::{ObjectFamily, RecordClass, SourceKind, StoreError},
    journal::{JournalRow, validate_complete_command, validate_journal_rows},
    objects::{OBJECTS_CHECKPOINT_ID, ObjectRow, ObjectRowClass, ObjectRowKind},
    relations::{RELATIONS_CHECKPOINT_ID, RelationProjectionRow},
};

pub(crate) const SQLITE_FILE_NAME: &str = "evertrace.sqlite";
const WAL_FILE_SUFFIX: &str = "-wal";
const SHM_FILE_SUFFIX: &str = "-shm";
/// "EVSJ" identifies this physical format in the SQLite header.
const APPLICATION_ID: i64 = 0x4556_534A;
/// Physical header of this layout.  The test-only component gate used 1; a
/// version-1 file is an old isolated format that requires the offline
/// converter, never a silent in-place upgrade.
pub(crate) const USER_VERSION: i64 = 2;
/// One writer owns this connection. Unexpected contention must not consume
/// the product's shared two-second request deadline in a hidden SQLite wait.
const BUSY_TIMEOUT: Duration = Duration::ZERO;

static NEXT_INCARNATION: AtomicU64 = AtomicU64::new(1);

/// A cloneable physical-state handle. All SQLite writes execute through this
/// one connection; readers use separate short-lived read-only connections.
pub(crate) type SqliteHandle = Arc<Mutex<SqliteState>>;

pub(crate) struct StartupJournalIndex {
    pub(crate) commands: BTreeMap<CommandId, Vec<(u16, u64)>>,
    pub(crate) frontier: u64,
}

/// One real table carrying the existing `JournalRow` fields verbatim. `seq`
/// is a fixed 8-byte big-endian BLOB so SQL ordering and ranges preserve the
/// full u64 domain (including values above i64::MAX) and permitted gaps.
const CREATE_JOURNAL_TABLE: &str = "\
CREATE TABLE journal_events (
  seq BLOB NOT NULL PRIMARY KEY CHECK (length(seq) = 8),
  event_id TEXT NOT NULL UNIQUE,
  command_id TEXT NOT NULL,
  command_hash BLOB NOT NULL CHECK (length(command_hash) = 32),
  ordinal INTEGER NOT NULL,
  command_event_count INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  record_class TEXT NOT NULL,
  object_family TEXT,
  object_id TEXT,
  revision_id TEXT,
  project_id TEXT,
  repository_id TEXT,
  worktree_id TEXT,
  task_id TEXT,
  workstream_id TEXT,
  session_id TEXT,
  execution_lane_id TEXT,
  occurred_at_us INTEGER NOT NULL,
  ingested_at_us INTEGER NOT NULL,
  source_kind TEXT NOT NULL,
  source_ref_json TEXT,
  payload_schema INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  content_hash BLOB NOT NULL CHECK (length(content_hash) = 32),
  causation_id TEXT,
  correlation_id TEXT,
  effective_config_hash BLOB NOT NULL CHECK (length(effective_config_hash) = 32),
  algorithm_revision TEXT NOT NULL,
  UNIQUE (command_id, ordinal)
) WITHOUT ROWID";

const CREATE_OBJECTS_TABLE: &str = "\
CREATE TABLE object_rows (
  row_id TEXT NOT NULL PRIMARY KEY,
  row_kind TEXT NOT NULL CHECK (row_kind IN ('data', 'checkpoint')),
  row_class TEXT CHECK (row_class IS NULL OR row_class IN ('object', 'runtime', 'projection')),
  object_family TEXT,
  object_kind TEXT,
  object_id TEXT,
  current_revision_id TEXT,
  lifecycle TEXT,
  epistemic TEXT,
  authority TEXT,
  publication_state TEXT,
  support_state TEXT,
  project_id TEXT,
  repository_id TEXT,
  worktree_id TEXT,
  task_id TEXT,
  workstream_id TEXT,
  session_id TEXT,
  payload_json TEXT,
  source_event_seq BLOB NOT NULL CHECK (length(source_event_seq) = 8),
  projection_generation BLOB NOT NULL CHECK (length(projection_generation) = 8),
  CHECK (row_kind <> 'checkpoint' OR (row_class IS NULL AND object_family IS NULL AND object_kind IS NULL AND object_id IS NULL AND current_revision_id IS NULL AND lifecycle IS NULL AND epistemic IS NULL AND authority IS NULL AND publication_state IS NULL AND support_state IS NULL AND project_id IS NULL AND repository_id IS NULL AND worktree_id IS NULL AND task_id IS NULL AND workstream_id IS NULL AND session_id IS NULL AND payload_json IS NULL)),
  CHECK (row_kind <> 'data' OR row_class IS NOT NULL),
  CHECK (row_kind <> 'data' OR payload_json IS NOT NULL),
  CHECK (row_class IS NULL OR row_class <> 'object' OR (object_family IS NOT NULL AND object_id IS NOT NULL)),
  CHECK (row_class IS NULL OR row_class = 'object' OR (object_family IS NULL AND object_id IS NULL))
) WITHOUT ROWID";

const CREATE_RELATIONS_TABLE: &str = "\
CREATE TABLE relation_rows (
  row_id TEXT NOT NULL PRIMARY KEY,
  relation_kind TEXT,
  source_id TEXT,
  target_id TEXT,
  source_event_seq BLOB NOT NULL CHECK (length(source_event_seq) = 8),
  projection_generation BLOB NOT NULL CHECK (length(projection_generation) = 8)
) WITHOUT ROWID";

const SELECT_COMMAND_ROWS: &str = "SELECT seq, event_id, command_id, command_hash, ordinal, command_event_count, event_type, record_class, object_family, object_id, revision_id, project_id, repository_id, worktree_id, task_id, workstream_id, session_id, execution_lane_id, occurred_at_us, ingested_at_us, source_kind, source_ref_json, payload_schema, payload_json, content_hash, causation_id, correlation_id, effective_config_hash, algorithm_revision FROM journal_events WHERE command_id = ?1 ORDER BY seq";
const SELECT_ALL_ROWS: &str = "SELECT seq, event_id, command_id, command_hash, ordinal, command_event_count, event_type, record_class, object_family, object_id, revision_id, project_id, repository_id, worktree_id, task_id, workstream_id, session_id, execution_lane_id, occurred_at_us, ingested_at_us, source_kind, source_ref_json, payload_schema, payload_json, content_hash, causation_id, correlation_id, effective_config_hash, algorithm_revision FROM journal_events ORDER BY seq";
const SELECT_PERSISTED_FRONTIER: &str = "SELECT seq FROM journal_events ORDER BY seq DESC LIMIT 1";
const SELECT_ROWS_AFTER: &str = "SELECT seq, event_id, command_id, command_hash, ordinal, command_event_count, event_type, record_class, object_family, object_id, revision_id, project_id, repository_id, worktree_id, task_id, workstream_id, session_id, execution_lane_id, occurred_at_us, ingested_at_us, source_kind, source_ref_json, payload_schema, payload_json, content_hash, causation_id, correlation_id, effective_config_hash, algorithm_revision FROM journal_events WHERE seq > ?1 ORDER BY seq";
const SELECT_ROWS_PAGE: &str = "SELECT seq, event_id, command_id, command_hash, ordinal, command_event_count, event_type, record_class, object_family, object_id, revision_id, project_id, repository_id, worktree_id, task_id, workstream_id, session_id, execution_lane_id, occurred_at_us, ingested_at_us, source_kind, source_ref_json, payload_schema, payload_json, content_hash, causation_id, correlation_id, effective_config_hash, algorithm_revision FROM journal_events WHERE seq > ?1 AND seq <= ?2 ORDER BY seq LIMIT 256";
const SELECT_BUDGET_PAGE: &str = "SELECT seq, event_id, command_id, command_hash, ordinal, command_event_count, event_type, record_class, object_family, object_id, revision_id, project_id, repository_id, worktree_id, task_id, workstream_id, session_id, execution_lane_id, occurred_at_us, ingested_at_us, source_kind, source_ref_json, payload_schema, payload_json, content_hash, causation_id, correlation_id, effective_config_hash, algorithm_revision FROM journal_events WHERE seq > ?1 AND seq <= ?2 AND occurred_at_us >= ?3 AND occurred_at_us < ?4 AND event_type IN ('job_state_v1', 'job_lease_v1', 'semantic_derivation_run_recorded_v1') ORDER BY seq LIMIT 256";

const INSERT_EVENT: &str = "\
INSERT INTO journal_events (\
seq, event_id, command_id, command_hash, ordinal, command_event_count, event_type, \
record_class, object_family, object_id, revision_id, project_id, repository_id, \
worktree_id, task_id, workstream_id, session_id, execution_lane_id, occurred_at_us, \
ingested_at_us, source_kind, source_ref_json, payload_schema, payload_json, \
content_hash, causation_id, correlation_id, effective_config_hash, algorithm_revision\
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29)";

const SELECT_OBJECT_ROWS: &str = "SELECT row_id, row_kind, row_class, object_family, object_kind, object_id, current_revision_id, lifecycle, epistemic, authority, publication_state, support_state, project_id, repository_id, worktree_id, task_id, workstream_id, session_id, payload_json, source_event_seq, projection_generation FROM object_rows ORDER BY row_id";
const SELECT_OBJECT_CHECKPOINT: &str = "SELECT row_id, row_kind, row_class, object_family, object_kind, object_id, current_revision_id, lifecycle, epistemic, authority, publication_state, support_state, project_id, repository_id, worktree_id, task_id, workstream_id, session_id, payload_json, source_event_seq, projection_generation FROM object_rows WHERE row_id = ?1";
const SELECT_BATCH_OBJECT_ROWS: &str = "SELECT o.row_id, o.row_kind, o.row_class, o.object_family, o.object_kind, o.object_id, o.current_revision_id, o.lifecycle, o.epistemic, o.authority, o.publication_state, o.support_state, o.project_id, o.repository_id, o.worktree_id, o.task_id, o.workstream_id, o.session_id, o.payload_json, o.source_event_seq, o.projection_generation FROM object_rows o JOIN projection_batch_ids b ON o.row_id = b.row_id";
const DELETE_ALL_REMOVED_OBJECTS: &str =
    "DELETE FROM object_rows WHERE row_id NOT IN (SELECT row_id FROM projection_batch_ids)";
const DELETE_FAMILY_REMOVED_OBJECTS: &str = "DELETE FROM object_rows WHERE object_kind = ?1 AND row_id NOT IN (SELECT row_id FROM projection_batch_ids)";
const SELECT_ROUTE_SCOPE_OBJECTS: &str = "SELECT row_id, row_kind, row_class, object_family, object_kind, object_id, current_revision_id, lifecycle, epistemic, authority, publication_state, support_state, project_id, repository_id, worktree_id, task_id, workstream_id, session_id, payload_json, source_event_seq, projection_generation FROM object_rows WHERE row_kind = 'data' AND ((object_kind IN (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) AND (task_id = ?11 OR repository_id = ?12 OR worktree_id = ?13)) OR object_kind = ?14) ORDER BY row_id";

const SELECT_RELATION_ROWS: &str = "SELECT row_id, relation_kind, source_id, target_id, source_event_seq, projection_generation FROM relation_rows ORDER BY row_id";
const SELECT_RELATION_CHECKPOINT: &str = "SELECT row_id, relation_kind, source_id, target_id, source_event_seq, projection_generation FROM relation_rows WHERE row_id = ?1";

/// The closed object_kind set ordinary Search needs for its route closure.
/// These are the same values the previous native predicate used; the query is
/// deliberately parametrised by task/repository/worktree plus this closed set
/// instead of growing a general SQL predicate language.
const NORMAL_SEARCH_ROUTE_SCOPE_KINDS: [&str; 10] = [
    "task",
    "workstream",
    "work_episode",
    "attempt",
    "atom_revision",
    "experiment_run",
    "work_artifact",
    "scenario",
    "work_binding",
    "result_evidence",
];
const NORMAL_SEARCH_ROUTE_GLOBAL_KIND: &str = "work_checkpoint";

/// Success proof for the physical SQLite state.  It binds the connection
/// incarnation, the externally observed `data_version`, every family's
/// successful commit epoch and the real committed checkpoints/generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SqliteStamp {
    pub incarnation: u64,
    pub data_version: i64,
    pub journal_epoch: u64,
    pub objects_epoch: u64,
    pub relations_epoch: u64,
    pub frontier: u64,
    pub object_checkpoint: u64,
    pub object_generation: u64,
    pub relation_checkpoint: u64,
}

/// Reconcile semantics preserved from the former native merge path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ObjectReconcile {
    pub recall: bool,
    pub core: bool,
    pub wiki: bool,
    pub procedure_effect: bool,
    pub all: bool,
}

/// Physical `(path, (device, inode))` identity of a held state file or root.
type HeldPathIdentity = (PathBuf, (u64, u64));

pub(crate) struct SqliteState {
    // Fields drop in declaration order: the connection closes before the
    // directory handle, and the sibling lock (owned by JournalWriter) is
    // released after this state.
    connection: Option<Connection>,
    path: PathBuf,
    directory_path: PathBuf,
    directory: File,
    file_identity: (u64, u64),
    incarnation: u64,
    data_version: i64,
    data_version_known: bool,
    journal_epoch: u64,
    objects_epoch: u64,
    relations_epoch: u64,
    frontier: u64,
    object_checkpoint: u64,
    object_generation: u64,
    relation_checkpoint: u64,
    poisoned: bool,
    #[cfg(test)]
    faults: Faults,
}

#[cfg(test)]
#[derive(Default)]
struct Faults {
    fail_after_first_insert: bool,
    fail_commit: bool,
}

impl SqliteState {
    /// Open (or create) the single physical database below `data_dir/store`.
    /// The caller must already own the store directory and writer lock.
    pub(crate) fn open(data_dir: &Path) -> Result<Self, StoreError> {
        // The state root itself must be the same private directory the writer
        // lock validated; opening store SQLite under a world-writable parent
        // must fail closed even when the child happens to be 0700.
        let data_root = fs::symlink_metadata(data_dir).map_err(|_| StoreError::Io)?;
        validate_data_root_metadata(&data_root)?;
        let directory_path = crate::connection::native_root(data_dir);
        match fs::symlink_metadata(&directory_path) {
            Ok(metadata) => validate_directory_metadata(&metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&directory_path)
                    .map_err(|_| StoreError::Io)?;
                File::open(data_dir)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| StoreError::Io)?;
            }
            Err(_) => return Err(StoreError::Io),
        }
        Self::open_in(directory_path)
    }

    /// Open (or create) the single physical database directly in an isolated
    /// native directory. The offline converter uses this for a candidate whose
    /// directory itself is the native store; no parent state root is involved.
    pub(crate) fn open_native(native_dir: &Path) -> Result<Self, StoreError> {
        let metadata = fs::symlink_metadata(native_dir).map_err(|_| StoreError::Io)?;
        validate_directory_metadata(&metadata)?;
        Self::open_in(native_dir.to_owned())
    }

    fn open_in(directory_path: PathBuf) -> Result<Self, StoreError> {
        let path = directory_path.join(SQLITE_FILE_NAME);
        let fresh_file = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_file_metadata(&metadata)?;
                for suffix in [WAL_FILE_SUFFIX, SHM_FILE_SUFFIX] {
                    match fs::symlink_metadata(sidecar_path(&path, suffix)) {
                        Ok(sidecar) => validate_file_metadata(&sidecar)?,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(_) => return Err(StoreError::Io),
                    }
                }
                false
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                for suffix in [WAL_FILE_SUFFIX, SHM_FILE_SUFFIX] {
                    match fs::symlink_metadata(sidecar_path(&path, suffix)) {
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        _ => return Err(StoreError::StoreCorrupt),
                    }
                }
                // SQLite inherits WAL/SHM modes from the database. Create it
                // privately before opening SQLite, not chmod after WAL writes.
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .and_then(|file| file.sync_all())
                    .map_err(|_| StoreError::Io)?;
                true
            }
            Err(_) => return Err(StoreError::Io),
        };
        let directory = File::open(&directory_path).map_err(|_| StoreError::Io)?;
        let directory_metadata = directory.metadata().map_err(|_| StoreError::Io)?;
        validate_directory_metadata(&directory_metadata)?;
        let directory_identity = (directory_metadata.dev(), directory_metadata.ino());
        let file_metadata = fs::symlink_metadata(&path).map_err(|_| StoreError::Io)?;
        validate_file_metadata(&file_metadata)?;
        let file_identity = (file_metadata.dev(), file_metadata.ino());
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| StoreError::Io)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|_| StoreError::Io)?;
        if !fresh_file {
            // The existing file's physical format identity is checked before
            // any write: an unexpected schema/format is rejected, never reset
            // or created over.
            let application_id: i64 = connection
                .pragma_query_value(None, "application_id", |row| row.get(0))
                .map_err(|_| StoreError::StoreCorrupt)?;
            if application_id != APPLICATION_ID {
                return Err(StoreError::StoreCorrupt);
            }
            let user_version: i64 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .map_err(|_| StoreError::StoreCorrupt)?;
            if user_version == 1 {
                return Err(StoreError::UpgradeRequired);
            }
            if user_version != USER_VERSION {
                return Err(StoreError::StoreCorrupt);
            }
        }
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|_| {
                if fresh_file {
                    StoreError::Io
                } else {
                    StoreError::StoreCorrupt
                }
            })?;
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(|_| StoreError::StoreCorrupt)?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::StoreCorrupt);
        }
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|_| StoreError::Io)?;
        let synchronous: i64 = connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(|_| StoreError::StoreCorrupt)?;
        if synchronous != 2 {
            return Err(StoreError::StoreCorrupt);
        }
        if fresh_file {
            // Physical format and all three tables publish in one transaction.
            let transaction = connection
                .unchecked_transaction()
                .map_err(|_| StoreError::Io)?;
            transaction
                .pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(|_| StoreError::Io)?;
            transaction
                .pragma_update(None, "user_version", USER_VERSION)
                .map_err(|_| StoreError::Io)?;
            transaction
                .execute(CREATE_JOURNAL_TABLE, [])
                .map_err(|_| StoreError::Io)?;
            transaction
                .execute(CREATE_OBJECTS_TABLE, [])
                .map_err(|_| StoreError::Io)?;
            transaction
                .execute(CREATE_RELATIONS_TABLE, [])
                .map_err(|_| StoreError::Io)?;
            transaction.commit().map_err(|_| StoreError::Io)?;
        } else {
            validate_physical_schema(&connection)?;
        }
        for suffix in [WAL_FILE_SUFFIX, SHM_FILE_SUFFIX] {
            match fs::symlink_metadata(sidecar_path(&path, suffix)) {
                Ok(metadata) => validate_file_metadata(&metadata)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(StoreError::Io),
            }
        }
        File::open(&directory_path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| StoreError::Io)?;

        let data_version: i64 = connection
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| StoreError::StoreCorrupt)?;
        let journal_index = read_startup_journal_index(&connection)?;
        let command_validation = (|| {
            for command_id in journal_index.commands.keys() {
                validate_complete_command(&read_command_rows(&connection, *command_id)?)?;
            }
            Ok(())
        })();
        revalidate_physical(&directory_path, directory_identity, &path, file_identity)?;
        let observed_data_version: i64 = connection
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| StoreError::StoreCorrupt)?;
        if observed_data_version != data_version {
            return Err(StoreError::StoreCorrupt);
        }
        command_validation?;
        let frontier = journal_index.frontier;
        let object_rows = read_object_rows(&connection)?;
        let (object_checkpoint, object_generation) =
            object_checkpoint_from_rows(&object_rows).unwrap_or((0, 0));
        let relation_rows = read_relation_rows(&connection)?;
        let relation_checkpoint = if relation_rows.is_empty() {
            0
        } else {
            crate::relations::checkpoint_from_rows(&relation_rows)?
        };
        let observed_data_version: i64 = connection
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| StoreError::StoreCorrupt)?;
        if observed_data_version != data_version {
            return Err(StoreError::StoreCorrupt);
        }
        let mut state = Self {
            connection: Some(connection),
            path,
            directory_path,
            directory,
            file_identity,
            incarnation: NEXT_INCARNATION.fetch_add(1, Ordering::Relaxed),
            data_version,
            data_version_known: true,
            journal_epoch: if journal_index.commands.is_empty() {
                0
            } else {
                1
            },
            objects_epoch: if object_rows.is_empty() { 0 } else { 1 },
            relations_epoch: if relation_rows.is_empty() { 0 } else { 1 },
            frontier,
            object_checkpoint,
            object_generation,
            relation_checkpoint,
            poisoned: false,
            #[cfg(test)]
            faults: Faults::default(),
        };
        state.observe()?;
        state.revalidate()?;
        Ok(state)
    }

    /// A cloneable handle for the projection workers that run inside the
    /// writer turn. Readers on their own connections use `StoreReadHandle`.
    pub(crate) fn handle(self) -> SqliteHandle {
        Arc::new(Mutex::new(self))
    }

    #[cfg(test)]
    pub(crate) fn poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) fn file_identity(&self) -> (u64, u64) {
        self.file_identity
    }

    pub(crate) fn stamp(&mut self) -> Result<SqliteStamp, StoreError> {
        self.ensure_usable()?;
        self.revalidate()?;
        self.observe()?;
        Ok(SqliteStamp {
            incarnation: self.incarnation,
            data_version: self.data_version,
            journal_epoch: self.journal_epoch,
            objects_epoch: self.objects_epoch,
            relations_epoch: self.relations_epoch,
            frontier: self.frontier,
            object_checkpoint: self.object_checkpoint,
            object_generation: self.object_generation,
            relation_checkpoint: self.relation_checkpoint,
        })
    }

    /// Compare a previously captured stamp against the live physical state.
    /// Any identity, external-commit, epoch or checkpoint difference fails
    /// closed; callers must not re-stamp their way past it.
    #[cfg(test)]
    pub(crate) fn validate_stamp(&mut self, stamp: &SqliteStamp) -> Result<(), StoreError> {
        let current = self.stamp()?;
        if current != *stamp {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Journal family
    // ------------------------------------------------------------------

    pub(crate) fn journal_epoch(&self) -> u64 {
        self.journal_epoch
    }

    pub(crate) fn objects_epoch(&self) -> u64 {
        self.objects_epoch
    }

    pub(crate) fn relations_epoch(&self) -> u64 {
        self.relations_epoch
    }

    pub(crate) fn rows(&self) -> Result<Vec<JournalRow>, StoreError> {
        self.with_connection(read_all_rows)
    }

    pub(crate) fn startup_journal_index(&self) -> Result<StartupJournalIndex, StoreError> {
        self.with_connection(read_startup_journal_index)
    }

    pub(crate) fn committed_rows(
        &self,
        command_id: CommandId,
    ) -> Result<Vec<JournalRow>, StoreError> {
        self.with_connection(|connection| read_command_rows(connection, command_id))
    }

    pub(crate) fn rows_after(&self, seq: u64) -> Result<Vec<JournalRow>, StoreError> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(SELECT_ROWS_AFTER)
                .map_err(|_| StoreError::StoreCorrupt)?;
            let mut queried = statement
                .query(params![seq.to_be_bytes().as_slice()])
                .map_err(|_| StoreError::StoreCorrupt)?;
            let mut rows = Vec::new();
            while let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? {
                rows.push(journal_row_from_sql(sql_row)?);
            }
            Ok(rows)
        })
    }

    pub(crate) fn rows_page(
        &self,
        after: u64,
        frontier: u64,
    ) -> Result<Vec<JournalRow>, StoreError> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(SELECT_ROWS_PAGE)
                .map_err(|_| StoreError::StoreCorrupt)?;
            let mut queried = statement
                .query(params![
                    after.to_be_bytes().as_slice(),
                    frontier.to_be_bytes().as_slice(),
                ])
                .map_err(|_| StoreError::StoreCorrupt)?;
            let mut rows = Vec::new();
            while let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? {
                rows.push(journal_row_from_sql(sql_row)?);
            }
            Ok(rows)
        })
    }

    /// Append one complete command in a single immediate transaction. This
    /// call is the caller's physical durability boundary: it returns only
    /// after COMMIT succeeded or poisons the handle for an uncertain result.
    pub(crate) fn append_command_rows(&mut self, rows: &[JournalRow]) -> Result<(), StoreError> {
        self.ensure_usable()?;
        self.revalidate()?;
        self.observe()?;
        if rows.is_empty() {
            return Err(StoreError::InvalidInput);
        }
        let last = rows.last().ok_or(StoreError::StoreCorrupt)?.seq;
        let first = rows.first().ok_or(StoreError::StoreCorrupt)?.seq;
        if first.checked_add(rows.len() as u64 - 1) != Some(last)
            || rows.windows(2).any(|pair| pair[0].seq >= pair[1].seq)
        {
            return Err(StoreError::StoreCorrupt);
        }
        #[cfg(test)]
        let fail_after_first_insert = self.faults.fail_after_first_insert;
        #[cfg(not(test))]
        let fail_after_first_insert = false;
        #[cfg(not(test))]
        let _ = fail_after_first_insert;
        #[cfg(test)]
        let fail_commit = self.faults.fail_commit;
        #[cfg(not(test))]
        let fail_commit = false;
        let (directory, file) = self.held_identity()?;
        let data_version = self.data_version;
        let data_version_known = self.data_version_known;
        let connection = self.connection.as_ref().ok_or(StoreError::Io)?;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| StoreError::Io)?;
        let mut poison = false;
        let outcome: Result<(), StoreError> = (|| {
            // The write lock is held now; re-check the real root, database and
            // sidecar identity plus this connection's external data_version
            // before the first physical change.
            revalidate_physical(&directory.0, directory.1, &file.0, file.1)?;
            let observed: i64 = connection
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| StoreError::StoreCorrupt)?;
            if !data_version_known || observed != data_version {
                return Err(StoreError::StoreCorrupt);
            }
            for (index, row) in rows.iter().enumerate() {
                #[cfg(test)]
                let injected = index == 0 && fail_after_first_insert;
                #[cfg(not(test))]
                let injected = {
                    let _ = index;
                    false
                };
                if injected {
                    return Err(StoreError::Io);
                }
                connection
                    .execute(
                        INSERT_EVENT,
                        params![
                            row.seq.to_be_bytes().as_slice(),
                            row.event_id,
                            row.command_id.to_string(),
                            row.command_hash.as_slice(),
                            row.ordinal,
                            row.command_event_count,
                            row.event_type,
                            row.record_class.as_str(),
                            row.object_family.map(|family| family.as_str()),
                            row.object_id,
                            row.revision_id,
                            row.scope.project_id,
                            row.scope.repository_id,
                            row.scope.worktree_id,
                            row.scope.task_id,
                            row.scope.workstream_id,
                            row.scope.session_id,
                            row.scope.execution_lane_id,
                            row.occurred_at_us,
                            row.ingested_at_us,
                            row.source_kind.as_str(),
                            row.source_ref_json,
                            row.payload_schema,
                            row.payload_json,
                            row.content_hash.as_slice(),
                            row.causation_id,
                            row.correlation_id,
                            row.effective_config_hash.as_slice(),
                            row.algorithm_revision,
                        ],
                    )
                    .map_err(precommit_error)?;
            }
            Ok(())
        })();
        match outcome {
            Ok(()) if fail_commit => {
                // Models an uncertain COMMIT outcome: the caller must treat the
                // ACK as lost, this handle is poisoned, and a reopened handle
                // decides the actual outcome through persisted replay.
                let _ = connection.execute_batch("ROLLBACK");
                poison = true;
            }
            Ok(()) => {
                if connection.execute_batch("COMMIT").is_err() {
                    poison = true;
                }
            }
            Err(error) => {
                let rollback = connection.execute_batch("ROLLBACK");
                if rollback.is_err() || !connection.is_autocommit() {
                    poison = true;
                } else {
                    return Err(error);
                }
            }
        }
        if poison {
            return Err(self.poison());
        }
        if self.after_commit().is_err() {
            return Err(self.poison());
        }
        self.journal_epoch = self.journal_epoch.saturating_add(1);
        self.frontier = last;
        Ok(())
    }

    /// Test-only fault injection: advance the persisted objects checkpoint
    /// Test-only fault injection: advance the persisted objects checkpoint
    /// without any projection, so consumers must detect the logical gap.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn advance_object_checkpoint_for_test(&mut self) -> Result<(), StoreError> {
        self.ensure_usable()?;
        let connection = self.connection.as_mut().ok_or(StoreError::Io)?;
        let changed = connection
            .execute(
                "UPDATE object_rows SET source_event_seq = ?1 WHERE row_id = ?2",
                params![
                    self.object_checkpoint
                        .saturating_add(1)
                        .to_be_bytes()
                        .as_slice(),
                    crate::objects::OBJECTS_CHECKPOINT_ID
                ],
            )
            .map_err(|_| StoreError::Io)?;
        if changed != 1 {
            return Err(StoreError::StoreCorrupt);
        }
        self.data_version_known = false;
        self.observe()?;
        self.object_checkpoint = self.object_checkpoint.saturating_add(1);
        Ok(())
    }

    /// Test-only fault injection: clear the objects family so the next open
    /// must rebuild it from the authoritative journal.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn clear_object_rows_for_test(&mut self) -> Result<(), StoreError> {
        self.ensure_usable()?;
        let connection = self.connection.as_mut().ok_or(StoreError::Io)?;
        let transaction = connection.transaction().map_err(|_| StoreError::Io)?;
        transaction
            .execute("DELETE FROM object_rows", [])
            .map_err(|_| StoreError::Io)?;
        transaction.commit().map_err(|_| StoreError::Io)?;
        self.data_version_known = false;
        self.observe()?;
        self.object_checkpoint = 0;
        self.object_generation = 0;
        Ok(())
    }

    /// Test-only fault injection: replace the persisted journal rows without
    /// any validation so consumers must detect the corruption themselves.
    #[cfg(test)]
    pub(crate) fn overwrite_rows_for_test(
        &mut self,
        rows: &[JournalRow],
    ) -> Result<(), StoreError> {
        self.ensure_usable()?;
        let connection = self.connection.as_mut().ok_or(StoreError::Io)?;
        let transaction = connection.transaction().map_err(|_| StoreError::Io)?;
        transaction
            .execute("DELETE FROM journal_events", [])
            .map_err(|_| StoreError::Io)?;
        for row in rows {
            transaction
                .execute(
                    INSERT_EVENT,
                    params![
                        row.seq.to_be_bytes().as_slice(),
                        row.event_id,
                        row.command_id.to_string(),
                        row.command_hash.as_slice(),
                        row.ordinal,
                        row.command_event_count,
                        row.event_type,
                        row.record_class.as_str(),
                        row.object_family.map(|family| family.as_str()),
                        row.object_id,
                        row.revision_id,
                        row.scope.project_id,
                        row.scope.repository_id,
                        row.scope.worktree_id,
                        row.scope.task_id,
                        row.scope.workstream_id,
                        row.scope.session_id,
                        row.scope.execution_lane_id,
                        row.occurred_at_us,
                        row.ingested_at_us,
                        row.source_kind.as_str(),
                        row.source_ref_json,
                        row.payload_schema,
                        row.payload_json,
                        row.content_hash.as_slice(),
                        row.causation_id,
                        row.correlation_id,
                        row.effective_config_hash.as_slice(),
                        row.algorithm_revision,
                    ],
                )
                .map_err(|_| StoreError::Io)?;
        }
        transaction.commit().map_err(|_| StoreError::Io)?;
        self.data_version_known = false;
        self.observe()?;
        self.frontier = rows.last().map(|row| row.seq).unwrap_or(0);
        Ok(())
    }

    /// Test-only raw append without structural or admission validation, so a
    /// caller can model a physical successor this writer never admitted.
    #[cfg(test)]
    pub(crate) fn append_rows_for_test(&mut self, rows: &[JournalRow]) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Err(StoreError::InvalidInput);
        }
        let mut combined = self.rows()?;
        combined.extend_from_slice(rows);
        combined.sort_by_key(|row| row.seq);
        self.overwrite_rows_for_test(&combined)?;
        self.journal_epoch = self.journal_epoch.saturating_add(1);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Objects family
    // ------------------------------------------------------------------

    pub(crate) fn object_rows(&self) -> Result<Vec<ObjectRow>, StoreError> {
        self.with_connection(read_object_rows)
    }

    #[cfg(test)]
    pub(crate) fn object_checkpoint(&self) -> (u64, u64) {
        (self.object_checkpoint, self.object_generation)
    }

    /// Test-only raw upsert of one object row without validation, so consumers
    /// must detect a malformed row themselves.
    #[cfg(test)]
    pub(crate) fn insert_object_row_for_test(&mut self, row: &ObjectRow) -> Result<(), StoreError> {
        self.ensure_usable()?;
        let connection = self.connection.as_mut().ok_or(StoreError::Io)?;
        let transaction = connection.transaction().map_err(|_| StoreError::Io)?;
        upsert_object_row(&transaction, row)?;
        transaction.commit().map_err(|_| StoreError::Io)?;
        self.data_version_known = false;
        self.observe()?;
        self.objects_epoch = self.objects_epoch.saturating_add(1);
        Ok(())
    }

    pub(crate) fn object_row_count(&self) -> Result<u64, StoreError> {
        self.with_connection(|connection| {
            connection
                .query_row("SELECT COUNT(*) FROM object_rows", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(|_| StoreError::StoreCorrupt)
                .and_then(|count| u64::try_from(count).map_err(|_| StoreError::StoreCorrupt))
        })
    }

    pub(crate) fn rows_until(&self, frontier: u64) -> Result<Vec<JournalRow>, StoreError> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare("SELECT seq, event_id, command_id, command_hash, ordinal, command_event_count, event_type, record_class, object_family, object_id, revision_id, project_id, repository_id, worktree_id, task_id, workstream_id, session_id, execution_lane_id, occurred_at_us, ingested_at_us, source_kind, source_ref_json, payload_schema, payload_json, content_hash, causation_id, correlation_id, effective_config_hash, algorithm_revision FROM journal_events WHERE seq <= ?1 ORDER BY seq")
                .map_err(|_| StoreError::StoreCorrupt)?;
            let mut queried = statement
                .query(params![frontier.to_be_bytes().as_slice()])
                .map_err(|_| StoreError::StoreCorrupt)?;
            let mut rows = Vec::new();
            while let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? {
                rows.push(journal_row_from_sql(sql_row)?);
            }
            Ok(rows)
        })
    }

    /// Lightweight diagnostics read of the checkpoint row only; it validates
    /// the row but never repairs the table.
    pub(crate) fn object_checkpoint_row(&self) -> Result<Option<(u64, u64)>, StoreError> {
        self.with_connection(read_object_checkpoint)
    }

    /// Lightweight diagnostics read of the relation checkpoint row only.
    pub(crate) fn relation_checkpoint_row(&self) -> Result<Option<(u64, u64)>, StoreError> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(SELECT_RELATION_CHECKPOINT)
                .map_err(|_| StoreError::StoreCorrupt)?;
            let mut queried = statement
                .query(params![RELATIONS_CHECKPOINT_ID])
                .map_err(|_| StoreError::StoreCorrupt)?;
            let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? else {
                return Ok(None);
            };
            let row = relation_row_from_sql(sql_row)?;
            row.validate()?;
            Ok(Some((row.source_event_seq, row.projection_generation)))
        })
    }

    /// The real production consumer of a filtered objects read: ordinary
    /// Search's bounded route closure. Named task/repository/worktree
    /// parameters plus a closed kind set, not a general predicate language.
    pub(crate) fn normal_search_route_scope_rows(
        &self,
        task_id: Option<evertrace_domain::ids::TaskId>,
        repository_id: Option<evertrace_domain::ids::RepositoryId>,
        worktree_id: Option<evertrace_domain::ids::WorktreeId>,
    ) -> Result<Vec<ObjectRow>, StoreError> {
        let task = task_id.map(|id| id.to_string());
        let repository = repository_id.map(|id| id.to_string());
        let worktree = worktree_id.map(|id| id.to_string());
        if task.is_none() && repository.is_none() && worktree.is_none() {
            return Ok(Vec::new());
        }
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(SELECT_ROUTE_SCOPE_OBJECTS)
                .map_err(|_| StoreError::StoreCorrupt)?;
            let mut queried = statement
                .query(params![
                    NORMAL_SEARCH_ROUTE_SCOPE_KINDS[0],
                    NORMAL_SEARCH_ROUTE_SCOPE_KINDS[1],
                    NORMAL_SEARCH_ROUTE_SCOPE_KINDS[2],
                    NORMAL_SEARCH_ROUTE_SCOPE_KINDS[3],
                    NORMAL_SEARCH_ROUTE_SCOPE_KINDS[4],
                    NORMAL_SEARCH_ROUTE_SCOPE_KINDS[5],
                    NORMAL_SEARCH_ROUTE_SCOPE_KINDS[6],
                    NORMAL_SEARCH_ROUTE_SCOPE_KINDS[7],
                    NORMAL_SEARCH_ROUTE_SCOPE_KINDS[8],
                    NORMAL_SEARCH_ROUTE_SCOPE_KINDS[9],
                    task,
                    repository,
                    worktree,
                    NORMAL_SEARCH_ROUTE_GLOBAL_KIND,
                ])
                .map_err(|_| StoreError::StoreCorrupt)?;
            let mut rows = Vec::new();
            while let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? {
                let row = object_row_from_sql(sql_row)?;
                row.validate()?;
                rows.push(row);
            }
            Ok(rows)
        })
    }

    /// Commit one objects projection delta. The batch contains every row the
    /// reconcile predicates protect (the existing reducer already includes the
    /// full touched family), the checkpoint row is always part of it, and the
    /// rows, deletions and checkpoint land in one transaction. A commit with
    /// no real row change does not advance the family epoch.
    pub(crate) fn commit_object_rows(
        &mut self,
        batch: &[ObjectRow],
        reconcile: ObjectReconcile,
        checkpoint: &ObjectRow,
    ) -> Result<(), StoreError> {
        self.ensure_usable()?;
        self.revalidate()?;
        self.observe()?;
        if batch.is_empty() || checkpoint.row_id != OBJECTS_CHECKPOINT_ID {
            return Err(StoreError::StoreCorrupt);
        }
        for row in batch {
            row.validate()?;
        }
        checkpoint.validate()?;
        let (directory, file) = self.held_identity()?;
        let data_version = self.data_version;
        let data_version_known = self.data_version_known;
        let connection = self.connection.as_ref().ok_or(StoreError::Io)?;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| StoreError::Io)?;
        let mut poison = false;
        let outcome: Result<bool, StoreError> = (|| {
            revalidate_physical(&directory.0, directory.1, &file.0, file.1)?;
            let observed: i64 = connection
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| StoreError::StoreCorrupt)?;
            if !data_version_known || observed != data_version {
                return Err(StoreError::StoreCorrupt);
            }
            begin_batch_table(connection)?;
            for row in batch {
                insert_batch_id(connection, &row.row_id)?;
            }
            let existing = {
                let mut statement = connection
                    .prepare(SELECT_BATCH_OBJECT_ROWS)
                    .map_err(|_| StoreError::StoreCorrupt)?;
                let mut queried = statement.query([]).map_err(|_| StoreError::StoreCorrupt)?;
                let mut rows = Vec::new();
                while let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? {
                    rows.push(object_row_from_sql(sql_row)?);
                }
                rows
            };
            let existing_by_id = existing
                .iter()
                .map(|row| (row.row_id.as_str(), row))
                .collect::<std::collections::BTreeMap<_, _>>();
            let mut changed = Vec::new();
            for row in batch {
                if existing_by_id.get(row.row_id.as_str()).copied() != Some(row) {
                    changed.push(row);
                }
            }
            let mut removed = 0_usize;
            if reconcile.all {
                removed += connection
                    .execute(DELETE_ALL_REMOVED_OBJECTS, [])
                    .map_err(|_| StoreError::StoreCorrupt)?;
            } else {
                for family in reconcile_families(&reconcile) {
                    removed += connection
                        .execute(DELETE_FAMILY_REMOVED_OBJECTS, params![family])
                        .map_err(|_| StoreError::StoreCorrupt)?;
                }
            }
            for row in &changed {
                upsert_object_row(connection, row)?;
            }
            end_batch_table(connection)?;
            Ok(changed.is_empty() && removed == 0)
        })();
        match outcome {
            Ok(true) => {
                // No physical delta: roll the empty bookkeeping transaction
                // back explicitly and leave the family epoch untouched.
                let rollback = connection.execute_batch("ROLLBACK");
                let autocommit = connection.is_autocommit();
                if rollback.is_err() || !autocommit {
                    return Err(self.poison());
                }
                return Ok(());
            }
            Ok(false) => {
                if connection.execute_batch("COMMIT").is_err() {
                    poison = true;
                }
            }
            Err(error) => {
                let rollback = connection.execute_batch("ROLLBACK");
                if rollback.is_err() || !connection.is_autocommit() {
                    poison = true;
                } else {
                    return Err(error);
                }
            }
        }
        if poison {
            return Err(self.poison());
        }
        if self.after_commit().is_err() {
            return Err(self.poison());
        }
        self.objects_epoch = self.objects_epoch.saturating_add(1);
        self.object_checkpoint = checkpoint.source_event_seq;
        self.object_generation = checkpoint.projection_generation;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Relations family
    // ------------------------------------------------------------------

    pub(crate) fn relation_rows(&self) -> Result<Vec<RelationProjectionRow>, StoreError> {
        self.with_connection(read_relation_rows)
    }

    #[cfg(test)]
    pub(crate) fn relation_checkpoint(&self) -> u64 {
        self.relation_checkpoint
    }

    pub(crate) fn commit_relation_rows(
        &mut self,
        changed: &[RelationProjectionRow],
        removed: &[String],
        checkpoint: &RelationProjectionRow,
    ) -> Result<(), StoreError> {
        self.ensure_usable()?;
        self.revalidate()?;
        self.observe()?;
        if checkpoint.row_id != RELATIONS_CHECKPOINT_ID {
            return Err(StoreError::StoreCorrupt);
        }
        for row in changed {
            row.validate()?;
        }
        checkpoint.validate()?;
        let (directory, file) = self.held_identity()?;
        let data_version = self.data_version;
        let data_version_known = self.data_version_known;
        let connection = self.connection.as_ref().ok_or(StoreError::Io)?;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| StoreError::Io)?;
        let mut poison = false;
        let outcome: Result<bool, StoreError> = (|| {
            revalidate_physical(&directory.0, directory.1, &file.0, file.1)?;
            let observed: i64 = connection
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| StoreError::StoreCorrupt)?;
            if !data_version_known || observed != data_version {
                return Err(StoreError::StoreCorrupt);
            }
            for row in changed {
                upsert_relation_row(connection, row)?;
            }
            for row_id in removed {
                connection
                    .execute(
                        "DELETE FROM relation_rows WHERE row_id = ?1",
                        params![row_id],
                    )
                    .map_err(|_| StoreError::StoreCorrupt)?;
            }
            Ok(changed.is_empty() && removed.is_empty())
        })();
        match outcome {
            Ok(true) => {
                // No physical delta: roll the empty transaction back
                // explicitly and leave the family epoch untouched.
                let rollback = connection.execute_batch("ROLLBACK");
                let autocommit = connection.is_autocommit();
                if rollback.is_err() || !autocommit {
                    return Err(self.poison());
                }
                return Ok(());
            }
            Ok(false) => {
                if connection.execute_batch("COMMIT").is_err() {
                    poison = true;
                }
            }
            Err(error) => {
                let rollback = connection.execute_batch("ROLLBACK");
                if rollback.is_err() || !connection.is_autocommit() {
                    poison = true;
                } else {
                    return Err(error);
                }
            }
        }
        if poison {
            return Err(self.poison());
        }
        if self.after_commit().is_err() {
            return Err(self.poison());
        }
        self.relations_epoch = self.relations_epoch.saturating_add(1);
        self.relation_checkpoint = checkpoint.source_event_seq;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Lifecycle and identity
    // ------------------------------------------------------------------

    /// WAL checkpoint followed by an actual connection close. Used by the
    /// quiesced backup path before the caller copies the closed database file.
    ///
    /// `Ok(true)` is a confirmed physical close; `Ok(false)` is SQLite's
    /// explicit busy result and leaves the connection, WAL and state untouched
    /// so a later backup can retry. Real checkpoint/close/identity errors stay
    /// `Err` and fail closed; an unknown failure is never reported as busy.
    pub(crate) fn checkpoint_and_close(&mut self) -> Result<bool, StoreError> {
        if self.poisoned {
            return Err(StoreError::Io);
        }
        self.revalidate()?;
        self.observe()?;
        let connection = self.connection.as_ref().ok_or(StoreError::Io)?;
        let (busy, _log, _checkpointed): (i64, i64, i64) = connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|_| StoreError::Io)?;
        // Checkpointing does not authorize another connection's changes. In
        // particular, do not close/reopen and re-stamp an external commit.
        self.observe()?;
        if busy != 0 {
            return Ok(false);
        }
        let connection = self.connection.take().ok_or(StoreError::Io)?;
        connection.close().map_err(|_| StoreError::Io)?;
        self.revalidate()?;
        Ok(true)
    }

    /// Terminal actor close: invalidate the state and drop the actual SQLite
    /// connection without requiring a WAL checkpoint, so a third-party reader
    /// that keeps the WAL busy cannot block actor shutdown. The invalidation
    /// also stops any cloned `ProjectionWorker` handle from writing after the
    /// connection is gone.
    pub(crate) fn close_connection(&mut self) -> Result<(), StoreError> {
        self.poisoned = true;
        let connection = self.connection.take().ok_or(StoreError::Io)?;
        connection.close().map_err(|_| StoreError::Io)
    }

    pub(crate) fn has_open_connection(&self) -> bool {
        self.connection.is_some()
    }

    fn with_connection<T>(
        &self,
        read: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.ensure_usable()?;
        self.revalidate()?;
        let connection = self.connection.as_ref().ok_or(StoreError::Io)?;
        let check_external_commit = || {
            let data_version: i64 = connection
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| StoreError::StoreCorrupt)?;
            if !self.data_version_known || data_version != self.data_version {
                return Err(StoreError::StoreCorrupt);
            }
            Ok(())
        };
        check_external_commit()?;
        let result = read(connection);
        self.revalidate()?;
        check_external_commit()?;
        result
    }

    fn ensure_usable(&self) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::Io);
        }
        Ok(())
    }

    /// Observe `PRAGMA data_version` on the writer connection.  Only another
    /// connection's committed changes move it (never this connection's own
    /// commits), so any unexpected move is an external commit and fails
    /// closed.  The handle poisons itself and requires a reopen.
    fn observe(&mut self) -> Result<(), StoreError> {
        let connection = self.connection.as_ref().ok_or(StoreError::Io)?;
        let data_version: i64 = connection
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| StoreError::StoreCorrupt)?;
        if self.data_version_known && data_version != self.data_version {
            self.poisoned = true;
            self.connection = None;
            return Err(StoreError::StoreCorrupt);
        }
        self.data_version = data_version;
        self.data_version_known = true;
        Ok(())
    }

    fn after_commit(&mut self) -> Result<(), StoreError> {
        self.revalidate()?;
        let connection = self.connection.as_ref().ok_or(StoreError::Io)?;
        let data_version: i64 = connection
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| StoreError::StoreCorrupt)?;
        if data_version != self.data_version {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    /// An uncertain result invalidates the handle: close the connection and
    /// refuse all further reuse. The caller must reopen and resubmit the same
    /// complete command ID so persisted replay can decide the real outcome.
    fn poison(&mut self) -> StoreError {
        self.poisoned = true;
        drop(self.connection.take());
        StoreError::Io
    }

    /// Hold the store directory identity and re-check root, main file and
    /// WAL/SHM types before accepting a command and after committing.
    pub(crate) fn revalidate(&self) -> Result<(), StoreError> {
        let held = self.directory.metadata().map_err(|_| StoreError::Io)?;
        revalidate_physical(
            &self.directory_path,
            (held.dev(), held.ino()),
            &self.path,
            self.file_identity,
        )
    }

    /// The physical identity of this state as a value, so a write transaction
    /// can re-check it after the database write lock is already held without
    /// borrowing the state along with its connection.
    fn held_identity(&self) -> Result<(HeldPathIdentity, HeldPathIdentity), StoreError> {
        let held = self.directory.metadata().map_err(|_| StoreError::Io)?;
        Ok((
            (self.directory_path.clone(), (held.dev(), held.ino())),
            (self.path.clone(), self.file_identity),
        ))
    }
}

fn revalidate_physical(
    directory_path: &Path,
    directory_identity: (u64, u64),
    path: &Path,
    file_identity: (u64, u64),
) -> Result<(), StoreError> {
    let located = fs::symlink_metadata(directory_path).map_err(|_| StoreError::Io)?;
    validate_directory_metadata(&located)?;
    if !located.is_dir()
        || located.file_type().is_symlink()
        || (located.dev(), located.ino()) != directory_identity
    {
        return Err(StoreError::StoreCorrupt);
    }
    let file = fs::symlink_metadata(path).map_err(|_| StoreError::StoreCorrupt)?;
    validate_file_metadata(&file)?;
    if (file.dev(), file.ino()) != file_identity {
        return Err(StoreError::StoreCorrupt);
    }
    for suffix in [WAL_FILE_SUFFIX, SHM_FILE_SUFFIX] {
        match fs::symlink_metadata(sidecar_path(path, suffix)) {
            Ok(sidecar) => validate_file_metadata(&sidecar)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Io),
        }
    }
    Ok(())
}

fn reconcile_families(reconcile: &ObjectReconcile) -> Vec<&'static str> {
    let mut families = Vec::new();
    if reconcile.recall {
        families.push(crate::projections::RECALL_TRIGGER_INDEX_KIND);
    }
    if reconcile.core {
        families.push(crate::projections::CORE_INDEX_KIND);
    }
    if reconcile.wiki {
        families.push(crate::projections::WIKI_INDEX_KIND);
    }
    if reconcile.procedure_effect {
        families.push("procedure_context_effect");
    }
    families
}

fn begin_batch_table(transaction: &Connection) -> Result<(), StoreError> {
    transaction
        .execute(
            "CREATE TEMP TABLE IF NOT EXISTS projection_batch_ids (row_id TEXT PRIMARY KEY) WITHOUT ROWID",
            [],
        )
        .map_err(|_| StoreError::Io)?;
    transaction
        .execute("DELETE FROM projection_batch_ids", [])
        .map_err(|_| StoreError::Io)?;
    Ok(())
}

fn end_batch_table(transaction: &Connection) -> Result<(), StoreError> {
    transaction
        .execute("DELETE FROM projection_batch_ids", [])
        .map_err(|_| StoreError::Io)?;
    Ok(())
}

fn insert_batch_id(transaction: &Connection, row_id: &str) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT OR IGNORE INTO projection_batch_ids (row_id) VALUES (?1)",
            params![row_id],
        )
        .map_err(|_| StoreError::Io)?;
    Ok(())
}

fn upsert_object_row(transaction: &Connection, row: &ObjectRow) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO object_rows (row_id, row_kind, row_class, object_family, object_kind, object_id, \
             current_revision_id, lifecycle, epistemic, authority, publication_state, support_state, \
             project_id, repository_id, worktree_id, task_id, workstream_id, session_id, payload_json, \
             source_event_seq, projection_generation) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21) \
             ON CONFLICT(row_id) DO UPDATE SET row_kind = excluded.row_kind, row_class = excluded.row_class, \
             object_family = excluded.object_family, object_kind = excluded.object_kind, object_id = excluded.object_id, \
             current_revision_id = excluded.current_revision_id, lifecycle = excluded.lifecycle, epistemic = excluded.epistemic, \
             authority = excluded.authority, publication_state = excluded.publication_state, support_state = excluded.support_state, \
             project_id = excluded.project_id, repository_id = excluded.repository_id, worktree_id = excluded.worktree_id, \
             task_id = excluded.task_id, workstream_id = excluded.workstream_id, session_id = excluded.session_id, \
             payload_json = excluded.payload_json, source_event_seq = excluded.source_event_seq, \
             projection_generation = excluded.projection_generation",
            params![
                row.row_id,
                row.row_kind.as_str(),
                row.row_class.map(ObjectRowClass::as_str),
                row.object_family.map(ObjectFamily::as_str),
                row.object_kind,
                row.object_id,
                row.current_revision_id,
                row.lifecycle,
                row.epistemic,
                row.authority,
                row.publication_state,
                row.support_state,
                row.project_id,
                row.repository_id,
                row.worktree_id,
                row.task_id,
                row.workstream_id,
                row.session_id,
                row.payload_json,
                row.source_event_seq.to_be_bytes().as_slice(),
                row.projection_generation.to_be_bytes().as_slice(),
            ],
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
    Ok(())
}

fn upsert_relation_row(
    transaction: &Connection,
    row: &RelationProjectionRow,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO relation_rows (row_id, relation_kind, source_id, target_id, source_event_seq, projection_generation) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(row_id) DO UPDATE SET relation_kind = excluded.relation_kind, source_id = excluded.source_id, \
             target_id = excluded.target_id, source_event_seq = excluded.source_event_seq, \
             projection_generation = excluded.projection_generation",
            params![
                row.row_id,
                row.relation_kind,
                row.source_id,
                row.target_id,
                row.source_event_seq.to_be_bytes().as_slice(),
                row.projection_generation.to_be_bytes().as_slice(),
            ],
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
    Ok(())
}

/// Errors raised while statements run inside the transaction are known
/// rollbacks: nothing published, the connection stays coherent, and the
/// reservation remains a legal gap. They never preempt the domain error
/// precedence enforced before insertion.
fn precommit_error(error: rusqlite::Error) -> StoreError {
    match error {
        rusqlite::Error::SqliteFailure(error, _)
            if error.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            StoreError::StoreCorrupt
        }
        _ => StoreError::Io,
    }
}

/// Validated physical contents of one isolated store directory as read by a
/// short read-only connection. Used by backup/restore verification so the
/// copy is never opened as a writer.
pub(crate) struct VerifiedSqliteState {
    pub(crate) rows: Vec<JournalRow>,
    pub(crate) objects: Vec<ObjectRow>,
    pub(crate) object_checkpoint: (u64, u64),
    pub(crate) relations: Vec<RelationProjectionRow>,
    pub(crate) relation_checkpoint: (u64, u64),
}

pub(crate) fn verify_store_database(native_dir: &Path) -> Result<VerifiedSqliteState, StoreError> {
    evertrace_capture::ConfinedRoot::open_owned_private(native_dir)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let path = native_dir.join(SQLITE_FILE_NAME);
    let metadata = fs::symlink_metadata(&path).map_err(|_| StoreError::Io)?;
    validate_file_metadata(&metadata)?;
    // A verified copy is closed and checkpointed: any WAL/SHM sidecar means the
    // caller did not quiesce the store and this read must not silently fall
    // back to the main file.
    for suffix in ["-wal", "-shm"] {
        match fs::symlink_metadata(native_dir.join(format!("{SQLITE_FILE_NAME}{suffix}"))) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(StoreError::StoreCorrupt),
            Err(_) => return Err(StoreError::Io),
        }
    }
    // Open the closed copy immutably so verification never creates WAL/SHM
    // bookkeeping that the file manifest and its recorded identities do not
    // list.
    let mut uri = String::from("file:");
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in path.as_os_str().as_encoded_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'.' | b'_' | b'~') {
            uri.push(char::from(byte));
        } else {
            uri.push('%');
            uri.push(char::from(HEX[usize::from(byte >> 4)]));
            uri.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    uri.push_str("?immutable=1");
    let connection = Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|_| StoreError::Io)?;
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(|_| StoreError::Io)?;
    validate_read_header(&connection)?;
    let rows = read_all_rows(&connection)?;
    validate_journal_rows(&rows)?;
    let objects = read_object_rows(&connection)?;
    let object_checkpoint = object_checkpoint_from_rows(&objects)?;
    let relations = read_relation_rows(&connection)?;
    let relation_checkpoint = if relations.is_empty() {
        (0, 0)
    } else {
        let row = relations
            .iter()
            .find(|row| row.row_id == RELATIONS_CHECKPOINT_ID)
            .ok_or(StoreError::StoreCorrupt)?;
        (row.source_event_seq, row.projection_generation)
    };
    Ok(VerifiedSqliteState {
        rows,
        objects,
        object_checkpoint,
        relations,
        relation_checkpoint,
    })
}

/// Validate the physical header on a short read-only connection before using
/// it; a foreign or old isolated file must never be read as this layout.
pub(crate) fn validate_read_header(connection: &Connection) -> Result<(), StoreError> {
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| StoreError::StoreCorrupt)?;
    if application_id != APPLICATION_ID {
        return Err(StoreError::StoreCorrupt);
    }
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| StoreError::StoreCorrupt)?;
    if user_version == 1 {
        return Err(StoreError::UpgradeRequired);
    }
    if user_version != USER_VERSION {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

/// The persisted committed frontier as seen by one read-only connection.
pub(crate) fn read_persisted_frontier(connection: &Connection) -> Result<u64, StoreError> {
    validate_read_header(connection)?;
    let blob = connection
        .query_row(SELECT_PERSISTED_FRONTIER, [], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .optional()
        .map_err(|_| StoreError::StoreCorrupt)?;
    blob.as_deref()
        .map(seq_from_blob)
        .transpose()
        .map(|seq| seq.unwrap_or(0))
}

/// One bounded LLM budget page from a read-only connection at a fixed upper
/// bound. The caller's first read transaction fixes that bound.
pub(crate) fn read_budget_page(
    connection: &Connection,
    day_start_us: i64,
    after: u64,
    upper: u64,
) -> Result<Vec<JournalRow>, StoreError> {
    let day_end_us = day_start_us.saturating_add(86_400_000_000);
    let mut statement = connection
        .prepare(SELECT_BUDGET_PAGE)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut queried = statement
        .query(params![
            after.to_be_bytes().as_slice(),
            upper.to_be_bytes().as_slice(),
            day_start_us,
            day_end_us,
        ])
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut rows = Vec::new();
    while let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? {
        rows.push(journal_row_from_sql(sql_row)?);
    }
    Ok(rows)
}

pub(crate) fn read_all_rows(connection: &Connection) -> Result<Vec<JournalRow>, StoreError> {
    let mut statement = connection
        .prepare(SELECT_ALL_ROWS)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut queried = statement.query([]).map_err(|_| StoreError::StoreCorrupt)?;
    let mut rows = Vec::new();
    while let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? {
        rows.push(journal_row_from_sql(sql_row)?);
    }
    Ok(rows)
}

fn read_startup_journal_index(connection: &Connection) -> Result<StartupJournalIndex, StoreError> {
    let mut statement = connection
        .prepare(SELECT_ALL_ROWS)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut queried = statement.query([]).map_err(|_| StoreError::StoreCorrupt)?;
    let mut index = StartupJournalIndex {
        commands: BTreeMap::new(),
        frontier: 0,
    };
    let mut previous_seq = None;
    let mut invalid_sequence_order = false;
    while let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? {
        let row = journal_row_from_sql(sql_row)?;
        invalid_sequence_order |= previous_seq.is_some_and(|seq| seq >= row.seq);
        previous_seq = Some(row.seq);
        index.frontier = row.seq;
        index
            .commands
            .entry(row.command_id)
            .or_default()
            .push((row.ordinal, row.seq));
    }
    if invalid_sequence_order {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(index)
}

fn read_command_rows(
    connection: &Connection,
    command_id: CommandId,
) -> Result<Vec<JournalRow>, StoreError> {
    let mut statement = connection
        .prepare(SELECT_COMMAND_ROWS)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut queried = statement
        .query(params![command_id.to_string()])
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut rows = Vec::new();
    while let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? {
        rows.push(journal_row_from_sql(sql_row)?);
    }
    Ok(rows)
}

fn read_object_rows(connection: &Connection) -> Result<Vec<ObjectRow>, StoreError> {
    let mut statement = connection
        .prepare(SELECT_OBJECT_ROWS)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut queried = statement.query([]).map_err(|_| StoreError::StoreCorrupt)?;
    let mut rows = Vec::new();
    while let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? {
        let row = object_row_from_sql(sql_row)?;
        row.validate()?;
        rows.push(row);
    }
    rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    Ok(rows)
}

pub(crate) fn object_checkpoint_from_rows(rows: &[ObjectRow]) -> Result<(u64, u64), StoreError> {
    let frontier = crate::objects::checkpoint_from_rows(rows)?;
    let checkpoint = rows
        .iter()
        .find(|row| row.row_id == OBJECTS_CHECKPOINT_ID)
        .ok_or(StoreError::StoreCorrupt)?;
    Ok((frontier, checkpoint.projection_generation))
}

fn read_relation_rows(connection: &Connection) -> Result<Vec<RelationProjectionRow>, StoreError> {
    let mut statement = connection
        .prepare(SELECT_RELATION_ROWS)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut queried = statement.query([]).map_err(|_| StoreError::StoreCorrupt)?;
    let mut rows = Vec::new();
    while let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? {
        let row = relation_row_from_sql(sql_row)?;
        row.validate()?;
        rows.push(row);
    }
    rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    Ok(rows)
}

pub(crate) fn read_object_checkpoint(
    connection: &Connection,
) -> Result<Option<(u64, u64)>, StoreError> {
    let mut statement = connection
        .prepare(SELECT_OBJECT_CHECKPOINT)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut queried = statement
        .query(params![OBJECTS_CHECKPOINT_ID])
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut rows = Vec::new();
    while let Some(sql_row) = queried.next().map_err(|_| StoreError::StoreCorrupt)? {
        let row = object_row_from_sql(sql_row)?;
        row.validate()?;
        rows.push(row);
    }
    if rows.is_empty() {
        return Ok(None);
    }
    let (frontier, generation) = object_checkpoint_from_rows(&rows)?;
    Ok(Some((frontier, generation)))
}

fn journal_row_from_sql(row: &Row<'_>) -> Result<JournalRow, StoreError> {
    let seq: Vec<u8> = sql_value(row, 0)?;
    let command_id: String = sql_value(row, 2)?;
    let record_class: String = sql_value(row, 7)?;
    let source_kind: String = sql_value(row, 20)?;
    let object_family: Option<String> = sql_value(row, 8)?;
    Ok(JournalRow {
        seq: seq_from_blob(&seq)?,
        event_id: sql_value(row, 1)?,
        command_id: command_id.parse().map_err(|_| StoreError::StoreCorrupt)?,
        command_hash: fixed_hash(row, 3)?,
        ordinal: smallint(row, 4)?,
        command_event_count: smallint(row, 5)?,
        event_type: sql_value(row, 6)?,
        record_class: RecordClass::parse(&record_class)?,
        object_family: object_family
            .as_deref()
            .map(ObjectFamily::parse)
            .transpose()?,
        object_id: optional_text(row, 9)?,
        revision_id: optional_text(row, 10)?,
        scope: crate::command::EventScope {
            project_id: optional_text(row, 11)?,
            repository_id: optional_text(row, 12)?,
            worktree_id: optional_text(row, 13)?,
            task_id: optional_text(row, 14)?,
            workstream_id: optional_text(row, 15)?,
            session_id: optional_text(row, 16)?,
            execution_lane_id: optional_text(row, 17)?,
        },
        occurred_at_us: sql_value(row, 18)?,
        ingested_at_us: sql_value(row, 19)?,
        source_kind: SourceKind::parse(&source_kind)?,
        source_ref_json: optional_text(row, 21)?,
        payload_schema: smallint(row, 22)?,
        payload_json: sql_value(row, 23)?,
        content_hash: fixed_hash(row, 24)?,
        causation_id: optional_text(row, 25)?,
        correlation_id: optional_text(row, 26)?,
        effective_config_hash: fixed_hash(row, 27)?,
        algorithm_revision: sql_value(row, 28)?,
    })
}

fn object_row_from_sql(row: &Row<'_>) -> Result<ObjectRow, StoreError> {
    let row_id: String = sql_value(row, 0)?;
    let row_kind: String = sql_value(row, 1)?;
    let row_class: Option<String> = sql_value(row, 2)?;
    let object_family: Option<String> = sql_value(row, 3)?;
    Ok(ObjectRow {
        row_id,
        row_kind: ObjectRowKind::parse(&row_kind)?,
        row_class: row_class
            .as_deref()
            .map(ObjectRowClass::parse)
            .transpose()?,
        object_family: object_family
            .as_deref()
            .map(ObjectFamily::parse)
            .transpose()?,
        object_kind: optional_text(row, 4)?,
        object_id: optional_text(row, 5)?,
        current_revision_id: optional_text(row, 6)?,
        lifecycle: optional_text(row, 7)?,
        epistemic: optional_text(row, 8)?,
        authority: optional_text(row, 9)?,
        publication_state: optional_text(row, 10)?,
        support_state: optional_text(row, 11)?,
        project_id: optional_text(row, 12)?,
        repository_id: optional_text(row, 13)?,
        worktree_id: optional_text(row, 14)?,
        task_id: optional_text(row, 15)?,
        workstream_id: optional_text(row, 16)?,
        session_id: optional_text(row, 17)?,
        payload_json: optional_text(row, 18)?,
        source_event_seq: seq_from_blob(&sql_value::<Vec<u8>>(row, 19)?)?,
        projection_generation: seq_from_blob(&sql_value::<Vec<u8>>(row, 20)?)?,
    })
}

fn relation_row_from_sql(row: &Row<'_>) -> Result<RelationProjectionRow, StoreError> {
    Ok(RelationProjectionRow {
        row_id: sql_value(row, 0)?,
        relation_kind: optional_text(row, 1)?,
        source_id: optional_text(row, 2)?,
        target_id: optional_text(row, 3)?,
        source_event_seq: seq_from_blob(&sql_value::<Vec<u8>>(row, 4)?)?,
        projection_generation: seq_from_blob(&sql_value::<Vec<u8>>(row, 5)?)?,
    })
}

fn sql_value<T: rusqlite::types::FromSql>(row: &Row<'_>, index: usize) -> Result<T, StoreError> {
    row.get(index).map_err(|_| StoreError::StoreCorrupt)
}

fn optional_text(row: &Row<'_>, index: usize) -> Result<Option<String>, StoreError> {
    sql_value(row, index)
}

fn fixed_hash<const N: usize>(row: &Row<'_>, index: usize) -> Result<[u8; N], StoreError> {
    let blob: Vec<u8> = sql_value(row, index)?;
    blob.as_slice()
        .try_into()
        .map_err(|_| StoreError::StoreCorrupt)
}

fn smallint(row: &Row<'_>, index: usize) -> Result<u16, StoreError> {
    let value: i64 = sql_value(row, index)?;
    u16::try_from(value).map_err(|_| StoreError::StoreCorrupt)
}

pub(crate) fn seq_from_blob(blob: &[u8]) -> Result<u64, StoreError> {
    let bytes: [u8; 8] = blob.try_into().map_err(|_| StoreError::StoreCorrupt)?;
    Ok(u64::from_be_bytes(bytes))
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", path.display()))
}

fn current_uid() -> Result<u32, StoreError> {
    fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .map_err(|_| StoreError::Io)
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

fn validate_directory_metadata(metadata: &fs::Metadata) -> Result<(), StoreError> {
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

fn validate_file_metadata(metadata: &fs::Metadata) -> Result<(), StoreError> {
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

fn validate_physical_schema(connection: &Connection) -> Result<(), StoreError> {
    // Physical format has one definition. Column-only checks miss removed
    // UNIQUE/CHECK constraints and unexpected triggers that can drop writes.
    for (name, expected) in [
        ("journal_events", CREATE_JOURNAL_TABLE),
        ("object_rows", CREATE_OBJECTS_TABLE),
        ("relation_rows", CREATE_RELATIONS_TABLE),
    ] {
        let schema: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                params![name],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
        if schema != expected {
            return Err(StoreError::StoreCorrupt);
        }
    }
    let unexpected: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT IN ('journal_events', 'object_rows', 'relation_rows'))",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
    if unexpected {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs::Permissions, os::unix::fs::symlink};

    use super::*;
    use crate::{
        command::{
            DirtyTarget, DirtyTargetKind, JournalCommand, JournalEventDraft, JournalPayload,
            WatermarkAdvanced, WatermarkKind, prepare_command,
        },
        journal::rows_for_append,
        relations::RelationProjectionRow,
    };

    const COMMAND_A: &str = "01890f47-6a4a-7cc1-98b9-01890f476a4a";
    const COMMAND_B: &str = "01890f47-6a4a-7cc1-98b9-01890f476a4b";
    const COMMAND_C: &str = "01890f47-6a4a-7cc1-98b9-01890f476a4c";

    fn dirty_target_event(occurred_at_us: i64, label: &str) -> JournalEventDraft {
        JournalEventDraft::runtime(
            occurred_at_us,
            [1; 32],
            "objects-v1",
            JournalPayload::DirtyTarget(DirtyTarget {
                target_kind: DirtyTargetKind::ObjectsProjection,
                target_id: label.into(),
                algorithm_revision: "objects-v1".into(),
                source_watermark: 1,
            }),
        )
    }

    fn single_event_command(command_id: &str, label: &str) -> JournalCommand {
        JournalCommand::new(
            command_id.parse().unwrap(),
            vec![dirty_target_event(1, label)],
        )
        .unwrap()
    }

    fn multi_event_command(command_id: &str) -> JournalCommand {
        JournalCommand::new(
            command_id.parse().unwrap(),
            vec![
                dirty_target_event(1, "multi-a"),
                JournalEventDraft::runtime(
                    2,
                    [2; 32],
                    "watermark-v1",
                    JournalPayload::WatermarkAdvanced(WatermarkAdvanced {
                        kind: WatermarkKind::ObjectsProjection,
                        value: 7,
                    }),
                ),
                dirty_target_event(3, "multi-b"),
            ],
        )
        .unwrap()
    }

    fn committed_rows_for(command: &JournalCommand, first_seq: u64) -> Vec<JournalRow> {
        rows_for_append(&prepare_command(command).unwrap(), first_seq, 1).unwrap()
    }

    fn initialized_state() -> (tempfile::TempDir, PathBuf, SqliteState, JournalCommand) {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        fs::set_permissions(&data_dir, Permissions::from_mode(0o700)).unwrap();
        let mut state = SqliteState::open(&data_dir).unwrap();
        // A fresh physical store has no marker yet; give objects/relations
        // their initial checkpoints exactly like L0001/L0002 do.
        state
            .commit_object_rows(
                &[ObjectRow::checkpoint(0, 1)],
                ObjectReconcile::default(),
                &ObjectRow::checkpoint(0, 1),
            )
            .unwrap();
        state
            .commit_relation_rows(
                &[RelationProjectionRow::checkpoint(0)],
                &[],
                &RelationProjectionRow::checkpoint(0),
            )
            .unwrap();
        let command = multi_event_command(COMMAND_A);
        (temp, data_dir, state, command)
    }

    fn database_path(data_dir: &Path) -> PathBuf {
        crate::connection::native_root(data_dir).join(SQLITE_FILE_NAME)
    }

    #[tokio::test]
    async fn actual_writer_commit_io_probe() {
        // Run normally first; a separate strace diagnostic injects a syscall
        // error at this command's observed COMMIT sync, not a mocked SQL flag.
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let mut writer = crate::JournalWriter::open(&data_dir).await.unwrap();
        let start = writer.frontier();
        let baseline = writer.journal_rows().await.unwrap();
        let command = multi_event_command(COMMAND_A);
        eprintln!("actual writer IO probe: command commit begins");
        let result = writer.commit(&command, 42).await;
        match result {
            Ok(outcome) => {
                eprintln!("actual writer IO probe: commit acknowledged");
                assert!(!outcome.replayed);
                assert_eq!(outcome.last_seq, start + 3);
                assert_eq!(writer.frontier(), start + 3);
            }
            Err(error) => {
                eprintln!("actual writer IO probe: commit failed without ACK");
                assert_eq!(error, StoreError::Io);
                assert_eq!(writer.frontier(), start);
                assert_eq!(writer.journal_rows().await.err(), Some(StoreError::Io));
                assert_eq!(
                    writer.commit(&command, 43).await.err(),
                    Some(StoreError::Io)
                );
            }
        }
        drop(writer);

        let mut reopened = crate::JournalWriter::open(&data_dir).await.unwrap();
        let before_retry = reopened.journal_rows().await.unwrap();
        assert_eq!(&before_retry[..baseline.len()], baseline.as_slice());
        let committed_count = before_retry
            .iter()
            .filter(|row| row.command_id == command.command_id())
            .count();
        assert!(matches!(committed_count, 0 | 3), "no partial command");
        let retried = reopened.commit(&command, 44).await.unwrap();
        assert_eq!(retried.replayed, committed_count == 3);
        let rows = reopened.journal_rows().await.unwrap();
        assert_eq!(rows.len(), baseline.len() + 3);
        let mut expected = baseline;
        expected.extend(
            rows_for_append(
                &prepare_command(&command).unwrap(),
                start + 1,
                if committed_count == 3 { 42 } else { 44 },
            )
            .unwrap(),
        );
        assert_eq!(rows, expected);
        let replay = reopened.commit(&command, 45).await.unwrap();
        assert!(replay.replayed);
        assert_eq!(reopened.journal_rows().await.unwrap(), rows);
        eprintln!("actual writer IO probe: reopened complete command exactly once");
    }

    #[tokio::test]
    async fn complete_command_commits_replays_and_reopens_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let mut writer = crate::JournalWriter::open(&data_dir).await.unwrap();
        let start = writer.frontier();
        let command = multi_event_command(COMMAND_A);
        let outcome = writer.commit(&command, 42).await.expect("first commit");
        assert!(!outcome.replayed);
        assert_eq!(outcome.first_seq, start + 1);
        assert_eq!(outcome.last_seq, start + 3);
        assert_eq!(writer.frontier(), start + 3);
        let persisted = writer.journal_rows().await.unwrap();

        // A lost-ACK retry of the same complete command answers replay.
        let replayed = writer.commit(&command, 43).await.unwrap();
        assert!(replayed.replayed);
        assert_eq!(
            (replayed.first_seq, replayed.last_seq),
            (start + 1, start + 3)
        );
        assert_eq!(writer.frontier(), start + 3);

        drop(writer);
        let mut reopened = crate::JournalWriter::open(&data_dir).await.unwrap();
        assert_eq!(reopened.frontier(), start + 3);
        assert_eq!(reopened.journal_rows().await.unwrap(), persisted);
        let replayed = reopened
            .commit_if_frontier(&command, 44, start + 3)
            .await
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(reopened.frontier(), start + 3);
    }

    #[tokio::test]
    async fn lost_ack_replay_precedes_stale_frontier_and_conflict_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let mut writer = crate::JournalWriter::open(&data_dir).await.unwrap();
        let baseline = writer.journal_rows().await.unwrap().len();
        let command = multi_event_command(COMMAND_A);
        let committed = writer.commit(&command, 1).await.unwrap();

        // A retry answers replay even when the caller's frontier proof is stale.
        let replayed = writer
            .commit_if_frontier(&command, 2, committed.first_seq.saturating_sub(1))
            .await
            .unwrap();
        assert!(replayed.replayed);

        let conflicting = single_event_command(COMMAND_A, "tampered-payload");
        assert_eq!(
            writer.commit(&conflicting, 1).await.err(),
            Some(StoreError::IdempotencyConflict)
        );
        assert_eq!(writer.frontier(), committed.last_seq);
        assert_eq!(writer.journal_rows().await.unwrap().len(), baseline + 3);
    }

    #[test]
    fn mid_command_insert_fault_rolls_back_and_gap_is_legal() {
        let (_temp, data_dir, mut state, command) = initialized_state();
        state.faults.fail_after_first_insert = true;
        let rows = committed_rows_for(&command, 1);
        assert_eq!(state.append_command_rows(&rows).err(), Some(StoreError::Io));
        state.faults.fail_after_first_insert = false;
        assert_eq!(state.stamp().unwrap().frontier, 0);
        assert!(
            state
                .committed_rows(command.command_id())
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.journal_epoch(), 0);

        // The next valid command commits after the abandoned reservation; the
        // gap is not part of the persisted frontier.
        let next = multi_event_command(COMMAND_B);
        state
            .append_command_rows(&committed_rows_for(&next, 4))
            .unwrap();
        let seqs = state
            .rows()
            .unwrap()
            .iter()
            .map(|row| row.seq)
            .collect::<Vec<_>>();
        assert_eq!(seqs, vec![4, 5, 6]);
        drop(state);
        let mut reopened = SqliteState::open(&data_dir).unwrap();
        assert_eq!(reopened.stamp().unwrap().frontier, 6);
    }

    #[test]
    fn uncertain_commit_poisons_handle_and_reopen_accepts_a_new_append() {
        let (_temp, data_dir, mut state, command) = initialized_state();
        state.faults.fail_commit = true;
        let rows = committed_rows_for(&command, 1);
        assert_eq!(state.append_command_rows(&rows).err(), Some(StoreError::Io));
        assert!(state.poisoned());
        assert_eq!(state.append_command_rows(&rows).err(), Some(StoreError::Io));
        // A poisoned handle is unusable until it is reopened.
        assert!(state.stamp().is_err());
        drop(state);

        let mut reopened = SqliteState::open(&data_dir).unwrap();
        assert_eq!(reopened.stamp().unwrap().frontier, 0);
        reopened.append_command_rows(&rows).unwrap();
        assert_eq!(reopened.stamp().unwrap().frontier, 3);
    }

    #[test]
    fn fixed_blob_sequence_ordering_preserves_full_u64() {
        let (_temp, _data_dir, mut state, _) = initialized_state();
        for (command_id, first_seq) in [
            (COMMAND_A, i64::MAX as u64),
            (COMMAND_B, i64::MAX as u64 + 1),
            (COMMAND_C, u64::MAX - 1),
        ] {
            let command = single_event_command(command_id, command_id);
            let rows = committed_rows_for(&command, first_seq);
            state.append_command_rows(&rows).unwrap();
            assert_eq!(state.stamp().unwrap().frontier, first_seq);
        }
        assert_eq!(state.rows().unwrap().len(), 3);
        drop(state);
    }

    #[test]
    fn partial_or_tampered_persisted_rows_fail_closed_on_reopen() {
        let (_temp, data_dir, mut state, command) = initialized_state();
        state
            .append_command_rows(&committed_rows_for(&command, 1))
            .unwrap();
        drop(state);

        let connection = Connection::open(database_path(&data_dir)).unwrap();
        connection
            .execute("DELETE FROM journal_events WHERE ordinal = 1", [])
            .unwrap();
        drop(connection);
        assert_eq!(
            SqliteState::open(&data_dir).err(),
            Some(StoreError::StoreCorrupt)
        );

        // A foreign SQLite file with another application identity is rejected.
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        fs::set_permissions(&data_dir, Permissions::from_mode(0o700)).unwrap();
        let store = crate::connection::native_root(&data_dir);
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, Permissions::from_mode(0o700)).unwrap();
        let foreign = Connection::open(database_path(&data_dir)).unwrap();
        foreign
            .execute("CREATE TABLE other (id INTEGER)", [])
            .unwrap();
        drop(foreign);
        fs::set_permissions(database_path(&data_dir), Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            SqliteState::open(&data_dir).err(),
            Some(StoreError::StoreCorrupt)
        );

        // A physical trigger that can silently drop inserts is corruption even
        // when every column matches.
        let (_temp2, data_dir2, state, _command) = initialized_state();
        drop(state);
        let altered = Connection::open(database_path(&data_dir2)).unwrap();
        altered
            .execute_batch("CREATE TRIGGER suppress_insert BEFORE INSERT ON journal_events BEGIN SELECT RAISE(IGNORE); END")
            .unwrap();
        drop(altered);
        assert_eq!(
            SqliteState::open(&data_dir2).err(),
            Some(StoreError::StoreCorrupt)
        );

        let (_temp3, data_dir3, mut state, command) = initialized_state();
        state
            .append_command_rows(&committed_rows_for(&command, 1))
            .unwrap();
        drop(state);
        let corrupted = Connection::open(database_path(&data_dir3)).unwrap();
        corrupted
            .execute(
                "UPDATE journal_events SET occurred_at_us = -1 WHERE ordinal = 0",
                [],
            )
            .unwrap();
        assert_eq!(
            SqliteState::open(&data_dir3).err(),
            Some(StoreError::InvalidInput)
        );
        corrupted
            .execute(
                "UPDATE journal_events SET source_kind = 'unsupported' WHERE ordinal = 1",
                [],
            )
            .unwrap();
        drop(corrupted);
        assert_eq!(
            SqliteState::open(&data_dir3).err(),
            Some(StoreError::StoreCorrupt)
        );
    }

    #[test]
    fn component_version_one_requires_offline_upgrade() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        fs::set_permissions(&data_dir, Permissions::from_mode(0o700)).unwrap();
        let store = crate::connection::native_root(&data_dir);
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, Permissions::from_mode(0o700)).unwrap();
        let path = database_path(&data_dir);
        let connection = Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        connection
            .pragma_update(None, "user_version", 1_i64)
            .unwrap();
        drop(connection);
        fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            SqliteState::open(&data_dir).err(),
            Some(StoreError::UpgradeRequired)
        );
    }

    #[test]
    fn private_path_identity_failures_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        fs::create_dir(&data_dir).unwrap();

        fs::set_permissions(&data_dir, Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            SqliteState::open(&data_dir).err(),
            Some(StoreError::InvalidPermissions)
        );
        fs::set_permissions(&data_dir, Permissions::from_mode(0o700)).unwrap();

        let state = SqliteState::open(&data_dir).unwrap();
        let store = crate::connection::native_root(&data_dir);
        drop(state);

        fs::remove_dir_all(&store).unwrap();
        let elsewhere = temp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        symlink(&elsewhere, &store).unwrap();
        assert_eq!(
            SqliteState::open(&data_dir).err(),
            Some(StoreError::InvalidType)
        );
        fs::remove_file(&store).unwrap();

        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            SqliteState::open(&data_dir).err(),
            Some(StoreError::InvalidPermissions)
        );
        fs::set_permissions(&store, Permissions::from_mode(0o700)).unwrap();

        let state = SqliteState::open(&data_dir).unwrap();
        drop(state);
        let database = database_path(&data_dir);
        fs::set_permissions(&database, Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            SqliteState::open(&data_dir).err(),
            Some(StoreError::InvalidPermissions)
        );
    }

    #[test]
    fn live_sidecar_permissions_are_not_silently_repaired() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        fs::set_permissions(&data_dir, Permissions::from_mode(0o700)).unwrap();
        let mut state = SqliteState::open(&data_dir).unwrap();
        let command = single_event_command(COMMAND_A, "perm");
        state
            .append_command_rows(&committed_rows_for(&command, 1))
            .unwrap();
        let wal = sidecar_path(&database_path(&data_dir), WAL_FILE_SUFFIX);
        assert_eq!(
            fs::metadata(&wal).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&wal, Permissions::from_mode(0o644)).unwrap();
        let blocked = committed_rows_for(&single_event_command(COMMAND_B, "perm"), 2);
        assert_eq!(
            state.append_command_rows(&blocked).err(),
            Some(StoreError::InvalidPermissions)
        );
        assert_eq!(
            fs::metadata(&wal).unwrap().permissions().mode() & 0o777,
            0o644
        );
        fs::set_permissions(&wal, Permissions::from_mode(0o600)).unwrap();
        let retry = committed_rows_for(&single_event_command(COMMAND_B, "perm"), 2);
        state.append_command_rows(&retry).unwrap();
        assert_eq!(state.stamp().unwrap().frontier, 2);
    }

    #[test]
    fn object_reconcile_keeps_unchanged_rows_and_deletes_only_removed_family() {
        let (_temp, _data_dir, mut state, _) = initialized_state();
        let object = |id: &str, kind: &str, seq: u64| ObjectRow {
            row_id: format!("row:{id}"),
            row_kind: ObjectRowKind::Data,
            row_class: Some(ObjectRowClass::Object),
            object_family: Some(ObjectFamily::parse("work").unwrap()),
            object_kind: Some(kind.into()),
            object_id: Some(format!("object:{id}")),
            current_revision_id: Some(format!("revision:{id}")),
            lifecycle: Some("active".into()),
            epistemic: Some("observed".into()),
            authority: Some("evidence".into()),
            publication_state: Some("published".into()),
            support_state: Some("supported".into()),
            project_id: None,
            repository_id: None,
            worktree_id: None,
            task_id: None,
            workstream_id: None,
            session_id: None,
            payload_json: Some("{}".into()),
            source_event_seq: seq,
            projection_generation: 1,
        };
        let batch = vec![
            object("a", crate::projections::CORE_INDEX_KIND, 1),
            object("b", "task", 2),
            object("c", "atom_revision", 3),
            ObjectRow::checkpoint(3, 1),
        ];
        state
            .commit_object_rows(
                &batch,
                ObjectReconcile::default(),
                &ObjectRow::checkpoint(3, 1),
            )
            .unwrap();
        assert_eq!(state.objects_epoch(), 2);
        assert_eq!(state.object_checkpoint(), (3, 1));

        // A no-change commit does not advance the objects epoch.
        state
            .commit_object_rows(
                &batch,
                ObjectReconcile::default(),
                &ObjectRow::checkpoint(3, 1),
            )
            .unwrap();
        assert_eq!(state.objects_epoch(), 2);

        // A core-family reconcile deletes the removed core row but keeps
        // unrelated object rows and the checkpoint.
        let next = vec![object("b", "task", 4), ObjectRow::checkpoint(4, 1)];
        state
            .commit_object_rows(
                &next,
                ObjectReconcile {
                    core: true,
                    ..ObjectReconcile::default()
                },
                &ObjectRow::checkpoint(4, 1),
            )
            .unwrap();
        let rows = state.object_rows().unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().any(|row| row.row_id == "row:c"));
        assert_eq!(state.objects_epoch(), 3);

        // A full reconcile drops every row not present in the batch.
        let final_rows = vec![object("c", "atom_revision", 5), ObjectRow::checkpoint(5, 1)];
        state
            .commit_object_rows(
                &final_rows,
                ObjectReconcile {
                    all: true,
                    ..ObjectReconcile::default()
                },
                &ObjectRow::checkpoint(5, 1),
            )
            .unwrap();
        let rows = state.object_rows().unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row.row_id.as_str())
                .collect::<Vec<_>>(),
            vec!["checkpoint:evertrace_objects", "row:c"]
        );
        assert_eq!(state.objects_epoch(), 4);
    }

    #[test]
    fn relation_commit_changes_echo_and_deletes_only_removed() {
        let (_temp, _data_dir, mut state, _) = initialized_state();
        let edge = RelationProjectionRow::edge("task_continues", 1, "a".into(), "b".into());
        state
            .commit_relation_rows(
                std::slice::from_ref(&edge),
                &[],
                &RelationProjectionRow::checkpoint(1),
            )
            .unwrap();
        assert_eq!(state.relations_epoch(), 2);
        assert_eq!(state.relation_checkpoint(), 1);
        // No-op commit does not advance the epoch.
        state
            .commit_relation_rows(&[], &[], &RelationProjectionRow::checkpoint(1))
            .unwrap();
        assert_eq!(state.relations_epoch(), 2);
        state
            .commit_relation_rows(
                &[],
                std::slice::from_ref(&edge.row_id),
                &RelationProjectionRow::checkpoint(2),
            )
            .unwrap();
        assert_eq!(state.relations_epoch(), 3);
        assert_eq!(state.relation_rows().unwrap().len(), 1);
    }

    #[test]
    fn checkpoint_truncate_then_close_removes_wal_and_refuses_reuse() {
        let (temp, data_dir, mut state, _) = initialized_state();
        let first = committed_rows_for(&single_event_command(COMMAND_A, "backup"), 1);
        state.append_command_rows(&first).unwrap();
        assert!(state.checkpoint_and_close().unwrap());
        assert!(!state.has_open_connection());
        let wal = sidecar_path(&database_path(&data_dir), WAL_FILE_SUFFIX);
        assert!(
            fs::symlink_metadata(&wal).is_err() || fs::metadata(&wal).unwrap().len() == 0,
            "TRUNCATE checkpoint must leave no uncheckpointed WAL content"
        );
        // The closed state cannot accept more work; reopening is the only path.
        let blocked = committed_rows_for(&single_event_command(COMMAND_B, "after"), 2);
        assert_eq!(
            state.append_command_rows(&blocked).err(),
            Some(StoreError::Io)
        );

        // Immutable verification must preserve the filename's bytes, including
        // Unicode and URI delimiters, without creating sidecar bookkeeping.
        let data_dir_with_delimiters = temp.path().join("记忆 %?#& data");
        fs::rename(&data_dir, &data_dir_with_delimiters).unwrap();
        let native_dir = crate::connection::native_root(&data_dir_with_delimiters);
        let verified = verify_store_database(&native_dir).unwrap();
        assert_eq!(verified.rows, first);
        for suffix in ["-wal", "-shm"] {
            assert!(
                !native_dir
                    .join(format!("{SQLITE_FILE_NAME}{suffix}"))
                    .exists()
            );
        }
        let mut reopened = SqliteState::open(&data_dir_with_delimiters).unwrap();
        assert_eq!(reopened.stamp().unwrap().frontier, 1);
    }

    #[test]
    fn external_connection_commit_fails_closed_on_next_write() {
        let (_temp, data_dir, mut state, command) = initialized_state();
        state
            .append_command_rows(&committed_rows_for(&command, 1))
            .unwrap();
        let stamp = state.stamp().unwrap();
        // A second connection to the same file commits outside the writer.
        let external = Connection::open(database_path(&data_dir)).unwrap();
        external
            .execute(
                "INSERT INTO journal_events (seq, event_id, command_id, command_hash, ordinal, command_event_count, event_type, record_class, source_kind, occurred_at_us, ingested_at_us, payload_schema, payload_json, content_hash, effective_config_hash, algorithm_revision) VALUES (?1, ?2, ?3, ?4, 0, 1, 't', 'runtime', 'runtime', 0, 0, 1, '{}', ?5, ?6, 'x')",
                params![
                    99_u64.to_be_bytes().as_slice(),
                    "external-event",
                    "01890f47-6a4a-7cc1-98b9-01890f476aff",
                    [0_u8; 32].as_slice(),
                    [0_u8; 32].as_slice(),
                    [0_u8; 32].as_slice(),
                ],
            )
            .unwrap();
        drop(external);
        assert_eq!(
            state.validate_stamp(&stamp).err(),
            Some(StoreError::StoreCorrupt)
        );
        assert!(state.poisoned());
    }
}
