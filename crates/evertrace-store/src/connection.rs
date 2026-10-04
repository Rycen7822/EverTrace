use std::{
    future::poll_fn,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use arrow_array::RecordBatch;
use lancedb::{Connection, Table, query::ExecutableQuery};
use rusqlite::{Connection as SqliteConnection, OpenFlags};
use thiserror::Error;

/// The state root owns locks, CAS and spool; only this child is a normal native store.
pub fn native_root(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("store")
}

/// One shared budget for all tables opened through a native connection.
/// The journal, objects/runtime and relations families no longer live here;
/// this session now only serves the search projection.
pub(crate) fn native_session() -> Arc<lancedb::Session> {
    Arc::new(lancedb::Session::new(
        64 * 1024 * 1024,
        256 * 1024 * 1024,
        Arc::new(lancedb::ObjectStoreRegistry::default()),
    ))
}

/// Ensure the common `store/` container exists and reject the retired
/// four-Lance physical layout before any write. A real old store is a job for
/// the explicit offline converter, never an automatic in-place migration.
pub(crate) fn prepare_native_root(data_dir: &Path) -> Result<(), crate::StoreError> {
    use std::os::unix::fs::DirBuilderExt;
    let native = native_root(data_dir);
    match std::fs::symlink_metadata(&native) {
        Ok(_) => {
            evertrace_capture::ConfinedRoot::open_owned_private(&native)
                .map_err(|_| crate::StoreError::StoreCorrupt)?;
            for table in [
                crate::JOURNAL_TABLE,
                crate::OBJECTS_TABLE,
                crate::RELATIONS_TABLE,
            ] {
                match std::fs::symlink_metadata(native.join(format!("{table}.lance"))) {
                    Ok(metadata) => {
                        if !metadata.is_dir() || metadata.file_type().is_symlink() {
                            return Err(crate::StoreError::StoreCorrupt);
                        }
                        return Err(crate::StoreError::UpgradeRequired);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(crate::StoreError::Io),
                }
            }
            if !crate::JournalWriter::store_database_exists(data_dir)? {
                match std::fs::symlink_metadata(
                    native.join(format!("{}.lance", crate::SEARCH_TABLE)),
                ) {
                    Ok(_) => return Err(crate::StoreError::StoreCorrupt),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(crate::StoreError::Io),
                }
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
        .session(native_session())
        .execute()
        .await
        .map_err(|_| crate::StoreError::LanceDb)
}

/// Open one short-lived read-only connection to the single physical store
/// database. The caller must hold a read lease on `StoreReadHandle`.
fn open_read_connection(
    data_dir: &Path,
    path: &Path,
) -> Result<SqliteConnection, crate::StoreError> {
    let native = native_root(data_dir);
    evertrace_capture::ConfinedRoot::open_owned_private(&native)
        .map_err(|_| crate::StoreError::StoreCorrupt)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| crate::StoreError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(crate::StoreError::InvalidType);
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(crate::StoreError::InvalidPermissions);
    }
    let connection = SqliteConnection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| crate::StoreError::Io)?;
    connection
        .busy_timeout(Duration::ZERO)
        .map_err(|_| crate::StoreError::Io)?;
    Ok(connection)
}

/// One published read binding. Only a writer that completed its full startup
/// validation (or the standalone read-only opener that validated the actual
/// on-disk identity) may publish it; nothing grants read access from a path
/// alone. Revocation on close/poison makes every later read fail closed.
struct ReadBinding {
    lance: Option<Connection>,
    sqlite: Option<Weak<Mutex<crate::sqlite_state::SqliteState>>>,
    incarnation: u64,
    data_version: i64,
    file_identity: (u64, u64),
}

/// The identity a read re-checks before and after its blocking closure.
#[derive(Clone)]
struct BoundIdentity {
    sqlite: Option<Weak<Mutex<crate::sqlite_state::SqliteState>>>,
    incarnation: u64,
    data_version: i64,
    file_identity: (u64, u64),
}

/// Cancellation for one blocking read. Dropping the outer read future marks
/// the token; the SQLite progress handler (and any explicit Rust check) aborts
/// the closure so the permit/fence/lease are released only after it really
/// exits.
pub struct ReadCancel(Arc<AtomicBool>);

impl ReadCancel {
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    pub fn check(&self) -> Result<(), crate::StoreError> {
        if self.is_cancelled() {
            return Err(crate::StoreError::Io);
        }
        Ok(())
    }
}

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn install_cancel(
    connection: &SqliteConnection,
    cancel: &Arc<AtomicBool>,
) -> Result<(), crate::StoreError> {
    let flag = Arc::clone(cancel);
    connection
        .progress_handler(1000, Some(move || flag.load(Ordering::SeqCst)))
        .map_err(|_| crate::StoreError::Io)
}

fn validate_read_root(data_dir: &Path) -> Result<(), crate::StoreError> {
    evertrace_capture::ConfinedRoot::open_owned_private(&native_root(data_dir))
        .map_err(|_| crate::StoreError::StoreCorrupt)?;
    Ok(())
}

fn validate_read_file(metadata: &std::fs::Metadata) -> Result<(), crate::StoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(crate::StoreError::InvalidType);
    }
    if metadata.uid() != current_uid()? {
        return Err(crate::StoreError::WrongOwner);
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(crate::StoreError::InvalidPermissions);
    }
    Ok(())
}

fn current_uid() -> Result<u32, crate::StoreError> {
    std::fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .map_err(|_| crate::StoreError::Io)
}

fn validate_read_path(data_dir: &Path, identity: &BoundIdentity) -> Result<(), crate::StoreError> {
    validate_read_root(data_dir)?;
    let path = sqlite_path(data_dir);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| crate::StoreError::Io)?;
    validate_read_file(&metadata)?;
    if (metadata.dev(), metadata.ino()) != identity.file_identity {
        return Err(crate::StoreError::StoreCorrupt);
    }
    Ok(())
}

/// Shared read side of one store. It owns the permit budget (at most two
/// short read-only connections), the maintenance fence real readers drain
/// through and the one Lance search connection the writer published. There is
/// deliberately no reader actor, registry or per-session pool.
#[derive(Clone)]
pub struct StoreReadHandle {
    inner: Arc<ReadHandleInner>,
}

struct ReadHandleInner {
    data_dir: PathBuf,
    permits: Arc<tokio::sync::Semaphore>,
    fence: Arc<tokio::sync::RwLock<()>>,
    binding: Mutex<Option<ReadBinding>>,
    incarnation: AtomicU64,
}

impl StoreReadHandle {
    /// An unbound publication target. Only a writer that completed its full
    /// validation, or the standalone read-only opener for this exact
    /// directory, may publish; reads while unbound fail closed.
    pub fn open(data_dir: &Path) -> Self {
        Self {
            inner: Arc::new(ReadHandleInner {
                data_dir: data_dir.to_owned(),
                permits: Arc::new(tokio::sync::Semaphore::new(2)),
                fence: Arc::new(tokio::sync::RwLock::new(())),
                binding: Mutex::new(None),
                incarnation: AtomicU64::new(0),
            }),
        }
    }

    /// Bind a read-only handle to the real store on disk. The physical file
    /// must already be a complete current-format database; this never creates
    /// or repairs one, and the recorded identity is re-checked on every read.
    pub async fn open_read_only(data_dir: &Path) -> Result<Self, crate::StoreError> {
        let handle = Self::open(data_dir);
        let path = sqlite_path(data_dir);
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| crate::StoreError::Io)?;
        validate_read_file(&metadata)?;
        let connection = open_read_connection(data_dir, &path)?;
        crate::sqlite_state::validate_read_header(&connection)?;
        let rows = crate::sqlite_state::read_all_rows(&connection)?;
        crate::journal::validate_journal_rows(&rows)?;
        drop(connection);
        handle.bind(ReadBinding {
            lance: None,
            sqlite: None,
            incarnation: 0,
            data_version: 0,
            file_identity: (metadata.dev(), metadata.ino()),
        });
        Ok(handle)
    }

    pub fn data_dir(&self) -> &Path {
        &self.inner.data_dir
    }

    /// The actual published physical incarnation, or 0 while unbound. This
    /// mirrors the writer's validated state and is never a private counter.
    pub fn incarnation(&self) -> u64 {
        self.inner.incarnation.load(Ordering::SeqCst)
    }

    /// Publish the writer's validated binding. Called only after the writer
    /// opened, migrated, validated and indexed this exact physical state.
    pub(crate) fn publish_writer_binding(
        &self,
        lance: Connection,
        sqlite: &crate::sqlite_state::SqliteHandle,
    ) -> Result<(), crate::StoreError> {
        let (incarnation, data_version, file_identity) = {
            let mut state = sqlite.lock().map_err(|_| crate::StoreError::StoreCorrupt)?;
            let stamp = state.stamp()?;
            (stamp.incarnation, stamp.data_version, state.file_identity())
        };
        self.bind(ReadBinding {
            lance: Some(lance),
            sqlite: Some(Arc::downgrade(sqlite)),
            incarnation,
            data_version,
            file_identity,
        });
        Ok(())
    }

    /// Attach the native search connection to an already validated read-only
    /// binding. The standalone SearchIndex opener uses this; a writer binding
    /// already carries its own connection.
    pub(crate) fn bind_read_only_search(&self, lance: Connection) -> Result<(), crate::StoreError> {
        let mut binding = self
            .inner
            .binding
            .lock()
            .map_err(|_| crate::StoreError::StoreCorrupt)?;
        let Some(binding) = binding.as_mut() else {
            return Err(crate::StoreError::Io);
        };
        if binding.sqlite.is_some() {
            return Err(crate::StoreError::StoreCorrupt);
        }
        binding.lance = Some(lance);
        Ok(())
    }

    /// Revoke every published binding. Called when the physical store closes
    /// or its identity can no longer be trusted; later reads fail closed.
    pub(crate) fn revoke(&self) {
        if let Ok(mut binding) = self.inner.binding.lock() {
            *binding = None;
        }
        self.inner.incarnation.store(0, Ordering::SeqCst);
    }

    fn bind(&self, binding: ReadBinding) {
        self.inner
            .incarnation
            .store(binding.incarnation, Ordering::SeqCst);
        if let Ok(mut current) = self.inner.binding.lock() {
            *current = Some(binding);
        }
    }

    fn bound_identity(&self) -> Result<BoundIdentity, crate::StoreError> {
        let binding = self
            .inner
            .binding
            .lock()
            .map_err(|_| crate::StoreError::StoreCorrupt)?;
        let Some(binding) = binding.as_ref() else {
            return Err(crate::StoreError::Io);
        };
        Ok(BoundIdentity {
            sqlite: binding.sqlite.clone(),
            incarnation: binding.incarnation,
            data_version: binding.data_version,
            file_identity: binding.file_identity,
        })
    }

    /// Re-check the actual published identity. A live writer state is asked
    /// for its own stamp (its connection's external `data_version` and file
    /// identity); a standalone binding re-checks the recorded physical
    /// identity. Values from different connections are never compared.
    fn check_identity(&self, identity: &BoundIdentity) -> Result<(), crate::StoreError> {
        match identity.sqlite.as_ref() {
            Some(weak) => {
                let state = weak.upgrade().ok_or(crate::StoreError::Io)?;
                let mut state = state.lock().map_err(|_| crate::StoreError::StoreCorrupt)?;
                let stamp = state.stamp()?;
                if stamp.incarnation != identity.incarnation
                    || stamp.data_version != identity.data_version
                {
                    return Err(crate::StoreError::StoreCorrupt);
                }
            }
            None => validate_read_path(&self.inner.data_dir, identity)?,
        }
        Ok(())
    }

    /// Run one short synchronous read on its own read-only connection. The
    /// blocking closure owns the connection, the permit and the fence lease;
    /// they are released only after the connection actually closed. Dropping
    /// the outer future marks the read cancelled so the closure stops at its
    /// next SQLite step instead of running to completion.
    pub async fn read<T, F>(&self, read: F) -> Result<T, crate::StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&SqliteConnection, &ReadCancel) -> Result<T, crate::StoreError> + Send + 'static,
    {
        // Fixed lock order: the fair maintenance fence first, then the short
        // SQL permit, then a brief writer-state check. Permit-first could
        // deadlock a fair maintenance write against a reader that still waits
        // for the fence.
        let fence = Arc::clone(&self.inner.fence).read_owned().await;
        let permit = Arc::clone(&self.inner.permits)
            .acquire_owned()
            .await
            .map_err(|_| crate::StoreError::Io)?;
        let identity = self.bound_identity()?;
        self.check_identity(&identity)?;
        let cancel = Arc::new(AtomicBool::new(false));
        let guard = CancelOnDrop(Arc::clone(&cancel));
        let inner = Arc::clone(&self.inner);
        let path = sqlite_path(&self.inner.data_dir);
        let task_identity = identity.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _fence = fence;
            validate_read_path(&inner.data_dir, &task_identity)?;
            let connection = open_read_connection(&inner.data_dir, &path)?;
            install_cancel(&connection, &cancel)?;
            let token = ReadCancel(Arc::clone(&cancel));
            let result = read(&connection, &token);
            drop(connection);
            result
        });
        let result = joined.await.map_err(|_| crate::StoreError::Io)?;
        drop(guard);
        let value = result?;
        self.check_identity(&identity)?;
        Ok(value)
    }

    /// Drain every reader lease and block new ones. The returned guard is
    /// held across the closed backup window; readers that arrive while the
    /// store is closed queue behind it and run against the reopened handle.
    pub async fn quiesce(&self) -> tokio::sync::OwnedRwLockWriteGuard<()> {
        Arc::clone(&self.inner.fence).write_owned().await
    }

    /// Read the persisted journal through a short-lived read-only connection.
    pub async fn journal_rows(&self) -> Result<Vec<crate::JournalRow>, crate::StoreError> {
        self.read(|connection, _| crate::sqlite_state::read_all_rows(connection))
            .await
    }

    /// The first consistent read transaction of an LLM budget scan fixes the
    /// persistent frontier upper bound; later pages pass it back and never
    /// extend. No actor message or writer wait is involved, so a reader can
    /// never deadlock a backup that is waiting for the writer.
    pub async fn llm_budget_page(
        &self,
        day_start_us: i64,
        after: u64,
        requested_frontier: u64,
        bound: Option<u64>,
    ) -> Result<(u64, Vec<crate::JournalRow>), crate::StoreError> {
        self.read(move |connection, cancel| {
            cancel.check()?;
            let transaction = connection
                .unchecked_transaction()
                .map_err(|_| crate::StoreError::Io)?;
            let persisted = crate::sqlite_state::read_persisted_frontier(connection)?;
            let upper = match bound {
                Some(bound) => bound,
                None if requested_frontier == 0 => persisted,
                None => persisted.min(requested_frontier),
            };
            let rows =
                crate::sqlite_state::read_budget_page(connection, day_start_us, after, upper)?;
            drop(transaction);
            Ok((upper, rows))
        })
        .await
    }

    /// A search lease: one pinned Lance connection held together with a read
    /// fence, so maintenance cannot close the store while the query is done.
    /// It deliberately holds no SQL permit: the permit belongs to each short
    /// SQL read, so several pinned snapshots cannot starve each other.
    pub(crate) async fn search_lease(&self) -> Result<StoreReadLease, crate::StoreError> {
        let fence = Arc::clone(&self.inner.fence).read_owned().await;
        let identity = self.bound_identity()?;
        self.check_identity(&identity)?;
        let lance = {
            let binding = self
                .inner
                .binding
                .lock()
                .map_err(|_| crate::StoreError::StoreCorrupt)?;
            let binding = binding.as_ref().ok_or(crate::StoreError::Io)?;
            binding.lance.clone().ok_or(crate::StoreError::Io)?
        };
        Ok(StoreReadLease {
            inner: Arc::new(LeaseInner {
                lance,
                identity,
                _fence: fence,
            }),
        })
    }

    /// Run one short SQL read while already holding a lease. The lease owns
    /// the fence and the pinned native connection; this takes one SQL permit
    /// for the duration of the closure only, re-checks the bound identity and
    /// never nests the fair fence.
    pub(crate) async fn lease_read<T>(
        &self,
        lease: &StoreReadLease,
        read: impl FnOnce(&SqliteConnection, &ReadCancel) -> Result<T, crate::StoreError>
        + Send
        + 'static,
    ) -> Result<T, crate::StoreError>
    where
        T: Send + 'static,
    {
        let permit = Arc::clone(&self.inner.permits)
            .acquire_owned()
            .await
            .map_err(|_| crate::StoreError::Io)?;
        let identity = lease.inner.identity.clone();
        self.check_identity(&identity)?;
        // The caller may drop its future and last lease while this blocking
        // task is still running. Keep the actual maintenance fence here.
        let task_lease = lease.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let guard = CancelOnDrop(Arc::clone(&cancel));
        let inner = Arc::clone(&self.inner);
        let path = sqlite_path(&self.inner.data_dir);
        let task_identity = identity.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let _lease = task_lease;
            let _permit = permit;
            validate_read_path(&inner.data_dir, &task_identity)?;
            let connection = open_read_connection(&inner.data_dir, &path)?;
            install_cancel(&connection, &cancel)?;
            let token = ReadCancel(Arc::clone(&cancel));
            let result = read(&connection, &token);
            drop(connection);
            result
        });
        let result = joined.await.map_err(|_| crate::StoreError::Io)?;
        drop(guard);
        let value = result?;
        self.check_identity(&identity)?;
        Ok(value)
    }
}

/// A shared, cheaply cloneable pinned lease. The inner native connection is
/// declared before the fence so it drops first: maintenance never observes the
/// fence released while a pinned native table can still submit work.
#[derive(Clone)]
pub(crate) struct StoreReadLease {
    inner: Arc<LeaseInner>,
}

struct LeaseInner {
    lance: Connection,
    identity: BoundIdentity,
    _fence: tokio::sync::OwnedRwLockReadGuard<()>,
}

impl StoreReadLease {
    pub(crate) fn lance(&self) -> &Connection {
        &self.inner.lance
    }
}

impl std::fmt::Debug for StoreReadHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoreReadHandle")
            .field("data_dir", &self.inner.data_dir)
            .field("incarnation", &self.incarnation())
            .finish()
    }
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
            .session(native_session())
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

/// The physical database path for one data root.
pub(crate) fn sqlite_path(data_dir: &Path) -> PathBuf {
    native_root(data_dir).join(crate::sqlite_state::SQLITE_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn cancelled_started_read_releases_the_fence_and_other_readers() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        let writer = crate::JournalWriter::open(&data).await.unwrap();
        let readers = writer.read_handle();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn({
            let readers = readers.clone();
            async move {
                readers
                    .read(move |connection, cancel| {
                        started_tx.send(()).unwrap();
                        // A real query loop that has genuinely started before the
                        // caller cancels; the token is checked in Rust and the
                        // SQLite progress handler interrupts the statement.
                        for _ in 0..1_000_000 {
                            cancel.check()?;
                            connection
                                .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                                .map_err(|_| crate::StoreError::Io)?;
                        }
                        Ok(())
                    })
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .expect("blocking read actually started")
            .expect("read started");
        task.abort();
        let _ = task.await;
        // The permit and fence are released only after the real closure exits.
        let guard = tokio::time::timeout(Duration::from_secs(5), readers.quiesce())
            .await
            .expect("cancelled read drained");
        drop(guard);
        // Both read permits and the shared writer binding still work.
        let (first, second) = tokio::join!(
            readers.read(|connection, _| crate::sqlite_state::read_persisted_frontier(connection)),
            readers.read(|connection, _| crate::sqlite_state::read_persisted_frontier(connection))
        );
        first.unwrap();
        second.unwrap();
        drop(writer);
    }
    #[tokio::test]
    async fn at_most_two_short_sql_connections_are_checked_out_at_once() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let writer = crate::JournalWriter::open(&root).await.unwrap();
        let readers = writer.read_handle();
        let (started_tx, mut started_rx) = tokio::sync::mpsc::channel(4);
        let mut releases = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let readers = readers.clone();
            let started_tx = started_tx.clone();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            releases.push(release_tx);
            tasks.push(tokio::spawn(async move {
                readers
                    .read(move |connection, _| {
                        started_tx.try_send(()).unwrap();
                        let _ = release_rx.recv();
                        crate::sqlite_state::read_persisted_frontier(connection)
                    })
                    .await
            }));
        }
        for _ in 0..2 {
            started_rx.recv().await.unwrap();
        }
        // Both store-wide read connections are checked out: a third read waits
        // for a permit instead of opening an unbounded connection.
        let (third_tx, mut third_rx) = tokio::sync::oneshot::channel();
        let third = tokio::spawn({
            let readers = readers.clone();
            async move {
                readers
                    .read(move |connection, _| {
                        third_tx.send(()).ok();
                        crate::sqlite_state::read_persisted_frontier(connection)
                    })
                    .await
            }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut third_rx)
                .await
                .is_err()
        );
        releases.pop().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut third_rx)
            .await
            .expect("a freed permit must serve the queued read")
            .unwrap();
        releases.pop().unwrap().send(()).unwrap();
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        third.await.unwrap().unwrap();
        drop(writer);
    }
}
