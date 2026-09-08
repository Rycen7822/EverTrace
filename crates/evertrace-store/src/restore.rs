//! Offline restoration under the continuously held sibling writer lock.

use crate::{EventScope, JournalPayload, JournalRow, SourceKind, StoreError};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum NativeUpgradeOutcome {
    Empty,
    Noop {
        retained_native: Vec<PathBuf>,
    },
    Published {
        backup: PathBuf,
        migrated: bool,
        retained_native: Vec<PathBuf>,
    },
}

/// Offline native publication only. Capture's state root and all durable inputs
/// remain in place; this transaction never performs Restore authority resets.
pub async fn upgrade_native(
    data_dir: &Path,
    config_path: &Path,
    freeze_hook: impl FnOnce() -> Result<crate::backup::BackupHookBoundary, crate::BackupError>,
    verify_hook: impl Fn(&Path, &crate::BackupSummary) -> Result<(), crate::BackupError>,
) -> Result<NativeUpgradeOutcome, RestoreError> {
    upgrade_native_inner(data_dir, config_path, freeze_hook, verify_hook, |_| Ok(())).await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativePublicationPoint {
    BackupFrozen,
    Prepared,
    Published,
    Durable,
}

async fn upgrade_native_inner(
    data_dir: &Path,
    config_path: &Path,
    freeze_hook: impl FnOnce() -> Result<crate::backup::BackupHookBoundary, crate::BackupError>,
    verify_hook: impl Fn(&Path, &crate::BackupSummary) -> Result<(), crate::BackupError>,
    checkpoint: impl Fn(NativePublicationPoint) -> Result<(), RestoreError>,
) -> Result<NativeUpgradeOutcome, RestoreError> {
    match prepare_upgrade_inner(
        data_dir,
        config_path,
        freeze_hook,
        verify_hook,
        false,
        &checkpoint,
    )
    .await?
    {
        NativeUpgradePreparation::Unchanged(outcome) => Ok(outcome),
        NativeUpgradePreparation::Prepared(prepared) => prepared.publish(checkpoint).await,
    }
}

pub enum NativeUpgradePreparation {
    Unchanged(NativeUpgradeOutcome),
    Prepared(Box<PreparedNativeUpgrade>),
}

pub struct PreparedNativeUpgrade {
    lock: crate::SiblingWriterLock,
    parent: evertrace_capture::ConfinedRoot,
    source_root: evertrace_capture::ConfinedRoot,
    source_tables: Vec<(PathBuf, evertrace_capture::ConfinedRoot)>,
    data_dir: PathBuf,
    source: PathBuf,
    canonical: PathBuf,
    canonical_exists: bool,
    candidate: PathBuf,
    custody: evertrace_capture::ConfinedRoot,
    backup: PathBuf,
    verification: crate::backup::BackupVerification,
    prepared_manifest: Vec<crate::backup::BackupFileManifest>,
    table_names: &'static [&'static str],
    migrated: bool,
}

/// Package checks require the actual backup/replay boundary even at L0002.
pub async fn prepare_native_upgrade(
    data_dir: &Path,
    config_path: &Path,
    freeze_hook: impl FnOnce() -> Result<crate::backup::BackupHookBoundary, crate::BackupError>,
    verify_hook: impl Fn(&Path, &crate::BackupSummary) -> Result<(), crate::BackupError>,
) -> Result<NativeUpgradePreparation, RestoreError> {
    prepare_upgrade_inner(
        data_dir,
        config_path,
        freeze_hook,
        verify_hook,
        true,
        &|_| Ok(()),
    )
    .await
}

async fn prepare_upgrade_inner(
    data_dir: &Path,
    config_path: &Path,
    freeze_hook: impl FnOnce() -> Result<crate::backup::BackupHookBoundary, crate::BackupError>,
    verify_hook: impl Fn(&Path, &crate::BackupSummary) -> Result<(), crate::BackupError>,
    check_package: bool,
    checkpoint: &impl Fn(NativePublicationPoint) -> Result<(), RestoreError>,
) -> Result<NativeUpgradePreparation, RestoreError> {
    let lock = crate::SiblingWriterLock::acquire(data_dir)?;
    let parent = evertrace_capture::ConfinedRoot::open_owned_private(data_dir)
        .map_err(|_| RestoreError::Io)?;
    reject_retained_upgrade_candidate(data_dir)?;
    let canonical = crate::connection::native_root(data_dir);
    let canonical_exists = match std::fs::symlink_metadata(&canonical) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(RestoreError::Io),
    };
    let source = if canonical_exists {
        canonical.as_path()
    } else {
        data_dir
    };
    let source_root = evertrace_capture::ConfinedRoot::open_owned_private(source)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let profile = crate::JournalWriter::existing_profile(source).await?;
    if profile.is_none() {
        if canonical_exists
            || [
                crate::OBJECTS_TABLE,
                crate::RELATIONS_TABLE,
                crate::SEARCH_TABLE,
            ]
            .iter()
            .any(|table| source.join(format!("{table}.lance")).exists())
        {
            return Err(StoreError::StoreCorrupt.into());
        }
        return Ok(NativeUpgradePreparation::Unchanged(
            NativeUpgradeOutcome::Empty,
        ));
    }
    let table_names: &'static [&'static str] = if profile == Some("L0001") {
        &[crate::JOURNAL_TABLE, crate::OBJECTS_TABLE]
    } else {
        &[
            crate::JOURNAL_TABLE,
            crate::OBJECTS_TABLE,
            crate::RELATIONS_TABLE,
            crate::SEARCH_TABLE,
        ]
    };
    let source_tables = table_names
        .iter()
        .map(|name| {
            let path = source.join(format!("{name}.lance"));
            let custody = evertrace_capture::ConfinedRoot::open_owned_private(&path)
                .map_err(|_| StoreError::StoreCorrupt)?;
            Ok::<_, RestoreError>((path, custody))
        })
        .collect::<Result<Vec<_>, _>>()?;
    crate::backup::read_verified_store_tables(source).await?;
    if !check_package && canonical_exists && profile == Some("L0002") {
        let mut retained_native = Vec::new();
        for table in table_names {
            let path = data_dir.join(format!("{table}.lance"));
            match std::fs::symlink_metadata(&path) {
                Ok(_) => retained_native.push(path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(RestoreError::Io),
            }
        }
        return Ok(NativeUpgradePreparation::Unchanged(
            NativeUpgradeOutcome::Noop { retained_native },
        ));
    }
    if canonical_exists {
        validate_upgrade_container_entries(source, table_names)?;
    }
    catch_up_upgrade_source(source, profile == Some("L0002")).await?;
    let (states, snapshot) = crate::backup::read_verified_store_tables(source).await?;
    let runtime = evertrace_capture::RuntimeSnapshot::load(
        &evertrace_capture::RuntimeSnapshot::snapshot_path(data_dir),
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    let fence =
        evertrace_capture::MaintenanceFence::open(data_dir).map_err(|_| RestoreError::Io)?;
    let (mut spool, _) = evertrace_capture::DurableSpool::open(
        runtime.spool_dir.clone(),
        runtime
            .spool_limits()
            .map_err(|_| StoreError::InvalidInput)?,
    )
    .map_err(|_| RestoreError::Io)?;
    let guard = fence.exclusive().map_err(|_| RestoreError::Io)?;
    let spool_boundary = spool
        .freeze_backup_boundary(&guard, runtime.generation)
        .map_err(|_| RestoreError::Io)?;
    drop(guard);
    drop(spool);
    checkpoint(NativePublicationPoint::BackupFrozen)?;
    let boundary = crate::backup::BackupFrozenBoundary {
        spool: spool_boundary,
        hook: freeze_hook()?,
    };
    let id = evertrace_domain::ids::JobId::new_v7();
    let plan = crate::backup::prepare_backup(
        (data_dir, source),
        config_path,
        &runtime,
        id,
        &snapshot,
        states,
        boundary,
    )?;
    plan.check_upgrade_space()?;
    let staging = crate::backup::stage_backup(plan)?;
    let verified_staging = async {
        let summary = crate::backup::verify_staged_backup(&staging).await?;
        verify_hook(staging.directory(), &summary)?;
        Ok::<_, crate::BackupError>(summary)
    }
    .await;
    let summary = match verified_staging {
        Ok(summary) => summary,
        Err(cause) => {
            crate::backup::discard_backup(&staging).map_err(|_| {
                RestoreError::ResidualCandidate {
                    directory: staging.directory().to_owned(),
                    cause: Box::new(cause.into()),
                }
            })?;
            return Err(cause.into());
        }
    };
    crate::backup::publish_backup(staging, summary)?;
    let backup = data_dir.join(format!("backups/backup-{id}"));
    let verification = crate::backup::prepare_verification_directory(&backup, Some(id))?;
    let verified = crate::backup::complete_backup_verification_ref(&verification).await?;
    verify_hook(&backup, &verified)?;
    lock.validate_held()?;
    source_root
        .revalidate_stable()
        .map_err(|_| StoreError::StoreCorrupt)?;
    let candidate = data_dir.join(format!(".upgrade-{id}"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&candidate)
        .map_err(|_| RestoreError::Io)?;
    let custody =
        evertrace_capture::ConfinedRoot::open_owned_private(&candidate).map_err(|_| {
            RestoreError::ResidualCandidate {
                directory: candidate.clone(),
                cause: Box::new(RestoreError::Io),
            }
        })?;
    let prepared = async {
        crate::backup::copy_upgrade_native_candidate(&verification, &candidate, &custody)?;
        rebuild_upgrade_native(&candidate).await?;
        lock.validate_held()?;
        source_root
            .revalidate_stable()
            .map_err(|_| StoreError::StoreCorrupt)?;
        if canonical_exists {
            validate_upgrade_container_entries(source, table_names)?;
        }
        checkpoint(NativePublicationPoint::Prepared)?;
        crate::backup::native_upgrade_manifest(&candidate).map_err(RestoreError::from)
    }
    .await;
    let prepared_manifest = match prepared {
        Ok(manifest) => manifest,
        Err(cause) => {
            return match remove_owned_candidate_tree(&candidate, &custody) {
                Ok(()) => Err(cause),
                Err(_) => Err(RestoreError::ResidualCandidate {
                    directory: candidate,
                    cause: Box::new(cause),
                }),
            };
        }
    };
    Ok(NativeUpgradePreparation::Prepared(Box::new(
        PreparedNativeUpgrade {
            lock,
            parent,
            source_root,
            source_tables,
            data_dir: data_dir.to_owned(),
            source: source.to_owned(),
            canonical,
            canonical_exists,
            candidate,
            custody,
            backup,
            verification,
            prepared_manifest,
            table_names,
            migrated: profile == Some("L0001"),
        },
    )))
}

impl PreparedNativeUpgrade {
    pub fn path(&self) -> &Path {
        &self.candidate
    }
    pub fn backup(&self) -> &Path {
        &self.backup
    }
    pub fn migrated(&self) -> bool {
        self.migrated
    }

    pub fn discard(self) -> Result<(), RestoreError> {
        let cleanup = self
            .lock
            .validate_held()
            .map_err(RestoreError::from)
            .and_then(|()| remove_owned_candidate_tree(&self.candidate, &self.custody));
        cleanup.map_err(|cause| RestoreError::ResidualCandidate {
            directory: self.candidate,
            cause: Box::new(cause),
        })
    }

    async fn publish(
        self,
        checkpoint: impl Fn(NativePublicationPoint) -> Result<(), RestoreError>,
    ) -> Result<NativeUpgradeOutcome, RestoreError> {
        let Self {
            lock,
            parent,
            source_root,
            source_tables,
            data_dir,
            source,
            canonical,
            canonical_exists,
            candidate,
            custody,
            backup,
            verification,
            prepared_manifest,
            table_names,
            migrated,
        } = self;
        let source = source.as_path();
        let directory_identity = |path: &Path| -> Result<(u64, u64), RestoreError> {
            let metadata = std::fs::symlink_metadata(path).map_err(|_| RestoreError::Io)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(StoreError::StoreCorrupt.into());
            }
            Ok((metadata.dev(), metadata.ino()))
        };
        let candidate_identity =
            directory_identity(&candidate).map_err(|cause| RestoreError::ResidualCandidate {
                directory: candidate.clone(),
                cause: Box::new(cause),
            })?;
        let previous_identity =
            directory_identity(source).map_err(|cause| RestoreError::ResidualCandidate {
                directory: candidate.clone(),
                cause: Box::new(cause),
            })?;
        // No semantic write resumes until publication, directory sync and validation
        // have all succeeded. Flat source tables are never moved or overwritten.
        let publish = if canonical_exists {
            parent.exchange_directories(&custody, &source_root)
        } else {
            parent.publish_directory_noreplace(&custody, "store")
        };
        if publish.is_err() {
            let source_unchanged = directory_identity(&candidate).ok() == Some(candidate_identity);
            let target_unchanged = if canonical_exists {
                directory_identity(&canonical).ok() == Some(previous_identity)
            } else {
                directory_identity(&canonical).ok() != Some(candidate_identity)
            };
            if source_unchanged
                && target_unchanged
                && parent.revalidate_stable().is_ok()
                && lock.validate_held().is_ok()
            {
                remove_owned_candidate_tree(&candidate, &custody).map_err(|cause| {
                    RestoreError::ResidualCandidate {
                        directory: candidate.clone(),
                        cause: Box::new(cause),
                    }
                })?;
                return Err(RestoreError::Io);
            }
            return Err(RestoreError::NativePublicationUncertain {
                active: canonical,
                preserved: candidate,
            });
        }
        let checked = async {
            checkpoint(NativePublicationPoint::Published)?;
            std::fs::File::open(&data_dir)
                .and_then(|file| file.sync_all())
                .map_err(|_| RestoreError::Io)?;
            checkpoint(NativePublicationPoint::Durable)?;
            lock.validate_held()?;
            let (states, _) = crate::backup::read_verified_store_tables(&canonical).await?;
            if states.relations.is_none() || states.search.is_none() {
                return Err(StoreError::StoreCorrupt.into());
            }
            if crate::backup::native_upgrade_manifest(&canonical)? != prepared_manifest {
                return Err(StoreError::StoreCorrupt.into());
            }
            Ok::<_, RestoreError>(())
        }
        .await;
        if let Err(cause) = checked {
            if directory_identity(&canonical).ok() != Some(candidate_identity)
                || (canonical_exists
                    && directory_identity(&candidate).ok() != Some(previous_identity))
            {
                return Err(RestoreError::NativePublicationUncertain {
                    active: canonical,
                    preserved: candidate,
                });
            }
            let active =
                evertrace_capture::ConfinedRoot::open_owned_private(&canonical).map_err(|_| {
                    RestoreError::NativePublicationUncertain {
                        active: canonical.clone(),
                        preserved: candidate.clone(),
                    }
                })?;
            let rollback = if canonical_exists {
                evertrace_capture::ConfinedRoot::open_owned_private(&candidate)
                    .and_then(|old| parent.exchange_directories(&active, &old))
            } else {
                parent.publish_directory_noreplace(
                    &active,
                    candidate
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or(RestoreError::Io)?,
                )
            };
            if rollback.is_err()
                || std::fs::File::open(&data_dir)
                    .and_then(|file| file.sync_all())
                    .is_err()
            {
                return Err(RestoreError::NativePublicationUncertain {
                    active: canonical,
                    preserved: candidate,
                });
            }
            if directory_identity(&candidate).ok() != Some(candidate_identity) {
                return Err(RestoreError::NativePublicationUncertain {
                    active: canonical,
                    preserved: candidate,
                });
            }
            let rolled_back = evertrace_capture::ConfinedRoot::open_owned_private(&candidate)
                .map_err(|_| RestoreError::ResidualCandidate {
                    directory: candidate.clone(),
                    cause: Box::new(RestoreError::Io),
                })?;
            remove_owned_candidate_tree(&candidate, &rolled_back).map_err(|cause| {
                RestoreError::ResidualCandidate {
                    directory: candidate.clone(),
                    cause: Box::new(cause),
                }
            })?;
            return Err(cause);
        }
        let retained_native = if canonical_exists {
            if directory_identity(&candidate).ok() != Some(previous_identity) {
                return Err(RestoreError::NativePublicationUncertain {
                    active: canonical,
                    preserved: candidate,
                });
            }
            match validate_upgrade_container_entries(&candidate, table_names).and_then(|()| {
                let old = evertrace_capture::ConfinedRoot::open_owned_private(&candidate)
                    .map_err(|_| RestoreError::Io)?;
                remove_owned_candidate_tree(&candidate, &old)
            }) {
                Ok(()) => Vec::new(),
                Err(_) => vec![candidate],
            }
        } else {
            let mut retained = Vec::new();
            for (path, custody) in source_tables {
                let cleanup = (|| {
                    custody
                        .revalidate_stable()
                        .map_err(|_| StoreError::StoreCorrupt)?;
                    let prefix =
                        Path::new("store").join(path.file_name().ok_or(StoreError::InvalidPath)?);
                    let expected = verification
                        .files()
                        .iter()
                        .filter_map(|entry| {
                            let relative =
                                Path::new(&entry.relative_path).strip_prefix(&prefix).ok()?;
                            let mut entry = entry.clone();
                            entry.relative_path = if relative.as_os_str().is_empty() {
                                "store".to_owned()
                            } else {
                                Path::new("store").join(relative).to_str()?.to_owned()
                            };
                            Some(entry)
                        })
                        .collect::<Vec<_>>();
                    if expected.is_empty()
                        || crate::backup::native_upgrade_manifest(&path)? != expected
                    {
                        return Err(StoreError::StoreCorrupt.into());
                    }
                    custody
                        .revalidate_stable()
                        .map_err(|_| StoreError::StoreCorrupt)?;
                    remove_owned_candidate_tree(&path, &custody)
                })();
                if cleanup.is_err() {
                    retained.push(path);
                }
            }
            retained
        };
        Ok(NativeUpgradeOutcome::Published {
            backup,
            migrated,
            retained_native,
        })
    }
}

fn reject_retained_upgrade_candidate(data_dir: &Path) -> Result<(), RestoreError> {
    // No name grants cleanup authority. Bound this preflight before any backup
    // or candidate copy, including the otherwise-Noop canonical path.
    const MAX_ROOT_ENTRIES: usize = 4096;
    let uncertain = || RestoreError::ResidualCandidate {
        directory: data_dir.to_owned(),
        cause: Box::new(RestoreError::Io),
    };
    let entries = std::fs::read_dir(data_dir).map_err(|_| uncertain())?;
    for (index, entry) in entries.take(MAX_ROOT_ENTRIES + 1).enumerate() {
        if index == MAX_ROOT_ENTRIES {
            return Err(RestoreError::ResidualCandidate {
                directory: data_dir.to_owned(),
                cause: Box::new(crate::BackupError::ResourceExhausted.into()),
            });
        }
        let entry = entry.map_err(|_| uncertain())?;
        if entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(b".upgrade-")
        {
            return Err(RestoreError::ResidualCandidate {
                directory: entry.path(),
                cause: Box::new(StoreError::InvalidInput.into()),
            });
        }
    }
    Ok(())
}

fn validate_upgrade_container_entries(native: &Path, tables: &[&str]) -> Result<(), RestoreError> {
    for entry in std::fs::read_dir(native)
        .map_err(|_| RestoreError::Io)?
        .take(tables.len() + 1)
    {
        let name = entry.map_err(|_| RestoreError::Io)?.file_name();
        if !tables
            .iter()
            .any(|table| name == std::ffi::OsStr::new(&format!("{table}.lance")))
        {
            return Err(StoreError::StoreCorrupt.into());
        }
    }
    Ok(())
}

async fn catch_up_upgrade_source(native: &Path, l0002: bool) -> Result<(), RestoreError> {
    let connection = lancedb::connect(native.to_str().ok_or(StoreError::InvalidPath)?)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let journal = connection
        .open_table(crate::JOURNAL_TABLE)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let objects = connection
        .open_table(crate::OBJECTS_TABLE)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let frontier = crate::journal::read_journal_frontier(&journal).await?;
    let journal_version = journal.version().await.map_err(|_| StoreError::LanceDb)?;
    let snapshot = crate::ProjectionWorker::new(journal.clone(), objects)
        .catch_up()
        .await?;
    if l0002 {
        let relations = connection
            .open_table(crate::RELATIONS_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        let search = connection
            .open_table(crate::SEARCH_TABLE)
            .execute()
            .await
            .map_err(|_| StoreError::LanceDb)?;
        crate::query::L0002ProjectionWorker::new(journal.clone(), relations, search)
            .catch_up(&snapshot)
            .await?;
    }
    if crate::journal::read_journal_frontier(&journal).await? != frontier
        || journal.version().await.map_err(|_| StoreError::LanceDb)? != journal_version
    {
        return Err(StoreError::StoreCorrupt.into());
    }
    Ok(())
}

async fn rebuild_upgrade_native(native: &Path) -> Result<(), RestoreError> {
    let connection = lancedb::connect(native.to_str().ok_or(StoreError::InvalidPath)?)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    crate::migrations::L0002::apply(&connection).await?;
    let journal = connection
        .open_table(crate::JOURNAL_TABLE)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let objects = connection
        .open_table(crate::OBJECTS_TABLE)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let relations = connection
        .open_table(crate::RELATIONS_TABLE)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let search = connection
        .open_table(crate::SEARCH_TABLE)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let projected = crate::ProjectionWorker::new(journal.clone(), objects)
        .rebuild_for_restore()
        .await?;
    crate::query::L0002ProjectionWorker::new(journal, relations, search)
        .rebuild_for_restore(&projected)
        .await?;
    Ok(())
}

/// Read-only candidate validation: no writer, migration, catch-up or repair.
pub async fn verify_package_native(native: &Path, cas: &Path) -> Result<(), RestoreError> {
    let custody = evertrace_capture::ConfinedRoot::open_owned_private(native)
        .map_err(|_| StoreError::InvalidPath)?;
    let before = crate::backup::native_upgrade_manifest(native)?;
    let (_, persisted) = crate::backup::read_verified_store_tables(native).await?;
    if crate::JournalWriter::existing_profile(native).await? != Some("L0002") {
        return Err(StoreError::StoreCorrupt.into());
    }
    let connection = lancedb::connect(native.to_str().ok_or(StoreError::InvalidPath)?)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let journal = connection
        .open_table(crate::JOURNAL_TABLE)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let objects = connection
        .open_table(crate::OBJECTS_TABLE)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let expected = crate::ProjectionWorker::new(journal.clone(), objects)
        .full_snapshot()
        .await?;
    if expected != persisted {
        return Err(StoreError::Projection.into());
    }
    let relations = connection
        .open_table(crate::RELATIONS_TABLE)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let search = connection
        .open_table(crate::SEARCH_TABLE)
        .execute()
        .await
        .map_err(|_| StoreError::LanceDb)?;
    let actual = crate::query::L0002ProjectionWorker::new(journal, relations, search)
        .current()
        .await?;
    let derived = crate::query::derive_l0002_projections(&expected)?;
    if actual.frontier != derived.frontier
        || actual.relation_hash()? != derived.relation_hash()?
        || actual.search_hash()? != derived.search_hash()?
    {
        return Err(StoreError::Projection.into());
    }
    let references = expected.live_cas_refs()?;
    if !references.is_empty() {
        let cas = evertrace_capture::CasStore::open_existing(cas.to_owned())
            .map_err(|_| StoreError::StoreCorrupt)?;
        for reference in references {
            let digest = evertrace_capture::CasStore::parse_digest(&reference)
                .map_err(|_| StoreError::StoreCorrupt)?;
            cas.verify_envelope(&digest)
                .map_err(|_| StoreError::StoreCorrupt)?;
        }
    }
    custody
        .revalidate_stable()
        .map_err(|_| StoreError::StoreCorrupt)?;
    if before != crate::backup::native_upgrade_manifest(native)? {
        return Err(StoreError::StoreCorrupt.into());
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error(
        "native publication or rollback could not be confirmed; no cleanup was attempted: active locator {active}, preserved locator {preserved}"
    )]
    NativePublicationUncertain { active: PathBuf, preserved: PathBuf },
    #[error("restore store validation failed: {0}")]
    Store(#[from] StoreError),
    #[error("restore backup validation failed: {0}")]
    Backup(#[from] crate::BackupError),
    #[error("restore filesystem operation failed")]
    Io,
    #[error("operation stopped; preserved candidate or residual locator {directory}: {cause}")]
    ResidualCandidate {
        directory: PathBuf,
        cause: Box<RestoreError>,
    },
    #[error(
        "restore rollback failed; inspect active root {active}, preserved root {rollback}, candidate locator {candidate}, and configuration staging locators {config_staging:?}: {cause}"
    )]
    RollbackFailed {
        active: PathBuf,
        rollback: PathBuf,
        candidate: PathBuf,
        config_staging: Box<[PathBuf; 2]>,
        cause: Box<RestoreError>,
    },
    #[error(
        "restore rolled back but configuration cleanup failed; inspect staging locators {temporary} and {saved}: {cause}"
    )]
    ResidualConfiguration {
        temporary: PathBuf,
        saved: PathBuf,
        cause: Box<RestoreError>,
    },
}

/// A prepared candidate is never an activation receipt.
pub struct RestoreCandidate {
    writer: crate::JournalWriter,
    path: PathBuf,
}

impl RestoreCandidate {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn lock_inode_identity(&self) -> Result<(u64, u64), StoreError> {
        self.writer.lock_inode_identity()
    }

    pub async fn full_projection(&self) -> Result<crate::ProjectionSnapshot, StoreError> {
        self.writer.full_projection().await
    }

    pub async fn commit(
        &mut self,
        command: &crate::JournalCommand,
        at: i64,
    ) -> Result<(), StoreError> {
        self.writer.validate_restore_lock()?;
        self.writer.commit(command, at).await?;
        Ok(())
    }

    pub async fn rebuild_projections(&self) -> Result<(), StoreError> {
        self.writer.rebuild_restore_projections().await
    }

    /// The adapter validates its own fixed roles after the root has moved. No
    /// server or worker is started while the original sibling lock remains held.
    pub async fn activate(
        self,
        config_path: &Path,
        config_bytes: &[u8],
        validate_hook: impl Fn(&Path) -> Result<(), RestoreError>,
    ) -> Result<RestoreActivated, RestoreError> {
        self.activate_with_root_sync(
            config_path,
            config_bytes,
            validate_hook,
            std::fs::File::sync_all,
        )
        .await
    }

    async fn activate_with_root_sync(
        self,
        config_path: &Path,
        config_bytes: &[u8],
        validate_hook: impl Fn(&Path) -> Result<(), RestoreError>,
        sync_root: impl Fn(&std::fs::File) -> std::io::Result<()>,
    ) -> Result<RestoreActivated, RestoreError> {
        let path = self.path.clone();
        let custody = evertrace_capture::ConfinedRoot::open_owned_private(&path).map_err(|_| {
            RestoreError::ResidualCandidate {
                directory: path.clone(),
                cause: Box::new(RestoreError::Io),
            }
        })?;
        match self
            .activate_inner(config_path, config_bytes, validate_hook, sync_root)
            .await
        {
            Ok(value) => Ok(value),
            Err(error @ RestoreError::RollbackFailed { .. }) => Err(error),
            Err(cause) => {
                if remove_failed_candidate(&path, &custody).is_err() {
                    Err(RestoreError::ResidualCandidate {
                        directory: path,
                        cause: Box::new(cause),
                    })
                } else {
                    Err(cause)
                }
            }
        }
    }

    pub fn discard(self, cause: RestoreError) -> RestoreError {
        let custody = evertrace_capture::ConfinedRoot::open_owned_private(&self.path);
        drop(self.writer);
        if custody
            .as_ref()
            .is_ok_and(|root| remove_failed_candidate(&self.path, root).is_ok())
        {
            cause
        } else {
            RestoreError::ResidualCandidate {
                directory: self.path,
                cause: Box::new(cause),
            }
        }
    }

    async fn activate_inner(
        self,
        config_path: &Path,
        config_bytes: &[u8],
        validate_hook: impl Fn(&Path) -> Result<(), RestoreError>,
        sync_root: impl Fn(&std::fs::File) -> std::io::Result<()>,
    ) -> Result<RestoreActivated, RestoreError> {
        evertrace_domain::config::EffectiveConfig::parse_toml(
            std::str::from_utf8(config_bytes).map_err(|_| StoreError::InvalidInput)?,
        )
        .map_err(|_| StoreError::InvalidInput)?;
        self.writer.rebuild_restore_projections().await?;
        let expected = self.writer.full_projection().await?;
        let states = self.writer.backup_table_states().await?;
        let custody = evertrace_capture::ConfinedRoot::open_owned_private(&self.path)
            .map_err(|_| StoreError::StoreCorrupt)?;
        let candidate_identity = custody.identity();
        let mut closed = self.writer.close_for_backup();
        let active = closed.lock.data_dir().to_owned();
        let live_fence = evertrace_capture::MaintenanceFence::open(&active)
            .map_err(|_| StoreError::StoreCorrupt)?;
        let candidate_fence = evertrace_capture::MaintenanceFence::open(&self.path)
            .map_err(|_| StoreError::StoreCorrupt)?;
        let candidate_fence_identity =
            std::fs::symlink_metadata(candidate_fence.lock_path()).map_err(|_| RestoreError::Io)?;
        let _live_guard = live_fence
            .exclusive()
            .map_err(|_| StoreError::StoreCorrupt)?;
        let _candidate_guard = candidate_fence
            .exclusive()
            .map_err(|_| StoreError::StoreCorrupt)?;
        let parent = active.parent().ok_or(StoreError::InvalidPath)?;
        let data_parent =
            evertrace_capture::ConfinedRoot::open(parent).map_err(|_| StoreError::InvalidPath)?;
        let data_parent_file =
            std::fs::File::open(data_parent.proc_cwd_path().map_err(|_| RestoreError::Io)?)
                .map_err(|_| RestoreError::Io)?;
        let id = evertrace_domain::ids::JobId::new_v7();
        let rollback = parent.join(format!(
            "{}.rollback-{id}",
            active
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or(StoreError::InvalidPath)?
        ));
        let config_parent = config_path.parent().ok_or(StoreError::InvalidPath)?;
        let config_root = evertrace_capture::ConfinedRoot::open_owned_private(config_parent)
            .map_err(|_| StoreError::InvalidPath)?;
        // The held directory keeps these same-filesystem names usable even
        // when a configuration nested in the old root moves to rollback.
        let config_directory = config_root.proc_cwd_path().map_err(|_| RestoreError::Io)?;
        let config_temp = config_directory.join(format!(".restore-config-{id}.tmp"));
        let saved_name = format!(".restore-config-{id}.rollback");
        let config_saved = config_directory.join(&saved_name);
        let mut original_file = config_root
            .open_regular_file(Path::new(
                config_path.file_name().ok_or(StoreError::InvalidPath)?,
            ))
            .map_err(|_| StoreError::InvalidPath)?;
        let metadata = original_file.metadata().map_err(|_| RestoreError::Io)?;
        if metadata.mode() & 0o777 != 0o600
            || metadata.uid()
                != std::fs::metadata("/proc/self")
                    .map_err(|_| RestoreError::Io)?
                    .uid()
        {
            return Err(StoreError::InvalidPath.into());
        }
        let mut original = Vec::new();
        (&mut original_file)
            .take(1024 * 1024 + 1)
            .read_to_end(&mut original)
            .map_err(|_| RestoreError::Io)?;
        if original.len() > 1024 * 1024 {
            return Err(StoreError::InvalidInput.into());
        }
        let write_config = |path: &Path,
                            bytes: &[u8],
                            owned: &mut Option<std::fs::File>|
         -> Result<(), RestoreError> {
            *owned = Some(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|_| RestoreError::Io)?,
            );
            let file = owned.as_mut().ok_or(RestoreError::Io)?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| RestoreError::Io)
        };
        let remove_config =
            |path: &Path, owned: &Option<std::fs::File>| -> Result<(), RestoreError> {
                let Some(file) = owned else {
                    return Ok(());
                };
                let located = match std::fs::symlink_metadata(path) {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                    Err(_) => return Err(RestoreError::Io),
                };
                let held = file.metadata().map_err(|_| RestoreError::Io)?;
                if (located.dev(), located.ino()) != (held.dev(), held.ino()) {
                    return Err(StoreError::StoreCorrupt.into());
                }
                std::fs::remove_file(path).map_err(|_| RestoreError::Io)
            };
        let mut saved_file = None;
        let mut temp_file = None;
        let lock_inode = closed.lock.inode_identity()?;
        let original_identity = (metadata.dev(), metadata.ino());
        let old_root = std::fs::symlink_metadata(&active).map_err(|_| RestoreError::Io)?;
        let old_identity = (old_root.dev(), old_root.ino());
        let mut moved_old = false;
        let mut installed = false;
        let mut installed_config = false;
        let result = async {
            config_root
                .revalidate_stable()
                .map_err(|_| StoreError::StoreCorrupt)?;
            write_config(&config_saved, &original, &mut saved_file)?;
            config_root
                .revalidate_stable()
                .map_err(|_| StoreError::StoreCorrupt)?;
            write_config(&config_temp, config_bytes, &mut temp_file)?;
            std::fs::File::open(&config_directory)
                .and_then(|file| file.sync_all())
                .map_err(|_| RestoreError::Io)?;
            closed.lock.validate_held()?;
            custody
                .revalidate_stable()
                .map_err(|_| StoreError::StoreCorrupt)?;
            std::fs::rename(&active, &rollback).map_err(|_| RestoreError::Io)?;
            moved_old = true;
            std::fs::rename(&self.path, &active).map_err(|_| RestoreError::Io)?;
            installed = true;
            closed
                .lock
                .rebind_restored_root((candidate_identity.device, candidate_identity.inode))?;
            data_parent
                .revalidate_stable()
                .map_err(|_| StoreError::StoreCorrupt)?;
            sync_root(&data_parent_file).map_err(|_| RestoreError::Io)?;
            let (actual_states, actual) =
                crate::backup::read_verified_store_tables(&crate::connection::native_root(&active))
                    .await?;
            if actual_states != states || actual.rows != expected.rows {
                return Err(StoreError::StoreCorrupt.into());
            }
            validate_hook(&active)?;
            let old_config = config_path.strip_prefix(&active).map_or_else(
                |_| config_path.to_owned(),
                |relative| rollback.join(relative),
            );
            let located = std::fs::symlink_metadata(old_config).map_err(|_| RestoreError::Io)?;
            if (located.dev(), located.ino()) != original_identity
                || located.len() != metadata.len()
                || located.mtime() != metadata.mtime()
                || located.mtime_nsec() != metadata.mtime_nsec()
            {
                return Err(StoreError::StoreCorrupt.into());
            }
            // A configuration nested in the root may need its (previously
            // validated) parent recreated in the private restored tree.
            if config_parent.starts_with(&active) && !config_parent.exists() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(config_parent)
                    .map_err(|_| RestoreError::Io)?;
            }
            if !config_parent.starts_with(&active) {
                config_root
                    .revalidate_stable()
                    .map_err(|_| StoreError::StoreCorrupt)?;
            }
            let destination = evertrace_capture::ConfinedRoot::open_owned_private(config_parent)
                .map_err(|_| StoreError::InvalidPath)?;
            let destination_directory =
                destination.proc_cwd_path().map_err(|_| RestoreError::Io)?;
            destination
                .revalidate_stable()
                .map_err(|_| StoreError::StoreCorrupt)?;
            std::fs::rename(
                &config_temp,
                destination_directory.join(config_path.file_name().ok_or(StoreError::InvalidPath)?),
            )
            .map_err(|_| RestoreError::Io)?;
            installed_config = true;
            std::fs::File::open(&destination_directory)
                .and_then(|file| file.sync_all())
                .map_err(|_| RestoreError::Io)?;
            // For an in-root configuration the source and destination parents
            // are distinct directories after the root swap.
            std::fs::File::open(&config_directory)
                .and_then(|file| file.sync_all())
                .map_err(|_| RestoreError::Io)?;
            validate_hook(&active)?;
            closed.lock.validate_held()?;
            Ok::<(), RestoreError>(())
        }
        .await;
        if let Err(cause) = result {
            let rollback_result = (|| -> Result<(), RestoreError> {
                if installed {
                    let located =
                        std::fs::symlink_metadata(&active).map_err(|_| RestoreError::Io)?;
                    if (located.dev(), located.ino())
                        != (candidate_identity.device, candidate_identity.inode)
                        || std::fs::symlink_metadata(&self.path).is_ok()
                    {
                        return Err(StoreError::StoreCorrupt.into());
                    }
                }
                if moved_old {
                    let located =
                        std::fs::symlink_metadata(&rollback).map_err(|_| RestoreError::Io)?;
                    if (located.dev(), located.ino()) != old_identity {
                        return Err(StoreError::StoreCorrupt.into());
                    }
                }
                if installed_config && !config_path.starts_with(&active) {
                    config_root
                        .revalidate_stable()
                        .map_err(|_| StoreError::StoreCorrupt)?;
                    let located =
                        std::fs::symlink_metadata(config_path).map_err(|_| RestoreError::Io)?;
                    let held = temp_file
                        .as_ref()
                        .ok_or(RestoreError::Io)?
                        .metadata()
                        .map_err(|_| RestoreError::Io)?;
                    if (located.dev(), located.ino()) != (held.dev(), held.ino()) {
                        return Err(StoreError::StoreCorrupt.into());
                    }
                    std::fs::rename(
                        &config_saved,
                        config_directory
                            .join(config_path.file_name().ok_or(StoreError::InvalidPath)?),
                    )
                    .map_err(|_| RestoreError::Io)?;
                    std::fs::File::open(&config_directory)
                        .and_then(|file| file.sync_all())
                        .map_err(|_| RestoreError::Io)?;
                }
                if installed {
                    std::fs::rename(&active, &self.path).map_err(|_| RestoreError::Io)?;
                }
                if moved_old {
                    std::fs::rename(&rollback, &active).map_err(|_| RestoreError::Io)?;
                }
                closed.lock.rebind_restored_root(old_identity)?;
                data_parent
                    .revalidate_stable()
                    .map_err(|_| StoreError::StoreCorrupt)?;
                sync_root(&data_parent_file).map_err(|_| RestoreError::Io)?;
                Ok(())
            })();
            if rollback_result.is_err() {
                let old_root_restored = std::fs::symlink_metadata(&active)
                    .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == old_identity);
                let staging_parent = config_parent.strip_prefix(&active).map_or_else(
                    |_| config_parent.to_owned(),
                    |relative| {
                        if old_root_restored {
                            active.join(relative)
                        } else {
                            rollback.join(relative)
                        }
                    },
                );
                return Err(RestoreError::RollbackFailed {
                    config_staging: Box::new([
                        staging_parent
                            .join(config_temp.file_name().ok_or(StoreError::InvalidPath)?),
                        staging_parent.join(&saved_name),
                    ]),
                    active,
                    rollback,
                    candidate: self.path,
                    cause: Box::new(cause),
                });
            }
            if remove_config(&config_temp, &temp_file)
                .and_then(|()| remove_config(&config_saved, &saved_file))
                .and_then(|()| {
                    std::fs::File::open(&config_directory)
                        .and_then(|file| file.sync_all())
                        .map_err(|_| RestoreError::Io)
                })
                .is_err()
            {
                return Err(RestoreError::ResidualConfiguration {
                    temporary: config_parent
                        .join(config_temp.file_name().ok_or(StoreError::InvalidPath)?),
                    saved: config_parent.join(&saved_name),
                    cause: Box::new(cause),
                });
            }
            return Err(cause);
        }
        let retained_config_backup = remove_config(&config_saved, &saved_file).err().map(|_| {
            config_parent
                .strip_prefix(&active)
                .map_or_else(
                    |_| config_parent.to_owned(),
                    |relative| rollback.join(relative),
                )
                .join(&saved_name)
        });
        let retained_config_backup = if std::fs::File::open(&config_directory)
            .and_then(|file| file.sync_all())
            .is_err()
        {
            Some(
                config_parent
                    .strip_prefix(&active)
                    .map_or_else(
                        |_| config_parent.to_owned(),
                        |relative| rollback.join(relative),
                    )
                    .join(&saved_name),
            )
        } else {
            retained_config_backup
        };
        // This final checked parent sync also covers removal of the saved
        // configuration. Cleanup warnings do not hide a committed activation.
        let retained_candidate_fence =
            remove_candidate_fence(&candidate_fence, &candidate_fence_identity)
                .err()
                .map(|_| candidate_fence.lock_path().to_owned());
        Ok(RestoreActivated {
            rollback_root: rollback,
            lock_inode,
            retained_config_backup,
            retained_candidate_fence,
        })
    }
}

pub struct RestoreActivated {
    /// The former root is preserved, including backup/export assets not present
    /// in the restored include set; it is never silently garbage-collected.
    pub rollback_root: PathBuf,
    pub lock_inode: (u64, u64),
    pub retained_config_backup: Option<PathBuf>,
    pub retained_candidate_fence: Option<PathBuf>,
}

pub enum RestorePreparation {
    Historical { directory: PathBuf },
    Candidate(Box<RestoreCandidate>),
}

pub async fn prepare(
    data_dir: &Path,
    backup: &Path,
    occurred_at_us: i64,
    config_hash: [u8; 32],
) -> Result<RestorePreparation, RestoreError> {
    let lock = crate::SiblingWriterLock::acquire(data_dir)?;
    let current_exists = crate::connection::native_root(data_dir)
        .join(format!("{}.lance", crate::JOURNAL_TABLE))
        .exists();
    let source = crate::backup::prepare_verification_directory(backup, None)?;
    let parent = data_dir.parent().ok_or(StoreError::InvalidPath)?;
    let name = data_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(StoreError::InvalidPath)?;
    let path = parent.join(format!(
        "{name}.restore-{}",
        evertrace_domain::ids::JobId::new_v7()
    ));
    crate::backup::check_restore_copy_budget(&source, &path)?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| RestoreError::Io)?;
    let custody = evertrace_capture::ConfinedRoot::open_owned_private(&path).map_err(|_| {
        RestoreError::ResidualCandidate {
            directory: path.clone(),
            cause: Box::new(RestoreError::Io),
        }
    })?;
    let result = async {
        crate::backup::copy_restore_candidate(&source, &path, &custody)?;
        let verified = crate::backup::prepare_verification_directory(&path, None)?;
        crate::backup::complete_backup_verification_ref(&verified).await?;
        if !current_exists {
            return Ok(RestorePreparation::Historical {
                directory: path.clone(),
            });
        }
        let current_writer = crate::JournalWriter::open_with_lock(lock).await?;
        let ledger = CurrentLedger::read(&current_writer).await?;
        let mut writer = current_writer
            .close_for_backup()
            .open_restore_candidate(&path)
            .await?;
        let physical = candidate_scope_refs(&writer, &ledger).await?;
        writer
            .import_restore_ledger(&ledger, occurred_at_us, config_hash)
            .await?;
        complete_candidate_deletions(
            &mut writer,
            &path,
            &ledger,
            physical,
            occurred_at_us,
            config_hash,
        )
        .await?;
        reset_runtime_authority(&mut writer, occurred_at_us, config_hash).await?;
        writer.rebuild_restore_projections().await?;
        Ok(RestorePreparation::Candidate(Box::new(RestoreCandidate {
            writer,
            path: path.clone(),
        })))
    }
    .await;
    match result {
        Ok(prepared) => Ok(prepared),
        Err(cause) => {
            if remove_failed_candidate(&path, &custody).is_err() {
                return Err(RestoreError::ResidualCandidate {
                    directory: path,
                    cause: Box::new(cause),
                });
            }
            Err(cause)
        }
    }
}

fn remove_failed_candidate(
    path: &Path,
    custody: &evertrace_capture::ConfinedRoot,
) -> Result<(), RestoreError> {
    custody.revalidate_stable().map_err(|_| RestoreError::Io)?;
    let fence = evertrace_capture::MaintenanceFence::open(path).map_err(|_| RestoreError::Io)?;
    let fence_identity =
        std::fs::symlink_metadata(fence.lock_path()).map_err(|_| RestoreError::Io)?;
    remove_owned_candidate_tree(path, custody)?;
    remove_candidate_fence(&fence, &fence_identity).map_err(|cause| {
        RestoreError::ResidualCandidate {
            directory: fence.lock_path().to_owned(),
            cause: Box::new(cause),
        }
    })
}

fn remove_owned_candidate_tree(
    path: &Path,
    custody: &evertrace_capture::ConfinedRoot,
) -> Result<(), RestoreError> {
    custody.revalidate_stable().map_err(|_| RestoreError::Io)?;
    // Delete through the held directory, never recursively through a replaced locator.
    let held = custody.proc_cwd_path().map_err(|_| RestoreError::Io)?;
    for entry in std::fs::read_dir(held).map_err(|_| RestoreError::Io)? {
        let entry = entry.map_err(|_| RestoreError::Io)?;
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| RestoreError::Io)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            std::fs::remove_dir_all(entry.path()).map_err(|_| RestoreError::Io)?;
        } else {
            std::fs::remove_file(entry.path()).map_err(|_| RestoreError::Io)?;
        }
    }
    custody.revalidate_stable().map_err(|_| RestoreError::Io)?;
    std::fs::remove_dir(path).map_err(|_| RestoreError::Io)?;
    std::fs::File::open(path.parent().ok_or(StoreError::InvalidPath)?)
        .and_then(|file| file.sync_all())
        .map_err(|_| RestoreError::Io)
}

fn remove_candidate_fence(
    fence: &evertrace_capture::MaintenanceFence,
    identity: &std::fs::Metadata,
) -> Result<(), RestoreError> {
    let located = std::fs::symlink_metadata(fence.lock_path()).map_err(|_| RestoreError::Io)?;
    if (located.dev(), located.ino()) != (identity.dev(), identity.ino()) {
        return Err(StoreError::StoreCorrupt.into());
    }
    std::fs::remove_file(fence.lock_path()).map_err(|_| RestoreError::Io)?;
    std::fs::File::open(fence.lock_path().parent().ok_or(StoreError::InvalidPath)?)
        .and_then(|file| file.sync_all())
        .map_err(|_| RestoreError::Io)
}

async fn reset_runtime_authority(
    writer: &mut crate::JournalWriter,
    occurred_at_us: i64,
    config_hash: [u8; 32],
) -> Result<(), StoreError> {
    let snapshot = writer.full_projection().await?;
    let mut payloads = Vec::new();
    for row in snapshot.data_rows() {
        let Some(json) = &row.payload_json else {
            continue;
        };
        let payload: JournalPayload =
            serde_json::from_str(json).map_err(|_| StoreError::StoreCorrupt)?;
        match payload {
            JournalPayload::JobState(mut job) if job.state == crate::JobStatus::Leased => {
                job.state = crate::JobStatus::Queued;
                job.lease_until_us = None;
                job.backoff_until_us = None;
                payloads.push(JournalPayload::JobState(job));
            }
            JournalPayload::RecallLedgerRecorded(event) => {
                use evertrace_domain::recall::{
                    PresentationAttemptState, RecallDeliveryState, RecallLedgerEvent,
                    RecallObligationState, RecallPresentationAttempt,
                };
                if let RecallLedgerEvent::NeedRecorded { need } = *event
                    && need.obligation_state == RecallObligationState::Active
                    && need.delivery_state == RecallDeliveryState::ClaimedForBoundary
                {
                    payloads.push(JournalPayload::RecallLedgerRecorded(Box::new(
                        RecallLedgerEvent::PresentationAttempt {
                            attempt: RecallPresentationAttempt {
                                presentation_attempt_id: need
                                    .active_presentation_attempt_id
                                    .ok_or(StoreError::StoreCorrupt)?,
                                recall_need_id: need.recall_need_id,
                                recall_need_hash: need.recall_need_hash,
                                boundary_event_ref: need.boundary_event_ref,
                                state: PresentationAttemptState::PresentationUnknown,
                                occurred_at_us,
                            },
                        },
                    )));
                }
            }
            _ => {}
        }
    }
    for payload in payloads {
        let command = crate::JournalCommand::new(
            evertrace_domain::ids::CommandId::new_v7(),
            vec![crate::JournalEventDraft::runtime(
                occurred_at_us,
                config_hash,
                "offline_restore_runtime_v1",
                payload,
            )],
        )?;
        writer.commit(&command, occurred_at_us).await?;
    }
    Ok(())
}

pub(crate) const LEDGER_REVISION: &str = "offline_restore_ledger_v1";

/// Current authority captured from a fully replayed live journal while its one
/// writer lock remains held. There is no constructor accepting caller payloads.
pub(crate) struct CurrentLedger {
    lock_inode: (u64, u64),
    object: crate::ObjectDeletionCurrentView,
    scope: crate::ScopePurgeCurrentView,
    jobs: Vec<crate::DurableJob>,
    scope_plans: std::collections::BTreeMap<evertrace_domain::ids::RepositoryId, Vec<String>>,
}

impl CurrentLedger {
    async fn read(writer: &crate::JournalWriter) -> Result<Self, StoreError> {
        writer.validate_restore_lock()?;
        let snapshot = writer.full_projection().await?;
        let mut result = Self {
            lock_inode: writer.lock_inode_identity()?,
            object: crate::ObjectDeletionCurrentView::from_snapshot(&snapshot)?,
            scope: crate::ScopePurgeCurrentView::from_snapshot(&snapshot)?,
            jobs: crate::RuntimeSchedulerView::from_snapshot(&snapshot)?.jobs,
            scope_plans: std::collections::BTreeMap::new(),
        };
        for progress in result.scope.events.values() {
            if progress.stage == evertrace_domain::purge::ScopePurgeStage::Purged {
                continue;
            }
            let confirmed = writer
                .projection_worker()
                .project_at_frontier(progress.confirmation_frontier)
                .await?;
            let plan = crate::repository_scope_purge_preview(
                &confirmed,
                progress.target.repository_id(),
                progress.target.repository_revision(),
            )?;
            let job = result
                .jobs
                .iter()
                .find(|job| job.job_id == progress.purge_job_id)
                .ok_or(StoreError::StoreCorrupt)?;
            if plan.deletion_generation != progress.deletion_generation
                || plan.physical_item_count()? != job.budget.max_items
            {
                return Err(StoreError::StoreCorrupt);
            }
            result
                .scope_plans
                .insert(progress.target.repository_id(), plan.exclusive_cas_refs);
        }
        writer.validate_restore_lock()?;
        Ok(result)
    }

    pub(crate) fn commands(
        &self,
        writer: &crate::JournalWriter,
        occurred_at_us: i64,
        config_hash: [u8; 32],
    ) -> Result<impl Iterator<Item = Result<crate::JournalCommand, StoreError>> + '_, StoreError>
    {
        writer.validate_restore_lock()?;
        if writer.lock_inode_identity()? != self.lock_inode {
            return Err(StoreError::StoreCorrupt);
        }
        let events = self
            .object
            .events
            .values()
            .cloned()
            .map(|event| JournalPayload::ObjectDeletionLedgerRecorded(Box::new(event)))
            .chain(
                self.scope
                    .events
                    .values()
                    .cloned()
                    .map(|event| JournalPayload::ScopePurgeProgressRecorded(Box::new(event))),
            )
            .map(move |payload| {
                crate::JournalEventDraft::runtime(
                    occurred_at_us,
                    config_hash,
                    LEDGER_REVISION,
                    payload,
                )
            });
        Ok(ledger_commands(events))
    }
}

fn ledger_commands(
    mut events: impl Iterator<Item = crate::JournalEventDraft>,
) -> impl Iterator<Item = Result<crate::JournalCommand, StoreError>> {
    std::iter::from_fn(move || {
        let batch = events
            .by_ref()
            .take(usize::from(u16::MAX))
            .collect::<Vec<_>>();
        if batch.is_empty() {
            return None;
        }
        Some(crate::JournalCommand::new(
            evertrace_domain::ids::CommandId::new_v7(),
            batch,
        ))
    })
}

async fn candidate_scope_refs(
    writer: &crate::JournalWriter,
    current: &CurrentLedger,
) -> Result<std::collections::BTreeSet<String>, StoreError> {
    let snapshot = writer.full_projection().await?;
    let existing = crate::ScopePurgeCurrentView::from_snapshot(&snapshot)?;
    let mut refs = std::collections::BTreeSet::new();
    for progress in current.scope.events.values() {
        let target = progress.target.repository_id();
        let basis = if let Some(previous) = existing.events.get(&target)
            && previous.stage != evertrace_domain::purge::ScopePurgeStage::Purged
        {
            writer
                .projection_worker()
                .project_at_frontier(previous.confirmation_frontier)
                .await?
        } else {
            snapshot.clone()
        };
        if let Some(repository) = crate::repository::RepositoryCurrentView::from_snapshot(&basis)?
            .repositories
            .get(&target)
        {
            let preview = crate::repository_scope_purge_preview(
                &basis,
                target,
                repository.repository_revision,
            )?;
            if !preview.blockers.is_empty() {
                return Err(StoreError::InvalidInput);
            }
            refs.extend(preview.exclusive_cas_refs);
        }
    }
    refs.extend(current.scope_plans.values().flatten().cloned());
    Ok(refs)
}

async fn restore_commit(
    writer: &mut crate::JournalWriter,
    payloads: Vec<JournalPayload>,
    at: i64,
    config: [u8; 32],
) -> Result<(), StoreError> {
    let command = crate::JournalCommand::new(
        evertrace_domain::ids::CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| {
                crate::JournalEventDraft::runtime(at, config, "offline_restore_runtime_v1", payload)
            })
            .collect(),
    )?;
    writer.commit(&command, at).await?;
    Ok(())
}

async fn restore_purge_job(
    writer: &mut crate::JournalWriter,
    current: &CurrentLedger,
    job_id: evertrace_domain::ids::JobId,
    at: i64,
    config: [u8; 32],
) -> Result<crate::DurableJob, StoreError> {
    let view = crate::RuntimeSchedulerView::from_snapshot(&writer.full_projection().await?)?;
    let authoritative = current
        .jobs
        .iter()
        .find(|job| job.job_id == job_id)
        .ok_or(StoreError::StoreCorrupt)?;
    let mut job = if let Some(job) = view.jobs.into_iter().find(|job| job.job_id == job_id) {
        let mut expected = authoritative.clone();
        expected.state = job.state;
        expected.attempt = job.attempt;
        expected.lease_until_us = job.lease_until_us;
        expected.backoff_until_us = job.backoff_until_us;
        expected.terminal = job.terminal.clone();
        if expected != job {
            return Err(StoreError::StoreCorrupt);
        }
        job
    } else {
        let mut job = authoritative.clone();
        job.state = crate::JobStatus::Queued;
        job.lease_until_us = None;
        job.backoff_until_us = None;
        job.terminal = None;
        restore_commit(
            writer,
            vec![JournalPayload::JobState(job.clone())],
            at,
            config,
        )
        .await?;
        job
    };
    if job.state == crate::JobStatus::Leased
        || job.state == crate::JobStatus::Failed
            && job.backoff_until_us.is_none_or(|deadline| deadline <= at)
    {
        if job.state == crate::JobStatus::Failed {
            job.attempt = job.attempt.checked_add(1).ok_or(StoreError::InvalidInput)?;
        }
        job.state = crate::JobStatus::Queued;
        job.lease_until_us = None;
        job.backoff_until_us = None;
        job.terminal = None;
        restore_commit(
            writer,
            vec![JournalPayload::JobState(job.clone())],
            at,
            config,
        )
        .await?;
    }
    if job.state != crate::JobStatus::Queued {
        return Err(StoreError::InvalidInput);
    }
    Ok(job)
}

async fn complete_candidate_deletions(
    writer: &mut crate::JournalWriter,
    path: &Path,
    current: &CurrentLedger,
    refs: std::collections::BTreeSet<String>,
    at: i64,
    config: [u8; 32],
) -> Result<(), RestoreError> {
    use evertrace_domain::purge::{ObjectDeletionPhase, ScopePurgeStage};
    let mut runtime = evertrace_capture::RuntimeSnapshot::load(
        &evertrace_capture::RuntimeSnapshot::snapshot_path(path),
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    runtime.cas_dir = path.join("cas");
    runtime.spool_dir = path.join("spool");
    evertrace_capture::CasStore::open(&runtime.cas_dir).map_err(|_| StoreError::StoreCorrupt)?;
    let fence =
        evertrace_capture::MaintenanceFence::open(path).map_err(|_| StoreError::StoreCorrupt)?;
    let guard = fence.exclusive().map_err(|_| StoreError::StoreCorrupt)?;
    let snapshot = writer.full_projection().await?;
    let mut pins = snapshot.live_cas_refs_intersect(&refs)?;
    let limits = runtime
        .spool_limits()
        .map_err(|_| StoreError::StoreCorrupt)?;
    let (spool, _) = evertrace_capture::DurableSpool::open(runtime.spool_dir.clone(), limits)
        .map_err(|_| StoreError::StoreCorrupt)?;
    pins.extend(
        spool
            .durable_cas_refs_intersect(
                &refs,
                limits.max_main_files as usize,
                limits.high_watermark_bytes,
            )
            .map_err(|_| StoreError::StoreCorrupt)?,
    );
    let delete = refs
        .difference(&pins)
        .map(|value| {
            evertrace_capture::CasStore::parse_digest(value).map_err(|_| StoreError::StoreCorrupt)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for chunk in delete.chunks(crate::purge::REPOSITORY_SCOPE_PURGE_BATCH_SIZE as usize) {
        evertrace_capture::CasStore::delete_guarded_batch(&guard, chunk)
            .map_err(|_| StoreError::StoreCorrupt)?;
    }
    for event in current
        .object
        .events
        .values()
        .filter(|event| event.phase == ObjectDeletionPhase::Pending)
    {
        let job = restore_purge_job(writer, current, event.purge_job_id, at, config).await?;
        let (terminal, lease, job) = crate::purge::purged_object_deletion(event, &job, at)?;
        restore_commit(
            writer,
            vec![
                JournalPayload::ObjectDeletionLedgerRecorded(Box::new(terminal)),
                JournalPayload::JobLease(lease),
                JournalPayload::JobState(job),
            ],
            at,
            config,
        )
        .await?;
    }
    for event in current
        .scope
        .events
        .values()
        .filter(|event| event.stage != ScopePurgeStage::Purged)
    {
        let mut progress = event.clone();
        let mut job = restore_purge_job(writer, current, event.purge_job_id, at, config).await?;
        loop {
            let lease = crate::JobLease {
                job_id: job.job_id,
                target_generation: job.target_generation,
                attempt: job.attempt.checked_add(1).ok_or(StoreError::InvalidInput)?,
                lease_until_us: at.checked_add(30_000_000).ok_or(StoreError::InvalidInput)?,
            };
            restore_commit(
                writer,
                vec![JournalPayload::JobLease(lease.clone())],
                at,
                config,
            )
            .await?;
            job.state = crate::JobStatus::Leased;
            job.attempt = lease.attempt;
            job.lease_until_us = Some(lease.lease_until_us);
            let (stage, ordinal) = if progress.stage == ScopePurgeStage::Pending {
                (ScopePurgeStage::ProjectionClosed, 0)
            } else if progress.next_ordinal < u64::from(job.budget.max_items) {
                (
                    ScopePurgeStage::PhysicalDeleting,
                    progress
                        .next_ordinal
                        .saturating_add(crate::purge::REPOSITORY_SCOPE_PURGE_BATCH_SIZE)
                        .min(u64::from(job.budget.max_items)),
                )
            } else {
                (ScopePurgeStage::Purged, progress.next_ordinal)
            };
            let next = crate::purge::advance_repository_scope_purge(&progress, stage, ordinal, at)?;
            if stage == ScopePurgeStage::Purged {
                let terminal = crate::purge::terminal_repository_scope_purge_job(&progress, &job)?;
                restore_commit(
                    writer,
                    vec![
                        JournalPayload::ScopePurgeProgressRecorded(Box::new(next)),
                        JournalPayload::JobState(terminal),
                    ],
                    at,
                    config,
                )
                .await?;
                break;
            }
            job.state = crate::JobStatus::Queued;
            job.lease_until_us = None;
            job.backoff_until_us = None;
            restore_commit(
                writer,
                vec![
                    JournalPayload::ScopePurgeProgressRecorded(Box::new(next.clone())),
                    JournalPayload::JobState(job.clone()),
                ],
                at,
                config,
            )
            .await?;
            progress = next;
        }
    }
    Ok(())
}

/// This distinguishes a persisted restore command, not caller authorization.
/// Ordinary writer admission must reject this revision before idempotency lookup.
pub(crate) fn ledger_command(rows: &[&JournalRow]) -> Result<bool, StoreError> {
    if !rows
        .iter()
        .any(|row| row.algorithm_revision == LEDGER_REVISION)
    {
        return Ok(false);
    }
    for row in rows {
        if row.algorithm_revision != LEDGER_REVISION
            || row.source_kind != SourceKind::System
            || row.scope != EventScope::default()
            || row.causation_id.is_some()
            || row.correlation_id.is_some()
            || rows.first().is_some_and(|first| {
                row.effective_config_hash != first.effective_config_hash
                    || row.occurred_at_us != first.occurred_at_us
            })
        {
            return Err(StoreError::StoreCorrupt);
        }
        let payload = row.payload()?;
        payload.validate().map_err(|_| StoreError::StoreCorrupt)?;
        if !matches!(
            payload,
            JournalPayload::ObjectDeletionLedgerRecorded(_)
                | JournalPayload::ScopePurgeProgressRecorded(_)
        ) {
            return Err(StoreError::StoreCorrupt);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JobLease, JournalEventDraft};
    use evertrace_domain::ids::JobId;

    async fn upgrade_fixture(data: &Path, canonical: bool) -> PathBuf {
        use evertrace_capture::{
            RecallCueGateMode, RecoveryGateMode, RecoverySnapshotSettings, RuntimeSnapshot,
            SpoolLimits,
        };
        use std::os::unix::fs::PermissionsExt;
        std::fs::DirBuilder::new().mode(0o700).create(data).unwrap();
        let native = if canonical {
            data.join("store")
        } else {
            data.to_owned()
        };
        if canonical {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&native)
                .unwrap();
        }
        let connection = lancedb::connect(native.to_str().unwrap())
            .execute()
            .await
            .unwrap();
        crate::L0001::apply(&connection).await.unwrap();
        let journal = connection
            .open_table(crate::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        let pending = crate::JournalCommand::new(
            evertrace_domain::ids::CommandId::new_v7(),
            vec![crate::JournalEventDraft::runtime(
                1,
                [0; 32],
                "upgrade-lag-proof",
                crate::JournalPayload::DirtyTarget(crate::DirtyTarget {
                    target_kind: crate::DirtyTargetKind::ObjectsProjection,
                    target_id: "objects".into(),
                    algorithm_revision: "upgrade-lag-proof".into(),
                    source_watermark: 1,
                }),
            )],
        )
        .unwrap();
        crate::journal::append_rows(
            &journal,
            &crate::journal::rows_for_append(&crate::prepare_command(&pending).unwrap(), 2, 1)
                .unwrap(),
        )
        .await
        .unwrap();
        drop(journal);
        drop(connection);
        let config = evertrace_domain::config::EffectiveConfig::default();
        let path = data.parent().unwrap().join("config.toml");
        std::fs::write(&path, config.to_toml().unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let runtime = RuntimeSnapshot::for_data_dir(
            data,
            1,
            SpoolLimits {
                high_watermark_bytes: 4 << 20,
                low_watermark_bytes: 64 << 10,
                max_main_files: 16,
                emergency_slots: 2,
            },
            RecoverySnapshotSettings {
                gate: RecoveryGateMode::Disabled,
                preflight_timeout_ms: 250,
                effective_config_hash: config.hash(),
                adapter_manifest_id: None,
                classifier_revision: 1,
                max_bundle_bytes: 4 << 20,
                max_untracked_file_bytes: 1 << 20,
                max_untracked_total_bytes: 2 << 20,
                recall_cue_gate: RecallCueGateMode::Disabled,
                recall_cue_adapter_manifest_id: None,
            },
        )
        .unwrap();
        runtime
            .publish(&RuntimeSnapshot::snapshot_path(data))
            .unwrap();
        evertrace_capture::CasStore::open(runtime.cas_dir).unwrap();
        path
    }

    fn empty_hook() -> Result<crate::backup::BackupHookBoundary, crate::BackupError> {
        Ok(crate::backup::BackupHookBoundary {
            current_generation: None,
            retained_generations: Vec::new(),
            pin_count: 0,
            pinned_generation_count: 0,
            files: Vec::new(),
        })
    }

    #[tokio::test]
    async fn native_upgrade_rolls_back_before_resuming_writes() {
        for (canonical, failure) in [
            (false, NativePublicationPoint::Prepared),
            (false, NativePublicationPoint::Published),
            (true, NativePublicationPoint::Published),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("data");
            let config = upgrade_fixture(&data, canonical).await;
            let source = if canonical {
                data.join("store")
            } else {
                data.clone()
            };
            let original = std::fs::metadata(&source).unwrap().ino();
            let journal_files = |files: Vec<crate::backup::BackupFileManifest>| {
                files
                    .into_iter()
                    .filter(|entry| {
                        entry
                            .relative_path
                            .starts_with(&format!("store/{}.lance", crate::JOURNAL_TABLE))
                    })
                    .collect::<Vec<_>>()
            };
            let original_journal =
                journal_files(crate::backup::native_upgrade_manifest(&source).unwrap());
            let (before, _) = crate::backup::read_verified_store_tables(&source)
                .await
                .unwrap();
            assert!(before.objects.checkpoint < before.journal.checkpoint);
            let shared_capture = std::cell::RefCell::new(None);
            let sibling_identity = std::cell::Cell::new(None);
            let result = upgrade_native_inner(
                &data,
                &config,
                empty_hook,
                |_, _| Ok(()),
                |point| {
                    if point == NativePublicationPoint::BackupFrozen {
                        let fence = evertrace_capture::MaintenanceFence::open(&data).unwrap();
                        *shared_capture.borrow_mut() = Some(fence.shared().unwrap());
                        let metadata =
                            std::fs::metadata(data.with_extension("writer.lock")).unwrap();
                        sibling_identity.set(Some((metadata.dev(), metadata.ino())));
                    }
                    if point == NativePublicationPoint::Published {
                        let metadata =
                            std::fs::metadata(data.with_extension("writer.lock")).unwrap();
                        assert_eq!(
                            sibling_identity.get(),
                            Some((metadata.dev(), metadata.ino()))
                        );
                        let status = std::process::Command::new(std::env::current_exe().unwrap())
                            .args([
                                "--exact",
                                "restore::tests::native_upgrade_process_exit_has_one_restart_entry",
                                "--test-threads=1",
                            ])
                            .env("EVERTRACE_TEST_NATIVE_UPGRADE_ROOT", &data)
                            .env("EVERTRACE_TEST_NATIVE_UPGRADE_POINT", "LockProbe")
                            .status()
                            .unwrap();
                        assert_eq!(status.code(), Some(78));
                    }
                    if point == failure {
                        Err(RestoreError::Io)
                    } else {
                        Ok(())
                    }
                },
            )
            .await;
            assert!(
                shared_capture.borrow().is_some(),
                "capture shared guard spans backup verification and native publication"
            );
            assert!(matches!(result, Err(RestoreError::Io)));
            assert_eq!(std::fs::metadata(&source).unwrap().ino(), original);
            assert_eq!(
                journal_files(crate::backup::native_upgrade_manifest(&source).unwrap()),
                original_journal
            );
            let (caught_up, _) = crate::backup::read_verified_store_tables(&source)
                .await
                .unwrap();
            assert_eq!(caught_up.objects.checkpoint, caught_up.journal.checkpoint);
            assert_eq!(
                crate::JournalWriter::existing_profile(&source)
                    .await
                    .unwrap(),
                Some("L0001")
            );
            assert!(!std::fs::read_dir(&data).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".upgrade-")
            }));
            assert!(matches!(
                crate::JournalWriter::open(&data).await,
                Err(StoreError::UpgradeRequired)
            ));
        }
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let config = upgrade_fixture(&data, false).await;
        let result = upgrade_native_inner(
            &data,
            &config,
            empty_hook,
            |_, _| Ok(()),
            |point| {
                if point == NativePublicationPoint::Prepared {
                    std::fs::create_dir(data.join("store")).unwrap();
                    std::fs::write(data.join("store/unknown-user-asset"), b"keep").unwrap();
                }
                Ok(())
            },
        )
        .await;
        assert!(matches!(result, Err(RestoreError::Io)));
        assert_eq!(
            std::fs::read(data.join("store/unknown-user-asset")).unwrap(),
            b"keep"
        );
        assert!(!std::fs::read_dir(&data).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".upgrade-")
        }));
    }

    #[tokio::test]
    async fn native_upgrade_preserves_replaced_flat_table() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let config = upgrade_fixture(&data, false).await;
        let original = data.join(format!("{}.lance", crate::JOURNAL_TABLE));
        let moved = temp.path().join("original-journal");
        let outcome = upgrade_native_inner(
            &data,
            &config,
            empty_hook,
            |_, _| Ok(()),
            |point| {
                if point == NativePublicationPoint::Durable {
                    std::fs::rename(&original, &moved).unwrap();
                    std::fs::create_dir(&original).unwrap();
                    std::fs::write(original.join("unknown"), b"keep").unwrap();
                }
                Ok(())
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, NativeUpgradeOutcome::Published { retained_native, .. }
            if retained_native == vec![original.clone()])
        );
        assert_eq!(std::fs::read(original.join("unknown")).unwrap(), b"keep");
        assert!(moved.is_dir());
        assert!(
            !data
                .join(format!("{}.lance", crate::OBJECTS_TABLE))
                .exists()
        );
        crate::JournalWriter::open(&data).await.unwrap();
    }

    #[tokio::test]
    async fn native_upgrade_process_exit_has_one_restart_entry() {
        const CHILD_ROOT: &str = "EVERTRACE_TEST_NATIVE_UPGRADE_ROOT";
        const CHILD_POINT: &str = "EVERTRACE_TEST_NATIVE_UPGRADE_POINT";
        if let Some(path) = std::env::var_os(CHILD_ROOT) {
            let data = PathBuf::from(path);
            let wanted = std::env::var(CHILD_POINT).unwrap();
            if wanted == "LockProbe" {
                assert!(matches!(
                    crate::SiblingWriterLock::acquire(&data),
                    Err(StoreError::WriterAlreadyRunning)
                ));
                std::process::exit(78);
            }
            upgrade_native_inner(
                &data,
                &data.parent().unwrap().join("config.toml"),
                empty_hook,
                |_, _| Ok(()),
                |point| {
                    if format!("{point:?}") == wanted {
                        std::process::exit(77);
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
            panic!("publication checkpoint was not reached");
        }
        for (canonical, point) in [(false, "Prepared"), (false, "Durable"), (true, "Durable")] {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("data");
            upgrade_fixture(&data, canonical).await;
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "restore::tests::native_upgrade_process_exit_has_one_restart_entry",
                    "--test-threads=1",
                ])
                .env(CHILD_ROOT, &data)
                .env(CHILD_POINT, point)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(77));
            let entries_before = std::fs::read_dir(&data)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>();
            let backups_before = std::fs::read_dir(data.join("backups"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>();
            if point == "Prepared" {
                assert!(!data.join("store").exists());
                assert_eq!(
                    crate::JournalWriter::existing_profile(&data).await.unwrap(),
                    Some("L0001")
                );
            } else {
                let writer = crate::JournalWriter::open(&data).await.unwrap();
                assert_eq!(writer.full_projection().await.unwrap().frontier, 3);
            }
            if point == "Durable" && !canonical {
                let outcome = upgrade_native(
                    &data,
                    &data.parent().unwrap().join("config.toml"),
                    empty_hook,
                    |_, _| Ok(()),
                )
                .await
                .unwrap();
                assert!(
                    matches!(outcome, NativeUpgradeOutcome::Noop { retained_native }
                    if retained_native == vec![data.join(format!("{}.lance", crate::JOURNAL_TABLE)), data.join(format!("{}.lance", crate::OBJECTS_TABLE))])
                );
            }
            if point == "Prepared" || canonical {
                let residual = std::fs::read_dir(&data)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .as_encoded_bytes()
                            .starts_with(b".upgrade-")
                    })
                    .unwrap();
                let original = crate::backup::native_upgrade_manifest(&residual).unwrap();
                assert!(
                    matches!(upgrade_native(&data, &data.parent().unwrap().join("config.toml"), empty_hook, |_, _| Ok(())).await,
                    Err(RestoreError::ResidualCandidate { directory, .. }) if directory == residual)
                );
                assert_eq!(
                    crate::backup::native_upgrade_manifest(&residual).unwrap(),
                    original
                );
                assert_eq!(
                    std::fs::read_dir(&data)
                        .unwrap()
                        .map(|entry| entry.unwrap().file_name())
                        .collect::<std::collections::BTreeSet<_>>(),
                    entries_before
                );
                assert_eq!(
                    std::fs::read_dir(data.join("backups"))
                        .unwrap()
                        .map(|entry| entry.unwrap().file_name())
                        .collect::<std::collections::BTreeSet<_>>(),
                    backups_before
                );
            }
        }
    }

    #[tokio::test]
    async fn root_sync_is_required_for_activation_and_rollback_with_nested_config() {
        use std::cell::Cell;
        for fail_syncs in [0, 1, 2] {
            let temp = tempfile::tempdir().unwrap();
            let active = temp.path().join("data");
            let writer = crate::JournalWriter::open(&active).await.unwrap();
            evertrace_capture::CasStore::open(active.join("cas")).unwrap();
            let old_identity = std::fs::metadata(&active).unwrap().ino();
            let config_parent = active.join("settings");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&config_parent)
                .unwrap();
            let config = config_parent.join("config.toml");
            let original = evertrace_domain::config::EffectiveConfig::default()
                .to_toml()
                .unwrap();
            std::fs::write(&config, original.as_bytes()).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
            let replacement = format!("{original}\n# restored configuration\n");
            let path = temp.path().join("candidate");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            let writer = writer
                .close_for_backup()
                .open_restore_candidate(&path)
                .await
                .unwrap();
            evertrace_capture::CasStore::open(path.join("cas")).unwrap();
            let candidate = RestoreCandidate {
                writer,
                path: path.clone(),
            };
            let syncs = Cell::new(0);
            let validations = Cell::new(0);
            let result = candidate
                .activate_with_root_sync(
                    &config,
                    replacement.as_bytes(),
                    |_| {
                        assert_eq!(
                            syncs.get(),
                            1,
                            "root publication must be synced before health checks"
                        );
                        validations.set(validations.get() + 1);
                        Ok(())
                    },
                    |parent| {
                        syncs.set(syncs.get() + 1);
                        if syncs.get() <= fail_syncs {
                            Err(std::io::Error::other(
                                "injected root directory sync failure",
                            ))
                        } else {
                            parent.sync_all()
                        }
                    },
                )
                .await;
            if fail_syncs == 0 {
                let activated = result.unwrap();
                assert_eq!(validations.get(), 2);
                assert_eq!(std::fs::read_to_string(&config).unwrap(), replacement);
                assert_eq!(
                    std::fs::read_to_string(activated.rollback_root.join("settings/config.toml"))
                        .unwrap(),
                    original
                );
            } else {
                assert_eq!(
                    syncs.get(),
                    2,
                    "rollback must independently sync its root renames"
                );
                assert_eq!(validations.get(), 0);
                assert_eq!(std::fs::metadata(&active).unwrap().ino(), old_identity);
                assert_eq!(std::fs::read_to_string(&config).unwrap(), original);
                if fail_syncs == 1 {
                    assert!(matches!(result, Err(RestoreError::Io)));
                    assert!(!path.exists());
                } else {
                    assert!(matches!(result, Err(RestoreError::RollbackFailed { .. })));
                    assert!(
                        path.exists(),
                        "uncertain rollback must retain its candidate locator"
                    );
                }
            }
        }
    }

    #[test]
    fn ledger_batches_obey_the_existing_command_limit() {
        let event = JournalEventDraft::runtime(
            1,
            [1; 32],
            LEDGER_REVISION,
            JournalPayload::JobLease(JobLease {
                job_id: JobId::new_v7(),
                target_generation: 1,
                attempt: 1,
                lease_until_us: 2,
            }),
        );
        let limit = usize::from(u16::MAX);
        let mut commands = ledger_commands(std::iter::repeat_n(event, limit + 1));
        let first = commands.next().unwrap().unwrap();
        assert_eq!(first.events().len(), limit);
        let second = commands.next().unwrap().unwrap();
        assert_eq!(second.events().len(), 1);
        assert_ne!(first.command_id(), second.command_id());
        assert!(commands.next().is_none());
        assert!(ledger_commands(std::iter::empty()).next().is_none());
    }

    #[test]
    fn failed_candidate_cleanup_refuses_a_replaced_root() {
        let root = tempfile::TempDir::new().unwrap();
        let path = root.path().join("candidate");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let custody = evertrace_capture::ConfinedRoot::open_owned_private(&path).unwrap();
        let displaced = root.path().join("displaced");
        std::fs::rename(&path, &displaced).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("other-task"), b"preserve").unwrap();
        assert!(remove_failed_candidate(&path, &custody).is_err());
        assert_eq!(std::fs::read(path.join("other-task")).unwrap(), b"preserve");
        assert!(displaced.exists());
    }
}
