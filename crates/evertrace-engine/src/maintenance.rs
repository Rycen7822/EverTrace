//! Single bounded owner for durable background work.

/// Offline installation keeps runtime interpretation in Engine/Capture. The
/// adapter never manufactures snapshot JSON or alters a pinned runtime.
pub fn install_offline(
    paths: &evertrace_codex::install::ManagedInstallPaths,
    uninstall: bool,
) -> Result<
    evertrace_codex::install::ManagedInstallResult,
    evertrace_codex::install::ManagedInstallError,
> {
    use evertrace_codex::install::{InstallError, ManagedInstallError};
    let invalid = || ManagedInstallError {
        stage: "configuration",
        cause: InstallError::InvalidType,
        preserved: Vec::new(),
    };
    let (config, bytes) = match std::fs::symlink_metadata(&paths.config) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= 1024 * 1024 =>
        {
            let bytes = std::fs::read(&paths.config).map_err(|_| invalid())?;
            let config = evertrace_domain::config::EffectiveConfig::parse_toml(
                std::str::from_utf8(&bytes).map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?;
            (config, bytes)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let config = evertrace_domain::config::EffectiveConfig::default();
            let bytes = config.to_toml().map_err(|_| invalid())?.into_bytes();
            (config, bytes)
        }
        _ => return Err(invalid()),
    };
    evertrace_codex::install::managed_install(
        paths,
        &bytes,
        uninstall,
        |_generation, destination| {
            let snapshot_path = RuntimeSnapshot::snapshot_path(&paths.data_root);
            let mut runtime = match std::fs::symlink_metadata(&snapshot_path) {
                Ok(_) => {
                    RuntimeSnapshot::load(&snapshot_path).map_err(|_| InstallError::InvalidType)?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let _lock = evertrace_store::SiblingWriterLock::acquire(&paths.data_root)
                        .map_err(|_| InstallError::LockBusy)?;
                    if snapshot_path.try_exists().map_err(|_| InstallError::Io)? {
                        return Err(InstallError::InvalidType);
                    }
                    crate::publish_recovery_runtime(&paths.data_root, &config, None)
                        .map_err(|_| InstallError::InvalidType)?
                }
                Err(_) => return Err(InstallError::Io),
            };
            runtime.recovery_gate = evertrace_capture::RecoveryGateMode::Disabled;
            runtime.recovery_adapter_manifest_id = None;
            runtime.recall_cue_gate = evertrace_capture::RecallCueGateMode::Disabled;
            runtime.recall_cue_adapter_manifest_id = None;
            runtime.recall_cues.clear();
            runtime.publish(destination).map_err(|_| InstallError::Io)
        },
    )
}

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use evertrace_capture::{CaptureAdmissionState, RuntimeSnapshot};
use evertrace_codex::HostProbeReport;
use evertrace_domain::{
    config::DreamingConfig,
    ids::{CommandId, JobId, SourceObservationId},
    semantic::{
        AtomLifecycleStatus, GlobalSuccessorSupportContract, GlobalSupportValidationEvent,
        ProposalStatus,
    },
};
use evertrace_store::{
    BackupError, BackupSummary, DirtyTargetKind, DurableJob, EventScope, JobBudget, JobLease,
    JobStatus, JobTerminalAudit, JobTerminalOutcome, JobTerminalReason, JournalCommand,
    JournalEventDraft, JournalPayload, QUIESCED_BACKUP_CREATE_JOB_KIND,
    QUIESCED_BACKUP_VERIFY_JOB_KIND, RuntimeSchedulerView, SourceKind,
};
use thiserror::Error;
use tokio::sync::{OwnedRwLockReadGuard, RwLock, mpsc, oneshot, watch};

use crate::{
    SessionImportBudget, SessionImportWorker, WriterActorError, WriterHandle,
    capture::{ReconcileError, ReconcileInput, reconcile_observations_once},
    jobs::{JobResultDisposition, SynthesisPlanner, expired_leases, support_closure_result},
    session_import::{SessionCatalogService, session_import_job_budget},
};

const TOTAL_LIMIT: usize = 32;
const PER_LANE_LIMIT: usize = 8;
const CAPTURE_PROBE_LIMIT: usize = TOTAL_LIMIT + PER_LANE_LIMIT;
const RETRY_DELAY: Duration = Duration::from_secs(5);
const CAPTURE_ALGORITHM_REVISION: &str = "capture-reconciliation-v1";

pub(crate) fn freeze_hook_backup(
    data_dir: &Path,
) -> Result<evertrace_store::backup::BackupHookBoundary, BackupError> {
    let snapshot = evertrace_codex::install::StableLauncher::freeze_backup_snapshot(data_dir)
        .map_err(|error| match error {
            evertrace_codex::install::InstallError::ResourceExhausted => {
                BackupError::ResourceExhausted
            }
            evertrace_codex::install::InstallError::LockBusy => BackupError::Io,
            _ => BackupError::Corrupt,
        })?;
    Ok(evertrace_store::backup::BackupHookBoundary {
        current_generation: snapshot.current_generation,
        retained_generations: snapshot.retained_generations,
        pin_count: snapshot.pin_count,
        pinned_generation_count: snapshot.pinned_generation_count,
        files: snapshot
            .files
            .into_iter()
            .map(|file| evertrace_store::backup::BackupFrozenFile {
                directories: file.directories,
                source: file.source,
                relative_path: file.relative_path,
                device: file.device,
                inode: file.inode,
                length: file.length,
                modified_seconds: file.modified_seconds,
                modified_nanoseconds: file.modified_nanoseconds,
                changed_seconds: file.changed_seconds,
                changed_nanoseconds: file.changed_nanoseconds,
            })
            .collect(),
    })
}

/// Uses no daemon, worker, provider or host-installation side effect.
pub async fn upgrade_offline(
    data_dir: &Path,
    config_path: &Path,
) -> Result<evertrace_store::restore::NativeUpgradeOutcome, evertrace_store::restore::RestoreError>
{
    evertrace_store::restore::upgrade_native(
        data_dir,
        config_path,
        || freeze_hook_backup(data_dir),
        verify_hook_backup_assets,
    )
    .await
}

pub struct PackageUpgradeCheck {
    pub backup: std::path::PathBuf,
    pub migrated: bool,
    pub generation: Option<u64>,
    pub materials_validated: bool,
    pub candidate_native_verified: bool,
    pub candidate_daemon_verified: bool,
}

pub async fn verify_package_native(
    native: &Path,
    cas: &Path,
) -> Result<(), evertrace_store::restore::RestoreError> {
    evertrace_store::restore::verify_package_native(native, cas).await
}

/// Pre-publication only. The returned materials result never certifies a Host
/// or package-ready state; the verified backup survives candidate disposal.
pub async fn check_package_upgrade<F, Fut>(
    data_dir: &Path,
    config_path: &Path,
    host_config: &Path,
    unit: &Path,
    package: &Path,
    health: F,
) -> Result<PackageUpgradeCheck, evertrace_store::restore::RestoreError>
where
    F: Fn(std::path::PathBuf) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    use evertrace_store::restore::{NativeUpgradePreparation, RestoreError};
    let preflight = evertrace_codex::install::preflight_package_check(
        data_dir,
        config_path,
        host_config,
        unit,
        package,
    )
    .map_err(|_| RestoreError::Store(evertrace_store::StoreError::InvalidInput))?;
    let preparation = evertrace_store::restore::prepare_native_upgrade(
        data_dir,
        config_path,
        || freeze_hook_backup(data_dir),
        verify_hook_backup_assets,
    )
    .await?;
    let NativeUpgradePreparation::Prepared(prepared) = preparation else {
        return Err(evertrace_store::StoreError::InvalidInput.into());
    };
    let backup = prepared.backup().to_owned();
    let migrated = prepared.migrated();
    let mut candidate_native_verified = false;
    let mut candidate_daemon_verified = false;
    let validation = async {
        let mut runtime = RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(data_dir))
            .map_err(|_| RestoreError::Store(evertrace_store::StoreError::StoreCorrupt))?;
        runtime.recovery_gate = evertrace_capture::RecoveryGateMode::Disabled;
        runtime.recovery_adapter_manifest_id = None;
        runtime.recall_cue_gate = evertrace_capture::RecallCueGateMode::Disabled;
        runtime.recall_cue_adapter_manifest_id = None;
        runtime.recall_cues.clear();
        let materials = evertrace_codex::install::prepare_package_check(
            preflight,
            prepared.path(),
            |destination| {
                runtime
                    .publish(destination)
                    .map_err(|_| evertrace_codex::install::InstallError::Io)
            },
        )
        .map_err(|_| RestoreError::Store(evertrace_store::StoreError::InvalidInput))?;
        let candidate_runtime = RuntimeSnapshot::load(&materials.runtime)
            .map_err(|_| RestoreError::Store(evertrace_store::StoreError::StoreCorrupt))?;
        probe_package_capture(prepared.path(), &materials.executable, &candidate_runtime)?;
        run_package_native(
            &package.join("evertraced"),
            prepared.path(),
            &backup.join("cas"),
        )
        .await?;
        candidate_native_verified = true;
        probe_package_daemon(package, &health).await?;
        candidate_daemon_verified = true;
        materials
            .validate()
            .map_err(|_| RestoreError::Store(evertrace_store::StoreError::InvalidInput))?;
        Ok::<_, RestoreError>(materials.generation)
    }
    .await;
    // Both failed and successful checks dispose only this owned candidate while
    // the same sibling lock is still held. Unknown residuals are explicit errors.
    if matches!(&validation, Err(RestoreError::ResidualCandidate { directory, .. }) if directory.starts_with(prepared.path()))
    {
        return validation.map(|_| unreachable!());
    }
    prepared.discard()?;
    if matches!(&validation, Err(RestoreError::ResidualCandidate { .. })) {
        return validation.map(|_| unreachable!());
    }
    Ok(PackageUpgradeCheck {
        backup,
        migrated,
        generation: validation.as_ref().ok().copied(),
        materials_validated: validation.is_ok(),
        candidate_native_verified,
        candidate_daemon_verified,
    })
}

pub enum OfflineRestoreOutcome {
    Historical { directory: std::path::PathBuf },
    Activated(evertrace_store::restore::RestoreActivated),
}

struct PackageProbeChild(Option<std::process::Child>);

impl Drop for PackageProbeChild {
    fn drop(&mut self) {
        if crate::recovery::finish_owned_child(&mut self.0, true).is_err() {
            tracing::warn!("package probe child cleanup failed");
        }
    }
}

async fn run_package_native(
    executable: &Path,
    native: &Path,
    cas: &Path,
) -> Result<(), evertrace_store::restore::RestoreError> {
    use evertrace_store::restore::RestoreError;
    use std::{
        io::Read,
        os::{
            fd::OwnedFd,
            unix::{net::UnixStream, process::CommandExt},
        },
        process::Stdio,
    };
    let (mut reader, output) = UnixStream::pair().map_err(|_| RestoreError::Io)?;
    reader.set_nonblocking(true).map_err(|_| RestoreError::Io)?;
    let descriptor: OwnedFd = output.into();
    let mut child = PackageProbeChild(Some(
        std::process::Command::new(executable)
            .args(["--verify-package-native"])
            .arg(native)
            .arg("--cas")
            .arg(cas)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::from(descriptor))
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|_| RestoreError::Io)?,
    ));
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut output = Vec::new();
    let result =
        async {
            loop {
                let mut buffer = [0; 1024];
                match reader.read(&mut buffer) {
                    Ok(count) => output.extend_from_slice(&buffer[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(RestoreError::Io),
                }
                if output.len() > 4096 || std::time::Instant::now() >= deadline {
                    return Err(RestoreError::Io);
                }
                if let Some(status) = crate::recovery::finish_owned_child(&mut child.0, false)
                    .map_err(|_| RestoreError::ResidualCandidate {
                        directory: native.to_owned(),
                        cause: Box::new(RestoreError::Io),
                    })?
                {
                    // Drain only the bounded bytes already available after group cleanup.
                    loop {
                        match reader.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(count) if output.len() + count <= 4096 => {
                                output.extend_from_slice(&buffer[..count])
                            }
                            _ => return Err(RestoreError::Io),
                        }
                    }
                    return if status.success() && output == b"candidate native verified\n" {
                        Ok(())
                    } else {
                        Err(RestoreError::Io)
                    };
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        .await;
    crate::recovery::finish_owned_child(&mut child.0, true).map_err(|_| {
        RestoreError::ResidualCandidate {
            directory: native.to_owned(),
            cause: Box::new(RestoreError::Io),
        }
    })?;
    result
}

async fn probe_package_daemon<F, Fut>(
    package: &Path,
    health: &F,
) -> Result<(), evertrace_store::restore::RestoreError>
where
    F: Fn(std::path::PathBuf) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    use evertrace_store::restore::RestoreError;
    use std::{
        io::Write,
        os::unix::{
            fs::{DirBuilderExt, OpenOptionsExt},
            process::CommandExt,
        },
        process::Stdio,
    };
    let invalid = || RestoreError::Store(evertrace_store::StoreError::StoreCorrupt);
    // Do not inherit TMPDIR or the potentially long historical native locator.
    if !std::fs::symlink_metadata("/tmp")
        .map_err(|_| invalid())?
        .is_dir()
    {
        return Err(invalid());
    }
    let temporary =
        evertrace_capture::ConfinedRoot::open(Path::new("/tmp")).map_err(|_| invalid())?;
    let wrapper = Path::new("/tmp").join(format!("et-pkg-{}", JobId::new_v7()));
    let root = wrapper.join("data");
    let uncertain = || RestoreError::ResidualCandidate {
        directory: wrapper.clone(),
        cause: Box::new(RestoreError::Io),
    };
    use std::os::unix::ffi::OsStrExt;
    if root
        .join("runtime/evertraced-v1.sock")
        .as_os_str()
        .as_bytes()
        .len()
        >= 108
    {
        return Err(invalid());
    }
    temporary.revalidate_stable().map_err(|_| invalid())?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&wrapper)
        .map_err(|_| RestoreError::Io)?;
    let custody =
        evertrace_capture::ConfinedRoot::open_owned_private(&wrapper).map_err(|_| uncertain())?;
    let result = async {
    temporary.revalidate_stable().map_err(|_| uncertain())?;
    std::fs::DirBuilder::new().mode(0o700).create(&root).map_err(|_| RestoreError::Io)?;
    let mut config = evertrace_domain::config::EffectiveConfig::default()
        .config()
        .clone();
    config.runtime.data_dir = root.to_str().ok_or_else(invalid)?.to_owned();
    config.llm.enabled = false;
    let config = evertrace_domain::config::EffectiveConfig::new(config).map_err(|_| invalid())?;
    let config_path = root.join("probe.toml");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&config_path)
        .map_err(|_| RestoreError::Io)?;
    file.write_all(config.to_toml().map_err(|_| invalid())?.as_bytes())
        .map_err(|_| RestoreError::Io)?;
    file.sync_all().map_err(|_| RestoreError::Io)?;
    drop(file);
    let mut daemon = PackageProbeChild(Some(
        std::process::Command::new(package.join("evertraced"))
            .arg("--config")
            .arg(&config_path)
            .env_clear()
            .env("HOME", &root)
            .env("XDG_CONFIG_HOME", &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|_| RestoreError::Io)?,
    ));
    let result = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if crate::recovery::finish_owned_child(&mut daemon.0, false).map_err(|_| uncertain())?.is_some() { return Err(invalid()); }
            let ready = tokio::time::timeout_at(deadline, health(root.join("runtime/evertraced-v1.sock"))).await.map_err(|_| invalid())?;
            if ready { break; }
            if tokio::time::Instant::now() >= deadline { return Err(invalid()); }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let runtime_path = RuntimeSnapshot::snapshot_path(&root);
        let runtime = RuntimeSnapshot::load(&runtime_path).map_err(|_| invalid())?;
        if runtime.effective_config_hash != config.hash() { return Err(invalid()); }
        let launcher = evertrace_codex::install::prepare_probe_generation(&root, &package.join("evertrace-hook"), |path| runtime.publish(path).map_err(|_| evertrace_codex::install::InstallError::Io)).map_err(|_| invalid())?;
        let native = serde_json::json!({
            "cwd": root, "hook_event_name":"PreToolUse", "model":"package-probe", "permission_mode":"default",
            "session_id":"package-daemon-probe", "tool_input":{"command":"printf package-daemon-probe"},
            "tool_name":"Bash", "tool_use_id":"one", "transcript_path":null, "turn_id":"one"
        });
        let mut hook = PackageProbeChild(Some(std::process::Command::new(launcher)
            .arg("--launcher-root").arg(&root).env_clear().stdin(Stdio::piped())
            .stdout(Stdio::null()).stderr(Stdio::null()).process_group(0).spawn().map_err(|_| RestoreError::Io)?));
        let hook_result = async {
        hook.0.as_mut().ok_or_else(invalid)?.stdin.take().ok_or_else(invalid)?.write_all(&serde_json::to_vec(&native).map_err(|_| invalid())?).map_err(|_| RestoreError::Io)?;
        loop {
            if let Some(status) = crate::recovery::finish_owned_child(&mut hook.0, false).map_err(|_| uncertain())? {
                if !status.success() { return Err(invalid()); }
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline { return Err(invalid()); }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        }.await;
        crate::recovery::finish_owned_child(&mut hook.0, true).map_err(|_| uncertain())?;
        hook_result?;
        loop {
            let connection = evertrace_store::connection::CompatibilityStore::connect_local(&evertrace_store::connection::native_root(&root)).await.map_err(|_| invalid())?;
            let journal = connection.connection().open_table(evertrace_store::JOURNAL_TABLE).execute().await.map_err(|_| invalid())?;
            let payloads = evertrace_store::journal::read_all_journal_rows(&journal).await?.iter().map(|row| row.payload()).collect::<Result<Vec<_>, _>>()?;
            let receipt = payloads.iter().find_map(|payload| match payload {
                JournalPayload::SourceReceiptRecorded(receipt) if receipt.source_session_ref == "package-daemon-probe" => Some(receipt), _ => None,
            });
            let normalized = payloads.iter().any(|payload| matches!(payload, JournalPayload::HostOccurrenceNormalized(_)));
            if let Some(receipt) = receipt && normalized
                && payloads.iter().any(|payload| matches!(payload, JournalPayload::SourceIngestWatermark(value) if value.source_instance_id == receipt.source_instance_id)) {
                if payloads.iter().any(|payload| matches!(payload, JournalPayload::ExecutionLaneRecorded(_) | JournalPayload::CaptureReceiptRecorded(_))) { return Err(invalid()); }
                let cas = evertrace_capture::CasStore::open_existing(runtime.cas_dir.clone()).map_err(|_| invalid())?;
                let digest = evertrace_capture::CasStore::parse_digest(&receipt.cas_ref).map_err(|_| invalid())?;
                let (payload, _) = cas.read_bounded(&digest, 64 * 1024, 64 * 1024).map_err(|_| invalid())?;
                if !payload.windows(b"package-daemon-probe".len()).any(|value| value == b"package-daemon-probe") { return Err(invalid()); }
                return Ok(());
            }
            drop(journal); drop(connection);
            if tokio::time::Instant::now() >= deadline { return Err(invalid()); }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }.await;
    crate::recovery::finish_owned_child(&mut daemon.0, true).map_err(|_| {
        RestoreError::ResidualCandidate {
            directory: wrapper.clone(),
            cause: Box::new(RestoreError::Io),
        }
    })?;
    result
    }.await;
    // Uncertain process custody must never authorize removing its files.
    if matches!(&result, Err(RestoreError::ResidualCandidate { .. })) {
        return result;
    }
    temporary.revalidate_stable().map_err(|_| uncertain())?;
    custody.revalidate_stable().map_err(|_| uncertain())?;
    std::fs::remove_dir_all(&wrapper).map_err(|_| uncertain())?;
    result
}

/// Offline only: no actor, provider, socket or background scheduler is started.
pub async fn restore_offline(
    data_dir: &Path,
    config_path: &Path,
    backup: &Path,
    current_hook: &Path,
    config_hash: [u8; 32],
) -> Result<OfflineRestoreOutcome, evertrace_store::restore::RestoreError> {
    use evertrace_store::restore::{RestoreError, RestorePreparation};
    let at = now_us().map_err(|_| RestoreError::Io)?;
    let preparation = evertrace_store::restore::prepare(data_dir, backup, at, config_hash).await?;
    let RestorePreparation::Candidate(mut candidate) = preparation else {
        let RestorePreparation::Historical { directory } = preparation else {
            unreachable!()
        };
        return Ok(OfflineRestoreOutcome::Historical { directory });
    };
    let prepared = async {
        let invalid = || RestoreError::Store(evertrace_store::StoreError::InvalidInput);
        let bytes = std::fs::read(candidate.path().join("config/config.toml"))
            .map_err(|_| RestoreError::Io)?;
        let config = evertrace_domain::config::EffectiveConfig::parse_toml(
            std::str::from_utf8(&bytes).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let mut restored = config.config().clone();
        restored.runtime.data_dir = data_dir.to_str().ok_or_else(invalid)?.to_owned();
        let config =
            evertrace_domain::config::EffectiveConfig::new(restored).map_err(|_| invalid())?;
        let config_bytes = config.to_toml().map_err(|_| invalid())?.into_bytes();
        let package = evertrace_codex::install::StableLauncher::prepare_restored_package(
            candidate.path(),
            data_dir,
            current_hook,
        )
        .map_err(|_| invalid())?;
        let mut runtime = RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(candidate.path()))
            .map_err(|_| invalid())?;
        let current_generation = RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(data_dir))
            .map_err(|_| invalid())?
            .generation;
        let mut max_generation = runtime.generation.max(current_generation);
        for path in &package.pinned_runtime_files {
            let mut pinned = RuntimeSnapshot::load(path).map_err(|_| invalid())?;
            max_generation = max_generation.max(pinned.generation);
            relocate_restore_runtime(&mut pinned, data_dir, config.hash());
            pinned.publish(path).map_err(|_| invalid())?;
        }
        runtime.generation = max_generation.checked_add(1).ok_or_else(invalid)?;
        relocate_restore_runtime(&mut runtime, data_dir, config.hash());
        runtime
            .publish(&RuntimeSnapshot::snapshot_path(candidate.path()))
            .map_err(|_| invalid())?;
        runtime
            .publish(&package.current_runtime_file)
            .map_err(|_| invalid())?;
        evertrace_capture::DeviceKeyStore::new(candidate.path().join("keys"))
            .load_or_create()
            .map_err(|_| invalid())?;
        probe_package_capture(
            candidate.path(),
            &candidate.path().join("hook-v1"),
            &runtime,
        )?;
        validate_restore_jobs(&mut candidate, &config, at).await?;
        evertrace_codex::install::StableLauncher::validate_restored_package(
            candidate.path(),
            data_dir,
        )
        .map_err(|_| invalid())?;
        Ok::<_, RestoreError>(config_bytes)
    }
    .await;
    let config_bytes = match prepared {
        Ok(bytes) => bytes,
        Err(error) => return Err(candidate.discard(error)),
    };
    let activated = candidate
        .activate(config_path, &config_bytes, |root| {
            evertrace_codex::install::StableLauncher::validate_restored_package(root, root)
                .map_err(|_| RestoreError::Store(evertrace_store::StoreError::StoreCorrupt))
        })
        .await?;
    Ok(OfflineRestoreOutcome::Activated(activated))
}

fn relocate_restore_runtime(runtime: &mut RuntimeSnapshot, root: &Path, config_hash: [u8; 32]) {
    runtime.device_key_dir = root.join("keys");
    runtime.cas_dir = root.join("cas");
    runtime.spool_dir = root.join("spool");
    runtime.recovery_socket_path = root.join("runtime/evertraced-v1.sock");
    runtime.effective_config_hash = config_hash;
    runtime.recall_cues.clear();
    // A private package probe cannot certify a live Host capability.
    runtime.recall_cue_gate = evertrace_capture::RecallCueGateMode::Disabled;
    runtime.recall_cue_adapter_manifest_id = None;
    runtime.recovery_gate = evertrace_capture::RecoveryGateMode::Disabled;
    runtime.recovery_adapter_manifest_id = None;
}

fn probe_package_capture(
    candidate: &Path,
    executable: &Path,
    runtime: &RuntimeSnapshot,
) -> Result<(), evertrace_store::restore::RestoreError> {
    use evertrace_capture::{CasStore, ConfinedRoot, DurableSpool};
    use evertrace_store::restore::RestoreError;
    use std::{
        io::Write,
        os::unix::fs::{DirBuilderExt, MetadataExt},
        process::Stdio,
    };
    let invalid = || RestoreError::Store(evertrace_store::StoreError::StoreCorrupt);
    let root = candidate.join(format!("restore-probe-{}", JobId::new_v7()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .map_err(|_| RestoreError::Io)?;
    let custody = ConfinedRoot::open_owned_private(&root).map_err(|_| invalid())?;
    let fence = evertrace_capture::MaintenanceFence::open(&root).map_err(|_| invalid())?;
    let fence_identity =
        std::fs::symlink_metadata(fence.lock_path()).map_err(|_| RestoreError::Io)?;
    let result = (|| {
        let mut probe = runtime.clone();
        relocate_restore_runtime(&mut probe, &root, runtime.effective_config_hash);
        let snapshot_path = RuntimeSnapshot::snapshot_path(&root);
        probe.publish(&snapshot_path).map_err(|_| invalid())?;
        evertrace_capture::DeviceKeyStore::new(probe.device_key_dir.clone())
            .load_or_create()
            .map_err(|_| invalid())?;
        let input = serde_json::json!({
            "input_version": evertrace_codex::hook_input::CAPTURE_HOOK_INPUT_VERSION,
            "spool_record_id": "restore-package-probe", "source_observation_id_hint": null,
            "source_instance_id": "restore-package-probe", "source_revision": "probe-v1",
            "source_record_identity": "restore-package-probe", "identity_strength": "stable_native",
            "source_kind": "codex_hook", "identity_domain": "codex-hook-v1",
            "adapter_manifest_ref": "restore-package-probe", "eligible_event_manifest_ref": "restore-package-probe",
            "source_revision_mode": "append", "previous_source_revision": null,
            "source_ref": "restore-package-probe", "session_id": "restore-package-probe",
            "turn_id": null, "tool_use_id": null, "event_kind": "post_tool_use",
            "correlation": {
                "occurrence_schema_version": 1, "host_instance_id": null, "host_trace_lineage_id": null,
                "host_lane_key": null, "canonical_event_family": null, "native_request_id": null,
                "physical_execution_ordinal": null, "pairing_role": "result", "field_provenance": [],
                "adapter_manifest_ref": "restore-package-probe", "adapter_revision": 1,
                "strong_gate_receipt_ref": null, "admission": "unavailable", "partial_correlation_ref": null,
                "possible_duplicate_group_id": null
            },
            "scope_effect_claims": [], "lifecycle": null, "source_sequence": 1,
            "source_sequence_origin": null, "task_id": null, "repository_instance_id": null,
            "worktree_instance_id": null, "event_time_us": 1, "payload": "restore-package-probe"
        });
        // Decode through the adapter before execution; the runtime probe uses the
        // same public input contract as the installed Hook, not a special mode.
        let bytes = serde_json::to_vec(&input).map_err(|_| invalid())?;
        evertrace_codex::hook_input::CaptureHookInput::from_json(&bytes).map_err(|_| invalid())?;
        let mut child = std::process::Command::new(executable)
            .arg("--runtime-snapshot")
            .arg(&snapshot_path)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| RestoreError::Io)?;
        let execution = (|| {
            child
                .stdin
                .take()
                .ok_or_else(invalid)?
                .write_all(&bytes)
                .map_err(|_| RestoreError::Io)?;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = child.try_wait().map_err(|_| RestoreError::Io)? {
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(invalid())
                    };
                }
                if std::time::Instant::now() >= deadline {
                    return Err(invalid());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        if execution.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        execution?;
        let (spool, _) = DurableSpool::open(
            probe.spool_dir.clone(),
            probe.spool_limits().map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let frames = spool.read_active().map_err(|_| invalid())?;
        let [frame] = frames.as_slice() else {
            return Err(invalid());
        };
        if frame.record.spool_record_id != "restore-package-probe"
            || frame.record.spool_generation != probe.generation
            || frame.record.cas_refs.len() != 1
        {
            return Err(invalid());
        }
        evertrace_capture::decode_validated_record_body(&frame.record).map_err(|_| invalid())?;
        let cas = CasStore::open(probe.cas_dir).map_err(|_| invalid())?;
        let digest = CasStore::parse_digest(&frame.record.cas_refs[0]).map_err(|_| invalid())?;
        if cas.read(&digest).map_err(|_| invalid())? != b"restore-package-probe" {
            return Err(invalid());
        }
        Ok(())
    })();
    custody.revalidate_stable().map_err(|_| invalid())?;
    std::fs::remove_dir_all(&root).map_err(|_| RestoreError::Io)?;
    // This private root's fence lives inside the candidate, never at the live
    // sibling locator. It is not a restored capability or durable work item.
    let located = std::fs::symlink_metadata(fence.lock_path()).map_err(|_| RestoreError::Io)?;
    if (located.dev(), located.ino()) != (fence_identity.dev(), fence_identity.ino()) {
        return Err(invalid());
    }
    std::fs::remove_file(fence.lock_path()).map_err(|_| RestoreError::Io)?;
    result
}

async fn validate_restore_jobs(
    candidate: &mut evertrace_store::restore::RestoreCandidate,
    config: &evertrace_domain::config::EffectiveConfig,
    at: i64,
) -> Result<(), evertrace_store::restore::RestoreError> {
    let snapshot = candidate.full_projection().await?;
    let view = RuntimeSchedulerView::from_snapshot(&snapshot)?;
    for mut job in view
        .jobs
        .iter()
        .filter(|job| job.state == JobStatus::Queued)
        .cloned()
    {
        if restore_job_is_current(&snapshot, &view, &job, config)? {
            continue;
        }
        let replacement =
            if job.kind == "session_import_v1" && import_target_is_current(&snapshot, &job)? {
                Some(replacement_import_job(&job, config.hash()))
            } else if job.kind == "support_closure"
                && job_target_is_current(&snapshot, &view, &job, config.hash())?
            {
                let mut replacement = job.clone();
                replacement.job_id = JobId::new_v7();
                replacement.config_hash = config.hash();
                replacement.attempt = 1;
                replacement.backoff_until_us = None;
                Some(replacement)
            } else {
                None
            };
        job.state = JobStatus::Failed;
        job.lease_until_us = None;
        job.backoff_until_us = None;
        job.terminal = Some(Box::new(JobTerminalAudit {
            outcome: JobTerminalOutcome::Failed,
            reason: JobTerminalReason::StaleGeneration,
            result_ref: Some(job.target_revision.clone()),
        }));
        let mut events = vec![JournalEventDraft {
            occurred_at_us: at,
            source_kind: SourceKind::System,
            scope: EventScope::default(),
            causation_id: None,
            correlation_id: None,
            effective_config_hash: job.config_hash,
            algorithm_revision: job.algorithm_revision.clone(),
            payload: JournalPayload::JobState(job),
        }];
        if let Some(replacement) = replacement {
            events.push(JournalEventDraft::runtime(
                at,
                replacement.config_hash,
                replacement.algorithm_revision.clone(),
                JournalPayload::JobState(replacement),
            ));
        }
        let command = JournalCommand::new(CommandId::new_v7(), events)?;
        candidate.commit(&command, at).await?;
    }
    Ok(())
}

fn restore_job_is_current(
    snapshot: &evertrace_store::ProjectionSnapshot,
    view: &RuntimeSchedulerView,
    job: &DurableJob,
    config: &evertrace_domain::config::EffectiveConfig,
) -> Result<bool, evertrace_store::StoreError> {
    // Objects projection is a pure authoritative rebuild, independent of config.
    if job.kind != "objects_projection" && job.config_hash != config.hash() {
        return Ok(false);
    }
    if job.kind == QUIESCED_BACKUP_VERIFY_JOB_KIND {
        return Ok(false);
    }
    if job.kind == "semantic_synthesis_v1" {
        let llm = &config.config().llm;
        if !crate::jobs::synthesis::synthesis_identity_is_current(llm, job, config.hash())
            || !crate::jobs::synthesis::synthesis_budget(
                llm,
                Duration::from_secs(config.config().dreaming.max_wall_time.seconds()),
            )
            .is_ok_and(|budget| budget == job.budget)
        {
            return Ok(false);
        }
    }
    job_target_is_current(snapshot, view, job, config.hash())
}

/// Pure authoritative target checks, shared by offline preparation and the
/// ordinary pre-lease boundary. Host manifests are additionally checked online.
fn job_target_is_current(
    snapshot: &evertrace_store::ProjectionSnapshot,
    view: &RuntimeSchedulerView,
    job: &DurableJob,
    config_hash: [u8; 32],
) -> Result<bool, evertrace_store::StoreError> {
    if job.target_watermark > snapshot.frontier {
        return Ok(false);
    }
    Ok(match job.kind.as_str() {
        evertrace_store::optimize::GC_ALGORITHM_REVISION => {
            job.target_revision == job.job_id.to_string()
                && job.algorithm_revision == evertrace_store::optimize::GC_ALGORITHM_REVISION
                && job.target_generation == 1
                && job.idempotency_key == format!("{}:{}", job.kind, job.job_id)
        }
        "objects_projection" => view.dirty.iter().any(|dirty| {
            dirty.target_kind == DirtyTargetKind::ObjectsProjection
                && dirty.stable_key() == job.idempotency_key
                && dirty.target_id == job.target_revision
                && dirty.source_watermark == job.target_watermark
                && job.target_generation == dirty.source_watermark.max(1)
                && dirty.algorithm_revision == job.algorithm_revision
        }),
        "physical_normalization" | "capture_reconciliation" => {
            if !capture_job_is_current(job, config_hash) {
                return Ok(false);
            }
            let id = SourceObservationId::from_str(&job.target_revision)
                .map_err(|_| evertrace_store::StoreError::StoreCorrupt)?;
            let frontier = snapshot.reconciliation_frontier_for_observations(&[id])?;
            // A retained, exact dirty target may already have its authoritative
            // watermark satisfied. That is safe no-work, not a stale target.
            if frontier.items.is_empty() {
                return Ok(view.dirty.iter().any(|dirty| {
                    dirty.target_id == job.target_revision
                        && dirty.target_kind.as_str() == job.kind
                        && job.idempotency_key == format!("{}:{}", job.kind, dirty.target_id)
                        && snapshot
                            .row(&format!("runtime:dirty:{}", dirty.stable_key()))
                            .is_some_and(|row| {
                                row.source_event_seq == job.target_watermark
                                    && job.target_generation == row.source_event_seq.max(1)
                            })
                }));
            }
            frontier.items.iter().any(|item| {
                item.target_id == job.target_revision
                    && item.source_event_seq == job.target_watermark
                    && job.target_generation == item.source_event_seq.max(1)
                    && ((job.kind == "physical_normalization"
                        && item.target_kind == DirtyTargetKind::PhysicalNormalization)
                        || (job.kind == "capture_reconciliation"
                            && item.target_kind == DirtyTargetKind::CaptureReconciliation))
            })
        }
        "semantic_synthesis_v1" => {
            crate::jobs::synthesis::synthesis_target_is_current(snapshot, job)
        }
        "support_closure" => support_context(snapshot, job).is_ok_and(|(contract, current)| {
            current.support_contract_ref == contract.support_contract_revision_id
                && current.dependency_generation == job.target_generation
        }),
        "session_import_v1" => {
            import_job_is_current(job, config_hash) && import_target_is_current(snapshot, job)?
        }
        QUIESCED_BACKUP_CREATE_JOB_KIND => {
            job.target_revision == job.job_id.to_string()
                && job.algorithm_revision == evertrace_store::QUIESCED_BACKUP_ALGORITHM_REVISION
        }
        QUIESCED_BACKUP_VERIFY_JOB_KIND => {
            JobId::from_str(&job.target_revision).is_ok()
                && job.algorithm_revision == evertrace_store::QUIESCED_BACKUP_ALGORITHM_REVISION
        }
        evertrace_store::REPOSITORY_SCOPE_PURGE_JOB_KIND => {
            evertrace_store::ScopePurgeCurrentView::from_snapshot(snapshot)?
                .events
                .values()
                .any(|progress| {
                    progress.purge_job_id == job.job_id
                        && progress.deletion_generation == job.target_generation
                        && progress.confirmation_frontier == job.target_watermark
                        && progress.stage != evertrace_domain::purge::ScopePurgeStage::Purged
                })
        }
        _ => return Err(evertrace_store::StoreError::InvalidInput),
    })
}

fn import_target_is_current(
    snapshot: &evertrace_store::ProjectionSnapshot,
    job: &DurableJob,
) -> Result<bool, evertrace_store::StoreError> {
    let sessions =
        evertrace_store::session_import::SessionImportCurrentView::from_snapshot(snapshot)?;
    Ok(sessions.sessions.values().any(|session| {
        job.idempotency_key == format!("session_import:{}", session.session_id)
            && job.target_revision == session.metadata.source_revision.as_str()
            && job.target_generation <= session.revision
            && job.target_watermark <= session.source_event_seq
            && session.access_decision
                == Some(evertrace_store::session_import::SessionAccessDecision::Approved)
            && matches!(
                session.body_state,
                evertrace_store::session_import::SessionBodyState::Queued
                    | evertrace_store::session_import::SessionBodyState::Importing
                    | evertrace_store::session_import::SessionBodyState::Partial
            )
    }))
}

fn replacement_import_job(job: &DurableJob, config_hash: [u8; 32]) -> DurableJob {
    let mut replacement = job.clone();
    replacement.job_id = JobId::new_v7();
    replacement.config_hash = config_hash;
    replacement.algorithm_revision = "session_import_v1".into();
    replacement.model_id = None;
    replacement.budget = session_import_job_budget();
    replacement.state = JobStatus::Queued;
    replacement.attempt = 1;
    replacement.lease_until_us = None;
    replacement.backoff_until_us = None;
    replacement.terminal = None;
    replacement
}

pub(crate) fn verify_hook_backup_assets(
    directory: &Path,
    summary: &BackupSummary,
) -> Result<(), BackupError> {
    let semantic = evertrace_codex::install::StableLauncher::verify_backup_snapshot(directory)
        .map_err(|_| BackupError::Corrupt)?;
    if semantic.current_generation != summary.hook_current_generation
        || semantic.retained_generations != summary.hook_retained_generations
        || semantic.pin_count != summary.hook_pin_count
        || semantic.pinned_generation_count != summary.session_pinned_hook_artifact_count
    {
        return Err(BackupError::Corrupt);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BackgroundLane {
    Critical,
    Deterministic,
    Import,
    Synthesis,
    Maintenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledJob {
    pub lane: BackgroundLane,
    pub job: DurableJob,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BackgroundProgress {
    pub completed: usize,
    pub retryable: bool,
}

pub struct QuiescedBackupRequest {
    backup_job_id: JobId,
    reply: oneshot::Sender<Result<BackupSummary, BackupError>>,
}

impl QuiescedBackupRequest {
    pub const fn backup_job_id(&self) -> JobId {
        self.backup_job_id
    }

    pub fn complete(self, result: Result<BackupSummary, BackupError>) {
        let _ = self.reply.send(result);
    }

    pub fn complete_fatal(self) {
        let _ = self.reply.send(Err(BackupError::Io));
    }
}

struct ClaimedJob {
    snapshot: evertrace_store::ProjectionSnapshot,
    job: DurableJob,
    report: Option<OwnedRwLockReadGuard<Option<HostProbeReport>>>,
}

#[derive(Debug, Error)]
pub enum BackgroundSchedulerError {
    #[error("background scheduler store state is corrupt")]
    Store,
    #[error("background scheduler writer stopped")]
    Writer,
}

#[derive(Clone)]
pub struct BackgroundScheduler {
    writer: WriterHandle,
    catalog: SessionCatalogService,
    import: SessionImportWorker,
    report: Arc<RwLock<Option<HostProbeReport>>>,
    runtime: RuntimeSnapshot,
    synthesis: SynthesisPlanner,
    dreaming: DreamingConfig,
    capture_cursor: Arc<AtomicUsize>,
    repository_purge_plans: Arc<std::sync::Mutex<BTreeMap<JobId, Vec<String>>>>,
    backup_requests: Option<mpsc::Sender<QuiescedBackupRequest>>,
    gc_rounds: Arc<tokio::sync::Mutex<BTreeMap<JobId, evertrace_store::optimize::GcRound>>>,
    gc_cursor: Arc<tokio::sync::Mutex<Option<evertrace_capture::cas::CasGcCursor>>>,
}

impl BackgroundScheduler {
    pub fn new(
        writer: WriterHandle,
        catalog: SessionCatalogService,
        import: SessionImportWorker,
        report: Arc<RwLock<Option<HostProbeReport>>>,
        runtime: RuntimeSnapshot,
        synthesis: SynthesisPlanner,
        dreaming: DreamingConfig,
    ) -> Self {
        Self {
            writer,
            catalog,
            import,
            report,
            runtime,
            synthesis,
            dreaming,
            capture_cursor: Arc::new(AtomicUsize::new(0)),
            repository_purge_plans: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            backup_requests: None,
            gc_rounds: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())),
            gc_cursor: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub fn with_backup_requests(mut self, requests: mpsc::Sender<QuiescedBackupRequest>) -> Self {
        self.backup_requests = Some(requests);
        self
    }

    pub async fn run_once(&self) -> Result<BackgroundProgress, BackgroundSchedulerError> {
        let capture_state = self
            .runtime
            .spool_limits()
            .ok()
            .and_then(|limits| {
                let spool = evertrace_capture::DurableSpool::open_read_only(
                    self.runtime.spool_dir.clone(),
                    limits,
                )
                .ok()?;
                let quarantine = std::fs::read_dir(self.runtime.spool_dir.join("quarantine"))
                    .ok()?
                    .next()
                    .transpose()
                    .ok()?
                    .is_some();
                Some(
                    if spool.below_low_watermark().ok()?
                        && spool.pending_gap_markers().ok()?.is_empty()
                        && !quarantine
                    {
                        CaptureAdmissionState::Normal
                    } else {
                        CaptureAdmissionState::Recovering
                    },
                )
            })
            .unwrap_or(CaptureAdmissionState::Unavailable);
        let optional_allowed = capture_state == CaptureAdmissionState::Normal;
        let mut completed = 0;
        completed += self.run_gc_round().await?;
        let mut retryable = false;
        if optional_allowed {
            let report = Arc::clone(&self.report).read_owned().await;
            if let Some(report) = report.as_ref() {
                match self.catalog.refresh(report).await {
                    Ok(changed) => completed += changed,
                    Err(_) => retryable = true,
                }
            }
        }

        let mut snapshot = self.writer.project().await.map_err(map_writer)?;
        let recovery_now_us = now_us()?;
        let recovery = expired_leases(&snapshot.rows, recovery_now_us, snapshot.frontier)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        if !recovery.is_empty() {
            let events = recovery
                .into_iter()
                .map(|action| {
                    let mut job = action.job;
                    job.state = JobStatus::Queued;
                    job.attempt = action.next_attempt;
                    job.backoff_until_us = None;
                    job.lease_until_us = None;
                    job.terminal = None;
                    JournalEventDraft {
                        occurred_at_us: recovery_now_us,
                        source_kind: SourceKind::System,
                        scope: EventScope::default(),
                        causation_id: None,
                        correlation_id: None,
                        effective_config_hash: job.config_hash,
                        algorithm_revision: job.algorithm_revision.clone(),
                        payload: JournalPayload::JobState(job),
                    }
                })
                .collect::<Vec<_>>();
            let command = JournalCommand::new(CommandId::new_v7(), events)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            match self
                .writer
                .commit_if_frontier(command, recovery_now_us, snapshot.frontier)
                .await
            {
                Ok(outcome) => {
                    completed += usize::from(!outcome.replayed);
                    snapshot = self.writer.project().await.map_err(map_writer)?;
                }
                Err(WriterActorError::StaleFrontier) => {
                    return Ok(BackgroundProgress {
                        completed,
                        retryable: true,
                    });
                }
                Err(error) => return Err(map_writer(error)),
            }
        }

        let mut view = RuntimeSchedulerView::from_snapshot(&snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let max_synthesis_wall_time = Duration::from_secs(self.dreaming.max_wall_time.seconds());
        let synthesis_budget = self
            .synthesis
            .durable_budget(max_synthesis_wall_time)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let incompatible = view
            .jobs
            .iter()
            .filter(|job| {
                matches!(job.state, JobStatus::Queued | JobStatus::Leased)
                    && (job.kind == "session_import_v1"
                        && !import_job_is_current(job, self.runtime.effective_config_hash)
                        || job.kind == "semantic_synthesis_v1"
                            && (!self
                                .synthesis
                                .job_identity_is_current(job, self.runtime.effective_config_hash)
                                || !self.synthesis.job_is_current(
                                    job,
                                    self.runtime.effective_config_hash,
                                    &synthesis_budget,
                                )))
            })
            .cloned()
            .collect::<Vec<_>>();
        if !incompatible.is_empty() {
            let occurred_at_us = now_us()?;
            let mut events = Vec::new();
            let mut replacement_keys = BTreeSet::new();
            for mut job in incompatible {
                let needs_replacement = job.kind == "session_import_v1"
                    && !view.jobs.iter().any(|current| {
                        current.job_id != job.job_id
                            && matches!(current.state, JobStatus::Queued | JobStatus::Leased)
                            && current.idempotency_key == job.idempotency_key
                            && import_job_is_current(current, self.runtime.effective_config_hash)
                    })
                    && replacement_keys
                        .insert((job.idempotency_key.clone(), job.target_generation));
                let mut replacement = needs_replacement
                    .then(|| replacement_import_job(&job, self.runtime.effective_config_hash));
                job.state = JobStatus::Failed;
                job.lease_until_us = None;
                job.terminal = Some(Box::new(JobTerminalAudit {
                    outcome: JobTerminalOutcome::Failed,
                    reason: JobTerminalReason::Unsupported,
                    result_ref: Some(job.target_revision.clone()),
                }));
                events.push(JournalEventDraft {
                    occurred_at_us,
                    source_kind: SourceKind::System,
                    scope: EventScope::default(),
                    causation_id: None,
                    correlation_id: None,
                    effective_config_hash: job.config_hash,
                    algorithm_revision: job.algorithm_revision.clone(),
                    payload: JournalPayload::JobState(job),
                });
                if let Some(job) = replacement.take() {
                    events.push(JournalEventDraft {
                        occurred_at_us,
                        source_kind: SourceKind::System,
                        scope: EventScope::default(),
                        causation_id: None,
                        correlation_id: None,
                        effective_config_hash: job.config_hash,
                        algorithm_revision: job.algorithm_revision.clone(),
                        payload: JournalPayload::JobState(job),
                    });
                }
            }
            let command = JournalCommand::new(CommandId::new_v7(), events)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            match self
                .writer
                .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
                .await
            {
                Ok(outcome) => {
                    completed += usize::from(!outcome.replayed);
                    snapshot = self.writer.project().await.map_err(map_writer)?;
                    view = RuntimeSchedulerView::from_snapshot(&snapshot)
                        .map_err(|_| BackgroundSchedulerError::Store)?;
                }
                Err(WriterActorError::StaleFrontier) => {
                    return Ok(BackgroundProgress {
                        completed,
                        retryable: true,
                    });
                }
                Err(error) => return Err(map_writer(error)),
            }
        }
        let covered = view
            .jobs
            .iter()
            .filter(|job| {
                job.kind == "semantic_synthesis_v1"
                    && self
                        .synthesis
                        .job_identity_is_current(job, self.runtime.effective_config_hash)
                    && (!matches!(job.state, JobStatus::Queued | JobStatus::Leased)
                        || self.synthesis.job_is_current(
                            job,
                            self.runtime.effective_config_hash,
                            &synthesis_budget,
                        ))
            })
            .map(|job| {
                (
                    job.idempotency_key.clone(),
                    job.target_generation,
                    job.config_hash,
                )
            })
            .collect();
        let covered_projections = view
            .jobs
            .iter()
            .filter(|job| job.kind == "objects_projection")
            .map(|job| (job.idempotency_key.clone(), job.target_watermark))
            .collect::<BTreeSet<_>>();
        let projection_jobs = view
            .dirty
            .iter()
            .filter(|dirty| dirty.target_kind == DirtyTargetKind::ObjectsProjection)
            .filter(|dirty| {
                !covered_projections.contains(&(dirty.stable_key(), dirty.source_watermark))
            })
            .take(PER_LANE_LIMIT)
            .map(|dirty| DurableJob {
                job_id: JobId::new_v7(),
                idempotency_key: dirty.stable_key(),
                target_revision: dirty.target_id.clone(),
                target_watermark: dirty.source_watermark,
                target_generation: dirty.source_watermark.max(1),
                kind: "objects_projection".into(),
                algorithm_revision: dirty.algorithm_revision.clone(),
                model_id: None,
                priority: 0,
                state: JobStatus::Queued,
                attempt: 1,
                backoff_until_us: None,
                config_hash: self.runtime.effective_config_hash,
                budget: JobBudget {
                    max_items: 1,
                    max_bytes: None,
                    max_input_tokens: None,
                    max_output_tokens: None,
                    max_calls: None,
                    max_wall_time_ms: 250,
                },
                terminal: None,
                lease_until_us: None,
            })
            .collect::<Vec<_>>();
        if !projection_jobs.is_empty() {
            let occurred_at_us = now_us()?;
            let events = projection_jobs
                .into_iter()
                .map(|job| {
                    JournalEventDraft::runtime(
                        occurred_at_us,
                        job.config_hash,
                        job.algorithm_revision.clone(),
                        JournalPayload::JobState(job),
                    )
                })
                .collect();
            let command = JournalCommand::new(CommandId::new_v7(), events)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            match self
                .writer
                .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
                .await
            {
                Ok(_) => {
                    snapshot = self.writer.project().await.map_err(map_writer)?;
                    view = RuntimeSchedulerView::from_snapshot(&snapshot)
                        .map_err(|_| BackgroundSchedulerError::Store)?;
                }
                Err(WriterActorError::StaleFrontier) => retryable = true,
                Err(error) => return Err(map_writer(error)),
            }
        }
        let mut capture_candidates = BTreeMap::new();
        for dirty in view.dirty.iter().filter(|dirty| {
            matches!(
                dirty.target_kind,
                DirtyTargetKind::PhysicalNormalization | DirtyTargetKind::CaptureReconciliation
            )
        }) {
            let replace = dirty.target_kind == DirtyTargetKind::CaptureReconciliation
                && capture_candidates.get(&dirty.target_id).is_some_and(
                    |current: &evertrace_store::DirtyTarget| {
                        current.target_kind == DirtyTargetKind::PhysicalNormalization
                    },
                );
            if replace || !capture_candidates.contains_key(&dirty.target_id) {
                capture_candidates.insert(dirty.target_id.clone(), dirty.clone());
            }
        }
        let capture_candidates = capture_candidates
            .into_values()
            .filter(|dirty| {
                !capture_target_covered(&view, dirty, self.runtime.effective_config_hash)
            })
            .map(|dirty| {
                SourceObservationId::from_str(&dirty.target_id)
                    .map_err(|_| BackgroundSchedulerError::Store)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut probed = Vec::new();
        let capture_page_incomplete = capture_candidates.len() > CAPTURE_PROBE_LIMIT;
        if !capture_candidates.is_empty() {
            let start = self
                .capture_cursor
                .fetch_add(CAPTURE_PROBE_LIMIT, Ordering::Relaxed)
                % capture_candidates.len();
            probed.extend(
                (0..capture_candidates.len().min(CAPTURE_PROBE_LIMIT))
                    .map(|offset| capture_candidates[(start + offset) % capture_candidates.len()]),
            );
        }
        retryable |= capture_page_incomplete;
        let mut capture_items = BTreeMap::new();
        for chunk in probed.chunks(16) {
            let frontier = snapshot
                .reconciliation_frontier_for_observations(chunk)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            for item in frontier.items {
                let replace = item.target_kind == DirtyTargetKind::CaptureReconciliation
                    && capture_items.get(&item.target_id).is_some_and(
                        |current: &evertrace_store::ReconciliationWorkItem| {
                            current.target_kind == DirtyTargetKind::PhysicalNormalization
                        },
                    );
                if replace || !capture_items.contains_key(&item.target_id) {
                    capture_items.insert(item.target_id.clone(), item);
                }
            }
        }
        let report = self.report.read().await.clone();
        let occurred_at_us = now_us()?;
        let mut capture_jobs = Vec::new();
        for item in capture_items.into_values() {
            let kind = match item.target_kind {
                DirtyTargetKind::PhysicalNormalization => "physical_normalization",
                DirtyTargetKind::CaptureReconciliation => "capture_reconciliation",
                _ => return Err(BackgroundSchedulerError::Store),
            };
            let idempotency_key = format!("{kind}:{}", item.target_id);
            let active = view
                .jobs
                .iter()
                .filter(|job| {
                    is_capture_job(job)
                        && job.target_revision == item.target_id
                        && matches!(job.state, JobStatus::Queued | JobStatus::Leased)
                })
                .collect::<Vec<_>>();
            let current_active = active
                .iter()
                .filter(|existing| {
                    existing.kind == kind
                        && existing.idempotency_key == idempotency_key
                        && existing.target_watermark == item.source_event_seq
                        && existing.target_generation == item.source_event_seq.max(1)
                        && capture_job_is_current(existing, self.runtime.effective_config_hash)
                })
                .count();
            if current_active > 1 {
                return Err(BackgroundSchedulerError::Store);
            }
            for existing in active {
                let exact_tuple = existing.kind == kind
                    && existing.idempotency_key == idempotency_key
                    && existing.target_watermark == item.source_event_seq
                    && existing.target_generation == item.source_event_seq.max(1);
                if exact_tuple
                    && capture_job_is_current(existing, self.runtime.effective_config_hash)
                {
                    continue;
                }
                let mut failed = (*existing).clone();
                failed.state = JobStatus::Failed;
                failed.lease_until_us = None;
                failed.terminal = Some(Box::new(JobTerminalAudit {
                    outcome: JobTerminalOutcome::Failed,
                    reason: if exact_tuple {
                        JobTerminalReason::Unsupported
                    } else {
                        JobTerminalReason::StaleGeneration
                    },
                    result_ref: Some(failed.target_revision.clone()),
                }));
                capture_jobs.push(failed);
            }
            if current_active == 1 {
                continue;
            }
            let covered = view.jobs.iter().any(|job| {
                job.kind == kind
                    && job.idempotency_key == idempotency_key
                    && job.target_watermark == item.source_event_seq
                    && job.target_generation == item.source_event_seq.max(1)
                    && capture_job_is_current(job, self.runtime.effective_config_hash)
            });
            if covered || resolve_capture_report(&item, report.as_ref(), &self.runtime).is_none() {
                continue;
            }
            capture_jobs.push(DurableJob {
                job_id: JobId::new_v7(),
                idempotency_key,
                target_revision: item.target_id,
                target_watermark: item.source_event_seq,
                target_generation: item.source_event_seq.max(1),
                kind: kind.into(),
                algorithm_revision: CAPTURE_ALGORITHM_REVISION.into(),
                model_id: None,
                priority: 0,
                state: JobStatus::Queued,
                attempt: 1,
                backoff_until_us: None,
                config_hash: self.runtime.effective_config_hash,
                budget: capture_job_budget(),
                terminal: None,
                lease_until_us: None,
            });
        }
        if !capture_jobs.is_empty() {
            let events = capture_jobs
                .into_iter()
                .map(|job| {
                    JournalEventDraft::runtime(
                        occurred_at_us,
                        job.config_hash,
                        job.algorithm_revision.clone(),
                        JournalPayload::JobState(job),
                    )
                })
                .collect();
            let command = JournalCommand::new(CommandId::new_v7(), events)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            match self
                .writer
                .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
                .await
            {
                Ok(_) => {
                    snapshot = self.writer.project().await.map_err(map_writer)?;
                    view = RuntimeSchedulerView::from_snapshot(&snapshot)
                        .map_err(|_| BackgroundSchedulerError::Store)?;
                }
                Err(WriterActorError::StaleFrontier) => retryable = true,
                Err(error) => return Err(map_writer(error)),
            }
        }
        let synthesis_candidates = if self.dreaming.max_llm_tasks_per_run == 0 {
            Vec::new()
        } else {
            self.synthesis
                .durable_jobs(
                    &snapshot,
                    self.runtime.effective_config_hash,
                    &covered,
                    PER_LANE_LIMIT,
                    max_synthesis_wall_time,
                )
                .map_err(|_| BackgroundSchedulerError::Store)?
        };
        if !synthesis_candidates.is_empty() {
            let occurred_at_us = now_us()?;
            let events = synthesis_candidates
                .into_iter()
                .map(|job| JournalEventDraft {
                    occurred_at_us,
                    source_kind: SourceKind::System,
                    scope: EventScope::default(),
                    causation_id: None,
                    correlation_id: None,
                    effective_config_hash: job.config_hash,
                    algorithm_revision: job.algorithm_revision.clone(),
                    payload: JournalPayload::JobState(job),
                })
                .collect();
            let command = JournalCommand::new(CommandId::new_v7(), events)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            match self
                .writer
                .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
                .await
            {
                Ok(_) => {
                    snapshot = self.writer.project().await.map_err(map_writer)?;
                    view = RuntimeSchedulerView::from_snapshot(&snapshot)
                        .map_err(|_| BackgroundSchedulerError::Store)?;
                }
                Err(WriterActorError::StaleFrontier) => retryable = true,
                Err(error) => return Err(map_writer(error)),
            }
        }
        let selected = select_jobs(&view, capture_state)?;
        let paused_optional_pending = view.jobs.iter().any(|job| {
            matches!(job.state, JobStatus::Queued | JobStatus::Leased)
                && matches!(
                    job.kind.as_str(),
                    "physical_normalization"
                        | "session_import_v1"
                        | "semantic_synthesis_v1"
                        | evertrace_store::REPOSITORY_SCOPE_PURGE_JOB_KIND
                )
        });
        drop(snapshot);
        drop(view);
        for selected_job in selected
            .iter()
            .filter(|selected| selected.lane == BackgroundLane::Critical)
        {
            if let Some(claimed) = self.claim_job(&selected_job.job).await? {
                match claimed.job.kind.as_str() {
                    "support_closure" => {
                        completed += self
                            .run_support_closure(&claimed.snapshot, &claimed.job)
                            .await?;
                    }
                    "capture_reconciliation" => {
                        let progress = self.run_capture_reconciliation(claimed).await?;
                        completed += progress.completed;
                        retryable |= progress.retryable;
                    }
                    _ => return Err(BackgroundSchedulerError::Store),
                }
            }
        }
        for selected_job in selected
            .iter()
            .filter(|selected| selected.lane == BackgroundLane::Deterministic)
        {
            if let Some(claimed) = self.claim_job(&selected_job.job).await? {
                if claimed.job.kind == "physical_normalization" {
                    let progress = self.run_capture_reconciliation(claimed).await?;
                    completed += progress.completed;
                    retryable |= progress.retryable;
                    continue;
                }
                if claimed.job.kind != "objects_projection" {
                    return Err(BackgroundSchedulerError::Store);
                }
                if claimed.snapshot.frontier < claimed.job.target_watermark {
                    retryable = true;
                    continue;
                }
                let mut terminal = claimed.job;
                terminal.state = JobStatus::Succeeded;
                terminal.lease_until_us = None;
                terminal.terminal = Some(Box::new(JobTerminalAudit {
                    outcome: JobTerminalOutcome::Succeeded,
                    reason: JobTerminalReason::Completed,
                    result_ref: Some(terminal.target_revision.clone()),
                }));
                let occurred_at_us = now_us()?;
                let command = JournalCommand::new(
                    CommandId::new_v7(),
                    vec![JournalEventDraft::runtime(
                        occurred_at_us,
                        terminal.config_hash,
                        terminal.algorithm_revision.clone(),
                        JournalPayload::JobState(terminal),
                    )],
                )
                .map_err(|_| BackgroundSchedulerError::Store)?;
                match self
                    .writer
                    .commit_if_frontier(command, occurred_at_us, claimed.snapshot.frontier)
                    .await
                {
                    Ok(outcome) => completed += usize::from(!outcome.replayed),
                    Err(WriterActorError::StaleFrontier) => retryable = true,
                    Err(error) => return Err(map_writer(error)),
                }
            }
        }
        if let Some(selected_job) = selected
            .iter()
            .find(|selected| selected.lane == BackgroundLane::Maintenance)
        {
            if let Some(claimed) = self.claim_job(&selected_job.job).await? {
                if claimed.job.kind == QUIESCED_BACKUP_CREATE_JOB_KIND {
                    let progress = self.run_backup_create(claimed).await?;
                    completed += progress.completed;
                    retryable |= progress.retryable;
                } else if claimed.job.kind == QUIESCED_BACKUP_VERIFY_JOB_KIND {
                    let progress = self.run_backup_verify(claimed).await?;
                    completed += progress.completed;
                    retryable |= progress.retryable;
                } else if claimed.job.kind == evertrace_store::REPOSITORY_SCOPE_PURGE_JOB_KIND {
                    let progress = crate::jobs::reconcile_repository_scope_purge_batch(
                        &self.writer,
                        &self.runtime,
                        claimed.snapshot,
                        &claimed.job,
                        &self.repository_purge_plans,
                    )
                    .await
                    .map_err(map_writer)?;
                    completed += usize::from(progress.committed);
                    retryable |= progress.retryable;
                } else {
                    return Err(BackgroundSchedulerError::Store);
                }
            } else {
                retryable = true;
            }
        }
        retryable |= self.dreaming.max_llm_tasks_per_run != 0
            && selected
                .iter()
                .any(|selected| selected.lane == BackgroundLane::Synthesis);
        retryable |= !optional_allowed && paused_optional_pending;
        if optional_allowed
            && selected
                .iter()
                .any(|selected| selected.lane == BackgroundLane::Import)
        {
            let Some(import_job) = selected
                .iter()
                .find(|selected| selected.lane == BackgroundLane::Import)
            else {
                return Err(BackgroundSchedulerError::Store);
            };
            let max_items = usize::try_from(import_job.job.budget.max_items)
                .unwrap_or(usize::MAX)
                .min(PER_LANE_LIMIT);
            let max_bytes = import_job
                .job
                .budget
                .max_bytes
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(256 * 1024)
                .min(256 * 1024);
            let wall_time_ms = import_job.job.budget.max_wall_time_ms.min(250);
            match self
                .import
                .process_queued_once(
                    max_items,
                    SessionImportBudget {
                        max_bytes,
                        max_records: import_job.job.budget.max_items.min(16) as usize,
                        deadline: std::time::Instant::now() + Duration::from_millis(wall_time_ms),
                    },
                )
                .await
            {
                Ok((processed, pending)) => {
                    completed += processed;
                    retryable |= pending;
                }
                Err(_) => retryable = true,
            }
        }
        if optional_allowed && self.dreaming.max_llm_tasks_per_run != 0 {
            let synthesis_started = std::time::Instant::now();
            for selected_job in selected
                .iter()
                .filter(|selected| selected.lane == BackgroundLane::Synthesis)
                .take(usize::from(self.dreaming.max_llm_tasks_per_run))
            {
                let Some(remaining_wall_time) =
                    max_synthesis_wall_time.checked_sub(synthesis_started.elapsed())
                else {
                    retryable = true;
                    break;
                };
                let Some(claimed) = self.claim_job(&selected_job.job).await? else {
                    retryable = true;
                    continue;
                };
                let job_wall_time = Duration::from_millis(claimed.job.budget.max_wall_time_ms);
                let occurred_at_us = now_us()?;
                let daily_wall_time = self
                    .synthesis
                    .remaining_daily_wall_time(&claimed.snapshot, occurred_at_us)
                    .map_err(|_| BackgroundSchedulerError::Store)?;
                let execution_future = self.synthesis.execute_durable_job(
                    &claimed.snapshot,
                    &claimed.job,
                    self.runtime.effective_config_hash,
                    occurred_at_us,
                    max_synthesis_wall_time,
                );
                let execution = if daily_wall_time.is_zero() {
                    Ok(execution_future.await)
                } else {
                    tokio::time::timeout(
                        remaining_wall_time.min(job_wall_time).min(daily_wall_time),
                        execution_future,
                    )
                    .await
                };
                match execution {
                    Err(_) => {
                        retryable = true;
                        break;
                    }
                    Ok(Ok(command)) => match self
                        .writer
                        .commit_if_frontier(command, now_us()?, claimed.snapshot.frontier)
                        .await
                    {
                        Ok(outcome) => completed += usize::from(!outcome.replayed),
                        Err(WriterActorError::StaleFrontier) => retryable = true,
                        Err(error) => return Err(map_writer(error)),
                    },
                    Ok(Err(_)) => {
                        self.fail_stale(&claimed.job, claimed.snapshot.frontier)
                            .await?;
                        completed += 1;
                    }
                }
            }
        }
        Ok(BackgroundProgress {
            completed,
            retryable,
        })
    }

    async fn run_gc_round(&self) -> Result<usize, BackgroundSchedulerError> {
        let snapshot = self.writer.project().await.map_err(map_writer)?;
        let view = RuntimeSchedulerView::from_snapshot(&snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let Some(job) = view.jobs.iter().find(|job| {
            job.kind == evertrace_store::optimize::GC_ALGORITHM_REVISION
                && job.state == JobStatus::Queued
        }) else {
            return Ok(0);
        };
        let mut rounds = self.gc_rounds.lock().await;
        rounds.retain(|id, _| {
            view.jobs
                .iter()
                .any(|job| job.job_id == *id && job.state == JobStatus::Queued)
        });
        let data_dir = self
            .runtime
            .data_dir()
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let interrupted = data_dir
            .join("maintenance")
            .join(format!("gc-{}.json", job.job_id))
            .try_exists()
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let mut failed = interrupted;
        if !failed && !rounds.contains_key(&job.job_id) {
            // Enumeration progresses across ticks and jobs, but never survives
            // restart. Empty pinned pages neither finish the job nor start grace.
            let mut progress = self.gc_cursor.lock().await;
            let cursor = progress
                .take()
                .filter(|cursor| !cursor.finished())
                .unwrap_or_else(|| evertrace_capture::cas::CasGcCursor::new(0));
            match self.writer.mark_gc_page(self.runtime.clone(), cursor).await {
                Ok(page) => {
                    let finished = page.cursor.finished();
                    let empty = page.round.candidate_count() == 0;
                    *progress = Some(page.cursor);
                    if empty && !finished {
                        return Ok(0);
                    }
                    rounds.insert(job.job_id, page.round);
                    if !empty {
                        return Ok(0);
                    }
                }
                Err(_) => failed = true,
            }
        }
        if !failed
            && rounds.get(&job.job_id).is_some_and(|round| {
                round.candidate_count() != 0 && std::time::Instant::now() < round.ready_at()
            })
        {
            return Ok(0);
        }
        let Some(claimed) = self.claim_job(job).await? else {
            return Ok(0);
        };
        if !failed {
            let round = rounds
                .remove(&job.job_id)
                .ok_or(BackgroundSchedulerError::Store)?;
            failed = self
                .writer
                .sweep_gc(self.runtime.clone(), job.job_id, round)
                .await
                .is_err();
        }
        let mut terminal = claimed.job;
        terminal.state = if failed {
            JobStatus::Failed
        } else {
            JobStatus::Succeeded
        };
        terminal.lease_until_us = None;
        terminal.backoff_until_us = None;
        terminal.terminal = Some(Box::new(JobTerminalAudit {
            outcome: if failed {
                JobTerminalOutcome::Failed
            } else {
                JobTerminalOutcome::Succeeded
            },
            reason: if failed {
                JobTerminalReason::IntegrityFailure
            } else {
                JobTerminalReason::Completed
            },
            result_ref: Some(job.job_id.to_string()),
        }));
        let at = now_us()?;
        self.writer
            .commit(
                JournalCommand::new(
                    CommandId::new_v7(),
                    vec![JournalEventDraft::runtime(
                        at,
                        terminal.config_hash,
                        terminal.algorithm_revision.clone(),
                        JournalPayload::JobState(terminal),
                    )],
                )
                .map_err(|_| BackgroundSchedulerError::Store)?,
                at,
            )
            .await
            .map_err(map_writer)?;
        Ok(1)
    }

    async fn run_backup_create(
        &self,
        claimed: ClaimedJob,
    ) -> Result<BackgroundProgress, BackgroundSchedulerError> {
        let requests = self
            .backup_requests
            .as_ref()
            .ok_or(BackgroundSchedulerError::Store)?;
        let (reply, response) = oneshot::channel();
        requests
            .send(QuiescedBackupRequest {
                backup_job_id: claimed.job.job_id,
                reply,
            })
            .await
            .map_err(|_| BackgroundSchedulerError::Writer)?;
        let result = response
            .await
            .map_err(|_| BackgroundSchedulerError::Writer)?;
        self.finish_backup_job(claimed.job, result).await
    }

    async fn run_backup_verify(
        &self,
        claimed: ClaimedJob,
    ) -> Result<BackgroundProgress, BackgroundSchedulerError> {
        let backup_job_id = JobId::from_str(&claimed.job.target_revision)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let data_dir = self
            .runtime
            .data_dir()
            .map_err(|_| BackgroundSchedulerError::Store)?
            .to_owned();
        let backup_directory = data_dir
            .join("backups")
            .join(format!("backup-{backup_job_id}"));
        let prepared = tokio::task::spawn_blocking(move || {
            evertrace_store::backup::prepare_backup_verification(&data_dir, backup_job_id)
        })
        .await
        .map_err(|_| BackgroundSchedulerError::Store)?;
        let result = match prepared {
            Ok(verification) => {
                match evertrace_store::backup::complete_backup_verification(verification).await {
                    Ok(summary) => {
                        verify_hook_backup_assets(&backup_directory, &summary).map(|()| summary)
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        self.finish_backup_job(claimed.job, result).await
    }

    async fn finish_backup_job(
        &self,
        leased: DurableJob,
        result: Result<BackupSummary, BackupError>,
    ) -> Result<BackgroundProgress, BackgroundSchedulerError> {
        let snapshot = self.writer.project().await.map_err(map_writer)?;
        let current = RuntimeSchedulerView::from_snapshot(&snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?
            .jobs
            .into_iter()
            .find(|job| job.job_id == leased.job_id)
            .ok_or(BackgroundSchedulerError::Store)?;
        if current.state != JobStatus::Leased
            || current.target_generation != leased.target_generation
            || current.attempt != leased.attempt
            || current.kind != leased.kind
        {
            return Err(BackgroundSchedulerError::Store);
        }
        let mut terminal = current;
        terminal.lease_until_us = None;
        terminal.backoff_until_us = None;
        terminal.terminal = Some(Box::new(match result {
            Ok(summary) => {
                terminal.state = JobStatus::Succeeded;
                JobTerminalAudit {
                    outcome: JobTerminalOutcome::Succeeded,
                    reason: JobTerminalReason::Completed,
                    result_ref: Some(summary.backup_job_id.to_string()),
                }
            }
            Err(error) => {
                terminal.state = JobStatus::Failed;
                JobTerminalAudit {
                    outcome: JobTerminalOutcome::Failed,
                    reason: match error {
                        BackupError::Corrupt | BackupError::IdentityChanged => {
                            JobTerminalReason::IntegrityFailure
                        }
                        BackupError::ResourceExhausted => JobTerminalReason::BudgetExhausted,
                        BackupError::InvalidInput => JobTerminalReason::Unsupported,
                        BackupError::Io => JobTerminalReason::SourceUnavailable,
                    },
                    result_ref: None,
                }
            }
        }));
        let occurred_at_us = now_us()?;
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                occurred_at_us,
                terminal.config_hash,
                terminal.algorithm_revision.clone(),
                JournalPayload::JobState(terminal),
            )],
        )
        .map_err(|_| BackgroundSchedulerError::Store)?;
        match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(outcome) => Ok(BackgroundProgress {
                completed: usize::from(!outcome.replayed),
                retryable: false,
            }),
            Err(WriterActorError::StaleFrontier) => Ok(BackgroundProgress {
                completed: 0,
                retryable: true,
            }),
            Err(error) => Err(map_writer(error)),
        }
    }

    pub async fn run(
        self,
        mut wakeup: watch::Receiver<u64>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), BackgroundSchedulerError> {
        let mut durable = self.writer.subscribe_background_frontier();
        let mut run_at = tokio::time::Instant::now();
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                changed = wakeup.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                    run_at = tokio::time::Instant::now();
                }
                changed = durable.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                    run_at = tokio::time::Instant::now();
                }
                _ = tokio::time::sleep_until(run_at) => {
                    let progress = tokio::select! {
                        result = self.run_once() => result?,
                        _ = wait_for_shutdown(&mut shutdown) => return Ok(()),
                    };
                    run_at = tokio::time::Instant::now()
                        + self.next_wake_after(progress.retryable).await?;
                    tokio::task::yield_now().await;
                }
            }
        }
    }

    async fn next_wake_after(&self, retryable: bool) -> Result<Duration, BackgroundSchedulerError> {
        let snapshot = self.writer.project().await.map_err(map_writer)?;
        let view = RuntimeSchedulerView::from_snapshot(&snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let now = now_us()?;
        let lease_delay = view
            .jobs
            .iter()
            .filter(|job| job.state == JobStatus::Leased)
            .filter_map(|job| job.lease_until_us)
            .map(|deadline| {
                Duration::from_micros(u64::try_from(deadline.saturating_sub(now)).unwrap_or(0))
            })
            .min();
        let mut delay = Duration::from_secs(self.dreaming.integrity_sweep_interval.seconds());
        if retryable {
            delay = delay.min(RETRY_DELAY);
        }
        if let Some(lease_delay) = lease_delay {
            delay = delay.min(lease_delay);
        }
        Ok(delay)
    }

    async fn run_support_closure(
        &self,
        snapshot: &evertrace_store::ProjectionSnapshot,
        job: &DurableJob,
    ) -> Result<usize, BackgroundSchedulerError> {
        let (contract, current) = support_context(snapshot, job)?;
        let semantic = evertrace_store::SemanticCurrentView::from_snapshot(snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let current_atom_revisions = semantic
            .atoms
            .values()
            .filter(|atom| atom.lifecycle_status == AtomLifecycleStatus::Active)
            .map(|atom| atom.revision_id)
            .collect::<std::collections::BTreeSet<_>>();
        let mut surviving = Vec::new();
        let mut missing = Vec::new();
        for revision in &contract.support_revision_refs {
            if current_atom_revisions.contains(revision) {
                surviving.push(*revision);
            } else {
                missing.push(*revision);
            }
        }
        let authorization_current = contract.authorization_revision_refs.iter().all(|revision| {
            semantic.proposals.values().any(|proposal| {
                proposal.proposal_revision_id == *revision
                    && proposal.status == ProposalStatus::Accepted
            })
        });
        let action = support_closure_result(
            job,
            &contract,
            &current,
            surviving,
            missing,
            authorization_current,
            now_us()?,
        )
        .map_err(|_| BackgroundSchedulerError::Store)?;
        let mut terminal = job.clone();
        terminal.state = JobStatus::Succeeded;
        terminal.lease_until_us = None;
        let mut payloads = Vec::new();
        match action.disposition {
            JobResultDisposition::Apply => {
                let validation = action.validation.ok_or(BackgroundSchedulerError::Store)?;
                terminal.terminal = Some(Box::new(JobTerminalAudit {
                    outcome: JobTerminalOutcome::Succeeded,
                    reason: JobTerminalReason::Completed,
                    result_ref: Some(validation.validation_revision_id.to_string()),
                }));
                payloads.push(JournalPayload::GlobalSupportValidationRecorded(Box::new(
                    validation,
                )));
            }
            JobResultDisposition::StaleAudit(audit) => {
                terminal.state = JobStatus::Failed;
                terminal.terminal = Some(Box::new(JobTerminalAudit {
                    outcome: JobTerminalOutcome::Failed,
                    reason: JobTerminalReason::StaleGeneration,
                    result_ref: Some(job.target_revision.clone()),
                }));
                payloads.push(JournalPayload::StaleGenerationAudit(audit));
            }
        }
        payloads.push(JournalPayload::JobState(terminal));
        let occurred_at_us = now_us()?;
        let events = payloads
            .into_iter()
            .map(|payload| JournalEventDraft {
                occurred_at_us,
                source_kind: SourceKind::System,
                scope: EventScope::default(),
                causation_id: None,
                correlation_id: None,
                effective_config_hash: job.config_hash,
                algorithm_revision: job.algorithm_revision.clone(),
                payload,
            })
            .collect();
        let command = JournalCommand::new(CommandId::new_v7(), events)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(outcome) => Ok(usize::from(!outcome.replayed)),
            Err(WriterActorError::StaleFrontier) => Ok(0),
            Err(error) => Err(map_writer(error)),
        }
    }

    async fn run_capture_reconciliation(
        &self,
        mut claimed: ClaimedJob,
    ) -> Result<BackgroundProgress, BackgroundSchedulerError> {
        let report_guard = claimed
            .report
            .take()
            .ok_or(BackgroundSchedulerError::Store)?;
        let observation_id = SourceObservationId::from_str(&claimed.job.target_revision)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let expected_kind = match claimed.job.kind.as_str() {
            "physical_normalization" => DirtyTargetKind::PhysicalNormalization,
            "capture_reconciliation" => DirtyTargetKind::CaptureReconciliation,
            _ => return Err(BackgroundSchedulerError::Store),
        };
        let frontier = claimed
            .snapshot
            .reconciliation_frontier_for_observations(&[observation_id])
            .map_err(|_| BackgroundSchedulerError::Store)?;
        if frontier.items.is_empty() {
            return self
                .finish_job(
                    &claimed.job,
                    claimed.snapshot.frontier,
                    JobTerminalOutcome::Succeeded,
                    JobTerminalReason::Completed,
                )
                .await;
        }
        let Some(item) = frontier.items.iter().find(|item| {
            item.target_kind == expected_kind
                && item.source_event_seq == claimed.job.target_watermark
                && item.target_id == claimed.job.target_revision
        }) else {
            return self
                .finish_job(
                    &claimed.job,
                    claimed.snapshot.frontier,
                    JobTerminalOutcome::Failed,
                    JobTerminalReason::StaleGeneration,
                )
                .await;
        };
        if claimed.job.algorithm_revision != CAPTURE_ALGORITHM_REVISION
            || claimed.job.config_hash != self.runtime.effective_config_hash
        {
            return self
                .finish_job(
                    &claimed.job,
                    claimed.snapshot.frontier,
                    JobTerminalOutcome::Failed,
                    JobTerminalReason::Unsupported,
                )
                .await;
        }
        let Some(report) = resolve_capture_report(item, report_guard.as_ref(), &self.runtime)
        else {
            return Err(BackgroundSchedulerError::Store);
        };
        let reconciliation = reconcile_observations_once(
            ReconcileInput {
                runtime_snapshot: self.runtime.clone(),
                adapter_manifests: vec![report.manifest().clone()],
                liveness: Vec::new(),
                reconciled_gaps: Vec::new(),
                reconciled_outages: Vec::new(),
                independent_source_reconciliations: Vec::new(),
                effective_config_hash: self.runtime.effective_config_hash,
                algorithm_revision: CAPTURE_ALGORITHM_REVISION.into(),
                occurred_at_us: now_us()?,
                max_items: 1,
            },
            &self.writer,
            &[observation_id],
        )
        .await;
        drop(report_guard);
        let snapshot = self.writer.project().await.map_err(map_writer)?;
        let view = RuntimeSchedulerView::from_snapshot(&snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let current = view
            .jobs
            .into_iter()
            .find(|job| {
                job.job_id == claimed.job.job_id
                    && job.state == JobStatus::Leased
                    && job.attempt == claimed.job.attempt
                    && job.target_generation == claimed.job.target_generation
            })
            .ok_or(BackgroundSchedulerError::Store)?;
        let active = snapshot
            .reconciliation_frontier_for_observations(&[observation_id])
            .map_err(|_| BackgroundSchedulerError::Store)?
            .items;
        let (outcome, reason) = if active.is_empty() {
            (JobTerminalOutcome::Succeeded, JobTerminalReason::Completed)
        } else {
            match reconciliation {
                Ok(_) => (
                    JobTerminalOutcome::Failed,
                    JobTerminalReason::SourceUnavailable,
                ),
                Err(ReconcileError::StaleFrontier) => (
                    JobTerminalOutcome::Failed,
                    JobTerminalReason::StaleGeneration,
                ),
                Err(
                    ReconcileError::InvalidInput
                    | ReconcileError::Spool
                    | ReconcileError::Projection
                    | ReconcileError::Manifest
                    | ReconcileError::Domain
                    | ReconcileError::Commit
                    | ReconcileError::Acknowledgement,
                ) => (
                    JobTerminalOutcome::Failed,
                    JobTerminalReason::IntegrityFailure,
                ),
            }
        };
        self.finish_job(&current, snapshot.frontier, outcome, reason)
            .await
    }

    async fn finish_job(
        &self,
        job: &DurableJob,
        frontier: u64,
        outcome: JobTerminalOutcome,
        reason: JobTerminalReason,
    ) -> Result<BackgroundProgress, BackgroundSchedulerError> {
        if job.state != JobStatus::Leased || job.terminal.is_some() {
            return Err(BackgroundSchedulerError::Store);
        }
        let occurred_at_us = now_us()?;
        let mut terminal = job.clone();
        terminal.state = match outcome {
            JobTerminalOutcome::Succeeded => JobStatus::Succeeded,
            JobTerminalOutcome::Failed => JobStatus::Failed,
        };
        terminal.lease_until_us = None;
        terminal.backoff_until_us = None;
        terminal.terminal = Some(Box::new(JobTerminalAudit {
            outcome,
            reason,
            result_ref: Some(job.target_revision.clone()),
        }));
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                occurred_at_us,
                job.config_hash,
                job.algorithm_revision.clone(),
                JournalPayload::JobState(terminal),
            )],
        )
        .map_err(|_| BackgroundSchedulerError::Store)?;
        match self
            .writer
            .commit_if_frontier(command, occurred_at_us, frontier)
            .await
        {
            Ok(outcome) => Ok(BackgroundProgress {
                completed: usize::from(!outcome.replayed),
                retryable: false,
            }),
            Err(WriterActorError::StaleFrontier) => Ok(BackgroundProgress {
                completed: 0,
                retryable: true,
            }),
            Err(error) => Err(map_writer(error)),
        }
    }

    async fn claim_job(
        &self,
        selected: &DurableJob,
    ) -> Result<Option<ClaimedJob>, BackgroundSchedulerError> {
        let report = if is_capture_job(selected) {
            Some(Arc::clone(&self.report).read_owned().await)
        } else {
            None
        };
        let snapshot = self.writer.project().await.map_err(map_writer)?;
        let view = RuntimeSchedulerView::from_snapshot(&snapshot)
            .map_err(|_| BackgroundSchedulerError::Store)?;
        let Some(current) = view.jobs.iter().find(|job| job.job_id == selected.job_id) else {
            return Err(BackgroundSchedulerError::Store);
        };
        if current.state != JobStatus::Queued
            || current.target_generation != selected.target_generation
        {
            return Ok(None);
        }
        if !job_target_is_current(
            &snapshot,
            &view,
            current,
            self.runtime.effective_config_hash,
        )
        .map_err(|_| BackgroundSchedulerError::Store)?
        {
            let occurred_at_us = now_us()?;
            let mut stale = current.clone();
            stale.state = JobStatus::Failed;
            stale.lease_until_us = None;
            stale.backoff_until_us = None;
            stale.terminal = Some(Box::new(JobTerminalAudit {
                outcome: JobTerminalOutcome::Failed,
                reason: JobTerminalReason::StaleGeneration,
                result_ref: Some(stale.target_revision.clone()),
            }));
            let command = JournalCommand::new(
                CommandId::new_v7(),
                vec![JournalEventDraft::runtime(
                    occurred_at_us,
                    stale.config_hash,
                    stale.algorithm_revision.clone(),
                    JournalPayload::JobState(stale),
                )],
            )
            .map_err(|_| BackgroundSchedulerError::Store)?;
            match self
                .writer
                .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
                .await
            {
                Ok(_) | Err(WriterActorError::StaleFrontier) => {}
                Err(error) => return Err(map_writer(error)),
            }
            return Ok(None);
        }
        if let Some(report) = report.as_ref() {
            let observation_id = SourceObservationId::from_str(&current.target_revision)
                .map_err(|_| BackgroundSchedulerError::Store)?;
            let expected_kind = match current.kind.as_str() {
                "physical_normalization" => DirtyTargetKind::PhysicalNormalization,
                "capture_reconciliation" => DirtyTargetKind::CaptureReconciliation,
                _ => return Err(BackgroundSchedulerError::Store),
            };
            let frontier = snapshot
                .reconciliation_frontier_for_observations(&[observation_id])
                .map_err(|_| BackgroundSchedulerError::Store)?;
            if !capture_job_is_current(current, self.runtime.effective_config_hash) {
                return Ok(None);
            }
            if !frontier.items.is_empty()
                && !frontier.items.iter().any(|item| {
                    item.target_kind == expected_kind
                        && item.target_id == current.target_revision
                        && item.source_event_seq == current.target_watermark
                        && resolve_capture_report(item, report.as_ref(), &self.runtime).is_some()
                })
            {
                return Ok(None);
            }
        }
        let occurred_at_us = now_us()?;
        let lease_until_us = occurred_at_us
            .checked_add(
                i64::try_from(current.budget.max_wall_time_ms.min(5_000))
                    .map_err(|_| BackgroundSchedulerError::Store)?
                    .saturating_mul(1_000),
            )
            .ok_or(BackgroundSchedulerError::Store)?;
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft {
                occurred_at_us,
                source_kind: SourceKind::System,
                scope: EventScope::default(),
                causation_id: None,
                correlation_id: None,
                effective_config_hash: current.config_hash,
                algorithm_revision: current.algorithm_revision.clone(),
                payload: JournalPayload::JobLease(JobLease {
                    job_id: current.job_id,
                    target_generation: current.target_generation,
                    attempt: current
                        .attempt
                        .checked_add(1)
                        .ok_or(BackgroundSchedulerError::Store)?,
                    lease_until_us,
                }),
            }],
        )
        .map_err(|_| BackgroundSchedulerError::Store)?;
        match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(_) => {
                let snapshot = self.writer.project().await.map_err(map_writer)?;
                let view = RuntimeSchedulerView::from_snapshot(&snapshot)
                    .map_err(|_| BackgroundSchedulerError::Store)?;
                let job = view
                    .jobs
                    .into_iter()
                    .find(|job| job.job_id == selected.job_id)
                    .filter(|job| {
                        job.state == JobStatus::Leased
                            && job.target_generation == selected.target_generation
                    })
                    .ok_or(BackgroundSchedulerError::Store)?;
                Ok(Some(ClaimedJob {
                    snapshot,
                    job,
                    report,
                }))
            }
            Err(WriterActorError::StaleFrontier) => Ok(None),
            Err(error) => Err(map_writer(error)),
        }
    }

    async fn fail_stale(
        &self,
        job: &DurableJob,
        frontier: u64,
    ) -> Result<(), BackgroundSchedulerError> {
        let mut failed = job.clone();
        failed.state = JobStatus::Failed;
        failed.lease_until_us = None;
        failed.terminal = Some(Box::new(JobTerminalAudit {
            outcome: JobTerminalOutcome::Failed,
            reason: JobTerminalReason::StaleGeneration,
            result_ref: Some(job.target_revision.clone()),
        }));
        let occurred_at_us = now_us()?;
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft {
                occurred_at_us,
                source_kind: SourceKind::System,
                scope: EventScope::default(),
                causation_id: None,
                correlation_id: None,
                effective_config_hash: job.config_hash,
                algorithm_revision: job.algorithm_revision.clone(),
                payload: JournalPayload::JobState(failed),
            }],
        )
        .map_err(|_| BackgroundSchedulerError::Store)?;
        match self
            .writer
            .commit_if_frontier(command, occurred_at_us, frontier)
            .await
        {
            Ok(_) | Err(WriterActorError::StaleFrontier) => Ok(()),
            Err(error) => Err(map_writer(error)),
        }
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() || shutdown.changed().await.is_err() {
            return;
        }
    }
}

fn import_job_is_current(job: &DurableJob, effective_config_hash: [u8; 32]) -> bool {
    job.kind == "session_import_v1"
        && job.algorithm_revision == "session_import_v1"
        && job.model_id.is_none()
        && job.config_hash == effective_config_hash
        && job.budget == session_import_job_budget()
}

fn capture_job_budget() -> JobBudget {
    JobBudget {
        max_items: 1,
        max_bytes: None,
        max_input_tokens: None,
        max_output_tokens: None,
        max_calls: None,
        max_wall_time_ms: 250,
    }
}

fn capture_job_is_current(job: &DurableJob, effective_config_hash: [u8; 32]) -> bool {
    is_capture_job(job)
        && job.algorithm_revision == CAPTURE_ALGORITHM_REVISION
        && job.model_id.is_none()
        && job.config_hash == effective_config_hash
        && job.budget == capture_job_budget()
}

fn capture_target_covered(
    view: &RuntimeSchedulerView,
    dirty: &evertrace_store::DirtyTarget,
    effective_config_hash: [u8; 32],
) -> bool {
    let kind = match dirty.target_kind {
        DirtyTargetKind::PhysicalNormalization => "physical_normalization",
        DirtyTargetKind::CaptureReconciliation => "capture_reconciliation",
        _ => return false,
    };
    let idempotency_key = format!("{kind}:{}", dirty.target_id);
    let matching = |job: &DurableJob| {
        job.kind == kind
            && job.idempotency_key == idempotency_key
            && job.target_revision == dirty.target_id
            && job.target_watermark == dirty.source_watermark
            && job.target_generation == dirty.source_watermark.max(1)
            && capture_job_is_current(job, effective_config_hash)
    };
    if view.jobs.iter().any(|job| {
        is_capture_job(job)
            && job.target_revision == dirty.target_id
            && matches!(job.state, JobStatus::Queued | JobStatus::Leased)
            && !matching(job)
    }) {
        return false;
    }
    view.jobs.iter().any(matching)
}

fn is_capture_job(job: &DurableJob) -> bool {
    matches!(
        job.kind.as_str(),
        "physical_normalization" | "capture_reconciliation"
    )
}

fn capture_item_manifest_matches(
    item: &evertrace_store::ReconciliationWorkItem,
    report: &HostProbeReport,
) -> bool {
    if report.manifest().validate().is_err() {
        return false;
    }
    let manifest_id = report.manifest().adapter_manifest_id.as_str();
    let receipts = item.dependencies.iter().filter_map(|dependency| {
        if let JournalPayload::SourceReceiptRecorded(receipt) = &dependency.payload {
            Some(receipt.adapter_manifest_ref.as_str())
        } else {
            None
        }
    });
    let mut count = 0_usize;
    for receipt_manifest in receipts {
        count += 1;
        if receipt_manifest != manifest_id {
            return false;
        }
    }
    count != 0
}

fn resolve_capture_report(
    item: &evertrace_store::ReconciliationWorkItem,
    current: Option<&HostProbeReport>,
    runtime: &RuntimeSnapshot,
) -> Option<HostProbeReport> {
    if let Some(report) = current.filter(|report| capture_item_manifest_matches(item, report)) {
        return Some(report.clone());
    }
    // An unobserved native delivery has no lane/lifecycle authority. It can
    // normalize weak physical facts, never manufacture capture completeness.
    if item.target_kind != DirtyTargetKind::PhysicalNormalization {
        return None;
    }
    evertrace_codex::install::StableLauncher::retained_native_reports(runtime.data_dir().ok()?)
        .ok()?
        .into_iter()
        .find(|report| capture_item_manifest_matches(item, report))
}

pub fn select_jobs(
    view: &RuntimeSchedulerView,
    capture_state: CaptureAdmissionState,
) -> Result<Vec<ScheduledJob>, BackgroundSchedulerError> {
    let mut active = BTreeMap::<(String, String), DurableJob>::new();
    for job in view
        .jobs
        .iter()
        .filter(|job| job.state == JobStatus::Queued && executable_job(job))
    {
        let key = (job.kind.clone(), job.idempotency_key.clone());
        if let Some(existing) = active.get(&key) {
            if existing.target_generation == job.target_generation {
                return Err(BackgroundSchedulerError::Store);
            }
            if existing.target_generation > job.target_generation {
                continue;
            }
        }
        active.insert(key, job.clone());
    }
    let pause_optional = capture_state != CaptureAdmissionState::Normal;
    let mut candidates = active
        .into_values()
        .filter_map(|job| {
            let lane = job_lane(&job);
            (!pause_optional
                || lane == BackgroundLane::Critical
                || job.kind == "objects_projection")
                .then_some(ScheduledJob { lane, job })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.lane
            .cmp(&right.lane)
            .then_with(|| left.job.priority.cmp(&right.job.priority))
            .then_with(|| left.job.idempotency_key.cmp(&right.job.idempotency_key))
            .then_with(|| left.job.job_id.cmp(&right.job.job_id))
    });
    let mut lane_counts = BTreeMap::new();
    let mut selected = Vec::new();
    for candidate in candidates {
        let count = lane_counts.entry(candidate.lane).or_insert(0_usize);
        if *count == PER_LANE_LIMIT {
            continue;
        }
        *count += 1;
        selected.push(candidate);
        if selected.len() == TOTAL_LIMIT {
            break;
        }
    }
    Ok(selected)
}

fn executable_job(job: &DurableJob) -> bool {
    matches!(
        job.kind.as_str(),
        "support_closure"
            | "objects_projection"
            | "physical_normalization"
            | "capture_reconciliation"
            | "session_import_v1"
            | "semantic_synthesis_v1"
            | QUIESCED_BACKUP_CREATE_JOB_KIND
            | QUIESCED_BACKUP_VERIFY_JOB_KIND
            | evertrace_store::REPOSITORY_SCOPE_PURGE_JOB_KIND
    )
}

fn job_lane(job: &DurableJob) -> BackgroundLane {
    match job.kind.as_str() {
        "support_closure" | "capture_reconciliation" => BackgroundLane::Critical,
        "objects_projection" | "physical_normalization" => BackgroundLane::Deterministic,
        "session_import_v1" => BackgroundLane::Import,
        "semantic_synthesis_v1" => BackgroundLane::Synthesis,
        _ => BackgroundLane::Maintenance,
    }
}

fn support_context(
    snapshot: &evertrace_store::ProjectionSnapshot,
    job: &DurableJob,
) -> Result<(GlobalSuccessorSupportContract, GlobalSupportValidationEvent), BackgroundSchedulerError>
{
    let mut contracts = Vec::new();
    let mut validations = Vec::new();
    for row in snapshot.data_rows() {
        let Some(json) = row.payload_json.as_deref() else {
            return Err(BackgroundSchedulerError::Store);
        };
        let payload: JournalPayload =
            serde_json::from_str(json).map_err(|_| BackgroundSchedulerError::Store)?;
        match payload {
            JournalPayload::GlobalSupportContractRecorded(value)
                if value.successor_revision_or_membership_ref == job.target_revision =>
            {
                contracts.push(*value);
            }
            JournalPayload::GlobalSupportValidationRecorded(value)
                if value.successor_ref == job.target_revision =>
            {
                validations.push(*value);
            }
            _ => {}
        }
    }
    let [contract] = contracts.as_slice() else {
        return Err(BackgroundSchedulerError::Store);
    };
    validations.sort_by_key(|value| value.dependency_generation);
    let current = validations.last().ok_or(BackgroundSchedulerError::Store)?;
    if validations.len() > 1
        && validations[validations.len() - 2].dependency_generation == current.dependency_generation
    {
        return Err(BackgroundSchedulerError::Store);
    }
    Ok((contract.clone(), current.clone()))
}

fn now_us() -> Result<i64, BackgroundSchedulerError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| BackgroundSchedulerError::Store)?;
    i64::try_from(duration.as_micros()).map_err(|_| BackgroundSchedulerError::Store)
}

fn map_writer(error: WriterActorError) -> BackgroundSchedulerError {
    match error {
        WriterActorError::Stopped => BackgroundSchedulerError::Writer,
        _ => BackgroundSchedulerError::Store,
    }
}
