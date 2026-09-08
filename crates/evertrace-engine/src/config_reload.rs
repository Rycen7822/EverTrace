//! The single daemon configuration commit boundary. No on-disk configuration copy.
use crate::{EngineService, WriterHandle};
use evertrace_capture::{MaintenanceFence, RuntimeSnapshot};
use evertrace_domain::{config::EffectiveConfig, ids::CommandId};
use evertrace_store::{
    ConfigAudit, ConfigReloadAudit, ConfigReloadOutcome, ConfigReloadSource, JournalCommand,
    JournalEventDraft, JournalPayload,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, RwLock};

#[derive(Clone, Debug)]
pub struct ConfigReloadResult {
    pub active_hash: [u8; 32],
    pub pending_hash: Option<[u8; 32]>,
    pub outcome: ConfigReloadOutcome,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigReloadError {
    #[error("configuration input is unavailable or invalid")]
    Invalid,
    #[error("configuration commit is uncertain; stop admitting work")]
    Stopped,
    #[error("configuration publication is busy")]
    Busy,
}

pub struct ConfigReloadService {
    engine: Arc<EngineService>,
    writer: WriterHandle,
    data_dir: PathBuf,
    config_path: PathBuf,
    admission: RwLock<()>,
    serial: Mutex<()>,
    observed: Mutex<Option<evertrace_capture::confined_read::ConfinedFile>>,
    pending: std::sync::Mutex<Option<[u8; 32]>>,
    stopped: AtomicBool,
    #[cfg(test)]
    fault: std::sync::atomic::AtomicU8,
}

impl ConfigReloadService {
    pub fn new(
        engine: Arc<EngineService>,
        writer: WriterHandle,
        data_dir: PathBuf,
        config_path: PathBuf,
    ) -> Result<Self, ConfigReloadError> {
        evertrace_capture::CasStore::open(data_dir.join("cas"))
            .map_err(|_| ConfigReloadError::Invalid)?;
        Ok(Self {
            engine,
            writer,
            data_dir,
            config_path,
            admission: RwLock::new(()),
            serial: Mutex::new(()),
            observed: Mutex::new(None),
            pending: std::sync::Mutex::new(None),
            stopped: AtomicBool::new(false),
            #[cfg(test)]
            fault: std::sync::atomic::AtomicU8::new(0),
        })
    }

    /// The read guard is held only while fixing this operation's immutable value.
    pub async fn admit(&self) -> Result<Arc<EffectiveConfig>, ConfigReloadError> {
        let _gate = self.admission.read().await;
        if self.stopped.load(Ordering::Acquire) {
            return Err(ConfigReloadError::Stopped);
        }
        Ok(self.engine.effective_config())
    }

    pub(crate) async fn admit_job(
        &self,
    ) -> Result<Arc<crate::service::OperationConfig>, ConfigReloadError> {
        let _gate = self.admission.read().await;
        if self.stopped() {
            return Err(ConfigReloadError::Stopped);
        }
        Ok(self.engine.operation_config())
    }

    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Backup holds dispatch quiescence; serialize against reload and cue
    /// publication and verify all operational fields, not just the hash.
    pub async fn backup_runtime(
        &self,
        authority: &RuntimeSnapshot,
    ) -> Result<RuntimeSnapshot, ConfigReloadError> {
        let _serial = self.serial.lock().await;
        let config = self.admit().await?;
        let runtime = RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&self.data_dir))
            .map_err(|_| ConfigReloadError::Invalid)?;
        if runtime.data_dir().map_err(|_| ConfigReloadError::Invalid)? != self.data_dir
            || operation_runtime(authority, &config)?
                .sanitized_for_backup()
                .map_err(|_| ConfigReloadError::Invalid)?
                != runtime
                    .sanitized_for_backup()
                    .map_err(|_| ConfigReloadError::Invalid)?
        {
            return Err(ConfigReloadError::Invalid);
        }
        Ok(runtime)
    }

    /// Startup owns the writer and has not exposed any request handlers yet.
    /// A prior Prepared runtime is not promoted to historical reload success.
    pub async fn initialize_runtime(&self) -> Result<RuntimeSnapshot, ConfigReloadError> {
        let _serial = self.serial.lock().await;
        let config = self.engine.effective_config();
        let input = read_config(&self.config_path)?;
        let parsed = std::str::from_utf8(&input.bytes)
            .ok()
            .and_then(|text| EffectiveConfig::parse_toml(text).ok())
            .ok_or(ConfigReloadError::Invalid)?;
        if parsed.hash() != config.hash() {
            return Err(ConfigReloadError::Invalid);
        }
        let runtime = crate::recovery::prepare_recovery_runtime(&self.data_dir, &config, None)
            .map_err(|_| ConfigReloadError::Invalid)?;
        let projection = self
            .writer
            .project()
            .await
            .map_err(|_| ConfigReloadError::Invalid)?;
        let previous_hash = match projection
            .rows
            .iter()
            .find(|row| row.row_id == "runtime:config:current")
        {
            None => config.hash(),
            Some(row) => match row
                .payload_json
                .as_deref()
                .and_then(|json| serde_json::from_str::<JournalPayload>(json).ok())
            {
                Some(JournalPayload::ConfigAudit(audit)) if audit.is_applied() => {
                    audit.effective_config_hash
                }
                _ => return Err(ConfigReloadError::Invalid),
            },
        };
        let applied = Self::prepare_audit(
            &config,
            previous_hash,
            ConfigReloadOutcome::Applied,
            ConfigReloadSource::Startup,
        )?;
        self.audit(
            &config,
            previous_hash,
            ConfigReloadOutcome::Prepared,
            ConfigReloadSource::Startup,
        )
        .await?;
        let fence =
            MaintenanceFence::open(&self.data_dir).map_err(|_| ConfigReloadError::Invalid)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        let _guard = loop {
            match fence.exclusive() {
                Ok(guard) => break guard,
                Err(evertrace_capture::CasError::LockBusy) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(evertrace_capture::CasError::LockBusy) => return Err(ConfigReloadError::Busy),
                Err(_) => return Err(self.stop()),
            }
        };
        if read_config(&self.config_path)? != input {
            return Err(ConfigReloadError::Invalid);
        }
        runtime
            .publish(&RuntimeSnapshot::snapshot_path(&self.data_dir))
            .map_err(|_| self.stop())?;
        // Failure is a failed startup, never a claim that the previous daemon's
        // interrupted attempt completed. No request has been admitted.
        self.commit_audit(applied).await.map_err(|_| self.stop())?;
        *self.observed.lock().await = Some(input);
        Ok(runtime)
    }

    /// Poll the named file rather than an opened inode, so atomic replacement
    /// has exactly the same validation/commit path as an explicit reload.
    pub async fn watch_once(&self) -> Result<Option<ConfigReloadResult>, ConfigReloadError> {
        if self.stopped() {
            return Err(ConfigReloadError::Stopped);
        }
        let input = read_config(&self.config_path).ok();
        if *self.observed.lock().await == input {
            return Ok(None);
        }
        self.reload(ConfigReloadSource::Watcher).await.map(Some)
    }

    /// Recall owns cues, not operational configuration. Merge only its cue
    /// update into the current file while serializing with configuration commits.
    pub(crate) async fn publish_recall_cues(
        &self,
        proposed: &RuntimeSnapshot,
    ) -> Result<RuntimeSnapshot, ConfigReloadError> {
        let _serial = self.serial.lock().await;
        if self.stopped() {
            return Err(ConfigReloadError::Stopped);
        }
        let path = RuntimeSnapshot::snapshot_path(&self.data_dir);
        let mut current = RuntimeSnapshot::load(&path).map_err(|_| self.stop())?;
        if current.generation != proposed.generation
            || current.recall_cue_gate != proposed.recall_cue_gate
            || current.recall_cue_adapter_manifest_id != proposed.recall_cue_adapter_manifest_id
        {
            return Err(ConfigReloadError::Invalid);
        }
        current.recall_cues.clone_from(&proposed.recall_cues);
        current.validate().map_err(|_| ConfigReloadError::Invalid)?;
        current.publish(&path).map_err(|_| self.stop())?;
        Ok(current)
    }

    pub async fn reload(
        &self,
        source: ConfigReloadSource,
    ) -> Result<ConfigReloadResult, ConfigReloadError> {
        let _serial = self.serial.lock().await;
        self.reload_inner(source).await
    }

    pub fn read_editable(&self) -> Result<(String, String), ConfigReloadError> {
        let file = read_config(&self.config_path)?;
        if file.bytes.len() > 128 * 1024 {
            return Err(ConfigReloadError::Invalid);
        }
        let hash = config_file_hash(&file.bytes)?;
        let source = String::from_utf8(file.bytes).map_err(|_| ConfigReloadError::Invalid)?;
        Ok((source, hash))
    }

    pub async fn write_optimistic(
        &self,
        source: &str,
        expected_hash: &str,
    ) -> Result<ConfigReloadResult, ConfigReloadError> {
        let _serial = self.serial.lock().await;
        if self.stopped() {
            return Err(ConfigReloadError::Stopped);
        }
        if source.len() > 128 * 1024 || EffectiveConfig::parse_toml(source).is_err() {
            return Err(ConfigReloadError::Invalid);
        }
        let previous = read_config(&self.config_path)?;
        if config_file_hash(&previous.bytes)? != expected_hash {
            return Err(ConfigReloadError::Invalid);
        }
        use std::{
            fs::OpenOptions,
            io::Write,
            os::unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let parent_path = self
            .config_path
            .parent()
            .ok_or(ConfigReloadError::Invalid)?;
        let parent = evertrace_capture::ConfinedRoot::open(parent_path)
            .map_err(|_| ConfigReloadError::Invalid)?;
        let name = self
            .config_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ConfigReloadError::Invalid)?;
        let mut created = None;
        for slot in 0..16 {
            let path = parent_path.join(format!(".{name}.reload-{slot}.tmp"));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => {
                    created = Some((path, file));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(ConfigReloadError::Invalid),
            }
        }
        let (path, mut file) = created.ok_or(ConfigReloadError::Busy)?;
        let identity = file.metadata().map_err(|_| ConfigReloadError::Invalid)?;
        let prepared = (|| {
            file.write_all(source.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|_| ConfigReloadError::Invalid)?;
            parent
                .revalidate_stable()
                .map_err(|_| ConfigReloadError::Invalid)?;
            if read_config(&self.config_path)? != previous {
                return Err(ConfigReloadError::Invalid);
            }
            Ok(())
        })();
        if let Err(error) = prepared {
            if parent.revalidate_stable().is_ok()
                && std::fs::symlink_metadata(&path)
                    .is_ok_and(|now| (now.dev(), now.ino()) == (identity.dev(), identity.ino()))
            {
                let _ = std::fs::remove_file(&path);
            }
            return Err(error);
        }
        std::fs::rename(&path, &self.config_path).map_err(|_| self.stop())?;
        std::fs::File::open(parent_path)
            .and_then(|file| file.sync_all())
            .map_err(|_| self.stop())?;
        parent.revalidate_stable().map_err(|_| self.stop())?;
        self.reload_inner(ConfigReloadSource::Tui).await
    }

    async fn reload_inner(
        &self,
        source: ConfigReloadSource,
    ) -> Result<ConfigReloadResult, ConfigReloadError> {
        if self.stopped() {
            return Err(ConfigReloadError::Stopped);
        }
        let old_operation = self.engine.operation_config();
        let old = Arc::clone(&old_operation.effective);
        // Pending describes only the latest complete input, never a previously
        // valid file that has since disappeared or become malformed.
        *self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let input = read_config(&self.config_path);
        let candidate = input.as_ref().ok().and_then(|bytes| {
            std::str::from_utf8(&bytes.bytes)
                .ok()
                .and_then(|text| EffectiveConfig::parse_toml(text).ok())
        });
        let Some(candidate) = candidate else {
            *self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            self.audit(&old, old.hash(), ConfigReloadOutcome::Rejected, source)
                .await?;
            *self.observed.lock().await = input.ok();
            return Ok(ConfigReloadResult {
                active_hash: old.hash(),
                pending_hash: None,
                outcome: ConfigReloadOutcome::Rejected,
            });
        };
        let bytes = input?;
        let candidate = Arc::new(candidate);
        if candidate.config().runtime.data_dir != old.config().runtime.data_dir
            || candidate.config().runtime.background_workers
                != old.config().runtime.background_workers
        {
            self.audit(
                &candidate,
                old.hash(),
                ConfigReloadOutcome::RestartRequired,
                source,
            )
            .await?;
            *self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(candidate.hash());
            *self.observed.lock().await = Some(bytes);
            return Ok(ConfigReloadResult {
                active_hash: old.hash(),
                pending_hash: Some(candidate.hash()),
                outcome: ConfigReloadOutcome::RestartRequired,
            });
        }
        let path = RuntimeSnapshot::snapshot_path(&self.data_dir);
        let previous_runtime =
            RuntimeSnapshot::load(&path).map_err(|_| ConfigReloadError::Invalid)?;
        let runtime = operation_runtime(&previous_runtime, &candidate)?;
        let prepared = self
            .engine
            .prepare_config(Arc::clone(&candidate))
            .map_err(|_| ConfigReloadError::Invalid)?;
        let applied =
            Self::prepare_audit(&candidate, old.hash(), ConfigReloadOutcome::Applied, source)?;
        self.audit(
            &candidate,
            old.hash(),
            ConfigReloadOutcome::Prepared,
            source,
        )
        .await?;
        let fence =
            MaintenanceFence::open(&self.data_dir).map_err(|_| ConfigReloadError::Invalid)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        let (gate, maintenance) = loop {
            let gate = self.admission.write().await;
            match fence.exclusive() {
                Ok(guard) => break (gate, guard),
                Err(evertrace_capture::CasError::LockBusy) => {
                    drop(gate);
                    if Instant::now() >= deadline {
                        return Err(ConfigReloadError::Busy);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(_) => return Err(self.stop()),
            }
        };
        // A changed input cannot publish the earlier validated candidate.
        if read_config(&self.config_path)? != bytes {
            return Err(ConfigReloadError::Invalid);
        }
        if RuntimeSnapshot::load(&path).map_err(|_| self.stop())? != previous_runtime {
            return Err(self.stop());
        }
        // publish can fail after rename. Its Err is deliberately never treated
        // as proof that the old file is still installed.
        runtime.publish(&path).map_err(|_| self.stop())?;
        #[cfg(test)]
        if self.fault.load(Ordering::Relaxed) == 3 {
            return Err(self.stop());
        }
        self.engine.apply_config(prepared);
        match self.commit_audit(applied).await {
            Ok(()) => {}
            Err(ConfigReloadError::Invalid) => {
                previous_runtime.publish(&path).map_err(|_| self.stop())?;
                self.engine.apply_config(old_operation);
                self.audit(
                    &candidate,
                    old.hash(),
                    ConfigReloadOutcome::Rejected,
                    source,
                )
                .await?;
                return Err(ConfigReloadError::Invalid);
            }
            Err(_) => return Err(self.stop()),
        }
        self.engine.finish_config_commit();
        *self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        drop(maintenance);
        drop(gate);
        *self.observed.lock().await = Some(bytes);
        Ok(ConfigReloadResult {
            active_hash: candidate.hash(),
            pending_hash: None,
            outcome: ConfigReloadOutcome::Applied,
        })
    }

    fn stop(&self) -> ConfigReloadError {
        self.stopped.store(true, Ordering::Release);
        ConfigReloadError::Stopped
    }

    async fn audit(
        &self,
        candidate: &EffectiveConfig,
        previous_config_hash: [u8; 32],
        outcome: ConfigReloadOutcome,
        source: ConfigReloadSource,
    ) -> Result<(), ConfigReloadError> {
        self.commit_audit(Self::prepare_audit(
            candidate,
            previous_config_hash,
            outcome,
            source,
        )?)
        .await
    }

    fn prepare_audit(
        candidate: &EffectiveConfig,
        previous_config_hash: [u8; 32],
        outcome: ConfigReloadOutcome,
        source: ConfigReloadSource,
    ) -> Result<(JournalCommand, i64, JournalPayload), ConfigReloadError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|v| i64::try_from(v.as_micros()).ok())
            .ok_or(ConfigReloadError::Invalid)?;
        let payload = JournalPayload::ConfigAudit(ConfigAudit {
            config_version: candidate.config().config_version,
            effective_config_hash: candidate.hash(),
            reload: Some(ConfigReloadAudit {
                previous_config_hash,
                outcome,
                source,
                actor: format!("uid:{}", rustix::process::getuid().as_raw()),
            }),
        });
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                now,
                previous_config_hash,
                "config-reload-v1",
                payload.clone(),
            )],
        )
        .map_err(|_| ConfigReloadError::Invalid)?;
        Ok((command, now, payload))
    }

    async fn commit_audit(
        &self,
        (command, _, payload): (JournalCommand, i64, JournalPayload),
    ) -> Result<(), ConfigReloadError> {
        // Observe the attempt once, immediately before submission. Lost-ack
        // resolution below retains this exact command and never retimes it.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|value| i64::try_from(value.as_micros()).ok())
            .ok_or_else(|| self.stop())?;
        let mut events = command.events().to_vec();
        for event in &mut events {
            event.occurred_at_us = now;
        }
        let command = JournalCommand::new(command.command_id(), events).map_err(|_| self.stop())?;
        #[cfg(test)]
        let applied = matches!(&payload, JournalPayload::ConfigAudit(audit) if audit.reload.as_ref().is_some_and(|detail| detail.outcome == ConfigReloadOutcome::Applied));
        #[cfg(test)]
        if applied && self.fault.load(Ordering::Relaxed) == 1 {
            return Err(ConfigReloadError::Invalid);
        }
        let id = command.command_id();
        let acknowledged = self.writer.commit(command, now).await.is_ok();
        #[cfg(test)]
        let acknowledged = acknowledged && !(applied && self.fault.load(Ordering::Relaxed) == 2);
        if acknowledged {
            return Ok(());
        }
        match self.writer.committed_command(id).await {
            Ok(Some(committed)) if committed.payloads == [payload] => Ok(()),
            Ok(None) => Err(ConfigReloadError::Invalid),
            _ => Err(self.stop()),
        }
    }
}

fn config_file_hash(bytes: &[u8]) -> Result<String, ConfigReloadError> {
    evertrace_capture::cas::copy_exact_sha256_hex(
        &mut std::io::Cursor::new(bytes),
        &mut std::io::sink(),
        bytes.len() as u64,
    )
    .map_err(|_| ConfigReloadError::Invalid)
}

pub(crate) fn operation_runtime(
    authority: &RuntimeSnapshot,
    config: &EffectiveConfig,
) -> Result<RuntimeSnapshot, ConfigReloadError> {
    let settings = crate::RecoveryRuntimeSettings::compile(config, None, authority.generation)
        .map_err(|_| ConfigReloadError::Invalid)?;
    let mut runtime = authority.clone();
    // Keep implementation, generation, capability gates and cues unchanged.
    runtime.effective_config_hash = config.hash();
    runtime.recovery_preflight_timeout_ms = settings.capture_timeout_ms;
    runtime.recovery_max_bundle_bytes = settings.max_bundle_bytes;
    runtime.recovery_max_untracked_file_bytes = settings.max_untracked_file_bytes;
    runtime.recovery_max_untracked_total_bytes = settings.max_untracked_total_bytes;
    runtime.validate().map_err(|_| ConfigReloadError::Invalid)?;
    Ok(runtime)
}

fn read_config(
    path: &Path,
) -> Result<evertrace_capture::confined_read::ConfinedFile, ConfigReloadError> {
    use evertrace_capture::confined_read::{ConfinedReadLimits, ConfinedRoot};
    let root = ConfinedRoot::open(path.parent().ok_or(ConfigReloadError::Invalid)?)
        .map_err(|_| ConfigReloadError::Invalid)?;
    root.read(
        Path::new(path.file_name().ok_or(ConfigReloadError::Invalid)?),
        ConfinedReadLimits {
            single_file_remaining: 1 << 20,
            untracked_total_remaining: 1 << 20,
            bundle_remaining: 1 << 20,
            deadline: Instant::now() + Duration::from_secs(1),
        },
    )
    .map_err(|_| ConfigReloadError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    #[tokio::test]
    async fn publication_failure_lost_ack_and_interrupted_runtime_keep_distinct_authority() {
        let root = std::env::temp_dir().join(format!("evertrace-reload-{}", CommandId::new_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let data = root.join("data");
        let path = root.join("config.toml");
        let mut initial = EffectiveConfig::default().config().clone();
        initial.runtime.data_dir = data.to_str().unwrap().into();
        let initial = EffectiveConfig::new(initial).unwrap();
        std::fs::write(&path, initial.to_toml().unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let engine = Arc::new(
            EngineService::from_toml(&initial.to_toml().unwrap(), crate::RuntimeMode::Normal)
                .unwrap(),
        );
        let (writer, task) =
            crate::spawn_writer(crate::open_writer(&data).await.unwrap(), 8).unwrap();
        let reload = ConfigReloadService::new(
            Arc::clone(&engine),
            writer.clone(),
            data.clone(),
            path.clone(),
        )
        .unwrap();
        let authority = reload.initialize_runtime().await.unwrap();
        assert_eq!(reload.backup_runtime(&authority).await.unwrap(), authority);
        let mut untrusted = authority.clone();
        untrusted.generation += 1;
        untrusted
            .publish(&RuntimeSnapshot::snapshot_path(&data))
            .unwrap();
        assert!(reload.backup_runtime(&authority).await.is_err());
        authority
            .publish(&RuntimeSnapshot::snapshot_path(&data))
            .unwrap();
        let mut changed = initial.config().clone();
        changed.search.get_token_budget = 17;
        let changed = EffectiveConfig::new(changed).unwrap();
        // Health's maintenance fast path uses this same admission boundary:
        // even an installed in-memory candidate is invisible until release.
        let old_operation = engine.operation_config();
        let candidate_operation = engine.prepare_config(Arc::new(changed.clone())).unwrap();
        let gate = reload.admission.write().await;
        engine.apply_config(candidate_operation);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), reload.admit())
                .await
                .is_err()
        );
        engine.apply_config(old_operation);
        drop(gate);
        assert_eq!(reload.admit().await.unwrap().hash(), initial.hash());
        std::fs::write(&path, changed.to_toml().unwrap()).unwrap();
        reload.fault.store(1, Ordering::Relaxed);
        assert!(matches!(
            reload.reload(ConfigReloadSource::Cli).await,
            Err(ConfigReloadError::Invalid)
        ));
        assert_eq!(reload.admit().await.unwrap().hash(), initial.hash());
        assert_eq!(
            RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&data))
                .unwrap()
                .effective_config_hash,
            initial.hash()
        );
        reload.fault.store(2, Ordering::Relaxed);
        assert_eq!(
            reload
                .reload(ConfigReloadSource::Cli)
                .await
                .unwrap()
                .outcome,
            ConfigReloadOutcome::Applied
        );
        assert_eq!(reload.admit().await.unwrap().hash(), changed.hash());
        std::fs::write(&path, initial.to_toml().unwrap()).unwrap();
        reload.fault.store(3, Ordering::Relaxed);
        assert!(matches!(
            reload.reload(ConfigReloadSource::Cli).await,
            Err(ConfigReloadError::Stopped)
        ));
        assert!(reload.admit().await.is_err());
        assert_eq!(
            RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&data))
                .unwrap()
                .effective_config_hash,
            initial.hash()
        );
        let current = writer.project().await.unwrap();
        let audit: JournalPayload = serde_json::from_str(
            current
                .rows
                .iter()
                .find(|row| row.row_id == "runtime:config:current")
                .unwrap()
                .payload_json
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        assert!(
            matches!(audit, JournalPayload::ConfigAudit(audit) if audit.effective_config_hash == changed.hash())
        );
        writer.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        drop(reload);
        // A fresh startup coordinates its own TOML; it never retroactively
        // marks the interrupted CLI attempt as Applied.
        let engine = Arc::new(
            EngineService::from_toml(&initial.to_toml().unwrap(), crate::RuntimeMode::Normal)
                .unwrap(),
        );
        let (writer, task) =
            crate::spawn_writer(crate::open_writer(&data).await.unwrap(), 8).unwrap();
        let startup = ConfigReloadService::new(engine, writer.clone(), data.clone(), path).unwrap();
        startup.initialize_runtime().await.unwrap();
        assert_eq!(startup.admit().await.unwrap().hash(), initial.hash());
        let projection = writer.project().await.unwrap();
        let row = projection
            .rows
            .iter()
            .find(|row| row.row_id == "runtime:config:current")
            .unwrap();
        let JournalPayload::ConfigAudit(audit) =
            serde_json::from_str(row.payload_json.as_ref().unwrap()).unwrap()
        else {
            panic!("config audit");
        };
        assert_eq!(audit.reload.unwrap().previous_config_hash, changed.hash());
        let native = evertrace_store::connection::CompatibilityStore::connect_local(
            &evertrace_store::connection::native_root(&data),
        )
        .await
        .unwrap();
        let table = native
            .connection()
            .open_table(evertrace_store::JOURNAL_TABLE)
            .execute()
            .await
            .unwrap();
        let rows = evertrace_store::journal::read_all_journal_rows(&table)
            .await
            .unwrap();
        let mut prepared_time = None;
        for row in rows {
            if let Ok(JournalPayload::ConfigAudit(audit)) = serde_json::from_str(&row.payload_json)
            {
                match audit.reload.unwrap().outcome {
                    ConfigReloadOutcome::Prepared => prepared_time = Some(row.occurred_at_us),
                    ConfigReloadOutcome::Applied => {
                        assert!(row.occurred_at_us >= prepared_time.unwrap())
                    }
                    _ => {}
                }
            }
        }
        drop(table);
        drop(native);
        writer.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        drop(startup);
        std::fs::remove_dir_all(root).unwrap();
    }
}
