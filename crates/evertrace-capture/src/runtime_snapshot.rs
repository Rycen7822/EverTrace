use std::{
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::spool::SpoolLimits;

pub const RUNTIME_SNAPSHOT_VERSION: u16 = 4;
const SNAPSHOT_MAGIC: &[u8; 8] = b"ETRUN001";

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSnapshot {
    pub snapshot_version: u16,
    pub generation: u64,
    pub device_key_dir: PathBuf,
    pub cas_dir: PathBuf,
    pub spool_dir: PathBuf,
    pub main_high_watermark_bytes: u64,
    pub main_low_watermark_bytes: u64,
    pub max_main_files: u32,
    pub emergency_slots: u16,
    pub effective_config_hash: [u8; 32],
    pub recovery_gate: RecoveryGateMode,
    pub recovery_adapter_manifest_id: Option<String>,
    pub recovery_classifier_revision: u32,
    pub recovery_socket_path: PathBuf,
    pub recovery_preflight_timeout_ms: u32,
    pub recovery_max_bundle_bytes: u64,
    pub recovery_max_untracked_file_bytes: u64,
    pub recovery_max_untracked_total_bytes: u64,
    pub recall_cue_gate: RecallCueGateMode,
    pub recall_cue_adapter_manifest_id: Option<String>,
    pub recall_cues: Vec<evertrace_domain::recall::RecallCueSnapshot>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryGateMode {
    Disabled,
    BestEffort,
    Active,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallCueGateMode {
    Disabled,
    Active,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySnapshotSettings {
    pub gate: RecoveryGateMode,
    pub preflight_timeout_ms: u32,
    pub effective_config_hash: [u8; 32],
    pub adapter_manifest_id: Option<String>,
    pub classifier_revision: u32,
    pub max_bundle_bytes: u64,
    pub max_untracked_file_bytes: u64,
    pub max_untracked_total_bytes: u64,
    pub recall_cue_gate: RecallCueGateMode,
    pub recall_cue_adapter_manifest_id: Option<String>,
}

impl fmt::Debug for RuntimeSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeSnapshot")
            .field("snapshot_version", &self.snapshot_version)
            .field("generation", &self.generation)
            .field("paths_configured", &true)
            .field("main_high_watermark_bytes", &self.main_high_watermark_bytes)
            .field("main_low_watermark_bytes", &self.main_low_watermark_bytes)
            .field("max_main_files", &self.max_main_files)
            .field("emergency_slots", &self.emergency_slots)
            .field("recovery_gate", &self.recovery_gate)
            .field(
                "has_recovery_adapter_manifest",
                &self.recovery_adapter_manifest_id.is_some(),
            )
            .field("recovery_socket_configured", &true)
            .field(
                "recovery_preflight_timeout_ms",
                &self.recovery_preflight_timeout_ms,
            )
            .finish()
    }
}

impl RuntimeSnapshot {
    pub fn for_data_dir(
        data_dir: &Path,
        generation: u64,
        limits: SpoolLimits,
        recovery: RecoverySnapshotSettings,
    ) -> Result<Self, RuntimeSnapshotError> {
        if !is_normal_absolute(data_dir) {
            return Err(RuntimeSnapshotError::Invalid);
        }
        let snapshot = Self {
            snapshot_version: RUNTIME_SNAPSHOT_VERSION,
            generation,
            device_key_dir: data_dir.join("keys"),
            cas_dir: data_dir.join("cas"),
            spool_dir: data_dir.join("spool"),
            main_high_watermark_bytes: limits.high_watermark_bytes,
            main_low_watermark_bytes: limits.low_watermark_bytes,
            max_main_files: limits.max_main_files,
            emergency_slots: limits.emergency_slots,
            effective_config_hash: recovery.effective_config_hash,
            recovery_gate: recovery.gate,
            recovery_adapter_manifest_id: recovery.adapter_manifest_id,
            recovery_classifier_revision: recovery.classifier_revision,
            recovery_socket_path: data_dir.join("runtime/evertraced-v1.sock"),
            recovery_preflight_timeout_ms: recovery.preflight_timeout_ms,
            recovery_max_bundle_bytes: recovery.max_bundle_bytes,
            recovery_max_untracked_file_bytes: recovery.max_untracked_file_bytes,
            recovery_max_untracked_total_bytes: recovery.max_untracked_total_bytes,
            recall_cue_gate: recovery.recall_cue_gate,
            recall_cue_adapter_manifest_id: recovery.recall_cue_adapter_manifest_id,
            recall_cues: Vec::new(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn snapshot_path(data_dir: &Path) -> PathBuf {
        data_dir.join("runtime/hook-runtime-v1.json")
    }

    pub fn data_dir(&self) -> Result<&Path, RuntimeSnapshotError> {
        let data_dir = self
            .spool_dir
            .parent()
            .ok_or(RuntimeSnapshotError::Invalid)?;
        if !is_normal_absolute(data_dir)
            || self.device_key_dir != data_dir.join("keys")
            || self.cas_dir != data_dir.join("cas")
            || self.spool_dir != data_dir.join("spool")
            || self.recovery_socket_path != data_dir.join("runtime/evertraced-v1.sock")
        {
            return Err(RuntimeSnapshotError::Invalid);
        }
        Ok(data_dir)
    }

    pub fn validate(&self) -> Result<(), RuntimeSnapshotError> {
        if self.snapshot_version != RUNTIME_SNAPSHOT_VERSION
            || self.generation == 0
            || [&self.device_key_dir, &self.cas_dir, &self.spool_dir]
                .iter()
                .any(|path| !path.is_absolute())
            || !self.recovery_socket_path.is_absolute()
            || self.recovery_preflight_timeout_ms == 0
            || self.recovery_preflight_timeout_ms > 120_000
            || self.recovery_classifier_revision == 0
            || self.effective_config_hash == [0; 32]
            || self.recovery_max_bundle_bytes == 0
            || self.recovery_max_untracked_file_bytes == 0
            || self.recovery_max_untracked_total_bytes == 0
            || self.recovery_max_untracked_file_bytes > self.recovery_max_untracked_total_bytes
            || self.recovery_max_untracked_total_bytes > self.recovery_max_bundle_bytes
            || (self.recovery_gate == RecoveryGateMode::Active)
                != self.recovery_adapter_manifest_id.is_some()
            || (self.recall_cue_gate == RecallCueGateMode::Active)
                != self.recall_cue_adapter_manifest_id.is_some()
            || self.recall_cues.len() > 32
            || self.recall_cues.iter().any(|cue| {
                !cue.validate()
                    || cue.runtime_generation != self.generation
                    || Some(cue.adapter_manifest_id.as_str())
                        != self.recall_cue_adapter_manifest_id.as_deref()
            })
            || self.recall_cues.windows(2).any(|pair| {
                pair[0]
                    .session_id
                    .cmp(&pair[1].session_id)
                    .then(pair[0].execution_lane_id.cmp(&pair[1].execution_lane_id))
                    .then(
                        pair[0]
                            .presentation_attempt_id
                            .cmp(&pair[1].presentation_attempt_id),
                    )
                    .is_ge()
            })
            || self
                .recovery_adapter_manifest_id
                .as_deref()
                .is_some_and(|value| {
                    value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
                })
            || self
                .recall_cue_adapter_manifest_id
                .as_deref()
                .is_some_and(|value| {
                    value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
                })
        {
            return Err(RuntimeSnapshotError::Invalid);
        }
        self.spool_limits()
            .map_err(|_| RuntimeSnapshotError::Invalid)?;
        self.data_dir()?;
        Ok(())
    }

    pub fn spool_limits(&self) -> Result<SpoolLimits, crate::spool::SpoolError> {
        SpoolLimits {
            high_watermark_bytes: self.main_high_watermark_bytes,
            low_watermark_bytes: self.main_low_watermark_bytes,
            max_main_files: self.max_main_files,
            emergency_slots: self.emergency_slots,
        }
        .validate()
    }

    pub fn load(path: &Path) -> Result<Self, RuntimeSnapshotError> {
        let metadata = fs::symlink_metadata(path).map_err(map_io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(RuntimeSnapshotError::InvalidType);
        }
        if metadata.uid() != current_uid()? || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(RuntimeSnapshotError::InvalidPermissions);
        }
        let bytes = fs::read(path).map_err(map_io)?;
        let snapshot = decode_snapshot(&bytes)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn publish(&self, path: &Path) -> Result<(), RuntimeSnapshotError> {
        self.validate()?;
        let parent = path.parent().ok_or(RuntimeSnapshotError::Invalid)?;
        ensure_private_directory(parent)?;
        if let Ok(metadata) = fs::symlink_metadata(path)
            && (metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != current_uid()?)
        {
            return Err(RuntimeSnapshotError::InvalidType);
        }
        let bytes = encode_snapshot(self)?;
        let staging = create_staging(parent, &bytes)?;
        let result = (|| {
            fs::rename(&staging, path).map_err(map_io)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(map_io)?;
            File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(map_io)
        })();
        if result.is_err() {
            let _ = fs::remove_file(staging);
        }
        result
    }
}

fn is_normal_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
                    | std::path::Component::Normal(_)
            )
        })
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RuntimeSnapshotError {
    #[error("runtime snapshot is invalid")]
    Invalid,
    #[error("runtime snapshot path has an invalid type")]
    InvalidType,
    #[error("runtime snapshot permissions are invalid")]
    InvalidPermissions,
    #[error("runtime snapshot operation failed")]
    Io,
}

fn ensure_private_directory(path: &Path) -> Result<(), RuntimeSnapshotError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != current_uid()?
                || metadata.permissions().mode() & 0o777 != 0o700
            {
                return Err(RuntimeSnapshotError::InvalidPermissions);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700).create(path).map_err(map_io)?;
        }
        Err(error) => return Err(map_io(error)),
    }
    Ok(())
}

fn create_staging(parent: &Path, bytes: &[u8]) -> Result<PathBuf, RuntimeSnapshotError> {
    for attempt in 0..32_u32 {
        let path = parent.join(format!(
            ".runtime-snapshot-{}-{attempt}.tmp",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(bytes).map_err(map_io)?;
                file.sync_all().map_err(map_io)?;
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(map_io(error)),
        }
    }
    Err(RuntimeSnapshotError::Io)
}

fn encode_snapshot(value: &RuntimeSnapshot) -> Result<Vec<u8>, RuntimeSnapshotError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&value.snapshot_version.to_be_bytes());
    bytes.extend_from_slice(&value.generation.to_be_bytes());
    for path in [&value.device_key_dir, &value.cas_dir, &value.spool_dir] {
        let path = path.to_str().ok_or(RuntimeSnapshotError::Invalid)?;
        let length = u16::try_from(path.len()).map_err(|_| RuntimeSnapshotError::Invalid)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(path.as_bytes());
    }
    bytes.extend_from_slice(&value.main_high_watermark_bytes.to_be_bytes());
    bytes.extend_from_slice(&value.main_low_watermark_bytes.to_be_bytes());
    bytes.extend_from_slice(&value.max_main_files.to_be_bytes());
    bytes.extend_from_slice(&value.emergency_slots.to_be_bytes());
    bytes.extend_from_slice(&value.effective_config_hash);
    bytes.push(match value.recovery_gate {
        RecoveryGateMode::Disabled => 0,
        RecoveryGateMode::BestEffort => 1,
        RecoveryGateMode::Active => 2,
    });
    match &value.recovery_adapter_manifest_id {
        None => bytes.extend_from_slice(&0_u16.to_be_bytes()),
        Some(value) => {
            let length = u16::try_from(value.len()).map_err(|_| RuntimeSnapshotError::Invalid)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
    }
    bytes.extend_from_slice(&value.recovery_classifier_revision.to_be_bytes());
    let socket = value
        .recovery_socket_path
        .to_str()
        .ok_or(RuntimeSnapshotError::Invalid)?;
    let length = u16::try_from(socket.len()).map_err(|_| RuntimeSnapshotError::Invalid)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(socket.as_bytes());
    bytes.extend_from_slice(&value.recovery_preflight_timeout_ms.to_be_bytes());
    bytes.extend_from_slice(&value.recovery_max_bundle_bytes.to_be_bytes());
    bytes.extend_from_slice(&value.recovery_max_untracked_file_bytes.to_be_bytes());
    bytes.extend_from_slice(&value.recovery_max_untracked_total_bytes.to_be_bytes());
    bytes.push(match value.recall_cue_gate {
        RecallCueGateMode::Disabled => 0,
        RecallCueGateMode::Active => 1,
    });
    match &value.recall_cue_adapter_manifest_id {
        None => bytes.extend_from_slice(&0_u16.to_be_bytes()),
        Some(value) => {
            let length = u16::try_from(value.len()).map_err(|_| RuntimeSnapshotError::Invalid)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
    }
    bytes.extend_from_slice(
        &u16::try_from(value.recall_cues.len())
            .map_err(|_| RuntimeSnapshotError::Invalid)?
            .to_be_bytes(),
    );
    for cue in &value.recall_cues {
        let encoded = serde_json::to_vec(cue).map_err(|_| RuntimeSnapshotError::Invalid)?;
        bytes.extend_from_slice(
            &u32::try_from(encoded.len())
                .map_err(|_| RuntimeSnapshotError::Invalid)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&encoded);
    }
    Ok(bytes)
}

fn decode_snapshot(bytes: &[u8]) -> Result<RuntimeSnapshot, RuntimeSnapshotError> {
    if bytes.get(..8) != Some(SNAPSHOT_MAGIC) {
        return Err(RuntimeSnapshotError::Invalid);
    }
    let mut cursor = SnapshotCursor {
        remaining: &bytes[8..],
    };
    let snapshot_version = cursor.u16()?;
    let generation = cursor.u64()?;
    let device_key_dir = cursor.path()?;
    let cas_dir = cursor.path()?;
    let spool_dir = cursor.path()?;
    let main_high_watermark_bytes = cursor.u64()?;
    let main_low_watermark_bytes = cursor.u64()?;
    let max_main_files = cursor.u32()?;
    let emergency_slots = cursor.u16()?;
    let mut effective_config_hash = [0_u8; 32];
    effective_config_hash.copy_from_slice(cursor.take(32)?);
    let recovery_gate = match cursor.take(1)?[0] {
        0 => RecoveryGateMode::Disabled,
        1 => RecoveryGateMode::BestEffort,
        2 => RecoveryGateMode::Active,
        _ => return Err(RuntimeSnapshotError::Invalid),
    };
    let manifest_length = usize::from(cursor.u16()?);
    let recovery_adapter_manifest_id = if manifest_length == 0 {
        None
    } else {
        Some(
            std::str::from_utf8(cursor.take(manifest_length)?)
                .map_err(|_| RuntimeSnapshotError::Invalid)?
                .to_owned(),
        )
    };
    let recovery_classifier_revision = cursor.u32()?;
    let recovery_socket_path = cursor.path()?;
    let recovery_preflight_timeout_ms = cursor.u32()?;
    let recovery_max_bundle_bytes = cursor.u64()?;
    let recovery_max_untracked_file_bytes = cursor.u64()?;
    let recovery_max_untracked_total_bytes = cursor.u64()?;
    let recall_cue_gate = match cursor.take(1)?[0] {
        0 => RecallCueGateMode::Disabled,
        1 => RecallCueGateMode::Active,
        _ => return Err(RuntimeSnapshotError::Invalid),
    };
    let cue_manifest_length = usize::from(cursor.u16()?);
    let recall_cue_adapter_manifest_id = if cue_manifest_length == 0 {
        None
    } else {
        Some(
            std::str::from_utf8(cursor.take(cue_manifest_length)?)
                .map_err(|_| RuntimeSnapshotError::Invalid)?
                .to_owned(),
        )
    };
    let cue_count = usize::from(cursor.u16()?);
    if cue_count > 32 {
        return Err(RuntimeSnapshotError::Invalid);
    }
    let mut recall_cues = Vec::with_capacity(cue_count);
    for _ in 0..cue_count {
        let length = usize::try_from(cursor.u32()?).map_err(|_| RuntimeSnapshotError::Invalid)?;
        let cue = serde_json::from_slice(cursor.take(length)?)
            .map_err(|_| RuntimeSnapshotError::Invalid)?;
        recall_cues.push(cue);
    }
    if !cursor.remaining.is_empty() {
        return Err(RuntimeSnapshotError::Invalid);
    }
    Ok(RuntimeSnapshot {
        snapshot_version,
        generation,
        device_key_dir,
        cas_dir,
        spool_dir,
        main_high_watermark_bytes,
        main_low_watermark_bytes,
        max_main_files,
        emergency_slots,
        effective_config_hash,
        recovery_gate,
        recovery_adapter_manifest_id,
        recovery_classifier_revision,
        recovery_socket_path,
        recovery_preflight_timeout_ms,
        recovery_max_bundle_bytes,
        recovery_max_untracked_file_bytes,
        recovery_max_untracked_total_bytes,
        recall_cue_gate,
        recall_cue_adapter_manifest_id,
        recall_cues,
    })
}

struct SnapshotCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> SnapshotCursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], RuntimeSnapshotError> {
        if self.remaining.len() < length {
            return Err(RuntimeSnapshotError::Invalid);
        }
        let (value, rest) = self.remaining.split_at(length);
        self.remaining = rest;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, RuntimeSnapshotError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| RuntimeSnapshotError::Invalid)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, RuntimeSnapshotError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| RuntimeSnapshotError::Invalid)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, RuntimeSnapshotError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| RuntimeSnapshotError::Invalid)?,
        ))
    }

    fn path(&mut self) -> Result<PathBuf, RuntimeSnapshotError> {
        let length = self.u16()? as usize;
        let value =
            std::str::from_utf8(self.take(length)?).map_err(|_| RuntimeSnapshotError::Invalid)?;
        Ok(PathBuf::from(value))
    }
}

fn current_uid() -> Result<u32, RuntimeSnapshotError> {
    fs::metadata("/proc/self")
        .map(|value| value.uid())
        .map_err(map_io)
}

fn map_io(_: io::Error) -> RuntimeSnapshotError {
    RuntimeSnapshotError::Io
}

#[cfg(test)]
mod tests {
    use evertrace_domain::{
        ids::{ExecutionLaneId, PresentationAttemptId},
        recall::RecallCueSnapshot,
    };

    use super::*;

    fn active_snapshot() -> RuntimeSnapshot {
        RuntimeSnapshot::for_data_dir(
            Path::new("/tmp/evertrace-runtime-snapshot-test"),
            7,
            SpoolLimits {
                high_watermark_bytes: 1024,
                low_watermark_bytes: 512,
                max_main_files: 4,
                emergency_slots: 2,
            },
            RecoverySnapshotSettings {
                gate: RecoveryGateMode::Disabled,
                preflight_timeout_ms: 100,
                effective_config_hash: [7; 32],
                adapter_manifest_id: None,
                classifier_revision: 1,
                max_bundle_bytes: 4096,
                max_untracked_file_bytes: 1024,
                max_untracked_total_bytes: 2048,
                recall_cue_gate: RecallCueGateMode::Active,
                recall_cue_adapter_manifest_id: Some("adapter:s22".into()),
            },
        )
        .unwrap()
    }

    fn cue(session_id: &str) -> RecallCueSnapshot {
        RecallCueSnapshot {
            session_id: session_id.into(),
            execution_lane_id: ExecutionLaneId::new_v7(),
            host_lane_key: format!("lane:{session_id}"),
            adapter_manifest_id: "adapter:s22".into(),
            runtime_generation: 7,
            recall_need_hash: [8; 32],
            presentation_attempt_id: PresentationAttemptId::new_v7(),
            expires_at_us: i64::MAX,
            checksum: [0; 32],
        }
        .seal()
        .unwrap()
    }

    #[test]
    fn recall_cues_round_trip_and_enforce_order_uniqueness_and_limit() {
        let mut snapshot = active_snapshot();
        snapshot.recall_cues = vec![cue("a"), cue("b")];
        snapshot.validate().unwrap();
        let encoded = encode_snapshot(&snapshot).unwrap();
        assert_eq!(decode_snapshot(&encoded).unwrap(), snapshot);

        snapshot.recall_cues.swap(0, 1);
        assert_eq!(snapshot.validate(), Err(RuntimeSnapshotError::Invalid));
        snapshot.recall_cues = (0..33).map(|index| cue(&format!("s{index:02}"))).collect();
        assert_eq!(snapshot.validate(), Err(RuntimeSnapshotError::Invalid));
    }
}
