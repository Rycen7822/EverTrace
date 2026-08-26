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

pub const RUNTIME_SNAPSHOT_VERSION: u16 = 1;
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
            .finish()
    }
}

impl RuntimeSnapshot {
    pub fn validate(&self) -> Result<(), RuntimeSnapshotError> {
        if self.snapshot_version != RUNTIME_SNAPSHOT_VERSION
            || self.generation == 0
            || [&self.device_key_dir, &self.cas_dir, &self.spool_dir]
                .iter()
                .any(|path| !path.is_absolute())
        {
            return Err(RuntimeSnapshotError::Invalid);
        }
        self.spool_limits()
            .map_err(|_| RuntimeSnapshotError::Invalid)?;
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
