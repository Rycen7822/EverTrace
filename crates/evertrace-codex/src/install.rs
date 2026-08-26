use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capability::HookDiagnostic;

const REGISTRY_VERSION: u16 = 1;
const REGISTRY_NAME: &str = "generations.json";

pub const fn shadow_canary_diagnostic(durable_frame_observed: bool) -> Option<HookDiagnostic> {
    if durable_frame_observed {
        None
    } else {
        Some(HookDiagnostic::WiredUnobserved)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HookGeneration {
    pub generation: u64,
    pub protocol_version: u16,
    pub executable: PathBuf,
    pub runtime_snapshot: PathBuf,
    pub compatible: bool,
}

impl fmt::Debug for HookGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookGeneration")
            .field("generation", &self.generation)
            .field("protocol_version", &self.protocol_version)
            .field("compatible", &self.compatible)
            .field("paths_configured", &true)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationRegistry {
    registry_version: u16,
    current_generation: u64,
    generations: Vec<HookGeneration>,
}

#[derive(Clone, Debug)]
pub struct StableLauncher {
    root: PathBuf,
}

impl StableLauncher {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, InstallError> {
        let root = root.into();
        ensure_private_directory(&root)?;
        ensure_private_directory(&root.join("pins"))?;
        let lock_path = root.join("registry.lock");
        if !lock_path.exists() {
            let _ = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&lock_path);
        }
        validate_private_file(&lock_path, 0o600)?;
        Ok(Self { root })
    }

    pub fn launcher_path(&self) -> PathBuf {
        self.root.join("hook-v1")
    }

    pub fn install_launcher_binary(&self, source: &Path) -> Result<(), InstallError> {
        let metadata = fs::symlink_metadata(source).map_err(map_io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(InstallError::InvalidType);
        }
        let bytes = fs::read(source).map_err(map_io)?;
        atomic_write(&self.launcher_path(), &bytes, 0o700)
    }

    pub fn publish_generation(&self, generation: HookGeneration) -> Result<(), InstallError> {
        validate_generation(&generation)?;
        self.with_lock(|| {
            let registry_path = self.root.join(REGISTRY_NAME);
            let mut registry = match fs::symlink_metadata(&registry_path) {
                Ok(_) => self.read_registry()?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => GenerationRegistry {
                    registry_version: REGISTRY_VERSION,
                    current_generation: generation.generation,
                    generations: Vec::new(),
                },
                Err(error) => return Err(map_io(error)),
            };
            registry
                .generations
                .retain(|item| item.generation != generation.generation);
            registry.generations.push(generation.clone());
            registry.generations.sort_by_key(|item| item.generation);
            registry.current_generation = generation.generation;
            validate_registry(&registry)?;
            atomic_json(&self.root.join(REGISTRY_NAME), &registry, 0o600)
        })
    }

    pub fn resolve_for_session(&self, session_id: &str) -> Result<HookGeneration, InstallError> {
        validate_session_id(session_id)?;
        self.with_lock(|| {
            let registry = self.read_registry()?;
            let pin_path = self.root.join("pins").join(format!("{session_id}.pin"));
            let generation = match fs::read_to_string(&pin_path) {
                Ok(value) => value
                    .parse::<u64>()
                    .map_err(|_| InstallError::InvalidRegistry)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    atomic_write(
                        &pin_path,
                        registry.current_generation.to_string().as_bytes(),
                        0o600,
                    )?;
                    registry.current_generation
                }
                Err(error) => return Err(map_io(error)),
            };
            registry
                .generations
                .into_iter()
                .find(|item| item.generation == generation && item.compatible)
                .ok_or(InstallError::GenerationUnavailable)
        })
    }

    pub fn retained_generations(&self) -> Result<Vec<u64>, InstallError> {
        let registry = self.read_registry()?;
        let mut retained = BTreeSet::from([registry.current_generation]);
        if let Some(previous) = registry
            .generations
            .iter()
            .filter(|item| item.compatible && item.generation < registry.current_generation)
            .map(|item| item.generation)
            .max()
        {
            retained.insert(previous);
        }
        for entry in fs::read_dir(self.root.join("pins")).map_err(map_io)? {
            let value = fs::read_to_string(entry.map_err(map_io)?.path()).map_err(map_io)?;
            retained.insert(value.parse().map_err(|_| InstallError::InvalidRegistry)?);
        }
        Ok(retained.into_iter().collect())
    }

    fn read_registry(&self) -> Result<GenerationRegistry, InstallError> {
        let path = self.root.join(REGISTRY_NAME);
        validate_private_file(&path, 0o600)?;
        let registry = serde_json::from_slice(&fs::read(path).map_err(map_io)?)
            .map_err(|_| InstallError::InvalidRegistry)?;
        validate_registry(&registry)?;
        Ok(registry)
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, InstallError>,
    ) -> Result<T, InstallError> {
        let lock = File::open(self.root.join("registry.lock")).map_err(map_io)?;
        FileExt::lock_exclusive(&lock).map_err(map_io)?;
        operation()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InstallError {
    #[error("hook generation registry is invalid")]
    InvalidRegistry,
    #[error("hook generation is unavailable")]
    GenerationUnavailable,
    #[error("hook installation path has an invalid type")]
    InvalidType,
    #[error("hook installation permissions are invalid")]
    InvalidPermissions,
    #[error("hook installation operation failed")]
    Io,
}

fn validate_generation(value: &HookGeneration) -> Result<(), InstallError> {
    if value.generation == 0
        || value.protocol_version == 0
        || !value.executable.is_absolute()
        || !value.runtime_snapshot.is_absolute()
    {
        return Err(InstallError::InvalidRegistry);
    }
    validate_private_file(&value.executable, 0o700)?;
    validate_private_file(&value.runtime_snapshot, 0o600)?;
    Ok(())
}

fn validate_registry(value: &GenerationRegistry) -> Result<(), InstallError> {
    if value.registry_version != REGISTRY_VERSION
        || value.generations.is_empty()
        || value
            .generations
            .iter()
            .any(|item| validate_generation(item).is_err())
        || value
            .generations
            .iter()
            .map(|item| item.generation)
            .collect::<BTreeSet<_>>()
            .len()
            != value.generations.len()
        || !value
            .generations
            .iter()
            .any(|item| item.generation == value.current_generation && item.compatible)
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

fn validate_session_id(value: &str) -> Result<(), InstallError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != current_uid()?
                || metadata.permissions().mode() & 0o777 != 0o700
            {
                return Err(InstallError::InvalidPermissions);
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

fn validate_private_file(path: &Path, mode: u32) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InstallError::InvalidType);
    }
    if metadata.uid() != current_uid()? || metadata.permissions().mode() & 0o777 != mode {
        return Err(InstallError::InvalidPermissions);
    }
    Ok(())
}

fn atomic_json<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<(), InstallError> {
    let bytes = serde_json::to_vec(value).map_err(|_| InstallError::InvalidRegistry)?;
    atomic_write(path, &bytes, mode)
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), InstallError> {
    let parent = path.parent().ok_or(InstallError::InvalidRegistry)?;
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != current_uid()? =>
        {
            return Err(InstallError::InvalidType);
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(map_io(error)),
    }
    for attempt in 0..32_u32 {
        let staging = parent.join(format!(".install-{}-{attempt}.tmp", std::process::id()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&staging)
        {
            Ok(mut file) => {
                let result = (|| {
                    file.write_all(bytes).map_err(map_io)?;
                    file.sync_all().map_err(map_io)?;
                    fs::rename(&staging, path).map_err(map_io)?;
                    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(map_io)?;
                    File::open(parent)
                        .and_then(|dir| dir.sync_all())
                        .map_err(map_io)
                })();
                if result.is_err() {
                    let _ = fs::remove_file(staging);
                }
                return result;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(map_io(error)),
        }
    }
    Err(InstallError::Io)
}

fn current_uid() -> Result<u32, InstallError> {
    fs::metadata("/proc/self")
        .map(|value| value.uid())
        .map_err(map_io)
}

fn map_io(_: io::Error) -> InstallError {
    InstallError::Io
}
