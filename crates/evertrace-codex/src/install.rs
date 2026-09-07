use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capability::HookDiagnostic;

const REGISTRY_VERSION: u16 = 1;
const REGISTRY_NAME: &str = "registry-v1.json";
const HOOKS_DIRECTORY: &str = "hooks";
const GENERATIONS_DIRECTORY: &str = "generations";
const PINS_DIRECTORY: &str = "pins";
const REGISTRY_LOCK_NAME: &str = "registry.lock";
const GENERATION_EXECUTABLE_NAME: &str = "evertrace-hook";
const GENERATION_RUNTIME_NAME: &str = "hook-runtime-v1.json";
const MAX_REGISTRY_BYTES: u64 = 1024 * 1024;
const MAX_PIN_BYTES: u64 = 64;
const MAX_HOOK_SNAPSHOT_FILES: usize = 4096;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenHookFile {
    pub directories: Vec<(PathBuf, u64, u64)>,
    pub source: PathBuf,
    pub relative_path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookBackupSnapshot {
    pub current_generation: Option<u64>,
    pub retained_generations: Vec<u64>,
    pub pin_count: u32,
    pub pinned_generation_count: u32,
    pub files: Vec<FrozenHookFile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookBackupSemantic {
    pub current_generation: Option<u64>,
    pub retained_generations: Vec<u64>,
    pub pin_count: u32,
    pub pinned_generation_count: u32,
}

#[derive(Clone, Debug)]
pub struct StableLauncher {
    root: PathBuf,
}

impl StableLauncher {
    pub fn open(data_root: impl Into<PathBuf>) -> Result<Self, InstallError> {
        let root = data_root.into();
        ensure_private_directory(&root)?;
        ensure_private_directory(&root.join(HOOKS_DIRECTORY))?;
        ensure_private_directory(&root.join(HOOKS_DIRECTORY).join(PINS_DIRECTORY))?;
        ensure_private_directory(&root.join(HOOKS_DIRECTORY).join(GENERATIONS_DIRECTORY))?;
        let lock_path = root.join(HOOKS_DIRECTORY).join(REGISTRY_LOCK_NAME);
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
        validate_generation(&self.root, &generation)?;
        self.with_lock(|| {
            let registry_path = self.registry_path();
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
            validate_registry(&self.root, &registry)?;
            atomic_json(&self.registry_path(), &registry, 0o600)
        })
    }

    pub fn resolve_for_session(&self, session_id: &str) -> Result<HookGeneration, InstallError> {
        validate_session_id(session_id)?;
        self.with_lock(|| {
            let registry = self.read_registry()?;
            let pin_path = self
                .root
                .join(HOOKS_DIRECTORY)
                .join(PINS_DIRECTORY)
                .join(format!("{session_id}.pin"));
            let generation = match fs::symlink_metadata(&pin_path) {
                Ok(_) => std::str::from_utf8(&read_private_file_bounded(
                    &pin_path,
                    0o600,
                    MAX_PIN_BYTES,
                )?)
                .map_err(|_| InstallError::InvalidRegistry)?
                .parse::<u64>()
                .map_err(|_| InstallError::InvalidRegistry)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let selected = registry
                        .generations
                        .iter()
                        .find(|item| {
                            item.generation == registry.current_generation && item.compatible
                        })
                        .ok_or(InstallError::GenerationUnavailable)?;
                    validate_generation(&self.root, selected)?;
                    atomic_write(
                        &pin_path,
                        registry.current_generation.to_string().as_bytes(),
                        0o600,
                    )?;
                    registry.current_generation
                }
                Err(error) => return Err(map_io(error)),
            };
            let selected = registry
                .generations
                .into_iter()
                .find(|item| item.generation == generation && item.compatible)
                .ok_or(InstallError::GenerationUnavailable)?;
            validate_generation(&self.root, &selected)?;
            Ok(selected)
        })
    }

    pub fn retained_generations(&self) -> Result<Vec<u64>, InstallError> {
        self.with_lock(|| {
            let registry = self.read_registry()?;
            let pins = read_pins(&self.root.join(HOOKS_DIRECTORY).join(PINS_DIRECTORY), true)?;
            let retained = retained_generations(&registry, &pins)?;
            for generation in &retained {
                let value = registry
                    .generations
                    .iter()
                    .find(|item| item.generation == *generation)
                    .ok_or(InstallError::GenerationUnavailable)?;
                validate_generation(&self.root, value)?;
            }
            Ok(retained)
        })
    }

    pub fn freeze_backup_snapshot(data_root: &Path) -> Result<HookBackupSnapshot, InstallError> {
        validate_private_directory(data_root)?;
        let launcher_path = data_root.join("hook-v1");
        let hooks_path = data_root.join(HOOKS_DIRECTORY);
        match (
            fs::symlink_metadata(&launcher_path),
            fs::symlink_metadata(&hooks_path),
        ) {
            (Err(launcher), Err(hooks))
                if launcher.kind() == io::ErrorKind::NotFound
                    && hooks.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(HookBackupSnapshot {
                    current_generation: None,
                    retained_generations: Vec::new(),
                    pin_count: 0,
                    pinned_generation_count: 0,
                    files: Vec::new(),
                });
            }
            (Ok(_), Ok(_)) => {}
            _ => return Err(InstallError::InvalidRegistry),
        }
        validate_private_directory(&hooks_path)?;
        validate_private_file(&launcher_path, 0o700)?;
        let lock_path = hooks_path.join(REGISTRY_LOCK_NAME);
        let lock_before = private_file_identity(&lock_path, 0o600)?;
        let lock = File::open(&lock_path).map_err(map_io)?;
        if hook_file_identity(&lock.metadata().map_err(map_io)?) != lock_before {
            return Err(InstallError::InvalidRegistry);
        }
        fs2::FileExt::try_lock_shared(&lock).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                InstallError::LockBusy
            } else {
                map_io(error)
            }
        })?;
        let hooks_before = private_directory_identity(&hooks_path)?;
        let pins_path = hooks_path.join(PINS_DIRECTORY);
        let pins_before = private_directory_identity(&pins_path)?;

        let launcher = Self {
            root: data_root.to_owned(),
        };
        let registry = launcher.read_registry()?;
        let pins = read_pins(&pins_path, true)?;
        let retained = retained_generations(&registry, &pins)?;
        let pinned_generation_count = unique_pin_generation_count(&pins)?;
        let mut files = vec![
            freeze_file(&launcher_path, Path::new("hook-v1"), 0o700)?,
            freeze_file(
                &launcher.registry_path(),
                &PathBuf::from(HOOKS_DIRECTORY).join(REGISTRY_NAME),
                0o600,
            )?,
        ];
        for pin in &pins {
            files.push(freeze_file(
                &pin.path,
                &PathBuf::from(HOOKS_DIRECTORY)
                    .join(PINS_DIRECTORY)
                    .join(format!("{}.pin", pin.session_id)),
                0o600,
            )?);
        }
        for generation in &retained {
            let value = registry
                .generations
                .iter()
                .find(|value| value.generation == *generation && value.compatible)
                .ok_or(InstallError::GenerationUnavailable)?;
            validate_generation(data_root, value)?;
            files.push(freeze_file(
                &value.executable,
                &generation_relative(*generation, GENERATION_EXECUTABLE_NAME),
                0o700,
            )?);
            files.push(freeze_file(
                &value.runtime_snapshot,
                &generation_relative(*generation, GENERATION_RUNTIME_NAME),
                0o600,
            )?);
        }
        files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        if files.len() > MAX_HOOK_SNAPSHOT_FILES
            || files
                .windows(2)
                .any(|pair| pair[0].relative_path == pair[1].relative_path)
        {
            return Err(InstallError::ResourceExhausted);
        }
        for file in &files {
            revalidate_frozen_file(file)?;
        }
        if private_file_identity(&lock_path, 0o600)? != lock_before {
            return Err(InstallError::InvalidRegistry);
        }
        if private_directory_identity(&hooks_path)? != hooks_before
            || private_directory_identity(&pins_path)? != pins_before
        {
            return Err(InstallError::InvalidRegistry);
        }
        Ok(HookBackupSnapshot {
            current_generation: Some(registry.current_generation),
            retained_generations: retained,
            pin_count: u32::try_from(pins.len()).map_err(|_| InstallError::ResourceExhausted)?,
            pinned_generation_count,
            files,
        })
    }

    pub fn verify_backup_snapshot(backup_root: &Path) -> Result<HookBackupSemantic, InstallError> {
        validate_private_directory(backup_root)?;
        let launcher_path = backup_root.join("hook-v1");
        let hooks_path = backup_root.join(HOOKS_DIRECTORY);
        match (
            fs::symlink_metadata(&launcher_path),
            fs::symlink_metadata(&hooks_path),
        ) {
            (Err(launcher), Err(hooks))
                if launcher.kind() == io::ErrorKind::NotFound
                    && hooks.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(HookBackupSemantic {
                    current_generation: None,
                    retained_generations: Vec::new(),
                    pin_count: 0,
                    pinned_generation_count: 0,
                });
            }
            (Ok(_), Ok(_)) => {}
            _ => return Err(InstallError::InvalidRegistry),
        }
        validate_private_directory(&hooks_path)?;
        validate_private_file(&launcher_path, 0o600)?;
        let registry_path = hooks_path.join(REGISTRY_NAME);
        let registry: GenerationRegistry = serde_json::from_slice(&read_private_file_bounded(
            &registry_path,
            0o600,
            MAX_REGISTRY_BYTES,
        )?)
        .map_err(|_| InstallError::InvalidRegistry)?;
        validate_registry_shape(&registry)?;
        validate_registry_layout(&registry)?;
        let pins = read_pins(&hooks_path.join(PINS_DIRECTORY), false)?;
        let retained = retained_generations(&registry, &pins)?;
        for generation in &retained {
            validate_private_file(
                &backup_root.join(generation_relative(*generation, GENERATION_EXECUTABLE_NAME)),
                0o600,
            )?;
            validate_private_file(
                &backup_root.join(generation_relative(*generation, GENERATION_RUNTIME_NAME)),
                0o600,
            )?;
        }
        Ok(HookBackupSemantic {
            current_generation: Some(registry.current_generation),
            retained_generations: retained,
            pin_count: u32::try_from(pins.len()).map_err(|_| InstallError::ResourceExhausted)?,
            pinned_generation_count: unique_pin_generation_count(&pins)?,
        })
    }

    fn read_registry(&self) -> Result<GenerationRegistry, InstallError> {
        let path = self.registry_path();
        let registry = serde_json::from_slice(&read_private_file_bounded(
            &path,
            0o600,
            MAX_REGISTRY_BYTES,
        )?)
        .map_err(|_| InstallError::InvalidRegistry)?;
        validate_registry(&self.root, &registry)?;
        Ok(registry)
    }

    fn registry_path(&self) -> PathBuf {
        self.root.join(HOOKS_DIRECTORY).join(REGISTRY_NAME)
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, InstallError>,
    ) -> Result<T, InstallError> {
        let lock =
            File::open(self.root.join(HOOKS_DIRECTORY).join(REGISTRY_LOCK_NAME)).map_err(map_io)?;
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
    #[error("hook generation registry is busy")]
    LockBusy,
    #[error("hook generation snapshot exceeded its resource boundary")]
    ResourceExhausted,
    #[error("hook installation operation failed")]
    Io,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PinRecord {
    session_id: String,
    generation: u64,
    path: PathBuf,
}

fn validate_generation(data_root: &Path, value: &HookGeneration) -> Result<(), InstallError> {
    validate_generation_shape(value)?;
    if generation_data_root(value)? != data_root
        || value.executable
            != data_root.join(generation_relative(
                value.generation,
                GENERATION_EXECUTABLE_NAME,
            ))
        || value.runtime_snapshot
            != data_root.join(generation_relative(
                value.generation,
                GENERATION_RUNTIME_NAME,
            ))
    {
        return Err(InstallError::InvalidRegistry);
    }
    for path in [
        data_root.join(HOOKS_DIRECTORY),
        data_root.join(HOOKS_DIRECTORY).join(GENERATIONS_DIRECTORY),
        value
            .executable
            .parent()
            .ok_or(InstallError::InvalidRegistry)?
            .to_owned(),
    ] {
        validate_private_directory(&path)?;
    }
    validate_private_file(&value.executable, 0o700)?;
    validate_private_file(&value.runtime_snapshot, 0o600)?;
    Ok(())
}

fn validate_generation_shape(value: &HookGeneration) -> Result<(), InstallError> {
    if value.generation == 0
        || value.protocol_version == 0
        || !value.executable.is_absolute()
        || !value.runtime_snapshot.is_absolute()
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

fn validate_registry(data_root: &Path, value: &GenerationRegistry) -> Result<(), InstallError> {
    validate_registry_shape(value)?;
    validate_registry_layout(value)?;
    if value
        .generations
        .iter()
        .any(|item| generation_data_root(item) != Ok(data_root))
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

fn validate_registry_shape(value: &GenerationRegistry) -> Result<(), InstallError> {
    if value.registry_version != REGISTRY_VERSION
        || value.generations.is_empty()
        || value.generations.len() > MAX_HOOK_SNAPSHOT_FILES
        || value
            .generations
            .iter()
            .any(|item| validate_generation_shape(item).is_err())
        || value
            .generations
            .windows(2)
            .any(|pair| pair[0].generation >= pair[1].generation)
        || !value
            .generations
            .iter()
            .any(|item| item.generation == value.current_generation && item.compatible)
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

fn validate_registry_layout(value: &GenerationRegistry) -> Result<(), InstallError> {
    let mut roots = BTreeSet::new();
    for generation in &value.generations {
        roots.insert(generation_data_root(generation)?.to_owned());
    }
    if roots.len() != 1 {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

fn generation_data_root(value: &HookGeneration) -> Result<&Path, InstallError> {
    let directory = value
        .executable
        .parent()
        .ok_or(InstallError::InvalidRegistry)?;
    if value.executable.file_name().and_then(|name| name.to_str())
        != Some(GENERATION_EXECUTABLE_NAME)
        || directory.file_name().and_then(|name| name.to_str())
            != Some(value.generation.to_string().as_str())
        || directory
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some(GENERATIONS_DIRECTORY)
        || directory
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some(HOOKS_DIRECTORY)
        || value.runtime_snapshot != directory.join(GENERATION_RUNTIME_NAME)
    {
        return Err(InstallError::InvalidRegistry);
    }
    directory
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or(InstallError::InvalidRegistry)
}

fn generation_relative(generation: u64, file: &str) -> PathBuf {
    PathBuf::from(HOOKS_DIRECTORY)
        .join(GENERATIONS_DIRECTORY)
        .join(generation.to_string())
        .join(file)
}

fn retained_generations(
    registry: &GenerationRegistry,
    pins: &[PinRecord],
) -> Result<Vec<u64>, InstallError> {
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
    retained.extend(pins.iter().map(|pin| pin.generation));
    if retained.iter().any(|generation| {
        !registry
            .generations
            .iter()
            .any(|item| item.generation == *generation && item.compatible)
    }) {
        return Err(InstallError::GenerationUnavailable);
    }
    Ok(retained.into_iter().collect())
}

fn unique_pin_generation_count(pins: &[PinRecord]) -> Result<u32, InstallError> {
    u32::try_from(
        pins.iter()
            .map(|pin| pin.generation)
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .map_err(|_| InstallError::ResourceExhausted)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HookFileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn read_pins(path: &Path, required: bool) -> Result<Vec<PinRecord>, InstallError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path)?,
        Err(error) if !required && error.kind() == io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(map_io(error)),
    }
    let mut pins = BTreeMap::new();
    for entry in fs::read_dir(path).map_err(map_io)? {
        if pins.len() == MAX_HOOK_SNAPSHOT_FILES {
            return Err(InstallError::ResourceExhausted);
        }
        let entry = entry.map_err(map_io)?;
        let file_name = entry
            .file_name()
            .into_string()
            .map_err(|_| InstallError::InvalidRegistry)?;
        let session_id = file_name
            .strip_suffix(".pin")
            .ok_or(InstallError::InvalidRegistry)?;
        validate_session_id(session_id)?;
        let path = entry.path();
        let value = read_private_file_bounded(&path, 0o600, MAX_PIN_BYTES)?;
        let generation = std::str::from_utf8(&value)
            .map_err(|_| InstallError::InvalidRegistry)?
            .parse::<u64>()
            .map_err(|_| InstallError::InvalidRegistry)?;
        if generation == 0
            || pins
                .insert(
                    session_id.to_owned(),
                    PinRecord {
                        session_id: session_id.to_owned(),
                        generation,
                        path,
                    },
                )
                .is_some()
        {
            return Err(InstallError::InvalidRegistry);
        }
    }
    Ok(pins.into_values().collect())
}

fn freeze_file(
    source: &Path,
    relative_path: &Path,
    mode: u32,
) -> Result<FrozenHookFile, InstallError> {
    let mut directory = source;
    let mut directories = Vec::new();
    for _ in relative_path.components() {
        directory = directory.parent().ok_or(InstallError::InvalidRegistry)?;
        let identity = private_directory_identity(directory)?;
        directories.push((directory.to_owned(), identity.device, identity.inode));
    }
    let identity = private_file_identity(source, mode)?;
    Ok(FrozenHookFile {
        directories,
        source: source.to_owned(),
        relative_path: relative_path.to_owned(),
        device: identity.device,
        inode: identity.inode,
        length: identity.length,
        modified_seconds: identity.modified_seconds,
        modified_nanoseconds: identity.modified_nanoseconds,
        changed_seconds: identity.changed_seconds,
        changed_nanoseconds: identity.changed_nanoseconds,
    })
}

fn revalidate_frozen_file(file: &FrozenHookFile) -> Result<(), InstallError> {
    for (path, device, inode) in &file.directories {
        let identity = private_directory_identity(path)?;
        if identity.device != *device || identity.inode != *inode {
            return Err(InstallError::InvalidRegistry);
        }
    }
    let metadata = fs::symlink_metadata(&file.source).map_err(map_io)?;
    validate_private_file_metadata(&metadata, None)?;
    if hook_file_identity(&metadata)
        != (HookFileIdentity {
            device: file.device,
            inode: file.inode,
            length: file.length,
            modified_seconds: file.modified_seconds,
            modified_nanoseconds: file.modified_nanoseconds,
            changed_seconds: file.changed_seconds,
            changed_nanoseconds: file.changed_nanoseconds,
        })
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(())
}

fn read_private_file_bounded(
    path: &Path,
    mode: u32,
    max_bytes: u64,
) -> Result<Vec<u8>, InstallError> {
    let before = private_file_identity(path, mode)?;
    if before.length == 0 || before.length > max_bytes {
        return Err(InstallError::ResourceExhausted);
    }
    let file = File::open(path).map_err(map_io)?;
    if hook_file_identity(&file.metadata().map_err(map_io)?) != before {
        return Err(InstallError::InvalidRegistry);
    }
    let capacity = usize::try_from(before.length).map_err(|_| InstallError::ResourceExhausted)?;
    let limit = max_bytes
        .checked_add(1)
        .ok_or(InstallError::ResourceExhausted)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit).read_to_end(&mut bytes).map_err(map_io)?;
    if u64::try_from(bytes.len()).ok() != Some(before.length)
        || private_file_identity(path, mode)? != before
    {
        return Err(InstallError::InvalidRegistry);
    }
    Ok(bytes)
}

fn private_file_identity(path: &Path, mode: u32) -> Result<HookFileIdentity, InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    validate_private_file_metadata(&metadata, Some(mode))?;
    Ok(hook_file_identity(&metadata))
}

fn private_directory_identity(path: &Path) -> Result<HookFileIdentity, InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    validate_private_directory_metadata(&metadata)?;
    Ok(hook_file_identity(&metadata))
}

fn hook_file_identity(metadata: &fs::Metadata) -> HookFileIdentity {
    HookFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
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

fn validate_private_directory(path: &Path) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    validate_private_directory_metadata(&metadata)
}

fn validate_private_directory_metadata(metadata: &fs::Metadata) -> Result<(), InstallError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != current_uid()?
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(InstallError::InvalidPermissions);
    }
    Ok(())
}

fn validate_private_file(path: &Path, mode: u32) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    validate_private_file_metadata(&metadata, Some(mode))
}

fn validate_private_file_metadata(
    metadata: &fs::Metadata,
    mode: Option<u32>,
) -> Result<(), InstallError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InstallError::InvalidType);
    }
    if metadata.uid() != current_uid()?
        || mode.is_some_and(|mode| metadata.permissions().mode() & 0o777 != mode)
    {
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
