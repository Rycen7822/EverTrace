use std::{
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use thiserror::Error;

const KEY_MAGIC: &[u8; 8] = b"ETKEYV1\0";
const KEY_LENGTH: usize = 32;
const KEY_FILE_LENGTH: usize = KEY_MAGIC.len() + 8 + KEY_LENGTH;
const ACTIVE_KEY_FILE: &str = "active.key";
const CREATE_ATTEMPTS: u8 = 16;

#[derive(Clone, Eq, PartialEq)]
pub struct DeviceKey {
    generation: u64,
    bytes: [u8; KEY_LENGTH],
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceKey")
            .field("generation", &self.generation)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl DeviceKey {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) const fn bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceKeyStore {
    directory: PathBuf,
}

impl DeviceKeyStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn load_or_create(&self) -> Result<DeviceKey, DeviceKeyError> {
        self.ensure_directory()?;
        let directory = self.lock_directory()?;
        match self.load_unlocked() {
            Ok(key) => Ok(key),
            Err(DeviceKeyError::Missing) => {
                let mut bytes = [0_u8; KEY_LENGTH];
                secure_random(&mut bytes)?;
                let key = DeviceKey {
                    generation: 1,
                    bytes,
                };
                self.publish(&key, false)?;
                directory.sync_all().map_err(map_io)?;
                self.load_unlocked()
            }
            Err(error) => Err(error),
        }
    }

    pub fn load(&self) -> Result<DeviceKey, DeviceKeyError> {
        self.validate_directory()?;
        let _directory = self.lock_directory()?;
        self.load_unlocked()
    }

    pub fn rotate(&self) -> Result<DeviceKey, DeviceKeyError> {
        self.validate_directory()?;
        let directory = self.lock_directory()?;
        let current = self.load_unlocked()?;
        let generation = current
            .generation
            .checked_add(1)
            .ok_or(DeviceKeyError::GenerationOverflow)?;
        let mut bytes = [0_u8; KEY_LENGTH];
        secure_random(&mut bytes)?;
        let key = DeviceKey { generation, bytes };
        self.publish(&key, true)?;
        directory.sync_all().map_err(map_io)?;
        self.load_unlocked()
    }

    pub fn active_path(&self) -> PathBuf {
        self.directory.join(ACTIVE_KEY_FILE)
    }

    pub fn ordinary_backup_includes(&self, path: &Path) -> bool {
        !path.starts_with(&self.directory)
    }

    fn ensure_directory(&self) -> Result<(), DeviceKeyError> {
        match fs::symlink_metadata(&self.directory) {
            Ok(_) => self.validate_directory(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&self.directory) {
                    Ok(()) => self.validate_directory(),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        self.validate_directory()
                    }
                    Err(error) => Err(map_io(error)),
                }
            }
            Err(error) => Err(map_io(error)),
        }
    }

    fn validate_directory(&self) -> Result<(), DeviceKeyError> {
        let metadata = fs::symlink_metadata(&self.directory).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                DeviceKeyError::Missing
            } else {
                map_io(error)
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(DeviceKeyError::InvalidType);
        }
        if metadata.uid() != current_uid()? {
            return Err(DeviceKeyError::WrongOwner);
        }
        if metadata.mode() & 0o7777 != 0o700 {
            return Err(DeviceKeyError::WrongPermissions);
        }
        Ok(())
    }

    fn lock_directory(&self) -> Result<File, DeviceKeyError> {
        let directory = File::open(&self.directory).map_err(map_io)?;
        FileExt::lock_exclusive(&directory).map_err(map_io)?;
        Ok(directory)
    }

    fn load_unlocked(&self) -> Result<DeviceKey, DeviceKeyError> {
        let path = self.active_path();
        let before = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                DeviceKeyError::Missing
            } else {
                map_io(error)
            }
        })?;
        if before.file_type().is_symlink() || !before.is_file() {
            return Err(DeviceKeyError::InvalidType);
        }
        if before.uid() != current_uid()? {
            return Err(DeviceKeyError::WrongOwner);
        }
        if before.mode() & 0o7777 != 0o600 {
            return Err(DeviceKeyError::WrongPermissions);
        }
        let mut file = File::open(&path).map_err(map_io)?;
        let opened = file.metadata().map_err(map_io)?;
        if before.dev() != opened.dev() || before.ino() != opened.ino() || !opened.is_file() {
            return Err(DeviceKeyError::IdentityChanged);
        }
        let mut encoded = [0_u8; KEY_FILE_LENGTH];
        file.read_exact(&mut encoded)
            .map_err(|_| DeviceKeyError::Corrupt)?;
        let mut extra = [0_u8; 1];
        if file.read(&mut extra).map_err(map_io)? != 0 || &encoded[..KEY_MAGIC.len()] != KEY_MAGIC {
            return Err(DeviceKeyError::Corrupt);
        }
        let generation = u64::from_be_bytes(
            encoded[KEY_MAGIC.len()..KEY_MAGIC.len() + 8]
                .try_into()
                .map_err(|_| DeviceKeyError::Corrupt)?,
        );
        if generation == 0 {
            return Err(DeviceKeyError::Corrupt);
        }
        let mut bytes = [0_u8; KEY_LENGTH];
        bytes.copy_from_slice(&encoded[KEY_MAGIC.len() + 8..]);
        Ok(DeviceKey { generation, bytes })
    }

    fn publish(&self, key: &DeviceKey, replace: bool) -> Result<(), DeviceKeyError> {
        if !replace && fs::symlink_metadata(self.active_path()).is_ok() {
            return Err(DeviceKeyError::AlreadyExists);
        }
        let mut suffix = [0_u8; 8];
        for attempt in 0..CREATE_ATTEMPTS {
            secure_random(&mut suffix)?;
            let name = format!(".active.key.tmp-{}-{}", attempt, hex(&suffix));
            let staging = self.directory.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            let mut file = match options.open(&staging) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(map_io(error)),
            };
            let result = (|| {
                file.write_all(KEY_MAGIC).map_err(map_io)?;
                file.write_all(&key.generation.to_be_bytes())
                    .map_err(map_io)?;
                file.write_all(&key.bytes).map_err(map_io)?;
                file.sync_all().map_err(map_io)?;
                drop(file);
                if !replace && fs::symlink_metadata(self.active_path()).is_ok() {
                    return Err(DeviceKeyError::AlreadyExists);
                }
                fs::rename(&staging, self.active_path()).map_err(map_io)?;
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::remove_file(&staging);
            }
            return result;
        }
        Err(DeviceKeyError::CreateCollision)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DeviceKeyError {
    #[error("device key is missing")]
    Missing,
    #[error("device key path has an invalid type")]
    InvalidType,
    #[error("device key path has the wrong owner")]
    WrongOwner,
    #[error("device key path has unsafe permissions")]
    WrongPermissions,
    #[error("device key identity changed during access")]
    IdentityChanged,
    #[error("device key is corrupt")]
    Corrupt,
    #[error("device key generation overflowed")]
    GenerationOverflow,
    #[error("device key already exists")]
    AlreadyExists,
    #[error("device key staging names were exhausted")]
    CreateCollision,
    #[error("device key operation failed")]
    Io,
    #[error("secure operating-system randomness is unavailable")]
    RandomUnavailable,
}

fn current_uid() -> Result<u32, DeviceKeyError> {
    let metadata = fs::metadata("/proc/self").map_err(map_io)?;
    Ok(metadata.uid())
}

fn secure_random(output: &mut [u8]) -> Result<(), DeviceKeyError> {
    let metadata =
        fs::symlink_metadata("/dev/urandom").map_err(|_| DeviceKeyError::RandomUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_char_device() {
        return Err(DeviceKeyError::RandomUnavailable);
    }
    let mut random = File::open("/dev/urandom").map_err(|_| DeviceKeyError::RandomUnavailable)?;
    random
        .read_exact(output)
        .map_err(|_| DeviceKeyError::RandomUnavailable)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[(byte >> 4) as usize]));
        output.push(char::from(DIGITS[(byte & 0x0f) as usize]));
    }
    output
}

fn map_io(_: io::Error) -> DeviceKeyError {
    DeviceKeyError::Io
}
