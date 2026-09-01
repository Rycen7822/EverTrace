use std::{
    ffi::OsString,
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
};

use fs2::FileExt;
use rustix::fs::{AtFlags, Mode, OFlags, openat, statat, unlinkat};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::protect::ProtectedPayload;

const CAS_MAGIC: &[u8; 8] = b"ETCAS001";
const FORMAT_VERSION: u16 = 1;
const COMPRESSION_VERSION: u16 = 1;
const HEADER_LENGTH: usize = 64;
const CREATE_ATTEMPTS: u8 = 16;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CasDigest([u8; 32]);

impl CasDigest {
    pub fn for_protected_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn as_hex(self) -> String {
        hex(&self.0)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CasDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CasDigest")
            .field(&self.as_hex())
            .finish()
    }
}

impl fmt::Display for CasDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_hex())
    }
}

impl FromStr for CasDigest {
    type Err = CasError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CasError::InvalidDigest);
        }
        let mut digest = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            digest[index] = (hex_value(pair[0]).ok_or(CasError::InvalidDigest)? << 4)
                | hex_value(pair[1]).ok_or(CasError::InvalidDigest)?;
        }
        Ok(Self(digest))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CasStore {
    root: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CasDeleteOutcome {
    Deleted,
    Missing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceFence {
    data_dir: PathBuf,
    parent: PathBuf,
    path: PathBuf,
    parent_identity: (u64, u64),
    data_identity: (u64, u64),
    lock_identity: (u64, u64, i64, i64),
}

#[derive(Debug)]
pub struct MaintenanceGuard {
    exclusive: bool,
    lock_file: File,
    _parent_file: File,
    data_dir: File,
    cas_dir: File,
    blobs_dir: File,
}

impl MaintenanceFence {
    pub fn open(data_dir: &Path) -> Result<Self, CasError> {
        validate_directory(data_dir)?;
        let parent = data_dir.parent().ok_or(CasError::InvalidPath)?;
        validate_coordination_parent(parent)?;
        let mut name = OsString::from(data_dir.file_name().ok_or(CasError::InvalidPath)?);
        name.push(".maintenance.lock");
        let path = parent.join(name);
        let existed = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_lock_metadata(&metadata)?;
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(map_io(error)),
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(map_io)?;
        validate_lock_file(&path, &file)?;
        if !existed {
            file.sync_all().map_err(map_io)?;
            File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(map_io)?;
        }
        Ok(Self {
            data_dir: data_dir.to_owned(),
            parent: parent.to_owned(),
            path,
            parent_identity: directory_identity(parent)?,
            data_identity: directory_identity(data_dir)?,
            lock_identity: file_identity(&file)?,
        })
    }

    pub fn shared(&self) -> Result<MaintenanceGuard, CasError> {
        self.lock(false)
    }

    pub fn exclusive(&self) -> Result<MaintenanceGuard, CasError> {
        self.lock(true)
    }

    fn lock(&self, exclusive: bool) -> Result<MaintenanceGuard, CasError> {
        self.validate_coordination_identity()?;
        let parent_file = File::open(&self.parent).map_err(map_io)?;
        if directory_file_identity(&parent_file)? != self.parent_identity {
            return Err(CasError::IdentityChanged);
        }
        self.validate_coordination_identity()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .map_err(map_io)?;
        validate_lock_file(&self.path, &file)?;
        try_lock(&file, exclusive)?;
        validate_lock_file(&self.path, &file)?;
        if file_identity(&file)? != self.lock_identity {
            return Err(CasError::IdentityChanged);
        }
        self.validate_coordination_identity()?;
        let data_name = self.data_dir.file_name().ok_or(CasError::InvalidPath)?;
        let data_dir = open_directory_at(&parent_file, data_name)?;
        if directory_file_identity(&data_dir)? != self.data_identity {
            return Err(CasError::IdentityChanged);
        }
        let cas_dir = open_directory_at(&data_dir, "cas")?;
        let blobs_dir = open_directory_at(&cas_dir, "blobs")?;
        Ok(MaintenanceGuard {
            exclusive,
            lock_file: file,
            _parent_file: parent_file,
            data_dir,
            cas_dir,
            blobs_dir,
        })
    }

    pub fn lock_path(&self) -> &Path {
        &self.path
    }

    fn validate_coordination_identity(&self) -> Result<(), CasError> {
        validate_coordination_parent(&self.parent)?;
        validate_directory(&self.data_dir)?;
        if directory_identity(&self.parent)? != self.parent_identity
            || directory_identity(&self.data_dir)? != self.data_identity
        {
            return Err(CasError::IdentityChanged);
        }
        let lock = fs::symlink_metadata(&self.path).map_err(map_io)?;
        validate_lock_metadata(&lock)?;
        if metadata_identity(&lock) != self.lock_identity {
            return Err(CasError::IdentityChanged);
        }
        Ok(())
    }
}

impl Drop for MaintenanceGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.lock_file);
    }
}

impl CasStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, CasError> {
        let store = Self { root: root.into() };
        ensure_directory(&store.root)?;
        ensure_directory(&store.root.join("blobs"))?;
        Ok(store)
    }

    pub fn put(&self, payload: &ProtectedPayload) -> Result<CasDigest, CasError> {
        self.validate_root()?;
        let digest = CasDigest::for_protected_bytes(payload.protected_bytes());
        let path = self.blob_path(&digest);
        let parent = path.parent().ok_or(CasError::Io)?;
        ensure_directory(parent)?;
        let lock = File::open(parent).map_err(map_io)?;
        FileExt::lock_exclusive(&lock).map_err(map_io)?;
        if fs::symlink_metadata(&path).is_ok() {
            let existing = self.read(&digest)?;
            if existing == payload.protected_bytes() {
                return Ok(digest);
            }
            return Err(CasError::StoreCorrupt);
        }
        let compressed = zstd::stream::encode_all(payload.protected_bytes(), 0)
            .map_err(|_| CasError::Compression)?;
        let envelope = encode_envelope(payload, digest, &compressed)?;
        let staging = create_staging(parent, &envelope)?;
        let publish = (|| {
            if fs::symlink_metadata(&path).is_ok() {
                return Err(CasError::StoreCorrupt);
            }
            fs::rename(&staging, &path).map_err(map_io)?;
            lock.sync_all().map_err(map_io)
        })();
        if publish.is_err() {
            let _ = fs::remove_file(&staging);
        }
        publish?;
        Ok(digest)
    }

    pub fn read(&self, digest: &CasDigest) -> Result<Vec<u8>, CasError> {
        self.validate_root()?;
        let path = self.blob_path(digest);
        let before = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                CasError::NotFound
            } else {
                map_io(error)
            }
        })?;
        if before.file_type().is_symlink() || !before.is_file() {
            return Err(CasError::InvalidType);
        }
        if before.uid() != current_uid()? {
            return Err(CasError::WrongOwner);
        }
        if before.len() < HEADER_LENGTH as u64 {
            return Err(CasError::StoreCorrupt);
        }
        let mut file = File::open(&path).map_err(map_io)?;
        let opened = file.metadata().map_err(map_io)?;
        if opened.dev() != before.dev() || opened.ino() != before.ino() || !opened.is_file() {
            return Err(CasError::IdentityChanged);
        }
        let mut header = [0_u8; HEADER_LENGTH];
        file.read_exact(&mut header)
            .map_err(|_| CasError::StoreCorrupt)?;
        let decoded = decode_header(&header, digest)?;
        if before.len()
            != (HEADER_LENGTH as u64)
                .checked_add(decoded.compressed_length)
                .ok_or(CasError::StoreCorrupt)?
        {
            return Err(CasError::StoreCorrupt);
        }
        let compressed_length =
            usize::try_from(decoded.compressed_length).map_err(|_| CasError::StoreCorrupt)?;
        let mut compressed = vec![0_u8; compressed_length];
        file.read_exact(&mut compressed)
            .map_err(|_| CasError::StoreCorrupt)?;
        let expected_length =
            usize::try_from(decoded.uncompressed_length).map_err(|_| CasError::StoreCorrupt)?;
        let decoder = zstd::stream::read::Decoder::new(compressed.as_slice())
            .map_err(|_| CasError::StoreCorrupt)?;
        let limit = u64::try_from(expected_length)
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or(CasError::StoreCorrupt)?;
        let mut protected = Vec::with_capacity(expected_length.min(1024 * 1024));
        decoder
            .take(limit)
            .read_to_end(&mut protected)
            .map_err(|_| CasError::StoreCorrupt)?;
        if protected.len() != expected_length
            || CasDigest::for_protected_bytes(&protected) != *digest
        {
            return Err(CasError::StoreCorrupt);
        }
        Ok(protected)
    }

    pub fn encoded_blob_length(&self, digest: &CasDigest) -> Result<u64, CasError> {
        self.validate_root()?;
        let path = self.blob_path(digest);
        let before = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                CasError::NotFound
            } else {
                map_io(error)
            }
        })?;
        if before.file_type().is_symlink() || !before.is_file() {
            return Err(CasError::InvalidType);
        }
        if before.uid() != current_uid()? {
            return Err(CasError::WrongOwner);
        }
        if before.len() < HEADER_LENGTH as u64 {
            return Err(CasError::StoreCorrupt);
        }
        let mut file = File::open(&path).map_err(map_io)?;
        let opened = file.metadata().map_err(map_io)?;
        if opened.dev() != before.dev() || opened.ino() != before.ino() || !opened.is_file() {
            return Err(CasError::IdentityChanged);
        }
        let mut header = [0_u8; HEADER_LENGTH];
        file.read_exact(&mut header)
            .map_err(|_| CasError::StoreCorrupt)?;
        let decoded = decode_header(&header, digest)?;
        if before.len()
            != (HEADER_LENGTH as u64)
                .checked_add(decoded.compressed_length)
                .ok_or(CasError::StoreCorrupt)?
        {
            return Err(CasError::StoreCorrupt);
        }
        Ok(before.len())
    }

    pub fn delete_guarded_batch(
        guard: &MaintenanceGuard,
        digests: &[CasDigest],
    ) -> Result<Vec<CasDeleteOutcome>, CasError> {
        if !guard.exclusive {
            return Err(CasError::ExclusiveMaintenanceRequired);
        }
        if directory_file_identity(&guard.data_dir).is_err()
            || directory_file_identity(&guard.cas_dir).is_err()
            || directory_file_identity(&guard.blobs_dir).is_err()
        {
            return Err(CasError::IdentityChanged);
        }
        let mut by_parent = std::collections::BTreeMap::<String, Vec<(usize, CasDigest)>>::new();
        for (index, digest) in digests.iter().copied().enumerate() {
            let value = digest.as_hex();
            by_parent
                .entry(value[..2].to_owned())
                .or_default()
                .push((index, digest));
        }
        let mut outcomes = vec![CasDeleteOutcome::Missing; digests.len()];
        for (prefix, entries) in by_parent {
            let Some(parent) = open_optional_directory_at(&guard.blobs_dir, &prefix)? else {
                continue;
            };
            try_lock(&parent, true)?;
            let mut changed = false;
            for (index, digest) in entries {
                let value = digest.as_hex();
                let outcome = delete_from_parent(&parent, &value[2..], &digest)?;
                changed |= outcome == CasDeleteOutcome::Deleted;
                outcomes[index] = outcome;
            }
            if changed {
                parent.sync_all().map_err(map_io)?;
            }
        }
        Ok(outcomes)
    }

    pub fn parse_digest(value: &str) -> Result<CasDigest, CasError> {
        value.parse()
    }

    pub fn blob_path(&self, digest: &CasDigest) -> PathBuf {
        let value = digest.as_hex();
        self.root.join("blobs").join(&value[..2]).join(&value[2..])
    }

    fn validate_root(&self) -> Result<(), CasError> {
        validate_directory(&self.root)?;
        validate_directory(&self.root.join("blobs"))
    }
}

fn validate_lock_file(path: &Path, file: &File) -> Result<(), CasError> {
    let path_metadata = fs::symlink_metadata(path).map_err(map_io)?;
    let opened = file.metadata().map_err(map_io)?;
    validate_lock_metadata(&path_metadata)?;
    validate_lock_metadata(&opened)?;
    if path_metadata.dev() != opened.dev() || path_metadata.ino() != opened.ino() {
        return Err(CasError::IdentityChanged);
    }
    Ok(())
}

fn validate_lock_metadata(metadata: &fs::Metadata) -> Result<(), CasError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CasError::InvalidType);
    }
    if metadata.uid() != current_uid()? {
        return Err(CasError::WrongOwner);
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(CasError::InvalidPermissions);
    }
    Ok(())
}

fn validate_coordination_parent(path: &Path) -> Result<(), CasError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CasError::InvalidType);
    }
    Ok(())
}

fn try_lock(file: &File, exclusive: bool) -> Result<(), CasError> {
    let result = if exclusive {
        FileExt::try_lock_exclusive(file)
    } else {
        FileExt::try_lock_shared(file)
    };
    result.map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            CasError::LockBusy
        } else {
            map_io(error)
        }
    })
}

fn open_directory_at(parent: &File, name: impl AsRef<Path>) -> Result<File, CasError> {
    open_optional_directory_at(parent, name)?.ok_or(CasError::Io)
}

fn open_optional_directory_at(
    parent: &File,
    name: impl AsRef<Path>,
) -> Result<Option<File>, CasError> {
    let file = match openat(
        parent,
        name.as_ref(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(Errno::NOENT) => return Ok(None),
        Err(_) => return Err(CasError::Io),
    };
    let metadata = file.metadata().map_err(map_io)?;
    if !metadata.is_dir() {
        return Err(CasError::InvalidType);
    }
    if metadata.uid() != current_uid()? {
        return Err(CasError::WrongOwner);
    }
    Ok(Some(file))
}

fn directory_file_identity(file: &File) -> Result<(u64, u64), CasError> {
    let metadata = file.metadata().map_err(map_io)?;
    if !metadata.is_dir() {
        return Err(CasError::InvalidType);
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn directory_identity(path: &Path) -> Result<(u64, u64), CasError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn file_identity(file: &File) -> Result<(u64, u64, i64, i64), CasError> {
    let metadata = file.metadata().map_err(map_io)?;
    Ok(metadata_identity(&metadata))
}

fn metadata_identity(metadata: &fs::Metadata) -> (u64, u64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

struct DecodedHeader {
    uncompressed_length: u64,
    compressed_length: u64,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CasError {
    #[error("CAS path is invalid")]
    InvalidPath,
    #[error("CAS digest is invalid")]
    InvalidDigest,
    #[error("CAS blob was not found")]
    NotFound,
    #[error("CAS path has an invalid type")]
    InvalidType,
    #[error("CAS path has the wrong owner")]
    WrongOwner,
    #[error("CAS path has invalid permissions")]
    InvalidPermissions,
    #[error("CAS maintenance fence is busy")]
    LockBusy,
    #[error("CAS deletion requires an exclusive maintenance fence")]
    ExclusiveMaintenanceRequired,
    #[error("CAS identity changed during access")]
    IdentityChanged,
    #[error("CAS blob is corrupt")]
    StoreCorrupt,
    #[error("CAS compression failed")]
    Compression,
    #[error("CAS staging names were exhausted")]
    CreateCollision,
    #[error("CAS operation failed")]
    Io,
    #[error("secure operating-system randomness is unavailable")]
    RandomUnavailable,
}

fn encode_envelope(
    payload: &ProtectedPayload,
    digest: CasDigest,
    compressed: &[u8],
) -> Result<Vec<u8>, CasError> {
    let uncompressed_length =
        u64::try_from(payload.protected_bytes().len()).map_err(|_| CasError::Io)?;
    let compressed_length = u64::try_from(compressed.len()).map_err(|_| CasError::Io)?;
    let mut output = Vec::with_capacity(HEADER_LENGTH + compressed.len());
    output.extend_from_slice(CAS_MAGIC);
    output.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    output.extend_from_slice(&payload.protection_version().to_be_bytes());
    output.extend_from_slice(&COMPRESSION_VERSION.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&uncompressed_length.to_be_bytes());
    output.extend_from_slice(digest.as_bytes());
    output.extend_from_slice(&compressed_length.to_be_bytes());
    output.extend_from_slice(compressed);
    Ok(output)
}

fn decode_header(
    header: &[u8; HEADER_LENGTH],
    requested: &CasDigest,
) -> Result<DecodedHeader, CasError> {
    if &header[..8] != CAS_MAGIC
        || u16::from_be_bytes(
            header[8..10]
                .try_into()
                .map_err(|_| CasError::StoreCorrupt)?,
        ) != FORMAT_VERSION
        || u16::from_be_bytes(
            header[10..12]
                .try_into()
                .map_err(|_| CasError::StoreCorrupt)?,
        ) != 1
        || u16::from_be_bytes(
            header[12..14]
                .try_into()
                .map_err(|_| CasError::StoreCorrupt)?,
        ) != COMPRESSION_VERSION
        || header[14..16] != [0, 0]
    {
        return Err(CasError::StoreCorrupt);
    }
    let uncompressed_length = u64::from_be_bytes(
        header[16..24]
            .try_into()
            .map_err(|_| CasError::StoreCorrupt)?,
    );
    if &header[24..56] != requested.as_bytes() {
        return Err(CasError::StoreCorrupt);
    }
    let compressed_length = u64::from_be_bytes(
        header[56..64]
            .try_into()
            .map_err(|_| CasError::StoreCorrupt)?,
    );
    Ok(DecodedHeader {
        uncompressed_length,
        compressed_length,
    })
}

fn create_staging(parent: &Path, envelope: &[u8]) -> Result<PathBuf, CasError> {
    let mut suffix = [0_u8; 8];
    for attempt in 0..CREATE_ATTEMPTS {
        secure_random(&mut suffix)?;
        let path = parent.join(format!(".blob.tmp-{}-{}", attempt, hex(&suffix)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(map_io(error)),
        };
        let result = file
            .write_all(envelope)
            .and_then(|()| file.sync_all())
            .map_err(map_io);
        if let Err(error) = result {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        return Ok(path);
    }
    Err(CasError::CreateCollision)
}

fn delete_from_parent(
    parent: &File,
    file_name: &str,
    digest: &CasDigest,
) -> Result<CasDeleteOutcome, CasError> {
    let blob_fd = match openat(
        parent,
        file_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(value) => value,
        Err(rustix::io::Errno::NOENT) => return Ok(CasDeleteOutcome::Missing),
        Err(_) => return Err(CasError::Io),
    };
    let mut file = File::from(blob_fd);
    let opened = file.metadata().map_err(map_io)?;
    if !opened.is_file() {
        return Err(CasError::InvalidType);
    }
    if opened.uid() != current_uid()? {
        return Err(CasError::WrongOwner);
    }
    let mut header = [0_u8; HEADER_LENGTH];
    file.read_exact(&mut header)
        .map_err(|_| CasError::StoreCorrupt)?;
    let decoded = decode_header(&header, digest)?;
    if opened.len()
        != (HEADER_LENGTH as u64)
            .checked_add(decoded.compressed_length)
            .ok_or(CasError::StoreCorrupt)?
    {
        return Err(CasError::StoreCorrupt);
    }
    let current = statat(parent, file_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CasError::IdentityChanged)?;
    if current.st_dev != opened.dev()
        || current.st_ino != opened.ino()
        || current.st_uid != current_uid()?
    {
        return Err(CasError::IdentityChanged);
    }
    unlinkat(parent, file_name, AtFlags::empty()).map_err(|_| CasError::Io)?;
    Ok(CasDeleteOutcome::Deleted)
}

fn ensure_directory(path: &Path) -> Result<(), CasError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            match builder.create(path) {
                Ok(()) => validate_directory(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    validate_directory(path)
                }
                Err(error) => Err(map_io(error)),
            }
        }
        Err(error) => Err(map_io(error)),
    }
}

fn validate_directory(path: &Path) -> Result<(), CasError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CasError::InvalidType);
    }
    if metadata.uid() != current_uid()? {
        return Err(CasError::WrongOwner);
    }
    Ok(())
}

fn current_uid() -> Result<u32, CasError> {
    fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .map_err(map_io)
}

fn secure_random(output: &mut [u8]) -> Result<(), CasError> {
    let metadata = fs::symlink_metadata("/dev/urandom").map_err(|_| CasError::RandomUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_char_device() {
        return Err(CasError::RandomUnavailable);
    }
    File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(output))
        .map_err(|_| CasError::RandomUnavailable)
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

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn map_io(_: io::Error) -> CasError {
    CasError::Io
}
