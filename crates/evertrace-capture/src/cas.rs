use std::{
    ffi::OsString,
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    ops::Range,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    str::FromStr,
};

use evertrace_domain::evidence::{
    ProtectedPresentation, SourceArchiveMode, SourceObservation, SourcePayloadFingerprint,
    SourceReceipt,
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
pub const SOURCE_ARCHIVE_MAX_ENCODED_BYTES: u64 = 64 * 1024 * 1024;
pub const SOURCE_ARCHIVE_MAX_DECODED_BYTES: u64 = 128 * 1024 * 1024;
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

/// Streams one exact-length file while computing its ordinary SHA-256 checksum.
/// This is deliberately independent from the protected-payload CAS digest type.
pub fn copy_exact_sha256_hex(
    reader: &mut impl Read,
    writer: &mut impl Write,
    expected_length: u64,
) -> Result<String, CasError> {
    let mut remaining = expected_length;
    let mut checksum = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| CasError::StoreCorrupt)?;
        let read = reader.read(&mut buffer[..limit]).map_err(map_io)?;
        if read == 0 {
            return Err(CasError::StoreCorrupt);
        }
        writer.write_all(&buffer[..read]).map_err(map_io)?;
        checksum.update(&buffer[..read]);
        remaining = remaining
            .checked_sub(u64::try_from(read).map_err(|_| CasError::StoreCorrupt)?)
            .ok_or(CasError::StoreCorrupt)?;
    }
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra).map_err(map_io)? != 0 {
        return Err(CasError::StoreCorrupt);
    }
    Ok(hex(&checksum.finalize()))
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

#[derive(Clone, Debug)]
pub struct CasGcCandidate {
    pub digest: CasDigest,
    pub bytes: u64,
    uncompressed_bytes: u64,
    identity: (u64, u64, i64, i64),
    parent_identity: (u64, u64),
    cas_identity: (u64, u64),
}

/// Process-local enumeration only: never serialized, and discarded on restart.
pub struct CasGcCursor {
    first_shard: u8,
    offset: u16,
    directory: Option<(File, fs::ReadDir)>,
}

impl CasGcCursor {
    pub fn new(first_shard: u8) -> Self {
        Self {
            first_shard,
            offset: 0,
            directory: None,
        }
    }

    pub fn finished(&self) -> bool {
        self.offset == 256
    }
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

impl MaintenanceGuard {
    /// Duplicate this same flock description for the immediately following
    /// single-threaded child spawn. The caller closes its copy after spawn.
    /// Last close, not explicit LOCK_UN, releases the shared lease.
    pub fn inherit_shared_for_spawn(&self) -> Result<std::os::fd::OwnedFd, CasError> {
        if self.exclusive {
            return Err(CasError::ExclusiveMaintenanceRequired);
        }
        rustix::io::dup(&self.lock_file).map_err(|_| CasError::Io)
    }

    pub fn require_exclusive_for(&self, data_dir: &Path) -> Result<(), CasError> {
        if !self.exclusive {
            return Err(CasError::ExclusiveMaintenanceRequired);
        }
        self.require_root(data_dir)
    }

    pub(crate) fn require_root(&self, data_dir: &Path) -> Result<(), CasError> {
        if directory_identity(data_dir)? != directory_file_identity(&self.data_dir)? {
            return Err(CasError::IdentityChanged);
        }
        Ok(())
    }
}

impl CasStore {
    /// Enumerate one bounded canonical shard while holding the producer fence.
    /// Unknown files and over-limit shards are inconclusive, never deletable.
    pub fn gc_candidates(
        &self,
        guard: &MaintenanceGuard,
        cursor: &mut CasGcCursor,
        max_files: usize,
        max_bytes: u64,
    ) -> Result<Vec<CasGcCandidate>, CasError> {
        let data_dir = self.root.parent().ok_or(CasError::InvalidPath)?;
        guard.require_exclusive_for(data_dir)?;
        if directory_identity(&self.root)? != directory_file_identity(&guard.cas_dir)? {
            return Err(CasError::IdentityChanged);
        }
        let mut total = 0_u64;
        let mut uncompressed_total = 0_u64;
        let mut candidates = Vec::new();
        let mut examined = 0;
        while !cursor.finished() && examined < max_files {
            let prefix = format!(
                "{:02x}",
                cursor.first_shard.wrapping_add(cursor.offset as u8)
            );
            if cursor.directory.is_none() {
                let Some(parent) = open_optional_directory_at(&guard.blobs_dir, &prefix)? else {
                    cursor.offset += 1;
                    continue;
                };
                let entries = fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd()))
                    .map_err(map_io)?;
                cursor.directory = Some((parent, entries));
            }
            let (parent, entries) = cursor.directory.as_mut().ok_or(CasError::StoreCorrupt)?;
            let current = open_optional_directory_at(&guard.blobs_dir, &prefix)?
                .ok_or(CasError::IdentityChanged)?;
            if directory_file_identity(parent)? != directory_file_identity(&current)? {
                return Err(CasError::IdentityChanged);
            }
            let Some(entry) = entries.next() else {
                cursor.directory = None;
                cursor.offset += 1;
                continue;
            };
            let entry = entry.map_err(map_io)?;
            examined += 1;
            if !entry.file_type().map_err(map_io)?.is_file() {
                return Err(CasError::InvalidType);
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or(CasError::InvalidPath)?;
            let digest = CasDigest::from_str(&format!("{prefix}{name}"))?;
            let mut file = File::from(
                openat(
                    &*parent,
                    name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CasError::Io)?,
            );
            let before = file.metadata().map_err(map_io)?;
            validate_lock_metadata(&before)?;
            let mut header = [0_u8; HEADER_LENGTH];
            file.read_exact(&mut header)
                .map_err(|_| CasError::StoreCorrupt)?;
            let decoded = decode_header(&header, &digest)?;
            if decoded.uncompressed_length > max_bytes || before.len() > max_bytes {
                continue;
            }
            let bytes = before.len();
            let Some(next_total) = total.checked_add(bytes).filter(|total| *total <= max_bytes)
            else {
                // This file remains retained; consuming it cannot block later
                // small files. A later full enumeration may select it.
                continue;
            };
            let Some(next_uncompressed) = uncompressed_total
                .checked_add(decoded.uncompressed_length)
                .filter(|total| *total <= max_bytes)
            else {
                continue;
            };
            total = next_total;
            uncompressed_total = next_uncompressed;
            if metadata_identity(&before) != file_identity(&file)? || before.len() != bytes {
                return Err(CasError::IdentityChanged);
            }
            candidates.push(CasGcCandidate {
                digest,
                bytes,
                uncompressed_bytes: decoded.uncompressed_length,
                identity: metadata_identity(&before),
                parent_identity: directory_file_identity(parent)?,
                cas_identity: directory_file_identity(&guard.cas_dir)?,
            });
        }
        Self::validate_gc_candidates(guard, &candidates)?;
        Ok(candidates)
    }

    /// Expensive envelope hashing/decompression belongs outside the exclusive
    /// fence. The Writer rechecks original candidate identities after this pass.
    pub fn verify_gc_candidates(&self, candidates: &[CasGcCandidate]) -> Result<(), CasError> {
        for candidate in candidates {
            if self.verify_envelope(&candidate.digest)? != candidate.uncompressed_bytes {
                return Err(CasError::StoreCorrupt);
            }
        }
        Ok(())
    }

    pub fn validate_gc_candidates(
        guard: &MaintenanceGuard,
        candidates: &[CasGcCandidate],
    ) -> Result<(), CasError> {
        if !guard.exclusive {
            return Err(CasError::ExclusiveMaintenanceRequired);
        }
        for candidate in candidates {
            let name = candidate.digest.as_hex();
            let parent = open_directory_at(&guard.blobs_dir, &name[..2])?;
            if directory_file_identity(&parent)? != candidate.parent_identity
                || directory_file_identity(&guard.cas_dir)? != candidate.cas_identity
            {
                return Err(CasError::IdentityChanged);
            }
            let file = File::from(
                openat(
                    &parent,
                    &name[2..],
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CasError::Io)?,
            );
            let metadata = file.metadata().map_err(map_io)?;
            validate_lock_metadata(&metadata)?;
            if metadata_identity(&metadata) != candidate.identity
                || metadata.len() != candidate.bytes
            {
                return Err(CasError::IdentityChanged);
            }
        }
        Ok(())
    }

    pub fn open(root: impl Into<PathBuf>) -> Result<Self, CasError> {
        let store = Self { root: root.into() };
        ensure_directory(&store.root)?;
        ensure_directory(&store.root.join("blobs"))?;
        Ok(store)
    }

    pub fn open_existing(root: impl Into<PathBuf>) -> Result<Self, CasError> {
        let store = Self { root: root.into() };
        validate_directory(&store.root)?;
        validate_directory(&store.root.join("blobs"))?;
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
        self.read_bounded(digest, u64::MAX, u64::MAX)
            .map(|(bytes, _)| bytes)
    }

    /// Caller budgets cover encoded envelope and decoded output bytes, not the
    /// decoder's total RSS/window. Returns actual encoded bytes for batching.
    pub fn read_bounded(
        &self,
        digest: &CasDigest,
        max_encoded: u64,
        max_decoded: u64,
    ) -> Result<(Vec<u8>, u64), CasError> {
        self.read_bounded_checked(digest, max_encoded, max_decoded, || Ok(()))
    }

    /// Checkpoints cover encoded reads, decompression and hashing. This API
    /// intentionally retains decoded bytes; decoder window RSS is separate.
    pub fn read_bounded_checked(
        &self,
        digest: &CasDigest,
        max_encoded: u64,
        max_decoded: u64,
        mut check: impl FnMut() -> Result<(), CasError>,
    ) -> Result<(Vec<u8>, u64), CasError> {
        let mut protected = Vec::new();
        let (_, encoded) =
            self.read_verified(digest, max_encoded, max_decoded, &mut check, &mut |bytes| {
                protected.extend_from_slice(bytes);
                Ok(())
            })?;
        Ok((protected, encoded))
    }

    /// Verify the whole bounded envelope, retaining only the requested decoded range.
    /// The visitor is a Native validator, not a delivery sink; neither it nor the
    /// selected bytes may be exposed until this read and the validator finish.
    pub fn read_bounded_window_checked(
        &self,
        digest: &CasDigest,
        max_encoded: u64,
        max_decoded: u64,
        range: Range<u64>,
        check: &mut dyn FnMut() -> Result<(), CasError>,
        visit: &mut dyn FnMut(&[u8]) -> Result<(), CasError>,
    ) -> Result<CasReadWindow, CasError> {
        if range.end < range.start || range.end - range.start > max_decoded {
            return Err(CasError::ReadBudgetExceeded);
        }
        let mut bytes = Vec::new();
        let mut offset = 0_u64;
        let (total_bytes, encoded_bytes) =
            self.read_verified(digest, max_encoded, max_decoded, check, &mut |chunk| {
                visit(chunk)?;
                let next = offset
                    .checked_add(chunk.len() as u64)
                    .ok_or(CasError::StoreCorrupt)?;
                let start = range.start.max(offset);
                let end = range.end.min(next);
                if start < end {
                    bytes.extend_from_slice(
                        &chunk[(start - offset) as usize..(end - offset) as usize],
                    );
                }
                offset = next;
                Ok(())
            })?;
        Ok(CasReadWindow {
            bytes,
            total_bytes,
            encoded_bytes,
        })
    }

    /// Exact protected source text. Complete archive and text classification are
    /// verified before returning any selected bytes; no locator comes from a read client.
    pub fn read_source_text_window_checked(
        &self,
        receipt: &SourceReceipt,
        observation: &SourceObservation,
        range: Range<u64>,
        check: &mut dyn FnMut() -> Result<(), CasError>,
    ) -> Result<(CasReadWindow, bool), CasError> {
        let digest = receipt.cas_ref.parse::<CasDigest>()?;
        let mut verifier = SourceArchiveVerifier::new(receipt, observation)?;
        let mut utf8 = Utf8Check::default();
        let window = self.read_bounded_window_checked(
            &digest,
            SOURCE_ARCHIVE_MAX_ENCODED_BYTES,
            SOURCE_ARCHIVE_MAX_DECODED_BYTES,
            range,
            check,
            &mut |bytes| {
                verifier.update(bytes)?;
                utf8.update(bytes);
                Ok(())
            },
        )?;
        check()?;
        verifier.finish()?;
        Ok((window, utf8.valid && utf8.pending_len == 0))
    }

    /// Verifies the same envelope/digest without retaining decoded bytes.
    /// This does not assert a format-independent bound on the decoder window.
    pub fn verify_envelope(&self, digest: &CasDigest) -> Result<u64, CasError> {
        self.read_verified(digest, u64::MAX, u64::MAX, &mut || Ok(()), &mut |_| Ok(()))
            .map(|(decoded, _)| decoded)
    }

    fn read_verified(
        &self,
        digest: &CasDigest,
        max_encoded: u64,
        max_decoded: u64,
        check: &mut dyn FnMut() -> Result<(), CasError>,
        visit: &mut dyn FnMut(&[u8]) -> Result<(), CasError>,
    ) -> Result<(u64, u64), CasError> {
        check()?;
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
        let mut file =
            crate::open_regular_nofollow(&path).map_err(|_| CasError::IdentityChanged)?;
        let opened = file.metadata().map_err(map_io)?;
        if opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.len() != before.len()
        {
            return Err(CasError::IdentityChanged);
        }
        let mut header = [0_u8; HEADER_LENGTH];
        file.read_exact(&mut header)
            .map_err(|_| CasError::StoreCorrupt)?;
        let decoded = decode_header(&header, digest)?;
        if before.permissions().mode() & 0o777 != 0o600 {
            return Err(CasError::InvalidPermissions);
        }
        if before.len() > max_encoded
            || decoded.compressed_length > max_encoded
            || decoded.uncompressed_length > max_decoded
        {
            return Err(CasError::ReadBudgetExceeded);
        }
        if before.len()
            != (HEADER_LENGTH as u64)
                .checked_add(decoded.compressed_length)
                .ok_or(CasError::StoreCorrupt)?
        {
            return Err(CasError::StoreCorrupt);
        }
        let reader = CheckedRead {
            inner: file.take(decoded.compressed_length),
            check,
            failure: None,
        };
        let mut decoder =
            zstd::stream::read::Decoder::new(reader).map_err(|_| CasError::StoreCorrupt)?;
        let mut checksum = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            (decoder.get_mut().get_mut().check)()?;
            let read = match decoder.read(&mut buffer) {
                Ok(read) => read,
                Err(_) => {
                    return Err(decoder
                        .get_mut()
                        .get_mut()
                        .failure
                        .take()
                        .unwrap_or(CasError::StoreCorrupt));
                }
            };
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or(CasError::StoreCorrupt)?;
            if total > decoded.uncompressed_length {
                return Err(CasError::StoreCorrupt);
            }
            (decoder.get_mut().get_mut().check)()?;
            checksum.update(&buffer[..read]);
            visit(&buffer[..read])?;
        }
        let buffered = decoder.finish();
        if !buffered.buffer().is_empty() || buffered.get_ref().inner.limit() != 0 {
            return Err(CasError::StoreCorrupt);
        }
        let CheckedRead { inner, check, .. } = buffered.into_inner();
        let file = inner.into_inner();
        check()?;
        let after = fs::symlink_metadata(&path).map_err(map_io)?;
        let opened_after = file.metadata().map_err(map_io)?;
        if metadata_identity(&after) != metadata_identity(&before)
            || metadata_identity(&opened_after) != metadata_identity(&before)
            || after.len() != before.len()
            || opened_after.len() != before.len()
        {
            return Err(CasError::IdentityChanged);
        }
        let actual: [u8; 32] = checksum.finalize().into();
        if total != decoded.uncompressed_length || actual != *digest.as_bytes() {
            return Err(CasError::StoreCorrupt);
        }
        Ok((total, before.len()))
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

/// Classifies the complete archive while retaining at most one partial UTF-8 character.
struct Utf8Check {
    valid: bool,
    pending: [u8; 4],
    pending_len: usize,
}

impl Default for Utf8Check {
    fn default() -> Self {
        Self {
            valid: true,
            pending: [0; 4],
            pending_len: 0,
        }
    }
}

impl Utf8Check {
    fn update(&mut self, mut bytes: &[u8]) {
        if !self.valid {
            return;
        }
        if bytes.contains(&0) {
            self.valid = false;
            return;
        }
        if self.pending_len != 0 {
            let needed = self.pending[0].leading_ones() as usize;
            let take = bytes.len().min(needed - self.pending_len);
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&bytes[..take]);
            self.pending_len += take;
            if self.pending_len < needed {
                return;
            }
            if std::str::from_utf8(&self.pending[..needed]).is_err() {
                self.valid = false;
                return;
            }
            self.pending_len = 0;
            bytes = &bytes[take..];
        }
        if let Err(error) = std::str::from_utf8(bytes) {
            if error.error_len().is_some() {
                self.valid = false;
                return;
            }
            let tail = &bytes[error.valid_up_to()..];
            self.pending[..tail.len()].copy_from_slice(tail);
            self.pending_len = tail.len();
        }
    }
}

/// A verified CAS byte range. An offset beyond EOF yields an empty range and the actual total.
/// The data owner still validates the requested text boundary and current access.
pub struct CasReadWindow {
    pub bytes: Vec<u8>,
    pub total_bytes: u64,
    pub encoded_bytes: u64,
}

/// One request-local check of an existing source archive. Export and exact reads
/// share its tuple, protected-presentation, fingerprint and redaction validation.
/// It does not authorize access or retain the archive.
pub struct SourceArchiveVerifier<'a> {
    fingerprint: SourcePayloadFingerprint,
    expected_fingerprint: &'a str,
    presentation_prefix: &'a [u8],
    protected_length: u64,
    offset: u64,
    redactions: usize,
    minimum_redactions: usize,
    marker_position: usize,
}

impl<'a> SourceArchiveVerifier<'a> {
    pub fn new(
        receipt: &'a SourceReceipt,
        observation: &'a SourceObservation,
    ) -> Result<Self, CasError> {
        receipt.validate().map_err(|_| CasError::StoreCorrupt)?;
        observation.validate().map_err(|_| CasError::StoreCorrupt)?;
        if receipt.source_observation_id != observation.source_observation_id
            || receipt.source_receipt_id != observation.source_receipt_ref
            || receipt.source_instance_id != observation.source_instance_id
            || receipt.source_revision != observation.source_revision
            || receipt.source_record_identity != observation.source_record_identity
            || receipt.observation_role != observation.observation_role
            || receipt.identity_strength != observation.identity_strength
            || receipt.capture_completeness != observation.capture_completeness
            || receipt.adapter_revision != observation.adapter_revision
            || receipt.parser_revision != observation.parser_revision
            || receipt.canonicalization_revision != observation.canonicalization_revision
            || receipt.detector_revision != observation.detector_revision
            || receipt.redaction_revision != observation.redaction_revision
        {
            return Err(CasError::StoreCorrupt);
        }
        let secret = receipt
            .protected_secret_digest
            .as_deref()
            .map(str::parse::<CasDigest>)
            .transpose()?
            .map(|digest| *digest.as_bytes());
        let fingerprint = SourcePayloadFingerprint::new(
            receipt.canonicalization_revision,
            usize::try_from(receipt.protected_length).map_err(|_| CasError::StoreCorrupt)?,
            secret,
        )
        .map_err(|_| CasError::StoreCorrupt)?;
        let presentation_prefix = match &receipt.protected_presentation {
            Some(
                ProtectedPresentation::Inline { text } | ProtectedPresentation::Preview { text },
            ) => text.as_bytes(),
            _ => &[],
        };
        Ok(Self {
            fingerprint,
            expected_fingerprint: &observation.payload_fingerprint,
            presentation_prefix,
            protected_length: receipt.protected_length,
            offset: 0,
            redactions: 0,
            marker_position: 0,
            minimum_redactions: if receipt.archive_mode == SourceArchiveMode::Redacted {
                receipt.redaction_spans.len()
            } else {
                0
            },
        })
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<(), CasError> {
        self.fingerprint
            .update(bytes)
            .map_err(|_| CasError::StoreCorrupt)?;
        let start = usize::try_from(self.offset).map_err(|_| CasError::StoreCorrupt)?;
        if start < self.presentation_prefix.len() {
            let size = bytes.len().min(self.presentation_prefix.len() - start);
            if bytes[..size] != self.presentation_prefix[start..start + size] {
                return Err(CasError::StoreCorrupt);
            }
        }
        if self.minimum_redactions != 0 {
            // REDACTION_TOKEN contains no internal '['; only that byte can restart a partial match.
            for &byte in bytes {
                if byte == crate::protect::REDACTION_TOKEN[self.marker_position] {
                    self.marker_position += 1;
                    if self.marker_position == crate::protect::REDACTION_TOKEN.len() {
                        self.redactions += 1;
                        self.marker_position = 0;
                    }
                } else {
                    self.marker_position = usize::from(byte == b'[');
                }
            }
        }
        self.offset = self
            .offset
            .checked_add(bytes.len() as u64)
            .ok_or(CasError::StoreCorrupt)?;
        Ok(())
    }

    pub fn finish(self) -> Result<(), CasError> {
        if self.offset != self.protected_length
            || self.redactions < self.minimum_redactions
            || hex(&self
                .fingerprint
                .finish()
                .map_err(|_| CasError::StoreCorrupt)?)
                != self.expected_fingerprint
        {
            return Err(CasError::StoreCorrupt);
        }
        Ok(())
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

/// Limits each encoded read and preserves cancellation rather than relabeling it as corruption.
struct CheckedRead<'a> {
    inner: io::Take<File>,
    check: &'a mut dyn FnMut() -> Result<(), CasError>,
    failure: Option<CasError>,
}

impl Read for CheckedRead<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if let Err(error) = (self.check)() {
            self.failure = Some(error);
            return Err(io::Error::other("CAS read checkpoint refused"));
        }
        let limit = buffer.len().min(64 * 1024);
        self.inner.read(&mut buffer[..limit])
    }
}

struct DecodedHeader {
    uncompressed_length: u64,
    compressed_length: u64,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CasError {
    #[error("CAS read was cancelled or exceeded its deadline")]
    ReadCancelled,
    #[error("CAS read byte budget was exceeded")]
    ReadBudgetExceeded,
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
