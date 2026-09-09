//! Root-confined, no-follow reads for bounded capture inputs.

use std::ffi::{OsStr, OsString};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags, RawDir, Stat, fstat, open, openat, statat};

/// Opens one regular file without following a final symlink. Callers that own a
/// stronger path identity compare the returned file metadata with that identity.
pub fn open_regular_nofollow(path: &Path) -> Result<std::fs::File, ConfinedReadError> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_open_error)?;
    let opened = fstat(&fd).map_err(|_| ConfinedReadError::Io)?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile {
        return Err(ConfinedReadError::UnsupportedType);
    }
    Ok(std::fs::File::from(fd))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfinedReadLimits {
    pub single_file_remaining: u64,
    pub untracked_total_remaining: u64,
    pub bundle_remaining: u64,
    pub deadline: Instant,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConfinedFileIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: u64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfinedLimitKind {
    SingleFile,
    UntrackedTotal,
    Bundle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfinedFileMetadata {
    pub identity: ConfinedFileIdentity,
}

#[derive(Eq, PartialEq)]
pub struct ConfinedFile {
    pub bytes: Vec<u8>,
    pub identity: ConfinedFileIdentity,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConfinedEntryType {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConfinedDirectoryEntry {
    pub name: String,
    pub entry_type: ConfinedEntryType,
    pub identity: ConfinedFileIdentity,
}

#[derive(Eq, PartialEq)]
pub struct ConfinedFileRange {
    pub bytes: Vec<u8>,
    pub identity: ConfinedFileIdentity,
    pub next_offset: u64,
    pub eof: bool,
}

impl std::fmt::Debug for ConfinedFileRange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfinedFileRange")
            .field("byte_length", &self.bytes.len())
            .field("identity", &self.identity)
            .field("next_offset", &self.next_offset)
            .field("eof", &self.eof)
            .finish()
    }
}

impl std::fmt::Debug for ConfinedFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfinedFile")
            .field("byte_length", &self.bytes.len())
            .field("identity", &self.identity)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConfinedReadError {
    #[error("invalid confined path")]
    InvalidPath,
    #[error("capture deadline expired")]
    Deadline,
    #[error("capture item exceeds a closed budget")]
    LimitExceeded {
        kind: ConfinedLimitKind,
        metadata: ConfinedFileMetadata,
    },
    #[error("capture item is not a regular file")]
    UnsupportedType,
    #[error("capture item changed while it was read")]
    Changed,
    #[error("capture size arithmetic failed")]
    Arithmetic,
    #[error("confined filesystem operation failed")]
    Io,
}

pub struct ConfinedRoot {
    fd: OwnedFd,
    locator: PathBuf,
    identity: ConfinedFileIdentity,
    owner: u32,
    mode: u32,
    locator_chain: Option<Vec<(OsString, ConfinedFileIdentity)>>,
    external_source: bool,
}

impl ConfinedRoot {
    /// Publish a private sibling directory without replacing any existing target.
    /// The caller retains its writer lock and synchronizes this parent before
    /// treating publication as durable.
    /// An error can follow a successful rename: callers must inspect held
    /// identities before rollback or cleanup, never infer that no mutation ran.
    pub fn publish_directory_noreplace(
        &self,
        source: &ConfinedRoot,
        destination: &str,
    ) -> Result<(), ConfinedReadError> {
        self.rename_directory(source, destination, None)
    }

    /// Atomically exchange two known sibling directories, including for rollback.
    /// As with publication, a post-rename identity error does not undo the syscall.
    pub fn exchange_directories(
        &self,
        source: &ConfinedRoot,
        destination: &ConfinedRoot,
    ) -> Result<(), ConfinedReadError> {
        let name = destination
            .locator
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or(ConfinedReadError::InvalidPath)?;
        self.rename_directory(source, name, Some(destination))
    }

    fn rename_directory(
        &self,
        source: &ConfinedRoot,
        destination: &str,
        exchange: Option<&ConfinedRoot>,
    ) -> Result<(), ConfinedReadError> {
        if self.external_source
            || source.external_source
            || exchange.is_some_and(|root| root.external_source)
        {
            return Err(ConfinedReadError::UnsupportedType);
        }
        if source.locator.parent() != Some(self.locator.as_path())
            || Path::new(destination).components().count() != 1
            || !matches!(
                Path::new(destination).components().next(),
                Some(Component::Normal(_))
            )
        {
            return Err(ConfinedReadError::InvalidPath);
        }
        self.revalidate_stable()?;
        source.revalidate_stable()?;
        if let Some(target) = exchange {
            if target.locator != self.locator.join(destination) {
                return Err(ConfinedReadError::InvalidPath);
            }
            target.revalidate_stable()?;
        }
        let name = source
            .locator
            .file_name()
            .ok_or(ConfinedReadError::InvalidPath)?;
        rustix::fs::renameat_with(
            &self.fd,
            name,
            &self.fd,
            destination,
            if exchange.is_some() {
                rustix::fs::RenameFlags::EXCHANGE
            } else {
                rustix::fs::RenameFlags::NOREPLACE
            },
        )
        .map_err(|_| ConfinedReadError::Io)?;
        self.revalidate_stable()?;
        let published = statat(&self.fd, destination, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ConfinedReadError::Io)?;
        if !source.matches_root(&published)? {
            return Err(ConfinedReadError::Changed);
        }
        if let Some(target) = exchange {
            let previous = statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| ConfinedReadError::Io)?;
            if !target.matches_root(&previous)? {
                return Err(ConfinedReadError::Changed);
            }
        }
        Ok(())
    }

    pub fn open(root: &Path) -> Result<Self, ConfinedReadError> {
        let locator = std::fs::canonicalize(root).map_err(|_| ConfinedReadError::Io)?;
        let fd = open(
            &locator,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ConfinedReadError::Io)?;
        let stat = fstat(&fd).map_err(|_| ConfinedReadError::Io)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(ConfinedReadError::UnsupportedType);
        }
        Ok(Self {
            fd,
            locator,
            identity: identity(&stat)?,
            owner: stat.st_uid,
            mode: stat.st_mode,
            locator_chain: None,
            external_source: false,
        })
    }

    /// Opens a recovery mutation root only when the locator itself is a
    /// directory (not a symlink), is owned by the daemon user, and is not
    /// writable by group or other users. The returned descriptor remains the
    /// authority for all subsequent child cwd and probe operations.
    pub fn open_owned_private(root: &Path) -> Result<Self, ConfinedReadError> {
        Self::open_owned(root, false)
    }

    /// Read-only Host sources may be public-readable below a private ancestor.
    /// This does not authorize body import or change recovery/mutation roots.
    pub fn open_external_source(root: &Path) -> Result<Self, ConfinedReadError> {
        Self::open_owned(root, true)
    }

    fn open_owned(root: &Path, external_source: bool) -> Result<Self, ConfinedReadError> {
        if !root.is_absolute() {
            return Err(ConfinedReadError::InvalidPath);
        }
        let components = root
            .components()
            .map(|component| match component {
                Component::RootDir => Ok(None),
                Component::Normal(value) if !value.is_empty() => Ok(Some(value.to_os_string())),
                _ => Err(ConfinedReadError::InvalidPath),
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        if components.is_empty() {
            return Err(ConfinedReadError::InvalidPath);
        }
        let mut current = open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ConfinedReadError::Io)?;
        let mut locator_chain = Vec::with_capacity(components.len());
        for component in &components {
            let next = openat(
                &current,
                component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(map_open_error)?;
            let opened = fstat(&next).map_err(|_| ConfinedReadError::Io)?;
            if FileType::from_raw_mode(opened.st_mode) != FileType::Directory {
                return Err(ConfinedReadError::UnsupportedType);
            }
            locator_chain.push((component.clone(), identity(&opened)?));
            current = next;
        }
        let fd = current;
        let opened = fstat(&fd).map_err(|_| ConfinedReadError::Io)?;
        let process_fd = open(
            "/proc/self",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ConfinedReadError::Io)?;
        let process = fstat(&process_fd).map_err(|_| ConfinedReadError::Io)?;
        if FileType::from_raw_mode(opened.st_mode) != FileType::Directory
            || opened.st_uid != process.st_uid
            || opened.st_mode & 0o022 != 0
        {
            return Err(ConfinedReadError::UnsupportedType);
        }
        let result = Self {
            fd,
            locator: root.to_path_buf(),
            identity: identity(&opened)?,
            owner: opened.st_uid,
            mode: opened.st_mode,
            locator_chain: Some(locator_chain),
            external_source,
        };
        if external_source {
            result.revalidate_stable()?;
        }
        Ok(result)
    }

    pub fn read(
        &self,
        relative: &Path,
        limits: ConfinedReadLimits,
    ) -> Result<ConfinedFile, ConfinedReadError> {
        self.read_impl(relative, limits, true, || {})
    }

    /// Reads through the already-pinned root after the supervised mutation
    /// may legitimately have changed directory timestamps.
    pub fn read_after_owned_mutation(
        &self,
        relative: &Path,
        limits: ConfinedReadLimits,
    ) -> Result<ConfinedFile, ConfinedReadError> {
        if self.external_source {
            return Err(ConfinedReadError::UnsupportedType);
        }
        self.read_impl(relative, limits, false, || {})
    }

    pub fn list_directory(
        &self,
        relative: Option<&Path>,
        max_entries: usize,
        deadline: Instant,
    ) -> Result<Vec<ConfinedDirectoryEntry>, ConfinedReadError> {
        if max_entries == 0 {
            return Err(ConfinedReadError::InvalidPath);
        }
        check_deadline(deadline)?;
        let components = relative
            .map(strict_components)
            .transpose()?
            .unwrap_or_default();
        let (directory, identities) = self.open_directory_chain(&components, deadline)?;
        let before = identity(&fstat(&directory).map_err(|_| ConfinedReadError::Io)?)?;
        let mut buffer = [MaybeUninit::uninit(); 8192];
        let mut entries = Vec::new();
        let mut directory_entries = RawDir::new(&directory, &mut buffer);
        while let Some(entry) = directory_entries.next() {
            check_deadline(deadline)?;
            let entry = entry.map_err(|_| ConfinedReadError::Io)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let name = std::str::from_utf8(name).map_err(|_| ConfinedReadError::InvalidPath)?;
            if name.is_empty() || name.as_bytes().contains(&b'/') {
                return Err(ConfinedReadError::InvalidPath);
            }
            let stat = statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| ConfinedReadError::Io)?;
            self.validate_external_entry(&stat)?;
            let entry_type = match FileType::from_raw_mode(stat.st_mode) {
                FileType::RegularFile => ConfinedEntryType::File,
                FileType::Directory => ConfinedEntryType::Directory,
                _ => return Err(ConfinedReadError::UnsupportedType),
            };
            entries.push(ConfinedDirectoryEntry {
                name: name.to_owned(),
                entry_type,
                identity: identity(&stat)?,
            });
            if entries.len() > max_entries {
                return Err(ConfinedReadError::LimitExceeded {
                    kind: ConfinedLimitKind::Bundle,
                    metadata: ConfinedFileMetadata { identity: before },
                });
            }
        }
        entries.sort();
        if self.external_source {
            for entry in &entries {
                check_deadline(deadline)?;
                let stat = statat(&directory, entry.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| ConfinedReadError::Io)?;
                self.validate_external_entry(&stat)?;
                if identity(&stat)? != entry.identity {
                    return Err(ConfinedReadError::Changed);
                }
            }
        }
        let after = identity(&fstat(&directory).map_err(|_| ConfinedReadError::Io)?)?;
        if before != after {
            return Err(ConfinedReadError::Changed);
        }
        check_deadline(deadline)?;
        self.validate_directory_chain(&components, &identities, deadline)?;
        self.revalidate()?;
        Ok(entries)
    }

    /// Open a regular file without following any component below this root.
    pub fn open_regular_file(&self, relative: &Path) -> Result<std::fs::File, ConfinedReadError> {
        let components = strict_components(relative)?;
        let (leaf, parents) = components
            .split_last()
            .ok_or(ConfinedReadError::InvalidPath)?;
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        let (parent, identities) = self.open_directory_chain(parents, deadline)?;
        let fd = openat(
            &parent,
            *leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_open_error)?;
        let opened = fstat(&fd).map_err(|_| ConfinedReadError::Io)?;
        self.validate_external_entry(&opened)?;
        if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile {
            return Err(ConfinedReadError::UnsupportedType);
        }
        if self.external_source {
            let entry = statat(&parent, *leaf, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| ConfinedReadError::Io)?;
            self.validate_external_entry(&entry)?;
            if identity(&entry)? != identity(&opened)? {
                return Err(ConfinedReadError::Changed);
            }
        }
        self.validate_directory_chain(parents, &identities, deadline)?;
        self.revalidate_stable()?;
        Ok(fd.into())
    }

    /// Recheck a checkpoint's already-read source without reading body bytes.
    /// Uses the existing bounded metadata-open window, not an expired body-IO deadline.
    pub fn revalidate_file(
        &self,
        relative: &Path,
        expected: ConfinedFileIdentity,
    ) -> Result<(), ConfinedReadError> {
        let file = self.open_regular_file(relative)?;
        let current = fstat(&file).map_err(|_| ConfinedReadError::Io)?;
        self.validate_external_entry(&current)?;
        if identity(&current)? != expected {
            return Err(ConfinedReadError::Changed);
        }
        self.revalidate_stable()
    }

    /// Reads one newline-terminated record using the same confined range reader.
    /// The record bound excludes its newline; the total I/O budget includes it.
    pub fn read_first_record(
        &self,
        relative: &Path,
        expected: ConfinedFileIdentity,
        max_record_bytes: usize,
        remaining: &mut usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, ConfinedReadError> {
        let bound = max_record_bytes
            .checked_add(1)
            .ok_or(ConfinedReadError::Arithmetic)?;
        let mut bytes = Vec::new();
        loop {
            let limit = 4096.min(*remaining).min(bound - bytes.len());
            if limit == 0 {
                return Err(ConfinedReadError::LimitExceeded {
                    kind: ConfinedLimitKind::SingleFile,
                    metadata: ConfinedFileMetadata { identity: expected },
                });
            }
            let chunk = self.read_range(relative, expected, bytes.len() as u64, limit, deadline)?;
            *remaining -= chunk.bytes.len();
            if let Some(newline) = chunk.bytes.iter().position(|byte| *byte == b'\n') {
                bytes.extend_from_slice(&chunk.bytes[..newline]);
                check_deadline(deadline)?;
                return Ok(bytes);
            }
            if bytes.len() + chunk.bytes.len() > max_record_bytes {
                return Err(ConfinedReadError::LimitExceeded {
                    kind: ConfinedLimitKind::SingleFile,
                    metadata: ConfinedFileMetadata { identity: expected },
                });
            }
            if chunk.eof {
                return Err(ConfinedReadError::UnsupportedType);
            }
            bytes.extend_from_slice(&chunk.bytes);
        }
    }

    pub fn read_range(
        &self,
        relative: &Path,
        expected: ConfinedFileIdentity,
        offset: u64,
        max_bytes: usize,
        deadline: Instant,
    ) -> Result<ConfinedFileRange, ConfinedReadError> {
        if max_bytes == 0 {
            return Err(ConfinedReadError::InvalidPath);
        }
        check_deadline(deadline)?;
        let components = strict_components(relative)?;
        let (leaf, parents) = components
            .split_last()
            .ok_or(ConfinedReadError::InvalidPath)?;
        let (parent, identities) = self.open_directory_chain(parents, deadline)?;
        let fd = openat(
            &parent,
            *leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_open_error)?;
        let before = fstat(&fd).map_err(|_| ConfinedReadError::Io)?;
        self.validate_external_entry(&before)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || identity(&before)? != expected
            || offset > expected.size
        {
            return Err(ConfinedReadError::Changed);
        }
        let remaining = expected.size - offset;
        if remaining == 0 {
            if self.external_source {
                let after = fstat(&fd).map_err(|_| ConfinedReadError::Io)?;
                let entry = statat(&parent, *leaf, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| ConfinedReadError::Io)?;
                self.validate_external_entry(&after)?;
                self.validate_external_entry(&entry)?;
                if identity(&after)? != expected || identity(&entry)? != expected {
                    return Err(ConfinedReadError::Changed);
                }
            }
            self.validate_directory_chain(parents, &identities, deadline)?;
            self.revalidate()?;
            return Ok(ConfinedFileRange {
                bytes: Vec::new(),
                identity: expected,
                next_offset: offset,
                eof: true,
            });
        }
        let allocation = usize::try_from(remaining.min(max_bytes as u64))
            .map_err(|_| ConfinedReadError::Arithmetic)?;
        let mut bytes = vec![0_u8; allocation];
        let read = rustix::io::pread(&fd, &mut bytes, offset).map_err(|_| ConfinedReadError::Io)?;
        if read == 0 {
            return Err(ConfinedReadError::Changed);
        }
        bytes.truncate(read);
        check_deadline(deadline)?;
        let after = fstat(&fd).map_err(|_| ConfinedReadError::Io)?;
        let entry =
            statat(&parent, *leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ConfinedReadError::Io)?;
        self.validate_external_entry(&after)?;
        self.validate_external_entry(&entry)?;
        if identity(&after)? != expected || identity(&entry)? != expected {
            return Err(ConfinedReadError::Changed);
        }
        self.validate_directory_chain(parents, &identities, deadline)?;
        self.revalidate()?;
        let next_offset = offset
            .checked_add(u64::try_from(read).map_err(|_| ConfinedReadError::Arithmetic)?)
            .ok_or(ConfinedReadError::Arithmetic)?;
        Ok(ConfinedFileRange {
            bytes,
            identity: expected,
            next_offset,
            eof: next_offset == expected.size,
        })
    }

    fn open_directory_chain(
        &self,
        components: &[&OsStr],
        deadline: Instant,
    ) -> Result<(OwnedFd, Vec<ConfinedFileIdentity>), ConfinedReadError> {
        if self.external_source {
            self.revalidate_stable()?;
        }
        let mut current = openat(
            &self.fd,
            OsStr::new("."),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ConfinedReadError::Io)?;
        let mut identities = Vec::with_capacity(components.len());
        for component in components {
            check_deadline(deadline)?;
            let next = openat(
                &current,
                *component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(map_open_error)?;
            let stat = fstat(&next).map_err(|_| ConfinedReadError::Io)?;
            self.validate_external_entry(&stat)?;
            identities.push(identity(&stat)?);
            current = next;
        }
        Ok((current, identities))
    }

    fn validate_directory_chain(
        &self,
        components: &[&OsStr],
        identities: &[ConfinedFileIdentity],
        deadline: Instant,
    ) -> Result<(), ConfinedReadError> {
        let mut current = &self.fd;
        let mut opened = Vec::with_capacity(components.len());
        for (index, component) in components.iter().enumerate() {
            check_deadline(deadline)?;
            let entry = statat(current, *component, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| ConfinedReadError::Io)?;
            let next = openat(
                current,
                *component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(map_open_error)?;
            let stat = fstat(&next).map_err(|_| ConfinedReadError::Io)?;
            self.validate_external_entry(&entry)?;
            self.validate_external_entry(&stat)?;
            if identity(&entry)? != identities[index] || identity(&stat)? != identities[index] {
                return Err(ConfinedReadError::Changed);
            }
            opened.push(next);
            current = opened.last().ok_or(ConfinedReadError::Io)?;
        }
        Ok(())
    }

    pub const fn identity(&self) -> ConfinedFileIdentity {
        self.identity
    }

    pub fn proc_cwd_path(&self) -> Result<PathBuf, ConfinedReadError> {
        // Name the owning process explicitly. `Command` may use a spawn path
        // that closes CLOEXEC descriptors before applying the child cwd, so a
        // child-relative `/proc/self/fd/<n>` is not a stable locator. The
        // owning process retains custody until the recovery transaction ends.
        let path = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.fd.as_raw_fd()
        ));
        let stat = statat(CWD, &path, AtFlags::empty()).map_err(|_| ConfinedReadError::Io)?;
        if !self.matches_root(&stat)? {
            return Err(ConfinedReadError::Changed);
        }
        Ok(path)
    }

    #[cfg(test)]
    fn read_with_hook(
        &self,
        relative: &Path,
        limits: ConfinedReadLimits,
        before_read: impl FnOnce(),
    ) -> Result<ConfinedFile, ConfinedReadError> {
        self.read_impl(relative, limits, true, before_read)
    }

    fn read_impl(
        &self,
        relative: &Path,
        limits: ConfinedReadLimits,
        strict_root: bool,
        before_read: impl FnOnce(),
    ) -> Result<ConfinedFile, ConfinedReadError> {
        check_deadline(limits.deadline)?;
        if self.external_source {
            self.revalidate_stable()?;
        }
        let components = strict_components(relative)?;
        let (leaf, parents) = components
            .split_last()
            .ok_or(ConfinedReadError::InvalidPath)?;

        let mut owned_parents = Vec::with_capacity(parents.len());
        let mut parent_identities = Vec::with_capacity(parents.len());
        let mut parent = &self.fd;
        for component in parents {
            check_deadline(limits.deadline)?;
            let fd = openat(
                parent,
                *component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(map_open_error)?;
            let stat = fstat(&fd).map_err(|_| ConfinedReadError::Io)?;
            self.validate_external_entry(&stat)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
                return Err(ConfinedReadError::UnsupportedType);
            }
            parent_identities.push(identity(&stat)?);
            owned_parents.push(fd);
            parent = owned_parents.last().ok_or(ConfinedReadError::Io)?;
        }

        let fd = openat(
            parent,
            *leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_open_error)?;
        let before = fstat(&fd).map_err(|_| ConfinedReadError::Io)?;
        self.validate_external_entry(&before)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
            return Err(ConfinedReadError::UnsupportedType);
        }
        let before_identity = identity(&before)?;
        let allowed = limits
            .single_file_remaining
            .min(limits.untracked_total_remaining)
            .min(limits.bundle_remaining);
        if before_identity.size > allowed {
            return Err(limit_error(limits, before_identity));
        }
        let detection_limit = allowed
            .checked_add(1)
            .ok_or(ConfinedReadError::Arithmetic)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(before_identity.size)
                .map_err(|_| limit_error(limits, before_identity))?,
        );
        let mut chunk = [0_u8; 8192];
        before_read();
        loop {
            check_deadline(limits.deadline)?;
            let remaining = detection_limit
                .checked_sub(u64::try_from(bytes.len()).map_err(|_| ConfinedReadError::Arithmetic)?)
                .ok_or_else(|| limit_error(limits, before_identity))?;
            if remaining == 0 {
                return Err(limit_error(limits, before_identity));
            }
            let wanted = usize::try_from(remaining.min(chunk.len() as u64))
                .map_err(|_| ConfinedReadError::Arithmetic)?;
            let read =
                rustix::io::read(&fd, &mut chunk[..wanted]).map_err(|_| ConfinedReadError::Io)?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        if u64::try_from(bytes.len()).map_err(|_| ConfinedReadError::Arithmetic)?
            != before_identity.size
        {
            return Err(ConfinedReadError::Changed);
        }

        check_deadline(limits.deadline)?;
        let after = fstat(&fd).map_err(|_| ConfinedReadError::Io)?;
        let entry =
            statat(parent, *leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ConfinedReadError::Io)?;
        self.validate_external_entry(&after)?;
        self.validate_external_entry(&entry)?;
        if identity(&after)? != before_identity || identity(&entry)? != before_identity {
            return Err(ConfinedReadError::Changed);
        }
        for (index, component) in parents.iter().enumerate() {
            let containing = if index == 0 {
                &self.fd
            } else {
                &owned_parents[index - 1]
            };
            let entry = statat(containing, *component, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| ConfinedReadError::Io)?;
            let opened = fstat(&owned_parents[index]).map_err(|_| ConfinedReadError::Io)?;
            self.validate_external_entry(&entry)?;
            self.validate_external_entry(&opened)?;
            if identity(&entry)? != parent_identities[index]
                || identity(&opened)? != parent_identities[index]
            {
                return Err(ConfinedReadError::Changed);
            }
        }
        if strict_root {
            self.revalidate()?;
        } else {
            self.revalidate_stable()?;
        }
        Ok(ConfinedFile {
            bytes,
            identity: before_identity,
        })
    }

    pub fn revalidate(&self) -> Result<(), ConfinedReadError> {
        self.revalidate_locator_chain()?;
        let current = statat(CWD, &self.locator, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ConfinedReadError::Io)?;
        let opened = fstat(&self.fd).map_err(|_| ConfinedReadError::Io)?;
        if !self.matches_original_root(&current)? || !self.matches_original_root(&opened)? {
            return Err(ConfinedReadError::Changed);
        }
        Ok(())
    }

    pub fn revalidate_stable(&self) -> Result<(), ConfinedReadError> {
        self.revalidate_locator_chain()?;
        let current = statat(CWD, &self.locator, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ConfinedReadError::Io)?;
        let opened = fstat(&self.fd).map_err(|_| ConfinedReadError::Io)?;
        if !self.matches_root(&current)? || !self.matches_root(&opened)? {
            return Err(ConfinedReadError::Changed);
        }
        Ok(())
    }

    fn matches_original_root(&self, stat: &Stat) -> Result<bool, ConfinedReadError> {
        // External root authority is its no-follow inode and current permission
        // boundary, not directory timestamps changed by unrelated Host entries.
        Ok(self.matches_root(stat)? && (self.external_source || identity(stat)? == self.identity))
    }

    fn revalidate_locator_chain(&self) -> Result<(), ConfinedReadError> {
        let Some(expected) = &self.locator_chain else {
            return Ok(());
        };
        let mut current = open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ConfinedReadError::Io)?;
        let mut private = false;
        if self.external_source {
            validate_external_ancestor(
                &fstat(&current).map_err(|_| ConfinedReadError::Io)?,
                self.owner,
                &mut private,
            )?;
        }
        for (component, expected_identity) in expected {
            let entry = statat(&current, component, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| ConfinedReadError::Io)?;
            let next = openat(
                &current,
                component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(map_open_error)?;
            let opened = fstat(&next).map_err(|_| ConfinedReadError::Io)?;
            if self.external_source {
                validate_external_ancestor(&entry, self.owner, &mut private)?;
                validate_external_ancestor(&opened, self.owner, &mut private)?;
            }
            if !same_file_identity(&identity(&entry)?, expected_identity)
                || !same_file_identity(&identity(&opened)?, expected_identity)
            {
                return Err(ConfinedReadError::Changed);
            }
            current = next;
        }
        if self.external_source && !private {
            return Err(ConfinedReadError::UnsupportedType);
        }
        Ok(())
    }

    fn validate_external_entry(&self, stat: &Stat) -> Result<(), ConfinedReadError> {
        if self.external_source && (stat.st_uid != self.owner || stat.st_mode & 0o022 != 0) {
            return Err(ConfinedReadError::UnsupportedType);
        }
        Ok(())
    }

    fn matches_root(&self, stat: &Stat) -> Result<bool, ConfinedReadError> {
        let current = identity(stat)?;
        Ok(FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            && current.device == self.identity.device
            && current.inode == self.identity.inode
            && stat.st_uid == self.owner
            && if self.external_source {
                stat.st_mode & 0o022 == 0
            } else {
                stat.st_mode == self.mode
            })
    }
}

fn validate_external_ancestor(
    stat: &Stat,
    owner: u32,
    private: &mut bool,
) -> Result<(), ConfinedReadError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || if *private {
            stat.st_uid != owner || stat.st_mode & 0o022 != 0
        } else {
            // A sticky writable parent protects root/current-UID child entries;
            // the next component must satisfy this same owner check.
            (stat.st_uid != 0 && stat.st_uid != owner)
                || (stat.st_mode & 0o022 != 0 && stat.st_mode & 0o1000 == 0)
        }
    {
        return Err(ConfinedReadError::UnsupportedType);
    }
    *private |= stat.st_uid == owner && stat.st_mode & 0o077 == 0;
    Ok(())
}

fn same_file_identity(left: &ConfinedFileIdentity, right: &ConfinedFileIdentity) -> bool {
    left.device == right.device && left.inode == right.inode
}

fn strict_components(path: &Path) -> Result<Vec<&OsStr>, ConfinedReadError> {
    let raw = path.as_os_str().as_bytes();
    if raw.is_empty()
        || raw.first() == Some(&b'/')
        || raw.last() == Some(&b'/')
        || raw.windows(2).any(|part| part == b"//")
    {
        return Err(ConfinedReadError::InvalidPath);
    }
    path.components()
        .map(|component| match component {
            Component::Normal(value) if !value.is_empty() => Ok(value),
            _ => Err(ConfinedReadError::InvalidPath),
        })
        .collect()
}

fn identity(stat: &Stat) -> Result<ConfinedFileIdentity, ConfinedReadError> {
    Ok(ConfinedFileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        size: u64::try_from(stat.st_size).map_err(|_| ConfinedReadError::Io)?,
        mtime_seconds: stat.st_mtime,
        mtime_nanoseconds: stat.st_mtime_nsec,
        ctime_seconds: stat.st_ctime,
        ctime_nanoseconds: stat.st_ctime_nsec,
    })
}

fn check_deadline(deadline: Instant) -> Result<(), ConfinedReadError> {
    if Instant::now() >= deadline {
        Err(ConfinedReadError::Deadline)
    } else {
        Ok(())
    }
}

fn limit_error(limits: ConfinedReadLimits, identity: ConfinedFileIdentity) -> ConfinedReadError {
    let minimum = limits
        .single_file_remaining
        .min(limits.untracked_total_remaining)
        .min(limits.bundle_remaining);
    let kind = if limits.single_file_remaining == minimum {
        ConfinedLimitKind::SingleFile
    } else if limits.untracked_total_remaining == minimum {
        ConfinedLimitKind::UntrackedTotal
    } else {
        ConfinedLimitKind::Bundle
    };
    ConfinedReadError::LimitExceeded {
        kind,
        metadata: ConfinedFileMetadata { identity },
    }
}

fn map_open_error(error: rustix::io::Errno) -> ConfinedReadError {
    if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        ConfinedReadError::UnsupportedType
    } else {
        ConfinedReadError::Io
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::Duration;

    fn root() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("evertrace-confined-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&path).expect("create root");
        path
    }

    fn limits(max: u64) -> ConfinedReadLimits {
        ConfinedReadLimits {
            single_file_remaining: max,
            untracked_total_remaining: max,
            bundle_remaining: max,
            deadline: Instant::now() + Duration::from_secs(1),
        }
    }

    #[test]
    fn reads_regular_file_beneath_verified_root() {
        let root = root();
        std::fs::create_dir(root.join("nested")).expect("create nested");
        std::fs::write(root.join("nested/file"), b"recoverable").expect("write");
        let confined = ConfinedRoot::open(&root).expect("open root");
        let read = confined
            .read(Path::new("nested/file"), limits(32))
            .expect("read");
        assert_eq!(read.bytes, b"recoverable");
        assert!(!format!("{read:?}").contains("recoverable"));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn rejects_escape_symlink_and_budget_overrun() {
        let root = root();
        std::fs::write(root.join("large"), b"12345").expect("write");
        symlink("large", root.join("link")).expect("symlink");
        let confined = ConfinedRoot::open(&root).expect("open root");
        assert_eq!(
            confined.read(Path::new("../large"), limits(8)),
            Err(ConfinedReadError::InvalidPath)
        );
        assert_eq!(
            confined.read(Path::new("link"), limits(8)),
            Err(ConfinedReadError::UnsupportedType)
        );
        assert!(matches!(
            confined.read(Path::new("large"), limits(4)),
            Err(ConfinedReadError::LimitExceeded {
                kind: ConfinedLimitKind::SingleFile,
                metadata: ConfinedFileMetadata {
                    identity: ConfinedFileIdentity { size: 5, .. }
                },
            })
        ));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn bounded_listing_is_sorted_and_rejects_overflow_and_symlink() {
        let root = root();
        std::fs::create_dir(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/b"), b"b").unwrap();
        std::fs::write(root.join("nested/a"), b"a").unwrap();
        let confined = ConfinedRoot::open(&root).unwrap();
        let entries = confined
            .list_directory(
                Some(Path::new("nested")),
                2,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert!(matches!(
            confined.list_directory(
                Some(Path::new("nested")),
                1,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(ConfinedReadError::LimitExceeded { .. })
        ));
        symlink("a", root.join("nested/link")).unwrap();
        assert_eq!(
            confined.list_directory(
                Some(Path::new("nested")),
                3,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(ConfinedReadError::UnsupportedType)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn range_read_is_offset_bounded_and_identity_pinned() {
        let root = root();
        std::fs::write(root.join("file"), b"abcdef").unwrap();
        let confined = ConfinedRoot::open(&root).unwrap();
        let identity = confined
            .list_directory(None, 1, Instant::now() + Duration::from_secs(1))
            .unwrap()[0]
            .identity;
        let first = confined
            .read_range(
                Path::new("file"),
                identity,
                0,
                2,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(first.bytes, b"ab");
        assert_eq!(first.next_offset, 2);
        assert!(!first.eof);
        let tail = confined
            .read_range(
                Path::new("file"),
                identity,
                2,
                8,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(tail.bytes, b"cdef");
        assert!(tail.eof);
        assert_eq!(
            confined.read_range(
                Path::new("file"),
                identity,
                0,
                1,
                Instant::now() - Duration::from_millis(1),
            ),
            Err(ConfinedReadError::Deadline)
        );
        std::fs::write(root.join("file"), b"changed").unwrap();
        assert_eq!(
            confined.read_range(
                Path::new("file"),
                identity,
                0,
                2,
                Instant::now() + Duration::from_secs(1),
            ),
            Err(ConfinedReadError::Changed)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expired_deadline_fails_before_read() {
        let root = root();
        std::fs::write(root.join("file"), b"content").expect("write");
        let confined = ConfinedRoot::open(&root).expect("open root");
        let mut expired = limits(32);
        expired.deadline = Instant::now();
        assert_eq!(
            confined.read(Path::new("file"), expired),
            Err(ConfinedReadError::Deadline)
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn equal_limit_is_accepted_and_each_limit_kind_is_preserved() {
        let root = root();
        std::fs::write(root.join("file"), b"1234").expect("write");
        let confined = ConfinedRoot::open(&root).expect("open root");
        assert_eq!(
            confined
                .read(Path::new("file"), limits(4))
                .expect("equal limit")
                .bytes,
            b"1234"
        );
        let mut total = limits(8);
        total.untracked_total_remaining = 3;
        assert!(matches!(
            confined.read(Path::new("file"), total),
            Err(ConfinedReadError::LimitExceeded {
                kind: ConfinedLimitKind::UntrackedTotal,
                ..
            })
        ));
        let mut bundle = limits(8);
        bundle.bundle_remaining = 3;
        assert!(matches!(
            confined.read(Path::new("file"), bundle),
            Err(ConfinedReadError::LimitExceeded {
                kind: ConfinedLimitKind::Bundle,
                ..
            })
        ));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn growing_file_is_not_returned_as_stable() {
        let root = root();
        std::fs::write(root.join("file"), b"1234").expect("write");
        let confined = ConfinedRoot::open(&root).expect("open root");
        let path = root.join("file");
        let result = confined.read_with_hook(Path::new("file"), limits(8), || {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .expect("open append")
                .write_all(b"5")
                .expect("append");
        });
        assert_eq!(result, Err(ConfinedReadError::Changed));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn rejects_intermediate_and_final_symlinks_as_unsupported_types() {
        let root = root();
        std::fs::create_dir(root.join("real")).expect("create real");
        std::fs::write(root.join("real/file"), b"content").expect("write");
        symlink("real", root.join("alias")).expect("intermediate symlink");
        symlink("real/file", root.join("leaf")).expect("final symlink");
        let confined = ConfinedRoot::open(&root).expect("open root");
        assert_eq!(
            confined.read(Path::new("alias/file"), limits(32)),
            Err(ConfinedReadError::UnsupportedType)
        );
        assert_eq!(
            confined.read(Path::new("leaf"), limits(32)),
            Err(ConfinedReadError::UnsupportedType)
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn detects_root_locator_replacement() {
        let root = root();
        std::fs::write(root.join("file"), b"content").expect("write");
        let confined = ConfinedRoot::open(&root).expect("open root");
        let displaced = root.with_extension("displaced");
        std::fs::rename(&root, &displaced).expect("rename root");
        std::fs::create_dir(&root).expect("replacement root");
        assert_eq!(
            confined.read(Path::new("file"), limits(32)),
            Err(ConfinedReadError::Changed)
        );
        std::fs::remove_dir_all(root).expect("cleanup replacement");
        std::fs::remove_dir_all(displaced).expect("cleanup original");
    }

    #[test]
    fn external_source_rechecks_private_ancestor_and_public_readonly_descendants() {
        use std::os::unix::fs::PermissionsExt;
        let outer = root();
        let source = outer.join("sessions");
        let middle = source.join("dated");
        std::fs::create_dir_all(&middle).unwrap();
        std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o700)).unwrap();
        for path in [&source, &middle] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let leaf = middle.join("file");
        std::fs::write(&leaf, b"content").unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644)).unwrap();
        let confined = ConfinedRoot::open_external_source(&source).unwrap();
        let file = confined.read(Path::new("dated/file"), limits(32)).unwrap();
        assert!(
            confined
                .revalidate_file(Path::new("dated/file"), file.identity)
                .is_ok()
        );
        assert!(confined.open_regular_file(Path::new("dated/file")).is_ok());
        assert!(
            confined
                .list_directory(Some(Path::new("dated")), 4, limits(32).deadline)
                .is_ok()
        );
        assert!(
            confined
                .read_range(
                    Path::new("dated/file"),
                    file.identity,
                    0,
                    4,
                    limits(32).deadline
                )
                .is_ok()
        );
        assert!(
            confined
                .read_after_owned_mutation(Path::new("dated/file"), limits(32))
                .is_err()
        );
        // Loss of the only private boundary is caught after actual IO, too.
        assert!(
            confined
                .read_with_hook(Path::new("dated/file"), limits(32), || {
                    std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                })
                .is_err()
        );
        assert!(ConfinedRoot::open_external_source(&source).is_err());
        std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(confined.revalidate_stable().is_ok());
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            ConfinedRoot::open_external_source(&source)
                .unwrap()
                .read(Path::new("dated/file"), limits(32))
                .is_ok()
        );
        std::fs::set_permissions(&middle, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(confined.open_regular_file(Path::new("dated/file")).is_err());
        assert!(
            confined
                .list_directory(Some(Path::new("dated")), 4, limits(32).deadline)
                .is_err()
        );
        std::fs::set_permissions(&middle, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            confined
                .revalidate_file(Path::new("dated/file"), file.identity)
                .is_err()
        );
        assert!(confined.read(Path::new("dated/file"), limits(32)).is_err());
        assert!(confined.open_regular_file(Path::new("dated/file")).is_err());
        assert!(
            confined
                .read_range(
                    Path::new("dated/file"),
                    file.identity,
                    0,
                    4,
                    limits(32).deadline
                )
                .is_err()
        );
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644)).unwrap();
        let fresh = confined.read(Path::new("dated/file"), limits(32)).unwrap();
        std::fs::rename(&leaf, middle.join("old")).unwrap();
        std::fs::write(&leaf, b"content").unwrap();
        assert!(
            confined
                .read_range(
                    Path::new("dated/file"),
                    fresh.identity,
                    0,
                    4,
                    limits(32).deadline
                )
                .is_err()
        );
        std::fs::remove_file(&leaf).unwrap();
        symlink("old", &leaf).unwrap();
        assert!(confined.read(Path::new("dated/file"), limits(32)).is_err());
        symlink("dated", source.join("alias")).unwrap();
        assert!(confined.open_regular_file(Path::new("alias/old")).is_err());
        std::fs::remove_dir_all(outer).unwrap();
    }

    #[test]
    fn external_source_rejects_unprotected_writable_ancestor_above_private_boundary() {
        use std::os::unix::fs::PermissionsExt;
        let outer = root();
        let private = outer.join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ConfinedRoot::open_external_source(&private).is_err());
        // Original recovery entry has not acquired this external-source policy.
        assert!(ConfinedRoot::open_owned_private(&private).is_ok());
        std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let confined = ConfinedRoot::open_external_source(&private).unwrap();
        std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(confined.revalidate_stable().is_err());
        std::fs::remove_dir_all(outer).unwrap();
    }

    #[test]
    fn owned_private_root_preserves_the_absolute_nofollow_locator_identity() {
        use std::os::unix::fs::PermissionsExt;

        let root = root();
        let confined = ConfinedRoot::open_owned_private(&root).expect("open owned private root");
        let displaced = root.with_extension("owned-displaced");
        std::fs::rename(&root, &displaced).expect("displace root");
        std::fs::create_dir(&root).expect("replacement root");
        assert_eq!(
            confined.revalidate_stable(),
            Err(ConfinedReadError::Changed)
        );

        let symlink_root = root.with_extension("owned-symlink");
        symlink(&root, &symlink_root).expect("root symlink");
        assert!(ConfinedRoot::open_owned_private(&symlink_root).is_err());
        assert_eq!(
            ConfinedRoot::open_owned_private(Path::new("relative-root")).err(),
            Some(ConfinedReadError::InvalidPath)
        );

        let public_root = root.with_extension("owned-public");
        std::fs::create_dir(&public_root).expect("public root");
        std::fs::set_permissions(&public_root, std::fs::Permissions::from_mode(0o770))
            .expect("public permissions");
        assert_eq!(
            ConfinedRoot::open_owned_private(&public_root).err(),
            Some(ConfinedReadError::UnsupportedType)
        );

        std::fs::remove_file(symlink_root).expect("cleanup symlink");
        std::fs::remove_dir_all(public_root).expect("cleanup public root");
        std::fs::remove_dir_all(root).expect("cleanup replacement");
        std::fs::remove_dir_all(displaced).expect("cleanup original");
    }

    #[test]
    fn owned_private_root_rejects_symlinked_or_replaced_ancestor() {
        let outer = root();
        let real_parent = outer.join("real");
        std::fs::create_dir(&real_parent).unwrap();
        let child = real_parent.join("sessions");
        std::fs::create_dir(&child).unwrap();
        let alias = outer.join("alias");
        symlink(&real_parent, &alias).unwrap();
        assert!(ConfinedRoot::open_owned_private(&alias.join("sessions")).is_err());

        let confined = ConfinedRoot::open_owned_private(&child).unwrap();
        let displaced = outer.join("displaced");
        std::fs::rename(&real_parent, &displaced).unwrap();
        std::fs::create_dir(&real_parent).unwrap();
        std::fs::create_dir(real_parent.join("sessions")).unwrap();
        assert_eq!(
            confined.revalidate_stable(),
            Err(ConfinedReadError::Changed)
        );
        std::fs::remove_dir_all(outer).unwrap();
    }

    #[test]
    fn detects_final_entry_replacement_and_type_change() {
        let root = root();
        std::fs::write(root.join("file"), b"content").expect("write");
        let confined = ConfinedRoot::open(&root).expect("open root");
        let result = confined.read_with_hook(Path::new("file"), limits(32), || {
            std::fs::rename(root.join("file"), root.join("old")).expect("move file");
            std::fs::create_dir(root.join("file")).expect("replace with directory");
        });
        assert_eq!(result, Err(ConfinedReadError::Changed));
        std::fs::remove_dir_all(root).expect("cleanup");
    }
}
