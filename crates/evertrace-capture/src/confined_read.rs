//! Root-confined, no-follow reads for bounded capture inputs.

use std::ffi::OsStr;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags, Stat, fstat, open, openat, statat};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfinedReadLimits {
    pub single_file_remaining: u64,
    pub untracked_total_remaining: u64,
    pub bundle_remaining: u64,
    pub deadline: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
}

impl ConfinedRoot {
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
        })
    }

    /// Opens a recovery mutation root only when the locator itself is a
    /// directory (not a symlink), is owned by the daemon user, and is not
    /// writable by group or other users. The returned descriptor remains the
    /// authority for all subsequent child cwd and probe operations.
    pub fn open_owned_private(root: &Path) -> Result<Self, ConfinedReadError> {
        if !root.is_absolute() {
            return Err(ConfinedReadError::InvalidPath);
        }
        let fd = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ConfinedReadError::Io)?;
        let opened = fstat(&fd).map_err(|_| ConfinedReadError::Io)?;
        let entry =
            statat(CWD, root, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ConfinedReadError::Io)?;
        let process_fd = open(
            "/proc/self",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ConfinedReadError::Io)?;
        let process = fstat(&process_fd).map_err(|_| ConfinedReadError::Io)?;
        if FileType::from_raw_mode(opened.st_mode) != FileType::Directory
            || FileType::from_raw_mode(entry.st_mode) != FileType::Directory
            || opened.st_dev != entry.st_dev
            || opened.st_ino != entry.st_ino
            || opened.st_uid != entry.st_uid
            || opened.st_mode != entry.st_mode
            || opened.st_uid != process.st_uid
            || entry.st_uid != process.st_uid
            || opened.st_mode & 0o022 != 0
            || entry.st_mode & 0o022 != 0
        {
            return Err(ConfinedReadError::UnsupportedType);
        }
        Ok(Self {
            fd,
            locator: root.to_path_buf(),
            identity: identity(&opened)?,
            owner: opened.st_uid,
            mode: opened.st_mode,
        })
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
        self.read_impl(relative, limits, false, || {})
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
        let current = statat(CWD, &self.locator, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ConfinedReadError::Io)?;
        let opened = fstat(&self.fd).map_err(|_| ConfinedReadError::Io)?;
        if !self.matches_original_root(&current)? || !self.matches_original_root(&opened)? {
            return Err(ConfinedReadError::Changed);
        }
        Ok(())
    }

    pub fn revalidate_stable(&self) -> Result<(), ConfinedReadError> {
        let current = statat(CWD, &self.locator, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ConfinedReadError::Io)?;
        let opened = fstat(&self.fd).map_err(|_| ConfinedReadError::Io)?;
        if !self.matches_root(&current)? || !self.matches_root(&opened)? {
            return Err(ConfinedReadError::Changed);
        }
        Ok(())
    }

    fn matches_original_root(&self, stat: &Stat) -> Result<bool, ConfinedReadError> {
        Ok(self.matches_root(stat)? && identity(stat)? == self.identity)
    }

    fn matches_root(&self, stat: &Stat) -> Result<bool, ConfinedReadError> {
        let current = identity(stat)?;
        Ok(FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            && current.device == self.identity.device
            && current.inode == self.identity.inode
            && stat.st_uid == self.owner
            && stat.st_mode == self.mode)
    }
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
