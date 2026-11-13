//! Bounded native measurement for the fixed recorder's isolated Python execution.
//! The result is the Run environment identity, not a second image registry or manifest.

use std::{
    collections::BTreeMap,
    fs::{self, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use super::{Header, ProcessIdentity, ProcessSourceError, Result};

const MAX_FILES: usize = 8192;
const MAX_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Eq, PartialEq)]
struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn stamp(value: &Metadata) -> Result<Stamp> {
    // This is a stable observation of executable bytes, not a filesystem read-only claim.
    if !value.is_file() {
        return Err(ProcessSourceError);
    }
    Ok(Stamp {
        device: value.dev(),
        inode: value.ino(),
        length: value.len(),
        modified: (value.mtime(), value.mtime_nsec()),
        changed: (value.ctime(), value.ctime_nsec()),
    })
}

fn empty_cache(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(value) if value.is_dir() => {
            if fs::read_dir(path)
                .map_err(|_| ProcessSourceError)?
                .next()
                .is_none()
            {
                Ok(())
            } else {
                Err(ProcessSourceError)
            }
        }
        _ => Err(ProcessSourceError),
    }
}

/// Close the fixed source profile's import namespace, including ignored Python bytecode.
/// Git/tree validation still belongs to the repository and Run contract owners.
pub(super) fn verify_source_namespace(script: &Path) -> Result<()> {
    let root = script.parent().ok_or(ProcessSourceError)?;
    // External-format paths, not an internal domain registry or a second file manifest.
    let expected = [
        "raven/__init__.py",
        "raven/evolver/__init__.py",
        "raven/evolver/analysis/__init__.py",
        "raven/evolver/analysis/stability_bucket.py",
        "raven/evolver/orchestrator/__init__.py",
        "raven/evolver/orchestrator/scoring.py",
        "raven/evolver/scheduler/__init__.py",
        "raven/evolver/scheduler/anchor_selection.py",
    ];
    let deadline = Instant::now() + Duration::from_millis(40);
    let mut pending = vec![root.join("raven")];
    let mut seen = std::collections::BTreeSet::new();
    let mut entries = 0;
    while let Some(directory) = pending.pop() {
        if Instant::now() >= deadline
            || !fs::symlink_metadata(&directory).is_ok_and(|value| value.is_dir())
        {
            return Err(ProcessSourceError);
        }
        for entry in fs::read_dir(&directory).map_err(|_| ProcessSourceError)? {
            entries += 1;
            if entries > 64 || Instant::now() >= deadline {
                return Err(ProcessSourceError);
            }
            let entry = entry.map_err(|_| ProcessSourceError)?;
            let path = entry.path();
            let relative = path.strip_prefix(root).map_err(|_| ProcessSourceError)?;
            let name = relative.to_str().ok_or(ProcessSourceError)?;
            let kind = entry.file_type().map_err(|_| ProcessSourceError)?;
            if kind.is_dir() && entry.file_name() == "__pycache__" {
                empty_cache(&path)?;
            } else if kind.is_dir()
                && expected
                    .iter()
                    .any(|value| Path::new(value).starts_with(relative))
            {
                pending.push(path);
            } else if kind.is_file() && expected.contains(&name) {
                seen.insert(name.to_owned());
            } else {
                return Err(ProcessSourceError);
            }
        }
    }
    if seen.len() != expected.len()
        || !fs::symlink_metadata(root.join("fixed_scorer.py")).is_ok_and(|value| value.is_file())
    {
        return Err(ProcessSourceError);
    }
    empty_cache(&root.join("__pycache__"))
}

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn add(files: &mut BTreeMap<PathBuf, Stamp>, path: &Path, deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline || files.len() >= MAX_FILES {
        return Err(ProcessSourceError);
    }
    let path = fs::canonicalize(path).map_err(|_| ProcessSourceError)?;
    let metadata = fs::symlink_metadata(&path).map_err(|_| ProcessSourceError)?;
    let value = stamp(&metadata)?;
    files.insert(path, value);
    Ok(())
}

fn add_directory_files(
    files: &mut BTreeMap<PathBuf, Stamp>,
    directory: &Path,
    prefix: &Path,
    excluded: &Path,
    deadline: Instant,
) -> Result<()> {
    let mut pending = vec![directory.to_owned()];
    let mut visited = 0;
    while let Some(directory) = pending.pop() {
        if Instant::now() >= deadline || visited >= MAX_FILES {
            return Err(ProcessSourceError);
        }
        for entry in fs::read_dir(&directory).map_err(|_| ProcessSourceError)? {
            visited += 1;
            if Instant::now() >= deadline || visited >= MAX_FILES {
                return Err(ProcessSourceError);
            }
            let entry = entry.map_err(|_| ProcessSourceError)?;
            let path = entry.path();
            // Only the five actual distributions below belong to this source profile.
            if path == excluded {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).map_err(|_| ProcessSourceError)?;
            if metadata.is_dir() {
                pending.push(path);
            } else {
                let canonical = fs::canonicalize(&path).map_err(|_| ProcessSourceError)?;
                if !canonical.starts_with(prefix) {
                    return Err(ProcessSourceError);
                }
                add(files, &canonical, deadline)?;
            }
        }
    }
    Ok(())
}

fn files(
    header: &Header,
    conditions: &serde_json::Value,
    prefix: &Path,
    purelib: &Path,
    deadline: Instant,
    package_namespace: bool,
) -> Result<BTreeMap<PathBuf, Stamp>> {
    let process = header.process.as_ref().ok_or(ProcessSourceError)?;
    let mut files = BTreeMap::new();
    let executable = PathBuf::from(format!("/proc/{}/exe", process.pid));
    add(&mut files, &executable, deadline)?;
    add_directory_files(
        &mut files,
        purelib.parent().ok_or(ProcessSourceError)?,
        prefix,
        purelib,
        deadline,
    )?;
    let packages = conditions["packages"]
        .as_array()
        .ok_or(ProcessSourceError)?;
    let mut names = std::collections::BTreeSet::new();
    let mut roots = std::collections::BTreeSet::new();
    for package in packages {
        let name = package["name"].as_str().ok_or(ProcessSourceError)?;
        names.insert(name);
        let record = package["record"].as_str().ok_or(ProcessSourceError)?;
        if record.is_empty() || record.contains(['"', '\r']) {
            return Err(ProcessSourceError);
        }
        for line in record.lines() {
            // This profile's original records have unquoted three-column paths.
            // Other CSV forms remain unsupported, never silently misparsed.
            let fields = line.split(',').collect::<Vec<_>>();
            if fields.len() != 3 || fields[0].is_empty() || Path::new(fields[0]).is_absolute() {
                return Err(ProcessSourceError);
            }
            if package_namespace
                && let Some(std::path::Component::Normal(root)) =
                    Path::new(fields[0]).components().next()
            {
                let path = purelib.join(root);
                if fs::symlink_metadata(&path)
                    .map_err(|_| ProcessSourceError)?
                    .is_dir()
                {
                    roots.insert(path);
                }
            }
            let path = fs::canonicalize(purelib.join(fields[0])).map_err(|_| ProcessSourceError)?;
            if !path.starts_with(prefix) {
                return Err(ProcessSourceError);
            }
            add(&mut files, &path, deadline)?;
        }
    }
    if packages.len() != 5
        || names
            != std::collections::BTreeSet::from([
                "pytest",
                "pluggy",
                "iniconfig",
                "packaging",
                "Pygments",
            ])
    {
        return Err(ProcessSourceError);
    }
    // RECORD is not a namespace boundary: unlisted cache/extension/module bytes can execute too.
    for root in roots {
        add_directory_files(&mut files, &root, prefix, purelib, deadline)?;
    }
    // These are kernel-selected mapped files, not caller-supplied library locators.
    let maps = super::text(Path::new(&format!("/proc/{}/maps", process.pid)))?;
    for line in maps.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() >= 6 && fields[5].starts_with('/') {
            if fields.len() != 6 {
                return Err(ProcessSourceError);
            }
            let (major, minor) = fields[3].split_once(':').ok_or(ProcessSourceError)?;
            let device = rustix::fs::makedev(
                u32::from_str_radix(major, 16).map_err(|_| ProcessSourceError)?,
                u32::from_str_radix(minor, 16).map_err(|_| ProcessSourceError)?,
            );
            let inode = fields[4].parse::<u64>().map_err(|_| ProcessSourceError)?;
            let metadata = fs::metadata(fields[5]).map_err(|_| ProcessSourceError)?;
            if metadata.dev() != device || metadata.ino() != inode {
                return Err(ProcessSourceError);
            }
            add(&mut files, Path::new(fields[5]), deadline)?;
        }
    }
    Ok(files)
}

/// Measure while the source holds its exact live child; no cached or declared file hash is adopted.
pub(super) fn fingerprint(
    header: &Header,
    conditions: &[u8],
    package_namespace: bool,
) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let conditions: serde_json::Value =
        serde_json::from_slice(conditions).map_err(|_| ProcessSourceError)?;
    let config = header.config.as_ref().ok_or(ProcessSourceError)?;
    let purelib = fs::canonicalize(config["purelib"].as_str().ok_or(ProcessSourceError)?)
        .map_err(|_| ProcessSourceError)?;
    let process = header.process.as_ref().ok_or(ProcessSourceError)?;
    let executable =
        fs::canonicalize(format!("/proc/{}/exe", process.pid)).map_err(|_| ProcessSourceError)?;
    let prefix = executable
        .parent()
        .and_then(Path::parent)
        .ok_or(ProcessSourceError)?;
    let measured: ProcessIdentity =
        serde_json::from_value(conditions["process"].clone()).map_err(|_| ProcessSourceError)?;
    if !purelib.starts_with(prefix) || measured != *process {
        return Err(ProcessSourceError);
    }
    let before = files(
        header,
        &conditions,
        prefix,
        &purelib,
        deadline,
        package_namespace,
    )?;
    let mut hash = Sha256::new();
    field(&mut hash, b"evertrace.native_execution_environment.v1");
    for name in ["python", "framework", "environment", "packages"] {
        field(&mut hash, name.as_bytes());
        field(
            &mut hash,
            &serde_json::to_vec(&conditions[name]).map_err(|_| ProcessSourceError)?,
        );
    }
    let mut total = 0u64;
    let mut buffer = [0u8; 65536];
    for (path, expected) in &before {
        if Instant::now() >= deadline {
            return Err(ProcessSourceError);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(|_| ProcessSourceError)?;
        if stamp(&file.metadata().map_err(|_| ProcessSourceError)?)? != *expected {
            return Err(ProcessSourceError);
        }
        let label = if let Ok(relative) = path.strip_prefix(prefix) {
            format!("python/{}", relative.to_str().ok_or(ProcessSourceError)?)
        } else {
            format!("system{}", path.to_str().ok_or(ProcessSourceError)?)
        };
        field(&mut hash, label.as_bytes());
        hash.update(expected.length.to_be_bytes());
        let mut length = 0u64;
        loop {
            if Instant::now() >= deadline {
                return Err(ProcessSourceError);
            }
            let count = file.read(&mut buffer).map_err(|_| ProcessSourceError)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .filter(|value| *value <= MAX_BYTES)
                .ok_or(ProcessSourceError)?;
            length += count as u64;
            hash.update(&buffer[..count]);
        }
        if length != expected.length
            || stamp(&file.metadata().map_err(|_| ProcessSourceError)?)? != *expected
        {
            return Err(ProcessSourceError);
        }
    }
    if files(
        header,
        &conditions,
        prefix,
        &purelib,
        deadline,
        package_namespace,
    )? != before
    {
        return Err(ProcessSourceError);
    }
    Ok(format!("measured-runtime-v1:{:x}", hash.finalize()))
}
