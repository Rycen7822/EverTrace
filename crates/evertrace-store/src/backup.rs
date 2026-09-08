use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use evertrace_capture::{
    CasStore, RuntimeSnapshot, SpoolBackupBoundary, SpoolBackupFileKind, copy_exact_sha256_hex,
    open_regular_nofollow, verify_backup_spool_file,
};
use evertrace_domain::{
    config::EffectiveConfig,
    evidence::{SourceInstanceId, SourceRevision},
    ids::JobId,
};
use serde::{Deserialize, Serialize};

use crate::{
    JournalPayload, ObjectDeletionCurrentView, ProjectionSnapshot, RuntimeSchedulerView,
    ScopePurgeCurrentView, StoreError, command::WatermarkKind,
};

pub const QUIESCED_BACKUP_CREATE_JOB_KIND: &str = "quiesced_backup_create_v1";
pub const QUIESCED_BACKUP_VERIFY_JOB_KIND: &str = "quiesced_backup_verify_v1";
pub const QUIESCED_BACKUP_ALGORITHM_REVISION: &str = "quiesced_backup_v1";
const MANIFEST_NAME: &str = "manifest.json";
const MANIFEST_VERSION: u16 = 2;
const MAX_BACKUP_FILES: usize = 100_000;
const MAX_BACKUP_DEPTH: usize = 256;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_AUXILIARY_FILE_BYTES: u64 = 1024 * 1024;
const COPY_SPACE_RESERVE: u64 = MAX_MANIFEST_BYTES + 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupFileKind {
    Directory,
    Regular,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupFileManifest {
    pub relative_path: String,
    pub kind: BackupFileKind,
    pub size: u64,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupTableState {
    pub version: u64,
    pub checkpoint: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupTableStates {
    pub journal: BackupTableState,
    pub objects: BackupTableState,
    pub relations: Option<BackupTableState>,
    pub search: Option<BackupTableState>,
}

impl BackupTableStates {
    fn profile(&self) -> Result<&'static str, BackupError> {
        match (&self.relations, &self.search) {
            (None, None) => Ok("L0001"),
            (Some(_), Some(_)) => Ok("L0002"),
            _ => Err(BackupError::Corrupt),
        }
    }

    fn validate(&self, frontier: u64) -> bool {
        self.profile().is_ok()
            && self.journal.version > 0
            && self.journal.checkpoint == frontier
            && self.objects.version > 0
            && self.objects.checkpoint == frontier
            && [&self.relations, &self.search]
                .into_iter()
                .flatten()
                .all(|table| table.version > 0 && table.checkpoint <= frontier)
    }

    fn table_names(&self) -> Result<Vec<&'static str>, BackupError> {
        let mut names = vec![crate::JOURNAL_TABLE, crate::OBJECTS_TABLE];
        if self.profile()? == "L0002" {
            names.extend([crate::RELATIONS_TABLE, crate::SEARCH_TABLE]);
        }
        Ok(names)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupFrozenFile {
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
pub struct BackupHookBoundary {
    pub current_generation: Option<u64>,
    pub retained_generations: Vec<u64>,
    pub pin_count: u32,
    pub pinned_generation_count: u32,
    pub files: Vec<BackupFrozenFile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupFrozenBoundary {
    pub spool: SpoolBackupBoundary,
    pub hook: BackupHookBoundary,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSourceWatermark {
    pub source_instance_id: SourceInstanceId,
    pub source_revision: SourceRevision,
    pub source_sequence: u64,
    pub confirmed_prefix_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSpoolSourceWatermark {
    pub source_instance_id: SourceInstanceId,
    pub source_revision: SourceRevision,
    pub source_sequence: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupSpoolFileKind {
    Normal,
    Isolated,
    EmergencyGap,
    Quarantine,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSpoolFileBoundary {
    pub relative_path: String,
    pub kind: BackupSpoolFileKind,
    pub frame_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub manifest_version: u16,
    pub backup_job_id: JobId,
    pub frontier: u64,
    pub table_states: BackupTableStates,
    pub committed_source_watermarks: Vec<BackupSourceWatermark>,
    pub spool_source_watermarks: Vec<BackupSpoolSourceWatermark>,
    pub live_cas_refs: Vec<String>,
    pub spool_cas_refs: Vec<String>,
    pub spool_files: Vec<BackupSpoolFileBoundary>,
    pub spool_generations: Vec<u64>,
    pub normal_spool_frame_count: u32,
    pub isolated_spool_frame_count: u32,
    pub emergency_gap_count: u32,
    pub quarantine_count: u32,
    pub runtime_outbox_watermark: u64,
    pub index_generation: u64,
    pub compiler_watermark: u64,
    pub effective_config_hash: [u8; 32],
    pub runtime_generation: u64,
    pub hook_current_generation: Option<u64>,
    pub hook_retained_generations: Vec<u64>,
    pub hook_pin_count: u32,
    pub session_pinned_hook_artifact_count: u32,
    pub schema_revision: String,
    pub backup_algorithm_revision: String,
    pub object_deletion_generation: u64,
    pub repository_purge_generation: u64,
    pub required_space_bytes: u64,
    pub available_space_bytes_at_preflight: u64,
    pub files: Vec<BackupFileManifest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSummary {
    pub backup_job_id: JobId,
    pub frontier: u64,
    pub table_states: BackupTableStates,
    pub committed_source_watermark_count: u32,
    pub spool_source_watermark_count: u32,
    pub live_cas_count: u32,
    pub spool_cas_count: u32,
    pub spool_file_count: u32,
    pub spool_generation_count: u32,
    pub normal_spool_frame_count: u32,
    pub isolated_spool_frame_count: u32,
    pub emergency_gap_count: u32,
    pub quarantine_count: u32,
    pub runtime_outbox_watermark: u64,
    pub index_generation: u64,
    pub compiler_watermark: u64,
    pub effective_config_hash: [u8; 32],
    pub runtime_generation: u64,
    pub hook_current_generation: Option<u64>,
    pub hook_retained_generations: Vec<u64>,
    pub hook_pin_count: u32,
    pub session_pinned_hook_artifact_count: u32,
    pub object_deletion_generation: u64,
    pub repository_purge_generation: u64,
    pub file_count: u32,
    pub total_bytes: u64,
    pub required_space_bytes: u64,
    pub available_space_bytes_at_preflight: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BackupError {
    #[error("backup input is invalid")]
    InvalidInput,
    #[error("backup source changed during snapshot")]
    IdentityChanged,
    #[error("backup content is corrupt")]
    Corrupt,
    #[error("backup resource boundary was exceeded")]
    ResourceExhausted,
    #[error("backup filesystem operation failed")]
    Io,
}

#[derive(Debug)]
pub(crate) struct BackupPlan {
    data_dir: PathBuf,
    backup_dir: PathBuf,
    staging_dir: PathBuf,
    manifest: BackupManifest,
    sources: Vec<PlannedSource>,
    source_directories: Vec<PlannedDirectory>,
    backup_runtime: RuntimeSnapshot,
}

impl BackupPlan {
    /// Upgrade retains its preflight backup and one native-only candidate.
    pub(crate) fn check_upgrade_space(&self) -> Result<(), BackupError> {
        let native_bytes = self
            .manifest
            .files
            .iter()
            .filter(|entry| Path::new(&entry.relative_path).starts_with("store"))
            .try_fold(0u64, |total, entry| total.checked_add(entry.size))
            .ok_or(BackupError::ResourceExhausted)?;
        let needed = self
            .manifest
            .files
            .iter()
            .try_fold(native_bytes, |total, entry| total.checked_add(entry.size))
            .and_then(|total| total.checked_add(COPY_SPACE_RESERVE))
            .ok_or(BackupError::ResourceExhausted)?;
        if fs2::available_space(&self.data_dir).map_err(|_| BackupError::Io)? < needed {
            return Err(BackupError::ResourceExhausted);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct BackupStaging {
    backup_dir: PathBuf,
    staging_dir: PathBuf,
    backup_job_id: JobId,
    staging_identity: FileIdentity,
    verification: BackupVerification,
}

#[derive(Debug)]
pub struct BackupVerification {
    directory: PathBuf,
    manifest: BackupManifest,
    summary: BackupSummary,
    root_identity: FileIdentity,
    input_identities: Vec<(PathBuf, bool, FileIdentity)>,
}

impl BackupVerification {
    pub(crate) fn files(&self) -> &[BackupFileManifest] {
        &self.manifest.files
    }

    pub(crate) fn revalidate_gc_inputs(
        &self,
        deadline: std::time::Instant,
        remaining: &mut usize,
    ) -> Result<(), BackupError> {
        if private_directory_identity(&self.directory)? != self.root_identity {
            return Err(BackupError::IdentityChanged);
        }
        for (relative, directory, expected) in &self.input_identities {
            if *remaining == 0 || std::time::Instant::now() >= deadline {
                return Err(BackupError::ResourceExhausted);
            }
            *remaining -= 1;
            let path = self.directory.join(relative);
            let actual = if *directory {
                private_directory_identity(&path)?
            } else {
                private_file_identity(&path)?
            };
            if actual != *expected {
                return Err(BackupError::IdentityChanged);
            }
        }
        Ok(())
    }

    pub(crate) fn cas_refs_intersect(&self, candidates: &BTreeSet<String>) -> BTreeSet<String> {
        self.manifest
            .live_cas_refs
            .iter()
            .chain(&self.manifest.spool_cas_refs)
            .filter(|value| candidates.contains(*value))
            .cloned()
            .collect()
    }
}

impl BackupStaging {
    pub fn directory(&self) -> &Path {
        &self.staging_dir
    }
}

#[derive(Debug)]
struct PlannedDirectory {
    path: PathBuf,
    identity: FileIdentity,
}

#[derive(Debug)]
struct PlannedSource {
    hook_directories: Vec<(PathBuf, u64, u64)>,
    source: PathBuf,
    relative: PathBuf,
    kind: BackupFileKind,
    identity: FileIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

struct BoundedCountWriter {
    written: u64,
    limit: u64,
}

impl Write for BoundedCountWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next = self
            .written
            .checked_add(u64::try_from(buffer.len()).map_err(|_| io::Error::other("overflow"))?)
            .ok_or_else(|| io::Error::other("overflow"))?;
        if next > self.limit {
            return Err(io::Error::other("limit"));
        }
        self.written = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn prepare_backup(
    roots: (&Path, &Path),
    config_path: &Path,
    expected_runtime: &RuntimeSnapshot,
    backup_job_id: JobId,
    snapshot: &ProjectionSnapshot,
    table_states: BackupTableStates,
    boundary: BackupFrozenBoundary,
) -> Result<BackupPlan, BackupError> {
    let (data_dir, native_dir) = roots;
    let BackupFrozenBoundary { spool, hook } = boundary;
    expected_runtime
        .validate()
        .map_err(|_| BackupError::InvalidInput)?;
    if expected_runtime
        .data_dir()
        .map_err(|_| BackupError::InvalidInput)?
        != data_dir
        || expected_runtime.effective_config_hash == [0; 32]
        || snapshot.frontier == 0
        || !table_states.validate(snapshot.frontier)
    {
        return Err(BackupError::InvalidInput);
    }
    validate_hook_boundary(&hook)?;
    validate_private_directory(data_dir)?;
    let backups_dir = data_dir.join("backups");
    ensure_private_directory(&backups_dir)?;
    let backup_dir = backups_dir.join(format!("backup-{backup_job_id}"));
    let staging_dir = backups_dir.join(format!(".staging-{backup_job_id}"));
    remove_owned_staging(&staging_dir)?;

    let mut sources = Vec::new();
    for table in table_states.table_names()? {
        collect_tree(
            &native_dir.join(format!("{table}.lance")),
            &PathBuf::from("store").join(format!("{table}.lance")),
            &mut sources,
        )?;
    }

    let live_cas = snapshot.live_cas_refs().map_err(map_store)?;
    let mut backup_cas = live_cas.clone();
    backup_cas.extend(spool.cas_refs.iter().cloned());
    let cas = CasStore::open(expected_runtime.cas_dir.clone()).map_err(|_| BackupError::Corrupt)?;
    for value in &backup_cas {
        let digest = CasStore::parse_digest(value).map_err(|_| BackupError::Corrupt)?;
        cas.verify_envelope(&digest)
            .map_err(|_| BackupError::Corrupt)?;
        let source = cas.blob_path(&digest);
        let relative = source
            .strip_prefix(data_dir)
            .map_err(|_| BackupError::InvalidInput)?
            .to_owned();
        push_source(&source, &relative, BackupFileKind::Regular, &mut sources)?;
    }
    for file in &spool.files {
        push_frozen_source(
            &expected_runtime.spool_dir.join(&file.relative_path),
            &PathBuf::from("spool").join(&file.relative_path),
            FileIdentity {
                device: file.device,
                inode: file.inode,
                size: file.length,
                modified_seconds: file.modified_seconds,
                modified_nanoseconds: file.modified_nanoseconds,
                changed_seconds: file.changed_seconds,
                changed_nanoseconds: file.changed_nanoseconds,
            },
            &mut sources,
        )?;
    }
    push_source(
        config_path,
        Path::new("config/config.toml"),
        BackupFileKind::Regular,
        &mut sources,
    )?;
    let maintenance = data_dir.join("maintenance");
    if maintenance.try_exists().map_err(|_| BackupError::Io)? {
        let root = evertrace_capture::ConfinedRoot::open_owned_private(&maintenance)
            .map_err(|_| BackupError::Corrupt)?;
        let entries = root
            .list_directory(
                None,
                1024,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            )
            .map_err(|_| BackupError::ResourceExhausted)?;
        for entry in entries {
            if entry.name.starts_with('.') {
                continue;
            }
            let id = entry
                .name
                .strip_prefix("gc-")
                .and_then(|name| name.strip_suffix(".json"))
                .ok_or(BackupError::Corrupt)?
                .parse()
                .map_err(|_| BackupError::Corrupt)?;
            crate::optimize::read_gc_report(data_dir, id).map_err(map_store)?;
            push_source(
                &maintenance.join(&entry.name),
                &PathBuf::from("maintenance").join(&entry.name),
                BackupFileKind::Regular,
                &mut sources,
            )?;
        }
    }
    for file in &hook.files {
        if file
            .source
            .strip_prefix(data_dir)
            .ok()
            .is_none_or(|relative| relative != file.relative_path)
        {
            return Err(BackupError::InvalidInput);
        }
        push_frozen_source(
            &file.source,
            &file.relative_path,
            FileIdentity {
                device: file.device,
                inode: file.inode,
                size: file.length,
                modified_seconds: file.modified_seconds,
                modified_nanoseconds: file.modified_nanoseconds,
                changed_seconds: file.changed_seconds,
                changed_nanoseconds: file.changed_nanoseconds,
            },
            &mut sources,
        )?;
        let source = sources.last_mut().ok_or(BackupError::Corrupt)?;
        source.hook_directories = file.directories.clone();
        if source.hook_directories.len() != source.relative.components().count() {
            return Err(BackupError::InvalidInput);
        }
        revalidate_source(source)?;
    }
    let runtime_path = RuntimeSnapshot::snapshot_path(data_dir);
    let current_runtime = RuntimeSnapshot::load(&runtime_path).map_err(|_| BackupError::Corrupt)?;
    if current_runtime.generation != expected_runtime.generation
        || current_runtime.effective_config_hash != expected_runtime.effective_config_hash
        || current_runtime
            .data_dir()
            .map_err(|_| BackupError::Corrupt)?
            != data_dir
    {
        return Err(BackupError::Corrupt);
    }
    let runtime_identity = private_file_identity(&runtime_path)?;
    if runtime_identity.size > MAX_AUXILIARY_FILE_BYTES
        || sources
            .iter()
            .find(|source| source.relative == Path::new("config/config.toml"))
            .is_none_or(|source| source.identity.size > MAX_AUXILIARY_FILE_BYTES)
    {
        return Err(BackupError::ResourceExhausted);
    }
    let backup_runtime = current_runtime
        .sanitized_for_backup()
        .map_err(|_| BackupError::Corrupt)?;

    sources.sort_by(|left, right| left.relative.cmp(&right.relative));
    if sources.len() > MAX_BACKUP_FILES
        || sources
            .windows(2)
            .any(|pair| pair[0].relative == pair[1].relative)
    {
        return Err(BackupError::ResourceExhausted);
    }
    let total_bytes = sources
        .iter()
        .try_fold(runtime_identity.size, |total, source| {
            total
                .checked_add(match source.kind {
                    BackupFileKind::Directory => 0,
                    BackupFileKind::Regular => source.identity.size,
                })
                .ok_or(BackupError::ResourceExhausted)
        })?;
    let required = total_bytes
        .checked_add(COPY_SPACE_RESERVE)
        .ok_or(BackupError::ResourceExhausted)?;
    let available_space = fs2::available_space(&backups_dir).map_err(|_| BackupError::Io)?;
    if available_space < required {
        return Err(BackupError::ResourceExhausted);
    }

    let scheduler = RuntimeSchedulerView::from_snapshot(snapshot).map_err(map_store)?;
    let object_deletions = ObjectDeletionCurrentView::from_snapshot(snapshot).map_err(map_store)?;
    let scope_purges = ScopePurgeCurrentView::from_snapshot(snapshot).map_err(map_store)?;
    let (committed_source_watermarks, runtime_outbox_watermark) = backup_watermarks(snapshot)?;
    if scheduler.frontier != snapshot.frontier {
        return Err(BackupError::Corrupt);
    }
    let profile = table_states.profile()?;
    let index_generation = if profile == "L0002" {
        crate::SEARCH_PROJECTION_GENERATION
    } else {
        0
    };
    let spool_source_watermarks = spool
        .source_watermarks
        .iter()
        .map(|value| BackupSpoolSourceWatermark {
            source_instance_id: value.source_instance_id.clone(),
            source_revision: value.source_revision.clone(),
            source_sequence: value.source_sequence,
        })
        .collect::<Vec<_>>();
    let spool_files = spool
        .files
        .iter()
        .map(|file| {
            Ok(BackupSpoolFileBoundary {
                relative_path: relative_string(&PathBuf::from("spool").join(&file.relative_path))?,
                kind: map_spool_file_kind(file.kind),
                frame_count: file.frame_count,
            })
        })
        .collect::<Result<Vec<_>, BackupError>>()?;
    let source_directories = spool
        .directories
        .iter()
        .map(|directory| PlannedDirectory {
            path: expected_runtime.spool_dir.join(&directory.relative_path),
            identity: FileIdentity {
                device: directory.device,
                inode: directory.inode,
                size: 0,
                modified_seconds: directory.modified_seconds,
                modified_nanoseconds: directory.modified_nanoseconds,
                changed_seconds: directory.changed_seconds,
                changed_nanoseconds: directory.changed_nanoseconds,
            },
        })
        .collect::<Vec<_>>();
    for directory in &source_directories {
        revalidate_directory(directory)?;
    }
    Ok(BackupPlan {
        data_dir: data_dir.to_owned(),
        backup_dir,
        staging_dir,
        manifest: BackupManifest {
            manifest_version: MANIFEST_VERSION,
            backup_job_id,
            frontier: snapshot.frontier,
            table_states,
            committed_source_watermarks,
            spool_source_watermarks,
            live_cas_refs: live_cas.into_iter().collect(),
            spool_cas_refs: spool.cas_refs.iter().cloned().collect(),
            spool_files,
            spool_generations: spool.spool_generations.clone(),
            normal_spool_frame_count: spool.normal_frame_count,
            isolated_spool_frame_count: spool.isolated_frame_count,
            emergency_gap_count: spool.emergency_gap_count,
            quarantine_count: spool.quarantine_count,
            runtime_outbox_watermark,
            index_generation,
            compiler_watermark: snapshot.frontier,
            effective_config_hash: current_runtime.effective_config_hash,
            runtime_generation: current_runtime.generation,
            hook_current_generation: hook.current_generation,
            hook_retained_generations: hook.retained_generations,
            hook_pin_count: hook.pin_count,
            session_pinned_hook_artifact_count: hook.pinned_generation_count,
            schema_revision: profile.into(),
            backup_algorithm_revision: QUIESCED_BACKUP_ALGORITHM_REVISION.into(),
            object_deletion_generation: object_deletions.generation,
            repository_purge_generation: scope_purges.generation,
            required_space_bytes: required,
            available_space_bytes_at_preflight: available_space,
            files: Vec::new(),
        },
        sources,
        source_directories,
        backup_runtime,
    })
}

pub(crate) fn stage_backup(mut plan: BackupPlan) -> Result<BackupStaging, BackupError> {
    validate_private_directory(&plan.data_dir)?;
    let parent = plan.staging_dir.parent().ok_or(BackupError::InvalidInput)?;
    validate_private_directory(parent)?;
    DirBuilder::new()
        .mode(0o700)
        .create(&plan.staging_dir)
        .map_err(|_| BackupError::Io)?;
    let result = (|| {
        let mut files = Vec::with_capacity(plan.sources.len());
        for source in &plan.sources {
            let destination = plan.staging_dir.join(&source.relative);
            match source.kind {
                BackupFileKind::Directory => {
                    revalidate_source(source)?;
                    let parent = destination.parent().ok_or(BackupError::InvalidInput)?;
                    ensure_staging_parents(&plan.staging_dir, parent)?;
                    DirBuilder::new()
                        .mode(0o700)
                        .create(&destination)
                        .map_err(|_| BackupError::Io)?;
                    revalidate_source(source)?;
                    files.push(BackupFileManifest {
                        relative_path: relative_string(&source.relative)?,
                        kind: BackupFileKind::Directory,
                        size: 0,
                        sha256: None,
                    });
                }
                BackupFileKind::Regular => {
                    let parent = destination.parent().ok_or(BackupError::InvalidInput)?;
                    ensure_staging_parents(&plan.staging_dir, parent)?;
                    let mut input = open_source(source)?;
                    let mut size = source.identity.size;
                    let digest = if source.relative.starts_with("hooks/generations")
                        && source
                            .relative
                            .file_name()
                            .is_some_and(|name| name == "hook-runtime-v1.json")
                    {
                        if size > MAX_AUXILIARY_FILE_BYTES {
                            return Err(BackupError::ResourceExhausted);
                        }
                        let mut bytes = Vec::new();
                        Read::by_ref(&mut input)
                            .take(size + 1)
                            .read_to_end(&mut bytes)
                            .map_err(|_| BackupError::Io)?;
                        if bytes.len() as u64 != size {
                            return Err(BackupError::IdentityChanged);
                        }
                        revalidate_source(source)?;
                        RuntimeSnapshot::from_bytes(&bytes)
                            .and_then(|snapshot| snapshot.sanitized_for_backup())
                            .and_then(|snapshot| snapshot.publish(&destination))
                            .map_err(|_| BackupError::Corrupt)?;
                        let final_identity = private_file_identity(&destination)?;
                        size = final_identity.size;
                        copy_exact_sha256_hex(
                            &mut open_exact_file(&destination, final_identity)?,
                            &mut io::sink(),
                            size,
                        )
                        .map_err(|_| BackupError::Corrupt)?
                    } else {
                        let mut output = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(&destination)
                            .map_err(|_| BackupError::Io)?;
                        let digest = copy_exact_sha256_hex(&mut input, &mut output, size)
                            .map_err(|_| BackupError::Corrupt)?;
                        output.sync_all().map_err(|_| BackupError::Io)?;
                        digest
                    };
                    revalidate_source(source)?;
                    files.push(BackupFileManifest {
                        relative_path: relative_string(&source.relative)?,
                        kind: BackupFileKind::Regular,
                        size,
                        sha256: Some(digest),
                    });
                }
            }
        }
        let runtime_relative = Path::new("runtime/hook-runtime-v1.json");
        let runtime_destination = plan.staging_dir.join(runtime_relative);
        ensure_staging_parents(
            &plan.staging_dir,
            runtime_destination
                .parent()
                .ok_or(BackupError::InvalidInput)?,
        )?;
        plan.backup_runtime
            .publish(&runtime_destination)
            .map_err(|_| BackupError::Io)?;
        let runtime_identity = private_file_identity(&runtime_destination)?;
        let mut runtime_file = open_exact_file(&runtime_destination, runtime_identity)?;
        let runtime_sha =
            copy_exact_sha256_hex(&mut runtime_file, &mut io::sink(), runtime_identity.size)
                .map_err(|_| BackupError::Corrupt)?;
        files.push(BackupFileManifest {
            relative_path: relative_string(runtime_relative)?,
            kind: BackupFileKind::Regular,
            size: runtime_identity.size,
            sha256: Some(runtime_sha),
        });
        for source in &plan.sources {
            revalidate_source(source)?;
        }
        for directory in &plan.source_directories {
            revalidate_directory(directory)?;
        }
        for (relative_path, kind) in enumerate_backup_tree(&plan.staging_dir)? {
            if kind == BackupFileKind::Directory
                && !files.iter().any(|item| item.relative_path == relative_path)
            {
                files.push(BackupFileManifest {
                    relative_path,
                    kind,
                    size: 0,
                    sha256: None,
                });
            }
        }
        files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        plan.manifest.files = files;
        validate_manifest(&plan.manifest)?;
        serde_json::to_writer(
            BoundedCountWriter {
                written: 0,
                limit: MAX_MANIFEST_BYTES,
            },
            &plan.manifest,
        )
        .map_err(|_| BackupError::ResourceExhausted)?;
        let mut manifest_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(plan.staging_dir.join(MANIFEST_NAME))
            .map_err(|_| BackupError::Io)?;
        serde_json::to_writer(&mut manifest_file, &plan.manifest).map_err(|_| BackupError::Io)?;
        if manifest_file.metadata().map_err(|_| BackupError::Io)?.len() > MAX_MANIFEST_BYTES {
            return Err(BackupError::ResourceExhausted);
        }
        manifest_file.sync_all().map_err(|_| BackupError::Io)?;
        File::open(&plan.staging_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| BackupError::Io)?;
        let verification =
            prepare_verification_directory(&plan.staging_dir, Some(plan.manifest.backup_job_id))?;
        let staging_identity = verification.root_identity;
        Ok(BackupStaging {
            backup_dir: plan.backup_dir,
            staging_dir: plan.staging_dir.clone(),
            backup_job_id: plan.manifest.backup_job_id,
            staging_identity,
            verification,
        })
    })();
    if result.is_err() {
        let _ = remove_owned_staging(&plan.staging_dir);
    }
    result
}

pub(crate) fn publish_backup(
    staging: BackupStaging,
    summary: BackupSummary,
) -> Result<BackupSummary, BackupError> {
    let staging_dir = staging.staging_dir.clone();
    let result = (|| {
        if private_directory_identity(&staging.staging_dir)? != staging.staging_identity
            || summary.backup_job_id != staging.backup_job_id
        {
            return Err(BackupError::IdentityChanged);
        }
        let parent = staging
            .staging_dir
            .parent()
            .ok_or(BackupError::InvalidInput)?;
        validate_private_directory(parent)?;
        fs::rename(&staging.staging_dir, &staging.backup_dir).map_err(|_| BackupError::Io)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| BackupError::Io)?;
        Ok(summary)
    })();
    if result.is_err() {
        let _ = remove_owned_staging(&staging_dir);
    }
    result
}

pub(crate) fn discard_backup(staging: &BackupStaging) -> Result<(), BackupError> {
    if private_directory_identity(&staging.staging_dir)? != staging.staging_identity {
        return Err(BackupError::IdentityChanged);
    }
    remove_owned_staging(&staging.staging_dir)
}

pub async fn verify_backup(
    data_dir: &Path,
    backup_job_id: JobId,
) -> Result<BackupSummary, BackupError> {
    validate_private_directory(data_dir)?;
    let directory = data_dir
        .join("backups")
        .join(format!("backup-{backup_job_id}"));
    complete_backup_verification(prepare_verification_directory(
        &directory,
        Some(backup_job_id),
    )?)
    .await
}

pub(crate) async fn verify_staged_backup(
    staging: &BackupStaging,
) -> Result<BackupSummary, BackupError> {
    if private_directory_identity(&staging.staging_dir)? != staging.staging_identity {
        return Err(BackupError::IdentityChanged);
    }
    complete_backup_verification_ref(&staging.verification).await
}

fn verify_backup_files(
    directory: &Path,
    expected_job_id: Option<JobId>,
) -> Result<BackupVerification, BackupError> {
    let root_before = private_directory_identity(directory)?;
    let manifest_path = directory.join(MANIFEST_NAME);
    let manifest_before = private_file_identity(&manifest_path)?;
    if manifest_before.size > MAX_MANIFEST_BYTES {
        return Err(BackupError::ResourceExhausted);
    }
    let mut manifest_file = open_exact_file(&manifest_path, manifest_before)?;
    let manifest: BackupManifest =
        serde_json::from_reader(&mut manifest_file).map_err(|_| BackupError::Corrupt)?;
    if private_file_identity(&manifest_path)? != manifest_before {
        return Err(BackupError::IdentityChanged);
    }
    validate_manifest(&manifest)?;
    if expected_job_id.is_some_and(|expected| manifest.backup_job_id != expected) {
        return Err(BackupError::Corrupt);
    }

    let actual = enumerate_backup_tree(directory)?;
    let mut expected = manifest
        .files
        .iter()
        .map(|file| (file.relative_path.clone(), file.kind.clone()))
        .collect::<Vec<_>>();
    expected.push((MANIFEST_NAME.into(), BackupFileKind::Regular));
    expected.sort_by(|left, right| left.0.cmp(&right.0));
    if actual != expected {
        return Err(BackupError::Corrupt);
    }

    let mut total_bytes = 0_u64;
    let mut input_identities = vec![(PathBuf::from(MANIFEST_NAME), false, manifest_before)];
    for item in &manifest.files {
        let relative = strict_relative(&item.relative_path)?;
        let path = directory.join(&relative);
        match item.kind {
            BackupFileKind::Directory => {
                if item.size != 0 || item.sha256.is_some() {
                    return Err(BackupError::Corrupt);
                }
                input_identities.push((relative, true, private_directory_identity(&path)?));
            }
            BackupFileKind::Regular => {
                let identity = private_file_identity(&path)?;
                if identity.size != item.size {
                    return Err(BackupError::Corrupt);
                }
                let mut file = open_exact_file(&path, identity)?;
                let digest = copy_exact_sha256_hex(&mut file, &mut io::sink(), item.size)
                    .map_err(|_| BackupError::Corrupt)?;
                if item.sha256.as_deref() != Some(digest.as_str())
                    || private_file_identity(&path)? != identity
                {
                    return Err(BackupError::Corrupt);
                }
                total_bytes = total_bytes
                    .checked_add(item.size)
                    .ok_or(BackupError::ResourceExhausted)?;
                input_identities.push((relative, false, identity));
            }
        }
    }
    validate_config_and_runtime(directory, &manifest)?;
    if private_file_identity(&manifest_path)? != manifest_before
        || private_directory_identity(directory)? != root_before
    {
        return Err(BackupError::IdentityChanged);
    }
    let summary = summary_from_manifest(&manifest, total_bytes)?;
    Ok(BackupVerification {
        directory: directory.to_owned(),
        manifest,
        summary,
        root_identity: root_before,
        input_identities,
    })
}

fn summary_from_manifest(
    manifest: &BackupManifest,
    total_bytes: u64,
) -> Result<BackupSummary, BackupError> {
    Ok(BackupSummary {
        backup_job_id: manifest.backup_job_id,
        frontier: manifest.frontier,
        table_states: manifest.table_states.clone(),
        committed_source_watermark_count: u32::try_from(manifest.committed_source_watermarks.len())
            .map_err(|_| BackupError::ResourceExhausted)?,
        spool_source_watermark_count: u32::try_from(manifest.spool_source_watermarks.len())
            .map_err(|_| BackupError::ResourceExhausted)?,
        live_cas_count: u32::try_from(manifest.live_cas_refs.len())
            .map_err(|_| BackupError::ResourceExhausted)?,
        spool_cas_count: u32::try_from(manifest.spool_cas_refs.len())
            .map_err(|_| BackupError::ResourceExhausted)?,
        spool_file_count: u32::try_from(manifest.spool_files.len())
            .map_err(|_| BackupError::ResourceExhausted)?,
        spool_generation_count: u32::try_from(manifest.spool_generations.len())
            .map_err(|_| BackupError::ResourceExhausted)?,
        normal_spool_frame_count: manifest.normal_spool_frame_count,
        isolated_spool_frame_count: manifest.isolated_spool_frame_count,
        emergency_gap_count: manifest.emergency_gap_count,
        quarantine_count: manifest.quarantine_count,
        runtime_outbox_watermark: manifest.runtime_outbox_watermark,
        index_generation: manifest.index_generation,
        compiler_watermark: manifest.compiler_watermark,
        effective_config_hash: manifest.effective_config_hash,
        runtime_generation: manifest.runtime_generation,
        hook_current_generation: manifest.hook_current_generation,
        hook_retained_generations: manifest.hook_retained_generations.clone(),
        hook_pin_count: manifest.hook_pin_count,
        session_pinned_hook_artifact_count: manifest.session_pinned_hook_artifact_count,
        object_deletion_generation: manifest.object_deletion_generation,
        repository_purge_generation: manifest.repository_purge_generation,
        file_count: u32::try_from(manifest.files.len())
            .map_err(|_| BackupError::ResourceExhausted)?,
        total_bytes,
        required_space_bytes: manifest.required_space_bytes,
        available_space_bytes_at_preflight: manifest.available_space_bytes_at_preflight,
    })
}

pub fn read_backup_summary(
    data_dir: &Path,
    backup_job_id: JobId,
) -> Result<BackupSummary, BackupError> {
    validate_private_directory(data_dir)?;
    let directory = data_dir
        .join("backups")
        .join(format!("backup-{backup_job_id}"));
    let root_before = private_directory_identity(&directory)?;
    let manifest_path = directory.join(MANIFEST_NAME);
    let manifest_before = private_file_identity(&manifest_path)?;
    if manifest_before.size > MAX_MANIFEST_BYTES {
        return Err(BackupError::ResourceExhausted);
    }
    let mut manifest_file = open_exact_file(&manifest_path, manifest_before)?;
    let manifest: BackupManifest =
        serde_json::from_reader(&mut manifest_file).map_err(|_| BackupError::Corrupt)?;
    validate_manifest(&manifest)?;
    if manifest.backup_job_id != backup_job_id
        || private_file_identity(&manifest_path)? != manifest_before
        || private_directory_identity(&directory)? != root_before
    {
        return Err(BackupError::IdentityChanged);
    }
    let total_bytes = manifest.files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.size)
            .ok_or(BackupError::ResourceExhausted)
    })?;
    summary_from_manifest(&manifest, total_bytes)
}

pub(crate) fn prepare_verification_directory(
    directory: &Path,
    expected_job_id: Option<JobId>,
) -> Result<BackupVerification, BackupError> {
    let verification = verify_backup_files(directory, expected_job_id)?;
    verify_backup_cas_and_spool(directory, &verification.manifest)?;
    if private_directory_identity(directory)? != verification.root_identity {
        return Err(BackupError::IdentityChanged);
    }
    Ok(verification)
}

pub fn prepare_backup_verification(
    data_dir: &Path,
    backup_job_id: JobId,
) -> Result<BackupVerification, BackupError> {
    validate_private_directory(data_dir)?;
    prepare_verification_directory(
        &data_dir
            .join("backups")
            .join(format!("backup-{backup_job_id}")),
        Some(backup_job_id),
    )
}

pub(crate) fn check_restore_copy_budget(
    verification: &BackupVerification,
    destination: &Path,
) -> Result<(), BackupError> {
    let parent = destination.parent().ok_or(BackupError::InvalidInput)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| BackupError::Io)?;
    if !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != current_uid()?
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(BackupError::Corrupt);
    }
    let needed = verification
        .summary
        .total_bytes
        .checked_add(COPY_SPACE_RESERVE)
        .ok_or(BackupError::ResourceExhausted)?;
    if fs2::available_space(parent).map_err(|_| BackupError::Io)? < needed {
        return Err(BackupError::ResourceExhausted);
    }
    Ok(())
}

pub(crate) fn copy_restore_candidate(
    verification: &BackupVerification,
    destination: &Path,
    destination_root: &evertrace_capture::ConfinedRoot,
) -> Result<(), BackupError> {
    copy_verified_candidate(verification, destination, destination_root, false)
}

pub(crate) fn copy_upgrade_native_candidate(
    verification: &BackupVerification,
    destination: &Path,
    destination_root: &evertrace_capture::ConfinedRoot,
) -> Result<(), BackupError> {
    copy_verified_candidate(verification, destination, destination_root, true)
}

/// Ephemeral use of the same file manifest and streaming checksum algorithm:
/// compare the prepared native tree with the published tree before writes resume.
pub(crate) fn native_upgrade_manifest(
    native: &Path,
) -> Result<Vec<BackupFileManifest>, BackupError> {
    let mut sources = Vec::new();
    collect_tree(native, Path::new("store"), &mut sources)?;
    sources.sort_by(|left, right| left.relative.cmp(&right.relative));
    let mut files = Vec::with_capacity(sources.len());
    for source in sources {
        revalidate_source(&source)?;
        let sha256 = if source.kind == BackupFileKind::Regular {
            let mut file = open_source(&source)?;
            let checksum = copy_exact_sha256_hex(&mut file, &mut io::sink(), source.identity.size)
                .map_err(|_| BackupError::Corrupt)?;
            file.sync_all().map_err(|_| BackupError::Io)?;
            revalidate_source(&source)?;
            Some(checksum)
        } else {
            File::open(&source.source)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| BackupError::Io)?;
            revalidate_source(&source)?;
            None
        };
        files.push(BackupFileManifest {
            relative_path: source
                .relative
                .to_str()
                .ok_or(BackupError::Corrupt)?
                .to_owned(),
            kind: source.kind,
            size: if sha256.is_some() {
                source.identity.size
            } else {
                0
            },
            sha256,
        });
    }
    Ok(files)
}

fn copy_verified_candidate(
    verification: &BackupVerification,
    destination: &Path,
    destination_root: &evertrace_capture::ConfinedRoot,
    native_only: bool,
) -> Result<(), BackupError> {
    destination_root
        .revalidate_stable()
        .map_err(|_| BackupError::IdentityChanged)?;
    let source_root = evertrace_capture::ConfinedRoot::open_owned_private(&verification.directory)
        .map_err(|_| BackupError::IdentityChanged)?;
    for entry in &verification.manifest.files {
        let relative = strict_relative(&entry.relative_path)?;
        let output_relative = if native_only {
            let Ok(native) = relative.strip_prefix("store") else {
                continue;
            };
            native
        } else {
            relative.as_path()
        };
        let output_path = destination.join(output_relative);
        if entry.kind == BackupFileKind::Directory {
            ensure_staging_parents(destination, &output_path)?;
            continue;
        }
        ensure_staging_parents(
            destination,
            output_path.parent().ok_or(BackupError::InvalidInput)?,
        )?;
        let mut input = source_root
            .open_regular_file(&relative)
            .map_err(|_| BackupError::IdentityChanged)?;
        let before = identity(&input.metadata().map_err(|_| BackupError::Io)?);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&output_path)
            .map_err(|_| BackupError::Io)?;
        let digest = copy_exact_sha256_hex(&mut input, &mut output, entry.size)
            .map_err(|_| BackupError::Corrupt)?;
        if entry.sha256.as_deref() != Some(digest.as_str())
            || identity(&input.metadata().map_err(|_| BackupError::Io)?) != before
            || identity(
                &source_root
                    .open_regular_file(&relative)
                    .map_err(|_| BackupError::IdentityChanged)?
                    .metadata()
                    .map_err(|_| BackupError::Io)?,
            ) != before
        {
            return Err(BackupError::IdentityChanged);
        }
        output.sync_all().map_err(|_| BackupError::Io)?;
    }
    if !native_only {
        let manifest =
            serde_json::to_vec(&verification.manifest).map_err(|_| BackupError::Corrupt)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination.join(MANIFEST_NAME))
            .map_err(|_| BackupError::Io)?;
        output.write_all(&manifest).map_err(|_| BackupError::Io)?;
        output.sync_all().map_err(|_| BackupError::Io)?;
    }
    source_root
        .revalidate_stable()
        .map_err(|_| BackupError::IdentityChanged)?;
    File::open(destination)
        .and_then(|root| root.sync_all())
        .map_err(|_| BackupError::Io)?;
    destination_root
        .revalidate_stable()
        .map_err(|_| BackupError::IdentityChanged)?;
    Ok(())
}

pub async fn complete_backup_verification(
    verification: BackupVerification,
) -> Result<BackupSummary, BackupError> {
    complete_backup_verification_ref(&verification).await
}

pub(crate) async fn complete_backup_verification_ref(
    verification: &BackupVerification,
) -> Result<BackupSummary, BackupError> {
    verify_backup_tables(&verification.directory, &verification.manifest).await?;
    for entry in &verification.manifest.files {
        if valid_gc_report_path(&entry.relative_path) {
            let id = entry
                .relative_path
                .strip_prefix("maintenance/gc-")
                .and_then(|value| value.strip_suffix(".json"))
                .ok_or(BackupError::Corrupt)?
                .parse()
                .map_err(|_| BackupError::Corrupt)?;
            crate::optimize::read_gc_report(&verification.directory, id).map_err(map_store)?;
        }
    }
    if private_directory_identity(&verification.directory)? != verification.root_identity {
        return Err(BackupError::IdentityChanged);
    }
    Ok(verification.summary.clone())
}

fn verify_backup_cas_and_spool(
    directory: &Path,
    manifest: &BackupManifest,
) -> Result<(), BackupError> {
    let expected_cas_refs = manifest
        .live_cas_refs
        .iter()
        .chain(&manifest.spool_cas_refs)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut expected_cas_paths = BTreeSet::new();
    if !expected_cas_refs.is_empty() {
        let cas =
            CasStore::open_existing(directory.join("cas")).map_err(|_| BackupError::Corrupt)?;
        for value in &expected_cas_refs {
            let digest = CasStore::parse_digest(value).map_err(|_| BackupError::Corrupt)?;
            cas.verify_envelope(&digest)
                .map_err(|_| BackupError::Corrupt)?;
            expected_cas_paths.insert(relative_string(
                cas.blob_path(&digest)
                    .strip_prefix(directory)
                    .map_err(|_| BackupError::Corrupt)?,
            )?);
        }
    }
    let actual_cas_paths = manifest
        .files
        .iter()
        .filter(|file| {
            file.kind == BackupFileKind::Regular && file.relative_path.starts_with("cas/")
        })
        .map(|file| file.relative_path.clone())
        .collect::<BTreeSet<_>>();
    if actual_cas_paths != expected_cas_paths {
        return Err(BackupError::Corrupt);
    }

    let runtime = RuntimeSnapshot::load(&directory.join("runtime/hook-runtime-v1.json"))
        .map_err(|_| BackupError::Corrupt)?;
    let max_spool_bytes = runtime.main_high_watermark_bytes;
    let mut spool_cas_refs = BTreeSet::new();
    let mut spool_source_watermarks: BTreeMap<(SourceInstanceId, SourceRevision), u64> =
        BTreeMap::new();
    let mut spool_generations = BTreeSet::new();
    let mut normal_frames = 0_u32;
    let mut isolated_frames = 0_u32;
    for file in &manifest.spool_files {
        let path = directory.join(strict_relative(&file.relative_path)?);
        let kind = match file.kind {
            BackupSpoolFileKind::Normal => SpoolBackupFileKind::Normal,
            BackupSpoolFileKind::Isolated => SpoolBackupFileKind::Isolated,
            BackupSpoolFileKind::EmergencyGap => SpoolBackupFileKind::EmergencyGap,
            BackupSpoolFileKind::Quarantine => SpoolBackupFileKind::Quarantine,
        };
        let semantic = verify_backup_spool_file(&path, kind, max_spool_bytes)
            .map_err(|_| BackupError::Corrupt)?;
        if semantic.frame_count != file.frame_count {
            return Err(BackupError::Corrupt);
        }
        match file.kind {
            BackupSpoolFileKind::Normal => {
                normal_frames = normal_frames
                    .checked_add(semantic.frame_count)
                    .ok_or(BackupError::ResourceExhausted)?;
            }
            BackupSpoolFileKind::Isolated => {
                isolated_frames = isolated_frames
                    .checked_add(semantic.frame_count)
                    .ok_or(BackupError::ResourceExhausted)?;
            }
            BackupSpoolFileKind::EmergencyGap | BackupSpoolFileKind::Quarantine => {}
        }
        spool_cas_refs.extend(semantic.cas_refs);
        spool_generations.extend(semantic.spool_generations);
        for value in semantic.source_watermarks {
            spool_source_watermarks
                .entry((value.source_instance_id, value.source_revision))
                .and_modify(|sequence| *sequence = (*sequence).max(value.source_sequence))
                .or_insert(value.source_sequence);
        }
    }
    if spool_cas_refs.into_iter().collect::<Vec<_>>() != manifest.spool_cas_refs
        || spool_source_watermarks
            .into_iter()
            .map(|((source_instance_id, source_revision), source_sequence)| {
                BackupSpoolSourceWatermark {
                    source_instance_id,
                    source_revision,
                    source_sequence,
                }
            })
            .collect::<Vec<_>>()
            != manifest.spool_source_watermarks
        || spool_generations.into_iter().collect::<Vec<_>>() != manifest.spool_generations
        || normal_frames != manifest.normal_spool_frame_count
        || isolated_frames != manifest.isolated_spool_frame_count
    {
        return Err(BackupError::Corrupt);
    }
    Ok(())
}

pub(crate) async fn read_verified_store_tables(
    store_dir: &Path,
) -> Result<(BackupTableStates, ProjectionSnapshot), BackupError> {
    let connection = lancedb::connect(store_dir.to_str().ok_or(BackupError::Corrupt)?)
        .execute()
        .await
        .map_err(|_| BackupError::Corrupt)?;
    let mut names = connection
        .table_names()
        .execute()
        .await
        .map_err(|_| BackupError::Corrupt)?;
    names.sort();
    let mut expected_names = vec![
        crate::JOURNAL_TABLE.to_owned(),
        crate::OBJECTS_TABLE.to_owned(),
    ];
    let l0002 = names
        .iter()
        .any(|name| name == crate::RELATIONS_TABLE || name == crate::SEARCH_TABLE);
    if l0002 {
        expected_names.extend([
            crate::RELATIONS_TABLE.to_owned(),
            crate::SEARCH_TABLE.to_owned(),
        ]);
    }
    expected_names.sort();
    if names != expected_names {
        return Err(BackupError::Corrupt);
    }
    let journal = connection
        .open_table(crate::JOURNAL_TABLE)
        .execute()
        .await
        .map_err(|_| BackupError::Corrupt)?;
    let objects = connection
        .open_table(crate::OBJECTS_TABLE)
        .execute()
        .await
        .map_err(|_| BackupError::Corrupt)?;
    let relations = if l0002 {
        Some(
            connection
                .open_table(crate::RELATIONS_TABLE)
                .execute()
                .await
                .map_err(|_| BackupError::Corrupt)?,
        )
    } else {
        None
    };
    let search = if l0002 {
        Some(
            connection
                .open_table(crate::SEARCH_TABLE)
                .execute()
                .await
                .map_err(|_| BackupError::Corrupt)?,
        )
    } else {
        None
    };
    crate::journal::validate_journal_table(&journal)
        .await
        .map_err(map_store)?;
    let journal_checkpoint = crate::journal::read_journal_frontier(&journal)
        .await
        .map_err(map_store)?;
    let object_rows = crate::objects::validate_objects_table(&objects)
        .await
        .map_err(map_store)?;
    let object_checkpoint = object_rows
        .iter()
        .find(|row| row.row_id == crate::OBJECTS_CHECKPOINT_ID)
        .ok_or(BackupError::Corrupt)?
        .source_event_seq;
    let relation_state = if let Some(table) = &relations {
        Some(BackupTableState {
            version: table.version().await.map_err(|_| BackupError::Corrupt)?,
            checkpoint: crate::relations::read_relation_checkpoint(table)
                .await
                .map_err(map_store)?,
        })
    } else {
        None
    };
    let search_state = if let Some(table) = &search {
        Some(BackupTableState {
            version: table.version().await.map_err(|_| BackupError::Corrupt)?,
            checkpoint: crate::search::read_search_checkpoint(table)
                .await
                .map_err(map_store)?,
        })
    } else {
        None
    };
    let actual = BackupTableStates {
        journal: BackupTableState {
            version: journal.version().await.map_err(|_| BackupError::Corrupt)?,
            checkpoint: journal_checkpoint,
        },
        objects: BackupTableState {
            version: objects.version().await.map_err(|_| BackupError::Corrupt)?,
            checkpoint: object_checkpoint,
        },
        relations: relation_state,
        search: search_state,
    };
    if crate::JournalWriter::existing_profile(store_dir)
        .await
        .map_err(map_store)?
        != Some(actual.profile()?)
    {
        return Err(BackupError::Corrupt);
    }
    Ok((
        actual,
        ProjectionSnapshot {
            frontier: journal_checkpoint,
            rows: object_rows,
        },
    ))
}

async fn verify_backup_tables(
    directory: &Path,
    manifest: &BackupManifest,
) -> Result<(), BackupError> {
    let (actual, snapshot) = read_verified_store_tables(&directory.join("store")).await?;
    let journal_checkpoint = actual.journal.checkpoint;
    let object_checkpoint = actual.objects.checkpoint;
    if actual != manifest.table_states
        || journal_checkpoint != manifest.frontier
        || object_checkpoint != manifest.frontier
        || !actual.validate(manifest.frontier)
        || manifest.schema_revision != actual.profile()?
        || manifest.index_generation
            != if actual.profile()? == "L0002" {
                crate::SEARCH_PROJECTION_GENERATION
            } else {
                0
            }
        || manifest.compiler_watermark != actual.objects.checkpoint
    {
        return Err(BackupError::Corrupt);
    }
    let (committed_source_watermarks, runtime_outbox_watermark) = backup_watermarks(&snapshot)?;
    let object_deletions =
        ObjectDeletionCurrentView::from_snapshot(&snapshot).map_err(map_store)?;
    let scope_purges = ScopePurgeCurrentView::from_snapshot(&snapshot).map_err(map_store)?;
    if committed_source_watermarks != manifest.committed_source_watermarks
        || runtime_outbox_watermark != manifest.runtime_outbox_watermark
        || snapshot.live_cas_refs().map_err(map_store)?
            != manifest.live_cas_refs.iter().cloned().collect()
        || object_deletions.generation != manifest.object_deletion_generation
        || scope_purges.generation != manifest.repository_purge_generation
    {
        return Err(BackupError::Corrupt);
    }
    Ok(())
}

fn validate_config_and_runtime(
    directory: &Path,
    manifest: &BackupManifest,
) -> Result<(), BackupError> {
    for generation in &manifest.hook_retained_generations {
        let path = directory.join(format!(
            "hooks/generations/{generation}/hook-runtime-v1.json"
        ));
        let before = private_file_identity(&path)?;
        if before.size > MAX_AUXILIARY_FILE_BYTES {
            return Err(BackupError::ResourceExhausted);
        }
        let snapshot = RuntimeSnapshot::load(&path).map_err(|_| BackupError::Corrupt)?;
        if !snapshot.recall_cues.is_empty() || private_file_identity(&path)? != before {
            return Err(BackupError::Corrupt);
        }
    }
    let config_path = directory.join("config/config.toml");
    let config_identity = private_file_identity(&config_path)?;
    let config = read_small_utf8_file(&config_path, config_identity)?;
    let effective = EffectiveConfig::parse_toml(&config).map_err(|_| BackupError::Corrupt)?;
    if effective.hash() != manifest.effective_config_hash {
        return Err(BackupError::Corrupt);
    }
    let runtime_path = directory.join("runtime/hook-runtime-v1.json");
    let runtime_identity = private_file_identity(&runtime_path)?;
    if runtime_identity.size > MAX_AUXILIARY_FILE_BYTES {
        return Err(BackupError::ResourceExhausted);
    }
    let runtime = RuntimeSnapshot::load(&runtime_path).map_err(|_| BackupError::Corrupt)?;
    if private_file_identity(&runtime_path)? != runtime_identity {
        return Err(BackupError::IdentityChanged);
    }
    if runtime.generation != manifest.runtime_generation
        || runtime.effective_config_hash != manifest.effective_config_hash
        || !runtime.recall_cues.is_empty()
    {
        return Err(BackupError::Corrupt);
    }
    Ok(())
}

fn read_small_utf8_file(path: &Path, expected: FileIdentity) -> Result<String, BackupError> {
    if expected.size > MAX_AUXILIARY_FILE_BYTES {
        return Err(BackupError::ResourceExhausted);
    }
    let capacity = usize::try_from(expected.size).map_err(|_| BackupError::ResourceExhausted)?;
    let mut file = open_exact_file(path, expected)?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(expected.size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| BackupError::Io)?;
    if u64::try_from(bytes.len()).map_err(|_| BackupError::ResourceExhausted)? != expected.size
        || private_file_identity(path)? != expected
    {
        return Err(BackupError::IdentityChanged);
    }
    String::from_utf8(bytes).map_err(|_| BackupError::Corrupt)
}

fn backup_watermarks(
    snapshot: &ProjectionSnapshot,
) -> Result<(Vec<BackupSourceWatermark>, u64), BackupError> {
    let mut source = Vec::new();
    let mut outbox = 0_u64;
    for row in snapshot.data_rows() {
        let Some(json) = row.payload_json.as_deref() else {
            return Err(BackupError::Corrupt);
        };
        let payload: JournalPayload =
            serde_json::from_str(json).map_err(|_| BackupError::Corrupt)?;
        payload.validate().map_err(map_store)?;
        match payload {
            JournalPayload::SourceIngestWatermark(value) => {
                source.push(BackupSourceWatermark {
                    source_instance_id: value.source_instance_id,
                    source_revision: value.source_revision,
                    source_sequence: value.source_sequence,
                    confirmed_prefix_digest: value.confirmed_prefix_digest,
                });
            }
            JournalPayload::WatermarkAdvanced(value)
                if value.kind == WatermarkKind::RuntimeOutbox =>
            {
                outbox = outbox.max(value.value);
            }
            _ => {}
        }
    }
    source.sort();
    if source.windows(2).any(|pair| {
        pair[0].source_instance_id == pair[1].source_instance_id
            && pair[0].source_revision == pair[1].source_revision
    }) {
        return Err(BackupError::Corrupt);
    }
    Ok((source, outbox))
}

fn validate_hook_boundary(boundary: &BackupHookBoundary) -> Result<(), BackupError> {
    let paths = boundary
        .files
        .iter()
        .map(|file| file.relative_path.to_str().map(str::to_owned))
        .collect::<Option<BTreeSet<_>>>()
        .ok_or(BackupError::InvalidInput)?;
    if hook_snapshot_paths(
        boundary.current_generation,
        &boundary.retained_generations,
        boundary.pin_count,
        boundary.pinned_generation_count,
        &paths,
    )
    .is_none()
    {
        return Err(BackupError::InvalidInput);
    }
    Ok(())
}

fn valid_hook_manifest(manifest: &BackupManifest) -> bool {
    let paths = manifest
        .files
        .iter()
        .filter(|file| {
            file.kind == BackupFileKind::Regular
                && (file.relative_path == "hook-v1" || file.relative_path.starts_with("hooks/"))
        })
        .map(|file| file.relative_path.clone())
        .collect::<BTreeSet<_>>();
    hook_snapshot_paths(
        manifest.hook_current_generation,
        &manifest.hook_retained_generations,
        manifest.hook_pin_count,
        manifest.session_pinned_hook_artifact_count,
        &paths,
    )
    .is_some()
}

fn hook_snapshot_paths(
    current_generation: Option<u64>,
    retained_generations: &[u64],
    pin_count: u32,
    pinned_generation_count: u32,
    actual: &BTreeSet<String>,
) -> Option<BTreeSet<String>> {
    if retained_generations.contains(&0)
        || retained_generations
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || usize::try_from(pinned_generation_count).ok()? > retained_generations.len()
        || pinned_generation_count > pin_count
    {
        return None;
    }
    let Some(current_generation) = current_generation else {
        return (retained_generations.is_empty()
            && pin_count == 0
            && pinned_generation_count == 0
            && actual.is_empty())
        .then(BTreeSet::new);
    };
    if current_generation == 0 || !retained_generations.contains(&current_generation) {
        return None;
    }
    let mut expected = BTreeSet::from(["hook-v1".to_owned(), "hooks/registry-v1.json".to_owned()]);
    for generation in retained_generations {
        expected.insert(format!("hooks/generations/{generation}/evertrace-hook"));
        expected.insert(format!(
            "hooks/generations/{generation}/hook-runtime-v1.json"
        ));
    }
    let pin_paths = actual
        .iter()
        .filter(|path| valid_hook_pin_path(path))
        .cloned()
        .collect::<Vec<_>>();
    if u32::try_from(pin_paths.len()).ok()? != pin_count {
        return None;
    }
    expected.extend(pin_paths);
    (expected == *actual).then_some(expected)
}

fn valid_hook_pin_path(path: &str) -> bool {
    let Some(session_id) = path
        .strip_prefix("hooks/pins/")
        .and_then(|value| value.strip_suffix(".pin"))
    else {
        return false;
    };
    !session_id.is_empty()
        && session_id.len() <= 128
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_manifest(manifest: &BackupManifest) -> Result<(), BackupError> {
    if manifest.manifest_version != MANIFEST_VERSION
        || manifest.frontier == 0
        || !manifest.table_states.validate(manifest.frontier)
        || manifest.index_generation
            != if manifest.schema_revision == "L0002" {
                crate::SEARCH_PROJECTION_GENERATION
            } else {
                0
            }
        || manifest.compiler_watermark != manifest.frontier
        || manifest.effective_config_hash == [0; 32]
        || manifest.runtime_generation == 0
        || !valid_hook_manifest(manifest)
        || manifest.schema_revision != manifest.table_states.profile()?
        || manifest.backup_algorithm_revision != QUIESCED_BACKUP_ALGORITHM_REVISION
        || manifest.files.is_empty()
        || manifest.files.len() > MAX_BACKUP_FILES
        || manifest.committed_source_watermarks.len() > MAX_BACKUP_FILES
        || manifest.spool_source_watermarks.len() > MAX_BACKUP_FILES
        || manifest.live_cas_refs.len() > MAX_BACKUP_FILES
        || manifest.spool_cas_refs.len() > MAX_BACKUP_FILES
        || manifest.spool_files.len() > MAX_BACKUP_FILES
        || manifest.spool_generations.len() > MAX_BACKUP_FILES
        || manifest.hook_retained_generations.len() > MAX_BACKUP_FILES
        || manifest.files.windows(2).any(|pair| {
            pair[0].relative_path >= pair[1].relative_path
                || strict_relative(&pair[0].relative_path).is_err()
        })
        || manifest
            .files
            .last()
            .is_some_and(|item| strict_relative(&item.relative_path).is_err())
    {
        return Err(BackupError::Corrupt);
    }
    if manifest
        .committed_source_watermarks
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || manifest.spool_source_watermarks.windows(2).any(|pair| {
            pair[0] >= pair[1]
                || (pair[0].source_instance_id == pair[1].source_instance_id
                    && pair[0].source_revision == pair[1].source_revision)
        })
        || manifest
            .live_cas_refs
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || manifest
            .spool_cas_refs
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || manifest
            .spool_files
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || manifest
            .spool_generations
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || manifest
            .live_cas_refs
            .iter()
            .chain(&manifest.spool_cas_refs)
            .any(|value| CasStore::parse_digest(value).is_err())
    {
        return Err(BackupError::Corrupt);
    }
    let normal_frames = manifest
        .spool_files
        .iter()
        .filter(|file| file.kind == BackupSpoolFileKind::Normal)
        .try_fold(0_u32, |total, file| total.checked_add(file.frame_count))
        .ok_or(BackupError::Corrupt)?;
    let isolated_frames = manifest
        .spool_files
        .iter()
        .filter(|file| file.kind == BackupSpoolFileKind::Isolated)
        .try_fold(0_u32, |total, file| total.checked_add(file.frame_count))
        .ok_or(BackupError::Corrupt)?;
    if normal_frames != manifest.normal_spool_frame_count
        || isolated_frames != manifest.isolated_spool_frame_count
        || u32::try_from(
            manifest
                .spool_files
                .iter()
                .filter(|file| file.kind == BackupSpoolFileKind::EmergencyGap)
                .count(),
        )
        .ok()
            != Some(manifest.emergency_gap_count)
        || u32::try_from(
            manifest
                .spool_files
                .iter()
                .filter(|file| file.kind == BackupSpoolFileKind::Quarantine)
                .count(),
        )
        .ok()
            != Some(manifest.quarantine_count)
        || manifest.required_space_bytes > manifest.available_space_bytes_at_preflight
    {
        return Err(BackupError::Corrupt);
    }
    let declared_spool_paths = manifest
        .spool_files
        .iter()
        .map(|file| file.relative_path.clone())
        .collect::<BTreeSet<_>>();
    let stored_spool_paths = manifest
        .files
        .iter()
        .filter(|file| {
            file.kind == BackupFileKind::Regular && file.relative_path.starts_with("spool/")
        })
        .map(|file| file.relative_path.clone())
        .collect::<BTreeSet<_>>();
    if declared_spool_paths != stored_spool_paths
        || manifest.spool_files.iter().any(|file| {
            strict_relative(&file.relative_path).is_err()
                || match file.kind {
                    BackupSpoolFileKind::Normal => {
                        !file.relative_path.starts_with("spool/main/") || file.frame_count == 0
                    }
                    BackupSpoolFileKind::Isolated => {
                        !file.relative_path.starts_with("spool/main/isolated-")
                            || file.frame_count == 0
                    }
                    BackupSpoolFileKind::EmergencyGap => {
                        !file.relative_path.starts_with("spool/emergency/") || file.frame_count != 0
                    }
                    BackupSpoolFileKind::Quarantine => {
                        !file.relative_path.starts_with("spool/quarantine/")
                            || file.frame_count != 0
                    }
                }
        })
    {
        return Err(BackupError::Corrupt);
    }
    for required in ["config/config.toml", "runtime/hook-runtime-v1.json"] {
        if !manifest
            .files
            .iter()
            .any(|item| item.relative_path == required)
        {
            return Err(BackupError::Corrupt);
        }
    }
    for table in manifest.table_states.table_names()? {
        let prefix = format!("store/{table}.lance/");
        if !manifest
            .files
            .iter()
            .any(|item| item.relative_path.starts_with(&prefix))
        {
            return Err(BackupError::Corrupt);
        }
    }
    if manifest.table_states.profile()? == "L0001"
        && manifest.files.iter().any(|item| {
            item.relative_path
                .starts_with("store/evertrace_relations.lance")
                || item
                    .relative_path
                    .starts_with("store/evertrace_search.lance")
        })
    {
        return Err(BackupError::Corrupt);
    }
    let regular_paths = manifest
        .files
        .iter()
        .filter(|item| item.kind == BackupFileKind::Regular)
        .map(|item| item.relative_path.as_str())
        .collect::<BTreeSet<_>>();
    if manifest.files.iter().any(|item| match item.kind {
        BackupFileKind::Regular => {
            item.relative_path != "config/config.toml"
                && item.relative_path != "runtime/hook-runtime-v1.json"
                && item.relative_path != "hook-v1"
                && !item
                    .relative_path
                    .starts_with("store/evertrace_journal.lance/")
                && !item
                    .relative_path
                    .starts_with("store/evertrace_objects.lance/")
                && !item
                    .relative_path
                    .starts_with("store/evertrace_relations.lance/")
                && !item
                    .relative_path
                    .starts_with("store/evertrace_search.lance/")
                && !item.relative_path.starts_with("cas/blobs/")
                && !declared_spool_paths.contains(&item.relative_path)
                && !item.relative_path.starts_with("hooks/")
                && !valid_gc_report_path(&item.relative_path)
        }
        BackupFileKind::Directory => {
            let prefix = format!("{}/", item.relative_path);
            !regular_paths.iter().any(|path| path.starts_with(&prefix))
        }
    }) {
        return Err(BackupError::Corrupt);
    }
    if manifest.files.iter().any(|item| {
        item.relative_path == MANIFEST_NAME
            || item.relative_path.starts_with("backups/")
            || item.relative_path.starts_with("keys/")
            || item.relative_path.contains("evertraced-v1.sock")
            || matches!(item.kind, BackupFileKind::Regular) != item.sha256.is_some()
            || item.sha256.as_deref().is_some_and(|value| {
                value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    }) {
        return Err(BackupError::Corrupt);
    }
    Ok(())
}

fn valid_gc_report_path(path: &str) -> bool {
    path.strip_prefix("maintenance/gc-")
        .and_then(|value| value.strip_suffix(".json"))
        .is_some_and(|value| value.parse::<JobId>().is_ok())
}

fn collect_tree(
    source: &Path,
    relative: &Path,
    output: &mut Vec<PlannedSource>,
) -> Result<(), BackupError> {
    collect_tree_at_depth(source, relative, output, 0)
}

fn collect_tree_at_depth(
    source: &Path,
    relative: &Path,
    output: &mut Vec<PlannedSource>,
    depth: usize,
) -> Result<(), BackupError> {
    if depth > MAX_BACKUP_DEPTH {
        return Err(BackupError::ResourceExhausted);
    }
    let metadata = fs::symlink_metadata(source).map_err(|_| BackupError::Io)?;
    validate_source_metadata(&metadata, &BackupFileKind::Directory)?;
    push_source(source, relative, BackupFileKind::Directory, output)?;
    let directory_index = output
        .len()
        .checked_sub(1)
        .ok_or(BackupError::ResourceExhausted)?;
    let mut children = Vec::new();
    for entry in fs::read_dir(source).map_err(|_| BackupError::Io)? {
        if children
            .len()
            .checked_add(1)
            .is_none_or(|count| count > MAX_BACKUP_FILES)
        {
            return Err(BackupError::ResourceExhausted);
        }
        children.push(entry.map_err(|_| BackupError::Io)?.path());
    }
    children.sort();
    for child in children {
        let name = child.file_name().ok_or(BackupError::InvalidInput)?;
        let child_relative = relative.join(name);
        let metadata = fs::symlink_metadata(&child).map_err(|_| BackupError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(BackupError::Corrupt);
        }
        if metadata.is_dir() {
            collect_tree_at_depth(
                &child,
                &child_relative,
                output,
                depth.checked_add(1).ok_or(BackupError::ResourceExhausted)?,
            )?;
        } else if metadata.is_file() {
            push_source(&child, &child_relative, BackupFileKind::Regular, output)?;
        } else {
            return Err(BackupError::Corrupt);
        }
        if output.len() > MAX_BACKUP_FILES {
            return Err(BackupError::ResourceExhausted);
        }
    }
    revalidate_source(&output[directory_index])?;
    Ok(())
}

fn push_source(
    source: &Path,
    relative: &Path,
    kind: BackupFileKind,
    output: &mut Vec<PlannedSource>,
) -> Result<(), BackupError> {
    if output.len() == MAX_BACKUP_FILES {
        return Err(BackupError::ResourceExhausted);
    }
    strict_relative(relative.to_str().ok_or(BackupError::InvalidInput)?)?;
    let metadata = fs::symlink_metadata(source).map_err(|_| BackupError::Io)?;
    validate_source_metadata(&metadata, &kind)?;
    output.push(PlannedSource {
        hook_directories: Vec::new(),
        source: source.to_owned(),
        relative: relative.to_owned(),
        kind,
        identity: identity(&metadata),
    });
    Ok(())
}

fn push_frozen_source(
    source: &Path,
    relative: &Path,
    expected: FileIdentity,
    output: &mut Vec<PlannedSource>,
) -> Result<(), BackupError> {
    if output.len() == MAX_BACKUP_FILES {
        return Err(BackupError::ResourceExhausted);
    }
    strict_relative(relative.to_str().ok_or(BackupError::InvalidInput)?)?;
    let planned = PlannedSource {
        hook_directories: Vec::new(),
        source: source.to_owned(),
        relative: relative.to_owned(),
        kind: BackupFileKind::Regular,
        identity: expected,
    };
    revalidate_source(&planned)?;
    output.push(planned);
    Ok(())
}

const fn map_spool_file_kind(kind: SpoolBackupFileKind) -> BackupSpoolFileKind {
    match kind {
        SpoolBackupFileKind::Normal => BackupSpoolFileKind::Normal,
        SpoolBackupFileKind::Isolated => BackupSpoolFileKind::Isolated,
        SpoolBackupFileKind::EmergencyGap => BackupSpoolFileKind::EmergencyGap,
        SpoolBackupFileKind::Quarantine => BackupSpoolFileKind::Quarantine,
    }
}

fn open_source(source: &PlannedSource) -> Result<File, BackupError> {
    revalidate_source(source)?;
    let file = if let Some((root, _, _)) = source.hook_directories.last() {
        evertrace_capture::ConfinedRoot::open_owned_private(root)
            .and_then(|root| root.open_regular_file(&source.relative))
            .map_err(|_| BackupError::IdentityChanged)?
    } else {
        open_regular_nofollow(&source.source).map_err(|_| BackupError::IdentityChanged)?
    };
    let opened = file.metadata().map_err(|_| BackupError::Io)?;
    if identity(&opened) != source.identity || !opened.is_file() {
        return Err(BackupError::IdentityChanged);
    }
    revalidate_source(source)?;
    Ok(file)
}

fn revalidate_source(source: &PlannedSource) -> Result<(), BackupError> {
    let mut parent = source.source.as_path();
    for (path, device, inode) in &source.hook_directories {
        parent = parent.parent().ok_or(BackupError::InvalidInput)?;
        let metadata = fs::symlink_metadata(path).map_err(|_| BackupError::IdentityChanged)?;
        validate_source_metadata(&metadata, &BackupFileKind::Directory)?;
        if path != parent || metadata.dev() != *device || metadata.ino() != *inode {
            return Err(BackupError::IdentityChanged);
        }
    }
    let metadata = fs::symlink_metadata(&source.source).map_err(|_| BackupError::Io)?;
    validate_source_metadata(&metadata, &source.kind)?;
    if identity(&metadata) != source.identity {
        return Err(BackupError::IdentityChanged);
    }
    Ok(())
}

fn revalidate_directory(directory: &PlannedDirectory) -> Result<(), BackupError> {
    let metadata = fs::symlink_metadata(&directory.path).map_err(|_| BackupError::Io)?;
    validate_source_metadata(&metadata, &BackupFileKind::Directory)?;
    // Directory timestamps may advance when Hook publishes post-boundary work. The
    // pinned directory inode plus every selected file's full identity is the frozen
    // prefix; later entries remain live and are intentionally outside this backup.
    if metadata.dev() != directory.identity.device || metadata.ino() != directory.identity.inode {
        return Err(BackupError::IdentityChanged);
    }
    Ok(())
}

fn validate_source_metadata(
    metadata: &fs::Metadata,
    kind: &BackupFileKind,
) -> Result<(), BackupError> {
    if metadata.file_type().is_symlink()
        || metadata.uid() != current_uid()?
        || metadata.permissions().mode() & 0o022 != 0
        || (matches!(kind, BackupFileKind::Directory) && !metadata.is_dir())
        || (matches!(kind, BackupFileKind::Regular) && !metadata.is_file())
    {
        return Err(BackupError::Corrupt);
    }
    Ok(())
}

fn private_file_identity(path: &Path) -> Result<FileIdentity, BackupError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BackupError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != current_uid()?
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(BackupError::Corrupt);
    }
    Ok(identity(&metadata))
}

fn private_directory_identity(path: &Path) -> Result<FileIdentity, BackupError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BackupError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != current_uid()?
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(BackupError::Corrupt);
    }
    Ok(identity(&metadata))
}

fn open_exact_file(path: &Path, expected: FileIdentity) -> Result<File, BackupError> {
    let file = open_regular_nofollow(path).map_err(|_| BackupError::IdentityChanged)?;
    let opened = file.metadata().map_err(|_| BackupError::Io)?;
    if identity(&opened) != expected || !opened.is_file() {
        return Err(BackupError::IdentityChanged);
    }
    Ok(file)
}

fn identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn enumerate_backup_tree(directory: &Path) -> Result<Vec<(String, BackupFileKind)>, BackupError> {
    fn visit(
        root: &Path,
        current: &Path,
        output: &mut Vec<(String, BackupFileKind)>,
        depth: usize,
    ) -> Result<(), BackupError> {
        if depth > MAX_BACKUP_DEPTH {
            return Err(BackupError::ResourceExhausted);
        }
        let mut children = Vec::new();
        for entry in fs::read_dir(current).map_err(|_| BackupError::Io)? {
            if output
                .len()
                .checked_add(children.len())
                .and_then(|count| count.checked_add(1))
                .is_none_or(|count| count > MAX_BACKUP_FILES + 1)
            {
                return Err(BackupError::ResourceExhausted);
            }
            children.push(entry.map_err(|_| BackupError::Io)?.path());
        }
        children.sort();
        for path in children {
            let metadata = fs::symlink_metadata(&path).map_err(|_| BackupError::Io)?;
            if metadata.file_type().is_symlink() || metadata.uid() != current_uid()? {
                return Err(BackupError::Corrupt);
            }
            let relative = path.strip_prefix(root).map_err(|_| BackupError::Corrupt)?;
            let relative = relative_string(relative)?;
            if metadata.is_dir() {
                if metadata.permissions().mode() & 0o777 != 0o700 {
                    return Err(BackupError::Corrupt);
                }
                if output.len() > MAX_BACKUP_FILES {
                    return Err(BackupError::ResourceExhausted);
                }
                output.push((relative, BackupFileKind::Directory));
                visit(
                    root,
                    &path,
                    output,
                    depth.checked_add(1).ok_or(BackupError::ResourceExhausted)?,
                )?;
                if private_directory_identity(&path)? != identity(&metadata) {
                    return Err(BackupError::IdentityChanged);
                }
            } else if metadata.is_file() {
                if metadata.permissions().mode() & 0o777 != 0o600 {
                    return Err(BackupError::Corrupt);
                }
                if output.len() > MAX_BACKUP_FILES {
                    return Err(BackupError::ResourceExhausted);
                }
                output.push((relative, BackupFileKind::Regular));
            } else {
                return Err(BackupError::Corrupt);
            }
        }
        Ok(())
    }
    let mut output = Vec::new();
    visit(directory, directory, &mut output, 0)?;
    output.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(output)
}

fn strict_relative(value: &str) -> Result<PathBuf, BackupError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(item) if !item.is_empty()))
    {
        return Err(BackupError::Corrupt);
    }
    Ok(path.to_owned())
}

fn relative_string(path: &Path) -> Result<String, BackupError> {
    let value = path.to_str().ok_or(BackupError::Corrupt)?.to_owned();
    strict_relative(&value)?;
    Ok(value)
}

fn ensure_staging_parents(root: &Path, parent: &Path) -> Result<(), BackupError> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| BackupError::InvalidInput)?;
    let mut current = root.to_owned();
    for component in relative.components() {
        let Component::Normal(value) = component else {
            return Err(BackupError::InvalidInput);
        };
        current.push(value);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || metadata.uid() != current_uid()?
                    || metadata.permissions().mode() & 0o777 != 0o700
                {
                    return Err(BackupError::Corrupt);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                DirBuilder::new()
                    .mode(0o700)
                    .create(&current)
                    .map_err(|_| BackupError::Io)?;
            }
            Err(_) => return Err(BackupError::Io),
        }
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), BackupError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|_| BackupError::Io)?;
            File::open(path)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| BackupError::Io)
        }
        Err(_) => Err(BackupError::Io),
    }
}

fn validate_private_directory(path: &Path) -> Result<(), BackupError> {
    private_directory_identity(path).map(|_| ())
}

fn remove_owned_staging(path: &Path) -> Result<(), BackupError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_private_directory(path)?;
            if enumerate_backup_tree(path)?.iter().any(|(relative, _)| {
                strict_relative(relative).is_err()
                    || relative.starts_with("../")
                    || relative.contains("/.staging-")
            }) {
                return Err(BackupError::Corrupt);
            }
            fs::remove_dir_all(path).map_err(|_| BackupError::Io)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(BackupError::Io),
    }
}

fn current_uid() -> Result<u32, BackupError> {
    fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .map_err(|_| BackupError::Io)
}

fn map_store(_: StoreError) -> BackupError {
    BackupError::Corrupt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watermark_row(source: &str, revision: &str, sequence: u64) -> crate::ObjectRow {
        let payload = JournalPayload::SourceIngestWatermark(crate::SourceIngestWatermark {
            source_instance_id: SourceInstanceId::parse(source).unwrap(),
            source_revision: SourceRevision::parse(revision).unwrap(),
            source_sequence: sequence,
            confirmed_prefix_digest: None,
        });
        crate::ObjectRow {
            row_id: format!("runtime:watermark:{source}:{revision}"),
            row_kind: crate::ObjectRowKind::Data,
            row_class: Some(crate::ObjectRowClass::Runtime),
            object_family: None,
            object_kind: None,
            object_id: None,
            current_revision_id: None,
            lifecycle: None,
            epistemic: None,
            authority: None,
            publication_state: None,
            support_state: None,
            project_id: None,
            repository_id: None,
            worktree_id: None,
            task_id: None,
            workstream_id: None,
            session_id: None,
            payload_json: Some(serde_json::to_string(&payload).unwrap()),
            source_event_seq: sequence,
            projection_generation: 1,
        }
    }

    #[test]
    fn committed_source_watermarks_remain_exact_per_source() {
        let snapshot = ProjectionSnapshot {
            frontier: 900,
            rows: vec![
                watermark_row("source-b", "revision-b", 900),
                watermark_row("source-a", "revision-a", 3),
            ],
        };
        let (watermarks, outbox) = backup_watermarks(&snapshot).unwrap();
        assert_eq!(outbox, 0);
        assert_eq!(watermarks.len(), 2);
        assert_eq!(watermarks[0].source_instance_id.as_str(), "source-a");
        assert_eq!(watermarks[0].source_sequence, 3);
        assert_eq!(watermarks[1].source_instance_id.as_str(), "source-b");
        assert_eq!(watermarks[1].source_sequence, 900);
    }

    #[test]
    fn verify_identity_checks_reject_inflight_path_replacement() {
        let root = tempfile::TempDir::new().unwrap();
        let path = root.path().join("entry");
        fs::write(&path, b"same-length").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let expected = private_file_identity(&path).unwrap();
        open_exact_file(&path, expected).unwrap();

        let original = root.path().join("original");
        fs::rename(&path, &original).unwrap();
        fs::write(&path, b"same-length").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            open_exact_file(&path, expected).unwrap_err(),
            BackupError::IdentityChanged
        );
        assert_eq!(
            push_frozen_source(
                &path,
                Path::new("spool/main/frozen.sealed"),
                expected,
                &mut Vec::new(),
            )
            .unwrap_err(),
            BackupError::IdentityChanged
        );
        assert_ne!(private_file_identity(&path).unwrap(), expected);

        let generation = root.path().join("generation");
        fs::create_dir(&generation).unwrap();
        fs::set_permissions(&generation, fs::Permissions::from_mode(0o700)).unwrap();
        let hook = generation.join("hook");
        fs::write(&hook, b"hook").unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o600)).unwrap();
        let mut sources = Vec::new();
        push_source(
            &hook,
            Path::new("generation/hook"),
            BackupFileKind::Regular,
            &mut sources,
        )
        .unwrap();
        let source = sources.last_mut().unwrap();
        for directory in [&generation, root.path()] {
            let metadata = fs::metadata(directory).unwrap();
            source
                .hook_directories
                .push((directory.to_owned(), metadata.dev(), metadata.ino()));
        }
        open_source(source).unwrap();
        let displaced = root.path().join("displaced");
        fs::rename(&generation, &displaced).unwrap();
        // Moving the same directory back through a symlink preserves leaf identity.
        std::os::unix::fs::symlink(&displaced, &generation).unwrap();
        assert!(open_source(source).is_err());
        fs::remove_file(&generation).unwrap();
        fs::create_dir(&generation).unwrap();
        fs::set_permissions(&generation, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(displaced.join("hook"), &hook).unwrap();
        // Even the original regular file cannot legitimize a replacement directory.
        assert_eq!(
            open_source(source).unwrap_err(),
            BackupError::IdentityChanged
        );
    }
}
