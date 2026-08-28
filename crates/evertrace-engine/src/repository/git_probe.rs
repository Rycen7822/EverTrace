//! Read-only bounded Git probe evidence. This is the only product code path
//! that executes `git`: it can only express the closed [`GitProbeOp`]
//! allowlist, always runs with `GIT_OPTIONAL_LOCKS=0`, no pager and a fixed
//! `LC_ALL=C` locale, and enforces [`ProbeLimits`] by killing the child
//! process as soon as any bound is exceeded.

use std::{
    cell::Cell,
    collections::BTreeSet,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    evidence::hex,
    repository::{
        FilesystemIdentity, GitObjectFormat, GitOperation, ProbeUnavailableReason,
        REMOTE_FINGERPRINT_PREFIX, SnapshotField, UntrackedCaptureScope,
    },
};
use thiserror::Error;

pub const GIT_PROBE_SCHEMA_VERSION: u32 = 1;

const REMOTE_FINGERPRINT_TAG: &str = "s11_remote_fingerprint_v1";
const TRACKED_DIFF_DIGEST_TAG: &str = "worktree_tracked_diff_v1";
const INDEX_DIGEST_TAG: &str = "worktree_index_v1";
const UNTRACKED_DIGEST_TAG: &str = "worktree_untracked_manifest_v1";
const PATCH_EQUIVALENCE_TAG: &str = "worktree_patch_equivalence_v1";

const POLL_INTERVAL: Duration = Duration::from_millis(5);

thread_local! {
    static SHARED_PROBE_DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// Applies one absolute budget to every closed Git operation performed by
/// `operation` on this blocking worker thread. Nested scopes can only shorten
/// the active deadline.
pub(crate) fn with_probe_deadline<T>(deadline: Instant, operation: impl FnOnce() -> T) -> T {
    SHARED_PROBE_DEADLINE.with(|slot| {
        let previous = slot.replace(Some(
            slot.get().map_or(deadline, |value| value.min(deadline)),
        ));
        struct Reset<'a>(&'a Cell<Option<Instant>>, Option<Instant>);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.set(self.1);
            }
        }
        let _reset = Reset(slot, previous);
        operation()
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostTrustDecision {
    Trusted,
    Untrusted,
    Unknown,
    Revoked,
}

impl HostTrustDecision {
    pub const fn permits_content_probe(self) -> bool {
        matches!(self, Self::Trusted)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeLimits {
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub max_records: usize,
    pub max_untracked_paths: usize,
    pub max_diff_bytes: usize,
    pub max_duration_ms: u64,
}

impl ProbeLimits {
    pub fn validate(&self) -> Result<(), RepositoryProbeError> {
        if self.max_stdout_bytes == 0
            || self.max_stderr_bytes == 0
            || self.max_records == 0
            || self.max_untracked_paths == 0
            || self.max_diff_bytes == 0
            || self.max_duration_ms == 0
        {
            return Err(RepositoryProbeError::InvalidInput);
        }
        Ok(())
    }
}

impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            max_stdout_bytes: 1 << 20,
            max_stderr_bytes: 16 << 10,
            max_records: 4096,
            max_untracked_paths: 1024,
            max_diff_bytes: 1 << 20,
            max_duration_ms: 10_000,
        }
    }
}

/// A validated Git object id; the closed probe ops only accept this type for
/// revision arguments, so arbitrary argv injection is not expressible.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GitOid(String);

impl GitOid {
    pub fn parse(value: &str) -> Result<Self, RepositoryProbeError> {
        if !(value.len() == 40 || value.len() == 64)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RepositoryProbeError::InvalidInput);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The closed set of read-only Git operations the probe can execute. Anything
/// outside this enum is not expressible in product code; [`GitProbeOp::argv`]
/// is the single argv construction point and is covered by an audit test.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitProbeOp {
    RevParseGitDir,
    RevParseCommonDir,
    RevParseShowToplevel,
    RevParseIsInsideWorkTree,
    RevParseShowObjectFormat,
    RevParseVerifyHead,
    RevParseHeadTree,
    SymbolicRefHead,
    StatusPorcelainV2,
    WorktreeListPorcelain,
    ForEachRefNull,
    MergeBaseIsAncestor {
        ancestor: GitOid,
        descendant: GitOid,
    },
    CatFileBatchCheck {
        oid: GitOid,
    },
    DiffRawRange {
        base: GitOid,
        tip: GitOid,
    },
    LsFilesStage,
    LsFilesOthersStandard,
    LsFilesOthersIncludingIgnored,
    LsFilesOthersIgnoredOnly,
    DiffBinary,
    DiffCachedBinary,
    ConfigGetRemoteUrls,
}

impl GitProbeOp {
    /// Single audit point for probe argv construction. The argv never goes
    /// through a shell and always starts with the fixed `--no-pager` prefix.
    pub fn argv(&self) -> Vec<String> {
        let mut argv = vec!["--no-pager".to_owned()];
        match self {
            Self::RevParseGitDir => argv.extend(["rev-parse", "--git-dir"].map(str::to_owned)),
            Self::RevParseCommonDir => {
                argv.extend(["rev-parse", "--git-common-dir"].map(str::to_owned))
            }
            Self::RevParseShowToplevel => {
                argv.extend(["rev-parse", "--show-toplevel"].map(str::to_owned))
            }
            Self::RevParseIsInsideWorkTree => {
                argv.extend(["rev-parse", "--is-inside-work-tree"].map(str::to_owned))
            }
            Self::RevParseShowObjectFormat => {
                argv.extend(["rev-parse", "--show-object-format"].map(str::to_owned))
            }
            Self::RevParseVerifyHead => {
                argv.extend(["rev-parse", "--verify", "HEAD"].map(str::to_owned))
            }
            Self::RevParseHeadTree => {
                argv.extend(["rev-parse", "--verify", "HEAD^{tree}"].map(str::to_owned))
            }
            Self::SymbolicRefHead => argv.extend(["symbolic-ref", "HEAD"].map(str::to_owned)),
            Self::StatusPorcelainV2 => argv.extend(
                ["status", "--porcelain=v2", "-z", "--untracked-files=all"].map(str::to_owned),
            ),
            Self::WorktreeListPorcelain => {
                argv.extend(["worktree", "list", "--porcelain", "-z"].map(str::to_owned))
            }
            Self::ForEachRefNull => argv
                .extend(["for-each-ref", "--format=%(refname)%00%(objectname)"].map(str::to_owned)),
            Self::MergeBaseIsAncestor {
                ancestor,
                descendant,
            } => argv.extend(
                [
                    "merge-base",
                    "--is-ancestor",
                    ancestor.as_str(),
                    descendant.as_str(),
                ]
                .map(str::to_owned),
            ),
            Self::CatFileBatchCheck { .. } => {
                // The OID travels over stdin (see `stdin_bytes`), never argv.
                argv.extend(["cat-file", "--batch-check"].map(str::to_owned))
            }
            Self::DiffRawRange { base, tip } => {
                argv.extend(["diff", "--raw", "-z", base.as_str(), tip.as_str()].map(str::to_owned))
            }
            Self::LsFilesStage => argv.extend(["ls-files", "--stage", "-z"].map(str::to_owned)),
            Self::LsFilesOthersStandard => {
                argv.extend(["ls-files", "--others", "-z", "--exclude-standard"].map(str::to_owned))
            }
            Self::LsFilesOthersIncludingIgnored => {
                argv.extend(["ls-files", "--others", "-z"].map(str::to_owned))
            }
            Self::LsFilesOthersIgnoredOnly => argv.extend(
                [
                    "ls-files",
                    "--others",
                    "--ignored",
                    "-z",
                    "--exclude-standard",
                ]
                .map(str::to_owned),
            ),
            Self::DiffBinary => argv
                .extend(["diff", "--binary", "--no-ext-diff", "--no-textconv"].map(str::to_owned)),
            Self::DiffCachedBinary => argv.extend(
                [
                    "diff",
                    "--cached",
                    "--binary",
                    "--no-ext-diff",
                    "--no-textconv",
                ]
                .map(str::to_owned),
            ),
            Self::ConfigGetRemoteUrls => argv.extend(
                ["config", "--null", "--get-regexp", "^remote\\..*\\.url$"].map(str::to_owned),
            ),
        }
        argv
    }

    fn stdout_limit(&self, limits: &ProbeLimits) -> usize {
        match self {
            Self::DiffRawRange { .. } | Self::DiffBinary | Self::DiffCachedBinary => {
                limits.max_diff_bytes
            }
            _ => limits.max_stdout_bytes,
        }
    }

    /// Bytes written to the child's stdin, if the operation reads from it.
    /// Only `cat-file --batch-check` does, and it receives exactly one
    /// parser-checked OID line so no untrusted text ever reaches argv.
    fn stdin_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::CatFileBatchCheck { oid } => Some(format!("{}\n", oid.as_str()).into_bytes()),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProbeField {
    HeadOid,
    TreeOid,
    BranchRef,
    TrackedDiff,
    Index,
    UntrackedManifest,
    RefTips,
    WorktreeList,
    RemoteFingerprints,
    CommonDirFilesystem,
    ContinuityAncestry,
}

impl ProbeField {
    pub(crate) fn snapshot_field(self) -> Option<SnapshotField> {
        match self {
            Self::HeadOid => Some(SnapshotField::HeadOid),
            Self::TreeOid => Some(SnapshotField::TreeOid),
            Self::BranchRef => Some(SnapshotField::BranchRef),
            Self::TrackedDiff => Some(SnapshotField::TrackedDiffDigest),
            Self::Index => Some(SnapshotField::IndexDigest),
            Self::UntrackedManifest => Some(SnapshotField::UntrackedManifestDigest),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProbeOmission {
    pub field: ProbeField,
    pub reason: ProbeUnavailableReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorktreeAdminEntry {
    pub path: String,
    pub gitdir: Option<String>,
    pub head: Option<GitOid>,
    pub branch: Option<String>,
    pub detached: bool,
    pub locked: bool,
    pub prunable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminPathProbe {
    pub path: String,
    pub present: bool,
}

/// Versioned typed probe evidence; the resolver consumes only this structure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitProbeEvidence {
    pub probe_schema_version: u32,
    pub candidate_path: String,
    pub occurred_at_us: i64,
    pub evidence_refs: Vec<String>,
    pub unavailable_reason: Option<ProbeUnavailableReason>,
    pub worktree_root: Option<String>,
    pub worktree_root_filesystem: Option<FilesystemIdentity>,
    pub git_dir: Option<String>,
    pub common_dir: Option<String>,
    pub common_dir_filesystem: Option<FilesystemIdentity>,
    pub object_format: Option<GitObjectFormat>,
    pub head_oid: Option<GitOid>,
    /// Known historical HEADs positively proven to be ancestors of the
    /// current HEAD by `merge-base --is-ancestor`; sorted and deduplicated.
    pub head_ancestors: Vec<GitOid>,
    pub branch_ref: Option<String>,
    pub detached_head: Option<bool>,
    pub tree_oid: Option<GitOid>,
    pub tracked_diff_digest: Option<String>,
    pub index_digest: Option<String>,
    pub untracked_manifest_digest: Option<String>,
    pub ref_tips: Vec<(String, GitOid)>,
    pub worktree_entries: Vec<WorktreeAdminEntry>,
    pub worktree_list_complete: bool,
    pub remote_fingerprints: Vec<String>,
    pub git_operation: GitOperation,
    pub admin_path_probes: Vec<AdminPathProbe>,
    pub omissions: Vec<ProbeOmission>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryGitCaptureItem {
    WorktreeStatus,
    TrackedDiff,
    IndexDiff,
    IndexEntries,
    UntrackedManifest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryGitCaptureOmission {
    pub item: RecoveryGitCaptureItem,
    pub reason: ProbeUnavailableReason,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryGitCaptureEvidence {
    pub fingerprint: Option<String>,
    pub tracked_diff: Option<Vec<u8>>,
    pub index_diff: Option<Vec<u8>>,
    pub index_entries: Option<Vec<u8>>,
    pub untracked_paths: Vec<std::path::PathBuf>,
    pub omissions: Vec<RecoveryGitCaptureOmission>,
}

impl std::fmt::Debug for RecoveryGitCaptureEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryGitCaptureEvidence")
            .field("has_fingerprint", &self.fingerprint.is_some())
            .field(
                "tracked_diff_bytes",
                &self.tracked_diff.as_ref().map(Vec::len),
            )
            .field("index_diff_bytes", &self.index_diff.as_ref().map(Vec::len))
            .field(
                "index_entries_bytes",
                &self.index_entries.as_ref().map(Vec::len),
            )
            .field("untracked_path_count", &self.untracked_paths.len())
            .field("omissions", &self.omissions)
            .finish()
    }
}

pub fn probe_recovery_capture(
    cwd: &Path,
    limits: &ProbeLimits,
) -> Result<RecoveryGitCaptureEvidence, RepositoryProbeError> {
    probe_recovery_capture_scoped(cwd, limits, UntrackedCaptureScope::Standard)
}

pub fn probe_recovery_capture_scoped(
    cwd: &Path,
    limits: &ProbeLimits,
    scope: UntrackedCaptureScope,
) -> Result<RecoveryGitCaptureEvidence, RepositoryProbeError> {
    limits.validate()?;
    let canonical = std::fs::canonicalize(cwd).map_err(|_| RepositoryProbeError::InvalidInput)?;
    probe_recovery_capture_at(&canonical, limits, scope)
}

pub fn probe_recovery_capture_scoped_pinned(
    cwd: &Path,
    expected_identity: FilesystemIdentity,
    limits: &ProbeLimits,
    scope: UntrackedCaptureScope,
) -> Result<RecoveryGitCaptureEvidence, RepositoryProbeError> {
    limits.validate()?;
    validate_pinned_cwd(cwd, expected_identity)?;
    probe_recovery_capture_at(cwd, limits, scope)
}

fn probe_recovery_capture_at(
    cwd: &Path,
    limits: &ProbeLimits,
    scope: UntrackedCaptureScope,
) -> Result<RecoveryGitCaptureEvidence, RepositoryProbeError> {
    let mut evidence = RecoveryGitCaptureEvidence {
        fingerprint: None,
        tracked_diff: None,
        index_diff: None,
        index_entries: None,
        untracked_paths: Vec::new(),
        omissions: Vec::new(),
    };
    let status = capture_op(
        cwd,
        &GitProbeOp::StatusPorcelainV2,
        limits,
        RecoveryGitCaptureItem::WorktreeStatus,
        &mut evidence.omissions,
    );
    let untracked_manifest = capture_op(
        cwd,
        &match scope {
            UntrackedCaptureScope::Standard => GitProbeOp::LsFilesOthersStandard,
            UntrackedCaptureScope::StandardAndIgnored => GitProbeOp::LsFilesOthersIncludingIgnored,
            UntrackedCaptureScope::IgnoredOnly => GitProbeOp::LsFilesOthersIgnoredOnly,
        },
        limits,
        RecoveryGitCaptureItem::UntrackedManifest,
        &mut evidence.omissions,
    );
    if let Some(manifest) = untracked_manifest.as_ref() {
        let records = manifest
            .strip_suffix(&[0])
            .unwrap_or(manifest)
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty())
            .collect::<Vec<_>>();
        let malformed = (!manifest.is_empty() && !manifest.ends_with(&[0]))
            || manifest.windows(2).any(|bytes| bytes == [0, 0]);
        if records.len() > limits.max_records {
            evidence.omissions.push(RecoveryGitCaptureOmission {
                item: RecoveryGitCaptureItem::UntrackedManifest,
                reason: ProbeUnavailableReason::OutputLimitExceeded,
            });
        } else {
            #[cfg(unix)]
            use std::os::unix::ffi::OsStringExt;
            let mut paths = BTreeSet::new();
            #[cfg(unix)]
            let invalid_record = malformed;
            #[cfg(not(unix))]
            let mut invalid_record = malformed;
            for record in records {
                #[cfg(unix)]
                paths.insert(std::path::PathBuf::from(std::ffi::OsString::from_vec(
                    record.to_vec(),
                )));
                #[cfg(not(unix))]
                match std::str::from_utf8(record) {
                    Ok(path) => {
                        paths.insert(std::path::PathBuf::from(path));
                    }
                    Err(_) => invalid_record = true,
                }
            }
            if invalid_record {
                evidence.omissions.push(RecoveryGitCaptureOmission {
                    item: RecoveryGitCaptureItem::UntrackedManifest,
                    reason: ProbeUnavailableReason::CorruptAdminMetadata,
                });
            }
            if paths.len() > limits.max_untracked_paths {
                evidence.omissions.push(RecoveryGitCaptureOmission {
                    item: RecoveryGitCaptureItem::UntrackedManifest,
                    reason: ProbeUnavailableReason::OutputLimitExceeded,
                });
            } else {
                evidence.untracked_paths = paths.into_iter().collect();
            }
        }
    }
    evidence.tracked_diff = capture_op(
        cwd,
        &GitProbeOp::DiffBinary,
        limits,
        RecoveryGitCaptureItem::TrackedDiff,
        &mut evidence.omissions,
    );
    evidence.index_diff = capture_op(
        cwd,
        &GitProbeOp::DiffCachedBinary,
        limits,
        RecoveryGitCaptureItem::IndexDiff,
        &mut evidence.omissions,
    );
    evidence.index_entries = capture_op(
        cwd,
        &GitProbeOp::LsFilesStage,
        limits,
        RecoveryGitCaptureItem::IndexEntries,
        &mut evidence.omissions,
    );
    if let (
        Some(status),
        Some(tracked_diff),
        Some(index_diff),
        Some(index_entries),
        Some(untracked),
    ) = (
        status.as_ref(),
        evidence.tracked_diff.as_ref(),
        evidence.index_diff.as_ref(),
        evidence.index_entries.as_ref(),
        untracked_manifest.as_ref(),
    ) {
        let value = CanonicalValue::Map(vec![
            ("status".into(), CanonicalValue::Bytes(status.clone())),
            (
                "tracked_diff".into(),
                CanonicalValue::Bytes(tracked_diff.clone()),
            ),
            (
                "index_diff".into(),
                CanonicalValue::Bytes(index_diff.clone()),
            ),
            (
                "index_entries".into(),
                CanonicalValue::Bytes(index_entries.clone()),
            ),
            (
                "untracked_scope".into(),
                CanonicalValue::String(
                    match scope {
                        UntrackedCaptureScope::Standard => "standard",
                        UntrackedCaptureScope::StandardAndIgnored => "standard_and_ignored",
                        UntrackedCaptureScope::IgnoredOnly => "ignored_only",
                    }
                    .to_owned(),
                ),
            ),
            (
                "untracked_manifest".into(),
                CanonicalValue::Bytes(untracked.clone()),
            ),
        ]);
        evidence.fingerprint = sha256("recovery_fence_fingerprint_v2", 2, &value)
            .ok()
            .map(|value| hex(&value));
    }
    Ok(evidence)
}

fn capture_op(
    cwd: &Path,
    op: &GitProbeOp,
    limits: &ProbeLimits,
    item: RecoveryGitCaptureItem,
    omissions: &mut Vec<RecoveryGitCaptureOmission>,
) -> Option<Vec<u8>> {
    match run_op(cwd, op, limits) {
        Ok(output) if output.code == Some(0) && !output.truncated && !output.timed_out => {
            Some(output.stdout)
        }
        Ok(output) => {
            omissions.push(RecoveryGitCaptureOmission {
                item,
                reason: if output.timed_out {
                    ProbeUnavailableReason::Timeout
                } else if output.truncated {
                    ProbeUnavailableReason::OutputLimitExceeded
                } else {
                    ProbeUnavailableReason::CorruptAdminMetadata
                },
            });
            None
        }
        Err(reason) => {
            omissions.push(RecoveryGitCaptureOmission { item, reason });
            None
        }
    }
}

impl GitProbeEvidence {
    fn unavailable(
        candidate_path: String,
        occurred_at_us: i64,
        evidence_refs: Vec<String>,
        reason: ProbeUnavailableReason,
    ) -> Self {
        Self {
            probe_schema_version: GIT_PROBE_SCHEMA_VERSION,
            candidate_path,
            occurred_at_us,
            evidence_refs,
            unavailable_reason: Some(reason),
            worktree_root: None,
            worktree_root_filesystem: None,
            git_dir: None,
            common_dir: None,
            common_dir_filesystem: None,
            object_format: None,
            head_oid: None,
            head_ancestors: Vec::new(),
            branch_ref: None,
            detached_head: None,
            tree_oid: None,
            tracked_diff_digest: None,
            index_digest: None,
            untracked_manifest_digest: None,
            ref_tips: Vec::new(),
            worktree_entries: Vec::new(),
            worktree_list_complete: false,
            remote_fingerprints: Vec::new(),
            git_operation: GitOperation::None,
            admin_path_probes: Vec::new(),
            omissions: Vec::new(),
        }
    }

    fn established(
        candidate_path: String,
        occurred_at_us: i64,
        evidence_refs: Vec<String>,
        admin_path_probes: Vec<AdminPathProbe>,
    ) -> Self {
        Self {
            admin_path_probes,
            worktree_list_complete: true,
            ..Self::unavailable(
                candidate_path,
                occurred_at_us,
                evidence_refs,
                ProbeUnavailableReason::NonGit,
            )
        }
        .with_established()
    }

    fn with_established(mut self) -> Self {
        self.unavailable_reason = None;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RepositoryProbeError {
    #[error("probe input is invalid")]
    InvalidInput,
}

struct CommandOutput {
    code: Option<i32>,
    stdout: Vec<u8>,
    truncated: bool,
    timed_out: bool,
}

fn run_op(
    cwd: &Path,
    op: &GitProbeOp,
    limits: &ProbeLimits,
) -> Result<CommandOutput, ProbeUnavailableReason> {
    let stdout_limit = op.stdout_limit(limits);
    let stdin_bytes = op.stdin_bytes();
    let mut command = Command::new("git");
    command
        .args(op.argv())
        .current_dir(cwd)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .env("LC_ALL", "C")
        .stdin(if stdin_bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| match error.kind() {
        std::io::ErrorKind::PermissionDenied => ProbeUnavailableReason::PermissionDenied,
        _ => ProbeUnavailableReason::SpawnFailed,
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or(ProbeUnavailableReason::SpawnFailed)?;
    let stderr = child
        .stderr
        .take()
        .ok_or(ProbeUnavailableReason::SpawnFailed)?;
    let truncated = Arc::new(AtomicBool::new(false));
    let max_stderr_bytes = limits.max_stderr_bytes;
    let stdout_handle = thread::spawn({
        let truncated = Arc::clone(&truncated);
        move || read_bounded(stdout, stdout_limit, truncated)
    });
    let stderr_handle = thread::spawn({
        let truncated = Arc::new(AtomicBool::new(false));
        move || read_bounded(stderr, max_stderr_bytes, truncated)
    });
    if let Some(bytes) = stdin_bytes {
        // The readers are already draining, so this bounded write cannot
        // deadlock; closing stdin lets the batch command terminate.
        let mut stdin = child
            .stdin
            .take()
            .ok_or(ProbeUnavailableReason::SpawnFailed)?;
        if stdin.write_all(&bytes).is_err() {
            drop(stdin);
            terminate(&mut child);
            return Err(ProbeUnavailableReason::SpawnFailed);
        }
        drop(stdin);
    }
    let local_deadline = Instant::now() + Duration::from_millis(limits.max_duration_ms);
    let deadline = SHARED_PROBE_DEADLINE
        .with(|slot| slot.get())
        .map_or(local_deadline, |shared| shared.min(local_deadline));
    let mut timed_out = false;
    let status = loop {
        if truncated.load(Ordering::Acquire) {
            terminate(&mut child);
            break child
                .wait()
                .map_err(|_| ProbeUnavailableReason::SpawnFailed)?;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    terminate(&mut child);
                    break child
                        .wait()
                        .map_err(|_| ProbeUnavailableReason::SpawnFailed)?;
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                terminate(&mut child);
                return Err(ProbeUnavailableReason::SpawnFailed);
            }
        }
    };
    let stdout = stdout_handle
        .join()
        .map_err(|_| ProbeUnavailableReason::SpawnFailed)?;
    let _ = stderr_handle.join();
    Ok(CommandOutput {
        code: status.code(),
        stdout,
        truncated: truncated.load(Ordering::Acquire),
        timed_out,
    })
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
}

fn read_bounded(mut reader: impl Read, limit: usize, truncated: Arc<AtomicBool>) -> Vec<u8> {
    let mut output = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                let remaining = limit.saturating_sub(output.len());
                if count > remaining {
                    output.extend_from_slice(&chunk[..remaining]);
                    truncated.store(true, Ordering::Release);
                    // Drain so the child can exit; the kill from the main
                    // loop terminates it promptly either way.
                    let mut sink = [0_u8; 8192];
                    while matches!(reader.read(&mut sink), Ok(count) if count > 0) {}
                    break;
                }
                output.extend_from_slice(&chunk[..count]);
            }
        }
    }
    output
}

fn map_fs_error(error: &std::io::Error) -> ProbeUnavailableReason {
    match error.kind() {
        std::io::ErrorKind::NotFound => ProbeUnavailableReason::PathMissing,
        std::io::ErrorKind::PermissionDenied => ProbeUnavailableReason::PermissionDenied,
        _ => ProbeUnavailableReason::PermissionDenied,
    }
}

fn filesystem_identity(path: &Path) -> Result<FilesystemIdentity, ProbeUnavailableReason> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).map_err(|error| map_fs_error(&error))?;
    Ok(FilesystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn validate_pinned_cwd(
    path: &Path,
    expected_identity: FilesystemIdentity,
) -> Result<(), RepositoryProbeError> {
    let value = path.to_str().ok_or(RepositoryProbeError::InvalidInput)?;
    let prefix = format!("/proc/{}/fd/", std::process::id());
    let fd = value
        .strip_prefix(&prefix)
        .filter(|suffix| !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|suffix| suffix.parse::<i32>().ok().map(|fd| (suffix, fd)))
        .filter(|(suffix, fd)| fd.to_string() == *suffix)
        .ok_or(RepositoryProbeError::InvalidInput)?;
    let link = std::fs::read_link(path).map_err(|_| RepositoryProbeError::InvalidInput)?;
    if link.to_string_lossy().ends_with(" (deleted)") {
        return Err(RepositoryProbeError::InvalidInput);
    }
    let metadata = std::fs::metadata(path).map_err(|_| RepositoryProbeError::InvalidInput)?;
    if !metadata.is_dir()
        || filesystem_identity(path).map_err(|_| RepositoryProbeError::InvalidInput)?
            != expected_identity
    {
        return Err(RepositoryProbeError::InvalidInput);
    }
    let _ = fd;
    Ok(())
}

/// Normalizes a remote URL into a credential-free `scheme://host/path`
/// locator. Password-bearing locators fail closed (`None`); username-only
/// locators are stripped. Unparseable inputs return `None`. The returned
/// value is an intermediate only — it is hashed by [`remote_fingerprint`]
/// before it may leave this module.
fn normalize_remote_locator(raw: &str) -> Option<String> {
    if raw.bytes().any(|byte| byte == 0 || byte.is_ascii_control()) {
        return None;
    }
    if raw.contains("://") {
        let parsed = url::Url::parse(raw).ok()?;
        // A password-bearing locator never contributes a fingerprint at all;
        // stripping it and continuing would still leak the fact (and the
        // shape) of a credentialed remote.
        if parsed.password().is_some() {
            return None;
        }
        let scheme = parsed.scheme().to_ascii_lowercase();
        if scheme == "file" {
            // file URLs have an empty host; the url crate refuses credential
            // setters on them, so handle the scheme before normalizing.
            if !parsed.username().is_empty() {
                return None;
            }
            let mut path = parsed.path().to_owned();
            while path.ends_with('/') {
                path.pop();
            }
            if path.is_empty() {
                return None;
            }
            return Some(format!("file://{path}"));
        }
        let mut parsed = parsed;
        parsed.set_username("").ok()?;
        let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        // `url::Url::port()` already normalizes the scheme's default port to
        // `None`; a non-default port is part of the remote's identity and
        // stays in the canonical locator.
        let port = parsed
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        let mut path = parsed.path().to_owned();
        while path.ends_with('/') {
            path.pop();
        }
        Some(format!("{scheme}://{host}{port}{path}"))
    } else {
        if raw.starts_with('/') {
            return Some(format!("file://{raw}"));
        }
        // scp-like syntax: [user@]host:path
        let (user_host, path) = raw.split_once(':')?;
        let host = user_host.rsplit('@').next()?;
        if host.is_empty() || path.is_empty() {
            return None;
        }
        Some(format!("ssh://{}/{path}", host.to_ascii_lowercase()))
    }
}

/// The only persisted form of a remote locator: a versioned SHA-256
/// fingerprint of the normalized, credential-free locator in the closed
/// `s11-remote-fp-v1:<64 lowercase hex>` format. The raw input never appears
/// in the output, in any error, or in `Debug` output.
pub fn remote_fingerprint(raw: &str) -> Option<String> {
    let normalized = normalize_remote_locator(raw)?;
    let digest = sha256(
        REMOTE_FINGERPRINT_TAG,
        1,
        &CanonicalValue::String(normalized),
    )
    .ok()?;
    Some(format!("{REMOTE_FINGERPRINT_PREFIX}{}", hex(&digest)))
}

/// Runs the closed read-only probe against an explicit candidate path.
///
/// `known_admin_paths` carries the admin (`gitdir`) paths of currently known
/// worktrees so removal can be proven by positive evidence (admin record gone
/// from the complete worktree list *and* admin directory missing on disk).
/// `known_head_oids` carries the HEAD OIDs recorded in the current view so
/// continuity can be proven by positive ancestry evidence.
pub fn probe_repository(
    candidate_path: &Path,
    trust: HostTrustDecision,
    evidence_refs: &[String],
    occurred_at_us: i64,
    limits: &ProbeLimits,
    known_admin_paths: &[String],
    known_head_oids: &[GitOid],
) -> Result<GitProbeEvidence, RepositoryProbeError> {
    probe_repository_impl(
        candidate_path,
        None,
        trust,
        evidence_refs,
        occurred_at_us,
        limits,
        known_admin_paths,
        known_head_oids,
    )
}

/// Runs the same closed probe with a caller-validated proc-fd cwd.
///
/// This is restricted to recovery custody: the proc-fd symlink is followed
/// once to the already-open directory, while ordinary repository discovery
/// continues to reject symlink candidates.
#[allow(clippy::too_many_arguments)]
pub fn probe_repository_pinned(
    candidate_path: &Path,
    logical_target_path: &Path,
    expected_identity: FilesystemIdentity,
    trust: HostTrustDecision,
    evidence_refs: &[String],
    occurred_at_us: i64,
    limits: &ProbeLimits,
    known_admin_paths: &[String],
    known_head_oids: &[GitOid],
) -> Result<GitProbeEvidence, RepositoryProbeError> {
    validate_pinned_cwd(candidate_path, expected_identity)?;
    if !logical_target_path.is_absolute() {
        return Err(RepositoryProbeError::InvalidInput);
    }
    probe_repository_impl(
        candidate_path,
        Some((logical_target_path, expected_identity)),
        trust,
        evidence_refs,
        occurred_at_us,
        limits,
        known_admin_paths,
        known_head_oids,
    )
}

#[allow(clippy::too_many_arguments)]
fn probe_repository_impl(
    candidate_path: &Path,
    pinned: Option<(&Path, FilesystemIdentity)>,
    trust: HostTrustDecision,
    evidence_refs: &[String],
    occurred_at_us: i64,
    limits: &ProbeLimits,
    known_admin_paths: &[String],
    known_head_oids: &[GitOid],
) -> Result<GitProbeEvidence, RepositoryProbeError> {
    limits.validate()?;
    if occurred_at_us < 0 || evidence_refs.is_empty() || !candidate_path.is_absolute() {
        return Err(RepositoryProbeError::InvalidInput);
    }
    let candidate = pinned.map_or(candidate_path, |(logical, _)| logical);
    let candidate = candidate.to_string_lossy().into_owned();
    let refs = evidence_refs.to_vec();
    if !trust.permits_content_probe() {
        return Ok(GitProbeEvidence::unavailable(
            candidate,
            occurred_at_us,
            refs,
            ProbeUnavailableReason::TrustDenied,
        ));
    }
    let metadata = if pinned.is_some() {
        std::fs::metadata(candidate_path)
    } else {
        std::fs::symlink_metadata(candidate_path)
    };
    let command_cwd = match metadata {
        Ok(metadata) if metadata.is_dir() && pinned.is_some() => candidate_path.to_path_buf(),
        Ok(metadata) if metadata.is_dir() => match std::fs::canonicalize(candidate_path) {
            Ok(path) => path,
            Err(error) => {
                return Ok(GitProbeEvidence::unavailable(
                    candidate,
                    occurred_at_us,
                    refs,
                    map_fs_error(&error),
                ));
            }
        },
        Ok(_) => {
            return Ok(GitProbeEvidence::unavailable(
                candidate,
                occurred_at_us,
                refs,
                ProbeUnavailableReason::NonGit,
            ));
        }
        Err(error) => {
            return Ok(GitProbeEvidence::unavailable(
                candidate,
                occurred_at_us,
                refs,
                map_fs_error(&error),
            ));
        }
    };
    let admin_path_probes = known_admin_paths
        .iter()
        .map(|path| AdminPathProbe {
            path: path.clone(),
            present: std::fs::metadata(path).is_ok(),
        })
        .collect::<Vec<_>>();
    let mut evidence =
        GitProbeEvidence::established(candidate.clone(), occurred_at_us, refs, admin_path_probes);

    let inside = run_op(&command_cwd, &GitProbeOp::RevParseIsInsideWorkTree, limits);
    match inside {
        Ok(output) if output.code == Some(0) && output.stdout == b"true\n" => {}
        Ok(output) if output.timed_out => {
            evidence.unavailable_reason = Some(ProbeUnavailableReason::Timeout);
            return Ok(evidence);
        }
        Ok(_) => {
            // Git refused the directory. If admin metadata exists, Git
            // rejected it: corrupt, not absent.
            evidence.unavailable_reason = Some(
                if std::fs::symlink_metadata(command_cwd.join(".git")).is_ok() {
                    ProbeUnavailableReason::CorruptAdminMetadata
                } else {
                    ProbeUnavailableReason::NonGit
                },
            );
            return Ok(evidence);
        }
        Err(reason) => {
            evidence.unavailable_reason = Some(reason);
            return Ok(evidence);
        }
    }

    // From here the path is a Git worktree; individual failures degrade the
    // evidence to partial, and inconsistent admin metadata makes the whole
    // probe unavailable.
    match run_op(&command_cwd, &GitProbeOp::RevParseShowToplevel, limits) {
        Ok(output) if output.code == Some(0) => {
            evidence.worktree_root = Some(first_line(&output.stdout).unwrap_or_default());
        }
        _ => {
            evidence.unavailable_reason = Some(ProbeUnavailableReason::CorruptAdminMetadata);
            return Ok(evidence);
        }
    }
    if let Some(worktree_root) = evidence.worktree_root.as_deref() {
        evidence.worktree_root_filesystem = filesystem_identity(Path::new(worktree_root)).ok();
        if evidence.worktree_root_filesystem.is_none() {
            evidence.unavailable_reason = Some(ProbeUnavailableReason::PathMissing);
            return Ok(evidence);
        }
    }
    match run_op(&command_cwd, &GitProbeOp::RevParseGitDir, limits) {
        Ok(output) if output.code == Some(0) => {
            evidence.git_dir = first_line(&output.stdout).map(|value| {
                pinned_absolutize(&command_cwd, pinned.map(|value| value.0), &value)
                    .to_string_lossy()
                    .into_owned()
            });
        }
        _ => {
            evidence.unavailable_reason = Some(ProbeUnavailableReason::CorruptAdminMetadata);
            return Ok(evidence);
        }
    }
    match run_op(&command_cwd, &GitProbeOp::RevParseCommonDir, limits) {
        Ok(output) if output.code == Some(0) => {
            evidence.common_dir = first_line(&output.stdout).map(|value| {
                pinned_absolutize(&command_cwd, pinned.map(|value| value.0), &value)
                    .to_string_lossy()
                    .into_owned()
            });
        }
        _ => {
            evidence.unavailable_reason = Some(ProbeUnavailableReason::CorruptAdminMetadata);
            return Ok(evidence);
        }
    }
    match run_op(&command_cwd, &GitProbeOp::RevParseShowObjectFormat, limits) {
        Ok(output) if output.code == Some(0) => {
            evidence.object_format =
                first_line(&output.stdout).and_then(|value| GitObjectFormat::parse(&value).ok());
            if evidence.object_format.is_none() {
                evidence.unavailable_reason = Some(ProbeUnavailableReason::CorruptAdminMetadata);
                return Ok(evidence);
            }
        }
        _ => {
            evidence.unavailable_reason = Some(ProbeUnavailableReason::CorruptAdminMetadata);
            return Ok(evidence);
        }
    }
    if let Some(common_dir) = evidence.common_dir.clone() {
        match filesystem_identity(Path::new(&common_dir)) {
            Ok(identity) => evidence.common_dir_filesystem = Some(identity),
            Err(reason) => evidence.omissions.push(ProbeOmission {
                field: ProbeField::CommonDirFilesystem,
                reason,
            }),
        }
    }
    probe_head(&command_cwd, limits, &mut evidence);
    probe_status(&command_cwd, limits, &mut evidence);
    probe_index(&command_cwd, limits, &mut evidence);
    probe_refs(&command_cwd, limits, &mut evidence);
    probe_continuity(&command_cwd, limits, &mut evidence, known_head_oids);
    probe_remotes(&command_cwd, limits, &mut evidence);
    probe_git_operation(&evidence.git_dir.clone(), &mut evidence);
    probe_worktree_entries(&command_cwd, pinned.is_none(), limits, &mut evidence);
    Ok(evidence)
}

fn probe_head(canonical: &Path, limits: &ProbeLimits, evidence: &mut GitProbeEvidence) {
    let verify = run_op(canonical, &GitProbeOp::RevParseVerifyHead, limits);
    let symbolic = run_op(canonical, &GitProbeOp::SymbolicRefHead, limits);
    match (verify, symbolic) {
        (Ok(head), branch) if head.code == Some(0) => {
            evidence.head_oid =
                first_line(&head.stdout).and_then(|value| GitOid::parse(&value).ok());
            if evidence.head_oid.is_none() {
                evidence.unavailable_reason = Some(ProbeUnavailableReason::CorruptAdminMetadata);
                return;
            }
            match branch {
                Ok(branch) if branch.code == Some(0) => {
                    evidence.branch_ref = first_line(&branch.stdout);
                    evidence.detached_head = Some(false);
                }
                Ok(_) => {
                    // HEAD resolves but is not a symbolic ref: detached. Git
                    // exits 1 or 128 here depending on version.
                    evidence.detached_head = Some(true);
                }
                Err(reason) => evidence.omissions.push(ProbeOmission {
                    field: ProbeField::BranchRef,
                    reason,
                }),
            }
            match run_op(canonical, &GitProbeOp::RevParseHeadTree, limits) {
                Ok(tree) if tree.code == Some(0) => {
                    evidence.tree_oid =
                        first_line(&tree.stdout).and_then(|value| GitOid::parse(&value).ok());
                    if evidence.tree_oid.is_none() {
                        evidence.omissions.push(ProbeOmission {
                            field: ProbeField::TreeOid,
                            reason: ProbeUnavailableReason::CorruptAdminMetadata,
                        });
                    }
                }
                _ => evidence.omissions.push(ProbeOmission {
                    field: ProbeField::TreeOid,
                    reason: ProbeUnavailableReason::CorruptAdminMetadata,
                }),
            }
        }
        (Ok(_), Ok(branch)) if branch.code == Some(0) => {
            // Unborn HEAD on a valid branch: not corruption.
            evidence.branch_ref = first_line(&branch.stdout);
            evidence.detached_head = Some(false);
        }
        (Ok(_), _) => {
            evidence.unavailable_reason = Some(ProbeUnavailableReason::CorruptAdminMetadata);
        }
        (Err(reason), _) => {
            evidence.unavailable_reason = Some(reason);
        }
    }
}

fn probe_status(canonical: &Path, limits: &ProbeLimits, evidence: &mut GitProbeEvidence) {
    match run_op(canonical, &GitProbeOp::StatusPorcelainV2, limits) {
        Ok(output) if output.code == Some(0) && !output.truncated && !output.timed_out => {
            let records = output
                .stdout
                .split(|byte| *byte == 0)
                .filter(|record| !record.is_empty())
                .collect::<Vec<_>>();
            if records.len() > limits.max_records {
                evidence.omissions.push(ProbeOmission {
                    field: ProbeField::TrackedDiff,
                    reason: ProbeUnavailableReason::OutputLimitExceeded,
                });
                evidence.omissions.push(ProbeOmission {
                    field: ProbeField::UntrackedManifest,
                    reason: ProbeUnavailableReason::OutputLimitExceeded,
                });
                return;
            }
            let digest = sha256(
                TRACKED_DIFF_DIGEST_TAG,
                1,
                &CanonicalValue::Bytes(output.stdout.clone()),
            );
            evidence.tracked_diff_digest = digest.ok().map(|value| hex(&value));
            let mut invalid_untracked = false;
            let untracked = records
                .iter()
                .filter_map(|record| match std::str::from_utf8(record) {
                    Ok(record) => record.strip_prefix("? ").map(str::to_owned),
                    Err(_) => {
                        if record.starts_with(b"? ") {
                            invalid_untracked = true;
                        }
                        None
                    }
                })
                .collect::<BTreeSet<_>>();
            if invalid_untracked {
                evidence.omissions.push(ProbeOmission {
                    field: ProbeField::UntrackedManifest,
                    reason: ProbeUnavailableReason::CorruptAdminMetadata,
                });
            }
            if untracked.len() > limits.max_untracked_paths {
                evidence.omissions.push(ProbeOmission {
                    field: ProbeField::UntrackedManifest,
                    reason: ProbeUnavailableReason::OutputLimitExceeded,
                });
            } else {
                let manifest = CanonicalValue::Sequence(
                    untracked.into_iter().map(CanonicalValue::String).collect(),
                );
                evidence.untracked_manifest_digest = sha256(UNTRACKED_DIGEST_TAG, 1, &manifest)
                    .ok()
                    .map(|value| hex(&value));
            }
        }
        Ok(output) => {
            let reason = if output.timed_out {
                ProbeUnavailableReason::Timeout
            } else if output.truncated {
                ProbeUnavailableReason::OutputLimitExceeded
            } else {
                ProbeUnavailableReason::CorruptAdminMetadata
            };
            evidence.omissions.push(ProbeOmission {
                field: ProbeField::TrackedDiff,
                reason,
            });
            evidence.omissions.push(ProbeOmission {
                field: ProbeField::UntrackedManifest,
                reason,
            });
        }
        Err(reason) => {
            evidence.omissions.push(ProbeOmission {
                field: ProbeField::TrackedDiff,
                reason,
            });
            evidence.omissions.push(ProbeOmission {
                field: ProbeField::UntrackedManifest,
                reason,
            });
        }
    }
}

fn probe_index(canonical: &Path, limits: &ProbeLimits, evidence: &mut GitProbeEvidence) {
    match run_op(canonical, &GitProbeOp::LsFilesStage, limits) {
        Ok(output) if output.code == Some(0) && !output.truncated && !output.timed_out => {
            evidence.index_digest =
                sha256(INDEX_DIGEST_TAG, 1, &CanonicalValue::Bytes(output.stdout))
                    .ok()
                    .map(|value| hex(&value));
        }
        Ok(output) => evidence.omissions.push(ProbeOmission {
            field: ProbeField::Index,
            reason: if output.timed_out {
                ProbeUnavailableReason::Timeout
            } else if output.truncated {
                ProbeUnavailableReason::OutputLimitExceeded
            } else {
                ProbeUnavailableReason::CorruptAdminMetadata
            },
        }),
        Err(reason) => evidence.omissions.push(ProbeOmission {
            field: ProbeField::Index,
            reason,
        }),
    }
}

fn probe_refs(canonical: &Path, limits: &ProbeLimits, evidence: &mut GitProbeEvidence) {
    match run_op(canonical, &GitProbeOp::ForEachRefNull, limits) {
        Ok(output) if output.code == Some(0) && !output.truncated && !output.timed_out => {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut tips = Vec::new();
            let mut failed = false;
            for line in text.lines() {
                if line.is_empty() {
                    continue;
                }
                match line.split_once('\0') {
                    Some((name, oid)) if !name.is_empty() => match GitOid::parse(oid) {
                        Ok(oid) => tips.push((name.to_owned(), oid)),
                        Err(_) => failed = true,
                    },
                    _ => failed = true,
                }
            }
            if tips.len() > limits.max_records || failed {
                evidence.omissions.push(ProbeOmission {
                    field: ProbeField::RefTips,
                    reason: ProbeUnavailableReason::OutputLimitExceeded,
                });
                evidence.ref_tips = Vec::new();
            } else {
                tips.sort();
                evidence.ref_tips = tips;
            }
        }
        Ok(output) => evidence.omissions.push(ProbeOmission {
            field: ProbeField::RefTips,
            reason: if output.timed_out {
                ProbeUnavailableReason::Timeout
            } else if output.truncated {
                ProbeUnavailableReason::OutputLimitExceeded
            } else {
                ProbeUnavailableReason::CorruptAdminMetadata
            },
        }),
        Err(reason) => evidence.omissions.push(ProbeOmission {
            field: ProbeField::RefTips,
            reason,
        }),
    }
}

/// Machine-readable classification of one `cat-file --batch-check` response
/// line. Only stdout is parsed; stderr text is never inspected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BatchCheckPresence {
    /// The OID is not an object in this repository at all.
    Missing,
    /// The object exists and is a commit.
    Commit,
    /// The object exists but is not a commit.
    NonCommit,
}

/// Parses the single response line for one queried OID:
/// `<oid> missing\n` or `<oid> <type> <size>\n`. Any deviation — a foreign
/// echo, extra or missing fields, a non-numeric size, extra lines, invalid
/// UTF-8 — is malformed and yields `None` (fail closed).
fn parse_batch_check_presence(stdout: &[u8], oid: &GitOid) -> Option<BatchCheckPresence> {
    let text = String::from_utf8(stdout.to_vec()).ok()?;
    let mut lines = text.lines();
    let line = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    let mut fields = line.split(' ');
    if fields.next()? != oid.as_str() {
        return None;
    }
    let object_type = fields.next()?;
    if object_type == "missing" {
        return fields
            .next()
            .is_none()
            .then_some(BatchCheckPresence::Missing);
    }
    let size = fields.next()?;
    if fields.next().is_some() || size.is_empty() || !size.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(if object_type == "commit" {
        BatchCheckPresence::Commit
    } else {
        BatchCheckPresence::NonCommit
    })
}

/// Classifies a finished `cat-file --batch-check` run for one OID. Timeout,
/// truncation, a non-zero exit or malformed stdout are all probe omissions,
/// never silently a negative.
fn classify_batch_check_output(
    output: &CommandOutput,
    oid: &GitOid,
) -> Result<BatchCheckPresence, ProbeUnavailableReason> {
    if output.timed_out {
        return Err(ProbeUnavailableReason::Timeout);
    }
    if output.truncated {
        return Err(ProbeUnavailableReason::OutputLimitExceeded);
    }
    if output.code != Some(0) {
        return Err(ProbeUnavailableReason::CorruptAdminMetadata);
    }
    parse_batch_check_presence(&output.stdout, oid)
        .ok_or(ProbeUnavailableReason::CorruptAdminMetadata)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MergeBaseVerdict {
    Ancestor,
    NotAncestor,
}

/// Classifies a finished `merge-base --is-ancestor` run. Exit code 0 is a
/// proof, exit code 1 a legitimate negative; every other outcome — including
/// exit code 128 from a damaged object store — is a probe omission.
fn classify_merge_base_output(
    output: &CommandOutput,
) -> Result<MergeBaseVerdict, ProbeUnavailableReason> {
    if output.timed_out {
        return Err(ProbeUnavailableReason::Timeout);
    }
    if output.truncated {
        return Err(ProbeUnavailableReason::OutputLimitExceeded);
    }
    match output.code {
        Some(0) => Ok(MergeBaseVerdict::Ancestor),
        Some(1) => Ok(MergeBaseVerdict::NotAncestor),
        _ => Err(ProbeUnavailableReason::CorruptAdminMetadata),
    }
}

/// Positive continuity evidence: for every known historical HEAD that exists
/// as a commit in this repository's object store, prove by
/// `merge-base --is-ancestor` that it is an ancestor of the current HEAD.
/// Presence is checked first with `cat-file --batch-check`: an OID that is
/// not an object here belongs to a *different* repository instance and is a
/// deterministic not-applicable negative (no omission, no merge-base).
/// A present commit that merge-base rejects with exit code 1 is a legitimate
/// negative. Everything else — damaged object store (merge-base exit 128),
/// a non-commit object, malformed output, timeout, truncation, spawn/read
/// failure — is a `ContinuityAncestry` omission, so an incomplete probe can
/// never silently pass.
fn probe_continuity(
    canonical: &Path,
    limits: &ProbeLimits,
    evidence: &mut GitProbeEvidence,
    known_head_oids: &[GitOid],
) {
    // Unborn HEAD carries no ancestry to prove; that is not an omission.
    let Some(head) = evidence.head_oid.clone() else {
        return;
    };
    let mut known = known_head_oids.to_vec();
    known.sort();
    known.dedup();
    if known.len() > limits.max_records {
        evidence.omissions.push(ProbeOmission {
            field: ProbeField::ContinuityAncestry,
            reason: ProbeUnavailableReason::OutputLimitExceeded,
        });
        known.truncate(limits.max_records);
    }
    let mut ancestors = BTreeSet::new();
    for known_head in known {
        let presence = run_op(
            canonical,
            &GitProbeOp::CatFileBatchCheck {
                oid: known_head.clone(),
            },
            limits,
        )
        .and_then(|output| classify_batch_check_output(&output, &known_head));
        let presence = match presence {
            Ok(presence) => presence,
            Err(reason) => {
                evidence.omissions.push(ProbeOmission {
                    field: ProbeField::ContinuityAncestry,
                    reason,
                });
                continue;
            }
        };
        match presence {
            BatchCheckPresence::Missing => {}
            BatchCheckPresence::NonCommit => {
                evidence.omissions.push(ProbeOmission {
                    field: ProbeField::ContinuityAncestry,
                    reason: ProbeUnavailableReason::CorruptAdminMetadata,
                });
            }
            BatchCheckPresence::Commit => {
                let verdict = run_op(
                    canonical,
                    &GitProbeOp::MergeBaseIsAncestor {
                        ancestor: known_head.clone(),
                        descendant: head.clone(),
                    },
                    limits,
                )
                .and_then(|output| classify_merge_base_output(&output));
                match verdict {
                    Ok(MergeBaseVerdict::Ancestor) => {
                        ancestors.insert(known_head);
                    }
                    Ok(MergeBaseVerdict::NotAncestor) => {}
                    Err(reason) => {
                        evidence.omissions.push(ProbeOmission {
                            field: ProbeField::ContinuityAncestry,
                            reason,
                        });
                    }
                }
            }
        }
    }
    evidence.head_ancestors = ancestors.into_iter().collect();
}

fn probe_remotes(canonical: &Path, limits: &ProbeLimits, evidence: &mut GitProbeEvidence) {
    match run_op(canonical, &GitProbeOp::ConfigGetRemoteUrls, limits) {
        Ok(output) if output.code == Some(0) && !output.truncated => {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut fingerprints = BTreeSet::new();
            let mut dropped = false;
            for entry in text.split('\0') {
                if entry.is_empty() {
                    continue;
                }
                match entry.split_once('\n') {
                    Some((key, value)) if key.starts_with("remote.") => {
                        match remote_fingerprint(value) {
                            Some(fingerprint) => {
                                fingerprints.insert(fingerprint);
                            }
                            None => dropped = true,
                        }
                    }
                    _ => dropped = true,
                }
            }
            evidence.remote_fingerprints = fingerprints.into_iter().collect();
            if dropped {
                evidence.omissions.push(ProbeOmission {
                    field: ProbeField::RemoteFingerprints,
                    reason: ProbeUnavailableReason::CorruptAdminMetadata,
                });
            }
        }
        Ok(output) if output.code == Some(1) => {}
        Ok(_) | Err(_) => evidence.omissions.push(ProbeOmission {
            field: ProbeField::RemoteFingerprints,
            reason: ProbeUnavailableReason::CorruptAdminMetadata,
        }),
    }
}

fn probe_git_operation(git_dir: &Option<String>, evidence: &mut GitProbeEvidence) {
    let Some(git_dir) = git_dir else { return };
    let git_dir = Path::new(git_dir);
    let exists = |name: &str| std::fs::metadata(git_dir.join(name)).is_ok();
    evidence.git_operation = if exists("MERGE_HEAD") {
        GitOperation::Merge
    } else if exists("rebase-merge") || exists("rebase-apply") {
        GitOperation::Rebase
    } else if exists("CHERRY_PICK_HEAD") {
        GitOperation::CherryPick
    } else if exists("REVERT_HEAD") {
        GitOperation::Revert
    } else if exists("BISECT_LOG") {
        GitOperation::Bisect
    } else {
        GitOperation::None
    };
}

fn probe_worktree_entries(
    canonical: &Path,
    probe_entry_gitdirs: bool,
    limits: &ProbeLimits,
    evidence: &mut GitProbeEvidence,
) {
    let output = match run_op(canonical, &GitProbeOp::WorktreeListPorcelain, limits) {
        Ok(output) if output.code == Some(0) && !output.truncated && !output.timed_out => output,
        Ok(output) => {
            evidence.worktree_list_complete = false;
            evidence.omissions.push(ProbeOmission {
                field: ProbeField::WorktreeList,
                reason: if output.timed_out {
                    ProbeUnavailableReason::Timeout
                } else if output.truncated {
                    ProbeUnavailableReason::OutputLimitExceeded
                } else {
                    ProbeUnavailableReason::CorruptAdminMetadata
                },
            });
            return;
        }
        Err(reason) => {
            evidence.worktree_list_complete = false;
            evidence.omissions.push(ProbeOmission {
                field: ProbeField::WorktreeList,
                reason,
            });
            return;
        }
    };
    let mut entries = Vec::new();
    let mut current: Option<WorktreeAdminEntry> = None;
    for token in output.stdout.split(|byte| *byte == 0) {
        if token.is_empty() {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            continue;
        }
        let token = String::from_utf8_lossy(token).into_owned();
        if let Some(path) = token.strip_prefix("worktree ") {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            current = Some(WorktreeAdminEntry {
                path: path.to_owned(),
                gitdir: None,
                head: None,
                branch: None,
                detached: false,
                locked: false,
                prunable: false,
            });
        } else if let Some(entry) = current.as_mut() {
            if let Some(head) = token.strip_prefix("HEAD ") {
                entry.head = GitOid::parse(head).ok();
            } else if let Some(branch) = token.strip_prefix("branch ") {
                entry.branch = Some(branch.to_owned());
            } else if token == "detached" {
                entry.detached = true;
            } else if token == "locked" || token.starts_with("locked ") {
                entry.locked = true;
            } else if token == "prunable" || token.starts_with("prunable ") {
                entry.prunable = true;
            }
        }
    }
    if let Some(entry) = current.take() {
        entries.push(entry);
    }
    if entries.len() > limits.max_records {
        evidence.worktree_list_complete = false;
        evidence.omissions.push(ProbeOmission {
            field: ProbeField::WorktreeList,
            reason: ProbeUnavailableReason::OutputLimitExceeded,
        });
        evidence.worktree_entries = Vec::new();
        return;
    }
    for entry in &mut entries {
        if !probe_entry_gitdirs || entry.prunable || std::fs::metadata(&entry.path).is_err() {
            continue;
        }
        if let Ok(gitdir) = run_op(Path::new(&entry.path), &GitProbeOp::RevParseGitDir, limits)
            && gitdir.code == Some(0)
        {
            entry.gitdir = first_line(&gitdir.stdout).map(|value| {
                absolutize(Path::new(&entry.path), &value)
                    .to_string_lossy()
                    .into_owned()
            });
        }
    }
    evidence.worktree_entries = entries;
}

/// Bounded ancestry evidence: `merge-base --is-ancestor`.
pub fn probe_is_ancestor(
    repository_path: &Path,
    ancestor: &GitOid,
    descendant: &GitOid,
    limits: &ProbeLimits,
) -> Result<bool, RepositoryProbeError> {
    limits.validate()?;
    if !repository_path.is_absolute() {
        return Err(RepositoryProbeError::InvalidInput);
    }
    match run_op(
        repository_path,
        &GitProbeOp::MergeBaseIsAncestor {
            ancestor: ancestor.clone(),
            descendant: descendant.clone(),
        },
        limits,
    ) {
        Ok(output) if output.code == Some(0) => Ok(true),
        Ok(output) if output.code == Some(1) => Ok(false),
        _ => Err(RepositoryProbeError::InvalidInput),
    }
}

/// Bounded patch equivalence evidence: digests of `diff --raw -z base tip`
/// for both ranges; equal digests produce a shared `patch:` evidence ref.
pub fn probe_patch_equivalence(
    repository_path: &Path,
    base_a: &GitOid,
    tip_a: &GitOid,
    base_b: &GitOid,
    tip_b: &GitOid,
    limits: &ProbeLimits,
) -> Result<Option<String>, RepositoryProbeError> {
    limits.validate()?;
    if !repository_path.is_absolute() {
        return Err(RepositoryProbeError::InvalidInput);
    }
    let digest_of = |base: &GitOid, tip: &GitOid| -> Option<String> {
        let output = run_op(
            repository_path,
            &GitProbeOp::DiffRawRange {
                base: base.clone(),
                tip: tip.clone(),
            },
            limits,
        )
        .ok()?;
        if output.code != Some(0) || output.truncated || output.timed_out {
            return None;
        }
        sha256(
            PATCH_EQUIVALENCE_TAG,
            1,
            &CanonicalValue::Bytes(output.stdout),
        )
        .ok()
        .map(|value| hex(&value))
    };
    match (digest_of(base_a, tip_a), digest_of(base_b, tip_b)) {
        (Some(first), Some(second)) if first == second => Ok(Some(format!("patch:{first}"))),
        _ => Ok(None),
    }
}

fn first_line(output: &[u8]) -> Option<String> {
    let text = String::from_utf8(output.to_vec()).ok()?;
    text.lines().next().map(str::to_owned)
}

fn absolutize(cwd: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    let joined = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn pinned_absolutize(cwd: &Path, logical_root: Option<&Path>, value: &str) -> PathBuf {
    let value = Path::new(value);
    if value.is_absolute() {
        value.to_path_buf()
    } else {
        logical_root.unwrap_or(cwd).join(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_recovery_git_cwd_never_follows_a_replaced_locator() {
        use std::os::unix::fs::MetadataExt;

        let base = std::env::temp_dir().join(format!(
            "evertrace-pinned-{}",
            evertrace_domain::ids::CommandId::new_v7()
        ));
        let root = base.join("worktree");
        let displaced = base.join("pinned-a");
        let replacement = base.join("replacement-b");
        std::fs::create_dir_all(&root).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(&root)
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(root.join("from-a"), b"a").unwrap();
        let confined = evertrace_capture::ConfinedRoot::open(&root).unwrap();
        let cwd = confined.proc_cwd_path().unwrap();
        let metadata = std::fs::metadata(&cwd).unwrap();
        let identity = FilesystemIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let limits = ProbeLimits::default();
        let first = probe_recovery_capture_scoped_pinned(
            &cwd,
            identity,
            &limits,
            UntrackedCaptureScope::Standard,
        )
        .unwrap();
        assert!(first.untracked_paths.contains(&PathBuf::from("from-a")));

        std::fs::rename(&root, &displaced).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(&root)
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(root.join("from-b"), b"b").unwrap();
        let during_replacement = probe_recovery_capture_scoped_pinned(
            &cwd,
            identity,
            &limits,
            UntrackedCaptureScope::Standard,
        )
        .unwrap();
        assert!(
            during_replacement
                .untracked_paths
                .contains(&PathBuf::from("from-a"))
        );
        assert!(
            !during_replacement
                .untracked_paths
                .contains(&PathBuf::from("from-b"))
        );
        assert!(confined.revalidate().is_err());

        std::fs::rename(&root, &replacement).unwrap();
        std::fs::rename(&displaced, &root).unwrap();
        // The open descriptor still names A, while root locator validation
        // conservatively detects the rename/ABA metadata change.
        assert!(confined.revalidate().is_err());
        let after_aba = probe_recovery_capture_scoped_pinned(
            &cwd,
            identity,
            &limits,
            UntrackedCaptureScope::Standard,
        )
        .unwrap();
        assert!(after_aba.untracked_paths.contains(&PathBuf::from("from-a")));
        assert!(!after_aba.untracked_paths.contains(&PathBuf::from("from-b")));
        assert!(
            probe_recovery_capture_scoped_pinned(
                &cwd,
                FilesystemIdentity {
                    device: identity.device,
                    inode: identity.inode.saturating_add(1),
                },
                &limits,
                UntrackedCaptureScope::Standard,
            )
            .is_err()
        );
        assert!(
            probe_recovery_capture_scoped_pinned(
                Path::new("/proc/self/fd/not-a-fd"),
                identity,
                &limits,
                UntrackedCaptureScope::Standard,
            )
            .is_err()
        );

        drop(confined);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn shared_probe_deadline_is_monotonic_and_never_extended_by_a_stage() {
        let outer = Instant::now() + Duration::from_secs(10);
        let shorter = Instant::now() + Duration::from_secs(5);
        with_probe_deadline(outer, || {
            assert_eq!(SHARED_PROBE_DEADLINE.with(Cell::get), Some(outer));
            with_probe_deadline(outer + Duration::from_secs(10), || {
                assert_eq!(SHARED_PROBE_DEADLINE.with(Cell::get), Some(outer));
            });
            with_probe_deadline(shorter, || {
                assert_eq!(SHARED_PROBE_DEADLINE.with(Cell::get), Some(shorter));
            });
            assert_eq!(SHARED_PROBE_DEADLINE.with(Cell::get), Some(outer));
        });
        assert_eq!(SHARED_PROBE_DEADLINE.with(Cell::get), None);
    }

    fn oid(value: char) -> GitOid {
        GitOid::parse(&value.to_string().repeat(40)).unwrap()
    }

    fn all_ops() -> Vec<GitProbeOp> {
        vec![
            GitProbeOp::RevParseGitDir,
            GitProbeOp::RevParseCommonDir,
            GitProbeOp::RevParseShowToplevel,
            GitProbeOp::RevParseIsInsideWorkTree,
            GitProbeOp::RevParseShowObjectFormat,
            GitProbeOp::RevParseVerifyHead,
            GitProbeOp::RevParseHeadTree,
            GitProbeOp::SymbolicRefHead,
            GitProbeOp::StatusPorcelainV2,
            GitProbeOp::WorktreeListPorcelain,
            GitProbeOp::ForEachRefNull,
            GitProbeOp::MergeBaseIsAncestor {
                ancestor: oid('a'),
                descendant: oid('b'),
            },
            GitProbeOp::CatFileBatchCheck { oid: oid('e') },
            GitProbeOp::DiffRawRange {
                base: oid('c'),
                tip: oid('d'),
            },
            GitProbeOp::LsFilesStage,
            GitProbeOp::ConfigGetRemoteUrls,
        ]
    }

    #[test]
    fn argv_audit_proves_only_allowlisted_read_only_operations() {
        const ALLOWED_SUBCOMMANDS: &[&str] = &[
            "rev-parse",
            "symbolic-ref",
            "status",
            "worktree",
            "for-each-ref",
            "merge-base",
            "cat-file",
            "diff",
            "ls-files",
            "config",
        ];
        const FORBIDDEN: &[&str] = &[
            "add",
            "am",
            "apply",
            "bisect",
            "branch",
            "checkout",
            "cherry-pick",
            "clean",
            "clone",
            "commit",
            "fetch",
            "gc",
            "init",
            "merge",
            "mv",
            "prune",
            "pull",
            "push",
            "rebase",
            "reflog",
            "remote",
            "remove",
            "repair",
            "reset",
            "restore",
            "revert",
            "rm",
            "stash",
            "submodule",
            "switch",
            "tag",
            "update-ref",
            "write-tree",
            "hash-object",
            "config-set",
        ];
        let ops = all_ops();
        assert_eq!(ops.len(), 16);
        for op in &ops {
            let argv = op.argv();
            assert_eq!(argv[0], "--no-pager");
            let subcommand = argv[1].as_str();
            assert!(ALLOWED_SUBCOMMANDS.contains(&subcommand), "{argv:?}");
            assert!(
                !argv.iter().any(|arg| FORBIDDEN.contains(&arg.as_str())),
                "{argv:?}"
            );
            match subcommand {
                "worktree" => assert_eq!(argv[2], "list"),
                "config" => assert_eq!(argv[2], "--null"),
                "status" => assert!(argv.contains(&"--porcelain=v2".to_owned())),
                "diff" => assert!(argv.contains(&"--raw".to_owned())),
                // The queried OID travels over stdin, never argv.
                "cat-file" => assert_eq!(argv, &["--no-pager", "cat-file", "--batch-check"]),
                _ => {}
            }
            // No argv ever embeds a raw OID for the stdin-fed operation.
            if op.stdin_bytes().is_some() {
                assert_eq!(argv.len(), 3, "{argv:?}");
            }
        }
    }

    fn output(code: Option<i32>, stdout: &[u8], truncated: bool, timed_out: bool) -> CommandOutput {
        CommandOutput {
            code,
            stdout: stdout.to_vec(),
            truncated,
            timed_out,
        }
    }

    #[test]
    fn batch_check_presence_parses_only_the_exact_machine_format() {
        let queried = oid('a');
        assert_eq!(
            parse_batch_check_presence(
                format!("{} missing\n", queried.as_str()).as_bytes(),
                &queried
            ),
            Some(BatchCheckPresence::Missing)
        );
        assert_eq!(
            parse_batch_check_presence(
                format!("{} commit 231\n", queried.as_str()).as_bytes(),
                &queried
            ),
            Some(BatchCheckPresence::Commit)
        );
        assert_eq!(
            parse_batch_check_presence(
                format!("{} tag 184\n", queried.as_str()).as_bytes(),
                &queried
            ),
            Some(BatchCheckPresence::NonCommit)
        );
        // Malformed output fails closed: foreign echo, extra or missing
        // fields, non-numeric size, extra lines, empty or non-UTF-8 bytes.
        let queried_text = queried.as_str();
        let foreign = oid('b');
        let malformed: Vec<Vec<u8>> = vec![
            format!("{} missing\n", foreign.as_str()).into_bytes(),
            format!("{queried_text} missing extra\n").into_bytes(),
            format!("{queried_text} commit\n").into_bytes(),
            format!("{queried_text} commit abc\n").into_bytes(),
            format!("{queried_text} commit 12 trailing\n").into_bytes(),
            format!("{queried_text} commit 1\n{queried_text} commit 2\n").into_bytes(),
            Vec::new(),
            b"\xff\xfe\n".to_vec(),
        ];
        for bytes in malformed {
            assert_eq!(
                parse_batch_check_presence(&bytes, &queried),
                None,
                "{bytes:?}"
            );
        }
    }

    #[test]
    fn batch_check_output_classification_fails_closed() {
        let queried = oid('a');
        let ok = output(
            Some(0),
            format!("{} missing\n", queried.as_str()).as_bytes(),
            false,
            false,
        );
        assert_eq!(
            classify_batch_check_output(&ok, &queried),
            Ok(BatchCheckPresence::Missing)
        );
        // A non-zero exit (e.g. 128 from a damaged object store), timeout,
        // truncation and malformed stdout are omissions, never negatives.
        let fatal = output(Some(128), b"", false, false);
        assert_eq!(
            classify_batch_check_output(&fatal, &queried),
            Err(ProbeUnavailableReason::CorruptAdminMetadata)
        );
        let timed = output(None, b"", false, true);
        assert_eq!(
            classify_batch_check_output(&timed, &queried),
            Err(ProbeUnavailableReason::Timeout)
        );
        let cut = output(
            Some(0),
            format!("{} commit", queried.as_str()).as_bytes(),
            true,
            false,
        );
        assert_eq!(
            classify_batch_check_output(&cut, &queried),
            Err(ProbeUnavailableReason::OutputLimitExceeded)
        );
        let garbage = output(Some(0), b"fatal: not a git repository\n", false, false);
        assert_eq!(
            classify_batch_check_output(&garbage, &queried),
            Err(ProbeUnavailableReason::CorruptAdminMetadata)
        );
    }

    #[test]
    fn merge_base_classification_never_treats_128_as_negative() {
        assert_eq!(
            classify_merge_base_output(&output(Some(0), b"", false, false)),
            Ok(MergeBaseVerdict::Ancestor)
        );
        assert_eq!(
            classify_merge_base_output(&output(Some(1), b"", false, false)),
            Ok(MergeBaseVerdict::NotAncestor)
        );
        // 128 (missing/corrupt object), any other code, no code, timeout and
        // truncation are all omissions.
        assert_eq!(
            classify_merge_base_output(&output(Some(128), b"", false, false)),
            Err(ProbeUnavailableReason::CorruptAdminMetadata)
        );
        assert_eq!(
            classify_merge_base_output(&output(Some(2), b"", false, false)),
            Err(ProbeUnavailableReason::CorruptAdminMetadata)
        );
        assert_eq!(
            classify_merge_base_output(&output(None, b"", false, false)),
            Err(ProbeUnavailableReason::CorruptAdminMetadata)
        );
        assert_eq!(
            classify_merge_base_output(&output(Some(0), b"", false, true)),
            Err(ProbeUnavailableReason::Timeout)
        );
        assert_eq!(
            classify_merge_base_output(&output(Some(0), b"", true, false)),
            Err(ProbeUnavailableReason::OutputLimitExceeded)
        );
    }

    #[test]
    fn cat_file_batch_check_feeds_exactly_one_oid_line_over_stdin() {
        let queried = oid('c');
        let op = GitProbeOp::CatFileBatchCheck {
            oid: queried.clone(),
        };
        assert_eq!(
            op.stdin_bytes(),
            Some(format!("{}\n", queried.as_str()).into_bytes())
        );
        assert!(
            GitProbeOp::MergeBaseIsAncestor {
                ancestor: oid('a'),
                descendant: oid('b'),
            }
            .stdin_bytes()
            .is_none()
        );
    }

    #[test]
    fn git_oid_rejects_non_hex_and_injection() {
        assert!(GitOid::parse(&"a".repeat(40)).is_ok());
        assert!(GitOid::parse("--upload-pack=evil").is_err());
        assert!(GitOid::parse(&"g".repeat(40)).is_err());
        assert!(GitOid::parse(&"a".repeat(39)).is_err());
    }

    fn valid_fingerprint(value: &str) -> bool {
        let Some(hex_digits) = value.strip_prefix(REMOTE_FINGERPRINT_PREFIX) else {
            return false;
        };
        hex_digits.len() == 64
            && hex_digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    #[test]
    fn remote_fingerprints_are_hashed_and_fail_closed_on_passwords() {
        // Password-bearing locators fail closed: no fingerprint at all, and
        // neither the secret nor the host appears in the result or its Debug.
        let password = remote_fingerprint("https://user:secret@example.com/repo");
        assert_eq!(password, None);
        let debug = format!("{password:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("example.com"));

        // Username-only locators are stripped and hashed.
        let scp = remote_fingerprint("git@example.com:org/repo.git").unwrap();
        let https = remote_fingerprint("https://user@example.com/repo").unwrap();
        assert!(valid_fingerprint(&scp));
        assert!(valid_fingerprint(&https));
        assert!(!scp.contains("example.com"));
        assert!(!format!("{scp:?}").contains("example.com"));

        // Normalization is stable: userinfo, default ports, case and
        // trailing slashes collapse into one fingerprint; a non-default port
        // is part of the remote's identity and changes the fingerprint.
        assert_eq!(
            remote_fingerprint("https://user:secret@example.com/org/repo.git"),
            None
        );
        assert_eq!(
            remote_fingerprint("https://user@Example.COM:443/org/repo.git/"),
            remote_fingerprint("https://example.com/org/repo.git")
        );
        assert_ne!(
            remote_fingerprint("https://user@Example.COM:8443/org/repo.git/"),
            remote_fingerprint("https://example.com/org/repo.git")
        );
        assert_eq!(
            remote_fingerprint("git@Example.COM:org/repo.git"),
            remote_fingerprint("ssh://example.com/org/repo.git")
        );
        // ssh is not a url-crate "special" scheme, so it has no default port
        // to normalize: any explicit ssh port stays in the locator.
        assert_ne!(
            remote_fingerprint("ssh://git@example.com:22/org/repo.git"),
            remote_fingerprint("ssh://example.com/org/repo.git")
        );
        assert_ne!(
            remote_fingerprint("ssh://git@example.com:2222/org/repo.git"),
            remote_fingerprint("ssh://example.com/org/repo.git")
        );
        assert_ne!(
            remote_fingerprint("https://example.com/org/repo.git"),
            remote_fingerprint("https://example.com/org/other.git")
        );
        assert!(valid_fingerprint(
            &remote_fingerprint("/srv/repos/a.git").unwrap()
        ));
        assert!(remote_fingerprint("not a url with spaces").is_none());
    }

    #[test]
    fn probe_limits_must_be_positive() {
        assert!(ProbeLimits::default().validate().is_ok());
        let limits = ProbeLimits {
            max_stdout_bytes: 0,
            ..ProbeLimits::default()
        };
        assert_eq!(limits.validate(), Err(RepositoryProbeError::InvalidInput));
    }
}
