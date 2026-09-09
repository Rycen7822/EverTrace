use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use evertrace_capture::{ConfinedReadError, ConfinedReadLimits, ConfinedRoot};
use evertrace_codex::{
    adapter_manifest::{AdapterKind, SessionCatalogRootKind},
    binding::NativeToolUse,
    capability::CanaryStatus,
    policy::{RepositoryTrustResult, RepositoryTrustState, parse_repository_trust},
    probe::{
        CODEX_SESSION_LAYOUT_REVISION, EvidenceSourceKind, HostProbeReport, ProbeContext,
        ProbeEvidence, SessionCatalogRootEvidence,
    },
    source_catalog::CODEX_ELIGIBLE_EVENT_MANIFEST,
    source_catalog::qualify_requested_session_root,
};
use evertrace_domain::{ids::WorktreeId, repository::WorktreeLifecycle};
use evertrace_store::repository::RepositoryCurrentView;
use serde_json::Value;
use thiserror::Error;

const SESSION_ROOT_PROBE_BUDGET: Duration = Duration::from_millis(50);

pub(crate) fn freeze_native_namespace(
    call: &evertrace_domain::evidence::SourceLocalNativeCall,
) -> Option<evertrace_domain::evidence::SourceLocalNamespaceWitness> {
    use evertrace_codex::session_import::{
        MAX_RECORD_BYTES, namespace_from_header, native_session_path,
    };
    let deadline = Instant::now() + SESSION_ROOT_PROBE_BUDGET;
    let (root, relative) = native_session_path(call.transcript_path.as_deref()?).ok()?;
    let root = ConfinedRoot::open_external_source(&root).ok()?;
    let identity = match root.read(
        &relative,
        ConfinedReadLimits {
            single_file_remaining: 0,
            untracked_total_remaining: 0,
            bundle_remaining: 0,
            deadline,
        },
    ) {
        Ok(file) => file.identity,
        Err(ConfinedReadError::LimitExceeded { metadata, .. }) => metadata.identity,
        Err(_) => return None,
    };
    let mut remaining = MAX_RECORD_BYTES + 1;
    let bytes = root
        .read_first_record(
            &relative,
            identity,
            MAX_RECORD_BYTES,
            &mut remaining,
            deadline,
        )
        .ok()?;
    namespace_from_header(call, &bytes, identity.device, identity.inode, identity.size).ok()
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionCatalogObservationError {
    #[error("native pre-tool input is invalid")]
    InvalidNativeInput,
    #[error("transcript path does not match the closed Codex session layout")]
    UnsupportedLayout,
    #[error("session catalog root or transcript identity is unsafe")]
    UnsafeIdentity,
}

/// Derives transient session-root evidence from the host-authored native hook
/// envelope. The transcript is opened through the capture crate's confined,
/// no-follow reader. Only its bounded first metadata record is decoded;
/// session body records do not become root authority.
pub fn observe_native_session_catalog_root(
    native_input: &[u8],
) -> Result<SessionCatalogRootEvidence, SessionCatalogObservationError> {
    observe_native_session_catalog_root_at(native_input, Instant::now() + SESSION_ROOT_PROBE_BUDGET)
        .map(|(evidence, _)| evidence)
}

fn observe_native_session_catalog_root_at(
    native_input: &[u8],
    deadline: Instant,
) -> Result<(SessionCatalogRootEvidence, PathBuf), SessionCatalogObservationError> {
    let input = NativeToolUse::<Value>::from_json(native_input)
        .map_err(|_| SessionCatalogObservationError::InvalidNativeInput)?;
    input
        .validate_host_fields()
        .map_err(|_| SessionCatalogObservationError::InvalidNativeInput)?;
    observe_session_catalog_root_at(
        input.transcript_path.as_deref(),
        &input.session_id,
        &input.tool_use_id,
        input.agent_id.as_deref(),
        deadline,
    )
}

/// Validates the host-authored fields carried by the existing MCP binding
/// request. The daemon, rather than the Hook, derives the transient root
/// evidence and authority verdict.
pub fn observe_session_catalog_root(
    transcript_path: Option<&str>,
    session_id: &str,
    tool_use_id: &str,
    agent_id: Option<&str>,
) -> Result<SessionCatalogRootEvidence, SessionCatalogObservationError> {
    observe_session_catalog_root_at(
        transcript_path,
        session_id,
        tool_use_id,
        agent_id,
        Instant::now() + SESSION_ROOT_PROBE_BUDGET,
    )
    .map(|(evidence, _)| evidence)
}

/// Compiles the daemon's bounded, transient current report from one validated
/// native binding request.
pub fn observe_session_catalog_report(
    transcript_path: Option<&str>,
    session_id: &str,
    tool_use_id: &str,
    agent_id: Option<&str>,
) -> Result<HostProbeReport, SessionCatalogObservationError> {
    let root = observe_session_catalog_root(transcript_path, session_id, tool_use_id, agent_id)?;
    let context = ProbeContext {
        adapter_kind: AdapterKind::CodexHook,
        adapter_revision: "codex-native-binding-v1".into(),
        observed_host_version_range: "official-native-pre-tool-v1".into(),
        eligible_event_manifest_ref: CODEX_ELIGIBLE_EVENT_MANIFEST.into(),
        evidence_source: EvidenceSourceKind::ObservedHostCanary,
    };
    let mut evidence = ProbeEvidence::empty();
    evidence.session_catalog_roots = vec![root];
    HostProbeReport::evaluate(&context, &evidence)
        .map_err(|_| SessionCatalogObservationError::InvalidNativeInput)
}

fn observe_session_catalog_root_at(
    transcript_path: Option<&str>,
    session_id: &str,
    tool_use_id: &str,
    agent_id: Option<&str>,
    deadline: Instant,
) -> Result<(SessionCatalogRootEvidence, PathBuf), SessionCatalogObservationError> {
    if session_id.is_empty()
        || session_id.len() > 256
        || session_id.bytes().any(|byte| byte.is_ascii_control())
        || tool_use_id.is_empty()
        || tool_use_id.len() > 256
        || tool_use_id.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(SessionCatalogObservationError::InvalidNativeInput);
    }
    let transcript = transcript_path.ok_or(SessionCatalogObservationError::UnsupportedLayout)?;
    let (root, relative) = codex_session_path(transcript)?;
    let confined = ConfinedRoot::open_external_source(&root)
        .map_err(|_| SessionCatalogObservationError::UnsafeIdentity)?;
    let observed_identity = match confined.read(
        &relative,
        ConfinedReadLimits {
            single_file_remaining: 0,
            untracked_total_remaining: 0,
            bundle_remaining: 0,
            deadline,
        },
    ) {
        Ok(file) => file.identity,
        Err(ConfinedReadError::LimitExceeded { metadata, .. }) => metadata.identity,
        Err(_) => return Err(SessionCatalogObservationError::UnsafeIdentity),
    };
    let transcript_metadata = std::fs::symlink_metadata(transcript)
        .map_err(|_| SessionCatalogObservationError::UnsafeIdentity)?;
    let root_metadata = std::fs::symlink_metadata(&root)
        .map_err(|_| SessionCatalogObservationError::UnsafeIdentity)?;
    let process_owner = std::fs::metadata("/proc/self")
        .map_err(|_| SessionCatalogObservationError::UnsafeIdentity)?
        .uid();
    if !root_metadata.file_type().is_dir()
        || root_metadata.file_type().is_symlink()
        || root_metadata.uid() != process_owner
        || root_metadata.permissions().mode() & 0o022 != 0
        || root_metadata.dev() != confined.identity().device
        || root_metadata.ino() != confined.identity().inode
        || !transcript_metadata.file_type().is_file()
        || transcript_metadata.file_type().is_symlink()
        || transcript_metadata.uid() != process_owner
        || transcript_metadata.permissions().mode() & 0o022 != 0
        || transcript_metadata.dev() != observed_identity.device
        || transcript_metadata.ino() != observed_identity.inode
        || transcript_metadata.size() != observed_identity.size
        || transcript_metadata.mtime() != observed_identity.mtime_seconds
        || transcript_metadata.mtime_nsec() as u64 != observed_identity.mtime_nanoseconds
        || transcript_metadata.ctime() != observed_identity.ctime_seconds
        || transcript_metadata.ctime_nsec() as u64 != observed_identity.ctime_nanoseconds
    {
        return Err(SessionCatalogObservationError::UnsafeIdentity);
    }
    let mut remaining = crate::session_import::MAX_RECORD_BYTES + 1;
    let header = crate::session_import::read_session_header(
        &confined,
        &relative,
        observed_identity,
        &mut remaining,
        deadline,
    )
    .map_err(|_| SessionCatalogObservationError::UnsupportedLayout)?;
    if header.payload.session_id.as_deref() != Some(session_id)
        || agent_id.is_some_and(|agent| agent != header.payload.id)
    {
        return Err(SessionCatalogObservationError::InvalidNativeInput);
    }
    confined
        .revalidate()
        .map_err(|_| SessionCatalogObservationError::UnsafeIdentity)?;
    let root_identity = confined.identity();
    let evidence_ref = format!("native_pre_tool:{tool_use_id}");
    if evidence_ref.len() > 512 {
        return Err(SessionCatalogObservationError::InvalidNativeInput);
    }
    let evidence = SessionCatalogRootEvidence {
        root_kind: SessionCatalogRootKind::CodexSessions,
        canonical_absolute_path: root.to_string_lossy().into_owned(),
        layout_revision: CODEX_SESSION_LAYOUT_REVISION.into(),
        filesystem_device: root_identity.device,
        filesystem_inode: root_identity.inode,
        canary: CanaryStatus::Passed,
        evidence_refs: vec![evidence_ref],
    };
    Ok((evidence, root))
}

/// Reads the current Codex trust entry for one worktree already resolved from
/// the authoritative current projection. Every call revalidates the native
/// transcript root and config file under one monotonic deadline; failures are
/// deliberately collapsed to an authority-free `Unknown` result.
pub fn read_native_repository_trust(
    native_input: &[u8],
    current: &RepositoryCurrentView,
    worktree_id: WorktreeId,
) -> RepositoryTrustResult {
    let unknown = || RepositoryTrustResult {
        state: RepositoryTrustState::Unknown,
        canonical_repository_path: None,
        evidence_refs: Vec::new(),
    };
    let deadline = Instant::now() + SESSION_ROOT_PROBE_BUDGET;
    let Ok((root_evidence, sessions_root)) =
        observe_native_session_catalog_root_at(native_input, deadline)
    else {
        return unknown();
    };
    let Some(worktree) = current.worktrees.get(&worktree_id) else {
        return unknown();
    };
    if worktree.lifecycle != WorktreeLifecycle::Active || worktree.validate().is_err() {
        return unknown();
    }
    let Some(path) = worktree.current_path.as_deref() else {
        return unknown();
    };
    let Some(adapter_root) = sessions_root.parent() else {
        return unknown();
    };
    let Ok(confined) = ConfinedRoot::open_external_source(adapter_root) else {
        return unknown();
    };
    let Ok(config) = confined.read(
        Path::new("config.toml"),
        ConfinedReadLimits {
            single_file_remaining: 256 * 1024,
            untracked_total_remaining: 256 * 1024,
            bundle_remaining: 256 * 1024,
            deadline,
        },
    ) else {
        return unknown();
    };
    let Ok(metadata) = std::fs::symlink_metadata(adapter_root.join("config.toml")) else {
        return unknown();
    };
    let Ok(process) = std::fs::metadata("/proc/self") else {
        return unknown();
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != process.uid()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.dev() != config.identity.device
        || metadata.ino() != config.identity.inode
        || metadata.size() != config.identity.size
        || confined.revalidate().is_err()
    {
        return unknown();
    }
    let Ok(state) = parse_repository_trust(&config.bytes, path) else {
        return unknown();
    };
    if state == RepositoryTrustState::Unknown {
        return unknown();
    }
    RepositoryTrustResult {
        state,
        canonical_repository_path: Some(path.to_owned()),
        evidence_refs: root_evidence.evidence_refs,
    }
}

/// Revalidates repository trust from the daemon's current observed-host
/// report. No caller path participates: the ready root is selected from the
/// report and must survive exact qualification before `config.toml` is read.
pub fn read_report_repository_trust(
    report: &HostProbeReport,
    current: &RepositoryCurrentView,
    worktree_id: WorktreeId,
) -> RepositoryTrustResult {
    let unknown = || RepositoryTrustResult {
        state: RepositoryTrustState::Unknown,
        canonical_repository_path: None,
        evidence_refs: Vec::new(),
    };
    let Some(path) = report
        .session_catalog_roots()
        .iter()
        .find(|root| root.root_kind == SessionCatalogRootKind::CodexSessions)
        .and_then(|root| root.canonical_absolute_path.as_deref())
        .map(PathBuf::from)
    else {
        return unknown();
    };
    let Ok(qualified) =
        qualify_requested_session_root(report, SessionCatalogRootKind::CodexSessions, &path)
    else {
        return unknown();
    };
    let Some(adapter_root) = qualified.path().parent() else {
        return unknown();
    };
    read_repository_trust_at(
        adapter_root,
        current,
        worktree_id,
        Instant::now() + SESSION_ROOT_PROBE_BUDGET,
    )
}

fn read_repository_trust_at(
    adapter_root: &Path,
    current: &RepositoryCurrentView,
    worktree_id: WorktreeId,
    deadline: Instant,
) -> RepositoryTrustResult {
    let unknown = || RepositoryTrustResult {
        state: RepositoryTrustState::Unknown,
        canonical_repository_path: None,
        evidence_refs: Vec::new(),
    };
    let Some(worktree) = current.worktrees.get(&worktree_id) else {
        return unknown();
    };
    if worktree.lifecycle != WorktreeLifecycle::Active || worktree.validate().is_err() {
        return unknown();
    }
    let Some(path) = worktree.current_path.as_deref() else {
        return unknown();
    };
    let Ok(confined) = ConfinedRoot::open_external_source(adapter_root) else {
        return unknown();
    };
    let Ok(config) = confined.read(
        Path::new("config.toml"),
        ConfinedReadLimits {
            single_file_remaining: 256 * 1024,
            untracked_total_remaining: 256 * 1024,
            bundle_remaining: 256 * 1024,
            deadline,
        },
    ) else {
        return unknown();
    };
    let Ok(metadata) = std::fs::symlink_metadata(adapter_root.join("config.toml")) else {
        return unknown();
    };
    let Ok(process) = std::fs::metadata("/proc/self") else {
        return unknown();
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != process.uid()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.dev() != config.identity.device
        || metadata.ino() != config.identity.inode
        || metadata.size() != config.identity.size
        || confined.revalidate().is_err()
    {
        return unknown();
    }
    let Ok(state) = parse_repository_trust(&config.bytes, path) else {
        return unknown();
    };
    RepositoryTrustResult {
        state,
        canonical_repository_path: Some(path.to_owned()),
        evidence_refs: vec![format!(
            "codex_config:{}:{}",
            config.identity.device, config.identity.inode
        )],
    }
}

fn codex_session_path(
    transcript: &str,
) -> Result<(PathBuf, PathBuf), SessionCatalogObservationError> {
    evertrace_codex::session_import::native_session_path(transcript)
        .map_err(|_| SessionCatalogObservationError::UnsupportedLayout)
}
