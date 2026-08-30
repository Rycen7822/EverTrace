use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use thiserror::Error;

use crate::{
    HostProbeReport,
    adapter_manifest::{
        AdapterCapabilityManifest, ManifestError, ObservableCapability, SessionCatalogRootKind,
    },
    probe::SessionCatalogRootState,
};

pub const CODEX_ELIGIBLE_EVENT_MANIFEST: &str = "codex_host_events_v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualifiedSessionCatalogRoot {
    path: PathBuf,
    device: u64,
    inode: u64,
    layout_revision: String,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionCatalogRootError {
    #[error("session catalog root authority is unavailable")]
    Unavailable,
    #[error("session catalog root does not match the current report")]
    Mismatch,
    #[error("session catalog root identity is unsafe or stale")]
    UnsafeIdentity,
}

impl QualifiedSessionCatalogRoot {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn layout_revision(&self) -> &str {
        &self.layout_revision
    }

    pub fn revalidate(&self) -> Result<(), SessionCatalogRootError> {
        validate_root_identity(&self.path, self.device, self.inode)
    }
}

pub fn qualify_requested_session_root(
    report: &HostProbeReport,
    root_kind: SessionCatalogRootKind,
    requested_path: &Path,
) -> Result<QualifiedSessionCatalogRoot, SessionCatalogRootError> {
    let contract = report
        .manifest()
        .session_catalog_root_contracts
        .iter()
        .find(|contract| contract.root_kind == root_kind)
        .ok_or(SessionCatalogRootError::Unavailable)?;
    let mut roots = report
        .session_catalog_roots()
        .iter()
        .filter(|root| root.root_kind == root_kind && root.state == SessionCatalogRootState::Ready);
    let root = roots.next().ok_or(SessionCatalogRootError::Unavailable)?;
    if roots.next().is_some() {
        return Err(SessionCatalogRootError::Unavailable);
    }
    let canonical = PathBuf::from(
        root.canonical_absolute_path
            .as_deref()
            .ok_or(SessionCatalogRootError::Unavailable)?,
    );
    if requested_path != canonical
        || root.layout_revision != contract.layout_revision
        || !lexical_absolute(&canonical)
    {
        return Err(SessionCatalogRootError::Mismatch);
    }
    let device = root
        .filesystem_device
        .ok_or(SessionCatalogRootError::Unavailable)?;
    let inode = root
        .filesystem_inode
        .ok_or(SessionCatalogRootError::Unavailable)?;
    validate_root_identity(&canonical, device, inode)?;
    Ok(QualifiedSessionCatalogRoot {
        path: canonical,
        device,
        inode,
        layout_revision: root.layout_revision.clone(),
    })
}

fn lexical_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

fn validate_root_identity(
    path: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<(), SessionCatalogRootError> {
    let before = fs::symlink_metadata(path).map_err(|_| SessionCatalogRootError::UnsafeIdentity)?;
    if !before.file_type().is_dir()
        || before.file_type().is_symlink()
        || before.dev() != expected_device
        || before.ino() != expected_inode
        || before.permissions().mode() & 0o077 != 0
    {
        return Err(SessionCatalogRootError::UnsafeIdentity);
    }
    let owner = fs::metadata("/proc/self")
        .map_err(|_| SessionCatalogRootError::UnsafeIdentity)?
        .uid();
    if before.uid() != owner {
        return Err(SessionCatalogRootError::UnsafeIdentity);
    }
    let opened = fs::File::open(path).map_err(|_| SessionCatalogRootError::UnsafeIdentity)?;
    let pinned = opened
        .metadata()
        .map_err(|_| SessionCatalogRootError::UnsafeIdentity)?;
    let after = fs::symlink_metadata(path).map_err(|_| SessionCatalogRootError::UnsafeIdentity)?;
    if pinned.dev() != expected_device
        || pinned.ino() != expected_inode
        || after.dev() != expected_device
        || after.ino() != expected_inode
        || after.file_type().is_symlink()
    {
        return Err(SessionCatalogRootError::UnsafeIdentity);
    }
    Ok(())
}

pub const REQUIRED_FOR_FULL: [ObservableCapability; 4] = [
    ObservableCapability::ChildSessionId,
    ObservableCapability::ChildToolCall,
    ObservableCapability::ChildToolResult,
    ObservableCapability::ChildFinalResult,
];

pub const ELIGIBLE_CAPABILITIES: [ObservableCapability; 10] = [
    ObservableCapability::DelegationStart,
    ObservableCapability::ChildSessionId,
    ObservableCapability::ChildToolCall,
    ObservableCapability::ChildToolResult,
    ObservableCapability::ChildFileChange,
    ObservableCapability::ChildPlan,
    ObservableCapability::ChildReasoningSummary,
    ObservableCapability::ChildFinalResult,
    ObservableCapability::DelegationEnd,
    ObservableCapability::RawHiddenReasoning,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledCaptureContract {
    pub adapter_manifest_ref: String,
    pub eligible_event_manifest_refs: Vec<String>,
    pub observed: BTreeSet<String>,
    pub required_for_full: BTreeSet<String>,
    pub missing_required: BTreeSet<String>,
}

pub fn compile_capture_contract(
    manifest: &AdapterCapabilityManifest,
    observations: impl IntoIterator<Item = ObservableCapability>,
) -> Result<CompiledCaptureContract, ManifestError> {
    manifest.validate()?;
    let eligible = manifest.observable.iter().copied().collect::<BTreeSet<_>>();
    let observed_capabilities = observations.into_iter().collect::<BTreeSet<_>>();
    if !observed_capabilities.is_subset(&eligible) {
        return Err(ManifestError::InvalidCapabilityRelationship);
    }
    let observed = observed_capabilities
        .iter()
        .map(|capability| capability.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let required_for_full = manifest
        .required_for_full
        .iter()
        .map(|capability| capability.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let missing_required = required_for_full.difference(&observed).cloned().collect();
    Ok(CompiledCaptureContract {
        adapter_manifest_ref: manifest.adapter_manifest_id.clone(),
        eligible_event_manifest_refs: manifest.eligible_event_manifest_refs.clone(),
        observed,
        required_for_full,
        missing_required,
    })
}
