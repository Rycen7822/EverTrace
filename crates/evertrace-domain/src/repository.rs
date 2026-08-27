use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ids::{
    AttemptId, IntegrationEventId, RepositoryId, WorktreeId, WorktreeSnapshotId,
    WorktreeTransitionId,
};

pub const REPOSITORY_RESOLVER_VERSION: u32 = 1;

const MAX_LOCATOR_BYTES: usize = 4096;
const MAX_REF_BYTES: usize = 256;
const MAX_DIGEST_HEX: usize = 64;

/// Fixed prefix of the hashed remote fingerprint format; the fingerprint is
/// the only persisted form of a remote locator.
pub const REMOTE_FINGERPRINT_PREFIX: &str = "s11-remote-fp-v1:";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitObjectFormat {
    Sha1,
    Sha256,
}

impl GitObjectFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    pub fn parse(value: &str) -> Result<Self, RepositoryError> {
        match value {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            _ => Err(RepositoryError::InvalidIdentity),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeUnavailableReason {
    NonGit,
    CorruptAdminMetadata,
    PermissionDenied,
    TrustDenied,
    OutputLimitExceeded,
    Timeout,
    PathMissing,
    SpawnFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeKind {
    Main,
    Linked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeLifecycle {
    Active,
    Missing,
    Removed,
    Pruned,
    Archived,
}

impl WorktreeLifecycle {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Removed | Self::Pruned)
    }
}

/// Lifecycle transition closure: `removed`/`pruned` never revive, `archived`
/// can only terminate, `missing` can be repaired back to `active`.
pub fn lifecycle_successor_allowed(
    current: WorktreeLifecycle,
    successor: WorktreeLifecycle,
) -> bool {
    match current {
        WorktreeLifecycle::Active => true,
        WorktreeLifecycle::Missing => true,
        WorktreeLifecycle::Removed => successor == WorktreeLifecycle::Removed,
        WorktreeLifecycle::Pruned => successor == WorktreeLifecycle::Pruned,
        WorktreeLifecycle::Archived => matches!(
            successor,
            WorktreeLifecycle::Archived | WorktreeLifecycle::Removed | WorktreeLifecycle::Pruned
        ),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitRegistrationState {
    Registered,
    Locked,
    Prunable,
    Absent,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitOperation {
    None,
    Merge,
    Rebase,
    CherryPick,
    Revert,
    Bisect,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotCaptureStatus {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotField {
    HeadOid,
    TreeOid,
    BranchRef,
    TrackedDiffDigest,
    IndexDigest,
    UntrackedManifestDigest,
    AnchorDigests,
    DependencyFingerprints,
    ToolchainFingerprint,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    PathMoved,
    HeadAdvanced,
    BranchSwitched,
    DetachedOrAttached,
    HistoryRewritten,
    MergeIntegrated,
    PatchTransferred,
    WorktreeMissing,
    WorktreeRepaired,
    WorktreeRemoved,
    WorktreePruned,
    WorktreeRecreated,
    RepositoryMoved,
    RepositoryCopied,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageAssessment {
    Proven,
    Partial,
    Unknown,
    Contradicted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationKind {
    FastForward,
    MergeCommit,
    Rebase,
    CherryPick,
    Squash,
    ManualPatch,
}

impl IntegrationKind {
    pub const fn ancestry_based(self) -> bool {
        matches!(self, Self::FastForward | Self::MergeCommit)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathObservation {
    pub path: String,
    pub first_observed_at_us: i64,
    pub last_observed_at_us: i64,
    pub evidence_refs: Vec<String>,
}

impl PathObservation {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        valid_locator(&self.path)?;
        if self.first_observed_at_us < 0
            || self.last_observed_at_us < self.first_observed_at_us
            || self.evidence_refs.is_empty()
        {
            return Err(RepositoryError::InvalidReference);
        }
        for reference in &self.evidence_refs {
            valid_ref(reference)?;
        }
        require_unique(&self.evidence_refs)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotOmission {
    pub field: SnapshotField,
    pub reason: ProbeUnavailableReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryInstance {
    pub repository_id: RepositoryId,
    pub repository_revision: u32,
    pub predecessor_revision: Option<u32>,
    pub current_path: String,
    pub path_history: Vec<PathObservation>,
    pub git_common_dir_path: Option<String>,
    pub common_dir_filesystem: Option<FilesystemIdentity>,
    pub object_format: Option<GitObjectFormat>,
    pub remote_fingerprints: Vec<String>,
    pub derived_from: Option<RepositoryId>,
    pub identity_evidence_refs: Vec<String>,
    pub recorded_at_us: i64,
}

impl RepositoryInstance {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        if !valid_revision_chain(self.repository_revision, self.predecessor_revision)
            || self.derived_from == Some(self.repository_id)
            || self.recorded_at_us < 0
        {
            return Err(RepositoryError::InvalidRevision);
        }
        valid_locator(&self.current_path)?;
        valid_path_history(&self.path_history, &self.current_path)?;
        if let Some(common_dir) = &self.git_common_dir_path {
            valid_locator(common_dir)?;
        }
        for fingerprint in &self.remote_fingerprints {
            valid_remote_fingerprint(fingerprint)?;
        }
        require_unique(&self.remote_fingerprints)?;
        for reference in &self.identity_evidence_refs {
            valid_ref(reference)?;
        }
        require_unique(&self.identity_evidence_refs)?;
        // Identity is only ever persisted once established: the common dir,
        // its filesystem identity, the object format and at least one
        // identity evidence ref are unconditionally required. Unavailable
        // probes produce no instance at all.
        if self.git_common_dir_path.is_none()
            || self.common_dir_filesystem.is_none()
            || self.object_format.is_none()
            || self.identity_evidence_refs.is_empty()
        {
            return Err(RepositoryError::InvalidIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorktreeInstance {
    pub worktree_instance_id: WorktreeId,
    pub worktree_revision: u32,
    pub predecessor_revision: Option<u32>,
    pub repository_instance_id: RepositoryId,
    pub kind: WorktreeKind,
    pub lifecycle: WorktreeLifecycle,
    pub current_path: Option<String>,
    pub path_history: Vec<PathObservation>,
    pub git_admin_path_history: Vec<PathObservation>,
    pub git_registration_state: GitRegistrationState,
    pub current_snapshot_id: Option<WorktreeSnapshotId>,
    pub created_event_ref: String,
    pub terminal_event_ref: Option<String>,
    pub recreated_from_worktree_instance_id: Option<WorktreeId>,
    pub recorded_at_us: i64,
}

impl WorktreeInstance {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        if !valid_revision_chain(self.worktree_revision, self.predecessor_revision)
            || self.recreated_from_worktree_instance_id == Some(self.worktree_instance_id)
            || self.recorded_at_us < 0
        {
            return Err(RepositoryError::InvalidRevision);
        }
        if self.path_history.is_empty() || self.git_admin_path_history.is_empty() {
            return Err(RepositoryError::InvalidLifecycle);
        }
        for observation in self.path_history.iter().chain(&self.git_admin_path_history) {
            observation.validate()?;
        }
        valid_ref(&self.created_event_ref)?;
        if let Some(reference) = &self.terminal_event_ref {
            valid_ref(reference)?;
        }
        match self.lifecycle {
            WorktreeLifecycle::Active | WorktreeLifecycle::Missing => {
                let path = self
                    .current_path
                    .as_deref()
                    .ok_or(RepositoryError::InvalidLifecycle)?;
                valid_locator(path)?;
                if self.terminal_event_ref.is_some()
                    || self
                        .path_history
                        .last()
                        .is_some_and(|entry| entry.path != path)
                {
                    return Err(RepositoryError::InvalidLifecycle);
                }
            }
            WorktreeLifecycle::Removed | WorktreeLifecycle::Pruned => {
                if self.terminal_event_ref.is_none() || self.current_path.is_some() {
                    return Err(RepositoryError::InvalidLifecycle);
                }
            }
            WorktreeLifecycle::Archived => {
                let path = self
                    .current_path
                    .as_deref()
                    .ok_or(RepositoryError::InvalidLifecycle)?;
                valid_locator(path)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorktreeSnapshot {
    pub worktree_snapshot_id: WorktreeSnapshotId,
    pub worktree_instance_id: WorktreeId,
    pub head_oid: Option<String>,
    pub tree_oid: Option<String>,
    pub branch_ref: Option<String>,
    pub detached_head: bool,
    pub tracked_diff_digest: Option<String>,
    pub index_digest: Option<String>,
    pub untracked_manifest_digest: Option<String>,
    pub relevant_anchor_digests: Vec<String>,
    pub dependency_fingerprints: Vec<String>,
    pub toolchain_fingerprint: Option<String>,
    pub git_operation: GitOperation,
    pub captured_at_us: i64,
    pub evidence_refs: Vec<String>,
    pub capture_status: SnapshotCaptureStatus,
    pub omission_reasons: Vec<SnapshotOmission>,
}

impl WorktreeSnapshot {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        if self.captured_at_us < 0 {
            return Err(RepositoryError::InvalidSnapshot);
        }
        if let Some(head) = &self.head_oid {
            valid_oid(head)?;
        }
        if let Some(tree) = &self.tree_oid {
            valid_oid(tree)?;
        }
        if let Some(branch) = &self.branch_ref {
            if !branch.starts_with("refs/") {
                return Err(RepositoryError::InvalidSnapshot);
            }
            valid_ref(branch)?;
        }
        if self.detached_head != (self.head_oid.is_some() && self.branch_ref.is_none()) {
            return Err(RepositoryError::InvalidSnapshot);
        }
        for digest in [
            self.tracked_diff_digest.as_deref(),
            self.index_digest.as_deref(),
            self.untracked_manifest_digest.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            valid_digest(digest)?;
        }
        for digest in &self.relevant_anchor_digests {
            valid_digest(digest)?;
        }
        require_unique(&self.relevant_anchor_digests)?;
        for fingerprint in &self.dependency_fingerprints {
            valid_ref(fingerprint)?;
        }
        require_unique(&self.dependency_fingerprints)?;
        if let Some(fingerprint) = &self.toolchain_fingerprint {
            valid_ref(fingerprint)?;
        }
        if self.evidence_refs.is_empty() {
            return Err(RepositoryError::InvalidSnapshot);
        }
        for reference in &self.evidence_refs {
            valid_ref(reference)?;
        }
        require_unique(&self.evidence_refs)?;
        let omission_fields = self
            .omission_reasons
            .iter()
            .map(|omission| omission.field)
            .collect::<BTreeSet<_>>();
        if omission_fields.len() != self.omission_reasons.len() {
            return Err(RepositoryError::Duplicate);
        }
        match self.capture_status {
            SnapshotCaptureStatus::Complete => {
                if !self.omission_reasons.is_empty() {
                    return Err(RepositoryError::InvalidSnapshot);
                }
            }
            SnapshotCaptureStatus::Partial => {
                if self.omission_reasons.is_empty() {
                    return Err(RepositoryError::InvalidSnapshot);
                }
            }
            SnapshotCaptureStatus::Unavailable => {
                if self.omission_reasons.is_empty()
                    || self.head_oid.is_some()
                    || self.tree_oid.is_some()
                    || self.branch_ref.is_some()
                    || self.tracked_diff_digest.is_some()
                    || self.index_digest.is_some()
                    || self.untracked_manifest_digest.is_some()
                {
                    return Err(RepositoryError::InvalidSnapshot);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorktreeTransition {
    pub worktree_transition_id: WorktreeTransitionId,
    pub transition_revision: u32,
    pub predecessor_revision: Option<u32>,
    pub from_worktree_instance_id: WorktreeId,
    pub from_snapshot_id: Option<WorktreeSnapshotId>,
    pub to_worktree_instance_id: WorktreeId,
    pub to_snapshot_id: Option<WorktreeSnapshotId>,
    pub kind: TransitionKind,
    pub lineage_assessment: LineageAssessment,
    pub correction_reason: Option<String>,
    pub source_watermark: u64,
    pub evidence_refs: Vec<String>,
}

impl WorktreeTransition {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        if !valid_revision_chain(self.transition_revision, self.predecessor_revision) {
            return Err(RepositoryError::InvalidRevision);
        }
        if (self.transition_revision > 1) != self.correction_reason.is_some() {
            return Err(RepositoryError::InvalidTransition);
        }
        if let Some(reason) = &self.correction_reason {
            valid_ref(reason)?;
        }
        if self.evidence_refs.is_empty() {
            return Err(RepositoryError::InvalidTransition);
        }
        for reference in &self.evidence_refs {
            valid_ref(reference)?;
        }
        require_unique(&self.evidence_refs)?;
        let same_worktree = self.from_worktree_instance_id == self.to_worktree_instance_id;
        let kind_valid = match self.kind {
            TransitionKind::PathMoved
            | TransitionKind::HeadAdvanced
            | TransitionKind::BranchSwitched
            | TransitionKind::DetachedOrAttached
            | TransitionKind::HistoryRewritten
            | TransitionKind::WorktreeMissing
            | TransitionKind::WorktreeRepaired
            | TransitionKind::WorktreeRemoved
            | TransitionKind::WorktreePruned
            | TransitionKind::RepositoryMoved => same_worktree,
            TransitionKind::WorktreeRecreated | TransitionKind::RepositoryCopied => !same_worktree,
            TransitionKind::MergeIntegrated | TransitionKind::PatchTransferred => true,
        };
        if !kind_valid {
            return Err(RepositoryError::InvalidTransition);
        }
        let snapshot_required = matches!(
            self.kind,
            TransitionKind::HeadAdvanced
                | TransitionKind::BranchSwitched
                | TransitionKind::DetachedOrAttached
                | TransitionKind::HistoryRewritten
                | TransitionKind::MergeIntegrated
                | TransitionKind::PatchTransferred
        );
        if snapshot_required != self.to_snapshot_id.is_some() {
            return Err(RepositoryError::InvalidTransition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationEvent {
    pub integration_event_id: IntegrationEventId,
    pub repository_instance_id: RepositoryId,
    pub source_worktree_instance_id: WorktreeId,
    pub source_snapshot_id: WorktreeSnapshotId,
    pub destination_worktree_instance_id: WorktreeId,
    pub destination_snapshot_id: WorktreeSnapshotId,
    pub kind: IntegrationKind,
    pub commit_refs: Vec<String>,
    pub patch_equivalence_refs: Vec<String>,
    pub conflict_resolution_detected: bool,
    pub integrated_attempt_ids: Vec<AttemptId>,
    pub revalidated_anchor_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub assessment: LineageAssessment,
}

impl IntegrationEvent {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        if self.evidence_refs.is_empty() {
            return Err(RepositoryError::InvalidIntegration);
        }
        // S11 contract: Attempt objects do not exist yet, so this list is
        // always empty; it only reserves the schema position.
        if !self.integrated_attempt_ids.is_empty() {
            return Err(RepositoryError::InvalidIntegration);
        }
        for reference in &self.commit_refs {
            valid_oid(reference)?;
        }
        require_unique(&self.commit_refs)?;
        for reference in &self.patch_equivalence_refs {
            valid_ref(reference)?;
        }
        require_unique(&self.patch_equivalence_refs)?;
        for reference in &self.revalidated_anchor_refs {
            valid_ref(reference)?;
        }
        require_unique(&self.revalidated_anchor_refs)?;
        for reference in &self.evidence_refs {
            valid_ref(reference)?;
        }
        require_unique(&self.evidence_refs)?;
        if self.kind.ancestry_based() != !self.commit_refs.is_empty()
            || (!self.kind.ancestry_based() && self.patch_equivalence_refs.is_empty())
        {
            return Err(RepositoryError::InvalidIntegration);
        }
        if self.conflict_resolution_detected
            && self.assessment == LineageAssessment::Proven
            && self.revalidated_anchor_refs.is_empty()
        {
            return Err(RepositoryError::InvalidIntegration);
        }
        Ok(())
    }
}

fn valid_revision_chain(revision: u32, predecessor: Option<u32>) -> bool {
    revision > 0 && predecessor == revision.checked_sub(1).filter(|_| revision > 1)
}

fn valid_locator(value: &str) -> Result<(), RepositoryError> {
    if value.is_empty()
        || value.len() > MAX_LOCATOR_BYTES
        || !value.starts_with('/')
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(RepositoryError::InvalidReference);
    }
    Ok(())
}

fn valid_ref(value: &str) -> Result<(), RepositoryError> {
    if value.is_empty()
        || value.len() > MAX_REF_BYTES
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(RepositoryError::InvalidReference);
    }
    Ok(())
}

fn valid_oid(value: &str) -> Result<(), RepositoryError> {
    if !(value.len() == 40 || value.len() == 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RepositoryError::InvalidReference);
    }
    Ok(())
}

fn valid_digest(value: &str) -> Result<(), RepositoryError> {
    if value.len() != MAX_DIGEST_HEX
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RepositoryError::InvalidReference);
    }
    Ok(())
}

/// Persisted remote identity is a closed fingerprint format:
/// `s11-remote-fp-v1:` followed by 64 lowercase hex chars. No locator text,
/// host, username or file path is ever stored.
fn valid_remote_fingerprint(value: &str) -> Result<(), RepositoryError> {
    let Some(hex_digits) = value.strip_prefix(REMOTE_FINGERPRINT_PREFIX) else {
        return Err(RepositoryError::InvalidIdentity);
    };
    if hex_digits.len() != MAX_DIGEST_HEX
        || !hex_digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RepositoryError::InvalidIdentity);
    }
    Ok(())
}

fn valid_path_history(history: &[PathObservation], current: &str) -> Result<(), RepositoryError> {
    if history.is_empty() {
        return Err(RepositoryError::InvalidReference);
    }
    let mut previous_first = None;
    for observation in history {
        observation.validate()?;
        if previous_first.is_some_and(|first| observation.first_observed_at_us < first) {
            return Err(RepositoryError::InvalidReference);
        }
        previous_first = Some(observation.first_observed_at_us);
    }
    if history.last().is_some_and(|entry| entry.path != current) {
        return Err(RepositoryError::InvalidReference);
    }
    Ok(())
}

fn require_unique<T: Ord + Clone>(values: &[T]) -> Result<(), RepositoryError> {
    if values.iter().cloned().collect::<BTreeSet<_>>().len() != values.len() {
        Err(RepositoryError::Duplicate)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RepositoryError {
    #[error("repository revision chain is invalid")]
    InvalidRevision,
    #[error("repository reference is invalid")]
    InvalidReference,
    #[error("repository collection contains duplicates")]
    Duplicate,
    #[error("repository identity evidence is invalid")]
    InvalidIdentity,
    #[error("worktree lifecycle state is invalid")]
    InvalidLifecycle,
    #[error("worktree snapshot is invalid")]
    InvalidSnapshot,
    #[error("worktree transition is invalid")]
    InvalidTransition,
    #[error("integration event is invalid")]
    InvalidIntegration,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn path_observation(path: &str) -> PathObservation {
        PathObservation {
            path: path.into(),
            first_observed_at_us: 1,
            last_observed_at_us: 1,
            evidence_refs: vec!["probe-a".into()],
        }
    }

    fn fingerprint() -> String {
        format!("{REMOTE_FINGERPRINT_PREFIX}{}", "ab".repeat(32))
    }

    fn repository() -> RepositoryInstance {
        RepositoryInstance {
            repository_id: RepositoryId::from_str("repo:01890f47-6a4a-7cc1-98b9-01890f476a01")
                .unwrap(),
            repository_revision: 1,
            predecessor_revision: None,
            current_path: "/repo".into(),
            path_history: vec![path_observation("/repo")],
            git_common_dir_path: Some("/repo/.git".into()),
            common_dir_filesystem: Some(FilesystemIdentity {
                device: 1,
                inode: 2,
            }),
            object_format: Some(GitObjectFormat::Sha1),
            remote_fingerprints: vec![fingerprint()],
            derived_from: None,
            identity_evidence_refs: vec!["probe-a".into()],
            recorded_at_us: 1,
        }
    }

    fn worktree(repository: &RepositoryInstance) -> WorktreeInstance {
        WorktreeInstance {
            worktree_instance_id: WorktreeId::from_str("wt:01890f47-6a4a-7cc1-98b9-01890f476a11")
                .unwrap(),
            worktree_revision: 1,
            predecessor_revision: None,
            repository_instance_id: repository.repository_id,
            kind: WorktreeKind::Main,
            lifecycle: WorktreeLifecycle::Active,
            current_path: Some("/repo".into()),
            path_history: vec![path_observation("/repo")],
            git_admin_path_history: vec![path_observation("/repo/.git")],
            git_registration_state: GitRegistrationState::Registered,
            current_snapshot_id: None,
            created_event_ref: "probe-a".into(),
            terminal_event_ref: None,
            recreated_from_worktree_instance_id: None,
            recorded_at_us: 1,
        }
    }

    fn transition(worktree: &WorktreeInstance) -> WorktreeTransition {
        WorktreeTransition {
            worktree_transition_id: WorktreeTransitionId::from_str(
                "wtt:01890f47-6a4a-7cc1-98b9-01890f476a21",
            )
            .unwrap(),
            transition_revision: 1,
            predecessor_revision: None,
            from_worktree_instance_id: worktree.worktree_instance_id,
            from_snapshot_id: None,
            to_worktree_instance_id: worktree.worktree_instance_id,
            to_snapshot_id: None,
            kind: TransitionKind::WorktreeMissing,
            lineage_assessment: LineageAssessment::Proven,
            correction_reason: None,
            source_watermark: 1,
            evidence_refs: vec!["probe-b".into()],
        }
    }

    #[test]
    fn revision_chain_is_strict_and_initial_revision_has_no_predecessor() {
        let mut value = repository();
        assert_eq!(value.validate(), Ok(()));
        value.predecessor_revision = Some(0);
        assert_eq!(value.validate(), Err(RepositoryError::InvalidRevision));
        value.repository_revision = 2;
        value.predecessor_revision = Some(2);
        assert_eq!(value.validate(), Err(RepositoryError::InvalidRevision));
        value.predecessor_revision = Some(1);
        assert_eq!(value.validate(), Ok(()));
    }

    #[test]
    fn remote_fingerprints_are_a_closed_hashed_format() {
        let mut value = repository();
        assert_eq!(value.validate(), Ok(()));
        // Wrong prefix.
        value.remote_fingerprints = vec![format!("s11-remote-fp-v0:{}", "ab".repeat(32))];
        assert_eq!(value.validate(), Err(RepositoryError::InvalidIdentity));
        // Raw locators are never a valid fingerprint.
        value.remote_fingerprints = vec!["https://example.com/org/repo.git".into()];
        assert_eq!(value.validate(), Err(RepositoryError::InvalidIdentity));
        // Wrong length.
        value.remote_fingerprints = vec![format!("{REMOTE_FINGERPRINT_PREFIX}{}", "ab".repeat(31))];
        assert_eq!(value.validate(), Err(RepositoryError::InvalidIdentity));
        // Uppercase hex is rejected.
        value.remote_fingerprints = vec![format!("{REMOTE_FINGERPRINT_PREFIX}{}", "AB".repeat(32))];
        assert_eq!(value.validate(), Err(RepositoryError::InvalidIdentity));
        // Non-hex is rejected.
        value.remote_fingerprints = vec![format!("{REMOTE_FINGERPRINT_PREFIX}{}", "gh".repeat(32))];
        assert_eq!(value.validate(), Err(RepositoryError::InvalidIdentity));
        value.remote_fingerprints = vec![fingerprint()];
        assert_eq!(value.validate(), Ok(()));
    }

    #[test]
    fn terminal_worktrees_require_terminal_evidence_and_no_current_path() {
        let repository = repository();
        let mut value = worktree(&repository);
        value.lifecycle = WorktreeLifecycle::Removed;
        assert_eq!(value.validate(), Err(RepositoryError::InvalidLifecycle));
        value.terminal_event_ref = Some("remove-proof".into());
        assert_eq!(value.validate(), Err(RepositoryError::InvalidLifecycle));
        value.current_path = None;
        assert_eq!(value.validate(), Ok(()));
        assert!(!lifecycle_successor_allowed(
            WorktreeLifecycle::Removed,
            WorktreeLifecycle::Active
        ));
        assert!(lifecycle_successor_allowed(
            WorktreeLifecycle::Missing,
            WorktreeLifecycle::Active
        ));
        assert!(lifecycle_successor_allowed(
            WorktreeLifecycle::Removed,
            WorktreeLifecycle::Removed
        ));
    }

    #[test]
    fn snapshot_detached_branch_and_capture_status_are_closed() {
        let repository = repository();
        let worktree = worktree(&repository);
        let snapshot = WorktreeSnapshot {
            worktree_snapshot_id: WorktreeSnapshotId::from_str(
                "wts:01890f47-6a4a-7cc1-98b9-01890f476a31",
            )
            .unwrap(),
            worktree_instance_id: worktree.worktree_instance_id,
            head_oid: Some("a".repeat(40)),
            tree_oid: Some("b".repeat(40)),
            branch_ref: Some("refs/heads/main".into()),
            detached_head: false,
            tracked_diff_digest: Some("c".repeat(64)),
            index_digest: Some("d".repeat(64)),
            untracked_manifest_digest: Some("e".repeat(64)),
            relevant_anchor_digests: Vec::new(),
            dependency_fingerprints: Vec::new(),
            toolchain_fingerprint: None,
            git_operation: GitOperation::None,
            captured_at_us: 1,
            evidence_refs: vec!["probe-a".into()],
            capture_status: SnapshotCaptureStatus::Complete,
            omission_reasons: Vec::new(),
        };
        assert_eq!(snapshot.validate(), Ok(()));
        let mut detached = snapshot.clone();
        detached.branch_ref = None;
        assert_eq!(detached.validate(), Err(RepositoryError::InvalidSnapshot));
        detached.detached_head = true;
        assert_eq!(detached.validate(), Ok(()));
        let mut partial = snapshot.clone();
        partial.capture_status = SnapshotCaptureStatus::Partial;
        assert_eq!(partial.validate(), Err(RepositoryError::InvalidSnapshot));
        partial.omission_reasons = vec![SnapshotOmission {
            field: SnapshotField::UntrackedManifestDigest,
            reason: ProbeUnavailableReason::OutputLimitExceeded,
        }];
        assert_eq!(partial.validate(), Ok(()));
    }

    #[test]
    fn transition_kind_worktree_cardinality_and_corrections_are_closed() {
        let repository = repository();
        let worktree = worktree(&repository);
        let value = transition(&worktree);
        assert_eq!(value.validate(), Ok(()));
        let mut recreated = value.clone();
        recreated.kind = TransitionKind::WorktreeRecreated;
        assert_eq!(
            recreated.validate(),
            Err(RepositoryError::InvalidTransition)
        );
        recreated.to_worktree_instance_id =
            WorktreeId::from_str("wt:01890f47-6a4a-7cc1-98b9-01890f476a12").unwrap();
        assert_eq!(recreated.validate(), Ok(()));
        let mut correction = value.clone();
        correction.transition_revision = 2;
        correction.predecessor_revision = Some(1);
        assert_eq!(
            correction.validate(),
            Err(RepositoryError::InvalidTransition)
        );
        correction.correction_reason = Some("late-evidence".into());
        assert_eq!(correction.validate(), Ok(()));
        let mut advanced = value;
        advanced.kind = TransitionKind::HeadAdvanced;
        assert_eq!(advanced.validate(), Err(RepositoryError::InvalidTransition));
        advanced.to_snapshot_id =
            Some(WorktreeSnapshotId::from_str("wts:01890f47-6a4a-7cc1-98b9-01890f476a31").unwrap());
        assert_eq!(advanced.validate(), Ok(()));
    }

    #[test]
    fn integration_evidence_gates_are_closed() {
        let repository = repository();
        let worktree = worktree(&repository);
        let event = IntegrationEvent {
            integration_event_id: IntegrationEventId::from_str(
                "int:01890f47-6a4a-7cc1-98b9-01890f476a41",
            )
            .unwrap(),
            repository_instance_id: repository.repository_id,
            source_worktree_instance_id: worktree.worktree_instance_id,
            source_snapshot_id: WorktreeSnapshotId::from_str(
                "wts:01890f47-6a4a-7cc1-98b9-01890f476a31",
            )
            .unwrap(),
            destination_worktree_instance_id: worktree.worktree_instance_id,
            destination_snapshot_id: WorktreeSnapshotId::from_str(
                "wts:01890f47-6a4a-7cc1-98b9-01890f476a32",
            )
            .unwrap(),
            kind: IntegrationKind::MergeCommit,
            commit_refs: vec!["a".repeat(40)],
            patch_equivalence_refs: Vec::new(),
            conflict_resolution_detected: false,
            integrated_attempt_ids: Vec::new(),
            revalidated_anchor_refs: Vec::new(),
            evidence_refs: vec!["merge-host-event".into()],
            assessment: LineageAssessment::Proven,
        };
        assert_eq!(event.validate(), Ok(()));
        let mut cherry_pick = event.clone();
        cherry_pick.kind = IntegrationKind::CherryPick;
        assert_eq!(
            cherry_pick.validate(),
            Err(RepositoryError::InvalidIntegration)
        );
        cherry_pick.commit_refs = Vec::new();
        cherry_pick.patch_equivalence_refs = vec!["patch-proof".into()];
        assert_eq!(cherry_pick.validate(), Ok(()));
        let mut conflicted = event.clone();
        conflicted.conflict_resolution_detected = true;
        assert_eq!(
            conflicted.validate(),
            Err(RepositoryError::InvalidIntegration)
        );
        conflicted.revalidated_anchor_refs = vec!["anchor-a".into()];
        assert_eq!(conflicted.validate(), Ok(()));
    }
}
