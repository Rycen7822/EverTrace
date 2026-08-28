//! Immutable S16 recovery request, bundle, and application contracts.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    ids::{
        AttemptId, RecoveryApplicationId, RecoveryBundleId, RecoveryCaptureRequestId, RepositoryId,
        WorktreeId, WorktreeSnapshotId,
    },
    revision::RevisionId,
};

use super::RepositoryError;

pub const RECOVERY_CONTRACT_VERSION: u32 = 1;
pub const SUPPORTED_MUTATION_DOMAIN: &str = "supported_codex_local_mutators";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DestructiveClass {
    GitWorktreeRemove,
    GitResetHard,
    GitClean,
    GitCheckoutForce,
    GitSwitchDiscardChanges,
    GitRestoreDiscard,
    TrackedFileRemove,
    AttemptAnchorRemove,
    RegisteredArtifactRemove,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DestructiveDetectionStatus {
    Matched,
    Unknown,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UntrackedCaptureScope {
    Standard,
    StandardAndIgnored,
    IgnoredOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRequestStatus {
    Pending,
    Complete,
    Partial,
    Skipped,
    Failed,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReasonCode {
    CaptureComplete,
    CapturePartial,
    NoRecoverableContent,
    DaemonCaptureFailed,
    DeadlineExhausted,
    DaemonOrWireUnavailable,
    DaemonTimeout,
    LateTimeout,
}

impl RecoveryRequestStatus {
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCaptureStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingIntegrity {
    Complete,
    Raced,
    BestEffort,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOmissionReason {
    SecretRedacted,
    CredentialExcluded,
    PrivateKeyExcluded,
    FileTooLarge,
    UntrackedTotalExceeded,
    BundleBudgetExceeded,
    TimeBudgetExceeded,
    RegenerableBuildOutput,
    UnsupportedKind,
    Unreadable,
    ConcurrentChange,
    CriticalTrackedStateMissing,
    CriticalIndexStateMissing,
    AttemptAnchorMissing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryOmission {
    pub item_ref: String,
    pub reason: RecoveryOmissionReason,
    pub metadata_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryContentRef {
    pub item_ref: String,
    pub payload: RecoveryProtectedRef,
    pub protected_relative_path: Option<RecoveryProtectedRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryProtectedRef {
    pub cas_ref: String,
    pub protected_length: u64,
    pub original_length: u64,
    pub protected_secret_digest: Option<String>,
    pub redaction_spans: u32,
}

impl RecoveryContentRef {
    pub fn validate(&self, file: bool) -> Result<(), RepositoryError> {
        if !valid_ref(&self.item_ref) || self.payload.validate(!file).is_err() {
            return Err(RepositoryError::InvalidRecovery);
        }
        match (&self.protected_relative_path, file) {
            (Some(path), true) if path.validate(true).is_ok() => Ok(()),
            (None, false) => Ok(()),
            _ => Err(RepositoryError::InvalidRecovery),
        }
    }

    fn protected_bytes(&self) -> Option<u64> {
        self.payload.protected_length.checked_add(
            self.protected_relative_path
                .as_ref()
                .map_or(0, |path| path.protected_length),
        )
    }
}

impl RecoveryProtectedRef {
    fn validate(&self, nonempty: bool) -> Result<(), RepositoryError> {
        if !valid_cas_ref(&self.cas_ref)
            || (nonempty && (self.protected_length == 0 || self.original_length == 0))
            || (!nonempty && (self.protected_length != 0) != (self.original_length != 0))
            || self
                .protected_secret_digest
                .as_deref()
                .is_some_and(|value| !valid_digest(value))
            || (self.redaction_spans == 0) != self.protected_secret_digest.is_none()
        {
            return Err(RepositoryError::InvalidRecovery);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCaptureRequest {
    pub recovery_capture_request_id: RecoveryCaptureRequestId,
    pub request_revision_id: RevisionId,
    pub parent_request_revision_id: Option<RevisionId>,
    pub trigger_event_id: String,
    pub repository_instance_id: RepositoryId,
    pub worktree_instance_id: WorktreeId,
    pub pre_operation_snapshot_id: Option<WorktreeSnapshotId>,
    pub command_fingerprint: String,
    pub destructive_class: DestructiveClass,
    pub untracked_capture_scope: UntrackedCaptureScope,
    pub detection_status: DestructiveDetectionStatus,
    pub request_status: RecoveryRequestStatus,
    pub recovery_bundle_id: Option<RecoveryBundleId>,
    pub reason_codes: Vec<RecoveryReasonCode>,
    pub started_at_us: i64,
    pub finished_at_us: Option<i64>,
    pub effective_config_hash: [u8; 32],
}

impl RecoveryCaptureRequest {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        if !valid_ref(&self.trigger_event_id)
            || !valid_digest(&self.command_fingerprint)
            || self.started_at_us < 0
            || self
                .finished_at_us
                .is_some_and(|value| value < self.started_at_us)
            || !unique(&self.reason_codes)
            || (self.request_status == RecoveryRequestStatus::Pending)
                != self.parent_request_revision_id.is_none()
            || self.request_status.is_terminal() != self.finished_at_us.is_some()
            || (self.request_status == RecoveryRequestStatus::Complete
                && self.recovery_bundle_id.is_none())
            || (self.request_status == RecoveryRequestStatus::Complete
                && self.pre_operation_snapshot_id.is_none())
            || self.detection_status != DestructiveDetectionStatus::Matched
        {
            return Err(RepositoryError::InvalidRecovery);
        }
        if self.request_status == RecoveryRequestStatus::Pending
            && (self.recovery_bundle_id.is_some()
                || self.pre_operation_snapshot_id.is_some()
                || !self.reason_codes.is_empty())
        {
            return Err(RepositoryError::InvalidRecovery);
        }
        if self.request_status.is_terminal() && self.reason_codes.is_empty() {
            return Err(RepositoryError::InvalidRecovery);
        }
        Ok(())
    }

    pub fn is_successor_of(&self, current: &Self) -> bool {
        self.recovery_capture_request_id == current.recovery_capture_request_id
            && current.request_status == RecoveryRequestStatus::Pending
            && self.request_status.is_terminal()
            && self.parent_request_revision_id == Some(current.request_revision_id)
            && self.request_revision_id != current.request_revision_id
            && self.trigger_event_id == current.trigger_event_id
            && self.repository_instance_id == current.repository_instance_id
            && self.worktree_instance_id == current.worktree_instance_id
            && self.command_fingerprint == current.command_fingerprint
            && self.destructive_class == current.destructive_class
            && self.untracked_capture_scope == current.untracked_capture_scope
            && self.detection_status == current.detection_status
            && self.started_at_us == current.started_at_us
            && self.effective_config_hash == current.effective_config_hash
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBundle {
    pub recovery_bundle_id: RecoveryBundleId,
    pub source_worktree_instance_id: WorktreeId,
    pub source_snapshot_id: WorktreeSnapshotId,
    pub trigger_request_ids: Vec<RecoveryCaptureRequestId>,
    pub tracked_diff_blob_refs: Vec<RecoveryContentRef>,
    pub tracked_file_blob_refs: Vec<RecoveryContentRef>,
    pub index_state_refs: Vec<RecoveryContentRef>,
    pub untracked_file_blob_refs: Vec<RecoveryContentRef>,
    pub untracked_work_artifact_refs: Vec<String>,
    pub metadata_only_work_artifact_refs: Vec<String>,
    pub config_and_run_refs: Vec<String>,
    pub attempt_anchor_ids: Vec<AttemptId>,
    pub omissions: Vec<RecoveryOmission>,
    pub capture_status: RecoveryCaptureStatus,
    pub ordering_integrity: OrderingIntegrity,
    pub adapter_manifest_id: String,
    pub eligible_mutation_manifest_version: u32,
    pub eligible_mutation_domain: String,
    pub captured_bytes: u64,
    pub captured_at_us: i64,
}

impl RecoveryBundle {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        for value in self
            .tracked_diff_blob_refs
            .iter()
            .chain(&self.index_state_refs)
        {
            value.validate(false)?;
        }
        for value in self
            .tracked_file_blob_refs
            .iter()
            .chain(&self.untracked_file_blob_refs)
        {
            value.validate(true)?;
        }
        let content_bytes = self
            .tracked_diff_blob_refs
            .iter()
            .chain(&self.tracked_file_blob_refs)
            .chain(&self.index_state_refs)
            .chain(&self.untracked_file_blob_refs)
            .try_fold(0_u64, |total, value| {
                total.checked_add(value.protected_bytes()?)
            })
            .ok_or(RepositoryError::InvalidRecovery)?;
        let has_recoverable_content = !self.tracked_diff_blob_refs.is_empty()
            || !self.tracked_file_blob_refs.is_empty()
            || !self.index_state_refs.is_empty()
            || !self.untracked_file_blob_refs.is_empty()
            || !self.untracked_work_artifact_refs.is_empty()
            || !self.metadata_only_work_artifact_refs.is_empty()
            || !self.config_and_run_refs.is_empty();
        let has_partial_fact =
            !self.omissions.is_empty() || self.ordering_integrity != OrderingIntegrity::Complete;
        if self.trigger_request_ids.is_empty()
            || self.eligible_mutation_manifest_version == 0
            || self.eligible_mutation_domain != SUPPORTED_MUTATION_DOMAIN
            || !valid_ref(&self.adapter_manifest_id)
            || self.captured_at_us < 0
            || self.captured_bytes != content_bytes
            || (!has_recoverable_content && !has_partial_fact)
            || !unique(&self.trigger_request_ids)
            || !unique(&self.attempt_anchor_ids)
            || !unique_valid_refs(&self.untracked_work_artifact_refs)
            || !unique_valid_refs(&self.metadata_only_work_artifact_refs)
            || !unique_valid_refs(&self.config_and_run_refs)
            || !unique_content_refs(self)
            || !unique_omissions(&self.omissions)
        {
            return Err(RepositoryError::InvalidRecovery);
        }
        if self.capture_status == RecoveryCaptureStatus::Complete
            && (!has_recoverable_content
                || !self.omissions.is_empty()
                || self.ordering_integrity != OrderingIntegrity::Complete)
        {
            return Err(RepositoryError::InvalidRecovery);
        }
        if self.capture_status == RecoveryCaptureStatus::Partial
            && self.omissions.is_empty()
            && self.ordering_integrity == OrderingIntegrity::Complete
        {
            return Err(RepositoryError::InvalidRecovery);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryApplicationKind {
    Patch,
    FileRestore,
    IndexRestore,
    Mixed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryApplicationStatus {
    Applied,
    PartiallyApplied,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApplication {
    pub recovery_application_id: RecoveryApplicationId,
    pub revision_id: RevisionId,
    pub parent_revision_id: Option<RevisionId>,
    pub recovery_bundle_id: RecoveryBundleId,
    pub target_worktree_instance_id: WorktreeId,
    pub pre_application_snapshot_id: Option<WorktreeSnapshotId>,
    pub post_application_snapshot_id: Option<WorktreeSnapshotId>,
    pub application_kind: RecoveryApplicationKind,
    pub application_evidence_refs: Vec<String>,
    pub verification_refs: Vec<String>,
    pub application_status: RecoveryApplicationStatus,
    pub created_at_us: i64,
}

impl RecoveryApplication {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        if self.created_at_us < 0
            || !unique_valid_refs(&self.application_evidence_refs)
            || !unique_valid_refs(&self.verification_refs)
        {
            return Err(RepositoryError::InvalidRecovery);
        }
        if self.supports_compatible_lineage_transfer()
            && self.pre_application_snapshot_id == self.post_application_snapshot_id
        {
            return Err(RepositoryError::InvalidRecovery);
        }
        Ok(())
    }

    pub fn supports_compatible_lineage_transfer(&self) -> bool {
        false
    }

    pub fn is_successor_of(&self, current: &Self) -> bool {
        let evidence_progress = self.application_evidence_refs.len()
            > current.application_evidence_refs.len()
            || self.verification_refs.len() > current.verification_refs.len()
            || self.post_application_snapshot_id != current.post_application_snapshot_id;
        let verification_progress = self.verification_refs.len() > current.verification_refs.len()
            || self.post_application_snapshot_id != current.post_application_snapshot_id;
        self.recovery_application_id == current.recovery_application_id
            && self.revision_id != current.revision_id
            && self.parent_revision_id == Some(current.revision_id)
            && self.recovery_bundle_id == current.recovery_bundle_id
            && self.target_worktree_instance_id == current.target_worktree_instance_id
            && self.pre_application_snapshot_id == current.pre_application_snapshot_id
            && self.application_kind == current.application_kind
            && current
                .application_evidence_refs
                .iter()
                .all(|value| self.application_evidence_refs.contains(value))
            && current
                .verification_refs
                .iter()
                .all(|value| self.verification_refs.contains(value))
            && current
                .post_application_snapshot_id
                .is_none_or(|snapshot| self.post_application_snapshot_id == Some(snapshot))
            && match current.application_status {
                RecoveryApplicationStatus::Applied => {
                    self.application_status == RecoveryApplicationStatus::Applied
                        && verification_progress
                }
                RecoveryApplicationStatus::Failed => {
                    self.application_status == RecoveryApplicationStatus::Failed
                        && verification_progress
                }
                RecoveryApplicationStatus::PartiallyApplied => {
                    matches!(
                        self.application_status,
                        RecoveryApplicationStatus::PartiallyApplied
                            | RecoveryApplicationStatus::Applied
                            | RecoveryApplicationStatus::Failed
                    ) && evidence_progress
                }
                RecoveryApplicationStatus::Unknown => evidence_progress,
            }
            && self.created_at_us >= current.created_at_us
    }
}

fn valid_ref(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_cas_ref(value: &str) -> bool {
    value.strip_prefix("cas:").is_some_and(valid_digest) || valid_digest(value)
}

fn unique_valid_refs(values: &[String]) -> bool {
    values.iter().all(|value| valid_ref(value)) && unique(values)
}

fn unique<T: Ord>(values: &[T]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn unique_content_refs(bundle: &RecoveryBundle) -> bool {
    let mut refs = BTreeSet::new();
    bundle
        .tracked_diff_blob_refs
        .iter()
        .chain(&bundle.tracked_file_blob_refs)
        .chain(&bundle.index_state_refs)
        .chain(&bundle.untracked_file_blob_refs)
        .all(|value| refs.insert(&value.item_ref))
}

fn unique_omissions(values: &[RecoveryOmission]) -> bool {
    let mut refs = BTreeSet::new();
    values.iter().all(|value| {
        valid_ref(&value.item_ref)
            && value.metadata_ref.as_deref().is_none_or(valid_ref)
            && refs.insert(&value.item_ref)
    })
}
