//! Immutable S16 recovery request, bundle, and application contracts.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    ids::{
        AttemptId, CaptureReceiptId, CasId, CompetingAttemptGroupId, ExecutionLaneId, OperationId,
        RecoveryApplicationId, RecoveryBundleId, RecoveryCaptureRequestId, RepositoryId,
        ScopeEffectId, SourceObservationId, WorktreeId, WorktreeSnapshotId,
    },
    revision::RevisionId,
    work::CompetingResolutionStatus,
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
    pub attempt_anchor_claims: Vec<RecoveryAttemptAnchorClaim>,
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
    pub fn is_exact_patch_only_anchor_shape(&self) -> bool {
        self.capture_status == RecoveryCaptureStatus::Complete
            && self.ordering_integrity == OrderingIntegrity::Complete
            && self.omissions.is_empty()
            && matches!(self.tracked_diff_blob_refs.as_slice(), [content] if content.item_ref == "git:tracked_diff")
            && self.tracked_file_blob_refs.is_empty()
            && self.index_state_refs.is_empty()
            && self.untracked_file_blob_refs.is_empty()
            && self.untracked_work_artifact_refs.is_empty()
            && self.metadata_only_work_artifact_refs.is_empty()
            && self.config_and_run_refs.is_empty()
    }

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
            .and_then(|total| {
                let mut seen = BTreeSet::new();
                self.attempt_anchor_claims
                    .iter()
                    .try_fold(total, |sum, claim| {
                        if seen.insert(&claim.affected_relative_path.cas_ref) {
                            sum.checked_add(claim.affected_relative_path.protected_length)
                        } else {
                            Some(sum)
                        }
                    })
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
            || !unique_anchor_claims(&self.attempt_anchor_claims)
            || self
                .attempt_anchor_claims
                .iter()
                .any(|claim| !self.attempt_anchor_ids.contains(&claim.attempt_id))
            || !self.attempt_anchor_claims.is_empty() && !self.is_exact_patch_only_anchor_shape()
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
#[serde(deny_unknown_fields)]
pub struct RecoveryConfinedFileIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: u64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCompetingGroupClaim {
    pub competing_group_id: CompetingAttemptGroupId,
    pub revision_id: RevisionId,
    pub resolution_status: CompetingResolutionStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAttemptAnchorClaim {
    pub attempt_id: AttemptId,
    pub attempt_revision_id: RevisionId,
    pub strategy_contract_fingerprint: [u8; 32],
    pub source_repository_instance_id: RepositoryId,
    pub source_worktree_instance_id: WorktreeId,
    pub source_snapshot_id: WorktreeSnapshotId,
    pub affected_relative_path: RecoveryProtectedRef,
    pub source_file_identity: RecoveryConfinedFileIdentity,
    pub competing_groups: Vec<RecoveryCompetingGroupClaim>,
}

impl RecoveryAttemptAnchorClaim {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        if self.strategy_contract_fingerprint == [0; 32]
            || self.affected_relative_path.redaction_spans != 0
            || self
                .affected_relative_path
                .protected_secret_digest
                .is_some()
            || self.affected_relative_path.validate(true).is_err()
            || self.affected_relative_path.original_length == 0
            || self.affected_relative_path.original_length > 4096
            || self.affected_relative_path.protected_length
                != self.affected_relative_path.original_length
            || self.source_file_identity.device == 0
            || self.source_file_identity.inode == 0
            || self.source_file_identity.mtime_nanoseconds >= 1_000_000_000
            || self.source_file_identity.ctime_nanoseconds >= 1_000_000_000
            || self.competing_groups.len() > 256
            || self
                .competing_groups
                .windows(2)
                .any(|pair| pair[0].competing_group_id >= pair[1].competing_group_id)
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryInputDeliveryKind {
    PatchStdin,
    ConfinedFileRestore,
    IndexRestore,
    Mixed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryInputDeliveryState {
    Admitted,
    Delivered,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryVerificationOutcome {
    Applied,
    PartiallyApplied,
    NotApplied,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryVerifierReceipt {
    pub verification_revision: u32,
    pub verifier_version: u16,
    pub result_source_observation_id: SourceObservationId,
    pub post_application_snapshot_id: WorktreeSnapshotId,
    pub outcome: RecoveryVerificationOutcome,
}

pub const RECOVERY_ANCHOR_VERIFIER_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAnchorVerifierReceipt {
    pub verifier_version: u16,
    pub attempt_id: AttemptId,
    pub source_attempt_revision_id: RevisionId,
    pub revalidated_attempt_revision_id: RevisionId,
    pub strategy_contract_fingerprint: [u8; 32],
    pub source_repository_instance_id: RepositoryId,
    pub source_worktree_instance_id: WorktreeId,
    pub source_snapshot_id: WorktreeSnapshotId,
    pub target_repository_instance_id: RepositoryId,
    pub target_worktree_instance_id: WorktreeId,
    pub post_application_snapshot_id: WorktreeSnapshotId,
    pub affected_relative_path: RecoveryProtectedRef,
    pub competing_groups: Vec<RecoveryCompetingGroupClaim>,
    pub revalidated_competing_groups: Vec<RecoveryCompetingGroupClaim>,
    pub operation_id: OperationId,
    pub operation_revision: u32,
    pub execution_lane_id: ExecutionLaneId,
    pub capture_receipt_revision_id: CaptureReceiptId,
    pub scope_effect_ids: Vec<ScopeEffectId>,
    pub result_source_observation_id: SourceObservationId,
    pub recovery_verification_revision: u32,
}

impl RecoveryAnchorVerifierReceipt {
    fn validate(&self) -> Result<(), RepositoryError> {
        if self.verifier_version != RECOVERY_ANCHOR_VERIFIER_VERSION
            || self.strategy_contract_fingerprint == [0; 32]
            || self.source_repository_instance_id != self.target_repository_instance_id
            || self.source_worktree_instance_id == self.target_worktree_instance_id
            || self.operation_revision == 0
            || self.recovery_verification_revision == 0
            || !strictly_ordered(&self.scope_effect_ids)
            || self.affected_relative_path.validate(true).is_err()
            || self.affected_relative_path.redaction_spans != 0
            || self
                .affected_relative_path
                .protected_secret_digest
                .is_some()
            || self.competing_groups.len() > 256
            || self
                .competing_groups
                .windows(2)
                .any(|pair| pair[0].competing_group_id >= pair[1].competing_group_id)
            || self.competing_groups.iter().any(|source| {
                !self
                    .revalidated_competing_groups
                    .iter()
                    .any(|current| current.competing_group_id == source.competing_group_id)
            })
            || self
                .revalidated_competing_groups
                .windows(2)
                .any(|pair| pair[0].competing_group_id >= pair[1].competing_group_id)
            || self
                .revalidated_competing_groups
                .iter()
                .any(|group| group.resolution_status != CompetingResolutionStatus::Selected)
        {
            return Err(RepositoryError::InvalidRecovery);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApplication {
    pub recovery_application_id: RecoveryApplicationId,
    pub revision_id: RevisionId,
    pub parent_revision_id: Option<RevisionId>,
    pub recovery_bundle_id: RecoveryBundleId,
    pub target_worktree_instance_id: WorktreeId,
    pub pre_application_snapshot_id: WorktreeSnapshotId,
    pub post_application_snapshot_id: Option<WorktreeSnapshotId>,
    pub application_kind: RecoveryApplicationKind,
    pub ticket_claims_version: u16,
    pub selected_cas_refs: Vec<CasId>,
    pub input_delivery_kind: RecoveryInputDeliveryKind,
    pub input_delivery_state: RecoveryInputDeliveryState,
    pub operation_id: Option<OperationId>,
    pub operation_revision: Option<u32>,
    pub execution_lane_id: Option<ExecutionLaneId>,
    pub capture_receipt_revision_id: Option<CaptureReceiptId>,
    pub scope_effect_ids: Vec<ScopeEffectId>,
    pub input_source_observation_ids: Vec<SourceObservationId>,
    pub result_source_observation_ids: Vec<SourceObservationId>,
    pub verifier_receipts: Vec<RecoveryVerifierReceipt>,
    pub relevant_attempt_anchor_ids: Vec<AttemptId>,
    pub attempt_anchor_claims: Vec<RecoveryAttemptAnchorClaim>,
    pub anchor_verifier_receipts: Vec<RecoveryAnchorVerifierReceipt>,
    pub application_status: RecoveryApplicationStatus,
    pub created_at_us: i64,
}

impl RecoveryApplication {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        let initial = self.parent_revision_id.is_none();
        let operation_shape = self.operation_id.is_some() == self.operation_revision.is_some()
            && self.operation_revision.is_none_or(|value| value > 0);
        let delivered_shape = self.input_delivery_state == RecoveryInputDeliveryState::Delivered
            && self.operation_id.is_some()
            && self.execution_lane_id.is_some()
            && self.capture_receipt_revision_id.is_some()
            && !self.scope_effect_ids.is_empty()
            && !self.input_source_observation_ids.is_empty();
        if self.created_at_us < 0
            || self.ticket_claims_version == 0
            || self.selected_cas_refs.is_empty()
            || !strictly_ordered(&self.selected_cas_refs)
            || !strictly_ordered(&self.scope_effect_ids)
            || !strictly_ordered(&self.input_source_observation_ids)
            || !strictly_ordered(&self.result_source_observation_ids)
            || !valid_verifier_receipts(&self.verifier_receipts)
            || !strictly_ordered(&self.relevant_attempt_anchor_ids)
            || !unique_anchor_claims(&self.attempt_anchor_claims)
            || self
                .attempt_anchor_claims
                .iter()
                .any(|claim| !self.relevant_attempt_anchor_ids.contains(&claim.attempt_id))
            || !valid_anchor_verifier_receipts(self)
            || !self.anchor_verifier_receipts.is_empty()
                && self.application_status != RecoveryApplicationStatus::Applied
            || !operation_shape
            || initial
                && (self.input_delivery_state != RecoveryInputDeliveryState::Admitted
                    || self.application_status != RecoveryApplicationStatus::Unknown
                    || self.post_application_snapshot_id.is_some()
                    || self.operation_id.is_some()
                    || self.execution_lane_id.is_some()
                    || self.capture_receipt_revision_id.is_some()
                    || !self.scope_effect_ids.is_empty()
                    || !self.input_source_observation_ids.is_empty()
                    || !self.result_source_observation_ids.is_empty()
                    || !self.verifier_receipts.is_empty()
                    || !self.anchor_verifier_receipts.is_empty())
            || !initial
                && self.input_delivery_state == RecoveryInputDeliveryState::Delivered
                && !delivered_shape
            || self.input_delivery_state == RecoveryInputDeliveryState::Admitted
                && (self.operation_id.is_some()
                    || self.execution_lane_id.is_some()
                    || self.capture_receipt_revision_id.is_some()
                    || !self.scope_effect_ids.is_empty()
                    || !self.input_source_observation_ids.is_empty()
                    || !self.result_source_observation_ids.is_empty()
                    || self.post_application_snapshot_id.is_some()
                    || !self.verifier_receipts.is_empty()
                    || !self.anchor_verifier_receipts.is_empty()
                    || self.application_status != RecoveryApplicationStatus::Unknown)
            || !status_evidence_is_valid(self)
        {
            return Err(RepositoryError::InvalidRecovery);
        }
        Ok(())
    }

    pub fn has_complete_recorded_lineage_transfer_receipts(&self) -> bool {
        self.application_status == RecoveryApplicationStatus::Applied
            && self.post_application_snapshot_id.is_some()
            && !self.relevant_attempt_anchor_ids.is_empty()
            && self.relevant_attempt_anchor_ids.len() == self.attempt_anchor_claims.len()
            && self.relevant_attempt_anchor_ids.len() == self.anchor_verifier_receipts.len()
            && Some(self.pre_application_snapshot_id) != self.post_application_snapshot_id
            && valid_anchor_verifier_receipts(self)
            && self
                .relevant_attempt_anchor_ids
                .iter()
                .zip(&self.attempt_anchor_claims)
                .zip(&self.anchor_verifier_receipts)
                .all(|((attempt_id, claim), receipt)| {
                    *attempt_id == claim.attempt_id && *attempt_id == receipt.attempt_id
                })
    }

    pub fn is_successor_of(&self, current: &Self) -> bool {
        if self.validate().is_err() || current.validate().is_err() {
            return false;
        }
        let anchor_progress = anchor_receipt_revalidation_progress(
            &current.anchor_verifier_receipts,
            &self.anchor_verifier_receipts,
        );
        let evidence_progress = self.input_delivery_state != current.input_delivery_state
            || option_progress(current.operation_id, self.operation_id)
            || option_progress(current.execution_lane_id, self.execution_lane_id)
            || option_progress(
                current.capture_receipt_revision_id,
                self.capture_receipt_revision_id,
            )
            || strict_superset(&current.scope_effect_ids, &self.scope_effect_ids)
            || strict_superset(
                &current.input_source_observation_ids,
                &self.input_source_observation_ids,
            )
            || strict_superset(
                &current.result_source_observation_ids,
                &self.result_source_observation_ids,
            )
            || option_progress(
                current.post_application_snapshot_id,
                self.post_application_snapshot_id,
            )
            || verifier_history_progress(&current.verifier_receipts, &self.verifier_receipts)
            || anchor_progress;
        let verification_progress =
            option_progress(
                current.post_application_snapshot_id,
                self.post_application_snapshot_id,
            ) || verifier_history_progress(&current.verifier_receipts, &self.verifier_receipts);
        self.recovery_application_id == current.recovery_application_id
            && self.revision_id != current.revision_id
            && self.parent_revision_id == Some(current.revision_id)
            && self.recovery_bundle_id == current.recovery_bundle_id
            && self.target_worktree_instance_id == current.target_worktree_instance_id
            && self.pre_application_snapshot_id == current.pre_application_snapshot_id
            && self.application_kind == current.application_kind
            && self.ticket_claims_version == current.ticket_claims_version
            && self.selected_cas_refs == current.selected_cas_refs
            && self.relevant_attempt_anchor_ids == current.relevant_attempt_anchor_ids
            && self.attempt_anchor_claims == current.attempt_anchor_claims
            && self.input_delivery_kind == current.input_delivery_kind
            && delivery_progress(current.input_delivery_state, self.input_delivery_state)
            && option_compatible(current.operation_id, self.operation_id)
            && option_compatible(current.operation_revision, self.operation_revision)
            && option_compatible(current.execution_lane_id, self.execution_lane_id)
            && option_compatible(
                current.capture_receipt_revision_id,
                self.capture_receipt_revision_id,
            )
            && contains_all(&self.scope_effect_ids, &current.scope_effect_ids)
            && contains_all(
                &self.input_source_observation_ids,
                &current.input_source_observation_ids,
            )
            && contains_all(
                &self.result_source_observation_ids,
                &current.result_source_observation_ids,
            )
            && option_compatible(
                current.post_application_snapshot_id,
                self.post_application_snapshot_id,
            )
            && (self.verifier_receipts == current.verifier_receipts
                || verifier_history_progress(&current.verifier_receipts, &self.verifier_receipts))
            && (self.anchor_verifier_receipts == current.anchor_verifier_receipts
                || anchor_progress)
            && match current.application_status {
                RecoveryApplicationStatus::Applied => {
                    self.application_status == RecoveryApplicationStatus::Applied
                        && (verification_progress || anchor_progress)
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

fn status_evidence_is_valid(value: &RecoveryApplication) -> bool {
    let terminal = match value.application_status {
        RecoveryApplicationStatus::Unknown => return value.verifier_receipts.is_empty(),
        RecoveryApplicationStatus::Applied => RecoveryVerificationOutcome::Applied,
        RecoveryApplicationStatus::PartiallyApplied => {
            RecoveryVerificationOutcome::PartiallyApplied
        }
        RecoveryApplicationStatus::Failed => RecoveryVerificationOutcome::NotApplied,
    };
    let Some(receipt) = value.verifier_receipts.last() else {
        return false;
    };
    value.input_delivery_state == RecoveryInputDeliveryState::Delivered
        && value.result_source_observation_ids.as_slice() == [receipt.result_source_observation_id]
        && value.post_application_snapshot_id.is_some()
        && Some(receipt.post_application_snapshot_id) == value.post_application_snapshot_id
        && value.verifier_receipts.iter().all(|candidate| {
            candidate.result_source_observation_id == receipt.result_source_observation_id
                && candidate.post_application_snapshot_id == receipt.post_application_snapshot_id
        })
        && receipt.outcome == terminal
}

fn valid_anchor_verifier_receipts(value: &RecoveryApplication) -> bool {
    if value.anchor_verifier_receipts.len() > 256
        || value
            .anchor_verifier_receipts
            .windows(2)
            .any(|pair| pair[0].attempt_id >= pair[1].attempt_id)
        || value
            .anchor_verifier_receipts
            .iter()
            .any(|receipt| receipt.validate().is_err())
    {
        return false;
    }
    value.anchor_verifier_receipts.iter().all(|receipt| {
        let Some(claim) = value
            .attempt_anchor_claims
            .iter()
            .find(|claim| claim.attempt_id == receipt.attempt_id)
        else {
            return false;
        };
        receipt.source_attempt_revision_id == claim.attempt_revision_id
            && receipt.strategy_contract_fingerprint == claim.strategy_contract_fingerprint
            && receipt.source_repository_instance_id == claim.source_repository_instance_id
            && receipt.source_worktree_instance_id == claim.source_worktree_instance_id
            && receipt.source_snapshot_id == claim.source_snapshot_id
            && receipt.affected_relative_path == claim.affected_relative_path
            && receipt.competing_groups == claim.competing_groups
            && receipt.target_worktree_instance_id == value.target_worktree_instance_id
            && Some(receipt.post_application_snapshot_id) == value.post_application_snapshot_id
            && Some(receipt.operation_id) == value.operation_id
            && Some(receipt.operation_revision) == value.operation_revision
            && Some(receipt.execution_lane_id) == value.execution_lane_id
            && Some(receipt.capture_receipt_revision_id) == value.capture_receipt_revision_id
            && receipt.scope_effect_ids == value.scope_effect_ids
            && value.result_source_observation_ids.as_slice()
                == [receipt.result_source_observation_id]
            && value.verifier_receipts.iter().any(|verifier| {
                verifier.verification_revision == receipt.recovery_verification_revision
                    && verifier.outcome == RecoveryVerificationOutcome::Applied
                    && verifier.result_source_observation_id == receipt.result_source_observation_id
                    && verifier.post_application_snapshot_id == receipt.post_application_snapshot_id
            })
    })
}

fn anchor_receipt_revalidation_progress(
    current: &[RecoveryAnchorVerifierReceipt],
    next: &[RecoveryAnchorVerifierReceipt],
) -> bool {
    if current.is_empty() {
        return !next.is_empty();
    }
    current.len() == next.len()
        && current.iter().zip(next).all(|(prior, successor)| {
            prior.attempt_id == successor.attempt_id
                && prior.source_attempt_revision_id == successor.source_attempt_revision_id
                && prior.strategy_contract_fingerprint == successor.strategy_contract_fingerprint
                && prior.source_repository_instance_id == successor.source_repository_instance_id
                && prior.source_worktree_instance_id == successor.source_worktree_instance_id
                && prior.source_snapshot_id == successor.source_snapshot_id
                && prior.target_repository_instance_id == successor.target_repository_instance_id
                && prior.target_worktree_instance_id == successor.target_worktree_instance_id
                && prior.post_application_snapshot_id == successor.post_application_snapshot_id
                && prior.affected_relative_path == successor.affected_relative_path
                && prior.competing_groups == successor.competing_groups
                && prior.operation_id == successor.operation_id
                && prior.operation_revision == successor.operation_revision
                && prior.execution_lane_id == successor.execution_lane_id
                && prior.capture_receipt_revision_id == successor.capture_receipt_revision_id
                && prior.scope_effect_ids == successor.scope_effect_ids
                && prior.result_source_observation_id == successor.result_source_observation_id
                && prior.recovery_verification_revision == successor.recovery_verification_revision
        })
        && current.iter().zip(next).any(|(prior, successor)| {
            prior.revalidated_attempt_revision_id != successor.revalidated_attempt_revision_id
                || prior.revalidated_competing_groups != successor.revalidated_competing_groups
        })
}

fn valid_verifier_receipts(values: &[RecoveryVerifierReceipt]) -> bool {
    if values.len() > 16 {
        return false;
    }
    values.iter().enumerate().all(|(index, value)| {
        value.verification_revision == u32::try_from(index + 1).unwrap_or(u32::MAX)
            && value.verifier_version == 1
            && index
                .checked_sub(1)
                .is_none_or(|prior| verifier_outcome_progress(values[prior].outcome, value.outcome))
    })
}

fn verifier_outcome_progress(
    current: RecoveryVerificationOutcome,
    next: RecoveryVerificationOutcome,
) -> bool {
    match current {
        RecoveryVerificationOutcome::PartiallyApplied => true,
        RecoveryVerificationOutcome::Applied => next == RecoveryVerificationOutcome::Applied,
        RecoveryVerificationOutcome::NotApplied => next == RecoveryVerificationOutcome::NotApplied,
    }
}

fn verifier_history_progress(
    current: &[RecoveryVerifierReceipt],
    next: &[RecoveryVerifierReceipt],
) -> bool {
    next.len() == current.len() + 1 && next.starts_with(current)
}

fn delivery_progress(
    current: RecoveryInputDeliveryState,
    next: RecoveryInputDeliveryState,
) -> bool {
    current == next
        || current == RecoveryInputDeliveryState::Admitted
            && next == RecoveryInputDeliveryState::Delivered
}

fn option_compatible<T: Eq + Copy>(current: Option<T>, next: Option<T>) -> bool {
    current.is_none() || current == next
}

fn option_progress<T: Eq + Copy>(current: Option<T>, next: Option<T>) -> bool {
    current.is_none() && next.is_some()
}

fn strictly_ordered<T: Ord>(values: &[T]) -> bool {
    values.len() <= 256 && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn contains_all<T: Eq>(values: &[T], required: &[T]) -> bool {
    required.iter().all(|value| values.contains(value))
}

fn strict_superset<T: Eq>(current: &[T], next: &[T]) -> bool {
    next.len() > current.len() && contains_all(next, current)
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

fn unique_anchor_claims(values: &[RecoveryAttemptAnchorClaim]) -> bool {
    values.len() <= 256
        && values.iter().all(|value| value.validate().is_ok())
        && values
            .windows(2)
            .all(|pair| pair[0].attempt_id < pair[1].attempt_id)
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
