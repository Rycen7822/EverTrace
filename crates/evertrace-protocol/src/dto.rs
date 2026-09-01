use evertrace_domain::{
    evidence::IdentityStrength,
    ids::{
        AttemptId, CaptureReceiptId, ExecutionLaneId, JobId, ProcedureNegativeEvidenceId,
        RecoveryApplicationId, RecoveryBundleId, RecoveryCaptureRequestId, RepositoryId,
        RevisionProposalId, WorktreeId, WorktreeSnapshotId,
    },
    procedure::ProcedureNegativeReviewStatus,
    purge::{ObjectDeletionTarget, ObjectReauthorizationRef},
    repository::{
        DestructiveClass, GitRegistrationState, OrderingIntegrity, RecoveryApplicationKind,
        RecoveryApplicationStatus, RecoveryCaptureStatus, RecoveryInputDeliveryState,
        RecoveryOmissionReason, RecoveryReasonCode, RecoveryRequestStatus, UntrackedCaptureScope,
        WorktreeKind, WorktreeLifecycle,
    },
    revision::RevisionId,
    semantic::{
        AtomProposalPayload, CoreMembershipProposalPayload, GlobalSupportState,
        ProcedureProposalPayload, ProposalEligibility, ProposalOperation, ProposalPayload,
        ProposalStatus, ProposalTargetId, ProposalTargetKind, RevisionProposal,
        SupportThresholdSnapshot,
    },
    work::{
        AdmissionFailureObservability, CoverageLevel, LaneStatus, LivenessState,
        OrderingIntegrity as WorkOrderingIntegrity, PairingIntegrity, PayloadIntegrity,
        ReasoningVisibility, SourceCoverage, TerminalKind,
    },
};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_SIZE: usize = 1_048_576;

pub fn proposal_payload_pretty_document(
    payload: &ProposalPayload,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(payload)
}

pub fn parse_proposal_payload_document(
    document: &str,
) -> Result<ProposalPayload, serde_json::Error> {
    serde_json::from_str(document)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    Cli,
    Hook,
    Mcp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionContext {
    pub connection_id: String,
    pub client_kind: ClientKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthMode {
    Normal,
    Maintenance,
}

pub const HUMAN_PAGE_LIMIT: u16 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanSurface {
    Inbox,
    Explorer,
    System,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanRelationKind {
    ProposalEvidence,
    SupportDependencies,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanReadRequest {
    List {
        surface: HumanSurface,
        expected_frontier: Option<u64>,
        after: Option<String>,
        limit: u16,
    },
    Detail {
        surface: HumanSurface,
        object_ref: String,
        expected_frontier: u64,
        expected_revision_ref: Option<String>,
    },
    Related {
        relation: HumanRelationKind,
        source_stable_key: String,
        expected_source_revision_ref: String,
        expected_frontier: u64,
        after: Option<String>,
        limit: u16,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalHumanDecision {
    Accept,
    EditAndAccept,
    Reauthorize,
    MergeAndAccept,
    Defer,
    Reject,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NegativeReviewDecision {
    ResolveAsIneffective,
    DismissAttribution,
    ConfirmHarm,
    RequestRevision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanUnavailableAction {
    SupportGovernance,
    SegmentationCorrection,
    LaneCorrection,
    ResumeCorrection,
    LineageCorrection,
    ForgetOrPurge,
    ConfigurationWrite,
    BackupRestoreOrGc,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanActionRequest {
    Proposal {
        proposal_id: RevisionProposalId,
        expected_revision_id: RevisionId,
        expected_fingerprint: String,
        decision: ProposalHumanDecision,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        edited_payload: Option<Box<ProposalPayload>>,
    },
    NegativeReview {
        negative_evidence_id: ProcedureNegativeEvidenceId,
        expected_review_revision_id: RevisionId,
        decision: NegativeReviewDecision,
    },
    SupportReplacement {
        expected_validation_revision_id: RevisionId,
        edited_payload: Box<ProposalPayload>,
    },
    SupportDeprecate {
        expected_validation_revision_id: RevisionId,
        reason: String,
    },
    ResolveCompetingSelected {
        expected_group_revision_id: RevisionId,
        chosen_attempt_id: AttemptId,
    },
    MarkNewAttempt {
        expected_attempt_revision_id: RevisionId,
    },
    ForgetObject {
        target: ObjectDeletionTarget,
        expected_revision_ids: Vec<RevisionId>,
        expected_deletion_generation: u64,
    },
    Unavailable {
        action: HumanUnavailableAction,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanGovernanceRequest {
    Read {
        request: HumanReadRequest,
    },
    Act {
        expected_frontier: u64,
        action: HumanActionRequest,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanSnapshotStatus {
    Ready,
    Degraded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanDegradedReason {
    CurrentJobFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanItemKind {
    Generic,
    RevisionProposal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanRowClass {
    Object,
    Runtime,
    Projection,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanObjectFamily {
    Evidence,
    Work,
    Atom,
    Procedure,
    RevisionProposal,
    Runtime,
    Projection,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanItemCategory {
    Proposal,
    Support,
    NegativeReview,
    SegmentationCorrection,
    RecoveryCorrection,
    Assignment,
    CompetingResolution,
    AttemptResume,
    LaneLifecycle,
    CaptureIntegrity,
    WorktreeLineage,
    ReviewHold,
    Repository,
    Work,
    Semantic,
    Procedure,
    Research,
    RecoveryEvidence,
    Evidence,
    Runtime,
    Projection,
    SessionImport,
    SemanticDerivation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanProposalMetadata {
    pub proposal_id: RevisionProposalId,
    pub current_revision_id: RevisionId,
    pub fingerprint: String,
    pub target_kind: ProposalTargetKind,
    pub target_id: Option<ProposalTargetId>,
    pub operation: ProposalOperation,
    pub base_revision_id: Option<RevisionId>,
    pub source_cohort_refs: Vec<String>,
    pub eligibility: ProposalEligibility,
    pub status: ProposalStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanProposalReview {
    pub proposal: Box<RevisionProposal>,
    pub plain_accept_eligible: bool,
    pub merge_and_accept_eligible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reauthorization: Option<ObjectReauthorizationRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSupportDetail {
    pub support_contract_revision_id: RevisionId,
    pub successor_ref: String,
    pub validation_revision_id: RevisionId,
    pub state: GlobalSupportState,
    pub dependency_generation: u64,
    pub provenance_degraded: bool,
    pub threshold: SupportThresholdSnapshot,
    pub support_revision_refs: Vec<RevisionId>,
    pub authorization_revision_refs: Vec<RevisionId>,
    pub surviving_support_refs: Vec<RevisionId>,
    pub invalid_or_missing_refs: Vec<RevisionId>,
    pub trigger_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_replacement_payload: Option<Box<ProposalPayload>>,
    pub deprecate_available: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanCompetingDetail {
    pub expected_group_revision_id: RevisionId,
    pub eligible_attempt_ids: Vec<AttemptId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanForgetPreview {
    pub target: ObjectDeletionTarget,
    pub current_revision_id: RevisionId,
    pub exact_revision_ids: Vec<RevisionId>,
    pub deletion_generation: u64,
    pub shared_source_count: u32,
    pub suppressed_source_count: u32,
    pub suppression_ref_count: u32,
    pub downstream_support_revalidation_count: u32,
    pub dependent_procedure_review_hold_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSnapshotItem {
    pub item_kind: HumanItemKind,
    pub proposal: Option<HumanProposalMetadata>,
    pub proposal_review: Option<HumanProposalReview>,
    pub support_detail: Option<HumanSupportDetail>,
    pub competing_detail: Option<HumanCompetingDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forget_preview: Option<Box<HumanForgetPreview>>,
    pub negative_review: Option<HumanNegativeReviewMetadata>,
    pub recovery_detail: Option<HumanRecoveryDetail>,
    pub worktree_detail: Option<HumanWorktreeDetail>,
    pub execution_integrity_detail: Option<HumanExecutionIntegrityDetail>,
    pub system_detail: Option<HumanSystemDetail>,
    pub stable_key: String,
    pub row_class: HumanRowClass,
    pub family: HumanObjectFamily,
    pub category: HumanItemCategory,
    pub object_kind: String,
    pub object_ref: Option<String>,
    pub revision_ref: Option<String>,
    pub lifecycle: Option<String>,
    pub epistemic: Option<String>,
    pub authority: Option<String>,
    pub publication_state: Option<String>,
    pub support_state: Option<String>,
    pub scope_ref: Option<String>,
    pub source_event_seq: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanExecutionIntegrityDetail {
    Lane {
        execution_lane_id: ExecutionLaneId,
        lane_revision: u32,
        parent_lane_id: Option<ExecutionLaneId>,
        status: LaneStatus,
        terminal_kind: Option<TerminalKind>,
        liveness_state: LivenessState,
        finalized: bool,
        event_watermark: u64,
        active_capture_receipt_revision_id: CaptureReceiptId,
        coverage_level: CoverageLevel,
        source_coverage: SourceCoverage,
        pairing_integrity: PairingIntegrity,
        payload_integrity: PayloadIntegrity,
        ordering_integrity: WorkOrderingIntegrity,
        reasoning_visibility: Vec<ReasoningVisibility>,
    },
    Receipt {
        capture_receipt_revision_id: CaptureReceiptId,
        execution_lane_id: ExecutionLaneId,
        predecessor_revision_id: Option<CaptureReceiptId>,
        admission_failure_observability: AdmissionFailureObservability,
        identity_strength: IdentityStrength,
        delegation_start_seen: bool,
        child_session_linked: bool,
        parent_session_end_seen: bool,
        lifecycle_end_seen: bool,
        terminal_event_kind: Option<TerminalKind>,
        finalized: bool,
        first_sequence: Option<u64>,
        last_sequence: Option<u64>,
        sequence_gap_count: u32,
        outage_count: u32,
        tool_call_count: u32,
        tool_result_count: u32,
        unmatched_tool_call_count: u32,
        unmatched_tool_result_count: u32,
        truncation_count: u32,
        redaction_count: u32,
        corrupt_count: u32,
        unsupported_count: u32,
        import_watermark: u64,
        coverage_level: CoverageLevel,
        source_coverage: SourceCoverage,
        pairing_integrity: PairingIntegrity,
        payload_integrity: PayloadIntegrity,
        ordering_integrity: WorkOrderingIntegrity,
        reasoning_visibility: Vec<ReasoningVisibility>,
        exact_byte_replay: bool,
        resolver_version: u32,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanJobState {
    Queued,
    Leased,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanJobTerminalReason {
    Completed,
    StaleGeneration,
    BudgetExhausted,
    SourceUnavailable,
    Unsupported,
    SourceReplaced,
    Revoked,
    IntegrityFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanJobBudget {
    pub max_items: u32,
    pub max_bytes: Option<u64>,
    pub max_input_tokens: Option<u64>,
    pub max_output_tokens: Option<u64>,
    pub max_calls: Option<u32>,
    pub max_wall_time_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanJobDetail {
    pub job_id: JobId,
    pub target_revision: String,
    pub target_watermark: u64,
    pub target_generation: u64,
    pub job_kind: String,
    pub algorithm_revision: String,
    pub model_id: Option<String>,
    pub priority: i16,
    pub state: HumanJobState,
    pub attempt: u32,
    pub backoff_until_us: Option<i64>,
    pub lease_until_us: Option<i64>,
    pub config_hash: [u8; 32],
    pub budget: HumanJobBudget,
    pub terminal_reason: Option<HumanJobTerminalReason>,
    pub terminal_result_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanSystemDetail {
    Job {
        detail: Box<HumanJobDetail>,
    },
    Config {
        config_version: u32,
        effective_config_hash: [u8; 32],
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanRecoveryDetail {
    CaptureRequest {
        request_id: RecoveryCaptureRequestId,
        revision_id: RevisionId,
        repository_id: RepositoryId,
        worktree_id: WorktreeId,
        destructive_class: DestructiveClass,
        untracked_scope: UntrackedCaptureScope,
        status: RecoveryRequestStatus,
        bundle_id: Option<RecoveryBundleId>,
        reason_codes: Vec<RecoveryReasonCode>,
    },
    Bundle {
        bundle_id: RecoveryBundleId,
        source_worktree_id: WorktreeId,
        source_snapshot_id: WorktreeSnapshotId,
        capture_status: RecoveryCaptureStatus,
        ordering_integrity: OrderingIntegrity,
        captured_bytes: u64,
        tracked_diff_count: u32,
        tracked_file_count: u32,
        index_state_count: u32,
        untracked_file_count: u32,
        untracked_artifact_count: u32,
        metadata_artifact_count: u32,
        config_run_count: u32,
        attempt_anchor_count: u32,
        omission_counts: Vec<HumanRecoveryOmissionCount>,
    },
    Application {
        application_id: RecoveryApplicationId,
        revision_id: RevisionId,
        bundle_id: RecoveryBundleId,
        target_worktree_id: WorktreeId,
        application_kind: RecoveryApplicationKind,
        input_delivery_state: RecoveryInputDeliveryState,
        status: RecoveryApplicationStatus,
        pre_snapshot_id: WorktreeSnapshotId,
        post_snapshot_id: Option<WorktreeSnapshotId>,
        selected_input_count: u32,
        result_count: u32,
        verifier_count: u32,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRecoveryOmissionCount {
    pub reason: RecoveryOmissionReason,
    pub count: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanWorktreeDetail {
    pub worktree_id: WorktreeId,
    pub repository_id: RepositoryId,
    pub kind: WorktreeKind,
    pub lifecycle: WorktreeLifecycle,
    pub registration_state: GitRegistrationState,
    pub current_snapshot_id: Option<WorktreeSnapshotId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanNegativeReviewMetadata {
    pub negative_evidence_id: ProcedureNegativeEvidenceId,
    pub current_review_revision_id: RevisionId,
    pub status: ProcedureNegativeReviewStatus,
    pub available_decisions: Vec<NegativeReviewDecision>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanActionStatus {
    Applied,
    NoDelta,
    Conflict,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanActionResult {
    pub status: HumanActionStatus,
    pub current_revision_ref: Option<String>,
    pub audit_event_ref: Option<String>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanGovernanceResponse {
    Snapshot {
        frontier: u64,
        status: HumanSnapshotStatus,
        degraded_reasons: Vec<HumanDegradedReason>,
        items: Vec<HumanSnapshotItem>,
        next_cursor: Option<String>,
    },
    Action {
        result: HumanActionResult,
    },
    Conflict {
        current_frontier: u64,
        current_revision_ref: Option<String>,
    },
}

impl HumanGovernanceRequest {
    pub fn validate(&self) -> bool {
        match self {
            Self::Read { request } => request.validate(),
            Self::Act { action, .. } => action.validate(),
        }
    }
}

impl HumanReadRequest {
    fn validate(&self) -> bool {
        match self {
            Self::List { after, limit, .. } => {
                (1..=HUMAN_PAGE_LIMIT).contains(limit) && after.as_deref().is_none_or(valid_ref)
            }
            Self::Detail {
                object_ref,
                expected_revision_ref,
                ..
            } => valid_ref(object_ref) && expected_revision_ref.as_deref().is_none_or(valid_ref),
            Self::Related {
                source_stable_key,
                expected_source_revision_ref,
                after,
                limit,
                ..
            } => {
                valid_ref(source_stable_key)
                    && valid_ref(expected_source_revision_ref)
                    && (1..=HUMAN_PAGE_LIMIT).contains(limit)
                    && after.as_deref().is_none_or(valid_ref)
            }
        }
    }
}

impl HumanActionRequest {
    fn validate(&self) -> bool {
        match self {
            Self::Proposal {
                expected_fingerprint,
                decision,
                edited_payload,
                ..
            } => {
                valid_hex(expected_fingerprint)
                    && match decision {
                        ProposalHumanDecision::EditAndAccept => edited_payload.is_some(),
                        ProposalHumanDecision::Reauthorize => edited_payload.is_none(),
                        ProposalHumanDecision::Accept
                        | ProposalHumanDecision::MergeAndAccept
                        | ProposalHumanDecision::Defer
                        | ProposalHumanDecision::Reject => edited_payload.is_none(),
                    }
            }
            Self::NegativeReview { .. } => true,
            Self::SupportReplacement { edited_payload, .. } => {
                matches!(
                    edited_payload.as_ref(),
                    ProposalPayload::Atom(payload)
                        if matches!(payload.as_ref(), AtomProposalPayload::Replace { .. })
                ) || matches!(
                    edited_payload.as_ref(),
                    ProposalPayload::Procedure(payload)
                        if matches!(payload.as_ref(), ProcedureProposalPayload::Replace { .. })
                )
            }
            Self::SupportDeprecate { reason, .. } => AtomProposalPayload::Deprecate {
                reason: reason.clone(),
            }
            .validate()
            .is_ok(),
            Self::ResolveCompetingSelected { .. } | Self::MarkNewAttempt { .. } => true,
            Self::ForgetObject {
                expected_revision_ids,
                expected_deletion_generation,
                ..
            } => {
                *expected_deletion_generation > 0
                    && !expected_revision_ids.is_empty()
                    && expected_revision_ids.len() <= 256
                    && expected_revision_ids
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
            }
            Self::Unavailable { .. } => true,
        }
    }
}

impl HumanGovernanceResponse {
    pub fn validate(&self) -> bool {
        match self {
            Self::Snapshot {
                status,
                degraded_reasons,
                items,
                next_cursor,
                ..
            } => {
                ((matches!(status, HumanSnapshotStatus::Ready) && degraded_reasons.is_empty())
                    || (matches!(status, HumanSnapshotStatus::Degraded)
                        && !degraded_reasons.is_empty()))
                    && degraded_reasons.windows(2).all(|pair| pair[0] < pair[1])
                    && items.len() <= usize::from(HUMAN_PAGE_LIMIT)
                    && items
                        .windows(2)
                        .all(|pair| pair[0].stable_key < pair[1].stable_key)
                    && items.iter().all(HumanSnapshotItem::validate)
                    && next_cursor.as_deref().is_none_or(valid_ref)
            }
            Self::Action { result } => result.validate(),
            Self::Conflict {
                current_revision_ref,
                ..
            } => current_revision_ref.as_deref().is_none_or(valid_ref),
        }
    }
}

impl HumanSnapshotItem {
    fn validate(&self) -> bool {
        ((self.item_kind == HumanItemKind::RevisionProposal) == self.proposal.is_some())
            && ((self.category == HumanItemCategory::NegativeReview)
                == self.negative_review.is_some())
            && self.proposal.as_ref().is_none_or(|proposal| {
                valid_hex(&proposal.fingerprint)
                    && self.object_ref.as_deref() == Some(proposal.proposal_id.to_string().as_str())
                    && self.revision_ref.as_deref()
                        == Some(proposal.current_revision_id.to_string().as_str())
                    && !proposal.source_cohort_refs.is_empty()
                    && proposal.source_cohort_refs.len() <= 256
                    && proposal
                        .source_cohort_refs
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
                    && proposal
                        .source_cohort_refs
                        .iter()
                        .all(|value| valid_ref(value))
            })
            && self.proposal_review.as_ref().is_none_or(|review| {
                let Some(summary) = self.proposal.as_ref() else {
                    return false;
                };
                review.proposal.validate().is_ok()
                    && review.proposal.proposal_id == summary.proposal_id
                    && review.proposal.proposal_revision_id == summary.current_revision_id
                    && evertrace_domain::evidence::hex(&review.proposal.fingerprint)
                        == summary.fingerprint
                    && review.proposal.target_kind == summary.target_kind
                    && review.proposal.target_id == summary.target_id
                    && review.proposal.operation == summary.operation
                    && review.proposal.base_revision_id == summary.base_revision_id
                    && review.proposal.source_cohort_refs == summary.source_cohort_refs
                    && review.proposal.eligibility == summary.eligibility
                    && review.proposal.status == summary.status
                    && review.plain_accept_eligible
                        == plain_accept_eligible(review.proposal.as_ref())
                    && (!review.merge_and_accept_eligible
                        || (review.proposal.target_kind == ProposalTargetKind::Atom
                            && review.proposal.operation == ProposalOperation::Merge
                            && review.proposal.status.is_open()
                            && review.proposal.eligibility
                                != ProposalEligibility::AutoEligibleFull))
                    && (review.reauthorization.as_ref().is_none_or(|reference| {
                        reference.deletion_generation > 0
                            && valid_ref(&reference.purge_job_audit_ref)
                            && !review.plain_accept_eligible
                            && review.proposal.operation == ProposalOperation::Create
                            && review.proposal.status.is_open()
                            && review.proposal.eligibility == ProposalEligibility::ManualRequired
                    }))
            })
            && self
                .support_detail
                .as_ref()
                .is_none_or(|detail| detail.validate(self))
            && self.competing_detail.as_ref().is_none_or(|detail| {
                self.category == HumanItemCategory::CompetingResolution
                    && self.object_kind == "competing_attempt_group"
                    && self.revision_ref.as_deref()
                        == Some(detail.expected_group_revision_id.to_string().as_str())
                    && !detail.eligible_attempt_ids.is_empty()
                    && detail.eligible_attempt_ids.len() <= 64
                    && detail
                        .eligible_attempt_ids
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
            })
            && self.forget_preview.as_ref().is_none_or(|preview| {
                preview.deletion_generation > 0
                    && !preview.exact_revision_ids.is_empty()
                    && preview.exact_revision_ids.len() <= 256
                    && preview
                        .exact_revision_ids
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
                    && preview
                        .exact_revision_ids
                        .binary_search(&preview.current_revision_id)
                        .is_ok()
                    && self.revision_ref.as_deref()
                        == Some(preview.current_revision_id.to_string().as_str())
                    && self.object_ref.as_deref() == Some(preview.target.object_ref().as_str())
            })
            && self.negative_review.as_ref().is_none_or(|review| {
                self.revision_ref.as_deref()
                    == Some(review.current_review_revision_id.to_string().as_str())
                    && (!matches!(
                        review.status,
                        ProcedureNegativeReviewStatus::Upheld
                            | ProcedureNegativeReviewStatus::Dismissed
                            | ProcedureNegativeReviewStatus::Superseded
                    ) || review.available_decisions.is_empty())
                    && review.available_decisions.len() <= 4
                    && review
                        .available_decisions
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
            })
            && self.recovery_detail.as_ref().is_none_or(|detail| {
                self.category == HumanItemCategory::RecoveryEvidence
                    && detail.validate(
                        self.object_kind.as_str(),
                        self.object_ref.as_deref(),
                        self.revision_ref.as_deref(),
                    )
            })
            && self.worktree_detail.as_ref().is_none_or(|detail| {
                self.category == HumanItemCategory::Repository
                    && self.object_kind == "worktree"
                    && self.object_ref.as_deref() == Some(detail.worktree_id.to_string().as_str())
            })
            && self
                .execution_integrity_detail
                .as_ref()
                .is_none_or(|detail| {
                    detail.validate(
                        self.row_class,
                        self.family,
                        self.category,
                        self.object_kind.as_str(),
                        self.object_ref.as_deref(),
                        self.revision_ref.as_deref(),
                    )
                })
            && self
                .system_detail
                .as_ref()
                .is_none_or(|detail| detail.validate(self))
            && (self.object_kind == "worktree" || self.worktree_detail.is_none())
            && valid_ref(&self.stable_key)
            && valid_short(&self.object_kind)
            && self.source_event_seq > 0
            && family_matches_class(self.row_class, self.family)
            && category_matches(self)
            && [
                self.object_ref.as_deref(),
                self.revision_ref.as_deref(),
                self.lifecycle.as_deref(),
                self.epistemic.as_deref(),
                self.authority.as_deref(),
                self.publication_state.as_deref(),
                self.support_state.as_deref(),
                self.scope_ref.as_deref(),
            ]
            .into_iter()
            .flatten()
            .all(valid_ref)
    }
}

fn plain_accept_eligible(proposal: &RevisionProposal) -> bool {
    proposal.status.is_open()
        && proposal.eligibility != ProposalEligibility::AutoEligibleFull
        && match &proposal.payload {
            ProposalPayload::Atom(payload) => matches!(
                payload.as_ref(),
                AtomProposalPayload::Create { .. }
                    | AtomProposalPayload::Replace { .. }
                    | AtomProposalPayload::Deprecate { .. }
                    | AtomProposalPayload::Reclassify { .. }
            ),
            ProposalPayload::Procedure(payload) => matches!(
                payload.as_ref(),
                ProcedureProposalPayload::Create { .. } | ProcedureProposalPayload::Replace { .. }
            ),
            ProposalPayload::CoreMembership(payload) => matches!(
                payload.as_ref(),
                CoreMembershipProposalPayload::Create { .. }
            ),
            ProposalPayload::ReservedTarget { .. } => false,
        }
}

impl HumanSupportDetail {
    fn validate(&self, item: &HumanSnapshotItem) -> bool {
        let sorted_unique = |values: &[RevisionId]| values.windows(2).all(|pair| pair[0] < pair[1]);
        let mut classified = self.surviving_support_refs.clone();
        classified.extend(&self.invalid_or_missing_refs);
        classified.sort();
        let support_sufficient = self.surviving_support_refs.len()
            >= usize::from(self.threshold.minimum_surviving_support);
        let state_consistent = match self.state {
            GlobalSupportState::Valid => {
                support_sufficient
                    && self.provenance_degraded == !self.invalid_or_missing_refs.is_empty()
            }
            GlobalSupportState::Insufficient => !support_sufficient,
            GlobalSupportState::Invalidated => self.threshold.require_authorization,
            GlobalSupportState::RevalidationPending => true,
        };
        item.row_class == HumanRowClass::Object
            && item.family == HumanObjectFamily::Atom
            && matches!(
                item.category,
                HumanItemCategory::Support | HumanItemCategory::Semantic
            )
            && item.object_kind == "global_support_validation"
            && item.lifecycle.as_deref()
                == Some(match self.state {
                    GlobalSupportState::Valid => "valid",
                    GlobalSupportState::RevalidationPending => "revalidation_pending",
                    GlobalSupportState::Insufficient => "insufficient",
                    GlobalSupportState::Invalidated => "invalidated",
                })
            && item.object_ref.as_deref()
                == Some(self.support_contract_revision_id.to_string().as_str())
            && item.revision_ref.as_deref()
                == Some(self.validation_revision_id.to_string().as_str())
            && valid_ref(&self.successor_ref)
            && self.dependency_generation > 0
            && self.threshold.validate().is_ok()
            && !self.support_revision_refs.is_empty()
            && self.support_revision_refs.len() <= 256
            && self.authorization_revision_refs.len() <= 256
            && self.surviving_support_refs.len() <= 256
            && self.invalid_or_missing_refs.len() <= 256
            && self.trigger_refs.len() <= 256
            && sorted_unique(&self.support_revision_refs)
            && sorted_unique(&self.authorization_revision_refs)
            && sorted_unique(&self.surviving_support_refs)
            && sorted_unique(&self.invalid_or_missing_refs)
            && self.trigger_refs.windows(2).all(|pair| pair[0] < pair[1])
            && self.trigger_refs.iter().all(|value| valid_ref(value))
            && usize::from(self.threshold.minimum_surviving_support)
                <= self.support_revision_refs.len()
            && (!self.threshold.require_authorization
                || !self.authorization_revision_refs.is_empty())
            && state_consistent
            && self.surviving_support_refs.iter().all(|reference| {
                self.support_revision_refs.contains(reference)
                    && !self.invalid_or_missing_refs.contains(reference)
            })
            && self
                .invalid_or_missing_refs
                .iter()
                .all(|reference| self.support_revision_refs.contains(reference))
            && (self.state == GlobalSupportState::RevalidationPending
                || classified == self.support_revision_refs)
            && self.initial_replacement_payload.as_ref().is_none_or(|payload| {
                self.state != GlobalSupportState::Valid
                    && (matches!(
                        payload.as_ref(),
                        ProposalPayload::Atom(value)
                            if matches!(value.as_ref(), AtomProposalPayload::Replace { .. })
                    ) || matches!(
                        payload.as_ref(),
                        ProposalPayload::Procedure(value)
                            if matches!(value.as_ref(), ProcedureProposalPayload::Replace { .. })
                    ))
            })
            && (!self.deprecate_available
                || self.state != GlobalSupportState::Valid
                    && matches!(
                        self.initial_replacement_payload.as_deref(),
                        Some(ProposalPayload::Atom(payload))
                            if matches!(payload.as_ref(), AtomProposalPayload::Replace { .. })
                    ))
    }
}

impl HumanExecutionIntegrityDetail {
    fn validate(
        &self,
        row_class: HumanRowClass,
        family: HumanObjectFamily,
        category: HumanItemCategory,
        object_kind: &str,
        object_ref: Option<&str>,
        revision_ref: Option<&str>,
    ) -> bool {
        let visibility_valid = |values: &[ReasoningVisibility]| {
            values.len() <= 3 && values.windows(2).all(|pair| pair[0] < pair[1])
        };
        match self {
            Self::Lane {
                execution_lane_id,
                lane_revision,
                reasoning_visibility,
                ..
            } => {
                row_class == HumanRowClass::Object
                    && family == HumanObjectFamily::Work
                    && matches!(
                        category,
                        HumanItemCategory::LaneLifecycle | HumanItemCategory::Work
                    )
                    && object_kind == "execution_lane"
                    && *lane_revision > 0
                    && object_ref == Some(execution_lane_id.to_string().as_str())
                    && revision_ref == Some(format!("{execution_lane_id}@{lane_revision}").as_str())
                    && visibility_valid(reasoning_visibility)
            }
            Self::Receipt {
                capture_receipt_revision_id,
                execution_lane_id,
                first_sequence,
                last_sequence,
                reasoning_visibility,
                resolver_version,
                ..
            } => {
                row_class == HumanRowClass::Object
                    && family == HumanObjectFamily::Evidence
                    && matches!(
                        category,
                        HumanItemCategory::CaptureIntegrity | HumanItemCategory::Evidence
                    )
                    && object_kind == "capture_receipt"
                    && object_ref == Some(execution_lane_id.to_string().as_str())
                    && revision_ref == Some(capture_receipt_revision_id.to_string().as_str())
                    && first_sequence.is_some() == last_sequence.is_some()
                    && first_sequence
                        .zip(*last_sequence)
                        .is_none_or(|(first, last)| first <= last)
                    && *resolver_version > 0
                    && visibility_valid(reasoning_visibility)
            }
        }
    }
}

impl HumanSystemDetail {
    fn validate(&self, item: &HumanSnapshotItem) -> bool {
        if item.row_class != HumanRowClass::Runtime
            || item.family != HumanObjectFamily::Runtime
            || item.category != HumanItemCategory::Runtime
            || item.object_kind != "runtime_event"
            || item.object_ref.is_some()
            || item.revision_ref.is_some()
        {
            return false;
        }
        match self {
            Self::Job { detail } => {
                let HumanJobDetail {
                    job_id,
                    target_revision,
                    target_generation,
                    job_kind,
                    algorithm_revision,
                    model_id,
                    state,
                    attempt,
                    backoff_until_us,
                    lease_until_us,
                    budget,
                    terminal_reason,
                    terminal_result_ref,
                    ..
                } = detail.as_ref();
                let terminal = terminal_reason.is_some();
                item.stable_key == format!("runtime:job:{job_id}")
                    && [
                        target_revision.as_str(),
                        job_kind.as_str(),
                        algorithm_revision.as_str(),
                    ]
                    .into_iter()
                    .all(valid_ref)
                    && model_id.as_deref().is_none_or(valid_ref)
                    && terminal_result_ref.as_deref().is_none_or(valid_ref)
                    && *target_generation > 0
                    && *attempt > 0
                    && backoff_until_us.is_none_or(|value| value >= 0)
                    && lease_until_us.is_none_or(|value| value > 0)
                    && (*state == HumanJobState::Leased) == lease_until_us.is_some()
                    && matches!(state, HumanJobState::Queued | HumanJobState::Leased) != terminal
                    && (*state == HumanJobState::Succeeded)
                        == (*terminal_reason == Some(HumanJobTerminalReason::Completed))
                    && (*state == HumanJobState::Failed)
                        == terminal_reason
                            .is_some_and(|reason| reason != HumanJobTerminalReason::Completed)
                    && (terminal_result_ref.is_none() || terminal)
                    && budget.validate()
            }
            Self::Config { config_version, .. } => {
                item.stable_key == "runtime:config:current" && *config_version > 0
            }
        }
    }
}

impl HumanJobBudget {
    fn validate(&self) -> bool {
        self.max_items > 0
            && self.max_wall_time_ms > 0
            && self.max_bytes != Some(0)
            && self.max_input_tokens != Some(0)
            && self.max_output_tokens != Some(0)
            && self.max_calls != Some(0)
    }
}

impl HumanRecoveryDetail {
    fn validate(
        &self,
        object_kind: &str,
        object_ref: Option<&str>,
        revision_ref: Option<&str>,
    ) -> bool {
        match self {
            Self::CaptureRequest {
                request_id,
                revision_id,
                reason_codes,
                ..
            } => {
                object_kind == "recovery_capture_request_revision"
                    && object_ref == Some(request_id.to_string().as_str())
                    && revision_ref == Some(revision_id.to_string().as_str())
                    && reason_codes.len() <= 8
                    && reason_codes.windows(2).all(|pair| pair[0] < pair[1])
            }
            Self::Bundle {
                bundle_id,
                omission_counts,
                ..
            } => {
                object_kind == "recovery_bundle"
                    && object_ref == Some(bundle_id.to_string().as_str())
                    && omission_counts.len() <= 14
                    && omission_counts.iter().all(|entry| entry.count > 0)
                    && omission_counts.iter().enumerate().all(|(index, entry)| {
                        omission_counts[..index]
                            .iter()
                            .all(|prior| prior.reason != entry.reason)
                    })
            }
            Self::Application {
                application_id,
                revision_id,
                ..
            } => {
                object_kind == "recovery_application_revision"
                    && object_ref == Some(application_id.to_string().as_str())
                    && revision_ref == Some(revision_id.to_string().as_str())
            }
        }
    }
}

fn family_matches_class(row_class: HumanRowClass, family: HumanObjectFamily) -> bool {
    match row_class {
        HumanRowClass::Object => !matches!(
            family,
            HumanObjectFamily::Runtime | HumanObjectFamily::Projection
        ),
        HumanRowClass::Runtime => family == HumanObjectFamily::Runtime,
        HumanRowClass::Projection => family == HumanObjectFamily::Projection,
    }
}

fn category_matches(item: &HumanSnapshotItem) -> bool {
    use HumanItemCategory as Category;
    match item.category {
        Category::Proposal => {
            item.item_kind == HumanItemKind::RevisionProposal
                && item.object_kind == "revision_proposal_revision"
        }
        Category::Support => matches!(
            item.object_kind.as_str(),
            "global_support_contract" | "global_support_validation"
        ),
        Category::NegativeReview => matches!(
            item.object_kind.as_str(),
            "procedure_negative_evidence" | "procedure_negative_review"
        ),
        Category::SegmentationCorrection => item.object_kind == "work_episode",
        Category::RecoveryCorrection => item.object_kind == "recovery_capture_request_revision",
        Category::Assignment => item.object_kind == "work_binding",
        Category::CompetingResolution => item.object_kind == "competing_attempt_group",
        Category::AttemptResume => item.object_kind == "attempt",
        Category::LaneLifecycle => item.object_kind == "execution_lane",
        Category::CaptureIntegrity => item.object_kind == "capture_receipt",
        Category::WorktreeLineage => item.object_kind == "worktree_transition",
        Category::ReviewHold => item.publication_state.as_deref() == Some("review_hold"),
        Category::Repository => matches!(
            item.object_kind.as_str(),
            "repository"
                | "worktree"
                | "worktree_snapshot"
                | "worktree_transition"
                | "integration_event"
        ),
        Category::Research => matches!(
            item.object_kind.as_str(),
            "experiment_run" | "result_evidence" | "work_artifact"
        ),
        Category::RecoveryEvidence => matches!(
            item.object_kind.as_str(),
            "recovery_capture_request_revision"
                | "recovery_bundle"
                | "recovery_application_revision"
        ),
        Category::SessionImport => item.object_kind == "session_import_current",
        Category::SemanticDerivation => item.object_kind == "semantic_derivation_run",
        Category::Runtime => item.row_class == HumanRowClass::Runtime,
        Category::Projection => item.row_class == HumanRowClass::Projection,
        Category::Evidence => item.family == HumanObjectFamily::Evidence,
        Category::Work => item.family == HumanObjectFamily::Work,
        Category::Semantic => item.family == HumanObjectFamily::Atom,
        Category::Procedure => item.family == HumanObjectFamily::Procedure,
    }
}

impl HumanActionResult {
    fn validate(&self) -> bool {
        let refs_valid = [
            self.current_revision_ref.as_deref(),
            self.audit_event_ref.as_deref(),
            self.reason.as_deref(),
        ]
        .into_iter()
        .flatten()
        .all(valid_ref);
        refs_valid
            && match self.status {
                HumanActionStatus::Applied => {
                    self.current_revision_ref.is_some()
                        && self.audit_event_ref.is_some()
                        && self.reason.is_none()
                }
                HumanActionStatus::NoDelta => {
                    self.current_revision_ref.is_some()
                        && self.audit_event_ref.is_none()
                        && self.reason.is_none()
                }
                HumanActionStatus::Conflict => {
                    self.audit_event_ref.is_none() && self.reason.is_some()
                }
                HumanActionStatus::Unavailable => {
                    self.audit_event_ref.is_none() && self.reason.is_some()
                }
            }
    }
}

fn valid_short(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn valid_ref(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn valid_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
