use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use evertrace_capture::{
    CaptureOutcome, CaptureRecordInput, CaptureRuntime, CasDigest, CasStore, DurableSpool,
    RuntimeSnapshot,
};
use evertrace_domain::{
    config::GlobalPromotionConfig,
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceArchiveMode,
        SourceRevisionMode, SourceRole, hex, payload_fingerprint,
    },
    ids::{
        AtomId, AttemptId, CaptureReceiptId, CommandId, CoreMembershipId, ExecutionLaneId, JobId,
        ProcedureId, ProcedureNegativeEvidenceId, RecoveryApplicationId, RecoveryBundleId,
        RecoveryCaptureRequestId, RepositoryId, RequestId, RevisionProposalId, WorktreeId,
        WorktreeSnapshotId,
    },
    procedure::{
        ProcedureNegativeReviewEvent, ProcedureNegativeReviewStatus, ProcedurePublicationState,
        ProcedureScope,
    },
    purge::{
        ObjectDeletionLedgerEvent, ObjectDeletionTarget, ObjectReauthorizationIntent,
        ObjectReauthorizationRef, RepositoryPurgeBlocker,
    },
    repository::{
        DestructiveClass, GitRegistrationState, LineageAssessment,
        OrderingIntegrity as RecoveryOrderingIntegrity, RecoveryApplicationKind,
        RecoveryApplicationStatus, RecoveryCaptureStatus, RecoveryInputDeliveryState,
        RecoveryOmissionReason, RecoveryReasonCode, RecoveryRequestStatus, UntrackedCaptureScope,
        WorktreeKind, WorktreeLifecycle,
    },
    revision::RevisionId,
    semantic::{
        AcceptedProposalTarget, AtomProposalPayload, AtomScope, CoreMembershipProposalPayload,
        GlobalSuccessorSupportContract, GlobalSupportState, GlobalSupportValidationEvent,
        ProposalAcceptanceAuthority, ProposalCreatedBy, ProposalEligibility, ProposalOperation,
        ProposalPayload, ProposalStatus, ProposalTargetId, ProposalTargetKind, RevisionProposal,
        SupportThresholdSnapshot, TUI_ACCEPTANCE_EVENT_MANIFEST_REF, tui_acceptance_event_payload,
    },
    work::{
        AdmissionFailureObservability, AssignmentStatus, AttemptExecutionStatus,
        AttemptLifecycleStatus, BoundaryStatus, CompetingResolutionStatus, CoverageLevel,
        LaneStatus, LivenessState, OrderingIntegrity, PairingIntegrity, PayloadIntegrity,
        ReasoningVisibility, SourceCoverage, TerminalKind,
    },
};
use evertrace_store::{
    JobStatus, JobTerminalReason, JournalCommand, JournalPayload, ObjectDeletionCandidateAdmission,
    ObjectDeletionCandidateAdmissionView, ObjectDeletionCurrentView, ObjectFamily, ObjectRow,
    ObjectRowClass, ObjectRowKind, ProjectionSnapshot, RecoveryEvidenceCurrentView,
    RuntimeSchedulerView, SemanticCurrentView, SourceIngestWatermark,
};
use thiserror::Error;

use crate::{
    WriterHandle,
    capture::verify_capture_frame,
    ingest::capture_event_drafts,
    procedure::{
        EditedProcedureAcceptance, ProcedureAcceptanceContext, ProcedureAcceptanceResolution,
        ProcedureNegativeReviewDecision, ProcedureRevisionRequestResolution,
        ProcedureUsageCurrentView, accept_procedure, accept_procedure_edited,
        request_procedure_revision, review_procedure_negative,
    },
    purge::{
        ObjectForgetLookup, RepositoryPurgeLookup, pending_object_forget_command,
        pending_repository_purge_command, select_object_forget, select_repository_purge,
    },
    semantic::{
        AtomAcceptanceContext, CoreMembershipAcceptanceContext, ProposalCommandContext,
        ProposalResolution, RevisionProposalService, SubmitProposalRequest, SupportAtomAcceptance,
        SupportDeprecateLookup, SupportReplacementLookup, accept_core_membership,
        compose_support_deprecate, compose_support_replacement, select_support_atom_acceptance,
        select_support_deprecate, select_support_replacement,
    },
    work::{
        WorkCommandContext,
        attempt::{
            CompetingSelectedLookup, CompetingSelectedResolution, MarkNewAttemptLookup,
            MarkNewAttemptResolution, mark_new_attempt, resolve_competing_selected,
            select_competing_selected, select_mark_new_attempt,
        },
    },
};

const ALGORITHM_REVISION: &str = "s31-human-governance-v1";
const MAX_PAGE: u16 = 64;
const MAX_REF: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProposalEditIntent {
    original_proposal_id: RevisionProposalId,
    original_proposal_revision_id: RevisionId,
    original_fingerprint: [u8; 32],
    new_proposal: RevisionProposal,
}

impl ProposalEditIntent {
    fn new(original: &RevisionProposal, new_proposal: RevisionProposal) -> Self {
        Self {
            original_proposal_id: original.proposal_id,
            original_proposal_revision_id: original.proposal_revision_id,
            original_fingerprint: original.fingerprint,
            new_proposal,
        }
    }

    fn validate(&self, original: &RevisionProposal) -> Result<(), HumanGovernanceError> {
        if self.original_proposal_id != original.proposal_id
            || self.original_proposal_revision_id != original.proposal_revision_id
            || self.original_fingerprint != original.fingerprint
        {
            return Err(HumanGovernanceError::InvalidInput);
        }
        original
            .validate_edit_candidate(&self.new_proposal)
            .map_err(|_| HumanGovernanceError::InvalidInput)
    }

    fn canonical_toml(&self, original: &RevisionProposal) -> Result<String, HumanGovernanceError> {
        self.validate(original)?;
        original
            .edit_intent_toml(&self.new_proposal)
            .map_err(|_| HumanGovernanceError::InvalidInput)
    }

    fn from_toml(value: &str) -> Result<Self, HumanGovernanceError> {
        let (
            original_proposal_id,
            original_proposal_revision_id,
            original_fingerprint,
            new_proposal,
        ) = RevisionProposal::parse_edit_intent_toml(value)
            .map_err(|_| HumanGovernanceError::Store)?;
        Ok(Self {
            original_proposal_id,
            original_proposal_revision_id,
            original_fingerprint,
            new_proposal,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanSurface {
    Inbox,
    Explorer,
    System,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanRelationKind {
    ProposalEvidence,
    SupportDependencies,
}

#[derive(Clone, Copy, Debug)]
pub struct HumanRelatedRequest<'a> {
    pub relation: HumanRelationKind,
    pub source_stable_key: &'a str,
    pub expected_source_revision_ref: &'a str,
    pub expected_frontier: u64,
    pub after: Option<&'a str>,
    pub limit: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanRowClass {
    Object,
    Runtime,
    Projection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanObjectFamily {
    Evidence,
    Work,
    Atom,
    Procedure,
    RevisionProposal,
    Runtime,
    Projection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanSummary {
    pub proposal: Option<HumanProposalSummary>,
    pub proposal_review: Option<HumanProposalReview>,
    pub support_detail: Option<HumanSupportDetail>,
    pub competing_detail: Option<HumanCompetingDetail>,
    pub forget_preview: Option<Box<HumanForgetPreview>>,
    pub repository_purge_preview: Option<Box<HumanRepositoryPurgePreview>>,
    pub negative_review: Option<HumanNegativeReviewSummary>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
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
        ordering_integrity: OrderingIntegrity,
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
        ordering_integrity: OrderingIntegrity,
        reasoning_visibility: Vec<ReasoningVisibility>,
        exact_byte_replay: bool,
        resolver_version: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanJobState {
    Queued,
    Leased,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanJobBudget {
    pub max_items: u32,
    pub max_bytes: Option<u64>,
    pub max_input_tokens: Option<u64>,
    pub max_output_tokens: Option<u64>,
    pub max_calls: Option<u32>,
    pub max_wall_time_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HumanSystemDetail {
    Job {
        detail: Box<HumanJobDetail>,
    },
    Config {
        config_version: u32,
        effective_config_hash: [u8; 32],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
        ordering_integrity: RecoveryOrderingIntegrity,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanRecoveryOmissionCount {
    pub reason: RecoveryOmissionReason,
    pub count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanWorktreeDetail {
    pub worktree_id: WorktreeId,
    pub repository_id: RepositoryId,
    pub kind: WorktreeKind,
    pub lifecycle: WorktreeLifecycle,
    pub registration_state: GitRegistrationState,
    pub current_snapshot_id: Option<WorktreeSnapshotId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanNegativeReviewSummary {
    pub negative_evidence_id: ProcedureNegativeEvidenceId,
    pub current_review_revision_id: RevisionId,
    pub status: ProcedureNegativeReviewStatus,
    pub available_decisions: Vec<HumanNegativeDecision>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanProposalSummary {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanProposalReview {
    pub proposal: Box<RevisionProposal>,
    pub plain_accept_eligible: bool,
    pub merge_and_accept_eligible: bool,
    pub reauthorization: Option<ObjectReauthorizationRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
    pub initial_replacement_payload: Option<Box<ProposalPayload>>,
    pub deprecate_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanCompetingDetail {
    pub expected_group_revision_id: RevisionId,
    pub eligible_attempt_ids: Vec<AttemptId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanRepositoryPurgePreview {
    pub repository_id: RepositoryId,
    pub repository_revision: u32,
    pub deletion_generation: u64,
    pub planned_exclusive_cas_count: u32,
    pub shared_cas_retained_count: u32,
    pub repository_derived_global_dependency_count: u32,
    pub affected_session_count: u32,
    pub affected_evidence_receipt_capture_count: u32,
    pub affected_work_count: u32,
    pub affected_atom_count: u32,
    pub affected_procedure_count: u32,
    pub affected_experiment_run_count: u32,
    pub affected_result_evidence_count: u32,
    pub affected_artifact_count: u32,
    pub affected_recovery_count: u32,
    pub affected_recall_derived_count: u32,
    pub relationship_only_count: u32,
    pub estimated_reclaimable_bytes: Option<u64>,
    pub blockers: Vec<RepositoryPurgeBlocker>,
    pub downstream_support_revalidation_count: u32,
    pub dependent_procedure_review_hold_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanPage {
    pub frontier: u64,
    pub status: HumanSnapshotStatus,
    pub degraded_reasons: Vec<HumanDegradedReason>,
    pub items: Vec<HumanSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanSnapshotStatus {
    Ready,
    Degraded,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HumanDegradedReason {
    CurrentJobFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HumanProposalDecision {
    Accept,
    EditAndAccept(Box<ProposalPayload>),
    Reauthorize,
    MergeAndAccept,
    Defer,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HumanNegativeDecision {
    ResolveAsIneffective,
    DismissAttribution,
    ConfirmHarm,
    RequestRevision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HumanActionOutcome {
    Applied {
        current_revision_ref: String,
        audit_event_ref: String,
    },
    NoDelta {
        current_revision_ref: String,
    },
    Conflict {
        current_revision_ref: Option<String>,
    },
    Unavailable {
        reason: &'static str,
    },
}

#[derive(Debug, Error)]
pub enum HumanGovernanceError {
    #[error("invalid human governance request")]
    InvalidInput,
    #[error("human governance store failure")]
    Store,
}

#[derive(Clone)]
pub struct HumanGovernanceService {
    writer: WriterHandle,
    effective_config_hash: [u8; 32],
    runtime_snapshot: Option<RuntimeSnapshot>,
    global_promotion: GlobalPromotionConfig,
}

impl HumanGovernanceService {
    pub fn new(writer: WriterHandle, effective_config_hash: [u8; 32]) -> Self {
        Self {
            writer,
            effective_config_hash,
            runtime_snapshot: None,
            global_promotion: GlobalPromotionConfig::default(),
        }
    }

    pub fn with_acceptance(
        writer: WriterHandle,
        effective_config_hash: [u8; 32],
        runtime_snapshot: RuntimeSnapshot,
        global_promotion: GlobalPromotionConfig,
    ) -> Self {
        Self {
            writer,
            effective_config_hash,
            runtime_snapshot: Some(runtime_snapshot),
            global_promotion,
        }
    }

    pub async fn reconcile_reserved_once(&self) -> Result<(), HumanGovernanceError> {
        let Some(runtime_snapshot) = self.runtime_snapshot.as_ref() else {
            return Ok(());
        };
        let spool = DurableSpool::open_read_only(
            runtime_snapshot.spool_dir.clone(),
            runtime_snapshot
                .spool_limits()
                .map_err(|_| HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let limit = usize::try_from(runtime_snapshot.max_main_files)
            .map_err(|_| HumanGovernanceError::Store)?;
        let cas = CasStore::open(runtime_snapshot.cas_dir.clone())
            .map_err(|_| HumanGovernanceError::Store)?;
        for segment in spool
            .isolated_segments(limit)
            .map_err(|_| HumanGovernanceError::Store)?
        {
            let frame = segment
                .frames()
                .first()
                .filter(|_| segment.frames().len() == 1)
                .ok_or(HumanGovernanceError::Store)?;
            let verified =
                verify_capture_frame(frame, &cas).map_err(|_| HumanGovernanceError::Store)?;
            if verified.body.eligible_event_manifest_ref != TUI_ACCEPTANCE_EVENT_MANIFEST_REF {
                return Err(HumanGovernanceError::Store);
            }
            let proposal_id = RevisionProposalId::from_str(&verified.body.source_ref)
                .map_err(|_| HumanGovernanceError::Store)?;
            let snapshot = self
                .writer
                .project()
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
            let view = SemanticCurrentView::from_snapshot(&snapshot)
                .map_err(|_| HumanGovernanceError::Store)?;
            let reviewed_revision = RevisionId::from_str(verified.body.source_revision.as_str())
                .map_err(|_| HumanGovernanceError::Store)?;
            let reviewed = view
                .proposal_revisions
                .get(&reviewed_revision)
                .filter(|value| value.proposal_id == proposal_id)
                .ok_or(HumanGovernanceError::Store)?;
            if let Some(reserved) =
                try_read_reauthorization_intent(&verified, &cas, &snapshot, reviewed)?
            {
                let deletion = reserved.deletion;
                let intent = reserved.intent;
                let source = reviewed;
                let canonical = intent
                    .canonical_toml(&deletion, reviewed)
                    .ok_or(HumanGovernanceError::Store)?;
                validate_reauthorization_capture(&verified, source, &canonical)?;
                if let Some(committed) = self
                    .writer
                    .committed_command(verified.body.command_id)
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?
                {
                    let accepted = verify_reauthorization_cohort(
                        &committed.payloads,
                        &verified,
                        &deletion,
                        reviewed,
                    )?;
                    if view.proposals.get(&accepted.proposal_id) != Some(&accepted) {
                        return Err(HumanGovernanceError::Store);
                    }
                    spool
                        .acknowledge_segment(segment, 1)
                        .map_err(|_| HumanGovernanceError::Store)?;
                    continue;
                }
                if view.proposals.get(&source.proposal_id) != Some(source) {
                    continue;
                }
                let request_id = RequestId::from_uuid(verified.body.command_id.as_uuid())
                    .map_err(|_| HumanGovernanceError::Store)?;
                drop(segment);
                let _ = Box::pin(self.accept_reauthorization(request_id, &snapshot, &view, source))
                    .await?;
                continue;
            }
            if let Some(intent) = try_read_edit_intent(&verified, &cas, reviewed)? {
                validate_edit_capture(&verified, reviewed, &intent)?;
                if let Some(committed) = self
                    .writer
                    .committed_command(verified.body.command_id)
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?
                {
                    let (superseded, accepted) = verify_edit_acceptance_cohort(
                        &committed.payloads,
                        &verified,
                        reviewed,
                        &intent,
                    )?;
                    validate_current_edit_cohort(&snapshot, &view, &superseded, &accepted)?;
                    spool
                        .acknowledge_segment(segment, 1)
                        .map_err(|_| HumanGovernanceError::Store)?;
                    continue;
                }
                if view.proposals.get(&proposal_id) != Some(reviewed) {
                    spool
                        .acknowledge_segment(segment, 1)
                        .map_err(|_| HumanGovernanceError::Store)?;
                    continue;
                }
                let request_id = RequestId::from_uuid(verified.body.command_id.as_uuid())
                    .map_err(|_| HumanGovernanceError::Store)?;
                drop(segment);
                let _ = self
                    .accept_edit(
                        request_id,
                        &snapshot,
                        &view,
                        reviewed,
                        intent.new_proposal.payload,
                    )
                    .await?;
                continue;
            }
            validate_acceptance_capture(&verified, reviewed)?;
            if let Some(committed) = self
                .writer
                .committed_command(verified.body.command_id)
                .await
                .map_err(|_| HumanGovernanceError::Store)?
            {
                let accepted = verify_acceptance_cohort(&committed.payloads, &verified, reviewed)?;
                if view.proposals.get(&proposal_id) != Some(&accepted) {
                    return Err(HumanGovernanceError::Store);
                }
                spool
                    .acknowledge_segment(segment, 1)
                    .map_err(|_| HumanGovernanceError::Store)?;
                continue;
            }
            let Some(proposal) = view.proposals.get(&proposal_id) else {
                spool
                    .acknowledge_segment(segment, 1)
                    .map_err(|_| HumanGovernanceError::Store)?;
                continue;
            };
            if proposal.proposal_revision_id.to_string() != verified.body.source_revision.as_str()
                || !proposal.status.is_open()
            {
                spool
                    .acknowledge_segment(segment, 1)
                    .map_err(|_| HumanGovernanceError::Store)?;
                continue;
            }
            if inactive_unchanged_procedure(&snapshot, proposal)? {
                spool
                    .acknowledge_segment(segment, 1)
                    .map_err(|_| HumanGovernanceError::Store)?;
                continue;
            }
            if proposal.operation == ProposalOperation::Merge
                && RevisionProposalService
                    .validate_atom_merge(&view, proposal.proposal_id)
                    .is_err()
            {
                spool
                    .acknowledge_segment(segment, 1)
                    .map_err(|_| HumanGovernanceError::Store)?;
                continue;
            }
            let request_id = RequestId::from_uuid(verified.body.command_id.as_uuid())
                .map_err(|_| HumanGovernanceError::Store)?;
            drop(segment);
            let _ = self
                .accept_plain(request_id, &snapshot, &view, proposal)
                .await?;
        }
        Ok(())
    }

    pub async fn list(
        &self,
        surface: HumanSurface,
        expected_frontier: Option<u64>,
        after: Option<&str>,
        limit: u16,
    ) -> Result<Result<HumanPage, u64>, HumanGovernanceError> {
        if limit == 0 || limit > MAX_PAGE || after.is_some_and(|value| !valid_ref(value)) {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if expected_frontier.is_some_and(|frontier| frontier != snapshot.frontier) {
            return Ok(Err(snapshot.frontier));
        }
        Ok(Ok(page(&snapshot, surface, after, usize::from(limit))?))
    }

    pub async fn detail(
        &self,
        surface: HumanSurface,
        object_ref: &str,
        expected_frontier: u64,
        expected_revision_ref: Option<&str>,
    ) -> Result<Result<HumanPage, (u64, Option<String>)>, HumanGovernanceError> {
        if !valid_ref(object_ref) || expected_revision_ref.is_some_and(|value| !valid_ref(value)) {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier != expected_frontier {
            return Ok(Err((snapshot.frontier, None)));
        }
        let mut matching = surface_rows(&snapshot, surface)?
            .into_iter()
            .filter(|row| row.row_id == object_ref || row.object_id.as_deref() == Some(object_ref))
            .collect::<Vec<_>>();
        if let Some(expected) = expected_revision_ref
            && let Some(current) = matching
                .iter()
                .find_map(|row| row.current_revision_id.as_deref())
            && current != expected
        {
            return Ok(Err((snapshot.frontier, Some(current.into()))));
        }
        if matching.len() > 1 {
            matching.retain(|row| {
                row.row_id == object_ref
                    || expected_revision_ref.is_some_and(|expected| {
                        row.current_revision_id.as_deref() == Some(expected)
                    })
            });
        }
        if matching.len() > 1 {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let semantic_view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let usage_view = ProcedureUsageCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let items = matching
            .into_iter()
            .map(|row| {
                summary(
                    &snapshot,
                    row,
                    &semantic_view,
                    &usage_view,
                    self.runtime_snapshot.as_ref(),
                    surface,
                    true,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (status, degraded_reasons) = snapshot_status(&snapshot)?;
        Ok(Ok(HumanPage {
            frontier: snapshot.frontier,
            status,
            degraded_reasons,
            items,
            next_cursor: None,
        }))
    }

    pub async fn related(
        &self,
        request: HumanRelatedRequest<'_>,
    ) -> Result<Result<HumanPage, (u64, Option<String>)>, HumanGovernanceError> {
        if !valid_ref(request.source_stable_key)
            || !valid_ref(request.expected_source_revision_ref)
            || request.limit == 0
            || request.limit > MAX_PAGE
            || request.after.is_some_and(|value| !valid_ref(value))
        {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier != request.expected_frontier {
            return Ok(Err((snapshot.frontier, None)));
        }
        let source = snapshot
            .data_rows()
            .find(|row| row.row_id == request.source_stable_key)
            .ok_or(HumanGovernanceError::InvalidInput)?;
        let semantic_view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let refs = match request.relation {
            HumanRelationKind::ProposalEvidence => {
                let proposal_id = source
                    .object_id
                    .as_deref()
                    .and_then(|value| value.parse::<RevisionProposalId>().ok())
                    .ok_or(HumanGovernanceError::InvalidInput)?;
                let current = semantic_view
                    .proposals
                    .get(&proposal_id)
                    .ok_or(HumanGovernanceError::InvalidInput)?;
                if source.object_kind.as_deref() != Some("revision_proposal_revision")
                    || source.current_revision_id.as_deref()
                        != Some(current.proposal_revision_id.to_string().as_str())
                    || request.expected_source_revision_ref
                        != current.proposal_revision_id.to_string()
                {
                    return Ok(Err((
                        snapshot.frontier,
                        Some(current.proposal_revision_id.to_string()),
                    )));
                }
                current
                    .evidence_refs
                    .iter()
                    .chain(&current.source_cohort_refs)
                    .cloned()
                    .collect::<BTreeSet<_>>()
            }
            HumanRelationKind::SupportDependencies => {
                if support_validation(source)?.is_none() {
                    return Err(HumanGovernanceError::InvalidInput);
                }
                let Some((validation, contract)) = current_support_source(&snapshot, source)?
                else {
                    let current = current_support_revision(&snapshot, source)?;
                    return Ok(Err((
                        snapshot.frontier,
                        current.map(|value| value.to_string()),
                    )));
                };
                if request.expected_source_revision_ref
                    != validation.validation_revision_id.to_string()
                {
                    return Ok(Err((
                        snapshot.frontier,
                        Some(validation.validation_revision_id.to_string()),
                    )));
                }
                support_dependency_refs(&validation, &contract)
            }
        };
        let rows = related_rows(&snapshot, refs, request.after, usize::from(request.limit))?;
        let usage_view = ProcedureUsageCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let (selected, next_cursor) = rows;
        let (status, degraded_reasons) = snapshot_status(&snapshot)?;
        Ok(Ok(HumanPage {
            frontier: snapshot.frontier,
            status,
            degraded_reasons,
            items: selected
                .into_iter()
                .map(|row| {
                    summary(
                        &snapshot,
                        row,
                        &semantic_view,
                        &usage_view,
                        None,
                        HumanSurface::Explorer,
                        false,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
            next_cursor,
        }))
    }

    pub async fn decide_proposal(
        &self,
        request_id: RequestId,
        expected_frontier: u64,
        proposal_id: RevisionProposalId,
        expected_revision_id: RevisionId,
        expected_fingerprint: &str,
        decision: HumanProposalDecision,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        if expected_fingerprint.len() != 64
            || !expected_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(HumanGovernanceError::InvalidInput);
        }
        if matches!(
            &decision,
            HumanProposalDecision::Accept
                | HumanProposalDecision::MergeAndAccept
                | HumanProposalDecision::Reauthorize
        ) {
            Box::pin(self.reconcile_reserved_once()).await?;
        }
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        if let HumanProposalDecision::EditAndAccept(edited_payload) = &decision
            && let Some(original) =
                view.proposal_revisions
                    .get(&expected_revision_id)
                    .filter(|value| {
                        value.proposal_id == proposal_id
                            && hex(&value.fingerprint) == expected_fingerprint
                    })
            && let Some(accepted) = accepted_edit_retry(&snapshot, &view, original, edited_payload)?
        {
            Box::pin(self.reconcile_reserved_once()).await?;
            return Ok(HumanActionOutcome::NoDelta {
                current_revision_ref: accepted.proposal_revision_id.to_string(),
            });
        }
        if let HumanProposalDecision::Reauthorize = &decision
            && let Some(original) =
                view.proposal_revisions
                    .get(&expected_revision_id)
                    .filter(|value| {
                        value.proposal_id == proposal_id
                            && hex(&value.fingerprint) == expected_fingerprint
                    })
            && let Some(accepted) = accepted_reauthorization_retry(&snapshot, &view, original)?
        {
            Box::pin(self.reconcile_reserved_once()).await?;
            return Ok(HumanActionOutcome::NoDelta {
                current_revision_ref: accepted.proposal_revision_id.to_string(),
            });
        }
        let Some(current) = view.proposals.get(&proposal_id) else {
            return Err(HumanGovernanceError::InvalidInput);
        };
        if matches!(
            &decision,
            HumanProposalDecision::Accept | HumanProposalDecision::MergeAndAccept
        ) && current.status == ProposalStatus::Accepted
            && current.acceptance.as_ref().is_some_and(|acceptance| {
                acceptance.reviewed_proposal_revision_id == expected_revision_id
                    && hex(&acceptance.reviewed_fingerprint) == expected_fingerprint
            })
        {
            return Ok(HumanActionOutcome::NoDelta {
                current_revision_ref: current.proposal_revision_id.to_string(),
            });
        }
        if snapshot.frontier != expected_frontier {
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref: Some(current.proposal_revision_id.to_string()),
            });
        }
        if current.proposal_revision_id != expected_revision_id
            || hex(&current.fingerprint) != expected_fingerprint
        {
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref: Some(current.proposal_revision_id.to_string()),
            });
        }
        let deletion_admission = ObjectDeletionCandidateAdmissionView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?
            .classify_proposal(current)
            .map_err(|_| HumanGovernanceError::Store)?;
        if matches!(
            &decision,
            HumanProposalDecision::Accept
                | HumanProposalDecision::EditAndAccept(_)
                | HumanProposalDecision::MergeAndAccept
        ) && !matches!(deletion_admission, ObjectDeletionCandidateAdmission::Clear)
        {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "forgotten_object_requires_explicit_reauthorization",
            });
        }
        let next_status = match &decision {
            HumanProposalDecision::Defer => ProposalStatus::Deferred,
            HumanProposalDecision::Reject => ProposalStatus::Rejected,
            HumanProposalDecision::Accept => {
                let (plain_accept_eligible, _) = proposal_acceptance_eligibility(&view, current);
                if !plain_accept_eligible {
                    return Ok(HumanActionOutcome::Unavailable {
                        reason: "atomic_plain_acceptance_unavailable",
                    });
                }
                return self
                    .accept_plain(request_id, &snapshot, &view, current)
                    .await;
            }
            HumanProposalDecision::EditAndAccept(edited_payload) => {
                if !proposal_edit_supported(&current.payload) {
                    return Ok(HumanActionOutcome::Unavailable {
                        reason: "atomic_edit_and_accept_unavailable",
                    });
                }
                return self
                    .accept_edit(
                        request_id,
                        &snapshot,
                        &view,
                        current,
                        edited_payload.as_ref().clone(),
                    )
                    .await;
            }
            HumanProposalDecision::Reauthorize => {
                if deletion_admission
                    .representative_historical_deletion()
                    .is_none()
                    || current.operation != ProposalOperation::Create
                {
                    return Ok(HumanActionOutcome::Unavailable {
                        reason: "object_reauthorization_unavailable",
                    });
                }
                return Box::pin(
                    self.accept_reauthorization(request_id, &snapshot, &view, current),
                )
                .await;
            }
            HumanProposalDecision::MergeAndAccept => {
                let (_, merge_and_accept_eligible) =
                    proposal_acceptance_eligibility(&view, current);
                if !merge_and_accept_eligible {
                    return Ok(HumanActionOutcome::Unavailable {
                        reason: "atomic_merge_and_accept_unavailable",
                    });
                }
                return self
                    .accept_plain(request_id, &snapshot, &view, current)
                    .await;
            }
        };
        let context = command_context(request_id, self.effective_config_hash)?;
        match RevisionProposalService
            .revise_status(
                &view,
                context,
                proposal_id,
                next_status,
                Vec::new(),
                Some(
                    match &decision {
                        HumanProposalDecision::Defer => "human_deferred",
                        HumanProposalDecision::Reject => "human_rejected",
                        HumanProposalDecision::Reauthorize => unreachable!(),
                        _ => unreachable!(),
                    }
                    .into(),
                ),
            )
            .map_err(|_| HumanGovernanceError::InvalidInput)?
        {
            ProposalResolution::NoDelta => Ok(HumanActionOutcome::NoDelta {
                current_revision_ref: current.proposal_revision_id.to_string(),
            }),
            ProposalResolution::Revision { value, command } => {
                let revision = value.proposal_revision_id.to_string();
                let outcome = match self
                    .writer
                    .commit_if_frontier(command, now_us()?, snapshot.frontier)
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(crate::WriterActorError::StaleFrontier) => {
                        let latest = self
                            .writer
                            .project()
                            .await
                            .map_err(|_| HumanGovernanceError::Store)?;
                        return Ok(HumanActionOutcome::Conflict {
                            current_revision_ref: current_proposal_revision(&latest, proposal_id),
                        });
                    }
                    Err(_) => return Err(HumanGovernanceError::Store),
                };
                let audit = outcome
                    .event_ids
                    .last()
                    .cloned()
                    .ok_or(HumanGovernanceError::Store)?;
                Ok(HumanActionOutcome::Applied {
                    current_revision_ref: revision,
                    audit_event_ref: audit,
                })
            }
        }
    }

    async fn accept_edit(
        &self,
        request_id: RequestId,
        snapshot: &ProjectionSnapshot,
        view: &SemanticCurrentView,
        original: &RevisionProposal,
        edited_payload: ProposalPayload,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let Some(runtime_snapshot) = self.runtime_snapshot.as_ref() else {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "atomic_tui_acceptance_source_unavailable",
            });
        };
        let support = match support_atom_acceptance(snapshot, view, original) {
            Ok(value) => value,
            Err(crate::semantic::SemanticServiceError::Store(_)) => {
                return Err(HumanGovernanceError::Store);
            }
            Err(_) => {
                return Ok(HumanActionOutcome::Unavailable {
                    reason: "support_linked_global_acceptance_unavailable",
                });
            }
        };
        let record_id = format!(
            "tui-accept-{}-{}",
            original.proposal_id, original.proposal_revision_id
        );
        let routing_hint = format!("tui-{}", original.proposal_id.as_uuid().hyphenated());
        let max_segments = usize::try_from(runtime_snapshot.max_main_files)
            .map_err(|_| HumanGovernanceError::Store)?;
        let spool = DurableSpool::open_read_only(
            runtime_snapshot.spool_dir.clone(),
            runtime_snapshot
                .spool_limits()
                .map_err(|_| HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let cas = CasStore::open(runtime_snapshot.cas_dir.clone())
            .map_err(|_| HumanGovernanceError::Store)?;
        let mut claimed = claim_isolated_record(&spool, &record_id, max_segments)?;
        if let Some(segment) = claimed.take() {
            let frame = segment
                .frames()
                .first()
                .filter(|_| segment.frames().len() == 1)
                .ok_or(HumanGovernanceError::Store)?;
            let verified =
                verify_capture_frame(frame, &cas).map_err(|_| HumanGovernanceError::Store)?;
            let stored = read_edit_intent(&verified, &cas, original)?;
            validate_edit_capture(&verified, original, &stored)?;
            if stored.new_proposal.payload == edited_payload {
                claimed = Some(segment);
            } else {
                match self
                    .writer
                    .committed_command(verified.body.command_id)
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?
                {
                    None if view.proposals.get(&original.proposal_id) == Some(original) => {
                        spool
                            .acknowledge_segment(segment, 1)
                            .map_err(|_| HumanGovernanceError::Store)?;
                    }
                    _ => return Err(HumanGovernanceError::Store),
                }
            }
        }
        if claimed.is_none() {
            let command_id = CommandId::from_uuid(request_id.as_uuid())
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
            let created_at_us = now_us()?;
            let (intent, _) = prepare_edit_candidate(
                view,
                original,
                edited_payload.clone(),
                command_id,
                created_at_us,
                self.effective_config_hash,
                None,
            )?;
            let canonical = intent.canonical_toml(original)?;
            let scope = acceptance_capture_scope(&intent.new_proposal, view)?;
            let mut capture = CaptureRuntime::open(runtime_snapshot.clone())
                .map_err(|_| HumanGovernanceError::Store)?;
            let isolated = capture
                .capture_isolated(
                    acceptance_capture_input(original, &canonical, &record_id, scope)?,
                    command_id,
                    &routing_hint,
                )
                .map_err(|_| HumanGovernanceError::Store)?;
            if !matches!(isolated.outcome, CaptureOutcome::Durable { .. }) {
                return Err(HumanGovernanceError::Store);
            }
            claimed = Some(isolated.segment);
        }
        let segment = claimed.ok_or(HumanGovernanceError::Store)?;
        let frame = segment
            .frames()
            .first()
            .filter(|_| segment.frames().len() == 1)
            .ok_or(HumanGovernanceError::Store)?;
        let verified =
            verify_capture_frame(frame, &cas).map_err(|_| HumanGovernanceError::Store)?;
        let intent = read_edit_intent(&verified, &cas, original)?;
        validate_edit_capture(&verified, original, &intent)?;
        if intent.new_proposal.payload != edited_payload {
            return Err(HumanGovernanceError::Store);
        }
        let occurred_at_us = now_us()?;
        let command_context = ProposalCommandContext {
            command_id: verified.body.command_id,
            occurred_at_us,
            effective_config_hash: self.effective_config_hash,
            algorithm_revision: ALGORITHM_REVISION.into(),
        };
        let mut edited_view = view.clone();
        edited_view
            .proposals
            .insert(intent.new_proposal.proposal_id, intent.new_proposal.clone());
        edited_view.proposal_revisions.insert(
            intent.new_proposal.proposal_revision_id,
            intent.new_proposal.clone(),
        );
        let context = acceptance_context(&intent.new_proposal, &edited_view, &verified)?;
        let composed = compose_edited_acceptance(EditedAcceptanceInput {
            snapshot,
            view,
            original,
            reviewed: &intent.new_proposal,
            acceptance: context,
            command_context,
            effective_config_hash: self.effective_config_hash,
            global_promotion: &self.global_promotion,
            support: support.as_ref(),
        })?;
        let accepted_revision = composed.accepted_revision;
        let superseded = composed.superseded;
        let mut events = capture_event_drafts(
            &verified,
            None,
            self.effective_config_hash,
            ALGORITHM_REVISION,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        events.extend(composed.events);
        let audit_ordinal = events
            .iter()
            .position(|event| {
                matches!(
                    &event.payload,
                    JournalPayload::RevisionProposalRecorded(value)
                        if value.proposal_id == intent.new_proposal.proposal_id
                            && value.status == ProposalStatus::Accepted
                )
            })
            .ok_or(HumanGovernanceError::Store)?;
        let command = JournalCommand::new(verified.body.command_id, events)
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let outcome = match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(outcome) => outcome,
            Err(crate::WriterActorError::StaleFrontier) => {
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: current_proposal_revision(
                        &self
                            .writer
                            .project()
                            .await
                            .map_err(|_| HumanGovernanceError::Store)?,
                        original.proposal_id,
                    ),
                });
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        };
        let committed = self
            .writer
            .committed_command(verified.body.command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
            .ok_or(HumanGovernanceError::Store)?;
        let (committed_superseded, committed_accepted) =
            verify_edit_acceptance_cohort(&committed.payloads, &verified, original, &intent)?;
        let fresh = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let fresh_view =
            SemanticCurrentView::from_snapshot(&fresh).map_err(|_| HumanGovernanceError::Store)?;
        validate_current_edit_cohort(
            &fresh,
            &fresh_view,
            &committed_superseded,
            &committed_accepted,
        )?;
        if committed_superseded.as_ref() != superseded.as_ref()
            || committed_accepted.proposal_revision_id != accepted_revision
        {
            return Err(HumanGovernanceError::Store);
        }
        let audit_event_ref = outcome
            .event_ids
            .get(audit_ordinal)
            .cloned()
            .ok_or(HumanGovernanceError::Store)?;
        spool
            .acknowledge_segment(segment, 1)
            .map_err(|_| HumanGovernanceError::Store)?;
        Ok(HumanActionOutcome::Applied {
            current_revision_ref: accepted_revision.to_string(),
            audit_event_ref,
        })
    }

    async fn accept_reauthorization(
        &self,
        request_id: RequestId,
        snapshot: &ProjectionSnapshot,
        view: &SemanticCurrentView,
        original: &RevisionProposal,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let Some(runtime_snapshot) = self.runtime_snapshot.as_ref() else {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "atomic_tui_acceptance_source_unavailable",
            });
        };
        let admission = ObjectDeletionCandidateAdmissionView::from_snapshot(snapshot)
            .map_err(|_| HumanGovernanceError::Store)?
            .classify_proposal(original)
            .map_err(|_| HumanGovernanceError::Store)?;
        let deletion = admission
            .representative_historical_deletion()
            .cloned()
            .ok_or(HumanGovernanceError::InvalidInput)?;
        let record_id = format!(
            "tui-reauthorize-{}-{}",
            original.proposal_id, original.proposal_revision_id
        );
        let routing_hint = format!("tui-{}", original.proposal_id.as_uuid().hyphenated());
        let max_segments = usize::try_from(runtime_snapshot.max_main_files)
            .map_err(|_| HumanGovernanceError::Store)?;
        let spool = DurableSpool::open_read_only(
            runtime_snapshot.spool_dir.clone(),
            runtime_snapshot
                .spool_limits()
                .map_err(|_| HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let cas = CasStore::open(runtime_snapshot.cas_dir.clone())
            .map_err(|_| HumanGovernanceError::Store)?;
        let mut claimed = claim_isolated_record(&spool, &record_id, max_segments)?;
        if claimed.is_none() {
            let command_id = CommandId::from_uuid(request_id.as_uuid())
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
            let intent = ObjectReauthorizationIntent::new(&deletion, original)
                .ok_or(HumanGovernanceError::InvalidInput)?;
            let canonical = intent
                .canonical_toml(&deletion, original)
                .ok_or(HumanGovernanceError::InvalidInput)?;
            let scope = acceptance_capture_scope(original, view)?;
            let mut capture = CaptureRuntime::open(runtime_snapshot.clone())
                .map_err(|_| HumanGovernanceError::Store)?;
            let isolated = capture
                .capture_isolated(
                    acceptance_capture_input(original, &canonical, &record_id, scope)?,
                    command_id,
                    &routing_hint,
                )
                .map_err(|_| HumanGovernanceError::Store)?;
            if !matches!(isolated.outcome, CaptureOutcome::Durable { .. }) {
                return Err(HumanGovernanceError::Store);
            }
            claimed = Some(isolated.segment);
        }
        let segment = claimed.ok_or(HumanGovernanceError::Store)?;
        let frame = segment
            .frames()
            .first()
            .filter(|_| segment.frames().len() == 1)
            .ok_or(HumanGovernanceError::Store)?;
        let verified =
            verify_capture_frame(frame, &cas).map_err(|_| HumanGovernanceError::Store)?;
        let intent = read_reauthorization_intent(&verified, &cas, &deletion, original)?;
        let reviewed = original;
        let canonical = intent
            .canonical_toml(&deletion, reviewed)
            .ok_or(HumanGovernanceError::Store)?;
        validate_reauthorization_capture(&verified, reviewed, &canonical)?;
        let occurred_at_us = now_us()?;
        let command_context = ProposalCommandContext {
            command_id: verified.body.command_id,
            occurred_at_us,
            effective_config_hash: self.effective_config_hash,
            algorithm_revision: ALGORITHM_REVISION.into(),
        };
        let mut events = capture_event_drafts(
            &verified,
            None,
            self.effective_config_hash,
            ALGORITHM_REVISION,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let acceptance = reauthorization_acceptance_context(reviewed, view, &verified, canonical)?;
        let (accepted_revision, accepted_command) = match &reviewed.payload {
            ProposalPayload::Atom(_) => {
                let accepted = RevisionProposalService
                    .accept(view, command_context, reviewed.proposal_id, acceptance)
                    .map_err(|_| HumanGovernanceError::InvalidInput)?;
                (accepted.proposal.proposal_revision_id, accepted.command)
            }
            ProposalPayload::Procedure(_) => {
                let result = accept_procedure(
                    view,
                    command_context,
                    reviewed.proposal_id,
                    ProcedureAcceptanceContext::Manual(acceptance),
                    None,
                    None,
                    &self.global_promotion,
                )
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
                match result {
                    ProcedureAcceptanceResolution::Command {
                        proposal, command, ..
                    } => (proposal.proposal_revision_id, command),
                    ProcedureAcceptanceResolution::AcceptedExisting { .. }
                    | ProcedureAcceptanceResolution::NoDelta => {
                        return Err(HumanGovernanceError::Store);
                    }
                }
            }
            ProposalPayload::CoreMembership(payload) => {
                let CoreMembershipProposalPayload::Create {
                    atom_revision_id, ..
                } = payload.as_ref()
                else {
                    return Err(HumanGovernanceError::InvalidInput);
                };
                let atom = view
                    .atom_revisions
                    .get(atom_revision_id)
                    .ok_or(HumanGovernanceError::InvalidInput)?;
                let membership = accept_core_membership(
                    view,
                    command_context,
                    reviewed.proposal_id,
                    CoreMembershipAcceptanceContext::Tui(acceptance),
                    atom,
                    CoreMembershipId::from_uuid(reviewed.proposal_id.as_uuid())
                        .map_err(|_| HumanGovernanceError::InvalidInput)?,
                    SupportThresholdSnapshot {
                        minimum_surviving_support: 1,
                        require_authorization: true,
                    },
                )
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
                (membership.proposal.proposal_revision_id, membership.command)
            }
            ProposalPayload::ReservedTarget { .. } => {
                return Err(HumanGovernanceError::InvalidInput);
            }
        };
        events.extend(accepted_command.events().iter().cloned());
        let audit_ordinal = events
            .iter()
            .position(|event| {
                matches!(
                    &event.payload,
                    JournalPayload::RevisionProposalRecorded(value)
                        if value.proposal_id == reviewed.proposal_id
                            && value.status == ProposalStatus::Accepted
                )
            })
            .ok_or(HumanGovernanceError::Store)?;
        let command = JournalCommand::new(verified.body.command_id, events)
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let outcome = match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(outcome) => outcome,
            Err(crate::WriterActorError::StaleFrontier) => {
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: current_proposal_revision(
                        &self
                            .writer
                            .project()
                            .await
                            .map_err(|_| HumanGovernanceError::Store)?,
                        original.proposal_id,
                    ),
                });
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        };
        let committed = self
            .writer
            .committed_command(verified.body.command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
            .ok_or(HumanGovernanceError::Store)?;
        let accepted =
            verify_reauthorization_cohort(&committed.payloads, &verified, &deletion, reviewed)?;
        if accepted.proposal_revision_id != accepted_revision {
            return Err(HumanGovernanceError::Store);
        }
        let audit_event_ref = outcome
            .event_ids
            .get(audit_ordinal)
            .cloned()
            .ok_or(HumanGovernanceError::Store)?;
        spool
            .acknowledge_segment(segment, 1)
            .map_err(|_| HumanGovernanceError::Store)?;
        Ok(HumanActionOutcome::Applied {
            current_revision_ref: accepted_revision.to_string(),
            audit_event_ref,
        })
    }

    async fn accept_plain(
        &self,
        request_id: RequestId,
        snapshot: &ProjectionSnapshot,
        view: &SemanticCurrentView,
        proposal: &RevisionProposal,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let Some(runtime_snapshot) = self.runtime_snapshot.as_ref() else {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "atomic_tui_acceptance_source_unavailable",
            });
        };
        if inactive_unchanged_procedure(snapshot, proposal)? {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "existing_procedure_not_active",
            });
        }
        let support = match support_atom_acceptance(snapshot, view, proposal) {
            Ok(value) => value,
            Err(crate::semantic::SemanticServiceError::Store(_)) => {
                return Err(HumanGovernanceError::Store);
            }
            Err(_) => {
                return Ok(HumanActionOutcome::Unavailable {
                    reason: "support_linked_global_acceptance_unavailable",
                });
            }
        };
        let payload = tui_acceptance_event_payload(
            proposal.proposal_id,
            proposal.proposal_revision_id,
            &proposal.fingerprint,
        );
        let record_id = format!(
            "tui-accept-{}-{}",
            proposal.proposal_id, proposal.proposal_revision_id
        );
        let routing_hint = format!("tui-{}", proposal.proposal_id.as_uuid().hyphenated());
        let max_segments = usize::try_from(runtime_snapshot.max_main_files)
            .map_err(|_| HumanGovernanceError::Store)?;
        let spool = DurableSpool::open_read_only(
            runtime_snapshot.spool_dir.clone(),
            runtime_snapshot
                .spool_limits()
                .map_err(|_| HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let mut claimed = claim_isolated_record(&spool, &record_id, max_segments)?;
        if claimed.is_none() {
            let scope = acceptance_capture_scope(proposal, view)?;
            let command_id = CommandId::from_uuid(request_id.as_uuid())
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
            let mut capture = CaptureRuntime::open(runtime_snapshot.clone())
                .map_err(|_| HumanGovernanceError::Store)?;
            let isolated = capture
                .capture_isolated(
                    acceptance_capture_input(proposal, &payload, &record_id, scope)?,
                    command_id,
                    &routing_hint,
                )
                .map_err(|_| HumanGovernanceError::Store)?;
            if !matches!(isolated.outcome, CaptureOutcome::Durable { .. }) {
                return Err(HumanGovernanceError::Store);
            }
            claimed = Some(isolated.segment);
        }
        let segment = claimed.ok_or(HumanGovernanceError::Store)?;
        let frame = segment
            .frames()
            .first()
            .filter(|_| segment.frames().len() == 1)
            .ok_or(HumanGovernanceError::Store)?;
        let cas = CasStore::open(runtime_snapshot.cas_dir.clone())
            .map_err(|_| HumanGovernanceError::Store)?;
        let verified =
            verify_capture_frame(frame, &cas).map_err(|_| HumanGovernanceError::Store)?;
        if verified.body.eligible_event_manifest_ref != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
            || verified.body.source_role != SourceRole::User
            || verified.body.content_trust != ContentTrust::UserStatement
            || verified.body.capture_completeness != CaptureCompleteness::Complete
            || verified.body.observation_role != ObservationRole::Message
        {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let context = acceptance_context(proposal, view, &verified)?;
        let occurred_at_us = now_us()?;
        let command_context = ProposalCommandContext {
            command_id: verified.body.command_id,
            occurred_at_us,
            effective_config_hash: self.effective_config_hash,
            algorithm_revision: ALGORITHM_REVISION.into(),
        };
        let (accepted_revision, accepted_command) = match &proposal.payload {
            ProposalPayload::Atom(_) => {
                let accepted = if let Some(support) = &support {
                    RevisionProposalService.accept_support_linked(
                        view,
                        command_context,
                        proposal.proposal_id,
                        context,
                        support,
                    )
                } else {
                    RevisionProposalService.accept(
                        view,
                        command_context,
                        proposal.proposal_id,
                        context,
                    )
                }
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
                (accepted.proposal.proposal_revision_id, accepted.command)
            }
            ProposalPayload::Procedure(_) => {
                let (current, publication) = current_procedure(snapshot, proposal)?;
                let result = accept_procedure(
                    view,
                    command_context,
                    proposal.proposal_id,
                    ProcedureAcceptanceContext::Manual(context),
                    current.as_ref(),
                    publication,
                    &self.global_promotion,
                )
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
                match result {
                    ProcedureAcceptanceResolution::Command {
                        proposal, command, ..
                    }
                    | ProcedureAcceptanceResolution::AcceptedExisting { proposal, command } => {
                        (proposal.proposal_revision_id, command)
                    }
                    ProcedureAcceptanceResolution::NoDelta => {
                        return Err(HumanGovernanceError::Store);
                    }
                }
            }
            ProposalPayload::CoreMembership(payload) => {
                let CoreMembershipProposalPayload::Create {
                    atom_revision_id, ..
                } = payload.as_ref()
                else {
                    return Ok(HumanActionOutcome::Unavailable {
                        reason: "atomic_core_conflict_acceptance_unavailable",
                    });
                };
                let atom = view
                    .atom_revisions
                    .get(atom_revision_id)
                    .ok_or(HumanGovernanceError::InvalidInput)?;
                let membership = accept_core_membership(
                    view,
                    command_context,
                    proposal.proposal_id,
                    CoreMembershipAcceptanceContext::Tui(context),
                    atom,
                    evertrace_domain::ids::CoreMembershipId::from_uuid(
                        proposal.proposal_id.as_uuid(),
                    )
                    .map_err(|_| HumanGovernanceError::InvalidInput)?,
                    SupportThresholdSnapshot {
                        minimum_surviving_support: 1,
                        require_authorization: true,
                    },
                )
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
                (membership.proposal.proposal_revision_id, membership.command)
            }
            ProposalPayload::ReservedTarget { .. } => {
                return Ok(HumanActionOutcome::Unavailable {
                    reason: "atomic_plain_acceptance_unavailable",
                });
            }
        };
        let mut events = capture_event_drafts(
            &verified,
            None,
            self.effective_config_hash,
            ALGORITHM_REVISION,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        events.extend(accepted_command.events().iter().cloned());
        let audit_ordinal = events
            .iter()
            .position(|event| {
                matches!(
                    &event.payload,
                    JournalPayload::RevisionProposalRecorded(value)
                        if value.proposal_id == proposal.proposal_id
                            && value.status == ProposalStatus::Accepted
                )
            })
            .ok_or(HumanGovernanceError::Store)?;
        let command = JournalCommand::new(verified.body.command_id, events)
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let outcome = match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(outcome) => outcome,
            Err(crate::WriterActorError::StaleFrontier) => {
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: current_proposal_revision(
                        &self
                            .writer
                            .project()
                            .await
                            .map_err(|_| HumanGovernanceError::Store)?,
                        proposal.proposal_id,
                    ),
                });
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        };
        let committed = self
            .writer
            .committed_command(verified.body.command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
            .ok_or(HumanGovernanceError::Store)?;
        let accepted = verify_acceptance_cohort(&committed.payloads, &verified, proposal)?;
        let fresh = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let fresh_view =
            SemanticCurrentView::from_snapshot(&fresh).map_err(|_| HumanGovernanceError::Store)?;
        if fresh_view.proposals.get(&proposal.proposal_id) != Some(&accepted)
            || accepted.proposal_revision_id != accepted_revision
        {
            return Err(HumanGovernanceError::Store);
        }
        let audit_event_ref = outcome
            .event_ids
            .get(audit_ordinal)
            .cloned()
            .ok_or(HumanGovernanceError::Store)?;
        spool
            .acknowledge_segment(segment, 1)
            .map_err(|_| HumanGovernanceError::Store)?;
        Ok(HumanActionOutcome::Applied {
            current_revision_ref: accepted_revision.to_string(),
            audit_event_ref,
        })
    }

    pub async fn submit_support_replacement(
        &self,
        request_id: RequestId,
        expected_frontier: u64,
        expected_validation_revision_id: RevisionId,
        edited_payload: ProposalPayload,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier != expected_frontier {
            let current_revision_ref =
                match select_support_replacement(&snapshot, expected_validation_revision_id) {
                    Ok(SupportReplacementLookup::Conflict {
                        current_revision_id,
                    }) => Some(current_revision_id.to_string()),
                    Ok(
                        SupportReplacementLookup::Available(_)
                        | SupportReplacementLookup::Unavailable { .. },
                    ) => Some(expected_validation_revision_id.to_string()),
                    Err(_) => None,
                };
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref,
            });
        }
        let selection = match select_support_replacement(&snapshot, expected_validation_revision_id)
            .map_err(|error| match error {
                crate::semantic::SemanticServiceError::InvalidInput => {
                    HumanGovernanceError::InvalidInput
                }
                _ => HumanGovernanceError::Store,
            })? {
            SupportReplacementLookup::Available(selection) => selection,
            SupportReplacementLookup::Conflict {
                current_revision_id,
            } => {
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: Some(current_revision_id.to_string()),
                });
            }
            SupportReplacementLookup::Unavailable { reason } => {
                return Ok(HumanActionOutcome::Unavailable { reason });
            }
        };
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let edited_for_retry = edited_payload.clone();
        match compose_support_replacement(
            &view,
            command_context(request_id, self.effective_config_hash)?,
            &selection,
            edited_payload,
        )
        .map_err(|_| HumanGovernanceError::InvalidInput)?
        {
            ProposalResolution::NoDelta => {
                let validation_ref = expected_validation_revision_id.to_string();
                let mut matches = view.proposals.values().filter(|proposal| {
                    proposal.target_kind == selection.target_kind
                        && proposal.target_id == Some(selection.target_id)
                        && proposal.base_revision_id == Some(selection.base_revision_id)
                        && proposal.operation == ProposalOperation::Replace
                        && proposal.payload == edited_for_retry
                        && proposal.evidence_refs.len() == 1
                        && proposal.evidence_refs[0] == validation_ref
                        && proposal.source_cohort_refs == proposal.evidence_refs
                        && proposal.eligibility == ProposalEligibility::ManualRequired
                        && proposal.created_by == ProposalCreatedBy::User
                });
                let proposal = matches.next().ok_or(HumanGovernanceError::Store)?;
                if matches.next().is_some() {
                    return Err(HumanGovernanceError::Store);
                }
                Ok(HumanActionOutcome::NoDelta {
                    current_revision_ref: proposal.proposal_revision_id.to_string(),
                })
            }
            ProposalResolution::Revision { value, command } => {
                let revision = value.proposal_revision_id.to_string();
                let mut audit_ordinals =
                    command
                        .events()
                        .iter()
                        .enumerate()
                        .filter_map(|(ordinal, event)| {
                            matches!(
                                &event.payload,
                                JournalPayload::RevisionProposalRecorded(proposal)
                                    if proposal.proposal_id == value.proposal_id
                                        && proposal.proposal_revision_id
                                            == value.proposal_revision_id
                            )
                            .then_some(ordinal)
                        });
                let audit_ordinal = audit_ordinals.next().ok_or(HumanGovernanceError::Store)?;
                if audit_ordinals.next().is_some() {
                    return Err(HumanGovernanceError::Store);
                }
                let outcome = match self
                    .writer
                    .commit_if_frontier(command, now_us()?, snapshot.frontier)
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(crate::WriterActorError::StaleFrontier) => {
                        let latest = self
                            .writer
                            .project()
                            .await
                            .map_err(|_| HumanGovernanceError::Store)?;
                        let current_revision_ref = match select_support_replacement(
                            &latest,
                            expected_validation_revision_id,
                        ) {
                            Ok(SupportReplacementLookup::Conflict {
                                current_revision_id,
                            }) => Some(current_revision_id.to_string()),
                            Ok(
                                SupportReplacementLookup::Available(_)
                                | SupportReplacementLookup::Unavailable { .. },
                            ) => Some(expected_validation_revision_id.to_string()),
                            Err(_) => None,
                        };
                        return Ok(HumanActionOutcome::Conflict {
                            current_revision_ref,
                        });
                    }
                    Err(_) => return Err(HumanGovernanceError::Store),
                };
                let audit_event_ref = outcome
                    .event_ids
                    .get(audit_ordinal)
                    .cloned()
                    .ok_or(HumanGovernanceError::Store)?;
                Ok(HumanActionOutcome::Applied {
                    current_revision_ref: revision,
                    audit_event_ref,
                })
            }
        }
    }

    pub async fn submit_support_deprecate(
        &self,
        request_id: RequestId,
        expected_frontier: u64,
        expected_validation_revision_id: RevisionId,
        reason: String,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let command_id = CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if let Some(committed) = self
            .writer
            .committed_command(command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
        {
            let validation_ref = expected_validation_revision_id.to_string();
            let mut matches = committed.payloads.iter().enumerate().filter_map(
                |(ordinal, payload)| match payload {
                    JournalPayload::RevisionProposalRecorded(proposal)
                        if proposal.parent_proposal_revision_id.is_none()
                            && proposal.status == ProposalStatus::Pending
                            && proposal.operation == ProposalOperation::Deprecate
                            && matches!(
                                &proposal.payload,
                                ProposalPayload::Atom(payload)
                                    if matches!(
                                        payload.as_ref(),
                                        AtomProposalPayload::Deprecate { reason: value }
                                            if value == &reason
                                    )
                            )
                            && proposal.evidence_refs == [validation_ref.clone()]
                            && proposal.source_cohort_refs == proposal.evidence_refs
                            && proposal.eligibility == ProposalEligibility::ManualRequired
                            && proposal.created_by == ProposalCreatedBy::User =>
                    {
                        Some((ordinal, proposal.proposal_revision_id))
                    }
                    _ => None,
                },
            );
            let (ordinal, revision_id) = matches.next().ok_or(HumanGovernanceError::Store)?;
            if matches.next().is_some() || committed.payloads.len() != 1 {
                return Err(HumanGovernanceError::Store);
            }
            let audit_event_ref = committed
                .event_ids
                .get(ordinal)
                .cloned()
                .ok_or(HumanGovernanceError::Store)?;
            return Ok(HumanActionOutcome::Applied {
                current_revision_ref: revision_id.to_string(),
                audit_event_ref,
            });
        }

        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier != expected_frontier {
            let current_revision_ref =
                match select_support_deprecate(&snapshot, expected_validation_revision_id) {
                    Ok(SupportDeprecateLookup::Conflict {
                        current_revision_id,
                    }) => Some(current_revision_id.to_string()),
                    Ok(
                        SupportDeprecateLookup::Available(_)
                        | SupportDeprecateLookup::Unavailable { .. },
                    ) => Some(expected_validation_revision_id.to_string()),
                    Err(_) => None,
                };
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref,
            });
        }
        let selection = match select_support_deprecate(&snapshot, expected_validation_revision_id)
            .map_err(|error| match error {
            crate::semantic::SemanticServiceError::InvalidInput => {
                HumanGovernanceError::InvalidInput
            }
            _ => HumanGovernanceError::Store,
        })? {
            SupportDeprecateLookup::Available(selection) => selection,
            SupportDeprecateLookup::Conflict {
                current_revision_id,
            } => {
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: Some(current_revision_id.to_string()),
                });
            }
            SupportDeprecateLookup::Unavailable { reason } => {
                return Ok(HumanActionOutcome::Unavailable { reason });
            }
        };
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        match compose_support_deprecate(
            &view,
            command_context(request_id, self.effective_config_hash)?,
            &selection,
            reason.clone(),
        )
        .map_err(|_| HumanGovernanceError::InvalidInput)?
        {
            ProposalResolution::NoDelta => {
                let validation_ref = expected_validation_revision_id.to_string();
                let mut matches = view.proposals.values().filter(|proposal| {
                    proposal.target_kind == ProposalTargetKind::Atom
                        && proposal.target_id == Some(ProposalTargetId::Atom(selection.atom_id))
                        && proposal.base_revision_id == Some(selection.base_revision_id)
                        && proposal.operation == ProposalOperation::Deprecate
                        && matches!(
                            &proposal.payload,
                            ProposalPayload::Atom(payload)
                                if matches!(
                                    payload.as_ref(),
                                    AtomProposalPayload::Deprecate { reason: value }
                                        if value == &reason
                                )
                        )
                        && proposal.evidence_refs == [validation_ref.clone()]
                        && proposal.source_cohort_refs == proposal.evidence_refs
                        && proposal.eligibility == ProposalEligibility::ManualRequired
                        && proposal.created_by == ProposalCreatedBy::User
                });
                let proposal = matches.next().ok_or(HumanGovernanceError::Store)?;
                if matches.next().is_some() {
                    return Err(HumanGovernanceError::Store);
                }
                Ok(HumanActionOutcome::NoDelta {
                    current_revision_ref: proposal.proposal_revision_id.to_string(),
                })
            }
            ProposalResolution::Revision { value, command } => {
                let mut audit_ordinals =
                    command
                        .events()
                        .iter()
                        .enumerate()
                        .filter_map(|(ordinal, event)| {
                            matches!(
                            &event.payload,
                            JournalPayload::RevisionProposalRecorded(proposal)
                                if proposal.proposal_id == value.proposal_id
                                    && proposal.proposal_revision_id == value.proposal_revision_id
                        )
                        .then_some(ordinal)
                        });
                let audit_ordinal = audit_ordinals.next().ok_or(HumanGovernanceError::Store)?;
                if audit_ordinals.next().is_some() {
                    return Err(HumanGovernanceError::Store);
                }
                let outcome = match self
                    .writer
                    .commit_if_frontier(command, now_us()?, snapshot.frontier)
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(crate::WriterActorError::StaleFrontier) => {
                        let latest = self
                            .writer
                            .project()
                            .await
                            .map_err(|_| HumanGovernanceError::Store)?;
                        let current_revision_ref = match select_support_deprecate(
                            &latest,
                            expected_validation_revision_id,
                        ) {
                            Ok(SupportDeprecateLookup::Conflict {
                                current_revision_id,
                            }) => Some(current_revision_id.to_string()),
                            Ok(
                                SupportDeprecateLookup::Available(_)
                                | SupportDeprecateLookup::Unavailable { .. },
                            ) => Some(expected_validation_revision_id.to_string()),
                            Err(_) => None,
                        };
                        return Ok(HumanActionOutcome::Conflict {
                            current_revision_ref,
                        });
                    }
                    Err(_) => return Err(HumanGovernanceError::Store),
                };
                Ok(HumanActionOutcome::Applied {
                    current_revision_ref: value.proposal_revision_id.to_string(),
                    audit_event_ref: outcome
                        .event_ids
                        .get(audit_ordinal)
                        .cloned()
                        .ok_or(HumanGovernanceError::Store)?,
                })
            }
        }
    }

    pub async fn resolve_competing_selected(
        &self,
        request_id: RequestId,
        expected_frontier: u64,
        expected_group_revision_id: RevisionId,
        chosen_attempt_id: AttemptId,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let command_id = CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if let Some(committed) = self
            .writer
            .committed_command(command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
        {
            if committed.payloads.len() != 1 {
                return Err(HumanGovernanceError::Store);
            }
            let mut matches = committed.payloads.iter().enumerate().filter_map(
                |(ordinal, payload)| match payload {
                    JournalPayload::CompetingAttemptGroupRecorded(group)
                        if group.predecessor_revision_id == Some(expected_group_revision_id)
                            && group.resolution_status == CompetingResolutionStatus::Selected
                            && group.selected_attempt_id == Some(chosen_attempt_id) =>
                    {
                        Some((ordinal, group.revision_id))
                    }
                    _ => None,
                },
            );
            let (ordinal, revision_id) = matches.next().ok_or(HumanGovernanceError::Store)?;
            if matches.next().is_some() {
                return Err(HumanGovernanceError::Store);
            }
            let audit_event_ref = committed
                .event_ids
                .get(ordinal)
                .cloned()
                .ok_or(HumanGovernanceError::Store)?;
            return Ok(HumanActionOutcome::Applied {
                current_revision_ref: revision_id.to_string(),
                audit_event_ref,
            });
        }

        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier != expected_frontier {
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref: current_competing_revision(
                    &snapshot,
                    expected_group_revision_id,
                ),
            });
        }
        let resolution = resolve_competing_selected(
            work_command_context(request_id, self.effective_config_hash)?,
            &snapshot,
            expected_group_revision_id,
            chosen_attempt_id,
        )
        .map_err(|error| match error {
            crate::work::WorkIdentityError::InvalidInput
            | crate::work::WorkIdentityError::Conflict
            | crate::work::WorkIdentityError::ScopeUnresolved => HumanGovernanceError::InvalidInput,
            crate::work::WorkIdentityError::Store(_) => HumanGovernanceError::Store,
        })?;
        let (group, command) = match resolution {
            CompetingSelectedResolution::Revision { group, command } => (group, command),
            CompetingSelectedResolution::Conflict {
                current_revision_id,
            } => {
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: Some(current_revision_id.to_string()),
                });
            }
            CompetingSelectedResolution::Unavailable { reason } => {
                return Ok(HumanActionOutcome::Unavailable { reason });
            }
        };
        let mut audit_ordinals =
            command
                .events()
                .iter()
                .enumerate()
                .filter_map(|(ordinal, event)| {
                    matches!(
                        &event.payload,
                        JournalPayload::CompetingAttemptGroupRecorded(value)
                            if value.competing_group_id == group.competing_group_id
                                && value.revision_id == group.revision_id
                    )
                    .then_some(ordinal)
                });
        let audit_ordinal = audit_ordinals.next().ok_or(HumanGovernanceError::Store)?;
        if audit_ordinals.next().is_some() {
            return Err(HumanGovernanceError::Store);
        }
        let outcome = match self
            .writer
            .commit_if_frontier(command, now_us()?, snapshot.frontier)
            .await
        {
            Ok(outcome) => outcome,
            Err(crate::WriterActorError::StaleFrontier) => {
                let latest = self
                    .writer
                    .project()
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?;
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: current_competing_revision(
                        &latest,
                        expected_group_revision_id,
                    ),
                });
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        };
        let audit_event_ref = outcome
            .event_ids
            .get(audit_ordinal)
            .cloned()
            .ok_or(HumanGovernanceError::Store)?;
        Ok(HumanActionOutcome::Applied {
            current_revision_ref: group.revision_id.to_string(),
            audit_event_ref,
        })
    }

    pub async fn mark_new_attempt(
        &self,
        request_id: RequestId,
        expected_frontier: u64,
        expected_attempt_revision_id: RevisionId,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let command_id = CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if let Some(committed) = self
            .writer
            .committed_command(command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
        {
            if committed.payloads.len() != 1 {
                return Err(HumanGovernanceError::Store);
            }
            let (ordinal, child) = committed
                .payloads
                .iter()
                .enumerate()
                .find_map(|(ordinal, payload)| match payload {
                    JournalPayload::AttemptRecorded(child)
                        if child.revision_generation == 1
                            && child.predecessor_revision_id.is_none()
                            && child.resume_state_assessment
                                == Some(evertrace_domain::work::ResumeStateAssessment::Unknown)
                            && child.resume_event_refs
                                == [expected_attempt_revision_id.to_string()] =>
                    {
                        Some((ordinal, child))
                    }
                    _ => None,
                })
                .ok_or(HumanGovernanceError::Store)?;
            let audit_event_ref = committed
                .event_ids
                .get(ordinal)
                .cloned()
                .ok_or(HumanGovernanceError::Store)?;
            return Ok(HumanActionOutcome::Applied {
                current_revision_ref: child.revision_id.to_string(),
                audit_event_ref,
            });
        }

        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier != expected_frontier {
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref: current_attempt_revision(
                    &snapshot,
                    expected_attempt_revision_id,
                ),
            });
        }
        let resolution = mark_new_attempt(
            work_command_context(request_id, self.effective_config_hash)?,
            &snapshot,
            expected_attempt_revision_id,
        )
        .map_err(|error| match error {
            crate::work::WorkIdentityError::InvalidInput
            | crate::work::WorkIdentityError::Conflict
            | crate::work::WorkIdentityError::ScopeUnresolved => HumanGovernanceError::InvalidInput,
            crate::work::WorkIdentityError::Store(_) => HumanGovernanceError::Store,
        })?;
        let (child, command) = match resolution {
            MarkNewAttemptResolution::Revision { child, command } => (child, command),
            MarkNewAttemptResolution::Conflict {
                current_revision_id,
            } => {
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: Some(current_revision_id.to_string()),
                });
            }
            MarkNewAttemptResolution::NoDelta {
                current_revision_id,
            } => {
                return Ok(HumanActionOutcome::NoDelta {
                    current_revision_ref: current_revision_id.to_string(),
                });
            }
            MarkNewAttemptResolution::Unavailable { reason } => {
                return Ok(HumanActionOutcome::Unavailable { reason });
            }
        };
        let mut audit_ordinals =
            command
                .events()
                .iter()
                .enumerate()
                .filter_map(|(ordinal, event)| {
                    matches!(
                        &event.payload,
                        JournalPayload::AttemptRecorded(value)
                            if value.attempt_id == child.attempt_id
                                && value.revision_id == child.revision_id
                    )
                    .then_some(ordinal)
                });
        let audit_ordinal = audit_ordinals.next().ok_or(HumanGovernanceError::Store)?;
        if audit_ordinals.next().is_some() {
            return Err(HumanGovernanceError::Store);
        }
        let outcome = match self
            .writer
            .commit_if_frontier(command, now_us()?, snapshot.frontier)
            .await
        {
            Ok(outcome) => outcome,
            Err(crate::WriterActorError::StaleFrontier) => {
                let latest = self
                    .writer
                    .project()
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?;
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: current_attempt_revision(
                        &latest,
                        expected_attempt_revision_id,
                    ),
                });
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        };
        Ok(HumanActionOutcome::Applied {
            current_revision_ref: child.revision_id.to_string(),
            audit_event_ref: outcome
                .event_ids
                .get(audit_ordinal)
                .cloned()
                .ok_or(HumanGovernanceError::Store)?,
        })
    }

    pub async fn forget_object(
        &self,
        request_id: RequestId,
        expected_frontier: u64,
        target: ObjectDeletionTarget,
        expected_revision_ids: Vec<RevisionId>,
        expected_deletion_generation: u64,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let command_id = CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if let Some(committed) = self
            .writer
            .committed_command(command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
        {
            let matches = committed
                .payloads
                .iter()
                .enumerate()
                .filter_map(|(ordinal, payload)| match payload {
                    JournalPayload::ObjectDeletionLedgerRecorded(event)
                        if event.phase == evertrace_domain::purge::ObjectDeletionPhase::Pending
                            && event.target == target
                            && event.exact_revision_ids == expected_revision_ids
                            && event.deletion_generation == expected_deletion_generation =>
                    {
                        Some((ordinal, event))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            let [(ordinal, event)] = matches.as_slice() else {
                return Err(HumanGovernanceError::Store);
            };
            return Ok(HumanActionOutcome::Applied {
                current_revision_ref: deletion_revision_ref(event),
                audit_event_ref: committed
                    .event_ids
                    .get(*ordinal)
                    .cloned()
                    .ok_or(HumanGovernanceError::Store)?,
            });
        }
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier != expected_frontier {
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref: current_object_deletion_revision(&snapshot, target),
            });
        }
        let preview = match select_object_forget(&snapshot, target)
            .map_err(|_| HumanGovernanceError::Store)?
        {
            ObjectForgetLookup::Available(preview) => preview,
            ObjectForgetLookup::NoDelta(event) => {
                return Ok(HumanActionOutcome::NoDelta {
                    current_revision_ref: deletion_revision_ref(&event),
                });
            }
            ObjectForgetLookup::Unavailable => {
                return Ok(HumanActionOutcome::Unavailable {
                    reason: "object_forget_unavailable",
                });
            }
        };
        if preview.exact_revision_ids != expected_revision_ids
            || preview.deletion_generation != expected_deletion_generation
        {
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref: Some(preview.current_revision_id.to_string()),
            });
        }
        let occurred_at_us = now_us()?;
        let command = pending_object_forget_command(
            request_id,
            &preview,
            &expected_revision_ids,
            expected_deletion_generation,
            occurred_at_us,
            snapshot.frontier,
            self.effective_config_hash,
        )
        .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let ordinals = command
            .events()
            .iter()
            .enumerate()
            .filter_map(|(ordinal, event)| {
                matches!(
                    &event.payload,
                    JournalPayload::ObjectDeletionLedgerRecorded(value)
                        if value.target == target
                            && value.phase
                                == evertrace_domain::purge::ObjectDeletionPhase::Pending
                )
                .then_some(ordinal)
            })
            .collect::<Vec<_>>();
        let [audit_ordinal] = ordinals.as_slice() else {
            return Err(HumanGovernanceError::Store);
        };
        let outcome = match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(outcome) => outcome,
            Err(crate::WriterActorError::StaleFrontier) => {
                let latest = self
                    .writer
                    .project()
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?;
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: current_object_deletion_revision(&latest, target),
                });
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        };
        let audit_event_ref = outcome
            .event_ids
            .get(*audit_ordinal)
            .cloned()
            .ok_or(HumanGovernanceError::Store)?;
        Ok(HumanActionOutcome::Applied {
            current_revision_ref: format!("deletion-generation-{expected_deletion_generation}"),
            audit_event_ref,
        })
    }

    pub async fn purge_repository(
        &self,
        request_id: RequestId,
        expected_frontier: u64,
        repository_id: RepositoryId,
        repository_confirmation: &str,
        expected_repository_revision: u32,
        expected_deletion_generation: u64,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        if repository_confirmation.parse::<RepositoryId>().ok() != Some(repository_id) {
            return Err(HumanGovernanceError::InvalidInput);
        }
        let command_id = CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if let Some(committed) = self
            .writer
            .committed_command(command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
        {
            let matches = committed
                .payloads
                .iter()
                .enumerate()
                .filter_map(|(ordinal, payload)| match payload {
                    JournalPayload::ScopePurgeProgressRecorded(progress)
                        if progress.stage == evertrace_domain::purge::ScopePurgeStage::Pending
                            && progress.target.repository_id() == repository_id
                            && progress.target.repository_revision()
                                == expected_repository_revision
                            && progress.confirmation_frontier == expected_frontier
                            && progress.deletion_generation == expected_deletion_generation =>
                    {
                        Some((ordinal, progress))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            let [(ordinal, progress)] = matches.as_slice() else {
                return Err(HumanGovernanceError::Store);
            };
            return Ok(HumanActionOutcome::Applied {
                current_revision_ref: scope_purge_revision_ref(progress),
                audit_event_ref: committed
                    .event_ids
                    .get(*ordinal)
                    .cloned()
                    .ok_or(HumanGovernanceError::Store)?,
            });
        }
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier != expected_frontier {
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref: current_repository_purge_revision(&snapshot, repository_id),
            });
        }
        let preview =
            match select_repository_purge(&snapshot, repository_id, expected_repository_revision)
                .map_err(|_| HumanGovernanceError::Store)?
            {
                RepositoryPurgeLookup::Available(preview) => preview,
                RepositoryPurgeLookup::NoDelta(progress) => {
                    return Ok(HumanActionOutcome::NoDelta {
                        current_revision_ref: scope_purge_revision_ref(&progress),
                    });
                }
                RepositoryPurgeLookup::Unavailable => {
                    return Ok(HumanActionOutcome::Unavailable {
                        reason: "repository_purge_unavailable",
                    });
                }
            };
        if preview.deletion_generation != expected_deletion_generation
            || preview.target.repository_revision() != expected_repository_revision
        {
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref: Some(expected_repository_revision.to_string()),
            });
        }
        if !preview.permits_pending() {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "repository_purge_cross_scope_dependency_blocked",
            });
        }
        let occurred_at_us = now_us()?;
        let command = pending_repository_purge_command(
            request_id,
            &preview,
            expected_deletion_generation,
            occurred_at_us,
            snapshot.frontier,
            self.effective_config_hash,
        )
        .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let ordinals = command
            .events()
            .iter()
            .enumerate()
            .filter_map(|(ordinal, event)| {
                matches!(
                    &event.payload,
                    JournalPayload::ScopePurgeProgressRecorded(value)
                        if value.stage == evertrace_domain::purge::ScopePurgeStage::Pending
                            && value.target.repository_id() == repository_id
                )
                .then_some(ordinal)
            })
            .collect::<Vec<_>>();
        let [audit_ordinal] = ordinals.as_slice() else {
            return Err(HumanGovernanceError::Store);
        };
        let outcome = match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(outcome) => outcome,
            Err(crate::WriterActorError::StaleFrontier) => {
                let latest = self
                    .writer
                    .project()
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?;
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: current_repository_purge_revision(&latest, repository_id),
                });
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        };
        Ok(HumanActionOutcome::Applied {
            current_revision_ref: format!(
                "repository-purge-generation-{expected_deletion_generation}"
            ),
            audit_event_ref: outcome
                .event_ids
                .get(*audit_ordinal)
                .cloned()
                .ok_or(HumanGovernanceError::Store)?,
        })
    }

    pub async fn review_negative(
        &self,
        request_id: RequestId,
        expected_frontier: u64,
        negative_evidence_id: ProcedureNegativeEvidenceId,
        expected_review_revision_id: RevisionId,
        decision: HumanNegativeDecision,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier != expected_frontier {
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref: current_negative_review_revision(
                    &snapshot,
                    negative_evidence_id,
                ),
            });
        }
        let current_revision = current_negative_review_revision(&snapshot, negative_evidence_id);
        if current_revision.as_deref() != Some(&expected_review_revision_id.to_string()) {
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref: current_revision,
            });
        }
        let view = ProcedureUsageCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let selection = view
            .select_negative_review(negative_evidence_id)
            .map_err(|_| HumanGovernanceError::Store)?;
        let proof_decision = match decision {
            HumanNegativeDecision::ResolveAsIneffective => {
                ProcedureNegativeReviewDecision::ResolveAsIneffective
            }
            HumanNegativeDecision::DismissAttribution => {
                ProcedureNegativeReviewDecision::DismissAttribution
            }
            HumanNegativeDecision::ConfirmHarm => ProcedureNegativeReviewDecision::ConfirmHarm,
            HumanNegativeDecision::RequestRevision => {
                ProcedureNegativeReviewDecision::RequestRevision
            }
        };
        let Some(proof) = selection.proof(proof_decision) else {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "negative_review_proof_unavailable",
            });
        };
        if decision == HumanNegativeDecision::RequestRevision {
            let semantic_view = SemanticCurrentView::from_snapshot(&snapshot)
                .map_err(|_| HumanGovernanceError::Store)?;
            return match request_procedure_revision(
                &view,
                &semantic_view,
                command_context(request_id, self.effective_config_hash)?,
                negative_evidence_id,
                proof,
            )
            .map_err(|_| HumanGovernanceError::Store)?
            {
                ProcedureRevisionRequestResolution::NoDelta { proposal } => {
                    Ok(HumanActionOutcome::NoDelta {
                        current_revision_ref: proposal.proposal_revision_id.to_string(),
                    })
                }
                ProcedureRevisionRequestResolution::Command { proposal, command } => {
                    let proposal_ordinals = command
                        .events()
                        .iter()
                        .enumerate()
                        .filter_map(|(ordinal, event)| {
                            matches!(
                                &event.payload,
                                JournalPayload::RevisionProposalRecorded(value)
                                    if value.proposal_id == proposal.proposal_id
                                        && value.proposal_revision_id
                                            == proposal.proposal_revision_id
                            )
                            .then_some(ordinal)
                        })
                        .collect::<Vec<_>>();
                    let [proposal_ordinal] = proposal_ordinals.as_slice() else {
                        return Err(HumanGovernanceError::Store);
                    };
                    let outcome = match self
                        .writer
                        .commit_if_frontier(command, now_us()?, snapshot.frontier)
                        .await
                    {
                        Ok(outcome) => outcome,
                        Err(crate::WriterActorError::StaleFrontier) => {
                            let latest = self
                                .writer
                                .project()
                                .await
                                .map_err(|_| HumanGovernanceError::Store)?;
                            return Ok(HumanActionOutcome::Conflict {
                                current_revision_ref: current_negative_review_revision(
                                    &latest,
                                    negative_evidence_id,
                                ),
                            });
                        }
                        Err(_) => return Err(HumanGovernanceError::Store),
                    };
                    let audit_event_ref = outcome
                        .event_ids
                        .get(*proposal_ordinal)
                        .cloned()
                        .ok_or(HumanGovernanceError::Store)?;
                    Ok(HumanActionOutcome::Applied {
                        current_revision_ref: proposal.proposal_revision_id.to_string(),
                        audit_event_ref,
                    })
                }
            };
        }
        let command = review_procedure_negative(
            &view,
            command_context(request_id, self.effective_config_hash)?,
            negative_evidence_id,
            proof,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let review_ordinals = command
            .events()
            .iter()
            .enumerate()
            .filter_map(|(ordinal, event)| {
                matches!(
                    &event.payload,
                    JournalPayload::ProcedureNegativeReviewRecorded(review)
                        if review.negative_evidence_id == negative_evidence_id
                )
                .then_some(ordinal)
            })
            .collect::<Vec<_>>();
        let [review_ordinal] = review_ordinals.as_slice() else {
            return Err(HumanGovernanceError::Store);
        };
        let outcome = match self
            .writer
            .commit_if_frontier(command, now_us()?, snapshot.frontier)
            .await
        {
            Ok(outcome) => outcome,
            Err(crate::WriterActorError::StaleFrontier) => {
                let latest = self
                    .writer
                    .project()
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?;
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: current_negative_review_revision(
                        &latest,
                        negative_evidence_id,
                    ),
                });
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        };
        let audit = outcome
            .event_ids
            .get(*review_ordinal)
            .cloned()
            .ok_or(HumanGovernanceError::Store)?;
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let revision = current_negative_review_revision(&projected, negative_evidence_id)
            .ok_or(HumanGovernanceError::Store)?;
        Ok(HumanActionOutcome::Applied {
            current_revision_ref: revision,
            audit_event_ref: audit,
        })
    }
}

fn page(
    snapshot: &ProjectionSnapshot,
    surface: HumanSurface,
    after: Option<&str>,
    limit: usize,
) -> Result<HumanPage, HumanGovernanceError> {
    let (status, degraded_reasons) = snapshot_status(snapshot)?;
    let semantic_view =
        SemanticCurrentView::from_snapshot(snapshot).map_err(|_| HumanGovernanceError::Store)?;
    let usage_view = ProcedureUsageCurrentView::from_snapshot(snapshot)
        .map_err(|_| HumanGovernanceError::Store)?;
    let mut rows = surface_rows(snapshot, surface)?;
    rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    let mut selected = rows
        .into_iter()
        .filter(|row| after.is_none_or(|cursor| row.row_id.as_str() > cursor))
        .take(limit + 1)
        .collect::<Vec<_>>();
    let next_cursor = (selected.len() > limit).then(|| selected[limit - 1].row_id.clone());
    selected.truncate(limit);
    Ok(HumanPage {
        frontier: snapshot.frontier,
        status,
        degraded_reasons,
        items: selected
            .into_iter()
            .map(|row| {
                summary(
                    snapshot,
                    row,
                    &semantic_view,
                    &usage_view,
                    None,
                    surface,
                    false,
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
        next_cursor,
    })
}

fn snapshot_status(
    snapshot: &ProjectionSnapshot,
) -> Result<(HumanSnapshotStatus, Vec<HumanDegradedReason>), HumanGovernanceError> {
    let degraded = RuntimeSchedulerView::from_snapshot(snapshot)
        .map_err(|_| HumanGovernanceError::Store)?
        .jobs
        .iter()
        .any(|job| job.state == JobStatus::Failed);
    Ok(if degraded {
        (
            HumanSnapshotStatus::Degraded,
            vec![HumanDegradedReason::CurrentJobFailed],
        )
    } else {
        (HumanSnapshotStatus::Ready, Vec::new())
    })
}

fn surface_rows(
    snapshot: &ProjectionSnapshot,
    surface: HumanSurface,
) -> Result<Vec<&ObjectRow>, HumanGovernanceError> {
    if surface == HumanSurface::Inbox {
        let actionable = actionable_inbox_rows(snapshot)?;
        return Ok(snapshot
            .data_rows()
            .filter(|row| actionable.contains(&row.row_id))
            .collect());
    }
    Ok(snapshot
        .data_rows()
        .filter(|row| surface_matches(surface, row))
        .collect())
}

fn surface_matches(surface: HumanSurface, row: &ObjectRow) -> bool {
    if row.row_kind != ObjectRowKind::Data {
        return false;
    }
    let kind = row.object_kind.as_deref().unwrap_or_default();
    match surface {
        HumanSurface::Inbox => false,
        HumanSurface::Explorer => row.row_class != Some(ObjectRowClass::Runtime),
        HumanSurface::System => {
            row.row_class == Some(ObjectRowClass::Runtime)
                || matches!(kind, "session_import_current" | "semantic_derivation_run")
        }
    }
}

fn actionable_inbox_rows(
    snapshot: &ProjectionSnapshot,
) -> Result<BTreeSet<String>, HumanGovernanceError> {
    let proposals = SemanticCurrentView::from_snapshot(snapshot)
        .map_err(|_| HumanGovernanceError::Store)?
        .proposals;
    let mut selected = BTreeMap::<String, (u64, String, bool)>::new();
    let mut direct = BTreeSet::new();
    let mut resumed_source_ids = BTreeSet::new();
    for row in snapshot.data_rows() {
        let Some(kind) = row.object_kind.as_deref() else {
            continue;
        };
        if !matches!(
            kind,
            "revision_proposal_revision"
                | "global_support_validation"
                | "procedure_negative_evidence"
                | "procedure_negative_review"
                | "procedure_state_event"
                | "work_episode"
                | "work_binding"
                | "competing_attempt_group"
                | "attempt"
                | "execution_lane"
                | "capture_receipt"
                | "worktree_transition"
                | "recovery_capture_request_revision"
        ) {
            continue;
        }
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        payload
            .validate()
            .map_err(|_| HumanGovernanceError::Store)?;
        match payload {
            JournalPayload::RevisionProposalRecorded(value) => {
                let current = proposals.get(&value.proposal_id);
                if current.is_some_and(|proposal| {
                    proposal.proposal_revision_id == value.proposal_revision_id
                        && matches!(
                            proposal.status,
                            ProposalStatus::Pending
                                | ProposalStatus::Validating
                                | ProposalStatus::Deferred
                        )
                }) {
                    direct.insert(row.row_id.clone());
                }
            }
            JournalPayload::GlobalSupportValidationRecorded(value) => select_current(
                &mut selected,
                format!("support:{}", value.support_contract_ref),
                row.source_event_seq,
                row,
                matches!(
                    value.state,
                    GlobalSupportState::RevalidationPending
                        | GlobalSupportState::Insufficient
                        | GlobalSupportState::Invalidated
                ),
            )?,
            JournalPayload::ProcedureNegativeEvidenceRecorded(_) => {}
            JournalPayload::ProcedureNegativeReviewRecorded(value) => select_current(
                &mut selected,
                format!("negative:{}", value.negative_evidence_id),
                u64::from(value.review_generation),
                row,
                matches!(
                    value.status,
                    ProcedureNegativeReviewStatus::Pending | ProcedureNegativeReviewStatus::Upheld
                ),
            )?,
            JournalPayload::ProcedureStateRecorded(value) => select_current(
                &mut selected,
                format!("publication:{}", value.procedure_revision_id),
                row.source_event_seq,
                row,
                value.to_state == ProcedurePublicationState::ReviewHold,
            )?,
            JournalPayload::WorkEpisodeRecorded(value) => select_current(
                &mut selected,
                format!("episode:{}", value.episode_id),
                value.revision_generation,
                row,
                boundary_candidate_actionable(value.boundary_status),
            )?,
            JournalPayload::WorkBindingRecorded(value) => select_current(
                &mut selected,
                format!("binding:{}", value.operation_id),
                value.revision_generation,
                row,
                value.assignment_status != AssignmentStatus::Resolved,
            )?,
            JournalPayload::CompetingAttemptGroupRecorded(value) => select_current(
                &mut selected,
                format!("competing:{}", value.competing_group_id),
                value.revision_generation,
                row,
                matches!(
                    value.resolution_status,
                    CompetingResolutionStatus::Open | CompetingResolutionStatus::Unresolved
                ),
            )?,
            JournalPayload::AttemptRecorded(value) => {
                if value.revision_generation == 1
                    && value.predecessor_revision_id.is_none()
                    && let Some(source_id) = value.resumes_from_attempt_id
                {
                    resumed_source_ids.insert(source_id);
                }
                select_current(
                    &mut selected,
                    format!("attempt:{}", value.attempt_id),
                    value.revision_generation,
                    row,
                    value.lifecycle_status == AttemptLifecycleStatus::Active
                        && value.execution_status == AttemptExecutionStatus::Interrupted,
                )?;
            }
            JournalPayload::ExecutionLaneRecorded(value) => select_current(
                &mut selected,
                format!("lane:{}", value.execution_lane_id),
                u64::from(value.lane_revision),
                row,
                lane_needs_review(&value),
            )?,
            JournalPayload::CaptureReceiptRecorded(value) if kind == "capture_receipt" => {
                select_current(
                    &mut selected,
                    format!("receipt:{}", value.execution_lane_id),
                    row.source_event_seq,
                    row,
                    receipt_needs_review(&value),
                )?;
            }
            JournalPayload::WorktreeTransitionRecorded(value) => select_current(
                &mut selected,
                format!("worktree-transition:{}", value.worktree_transition_id),
                u64::from(value.transition_revision),
                row,
                value.lineage_assessment != LineageAssessment::Proven,
            )?,
            JournalPayload::RecoveryCaptureRequestRecorded(value) => select_current(
                &mut selected,
                format!("recovery:{}", value.recovery_capture_request_id),
                row.source_event_seq,
                row,
                matches!(
                    value.request_status,
                    RecoveryRequestStatus::Pending | RecoveryRequestStatus::Partial
                ),
            )?,
            _ => return Err(HumanGovernanceError::Store),
        }
    }
    for source_id in resumed_source_ids {
        if let Some((_, _, actionable)) = selected.get_mut(&format!("attempt:{source_id}")) {
            *actionable = false;
        }
    }
    direct.extend(
        selected
            .into_values()
            .filter_map(|(_, row_id, actionable)| actionable.then_some(row_id)),
    );
    Ok(direct)
}

fn select_current(
    selected: &mut BTreeMap<String, (u64, String, bool)>,
    key: String,
    rank: u64,
    row: &ObjectRow,
    actionable: bool,
) -> Result<(), HumanGovernanceError> {
    match selected.get(&key) {
        Some((current_rank, current_row, _))
            if *current_rank == rank && current_row != &row.row_id =>
        {
            return Err(HumanGovernanceError::Store);
        }
        Some((current_rank, _, _)) if *current_rank > rank => return Ok(()),
        _ => {}
    }
    selected.insert(key, (rank, row.row_id.clone(), actionable));
    Ok(())
}

fn boundary_candidate_actionable(status: BoundaryStatus) -> bool {
    status == BoundaryStatus::Candidate
}

fn lane_needs_review(lane: &evertrace_domain::work::ExecutionLane) -> bool {
    matches!(
        lane.status,
        LaneStatus::Unresolved | LaneStatus::InterruptedUnconfirmed
    ) || lane.liveness_state == LivenessState::Unknown
        || lane.coverage_level != CoverageLevel::Full
        || matches!(
            lane.source_coverage,
            SourceCoverage::Partial | SourceCoverage::Unavailable
        )
        || lane.pairing_integrity != PairingIntegrity::Complete
        || lane.payload_integrity != PayloadIntegrity::Complete
        || lane.ordering_integrity != OrderingIntegrity::Complete
}

fn receipt_needs_review(receipt: &evertrace_domain::work::CaptureReceipt) -> bool {
    receipt.coverage_level != CoverageLevel::Full
        || matches!(
            receipt.source_coverage,
            SourceCoverage::Partial | SourceCoverage::Unavailable
        )
        || receipt.pairing_integrity != PairingIntegrity::Complete
        || receipt.payload_integrity != PayloadIntegrity::Complete
        || receipt.ordering_integrity != OrderingIntegrity::Complete
        || matches!(
            receipt.admission_failure_observability,
            AdmissionFailureObservability::BestEffort | AdmissionFailureObservability::Unavailable
        )
}

fn support_validation(
    row: &ObjectRow,
) -> Result<Option<GlobalSupportValidationEvent>, HumanGovernanceError> {
    if row.object_kind.as_deref() != Some("global_support_validation") {
        return Ok(None);
    }
    let payload: JournalPayload = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(HumanGovernanceError::Store)?,
    )
    .map_err(|_| HumanGovernanceError::Store)?;
    payload
        .validate()
        .map_err(|_| HumanGovernanceError::Store)?;
    let JournalPayload::GlobalSupportValidationRecorded(value) = payload else {
        return Err(HumanGovernanceError::Store);
    };
    if !support_object_row_matches(
        row,
        "global_support_validation",
        &value.support_contract_ref.to_string(),
        &value.validation_revision_id.to_string(),
        support_state_name(value.state),
    ) {
        return Err(HumanGovernanceError::Store);
    }
    Ok(Some(*value))
}

fn current_support_revision(
    snapshot: &ProjectionSnapshot,
    source: &ObjectRow,
) -> Result<Option<RevisionId>, HumanGovernanceError> {
    let Some(source) = support_validation(source)? else {
        return Ok(None);
    };
    let mut current = None::<(u64, String, RevisionId)>;
    for row in snapshot.data_rows() {
        let Some(candidate) = support_validation(row)? else {
            continue;
        };
        if candidate.support_contract_ref != source.support_contract_ref {
            continue;
        }
        match &current {
            Some((seq, current_row, _)) if *seq == row.source_event_seq => {
                if current_row != &row.row_id {
                    return Err(HumanGovernanceError::Store);
                }
            }
            Some((seq, _, _)) if *seq > row.source_event_seq => {}
            _ => {
                current = Some((
                    row.source_event_seq,
                    row.row_id.clone(),
                    candidate.validation_revision_id,
                ));
            }
        }
    }
    Ok(current.map(|(_, _, revision)| revision))
}

fn current_support_source(
    snapshot: &ProjectionSnapshot,
    source: &ObjectRow,
) -> Result<
    Option<(GlobalSupportValidationEvent, GlobalSuccessorSupportContract)>,
    HumanGovernanceError,
> {
    let Some(validation) = support_validation(source)? else {
        return Ok(None);
    };
    if current_support_revision(snapshot, source)? != Some(validation.validation_revision_id) {
        return Ok(None);
    }
    let mut contracts = snapshot.data_rows().filter_map(|row| {
        (row.object_kind.as_deref() == Some("global_support_contract"))
            .then_some(row)
            .filter(|row| {
                row.current_revision_id.as_deref()
                    == Some(validation.support_contract_ref.to_string().as_str())
            })
    });
    let row = contracts.next().ok_or(HumanGovernanceError::Store)?;
    if contracts.next().is_some() {
        return Err(HumanGovernanceError::Store);
    }
    let payload: JournalPayload = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(HumanGovernanceError::Store)?,
    )
    .map_err(|_| HumanGovernanceError::Store)?;
    payload
        .validate()
        .map_err(|_| HumanGovernanceError::Store)?;
    let JournalPayload::GlobalSupportContractRecorded(contract) = payload else {
        return Err(HumanGovernanceError::Store);
    };
    if !support_object_row_matches(
        row,
        "global_support_contract",
        &contract.support_contract_revision_id.to_string(),
        &contract.support_contract_revision_id.to_string(),
        "immutable",
    ) || contract.support_contract_revision_id != validation.support_contract_ref
        || contract.successor_revision_or_membership_ref != validation.successor_ref
    {
        return Err(HumanGovernanceError::Store);
    }
    Ok(Some((validation, *contract)))
}

fn support_object_row_matches(
    row: &ObjectRow,
    kind: &str,
    object_id: &str,
    revision_id: &str,
    lifecycle: &str,
) -> bool {
    row.row_kind == ObjectRowKind::Data
        && row.row_class == Some(ObjectRowClass::Object)
        && row.object_family == Some(ObjectFamily::Atom)
        && row.object_kind.as_deref() == Some(kind)
        && row.row_id == format!("object:atom:{kind}:{revision_id}")
        && row.object_id.as_deref() == Some(object_id)
        && row.current_revision_id.as_deref() == Some(revision_id)
        && row.lifecycle.as_deref() == Some(lifecycle)
        && row.epistemic.is_none()
        && row.authority.is_none()
        && row.publication_state.is_none()
        && row.support_state.is_none()
        && row.project_id.is_none()
        && row.repository_id.is_none()
        && row.worktree_id.is_none()
        && row.task_id.is_none()
        && row.workstream_id.is_none()
        && row.session_id.is_none()
        && row.source_event_seq > 0
}

fn support_state_name(state: GlobalSupportState) -> &'static str {
    match state {
        GlobalSupportState::Valid => "valid",
        GlobalSupportState::RevalidationPending => "revalidation_pending",
        GlobalSupportState::Insufficient => "insufficient",
        GlobalSupportState::Invalidated => "invalidated",
    }
}

fn related_rows<'a>(
    snapshot: &'a ProjectionSnapshot,
    refs: BTreeSet<String>,
    after: Option<&str>,
    limit: usize,
) -> Result<(Vec<&'a ObjectRow>, Option<String>), HumanGovernanceError> {
    let mut index = BTreeMap::<String, Option<&ObjectRow>>::new();
    for row in snapshot
        .data_rows()
        .filter(|row| surface_matches(HumanSurface::Explorer, row))
    {
        let keys = [
            Some(row.row_id.as_str()),
            row.object_id.as_deref(),
            row.current_revision_id.as_deref(),
        ];
        for key in keys.into_iter().flatten().collect::<BTreeSet<_>>() {
            index
                .entry(key.to_owned())
                .and_modify(|current| {
                    if current.is_some_and(|existing| existing.row_id != row.row_id) {
                        *current = None;
                    }
                })
                .or_insert(Some(row));
        }
    }
    let mut resolved = BTreeMap::<String, &ObjectRow>::new();
    for reference in refs {
        if let Some(Some(row)) = index.get(&reference) {
            resolved.insert(row.row_id.clone(), row);
        }
    }
    let mut selected = resolved
        .into_values()
        .filter(|row| after.is_none_or(|cursor| row.row_id.as_str() > cursor))
        .take(limit + 1)
        .collect::<Vec<_>>();
    let next_cursor =
        (selected.len() > limit).then(|| selected[limit.saturating_sub(1)].row_id.clone());
    selected.truncate(limit);
    Ok((selected, next_cursor))
}

fn support_dependency_refs(
    validation: &GlobalSupportValidationEvent,
    contract: &GlobalSuccessorSupportContract,
) -> BTreeSet<String> {
    contract
        .support_revision_refs
        .iter()
        .chain(&contract.authorization_revision_refs)
        .chain(&validation.surviving_support_refs)
        .chain(&validation.invalid_or_missing_refs)
        .map(ToString::to_string)
        .chain(validation.trigger_refs.iter().cloned())
        .collect()
}

fn summary(
    snapshot: &ProjectionSnapshot,
    row: &ObjectRow,
    semantic_view: &SemanticCurrentView,
    usage_view: &ProcedureUsageCurrentView,
    runtime_snapshot: Option<&RuntimeSnapshot>,
    surface: HumanSurface,
    include_detail: bool,
) -> Result<HumanSummary, HumanGovernanceError> {
    let deletion_admission = include_detail
        .then(|| ObjectDeletionCandidateAdmissionView::from_snapshot(snapshot))
        .transpose()
        .map_err(|_| HumanGovernanceError::Store)?;
    let proposal = (row.object_kind.as_deref() == Some("revision_proposal_revision"))
        .then_some(())
        .and_then(|()| row.object_id.as_deref()?.parse().ok())
        .and_then(|id| semantic_view.proposals.get(&id))
        .filter(|value| {
            row.object_id
                .as_deref()
                .is_some_and(|id| id == value.proposal_id.to_string())
                && row
                    .current_revision_id
                    .as_deref()
                    .is_some_and(|id| id == value.proposal_revision_id.to_string())
        })
        .map(|value| HumanProposalSummary {
            proposal_id: value.proposal_id,
            current_revision_id: value.proposal_revision_id,
            fingerprint: hex(&value.fingerprint),
            target_kind: value.target_kind,
            target_id: value.target_id,
            operation: value.operation,
            base_revision_id: value.base_revision_id,
            source_cohort_refs: value.source_cohort_refs.clone(),
            eligibility: value.eligibility,
            status: value.status,
        });
    let proposal_review = if include_detail {
        proposal
            .as_ref()
            .and_then(|summary| semantic_view.proposals.get(&summary.proposal_id))
            .map(|value| {
                let (plain_accept_eligible, merge_and_accept_eligible) =
                    proposal_acceptance_eligibility(semantic_view, value);
                let reauthorization =
                    if value.status.is_open() && value.operation == ProposalOperation::Create {
                        deletion_admission
                            .as_ref()
                            .ok_or(HumanGovernanceError::Store)?
                            .classify_proposal(value)
                            .map_err(|_| HumanGovernanceError::Store)?
                            .representative_historical_deletion()
                            .and_then(ObjectReauthorizationRef::from_deletion)
                    } else {
                        None
                    };
                Ok(HumanProposalReview {
                    proposal: Box::new(value.clone()),
                    plain_accept_eligible: plain_accept_eligible && reauthorization.is_none(),
                    merge_and_accept_eligible,
                    reauthorization,
                })
            })
            .transpose()?
    } else {
        None
    };
    let support_detail = if include_detail {
        current_support_source(snapshot, row)?
            .map(|(validation, contract)| {
                let initial_replacement_payload =
                    match select_support_replacement(snapshot, validation.validation_revision_id) {
                        Ok(SupportReplacementLookup::Available(selection)) => {
                            Some(Box::new(selection.initial_payload))
                        }
                        Ok(
                            SupportReplacementLookup::Conflict { .. }
                            | SupportReplacementLookup::Unavailable { .. },
                        ) => None,
                        Err(_) => return Err(HumanGovernanceError::Store),
                    };
                let deprecate_available =
                    match select_support_deprecate(snapshot, validation.validation_revision_id) {
                        Ok(SupportDeprecateLookup::Available(_)) => true,
                        Ok(
                            SupportDeprecateLookup::Conflict { .. }
                            | SupportDeprecateLookup::Unavailable { .. },
                        ) => false,
                        Err(_) => return Err(HumanGovernanceError::Store),
                    };
                Ok(HumanSupportDetail {
                    support_contract_revision_id: contract.support_contract_revision_id,
                    successor_ref: validation.successor_ref,
                    validation_revision_id: validation.validation_revision_id,
                    state: validation.state,
                    dependency_generation: validation.dependency_generation,
                    provenance_degraded: validation.provenance_degraded,
                    threshold: contract.support_threshold_snapshot,
                    support_revision_refs: contract.support_revision_refs,
                    authorization_revision_refs: contract.authorization_revision_refs,
                    surviving_support_refs: validation.surviving_support_refs,
                    invalid_or_missing_refs: validation.invalid_or_missing_refs,
                    trigger_refs: validation.trigger_refs,
                    initial_replacement_payload,
                    deprecate_available,
                })
            })
            .transpose()?
    } else {
        None
    };
    let competing_detail =
        if include_detail && row.object_kind.as_deref() == Some("competing_attempt_group") {
            let expected_group_revision_id = row
                .current_revision_id
                .as_deref()
                .ok_or(HumanGovernanceError::Store)?
                .parse::<RevisionId>()
                .map_err(|_| HumanGovernanceError::Store)?;
            match select_competing_selected(snapshot, expected_group_revision_id)
                .map_err(|_| HumanGovernanceError::Store)?
            {
                CompetingSelectedLookup::Available(selection) => Some(HumanCompetingDetail {
                    expected_group_revision_id,
                    eligible_attempt_ids: selection
                        .candidates
                        .iter()
                        .map(|candidate| candidate.attempt_id)
                        .collect(),
                }),
                CompetingSelectedLookup::Conflict { .. }
                | CompetingSelectedLookup::Unavailable { .. } => None,
            }
        } else {
            None
        };
    let forget_preview = if include_detail && surface == HumanSurface::Explorer {
        forget_target(row)?
            .map(|target| {
                let lookup = select_object_forget(snapshot, target)
                    .map_err(|_| HumanGovernanceError::Store)?;
                let ObjectForgetLookup::Available(preview) = lookup else {
                    return Ok(None);
                };
                if row.current_revision_id.as_deref()
                    != Some(preview.current_revision_id.to_string().as_str())
                {
                    return Ok(None);
                }
                Ok(Some(Box::new(HumanForgetPreview {
                    target: preview.target,
                    current_revision_id: preview.current_revision_id,
                    exact_revision_ids: preview.exact_revision_ids,
                    deletion_generation: preview.deletion_generation,
                    shared_source_count: preview.shared_source_count,
                    suppressed_source_count: preview.suppressed_source_count,
                    suppression_ref_count: preview.suppression_ref_count,
                    downstream_support_revalidation_count: u32::try_from(
                        preview.downstream_support_impacts.len(),
                    )
                    .map_err(|_| HumanGovernanceError::Store)?,
                    dependent_procedure_review_hold_count: u32::try_from(
                        preview.dependent_procedure_impacts.len(),
                    )
                    .map_err(|_| HumanGovernanceError::Store)?,
                })))
            })
            .transpose()?
            .flatten()
    } else {
        None
    };
    let repository_purge_preview = if include_detail
        && surface == HumanSurface::Explorer
        && row.object_kind.as_deref() == Some("repository")
    {
        let repository_id = row
            .object_id
            .as_deref()
            .ok_or(HumanGovernanceError::Store)?
            .parse::<RepositoryId>()
            .map_err(|_| HumanGovernanceError::Store)?;
        let repository_revision = row
            .current_revision_id
            .as_deref()
            .ok_or(HumanGovernanceError::Store)?
            .strip_prefix(&format!("{repository_id}@"))
            .ok_or(HumanGovernanceError::Store)?
            .parse::<u32>()
            .map_err(|_| HumanGovernanceError::Store)?;
        match select_repository_purge(snapshot, repository_id, repository_revision)
            .map_err(|_| HumanGovernanceError::Store)?
        {
            RepositoryPurgeLookup::Available(preview) => {
                let estimated_reclaimable_bytes = runtime_snapshot.and_then(|runtime| {
                    let cas = CasStore::open(runtime.cas_dir.clone()).ok()?;
                    preview
                        .exclusive_cas_refs
                        .iter()
                        .try_fold(0_u64, |total, reference| {
                            let digest = CasDigest::from_str(reference).ok()?;
                            total.checked_add(cas.encoded_blob_length(&digest).ok()?)
                        })
                });
                Some(Box::new(HumanRepositoryPurgePreview {
                    repository_id,
                    repository_revision,
                    deletion_generation: preview.deletion_generation,
                    planned_exclusive_cas_count: preview
                        .physical_item_count()
                        .map_err(|_| HumanGovernanceError::Store)?,
                    shared_cas_retained_count: preview.shared_cas_count,
                    repository_derived_global_dependency_count: preview
                        .repository_derived_global_dependency_count,
                    affected_session_count: preview.affected_session_count,
                    affected_evidence_receipt_capture_count: preview
                        .affected_evidence_receipt_capture_count,
                    affected_work_count: preview.affected_work_count,
                    affected_atom_count: preview.affected_atom_count,
                    affected_procedure_count: preview.affected_procedure_count,
                    affected_experiment_run_count: preview.affected_experiment_run_count,
                    affected_result_evidence_count: preview.affected_result_evidence_count,
                    affected_artifact_count: preview.affected_artifact_count,
                    affected_recovery_count: preview.affected_recovery_count,
                    affected_recall_derived_count: preview.affected_recall_derived_count,
                    relationship_only_count: preview.relationship_only_count,
                    estimated_reclaimable_bytes,
                    blockers: preview.blockers,
                    downstream_support_revalidation_count: u32::try_from(
                        preview.downstream_support_impacts.len(),
                    )
                    .map_err(|_| HumanGovernanceError::Store)?,
                    dependent_procedure_review_hold_count: u32::try_from(
                        preview.dependent_procedure_impacts.len(),
                    )
                    .map_err(|_| HumanGovernanceError::Store)?,
                }))
            }
            RepositoryPurgeLookup::NoDelta(_) | RepositoryPurgeLookup::Unavailable => None,
        }
    } else {
        None
    };
    let negative_review = if row.object_kind.as_deref() == Some("procedure_negative_review") {
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let JournalPayload::ProcedureNegativeReviewRecorded(review) = payload else {
            return Err(HumanGovernanceError::Store);
        };
        let selection = usage_view
            .select_negative_review(review.negative_evidence_id)
            .map_err(|_| HumanGovernanceError::Store)?;
        if selection.review_revision_id != review.review_event_id {
            return Err(HumanGovernanceError::Store);
        }
        Some(HumanNegativeReviewSummary {
            negative_evidence_id: review.negative_evidence_id,
            current_review_revision_id: selection.review_revision_id,
            status: selection.review_status,
            available_decisions: selection
                .available_decisions
                .into_iter()
                .map(|decision| match decision {
                    ProcedureNegativeReviewDecision::ResolveAsIneffective => {
                        HumanNegativeDecision::ResolveAsIneffective
                    }
                    ProcedureNegativeReviewDecision::DismissAttribution => {
                        HumanNegativeDecision::DismissAttribution
                    }
                    ProcedureNegativeReviewDecision::ConfirmHarm => {
                        HumanNegativeDecision::ConfirmHarm
                    }
                    ProcedureNegativeReviewDecision::RequestRevision => {
                        HumanNegativeDecision::RequestRevision
                    }
                })
                .collect(),
        })
    } else {
        None
    };
    let (recovery_detail, worktree_detail, execution_integrity_detail, system_detail) =
        if include_detail {
            typed_current_detail(row)?
        } else {
            (None, None, None, None)
        };
    Ok(HumanSummary {
        proposal,
        proposal_review,
        support_detail,
        competing_detail,
        forget_preview,
        repository_purge_preview,
        negative_review,
        recovery_detail,
        worktree_detail,
        execution_integrity_detail,
        system_detail,
        stable_key: row.row_id.clone(),
        row_class: human_row_class(row),
        family: human_object_family(row),
        category: human_item_category(surface, row),
        object_kind: row
            .object_kind
            .clone()
            .unwrap_or_else(|| "runtime_event".into()),
        object_ref: row.object_id.clone(),
        revision_ref: row.current_revision_id.clone(),
        lifecycle: row.lifecycle.clone(),
        epistemic: row.epistemic.clone(),
        authority: row.authority.clone(),
        publication_state: row.publication_state.clone(),
        support_state: row.support_state.clone(),
        scope_ref: row
            .task_id
            .clone()
            .or_else(|| row.worktree_id.clone())
            .or_else(|| row.repository_id.clone())
            .or_else(|| row.project_id.clone())
            .or_else(|| row.session_id.clone()),
        source_event_seq: row.source_event_seq,
    })
}

fn forget_target(row: &ObjectRow) -> Result<Option<ObjectDeletionTarget>, HumanGovernanceError> {
    if row.row_class != Some(ObjectRowClass::Object) {
        return Ok(None);
    }
    let Some(object_ref) = row.object_id.as_deref() else {
        return Ok(None);
    };
    match row.object_kind.as_deref() {
        Some("atom_revision") => object_ref
            .parse::<AtomId>()
            .map(|atom_id| Some(ObjectDeletionTarget::Atom { atom_id }))
            .map_err(|_| HumanGovernanceError::Store),
        Some("procedure_revision") => object_ref
            .parse::<ProcedureId>()
            .map(|procedure_id| Some(ObjectDeletionTarget::Procedure { procedure_id }))
            .map_err(|_| HumanGovernanceError::Store),
        Some("core_membership") => object_ref
            .parse::<CoreMembershipId>()
            .map(|core_membership_id| {
                Some(ObjectDeletionTarget::CoreMembership { core_membership_id })
            })
            .map_err(|_| HumanGovernanceError::Store),
        _ => Ok(None),
    }
}

fn proposal_acceptance_eligibility(
    view: &SemanticCurrentView,
    proposal: &RevisionProposal,
) -> (bool, bool) {
    let reviewable =
        proposal.status.is_open() && proposal.eligibility != ProposalEligibility::AutoEligibleFull;
    let plain = reviewable
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
                evertrace_domain::semantic::ProcedureProposalPayload::Create { .. }
                    | evertrace_domain::semantic::ProcedureProposalPayload::Replace { .. }
            ),
            ProposalPayload::CoreMembership(payload) => matches!(
                payload.as_ref(),
                CoreMembershipProposalPayload::Create { .. }
            ),
            ProposalPayload::ReservedTarget { .. } => false,
        };
    let merge = reviewable
        && matches!(
            &proposal.payload,
            ProposalPayload::Atom(payload)
                if matches!(payload.as_ref(), AtomProposalPayload::Merge { .. })
        )
        && RevisionProposalService
            .validate_atom_merge(view, proposal.proposal_id)
            .is_ok();
    (plain, merge)
}

fn proposal_edit_supported(payload: &ProposalPayload) -> bool {
    match payload {
        ProposalPayload::Atom(payload) => matches!(
            payload.as_ref(),
            AtomProposalPayload::Create { .. }
                | AtomProposalPayload::Replace { .. }
                | AtomProposalPayload::Deprecate { .. }
                | AtomProposalPayload::Reclassify { .. }
        ),
        ProposalPayload::Procedure(payload) => matches!(
            payload.as_ref(),
            evertrace_domain::semantic::ProcedureProposalPayload::Create { .. }
                | evertrace_domain::semantic::ProcedureProposalPayload::Replace { .. }
        ),
        ProposalPayload::CoreMembership(_) | ProposalPayload::ReservedTarget { .. } => false,
    }
}

type HumanTypedDetails = (
    Option<HumanRecoveryDetail>,
    Option<HumanWorktreeDetail>,
    Option<HumanExecutionIntegrityDetail>,
    Option<HumanSystemDetail>,
);

fn typed_current_detail(row: &ObjectRow) -> Result<HumanTypedDetails, HumanGovernanceError> {
    let kind = match row.object_kind.as_deref() {
        Some(kind) => kind,
        None if row.row_class == Some(ObjectRowClass::Runtime) => "runtime_event",
        None => return Ok((None, None, None, None)),
    };
    if !matches!(
        kind,
        "recovery_capture_request_revision"
            | "recovery_bundle"
            | "recovery_application_revision"
            | "worktree"
            | "execution_lane"
            | "capture_receipt"
            | "runtime_event"
    ) {
        return Ok((None, None, None, None));
    }
    let payload: JournalPayload = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(HumanGovernanceError::Store)?,
    )
    .map_err(|_| HumanGovernanceError::Store)?;
    match (kind, payload) {
        (
            "recovery_capture_request_revision",
            JournalPayload::RecoveryCaptureRequestRecorded(value),
        ) => Ok((
            Some(HumanRecoveryDetail::CaptureRequest {
                request_id: value.recovery_capture_request_id,
                revision_id: value.request_revision_id,
                repository_id: value.repository_instance_id,
                worktree_id: value.worktree_instance_id,
                destructive_class: value.destructive_class,
                untracked_scope: value.untracked_capture_scope,
                status: value.request_status,
                bundle_id: value.recovery_bundle_id,
                reason_codes: sorted_reason_codes(&value.reason_codes),
            }),
            None,
            None,
            None,
        )),
        ("recovery_bundle", JournalPayload::RecoveryBundleRecorded(value)) => {
            let mut omission_counts = Vec::<HumanRecoveryOmissionCount>::new();
            for omission in &value.omissions {
                if let Some(current) = omission_counts
                    .iter_mut()
                    .find(|current| current.reason == omission.reason)
                {
                    current.count = current
                        .count
                        .checked_add(1)
                        .ok_or(HumanGovernanceError::Store)?;
                } else {
                    omission_counts.push(HumanRecoveryOmissionCount {
                        reason: omission.reason,
                        count: 1,
                    });
                }
            }
            Ok((
                Some(HumanRecoveryDetail::Bundle {
                    bundle_id: value.recovery_bundle_id,
                    source_worktree_id: value.source_worktree_instance_id,
                    source_snapshot_id: value.source_snapshot_id,
                    capture_status: value.capture_status,
                    ordering_integrity: value.ordering_integrity,
                    captured_bytes: value.captured_bytes,
                    tracked_diff_count: bounded_count(value.tracked_diff_blob_refs.len())?,
                    tracked_file_count: bounded_count(value.tracked_file_blob_refs.len())?,
                    index_state_count: bounded_count(value.index_state_refs.len())?,
                    untracked_file_count: bounded_count(value.untracked_file_blob_refs.len())?,
                    untracked_artifact_count: bounded_count(
                        value.untracked_work_artifact_refs.len(),
                    )?,
                    metadata_artifact_count: bounded_count(
                        value.metadata_only_work_artifact_refs.len(),
                    )?,
                    config_run_count: bounded_count(value.config_and_run_refs.len())?,
                    attempt_anchor_count: bounded_count(value.attempt_anchor_ids.len())?,
                    omission_counts,
                }),
                None,
                None,
                None,
            ))
        }
        ("recovery_application_revision", JournalPayload::RecoveryApplicationRecorded(value)) => {
            Ok((
                Some(HumanRecoveryDetail::Application {
                    application_id: value.recovery_application_id,
                    revision_id: value.revision_id,
                    bundle_id: value.recovery_bundle_id,
                    target_worktree_id: value.target_worktree_instance_id,
                    application_kind: value.application_kind,
                    input_delivery_state: value.input_delivery_state,
                    status: value.application_status,
                    pre_snapshot_id: value.pre_application_snapshot_id,
                    post_snapshot_id: value.post_application_snapshot_id,
                    selected_input_count: bounded_count(value.selected_cas_refs.len())?,
                    result_count: bounded_count(value.result_source_observation_ids.len())?,
                    verifier_count: bounded_count(
                        value
                            .verifier_receipts
                            .len()
                            .checked_add(value.anchor_verifier_receipts.len())
                            .ok_or(HumanGovernanceError::Store)?,
                    )?,
                }),
                None,
                None,
                None,
            ))
        }
        ("worktree", JournalPayload::WorktreeInstanceRecorded(value)) => Ok((
            None,
            Some(HumanWorktreeDetail {
                worktree_id: value.worktree_instance_id,
                repository_id: value.repository_instance_id,
                kind: value.kind,
                lifecycle: value.lifecycle,
                registration_state: value.git_registration_state,
                current_snapshot_id: value.current_snapshot_id,
            }),
            None,
            None,
        )),
        ("execution_lane", JournalPayload::ExecutionLaneRecorded(value)) => Ok((
            None,
            None,
            Some(HumanExecutionIntegrityDetail::Lane {
                execution_lane_id: value.execution_lane_id,
                lane_revision: value.lane_revision,
                parent_lane_id: value.parent_lane_id,
                status: value.status,
                terminal_kind: value.terminal_kind,
                liveness_state: value.liveness_state,
                finalized: value.finalized,
                event_watermark: value.event_watermark,
                active_capture_receipt_revision_id: value.active_capture_receipt_revision_id,
                coverage_level: value.coverage_level,
                source_coverage: value.source_coverage,
                pairing_integrity: value.pairing_integrity,
                payload_integrity: value.payload_integrity,
                ordering_integrity: value.ordering_integrity,
                reasoning_visibility: sorted_reasoning_visibility(&value.reasoning_visibility),
            }),
            None,
        )),
        ("capture_receipt", JournalPayload::CaptureReceiptRecorded(value)) => Ok((
            None,
            None,
            Some(HumanExecutionIntegrityDetail::Receipt {
                capture_receipt_revision_id: value.capture_receipt_revision_id,
                execution_lane_id: value.execution_lane_id,
                predecessor_revision_id: value.predecessor_revision_id,
                admission_failure_observability: value.admission_failure_observability,
                identity_strength: value.identity_strength,
                delegation_start_seen: value.delegation_start_seen,
                child_session_linked: value.child_session_linked,
                parent_session_end_seen: value.parent_session_end_seen,
                lifecycle_end_seen: value.lifecycle_end_seen,
                terminal_event_kind: value.terminal_event_kind,
                finalized: value.finalized,
                first_sequence: value.first_sequence,
                last_sequence: value.last_sequence,
                sequence_gap_count: bounded_count(value.sequence_gaps.len())?,
                outage_count: bounded_count(value.capture_outage_interval_refs.len())?,
                tool_call_count: bounded_count(value.tool_calls_seen.len())?,
                tool_result_count: bounded_count(value.tool_results_seen.len())?,
                unmatched_tool_call_count: bounded_count(value.unmatched_tool_call_ids.len())?,
                unmatched_tool_result_count: bounded_count(value.unmatched_tool_result_ids.len())?,
                truncation_count: bounded_count(value.payload_truncations.len())?,
                redaction_count: bounded_count(value.redaction_refs.len())?,
                corrupt_count: bounded_count(value.corrupt_payload_refs.len())?,
                unsupported_count: bounded_count(value.unsupported_record_types.len())?,
                import_watermark: value.import_watermark,
                coverage_level: value.coverage_level,
                source_coverage: value.source_coverage,
                pairing_integrity: value.pairing_integrity,
                payload_integrity: value.payload_integrity,
                ordering_integrity: value.ordering_integrity,
                reasoning_visibility: sorted_reasoning_visibility(&value.reasoning_visibility),
                exact_byte_replay: value.exact_byte_replay,
                resolver_version: value.resolver_version,
            }),
            None,
        )),
        ("runtime_event", JournalPayload::JobState(value)) => {
            if row.row_id != format!("runtime:job:{}", value.job_id)
                || row.object_id.is_some()
                || row.current_revision_id.is_some()
            {
                return Err(HumanGovernanceError::Store);
            }
            Ok((
                None,
                None,
                None,
                Some(HumanSystemDetail::Job {
                    detail: Box::new(HumanJobDetail {
                        job_id: value.job_id,
                        target_revision: value.target_revision,
                        target_watermark: value.target_watermark,
                        target_generation: value.target_generation,
                        job_kind: value.kind,
                        algorithm_revision: value.algorithm_revision,
                        model_id: value.model_id,
                        priority: value.priority,
                        state: map_job_state(value.state),
                        attempt: value.attempt,
                        backoff_until_us: value.backoff_until_us,
                        lease_until_us: value.lease_until_us,
                        config_hash: value.config_hash,
                        budget: HumanJobBudget {
                            max_items: value.budget.max_items,
                            max_bytes: value.budget.max_bytes,
                            max_input_tokens: value.budget.max_input_tokens,
                            max_output_tokens: value.budget.max_output_tokens,
                            max_calls: value.budget.max_calls,
                            max_wall_time_ms: value.budget.max_wall_time_ms,
                        },
                        terminal_reason: value
                            .terminal
                            .as_deref()
                            .map(|terminal| map_job_terminal_reason(terminal.reason)),
                        terminal_result_ref: value
                            .terminal
                            .and_then(|terminal| terminal.result_ref),
                    }),
                }),
            ))
        }
        ("runtime_event", JournalPayload::ConfigAudit(value)) => {
            if row.row_id != "runtime:config:current"
                || row.object_id.is_some()
                || row.current_revision_id.is_some()
            {
                return Err(HumanGovernanceError::Store);
            }
            Ok((
                None,
                None,
                None,
                Some(HumanSystemDetail::Config {
                    config_version: value.config_version,
                    effective_config_hash: value.effective_config_hash,
                }),
            ))
        }
        ("runtime_event", _) => Ok((None, None, None, None)),
        _ => Err(HumanGovernanceError::Store),
    }
}

fn bounded_count(value: usize) -> Result<u32, HumanGovernanceError> {
    u32::try_from(value).map_err(|_| HumanGovernanceError::Store)
}

fn sorted_reason_codes(values: &[RecoveryReasonCode]) -> Vec<RecoveryReasonCode> {
    let mut values = values.to_vec();
    values.sort();
    values
}

fn sorted_reasoning_visibility(values: &[ReasoningVisibility]) -> Vec<ReasoningVisibility> {
    let mut values = values.to_vec();
    values.sort();
    values
}

fn map_job_state(value: JobStatus) -> HumanJobState {
    match value {
        JobStatus::Queued => HumanJobState::Queued,
        JobStatus::Leased => HumanJobState::Leased,
        JobStatus::Succeeded => HumanJobState::Succeeded,
        JobStatus::Failed => HumanJobState::Failed,
    }
}

fn map_job_terminal_reason(value: JobTerminalReason) -> HumanJobTerminalReason {
    match value {
        JobTerminalReason::Completed => HumanJobTerminalReason::Completed,
        JobTerminalReason::StaleGeneration => HumanJobTerminalReason::StaleGeneration,
        JobTerminalReason::BudgetExhausted => HumanJobTerminalReason::BudgetExhausted,
        JobTerminalReason::SourceUnavailable => HumanJobTerminalReason::SourceUnavailable,
        JobTerminalReason::Unsupported => HumanJobTerminalReason::Unsupported,
        JobTerminalReason::SourceReplaced => HumanJobTerminalReason::SourceReplaced,
        JobTerminalReason::Revoked => HumanJobTerminalReason::Revoked,
        JobTerminalReason::IntegrityFailure => HumanJobTerminalReason::IntegrityFailure,
    }
}

fn human_row_class(row: &ObjectRow) -> HumanRowClass {
    match row.row_class.expect("data rows have a class") {
        ObjectRowClass::Object => HumanRowClass::Object,
        ObjectRowClass::Runtime => HumanRowClass::Runtime,
        ObjectRowClass::Projection => HumanRowClass::Projection,
    }
}

fn human_object_family(row: &ObjectRow) -> HumanObjectFamily {
    match row.object_family {
        Some(ObjectFamily::Evidence) => HumanObjectFamily::Evidence,
        Some(ObjectFamily::Work) => HumanObjectFamily::Work,
        Some(ObjectFamily::Atom) => HumanObjectFamily::Atom,
        Some(ObjectFamily::Procedure) => HumanObjectFamily::Procedure,
        Some(ObjectFamily::RevisionProposal) => HumanObjectFamily::RevisionProposal,
        None if row.row_class == Some(ObjectRowClass::Runtime) => HumanObjectFamily::Runtime,
        None => HumanObjectFamily::Projection,
    }
}

fn human_item_category(surface: HumanSurface, row: &ObjectRow) -> HumanItemCategory {
    let kind = row.object_kind.as_deref().unwrap_or_default();
    match surface {
        HumanSurface::Inbox => match kind {
            "revision_proposal_revision" => HumanItemCategory::Proposal,
            "global_support_contract" | "global_support_validation" => HumanItemCategory::Support,
            "procedure_negative_evidence" | "procedure_negative_review" => {
                HumanItemCategory::NegativeReview
            }
            "work_episode" => HumanItemCategory::SegmentationCorrection,
            "recovery_capture_request_revision" => HumanItemCategory::RecoveryCorrection,
            "work_binding" => HumanItemCategory::Assignment,
            "competing_attempt_group" => HumanItemCategory::CompetingResolution,
            "attempt" => HumanItemCategory::AttemptResume,
            "execution_lane" => HumanItemCategory::LaneLifecycle,
            "capture_receipt" => HumanItemCategory::CaptureIntegrity,
            "worktree_transition" => HumanItemCategory::WorktreeLineage,
            _ => HumanItemCategory::ReviewHold,
        },
        HumanSurface::Explorer => match kind {
            "repository"
            | "worktree"
            | "worktree_snapshot"
            | "worktree_transition"
            | "integration_event" => HumanItemCategory::Repository,
            "experiment_run" | "result_evidence" | "work_artifact" => HumanItemCategory::Research,
            "recovery_capture_request_revision"
            | "recovery_bundle"
            | "recovery_application_revision" => HumanItemCategory::RecoveryEvidence,
            _ => match human_object_family(row) {
                HumanObjectFamily::Evidence => HumanItemCategory::Evidence,
                HumanObjectFamily::Work => HumanItemCategory::Work,
                HumanObjectFamily::Atom => HumanItemCategory::Semantic,
                HumanObjectFamily::Procedure => HumanItemCategory::Procedure,
                HumanObjectFamily::RevisionProposal => HumanItemCategory::Proposal,
                HumanObjectFamily::Runtime => HumanItemCategory::Runtime,
                HumanObjectFamily::Projection => HumanItemCategory::Projection,
            },
        },
        HumanSurface::System => match kind {
            "session_import_current" => HumanItemCategory::SessionImport,
            "semantic_derivation_run" => HumanItemCategory::SemanticDerivation,
            _ if row.row_class == Some(ObjectRowClass::Runtime) => HumanItemCategory::Runtime,
            _ => HumanItemCategory::Projection,
        },
    }
}

fn current_proposal_revision(
    snapshot: &ProjectionSnapshot,
    proposal_id: RevisionProposalId,
) -> Option<String> {
    SemanticCurrentView::from_snapshot(snapshot)
        .ok()?
        .proposals
        .get(&proposal_id)
        .map(|proposal: &RevisionProposal| proposal.proposal_revision_id.to_string())
}

#[derive(Clone, Copy)]
struct AcceptanceCaptureScope {
    task_id: Option<evertrace_domain::ids::TaskId>,
    repository_id: Option<evertrace_domain::ids::RepositoryId>,
    worktree_id: Option<evertrace_domain::ids::WorktreeId>,
}

fn proposal_scope(
    proposal: &RevisionProposal,
    view: &SemanticCurrentView,
) -> Result<AtomScope, HumanGovernanceError> {
    match &proposal.payload {
        ProposalPayload::Atom(payload) => match payload.as_ref() {
            AtomProposalPayload::Create { draft }
            | AtomProposalPayload::Replace { draft }
            | AtomProposalPayload::Reclassify { draft } => Ok(draft.scope.clone()),
            AtomProposalPayload::Deprecate { .. } => {
                let Some(ProposalTargetId::Atom(atom_id)) = proposal.target_id else {
                    return Err(HumanGovernanceError::InvalidInput);
                };
                view.atoms
                    .get(&atom_id)
                    .map(|atom| atom.scope.clone())
                    .ok_or(HumanGovernanceError::InvalidInput)
            }
            AtomProposalPayload::Merge { draft, .. } => Ok(draft.scope.clone()),
            AtomProposalPayload::Split { .. } => Err(HumanGovernanceError::InvalidInput),
        },
        ProposalPayload::Procedure(payload) => Ok(match payload.draft().scope {
            ProcedureScope::Worktree { repository_id, .. }
            | ProcedureScope::Repository { repository_id } => AtomScope::Repository {
                repository_instance_id: repository_id,
            },
            ProcedureScope::Global => AtomScope::Global,
        }),
        ProposalPayload::CoreMembership(payload) => {
            let CoreMembershipProposalPayload::Create {
                atom_revision_id, ..
            } = payload.as_ref()
            else {
                return Err(HumanGovernanceError::InvalidInput);
            };
            view.atom_revisions
                .get(atom_revision_id)
                .map(|atom| atom.scope.clone())
                .ok_or(HumanGovernanceError::InvalidInput)
        }
        ProposalPayload::ReservedTarget { .. } => Err(HumanGovernanceError::InvalidInput),
    }
}

fn support_atom_acceptance(
    snapshot: &ProjectionSnapshot,
    view: &SemanticCurrentView,
    proposal: &RevisionProposal,
) -> Result<Option<SupportAtomAcceptance>, crate::semantic::SemanticServiceError> {
    let Some(ProposalTargetId::Atom(atom_id)) = proposal.target_id else {
        return Ok(None);
    };
    let Some(base_revision_id) = proposal.base_revision_id else {
        return Ok(None);
    };
    let Some(atom) = view.atoms.get(&atom_id) else {
        return Err(crate::semantic::SemanticServiceError::BaseConflict);
    };
    if atom.revision_id != base_revision_id {
        return Err(crate::semantic::SemanticServiceError::BaseConflict);
    }
    if atom.scope != AtomScope::Global {
        return Ok(None);
    }
    select_support_atom_acceptance(snapshot, proposal).map(Some)
}

fn acceptance_capture_scope(
    proposal: &RevisionProposal,
    view: &SemanticCurrentView,
) -> Result<AcceptanceCaptureScope, HumanGovernanceError> {
    let scope = proposal_scope(proposal, view)?;
    let mut capture = AcceptanceCaptureScope {
        task_id: None,
        repository_id: None,
        worktree_id: None,
    };
    match scope {
        AtomScope::Task { task_id } => capture.task_id = Some(task_id),
        AtomScope::Repository {
            repository_instance_id,
        } => capture.repository_id = Some(repository_instance_id),
        AtomScope::Worktree {
            repository_instance_id,
            worktree_instance_id,
        } => {
            capture.repository_id = Some(repository_instance_id);
            capture.worktree_id = Some(worktree_instance_id);
        }
        AtomScope::Global => {}
    }
    if let ProposalPayload::Procedure(payload) = &proposal.payload
        && let ProcedureScope::Worktree {
            repository_id,
            worktree_id,
        } = payload.draft().scope
    {
        capture.repository_id = Some(repository_id);
        capture.worktree_id = Some(worktree_id);
    }
    Ok(capture)
}

fn acceptance_capture_input(
    proposal: &RevisionProposal,
    payload: &str,
    record_id: &str,
    scope: AcceptanceCaptureScope,
) -> Result<CaptureRecordInput, HumanGovernanceError> {
    Ok(CaptureRecordInput {
        spool_record_id: Some(record_id.into()),
        source_observation_id_hint: None,
        source_instance_id: format!("tui-acceptance:{}", proposal.proposal_id),
        source_revision: proposal.proposal_revision_id.to_string(),
        source_record_identity: Some(record_id.into()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into(),
        source_ref: proposal.proposal_id.to_string(),
        session_ref: "human-governance".into(),
        turn_ref: None,
        tool_ref: None,
        source_sequence: 1,
        source_sequence_origin: Some(1),
        task_id: scope.task_id.map(|value| value.to_string()),
        repository_instance_id: scope.repository_id.map(|value| value.to_string()),
        worktree_instance_id: scope.worktree_id.map(|value| value.to_string()),
        source_byte_range: None,
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: None,
        observation_role: ObservationRole::Message,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            pairing_role: ObservationRole::Message,
            field_provenance: Vec::new(),
            adapter_manifest_ref: TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: Vec::new(),
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: SourceRole::User,
        content_trust: ContentTrust::UserStatement,
        capture_completeness: CaptureCompleteness::Complete,
        surface_eligible: true,
        adapter_revision: 1,
        adapter_manifest_ref: TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into(),
        eligible_event_manifest_ref: TUI_ACCEPTANCE_EVENT_MANIFEST_REF.into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: Some(now_us()?),
        raw_payload: payload.as_bytes().to_vec(),
    })
}

fn acceptance_context(
    proposal: &RevisionProposal,
    view: &SemanticCurrentView,
    verified: &crate::capture::VerifiedCapture,
) -> Result<AtomAcceptanceContext, HumanGovernanceError> {
    let observation = Box::new(verified.observation.clone());
    let receipt = Box::new(verified.receipt.clone());
    Ok(match proposal_scope(proposal, view)? {
        AtomScope::Task { .. } => AtomAcceptanceContext::TaskTui {
            observation,
            receipt,
        },
        AtomScope::Repository { .. } | AtomScope::Worktree { .. } => {
            AtomAcceptanceContext::RepositoryTui {
                observation,
                receipt,
            }
        }
        AtomScope::Global => AtomAcceptanceContext::GlobalTui {
            observation,
            receipt,
        },
    })
}

fn reauthorization_acceptance_context(
    proposal: &RevisionProposal,
    view: &SemanticCurrentView,
    verified: &crate::capture::VerifiedCapture,
    canonical_payload: String,
) -> Result<AtomAcceptanceContext, HumanGovernanceError> {
    let scope = proposal_scope(proposal, view)?;
    let authorized_scope_ceiling = match scope {
        AtomScope::Task { task_id } => AtomScope::Task { task_id },
        AtomScope::Repository {
            repository_instance_id,
        }
        | AtomScope::Worktree {
            repository_instance_id,
            ..
        } => AtomScope::Repository {
            repository_instance_id,
        },
        AtomScope::Global => AtomScope::Global,
    };
    Ok(AtomAcceptanceContext::ReauthorizationTui {
        observation: Box::new(verified.observation.clone()),
        receipt: Box::new(verified.receipt.clone()),
        authorized_scope_ceiling,
        canonical_payload,
    })
}

fn claim_isolated_record(
    spool: &DurableSpool,
    record_id: &str,
    limit: usize,
) -> Result<Option<evertrace_capture::SealedSegment>, HumanGovernanceError> {
    let mut matching = spool
        .isolated_segments(limit)
        .map_err(|_| HumanGovernanceError::Store)?
        .into_iter()
        .filter(|segment| {
            segment.frames().len() == 1 && segment.frames()[0].record.spool_record_id == record_id
        });
    let result = matching.next();
    if matching.next().is_some() {
        return Err(HumanGovernanceError::Store);
    }
    Ok(result)
}

fn current_procedure(
    snapshot: &ProjectionSnapshot,
    proposal: &RevisionProposal,
) -> Result<
    (
        Option<evertrace_domain::procedure::ProcedureRevision>,
        Option<ProcedurePublicationState>,
    ),
    HumanGovernanceError,
> {
    let Some(ProposalTargetId::Procedure(procedure_id)) = proposal.target_id else {
        return Ok((None, None));
    };
    let base = proposal
        .base_revision_id
        .ok_or(HumanGovernanceError::InvalidInput)?;
    let mut found = None;
    for row in snapshot.data_rows().filter(|row| {
        row.object_kind.as_deref() == Some("procedure_revision")
            && row.object_id.as_deref() == Some(&procedure_id.to_string())
            && row.current_revision_id.as_deref() == Some(&base.to_string())
    }) {
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let JournalPayload::ProcedureRevisionRecorded(value) = payload else {
            return Err(HumanGovernanceError::Store);
        };
        let publication = match row.publication_state.as_deref() {
            Some("active_probationary") => ProcedurePublicationState::ActiveProbationary,
            Some("review_hold") => ProcedurePublicationState::ReviewHold,
            Some("active_stable") => ProcedurePublicationState::ActiveStable,
            Some("suspended") => ProcedurePublicationState::Suspended,
            Some("rolled_back") => ProcedurePublicationState::RolledBack,
            Some("superseded") => ProcedurePublicationState::Superseded,
            _ => return Err(HumanGovernanceError::Store),
        };
        if found.replace((*value, publication)).is_some() {
            return Err(HumanGovernanceError::Store);
        }
    }
    found
        .map(|value| (Some(value.0), Some(value.1)))
        .ok_or(HumanGovernanceError::InvalidInput)
}

fn inactive_unchanged_procedure(
    snapshot: &ProjectionSnapshot,
    proposal: &RevisionProposal,
) -> Result<bool, HumanGovernanceError> {
    let ProposalPayload::Procedure(payload) = &proposal.payload else {
        return Ok(false);
    };
    if !matches!(
        payload.as_ref(),
        evertrace_domain::semantic::ProcedureProposalPayload::Replace { .. }
    ) {
        return Ok(false);
    }
    let (current, publication) = current_procedure(snapshot, proposal)?;
    Ok(current
        .as_ref()
        .is_some_and(|current| current.draft == *payload.draft())
        && !matches!(
            publication,
            Some(
                ProcedurePublicationState::ActiveProbationary
                    | ProcedurePublicationState::ActiveStable
            )
        ))
}

fn prepare_edit_candidate(
    view: &SemanticCurrentView,
    original: &RevisionProposal,
    edited_payload: ProposalPayload,
    command_id: CommandId,
    created_at_us: i64,
    effective_config_hash: [u8; 32],
    identity: Option<(RevisionProposalId, RevisionId)>,
) -> Result<(ProposalEditIntent, JournalCommand), HumanGovernanceError> {
    let (proposal_id, proposal_revision_id) =
        identity.unwrap_or_else(|| (RevisionProposalId::new_v7(), RevisionId::new_v7()));
    let request = SubmitProposalRequest {
        target_kind: original.target_kind,
        target_id: original.target_id,
        base_revision_id: original.base_revision_id,
        operation: original.operation,
        payload: edited_payload,
        evidence_refs: original.evidence_refs.clone(),
        source_cohort_refs: original.source_cohort_refs.clone(),
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::User,
    };
    let context = ProposalCommandContext {
        command_id,
        occurred_at_us: created_at_us,
        effective_config_hash,
        algorithm_revision: ALGORITHM_REVISION.into(),
    };
    let ProposalResolution::Revision { value, command } = RevisionProposalService
        .submit_with_identity(view, context, request, proposal_id, proposal_revision_id)
        .map_err(|_| HumanGovernanceError::InvalidInput)?
    else {
        return Err(HumanGovernanceError::InvalidInput);
    };
    let intent = ProposalEditIntent::new(original, *value);
    intent.validate(original)?;
    Ok((intent, command))
}

struct EditedAcceptanceInput<'a> {
    snapshot: &'a ProjectionSnapshot,
    view: &'a SemanticCurrentView,
    original: &'a RevisionProposal,
    reviewed: &'a RevisionProposal,
    acceptance: AtomAcceptanceContext,
    command_context: ProposalCommandContext,
    effective_config_hash: [u8; 32],
    global_promotion: &'a GlobalPromotionConfig,
    support: Option<&'a crate::semantic::SupportAtomAcceptance>,
}

struct EditedAcceptanceCommand {
    superseded: Box<RevisionProposal>,
    accepted_revision: RevisionId,
    events: Vec<evertrace_store::JournalEventDraft>,
}

fn compose_edited_acceptance(
    input: EditedAcceptanceInput<'_>,
) -> Result<EditedAcceptanceCommand, HumanGovernanceError> {
    let ProposalResolution::Revision {
        value: superseded,
        command: supersede,
    } = RevisionProposalService
        .revise_status(
            input.view,
            input.command_context.clone(),
            input.original.proposal_id,
            ProposalStatus::Superseded,
            Vec::new(),
            Some("human_edit_superseded".into()),
        )
        .map_err(|_| HumanGovernanceError::InvalidInput)?
    else {
        return Err(HumanGovernanceError::Store);
    };
    let (rebuilt, pending) = prepare_edit_candidate(
        input.view,
        input.original,
        input.reviewed.payload.clone(),
        input.command_context.command_id,
        input.reviewed.created_at_us,
        input.effective_config_hash,
        Some((
            input.reviewed.proposal_id,
            input.reviewed.proposal_revision_id,
        )),
    )?;
    if rebuilt.new_proposal != *input.reviewed {
        return Err(HumanGovernanceError::Store);
    }
    let mut edited_view = input.view.clone();
    edited_view
        .proposals
        .insert(input.reviewed.proposal_id, input.reviewed.clone());
    edited_view
        .proposal_revisions
        .insert(input.reviewed.proposal_revision_id, input.reviewed.clone());
    let (accepted_revision, accepted) = match &input.reviewed.payload {
        ProposalPayload::Atom(_) => {
            let accepted = if let Some(support) = input.support {
                RevisionProposalService.accept_support_linked_edited(
                    &edited_view,
                    input.command_context,
                    input.reviewed.proposal_id,
                    input.acceptance,
                    input.original,
                    support,
                )
            } else {
                RevisionProposalService.accept_edited(
                    &edited_view,
                    input.command_context,
                    input.reviewed.proposal_id,
                    input.acceptance,
                    input.original,
                )
            }
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
            (accepted.proposal.proposal_revision_id, accepted.command)
        }
        ProposalPayload::Procedure(_) => {
            let (current, publication) = current_procedure(input.snapshot, input.reviewed)?;
            let accepted = accept_procedure_edited(
                &edited_view,
                input.command_context,
                input.reviewed.proposal_id,
                EditedProcedureAcceptance {
                    source: input.acceptance,
                    original: input.original,
                },
                current.as_ref(),
                publication,
                input.global_promotion,
            )
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
            match accepted {
                ProcedureAcceptanceResolution::Command {
                    proposal, command, ..
                }
                | ProcedureAcceptanceResolution::AcceptedExisting { proposal, command } => {
                    (proposal.proposal_revision_id, command)
                }
                ProcedureAcceptanceResolution::NoDelta => {
                    return Err(HumanGovernanceError::Store);
                }
            }
        }
        ProposalPayload::CoreMembership(_) | ProposalPayload::ReservedTarget { .. } => {
            return Err(HumanGovernanceError::InvalidInput);
        }
    };
    let mut events = supersede.events().to_vec();
    events.extend(pending.events().iter().cloned());
    events.extend(accepted.events().iter().cloned());
    Ok(EditedAcceptanceCommand {
        superseded,
        accepted_revision,
        events,
    })
}

fn read_edit_intent(
    verified: &crate::capture::VerifiedCapture,
    cas: &CasStore,
    original: &RevisionProposal,
) -> Result<ProposalEditIntent, HumanGovernanceError> {
    try_read_edit_intent(verified, cas, original)?.ok_or(HumanGovernanceError::Store)
}

fn try_read_edit_intent(
    verified: &crate::capture::VerifiedCapture,
    cas: &CasStore,
    original: &RevisionProposal,
) -> Result<Option<ProposalEditIntent>, HumanGovernanceError> {
    let digest =
        CasDigest::from_str(&verified.body.cas_ref).map_err(|_| HumanGovernanceError::Store)?;
    let bytes = cas.read(&digest).map_err(|_| HumanGovernanceError::Store)?;
    let Ok(value) = std::str::from_utf8(&bytes) else {
        return Ok(None);
    };
    let Ok(intent) = ProposalEditIntent::from_toml(value) else {
        return Ok(None);
    };
    if intent.canonical_toml(original)?.as_bytes() != bytes.as_slice() {
        return Err(HumanGovernanceError::Store);
    }
    Ok(Some(intent))
}

fn read_reauthorization_intent(
    verified: &crate::capture::VerifiedCapture,
    cas: &CasStore,
    deletion: &ObjectDeletionLedgerEvent,
    reviewed: &RevisionProposal,
) -> Result<ObjectReauthorizationIntent, HumanGovernanceError> {
    let digest =
        CasDigest::from_str(&verified.body.cas_ref).map_err(|_| HumanGovernanceError::Store)?;
    let bytes = cas.read(&digest).map_err(|_| HumanGovernanceError::Store)?;
    let value = std::str::from_utf8(&bytes).map_err(|_| HumanGovernanceError::Store)?;
    let intent =
        ObjectReauthorizationIntent::from_toml(value).ok_or(HumanGovernanceError::Store)?;
    let canonical = intent
        .canonical_toml(deletion, reviewed)
        .ok_or(HumanGovernanceError::Store)?;
    if canonical.as_bytes() != bytes.as_slice() {
        return Err(HumanGovernanceError::Store);
    }
    Ok(intent)
}

struct ReservedReauthorizationIntent {
    deletion: ObjectDeletionLedgerEvent,
    intent: ObjectReauthorizationIntent,
}

fn try_read_reauthorization_intent(
    verified: &crate::capture::VerifiedCapture,
    cas: &CasStore,
    snapshot: &ProjectionSnapshot,
    reviewed: &RevisionProposal,
) -> Result<Option<ReservedReauthorizationIntent>, HumanGovernanceError> {
    let digest =
        CasDigest::from_str(&verified.body.cas_ref).map_err(|_| HumanGovernanceError::Store)?;
    let bytes = cas.read(&digest).map_err(|_| HumanGovernanceError::Store)?;
    let Ok(value) = std::str::from_utf8(&bytes) else {
        return Ok(None);
    };
    let Some(intent) = ObjectReauthorizationIntent::from_toml(value) else {
        return Ok(None);
    };
    let ledger = ObjectDeletionCurrentView::from_snapshot(snapshot)
        .map_err(|_| HumanGovernanceError::Store)?;
    let deletion = ledger
        .events
        .get(&intent.deletion.target)
        .filter(|event| event.deletion_generation == intent.deletion.deletion_generation)
        .cloned()
        .ok_or(HumanGovernanceError::Store)?;
    let canonical = intent
        .canonical_toml(&deletion, reviewed)
        .ok_or(HumanGovernanceError::Store)?;
    if canonical.as_bytes() != bytes.as_slice() {
        return Err(HumanGovernanceError::Store);
    }
    Ok(Some(ReservedReauthorizationIntent { deletion, intent }))
}

fn accepted_edit_retry<'a>(
    snapshot: &ProjectionSnapshot,
    view: &'a SemanticCurrentView,
    original: &RevisionProposal,
    edited_payload: &ProposalPayload,
) -> Result<Option<&'a RevisionProposal>, HumanGovernanceError> {
    let mut evidence = None;
    for accepted in view.proposals.values() {
        if accepted.status != ProposalStatus::Accepted {
            continue;
        }
        let Some(acceptance) = accepted.acceptance.as_ref() else {
            continue;
        };
        let Some(reviewed) = view
            .proposal_revisions
            .get(&acceptance.reviewed_proposal_revision_id)
        else {
            continue;
        };
        let intent = ProposalEditIntent::new(original, reviewed.clone());
        if reviewed.payload != *edited_payload || intent.validate(original).is_err() {
            continue;
        }
        let ProposalAcceptanceAuthority::TuiAcceptance {
            user_source_observation_ref,
            ..
        } = &acceptance.authority_basis
        else {
            continue;
        };
        if acceptance.acceptance_event_ref != user_source_observation_ref.to_string() {
            continue;
        }
        if evidence.is_none() {
            evidence = Some(
                RecoveryEvidenceCurrentView::from_snapshot(snapshot)
                    .map_err(|_| HumanGovernanceError::Store)?,
            );
        }
        let evidence = evidence.as_ref().ok_or(HumanGovernanceError::Store)?;
        let observation = evidence
            .observation(*user_source_observation_ref)
            .ok_or(HumanGovernanceError::Store)?;
        let receipt = evidence
            .receipt_for_observation(*user_source_observation_ref)
            .ok_or(HumanGovernanceError::Store)?;
        if observation.source_observation_id == *user_source_observation_ref
            && receipt.eligible_event_manifest_ref == TUI_ACCEPTANCE_EVENT_MANIFEST_REF
            && receipt.source_ref == original.proposal_id.to_string()
            && receipt.source_revision.as_str() == original.proposal_revision_id.to_string()
        {
            return Ok(Some(accepted));
        }
    }
    Ok(None)
}

fn accepted_reauthorization_retry<'a>(
    snapshot: &ProjectionSnapshot,
    view: &'a SemanticCurrentView,
    original: &RevisionProposal,
) -> Result<Option<&'a RevisionProposal>, HumanGovernanceError> {
    let deletion = ObjectDeletionCandidateAdmissionView::from_snapshot(snapshot)
        .map_err(|_| HumanGovernanceError::Store)?
        .classify_proposal(original)
        .map_err(|_| HumanGovernanceError::Store)?
        .representative_historical_deletion()
        .cloned();
    let Some(deletion) = deletion else {
        return Ok(None);
    };
    let mut evidence = None;
    let mut matched = None;
    for accepted in view.proposals.values() {
        if accepted.status != ProposalStatus::Accepted {
            continue;
        }
        let Some(acceptance) = accepted.acceptance.as_ref() else {
            continue;
        };
        let Some(reviewed) = view
            .proposal_revisions
            .get(&acceptance.reviewed_proposal_revision_id)
        else {
            continue;
        };
        if reviewed != original {
            continue;
        }
        let ProposalAcceptanceAuthority::TuiAcceptance {
            user_source_observation_ref,
            ..
        } = &acceptance.authority_basis
        else {
            continue;
        };
        if acceptance.acceptance_event_ref != user_source_observation_ref.to_string() {
            continue;
        }
        let intent = ObjectReauthorizationIntent::new(&deletion, reviewed)
            .ok_or(HumanGovernanceError::Store)?;
        let canonical = intent
            .canonical_toml(&deletion, reviewed)
            .ok_or(HumanGovernanceError::Store)?;
        if evidence.is_none() {
            evidence = Some(
                RecoveryEvidenceCurrentView::from_snapshot(snapshot)
                    .map_err(|_| HumanGovernanceError::Store)?,
            );
        }
        let evidence = evidence.as_ref().ok_or(HumanGovernanceError::Store)?;
        let observation = evidence
            .observation(*user_source_observation_ref)
            .ok_or(HumanGovernanceError::Store)?;
        let receipt = evidence
            .receipt_for_observation(*user_source_observation_ref)
            .ok_or(HumanGovernanceError::Store)?;
        let expected_fingerprint = hex(&payload_fingerprint(1, canonical.as_bytes(), None)
            .map_err(|_| HumanGovernanceError::Store)?);
        if observation.source_observation_id != *user_source_observation_ref
            || observation.payload_fingerprint != expected_fingerprint
            || receipt.eligible_event_manifest_ref != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
            || receipt.source_ref != reviewed.proposal_id.to_string()
            || receipt.source_revision.as_str() != reviewed.proposal_revision_id.to_string()
        {
            continue;
        }
        if matched.replace(accepted).is_some() {
            return Err(HumanGovernanceError::Store);
        }
    }
    Ok(matched)
}

fn verify_edit_acceptance_cohort(
    payloads: &[JournalPayload],
    verified: &crate::capture::VerifiedCapture,
    original: &RevisionProposal,
    intent: &ProposalEditIntent,
) -> Result<(Box<RevisionProposal>, Box<RevisionProposal>), HumanGovernanceError> {
    validate_edit_capture(verified, original, intent)?;
    let expected_watermark = SourceIngestWatermark {
        source_instance_id: verified.body.source_instance_id.clone(),
        source_revision: verified.body.source_revision.clone(),
        source_sequence: 1,
        confirmed_prefix_digest: None,
    };
    if payloads
        .iter()
        .filter(|payload| matches!(payload, JournalPayload::SourceReceiptRecorded(value) if value.as_ref() == &verified.receipt))
        .count()
        != 1
        || payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::SourceObservationRecorded(value) if value.as_ref() == &verified.observation))
            .count()
            != 1
        || payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::SourceIngestWatermark(value) if value == &expected_watermark))
            .count()
            != 1
        || payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::SourceReceiptRecorded(_)))
            .count()
            != 1
        || payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::SourceObservationRecorded(_)))
            .count()
            != 1
        || payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::SourceIngestWatermark(_)))
            .count()
            != 1
    {
        return Err(HumanGovernanceError::Store);
    }
    let proposal_events = payloads
        .iter()
        .enumerate()
        .filter_map(|(index, payload)| match payload {
            JournalPayload::RevisionProposalRecorded(value)
                if value.proposal_id == original.proposal_id
                    || value.proposal_id == intent.new_proposal.proposal_id =>
            {
                Some((index, value.as_ref()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let superseded = proposal_events
        .iter()
        .filter(|(_, value)| {
            value.proposal_id == original.proposal_id && value.status == ProposalStatus::Superseded
        })
        .collect::<Vec<_>>();
    let pending = proposal_events
        .iter()
        .filter(|(_, value)| **value == intent.new_proposal)
        .collect::<Vec<_>>();
    let validating = proposal_events
        .iter()
        .filter(|(_, value)| {
            value.proposal_id == intent.new_proposal.proposal_id
                && value.status == ProposalStatus::Validating
        })
        .collect::<Vec<_>>();
    let accepted = proposal_events
        .iter()
        .filter(|(_, value)| {
            value.proposal_id == intent.new_proposal.proposal_id
                && value.status == ProposalStatus::Accepted
        })
        .collect::<Vec<_>>();
    let ([superseded], [pending], [validating], [accepted]) = (
        superseded.as_slice(),
        pending.as_slice(),
        validating.as_slice(),
        accepted.as_slice(),
    ) else {
        return Err(HumanGovernanceError::Store);
    };
    if proposal_events.len() != 4
        || !(superseded.0 < pending.0 && pending.0 < validating.0 && validating.0 < accepted.0)
        || original.validate_successor(superseded.1).is_err()
        || intent
            .new_proposal
            .validate_successor(validating.1)
            .is_err()
        || validating.1.validate_successor(accepted.1).is_err()
        || accepted.1.acceptance.as_ref().is_none_or(|acceptance| {
            acceptance.reviewed_proposal_revision_id != intent.new_proposal.proposal_revision_id
                || acceptance.reviewed_fingerprint != intent.new_proposal.fingerprint
                || acceptance.acceptance_event_ref
                    != verified.observation.source_observation_id.to_string()
        })
    {
        return Err(HumanGovernanceError::Store);
    }
    let acceptance = accepted
        .1
        .acceptance
        .as_ref()
        .ok_or(HumanGovernanceError::Store)?;
    match &acceptance.accepted_target {
        AcceptedProposalTarget::Atom {
            atom_id,
            atom_revision_id,
            ..
        } => {
            if payloads
                .iter()
                .filter(|payload| {
                    matches!(payload, JournalPayload::AtomRecorded(atom)
                    if atom.atom_id == *atom_id
                        && atom.revision_id == *atom_revision_id
                        && atom.accepted_proposal_id == Some(accepted.1.proposal_id)
                        && atom.accepted_proposal_revision_id
                            == Some(accepted.1.proposal_revision_id))
                })
                .count()
                != 1
            {
                return Err(HumanGovernanceError::Store);
            }
        }
        AcceptedProposalTarget::Procedure {
            procedure_id,
            procedure_revision_id,
            auto_full_audit,
        } => {
            let ProposalPayload::Procedure(procedure_payload) = &accepted.1.payload else {
                return Err(HumanGovernanceError::Store);
            };
            if auto_full_audit.is_some() {
                return Err(HumanGovernanceError::Store);
            }
            let materialized = payloads
                .iter()
                .filter_map(|payload| match payload {
                    JournalPayload::ProcedureRevisionRecorded(value)
                        if value.procedure_id == *procedure_id
                            && value.revision_id == *procedure_revision_id =>
                    {
                        Some(value.as_ref())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            match materialized.as_slice() {
                [procedure]
                    if procedure.draft == *procedure_payload.draft()
                        && match accepted.1.operation {
                            ProposalOperation::Create => {
                                accepted.1.target_id.is_none()
                                    && accepted.1.base_revision_id.is_none()
                                    && procedure.parent_revision_id.is_none()
                                    && procedure.revision_generation == 1
                            }
                            ProposalOperation::Replace => {
                                accepted.1.target_id
                                    == Some(ProposalTargetId::Procedure(*procedure_id))
                                    && procedure.parent_revision_id == accepted.1.base_revision_id
                            }
                            _ => false,
                        } => {}
                [] if accepted.1.operation == ProposalOperation::Replace
                    && accepted.1.target_id == Some(ProposalTargetId::Procedure(*procedure_id))
                    && accepted.1.base_revision_id == Some(*procedure_revision_id) => {}
                _ => return Err(HumanGovernanceError::Store),
            }
        }
        AcceptedProposalTarget::CoreMembership { .. } => {
            return Err(HumanGovernanceError::Store);
        }
    }
    Ok((Box::new(superseded.1.clone()), Box::new(accepted.1.clone())))
}

fn validate_current_edit_cohort(
    snapshot: &ProjectionSnapshot,
    view: &SemanticCurrentView,
    superseded: &RevisionProposal,
    accepted: &RevisionProposal,
) -> Result<(), HumanGovernanceError> {
    if view.proposals.get(&superseded.proposal_id) != Some(superseded)
        || view.proposals.get(&accepted.proposal_id) != Some(accepted)
    {
        return Err(HumanGovernanceError::Store);
    }
    match &accepted
        .acceptance
        .as_ref()
        .ok_or(HumanGovernanceError::Store)?
        .accepted_target
    {
        AcceptedProposalTarget::Atom {
            atom_id,
            atom_revision_id,
            ..
        } if view
            .atoms
            .get(atom_id)
            .is_some_and(|atom| atom.revision_id == *atom_revision_id)
            && view.atom_revisions.get(atom_revision_id) == view.atoms.get(atom_id) =>
        {
            Ok(())
        }
        AcceptedProposalTarget::Procedure {
            procedure_id,
            procedure_revision_id,
            auto_full_audit: None,
        } => {
            let ProposalPayload::Procedure(payload) = &accepted.payload else {
                return Err(HumanGovernanceError::Store);
            };
            let rows = snapshot
                .data_rows()
                .filter(|row| {
                    row.object_kind.as_deref() == Some("procedure_revision")
                        && row.object_id.as_deref() == Some(&procedure_id.to_string())
                        && row.current_revision_id.as_deref()
                            == Some(&procedure_revision_id.to_string())
                })
                .collect::<Vec<_>>();
            let [row] = rows.as_slice() else {
                return Err(HumanGovernanceError::Store);
            };
            let JournalPayload::ProcedureRevisionRecorded(procedure) = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(HumanGovernanceError::Store)?,
            )
            .map_err(|_| HumanGovernanceError::Store)?
            else {
                return Err(HumanGovernanceError::Store);
            };
            if procedure.procedure_id != *procedure_id
                || procedure.revision_id != *procedure_revision_id
                || procedure.draft != *payload.draft()
            {
                return Err(HumanGovernanceError::Store);
            }
            Ok(())
        }
        _ => Err(HumanGovernanceError::Store),
    }
}

fn verify_acceptance_cohort(
    payloads: &[JournalPayload],
    verified: &crate::capture::VerifiedCapture,
    reviewed: &RevisionProposal,
) -> Result<RevisionProposal, HumanGovernanceError> {
    validate_acceptance_capture(verified, reviewed)?;
    verify_acceptance_payload_cohort(payloads, verified, reviewed)
}

fn verify_acceptance_payload_cohort(
    payloads: &[JournalPayload],
    verified: &crate::capture::VerifiedCapture,
    reviewed: &RevisionProposal,
) -> Result<RevisionProposal, HumanGovernanceError> {
    let mut receipt_count = 0;
    let mut observation_count = 0;
    let mut watermark_count = 0;
    for payload in payloads {
        match payload {
            JournalPayload::SourceReceiptRecorded(value) if value.as_ref() == &verified.receipt => {
                receipt_count += 1;
            }
            JournalPayload::SourceObservationRecorded(value)
                if value.as_ref() == &verified.observation =>
            {
                observation_count += 1;
            }
            JournalPayload::SourceIngestWatermark(value)
                if value
                    == &SourceIngestWatermark {
                        source_instance_id: verified.body.source_instance_id.clone(),
                        source_revision: verified.body.source_revision.clone(),
                        source_sequence: 1,
                        confirmed_prefix_digest: None,
                    } =>
            {
                watermark_count += 1;
            }
            _ => {}
        }
    }
    if receipt_count != 1 || observation_count != 1 || watermark_count != 1 {
        return Err(HumanGovernanceError::Store);
    }
    if payloads
        .iter()
        .filter(|payload| matches!(payload, JournalPayload::SourceReceiptRecorded(_)))
        .count()
        != 1
        || payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::SourceObservationRecorded(_)))
            .count()
            != 1
        || payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::SourceIngestWatermark(_)))
            .count()
            != 1
    {
        return Err(HumanGovernanceError::Store);
    }
    let accepted = payloads
        .iter()
        .filter_map(|payload| match payload {
            JournalPayload::RevisionProposalRecorded(value)
                if value.proposal_id == reviewed.proposal_id
                    && value.status == ProposalStatus::Accepted
                    && value.acceptance.as_ref().is_some_and(|acceptance| {
                        acceptance.reviewed_proposal_revision_id == reviewed.proposal_revision_id
                            && acceptance.reviewed_fingerprint == reviewed.fingerprint
                            && acceptance.acceptance_event_ref
                                == verified.observation.source_observation_id.to_string()
                            && matches!(
                                acceptance.authority_basis,
                                ProposalAcceptanceAuthority::TuiAcceptance {
                                    user_source_observation_ref,
                                    ..
                                } if user_source_observation_ref
                                    == verified.observation.source_observation_id
                            )
                    }) =>
            {
                Some(value.as_ref())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [accepted] = accepted.as_slice() else {
        return Err(HumanGovernanceError::Store);
    };
    Ok((*accepted).clone())
}

fn verify_reauthorization_cohort(
    payloads: &[JournalPayload],
    verified: &crate::capture::VerifiedCapture,
    deletion: &ObjectDeletionLedgerEvent,
    reviewed: &RevisionProposal,
) -> Result<RevisionProposal, HumanGovernanceError> {
    let intent =
        ObjectReauthorizationIntent::new(deletion, reviewed).ok_or(HumanGovernanceError::Store)?;
    let canonical = intent
        .canonical_toml(deletion, reviewed)
        .ok_or(HumanGovernanceError::Store)?;
    validate_reauthorization_capture(verified, reviewed, &canonical)?;
    verify_acceptance_payload_cohort(payloads, verified, reviewed)
}

fn validate_acceptance_capture(
    verified: &crate::capture::VerifiedCapture,
    reviewed: &RevisionProposal,
) -> Result<(), HumanGovernanceError> {
    let canonical = tui_acceptance_event_payload(
        reviewed.proposal_id,
        reviewed.proposal_revision_id,
        &reviewed.fingerprint,
    );
    validate_acceptance_capture_payload(verified, reviewed, &canonical, "tui-accept")
}

fn validate_edit_capture(
    verified: &crate::capture::VerifiedCapture,
    original: &RevisionProposal,
    intent: &ProposalEditIntent,
) -> Result<(), HumanGovernanceError> {
    intent.validate(original)?;
    let canonical = intent.canonical_toml(original)?;
    validate_acceptance_capture_payload(verified, original, &canonical, "tui-accept")
}

fn validate_reauthorization_capture(
    verified: &crate::capture::VerifiedCapture,
    source: &RevisionProposal,
    canonical: &str,
) -> Result<(), HumanGovernanceError> {
    validate_acceptance_capture_payload(verified, source, canonical, "tui-reauthorize")
}

fn validate_acceptance_capture_payload(
    verified: &crate::capture::VerifiedCapture,
    source: &RevisionProposal,
    canonical: &str,
    record_prefix: &str,
) -> Result<(), HumanGovernanceError> {
    let expected_record = format!(
        "{record_prefix}-{}-{}",
        source.proposal_id, source.proposal_revision_id
    );
    let expected_instance = format!("tui-acceptance:{}", source.proposal_id);
    let expected_fingerprint = hex(&payload_fingerprint(1, canonical.as_bytes(), None)
        .map_err(|_| HumanGovernanceError::Store)?);
    if verified.body.source_instance_id.as_str() != expected_instance
        || verified.body.source_revision.as_str() != source.proposal_revision_id.to_string()
        || verified.body.source_record_identity.as_str() != expected_record
        || verified.body.source_ref != source.proposal_id.to_string()
        || verified.body.source_session_ref != "human-governance"
        || verified.body.source_sequence != 1
        || verified.body.source_sequence_origin != Some(1)
        || verified.body.identity_strength != IdentityStrength::StableNative
        || verified.body.source_kind != EvidenceSourceKind::Other
        || verified.body.identity_domain != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
        || verified.body.adapter_revision != 1
        || verified.body.adapter_manifest_ref != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
        || verified.body.eligible_event_manifest_ref != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
        || verified.body.parser_revision != 1
        || verified.body.canonicalization_revision != 1
        || verified.body.source_role != SourceRole::User
        || verified.body.content_trust != ContentTrust::UserStatement
        || verified.body.capture_completeness != CaptureCompleteness::Complete
        || verified.body.observation_role != ObservationRole::Message
        || verified.body.archive_mode != SourceArchiveMode::Exact
        || verified.body.protected_secret_digest.is_some()
        || !verified.body.redaction_spans.is_empty()
        || verified.body.protected_length != canonical.len() as u64
        || verified.body.original_length != canonical.len() as u64
        || verified.observation.payload_fingerprint != expected_fingerprint
    {
        return Err(HumanGovernanceError::Store);
    }
    Ok(())
}

fn current_negative_review_revision(
    snapshot: &ProjectionSnapshot,
    negative_evidence_id: ProcedureNegativeEvidenceId,
) -> Option<String> {
    snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("procedure_negative_review"))
        .filter_map(|row| serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok())
        .filter_map(|payload| match payload {
            JournalPayload::ProcedureNegativeReviewRecorded(value)
                if value.negative_evidence_id == negative_evidence_id =>
            {
                Some(*value)
            }
            _ => None,
        })
        .max_by_key(|value: &ProcedureNegativeReviewEvent| value.review_generation)
        .map(|value| value.review_event_id.to_string())
}

fn command_context(
    request_id: RequestId,
    effective_config_hash: [u8; 32],
) -> Result<ProposalCommandContext, HumanGovernanceError> {
    Ok(ProposalCommandContext {
        command_id: CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?,
        occurred_at_us: now_us()?,
        effective_config_hash,
        algorithm_revision: ALGORITHM_REVISION.into(),
    })
}

fn work_command_context(
    request_id: RequestId,
    effective_config_hash: [u8; 32],
) -> Result<WorkCommandContext, HumanGovernanceError> {
    Ok(WorkCommandContext {
        command_id: CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?,
        occurred_at_us: now_us()?,
        effective_config_hash,
        algorithm_revision: ALGORITHM_REVISION,
    })
}

fn current_competing_revision(
    snapshot: &ProjectionSnapshot,
    expected_revision_id: RevisionId,
) -> Option<String> {
    match select_competing_selected(snapshot, expected_revision_id).ok()? {
        CompetingSelectedLookup::Conflict {
            current_revision_id,
        } => Some(current_revision_id.to_string()),
        CompetingSelectedLookup::Available(_) | CompetingSelectedLookup::Unavailable { .. } => {
            Some(expected_revision_id.to_string())
        }
    }
}

fn current_attempt_revision(
    snapshot: &ProjectionSnapshot,
    expected_revision_id: RevisionId,
) -> Option<String> {
    match select_mark_new_attempt(snapshot, expected_revision_id).ok()? {
        MarkNewAttemptLookup::Conflict {
            current_revision_id,
        }
        | MarkNewAttemptLookup::NoDelta {
            current_revision_id,
        } => Some(current_revision_id.to_string()),
        MarkNewAttemptLookup::Available { source } => Some(source.revision_id.to_string()),
        MarkNewAttemptLookup::Unavailable { .. } => Some(expected_revision_id.to_string()),
    }
}

fn deletion_revision_ref(event: &evertrace_domain::purge::ObjectDeletionLedgerEvent) -> String {
    format!("deletion-generation-{}", event.deletion_generation)
}

fn current_object_deletion_revision(
    snapshot: &ProjectionSnapshot,
    target: ObjectDeletionTarget,
) -> Option<String> {
    match select_object_forget(snapshot, target).ok()? {
        ObjectForgetLookup::Available(preview) => Some(preview.current_revision_id.to_string()),
        ObjectForgetLookup::NoDelta(event) => Some(deletion_revision_ref(&event)),
        ObjectForgetLookup::Unavailable => None,
    }
}

fn scope_purge_revision_ref(progress: &evertrace_domain::purge::ScopePurgeProgress) -> String {
    format!(
        "repository-purge-generation-{}-{}",
        progress.deletion_generation,
        match progress.stage {
            evertrace_domain::purge::ScopePurgeStage::Pending => "pending",
            evertrace_domain::purge::ScopePurgeStage::ProjectionClosed => "projection-closed",
            evertrace_domain::purge::ScopePurgeStage::PhysicalDeleting => "physical-deleting",
            evertrace_domain::purge::ScopePurgeStage::Purged => "purged",
        }
    )
}

fn current_repository_purge_revision(
    snapshot: &ProjectionSnapshot,
    repository_id: RepositoryId,
) -> Option<String> {
    let current = evertrace_store::ScopePurgeCurrentView::from_snapshot(snapshot).ok()?;
    current
        .events
        .get(&repository_id)
        .map(scope_purge_revision_ref)
}

fn now_us() -> Result<i64, HumanGovernanceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_micros()).ok())
        .ok_or(HumanGovernanceError::Store)
}

fn valid_ref(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_REF && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use evertrace_domain::work::ExecutionLane;

    #[test]
    fn recovery_reason_codes_are_stably_sorted() {
        assert_eq!(
            sorted_reason_codes(&[
                RecoveryReasonCode::LateTimeout,
                RecoveryReasonCode::CaptureComplete,
                RecoveryReasonCode::DaemonCaptureFailed,
            ]),
            vec![
                RecoveryReasonCode::CaptureComplete,
                RecoveryReasonCode::DaemonCaptureFailed,
                RecoveryReasonCode::LateTimeout,
            ]
        );
    }

    #[test]
    fn execution_lane_detail_is_exact_and_visibility_is_sorted() {
        let lane_id = ExecutionLaneId::new_v7();
        let receipt_id = CaptureReceiptId::new_v7();
        let lane = ExecutionLane {
            execution_lane_id: lane_id,
            lane_revision: 1,
            predecessor_revision: None,
            host_session_id: "session:one".into(),
            agent_id: "agent:one".into(),
            host_lane_key: "lane:one".into(),
            incarnation_ref: "incarnation:one".into(),
            parent_lane_id: None,
            parent_host_lane_key: None,
            spawn_event_ref: None,
            terminal_event_ref: None,
            termination_evidence_refs: Vec::new(),
            delegated_goal_ref: None,
            delegated_target_refs: Vec::new(),
            delegated_acceptance_refs: Vec::new(),
            status: LaneStatus::Active,
            terminal_kind: None,
            liveness_state: LivenessState::Live,
            liveness_probe_refs: Vec::new(),
            finalized: false,
            event_watermark: 3,
            adapter_manifest_ids: vec!["manifest:one".into()],
            active_capture_receipt_revision_id: receipt_id,
            coverage_level: CoverageLevel::Full,
            source_coverage: SourceCoverage::Open,
            pairing_integrity: PairingIntegrity::Complete,
            payload_integrity: PayloadIntegrity::Complete,
            ordering_integrity: OrderingIntegrity::Complete,
            reasoning_visibility: vec![ReasoningVisibility::Summary, ReasoningVisibility::Raw],
            operation_ids: Vec::new(),
            correction_reason: None,
        };
        let mut row = object_row("lane-row", 3);
        row.object_kind = Some("execution_lane".into());
        row.object_id = Some(lane_id.to_string());
        row.current_revision_id = Some(format!("{lane_id}@1"));
        row.payload_json = Some(
            serde_json::to_string(&JournalPayload::ExecutionLaneRecorded(Box::new(lane))).unwrap(),
        );

        let (recovery, worktree, execution, system) = typed_current_detail(&row).unwrap();
        assert!(recovery.is_none());
        assert!(worktree.is_none());
        assert!(system.is_none());
        assert!(matches!(
            execution,
            Some(HumanExecutionIntegrityDetail::Lane {
                reasoning_visibility,
                ..
            }) if reasoning_visibility
                == vec![ReasoningVisibility::Raw, ReasoningVisibility::Summary]
        ));
    }

    #[test]
    fn support_related_uses_exact_unique_current_rows() {
        let contract_revision = RevisionId::new_v7();
        let validation_revision = RevisionId::new_v7();
        let support_revision = RevisionId::new_v7();
        let missing_support_revision = RevisionId::new_v7();
        let authorization_revision = RevisionId::new_v7();
        let successor = RevisionId::new_v7().to_string();
        let mut support_revision_refs = vec![support_revision, missing_support_revision];
        support_revision_refs.sort();
        let contract = GlobalSuccessorSupportContract {
            support_contract_revision_id: contract_revision,
            successor_revision_or_membership_ref: successor.clone(),
            support_revision_refs,
            authorization_revision_refs: vec![authorization_revision],
            evidence_cohort_hash: [1; 32],
            support_threshold_snapshot: SupportThresholdSnapshot {
                minimum_surviving_support: 1,
                require_authorization: false,
            },
            promotion_proposal_revision_id: RevisionId::new_v7(),
            promotion_validator_revision: 1,
            applicability_contract_hash: [2; 32],
            created_at_us: 1,
        };
        let pending = GlobalSupportValidationEvent {
            validation_revision_id: RevisionId::new_v7(),
            support_contract_ref: contract_revision,
            successor_ref: successor.clone(),
            dependency_generation: 1,
            state: GlobalSupportState::RevalidationPending,
            provenance_degraded: false,
            surviving_support_refs: Vec::new(),
            invalid_or_missing_refs: Vec::new(),
            trigger_refs: vec!["trigger:pending".into()],
            validator_revision: 1,
            created_at_us: 2,
        };
        let validation = GlobalSupportValidationEvent {
            validation_revision_id: validation_revision,
            support_contract_ref: contract_revision,
            successor_ref: successor,
            dependency_generation: 1,
            state: GlobalSupportState::Valid,
            provenance_degraded: true,
            surviving_support_refs: vec![support_revision],
            invalid_or_missing_refs: vec![missing_support_revision],
            trigger_refs: vec!["missing:related".into()],
            validator_revision: 1,
            created_at_us: 3,
        };
        let mut contract_row = object_row(
            &format!("object:atom:global_support_contract:{contract_revision}"),
            1,
        );
        contract_row.object_family = Some(ObjectFamily::Atom);
        contract_row.object_kind = Some("global_support_contract".into());
        contract_row.object_id = Some(contract_revision.to_string());
        contract_row.current_revision_id = Some(contract_revision.to_string());
        contract_row.lifecycle = Some("immutable".into());
        contract_row.payload_json = Some(
            serde_json::to_string(&JournalPayload::GlobalSupportContractRecorded(Box::new(
                contract.clone(),
            )))
            .unwrap(),
        );
        let mut pending_row = object_row(
            &format!(
                "object:atom:global_support_validation:{}",
                pending.validation_revision_id
            ),
            2,
        );
        pending_row.object_family = Some(ObjectFamily::Atom);
        pending_row.object_kind = Some("global_support_validation".into());
        pending_row.object_id = Some(contract_revision.to_string());
        pending_row.current_revision_id = Some(pending.validation_revision_id.to_string());
        pending_row.lifecycle = Some("revalidation_pending".into());
        pending_row.payload_json = Some(
            serde_json::to_string(&JournalPayload::GlobalSupportValidationRecorded(Box::new(
                pending,
            )))
            .unwrap(),
        );
        let mut validation_row = object_row(
            &format!("object:atom:global_support_validation:{validation_revision}"),
            3,
        );
        validation_row.object_family = Some(ObjectFamily::Atom);
        validation_row.object_kind = Some("global_support_validation".into());
        validation_row.object_id = Some(contract_revision.to_string());
        validation_row.current_revision_id = Some(validation_revision.to_string());
        validation_row.lifecycle = Some("valid".into());
        validation_row.payload_json = Some(
            serde_json::to_string(&JournalPayload::GlobalSupportValidationRecorded(Box::new(
                validation.clone(),
            )))
            .unwrap(),
        );
        let mut support_row = object_row("support", 1);
        support_row.object_family = Some(ObjectFamily::Atom);
        support_row.object_kind = Some("atom_revision".into());
        support_row.object_id = Some("atom:related".into());
        support_row.current_revision_id = Some(support_revision.to_string());
        let mut missing_support_row = object_row("missing-support", 1);
        missing_support_row.object_family = Some(ObjectFamily::Atom);
        missing_support_row.object_kind = Some("atom_revision".into());
        missing_support_row.object_id = Some("atom:missing-related".into());
        missing_support_row.current_revision_id = Some(missing_support_revision.to_string());
        let mut authorization_row = object_row("authorization", 1);
        authorization_row.object_family = Some(ObjectFamily::RevisionProposal);
        authorization_row.object_kind = Some("revision_proposal_revision".into());
        authorization_row.object_id = Some("proposal:related".into());
        authorization_row.current_revision_id = Some(authorization_revision.to_string());
        let mut ambiguous_one = object_row("ambiguous-one", 1);
        ambiguous_one.object_family = Some(ObjectFamily::Atom);
        ambiguous_one.object_kind = Some("atom_revision".into());
        ambiguous_one.object_id = Some("ambiguous:related".into());
        let mut ambiguous_two = object_row("ambiguous-two", 1);
        ambiguous_two.object_family = Some(ObjectFamily::Atom);
        ambiguous_two.object_kind = Some("atom_revision".into());
        ambiguous_two.object_id = Some("ambiguous:related".into());
        let snapshot = ProjectionSnapshot {
            frontier: 3,
            rows: vec![
                contract_row,
                pending_row.clone(),
                validation_row.clone(),
                support_row,
                missing_support_row,
                authorization_row,
                ambiguous_one,
                ambiguous_two,
            ],
        };

        let mut refs = support_dependency_refs(&validation, &contract);
        assert_eq!(
            current_support_source(&snapshot, &validation_row).unwrap(),
            Some((validation.clone(), contract.clone()))
        );
        assert!(
            current_support_source(&snapshot, &pending_row)
                .unwrap()
                .is_none()
        );
        let mut malformed_validation = validation_row.clone();
        malformed_validation.lifecycle = Some("revalidation_pending".into());
        assert!(support_validation(&malformed_validation).is_err());
        let mut malformed_contract = snapshot.clone();
        malformed_contract.rows[0].object_family = Some(ObjectFamily::Work);
        assert!(current_support_source(&malformed_contract, &validation_row).is_err());
        let inbox_snapshot = ProjectionSnapshot {
            frontier: 3,
            rows: snapshot.rows[..3].to_vec(),
        };
        assert!(actionable_inbox_rows(&inbox_snapshot).unwrap().is_empty());
        refs.insert("ambiguous:related".into());
        let (rows, next) = related_rows(&snapshot, refs, None, 64).unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row.row_id.as_str())
                .collect::<Vec<_>>(),
            vec!["authorization", "missing-support", "support"]
        );
        assert!(next.is_none());
    }

    #[test]
    fn only_current_candidate_episode_is_actionable() {
        let candidate = object_row("episode-r1", 1);
        let confirmed = object_row("episode-r2", 2);
        let mut selected = BTreeMap::new();
        select_current(
            &mut selected,
            "episode:one".into(),
            1,
            &candidate,
            boundary_candidate_actionable(BoundaryStatus::Candidate),
        )
        .unwrap();
        select_current(
            &mut selected,
            "episode:one".into(),
            2,
            &confirmed,
            boundary_candidate_actionable(BoundaryStatus::Confirmed),
        )
        .unwrap();
        assert_eq!(
            selected.get("episode:one"),
            Some(&(2, "episode-r2".into(), false))
        );

        let mut current_candidate = BTreeMap::new();
        select_current(
            &mut current_candidate,
            "episode:two".into(),
            1,
            &candidate,
            boundary_candidate_actionable(BoundaryStatus::Candidate),
        )
        .unwrap();
        assert_eq!(
            current_candidate.get("episode:two"),
            Some(&(1, "episode-r1".into(), true))
        );
    }

    fn object_row(row_id: &str, source_event_seq: u64) -> ObjectRow {
        ObjectRow {
            row_id: row_id.into(),
            row_kind: ObjectRowKind::Data,
            row_class: Some(ObjectRowClass::Object),
            object_family: Some(ObjectFamily::Work),
            object_kind: Some("work_episode".into()),
            object_id: Some("episode:one".into()),
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
            payload_json: None,
            source_event_seq,
            projection_generation: 1,
        }
    }
}
