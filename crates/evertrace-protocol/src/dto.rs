pub use evertrace_domain::query::ExactReadQuery;
use evertrace_domain::{
    ids::{
        AttemptId, JobId, ProcedureNegativeEvidenceId, RepositoryId, RevisionProposalId, WorktreeId,
    },
    procedure::ProcedureNegativeReviewStatus,
    purge::{ObjectDeletionTarget, ObjectReauthorizationRef},
    revision::RevisionId,
    semantic::{
        AtomProposalPayload, CoreMembershipProposalPayload, GlobalSupportState,
        ProcedureProposalPayload, ProposalEligibility, ProposalOperation, ProposalPayload,
        ProposalStatus, ProposalTargetId, ProposalTargetKind, RevisionProposal,
        SupportThresholdSnapshot,
    },
};
use serde::{Deserialize, Serialize};

pub use evertrace_domain::{ids::RequestId, query::MetadataReadOutcome};

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
    Web,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionContext {
    pub connection_id: String,
    pub client_kind: ClientKind,
    /// Kernel observations, never supplied by the handshake or serialized.
    pub peer_credentials: Option<PeerCredentials>,
    /// Daemon-verified launcher at handshake, preserved only on this connection.
    pub web_launcher: bool,
    /// Its weak form lets an in-flight observer detect connection termination.
    pub connection_lifetime: std::sync::Arc<()>,
    /// Server-only association from a successfully sent, budgeted response.
    pub mcp_returned: Option<(
        evertrace_domain::ids::RequestId,
        Vec<evertrace_domain::revision::RevisionId>,
    )>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
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
    State,
    ReadExact {
        query: Box<evertrace_domain::query::ExactReadQuery>,
    },
    ReadRevisionPair {
        query: Box<evertrace_domain::query::RevisionCompareQuery>,
    },
    ReadBatch {
        query: Box<evertrace_domain::query::MetadataBatchQuery>,
    },
    Jobs {
        query: Box<evertrace_domain::query::JobsReadQuery>,
    },
    CompiledProjections {
        query: evertrace_domain::query::CompiledProjectionQuery,
        expected_frontier: Option<u64>,
        after: Option<String>,
        limit: u16,
    },
    Search {
        query: Box<evertrace_domain::query::HumanSearchQuery>,
    },
    BrowseMemories {
        query: evertrace_domain::query::MemoryBrowseQuery,
        expected_frontier: Option<u64>,
        after: Option<String>,
        limit: u16,
    },
    List {
        surface: HumanSurface,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        system_selection: Option<HumanSystemListSelection>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        explorer_selection: Option<HumanExplorerListSelection>,
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
    ProposalReview {
        proposal_id: RevisionProposalId,
        expected_revision_id: RevisionId,
        expected_frontier: u64,
        expected_digest: Option<String>,
    },
    WebAcceptanceOutcome {
        request_id: RequestId,
        expected_frontier: u64,
        review: ProposalConfirmation,
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
pub enum HumanSystemListSelection {
    Jobs,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanExplorerListSelection {
    Memories,
    Capture,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryAccessAction {
    Disable,
    Enable,
    Rescan,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanActionRequest {
    WebAccept {
        review: ProposalConfirmation,
    },
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
    PurgeRepository {
        repository_id: evertrace_domain::ids::RepositoryId,
        repository_confirmation: String,
        expected_repository_revision: u32,
        expected_deletion_generation: u64,
    },
    RepositoryAccess {
        repository_id: evertrace_domain::ids::RepositoryId,
        expected_repository_revision: u32,
        action: RepositoryAccessAction,
        worktree_id: Option<evertrace_domain::ids::WorktreeId>,
        inventory_ref: Option<JobId>,
    },
    CreateBackup,
    CollectGarbage,
    VerifyBackup {
        backup_job_id: JobId,
    },
    Unavailable {
        action: HumanUnavailableAction,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanGovernanceRequest {
    Export {
        selections: Vec<HumanExportSelection>,
    },
    Read {
        request: HumanReadRequest,
    },
    Act {
        expected_frontier: u64,
        action: HumanActionRequest,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanExportSelection {
    pub object_ref: String,
    pub expected_revision_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanExportStatus {
    Published,
    PublicationUncertain,
    Conflict,
    Denied,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanExportResult {
    pub status: HumanExportStatus,
    pub path: Option<String>,
    pub frontier: u64,
    pub object_count: u16,
    pub total_bytes: u64,
    pub reason: Option<String>,
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
    ProposalRevision,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_coverage: Option<evertrace_domain::inventory::CapabilityCoverageSummary>,
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
pub struct HumanRepositoryPurgePreview {
    pub repository_id: evertrace_domain::ids::RepositoryId,
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
    pub blockers: Vec<evertrace_domain::purge::RepositoryPurgeBlocker>,
    pub downstream_support_revalidation_count: u32,
    pub dependent_procedure_review_hold_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSnapshotItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reading_preview: Option<HumanMemoryPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_detail: Option<HumanSemanticDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_base: Option<HumanSemanticDetail>,
    pub item_kind: HumanItemKind,
    pub proposal: Option<HumanProposalMetadata>,
    pub proposal_review: Option<HumanProposalReview>,
    pub support_detail: Option<HumanSupportDetail>,
    pub competing_detail: Option<HumanCompetingDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forget_preview: Option<Box<HumanForgetPreview>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_purge_preview: Option<Box<HumanRepositoryPurgePreview>>,
    pub negative_review: Option<HumanNegativeReviewMetadata>,
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
    pub native_event_time_us: Option<i64>,
    pub source_event_seq: u64,
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
pub struct HumanBackupTableState {
    pub version: Option<u64>,
    pub frontier: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanBackupValidationResult {
    VerifiedBeforePublish,
    VerifyJobPassed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanBackupSummary {
    pub frontier: u64,
    pub journal: HumanBackupTableState,
    pub objects: HumanBackupTableState,
    pub relations: Option<HumanBackupTableState>,
    pub search: Option<HumanBackupTableState>,
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
    pub validation_result: HumanBackupValidationResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanJobDetail {
    /// Current capability only; never an execution audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_history_cleanup_availability: Option<HumanNativeHistoryCleanupAvailability>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_summary: Option<HumanBackupSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gc_summary: Option<HumanGcSummary>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanNativeHistoryCleanupAvailability {
    ExternalReaderExclusionUnverified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanGcSummary {
    pub examined_files: u32,
    pub marked_candidates: u32,
    pub deleted_count: u32,
    pub deleted_bytes: u64,
    pub unknown_count: u32,
    pub mark_watermark: u64,
    pub sweep_watermark: u64,
    pub checksum: String,
    pub conservative_prune: Vec<HumanConservativePruneResult>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanConservativePruneResult {
    pub table: String,
    pub bytes_removed: Option<u64>,
    pub old_versions: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanSystemDetail {
    Repository {
        repository_id: RepositoryId,
        repository_revision: u32,
        user_disabled: bool,
        trust_revoked: bool,
        revalidated_inventory_ref: Option<JobId>,
        worktree_id: Option<WorktreeId>,
    },
    CapabilityInventory {
        job_id: JobId,
        repository_id: RepositoryId,
        repository_revision: u32,
        worktree_id: WorktreeId,
        cwd: String,
        state: String,
        source_count: Option<u32>,
        signature_count: Option<u32>,
        unobserved_source_count: Option<u32>,
        unknown_contract_count: Option<u32>,
        asset_names: Vec<String>,
    },
    SessionImport {
        session_id: String,
        source_instance_id: String,
        body_state: String,
        access: String,
        workspace: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repository_read_restrictions: Option<Vec<RepositoryId>>,
    },
    Job {
        detail: Box<HumanJobDetail>,
    },
    Config {
        config_version: u32,
        effective_config_hash: [u8; 32],
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reload: Option<ConfigReloadAudit>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigReloadAudit {
    pub previous_config_hash: [u8; 32],
    pub outcome: ConfigReloadOutcome,
    pub source: ConfigReloadSource,
    pub actor: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigReloadOutcome {
    Prepared,
    Applied,
    Rejected,
    RestartRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigReloadSource {
    Startup,
    Watcher,
    Cli,
    Tui,
}

impl ConfigReloadAudit {
    fn validate(&self) -> bool {
        !self.actor.is_empty()
            && self.actor.len() <= 128
            && !self.actor.chars().any(char::is_control)
    }
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
    Unknown,
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
    RecordWindow {
        page: Box<evertrace_domain::query::ExactRecordWindow>,
    },
    SourceWindow {
        page: Box<evertrace_domain::query::ExactSourceWindow>,
    },
    StoredFields {
        page: Box<evertrace_domain::query::ExactStoredFields>,
    },
    RevisionPair {
        page: Box<evertrace_domain::query::RevisionPairFields>,
    },
    MetadataBatch {
        page: Box<evertrace_domain::query::ObjectReadBatch>,
    },
    Jobs {
        page: Box<evertrace_domain::query::ObjectReadJobs>,
    },
    State {
        state: Box<evertrace_domain::query::ObjectReadState>,
    },
    CompiledProjections {
        page: Box<evertrace_domain::query::CompiledProjectionPage>,
    },
    Search {
        page: Box<evertrace_domain::query::HumanSearchPage>,
    },
    MemoryPage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        diagnostics: Option<Box<HumanDiagnostics>>,
        frontier: u64,
        status: HumanSnapshotStatus,
        degraded_reasons: Vec<HumanDegradedReason>,
        items: Vec<HumanSnapshotItem>,
        next_cursor: Option<String>,
        query: evertrace_domain::query::MemoryBrowseQuery,
        total_count: Option<u64>,
        matching_count: Option<u64>,
        scope_available: bool,
        counts_complete: bool,
        unresolved_scope_count: u64,
    },
    Export {
        result: HumanExportResult,
    },
    Snapshot {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        diagnostics: Option<Box<HumanDiagnostics>>,
        frontier: u64,
        status: HumanSnapshotStatus,
        degraded_reasons: Vec<HumanDegradedReason>,
        items: Vec<HumanSnapshotItem>,
        next_cursor: Option<String>,
    },
    ProposalReview {
        frontier: u64,
        item: Option<Box<HumanSnapshotItem>>,
        confirmation_digest: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        web_accept_available: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        core_anchor: Option<Box<HumanSemanticDetail>>,
    },
    Action {
        result: HumanActionResult,
    },
    Conflict {
        current_frontier: u64,
        current_revision_ref: Option<String>,
    },
}

/// Bind the complete permission-filtered review, not a browser-supplied statement of authority.
pub fn proposal_confirmation_digest(item: &HumanSnapshotItem, frontier: u64) -> Option<String> {
    let review = item
        .proposal_review
        .as_ref()
        .filter(|review| review.proposal.status.is_open())?;
    let digest = review_intent(item, frontier)
        .map(|intent| intent.review_digest)
        .or_else(|| {
            evertrace_domain::semantic::proposal_review_digest(
                frontier,
                review,
                &item.proposal_base,
            )
        })?;
    Some(evertrace_domain::evidence::hex(&digest))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalConfirmation {
    pub proposal_id: RevisionProposalId,
    pub expected_revision_id: RevisionId,
    pub expected_digest: String,
}

fn review_intent(
    item: &HumanSnapshotItem,
    frontier: u64,
) -> Option<evertrace_domain::semantic::WebAcceptanceIntent> {
    let review = item.proposal_review.as_ref().filter(|review| {
        review.plain_accept_eligible
            && !review.merge_and_accept_eligible
            && review.reauthorization.is_none()
    })?;
    if let Some(revision) = review.proposal.base_revision_id {
        let base = item
            .proposal_base
            .as_ref()
            .filter(|base| base.state == HumanContentState::Ready)?;
        let Some(HumanSemanticContent::Procedure(base)) = base.content.as_ref() else {
            return None;
        };
        if base.revision_id != revision
            || review.proposal.target_id != Some(ProposalTargetId::Procedure(base.procedure_id))
        {
            return None;
        }
    }
    evertrace_domain::semantic::WebAcceptanceIntent::for_review(
        &review.proposal,
        frontier,
        review.capability_coverage.as_ref(),
    )
}

pub fn web_acceptance_intent(
    item: &HumanSnapshotItem,
    frontier: u64,
    digest: &str,
    core_anchor: Option<&HumanSemanticDetail>,
) -> Option<evertrace_domain::semantic::WebAcceptanceIntent> {
    item.proposal_review
        .as_ref()
        .filter(|review| {
            review
                .proposal
                .core_creation()
                .is_none_or(|(revision, scope)| {
                    core_anchor.is_some_and(|detail| {
                        matches!(&detail.content, Some(HumanSemanticContent::Atom(atom))
                if atom.revision_id == revision && scope.permits_atom(atom))
                    })
                })
        })
        .and_then(|_| review_intent(item, frontier))
        .filter(|intent| evertrace_domain::evidence::hex(&intent.review_digest) == digest)
}

impl HumanGovernanceRequest {
    pub fn is_web_acceptance(&self) -> bool {
        matches!(
            self,
            Self::Act {
                action: HumanActionRequest::WebAccept { .. },
                ..
            }
        )
    }

    pub fn validate(&self) -> bool {
        match self {
            Self::Export { selections } => {
                !selections.is_empty()
                    && selections.len() <= 64
                    && selections.iter().all(|item| {
                        valid_ref(&item.object_ref)
                            && item.expected_revision_ref.as_deref().is_none_or(valid_ref)
                    })
            }
            Self::Read { request } => request.validate(),
            Self::Act {
                action,
                expected_frontier,
            } => (!self.is_web_acceptance() || *expected_frontier != 0) && action.validate(),
        }
    }
}

impl HumanReadRequest {
    fn validate(&self) -> bool {
        match self {
            Self::State => true,
            Self::ReadExact { query } => query.validate(),
            Self::ReadRevisionPair { query } => query.validate().is_ok(),
            Self::ReadBatch { query } => query.validate(),
            Self::Jobs { query } => query.validate(),
            Self::CompiledProjections {
                query,
                expected_frontier,
                after,
                limit,
            } => {
                query.validate().is_ok()
                    && (1..=64).contains(limit)
                    && (!matches!(
                        query,
                        evertrace_domain::query::CompiledProjectionQuery::Entries { .. }
                    ) || *limit <= 8 && expected_frontier.is_some())
                    && after
                        .as_ref()
                        .is_none_or(|v| !v.is_empty() && v.len() <= 4096)
            }
            Self::Search { query } => query.validate().is_ok(),
            Self::BrowseMemories {
                query,
                expected_frontier,
                after,
                limit,
            } => {
                query.validate().is_ok()
                    && (1..=HUMAN_PAGE_LIMIT).contains(limit)
                    && after
                        .as_ref()
                        .is_none_or(|value| value.len() <= 2048 && expected_frontier.is_some())
            }
            Self::List {
                surface,
                system_selection,
                explorer_selection,
                after,
                limit,
                ..
            } => {
                (system_selection.is_none() || *surface == HumanSurface::System)
                    && (explorer_selection.is_none() || *surface == HumanSurface::Explorer)
                    && (1..=HUMAN_PAGE_LIMIT).contains(limit)
                    && after.as_deref().is_none_or(valid_ref)
            }
            Self::Detail {
                object_ref,
                expected_revision_ref,
                ..
            } => valid_ref(object_ref) && expected_revision_ref.as_deref().is_none_or(valid_ref),
            Self::WebAcceptanceOutcome {
                review,
                expected_frontier,
                ..
            } => *expected_frontier != 0 && valid_hex(&review.expected_digest),
            Self::ProposalReview {
                expected_digest, ..
            } => expected_digest.as_deref().is_none_or(valid_hex),
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
            Self::WebAccept { review } => valid_hex(&review.expected_digest),
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
            Self::PurgeRepository {
                repository_id,
                repository_confirmation,
                expected_repository_revision,
                expected_deletion_generation,
                ..
            } => {
                repository_confirmation
                    .parse::<evertrace_domain::ids::RepositoryId>()
                    .ok()
                    == Some(*repository_id)
                    && *expected_repository_revision > 0
                    && *expected_deletion_generation > 0
            }
            Self::CreateBackup | Self::VerifyBackup { .. } | Self::CollectGarbage => true,
            Self::RepositoryAccess {
                expected_repository_revision,
                action,
                worktree_id,
                inventory_ref,
                ..
            } => {
                *expected_repository_revision > 0
                    && match action {
                        RepositoryAccessAction::Disable => {
                            worktree_id.is_none() && inventory_ref.is_none()
                        }
                        RepositoryAccessAction::Enable | RepositoryAccessAction::Rescan => {
                            worktree_id.is_some()
                        }
                    }
            }
            Self::Unavailable { .. } => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanDiagnosticState {
    Checked,
    Unavailable,
    Inconsistent,
    NotChecked,
    NotRun,
    Disabled,
    Exhausted,
    Historical,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanDiagnosticCheck {
    pub name: String,
    pub state: HumanDiagnosticState,
    pub count: Option<u64>,
    pub limit: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanTableDiagnostic {
    pub schema_matches: Option<bool>,
    pub version: Option<u64>,
    pub checkpoint: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanDiagnostics {
    pub config_version: u32,
    pub algorithm_revision: u32,
    pub config_hash: String,
    pub observed_at_us: i64,
    pub tables: Vec<HumanTableDiagnostic>,
    pub checks: Vec<HumanDiagnosticCheck>,
    pub host: Option<HostCanaryDiagnostic>,
}

impl HumanDiagnostics {
    pub fn validate(&self) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        self.config_version == 1
            && self.algorithm_revision != 0
            && self.observed_at_us >= 0
            && self.config_hash.len() == 64
            && self
                .config_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && self.tables.len() == 4
            && self.checks.len() <= 40
            && self.checks.iter().all(|check| {
                seen.insert(&check.name)
                    && matches!(
                        check.name.as_str(),
                        "projection_checkpoints"
                            | "fts_metadata"
                            | "journal_content"
                            | "objects_rows"
                            | "relations_content"
                            | "search_content"
                            | "spool_metadata"
                            | "cas_metadata"
                            | "spool_frames"
                            | "cas_content"
                            | "jobs_queued"
                            | "jobs_leased"
                            | "jobs_failed_history"
                            | "backup_create_history"
                            | "backup_verify_history"
                            | "backup_content_current"
                            | "purge_current"
                            | "native_history_cleanup"
                            | "llm_daily_calls"
                            | "llm_daily_input_tokens"
                            | "llm_daily_output_tokens"
                            | "llm_daily_wall_time_us"
                            | "provider_connectivity"
                            | "acceptance_a_f"
                            | "backup_manifest_sample"
                            | "backup_sample_declared_bytes"
                            | "runtime_generation"
                            | "runtime_snapshot_version"
                            | "recovery_classifier_revision"
                            | "spool_high_watermark_bytes"
                            | "spool_low_watermark_bytes"
                            | "spool_max_main_files"
                            | "object_deletion_current"
                    )
            })
            && self
                .host
                .as_ref()
                .is_none_or(HostCanaryDiagnostic::validate)
    }
}

impl HumanGovernanceResponse {
    pub fn validate(&self) -> bool {
        match self {
            Self::RecordWindow { page } => page.validate(),
            Self::SourceWindow { page } => page.validate(),
            Self::StoredFields { page } => page.validate(),
            Self::RevisionPair { page } => page.validate(),
            Self::MetadataBatch { page } => page.validate(),
            Self::Jobs { page } => page.validate(),
            Self::State { state } => state.validate(),
            Self::CompiledProjections { page } => page.validate(),
            Self::Search { page } => page.validate(),
            Self::Export { result } => {
                result.object_count <= 64
                    && result
                        .path
                        .as_ref()
                        .is_none_or(|path| path.len() <= 4096 && path.starts_with('/'))
                    && result.reason.as_deref().is_none_or(valid_ref)
                    && (!matches!(
                        result.status,
                        HumanExportStatus::Published | HumanExportStatus::PublicationUncertain
                    ) || result.path.is_some())
            }
            Self::MemoryPage {
                diagnostics,
                frontier,
                status,
                degraded_reasons,
                items,
                next_cursor,
                query,
                total_count,
                matching_count,
                scope_available,
                counts_complete,
                unresolved_scope_count,
            } => {
                use evertrace_domain::query::{MemoryBrowseCursor, MemoryBrowseOrder};
                let newest = matches!(
                    query.order,
                    MemoryBrowseOrder::RecordedNewest | MemoryBrowseOrder::EventNewest
                );
                let rank = |item: &HumanSnapshotItem| {
                    let event = if query.order.uses_event_time() {
                        i128::from(item.native_event_time_us?)
                    } else {
                        0
                    };
                    let seq = i128::from(item.source_event_seq);
                    Some((
                        if newest { -event } else { event },
                        if newest { -seq } else { seq },
                        item.stable_key.clone(),
                    ))
                };
                query.validate().is_ok()
                    && items.iter().all(|item| rank(item).is_some())
                    && if *scope_available {
                        total_count
                            .zip(*matching_count)
                            .is_some_and(|(total, matching)| {
                                matching <= total && items.len() as u64 <= matching
                            })
                            && (!*counts_complete
                                || query.selection
                                    == evertrace_domain::query::MemoryScopeSelection::All
                                || *unresolved_scope_count == 0)
                    } else {
                        !*counts_complete
                            && total_count.is_none()
                            && matching_count.is_none()
                            && items.is_empty()
                            && next_cursor.is_none()
                    }
                    && valid_human_page(diagnostics, status, degraded_reasons, items, next_cursor)
                    && items.windows(2).all(|pair| rank(&pair[0]) < rank(&pair[1]))
                    && items
                        .iter()
                        .map(|item| &item.stable_key)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        == items.len()
                    && next_cursor.as_ref().is_none_or(|raw| {
                        raw.len() <= 2048
                            && serde_json::from_str::<MemoryBrowseCursor>(raw).is_ok_and(|cursor| {
                                cursor.validate_for(query).is_ok()
                                    && cursor.frontier == *frontier
                                    && items.last().is_some_and(|last| {
                                        last.stable_key == cursor.row_id
                                            && last.source_event_seq == cursor.source_event_seq
                                            && last.native_event_time_us == cursor.event_time_us
                                    })
                            })
                    })
            }
            Self::Snapshot {
                diagnostics,
                status,
                degraded_reasons,
                items,
                next_cursor,
                ..
            } => {
                valid_human_page(diagnostics, status, degraded_reasons, items, next_cursor)
                    && items
                        .windows(2)
                        .all(|pair| pair[0].stable_key < pair[1].stable_key)
            }
            Self::ProposalReview {
                item,
                confirmation_digest,
                web_accept_available: available,
                core_anchor,
                frontier,
            } => match item {
                Some(item) => {
                    item.validate()
                        && item.proposal.is_some()
                        && core_anchor.as_ref().is_none_or(|anchor| anchor.validate())
                        && (!available
                            || confirmation_digest.as_deref().is_some_and(|digest| {
                                web_acceptance_intent(
                                    item,
                                    *frontier,
                                    digest,
                                    core_anchor.as_deref(),
                                )
                                .is_some()
                            }))
                        && confirmation_digest.as_deref().is_none_or(valid_hex)
                        && (confirmation_digest.is_some()
                            == item
                                .proposal_review
                                .as_ref()
                                .is_some_and(|review| review.proposal.status.is_open()))
                }
                None => confirmation_digest.is_none() && core_anchor.is_none() && !available,
            },
            Self::Action { result } => result.validate(),
            Self::Conflict {
                current_revision_ref,
                ..
            } => current_revision_ref.as_deref().is_none_or(valid_ref),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum HumanSemanticContent {
    Digest(Box<evertrace_domain::semantic::SemanticDigest>),
    Atom(Box<evertrace_domain::semantic::Atom>),
    Procedure(Box<evertrace_domain::procedure::ProcedureRevision>),
    CoreMembership(Box<evertrace_domain::semantic::CoreMembership>),
}

pub use evertrace_domain::query::HumanContentState;

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanMemoryPreview {
    pub state: HumanContentState,
    pub title: Option<String>,
    pub excerpt: Option<String>,
    pub origin: Option<evertrace_domain::query::MemorySummaryOrigin>,
    pub truncated: bool,
}
impl HumanMemoryPreview {
    fn validate(&self) -> bool {
        if self.state == HumanContentState::Ready {
            self.title.as_ref().is_none_or(|value| {
                !value.trim().is_empty()
                    && value.len() <= 512
                    && !value.chars().any(char::is_control)
            }) && (self.title.is_some() || self.excerpt.is_some())
                && self
                    .excerpt
                    .as_ref()
                    .is_none_or(|value| !value.is_empty() && value.len() <= 1024)
                && self.origin.is_some()
        } else {
            self.title.is_none()
                && self.excerpt.is_none()
                && self.origin.is_none()
                && !self.truncated
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSemanticDetail {
    pub object_ref: Option<String>,
    pub revision_ref: Option<String>,
    pub state: HumanContentState,
    pub preview: Option<String>,
    pub original_bytes: u64,
    pub content: Option<HumanSemanticContent>,
}

impl HumanSemanticDetail {
    fn validate(&self) -> bool {
        if self
            .preview
            .as_ref()
            .is_some_and(|text| text.chars().count() > 160)
            || self
                .object_ref
                .iter()
                .chain(self.revision_ref.iter())
                .any(|reference| reference.is_empty() || reference.len() > 4096)
        {
            return false;
        }
        let Some(content) = &self.content else {
            return self.state != HumanContentState::Ready
                && if self.state == HumanContentState::TooLarge {
                    self.original_bytes > 32 * 1024
                } else {
                    self.preview.is_none() && self.original_bytes == 0
                };
        };
        if self.state != HumanContentState::Ready {
            return false;
        }
        let valid_identity = match content {
            HumanSemanticContent::Digest(value) => {
                value.validate().is_ok()
                    && self.object_ref.as_deref()
                        == Some(value.semantic_digest_id.to_string().as_str())
                    && self.revision_ref == self.object_ref
            }
            HumanSemanticContent::Atom(value) => {
                value.validate().is_ok()
                    && self.object_ref.as_deref() == Some(value.atom_id.to_string().as_str())
                    && self.revision_ref.as_deref() == Some(value.revision_id.to_string().as_str())
            }
            HumanSemanticContent::Procedure(value) => {
                value.validate().is_ok()
                    && self.object_ref.as_deref() == Some(value.procedure_id.to_string().as_str())
                    && self.revision_ref.as_deref() == Some(value.revision_id.to_string().as_str())
            }
            HumanSemanticContent::CoreMembership(value) => {
                value.validate().is_ok()
                    && self.object_ref.as_deref()
                        == Some(value.core_membership_id.to_string().as_str())
                    && self.revision_ref.as_deref()
                        == Some(value.membership_revision_id.to_string().as_str())
            }
        };
        valid_identity
            && serde_json::to_vec(content).is_ok_and(|bytes| {
                bytes.len() <= 32 * 1024 && bytes.len() as u64 == self.original_bytes
            })
    }
}

impl HumanSnapshotItem {
    fn validate(&self) -> bool {
        if !self.reading_preview.as_ref().is_none_or(|preview| {
            preview.validate()
                && matches!(
                    self.object_kind.as_str(),
                    "semantic_digest"
                        | "atom_revision"
                        | "procedure_revision"
                        | "core_membership"
                        | "revision_proposal_revision"
                        | "work_episode"
                )
        }) {
            return false;
        }
        self.semantic_detail.as_ref().is_none_or(|detail| {
            detail.validate()
                && detail.object_ref == self.object_ref
                && detail.revision_ref == self.revision_ref
                && detail.content.as_ref().is_none_or(|content| match content {
                    HumanSemanticContent::Digest(_) => self.object_kind == "semantic_digest",
                    HumanSemanticContent::Atom(_) => self.object_kind == "atom_revision",
                    HumanSemanticContent::Procedure(_) => self.object_kind == "procedure_revision",
                    HumanSemanticContent::CoreMembership(_) => {
                        self.object_kind == "core_membership"
                    }
                })
        }) && self.proposal_base.as_ref().is_none_or(|detail| {
            detail.validate()
                && self.proposal.as_ref().is_some_and(|proposal| {
                    proposal.base_revision_id.is_some_and(|revision| {
                        detail.revision_ref.as_deref() == Some(revision.to_string().as_str())
                    }) && detail
                        .object_ref
                        .as_ref()
                        .is_none_or(|object| match proposal.target_id {
                            Some(ProposalTargetId::Atom(id)) => {
                                object == &id.to_string()
                                    && detail.content.as_ref().is_none_or(|value| {
                                        matches!(value, HumanSemanticContent::Atom(_))
                                    })
                            }
                            Some(ProposalTargetId::Procedure(id)) => {
                                object == &id.to_string()
                                    && detail.content.as_ref().is_none_or(|value| {
                                        matches!(value, HumanSemanticContent::Procedure(_))
                                    })
                            }
                            Some(ProposalTargetId::CoreMembership(id)) => {
                                object == &id.to_string()
                                    && detail.content.as_ref().is_none_or(|value| {
                                        matches!(value, HumanSemanticContent::CoreMembership(_))
                                    })
                            }
                            None => false,
                        })
                })
        }) && ((self.item_kind == HumanItemKind::RevisionProposal) == self.proposal.is_some())
            && self.proposal_review.as_ref().is_none_or(|review| {
                review.capability_coverage.as_ref().is_none_or(|coverage| {
                    coverage.validate()
                        && matches!(
                            review.proposal.payload,
                            evertrace_domain::semantic::ProposalPayload::Procedure(_)
                        )
                })
            })
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
                        == (review.reauthorization.is_none()
                            && plain_accept_eligible(review.proposal.as_ref()))
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
            && self
                .repository_purge_preview
                .as_ref()
                .is_none_or(|preview| {
                    preview.repository_revision > 0
                        && preview.deletion_generation > 0
                        && self.object_kind == "repository"
                        && self.object_ref.as_deref()
                            == Some(preview.repository_id.to_string().as_str())
                        && self.revision_ref.as_deref()
                            == Some(
                                format!(
                                    "{}@{}",
                                    preview.repository_id, preview.repository_revision
                                )
                                .as_str(),
                            )
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
            && self
                .system_detail
                .as_ref()
                .is_none_or(|detail| detail.validate(self))
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

impl HumanSystemDetail {
    fn validate(&self, item: &HumanSnapshotItem) -> bool {
        if matches!(self, Self::Job { .. } | Self::Config { .. })
            && (item.row_class != HumanRowClass::Runtime
                || item.family != HumanObjectFamily::Runtime
                || item.category != HumanItemCategory::Runtime
                || item.object_kind != "runtime_event"
                || item.object_ref.is_some()
                || item.revision_ref.is_some())
        {
            return false;
        }
        match self {
            Self::Repository {
                repository_id,
                repository_revision,
                ..
            } => {
                item.object_kind == "repository"
                    && *repository_revision > 0
                    && item.object_ref.as_deref() == Some(repository_id.to_string().as_str())
            }
            Self::CapabilityInventory {
                job_id,
                repository_id: _,
                repository_revision,
                worktree_id: _,
                cwd,
                state,
                source_count,
                signature_count,
                unobserved_source_count,
                unknown_contract_count,
                asset_names,
            } => {
                item.object_kind == "capability_inventory"
                    && *repository_revision > 0
                    && item.object_ref.as_deref() == Some(job_id.to_string().as_str())
                    && cwd.starts_with('/')
                    && cwd.len() <= 4096
                    && !cwd.chars().any(char::is_control)
                    && matches!(
                        state.as_str(),
                        "recorded"
                            | "ready"
                            | "stale"
                            | "disabled"
                            | "revoked"
                            | "purged"
                            | "unobserved"
                    )
                    && asset_names.len() <= 16
                    && asset_names.iter().all(|name| valid_short(name))
                    && (state == "ready"
                        || source_count.is_none()
                            && signature_count.is_none()
                            && unobserved_source_count.is_none()
                            && unknown_contract_count.is_none()
                            && asset_names.is_empty())
            }
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
                    backup_summary,
                    gc_summary,
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
                    && backup_summary.as_ref().is_none_or(|summary| {
                        *state == HumanJobState::Succeeded
                            && *terminal_reason == Some(HumanJobTerminalReason::Completed)
                            && match summary.validation_result {
                                HumanBackupValidationResult::VerifiedBeforePublish => {
                                    job_kind == "quiesced_backup_create_v1"
                                }
                                HumanBackupValidationResult::VerifyJobPassed => {
                                    job_kind == "quiesced_backup_verify_v1"
                                }
                            }
                            && summary.validate()
                    })
                    && budget.validate()
                    && gc_summary.as_ref().is_none_or(|summary| {
                        job_kind == "two_pass_gc_v1"
                            && valid_hex(&summary.checksum)
                            && summary.mark_watermark <= summary.sweep_watermark
                            && summary.marked_candidates <= summary.examined_files
                            && summary.examined_files <= budget.max_items
                            && summary.deleted_count <= summary.marked_candidates
                            && summary.unknown_count <= summary.marked_candidates
                            && summary
                                .deleted_count
                                .checked_add(summary.unknown_count)
                                .is_some_and(|count| count <= summary.marked_candidates)
                            && summary.conservative_prune.len() <= 4
                            && summary.conservative_prune.iter().all(|result| {
                                valid_short(&result.table)
                                    && result.bytes_removed.is_some()
                                        == result.old_versions.is_some()
                            })
                            && (*state != HumanJobState::Succeeded
                                || (summary.unknown_count == 0
                                    && summary.conservative_prune.len() == 4
                                    && summary
                                        .conservative_prune
                                        .iter()
                                        .all(|result| result.bytes_removed.is_some())))
                    })
            }
            Self::SessionImport {
                session_id,
                source_instance_id,
                body_state,
                access,
                workspace,
                repository_read_restrictions,
            } => {
                valid_ref(session_id)
                    && repository_read_restrictions.as_ref().is_none_or(|ids| {
                        ids.len() <= 16 && ids.windows(2).all(|pair| pair[0] < pair[1])
                    })
                    && valid_ref(source_instance_id)
                    && item.object_kind == "session_import_current"
                    && matches!(
                        body_state.as_str(),
                        "NotImported"
                            | "Queued"
                            | "Importing"
                            | "Imported"
                            | "BlockedUntrusted"
                            | "BlockedUnapproved"
                            | "BlockedScopeUnresolved"
                            | "Partial"
                            | "Failed"
                            | "SourceReplaced"
                    )
                    && matches!(access.as_str(), "None" | "Approved" | "Revoked")
                    && matches!(
                        workspace.as_str(),
                        "Repository" | "NonRepository" | "Ambiguous" | "Unavailable"
                    )
            }
            Self::Config {
                config_version,
                reload,
                ..
            } => {
                *config_version > 0
                    && match item.stable_key.as_str() {
                        "runtime:config:current" => reload.as_ref().is_none_or(|detail| {
                            detail.outcome == ConfigReloadOutcome::Applied && detail.validate()
                        }),
                        "runtime:config:attempt" => {
                            reload.as_ref().is_some_and(ConfigReloadAudit::validate)
                        }
                        _ => false,
                    }
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

impl HumanBackupSummary {
    fn validate(&self) -> bool {
        let legacy = match (self.journal.version, self.objects.version) {
            (None, None) => false,
            (Some(journal), Some(objects)) if journal > 0 && objects > 0 => true,
            _ => return false,
        };
        self.frontier > 0
            && self.journal.frontier == self.frontier
            && self.objects.frontier > 0
            && self.objects.frontier <= self.frontier
            && (legacy || self.objects.frontier == self.frontier)
            && self.compiler_watermark == self.objects.frontier
            && match (&self.relations, &self.search) {
                (None, None) => self.index_generation == 0,
                (Some(relations), Some(search)) => {
                    (if legacy {
                        relations.version.is_some_and(|version| version > 0)
                    } else {
                        relations.version.is_none()
                    }) && relations.frontier <= self.frontier
                        && search.version.is_some_and(|version| version > 0)
                        && search.frontier <= self.frontier
                        && self.index_generation > 0
                }
                _ => false,
            }
            && self.effective_config_hash != [0; 32]
            && self.runtime_generation > 0
            && match self.hook_current_generation {
                Some(generation) => {
                    generation > 0
                        && self.hook_retained_generations.contains(&generation)
                        && !self.hook_retained_generations.is_empty()
                        && self.hook_retained_generations.len() <= 4096
                        && self
                            .hook_retained_generations
                            .windows(2)
                            .all(|pair| pair[0] < pair[1])
                        && usize::try_from(self.session_pinned_hook_artifact_count)
                            .is_ok_and(|count| count <= self.hook_retained_generations.len())
                        && self.session_pinned_hook_artifact_count <= self.hook_pin_count
                }
                None => {
                    self.hook_retained_generations.is_empty()
                        && self.hook_pin_count == 0
                        && self.session_pinned_hook_artifact_count == 0
                }
            }
            && self.file_count > 0
            && self.total_bytes > 0
            && self.required_space_bytes <= self.available_space_bytes_at_preflight
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

fn valid_human_page(
    diagnostics: &Option<Box<HumanDiagnostics>>,
    status: &HumanSnapshotStatus,
    reasons: &[HumanDegradedReason],
    items: &[HumanSnapshotItem],
    next: &Option<String>,
) -> bool {
    ((matches!(status, HumanSnapshotStatus::Ready) && reasons.is_empty())
        || (matches!(status, HumanSnapshotStatus::Degraded) && !reasons.is_empty()))
        && reasons.windows(2).all(|pair| pair[0] < pair[1])
        && items.len() <= usize::from(HUMAN_PAGE_LIMIT)
        && items.iter().all(HumanSnapshotItem::validate)
        && next.as_deref().is_none_or(valid_ref)
        && diagnostics.as_ref().is_none_or(|value| value.validate())
}

fn category_matches(item: &HumanSnapshotItem) -> bool {
    use HumanItemCategory as Category;
    match item.category {
        Category::Proposal => {
            item.item_kind == HumanItemKind::RevisionProposal
                && item.object_kind == "revision_proposal_revision"
        }
        Category::ProposalRevision => {
            item.item_kind == HumanItemKind::Generic
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
                HumanActionStatus::Unknown => {
                    self.current_revision_ref.is_none()
                        && self.audit_event_ref.is_none()
                        && self.reason.is_none()
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
/// Current process-local observation, never a capability grant or durable audit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCanaryDiagnostic {
    pub scope: HostCanaryScope,
    pub status: HostCanaryStatus,
    pub native_delivery_observed: bool,
    pub mcp_claim_consumed: bool,
    pub capture_receipt_observed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification: Option<HostCanaryQualification>,
}

/// Fixed display/check projection of the daemon's evaluated current report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCanaryQualification {
    pub hook_activation: CanaryHookActivation,
    pub mcp_binding: CanaryMcpBinding,
    pub mcp_mechanism: CanaryMcpMechanism,
    pub capture: CanaryGateQualification,
    pub recovery: CanaryGateQualification,
    pub active_search_due: CanaryGateQualification,
    pub strong_normalization: CanaryGateQualification,
    pub project_policy: CanaryGateQualification,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryHookActivation {
    Missing,
    PendingTrust,
    Active,
    Disabled,
    HashChanged,
    CanaryFailed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryMcpBinding {
    Exact,
    ConnectionScoped,
    CwdOnly,
    Unavailable,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryMcpMechanism {
    DirectProtocol,
    HookStamped,
    ConnectionLease,
    Cwd,
    None,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryGateResult {
    Enabled,
    Disabled,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryGateReason {
    RequirementsSatisfied,
    MissingEvidence,
    EvidenceIntegrityFailed,
    ManifestInsufficient,
    SourceNotClosed,
    GapOrOutage,
    PairingIncomplete,
    SubagentTraceIncomplete,
    RecoveryNotFenced,
    RecoveryCanaryFailed,
    HookInactive,
    CueBoundaryUnavailable,
    SessionBindingUnproven,
    IdentityUnstable,
    CorrelationUnproven,
    PolicySurfaceUndeclared,
    PolicyNotLoaded,
    PolicyReadbackMismatch,
    PolicyRevoked,
    PolicyScopeUnresolved,
    TrustUnavailable,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryGateQualification {
    pub result: CanaryGateResult,
    pub reason: CanaryGateReason,
}

impl HostCanaryQualification {
    fn validate(&self) -> bool {
        [
            &self.capture,
            &self.recovery,
            &self.active_search_due,
            &self.strong_normalization,
            &self.project_policy,
        ]
        .into_iter()
        .all(|gate| {
            (gate.result == CanaryGateResult::Enabled)
                == (gate.reason == CanaryGateReason::RequirementsSatisfied)
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostCanaryScope {
    Installed,
    Candidate { check_id: String, generation: u64 },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostCanaryStatus {
    NotRun,
    Running,
    Unavailable,
    BudgetExceeded,
    EvidenceMissing,
    TimedOut,
    IdentityChanged,
    Interrupted,
    Observed,
}

impl HostCanaryDiagnostic {
    pub fn validate(&self) -> bool {
        self.qualification
            .as_ref()
            .is_none_or(HostCanaryQualification::validate)
            && (match &self.scope {
                HostCanaryScope::Installed => true,
                HostCanaryScope::Candidate {
                    check_id,
                    generation,
                } => *generation > 0 && check_id.parse::<evertrace_domain::ids::JobId>().is_ok(),
            })
            && (!self.capture_receipt_observed || self.native_delivery_observed)
            && match self.status {
                HostCanaryStatus::Observed => {
                    self.native_delivery_observed && self.mcp_claim_consumed
                }
                HostCanaryStatus::EvidenceMissing => true,
                _ => {
                    !self.native_delivery_observed
                        && !self.mcp_claim_consumed
                        && !self.capture_receipt_observed
                }
            }
    }
}

#[cfg(test)]
mod human_backup_summary_tests {
    use super::*;

    fn summary(legacy: bool) -> HumanBackupSummary {
        HumanBackupSummary {
            frontier: 5,
            journal: HumanBackupTableState {
                version: legacy.then_some(3),
                frontier: 5,
            },
            objects: HumanBackupTableState {
                version: legacy.then_some(3),
                frontier: if legacy { 3 } else { 5 },
            },
            relations: Some(HumanBackupTableState {
                version: legacy.then_some(3),
                frontier: 4,
            }),
            search: Some(HumanBackupTableState {
                version: Some(3),
                frontier: 4,
            }),
            committed_source_watermark_count: 0,
            spool_source_watermark_count: 0,
            live_cas_count: 0,
            spool_cas_count: 0,
            spool_file_count: 0,
            spool_generation_count: 0,
            normal_spool_frame_count: 0,
            isolated_spool_frame_count: 0,
            emergency_gap_count: 0,
            quarantine_count: 0,
            runtime_outbox_watermark: 0,
            index_generation: 1,
            compiler_watermark: if legacy { 3 } else { 5 },
            effective_config_hash: [1; 32],
            runtime_generation: 1,
            hook_current_generation: None,
            hook_retained_generations: Vec::new(),
            hook_pin_count: 0,
            session_pinned_hook_artifact_count: 0,
            object_deletion_generation: 0,
            repository_purge_generation: 0,
            file_count: 1,
            total_bytes: 1,
            required_space_bytes: 1,
            available_space_bytes_at_preflight: 1,
            validation_result: HumanBackupValidationResult::VerifiedBeforePublish,
        }
    }

    fn response(summary: HumanBackupSummary) -> HumanGovernanceResponse {
        let job_id = JobId::new_v7();
        HumanGovernanceResponse::Snapshot {
            diagnostics: None,
            frontier: 1,
            status: HumanSnapshotStatus::Ready,
            degraded_reasons: Vec::new(),
            items: vec![HumanSnapshotItem {
                reading_preview: None,
                semantic_detail: None,
                proposal_base: None,
                item_kind: HumanItemKind::Generic,
                proposal: None,
                proposal_review: None,
                support_detail: None,
                competing_detail: None,
                forget_preview: None,
                repository_purge_preview: None,
                negative_review: None,
                system_detail: Some(HumanSystemDetail::Job {
                    detail: Box::new(HumanJobDetail {
                        native_history_cleanup_availability: None,
                        job_id,
                        target_revision: "revision:1".into(),
                        target_watermark: 1,
                        target_generation: 1,
                        job_kind: "quiesced_backup_create_v1".into(),
                        algorithm_revision: "algorithm:1".into(),
                        model_id: None,
                        priority: 0,
                        state: HumanJobState::Succeeded,
                        attempt: 1,
                        backoff_until_us: None,
                        lease_until_us: None,
                        config_hash: [1; 32],
                        budget: HumanJobBudget {
                            max_items: 1,
                            max_bytes: None,
                            max_input_tokens: None,
                            max_output_tokens: None,
                            max_calls: None,
                            max_wall_time_ms: 1,
                        },
                        terminal_reason: Some(HumanJobTerminalReason::Completed),
                        terminal_result_ref: Some("backup:1".into()),
                        backup_summary: Some(summary),
                        gc_summary: None,
                    }),
                }),
                stable_key: format!("runtime:job:{job_id}"),
                row_class: HumanRowClass::Runtime,
                family: HumanObjectFamily::Runtime,
                category: HumanItemCategory::Runtime,
                object_kind: "runtime_event".into(),
                object_ref: None,
                revision_ref: None,
                lifecycle: None,
                epistemic: None,
                authority: None,
                publication_state: None,
                support_state: None,
                scope_ref: None,
                native_event_time_us: None,
                source_event_seq: 1,
            }],
            next_cursor: None,
        }
    }

    #[test]
    fn human_response_accepts_supported_current_and_legacy_backup_shapes() {
        assert!(response(summary(false)).validate());
        assert!(response(summary(true)).validate());

        let mut mixed = summary(true);
        mixed.objects.version = None;
        assert!(!response(mixed).validate());
    }
}
