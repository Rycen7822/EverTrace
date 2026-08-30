use std::fmt;

use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    evidence::{
        CaptureGapMarkerEvidence, CaptureOutageInterval, EvidenceSurface, HostOccurrence,
        Operation, ScopeEffect, SourceInstanceId, SourceObservation, SourceReceipt, SourceRevision,
        SourceRevisionMode,
    },
    ids::{CaptureOutageIntervalId, CommandId, ExecutionLaneId, JobId, SourceObservationId},
    procedure::{
        ProcedureNegativeEvidence, ProcedureNegativeReviewEvent, ProcedureRevision,
        ProcedureStateEvent, ProcedureUsageRevision,
    },
    recall::RecallLedgerEvent,
    repository::{
        IntegrationEvent, RecoveryApplication, RecoveryBundle, RecoveryCaptureRequest,
        RecoveryRequestStatus, RepositoryInstance, WorktreeInstance, WorktreeSnapshot,
        WorktreeTransition,
    },
    semantic::{
        Atom, CoreMembership, GlobalSuccessorSupportContract, GlobalSupportValidationEvent,
        ResultEvidence, RevisionProposal, Scenario, SemanticDerivationRun, SemanticDigest,
    },
    work::{
        AdmissionFailureObservability, Attempt, CaptureReceipt, CompetingAttemptGroup,
        ExecutionLane, ExperimentRun, OperationBurst, SegmentationCorrection, Task, WorkArtifact,
        WorkBindingRevision, WorkCheckpoint, WorkEpisode, Workstream,
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const JOURNAL_PAYLOAD_SCHEMA: u16 = 1;
pub(crate) const ATOM_RECORDED_EVENT_TYPE: &str = "atom_recorded_v1";
const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordClass {
    ObjectEvent,
    RuntimeEvent,
    ProjectionControl,
}

impl RecordClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectEvent => "object_event",
            Self::RuntimeEvent => "runtime_event",
            Self::ProjectionControl => "projection_control",
        }
    }

    pub fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "object_event" => Ok(Self::ObjectEvent),
            "runtime_event" => Ok(Self::RuntimeEvent),
            "projection_control" => Ok(Self::ProjectionControl),
            _ => Err(StoreError::StoreCorrupt),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectFamily {
    Evidence,
    Work,
    Atom,
    Procedure,
    RevisionProposal,
}

impl ObjectFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Work => "work",
            Self::Atom => "atom",
            Self::Procedure => "procedure",
            Self::RevisionProposal => "revision_proposal",
        }
    }

    pub fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "evidence" => Ok(Self::Evidence),
            "work" => Ok(Self::Work),
            "atom" => Ok(Self::Atom),
            "procedure" => Ok(Self::Procedure),
            "revision_proposal" => Ok(Self::RevisionProposal),
            _ => Err(StoreError::StoreCorrupt),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Hook,
    Session,
    Manual,
    Import,
    System,
    Model,
}

impl SourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hook => "hook",
            Self::Session => "session",
            Self::Manual => "manual",
            Self::Import => "import",
            Self::System => "system",
            Self::Model => "model",
        }
    }

    pub fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "hook" => Ok(Self::Hook),
            "session" => Ok(Self::Session),
            "manual" => Ok(Self::Manual),
            "import" => Ok(Self::Import),
            "system" => Ok(Self::System),
            "model" => Ok(Self::Model),
            _ => Err(StoreError::StoreCorrupt),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirtyTargetKind {
    ObjectsProjection,
    EvidenceSurface,
    PhysicalNormalization,
    CaptureReconciliation,
    CaptureLiveness,
    RuntimeJob,
    RuntimeOutbox,
}

impl DirtyTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectsProjection => "objects_projection",
            Self::EvidenceSurface => "evidence_surface",
            Self::PhysicalNormalization => "physical_normalization",
            Self::CaptureReconciliation => "capture_reconciliation",
            Self::CaptureLiveness => "capture_liveness",
            Self::RuntimeJob => "runtime_job",
            Self::RuntimeOutbox => "runtime_outbox",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Leased,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkKind {
    ObjectsProjection,
    RuntimeJobs,
    RuntimeOutbox,
}

impl WatermarkKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectsProjection => "objects_projection",
            Self::RuntimeJobs => "runtime_jobs",
            Self::RuntimeOutbox => "runtime_outbox",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventScope {
    pub project_id: Option<String>,
    pub repository_id: Option<String>,
    pub worktree_id: Option<String>,
    pub task_id: Option<String>,
    pub workstream_id: Option<String>,
    pub session_id: Option<String>,
    pub execution_lane_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationApplied {
    pub migration_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirtyTarget {
    pub target_kind: DirtyTargetKind,
    pub target_id: String,
    pub algorithm_revision: String,
    pub source_watermark: u64,
}

impl DirtyTarget {
    pub fn stable_key(&self) -> String {
        length_key(&[
            self.target_kind.as_str(),
            &self.target_id,
            &self.algorithm_revision,
            &self.source_watermark.to_string(),
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxEntry {
    pub outbox_id: String,
    pub dirty: DirtyTarget,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableJob {
    pub job_id: JobId,
    pub idempotency_key: String,
    pub target_revision: String,
    pub target_watermark: u64,
    pub target_generation: u64,
    pub kind: String,
    pub priority: i16,
    pub state: JobStatus,
    pub attempt: u32,
    pub backoff_until_us: Option<i64>,
    pub config_hash: [u8; 32],
    pub lease_until_us: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobLease {
    pub job_id: JobId,
    pub target_generation: u64,
    pub attempt: u32,
    pub lease_until_us: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatermarkAdvanced {
    pub kind: WatermarkKind,
    pub value: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigAudit {
    pub config_version: u32,
    pub effective_config_hash: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaleGenerationAudit {
    pub job_id: JobId,
    pub expected_generation: u64,
    pub observed_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRevisionRecorded {
    pub source_instance_id: SourceInstanceId,
    pub source_revision: SourceRevision,
    pub previous_source_revision: Option<SourceRevision>,
    pub mode: SourceRevisionMode,
    pub recorded_at_us: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIngestWatermark {
    pub source_instance_id: SourceInstanceId,
    pub source_revision: SourceRevision,
    pub source_sequence: u64,
}

impl SourceIngestWatermark {
    pub fn stable_key(&self) -> String {
        length_key(&[
            self.source_instance_id.as_str(),
            self.source_revision.as_str(),
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizationWatermark {
    pub source_observation_id: SourceObservationId,
    pub resolver_version: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCloseDecision {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentSourceReconciliation {
    pub source_instance_id: SourceInstanceId,
    pub source_revision: SourceRevision,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub evidence_refs: Vec<String>,
}

impl IndependentSourceReconciliation {
    fn validate(&self) -> Result<(), StoreError> {
        if self.first_sequence > self.last_sequence || self.evidence_refs.is_empty() {
            return Err(StoreError::InvalidInput);
        }
        for reference in &self.evidence_refs {
            validate_identifier(reference)?;
        }
        require_unique_strings(&self.evidence_refs)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCloseRange {
    pub source_instance_id: SourceInstanceId,
    pub source_revision: SourceRevision,
    pub eligible_event_manifest_refs: Vec<String>,
    pub first_sequence: u64,
    pub close_watermark: u64,
    pub observed_through_sequence: u64,
    pub admission_failure_observability: AdmissionFailureObservability,
    pub independent_reconciliation: Option<IndependentSourceReconciliation>,
}

impl SourceCloseRange {
    pub fn source_revision_ref(&self) -> String {
        source_revision_ref(&self.source_instance_id, &self.source_revision)
    }

    pub fn close_watermark_ref(&self) -> String {
        format!("{}:{}", self.source_revision_ref(), self.close_watermark)
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.eligible_event_manifest_refs.is_empty()
            || self.first_sequence > self.close_watermark
            || self.observed_through_sequence > self.close_watermark
        {
            return Err(StoreError::InvalidInput);
        }
        for reference in &self.eligible_event_manifest_refs {
            validate_identifier(reference)?;
        }
        require_unique_strings(&self.eligible_event_manifest_refs)?;
        if let Some(independent) = &self.independent_reconciliation {
            independent.validate()?;
            if independent.source_instance_id == self.source_instance_id
                && independent.source_revision == self.source_revision
            {
                return Err(StoreError::InvalidInput);
            }
        }
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.observed_through_sequence == self.close_watermark
            && matches!(
                self.admission_failure_observability,
                AdmissionFailureObservability::Complete
                    | AdmissionFailureObservability::Reconcilable
            )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCloseReconciliation {
    pub reconciliation_ref: String,
    pub execution_lane_id: ExecutionLaneId,
    pub sources: Vec<SourceCloseRange>,
    pub unresolved_gap_refs: Vec<String>,
    pub unresolved_outage_interval_refs: Vec<CaptureOutageIntervalId>,
    decision: SourceCloseDecision,
}

impl SourceCloseReconciliation {
    pub fn new(
        reconciliation_ref: impl Into<String>,
        execution_lane_id: ExecutionLaneId,
        sources: Vec<SourceCloseRange>,
        unresolved_gap_refs: Vec<String>,
        unresolved_outage_interval_refs: Vec<CaptureOutageIntervalId>,
    ) -> Result<Self, StoreError> {
        let mut value = Self {
            reconciliation_ref: reconciliation_ref.into(),
            execution_lane_id,
            sources,
            unresolved_gap_refs,
            unresolved_outage_interval_refs,
            decision: SourceCloseDecision::Failed,
        };
        value.decision = value.derived_decision();
        value.validate()?;
        Ok(value)
    }

    pub const fn decision(&self) -> SourceCloseDecision {
        self.decision
    }

    pub const fn passed(&self) -> bool {
        matches!(self.decision, SourceCloseDecision::Passed)
    }

    pub fn source_revision_refs(&self) -> Vec<String> {
        self.sources
            .iter()
            .map(SourceCloseRange::source_revision_ref)
            .collect()
    }

    pub fn close_watermark_refs(&self) -> Vec<String> {
        self.sources
            .iter()
            .map(SourceCloseRange::close_watermark_ref)
            .collect()
    }

    fn derived_decision(&self) -> SourceCloseDecision {
        if !self.sources.is_empty()
            && self.sources.iter().all(SourceCloseRange::is_complete)
            && self.unresolved_gap_refs.is_empty()
            && self.unresolved_outage_interval_refs.is_empty()
        {
            SourceCloseDecision::Passed
        } else {
            SourceCloseDecision::Failed
        }
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        validate_identifier(&self.reconciliation_ref)?;
        if self.sources.is_empty() || self.decision != self.derived_decision() {
            return Err(StoreError::InvalidInput);
        }
        for source in &self.sources {
            source.validate()?;
        }
        let source_refs = self.source_revision_refs();
        require_unique_strings(&source_refs)?;
        for reference in &self.unresolved_gap_refs {
            validate_identifier(reference)?;
        }
        require_unique_strings(&self.unresolved_gap_refs)?;
        require_unique_values(&self.unresolved_outage_interval_refs)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum JournalPayload {
    MigrationApplied(MigrationApplied),
    DirtyTarget(DirtyTarget),
    OutboxEnqueued(OutboxEntry),
    JobState(DurableJob),
    JobLease(JobLease),
    WatermarkAdvanced(WatermarkAdvanced),
    ConfigAudit(ConfigAudit),
    StaleGenerationAudit(StaleGenerationAudit),
    SourceRevisionRecorded(SourceRevisionRecorded),
    SourceReceiptRecorded(Box<SourceReceipt>),
    SourceObservationRecorded(Box<SourceObservation>),
    SourceIngestWatermark(SourceIngestWatermark),
    EvidenceSurfaceRecorded(Box<EvidenceSurface>),
    HostOccurrenceNormalized(Box<HostOccurrence>),
    OperationDerived(Box<Operation>),
    ScopeEffectDerived(Box<ScopeEffect>),
    NormalizationWatermark(NormalizationWatermark),
    ExecutionLaneRecorded(Box<ExecutionLane>),
    CaptureReceiptRecorded(Box<CaptureReceipt>),
    CaptureGapMarkerRecorded(Box<CaptureGapMarkerEvidence>),
    CaptureOutageIntervalRecorded(Box<CaptureOutageInterval>),
    SourceCloseReconciliation(SourceCloseReconciliation),
    RepositoryInstanceRecorded(Box<RepositoryInstance>),
    WorktreeInstanceRecorded(Box<WorktreeInstance>),
    WorktreeSnapshotRecorded(Box<WorktreeSnapshot>),
    WorktreeTransitionRecorded(Box<WorktreeTransition>),
    IntegrationEventRecorded(Box<IntegrationEvent>),
    TaskRecorded(Box<Task>),
    WorkstreamRecorded(Box<Workstream>),
    WorkBindingRecorded(Box<WorkBindingRevision>),
    AttemptRecorded(Box<Attempt>),
    CompetingAttemptGroupRecorded(Box<CompetingAttemptGroup>),
    OperationBurstRecorded(Box<OperationBurst>),
    WorkEpisodeRecorded(Box<WorkEpisode>),
    WorkCheckpointRecorded(Box<WorkCheckpoint>),
    SegmentationCorrectionRecorded(Box<SegmentationCorrection>),
    RecoveryCaptureRequestRecorded(Box<RecoveryCaptureRequest>),
    RecoveryBundleRecorded(Box<RecoveryBundle>),
    RecoveryApplicationRecorded(Box<RecoveryApplication>),
    ExperimentRunRecorded(Box<ExperimentRun>),
    ResultEvidenceRecorded(Box<ResultEvidence>),
    WorkArtifactRecorded(Box<WorkArtifact>),
    AtomRecorded(Box<Atom>),
    RevisionProposalRecorded(Box<RevisionProposal>),
    ProcedureRevisionRecorded(Box<ProcedureRevision>),
    ProcedureStateRecorded(Box<ProcedureStateEvent>),
    ProcedureUsageRecorded(Box<ProcedureUsageRevision>),
    ProcedureNegativeEvidenceRecorded(Box<ProcedureNegativeEvidence>),
    ProcedureNegativeReviewRecorded(Box<ProcedureNegativeReviewEvent>),
    ScenarioRecorded(Box<Scenario>),
    CoreMembershipRecorded(Box<CoreMembership>),
    GlobalSupportContractRecorded(Box<GlobalSuccessorSupportContract>),
    GlobalSupportValidationRecorded(Box<GlobalSupportValidationEvent>),
    SemanticDigestRecorded(Box<SemanticDigest>),
    SemanticDerivationRunRecorded(Box<SemanticDerivationRun>),
    RecallLedgerRecorded(Box<RecallLedgerEvent>),
}

impl JournalPayload {
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::MigrationApplied(_) => "migration_applied_v1",
            Self::DirtyTarget(_) => "dirty_target_v1",
            Self::OutboxEnqueued(_) => "outbox_enqueued_v1",
            Self::JobState(_) => "job_state_v1",
            Self::JobLease(_) => "job_lease_v1",
            Self::WatermarkAdvanced(_) => "watermark_advanced_v1",
            Self::ConfigAudit(_) => "config_audit_v1",
            Self::StaleGenerationAudit(_) => "stale_generation_audit_v1",
            Self::SourceRevisionRecorded(_) => "source_revision_recorded_v1",
            Self::SourceReceiptRecorded(_) => "source_receipt_recorded_v1",
            Self::SourceObservationRecorded(_) => "source_observation_recorded_v1",
            Self::SourceIngestWatermark(_) => "source_ingest_watermark_v1",
            Self::EvidenceSurfaceRecorded(_) => "evidence_surface_recorded_v1",
            Self::HostOccurrenceNormalized(_) => "host_occurrence_normalized_v1",
            Self::OperationDerived(_) => "operation_derived_v1",
            Self::ScopeEffectDerived(_) => "scope_effect_derived_v1",
            Self::NormalizationWatermark(_) => "normalization_watermark_v1",
            Self::ExecutionLaneRecorded(_) => "execution_lane_recorded_v1",
            Self::CaptureReceiptRecorded(_) => "capture_receipt_recorded_v1",
            Self::CaptureGapMarkerRecorded(_) => "capture_gap_marker_recorded_v1",
            Self::CaptureOutageIntervalRecorded(_) => "capture_outage_interval_recorded_v1",
            Self::SourceCloseReconciliation(_) => "source_close_reconciliation_v1",
            Self::RepositoryInstanceRecorded(_) => "repository_instance_recorded_v1",
            Self::WorktreeInstanceRecorded(_) => "worktree_instance_recorded_v1",
            Self::WorktreeSnapshotRecorded(_) => "worktree_snapshot_recorded_v1",
            Self::WorktreeTransitionRecorded(_) => "worktree_transition_recorded_v1",
            Self::IntegrationEventRecorded(_) => "integration_event_recorded_v1",
            Self::TaskRecorded(_) => "task_recorded_v1",
            Self::WorkstreamRecorded(_) => "workstream_recorded_v1",
            Self::WorkBindingRecorded(_) => "work_binding_recorded_v1",
            Self::AttemptRecorded(_) => "attempt_recorded_v1",
            Self::CompetingAttemptGroupRecorded(_) => "competing_attempt_group_recorded_v1",
            Self::OperationBurstRecorded(_) => "operation_burst_recorded_v1",
            Self::WorkEpisodeRecorded(_) => "work_episode_recorded_v1",
            Self::WorkCheckpointRecorded(_) => "work_checkpoint_recorded_v1",
            Self::SegmentationCorrectionRecorded(_) => "segmentation_correction_recorded_v1",
            Self::RecoveryCaptureRequestRecorded(_) => "recovery_capture_request_recorded_v1",
            Self::RecoveryBundleRecorded(_) => "recovery_bundle_recorded_v1",
            Self::RecoveryApplicationRecorded(_) => "recovery_application_recorded_v1",
            Self::ExperimentRunRecorded(_) => "experiment_run_recorded_v1",
            Self::ResultEvidenceRecorded(_) => "result_evidence_recorded_v1",
            Self::WorkArtifactRecorded(_) => "work_artifact_recorded_v1",
            Self::AtomRecorded(_) => ATOM_RECORDED_EVENT_TYPE,
            Self::RevisionProposalRecorded(_) => "revision_proposal_recorded_v1",
            Self::ProcedureRevisionRecorded(_) => "procedure_revision_recorded_v1",
            Self::ProcedureStateRecorded(_) => "procedure_state_recorded_v1",
            Self::ProcedureUsageRecorded(_) => "procedure_usage_recorded_v1",
            Self::ProcedureNegativeEvidenceRecorded(_) => "procedure_negative_evidence_recorded_v1",
            Self::ProcedureNegativeReviewRecorded(_) => "procedure_negative_review_recorded_v1",
            Self::ScenarioRecorded(_) => "scenario_recorded_v1",
            Self::CoreMembershipRecorded(_) => "core_membership_recorded_v1",
            Self::GlobalSupportContractRecorded(_) => "global_support_contract_recorded_v1",
            Self::GlobalSupportValidationRecorded(_) => "global_support_validation_recorded_v1",
            Self::SemanticDigestRecorded(_) => "semantic_digest_recorded_v1",
            Self::SemanticDerivationRunRecorded(_) => "semantic_derivation_run_recorded_v1",
            Self::RecallLedgerRecorded(_) => "recall_ledger_recorded_v1",
        }
    }

    pub const fn record_class(&self) -> RecordClass {
        match self {
            Self::MigrationApplied(_)
            | Self::WatermarkAdvanced(_)
            | Self::EvidenceSurfaceRecorded(_) => RecordClass::ProjectionControl,
            Self::SourceRevisionRecorded(_)
            | Self::SourceReceiptRecorded(_)
            | Self::SourceObservationRecorded(_)
            | Self::HostOccurrenceNormalized(_)
            | Self::OperationDerived(_)
            | Self::ScopeEffectDerived(_) => RecordClass::ObjectEvent,
            Self::ExecutionLaneRecorded(_)
            | Self::CaptureReceiptRecorded(_)
            | Self::CaptureGapMarkerRecorded(_)
            | Self::CaptureOutageIntervalRecorded(_)
            | Self::RepositoryInstanceRecorded(_)
            | Self::WorktreeInstanceRecorded(_)
            | Self::WorktreeSnapshotRecorded(_)
            | Self::WorktreeTransitionRecorded(_)
            | Self::IntegrationEventRecorded(_) => RecordClass::ObjectEvent,
            Self::TaskRecorded(_)
            | Self::WorkstreamRecorded(_)
            | Self::WorkBindingRecorded(_)
            | Self::AttemptRecorded(_)
            | Self::CompetingAttemptGroupRecorded(_) => RecordClass::ObjectEvent,
            Self::OperationBurstRecorded(_)
            | Self::WorkEpisodeRecorded(_)
            | Self::WorkCheckpointRecorded(_) => RecordClass::ObjectEvent,
            Self::SegmentationCorrectionRecorded(_) => RecordClass::ObjectEvent,
            Self::RecoveryCaptureRequestRecorded(_)
            | Self::RecoveryBundleRecorded(_)
            | Self::RecoveryApplicationRecorded(_) => RecordClass::ObjectEvent,
            Self::ExperimentRunRecorded(_)
            | Self::ResultEvidenceRecorded(_)
            | Self::WorkArtifactRecorded(_)
            | Self::AtomRecorded(_)
            | Self::RevisionProposalRecorded(_)
            | Self::ProcedureRevisionRecorded(_)
            | Self::ProcedureStateRecorded(_)
            | Self::ProcedureUsageRecorded(_)
            | Self::ProcedureNegativeEvidenceRecorded(_)
            | Self::ProcedureNegativeReviewRecorded(_)
            | Self::ScenarioRecorded(_)
            | Self::CoreMembershipRecorded(_)
            | Self::GlobalSupportContractRecorded(_)
            | Self::GlobalSupportValidationRecorded(_)
            | Self::SemanticDigestRecorded(_)
            | Self::SemanticDerivationRunRecorded(_)
            | Self::RecallLedgerRecorded(_) => RecordClass::ObjectEvent,
            _ => RecordClass::RuntimeEvent,
        }
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        match self {
            Self::MigrationApplied(value) => validate_identifier(&value.migration_id),
            Self::DirtyTarget(value) => validate_dirty(value),
            Self::OutboxEnqueued(value) => {
                validate_identifier(&value.outbox_id)?;
                validate_dirty(&value.dirty)
            }
            Self::JobState(value) => validate_job(value),
            Self::JobLease(value) => {
                if value.target_generation == 0 || value.attempt == 0 || value.lease_until_us <= 0 {
                    return Err(StoreError::InvalidInput);
                }
                Ok(())
            }
            Self::WatermarkAdvanced(_) => Ok(()),
            Self::ConfigAudit(value) => {
                if value.config_version == 0 {
                    return Err(StoreError::InvalidInput);
                }
                Ok(())
            }
            Self::StaleGenerationAudit(value) => {
                if value.expected_generation == value.observed_generation {
                    return Err(StoreError::InvalidInput);
                }
                Ok(())
            }
            Self::SourceRevisionRecorded(value) => {
                validate_identifier(value.source_instance_id.as_str())?;
                validate_identifier(value.source_revision.as_str())?;
                if value.recorded_at_us < 0
                    || (value.mode == SourceRevisionMode::Replacement
                        && value.previous_source_revision.is_none())
                    || (value.mode == SourceRevisionMode::Append
                        && value.previous_source_revision.is_some())
                {
                    return Err(StoreError::InvalidInput);
                }
                if let Some(previous) = &value.previous_source_revision {
                    validate_identifier(previous.as_str())?;
                    if previous == &value.source_revision {
                        return Err(StoreError::InvalidInput);
                    }
                }
                Ok(())
            }
            Self::SourceReceiptRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::SourceObservationRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::SourceIngestWatermark(value) => {
                validate_identifier(value.source_instance_id.as_str())?;
                validate_identifier(value.source_revision.as_str())
            }
            Self::EvidenceSurfaceRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::HostOccurrenceNormalized(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::OperationDerived(value) => value.validate().map_err(|_| StoreError::InvalidInput),
            Self::ScopeEffectDerived(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::NormalizationWatermark(value) => {
                if value.resolver_version == 0 {
                    return Err(StoreError::InvalidInput);
                }
                Ok(())
            }
            Self::ExecutionLaneRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::CaptureReceiptRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::CaptureGapMarkerRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::CaptureOutageIntervalRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::SourceCloseReconciliation(value) => value.validate(),
            Self::RepositoryInstanceRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::WorktreeInstanceRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::WorktreeSnapshotRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::WorktreeTransitionRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::IntegrationEventRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::TaskRecorded(value) => value.validate().map_err(|_| StoreError::InvalidInput),
            Self::WorkstreamRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::WorkBindingRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::AttemptRecorded(value) => value.validate().map_err(|_| StoreError::InvalidInput),
            Self::CompetingAttemptGroupRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::OperationBurstRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::WorkEpisodeRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::WorkCheckpointRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::SegmentationCorrectionRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::RecoveryCaptureRequestRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::RecoveryBundleRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::RecoveryApplicationRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::ExperimentRunRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::ResultEvidenceRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::WorkArtifactRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::AtomRecorded(value) => value.validate().map_err(|_| StoreError::InvalidInput),
            Self::RevisionProposalRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::ProcedureRevisionRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::ProcedureStateRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::ProcedureUsageRecorded(value) => {
                if value.validate() {
                    Ok(())
                } else {
                    Err(StoreError::InvalidInput)
                }
            }
            Self::ProcedureNegativeEvidenceRecorded(value) => {
                if value.validate() {
                    Ok(())
                } else {
                    Err(StoreError::InvalidInput)
                }
            }
            Self::ProcedureNegativeReviewRecorded(value) => {
                if value.validate() {
                    Ok(())
                } else {
                    Err(StoreError::InvalidInput)
                }
            }
            Self::ScenarioRecorded(value) => value.validate().map_err(|_| StoreError::InvalidInput),
            Self::CoreMembershipRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::GlobalSupportContractRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::SemanticDigestRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::SemanticDerivationRunRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::GlobalSupportValidationRecorded(value) => {
                value.validate().map_err(|_| StoreError::InvalidInput)
            }
            Self::RecallLedgerRecorded(value) => {
                if value.validate() {
                    Ok(())
                } else {
                    Err(StoreError::InvalidInput)
                }
            }
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        match self {
            Self::MigrationApplied(value) => tagged(
                "migration_applied",
                vec![("migration_id", text(&value.migration_id))],
            ),
            Self::DirtyTarget(value) => tagged("dirty_target", dirty_entries(value)),
            Self::OutboxEnqueued(value) => tagged(
                "outbox_enqueued",
                vec![
                    ("outbox_id", text(&value.outbox_id)),
                    (
                        "dirty",
                        CanonicalValue::Map(
                            dirty_entries(&value.dirty)
                                .into_iter()
                                .map(|(key, value)| (key.into(), value))
                                .collect(),
                        ),
                    ),
                ],
            ),
            Self::JobState(value) => tagged(
                "job_state",
                vec![
                    ("job_id", text(&value.job_id.to_string())),
                    ("idempotency_key", text(&value.idempotency_key)),
                    ("target_revision", text(&value.target_revision)),
                    ("target_watermark", integer(value.target_watermark)),
                    ("target_generation", integer(value.target_generation)),
                    ("kind", text(&value.kind)),
                    (
                        "priority",
                        CanonicalValue::Integer(i128::from(value.priority)),
                    ),
                    ("state", text(job_status(value.state))),
                    ("attempt", integer(value.attempt)),
                    ("backoff_until_us", optional_i64(value.backoff_until_us)),
                    (
                        "config_hash",
                        CanonicalValue::Bytes(value.config_hash.to_vec()),
                    ),
                    ("lease_until_us", optional_i64(value.lease_until_us)),
                ],
            ),
            Self::JobLease(value) => tagged(
                "job_lease",
                vec![
                    ("job_id", text(&value.job_id.to_string())),
                    ("target_generation", integer(value.target_generation)),
                    ("attempt", integer(value.attempt)),
                    (
                        "lease_until_us",
                        CanonicalValue::Integer(i128::from(value.lease_until_us)),
                    ),
                ],
            ),
            Self::WatermarkAdvanced(value) => tagged(
                "watermark_advanced",
                vec![
                    ("kind", text(value.kind.as_str())),
                    ("value", integer(value.value)),
                ],
            ),
            Self::ConfigAudit(value) => tagged(
                "config_audit",
                vec![
                    ("config_version", integer(value.config_version)),
                    (
                        "effective_config_hash",
                        CanonicalValue::Bytes(value.effective_config_hash.to_vec()),
                    ),
                ],
            ),
            Self::StaleGenerationAudit(value) => tagged(
                "stale_generation_audit",
                vec![
                    ("job_id", text(&value.job_id.to_string())),
                    ("expected_generation", integer(value.expected_generation)),
                    ("observed_generation", integer(value.observed_generation)),
                ],
            ),
            Self::SourceRevisionRecorded(value) => tagged_json("source_revision_recorded", value),
            Self::SourceReceiptRecorded(value) => tagged_json("source_receipt_recorded", value),
            Self::SourceObservationRecorded(value) => {
                tagged_json("source_observation_recorded", value)
            }
            Self::SourceIngestWatermark(value) => tagged_json("source_ingest_watermark", value),
            Self::EvidenceSurfaceRecorded(value) => tagged_json("evidence_surface_recorded", value),
            Self::HostOccurrenceNormalized(value) => {
                tagged_json("host_occurrence_normalized", value)
            }
            Self::OperationDerived(value) => tagged_json("operation_derived", value),
            Self::ScopeEffectDerived(value) => tagged_json("scope_effect_derived", value),
            Self::NormalizationWatermark(value) => tagged_json("normalization_watermark", value),
            Self::ExecutionLaneRecorded(value) => tagged_json("execution_lane_recorded", value),
            Self::CaptureReceiptRecorded(value) => tagged_json("capture_receipt_recorded", value),
            Self::CaptureGapMarkerRecorded(value) => {
                tagged_json("capture_gap_marker_recorded", value)
            }
            Self::CaptureOutageIntervalRecorded(value) => {
                tagged_json("capture_outage_interval_recorded", value)
            }
            Self::SourceCloseReconciliation(value) => {
                tagged_json("source_close_reconciliation", value)
            }
            Self::RepositoryInstanceRecorded(value) => {
                tagged_json("repository_instance_recorded", value)
            }
            Self::WorktreeInstanceRecorded(value) => {
                tagged_json("worktree_instance_recorded", value)
            }
            Self::WorktreeSnapshotRecorded(value) => {
                tagged_json("worktree_snapshot_recorded", value)
            }
            Self::WorktreeTransitionRecorded(value) => {
                tagged_json("worktree_transition_recorded", value)
            }
            Self::IntegrationEventRecorded(value) => {
                tagged_json("integration_event_recorded", value)
            }
            Self::TaskRecorded(value) => tagged_json("task_recorded", value),
            Self::WorkstreamRecorded(value) => tagged_json("workstream_recorded", value),
            Self::WorkBindingRecorded(value) => tagged_json("work_binding_recorded", value),
            Self::AttemptRecorded(value) => tagged_json("attempt_recorded", value),
            Self::CompetingAttemptGroupRecorded(value) => {
                tagged_json("competing_attempt_group_recorded", value)
            }
            Self::OperationBurstRecorded(value) => tagged_json("operation_burst_recorded", value),
            Self::WorkEpisodeRecorded(value) => tagged_json("work_episode_recorded", value),
            Self::WorkCheckpointRecorded(value) => tagged_json("work_checkpoint_recorded", value),
            Self::SegmentationCorrectionRecorded(value) => {
                tagged_json("segmentation_correction_recorded", value)
            }
            Self::RecoveryCaptureRequestRecorded(value) => {
                tagged_json("recovery_capture_request_recorded", value)
            }
            Self::RecoveryBundleRecorded(value) => tagged_json("recovery_bundle_recorded", value),
            Self::RecoveryApplicationRecorded(value) => {
                tagged_json("recovery_application_recorded", value)
            }
            Self::ExperimentRunRecorded(value) => tagged_json("experiment_run_recorded", value),
            Self::ResultEvidenceRecorded(value) => tagged_json("result_evidence_recorded", value),
            Self::WorkArtifactRecorded(value) => tagged_json("work_artifact_recorded", value),
            Self::AtomRecorded(value) => tagged_json("atom_recorded", value),
            Self::RevisionProposalRecorded(value) => {
                tagged_json("revision_proposal_recorded", value)
            }
            Self::ProcedureRevisionRecorded(value) => {
                tagged_json("procedure_revision_recorded", value)
            }
            Self::ProcedureStateRecorded(value) => tagged_json("procedure_state_recorded", value),
            Self::ProcedureUsageRecorded(value) => tagged_json("procedure_usage_recorded", value),
            Self::ProcedureNegativeEvidenceRecorded(value) => {
                tagged_json("procedure_negative_evidence_recorded", value)
            }
            Self::ProcedureNegativeReviewRecorded(value) => {
                tagged_json("procedure_negative_review_recorded", value)
            }
            Self::ScenarioRecorded(value) => tagged_json("scenario_recorded", value),
            Self::CoreMembershipRecorded(value) => tagged_json("core_membership_recorded", value),
            Self::GlobalSupportContractRecorded(value) => {
                tagged_json("global_support_contract_recorded", value)
            }
            Self::GlobalSupportValidationRecorded(value) => {
                tagged_json("global_support_validation_recorded", value)
            }
            Self::SemanticDigestRecorded(value) => tagged_json("semantic_digest_recorded", value),
            Self::SemanticDerivationRunRecorded(value) => {
                tagged_json("semantic_derivation_run_recorded", value)
            }
            Self::RecallLedgerRecorded(value) => tagged_json("recall_ledger_recorded", value),
        }
    }

    pub fn canonical_json(&self) -> Result<String, StoreError> {
        serde_json::to_string(self).map_err(|_| StoreError::Serialization)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalEventDraft {
    pub occurred_at_us: i64,
    pub source_kind: SourceKind,
    pub scope: EventScope,
    pub causation_id: Option<String>,
    pub correlation_id: Option<String>,
    pub effective_config_hash: [u8; 32],
    pub algorithm_revision: String,
    pub payload: JournalPayload,
}

impl JournalEventDraft {
    pub fn runtime(
        occurred_at_us: i64,
        effective_config_hash: [u8; 32],
        algorithm_revision: impl Into<String>,
        payload: JournalPayload,
    ) -> Self {
        Self {
            occurred_at_us,
            source_kind: SourceKind::System,
            scope: EventScope::default(),
            causation_id: None,
            correlation_id: None,
            effective_config_hash,
            algorithm_revision: algorithm_revision.into(),
            payload,
        }
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.occurred_at_us < 0 {
            return Err(StoreError::InvalidInput);
        }
        validate_identifier(&self.algorithm_revision)?;
        validate_optional_identifier(self.causation_id.as_deref())?;
        validate_optional_identifier(self.correlation_id.as_deref())?;
        for value in [
            self.scope.project_id.as_deref(),
            self.scope.repository_id.as_deref(),
            self.scope.worktree_id.as_deref(),
            self.scope.task_id.as_deref(),
            self.scope.workstream_id.as_deref(),
            self.scope.session_id.as_deref(),
            self.scope.execution_lane_id.as_deref(),
        ] {
            validate_optional_identifier(value)?;
        }
        self.payload.validate()
    }

    fn canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                "occurred_at_us".into(),
                CanonicalValue::Integer(i128::from(self.occurred_at_us)),
            ),
            ("source_kind".into(), text(self.source_kind.as_str())),
            ("scope".into(), scope_value(&self.scope)),
            (
                "causation_id".into(),
                optional_text(self.causation_id.as_deref()),
            ),
            (
                "correlation_id".into(),
                optional_text(self.correlation_id.as_deref()),
            ),
            (
                "effective_config_hash".into(),
                CanonicalValue::Bytes(self.effective_config_hash.to_vec()),
            ),
            ("algorithm_revision".into(), text(&self.algorithm_revision)),
            ("payload".into(), self.payload.canonical_value()),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalCommand {
    command_id: CommandId,
    events: Vec<JournalEventDraft>,
}

impl JournalCommand {
    pub fn new(command_id: CommandId, events: Vec<JournalEventDraft>) -> Result<Self, StoreError> {
        if events.is_empty() || u16::try_from(events.len()).is_err() {
            return Err(StoreError::InvalidInput);
        }
        Ok(Self { command_id, events })
    }

    pub const fn command_id(&self) -> CommandId {
        self.command_id
    }

    pub fn events(&self) -> &[JournalEventDraft] {
        &self.events
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitOutcome {
    pub command_id: CommandId,
    pub first_seq: u64,
    pub last_seq: u64,
    pub event_ids: Vec<String>,
    pub replayed: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedEvent {
    pub event_id: String,
    pub ordinal: u16,
    pub event_type: &'static str,
    pub record_class: RecordClass,
    pub payload_json: String,
    pub content_hash: [u8; 32],
    pub draft: JournalEventDraft,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedCommand {
    pub command_id: CommandId,
    pub command_hash: [u8; 32],
    pub event_count: u16,
    pub events: Vec<PreparedEvent>,
}

fn validate_recovery_command(events: &[JournalEventDraft]) -> Result<(), StoreError> {
    let requests = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::RecoveryCaptureRequestRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let bundles = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::RecoveryBundleRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for (bundle_index, event) in events.iter().enumerate() {
        let JournalPayload::RecoveryBundleRecorded(bundle) = &event.payload else {
            continue;
        };
        let snapshot_position = events.iter().position(|candidate| {
            matches!(
                &candidate.payload,
                JournalPayload::WorktreeSnapshotRecorded(snapshot)
                    if snapshot.worktree_snapshot_id == bundle.source_snapshot_id
            )
        });
        if !bundle.attempt_anchor_claims.is_empty()
            && snapshot_position.is_some_and(|snapshot_index| snapshot_index >= bundle_index)
        {
            return Err(StoreError::InvalidInput);
        }
    }

    for (index, left) in requests.iter().enumerate() {
        if requests[index + 1..].iter().any(|right| {
            right.recovery_capture_request_id == left.recovery_capture_request_id
                || right.request_revision_id == left.request_revision_id
        }) {
            return Err(StoreError::InvalidInput);
        }
    }
    for (index, left) in bundles.iter().enumerate() {
        if bundles[index + 1..]
            .iter()
            .any(|right| right.recovery_bundle_id == left.recovery_bundle_id)
        {
            return Err(StoreError::InvalidInput);
        }
        let paired = requests.iter().any(|request| {
            request.request_status.is_terminal()
                && request.recovery_bundle_id == Some(left.recovery_bundle_id)
                && left
                    .trigger_request_ids
                    .contains(&request.recovery_capture_request_id)
                && request.pre_operation_snapshot_id == Some(left.source_snapshot_id)
                && request.worktree_instance_id == left.source_worktree_instance_id
        });
        if !paired {
            return Err(StoreError::InvalidInput);
        }
    }
    for request in requests {
        if request.request_status == RecoveryRequestStatus::Pending
            && (!bundles.is_empty() || request.parent_request_revision_id.is_some())
        {
            return Err(StoreError::InvalidInput);
        }
        if let Some(bundle_id) = request.recovery_bundle_id
            && let Some(bundle) = bundles
                .iter()
                .find(|bundle| bundle.recovery_bundle_id == bundle_id)
            && (!bundle
                .trigger_request_ids
                .contains(&request.recovery_capture_request_id)
                || request.pre_operation_snapshot_id != Some(bundle.source_snapshot_id)
                || request.worktree_instance_id != bundle.source_worktree_instance_id)
        {
            return Err(StoreError::InvalidInput);
        }
    }
    Ok(())
}

fn validate_semantic_command(events: &[JournalEventDraft]) -> Result<(), StoreError> {
    for (proposal_index, proposal) in
        events
            .iter()
            .enumerate()
            .filter_map(|(index, event)| match &event.payload {
                JournalPayload::RevisionProposalRecorded(value)
                    if value.status == evertrace_domain::semantic::ProposalStatus::Accepted =>
                {
                    Some((index, value.as_ref()))
                }
                _ => None,
            })
    {
        let acceptance = proposal
            .acceptance
            .as_ref()
            .ok_or(StoreError::InvalidInput)?;
        let (successor_ref, expected_support_refs, expected_contract_ref) = match acceptance
            .accepted_target
            .clone()
        {
            evertrace_domain::semantic::AcceptedProposalTarget::Atom {
                atom_id,
                atom_revision_id,
                ..
            } => {
                let matching_atoms = events
                    .iter()
                    .enumerate()
                    .filter_map(|(index, event)| {
                        if index > proposal_index
                            && let JournalPayload::AtomRecorded(atom) = &event.payload
                            && atom.atom_id == atom_id
                            && atom.revision_id == atom_revision_id
                            && atom.accepted_proposal_id == Some(proposal.proposal_id)
                            && atom.accepted_proposal_revision_id
                                == Some(proposal.proposal_revision_id)
                        {
                            Some(atom.as_ref())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                let [atom] = matching_atoms.as_slice() else {
                    return Err(StoreError::InvalidInput);
                };
                (
                    atom_revision_id.to_string(),
                    matches!(atom.scope, evertrace_domain::semantic::AtomScope::Global)
                        .then(|| atom.supports_revision_refs.clone()),
                    None,
                )
            }
            evertrace_domain::semantic::AcceptedProposalTarget::CoreMembership {
                core_membership_id,
                membership_revision_id,
            } => {
                let matching = events
                    .iter()
                    .enumerate()
                    .filter_map(|(index, event)| match &event.payload {
                        JournalPayload::CoreMembershipRecorded(value)
                            if index > proposal_index
                                && value.core_membership_id == core_membership_id
                                && value.membership_revision_id == membership_revision_id
                                && value.created_by_acceptance_ref
                                    == proposal.proposal_revision_id
                                && value.authorization_revision_refs
                                    == vec![proposal.proposal_revision_id] =>
                        {
                            Some(value.as_ref())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let [membership] = matching.as_slice() else {
                    return Err(StoreError::InvalidInput);
                };
                (
                    membership_revision_id.to_string(),
                    Some(vec![membership.atom_revision_id]),
                    Some(membership.support_contract_ref),
                )
            }
            evertrace_domain::semantic::AcceptedProposalTarget::Procedure {
                procedure_id,
                procedure_revision_id,
                ..
            } => {
                let matching = events
                    .iter()
                    .enumerate()
                    .filter_map(|(index, event)| match &event.payload {
                        JournalPayload::ProcedureRevisionRecorded(value)
                            if index > proposal_index
                                && value.procedure_id == procedure_id
                                && value.revision_id == procedure_revision_id =>
                        {
                            Some(value.as_ref())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let [procedure] = matching.as_slice() else {
                    return Err(StoreError::InvalidInput);
                };
                let evertrace_domain::semantic::ProposalPayload::Procedure(payload) =
                    &proposal.payload
                else {
                    return Err(StoreError::InvalidInput);
                };
                if procedure.draft != *payload.draft() {
                    return Err(StoreError::InvalidInput);
                }
                match (&proposal.payload, proposal.operation) {
                    (
                        evertrace_domain::semantic::ProposalPayload::Procedure(payload),
                        evertrace_domain::semantic::ProposalOperation::Create,
                    ) if matches!(
                        payload.as_ref(),
                        evertrace_domain::semantic::ProcedureProposalPayload::Create { .. }
                    ) && proposal.target_id.is_none()
                        && proposal.base_revision_id.is_none()
                        && procedure.parent_revision_id.is_none()
                        && procedure.revision_generation == 1 => {}
                    (
                        evertrace_domain::semantic::ProposalPayload::Procedure(payload),
                        evertrace_domain::semantic::ProposalOperation::Replace,
                    ) if matches!(
                        payload.as_ref(),
                        evertrace_domain::semantic::ProcedureProposalPayload::Replace { .. }
                    ) && proposal.target_id
                        == Some(evertrace_domain::semantic::ProposalTargetId::Procedure(
                            procedure.procedure_id,
                        ))
                        && proposal.base_revision_id == procedure.parent_revision_id
                        && procedure.revision_generation > 1 => {}
                    _ => return Err(StoreError::InvalidInput),
                }
                let target_states = events
                    .iter()
                    .filter_map(|event| match &event.payload {
                        JournalPayload::ProcedureStateRecorded(value)
                            if value.procedure_revision_id == procedure_revision_id =>
                        {
                            Some(value.as_ref())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let [initial_state] = target_states.as_slice() else {
                    return Err(StoreError::InvalidInput);
                };
                if initial_state.from_state.is_some()
                    || initial_state.to_state
                        != evertrace_domain::procedure::ProcedurePublicationState::ActiveProbationary
                    || initial_state.reason
                        != evertrace_domain::procedure::ProcedureStateReason::Accepted
                    || initial_state.resume_state.is_some()
                {
                    return Err(StoreError::InvalidInput);
                }
                if let Some(parent_revision_id) = procedure.parent_revision_id {
                    let parent_states = events
                        .iter()
                        .filter_map(|event| match &event.payload {
                            JournalPayload::ProcedureStateRecorded(value)
                                if value.procedure_revision_id == parent_revision_id =>
                            {
                                Some(value.as_ref())
                            }
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    let [superseded_parent] = parent_states.as_slice() else {
                        return Err(StoreError::InvalidInput);
                    };
                    if superseded_parent.from_state.is_none()
                        || superseded_parent.to_state
                            != evertrace_domain::procedure::ProcedurePublicationState::Superseded
                        || superseded_parent.reason
                            != evertrace_domain::procedure::ProcedureStateReason::Replaced
                        || superseded_parent.resume_state.is_some()
                    {
                        return Err(StoreError::InvalidInput);
                    }
                }
                (
                    procedure_revision_id.to_string(),
                    matches!(
                        procedure.draft.scope,
                        evertrace_domain::procedure::ProcedureScope::Global
                    )
                    .then(|| procedure.draft.support_revision_refs.clone()),
                    None,
                )
            }
        };
        let Some(expected_support_refs) = expected_support_refs else {
            continue;
        };
        let contracts = events
            .iter()
            .filter_map(|event| match &event.payload {
                JournalPayload::GlobalSupportContractRecorded(value)
                    if value.successor_revision_or_membership_ref == successor_ref =>
                {
                    Some(value.as_ref())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let [contract] = contracts.as_slice() else {
            return Err(StoreError::InvalidInput);
        };
        let validations = events
            .iter()
            .filter_map(|event| match &event.payload {
                JournalPayload::GlobalSupportValidationRecorded(value)
                    if value.support_contract_ref == contract.support_contract_revision_id
                        && value.successor_ref == successor_ref
                        && value.dependency_generation == 1
                        && value.state == evertrace_domain::semantic::GlobalSupportState::Valid =>
                {
                    Some(value.as_ref())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let [validation] = validations.as_slice() else {
            return Err(StoreError::InvalidInput);
        };
        if contract.support_revision_refs != expected_support_refs
            || expected_contract_ref
                .is_some_and(|expected| contract.support_contract_revision_id != expected)
            || contract.authorization_revision_refs != vec![proposal.proposal_revision_id]
            || contract.promotion_proposal_revision_id != proposal.proposal_revision_id
            || validation.surviving_support_refs != contract.support_revision_refs
            || !validation.invalid_or_missing_refs.is_empty()
            || validation.provenance_degraded
            || !validation.trigger_refs.is_empty()
            || validation.validator_revision != contract.promotion_validator_revision
        {
            return Err(StoreError::InvalidInput);
        }
        let matching_dirty = events
            .iter()
            .filter_map(|event| match &event.payload {
                JournalPayload::DirtyTarget(value)
                    if value.target_kind == DirtyTargetKind::RuntimeJob
                        && value.target_id == contract.support_contract_revision_id.to_string()
                        && value.source_watermark == 1 =>
                {
                    Some(value)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let [dirty] = matching_dirty.as_slice() else {
            return Err(StoreError::InvalidInput);
        };
        if events
            .iter()
            .filter(|event| {
                matches!(&event.payload, JournalPayload::OutboxEnqueued(value) if &value.dirty == *dirty)
            })
            .count()
            != 1
        {
            return Err(StoreError::InvalidInput);
        }
    }
    for procedure in events.iter().filter_map(|event| match &event.payload {
        JournalPayload::ProcedureRevisionRecorded(value) => Some(value.as_ref()),
        _ => None,
    }) {
        let matching_acceptances = events
            .iter()
            .filter(|event| {
                matches!(&event.payload, JournalPayload::RevisionProposalRecorded(proposal)
                    if proposal.status == evertrace_domain::semantic::ProposalStatus::Accepted
                        && matches!(proposal.acceptance.as_ref().map(|value| &value.accepted_target),
                            Some(evertrace_domain::semantic::AcceptedProposalTarget::Procedure {
                                procedure_id,
                                procedure_revision_id,
                                ..
                            }) if *procedure_id == procedure.procedure_id
                                && *procedure_revision_id == procedure.revision_id))
            })
            .count();
        if matching_acceptances != 1 {
            return Err(StoreError::InvalidInput);
        }
    }
    for contract in events.iter().filter_map(|event| match &event.payload {
        JournalPayload::GlobalSupportContractRecorded(value) => Some(value.as_ref()),
        _ => None,
    }) {
        if events
            .iter()
            .filter(|event| {
                matches!(&event.payload, JournalPayload::RevisionProposalRecorded(proposal)
                    if proposal.proposal_revision_id == contract.promotion_proposal_revision_id
                        && proposal.status == evertrace_domain::semantic::ProposalStatus::Accepted)
            })
            .count()
            != 1
        {
            return Err(StoreError::InvalidInput);
        }
    }
    for atom in events.iter().filter_map(|event| match &event.payload {
        JournalPayload::AtomRecorded(value) if value.accepted_proposal_revision_id.is_some() => {
            Some(value.as_ref())
        }
        _ => None,
    }) {
        let (Some(proposal_id), Some(proposal_revision_id)) = (
            atom.accepted_proposal_id,
            atom.accepted_proposal_revision_id,
        ) else {
            return Err(StoreError::InvalidInput);
        };
        let matching = events
            .iter()
            .filter(|event| {
                matches!(
                    &event.payload,
                    JournalPayload::RevisionProposalRecorded(proposal)
                        if proposal.proposal_id == proposal_id
                            && proposal.proposal_revision_id == proposal_revision_id
                            && proposal.status
                                == evertrace_domain::semantic::ProposalStatus::Accepted
                )
            })
            .count();
        if matching != 1 {
            return Err(StoreError::InvalidInput);
        }
    }
    for negative in events.iter().filter_map(|event| match &event.payload {
        JournalPayload::ProcedureNegativeEvidenceRecorded(value) => Some(value.as_ref()),
        _ => None,
    }) {
        let reviews = events
            .iter()
            .filter_map(|event| match &event.payload {
                JournalPayload::ProcedureNegativeReviewRecorded(value)
                    if value.negative_evidence_id == negative.negative_evidence_id
                        && value.review_generation == 1
                        && value.status
                            == evertrace_domain::procedure::ProcedureNegativeReviewStatus::Pending =>
                {
                    Some(value.as_ref())
                }
                _ => None,
            })
            .count();
        let states = events
            .iter()
            .filter_map(|event| match &event.payload {
                JournalPayload::ProcedureStateRecorded(value)
                    if value.procedure_revision_id == negative.procedure_revision_id
                        && value.evidence_refs
                            == vec![negative.negative_evidence_id.to_string()] =>
                {
                    Some((value.to_state, value.reason))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let expected_state = match negative.level {
            evertrace_domain::procedure::ProcedureNegativeLevel::Ineffective => None,
            evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                if negative.attribution_basis
                    == evertrace_domain::procedure::ProcedureAttributionBasis::ResolvedLocalized =>
            {
                None
            }
            evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm => Some((
                evertrace_domain::procedure::ProcedurePublicationState::ReviewHold,
                evertrace_domain::procedure::ProcedureStateReason::SuspectedHarm,
            )),
            evertrace_domain::procedure::ProcedureNegativeLevel::ConfirmedHarm => Some((
                evertrace_domain::procedure::ProcedurePublicationState::Suspended,
                evertrace_domain::procedure::ProcedureStateReason::ConfirmedHarm,
            )),
        };
        if reviews != 1
            || states.len() > 1
            || states
                .first()
                .is_some_and(|state| Some(*state) != expected_state)
        {
            return Err(StoreError::InvalidInput);
        }
    }
    for state in events.iter().filter_map(|event| match &event.payload {
        JournalPayload::ProcedureStateRecorded(value)
            if value.to_state
                == evertrace_domain::procedure::ProcedurePublicationState::ActiveStable
                && value.reason
                    == evertrace_domain::procedure::ProcedureStateReason::ObjectiveSuccesses =>
        {
            Some(value.as_ref())
        }
        _ => None,
    }) {
        let usages = events
            .iter()
            .filter_map(|event| match &event.payload {
                JournalPayload::ProcedureUsageRecorded(value)
                    if value.procedure_revision_id == state.procedure_revision_id
                        && value.outcome_supported
                            == evertrace_domain::procedure::ProcedureTruth::True
                        && state
                            .evidence_refs
                            .contains(&value.usage_revision_id.to_string()) =>
                {
                    Some(value.as_ref())
                }
                _ => None,
            })
            .count();
        if usages != 1 {
            return Err(StoreError::InvalidInput);
        }
    }
    Ok(())
}

pub(crate) fn prepare_command(command: &JournalCommand) -> Result<PreparedCommand, StoreError> {
    let event_count = u16::try_from(command.events.len()).map_err(|_| StoreError::InvalidInput)?;
    if event_count == 0 {
        return Err(StoreError::InvalidInput);
    }
    for draft in &command.events {
        draft.validate()?;
    }
    for outbox in command.events.iter().filter_map(|draft| {
        if let JournalPayload::OutboxEnqueued(outbox) = &draft.payload {
            Some(outbox)
        } else {
            None
        }
    }) {
        let paired_dirty = command.events.iter().any(|draft| {
            matches!(&draft.payload, JournalPayload::DirtyTarget(dirty) if dirty == &outbox.dirty)
        });
        if !paired_dirty {
            return Err(StoreError::InvalidInput);
        }
    }
    validate_evidence_command(&command.events)?;
    validate_normalization_command(&command.events)?;
    crate::repository::validate_repository_command(&command.events)?;
    validate_recovery_command(&command.events)?;
    validate_semantic_command(&command.events)?;
    validate_work_identity_command(&command.events)?;
    let command_value = CanonicalValue::Map(vec![
        ("command_id".into(), text(&command.command_id.to_string())),
        (
            "events".into(),
            CanonicalValue::Sequence(
                command
                    .events
                    .iter()
                    .map(JournalEventDraft::canonical_value)
                    .collect(),
            ),
        ),
    ]);
    let command_hash =
        sha256("journal_command_v1", 1, &command_value).map_err(|_| StoreError::Serialization)?;
    let mut events = Vec::with_capacity(command.events.len());
    for (index, draft) in command.events.iter().cloned().enumerate() {
        let ordinal = u16::try_from(index).map_err(|_| StoreError::InvalidInput)?;
        let event_hash = sha256(
            "journal_event_v1",
            1,
            &CanonicalValue::Sequence(vec![
                text(&command.command_id.to_string()),
                integer(ordinal),
            ]),
        )
        .map_err(|_| StoreError::Serialization)?;
        let content_hash = sha256(
            "journal_payload_v1",
            u32::from(JOURNAL_PAYLOAD_SCHEMA),
            &draft.payload.canonical_value(),
        )
        .map_err(|_| StoreError::Serialization)?;
        let payload_json = draft.payload.canonical_json()?;
        events.push(PreparedEvent {
            event_id: hex(&event_hash),
            ordinal,
            event_type: draft.payload.event_type(),
            record_class: draft.payload.record_class(),
            payload_json,
            content_hash,
            draft,
        });
    }
    Ok(PreparedCommand {
        command_id: command.command_id,
        command_hash,
        event_count,
        events,
    })
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StoreError {
    #[error("store input is invalid")]
    InvalidInput,
    #[error("store path is invalid")]
    InvalidPath,
    #[error("store path has an invalid type")]
    InvalidType,
    #[error("store path has the wrong owner")]
    WrongOwner,
    #[error("store path permissions are invalid")]
    InvalidPermissions,
    #[error("another store writer is active")]
    WriterAlreadyRunning,
    #[error("journal command conflicts with an existing command")]
    IdempotencyConflict,
    #[error("journal frontier changed before command append")]
    StaleFrontier,
    #[error("S10 reconciliation dependency closure exceeds its safety ceiling")]
    ReconciliationDependencyOverflow,
    #[error("store data is corrupt")]
    StoreCorrupt,
    #[error("store migration failed")]
    Migration,
    #[error("store projection failed")]
    Projection,
    #[error("store serialization failed")]
    Serialization,
    #[error("store Arrow operation failed")]
    Arrow,
    #[error("store LanceDB operation failed")]
    LanceDb,
    #[error("store I/O operation failed")]
    Io,
}

impl fmt::Display for DirtyTargetKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn validate_dirty(value: &DirtyTarget) -> Result<(), StoreError> {
    validate_identifier(&value.target_id)?;
    validate_identifier(&value.algorithm_revision)
}

fn validate_job(value: &DurableJob) -> Result<(), StoreError> {
    for item in [
        value.idempotency_key.as_str(),
        value.target_revision.as_str(),
        value.kind.as_str(),
    ] {
        validate_identifier(item)?;
    }
    if value.target_generation == 0
        || value.attempt == 0
        || value.backoff_until_us.is_some_and(|time| time < 0)
        || value.lease_until_us.is_some_and(|time| time <= 0)
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}

fn validate_optional_identifier(value: Option<&str>) -> Result<(), StoreError> {
    value.map_or(Ok(()), validate_identifier)
}

pub fn source_revision_ref(
    source_instance_id: &SourceInstanceId,
    source_revision: &SourceRevision,
) -> String {
    format!(
        "{}@{}",
        source_instance_id.as_str(),
        source_revision.as_str()
    )
}

fn require_unique_strings(values: &[String]) -> Result<(), StoreError> {
    if values
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != values.len()
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}

fn require_unique_values<T: Ord>(values: &[T]) -> Result<(), StoreError> {
    if values
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != values.len()
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}

fn validate_work_identity_command(events: &[JournalEventDraft]) -> Result<(), StoreError> {
    let tasks = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::TaskRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut by_id = std::collections::BTreeMap::new();
    for task in &tasks {
        if by_id.insert(task.task_id, *task).is_some() {
            return Err(StoreError::InvalidInput);
        }
    }
    for task in &tasks {
        if !task.split_into_task_ids.is_empty() {
            if task.predecessor_revision_id.is_none() || !task.lifecycle.is_terminal() {
                return Err(StoreError::InvalidInput);
            }
            for child_id in &task.split_into_task_ids {
                let child = by_id.get(child_id).ok_or(StoreError::InvalidInput)?;
                if child.split_from_task_id != Some(task.task_id)
                    || child.predecessor_revision_id.is_some()
                {
                    return Err(StoreError::InvalidInput);
                }
            }
        }
        if let Some(source_id) = task.split_from_task_id {
            let source = by_id.get(&source_id).ok_or(StoreError::InvalidInput)?;
            if !source.split_into_task_ids.contains(&task.task_id) {
                return Err(StoreError::InvalidInput);
            }
        }
        if !task.merged_from_task_ids.is_empty() {
            for source_id in &task.merged_from_task_ids {
                let source = by_id.get(source_id).ok_or(StoreError::InvalidInput)?;
                if source.merged_into_task_id != Some(task.task_id)
                    || source.predecessor_revision_id.is_none()
                    || !source.lifecycle.is_terminal()
                {
                    return Err(StoreError::InvalidInput);
                }
            }
        }
        if let Some(target_id) = task.merged_into_task_id {
            let target = by_id.get(&target_id).ok_or(StoreError::InvalidInput)?;
            if !target.merged_from_task_ids.contains(&task.task_id) {
                return Err(StoreError::InvalidInput);
            }
        }
    }
    Ok(())
}

fn validate_evidence_command(events: &[JournalEventDraft]) -> Result<(), StoreError> {
    let has_evidence = events.iter().any(|event| {
        matches!(
            &event.payload,
            JournalPayload::SourceRevisionRecorded(_)
                | JournalPayload::SourceReceiptRecorded(_)
                | JournalPayload::SourceObservationRecorded(_)
                | JournalPayload::SourceIngestWatermark(_)
                | JournalPayload::EvidenceSurfaceRecorded(_)
        )
    });
    if !has_evidence {
        return Ok(());
    }
    let receipts = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::SourceReceiptRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let observations = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::SourceObservationRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let watermarks = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::SourceIngestWatermark(value) => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    let surfaces = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::EvidenceSurfaceRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let surface_dirty = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::DirtyTarget(value)
                if value.target_kind == DirtyTargetKind::EvidenceSurface =>
            {
                Some(value)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let normalization_dirty = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::DirtyTarget(value)
                if value.target_kind == DirtyTargetKind::PhysicalNormalization =>
            {
                Some(value)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if receipts.len() != 1
        || observations.len() != 1
        || watermarks.len() != 1
        || surface_dirty.len() != 1
        || normalization_dirty.len() != 1
        || surfaces.len() > 1
    {
        return Err(StoreError::InvalidInput);
    }
    let receipt = receipts[0];
    let observation = observations[0];
    let watermark = watermarks[0];
    let surface_dirty = surface_dirty[0];
    let normalization_dirty = normalization_dirty[0];
    if receipt.source_observation_id != observation.source_observation_id
        || receipt.source_receipt_id != observation.source_receipt_ref
        || receipt.source_instance_id != observation.source_instance_id
        || receipt.source_revision != observation.source_revision
        || receipt.source_record_identity != observation.source_record_identity
        || receipt.source_instance_id != watermark.source_instance_id
        || receipt.source_revision != watermark.source_revision
        || receipt.source_sequence != watermark.source_sequence
        || surface_dirty.target_id != observation.source_observation_id.to_string()
        || surface_dirty.source_watermark != receipt.source_sequence
        || normalization_dirty.target_id != observation.source_observation_id.to_string()
        || normalization_dirty.source_watermark != receipt.source_sequence
        || surfaces.first().is_some_and(|surface| {
            surface.source_observation_revision_ref != observation.source_observation_id
        })
    {
        return Err(StoreError::InvalidInput);
    }
    for revision in events.iter().filter_map(|event| match &event.payload {
        JournalPayload::SourceRevisionRecorded(value) => Some(value),
        _ => None,
    }) {
        if revision.source_instance_id != receipt.source_instance_id
            || revision.source_revision != receipt.source_revision
            || revision.mode != receipt.source_revision_mode
            || revision.previous_source_revision != receipt.previous_source_revision
        {
            return Err(StoreError::InvalidInput);
        }
    }
    Ok(())
}

fn validate_normalization_command(events: &[JournalEventDraft]) -> Result<(), StoreError> {
    let occurrences = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::HostOccurrenceNormalized(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let operations = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::OperationDerived(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let effects = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::ScopeEffectDerived(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let watermarks = events
        .iter()
        .filter_map(|event| match &event.payload {
            JournalPayload::NormalizationWatermark(value) => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    if occurrences.is_empty()
        && operations.is_empty()
        && effects.is_empty()
        && watermarks.is_empty()
    {
        return Ok(());
    }
    if occurrences.is_empty() || watermarks.is_empty() {
        return Err(StoreError::InvalidInput);
    }
    let occurrence_ids = occurrences
        .iter()
        .map(|value| value.host_occurrence_id)
        .collect::<std::collections::BTreeSet<_>>();
    let operation_ids = operations
        .iter()
        .map(|value| value.operation_id)
        .collect::<std::collections::BTreeSet<_>>();
    let effect_ids = effects
        .iter()
        .map(|value| value.scope_effect_id)
        .collect::<std::collections::BTreeSet<_>>();
    if occurrence_ids.len() != occurrences.len()
        || operation_ids.len() != operations.len()
        || effect_ids.len() != effects.len()
        || operations
            .iter()
            .any(|operation| !occurrence_ids.contains(&operation.host_occurrence_id))
        || effects
            .iter()
            .any(|effect| !operation_ids.contains(&effect.operation_id))
        || operations.iter().any(|operation| {
            operation
                .scope_effect_ids
                .iter()
                .any(|id| !effect_ids.contains(id))
        })
        || watermarks.iter().any(|watermark| {
            !occurrences.iter().any(|occurrence| {
                occurrence
                    .source_observation_refs
                    .contains(&watermark.source_observation_id)
                    && occurrence.correlation_resolver_version == watermark.resolver_version
            })
        })
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}

fn tagged(kind: &str, entries: Vec<(&str, CanonicalValue)>) -> CanonicalValue {
    CanonicalValue::Map(vec![
        ("kind".into(), text(kind)),
        (
            "value".into(),
            CanonicalValue::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.into(), value))
                    .collect(),
            ),
        ),
    ])
}

fn tagged_json(kind: &str, value: &impl Serialize) -> CanonicalValue {
    tagged(
        kind,
        vec![(
            "closed_payload_json",
            text(&serde_json::to_string(value).expect("closed evidence payload serializes")),
        )],
    )
}

fn dirty_entries(value: &DirtyTarget) -> Vec<(&'static str, CanonicalValue)> {
    vec![
        ("target_kind", text(value.target_kind.as_str())),
        ("target_id", text(&value.target_id)),
        ("algorithm_revision", text(&value.algorithm_revision)),
        ("source_watermark", integer(value.source_watermark)),
    ]
}

fn scope_value(value: &EventScope) -> CanonicalValue {
    CanonicalValue::Map(vec![
        (
            "project_id".into(),
            optional_text(value.project_id.as_deref()),
        ),
        (
            "repository_id".into(),
            optional_text(value.repository_id.as_deref()),
        ),
        (
            "worktree_id".into(),
            optional_text(value.worktree_id.as_deref()),
        ),
        ("task_id".into(), optional_text(value.task_id.as_deref())),
        (
            "workstream_id".into(),
            optional_text(value.workstream_id.as_deref()),
        ),
        (
            "session_id".into(),
            optional_text(value.session_id.as_deref()),
        ),
        (
            "execution_lane_id".into(),
            optional_text(value.execution_lane_id.as_deref()),
        ),
    ])
}

fn job_status(value: JobStatus) -> &'static str {
    match value {
        JobStatus::Queued => "queued",
        JobStatus::Leased => "leased",
        JobStatus::Succeeded => "succeeded",
        JobStatus::Failed => "failed",
    }
}

fn text(value: &str) -> CanonicalValue {
    CanonicalValue::String(value.to_owned())
}

fn optional_text(value: Option<&str>) -> CanonicalValue {
    value.map_or(CanonicalValue::Null, text)
}

fn optional_i64(value: Option<i64>) -> CanonicalValue {
    value.map_or(CanonicalValue::Null, |value| {
        CanonicalValue::Integer(i128::from(value))
    })
}

fn integer(value: impl Into<i128>) -> CanonicalValue {
    CanonicalValue::Integer(value.into())
}

fn length_key(parts: &[&str]) -> String {
    let mut output = String::new();
    for part in parts {
        output.push_str(&part.len().to_string());
        output.push(':');
        output.push_str(part);
    }
    output
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_range() -> SourceCloseRange {
        SourceCloseRange {
            source_instance_id: SourceInstanceId::parse("source-a").unwrap(),
            source_revision: SourceRevision::parse("revision-a").unwrap(),
            eligible_event_manifest_refs: vec!["eligible-a".into()],
            first_sequence: 1,
            close_watermark: 3,
            observed_through_sequence: 3,
            admission_failure_observability: AdmissionFailureObservability::Complete,
            independent_reconciliation: None,
        }
    }

    #[test]
    fn source_close_decision_is_derived_and_tamper_evident() {
        let lane_id = ExecutionLaneId::new_v7();
        let passed = SourceCloseReconciliation::new(
            "close-proof-a",
            lane_id,
            vec![direct_range()],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(passed.decision(), SourceCloseDecision::Passed);

        let failed = SourceCloseReconciliation::new(
            "close-proof-b",
            lane_id,
            vec![direct_range()],
            vec!["gap-a".into()],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(failed.decision(), SourceCloseDecision::Failed);

        let mut encoded = serde_json::to_value(&passed).unwrap();
        encoded["decision"] = serde_json::Value::String("failed".into());
        let forged: SourceCloseReconciliation = serde_json::from_value(encoded).unwrap();
        assert_eq!(forged.validate(), Err(StoreError::InvalidInput));
    }

    #[test]
    fn independent_source_must_be_distinct_and_cover_the_closed_range() {
        let mut range = direct_range();
        range.admission_failure_observability = AdmissionFailureObservability::Unavailable;
        range.independent_reconciliation = Some(IndependentSourceReconciliation {
            source_instance_id: range.source_instance_id.clone(),
            source_revision: range.source_revision.clone(),
            first_sequence: 1,
            last_sequence: 3,
            evidence_refs: vec!["independent-a".into()],
        });
        assert_eq!(
            SourceCloseReconciliation::new(
                "close-proof-c",
                ExecutionLaneId::new_v7(),
                vec![range],
                Vec::new(),
                Vec::new(),
            ),
            Err(StoreError::InvalidInput)
        );

        let mut distinct = direct_range();
        distinct.admission_failure_observability = AdmissionFailureObservability::Unavailable;
        distinct.independent_reconciliation = Some(IndependentSourceReconciliation {
            source_instance_id: SourceInstanceId::parse("source-independent").unwrap(),
            source_revision: SourceRevision::parse("revision-independent").unwrap(),
            first_sequence: 100,
            last_sequence: 102,
            evidence_refs: vec!["mapping-not-proven".into()],
        });
        let reconciliation = SourceCloseReconciliation::new(
            "close-proof-d",
            ExecutionLaneId::new_v7(),
            vec![distinct],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(reconciliation.decision(), SourceCloseDecision::Failed);
    }
}
