use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    canonical::{CanonicalValue, sha256},
    ids::{
        DuplicateGroupId, ExecutionLaneId, ExperimentRunId, HostOccurrenceId, OperationId,
        RepositoryId, ScopeEffectId, SourceObservationId, SourceReceiptId, TaskId, WorkArtifactId,
        WorktreeId, WorktreeSnapshotId,
    },
};

const MAX_IDENTITY_BYTES: usize = 256;
pub const MAX_EVIDENCE_SURFACE_BYTES: usize = 16 * 1024;

macro_rules! source_identity {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, EvidenceError> {
                let value = value.into();
                validate_identifier(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

source_identity!(SourceInstanceId);
source_identity!(SourceRevision);
source_identity!(SourceRecordIdentity);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStrength {
    StableNative,
    StableSourceSequence,
    SynthesizedBestEffort,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationRole {
    Intent,
    Result,
    Message,
    Lifecycle,
    StateProbe,
    Artifact,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalEventFamily {
    Read,
    Search,
    Mutate,
    Verify,
    Build,
    Launch,
    Observe,
    Integrate,
    OtherExecutable,
    Message,
    Lifecycle,
}

impl CanonicalEventFamily {
    pub const fn operation_kind(self) -> Option<OperationKind> {
        match self {
            Self::Read => Some(OperationKind::Read),
            Self::Search => Some(OperationKind::Search),
            Self::Mutate => Some(OperationKind::Mutate),
            Self::Verify => Some(OperationKind::Verify),
            Self::Build => Some(OperationKind::Build),
            Self::Launch => Some(OperationKind::Launch),
            Self::Observe => Some(OperationKind::Observe),
            Self::Integrate => Some(OperationKind::Integrate),
            Self::OtherExecutable => Some(OperationKind::Other),
            Self::Message | Self::Lifecycle => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationField {
    HostInstanceId,
    HostTraceLineageId,
    HostLaneKey,
    CanonicalEventFamily,
    NativeRequestId,
    PhysicalExecutionOrdinal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationAdmission {
    ExactCapable,
    Ambiguous,
    Conflicted,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationFieldClaim {
    pub field: CorrelationField,
    pub source_ref: String,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCorrelationEvidence {
    pub occurrence_schema_version: u32,
    pub host_instance_id: Option<String>,
    pub host_trace_lineage_id: Option<String>,
    pub host_lane_key: Option<String>,
    pub canonical_event_family: Option<CanonicalEventFamily>,
    pub native_request_id: Option<String>,
    pub physical_execution_ordinal: Option<u32>,
    pub pairing_role: ObservationRole,
    pub field_provenance: Vec<CorrelationFieldClaim>,
    pub adapter_manifest_ref: String,
    pub adapter_revision: u32,
    pub strong_gate_receipt_ref: Option<String>,
    pub admission: CorrelationAdmission,
    pub partial_correlation_ref: Option<String>,
    pub possible_duplicate_group_id: Option<DuplicateGroupId>,
}

impl HostCorrelationEvidence {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.occurrence_schema_version == 0 || self.adapter_revision == 0 {
            return Err(EvidenceError::InvalidCorrelation);
        }
        validate_identifier(&self.adapter_manifest_ref)?;
        for value in [
            self.host_instance_id.as_deref(),
            self.host_trace_lineage_id.as_deref(),
            self.host_lane_key.as_deref(),
            self.native_request_id.as_deref(),
            self.strong_gate_receipt_ref.as_deref(),
            self.partial_correlation_ref.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_identifier(value)?;
        }
        if self.physical_execution_ordinal == Some(0) {
            return Err(EvidenceError::InvalidCorrelation);
        }
        let expected_fields = self.present_fields();
        let mut observed = std::collections::BTreeSet::new();
        for claim in &self.field_provenance {
            validate_identifier(&claim.source_ref)?;
            validate_identifier(&claim.evidence_ref)?;
            if !expected_fields.contains(&claim.field) || !observed.insert(claim.field) {
                return Err(EvidenceError::InvalidCorrelation);
            }
        }
        if observed != expected_fields {
            return Err(EvidenceError::InvalidCorrelation);
        }
        let complete = self.exact_key().is_some();
        if self.admission == CorrelationAdmission::ExactCapable
            && (!complete || self.strong_gate_receipt_ref.is_none())
        {
            return Err(EvidenceError::InvalidCorrelation);
        }
        if self.admission != CorrelationAdmission::ExactCapable
            && self.strong_gate_receipt_ref.is_some()
        {
            return Err(EvidenceError::InvalidCorrelation);
        }
        if self.possible_duplicate_group_id.is_some() && self.partial_correlation_ref.is_none() {
            return Err(EvidenceError::InvalidCorrelation);
        }
        Ok(())
    }

    pub fn exact_key(&self) -> Option<HostOccurrenceExactKey> {
        if self.admission != CorrelationAdmission::ExactCapable
            || self.strong_gate_receipt_ref.is_none()
        {
            return None;
        }
        Some(HostOccurrenceExactKey {
            occurrence_schema_version: self.occurrence_schema_version,
            host_instance_id: self.host_instance_id.clone()?,
            host_trace_lineage_id: self.host_trace_lineage_id.clone()?,
            host_lane_key: self.host_lane_key.clone()?,
            canonical_event_family: self.canonical_event_family?,
            native_request_id: self.native_request_id.clone()?,
            physical_execution_ordinal: self.physical_execution_ordinal?,
        })
    }

    fn present_fields(&self) -> std::collections::BTreeSet<CorrelationField> {
        let mut fields = std::collections::BTreeSet::new();
        if self.host_instance_id.is_some() {
            fields.insert(CorrelationField::HostInstanceId);
        }
        if self.host_trace_lineage_id.is_some() {
            fields.insert(CorrelationField::HostTraceLineageId);
        }
        if self.host_lane_key.is_some() {
            fields.insert(CorrelationField::HostLaneKey);
        }
        if self.canonical_event_family.is_some() {
            fields.insert(CorrelationField::CanonicalEventFamily);
        }
        if self.native_request_id.is_some() {
            fields.insert(CorrelationField::NativeRequestId);
        }
        if self.physical_execution_ordinal.is_some() {
            fields.insert(CorrelationField::PhysicalExecutionOrdinal);
        }
        fields
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeEffectClaim {
    pub effect_role: EffectRole,
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_id: Option<WorktreeId>,
    pub pre_snapshot_id: Option<WorktreeSnapshotId>,
    pub post_snapshot_id: Option<WorktreeSnapshotId>,
    pub experiment_run_ids: Vec<ExperimentRunId>,
    pub artifact_refs: Vec<WorkArtifactId>,
    pub evidence_refs: Vec<SourceObservationId>,
}

impl ScopeEffectClaim {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.repository_instance_id.is_none()
            && self.worktree_instance_id.is_none()
            && self.pre_snapshot_id.is_none()
            && self.post_snapshot_id.is_none()
            && self.experiment_run_ids.is_empty()
            && self.artifact_refs.is_empty()
            && self.evidence_refs.is_empty()
        {
            return Err(EvidenceError::InvalidScopeEffect);
        }
        require_unique(&self.experiment_run_ids)?;
        require_unique(&self.artifact_refs)?;
        require_unique(&self.evidence_refs)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRole {
    User,
    Assistant,
    Tool,
    Host,
    Imported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceKind {
    CodexHook,
    CodexExecJsonl,
    CodexSessionJsonl,
    HermesSession,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedRecordClassification {
    UnknownRecordType,
    Reasoning,
    Binary,
    UnboundedToolOutput,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentTrust {
    UserStatement,
    Observed,
    AgentClaim,
    ImportedClaim,
    UntrustedSourceContent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionAuthority {
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureCompleteness {
    Complete,
    Partial,
    Opaque,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRevisionMode {
    Append,
    Replacement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceArchiveMode {
    Exact,
    Redacted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceByteRange {
    pub start: u64,
    pub end: u64,
}

impl EvidenceByteRange {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.end <= self.start {
            return Err(EvidenceError::InvalidRange);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRedactionSpan {
    pub start: u64,
    pub end: u64,
    pub kind: String,
}

impl EvidenceRedactionSpan {
    fn validate(&self, raw_length: u64) -> Result<(), EvidenceError> {
        if self.start >= self.end || self.end > raw_length {
            return Err(EvidenceError::InvalidRange);
        }
        validate_identifier(&self.kind)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReceipt {
    pub source_receipt_id: SourceReceiptId,
    pub source_observation_id: SourceObservationId,
    pub source_instance_id: SourceInstanceId,
    pub source_kind: EvidenceSourceKind,
    pub identity_domain: String,
    pub source_ref: String,
    pub source_session_ref: String,
    pub source_revision: SourceRevision,
    pub source_record_identity: SourceRecordIdentity,
    pub identity_strength: IdentityStrength,
    pub source_sequence: u64,
    pub task_id: Option<TaskId>,
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_id: Option<WorktreeId>,
    pub source_byte_range: Option<EvidenceByteRange>,
    pub spool_byte_range: EvidenceByteRange,
    pub source_revision_mode: SourceRevisionMode,
    pub previous_source_revision: Option<SourceRevision>,
    pub close_watermark: Option<u64>,
    pub observation_role: ObservationRole,
    pub unsupported_record_classification: Option<UnsupportedRecordClassification>,
    pub capture_completeness: CaptureCompleteness,
    pub archive_mode: SourceArchiveMode,
    pub cas_ref: String,
    pub protected_length: u64,
    pub original_length: u64,
    pub protected_secret_digest: Option<String>,
    pub redaction_spans: Vec<EvidenceRedactionSpan>,
    pub adapter_revision: u32,
    pub adapter_manifest_ref: String,
    pub eligible_event_manifest_ref: String,
    pub parser_revision: u32,
    pub canonicalization_revision: u32,
    pub detector_revision: u32,
    pub redaction_revision: u32,
    pub protection_key_generation: u64,
    pub event_time_us: i64,
    pub recorded_at_us: i64,
}

impl SourceReceipt {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_identifier(&self.source_session_ref)?;
        validate_identifier(&self.identity_domain)?;
        validate_identifier(&self.source_ref)?;
        validate_identifier(&self.adapter_manifest_ref)?;
        validate_identifier(&self.eligible_event_manifest_ref)?;
        validate_digest(&self.cas_ref)?;
        if self.source_receipt_id
            != source_receipt_id(
                &self.source_instance_id,
                &self.source_revision,
                &self.source_record_identity,
            )?
            || self.source_observation_id
                != source_observation_id(
                    &self.source_instance_id,
                    &self.source_revision,
                    &self.source_record_identity,
                )?
            || self.protected_length == 0
            || self.original_length == 0
            || self.adapter_revision == 0
            || self.parser_revision == 0
            || self.canonicalization_revision == 0
            || self.detector_revision == 0
            || self.redaction_revision == 0
            || self.protection_key_generation == 0
            || self.event_time_us < 0
            || self.recorded_at_us < 0
            || self.event_time_us > self.recorded_at_us
        {
            return Err(EvidenceError::Invalid);
        }
        self.spool_byte_range.validate()?;
        if let Some(range) = &self.source_byte_range {
            range.validate()?;
        }
        if self.source_revision_mode == SourceRevisionMode::Replacement
            && self.previous_source_revision.is_none()
        {
            return Err(EvidenceError::InvalidRevision);
        }
        if self.source_revision_mode == SourceRevisionMode::Append
            && self.previous_source_revision.is_some()
        {
            return Err(EvidenceError::InvalidRevision);
        }
        if self.identity_strength == IdentityStrength::SynthesizedBestEffort
            && self.capture_completeness == CaptureCompleteness::Complete
            || self.unsupported_record_classification.is_some()
                && self.capture_completeness == CaptureCompleteness::Complete
        {
            return Err(EvidenceError::InvalidCompleteness);
        }
        validate_redaction(
            self.archive_mode,
            self.original_length,
            self.protected_secret_digest.as_deref(),
            &self.redaction_spans,
        )
    }

    pub const fn capture_completeness(&self) -> CaptureCompleteness {
        self.capture_completeness
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceObservation {
    pub source_observation_id: SourceObservationId,
    pub source_instance_id: SourceInstanceId,
    pub source_revision: SourceRevision,
    pub source_record_identity: SourceRecordIdentity,
    pub observation_role: ObservationRole,
    pub identity_strength: IdentityStrength,
    pub payload_fingerprint: String,
    pub source_receipt_ref: SourceReceiptId,
    pub source_role: SourceRole,
    pub content_trust: ContentTrust,
    pub capture_completeness: CaptureCompleteness,
    pub adapter_revision: u32,
    pub parser_revision: u32,
    pub canonicalization_revision: u32,
    pub detector_revision: u32,
    pub redaction_revision: u32,
    pub correlation: HostCorrelationEvidence,
    pub scope_effect_claims: Vec<ScopeEffectClaim>,
}

impl SourceObservation {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_digest(&self.payload_fingerprint)?;
        if self.source_observation_id
            != source_observation_id(
                &self.source_instance_id,
                &self.source_revision,
                &self.source_record_identity,
            )?
            || self.source_receipt_ref
                != source_receipt_id(
                    &self.source_instance_id,
                    &self.source_revision,
                    &self.source_record_identity,
                )?
            || self.adapter_revision == 0
            || self.parser_revision == 0
            || self.canonicalization_revision == 0
            || self.detector_revision == 0
            || self.redaction_revision == 0
            || (self.identity_strength == IdentityStrength::SynthesizedBestEffort
                && self.capture_completeness == CaptureCompleteness::Complete)
        {
            return Err(EvidenceError::Invalid);
        }
        self.correlation.validate()?;
        if self.correlation.pairing_role != self.observation_role
            || self.correlation.adapter_revision != self.adapter_revision
        {
            return Err(EvidenceError::InvalidCorrelation);
        }
        for claim in &self.scope_effect_claims {
            claim.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostOccurrenceExactKey {
    pub occurrence_schema_version: u32,
    pub host_instance_id: String,
    pub host_trace_lineage_id: String,
    pub host_lane_key: String,
    pub canonical_event_family: CanonicalEventFamily,
    pub native_request_id: String,
    pub physical_execution_ordinal: u32,
}

impl HostOccurrenceExactKey {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.occurrence_schema_version == 0 || self.physical_execution_ordinal == 0 {
            return Err(EvidenceError::InvalidCorrelation);
        }
        for value in [
            &self.host_instance_id,
            &self.host_trace_lineage_id,
            &self.host_lane_key,
            &self.native_request_id,
        ] {
            validate_identifier(value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationStrength {
    Exact,
    Ambiguous,
    Conflicted,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizationState {
    SingleSource,
    Corroborated,
    Complemented,
    NormalizationConflicted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingState {
    NotApplicable,
    UnmatchedIntent,
    UnmatchedResult,
    Paired,
    Conflicted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Read,
    Search,
    Mutate,
    Verify,
    Build,
    Launch,
    Observe,
    Integrate,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectRole {
    Read,
    Mutate,
    Verify,
    Launch,
    Observe,
    Integrate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FieldProvenanceEntry {
    pub field: CorrelationField,
    pub source_observation_ref: SourceObservationId,
    pub source_ref: String,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostOccurrence {
    pub host_occurrence_id: HostOccurrenceId,
    pub exact_key: Option<HostOccurrenceExactKey>,
    pub host_instance_id: Option<String>,
    pub host_trace_lineage_id: Option<String>,
    pub host_lane_key: Option<String>,
    pub canonical_event_family: Option<CanonicalEventFamily>,
    pub native_request_id: Option<String>,
    pub physical_execution_ordinal: Option<u32>,
    pub correlation_strength: CorrelationStrength,
    pub source_observation_refs: Vec<SourceObservationId>,
    pub field_provenance: Vec<FieldProvenanceEntry>,
    pub normalization_state: NormalizationState,
    pub pairing_state: PairingState,
    pub possible_duplicate_group_id: Option<DuplicateGroupId>,
    pub correlation_resolver_version: u32,
    pub normalization_revision: u32,
    pub previous_normalization_revision: Option<u32>,
}

impl HostOccurrence {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.source_observation_refs.is_empty()
            || self.correlation_resolver_version == 0
            || self.normalization_revision == 0
            || self
                .previous_normalization_revision
                .is_some_and(|previous| {
                    previous == 0 || previous + 1 != self.normalization_revision
                })
            || (self.normalization_revision == 1 && self.previous_normalization_revision.is_some())
        {
            return Err(EvidenceError::InvalidOccurrence);
        }
        require_unique(&self.source_observation_refs)?;
        match self.correlation_strength {
            CorrelationStrength::Exact => {
                let key = self
                    .exact_key
                    .as_ref()
                    .ok_or(EvidenceError::InvalidOccurrence)?;
                key.validate()?;
                if self.host_occurrence_id != host_occurrence_id_for_exact(key)?
                    || self.host_instance_id.as_deref() != Some(&key.host_instance_id)
                    || self.host_trace_lineage_id.as_deref() != Some(&key.host_trace_lineage_id)
                    || self.host_lane_key.as_deref() != Some(&key.host_lane_key)
                    || self.canonical_event_family != Some(key.canonical_event_family)
                    || self.native_request_id.as_deref() != Some(&key.native_request_id)
                    || self.physical_execution_ordinal != Some(key.physical_execution_ordinal)
                    || self.possible_duplicate_group_id.is_some()
                {
                    return Err(EvidenceError::InvalidOccurrence);
                }
            }
            _ => {
                if self.exact_key.is_some()
                    || self.source_observation_refs.len() != 1
                    || self.host_occurrence_id
                        != host_occurrence_id_for_nonexact(
                            self.source_observation_refs[0],
                            self.correlation_strength,
                        )?
                {
                    return Err(EvidenceError::InvalidOccurrence);
                }
            }
        }
        let mut provenance = std::collections::BTreeSet::new();
        for entry in &self.field_provenance {
            if !self
                .source_observation_refs
                .contains(&entry.source_observation_ref)
                || !provenance.insert((entry.field, entry.source_observation_ref))
            {
                return Err(EvidenceError::InvalidOccurrence);
            }
            validate_identifier(&entry.source_ref)?;
            validate_identifier(&entry.evidence_ref)?;
        }
        let expected_fields = [
            (
                CorrelationField::HostInstanceId,
                self.host_instance_id.is_some(),
            ),
            (
                CorrelationField::HostTraceLineageId,
                self.host_trace_lineage_id.is_some(),
            ),
            (CorrelationField::HostLaneKey, self.host_lane_key.is_some()),
            (
                CorrelationField::CanonicalEventFamily,
                self.canonical_event_family.is_some(),
            ),
            (
                CorrelationField::NativeRequestId,
                self.native_request_id.is_some(),
            ),
            (
                CorrelationField::PhysicalExecutionOrdinal,
                self.physical_execution_ordinal.is_some(),
            ),
        ]
        .into_iter()
        .filter_map(|(field, present)| present.then_some(field))
        .collect::<std::collections::BTreeSet<_>>();
        for source in &self.source_observation_refs {
            let actual = self
                .field_provenance
                .iter()
                .filter(|entry| entry.source_observation_ref == *source)
                .map(|entry| entry.field)
                .collect::<std::collections::BTreeSet<_>>();
            if actual != expected_fields {
                return Err(EvidenceError::InvalidOccurrence);
            }
        }
        if (self.source_observation_refs.len() == 1
            && !matches!(
                self.normalization_state,
                NormalizationState::SingleSource | NormalizationState::NormalizationConflicted
            ))
            || (self.source_observation_refs.len() > 1
                && self.normalization_state == NormalizationState::SingleSource)
            || (self.correlation_strength == CorrelationStrength::Conflicted
                && self.normalization_state != NormalizationState::NormalizationConflicted)
        {
            return Err(EvidenceError::InvalidOccurrence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub operation_id: OperationId,
    pub host_occurrence_id: HostOccurrenceId,
    pub execution_lane_id: Option<ExecutionLaneId>,
    pub operation_kind: OperationKind,
    pub input_source_observation_refs: Vec<SourceObservationId>,
    pub result_source_observation_refs: Vec<SourceObservationId>,
    pub pairing_state: PairingState,
    pub scope_effect_ids: Vec<ScopeEffectId>,
    pub artifact_refs: Vec<WorkArtifactId>,
    pub operation_resolver_version: u32,
    pub operation_revision: u32,
    pub previous_operation_revision: Option<u32>,
}

impl Operation {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.operation_resolver_version == 0
            || self.operation_revision == 0
            || self
                .previous_operation_revision
                .is_some_and(|previous| previous == 0 || previous + 1 != self.operation_revision)
            || (self.operation_revision == 1 && self.previous_operation_revision.is_some())
        {
            return Err(EvidenceError::InvalidOperation);
        }
        require_unique(&self.input_source_observation_refs)?;
        require_unique(&self.result_source_observation_refs)?;
        require_unique(&self.scope_effect_ids)?;
        require_unique(&self.artifact_refs)?;
        if self
            .input_source_observation_refs
            .iter()
            .any(|value| self.result_source_observation_refs.contains(value))
            || match self.pairing_state {
                PairingState::Paired => {
                    self.input_source_observation_refs.is_empty()
                        || self.result_source_observation_refs.is_empty()
                }
                PairingState::UnmatchedIntent => {
                    self.input_source_observation_refs.is_empty()
                        || !self.result_source_observation_refs.is_empty()
                }
                PairingState::UnmatchedResult => {
                    !self.input_source_observation_refs.is_empty()
                        || self.result_source_observation_refs.is_empty()
                }
                PairingState::Conflicted => {
                    self.input_source_observation_refs.len() <= 1
                        && self.result_source_observation_refs.len() <= 1
                }
                PairingState::NotApplicable => false,
            }
        {
            return Err(EvidenceError::InvalidOperation);
        }
        if self.input_source_observation_refs.is_empty()
            && self.result_source_observation_refs.is_empty()
        {
            return Err(EvidenceError::InvalidOperation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeEffect {
    pub scope_effect_id: ScopeEffectId,
    pub operation_id: OperationId,
    pub effect_role: EffectRole,
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_id: Option<WorktreeId>,
    pub pre_snapshot_id: Option<WorktreeSnapshotId>,
    pub post_snapshot_id: Option<WorktreeSnapshotId>,
    pub experiment_run_ids: Vec<ExperimentRunId>,
    pub artifact_refs: Vec<WorkArtifactId>,
    pub evidence_refs: Vec<SourceObservationId>,
}

impl ScopeEffect {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        ScopeEffectClaim {
            effect_role: self.effect_role,
            repository_instance_id: self.repository_instance_id,
            worktree_instance_id: self.worktree_instance_id,
            pre_snapshot_id: self.pre_snapshot_id,
            post_snapshot_id: self.post_snapshot_id,
            experiment_run_ids: self.experiment_run_ids.clone(),
            artifact_refs: self.artifact_refs.clone(),
            evidence_refs: self.evidence_refs.clone(),
        }
        .validate()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSurface {
    pub source_observation_revision_ref: SourceObservationId,
    pub source_role: SourceRole,
    pub content_trust: ContentTrust,
    pub instruction_authority: InstructionAuthority,
    pub task_id: Option<TaskId>,
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_id: Option<WorktreeId>,
    pub event_time_us: i64,
    pub recorded_at_us: i64,
    pub source_sequence: u64,
    pub capture_completeness: CaptureCompleteness,
    pub canonicalization_version: u32,
    pub span_hash: String,
    pub projection_generation: u64,
    pub protected_text: String,
}

impl std::fmt::Debug for EvidenceSurface {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceSurface")
            .field(
                "source_observation_revision_ref",
                &self.source_observation_revision_ref,
            )
            .field("source_role", &self.source_role)
            .field("content_trust", &self.content_trust)
            .field("instruction_authority", &self.instruction_authority)
            .field("source_sequence", &self.source_sequence)
            .field("capture_completeness", &self.capture_completeness)
            .field("span_hash", &self.span_hash)
            .field("protected_text_length", &self.protected_text.len())
            .finish()
    }
}

impl EvidenceSurface {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.instruction_authority != InstructionAuthority::None
            || self.event_time_us < 0
            || self.recorded_at_us < 0
            || self.event_time_us > self.recorded_at_us
            || self.canonicalization_version == 0
            || self.projection_generation == 0
            || self.protected_text.is_empty()
            || self.protected_text.len() > MAX_EVIDENCE_SURFACE_BYTES
        {
            return Err(EvidenceError::Invalid);
        }
        validate_digest(&self.span_hash)?;
        let expected = evidence_span_hash(
            self.source_observation_revision_ref,
            self.canonicalization_version,
            &self.protected_text,
        )?;
        if self.span_hash != hex(&expected) {
            return Err(EvidenceError::InvalidDigest);
        }
        Ok(())
    }
}

pub fn source_observation_id(
    source_instance_id: &SourceInstanceId,
    source_revision: &SourceRevision,
    source_record_identity: &SourceRecordIdentity,
) -> Result<SourceObservationId, EvidenceError> {
    Ok(SourceObservationId::from_digest(source_identity_digest(
        "source_observation_id",
        source_instance_id,
        source_revision,
        source_record_identity,
    )?))
}

pub fn source_receipt_id(
    source_instance_id: &SourceInstanceId,
    source_revision: &SourceRevision,
    source_record_identity: &SourceRecordIdentity,
) -> Result<SourceReceiptId, EvidenceError> {
    Ok(SourceReceiptId::from_digest(source_identity_digest(
        "source_receipt_id",
        source_instance_id,
        source_revision,
        source_record_identity,
    )?))
}

pub fn host_occurrence_id_for_exact(
    key: &HostOccurrenceExactKey,
) -> Result<HostOccurrenceId, EvidenceError> {
    key.validate()?;
    Ok(HostOccurrenceId::from_digest(
        sha256(
            "host_occurrence_exact_key",
            key.occurrence_schema_version,
            &CanonicalValue::Sequence(vec![
                CanonicalValue::String(key.host_instance_id.clone()),
                CanonicalValue::String(key.host_trace_lineage_id.clone()),
                CanonicalValue::String(key.host_lane_key.clone()),
                CanonicalValue::String(event_family_name(key.canonical_event_family).into()),
                CanonicalValue::String(key.native_request_id.clone()),
                CanonicalValue::Integer(i128::from(key.physical_execution_ordinal)),
            ]),
        )
        .map_err(|_| EvidenceError::Canonical)?,
    ))
}

pub fn host_occurrence_id_for_nonexact(
    observation_id: SourceObservationId,
    strength: CorrelationStrength,
) -> Result<HostOccurrenceId, EvidenceError> {
    if strength == CorrelationStrength::Exact {
        return Err(EvidenceError::InvalidOccurrence);
    }
    Ok(HostOccurrenceId::from_digest(
        sha256(
            "host_occurrence_nonexact",
            1,
            &CanonicalValue::Sequence(vec![
                CanonicalValue::String(observation_id.to_string()),
                CanonicalValue::String(correlation_strength_name(strength).into()),
            ]),
        )
        .map_err(|_| EvidenceError::Canonical)?,
    ))
}

pub fn payload_fingerprint(
    canonicalization_version: u32,
    protected_payload: &[u8],
    protected_secret_digest: Option<[u8; 32]>,
) -> Result<[u8; 32], EvidenceError> {
    if canonicalization_version == 0 || protected_payload.is_empty() {
        return Err(EvidenceError::Invalid);
    }
    sha256(
        "source_payload_fingerprint",
        1,
        &CanonicalValue::Map(vec![
            (
                "canonicalization_version".into(),
                CanonicalValue::Integer(i128::from(canonicalization_version)),
            ),
            (
                "protected_payload".into(),
                CanonicalValue::Bytes(protected_payload.to_vec()),
            ),
            (
                "protected_secret_digest".into(),
                protected_secret_digest.map_or(CanonicalValue::Null, |value| {
                    CanonicalValue::Bytes(value.to_vec())
                }),
            ),
        ]),
    )
    .map_err(|_| EvidenceError::Canonical)
}

pub fn evidence_span_hash(
    source_observation_id: SourceObservationId,
    canonicalization_version: u32,
    protected_text: &str,
) -> Result<[u8; 32], EvidenceError> {
    if canonicalization_version == 0
        || protected_text.is_empty()
        || protected_text.len() > MAX_EVIDENCE_SURFACE_BYTES
    {
        return Err(EvidenceError::Invalid);
    }
    sha256(
        "evidence_surface_span",
        1,
        &CanonicalValue::Map(vec![
            (
                "source_observation_revision_ref".into(),
                CanonicalValue::String(source_observation_id.to_string()),
            ),
            (
                "canonicalization_version".into(),
                CanonicalValue::Integer(i128::from(canonicalization_version)),
            ),
            (
                "protected_text".into(),
                CanonicalValue::String(protected_text.to_owned()),
            ),
        ]),
    )
    .map_err(|_| EvidenceError::Canonical)
}

fn source_identity_digest(
    schema_tag: &str,
    source_instance_id: &SourceInstanceId,
    source_revision: &SourceRevision,
    source_record_identity: &SourceRecordIdentity,
) -> Result<[u8; 32], EvidenceError> {
    validate_identifier(source_instance_id.as_str())?;
    validate_identifier(source_revision.as_str())?;
    validate_identifier(source_record_identity.as_str())?;
    sha256(
        schema_tag,
        1,
        &CanonicalValue::Sequence(vec![
            CanonicalValue::String(source_instance_id.as_str().to_owned()),
            CanonicalValue::String(source_revision.as_str().to_owned()),
            CanonicalValue::String(source_record_identity.as_str().to_owned()),
        ]),
    )
    .map_err(|_| EvidenceError::Canonical)
}

fn validate_identifier(value: &str) -> Result<(), EvidenceError> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(EvidenceError::InvalidIdentifier);
    }
    Ok(())
}

fn require_unique<T: Ord + Clone>(values: &[T]) -> Result<(), EvidenceError> {
    if values
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != values.len()
    {
        return Err(EvidenceError::Invalid);
    }
    Ok(())
}

const fn event_family_name(value: CanonicalEventFamily) -> &'static str {
    match value {
        CanonicalEventFamily::Read => "read",
        CanonicalEventFamily::Search => "search",
        CanonicalEventFamily::Mutate => "mutate",
        CanonicalEventFamily::Verify => "verify",
        CanonicalEventFamily::Build => "build",
        CanonicalEventFamily::Launch => "launch",
        CanonicalEventFamily::Observe => "observe",
        CanonicalEventFamily::Integrate => "integrate",
        CanonicalEventFamily::OtherExecutable => "other_executable",
        CanonicalEventFamily::Message => "message",
        CanonicalEventFamily::Lifecycle => "lifecycle",
    }
}

const fn correlation_strength_name(value: CorrelationStrength) -> &'static str {
    match value {
        CorrelationStrength::Exact => "exact",
        CorrelationStrength::Ambiguous => "ambiguous",
        CorrelationStrength::Conflicted => "conflicted",
        CorrelationStrength::Unavailable => "unavailable",
    }
}

fn validate_digest(value: &str) -> Result<(), EvidenceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EvidenceError::InvalidDigest);
    }
    Ok(())
}

fn validate_redaction(
    archive_mode: SourceArchiveMode,
    raw_length: u64,
    protected_secret_digest: Option<&str>,
    spans: &[EvidenceRedactionSpan],
) -> Result<(), EvidenceError> {
    if raw_length == 0 {
        return Err(EvidenceError::Invalid);
    }
    match archive_mode {
        SourceArchiveMode::Exact if protected_secret_digest.is_some() || !spans.is_empty() => {
            return Err(EvidenceError::InvalidRedaction);
        }
        SourceArchiveMode::Redacted if protected_secret_digest.is_none() || spans.is_empty() => {
            return Err(EvidenceError::InvalidRedaction);
        }
        _ => {}
    }
    if let Some(digest) = protected_secret_digest {
        validate_digest(digest)?;
    }
    let mut previous_end = 0;
    for span in spans {
        span.validate(raw_length)?;
        if span.start < previous_end {
            return Err(EvidenceError::InvalidRedaction);
        }
        previous_end = span.end;
    }
    Ok(())
}

pub fn hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EvidenceError {
    #[error("evidence value is invalid")]
    Invalid,
    #[error("evidence identifier is invalid")]
    InvalidIdentifier,
    #[error("evidence byte range is invalid")]
    InvalidRange,
    #[error("evidence digest is invalid")]
    InvalidDigest,
    #[error("evidence source revision relationship is invalid")]
    InvalidRevision,
    #[error("evidence capture completeness is invalid")]
    InvalidCompleteness,
    #[error("evidence redaction metadata is invalid")]
    InvalidRedaction,
    #[error("host correlation evidence is invalid")]
    InvalidCorrelation,
    #[error("host occurrence is invalid")]
    InvalidOccurrence,
    #[error("operation is invalid")]
    InvalidOperation,
    #[error("scope effect is invalid")]
    InvalidScopeEffect,
    #[error("evidence canonical encoding failed")]
    Canonical,
}
