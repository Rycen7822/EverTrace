use std::fmt;

use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    evidence::{
        EvidenceSurface, HostOccurrence, Operation, ScopeEffect, SourceInstanceId,
        SourceObservation, SourceReceipt, SourceRevision, SourceRevisionMode,
    },
    ids::{CommandId, JobId, SourceObservationId},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const JOURNAL_PAYLOAD_SCHEMA: u16 = 1;
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
    RuntimeJob,
    RuntimeOutbox,
}

impl DirtyTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectsProjection => "objects_projection",
            Self::EvidenceSurface => "evidence_surface",
            Self::PhysicalNormalization => "physical_normalization",
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
