use std::{
    path::PathBuf,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, EvidenceByteRange, EvidenceRedactionSpan,
        EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength, ObservationRole,
        ScopeEffectClaim, SourceArchiveMode, SourceInstanceId, SourceRecordIdentity,
        SourceRevision, SourceRevisionMode, SourceRole, UnsupportedRecordClassification, hex,
        source_observation_id,
    },
    ids::{CommandId, RepositoryId, SourceObservationId, TaskId, WorktreeId},
};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    CasStore, DeviceKeyStore,
    frame::{CaptureRecordBody, SpoolRecord, encode_record_body},
    protect,
    runtime_snapshot::RuntimeSnapshot,
    spool::{CaptureGapMarker, DurableSpool, GapReason, SpoolError},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureAdmissionState {
    Normal,
    Pressure,
    Unavailable,
    Recovering,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CaptureRecordInput {
    pub spool_record_id: Option<String>,
    pub source_observation_id_hint: Option<String>,
    pub source_instance_id: String,
    pub source_revision: String,
    pub source_record_identity: Option<String>,
    pub identity_strength: Option<IdentityStrength>,
    pub source_kind: EvidenceSourceKind,
    pub identity_domain: String,
    pub source_ref: String,
    pub session_ref: String,
    pub turn_ref: Option<String>,
    pub tool_ref: Option<String>,
    pub source_sequence: u64,
    pub source_sequence_origin: Option<u64>,
    pub task_id: Option<String>,
    pub repository_instance_id: Option<String>,
    pub worktree_instance_id: Option<String>,
    pub source_byte_range: Option<EvidenceByteRange>,
    pub source_revision_mode: SourceRevisionMode,
    pub previous_source_revision: Option<String>,
    pub close_watermark: Option<u64>,
    pub observation_role: ObservationRole,
    pub correlation: HostCorrelationEvidence,
    pub scope_effect_claims: Vec<ScopeEffectClaim>,
    pub lifecycle: Option<evertrace_domain::work::LaneLifecycleEvidence>,
    pub unsupported_record_classification: Option<UnsupportedRecordClassification>,
    pub source_role: SourceRole,
    pub content_trust: ContentTrust,
    pub capture_completeness: CaptureCompleteness,
    pub surface_eligible: bool,
    pub adapter_revision: u32,
    pub adapter_manifest_ref: String,
    pub eligible_event_manifest_ref: String,
    pub parser_revision: u32,
    pub canonicalization_revision: u32,
    pub event_time_us: Option<i64>,
    pub raw_payload: Vec<u8>,
}

impl std::fmt::Debug for CaptureRecordInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureRecordInput")
            .field("has_spool_record_id", &self.spool_record_id.is_some())
            .field("source_instance_id", &self.source_instance_id)
            .field("source_revision", &self.source_revision)
            .field("identity_strength", &self.identity_strength)
            .field("source_sequence", &self.source_sequence)
            .field("observation_role", &self.observation_role)
            .field("source_role", &self.source_role)
            .field("raw_payload_length", &self.raw_payload.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureOutcome {
    Durable {
        command_id: CommandId,
        spool_record_id: String,
        cas_digest: String,
        end_watermark: u64,
    },
    GapRecorded {
        marker_path: PathBuf,
    },
    CompletenessLost,
}

#[derive(Debug)]
pub struct CaptureRuntime {
    snapshot: RuntimeSnapshot,
    cas: CasStore,
    spool: DurableSpool,
    state: CaptureAdmissionState,
}

impl CaptureRuntime {
    pub fn open(snapshot: RuntimeSnapshot) -> Result<Self, CaptureError> {
        snapshot.validate()?;
        let cas = CasStore::open(snapshot.cas_dir.clone())?;
        let (spool, recovery) =
            DurableSpool::open(snapshot.spool_dir.clone(), snapshot.spool_limits()?)?;
        let state = if recovery.gaps.is_empty()
            && recovery.repaired_tail_bytes == 0
            && spool.below_low_watermark()?
        {
            CaptureAdmissionState::Normal
        } else {
            CaptureAdmissionState::Recovering
        };
        Ok(Self {
            snapshot,
            cas,
            spool,
            state,
        })
    }

    pub const fn state(&self) -> CaptureAdmissionState {
        self.state
    }

    pub fn complete_recovery(&mut self) -> Result<(), CaptureError> {
        if !self.spool.below_low_watermark()? {
            return Err(CaptureError::RecoveryIncomplete);
        }
        self.state = CaptureAdmissionState::Normal;
        Ok(())
    }

    pub fn capture(&mut self, input: CaptureRecordInput) -> Result<CaptureOutcome, CaptureError> {
        validate_input(&input)?;
        let recorded_at_us = now_us()?;
        let command_id = CommandId::new_v7();
        let spool_record_id = input
            .spool_record_id
            .clone()
            .unwrap_or_else(|| Uuid::now_v7().hyphenated().to_string());
        let source_instance_id = SourceInstanceId::parse(&input.source_instance_id)
            .map_err(|_| CaptureError::InvalidInput)?;
        let source_revision = SourceRevision::parse(&input.source_revision)
            .map_err(|_| CaptureError::InvalidInput)?;
        let (source_record_identity, identity_strength) = match (
            input.source_record_identity.as_deref(),
            input.identity_strength,
        ) {
            (
                Some(identity),
                Some(
                    strength @ (IdentityStrength::StableNative
                    | IdentityStrength::StableSourceSequence),
                ),
            ) => (
                SourceRecordIdentity::parse(identity).map_err(|_| CaptureError::InvalidInput)?,
                strength,
            ),
            (None, None | Some(IdentityStrength::SynthesizedBestEffort)) => (
                SourceRecordIdentity::parse(&spool_record_id)
                    .map_err(|_| CaptureError::InvalidInput)?,
                IdentityStrength::SynthesizedBestEffort,
            ),
            _ => return Err(CaptureError::InvalidInput),
        };
        let observation_id = source_observation_id(
            &source_instance_id,
            &source_revision,
            &source_record_identity,
        )
        .map_err(|_| CaptureError::InvalidInput)?;
        let observation_hint = input
            .source_observation_id_hint
            .as_deref()
            .map(SourceObservationId::from_str)
            .transpose()
            .map_err(|_| CaptureError::InvalidInput)?;
        if observation_hint.is_some_and(|hint| hint != observation_id) {
            return Err(CaptureError::InvalidInput);
        }
        let key = DeviceKeyStore::new(self.snapshot.device_key_dir.clone()).load()?;
        let protected = protect(&input.raw_payload, &key)?;
        let content_digest =
            crate::CasDigest::for_protected_bytes(protected.protected_bytes()).as_hex();
        let cas_digest = match self.cas.put(&protected) {
            Ok(value) => value.as_hex(),
            Err(_) => {
                self.state = CaptureAdmissionState::Unavailable;
                return Ok(self.record_gap(
                    &input,
                    &spool_record_id,
                    &content_digest,
                    GapReason::MainUnavailable,
                ));
            }
        };
        let archive_mode = match protected.archive_mode() {
            crate::ArchiveMode::Exact => SourceArchiveMode::Exact,
            crate::ArchiveMode::Redacted => SourceArchiveMode::Redacted,
        };
        let protected_secret_digest = protected.protected_secret_digest().map(|value| hex(&value));
        let redaction_spans = protected
            .spans()
            .iter()
            .map(|span| EvidenceRedactionSpan {
                start: span.start(),
                end: span.end(),
                kind: span.kind().as_str().to_owned(),
            })
            .collect();
        let body = CaptureRecordBody {
            body_version: crate::frame::CAPTURE_RECORD_BODY_VERSION,
            command_id,
            source_instance_id,
            source_revision,
            source_record_identity,
            identity_strength,
            source_observation_id_hint: observation_hint,
            source_kind: input.source_kind,
            identity_domain: input.identity_domain.clone(),
            source_ref: input.source_ref.clone(),
            source_session_ref: input.session_ref.clone(),
            source_sequence: input.source_sequence,
            source_sequence_origin: input.source_sequence_origin,
            task_id: input
                .task_id
                .as_deref()
                .map(TaskId::from_str)
                .transpose()
                .map_err(|_| CaptureError::InvalidInput)?,
            repository_instance_id: input
                .repository_instance_id
                .as_deref()
                .map(RepositoryId::from_str)
                .transpose()
                .map_err(|_| CaptureError::InvalidInput)?,
            worktree_instance_id: input
                .worktree_instance_id
                .as_deref()
                .map(WorktreeId::from_str)
                .transpose()
                .map_err(|_| CaptureError::InvalidInput)?,
            source_byte_range: input.source_byte_range.clone(),
            source_revision_mode: input.source_revision_mode,
            previous_source_revision: input
                .previous_source_revision
                .as_deref()
                .map(SourceRevision::parse)
                .transpose()
                .map_err(|_| CaptureError::InvalidInput)?,
            close_watermark: input.close_watermark,
            observation_role: input.observation_role,
            correlation: input.correlation.clone(),
            scope_effect_claims: input.scope_effect_claims.clone(),
            lifecycle: input.lifecycle.clone(),
            unsupported_record_classification: input.unsupported_record_classification,
            source_role: input.source_role,
            content_trust: input.content_trust,
            capture_completeness: input.capture_completeness,
            surface_eligible: input.surface_eligible,
            cas_ref: cas_digest.clone(),
            archive_mode,
            protected_length: u64::try_from(protected.protected_bytes().len())
                .map_err(|_| CaptureError::Serialization)?,
            original_length: protected.raw_length(),
            protected_secret_digest,
            redaction_spans,
            adapter_revision: input.adapter_revision,
            adapter_manifest_ref: input.adapter_manifest_ref.clone(),
            eligible_event_manifest_ref: input.eligible_event_manifest_ref.clone(),
            parser_revision: input.parser_revision,
            canonicalization_revision: input.canonicalization_revision,
            detector_revision: protected.detector_revision(),
            redaction_revision: protected.redaction_revision(),
            protection_key_generation: protected.key_generation(),
            event_time_us: input.event_time_us.unwrap_or(recorded_at_us),
            recorded_at_us,
        };
        let body = encode_record_body(&body)?;
        let record = SpoolRecord {
            spool_generation: self.snapshot.generation,
            spool_record_id: spool_record_id.clone(),
            source_observation_id: observation_id.to_string(),
            cas_refs: vec![cas_digest.clone()],
            record_body: body,
        };
        match self.spool.append(&record) {
            Ok(written) => {
                if self.state != CaptureAdmissionState::Recovering {
                    self.state = CaptureAdmissionState::Normal;
                }
                Ok(CaptureOutcome::Durable {
                    command_id,
                    spool_record_id,
                    cas_digest,
                    end_watermark: written.end_watermark,
                })
            }
            Err(SpoolError::Pressure) => {
                self.state = CaptureAdmissionState::Pressure;
                Ok(self.record_gap(
                    &input,
                    &spool_record_id,
                    &content_digest,
                    GapReason::MainPressure,
                ))
            }
            Err(_) => {
                self.state = CaptureAdmissionState::Unavailable;
                Ok(self.record_gap(
                    &input,
                    &spool_record_id,
                    &content_digest,
                    GapReason::MainUnavailable,
                ))
            }
        }
    }

    pub fn spool(&self) -> &DurableSpool {
        &self.spool
    }

    pub fn seal_active(&mut self) -> Result<Option<PathBuf>, CaptureError> {
        self.spool
            .seal_active(self.snapshot.generation)
            .map_err(Into::into)
    }

    fn record_gap(
        &self,
        input: &CaptureRecordInput,
        spool_record_id: &str,
        redacted_fingerprint: &str,
        reason: GapReason,
    ) -> CaptureOutcome {
        let marker = CaptureGapMarker {
            marker_id: format!("gap:{spool_record_id}"),
            source_ref: input.source_ref.clone(),
            session_ref: input.session_ref.clone(),
            turn_ref: input.turn_ref.clone(),
            tool_ref: input.tool_ref.clone(),
            failure_reason: reason,
            redacted_fingerprint: redacted_fingerprint.into(),
            attempted_bytes: input.raw_payload.len() as u64,
            last_durable_watermark: self.spool.last_durable_watermark(),
        };
        self.spool
            .write_gap_marker(&marker)
            .map_or(CaptureOutcome::CompletenessLost, |marker_path| {
                CaptureOutcome::GapRecorded { marker_path }
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CaptureError {
    #[error("capture input is invalid")]
    InvalidInput,
    #[error("capture runtime snapshot is invalid")]
    Snapshot,
    #[error("capture device key is unavailable")]
    Key,
    #[error("capture protection failed")]
    Protection,
    #[error("capture CAS is unavailable")]
    Cas,
    #[error("capture spool is unavailable")]
    Spool,
    #[error("capture serialization failed")]
    Serialization,
    #[error("capture clock is unavailable")]
    Clock,
    #[error("capture recovery is incomplete")]
    RecoveryIncomplete,
}

impl From<crate::runtime_snapshot::RuntimeSnapshotError> for CaptureError {
    fn from(_: crate::runtime_snapshot::RuntimeSnapshotError) -> Self {
        Self::Snapshot
    }
}

impl From<crate::key::DeviceKeyError> for CaptureError {
    fn from(_: crate::key::DeviceKeyError) -> Self {
        Self::Key
    }
}

impl From<crate::protect::ProtectError> for CaptureError {
    fn from(_: crate::protect::ProtectError) -> Self {
        Self::Protection
    }
}

impl From<crate::cas::CasError> for CaptureError {
    fn from(_: crate::cas::CasError) -> Self {
        Self::Cas
    }
}

impl From<SpoolError> for CaptureError {
    fn from(_: SpoolError) -> Self {
        Self::Spool
    }
}

impl From<crate::frame::SpoolFrameError> for CaptureError {
    fn from(_: crate::frame::SpoolFrameError) -> Self {
        Self::Serialization
    }
}

fn validate_input(input: &CaptureRecordInput) -> Result<(), CaptureError> {
    if input
        .spool_record_id
        .as_deref()
        .is_some_and(|value| !valid_input_text(value))
        || !valid_input_text(&input.source_instance_id)
        || !valid_input_text(&input.source_revision)
        || !valid_input_text(&input.source_ref)
        || !valid_input_text(&input.identity_domain)
        || !valid_input_text(&input.session_ref)
        || input
            .turn_ref
            .as_deref()
            .is_some_and(|value| !valid_input_text(value))
        || input
            .tool_ref
            .as_deref()
            .is_some_and(|value| !valid_input_text(value))
        || input.raw_payload.is_empty()
        || input.raw_payload.len() > crate::frame::MAX_RECORD_BODY
        || input.adapter_revision == 0
        || !valid_input_text(&input.adapter_manifest_ref)
        || !valid_input_text(&input.eligible_event_manifest_ref)
        || input.parser_revision == 0
        || input.canonicalization_revision == 0
        || input.event_time_us.is_some_and(|value| value < 0)
        || input
            .source_sequence_origin
            .is_some_and(|origin| origin > input.source_sequence)
        || input
            .close_watermark
            .is_some_and(|close| close < input.source_sequence)
        || (input.unsupported_record_classification.is_some() && input.surface_eligible)
        || (input.source_record_identity.is_none()
            && input.capture_completeness == CaptureCompleteness::Complete)
        || (input.source_revision_mode == SourceRevisionMode::Replacement
            && input.previous_source_revision.is_none())
        || (input.source_revision_mode == SourceRevisionMode::Append
            && input.previous_source_revision.is_some())
    {
        return Err(CaptureError::InvalidInput);
    }
    input
        .correlation
        .validate()
        .map_err(|_| CaptureError::InvalidInput)?;
    for claim in &input.scope_effect_claims {
        claim.validate().map_err(|_| CaptureError::InvalidInput)?;
    }
    if let Some(lifecycle) = &input.lifecycle {
        lifecycle
            .validate()
            .map_err(|_| CaptureError::InvalidInput)?;
        if lifecycle.incarnation_ref.is_none()
            || lifecycle.host_session_id != input.session_ref
            || lifecycle.adapter_manifest_ref != input.adapter_manifest_ref
            || lifecycle.eligible_event_manifest_ref != input.eligible_event_manifest_ref
        {
            return Err(CaptureError::InvalidInput);
        }
    }
    Ok(())
}

fn valid_input_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte != 0 && !byte.is_ascii_control())
}

fn now_us() -> Result<i64, CaptureError> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CaptureError::Clock)?
        .as_micros();
    i64::try_from(value).map_err(|_| CaptureError::Clock)
}
