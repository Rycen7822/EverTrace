use std::collections::BTreeSet;

use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, EvidenceByteRange, EvidenceRedactionSpan,
        EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength, ObservationRole,
        ScopeEffectClaim, SourceArchiveMode, SourceInstanceId, SourceRecordIdentity,
        SourceRevision, SourceRevisionMode, SourceRole, UnsupportedRecordClassification,
        source_observation_id,
    },
    ids::{CommandId, RepositoryId, SourceObservationId, TaskId, WorktreeId},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"ETSPL001";
const COMMIT_TRAILER: &[u8; 8] = b"ETCOMMIT";
pub const SPOOL_FRAME_VERSION: u16 = 1;
pub const CAPTURE_RECORD_BODY_VERSION: u16 = 3;
pub const MAX_RECORD_BODY: usize = 1_048_576;
const PREFIX_LENGTH: usize = 8 + 2 + 4 + 8 + 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpoolRecord {
    pub spool_generation: u64,
    pub spool_record_id: String,
    pub source_observation_id: String,
    pub cas_refs: Vec<String>,
    pub record_body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedFrame {
    pub record: SpoolRecord,
    pub frame_length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameScan {
    pub frames: Vec<DecodedFrame>,
    pub complete_length: u64,
    pub incomplete_tail: bool,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRecordBody {
    pub body_version: u16,
    pub command_id: CommandId,
    pub source_instance_id: SourceInstanceId,
    pub source_revision: SourceRevision,
    pub source_record_identity: SourceRecordIdentity,
    pub identity_strength: IdentityStrength,
    pub source_observation_id_hint: Option<SourceObservationId>,
    pub source_kind: EvidenceSourceKind,
    pub identity_domain: String,
    pub source_ref: String,
    pub source_session_ref: String,
    pub source_sequence: u64,
    pub task_id: Option<TaskId>,
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_id: Option<WorktreeId>,
    pub source_byte_range: Option<EvidenceByteRange>,
    pub source_revision_mode: SourceRevisionMode,
    pub previous_source_revision: Option<SourceRevision>,
    pub close_watermark: Option<u64>,
    pub observation_role: ObservationRole,
    pub correlation: HostCorrelationEvidence,
    pub scope_effect_claims: Vec<ScopeEffectClaim>,
    pub unsupported_record_classification: Option<UnsupportedRecordClassification>,
    pub source_role: SourceRole,
    pub content_trust: ContentTrust,
    pub capture_completeness: CaptureCompleteness,
    pub surface_eligible: bool,
    pub cas_ref: String,
    pub archive_mode: SourceArchiveMode,
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

impl std::fmt::Debug for CaptureRecordBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureRecordBody")
            .field("body_version", &self.body_version)
            .field("command_id", &self.command_id)
            .field("source_instance_id", &self.source_instance_id)
            .field("source_revision", &self.source_revision)
            .field("source_sequence", &self.source_sequence)
            .field("identity_strength", &self.identity_strength)
            .field("archive_mode", &self.archive_mode)
            .field("protected_length", &self.protected_length)
            .field("original_length", &self.original_length)
            .field("redaction_count", &self.redaction_spans.len())
            .field("surface_eligible", &self.surface_eligible)
            .finish()
    }
}

impl CaptureRecordBody {
    pub fn observation_id(&self) -> Result<SourceObservationId, SpoolFrameError> {
        source_observation_id(
            &self.source_instance_id,
            &self.source_revision,
            &self.source_record_identity,
        )
        .map_err(|_| SpoolFrameError::Invalid)
    }

    pub fn validate(&self) -> Result<(), SpoolFrameError> {
        let observation_id = self.observation_id()?;
        if self.body_version != CAPTURE_RECORD_BODY_VERSION
            || self
                .source_observation_id_hint
                .is_some_and(|hint| hint != observation_id)
            || !valid_text(&self.source_ref)
            || !valid_text(&self.identity_domain)
            || !valid_text(&self.source_session_ref)
            || !valid_text(&self.adapter_manifest_ref)
            || !valid_text(&self.eligible_event_manifest_ref)
            || !valid_digest(&self.cas_ref)
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
            || (self.identity_strength == IdentityStrength::SynthesizedBestEffort
                && self.capture_completeness == CaptureCompleteness::Complete)
            || (self.unsupported_record_classification.is_some() && self.surface_eligible)
            || self.correlation.pairing_role != self.observation_role
            || self.correlation.adapter_revision != self.adapter_revision
            || self.correlation.adapter_manifest_ref != self.adapter_manifest_ref
        {
            return Err(SpoolFrameError::Invalid);
        }
        if self.source_revision_mode == SourceRevisionMode::Replacement
            && self.previous_source_revision.is_none()
        {
            return Err(SpoolFrameError::Invalid);
        }
        if self.source_revision_mode == SourceRevisionMode::Append
            && self.previous_source_revision.is_some()
        {
            return Err(SpoolFrameError::Invalid);
        }
        if let Some(range) = &self.source_byte_range {
            range.validate().map_err(|_| SpoolFrameError::Invalid)?;
        }
        self.correlation
            .validate()
            .map_err(|_| SpoolFrameError::Invalid)?;
        for claim in &self.scope_effect_claims {
            claim.validate().map_err(|_| SpoolFrameError::Invalid)?;
        }
        match self.archive_mode {
            SourceArchiveMode::Exact
                if self.protected_secret_digest.is_some() || !self.redaction_spans.is_empty() =>
            {
                return Err(SpoolFrameError::Invalid);
            }
            SourceArchiveMode::Redacted
                if self.protected_secret_digest.is_none() || self.redaction_spans.is_empty() =>
            {
                return Err(SpoolFrameError::Invalid);
            }
            _ => {}
        }
        if self
            .protected_secret_digest
            .as_deref()
            .is_some_and(|value| !valid_digest(value))
        {
            return Err(SpoolFrameError::Invalid);
        }
        let mut previous_end = 0;
        for span in &self.redaction_spans {
            if span.start >= span.end
                || span.end > self.original_length
                || span.start < previous_end
                || !valid_text(&span.kind)
            {
                return Err(SpoolFrameError::Invalid);
            }
            previous_end = span.end;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SpoolFrameError {
    #[error("spool frame is invalid")]
    Invalid,
    #[error("spool frame is corrupt")]
    Corrupt,
    #[error("spool frame is too large")]
    Oversize,
    #[error("spool frame serialization failed")]
    Serialization,
    #[error("legacy capture record bodies are unsupported")]
    LegacyUnsupported,
}

pub fn encode_record_body(body: &CaptureRecordBody) -> Result<Vec<u8>, SpoolFrameError> {
    body.validate()?;
    let json = serde_json::to_vec(body).map_err(|_| SpoolFrameError::Serialization)?;
    let total = json.len().checked_add(2).ok_or(SpoolFrameError::Oversize)?;
    if total > MAX_RECORD_BODY {
        return Err(SpoolFrameError::Oversize);
    }
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(&CAPTURE_RECORD_BODY_VERSION.to_be_bytes());
    encoded.extend_from_slice(&json);
    Ok(encoded)
}

pub fn decode_record_body(bytes: &[u8]) -> Result<CaptureRecordBody, SpoolFrameError> {
    if bytes.len() < 2 || bytes.len() > MAX_RECORD_BODY {
        return Err(if bytes.len() > MAX_RECORD_BODY {
            SpoolFrameError::Oversize
        } else {
            SpoolFrameError::Invalid
        });
    }
    let version = u16::from_be_bytes([bytes[0], bytes[1]]);
    if version == 1 {
        return Err(SpoolFrameError::LegacyUnsupported);
    }
    if version != CAPTURE_RECORD_BODY_VERSION {
        return Err(SpoolFrameError::Invalid);
    }
    let body: CaptureRecordBody =
        serde_json::from_slice(&bytes[2..]).map_err(|_| SpoolFrameError::Invalid)?;
    body.validate()?;
    if serde_json::to_vec(&body).map_err(|_| SpoolFrameError::Serialization)? != bytes[2..] {
        return Err(SpoolFrameError::Invalid);
    }
    Ok(body)
}

pub fn encode_frame(record: &SpoolRecord) -> Result<Vec<u8>, SpoolFrameError> {
    validate_record(record)?;
    let payload_length =
        u64::try_from(record.record_body.len()).map_err(|_| SpoolFrameError::Oversize)?;
    let mut header = Vec::new();
    header.extend_from_slice(&SPOOL_FRAME_VERSION.to_be_bytes());
    header.extend_from_slice(&record.spool_generation.to_be_bytes());
    put_string(&mut header, &record.spool_record_id)?;
    put_string(&mut header, &record.source_observation_id)?;
    let ref_count = u16::try_from(record.cas_refs.len()).map_err(|_| SpoolFrameError::Oversize)?;
    header.extend_from_slice(&ref_count.to_be_bytes());
    for reference in &record.cas_refs {
        header.extend_from_slice(reference.as_bytes());
    }
    header.extend_from_slice(&payload_length.to_be_bytes());
    let header_length = u32::try_from(header.len()).map_err(|_| SpoolFrameError::Oversize)?;
    let checksum = checksum(&header, &record.record_body);
    let mut encoded = Vec::with_capacity(
        PREFIX_LENGTH + header.len() + record.record_body.len() + COMMIT_TRAILER.len(),
    );
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&SPOOL_FRAME_VERSION.to_be_bytes());
    encoded.extend_from_slice(&header_length.to_be_bytes());
    encoded.extend_from_slice(&payload_length.to_be_bytes());
    encoded.extend_from_slice(&checksum);
    encoded.extend_from_slice(&header);
    encoded.extend_from_slice(&record.record_body);
    encoded.extend_from_slice(COMMIT_TRAILER);
    Ok(encoded)
}

pub fn scan_frames(bytes: &[u8]) -> Result<FrameScan, SpoolFrameError> {
    let mut offset = 0_usize;
    let mut frames = Vec::new();
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.len() < PREFIX_LENGTH {
            if !MAGIC.starts_with(remaining) {
                return Err(SpoolFrameError::Corrupt);
            }
            return Ok(FrameScan {
                frames,
                complete_length: offset as u64,
                incomplete_tail: true,
            });
        }
        if &remaining[..8] != MAGIC {
            return Err(SpoolFrameError::Corrupt);
        }
        let version = u16::from_be_bytes([remaining[8], remaining[9]]);
        if version != SPOOL_FRAME_VERSION {
            return Err(SpoolFrameError::Corrupt);
        }
        let header_length = u32::from_be_bytes(
            remaining[10..14]
                .try_into()
                .map_err(|_| SpoolFrameError::Corrupt)?,
        ) as usize;
        let body_length_u64 = u64::from_be_bytes(
            remaining[14..22]
                .try_into()
                .map_err(|_| SpoolFrameError::Corrupt)?,
        );
        let body_length =
            usize::try_from(body_length_u64).map_err(|_| SpoolFrameError::Oversize)?;
        if body_length > MAX_RECORD_BODY {
            return Err(SpoolFrameError::Oversize);
        }
        let frame_length = PREFIX_LENGTH
            .checked_add(header_length)
            .and_then(|value| value.checked_add(body_length))
            .and_then(|value| value.checked_add(COMMIT_TRAILER.len()))
            .ok_or(SpoolFrameError::Oversize)?;
        if remaining.len() < frame_length {
            return Ok(FrameScan {
                frames,
                complete_length: offset as u64,
                incomplete_tail: true,
            });
        }
        let header_start = PREFIX_LENGTH;
        let body_start = header_start + header_length;
        let trailer_start = body_start + body_length;
        let header_bytes = &remaining[header_start..body_start];
        let body = &remaining[body_start..trailer_start];
        if &remaining[trailer_start..frame_length] != COMMIT_TRAILER
            || remaining[22..54] != checksum(header_bytes, body)
        {
            return Err(SpoolFrameError::Corrupt);
        }
        let (
            protocol_version,
            spool_generation,
            spool_record_id,
            source_observation_id,
            cas_refs,
            payload_length,
        ) = decode_header(header_bytes)?;
        let record = SpoolRecord {
            spool_generation,
            spool_record_id,
            source_observation_id,
            cas_refs,
            record_body: body.to_vec(),
        };
        if protocol_version != SPOOL_FRAME_VERSION
            || payload_length != body_length_u64
            || validate_record(&record).is_err()
        {
            return Err(SpoolFrameError::Corrupt);
        }
        frames.push(DecodedFrame {
            record,
            frame_length: frame_length as u64,
        });
        offset += frame_length;
    }
    Ok(FrameScan {
        frames,
        complete_length: offset as u64,
        incomplete_tail: false,
    })
}

fn put_string(output: &mut Vec<u8>, value: &str) -> Result<(), SpoolFrameError> {
    let length = u16::try_from(value.len()).map_err(|_| SpoolFrameError::Oversize)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

#[allow(clippy::type_complexity)]
fn decode_header(
    bytes: &[u8],
) -> Result<(u16, u64, String, String, Vec<String>, u64), SpoolFrameError> {
    let mut cursor = Cursor::new(bytes);
    let protocol_version = cursor.u16()?;
    let spool_generation = cursor.u64()?;
    let spool_record_id = cursor.string()?;
    let source_observation_id = cursor.string()?;
    let ref_count = cursor.u16()?;
    let mut cas_refs = Vec::with_capacity(ref_count as usize);
    for _ in 0..ref_count {
        let raw = cursor.take(64)?;
        cas_refs.push(
            std::str::from_utf8(raw)
                .map_err(|_| SpoolFrameError::Corrupt)?
                .into(),
        );
    }
    let payload_length = cursor.u64()?;
    if !cursor.remaining().is_empty() {
        return Err(SpoolFrameError::Corrupt);
    }
    Ok((
        protocol_version,
        spool_generation,
        spool_record_id,
        source_observation_id,
        cas_refs,
        payload_length,
    ))
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SpoolFrameError> {
        if self.remaining.len() < length {
            return Err(SpoolFrameError::Corrupt);
        }
        let (value, rest) = self.remaining.split_at(length);
        self.remaining = rest;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, SpoolFrameError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| SpoolFrameError::Corrupt)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, SpoolFrameError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| SpoolFrameError::Corrupt)?,
        ))
    }

    fn string(&mut self) -> Result<String, SpoolFrameError> {
        let length = self.u16()? as usize;
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| SpoolFrameError::Corrupt)
    }

    const fn remaining(&self) -> &[u8] {
        self.remaining
    }
}

fn validate_record(record: &SpoolRecord) -> Result<(), SpoolFrameError> {
    if record.spool_generation == 0
        || record.spool_record_id.is_empty()
        || record.spool_record_id.len() > 256
        || record.source_observation_id.is_empty()
        || record.source_observation_id.len() > 256
        || record.record_body.len() > MAX_RECORD_BODY
        || record.cas_refs.iter().collect::<BTreeSet<_>>().len() != record.cas_refs.len()
        || record.cas_refs.iter().any(|value| {
            value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(SpoolFrameError::Invalid);
    }
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte != 0 && !byte.is_ascii_control())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn checksum(header: &[u8], body: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"evertrace.spool.frame.v1");
    digest.update((header.len() as u64).to_be_bytes());
    digest.update(header);
    digest.update((body.len() as u64).to_be_bytes());
    digest.update(body);
    digest.finalize().into()
}
