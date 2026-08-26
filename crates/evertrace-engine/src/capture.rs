use std::str::FromStr;

use evertrace_capture::{CasDigest, CasStore, SealedFrame, decode_record_body};
use evertrace_domain::evidence::{
    EvidenceByteRange, EvidenceSurface, SourceArchiveMode, SourceObservation, SourceReceipt, hex,
    payload_fingerprint, source_observation_id, source_receipt_id,
};
use evertrace_store::search::build_evidence_surface;

use crate::ingest::IngestError;

pub(crate) struct VerifiedCapture {
    pub body: evertrace_capture::CaptureRecordBody,
    pub receipt: SourceReceipt,
    pub observation: SourceObservation,
    pub surface: Option<EvidenceSurface>,
}

pub(crate) fn verify_capture_frame(
    frame: &SealedFrame,
    cas: &CasStore,
) -> Result<VerifiedCapture, IngestError> {
    let body = decode_record_body(&frame.record.record_body).map_err(|error| match error {
        evertrace_capture::SpoolFrameError::LegacyUnsupported => IngestError::LegacyRecord,
        _ => IngestError::InvalidRecord,
    })?;
    let observation_id = source_observation_id(
        &body.source_instance_id,
        &body.source_revision,
        &body.source_record_identity,
    )
    .map_err(|_| IngestError::InvalidRecord)?;
    if frame.record.source_observation_id != observation_id.to_string()
        || frame.record.cas_refs.as_slice() != [body.cas_ref.as_str()]
    {
        return Err(IngestError::IdentityMismatch);
    }
    let cas_digest = CasDigest::from_str(&body.cas_ref).map_err(|_| IngestError::Cas)?;
    let protected = cas.read(&cas_digest).map_err(|_| IngestError::Cas)?;
    if u64::try_from(protected.len()).map_err(|_| IngestError::InvalidRecord)?
        != body.protected_length
        || CasDigest::for_protected_bytes(&protected) != cas_digest
        || body.detector_revision != evertrace_capture::protect::DETECTOR_REVISION
        || body.redaction_revision != evertrace_capture::protect::REDACTION_REVISION
        || (body.archive_mode == SourceArchiveMode::Redacted
            && protected
                .windows(b"[REDACTED]".len())
                .filter(|window| *window == b"[REDACTED]")
                .count()
                < body.redaction_spans.len())
    {
        return Err(IngestError::CasMismatch);
    }
    let secret_digest = body
        .protected_secret_digest
        .as_deref()
        .map(parse_digest)
        .transpose()?;
    let receipt_id = source_receipt_id(
        &body.source_instance_id,
        &body.source_revision,
        &body.source_record_identity,
    )
    .map_err(|_| IngestError::InvalidRecord)?;
    let receipt = SourceReceipt {
        source_receipt_id: receipt_id,
        source_observation_id: observation_id,
        source_instance_id: body.source_instance_id.clone(),
        source_kind: body.source_kind,
        identity_domain: body.identity_domain.clone(),
        source_ref: body.source_ref.clone(),
        source_session_ref: body.source_session_ref.clone(),
        source_revision: body.source_revision.clone(),
        source_record_identity: body.source_record_identity.clone(),
        identity_strength: body.identity_strength,
        source_sequence: body.source_sequence,
        task_id: body.task_id,
        repository_instance_id: body.repository_instance_id,
        worktree_instance_id: body.worktree_instance_id,
        source_byte_range: body.source_byte_range.clone(),
        spool_byte_range: EvidenceByteRange {
            start: frame.byte_start,
            end: frame.byte_end,
        },
        source_revision_mode: body.source_revision_mode,
        previous_source_revision: body.previous_source_revision.clone(),
        close_watermark: body.close_watermark,
        observation_role: body.observation_role,
        unsupported_record_classification: body.unsupported_record_classification,
        capture_completeness: body.capture_completeness,
        archive_mode: body.archive_mode,
        cas_ref: body.cas_ref.clone(),
        protected_length: body.protected_length,
        original_length: body.original_length,
        protected_secret_digest: body.protected_secret_digest.clone(),
        redaction_spans: body.redaction_spans.clone(),
        adapter_revision: body.adapter_revision,
        adapter_manifest_ref: body.adapter_manifest_ref.clone(),
        eligible_event_manifest_ref: body.eligible_event_manifest_ref.clone(),
        parser_revision: body.parser_revision,
        canonicalization_revision: body.canonicalization_revision,
        detector_revision: body.detector_revision,
        redaction_revision: body.redaction_revision,
        protection_key_generation: body.protection_key_generation,
        event_time_us: body.event_time_us,
        recorded_at_us: body.recorded_at_us,
    };
    receipt.validate().map_err(|_| IngestError::InvalidRecord)?;
    let fingerprint =
        payload_fingerprint(body.canonicalization_revision, &protected, secret_digest)
            .map_err(|_| IngestError::InvalidRecord)?;
    let observation = SourceObservation {
        source_observation_id: observation_id,
        source_instance_id: body.source_instance_id.clone(),
        source_revision: body.source_revision.clone(),
        source_record_identity: body.source_record_identity.clone(),
        observation_role: body.observation_role,
        identity_strength: body.identity_strength,
        payload_fingerprint: hex(&fingerprint),
        source_receipt_ref: receipt_id,
        source_role: body.source_role,
        content_trust: body.content_trust,
        capture_completeness: body.capture_completeness,
        adapter_revision: body.adapter_revision,
        parser_revision: body.parser_revision,
        canonicalization_revision: body.canonicalization_revision,
        detector_revision: body.detector_revision,
        redaction_revision: body.redaction_revision,
        correlation: body.correlation.clone(),
        scope_effect_claims: body.scope_effect_claims.clone(),
    };
    observation
        .validate()
        .map_err(|_| IngestError::InvalidRecord)?;
    let surface = build_evidence_surface(&receipt, &observation, &protected, body.surface_eligible)
        .map_err(|_| IngestError::InvalidRecord)?;
    Ok(VerifiedCapture {
        body,
        receipt,
        observation,
        surface,
    })
}

fn parse_digest(value: &str) -> Result<[u8; 32], IngestError> {
    if value.len() != 64 {
        return Err(IngestError::InvalidRecord);
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| IngestError::InvalidRecord)?;
        digest[index] = u8::from_str_radix(pair, 16).map_err(|_| IngestError::InvalidRecord)?;
    }
    Ok(digest)
}
