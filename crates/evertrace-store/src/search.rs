use evertrace_domain::evidence::{
    EvidenceError, EvidenceSurface, InstructionAuthority, SourceArchiveMode, SourceObservation,
    SourceReceipt, UnsupportedRecordClassification, evidence_span_hash, hex,
};

pub fn build_evidence_surface(
    receipt: &SourceReceipt,
    observation: &SourceObservation,
    protected_payload: &[u8],
    surface_eligible: bool,
) -> Result<Option<EvidenceSurface>, EvidenceError> {
    receipt.validate()?;
    observation.validate()?;
    if receipt.source_observation_id != observation.source_observation_id
        || receipt.source_receipt_id != observation.source_receipt_ref
        || receipt.source_instance_id != observation.source_instance_id
        || receipt.source_revision != observation.source_revision
        || receipt.source_record_identity != observation.source_record_identity
        || receipt.observation_role != observation.observation_role
        || receipt.capture_completeness != observation.capture_completeness
    {
        return Err(EvidenceError::Invalid);
    }
    if !surface_eligible
        || receipt.unsupported_record_classification.is_some()
        || receipt.archive_mode == SourceArchiveMode::Redacted
    {
        return Ok(None);
    }
    let text = match std::str::from_utf8(protected_payload) {
        Ok(value) => canonicalize_text(value),
        Err(_) => return Ok(None),
    };
    if text.is_empty()
        || text.len() > evertrace_domain::evidence::MAX_EVIDENCE_SURFACE_BYTES
        || text.bytes().any(|byte| byte == 0)
    {
        return Ok(None);
    }
    let span_hash = evidence_span_hash(
        observation.source_observation_id,
        observation.canonicalization_revision,
        &text,
    )?;
    let surface = EvidenceSurface {
        source_observation_revision_ref: observation.source_observation_id,
        source_role: observation.source_role,
        content_trust: observation.content_trust,
        instruction_authority: InstructionAuthority::None,
        task_id: receipt.task_id,
        repository_instance_id: receipt.repository_instance_id,
        worktree_instance_id: receipt.worktree_instance_id,
        event_time_us: receipt.event_time_us,
        recorded_at_us: receipt.recorded_at_us,
        source_sequence: receipt.source_sequence,
        capture_completeness: observation.capture_completeness,
        canonicalization_version: observation.canonicalization_revision,
        span_hash: hex(&span_hash),
        projection_generation: 1,
        protected_text: text,
    };
    surface.validate()?;
    Ok(Some(surface))
}

pub fn unsupported_surface_reason(classification: UnsupportedRecordClassification) -> &'static str {
    match classification {
        UnsupportedRecordClassification::UnknownRecordType => "unsupported_record_type",
        UnsupportedRecordClassification::Reasoning => "reasoning_not_searchable",
        UnsupportedRecordClassification::Binary => "binary_not_searchable",
        UnsupportedRecordClassification::UnboundedToolOutput => "unbounded_tool_output",
    }
}

fn canonicalize_text(value: &str) -> String {
    value.replace("\r\n", "\n").replace('\r', "\n")
}
