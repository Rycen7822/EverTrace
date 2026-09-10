use super::*;
use evertrace_domain::{
    evidence::{SourceObservation, SourceReceipt},
    ids::{SourceObservationId, SourceReceiptId},
    semantic::{SemanticJobTarget, SemanticSourceTarget},
};

pub(super) fn validate_refs(
    source: &SemanticSourceTarget,
    after_sequence: u64,
    through_sequence: u64,
    refs: &[String],
    receipts: &BTreeMap<SourceReceiptId, (SourceReceipt, u64)>,
    observations: &BTreeMap<SourceObservationId, (SourceObservation, u64)>,
) -> Result<(), StoreError> {
    let mut sequences = std::collections::BTreeSet::new();
    for reference in refs {
        let id = reference
            .parse::<SourceObservationId>()
            .map_err(|_| StoreError::StoreCorrupt)?;
        let observation = &observations.get(&id).ok_or(StoreError::StoreCorrupt)?.0;
        let receipt = &receipts
            .get(&observation.source_receipt_ref)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        if !source.contains_message(receipt, observation, after_sequence, through_sequence)
            || !sequences.insert(receipt.source_sequence)
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    // A frozen interval must account for every imported message in that interval;
    // metadata/tool records are not message inputs or independent LLM triggers.
    if receipts.values().any(|(receipt, _)| {
        receipt.source_instance_id == source.source_instance_id
            && receipt.source_revision == source.source_revision
            && receipt.observation_role == evertrace_domain::evidence::ObservationRole::Message
            && receipt.source_sequence > after_sequence
            && receipt.source_sequence <= through_sequence
            && refs
                .binary_search(&receipt.source_observation_id.to_string())
                .is_err()
    }) || sequences.last() != Some(&through_sequence)
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

impl SynthesisState {
    pub(super) fn validate_source_run(
        &self,
        view: &SynthesisAdmissionView<'_>,
        payloads: &[&JournalPayload],
        run: &SemanticDerivationRun,
        digests: &[&SemanticDigest],
    ) -> Result<(), StoreError> {
        run.validate().map_err(|_| StoreError::StoreCorrupt)?;
        let source = run.source_target.as_ref().ok_or(StoreError::StoreCorrupt)?;
        validate_refs(
            source,
            run.from_watermark,
            run.to_watermark,
            &run.selected_direct_refs,
            view.source_receipts,
            view.source_observations,
        )?;
        if payloads.iter().any(|payload| {
            matches!(
                payload,
                JournalPayload::WorkEpisodeRecorded(_)
                    | JournalPayload::RevisionProposalRecorded(_)
                    | JournalPayload::AtomRecorded(_)
                    | JournalPayload::ProcedureRevisionRecorded(_)
            )
        }) {
            return Err(StoreError::StoreCorrupt);
        }
        let mut selected = run
            .selected_direct_refs
            .iter()
            .map(|reference| {
                let id = reference
                    .parse::<SourceObservationId>()
                    .map_err(|_| StoreError::StoreCorrupt)?;
                let observation = &view
                    .source_observations
                    .get(&id)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0;
                Ok(&view
                    .source_receipts
                    .get(&observation.source_receipt_ref)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0)
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        selected.sort_by_key(|receipt| receipt.source_sequence);
        let first = selected.first().ok_or(StoreError::StoreCorrupt)?;
        let last = selected.last().ok_or(StoreError::StoreCorrupt)?;
        if first.source_sequence.checked_sub(1) != Some(run.from_watermark)
            || last.source_sequence != run.to_watermark
        {
            return Err(StoreError::StoreCorrupt);
        }
        let expected = SemanticJobTarget::Source {
            first_observation_id: first.source_observation_id,
            last_observation_id: last.source_observation_id,
        }
        .encode()
        .map_err(|_| StoreError::StoreCorrupt)?;
        let jobs = payloads
            .iter()
            .filter_map(|payload| match payload {
                JournalPayload::JobState(job) if job.kind == "semantic_synthesis_v1" => Some(job),
                _ => None,
            })
            .collect::<Vec<_>>();
        let [job] = jobs.as_slice() else {
            return Err(StoreError::StoreCorrupt);
        };
        if job.target_revision != expected
            || job.idempotency_key != format!("semantic_synthesis:{expected}")
            || job.target_watermark != run.to_watermark
            || job.target_generation != 1
            || job.config_hash != run.effective_config_hash
            || job.model_id.as_deref() != Some(run.model_id.as_str())
            || job.algorithm_revision != run.algorithm_revision
            || job.state
                != if run.status == DerivationRunStatus::Succeeded {
                    crate::JobStatus::Succeeded
                } else {
                    crate::JobStatus::Failed
                }
        {
            return Err(StoreError::StoreCorrupt);
        }
        if run.status != DerivationRunStatus::Succeeded {
            return Ok(());
        }
        if self.runs.values().any(|(prior, _)| {
            prior.status == DerivationRunStatus::Succeeded
                && prior.source_target.as_ref() == Some(source)
                && prior.from_watermark < run.to_watermark
                && run.from_watermark < prior.to_watermark
        }) {
            return Err(StoreError::StoreCorrupt);
        }
        let [digest] = digests else {
            return Err(StoreError::StoreCorrupt);
        };
        digest.validate().map_err(|_| StoreError::StoreCorrupt)?;
        if digest.source_target != run.source_target
            || digest.from_watermark != run.from_watermark
            || digest.to_watermark != run.to_watermark
            || digest.selected_direct_refs != run.selected_direct_refs
            || digest.job_fingerprint != run.job_fingerprint
            || digest.model_id != run.model_id
            || digest.prompt_hash != run.prompt_hash
            || digest.schema_version != run.schema_version
            || digest.algorithm_revision != run.algorithm_revision
            || digest.effective_config_hash != run.effective_config_hash
            || digest.created_at_us != run.created_at_us
            || digest.status != evertrace_domain::semantic::SemanticDigestStatus::LlmEnriched
            || job
                .terminal
                .as_ref()
                .and_then(|terminal| terminal.result_ref.as_deref())
                != Some(digest.semantic_digest_id.to_string().as_str())
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }
}
