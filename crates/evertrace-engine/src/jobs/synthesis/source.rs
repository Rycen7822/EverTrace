use super::*;
use evertrace_domain::{
    evidence::{EvidenceSourceKind, ObservationRole, SourceReceipt},
    semantic::{SemanticJobTarget, SemanticSourceTarget},
};
use std::collections::BTreeMap;

// Read selection metadata only. In particular serde skips protected_presentation
// before allocation; body loading remains bounded to the claimed archive refs.
#[derive(serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum ReceiptProjection {
    SourceReceiptRecorded(MessageMetadata),
}

#[derive(serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum ObservationProjection {
    SourceObservationRecorded(ObservationEndpoint),
}
#[derive(serde::Deserialize)]
struct ObservationEndpoint {
    source_receipt_ref: evertrace_domain::ids::SourceReceiptId,
}

#[derive(Clone, serde::Deserialize)]
struct MessageMetadata {
    source_observation_id: evertrace_domain::ids::SourceObservationId,
    source_instance_id: evertrace_domain::evidence::SourceInstanceId,
    source_revision: evertrace_domain::evidence::SourceRevision,
    source_kind: EvidenceSourceKind,
    observation_role: ObservationRole,
    unsupported_record_classification:
        Option<evertrace_domain::evidence::UnsupportedRecordClassification>,
    repository_instance_id: Option<evertrace_domain::ids::RepositoryId>,
    worktree_instance_id: Option<evertrace_domain::ids::WorktreeId>,
    source_sequence: u64,
    protected_length: u64,
}

impl MessageMetadata {
    fn target(&self) -> Option<SemanticSourceTarget> {
        if self.source_kind != EvidenceSourceKind::CodexSessionJsonl
            || self.observation_role != ObservationRole::Message
            || self.unsupported_record_classification.is_some()
        {
            return None;
        }
        Some(SemanticSourceTarget {
            source_instance_id: self.source_instance_id.clone(),
            source_revision: self.source_revision.clone(),
            repository_id: self.repository_instance_id?,
            worktree_id: self.worktree_instance_id?,
        })
    }
}

fn metadata(
    row: &evertrace_store::ObjectRow,
) -> Result<MessageMetadata, crate::semantic::SemanticServiceError> {
    let ReceiptProjection::SourceReceiptRecorded(receipt) = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(evertrace_store::StoreError::StoreCorrupt)?,
    )
    .map_err(|_| evertrace_store::StoreError::StoreCorrupt)?;
    Ok(receipt)
}

pub(crate) struct SourceInput {
    pub(crate) source: SemanticSourceTarget,
    pub(crate) after_sequence: u64,
    pub(crate) through_sequence: u64,
    pub(crate) refs: Vec<String>,
    receipts: Vec<SourceReceipt>,
}

fn message_groups(
    snapshot: &ProjectionSnapshot,
) -> Result<
    BTreeMap<
        (
            evertrace_domain::evidence::SourceInstanceId,
            evertrace_domain::evidence::SourceRevision,
        ),
        Vec<MessageMetadata>,
    >,
    crate::semantic::SemanticServiceError,
> {
    let mut groups = BTreeMap::<_, Vec<_>>::new();
    for row in snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("source_receipt"))
    {
        let receipt = metadata(row)?;
        if receipt.source_kind != EvidenceSourceKind::CodexSessionJsonl
            || receipt.observation_role != ObservationRole::Message
            || !evertrace_store::is_session_import_source(receipt.source_instance_id.as_str())
        {
            continue;
        }
        // Keep ineligible messages as interval boundaries, including changes
        // of scope within the same source revision.
        groups
            .entry((
                receipt.source_instance_id.clone(),
                receipt.source_revision.clone(),
            ))
            .or_default()
            .push(receipt);
    }
    for receipts in groups.values_mut() {
        receipts.sort_by_key(|receipt| receipt.source_sequence);
        if !receipts
            .windows(2)
            .all(|pair| pair[0].source_sequence < pair[1].source_sequence)
        {
            return Err(evertrace_store::StoreError::StoreCorrupt.into());
        }
    }
    Ok(groups)
}

pub(crate) fn validate_input(
    snapshot: &ProjectionSnapshot,
    source: &SemanticSourceTarget,
    after_sequence: u64,
    through_sequence: u64,
    refs: &[String],
) -> Result<(), crate::semantic::SemanticServiceError> {
    crate::session_import::source_summary_receipts(
        snapshot,
        source,
        after_sequence,
        through_sequence,
        refs,
    )
    .map(|_| ())
    .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)
}

pub(crate) fn input(
    snapshot: &ProjectionSnapshot,
    job: &DurableJob,
) -> Result<SourceInput, crate::semantic::SemanticServiceError> {
    let (first, last) = endpoints(snapshot, job)?;
    let source = first
        .target()
        .ok_or(crate::semantic::SemanticServiceError::InvalidInput)?;
    if last.target().as_ref() != Some(&source) {
        return Err(crate::semantic::SemanticServiceError::InvalidInput);
    }
    let after_sequence = first
        .source_sequence
        .checked_sub(1)
        .ok_or(crate::semantic::SemanticServiceError::InvalidInput)?;
    let through_sequence = last.source_sequence;
    if after_sequence >= through_sequence
        || job.target_watermark != through_sequence
        || job.target_generation != 1
        || job.idempotency_key != format!("semantic_synthesis:{}", job.target_revision)
    {
        return Err(crate::semantic::SemanticServiceError::InvalidInput);
    }
    let source_needle = format!(
        "\"source_instance_id\":{}",
        serde_json::to_string(source.source_instance_id.as_str())
            .map_err(|_| evertrace_store::StoreError::StoreCorrupt)?
    );
    let revision_needle = format!(
        "\"source_revision\":{}",
        serde_json::to_string(source.source_revision.as_str())
            .map_err(|_| evertrace_store::StoreError::StoreCorrupt)?
    );
    let mut refs = Vec::new();
    // Frozen jobs scan only this source/revision's metadata, retaining <=64
    // interval refs. No all-source grouping, sorting or body decoding.
    for row in snapshot.data_rows().filter(|row| {
        row.object_kind.as_deref() == Some("source_receipt")
            && row.payload_json.as_deref().is_some_and(|json| {
                json.contains(&source_needle) && json.contains(&revision_needle)
            })
    }) {
        let receipt = metadata(row)?;
        if receipt.source_instance_id == source.source_instance_id
            && receipt.source_revision == source.source_revision
            && receipt.observation_role == ObservationRole::Message
            && receipt.source_sequence > after_sequence
            && receipt.source_sequence <= through_sequence
        {
            if receipt.target().as_ref() != Some(&source) || refs.len() == 64 {
                return Err(crate::semantic::SemanticServiceError::InvalidInput);
            }
            refs.push(receipt.source_observation_id.to_string());
        }
    }
    refs.sort();
    let receipts = crate::session_import::source_summary_receipts(
        snapshot,
        &source,
        after_sequence,
        through_sequence,
        &refs,
    )
    .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
    Ok(SourceInput {
        source,
        after_sequence,
        through_sequence,
        refs,
        receipts,
    })
}

fn endpoints(
    snapshot: &ProjectionSnapshot,
    job: &DurableJob,
) -> Result<(MessageMetadata, MessageMetadata), crate::semantic::SemanticServiceError> {
    let SemanticJobTarget::Source {
        first_observation_id,
        last_observation_id,
    } = SemanticJobTarget::parse(&job.target_revision)
        .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?
    else {
        return Err(crate::semantic::SemanticServiceError::InvalidInput);
    };
    let endpoint = |id: evertrace_domain::ids::SourceObservationId| -> Result<MessageMetadata, crate::semantic::SemanticServiceError> {
        let observation_id = id.to_string();
        let row = snapshot
            .data_rows()
            .find(|row| {
                row.object_kind.as_deref() == Some("source_observation")
                    && row.object_id.as_deref() == Some(observation_id.as_str())
            })
            .ok_or(crate::semantic::SemanticServiceError::InvalidInput)?;
        let ObservationProjection::SourceObservationRecorded(observation) = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(evertrace_store::StoreError::StoreCorrupt)?,
        )
        .map_err(|_| evertrace_store::StoreError::StoreCorrupt)?;
        let receipt_id = observation.source_receipt_ref.to_string();
        let row = snapshot
            .data_rows()
            .find(|row| {
                row.object_kind.as_deref() == Some("source_receipt")
                    && row.object_id.as_deref() == Some(receipt_id.as_str())
            })
            .ok_or(crate::semantic::SemanticServiceError::InvalidInput)?;
        let receipt = metadata(row)?;
        if receipt.source_observation_id != id {
            return Err(evertrace_store::StoreError::StoreCorrupt.into());
        }
        Ok(receipt)
    };
    Ok((
        endpoint(first_observation_id)?,
        endpoint(last_observation_id)?,
    ))
}

pub(crate) fn job_scope(
    snapshot: &ProjectionSnapshot,
    job: &DurableJob,
) -> Result<SemanticSourceTarget, crate::semantic::SemanticServiceError> {
    let (first, last) = endpoints(snapshot, job)?;
    let source = first
        .target()
        .ok_or(crate::semantic::SemanticServiceError::InvalidInput)?;
    if last.target().as_ref() != Some(&source) {
        return Err(crate::semantic::SemanticServiceError::InvalidInput);
    }
    Ok(source)
}

pub(crate) async fn allowed(
    writer: &crate::WriterHandle,
    report: Option<&evertrace_codex::HostProbeReport>,
    snapshot: &ProjectionSnapshot,
    input: &SourceInput,
    config_hash: [u8; 32],
) -> Result<bool, crate::semantic::SemanticServiceError> {
    validate_input(
        snapshot,
        &input.source,
        input.after_sequence,
        input.through_sequence,
        &input.refs,
    )?;
    let rows = snapshot
        .data_rows()
        .filter(|row| {
            row.object_kind.as_deref() == Some("source_observation")
                && row
                    .object_id
                    .as_ref()
                    .is_some_and(|id| input.refs.binary_search(id).is_ok())
        })
        .collect::<Vec<_>>();
    crate::session_import::blocked_source_rows(writer, report, snapshot, &rows, config_hash)
        .await
        .map(|blocked| blocked.is_empty())
        .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)
}

// A suppressed/unsupported/differently scoped message is an interval boundary,
// not a reason to discard every subsequent message from this source revision.
fn next_segment<'a>(
    receipts: &'a [MessageMetadata],
    cursor: &mut usize,
    blocked: &impl Fn(&MessageMetadata) -> bool,
) -> Option<(SemanticSourceTarget, &'a [MessageMetadata])> {
    while *cursor < receipts.len() {
        let first = &receipts[*cursor];
        let Some(source) = first.target().filter(|_| !blocked(first)) else {
            *cursor += 1;
            continue;
        };
        let start = *cursor;
        let mut bytes = 0;
        while let Some(receipt) = receipts.get(*cursor) {
            let cost = receipt.protected_length.min(4096).saturating_add(256);
            if *cursor - start == 64
                || bytes + cost > 32 * 1024
                || blocked(receipt)
                || receipt.target().as_ref() != Some(&source)
            {
                break;
            }
            bytes += cost;
            *cursor += 1;
        }
        return Some((source, &receipts[start..*cursor]));
    }
    None
}

fn selected_input(
    snapshot: &ProjectionSnapshot,
    source: SemanticSourceTarget,
    selected: &[MessageMetadata],
) -> Result<SourceInput, crate::semantic::SemanticServiceError> {
    let after_sequence = selected
        .first()
        .and_then(|receipt| receipt.source_sequence.checked_sub(1))
        .ok_or(evertrace_store::StoreError::StoreCorrupt)?;
    let through_sequence = selected
        .last()
        .ok_or(evertrace_store::StoreError::StoreCorrupt)?
        .source_sequence;
    let mut refs = selected
        .iter()
        .map(|receipt| receipt.source_observation_id.to_string())
        .collect::<Vec<_>>();
    refs.sort();
    let receipts = crate::session_import::source_summary_receipts(
        snapshot,
        &source,
        after_sequence,
        through_sequence,
        &refs,
    )
    .map_err(|error| match error {
        crate::session_import::SessionImportServiceError::Unavailable => {
            crate::semantic::SemanticServiceError::InvalidInput
        }
        _ => evertrace_store::StoreError::StoreCorrupt.into(),
    })?;
    Ok(SourceInput {
        source,
        after_sequence,
        through_sequence,
        refs,
        receipts,
    })
}

const MAX_TRANSIENT_FAILURES: usize = 3;

pub(super) fn retry_not_before(run: &SemanticDerivationRun, attempt: u32) -> Option<i64> {
    match run.status {
        DerivationRunStatus::BudgetExhausted => {
            Some((run.created_at_us / DAY_US + 1).saturating_mul(DAY_US))
        }
        DerivationRunStatus::ProviderUnavailable | DerivationRunStatus::ProviderFailed => Some(
            run.created_at_us
                .saturating_add(i64::try_from(run.quota_usage.wall_time_us).unwrap_or(i64::MAX))
                .saturating_add(
                    // The original lease increments attempt as well as the
                    // Failed -> Queued successor: ordinary claims are 2,4,6.
                    5_000_000_i64.saturating_mul(1_i64 << (attempt / 2).saturating_sub(1).min(4)),
                ),
        ),
        _ => None,
    }
}

fn retry_job(job: &DurableJob, prior: &[SemanticDerivationRun], now_us: i64) -> Option<DurableJob> {
    if job.state != JobStatus::Failed {
        return None;
    }
    let reference = job.terminal.as_ref()?.result_ref.as_deref()?;
    let run = prior.iter().find(|run| {
        run.derivation_run_id.to_string() == reference && run.source_target.is_some()
    })?;
    if prior.iter().any(|completed| {
        completed.status == DerivationRunStatus::Succeeded
            && completed.source_target == run.source_target
            && completed.from_watermark < run.to_watermark
            && run.from_watermark < completed.to_watermark
    }) {
        return None;
    }
    let due = job
        .backoff_until_us
        .unwrap_or(retry_not_before(run, job.attempt)?);
    if now_us < due
        || prior
            .iter()
            .filter(|prior| {
                prior.job_fingerprint == run.job_fingerprint
                    && (matches!(
                        prior.status,
                        DerivationRunStatus::ProviderUnavailable
                            | DerivationRunStatus::ProviderFailed
                    ) || prior.status == DerivationRunStatus::BudgetExhausted
                        && prior.quota_usage.calls > 0)
            })
            .count()
            >= MAX_TRANSIENT_FAILURES
    {
        return None;
    }
    let mut retry = job.clone();
    retry.state = JobStatus::Queued;
    retry.attempt = retry.attempt.checked_add(1)?;
    retry.backoff_until_us = None;
    retry.lease_until_us = None;
    retry.terminal = None;
    Some(retry)
}

impl SynthesisPlanner {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn durable_source_jobs(
        &self,
        snapshot: &ProjectionSnapshot,
        writer: &crate::WriterHandle,
        report: Option<&evertrace_codex::HostProbeReport>,
        effective_config_hash: [u8; 32],
        limit: usize,
        max_wall_time: std::time::Duration,
        now_us: i64,
        ready: impl Fn(&SemanticSourceTarget) -> bool,
    ) -> Result<Vec<DurableJob>, crate::semantic::SemanticServiceError> {
        if !self.llm.enabled || limit == 0 {
            return Ok(Vec::new());
        }
        let groups = message_groups(snapshot)?;
        let prior = prior_runs(snapshot)?;
        let jobs = evertrace_store::RuntimeSchedulerView::from_snapshot(snapshot)?;
        let suppression =
            evertrace_store::ObjectDeletionCandidateAdmissionView::from_snapshot(snapshot)?;
        let mut output = Vec::new();
        for ((instance, revision), receipts) in groups {
            let mut unavailable = std::collections::BTreeSet::new();
            for receipt in &receipts {
                if receipt.target().is_none()
                    || suppression
                        .source_refs_suppressed(&[receipt.source_observation_id.to_string()])?
                {
                    unavailable.insert(receipt.source_observation_id);
                }
            }
            // Successful input alone is permanently covered. Runtime attempts
            // reserve their original intervals; failed ones may be requeued
            // below, never replaced by a fresh UUID on each scheduler tick.
            let mut reserved = prior
                .iter()
                .filter(|run| {
                    run.status == DerivationRunStatus::Succeeded
                        && run.source_target.as_ref().is_some_and(|source| {
                            source.source_instance_id == instance
                                && source.source_revision == revision
                        })
                })
                .map(|run| (run.from_watermark, run.to_watermark))
                .collect::<Vec<_>>();
            let positions = receipts
                .iter()
                .enumerate()
                .map(|(index, receipt)| (receipt.source_observation_id, index))
                .collect::<BTreeMap<_, _>>();
            for job in jobs.jobs.iter().filter(|job| {
                job.kind == "semantic_synthesis_v1"
                    && (matches!(job.state, JobStatus::Queued | JobStatus::Leased)
                        || job.state == JobStatus::Failed
                            && job.config_hash == effective_config_hash)
            }) {
                let Ok(SemanticJobTarget::Source {
                    first_observation_id,
                    last_observation_id,
                }) = SemanticJobTarget::parse(&job.target_revision)
                else {
                    continue;
                };
                let (Some(&first), Some(&last)) = (
                    positions.get(&first_observation_id),
                    positions.get(&last_observation_id),
                ) else {
                    continue;
                };
                if first > last {
                    return Err(evertrace_store::StoreError::StoreCorrupt.into());
                }
                let selected = &receipts[first..=last];
                let source = receipts[first].target();
                if job.state == JobStatus::Failed
                    && (source.is_none()
                        || selected.iter().any(|receipt| {
                            unavailable.contains(&receipt.source_observation_id)
                                || receipt.target() != source
                        }))
                {
                    // The old failed interval can no longer be retried intact.
                    // Release its still-eligible subsegments; the unavailable
                    // refs remain boundaries, not successful coverage.
                    continue;
                }
                reserved.push((
                    receipts[first].source_sequence.saturating_sub(1),
                    receipts[last].source_sequence,
                ));
                let Some(retry) = retry_job(job, &prior, now_us) else {
                    continue;
                };
                let Some(source) = source else {
                    continue;
                };
                if selected.len() > 64
                    || !ready(&source)
                    || !self.job_is_current(
                        &retry,
                        effective_config_hash,
                        &self.durable_budget(max_wall_time)?,
                    )
                {
                    continue;
                }
                let selected = selected_input(snapshot, source, selected)?;
                if allowed(writer, report, snapshot, &selected, effective_config_hash).await? {
                    output.push(retry);
                    if output.len() == limit {
                        return Ok(output);
                    }
                }
            }
            let blocked = |receipt: &MessageMetadata| {
                unavailable.contains(&receipt.source_observation_id)
                    || reserved.iter().any(|(from, to)| {
                        receipt.source_sequence > *from && receipt.source_sequence <= *to
                    })
            };
            let mut cursor = 0;
            while let Some((source, selected)) = next_segment(&receipts, &mut cursor, &blocked) {
                if !ready(&source) {
                    continue;
                }
                let selected = selected_input(snapshot, source, selected)?;
                if !allowed(writer, report, snapshot, &selected, effective_config_hash).await? {
                    break;
                }
                let target = SemanticJobTarget::Source {
                    first_observation_id: selected.receipts.first().unwrap().source_observation_id,
                    last_observation_id: selected.receipts.last().unwrap().source_observation_id,
                }
                .encode()
                .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
                output.push(DurableJob {
                    job_id: JobId::new_v7(),
                    idempotency_key: format!("semantic_synthesis:{target}"),
                    target_revision: target,
                    target_watermark: selected.through_sequence,
                    target_generation: 1,
                    kind: "semantic_synthesis_v1".into(),
                    algorithm_revision: "semantic_synthesis_v1".into(),
                    model_id: Some(self.llm.model.clone()),
                    priority: 10,
                    state: JobStatus::Queued,
                    attempt: 1,
                    backoff_until_us: None,
                    config_hash: effective_config_hash,
                    budget: self.durable_budget(max_wall_time)?,
                    terminal: None,
                    lease_until_us: None,
                });
                if output.len() == limit {
                    return Ok(output);
                }
                // One fresh contiguous interval per source per round. Later
                // deltas remain selectable after an unavailable/retrying one.
                break;
            }
        }
        Ok(output)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_source_job(
        &self,
        snapshot: &ProjectionSnapshot,
        job: &DurableJob,
        effective_config_hash: [u8; 32],
        occurred_at_us: i64,
        max_wall_time: std::time::Duration,
        runtime: &evertrace_capture::RuntimeSnapshot,
        writer: &crate::WriterHandle,
        report: Option<&evertrace_codex::HostProbeReport>,
    ) -> Result<JournalCommand, crate::semantic::SemanticServiceError> {
        if job.state != JobStatus::Leased
            || !self.job_is_current(
                job,
                effective_config_hash,
                &self.durable_budget(max_wall_time)?,
            )
        {
            return Err(crate::semantic::SemanticServiceError::InvalidInput);
        }
        let input = input(snapshot, job)?;
        let cas = evertrace_capture::CasStore::open(runtime.cas_dir.clone())
            .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
        let mut direct_delta = Vec::new();
        let mut truncated = Vec::new();
        for receipt in &input.receipts {
            let digest = evertrace_capture::CasDigest::from_str(&receipt.cas_ref)
                .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
            let (bytes, _) = cas
                .read_bounded(&digest, 128 * 1024, 64 * 1024)
                .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
            if bytes.len() as u64 != receipt.protected_length {
                return Err(crate::semantic::SemanticServiceError::InvalidInput);
            }
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| crate::semantic::SemanticServiceError::InvalidInput)?;
            let value = if text.trim().len() > 4096 {
                truncated.push(receipt.source_observation_id.to_string());
                bounded_protected_text(&format!(
                    "Truncated protected archive prefix: {}",
                    text.trim()
                ))
            } else {
                text.trim().to_owned()
            };
            direct_delta.push(ProtectedDeltaItem {
                kind: ProtectedDeltaKind::Progress,
                value,
                direct_refs: vec![receipt.source_observation_id.to_string()],
            });
        }
        truncated.sort();
        let omission = (!truncated.is_empty())
            .then_some(evertrace_domain::semantic::SemanticOmission {
            category: "source_input_budget".into(),
            reason:
                "Only bounded protected prefixes were supplied; message tails were not summarized."
                    .into(),
            direct_refs: truncated,
        });
        let resolution = self
            .execute_admitted(
                SynthesisRequest {
                    snapshot,
                    target: SynthesisTarget::Source {
                        source: input.source.clone(),
                        after_sequence: input.after_sequence,
                        through_sequence: input.through_sequence,
                    },
                    trigger: SemanticDigestTrigger::SourceMessages,
                    direct_delta,
                    selected_direct_refs: input.refs.clone(),
                    command_id: CommandId::new_v7(),
                    occurred_at_us,
                    algorithm_revision: job.algorithm_revision.clone(),
                    effective_config_hash: job.config_hash,
                },
                || async {
                    let current = writer
                        .project()
                        .await
                        .map_err(|_| ProviderError::Disabled)?;
                    if allowed(writer, report, &current, &input, job.config_hash)
                        .await
                        .map_err(|_| ProviderError::Disabled)?
                    {
                        Ok(())
                    } else {
                        Err(ProviderError::Disabled)
                    }
                },
                omission,
            )
            .await?;
        durable_resolution(job, resolution, occurred_at_us, EventScope::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use evertrace_domain::{evidence::*, ids::*};

    fn message(index: u8) -> MessageMetadata {
        MessageMetadata {
            source_observation_id: SourceObservationId::from_digest([index; 32]),
            source_instance_id: SourceInstanceId::parse("session-rollout:test:one").unwrap(),
            source_revision: SourceRevision::parse("revision-one").unwrap(),
            source_kind: EvidenceSourceKind::CodexSessionJsonl,
            observation_role: ObservationRole::Message,
            unsupported_record_classification: None,
            repository_instance_id: Some(
                "repo:019d0000-0000-7000-8000-000000000001".parse().unwrap(),
            ),
            worktree_instance_id: Some("wt:019d0000-0000-7000-8000-000000000002".parse().unwrap()),
            source_sequence: u64::from(index),
            protected_length: 64,
        }
    }

    #[test]
    fn suppressed_and_ineligible_messages_split_without_hiding_later_delta() {
        let mut receipts = (1..=7).map(message).collect::<Vec<_>>();
        receipts[2].worktree_instance_id = None;
        receipts[3].worktree_instance_id = Some(WorktreeId::new_v7());
        receipts[4].unsupported_record_classification =
            Some(UnsupportedRecordClassification::UnknownRecordType);
        let suppressed = receipts[0].source_observation_id;
        let mut cursor = 0;
        let blocked = |receipt: &MessageMetadata| receipt.source_observation_id == suppressed;
        let (_, first) = next_segment(&receipts, &mut cursor, &blocked).unwrap();
        assert_eq!(
            first
                .iter()
                .map(|item| item.source_sequence)
                .collect::<Vec<_>>(),
            [2]
        );
        let (_, second) = next_segment(&receipts, &mut cursor, &blocked).unwrap();
        assert_eq!(
            second
                .iter()
                .map(|item| item.source_sequence)
                .collect::<Vec<_>>(),
            [4]
        );
        let (_, third) = next_segment(&receipts, &mut cursor, &blocked).unwrap();
        assert_eq!(
            third
                .iter()
                .map(|item| item.source_sequence)
                .collect::<Vec<_>>(),
            [6, 7]
        );
        assert!(next_segment(&receipts, &mut cursor, &blocked).is_none());
    }

    #[test]
    fn failed_job_reuses_identity_after_backoff_and_daily_budget_rollover() {
        let message = message(1);
        let source = message.target().unwrap();
        let mut run = SemanticDerivationRun {
            derivation_run_id: SemanticDerivationRunId::new_v7(),
            episode_id: None,
            episode_revision_id: None,
            from_watermark: 0,
            to_watermark: 1,
            selected_direct_refs: vec![message.source_observation_id.to_string()],
            job_fingerprint: [1; 32],
            status: DerivationRunStatus::BudgetExhausted,
            quota_usage: DerivationQuotaUsage::default(),
            model_id: "test".into(),
            prompt_hash: [0; 32],
            schema_version: 1,
            algorithm_revision: "semantic_synthesis_v1".into(),
            effective_config_hash: [0; 32],
            created_at_us: DAY_US + 1,
            source_target: Some(source.clone()),
        };
        let target = SemanticJobTarget::Source {
            first_observation_id: message.source_observation_id,
            last_observation_id: message.source_observation_id,
        }
        .encode()
        .unwrap();
        let job = DurableJob {
            job_id: JobId::new_v7(),
            kind: "semantic_synthesis_v1".into(),
            idempotency_key: format!("semantic_synthesis:{target}"),
            target_revision: target,
            target_generation: 1,
            target_watermark: 1,
            algorithm_revision: run.algorithm_revision.clone(),
            model_id: Some("test".into()),
            priority: 10,
            state: JobStatus::Failed,
            attempt: 1,
            config_hash: [0; 32],
            lease_until_us: None,
            budget: JobBudget {
                max_items: 64,
                max_bytes: Some(32768),
                max_wall_time_ms: 1000,
                max_input_tokens: Some(1024),
                max_output_tokens: Some(1024),
                max_calls: Some(1),
            },
            backoff_until_us: retry_not_before(&run, 1),
            terminal: Some(Box::new(JobTerminalAudit {
                outcome: JobTerminalOutcome::Failed,
                reason: JobTerminalReason::BudgetExhausted,
                result_ref: Some(run.derivation_run_id.to_string()),
            })),
        };
        assert!(retry_job(&job, std::slice::from_ref(&run), DAY_US * 2 - 1).is_none());
        let retry = retry_job(&job, std::slice::from_ref(&run), DAY_US * 2).unwrap();
        assert_eq!(
            (retry.job_id, retry.attempt, retry.state),
            (job.job_id, 2, JobStatus::Queued)
        );
        assert_eq!(retry.config_hash, job.config_hash);
        run.status = DerivationRunStatus::ProviderFailed;
        let mut failed = job.clone();
        failed.terminal.as_mut().unwrap().reason = JobTerminalReason::SourceUnavailable;
        failed.backoff_until_us = retry_not_before(&run, 1);
        let due = failed.backoff_until_us.unwrap();
        assert!(retry_job(&failed, std::slice::from_ref(&run), due - 1).is_none());
        assert!(retry_job(&failed, std::slice::from_ref(&run), due).is_some());
        let mut completed = run.clone();
        completed.derivation_run_id = SemanticDerivationRunId::new_v7();
        completed.status = DerivationRunStatus::Succeeded;
        completed.job_fingerprint = [2; 32];
        assert!(retry_job(&failed, &[run.clone(), completed], due).is_none());
        let failures = (0..MAX_TRANSIENT_FAILURES - 1)
            .map(|_| {
                let mut copy = run.clone();
                copy.derivation_run_id = SemanticDerivationRunId::new_v7();
                copy
            })
            .chain([run.clone()])
            .collect::<Vec<_>>();
        assert!(retry_job(&failed, &failures, due).is_none());
        let mut budget_failures = failures.clone();
        for failure in &mut budget_failures {
            failure.status = DerivationRunStatus::BudgetExhausted;
            failure.quota_usage.calls = 1;
        }
        failed.terminal.as_mut().unwrap().reason = JobTerminalReason::BudgetExhausted;
        assert!(retry_job(&failed, &budget_failures, DAY_US * 3).is_none());
        for failure in &mut budget_failures {
            failure.quota_usage.calls = 0;
        }
        // Deferrals before any provider call do not consume the failure cap.
        assert!(retry_job(&failed, &budget_failures, DAY_US * 3).is_some());
        failed.state = JobStatus::Succeeded;
        assert!(retry_job(&failed, &[run], due).is_none());
    }

    #[test]
    fn frozen_scope_reads_only_endpoint_metadata_not_other_sources_or_bodies() {
        let message = message(1);
        let id = message.source_observation_id;
        let receipt = SourceReceiptId::from_digest([9; 32]);
        let row = |kind: &str, id: String, json: serde_json::Value| {
            let mut row = evertrace_store::ObjectRow::checkpoint(1, 1);
            row.row_kind = evertrace_store::ObjectRowKind::Data;
            row.object_kind = Some(kind.into());
            row.object_id = Some(id);
            row.payload_json = Some(json.to_string());
            row
        };
        let observation = row(
            "source_observation",
            id.to_string(),
            serde_json::json!({"kind":"source_observation_recorded","value":{"source_receipt_ref":receipt, "scope_effect_claims":"not decoded here"}}),
        );
        let receipt_row = row(
            "source_receipt",
            receipt.to_string(),
            serde_json::json!({"kind":"source_receipt_recorded","value": {
                "source_observation_id":id, "source_instance_id":message.source_instance_id, "source_revision":message.source_revision,
                "source_kind":"codex_session_jsonl", "observation_role":"message", "unsupported_record_classification":null,
                "repository_instance_id":message.repository_instance_id, "worktree_instance_id":message.worktree_instance_id,
                "source_sequence":1, "protected_length":64, "protected_presentation":"not decoded here"
            }}),
        );
        let unrelated = row(
            "source_receipt",
            SourceReceiptId::from_digest([10; 32]).to_string(),
            serde_json::json!("unrelated payload must not be decoded"),
        );
        let target = SemanticJobTarget::Source {
            first_observation_id: id,
            last_observation_id: id,
        }
        .encode()
        .unwrap();
        // Only fields used to locate the frozen endpoints matter to this narrow
        // metadata check; full input admission remains covered by S28.
        let job: DurableJob = serde_json::from_value(serde_json::json!({"job_id":JobId::new_v7(),"idempotency_key":"unused","target_revision":target,"target_watermark":1,"target_generation":1,"kind":"semantic_synthesis_v1","algorithm_revision":"semantic_synthesis_v1","model_id":"test","priority":10,"state":"queued","attempt":1,"backoff_until_us":null,"config_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"budget":{"max_items":1,"max_wall_time_ms":1000,"max_bytes":1,"max_input_tokens":1,"max_output_tokens":1,"max_calls":1},"terminal":null,"lease_until_us":null})).unwrap();
        assert_eq!(
            job_scope(
                &ProjectionSnapshot {
                    frontier: 1,
                    rows: vec![unrelated, observation, receipt_row]
                },
                &job
            )
            .unwrap(),
            message.target().unwrap()
        );
    }
}
