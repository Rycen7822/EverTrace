//! First method proposals from bounded, independently admitted source Evidence.
use super::*;
use evertrace_domain::{
    evidence::{EvidenceSourceKind, ObservationRole, SourceInstanceId, SourceRevision},
    ids::{RepositoryId, SourceObservationId, WorktreeId},
    semantic::SemanticSourceTarget,
};

const PREFIX: &str = "procedure_source_v1|";

#[derive(Clone, serde::Deserialize)]
struct Metadata {
    source_observation_id: SourceObservationId,
    source_instance_id: SourceInstanceId,
    source_revision: SourceRevision,
    repository_instance_id: Option<RepositoryId>,
    worktree_instance_id: Option<WorktreeId>,
    source_kind: EvidenceSourceKind,
    observation_role: ObservationRole,
    unsupported_record_classification:
        Option<evertrace_domain::evidence::UnsupportedRecordClassification>,
    source_sequence: u64,
}

impl Metadata {
    fn scope(&self) -> Option<SemanticSourceTarget> {
        (self.source_kind == EvidenceSourceKind::CodexSessionJsonl
            && self.observation_role == ObservationRole::Message
            && self.unsupported_record_classification.is_none()
            && evertrace_store::is_session_import_source(self.source_instance_id.as_str()))
        .then(|| {
            Some(SemanticSourceTarget {
                source_instance_id: self.source_instance_id.clone(),
                source_revision: self.source_revision.clone(),
                repository_id: self.repository_instance_id?,
                worktree_id: self.worktree_instance_id?,
            })
        })
        .flatten()
    }
}

fn messages(snapshot: &ProjectionSnapshot) -> Result<Vec<Metadata>, SemanticServiceError> {
    selected_messages(snapshot, |_| true)
}

pub(super) fn review_sources(
    snapshot: &ProjectionSnapshot,
) -> Result<Vec<(String, String, String)>, SemanticServiceError> {
    Ok(messages(snapshot)?
        .into_iter()
        .filter(|value| value.scope().is_some())
        .map(|value| {
            (
                value.source_instance_id.as_str().to_owned(),
                value.source_revision.as_str().to_owned(),
                value.source_observation_id.to_string(),
            )
        })
        .collect())
}

fn selected_messages(
    snapshot: &ProjectionSnapshot,
    selected: impl Fn(&str) -> bool,
) -> Result<Vec<Metadata>, SemanticServiceError> {
    #[derive(serde::Deserialize)]
    #[serde(tag = "kind", content = "value", rename_all = "snake_case")]
    enum Receipt {
        SourceReceiptRecorded(Metadata),
    }
    snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("source_receipt"))
        .filter(|row| row.payload_json.as_deref().is_some_and(&selected))
        .map(|row| {
            let Receipt::SourceReceiptRecorded(value) = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            Ok(value)
        })
        .collect()
}

pub(crate) fn is_source(job: &DurableJob) -> bool {
    job.target_revision.starts_with(PREFIX)
}

struct SourceInput {
    source: SemanticSourceTarget,
    refs: Vec<String>,
    after: u64,
    through: u64,
}

fn input(
    snapshot: &ProjectionSnapshot,
    job: &DurableJob,
) -> Result<SourceInput, SemanticServiceError> {
    let (first, last) = job
        .target_revision
        .strip_prefix(PREFIX)
        .and_then(|value| value.split_once('|'))
        .ok_or(SemanticServiceError::InvalidInput)?;
    let first_needle = format!("\"source_observation_id\":\"{first}\"");
    let last_needle = format!("\"source_observation_id\":\"{last}\"");
    let endpoints = selected_messages(snapshot, |json| {
        json.contains(&first_needle) || json.contains(&last_needle)
    })?;
    let first = endpoints
        .iter()
        .find(|value| value.source_observation_id.to_string() == first)
        .ok_or(SemanticServiceError::BaseConflict)?;
    let last = endpoints
        .iter()
        .find(|value| value.source_observation_id.to_string() == last)
        .ok_or(SemanticServiceError::BaseConflict)?;
    let source = first.scope().ok_or(SemanticServiceError::InvalidInput)?;
    if last.scope().as_ref() != Some(&source)
        || first.source_sequence > last.source_sequence
        || job.kind != KIND
        || job.algorithm_revision != KIND
        || job.target_generation != 1
        || job.target_watermark != last.source_sequence
        || job.idempotency_key != format!("{KIND}:{}", job.target_revision)
    {
        return Err(SemanticServiceError::BaseConflict);
    }
    let source_needle = format!(
        "\"source_instance_id\":{}",
        serde_json::to_string(source.source_instance_id.as_str())
            .map_err(|_| StoreError::StoreCorrupt)?
    );
    let revision_needle = format!(
        "\"source_revision\":{}",
        serde_json::to_string(source.source_revision.as_str())
            .map_err(|_| StoreError::StoreCorrupt)?
    );
    let messages = selected_messages(snapshot, |json| {
        json.contains(&source_needle) && json.contains(&revision_needle)
    })?;
    let mut refs = messages
        .iter()
        .filter(|value| {
            value.scope().as_ref() == Some(&source)
                && value.source_sequence >= first.source_sequence
                && value.source_sequence <= last.source_sequence
        })
        .map(|value| value.source_observation_id.to_string())
        .collect::<Vec<_>>();
    refs.sort();
    if refs.is_empty() || refs.len() > 4 {
        return Err(SemanticServiceError::InvalidInput);
    }
    let after = first
        .source_sequence
        .checked_sub(1)
        .ok_or(SemanticServiceError::InvalidInput)?;
    crate::session_import::source_summary_receipts(
        snapshot,
        &source,
        after,
        last.source_sequence,
        &refs,
    )
    .map_err(|_| SemanticServiceError::BaseConflict)?;
    Ok(SourceInput {
        source,
        refs,
        after,
        through: last.source_sequence,
    })
}

pub(super) fn current(snapshot: &ProjectionSnapshot, job: &DurableJob) -> bool {
    input(snapshot, job).is_ok()
}

pub(super) fn scope(snapshot: &ProjectionSnapshot, job: &DurableJob) -> Option<ProcedureScope> {
    let input = input(snapshot, job).ok()?;
    Some(ProcedureScope::Worktree {
        repository_id: input.source.repository_id,
        worktree_id: input.source.worktree_id,
    })
}

pub(crate) async fn jobs(
    snapshot: &ProjectionSnapshot,
    planner: &super::super::SynthesisPlanner,
    config: [u8; 32],
    wall: std::time::Duration,
    limit: usize,
    access: (
        &crate::WriterHandle,
        Option<&evertrace_codex::HostProbeReport>,
    ),
    ready: impl Fn(&SemanticSourceTarget) -> bool,
) -> Result<Vec<DurableJob>, SemanticServiceError> {
    if !planner.llm.enabled || limit == 0 {
        return Ok(Vec::new());
    }
    let runtime = RuntimeSchedulerView::from_snapshot(snapshot)?;
    let suppression = ObjectDeletionCandidateAdmissionView::from_snapshot(snapshot)?;
    let view = SemanticCurrentView::from_snapshot(snapshot)?;
    let reviewing = view
        .proposals
        .values()
        .filter(|proposal| {
            matches!(proposal.payload, ProposalPayload::Procedure(_))
                && matches!(
                    proposal.status,
                    ProposalStatus::Pending | ProposalStatus::Validating | ProposalStatus::Accepted
                )
        })
        .flat_map(|proposal| proposal.source_cohort_refs.iter())
        .collect::<BTreeSet<_>>();
    let mut groups = BTreeMap::<_, Vec<Metadata>>::new();
    for value in messages(snapshot)? {
        if value.scope().is_some() {
            groups
                .entry((
                    value.source_instance_id.clone(),
                    value.source_revision.clone(),
                ))
                .or_default()
                .push(value);
        }
    }
    let mut output = Vec::new();
    for values in groups.values_mut() {
        values.sort_by_key(|value| value.source_sequence);
        let positions = values
            .iter()
            .enumerate()
            .map(|(index, value)| (value.source_observation_id.to_string(), index))
            .collect::<BTreeMap<_, _>>();
        // A proposal covers its actual processed observations, not all future
        // messages that happen to share the same session/source revision.
        let mut covered = positions
            .iter()
            .filter_map(|(reference, position)| reviewing.contains(reference).then_some(*position))
            .collect::<BTreeSet<_>>();
        for job in runtime.jobs.iter().filter(|job| {
            job.kind == KIND
                && is_source(job)
                && (matches!(
                    job.state,
                    JobStatus::Succeeded | JobStatus::Queued | JobStatus::Leased
                ) || job.config_hash == config)
        }) {
            if let Some((first, last)) = job
                .target_revision
                .strip_prefix(PREFIX)
                .and_then(|value| value.split_once('|'))
                && let (Some(first), Some(last)) = (positions.get(first), positions.get(last))
            {
                covered.extend(*first..=*last);
            }
        }
        let mut cursor = 0;
        while cursor < values.len() && output.len() < limit {
            let start = cursor;
            cursor += 1;
            let first = &values[start];
            if covered.contains(&start)
                || !first.scope().is_some_and(|scope| ready(&scope))
                || suppression.source_refs_suppressed(&[first.source_observation_id.to_string()])?
            {
                continue;
            }
            while cursor < values.len()
                && cursor - start < 4
                && !covered.contains(&cursor)
                && values[cursor].scope() == first.scope()
                && !suppression
                    .source_refs_suppressed(&[values[cursor].source_observation_id.to_string()])?
            {
                cursor += 1;
            }
            let last = &values[cursor - 1];
            let target = format!(
                "{PREFIX}{}|{}",
                first.source_observation_id, last.source_observation_id
            );
            let job = DurableJob {
                job_id: JobId::new_v7(),
                idempotency_key: format!("{KIND}:{target}"),
                target_revision: target,
                target_watermark: last.source_sequence,
                target_generation: 1,
                kind: KIND.into(),
                algorithm_revision: KIND.into(),
                model_id: Some(planner.llm.model.clone()),
                priority: 5,
                state: JobStatus::Queued,
                attempt: 1,
                backoff_until_us: None,
                config_hash: config,
                budget: budget(planner, wall)?,
                terminal: None,
                lease_until_us: None,
            };
            if current(snapshot, &job) && allowed(access.0, snapshot, &job, access.1).await? {
                output.push(job);
            }
        }
        if output.len() >= limit {
            break;
        }
    }
    Ok(output)
}

pub(super) async fn allowed(
    writer: &crate::WriterHandle,
    snapshot: &ProjectionSnapshot,
    job: &DurableJob,
    report: Option<&evertrace_codex::HostProbeReport>,
) -> Result<bool, SemanticServiceError> {
    let input = match input(snapshot, job) {
        Ok(value) => value,
        Err(SemanticServiceError::BaseConflict | SemanticServiceError::InvalidInput) => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
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
    Ok(crate::repository::blocked_repositories(
        writer,
        [input.source.repository_id].into_iter().collect(),
        report,
        job.config_hash,
    )
    .await
    .map_err(|_| StoreError::StoreCorrupt)?
    .is_empty()
        && crate::session_import::blocked_source_rows(
            writer,
            report,
            snapshot,
            &rows,
            job.config_hash,
        )
        .await
        .map_err(|_| StoreError::StoreCorrupt)?
        .is_empty())
}

pub(super) async fn execute(
    writer: &crate::WriterHandle,
    planner: &super::super::SynthesisPlanner,
    snapshot: &ProjectionSnapshot,
    job: &DurableJob,
    report: Option<&evertrace_codex::HostProbeReport>,
    at: i64,
    runtime: &evertrace_capture::RuntimeSnapshot,
) -> Result<JournalCommand, SemanticServiceError> {
    let input = input(snapshot, job)?;
    if !allowed(writer, snapshot, job, report).await? {
        return Err(SemanticServiceError::BaseConflict);
    }
    let receipts = crate::session_import::source_summary_receipts(
        snapshot,
        &input.source,
        input.after,
        input.through,
        &input.refs,
    )
    .map_err(|_| SemanticServiceError::BaseConflict)?;
    let cas = evertrace_capture::CasStore::open(runtime.cas_dir.clone())
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    let mut evidence = Vec::new();
    for receipt in receipts {
        let digest = receipt
            .cas_ref
            .parse()
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        let (bytes, _) = cas
            .read_bounded(&digest, 128 * 1024, 64 * 1024)
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        if bytes.len() as u64 != receipt.protected_length {
            return Err(SemanticServiceError::InvalidInput);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| SemanticServiceError::InvalidInput)?;
        let mut end = text.len().min(1024);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        evidence.push(crate::provider::ProtectedDeltaItem {
            kind: crate::provider::ProtectedDeltaKind::Progress,
            value: text[..end].into(),
            direct_refs: vec![receipt.source_observation_id.to_string()],
        });
    }
    let json = serde_json::to_string(
        &serde_json::json!({"evidence": evidence, "effectiveness": "unverified"}),
    )
    .map_err(|_| SemanticServiceError::InvalidInput)?;
    let mut payloads = Vec::new();
    let mut reason = JobTerminalReason::Completed;
    if (json.len() + crate::provider::source_method_prompt().len()) as u64
        > job.budget.max_input_tokens.unwrap_or(0)
    {
        reason = JobTerminalReason::BudgetExhausted;
    } else if let Some(provider) = &planner.provider {
        let response = provider
            .propose_source_method(json, job.budget.max_output_tokens.unwrap_or(0), &|| async {
                let current = writer
                    .project()
                    .await
                    .map_err(|_| crate::provider::ProviderError::Transport)?;
                if allowed(writer, &current, job, report)
                    .await
                    .unwrap_or(false)
                {
                    Ok(())
                } else {
                    Err(crate::provider::ProviderError::Disabled)
                }
            })
            .await;
        match response {
            Ok((Some((content, mut refs)), used_input, used_output))
                if used_input <= job.budget.max_input_tokens.unwrap_or(0)
                    && used_output <= job.budget.max_output_tokens.unwrap_or(0) =>
            {
                refs.sort();
                refs.dedup();
                if refs.is_empty()
                    || refs
                        .iter()
                        .any(|reference| input.refs.binary_search(reference).is_err())
                    || content.stage_alignment.is_some()
                    || content.actions.stages.len() < 2
                    || content.when.goals.is_empty()
                    || content.when.requires.is_empty()
                    || content.done.verify.is_empty()
                {
                    reason = JobTerminalReason::Unsupported;
                } else {
                    let draft = ProcedureDraft {
                        scope: ProcedureScope::Worktree {
                            repository_id: input.source.repository_id,
                            worktree_id: input.source.worktree_id,
                        },
                        title: content.title,
                        summary: content.summary,
                        kind: content.procedure_kind,
                        when: content.when,
                        condition_ir_version: 1,
                        applicability_expr: content.applicability_expr,
                        avoid_expr: content.avoid_expr,
                        completion_expr: content.completion_expr,
                        stage_alignment: None,
                        actions: content.actions,
                        done: content.done,
                        pitfalls: content.pitfalls,
                        evidence_refs: refs.clone(),
                        support_revision_refs: Vec::new(),
                    };
                    draft
                        .validate()
                        .map_err(|_| SemanticServiceError::InvalidInput)?;
                    let suppressed = if let Some(inventory) = &planner.inventory {
                        inventory
                            .procedure_coverage(snapshot, &draft, &refs)
                            .await?
                            .suppresses_duplicate_create()
                    } else {
                        false
                    };
                    if !suppressed {
                        let resolution = crate::semantic::RevisionProposalService
                            .submit_with_deletion_admission(
                            &SemanticCurrentView::from_snapshot(snapshot)?,
                            &ObjectDeletionCandidateAdmissionView::from_snapshot(snapshot)?,
                            crate::semantic::ProposalCommandContext {
                                command_id: CommandId::new_v7(),
                                occurred_at_us: at,
                                effective_config_hash: job.config_hash,
                                algorithm_revision: KIND.into(),
                            },
                            crate::semantic::SubmitProposalRequest {
                                target_kind:
                                    evertrace_domain::semantic::ProposalTargetKind::Procedure,
                                target_id: None,
                                base_revision_id: None,
                                operation: evertrace_domain::semantic::ProposalOperation::Create,
                                payload: ProposalPayload::Procedure(Box::new(
                                    evertrace_domain::semantic::ProcedureProposalPayload::Create {
                                        draft,
                                    },
                                )),
                                evidence_refs: refs,
                                source_cohort_refs: input.refs,
                                eligibility: ProposalEligibility::ManualRequired,
                                created_by: evertrace_domain::semantic::ProposalCreatedBy::Agent,
                            },
                        )?;
                        if let crate::semantic::DeletionAwareProposalResolution::Proposal(
                            crate::semantic::ProposalResolution::Revision { command, .. },
                        ) = resolution
                        {
                            payloads
                                .extend(command.events().iter().map(|event| event.payload.clone()));
                        }
                    }
                }
            }
            Ok((None, used_input, used_output))
                if used_input <= job.budget.max_input_tokens.unwrap_or(0)
                    && used_output <= job.budget.max_output_tokens.unwrap_or(0) => {}
            Ok(_) => reason = JobTerminalReason::BudgetExhausted,
            Err(crate::provider::ProviderError::Schema) => reason = JobTerminalReason::Unsupported,
            Err(_) => reason = JobTerminalReason::SourceUnavailable,
        }
    } else {
        reason = JobTerminalReason::SourceUnavailable;
    }
    finish(job, payloads, reason, at)
}
