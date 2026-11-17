//! Source-bound gray-zone advice on the existing durable model lane.
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use evertrace_domain::canonical::sha256;
use evertrace_domain::{
    ids::{CommandId, JobId, WorkEpisodeId},
    revision::RevisionId,
    work::{
        ArtifactActor, ArtifactDerivability, ArtifactPayloadStatus, ArtifactRetention,
        ArtifactRevision, ArtifactScope, BoundaryStatus, CheckpointReason, EpisodeLifecycle,
        PhaseKind, WorkArtifactKind, WorkEpisode,
    },
};
use evertrace_store::{
    CurrentFacts, DurableJob, JobStatus, JobTerminalAudit, JobTerminalOutcome, JobTerminalReason,
    JournalCommand, JournalEventDraft, JournalPayload, RuntimeSchedulerView,
    SegmentationReadContext,
};
use serde::{Deserialize, Serialize};

use crate::{
    SynthesisPlanner, WriterHandle, maintenance::BackgroundSchedulerError as Error,
    semantic::SemanticServiceError,
};

pub(crate) use evertrace_store::PHASE_REFINEMENT_JOB_KIND as KIND;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Choice {
    ContinueSameAttempt,
    NewAttemptSameEpisode,
    NewEpisodeSameWorkstream,
    SwitchWorkstream,
    Underdetermined,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Decision {
    decision: Choice,
    evidence_refs: Vec<String>,
    confidence: f64,
    phase_kind: PhaseKind,
    phase_label: String,
}

impl Decision {
    fn validate(&self, refs: &BTreeSet<String>) -> bool {
        self.confidence.is_finite()
            && (0.0..=1.0).contains(&self.confidence)
            && !self.phase_label.trim().is_empty()
            && self.phase_label.len() <= 256
            && self.evidence_refs.len() <= 64
            && self
                .evidence_refs
                .iter()
                .all(|reference| refs.contains(reference))
            && self.evidence_refs.iter().collect::<BTreeSet<_>>().len() == self.evidence_refs.len()
            && (matches!(self.decision, Choice::Underdetermined) || !self.evidence_refs.is_empty())
    }
}

pub(crate) struct Input {
    selected: SegmentationReadContext,
    episode: WorkEpisode,
    json: String,
    key: String,
    evidence: BTreeSet<String>,
}

fn later_checkpoint(snapshot: &CurrentFacts, episode: &WorkEpisode) -> Result<bool, Error> {
    let Some(candidate) = &episode.boundary_candidate else {
        return Ok(false);
    };
    let deadline = Instant::now() + Duration::from_millis(40);
    for row in snapshot
        .other_data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("work_checkpoint"))
    {
        if Instant::now() >= deadline {
            return Ok(false);
        }
        if let Some(JournalPayload::WorkCheckpointRecorded(value)) = row
            .payload_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| Error::Store)?
            && value.episode_id == episode.episode_id
            && value.source_watermark >= candidate.candidate_watermark
            && value.created_reason != CheckpointReason::PhaseCandidate
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn current_episode(snapshot: &CurrentFacts, job: &DurableJob) -> Option<WorkEpisode> {
    if job.kind != KIND || job.algorithm_revision != KIND {
        return None;
    }
    let mut selected = None;
    for row in snapshot.other_data_rows().filter(|row| {
        row.object_kind.as_deref() == Some("work_episode")
            && row.current_revision_id.as_deref() == Some(job.target_revision.as_str())
    }) {
        if let Some(JournalPayload::WorkEpisodeRecorded(value)) = row
            .payload_json
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok())
        {
            selected = Some(*value);
        }
    }
    let episode = selected?;
    if episode.lifecycle_status != EpisodeLifecycle::Open
        || episode.boundary_status != BoundaryStatus::Candidate
        || episode.revision_generation != job.target_generation
        || episode.source_watermark != job.target_watermark
        || !later_checkpoint(snapshot, &episode).ok()?
    {
        return None;
    }
    let episode_key = episode.episode_id.to_string();
    for row in snapshot.other_data_rows().filter(|row| {
        row.object_kind.as_deref() == Some("work_episode")
            && row.object_id.as_deref() == Some(episode_key.as_str())
    }) {
        if let Some(JournalPayload::WorkEpisodeRecorded(value)) = row
            .payload_json
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok())
            && value.revision_generation > episode.revision_generation
        {
            return None;
        }
    }
    Some(episode)
}

pub(crate) async fn input(
    writer: &WriterHandle,
    snapshot: &CurrentFacts,
    episode_id: WorkEpisodeId,
    runtime: &evertrace_capture::RuntimeSnapshot,
) -> Result<Option<Input>, Error> {
    let Some(mut selected) = writer
        .phase_refinement_current_context(episode_id)
        .await
        .map_err(|_| Error::Writer)?
    else {
        return Ok(None);
    };
    if selected.state.frontier() != snapshot.frontier() {
        return Ok(None);
    }
    let episode = selected
        .state
        .episode(episode_id)
        .ok_or(Error::Store)?
        .clone();
    if episode.lifecycle_status != EpisodeLifecycle::Open
        || episode.boundary_status != BoundaryStatus::Candidate
        || !later_checkpoint(snapshot, &episode)?
    {
        return Ok(None);
    }
    let candidate = episode.boundary_candidate.as_ref().ok_or(Error::Store)?;
    let mut bursts = selected
        .state
        .boundary_bursts(&episode)
        .map_err(|_| Error::Store)?;
    let recent = selected
        .state
        .recent_bursts(&episode)
        .map_err(|_| Error::Store)?;
    for burst in recent.iter().rev().take(2) {
        if !bursts
            .iter()
            .any(|value| value.operation_burst_id == burst.operation_burst_id)
        {
            bursts.push(burst.clone());
        }
    }
    bursts.sort_by_key(|burst| burst.source_watermark);
    if bursts.len() > 4 {
        return Ok(None);
    }
    let mut source_refs = BTreeSet::new();
    let summaries = bursts.iter().map(|burst| {
        for member in burst.members.first().into_iter().chain(burst.members.last()) {
            source_refs.extend(member.source_observation_refs.iter().copied());
        }
        serde_json::json!({"burst":burst.operation_burst_id, "watermark":burst.source_watermark,
            "operation_class":burst.operation_kind, "target_family":burst.target_family,
            "state_delta":burst.state_delta,"verifier_delta":burst.verifier_delta,
            "error_signature":burst.error_signature,"phase_hint":burst.phase_candidate,"members":burst.members.len()})
    }).collect::<Vec<_>>();
    let mut artifacts = BTreeMap::new();
    let deadline = Instant::now() + Duration::from_millis(40);
    for row in snapshot
        .other_data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("work_artifact"))
    {
        if Instant::now() >= deadline {
            return Ok(None);
        }
        let Some(JournalPayload::WorkArtifactRecorded(value)) = row
            .payload_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| Error::Store)?
        else {
            continue;
        };
        if value.revision.kind != WorkArtifactKind::Log
            || value.revision.media_type != "application/json"
            || value.revision.produced_by_refs != [ArtifactActor::WorkEpisode(episode_id)]
            || !value
                .revision
                .source_observation_refs
                .iter()
                .any(|id| source_refs.contains(id))
        {
            continue;
        }
        let entry = artifacts
            .entry(value.work_artifact_id)
            .or_insert((row.source_event_seq, value.clone()));
        if row.source_event_seq > entry.0 {
            *entry = (row.source_event_seq, value);
        }
    }
    if source_refs.len() > 64 {
        return Ok(None);
    }
    selected.source_refs.extend(source_refs.iter().copied());
    selected.source_refs.sort();
    selected.source_refs.dedup();
    if super::production::readable_context(writer, snapshot, &selected, runtime)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let (_, plan) = super::production::source_activity(snapshot, &selected, runtime)
        .await
        .map_err(|_| Error::Store)?;
    let cas =
        evertrace_capture::CasStore::open_existing(&runtime.cas_dir).map_err(|_| Error::Store)?;
    let mut rationale = Vec::new();
    let mut evidence = source_refs
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    for (_, artifact) in artifacts.into_values() {
        let revision = &artifact.revision;
        if revision.kind != WorkArtifactKind::Log
            || revision.media_type != "application/json"
            || revision.payload_status != ArtifactPayloadStatus::Available
        {
            continue;
        }
        let Some(blob) = revision.content_blob_ref else {
            continue;
        };
        let encoded = blob.to_string();
        let digest = encoded
            .strip_prefix("cas:")
            .ok_or(Error::Store)?
            .parse()
            .map_err(|_| Error::Store)?;
        let (raw, _) = cas
            .read_bounded(&digest, 131072, 131072)
            .map_err(|_| Error::Store)?;
        let Ok(original) = serde_json::from_slice::<serde_json::Value>(&raw) else {
            continue;
        };
        let Some(rows) = original
            .pointer("/result/data")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        if rows.len() != 1 || rows[0]["item"]["type"] != "commandExecution" {
            continue;
        }
        let Some(command) = rows[0]["item"]["command"]
            .as_str()
            .filter(|value| value.len() <= 8192)
        else {
            continue;
        };
        evidence.insert(revision.revision_id.to_string());
        rationale.push(serde_json::json!({"artifact_revision":revision.revision_id,
            "source_refs":revision.source_observation_refs, "logical_command":command}));
        if rationale.len() == 4 {
            break;
        }
    }
    if rationale.len() < 2 {
        return Ok(None);
    }
    let json = serde_json::to_string(&serde_json::json!({"phase_contract":episode.phase_contract,
        "candidate":{"watermark":candidate.candidate_watermark,"kind":candidate.kind},
        "bursts":summaries,"plan_delta":plan.filter(|value| value != &episode.phase_contract),
        "rationale":rationale,"evidence_refs":evidence}))
    .map_err(|_| Error::Store)?;
    if json.len() > 16384 {
        return Ok(None);
    }
    let hash = sha256(
        "evertrace.phase-refinement-window",
        1,
        &evertrace_domain::canonical::CanonicalValue::String(json.clone()),
    )
    .map_err(|_| Error::Store)?
    .iter()
    .map(|value| format!("{value:02x}"))
    .collect::<String>();
    let key = format!("{KIND}:{hash}");
    Ok(Some(Input {
        selected,
        episode,
        json,
        key,
        evidence,
    }))
}

pub(crate) async fn jobs(
    writer: &WriterHandle,
    snapshot: &CurrentFacts,
    episodes: impl Iterator<Item = &WorkEpisode>,
    planner: &SynthesisPlanner,
    runtime: &evertrace_capture::RuntimeSnapshot,
    view: &RuntimeSchedulerView,
    wall: Duration,
    at: i64,
    limit: usize,
) -> Result<Vec<DurableJob>, Error> {
    let mut jobs = Vec::new();
    if !planner.llm.enabled || planner.provider.is_none() {
        return Ok(jobs);
    }
    let budget = crate::jobs::procedure::budget(planner, wall).map_err(|_| Error::Store)?;
    for episode in episodes {
        if jobs.len() >= limit {
            break;
        }
        if episode.boundary_status != BoundaryStatus::Candidate
            || !later_checkpoint(snapshot, episode)?
        {
            continue;
        }
        let Some(input) = input(writer, snapshot, episode.episode_id, runtime).await? else {
            continue;
        };
        if input.json.len() as u64 + 2048 > budget.max_input_tokens.unwrap_or(0) {
            continue;
        }
        let same = view.jobs.iter().filter(|job| {
            job.kind == KIND
                && job.idempotency_key == input.key
                && job.config_hash == runtime.effective_config_hash
                && job.model_id.as_deref() == Some(planner.llm.model.as_str())
        });
        if same.clone().any(|job| {
            job.state == JobStatus::Succeeded
                || matches!(job.state, JobStatus::Queued | JobStatus::Leased)
                    && job.target_revision == episode.revision_id.to_string()
        }) {
            continue;
        }
        if let Some(previous) = same
            .filter(|job| job.target_revision == episode.revision_id.to_string())
            .max_by_key(|job| job.attempt)
        {
            if previous.attempt >= 6
                || previous.terminal.as_ref().is_none_or(|terminal| {
                    !matches!(
                        terminal.reason,
                        JobTerminalReason::SourceUnavailable | JobTerminalReason::Unsupported
                    )
                })
            {
                continue;
            }
            let mut retry = previous.clone();
            retry.state = JobStatus::Queued;
            retry.attempt += 1;
            retry.terminal = None;
            retry.backoff_until_us = Some(at.saturating_add(30_000_000));
            retry.lease_until_us = None;
            jobs.push(retry);
        } else {
            jobs.push(DurableJob {
                job_id: JobId::new_v7(),
                idempotency_key: input.key,
                target_revision: episode.revision_id.to_string(),
                target_watermark: episode.source_watermark,
                target_generation: episode.revision_generation,
                kind: KIND.into(),
                algorithm_revision: KIND.into(),
                model_id: Some(planner.llm.model.clone()),
                priority: 5,
                state: JobStatus::Queued,
                attempt: 1,
                backoff_until_us: None,
                config_hash: runtime.effective_config_hash,
                budget: budget.clone(),
                terminal: None,
                lease_until_us: None,
            });
        }
    }
    Ok(jobs)
}

pub(crate) async fn allowed(
    writer: &WriterHandle,
    snapshot: &CurrentFacts,
    job: &DurableJob,
    runtime: &evertrace_capture::RuntimeSnapshot,
) -> Result<Option<Input>, Error> {
    let Some(episode) = current_episode(snapshot, job) else {
        return Ok(None);
    };
    let Some(input) = input(writer, snapshot, episode.episode_id, runtime).await? else {
        return Ok(None);
    };
    Ok(
        (input.key == job.idempotency_key && job.config_hash == runtime.effective_config_hash)
            .then_some(input),
    )
}

pub(crate) async fn execute(
    writer: &WriterHandle,
    snapshot: &CurrentFacts,
    job: &DurableJob,
    planner: &SynthesisPlanner,
    runtime: &evertrace_capture::RuntimeSnapshot,
    at: i64,
) -> Result<JournalCommand, SemanticServiceError> {
    let mut payloads = Vec::new();
    let mut reason = JobTerminalReason::StaleGeneration;
    if let Some(input) = allowed(writer, snapshot, job, runtime)
        .await
        .map_err(|_| SemanticServiceError::InvalidInput)?
    {
        let admission = || async {
            let current = writer
                .project_current(true)
                .await
                .map_err(|_| crate::provider::ProviderError::Schema)?;
            allowed(writer, &current, job, runtime)
                .await
                .map_err(|_| crate::provider::ProviderError::Schema)?
                .ok_or(crate::provider::ProviderError::Schema)
                .map(|_| ())
        };
        reason = JobTerminalReason::SourceUnavailable;
        if let Some(provider) = planner
            .provider
            .as_ref()
            .filter(|_| job.model_id.as_deref() == Some(planner.llm.model.as_str()))
        {
            match provider
                .refine_phase(
                    input.json.clone(),
                    job.budget.max_output_tokens.unwrap_or(0),
                    Duration::from_millis(job.budget.max_wall_time_ms),
                    &admission,
                )
                .await
            {
                Ok((decision, used_input, used_output))
                    if decision.validate(&input.evidence)
                        && used_input <= job.budget.max_input_tokens.unwrap_or(0)
                        && used_output <= job.budget.max_output_tokens.unwrap_or(0) =>
                {
                    let key =
                        evertrace_capture::DeviceKeyStore::new(runtime.device_key_dir.clone())
                            .load()
                            .map_err(|_| SemanticServiceError::InvalidInput)?;
                    let raw = serde_json::to_vec(&decision)
                        .map_err(|_| SemanticServiceError::InvalidInput)?;
                    let protected = evertrace_capture::protect(&raw, &key)
                        .map_err(|_| SemanticServiceError::InvalidInput)?;
                    let cas = evertrace_capture::CasStore::open_existing(&runtime.cas_dir)
                        .map_err(|_| SemanticServiceError::InvalidInput)?;
                    let digest = cas
                        .put(&protected)
                        .map_err(|_| SemanticServiceError::InvalidInput)?;
                    let blob = evertrace_domain::ids::CasId::from_digest(*digest.as_bytes());
                    let episode = &input.episode;
                    let scope = match (episode.repository_instance_id, episode.worktree_instance_id)
                    {
                        (Some(repository_instance_id), Some(worktree_instance_id)) => {
                            ArtifactScope::Worktree {
                                repository_instance_id,
                                worktree_instance_id,
                            }
                        }
                        (None, None) => ArtifactScope::Task {
                            task_id: episode.task_id,
                        },
                        _ => return Err(SemanticServiceError::InvalidInput),
                    };
                    let artifact = crate::autoresearch::ArtifactService::new(cas)
                        .create(ArtifactRevision {
                            revision_id: RevisionId::new_v7(),
                            parent_revision_id: None,
                            kind: WorkArtifactKind::Review,
                            logical_name: "阶段判断".into(),
                            scope,
                            media_type: "application/json".into(),
                            content_blob_ref: Some(blob),
                            content_fingerprint: Some(blob),
                            external_reference: None,
                            payload_status: ArtifactPayloadStatus::Available,
                            produced_by_refs: vec![ArtifactActor::WorkEpisode(episode.episode_id)],
                            consumed_by_refs: vec![],
                            source_observation_refs: input.selected.source_refs.clone(),
                            derivability: ArtifactDerivability::PartiallyReproducible,
                            retention: ArtifactRetention::Task,
                            created_at_us: at,
                        })
                        .map_err(|_| SemanticServiceError::InvalidInput)?;
                    payloads.push(JournalPayload::WorkArtifactRecorded(Box::new(artifact)));
                    reason = JobTerminalReason::Completed;
                }
                Ok(_) | Err(crate::provider::ProviderError::Schema) => {
                    reason = JobTerminalReason::Unsupported
                }
                Err(_) => {}
            }
        }
    }
    let result_ref = payloads.iter().find_map(|value| match value {
        JournalPayload::WorkArtifactRecorded(artifact) => {
            Some(artifact.revision.revision_id.to_string())
        }
        _ => None,
    });
    let mut terminal = job.clone();
    terminal.state = if reason == JobTerminalReason::Completed {
        JobStatus::Succeeded
    } else {
        JobStatus::Failed
    };
    terminal.lease_until_us = None;
    terminal.terminal = Some(Box::new(JobTerminalAudit {
        outcome: if terminal.state == JobStatus::Succeeded {
            JobTerminalOutcome::Succeeded
        } else {
            JobTerminalOutcome::Failed
        },
        reason,
        result_ref,
    }));
    payloads.push(JournalPayload::JobState(terminal));
    Ok(JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, job.config_hash, KIND, payload))
            .collect(),
    )?)
}
