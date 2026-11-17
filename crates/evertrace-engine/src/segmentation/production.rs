//! Canonical activity intake for the existing maintenance worker.
use evertrace_domain::ids::SourceObservationId;
use evertrace_store::{CurrentFacts, SegmentationReadContext};

use super::{
    BoundaryEvidence, DetectorError, IncrementalSegmenter, SegmentOutcome, SegmentationFacts,
};

/// Revalidate the selected Work publisher and its link to actual execution, not merely the same Task.
async fn source_policy(
    current: &CurrentFacts,
    selected: &SegmentationReadContext,
) -> Result<Option<crate::repository::SourcePolicy>, crate::autoresearch::AutoresearchError> {
    let roots = selected
        .root_refs
        .iter()
        .filter_map(|reference| {
            let (observation, _) = current.source_observation(reference.parse().ok()?)?;
            let receipt = current.source_receipt(observation.source_receipt_ref)?.0;
            evertrace_capture::goal_source::is_source_revision(receipt.source_revision.as_str())
                .then(|| receipt.clone())
        })
        .collect::<Vec<_>>();
    let executions = selected
        .source_refs
        .iter()
        .filter_map(|id| {
            let (observation, _) = current.source_observation(*id)?;
            let receipt = current.source_receipt(observation.source_receipt_ref)?.0;
            evertrace_capture::execution_source::is_execution(observation, receipt)
                .then(|| receipt.clone())
        })
        .collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || {
        roots
            .iter()
            .filter(|root| {
                executions.iter().any(|execution| {
                    evertrace_capture::goal_source::same_execution_context(root, execution)
                })
            })
            .find_map(|root| crate::repository::SourcePolicy::from_recorded_goal(root))
    })
    .await
    .map_err(|_| crate::autoresearch::AutoresearchError::EvidenceIncomplete)
}

#[derive(Default)]
pub(super) struct SourceActivity {
    pub exit_code: Option<i32>,
    pub exit_refs: Vec<SourceObservationId>,
    pub phase: Option<evertrace_domain::work::PhaseContract>,
    pub strategy: Option<evertrace_domain::work::StrategyContract>,
    pub declaration_refs: Vec<SourceObservationId>,
}

pub(super) async fn source_activity(
    current: &CurrentFacts,
    selected: &SegmentationReadContext,
    runtime: &evertrace_capture::RuntimeSnapshot,
) -> Result<SourceActivity, evertrace_capture::CasError> {
    use evertrace_capture::CasError as Error;
    let operation = selected
        .state
        .authority()
        .operation(selected.operation_id)
        .ok_or(Error::StoreCorrupt)?;
    let binding = selected
        .state
        .authority()
        .binding(selected.operation_id)
        .ok_or(Error::StoreCorrupt)?;
    let inputs = operation.input_source_observation_refs.clone();
    let results = operation.result_source_observation_refs.clone();
    let references = inputs
        .iter()
        .chain(&results)
        .copied()
        .chain(
            binding
                .evidence_refs
                .iter()
                .filter_map(|value| value.parse().ok()),
        )
        .collect::<std::collections::BTreeSet<SourceObservationId>>();
    let records = references
        .iter()
        .filter_map(|id| {
            let (observation, _) = current.source_observation(*id)?;
            let receipt = current.source_receipt(observation.source_receipt_ref)?.0;
            ((evertrace_capture::execution_source::is_execution(observation, receipt)
                || evertrace_capture::process_source::is_work_revision(
                    receipt.source_revision.as_str(),
                ))
                && receipt.protected_length <= 128 * 1024)
                .then(|| (observation.clone(), receipt.clone()))
        })
        .collect::<Vec<_>>();
    if records.is_empty() {
        return Ok(SourceActivity::default());
    }
    let cas_dir = runtime.cas_dir.clone();
    tokio::task::spawn_blocking(move || {
        let cas = evertrace_capture::CasStore::open_existing(cas_dir)?;
        let mut protected = Vec::new();
        for (observation, receipt) in records {
            let digest = receipt.cas_ref.parse::<evertrace_capture::CasDigest>()?;
            let (bytes, _) = cas.read_bounded(&digest, 128 * 1024, 128 * 1024)?;
            if bytes.len() as u64 != receipt.protected_length {
                return Err(Error::StoreCorrupt);
            }
            protected.push((observation, receipt, bytes));
        }
        let mut exits = std::collections::BTreeSet::new();
        let mut exit_refs = std::collections::BTreeSet::new();
        let mut phases = Vec::new();
        let mut strategies = Vec::new();
        let mut declaration_refs = std::collections::BTreeSet::new();
        for (observation, receipt, bytes) in &protected {
            if results.contains(&observation.source_observation_id) {
                if let Some(code) = evertrace_capture::execution_source::execution_exit_code(
                    observation,
                    receipt,
                    bytes,
                ) {
                    exits.insert(code);
                    exit_refs.insert(observation.source_observation_id);
                }
            }
            for (native, native_receipt, native_bytes) in &protected {
                if inputs.contains(&native.source_observation_id) {
                    if let Some((phase, strategy)) = crate::autoresearch::declared_work_contract(
                        receipt,
                        bytes,
                        native,
                        native_receipt,
                        native_bytes,
                    ) {
                        if !phases.contains(&phase) {
                            phases.push(phase);
                        }
                        if !strategies.contains(&strategy) {
                            strategies.push(strategy);
                        }
                        declaration_refs.extend([
                            observation.source_observation_id,
                            native.source_observation_id,
                        ]);
                    }
                }
            }
        }
        Ok(SourceActivity {
            exit_code: (exits.len() == 1).then(|| *exits.first().expect("one physical result")),
            exit_refs: if exits.len() == 1 {
                exit_refs.into_iter().collect()
            } else {
                Vec::new()
            },
            phase: (phases.len() == 1).then(|| phases.remove(0)),
            strategy: (strategies.len() == 1).then(|| strategies.remove(0)),
            declaration_refs: declaration_refs.into_iter().collect(),
        })
    })
    .await
    .map_err(|_| Error::Io)?
}

/// A nonzero physical exit is an operation failure, not a verifier result or semantic boundary.
fn derive_activity(
    selected: &SegmentationReadContext,
    exit: Option<i32>,
    declared_phase: Option<evertrace_domain::work::PhaseContract>,
) -> Result<SegmentOutcome, DetectorError> {
    let state = &selected.state;
    let episode = state
        .episode(selected.episode_id)
        .ok_or(DetectorError::Ineligible)?;
    let operation = state
        .authority()
        .operation(selected.operation_id)
        .ok_or(DetectorError::Ineligible)?;
    let scope = episode.repository_instance_id.map_or_else(
        || "non_repository".to_owned(),
        |id| format!("repository:{id}"),
    );
    let facts = SegmentationFacts {
        sequence: selected.sequence,
        source_watermark: state.frontier(),
        target_family: scope,
        state_delta: if exit.is_some_and(|code| code != 0) {
            super::StateDeltaKind::Failed
        } else {
            super::StateDeltaKind::Observed
        },
        error_signature: exit
            .filter(|code| *code != 0)
            .map(|code| format!("process_exit:{code}")),
        verifier_transition: super::VerifierTransition::None,
        // A protected declaration supplies a structured hint, never objective boundary evidence.
        observed_phase_kind: declared_phase.as_ref().map(|phase| phase.phase_kind),
        boundary_evidence: BoundaryEvidence::None,
        evidence_refs: operation
            .input_source_observation_refs
            .iter()
            .chain(&operation.result_source_observation_refs)
            .copied()
            .collect(),
    };
    let mut segmenter = IncrementalSegmenter::restore(state, selected.episode_id)?;
    segmenter.observe_declared(state, selected.operation_id, facts, declared_phase.as_ref())
}

pub(super) fn tool_request_sources(
    current: &CurrentFacts,
    selected: &SegmentationReadContext,
    episode: &evertrace_domain::work::WorkEpisode,
) -> Result<Vec<SourceObservationId>, crate::maintenance::BackgroundSchedulerError> {
    use crate::maintenance::BackgroundSchedulerError as Error;
    let operation = selected
        .state
        .authority()
        .operation(selected.operation_id)
        .ok_or(Error::Store)?;
    let recent = selected
        .state
        .recent_bursts(episode)
        .map_err(|_| Error::Store)?;
    let left = recent
        .iter()
        .rev()
        .flat_map(|burst| burst.members.iter().rev())
        .find(|member| member.operation_id != selected.operation_id);
    let mut result = Vec::new();
    for refs in left
        .map(|member| member.source_observation_refs.as_slice())
        .into_iter()
        .chain([operation.input_source_observation_refs.as_slice()])
    {
        let mut physical = Vec::new();
        for id in refs {
            let (observation, _) = current.source_observation(*id).ok_or(Error::Store)?;
            let receipt = current
                .source_receipt(observation.source_receipt_ref)
                .ok_or(Error::Store)?
                .0;
            if observation.observation_role == evertrace_domain::evidence::ObservationRole::Intent
                && evertrace_capture::execution_source::is_execution(observation, receipt)
            {
                physical.push(*id);
            }
        }
        physical.sort();
        physical.dedup();
        if let [id] = physical.as_slice()
            && !result.contains(id)
        {
            result.push(*id);
        }
    }
    Ok(result)
}

pub(super) async fn tool_request_artifacts(
    current: &CurrentFacts,
    episode: &evertrace_domain::work::WorkEpisode,
    runtime: &evertrace_capture::RuntimeSnapshot,
    now_us: i64,
    sources: &[SourceObservationId],
) -> Result<Vec<evertrace_domain::work::WorkArtifact>, crate::maintenance::BackgroundSchedulerError>
{
    use crate::maintenance::BackgroundSchedulerError as Error;
    use evertrace_domain::work::{
        ArtifactActor, ArtifactDerivability, ArtifactPayloadStatus, ArtifactRetention,
        ArtifactRevision, ArtifactScope, WorkArtifactKind,
    };
    let mut candidates = Vec::new();
    for id in sources {
        let (observation, _) = current.source_observation(*id).ok_or(Error::Store)?;
        let receipt = current
            .source_receipt(observation.source_receipt_ref)
            .ok_or(Error::Store)?
            .0;
        if evertrace_capture::execution_source::is_execution(observation, receipt) {
            candidates.push((observation.clone(), receipt.clone()));
        }
    }
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let runtime = runtime.clone();
    let scope = match (episode.repository_instance_id, episode.worktree_instance_id) {
        (Some(repository_instance_id), Some(worktree_instance_id)) => ArtifactScope::Worktree {
            repository_instance_id,
            worktree_instance_id,
        },
        (None, None) => ArtifactScope::Task {
            task_id: episode.task_id,
        },
        _ => return Err(Error::Store),
    };
    let episode_id = episode.episode_id;
    tokio::task::spawn_blocking(move || {
        let cas = evertrace_capture::CasStore::open_existing(&runtime.cas_dir)
            .map_err(|_| Error::Store)?;
        let key = evertrace_capture::DeviceKeyStore::new(runtime.device_key_dir)
            .load()
            .map_err(|_| Error::Store)?;
        let mut artifacts = Vec::new();
        for (observation, receipt) in candidates {
            let digest = receipt.cas_ref.parse().map_err(|_| Error::Store)?;
            let (protected, _) = cas
                .read_bounded(&digest, 131_072, 131_072)
                .map_err(|_| Error::Store)?;
            if protected.len() as u64 != receipt.protected_length {
                return Err(Error::Store);
            }
            let Ok(raw) = evertrace_capture::goal_source::read_tool_request(
                &observation,
                &receipt,
                &protected,
            ) else {
                continue;
            };
            let payload = evertrace_capture::protect(&raw, &key).map_err(|_| Error::Store)?;
            let digest = cas.put(&payload).map_err(|_| Error::Store)?;
            let blob = evertrace_domain::ids::CasId::from_digest(*digest.as_bytes());
            artifacts.push(
                crate::autoresearch::ArtifactService::new(cas.clone())
                    .create(ArtifactRevision {
                        revision_id: evertrace_domain::revision::RevisionId::new_v7(),
                        parent_revision_id: None,
                        kind: WorkArtifactKind::Log,
                        logical_name: "工具请求".into(),
                        scope,
                        media_type: "application/json".into(),
                        content_blob_ref: Some(blob),
                        external_reference: None,
                        content_fingerprint: Some(blob),
                        payload_status: ArtifactPayloadStatus::Available,
                        produced_by_refs: vec![ArtifactActor::WorkEpisode(episode_id)],
                        consumed_by_refs: Vec::new(),
                        source_observation_refs: vec![observation.source_observation_id],
                        derivability: ArtifactDerivability::Original,
                        retention: ArtifactRetention::Task,
                        created_at_us: now_us,
                    })
                    .map_err(|_| Error::Store)?,
            );
        }
        Ok(artifacts)
    })
    .await
    .map_err(|_| Error::Store)?
}

pub(super) async fn readable_context(
    writer: &crate::WriterHandle,
    current: &CurrentFacts,
    selected: &SegmentationReadContext,
    runtime: &evertrace_capture::RuntimeSnapshot,
) -> Result<Option<std::time::Instant>, crate::maintenance::BackgroundSchedulerError> {
    use crate::maintenance::BackgroundSchedulerError as Error;
    // Existing canonical Work and physical evidence do not require the publisher to stay alive.
    // Only code access needs its current source-owned repository policy; there is no HOME fallback.
    let policy = if selected.repository_ids.is_empty() {
        None
    } else {
        source_policy(current, &selected)
            .await
            .map_err(|_| Error::Store)?
    };
    let authority = policy.as_ref().map_or(
        crate::repository::RepositoryReadAuthority::Unavailable,
        crate::repository::RepositoryReadAuthority::Source,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
    let refs = selected
        .source_refs
        .iter()
        .copied()
        .chain(
            selected
                .root_refs
                .iter()
                .filter_map(|reference| reference.parse::<SourceObservationId>().ok()),
        )
        .map(|id| id.to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut blocked = false;
    let mut revoked = Vec::new();
    for chunk in refs.chunks(64) {
        if std::time::Instant::now() >= deadline {
            blocked = true;
            break;
        }
        match crate::session_import::source_observations_read_assessment(
            writer, &authority, current, chunk,
        )
        .await
        {
            Ok((denied, observations)) => {
                blocked |= !denied.is_empty();
                revoked.extend(observations);
            }
            Err(crate::session_import::SessionImportServiceError::Unavailable) => {
                blocked = true;
                break;
            }
            Err(_) => return Err(Error::Store),
        }
    }
    if !blocked && std::time::Instant::now() < deadline {
        let (denied, observations) = crate::repository::repository_read_assessment(
            writer,
            selected.repository_ids.iter().copied().collect(),
            &authority,
            deadline,
        )
        .await
        .map_err(|_| Error::Store)?;
        blocked |= !denied.is_empty();
        revoked.extend(observations);
    } else {
        blocked = true;
    }
    crate::repository::record_trust_revocations(writer, revoked, runtime.effective_config_hash)
        .await
        .map_err(|_| Error::Store)?;
    if blocked || std::time::Instant::now() >= deadline {
        return Ok(None);
    }
    Ok(Some(deadline))
}

pub(crate) async fn advance_activity(
    writer: &crate::WriterHandle,
    current: &CurrentFacts,
    runtime: &evertrace_capture::RuntimeSnapshot,
    after: &mut u64,
) -> Result<crate::maintenance::BackgroundProgress, crate::maintenance::BackgroundSchedulerError> {
    use crate::maintenance::{BackgroundProgress, BackgroundSchedulerError as Error};
    let mut progress = BackgroundProgress {
        completed: 0,
        retryable: false,
    };
    for _ in 0..8 {
        let previous = *after;
        let Some(mut selected) = writer
            .segmentation_current_context(*after)
            .await
            .map_err(|_| Error::Writer)?
        else {
            *after = 0;
            return Ok(progress);
        };
        if selected.state.frontier() != current.frontier() {
            progress.retryable = true;
            return Ok(progress);
        }
        *after = selected.sequence;
        let Some(deadline) = readable_context(writer, current, &selected, runtime).await? else {
            continue;
        };
        let activity = match source_activity(current, &selected, runtime).await {
            Ok(activity) => activity,
            Err(error) => {
                let changed =
                    writer.sync_frontier().await.map_err(|_| Error::Writer)? != current.frontier();
                if changed || matches!(error, evertrace_capture::CasError::LockBusy) {
                    *after = previous;
                    progress.retryable = true;
                    return Ok(progress);
                }
                return Err(Error::Store);
            }
        };
        if std::time::Instant::now() >= deadline {
            continue;
        }
        let step = match derive_activity(&selected, activity.exit_code, activity.phase) {
            Ok(SegmentOutcome::Delta(step)) => step,
            Ok(SegmentOutcome::NoDelta) | Err(DetectorError::Ineligible) => continue,
            Err(_) => return Err(Error::Store),
        };
        let episode = selected
            .state
            .episode(selected.episode_id)
            .ok_or(Error::Store)?;
        let receipts = episode
            .execution_lane_ids
            .iter()
            .copied()
            .chain(
                selected
                    .state
                    .authority()
                    .operation(selected.operation_id)
                    .and_then(|op| op.execution_lane_id),
            )
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|id| {
                let view = selected.state.authority();
                view.lane(id)
                    .and_then(|lane| view.receipt(lane.active_capture_receipt_revision_id))
                    .cloned()
                    .ok_or(Error::Store)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let occurred_at_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_micros()).ok())
            .ok_or(Error::Store)?;
        let context = crate::work::WorkCommandContext {
            command_id: evertrace_domain::ids::CommandId::new_v7(),
            occurred_at_us,
            effective_config_hash: runtime.effective_config_hash,
            algorithm_revision: "incremental-segmentation-v1",
        };
        let needs_checkpoint = step.candidate_watermark().is_some_and(|watermark| {
            !selected.candidate_checkpointed
                || episode
                    .boundary_candidate
                    .as_ref()
                    .is_none_or(|candidate| candidate.candidate_watermark != watermark)
        });
        let artifacts = if needs_checkpoint {
            let sources = tool_request_sources(current, &selected, episode)?;
            selected.source_refs.extend(sources.iter().copied());
            selected.source_refs.sort();
            selected.source_refs.dedup();
            if readable_context(writer, current, &selected, runtime)
                .await?
                .is_none()
            {
                *after = previous;
                progress.retryable = true;
                return Ok(progress);
            }
            tool_request_artifacts(current, episode, runtime, occurred_at_us, &sources).await?
        } else {
            Vec::new()
        };
        if needs_checkpoint
            && readable_context(writer, current, &selected, runtime)
                .await?
                .is_none()
        {
            *after = previous;
            progress.retryable = true;
            return Ok(progress);
        }
        let command = if needs_checkpoint {
            let attempts = episode
                .attempt_ids
                .iter()
                .map(|id| {
                    selected
                        .state
                        .authority()
                        .attempt(*id)
                        .cloned()
                        .ok_or(Error::Store)
                })
                .collect::<Result<Vec<_>, _>>()?;
            crate::work::episode::save_candidate_checkpoint(
                context,
                episode,
                &step,
                &receipts,
                &attempts,
                selected.snapshot.as_ref(),
            )
        } else {
            crate::work::episode::save_segmentation_update(context, episode, &step, &receipts)
        }
        .map_err(|_| Error::Store)?;
        let command = if !artifacts.is_empty() {
            let mut events = command.events().to_vec();
            for artifact in artifacts {
                events.push(evertrace_store::JournalEventDraft::runtime(
                    occurred_at_us,
                    runtime.effective_config_hash,
                    "tool_request_v1",
                    evertrace_store::JournalPayload::WorkArtifactRecorded(Box::new(artifact)),
                ));
            }
            evertrace_store::JournalCommand::new(command.command_id(), events)
                .map_err(|_| Error::Store)?
        } else {
            command
        };
        match writer
            .commit_if_frontier(command, occurred_at_us, current.frontier())
            .await
        {
            Ok(_) => {
                // The controller is request-local: the next activity restores the committed canonical state.
                progress.completed = 1;
                progress.retryable = true;
                return Ok(progress);
            }
            Err(crate::WriterActorError::StaleFrontier { .. }) => {
                *after = previous;
                progress.retryable = true;
                return Ok(progress);
            }
            Err(_) => return Err(Error::Writer),
        }
    }
    progress.retryable = true;
    Ok(progress)
}
