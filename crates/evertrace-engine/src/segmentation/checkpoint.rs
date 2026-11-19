use crate::maintenance::{BackgroundProgress, BackgroundSchedulerError as Error};
use evertrace_domain::{
    repository::WorktreeSnapshot,
    work::{
        Attempt, CaptureReceipt, CaptureSummary, CheckpointReason, WorkCheckpoint, WorkEpisode,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckpointResolution {
    NoDelta,
    Checkpoint(Box<WorkCheckpoint>),
}

pub fn build_checkpoint(
    episode: &WorkEpisode,
    attempts: &[Attempt],
    snapshot: Option<&WorktreeSnapshot>,
    reason: CheckpointReason,
    existing: Option<&WorkCheckpoint>,
) -> Result<CheckpointResolution, evertrace_domain::work::WorkError> {
    let checkpoint = WorkCheckpoint::derive(episode, attempts, snapshot, reason)?;
    if let Some(current) = existing
        && current.stable_key() == checkpoint.stable_key()
    {
        return if current == &checkpoint {
            Ok(CheckpointResolution::NoDelta)
        } else {
            Err(evertrace_domain::work::WorkError::InvalidWorkIdentity)
        };
    }
    Ok(CheckpointResolution::Checkpoint(Box::new(checkpoint)))
}

pub(crate) async fn advance_checkpoints(
    writer: &crate::WriterHandle,
    current: &evertrace_store::CurrentFacts,
    runtime: &evertrace_capture::RuntimeSnapshot,
) -> Result<crate::maintenance::BackgroundProgress, crate::maintenance::BackgroundSchedulerError> {
    use evertrace_capture::{CasDigest, CasError, CasStore, checkpoint_source};
    let idle = BackgroundProgress {
        completed: 0,
        retryable: false,
    };
    for (observation, before) in current.source_observations() {
        if observation.source_revision.as_str() != checkpoint_source::SOURCE_REVISION {
            continue;
        }
        let Some((receipt, _)) = current.source_receipt(observation.source_receipt_ref) else {
            return Err(Error::Store);
        };
        if receipt.protected_length > 8192 {
            continue;
        }
        match crate::session_import::source_observations_read_assessment(
            writer,
            &crate::repository::RepositoryReadAuthority::Unavailable,
            current,
            &[observation.source_observation_id.to_string()],
        )
        .await
        {
            Ok((denied, revoked)) => {
                crate::repository::record_trust_revocations(
                    writer,
                    revoked,
                    runtime.effective_config_hash,
                )
                .await
                .map_err(|_| Error::Store)?;
                if !denied.is_empty() {
                    continue;
                }
            }
            Err(crate::session_import::SessionImportServiceError::Unavailable) => continue,
            Err(_) => return Err(Error::Store),
        }
        let cas_dir = runtime.cas_dir.clone();
        let digest = receipt
            .cas_ref
            .parse::<CasDigest>()
            .map_err(|_| Error::Store)?;
        let protected = match tokio::task::spawn_blocking(move || {
            CasStore::open_existing(cas_dir)?.read_bounded(&digest, 8192, 8192)
        })
        .await
        .map_err(|_| Error::Store)?
        {
            Ok((bytes, _)) => bytes,
            // A missing request is not authority for a checkpoint, but must not hide later requests.
            Err(CasError::NotFound) => continue,
            Err(_) => return Err(Error::Store),
        };
        let Some(request) = checkpoint_source::observed_request(observation, receipt, &protected)
        else {
            continue;
        };
        let sources = current
            .source_receipts()
            .filter(|(physical, seq)| *seq <= before && request.targets(receipt, physical))
            .map(|(physical, _)| physical.source_observation_id)
            .collect::<std::collections::BTreeSet<_>>();
        if sources.is_empty() {
            continue;
        }
        let Some(mut selected) = writer
            .checkpoint_current_context(
                sources,
                observation.source_observation_id,
                request.reason(),
            )
            .await
            .map_err(|_| Error::Writer)?
        else {
            continue;
        };
        selected.source_refs.push(observation.source_observation_id);
        selected.source_refs.sort();
        selected.source_refs.dedup();
        let progress = save_selected_checkpoint(
            writer,
            current,
            runtime,
            selected,
            request.reason(),
            Some(observation.source_observation_id),
        )
        .await?;
        if progress.completed != 0 || progress.retryable {
            return Ok(progress);
        }
    }
    Ok(idle)
}

pub(crate) async fn advance_idle_checkpoints(
    writer: &crate::WriterHandle,
    current: &evertrace_store::CurrentFacts,
    runtime: &evertrace_capture::RuntimeSnapshot,
    mut episodes: std::collections::BTreeSet<evertrace_domain::ids::WorkEpisodeId>,
) -> Result<BackgroundProgress, Error> {
    while !episodes.is_empty() {
        let Some(selected) = writer
            .idle_checkpoint_current_context(episodes.clone())
            .await
            .map_err(|_| Error::Writer)?
        else {
            break;
        };
        episodes.remove(&selected.episode_id);
        let progress = save_selected_checkpoint(
            writer,
            current,
            runtime,
            selected,
            CheckpointReason::Idle,
            None,
        )
        .await?;
        if progress.completed != 0 || progress.retryable {
            return Ok(progress);
        }
    }
    Ok(BackgroundProgress {
        completed: 0,
        retryable: false,
    })
}

async fn save_selected_checkpoint(
    writer: &crate::WriterHandle,
    current: &evertrace_store::CurrentFacts,
    runtime: &evertrace_capture::RuntimeSnapshot,
    mut selected: evertrace_store::SegmentationReadContext,
    reason: CheckpointReason,
    cause: Option<evertrace_domain::ids::SourceObservationId>,
) -> Result<BackgroundProgress, Error> {
    if selected.state.frontier() != current.frontier() {
        return Ok(BackgroundProgress {
            completed: 0,
            retryable: true,
        });
    }
    let Some(mut deadline) =
        super::production::readable_context(writer, current, &selected, runtime).await?
    else {
        return Ok(BackgroundProgress {
            completed: 0,
            retryable: false,
        });
    };
    let episode = selected
        .state
        .episode(selected.episode_id)
        .ok_or(Error::Store)?;
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
    let CheckpointResolution::Checkpoint(checkpoint) =
        build_checkpoint(episode, &attempts, selected.snapshot.as_ref(), reason, None)
            .map_err(|_| Error::Store)?
    else {
        return Ok(BackgroundProgress {
            completed: 0,
            retryable: false,
        });
    };
    let occurred_at_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_micros()).ok())
        .ok_or(Error::Store)?;
    let context = crate::work::WorkCommandContext {
        command_id: evertrace_domain::ids::CommandId::new_v7(),
        occurred_at_us,
        effective_config_hash: runtime.effective_config_hash,
        algorithm_revision: "work-checkpoint-v1",
    };
    let artifacts = if reason == CheckpointReason::Idle
        && episode.phase_contract.phase_kind == evertrace_domain::work::PhaseKind::Unknown
    {
        let sources = super::production::tool_request_sources(current, &selected, episode)?;
        selected.source_refs.extend(sources.iter().copied());
        selected.source_refs.sort();
        selected.source_refs.dedup();
        if super::production::readable_context(writer, current, &selected, runtime)
            .await?
            .is_none()
        {
            return Ok(BackgroundProgress::default());
        }
        let Some(artifacts) = super::production::tool_request_artifacts(
            current,
            episode,
            runtime,
            occurred_at_us,
            &sources,
        )
        .await?
        else {
            return Ok(BackgroundProgress::default());
        };
        let Some(allowed_until) =
            super::production::readable_context(writer, current, &selected, runtime).await?
        else {
            return Ok(BackgroundProgress::default());
        };
        deadline = allowed_until;
        artifacts
    } else {
        Vec::new()
    };
    let Some(command) = crate::work::episode::save_checkpoint(context, episode, *checkpoint, None)
        .map_err(|_| Error::Store)?
    else {
        return Ok(BackgroundProgress {
            completed: 0,
            retryable: false,
        });
    };
    if std::time::Instant::now() >= deadline {
        return Ok(BackgroundProgress {
            completed: 0,
            retryable: false,
        });
    }
    let mut events = command.events().to_vec();
    events.extend(artifacts.into_iter().map(|artifact| {
        evertrace_store::JournalEventDraft::runtime(
            occurred_at_us,
            runtime.effective_config_hash,
            "tool_request_v1",
            evertrace_store::JournalPayload::WorkArtifactRecorded(Box::new(artifact)),
        )
    }));
    for event in &mut events {
        event.causation_id = cause.map(|id| id.to_string());
    }
    let command = evertrace_store::JournalCommand::new(command.command_id(), events)
        .map_err(|_| Error::Store)?;
    match writer
        .commit_if_frontier(command, occurred_at_us, current.frontier())
        .await
    {
        Ok(_) => {
            return Ok(BackgroundProgress {
                completed: 1,
                retryable: true,
            });
        }
        Err(crate::WriterActorError::StaleFrontier { .. }) => {
            return Ok(BackgroundProgress {
                completed: 0,
                retryable: true,
            });
        }
        Err(_) => return Err(Error::Writer),
    }
}

pub fn capture_summary(
    receipts: &[CaptureReceipt],
) -> Result<CaptureSummary, evertrace_domain::work::WorkError> {
    CaptureSummary::from_receipts(receipts)
}
