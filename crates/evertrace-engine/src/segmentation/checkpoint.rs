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
    use crate::maintenance::{BackgroundProgress, BackgroundSchedulerError as Error};
    use evertrace_capture::{CasDigest, CasStore, checkpoint_source};
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
        let protected = tokio::task::spawn_blocking(move || {
            CasStore::open_existing(cas_dir)?.read_bounded(&digest, 8192, 8192)
        })
        .await
        .map_err(|_| Error::Store)?
        .map_err(|_| Error::Store)?
        .0;
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
        if selected.state.frontier() != current.frontier() {
            return Ok(BackgroundProgress {
                completed: 0,
                retryable: true,
            });
        }
        selected.source_refs.push(observation.source_observation_id);
        selected.source_refs.sort();
        selected.source_refs.dedup();
        let Some(deadline) =
            super::production::readable_context(writer, current, &selected, runtime).await?
        else {
            continue;
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
        let CheckpointResolution::Checkpoint(checkpoint) = build_checkpoint(
            episode,
            &attempts,
            selected.snapshot.as_ref(),
            request.reason(),
            None,
        )
        .map_err(|_| Error::Store)?
        else {
            continue;
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
            algorithm_revision: "host-checkpoint-v1",
        };
        let Some(command) =
            crate::work::episode::save_checkpoint(context, episode, *checkpoint, None)
                .map_err(|_| Error::Store)?
        else {
            continue;
        };
        if std::time::Instant::now() >= deadline {
            continue;
        }
        let mut events = command.events().to_vec();
        for event in &mut events {
            event.causation_id = Some(observation.source_observation_id.to_string());
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
    Ok(idle)
}

pub fn capture_summary(
    receipts: &[CaptureReceipt],
) -> Result<CaptureSummary, evertrace_domain::work::WorkError> {
    CaptureSummary::from_receipts(receipts)
}
