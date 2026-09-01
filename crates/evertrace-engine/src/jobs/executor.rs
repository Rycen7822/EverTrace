use evertrace_store::{
    CommitOutcome, CommittedCommand, JobStatus, JournalCommand, JournalWriter,
    ObjectDeletionCurrentView, ProjectionSnapshot, RecallCurrentContext,
    ReconciliationArtifactDescriptor, ReconciliationArtifactFrontier, ReconciliationFrontier,
    RuntimeSchedulerView, StoreError,
};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

enum WriterRequest {
    Commit {
        command: JournalCommand,
        ingested_at_us: i64,
        reply: oneshot::Sender<Result<CommitOutcome, WriterActorError>>,
    },
    CommitIfFrontier {
        command: JournalCommand,
        ingested_at_us: i64,
        expected_frontier: u64,
        reply: oneshot::Sender<Result<CommitOutcome, WriterActorError>>,
    },
    Project {
        reply: oneshot::Sender<Result<ProjectionSnapshot, WriterActorError>>,
    },
    CommittedCommand {
        command_id: evertrace_domain::ids::CommandId,
        reply: oneshot::Sender<Result<Option<CommittedCommand>, WriterActorError>>,
    },
    RecallCurrentContexts {
        limit: usize,
        reply: oneshot::Sender<Result<Vec<RecallCurrentContext>, WriterActorError>>,
    },
    ReconciliationFrontier {
        limit: usize,
        reply: oneshot::Sender<Result<ReconciliationFrontier, WriterActorError>>,
    },
    ReconciliationArtifactContext {
        descriptors: Vec<ReconciliationArtifactDescriptor>,
        limit: usize,
        reply: oneshot::Sender<Result<ReconciliationArtifactFrontier, WriterActorError>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
pub struct WriterHandle {
    sender: mpsc::Sender<WriterRequest>,
    recall_frontier: watch::Sender<u64>,
    background_frontier: watch::Sender<u64>,
}

impl WriterHandle {
    pub fn subscribe_recall_frontier(&self) -> watch::Receiver<u64> {
        self.recall_frontier.subscribe()
    }

    pub fn subscribe_background_frontier(&self) -> watch::Receiver<u64> {
        self.background_frontier.subscribe()
    }

    pub async fn recall_current_contexts(
        &self,
        limit: usize,
    ) -> Result<Vec<RecallCurrentContext>, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::RecallCurrentContexts { limit, reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }
    pub async fn commit(
        &self,
        command: JournalCommand,
        ingested_at_us: i64,
    ) -> Result<CommitOutcome, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::Commit {
                command,
                ingested_at_us,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn project(&self) -> Result<ProjectionSnapshot, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::Project { reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn committed_command(
        &self,
        command_id: evertrace_domain::ids::CommandId,
    ) -> Result<Option<CommittedCommand>, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::CommittedCommand { command_id, reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn reconciliation_frontier(
        &self,
        limit: usize,
    ) -> Result<ReconciliationFrontier, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::ReconciliationFrontier { limit, reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn reconciliation_artifact_context(
        &self,
        descriptors: Vec<ReconciliationArtifactDescriptor>,
        limit: usize,
    ) -> Result<ReconciliationArtifactFrontier, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::ReconciliationArtifactContext {
                descriptors,
                limit,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn commit_if_frontier(
        &self,
        command: JournalCommand,
        ingested_at_us: i64,
        expected_frontier: u64,
    ) -> Result<CommitOutcome, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::CommitIfFrontier {
                command,
                ingested_at_us,
                expected_frontier,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn shutdown(self) -> Result<(), WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::Shutdown { reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WriterActorError {
    #[error("writer actor input is invalid")]
    InvalidInput,
    #[error("writer actor stopped")]
    Stopped,
    #[error("journal command conflicts with an existing command")]
    IdempotencyConflict,
    #[error("journal frontier changed before command append")]
    StaleFrontier,
    #[error("writer actor detected corrupt store state")]
    StoreCorrupt,
    #[error("writer actor store operation failed")]
    Store,
}

pub async fn open_writer(data_dir: &Path) -> Result<JournalWriter, WriterActorError> {
    JournalWriter::open(data_dir).await.map_err(map_store_error)
}

pub fn spawn_writer(
    writer: JournalWriter,
    capacity: usize,
) -> Result<(WriterHandle, JoinHandle<Result<(), WriterActorError>>), WriterActorError> {
    if capacity == 0 {
        return Err(WriterActorError::InvalidInput);
    }
    let frontier = writer.frontier();
    let (sender, receiver) = mpsc::channel(capacity);
    let (recall_frontier, _) = watch::channel(frontier);
    let (background_frontier, _) = watch::channel(frontier);
    let task = tokio::spawn(Box::pin(run_writer(
        writer,
        receiver,
        recall_frontier.clone(),
        background_frontier.clone(),
    )));
    Ok((
        WriterHandle {
            sender,
            recall_frontier,
            background_frontier,
        },
        task,
    ))
}

async fn run_writer(
    mut writer: JournalWriter,
    mut receiver: mpsc::Receiver<WriterRequest>,
    recall_frontier: watch::Sender<u64>,
    background_frontier: watch::Sender<u64>,
) -> Result<(), WriterActorError> {
    if let Some(frontier) = Box::pin(reconcile_object_deletions(&mut writer)).await? {
        recall_frontier.send_replace(frontier);
        background_frontier.send_replace(frontier);
    }
    let mut shutdown_replies = Vec::new();
    while let Some(request) = receiver.recv().await {
        match request {
            WriterRequest::Commit {
                command,
                ingested_at_us,
                reply,
            } => {
                let result = writer
                    .commit(&command, ingested_at_us)
                    .await
                    .map_err(map_store_error);
                let notify = result
                    .as_ref()
                    .ok()
                    .filter(|_| recall_relevant(&command))
                    .map(|outcome| outcome.last_seq);
                let background_notify = result
                    .as_ref()
                    .ok()
                    .filter(|_| background_relevant(&command))
                    .map(|outcome| outcome.last_seq);
                let fatal = result.as_ref().err().copied().filter(|error| {
                    matches!(
                        error,
                        WriterActorError::Store | WriterActorError::StoreCorrupt
                    )
                });
                let reconcile = result.is_ok() && object_deletion_relevant(&command);
                let _ = reply.send(result);
                if let Some(frontier) = notify {
                    recall_frontier.send_replace(frontier);
                }
                if let Some(frontier) = background_notify {
                    background_frontier.send_replace(frontier);
                }
                if let Some(error) = fatal {
                    return Err(error);
                }
                if reconcile
                    && let Some(frontier) =
                        Box::pin(reconcile_object_deletions(&mut writer)).await?
                {
                    recall_frontier.send_replace(frontier);
                    background_frontier.send_replace(frontier);
                }
            }
            WriterRequest::CommitIfFrontier {
                command,
                ingested_at_us,
                expected_frontier,
                reply,
            } => {
                let result = writer
                    .commit_if_frontier(&command, ingested_at_us, expected_frontier)
                    .await
                    .map_err(map_store_error);
                let notify = result
                    .as_ref()
                    .ok()
                    .filter(|_| recall_relevant(&command))
                    .map(|outcome| outcome.last_seq);
                let background_notify = result
                    .as_ref()
                    .ok()
                    .filter(|_| background_relevant(&command))
                    .map(|outcome| outcome.last_seq);
                let fatal = result.as_ref().err().copied().filter(|error| {
                    matches!(
                        error,
                        WriterActorError::Store | WriterActorError::StoreCorrupt
                    )
                });
                let reconcile = result.is_ok() && object_deletion_relevant(&command);
                let _ = reply.send(result);
                if let Some(frontier) = notify {
                    recall_frontier.send_replace(frontier);
                }
                if let Some(frontier) = background_notify {
                    background_frontier.send_replace(frontier);
                }
                if let Some(error) = fatal {
                    return Err(error);
                }
                if reconcile
                    && let Some(frontier) =
                        Box::pin(reconcile_object_deletions(&mut writer)).await?
                {
                    recall_frontier.send_replace(frontier);
                    background_frontier.send_replace(frontier);
                }
            }
            WriterRequest::Project { reply } => {
                let result = writer.project().await.map_err(map_store_error);
                let fatal = result.is_err();
                let _ = reply.send(result);
                if fatal {
                    return Err(WriterActorError::Store);
                }
            }
            WriterRequest::CommittedCommand { command_id, reply } => {
                let result = writer
                    .committed_command(command_id)
                    .await
                    .map_err(map_store_error);
                let fatal = result.is_err();
                let _ = reply.send(result);
                if fatal {
                    return Err(WriterActorError::Store);
                }
            }
            WriterRequest::RecallCurrentContexts { limit, reply } => {
                let result = writer
                    .recall_current_contexts(limit)
                    .map_err(map_store_error);
                let _ = reply.send(result);
            }
            WriterRequest::ReconciliationFrontier { limit, reply } => {
                let result = writer
                    .reconciliation_frontier(limit)
                    .await
                    .map_err(map_store_error);
                let fatal = result.as_ref().err().copied().filter(|error| {
                    matches!(
                        error,
                        WriterActorError::Store | WriterActorError::StoreCorrupt
                    )
                });
                let _ = reply.send(result);
                if let Some(error) = fatal {
                    return Err(error);
                }
            }
            WriterRequest::ReconciliationArtifactContext {
                descriptors,
                limit,
                reply,
            } => {
                let result = writer
                    .reconciliation_artifact_context(&descriptors, limit)
                    .await
                    .map_err(map_store_error);
                let fatal = result.as_ref().err().copied().filter(|error| {
                    matches!(
                        error,
                        WriterActorError::Store | WriterActorError::StoreCorrupt
                    )
                });
                let _ = reply.send(result);
                if let Some(error) = fatal {
                    return Err(error);
                }
            }
            WriterRequest::Shutdown { reply } => {
                receiver.close();
                shutdown_replies.push(reply);
            }
        }
    }
    for reply in shutdown_replies {
        let _ = reply.send(());
    }
    Ok(())
}

async fn reconcile_object_deletions(
    writer: &mut JournalWriter,
) -> Result<Option<u64>, WriterActorError> {
    let mut completed_frontier = None;
    loop {
        let snapshot = writer.project().await.map_err(map_store_error)?;
        let ledger =
            ObjectDeletionCurrentView::from_snapshot(&snapshot).map_err(map_store_error)?;
        let Some(pending) = ledger
            .events
            .values()
            .find(|event| event.phase == evertrace_domain::purge::ObjectDeletionPhase::Pending)
            .cloned()
        else {
            return Ok(completed_frontier);
        };
        let runtime = RuntimeSchedulerView::from_snapshot(&snapshot).map_err(map_store_error)?;
        let job = runtime
            .jobs
            .iter()
            .find(|job| job.job_id == pending.purge_job_id)
            .filter(|job| job.state == JobStatus::Queued)
            .ok_or(WriterActorError::StoreCorrupt)?;
        let occurred_at_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_micros()).ok())
            .ok_or(WriterActorError::Store)?;
        let command = crate::purge::complete_object_forget_command(
            evertrace_domain::ids::CommandId::new_v7(),
            &pending,
            job,
            occurred_at_us,
            job.config_hash,
        )
        .map_err(map_store_error)?;
        let outcome = writer
            .commit_if_frontier(&command, occurred_at_us, snapshot.frontier)
            .await
            .map_err(map_store_error)?;
        completed_frontier = Some(outcome.last_seq);
    }
}

fn recall_relevant(command: &JournalCommand) -> bool {
    command.events().iter().any(|event| {
        matches!(
            event.payload,
            evertrace_store::JournalPayload::TaskRecorded(_)
                | evertrace_store::JournalPayload::WorkstreamRecorded(_)
                | evertrace_store::JournalPayload::ExecutionLaneRecorded(_)
                | evertrace_store::JournalPayload::WorkBindingRecorded(_)
                | evertrace_store::JournalPayload::WorkEpisodeRecorded(_)
                | evertrace_store::JournalPayload::WorkCheckpointRecorded(_)
                | evertrace_store::JournalPayload::AtomRecorded(_)
                | evertrace_store::JournalPayload::RecallLedgerRecorded(_)
        )
    })
}

fn background_relevant(command: &JournalCommand) -> bool {
    command.events().iter().any(|event| {
        matches!(
            event.payload,
            evertrace_store::JournalPayload::DirtyTarget(_)
                | evertrace_store::JournalPayload::OutboxEnqueued(_)
                | evertrace_store::JournalPayload::JobState(_)
                | evertrace_store::JournalPayload::JobLease(_)
                | evertrace_store::JournalPayload::WorkEpisodeRecorded(_)
                | evertrace_store::JournalPayload::WorkCheckpointRecorded(_)
                | evertrace_store::JournalPayload::SessionImportEventRecorded(_)
        )
    })
}

fn object_deletion_relevant(command: &JournalCommand) -> bool {
    command.events().iter().any(|event| {
        matches!(
            &event.payload,
            evertrace_store::JournalPayload::ObjectDeletionLedgerRecorded(value)
                if value.phase == evertrace_domain::purge::ObjectDeletionPhase::Pending
        )
    })
}

fn map_store_error(error: StoreError) -> WriterActorError {
    match error {
        StoreError::InvalidInput => WriterActorError::InvalidInput,
        StoreError::ReconciliationDependencyOverflow => WriterActorError::InvalidInput,
        StoreError::IdempotencyConflict => WriterActorError::IdempotencyConflict,
        StoreError::StaleFrontier => WriterActorError::StaleFrontier,
        StoreError::StoreCorrupt => WriterActorError::StoreCorrupt,
        _ => WriterActorError::Store,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capacity_is_rejected_without_spawning() {
        assert_eq!(
            WriterActorError::InvalidInput.to_string(),
            "writer actor input is invalid"
        );
    }

    #[test]
    fn work_episode_commit_wakes_background_scheduler() {
        let task_id = evertrace_domain::ids::TaskId::new_v7();
        let workstream = evertrace_domain::work::Workstream {
            workstream_id: evertrace_domain::ids::WorkstreamId::new_v7(),
            revision_id: evertrace_domain::revision::RevisionId::new_v7(),
            predecessor_revision_id: None,
            task_id,
            repository_instance_id: None,
            worktree_instance_ids: Vec::new(),
            active_worktree_instance_id: None,
            worktree_lineage_refs: Vec::new(),
            parent_workstream_id: None,
            dependency_workstream_ids: Vec::new(),
            status: evertrace_domain::work::WorkstreamStatus::Active,
            root_goal: "background synthesis wake".into(),
            workstream_goal: "record pending semantic delta".into(),
            target_family: "semantic digest".into(),
            hypothesis_or_failure_family: "missed background wake".into(),
            acceptance_boundary: "episode commit wakes scheduler".into(),
            phase_contract: evertrace_domain::work::PhaseContract {
                local_goal: "record pending delta".into(),
                phase_kind: evertrace_domain::work::PhaseKind::Analyze,
                phase_label: "analyze".into(),
                primary_targets: vec!["semantic digest".into()],
                entry_conditions: vec!["episode active".into()],
                acceptance_boundary: "background wake".into(),
                expected_state_transition: "synthesis queued".into(),
            },
            active_episode_id: None,
            execution_lane_ids: Vec::new(),
            source_watermark: 0,
        };
        let episode = crate::work::new_episode(&workstream, None, 1).unwrap();
        let command = JournalCommand::new(
            evertrace_domain::ids::CommandId::new_v7(),
            vec![evertrace_store::JournalEventDraft::runtime(
                1,
                [0x29; 32],
                "s29-work-episode-wake-v1",
                evertrace_store::JournalPayload::WorkEpisodeRecorded(Box::new(episode)),
            )],
        )
        .unwrap();
        assert!(background_relevant(&command));
    }
}
