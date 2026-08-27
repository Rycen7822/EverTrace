use evertrace_store::{
    CommitOutcome, JournalCommand, JournalWriter, ProjectionSnapshot,
    ReconciliationArtifactDescriptor, ReconciliationArtifactFrontier, ReconciliationFrontier,
    StoreError,
};
use std::path::Path;
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot},
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
}

impl WriterHandle {
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
    let (sender, receiver) = mpsc::channel(capacity);
    let task = tokio::spawn(run_writer(writer, receiver));
    Ok((WriterHandle { sender }, task))
}

async fn run_writer(
    mut writer: JournalWriter,
    mut receiver: mpsc::Receiver<WriterRequest>,
) -> Result<(), WriterActorError> {
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
            WriterRequest::Project { reply } => {
                let result = writer.project().await.map_err(map_store_error);
                let fatal = result.is_err();
                let _ = reply.send(result);
                if fatal {
                    return Err(WriterActorError::Store);
                }
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
}
