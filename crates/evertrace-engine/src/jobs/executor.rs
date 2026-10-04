use evertrace_store::{
    BackupError, BackupSummary, CommitOutcome, CommittedCommand, DurableJob, JobStatus,
    JournalCommand, JournalWriter, ObjectDeletionCurrentView, ProjectionSnapshot,
    RecallCurrentContext, ReconciliationArtifactDescriptor, ReconciliationArtifactFrontier,
    ReconciliationFrontier, RuntimeSchedulerView, ScopePurgeCurrentView,
    SessionCatalogCurrentContext, SessionImportContext, SessionImportPrefixPage,
    SessionImportPrefixRequest, SessionImportSelection, StoreError,
};
use std::{
    collections::BTreeSet,
    future::Future,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};

enum WriterRequest {
    ConfirmProcedureReturn {
        original_request: evertrace_domain::ids::RequestId,
        acknowledgement: evertrace_domain::ids::RequestId,
        returned: Vec<evertrace_domain::revision::RevisionId>,
        effective_config_hash: [u8; 32],
        stable_min_outcome_supported: u32,
        reply: oneshot::Sender<Result<(), WriterActorError>>,
    },
    ReadDiagnostics {
        reply: oneshot::Sender<evertrace_store::NativeDiagnostics>,
    },
    QueuedGcJobs {
        reply: oneshot::Sender<Vec<DurableJob>>,
    },
    MarkGc {
        runtime: Box<evertrace_capture::RuntimeSnapshot>,
        cursor: evertrace_capture::cas::CasGcCursor,
        reply: oneshot::Sender<Result<evertrace_store::optimize::GcScanPage, WriterActorError>>,
    },
    SweepGc {
        runtime: Box<evertrace_capture::RuntimeSnapshot>,
        job_id: evertrace_domain::ids::JobId,
        round: evertrace_store::optimize::GcRound,
        reply: oneshot::Sender<Result<evertrace_store::optimize::GcReport, WriterActorError>>,
    },
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
    ScopeCurrent {
        request: evertrace_store::ScopeCurrentRequest,
        reply: oneshot::Sender<Result<evertrace_store::ScopeCurrentContext, WriterActorError>>,
    },
    NormalSearchCurrent {
        request: evertrace_store::ScopeCurrentRequest,
        reply: oneshot::Sender<Result<evertrace_store::NormalSearchReadContext, WriterActorError>>,
    },
    NormalSearchCandidates {
        request: evertrace_store::ScopeCurrentRequest,
        candidate: evertrace_store::NormalSearchCandidateRequest,
        reply: oneshot::Sender<Result<evertrace_store::NormalSearchReadContext, WriterActorError>>,
    },
    PassiveSourceCurrent {
        selection: evertrace_store::PassiveSourceSelection,
        reply:
            oneshot::Sender<Result<evertrace_store::PassiveSourceCurrentContext, WriterActorError>>,
    },
    InboxCurrent {
        after: Option<String>,
        limit: usize,
        reply: oneshot::Sender<
            Result<evertrace_store::projections::InboxCurrentContext, WriterActorError>,
        >,
    },
    MemoriesCurrent {
        after: Option<String>,
        limit: usize,
        reply: oneshot::Sender<Result<evertrace_store::MemoriesCurrentContext, WriterActorError>>,
    },
    CaptureCurrent {
        after: Option<String>,
        exact: Option<String>,
        limit: usize,
        reply: oneshot::Sender<Result<evertrace_store::CaptureCurrentContext, WriterActorError>>,
    },
    Project {
        indexes: bool,
        reply: oneshot::Sender<Result<ProjectionSnapshot, WriterActorError>>,
    },
    SyncFrontier {
        indexes: bool,
        reply: oneshot::Sender<Result<u64, WriterActorError>>,
    },
    CommittedCommand {
        command_id: evertrace_domain::ids::CommandId,
        reply: oneshot::Sender<Result<Option<CommittedCommand>, WriterActorError>>,
    },
    ProjectAtFrontier {
        frontier: u64,
        reply: oneshot::Sender<Result<ProjectionSnapshot, WriterActorError>>,
    },
    CommittedCommands {
        command_ids: Vec<evertrace_domain::ids::CommandId>,
        reply: oneshot::Sender<
            Result<
                std::collections::BTreeMap<evertrace_domain::ids::CommandId, CommittedCommand>,
                WriterActorError,
            >,
        >,
    },
    RecallCurrentContexts {
        limit: usize,
        reply: oneshot::Sender<Result<Vec<RecallCurrentContext>, WriterActorError>>,
    },
    RepositoryReadContext {
        ids: std::collections::BTreeSet<evertrace_domain::ids::RepositoryId>,
        reply: oneshot::Sender<Result<evertrace_store::RepositoryReadContext, WriterActorError>>,
    },
    InventoryContext {
        context: evertrace_domain::inventory::InventoryContext,
        job_id: Option<evertrace_domain::ids::JobId>,
        reply: oneshot::Sender<Result<evertrace_store::InventoryCurrentContext, WriterActorError>>,
    },
    SessionImportContext {
        source: String,
        repository_locator: Option<(evertrace_domain::repository::FilesystemIdentity, String)>,
        reply: oneshot::Sender<Result<Option<SessionImportContext>, WriterActorError>>,
    },
    SessionCatalogCurrent {
        reply: oneshot::Sender<Result<SessionCatalogCurrentContext, WriterActorError>>,
    },
    SessionImportContexts {
        after: Option<String>,
        limit: usize,
        reply: oneshot::Sender<Result<SessionImportSelection, WriterActorError>>,
    },
    SessionImportPrefixPage {
        request: SessionImportPrefixRequest,
        reply: oneshot::Sender<Result<SessionImportPrefixPage, WriterActorError>>,
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
    CreateBackup {
        backup_job_id: evertrace_domain::ids::JobId,
        config_path: PathBuf,
        runtime: Box<evertrace_capture::RuntimeSnapshot>,
        reply: oneshot::Sender<Result<Result<BackupSummary, BackupError>, WriterActorError>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
pub struct WriterHandle {
    sender: mpsc::Sender<WriterRequest>,
    readers: evertrace_store::StoreReadHandle,
    recall_frontier: watch::Sender<u64>,
    background_frontier: watch::Sender<u64>,
}

impl WriterHandle {
    pub(crate) async fn llm_daily_usage(
        &self,
        at: i64,
        frontier: u64,
        jobs: &[DurableJob],
    ) -> Result<evertrace_domain::semantic::DerivationQuotaUsage, WriterActorError> {
        let mut usage = super::synthesis::DailyLlmUsage::new(jobs, at);
        let mut after = 0;
        let mut bound = None;
        loop {
            let (upper, rows) = self
                .readers
                .llm_budget_page(usage.day_start_us(), after, frontier, bound)
                .await
                .map_err(map_store_error)?;
            // Every later page reuses the frontier fixed by the first
            // consistent read transaction.
            bound = Some(upper);
            let Some(last) = rows.last() else {
                break;
            };
            after = last.seq;
            usage.extend(&rows).map_err(map_store_error)?;
        }
        Ok(usage.finish())
    }
    pub async fn read_diagnostics(
        &self,
    ) -> Result<evertrace_store::NativeDiagnostics, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::ReadDiagnostics { reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)
    }

    pub async fn mark_gc(
        &self,
        runtime: evertrace_capture::RuntimeSnapshot,
        shard: u8,
    ) -> Result<evertrace_store::optimize::GcRound, WriterActorError> {
        Ok(self
            .mark_gc_page(runtime, evertrace_capture::cas::CasGcCursor::new(shard))
            .await?
            .round)
    }

    pub async fn mark_gc_page(
        &self,
        runtime: evertrace_capture::RuntimeSnapshot,
        cursor: evertrace_capture::cas::CasGcCursor,
    ) -> Result<evertrace_store::optimize::GcScanPage, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::MarkGc {
                runtime: Box::new(runtime),
                cursor,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn sweep_gc(
        &self,
        runtime: evertrace_capture::RuntimeSnapshot,
        job_id: evertrace_domain::ids::JobId,
        round: evertrace_store::optimize::GcRound,
    ) -> Result<evertrace_store::optimize::GcReport, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::SweepGc {
                runtime: Box::new(runtime),
                job_id,
                round,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }
    /// The writer's shared read handle, so search snapshots participate in the
    /// same read fence and backup quiesce as every other reader.
    pub fn read_handle(&self) -> evertrace_store::StoreReadHandle {
        self.readers.clone()
    }

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

    pub async fn session_import_context(
        &self,
        source: &str,
    ) -> Result<Option<SessionImportContext>, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::SessionImportContext {
                source: source.to_owned(),
                repository_locator: None,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn session_catalog_current_context(
        &self,
    ) -> Result<SessionCatalogCurrentContext, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::SessionCatalogCurrent { reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn repository_read_context(
        &self,
        ids: std::collections::BTreeSet<evertrace_domain::ids::RepositoryId>,
    ) -> Result<evertrace_store::RepositoryReadContext, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::RepositoryReadContext { ids, reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn inventory_context(
        &self,
        context: &evertrace_domain::inventory::InventoryContext,
        job_id: Option<evertrace_domain::ids::JobId>,
    ) -> Result<evertrace_store::InventoryCurrentContext, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::InventoryContext {
                context: context.clone(),
                job_id,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn session_import_context_with_repository(
        &self,
        source: &str,
        identity: evertrace_domain::repository::FilesystemIdentity,
        common_dir: &str,
    ) -> Result<Option<SessionImportContext>, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::SessionImportContext {
                source: source.to_owned(),
                repository_locator: Some((identity, common_dir.to_owned())),
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn session_import_contexts(
        &self,
        after: Option<String>,
        limit: usize,
    ) -> Result<SessionImportSelection, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::SessionImportContexts {
                after,
                limit,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn session_import_prefix_page(
        &self,
        request: SessionImportPrefixRequest,
    ) -> Result<SessionImportPrefixPage, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::SessionImportPrefixPage { request, reply })
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

    pub(crate) async fn confirm_procedure_return(
        &self,
        original_request: evertrace_domain::ids::RequestId,
        acknowledgement: evertrace_domain::ids::RequestId,
        returned: Vec<evertrace_domain::revision::RevisionId>,
        effective_config_hash: [u8; 32],
        stable_min_outcome_supported: u32,
    ) -> Result<(), WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::ConfirmProcedureReturn {
                original_request,
                acknowledgement,
                returned,
                effective_config_hash,
                stable_min_outcome_supported,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub(crate) async fn queued_gc_jobs(&self) -> Result<Vec<DurableJob>, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::QueuedGcJobs { reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)
    }

    pub(crate) async fn scope_current_context(
        &self,
        request: evertrace_store::ScopeCurrentRequest,
    ) -> Result<evertrace_store::ScopeCurrentContext, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::ScopeCurrent { request, reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub(crate) async fn normal_search_current_context(
        &self,
        request: evertrace_store::ScopeCurrentRequest,
    ) -> Result<evertrace_store::NormalSearchReadContext, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::NormalSearchCurrent { request, reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub(crate) async fn normal_search_candidate_context(
        &self,
        request: evertrace_store::ScopeCurrentRequest,
        candidate: evertrace_store::NormalSearchCandidateRequest,
    ) -> Result<evertrace_store::NormalSearchReadContext, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::NormalSearchCandidates {
                request,
                candidate,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub(crate) async fn passive_source_current_context(
        &self,
        selection: evertrace_store::PassiveSourceSelection,
    ) -> Result<evertrace_store::PassiveSourceCurrentContext, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::PassiveSourceCurrent { selection, reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub(crate) async fn inbox_current_context(
        &self,
        after: Option<String>,
        limit: usize,
    ) -> Result<evertrace_store::projections::InboxCurrentContext, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::InboxCurrent {
                after,
                limit,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub(crate) async fn memories_current_context(
        &self,
        after: Option<String>,
        limit: usize,
    ) -> Result<evertrace_store::MemoriesCurrentContext, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::MemoriesCurrent {
                after,
                limit,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub(crate) async fn capture_current_context(
        &self,
        after: Option<String>,
        exact: Option<String>,
        limit: usize,
    ) -> Result<evertrace_store::CaptureCurrentContext, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::CaptureCurrent {
                after,
                exact,
                limit,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub(crate) async fn project_objects(&self) -> Result<ProjectionSnapshot, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::Project {
                indexes: false,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    pub async fn project(&self) -> Result<ProjectionSnapshot, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::Project {
                indexes: true,
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    /// Complete the projection barrier without transferring a full snapshot.
    pub async fn sync_frontier(&self) -> Result<u64, WriterActorError> {
        self.sync_projection_frontier(true).await
    }

    pub(crate) async fn sync_objects_frontier(&self) -> Result<u64, WriterActorError> {
        self.sync_projection_frontier(false).await
    }

    async fn sync_projection_frontier(&self, indexes: bool) -> Result<u64, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::SyncFrontier { indexes, reply })
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

    pub async fn committed_commands(
        &self,
        command_ids: Vec<evertrace_domain::ids::CommandId>,
    ) -> Result<
        std::collections::BTreeMap<evertrace_domain::ids::CommandId, CommittedCommand>,
        WriterActorError,
    > {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::CommittedCommands { command_ids, reply })
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

    pub async fn create_backup(
        &self,
        backup_job_id: evertrace_domain::ids::JobId,
        config_path: PathBuf,
        runtime: evertrace_capture::RuntimeSnapshot,
    ) -> Result<Result<BackupSummary, BackupError>, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::CreateBackup {
                backup_job_id,
                config_path,
                runtime: Box::new(runtime),
                reply,
            })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
    }

    async fn project_at_frontier(
        &self,
        frontier: u64,
    ) -> Result<ProjectionSnapshot, WriterActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterRequest::ProjectAtFrontier { frontier, reply })
            .await
            .map_err(|_| WriterActorError::Stopped)?;
        response.await.map_err(|_| WriterActorError::Stopped)?
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
) -> Result<(WriterHandle, WriterTask), WriterActorError> {
    if capacity == 0 {
        return Err(WriterActorError::InvalidInput);
    }
    let frontier = writer.frontier();
    let readers = writer.read_handle();
    let (sender, receiver) = mpsc::channel(capacity);
    let (recall_frontier, _) = watch::channel(frontier);
    let (background_frontier, _) = watch::channel(frontier);
    // Out-of-band stop, deliberately independent of the bounded request queue:
    // a full queue must never prevent shutdown.
    let (stop, stop_rx) = watch::channel(false);
    let (completion, completed) = oneshot::channel();
    let runtime = tokio::runtime::Handle::current();
    let task_recall = recall_frontier.clone();
    let task_background = background_frontier.clone();
    let join = std::thread::Builder::new()
        .name("evertrace-writer".to_owned())
        .spawn(move || {
            let result = runtime.block_on(run_writer(
                writer,
                receiver,
                stop_rx,
                task_recall,
                task_background,
            ));
            let _ = completion.send(result);
        })
        .map_err(|_| WriterActorError::Store)?;
    Ok((
        WriterHandle {
            sender,
            readers,
            recall_frontier,
            background_frontier,
        },
        WriterTask {
            stop: Some(stop),
            completion: completed,
            join: Some(join),
            finished: false,
            result: None,
        },
    ))
}

pub struct WriterTask {
    stop: Option<watch::Sender<bool>>,
    completion: oneshot::Receiver<Result<(), WriterActorError>>,
    join: Option<std::thread::JoinHandle<()>>,
    finished: bool,
    result: Option<Result<(), WriterActorError>>,
}

impl WriterTask {
    fn signal_stop(&mut self) {
        if let Some(stop) = self.stop.as_ref() {
            let _ = stop.send(true);
        }
    }

    /// Actively signal stop, wait for the actor to finish the executing
    /// command and drain every accepted request, then join the writer thread
    /// exactly once through a bounded blocking-pool task. Never joins on the
    /// async executor thread.
    pub async fn shutdown_and_join(mut self) -> Result<(), WriterActorError> {
        self.signal_stop();
        let result = match self.result.take() {
            Some(result) => result,
            None => (&mut self.completion)
                .await
                .unwrap_or(Err(WriterActorError::Stopped)),
        };
        let joined = if let Some(join) = self.join.take() {
            tokio::task::spawn_blocking(move || join.join())
                .await
                .map_err(|_| WriterActorError::Stopped)
                .and_then(|result| result.map_err(|_| WriterActorError::Stopped))
        } else {
            Ok(())
        };
        self.finished = true;
        result.and(joined)
    }
}

impl Future for WriterTask {
    type Output = Result<Result<(), WriterActorError>, WriterActorError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if !self.finished {
            match std::pin::Pin::new(&mut self.completion).poll(context) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(result) => {
                    self.finished = true;
                    self.result = Some(match &result {
                        Ok(result) => *result,
                        Err(_) => Err(WriterActorError::Stopped),
                    });
                    // The actor only sends completion after the writer and its
                    // sibling lock are dropped; the reaping join is deferred to
                    // `shutdown_and_join` or the Drop fallback.
                    return std::task::Poll::Ready(match result {
                        Ok(result) => Ok(result),
                        Err(_) => Err(WriterActorError::Stopped),
                    });
                }
            }
        }
        std::task::Poll::Ready(Err(WriterActorError::Stopped))
    }
}

impl Drop for WriterTask {
    fn drop(&mut self) {
        self.signal_stop();
        // A cancelled owner must not block the executor. Detaching permits
        // the signalled thread to exit; normal teardown uses the explicit join.
        drop(self.join.take());
    }
}

async fn run_writer(
    writer: JournalWriter,
    mut receiver: mpsc::Receiver<WriterRequest>,
    mut stop: watch::Receiver<bool>,
    recall_frontier: watch::Sender<u64>,
    background_frontier: watch::Sender<u64>,
) -> Result<(), WriterActorError> {
    let mut writer = Some(writer);
    let mut shutdown_replies = Vec::new();
    let result = async {
        if let Some(frontier) = Box::pin(reconcile_object_deletions(
            writer.as_mut().ok_or(WriterActorError::Stopped)?,
        ))
        .await?
        {
            recall_frontier.send_replace(frontier);
            background_frontier.send_replace(frontier);
        }
        let mut stopped = false;
        loop {
            let request = tokio::select! {
                request = receiver.recv() => {
                    let Some(request) = request else { break };
                    request
                }
                changed = stop.changed(), if !stopped => {
                    // Out-of-band stop: refuse new submissions and keep
                    // draining everything already accepted. The executing
                    // command always finishes first because its handler runs
                    // to completion inside this loop.
                    let _ = changed;
                    stopped = true;
                    receiver.close();
                    continue;
                }
            };
            match request {
                WriterRequest::ConfirmProcedureReturn {
                    original_request,
                    acknowledgement,
                    returned,
                    effective_config_hash,
                    stable_min_outcome_supported,
                    reply,
                } => {
                    // Keep the current usage read, compilation and append in one
                    // writer turn: background commits cannot stale this receipt.
                    let result = confirm_procedure_return(
                        writer.as_mut().ok_or(WriterActorError::Stopped)?,
                        original_request,
                        acknowledgement,
                        &returned,
                        effective_config_hash,
                        stable_min_outcome_supported,
                    )
                    .await;
                    let fatal = result.as_ref().err().copied().filter(|error| {
                        matches!(
                            error,
                            WriterActorError::Store | WriterActorError::StoreCorrupt
                        )
                    });
                    if let Ok(Some((command, frontier))) = &result {
                        if recall_relevant(command) {
                            recall_frontier.send_replace(*frontier);
                        }
                        if background_relevant(command) {
                            background_frontier.send_replace(*frontier);
                        }
                    }
                    let _ = reply.send(result.map(|_| ()));
                    if let Some(error) = fatal {
                        return Err(error);
                    }
                }
                WriterRequest::Commit {
                    command,
                    ingested_at_us,
                    reply,
                } => {
                    let result = writer
                        .as_mut()
                        .ok_or(WriterActorError::Stopped)?
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
                        && let Some(frontier) = Box::pin(reconcile_object_deletions(
                            writer.as_mut().ok_or(WriterActorError::Stopped)?,
                        ))
                        .await?
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
                        .as_mut()
                        .ok_or(WriterActorError::Stopped)?
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
                        && let Some(frontier) = Box::pin(reconcile_object_deletions(
                            writer.as_mut().ok_or(WriterActorError::Stopped)?,
                        ))
                        .await?
                    {
                        recall_frontier.send_replace(frontier);
                        background_frontier.send_replace(frontier);
                    }
                }
                WriterRequest::ReadDiagnostics { reply } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .read_diagnostics()
                        .await;
                    let _ = reply.send(result);
                }
                WriterRequest::QueuedGcJobs { reply } => {
                    if !reply.is_closed() {
                        let jobs = writer
                            .as_ref()
                            .ok_or(WriterActorError::Stopped)?
                            .queued_gc_jobs();
                        let _ = reply.send(jobs);
                    }
                }
                WriterRequest::ScopeCurrent { request, reply } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .scope_current_context(&request)
                        .await
                        .map_err(map_store_error);
                    let fatal = result.is_err();
                    let _ = reply.send(result);
                    if fatal {
                        return Err(WriterActorError::Store);
                    }
                }
                WriterRequest::NormalSearchCurrent { request, reply } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .normal_search_current_context(&request)
                        .await
                        .map_err(map_store_error);
                    let fatal = result.is_err();
                    let _ = reply.send(result);
                    if fatal {
                        return Err(WriterActorError::Store);
                    }
                }
                WriterRequest::NormalSearchCandidates {
                    request,
                    candidate,
                    reply,
                } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .normal_search_candidate_context(&request, &candidate)
                        .await
                        .map_err(map_store_error);
                    let fatal = result.is_err();
                    let _ = reply.send(result);
                    if fatal {
                        return Err(WriterActorError::Store);
                    }
                }
                WriterRequest::PassiveSourceCurrent { selection, reply } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .passive_source_current_context(&selection)
                        .await
                        .map_err(map_store_error);
                    let fatal = result.is_err();
                    let _ = reply.send(result);
                    if fatal {
                        return Err(WriterActorError::Store);
                    }
                }
                WriterRequest::CaptureCurrent {
                    after,
                    exact,
                    limit,
                    reply,
                } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .capture_current_context(after.as_deref(), exact.as_deref(), limit)
                        .await
                        .map_err(map_store_error);
                    let fatal = result.is_err();
                    let _ = reply.send(result);
                    if fatal {
                        return Err(WriterActorError::Store);
                    }
                }
                WriterRequest::InboxCurrent {
                    after,
                    limit,
                    reply,
                } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .inbox_current_context(
                            after.as_deref(),
                            limit,
                            crate::procedure::inbox_negative_proof_limit(),
                        )
                        .await
                        .map_err(map_store_error);
                    let fatal = result.is_err();
                    let _ = reply.send(result);
                    if fatal {
                        return Err(WriterActorError::Store);
                    }
                }
                WriterRequest::MemoriesCurrent {
                    after,
                    limit,
                    reply,
                } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .memories_current_context(after.as_deref(), limit)
                        .await
                        .map_err(map_store_error);
                    let fatal = result.is_err();
                    let _ = reply.send(result);
                    if fatal {
                        return Err(WriterActorError::Store);
                    }
                }
                WriterRequest::Project { indexes, reply } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let writer = writer.as_ref().ok_or(WriterActorError::Stopped)?;
                    let result = if indexes {
                        writer.project().await
                    } else {
                        writer.project_objects().await
                    }
                    .map_err(map_store_error);
                    let fatal = result.is_err();
                    let _ = reply.send(result);
                    if fatal {
                        return Err(WriterActorError::Store);
                    }
                }
                WriterRequest::ProjectAtFrontier { frontier, reply } => {
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .projection_worker()
                        .project_at_frontier(frontier)
                        .await
                        .map_err(map_store_error);
                    let _ = reply.send(result);
                }
                WriterRequest::SyncFrontier { indexes, reply } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let writer = writer.as_ref().ok_or(WriterActorError::Stopped)?;
                    let result = if indexes {
                        writer.sync_frontier().await
                    } else {
                        writer.sync_objects_frontier().await
                    }
                    .map_err(map_store_error);
                    let fatal = result.is_err();
                    let _ = reply.send(result);
                    if fatal {
                        return Err(WriterActorError::Store);
                    }
                }
                WriterRequest::CommittedCommand { command_id, reply } => {
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .committed_command(command_id)
                        .await
                        .map_err(map_store_error);
                    let fatal = result.is_err();
                    let _ = reply.send(result);
                    if fatal {
                        return Err(WriterActorError::Store);
                    }
                }
                WriterRequest::CommittedCommands { command_ids, reply } => {
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .committed_commands(&command_ids)
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
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .recall_current_contexts(limit)
                        .map_err(map_store_error);
                    let _ = reply.send(result);
                }
                WriterRequest::SessionImportContext {
                    source,
                    repository_locator,
                    reply,
                } => {
                    let writer = writer.as_ref().ok_or(WriterActorError::Stopped)?;
                    let result = match repository_locator {
                        Some((identity, path)) => {
                            writer.session_import_context_with_repository(&source, identity, &path)
                        }
                        None => writer.session_import_context(&source),
                    }
                    .map_err(map_store_error);
                    let _ = reply.send(result);
                }
                WriterRequest::SessionCatalogCurrent { reply } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .session_catalog_current_context()
                        .await
                        .map_err(map_store_error);
                    let fatal = result.is_err();
                    let _ = reply.send(result);
                    if fatal {
                        return Err(WriterActorError::Store);
                    }
                }
                WriterRequest::RepositoryReadContext { ids, reply } => {
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .repository_read_context(&ids)
                        .map_err(map_store_error);
                    let _ = reply.send(result);
                }
                WriterRequest::InventoryContext {
                    context,
                    job_id,
                    reply,
                } => {
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .inventory_context(&context, job_id)
                        .map_err(map_store_error);
                    let _ = reply.send(result);
                }
                WriterRequest::SessionImportContexts {
                    after,
                    limit,
                    reply,
                } => {
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .session_import_contexts(after.as_deref(), limit)
                        .map_err(map_store_error);
                    let _ = reply.send(result);
                }
                WriterRequest::SessionImportPrefixPage { request, reply } => {
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .session_import_prefix_page(&request)
                        .map_err(map_store_error);
                    let _ = reply.send(result);
                }
                WriterRequest::ReconciliationFrontier { limit, reply } => {
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
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
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
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
                WriterRequest::CreateBackup {
                    backup_job_id,
                    config_path,
                    runtime,
                    reply,
                } => {
                    let result =
                        create_quiesced_backup(&mut writer, backup_job_id, config_path, *runtime)
                            .await;
                    let fatal = result.as_ref().err().copied();
                    let _ = reply.send(result);
                    if let Some(error) = fatal {
                        return Err(error);
                    }
                }
                WriterRequest::Shutdown { reply } => {
                    receiver.close();
                    shutdown_replies.push(reply);
                }
                WriterRequest::MarkGc {
                    runtime,
                    cursor,
                    reply,
                } => {
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .mark_gc_page(&runtime, cursor)
                        .await
                        .map_err(map_store_error);
                    let _ = reply.send(result);
                }
                WriterRequest::SweepGc {
                    runtime,
                    job_id,
                    round,
                    reply,
                } => {
                    let result = writer
                        .as_ref()
                        .ok_or(WriterActorError::Stopped)?
                        .sweep_gc(&runtime, job_id, &round)
                        .await
                        .map_err(map_store_error);
                    let _ = reply.send(result);
                }
            }
        }
        Ok::<(), WriterActorError>(())
    }
    .await;
    // One terminal cleanup for normal and fatal exits: drain the fence held by
    // real readers, revoke the binding, close SQLite and the native handles,
    // and only then release the sibling lock. A writer already consumed by a
    // closed-backup window is not closed twice.
    let mut failure = result.err();
    if let Some(writer) = writer.take()
        && let Err(error) = writer.shutdown().await
    {
        failure.get_or_insert_with(|| map_store_error(error));
    }
    for reply in shutdown_replies {
        let _ = reply.send(());
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

pub(crate) async fn create_quiesced_backup(
    writer: &mut Option<JournalWriter>,
    backup_job_id: evertrace_domain::ids::JobId,
    config_path: PathBuf,
    runtime: evertrace_capture::RuntimeSnapshot,
) -> Result<Result<BackupSummary, BackupError>, WriterActorError> {
    let data_dir = runtime
        .data_dir()
        .map_err(|_| WriterActorError::InvalidInput)?
        .to_owned();
    let published = data_dir
        .join("backups")
        .join(format!("backup-{backup_job_id}"));
    match std::fs::symlink_metadata(&published) {
        Ok(_) => {
            let backup_directory = published.clone();
            let prepared = tokio::task::spawn_blocking(move || {
                evertrace_store::backup::prepare_backup_verification(&data_dir, backup_job_id)
            })
            .await
            .map_err(|_| WriterActorError::Store)?;
            return Ok(match prepared {
                Ok(verification) => {
                    match evertrace_store::backup::complete_backup_verification(verification).await
                    {
                        Ok(summary) => crate::maintenance::verify_hook_backup_assets(
                            &backup_directory,
                            &summary,
                        )
                        .map(|()| summary),
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Ok(Err(BackupError::Io)),
    }

    let current = writer.as_ref().ok_or(WriterActorError::Stopped)?;
    let snapshot = current
        .projection_worker()
        .catch_up()
        .await
        .map_err(map_store_error)?;
    let table_states = current
        .backup_table_states()
        .await
        .map_err(map_store_error)?;
    let fence = evertrace_capture::MaintenanceFence::open(&data_dir)
        .map_err(|_| WriterActorError::Store)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let guard = loop {
        match fence.exclusive() {
            Ok(guard) => break guard,
            Err(evertrace_capture::CasError::LockBusy) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Err(evertrace_capture::CasError::LockBusy) => return Ok(Err(BackupError::Io)),
            Err(_) => return Ok(Err(BackupError::IdentityChanged)),
        }
    };
    let (mut spool, _) = evertrace_capture::DurableSpool::open(
        runtime.spool_dir.clone(),
        runtime
            .spool_limits()
            .map_err(|_| WriterActorError::InvalidInput)?,
    )
    .map_err(|_| WriterActorError::Store)?;
    let boundary = spool
        .freeze_backup_boundary(&guard, runtime.generation)
        .map_err(|_| WriterActorError::Store)?;
    drop(guard);
    drop(spool);
    let hook = match super::super::maintenance::freeze_hook_backup(&data_dir) {
        Ok(hook) => hook,
        Err(error) => return Ok(Err(error)),
    };
    let boundary = evertrace_store::backup::BackupFrozenBoundary {
        spool: boundary,
        hook,
    };

    let guard = match writer
        .as_mut()
        .ok_or(WriterActorError::Stopped)?
        .quiesce_for_backup()
        .await
    {
        Ok(Some(guard)) => guard,
        // A known SQLite-busy checkpoint is one ordinary failed backup: the
        // actor keeps the open writer and replies with the inner failure
        // instead of entering the fatal/reopen path.
        Ok(None) => return Ok(Err(BackupError::Io)),
        Err(error) => return Err(map_store_error(error)),
    };
    let closed = writer
        .take()
        .ok_or(WriterActorError::Stopped)?
        .close_for_backup(guard)
        .map_err(map_store_error)?;
    let (closed, staged) = tokio::task::spawn_blocking(move || {
        closed.stage_backup(
            config_path,
            runtime,
            backup_job_id,
            snapshot,
            table_states,
            boundary,
        )
    })
    .await
    .map_err(|_| WriterActorError::Store)?;
    let (closed, result) = match staged {
        Ok(staging) => match closed.verify_staged_backup(&staging).await {
            Ok(summary) => {
                match crate::maintenance::verify_hook_backup_assets(staging.directory(), &summary) {
                    Ok(()) => tokio::task::spawn_blocking(move || {
                        closed.publish_staged_backup(staging, summary)
                    })
                    .await
                    .map_err(|_| WriterActorError::Store)?,
                    Err(error) => tokio::task::spawn_blocking(move || {
                        let cleanup = closed.discard_staged_backup(&staging);
                        (closed, cleanup.err().map_or(Err(error), Err))
                    })
                    .await
                    .map_err(|_| WriterActorError::Store)?,
                }
            }
            Err(error) => tokio::task::spawn_blocking(move || {
                let cleanup = closed.discard_staged_backup(&staging);
                (closed, cleanup.err().map_or(Err(error), Err))
            })
            .await
            .map_err(|_| WriterActorError::Store)?,
        },
        Err(error) => (closed, Err(error)),
    };
    let reopened = closed.reopen().await.map_err(map_store_error)?;
    *writer = Some(reopened);
    Ok(result)
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RepositoryPurgeBatchOutcome {
    pub committed: bool,
    pub retryable: bool,
}

pub(crate) async fn reconcile_repository_scope_purge_batch(
    writer: &WriterHandle,
    runtime: &evertrace_capture::RuntimeSnapshot,
    snapshot: ProjectionSnapshot,
    leased_job: &DurableJob,
    plans: &std::sync::Mutex<std::collections::BTreeMap<evertrace_domain::ids::JobId, Vec<String>>>,
) -> Result<RepositoryPurgeBatchOutcome, WriterActorError> {
    let started = Instant::now();
    if leased_job.state != JobStatus::Leased
        || leased_job.kind != evertrace_store::REPOSITORY_SCOPE_PURGE_JOB_KIND
    {
        return Err(WriterActorError::InvalidInput);
    }
    let deadline = started + Duration::from_millis(leased_job.budget.max_wall_time_ms.min(5_000));
    let progress = ScopePurgeCurrentView::from_snapshot(&snapshot)
        .map_err(map_store_error)?
        .events
        .into_values()
        .find(|progress| progress.purge_job_id == leased_job.job_id)
        .ok_or(WriterActorError::StoreCorrupt)?;
    if progress.stage == evertrace_domain::purge::ScopePurgeStage::Pending {
        let occurred_at_us = now_us()?;
        let command = crate::purge::advance_repository_purge_command(
            evertrace_domain::ids::CommandId::new_v7(),
            &progress,
            leased_job,
            evertrace_domain::purge::ScopePurgeStage::ProjectionClosed,
            0,
            occurred_at_us,
            leased_job.config_hash,
        )
        .map_err(map_store_error)?;
        return commit_purge_batch(writer, command, occurred_at_us, snapshot.frontier).await;
    }
    let needs_plan = {
        let plans = plans.lock().map_err(|_| WriterActorError::Store)?;
        !plans.contains_key(&leased_job.job_id)
    };
    if needs_plan {
        let confirmation = writer
            .project_at_frontier(progress.confirmation_frontier)
            .await?;
        let preview = evertrace_store::repository_scope_purge_preview(
            &confirmation,
            progress.target.repository_id(),
            progress.target.repository_revision(),
        )
        .map_err(map_store_error)?;
        if preview.deletion_generation != progress.deletion_generation
            || preview.physical_item_count().map_err(map_store_error)?
                != leased_job.budget.max_items
        {
            return Err(WriterActorError::StoreCorrupt);
        }
        plans
            .lock()
            .map_err(|_| WriterActorError::Store)?
            .entry(leased_job.job_id)
            .or_insert(preview.exclusive_cas_refs);
    }
    let (next, batch_refs, plan_len) = {
        let plans = plans.lock().map_err(|_| WriterActorError::Store)?;
        let plan = plans
            .get(&leased_job.job_id)
            .ok_or(WriterActorError::StoreCorrupt)?;
        let next =
            usize::try_from(progress.next_ordinal).map_err(|_| WriterActorError::StoreCorrupt)?;
        if next > plan.len() {
            return Err(WriterActorError::StoreCorrupt);
        }
        let end = next
            .saturating_add(
                usize::try_from(evertrace_store::REPOSITORY_SCOPE_PURGE_BATCH_SIZE)
                    .map_err(|_| WriterActorError::StoreCorrupt)?,
            )
            .min(plan.len());
        (next, plan[next..end].to_vec(), plan.len())
    };
    if Instant::now() >= deadline {
        return Ok(RepositoryPurgeBatchOutcome {
            committed: false,
            retryable: true,
        });
    }
    let occurred_at_us = now_us()?;
    if next == plan_len {
        let command = crate::purge::complete_repository_purge_command(
            evertrace_domain::ids::CommandId::new_v7(),
            &progress,
            leased_job,
            occurred_at_us,
            leased_job.config_hash,
        )
        .map_err(map_store_error)?;
        let outcome =
            commit_purge_batch(writer, command, occurred_at_us, snapshot.frontier).await?;
        if outcome.committed {
            plans
                .lock()
                .map_err(|_| WriterActorError::Store)?
                .remove(&leased_job.job_id);
        }
        return Ok(outcome);
    }
    let batch = batch_refs
        .iter()
        .map(|value| evertrace_capture::CasStore::parse_digest(value))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| WriterActorError::StoreCorrupt)?;
    let candidate_refs = batch_refs.into_iter().collect::<BTreeSet<_>>();
    let fence = evertrace_capture::MaintenanceFence::open(
        runtime.data_dir().map_err(|_| WriterActorError::Store)?,
    )
    .map_err(|_| WriterActorError::Store)?;
    let maintenance = match fence.exclusive() {
        Ok(maintenance) => maintenance,
        Err(evertrace_capture::CasError::LockBusy) => {
            return Ok(RepositoryPurgeBatchOutcome {
                committed: false,
                retryable: true,
            });
        }
        Err(_) => return Err(WriterActorError::Store),
    };
    let fresh = writer.project().await?;
    let fresh_progress = ScopePurgeCurrentView::from_snapshot(&fresh)
        .map_err(map_store_error)?
        .events
        .into_values()
        .find(|value| value.purge_job_id == leased_job.job_id)
        .filter(|value| value == &progress)
        .ok_or(WriterActorError::StoreCorrupt)?;
    let current_job = RuntimeSchedulerView::from_snapshot(&fresh)
        .map_err(map_store_error)?
        .jobs
        .into_iter()
        .find(|job| job.job_id == leased_job.job_id)
        .filter(|job| job == leased_job)
        .ok_or(WriterActorError::StoreCorrupt)?;
    let pinned = current_cas_pins(&fresh, runtime, &candidate_refs)?;
    let delete = batch
        .iter()
        .filter(|digest| !pinned.contains(&digest.as_hex()))
        .copied()
        .collect::<Vec<_>>();
    match evertrace_capture::CasStore::delete_guarded_batch(&maintenance, &delete) {
        Ok(_) => {}
        Err(evertrace_capture::CasError::LockBusy) => {
            return Ok(RepositoryPurgeBatchOutcome {
                committed: false,
                retryable: true,
            });
        }
        Err(_) => return Err(WriterActorError::Store),
    }
    let next_ordinal = progress
        .next_ordinal
        .checked_add(u64::try_from(batch.len()).map_err(|_| WriterActorError::StoreCorrupt)?)
        .ok_or(WriterActorError::StoreCorrupt)?;
    let command = crate::purge::advance_repository_purge_command(
        evertrace_domain::ids::CommandId::new_v7(),
        &fresh_progress,
        &current_job,
        evertrace_domain::purge::ScopePurgeStage::PhysicalDeleting,
        next_ordinal,
        occurred_at_us,
        leased_job.config_hash,
    )
    .map_err(map_store_error)?;
    let outcome = commit_purge_batch(writer, command, occurred_at_us, fresh.frontier).await;
    drop(maintenance);
    outcome
}

async fn commit_purge_batch(
    writer: &WriterHandle,
    command: JournalCommand,
    occurred_at_us: i64,
    frontier: u64,
) -> Result<RepositoryPurgeBatchOutcome, WriterActorError> {
    match writer
        .commit_if_frontier(command, occurred_at_us, frontier)
        .await
    {
        Ok(outcome) => Ok(RepositoryPurgeBatchOutcome {
            committed: !outcome.replayed,
            retryable: false,
        }),
        Err(WriterActorError::StaleFrontier) => Ok(RepositoryPurgeBatchOutcome {
            committed: false,
            retryable: true,
        }),
        Err(error) => Err(error),
    }
}

fn current_cas_pins(
    snapshot: &ProjectionSnapshot,
    runtime: &evertrace_capture::RuntimeSnapshot,
    candidates: &BTreeSet<String>,
) -> Result<BTreeSet<String>, WriterActorError> {
    let mut refs = snapshot
        .live_cas_refs_intersect(candidates)
        .map_err(map_store_error)?;
    let limits = runtime
        .spool_limits()
        .map_err(|_| WriterActorError::Store)?;
    let spool = evertrace_capture::DurableSpool::open_read_only(runtime.spool_dir.clone(), limits)
        .map_err(|_| WriterActorError::Store)?;
    refs.extend(
        spool
            .durable_cas_refs_intersect(
                candidates,
                usize::try_from(limits.max_main_files).map_err(|_| WriterActorError::Store)?,
                limits.high_watermark_bytes,
            )
            .map_err(|_| WriterActorError::Store)?,
    );
    Ok(refs)
}

async fn confirm_procedure_return(
    writer: &mut JournalWriter,
    original_request: evertrace_domain::ids::RequestId,
    acknowledgement: evertrace_domain::ids::RequestId,
    returned: &[evertrace_domain::revision::RevisionId],
    effective_config_hash: [u8; 32],
    stable_min_outcome_supported: u32,
) -> Result<Option<(JournalCommand, u64)>, WriterActorError> {
    use evertrace_domain::ids::CommandId;
    let original_id = CommandId::from_uuid(original_request.as_uuid())
        .map_err(|_| WriterActorError::InvalidInput)?;
    let original = writer
        .committed_command(original_id)
        .await
        .map_err(map_store_error)?;
    // Only the protocol's same-connection final Search set reaches this path.
    // Historical exposure without a new routed command needs no new ledger row.
    let Some(original) = original else {
        return Ok(None);
    };
    let snapshot = writer.project().await.map_err(map_store_error)?;
    let view = crate::procedure::ProcedureUsageCurrentView::from_snapshot(&snapshot)
        .map_err(|_| WriterActorError::StoreCorrupt)?;
    let command_id = CommandId::from_uuid(acknowledgement.as_uuid())
        .map_err(|_| WriterActorError::InvalidInput)?;
    let now = now_us()?;
    let events = view
        .confirmed_return_events(
            crate::semantic::ProposalCommandContext {
                command_id,
                occurred_at_us: now,
                effective_config_hash,
                algorithm_revision: "s34-mcp-procedure-return-v1".into(),
            },
            &original.payloads,
            returned,
            stable_min_outcome_supported,
        )
        .map_err(|_| WriterActorError::InvalidInput)?;
    if events.is_empty() {
        return Ok(None);
    }
    let command = JournalCommand::new(command_id, events).map_err(map_store_error)?;
    let outcome = writer
        .commit_if_frontier(&command, now, snapshot.frontier)
        .await;
    let frontier = match outcome {
        Ok(outcome) => outcome.last_seq,
        Err(StoreError::StoreCorrupt) => return Err(WriterActorError::StoreCorrupt),
        Err(error) => {
            let committed = writer
                .committed_command(command_id)
                .await
                .map_err(map_store_error)?;
            if committed.is_none_or(|committed| {
                !committed
                    .payloads
                    .iter()
                    .eq(command.events().iter().map(|event| &event.payload))
            }) {
                return Err(map_store_error(error));
            }
            writer.sync_frontier().await.map_err(map_store_error)?
        }
    };
    Ok(Some((command, frontier)))
}

fn now_us() -> Result<i64, WriterActorError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_micros()).ok())
        .ok_or(WriterActorError::Store)
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
                | evertrace_store::JournalPayload::RepositoryInstanceRecorded(_)
                | evertrace_store::JournalPayload::ScopePurgeProgressRecorded(_)
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
                | evertrace_store::JournalPayload::SourceReceiptRecorded(_)
                | evertrace_store::JournalPayload::SourceObservationRecorded(_)
                | evertrace_store::JournalPayload::EvidenceSurfaceRecorded(_)
                | evertrace_store::JournalPayload::RevisionProposalRecorded(_)
                | evertrace_store::JournalPayload::ProcedureUsageRecorded(_)
                | evertrace_store::JournalPayload::ProcedureRevisionRecorded(_)
                | evertrace_store::JournalPayload::ProcedureStateRecorded(_)
                | evertrace_store::JournalPayload::ProcedureNegativeEvidenceRecorded(_)
                | evertrace_store::JournalPayload::ProcedureNegativeReviewRecorded(_)
                | evertrace_store::JournalPayload::GlobalSupportValidationRecorded(_)
                | evertrace_store::JournalPayload::ObjectDeletionLedgerRecorded(_)
                | evertrace_store::JournalPayload::TaskRecorded(_)
                | evertrace_store::JournalPayload::OperationDerived(_)
                | evertrace_store::JournalPayload::WorkBindingRecorded(_)
                | evertrace_store::JournalPayload::ConfigAudit(_)
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

    #[tokio::test]
    async fn cancelled_budget_read_is_drained_before_backup_quiesce() {
        let root =
            std::env::temp_dir().join(format!("evertrace-writer-readers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let data = root.join("data");
        std::fs::create_dir_all(&data).unwrap();
        private_root(&data);
        let writer = crate::open_writer(&data).await.unwrap();
        let readers = writer.read_handle();
        let task = tokio::spawn({
            let readers = readers.clone();
            async move { readers.llm_budget_page(0, 0, 0, None).await }
        });
        task.abort();
        let _ = task.await;
        // A cancelled caller must not release the physical read permit; the
        // backup quiesce barrier waits for the real blocking read to finish.
        let guard = tokio::time::timeout(Duration::from_secs(5), readers.quiesce())
            .await
            .expect("quiesce drains cancelled readers");
        drop(guard);
        // Both read permits are usable again after the fence drains.
        let (first, second) = tokio::join!(
            readers.llm_budget_page(0, 0, 0, None),
            readers.llm_budget_page(0, 0, 0, None)
        );
        first.unwrap();
        second.unwrap();
        drop(writer);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn zero_capacity_is_rejected_without_spawning() {
        assert_eq!(
            WriterActorError::InvalidInput.to_string(),
            "writer actor input is invalid"
        );
    }

    fn private_root(path: &std::path::Path) {
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
    }

    fn writer_test_root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("evertrace-writer-{label}-{}", std::process::id()))
    }

    #[tokio::test]
    async fn out_of_band_stop_drains_a_full_queue_and_releases_the_sibling_lock() {
        let root = writer_test_root("stop");
        let _ = std::fs::remove_dir_all(&root);
        let data = root.join("data");
        std::fs::create_dir_all(&data).unwrap();
        private_root(&data);
        let writer = crate::open_writer(&data).await.unwrap();
        // Capacity one: several senders with live handle clones fill the
        // accepted queue while the actor is busy, so only the out-of-band stop
        // can close admission.
        let (handle, task) = spawn_writer(writer, 1).unwrap();
        let mut senders = Vec::new();
        for _ in 0..8 {
            let handle = handle.clone();
            senders.push(tokio::spawn(async move { handle.project().await }));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::time::timeout(Duration::from_secs(10), task.shutdown_and_join())
            .await
            .expect("stop must not depend on a free queue slot")
            .unwrap();
        // The dedicated writer thread really joined and released the lock.
        let reopened = crate::open_writer(&data).await.unwrap();
        drop(reopened);
        for sender in senders {
            let _ = sender.await;
        }
        drop(handle);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn startup_error_teardown_joins_the_writer_and_releases_the_lock() {
        let root = writer_test_root("startup");
        let _ = std::fs::remove_dir_all(&root);
        let data = root.join("data");
        std::fs::create_dir_all(&data).unwrap();
        private_root(&data);
        let writer = crate::open_writer(&data).await.unwrap();
        let (handle, mut task) = spawn_writer(writer, 8).unwrap();
        // main::run's startup failure arm: stop the handle, then unconditionally
        // stop and join the writer before propagating the error.
        handle.shutdown().await.unwrap();
        // main also selects an already completed writer before its common
        // teardown. Joining must not poll the consumed oneshot a second time.
        (&mut task).await.unwrap().unwrap();
        task.shutdown_and_join().await.unwrap();
        let reopened = crate::open_writer(&data).await.unwrap();
        drop(reopened);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn shutdown_waits_for_a_started_reader_before_releasing_the_sibling_lock() {
        let root = writer_test_root("drain");
        let _ = std::fs::remove_dir_all(&root);
        let data = root.join("data");
        std::fs::create_dir_all(&data).unwrap();
        private_root(&data);
        let writer = crate::open_writer(&data).await.unwrap();
        let (handle, task) = spawn_writer(writer, 8).unwrap();
        let readers = handle.read_handle();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let read = tokio::spawn(async move {
            readers
                .read(move |_connection, _cancel| {
                    started_tx.send(()).unwrap();
                    let _ = release_rx.recv();
                    Ok(())
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .expect("the blocking read must actually start")
            .unwrap();

        let join = tokio::spawn(async move { task.shutdown_and_join().await });
        // The actor enters terminal cleanup, but the started read still holds
        // the fence: shutdown must neither complete nor release the sibling
        // lock before that real reader exits.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !join.is_finished(),
            "shutdown must wait for the live reader"
        );
        assert!(crate::open_writer(&data).await.is_err());

        release_tx.send(()).unwrap();
        // The read may fail closed if the actor revoked the binding first; the
        // join below is the real drain proof.
        let _ = read.await;
        let joined = tokio::time::timeout(Duration::from_secs(5), join)
            .await
            .expect("the actor joins after the reader exits")
            .unwrap();
        assert!(joined.is_ok());
        // The closed store refuses the old binding and a new writer takes the
        // sibling lock.
        assert!(handle.read_handle().journal_rows().await.is_err());
        let reopened = crate::open_writer(&data).await.unwrap();
        drop(reopened);
        drop(handle);
        let _ = std::fs::remove_dir_all(&root);
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

    #[test]
    fn normalization_and_binding_commits_wake_background_scheduler() {
        let operation_id = evertrace_domain::ids::OperationId::new_v7();
        let operation = evertrace_domain::evidence::Operation {
            source_local_pairing: None,
            operation_id,
            host_occurrence_id: evertrace_domain::ids::HostOccurrenceId::from_digest([0x2a; 32]),
            execution_lane_id: None,
            operation_kind: evertrace_domain::evidence::OperationKind::Observe,
            input_source_observation_refs: Vec::new(),
            result_source_observation_refs: Vec::new(),
            pairing_state: evertrace_domain::evidence::PairingState::NotApplicable,
            scope_effect_ids: Vec::new(),
            artifact_refs: Vec::new(),
            operation_resolver_version: 1,
            operation_revision: 1,
            previous_operation_revision: None,
        };
        let binding = evertrace_domain::work::WorkBindingRevision {
            work_binding_revision_id: evertrace_domain::ids::WorkBindingRevisionId::new_v7(),
            operation_id,
            revision_generation: 1,
            predecessor_revision_id: None,
            primary_binding: evertrace_domain::work::PrimaryWorkBinding::default(),
            secondary_bindings: Vec::new(),
            scope_effect_refs: Vec::new(),
            assignment_status: evertrace_domain::work::AssignmentStatus::Unresolved,
            evidence_refs: Vec::new(),
            resolver_version: 1,
        };
        for payload in [
            evertrace_store::JournalPayload::OperationDerived(Box::new(operation)),
            evertrace_store::JournalPayload::WorkBindingRecorded(Box::new(binding)),
        ] {
            let command = JournalCommand::new(
                evertrace_domain::ids::CommandId::new_v7(),
                vec![evertrace_store::JournalEventDraft::runtime(
                    1,
                    [0x2a; 32],
                    "s29-background-notify-v1",
                    payload,
                )],
            )
            .unwrap();
            assert!(background_relevant(&command));
        }
    }
}
