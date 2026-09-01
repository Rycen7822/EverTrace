#![forbid(unsafe_code)]
#![deny(warnings)]

//! Minimal engine service boundary for the local daemon.

pub mod autoresearch;
pub mod capture;
pub mod ingest;
pub mod jobs;
pub mod maintenance;
pub mod normalize;
pub mod procedure;
pub mod provider;
pub mod recall;
pub mod recovery;
pub mod repository;
pub mod search;
pub mod segmentation;
pub mod semantic;
mod service;
pub mod session_import;
pub mod work;

pub use ingest::{DrainProgress, EvidenceIngestor, IngestError};
pub use jobs::{
    JobResultDisposition, RecoveryAction, SessionImportBudget, SessionImportError,
    SessionImportProgress, SessionImportWorker, SupportClosureAction, SynthesisPlanner,
    WriterActorError, WriterHandle, classify_job_result, expired_leases, open_writer,
    pending_dirty, pending_outbox, spawn_writer, support_closure_result,
};
pub use maintenance::{
    BackgroundLane, BackgroundProgress, BackgroundScheduler, BackgroundSchedulerError,
    ScheduledJob, select_jobs,
};
pub use normalize::{NormalizationSnapshot, NormalizeError, PhysicalNormalizer};
pub use recall::{RecallCueError, RecallCueOutcome, RecallCueService};
pub use recovery::*;
pub use service::{
    EngineError, EngineService, HealthDispatchError, HealthSnapshot, HumanActionOutcome,
    HumanCompetingDetail, HumanDegradedReason, HumanExecutionIntegrityDetail, HumanGovernanceError,
    HumanGovernanceService, HumanItemCategory, HumanJobBudget, HumanJobDetail, HumanJobState,
    HumanJobTerminalReason, HumanNegativeDecision, HumanObjectFamily, HumanPage,
    HumanProposalDecision, HumanProposalReview, HumanRecoveryDetail, HumanRelatedRequest,
    HumanRelationKind, HumanRowClass, HumanSnapshotStatus, HumanSummary, HumanSupportDetail,
    HumanSurface, HumanSystemDetail, McpActionService, McpBindingAuthority, McpBindingError,
    McpBindingGrant, McpBindingIssue, McpItemPartition, McpResolvedScope, McpScopeMechanism,
    McpServiceAction, McpServiceError, McpServiceItem, McpServiceRequest, McpServiceResult,
    McpServiceStatus, RuntimeMode,
};
