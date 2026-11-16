#![forbid(unsafe_code)]
#![deny(warnings)]

//! Authoritative journal storage and the native derived search projection.

pub mod backup;
pub mod command;
pub mod connection;
pub(crate) mod conversion_input;
pub mod journal;
pub mod migrations;
pub mod objects;
pub mod optimize;
pub mod projections;
pub mod purge;
pub mod query;
pub mod relations;
pub mod repository;
pub mod restore;
pub mod search;
pub mod session_import;
pub(crate) mod sqlite_state;

/// Existing qualification fixtures and fault injection; not a product API.
#[cfg(feature = "test-utils")]
pub mod test_support;

pub mod writer;

pub use backup::{
    BackupError, BackupManifest, BackupSummary, BackupTableState, BackupTableStates,
    QUIESCED_BACKUP_ALGORITHM_REVISION, QUIESCED_BACKUP_CREATE_JOB_KIND,
    QUIESCED_BACKUP_VERIFY_JOB_KIND, verify_backup,
};
pub use command::*;
pub use connection::{StoreReadHandle, collect_batches};
pub use journal::{JOURNAL_TABLE, JournalRow, journal_schema};
pub use migrations::MigrationOutcome;
pub use objects::{
    OBJECTS_CHECKPOINT_ID, OBJECTS_TABLE, ObjectRow, ObjectRowClass, ObjectRowKind, objects_schema,
};
pub use projections::{
    AttemptCurrentView, AutoresearchCurrentView, CaptureCurrentContext, CaptureCurrentItem,
    CompetingResolutionEvidenceView, CurrentFacts, EpisodeCurrentView, InventoryCurrentContext,
    MemoriesCurrentContext, MemoryBrowseContext, NamedCurrentDependency,
    ObjectDeletionCandidateAdmissionView, OperationBurstCurrentView, PassiveSourceCurrentContext,
    PassiveSourceCurrentItem, PassiveSourceSelection, ProjectionSnapshot, ProjectionWorker,
    RecallCurrentAtom, RecallCurrentContext, ReconciliationArtifactContext,
    ReconciliationArtifactDescriptor, ReconciliationArtifactFrontier, ReconciliationArtifactKind,
    ReconciliationArtifactOwnership, ReconciliationFrontier, ReconciliationWorkItem,
    RecoveryEvidenceCurrentView, RepositoryReadContext, RuntimeSchedulerView, ScopeCurrentContext,
    ScopeCurrentRequest, SegmentationCurrentState, SegmentationCurrentView,
    SegmentationReadContext, SemanticCurrentView, SessionCatalogCurrentContext,
    WorkBindingCurrentView, WorkIdentityCurrentView, object_deletion_preview, reduce_journal,
    repository_scope_purge_preview,
};
pub use purge::{
    OBJECT_DELETION_ALGORITHM_REVISION, ObjectDeletionCandidateAdmission,
    ObjectDeletionCurrentView, ObjectDeletionPreview, ObjectDeletionProcedureImpact,
    ObjectDeletionSupportImpact, REPOSITORY_SCOPE_PURGE_ALGORITHM_REVISION,
    REPOSITORY_SCOPE_PURGE_BATCH_SIZE, REPOSITORY_SCOPE_PURGE_JOB_KIND,
    RepositoryScopePurgePreview, ScopePurgeCurrentView, advance_repository_scope_purge,
    pending_object_deletion, pending_repository_scope_purge, purged_object_deletion,
    terminal_repository_scope_purge_job,
};
pub use query::{
    DefaultRetrievalSuppressionGeneration, L0002ProjectionSnapshot,
    default_retrieval_suppression_ref_hash, derive_l0002_projections, object_projection_hash,
};
pub use relations::{
    RELATIONS_CHECKPOINT_ID, RELATIONS_TABLE, RelationProjectionRow, relations_schema,
};
pub use search::{
    SEARCH_CHECKPOINT_ID, SEARCH_PROJECTION_GENERATION, SEARCH_TABLE, SearchHardFilter,
    SearchIndex, SearchProjectionRow, SearchSnapshot, read_search_rows, search_schema,
};
pub use session_import::*;
pub use writer::{
    ClosedJournalWriter, CommittedCommand, JournalWriter, MAX_COMMITTED_COMMAND_READ,
    NativeDiagnosticTable, NativeDiagnostics, NormalSearchCandidateRequest,
    NormalSearchReadContext, SiblingWriterLock,
};
