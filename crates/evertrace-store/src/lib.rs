#![forbid(unsafe_code)]
#![deny(warnings)]

//! Authoritative journal storage and pinned LanceDB compatibility primitives.

pub mod backup;
pub mod command;
pub mod connection;
pub mod journal;
pub(crate) mod legacy_lance;
pub mod migrations;
pub mod objects;
pub mod optimize;
pub mod projections;
pub mod purge;
pub mod query;
pub mod relations;
pub mod repository;
pub mod restore;
pub mod schema;
pub mod search;
pub mod session_import;
pub(crate) mod sqlite_state;

/// Test-only fault injection for integration tests. Never compiled into a
/// production build.
#[cfg(feature = "test-utils")]
pub mod test_support {
    use std::path::Path;

    /// Remove the persisted objects family so a reopen must rebuild it from the
    /// authoritative journal.
    pub fn clear_objects(data_dir: &Path) -> Result<(), crate::StoreError> {
        crate::sqlite_state::SqliteState::open(data_dir)?
            .handle()
            .lock()
            .map_err(|_| crate::StoreError::StoreCorrupt)?
            .clear_object_rows_for_test()
    }

    /// Advance the persisted objects checkpoint without any projection, so a
    /// consumer must detect the logical gap.
    pub fn advance_object_checkpoint(data_dir: &Path) -> Result<(), crate::StoreError> {
        crate::sqlite_state::SqliteState::open(data_dir)?
            .handle()
            .lock()
            .map_err(|_| crate::StoreError::StoreCorrupt)?
            .advance_object_checkpoint_for_test()
    }

    /// Materialize one valid retired layout (`L0001` or `L0002`, canonical or
    /// flat) from already-persisted logical journal rows so cross-crate package
    /// and maintenance tests can exercise the named offline converter. `root`
    /// is a caller-owned empty test container: only the requested tables are
    /// created there; no existing store is deleted or converted.
    pub async fn write_legacy_fixture(
        root: &Path,
        canonical: bool,
        profile: &str,
        rows: &[crate::JournalRow],
    ) -> Result<(), crate::StoreError> {
        crate::legacy_lance::test_format::write_legacy_fixture(root, canonical, profile, rows).await
    }
}

pub mod writer;

pub use backup::{
    BackupError, BackupManifest, BackupSummary, BackupTableState, BackupTableStates,
    QUIESCED_BACKUP_ALGORITHM_REVISION, QUIESCED_BACKUP_CREATE_JOB_KIND,
    QUIESCED_BACKUP_VERIFY_JOB_KIND, verify_backup,
};
pub use command::*;
pub use connection::{CompatibilityStore, StoreProfileError, StoreReadHandle, collect_batches};
pub use journal::{JOURNAL_TABLE, JournalRow, journal_schema};
pub use migrations::MigrationOutcome;
pub use objects::{
    OBJECTS_CHECKPOINT_ID, OBJECTS_TABLE, ObjectRow, ObjectRowClass, ObjectRowKind, objects_schema,
};
pub use projections::{
    AttemptCurrentView, AutoresearchCurrentView, CaptureCurrentContext, CaptureCurrentItem,
    CompetingResolutionEvidenceView, EpisodeCurrentView, InventoryCurrentContext,
    MemoriesCurrentContext, NamedCurrentDependency, ObjectDeletionCandidateAdmissionView,
    OperationBurstCurrentView, PassiveSourceCurrentContext, PassiveSourceCurrentItem,
    PassiveSourceSelection, ProjectionSnapshot, ProjectionWorker, RecallCurrentAtom,
    RecallCurrentContext, ReconciliationArtifactContext, ReconciliationArtifactDescriptor,
    ReconciliationArtifactFrontier, ReconciliationArtifactKind, ReconciliationArtifactOwnership,
    ReconciliationFrontier, ReconciliationWorkItem, RecoveryEvidenceCurrentView,
    RepositoryReadContext, RuntimeSchedulerView, ScopeCurrentContext, ScopeCurrentRequest,
    SegmentationCurrentState, SegmentationCurrentView, SemanticCurrentView,
    SessionCatalogCurrentContext, WorkBindingCurrentView, WorkIdentityCurrentView,
    object_deletion_preview, reduce_journal, repository_scope_purge_preview,
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
pub use schema::{PROBE_SCHEMA_VERSION, ProbeRow, probe_batch, probe_schema, schema_fingerprint};
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
