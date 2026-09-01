#![forbid(unsafe_code)]
#![deny(warnings)]

//! Authoritative journal storage and pinned LanceDB compatibility primitives.

pub mod command;
pub mod connection;
pub mod journal;
pub mod migrations;
pub mod objects;
pub mod projections;
pub mod purge;
pub mod query;
pub mod relations;
pub mod repository;
pub mod schema;
pub mod search;
pub mod session_import;
pub mod writer;

pub use command::*;
pub use connection::{CompatibilityStore, StoreProfileError, collect_batches};
pub use journal::{JOURNAL_TABLE, JournalRow, journal_schema};
pub use migrations::{L0001, L0002, MigrationOutcome};
pub use objects::{
    OBJECTS_CHECKPOINT_ID, OBJECTS_TABLE, ObjectRow, ObjectRowClass, ObjectRowKind, objects_schema,
};
pub use projections::{
    AttemptCurrentView, AutoresearchCurrentView, CompetingResolutionEvidenceView,
    EpisodeCurrentView, NamedCurrentDependency, ObjectDeletionCandidateAdmissionView,
    OperationBurstCurrentView, ProjectionSnapshot, ProjectionWorker, RecallCurrentAtom,
    RecallCurrentContext, ReconciliationArtifactContext, ReconciliationArtifactDescriptor,
    ReconciliationArtifactFrontier, ReconciliationArtifactKind, ReconciliationArtifactOwnership,
    ReconciliationFrontier, ReconciliationWorkItem, RecoveryEvidenceCurrentView,
    RuntimeSchedulerView, SegmentationCurrentState, SegmentationCurrentView, SemanticCurrentView,
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
    RELATIONS_CHECKPOINT_ID, RELATIONS_TABLE, RelationProjectionRow, read_relation_rows,
    relations_schema,
};
pub use schema::{PROBE_SCHEMA_VERSION, ProbeRow, probe_batch, probe_schema, schema_fingerprint};
pub use search::{
    SEARCH_CHECKPOINT_ID, SEARCH_TABLE, SearchHardFilter, SearchIndex, SearchProjectionRow,
    SearchSnapshot, read_search_rows, search_schema,
};
pub use session_import::*;
pub use writer::{CommittedCommand, JournalWriter, SiblingWriterLock};
