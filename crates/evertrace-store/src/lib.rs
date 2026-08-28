#![forbid(unsafe_code)]
#![deny(warnings)]

//! Authoritative journal storage and pinned LanceDB compatibility primitives.

pub mod command;
pub mod connection;
pub mod journal;
pub mod migrations;
pub mod objects;
pub mod projections;
pub mod relations;
pub mod repository;
pub mod schema;
pub mod search;
pub mod writer;

pub use command::*;
pub use connection::{CompatibilityStore, StoreProfileError, collect_batches};
pub use journal::{JOURNAL_TABLE, JournalRow, journal_schema};
pub use migrations::{L0001, MigrationOutcome};
pub use objects::{
    OBJECTS_CHECKPOINT_ID, OBJECTS_TABLE, ObjectRow, ObjectRowClass, ObjectRowKind, objects_schema,
};
pub use projections::{
    AttemptCurrentView, EpisodeCurrentView, NamedCurrentDependency, OperationBurstCurrentView,
    ProjectionSnapshot, ProjectionWorker, ReconciliationArtifactContext,
    ReconciliationArtifactDescriptor, ReconciliationArtifactFrontier, ReconciliationArtifactKind,
    ReconciliationArtifactOwnership, ReconciliationFrontier, ReconciliationWorkItem,
    RecoveryEvidenceCurrentView, SegmentationCurrentState, SegmentationCurrentView,
    SemanticCurrentView, WorkBindingCurrentView, WorkIdentityCurrentView, reduce_journal,
};
pub use schema::{PROBE_SCHEMA_VERSION, ProbeRow, probe_batch, probe_schema, schema_fingerprint};
pub use writer::{JournalWriter, SiblingWriterLock};
