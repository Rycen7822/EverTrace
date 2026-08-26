#![forbid(unsafe_code)]
#![deny(warnings)]

//! Minimal engine service boundary for the local daemon.

mod capture;
pub mod ingest;
pub mod jobs;
pub mod normalize;
mod service;

pub use ingest::{DrainProgress, EvidenceIngestor, IngestError};
pub use jobs::{
    JobResultDisposition, RecoveryAction, WriterActorError, WriterHandle, classify_job_result,
    expired_leases, open_writer, pending_dirty, pending_outbox, spawn_writer,
};
pub use normalize::{NormalizationSnapshot, NormalizeError, PhysicalNormalizer};
pub use service::{EngineError, EngineService, HealthDispatchError, HealthSnapshot, RuntimeMode};
