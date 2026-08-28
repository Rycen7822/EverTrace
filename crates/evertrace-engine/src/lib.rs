#![forbid(unsafe_code)]
#![deny(warnings)]

//! Minimal engine service boundary for the local daemon.

pub mod autoresearch;
pub mod capture;
pub mod ingest;
pub mod jobs;
pub mod normalize;
pub mod recovery;
pub mod repository;
pub mod search;
pub mod segmentation;
pub mod semantic;
mod service;
pub mod work;

pub use ingest::{DrainProgress, EvidenceIngestor, IngestError};
pub use jobs::{
    JobResultDisposition, RecoveryAction, WriterActorError, WriterHandle, classify_job_result,
    expired_leases, open_writer, pending_dirty, pending_outbox, spawn_writer,
};
pub use normalize::{NormalizationSnapshot, NormalizeError, PhysicalNormalizer};
pub use recovery::*;
pub use service::{EngineError, EngineService, HealthDispatchError, HealthSnapshot, RuntimeMode};
