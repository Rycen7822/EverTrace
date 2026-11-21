//! L0002 relation and search projections.

mod derive;
mod projection;
mod relation_assembly;

pub use derive::{
    DefaultRetrievalSuppressionGeneration, canonical_work_binding_source,
    canonical_work_episode_source, default_retrieval_suppression_ref_hash,
};
pub use projection::{
    L0002ProjectionSnapshot, L0002ProjectionWorker, derive_l0002_projections,
    object_projection_hash,
};
