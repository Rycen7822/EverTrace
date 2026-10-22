//! L0002 relation and search projections.

mod derive;
mod projection;
mod relation_assembly;

pub use derive::{DefaultRetrievalSuppressionGeneration, default_retrieval_suppression_ref_hash};
pub(crate) use projection::SurfaceRowBase;
pub use projection::{
    L0002ProjectionSnapshot, L0002ProjectionWorker, derive_l0002_projections,
    object_projection_hash,
};
#[cfg(test)]
pub(crate) use projection::{reset_surface_row_reuses, surface_row_reuses};
