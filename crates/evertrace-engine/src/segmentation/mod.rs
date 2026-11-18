//! S15 deterministic, bounded incremental WorkEpisode segmentation.

mod burst;
mod checkpoint;
mod detector;
mod incremental;
mod production;
pub(crate) mod refinement;
mod token;

pub(crate) use burst::{BurstFoldUpdate, OperationBurstFolder, close_burst};
pub use checkpoint::{CheckpointResolution, build_checkpoint, capture_summary};
pub(crate) use checkpoint::{advance_checkpoints, advance_idle_checkpoints};
pub use detector::{AlignmentOutcome, DetectorError, GrayZoneDisposition};
pub(crate) use detector::{DetectorUpdate, SegmentationDetector};
pub use evertrace_store::SegmentationCurrentView;
pub use incremental::{IncrementalSegmentationStep, IncrementalSegmenter, SegmentOutcome};
pub(crate) use production::advance_activity;
pub(crate) use token::ActivityToken;
pub use token::{BoundaryEvidence, SegmentationFacts, StateDeltaKind, VerifierTransition};

use evertrace_domain::work::PhaseContract;

/// A display label is not a contract change. All other fields must match across evidence.
fn same_phase_proposal(left: &PhaseContract, right: &PhaseContract) -> bool {
    left.phase_kind == right.phase_kind
        && left.local_goal == right.local_goal
        && left.primary_targets == right.primary_targets
        && left.entry_conditions == right.entry_conditions
        && left.acceptance_boundary == right.acceptance_boundary
        && left.expected_state_transition == right.expected_state_transition
}
