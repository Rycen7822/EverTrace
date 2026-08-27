//! S15 deterministic, bounded incremental WorkEpisode segmentation.

mod burst;
mod checkpoint;
mod detector;
mod incremental;
mod token;

pub(crate) use burst::{BurstFoldUpdate, OperationBurstFolder, close_burst};
pub use checkpoint::{CheckpointResolution, build_checkpoint, capture_summary};
pub use detector::{AlignmentOutcome, DetectorError, GrayZoneDisposition};
pub(crate) use detector::{DetectorUpdate, SegmentationDetector};
pub use evertrace_store::SegmentationCurrentView;
pub use incremental::{IncrementalSegmentationStep, IncrementalSegmenter, SegmentOutcome};
pub(crate) use token::ActivityToken;
pub use token::{BoundaryEvidence, SegmentationFacts, StateDeltaKind, VerifierTransition};
