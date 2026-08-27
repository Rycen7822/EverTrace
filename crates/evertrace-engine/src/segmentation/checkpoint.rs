use evertrace_domain::{
    repository::WorktreeSnapshot,
    work::{
        Attempt, CaptureReceipt, CaptureSummary, CheckpointReason, WorkCheckpoint, WorkEpisode,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckpointResolution {
    NoDelta,
    Checkpoint(Box<WorkCheckpoint>),
}

pub fn build_checkpoint(
    episode: &WorkEpisode,
    attempts: &[Attempt],
    snapshot: Option<&WorktreeSnapshot>,
    reason: CheckpointReason,
    existing: Option<&WorkCheckpoint>,
) -> Result<CheckpointResolution, evertrace_domain::work::WorkError> {
    let checkpoint = WorkCheckpoint::derive(episode, attempts, snapshot, reason)?;
    if let Some(current) = existing
        && current.stable_key() == checkpoint.stable_key()
    {
        return if current == &checkpoint {
            Ok(CheckpointResolution::NoDelta)
        } else {
            Err(evertrace_domain::work::WorkError::InvalidWorkIdentity)
        };
    }
    Ok(CheckpointResolution::Checkpoint(Box::new(checkpoint)))
}

pub fn capture_summary(
    receipts: &[CaptureReceipt],
) -> Result<CaptureSummary, evertrace_domain::work::WorkError> {
    CaptureSummary::from_receipts(receipts)
}
