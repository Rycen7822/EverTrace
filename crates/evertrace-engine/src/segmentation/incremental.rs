use evertrace_domain::{
    ids::{OperationId, WorkEpisodeId},
    revision::RevisionId,
    work::{
        BoundaryCandidateKind, BoundaryCandidateState, BoundaryStatus, EpisodeLifecycle,
        OperationBurst, OperationBurstLifecycle, PhaseKind,
    },
};
use evertrace_store::SegmentationCurrentState;

use super::{
    ActivityToken, AlignmentOutcome, BurstFoldUpdate, DetectorError, DetectorUpdate,
    OperationBurstFolder, SegmentationDetector, SegmentationFacts,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SegmentOutcome {
    NoDelta,
    Delta(Box<IncrementalSegmentationStep>),
}

/// One inseparable token -> burst -> detector transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncrementalSegmentationStep {
    token: ActivityToken,
    burst: BurstFoldUpdate,
    detector: DetectorUpdate,
    episode_successor_revision_id: RevisionId,
}

impl IncrementalSegmentationStep {
    pub const fn source_watermark(&self) -> u64 {
        self.token.source_watermark()
    }
    pub const fn operation_id(&self) -> OperationId {
        self.token.operation_id()
    }
    pub const fn alignment(&self) -> AlignmentOutcome {
        self.detector.alignment()
    }
    pub const fn gray_zone(&self) -> super::GrayZoneDisposition {
        self.detector.gray_zone()
    }
    pub const fn candidate_retracted(&self) -> bool {
        self.detector.candidate_retracted()
    }
    pub fn current_burst(&self) -> &OperationBurst {
        self.burst.current()
    }
    pub fn closed_burst(&self) -> Option<&OperationBurst> {
        self.burst.closed()
    }
    pub const fn started_new_burst(&self) -> bool {
        self.burst.started_new()
    }
    pub const fn meaningful_new_burst(&self) -> bool {
        self.burst.meaningful_new()
    }
    pub const fn boundary_status(&self) -> BoundaryStatus {
        self.detector.boundary_status()
    }
    pub const fn candidate_phase_kind(&self) -> Option<PhaseKind> {
        self.detector.candidate_phase_kind()
    }
    pub const fn candidate_watermark(&self) -> Option<u64> {
        self.detector.candidate_watermark()
    }
    pub fn candidate_evidence_refs(&self) -> &[evertrace_domain::ids::SourceObservationId] {
        self.detector.candidate_evidence_refs()
    }
    pub const fn candidate_kind(&self) -> Option<BoundaryCandidateKind> {
        self.detector.candidate_kind()
    }
    pub const fn refinement_progress(&self) -> u8 {
        self.detector.refinement_progress()
    }
    pub const fn confirmation_watermark(&self) -> u64 {
        self.detector.confirmation_watermark()
    }
    pub(crate) fn token(&self) -> &ActivityToken {
        &self.token
    }
    pub(crate) fn burst(&self) -> &BurstFoldUpdate {
        &self.burst
    }
    pub(crate) fn detector(&self) -> &DetectorUpdate {
        &self.detector
    }
    pub(crate) const fn episode_successor_revision_id(&self) -> RevisionId {
        self.episode_successor_revision_id
    }
}

#[derive(Clone, Debug)]
pub struct IncrementalSegmenter {
    episode_id: WorkEpisodeId,
    folder: OperationBurstFolder,
    detector: SegmentationDetector,
    pending: Option<PendingTransition>,
    committed_episode_revision_id: RevisionId,
    committed_frontier: u64,
    closed: bool,
}

#[derive(Clone, Debug)]
struct PendingTransition {
    step: IncrementalSegmentationStep,
    next_folder: OperationBurstFolder,
    next_detector: SegmentationDetector,
}

impl IncrementalSegmenter {
    pub fn new(
        current: &SegmentationCurrentState,
        episode_id: WorkEpisodeId,
    ) -> Result<Self, DetectorError> {
        let episode = current
            .episode(episode_id)
            .ok_or(DetectorError::Ineligible)?;
        if episode.lifecycle_status != EpisodeLifecycle::Open
            || !episode.operation_burst_refs.is_empty()
        {
            return Err(DetectorError::Ineligible);
        }
        Ok(Self {
            episode_id,
            folder: OperationBurstFolder::new(),
            detector: SegmentationDetector::new(episode)?,
            pending: None,
            committed_episode_revision_id: episode.revision_id,
            committed_frontier: current.frontier(),
            closed: false,
        })
    }

    pub fn restore(
        current: &SegmentationCurrentState,
        episode_id: WorkEpisodeId,
    ) -> Result<Self, DetectorError> {
        let episode = current
            .episode(episode_id)
            .ok_or(DetectorError::Ineligible)?;
        let recent_bursts = current
            .recent_bursts(episode)
            .map_err(|_| DetectorError::Ineligible)?;
        Ok(Self {
            episode_id,
            folder: OperationBurstFolder::restore(&recent_bursts)?,
            detector: SegmentationDetector::restore(episode, &recent_bursts)?,
            pending: None,
            committed_episode_revision_id: episode.revision_id,
            committed_frontier: current.frontier(),
            closed: episode.lifecycle_status != EpisodeLifecycle::Open,
        })
    }

    pub fn observe(
        &mut self,
        current: &SegmentationCurrentState,
        operation_id: OperationId,
        facts: SegmentationFacts,
    ) -> Result<SegmentOutcome, DetectorError> {
        if self.closed || current.frontier() < self.committed_frontier {
            return Err(DetectorError::Ineligible);
        }
        let episode = current
            .episode(self.episode_id)
            .ok_or(DetectorError::Ineligible)?;
        if let Some(pending) = &self.pending {
            if episode.revision_id != self.committed_episode_revision_id
                && episode.revision_id != pending.step.episode_successor_revision_id
            {
                return Err(DetectorError::Ineligible);
            }
        } else if episode.revision_id != self.committed_episode_revision_id
            || episode.lifecycle_status != EpisodeLifecycle::Open
        {
            return Err(DetectorError::Ineligible);
        }
        let token = ActivityToken::compile_checked(
            current.authority(),
            operation_id,
            self.episode_id,
            facts,
        )?;
        if let Some(pending) = &self.pending {
            return if pending.step.token == token {
                Ok(SegmentOutcome::Delta(Box::new(pending.step.clone())))
            } else {
                Err(DetectorError::PendingTransition)
            };
        }
        let mut next_folder = self.folder.clone();
        let mut next_detector = self.detector.clone();
        let burst = next_folder.push(&token)?;
        if burst.no_delta() {
            return Ok(SegmentOutcome::NoDelta);
        }
        let detector = next_detector.push(token.clone(), &burst)?;
        let step = IncrementalSegmentationStep {
            token,
            burst,
            detector,
            episode_successor_revision_id: RevisionId::new_v7(),
        };
        self.pending = Some(PendingTransition {
            step: step.clone(),
            next_folder,
            next_detector,
        });
        Ok(SegmentOutcome::Delta(Box::new(step)))
    }

    /// Promote a prepared transition only after its journal command is durably committed.
    pub fn acknowledge_committed(
        &mut self,
        current: &SegmentationCurrentState,
        step: &IncrementalSegmentationStep,
    ) -> Result<(), DetectorError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(DetectorError::PendingTransition)?;
        if pending.step != *step || current.frontier() <= self.committed_frontier {
            return Err(DetectorError::PendingTransition);
        }
        let episode = current
            .episode(self.episode_id)
            .ok_or(DetectorError::PendingTransition)?;
        let expected_candidate =
            step.candidate_watermark()
                .map(|candidate_watermark| BoundaryCandidateState {
                    candidate_phase_kind: step.candidate_phase_kind(),
                    candidate_watermark,
                    evidence_refs: step.candidate_evidence_refs().to_vec(),
                    kind: step
                        .candidate_kind()
                        .expect("candidate kind is bound to watermark"),
                    refinement_progress: step.refinement_progress(),
                });
        let confirmed = step.boundary_status() == BoundaryStatus::Confirmed;
        let current_burst = current
            .current_burst(step.current_burst().operation_burst_id)
            .ok_or(DetectorError::PendingTransition)?;
        let current_burst_matches = if confirmed {
            current_burst.lifecycle == OperationBurstLifecycle::Closed
                && step
                    .current_burst()
                    .validate_successor(current_burst)
                    .is_ok()
        } else {
            current_burst == step.current_burst()
        };
        let closed_burst_matches = step.closed_burst().is_none_or(|closed| {
            current
                .current_burst(closed.operation_burst_id)
                .is_some_and(|value| value == closed)
        });
        if episode.revision_id != step.episode_successor_revision_id
            || episode.predecessor_revision_id != Some(self.committed_episode_revision_id)
            || episode.source_watermark != step.source_watermark()
            || episode.boundary_status != step.boundary_status()
            || episode.boundary_candidate != expected_candidate
            || episode.lifecycle_status
                != if confirmed {
                    EpisodeLifecycle::Closed
                } else {
                    EpisodeLifecycle::Open
                }
            || !episode
                .operation_burst_refs
                .contains(&step.current_burst().operation_burst_id)
            || !current_burst_matches
            || !closed_burst_matches
        {
            return Err(DetectorError::PendingTransition);
        }
        let pending = self.pending.take().expect("validated pending transition");
        self.folder = pending.next_folder;
        self.detector = pending.next_detector;
        self.committed_episode_revision_id = episode.revision_id;
        self.committed_frontier = current.frontier();
        self.closed = confirmed;
        Ok(())
    }

    pub fn rolling_len(&self) -> usize {
        self.detector.rolling_len()
    }
}
