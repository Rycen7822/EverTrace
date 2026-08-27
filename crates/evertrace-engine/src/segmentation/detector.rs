use std::collections::VecDeque;

use evertrace_domain::{
    evidence::OperationKind,
    ids::{AttemptId, SourceObservationId, TaskId, WorkEpisodeId, WorkstreamId},
    work::{BoundaryCandidateKind, BoundaryStatus, PhaseContract, PhaseKind, WorkEpisode},
};
use thiserror::Error;

use super::{ActivityToken, BoundaryEvidence, BurstFoldUpdate, StateDeltaKind, VerifierTransition};

const MAX_ROLLING_TOKENS: usize = 64;
const REFINEMENT_WINDOW: u8 = 8;
const SURPRISE_ALGORITHM_REVISION: u32 = 1;
const SURPRISE_GAMMA: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlignmentOutcome {
    ContinueCurrentPhase,
    NewAttemptSameEpisode,
    CandidatePhaseTransition,
    RecoverableDeviation,
    WorkstreamSwitch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrayZoneDisposition {
    Pending,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DetectorUpdate {
    episode_id: WorkEpisodeId,
    token_watermark: u64,
    alignment: AlignmentOutcome,
    boundary_status: BoundaryStatus,
    candidate_phase_kind: Option<PhaseKind>,
    candidate_watermark: Option<u64>,
    candidate_evidence_refs: Vec<SourceObservationId>,
    candidate_kind: Option<BoundaryCandidateKind>,
    refinement_progress: u8,
    confirmation_watermark: u64,
    confirmation_evidence_refs: Vec<SourceObservationId>,
    gray_zone: GrayZoneDisposition,
    candidate_retracted: bool,
}

impl DetectorUpdate {
    pub const fn episode_id(&self) -> WorkEpisodeId {
        self.episode_id
    }
    pub const fn token_watermark(&self) -> u64 {
        self.token_watermark
    }
    pub const fn alignment(&self) -> AlignmentOutcome {
        self.alignment
    }
    pub const fn boundary_status(&self) -> BoundaryStatus {
        self.boundary_status
    }
    pub const fn candidate_phase_kind(&self) -> Option<PhaseKind> {
        self.candidate_phase_kind
    }
    pub const fn candidate_watermark(&self) -> Option<u64> {
        self.candidate_watermark
    }
    pub fn candidate_evidence_refs(&self) -> &[SourceObservationId] {
        &self.candidate_evidence_refs
    }
    pub const fn candidate_kind(&self) -> Option<BoundaryCandidateKind> {
        self.candidate_kind
    }
    pub const fn refinement_progress(&self) -> u8 {
        self.refinement_progress
    }
    pub const fn confirmation_watermark(&self) -> u64 {
        self.confirmation_watermark
    }
    pub fn confirmation_evidence_refs(&self) -> &[SourceObservationId] {
        &self.confirmation_evidence_refs
    }
    pub const fn gray_zone(&self) -> GrayZoneDisposition {
        self.gray_zone
    }
    pub const fn candidate_retracted(&self) -> bool {
        self.candidate_retracted
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DetectorError {
    #[error("token is not eligible for deterministic segmentation")]
    Ineligible,
    #[error("source watermark or sequence regressed")]
    WatermarkRegression,
    #[error("a different segmentation transition is pending durable acknowledgement")]
    PendingTransition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BurstFeature {
    operation_kind: OperationKind,
    target_family: String,
    target_refs: Vec<String>,
    error_signature: Option<String>,
    verifier: VerifierTransition,
    state_delta: StateDeltaKind,
    phase_candidate: Option<PhaseKind>,
}

impl BurstFeature {
    fn from_burst(burst: &evertrace_domain::work::OperationBurst) -> Self {
        Self {
            operation_kind: burst.operation_kind,
            target_family: burst.target_family.clone(),
            target_refs: burst.target_refs.clone(),
            error_signature: burst.error_signature.clone(),
            verifier: burst.verifier_delta,
            state_delta: burst.state_delta,
            phase_candidate: burst.phase_candidate,
        }
    }

    fn distance(&self, other: &Self) -> u32 {
        u32::from(self.operation_kind != other.operation_kind) * 3
            + u32::from(self.target_refs != other.target_refs) * 3
            + u32::from(self.target_family != other.target_family) * 3
            + u32::from(self.error_signature != other.error_signature) * 3
            + u32::from(self.verifier != other.verifier) * 4
            + u32::from(self.state_delta != other.state_delta) * 3
            + u32::from(self.phase_candidate != other.phase_candidate) * 4
    }
}

#[derive(Clone, Debug)]
struct RecentFeature {
    source_watermark: u64,
    feature: BurstFeature,
    evidence_refs: Vec<SourceObservationId>,
}

#[derive(Clone, Debug)]
struct Candidate {
    original_phase: PhaseKind,
    proposed_phase: Option<PhaseKind>,
    source_watermark: u64,
    evidence_refs: Vec<SourceObservationId>,
    kind: BoundaryCandidateKind,
    observations: u8,
    feature: BurstFeature,
    left_feature: Option<BurstFeature>,
}

#[derive(Clone, Debug)]
pub(crate) struct SegmentationDetector {
    task_id: TaskId,
    workstream_id: WorkstreamId,
    episode_id: WorkEpisodeId,
    phase_contract: PhaseContract,
    rolling: VecDeque<RecentFeature>,
    surprise_scores: VecDeque<u32>,
    last_sequence: u64,
    source_watermark: u64,
    last_attempt_id: Option<AttemptId>,
    candidate: Option<Candidate>,
    boundary_status: BoundaryStatus,
    confirmation_watermark: u64,
}

impl SegmentationDetector {
    pub(crate) fn new(episode: &WorkEpisode) -> Result<Self, DetectorError> {
        episode.validate().map_err(|_| DetectorError::Ineligible)?;
        if !episode.operation_burst_refs.is_empty()
            || episode.boundary_candidate.is_some()
            || episode.boundary_status != BoundaryStatus::Provisional
        {
            return Err(DetectorError::Ineligible);
        }
        Ok(Self::empty(episode))
    }

    pub(crate) fn restore(
        episode: &WorkEpisode,
        recent_bursts: &[evertrace_domain::work::OperationBurst],
    ) -> Result<Self, DetectorError> {
        episode.validate().map_err(|_| DetectorError::Ineligible)?;
        if recent_bursts.len() > MAX_ROLLING_TOKENS
            || recent_bursts
                .iter()
                .map(|burst| burst.operation_burst_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != recent_bursts.len()
            || recent_bursts.iter().any(|burst| {
                burst.validate().is_err()
                    || !episode
                        .operation_burst_refs
                        .contains(&burst.operation_burst_id)
            })
            || recent_bursts
                .windows(2)
                .any(|pair| pair[0].source_watermark >= pair[1].source_watermark)
        {
            return Err(DetectorError::Ineligible);
        }
        let mut detector = Self::empty(episode);
        for burst in recent_bursts {
            detector.record_feature(burst)?;
            detector.last_sequence = burst
                .members
                .last()
                .map(|member| member.sequence)
                .ok_or(DetectorError::Ineligible)?;
            detector.source_watermark = burst.source_watermark;
            detector.last_attempt_id = burst.attempt_id;
        }
        detector.source_watermark = episode.source_watermark.max(detector.source_watermark);
        detector.boundary_status = episode.boundary_status;
        detector.confirmation_watermark = episode.confirmation_watermark;
        detector.candidate = episode
            .boundary_candidate
            .as_ref()
            .map(|value| {
                let index = detector
                    .rolling
                    .iter()
                    .position(|item| item.source_watermark == value.candidate_watermark)
                    .ok_or(DetectorError::Ineligible)?;
                let item = &detector.rolling[index];
                if value.candidate_watermark > episode.source_watermark
                    || episode.confirmation_watermark != 0
                    || value
                        .evidence_refs
                        .iter()
                        .any(|id| item.evidence_refs.binary_search(id).is_err())
                {
                    return Err(DetectorError::Ineligible);
                }
                Ok(Candidate {
                    original_phase: episode.phase_contract.phase_kind,
                    proposed_phase: value.candidate_phase_kind,
                    source_watermark: value.candidate_watermark,
                    evidence_refs: value.evidence_refs.clone(),
                    kind: value.kind,
                    observations: value.refinement_progress,
                    feature: item.feature.clone(),
                    left_feature: index
                        .checked_sub(1)
                        .and_then(|previous| detector.rolling.get(previous))
                        .map(|item| item.feature.clone()),
                })
            })
            .transpose()?;
        Ok(detector)
    }

    fn empty(episode: &WorkEpisode) -> Self {
        Self {
            task_id: episode.task_id,
            workstream_id: episode.workstream_id,
            episode_id: episode.episode_id,
            phase_contract: episode.phase_contract.clone(),
            rolling: VecDeque::with_capacity(MAX_ROLLING_TOKENS),
            surprise_scores: VecDeque::with_capacity(MAX_ROLLING_TOKENS),
            last_sequence: 0,
            source_watermark: 0,
            last_attempt_id: None,
            candidate: None,
            boundary_status: BoundaryStatus::Provisional,
            confirmation_watermark: 0,
        }
    }

    pub(crate) fn push(
        &mut self,
        token: ActivityToken,
        burst: &BurstFoldUpdate,
    ) -> Result<DetectorUpdate, DetectorError> {
        if burst.current().source_watermark != token.source_watermark()
            || burst
                .current()
                .members
                .iter()
                .all(|member| member.operation_id != token.operation_id())
        {
            return Err(DetectorError::Ineligible);
        }
        if token.workstream_id() != self.workstream_id {
            return Ok(self.update(&token, AlignmentOutcome::WorkstreamSwitch, false, vec![]));
        }
        if token.task_id() != self.task_id || token.episode_id() != self.episode_id {
            return Err(DetectorError::Ineligible);
        }
        if token.sequence() <= self.last_sequence
            || token.source_watermark() <= self.source_watermark
        {
            return Err(DetectorError::WatermarkRegression);
        }
        let observed = token.observed_phase_kind();
        let expected = self.phase_contract.phase_kind;
        let attempt_changed = self.last_attempt_id.is_some()
            && token.attempt_id().is_some()
            && self.last_attempt_id != token.attempt_id();
        let mut alignment = align(
            expected,
            observed,
            token.verifier_transition(),
            attempt_changed,
        );
        let mut retracted = false;
        let mut confirmation_evidence = vec![];
        let feature = BurstFeature::from_burst(burst.current());
        if let Some(candidate) = &mut self.candidate {
            if candidate.observations < REFINEMENT_WINDOW {
                candidate.observations = candidate
                    .observations
                    .checked_add(1)
                    .ok_or(DetectorError::Ineligible)?;
            }
            let returned_left = candidate
                .left_feature
                .as_ref()
                .is_some_and(|left| left.distance(&feature) < candidate.feature.distance(&feature));
            if observed == Some(candidate.original_phase) || returned_left {
                self.candidate = None;
                self.boundary_status = BoundaryStatus::Provisional;
                retracted = true;
            } else if candidate.kind == BoundaryCandidateKind::StructuredSurprise
                && token.boundary_evidence().objective()
            {
                candidate.kind = BoundaryCandidateKind::Objective;
                candidate.proposed_phase = observed;
                candidate.source_watermark = token.source_watermark();
                candidate.evidence_refs = token.boundary_evidence_refs().to_vec();
                candidate.observations = 0;
                candidate.feature = feature.clone();
                alignment = AlignmentOutcome::CandidatePhaseTransition;
            } else if candidate.kind == BoundaryCandidateKind::Objective
                && token.source_watermark() > candidate.source_watermark
                && observed == candidate.proposed_phase
                && token.boundary_evidence().objective()
            {
                self.boundary_status = BoundaryStatus::Confirmed;
                self.confirmation_watermark = token.source_watermark();
                confirmation_evidence = token.boundary_evidence_refs().to_vec();
                self.candidate = None;
            }
        }
        let phase_change = observed.is_some_and(|phase| phase != expected);
        let structured_surprise = burst.started_new()
            && token.boundary_evidence() == BoundaryEvidence::None
            && !phase_change
            && self.is_structured_surprise(&feature);
        if self.candidate.is_none()
            && self.boundary_status != BoundaryStatus::Confirmed
            && !retracted
            && (token.boundary_evidence() != BoundaryEvidence::None
                || phase_change
                || structured_surprise)
        {
            self.candidate = Some(Candidate {
                original_phase: expected,
                proposed_phase: observed,
                source_watermark: token.source_watermark(),
                evidence_refs: if structured_surprise {
                    burst
                        .current()
                        .members
                        .iter()
                        .flat_map(|member| member.source_observation_refs.iter().copied())
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect()
                } else {
                    token.boundary_evidence_refs().to_vec()
                },
                kind: if token.boundary_evidence().objective() || phase_change {
                    BoundaryCandidateKind::Objective
                } else {
                    BoundaryCandidateKind::StructuredSurprise
                },
                observations: 0,
                feature: feature.clone(),
                left_feature: self.rolling.back().map(|item| item.feature.clone()),
            });
            self.boundary_status = BoundaryStatus::Candidate;
            if alignment != AlignmentOutcome::RecoverableDeviation {
                alignment = AlignmentOutcome::CandidatePhaseTransition;
            }
        }
        self.last_sequence = token.sequence();
        self.source_watermark = token.source_watermark();
        self.last_attempt_id = token.attempt_id();
        let update = self.update(&token, alignment, retracted, confirmation_evidence);
        if burst.started_new() {
            self.record_feature(burst.current())?;
        }
        Ok(update)
    }

    pub(crate) fn rolling_len(&self) -> usize {
        self.rolling.len()
    }

    fn is_structured_surprise(&self, feature: &BurstFeature) -> bool {
        let Some(previous) = self.rolling.back() else {
            return false;
        };
        if self.surprise_scores.len() < 4 {
            return false;
        }
        let score = previous.feature.distance(feature);
        let count = u64::try_from(self.surprise_scores.len()).expect("rolling window is bounded");
        let sum = self
            .surprise_scores
            .iter()
            .map(|value| u64::from(*value))
            .sum::<u64>();
        let mean = sum / count;
        let variance = self
            .surprise_scores
            .iter()
            .map(|value| {
                let delta =
                    i64::from(*value) - i64::try_from(mean).expect("bounded score mean fits i64");
                u64::try_from(delta * delta).expect("squared bounded score is non-negative")
            })
            .sum::<u64>()
            / count;
        let threshold = match SURPRISE_ALGORITHM_REVISION {
            1 => mean + SURPRISE_GAMMA * integer_sqrt(variance),
            _ => return false,
        };
        u64::from(score) > threshold
    }

    fn record_feature(
        &mut self,
        burst: &evertrace_domain::work::OperationBurst,
    ) -> Result<(), DetectorError> {
        let feature = BurstFeature::from_burst(burst);
        if let Some(previous) = self.rolling.back() {
            self.surprise_scores
                .push_back(previous.feature.distance(&feature));
        }
        let mut evidence_refs = burst
            .members
            .iter()
            .flat_map(|member| member.source_observation_refs.iter().copied())
            .collect::<Vec<_>>();
        evidence_refs.sort();
        evidence_refs.dedup();
        self.rolling.push_back(RecentFeature {
            source_watermark: burst.source_watermark,
            feature,
            evidence_refs,
        });
        if self.rolling.len() > MAX_ROLLING_TOKENS {
            self.rolling.pop_front();
        }
        while self.surprise_scores.len() >= self.rolling.len() {
            self.surprise_scores.pop_front();
        }
        Ok(())
    }

    fn update(
        &self,
        token: &ActivityToken,
        alignment: AlignmentOutcome,
        candidate_retracted: bool,
        confirmation_evidence_refs: Vec<SourceObservationId>,
    ) -> DetectorUpdate {
        DetectorUpdate {
            episode_id: self.episode_id,
            token_watermark: token.source_watermark(),
            alignment,
            boundary_status: self.boundary_status,
            candidate_phase_kind: self
                .candidate
                .as_ref()
                .and_then(|value| value.proposed_phase),
            candidate_watermark: self.candidate.as_ref().map(|value| value.source_watermark),
            candidate_evidence_refs: self
                .candidate
                .as_ref()
                .map_or_else(Vec::new, |value| value.evidence_refs.clone()),
            candidate_kind: self.candidate.as_ref().map(|value| value.kind),
            refinement_progress: self
                .candidate
                .as_ref()
                .map_or(0, |value| value.observations),
            confirmation_watermark: self.confirmation_watermark,
            confirmation_evidence_refs,
            gray_zone: if self.candidate.is_some() {
                GrayZoneDisposition::Pending
            } else {
                GrayZoneDisposition::Disabled
            },
            candidate_retracted,
        }
    }
}

fn integer_sqrt(value: u64) -> u64 {
    if value < 2 {
        return value;
    }
    let mut low = 1;
    let mut high = value.min(u64::from(u32::MAX));
    while low <= high {
        let mid = low + (high - low) / 2;
        match mid.checked_mul(mid) {
            Some(square) if square == value => return mid,
            Some(square) if square < value => low = mid + 1,
            _ => high = mid - 1,
        }
    }
    high
}

fn align(
    current: PhaseKind,
    observed: Option<PhaseKind>,
    verifier: VerifierTransition,
    attempt_changed: bool,
) -> AlignmentOutcome {
    if attempt_changed && observed.is_none_or(|phase| phase == current) {
        return AlignmentOutcome::NewAttemptSameEpisode;
    }
    if verifier == VerifierTransition::Failed
        && matches!(observed, Some(PhaseKind::Diagnose | PhaseKind::Implement))
    {
        return AlignmentOutcome::RecoverableDeviation;
    }
    if observed == Some(PhaseKind::Recover)
        || (current == PhaseKind::Execute && observed == Some(PhaseKind::Analyze))
    {
        return AlignmentOutcome::RecoverableDeviation;
    }
    if observed.is_some_and(|phase| phase != current) {
        AlignmentOutcome::CandidatePhaseTransition
    } else {
        AlignmentOutcome::ContinueCurrentPhase
    }
}
