use serde::{Deserialize, Serialize};

use crate::{
    ids::{
        AttemptId, CaptureOutageIntervalId, CaptureReceiptId, CompetingAttemptGroupId,
        ExecutionLaneId, ExperimentRunId, OperationBurstId, RepositoryId, SourceObservationId,
        TaskId, WorkArtifactId, WorkEpisodeId, WorkstreamId, WorktreeId, WorktreeSnapshotId,
        WorktreeTransitionId,
    },
    repository::WorktreeSnapshot,
    revision::RevisionId,
    work::{
        CoverageLevel, OrderingIntegrity, PairingIntegrity, PayloadIntegrity, PhaseContract,
        ReasoningVisibility, SourceCoverage, WorkError, task::strictly_ordered_unique,
    },
};

pub const EPISODE_ALGORITHM_REVISION: u32 = 1;
const MAX_REFS: usize = 64;
const MAX_TEXT: usize = 4096;

fn bounded(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT
}

fn refs(values: &[String]) -> bool {
    values.len() <= MAX_REFS
        && values.iter().all(|value| bounded(value))
        && strictly_ordered_unique(values)
}

fn ids<T: Ord>(values: &[T]) -> bool {
    values.len() <= MAX_REFS && strictly_ordered_unique(values)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeLifecycle {
    Open,
    Closed,
    Superseded,
}

impl EpisodeLifecycle {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryStatus {
    Provisional,
    Candidate,
    Confirmed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryCandidateKind {
    StructuredSurprise,
    Objective,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryCandidateState {
    pub candidate_phase_kind: Option<super::PhaseKind>,
    pub candidate_watermark: u64,
    pub evidence_refs: Vec<SourceObservationId>,
    pub kind: BoundaryCandidateKind,
    pub refinement_progress: u8,
}

impl BoundaryCandidateState {
    pub fn validate(&self) -> Result<(), WorkError> {
        if self.candidate_watermark == 0
            || self.evidence_refs.is_empty()
            || !ids(&self.evidence_refs)
            || self.refinement_progress > 8
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrectionKind {
    Retract,
    Split,
    Merge,
    Reattach,
}

impl CorrectionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retract => "retract",
            Self::Split => "split",
            Self::Merge => "merge",
            Self::Reattach => "reattach",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentationCorrection {
    pub correction_revision_id: RevisionId,
    pub predecessor_revision_id: Option<RevisionId>,
    pub kind: CorrectionKind,
    pub source_episode_ids: Vec<WorkEpisodeId>,
    pub replacement_episode_ids: Vec<WorkEpisodeId>,
    pub evidence_refs: Vec<String>,
    pub source_watermark: u64,
}

impl SegmentationCorrection {
    pub fn validate(&self) -> Result<(), WorkError> {
        let shape = match self.kind {
            CorrectionKind::Retract => {
                self.source_episode_ids.len() == 1 && self.replacement_episode_ids.is_empty()
            }
            CorrectionKind::Split => {
                self.source_episode_ids.len() == 1 && self.replacement_episode_ids.len() >= 2
            }
            CorrectionKind::Merge => {
                self.source_episode_ids.len() >= 2 && self.replacement_episode_ids.len() == 1
            }
            CorrectionKind::Reattach => {
                self.source_episode_ids.len() == 1 && self.replacement_episode_ids.len() == 1
            }
        };
        if self.source_watermark == 0
            || !ids(&self.source_episode_ids)
            || !ids(&self.replacement_episode_ids)
            || !refs(&self.evidence_refs)
            || self.evidence_refs.is_empty()
            || !shape
            || self
                .source_episode_ids
                .iter()
                .any(|id| self.replacement_episode_ids.contains(id))
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingDeltaStats {
    pub selected_token_count: u32,
    pub meaningful_burst_count: u32,
    pub high_value_signal_count: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingSemanticInterval {
    pub after_watermark: u64,
    pub through_watermark: u64,
}

impl PendingSemanticInterval {
    pub const fn validate(self) -> Result<(), WorkError> {
        if self.after_watermark >= self.through_watermark {
            Err(WorkError::InvalidWorkIdentity)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSummary {
    pub minimum_coverage_level: CoverageLevel,
    pub source_coverage_states: Vec<SourceCoverage>,
    pub pairing_integrity_states: Vec<PairingIntegrity>,
    pub payload_integrity_states: Vec<PayloadIntegrity>,
    pub ordering_integrity_states: Vec<OrderingIntegrity>,
    pub reasoning_visibility: Vec<ReasoningVisibility>,
}

impl Default for CaptureSummary {
    fn default() -> Self {
        Self {
            minimum_coverage_level: CoverageLevel::Opaque,
            source_coverage_states: vec![SourceCoverage::Unavailable],
            pairing_integrity_states: vec![PairingIntegrity::Unavailable],
            payload_integrity_states: vec![PayloadIntegrity::Unavailable],
            ordering_integrity_states: vec![OrderingIntegrity::Unavailable],
            reasoning_visibility: vec![],
        }
    }
}

impl CaptureSummary {
    pub fn validate(&self) -> Result<(), WorkError> {
        if self.source_coverage_states.is_empty()
            || self.pairing_integrity_states.is_empty()
            || self.payload_integrity_states.is_empty()
            || self.ordering_integrity_states.is_empty()
            || !ids(&self.source_coverage_states)
            || !ids(&self.pairing_integrity_states)
            || !ids(&self.payload_integrity_states)
            || !ids(&self.ordering_integrity_states)
            || !ids(&self.reasoning_visibility)
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }

    pub fn from_receipts(receipts: &[super::CaptureReceipt]) -> Result<Self, WorkError> {
        if receipts.is_empty() {
            return Ok(Self::default());
        }
        for receipt in receipts {
            receipt.validate()?;
        }
        let mut source = receipts
            .iter()
            .map(|value| value.source_coverage)
            .collect::<Vec<_>>();
        let mut pairing = receipts
            .iter()
            .map(|value| value.pairing_integrity)
            .collect::<Vec<_>>();
        let mut payload = receipts
            .iter()
            .map(|value| value.payload_integrity)
            .collect::<Vec<_>>();
        let mut ordering = receipts
            .iter()
            .map(|value| value.ordering_integrity)
            .collect::<Vec<_>>();
        let mut visibility = receipts
            .iter()
            .flat_map(|value| value.reasoning_visibility.iter().copied())
            .collect::<Vec<_>>();
        source.sort();
        source.dedup();
        pairing.sort();
        pairing.dedup();
        payload.sort();
        payload.dedup();
        ordering.sort();
        ordering.dedup();
        visibility.sort();
        visibility.dedup();
        let opaque = receipts
            .iter()
            .any(|value| value.coverage_level == CoverageLevel::Opaque)
            || source.contains(&SourceCoverage::Unavailable)
            || pairing.contains(&PairingIntegrity::Unavailable)
            || payload.contains(&PayloadIntegrity::Unavailable)
            || ordering.contains(&OrderingIntegrity::Unavailable);
        let degraded = receipts.iter().any(|value| {
            value.coverage_level != CoverageLevel::Full
                || value.source_coverage != SourceCoverage::Complete
                || value.pairing_integrity != PairingIntegrity::Complete
                || value.payload_integrity != PayloadIntegrity::Complete
                || value.ordering_integrity != OrderingIntegrity::Complete
                || !value.finalized
                || !value.capture_gap_marker_refs.is_empty()
                || !value.capture_outage_interval_refs.is_empty()
        });
        Ok(Self {
            minimum_coverage_level: if opaque {
                CoverageLevel::Opaque
            } else if degraded {
                CoverageLevel::Partial
            } else {
                CoverageLevel::Full
            },
            source_coverage_states: source,
            pairing_integrity_states: pairing,
            payload_integrity_states: payload,
            ordering_integrity_states: ordering,
            reasoning_visibility: visibility,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkEpisode {
    pub episode_id: WorkEpisodeId,
    pub revision_id: RevisionId,
    pub predecessor_revision_id: Option<RevisionId>,
    pub revision_generation: u64,
    pub task_id: TaskId,
    pub workstream_id: WorkstreamId,
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_id: Option<WorktreeId>,
    pub phase_contract: PhaseContract,
    pub lifecycle_status: EpisodeLifecycle,
    pub boundary_status: BoundaryStatus,
    pub source_watermark: u64,
    pub semantic_watermark: u64,
    pub confirmation_watermark: u64,
    pub capture_watermark: u64,
    pub entry_worktree_snapshot_id: Option<WorktreeSnapshotId>,
    pub exit_worktree_snapshot_id: Option<WorktreeSnapshotId>,
    pub session_ids: Vec<String>,
    pub execution_lane_ids: Vec<ExecutionLaneId>,
    pub attempt_ids: Vec<AttemptId>,
    pub competing_attempt_group_ids: Vec<CompetingAttemptGroupId>,
    pub operation_burst_refs: Vec<OperationBurstId>,
    pub worktree_transition_refs: Vec<WorktreeTransitionId>,
    pub failed_attempt_ids: Vec<AttemptId>,
    pub interrupted_attempt_ids: Vec<AttemptId>,
    pub returned_but_unselected_attempt_ids: Vec<AttemptId>,
    pub selected_attempt_ids: Vec<AttemptId>,
    pub failure_refs: Vec<String>,
    pub interruption_refs: Vec<String>,
    pub completed_outcome_refs: Vec<String>,
    pub selected_outcome_refs: Vec<String>,
    pub verification_refs: Vec<String>,
    pub open_loops: Vec<String>,
    pub checkpoint_refs: Vec<String>,
    pub capture_receipt_revision_ids: Vec<CaptureReceiptId>,
    pub capture_gap_refs: Vec<String>,
    pub capture_outage_refs: Vec<CaptureOutageIntervalId>,
    pub pending_delta_stats: PendingDeltaStats,
    pub pending_semantic_delta: Option<PendingSemanticInterval>,
    pub boundary_candidate: Option<BoundaryCandidateState>,
    pub capture_summary: CaptureSummary,
    pub segmentation_correction_refs: Vec<RevisionId>,
    pub experiment_run_refs: Vec<ExperimentRunId>,
    pub work_artifact_refs: Vec<WorkArtifactId>,
    pub semantic_digest_refs: Vec<String>,
}

impl WorkEpisode {
    pub fn validate(&self) -> Result<(), WorkError> {
        self.phase_contract.validate()?;
        self.capture_summary.validate()?;
        let pending_ok = match self.pending_semantic_delta {
            Some(interval) => {
                interval.validate().is_ok()
                    && interval.after_watermark == self.semantic_watermark
                    && interval.through_watermark == self.source_watermark
            }
            None => self.semantic_watermark == self.source_watermark,
        };
        let all_lists = [
            refs(&self.session_ids),
            ids(&self.execution_lane_ids),
            ids(&self.attempt_ids),
            ids(&self.competing_attempt_group_ids),
            ids(&self.operation_burst_refs),
            ids(&self.worktree_transition_refs),
            ids(&self.failed_attempt_ids),
            ids(&self.interrupted_attempt_ids),
            ids(&self.returned_but_unselected_attempt_ids),
            ids(&self.selected_attempt_ids),
            refs(&self.failure_refs),
            refs(&self.interruption_refs),
            refs(&self.completed_outcome_refs),
            refs(&self.selected_outcome_refs),
            refs(&self.verification_refs),
            refs(&self.open_loops),
            refs(&self.checkpoint_refs),
            ids(&self.capture_receipt_revision_ids),
            refs(&self.capture_gap_refs),
            ids(&self.capture_outage_refs),
            ids(&self.segmentation_correction_refs),
        ]
        .into_iter()
        .all(|valid| valid);
        if self.revision_generation == 0
            || self.source_watermark == 0
            || (self.revision_generation == 1) != self.predecessor_revision_id.is_none()
            || self.semantic_watermark > self.source_watermark
            || self.confirmation_watermark > self.source_watermark
            || self.capture_watermark > self.source_watermark
            || !pending_ok
            || self.boundary_candidate.as_ref().is_some_and(|candidate| {
                candidate.validate().is_err()
                    || candidate.candidate_watermark > self.source_watermark
            })
            || (self.boundary_status == BoundaryStatus::Candidate)
                != self.boundary_candidate.is_some()
            || !all_lists
            || !self.experiment_run_refs.is_empty()
            || !self.work_artifact_refs.is_empty()
            || !self.semantic_digest_refs.is_empty()
            || (self.lifecycle_status == EpisodeLifecycle::Open
                && (self.boundary_status == BoundaryStatus::Confirmed
                    || self.exit_worktree_snapshot_id.is_some()))
            || (self.lifecycle_status != EpisodeLifecycle::Open
                && self.boundary_status != BoundaryStatus::Confirmed)
            || (self.boundary_status == BoundaryStatus::Confirmed
                && self.confirmation_watermark == 0)
            || (self.boundary_status != BoundaryStatus::Confirmed
                && self.confirmation_watermark != 0)
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), WorkError> {
        self.validate()?;
        next.validate()?;
        let next_generation = self
            .revision_generation
            .checked_add(1)
            .ok_or(WorkError::InvalidWorkIdentity)?;
        let lifecycle_ok = self.lifecycle_status == next.lifecycle_status
            || (self.lifecycle_status == EpisodeLifecycle::Open
                && matches!(
                    next.lifecycle_status,
                    EpisodeLifecycle::Closed | EpisodeLifecycle::Superseded
                ))
            || (self.lifecycle_status == EpisodeLifecycle::Closed
                && next.lifecycle_status == EpisodeLifecycle::Superseded);
        let boundary_ok = self.boundary_status == next.boundary_status
            || matches!(
                (self.boundary_status, next.boundary_status),
                (BoundaryStatus::Provisional, BoundaryStatus::Candidate)
                    | (BoundaryStatus::Candidate, BoundaryStatus::Provisional)
                    | (BoundaryStatus::Candidate, BoundaryStatus::Confirmed)
            );
        if next.episode_id != self.episode_id
            || next.revision_generation != next_generation
            || next.predecessor_revision_id != Some(self.revision_id)
            || next.revision_id == self.revision_id
            || next.task_id != self.task_id
            || next.workstream_id != self.workstream_id
            || next.repository_instance_id != self.repository_instance_id
            || next.worktree_instance_id != self.worktree_instance_id
            || next.phase_contract != self.phase_contract
            || next.entry_worktree_snapshot_id != self.entry_worktree_snapshot_id
            || next.source_watermark < self.source_watermark
            || next.semantic_watermark < self.semantic_watermark
            || next.confirmation_watermark < self.confirmation_watermark
            || next.capture_watermark < self.capture_watermark
            || !lifecycle_ok
            || !boundary_ok
            || self.lifecycle_status == EpisodeLifecycle::Superseded
            || (self.lifecycle_status == EpisodeLifecycle::Closed
                && next.lifecycle_status != EpisodeLifecycle::Superseded)
            || !retains(&self.session_ids, &next.session_ids)
            || !retains(&self.execution_lane_ids, &next.execution_lane_ids)
            || !retains(&self.attempt_ids, &next.attempt_ids)
            || !retains(
                &self.competing_attempt_group_ids,
                &next.competing_attempt_group_ids,
            )
            || !retains(&self.operation_burst_refs, &next.operation_burst_refs)
            || !retains(
                &self.worktree_transition_refs,
                &next.worktree_transition_refs,
            )
            || !retains(&self.failed_attempt_ids, &next.failed_attempt_ids)
            || !retains(&self.interrupted_attempt_ids, &next.interrupted_attempt_ids)
            || !retains(
                &self.returned_but_unselected_attempt_ids,
                &next.returned_but_unselected_attempt_ids,
            )
            || !retains(&self.selected_attempt_ids, &next.selected_attempt_ids)
            || !retains(&self.failure_refs, &next.failure_refs)
            || !retains(&self.interruption_refs, &next.interruption_refs)
            || !retains(&self.completed_outcome_refs, &next.completed_outcome_refs)
            || !retains(&self.selected_outcome_refs, &next.selected_outcome_refs)
            || !retains(&self.verification_refs, &next.verification_refs)
            || !retains(&self.checkpoint_refs, &next.checkpoint_refs)
            || !retains(&self.capture_gap_refs, &next.capture_gap_refs)
            || !retains(&self.capture_outage_refs, &next.capture_outage_refs)
            || !retains(
                &self.segmentation_correction_refs,
                &next.segmentation_correction_refs,
            )
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }
}

fn retains<T: Ord>(old: &[T], new: &[T]) -> bool {
    old.iter().all(|item| new.binary_search(item).is_ok())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointReason {
    Stop,
    SessionEnd,
    Compact,
    Idle,
    PhaseCandidate,
    Manual,
}

impl CheckpointReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::SessionEnd => "session_end",
            Self::Compact => "compact",
            Self::Idle => "idle",
            Self::PhaseCandidate => "phase_candidate",
            Self::Manual => "manual",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointVerifierState {
    Unverified,
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointAttemptRevisionRef {
    pub attempt_id: AttemptId,
    pub revision_id: RevisionId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkCheckpoint {
    pub episode_id: WorkEpisodeId,
    pub episode_revision_id: RevisionId,
    pub source_watermark: u64,
    pub active_attempt_ids: Vec<AttemptId>,
    pub attempt_revision_refs: Vec<CheckpointAttemptRevisionRef>,
    pub phase_contract: PhaseContract,
    pub open_loops: Vec<String>,
    pub verifier_state: CheckpointVerifierState,
    pub verifier_refs: Vec<String>,
    pub current_worktree_snapshot_id: Option<WorktreeSnapshotId>,
    pub pending_delta_stats: PendingDeltaStats,
    pub created_reason: CheckpointReason,
    pub continuation_candidate: bool,
    pub active_lineage_refs: Vec<String>,
    pub capture_receipt_revision_ids: Vec<CaptureReceiptId>,
    pub capture_gap_refs: Vec<String>,
    pub capture_outage_refs: Vec<CaptureOutageIntervalId>,
    pub algorithm_revision: u32,
}

impl WorkCheckpoint {
    pub fn stable_key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.episode_id,
            self.source_watermark,
            self.created_reason.as_str(),
            self.algorithm_revision
        )
    }

    pub fn validate(&self) -> Result<(), WorkError> {
        self.phase_contract.validate()?;
        if self.source_watermark == 0
            || self.algorithm_revision == 0
            || !ids(&self.active_attempt_ids)
            || !ids(&self.attempt_revision_refs)
            || !refs(&self.open_loops)
            || !refs(&self.verifier_refs)
            || !refs(&self.active_lineage_refs)
            || !ids(&self.capture_receipt_revision_ids)
            || !refs(&self.capture_gap_refs)
            || !ids(&self.capture_outage_refs)
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        Ok(())
    }

    pub fn derive(
        episode: &WorkEpisode,
        attempts: &[super::Attempt],
        snapshot: Option<&WorktreeSnapshot>,
        reason: CheckpointReason,
    ) -> Result<Self, WorkError> {
        episode.validate()?;
        let mut provided_attempt_ids = attempts
            .iter()
            .map(|attempt| attempt.attempt_id)
            .collect::<Vec<_>>();
        provided_attempt_ids.sort();
        if provided_attempt_ids != episode.attempt_ids
            || attempts.iter().any(|attempt| {
                attempt.validate().is_err()
                    || attempt.task_id != episode.task_id
                    || attempt.workstream_id != episode.workstream_id
                    || attempt.episode_id != Some(episode.episode_id)
                    || !episode.attempt_ids.contains(&attempt.attempt_id)
            })
            || snapshot.is_some_and(|value| {
                value.validate().is_err()
                    || episode.worktree_instance_id != Some(value.worktree_instance_id)
            })
        {
            return Err(WorkError::InvalidWorkIdentity);
        }
        let mut active_attempt_ids = attempts
            .iter()
            .filter(|attempt| {
                attempt.lifecycle_status == super::AttemptLifecycleStatus::Active
                    && matches!(
                        attempt.execution_status,
                        super::AttemptExecutionStatus::Proposed
                            | super::AttemptExecutionStatus::Active
                            | super::AttemptExecutionStatus::Interrupted
                    )
            })
            .map(|attempt| attempt.attempt_id)
            .collect::<Vec<_>>();
        active_attempt_ids.sort();
        let mut attempt_revision_refs = attempts
            .iter()
            .map(|attempt| CheckpointAttemptRevisionRef {
                attempt_id: attempt.attempt_id,
                revision_id: attempt.revision_id,
            })
            .collect::<Vec<_>>();
        attempt_revision_refs.sort();
        let has_passed = attempts
            .iter()
            .any(|attempt| attempt.verification == super::AttemptVerification::Passed);
        let has_failed = attempts
            .iter()
            .any(|attempt| attempt.verification == super::AttemptVerification::Failed);
        let has_inconclusive = attempts
            .iter()
            .any(|attempt| attempt.verification == super::AttemptVerification::Inconclusive);
        let verifier_state = if !attempts.is_empty()
            && attempts
                .iter()
                .all(|attempt| attempt.verification == super::AttemptVerification::Passed)
        {
            CheckpointVerifierState::Passed
        } else if has_failed && !has_passed && !has_inconclusive {
            CheckpointVerifierState::Failed
        } else if has_passed || has_failed || has_inconclusive {
            CheckpointVerifierState::Inconclusive
        } else {
            CheckpointVerifierState::Unverified
        };
        let mut verifier_refs = attempts
            .iter()
            .flat_map(|attempt| attempt.parent_verification_refs.iter().cloned())
            .collect::<Vec<_>>();
        verifier_refs.sort();
        verifier_refs.dedup();
        let checkpoint = Self {
            episode_id: episode.episode_id,
            episode_revision_id: episode.revision_id,
            source_watermark: episode.source_watermark,
            active_attempt_ids,
            attempt_revision_refs,
            phase_contract: episode.phase_contract.clone(),
            open_loops: episode.open_loops.clone(),
            verifier_state,
            verifier_refs,
            current_worktree_snapshot_id: snapshot.map(|value| value.worktree_snapshot_id),
            pending_delta_stats: episode.pending_delta_stats,
            created_reason: reason,
            continuation_candidate: episode.lifecycle_status == EpisodeLifecycle::Open,
            active_lineage_refs: episode
                .worktree_transition_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
            capture_receipt_revision_ids: episode.capture_receipt_revision_ids.clone(),
            capture_gap_refs: episode.capture_gap_refs.clone(),
            capture_outage_refs: episode.capture_outage_refs.clone(),
            algorithm_revision: EPISODE_ALGORITHM_REVISION,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }
}
