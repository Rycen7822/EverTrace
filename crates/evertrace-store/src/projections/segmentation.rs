use std::collections::BTreeMap;

use evertrace_domain::{
    evidence::{HostOccurrence, Operation, ScopeEffect},
    ids::{
        AttemptId, CaptureReceiptId, CompetingAttemptGroupId, ExecutionLaneId, HostOccurrenceId,
        OperationId, ScopeEffectId, WorkEpisodeId, WorkstreamId,
    },
    work::{
        Attempt, CaptureReceipt, CompetingAttemptGroup, ExecutionLane, WorkBindingRevision,
        WorkEpisode, Workstream,
    },
};

use super::*;

pub(super) fn record_episode(
    current: &mut BTreeMap<WorkEpisodeId, (WorkEpisode, u64)>,
    revisions: &mut BTreeMap<evertrace_domain::revision::RevisionId, (WorkEpisode, u64)>,
    value: WorkEpisode,
    seq: u64,
) -> Result<(), StoreError> {
    if let Some((existing, _)) = revisions.get(&value.revision_id) {
        return if existing == &value {
            Ok(())
        } else {
            Err(StoreError::StoreCorrupt)
        };
    }
    match current.get(&value.episode_id) {
        None if value.validate().is_err()
            || value.revision_generation != 1
            || value.predecessor_revision_id.is_some() =>
        {
            return Err(StoreError::StoreCorrupt);
        }
        None => {}
        Some((existing, _)) if existing == &value => return Ok(()),
        Some((existing, _)) => existing
            .validate_successor(&value)
            .map_err(|_| StoreError::StoreCorrupt)?,
    }
    current.insert(value.episode_id, (value.clone(), seq));
    revisions.insert(value.revision_id, (value, seq));
    Ok(())
}

pub(super) fn record_operation_burst(
    current: &mut BTreeMap<OperationBurstId, (OperationBurst, u64)>,
    revisions: &mut BTreeMap<evertrace_domain::revision::RevisionId, (OperationBurst, u64)>,
    value: OperationBurst,
    seq: u64,
) -> Result<(), StoreError> {
    if let Some((existing, _)) = revisions.get(&value.revision_id) {
        return if existing == &value {
            Ok(())
        } else {
            Err(StoreError::StoreCorrupt)
        };
    }
    match current.get(&value.operation_burst_id) {
        None if value.validate().is_err()
            || value.revision_generation != 1
            || value.predecessor_revision_id.is_some() =>
        {
            return Err(StoreError::StoreCorrupt);
        }
        None => {}
        Some((existing, _)) if existing == &value => return Ok(()),
        Some((existing, _)) => existing
            .validate_successor(&value)
            .map_err(|_| StoreError::StoreCorrupt)?,
    }
    current.insert(value.operation_burst_id, (value.clone(), seq));
    revisions.insert(value.revision_id, (value, seq));
    Ok(())
}

pub(super) fn record_checkpoint(
    values: &mut BTreeMap<String, (WorkCheckpoint, u64)>,
    value: WorkCheckpoint,
    seq: u64,
) -> Result<(), StoreError> {
    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
    let key = value.stable_key();
    if let Some((existing, _)) = values.get(&key) {
        return if existing == &value {
            Ok(())
        } else {
            Err(StoreError::StoreCorrupt)
        };
    }
    values.insert(key, (value, seq));
    Ok(())
}

pub(super) fn record_correction(
    values: &mut BTreeMap<evertrace_domain::revision::RevisionId, (SegmentationCorrection, u64)>,
    value: SegmentationCorrection,
    seq: u64,
) -> Result<(), StoreError> {
    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
    if let Some((existing, _)) = values.get(&value.correction_revision_id) {
        return if existing == &value {
            Ok(())
        } else {
            Err(StoreError::StoreCorrupt)
        };
    }
    if let Some(predecessor) = value.predecessor_revision_id {
        let previous = values
            .get(&predecessor)
            .map(|entry| &entry.0)
            .ok_or(StoreError::StoreCorrupt)?;
        let related = value.source_episode_ids.iter().any(|id| {
            previous.source_episode_ids.contains(id)
                || previous.replacement_episode_ids.contains(id)
        });
        if !related
            || values
                .values()
                .any(|(existing, _)| existing.predecessor_revision_id == Some(predecessor))
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    values.insert(value.correction_revision_id, (value, seq));
    Ok(())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EpisodeCurrentView {
    pub frontier: u64,
    pub episodes: BTreeMap<WorkEpisodeId, WorkEpisode>,
    pub checkpoints: BTreeMap<String, WorkCheckpoint>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OperationBurstCurrentView {
    frontier: u64,
    bursts: BTreeMap<OperationBurstId, OperationBurst>,
}

/// One store-owned, single-frontier segmentation authority snapshot.
#[derive(Clone, Debug)]
pub struct SegmentationCurrentState {
    authority: SegmentationCurrentView,
    bursts: OperationBurstCurrentView,
    episode_window: Option<WorkEpisodeId>,
}

/// One pending canonical activity and its bounded, single-frontier authority.
#[derive(Clone, Debug)]
pub struct SegmentationReadContext {
    pub operation_id: OperationId,
    pub sequence: u64,
    pub episode_id: WorkEpisodeId,
    pub state: SegmentationCurrentState,
    pub root_refs: Vec<String>,
    pub source_refs: Vec<evertrace_domain::ids::SourceObservationId>,
    pub repository_ids: std::collections::BTreeSet<evertrace_domain::ids::RepositoryId>,
    pub snapshot: Option<evertrace_domain::repository::WorktreeSnapshot>,
    pub candidate_checkpointed: bool,
}

fn boundary_context<'a>(
    episode: &WorkEpisode,
    bursts: impl Iterator<Item = &'a OperationBurst> + Clone,
) -> Result<Vec<&'a OperationBurst>, StoreError> {
    let Some(candidate) = &episode.boundary_candidate else {
        return Ok(vec![]);
    };
    let owned = bursts.filter(|burst| {
        burst.primary_binding.episode_id == Some(episode.episode_id)
            && episode
                .operation_burst_refs
                .binary_search(&burst.operation_burst_id)
                .is_ok()
    });
    let mut anchors = owned.clone().filter(|burst| {
        burst
            .members
            .iter()
            .any(|member| member.source_watermark == candidate.candidate_watermark)
    });
    let anchor = anchors.next().ok_or(StoreError::StoreCorrupt)?;
    if anchors.next().is_some() {
        return Err(StoreError::StoreCorrupt);
    }
    let first = anchor
        .members
        .first()
        .ok_or(StoreError::StoreCorrupt)?
        .source_watermark;
    let left = (first == candidate.candidate_watermark)
        .then(|| {
            owned
                .filter(|burst| burst.source_watermark < first)
                .max_by_key(|burst| burst.source_watermark)
        })
        .flatten();
    Ok(left.into_iter().chain(std::iter::once(anchor)).collect())
}

#[derive(Clone, Copy)]
enum CheckpointTarget<'a> {
    Source(
        &'a BTreeSet<SourceObservationId>,
        evertrace_domain::work::CheckpointReason,
    ),
    Idle(&'a BTreeSet<WorkEpisodeId>),
}

impl CheckpointTarget<'_> {
    fn reason(self) -> evertrace_domain::work::CheckpointReason {
        match self {
            Self::Source(_, reason) => reason,
            Self::Idle(_) => evertrace_domain::work::CheckpointReason::Idle,
        }
    }

    fn matches(self, operation: &Operation, binding: &WorkBindingRevision) -> bool {
        match self {
            Self::Source(sources, _) => operation
                .input_source_observation_refs
                .iter()
                .any(|id| sources.contains(id)),
            Self::Idle(episodes) => binding
                .primary_binding
                .episode_id
                .is_some_and(|id| episodes.contains(&id)),
        }
    }
}

impl JournalAdmissionState {
    pub(crate) fn segmentation_current_context(
        &self,
        after: u64,
    ) -> Result<Option<SegmentationReadContext>, StoreError> {
        self.activity_context(after, None, &mut |_| Ok(false))
    }

    pub(crate) fn checkpoint_current_context(
        &self,
        sources: &BTreeSet<SourceObservationId>,
        trigger: SourceObservationId,
        reason: evertrace_domain::work::CheckpointReason,
        causation: &mut dyn FnMut(u64) -> Result<Option<String>, StoreError>,
    ) -> Result<Option<SegmentationReadContext>, StoreError> {
        let trigger_seq = self
            .source_observations
            .get(&trigger)
            .ok_or(StoreError::InvalidInput)?
            .1;
        let trigger = trigger.to_string();
        let mut checked = BTreeMap::new();
        let mut completed = |episode_id| {
            if let Some(value) = checked.get(&episode_id) {
                return Ok(*value);
            }
            let episode = &self
                .episodes
                .get(&episode_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            let mut found = false;
            for key in &episode.checkpoint_refs {
                let (checkpoint, seq) =
                    self.checkpoints.get(key).ok_or(StoreError::StoreCorrupt)?;
                if *seq > trigger_seq
                    && checkpoint.created_reason == reason
                    && causation(*seq)?.as_deref() == Some(trigger.as_str())
                {
                    found = true;
                    break;
                }
            }
            checked.insert(episode_id, found);
            Ok(found)
        };
        self.activity_context(
            0,
            Some(CheckpointTarget::Source(sources, reason)),
            &mut completed,
        )
    }

    pub(crate) fn idle_checkpoint_current_context(
        &self,
        episodes: &BTreeSet<WorkEpisodeId>,
    ) -> Result<Option<SegmentationReadContext>, StoreError> {
        self.activity_context(0, Some(CheckpointTarget::Idle(episodes)), &mut |_| {
            Ok(false)
        })
    }

    fn activity_context(
        &self,
        after: u64,
        checkpoint: Option<CheckpointTarget<'_>>,
        completed: &mut dyn FnMut(WorkEpisodeId) -> Result<bool, StoreError>,
    ) -> Result<Option<SegmentationReadContext>, StoreError> {
        use evertrace_domain::{evidence::CorrelationStrength, work::AssignmentStatus};
        let mut bindings = BTreeMap::<OperationId, (&WorkBindingRevision, u64)>::new();
        for (binding, sequence) in self.work_bindings.values() {
            let current = bindings
                .entry(binding.operation_id)
                .or_insert((binding, *sequence));
            if binding.revision_generation > current.0.revision_generation {
                *current = (binding, *sequence);
            }
        }
        let mut selected: Option<(&Operation, &WorkBindingRevision, u64, &WorkEpisode)> = None;
        for (operation, operation_sequence) in self.operations.values() {
            let Some((binding, binding_sequence)) = bindings
                .get(&operation.operation_id)
                .filter(|(binding, _)| binding.assignment_status == AssignmentStatus::Resolved)
            else {
                continue;
            };
            let sequence = (*operation_sequence).max(*binding_sequence);
            if sequence <= after
                || checkpoint.is_some_and(|target| !target.matches(operation, binding))
            {
                continue;
            };
            let Some((episode, _)) = binding
                .primary_binding
                .episode_id
                .and_then(|id| self.episodes.get(&id))
            else {
                continue;
            };
            if episode.lifecycle_status != evertrace_domain::work::EpisodeLifecycle::Open
                || binding.primary_binding.task_id != Some(episode.task_id)
                || binding.primary_binding.workstream_id != Some(episode.workstream_id)
                || self.workstreams.get(&episode.workstream_id).is_none_or(|(stream, _)| {
                    stream.active_episode_id != Some(episode.episode_id)
                })
                || self.host_occurrences.get(&operation.host_occurrence_id).is_none_or(|(occurrence, _)| {
                    occurrence.correlation_strength != CorrelationStrength::Exact
                        || occurrence.normalization_state == evertrace_domain::evidence::NormalizationState::NormalizationConflicted
                        || occurrence.possible_duplicate_group_id.is_some()
                })
                || operation.execution_lane_id.is_none()
                || completed(episode.episode_id)?
            {
                continue;
            }
            if let Some(target) = checkpoint {
                let reason = target.reason();
                let saved = episode.checkpoint_refs.iter().any(|key| {
                    self.checkpoints.get(key).is_some_and(|(value, _)| {
                        value.created_reason == reason
                            && value.source_watermark == episode.source_watermark
                    })
                });
                if saved {
                    continue;
                }
            }
            let mut consumed = false;
            for id in &episode.operation_burst_refs {
                let (burst, _) = self
                    .operation_bursts
                    .get(id)
                    .ok_or(StoreError::StoreCorrupt)?;
                consumed |= burst.members.iter().any(|member| {
                    member.operation_id == operation.operation_id
                        && member.operation_revision == operation.operation_revision
                });
            }
            if consumed == checkpoint.is_some()
                && selected.is_none_or(|(_, _, previous, _)| sequence < previous)
            {
                selected = Some((operation, *binding, sequence, episode));
            }
        }
        let Some((operation, binding, sequence, episode)) = selected else {
            return Ok(None);
        };
        let occurrence = &self
            .host_occurrences
            .get(&operation.host_occurrence_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        let stream = &self
            .workstreams
            .get(&episode.workstream_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        let task = &self
            .tasks
            .get(&episode.task_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        let mut lanes = BTreeMap::new();
        let mut receipts = BTreeMap::new();
        for id in episode
            .execution_lane_ids
            .iter()
            .copied()
            .chain(operation.execution_lane_id)
        {
            let lane = &self
                .execution_lanes
                .get(&id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            let receipt = &self
                .capture_receipt_revisions
                .get(&lane.active_capture_receipt_revision_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            lanes.insert(id, lane.clone());
            receipts.insert(receipt.capture_receipt_revision_id, receipt.clone());
        }
        let mut scope_effects = BTreeMap::new();
        let mut source_refs = occurrence
            .source_observation_refs
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        source_refs.extend(operation.input_source_observation_refs.iter().copied());
        source_refs.extend(operation.result_source_observation_refs.iter().copied());
        let mut repository_ids = stream
            .repository_instance_id
            .into_iter()
            .collect::<BTreeSet<_>>();
        for id in &operation.scope_effect_ids {
            let effect = &self
                .scope_effects
                .get(id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            source_refs.extend(effect.evidence_refs.iter().copied());
            repository_ids.extend(effect.repository_instance_id);
            scope_effects.insert(*id, effect.clone());
        }
        let mut attempts = BTreeMap::new();
        for id in episode
            .attempt_ids
            .iter()
            .copied()
            .chain(binding.primary_binding.attempt_id)
        {
            attempts.insert(
                id,
                self.attempts
                    .get(&id)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0
                    .clone(),
            );
        }
        let mut groups = BTreeMap::new();
        if let Some(id) = binding.primary_binding.competing_group_id {
            groups.insert(
                id,
                self.competing_groups
                    .get(&id)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0
                    .clone(),
            );
        }
        source_refs.extend(
            binding
                .evidence_refs
                .iter()
                .filter_map(|reference| reference.parse::<SourceObservationId>().ok())
                .filter(|id| self.source_observations.contains_key(id)),
        );
        let mut recent = BTreeMap::new();
        for id in &episode.operation_burst_refs {
            let burst = &self
                .operation_bursts
                .get(id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            recent.insert((burst.source_watermark, *id), burst);
            if recent.len() > 64 {
                recent.pop_first();
            }
        }
        let context = boundary_context(
            episode,
            episode
                .operation_burst_refs
                .iter()
                .filter_map(|id| self.operation_bursts.get(id).map(|(burst, _)| burst)),
        )?;
        for burst in context {
            for member in &burst.members {
                source_refs.extend(member.source_observation_refs.iter().copied());
            }
            recent.insert((burst.source_watermark, burst.operation_burst_id), burst);
        }
        let authority = SegmentationCurrentView {
            frontier: self.frontier,
            occurrences: BTreeMap::from([(occurrence.host_occurrence_id, occurrence.clone())]),
            operations: BTreeMap::from([(operation.operation_id, operation.clone())]),
            bindings: BTreeMap::from([(operation.operation_id, binding.clone())]),
            lanes,
            receipts,
            scope_effects,
            attempts,
            groups,
            episodes: BTreeMap::from([(episode.episode_id, episode.clone())]),
            workstreams: BTreeMap::from([(stream.workstream_id, stream.clone())]),
        };
        let snapshot = episode
            .worktree_instance_id
            .and_then(|id| self.worktrees.get(&id))
            .and_then(|(tree, _)| tree.current_snapshot_id)
            .map(|id| {
                self.worktree_snapshots
                    .get(&id)
                    .map(|(snapshot, _)| snapshot.clone())
                    .ok_or(StoreError::StoreCorrupt)
            })
            .transpose()?;
        let candidate_checkpointed = if let Some(candidate) = &episode.boundary_candidate {
            let mut saved = false;
            for key in &episode.checkpoint_refs {
                let checkpoint = &self.checkpoints.get(key).ok_or(StoreError::StoreCorrupt)?.0;
                saved |= checkpoint.created_reason
                    == evertrace_domain::work::CheckpointReason::PhaseCandidate
                    && checkpoint.source_watermark >= candidate.candidate_watermark;
            }
            saved
        } else {
            false
        };
        Ok(Some(SegmentationReadContext {
            operation_id: operation.operation_id,
            sequence,
            episode_id: episode.episode_id,
            state: SegmentationCurrentState {
                authority,
                bursts: OperationBurstCurrentView {
                    frontier: self.frontier,
                    bursts: recent
                        .into_values()
                        .map(|burst| (burst.operation_burst_id, burst.clone()))
                        .collect(),
                },
                episode_window: Some(episode.episode_id),
            },
            root_refs: task.request_root_refs.clone(),
            source_refs: source_refs.into_iter().collect(),
            repository_ids,
            snapshot,
            candidate_checkpointed,
        }))
    }
}

impl SegmentationCurrentState {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let authority = SegmentationCurrentView::from_snapshot(snapshot)?;
        let bursts = OperationBurstCurrentView::from_snapshot(snapshot)?;
        if authority.frontier() != bursts.frontier() {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(Self {
            authority,
            bursts,
            episode_window: None,
        })
    }

    pub const fn frontier(&self) -> u64 {
        self.authority.frontier()
    }

    pub fn episode(&self, id: WorkEpisodeId) -> Option<&WorkEpisode> {
        self.authority.episode(id)
    }

    pub fn recent_bursts(&self, episode: &WorkEpisode) -> Result<Vec<OperationBurst>, StoreError> {
        match self.episode_window {
            None => self.bursts.recent_for_episode(episode),
            Some(id) if id == episode.episode_id => {
                let mut bursts = self.bursts.bursts.values().collect::<Vec<_>>();
                bursts.sort_by_key(|burst| burst.source_watermark);
                let start = bursts.len().saturating_sub(64);
                Ok(bursts.into_iter().skip(start).cloned().collect())
            }
            Some(_) => Err(StoreError::StoreCorrupt),
        }
    }

    /// At most the candidate's left neighbor and anchor; separate from rolling statistics.
    pub fn boundary_bursts(
        &self,
        episode: &WorkEpisode,
    ) -> Result<Vec<OperationBurst>, StoreError> {
        if self
            .episode_window
            .is_some_and(|id| id != episode.episode_id)
        {
            return Err(StoreError::StoreCorrupt);
        }
        boundary_context(episode, self.bursts.bursts.values())
            .map(|bursts| bursts.into_iter().cloned().collect())
    }

    pub fn current_burst(&self, id: OperationBurstId) -> Option<&OperationBurst> {
        self.bursts.bursts.get(&id)
    }

    pub const fn authority(&self) -> &SegmentationCurrentView {
        &self.authority
    }
}

impl OperationBurstCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        Self::from_rows(snapshot.frontier, &snapshot.rows)
    }

    pub fn from_rows(frontier: u64, rows: &[super::ObjectRow]) -> Result<Self, StoreError> {
        let mut revisions = BTreeMap::<OperationBurstId, Vec<OperationBurst>>::new();
        for row in rows
            .iter()
            .filter(|row| row.row_kind == super::ObjectRowKind::Data)
            .filter(|row| row.object_kind.as_deref() == Some("operation_burst"))
        {
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            let JournalPayload::OperationBurstRecorded(value) = payload else {
                return Err(StoreError::StoreCorrupt);
            };
            if row.row_id != format!("object:work:operation_burst:{}", value.revision_id) {
                return Err(StoreError::StoreCorrupt);
            }
            revisions
                .entry(value.operation_burst_id)
                .or_default()
                .push(*value);
        }
        let mut bursts = BTreeMap::new();
        for (id, mut values) in revisions {
            values.sort_by_key(|value| value.revision_generation);
            for (index, value) in values.iter().enumerate() {
                value.validate().map_err(|_| StoreError::StoreCorrupt)?;
                if value.revision_generation
                    != u64::try_from(index + 1).map_err(|_| StoreError::StoreCorrupt)?
                    || value.predecessor_revision_id
                        != index
                            .checked_sub(1)
                            .map(|previous| values[previous].revision_id)
                {
                    return Err(StoreError::StoreCorrupt);
                }
                if let Some(previous) = index.checked_sub(1) {
                    values[previous]
                        .validate_successor(value)
                        .map_err(|_| StoreError::StoreCorrupt)?;
                }
            }
            bursts.insert(id, values.pop().ok_or(StoreError::StoreCorrupt)?);
        }
        Ok(Self { frontier, bursts })
    }

    pub const fn frontier(&self) -> u64 {
        self.frontier
    }

    pub fn recent_for_episode(
        &self,
        episode: &WorkEpisode,
    ) -> Result<Vec<OperationBurst>, StoreError> {
        let mut values = episode
            .operation_burst_refs
            .iter()
            .map(|id| self.bursts.get(id).ok_or(StoreError::StoreCorrupt))
            .collect::<Result<Vec<_>, _>>()?;
        values.sort_by_key(|burst| burst.source_watermark);
        if values
            .windows(2)
            .any(|pair| pair[0].source_watermark >= pair[1].source_watermark)
        {
            return Err(StoreError::StoreCorrupt);
        }
        let start = values.len().saturating_sub(64);
        Ok(values.into_iter().skip(start).cloned().collect())
    }
}

impl EpisodeCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        Self::from_rows(snapshot.frontier, &snapshot.rows)
    }

    pub fn from_rows(frontier: u64, rows: &[super::ObjectRow]) -> Result<Self, StoreError> {
        let mut view = Self {
            frontier,
            ..Self::default()
        };
        let mut revisions = BTreeMap::<WorkEpisodeId, Vec<WorkEpisode>>::new();
        for row in rows
            .iter()
            .filter(|row| row.row_kind == super::ObjectRowKind::Data)
        {
            match row.object_kind.as_deref() {
                Some("work_episode") => {
                    let payload: JournalPayload = serde_json::from_str(
                        row.payload_json
                            .as_deref()
                            .ok_or(StoreError::StoreCorrupt)?,
                    )
                    .map_err(|_| StoreError::StoreCorrupt)?;
                    let JournalPayload::WorkEpisodeRecorded(value) = payload else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    if row.row_id != format!("object:work:work_episode:{}", value.revision_id) {
                        return Err(StoreError::StoreCorrupt);
                    }
                    revisions.entry(value.episode_id).or_default().push(*value);
                }
                Some("work_checkpoint") => {
                    let payload: JournalPayload = serde_json::from_str(
                        row.payload_json
                            .as_deref()
                            .ok_or(StoreError::StoreCorrupt)?,
                    )
                    .map_err(|_| StoreError::StoreCorrupt)?;
                    let JournalPayload::WorkCheckpointRecorded(value) = payload else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    let key = value.stable_key();
                    if row.row_id != format!("object:work:work_checkpoint:{key}")
                        || view.checkpoints.insert(key, *value).is_some()
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                _ => {}
            }
        }
        for (id, mut values) in revisions {
            values.sort_by_key(|value| value.revision_generation);
            for (index, value) in values.iter().enumerate() {
                value.validate().map_err(|_| StoreError::StoreCorrupt)?;
                if value.revision_generation
                    != u64::try_from(index + 1).map_err(|_| StoreError::StoreCorrupt)?
                    || value.predecessor_revision_id
                        != index
                            .checked_sub(1)
                            .map(|previous| values[previous].revision_id)
                {
                    return Err(StoreError::StoreCorrupt);
                }
                if let Some(previous) = index.checked_sub(1) {
                    values[previous]
                        .validate_successor(value)
                        .map_err(|_| StoreError::StoreCorrupt)?;
                }
            }
            view.episodes
                .insert(id, values.pop().ok_or(StoreError::StoreCorrupt)?);
        }
        Ok(view)
    }
}

/// Store-owned, typed current truth consumed by the incremental segmenter.
///
/// The maps stay private so callers cannot assemble a parallel authority view.
#[derive(Clone, Debug)]
pub struct SegmentationCurrentView {
    frontier: u64,
    occurrences: BTreeMap<HostOccurrenceId, HostOccurrence>,
    operations: BTreeMap<OperationId, Operation>,
    bindings: BTreeMap<OperationId, WorkBindingRevision>,
    lanes: BTreeMap<ExecutionLaneId, ExecutionLane>,
    receipts: BTreeMap<CaptureReceiptId, CaptureReceipt>,
    scope_effects: BTreeMap<ScopeEffectId, ScopeEffect>,
    attempts: BTreeMap<AttemptId, Attempt>,
    groups: BTreeMap<CompetingAttemptGroupId, CompetingAttemptGroup>,
    episodes: BTreeMap<WorkEpisodeId, WorkEpisode>,
    workstreams: BTreeMap<WorkstreamId, Workstream>,
}

impl SegmentationCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        Self::from_rows(snapshot.frontier, &snapshot.rows)
    }

    pub fn from_rows(frontier: u64, rows: &[super::ObjectRow]) -> Result<Self, StoreError> {
        let binding_view = WorkBindingCurrentView::from_rows(frontier, rows)?;
        let attempt_view = AttemptCurrentView::from_rows(frontier, rows)?;
        let episode_view = EpisodeCurrentView::from_rows(frontier, rows)?;
        let work_view = WorkIdentityCurrentView::from_rows(frontier, rows)?;
        let mut view = Self {
            frontier,
            occurrences: BTreeMap::new(),
            operations: BTreeMap::new(),
            bindings: binding_view.bindings,
            lanes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            scope_effects: BTreeMap::new(),
            attempts: attempt_view.attempts,
            groups: attempt_view.competing_groups,
            episodes: episode_view.episodes,
            workstreams: work_view.workstreams,
        };
        let mut occurrence_revisions = BTreeMap::<HostOccurrenceId, Vec<HostOccurrence>>::new();
        let mut operation_revisions = BTreeMap::<OperationId, Vec<Operation>>::new();
        let mut lane_revisions = BTreeMap::<ExecutionLaneId, Vec<ExecutionLane>>::new();
        for row in rows
            .iter()
            .filter(|row| row.row_kind == super::ObjectRowKind::Data)
        {
            let Some(kind) = row.object_kind.as_deref() else {
                continue;
            };
            if kind == "operation_revision" {
                return Err(StoreError::StoreCorrupt);
            }
            if !matches!(
                kind,
                "host_occurrence"
                    | "operation"
                    | "scope_effect"
                    | "execution_lane"
                    | "capture_receipt"
            ) {
                continue;
            }
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            match payload {
                JournalPayload::HostOccurrenceNormalized(value) if kind == "host_occurrence" => {
                    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
                    occurrence_revisions
                        .entry(value.host_occurrence_id)
                        .or_default()
                        .push(*value);
                }
                JournalPayload::OperationDerived(value) if kind == "operation" => {
                    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
                    operation_revisions
                        .entry(value.operation_id)
                        .or_default()
                        .push(*value);
                }
                JournalPayload::ScopeEffectDerived(value) if kind == "scope_effect" => {
                    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
                    insert_once(&mut view.scope_effects, value.scope_effect_id, *value)?;
                }
                JournalPayload::ExecutionLaneRecorded(value) if kind == "execution_lane" => {
                    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
                    lane_revisions
                        .entry(value.execution_lane_id)
                        .or_default()
                        .push(*value);
                }
                JournalPayload::CaptureReceiptRecorded(value) if kind == "capture_receipt" => {
                    value.validate().map_err(|_| StoreError::StoreCorrupt)?;
                    insert_once(
                        &mut view.receipts,
                        value.capture_receipt_revision_id,
                        *value,
                    )?;
                }
                _ => return Err(StoreError::StoreCorrupt),
            }
        }
        view.occurrences = fold_occurrence_revisions(occurrence_revisions)?;
        view.operations = fold_operation_revisions(operation_revisions)?;
        view.lanes = fold_lane_revisions(lane_revisions)?;
        Ok(view)
    }

    pub const fn frontier(&self) -> u64 {
        self.frontier
    }
    pub fn occurrence(&self, id: HostOccurrenceId) -> Option<&HostOccurrence> {
        self.occurrences.get(&id)
    }
    pub fn operation(&self, id: OperationId) -> Option<&Operation> {
        self.operations.get(&id)
    }
    pub fn operation_for_observation(
        &self,
        id: evertrace_domain::ids::SourceObservationId,
    ) -> Result<Option<&Operation>, StoreError> {
        let mut matches = self.operations.values().filter(|operation| {
            operation.input_source_observation_refs.contains(&id)
                || operation.result_source_observation_refs.contains(&id)
        });
        let value = matches.next();
        if matches.next().is_some() {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(value)
    }
    pub fn binding(&self, id: OperationId) -> Option<&WorkBindingRevision> {
        self.bindings.get(&id)
    }
    pub fn lane(&self, id: ExecutionLaneId) -> Option<&ExecutionLane> {
        self.lanes.get(&id)
    }
    pub fn receipt(&self, id: CaptureReceiptId) -> Option<&CaptureReceipt> {
        self.receipts.get(&id)
    }
    pub fn scope_effect(&self, id: ScopeEffectId) -> Option<&ScopeEffect> {
        self.scope_effects.get(&id)
    }
    pub fn attempt(&self, id: AttemptId) -> Option<&Attempt> {
        self.attempts.get(&id)
    }
    pub fn group(&self, id: CompetingAttemptGroupId) -> Option<&CompetingAttemptGroup> {
        self.groups.get(&id)
    }
    pub fn episode(&self, id: WorkEpisodeId) -> Option<&WorkEpisode> {
        self.episodes.get(&id)
    }
    pub fn workstream(&self, id: WorkstreamId) -> Option<&Workstream> {
        self.workstreams.get(&id)
    }
}

fn insert_once<K: Ord, V>(map: &mut BTreeMap<K, V>, key: K, value: V) -> Result<(), StoreError> {
    if map.insert(key, value).is_some() {
        Err(StoreError::StoreCorrupt)
    } else {
        Ok(())
    }
}

fn fold_occurrence_revisions(
    values: BTreeMap<HostOccurrenceId, Vec<HostOccurrence>>,
) -> Result<BTreeMap<HostOccurrenceId, HostOccurrence>, StoreError> {
    values
        .into_iter()
        .map(|(id, mut revisions)| {
            revisions.sort_by_key(|value| value.normalization_revision);
            if revisions.first().is_none_or(|value| {
                value.normalization_revision != 1 || value.previous_normalization_revision.is_some()
            }) || revisions.windows(2).any(|pair| {
                pair[0].normalization_revision.checked_add(1)
                    != Some(pair[1].normalization_revision)
                    || pair[1].previous_normalization_revision
                        != Some(pair[0].normalization_revision)
            }) {
                return Err(StoreError::StoreCorrupt);
            }
            Ok((id, revisions.pop().ok_or(StoreError::StoreCorrupt)?))
        })
        .collect()
}

fn fold_operation_revisions(
    values: BTreeMap<OperationId, Vec<Operation>>,
) -> Result<BTreeMap<OperationId, Operation>, StoreError> {
    values
        .into_iter()
        .map(|(id, mut revisions)| {
            revisions.sort_by_key(|value| value.operation_revision);
            if revisions.first().is_none_or(|value| {
                value.operation_revision != 1 || value.previous_operation_revision.is_some()
            }) || revisions.windows(2).any(|pair| {
                pair[0].operation_revision.checked_add(1) != Some(pair[1].operation_revision)
                    || pair[1].previous_operation_revision != Some(pair[0].operation_revision)
            }) {
                return Err(StoreError::StoreCorrupt);
            }
            Ok((id, revisions.pop().ok_or(StoreError::StoreCorrupt)?))
        })
        .collect()
}

fn fold_lane_revisions(
    values: BTreeMap<ExecutionLaneId, Vec<ExecutionLane>>,
) -> Result<BTreeMap<ExecutionLaneId, ExecutionLane>, StoreError> {
    values
        .into_iter()
        .map(|(id, mut revisions)| {
            revisions.sort_by_key(|value| value.lane_revision);
            // Projection rows retain the current lane, not its full journal history.
            // Each row is validated above; any supplied adjacent revisions must still agree.
            if revisions.is_empty()
                || revisions.windows(2).any(|pair| {
                    pair[0].lane_revision.checked_add(1) != Some(pair[1].lane_revision)
                        || pair[1].predecessor_revision != Some(pair[0].lane_revision)
                })
            {
                return Err(StoreError::StoreCorrupt);
            }
            Ok((id, revisions.pop().ok_or(StoreError::StoreCorrupt)?))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_episode_relations(
    episodes: &BTreeMap<WorkEpisodeId, (WorkEpisode, u64)>,
    episode_revisions: &BTreeMap<evertrace_domain::revision::RevisionId, (WorkEpisode, u64)>,
    checkpoints: &BTreeMap<String, (WorkCheckpoint, u64)>,
    corrections: &BTreeMap<evertrace_domain::revision::RevisionId, (SegmentationCorrection, u64)>,
    tasks: &BTreeMap<TaskId, (Task, u64)>,
    workstreams: &BTreeMap<WorkstreamId, (Workstream, u64)>,
    attempts: &BTreeMap<AttemptId, (Attempt, u64)>,
    attempt_revisions: &BTreeMap<evertrace_domain::revision::RevisionId, (Attempt, u64)>,
    competing_groups: &BTreeMap<CompetingAttemptGroupId, (CompetingAttemptGroup, u64)>,
    bindings: &BTreeMap<WorkBindingRevisionId, (WorkBindingRevision, u64)>,
    operation_bursts: &BTreeMap<OperationBurstId, (OperationBurst, u64)>,
    burst_revisions: &BTreeMap<evertrace_domain::revision::RevisionId, (OperationBurst, u64)>,
    operation_revisions: &BTreeMap<(OperationId, u32), (Operation, u64)>,
    occurrence_revisions: &BTreeMap<(HostOccurrenceId, u32), (HostOccurrence, u64)>,
    source_observations: &super::SourceObservationFacts,
    scope_effects: &BTreeMap<ScopeEffectId, (ScopeEffect, u64)>,
    lanes: &BTreeMap<ExecutionLaneId, (ExecutionLane, u64)>,
    receipt_revisions: &BTreeMap<evertrace_domain::ids::CaptureReceiptId, (CaptureReceipt, u64)>,
    capture_gaps: &BTreeMap<String, (CaptureGapMarkerEvidence, u64)>,
    capture_outages: &BTreeMap<CaptureOutageIntervalId, (CaptureOutageInterval, u64)>,
    worktree_snapshots: &BTreeMap<WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
    worktree_transitions: &BTreeMap<WorktreeTransitionId, (WorktreeTransition, u64)>,
    integration_events: &BTreeMap<IntegrationEventId, (IntegrationEvent, u64)>,
) -> Result<(), StoreError> {
    let mut open_by_workstream = BTreeMap::new();
    let mut burst_owners = BTreeMap::new();
    for (episode_id, (episode, _)) in episodes {
        episode.validate().map_err(|_| StoreError::StoreCorrupt)?;
        let task = &tasks
            .get(&episode.task_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        let workstream = &workstreams
            .get(&episode.workstream_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        if task.task_id != workstream.task_id
            || episode.task_id != workstream.task_id
            || episode.repository_instance_id != workstream.repository_instance_id
            || episode
                .worktree_instance_id
                .is_some_and(|id| !workstream.worktree_instance_ids.contains(&id))
        {
            return Err(StoreError::StoreCorrupt);
        }
        if episode.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Open
            && (open_by_workstream
                .insert(episode.workstream_id, *episode_id)
                .is_some()
                || workstream.active_episode_id != Some(*episode_id))
        {
            return Err(StoreError::StoreCorrupt);
        }
        if episode.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Open
            && episode.phase_contract != workstream.phase_contract
        {
            return Err(StoreError::StoreCorrupt);
        }
        for attempt_id in &episode.attempt_ids {
            let attempt = &attempts.get(attempt_id).ok_or(StoreError::StoreCorrupt)?.0;
            if attempt.task_id != episode.task_id
                || attempt.workstream_id != episode.workstream_id
                || attempt.episode_id != Some(*episode_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for selected_id in &episode.selected_attempt_ids {
            let attempt = &attempts.get(selected_id).ok_or(StoreError::StoreCorrupt)?.0;
            if attempt.adoption_status != AttemptAdoptionStatus::Integrated
                || attempt.verification != AttemptVerification::Passed
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for lane_id in &episode.execution_lane_ids {
            if !lanes.contains_key(lane_id) {
                return Err(StoreError::StoreCorrupt);
            }
        }
        let pinned_receipts = episode
            .capture_receipt_revision_ids
            .iter()
            .map(|receipt_id| {
                receipt_revisions
                    .get(receipt_id)
                    .map(|value| &value.0)
                    .ok_or(StoreError::StoreCorrupt)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut receipt_lane_ids = pinned_receipts
            .iter()
            .map(|receipt| receipt.execution_lane_id)
            .collect::<Vec<_>>();
        receipt_lane_ids.sort();
        let mut gap_union = pinned_receipts
            .iter()
            .flat_map(|receipt| receipt.capture_gap_marker_refs.iter().cloned())
            .collect::<Vec<_>>();
        gap_union.sort();
        gap_union.dedup();
        let mut outage_union = pinned_receipts
            .iter()
            .flat_map(|receipt| receipt.capture_outage_interval_refs.iter().copied())
            .collect::<Vec<_>>();
        outage_union.sort();
        outage_union.dedup();
        if receipt_lane_ids != episode.execution_lane_ids
            || receipt_lane_ids.windows(2).any(|pair| pair[0] == pair[1])
            || gap_union != episode.capture_gap_refs
            || outage_union != episode.capture_outage_refs
            || gap_union
                .iter()
                .any(|reference| !capture_gaps.contains_key(reference))
            || outage_union
                .iter()
                .any(|id| !capture_outages.contains_key(id))
            || evertrace_domain::work::CaptureSummary::from_receipts(
                &pinned_receipts
                    .iter()
                    .map(|value| (*value).clone())
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| StoreError::StoreCorrupt)?
                != episode.capture_summary
            || pinned_receipts
                .iter()
                .map(|receipt| receipt.import_watermark)
                .min()
                .unwrap_or(0)
                != episode.capture_watermark
        {
            return Err(StoreError::StoreCorrupt);
        }
        let mut episode_operation_revisions = BTreeMap::new();
        for burst_id in &episode.operation_burst_refs {
            let burst = &operation_bursts
                .get(burst_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            let member_cuts = burst_member_cuts(burst, burst_revisions)?;
            if burst_owners.insert(*burst_id, *episode_id).is_some()
                || !episode
                    .execution_lane_ids
                    .contains(&burst.execution_lane_id)
                || burst
                    .attempt_id
                    .is_some_and(|id| !episode.attempt_ids.contains(&id))
                || burst.primary_binding.attempt_id != burst.attempt_id
                || burst.primary_binding.experiment_run_id != burst.experiment_run_id
                || burst.primary_binding.competing_group_id != burst.competing_group_id
                || burst.attempt_id.is_some_and(|id| {
                    attempts.get(&id).is_none_or(|(attempt, _)| {
                        burst
                            .experiment_run_id
                            .is_some_and(|run| !attempt.experiment_run_ids.contains(&run))
                            || burst
                                .competing_group_id
                                .is_some_and(|group| !attempt.competing_group_ids.contains(&group))
                    })
                })
                || burst.competing_group_id.is_some_and(|id| {
                    competing_groups.get(&id).is_none_or(|(group, _)| {
                        burst
                            .attempt_id
                            .is_none_or(|attempt| !group.member_attempt_ids.contains(&attempt))
                    })
                })
                || burst.members.iter().enumerate().any(|(index, member)| {
                    if episode_operation_revisions
                        .insert((member.operation_id, member.operation_revision), *burst_id)
                        .is_some()
                    {
                        return true;
                    }
                    let Some((operation, _)) =
                        operation_revisions.get(&(member.operation_id, member.operation_revision))
                    else {
                        return true;
                    };
                    let Some((_, (occurrence, _))) = occurrence_revisions
                        .range(
                            (member.host_occurrence_id, 0)..=(member.host_occurrence_id, u32::MAX),
                        )
                        .rev()
                        .find(|(_, (_, sequence))| *sequence <= member_cuts[index])
                    else {
                        return true;
                    };
                    let Some((binding, _)) = bindings.get(&member.work_binding_revision_id) else {
                        return true;
                    };
                    let effects = member
                        .scope_effect_refs
                        .iter()
                        .map(|id| scope_effects.get(id).map(|value| &value.0))
                        .collect::<Option<Vec<_>>>();
                    let Some(effects) = effects else {
                        return true;
                    };
                    let member_attempt = member
                        .attempt_revision_id
                        .and_then(|id| attempt_revisions.get(&id).map(|value| &value.0));
                    let expected_transitions = member_attempt.map_or(&[][..], |attempt| {
                        attempt.worktree_transition_refs.as_slice()
                    });
                    let expected_integrations = member_attempt
                        .map_or(&[][..], |attempt| attempt.integration_event_refs.as_slice());
                    !member_has_exact_physical_provenance(
                        member, burst, operation, occurrence, &effects,
                    ) || binding.operation_id != member.operation_id
                        || binding.primary_binding != burst.primary_binding
                        || member_attempt.map(|attempt| attempt.attempt_id) != burst.attempt_id
                        || member
                            .source_observation_refs
                            .iter()
                            .any(|id| !source_observations.contains_key(id))
                        || expected_transitions != member.worktree_transition_refs
                        || expected_integrations != member.integration_event_refs
                        || member
                            .worktree_transition_refs
                            .iter()
                            .any(|id| !worktree_transitions.contains_key(id))
                        || member
                            .integration_event_refs
                            .iter()
                            .any(|id| !integration_events.contains_key(id))
                })
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        let open_bursts = episode
            .operation_burst_refs
            .iter()
            .filter(|id| {
                operation_bursts.get(id).is_some_and(|(burst, _)| {
                    burst.lifecycle == evertrace_domain::work::OperationBurstLifecycle::Open
                })
            })
            .count();
        if open_bursts
            > usize::from(
                episode.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Open,
            )
        {
            return Err(StoreError::StoreCorrupt);
        }
        if let Some(candidate) = &episode.boundary_candidate {
            let source_closure = episode
                .operation_burst_refs
                .iter()
                .filter_map(|id| operation_bursts.get(id))
                .flat_map(|(burst, _)| burst.members.iter())
                .flat_map(|member| member.source_observation_refs.iter().copied())
                .collect::<BTreeSet<_>>();
            if candidate.candidate_watermark > episode.source_watermark
                || episode.confirmation_watermark != 0
                || candidate
                    .evidence_refs
                    .iter()
                    .any(|id| !source_closure.contains(id))
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for key in &episode.checkpoint_refs {
            let checkpoint = &checkpoints.get(key).ok_or(StoreError::StoreCorrupt)?.0;
            if checkpoint.episode_id != *episode_id {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for correction_id in &episode.segmentation_correction_refs {
            let correction = &corrections
                .get(correction_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            if !correction.source_episode_ids.contains(episode_id) {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    for (workstream_id, (workstream, _)) in workstreams {
        if workstream.active_episode_id != open_by_workstream.get(workstream_id).copied() {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for (attempt_id, (attempt, _)) in attempts {
        if let Some(episode_id) = attempt.episode_id {
            let episode = &episodes.get(&episode_id).ok_or(StoreError::StoreCorrupt)?.0;
            if episode.task_id != attempt.task_id
                || episode.workstream_id != attempt.workstream_id
                || !episode.attempt_ids.contains(attempt_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    for (binding, _) in bindings.values() {
        if let Some(episode_id) = binding.primary_binding.episode_id {
            let episode = &episodes.get(&episode_id).ok_or(StoreError::StoreCorrupt)?.0;
            if binding.assignment_status != AssignmentStatus::Resolved
                || binding.primary_binding.task_id != Some(episode.task_id)
                || binding.primary_binding.workstream_id != Some(episode.workstream_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    for burst_id in operation_bursts.keys() {
        if !episodes
            .values()
            .any(|(episode, _)| episode.operation_burst_refs.contains(burst_id))
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for (key, (checkpoint, checkpoint_seq)) in checkpoints {
        if !episodes
            .get(&checkpoint.episode_id)
            .is_some_and(|(episode, _)| episode.checkpoint_refs.contains(key))
        {
            return Err(StoreError::StoreCorrupt);
        }
        let referenced_episode = episode_revisions
            .get(&checkpoint.episode_revision_id)
            .map(|value| &value.0)
            .ok_or(StoreError::StoreCorrupt)?;
        if referenced_episode.episode_id != checkpoint.episode_id {
            return Err(StoreError::StoreCorrupt);
        }
        let referenced_attempts = checkpoint
            .attempt_revision_refs
            .iter()
            .map(|reference| {
                let latest = attempt_revisions
                    .values()
                    .filter(|(attempt, seq)| {
                        attempt.attempt_id == reference.attempt_id && seq <= checkpoint_seq
                    })
                    .max_by_key(|(_, seq)| *seq)
                    .ok_or(StoreError::StoreCorrupt)?;
                if latest.0.revision_id != reference.revision_id {
                    return Err(StoreError::StoreCorrupt);
                }
                Ok(latest.0.clone())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let snapshot = checkpoint
            .current_worktree_snapshot_id
            .map(|id| {
                worktree_snapshots
                    .get(&id)
                    .map(|value| &value.0)
                    .ok_or(StoreError::StoreCorrupt)
            })
            .transpose()?;
        if let Some(snapshot) = snapshot
            && latest_snapshot_at(
                worktree_snapshots,
                snapshot.worktree_instance_id,
                *checkpoint_seq,
            )?
            .worktree_snapshot_id
                != snapshot.worktree_snapshot_id
        {
            return Err(StoreError::StoreCorrupt);
        }
        let expected = WorkCheckpoint::derive(
            referenced_episode,
            &referenced_attempts,
            snapshot,
            checkpoint.created_reason,
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        if key != &checkpoint.stable_key() || checkpoint != &expected {
            return Err(StoreError::StoreCorrupt);
        }
    }
    let mut capture_corrections = BTreeSet::new();
    let needed_receipts = corrections
        .values()
        .filter(|(value, _)| value.kind == evertrace_domain::work::CorrectionKind::CaptureRevision)
        .flat_map(|(value, _)| &value.evidence_refs)
        .map(|id| {
            id.parse::<evertrace_domain::ids::CaptureReceiptId>()
                .map_err(|_| StoreError::StoreCorrupt)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut receipt_successors = BTreeMap::new();
    if !needed_receipts.is_empty() {
        for (receipt, sequence) in receipt_revisions.values() {
            if let Some(parent) = receipt
                .predecessor_revision_id
                .filter(|id| needed_receipts.contains(id))
            {
                receipt_successors
                    .entry(parent)
                    .and_modify(|old: &mut u64| *old = (*old).min(*sequence))
                    .or_insert(*sequence);
            }
        }
    }
    for (episode, sequence) in episode_revisions.values() {
        let Some((previous, _)) = episode
            .predecessor_revision_id
            .and_then(|id| episode_revisions.get(&id))
        else {
            continue;
        };
        if previous.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Closed
            && episode.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Closed
            && previous.segmentation_correction_refs != episode.segmentation_correction_refs
        {
            let added = episode
                .segmentation_correction_refs
                .iter()
                .find(|id| !previous.segmentation_correction_refs.contains(id))
                .ok_or(StoreError::StoreCorrupt)?;
            let correction = &corrections.get(added).ok_or(StoreError::StoreCorrupt)?.0;
            if correction.kind != evertrace_domain::work::CorrectionKind::CaptureRevision
                || !capture_corrections.insert(*added)
            {
                return Err(StoreError::StoreCorrupt);
            }
            validate_capture_correction(
                correction,
                episode,
                *sequence,
                episode_revisions,
                receipt_revisions,
                corrections,
                &receipt_successors,
            )?;
        }
    }
    for (id, (correction, _)) in corrections {
        if id != &correction.correction_revision_id
            || correction
                .source_episode_ids
                .iter()
                .any(|episode_id| !episodes.contains_key(episode_id))
            || correction
                .replacement_episode_ids
                .iter()
                .any(|episode_id| !episodes.contains_key(episode_id))
            || correction.source_episode_ids.iter().any(|episode_id| {
                episodes
                    .get(episode_id)
                    .is_none_or(|(episode, _)| !episode.segmentation_correction_refs.contains(id))
            })
        {
            return Err(StoreError::StoreCorrupt);
        }
        if correction.kind == evertrace_domain::work::CorrectionKind::CaptureRevision
            && !capture_corrections.contains(id)
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    Ok(())
}

fn validate_capture_correction(
    correction: &SegmentationCorrection,
    episode: &WorkEpisode,
    sequence: u64,
    episodes: &BTreeMap<evertrace_domain::revision::RevisionId, (WorkEpisode, u64)>,
    receipts: &BTreeMap<evertrace_domain::ids::CaptureReceiptId, (CaptureReceipt, u64)>,
    corrections: &BTreeMap<evertrace_domain::revision::RevisionId, (SegmentationCorrection, u64)>,
    receipt_successors: &BTreeMap<evertrace_domain::ids::CaptureReceiptId, u64>,
) -> Result<(), StoreError> {
    let Some((previous, _)) = episode
        .predecessor_revision_id
        .and_then(|id| episodes.get(&id))
    else {
        return Err(StoreError::StoreCorrupt);
    };
    if previous
        .segmentation_correction_refs
        .contains(&correction.correction_revision_id)
    {
        return Err(StoreError::StoreCorrupt);
    }
    let predecessor = previous
        .segmentation_correction_refs
        .iter()
        .filter_map(|id| corrections.get(id))
        .max_by_key(|(_, sequence)| sequence)
        .map(|(value, _)| value.correction_revision_id);
    if correction.source_episode_ids != vec![episode.episode_id]
        || correction.predecessor_revision_id != predecessor
        || previous.lifecycle_status != evertrace_domain::work::EpisodeLifecycle::Closed
        || episode.lifecycle_status != evertrace_domain::work::EpisodeLifecycle::Closed
        || correction.source_watermark != episode.source_watermark
    {
        return Err(StoreError::StoreCorrupt);
    }
    previous
        .validate_successor(episode)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut evidence = Vec::new();
    for id in episode
        .capture_receipt_revision_ids
        .iter()
        .filter(|id| !previous.capture_receipt_revision_ids.contains(id))
    {
        let (receipt, receipt_seq) = receipts.get(id).ok_or(StoreError::StoreCorrupt)?;
        if *receipt_seq > sequence
            || receipt_successors
                .get(id)
                .is_some_and(|next| *next <= sequence)
        {
            return Err(StoreError::StoreCorrupt);
        }
        let mut ancestor = receipt;
        while !previous
            .capture_receipt_revision_ids
            .contains(&ancestor.capture_receipt_revision_id)
        {
            ancestor = &receipts
                .get(
                    &ancestor
                        .predecessor_revision_id
                        .ok_or(StoreError::StoreCorrupt)?,
                )
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            if ancestor.execution_lane_id != receipt.execution_lane_id {
                return Err(StoreError::StoreCorrupt);
            }
        }
        evidence.push(id.to_string());
    }
    evidence.sort();
    if evidence.is_empty() || evidence != correction.evidence_refs {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

/// A retained member keeps the occurrence closure that existed when it first entered this burst.
/// Later normalization may add sources without rewriting that immutable member.
fn burst_member_cuts(
    burst: &OperationBurst,
    revisions: &BTreeMap<evertrace_domain::revision::RevisionId, (OperationBurst, u64)>,
) -> Result<Vec<u64>, StoreError> {
    let (_, sequence) = revisions
        .get(&burst.revision_id)
        .ok_or(StoreError::StoreCorrupt)?;
    let mut cuts = vec![*sequence; burst.members.len()];
    let mut previous = burst.predecessor_revision_id;
    while let Some(id) = previous {
        let (revision, sequence) = revisions.get(&id).ok_or(StoreError::StoreCorrupt)?;
        for cut in cuts.iter_mut().take(revision.members.len()) {
            *cut = *sequence;
        }
        previous = revision.predecessor_revision_id;
    }
    Ok(cuts)
}

fn member_has_exact_physical_provenance(
    member: &evertrace_domain::work::OperationBurstMember,
    burst: &OperationBurst,
    operation: &Operation,
    occurrence: &HostOccurrence,
    effects: &[&ScopeEffect],
) -> bool {
    let mut expected_sources = occurrence.source_observation_refs.clone();
    expected_sources.extend(&operation.input_source_observation_refs);
    expected_sources.extend(&operation.result_source_observation_refs);
    expected_sources.extend(
        effects
            .iter()
            .flat_map(|effect| effect.evidence_refs.iter().copied()),
    );
    expected_sources.sort();
    expected_sources.dedup();
    let mut expected_artifacts = operation.artifact_refs.clone();
    expected_artifacts.extend(
        effects
            .iter()
            .flat_map(|effect| effect.artifact_refs.iter().copied()),
    );
    expected_artifacts.sort();
    expected_artifacts.dedup();
    let mut expected_side_effects = effects
        .iter()
        .map(|effect| effect.effect_role)
        .collect::<Vec<_>>();
    expected_side_effects.sort();
    expected_side_effects.dedup();
    operation.operation_revision == member.operation_revision
        && operation.host_occurrence_id == member.host_occurrence_id
        && operation.execution_lane_id == Some(burst.execution_lane_id)
        && operation.operation_kind == burst.operation_kind
        && occurrence.host_occurrence_id == operation.host_occurrence_id
        && operation.scope_effect_ids == member.scope_effect_refs
        && effects
            .iter()
            .all(|effect| effect.operation_id == member.operation_id)
        && expected_sources == member.source_observation_refs
        && expected_artifacts == member.artifact_refs
        && expected_side_effects == member.side_effects
}

fn latest_snapshot_at(
    snapshots: &BTreeMap<WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
    worktree_id: WorktreeId,
    at_seq: u64,
) -> Result<&WorktreeSnapshot, StoreError> {
    snapshots
        .values()
        .filter(|(candidate, seq)| candidate.worktree_instance_id == worktree_id && *seq <= at_seq)
        .max_by_key(|(_, seq)| *seq)
        .map(|(snapshot, _)| snapshot)
        .ok_or(StoreError::StoreCorrupt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use evertrace_domain::evidence::{
        CorrelationStrength, NormalizationState, OperationKind, PairingState,
    };
    use evertrace_domain::ids::{OperationBurstId, WorkBindingRevisionId};
    use evertrace_domain::repository::{GitOperation, SnapshotCaptureStatus};
    use evertrace_domain::revision::RevisionId;
    use evertrace_domain::work::{
        OperationBurstLifecycle, OperationBurstMember, OperationStateDelta, OperationVerifierDelta,
        PrimaryWorkBinding,
    };

    fn snapshot(worktree_instance_id: WorktreeId, captured_at_us: i64) -> WorktreeSnapshot {
        WorktreeSnapshot {
            worktree_snapshot_id: WorktreeSnapshotId::new_v7(),
            worktree_instance_id,
            head_oid: None,
            tree_oid: None,
            branch_ref: None,
            detached_head: false,
            tracked_diff_digest: None,
            index_digest: None,
            untracked_manifest_digest: None,
            relevant_anchor_digests: vec![],
            dependency_fingerprints: vec![],
            toolchain_fingerprint: None,
            git_operation: GitOperation::None,
            captured_at_us,
            evidence_refs: vec![],
            capture_status: SnapshotCaptureStatus::Unavailable,
            omission_reasons: vec![],
        }
    }

    #[test]
    fn checkpoint_snapshot_must_be_latest_visible_for_its_worktree() {
        let worktree_id = WorktreeId::new_v7();
        let old = snapshot(worktree_id, 1);
        let latest = snapshot(worktree_id, 2);
        let values = BTreeMap::from([
            (old.worktree_snapshot_id, (old.clone(), 10)),
            (latest.worktree_snapshot_id, (latest.clone(), 20)),
        ]);
        assert_eq!(
            latest_snapshot_at(&values, worktree_id, 15)
                .unwrap()
                .worktree_snapshot_id,
            old.worktree_snapshot_id
        );
        assert_eq!(
            latest_snapshot_at(&values, worktree_id, 20)
                .unwrap()
                .worktree_snapshot_id,
            latest.worktree_snapshot_id
        );
    }

    #[test]
    fn burst_member_rejects_missing_or_extra_physical_provenance() {
        let source: SourceObservationId =
            "obs:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap();
        let extra: SourceObservationId =
            "obs:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .unwrap();
        let occurrence_id = HostOccurrenceId::from_digest([7; 32]);
        let operation_id = OperationId::new_v7();
        let lane_id = ExecutionLaneId::new_v7();
        let occurrence = HostOccurrence {
            host_occurrence_id: occurrence_id,
            exact_key: None,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            correlation_strength: CorrelationStrength::Unavailable,
            source_observation_refs: vec![source],
            field_provenance: vec![],
            normalization_state: NormalizationState::SingleSource,
            pairing_state: PairingState::UnmatchedIntent,
            possible_duplicate_group_id: None,
            correlation_resolver_version: 1,
            normalization_revision: 1,
            previous_normalization_revision: None,
        };
        let operation = Operation {
            source_local_pairing: None,
            operation_id,
            host_occurrence_id: occurrence_id,
            execution_lane_id: Some(lane_id),
            operation_kind: OperationKind::Read,
            input_source_observation_refs: vec![source],
            result_source_observation_refs: vec![],
            pairing_state: PairingState::UnmatchedIntent,
            scope_effect_ids: vec![],
            artifact_refs: vec![],
            operation_resolver_version: 1,
            operation_revision: 1,
            previous_operation_revision: None,
        };
        let member = OperationBurstMember {
            sequence: 1,
            source_watermark: 1,
            operation_id,
            operation_revision: 1,
            host_occurrence_id: occurrence_id,
            work_binding_revision_id: WorkBindingRevisionId::new_v7(),
            attempt_revision_id: None,
            source_observation_refs: vec![source],
            scope_effect_refs: vec![],
            artifact_refs: vec![],
            side_effects: vec![],
            worktree_transition_refs: vec![],
            integration_event_refs: vec![],
        };
        let burst = OperationBurst {
            operation_burst_id: OperationBurstId::new_v7(),
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            revision_generation: 1,
            lifecycle: OperationBurstLifecycle::Open,
            algorithm_revision: 1,
            operation_kind: OperationKind::Read,
            state_delta: OperationStateDelta::None,
            verifier_delta: OperationVerifierDelta::None,
            phase_candidate: None,
            has_objective_boundary: false,
            error_signature: None,
            target_family: "test".into(),
            target_refs: vec![],
            members: vec![member.clone()],
            execution_lane_id: lane_id,
            parent_lane_id: None,
            subagent_id: None,
            primary_binding: PrimaryWorkBinding::default(),
            attempt_id: None,
            experiment_run_id: None,
            competing_group_id: None,
            worktree_lineage_refs: vec![],
            strategy_contract_fingerprint: None,
            source_watermark: 1,
        };
        assert!(member_has_exact_physical_provenance(
            &member,
            &burst,
            &operation,
            &occurrence,
            &[],
        ));
        let mut forged = member;
        forged.source_observation_refs.push(extra);
        forged.source_observation_refs.sort();
        assert!(!member_has_exact_physical_provenance(
            &forged,
            &burst,
            &operation,
            &occurrence,
            &[],
        ));
    }
}
