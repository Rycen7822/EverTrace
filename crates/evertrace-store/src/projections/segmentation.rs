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
}

impl SegmentationCurrentState {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let authority = SegmentationCurrentView::from_snapshot(snapshot)?;
        let bursts = OperationBurstCurrentView::from_snapshot(snapshot)?;
        if authority.frontier() != bursts.frontier() {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(Self { authority, bursts })
    }

    pub const fn frontier(&self) -> u64 {
        self.authority.frontier()
    }

    pub fn episode(&self, id: WorkEpisodeId) -> Option<&WorkEpisode> {
        self.authority.episode(id)
    }

    pub fn recent_bursts(&self, episode: &WorkEpisode) -> Result<Vec<OperationBurst>, StoreError> {
        self.bursts.recent_for_episode(episode)
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
        let mut revisions = BTreeMap::<OperationBurstId, Vec<OperationBurst>>::new();
        for row in snapshot
            .data_rows()
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
        Ok(Self {
            frontier: snapshot.frontier,
            bursts,
        })
    }

    pub const fn frontier(&self) -> u64 {
        self.frontier
    }

    pub fn recent_for_episode(
        &self,
        episode: &WorkEpisode,
    ) -> Result<Vec<OperationBurst>, StoreError> {
        if episode.operation_burst_refs.len() > 64 {
            return Err(StoreError::StoreCorrupt);
        }
        let mut values = episode
            .operation_burst_refs
            .iter()
            .map(|id| self.bursts.get(id).cloned().ok_or(StoreError::StoreCorrupt))
            .collect::<Result<Vec<_>, _>>()?;
        values.sort_by_key(|burst| burst.source_watermark);
        if values
            .windows(2)
            .any(|pair| pair[0].source_watermark >= pair[1].source_watermark)
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(values)
    }
}

impl EpisodeCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut view = Self {
            frontier: snapshot.frontier,
            ..Self::default()
        };
        let mut revisions = BTreeMap::<WorkEpisodeId, Vec<WorkEpisode>>::new();
        for row in snapshot.data_rows() {
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
        let binding_view = WorkBindingCurrentView::from_snapshot(snapshot)?;
        let attempt_view = AttemptCurrentView::from_snapshot(snapshot)?;
        let episode_view = EpisodeCurrentView::from_snapshot(snapshot)?;
        let work_view = WorkIdentityCurrentView::from_snapshot(snapshot)?;
        let mut view = Self {
            frontier: snapshot.frontier,
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
        for row in snapshot.data_rows() {
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
            if revisions.first().is_none_or(|value| {
                value.lane_revision != 1 || value.predecessor_revision.is_some()
            }) || revisions.windows(2).any(|pair| {
                pair[0].lane_revision.checked_add(1) != Some(pair[1].lane_revision)
                    || pair[1].predecessor_revision != Some(pair[0].lane_revision)
            }) {
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
    operation_revisions: &BTreeMap<(OperationId, u32), (Operation, u64)>,
    host_occurrences: &BTreeMap<HostOccurrenceId, (HostOccurrence, u64)>,
    source_observations: &BTreeMap<SourceObservationId, (SourceObservation, u64)>,
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
                || burst.members.iter().any(|member| {
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
                    let Some((occurrence, _)) = host_occurrences.get(&member.host_occurrence_id)
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
    }
    Ok(())
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
