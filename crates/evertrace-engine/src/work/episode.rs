use evertrace_domain::{
    ids::{WorkEpisodeId, WorktreeSnapshotId},
    revision::RevisionId,
    work::{
        Attempt, BoundaryStatus, CaptureSummary, EpisodeLifecycle, PendingDeltaStats,
        PendingSemanticInterval, WorkBindingRevision, WorkEpisode, Workstream,
    },
};
use evertrace_store::{JournalCommand, JournalEventDraft, JournalPayload};

use super::{WorkCommandContext, WorkIdentityError};

pub fn new_episode(
    workstream: &Workstream,
    entry_snapshot: Option<WorktreeSnapshotId>,
    source_watermark: u64,
) -> Result<WorkEpisode, WorkIdentityError> {
    if workstream.active_episode_id.is_some()
        || workstream.status.is_terminal()
        || source_watermark < workstream.source_watermark
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    let episode = WorkEpisode {
        episode_id: WorkEpisodeId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        revision_generation: 1,
        task_id: workstream.task_id,
        workstream_id: workstream.workstream_id,
        repository_instance_id: workstream.repository_instance_id,
        worktree_instance_id: workstream.active_worktree_instance_id,
        phase_contract: workstream.phase_contract.clone(),
        lifecycle_status: EpisodeLifecycle::Open,
        boundary_status: BoundaryStatus::Provisional,
        source_watermark,
        semantic_watermark: 0,
        confirmation_watermark: 0,
        capture_watermark: 0,
        entry_worktree_snapshot_id: entry_snapshot,
        exit_worktree_snapshot_id: None,
        session_ids: vec![],
        execution_lane_ids: vec![],
        attempt_ids: vec![],
        competing_attempt_group_ids: vec![],
        operation_burst_refs: vec![],
        worktree_transition_refs: vec![],
        failed_attempt_ids: vec![],
        interrupted_attempt_ids: vec![],
        returned_but_unselected_attempt_ids: vec![],
        selected_attempt_ids: vec![],
        failure_refs: vec![],
        interruption_refs: vec![],
        completed_outcome_refs: vec![],
        selected_outcome_refs: vec![],
        verification_refs: vec![],
        open_loops: vec![],
        checkpoint_refs: vec![],
        capture_receipt_revision_ids: vec![],
        capture_gap_refs: vec![],
        capture_outage_refs: vec![],
        pending_delta_stats: PendingDeltaStats::default(),
        pending_semantic_delta: (source_watermark > 0).then_some(PendingSemanticInterval {
            after_watermark: 0,
            through_watermark: source_watermark,
        }),
        boundary_candidate: None,
        capture_summary: CaptureSummary::default(),
        segmentation_correction_refs: vec![],
        experiment_run_refs: vec![],
        work_artifact_refs: vec![],
        semantic_digest_refs: vec![],
    };
    episode
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(episode)
}

pub fn next_episode(
    workstream: &Workstream,
    current: &WorkEpisode,
    phase_contract: evertrace_domain::work::PhaseContract,
    entry_snapshot: Option<WorktreeSnapshotId>,
    source_watermark: u64,
) -> Result<WorkEpisode, WorkIdentityError> {
    if workstream.active_episode_id != Some(current.episode_id)
        || current.lifecycle_status != EpisodeLifecycle::Open
        || current.task_id != workstream.task_id
        || current.workstream_id != workstream.workstream_id
        || phase_contract == current.phase_contract
        || source_watermark < current.source_watermark
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    let mut basis = workstream.clone();
    basis.active_episode_id = None;
    basis.phase_contract = phase_contract;
    basis.source_watermark = source_watermark;
    new_episode(&basis, entry_snapshot, source_watermark)
}

pub fn confirm_episode_boundary(
    current: &WorkEpisode,
    step: &crate::segmentation::IncrementalSegmentationStep,
    exit_snapshot: Option<WorktreeSnapshotId>,
    pinned_receipts: &[evertrace_domain::work::CaptureReceipt],
) -> Result<WorkEpisode, WorkIdentityError> {
    let update = step.detector();
    let confirmation_watermark = update.confirmation_watermark();
    if current.lifecycle_status != EpisodeLifecycle::Open
        || current.boundary_status != BoundaryStatus::Candidate
        || update.episode_id() != current.episode_id
        || update.boundary_status() != BoundaryStatus::Confirmed
        || update.token_watermark() != confirmation_watermark
        || update.confirmation_evidence_refs().is_empty()
        || confirmation_watermark <= current.source_watermark
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    revise_episode_from_step(current, step, pinned_receipts, true, exit_snapshot)
}

fn revise_episode_from_step(
    current: &WorkEpisode,
    step: &crate::segmentation::IncrementalSegmentationStep,
    pinned_receipts: &[evertrace_domain::work::CaptureReceipt],
    confirming: bool,
    exit_snapshot: Option<WorktreeSnapshotId>,
) -> Result<WorkEpisode, WorkIdentityError> {
    let token = step.token();
    let burst = step.burst();
    let update = step.detector();
    if token.episode_id() != current.episode_id
        || token.task_id() != current.task_id
        || token.workstream_id() != current.workstream_id
        || token.source_watermark() < current.source_watermark
        || update.episode_id() != current.episode_id
        || update.token_watermark() != token.source_watermark()
        || (update.boundary_status() == BoundaryStatus::Confirmed) != confirming
        || burst.current().source_watermark != token.source_watermark()
        || current.lifecycle_status != EpisodeLifecycle::Open
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    let mut provided_receipt_ids = pinned_receipts
        .iter()
        .map(|receipt| receipt.capture_receipt_revision_id)
        .collect::<Vec<_>>();
    provided_receipt_ids.sort();
    provided_receipt_ids.dedup();
    let mut provided_lane_ids = pinned_receipts
        .iter()
        .map(|receipt| receipt.execution_lane_id)
        .collect::<Vec<_>>();
    provided_lane_ids.sort();
    let mut expected_lane_ids = current.execution_lane_ids.clone();
    expected_lane_ids.push(token.execution_lane_id());
    expected_lane_ids.sort();
    expected_lane_ids.dedup();
    if provided_receipt_ids.len() != pinned_receipts.len()
        || provided_lane_ids.len() != pinned_receipts.len()
        || provided_lane_ids.windows(2).any(|pair| pair[0] == pair[1])
        || provided_lane_ids != expected_lane_ids
        || !provided_receipt_ids.contains(&token.capture_receipt().capture_receipt_revision_id)
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    let mut next = current.clone();
    next.revision_id = step.episode_successor_revision_id();
    next.predecessor_revision_id = Some(current.revision_id);
    next.revision_generation = current
        .revision_generation
        .checked_add(1)
        .ok_or(WorkIdentityError::InvalidInput)?;
    next.source_watermark = token.source_watermark();
    next.boundary_status = update.boundary_status();
    next.boundary_candidate = update.candidate_watermark().map(|candidate_watermark| {
        evertrace_domain::work::BoundaryCandidateState {
            candidate_phase_kind: update.candidate_phase_kind(),
            candidate_watermark,
            evidence_refs: update.candidate_evidence_refs().to_vec(),
            kind: update
                .candidate_kind()
                .expect("candidate watermark requires candidate kind"),
            refinement_progress: update.refinement_progress(),
        }
    });
    next.session_ids.push(token.session_id().to_owned());
    next.execution_lane_ids.push(token.execution_lane_id());
    if let Some(id) = token.attempt_id() {
        next.attempt_ids.push(id);
    }
    if let Some(id) = token.competing_group_id() {
        next.competing_attempt_group_ids.push(id);
    }
    next.worktree_transition_refs
        .extend_from_slice(token.worktree_transition_refs());
    next.operation_burst_refs
        .push(burst.current().operation_burst_id);
    if !burst.no_delta() {
        next.pending_delta_stats.selected_token_count = next
            .pending_delta_stats
            .selected_token_count
            .checked_add(1)
            .ok_or(WorkIdentityError::InvalidInput)?;
    }
    if burst.meaningful_new() {
        next.pending_delta_stats.meaningful_burst_count = next
            .pending_delta_stats
            .meaningful_burst_count
            .checked_add(1)
            .ok_or(WorkIdentityError::InvalidInput)?;
    }
    if token.boundary_evidence() != crate::segmentation::BoundaryEvidence::None
        || token.verifier_transition() != crate::segmentation::VerifierTransition::None
    {
        next.pending_delta_stats.high_value_signal_count = next
            .pending_delta_stats
            .high_value_signal_count
            .checked_add(1)
            .ok_or(WorkIdentityError::InvalidInput)?;
    }
    next.capture_receipt_revision_ids = provided_receipt_ids;
    next.capture_gap_refs = pinned_receipts
        .iter()
        .flat_map(|receipt| receipt.capture_gap_marker_refs.iter().cloned())
        .collect();
    next.capture_outage_refs = pinned_receipts
        .iter()
        .flat_map(|receipt| receipt.capture_outage_interval_refs.iter().copied())
        .collect();
    next.capture_watermark = pinned_receipts
        .iter()
        .map(|receipt| receipt.import_watermark)
        .min()
        .unwrap_or(0);
    next.capture_summary = evertrace_domain::work::CaptureSummary::from_receipts(pinned_receipts)
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    next.pending_semantic_delta =
        (next.semantic_watermark < next.source_watermark).then_some(PendingSemanticInterval {
            after_watermark: next.semantic_watermark,
            through_watermark: next.source_watermark,
        });
    if confirming {
        next.lifecycle_status = EpisodeLifecycle::Closed;
        next.boundary_status = BoundaryStatus::Confirmed;
        next.boundary_candidate = None;
        next.confirmation_watermark = update.confirmation_watermark();
        next.exit_worktree_snapshot_id = exit_snapshot;
    }
    sort_unique(&mut next.session_ids);
    sort_unique(&mut next.execution_lane_ids);
    sort_unique(&mut next.attempt_ids);
    sort_unique(&mut next.competing_attempt_group_ids);
    sort_unique(&mut next.worktree_transition_refs);
    sort_unique(&mut next.operation_burst_refs);
    sort_unique(&mut next.capture_gap_refs);
    sort_unique(&mut next.capture_outage_refs);
    current
        .validate_successor(&next)
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(next)
}

pub fn save_segmentation_update(
    context: WorkCommandContext,
    current: &WorkEpisode,
    step: &crate::segmentation::IncrementalSegmentationStep,
    pinned_receipts: &[evertrace_domain::work::CaptureReceipt],
) -> Result<JournalCommand, WorkIdentityError> {
    let successor = revise_episode_from_step(current, step, pinned_receipts, false, None)?;
    let burst = step.burst();
    let burst_payloads = burst
        .closed()
        .into_iter()
        .chain((!burst.no_delta()).then_some(burst.current()))
        .cloned()
        .map(|value| JournalPayload::OperationBurstRecorded(Box::new(value)));
    let payloads = burst_payloads.chain(std::iter::once(JournalPayload::WorkEpisodeRecorded(
        Box::new(successor),
    )));
    let events = payloads
        .map(|payload| {
            JournalEventDraft::runtime(
                context.occurred_at_us,
                context.effective_config_hash,
                context.algorithm_revision,
                payload,
            )
        })
        .collect();
    JournalCommand::new(context.command_id, events).map_err(Into::into)
}

pub fn link_attempt_to_episode(
    current: &Attempt,
    episode: &WorkEpisode,
    source_watermark: u64,
) -> Result<Attempt, WorkIdentityError> {
    if current.episode_id.is_some()
        || current.task_id != episode.task_id
        || current.workstream_id != episode.workstream_id
        || episode.lifecycle_status != EpisodeLifecycle::Open
        || source_watermark <= current.source_watermark
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    let mut next = current.clone();
    next.revision_id = RevisionId::new_v7();
    next.predecessor_revision_id = Some(current.revision_id);
    next.revision_generation = current
        .revision_generation
        .checked_add(1)
        .ok_or(WorkIdentityError::InvalidInput)?;
    next.episode_id = Some(episode.episode_id);
    next.source_watermark = source_watermark;
    current
        .validate_successor(&next)
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(next)
}

pub fn link_binding_to_episode(
    current: &WorkBindingRevision,
    episode: &WorkEpisode,
) -> Result<WorkBindingRevision, WorkIdentityError> {
    if current.assignment_status != evertrace_domain::work::AssignmentStatus::Resolved
        || current.primary_binding.episode_id.is_some()
        || current.primary_binding.task_id != Some(episode.task_id)
        || current.primary_binding.workstream_id != Some(episode.workstream_id)
        || episode.lifecycle_status != EpisodeLifecycle::Open
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    let mut next = current.clone();
    next.work_binding_revision_id = evertrace_domain::ids::WorkBindingRevisionId::new_v7();
    next.predecessor_revision_id = Some(current.work_binding_revision_id);
    next.revision_generation = current
        .revision_generation
        .checked_add(1)
        .ok_or(WorkIdentityError::InvalidInput)?;
    next.primary_binding.episode_id = Some(episode.episode_id);
    current
        .validate_successor(&next)
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    Ok(next)
}

pub fn record_episode_correction(
    context: WorkCommandContext,
    correction: evertrace_domain::work::SegmentationCorrection,
    episode_successors: Vec<WorkEpisode>,
    workstream_successors: Vec<Workstream>,
) -> Result<JournalCommand, WorkIdentityError> {
    correction
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    if correction.source_episode_ids.iter().any(|id| {
        !episode_successors.iter().any(|episode| {
            episode.episode_id == *id
                && episode
                    .segmentation_correction_refs
                    .contains(&correction.correction_revision_id)
        })
    }) || correction.replacement_episode_ids.iter().any(|id| {
        !episode_successors
            .iter()
            .any(|episode| episode.episode_id == *id)
    }) {
        return Err(WorkIdentityError::InvalidInput);
    }
    let events = std::iter::once(JournalPayload::SegmentationCorrectionRecorded(Box::new(
        correction,
    )))
    .chain(
        episode_successors
            .into_iter()
            .map(|value| JournalPayload::WorkEpisodeRecorded(Box::new(value))),
    )
    .chain(
        workstream_successors
            .into_iter()
            .map(|value| JournalPayload::WorkstreamRecorded(Box::new(value))),
    )
    .map(|payload| {
        JournalEventDraft::runtime(
            context.occurred_at_us,
            context.effective_config_hash,
            context.algorithm_revision,
            payload,
        )
    })
    .collect();
    JournalCommand::new(context.command_id, events).map_err(Into::into)
}

pub fn save_checkpoint(
    context: WorkCommandContext,
    current_episode: &WorkEpisode,
    checkpoint: evertrace_domain::work::WorkCheckpoint,
    existing: Option<&evertrace_domain::work::WorkCheckpoint>,
) -> Result<Option<JournalCommand>, WorkIdentityError> {
    checkpoint
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    if checkpoint.episode_id != current_episode.episode_id
        || checkpoint.episode_revision_id != current_episode.revision_id
        || checkpoint.source_watermark != current_episode.source_watermark
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    let key = checkpoint.stable_key();
    if let Some(value) = existing
        && value.stable_key() == key
    {
        return if value == &checkpoint {
            Ok(None)
        } else {
            Err(WorkIdentityError::Conflict)
        };
    }
    if current_episode.checkpoint_refs.binary_search(&key).is_ok() {
        return Err(WorkIdentityError::Conflict);
    }
    let mut successor = current_episode.clone();
    successor.revision_id = RevisionId::new_v7();
    successor.predecessor_revision_id = Some(current_episode.revision_id);
    successor.revision_generation = current_episode
        .revision_generation
        .checked_add(1)
        .ok_or(WorkIdentityError::InvalidInput)?;
    successor.checkpoint_refs.push(key);
    successor.checkpoint_refs.sort();
    current_episode
        .validate_successor(&successor)
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    episode_command(
        context,
        vec![],
        vec![successor],
        vec![],
        vec![],
        vec![],
        vec![checkpoint],
    )
    .map(Some)
}

pub fn activate_episode(
    context: WorkCommandContext,
    current_workstream: &Workstream,
    episode: WorkEpisode,
    attempt_successors: Vec<Attempt>,
    binding_successors: Vec<WorkBindingRevision>,
) -> Result<JournalCommand, WorkIdentityError> {
    if current_workstream.active_episode_id.is_some()
        || episode.workstream_id != current_workstream.workstream_id
        || episode.task_id != current_workstream.task_id
        || episode.predecessor_revision_id.is_some()
        || episode.lifecycle_status != EpisodeLifecycle::Open
        || attempt_successors
            .iter()
            .any(|attempt| attempt.episode_id != Some(episode.episode_id))
        || binding_successors.iter().any(|binding| {
            binding.primary_binding.episode_id != Some(episode.episode_id)
                || binding.primary_binding.task_id != Some(episode.task_id)
                || binding.primary_binding.workstream_id != Some(episode.workstream_id)
        })
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    episode
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    let mut workstream = current_workstream.clone();
    workstream.revision_id = RevisionId::new_v7();
    workstream.predecessor_revision_id = Some(current_workstream.revision_id);
    workstream.active_episode_id = Some(episode.episode_id);
    let successor_watermark = current_workstream
        .source_watermark
        .checked_add(1)
        .ok_or(WorkIdentityError::InvalidInput)?;
    workstream.source_watermark = episode.source_watermark.max(successor_watermark);
    workstream
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    episode_command(
        context,
        vec![],
        vec![episode],
        vec![workstream],
        attempt_successors,
        binding_successors,
        vec![],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn close_episode_and_optionally_open(
    context: WorkCommandContext,
    current_workstream: &Workstream,
    current_episode: &WorkEpisode,
    closed_episode: WorkEpisode,
    current_step: Option<&crate::segmentation::IncrementalSegmentationStep>,
    replacement: Option<WorkEpisode>,
    attempt_successors: Vec<Attempt>,
    binding_successors: Vec<WorkBindingRevision>,
) -> Result<JournalCommand, WorkIdentityError> {
    current_episode
        .validate_successor(&closed_episode)
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    if closed_episode.lifecycle_status == EpisodeLifecycle::Open
        || closed_episode.boundary_status != BoundaryStatus::Confirmed
        || current_workstream.active_episode_id != Some(current_episode.episode_id)
        || (!current_episode.operation_burst_refs.is_empty() && current_step.is_none())
    {
        return Err(WorkIdentityError::InvalidInput);
    }
    let closed_bursts = current_step
        .map(|step| {
            let burst = step.current_burst();
            if burst.lifecycle != evertrace_domain::work::OperationBurstLifecycle::Open
                || !closed_episode
                    .operation_burst_refs
                    .contains(&burst.operation_burst_id)
            {
                return Err(WorkIdentityError::InvalidInput);
            }
            let mut values = step.closed_burst().cloned().into_iter().collect::<Vec<_>>();
            values.push(
                crate::segmentation::close_burst(burst.clone())
                    .map_err(|_| WorkIdentityError::InvalidInput)?,
            );
            Ok(values)
        })
        .transpose()?
        .into_iter()
        .flatten()
        .collect();
    if let Some(next) = &replacement {
        if next.episode_id == current_episode.episode_id
            || next.task_id != current_episode.task_id
            || next.workstream_id != current_episode.workstream_id
            || next.lifecycle_status != EpisodeLifecycle::Open
            || next.phase_contract == current_episode.phase_contract
        {
            return Err(WorkIdentityError::InvalidInput);
        }
        next.validate()
            .map_err(|_| WorkIdentityError::InvalidInput)?;
    }
    let active_id = replacement.as_ref().map(|value| value.episode_id);
    let mut workstream = current_workstream.clone();
    workstream.revision_id = RevisionId::new_v7();
    workstream.predecessor_revision_id = Some(current_workstream.revision_id);
    workstream.active_episode_id = active_id;
    workstream.phase_contract = replacement.as_ref().map_or_else(
        || current_workstream.phase_contract.clone(),
        |value| value.phase_contract.clone(),
    );
    let successor_watermark = current_workstream
        .source_watermark
        .checked_add(1)
        .ok_or(WorkIdentityError::InvalidInput)?;
    workstream.source_watermark = closed_episode.source_watermark.max(successor_watermark);
    workstream
        .validate()
        .map_err(|_| WorkIdentityError::InvalidInput)?;
    let mut episodes = vec![closed_episode];
    if let Some(next) = replacement {
        episodes.push(next);
    }
    episode_command(
        context,
        closed_bursts,
        episodes,
        vec![workstream],
        attempt_successors,
        binding_successors,
        vec![],
    )
}

fn episode_command(
    context: WorkCommandContext,
    bursts: Vec<evertrace_domain::work::OperationBurst>,
    episodes: Vec<WorkEpisode>,
    workstreams: Vec<Workstream>,
    attempts: Vec<Attempt>,
    bindings: Vec<WorkBindingRevision>,
    checkpoints: Vec<evertrace_domain::work::WorkCheckpoint>,
) -> Result<JournalCommand, WorkIdentityError> {
    let events = bursts
        .into_iter()
        .map(|value| JournalPayload::OperationBurstRecorded(Box::new(value)))
        .chain(
            episodes
                .into_iter()
                .map(|value| JournalPayload::WorkEpisodeRecorded(Box::new(value))),
        )
        .chain(
            workstreams
                .into_iter()
                .map(|value| JournalPayload::WorkstreamRecorded(Box::new(value))),
        )
        .chain(
            attempts
                .into_iter()
                .map(|value| JournalPayload::AttemptRecorded(Box::new(value))),
        )
        .chain(
            bindings
                .into_iter()
                .map(|value| JournalPayload::WorkBindingRecorded(Box::new(value))),
        )
        .chain(
            checkpoints
                .into_iter()
                .map(|value| JournalPayload::WorkCheckpointRecorded(Box::new(value))),
        )
        .map(|payload| {
            JournalEventDraft::runtime(
                context.occurred_at_us,
                context.effective_config_hash,
                context.algorithm_revision,
                payload,
            )
        })
        .collect();
    JournalCommand::new(context.command_id, events).map_err(Into::into)
}

fn sort_unique<T: Ord>(values: &mut Vec<T>) {
    values.sort();
    values.dedup();
}
