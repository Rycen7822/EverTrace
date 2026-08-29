use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecallDetectionAnchor {
    pub session_id: String,
    pub execution_lane_id: ExecutionLaneId,
    pub task_id: TaskId,
    pub workstream_id: WorkstreamId,
    pub episode_revision_id: RevisionId,
    pub repository_id: Option<RepositoryId>,
    pub worktree_id: Option<WorktreeId>,
}

pub(crate) fn detect_current_context(
    context: &evertrace_store::RecallCurrentContext,
    index: &RecallTriggerIndex,
    now_us: i64,
) -> Result<Option<RecallLedgerEvent>, StoreError> {
    let checkpoint = &context.checkpoint;
    if now_us < 0
        || checkpoint.validate().is_err()
        || !checkpoint.capture_gap_refs.is_empty()
        || !checkpoint.capture_outage_refs.is_empty()
        || checkpoint.verifier_state == CheckpointVerifierState::Inconclusive
    {
        return Ok(None);
    }
    let boundary_ref = checkpoint.stable_key();
    let existing = context
        .needs
        .iter()
        .filter(|need| need.boundary_event_ref == boundary_ref)
        .collect::<Vec<_>>();
    if existing.len() > 1 {
        return Err(StoreError::StoreCorrupt);
    }
    let anchor = RecallDetectionAnchor {
        session_id: context.execution_lane.host_session_id.clone(),
        execution_lane_id: context.execution_lane.execution_lane_id,
        task_id: context.task.task_id,
        workstream_id: context.workstream.workstream_id,
        episode_revision_id: context.episode.revision_id,
        repository_id: context.workstream.repository_instance_id,
        worktree_id: context.workstream.active_worktree_instance_id,
    };
    let state = checkpoint_state(checkpoint);
    let conditions = index.evaluate(&state, None);
    if let Some(existing) = existing.first()
        && existing.trigger_family == TriggerFamily::ProspectiveObligation
    {
        let matched = conditions.iter().filter(|condition| {
            existing
                .matched_contract_ids
                .contains(&condition.future_cue_contract_id)
        });
        let terminal = matched.fold(None, |terminal, condition| {
            if condition.resolve_truth == ConstraintTruth::True {
                Some(RecallObligationState::Resolved)
            } else if condition.suppress_truth == ConstraintTruth::True {
                Some(RecallObligationState::Canceled)
            } else {
                terminal
            }
        });
        if let Some(obligation_state) = terminal {
            return terminal_need_event(existing, obligation_state).map(Some);
        }
    }
    let mut contracts = conditions
        .into_iter()
        .filter(|condition| {
            condition.match_truth == ConstraintTruth::True
                && condition.suppress_truth == ConstraintTruth::False
                && condition.resolve_truth == ConstraintTruth::False
        })
        .filter_map(|condition| {
            index
                .entry(&condition.future_cue_contract_id)
                .filter(|entry| scope_matches(&entry.scope, &anchor))
                .map(|entry| entry.contract.clone())
        })
        .collect::<Vec<_>>();
    contracts.sort_by_key(|contract| contract.future_cue_contract_id);
    let explicit = checkpoint.created_reason == CheckpointReason::Compact
        && checkpoint.continuation_candidate
        && (!checkpoint.open_loops.is_empty() || !checkpoint.active_attempt_ids.is_empty());
    let runtime_anomaly = runtime_anomaly(context.previous_checkpoint.as_ref(), checkpoint);
    let trigger_family = if !contracts.is_empty() {
        TriggerFamily::ProspectiveObligation
    } else if runtime_anomaly {
        TriggerFamily::RuntimeAnomaly
    } else if explicit {
        TriggerFamily::ExplicitOrRecovery
    } else {
        return Ok(None);
    };
    let mut source_revision_ids = contracts
        .iter()
        .map(|contract| contract.source_revision_id)
        .collect::<Vec<_>>();
    source_revision_ids.push(context.episode.revision_id);
    source_revision_ids.sort();
    source_revision_ids.dedup();
    let plan = RecallPlan {
        reason: trigger_family.as_str().into(),
        normative_constraint_refs: contracts
            .iter()
            .map(|contract| contract.source_revision_id.to_string())
            .collect(),
        relevant_episode_revision: Some(context.episode.revision_id),
        applicable_procedure_revision: None,
        open_loops: checkpoint.open_loops.clone(),
        stale_delivered_objects: Vec::new(),
        supporting_evidence_refs: checkpoint.verifier_refs.clone(),
    };
    if !plan.validate() {
        return Ok(None);
    }
    let current = existing.first().copied();
    if current.is_some_and(|need| {
        need.obligation_state != RecallObligationState::Active
            || !matches!(
                need.delivery_state,
                RecallDeliveryState::Detected
                    | RecallDeliveryState::Scheduled
                    | RecallDeliveryState::FailedPreEmit
            )
    }) {
        return Ok(None);
    }
    let mut need = RecallNeed {
        recall_need_id: current.map_or_else(RecallNeedId::new_v7, |need| need.recall_need_id),
        revision_id: RevisionId::new_v7(),
        parent_revision_id: current.map(|need| need.revision_id),
        recall_need_hash: [0; 32],
        trigger_family,
        source_revision_ids,
        matched_contract_ids: contracts
            .iter()
            .map(|contract| contract.future_cue_contract_id)
            .collect(),
        session_id: anchor.session_id,
        execution_lane_id: anchor.execution_lane_id,
        task_id: anchor.task_id,
        workstream_id: anchor.workstream_id,
        episode_revision_id: anchor.episode_revision_id,
        repository_id: anchor.repository_id,
        worktree_id: anchor.worktree_id,
        boundary_event_ref: boundary_ref,
        trigger_state: RecallTriggerState {
            phase_kind: checkpoint.phase_contract.phase_kind,
            verifier_state: checkpoint.verifier_state,
            attempt_ids: checkpoint.active_attempt_ids.clone(),
            worktree_snapshot_id: checkpoint.current_worktree_snapshot_id,
            binding_revision_id: Some(context.binding.work_binding_revision_id),
            scope_effect_refs: context.binding.scope_effect_refs.clone(),
        },
        source_watermark: checkpoint.source_watermark,
        recall_plan_fingerprint: [0; 32],
        recall_plan: plan,
        delivery_state: current.map_or(RecallDeliveryState::Detected, |need| need.delivery_state),
        agent_response: current.map_or(RecallAgentResponse::NotRetrieved, |need| {
            need.agent_response
        }),
        obligation_state: RecallObligationState::Active,
        created_at_us: current.map_or(now_us, |need| need.created_at_us),
        presentation_expires_at_us: current.map_or_else(
            || now_us.saturating_add(30_000_000),
            |need| need.presentation_expires_at_us,
        ),
        obligation_expires_at_us: current.and_then(|need| need.obligation_expires_at_us),
        active_presentation_attempt_id: current
            .and_then(|need| need.active_presentation_attempt_id),
        active_retrieval_request_id: current
            .and_then(|need| need.active_retrieval_request_id.clone()),
    }
    .seal()
    .map_err(|_| StoreError::Serialization)?;
    if current.is_some_and(|current| current.recall_need_hash == need.recall_need_hash) {
        return Ok(None);
    }
    if current.is_none() {
        need.parent_revision_id = None;
    }
    Ok(Some(RecallLedgerEvent::NeedRecorded {
        need: Box::new(need),
    }))
}

pub(crate) fn current_need_validity(
    context: &evertrace_store::RecallCurrentContext,
    need: &RecallNeed,
    index: &RecallTriggerIndex,
    now_us: i64,
) -> Result<RecallNeedValidity, StoreError> {
    let anchor = RecallDetectionAnchor {
        session_id: context.execution_lane.host_session_id.clone(),
        execution_lane_id: context.execution_lane.execution_lane_id,
        task_id: context.task.task_id,
        workstream_id: context.workstream.workstream_id,
        episode_revision_id: context.episode.revision_id,
        repository_id: context.workstream.repository_instance_id,
        worktree_id: context.workstream.active_worktree_instance_id,
    };
    let trigger_state = RecallTriggerState {
        phase_kind: context.checkpoint.phase_contract.phase_kind,
        verifier_state: context.checkpoint.verifier_state,
        attempt_ids: context.checkpoint.active_attempt_ids.clone(),
        worktree_snapshot_id: context.checkpoint.current_worktree_snapshot_id,
        binding_revision_id: Some(context.binding.work_binding_revision_id),
        scope_effect_refs: context.binding.scope_effect_refs.clone(),
    };
    validate_need_against_current(
        need,
        &anchor,
        &context.checkpoint,
        context.previous_checkpoint.as_ref(),
        &trigger_state,
        index,
        now_us,
    )
}

fn runtime_anomaly(previous: Option<&WorkCheckpoint>, current: &WorkCheckpoint) -> bool {
    previous.is_some_and(|value| {
        value.verifier_state == CheckpointVerifierState::Passed
            && current.verifier_state == CheckpointVerifierState::Failed
    })
}

pub fn spawn_recall_worker(
    writer: crate::WriterHandle,
    mut runtime: evertrace_capture::RuntimeSnapshot,
    data_dir: std::path::PathBuf,
) -> tokio::task::JoinHandle<()> {
    let mut frontier = writer.subscribe_recall_frontier();
    tokio::spawn(async move {
        let mut startup = true;
        loop {
            let first = process_recall_batch(&writer, &mut runtime, &data_dir, startup).await;
            if first.is_err()
                && process_recall_batch(&writer, &mut runtime, &data_dir, startup)
                    .await
                    .is_err()
            {
                eprintln!("evertraced: recall worker batch unavailable");
            }
            startup = false;
            if frontier.changed().await.is_err() {
                break;
            }
        }
    })
}

async fn process_recall_batch(
    writer: &crate::WriterHandle,
    runtime: &mut evertrace_capture::RuntimeSnapshot,
    data_dir: &std::path::Path,
    abandon_claims: bool,
) -> Result<(), crate::WriterActorError> {
    let mut stale_retries = 0;
    let mut state_advances = 0;
    loop {
        let contexts = writer.recall_current_contexts(32).await?;
        let frontier = contexts
            .first()
            .map(|context| context.frontier)
            .unwrap_or_else(|| *writer.subscribe_recall_frontier().borrow());
        if !contexts.iter().all(|context| context.frontier == frontier) {
            return Err(crate::WriterActorError::StoreCorrupt);
        }
        let index = RecallTriggerIndex::from_current_contexts(frontier, &contexts)
            .map_err(|_| crate::WriterActorError::StoreCorrupt)?;
        let occurred_at_us = current_time_us()?;
        let mut ledger_events = Vec::new();
        for context in &contexts {
            let mut terminalized = false;
            for need in &context.needs {
                match current_need_validity(context, need, &index, occurred_at_us)
                    .map_err(|_| crate::WriterActorError::StoreCorrupt)?
                {
                    RecallNeedValidity::Terminal(state) => {
                        ledger_events.push(
                            terminal_need_event(need, state)
                                .map_err(|_| crate::WriterActorError::StoreCorrupt)?,
                        );
                        terminalized = true;
                        continue;
                    }
                    RecallNeedValidity::Unavailable => continue,
                    RecallNeedValidity::Valid => {}
                }
                if need.presentation_expires_at_us <= occurred_at_us
                    && need.active_presentation_attempt_id.is_none()
                    && matches!(
                        need.delivery_state,
                        RecallDeliveryState::Detected
                            | RecallDeliveryState::Scheduled
                            | RecallDeliveryState::FailedPreEmit
                    )
                {
                    let mut successor = need.clone();
                    successor.parent_revision_id = Some(need.revision_id);
                    successor.revision_id = RevisionId::new_v7();
                    successor.presentation_expires_at_us =
                        occurred_at_us.saturating_add(30_000_000);
                    let successor = successor
                        .seal()
                        .map_err(|_| crate::WriterActorError::StoreCorrupt)?;
                    ledger_events.push(RecallLedgerEvent::NeedRecorded {
                        need: Box::new(successor),
                    });
                    terminalized = true;
                    continue;
                }
                if need.delivery_state == RecallDeliveryState::ClaimedForBoundary
                    && (abandon_claims || need.presentation_expires_at_us <= occurred_at_us)
                    && let Some(presentation_attempt_id) = need.active_presentation_attempt_id
                {
                    ledger_events.push(RecallLedgerEvent::PresentationAttempt {
                        attempt: evertrace_domain::recall::RecallPresentationAttempt {
                            presentation_attempt_id,
                            recall_need_id: need.recall_need_id,
                            recall_need_hash: need.recall_need_hash,
                            boundary_event_ref: need.boundary_event_ref.clone(),
                            state: evertrace_domain::recall::PresentationAttemptState::PresentationUnknown,
                            occurred_at_us,
                        },
                    });
                }
            }
            if !terminalized
                && let Some(event) = detect_current_context(context, &index, occurred_at_us)
                    .map_err(|_| crate::WriterActorError::StoreCorrupt)?
            {
                ledger_events.push(event);
            }
        }
        if !ledger_events.is_empty() {
            ensure_state_advance_allowed(state_advances)?;
            let events = ledger_events
                .into_iter()
                .map(|event| {
                    JournalEventDraft::runtime(
                        occurred_at_us,
                        runtime.effective_config_hash,
                        "s22-recall-v1",
                        JournalPayload::RecallLedgerRecorded(Box::new(event)),
                    )
                })
                .collect();
            let command = JournalCommand::new(evertrace_domain::ids::CommandId::new_v7(), events)
                .map_err(|_| crate::WriterActorError::InvalidInput)?;
            match writer
                .commit_if_frontier(command, occurred_at_us, frontier)
                .await
            {
                Ok(_) => {
                    state_advances += 1;
                    continue;
                }
                Err(crate::WriterActorError::StaleFrontier) if stale_retries == 0 => {
                    stale_retries += 1;
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        publish_cues(writer, runtime, data_dir, occurred_at_us).await?;
        return Ok(());
    }
}

fn ensure_state_advance_allowed(state_advances: u8) -> Result<(), crate::WriterActorError> {
    (state_advances < 2)
        .then_some(())
        .ok_or(crate::WriterActorError::StoreCorrupt)
}

async fn publish_cues(
    writer: &crate::WriterHandle,
    runtime: &mut evertrace_capture::RuntimeSnapshot,
    data_dir: &std::path::Path,
    occurred_at_us: i64,
) -> Result<(), crate::WriterActorError> {
    let contexts = writer.recall_current_contexts(32).await?;
    let mut cues = Vec::new();
    if runtime.recall_cue_gate == evertrace_capture::RecallCueGateMode::Active {
        let manifest = runtime
            .recall_cue_adapter_manifest_id
            .clone()
            .ok_or(crate::WriterActorError::StoreCorrupt)?;
        for context in &contexts {
            if !context
                .execution_lane
                .adapter_manifest_ids
                .contains(&manifest)
            {
                continue;
            }
            for need in &context.needs {
                if need.obligation_state != RecallObligationState::Active
                    || need.presentation_expires_at_us <= occurred_at_us
                    || need.active_presentation_attempt_id.is_some()
                    || !matches!(
                        need.delivery_state,
                        RecallDeliveryState::Detected
                            | RecallDeliveryState::Scheduled
                            | RecallDeliveryState::FailedPreEmit
                    )
                {
                    continue;
                }
                let reusable = (need.delivery_state != RecallDeliveryState::FailedPreEmit)
                    .then(|| {
                        runtime.recall_cues.iter().find(|cue| {
                            cue.session_id == context.execution_lane.host_session_id
                                && cue.execution_lane_id == context.execution_lane.execution_lane_id
                                && cue.recall_need_hash == need.recall_need_hash
                                && cue.expires_at_us > occurred_at_us
                        })
                    })
                    .flatten()
                    .cloned();
                let cue = if let Some(cue) = reusable {
                    cue
                } else {
                    evertrace_domain::recall::RecallCueSnapshot {
                        session_id: context.execution_lane.host_session_id.clone(),
                        execution_lane_id: context.execution_lane.execution_lane_id,
                        host_lane_key: context.execution_lane.host_lane_key.clone(),
                        adapter_manifest_id: manifest.clone(),
                        runtime_generation: runtime.generation,
                        recall_need_hash: need.recall_need_hash,
                        presentation_attempt_id:
                            evertrace_domain::ids::PresentationAttemptId::new_v7(),
                        expires_at_us: need
                            .presentation_expires_at_us
                            .min(occurred_at_us.saturating_add(5_000_000)),
                        checksum: [0; 32],
                    }
                    .seal()
                    .map_err(|_| crate::WriterActorError::StoreCorrupt)?
                };
                cues.push(cue);
            }
        }
    }
    cues.sort_by(|left, right| {
        left.session_id
            .cmp(&right.session_id)
            .then(left.execution_lane_id.cmp(&right.execution_lane_id))
            .then(
                left.presentation_attempt_id
                    .cmp(&right.presentation_attempt_id),
            )
    });
    if cues.len() > 32 {
        return Err(crate::WriterActorError::InvalidInput);
    }
    if runtime.recall_cues != cues {
        let mut next = runtime.clone();
        next.recall_cues = cues;
        publish_next_runtime(
            runtime,
            next,
            &evertrace_capture::RuntimeSnapshot::snapshot_path(data_dir),
        )?;
    }
    Ok(())
}

fn publish_next_runtime(
    runtime: &mut evertrace_capture::RuntimeSnapshot,
    next: evertrace_capture::RuntimeSnapshot,
    path: &std::path::Path,
) -> Result<(), crate::WriterActorError> {
    next.publish(path)
        .map_err(|_| crate::WriterActorError::Store)?;
    *runtime = next;
    Ok(())
}

fn current_time_us() -> Result<i64, crate::WriterActorError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_micros()).ok())
        .ok_or(crate::WriterActorError::InvalidInput)
}

pub(super) fn checkpoint_state(checkpoint: &WorkCheckpoint) -> ConstraintState {
    let mut bindings = vec![
        ConstraintBinding {
            field: ConstraintField::PhaseKind,
            value: ConstraintValue::Text(phase_kind(checkpoint.phase_contract.phase_kind).into()),
        },
        ConstraintBinding {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text(checkpoint.phase_contract.phase_label.clone()),
        },
        ConstraintBinding {
            field: ConstraintField::VerifierState,
            value: ConstraintValue::Text(
                match checkpoint.verifier_state {
                    CheckpointVerifierState::Unverified => "unverified",
                    CheckpointVerifierState::Passed => "passed",
                    CheckpointVerifierState::Failed => "failed",
                    CheckpointVerifierState::Inconclusive => "inconclusive",
                }
                .into(),
            ),
        },
    ];
    bindings.sort_by_key(|binding| binding.field);
    ConstraintState { bindings }
}

fn phase_kind(value: PhaseKind) -> &'static str {
    match value {
        PhaseKind::Orient => "orient",
        PhaseKind::Inspect => "inspect",
        PhaseKind::Reproduce => "reproduce",
        PhaseKind::Diagnose => "diagnose",
        PhaseKind::Design => "design",
        PhaseKind::Implement => "implement",
        PhaseKind::Verify => "verify",
        PhaseKind::Execute => "execute",
        PhaseKind::Analyze => "analyze",
        PhaseKind::Recover => "recover",
        PhaseKind::Deliver => "deliver",
        PhaseKind::Unknown => "unknown",
    }
}

pub(super) fn scope_matches(scope: &AtomScope, anchor: &RecallDetectionAnchor) -> bool {
    match scope {
        AtomScope::Task { task_id } => *task_id == anchor.task_id,
        AtomScope::Repository {
            repository_instance_id,
        } => Some(*repository_instance_id) == anchor.repository_id,
        AtomScope::Worktree {
            repository_instance_id,
            worktree_instance_id,
        } => {
            Some(*repository_instance_id) == anchor.repository_id
                && Some(*worktree_instance_id) == anchor.worktree_id
        }
        AtomScope::Global => false,
    }
}

pub(super) fn detection_anchor_current(
    snapshot: &ProjectionSnapshot,
    anchor: &RecallDetectionAnchor,
) -> Result<bool, StoreError> {
    let mut lane = 0;
    let mut task = 0;
    let mut workstream = 0;
    let mut episode = 0;
    for row in snapshot.data_rows().filter(|row| {
        matches!(
            row.object_kind.as_deref(),
            Some("execution_lane" | "task" | "workstream" | "work_episode")
        )
    }) {
        let payload: evertrace_store::JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        match payload {
            evertrace_store::JournalPayload::ExecutionLaneRecorded(value) => {
                if value.host_session_id == anchor.session_id
                    && value.status == evertrace_domain::work::LaneStatus::Active
                    && value.execution_lane_id == anchor.execution_lane_id
                {
                    lane += 1;
                }
            }
            evertrace_store::JournalPayload::TaskRecorded(value)
                if value.task_id == anchor.task_id
                    && value.lifecycle == evertrace_domain::work::TaskLifecycle::Active =>
            {
                task += 1;
            }
            evertrace_store::JournalPayload::WorkstreamRecorded(value)
                if value.workstream_id == anchor.workstream_id
                    && value.task_id == anchor.task_id
                    && value.status == evertrace_domain::work::WorkstreamStatus::Active
                    && value.repository_instance_id == anchor.repository_id
                    && value.active_worktree_instance_id == anchor.worktree_id
                    && value.execution_lane_ids.contains(&anchor.execution_lane_id) =>
            {
                workstream += 1;
            }
            evertrace_store::JournalPayload::WorkEpisodeRecorded(value)
                if value.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Open
                    && value.revision_id == anchor.episode_revision_id
                    && value.task_id == anchor.task_id
                    && value.workstream_id == anchor.workstream_id
                    && value.session_ids.contains(&anchor.session_id)
                    && value.repository_instance_id == anchor.repository_id
                    && value.worktree_instance_id == anchor.worktree_id
                    && value.execution_lane_ids.contains(&anchor.execution_lane_id) =>
            {
                episode += 1;
            }
            _ => {}
        }
    }
    Ok(lane == 1 && task == 1 && workstream == 1 && episode == 1)
}

pub(super) fn trigger_state(
    snapshot: &ProjectionSnapshot,
    checkpoint: &WorkCheckpoint,
    anchor: &RecallDetectionAnchor,
) -> Result<Option<RecallTriggerState>, StoreError> {
    let mut episode_id = None;
    for row in snapshot.data_rows().filter(|row| {
        matches!(
            row.object_kind.as_deref(),
            Some("work_episode" | "work_binding")
        )
    }) {
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        if let JournalPayload::WorkEpisodeRecorded(value) = payload
            && value.revision_id == anchor.episode_revision_id
            && episode_id.replace(value.episode_id).is_some()
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    let Some(episode_id) = episode_id else {
        return Ok(None);
    };
    let lanes = snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("execution_lane"))
        .filter_map(|row| {
            let payload =
                serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()?;
            match payload {
                JournalPayload::ExecutionLaneRecorded(value)
                    if value.execution_lane_id == anchor.execution_lane_id =>
                {
                    Some(*value)
                }
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    let [lane] = lanes.as_slice() else {
        return Ok(None);
    };
    let mut binding = None::<(evertrace_domain::work::WorkBindingRevision, u64)>;
    for row in snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("work_binding"))
    {
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        let JournalPayload::WorkBindingRecorded(value) = payload else {
            return Err(StoreError::StoreCorrupt);
        };
        if value.assignment_status == evertrace_domain::work::AssignmentStatus::Resolved
            && lane.operation_ids.contains(&value.operation_id)
            && value.primary_binding.task_id == Some(anchor.task_id)
            && value.primary_binding.workstream_id == Some(anchor.workstream_id)
            && value.primary_binding.episode_id == Some(episode_id)
        {
            match binding.as_ref() {
                Some((_, source_seq)) if *source_seq == row.source_event_seq => return Ok(None),
                Some((_, source_seq)) if *source_seq > row.source_event_seq => {}
                _ => binding = Some((*value, row.source_event_seq)),
            }
        }
    }
    let Some((binding, _)) = binding else {
        return Ok(None);
    };
    Ok(Some(RecallTriggerState {
        phase_kind: checkpoint.phase_contract.phase_kind,
        verifier_state: checkpoint.verifier_state,
        attempt_ids: checkpoint.active_attempt_ids.clone(),
        worktree_snapshot_id: checkpoint.current_worktree_snapshot_id,
        binding_revision_id: Some(binding.work_binding_revision_id),
        scope_effect_refs: binding.scope_effect_refs,
    }))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use evertrace_capture::{
        RecallCueGateMode, RecoveryGateMode, RecoverySnapshotSettings, RuntimeSnapshot, SpoolLimits,
    };
    use evertrace_domain::{
        ids::WorkEpisodeId,
        work::{
            CheckpointReason, CheckpointVerifierState, PendingDeltaStats, PhaseContract, PhaseKind,
        },
    };

    use super::*;

    fn checkpoint(revision: RevisionId, watermark: u64) -> WorkCheckpoint {
        WorkCheckpoint {
            episode_id: WorkEpisodeId::new_v7(),
            episode_revision_id: revision,
            source_watermark: watermark,
            active_attempt_ids: Vec::new(),
            attempt_revision_refs: Vec::new(),
            phase_contract: PhaseContract {
                local_goal: "bounded startup reconciliation".into(),
                phase_kind: PhaseKind::Verify,
                phase_label: "verify".into(),
                primary_targets: vec!["recall".into()],
                entry_conditions: vec!["open episode".into()],
                acceptance_boundary: "validated checkpoint".into(),
                expected_state_transition: "reconciled".into(),
            },
            open_loops: Vec::new(),
            verifier_state: CheckpointVerifierState::Passed,
            verifier_refs: vec!["verifier:test".into()],
            current_worktree_snapshot_id: None,
            pending_delta_stats: PendingDeltaStats::default(),
            created_reason: CheckpointReason::Manual,
            continuation_candidate: true,
            active_lineage_refs: Vec::new(),
            capture_receipt_revision_ids: Vec::new(),
            capture_gap_refs: Vec::new(),
            capture_outage_refs: Vec::new(),
            algorithm_revision: 1,
        }
    }

    #[test]
    fn runtime_anomaly_requires_a_typed_passed_to_failed_transition() {
        let revision = RevisionId::new_v7();
        let previous = checkpoint(revision, 1);
        let mut failed = checkpoint(revision, 2);
        failed.verifier_state = CheckpointVerifierState::Failed;
        assert!(runtime_anomaly(Some(&previous), &failed));
        assert!(!runtime_anomaly(None, &failed));
        assert!(!runtime_anomaly(Some(&previous), &previous));
    }

    #[test]
    fn failed_runtime_publish_preserves_memory_and_a_later_publish_updates_it() {
        let root = std::env::temp_dir().join(format!(
            "evertrace-recall-publish-{}",
            evertrace_domain::ids::RequestId::new_v7()
        ));
        std::fs::create_dir(&root).unwrap();
        let settings = RecoverySnapshotSettings {
            gate: RecoveryGateMode::Disabled,
            preflight_timeout_ms: 100,
            effective_config_hash: [7; 32],
            adapter_manifest_id: None,
            classifier_revision: 1,
            max_bundle_bytes: 4096,
            max_untracked_file_bytes: 1024,
            max_untracked_total_bytes: 2048,
            recall_cue_gate: RecallCueGateMode::Disabled,
            recall_cue_adapter_manifest_id: None,
        };
        let limits = SpoolLimits {
            high_watermark_bytes: 1024,
            low_watermark_bytes: 512,
            max_main_files: 4,
            emergency_slots: 2,
        };
        let mut current = RuntimeSnapshot::for_data_dir(&root, 1, limits, settings).unwrap();
        let mut next = current.clone();
        next.generation = 2;
        let blocker = root.join("ordinary-file");
        std::fs::write(&blocker, b"x").unwrap();
        assert!(
            publish_next_runtime(&mut current, next.clone(), &blocker.join("snapshot")).is_err()
        );
        assert_eq!(current.generation, 1);
        let runtime_dir = root.join("runtime");
        std::fs::create_dir(&runtime_dir).unwrap();
        std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let valid = RuntimeSnapshot::snapshot_path(&root);
        publish_next_runtime(&mut current, next, &valid).unwrap();
        assert_eq!(current.generation, 2);
        assert_eq!(RuntimeSnapshot::load(&valid).unwrap(), current);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recall_batch_rejects_a_third_state_advance_before_commit() {
        assert_eq!(ensure_state_advance_allowed(0), Ok(()));
        assert_eq!(ensure_state_advance_allowed(1), Ok(()));
        assert_eq!(
            ensure_state_advance_allowed(2),
            Err(crate::WriterActorError::StoreCorrupt)
        );
    }
}
