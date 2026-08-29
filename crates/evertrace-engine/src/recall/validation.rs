use super::detector::{checkpoint_state, detection_anchor_current, scope_matches, trigger_state};
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecallNeedValidity {
    Valid,
    Terminal(RecallObligationState),
    Unavailable,
}

pub(crate) fn terminal_need_event(
    need: &RecallNeed,
    obligation_state: RecallObligationState,
) -> Result<RecallLedgerEvent, StoreError> {
    if need.obligation_state != RecallObligationState::Active
        || obligation_state == RecallObligationState::Active
    {
        return Err(StoreError::InvalidInput);
    }
    let mut successor = need.clone();
    successor.parent_revision_id = Some(need.revision_id);
    successor.revision_id = RevisionId::new_v7();
    successor.obligation_state = obligation_state;
    let successor = successor.seal().map_err(|_| StoreError::Serialization)?;
    Ok(RecallLedgerEvent::NeedRecorded {
        need: Box::new(successor),
    })
}

pub(crate) fn revalidate_need(
    snapshot: &ProjectionSnapshot,
    need: &RecallNeed,
    now_us: i64,
) -> Result<RecallNeedValidity, StoreError> {
    let anchor = RecallDetectionAnchor {
        session_id: need.session_id.clone(),
        execution_lane_id: need.execution_lane_id,
        task_id: need.task_id,
        workstream_id: need.workstream_id,
        episode_revision_id: need.episode_revision_id,
        repository_id: need.repository_id,
        worktree_id: need.worktree_id,
    };
    if !detection_anchor_current(snapshot, &anchor)? {
        return Ok(RecallNeedValidity::Terminal(
            RecallObligationState::Superseded,
        ));
    }
    let Some((checkpoint, previous)) = current_episode_checkpoints(snapshot, &anchor)? else {
        return Ok(RecallNeedValidity::Terminal(
            RecallObligationState::Superseded,
        ));
    };
    let Some(current_trigger_state) = trigger_state(snapshot, &checkpoint, &anchor)? else {
        return Ok(RecallNeedValidity::Unavailable);
    };
    let index = RecallTriggerIndex::from_snapshot(snapshot)?;
    validate_need_against_current(
        need,
        &anchor,
        &checkpoint,
        previous.as_ref(),
        &current_trigger_state,
        &index,
        now_us,
    )
}

fn current_episode_checkpoints(
    snapshot: &ProjectionSnapshot,
    anchor: &RecallDetectionAnchor,
) -> Result<Option<(WorkCheckpoint, Option<WorkCheckpoint>)>, StoreError> {
    let mut revisions = BTreeMap::new();
    let mut current = None;
    for row in snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("work_episode"))
    {
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        let JournalPayload::WorkEpisodeRecorded(episode) = payload else {
            return Err(StoreError::StoreCorrupt);
        };
        if revisions
            .insert(episode.revision_id, (*episode).clone())
            .is_some()
        {
            return Err(StoreError::StoreCorrupt);
        }
        if episode.revision_id == anchor.episode_revision_id && current.replace(*episode).is_some()
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    let Some(current) = current else {
        return Ok(None);
    };
    let mut candidates = Vec::with_capacity(current.checkpoint_refs.len());
    for reference in &current.checkpoint_refs {
        let mut matches = snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("work_checkpoint"))
            .filter_map(|row| {
                let payload =
                    serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()?;
                match payload {
                    JournalPayload::WorkCheckpointRecorded(value)
                        if value.stable_key() == *reference =>
                    {
                        Some((*value, row.source_event_seq))
                    }
                    _ => None,
                }
            });
        let Some((checkpoint, source_event_seq)) = matches.next() else {
            return Err(StoreError::StoreCorrupt);
        };
        if matches.next().is_some() {
            return Err(StoreError::StoreCorrupt);
        }
        let source_episode = revisions
            .get(&checkpoint.episode_revision_id)
            .ok_or(StoreError::StoreCorrupt)?;
        if checkpoint.episode_id != current.episode_id
            || source_episode.episode_id != current.episode_id
            || source_episode.revision_generation > current.revision_generation
        {
            return Err(StoreError::StoreCorrupt);
        }
        candidates.push((checkpoint, source_event_seq));
    }
    candidates.sort_by_key(|(checkpoint, source_event_seq)| {
        (checkpoint.source_watermark, *source_event_seq)
    });
    if candidates.windows(2).any(|pair| {
        pair[0].0.source_watermark == pair[1].0.source_watermark && pair[0].1 == pair[1].1
    }) {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(candidates.pop().map(|(latest, _)| {
        let previous = candidates.pop().map(|(checkpoint, _)| checkpoint);
        (latest, previous)
    }))
}

pub(crate) fn validate_need_against_current(
    need: &RecallNeed,
    anchor: &RecallDetectionAnchor,
    checkpoint: &WorkCheckpoint,
    previous: Option<&WorkCheckpoint>,
    current_trigger_state: &RecallTriggerState,
    index: &RecallTriggerIndex,
    now_us: i64,
) -> Result<RecallNeedValidity, StoreError> {
    if !need.validate() || need.obligation_state != RecallObligationState::Active {
        return Ok(RecallNeedValidity::Unavailable);
    }
    if need
        .obligation_expires_at_us
        .is_some_and(|expiry| expiry <= now_us)
    {
        return Ok(RecallNeedValidity::Terminal(RecallObligationState::Expired));
    }
    if need.session_id != anchor.session_id
        || need.execution_lane_id != anchor.execution_lane_id
        || need.task_id != anchor.task_id
        || need.workstream_id != anchor.workstream_id
        || need.episode_revision_id != anchor.episode_revision_id
        || need.repository_id != anchor.repository_id
        || need.worktree_id != anchor.worktree_id
        || need.source_watermark != checkpoint.source_watermark
        || need.boundary_event_ref != checkpoint.stable_key()
        || &need.trigger_state != current_trigger_state
    {
        return Ok(RecallNeedValidity::Terminal(
            RecallObligationState::Superseded,
        ));
    }
    let mut expected_contracts = Vec::new();
    let valid_trigger = match need.trigger_family {
        TriggerFamily::ExplicitOrRecovery => {
            checkpoint.created_reason == CheckpointReason::Compact
                && checkpoint.continuation_candidate
                && (!checkpoint.open_loops.is_empty() || !checkpoint.active_attempt_ids.is_empty())
        }
        TriggerFamily::RuntimeAnomaly => previous.is_some_and(|value| {
            value.verifier_state == CheckpointVerifierState::Passed
                && checkpoint.verifier_state == CheckpointVerifierState::Failed
        }),
        TriggerFamily::ProspectiveObligation => {
            let conditions = index.evaluate(&checkpoint_state(checkpoint), None);
            for contract_id in &need.matched_contract_ids {
                let Some(condition) = conditions
                    .iter()
                    .find(|value| value.future_cue_contract_id == *contract_id)
                else {
                    return Ok(RecallNeedValidity::Terminal(
                        RecallObligationState::Superseded,
                    ));
                };
                if condition.resolve_truth == ConstraintTruth::True {
                    return Ok(RecallNeedValidity::Terminal(
                        RecallObligationState::Resolved,
                    ));
                }
                if condition.suppress_truth == ConstraintTruth::True {
                    return Ok(RecallNeedValidity::Terminal(
                        RecallObligationState::Canceled,
                    ));
                }
                if condition.match_truth != ConstraintTruth::True
                    || condition.resolve_truth != ConstraintTruth::False
                    || condition.suppress_truth != ConstraintTruth::False
                {
                    return Ok(RecallNeedValidity::Unavailable);
                }
                let Some(entry) = index
                    .entry(contract_id)
                    .filter(|entry| scope_matches(&entry.scope, anchor))
                else {
                    return Ok(RecallNeedValidity::Unavailable);
                };
                expected_contracts.push(entry.contract.clone());
            }
            !expected_contracts.is_empty()
        }
    };
    if !valid_trigger {
        return Ok(RecallNeedValidity::Terminal(
            RecallObligationState::Superseded,
        ));
    }
    let mut source_revision_ids = expected_contracts
        .iter()
        .map(|contract| contract.source_revision_id)
        .collect::<Vec<_>>();
    source_revision_ids.push(anchor.episode_revision_id);
    source_revision_ids.sort();
    source_revision_ids.dedup();
    let expected_plan = RecallPlan {
        reason: need.trigger_family.as_str().into(),
        normative_constraint_refs: expected_contracts
            .iter()
            .map(|contract| contract.source_revision_id.to_string())
            .collect(),
        relevant_episode_revision: Some(anchor.episode_revision_id),
        applicable_procedure_revision: None,
        open_loops: checkpoint.open_loops.clone(),
        stale_delivered_objects: Vec::new(),
        supporting_evidence_refs: checkpoint.verifier_refs.clone(),
    };
    if need.source_revision_ids != source_revision_ids
        || need.recall_plan != expected_plan
        || need.recall_plan_fingerprint
            != expected_plan
                .fingerprint()
                .map_err(|_| StoreError::Serialization)?
    {
        return Ok(RecallNeedValidity::Terminal(
            RecallObligationState::Superseded,
        ));
    }
    Ok(RecallNeedValidity::Valid)
}

#[cfg(test)]
mod tests {
    use evertrace_domain::{
        ids::{ExecutionLaneId, RecallNeedId, TaskId, WorkEpisodeId, WorkstreamId},
        recall::{
            FUTURE_CUE_COMPILER_VERSION, FUTURE_CUE_FIELD_REGISTRY_VERSION, FutureCueContract,
            RecallAgentResponse, RecallDeliveryState, RecallPlan, RecallTriggerState,
        },
        semantic::{AtomScope, ConstraintExpr, ConstraintField, ConstraintValue},
        work::{
            CheckpointReason, CheckpointVerifierState, PendingDeltaStats, PhaseContract, PhaseKind,
        },
    };

    use super::*;

    fn checkpoint(watermark: u64) -> WorkCheckpoint {
        WorkCheckpoint {
            episode_id: WorkEpisodeId::new_v7(),
            episode_revision_id: RevisionId::new_v7(),
            source_watermark: watermark,
            active_attempt_ids: Vec::new(),
            attempt_revision_refs: Vec::new(),
            phase_contract: PhaseContract {
                local_goal: "preserve recall validity".into(),
                phase_kind: PhaseKind::Verify,
                phase_label: "verify".into(),
                primary_targets: vec!["recall".into()],
                entry_conditions: vec!["open".into()],
                acceptance_boundary: "typed checkpoint".into(),
                expected_state_transition: "continue".into(),
            },
            open_loops: vec!["finish proof".into()],
            verifier_state: CheckpointVerifierState::Passed,
            verifier_refs: Vec::new(),
            current_worktree_snapshot_id: None,
            pending_delta_stats: PendingDeltaStats::default(),
            created_reason: CheckpointReason::Compact,
            continuation_candidate: true,
            active_lineage_refs: Vec::new(),
            capture_receipt_revision_ids: Vec::new(),
            capture_gap_refs: Vec::new(),
            capture_outage_refs: Vec::new(),
            algorithm_revision: 1,
        }
    }

    fn fixture() -> (
        RecallNeed,
        RecallDetectionAnchor,
        WorkCheckpoint,
        RecallTriggerState,
        RecallTriggerIndex,
    ) {
        let checkpoint = checkpoint(7);
        let anchor = RecallDetectionAnchor {
            session_id: "session-validity".into(),
            execution_lane_id: ExecutionLaneId::new_v7(),
            task_id: TaskId::new_v7(),
            workstream_id: WorkstreamId::new_v7(),
            episode_revision_id: checkpoint.episode_revision_id,
            repository_id: None,
            worktree_id: None,
        };
        let trigger_state = RecallTriggerState {
            phase_kind: checkpoint.phase_contract.phase_kind,
            verifier_state: checkpoint.verifier_state,
            attempt_ids: Vec::new(),
            worktree_snapshot_id: None,
            binding_revision_id: None,
            scope_effect_refs: Vec::new(),
        };
        let plan = RecallPlan {
            reason: TriggerFamily::ExplicitOrRecovery.as_str().into(),
            normative_constraint_refs: Vec::new(),
            relevant_episode_revision: Some(anchor.episode_revision_id),
            applicable_procedure_revision: None,
            open_loops: checkpoint.open_loops.clone(),
            stale_delivered_objects: Vec::new(),
            supporting_evidence_refs: Vec::new(),
        };
        let need = RecallNeed {
            recall_need_id: RecallNeedId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            recall_need_hash: [0; 32],
            trigger_family: TriggerFamily::ExplicitOrRecovery,
            source_revision_ids: vec![anchor.episode_revision_id],
            matched_contract_ids: Vec::new(),
            session_id: anchor.session_id.clone(),
            execution_lane_id: anchor.execution_lane_id,
            task_id: anchor.task_id,
            workstream_id: anchor.workstream_id,
            episode_revision_id: anchor.episode_revision_id,
            repository_id: None,
            worktree_id: None,
            boundary_event_ref: checkpoint.stable_key(),
            trigger_state: trigger_state.clone(),
            source_watermark: checkpoint.source_watermark,
            recall_plan_fingerprint: [0; 32],
            recall_plan: plan,
            delivery_state: RecallDeliveryState::Detected,
            agent_response: RecallAgentResponse::NotRetrieved,
            obligation_state: RecallObligationState::Active,
            created_at_us: 1,
            presentation_expires_at_us: 100,
            obligation_expires_at_us: None,
            active_presentation_attempt_id: None,
            active_retrieval_request_id: None,
        }
        .seal()
        .unwrap();
        let index = RecallTriggerIndex::from_current_contexts(0, &[]).unwrap();
        (need, anchor, checkpoint, trigger_state, index)
    }

    #[test]
    fn shared_validity_handles_current_expired_and_newer_boundary_identically() {
        let (need, anchor, current_checkpoint, state, index) = fixture();
        assert_eq!(
            validate_need_against_current(
                &need,
                &anchor,
                &current_checkpoint,
                None,
                &state,
                &index,
                2,
            ),
            Ok(RecallNeedValidity::Valid)
        );
        let mut expired = need.clone();
        expired.obligation_expires_at_us = Some(2);
        expired = expired.seal().unwrap();
        assert_eq!(
            validate_need_against_current(
                &expired,
                &anchor,
                &current_checkpoint,
                None,
                &state,
                &index,
                2,
            ),
            Ok(RecallNeedValidity::Terminal(RecallObligationState::Expired))
        );
        let newer = checkpoint(8);
        assert_eq!(
            validate_need_against_current(&need, &anchor, &newer, None, &state, &index, 2),
            Ok(RecallNeedValidity::Terminal(
                RecallObligationState::Superseded
            ))
        );
    }

    fn prospective_fixture(
        terminal_expr: ConstraintExpr,
        terminal_is_resolve: bool,
    ) -> (
        RecallNeed,
        RecallDetectionAnchor,
        WorkCheckpoint,
        RecallTriggerState,
        RecallTriggerIndex,
    ) {
        let (mut need, anchor, checkpoint, state, _) = fixture();
        let contract_id = [0x22; 32];
        let source_revision_id = RevisionId::new_v7();
        let false_expr = ConstraintExpr::Eq {
            field: ConstraintField::VerifierState,
            value: ConstraintValue::Text("failed".into()),
        };
        let contract = FutureCueContract {
            future_cue_contract_id: contract_id,
            source_revision_id,
            trigger_family: TriggerFamily::ProspectiveObligation,
            condition_ir_version: 1,
            match_expr: ConstraintExpr::Exists {
                field: ConstraintField::Phase,
            },
            suppress_expr: if terminal_is_resolve {
                false_expr.clone()
            } else {
                terminal_expr.clone()
            },
            resolve_expr: if terminal_is_resolve {
                terminal_expr
            } else {
                false_expr
            },
            field_registry_version: FUTURE_CUE_FIELD_REGISTRY_VERSION,
            global_support_dependency_generation: None,
            compiler_version: FUTURE_CUE_COMPILER_VERSION,
            source_watermark: 1,
        };
        let entries = vec![RecallTriggerEntry {
            contract,
            scope: AtomScope::Task {
                task_id: anchor.task_id,
            },
        }];
        let index = RecallTriggerIndex {
            frontier: 1,
            field_entries: super::super::field_entries(&entries),
            contract_entries: BTreeMap::from([(contract_id, 0)]),
            entries,
        };
        need.trigger_family = TriggerFamily::ProspectiveObligation;
        need.matched_contract_ids = vec![contract_id];
        need.source_revision_ids = vec![source_revision_id, anchor.episode_revision_id];
        need.source_revision_ids.sort();
        need.recall_plan = RecallPlan {
            reason: TriggerFamily::ProspectiveObligation.as_str().into(),
            normative_constraint_refs: vec![source_revision_id.to_string()],
            relevant_episode_revision: Some(anchor.episode_revision_id),
            applicable_procedure_revision: None,
            open_loops: checkpoint.open_loops.clone(),
            stale_delivered_objects: Vec::new(),
            supporting_evidence_refs: Vec::new(),
        };
        need = need.seal().unwrap();
        (need, anchor, checkpoint, state, index)
    }

    #[test]
    fn shared_validity_distinguishes_structured_resolve_and_suppress_truth() {
        let terminal = ConstraintExpr::Eq {
            field: ConstraintField::VerifierState,
            value: ConstraintValue::Text("passed".into()),
        };
        let (resolved, anchor, checkpoint, state, index) =
            prospective_fixture(terminal.clone(), true);
        assert_eq!(
            validate_need_against_current(&resolved, &anchor, &checkpoint, None, &state, &index, 2,),
            Ok(RecallNeedValidity::Terminal(
                RecallObligationState::Resolved
            ))
        );
        let (canceled, anchor, checkpoint, state, index) = prospective_fixture(terminal, false);
        assert_eq!(
            validate_need_against_current(&canceled, &anchor, &checkpoint, None, &state, &index, 2,),
            Ok(RecallNeedValidity::Terminal(
                RecallObligationState::Canceled
            ))
        );
    }
}
