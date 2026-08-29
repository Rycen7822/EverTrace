use std::collections::{BTreeMap, BTreeSet};

use evertrace_domain::{
    ids::RecallNeedId,
    recall::{
        PresentationAttemptState, RecallAgentResponse, RecallDeliveryState, RecallLedgerEvent,
        RecallNeed, RecallObligationState, RetrievalOutcomeState,
    },
};

use crate::{
    command::{JournalPayload, StoreError},
    objects::{ObjectRow, ObjectRowClass, ObjectRowKind},
};

pub const RECALL_NEED_KIND: &str = "recall_need";

#[derive(Clone, Default)]
pub struct RecallLedgerState {
    needs: BTreeMap<RecallNeedId, (RecallNeed, u64)>,
    presentation_attempts: BTreeSet<evertrace_domain::ids::PresentationAttemptId>,
    last_presentation_attempts:
        BTreeMap<RecallNeedId, evertrace_domain::ids::PresentationAttemptId>,
}

impl RecallLedgerState {
    pub fn apply(&mut self, event: RecallLedgerEvent, seq: u64) -> Result<(), StoreError> {
        if !event.validate() {
            return Err(StoreError::StoreCorrupt);
        }
        match event {
            RecallLedgerEvent::NeedRecorded { need } => self.record_need(*need, seq),
            RecallLedgerEvent::PresentationAttempt { attempt } => {
                let (need, source_seq) = self
                    .needs
                    .get_mut(&attempt.recall_need_id)
                    .ok_or(StoreError::StoreCorrupt)?;
                if need.recall_need_hash != attempt.recall_need_hash
                    || need.boundary_event_ref != attempt.boundary_event_ref
                    || need.obligation_state != RecallObligationState::Active
                {
                    return Err(StoreError::StoreCorrupt);
                }
                match attempt.state {
                    PresentationAttemptState::ClaimedForBoundary => {
                        if self
                            .presentation_attempts
                            .contains(&attempt.presentation_attempt_id)
                            || !matches!(
                                need.delivery_state,
                                RecallDeliveryState::Detected
                                    | RecallDeliveryState::Scheduled
                                    | RecallDeliveryState::FailedPreEmit
                            )
                        {
                            return Err(StoreError::StoreCorrupt);
                        }
                        self.presentation_attempts
                            .insert(attempt.presentation_attempt_id);
                        self.last_presentation_attempts
                            .insert(attempt.recall_need_id, attempt.presentation_attempt_id);
                        need.active_presentation_attempt_id = Some(attempt.presentation_attempt_id);
                        need.delivery_state = RecallDeliveryState::ClaimedForBoundary;
                    }
                    state => {
                        if !self
                            .presentation_attempts
                            .contains(&attempt.presentation_attempt_id)
                            || need.active_presentation_attempt_id
                                != Some(attempt.presentation_attempt_id)
                            || need.delivery_state != RecallDeliveryState::ClaimedForBoundary
                        {
                            return Err(StoreError::StoreCorrupt);
                        }
                        need.delivery_state = match state {
                            PresentationAttemptState::FailedPreEmit => {
                                RecallDeliveryState::FailedPreEmit
                            }
                            PresentationAttemptState::Emitted => RecallDeliveryState::Emitted,
                            PresentationAttemptState::HostPresented => {
                                RecallDeliveryState::HostPresented
                            }
                            PresentationAttemptState::PresentationUnknown => {
                                RecallDeliveryState::PresentationUnknown
                            }
                            PresentationAttemptState::ClaimedForBoundary => unreachable!(),
                        };
                        if state == PresentationAttemptState::FailedPreEmit {
                            need.active_presentation_attempt_id = None;
                        }
                    }
                }
                *source_seq = seq;
                Ok(())
            }
            RecallLedgerEvent::RetrievalOutcome { outcome } => {
                let (need, source_seq) = self
                    .needs
                    .get_mut(&outcome.recall_need_id)
                    .ok_or(StoreError::StoreCorrupt)?;
                if need.recall_need_hash != outcome.recall_need_hash
                    || need.obligation_state != RecallObligationState::Active
                {
                    return Err(StoreError::StoreCorrupt);
                }
                match outcome.state {
                    RetrievalOutcomeState::Claimed => {
                        if need.agent_response != RecallAgentResponse::NotRetrieved
                            || need.active_retrieval_request_id.is_some()
                        {
                            return Err(StoreError::StoreCorrupt);
                        }
                        need.active_retrieval_request_id = Some(outcome.request_id);
                        need.agent_response = RecallAgentResponse::RetrievalClaimed;
                    }
                    RetrievalOutcomeState::Returned | RetrievalOutcomeState::Unknown => {
                        if need.agent_response != RecallAgentResponse::RetrievalClaimed
                            || need.active_retrieval_request_id.as_deref()
                                != Some(outcome.request_id.as_str())
                        {
                            return Err(StoreError::StoreCorrupt);
                        }
                        need.agent_response = if outcome.state == RetrievalOutcomeState::Returned {
                            RecallAgentResponse::RetrievalReturned
                        } else {
                            RecallAgentResponse::RetrievalUnknown
                        };
                    }
                }
                *source_seq = seq;
                Ok(())
            }
        }
    }

    fn record_need(&mut self, need: RecallNeed, seq: u64) -> Result<(), StoreError> {
        if let Some((current, _)) = self.needs.get(&need.recall_need_id) {
            if need.parent_revision_id != Some(current.revision_id)
                || !same_need_identity(current, &need)
                || !same_delivery_and_agent_axes(current, &need)
                || !legal_obligation_successor(current, &need)
            {
                return Err(StoreError::StoreCorrupt);
            }
        } else if need.parent_revision_id.is_some()
            || need.delivery_state != RecallDeliveryState::Detected
            || need.agent_response != RecallAgentResponse::NotRetrieved
            || need.obligation_state != RecallObligationState::Active
            || need.active_presentation_attempt_id.is_some()
            || need.active_retrieval_request_id.is_some()
        {
            return Err(StoreError::StoreCorrupt);
        }
        self.needs.insert(need.recall_need_id, (need, seq));
        Ok(())
    }

    pub fn restore(&mut self, row: &ObjectRow, need: RecallNeed) -> Result<(), StoreError> {
        if row.row_kind != ObjectRowKind::Data
            || row.row_class != Some(ObjectRowClass::Runtime)
            || row.object_family.is_some()
            || row.object_kind.as_deref() != Some(RECALL_NEED_KIND)
            || row.object_id.is_some()
            || row.current_revision_id.as_deref() != Some(need.revision_id.to_string().as_str())
            || row.row_id != format!("runtime:recall_need:{}", need.recall_need_id)
            || !need.validate()
            || self.needs.contains_key(&need.recall_need_id)
        {
            return Err(StoreError::StoreCorrupt);
        }
        let recall_need_id = need.recall_need_id;
        if let Some(attempt_id) = need.active_presentation_attempt_id {
            if !self.presentation_attempts.insert(attempt_id) {
                return Err(StoreError::StoreCorrupt);
            }
            self.last_presentation_attempts
                .insert(recall_need_id, attempt_id);
        }
        self.needs
            .insert(recall_need_id, (need, row.source_event_seq));
        Ok(())
    }

    pub fn rows(self, generation: u64) -> Result<Vec<ObjectRow>, StoreError> {
        self.needs
            .into_values()
            .map(|(need, source_event_seq)| {
                Ok(ObjectRow {
                    row_id: format!("runtime:recall_need:{}", need.recall_need_id),
                    row_kind: ObjectRowKind::Data,
                    row_class: Some(ObjectRowClass::Runtime),
                    object_family: None,
                    object_kind: Some(RECALL_NEED_KIND.into()),
                    object_id: None,
                    current_revision_id: Some(need.revision_id.to_string()),
                    lifecycle: Some(
                        if need.obligation_state == RecallObligationState::Active {
                            "active"
                        } else {
                            "inactive"
                        }
                        .into(),
                    ),
                    epistemic: Some("runtime_ledger".into()),
                    authority: Some("none".into()),
                    publication_state: None,
                    support_state: None,
                    project_id: None,
                    repository_id: need.repository_id.map(|value| value.to_string()),
                    worktree_id: need.worktree_id.map(|value| value.to_string()),
                    task_id: Some(need.task_id.to_string()),
                    workstream_id: Some(need.workstream_id.to_string()),
                    session_id: Some(need.session_id.clone()),
                    payload_json: Some(
                        JournalPayload::RecallLedgerRecorded(Box::new(
                            RecallLedgerEvent::NeedRecorded {
                                need: Box::new(need),
                            },
                        ))
                        .canonical_json()?,
                    ),
                    source_event_seq,
                    projection_generation: generation,
                })
            })
            .collect()
    }

    pub fn values(&self) -> impl Iterator<Item = &RecallNeed> {
        self.needs.values().map(|(need, _)| need)
    }

    pub(crate) fn last_presentation_attempt(
        &self,
        recall_need_id: RecallNeedId,
    ) -> Option<evertrace_domain::ids::PresentationAttemptId> {
        self.last_presentation_attempts
            .get(&recall_need_id)
            .copied()
    }
}

fn same_need_identity(current: &RecallNeed, next: &RecallNeed) -> bool {
    current.recall_need_id == next.recall_need_id
        && current.session_id == next.session_id
        && current.execution_lane_id == next.execution_lane_id
        && current.task_id == next.task_id
        && current.workstream_id == next.workstream_id
        && current.episode_revision_id == next.episode_revision_id
        && current.repository_id == next.repository_id
        && current.worktree_id == next.worktree_id
        && current.boundary_event_ref == next.boundary_event_ref
        && current.created_at_us == next.created_at_us
        && current.obligation_expires_at_us == next.obligation_expires_at_us
}

fn same_delivery_and_agent_axes(current: &RecallNeed, next: &RecallNeed) -> bool {
    current.delivery_state == next.delivery_state
        && current.agent_response == next.agent_response
        && current.active_presentation_attempt_id == next.active_presentation_attempt_id
        && current.active_retrieval_request_id == next.active_retrieval_request_id
}

fn legal_obligation_successor(current: &RecallNeed, next: &RecallNeed) -> bool {
    if current.obligation_state != RecallObligationState::Active {
        return false;
    }
    if next.obligation_state == RecallObligationState::Active {
        let mutable_plan = matches!(
            current.delivery_state,
            RecallDeliveryState::Detected
                | RecallDeliveryState::Scheduled
                | RecallDeliveryState::FailedPreEmit
        ) && (current.recall_need_hash != next.recall_need_hash
            || current.recall_plan_fingerprint != next.recall_plan_fingerprint)
            && current.presentation_expires_at_us == next.presentation_expires_at_us;
        let rearm = matches!(
            current.delivery_state,
            RecallDeliveryState::Detected
                | RecallDeliveryState::Scheduled
                | RecallDeliveryState::FailedPreEmit
        ) && current.active_presentation_attempt_id.is_none()
            && current.recall_need_hash == next.recall_need_hash
            && current.recall_plan_fingerprint == next.recall_plan_fingerprint
            && current.trigger_family == next.trigger_family
            && current.source_revision_ids == next.source_revision_ids
            && current.matched_contract_ids == next.matched_contract_ids
            && current.trigger_state == next.trigger_state
            && current.source_watermark == next.source_watermark
            && current.recall_plan == next.recall_plan
            && next.presentation_expires_at_us > current.presentation_expires_at_us;
        mutable_plan || rearm
    } else {
        current.recall_need_hash == next.recall_need_hash
            && current.presentation_expires_at_us == next.presentation_expires_at_us
            && current.recall_plan_fingerprint == next.recall_plan_fingerprint
            && current.trigger_family == next.trigger_family
            && current.source_revision_ids == next.source_revision_ids
            && current.matched_contract_ids == next.matched_contract_ids
            && current.trigger_state == next.trigger_state
            && current.source_watermark == next.source_watermark
            && current.recall_plan == next.recall_plan
    }
}

pub fn need(row: &ObjectRow) -> Result<Option<RecallNeed>, StoreError> {
    if row.object_kind.as_deref() != Some(RECALL_NEED_KIND) {
        return Ok(None);
    }
    let payload_json = row
        .payload_json
        .as_deref()
        .ok_or(StoreError::StoreCorrupt)?;
    let payload: JournalPayload =
        serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
    if payload.canonical_json()? != payload_json {
        return Err(StoreError::StoreCorrupt);
    }
    let JournalPayload::RecallLedgerRecorded(event) = payload else {
        return Err(StoreError::StoreCorrupt);
    };
    let RecallLedgerEvent::NeedRecorded { need } = *event else {
        return Err(StoreError::StoreCorrupt);
    };
    if !need.validate() {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(Some(*need))
}

#[cfg(test)]
mod tests {
    use evertrace_domain::{
        ids::{ExecutionLaneId, PresentationAttemptId, RecallNeedId, TaskId, WorkstreamId},
        recall::{
            RecallAgentResponse, RecallDeliveryState, RecallLedgerEvent, RecallNeed,
            RecallObligationState, RecallPlan, RecallPresentationAttempt, RecallRetrievalOutcome,
            RecallTriggerState, RetrievalOutcomeState, TriggerFamily,
        },
        revision::RevisionId,
        work::{CheckpointVerifierState, PhaseKind},
    };

    use super::*;

    fn need() -> RecallNeed {
        let source = RevisionId::new_v7();
        RecallNeed {
            recall_need_id: RecallNeedId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            recall_need_hash: [0; 32],
            trigger_family: TriggerFamily::ExplicitOrRecovery,
            source_revision_ids: vec![source],
            matched_contract_ids: Vec::new(),
            session_id: "session-s22".into(),
            execution_lane_id: ExecutionLaneId::new_v7(),
            task_id: TaskId::new_v7(),
            workstream_id: WorkstreamId::new_v7(),
            episode_revision_id: source,
            repository_id: None,
            worktree_id: None,
            boundary_event_ref: "boundary:s22".into(),
            trigger_state: RecallTriggerState {
                phase_kind: PhaseKind::Deliver,
                verifier_state: CheckpointVerifierState::Passed,
                attempt_ids: Vec::new(),
                worktree_snapshot_id: None,
                binding_revision_id: None,
                scope_effect_refs: Vec::new(),
            },
            source_watermark: 1,
            recall_plan_fingerprint: [0; 32],
            recall_plan: RecallPlan {
                reason: "explicit_or_recovery".into(),
                normative_constraint_refs: Vec::new(),
                relevant_episode_revision: Some(source),
                applicable_procedure_revision: None,
                open_loops: vec!["loop:s22".into()],
                stale_delivered_objects: Vec::new(),
                supporting_evidence_refs: Vec::new(),
            },
            delivery_state: RecallDeliveryState::Detected,
            agent_response: RecallAgentResponse::NotRetrieved,
            obligation_state: RecallObligationState::Active,
            created_at_us: 1,
            presentation_expires_at_us: 10,
            obligation_expires_at_us: None,
            active_presentation_attempt_id: None,
            active_retrieval_request_id: None,
        }
        .seal()
        .unwrap()
    }

    #[test]
    fn presentation_and_retrieval_axes_are_immutable_and_rebuildable() {
        let need = need();
        let need_id = need.recall_need_id;
        let need_hash = need.recall_need_hash;
        let attempt_id = PresentationAttemptId::new_v7();
        let mut state = RecallLedgerState::default();
        state
            .apply(
                RecallLedgerEvent::NeedRecorded {
                    need: Box::new(need),
                },
                1,
            )
            .unwrap();
        assert!(
            state
                .apply(
                    RecallLedgerEvent::PresentationAttempt {
                        attempt: RecallPresentationAttempt {
                            presentation_attempt_id: attempt_id,
                            recall_need_id: need_id,
                            recall_need_hash: need_hash,
                            boundary_event_ref: "boundary:other".into(),
                            state: PresentationAttemptState::ClaimedForBoundary,
                            occurred_at_us: 2,
                        },
                    },
                    2,
                )
                .is_err()
        );
        state
            .apply(
                RecallLedgerEvent::PresentationAttempt {
                    attempt: RecallPresentationAttempt {
                        presentation_attempt_id: attempt_id,
                        recall_need_id: need_id,
                        recall_need_hash: need_hash,
                        boundary_event_ref: "boundary:s22".into(),
                        state: PresentationAttemptState::ClaimedForBoundary,
                        occurred_at_us: 2,
                    },
                },
                2,
            )
            .unwrap();
        state
            .apply(
                RecallLedgerEvent::PresentationAttempt {
                    attempt: RecallPresentationAttempt {
                        presentation_attempt_id: attempt_id,
                        recall_need_id: need_id,
                        recall_need_hash: need_hash,
                        boundary_event_ref: "boundary:s22".into(),
                        state: PresentationAttemptState::Emitted,
                        occurred_at_us: 3,
                    },
                },
                3,
            )
            .unwrap();
        let retrieval = RecallRetrievalOutcome {
            request_id: "request:s22".into(),
            recall_need_id: need_id,
            recall_need_hash: need_hash,
            state: RetrievalOutcomeState::Claimed,
            occurred_at_us: 4,
        };
        state
            .apply(
                RecallLedgerEvent::RetrievalOutcome {
                    outcome: retrieval.clone(),
                },
                4,
            )
            .unwrap();
        assert!(
            state
                .apply(
                    RecallLedgerEvent::RetrievalOutcome { outcome: retrieval },
                    5,
                )
                .is_err()
        );
        let rows = state.rows(1).unwrap();
        rows[0].validate().unwrap();
        let restored = super::need(&rows[0]).unwrap().unwrap();
        assert_eq!(restored.delivery_state, RecallDeliveryState::Emitted);
        assert_eq!(
            restored.agent_response,
            RecallAgentResponse::RetrievalClaimed
        );
    }

    #[test]
    fn need_successors_freeze_identity_axes_and_terminal_state_but_failed_emit_can_retry() {
        let initial = need();
        let mut state = RecallLedgerState::default();
        state
            .apply(
                RecallLedgerEvent::NeedRecorded {
                    need: Box::new(initial.clone()),
                },
                1,
            )
            .unwrap();
        let first = PresentationAttemptId::new_v7();
        for (seq, attempt_id, attempt_state) in [
            (2, first, PresentationAttemptState::ClaimedForBoundary),
            (3, first, PresentationAttemptState::FailedPreEmit),
            (
                4,
                PresentationAttemptId::new_v7(),
                PresentationAttemptState::ClaimedForBoundary,
            ),
        ] {
            state
                .apply(
                    RecallLedgerEvent::PresentationAttempt {
                        attempt: RecallPresentationAttempt {
                            presentation_attempt_id: attempt_id,
                            recall_need_id: initial.recall_need_id,
                            recall_need_hash: initial.recall_need_hash,
                            boundary_event_ref: initial.boundary_event_ref.clone(),
                            state: attempt_state,
                            occurred_at_us: seq,
                        },
                    },
                    u64::try_from(seq).unwrap(),
                )
                .unwrap();
            if attempt_state == PresentationAttemptState::FailedPreEmit {
                let rows = state.clone().rows(1).unwrap();
                rows[0].validate().unwrap();
                let failed = super::need(&rows[0]).unwrap().unwrap();
                assert_eq!(failed.delivery_state, RecallDeliveryState::FailedPreEmit);
                assert_eq!(failed.active_presentation_attempt_id, None);
                let mut restored = RecallLedgerState::default();
                restored.restore(&rows[0], failed).unwrap();
                assert!(
                    state
                        .apply(
                            RecallLedgerEvent::PresentationAttempt {
                                attempt: RecallPresentationAttempt {
                                    presentation_attempt_id: first,
                                    recall_need_id: initial.recall_need_id,
                                    recall_need_hash: initial.recall_need_hash,
                                    boundary_event_ref: initial.boundary_event_ref.clone(),
                                    state: PresentationAttemptState::ClaimedForBoundary,
                                    occurred_at_us: seq,
                                },
                            },
                            u64::try_from(seq).unwrap(),
                        )
                        .is_err()
                );
            }
        }
        assert_eq!(
            state.values().next().unwrap().delivery_state,
            RecallDeliveryState::ClaimedForBoundary
        );

        let mut forged = state.values().next().unwrap().clone();
        forged.parent_revision_id = Some(forged.revision_id);
        forged.revision_id = RevisionId::new_v7();
        forged.session_id = "session:forged".into();
        let forged = forged.seal().unwrap();
        assert!(
            state
                .apply(
                    RecallLedgerEvent::NeedRecorded {
                        need: Box::new(forged),
                    },
                    5,
                )
                .is_err()
        );

        let mut terminal_state = RecallLedgerState::default();
        terminal_state
            .apply(
                RecallLedgerEvent::NeedRecorded {
                    need: Box::new(initial),
                },
                1,
            )
            .unwrap();
        let mut terminal = terminal_state.values().next().unwrap().clone();
        terminal.parent_revision_id = Some(terminal.revision_id);
        terminal.revision_id = RevisionId::new_v7();
        terminal.obligation_state = RecallObligationState::Canceled;
        let terminal = terminal.seal().unwrap();
        terminal_state
            .apply(
                RecallLedgerEvent::NeedRecorded {
                    need: Box::new(terminal),
                },
                2,
            )
            .unwrap();
        let mut resurrection = terminal_state.values().next().unwrap().clone();
        resurrection.parent_revision_id = Some(resurrection.revision_id);
        resurrection.revision_id = RevisionId::new_v7();
        resurrection.obligation_state = RecallObligationState::Active;
        let resurrection = resurrection.seal().unwrap();
        assert!(
            terminal_state
                .apply(
                    RecallLedgerEvent::NeedRecorded {
                        need: Box::new(resurrection),
                    },
                    3,
                )
                .is_err()
        );
    }

    #[test]
    fn an_unclaimed_active_need_allows_one_monotonic_expiry_rearm() {
        let initial = need();
        let mut state = RecallLedgerState::default();
        state
            .apply(
                RecallLedgerEvent::NeedRecorded {
                    need: Box::new(initial.clone()),
                },
                1,
            )
            .unwrap();
        let mut rearmed = initial.clone();
        rearmed.revision_id = RevisionId::new_v7();
        rearmed.parent_revision_id = Some(initial.revision_id);
        rearmed.presentation_expires_at_us += 10;
        let rearmed = rearmed.seal().unwrap();
        state
            .apply(
                RecallLedgerEvent::NeedRecorded {
                    need: Box::new(rearmed.clone()),
                },
                2,
            )
            .unwrap();
        let mut unchanged = rearmed.clone();
        unchanged.revision_id = RevisionId::new_v7();
        unchanged.parent_revision_id = Some(rearmed.revision_id);
        let unchanged = unchanged.seal().unwrap();
        assert!(
            state
                .apply(
                    RecallLedgerEvent::NeedRecorded {
                        need: Box::new(unchanged),
                    },
                    3,
                )
                .is_err()
        );
    }

    #[test]
    fn claimed_current_object_restores_the_minimum_attempt_fence_for_outcome_delta() {
        let initial = need();
        let attempt_id = PresentationAttemptId::new_v7();
        let claim = RecallLedgerEvent::PresentationAttempt {
            attempt: RecallPresentationAttempt {
                presentation_attempt_id: attempt_id,
                recall_need_id: initial.recall_need_id,
                recall_need_hash: initial.recall_need_hash,
                boundary_event_ref: initial.boundary_event_ref.clone(),
                state: PresentationAttemptState::ClaimedForBoundary,
                occurred_at_us: 2,
            },
        };
        let mut uninterrupted = RecallLedgerState::default();
        uninterrupted
            .apply(
                RecallLedgerEvent::NeedRecorded {
                    need: Box::new(initial),
                },
                1,
            )
            .unwrap();
        uninterrupted.apply(claim, 2).unwrap();
        let row = uninterrupted.clone().rows(1).unwrap().remove(0);
        let current = super::need(&row).unwrap().unwrap();
        let mut restored = RecallLedgerState::default();
        restored.restore(&row, current).unwrap();
        let outcome = RecallLedgerEvent::PresentationAttempt {
            attempt: RecallPresentationAttempt {
                presentation_attempt_id: attempt_id,
                recall_need_id: row
                    .row_id
                    .strip_prefix("runtime:recall_need:")
                    .unwrap()
                    .parse()
                    .unwrap(),
                recall_need_hash: super::need(&row).unwrap().unwrap().recall_need_hash,
                boundary_event_ref: super::need(&row).unwrap().unwrap().boundary_event_ref,
                state: PresentationAttemptState::Emitted,
                occurred_at_us: 3,
            },
        };
        uninterrupted.apply(outcome.clone(), 3).unwrap();
        restored.apply(outcome, 3).unwrap();
        assert_eq!(restored.rows(1).unwrap(), uninterrupted.rows(1).unwrap());
    }
}
