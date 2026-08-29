use std::time::{SystemTime, UNIX_EPOCH};

use evertrace_capture::RecallCueGateMode;
use evertrace_domain::{
    ids::CommandId,
    recall::{
        PresentationAttemptState, RecallCueSnapshot, RecallDeliveryState, RecallLedgerEvent,
        RecallNeed, RecallObligationState, RecallPresentationAttempt,
    },
};
use evertrace_store::{JournalCommand, JournalEventDraft, JournalPayload, RecallCurrentContext};
use thiserror::Error;

use crate::{WriterActorError, WriterHandle};

use super::{RecallNeedValidity, RecallTriggerIndex, detector::current_need_validity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecallCueOutcome {
    Authorized,
    OutcomeAccepted,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecallCueError {
    #[error("recall cue input is invalid")]
    InvalidInput,
    #[error("recall cue state is ambiguous or corrupt")]
    Store,
}

#[derive(Clone)]
pub struct RecallCueService {
    writer: WriterHandle,
    gate: RecallCueGateMode,
    adapter_manifest_id: Option<String>,
    runtime_generation: u64,
    effective_config_hash: [u8; 32],
    runtime_snapshot_path: std::path::PathBuf,
}

impl RecallCueService {
    pub fn new(
        writer: WriterHandle,
        gate: RecallCueGateMode,
        adapter_manifest_id: Option<String>,
        runtime_generation: u64,
        effective_config_hash: [u8; 32],
        data_dir: &std::path::Path,
    ) -> Self {
        Self {
            writer,
            gate,
            adapter_manifest_id,
            runtime_generation,
            effective_config_hash,
            runtime_snapshot_path: evertrace_capture::RuntimeSnapshot::snapshot_path(data_dir),
        }
    }

    pub async fn authorize(
        &self,
        claim: &RecallCueSnapshot,
    ) -> Result<RecallCueOutcome, RecallCueError> {
        if !self.valid_claim(claim) {
            return Err(RecallCueError::InvalidInput);
        }
        if !claim_is_published(&self.runtime_snapshot_path, self.runtime_generation, claim)? {
            return Err(RecallCueError::InvalidInput);
        }
        let now = now_us()?;
        if claim.expires_at_us <= now {
            return Err(RecallCueError::InvalidInput);
        }
        for retry in 0..2 {
            let contexts = self.contexts().await?;
            let index = RecallTriggerIndex::from_current_contexts(frontier(&contexts)?, &contexts)
                .map_err(|_| RecallCueError::Store)?;
            let (context, need) = select_need(&contexts, claim, false)?;
            if !latest_valid(context, need, &index, now, &claim.adapter_manifest_id) {
                return Err(RecallCueError::Store);
            }
            let event = presentation_event(
                need,
                claim,
                PresentationAttemptState::ClaimedForBoundary,
                now,
            );
            match self.commit(event, now, context.frontier).await {
                Ok(()) => return Ok(RecallCueOutcome::Authorized),
                Err(WriterActorError::StaleFrontier) if retry == 0 => continue,
                Err(_) => return Err(RecallCueError::Store),
            }
        }
        Err(RecallCueError::Store)
    }

    pub async fn outcome(
        &self,
        claim: &RecallCueSnapshot,
        outcome: PresentationAttemptState,
    ) -> Result<RecallCueOutcome, RecallCueError> {
        if !self.valid_claim(claim)
            || !matches!(
                outcome,
                PresentationAttemptState::Emitted
                    | PresentationAttemptState::FailedPreEmit
                    | PresentationAttemptState::PresentationUnknown
            )
        {
            return Err(RecallCueError::InvalidInput);
        }
        let now = now_us()?;
        for retry in 0..2 {
            let contexts = self.contexts().await?;
            if let Some(replayed) = replayed_outcome(&contexts, claim, outcome) {
                return if replayed {
                    Ok(RecallCueOutcome::OutcomeAccepted)
                } else {
                    Err(RecallCueError::Store)
                };
            }
            let (context, need) = select_need(&contexts, claim, true)?;
            let event = presentation_event(need, claim, outcome, now);
            match self.commit(event, now, context.frontier).await {
                Ok(()) => return Ok(RecallCueOutcome::OutcomeAccepted),
                Err(WriterActorError::StaleFrontier) if retry == 0 => continue,
                Err(_) => return Err(RecallCueError::Store),
            }
        }
        Err(RecallCueError::Store)
    }

    async fn contexts(&self) -> Result<Vec<RecallCurrentContext>, RecallCueError> {
        self.writer
            .recall_current_contexts(32)
            .await
            .map_err(|_| RecallCueError::Store)
    }

    async fn commit(
        &self,
        event: RecallLedgerEvent,
        now: i64,
        frontier: u64,
    ) -> Result<(), WriterActorError> {
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                now,
                self.effective_config_hash,
                "s22-recall-v1",
                JournalPayload::RecallLedgerRecorded(Box::new(event)),
            )],
        )
        .map_err(|_| WriterActorError::InvalidInput)?;
        self.writer
            .commit_if_frontier(command, now, frontier)
            .await
            .map(|_| ())
    }

    fn valid_claim(&self, claim: &RecallCueSnapshot) -> bool {
        self.gate == RecallCueGateMode::Active
            && claim.validate()
            && claim.runtime_generation == self.runtime_generation
            && self.adapter_manifest_id.as_deref() == Some(&claim.adapter_manifest_id)
    }
}

fn claim_is_published(
    path: &std::path::Path,
    generation: u64,
    claim: &RecallCueSnapshot,
) -> Result<bool, RecallCueError> {
    let published =
        evertrace_capture::RuntimeSnapshot::load(path).map_err(|_| RecallCueError::Store)?;
    Ok(published.generation == generation && published.recall_cues.iter().any(|cue| cue == claim))
}

fn replayed_outcome(
    contexts: &[RecallCurrentContext],
    claim: &RecallCueSnapshot,
    outcome: PresentationAttemptState,
) -> Option<bool> {
    let mut selected = None;
    for context in contexts {
        for need in &context.needs {
            if context.execution_lane.host_session_id == claim.session_id
                && context.execution_lane.execution_lane_id == claim.execution_lane_id
                && context.execution_lane.host_lane_key == claim.host_lane_key
                && need.recall_need_hash == claim.recall_need_hash
                && context.last_presentation_attempts.get(&need.recall_need_id)
                    == Some(&claim.presentation_attempt_id)
                && need.delivery_state != RecallDeliveryState::ClaimedForBoundary
            {
                if selected.is_some() {
                    return Some(false);
                }
                selected = Some(matches!(
                    (need.delivery_state, outcome),
                    (
                        RecallDeliveryState::FailedPreEmit,
                        PresentationAttemptState::FailedPreEmit
                    ) | (
                        RecallDeliveryState::Emitted,
                        PresentationAttemptState::Emitted
                    ) | (
                        RecallDeliveryState::PresentationUnknown,
                        PresentationAttemptState::PresentationUnknown
                    )
                ));
            }
        }
    }
    selected
}

fn frontier(contexts: &[RecallCurrentContext]) -> Result<u64, RecallCueError> {
    let Some(frontier) = contexts.first().map(|context| context.frontier) else {
        return Err(RecallCueError::Store);
    };
    contexts
        .iter()
        .all(|context| context.frontier == frontier)
        .then_some(frontier)
        .ok_or(RecallCueError::Store)
}

fn select_need<'a>(
    contexts: &'a [RecallCurrentContext],
    claim: &RecallCueSnapshot,
    claimed: bool,
) -> Result<(&'a RecallCurrentContext, &'a RecallNeed), RecallCueError> {
    let mut matches = contexts.iter().flat_map(|context| {
        context.needs.iter().filter_map(move |need| {
            (context.execution_lane.host_session_id == claim.session_id
                && context.execution_lane.execution_lane_id == claim.execution_lane_id
                && context.execution_lane.host_lane_key == claim.host_lane_key
                && need.recall_need_hash == claim.recall_need_hash
                && need.obligation_state == RecallObligationState::Active
                && if claimed {
                    need.delivery_state == RecallDeliveryState::ClaimedForBoundary
                        && need.active_presentation_attempt_id
                            == Some(claim.presentation_attempt_id)
                } else {
                    matches!(
                        need.delivery_state,
                        RecallDeliveryState::Detected
                            | RecallDeliveryState::Scheduled
                            | RecallDeliveryState::FailedPreEmit
                    ) && need.active_presentation_attempt_id.is_none()
                        && context.last_presentation_attempts.get(&need.recall_need_id)
                            != Some(&claim.presentation_attempt_id)
                })
            .then_some((context, need))
        })
    });
    let selected = matches.next().ok_or(RecallCueError::Store)?;
    matches
        .next()
        .is_none()
        .then_some(selected)
        .ok_or(RecallCueError::Store)
}

fn latest_valid(
    context: &RecallCurrentContext,
    need: &RecallNeed,
    index: &RecallTriggerIndex,
    now: i64,
    adapter_manifest_id: &str,
) -> bool {
    if need.presentation_expires_at_us <= now
        || !context
            .execution_lane
            .adapter_manifest_ids
            .iter()
            .any(|value| value == adapter_manifest_id)
        || need.boundary_event_ref != context.checkpoint.stable_key()
        || need.source_watermark != context.checkpoint.source_watermark
        || need.task_id != context.task.task_id
        || need.workstream_id != context.workstream.workstream_id
        || need.episode_revision_id != context.episode.revision_id
        || !need.recall_plan.validate()
    {
        return false;
    }
    current_need_validity(context, need, index, now) == Ok(RecallNeedValidity::Valid)
}

fn presentation_event(
    need: &RecallNeed,
    claim: &RecallCueSnapshot,
    state: PresentationAttemptState,
    occurred_at_us: i64,
) -> RecallLedgerEvent {
    RecallLedgerEvent::PresentationAttempt {
        attempt: RecallPresentationAttempt {
            presentation_attempt_id: claim.presentation_attempt_id,
            recall_need_id: need.recall_need_id,
            recall_need_hash: need.recall_need_hash,
            boundary_event_ref: need.boundary_event_ref.clone(),
            state,
            occurred_at_us,
        },
    }
}

fn now_us() -> Result<i64, RecallCueError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_micros()).ok())
        .ok_or(RecallCueError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use evertrace_capture::{
        RecallCueGateMode, RecoveryGateMode, RecoverySnapshotSettings, RuntimeSnapshot, SpoolLimits,
    };
    use evertrace_domain::ids::{ExecutionLaneId, PresentationAttemptId};

    use super::*;

    #[test]
    fn valid_checksum_is_not_authority_without_exact_published_membership() {
        let root = std::env::temp_dir().join(format!(
            "evertrace-cue-test-{}",
            evertrace_domain::ids::RequestId::new_v7()
        ));
        std::fs::create_dir(&root).unwrap();
        let mut runtime = RuntimeSnapshot::for_data_dir(
            &root,
            9,
            SpoolLimits {
                high_watermark_bytes: 1024,
                low_watermark_bytes: 512,
                max_main_files: 4,
                emergency_slots: 2,
            },
            RecoverySnapshotSettings {
                gate: RecoveryGateMode::Disabled,
                preflight_timeout_ms: 100,
                effective_config_hash: [7; 32],
                adapter_manifest_id: None,
                classifier_revision: 1,
                max_bundle_bytes: 4096,
                max_untracked_file_bytes: 1024,
                max_untracked_total_bytes: 2048,
                recall_cue_gate: RecallCueGateMode::Active,
                recall_cue_adapter_manifest_id: Some("adapter:s22".into()),
            },
        )
        .unwrap();
        let claim = RecallCueSnapshot {
            session_id: "session:s22".into(),
            execution_lane_id: ExecutionLaneId::new_v7(),
            host_lane_key: "lane:s22".into(),
            adapter_manifest_id: "adapter:s22".into(),
            runtime_generation: 9,
            recall_need_hash: [8; 32],
            presentation_attempt_id: PresentationAttemptId::new_v7(),
            expires_at_us: i64::MAX,
            checksum: [0; 32],
        }
        .seal()
        .unwrap();
        let path = RuntimeSnapshot::snapshot_path(&root);
        runtime.publish(&path).unwrap();
        assert!(!claim_is_published(&path, 9, &claim).unwrap());
        runtime.recall_cues.push(claim.clone());
        runtime.publish(&path).unwrap();
        assert!(claim_is_published(&path, 9, &claim).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }
}
