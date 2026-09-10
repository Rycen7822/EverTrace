//! Ephemeral, source-bound stage facts shared by routing and frozen synthesis.
use evertrace_domain::{
    procedure::{ProcedureActions, ProcedureDraft, ProcedureStepAlignment},
    semantic::{
        ConstraintBinding, ConstraintField, ConstraintState, ConstraintTruth, ConstraintValue,
    },
    work::{Attempt, AttemptVerification, WorkCheckpoint, WorkEpisode},
};
use evertrace_store::{JournalPayload, ProjectionSnapshot};
use serde::Serialize;

use super::ProcedurePhase;
use crate::semantic::SemanticServiceError;

const MAX_FRAMES: usize = 256;

#[derive(Clone, Serialize)]
pub(crate) struct StageFrame {
    pub source_refs: Vec<String>,
    pub state: ConstraintState,
    #[serde(skip)]
    sequence: u64,
    #[serde(skip)]
    verifier_witness: Option<u64>,
}

#[derive(Clone, Default, Serialize)]
pub struct StageTrace {
    pub(crate) frames: Vec<StageFrame>,
    pub(crate) truncated: bool,
}

impl StageTrace {
    pub(crate) fn compile(
        snapshot: &ProjectionSnapshot,
        target: &WorkEpisode,
    ) -> Result<Self, SemanticServiceError> {
        let decode = |value: &str| {
            serde_json::from_str::<JournalPayload>(value)
                .map_err(|_| SemanticServiceError::InvalidInput)
        };
        // A target revision, not the live frontier, freezes generation input.
        let boundary = snapshot
            .data_rows()
            .find_map(|row| {
                (row.current_revision_id.as_deref() == Some(&target.revision_id.to_string()))
                    .then_some(row.source_event_seq)
            })
            .ok_or(SemanticServiceError::InvalidInput)?;
        // References into the already validated snapshot, private to this call.
        // Successors without a new checkpoint do not consume a stage frame.
        let mut episodes = std::collections::BTreeMap::new();
        let mut holders = std::collections::BTreeMap::new();
        let mut attempts = std::collections::BTreeMap::new();
        let mut runs = std::collections::BTreeMap::<&str, Vec<&evertrace_store::ObjectRow>>::new();
        for row in snapshot
            .data_rows()
            .filter(|row| row.source_event_seq <= boundary)
        {
            match row.object_kind.as_deref() {
                Some("attempt") => {
                    if let Some(id) = row.current_revision_id.as_deref() {
                        attempts.insert(id, row);
                    }
                }
                Some("experiment_run") => {
                    if let Some(id) = row.object_id.as_deref() {
                        runs.entry(id).or_default().push(row);
                    }
                }
                _ => {}
            }
        }
        for row in snapshot.data_rows().filter(|row| {
            row.object_kind.as_deref() == Some("work_episode") && row.source_event_seq <= boundary
        }) {
            let Some(json) = row.payload_json.as_deref() else {
                return Err(SemanticServiceError::InvalidInput);
            };
            if let JournalPayload::WorkEpisodeRecorded(episode) = decode(json)?
                && episode.task_id == target.task_id
                && episode.workstream_id == target.workstream_id
                && episode.repository_instance_id == target.repository_instance_id
                && episode.worktree_instance_id == target.worktree_instance_id
                && episode.source_watermark <= target.source_watermark
            {
                if !episode.segmentation_correction_refs.is_empty()
                    || !episode.competing_attempt_group_ids.is_empty()
                {
                    return Ok(Self::default());
                }
                for reference in &episode.checkpoint_refs {
                    holders.entry(reference.clone()).or_insert(row);
                }
                episodes.insert(episode.revision_id, row);
            }
        }
        let mut checkpoints = Vec::<(WorkCheckpoint, u64, WorkEpisode)>::new();
        for row in snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("work_checkpoint"))
        {
            let Some(json) = row.payload_json.as_deref() else {
                return Err(SemanticServiceError::InvalidInput);
            };
            if let JournalPayload::WorkCheckpointRecorded(checkpoint) = decode(json)? {
                let Some(holder) = holders.get(&checkpoint.stable_key()) else {
                    continue;
                };
                let Some(base) = episodes.get(&checkpoint.episode_revision_id) else {
                    continue;
                };
                let (Some(holder_json), Some(base_json)) =
                    (holder.payload_json.as_deref(), base.payload_json.as_deref())
                else {
                    return Err(SemanticServiceError::InvalidInput);
                };
                let (
                    JournalPayload::WorkEpisodeRecorded(holder),
                    JournalPayload::WorkEpisodeRecorded(episode),
                ) = (decode(holder_json)?, decode(base_json)?)
                else {
                    return Err(SemanticServiceError::InvalidInput);
                };
                if holder.episode_id != checkpoint.episode_id
                    || holder.source_watermark < checkpoint.source_watermark
                    || holder.phase_contract != checkpoint.phase_contract
                {
                    continue;
                }
                if checkpoints.len() == MAX_FRAMES {
                    return Ok(Self {
                        frames: vec![],
                        truncated: true,
                    });
                }
                checkpoints.push((*checkpoint, row.source_event_seq, *episode));
            }
        }
        checkpoints.sort_by_key(|(checkpoint, seq, _)| (checkpoint.source_watermark, *seq));
        let mut trace = Self::default();
        let mut origins = std::collections::BTreeMap::new();
        for (checkpoint, sequence, episode) in checkpoints {
            checkpoint
                .validate()
                .map_err(|_| SemanticServiceError::InvalidInput)?;
            let selected = if checkpoint.active_attempt_ids.len() == 1 {
                checkpoint.active_attempt_ids.first()
            } else if checkpoint.active_attempt_ids.is_empty()
                && episode.selected_attempt_ids.len() == 1
            {
                episode.selected_attempt_ids.first()
            } else if checkpoint.active_attempt_ids.is_empty()
                && checkpoint.attempt_revision_refs.len() == 1
            {
                Some(&checkpoint.attempt_revision_refs[0].attempt_id)
            } else {
                None
            };
            let reference = selected.and_then(|id| {
                checkpoint
                    .attempt_revision_refs
                    .iter()
                    .find(|value| &value.attempt_id == id)
            });
            let mut attempt = None;
            if let Some(reference) = reference
                && let Some(row) = attempts
                    .get(reference.revision_id.to_string().as_str())
                    .filter(|row| row.source_event_seq <= sequence)
            {
                let Some(json) = row.payload_json.as_deref() else {
                    return Err(SemanticServiceError::InvalidInput);
                };
                if let JournalPayload::AttemptRecorded(value) = decode(json)?
                    && value.attempt_id == reference.attempt_id
                    && value.task_id == episode.task_id
                    && value.workstream_id == episode.workstream_id
                    && value.episode_id == Some(episode.episode_id)
                    && value.repository_instance_id == episode.repository_instance_id
                    && episode
                        .worktree_instance_id
                        .is_some_and(|id| value.worktree_instance_ids.contains(&id))
                {
                    attempt = Some((*value, row.source_event_seq));
                }
            }
            let mut state = ConstraintState {
                bindings: vec![
                    ConstraintBinding {
                        field: ConstraintField::PhaseKind,
                        value: ConstraintValue::Text(
                            serde_json::to_value(checkpoint.phase_contract.phase_kind)
                                .map_err(|_| SemanticServiceError::InvalidInput)?
                                .as_str()
                                .ok_or(SemanticServiceError::InvalidInput)?
                                .into(),
                        ),
                    },
                    ConstraintBinding {
                        field: ConstraintField::RevisionActive,
                        value: ConstraintValue::Boolean(true),
                    },
                    ConstraintBinding {
                        field: ConstraintField::Phase,
                        value: ConstraintValue::Text(checkpoint.phase_contract.phase_label.clone()),
                    },
                ],
            };
            let mut refs = vec![episode.revision_id.to_string(), checkpoint.stable_key()];
            let mut witness = None;
            if let Some((attempt, seq)) = attempt {
                witness = verifier_origin(&attempts, &mut origins, &attempt, seq)?;
                if witness.is_some() {
                    state.bindings.push(ConstraintBinding {
                        field: ConstraintField::VerifierState,
                        value: ConstraintValue::Text(
                            match attempt.verification {
                                AttemptVerification::Unverified => "unverified",
                                AttemptVerification::Passed => "passed",
                                AttemptVerification::Failed => "failed",
                                AttemptVerification::Inconclusive => "inconclusive",
                            }
                            .into(),
                        ),
                    });
                }
                if let Some(signature) = &attempt.failure_signature {
                    state.bindings.push(ConstraintBinding {
                        field: ConstraintField::FailureSignature,
                        value: ConstraintValue::Text(signature.clone()),
                    });
                }
                refs.push(attempt.revision_id.to_string());
                let run_ids = &attempt.experiment_run_ids;
                if run_ids.len() == 1 {
                    let mut selected_run = None;
                    for row in runs
                        .get(run_ids[0].to_string().as_str())
                        .into_iter()
                        .flatten()
                        .filter(|row| row.source_event_seq <= sequence)
                    {
                        let Some(json) = row.payload_json.as_deref() else {
                            return Err(SemanticServiceError::InvalidInput);
                        };
                        if let JournalPayload::ExperimentRunRecorded(run) = decode(json)?
                            && run.run_id == run_ids[0]
                            && run.attempt_id == Some(attempt.attempt_id)
                            && run.workstream_id == episode.workstream_id
                            && run.attempt_binding_status
                                == evertrace_domain::work::AttemptBindingStatus::Resolved
                            && selected_run
                                .as_ref()
                                .is_none_or(|(_, seq)| *seq < row.source_event_seq)
                        {
                            selected_run = Some((run, row.source_event_seq));
                        }
                    }
                    if let Some((run, _)) = selected_run {
                        state.bindings.push(ConstraintBinding {
                            field: ConstraintField::ExperimentState,
                            value: ConstraintValue::Text(run.execution_status.as_str().into()),
                        });
                        refs.push(run.revision_id.to_string());
                    }
                }
            }
            state.bindings.sort_by_key(|binding| binding.field);
            state
                .validate()
                .map_err(|_| SemanticServiceError::InvalidInput)?;
            refs.sort();
            refs.dedup();
            trace.frames.push(StageFrame {
                source_refs: refs,
                state,
                sequence,
                verifier_witness: witness,
            });
        }
        Ok(trace)
    }

    pub(crate) fn current(&self) -> Option<&ConstraintState> {
        self.frames.last().map(|frame| &frame.state)
    }
    pub(crate) fn previous(&self) -> Option<&ConstraintState> {
        self.frames.iter().rev().nth(1).map(|frame| &frame.state)
    }

    pub(crate) fn supports(&self, draft: &ProcedureDraft) -> bool {
        let Some(mapping) = &draft.stage_alignment else {
            return true;
        };
        if self.truncated || self.frames.is_empty() {
            return false;
        }
        mapping
            .main
            .iter()
            .chain(mapping.branches.iter().flat_map(|branch| &branch.steps))
            .flat_map(|step| [&step.entry, &step.progress, &step.completed])
            .chain(
                draft
                    .actions
                    .branches
                    .iter()
                    .map(|branch| &branch.condition),
            )
            .all(|expr| self.supports_expr(expr))
    }

    fn supports_expr(&self, expr: &evertrace_domain::semantic::ConstraintExpr) -> bool {
        use evertrace_domain::semantic::ConstraintExpr::*;
        match expr {
            All { terms } | Any { terms } => terms.iter().all(|term| self.supports_expr(term)),
            Not { term } => self.supports_expr(term),
            Eq { field, value } => self.supports_operand(*field, value),
            In { field, values } => values
                .iter()
                .all(|value| self.supports_operand(*field, value)),
            Transitioned { field, from, to } => {
                self.supports_operand(*field, from) && self.supports_operand(*field, to)
            }
            Exists { field } | Changed { field } => matches!(
                field,
                ConstraintField::Phase
                    | ConstraintField::PhaseKind
                    | ConstraintField::FailureSignature
                    | ConstraintField::VerifierState
                    | ConstraintField::ExperimentState
                    | ConstraintField::RevisionActive
            ),
        }
    }

    fn supports_operand(&self, field: ConstraintField, value: &ConstraintValue) -> bool {
        fn canonical<T: serde::de::DeserializeOwned + Serialize>(value: &ConstraintValue) -> bool {
            let ConstraintValue::Text(text) = value else {
                return false;
            };
            let json = serde_json::Value::String(text.clone());
            serde_json::from_value::<T>(json.clone())
                .ok()
                .and_then(|value| serde_json::to_value(value).ok())
                .as_ref()
                == Some(&json)
        }
        match field {
            ConstraintField::PhaseKind => canonical::<evertrace_domain::work::PhaseKind>(value),
            ConstraintField::VerifierState => canonical::<AttemptVerification>(value),
            ConstraintField::ExperimentState => {
                canonical::<evertrace_domain::work::RunExecutionStatus>(value)
            }
            ConstraintField::RevisionActive => matches!(value, ConstraintValue::Boolean(_)),
            ConstraintField::Phase | ConstraintField::FailureSignature => {
                self.frames.iter().any(|frame| {
                    frame
                        .state
                        .bindings
                        .iter()
                        .any(|binding| binding.field == field && &binding.value == value)
                })
            }
            _ => false,
        }
    }

    pub(crate) fn align(
        &self,
        draft: &ProcedureDraft,
    ) -> Option<(ProcedurePhase, ProcedureActions)> {
        let mapping = draft.stage_alignment.as_ref()?;
        if self.truncated || self.frames.is_empty() {
            return None;
        }
        let mut from = 0;
        for (main_index, step) in mapping.main.iter().enumerate() {
            let entered = match self.entry(step, from) {
                Some(entry) => entry,
                None if main_index == 0
                    && self.frames.iter().enumerate().all(|(index, frame)| {
                        [&step.entry, &step.progress, &step.completed]
                            .iter()
                            .all(|expr| {
                                expr.evaluate(
                                    &frame.state,
                                    index.checked_sub(1).map(|prior| &self.frames[prior].state),
                                ) == ConstraintTruth::False
                            })
                    }) =>
                {
                    let mut actions = draft.actions.clone();
                    actions.branches.clear();
                    return Some((ProcedurePhase::BeforeEntry, actions));
                }
                None => return None,
            };
            let mut cursor = entered;
            let mut branch_from = entered;
            loop {
                let main_completed = self.completed(step, entered, cursor);
                let mut selected = None;
                for index in branch_from..self.frames.len() {
                    if main_completed.is_some_and(|completed| completed <= index) {
                        break;
                    }
                    let mut matches = Vec::new();
                    for (branch_index, branch) in mapping
                        .branches
                        .iter()
                        .enumerate()
                        .filter(|(_, branch)| branch.at_main_step == main_index)
                    {
                        let condition = draft.actions.branches[branch_index].condition.evaluate(
                            &self.frames[index].state,
                            index.checked_sub(1).map(|prior| &self.frames[prior].state),
                        );
                        match condition {
                            ConstraintTruth::True => matches.push((branch_index, branch)),
                            ConstraintTruth::Unknown => return None,
                            ConstraintTruth::False => {}
                        }
                    }
                    if matches.len() > 1 {
                        return None;
                    }
                    if let Some((branch_index, branch)) = matches.first() {
                        selected = Some((index, *branch_index, *branch));
                        break;
                    }
                }
                if let Some((index, branch_index, branch)) = selected {
                    let mut branch_cursor = index;
                    for (step_index, step) in branch.steps.iter().enumerate() {
                        let entry = self.entry(step, branch_cursor)?;
                        if let Some(completed) = self.completed(step, entry, entry) {
                            branch_cursor = completed;
                        } else {
                            self.position(step)?;
                            let mut actions = draft.actions.clone();
                            actions.stages =
                                draft.actions.branches[branch_index].stages[step_index..].to_vec();
                            actions.branches.clear();
                            return Some((ProcedurePhase::RecoverableDeviation, actions));
                        }
                    }
                    cursor = branch_cursor;
                    // The main step may share this completion boundary, but
                    // another recovery must have a strictly later entry.
                    branch_from = branch_cursor + 1;
                    continue;
                }
                if let Some(completed) = main_completed {
                    from = completed;
                    break;
                }
                let phase = self.position(step)?;
                let mut actions = draft.actions.clone();
                actions.stages = actions.stages[main_index..].to_vec();
                actions.branches.clear();
                return Some((phase, actions));
            }
        }
        Some((
            ProcedurePhase::AlreadyCompleted,
            ProcedureActions {
                stages: vec![],
                branches: vec![],
                avoid: draft.actions.avoid.clone(),
            },
        ))
    }

    fn entry(&self, step: &ProcedureStepAlignment, from: usize) -> Option<usize> {
        (from..self.frames.len()).find(|index| {
            step.entry.evaluate(
                &self.frames[*index].state,
                index.checked_sub(1).map(|prior| &self.frames[prior].state),
            ) == ConstraintTruth::True
        })
    }

    fn completed(&self, step: &ProcedureStepAlignment, entry: usize, from: usize) -> Option<usize> {
        let mut seen_not_complete = false;
        for index in entry..self.frames.len() {
            let value = step.completed.evaluate(
                &self.frames[index].state,
                index.checked_sub(1).map(|prior| &self.frames[prior].state),
            );
            if value == ConstraintTruth::False {
                seen_not_complete = true;
            }
            let fresh_verifier = self.frames[index]
                .verifier_witness
                .is_some_and(|seq| seq > self.frames[entry].sequence);
            // Removing this fact must remove the positive proof. Merely
            // mentioning a new verifier in an unrelated OR arm is insufficient.
            let new_positive = fresh_verifier && value == ConstraintTruth::True && {
                let mut without_verifier = self.frames[index].state.clone();
                without_verifier
                    .bindings
                    .retain(|binding| binding.field != ConstraintField::VerifierState);
                step.completed.evaluate(
                    &without_verifier,
                    index.checked_sub(1).map(|prior| &self.frames[prior].state),
                ) != ConstraintTruth::True
            };
            if index > entry
                && index >= from
                && (seen_not_complete || new_positive)
                && value == ConstraintTruth::True
                && (!step
                    .completed
                    .referenced_fields()
                    .contains(&ConstraintField::VerifierState)
                    || fresh_verifier)
            {
                return Some(index);
            }
        }
        None
    }

    fn position(&self, step: &ProcedureStepAlignment) -> Option<ProcedurePhase> {
        let current = self.current()?;
        let previous = self.previous();
        if step.completed.evaluate(current, previous) != ConstraintTruth::False {
            return None;
        }
        if step.progress.evaluate(current, previous) == ConstraintTruth::True {
            Some(ProcedurePhase::InProgress)
        } else if step.entry.evaluate(current, previous) == ConstraintTruth::True {
            Some(ProcedurePhase::AtEntry)
        } else {
            None
        }
    }
}

fn verifier_origin(
    attempts: &std::collections::BTreeMap<&str, &evertrace_store::ObjectRow>,
    origins: &mut std::collections::BTreeMap<evertrace_domain::revision::RevisionId, Option<u64>>,
    attempt: &Attempt,
    seq: u64,
) -> Result<Option<u64>, SemanticServiceError> {
    let mut current = attempt.clone();
    let mut origin = seq;
    let mut visited = Vec::new();
    let mut result = None;
    for _ in 0..attempts.len() {
        if let Some(known) = origins.get(&current.revision_id) {
            result = *known;
            break;
        }
        visited.push(current.revision_id);
        let Some(parent) = current.predecessor_revision_id else {
            result = Some(origin);
            break;
        };
        let Some(row) = attempts
            .get(parent.to_string().as_str())
            .filter(|row| row.source_event_seq < origin)
        else {
            break;
        };
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(SemanticServiceError::InvalidInput)?,
        )
        .map_err(|_| SemanticServiceError::InvalidInput)?;
        let JournalPayload::AttemptRecorded(previous) = payload else {
            break;
        };
        if previous.attempt_id != attempt.attempt_id {
            break;
        }
        if previous.verification != attempt.verification {
            result = Some(origin);
            break;
        }
        current = *previous;
        origin = row.source_event_seq;
    }
    for revision in visited {
        origins.insert(revision, result);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use evertrace_domain::procedure::*;

    fn eq(value: &str) -> evertrace_domain::semantic::ConstraintExpr {
        evertrace_domain::semantic::ConstraintExpr::Eq {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text(value.into()),
        }
    }
    fn step(entry: &str, completed: &str) -> ProcedureStepAlignment {
        ProcedureStepAlignment {
            entry: eq(entry),
            progress: eq(entry),
            completed: eq(completed),
        }
    }
    #[test]
    fn inventory_coverage_distinguishes_duplicate_from_incremental_boundary() {
        use crate::procedure::{
            VerifiedProcedureCoverage, equivalent_procedure_contract, extends_procedure_boundaries,
        };
        use evertrace_domain::{
            inventory::{
                CapabilityCoverageMatch, CapabilityCoverageSummary, CapabilityEvidenceLevel,
            },
            semantic::{ProcedureProposalPayload, SemanticCandidate},
        };
        let original = draft();
        let mut candidate = original.clone();
        candidate.title = "different authored title".into();
        assert!(equivalent_procedure_contract(&original, &candidate));
        candidate
            .pitfalls
            .push("preserve the repository-specific rollback marker".into());
        assert!(!equivalent_procedure_contract(&original, &candidate));
        assert!(extends_procedure_boundaries(&original, &candidate));
        let id = evertrace_domain::ids::ProcedureId::new_v7();
        let revision = evertrace_domain::revision::RevisionId::new_v7();
        let mut proof = VerifiedProcedureCoverage {
            summary: CapabilityCoverageSummary::default(),
            frontier: 1,
            draft: candidate.clone(),
            source_refs: vec!["source".into()],
            incremental_target: Some((id, revision)),
        };
        let mut proposal = SemanticCandidate::ProcedureProposal {
            target_id: None,
            base_revision_id: None,
            payload: Box::new(ProcedureProposalPayload::Create {
                draft: candidate.clone(),
            }),
        };
        proof.apply_incremental_boundary(&mut proposal);
        assert!(matches!(proposal, SemanticCandidate::ProcedureProposal {
            target_id: Some(target), base_revision_id: Some(base), payload,
        } if target == id && base == revision && matches!(payload.as_ref(), ProcedureProposalPayload::Replace { draft } if draft == &candidate)));
        candidate.completion_expr = eq("unproven verifier");
        assert!(!extends_procedure_boundaries(&original, &candidate));
        for (level, suppressed) in [
            (CapabilityEvidenceLevel::Present, false),
            (CapabilityEvidenceLevel::Routed, false),
            (CapabilityEvidenceLevel::ActionAligned, false),
            (CapabilityEvidenceLevel::OutcomeSupported, true),
        ] {
            proof.summary.equivalent_assets = vec![CapabilityCoverageMatch {
                revision_ref: revision.to_string(),
                level,
            }];
            assert_eq!(proof.suppresses_duplicate_create(), suppressed);
        }
    }

    fn draft() -> ProcedureDraft {
        ProcedureDraft {
            scope: ProcedureScope::Repository {
                repository_id: evertrace_domain::ids::RepositoryId::new_v7(),
            },
            title: "bounded path".into(),
            summary: "typed conditions, not prose matching".into(),
            kind: ProcedureKind::Diagnostic,
            when: ProcedureWhen {
                goals: vec![],
                targets: vec![],
                signals: vec![],
                stage: "display only".into(),
                requires: vec![],
                excludes: vec![],
            },
            condition_ir_version: 1,
            applicability_expr: eq("one"),
            avoid_expr: eq("unsafe"),
            completion_expr: eq("done"),
            stage_alignment: Some(ProcedureStageAlignment {
                main: vec![step("one", "two"), step("two", "done")],
                branches: vec![ProcedureBranchAlignment {
                    at_main_step: 0,
                    steps: vec![step("repair1", "repair2"), step("repair2", "one")],
                }],
            }),
            actions: ProcedureActions {
                stages: vec!["first".into(), "second".into()],
                branches: vec![ProcedureBranch {
                    label: "repair".into(),
                    condition: eq("repair1"),
                    stages: vec!["repair first".into(), "repair second".into()],
                }],
                avoid: vec![],
            },
            done: ProcedureDone {
                success: vec!["success".into()],
                abort: vec!["stop".into()],
                verify: vec!["verify".into()],
            },
            pitfalls: vec![],
            evidence_refs: vec!["source".into()],
            support_revision_refs: vec![],
        }
    }
    fn trace(phases: &[&str]) -> StageTrace {
        StageTrace {
            truncated: false,
            frames: phases
                .iter()
                .enumerate()
                .map(|(index, value)| StageFrame {
                    source_refs: vec![format!("checkpoint:{index}")],
                    sequence: index as u64 + 1,
                    verifier_witness: None,
                    state: ConstraintState {
                        bindings: vec![ConstraintBinding {
                            field: ConstraintField::Phase,
                            value: ConstraintValue::Text((*value).into()),
                        }],
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn explicit_prefix_branches_rejoin_and_fail_closed() {
        let mut draft = draft();
        draft.validate().unwrap();
        for (phases, actions, phase) in [
            (
                vec!["one"],
                vec!["first", "second"],
                ProcedurePhase::InProgress,
            ),
            (
                vec!["one", "repair1"],
                vec!["repair first", "repair second"],
                ProcedurePhase::RecoverableDeviation,
            ),
            (
                vec!["one", "repair1", "repair2"],
                vec!["repair second"],
                ProcedurePhase::RecoverableDeviation,
            ),
            (
                vec!["one", "repair1", "repair2", "one"],
                vec!["first", "second"],
                ProcedurePhase::InProgress,
            ),
            (
                vec!["one", "repair1", "repair2", "one", "two"],
                vec!["second"],
                ProcedurePhase::InProgress,
            ),
            (
                vec!["one", "repair1", "repair2", "one", "two", "done"],
                vec![],
                ProcedurePhase::AlreadyCompleted,
            ),
            (
                vec!["one", "repair1", "repair2", "one", "repair1"],
                vec!["repair first", "repair second"],
                ProcedurePhase::RecoverableDeviation,
            ),
        ] {
            let (actual_phase, actual) = trace(&phases).align(&draft).unwrap();
            assert_eq!(actual_phase, phase);
            assert_eq!(actual.stages, actions);
        }
        let mut bounded = trace(&["one"]);
        bounded.truncated = true;
        assert!(bounded.align(&draft).is_none());
        assert!(
            trace(&["display only"])
                .align(&draft)
                .is_some_and(|(phase, _)| phase == ProcedurePhase::BeforeEntry)
        );
        assert!(
            trace(&["two"]).align(&draft).is_none(),
            "later state is not a witnessed completed prefix"
        );
        draft
            .actions
            .branches
            .push(draft.actions.branches[0].clone());
        let mapping = draft.stage_alignment.as_mut().unwrap();
        mapping.branches.push(mapping.branches[0].clone());
        assert!(trace(&["one", "repair1"]).align(&draft).is_none());
        let mut draft = self::draft();
        draft.stage_alignment.as_mut().unwrap().main[1].completed =
            evertrace_domain::semantic::ConstraintExpr::Eq {
                field: ConstraintField::VerifierState,
                value: ConstraintValue::Text("passed".into()),
            };
        let mut old_pass = trace(&["one", "two", "two"]);
        for frame in &mut old_pass.frames {
            frame.state.bindings.push(ConstraintBinding {
                field: ConstraintField::VerifierState,
                value: ConstraintValue::Text("passed".into()),
            });
            frame.verifier_witness = Some(0);
            frame.state.bindings.sort_by_key(|binding| binding.field);
        }
        assert!(
            old_pass.align(&draft).is_none(),
            "old passing cannot complete the later step"
        );
        let mut fresh = trace(&["one", "two", "two"]);
        fresh.frames[2].state.bindings.push(ConstraintBinding {
            field: ConstraintField::VerifierState,
            value: ConstraintValue::Text("passed".into()),
        });
        fresh.frames[2]
            .state
            .bindings
            .sort_by_key(|binding| binding.field);
        fresh.frames[2].verifier_witness = Some(3);
        assert_eq!(
            fresh.align(&draft).unwrap().0,
            ProcedurePhase::AlreadyCompleted,
            "entry need not have a False verifier observation"
        );
        fresh.frames[2].verifier_witness = Some(1);
        assert!(
            fresh.align(&draft).is_none(),
            "revealing an old passing verifier is not a new completion"
        );
        fresh.frames[2].verifier_witness = Some(3);
        draft.stage_alignment.as_mut().unwrap().main[1].completed =
            evertrace_domain::semantic::ConstraintExpr::Any {
                terms: vec![
                    eq("two"),
                    draft.stage_alignment.as_ref().unwrap().main[1]
                        .completed
                        .clone(),
                ],
            };
        assert!(
            fresh.align(&draft).is_none(),
            "an irrelevant fresh OR arm cannot renew an already true completion"
        );
    }

    #[test]
    fn materialization_distinguishes_closed_future_values_from_free_vocabulary() {
        use evertrace_domain::semantic::ConstraintExpr;
        let frozen = trace(&["one"]);
        let mut draft = draft();
        draft.actions.stages.truncate(1);
        draft.actions.branches.clear();
        let mapping = draft.stage_alignment.as_mut().unwrap();
        mapping.main.truncate(1);
        mapping.branches.clear();
        mapping.main[0].completed = ConstraintExpr::Eq {
            field: ConstraintField::VerifierState,
            value: ConstraintValue::Text("passed".into()),
        };
        assert!(
            frozen.supports(&draft),
            "future passed is a valid declaration, not an observed fact"
        );
        for (field, text) in [
            (ConstraintField::VerifierState, "passing"),
            (ConstraintField::PhaseKind, "checking"),
            (ConstraintField::ExperimentState, "passed"),
        ] {
            draft.stage_alignment.as_mut().unwrap().main[0].completed = ConstraintExpr::Eq {
                field,
                value: ConstraintValue::Text(text.into()),
            };
            assert!(!frozen.supports(&draft));
        }
        draft.stage_alignment.as_mut().unwrap().main[0].completed = eq("invented");
        draft.completion_expr = eq("invented");
        assert!(
            !frozen.supports(&draft),
            "a sibling expression is not a source for a new free label"
        );
        draft.stage_alignment.as_mut().unwrap().main[0].completed = ConstraintExpr::Transitioned {
            field: ConstraintField::Phase,
            from: ConstraintValue::Text("one".into()),
            to: ConstraintValue::Text("invented".into()),
        };
        assert!(!frozen.supports(&draft));
    }

    #[test]
    fn episode_successors_without_new_checkpoints_do_not_consume_frames() {
        use evertrace_domain::{
            ids::{TaskId, WorkstreamId},
            revision::RevisionId,
            work::*,
        };
        let stream = Workstream {
            workstream_id: WorkstreamId::new_v7(),
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            task_id: TaskId::new_v7(),
            repository_instance_id: None,
            worktree_instance_ids: vec![],
            active_worktree_instance_id: None,
            worktree_lineage_refs: vec![],
            parent_workstream_id: None,
            dependency_workstream_ids: vec![],
            status: WorkstreamStatus::Active,
            root_goal: "goal".into(),
            workstream_goal: "goal".into(),
            target_family: "test".into(),
            hypothesis_or_failure_family: "test".into(),
            acceptance_boundary: "done".into(),
            phase_contract: PhaseContract {
                local_goal: "goal".into(),
                phase_kind: PhaseKind::Implement,
                phase_label: "one".into(),
                primary_targets: vec![],
                entry_conditions: vec![],
                acceptance_boundary: "done".into(),
                expected_state_transition: "done".into(),
            },
            active_episode_id: None,
            execution_lane_ids: vec![],
            source_watermark: 1,
        };
        let mut episode = crate::work::episode::new_episode(&stream, None, 1).unwrap();
        let checkpoint =
            WorkCheckpoint::derive(&episode, &[], None, CheckpointReason::Manual).unwrap();
        let episode_row = |episode: &WorkEpisode, seq| evertrace_store::ObjectRow {
            row_id: episode.revision_id.to_string(),
            row_kind: evertrace_store::ObjectRowKind::Data,
            object_kind: Some("work_episode".into()),
            current_revision_id: Some(episode.revision_id.to_string()),
            payload_json: Some(
                serde_json::to_string(&JournalPayload::WorkEpisodeRecorded(Box::new(
                    episode.clone(),
                )))
                .unwrap(),
            ),
            source_event_seq: seq,
            ..evertrace_store::ObjectRow::checkpoint(0, 1)
        };
        let mut snapshot = ProjectionSnapshot {
            frontier: 300,
            rows: vec![
                episode_row(&episode, 1),
                evertrace_store::ObjectRow {
                    row_id: checkpoint.stable_key(),
                    row_kind: evertrace_store::ObjectRowKind::Data,
                    object_kind: Some("work_checkpoint".into()),
                    payload_json: Some(
                        serde_json::to_string(&JournalPayload::WorkCheckpointRecorded(Box::new(
                            checkpoint.clone(),
                        )))
                        .unwrap(),
                    ),
                    source_event_seq: 2,
                    ..evertrace_store::ObjectRow::checkpoint(0, 1)
                },
            ],
        };
        for seq in 3..=300 {
            let mut successor = episode.clone();
            successor.predecessor_revision_id = Some(episode.revision_id);
            successor.revision_id = RevisionId::new_v7();
            successor.revision_generation += 1;
            successor.checkpoint_refs = vec![checkpoint.stable_key()];
            episode.validate_successor(&successor).unwrap();
            snapshot.rows.push(episode_row(&successor, seq));
            episode = successor;
        }
        let trace = StageTrace::compile(&snapshot, &episode).unwrap();
        assert!(!trace.truncated);
        assert_eq!(trace.frames.len(), 1);
        assert_eq!(trace.align(&draft()).unwrap().0, ProcedurePhase::InProgress);
    }
}
