use evertrace_domain::{
    evidence::{CorrelationStrength, EffectRole, NormalizationState, OperationKind},
    ids::{
        AttemptId, CompetingAttemptGroupId, ExecutionLaneId, ExperimentRunId, HostOccurrenceId,
        IntegrationEventId, OperationId, ScopeEffectId, SourceObservationId, TaskId,
        WorkArtifactId, WorkBindingRevisionId, WorkEpisodeId, WorkstreamId, WorktreeTransitionId,
    },
    work::{
        AssignmentStatus, CaptureReceipt, OperationStateDelta, OperationVerifierDelta, PhaseKind,
        PrimaryWorkBinding,
    },
};
use evertrace_store::SegmentationCurrentView;
use serde::{Deserialize, Serialize};

use super::DetectorError;

const MAX_TEXT: usize = 512;

pub type StateDeltaKind = OperationStateDelta;
pub type VerifierTransition = OperationVerifierDelta;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryEvidence {
    None,
    MaterialGoal,
    PhaseTransition,
    TargetFamily,
    AcceptanceSatisfied,
    AcceptanceAbandoned,
    AcceptanceReplaced,
    ExplicitPhaseComplete,
    ExplicitPhaseAbandon,
    ExplicitSupersede,
    ObjectiveOutcomeClosure,
    RecoverPhaseExit,
}

impl BoundaryEvidence {
    pub(crate) const fn objective(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentationFacts {
    pub sequence: u64,
    pub source_watermark: u64,
    pub target_family: String,
    pub state_delta: StateDeltaKind,
    pub error_signature: Option<String>,
    pub verifier_transition: VerifierTransition,
    pub observed_phase_kind: Option<PhaseKind>,
    pub boundary_evidence: BoundaryEvidence,
    pub evidence_refs: Vec<SourceObservationId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActivityToken {
    sequence: u64,
    source_watermark: u64,
    operation_id: OperationId,
    operation_revision: u32,
    host_occurrence_id: HostOccurrenceId,
    work_binding_revision_id: WorkBindingRevisionId,
    primary_binding: PrimaryWorkBinding,
    task_id: TaskId,
    workstream_id: WorkstreamId,
    episode_id: WorkEpisodeId,
    attempt_id: Option<AttemptId>,
    attempt_revision_id: Option<evertrace_domain::revision::RevisionId>,
    experiment_run_id: Option<ExperimentRunId>,
    competing_group_id: Option<CompetingAttemptGroupId>,
    execution_lane_id: ExecutionLaneId,
    parent_lane_id: Option<ExecutionLaneId>,
    subagent_id: Option<String>,
    operation_kind: OperationKind,
    target_refs: Vec<String>,
    scope_effect_refs: Vec<ScopeEffectId>,
    worktree_lineage_refs: Vec<String>,
    artifact_refs: Vec<WorkArtifactId>,
    side_effects: Vec<EffectRole>,
    source_observation_refs: Vec<SourceObservationId>,
    strategy_contract_fingerprint: Option<[u8; 32]>,
    worktree_transition_refs: Vec<WorktreeTransitionId>,
    integration_event_refs: Vec<IntegrationEventId>,
    target_family: String,
    state_delta: StateDeltaKind,
    error_signature: Option<String>,
    verifier_transition: VerifierTransition,
    observed_phase_kind: Option<PhaseKind>,
    boundary_evidence: BoundaryEvidence,
    boundary_evidence_refs: Vec<SourceObservationId>,
    session_id: String,
    capture_receipt: CaptureReceipt,
}

impl ActivityToken {
    pub(crate) fn compile_checked(
        view: &SegmentationCurrentView,
        operation_id: OperationId,
        episode_id: WorkEpisodeId,
        facts: SegmentationFacts,
    ) -> Result<Self, DetectorError> {
        let operation = view
            .operation(operation_id)
            .ok_or(DetectorError::Ineligible)?;
        let occurrence = view
            .occurrence(operation.host_occurrence_id)
            .ok_or(DetectorError::Ineligible)?;
        let binding = view
            .binding(operation_id)
            .ok_or(DetectorError::Ineligible)?;
        let episode = view.episode(episode_id).ok_or(DetectorError::Ineligible)?;
        let workstream = view
            .workstream(episode.workstream_id)
            .ok_or(DetectorError::Ineligible)?;
        let lane_id = operation
            .execution_lane_id
            .ok_or(DetectorError::Ineligible)?;
        let lane = view.lane(lane_id).ok_or(DetectorError::Ineligible)?;
        let receipt = view
            .receipt(lane.active_capture_receipt_revision_id)
            .ok_or(DetectorError::Ineligible)?;
        let effects = operation
            .scope_effect_ids
            .iter()
            .map(|id| view.scope_effect(*id).ok_or(DetectorError::Ineligible))
            .collect::<Result<Vec<_>, _>>()?;
        let attempt = binding
            .primary_binding
            .attempt_id
            .map(|id| view.attempt(id).ok_or(DetectorError::Ineligible))
            .transpose()?;
        let competing_group_id = binding.primary_binding.competing_group_id;
        let experiment_run_id = binding.primary_binding.experiment_run_id;
        let group = competing_group_id
            .map(|id| view.group(id).ok_or(DetectorError::Ineligible))
            .transpose()?;
        let mut admissible = operation
            .input_source_observation_refs
            .iter()
            .chain(&operation.result_source_observation_refs)
            .copied()
            .collect::<Vec<_>>();
        admissible.extend(
            effects
                .iter()
                .flat_map(|value| value.evidence_refs.iter().copied()),
        );
        sort_unique(&mut admissible);
        let mut evidence_refs = facts.evidence_refs;
        sort_unique(&mut evidence_refs);
        let claims_semantics = facts.boundary_evidence != BoundaryEvidence::None
            || facts.verifier_transition != VerifierTransition::None
            || facts.observed_phase_kind.is_some();
        if occurrence.correlation_strength != CorrelationStrength::Exact
            || occurrence.normalization_state == NormalizationState::NormalizationConflicted
            || occurrence.possible_duplicate_group_id.is_some()
            || operation.execution_lane_id != Some(lane.execution_lane_id)
            || !lane.operation_ids.contains(&operation_id)
            || binding.operation_id != operation_id
            || binding.assignment_status != AssignmentStatus::Resolved
            || binding.primary_binding.task_id != Some(episode.task_id)
            || binding.primary_binding.workstream_id != Some(episode.workstream_id)
            || binding.primary_binding.episode_id != Some(episode_id)
            || workstream.active_episode_id != Some(episode_id)
            || lane.active_capture_receipt_revision_id != receipt.capture_receipt_revision_id
            || receipt.execution_lane_id != lane_id
            || receipt.import_watermark > facts.source_watermark
            || facts.sequence == 0
            || facts.source_watermark == 0
            || !valid_text(&facts.target_family)
            || facts
                .error_signature
                .as_deref()
                .is_some_and(|value| !valid_text(value))
            || (claims_semantics && evidence_refs.is_empty())
            || evidence_refs
                .iter()
                .any(|reference| admissible.binary_search(reference).is_err())
            || effects
                .iter()
                .any(|effect| effect.operation_id != operation_id)
            || attempt.is_some_and(|value| {
                value.task_id != episode.task_id
                    || value.workstream_id != episode.workstream_id
                    || value.episode_id != Some(episode_id)
                    || !episode.attempt_ids.contains(&value.attempt_id)
                    || !value.execution_lane_ids.contains(&lane_id)
                    || competing_group_id.is_some_and(|id| !value.competing_group_ids.contains(&id))
                    || experiment_run_id.is_some_and(|id| !value.experiment_run_ids.contains(&id))
                    || (!value.competing_group_ids.is_empty() && competing_group_id.is_none())
                    || (!value.experiment_run_ids.is_empty() && experiment_run_id.is_none())
            })
            || group.is_some_and(|value| {
                attempt
                    .is_none_or(|attempt| !value.member_attempt_ids.contains(&attempt.attempt_id))
            })
            || effects.iter().any(|effect| {
                effect
                    .experiment_run_ids
                    .iter()
                    .any(|id| Some(*id) != experiment_run_id)
            })
        {
            return Err(DetectorError::Ineligible);
        }
        let mut target_refs = episode.phase_contract.primary_targets.clone();
        if let Some(attempt) = attempt {
            target_refs.extend(attempt.strategy_contract.target_refs.iter().cloned());
        }
        if let Some(group) = group {
            target_refs.extend(group.target_refs.iter().cloned());
        }
        sort_unique(&mut target_refs);
        let mut source_observation_refs = occurrence.source_observation_refs.clone();
        source_observation_refs.extend(admissible);
        sort_unique(&mut source_observation_refs);
        let mut artifact_refs = operation.artifact_refs.clone();
        artifact_refs.extend(
            effects
                .iter()
                .flat_map(|value| value.artifact_refs.iter().copied()),
        );
        sort_unique(&mut artifact_refs);
        let mut side_effects = effects
            .iter()
            .map(|value| value.effect_role)
            .collect::<Vec<_>>();
        sort_unique(&mut side_effects);
        Ok(Self {
            sequence: facts.sequence,
            source_watermark: facts.source_watermark,
            operation_id,
            operation_revision: operation.operation_revision,
            host_occurrence_id: occurrence.host_occurrence_id,
            work_binding_revision_id: binding.work_binding_revision_id,
            primary_binding: binding.primary_binding.clone(),
            task_id: episode.task_id,
            workstream_id: episode.workstream_id,
            episode_id,
            attempt_id: attempt.map(|value| value.attempt_id),
            attempt_revision_id: attempt.map(|value| value.revision_id),
            experiment_run_id,
            competing_group_id,
            execution_lane_id: lane_id,
            parent_lane_id: lane.parent_lane_id,
            subagent_id: lane.parent_lane_id.map(|_| lane.agent_id.clone()),
            operation_kind: operation.operation_kind,
            target_refs,
            scope_effect_refs: operation.scope_effect_ids.clone(),
            worktree_lineage_refs: workstream.worktree_lineage_refs.clone(),
            artifact_refs,
            side_effects,
            source_observation_refs,
            strategy_contract_fingerprint: attempt.map(|value| value.strategy_contract_fingerprint),
            worktree_transition_refs: attempt
                .map_or_else(Vec::new, |value| value.worktree_transition_refs.clone()),
            integration_event_refs: attempt
                .map_or_else(Vec::new, |value| value.integration_event_refs.clone()),
            target_family: facts.target_family,
            state_delta: facts.state_delta,
            error_signature: facts.error_signature,
            verifier_transition: facts.verifier_transition,
            observed_phase_kind: facts.observed_phase_kind,
            boundary_evidence: facts.boundary_evidence,
            boundary_evidence_refs: evidence_refs,
            session_id: lane.host_session_id.clone(),
            capture_receipt: receipt.clone(),
        })
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn source_watermark(&self) -> u64 {
        self.source_watermark
    }
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    pub const fn operation_revision(&self) -> u32 {
        self.operation_revision
    }
    pub const fn host_occurrence_id(&self) -> HostOccurrenceId {
        self.host_occurrence_id
    }
    pub const fn work_binding_revision_id(&self) -> WorkBindingRevisionId {
        self.work_binding_revision_id
    }
    pub fn primary_binding(&self) -> &PrimaryWorkBinding {
        &self.primary_binding
    }
    pub const fn task_id(&self) -> TaskId {
        self.task_id
    }
    pub const fn workstream_id(&self) -> WorkstreamId {
        self.workstream_id
    }
    pub const fn episode_id(&self) -> WorkEpisodeId {
        self.episode_id
    }
    pub const fn attempt_id(&self) -> Option<AttemptId> {
        self.attempt_id
    }
    pub(crate) const fn attempt_revision_id(
        &self,
    ) -> Option<evertrace_domain::revision::RevisionId> {
        self.attempt_revision_id
    }
    pub const fn experiment_run_id(&self) -> Option<ExperimentRunId> {
        self.experiment_run_id
    }
    pub const fn competing_group_id(&self) -> Option<CompetingAttemptGroupId> {
        self.competing_group_id
    }
    pub const fn execution_lane_id(&self) -> ExecutionLaneId {
        self.execution_lane_id
    }
    pub const fn parent_lane_id(&self) -> Option<ExecutionLaneId> {
        self.parent_lane_id
    }
    pub fn subagent_id(&self) -> Option<&str> {
        self.subagent_id.as_deref()
    }
    pub const fn operation_kind(&self) -> OperationKind {
        self.operation_kind
    }
    pub fn target_refs(&self) -> &[String] {
        &self.target_refs
    }
    pub fn scope_effect_refs(&self) -> &[ScopeEffectId] {
        &self.scope_effect_refs
    }
    pub fn worktree_lineage_refs(&self) -> &[String] {
        &self.worktree_lineage_refs
    }
    pub fn artifact_refs(&self) -> &[WorkArtifactId] {
        &self.artifact_refs
    }
    pub fn side_effects(&self) -> &[EffectRole] {
        &self.side_effects
    }
    pub fn source_observation_refs(&self) -> &[SourceObservationId] {
        &self.source_observation_refs
    }
    pub fn strategy_contract_fingerprint(&self) -> Option<[u8; 32]> {
        self.strategy_contract_fingerprint
    }
    pub fn worktree_transition_refs(&self) -> &[WorktreeTransitionId] {
        &self.worktree_transition_refs
    }
    pub fn integration_event_refs(&self) -> &[IntegrationEventId] {
        &self.integration_event_refs
    }
    pub const fn state_delta(&self) -> StateDeltaKind {
        self.state_delta
    }
    pub fn error_signature(&self) -> Option<&str> {
        self.error_signature.as_deref()
    }
    pub(crate) fn target_family(&self) -> &str {
        &self.target_family
    }
    pub const fn verifier_transition(&self) -> VerifierTransition {
        self.verifier_transition
    }
    pub const fn observed_phase_kind(&self) -> Option<PhaseKind> {
        self.observed_phase_kind
    }
    pub const fn boundary_evidence(&self) -> BoundaryEvidence {
        self.boundary_evidence
    }
    pub(crate) fn boundary_evidence_refs(&self) -> &[SourceObservationId] {
        &self.boundary_evidence_refs
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn capture_receipt(&self) -> &CaptureReceipt {
        &self.capture_receipt
    }
}

fn valid_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT
}

fn sort_unique<T: Ord>(values: &mut Vec<T>) {
    values.sort();
    values.dedup();
}
