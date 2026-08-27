use std::collections::BTreeMap;

use evertrace_domain::{
    evidence::OperationKind,
    ids::{OperationBurstId, OperationId},
    revision::RevisionId,
    work::{OperationBurst, OperationBurstLifecycle, OperationBurstMember, OperationVerifierDelta},
};

use super::{ActivityToken, DetectorError};

const BURST_ALGORITHM_REVISION: u32 = 2;
const MAX_BURST_ITEMS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BurstFoldUpdate {
    current: OperationBurst,
    closed: Option<OperationBurst>,
    started_new: bool,
    meaningful_new: bool,
    no_delta: bool,
}

impl BurstFoldUpdate {
    pub(crate) fn current(&self) -> &OperationBurst {
        &self.current
    }
    pub(crate) fn closed(&self) -> Option<&OperationBurst> {
        self.closed.as_ref()
    }
    pub(crate) const fn started_new(&self) -> bool {
        self.started_new
    }
    pub(crate) const fn meaningful_new(&self) -> bool {
        self.meaningful_new
    }
    pub(crate) const fn no_delta(&self) -> bool {
        self.no_delta
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeenOperation {
    revision: u32,
    member: OperationBurstMember,
    operation_kind: OperationKind,
    state_delta: evertrace_domain::work::OperationStateDelta,
    verifier_delta: OperationVerifierDelta,
    phase_candidate: Option<evertrace_domain::work::PhaseKind>,
    has_objective_boundary: bool,
    error_signature: Option<String>,
    target_family: String,
    target_refs: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct OperationBurstFolder {
    current: Option<OperationBurst>,
    seen: BTreeMap<OperationId, SeenOperation>,
}

impl OperationBurstFolder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn restore(bursts: &[OperationBurst]) -> Result<Self, DetectorError> {
        let current = bursts
            .iter()
            .filter(|value| value.lifecycle == OperationBurstLifecycle::Open)
            .cloned()
            .collect::<Vec<_>>();
        if current.len() > 1 || bursts.len() > 64 {
            return Err(DetectorError::Ineligible);
        }
        let mut seen = BTreeMap::new();
        for burst in bursts {
            burst.validate().map_err(|_| DetectorError::Ineligible)?;
            for member in &burst.members {
                let value = seen_from_burst(burst, member);
                match seen.get(&member.operation_id) {
                    None => {
                        seen.insert(member.operation_id, value);
                    }
                    Some(previous) if previous.revision < member.operation_revision => {
                        seen.insert(member.operation_id, value);
                    }
                    _ => return Err(DetectorError::Ineligible),
                }
            }
        }
        Ok(Self {
            current: current.into_iter().next(),
            seen,
        })
    }

    pub(crate) fn push(&mut self, token: &ActivityToken) -> Result<BurstFoldUpdate, DetectorError> {
        if let Some(previous) = self.seen.get(&token.operation_id()) {
            if previous.revision > token.operation_revision() {
                return Err(DetectorError::WatermarkRegression);
            }
            if previous.revision == token.operation_revision() {
                if previous.member != member_from_token(token)
                    || previous.operation_kind != token.operation_kind()
                    || previous.state_delta != token.state_delta()
                    || previous.verifier_delta != token.verifier_transition()
                    || previous.phase_candidate != token.observed_phase_kind()
                    || previous.has_objective_boundary
                        != (token.boundary_evidence() != super::BoundaryEvidence::None)
                    || previous.error_signature.as_deref() != token.error_signature()
                    || previous.target_family != token.target_family()
                    || previous.target_refs != token.target_refs()
                {
                    return Err(DetectorError::Ineligible);
                }
                return Ok(BurstFoldUpdate {
                    current: self.current.clone().ok_or(DetectorError::Ineligible)?,
                    closed: None,
                    started_new: false,
                    meaningful_new: false,
                    no_delta: true,
                });
            }
        }
        if self
            .current
            .as_ref()
            .is_some_and(|current| can_extend(current, token))
        {
            let current = self.current.as_ref().expect("checked above");
            if current.members.len() < MAX_BURST_ITEMS {
                let mut next = current.clone();
                next.revision_id = RevisionId::new_v7();
                next.predecessor_revision_id = Some(current.revision_id);
                next.revision_generation = current
                    .revision_generation
                    .checked_add(1)
                    .ok_or(DetectorError::Ineligible)?;
                next.members.push(member_from_token(token));
                next.source_watermark = token.source_watermark();
                current
                    .validate_successor(&next)
                    .map_err(|_| DetectorError::Ineligible)?;
                self.current = Some(next.clone());
                self.seen.insert(
                    token.operation_id(),
                    seen_from_burst(&next, next.members.last().expect("member appended")),
                );
                return Ok(BurstFoldUpdate {
                    current: next,
                    closed: None,
                    started_new: false,
                    meaningful_new: false,
                    no_delta: false,
                });
            }
        }
        let closed = self.current.take().map(close_burst).transpose()?;
        let current = new_burst(token)?;
        let meaningful_new = current.is_meaningful_after(closed.as_ref());
        self.current = Some(current.clone());
        self.seen.insert(
            token.operation_id(),
            seen_from_burst(&current, current.members.last().expect("new burst member")),
        );
        Ok(BurstFoldUpdate {
            current,
            closed,
            started_new: true,
            meaningful_new,
            no_delta: false,
        })
    }
}

fn seen_from_burst(burst: &OperationBurst, member: &OperationBurstMember) -> SeenOperation {
    SeenOperation {
        revision: member.operation_revision,
        member: member.clone(),
        operation_kind: burst.operation_kind,
        state_delta: burst.state_delta,
        verifier_delta: burst.verifier_delta,
        phase_candidate: burst.phase_candidate,
        has_objective_boundary: burst.has_objective_boundary,
        error_signature: burst.error_signature.clone(),
        target_family: burst.target_family.clone(),
        target_refs: burst.target_refs.clone(),
    }
}

pub(crate) fn close_burst(current: OperationBurst) -> Result<OperationBurst, DetectorError> {
    let mut next = current.clone();
    next.revision_id = RevisionId::new_v7();
    next.predecessor_revision_id = Some(current.revision_id);
    next.revision_generation = current
        .revision_generation
        .checked_add(1)
        .ok_or(DetectorError::Ineligible)?;
    next.lifecycle = OperationBurstLifecycle::Closed;
    current
        .validate_successor(&next)
        .map_err(|_| DetectorError::Ineligible)?;
    Ok(next)
}

fn new_burst(token: &ActivityToken) -> Result<OperationBurst, DetectorError> {
    let value = OperationBurst {
        operation_burst_id: OperationBurstId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        revision_generation: 1,
        lifecycle: OperationBurstLifecycle::Open,
        algorithm_revision: BURST_ALGORITHM_REVISION,
        operation_kind: token.operation_kind(),
        state_delta: token.state_delta(),
        verifier_delta: token.verifier_transition(),
        phase_candidate: token.observed_phase_kind(),
        has_objective_boundary: token.boundary_evidence() != super::BoundaryEvidence::None,
        error_signature: token.error_signature().map(str::to_owned),
        target_family: token.target_family().to_owned(),
        target_refs: token.target_refs().to_vec(),
        members: vec![member_from_token(token)],
        execution_lane_id: token.execution_lane_id(),
        parent_lane_id: token.parent_lane_id(),
        subagent_id: token.subagent_id().map(str::to_owned),
        primary_binding: token.primary_binding().clone(),
        attempt_id: token.attempt_id(),
        experiment_run_id: token.experiment_run_id(),
        competing_group_id: token.competing_group_id(),
        worktree_lineage_refs: token.worktree_lineage_refs().to_vec(),
        strategy_contract_fingerprint: token.strategy_contract_fingerprint(),
        source_watermark: token.source_watermark(),
    };
    value.validate().map_err(|_| DetectorError::Ineligible)?;
    Ok(value)
}

fn member_from_token(token: &ActivityToken) -> OperationBurstMember {
    OperationBurstMember {
        sequence: token.sequence(),
        source_watermark: token.source_watermark(),
        operation_id: token.operation_id(),
        operation_revision: token.operation_revision(),
        host_occurrence_id: token.host_occurrence_id(),
        work_binding_revision_id: token.work_binding_revision_id(),
        attempt_revision_id: token.attempt_revision_id(),
        source_observation_refs: token.source_observation_refs().to_vec(),
        scope_effect_refs: token.scope_effect_refs().to_vec(),
        artifact_refs: token.artifact_refs().to_vec(),
        side_effects: token.side_effects().to_vec(),
        worktree_transition_refs: token.worktree_transition_refs().to_vec(),
        integration_event_refs: token.integration_event_refs().to_vec(),
    }
}

fn can_extend(current: &OperationBurst, token: &ActivityToken) -> bool {
    current.lifecycle == OperationBurstLifecycle::Open
        && current.operation_kind == token.operation_kind()
        && current.state_delta == token.state_delta()
        && current.verifier_delta == OperationVerifierDelta::None
        && !current.has_objective_boundary
        && current.phase_candidate == token.observed_phase_kind()
        && token.verifier_transition() == OperationVerifierDelta::None
        && token.boundary_evidence() == super::BoundaryEvidence::None
        && current.error_signature.as_deref() == token.error_signature()
        && current.target_family == token.target_family()
        && current.target_refs == token.target_refs()
        && current.execution_lane_id == token.execution_lane_id()
        && current.parent_lane_id == token.parent_lane_id()
        && current.primary_binding == *token.primary_binding()
        && current.attempt_id == token.attempt_id()
        && current.experiment_run_id == token.experiment_run_id()
        && current.competing_group_id == token.competing_group_id()
        && current.worktree_lineage_refs == token.worktree_lineage_refs()
        && current.strategy_contract_fingerprint == token.strategy_contract_fingerprint()
        && token.worktree_transition_refs().is_empty()
        && token.integration_event_refs().is_empty()
        && !current
            .members
            .iter()
            .any(|member| member.operation_id == token.operation_id())
}
