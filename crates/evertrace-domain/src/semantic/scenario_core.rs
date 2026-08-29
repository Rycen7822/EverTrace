use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalValue, sha256},
    ids::{
        AtomId, AttemptId, CompetingAttemptGroupId, CoreMembershipId, CoreProjectionId,
        ExperimentRunId, RepositoryId, ScenarioId, TaskId, WorkArtifactId, WorkEpisodeId,
        WorkstreamId, WorktreeId, WorktreeSnapshotId,
    },
    revision::RevisionId,
    work::PhaseKind,
};

use super::{SemanticError, valid_identifier};

const MAX_REFS: usize = 256;
const MAX_TEXT: usize = 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioScope {
    pub task_id: TaskId,
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_id: Option<WorktreeId>,
}

impl ScenarioScope {
    pub fn validate(&self) -> Result<(), SemanticError> {
        if self.worktree_instance_id.is_some() && self.repository_instance_id.is_none() {
            return Err(SemanticError::InvalidScenario);
        }
        Ok(())
    }

    pub fn scenario_id(&self) -> Result<ScenarioId, SemanticError> {
        self.validate()?;
        let value = CanonicalValue::Map(vec![
            (
                "task_id".into(),
                CanonicalValue::String(self.task_id.to_string()),
            ),
            (
                "repository_instance_id".into(),
                optional_string(self.repository_instance_id.map(|value| value.to_string())),
            ),
            (
                "worktree_instance_id".into(),
                optional_string(self.worktree_instance_id.map(|value| value.to_string())),
            ),
        ]);
        sha256("evertrace.scenario.scope", 1, &value)
            .map(ScenarioId::from_digest)
            .map_err(|_| SemanticError::InvalidScenario)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStatus {
    Active,
    Closed,
    Superseded,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveScenarioLineage {
    pub active_workstream_id: Option<WorkstreamId>,
    pub active_episode_id: Option<WorkEpisodeId>,
    pub active_attempt_id: Option<AttemptId>,
    pub unresolved_competing_group_ids: Vec<CompetingAttemptGroupId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioWorkstream {
    pub workstream_id: WorkstreamId,
    pub phase_kind: PhaseKind,
    pub open_episode_id: Option<WorkEpisodeId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub scenario_id: ScenarioId,
    pub revision_id: RevisionId,
    pub predecessor_revision_id: Option<RevisionId>,
    pub revision_generation: u64,
    pub scope: ScenarioScope,
    pub active_worktree_snapshot_id: Option<WorktreeSnapshotId>,
    pub worktree_lineage_refs: Vec<String>,
    pub status: ScenarioStatus,
    pub goal: String,
    pub current_state: Vec<String>,
    pub active_lineage: ActiveScenarioLineage,
    pub active_workstreams: Vec<ScenarioWorkstream>,
    pub running_experiment_refs: Vec<ExperimentRunId>,
    pub constraints: Vec<RevisionId>,
    pub decisions: Vec<RevisionId>,
    pub open_loops: Vec<String>,
    pub active_failures: Vec<String>,
    pub completed_outcomes: Vec<String>,
    pub relevant_artifacts: Vec<WorkArtifactId>,
    pub support_atom_ids: Vec<AtomId>,
    pub source_watermark: u64,
}

impl Scenario {
    pub fn validate(&self) -> Result<(), SemanticError> {
        self.scope.validate()?;
        if self.scenario_id != self.scope.scenario_id()?
            || self.revision_generation == 0
            || (self.revision_generation == 1) != self.predecessor_revision_id.is_none()
            || !valid_text(&self.goal)
            || !valid_refs(&self.worktree_lineage_refs)
            || !valid_refs(&self.current_state)
            || !valid_refs(&self.open_loops)
            || !valid_refs(&self.active_failures)
            || !valid_refs(&self.completed_outcomes)
            || !bounded_sorted(&self.active_lineage.unresolved_competing_group_ids)
            || self.active_workstreams.len() > MAX_REFS
            || !self
                .active_workstreams
                .windows(2)
                .all(|pair| pair[0].workstream_id < pair[1].workstream_id)
            || !bounded_sorted(&self.running_experiment_refs)
            || !bounded_sorted(&self.constraints)
            || !bounded_sorted(&self.decisions)
            || !bounded_sorted(&self.relevant_artifacts)
            || !bounded_sorted(&self.support_atom_ids)
            || self.active_lineage.active_episode_id.is_some()
                && self.active_lineage.active_workstream_id.is_none()
            || self.active_lineage.active_attempt_id.is_some()
                && self.active_lineage.active_episode_id.is_none()
        {
            return Err(SemanticError::InvalidScenario);
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), SemanticError> {
        self.validate()?;
        next.validate()?;
        if next.scenario_id != self.scenario_id
            || next.scope != self.scope
            || next.predecessor_revision_id != Some(self.revision_id)
            || next.revision_generation != self.revision_generation + 1
            || self.status != ScenarioStatus::Active && next.status == ScenarioStatus::Active
            || self == next
        {
            return Err(SemanticError::InvalidScenario);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum CoreScopeIdentity {
    Global,
    Repository(RepositoryId),
}

impl CoreScopeIdentity {
    pub fn projection_id(&self) -> Result<CoreProjectionId, SemanticError> {
        let value = match self {
            Self::Global => CanonicalValue::String("global".into()),
            Self::Repository(id) => CanonicalValue::String(id.to_string()),
        };
        sha256("evertrace.core.scope", 1, &value)
            .map(CoreProjectionId::from_digest)
            .map_err(|_| SemanticError::InvalidCoreMembership)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoreMembership {
    pub core_membership_id: CoreMembershipId,
    pub membership_revision_id: RevisionId,
    pub atom_revision_id: RevisionId,
    pub scope_identity: CoreScopeIdentity,
    pub support_contract_ref: RevisionId,
    pub authorization_revision_refs: Vec<RevisionId>,
    pub supersedes_membership_revision_id: Option<RevisionId>,
    pub created_by_acceptance_ref: RevisionId,
    pub active: bool,
}

impl CoreMembership {
    pub fn validate(&self) -> Result<(), SemanticError> {
        if self.authorization_revision_refs.is_empty()
            || !bounded_sorted(&self.authorization_revision_refs)
            || self.supersedes_membership_revision_id == Some(self.membership_revision_id)
        {
            return Err(SemanticError::InvalidCoreMembership);
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), SemanticError> {
        self.validate()?;
        next.validate()?;
        if next.core_membership_id != self.core_membership_id
            || next.supersedes_membership_revision_id != Some(self.membership_revision_id)
            || !self.active
            || self == next
        {
            return Err(SemanticError::InvalidCoreMembership);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportThresholdSnapshot {
    pub minimum_surviving_support: u16,
    pub require_authorization: bool,
}

impl SupportThresholdSnapshot {
    pub fn validate(&self) -> Result<(), SemanticError> {
        if self.minimum_surviving_support == 0 {
            return Err(SemanticError::InvalidGlobalSupport);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalSuccessorSupportContract {
    pub support_contract_revision_id: RevisionId,
    pub successor_revision_or_membership_ref: String,
    pub support_revision_refs: Vec<RevisionId>,
    pub authorization_revision_refs: Vec<RevisionId>,
    pub evidence_cohort_hash: [u8; 32],
    pub support_threshold_snapshot: SupportThresholdSnapshot,
    pub promotion_proposal_revision_id: RevisionId,
    pub promotion_validator_revision: u32,
    pub applicability_contract_hash: [u8; 32],
    pub created_at_us: i64,
}

impl GlobalSuccessorSupportContract {
    pub fn validate(&self) -> Result<(), SemanticError> {
        if !valid_identifier(&self.successor_revision_or_membership_ref)
            || self.support_revision_refs.is_empty()
            || !bounded_sorted(&self.support_revision_refs)
            || !bounded_sorted(&self.authorization_revision_refs)
            || self.support_threshold_snapshot.require_authorization
                && self.authorization_revision_refs.is_empty()
            || usize::from(self.support_threshold_snapshot.minimum_surviving_support)
                > self.support_revision_refs.len()
            || self.promotion_validator_revision == 0
            || self.created_at_us < 0
        {
            return Err(SemanticError::InvalidGlobalSupport);
        }
        self.support_threshold_snapshot.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GlobalSupportState {
    Valid,
    RevalidationPending,
    Insufficient,
    Invalidated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalSupportValidationEvent {
    pub validation_revision_id: RevisionId,
    pub support_contract_ref: RevisionId,
    pub successor_ref: String,
    pub dependency_generation: u64,
    pub state: GlobalSupportState,
    pub provenance_degraded: bool,
    pub surviving_support_refs: Vec<RevisionId>,
    pub invalid_or_missing_refs: Vec<RevisionId>,
    pub trigger_refs: Vec<String>,
    pub validator_revision: u32,
    pub created_at_us: i64,
}

impl GlobalSupportValidationEvent {
    pub fn validate(&self) -> Result<(), SemanticError> {
        if !valid_identifier(&self.successor_ref)
            || self.dependency_generation == 0
            || self.validator_revision == 0
            || self.created_at_us < 0
            || !bounded_sorted(&self.surviving_support_refs)
            || !bounded_sorted(&self.invalid_or_missing_refs)
            || !valid_refs(&self.trigger_refs)
            || self
                .surviving_support_refs
                .iter()
                .any(|value| self.invalid_or_missing_refs.contains(value))
            || self.state == GlobalSupportState::Valid
                && self.provenance_degraded != !self.invalid_or_missing_refs.is_empty()
        {
            return Err(SemanticError::InvalidGlobalSupport);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct L3CoreProjection {
    pub core_projection_id: CoreProjectionId,
    pub scope_identity: CoreScopeIdentity,
    pub active_membership_revision_ids: Vec<RevisionId>,
    pub atom_revision_ids: Vec<RevisionId>,
    pub source_watermark: u64,
}

impl L3CoreProjection {
    pub fn validate(&self) -> Result<(), SemanticError> {
        if self.active_membership_revision_ids.len() != self.atom_revision_ids.len()
            || !bounded_sorted(&self.active_membership_revision_ids)
            || !bounded_sorted(&self.atom_revision_ids)
        {
            return Err(SemanticError::InvalidCoreMembership);
        }
        Ok(())
    }
}

fn optional_string(value: Option<String>) -> CanonicalValue {
    value.map_or(CanonicalValue::Null, CanonicalValue::String)
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
}

fn valid_refs(values: &[String]) -> bool {
    values.len() <= MAX_REFS
        && values.iter().all(|value| valid_identifier(value))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn bounded_sorted<T: Ord>(values: &[T]) -> bool {
    values.len() <= MAX_REFS && values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_identity_is_scope_derived_and_successors_never_reopen() {
        let task_id = TaskId::new_v7();
        let repository = RepositoryId::new_v7();
        let global = ScenarioScope {
            task_id,
            repository_instance_id: None,
            worktree_instance_id: None,
        };
        let shard = ScenarioScope {
            task_id,
            repository_instance_id: Some(repository),
            worktree_instance_id: None,
        };
        assert_ne!(global.scenario_id().unwrap(), shard.scenario_id().unwrap());
        assert!(
            ScenarioScope {
                task_id,
                repository_instance_id: None,
                worktree_instance_id: Some(WorktreeId::new_v7()),
            }
            .validate()
            .is_err()
        );

        let first = minimal_scenario(global, None, ScenarioStatus::Active, 1);
        let closed = minimal_scenario(first.scope.clone(), Some(&first), ScenarioStatus::Closed, 2);
        first.validate_successor(&closed).unwrap();
        let reopened = minimal_scenario(
            closed.scope.clone(),
            Some(&closed),
            ScenarioStatus::Active,
            3,
        );
        assert!(closed.validate_successor(&reopened).is_err());
    }

    #[test]
    fn membership_and_support_successors_are_closed_and_bounded() {
        let membership_id = CoreMembershipId::new_v7();
        let contract = RevisionId::new_v7();
        let first = CoreMembership {
            core_membership_id: membership_id,
            membership_revision_id: RevisionId::new_v7(),
            atom_revision_id: RevisionId::new_v7(),
            scope_identity: CoreScopeIdentity::Global,
            support_contract_ref: contract,
            authorization_revision_refs: vec![RevisionId::new_v7()],
            supersedes_membership_revision_id: None,
            created_by_acceptance_ref: RevisionId::new_v7(),
            active: true,
        };
        first.validate().unwrap();
        let mut inactive = first.clone();
        inactive.membership_revision_id = RevisionId::new_v7();
        inactive.supersedes_membership_revision_id = Some(first.membership_revision_id);
        inactive.active = false;
        first.validate_successor(&inactive).unwrap();
        let mut revived = inactive.clone();
        revived.membership_revision_id = RevisionId::new_v7();
        revived.supersedes_membership_revision_id = Some(inactive.membership_revision_id);
        revived.active = true;
        assert!(inactive.validate_successor(&revived).is_err());

        let pending = GlobalSupportValidationEvent {
            validation_revision_id: RevisionId::new_v7(),
            support_contract_ref: contract,
            successor_ref: first.membership_revision_id.to_string(),
            dependency_generation: 2,
            state: GlobalSupportState::RevalidationPending,
            provenance_degraded: false,
            surviving_support_refs: Vec::new(),
            invalid_or_missing_refs: Vec::new(),
            trigger_refs: vec!["dependency:changed".into()],
            validator_revision: 1,
            created_at_us: 2,
        };
        pending.validate().unwrap();

        let support = RevisionId::new_v7();
        let mut support_contract = GlobalSuccessorSupportContract {
            support_contract_revision_id: contract,
            successor_revision_or_membership_ref: first.membership_revision_id.to_string(),
            support_revision_refs: vec![support],
            authorization_revision_refs: vec![RevisionId::new_v7()],
            evidence_cohort_hash: [1; 32],
            support_threshold_snapshot: SupportThresholdSnapshot {
                minimum_surviving_support: 1,
                require_authorization: true,
            },
            promotion_proposal_revision_id: RevisionId::new_v7(),
            promotion_validator_revision: 1,
            applicability_contract_hash: [2; 32],
            created_at_us: 1,
        };
        support_contract.validate().unwrap();
        support_contract.authorization_revision_refs.clear();
        assert!(support_contract.validate().is_err());
        support_contract.authorization_revision_refs = vec![RevisionId::new_v7()];
        support_contract
            .support_threshold_snapshot
            .minimum_surviving_support = 2;
        assert!(support_contract.validate().is_err());

        let missing_support = RevisionId::new_v7();
        let valid_degraded = GlobalSupportValidationEvent {
            validation_revision_id: RevisionId::new_v7(),
            support_contract_ref: contract,
            successor_ref: first.membership_revision_id.to_string(),
            dependency_generation: 2,
            state: GlobalSupportState::Valid,
            provenance_degraded: true,
            surviving_support_refs: vec![support],
            invalid_or_missing_refs: vec![missing_support],
            trigger_refs: vec!["dependency:changed".into()],
            validator_revision: 1,
            created_at_us: 3,
        };
        valid_degraded.validate().unwrap();
        let mut false_provenance = valid_degraded.clone();
        false_provenance.provenance_degraded = false;
        assert!(false_provenance.validate().is_err());
        let mut overlap = valid_degraded;
        overlap.invalid_or_missing_refs = vec![support];
        assert!(overlap.validate().is_err());
    }

    fn minimal_scenario(
        scope: ScenarioScope,
        previous: Option<&Scenario>,
        status: ScenarioStatus,
        watermark: u64,
    ) -> Scenario {
        Scenario {
            scenario_id: scope.scenario_id().unwrap(),
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: previous.map(|value| value.revision_id),
            revision_generation: previous.map_or(1, |value| value.revision_generation + 1),
            scope,
            active_worktree_snapshot_id: None,
            worktree_lineage_refs: Vec::new(),
            status,
            goal: "goal".into(),
            current_state: Vec::new(),
            active_lineage: ActiveScenarioLineage {
                active_workstream_id: None,
                active_episode_id: None,
                active_attempt_id: None,
                unresolved_competing_group_ids: Vec::new(),
            },
            active_workstreams: Vec::new(),
            running_experiment_refs: Vec::new(),
            constraints: Vec::new(),
            decisions: Vec::new(),
            open_loops: Vec::new(),
            active_failures: Vec::new(),
            completed_outcomes: Vec::new(),
            relevant_artifacts: Vec::new(),
            support_atom_ids: Vec::new(),
            source_watermark: watermark,
        }
    }
}
