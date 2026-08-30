use std::collections::{BTreeMap, BTreeSet};

use evertrace_domain::{
    ids::{CoreMembershipId, ScenarioId},
    revision::RevisionId,
    semantic::{
        Atom, AtomAuthority, AtomKind, AtomLifecycleStatus, AtomScope, CoreMembership,
        CoreMembershipProposalPayload, CoreScopeIdentity, EpistemicStatus,
        GlobalSuccessorSupportContract, GlobalSupportState, GlobalSupportValidationEvent,
        L3CoreProjection, ProposalAcceptanceAuthority, ProposalEligibility, ProposalPayload,
        ProposalStatus, RevisionProposal, Scenario, UserAuthorizationMode,
    },
};

use crate::{JournalPayload, ObjectFamily, ObjectRow, ObjectRowClass, ObjectRowKind, StoreError};

pub(super) const CORE_PROJECTION_KIND: &str = "l3_core_projection";

#[derive(Clone, Default)]
pub(super) struct S23State {
    scenarios: BTreeMap<ScenarioId, (Scenario, u64)>,
    scenario_revisions: BTreeMap<RevisionId, (Scenario, u64)>,
    memberships: BTreeMap<CoreMembershipId, (CoreMembership, u64)>,
    membership_revisions: BTreeMap<RevisionId, (CoreMembership, u64)>,
    contracts: BTreeMap<RevisionId, (GlobalSuccessorSupportContract, u64)>,
    validations: BTreeMap<RevisionId, (GlobalSupportValidationEvent, u64)>,
    current_validations: BTreeMap<RevisionId, (GlobalSupportValidationEvent, u64)>,
}

impl S23State {
    pub(super) fn current_scenario(&self, revision_id: RevisionId) -> Option<&Scenario> {
        self.scenarios
            .values()
            .map(|(scenario, _)| scenario)
            .find(|scenario| scenario.revision_id == revision_id)
    }
    pub(super) fn atom_support_eligible(&self, revision_id: RevisionId) -> bool {
        self.atom_support_validations(revision_id)
            .into_iter()
            .all(|validation| validation.state == GlobalSupportState::Valid)
    }

    pub(super) fn global_wiki_support_watermark(&self, revision_id: RevisionId) -> Option<u64> {
        let memberships = self
            .memberships
            .values()
            .filter(|(membership, _)| {
                membership.active && membership.atom_revision_id == revision_id
            })
            .collect::<Vec<_>>();
        if memberships.is_empty() {
            return None;
        }
        let mut watermark = 0;
        for (membership, membership_seq) in memberships {
            let contract = self.contracts.get(&membership.support_contract_ref)?;
            let validation = self
                .current_validations
                .get(&membership.support_contract_ref)?;
            if validation.0.state != GlobalSupportState::Valid {
                return None;
            }
            watermark = watermark
                .max(*membership_seq)
                .max(contract.1)
                .max(validation.1);
        }
        Some(watermark)
    }

    pub(super) fn atom_support_state(&self, revision_id: RevisionId) -> Option<&'static str> {
        self.atom_support_validations(revision_id)
            .into_iter()
            .map(|validation| support_state(validation.state))
            .max_by_key(|state| support_state_rank(state))
    }

    pub(super) fn successor_support_states(&self) -> BTreeMap<String, &'static str> {
        let mut states: BTreeMap<String, &'static str> = BTreeMap::new();
        for (contract, _) in self.contracts.values() {
            let Some((validation, _)) = self
                .current_validations
                .get(&contract.support_contract_revision_id)
            else {
                continue;
            };
            let candidate = support_state(validation.state);
            states
                .entry(contract.successor_revision_or_membership_ref.clone())
                .and_modify(|current| {
                    if support_state_rank(candidate) > support_state_rank(current) {
                        *current = candidate;
                    }
                })
                .or_insert(candidate);
        }
        states
    }

    fn atom_support_validations(
        &self,
        revision_id: RevisionId,
    ) -> Vec<&GlobalSupportValidationEvent> {
        let mut contracts = self
            .memberships
            .values()
            .filter(|(membership, _)| {
                membership.active && membership.atom_revision_id == revision_id
            })
            .map(|(membership, _)| membership.support_contract_ref)
            .collect::<BTreeSet<_>>();
        contracts.extend(self.contracts.values().filter_map(|(contract, _)| {
            (contract.successor_revision_or_membership_ref == revision_id.to_string())
                .then_some(contract.support_contract_revision_id)
        }));
        contracts
            .into_iter()
            .filter_map(|contract| {
                self.current_validations
                    .get(&contract)
                    .map(|value| &value.0)
            })
            .collect()
    }
    pub(super) fn apply(&mut self, payload: JournalPayload, seq: u64) -> Result<bool, StoreError> {
        match payload {
            JournalPayload::ScenarioRecorded(value) => {
                let value = *value;
                if let Some((current, _)) = self.scenarios.get(&value.scenario_id) {
                    current
                        .validate_successor(&value)
                        .map_err(|_| StoreError::StoreCorrupt)?;
                } else if value.predecessor_revision_id.is_some() || value.revision_generation != 1
                {
                    return Err(StoreError::StoreCorrupt);
                }
                if self
                    .scenario_revisions
                    .insert(value.revision_id, (value.clone(), seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                self.scenarios.insert(value.scenario_id, (value, seq));
                Ok(true)
            }
            JournalPayload::CoreMembershipRecorded(value) => {
                let value = *value;
                if let Some((current, _)) = self.memberships.get(&value.core_membership_id) {
                    current
                        .validate_successor(&value)
                        .map_err(|_| StoreError::StoreCorrupt)?;
                } else if value.supersedes_membership_revision_id.is_some() {
                    return Err(StoreError::StoreCorrupt);
                }
                if self
                    .membership_revisions
                    .insert(value.membership_revision_id, (value.clone(), seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                self.memberships
                    .insert(value.core_membership_id, (value, seq));
                Ok(true)
            }
            JournalPayload::GlobalSupportContractRecorded(value) => {
                let value = *value;
                if self
                    .contracts
                    .insert(value.support_contract_revision_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                Ok(true)
            }
            JournalPayload::GlobalSupportValidationRecorded(value) => {
                let value = *value;
                let contract = self
                    .contracts
                    .get(&value.support_contract_ref)
                    .ok_or(StoreError::StoreCorrupt)?;
                validate_validation_against_contract(&contract.0, &value)?;
                if let Some((current, _)) =
                    self.current_validations.get(&value.support_contract_ref)
                {
                    validate_validation_successor(current, &value)?;
                } else if value.dependency_generation != 1 {
                    return Err(StoreError::StoreCorrupt);
                }
                if self
                    .validations
                    .insert(value.validation_revision_id, (value.clone(), seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                self.current_validations
                    .insert(value.support_contract_ref, (value, seq));
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub(super) fn validate(
        &self,
        atom_revisions: &BTreeMap<RevisionId, (Atom, u64)>,
        proposal_revisions: &BTreeMap<RevisionId, (RevisionProposal, u64)>,
        procedures: &super::procedure::ProcedureState,
    ) -> Result<(), StoreError> {
        for (membership, _) in self.memberships.values() {
            let atom = atom_revisions
                .get(&membership.atom_revision_id)
                .ok_or(StoreError::StoreCorrupt)?;
            if !core_atom_eligible(&atom.0, &membership.scope_identity)
                || !self
                    .contracts
                    .contains_key(&membership.support_contract_ref)
                || membership.authorization_revision_refs
                    != self.contracts[&membership.support_contract_ref]
                        .0
                        .authorization_revision_refs
            {
                return Err(StoreError::StoreCorrupt);
            }
            let proposal = proposal_revisions
                .get(&membership.created_by_acceptance_ref)
                .ok_or(StoreError::StoreCorrupt)?;
            if proposal.0.status != ProposalStatus::Accepted
                || !matches!(
                    proposal.0.payload,
                    ProposalPayload::CoreMembership(ref payload)
                        if matches!(payload.as_ref(), CoreMembershipProposalPayload::Create {
                            atom_revision_id,
                            scope_identity,
                        } if *atom_revision_id == membership.atom_revision_id
                            && scope_identity == &membership.scope_identity)
                )
                || !matches!(
                proposal.0.acceptance.as_ref().map(|value| &value.accepted_target),
                Some(evertrace_domain::semantic::AcceptedProposalTarget::CoreMembership {
                    core_membership_id,
                    membership_revision_id,
                }) if *core_membership_id == membership.core_membership_id
                    && *membership_revision_id == membership.membership_revision_id
                )
            {
                return Err(StoreError::StoreCorrupt);
            }
            if proposal.0.eligibility == ProposalEligibility::AutoEligibleFull {
                let authorization = atom
                    .0
                    .user_authorization_provenance
                    .as_ref()
                    .ok_or(StoreError::StoreCorrupt)?;
                let acceptance = proposal
                    .0
                    .acceptance
                    .as_ref()
                    .ok_or(StoreError::StoreCorrupt)?;
                if atom.0.authority != AtomAuthority::UserExplicit
                    || atom.0.scope != AtomScope::Global
                    || authorization.mode != UserAuthorizationMode::TuiAcceptance
                    || !matches!(authorization.authorized_scope_ceiling, AtomScope::Global)
                    || Some(&acceptance.acceptance_event_ref)
                        != authorization.acceptance_event_ref.as_ref()
                    || !matches!(
                        acceptance.authority_basis,
                        ProposalAcceptanceAuthority::TuiAcceptance {
                            user_source_observation_ref,
                            authorized_scope_ceiling: AtomScope::Global,
                        } if user_source_observation_ref
                            == authorization.user_source_observation_ref
                    )
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
        for (contract, _) in self.contracts.values() {
            let target_exists = atom_revisions
                .keys()
                .any(|value| value.to_string() == contract.successor_revision_or_membership_ref)
                || self.membership_revisions.keys().any(|value| {
                    value.to_string() == contract.successor_revision_or_membership_ref
                })
                || procedures.contains_revision_ref(&contract.successor_revision_or_membership_ref);
            if !target_exists
                || !self
                    .current_validations
                    .contains_key(&contract.support_contract_revision_id)
                || !proposal_revisions.contains_key(&contract.promotion_proposal_revision_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Ok(())
    }

    pub(super) fn restore(
        &mut self,
        payload: JournalPayload,
        seq: u64,
    ) -> Result<bool, StoreError> {
        match payload {
            JournalPayload::ScenarioRecorded(value) => {
                let value = *value;
                if self
                    .scenario_revisions
                    .insert(value.revision_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                Ok(true)
            }
            JournalPayload::CoreMembershipRecorded(value) => {
                let value = *value;
                if self
                    .membership_revisions
                    .insert(value.membership_revision_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                Ok(true)
            }
            JournalPayload::GlobalSupportContractRecorded(value) => {
                let value = *value;
                if self
                    .contracts
                    .insert(value.support_contract_revision_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                Ok(true)
            }
            JournalPayload::GlobalSupportValidationRecorded(value) => {
                let value = *value;
                if self
                    .validations
                    .insert(value.validation_revision_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub(super) fn rebuild(&mut self) -> Result<(), StoreError> {
        self.scenarios.clear();
        let mut scenarios = self
            .scenario_revisions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        scenarios.sort_by_key(|(value, _)| (value.scenario_id, value.revision_generation));
        for (value, seq) in scenarios {
            if let Some((current, _)) = self.scenarios.get(&value.scenario_id) {
                current
                    .validate_successor(&value)
                    .map_err(|_| StoreError::StoreCorrupt)?;
            } else if value.revision_generation != 1 || value.predecessor_revision_id.is_some() {
                return Err(StoreError::StoreCorrupt);
            }
            self.scenarios.insert(value.scenario_id, (value, seq));
        }
        self.memberships.clear();
        let ids = self
            .membership_revisions
            .values()
            .map(|(value, _)| value.core_membership_id)
            .collect::<BTreeSet<_>>();
        for id in ids {
            let members = self
                .membership_revisions
                .values()
                .filter(|(value, _)| value.core_membership_id == id)
                .cloned()
                .collect::<Vec<_>>();
            let roots = members
                .iter()
                .filter(|(value, _)| value.supersedes_membership_revision_id.is_none())
                .collect::<Vec<_>>();
            let [root] = roots.as_slice() else {
                return Err(StoreError::StoreCorrupt);
            };
            let mut current = (*root).clone();
            for _ in 1..members.len() {
                let next = members
                    .iter()
                    .filter(|(value, _)| {
                        value.supersedes_membership_revision_id
                            == Some(current.0.membership_revision_id)
                    })
                    .collect::<Vec<_>>();
                let [next] = next.as_slice() else {
                    return Err(StoreError::StoreCorrupt);
                };
                current
                    .0
                    .validate_successor(&next.0)
                    .map_err(|_| StoreError::StoreCorrupt)?;
                current = (*next).clone();
            }
            self.memberships.insert(id, current);
        }
        self.current_validations.clear();
        let mut validations = self.validations.values().cloned().collect::<Vec<_>>();
        validations.sort_by_key(|(value, seq)| {
            (
                value.support_contract_ref,
                value.dependency_generation,
                *seq,
            )
        });
        for (value, seq) in validations {
            let contract = self
                .contracts
                .get(&value.support_contract_ref)
                .ok_or(StoreError::StoreCorrupt)?;
            validate_validation_against_contract(&contract.0, &value)?;
            if let Some((current, _)) = self.current_validations.get(&value.support_contract_ref) {
                validate_validation_successor(current, &value)?;
            } else if value.dependency_generation != 1 {
                return Err(StoreError::StoreCorrupt);
            }
            self.current_validations
                .insert(value.support_contract_ref, (value, seq));
        }
        Ok(())
    }

    pub(super) fn rows(
        &self,
        atoms: &BTreeMap<RevisionId, (Atom, u64)>,
        generation: u64,
    ) -> Result<Vec<ObjectRow>, StoreError> {
        // Cross-family proposal validation is performed by the owning reducer before rows.
        let mut rows = Vec::new();
        for (revision, (value, seq)) in &self.scenario_revisions {
            rows.push(object_row(
                format!("object:work:scenario:{revision}"),
                ObjectFamily::Work,
                "scenario",
                value.scenario_id.to_string(),
                revision.to_string(),
                scenario_lifecycle(value),
                Some(value.scope.task_id.to_string()),
                value.scope.repository_instance_id.map(|id| id.to_string()),
                value.scope.worktree_instance_id.map(|id| id.to_string()),
                &JournalPayload::ScenarioRecorded(Box::new(value.clone())),
                *seq,
                generation,
            )?);
        }
        for (revision, (value, seq)) in &self.membership_revisions {
            let current = self
                .memberships
                .get(&value.core_membership_id)
                .map(|v| &v.0);
            rows.push(object_row(
                format!("object:atom:core_membership:{revision}"),
                ObjectFamily::Atom,
                "core_membership",
                value.core_membership_id.to_string(),
                revision.to_string(),
                if current == Some(value) && value.active {
                    "active"
                } else {
                    "inactive"
                },
                None,
                scope_repository(&value.scope_identity),
                None,
                &JournalPayload::CoreMembershipRecorded(Box::new(value.clone())),
                *seq,
                generation,
            )?);
        }
        for (revision, (value, seq)) in &self.contracts {
            rows.push(object_row(
                format!("object:atom:global_support_contract:{revision}"),
                ObjectFamily::Atom,
                "global_support_contract",
                revision.to_string(),
                revision.to_string(),
                "immutable",
                None,
                None,
                None,
                &JournalPayload::GlobalSupportContractRecorded(Box::new(value.clone())),
                *seq,
                generation,
            )?);
        }
        for (revision, (value, seq)) in &self.validations {
            rows.push(object_row(
                format!("object:atom:global_support_validation:{revision}"),
                ObjectFamily::Atom,
                "global_support_validation",
                value.support_contract_ref.to_string(),
                revision.to_string(),
                support_state(value.state),
                None,
                None,
                None,
                &JournalPayload::GlobalSupportValidationRecorded(Box::new(value.clone())),
                *seq,
                generation,
            )?);
        }
        rows.extend(self.core_rows(atoms, generation)?);
        Ok(rows)
    }

    fn core_rows(
        &self,
        atoms: &BTreeMap<RevisionId, (Atom, u64)>,
        generation: u64,
    ) -> Result<Vec<ObjectRow>, StoreError> {
        let conflicted = conflicted_revisions(atoms);
        let mut scopes = BTreeMap::<CoreScopeIdentity, Vec<(&CoreMembership, u64)>>::new();
        for (membership, seq) in self.memberships.values() {
            let validation = self
                .current_validations
                .get(&membership.support_contract_ref);
            let valid = validation.is_some_and(|value| value.0.state == GlobalSupportState::Valid);
            if membership.active
                && valid
                && self.atom_support_eligible(membership.atom_revision_id)
                && !conflicted.contains(&membership.atom_revision_id)
            {
                let watermark = (*seq).max(validation.map_or(0, |value| value.1)).max(
                    atoms
                        .get(&membership.atom_revision_id)
                        .map_or(0, |value| value.1),
                );
                scopes
                    .entry(membership.scope_identity.clone())
                    .or_default()
                    .push((membership, watermark));
            }
        }
        scopes
            .into_iter()
            .map(|(scope, mut members)| {
                members.sort_by_key(|(value, _)| value.membership_revision_id);
                let projection = L3CoreProjection {
                    core_projection_id: scope
                        .projection_id()
                        .map_err(|_| StoreError::StoreCorrupt)?,
                    scope_identity: scope,
                    active_membership_revision_ids: members
                        .iter()
                        .map(|(v, _)| v.membership_revision_id)
                        .collect(),
                    atom_revision_ids: members.iter().map(|(v, _)| v.atom_revision_id).collect(),
                    source_watermark: members.iter().map(|(_, seq)| *seq).max().unwrap_or(0),
                };
                projection
                    .validate()
                    .map_err(|_| StoreError::StoreCorrupt)?;
                let payload_json =
                    serde_json::to_string(&projection).map_err(|_| StoreError::Serialization)?;
                Ok(ObjectRow {
                    row_id: format!("projection:core:{}", projection.core_projection_id),
                    row_kind: ObjectRowKind::Data,
                    row_class: Some(ObjectRowClass::Projection),
                    object_family: None,
                    object_kind: Some(CORE_PROJECTION_KIND.into()),
                    object_id: None,
                    current_revision_id: None,
                    lifecycle: Some("active".into()),
                    epistemic: None,
                    authority: None,
                    publication_state: None,
                    support_state: Some("valid".into()),
                    project_id: None,
                    repository_id: scope_repository(&projection.scope_identity),
                    worktree_id: None,
                    task_id: None,
                    workstream_id: None,
                    session_id: None,
                    payload_json: Some(payload_json),
                    source_event_seq: projection.source_watermark,
                    projection_generation: generation,
                })
            })
            .collect()
    }

    pub(super) fn restore_projection(row: &ObjectRow) -> Result<bool, StoreError> {
        if row.object_kind.as_deref() != Some(CORE_PROJECTION_KIND) {
            return Ok(false);
        }
        let value: L3CoreProjection = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        value.validate().map_err(|_| StoreError::StoreCorrupt)?;
        if row.row_kind != ObjectRowKind::Data
            || row.row_class != Some(ObjectRowClass::Projection)
            || row.object_family.is_some()
            || row.row_id != format!("projection:core:{}", value.core_projection_id)
            || row.source_event_seq != value.source_watermark
            || row.repository_id != scope_repository(&value.scope_identity)
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(true)
    }
}

fn validate_validation_against_contract(
    contract: &GlobalSuccessorSupportContract,
    validation: &GlobalSupportValidationEvent,
) -> Result<(), StoreError> {
    contract.validate().map_err(|_| StoreError::StoreCorrupt)?;
    validation
        .validate()
        .map_err(|_| StoreError::StoreCorrupt)?;
    if validation.support_contract_ref != contract.support_contract_revision_id
        || validation.successor_ref != contract.successor_revision_or_membership_ref
    {
        return Err(StoreError::StoreCorrupt);
    }
    let mut partition = validation.surviving_support_refs.clone();
    partition.extend(validation.invalid_or_missing_refs.iter().copied());
    partition.sort();
    let support_sufficient = validation.surviving_support_refs.len()
        >= usize::from(
            contract
                .support_threshold_snapshot
                .minimum_surviving_support,
        );
    match validation.state {
        GlobalSupportState::Valid if !support_sufficient => {
            return Err(StoreError::StoreCorrupt);
        }
        GlobalSupportState::Insufficient if support_sufficient => {
            return Err(StoreError::StoreCorrupt);
        }
        GlobalSupportState::Invalidated
            if !contract.support_threshold_snapshot.require_authorization =>
        {
            return Err(StoreError::StoreCorrupt);
        }
        GlobalSupportState::RevalidationPending
            if partition
                .iter()
                .any(|value| contract.support_revision_refs.binary_search(value).is_err()) =>
        {
            return Err(StoreError::StoreCorrupt);
        }
        GlobalSupportState::Valid
        | GlobalSupportState::Insufficient
        | GlobalSupportState::Invalidated
            if partition != contract.support_revision_refs =>
        {
            return Err(StoreError::StoreCorrupt);
        }
        _ => {}
    }
    Ok(())
}

fn validate_validation_successor(
    current: &GlobalSupportValidationEvent,
    next: &GlobalSupportValidationEvent,
) -> Result<(), StoreError> {
    let same_generation_completion = next.dependency_generation == current.dependency_generation
        && current.state == GlobalSupportState::RevalidationPending
        && next.state != GlobalSupportState::RevalidationPending;
    let next_generation_pending = next.dependency_generation
        == current
            .dependency_generation
            .checked_add(1)
            .ok_or(StoreError::StoreCorrupt)?
        && next.state == GlobalSupportState::RevalidationPending;
    if current.support_contract_ref != next.support_contract_ref
        || current.successor_ref != next.successor_ref
        || !(same_generation_completion || next_generation_pending)
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn core_atom_eligible(atom: &Atom, scope: &CoreScopeIdentity) -> bool {
    atom.kind == AtomKind::Constraint
        && atom.epistemic_status == EpistemicStatus::NotApplicable
        && atom.lifecycle_status == AtomLifecycleStatus::Active
        && match (&atom.authority, &atom.scope, scope) {
            (AtomAuthority::UserExplicit, AtomScope::Global, CoreScopeIdentity::Global) => true,
            (
                AtomAuthority::UserExplicit | AtomAuthority::ProjectPolicy,
                AtomScope::Repository {
                    repository_instance_id,
                },
                CoreScopeIdentity::Repository(scope_repository),
            ) => repository_instance_id == scope_repository,
            _ => false,
        }
}

fn conflicted_revisions(atoms: &BTreeMap<RevisionId, (Atom, u64)>) -> BTreeSet<RevisionId> {
    let mut values = BTreeSet::new();
    for (revision, (atom, _)) in atoms {
        for contradicted in &atom.contradicts_revision_refs {
            if atoms.contains_key(contradicted) {
                values.insert(*revision);
                values.insert(*contradicted);
            }
        }
    }
    values
}

#[allow(clippy::too_many_arguments)]
fn object_row(
    row_id: String,
    family: ObjectFamily,
    kind: &str,
    object_id: String,
    revision_id: String,
    lifecycle: &str,
    task_id: Option<String>,
    repository_id: Option<String>,
    worktree_id: Option<String>,
    payload: &JournalPayload,
    seq: u64,
    generation: u64,
) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id,
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Object),
        object_family: Some(family),
        object_kind: Some(kind.into()),
        object_id: Some(object_id),
        current_revision_id: Some(revision_id),
        lifecycle: Some(lifecycle.into()),
        epistemic: None,
        authority: None,
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id,
        worktree_id,
        task_id,
        workstream_id: None,
        session_id: None,
        payload_json: Some(payload.canonical_json()?),
        source_event_seq: seq,
        projection_generation: generation,
    })
}

fn scenario_lifecycle(value: &Scenario) -> &'static str {
    match value.status {
        evertrace_domain::semantic::ScenarioStatus::Active => "active",
        evertrace_domain::semantic::ScenarioStatus::Closed => "closed",
        evertrace_domain::semantic::ScenarioStatus::Superseded => "superseded",
    }
}

fn support_state(value: GlobalSupportState) -> &'static str {
    match value {
        GlobalSupportState::Valid => "valid",
        GlobalSupportState::RevalidationPending => "revalidation_pending",
        GlobalSupportState::Insufficient => "insufficient",
        GlobalSupportState::Invalidated => "invalidated",
    }
}

fn support_state_rank(value: &str) -> u8 {
    match value {
        "valid" => 0,
        "revalidation_pending" => 1,
        "insufficient" => 2,
        "invalidated" => 3,
        _ => 4,
    }
}

fn scope_repository(value: &CoreScopeIdentity) -> Option<String> {
    match value {
        CoreScopeIdentity::Global => None,
        CoreScopeIdentity::Repository(id) => Some(id.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use evertrace_domain::semantic::SupportThresholdSnapshot;

    use super::*;

    fn support_contract(
        contract_id: RevisionId,
        successor_ref: &str,
    ) -> GlobalSuccessorSupportContract {
        GlobalSuccessorSupportContract {
            support_contract_revision_id: contract_id,
            successor_revision_or_membership_ref: successor_ref.into(),
            support_revision_refs: vec![RevisionId::new_v7()],
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
        }
    }

    #[test]
    fn reducer_rejects_unknown_or_omitted_terminal_support_partitions() {
        let support = RevisionId::new_v7();
        let contract_id = RevisionId::new_v7();
        let successor_ref = RevisionId::new_v7().to_string();
        let contract = GlobalSuccessorSupportContract {
            support_contract_revision_id: contract_id,
            successor_revision_or_membership_ref: successor_ref.clone(),
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
        let mut state = S23State::default();
        state
            .apply(
                JournalPayload::GlobalSupportContractRecorded(Box::new(contract)),
                1,
            )
            .unwrap();
        let validation = |surviving_support_refs, invalid_or_missing_refs, state| {
            JournalPayload::GlobalSupportValidationRecorded(Box::new(
                GlobalSupportValidationEvent {
                    validation_revision_id: RevisionId::new_v7(),
                    support_contract_ref: contract_id,
                    successor_ref: successor_ref.clone(),
                    dependency_generation: 1,
                    state,
                    provenance_degraded: false,
                    surviving_support_refs,
                    invalid_or_missing_refs,
                    trigger_refs: Vec::new(),
                    validator_revision: 1,
                    created_at_us: 1,
                },
            ))
        };
        assert!(matches!(
            state.apply(
                validation(
                    vec![RevisionId::new_v7()],
                    Vec::new(),
                    GlobalSupportState::Valid
                ),
                2,
            ),
            Err(StoreError::StoreCorrupt)
        ));
        assert!(matches!(
            state.apply(
                validation(Vec::new(), Vec::new(), GlobalSupportState::Insufficient),
                2,
            ),
            Err(StoreError::StoreCorrupt)
        ));
        let mut below_threshold =
            match validation(Vec::new(), vec![support], GlobalSupportState::Valid) {
                JournalPayload::GlobalSupportValidationRecorded(value) => value,
                _ => unreachable!(),
            };
        below_threshold.provenance_degraded = true;
        assert!(matches!(
            state.apply(
                JournalPayload::GlobalSupportValidationRecorded(below_threshold),
                2,
            ),
            Err(StoreError::StoreCorrupt)
        ));
    }

    #[test]
    fn rebuild_rejects_invalid_support_validation_history() {
        let support = RevisionId::new_v7();
        let contract_id = RevisionId::new_v7();
        let successor_ref = RevisionId::new_v7().to_string();
        let contract = GlobalSuccessorSupportContract {
            support_contract_revision_id: contract_id,
            successor_revision_or_membership_ref: successor_ref.clone(),
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
        let validation = |successor_ref, surviving_support_refs, invalid_or_missing_refs, state| {
            GlobalSupportValidationEvent {
                validation_revision_id: RevisionId::new_v7(),
                support_contract_ref: contract_id,
                successor_ref,
                dependency_generation: 1,
                state,
                provenance_degraded: false,
                surviving_support_refs,
                invalid_or_missing_refs,
                trigger_refs: Vec::new(),
                validator_revision: 1,
                created_at_us: 1,
            }
        };
        let assert_rebuild_rejects =
            |contract: GlobalSuccessorSupportContract, validation: GlobalSupportValidationEvent| {
                let mut restored = S23State::default();
                assert!(
                    restored
                        .restore(
                            JournalPayload::GlobalSupportContractRecorded(Box::new(contract)),
                            1,
                        )
                        .unwrap()
                );
                assert!(
                    restored
                        .restore(
                            JournalPayload::GlobalSupportValidationRecorded(Box::new(validation)),
                            2,
                        )
                        .unwrap()
                );
                assert!(matches!(restored.rebuild(), Err(StoreError::StoreCorrupt)));
            };

        let mut unknown_partition = vec![support, RevisionId::new_v7()];
        unknown_partition.sort();
        assert_rebuild_rejects(
            contract.clone(),
            validation(
                successor_ref.clone(),
                unknown_partition,
                Vec::new(),
                GlobalSupportState::Valid,
            ),
        );
        assert_rebuild_rejects(
            contract.clone(),
            validation(
                successor_ref.clone(),
                Vec::new(),
                Vec::new(),
                GlobalSupportState::Insufficient,
            ),
        );
        assert_rebuild_rejects(
            contract.clone(),
            validation(
                RevisionId::new_v7().to_string(),
                vec![support],
                Vec::new(),
                GlobalSupportState::Valid,
            ),
        );
        let mut optional_authorization_contract = contract;
        optional_authorization_contract
            .authorization_revision_refs
            .clear();
        optional_authorization_contract
            .support_threshold_snapshot
            .require_authorization = false;
        assert_rebuild_rejects(
            optional_authorization_contract,
            validation(
                successor_ref,
                vec![support],
                Vec::new(),
                GlobalSupportState::Invalidated,
            ),
        );
    }

    #[test]
    fn successor_support_states_builds_one_worst_state_lookup() {
        let successor_ref = RevisionId::new_v7().to_string();
        let valid_contract_id = RevisionId::new_v7();
        let invalid_contract_id = RevisionId::new_v7();
        let mut state = S23State::default();
        state.contracts.insert(
            valid_contract_id,
            (support_contract(valid_contract_id, &successor_ref), 1),
        );
        state.contracts.insert(
            invalid_contract_id,
            (support_contract(invalid_contract_id, &successor_ref), 2),
        );
        let validation = |contract_id, support_state| GlobalSupportValidationEvent {
            validation_revision_id: RevisionId::new_v7(),
            support_contract_ref: contract_id,
            successor_ref: successor_ref.clone(),
            dependency_generation: 1,
            state: support_state,
            provenance_degraded: false,
            surviving_support_refs: Vec::new(),
            invalid_or_missing_refs: Vec::new(),
            trigger_refs: Vec::new(),
            validator_revision: 1,
            created_at_us: 1,
        };
        state.current_validations.insert(
            valid_contract_id,
            (validation(valid_contract_id, GlobalSupportState::Valid), 3),
        );
        state.current_validations.insert(
            invalid_contract_id,
            (
                validation(invalid_contract_id, GlobalSupportState::Invalidated),
                4,
            ),
        );

        let lookup = state.successor_support_states();
        assert_eq!(lookup.len(), 1);
        assert_eq!(lookup.get(&successor_ref), Some(&"invalidated"));
    }
}
