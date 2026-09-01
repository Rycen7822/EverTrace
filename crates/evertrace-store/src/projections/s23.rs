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

use crate::{
    DirtyTargetKind, JobStatus, JournalPayload, ObjectFamily, ObjectRow, ObjectRowClass,
    ObjectRowKind, StoreError,
};

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
    pub(super) fn forget(
        &mut self,
        revision_ids: &BTreeSet<RevisionId>,
        membership_ids: &BTreeSet<CoreMembershipId>,
    ) {
        let removed_contracts = self
            .membership_revisions
            .values()
            .filter_map(|(membership, _)| {
                (membership_ids.contains(&membership.core_membership_id)
                    || revision_ids.contains(&membership.membership_revision_id)
                    || revision_ids.contains(&membership.atom_revision_id))
                .then_some(membership.support_contract_ref)
            })
            .chain(self.contracts.iter().filter_map(|(id, (contract, _))| {
                contract
                    .successor_revision_or_membership_ref
                    .parse::<RevisionId>()
                    .is_ok_and(|revision| revision_ids.contains(&revision))
                    .then_some(*id)
            }))
            .collect::<BTreeSet<_>>();
        self.memberships.retain(|id, (membership, _)| {
            !membership_ids.contains(id)
                && !revision_ids.contains(&membership.membership_revision_id)
                && !revision_ids.contains(&membership.atom_revision_id)
        });
        self.membership_revisions
            .retain(|revision, (membership, _)| {
                !revision_ids.contains(revision)
                    && !membership_ids.contains(&membership.core_membership_id)
                    && !revision_ids.contains(&membership.atom_revision_id)
            });
        self.contracts
            .retain(|id, _| !removed_contracts.contains(id));
        self.validations.retain(|_, (validation, _)| {
            !removed_contracts.contains(&validation.support_contract_ref)
        });
        self.current_validations
            .retain(|id, _| !removed_contracts.contains(id));
    }

    pub(super) fn deletion_support_impacts(
        &self,
        target: evertrace_domain::purge::ObjectDeletionTarget,
        revision_ids: &BTreeSet<RevisionId>,
    ) -> Result<Vec<crate::purge::ObjectDeletionSupportImpact>, StoreError> {
        let membership_ids = match target {
            evertrace_domain::purge::ObjectDeletionTarget::CoreMembership {
                core_membership_id,
            } => BTreeSet::from([core_membership_id]),
            evertrace_domain::purge::ObjectDeletionTarget::Atom { .. }
            | evertrace_domain::purge::ObjectDeletionTarget::Procedure { .. } => BTreeSet::new(),
        };
        self.scope_purge_support_impacts(revision_ids, &membership_ids)
    }

    pub(super) fn repository_membership_revision_ids(
        &self,
        repository_id: evertrace_domain::ids::RepositoryId,
    ) -> (BTreeSet<CoreMembershipId>, BTreeSet<RevisionId>) {
        let memberships = self
            .membership_revisions
            .values()
            .filter_map(|(membership, _)| {
                matches!(
                    membership.scope_identity,
                    evertrace_domain::semantic::CoreScopeIdentity::Repository(id)
                        if id == repository_id
                )
                .then_some((
                    membership.core_membership_id,
                    membership.membership_revision_id,
                ))
            })
            .collect::<Vec<_>>();
        (
            memberships.iter().map(|(id, _)| *id).collect(),
            memberships
                .into_iter()
                .map(|(_, revision)| revision)
                .collect(),
        )
    }

    pub(super) fn scope_purge_support_impacts(
        &self,
        revision_ids: &BTreeSet<RevisionId>,
        membership_ids: &BTreeSet<CoreMembershipId>,
    ) -> Result<Vec<crate::purge::ObjectDeletionSupportImpact>, StoreError> {
        let owned = self.deletion_owned_contracts(revision_ids, membership_ids);
        let mut impacts = Vec::new();
        for (contract_id, (contract, _)) in &self.contracts {
            if owned.contains(contract_id) {
                continue;
            }
            let trigger_refs = contract
                .support_revision_refs
                .iter()
                .chain(&contract.authorization_revision_refs)
                .filter(|revision| revision_ids.contains(revision))
                .map(ToString::to_string)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            if trigger_refs.is_empty() {
                continue;
            }
            let current_validation = self
                .current_validations
                .get(contract_id)
                .map(|(validation, _)| validation.clone())
                .ok_or(StoreError::StoreCorrupt)?;
            impacts.push(crate::purge::ObjectDeletionSupportImpact {
                current_validation,
                trigger_refs,
            });
        }
        Ok(impacts)
    }

    pub(super) fn deletion_owned_contracts(
        &self,
        revision_ids: &BTreeSet<RevisionId>,
        membership_ids: &BTreeSet<CoreMembershipId>,
    ) -> BTreeSet<RevisionId> {
        self.membership_revisions
            .values()
            .filter_map(|(membership, _)| {
                (membership_ids.contains(&membership.core_membership_id)
                    || revision_ids.contains(&membership.membership_revision_id)
                    || revision_ids.contains(&membership.atom_revision_id))
                .then_some(membership.support_contract_ref)
            })
            .chain(self.contracts.iter().filter_map(|(id, (contract, _))| {
                contract
                    .successor_revision_or_membership_ref
                    .parse::<RevisionId>()
                    .is_ok_and(|revision| revision_ids.contains(&revision))
                    .then_some(*id)
            }))
            .collect()
    }

    pub(super) fn validate_deletion_support_fanout(
        &self,
        impacts: &[crate::purge::ObjectDeletionSupportImpact],
        occurred_at_us: i64,
        effective_config_hash: [u8; 32],
        payloads: &[&JournalPayload],
        error: StoreError,
    ) -> Result<(), StoreError> {
        let mut validations_by_contract = BTreeMap::new();
        let mut dirty_by_target = BTreeMap::new();
        let mut outbox_by_id = BTreeMap::new();
        let mut jobs_by_idempotency = BTreeMap::new();
        for payload in payloads {
            match payload {
                JournalPayload::GlobalSupportValidationRecorded(value) => {
                    if validations_by_contract
                        .insert(value.support_contract_ref, value.as_ref())
                        .is_some()
                    {
                        return Err(error);
                    }
                }
                JournalPayload::DirtyTarget(value)
                    if value.target_kind == DirtyTargetKind::RuntimeJob =>
                {
                    if dirty_by_target
                        .insert(value.target_id.as_str(), value)
                        .is_some()
                    {
                        return Err(error);
                    }
                }
                JournalPayload::OutboxEnqueued(value)
                    if value.dirty.target_kind == DirtyTargetKind::RuntimeJob =>
                {
                    if outbox_by_id
                        .insert(value.outbox_id.as_str(), value)
                        .is_some()
                    {
                        return Err(error);
                    }
                }
                JournalPayload::JobState(value)
                    if value.kind == "support_closure"
                        && jobs_by_idempotency
                            .insert(value.idempotency_key.as_str(), value)
                            .is_some() =>
                {
                    return Err(error);
                }
                _ => {}
            }
        }
        if validations_by_contract.len() != impacts.len()
            || dirty_by_target.len() != impacts.len()
            || outbox_by_id.len() != impacts.len()
            || jobs_by_idempotency.len() != impacts.len()
        {
            return Err(error);
        }
        for impact in impacts {
            let current = &impact.current_validation;
            let pending = *validations_by_contract
                .get(&current.support_contract_ref)
                .ok_or(error)?;
            validate_validation_successor(current, pending).map_err(|_| error)?;
            let generation = current.dependency_generation.checked_add(1).ok_or(error)?;
            if pending.state != GlobalSupportState::RevalidationPending
                || pending.dependency_generation != generation
                || pending.provenance_degraded != current.provenance_degraded
                || pending.surviving_support_refs != current.surviving_support_refs
                || !pending.invalid_or_missing_refs.is_empty()
                || pending.trigger_refs != impact.trigger_refs
                || pending.validator_revision != 1
                || pending.created_at_us != occurred_at_us
            {
                return Err(error);
            }
            let contract_ref = current.support_contract_ref.to_string();
            let dirty = *dirty_by_target.get(contract_ref.as_str()).ok_or(error)?;
            if dirty.source_watermark != generation {
                return Err(error);
            }
            let idempotency_key = format!("support:{}:{generation}", current.support_contract_ref);
            let outbox = *outbox_by_id.get(idempotency_key.as_str()).ok_or(error)?;
            let job = *jobs_by_idempotency
                .get(idempotency_key.as_str())
                .ok_or(error)?;
            if outbox.dirty != *dirty
                || job.target_revision != current.successor_ref
                || job.target_watermark != generation
                || job.target_generation != generation
                || job.kind != "support_closure"
                || job.algorithm_revision != dirty.algorithm_revision
                || job.model_id.is_some()
                || job.priority != 0
                || job.state != JobStatus::Queued
                || job.attempt != 1
                || job.backoff_until_us.is_some()
                || job.config_hash != effective_config_hash
                || job.budget.max_items != 1
                || job.budget.max_bytes.is_some()
                || job.budget.max_input_tokens.is_some()
                || job.budget.max_output_tokens.is_some()
                || job.budget.max_calls.is_some()
                || job.budget.max_wall_time_ms != 250
                || job.terminal.is_some()
                || job.lease_until_us.is_some()
            {
                return Err(error);
            }
        }
        Ok(())
    }

    pub(super) fn current_membership(
        &self,
        membership_id: CoreMembershipId,
    ) -> Option<&CoreMembership> {
        self.memberships.get(&membership_id).map(|(value, _)| value)
    }

    pub(super) fn memberships_for_deletion(
        &self,
        membership_id: CoreMembershipId,
    ) -> impl Iterator<Item = &CoreMembership> {
        self.membership_revisions
            .values()
            .map(|(value, _)| value)
            .filter(move |value| value.core_membership_id == membership_id)
    }

    pub(super) fn all_membership_revisions(&self) -> impl Iterator<Item = &CoreMembership> {
        self.membership_revisions
            .values()
            .map(|(membership, _)| membership)
    }

    pub(super) fn validation(
        &self,
        revision_id: RevisionId,
    ) -> Option<&GlobalSupportValidationEvent> {
        self.validations.get(&revision_id).map(|(value, _)| value)
    }

    pub(super) fn current_validation(
        &self,
        contract_revision_id: RevisionId,
    ) -> Option<&GlobalSupportValidationEvent> {
        self.current_validations
            .get(&contract_revision_id)
            .map(|(value, _)| value)
    }

    pub(super) fn validate_successor_fanout(
        &self,
        base_revision_id: RevisionId,
        replacement_successor: Option<RevisionId>,
        occurred_at_us: i64,
        effective_config_hash: [u8; 32],
        payloads: &[&JournalPayload],
        error: StoreError,
    ) -> Result<(), StoreError> {
        let mut expected = Vec::new();
        for (contract_id, (contract, _)) in &self.contracts {
            if contract
                .support_revision_refs
                .binary_search(&base_revision_id)
                .is_err()
            {
                continue;
            }
            expected.push(
                self.current_validations
                    .get(contract_id)
                    .map(|(validation, _)| validation)
                    .ok_or(error)?,
            );
        }

        let mut recorded_contract = None;
        let mut validations_by_contract = BTreeMap::new();
        let mut dirty_by_target = BTreeMap::new();
        let mut outbox_by_id = BTreeMap::new();
        let mut jobs_by_idempotency = BTreeMap::new();
        let mut support_closure_job_count = 0usize;
        for payload in payloads {
            match payload {
                JournalPayload::GlobalSupportContractRecorded(value) => {
                    if recorded_contract.replace(value.as_ref()).is_some() {
                        return Err(error);
                    }
                }
                JournalPayload::GlobalSupportValidationRecorded(value) => {
                    if validations_by_contract
                        .insert(value.support_contract_ref, value.as_ref())
                        .is_some()
                    {
                        return Err(error);
                    }
                }
                JournalPayload::DirtyTarget(value)
                    if value.target_kind == DirtyTargetKind::RuntimeJob =>
                {
                    if dirty_by_target
                        .insert(value.target_id.as_str(), value)
                        .is_some()
                    {
                        return Err(error);
                    }
                }
                JournalPayload::OutboxEnqueued(value)
                    if value.dirty.target_kind == DirtyTargetKind::RuntimeJob =>
                {
                    if outbox_by_id
                        .insert(value.outbox_id.as_str(), value)
                        .is_some()
                    {
                        return Err(error);
                    }
                }
                JournalPayload::JobState(value) => {
                    if value.kind == "support_closure" {
                        support_closure_job_count =
                            support_closure_job_count.checked_add(1).ok_or(error)?;
                    }
                    if jobs_by_idempotency
                        .insert(value.idempotency_key.as_str(), value)
                        .is_some()
                    {
                        return Err(error);
                    }
                }
                _ => {}
            }
        }
        let replacement_contract = match (replacement_successor, recorded_contract) {
            (Some(revision), Some(contract))
                if contract.successor_revision_or_membership_ref == revision.to_string() =>
            {
                Some(contract)
            }
            (None, None) => None,
            _ => return Err(error),
        };

        let expected_trigger = vec![base_revision_id.to_string()];
        for current in &expected {
            let next_generation = current.dependency_generation.checked_add(1).ok_or(error)?;
            let pending = *validations_by_contract
                .get(&current.support_contract_ref)
                .ok_or(error)?;
            validate_validation_successor(current, pending).map_err(|_| error)?;
            if pending.dependency_generation != next_generation
                || pending.state != GlobalSupportState::RevalidationPending
                || pending.provenance_degraded != current.provenance_degraded
                || pending.surviving_support_refs != current.surviving_support_refs
                || !pending.invalid_or_missing_refs.is_empty()
                || pending.trigger_refs != expected_trigger
                || pending.validator_revision != 1
                || pending.created_at_us != occurred_at_us
            {
                return Err(error);
            }
            let contract_ref = current.support_contract_ref.to_string();
            let dirty = *dirty_by_target.get(contract_ref.as_str()).ok_or(error)?;
            if dirty.source_watermark != next_generation {
                return Err(error);
            }
            let idempotency_key =
                format!("support:{}:{next_generation}", current.support_contract_ref);
            let outbox = *outbox_by_id.get(idempotency_key.as_str()).ok_or(error)?;
            if outbox.dirty != *dirty {
                return Err(error);
            }
            let job = *jobs_by_idempotency
                .get(idempotency_key.as_str())
                .ok_or(error)?;
            if job.target_revision != current.successor_ref
                || job.target_watermark != next_generation
                || job.target_generation != next_generation
                || job.kind != "support_closure"
                || job.algorithm_revision != dirty.algorithm_revision
                || job.model_id.is_some()
                || job.priority != 0
                || job.state != JobStatus::Queued
                || job.attempt != 1
                || job.backoff_until_us.is_some()
                || job.config_hash != effective_config_hash
                || job.budget.max_items != 1
                || job.budget.max_bytes.is_some()
                || job.budget.max_input_tokens.is_some()
                || job.budget.max_output_tokens.is_some()
                || job.budget.max_calls.is_some()
                || job.budget.max_wall_time_ms != 250
                || job.terminal.is_some()
                || job.lease_until_us.is_some()
            {
                return Err(error);
            }
        }

        let replacement_contract_id =
            replacement_contract.map(|contract| contract.support_contract_revision_id);
        if let Some(contract_id) = replacement_contract_id
            && validations_by_contract
                .get(&contract_id)
                .is_none_or(|validation| validation.state != GlobalSupportState::Valid)
        {
            return Err(error);
        }
        let expected_validations = expected
            .len()
            .checked_add(usize::from(replacement_contract_id.is_some()))
            .ok_or(error)?;
        if validations_by_contract.len() != expected_validations
            || dirty_by_target.len() != expected_validations
            || outbox_by_id.len() != expected_validations
            || support_closure_job_count != expected.len()
        {
            return Err(error);
        }
        Ok(())
    }

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
    use evertrace_domain::{ids::JobId, semantic::SupportThresholdSnapshot};

    use crate::{DirtyTarget, DurableJob, JobBudget, OutboxEntry};

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
    fn successor_fanout_requires_exact_pending_cohort_and_contract_polarity() {
        let base_revision_id = RevisionId::new_v7();
        let contract_id = RevisionId::new_v7();
        let mut contract = support_contract(contract_id, &RevisionId::new_v7().to_string());
        contract.support_revision_refs = vec![base_revision_id];
        let current = GlobalSupportValidationEvent {
            validation_revision_id: RevisionId::new_v7(),
            support_contract_ref: contract_id,
            successor_ref: contract.successor_revision_or_membership_ref.clone(),
            dependency_generation: 1,
            state: GlobalSupportState::Valid,
            provenance_degraded: false,
            surviving_support_refs: vec![base_revision_id],
            invalid_or_missing_refs: Vec::new(),
            trigger_refs: Vec::new(),
            validator_revision: 1,
            created_at_us: 1,
        };
        let mut state = S23State::default();
        state
            .apply(
                JournalPayload::GlobalSupportContractRecorded(Box::new(contract)),
                1,
            )
            .unwrap();
        state
            .apply(
                JournalPayload::GlobalSupportValidationRecorded(Box::new(current.clone())),
                2,
            )
            .unwrap();

        let occurred_at_us = 9;
        let config_hash = [9; 32];
        let next_generation = current.dependency_generation + 1;
        let pending = GlobalSupportValidationEvent {
            validation_revision_id: RevisionId::new_v7(),
            dependency_generation: next_generation,
            state: GlobalSupportState::RevalidationPending,
            trigger_refs: vec![base_revision_id.to_string()],
            created_at_us: occurred_at_us,
            ..current.clone()
        };
        let dirty = DirtyTarget {
            target_kind: DirtyTargetKind::RuntimeJob,
            target_id: contract_id.to_string(),
            algorithm_revision: "s23-scenario-core-v1".into(),
            source_watermark: next_generation,
        };
        let idempotency_key = format!("support:{contract_id}:{next_generation}");
        let payloads = vec![
            JournalPayload::GlobalSupportValidationRecorded(Box::new(pending.clone())),
            JournalPayload::DirtyTarget(dirty.clone()),
            JournalPayload::OutboxEnqueued(OutboxEntry {
                outbox_id: idempotency_key.clone(),
                dirty: dirty.clone(),
            }),
            JournalPayload::JobState(DurableJob {
                job_id: JobId::new_v7(),
                idempotency_key,
                target_revision: current.successor_ref.clone(),
                target_watermark: next_generation,
                target_generation: next_generation,
                kind: "support_closure".into(),
                algorithm_revision: dirty.algorithm_revision.clone(),
                model_id: None,
                priority: 0,
                state: JobStatus::Queued,
                attempt: 1,
                backoff_until_us: None,
                config_hash,
                budget: JobBudget {
                    max_items: 1,
                    max_bytes: None,
                    max_input_tokens: None,
                    max_output_tokens: None,
                    max_calls: None,
                    max_wall_time_ms: 250,
                },
                terminal: None,
                lease_until_us: None,
            }),
        ];
        let validate = |payloads: &[JournalPayload], replacement| {
            state.validate_successor_fanout(
                base_revision_id,
                replacement,
                occurred_at_us,
                config_hash,
                &payloads.iter().collect::<Vec<_>>(),
                StoreError::InvalidInput,
            )
        };
        assert_eq!(validate(&payloads, None), Ok(()));

        let mut missing = payloads.clone();
        missing.pop();
        assert_eq!(validate(&missing, None), Err(StoreError::InvalidInput));

        let mut extra = payloads.clone();
        extra.push(JournalPayload::GlobalSupportValidationRecorded(Box::new(
            GlobalSupportValidationEvent {
                validation_revision_id: RevisionId::new_v7(),
                support_contract_ref: RevisionId::new_v7(),
                ..pending
            },
        )));
        assert_eq!(validate(&extra, None), Err(StoreError::InvalidInput));
        assert_eq!(
            validate(&payloads, Some(RevisionId::new_v7())),
            Err(StoreError::InvalidInput)
        );
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
