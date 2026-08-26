use std::collections::{BTreeMap, BTreeSet};

use evertrace_domain::{
    evidence::{
        CanonicalEventFamily, CorrelationAdmission, CorrelationStrength, EffectRole,
        FieldProvenanceEntry, HostOccurrence, HostOccurrenceExactKey, NormalizationState,
        ObservationRole, Operation, PairingState, ScopeEffect, ScopeEffectClaim, SourceObservation,
        host_occurrence_id_for_exact, host_occurrence_id_for_nonexact,
    },
    ids::{
        CommandId, ExperimentRunId, HostOccurrenceId, OperationId, RepositoryId, ScopeEffectId,
        SourceObservationId, WorkArtifactId, WorktreeId, WorktreeSnapshotId,
    },
};
use evertrace_store::{
    EventScope, JournalCommand, JournalEventDraft, JournalPayload, NormalizationWatermark,
    SourceKind,
};
use thiserror::Error;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NormalizationSnapshot {
    pub occurrences: Vec<HostOccurrence>,
    pub operations: Vec<Operation>,
    pub scope_effects: Vec<ScopeEffect>,
}

impl NormalizationSnapshot {
    pub fn validate(&self) -> Result<(), NormalizeError> {
        let occurrences = self
            .occurrences
            .iter()
            .map(|value| (value.host_occurrence_id, value))
            .collect::<BTreeMap<_, _>>();
        let operations = self
            .operations
            .iter()
            .map(|value| (value.operation_id, value))
            .collect::<BTreeMap<_, _>>();
        if occurrences.len() != self.occurrences.len() || operations.len() != self.operations.len()
        {
            return Err(NormalizeError::InvalidResult);
        }
        for occurrence in &self.occurrences {
            occurrence
                .validate()
                .map_err(|_| NormalizeError::InvalidResult)?;
        }
        for operation in &self.operations {
            operation
                .validate()
                .map_err(|_| NormalizeError::InvalidResult)?;
            if !occurrences.contains_key(&operation.host_occurrence_id) {
                return Err(NormalizeError::InvalidResult);
            }
        }
        let mut effect_ids = BTreeSet::new();
        for effect in &self.scope_effects {
            effect
                .validate()
                .map_err(|_| NormalizeError::InvalidResult)?;
            if !effect_ids.insert(effect.scope_effect_id)
                || !operations.contains_key(&effect.operation_id)
            {
                return Err(NormalizeError::InvalidResult);
            }
        }
        for operation in &self.operations {
            let actual = self
                .scope_effects
                .iter()
                .filter(|effect| effect.operation_id == operation.operation_id)
                .map(|effect| effect.scope_effect_id)
                .collect::<BTreeSet<_>>();
            if actual != operation.scope_effect_ids.iter().copied().collect() {
                return Err(NormalizeError::InvalidResult);
            }
        }
        Ok(())
    }

    pub fn journal_command(
        &self,
        command_id: CommandId,
        occurred_at_us: i64,
        effective_config_hash: [u8; 32],
        algorithm_revision: &str,
    ) -> Result<JournalCommand, NormalizeError> {
        self.validate()?;
        if occurred_at_us < 0 || algorithm_revision.is_empty() || algorithm_revision.len() > 256 {
            return Err(NormalizeError::InvalidInput);
        }
        let mut payloads = self
            .occurrences
            .iter()
            .cloned()
            .map(|value| JournalPayload::HostOccurrenceNormalized(Box::new(value)))
            .chain(
                self.operations
                    .iter()
                    .cloned()
                    .map(|value| JournalPayload::OperationDerived(Box::new(value))),
            )
            .chain(
                self.scope_effects
                    .iter()
                    .cloned()
                    .map(|value| JournalPayload::ScopeEffectDerived(Box::new(value))),
            )
            .collect::<Vec<_>>();
        let resolver_by_observation = self
            .occurrences
            .iter()
            .flat_map(|occurrence| {
                occurrence
                    .source_observation_refs
                    .iter()
                    .map(move |id| (*id, occurrence.correlation_resolver_version))
            })
            .collect::<BTreeMap<_, _>>();
        payloads.extend(resolver_by_observation.into_iter().map(
            |(source_observation_id, resolver_version)| {
                JournalPayload::NormalizationWatermark(NormalizationWatermark {
                    source_observation_id,
                    resolver_version,
                })
            },
        ));
        let events = payloads
            .into_iter()
            .map(|payload| JournalEventDraft {
                occurred_at_us,
                source_kind: SourceKind::System,
                scope: EventScope::default(),
                causation_id: None,
                correlation_id: None,
                effective_config_hash,
                algorithm_revision: algorithm_revision.to_owned(),
                payload,
            })
            .collect();
        JournalCommand::new(command_id, events).map_err(|_| NormalizeError::InvalidResult)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalNormalizer {
    resolver_version: u32,
}

impl PhysicalNormalizer {
    pub fn new(resolver_version: u32) -> Result<Self, NormalizeError> {
        if resolver_version == 0 {
            return Err(NormalizeError::InvalidInput);
        }
        Ok(Self { resolver_version })
    }

    pub fn normalize(
        &self,
        observations: &[SourceObservation],
        previous: Option<&NormalizationSnapshot>,
    ) -> Result<NormalizationSnapshot, NormalizeError> {
        let mut by_id = BTreeMap::new();
        for observation in observations {
            observation
                .validate()
                .map_err(|_| NormalizeError::InvalidInput)?;
            if by_id
                .insert(observation.source_observation_id, observation)
                .is_some()
            {
                return Err(NormalizeError::InvalidInput);
            }
        }
        if let Some(previous) = previous {
            previous.validate()?;
        }

        let conflicted_partial_refs = conflicting_partial_refs(observations);
        let mut exact_groups: BTreeMap<HostOccurrenceExactKey, Vec<&SourceObservation>> =
            BTreeMap::new();
        let mut nonexact = Vec::new();
        for observation in by_id.values() {
            if let Some(key) = observation.correlation.exact_key() {
                exact_groups.entry(key).or_default().push(observation);
            } else {
                nonexact.push(*observation);
            }
        }

        let previous_occurrences = previous
            .into_iter()
            .flat_map(|value| &value.occurrences)
            .map(|value| (value.host_occurrence_id, value))
            .collect::<BTreeMap<_, _>>();
        let previous_operations = previous
            .into_iter()
            .flat_map(|value| &value.operations)
            .map(|value| (value.host_occurrence_id, value))
            .collect::<BTreeMap<_, _>>();
        let previous_effects = previous
            .into_iter()
            .flat_map(|value| &value.scope_effects)
            .collect::<Vec<_>>();

        let mut occurrences = Vec::new();
        for (key, members) in exact_groups {
            occurrences.push(build_exact_occurrence(
                self.resolver_version,
                key,
                &members,
                &previous_occurrences,
            )?);
        }
        for observation in nonexact {
            occurrences.push(build_nonexact_occurrence(
                self.resolver_version,
                observation,
                &conflicted_partial_refs,
                &previous_occurrences,
            )?);
        }
        occurrences.sort_by_key(|value| value.host_occurrence_id);

        let mut operations = Vec::new();
        let mut scope_effects = Vec::new();
        for occurrence in &occurrences {
            let members = occurrence
                .source_observation_refs
                .iter()
                .map(|id| by_id.get(id).copied().ok_or(NormalizeError::InvalidResult))
                .collect::<Result<Vec<_>, _>>()?;
            let Some(operation_kind) = occurrence
                .canonical_event_family
                .and_then(CanonicalEventFamily::operation_kind)
            else {
                continue;
            };
            let previous_operation = previous_operations
                .get(&occurrence.host_occurrence_id)
                .copied();
            let operation_id =
                previous_operation.map_or_else(OperationId::new_v7, |value| value.operation_id);
            let claims = merge_scope_claims(&members)?;
            let mut effects = Vec::new();
            for claim in claims {
                let existing = previous_effects.iter().copied().find(|effect| {
                    effect.operation_id == operation_id && effect_matches_claim(effect, &claim)
                });
                let effect = existing.cloned().unwrap_or_else(|| ScopeEffect {
                    scope_effect_id: ScopeEffectId::new_v7(),
                    operation_id,
                    effect_role: claim.effect_role,
                    repository_instance_id: claim.repository_instance_id,
                    worktree_instance_id: claim.worktree_instance_id,
                    pre_snapshot_id: claim.pre_snapshot_id,
                    post_snapshot_id: claim.post_snapshot_id,
                    experiment_run_ids: claim.experiment_run_ids,
                    artifact_refs: claim.artifact_refs,
                    evidence_refs: claim.evidence_refs,
                });
                effect
                    .validate()
                    .map_err(|_| NormalizeError::InvalidResult)?;
                effects.push(effect);
            }
            effects.sort_by_key(|value| value.scope_effect_id);
            let mut inputs = members
                .iter()
                .filter(|value| value.observation_role == ObservationRole::Intent)
                .map(|value| value.source_observation_id)
                .collect::<Vec<_>>();
            let mut results = members
                .iter()
                .filter(|value| value.observation_role != ObservationRole::Intent)
                .map(|value| value.source_observation_id)
                .collect::<Vec<_>>();
            inputs.sort();
            results.sort();
            let mut operation = Operation {
                operation_id,
                host_occurrence_id: occurrence.host_occurrence_id,
                execution_lane_id: None,
                operation_kind,
                input_source_observation_refs: inputs,
                result_source_observation_refs: results,
                pairing_state: occurrence.pairing_state,
                scope_effect_ids: effects.iter().map(|value| value.scope_effect_id).collect(),
                artifact_refs: effects
                    .iter()
                    .flat_map(|value| value.artifact_refs.iter().copied())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                operation_resolver_version: self.resolver_version,
                operation_revision: 1,
                previous_operation_revision: None,
            };
            if let Some(previous) = previous_operation {
                let mut comparable = operation.clone();
                comparable.operation_revision = previous.operation_revision;
                comparable.previous_operation_revision = previous.previous_operation_revision;
                if comparable == *previous {
                    operation = previous.clone();
                } else {
                    operation.operation_revision = previous.operation_revision + 1;
                    operation.previous_operation_revision = Some(previous.operation_revision);
                }
            }
            operation
                .validate()
                .map_err(|_| NormalizeError::InvalidResult)?;
            scope_effects.extend(effects);
            operations.push(operation);
        }
        operations.sort_by_key(|value| value.operation_id);
        scope_effects.sort_by_key(|value| value.scope_effect_id);
        let result = NormalizationSnapshot {
            occurrences,
            operations,
            scope_effects,
        };
        result.validate()?;
        Ok(result)
    }
}

fn build_exact_occurrence(
    resolver_version: u32,
    key: HostOccurrenceExactKey,
    members: &[&SourceObservation],
    previous: &BTreeMap<HostOccurrenceId, &HostOccurrence>,
) -> Result<HostOccurrence, NormalizeError> {
    let id = host_occurrence_id_for_exact(&key).map_err(|_| NormalizeError::InvalidInput)?;
    let mut refs = members
        .iter()
        .map(|value| value.source_observation_id)
        .collect::<Vec<_>>();
    refs.sort();
    let pairing_state = pairing_state(members, true);
    let roles = members
        .iter()
        .map(|value| value.observation_role)
        .collect::<BTreeSet<_>>();
    let state = if pairing_state == PairingState::Conflicted {
        NormalizationState::NormalizationConflicted
    } else if members.len() == 1 {
        NormalizationState::SingleSource
    } else if roles.len() > 1 {
        NormalizationState::Complemented
    } else {
        NormalizationState::Corroborated
    };
    let mut occurrence = HostOccurrence {
        host_occurrence_id: id,
        exact_key: Some(key.clone()),
        host_instance_id: Some(key.host_instance_id.clone()),
        host_trace_lineage_id: Some(key.host_trace_lineage_id.clone()),
        host_lane_key: Some(key.host_lane_key.clone()),
        canonical_event_family: Some(key.canonical_event_family),
        native_request_id: Some(key.native_request_id.clone()),
        physical_execution_ordinal: Some(key.physical_execution_ordinal),
        correlation_strength: CorrelationStrength::Exact,
        source_observation_refs: refs,
        field_provenance: provenance(members),
        normalization_state: state,
        pairing_state,
        possible_duplicate_group_id: None,
        correlation_resolver_version: resolver_version,
        normalization_revision: 1,
        previous_normalization_revision: None,
    };
    update_occurrence_revision(&mut occurrence, previous.get(&id).copied());
    occurrence
        .validate()
        .map_err(|_| NormalizeError::InvalidResult)?;
    Ok(occurrence)
}

fn build_nonexact_occurrence(
    resolver_version: u32,
    observation: &SourceObservation,
    conflicted_partial_refs: &BTreeSet<String>,
    previous: &BTreeMap<HostOccurrenceId, &HostOccurrence>,
) -> Result<HostOccurrence, NormalizeError> {
    let strength = if observation
        .correlation
        .partial_correlation_ref
        .as_ref()
        .is_some_and(|value| conflicted_partial_refs.contains(value))
        || observation.correlation.admission == CorrelationAdmission::Conflicted
    {
        CorrelationStrength::Conflicted
    } else {
        match observation.correlation.admission {
            CorrelationAdmission::Unavailable => CorrelationStrength::Unavailable,
            CorrelationAdmission::Ambiguous | CorrelationAdmission::ExactCapable => {
                CorrelationStrength::Ambiguous
            }
            CorrelationAdmission::Conflicted => CorrelationStrength::Conflicted,
        }
    };
    let id = host_occurrence_id_for_nonexact(observation.source_observation_id, strength)
        .map_err(|_| NormalizeError::InvalidInput)?;
    let executable = observation
        .correlation
        .canonical_event_family
        .and_then(CanonicalEventFamily::operation_kind)
        .is_some();
    let mut occurrence = HostOccurrence {
        host_occurrence_id: id,
        exact_key: None,
        host_instance_id: observation.correlation.host_instance_id.clone(),
        host_trace_lineage_id: observation.correlation.host_trace_lineage_id.clone(),
        host_lane_key: observation.correlation.host_lane_key.clone(),
        canonical_event_family: observation.correlation.canonical_event_family,
        native_request_id: observation.correlation.native_request_id.clone(),
        physical_execution_ordinal: observation.correlation.physical_execution_ordinal,
        correlation_strength: strength,
        source_observation_refs: vec![observation.source_observation_id],
        field_provenance: provenance(&[observation]),
        normalization_state: if strength == CorrelationStrength::Conflicted {
            NormalizationState::NormalizationConflicted
        } else {
            NormalizationState::SingleSource
        },
        pairing_state: if executable {
            pairing_state(&[observation], false)
        } else {
            PairingState::NotApplicable
        },
        possible_duplicate_group_id: observation.correlation.possible_duplicate_group_id,
        correlation_resolver_version: resolver_version,
        normalization_revision: 1,
        previous_normalization_revision: None,
    };
    update_occurrence_revision(&mut occurrence, previous.get(&id).copied());
    occurrence
        .validate()
        .map_err(|_| NormalizeError::InvalidResult)?;
    Ok(occurrence)
}

fn update_occurrence_revision(current: &mut HostOccurrence, previous: Option<&HostOccurrence>) {
    if let Some(previous) = previous {
        let mut comparable = current.clone();
        comparable.normalization_revision = previous.normalization_revision;
        comparable.previous_normalization_revision = previous.previous_normalization_revision;
        if comparable == *previous {
            *current = previous.clone();
        } else {
            current.normalization_revision = previous.normalization_revision + 1;
            current.previous_normalization_revision = Some(previous.normalization_revision);
        }
    }
}

fn provenance(members: &[&SourceObservation]) -> Vec<FieldProvenanceEntry> {
    let mut entries = members
        .iter()
        .flat_map(|observation| {
            observation
                .correlation
                .field_provenance
                .iter()
                .map(move |claim| FieldProvenanceEntry {
                    field: claim.field,
                    source_observation_ref: observation.source_observation_id,
                    source_ref: claim.source_ref.clone(),
                    evidence_ref: claim.evidence_ref.clone(),
                })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.field.cmp(&right.field).then(
            left.source_observation_ref
                .cmp(&right.source_observation_ref),
        )
    });
    entries
}

fn pairing_state(members: &[&SourceObservation], exact: bool) -> PairingState {
    let intents = members
        .iter()
        .filter(|value| value.observation_role == ObservationRole::Intent)
        .count();
    let results = members
        .iter()
        .filter(|value| value.observation_role == ObservationRole::Result)
        .count();
    if intents > 1 || results > 1 {
        PairingState::Conflicted
    } else if exact && intents == 1 && results == 1 {
        PairingState::Paired
    } else if intents == 1 {
        PairingState::UnmatchedIntent
    } else if results == 1 {
        PairingState::UnmatchedResult
    } else {
        PairingState::NotApplicable
    }
}

fn conflicting_partial_refs(observations: &[SourceObservation]) -> BTreeSet<String> {
    let mut values: BTreeMap<String, BTreeSet<PartialTuple>> = BTreeMap::new();
    for observation in observations {
        if let Some(reference) = &observation.correlation.partial_correlation_ref {
            values
                .entry(reference.clone())
                .or_default()
                .insert(PartialTuple::from(observation));
        }
    }
    values
        .into_iter()
        .filter_map(|(reference, tuples)| (tuples.len() > 1).then_some(reference))
        .collect()
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PartialTuple {
    host_instance_id: Option<String>,
    host_trace_lineage_id: Option<String>,
    host_lane_key: Option<String>,
    canonical_event_family: Option<CanonicalEventFamily>,
    native_request_id: Option<String>,
    physical_execution_ordinal: Option<u32>,
}

impl From<&SourceObservation> for PartialTuple {
    fn from(value: &SourceObservation) -> Self {
        Self {
            host_instance_id: value.correlation.host_instance_id.clone(),
            host_trace_lineage_id: value.correlation.host_trace_lineage_id.clone(),
            host_lane_key: value.correlation.host_lane_key.clone(),
            canonical_event_family: value.correlation.canonical_event_family,
            native_request_id: value.correlation.native_request_id.clone(),
            physical_execution_ordinal: value.correlation.physical_execution_ordinal,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ScopeClaimKey {
    effect_role: EffectRole,
    repository_instance_id: Option<RepositoryId>,
    worktree_instance_id: Option<WorktreeId>,
    pre_snapshot_id: Option<WorktreeSnapshotId>,
    post_snapshot_id: Option<WorktreeSnapshotId>,
    experiment_run_ids: Vec<ExperimentRunId>,
    artifact_refs: Vec<WorkArtifactId>,
}

fn merge_scope_claims(
    observations: &[&SourceObservation],
) -> Result<Vec<ScopeEffectClaim>, NormalizeError> {
    let mut claims: BTreeMap<ScopeClaimKey, BTreeSet<SourceObservationId>> = BTreeMap::new();
    for observation in observations {
        for claim in &observation.scope_effect_claims {
            claim.validate().map_err(|_| NormalizeError::InvalidInput)?;
            let mut runs = claim.experiment_run_ids.clone();
            runs.sort();
            let mut artifacts = claim.artifact_refs.clone();
            artifacts.sort();
            let key = ScopeClaimKey {
                effect_role: claim.effect_role,
                repository_instance_id: claim.repository_instance_id,
                worktree_instance_id: claim.worktree_instance_id,
                pre_snapshot_id: claim.pre_snapshot_id,
                post_snapshot_id: claim.post_snapshot_id,
                experiment_run_ids: runs,
                artifact_refs: artifacts,
            };
            let evidence = claims.entry(key).or_default();
            evidence.insert(observation.source_observation_id);
            evidence.extend(claim.evidence_refs.iter().copied());
        }
    }
    Ok(claims
        .into_iter()
        .map(|(key, evidence_refs)| ScopeEffectClaim {
            effect_role: key.effect_role,
            repository_instance_id: key.repository_instance_id,
            worktree_instance_id: key.worktree_instance_id,
            pre_snapshot_id: key.pre_snapshot_id,
            post_snapshot_id: key.post_snapshot_id,
            experiment_run_ids: key.experiment_run_ids,
            artifact_refs: key.artifact_refs,
            evidence_refs: evidence_refs.into_iter().collect(),
        })
        .collect())
}

fn effect_matches_claim(effect: &ScopeEffect, claim: &ScopeEffectClaim) -> bool {
    effect.effect_role == claim.effect_role
        && effect.repository_instance_id == claim.repository_instance_id
        && effect.worktree_instance_id == claim.worktree_instance_id
        && effect.pre_snapshot_id == claim.pre_snapshot_id
        && effect.post_snapshot_id == claim.post_snapshot_id
        && effect.experiment_run_ids == claim.experiment_run_ids
        && effect.artifact_refs == claim.artifact_refs
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NormalizeError {
    #[error("normalization input is invalid")]
    InvalidInput,
    #[error("normalization result is invalid")]
    InvalidResult,
}
