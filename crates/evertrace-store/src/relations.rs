use std::collections::BTreeSet;

use evertrace_domain::evidence::{HostOccurrence, Operation, ScopeEffect};
use serde::{Deserialize, Serialize};

use crate::StoreError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalRelationKind {
    SourceObservationToHostOccurrence,
    HostOccurrenceToOperation,
    OperationToScopeEffect,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalRelationRow {
    pub kind: PhysicalRelationKind,
    pub source_id: String,
    pub target_id: String,
}

pub fn build_physical_relation_rows(
    occurrences: &[HostOccurrence],
    operations: &[Operation],
    scope_effects: &[ScopeEffect],
) -> Result<Vec<PhysicalRelationRow>, StoreError> {
    let occurrence_ids = occurrences
        .iter()
        .map(|value| value.host_occurrence_id)
        .collect::<BTreeSet<_>>();
    let operation_ids = operations
        .iter()
        .map(|value| value.operation_id)
        .collect::<BTreeSet<_>>();
    if occurrence_ids.len() != occurrences.len() || operation_ids.len() != operations.len() {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for occurrence in occurrences {
        occurrence
            .validate()
            .map_err(|_| StoreError::InvalidInput)?;
        for observation in &occurrence.source_observation_refs {
            rows.insert(PhysicalRelationRow {
                kind: PhysicalRelationKind::SourceObservationToHostOccurrence,
                source_id: observation.to_string(),
                target_id: occurrence.host_occurrence_id.to_string(),
            });
        }
    }
    for operation in operations {
        operation.validate().map_err(|_| StoreError::InvalidInput)?;
        if !occurrence_ids.contains(&operation.host_occurrence_id) {
            return Err(StoreError::InvalidInput);
        }
        rows.insert(PhysicalRelationRow {
            kind: PhysicalRelationKind::HostOccurrenceToOperation,
            source_id: operation.host_occurrence_id.to_string(),
            target_id: operation.operation_id.to_string(),
        });
    }
    for effect in scope_effects {
        effect.validate().map_err(|_| StoreError::InvalidInput)?;
        if !operation_ids.contains(&effect.operation_id) {
            return Err(StoreError::InvalidInput);
        }
        rows.insert(PhysicalRelationRow {
            kind: PhysicalRelationKind::OperationToScopeEffect,
            source_id: effect.operation_id.to_string(),
            target_id: effect.scope_effect_id.to_string(),
        });
    }
    Ok(rows.into_iter().collect())
}
