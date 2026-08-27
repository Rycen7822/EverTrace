//! S11 repository/worktree store wiring: typed current view over the objects
//! projection, command-closure and current-state admission helpers, and pure
//! relation DTO assembly. All Git reads stay in evertrace-engine; this module
//! never executes Git or touches the filesystem.

use std::collections::BTreeMap;

use evertrace_domain::{
    ids::{IntegrationEventId, RepositoryId, WorktreeId, WorktreeSnapshotId, WorktreeTransitionId},
    repository::{
        IntegrationEvent, RepositoryInstance, WorktreeInstance, WorktreeSnapshot,
        WorktreeTransition, lifecycle_successor_allowed,
    },
};

use crate::{
    command::{JournalEventDraft, JournalPayload, StoreError},
    projections::ProjectionSnapshot,
    relations::{RepositoryRelationRow, build_repository_relation_rows},
};

pub const REPOSITORY_ROW_PREFIX: &str = "object:work:repository:";
pub const WORKTREE_ROW_PREFIX: &str = "object:work:worktree:";
pub const SNAPSHOT_ROW_PREFIX: &str = "object:work:worktree_snapshot:";
pub const TRANSITION_ROW_PREFIX: &str = "object:work:worktree_transition:";
pub const INTEGRATION_ROW_PREFIX: &str = "object:work:integration_event:";

/// Typed read-only view of the repository/worktree current projection,
/// consumed by the engine resolver before any commit decision.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RepositoryCurrentView {
    pub frontier: u64,
    pub repositories: BTreeMap<RepositoryId, RepositoryInstance>,
    pub worktrees: BTreeMap<WorktreeId, WorktreeInstance>,
    pub snapshots: BTreeMap<WorktreeSnapshotId, WorktreeSnapshot>,
    pub transitions: BTreeMap<WorktreeTransitionId, WorktreeTransition>,
    pub integrations: BTreeMap<IntegrationEventId, IntegrationEvent>,
}

impl RepositoryCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut view = Self {
            frontier: snapshot.frontier,
            ..Self::default()
        };
        for row in snapshot.data_rows() {
            let Some(payload_json) = row.payload_json.as_deref() else {
                continue;
            };
            let payload: JournalPayload =
                serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
            match payload {
                JournalPayload::RepositoryInstanceRecorded(value)
                    if row.row_id == repository_row_id(&value.repository_id) =>
                {
                    view.repositories.insert(value.repository_id, *value);
                }
                JournalPayload::WorktreeInstanceRecorded(value)
                    if row.row_id == worktree_row_id(&value.worktree_instance_id) =>
                {
                    view.worktrees.insert(value.worktree_instance_id, *value);
                }
                JournalPayload::WorktreeSnapshotRecorded(value)
                    if row.row_id == snapshot_row_id(&value.worktree_snapshot_id) =>
                {
                    view.snapshots.insert(value.worktree_snapshot_id, *value);
                }
                JournalPayload::WorktreeTransitionRecorded(value)
                    if row.row_id == transition_row_id(&value.worktree_transition_id) =>
                {
                    view.transitions
                        .insert(value.worktree_transition_id, *value);
                }
                JournalPayload::IntegrationEventRecorded(value)
                    if row.row_id == integration_row_id(&value.integration_event_id) =>
                {
                    view.integrations.insert(value.integration_event_id, *value);
                }
                JournalPayload::RepositoryInstanceRecorded(_)
                | JournalPayload::WorktreeInstanceRecorded(_)
                | JournalPayload::WorktreeSnapshotRecorded(_)
                | JournalPayload::WorktreeTransitionRecorded(_)
                | JournalPayload::IntegrationEventRecorded(_) => {
                    return Err(StoreError::StoreCorrupt);
                }
                _ => {}
            }
        }
        validate_repository_relations(
            &with_unit_metadata(&view.repositories),
            &with_unit_metadata(&view.worktrees),
            &with_unit_metadata(&view.snapshots),
            &with_unit_metadata(&view.transitions),
            &with_unit_metadata(&view.integrations),
        )?;
        Ok(view)
    }

    pub fn worktrees_of(&self, repository_id: RepositoryId) -> Vec<&WorktreeInstance> {
        self.worktrees
            .values()
            .filter(|worktree| worktree.repository_instance_id == repository_id)
            .collect()
    }

    /// Admin (`gitdir`) paths of non-terminal worktrees, passed to the probe
    /// so removal can only be declared on positive evidence.
    pub fn known_admin_paths(&self) -> Vec<String> {
        self.worktrees
            .values()
            .filter(|worktree| !worktree.lifecycle.is_terminal())
            .filter_map(|worktree| {
                worktree
                    .git_admin_path_history
                    .last()
                    .map(|path| path.path.clone())
            })
            .collect()
    }

    /// Pure relation DTO assembly; no relation table is opened before L0002.
    pub fn relation_rows(&self) -> Result<Vec<RepositoryRelationRow>, StoreError> {
        build_repository_relation_rows(
            &self.repositories.values().cloned().collect::<Vec<_>>(),
            &self.worktrees.values().cloned().collect::<Vec<_>>(),
            &self.snapshots.values().cloned().collect::<Vec<_>>(),
            &self.transitions.values().cloned().collect::<Vec<_>>(),
            &self.integrations.values().cloned().collect::<Vec<_>>(),
        )
    }
}

pub fn repository_row_id(id: &RepositoryId) -> String {
    format!("{REPOSITORY_ROW_PREFIX}{id}")
}

pub fn worktree_row_id(id: &WorktreeId) -> String {
    format!("{WORKTREE_ROW_PREFIX}{id}")
}

pub fn snapshot_row_id(id: &WorktreeSnapshotId) -> String {
    format!("{SNAPSHOT_ROW_PREFIX}{id}")
}

pub fn transition_row_id(id: &WorktreeTransitionId) -> String {
    format!("{TRANSITION_ROW_PREFIX}{id}")
}

pub fn integration_row_id(id: &IntegrationEventId) -> String {
    format!("{INTEGRATION_ROW_PREFIX}{id}")
}

/// Command-level closure validation, mirroring `validate_normalization_command`:
/// every cross-reference resolvable inside the command must resolve, and a
/// worktree current-snapshot pointer must point at a snapshot committed in
/// the same command.
pub(crate) fn validate_repository_command(events: &[JournalEventDraft]) -> Result<(), StoreError> {
    validate_repository_payloads(events.iter().map(|event| &event.payload))
}

pub(crate) fn validate_repository_payloads<'a>(
    payloads: impl IntoIterator<Item = &'a JournalPayload>,
) -> Result<(), StoreError> {
    let mut repositories = BTreeMap::new();
    let mut worktrees = BTreeMap::new();
    let mut snapshots = BTreeMap::new();
    let mut transitions = BTreeMap::new();
    let mut integrations = BTreeMap::new();
    for payload in payloads {
        match payload {
            JournalPayload::RepositoryInstanceRecorded(value) => {
                insert_unique(&mut repositories, value.repository_id, value.as_ref())?;
            }
            JournalPayload::WorktreeInstanceRecorded(value) => {
                insert_unique(&mut worktrees, value.worktree_instance_id, value.as_ref())?;
            }
            JournalPayload::WorktreeSnapshotRecorded(value) => {
                insert_unique(&mut snapshots, value.worktree_snapshot_id, value.as_ref())?;
            }
            JournalPayload::WorktreeTransitionRecorded(value) => {
                insert_unique(
                    &mut transitions,
                    value.worktree_transition_id,
                    value.as_ref(),
                )?;
            }
            JournalPayload::IntegrationEventRecorded(value) => {
                insert_unique(
                    &mut integrations,
                    value.integration_event_id,
                    value.as_ref(),
                )?;
            }
            _ => {}
        }
    }
    for worktree in worktrees.values() {
        // Pointer targets committed in an earlier command are validated
        // against the merged state by `validate_repository_relations`; the
        // command-level closure only checks cross-references that are both
        // inside this command.
        if let Some(snapshot_id) = worktree.current_snapshot_id
            && let Some(snapshot) = snapshots.get(&snapshot_id)
            && snapshot.worktree_instance_id != worktree.worktree_instance_id
        {
            return Err(StoreError::InvalidInput);
        }
        if let Some(recreated_from) = worktree.recreated_from_worktree_instance_id
            && let Some(previous) = worktrees.get(&recreated_from)
            && !previous.lifecycle.is_terminal()
        {
            return Err(StoreError::InvalidInput);
        }
    }
    for snapshot in snapshots.values() {
        if let Some(worktree) = worktrees.get(&snapshot.worktree_instance_id)
            && worktree.current_snapshot_id != Some(snapshot.worktree_snapshot_id)
        {
            return Err(StoreError::InvalidInput);
        }
    }
    for transition in transitions.values() {
        for (worktree_id, snapshot_id) in [
            (
                transition.from_worktree_instance_id,
                transition.from_snapshot_id,
            ),
            (
                transition.to_worktree_instance_id,
                transition.to_snapshot_id,
            ),
        ] {
            if let Some(snapshot_id) = snapshot_id
                && let Some(snapshot) = snapshots.get(&snapshot_id)
                && snapshot.worktree_instance_id != worktree_id
            {
                return Err(StoreError::InvalidInput);
            }
        }
    }
    for integration in integrations.values() {
        if let Some(snapshot) = snapshots.get(&integration.source_snapshot_id)
            && snapshot.worktree_instance_id != integration.source_worktree_instance_id
        {
            return Err(StoreError::InvalidInput);
        }
        if let Some(snapshot) = snapshots.get(&integration.destination_snapshot_id)
            && snapshot.worktree_instance_id != integration.destination_worktree_instance_id
        {
            return Err(StoreError::InvalidInput);
        }
    }
    Ok(())
}

fn with_unit_metadata<K: Ord + Clone, V: Clone>(map: &BTreeMap<K, V>) -> BTreeMap<K, (V, ())> {
    map.iter()
        .map(|(key, value)| (key.clone(), (value.clone(), ())))
        .collect()
}

fn insert_unique<K: Ord, V>(map: &mut BTreeMap<K, V>, key: K, value: V) -> Result<(), StoreError> {
    if map.insert(key, value).is_some() {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}

/// Current-state relation closure, checked identically by live admission and
/// by journal replay (`JournalAdmissionState`) and by the reducer's
/// `validate_evidence_relations`.
pub(crate) fn validate_repository_relations<M: Copy>(
    repositories: &BTreeMap<RepositoryId, (RepositoryInstance, M)>,
    worktrees: &BTreeMap<WorktreeId, (WorktreeInstance, M)>,
    snapshots: &BTreeMap<WorktreeSnapshotId, (WorktreeSnapshot, M)>,
    transitions: &BTreeMap<WorktreeTransitionId, (WorktreeTransition, M)>,
    integrations: &BTreeMap<IntegrationEventId, (IntegrationEvent, M)>,
) -> Result<(), StoreError> {
    for (repository, _) in repositories.values() {
        if let Some(derived_from) = repository.derived_from
            && !repositories.contains_key(&derived_from)
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for (worktree, _) in worktrees.values() {
        if !repositories.contains_key(&worktree.repository_instance_id) {
            return Err(StoreError::StoreCorrupt);
        }
        if let Some(snapshot_id) = worktree.current_snapshot_id {
            let (snapshot, _) = snapshots
                .get(&snapshot_id)
                .ok_or(StoreError::StoreCorrupt)?;
            if snapshot.worktree_instance_id != worktree.worktree_instance_id {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if let Some(recreated_from) = worktree.recreated_from_worktree_instance_id {
            let (previous, _) = worktrees
                .get(&recreated_from)
                .ok_or(StoreError::StoreCorrupt)?;
            if !previous.lifecycle.is_terminal() {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    for (snapshot, _) in snapshots.values() {
        if !worktrees.contains_key(&snapshot.worktree_instance_id) {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for (transition, _) in transitions.values() {
        for (worktree_id, snapshot_id) in [
            (
                transition.from_worktree_instance_id,
                transition.from_snapshot_id,
            ),
            (
                transition.to_worktree_instance_id,
                transition.to_snapshot_id,
            ),
        ] {
            if !worktrees.contains_key(&worktree_id) {
                return Err(StoreError::StoreCorrupt);
            }
            if let Some(snapshot_id) = snapshot_id {
                let (snapshot, _) = snapshots
                    .get(&snapshot_id)
                    .ok_or(StoreError::StoreCorrupt)?;
                if snapshot.worktree_instance_id != worktree_id {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
    }
    for (integration, _) in integrations.values() {
        if !repositories.contains_key(&integration.repository_instance_id)
            || !worktrees.contains_key(&integration.source_worktree_instance_id)
            || !worktrees.contains_key(&integration.destination_worktree_instance_id)
        {
            return Err(StoreError::StoreCorrupt);
        }
        let (source, _) = snapshots
            .get(&integration.source_snapshot_id)
            .ok_or(StoreError::StoreCorrupt)?;
        if source.worktree_instance_id != integration.source_worktree_instance_id {
            return Err(StoreError::StoreCorrupt);
        }
        let (destination, _) = snapshots
            .get(&integration.destination_snapshot_id)
            .ok_or(StoreError::StoreCorrupt)?;
        if destination.worktree_instance_id != integration.destination_worktree_instance_id {
            return Err(StoreError::StoreCorrupt);
        }
    }
    Ok(())
}

pub(crate) fn replace_repository(
    values: &mut BTreeMap<RepositoryId, (RepositoryInstance, u64)>,
    value: RepositoryInstance,
    seq: u64,
) -> Result<(), StoreError> {
    match values.get(&value.repository_id) {
        None => {
            if value.repository_revision != 1 {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Some((current, _)) => {
            if current == &value {
                values.insert(value.repository_id, (value, seq));
                return Ok(());
            }
            let continuity_broken = value.repository_revision != current.repository_revision + 1
                || value.predecessor_revision != Some(current.repository_revision)
                || value.derived_from != current.derived_from
                || value.object_format != current.object_format
                || value.common_dir_filesystem != current.common_dir_filesystem
                || !prefix_of(&current.path_history, &value.path_history);
            if continuity_broken {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    values.insert(value.repository_id, (value, seq));
    Ok(())
}

pub(crate) fn replace_worktree(
    values: &mut BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
    value: WorktreeInstance,
    seq: u64,
) -> Result<(), StoreError> {
    match values.get(&value.worktree_instance_id) {
        None => {
            if value.worktree_revision != 1 {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Some((current, _)) => {
            if current == &value {
                values.insert(value.worktree_instance_id, (value, seq));
                return Ok(());
            }
            let continuity_broken = value.worktree_revision != current.worktree_revision + 1
                || value.predecessor_revision != Some(current.worktree_revision)
                || value.repository_instance_id != current.repository_instance_id
                || value.kind != current.kind
                || value.created_event_ref != current.created_event_ref
                || value.recreated_from_worktree_instance_id
                    != current.recreated_from_worktree_instance_id
                || !lifecycle_successor_allowed(current.lifecycle, value.lifecycle)
                || current.terminal_event_ref.is_some() && value.terminal_event_ref.is_none()
                || !prefix_of(&current.path_history, &value.path_history)
                || !prefix_of(
                    &current.git_admin_path_history,
                    &value.git_admin_path_history,
                );
            if continuity_broken {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    values.insert(value.worktree_instance_id, (value, seq));
    Ok(())
}

pub(crate) fn replace_snapshot(
    values: &mut BTreeMap<WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
    value: WorktreeSnapshot,
    seq: u64,
) -> Result<(), StoreError> {
    // Snapshots are immutable: the same ID with different content is
    // corruption; identical re-record is an idempotent no-op.
    if let Some((current, _)) = values.get(&value.worktree_snapshot_id)
        && current != &value
    {
        return Err(StoreError::StoreCorrupt);
    }
    values.insert(value.worktree_snapshot_id, (value, seq));
    Ok(())
}

pub(crate) fn replace_transition(
    values: &mut BTreeMap<WorktreeTransitionId, (WorktreeTransition, u64)>,
    value: WorktreeTransition,
    seq: u64,
) -> Result<(), StoreError> {
    match values.get(&value.worktree_transition_id) {
        None => {
            if value.transition_revision != 1 {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Some((current, _)) => {
            if current == &value {
                values.insert(value.worktree_transition_id, (value, seq));
                return Ok(());
            }
            // Corrections never rewrite in place: successor revision with an
            // exact predecessor reference, immutable participants and kind.
            let continuity_broken = value.transition_revision != current.transition_revision + 1
                || value.predecessor_revision != Some(current.transition_revision)
                || value.from_worktree_instance_id != current.from_worktree_instance_id
                || value.to_worktree_instance_id != current.to_worktree_instance_id
                || value.from_snapshot_id != current.from_snapshot_id
                || value.to_snapshot_id != current.to_snapshot_id
                || value.kind != current.kind
                || value.correction_reason.is_none()
                || value.source_watermark < current.source_watermark;
            if continuity_broken {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    values.insert(value.worktree_transition_id, (value, seq));
    Ok(())
}

pub(crate) fn replace_integration(
    values: &mut BTreeMap<IntegrationEventId, (IntegrationEvent, u64)>,
    value: IntegrationEvent,
    seq: u64,
) -> Result<(), StoreError> {
    if let Some((current, _)) = values.get(&value.integration_event_id)
        && current != &value
    {
        return Err(StoreError::StoreCorrupt);
    }
    values.insert(value.integration_event_id, (value, seq));
    Ok(())
}

fn prefix_of(
    previous: &[evertrace_domain::repository::PathObservation],
    next: &[evertrace_domain::repository::PathObservation],
) -> bool {
    next.len() >= previous.len() && next.starts_with(previous)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn row_id_prefixes_are_distinct() {
        let prefixes = [
            REPOSITORY_ROW_PREFIX,
            WORKTREE_ROW_PREFIX,
            SNAPSHOT_ROW_PREFIX,
            TRANSITION_ROW_PREFIX,
            INTEGRATION_ROW_PREFIX,
        ];
        let unique = prefixes.iter().collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), prefixes.len());
    }
}
