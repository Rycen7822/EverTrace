use std::collections::BTreeMap;

use evertrace_domain::{
    ids::AtomId,
    recall::{FutureCueContract, compile_atom_future_cue},
    semantic::{Atom, AtomScope},
};

use crate::{
    StoreError,
    objects::{ObjectRow, ObjectRowClass, ObjectRowKind},
};

pub(crate) const RECALL_TRIGGER_INDEX_KIND: &str = "recall_trigger_index";
const PROJECTION_GENERATION: u64 = 1;

pub(crate) fn rows(atoms: &BTreeMap<AtomId, (Atom, u64)>) -> Result<Vec<ObjectRow>, StoreError> {
    atoms
        .values()
        .filter_map(|(atom, source_event_seq)| {
            compile_atom_future_cue(atom, true, *source_event_seq)
                .ok()
                .map(|contract| row(atom, contract, *source_event_seq))
        })
        .collect()
}

pub(crate) fn contract(row: &ObjectRow) -> Result<Option<FutureCueContract>, StoreError> {
    if row.object_kind.as_deref() != Some(RECALL_TRIGGER_INDEX_KIND) {
        return Ok(None);
    }
    if row.row_kind != ObjectRowKind::Data
        || row.row_class != Some(ObjectRowClass::Projection)
        || row.object_family.is_some()
        || row.object_id.is_some()
        || row.lifecycle.as_deref() != Some("active")
        || row.authority.as_deref() != Some("user_explicit")
        || row.epistemic.is_some()
        || row.publication_state.is_some()
        || row.support_state.is_some()
        || row.project_id.is_some()
        || row.workstream_id.is_some()
        || row.session_id.is_some()
        || row.source_event_seq == 0
        || row.projection_generation != PROJECTION_GENERATION
        || !matches!(
            (
                row.task_id.as_ref(),
                row.repository_id.as_ref(),
                row.worktree_id.as_ref()
            ),
            (Some(_), None, None) | (None, Some(_), None) | (None, Some(_), Some(_))
        )
    {
        return Err(StoreError::StoreCorrupt);
    }
    let contract: FutureCueContract = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(StoreError::StoreCorrupt)?,
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    contract.validate().map_err(|_| StoreError::StoreCorrupt)?;
    if serde_json::to_string(&contract).map_err(|_| StoreError::StoreCorrupt)?
        != row
            .payload_json
            .as_deref()
            .ok_or(StoreError::StoreCorrupt)?
    {
        return Err(StoreError::StoreCorrupt);
    }
    if row.current_revision_id.as_deref() != Some(&contract.source_revision_id.to_string())
        || row.row_id != row_id(&contract.future_cue_contract_id)
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(Some(contract))
}

fn row(
    atom: &Atom,
    cue: FutureCueContract,
    source_event_seq: u64,
) -> Result<ObjectRow, StoreError> {
    let (repository_id, worktree_id, task_id) = match atom.scope {
        AtomScope::Task { task_id } => (None, None, Some(task_id.to_string())),
        AtomScope::Worktree {
            repository_instance_id,
            worktree_instance_id,
        } => (
            Some(repository_instance_id.to_string()),
            Some(worktree_instance_id.to_string()),
            None,
        ),
        AtomScope::Repository {
            repository_instance_id,
        } => (Some(repository_instance_id.to_string()), None, None),
        AtomScope::Global => (None, None, None),
    };
    let row = ObjectRow {
        row_id: row_id(&cue.future_cue_contract_id),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Projection),
        object_family: None,
        object_kind: Some(RECALL_TRIGGER_INDEX_KIND.into()),
        object_id: None,
        current_revision_id: Some(cue.source_revision_id.to_string()),
        lifecycle: Some("active".into()),
        epistemic: None,
        authority: Some(atom.authority.as_str().into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id,
        worktree_id,
        task_id,
        workstream_id: None,
        session_id: None,
        payload_json: Some(serde_json::to_string(&cue).map_err(|_| StoreError::Serialization)?),
        source_event_seq,
        projection_generation: PROJECTION_GENERATION,
    };
    contract(&row)?.ok_or(StoreError::StoreCorrupt)?;
    Ok(row)
}

fn row_id(id: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in id {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    format!("projection:recall_trigger:{encoded}")
}
