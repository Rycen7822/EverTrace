//! Store-owned S16 current truth and immutable recovery revision reducers.

use std::collections::BTreeMap;

use evertrace_domain::{
    ids::{RecoveryBundleId, RecoveryCaptureRequestId, WorktreeId},
    repository::{
        RecoveryBundle, RecoveryCaptureRequest, RecoveryRequestStatus, WorktreeInstance,
        WorktreeSnapshot,
    },
    revision::RevisionId,
};

use crate::{
    command::{JournalPayload, ObjectFamily, StoreError},
    objects::ObjectRow,
};

use super::{ProjectionSnapshot, physical_object_row};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveryCurrentState {
    pub requests: BTreeMap<RecoveryCaptureRequestId, RecoveryCaptureRequest>,
    pub bundles: BTreeMap<RecoveryBundleId, RecoveryBundle>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveryCurrentView {
    pub frontier: u64,
    pub state: RecoveryCurrentState,
}

impl RecoveryCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut request_revisions = BTreeMap::new();
        let mut bundles = BTreeMap::new();
        for row in snapshot.data_rows() {
            let Some(payload_json) = row.payload_json.as_deref() else {
                continue;
            };
            let payload: JournalPayload =
                serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
            match payload {
                JournalPayload::RecoveryCaptureRequestRecorded(value) => {
                    require_revision_row(
                        row,
                        "recovery_capture_request_revision",
                        &value.recovery_capture_request_id.to_string(),
                        &value.request_revision_id.to_string(),
                    )?;
                    if request_revisions
                        .insert(value.request_revision_id, (*value, row.source_event_seq))
                        .is_some()
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                JournalPayload::RecoveryBundleRecorded(value) => {
                    require_revision_row(
                        row,
                        "recovery_bundle",
                        &value.recovery_bundle_id.to_string(),
                        &value.recovery_bundle_id.to_string(),
                    )?;
                    if bundles
                        .insert(value.recovery_bundle_id, (*value, row.source_event_seq))
                        .is_some()
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                _ => {}
            }
        }
        let mut requests = BTreeMap::new();
        rebuild_requests(&mut requests, &request_revisions, StoreError::StoreCorrupt)?;
        let repository = crate::repository::RepositoryCurrentView::from_snapshot(snapshot)?;
        let worktrees = repository
            .worktrees
            .into_iter()
            .map(|(id, value)| (id, (value, snapshot.frontier)))
            .collect();
        let snapshots = repository
            .snapshots
            .into_iter()
            .map(|(id, value)| (id, (value, snapshot.frontier)))
            .collect();
        validate_relations(RecoveryRelationInputs {
            requests: &requests,
            bundles: &bundles,
            worktrees: &worktrees,
            snapshots: &snapshots,
        })?;
        Ok(Self {
            frontier: snapshot.frontier,
            state: RecoveryCurrentState {
                requests: requests
                    .into_iter()
                    .map(|(key, (value, _))| (key, value))
                    .collect(),
                bundles: bundles
                    .into_iter()
                    .map(|(key, (value, _))| (key, value))
                    .collect(),
            },
        })
    }

    pub fn terminal_request(
        &self,
        id: RecoveryCaptureRequestId,
    ) -> Option<&RecoveryCaptureRequest> {
        self.state
            .requests
            .get(&id)
            .filter(|value| value.request_status.is_terminal())
    }
}

pub(super) fn record_request(
    requests: &mut BTreeMap<RecoveryCaptureRequestId, (RecoveryCaptureRequest, u64)>,
    revisions: &mut BTreeMap<RevisionId, (RecoveryCaptureRequest, u64)>,
    value: RecoveryCaptureRequest,
    seq: u64,
    error: StoreError,
) -> Result<(), StoreError> {
    value.validate().map_err(|_| error)?;
    if revisions.contains_key(&value.request_revision_id) {
        return Err(error);
    }
    match requests.get(&value.recovery_capture_request_id) {
        None if value.request_status != RecoveryRequestStatus::Pending => return Err(error),
        None => {}
        Some((current, _)) if !value.is_successor_of(current) => return Err(error),
        Some(_) => {}
    }
    revisions.insert(value.request_revision_id, (value.clone(), seq));
    requests.insert(value.recovery_capture_request_id, (value, seq));
    Ok(())
}

pub(super) fn record_bundle(
    bundles: &mut BTreeMap<RecoveryBundleId, (RecoveryBundle, u64)>,
    value: RecoveryBundle,
    seq: u64,
    error: StoreError,
) -> Result<(), StoreError> {
    value.validate().map_err(|_| error)?;
    if bundles
        .insert(value.recovery_bundle_id, (value, seq))
        .is_some()
    {
        return Err(error);
    }
    Ok(())
}

pub(super) fn rebuild_requests(
    current: &mut BTreeMap<RecoveryCaptureRequestId, (RecoveryCaptureRequest, u64)>,
    revisions: &BTreeMap<RevisionId, (RecoveryCaptureRequest, u64)>,
    error: StoreError,
) -> Result<(), StoreError> {
    current.clear();
    let mut remaining = revisions.values().cloned().collect::<Vec<_>>();
    remaining.sort_by_key(|(_, seq)| *seq);
    for (value, seq) in remaining {
        record_current_request(current, value, seq, error)?;
    }
    Ok(())
}

fn record_current_request(
    current: &mut BTreeMap<RecoveryCaptureRequestId, (RecoveryCaptureRequest, u64)>,
    value: RecoveryCaptureRequest,
    seq: u64,
    error: StoreError,
) -> Result<(), StoreError> {
    match current.get(&value.recovery_capture_request_id) {
        None if value.request_status != RecoveryRequestStatus::Pending => return Err(error),
        None => {}
        Some((prior, _)) if !value.is_successor_of(prior) => return Err(error),
        Some(_) => {}
    }
    current.insert(value.recovery_capture_request_id, (value, seq));
    Ok(())
}

pub(super) struct RecoveryRelationInputs<'a> {
    pub requests: &'a BTreeMap<RecoveryCaptureRequestId, (RecoveryCaptureRequest, u64)>,
    pub bundles: &'a BTreeMap<RecoveryBundleId, (RecoveryBundle, u64)>,
    pub worktrees: &'a BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
    pub snapshots: &'a BTreeMap<evertrace_domain::ids::WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
}

pub(super) fn validate_relations(inputs: RecoveryRelationInputs<'_>) -> Result<(), StoreError> {
    let RecoveryRelationInputs {
        requests,
        bundles,
        worktrees,
        snapshots,
    } = inputs;
    for request in requests.values().map(|(value, _)| value) {
        let worktree = worktrees
            .get(&request.worktree_instance_id)
            .ok_or(StoreError::StoreCorrupt)?;
        if worktree.0.repository_instance_id != request.repository_instance_id {
            return Err(StoreError::StoreCorrupt);
        }
        if let Some(snapshot_id) = request.pre_operation_snapshot_id {
            if let Some((snapshot, _)) = snapshots.get(&snapshot_id) {
                if snapshot.worktree_instance_id != request.worktree_instance_id {
                    return Err(StoreError::StoreCorrupt);
                }
            } else {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if let Some(bundle_id) = request.recovery_bundle_id {
            let bundle = bundles
                .get(&bundle_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0
                .clone();
            if !bundle
                .trigger_request_ids
                .contains(&request.recovery_capture_request_id)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    for bundle in bundles.values().map(|(value, _)| value) {
        if !requests.values().any(|(request, _)| {
            request.recovery_bundle_id == Some(bundle.recovery_bundle_id)
                && request.request_status.is_terminal()
        }) {
            return Err(StoreError::StoreCorrupt);
        }
    }
    Ok(())
}

pub(super) fn revision_rows(
    request_revisions: BTreeMap<RevisionId, (RecoveryCaptureRequest, u64)>,
    bundles: BTreeMap<RecoveryBundleId, (RecoveryBundle, u64)>,
) -> Result<Vec<ObjectRow>, StoreError> {
    let mut rows = Vec::new();
    for (_, (value, seq)) in request_revisions {
        let mut row = physical_object_row(
            ObjectFamily::Work,
            "recovery_capture_request_revision",
            value.recovery_capture_request_id.to_string(),
            value.request_revision_id.to_string(),
            &JournalPayload::RecoveryCaptureRequestRecorded(Box::new(value)),
            seq,
        )?;
        row.row_id = format!(
            "object:work:recovery_capture_request_revision:{}",
            row.current_revision_id
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?
        );
        rows.push(row);
    }
    for (id, (value, seq)) in bundles {
        rows.push(physical_object_row(
            ObjectFamily::Work,
            "recovery_bundle",
            id.to_string(),
            id.to_string(),
            &JournalPayload::RecoveryBundleRecorded(Box::new(value)),
            seq,
        )?);
    }
    Ok(rows)
}

pub(super) fn require_revision_row(
    row: &ObjectRow,
    kind: &str,
    object_id: &str,
    revision_id: &str,
) -> Result<(), StoreError> {
    if row.object_family != Some(ObjectFamily::Work)
        || row.row_id != format!("object:work:{kind}:{revision_id}")
        || row.object_kind.as_deref() != Some(kind)
        || row.object_id.as_deref() != Some(object_id)
        || row.current_revision_id.as_deref() != Some(revision_id)
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}
