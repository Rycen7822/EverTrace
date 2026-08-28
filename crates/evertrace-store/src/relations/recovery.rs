//! Pure S16 recovery relation DTOs; no third production table is created.

use std::collections::BTreeSet;

use evertrace_domain::repository::{RecoveryBundle, RecoveryCaptureRequest};
use serde::{Deserialize, Serialize};

use crate::StoreError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRelationKind {
    RequestToWorktree,
    RequestToSnapshot,
    RequestToBundle,
    BundleToWorktree,
    BundleToSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRelationRow {
    pub kind: RecoveryRelationKind,
    pub source_id: String,
    pub target_id: String,
}

pub fn build_recovery_relation_rows(
    requests: &[RecoveryCaptureRequest],
    bundles: &[RecoveryBundle],
) -> Result<Vec<RecoveryRelationRow>, StoreError> {
    let request_ids = requests
        .iter()
        .map(|value| value.recovery_capture_request_id)
        .collect::<BTreeSet<_>>();
    let bundle_ids = bundles
        .iter()
        .map(|value| value.recovery_bundle_id)
        .collect::<BTreeSet<_>>();
    if request_ids.len() != requests.len() || bundle_ids.len() != bundles.len() {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for request in requests {
        request.validate().map_err(|_| StoreError::InvalidInput)?;
        add(
            &mut rows,
            RecoveryRelationKind::RequestToWorktree,
            request.recovery_capture_request_id.to_string(),
            request.worktree_instance_id.to_string(),
        );
        if let Some(snapshot_id) = request.pre_operation_snapshot_id {
            add(
                &mut rows,
                RecoveryRelationKind::RequestToSnapshot,
                request.recovery_capture_request_id.to_string(),
                snapshot_id.to_string(),
            );
        }
        if let Some(bundle_id) = request.recovery_bundle_id {
            if !bundle_ids.contains(&bundle_id) {
                return Err(StoreError::InvalidInput);
            }
            add(
                &mut rows,
                RecoveryRelationKind::RequestToBundle,
                request.recovery_capture_request_id.to_string(),
                bundle_id.to_string(),
            );
        }
    }
    for bundle in bundles {
        bundle.validate().map_err(|_| StoreError::InvalidInput)?;
        if bundle
            .trigger_request_ids
            .iter()
            .any(|id| !request_ids.contains(id))
        {
            return Err(StoreError::InvalidInput);
        }
        add(
            &mut rows,
            RecoveryRelationKind::BundleToWorktree,
            bundle.recovery_bundle_id.to_string(),
            bundle.source_worktree_instance_id.to_string(),
        );
        add(
            &mut rows,
            RecoveryRelationKind::BundleToSnapshot,
            bundle.recovery_bundle_id.to_string(),
            bundle.source_snapshot_id.to_string(),
        );
    }
    Ok(rows.into_iter().collect())
}

fn add(
    rows: &mut BTreeSet<RecoveryRelationRow>,
    kind: RecoveryRelationKind,
    source_id: String,
    target_id: String,
) {
    rows.insert(RecoveryRelationRow {
        kind,
        source_id,
        target_id,
    });
}
