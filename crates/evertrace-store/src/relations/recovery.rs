//! Pure S16 recovery relation DTOs; no third production table is created.

use std::collections::BTreeSet;

use evertrace_domain::repository::{RecoveryApplication, RecoveryBundle, RecoveryCaptureRequest};
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
    BundleToAttemptAnchor,
    ApplicationToBundle,
    ApplicationToWorktree,
    ApplicationToPreSnapshot,
    ApplicationToPostSnapshot,
    ApplicationToOperation,
    ApplicationToExecutionLane,
    ApplicationToCaptureReceipt,
    ApplicationToScopeEffect,
    ApplicationToInputObservation,
    ApplicationToResultObservation,
    ApplicationToAttemptAnchor,
}

pub fn build_recovery_application_relation_rows(
    applications: &[RecoveryApplication],
) -> Result<Vec<RecoveryRelationRow>, StoreError> {
    let ids = applications
        .iter()
        .map(|value| value.recovery_application_id)
        .collect::<BTreeSet<_>>();
    if ids.len() != applications.len() {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for application in applications {
        application
            .validate()
            .map_err(|_| StoreError::InvalidInput)?;
        let source = application.recovery_application_id.to_string();
        add(
            &mut rows,
            RecoveryRelationKind::ApplicationToBundle,
            source.clone(),
            application.recovery_bundle_id.to_string(),
        );
        add(
            &mut rows,
            RecoveryRelationKind::ApplicationToWorktree,
            source.clone(),
            application.target_worktree_instance_id.to_string(),
        );
        add(
            &mut rows,
            RecoveryRelationKind::ApplicationToPreSnapshot,
            source.clone(),
            application.pre_application_snapshot_id.to_string(),
        );
        if let Some(id) = application.post_application_snapshot_id {
            add(
                &mut rows,
                RecoveryRelationKind::ApplicationToPostSnapshot,
                source.clone(),
                id.to_string(),
            );
        }
        for (kind, target) in [
            (
                RecoveryRelationKind::ApplicationToOperation,
                application.operation_id.map(|id| id.to_string()),
            ),
            (
                RecoveryRelationKind::ApplicationToExecutionLane,
                application.execution_lane_id.map(|id| id.to_string()),
            ),
            (
                RecoveryRelationKind::ApplicationToCaptureReceipt,
                application
                    .capture_receipt_revision_id
                    .map(|id| id.to_string()),
            ),
        ] {
            if let Some(target) = target {
                add(&mut rows, kind, source.clone(), target);
            }
        }
        for (kind, targets) in [
            (
                RecoveryRelationKind::ApplicationToScopeEffect,
                application
                    .scope_effect_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
            (
                RecoveryRelationKind::ApplicationToInputObservation,
                application
                    .input_source_observation_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
            (
                RecoveryRelationKind::ApplicationToResultObservation,
                application
                    .result_source_observation_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
        ] {
            for target in targets {
                add(&mut rows, kind, source.clone(), target);
            }
        }
        for receipt in &application.anchor_verifier_receipts {
            add(
                &mut rows,
                RecoveryRelationKind::ApplicationToAttemptAnchor,
                source.clone(),
                receipt.attempt_id.to_string(),
            );
        }
    }
    Ok(rows.into_iter().collect())
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
        for claim in &bundle.attempt_anchor_claims {
            add(
                &mut rows,
                RecoveryRelationKind::BundleToAttemptAnchor,
                bundle.recovery_bundle_id.to_string(),
                claim.attempt_id.to_string(),
            );
        }
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
