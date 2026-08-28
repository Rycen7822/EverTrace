//! Store-owned S16 current truth and immutable recovery revision reducers.

use std::{collections::BTreeMap, str::FromStr};

use evertrace_domain::{
    evidence::{
        EffectRole, ObservationRole, Operation, OperationKind, PairingState, ScopeEffect,
        SourceObservation, SourceReceipt,
    },
    ids::{
        AttemptId, CaptureReceiptId, CasId, CompetingAttemptGroupId, ExecutionLaneId, OperationId,
        RecoveryApplicationId, RecoveryBundleId, RecoveryCaptureRequestId, ScopeEffectId,
        SourceObservationId, SourceReceiptId, WorktreeId,
    },
    repository::{
        RecoveryApplication, RecoveryApplicationKind, RecoveryApplicationStatus, RecoveryBundle,
        RecoveryCaptureRequest, RecoveryInputDeliveryKind, RecoveryRequestStatus,
        SnapshotCaptureStatus, WorktreeInstance, WorktreeSnapshot,
    },
    revision::RevisionId,
    work::{
        Attempt, AttemptExecutionStatus, AttemptLifecycleStatus, CaptureReceipt,
        CompetingAttemptGroup, CompetingResolutionStatus, CoverageLevel, ExecutionLane,
        OrderingIntegrity as CaptureOrdering, PairingIntegrity, PayloadIntegrity, SourceCoverage,
    },
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
    pub applications: BTreeMap<RecoveryApplicationId, RecoveryApplication>,
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
        let mut application_revisions = BTreeMap::new();
        let mut operation_revisions = BTreeMap::new();
        let mut execution_lane_revisions = BTreeMap::new();
        let mut capture_receipt_revisions = BTreeMap::new();
        let mut scope_effects = BTreeMap::new();
        let mut source_observations = BTreeMap::new();
        let mut source_receipts = BTreeMap::new();
        let mut attempt_revisions = BTreeMap::new();
        let mut competing_group_revisions = BTreeMap::new();
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
                JournalPayload::RecoveryApplicationRecorded(value) => {
                    require_revision_row(
                        row,
                        "recovery_application_revision",
                        &value.recovery_application_id.to_string(),
                        &value.revision_id.to_string(),
                    )?;
                    if application_revisions
                        .insert(value.revision_id, (*value, row.source_event_seq))
                        .is_some()
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                JournalPayload::OperationDerived(value) => {
                    operation_revisions.insert(
                        (value.operation_id, value.operation_revision),
                        (*value, row.source_event_seq),
                    );
                }
                JournalPayload::ExecutionLaneRecorded(value) => {
                    execution_lane_revisions.insert(
                        (value.execution_lane_id, value.lane_revision),
                        (*value, row.source_event_seq),
                    );
                }
                JournalPayload::CaptureReceiptRecorded(value) => {
                    capture_receipt_revisions.insert(
                        value.capture_receipt_revision_id,
                        (*value, row.source_event_seq),
                    );
                }
                JournalPayload::ScopeEffectDerived(value) => {
                    scope_effects.insert(value.scope_effect_id, (*value, row.source_event_seq));
                }
                JournalPayload::SourceObservationRecorded(value) => {
                    source_observations
                        .insert(value.source_observation_id, (*value, row.source_event_seq));
                }
                JournalPayload::SourceReceiptRecorded(value) => {
                    source_receipts.insert(value.source_receipt_id, (*value, row.source_event_seq));
                }
                JournalPayload::AttemptRecorded(value) => {
                    attempt_revisions.insert(value.revision_id, (*value, row.source_event_seq));
                }
                JournalPayload::CompetingAttemptGroupRecorded(value) => {
                    competing_group_revisions
                        .insert(value.revision_id, (*value, row.source_event_seq));
                }
                _ => {}
            }
        }
        let mut requests = BTreeMap::new();
        rebuild_requests(&mut requests, &request_revisions, StoreError::StoreCorrupt)?;
        let mut applications = BTreeMap::new();
        rebuild_applications(
            &mut applications,
            &application_revisions,
            StoreError::StoreCorrupt,
        )?;
        let repository = crate::repository::RepositoryCurrentView::from_snapshot(snapshot)?;
        let worktrees = repository
            .worktrees
            .into_iter()
            .map(|(id, value)| (id, (value, snapshot.frontier)))
            .collect();
        let snapshots = repository
            .snapshots
            .into_iter()
            .map(|(id, value)| {
                let source_event_seq = snapshot
                    .data_rows()
                    .find(|row| {
                        row.object_kind.as_deref() == Some("worktree_snapshot")
                            && row.object_id.as_deref() == Some(id.to_string().as_str())
                    })
                    .map(|row| row.source_event_seq)
                    .ok_or(StoreError::StoreCorrupt)?;
                Ok((id, (value, source_event_seq)))
            })
            .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
        validate_relations(RecoveryRelationInputs {
            requests: &requests,
            bundles: &bundles,
            applications: &applications,
            application_revisions: &application_revisions,
            worktrees: &worktrees,
            snapshots: &snapshots,
            operation_revisions: &operation_revisions,
            execution_lane_revisions: &execution_lane_revisions,
            capture_receipt_revisions: &capture_receipt_revisions,
            scope_effects: &scope_effects,
            source_observations: &source_observations,
            source_receipts: &source_receipts,
            attempt_revisions: &attempt_revisions,
            competing_group_revisions: &competing_group_revisions,
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
                applications: applications
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

pub(super) fn record_application(
    applications: &mut BTreeMap<RecoveryApplicationId, (RecoveryApplication, u64)>,
    revisions: &mut BTreeMap<RevisionId, (RecoveryApplication, u64)>,
    value: RecoveryApplication,
    seq: u64,
    error: StoreError,
) -> Result<(), StoreError> {
    value.validate().map_err(|_| error)?;
    if revisions.contains_key(&value.revision_id) {
        return Err(error);
    }
    match applications.get(&value.recovery_application_id) {
        None if value.parent_revision_id.is_some() => return Err(error),
        None => {}
        Some((current, _)) if !value.is_successor_of(current) => return Err(error),
        Some(_) => {}
    }
    revisions.insert(value.revision_id, (value.clone(), seq));
    applications.insert(value.recovery_application_id, (value, seq));
    Ok(())
}

pub(super) fn rebuild_applications(
    current: &mut BTreeMap<RecoveryApplicationId, (RecoveryApplication, u64)>,
    revisions: &BTreeMap<RevisionId, (RecoveryApplication, u64)>,
    error: StoreError,
) -> Result<(), StoreError> {
    current.clear();
    let mut remaining = revisions.values().cloned().collect::<Vec<_>>();
    remaining.sort_by_key(|(_, seq)| *seq);
    for (value, seq) in remaining {
        match current.get(&value.recovery_application_id) {
            None if value.parent_revision_id.is_some() => return Err(error),
            None => {}
            Some((prior, _)) if !value.is_successor_of(prior) => return Err(error),
            Some(_) => {}
        }
        current.insert(value.recovery_application_id, (value, seq));
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
    pub applications: &'a BTreeMap<RecoveryApplicationId, (RecoveryApplication, u64)>,
    pub application_revisions: &'a BTreeMap<RevisionId, (RecoveryApplication, u64)>,
    pub worktrees: &'a BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
    pub snapshots: &'a BTreeMap<evertrace_domain::ids::WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
    pub operation_revisions: &'a BTreeMap<(OperationId, u32), (Operation, u64)>,
    pub execution_lane_revisions: &'a BTreeMap<(ExecutionLaneId, u32), (ExecutionLane, u64)>,
    pub capture_receipt_revisions: &'a BTreeMap<CaptureReceiptId, (CaptureReceipt, u64)>,
    pub scope_effects: &'a BTreeMap<ScopeEffectId, (ScopeEffect, u64)>,
    pub source_observations: &'a BTreeMap<SourceObservationId, (SourceObservation, u64)>,
    pub source_receipts: &'a BTreeMap<SourceReceiptId, (SourceReceipt, u64)>,
    pub attempt_revisions: &'a BTreeMap<RevisionId, (Attempt, u64)>,
    pub competing_group_revisions: &'a BTreeMap<RevisionId, (CompetingAttemptGroup, u64)>,
}

pub(super) fn validate_relations(inputs: RecoveryRelationInputs<'_>) -> Result<(), StoreError> {
    let RecoveryRelationInputs {
        requests,
        bundles,
        applications,
        application_revisions,
        worktrees,
        snapshots,
        operation_revisions,
        execution_lane_revisions,
        capture_receipt_revisions,
        scope_effects,
        source_observations,
        source_receipts,
        attempt_revisions,
        competing_group_revisions,
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
    for (bundle, bundle_seq) in bundles.values().map(|(value, seq)| (value, *seq)) {
        if !requests.values().any(|(request, _)| {
            request.recovery_bundle_id == Some(bundle.recovery_bundle_id)
                && request.request_status.is_terminal()
        }) {
            return Err(StoreError::StoreCorrupt);
        }
        let source_worktree = worktrees
            .get(&bundle.source_worktree_instance_id)
            .ok_or(StoreError::StoreCorrupt)?;
        let (source_snapshot, source_snapshot_seq) = snapshots
            .get(&bundle.source_snapshot_id)
            .ok_or(StoreError::StoreCorrupt)?;
        if !bundle.attempt_anchor_claims.is_empty()
            && (*source_snapshot_seq > bundle_seq
                || source_snapshot.worktree_instance_id != bundle.source_worktree_instance_id
                || source_snapshot.capture_status != SnapshotCaptureStatus::Complete
                || !source_snapshot.omission_reasons.is_empty()
                || !bundle.is_exact_patch_only_anchor_shape())
        {
            return Err(StoreError::StoreCorrupt);
        }
        let relevant = current_attempts_at(attempt_revisions, bundle_seq)
            .into_values()
            .filter(|attempt| {
                attempt.repository_instance_id == Some(source_worktree.0.repository_instance_id)
                    && attempt
                        .worktree_instance_ids
                        .contains(&bundle.source_worktree_instance_id)
                    && attempt.lifecycle_status == AttemptLifecycleStatus::Active
                    && matches!(
                        attempt.execution_status,
                        AttemptExecutionStatus::Proposed
                            | AttemptExecutionStatus::Active
                            | AttemptExecutionStatus::Interrupted
                    )
            })
            .map(|attempt| attempt.attempt_id)
            .collect::<Vec<_>>();
        if bundle.attempt_anchor_ids != relevant
            || bundle.attempt_anchor_claims.iter().any(|claim| {
                let Some((attempt, _)) = attempt_revisions.get(&claim.attempt_revision_id) else {
                    return true;
                };
                attempt.attempt_id != claim.attempt_id
                    || latest_attempt_revision_at(attempt_revisions, claim.attempt_id, bundle_seq)
                        != Some(claim.attempt_revision_id)
                    || attempt.strategy_contract_fingerprint != claim.strategy_contract_fingerprint
                    || attempt.repository_instance_id != Some(claim.source_repository_instance_id)
                    || !attempt
                        .worktree_instance_ids
                        .contains(&claim.source_worktree_instance_id)
                    || claim.source_worktree_instance_id != bundle.source_worktree_instance_id
                    || claim.source_snapshot_id != bundle.source_snapshot_id
                    || claim.source_repository_instance_id
                        != source_worktree.0.repository_instance_id
                    || claim
                        .competing_groups
                        .iter()
                        .map(|group| group.competing_group_id)
                        .collect::<Vec<_>>()
                        != attempt.competing_group_ids
                    || claim.competing_groups.iter().any(|group_claim| {
                        competing_group_revisions
                            .get(&group_claim.revision_id)
                            .is_none_or(|(group, seq)| {
                                *seq > bundle_seq
                                    || group.competing_group_id != group_claim.competing_group_id
                                    || group.resolution_status != group_claim.resolution_status
                                    || !group.member_attempt_ids.contains(&claim.attempt_id)
                                    || latest_group_revision_at(
                                        competing_group_revisions,
                                        group.competing_group_id,
                                        bundle_seq,
                                    ) != Some(group.revision_id)
                            })
                    })
            })
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    if applications.values().any(|(current, _)| {
        application_revisions
            .get(&current.revision_id)
            .is_none_or(|(revision, _)| revision != current)
    }) {
        return Err(StoreError::StoreCorrupt);
    }
    let mut admitted_revisions = BTreeMap::new();
    for revision in application_revisions
        .values()
        .map(|(value, _)| value)
        .filter(|value| value.parent_revision_id.is_none())
    {
        if admitted_revisions
            .insert(
                revision.recovery_application_id,
                revision.revision_id.to_string(),
            )
            .is_some()
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for (application, application_seq) in application_revisions
        .values()
        .map(|(value, seq)| (value, *seq))
    {
        let admitted_revision = admitted_revisions
            .get(&application.recovery_application_id)
            .ok_or(StoreError::StoreCorrupt)?
            .as_str();
        let bundle = &bundles
            .get(&application.recovery_bundle_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        if application.relevant_attempt_anchor_ids != bundle.attempt_anchor_ids
            || application.attempt_anchor_claims != bundle.attempt_anchor_claims
            || !application.attempt_anchor_claims.is_empty()
                && (!bundle.is_exact_patch_only_anchor_shape()
                    || application.application_kind != RecoveryApplicationKind::Patch
                    || application.input_delivery_kind != RecoveryInputDeliveryKind::PatchStdin
                    || bundle.tracked_diff_blob_refs.first().is_none_or(|content| {
                        cas_id(&content.payload.cas_ref).is_none_or(|selected| {
                            application.selected_cas_refs.as_slice() != [selected]
                        })
                    }))
        {
            return Err(StoreError::StoreCorrupt);
        }
        let target = &worktrees
            .get(&application.target_worktree_instance_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        let source = &worktrees
            .get(&bundle.source_worktree_instance_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        let pre = &snapshots
            .get(&application.pre_application_snapshot_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        if target.repository_instance_id != source.repository_instance_id
            || pre.worktree_instance_id != application.target_worktree_instance_id
            || application.post_application_snapshot_id.is_some_and(|id| {
                snapshots.get(&id).is_none_or(|(snapshot, _)| {
                    snapshot.worktree_instance_id != application.target_worktree_instance_id
                })
            })
        {
            return Err(StoreError::StoreCorrupt);
        }
        let available = bundle
            .tracked_diff_blob_refs
            .iter()
            .chain(&bundle.tracked_file_blob_refs)
            .chain(&bundle.index_state_refs)
            .chain(&bundle.untracked_file_blob_refs)
            .filter_map(|content| cas_id(&content.payload.cas_ref))
            .collect::<Vec<_>>();
        if application
            .selected_cas_refs
            .iter()
            .any(|id| !available.contains(id))
        {
            return Err(StoreError::StoreCorrupt);
        }
        if let (Some(operation_id), Some(operation_revision)) =
            (application.operation_id, application.operation_revision)
        {
            let operation = &operation_revisions
                .get(&(operation_id, operation_revision))
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            let lane_id = application
                .execution_lane_id
                .ok_or(StoreError::StoreCorrupt)?;
            let receipt = &capture_receipt_revisions
                .get(
                    &application
                        .capture_receipt_revision_id
                        .ok_or(StoreError::StoreCorrupt)?,
                )
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            let matching_lanes = execution_lane_revisions
                .values()
                .filter(|(lane, _)| {
                    lane.execution_lane_id == lane_id
                        && lane.active_capture_receipt_revision_id
                            == receipt.capture_receipt_revision_id
                })
                .map(|(lane, _)| lane)
                .collect::<Vec<_>>();
            let [lane] = matching_lanes.as_slice() else {
                return Err(StoreError::StoreCorrupt);
            };
            if operation.execution_lane_id != Some(lane_id)
                || operation.operation_kind != OperationKind::Mutate
                || operation.pairing_state != PairingState::Paired
                || !lane.operation_ids.contains(&operation_id)
                || receipt.execution_lane_id != lane_id
                || operation.scope_effect_ids != application.scope_effect_ids
                || operation.input_source_observation_refs
                    != application.input_source_observation_ids
                || operation.result_source_observation_refs
                    != application.result_source_observation_ids
                || application.scope_effect_ids.iter().any(|id| {
                    scope_effects.get(id).is_none_or(|(effect, _)| {
                        effect.operation_id != operation_id
                            || effect.effect_role != EffectRole::Mutate
                            || effect.repository_instance_id != Some(target.repository_instance_id)
                            || effect.worktree_instance_id
                                != Some(application.target_worktree_instance_id)
                            || effect.pre_snapshot_id
                                != Some(application.pre_application_snapshot_id)
                            || effect.post_snapshot_id.is_some_and(|id| {
                                Some(id) != application.post_application_snapshot_id
                            })
                    })
                })
                || application.input_source_observation_ids.iter().any(|id| {
                    source_observations.get(id).is_none_or(|(observation, _)| {
                        observation.observation_role != ObservationRole::Intent
                            || observation.correlation.strong_gate_receipt_ref.as_deref()
                                != Some(admitted_revision)
                            || source_receipts
                                .get(&observation.source_receipt_ref)
                                .is_none_or(|(receipt, _)| {
                                    receipt.source_observation_id != *id
                                        || cas_id(&receipt.cas_ref).is_none_or(|cas| {
                                            !application.selected_cas_refs.contains(&cas)
                                        })
                                })
                    })
                })
                || application.result_source_observation_ids.iter().any(|id| {
                    source_observations.get(id).is_none_or(|(observation, _)| {
                        observation.observation_role != ObservationRole::Result
                            || observation.correlation.strong_gate_receipt_ref.as_deref()
                                != Some(admitted_revision)
                    })
                })
            {
                return Err(StoreError::StoreCorrupt);
            }
            if application.application_status != RecoveryApplicationStatus::Unknown
                && (lane.coverage_level != CoverageLevel::Full
                    || lane.source_coverage != SourceCoverage::Complete
                    || lane.pairing_integrity != PairingIntegrity::Complete
                    || lane.payload_integrity != PayloadIntegrity::Complete
                    || lane.ordering_integrity != CaptureOrdering::Complete
                    || receipt.coverage_level != CoverageLevel::Full
                    || receipt.source_coverage != SourceCoverage::Complete
                    || receipt.pairing_integrity != PairingIntegrity::Complete
                    || receipt.payload_integrity != PayloadIntegrity::Complete
                    || receipt.ordering_integrity != CaptureOrdering::Complete
                    || application
                        .post_application_snapshot_id
                        .is_none_or(|post_id| {
                            snapshots.get(&post_id).is_none_or(|(post, _)| {
                                post.worktree_instance_id != application.target_worktree_instance_id
                                    || post.capture_status != SnapshotCaptureStatus::Complete
                                    || !post.omission_reasons.is_empty()
                            })
                        })
                    || !application.scope_effect_ids.iter().any(|id| {
                        scope_effects.get(id).is_some_and(|(effect, _)| {
                            effect.effect_role == EffectRole::Mutate
                                && effect.pre_snapshot_id
                                    == Some(application.pre_application_snapshot_id)
                                && effect.post_snapshot_id
                                    == application.post_application_snapshot_id
                                && effect.evidence_refs.iter().any(|id| {
                                    application.result_source_observation_ids.contains(id)
                                })
                        })
                    }))
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if application.verifier_receipts.iter().any(|receipt| {
            receipt.verifier_version != 1
                || application.result_source_observation_ids.as_slice()
                    != [receipt.result_source_observation_id]
                || application.post_application_snapshot_id
                    != Some(receipt.post_application_snapshot_id)
                || !source_observations.contains_key(&receipt.result_source_observation_id)
                || !snapshots.contains_key(&receipt.post_application_snapshot_id)
        }) {
            return Err(StoreError::StoreCorrupt);
        }
        if application.anchor_verifier_receipts.iter().any(|receipt| {
            let Some((source_attempt, _)) =
                attempt_revisions.get(&receipt.source_attempt_revision_id)
            else {
                return true;
            };
            let Some((current_attempt, current_seq)) =
                attempt_revisions.get(&receipt.revalidated_attempt_revision_id)
            else {
                return true;
            };
            source_attempt.attempt_id != receipt.attempt_id
                || current_attempt.attempt_id != receipt.attempt_id
                || *current_seq > application_seq
                || receipt.source_repository_instance_id != source.repository_instance_id
                || receipt.target_repository_instance_id != target.repository_instance_id
                || receipt.target_worktree_instance_id != application.target_worktree_instance_id
                || current_attempt.repository_instance_id
                    != Some(receipt.source_repository_instance_id)
                || !current_attempt
                    .worktree_instance_ids
                    .contains(&receipt.source_worktree_instance_id)
                || latest_attempt_revision_at(
                    attempt_revisions,
                    receipt.attempt_id,
                    application_seq,
                ) != Some(receipt.revalidated_attempt_revision_id)
                || source_attempt.strategy_contract_fingerprint
                    != receipt.strategy_contract_fingerprint
                || current_attempt.strategy_contract_fingerprint
                    != receipt.strategy_contract_fingerprint
                || current_attempt.lifecycle_status != AttemptLifecycleStatus::Active
                || matches!(
                    current_attempt.execution_status,
                    AttemptExecutionStatus::Completed | AttemptExecutionStatus::Abandoned
                )
                || receipt
                    .revalidated_competing_groups
                    .iter()
                    .map(|group| group.competing_group_id)
                    .collect::<Vec<_>>()
                    != current_attempt.competing_group_ids
                || receipt
                    .revalidated_competing_groups
                    .iter()
                    .any(|group_claim| {
                        competing_group_revisions
                            .get(&group_claim.revision_id)
                            .is_none_or(|(group, seq)| {
                                *seq > application_seq
                                    || group.competing_group_id != group_claim.competing_group_id
                                    || group.resolution_status != group_claim.resolution_status
                                    || group.resolution_status
                                        != CompetingResolutionStatus::Selected
                                    || group.selected_attempt_id != Some(receipt.attempt_id)
                                    || !group.member_attempt_ids.contains(&receipt.attempt_id)
                                    || latest_group_revision_at(
                                        competing_group_revisions,
                                        group.competing_group_id,
                                        application_seq,
                                    ) != Some(group.revision_id)
                            })
                    })
        }) {
            return Err(StoreError::StoreCorrupt);
        }
    }
    Ok(())
}

fn cas_id(value: &str) -> Option<CasId> {
    CasId::from_str(if value.starts_with("cas:") {
        value
    } else {
        return CasId::from_str(&format!("cas:{value}")).ok();
    })
    .ok()
}

fn current_attempts_at(
    revisions: &BTreeMap<RevisionId, (Attempt, u64)>,
    frontier: u64,
) -> BTreeMap<AttemptId, Attempt> {
    let mut current = BTreeMap::<AttemptId, (Attempt, u64)>::new();
    for (attempt, seq) in revisions.values().filter(|(_, seq)| *seq <= frontier) {
        let replace = current
            .get(&attempt.attempt_id)
            .is_none_or(|(_, current_seq)| *current_seq < *seq);
        if replace {
            current.insert(attempt.attempt_id, (attempt.clone(), *seq));
        }
    }
    current
        .into_iter()
        .map(|(id, (attempt, _))| (id, attempt))
        .collect()
}

fn latest_attempt_revision_at(
    revisions: &BTreeMap<RevisionId, (Attempt, u64)>,
    attempt_id: AttemptId,
    frontier: u64,
) -> Option<RevisionId> {
    revisions
        .values()
        .filter(|(attempt, seq)| attempt.attempt_id == attempt_id && *seq <= frontier)
        .max_by_key(|(_, seq)| *seq)
        .map(|(attempt, _)| attempt.revision_id)
}

fn latest_group_revision_at(
    revisions: &BTreeMap<RevisionId, (CompetingAttemptGroup, u64)>,
    group_id: CompetingAttemptGroupId,
    frontier: u64,
) -> Option<RevisionId> {
    revisions
        .values()
        .filter(|(group, seq)| group.competing_group_id == group_id && *seq <= frontier)
        .max_by_key(|(_, seq)| *seq)
        .map(|(group, _)| group.revision_id)
}

pub(super) fn revision_rows(
    request_revisions: BTreeMap<RevisionId, (RecoveryCaptureRequest, u64)>,
    bundles: BTreeMap<RecoveryBundleId, (RecoveryBundle, u64)>,
    application_revisions: BTreeMap<RevisionId, (RecoveryApplication, u64)>,
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
    for (_, (value, seq)) in application_revisions {
        let mut row = physical_object_row(
            ObjectFamily::Work,
            "recovery_application_revision",
            value.recovery_application_id.to_string(),
            value.revision_id.to_string(),
            &JournalPayload::RecoveryApplicationRecorded(Box::new(value)),
            seq,
        )?;
        row.row_id = format!(
            "object:work:recovery_application_revision:{}",
            row.current_revision_id
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?
        );
        rows.push(row);
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
