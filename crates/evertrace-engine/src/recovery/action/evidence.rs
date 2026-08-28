use std::str::FromStr;

use evertrace_capture::{
    CaptureOutcome, CaptureRecordInput, CaptureRuntime, CasDigest, CasStore, ConfinedFileIdentity,
};
use evertrace_codex::{
    adapter_manifest::{
        AdapterCapabilityManifest, AdapterKind,
        AdmissionFailureObservability as ManifestObservability, CaptureGuarantee, CueBoundary,
        EventIdentity, ObservableCapability, RecoveryOrdering, SubagentTrace, TrustReadback,
    },
    capability::{McpBindingMechanism, McpSessionBinding},
    source_catalog::REQUIRED_FOR_FULL,
};
use evertrace_domain::{
    evidence::{
        CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
        CorrelationField, CorrelationFieldClaim, EffectRole, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, PairingState, ScopeEffectClaim,
        SourceInstanceId, SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole,
        source_observation_id,
    },
    ids::{CommandId, SourceObservationId},
    repository::{
        RECOVERY_ANCHOR_VERIFIER_VERSION, RecoveryAnchorVerifierReceipt, RecoveryApplication,
        RecoveryApplicationStatus, RecoveryCompetingGroupClaim, RecoveryInputDeliveryState,
        RecoveryVerificationOutcome, RecoveryVerifierReceipt, SnapshotCaptureStatus,
    },
    revision::RevisionId,
    work::{
        AttemptExecutionStatus, AttemptLifecycleStatus, CompetingAttemptGroup,
        CompetingResolutionStatus, LaneLifecycleEvidence, LivenessState, TerminalKind,
    },
};
use evertrace_store::{
    projections::{AttemptCurrentView, RecoveryEvidenceCurrentView, SegmentationCurrentView},
    repository::RepositoryCurrentView,
};

use super::{
    ACTION_ALGORITHM_REVISION, PreparedPatch, RecoveryActionOutcome, RecoveryActionService,
    RecoveryError, RecoveryRequest, application_command,
};
use crate::{
    EvidenceIngestor,
    capture::{ReconcileInput, reconcile_observations_once},
    recovery::barrier::current_time_us,
};

const ELIGIBLE_EVENTS: &str = "evertrace_recovery_supervisor_events_v1";

pub(super) fn current_lineage_transfer_supported(
    application: &RecoveryApplication,
    attempts: &AttemptCurrentView,
) -> bool {
    application.has_complete_recorded_lineage_transfer_receipts()
        && application.anchor_verifier_receipts.iter().all(|receipt| {
            let Some(attempt) = attempts.attempts.get(&receipt.attempt_id) else {
                return false;
            };
            attempt.revision_id == receipt.revalidated_attempt_revision_id
                && attempt.strategy_contract_fingerprint == receipt.strategy_contract_fingerprint
                && attempt.lifecycle_status == AttemptLifecycleStatus::Active
                && matches!(
                    attempt.execution_status,
                    AttemptExecutionStatus::Proposed
                        | AttemptExecutionStatus::Active
                        | AttemptExecutionStatus::Interrupted
                )
                && attempt.competing_group_ids
                    == receipt
                        .revalidated_competing_groups
                        .iter()
                        .map(|group| group.competing_group_id)
                        .collect::<Vec<_>>()
                && receipt.revalidated_competing_groups.iter().all(|claim| {
                    attempts
                        .competing_groups
                        .get(&claim.competing_group_id)
                        .is_some_and(|group| {
                            current_group_authorizes_attempt(
                                group,
                                receipt.attempt_id,
                                claim.revision_id,
                            )
                        })
                })
        })
}

fn current_group_authorizes_attempt(
    group: &CompetingAttemptGroup,
    attempt_id: evertrace_domain::ids::AttemptId,
    expected_revision_id: RevisionId,
) -> bool {
    group.revision_id == expected_revision_id
        && group.resolution_status == CompetingResolutionStatus::Selected
        && group.selected_attempt_id == Some(attempt_id)
        && group.member_attempt_ids.contains(&attempt_id)
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalEvidence {
    schema_version: u16,
    verifier_version: u16,
    normal_exit: bool,
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    cancelled: bool,
    truncated: bool,
    io_error: bool,
    supervised: bool,
    affected_file_identity: Option<TerminalAffectedFileIdentity>,
    verifier_outcome: Option<RecoveryVerificationOutcome>,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TerminalAffectedFileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mtime_seconds: i64,
    mtime_nanoseconds: u64,
    ctime_seconds: i64,
    ctime_nanoseconds: u64,
}

impl From<ConfinedFileIdentity> for TerminalAffectedFileIdentity {
    fn from(value: ConfinedFileIdentity) -> Self {
        Self {
            device: value.device,
            inode: value.inode,
            size: value.size,
            mtime_seconds: value.mtime_seconds,
            mtime_nanoseconds: value.mtime_nanoseconds,
            ctime_seconds: value.ctime_seconds,
            ctime_nanoseconds: value.ctime_nanoseconds,
        }
    }
}

impl TerminalAffectedFileIdentity {
    pub(super) fn matches(self, value: ConfinedFileIdentity) -> bool {
        self == Self::from(value)
    }
}

impl TerminalEvidence {
    fn authoritative_outcome(&self) -> Result<Option<RecoveryVerificationOutcome>, RecoveryError> {
        let abnormal = self.timed_out
            || self.cancelled
            || self.signal.is_some()
            || self.truncated
            || self.io_error;
        let expected_normal = !abnormal && self.exit_code.is_some();
        if self.schema_version != 1
            || self.verifier_version != 1
            || !self.supervised
            || self.normal_exit != expected_normal
            || abnormal && self.verifier_outcome.is_some()
            || self.verifier_outcome.is_some() && self.affected_file_identity.is_none()
        {
            return Err(RecoveryError::InvalidSuccessor);
        }
        match self.verifier_outcome {
            Some(RecoveryVerificationOutcome::Applied)
                if self.normal_exit && self.exit_code == Some(0) =>
            {
                Ok(self.verifier_outcome)
            }
            Some(RecoveryVerificationOutcome::NotApplied)
                if self.normal_exit && self.exit_code.is_some_and(|code| code != 0) =>
            {
                Ok(self.verifier_outcome)
            }
            Some(RecoveryVerificationOutcome::PartiallyApplied) if self.normal_exit => {
                Ok(self.verifier_outcome)
            }
            None => Ok(None),
            Some(_) => Err(RecoveryError::InvalidSuccessor),
        }
    }
}

impl RecoveryActionService {
    pub(super) fn capture_intent_frame(
        &self,
        request: &RecoveryRequest,
        admitted: &RecoveryApplication,
        prepared: &PreparedPatch,
    ) -> Result<(), RecoveryError> {
        #[cfg(test)]
        if self.take_test_fault(super::TestFault::IntentPersistence) {
            return Err(RecoveryError::Store);
        }
        let manifest = recovery_manifest()?;
        let CaptureOutcome::Durable { cas_digest, .. } =
            CaptureRuntime::open(self.snapshot.clone())
                .map_err(|_| RecoveryError::Store)?
                .capture(action_capture_input(
                    request,
                    admitted,
                    prepared,
                    None,
                    FrameFacts {
                        record: "patch-stdin",
                        role: ObservationRole::Intent,
                        sequence: 1,
                        bytes: &prepared.patch,
                        event_time_us: current_time_us(),
                        terminal_kind: None,
                        manifest_ref: &manifest.adapter_manifest_id,
                    },
                )?)
                .map_err(|_| RecoveryError::Store)?
        else {
            return Err(RecoveryError::Store);
        };
        if cas_digest != prepared.claims.selected_content_refs[0].payload.cas_ref {
            return Err(RecoveryError::InvalidInput);
        }
        Ok(())
    }

    pub(super) async fn persist_terminal_evidence(
        &self,
        request: &RecoveryRequest,
        admitted: &RecoveryApplication,
        prepared: &PreparedPatch,
        terminal: super::TerminalCaptureOutcome,
    ) -> Result<RecoveryActionOutcome, RecoveryError> {
        let manifest = recovery_manifest()?;
        let now = current_time_us();
        let super::TerminalCaptureOutcome {
            post_snapshot_id,
            affected_file_identity,
            execution,
            verification,
        } = terminal;
        let terminal_kind = if execution.timed_out {
            TerminalKind::Timeout
        } else if execution.cancelled {
            TerminalKind::Cancelled
        } else if execution.io_error || execution.truncated || execution.signal.is_some() {
            TerminalKind::Crashed
        } else {
            TerminalKind::Normal
        };
        let result_payload = terminal_payload(execution, affected_file_identity, verification)?;
        let CaptureOutcome::Durable { .. } = CaptureRuntime::open(self.snapshot.clone())
            .map_err(|_| RecoveryError::Store)?
            .capture(action_capture_input(
                request,
                admitted,
                prepared,
                post_snapshot_id,
                FrameFacts {
                    record: "patch-result",
                    role: ObservationRole::Result,
                    sequence: 2,
                    bytes: &result_payload,
                    event_time_us: now,
                    terminal_kind: Some(terminal_kind),
                    manifest_ref: &manifest.adapter_manifest_id,
                },
            )?)
            .map_err(|_| RecoveryError::Store)?
        else {
            return Err(RecoveryError::Store);
        };

        self.reconcile_durable_application(request, admitted, false)
            .await
    }

    pub(super) async fn reconcile_durable_application(
        &self,
        request: &RecoveryRequest,
        current: &RecoveryApplication,
        replayed: bool,
    ) -> Result<RecoveryActionOutcome, RecoveryError> {
        let manifest = recovery_manifest()?;
        let now = current_time_us();
        let ids = observation_ids(request)?;
        EvidenceIngestor::new(
            self.snapshot.clone(),
            self.writer.clone(),
            self.snapshot.effective_config_hash,
            ACTION_ALGORITHM_REVISION,
        )
        .map_err(|_| RecoveryError::Store)?
        .drain_observations_once(&ids)
        .await
        .map_err(|_| RecoveryError::Store)?;
        reconcile_observations_once(
            ReconcileInput {
                runtime_snapshot: self.snapshot.clone(),
                adapter_manifests: vec![manifest],
                liveness: vec![],
                reconciled_gaps: vec![],
                reconciled_outages: vec![],
                independent_source_reconciliations: vec![],
                effective_config_hash: self.snapshot.effective_config_hash,
                algorithm_revision: ACTION_ALGORITHM_REVISION.into(),
                occurred_at_us: now,
                max_items: 16,
            },
            &self.writer,
            &ids,
        )
        .await
        .map_err(|_| RecoveryError::Store)?;
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let evidence = RecoveryEvidenceCurrentView::from_snapshot(&projected)
            .map_err(|_| RecoveryError::Store)?;
        let segmentation =
            SegmentationCurrentView::from_snapshot(&projected).map_err(|_| RecoveryError::Store)?;
        let mut delivered = current.clone();
        if current.input_delivery_state == RecoveryInputDeliveryState::Admitted {
            // An intent-only invocation is a durable but unsettled fact. Until
            // the exact result receipt exists, an unpaired Operation is not an
            // immutable contradiction and must not manufacture Delivered.
            if evidence.receipt_for_observation(ids[0]).is_none()
                || evidence.receipt_for_observation(ids[1]).is_none()
            {
                return Ok(application_outcome(current, replayed));
            }
            let Some(operation) = segmentation
                .operation_for_observation(ids[0])
                .map_err(|_| RecoveryError::Store)?
            else {
                return Ok(application_outcome(current, replayed));
            };
            if operation.pairing_state != PairingState::Paired {
                return Ok(application_outcome(current, replayed));
            }
            if operation.input_source_observation_refs.as_slice() != [ids[0]]
                || operation.result_source_observation_refs.as_slice() != [ids[1]]
            {
                return Err(RecoveryError::InvalidSuccessor);
            }
            let Some(lane_id) = operation.execution_lane_id else {
                return Ok(application_outcome(current, replayed));
            };
            let Some(lane) = segmentation.lane(lane_id) else {
                return Ok(application_outcome(current, replayed));
            };
            let Some(receipt) = segmentation.receipt(lane.active_capture_receipt_revision_id)
            else {
                return Ok(application_outcome(current, replayed));
            };
            let post_ids = operation
                .scope_effect_ids
                .iter()
                .filter_map(|id| segmentation.scope_effect(*id))
                .filter_map(|effect| effect.post_snapshot_id)
                .collect::<std::collections::BTreeSet<_>>();
            let post_snapshot_id = match post_ids.iter().copied().collect::<Vec<_>>().as_slice() {
                [] => None,
                [value] => Some(*value),
                _ => return Err(RecoveryError::InvalidSuccessor),
            };
            delivered.revision_id = RevisionId::new_v7();
            delivered.parent_revision_id = Some(current.revision_id);
            delivered.post_application_snapshot_id = post_snapshot_id;
            delivered.input_delivery_state = RecoveryInputDeliveryState::Delivered;
            delivered.operation_id = Some(operation.operation_id);
            delivered.operation_revision = Some(operation.operation_revision);
            delivered.execution_lane_id = Some(lane_id);
            delivered.capture_receipt_revision_id = Some(receipt.capture_receipt_revision_id);
            delivered.scope_effect_ids = operation.scope_effect_ids.clone();
            delivered.input_source_observation_ids = vec![ids[0]];
            delivered.result_source_observation_ids = vec![ids[1]];
            delivered.verifier_receipts.clear();
            delivered.application_status = RecoveryApplicationStatus::Unknown;
            delivered.created_at_us = now;
            if !delivered.is_successor_of(current) {
                return Err(RecoveryError::InvalidSuccessor);
            }
            #[cfg(test)]
            if self.take_test_fault(super::TestFault::TerminalApplicationCommit) {
                return Err(RecoveryError::Store);
            }
            self.writer
                .commit(
                    application_command(
                        CommandId::new_v7(),
                        &delivered,
                        self.snapshot.effective_config_hash,
                    )?,
                    now,
                )
                .await
                .map_err(|_| RecoveryError::Store)?;
        } else if current.input_source_observation_ids.as_slice() != [ids[0]]
            || current.result_source_observation_ids.as_slice() != [ids[1]]
        {
            return Err(RecoveryError::InvalidSuccessor);
        }
        let Some(result_receipt) = evidence.receipt_for_observation(ids[1]) else {
            return Ok(application_outcome(&delivered, replayed));
        };
        let terminal = read_terminal_evidence(&self.snapshot, &result_receipt.cas_ref)?;
        let Some(post_snapshot_id) = delivered.post_application_snapshot_id else {
            return Ok(application_outcome(&delivered, replayed));
        };
        let outcome = match terminal.authoritative_outcome()? {
            Some(value) => value,
            None => match self
                .fresh_replay_verifier(
                    &delivered,
                    terminal.normal_exit,
                    terminal.exit_code,
                    terminal.affected_file_identity,
                )
                .await?
            {
                Some(value) => value,
                None => return Ok(application_outcome(&delivered, replayed)),
            },
        };
        let matching_receipts = delivered.verifier_receipts.iter().filter(|existing| {
            existing.verifier_version == terminal.verifier_version
                && existing.result_source_observation_id == ids[1]
                && existing.post_application_snapshot_id == post_snapshot_id
        });
        let mut matched = false;
        for existing in matching_receipts {
            if existing.outcome != outcome {
                return Err(RecoveryError::InvalidSuccessor);
            }
            matched = true;
        }
        if matched {
            if outcome == RecoveryVerificationOutcome::Applied {
                let receipts = self
                    .resolve_anchor_verifier_receipts(&delivered, &terminal)
                    .await?;
                if !receipts.is_empty()
                    && receipts != delivered.anchor_verifier_receipts
                    && receipts.len() == delivered.attempt_anchor_claims.len()
                {
                    let mut anchored = delivered.clone();
                    anchored.revision_id = RevisionId::new_v7();
                    anchored.parent_revision_id = Some(delivered.revision_id);
                    anchored.anchor_verifier_receipts = receipts;
                    anchored.created_at_us = current_time_us();
                    if !anchored.is_successor_of(&delivered) {
                        return Err(RecoveryError::InvalidSuccessor);
                    }
                    self.writer
                        .commit(
                            application_command(
                                CommandId::new_v7(),
                                &anchored,
                                self.snapshot.effective_config_hash,
                            )?,
                            anchored.created_at_us,
                        )
                        .await
                        .map_err(|_| RecoveryError::Store)?;
                    return Ok(application_outcome(&anchored, replayed));
                }
            }
            return Ok(application_outcome(&delivered, replayed));
        }
        let mut verified = delivered.clone();
        verified.revision_id = RevisionId::new_v7();
        verified.parent_revision_id = Some(delivered.revision_id);
        verified.verifier_receipts.push(RecoveryVerifierReceipt {
            verification_revision: u32::try_from(verified.verifier_receipts.len() + 1)
                .map_err(|_| RecoveryError::Budget)?,
            verifier_version: terminal.verifier_version,
            result_source_observation_id: ids[1],
            post_application_snapshot_id: post_snapshot_id,
            outcome,
        });
        verified.application_status = match outcome {
            RecoveryVerificationOutcome::Applied => RecoveryApplicationStatus::Applied,
            RecoveryVerificationOutcome::NotApplied => RecoveryApplicationStatus::Failed,
            RecoveryVerificationOutcome::PartiallyApplied => {
                RecoveryApplicationStatus::PartiallyApplied
            }
        };
        if outcome == RecoveryVerificationOutcome::Applied {
            verified.anchor_verifier_receipts = self
                .resolve_anchor_verifier_receipts(&verified, &terminal)
                .await?;
        }
        verified.created_at_us = current_time_us();
        if !verified.is_successor_of(&delivered) {
            return Err(RecoveryError::InvalidSuccessor);
        }
        self.writer
            .commit(
                application_command(
                    CommandId::new_v7(),
                    &verified,
                    self.snapshot.effective_config_hash,
                )?,
                verified.created_at_us,
            )
            .await
            .map_err(|_| RecoveryError::Store)?;
        Ok(application_outcome(&verified, replayed))
    }

    async fn resolve_anchor_verifier_receipts(
        &self,
        application: &RecoveryApplication,
        terminal: &TerminalEvidence,
    ) -> Result<Vec<RecoveryAnchorVerifierReceipt>, RecoveryError> {
        if application.relevant_attempt_anchor_ids.is_empty()
            || application.relevant_attempt_anchor_ids.len()
                != application.attempt_anchor_claims.len()
        {
            return Ok(Vec::new());
        }
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let attempts = AttemptCurrentView::from_snapshot(&projected)?;
        let repositories = RepositoryCurrentView::from_snapshot(&projected)?;
        let Some(post_snapshot_id) = application.post_application_snapshot_id else {
            return Ok(Vec::new());
        };
        let Some(post_snapshot) =
            repositories
                .snapshots
                .get(&post_snapshot_id)
                .filter(|snapshot| {
                    snapshot.capture_status == SnapshotCaptureStatus::Complete
                        && snapshot.worktree_instance_id == application.target_worktree_instance_id
                })
        else {
            return Ok(Vec::new());
        };
        let Some(target) = repositories
            .worktrees
            .get(&application.target_worktree_instance_id)
        else {
            return Ok(Vec::new());
        };
        let Some(operation_id) = application.operation_id else {
            return Ok(Vec::new());
        };
        let Some(operation_revision) = application.operation_revision else {
            return Ok(Vec::new());
        };
        let Some(execution_lane_id) = application.execution_lane_id else {
            return Ok(Vec::new());
        };
        let Some(capture_receipt_revision_id) = application.capture_receipt_revision_id else {
            return Ok(Vec::new());
        };
        let Some(result_source_observation_id) =
            application.result_source_observation_ids.first().copied()
        else {
            return Ok(Vec::new());
        };
        let Some(recovery_verification_revision) = application
            .verifier_receipts
            .last()
            .map(|receipt| receipt.verification_revision)
        else {
            return Ok(Vec::new());
        };
        let cas = CasStore::open(self.snapshot.cas_dir.clone()).map_err(|_| RecoveryError::Cas)?;
        let mut receipts = Vec::new();
        for (attempt_id, claim) in application
            .relevant_attempt_anchor_ids
            .iter()
            .zip(&application.attempt_anchor_claims)
        {
            if *attempt_id != claim.attempt_id
                || claim.source_repository_instance_id != target.repository_instance_id
                || claim.source_worktree_instance_id == application.target_worktree_instance_id
            {
                return Ok(Vec::new());
            }
            let Some(attempt) = attempts.attempts.get(attempt_id).filter(|attempt| {
                attempt.repository_instance_id == Some(claim.source_repository_instance_id)
                    && attempt
                        .worktree_instance_ids
                        .contains(&claim.source_worktree_instance_id)
                    && attempt.lifecycle_status == AttemptLifecycleStatus::Active
                    && matches!(
                        attempt.execution_status,
                        AttemptExecutionStatus::Proposed
                            | AttemptExecutionStatus::Active
                            | AttemptExecutionStatus::Interrupted
                    )
                    && attempt.strategy_contract_fingerprint == claim.strategy_contract_fingerprint
            }) else {
                return Ok(Vec::new());
            };
            let Ok(path_digest) = CasDigest::from_str(&claim.affected_relative_path.cas_ref) else {
                return Ok(Vec::new());
            };
            let Ok(path_bytes) = cas.read(&path_digest) else {
                return Ok(Vec::new());
            };
            if std::path::Path::new(std::str::from_utf8(&path_bytes).unwrap_or_default())
                != self
                    .strict_application_patch_path(application.recovery_bundle_id)
                    .await?
                    .as_deref()
                    .unwrap_or_else(|| std::path::Path::new(""))
            {
                return Ok(Vec::new());
            }
            if claim.competing_groups.iter().any(|source_group| {
                !attempt
                    .competing_group_ids
                    .contains(&source_group.competing_group_id)
            }) {
                return Ok(Vec::new());
            }
            let mut revalidated_groups = Vec::new();
            for group_id in &attempt.competing_group_ids {
                let Some(group) = attempts.competing_groups.get(group_id).filter(|group| {
                    current_group_authorizes_attempt(group, *attempt_id, group.revision_id)
                }) else {
                    return Ok(Vec::new());
                };
                revalidated_groups.push(RecoveryCompetingGroupClaim {
                    competing_group_id: group.competing_group_id,
                    revision_id: group.revision_id,
                    resolution_status: group.resolution_status,
                });
            }
            receipts.push(RecoveryAnchorVerifierReceipt {
                verifier_version: RECOVERY_ANCHOR_VERIFIER_VERSION,
                attempt_id: *attempt_id,
                source_attempt_revision_id: claim.attempt_revision_id,
                revalidated_attempt_revision_id: attempt.revision_id,
                strategy_contract_fingerprint: claim.strategy_contract_fingerprint,
                source_repository_instance_id: claim.source_repository_instance_id,
                source_worktree_instance_id: claim.source_worktree_instance_id,
                source_snapshot_id: claim.source_snapshot_id,
                target_repository_instance_id: target.repository_instance_id,
                target_worktree_instance_id: application.target_worktree_instance_id,
                post_application_snapshot_id: post_snapshot.worktree_snapshot_id,
                affected_relative_path: claim.affected_relative_path.clone(),
                competing_groups: claim.competing_groups.clone(),
                revalidated_competing_groups: revalidated_groups,
                operation_id,
                operation_revision,
                execution_lane_id,
                capture_receipt_revision_id,
                scope_effect_ids: application.scope_effect_ids.clone(),
                result_source_observation_id,
                recovery_verification_revision,
            });
        }
        if self
            .fresh_replay_verifier(
                application,
                terminal.normal_exit,
                terminal.exit_code,
                terminal.affected_file_identity,
            )
            .await?
            != Some(RecoveryVerificationOutcome::Applied)
        {
            return Ok(Vec::new());
        }
        Ok(receipts)
    }

    async fn strict_application_patch_path(
        &self,
        bundle_id: evertrace_domain::ids::RecoveryBundleId,
    ) -> Result<Option<std::path::PathBuf>, RecoveryError> {
        let projected = self
            .writer
            .project()
            .await
            .map_err(|_| RecoveryError::Store)?;
        let recovery =
            evertrace_store::projections::RecoveryCurrentView::from_snapshot(&projected)?;
        let Some(bundle) = recovery.state.bundles.get(&bundle_id) else {
            return Ok(None);
        };
        if !bundle.is_exact_patch_only_anchor_shape() {
            return Ok(None);
        }
        let [content] = bundle.tracked_diff_blob_refs.as_slice() else {
            return Ok(None);
        };
        let digest = CasDigest::from_str(&content.payload.cas_ref)
            .map_err(|_| RecoveryError::InvalidInput)?;
        let cas = CasStore::open(self.snapshot.cas_dir.clone()).map_err(|_| RecoveryError::Cas)?;
        let patch = cas.read(&digest).map_err(|_| RecoveryError::Cas)?;
        Ok(super::super::patch::strict_patch_target(&patch))
    }
}

fn application_outcome(application: &RecoveryApplication, replayed: bool) -> RecoveryActionOutcome {
    RecoveryActionOutcome::Application {
        recovery_application_id: application.recovery_application_id,
        application_status: application.application_status,
        replayed,
    }
}

fn read_terminal_evidence(
    snapshot: &evertrace_capture::RuntimeSnapshot,
    cas_ref: &str,
) -> Result<TerminalEvidence, RecoveryError> {
    let digest = CasDigest::from_str(cas_ref).map_err(|_| RecoveryError::InvalidSuccessor)?;
    let cas = CasStore::open(snapshot.cas_dir.clone()).map_err(|_| RecoveryError::Cas)?;
    let bytes = cas.read(&digest).map_err(|_| RecoveryError::Cas)?;
    serde_json::from_slice(&bytes).map_err(|_| RecoveryError::InvalidSuccessor)
}

fn recovery_manifest() -> Result<AdapterCapabilityManifest, RecoveryError> {
    let mut manifest = AdapterCapabilityManifest {
        adapter_manifest_id: String::new(),
        adapter_kind: AdapterKind::Other,
        adapter_version: "s17-supervised-recovery-v1".into(),
        host_version_range: "evertraced-internal-v1".into(),
        eligible_event_manifest_refs: vec![ELIGIBLE_EVENTS.into()],
        event_identity: EventIdentity::StableNative,
        capture_guarantee: CaptureGuarantee::Full,
        recovery_ordering: RecoveryOrdering::FencedHost,
        cue_boundary: CueBoundary::Unavailable,
        subagent_trace: SubagentTrace::Full,
        trust_readback: TrustReadback::Unavailable,
        project_policy_surfaces: vec![],
        admission_failure_observability: ManifestObservability::Complete,
        mcp_session_binding: McpSessionBinding::Unavailable,
        mcp_binding_mechanism: McpBindingMechanism::None,
        observable: vec![
            ObservableCapability::DelegationStart,
            ObservableCapability::ChildSessionId,
            ObservableCapability::ChildToolCall,
            ObservableCapability::ChildToolResult,
            ObservableCapability::ChildFinalResult,
            ObservableCapability::DelegationEnd,
        ],
        unavailable_by_design: vec![ObservableCapability::RawHiddenReasoning],
        required_for_full: REQUIRED_FOR_FULL.to_vec(),
    };
    manifest
        .finalize_content_revision()
        .map_err(|_| RecoveryError::Store)?;
    Ok(manifest)
}

fn observation_ids(request: &RecoveryRequest) -> Result<[SourceObservationId; 2], RecoveryError> {
    let instance = SourceInstanceId::parse(format!("recovery-{}", request.request_id))
        .map_err(|_| RecoveryError::InvalidInput)?;
    let revision = SourceRevision::parse("action-v1").map_err(|_| RecoveryError::InvalidInput)?;
    let values = ["patch-stdin", "patch-result"].map(|record| {
        source_observation_id(
            &instance,
            &revision,
            &SourceRecordIdentity::parse(record).map_err(|_| RecoveryError::InvalidInput)?,
        )
        .map_err(|_| RecoveryError::InvalidInput)
    });
    Ok([values[0]?, values[1]?])
}

fn terminal_payload(
    result: super::GitApplyResult,
    affected_file_identity: Option<ConfinedFileIdentity>,
    verification: Option<RecoveryVerificationOutcome>,
) -> Result<Vec<u8>, RecoveryError> {
    serde_json::to_vec(&TerminalEvidence {
        schema_version: 1,
        verifier_version: 1,
        normal_exit: result.exit_code.is_some()
            && !result.timed_out
            && !result.cancelled
            && result.signal.is_none()
            && !result.truncated
            && !result.io_error,
        exit_code: result.exit_code,
        signal: result.signal,
        timed_out: result.timed_out,
        cancelled: result.cancelled,
        truncated: result.truncated,
        io_error: result.io_error,
        supervised: true,
        affected_file_identity: affected_file_identity.map(Into::into),
        verifier_outcome: verification,
    })
    .map_err(|_| RecoveryError::Store)
}

struct FrameFacts<'a> {
    record: &'a str,
    role: ObservationRole,
    sequence: u64,
    bytes: &'a [u8],
    event_time_us: i64,
    terminal_kind: Option<TerminalKind>,
    manifest_ref: &'a str,
}

fn action_capture_input(
    request: &RecoveryRequest,
    admitted: &RecoveryApplication,
    prepared: &PreparedPatch,
    post_snapshot_id: Option<evertrace_domain::ids::WorktreeSnapshotId>,
    frame: FrameFacts<'_>,
) -> Result<CaptureRecordInput, RecoveryError> {
    let fields = [
        CorrelationField::HostInstanceId,
        CorrelationField::HostTraceLineageId,
        CorrelationField::HostLaneKey,
        CorrelationField::CanonicalEventFamily,
        CorrelationField::NativeRequestId,
        CorrelationField::PhysicalExecutionOrdinal,
    ];
    let source_ref = admitted.recovery_application_id.to_string();
    let observation_ids = observation_ids(request)?;
    let observation_id = observation_ids[usize::from(frame.sequence == 2)];
    let terminal = frame.terminal_kind;
    Ok(CaptureRecordInput {
        spool_record_id: None,
        source_observation_id_hint: None,
        source_instance_id: format!("recovery-{}", request.request_id),
        source_revision: "action-v1".into(),
        source_record_identity: Some(frame.record.into()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: "evertrace-supervised-recovery-v1".into(),
        source_ref: source_ref.clone(),
        session_ref: format!("recovery-session-{}", request.request_id),
        turn_ref: None,
        tool_ref: Some(format!("git-apply-{}", request.request_id)),
        source_sequence: frame.sequence,
        source_sequence_origin: Some(1),
        task_id: None,
        repository_instance_id: Some(prepared.repository_id.to_string()),
        worktree_instance_id: Some(request.target_worktree_instance_id.to_string()),
        source_byte_range: None,
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: terminal.map(|_| 2),
        observation_role: frame.role,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: Some("evertraced-recovery-supervisor".into()),
            host_trace_lineage_id: Some(format!("recovery-trace-{}", request.request_id)),
            host_lane_key: Some(format!("recovery-lane-{}", request.request_id)),
            canonical_event_family: Some(CanonicalEventFamily::Mutate),
            native_request_id: Some(request.request_id.to_string()),
            physical_execution_ordinal: Some(1),
            pairing_role: frame.role,
            field_provenance: fields
                .into_iter()
                .map(|field| CorrelationFieldClaim {
                    field,
                    source_ref: source_ref.clone(),
                    evidence_ref: admitted.revision_id.to_string(),
                })
                .collect(),
            adapter_manifest_ref: frame.manifest_ref.into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: Some(admitted.revision_id.to_string()),
            admission: CorrelationAdmission::ExactCapable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: vec![ScopeEffectClaim {
            effect_role: EffectRole::Mutate,
            repository_instance_id: Some(prepared.repository_id),
            worktree_instance_id: Some(request.target_worktree_instance_id),
            pre_snapshot_id: Some(prepared.claims.pre_application_snapshot_id),
            post_snapshot_id: (frame.role == ObservationRole::Result)
                .then_some(post_snapshot_id)
                .flatten(),
            experiment_run_ids: vec![],
            artifact_refs: vec![],
            evidence_refs: vec![observation_id],
        }],
        lifecycle: Some(LaneLifecycleEvidence {
            host_session_id: format!("recovery-session-{}", request.request_id),
            agent_id: "evertraced-recovery-supervisor".into(),
            incarnation_ref: Some(format!("recovery-invocation-{}", request.request_id)),
            child_session_id: Some(format!("git-apply-{}", request.request_id)),
            host_lane_key: format!("recovery-lane-{}", request.request_id),
            parent_host_lane_key: None,
            spawn_event_ref: Some(observation_ids[0].to_string()),
            terminal_event_ref: terminal.map(|_| observation_ids[1].to_string()),
            terminal_kind: terminal,
            host_final_return: terminal == Some(TerminalKind::Normal),
            source_close_ref: terminal.map(|_| observation_ids[1].to_string()),
            parent_session_end_ref: None,
            liveness_probe_ref: None,
            liveness_state: if terminal.is_some() {
                LivenessState::Absent
            } else {
                LivenessState::Live
            },
            lane_sequence: frame.sequence,
            adapter_manifest_ref: frame.manifest_ref.into(),
            eligible_event_manifest_ref: ELIGIBLE_EVENTS.into(),
            delegated_goal_ref: None,
            delegated_target_refs: vec![],
            delegated_acceptance_refs: vec![],
            reasoning_visibility: vec![],
        }),
        unsupported_record_classification: None,
        source_role: SourceRole::Tool,
        content_trust: ContentTrust::Observed,
        capture_completeness: if terminal.is_some_and(|kind| kind != TerminalKind::Normal) {
            CaptureCompleteness::Partial
        } else {
            CaptureCompleteness::Complete
        },
        surface_eligible: false,
        adapter_revision: 1,
        adapter_manifest_ref: frame.manifest_ref.into(),
        eligible_event_manifest_ref: ELIGIBLE_EVENTS.into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: Some(frame.event_time_us),
        raw_payload: frame.bytes.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_group(
        selected_attempt_id: Option<evertrace_domain::ids::AttemptId>,
        resolution_status: CompetingResolutionStatus,
    ) -> (CompetingAttemptGroup, evertrace_domain::ids::AttemptId) {
        let authorized = evertrace_domain::ids::AttemptId::new_v7();
        let other = evertrace_domain::ids::AttemptId::new_v7();
        let mut members = vec![authorized, other];
        members.sort();
        let group = CompetingAttemptGroup {
            competing_group_id: evertrace_domain::ids::CompetingAttemptGroupId::new_v7(),
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            revision_generation: 1,
            task_id: evertrace_domain::ids::TaskId::new_v7(),
            decision_boundary_ref: "typed:current-acceptance".into(),
            comparison_contract_ref: None,
            origin_workstream_id: None,
            origin_episode_id: None,
            member_workstream_ids: vec![],
            member_attempt_ids: members,
            candidate_snapshot_refs: vec![],
            target_refs: vec![],
            conflict_kind: evertrace_domain::work::CompetingConflictKind::AlternativeStrategy,
            resolution_status,
            selected_attempt_id,
            partially_integrated_attempt_ids: vec![],
            resolution_evidence_refs: vec!["typed:current-resolution".into()],
            source_watermark: 1,
        };
        (group, authorized)
    }

    fn terminal() -> TerminalEvidence {
        TerminalEvidence {
            schema_version: 1,
            verifier_version: 1,
            normal_exit: true,
            exit_code: Some(1),
            signal: None,
            timed_out: false,
            cancelled: false,
            truncated: false,
            io_error: false,
            supervised: true,
            affected_file_identity: Some(TerminalAffectedFileIdentity {
                device: 1,
                inode: 2,
                size: 3,
                mtime_seconds: 4,
                mtime_nanoseconds: 5,
                ctime_seconds: 6,
                ctime_nanoseconds: 7,
            }),
            verifier_outcome: Some(RecoveryVerificationOutcome::NotApplied),
        }
    }

    #[test]
    fn terminal_result_and_verifier_facts_must_be_symmetric() {
        assert_eq!(
            terminal().authoritative_outcome().unwrap(),
            Some(RecoveryVerificationOutcome::NotApplied)
        );
        let mut signal = terminal();
        signal.signal = Some(9);
        assert!(matches!(
            signal.authoritative_outcome(),
            Err(RecoveryError::InvalidSuccessor)
        ));
        let mut truncated = terminal();
        truncated.truncated = true;
        truncated.normal_exit = false;
        assert!(matches!(
            truncated.authoritative_outcome(),
            Err(RecoveryError::InvalidSuccessor)
        ));
        let mut forged_success = terminal();
        forged_success.exit_code = Some(0);
        assert!(matches!(
            forged_success.authoritative_outcome(),
            Err(RecoveryError::InvalidSuccessor)
        ));
    }

    #[test]
    fn current_group_selected_other_and_rejected_all_never_authorize_transfer() {
        let authorized = evertrace_domain::ids::AttemptId::new_v7();
        let other = evertrace_domain::ids::AttemptId::new_v7();
        let (mut selected_other, _) =
            current_group(Some(other), CompetingResolutionStatus::Selected);
        selected_other.member_attempt_ids = vec![authorized, other];
        selected_other.member_attempt_ids.sort();
        assert!(!current_group_authorizes_attempt(
            &selected_other,
            authorized,
            selected_other.revision_id,
        ));

        let (rejected_all, authorized) =
            current_group(None, CompetingResolutionStatus::RejectedAll);
        assert!(!current_group_authorizes_attempt(
            &rejected_all,
            authorized,
            rejected_all.revision_id,
        ));
    }
}
