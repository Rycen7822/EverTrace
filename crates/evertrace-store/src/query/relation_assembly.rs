use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use crate::{
    JournalPayload, StoreError,
    relations::{
        AttemptRelationKind, AutoresearchRelationKind, CaptureRelationKind, EpisodeRelationKind,
        OperationBurstRelationKind, PhysicalRelationKind, RecoveryRelationKind,
        RelationProjectionRow, RepositoryRelationKind, SegmentationCorrectionRelationKind,
        SemanticRelationKind, WorkBindingRelationKind, WorkIdentityRelationKind,
    },
};

fn causal_seq(endpoint_seqs: &BTreeMap<String, u64>, source: &str, target: &str) -> u64 {
    endpoint_seqs
        .get(source)
        .into_iter()
        .chain(endpoint_seqs.get(target))
        .copied()
        .max()
        .unwrap_or(0)
}

pub(super) fn index_typed_ids(
    payload: &JournalPayload,
    source_event_seq: u64,
    endpoint_seqs: &mut BTreeMap<String, u64>,
) -> Result<(), StoreError> {
    fn visit(value: &serde_json::Value, seq: u64, out: &mut BTreeMap<String, u64>) {
        match value {
            serde_json::Value::String(value)
                if evertrace_domain::ids::AnyPublicId::from_str(value).is_ok()
                    || evertrace_domain::revision::RevisionId::from_str(value).is_ok() =>
            {
                out.entry(value.clone())
                    .and_modify(|current| *current = (*current).max(seq))
                    .or_insert(seq);
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    visit(value, seq, out);
                }
            }
            serde_json::Value::Object(values) => {
                for value in values.values() {
                    visit(value, seq, out);
                }
            }
            _ => {}
        }
    }
    let value = serde_json::to_value(payload).map_err(|_| StoreError::StoreCorrupt)?;
    visit(&value, source_event_seq, endpoint_seqs);
    Ok(())
}

pub(super) fn add_physical(
    out: &mut BTreeSet<RelationProjectionRow>,
    rows: Vec<crate::relations::PhysicalRelationRow>,
    endpoint_seqs: &BTreeMap<String, u64>,
) {
    for row in rows {
        let kind = match row.kind {
            PhysicalRelationKind::SourceObservationToHostOccurrence => {
                "source_observation_to_host_occurrence"
            }
            PhysicalRelationKind::HostOccurrenceToOperation => "host_occurrence_to_operation",
            PhysicalRelationKind::OperationToScopeEffect => "operation_to_scope_effect",
        };
        out.insert(RelationProjectionRow::edge(
            kind,
            causal_seq(endpoint_seqs, &row.source_id, &row.target_id),
            row.source_id,
            row.target_id,
        ));
    }
}
pub(super) fn add_repository(
    out: &mut BTreeSet<RelationProjectionRow>,
    rows: Vec<crate::relations::RepositoryRelationRow>,
    endpoint_seqs: &BTreeMap<String, u64>,
) {
    for row in rows {
        let kind = match row.kind {
            RepositoryRelationKind::RepositoryToWorktree => "repository_to_worktree",
            RepositoryRelationKind::WorktreeToSnapshot => "worktree_to_snapshot",
            RepositoryRelationKind::WorktreeTransitionFrom => "worktree_transition_from",
            RepositoryRelationKind::WorktreeTransitionTo => "worktree_transition_to",
            RepositoryRelationKind::IntegrationEventSource => "integration_event_source",
            RepositoryRelationKind::IntegrationEventDestination => "integration_event_destination",
            RepositoryRelationKind::RepositoryDerivedFrom => "repository_derived_from",
            RepositoryRelationKind::WorktreeRecreatedFrom => "worktree_recreated_from",
        };
        out.insert(RelationProjectionRow::edge(
            kind,
            causal_seq(endpoint_seqs, &row.source_id, &row.target_id),
            row.source_id,
            row.target_id,
        ));
    }
}
pub(super) fn add_work_identity(
    out: &mut BTreeSet<RelationProjectionRow>,
    rows: Vec<crate::relations::WorkIdentityRelationRow>,
    endpoint_seqs: &BTreeMap<String, u64>,
) {
    for row in rows {
        let kind = match row.kind {
            WorkIdentityRelationKind::TaskContinues => "task_continues",
            WorkIdentityRelationKind::TaskSplitFrom => "task_split_from",
            WorkIdentityRelationKind::TaskSplitInto => "task_split_into",
            WorkIdentityRelationKind::TaskMergedFrom => "task_merged_from",
            WorkIdentityRelationKind::TaskMergedInto => "task_merged_into",
            WorkIdentityRelationKind::TaskContainsWorkstream => "task_contains_workstream",
            WorkIdentityRelationKind::WorkstreamParent => "workstream_parent",
            WorkIdentityRelationKind::WorkstreamDependency => "workstream_dependency",
            WorkIdentityRelationKind::WorkstreamRepository => "workstream_repository",
            WorkIdentityRelationKind::WorkstreamWorktree => "workstream_worktree",
        };
        out.insert(RelationProjectionRow::edge(
            kind,
            causal_seq(endpoint_seqs, &row.source_id, &row.target_id),
            row.source_id,
            row.target_id,
        ));
    }
}
pub(super) fn add_attempt(
    out: &mut BTreeSet<RelationProjectionRow>,
    rows: Vec<crate::relations::AttemptRelationRow>,
    endpoint_seqs: &BTreeMap<String, u64>,
) {
    for row in rows {
        let kind = match row.kind {
            AttemptRelationKind::AttemptToTask => "attempt_to_task",
            AttemptRelationKind::AttemptToWorkstream => "attempt_to_workstream",
            AttemptRelationKind::AttemptToEpisode => "attempt_to_episode",
            AttemptRelationKind::AttemptToExecutionLane => "attempt_to_execution_lane",
            AttemptRelationKind::AttemptToBindingRevision => "attempt_to_binding_revision",
            AttemptRelationKind::AttemptToIntegrationEvidence => "attempt_to_integration_evidence",
            AttemptRelationKind::AttemptToOutcomeEvidence => "attempt_to_outcome_evidence",
            AttemptRelationKind::AttemptToVerifierEvidence => "attempt_to_verifier_evidence",
            AttemptRelationKind::AttemptResumesFromHistorical => "attempt_resumes_from_historical",
            AttemptRelationKind::AttemptComposedFromHistorical => {
                "attempt_composed_from_historical"
            }
            AttemptRelationKind::GroupToCandidateMember => "group_to_candidate_member",
            AttemptRelationKind::GroupToComparisonSnapshot => "group_to_comparison_snapshot",
            AttemptRelationKind::GroupToSelectedAttempt => "group_to_selected_attempt",
            AttemptRelationKind::GroupToPartiallyIntegratedAttempt => {
                "group_to_partially_integrated_attempt"
            }
        };
        out.insert(RelationProjectionRow::edge(
            kind,
            causal_seq(endpoint_seqs, &row.source_id, &row.target_id),
            row.source_id,
            row.target_id,
        ));
    }
}
pub(super) fn add_work_binding(
    out: &mut BTreeSet<RelationProjectionRow>,
    rows: Vec<crate::relations::WorkBindingRelationRow>,
    endpoint_seqs: &BTreeMap<String, u64>,
) {
    for row in rows {
        let kind = match row.kind {
            WorkBindingRelationKind::OperationToBindingRevision => "operation_to_binding_revision",
            WorkBindingRelationKind::BindingToScopeEffect => "binding_to_scope_effect",
            WorkBindingRelationKind::BindingToPrimaryTask => "binding_to_primary_task",
            WorkBindingRelationKind::BindingToPrimaryWorkstream => "binding_to_primary_workstream",
            WorkBindingRelationKind::BindingToPrimaryEpisode => "binding_to_primary_episode",
            WorkBindingRelationKind::BindingToCandidateTask => "binding_to_candidate_task",
            WorkBindingRelationKind::BindingToCandidateWorkstream => {
                "binding_to_candidate_workstream"
            }
            WorkBindingRelationKind::BindingToSecondaryTarget => "binding_to_secondary_target",
        };
        out.insert(RelationProjectionRow::edge(
            kind,
            causal_seq(endpoint_seqs, &row.source_id, &row.target_id),
            row.source_id,
            row.target_id,
        ));
    }
}
pub(super) fn add_episode(
    out: &mut BTreeSet<RelationProjectionRow>,
    rows: Vec<crate::relations::EpisodeRelationRow>,
    endpoint_seqs: &BTreeMap<String, u64>,
) {
    for row in rows {
        let kind = match row.kind {
            EpisodeRelationKind::EpisodeToTask => "episode_to_task",
            EpisodeRelationKind::EpisodeToWorkstream => "episode_to_workstream",
            EpisodeRelationKind::EpisodeToAttempt => "episode_to_attempt",
            EpisodeRelationKind::EpisodeToExecutionLane => "episode_to_execution_lane",
            EpisodeRelationKind::EpisodeToCheckpoint => "episode_to_checkpoint",
        };
        out.insert(RelationProjectionRow::edge(
            kind,
            causal_seq(endpoint_seqs, &row.source_id, &row.target_id),
            row.source_id,
            row.target_id,
        ));
    }
}
pub(super) fn add_capture(
    out: &mut BTreeSet<RelationProjectionRow>,
    rows: Vec<crate::relations::CaptureRelationRow>,
    endpoint_seqs: &BTreeMap<String, u64>,
) {
    for row in rows {
        let kind = match row.kind {
            CaptureRelationKind::ExecutionLaneToCaptureReceipt => {
                "execution_lane_to_capture_receipt"
            }
            CaptureRelationKind::ExecutionLaneToOperation => "execution_lane_to_operation",
            CaptureRelationKind::CaptureReceiptToSourceRevision => {
                "capture_receipt_to_source_revision"
            }
            CaptureRelationKind::CaptureReceiptToGapEvidence => "capture_receipt_to_gap_evidence",
            CaptureRelationKind::CaptureReceiptToOutageEvidence => {
                "capture_receipt_to_outage_evidence"
            }
        };
        out.insert(RelationProjectionRow::edge(
            kind,
            causal_seq(endpoint_seqs, &row.source_id, &row.target_id),
            row.source_id,
            row.target_id,
        ));
    }
}
pub(super) fn add_burst(
    out: &mut BTreeSet<RelationProjectionRow>,
    rows: Vec<crate::relations::OperationBurstRelationRow>,
    endpoint_seqs: &BTreeMap<String, u64>,
) {
    for row in rows {
        let kind = match row.kind {
            OperationBurstRelationKind::EpisodeToBurst => "episode_to_burst",
            OperationBurstRelationKind::BurstToOperation => "burst_to_operation",
            OperationBurstRelationKind::BurstToHostOccurrence => "burst_to_host_occurrence",
            OperationBurstRelationKind::BurstToSourceObservation => "burst_to_source_observation",
            OperationBurstRelationKind::BurstToScopeEffect => "burst_to_scope_effect",
            OperationBurstRelationKind::BurstToBindingRevision => "burst_to_binding_revision",
            OperationBurstRelationKind::BurstToExecutionLane => "burst_to_execution_lane",
            OperationBurstRelationKind::BurstToAttempt => "burst_to_attempt",
        };
        out.insert(RelationProjectionRow::edge(
            kind,
            causal_seq(endpoint_seqs, &row.source_id, &row.target_id),
            row.source_id,
            row.target_id,
        ));
    }
}
pub(super) fn add_correction(
    out: &mut BTreeSet<RelationProjectionRow>,
    rows: Vec<crate::relations::SegmentationCorrectionRelationRow>,
    endpoint_seqs: &BTreeMap<String, u64>,
) {
    for row in rows {
        let kind = match row.kind {
            SegmentationCorrectionRelationKind::CorrectionFromEpisode => "correction_from_episode",
            SegmentationCorrectionRelationKind::CorrectionToEpisode => "correction_to_episode",
            SegmentationCorrectionRelationKind::CorrectionSuccessor => "correction_successor",
        };
        out.insert(RelationProjectionRow::edge(
            kind,
            causal_seq(endpoint_seqs, &row.source_id, &row.target_id),
            row.source_id,
            row.target_id,
        ));
    }
}
pub(super) fn add_recovery(
    out: &mut BTreeSet<RelationProjectionRow>,
    rows: Vec<crate::relations::RecoveryRelationRow>,
    endpoint_seqs: &BTreeMap<String, u64>,
) {
    for row in rows {
        let kind = match row.kind {
            RecoveryRelationKind::RequestToWorktree => "request_to_worktree",
            RecoveryRelationKind::RequestToSnapshot => "request_to_snapshot",
            RecoveryRelationKind::RequestToBundle => "request_to_bundle",
            RecoveryRelationKind::BundleToWorktree => "bundle_to_worktree",
            RecoveryRelationKind::BundleToSnapshot => "bundle_to_snapshot",
            RecoveryRelationKind::BundleToAttemptAnchor => "bundle_to_attempt_anchor",
            RecoveryRelationKind::ApplicationToBundle => "application_to_bundle",
            RecoveryRelationKind::ApplicationToWorktree => "application_to_worktree",
            RecoveryRelationKind::ApplicationToPreSnapshot => "application_to_pre_snapshot",
            RecoveryRelationKind::ApplicationToPostSnapshot => "application_to_post_snapshot",
            RecoveryRelationKind::ApplicationToOperation => "application_to_operation",
            RecoveryRelationKind::ApplicationToExecutionLane => "application_to_execution_lane",
            RecoveryRelationKind::ApplicationToCaptureReceipt => "application_to_capture_receipt",
            RecoveryRelationKind::ApplicationToScopeEffect => "application_to_scope_effect",
            RecoveryRelationKind::ApplicationToInputObservation => {
                "application_to_input_observation"
            }
            RecoveryRelationKind::ApplicationToResultObservation => {
                "application_to_result_observation"
            }
            RecoveryRelationKind::ApplicationToAttemptAnchor => "application_to_attempt_anchor",
        };
        out.insert(RelationProjectionRow::edge(
            kind,
            causal_seq(endpoint_seqs, &row.source_id, &row.target_id),
            row.source_id,
            row.target_id,
        ));
    }
}
pub(super) fn add_autoresearch(
    out: &mut BTreeSet<RelationProjectionRow>,
    rows: Vec<crate::relations::AutoresearchRelationRow>,
    endpoint_seqs: &BTreeMap<String, u64>,
) {
    for row in rows {
        let kind = match row.kind {
            AutoresearchRelationKind::RunToWorkstream => "run_to_workstream",
            AutoresearchRelationKind::RunToAttempt => "run_to_attempt",
            AutoresearchRelationKind::RunToArtifact => "run_to_artifact",
            AutoresearchRelationKind::ResultProducedByRun => "result_produced_by_run",
            AutoresearchRelationKind::ResultToRawArtifact => "result_to_raw_artifact",
            AutoresearchRelationKind::ArtifactProducedByOperation => {
                "artifact_produced_by_operation"
            }
            AutoresearchRelationKind::ArtifactProducedByRun => "artifact_produced_by_run",
            AutoresearchRelationKind::ArtifactProducedByEpisode => "artifact_produced_by_episode",
            AutoresearchRelationKind::ArtifactConsumedByOperation => {
                "artifact_consumed_by_operation"
            }
            AutoresearchRelationKind::ArtifactConsumedByRun => "artifact_consumed_by_run",
            AutoresearchRelationKind::ArtifactConsumedByEpisode => "artifact_consumed_by_episode",
            AutoresearchRelationKind::ArtifactRevisionSuccessor => "artifact_revision_successor",
        };
        out.insert(RelationProjectionRow::edge(
            kind,
            causal_seq(endpoint_seqs, &row.source_id, &row.target_id),
            row.source_id,
            row.target_id,
        ));
    }
}
pub(super) fn add_semantic(
    out: &mut BTreeSet<RelationProjectionRow>,
    rows: Vec<crate::relations::SemanticRelationRow>,
    endpoint_seqs: &BTreeMap<String, u64>,
) {
    for row in rows {
        let kind = match row.kind {
            SemanticRelationKind::AtomRevisionSuccessor => "atom_revision_successor",
            SemanticRelationKind::AtomSupersedes => "atom_supersedes",
            SemanticRelationKind::AtomSupports => "atom_supports",
            SemanticRelationKind::AtomContradicts => "atom_contradicts",
            SemanticRelationKind::AtomFromSourceObservation => "atom_from_source_observation",
            SemanticRelationKind::ProposalRevisionSuccessor => "proposal_revision_successor",
            SemanticRelationKind::ProposalReviewedRevision => "proposal_reviewed_revision",
            SemanticRelationKind::ProposalTargetsAtom => "proposal_targets_atom",
            SemanticRelationKind::ProposalAcceptedAtomRevision => "proposal_accepted_atom_revision",
        };
        out.insert(RelationProjectionRow::edge(
            kind,
            causal_seq(endpoint_seqs, &row.source_id, &row.target_id),
            row.source_id,
            row.target_id,
        ));
    }
}
