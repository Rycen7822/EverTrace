//! Integration-event resolution from typed integration evidence: merge,
//! rebase, cherry-pick and patch-transfer claims are gated by ancestry and
//! patch-equivalence proof.

use evertrace_domain::{
    ids::WorktreeId,
    repository::{
        IntegrationEvent, IntegrationKind, LineageAssessment, TransitionKind, WorktreeTransition,
    },
};
use evertrace_store::repository::RepositoryCurrentView;

use super::resolver::{
    RepositoryResolution, RepositoryResolveError, ResolutionKind, new_integration_id,
    new_transition_id,
};

pub struct IntegrationEvidence {
    pub source_worktree_instance_id: WorktreeId,
    pub destination_worktree_instance_id: WorktreeId,
    pub source_snapshot_id: evertrace_domain::ids::WorktreeSnapshotId,
    pub destination_snapshot_id: evertrace_domain::ids::WorktreeSnapshotId,
    pub kind: IntegrationKind,
    /// `Some(true)`/`Some(false)` from the bounded `merge-base --is-ancestor`
    /// probe; `None` when no ancestry probe was run.
    pub ancestry: Option<bool>,
    pub ancestry_evidence_ref: Option<String>,
    pub host_event_ref: Option<String>,
    pub patch_equivalence_refs: Vec<String>,
    pub conflict_resolution_detected: bool,
    pub revalidated_anchor_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub occurred_at_us: i64,
}

pub fn resolve_integration(
    view: &RepositoryCurrentView,
    evidence: &IntegrationEvidence,
) -> Result<RepositoryResolution, RepositoryResolveError> {
    if evidence.evidence_refs.is_empty() || evidence.occurred_at_us < 0 {
        return Err(RepositoryResolveError::InvalidEvidence);
    }
    let source_worktree = view
        .worktrees
        .get(&evidence.source_worktree_instance_id)
        .ok_or(RepositoryResolveError::InvalidInput)?;
    let destination_worktree = view
        .worktrees
        .get(&evidence.destination_worktree_instance_id)
        .ok_or(RepositoryResolveError::InvalidInput)?;
    let source_snapshot = view
        .snapshots
        .get(&evidence.source_snapshot_id)
        .ok_or(RepositoryResolveError::InvalidInput)?;
    let destination_snapshot = view
        .snapshots
        .get(&evidence.destination_snapshot_id)
        .ok_or(RepositoryResolveError::InvalidInput)?;
    if source_snapshot.worktree_instance_id != source_worktree.worktree_instance_id
        || destination_snapshot.worktree_instance_id != destination_worktree.worktree_instance_id
        || destination_worktree.current_snapshot_id
            != Some(destination_snapshot.worktree_snapshot_id)
    {
        return Err(RepositoryResolveError::InvalidEvidence);
    }
    let cross_repository =
        source_worktree.repository_instance_id != destination_worktree.repository_instance_id;
    let assessment = if evidence.kind.ancestry_based() {
        if evidence.ancestry == Some(false) {
            LineageAssessment::Contradicted
        } else if evidence.ancestry == Some(true) && evidence.host_event_ref.is_some() {
            let heads_match = evidence.kind != IntegrationKind::FastForward
                || source_snapshot.head_oid == destination_snapshot.head_oid;
            if heads_match {
                LineageAssessment::Proven
            } else {
                LineageAssessment::Contradicted
            }
        } else if evidence.ancestry == Some(true) {
            LineageAssessment::Partial
        } else {
            LineageAssessment::Unknown
        }
    } else {
        if evidence.patch_equivalence_refs.is_empty() {
            return Err(RepositoryResolveError::InsufficientEvidence);
        }
        if evidence.conflict_resolution_detected && evidence.revalidated_anchor_refs.is_empty() {
            // Commit/patch similarity alone never proves compatibility when
            // conflict resolution happened.
            LineageAssessment::Partial
        } else {
            LineageAssessment::Proven
        }
    };
    let assessment = if cross_repository && assessment == LineageAssessment::Proven {
        // repository_copied / reclone / cross-repository patch transfer can
        // only establish derived_from-level lineage.
        LineageAssessment::Partial
    } else {
        assessment
    };
    let mut commit_refs = Vec::new();
    if evidence.kind.ancestry_based() {
        for head in [
            source_snapshot.head_oid.as_ref(),
            destination_snapshot.head_oid.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            commit_refs.push(head.clone());
        }
        // Fast-forward leaves both snapshots on the same head.
        commit_refs.sort();
        commit_refs.dedup();
        if commit_refs.is_empty() {
            return Err(RepositoryResolveError::InsufficientEvidence);
        }
    }
    let mut evidence_refs = evidence.evidence_refs.clone();
    if let Some(reference) = &evidence.ancestry_evidence_ref {
        evidence_refs.push(reference.clone());
    }
    if let Some(reference) = &evidence.host_event_ref {
        evidence_refs.push(reference.clone());
    }
    evidence_refs.sort();
    evidence_refs.dedup();
    let integration_id = new_integration_id();
    let event = IntegrationEvent {
        integration_event_id: integration_id,
        repository_instance_id: destination_worktree.repository_instance_id,
        source_worktree_instance_id: source_worktree.worktree_instance_id,
        source_snapshot_id: source_snapshot.worktree_snapshot_id,
        destination_worktree_instance_id: destination_worktree.worktree_instance_id,
        destination_snapshot_id: destination_snapshot.worktree_snapshot_id,
        kind: evidence.kind,
        commit_refs,
        patch_equivalence_refs: evidence.patch_equivalence_refs.clone(),
        conflict_resolution_detected: evidence.conflict_resolution_detected,
        integrated_attempt_ids: Vec::new(),
        revalidated_anchor_refs: evidence.revalidated_anchor_refs.clone(),
        evidence_refs: evidence_refs.clone(),
        assessment,
    };
    event.validate().map_err(RepositoryResolveError::Domain)?;
    let transition_kind = if evidence.kind.ancestry_based() {
        TransitionKind::MergeIntegrated
    } else {
        TransitionKind::PatchTransferred
    };
    let transition_id = new_transition_id();
    let transition = WorktreeTransition {
        worktree_transition_id: transition_id,
        transition_revision: 1,
        predecessor_revision: None,
        from_worktree_instance_id: source_worktree.worktree_instance_id,
        from_snapshot_id: Some(source_snapshot.worktree_snapshot_id),
        to_worktree_instance_id: destination_worktree.worktree_instance_id,
        to_snapshot_id: Some(destination_snapshot.worktree_snapshot_id),
        kind: transition_kind,
        lineage_assessment: assessment,
        correction_reason: None,
        source_watermark: view.frontier,
        evidence_refs,
    };
    transition
        .validate()
        .map_err(RepositoryResolveError::Domain)?;
    let mut resolution = RepositoryResolution::empty(ResolutionKind::Create, None);
    resolution.integrations.push(event);
    resolution.transitions.push(transition);
    Ok(resolution)
}
