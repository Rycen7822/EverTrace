//! Repository/Worktree/Snapshot/Transition resolver: consumes typed probe
//! evidence plus the current store view and produces validated object
//! payloads. Object and command IDs are fresh UUIDv7 values allocated at
//! construction time; idempotent replay works because the caller re-submits
//! the already-constructed command and the writer deduplicates by command ID.

use std::collections::BTreeSet;

use evertrace_domain::{
    ids::{
        CommandId, IntegrationEventId, RepositoryId, WorktreeId, WorktreeSnapshotId,
        WorktreeTransitionId,
    },
    repository::{
        GitRegistrationState, IntegrationEvent, LineageAssessment, PathObservation,
        ProbeUnavailableReason, RepositoryError, RepositoryInstance, SnapshotCaptureStatus,
        SnapshotOmission, TransitionKind, WorktreeInstance, WorktreeKind, WorktreeLifecycle,
        WorktreeSnapshot, WorktreeTransition, lifecycle_successor_allowed,
    },
};
use evertrace_store::{
    JournalCommand, JournalEventDraft, JournalPayload, repository::RepositoryCurrentView,
};
use thiserror::Error;

use super::git_probe::{
    GIT_PROBE_SCHEMA_VERSION, GitOid, GitProbeEvidence, ProbeField, WorktreeAdminEntry,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionKind {
    Create,
    Successor,
    Correction,
    Ambiguous,
    NoDelta,
    Unavailable,
}

/// Discovery/scope hint for a path whose identity could not be probed. It is
/// never part of any persisted object; it only tells the caller that this
/// path was observed but is currently unresolvable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathHint {
    pub path: String,
    pub reason: ProbeUnavailableReason,
    pub evidence_refs: Vec<String>,
    pub occurred_at_us: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RepositoryResolution {
    pub kind: Option<ResolutionKind>,
    pub detail: Option<String>,
    /// Present iff `kind == Some(ResolutionKind::Unavailable)`.
    pub path_hint: Option<PathHint>,
    pub repositories: Vec<RepositoryInstance>,
    pub worktrees: Vec<WorktreeInstance>,
    pub snapshots: Vec<WorktreeSnapshot>,
    pub transitions: Vec<WorktreeTransition>,
    pub integrations: Vec<IntegrationEvent>,
}

pub(crate) fn new_repository_id() -> RepositoryId {
    RepositoryId::new_v7()
}

pub(crate) fn new_worktree_id() -> WorktreeId {
    WorktreeId::new_v7()
}

pub(crate) fn new_snapshot_id() -> WorktreeSnapshotId {
    WorktreeSnapshotId::new_v7()
}

pub(crate) fn new_transition_id() -> WorktreeTransitionId {
    WorktreeTransitionId::new_v7()
}

pub(crate) fn new_integration_id() -> IntegrationEventId {
    IntegrationEventId::new_v7()
}

impl RepositoryResolution {
    pub(crate) fn empty(kind: ResolutionKind, detail: Option<String>) -> Self {
        Self {
            kind: Some(kind),
            detail,
            ..Self::default()
        }
    }

    fn unavailable(reason: ProbeUnavailableReason, evidence: &GitProbeEvidence) -> Self {
        let mut resolution = Self::empty(ResolutionKind::Unavailable, None);
        resolution.path_hint = Some(PathHint {
            path: evidence.candidate_path.clone(),
            reason,
            evidence_refs: evidence.evidence_refs.clone(),
            occurred_at_us: evidence.occurred_at_us,
        });
        resolution
    }

    /// Materializes the journal command for this resolution. The command ID
    /// is a fresh UUIDv7 allocated once here; a lost-ack retry re-submits
    /// this same command and is deduplicated by the writer's replay path.
    pub fn journal_command(
        &self,
        occurred_at_us: i64,
        effective_config_hash: [u8; 32],
        algorithm_revision: &str,
    ) -> Result<Option<JournalCommand>, RepositoryResolveError> {
        let payloads = self.payloads();
        if payloads.is_empty() {
            return Ok(None);
        }
        let command_id = CommandId::new_v7();
        let events = payloads
            .into_iter()
            .map(|payload| {
                JournalEventDraft::runtime(
                    occurred_at_us,
                    effective_config_hash,
                    algorithm_revision,
                    payload,
                )
            })
            .collect();
        JournalCommand::new(command_id, events)
            .map(Some)
            .map_err(|_| RepositoryResolveError::InvalidInput)
    }

    fn payloads(&self) -> Vec<JournalPayload> {
        self.repositories
            .iter()
            .cloned()
            .map(|value| JournalPayload::RepositoryInstanceRecorded(Box::new(value)))
            .chain(
                self.worktrees
                    .iter()
                    .cloned()
                    .map(|value| JournalPayload::WorktreeInstanceRecorded(Box::new(value))),
            )
            .chain(
                self.snapshots
                    .iter()
                    .cloned()
                    .map(|value| JournalPayload::WorktreeSnapshotRecorded(Box::new(value))),
            )
            .chain(
                self.transitions
                    .iter()
                    .cloned()
                    .map(|value| JournalPayload::WorktreeTransitionRecorded(Box::new(value))),
            )
            .chain(
                self.integrations
                    .iter()
                    .cloned()
                    .map(|value| JournalPayload::IntegrationEventRecorded(Box::new(value))),
            )
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RepositoryResolveError {
    #[error("resolver input is invalid")]
    InvalidInput,
    #[error("probe evidence is invalid for resolution")]
    InvalidEvidence,
    #[error("typed evidence is insufficient to record the event")]
    InsufficientEvidence,
    #[error("domain validation failed")]
    Domain(RepositoryError),
}

pub struct RepositoryResolveInput<'a> {
    pub view: &'a RepositoryCurrentView,
    pub evidence: &'a GitProbeEvidence,
    pub derived_from_hint: Option<RepositoryId>,
}

pub fn resolve_repository(
    input: &RepositoryResolveInput<'_>,
) -> Result<RepositoryResolution, RepositoryResolveError> {
    let evidence = input.evidence;
    if evidence.probe_schema_version != GIT_PROBE_SCHEMA_VERSION
        || evidence.evidence_refs.is_empty()
        || evidence.occurred_at_us < 0
    {
        return Err(RepositoryResolveError::InvalidEvidence);
    }
    if let Some(reason) = evidence.unavailable_reason {
        return Ok(resolve_unavailable(input, reason));
    }
    resolve_established(input)
}

fn resolve_unavailable(
    input: &RepositoryResolveInput<'_>,
    reason: ProbeUnavailableReason,
) -> RepositoryResolution {
    let evidence = input.evidence;
    let path = &evidence.candidate_path;
    let known_worktree = input
        .view
        .worktrees
        .values()
        .find(|worktree| {
            !worktree.lifecycle.is_terminal() && worktree.current_path.as_deref() == Some(path)
        })
        .cloned();
    match reason {
        ProbeUnavailableReason::TrustDenied => {
            if known_worktree.is_some() {
                // Trust is orthogonal to worktree lifecycle: no state change.
                RepositoryResolution::empty(ResolutionKind::NoDelta, Some("trust_denied".into()))
            } else {
                RepositoryResolution::unavailable(reason, evidence)
            }
        }
        ProbeUnavailableReason::PathMissing => {
            if let Some(worktree) = known_worktree {
                if worktree.lifecycle == WorktreeLifecycle::Missing {
                    // Repeated absence of an already-missing worktree is not
                    // a new fact: no successor revision, no second transition.
                    return RepositoryResolution::empty(
                        ResolutionKind::NoDelta,
                        Some("path_missing".into()),
                    );
                }
                // Temporarily inaccessible or no longer verifiable: missing,
                // never removed.
                let mut resolution = RepositoryResolution::empty(ResolutionKind::Successor, None);
                let successor = worktree_successor(
                    &worktree,
                    WorktreeLifecycle::Missing,
                    worktree.current_path.clone(),
                    worktree.git_admin_path_history.clone(),
                    registration_for_missing(&worktree),
                    worktree.current_snapshot_id,
                    None,
                    evidence,
                );
                let transition = transition_for(
                    &successor,
                    TransitionKind::WorktreeMissing,
                    worktree.current_snapshot_id,
                    None,
                    assessment_of(evidence),
                    None,
                    input.view.frontier,
                    evidence,
                );
                resolution.worktrees.push(successor);
                resolution.transitions.push(transition);
                resolution
            } else {
                RepositoryResolution::unavailable(reason, evidence)
            }
        }
        ProbeUnavailableReason::NonGit
        | ProbeUnavailableReason::PermissionDenied
        | ProbeUnavailableReason::CorruptAdminMetadata
        | ProbeUnavailableReason::Timeout
        | ProbeUnavailableReason::OutputLimitExceeded
        | ProbeUnavailableReason::SpawnFailed => {
            // Identity is unavailable; no RepositoryInstance, WorktreeInstance,
            // Snapshot, Transition or IntegrationEvent is ever fabricated for
            // an unprobed path. A known worktree keeps its pointers untouched.
            if known_worktree.is_some() {
                RepositoryResolution::empty(
                    ResolutionKind::Ambiguous,
                    Some("identity_unavailable".into()),
                )
            } else {
                RepositoryResolution::unavailable(reason, evidence)
            }
        }
    }
}

fn resolve_established(
    input: &RepositoryResolveInput<'_>,
) -> Result<RepositoryResolution, RepositoryResolveError> {
    let evidence = input.evidence;
    let view = input.view;
    let root = evidence
        .worktree_root
        .clone()
        .ok_or(RepositoryResolveError::InvalidEvidence)?;
    let (Some(filesystem), Some(format)) = (evidence.common_dir_filesystem, evidence.object_format)
    else {
        // Essential continuity evidence is missing: never guess identity.
        return Ok(RepositoryResolution::empty(
            ResolutionKind::Ambiguous,
            Some("identity_evidence_incomplete".into()),
        ));
    };
    let identity_matches = view
        .repositories
        .values()
        .filter(|repository| repository.common_dir_filesystem == Some(filesystem))
        .collect::<Vec<_>>();
    if identity_matches
        .iter()
        .any(|repository| repository.object_format != Some(format))
    {
        // Same filesystem identity with a different object format is a
        // contradiction (re-init would change the inode).
        return Ok(RepositoryResolution::empty(
            ResolutionKind::Ambiguous,
            Some("object_format_contradiction".into()),
        ));
    }
    if identity_matches.is_empty() {
        let path_matches = view
            .repositories
            .values()
            .filter(|repository| repository.current_path == root)
            .collect::<Vec<_>>();
        if path_matches.len() > 1 {
            return Ok(RepositoryResolution::empty(
                ResolutionKind::Ambiguous,
                Some("multiple_identity_claimants".into()),
            ));
        }
        if let Some(other) = path_matches.first() {
            // Same path, different filesystem identity: re-init or copy at a
            // known path. Always a new instance.
            return create_repository(input, &root, Some(other.repository_id));
        }
        let hint = input
            .derived_from_hint
            .filter(|hint| view.repositories.contains_key(hint));
        return create_repository(input, &root, hint);
    }
    // Filesystem identity shared by several instances (same inode reused by
    // an unrelated history) resolves per candidate: exactly one positive
    // continuity proof wins; none or several never guesses.
    let complete = continuity_probe_complete(evidence);
    let positive = if complete {
        identity_matches
            .iter()
            .copied()
            .filter(|repository| candidate_continuity_positive(input, repository))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    match positive.as_slice() {
        [repository] => resolve_existing_repository(input, repository, &root),
        [] if !complete => Ok(RepositoryResolution::empty(
            ResolutionKind::Ambiguous,
            Some("continuity_evidence_incomplete".into()),
        )),
        [] => {
            let derived_from = match identity_matches.as_slice() {
                // A single identity candidate keeps the re-init semantics:
                // the new instance derives from the previous occupant.
                [repository] => Some(repository.repository_id),
                // Several candidates: only an explicit caller hint naming an
                // instance present in the view may supply lineage; never
                // guess by time, path or collection order.
                _ => input
                    .derived_from_hint
                    .filter(|hint| view.repositories.contains_key(hint)),
            };
            create_repository(input, &root, derived_from)
        }
        _ => Ok(RepositoryResolution::empty(
            ResolutionKind::Ambiguous,
            Some("multiple_identity_claimants".into()),
        )),
    }
}

/// Evidence-level continuity probe completeness: the ref tips and the
/// ancestry probe were not omitted. An unborn HEAD is complete on its own.
fn continuity_probe_complete(evidence: &GitProbeEvidence) -> bool {
    !evidence.omissions.iter().any(|omission| {
        matches!(
            omission.field,
            ProbeField::RefTips | ProbeField::ContinuityAncestry
        )
    })
}

/// Positive continuity evidence binding this specific repository instance:
/// the same HEAD, a probe-proven ancestor recorded in *this* instance's
/// history, or a verifiable ref overlap with its recorded HEADs. An unborn
/// candidate is continuous only with an instance that is still equally
/// unborn. Path, branch names, commit messages, temporal proximity or remote
/// similarity never count.
fn candidate_continuity_positive(
    input: &RepositoryResolveInput<'_>,
    repository: &RepositoryInstance,
) -> bool {
    let evidence = input.evidence;
    let known_heads = known_repository_heads(input.view, repository.repository_id);
    match &evidence.head_oid {
        Some(head) => {
            known_heads.contains(head.as_str())
                || evidence
                    .head_ancestors
                    .iter()
                    .any(|oid| known_heads.contains(oid.as_str()))
                || evidence
                    .ref_tips
                    .iter()
                    .any(|(_, oid)| known_heads.contains(oid.as_str()))
        }
        None => {
            evidence.ref_tips.is_empty()
                && known_heads.is_empty()
                && input
                    .view
                    .worktrees
                    .values()
                    .filter(|worktree| worktree.repository_instance_id == repository.repository_id)
                    .filter_map(|worktree| worktree.current_snapshot_id)
                    .filter_map(|id| input.view.snapshots.get(&id))
                    .any(|snapshot| snapshot.head_oid.is_none())
        }
    }
}

/// HEAD OIDs recorded by snapshots of every worktree of this repository.
fn known_repository_heads(
    view: &RepositoryCurrentView,
    repository_id: RepositoryId,
) -> BTreeSet<String> {
    view.snapshots
        .values()
        .filter(|snapshot| {
            view.worktrees
                .get(&snapshot.worktree_instance_id)
                .is_some_and(|worktree| worktree.repository_instance_id == repository_id)
        })
        .filter_map(|snapshot| snapshot.head_oid.clone())
        .collect()
}

fn resolve_existing_repository(
    input: &RepositoryResolveInput<'_>,
    repository: &RepositoryInstance,
    root: &str,
) -> Result<RepositoryResolution, RepositoryResolveError> {
    let evidence = input.evidence;
    let view = input.view;
    let mut resolution = RepositoryResolution::empty(ResolutionKind::NoDelta, None);
    let moved = repository.current_path != root;
    let remotes_changed = repository.remote_fingerprints != evidence.remote_fingerprints;
    if !continuity_probe_complete(evidence) {
        // An incomplete continuity probe never rewrites identity either way.
        return Ok(RepositoryResolution::empty(
            ResolutionKind::Ambiguous,
            Some("continuity_evidence_incomplete".into()),
        ));
    }
    if !candidate_continuity_positive(input, repository) {
        // Same filesystem identity but no positive continuity evidence (same
        // HEAD, proven ancestry or verifiable ref overlap): this is a
        // different repository reusing the identity, recorded as a new
        // instance with derived_from lineage.
        return create_repository(input, root, Some(repository.repository_id));
    }
    if moved {
        // Only Git-verifiable positive continuity reaches this branch, so a
        // proven move is always fully proven.
        let assessment = LineageAssessment::Proven;
        let mut history = repository.path_history.clone();
        history.push(path_observation(root, evidence));
        let successor = RepositoryInstance {
            repository_revision: repository.repository_revision + 1,
            predecessor_revision: Some(repository.repository_revision),
            current_path: root.to_owned(),
            path_history: history,
            git_common_dir_path: evidence.common_dir.clone(),
            identity_evidence_refs: union_refs(
                &repository.identity_evidence_refs,
                &evidence.evidence_refs,
            ),
            remote_fingerprints: evidence.remote_fingerprints.clone(),
            recorded_at_us: evidence.occurred_at_us,
            ..repository.clone()
        };
        successor
            .validate()
            .map_err(RepositoryResolveError::Domain)?;
        resolution.repositories.push(successor);
        resolution.kind = Some(ResolutionKind::Successor);
        resolution.detail = Some("repository_moved".into());
        let anchor = view
            .worktrees
            .values()
            .find(|worktree| {
                worktree.repository_instance_id == repository.repository_id
                    && worktree.kind == WorktreeKind::Main
            })
            .or_else(|| {
                view.worktrees
                    .values()
                    .find(|worktree| worktree.repository_instance_id == repository.repository_id)
            });
        if let Some(anchor) = anchor {
            let transition = transition_for_ids(
                anchor.worktree_instance_id,
                anchor.current_snapshot_id,
                anchor.worktree_instance_id,
                None,
                TransitionKind::RepositoryMoved,
                assessment,
                None,
                view.frontier,
                evidence,
            )?;
            resolution.transitions.push(transition);
        }
        reconcile_worktrees(
            input,
            repository.repository_id,
            assessment,
            true,
            &mut resolution,
        )?;
    } else if remotes_changed {
        let successor = RepositoryInstance {
            repository_revision: repository.repository_revision + 1,
            predecessor_revision: Some(repository.repository_revision),
            remote_fingerprints: evidence.remote_fingerprints.clone(),
            identity_evidence_refs: union_refs(
                &repository.identity_evidence_refs,
                &evidence.evidence_refs,
            ),
            recorded_at_us: evidence.occurred_at_us,
            ..repository.clone()
        };
        successor
            .validate()
            .map_err(RepositoryResolveError::Domain)?;
        resolution.repositories.push(successor);
        resolution.kind = Some(ResolutionKind::Successor);
        reconcile_worktrees(
            input,
            repository.repository_id,
            assessment_of(evidence),
            false,
            &mut resolution,
        )?;
    } else {
        reconcile_worktrees(
            input,
            repository.repository_id,
            assessment_of(evidence),
            false,
            &mut resolution,
        )?;
    }
    finalize_kind(&mut resolution);
    Ok(resolution)
}

fn create_repository(
    input: &RepositoryResolveInput<'_>,
    root: &str,
    derived_from: Option<RepositoryId>,
) -> Result<RepositoryResolution, RepositoryResolveError> {
    let evidence = input.evidence;
    let filesystem = evidence
        .common_dir_filesystem
        .ok_or(RepositoryResolveError::InvalidEvidence)?;
    let format = evidence
        .object_format
        .ok_or(RepositoryResolveError::InvalidEvidence)?;
    let repository_id = new_repository_id();
    let repository = RepositoryInstance {
        repository_id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: root.to_owned(),
        path_history: vec![path_observation(root, evidence)],
        git_common_dir_path: evidence.common_dir.clone(),
        common_dir_filesystem: Some(filesystem),
        object_format: Some(format),
        remote_fingerprints: evidence.remote_fingerprints.clone(),
        derived_from,
        identity_evidence_refs: evidence.evidence_refs.clone(),
        recorded_at_us: evidence.occurred_at_us,
    };
    repository
        .validate()
        .map_err(RepositoryResolveError::Domain)?;
    let mut resolution = RepositoryResolution::empty(ResolutionKind::Create, None);
    resolution.repositories.push(repository);
    let assessment = assessment_of(evidence);
    let candidate_entry = candidate_entry(evidence, root)?;
    let main = create_worktree(
        &mut resolution,
        input,
        repository_id,
        candidate_entry,
        None,
        assessment,
    )?;
    if let Some(source_repo) = derived_from {
        // repository_copied / reclone: derived_from lineage only, never a
        // proven continuity of the same instance.
        let source_worktree = input
            .view
            .worktrees
            .values()
            .find(|worktree| {
                worktree.repository_instance_id == source_repo
                    && worktree.kind == WorktreeKind::Main
            })
            .or_else(|| {
                input
                    .view
                    .worktrees
                    .values()
                    .find(|worktree| worktree.repository_instance_id == source_repo)
            });
        if let (Some(source), Some(destination)) = (source_worktree, main.as_ref()) {
            let transition = transition_for_ids(
                source.worktree_instance_id,
                source.current_snapshot_id,
                destination.worktree_instance_id,
                // repository_copied records derived_from lineage only; it
                // carries no snapshot binding on the destination side.
                None,
                TransitionKind::RepositoryCopied,
                LineageAssessment::Partial,
                None,
                input.view.frontier,
                evidence,
            )?;
            resolution.transitions.push(transition);
        }
    }
    for entry in evidence.worktree_entries.clone() {
        if entry.path == candidate_entry.path {
            continue;
        }
        if entry.gitdir.is_none() {
            continue;
        }
        create_worktree(
            &mut resolution,
            input,
            repository_id,
            &entry,
            recreated_from(input.view, &entry),
            assessment,
        )?;
    }
    finalize_kind(&mut resolution);
    Ok(resolution)
}

#[allow(clippy::too_many_arguments)]
fn reconcile_worktrees(
    input: &RepositoryResolveInput<'_>,
    repository_id: RepositoryId,
    repository_assessment: LineageAssessment,
    repository_moved: bool,
    resolution: &mut RepositoryResolution,
) -> Result<(), RepositoryResolveError> {
    let evidence = input.evidence;
    let view = input.view;
    let root = evidence
        .worktree_root
        .clone()
        .ok_or(RepositoryResolveError::InvalidEvidence)?;
    let candidate_entry = candidate_entry(evidence, &root)?;
    let known = view
        .worktrees
        .values()
        .filter(|worktree| worktree.repository_instance_id == repository_id)
        .cloned()
        .collect::<Vec<_>>();
    let mut matched_admin_paths = BTreeSet::new();

    // Candidate worktree: full typed evidence exists for it.
    let candidate_admin = candidate_entry
        .gitdir
        .clone()
        .ok_or(RepositoryResolveError::InvalidEvidence)?;
    let candidate_match = known.iter().find(|worktree| {
        !worktree.lifecycle.is_terminal()
            && admin_matches(worktree, &candidate_admin, view, repository_id, evidence)
    });
    let candidate_id = candidate_match.map(|worktree| worktree.worktree_instance_id);
    if let Some(current) = candidate_match {
        matched_admin_paths.insert(candidate_admin.clone());
        reconcile_existing_worktree(
            input,
            current,
            candidate_entry,
            repository_assessment,
            resolution,
        )?;
    } else {
        let recreated = recreated_from(view, candidate_entry);
        create_worktree(
            resolution,
            input,
            repository_id,
            candidate_entry,
            recreated,
            repository_assessment,
        )?;
    }

    // Passive reconciliation of other known worktrees from the complete
    // worktree list.
    let common_dir = evidence.common_dir.clone();
    for worktree in known.iter().filter(|worktree| {
        !worktree.lifecycle.is_terminal() && Some(worktree.worktree_instance_id) != candidate_id
    }) {
        let Some(admin) = worktree.git_admin_path_history.last() else {
            continue;
        };
        let expected_admin = if repository_moved {
            common_dir
                .as_ref()
                .map(|common| rebase_admin_path(&admin.path, view, repository_id, common))
        } else {
            Some(admin.path.clone())
        };
        let entry = expected_admin
            .as_ref()
            .and_then(|expected| {
                evidence
                    .worktree_entries
                    .iter()
                    .find(|entry| entry.gitdir.as_deref() == Some(expected.as_str()))
            })
            .or_else(|| {
                // Prunable entries carry no probed gitdir (the worktree path
                // may be gone); Git's own prunable flag on the known path is
                // positive evidence. Path identity is only meaningful when
                // the repository itself did not move.
                if repository_moved {
                    None
                } else {
                    evidence.worktree_entries.iter().find(|entry| {
                        entry.prunable
                            && entry.path == worktree.current_path.clone().unwrap_or_default()
                    })
                }
            });
        match entry {
            Some(entry) => {
                matched_admin_paths.insert(entry.gitdir.clone().unwrap_or_default());
                if entry.prunable {
                    if worktree.lifecycle == WorktreeLifecycle::Active {
                        let successor = worktree_successor(
                            worktree,
                            WorktreeLifecycle::Missing,
                            worktree.current_path.clone(),
                            worktree.git_admin_path_history.clone(),
                            GitRegistrationState::Prunable,
                            worktree.current_snapshot_id,
                            None,
                            evidence,
                        );
                        let transition = transition_for(
                            &successor,
                            TransitionKind::WorktreeMissing,
                            worktree.current_snapshot_id,
                            None,
                            LineageAssessment::Proven,
                            None,
                            view.frontier,
                            evidence,
                        );
                        resolution.worktrees.push(successor);
                        resolution.transitions.push(transition);
                    }
                } else if entry.path != worktree.current_path.clone().unwrap_or_default() {
                    let mut admin_history = worktree.git_admin_path_history.clone();
                    if let Some(expected) = &expected_admin
                        && expected != &admin.path
                    {
                        admin_history.push(path_observation(expected, evidence));
                    }
                    let mut path_history = worktree.path_history.clone();
                    path_history.push(path_observation(&entry.path, evidence));
                    let successor = WorktreeInstance {
                        worktree_revision: worktree.worktree_revision + 1,
                        predecessor_revision: Some(worktree.worktree_revision),
                        lifecycle: WorktreeLifecycle::Active,
                        current_path: Some(entry.path.clone()),
                        path_history,
                        git_admin_path_history: admin_history,
                        git_registration_state: registration_of(entry),
                        recorded_at_us: evidence.occurred_at_us,
                        ..worktree.clone()
                    };
                    successor
                        .validate()
                        .map_err(RepositoryResolveError::Domain)?;
                    let transition = transition_for(
                        &successor,
                        TransitionKind::PathMoved,
                        worktree.current_snapshot_id,
                        None,
                        LineageAssessment::Proven,
                        None,
                        view.frontier,
                        evidence,
                    );
                    resolution.worktrees.push(successor);
                    resolution.transitions.push(transition);
                }
            }
            None => {
                if !evidence.worktree_list_complete {
                    continue;
                }
                let admin_probe = evidence
                    .admin_path_probes
                    .iter()
                    .find(|probe| Some(&probe.path) == expected_admin.as_ref());
                match admin_probe {
                    Some(probe) if !probe.present => {
                        // Positive removal evidence: admin record gone from the
                        // complete list and admin directory missing on disk.
                        let terminal =
                            if worktree.git_registration_state == GitRegistrationState::Prunable {
                                WorktreeLifecycle::Pruned
                            } else {
                                WorktreeLifecycle::Removed
                            };
                        let successor = worktree_successor(
                            worktree,
                            terminal,
                            None,
                            worktree.git_admin_path_history.clone(),
                            GitRegistrationState::Absent,
                            worktree.current_snapshot_id,
                            Some(evidence.evidence_refs[0].clone()),
                            evidence,
                        );
                        let kind = if terminal == WorktreeLifecycle::Pruned {
                            TransitionKind::WorktreePruned
                        } else {
                            TransitionKind::WorktreeRemoved
                        };
                        let transition = transition_for(
                            &successor,
                            kind,
                            worktree.current_snapshot_id,
                            None,
                            LineageAssessment::Proven,
                            None,
                            view.frontier,
                            evidence,
                        );
                        resolution.worktrees.push(successor);
                        resolution.transitions.push(transition);
                    }
                    _ => {
                        // Admin record disagreement without positive evidence:
                        // do not guess.
                    }
                }
            }
        }
    }

    // Recreated worktrees at previously terminal paths.
    for entry in &evidence.worktree_entries {
        if entry.gitdir.is_none()
            || matched_admin_paths.contains(entry.gitdir.as_deref().unwrap_or_default())
            || known.iter().any(|worktree| {
                !worktree.lifecycle.is_terminal()
                    && worktree
                        .git_admin_path_history
                        .last()
                        .map(|path| &path.path)
                        == entry.gitdir.as_ref()
            })
        {
            continue;
        }
        if entry.path == root {
            continue;
        }
        if let Some(terminal) = recreated_from(view, entry) {
            create_worktree(
                resolution,
                input,
                repository_id,
                entry,
                Some(terminal),
                repository_assessment,
            )?;
        }
    }
    Ok(())
}

fn reconcile_existing_worktree(
    input: &RepositoryResolveInput<'_>,
    current: &WorktreeInstance,
    entry: &WorktreeAdminEntry,
    repository_assessment: LineageAssessment,
    resolution: &mut RepositoryResolution,
) -> Result<(), RepositoryResolveError> {
    let evidence = input.evidence;
    let view = input.view;
    let current_admin = current
        .git_admin_path_history
        .last()
        .map(|path| path.path.clone())
        .unwrap_or_default();
    let entry_admin = entry.gitdir.clone().unwrap_or_default();
    let path_changed = current.current_path.as_deref() != Some(entry.path.as_str());
    let admin_changed = current_admin != entry_admin;
    let registration = registration_of(entry);
    let repaired = current.lifecycle == WorktreeLifecycle::Missing || admin_changed;
    let mut successor = None;
    if current.lifecycle == WorktreeLifecycle::Missing
        || path_changed
        || admin_changed
        || current.git_registration_state != registration
    {
        let mut path_history = current.path_history.clone();
        if path_changed {
            path_history.push(path_observation(&entry.path, evidence));
        }
        let mut admin_history = current.git_admin_path_history.clone();
        if admin_changed {
            admin_history.push(path_observation(&entry_admin, evidence));
        }
        let value = WorktreeInstance {
            worktree_revision: current.worktree_revision + 1,
            predecessor_revision: Some(current.worktree_revision),
            lifecycle: WorktreeLifecycle::Active,
            current_path: Some(entry.path.clone()),
            path_history,
            git_admin_path_history: admin_history,
            git_registration_state: registration,
            recorded_at_us: evidence.occurred_at_us,
            ..current.clone()
        };
        value.validate().map_err(RepositoryResolveError::Domain)?;
        successor = Some(value);
    }

    // Snapshot diff for the candidate worktree.
    let current_snapshot = current
        .current_snapshot_id
        .and_then(|id| view.snapshots.get(&id));
    let state_changed = current_snapshot.is_none_or(|snapshot| {
        snapshot.head_oid.as_deref() != evidence.head_oid.as_ref().map(GitOid::as_str)
            || snapshot.tree_oid.as_deref() != evidence.tree_oid.as_ref().map(GitOid::as_str)
            || snapshot.branch_ref != evidence.branch_ref
            || Some(snapshot.detached_head) != evidence.detached_head
            || snapshot.tracked_diff_digest != evidence.tracked_diff_digest
            || snapshot.index_digest != evidence.index_digest
            || snapshot.untracked_manifest_digest != evidence.untracked_manifest_digest
            || snapshot.git_operation != evidence.git_operation
    });
    let snapshot = if state_changed {
        let snapshot = snapshot_from_evidence(
            successor
                .as_ref()
                .map_or(current.worktree_instance_id, |value| {
                    value.worktree_instance_id
                }),
            evidence,
        )?;
        Some(snapshot)
    } else {
        None
    };

    let effective = successor.clone().unwrap_or_else(|| current.clone());
    if let Some(snapshot) = &snapshot {
        let mut updated = effective.clone();
        updated.current_snapshot_id = Some(snapshot.worktree_snapshot_id);
        if successor.is_none() {
            updated.worktree_revision = current.worktree_revision + 1;
            updated.predecessor_revision = Some(current.worktree_revision);
            updated.recorded_at_us = evidence.occurred_at_us;
        }
        updated.validate().map_err(RepositoryResolveError::Domain)?;
        let kind = state_transition_kind(current_snapshot, snapshot);
        if let Some(kind) = kind {
            let transition = transition_for(
                &updated,
                kind,
                current.current_snapshot_id,
                Some(snapshot.worktree_snapshot_id),
                repository_assessment,
                None,
                view.frontier,
                evidence,
            );
            resolution.transitions.push(transition);
        }
        resolution.snapshots.push(snapshot.clone());
        resolution.worktrees.push(updated);
    } else if let Some(value) = successor {
        let kind = if repaired {
            TransitionKind::WorktreeRepaired
        } else {
            TransitionKind::PathMoved
        };
        if repaired || path_changed {
            let transition = transition_for(
                &value,
                kind,
                current.current_snapshot_id,
                None,
                LineageAssessment::Proven,
                None,
                view.frontier,
                evidence,
            );
            resolution.transitions.push(transition);
        }
        resolution.worktrees.push(value);
    }
    Ok(())
}

fn create_worktree(
    resolution: &mut RepositoryResolution,
    input: &RepositoryResolveInput<'_>,
    repository_id: RepositoryId,
    entry: &WorktreeAdminEntry,
    recreated_from: Option<WorktreeId>,
    assessment: LineageAssessment,
) -> Result<Option<WorktreeInstance>, RepositoryResolveError> {
    let evidence = input.evidence;
    let Some(gitdir) = entry.gitdir.clone() else {
        return Ok(None);
    };
    let kind = if evidence.common_dir.as_deref() == Some(gitdir.as_str()) {
        WorktreeKind::Main
    } else {
        WorktreeKind::Linked
    };
    let worktree_id = new_worktree_id();
    let is_candidate = evidence.worktree_root.as_deref() == Some(entry.path.as_str());
    let snapshot = if is_candidate {
        Some(snapshot_from_evidence(worktree_id, evidence)?)
    } else {
        None
    };
    let worktree = WorktreeInstance {
        worktree_instance_id: worktree_id,
        worktree_revision: 1,
        predecessor_revision: None,
        repository_instance_id: repository_id,
        kind,
        lifecycle: WorktreeLifecycle::Active,
        current_path: Some(entry.path.clone()),
        path_history: vec![path_observation(&entry.path, evidence)],
        git_admin_path_history: vec![path_observation(&gitdir, evidence)],
        git_registration_state: registration_of(entry),
        current_snapshot_id: snapshot.as_ref().map(|value| value.worktree_snapshot_id),
        created_event_ref: evidence.evidence_refs[0].clone(),
        terminal_event_ref: None,
        recreated_from_worktree_instance_id: recreated_from,
        recorded_at_us: evidence.occurred_at_us,
    };
    worktree
        .validate()
        .map_err(RepositoryResolveError::Domain)?;
    if let Some(snapshot) = snapshot {
        resolution.snapshots.push(snapshot);
    }
    if let Some(previous) = recreated_from {
        let transition = transition_for_ids(
            previous,
            input
                .view
                .worktrees
                .get(&previous)
                .and_then(|value| value.current_snapshot_id),
            worktree.worktree_instance_id,
            // worktree_recreated carries no snapshot binding on the new
            // instance side; lineage is derived_from-style only.
            None,
            TransitionKind::WorktreeRecreated,
            assessment,
            None,
            input.view.frontier,
            evidence,
        )?;
        resolution.transitions.push(transition);
    }
    resolution.worktrees.push(worktree.clone());
    Ok(Some(worktree))
}

fn recreated_from(view: &RepositoryCurrentView, entry: &WorktreeAdminEntry) -> Option<WorktreeId> {
    view.worktrees
        .values()
        .filter(|worktree| worktree.lifecycle.is_terminal())
        .find(|worktree| {
            worktree
                .path_history
                .last()
                .is_some_and(|path| path.path == entry.path)
        })
        .map(|worktree| worktree.worktree_instance_id)
}

fn admin_matches(
    worktree: &WorktreeInstance,
    candidate_admin: &str,
    view: &RepositoryCurrentView,
    repository_id: RepositoryId,
    evidence: &GitProbeEvidence,
) -> bool {
    if worktree
        .git_admin_path_history
        .last()
        .is_some_and(|path| path.path == candidate_admin)
    {
        return true;
    }
    // A proven repository move rebases admin paths from the old common dir to
    // the new one; only then is the rebased admin path valid evidence.
    let Some(common) = &evidence.common_dir else {
        return false;
    };
    worktree.git_admin_path_history.last().is_some_and(|path| {
        rebase_admin_path(&path.path, view, repository_id, common) == candidate_admin
    })
}

fn rebase_admin_path(
    admin: &str,
    view: &RepositoryCurrentView,
    repository_id: RepositoryId,
    new_common: &str,
) -> String {
    let old_common = view
        .repositories
        .get(&repository_id)
        .and_then(|repository| repository.git_common_dir_path.clone());
    match old_common {
        Some(old) if admin.starts_with(&old) => format!("{new_common}{}", &admin[old.len()..]),
        _ => admin.to_owned(),
    }
}

fn candidate_entry<'a>(
    evidence: &'a GitProbeEvidence,
    root: &str,
) -> Result<&'a WorktreeAdminEntry, RepositoryResolveError> {
    evidence
        .worktree_entries
        .iter()
        .find(|entry| entry.path == root)
        .ok_or(RepositoryResolveError::InvalidEvidence)
}

fn registration_of(entry: &WorktreeAdminEntry) -> GitRegistrationState {
    if entry.prunable {
        GitRegistrationState::Prunable
    } else if entry.locked {
        GitRegistrationState::Locked
    } else {
        GitRegistrationState::Registered
    }
}

fn registration_for_missing(worktree: &WorktreeInstance) -> GitRegistrationState {
    match worktree.git_registration_state {
        GitRegistrationState::Locked => GitRegistrationState::Locked,
        _ => GitRegistrationState::Unknown,
    }
}

fn state_transition_kind(
    current: Option<&WorktreeSnapshot>,
    next: &WorktreeSnapshot,
) -> Option<TransitionKind> {
    let current = current?;
    if current.branch_ref != next.branch_ref
        && next.branch_ref.is_some()
        && current.branch_ref.is_some()
    {
        Some(TransitionKind::BranchSwitched)
    } else if current.detached_head != next.detached_head
        || current.branch_ref.is_some() != next.branch_ref.is_some()
    {
        Some(TransitionKind::DetachedOrAttached)
    } else if current.head_oid != next.head_oid {
        Some(TransitionKind::HeadAdvanced)
    } else {
        None
    }
}

fn snapshot_from_evidence(
    worktree_id: WorktreeId,
    evidence: &GitProbeEvidence,
) -> Result<WorktreeSnapshot, RepositoryResolveError> {
    let omissions = evidence
        .omissions
        .iter()
        .filter_map(|omission| {
            omission
                .field
                .snapshot_field()
                .map(|field| SnapshotOmission {
                    field,
                    reason: omission.reason,
                })
        })
        .collect::<Vec<_>>();
    let capture_status = if evidence.unavailable_reason.is_some() {
        SnapshotCaptureStatus::Unavailable
    } else if omissions.is_empty() {
        SnapshotCaptureStatus::Complete
    } else {
        SnapshotCaptureStatus::Partial
    };
    let snapshot_id = new_snapshot_id();
    let snapshot = WorktreeSnapshot {
        worktree_snapshot_id: snapshot_id,
        worktree_instance_id: worktree_id,
        head_oid: evidence
            .head_oid
            .as_ref()
            .map(|oid| oid.as_str().to_owned()),
        tree_oid: evidence
            .tree_oid
            .as_ref()
            .map(|oid| oid.as_str().to_owned()),
        branch_ref: evidence.branch_ref.clone(),
        detached_head: evidence.detached_head.unwrap_or(false),
        tracked_diff_digest: evidence.tracked_diff_digest.clone(),
        index_digest: evidence.index_digest.clone(),
        untracked_manifest_digest: evidence.untracked_manifest_digest.clone(),
        relevant_anchor_digests: Vec::new(),
        dependency_fingerprints: Vec::new(),
        toolchain_fingerprint: None,
        git_operation: evidence.git_operation,
        captured_at_us: evidence.occurred_at_us,
        evidence_refs: evidence.evidence_refs.clone(),
        capture_status,
        omission_reasons: omissions,
    };
    snapshot
        .validate()
        .map_err(RepositoryResolveError::Domain)?;
    Ok(snapshot)
}

#[allow(clippy::too_many_arguments)]
fn worktree_successor(
    current: &WorktreeInstance,
    lifecycle: WorktreeLifecycle,
    current_path: Option<String>,
    admin_history: Vec<PathObservation>,
    registration: GitRegistrationState,
    current_snapshot_id: Option<evertrace_domain::ids::WorktreeSnapshotId>,
    terminal_event_ref: Option<String>,
    evidence: &GitProbeEvidence,
) -> WorktreeInstance {
    debug_assert!(lifecycle_successor_allowed(current.lifecycle, lifecycle));
    let value = WorktreeInstance {
        worktree_revision: current.worktree_revision + 1,
        predecessor_revision: Some(current.worktree_revision),
        lifecycle,
        current_path,
        git_admin_path_history: admin_history,
        git_registration_state: registration,
        current_snapshot_id,
        terminal_event_ref,
        recorded_at_us: evidence.occurred_at_us,
        ..current.clone()
    };
    value.validate().expect("resolver produces valid worktree");
    value
}

#[allow(clippy::too_many_arguments)]
fn transition_for(
    worktree: &WorktreeInstance,
    kind: TransitionKind,
    from_snapshot: Option<evertrace_domain::ids::WorktreeSnapshotId>,
    to_snapshot: Option<evertrace_domain::ids::WorktreeSnapshotId>,
    assessment: LineageAssessment,
    correction_reason: Option<String>,
    source_watermark: u64,
    evidence: &GitProbeEvidence,
) -> WorktreeTransition {
    transition_for_ids(
        worktree.worktree_instance_id,
        from_snapshot,
        worktree.worktree_instance_id,
        to_snapshot,
        kind,
        assessment,
        correction_reason,
        source_watermark,
        evidence,
    )
    .expect("resolver produces valid transition")
}

#[allow(clippy::too_many_arguments)]
fn transition_for_ids(
    from_worktree: WorktreeId,
    from_snapshot: Option<evertrace_domain::ids::WorktreeSnapshotId>,
    to_worktree: WorktreeId,
    to_snapshot: Option<evertrace_domain::ids::WorktreeSnapshotId>,
    kind: TransitionKind,
    assessment: LineageAssessment,
    correction_reason: Option<String>,
    source_watermark: u64,
    evidence: &GitProbeEvidence,
) -> Result<WorktreeTransition, RepositoryResolveError> {
    let transition_id = new_transition_id();
    let transition = WorktreeTransition {
        worktree_transition_id: transition_id,
        transition_revision: 1,
        predecessor_revision: None,
        from_worktree_instance_id: from_worktree,
        from_snapshot_id: from_snapshot,
        to_worktree_instance_id: to_worktree,
        to_snapshot_id: to_snapshot,
        kind,
        lineage_assessment: assessment,
        correction_reason,
        source_watermark,
        evidence_refs: evidence.evidence_refs.clone(),
    };
    transition
        .validate()
        .map_err(RepositoryResolveError::Domain)?;
    Ok(transition)
}

fn path_observation(path: &str, evidence: &GitProbeEvidence) -> PathObservation {
    PathObservation {
        path: path.to_owned(),
        first_observed_at_us: evidence.occurred_at_us,
        last_observed_at_us: evidence.occurred_at_us,
        evidence_refs: evidence.evidence_refs.clone(),
    }
}

fn assessment_of(evidence: &GitProbeEvidence) -> LineageAssessment {
    if evidence.omissions.is_empty() {
        LineageAssessment::Proven
    } else {
        LineageAssessment::Partial
    }
}

fn union_refs(current: &[String], new: &[String]) -> Vec<String> {
    current
        .iter()
        .chain(new)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn finalize_kind(resolution: &mut RepositoryResolution) {
    let has_payloads = !resolution.repositories.is_empty()
        || !resolution.worktrees.is_empty()
        || !resolution.snapshots.is_empty()
        || !resolution.transitions.is_empty()
        || !resolution.integrations.is_empty();
    if has_payloads && resolution.kind == Some(ResolutionKind::NoDelta) {
        resolution.kind = Some(ResolutionKind::Successor);
    }
}

/// original assessment stays in the journal untouched.
pub fn correct_transition(
    view: &RepositoryCurrentView,
    transition_id: evertrace_domain::ids::WorktreeTransitionId,
    new_assessment: LineageAssessment,
    correction_reason: &str,
    new_evidence_refs: &[String],
    occurred_at_us: i64,
) -> Result<RepositoryResolution, RepositoryResolveError> {
    let current = view
        .transitions
        .get(&transition_id)
        .ok_or(RepositoryResolveError::InvalidInput)?;
    if correction_reason.is_empty() || new_evidence_refs.is_empty() || occurred_at_us < 0 {
        return Err(RepositoryResolveError::InvalidInput);
    }
    let evidence_refs = union_refs(&current.evidence_refs, new_evidence_refs);
    let successor = WorktreeTransition {
        worktree_transition_id: current.worktree_transition_id,
        transition_revision: current.transition_revision + 1,
        predecessor_revision: Some(current.transition_revision),
        lineage_assessment: new_assessment,
        correction_reason: Some(correction_reason.to_owned()),
        source_watermark: view.frontier,
        evidence_refs,
        ..current.clone()
    };
    successor
        .validate()
        .map_err(RepositoryResolveError::Domain)?;
    let mut resolution = RepositoryResolution::empty(ResolutionKind::Correction, None);
    resolution.transitions.push(successor);
    Ok(resolution)
}
