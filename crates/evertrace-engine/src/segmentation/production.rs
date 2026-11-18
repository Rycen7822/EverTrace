//! Canonical activity intake for the existing maintenance worker.
use evertrace_domain::ids::SourceObservationId;
use evertrace_store::{CurrentFacts, SegmentationReadContext};

use super::{
    BoundaryEvidence, DetectorError, IncrementalSegmenter, SegmentOutcome, SegmentationFacts,
};

/// Revalidate the selected Work publisher and its link to actual execution, not merely the same Task.
async fn source_policy(
    current: &CurrentFacts,
    selected: &SegmentationReadContext,
) -> Result<Option<crate::repository::SourcePolicy>, crate::autoresearch::AutoresearchError> {
    let roots = selected
        .root_refs
        .iter()
        .filter_map(|reference| {
            let (observation, _) = current.source_observation(reference.parse().ok()?)?;
            let receipt = current.source_receipt(observation.source_receipt_ref)?.0;
            evertrace_capture::goal_source::is_source_revision(receipt.source_revision.as_str())
                .then(|| receipt.clone())
        })
        .collect::<Vec<_>>();
    let executions = selected
        .source_refs
        .iter()
        .filter_map(|id| {
            let (observation, _) = current.source_observation(*id)?;
            let receipt = current.source_receipt(observation.source_receipt_ref)?.0;
            evertrace_capture::execution_source::is_execution(observation, receipt)
                .then(|| receipt.clone())
        })
        .collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || {
        roots
            .iter()
            .filter(|root| {
                executions.iter().any(|execution| {
                    evertrace_capture::goal_source::same_execution_context(root, execution)
                })
            })
            .find_map(|root| crate::repository::SourcePolicy::from_recorded_goal(root))
    })
    .await
    .map_err(|_| crate::autoresearch::AutoresearchError::EvidenceIncomplete)
}

#[derive(Default)]
pub(super) struct SourceActivity {
    pub exit_code: Option<i32>,
    pub exit_refs: Vec<SourceObservationId>,
    pub phase: Option<evertrace_domain::work::PhaseContract>,
    pub strategy: Option<evertrace_domain::work::StrategyContract>,
    pub declaration_refs: Vec<SourceObservationId>,
}

pub(super) async fn source_activity(
    current: &CurrentFacts,
    selected: &SegmentationReadContext,
    runtime: &evertrace_capture::RuntimeSnapshot,
) -> Result<SourceActivity, evertrace_capture::CasError> {
    source_operation_activity(current, selected, selected.operation_id, runtime).await
}

async fn source_operation_activity(
    current: &CurrentFacts,
    selected: &SegmentationReadContext,
    operation_id: evertrace_domain::ids::OperationId,
    runtime: &evertrace_capture::RuntimeSnapshot,
) -> Result<SourceActivity, evertrace_capture::CasError> {
    use evertrace_capture::CasError as Error;
    let (operation, binding) = if operation_id == selected.operation_id {
        let view = selected.state.authority();
        (
            view.operation(operation_id).ok_or(Error::StoreCorrupt)?,
            view.binding(operation_id).ok_or(Error::StoreCorrupt)?,
        )
    } else {
        let (operation, binding) = selected
            .boundary_operation
            .as_ref()
            .ok_or(Error::StoreCorrupt)?;
        if operation.operation_id != operation_id {
            return Err(Error::StoreCorrupt);
        }
        (operation, binding)
    };
    let inputs = operation.input_source_observation_refs.clone();
    let results = operation.result_source_observation_refs.clone();
    let references = inputs
        .iter()
        .chain(&results)
        .copied()
        .chain(
            binding
                .evidence_refs
                .iter()
                .filter_map(|value| value.parse().ok()),
        )
        .collect::<std::collections::BTreeSet<SourceObservationId>>();
    let records = references
        .iter()
        .filter_map(|id| {
            let (observation, _) = current.source_observation(*id)?;
            let receipt = current.source_receipt(observation.source_receipt_ref)?.0;
            ((evertrace_capture::execution_source::is_execution(observation, receipt)
                || evertrace_capture::process_source::is_work_revision(
                    receipt.source_revision.as_str(),
                ))
                && receipt.protected_length <= 128 * 1024)
                .then(|| (observation.clone(), receipt.clone()))
        })
        .collect::<Vec<_>>();
    if records.is_empty() {
        return Ok(SourceActivity::default());
    }
    let cas_dir = runtime.cas_dir.clone();
    tokio::task::spawn_blocking(move || {
        let cas = evertrace_capture::CasStore::open_existing(cas_dir)?;
        let mut protected = Vec::new();
        for (observation, receipt) in records {
            let digest = receipt.cas_ref.parse::<evertrace_capture::CasDigest>()?;
            let (bytes, _) = cas.read_bounded(&digest, 128 * 1024, 128 * 1024)?;
            if bytes.len() as u64 != receipt.protected_length {
                return Err(Error::StoreCorrupt);
            }
            protected.push((observation, receipt, bytes));
        }
        let mut exits = std::collections::BTreeSet::new();
        let mut exit_refs = std::collections::BTreeSet::new();
        let mut phases = Vec::new();
        let mut strategies = Vec::new();
        let mut declaration_refs = std::collections::BTreeSet::new();
        for (observation, receipt, bytes) in &protected {
            if results.contains(&observation.source_observation_id) {
                if let Some(code) = evertrace_capture::execution_source::execution_exit_code(
                    observation,
                    receipt,
                    bytes,
                ) {
                    exits.insert(code);
                    exit_refs.insert(observation.source_observation_id);
                }
            }
            for (native, native_receipt, native_bytes) in &protected {
                if inputs.contains(&native.source_observation_id) {
                    if let Some((phase, strategy)) = crate::autoresearch::declared_work_contract(
                        receipt,
                        bytes,
                        native,
                        native_receipt,
                        native_bytes,
                    ) {
                        if !phases.contains(&phase) {
                            phases.push(phase);
                        }
                        if !strategies.contains(&strategy) {
                            strategies.push(strategy);
                        }
                        declaration_refs.extend([
                            observation.source_observation_id,
                            native.source_observation_id,
                        ]);
                    }
                }
            }
        }
        Ok(SourceActivity {
            exit_code: (exits.len() == 1).then(|| *exits.first().expect("one physical result")),
            exit_refs: if exits.len() == 1 {
                exit_refs.into_iter().collect()
            } else {
                Vec::new()
            },
            phase: (phases.len() == 1).then(|| phases.remove(0)),
            strategy: (strategies.len() == 1).then(|| strategies.remove(0)),
            declaration_refs: declaration_refs.into_iter().collect(),
        })
    })
    .await
    .map_err(|_| Error::Io)?
}

/// A current native completion can name this Phase only when its exact goal is the root goal.
/// It still needs a preceding candidate, a full new contract and later distinct compatible work.
async fn phase_completion(
    current: &CurrentFacts,
    selected: &SegmentationReadContext,
    runtime: &evertrace_capture::RuntimeSnapshot,
    phase: Option<&evertrace_domain::work::PhaseContract>,
) -> Result<Option<SourceObservationId>, evertrace_capture::CasError> {
    use evertrace_domain::work::BoundaryCandidateKind;
    let state = &selected.state;
    let Some(episode) = state.episode(selected.episode_id) else {
        return Ok(None);
    };
    let Some(candidate) = &episode.boundary_candidate else {
        return Ok(None);
    };
    let Some(phase) = phase.filter(|phase| phase.local_goal != episode.phase_contract.local_goal)
    else {
        return Ok(None);
    };
    let Some(stream) = state.authority().workstream(episode.workstream_id) else {
        return Ok(None);
    };
    if stream.root_goal != episode.phase_contract.local_goal
        || candidate.candidate_phase_kind != Some(phase.phase_kind)
    {
        return Ok(None);
    }
    let bursts = state
        .boundary_bursts(episode)
        .map_err(|_| evertrace_capture::CasError::StoreCorrupt)?;
    let Some(anchor) = bursts
        .iter()
        .flat_map(|burst| &burst.members)
        .find(|member| member.source_watermark == candidate.candidate_watermark)
    else {
        return Ok(None);
    };
    if anchor.operation_id == selected.operation_id {
        return Ok(None);
    }
    let Some((_, anchor_binding)) =
        selected
            .boundary_operation
            .as_ref()
            .filter(|(operation, binding)| {
                operation.operation_id == anchor.operation_id
                    && binding.work_binding_revision_id == anchor.work_binding_revision_id
            })
    else {
        return Ok(None);
    };
    let Some(binding) = state.authority().binding(selected.operation_id) else {
        return Ok(None);
    };
    let roots = binding
        .evidence_refs
        .iter()
        .filter_map(|reference| {
            let id = reference.parse().ok()?;
            let (observation, seq) = current.source_observation(id)?;
            let receipt = current.source_receipt(observation.source_receipt_ref)?.0;
            let after_phase_input = bursts
                .iter()
                .flat_map(|burst| &burst.members)
                .flat_map(|member| &member.source_observation_refs)
                .any(|id| {
                    current
                        .source_observation(*id)
                        .is_some_and(|(input, input_seq)| {
                            input_seq < seq
                                && input.observation_role
                                    == evertrace_domain::evidence::ObservationRole::Intent
                                && current
                                    .source_receipt(input.source_receipt_ref)
                                    .is_some_and(|(receipt, _)| {
                                        evertrace_capture::execution_source::is_execution(
                                            input, receipt,
                                        )
                                    })
                        })
                });
            (evertrace_capture::goal_source::is_source_revision(receipt.source_revision.as_str())
                && selected.root_refs.contains(&receipt.source_ref)
                && (after_phase_input
                    || (candidate.kind == BoundaryCandidateKind::Objective
                        && anchor_binding.evidence_refs.contains(reference))))
            .then(|| (observation.clone(), receipt.clone(), seq))
        })
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return Ok(None);
    }
    let previous =
        source_operation_activity(current, selected, anchor.operation_id, runtime).await?;
    if previous.phase.as_ref() != Some(phase) {
        return Ok(None);
    }
    let prior = selected
        .source_refs
        .iter()
        .filter_map(|id| {
            let (observation, seq) = current.source_observation(*id)?;
            let receipt = current.source_receipt(observation.source_receipt_ref)?.0;
            evertrace_capture::goal_source::is_source_revision(receipt.source_revision.as_str())
                .then(|| (receipt.clone(), seq))
        })
        .collect::<Vec<_>>();
    let objective_candidate = candidate.kind == BoundaryCandidateKind::Objective;
    let candidate_watermark = candidate.candidate_watermark;
    let anchor_roots = anchor_binding.evidence_refs.clone();
    let cas_dir = runtime.cas_dir.clone();
    let key_dir = runtime.device_key_dir.clone();
    let goal = stream.root_goal.clone();
    tokio::task::spawn_blocking(move || {
        let cas = evertrace_capture::CasStore::open_existing(cas_dir)?;
        let resolver = crate::autoresearch::ControlledRunResolver::new(cas.clone());
        let mut completed = Vec::new();
        for (observation, receipt, current_sequence) in roots {
            let Ok(root) = resolver.verified_root_goal(&receipt, &observation, Some(&key_dir))
            else {
                continue;
            };
            if root.objective() != goal || !root.completion_intent() {
                continue;
            }
            let already_grounded = objective_candidate
                && (current_sequence > candidate_watermark
                    || anchor_roots.contains(&receipt.source_observation_id.to_string()));
            let was_open = already_grounded || prior.iter().any(|(old, seq)| {
                if old.source_ref != receipt.source_ref || *seq >= current_sequence {
                    return false;
                }
                let Some(bytes) = old.cas_ref.parse::<evertrace_capture::CasDigest>().ok()
                    .and_then(|digest| cas.read_bounded(&digest, 128 * 1024, 128 * 1024).ok())
                    .map(|(bytes, _)| bytes)
                else {
                    return false;
                };
                matches!(evertrace_capture::goal_source::observed_goal(&bytes),
                    Ok(Some((reference, objective))) if reference == root.source_ref() && objective == goal)
                    && matches!(evertrace_capture::goal_source::observed_completion_intent(&bytes), Ok(Some(false)))
            });
            if was_open {
                completed.push(observation.source_observation_id);
            }
        }
        Ok((completed.len() == 1).then(|| completed[0]))
    })
    .await
    .map_err(|_| evertrace_capture::CasError::Io)?
}

struct CodeBoundarySnapshot {
    id: evertrace_domain::ids::WorktreeSnapshotId,
    payloads: Vec<evertrace_store::JournalPayload>,
}

/// Capture the current coherent worktree state at confirmation, never a retroactive tool-exit snapshot.
async fn code_boundary_snapshot(
    writer: &crate::WriterHandle,
    current: &CurrentFacts,
    selected: &SegmentationReadContext,
    completion: SourceObservationId,
) -> Result<Option<CodeBoundarySnapshot>, crate::maintenance::BackgroundSchedulerError> {
    use crate::maintenance::BackgroundSchedulerError as Error;
    use crate::repository::{GitOid, HostTrustDecision, ProbeLimits, RepositoryResolveInput};
    use evertrace_codex::policy::RepositoryTrustState::Trusted;
    use evertrace_domain::repository::SnapshotCaptureStatus;
    let Some((identity, repository, worktree)) =
        selected.boundary_repository_identity.and_then(|identity| {
            let episode = selected.state.episode(selected.episode_id)?;
            let worktree = episode.worktree_instance_id?;
            let stream = selected
                .state
                .authority()
                .workstream(episode.workstream_id)?;
            (stream.active_worktree_instance_id == Some(worktree)).then_some((
                identity,
                episode.repository_instance_id?,
                worktree,
            ))
        })
    else {
        return Ok(None);
    };
    let Some(policy) = source_policy(current, selected)
        .await
        .map_err(|_| Error::Store)?
    else {
        return Ok(None);
    };
    let (view, purged) = writer
        .repository_resolution_context(identity)
        .await
        .map_err(|_| Error::Writer)?;
    if view.frontier != current.frontier()
        || !view.repositories.contains_key(&repository)
        || view.repositories.values().any(|row| {
            !crate::repository::repository_read_gate(row, purged.contains(&row.repository_id))
        })
    {
        return Ok(None);
    }
    let Some(operation) = selected.state.authority().operation(selected.operation_id) else {
        return Ok(None);
    };
    let reference = completion.to_string();
    let mut references = vec![reference.clone()];
    references.extend(
        operation
            .input_source_observation_refs
            .iter()
            .map(ToString::to_string),
    );
    tokio::task::spawn_blocking(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        let path = view.worktrees.get(&worktree)?.current_path.as_deref()?;
        let locator = std::path::Path::new(path);
        let trust = policy.trust(Some(path), deadline);
        if trust.state != Trusted {
            return None;
        }
        let location = crate::repository::workspace_git_location(locator, deadline).ok()??;
        if location.worktree_path != locator || location.common_dir_filesystem != identity {
            return None;
        }
        references.extend(trust.evidence_refs);
        let root = evertrace_capture::ConfinedRoot::open_external_source(locator).ok()?;
        let pinned_cwd = root.proc_cwd_path().ok()?;
        let root_identity = evertrace_domain::repository::FilesystemIdentity {
            device: root.identity().device,
            inode: root.identity().inode,
        };
        let heads = view
            .snapshots
            .values()
            .filter_map(|snapshot| snapshot.head_oid.as_deref())
            .map(GitOid::parse)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_micros(),
        )
        .ok()?;
        let mut evidence = crate::repository::with_probe_deadline(deadline, || {
            crate::repository::probe_repository_pinned(
                &pinned_cwd,
                locator,
                root_identity,
                HostTrustDecision::Trusted,
                &references,
                now,
                &ProbeLimits::default(),
                &[],
                &heads,
            )
        })
        .ok()?;
        root.revalidate().ok()?;
        if evidence.unavailable_reason.is_some()
            || evidence.worktree_root.as_deref() != Some(path)
            || evidence.worktree_root_filesystem != Some(root_identity)
            || evidence.common_dir_filesystem != Some(identity)
            || evidence.git_dir.as_deref().map(std::path::Path::new)
                != Some(location.git_dir.as_path())
            || policy.trust(Some(path), deadline).state != Trusted
        {
            return None;
        }
        // The pinned probe does not traverse sibling worktrees. Only this entry has witnessed admin identity.
        let entry = evidence
            .worktree_entries
            .iter_mut()
            .find(|entry| entry.path == path)?;
        entry.gitdir = Some(location.git_dir.to_str()?.to_owned());
        evidence.git_dir = entry.gitdir.clone();
        evidence.common_dir = Some(location.common_dir.to_str()?.to_owned());
        let input = RepositoryResolveInput {
            view: &view,
            evidence: &evidence,
            derived_from_hint: None,
        };
        let resolved = input
            .resolve_with_incomplete_history(&view.repositories.keys().copied().collect())
            .ok()?;
        let resolved =
            crate::repository::complete_repository_source_start(&input, &reference, resolved)
                .ok()?;
        let snapshot = resolved.snapshots.iter().find(|snapshot| {
            snapshot.worktree_instance_id == worktree
                && snapshot.captured_at_us == now
                && snapshot.capture_status == SnapshotCaptureStatus::Complete
                && snapshot.evidence_refs.contains(&reference)
        })?;
        Some(CodeBoundarySnapshot {
            id: snapshot.worktree_snapshot_id,
            payloads: resolved.payloads(),
        })
    })
    .await
    .map_err(|_| Error::Store)
}

/// A nonzero physical exit is an operation failure, not a verifier result or semantic boundary.
fn derive_activity(
    selected: &SegmentationReadContext,
    exit: Option<i32>,
    declared_phase: Option<&evertrace_domain::work::PhaseContract>,
    completion: Option<SourceObservationId>,
) -> Result<SegmentOutcome, DetectorError> {
    let state = &selected.state;
    let episode = state
        .episode(selected.episode_id)
        .ok_or(DetectorError::Ineligible)?;
    let operation = state
        .authority()
        .operation(selected.operation_id)
        .ok_or(DetectorError::Ineligible)?;
    let scope = episode.repository_instance_id.map_or_else(
        || "non_repository".to_owned(),
        |id| format!("repository:{id}"),
    );
    let facts = SegmentationFacts {
        sequence: selected.sequence,
        source_watermark: state.frontier(),
        target_family: scope,
        state_delta: if exit.is_some_and(|code| code != 0) {
            super::StateDeltaKind::Failed
        } else {
            super::StateDeltaKind::Observed
        },
        error_signature: exit
            .filter(|code| *code != 0)
            .map(|code| format!("process_exit:{code}")),
        verifier_transition: super::VerifierTransition::None,
        observed_phase_kind: declared_phase.as_ref().map(|phase| phase.phase_kind),
        boundary_evidence: completion.map_or(BoundaryEvidence::None, |_| {
            BoundaryEvidence::ExplicitPhaseComplete
        }),
        evidence_refs: operation
            .input_source_observation_refs
            .iter()
            .chain(&operation.result_source_observation_refs)
            .copied()
            .collect(),
    };
    let mut segmenter = IncrementalSegmenter::restore(state, selected.episode_id)?;
    segmenter.observe_declared(state, selected.operation_id, facts, declared_phase)
}

pub(super) fn tool_request_sources(
    current: &CurrentFacts,
    selected: &SegmentationReadContext,
    episode: &evertrace_domain::work::WorkEpisode,
) -> Result<Vec<SourceObservationId>, crate::maintenance::BackgroundSchedulerError> {
    use crate::maintenance::BackgroundSchedulerError as Error;
    let operation = selected
        .state
        .authority()
        .operation(selected.operation_id)
        .ok_or(Error::Store)?;
    let recent = selected
        .state
        .recent_bursts(episode)
        .map_err(|_| Error::Store)?;
    let left = recent
        .iter()
        .rev()
        .flat_map(|burst| burst.members.iter().rev())
        .find(|member| member.operation_id != selected.operation_id);
    let mut result = Vec::new();
    for refs in left
        .map(|member| member.source_observation_refs.as_slice())
        .into_iter()
        .chain([operation.input_source_observation_refs.as_slice()])
    {
        let mut physical = Vec::new();
        for id in refs {
            let (observation, _) = current.source_observation(*id).ok_or(Error::Store)?;
            let receipt = current
                .source_receipt(observation.source_receipt_ref)
                .ok_or(Error::Store)?
                .0;
            if observation.observation_role == evertrace_domain::evidence::ObservationRole::Intent
                && evertrace_capture::execution_source::is_execution(observation, receipt)
            {
                physical.push(*id);
            }
        }
        physical.sort();
        physical.dedup();
        if let [id] = physical.as_slice()
            && !result.contains(id)
        {
            result.push(*id);
        }
    }
    Ok(result)
}

pub(super) async fn tool_request_artifacts(
    current: &CurrentFacts,
    episode: &evertrace_domain::work::WorkEpisode,
    runtime: &evertrace_capture::RuntimeSnapshot,
    now_us: i64,
    sources: &[SourceObservationId],
) -> Result<Vec<evertrace_domain::work::WorkArtifact>, crate::maintenance::BackgroundSchedulerError>
{
    use crate::maintenance::BackgroundSchedulerError as Error;
    use evertrace_domain::work::{
        ArtifactActor, ArtifactDerivability, ArtifactPayloadStatus, ArtifactRetention,
        ArtifactRevision, ArtifactScope, WorkArtifactKind,
    };
    let mut candidates = Vec::new();
    for id in sources {
        let (observation, _) = current.source_observation(*id).ok_or(Error::Store)?;
        let receipt = current
            .source_receipt(observation.source_receipt_ref)
            .ok_or(Error::Store)?
            .0;
        if evertrace_capture::execution_source::is_execution(observation, receipt) {
            candidates.push((observation.clone(), receipt.clone()));
        }
    }
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let runtime = runtime.clone();
    let scope = match (episode.repository_instance_id, episode.worktree_instance_id) {
        (Some(repository_instance_id), Some(worktree_instance_id)) => ArtifactScope::Worktree {
            repository_instance_id,
            worktree_instance_id,
        },
        (None, None) => ArtifactScope::Task {
            task_id: episode.task_id,
        },
        _ => return Err(Error::Store),
    };
    let episode_id = episode.episode_id;
    tokio::task::spawn_blocking(move || {
        let cas = evertrace_capture::CasStore::open_existing(&runtime.cas_dir)
            .map_err(|_| Error::Store)?;
        let key = evertrace_capture::DeviceKeyStore::new(runtime.device_key_dir)
            .load()
            .map_err(|_| Error::Store)?;
        let mut artifacts = Vec::new();
        for (observation, receipt) in candidates {
            let digest = receipt.cas_ref.parse().map_err(|_| Error::Store)?;
            let (protected, _) = cas
                .read_bounded(&digest, 131_072, 131_072)
                .map_err(|_| Error::Store)?;
            if protected.len() as u64 != receipt.protected_length {
                return Err(Error::Store);
            }
            let Ok(raw) = evertrace_capture::goal_source::read_tool_request(
                &observation,
                &receipt,
                &protected,
            ) else {
                continue;
            };
            let payload = evertrace_capture::protect(&raw, &key).map_err(|_| Error::Store)?;
            let digest = cas.put(&payload).map_err(|_| Error::Store)?;
            let blob = evertrace_domain::ids::CasId::from_digest(*digest.as_bytes());
            artifacts.push(
                crate::autoresearch::ArtifactService::new(cas.clone())
                    .create(ArtifactRevision {
                        revision_id: evertrace_domain::revision::RevisionId::new_v7(),
                        parent_revision_id: None,
                        kind: WorkArtifactKind::Log,
                        logical_name: "工具请求".into(),
                        scope,
                        media_type: "application/json".into(),
                        content_blob_ref: Some(blob),
                        external_reference: None,
                        content_fingerprint: Some(blob),
                        payload_status: ArtifactPayloadStatus::Available,
                        produced_by_refs: vec![ArtifactActor::WorkEpisode(episode_id)],
                        consumed_by_refs: Vec::new(),
                        source_observation_refs: vec![observation.source_observation_id],
                        derivability: ArtifactDerivability::Original,
                        retention: ArtifactRetention::Task,
                        created_at_us: now_us,
                    })
                    .map_err(|_| Error::Store)?,
            );
        }
        Ok(artifacts)
    })
    .await
    .map_err(|_| Error::Store)?
}

pub(super) async fn readable_context(
    writer: &crate::WriterHandle,
    current: &CurrentFacts,
    selected: &SegmentationReadContext,
    runtime: &evertrace_capture::RuntimeSnapshot,
) -> Result<Option<std::time::Instant>, crate::maintenance::BackgroundSchedulerError> {
    use crate::maintenance::BackgroundSchedulerError as Error;
    // Existing canonical Work and physical evidence do not require the publisher to stay alive.
    // Only code access needs its current source-owned repository policy; there is no HOME fallback.
    let policy = if selected.repository_ids.is_empty() {
        None
    } else {
        source_policy(current, &selected)
            .await
            .map_err(|_| Error::Store)?
    };
    let authority = policy.as_ref().map_or(
        crate::repository::RepositoryReadAuthority::Unavailable,
        crate::repository::RepositoryReadAuthority::Source,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
    let refs = selected
        .source_refs
        .iter()
        .copied()
        .chain(
            selected
                .root_refs
                .iter()
                .filter_map(|reference| reference.parse::<SourceObservationId>().ok()),
        )
        .map(|id| id.to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut blocked = false;
    let mut revoked = Vec::new();
    for chunk in refs.chunks(64) {
        if std::time::Instant::now() >= deadline {
            blocked = true;
            break;
        }
        match crate::session_import::source_observations_read_assessment(
            writer, &authority, current, chunk,
        )
        .await
        {
            Ok((denied, observations)) => {
                blocked |= !denied.is_empty();
                revoked.extend(observations);
            }
            Err(crate::session_import::SessionImportServiceError::Unavailable) => {
                blocked = true;
                break;
            }
            Err(_) => return Err(Error::Store),
        }
    }
    if !blocked && std::time::Instant::now() < deadline {
        let (denied, observations) = crate::repository::repository_read_assessment(
            writer,
            selected.repository_ids.iter().copied().collect(),
            &authority,
            deadline,
        )
        .await
        .map_err(|_| Error::Store)?;
        blocked |= !denied.is_empty();
        revoked.extend(observations);
    } else {
        blocked = true;
    }
    crate::repository::record_trust_revocations(writer, revoked, runtime.effective_config_hash)
        .await
        .map_err(|_| Error::Store)?;
    if blocked || std::time::Instant::now() >= deadline {
        return Ok(None);
    }
    Ok(Some(deadline))
}

pub(crate) async fn advance_activity(
    writer: &crate::WriterHandle,
    current: &CurrentFacts,
    runtime: &evertrace_capture::RuntimeSnapshot,
    after: &mut u64,
) -> Result<crate::maintenance::BackgroundProgress, crate::maintenance::BackgroundSchedulerError> {
    use crate::maintenance::{BackgroundProgress, BackgroundSchedulerError as Error};
    let mut progress = BackgroundProgress {
        completed: 0,
        retryable: false,
    };
    for _ in 0..8 {
        let previous = *after;
        let Some(mut selected) = writer
            .segmentation_current_context(*after)
            .await
            .map_err(|_| Error::Writer)?
        else {
            *after = 0;
            return Ok(progress);
        };
        if selected.state.frontier() != current.frontier() {
            progress.retryable = true;
            return Ok(progress);
        }
        *after = selected.sequence;
        let Some(deadline) = readable_context(writer, current, &selected, runtime).await? else {
            continue;
        };
        let activity = match source_activity(current, &selected, runtime).await {
            Ok(activity) => activity,
            Err(error) => {
                let changed =
                    writer.sync_frontier().await.map_err(|_| Error::Writer)? != current.frontier();
                if changed || matches!(error, evertrace_capture::CasError::LockBusy) {
                    *after = previous;
                    progress.retryable = true;
                    return Ok(progress);
                }
                return Err(Error::Store);
            }
        };
        if std::time::Instant::now() >= deadline {
            continue;
        }
        let completion =
            match phase_completion(current, &selected, runtime, activity.phase.as_ref()).await {
                Ok(value) => value,
                Err(evertrace_capture::CasError::LockBusy) => {
                    *after = previous;
                    progress.retryable = true;
                    return Ok(progress);
                }
                Err(_) => return Err(Error::Store),
            };
        let derive = |completion| {
            derive_activity(
                &selected,
                activity.exit_code,
                activity.phase.as_ref(),
                completion,
            )
        };
        let mut step = match derive(completion) {
            Ok(SegmentOutcome::Delta(step)) => step,
            Ok(SegmentOutcome::NoDelta) | Err(DetectorError::Ineligible) => continue,
            Err(_) => return Err(Error::Store),
        };
        let mut boundary_snapshot = None;
        if let Some(completion) = completion {
            let code_scope = selected
                .state
                .episode(selected.episode_id)
                .ok_or(Error::Store)?
                .repository_instance_id
                .is_some();
            if code_scope
                && step.detector().boundary_status()
                    == evertrace_domain::work::BoundaryStatus::Confirmed
            {
                boundary_snapshot =
                    code_boundary_snapshot(writer, current, &selected, completion).await?;
                if boundary_snapshot.is_none() {
                    step = match derive(None) {
                        Ok(SegmentOutcome::Delta(step)) => step,
                        Ok(SegmentOutcome::NoDelta) | Err(DetectorError::Ineligible) => continue,
                        Err(_) => return Err(Error::Store),
                    };
                }
            }
            if readable_context(writer, current, &selected, runtime)
                .await?
                .is_none()
            {
                *after = previous;
                progress.retryable = true;
                return Ok(progress);
            }
        }
        let episode = selected
            .state
            .episode(selected.episode_id)
            .ok_or(Error::Store)?;
        let receipts = episode
            .execution_lane_ids
            .iter()
            .copied()
            .chain(
                selected
                    .state
                    .authority()
                    .operation(selected.operation_id)
                    .and_then(|op| op.execution_lane_id),
            )
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|id| {
                let view = selected.state.authority();
                view.lane(id)
                    .and_then(|lane| view.receipt(lane.active_capture_receipt_revision_id))
                    .cloned()
                    .ok_or(Error::Store)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let occurred_at_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_micros()).ok())
            .ok_or(Error::Store)?;
        let context = crate::work::WorkCommandContext {
            command_id: evertrace_domain::ids::CommandId::new_v7(),
            occurred_at_us,
            effective_config_hash: runtime.effective_config_hash,
            algorithm_revision: "incremental-segmentation-v1",
        };
        let needs_checkpoint = step.candidate_watermark().is_some_and(|watermark| {
            !selected.candidate_checkpointed
                || episode
                    .boundary_candidate
                    .as_ref()
                    .is_none_or(|candidate| candidate.candidate_watermark != watermark)
        });
        let artifacts = if needs_checkpoint {
            let sources = tool_request_sources(current, &selected, episode)?;
            selected.source_refs.extend(sources.iter().copied());
            selected.source_refs.sort();
            selected.source_refs.dedup();
            if readable_context(writer, current, &selected, runtime)
                .await?
                .is_none()
            {
                *after = previous;
                progress.retryable = true;
                return Ok(progress);
            }
            tool_request_artifacts(current, episode, runtime, occurred_at_us, &sources).await?
        } else {
            Vec::new()
        };
        if needs_checkpoint
            && readable_context(writer, current, &selected, runtime)
                .await?
                .is_none()
        {
            *after = previous;
            progress.retryable = true;
            return Ok(progress);
        }
        let command = if step.detector().boundary_status()
            == evertrace_domain::work::BoundaryStatus::Confirmed
        {
            let stream = selected
                .state
                .authority()
                .workstream(episode.workstream_id)
                .ok_or(Error::Store)?;
            let closed = crate::work::episode::confirm_episode_boundary(
                episode,
                &step,
                boundary_snapshot.as_ref().map(|snapshot| snapshot.id),
                &receipts,
            )
            .map_err(|_| Error::Store)?;
            let next = crate::work::episode::next_episode(
                stream,
                episode,
                activity.phase.ok_or(Error::Store)?,
                boundary_snapshot.as_ref().map(|snapshot| snapshot.id),
                closed.source_watermark,
            )
            .map_err(|_| Error::Store)?;
            crate::work::episode::close_episode_and_optionally_open(
                context,
                stream,
                episode,
                closed,
                Some(&step),
                Some(next),
                vec![],
                vec![],
            )
        } else if needs_checkpoint {
            let attempts = episode
                .attempt_ids
                .iter()
                .map(|id| {
                    selected
                        .state
                        .authority()
                        .attempt(*id)
                        .cloned()
                        .ok_or(Error::Store)
                })
                .collect::<Result<Vec<_>, _>>()?;
            crate::work::episode::save_candidate_checkpoint(
                context,
                episode,
                &step,
                &receipts,
                &attempts,
                selected.snapshot.as_ref(),
            )
        } else {
            crate::work::episode::save_segmentation_update(context, episode, &step, &receipts)
        }
        .map_err(|_| Error::Store)?;
        let command = if !artifacts.is_empty() || boundary_snapshot.is_some() {
            let mut events = boundary_snapshot
                .into_iter()
                .flat_map(|snapshot| snapshot.payloads)
                .map(|payload| {
                    evertrace_store::JournalEventDraft::runtime(
                        occurred_at_us,
                        runtime.effective_config_hash,
                        "phase-boundary-snapshot-v1",
                        payload,
                    )
                })
                .collect::<Vec<_>>();
            events.extend_from_slice(command.events());
            for artifact in artifacts {
                events.push(evertrace_store::JournalEventDraft::runtime(
                    occurred_at_us,
                    runtime.effective_config_hash,
                    "tool_request_v1",
                    evertrace_store::JournalPayload::WorkArtifactRecorded(Box::new(artifact)),
                ));
            }
            evertrace_store::JournalCommand::new(command.command_id(), events)
                .map_err(|_| Error::Store)?
        } else {
            command
        };
        match writer
            .commit_if_frontier(command, occurred_at_us, current.frontier())
            .await
        {
            Ok(_) => {
                // The controller is request-local: the next activity restores the committed canonical state.
                progress.completed = 1;
                progress.retryable = true;
                return Ok(progress);
            }
            Err(crate::WriterActorError::StaleFrontier { .. }) => {
                *after = previous;
                progress.retryable = true;
                return Ok(progress);
            }
            Err(_) => return Err(Error::Writer),
        }
    }
    progress.retryable = true;
    Ok(progress)
}
