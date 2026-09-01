use std::collections::BTreeMap;

use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    ids::{CasId, SemanticDerivationRunId, SemanticDigestId, WikiProjectionId},
    revision::RevisionId,
    semantic::{
        Atom, AtomKind, AtomLifecycleStatus, AtomProvenance, AtomScope, DerivationRunStatus,
        EpistemicStatus, ProposalCreatedBy, ProposalEligibility, ProposalPayload, ProposalStatus,
        ProposalTargetId, ProposalTargetKind, SemanticCandidate, SemanticDerivationRun,
        SemanticDigest, WikiProjection,
    },
    work::{EpisodeLifecycle, WorkEpisode},
};

use crate::{JournalPayload, ObjectFamily, ObjectRow, ObjectRowClass, ObjectRowKind, StoreError};

use super::PROJECTION_GENERATION;

pub(super) const WIKI_PROJECTION_KIND: &str = "wiki_projection";

#[derive(Clone, Default)]
pub(super) struct SynthesisState {
    digests: BTreeMap<SemanticDigestId, (SemanticDigest, u64)>,
    runs: BTreeMap<SemanticDerivationRunId, (SemanticDerivationRun, u64)>,
    successful_fingerprints: BTreeMap<[u8; 32], SemanticDerivationRunId>,
}

pub(super) struct SynthesisAdmissionView<'a> {
    pub(super) episodes: &'a BTreeMap<evertrace_domain::ids::WorkEpisodeId, (WorkEpisode, u64)>,
    pub(super) proposals: &'a BTreeMap<
        evertrace_domain::ids::RevisionProposalId,
        (evertrace_domain::semantic::RevisionProposal, u64),
    >,
    pub(super) atoms: &'a BTreeMap<evertrace_domain::ids::AtomId, (Atom, u64)>,
    pub(super) procedures: &'a super::procedure::ProcedureState,
    pub(super) s23: &'a super::s23::S23State,
    pub(super) refs: &'a std::collections::BTreeSet<String>,
    pub(super) proposal_evidence_refs: &'a std::collections::BTreeSet<String>,
}

pub(super) fn wiki_rows(
    atoms: &BTreeMap<evertrace_domain::ids::AtomId, (Atom, u64)>,
    proposals: &BTreeMap<
        evertrace_domain::ids::RevisionProposalId,
        (evertrace_domain::semantic::RevisionProposal, u64),
    >,
    episodes: &BTreeMap<evertrace_domain::ids::WorkEpisodeId, (WorkEpisode, u64)>,
    synthesis: &SynthesisState,
    support: &super::s23::S23State,
) -> Result<Vec<ObjectRow>, StoreError> {
    let active_atom_revisions = atoms
        .values()
        .filter(|(atom, _)| atom.lifecycle_status == AtomLifecycleStatus::Active)
        .map(|(atom, _)| (atom.revision_id, atom))
        .collect::<BTreeMap<_, _>>();
    let digests_by_ref = synthesis
        .digests()
        .values()
        .map(|(digest, _)| (digest.semantic_digest_id.to_string(), digest))
        .collect::<BTreeMap<_, _>>();
    let mut topics = BTreeMap::<
        String,
        Vec<(
            &Atom,
            &evertrace_domain::semantic::RevisionProposal,
            u64,
            u64,
        )>,
    >::new();
    for (atom, seq) in atoms.values() {
        let Some(reviewed_proposal) = reviewed_proposal(atom, proposals)? else {
            continue;
        };
        let support_watermark = match atom.scope {
            AtomScope::Global => support.global_wiki_support_watermark(atom.revision_id),
            AtomScope::Repository { .. } => Some(0),
            _ => None,
        };
        if atom.lifecycle_status != AtomLifecycleStatus::Active
            || !matches!(atom.scope, AtomScope::Repository { .. } | AtomScope::Global)
            || !matches!(
                atom.kind,
                AtomKind::Fact
                    | AtomKind::Constraint
                    | AtomKind::Decision
                    | AtomKind::Claim
                    | AtomKind::Citation
            )
            || atom.kind == AtomKind::Claim && atom.epistemic_status != EpistemicStatus::Supported
            || atom.kind == AtomKind::Claim
                && has_unresolved_claim_contradiction(atom, &active_atom_revisions)
            || support_watermark.is_none()
        {
            continue;
        }
        let topic = normalize_topic(&atom.value.subject)?;
        topics.entry(topic).or_default().push((
            atom,
            reviewed_proposal,
            *seq,
            support_watermark.unwrap_or(0),
        ));
    }
    let mut rows = Vec::with_capacity(topics.len());
    for (topic, mut sources) in topics {
        sources.sort_by_key(|(atom, _, _, _)| atom.atom_id);
        let source_atom_ids = sources
            .iter()
            .map(|(atom, _, _, _)| atom.atom_id)
            .collect::<Vec<_>>();
        let source_episode_ids = sources
            .iter()
            .flat_map(|(atom, proposal, _, _)| {
                proposal.evidence_refs.iter().filter_map(|reference| {
                    let digest = digests_by_ref.get(reference)?;
                    let episode = &episodes.get(&digest.episode_id)?.0;
                    (episode.lifecycle_status == EpisodeLifecycle::Closed
                        && episode.repository_instance_id.is_some()
                        && episode.repository_instance_id == atom.scope.repository_id()
                        && digest.repository_id == episode.repository_instance_id
                        && episode
                            .semantic_digest_refs
                            .binary_search(&digest.semantic_digest_id.to_string())
                            .is_ok())
                    .then_some(episode.episode_id)
                })
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let source_atoms = sources
            .iter()
            .map(|(atom, _, _, _)| *atom)
            .collect::<Vec<_>>();
        let (rendered_blob_ref, _) =
            wiki_render_identity(&topic, &source_atoms, &source_episode_ids)?;
        let page_digest = sha256(
            "evertrace.wiki_projection.page",
            1,
            &CanonicalValue::String(topic.clone()),
        )
        .map_err(|_| StoreError::StoreCorrupt)?;
        let source_watermark = sources
            .iter()
            .map(|(_, _, seq, support_seq)| (*seq).max(*support_seq))
            .chain(
                source_episode_ids
                    .iter()
                    .filter_map(|episode_id| episodes.get(episode_id).map(|(_, seq)| *seq)),
            )
            .max()
            .unwrap_or(0);
        let projection = WikiProjection {
            page_id: WikiProjectionId::from_digest(page_digest),
            topic,
            source_atom_ids,
            source_episode_ids,
            compiler_version: 1,
            source_watermark,
            rendered_blob_ref,
        };
        projection
            .validate()
            .map_err(|_| StoreError::StoreCorrupt)?;
        rows.push(wiki_row(&projection)?);
    }
    Ok(rows)
}

fn reviewed_proposal<'a>(
    atom: &Atom,
    proposals: &'a BTreeMap<
        evertrace_domain::ids::RevisionProposalId,
        (evertrace_domain::semantic::RevisionProposal, u64),
    >,
) -> Result<Option<&'a evertrace_domain::semantic::RevisionProposal>, StoreError> {
    let (Some(proposal_id), Some(proposal_revision_id)) = (
        atom.accepted_proposal_id,
        atom.accepted_proposal_revision_id,
    ) else {
        if atom.accepted_proposal_id.is_some() || atom.accepted_proposal_revision_id.is_some() {
            return Err(StoreError::StoreCorrupt);
        }
        return Ok(None);
    };
    let proposal = &proposals
        .get(&proposal_id)
        .ok_or(StoreError::StoreCorrupt)?
        .0;
    let (accepted_atom_id, accepted_atom_revision_id, accepted_structure_hash) = proposal
        .acceptance
        .as_ref()
        .and_then(|acceptance| acceptance.accepted_atom())
        .ok_or(StoreError::StoreCorrupt)?;
    if proposal.proposal_revision_id != proposal_revision_id
        || proposal.status != ProposalStatus::Accepted
        || proposal.target_kind != ProposalTargetKind::Atom
        || proposal
            .target_id
            .is_some_and(|target| target != ProposalTargetId::Atom(atom.atom_id))
        || accepted_atom_id != atom.atom_id
        || accepted_atom_revision_id != atom.revision_id
        || accepted_structure_hash
            != atom
                .semantic_structure_hash()
                .map_err(|_| StoreError::StoreCorrupt)?
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(Some(proposal))
}

fn has_unresolved_claim_contradiction(
    claim: &Atom,
    active: &BTreeMap<evertrace_domain::revision::RevisionId, &Atom>,
) -> bool {
    claim.contradicts_revision_refs.iter().any(|revision| {
        active
            .get(revision)
            .is_some_and(|other| other.scope == claim.scope)
    }) || active.values().any(|other| {
        other.scope == claim.scope
            && other
                .contradicts_revision_refs
                .binary_search(&claim.revision_id)
                .is_ok()
    })
}

pub(super) fn restore_wiki_projection(
    row: &ObjectRow,
) -> Result<Option<WikiProjection>, StoreError> {
    if row.object_kind.as_deref() != Some(WIKI_PROJECTION_KIND) {
        return Ok(None);
    }
    let projection: WikiProjection = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or(StoreError::StoreCorrupt)?,
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    projection
        .validate()
        .map_err(|_| StoreError::StoreCorrupt)?;
    if wiki_row(&projection)? != *row {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(Some(projection))
}

fn wiki_row(value: &WikiProjection) -> Result<ObjectRow, StoreError> {
    Ok(ObjectRow {
        row_id: format!("projection:wiki:{}", value.page_id),
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Projection),
        object_family: None,
        object_kind: Some(WIKI_PROJECTION_KIND.into()),
        object_id: None,
        current_revision_id: None,
        lifecycle: Some("current".into()),
        epistemic: Some("derived".into()),
        authority: Some("none".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id: None,
        worktree_id: None,
        task_id: None,
        workstream_id: None,
        session_id: None,
        payload_json: Some(serde_json::to_string(value).map_err(|_| StoreError::Serialization)?),
        source_event_seq: value.source_watermark,
        projection_generation: PROJECTION_GENERATION,
    })
}

fn normalize_topic(value: &str) -> Result<String, StoreError> {
    let topic = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    if topic.is_empty() || topic.len() > 1024 || topic.chars().any(char::is_control) {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(topic)
}

pub(crate) fn wiki_render_identity(
    topic: &str,
    source_atoms: &[&Atom],
    source_episode_ids: &[evertrace_domain::ids::WorkEpisodeId],
) -> Result<(CasId, Vec<[RevisionId; 2]>), StoreError> {
    if source_atoms.is_empty()
        || source_atoms
            .windows(2)
            .any(|pair| pair[0].atom_id >= pair[1].atom_id)
        || source_episode_ids.windows(2).any(|pair| pair[0] >= pair[1])
        || source_atoms
            .iter()
            .any(|atom| normalize_topic(&atom.value.subject).as_deref() != Ok(topic))
    {
        return Err(StoreError::StoreCorrupt);
    }
    let source_revisions = source_atoms
        .iter()
        .map(|atom| atom.revision_id)
        .collect::<std::collections::BTreeSet<_>>();
    if source_revisions.len() != source_atoms.len() {
        return Err(StoreError::StoreCorrupt);
    }
    let mut contradictions = source_atoms
        .iter()
        .flat_map(|atom| {
            atom.contradicts_revision_refs
                .iter()
                .filter(|other| source_revisions.contains(other))
                .map(|other| {
                    if atom.revision_id < *other {
                        [atom.revision_id, *other]
                    } else {
                        [*other, atom.revision_id]
                    }
                })
        })
        .collect::<Vec<_>>();
    contradictions.sort();
    contradictions.dedup();
    let content = CanonicalValue::Sequence(vec![
        CanonicalValue::String(topic.to_owned()),
        CanonicalValue::Sequence(
            source_atoms
                .iter()
                .map(|atom| CanonicalValue::String(atom.atom_id.to_string()))
                .collect(),
        ),
        CanonicalValue::Sequence(
            source_atoms
                .iter()
                .map(|atom| CanonicalValue::String(atom.revision_id.to_string()))
                .collect(),
        ),
        CanonicalValue::Sequence(
            source_atoms
                .iter()
                .map(|atom| {
                    atom.value
                        .exact_hash()
                        .map(|hash| CanonicalValue::Bytes(hash.to_vec()))
                        .map_err(|_| StoreError::StoreCorrupt)
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        CanonicalValue::Sequence(
            source_episode_ids
                .iter()
                .map(|id| CanonicalValue::String(id.to_string()))
                .collect(),
        ),
        CanonicalValue::Sequence(
            contradictions
                .iter()
                .map(|pair| {
                    CanonicalValue::Sequence(
                        pair.iter()
                            .map(|id| CanonicalValue::String(id.to_string()))
                            .collect(),
                    )
                })
                .collect(),
        ),
    ]);
    let blob_digest = sha256("evertrace.wiki_projection.render", 1, &content)
        .map_err(|_| StoreError::StoreCorrupt)?;
    Ok((CasId::from_digest(blob_digest), contradictions))
}

impl SynthesisState {
    pub(super) fn live_source_reference_strings(&self) -> Vec<&str> {
        self.digests
            .values()
            .flat_map(|(digest, _)| digest.selected_direct_refs.iter().map(String::as_str))
            .chain(
                self.runs
                    .values()
                    .flat_map(|(run, _)| run.selected_direct_refs.iter().map(String::as_str)),
            )
            .collect()
    }

    pub(super) fn digests(&self) -> &BTreeMap<SemanticDigestId, (SemanticDigest, u64)> {
        &self.digests
    }

    pub(super) fn runs(&self) -> &BTreeMap<SemanticDerivationRunId, (SemanticDerivationRun, u64)> {
        &self.runs
    }

    pub(super) fn has_fingerprint(&self, fingerprint: &[u8; 32]) -> bool {
        self.successful_fingerprints.contains_key(fingerprint)
    }

    pub(super) fn validate_command<'a>(
        &self,
        view: SynthesisAdmissionView<'_>,
        payloads: impl IntoIterator<Item = &'a JournalPayload>,
    ) -> Result<(), StoreError> {
        let payloads = payloads.into_iter().collect::<Vec<_>>();
        let digests = payloads
            .iter()
            .filter_map(|payload| match payload {
                JournalPayload::SemanticDigestRecorded(value) => Some(value.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let runs = payloads
            .iter()
            .filter_map(|payload| match payload {
                JournalPayload::SemanticDerivationRunRecorded(value) => Some(value.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let episodes = payloads
            .iter()
            .filter_map(|payload| match payload {
                JournalPayload::WorkEpisodeRecorded(value) => Some(value.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let proposals = payloads
            .iter()
            .filter_map(|payload| match payload {
                JournalPayload::RevisionProposalRecorded(value) => Some(value.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();
        if runs.len() > 1 || digests.len() > 1 {
            return Err(StoreError::StoreCorrupt);
        }
        if runs.iter().any(|run| {
            run.selected_direct_refs
                .iter()
                .any(|reference| !view.refs.contains(reference))
        }) || digests.iter().any(|digest| {
            digest
                .selected_direct_refs
                .iter()
                .any(|reference| !view.refs.contains(reference))
        }) {
            return Err(StoreError::StoreCorrupt);
        }
        if runs
            .iter()
            .any(|run| run.status != DerivationRunStatus::Succeeded)
            && (!proposals.is_empty() || !digests.is_empty() || !episodes.is_empty())
        {
            return Err(StoreError::StoreCorrupt);
        }
        for run in &runs {
            let current = &view
                .episodes
                .get(&run.episode_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            if run.episode_revision_id != current.revision_id
                || run.from_watermark != current.semantic_watermark
                || run.to_watermark != current.source_watermark
            {
                return Err(StoreError::StoreCorrupt);
            }
            if run.status == DerivationRunStatus::Succeeded
                && self.has_fingerprint(&run.job_fingerprint)
            {
                return Err(StoreError::StoreCorrupt);
            }
            if run.status == DerivationRunStatus::Succeeded {
                let matching_digests = digests
                    .iter()
                    .copied()
                    .filter(|digest| digest.job_fingerprint == run.job_fingerprint)
                    .collect::<Vec<_>>();
                let [digest] = matching_digests.as_slice() else {
                    return Err(StoreError::StoreCorrupt);
                };
                if digest.status
                    == evertrace_domain::semantic::SemanticDigestStatus::RejectedInvalid
                    || digest.application.candidates.len() > 1
                {
                    return Err(StoreError::StoreCorrupt);
                }
                let matching_episodes = episodes
                    .iter()
                    .copied()
                    .filter(|episode| episode.episode_id == run.episode_id)
                    .collect::<Vec<_>>();
                let [successor] = matching_episodes.as_slice() else {
                    return Err(StoreError::StoreCorrupt);
                };
                if digest.episode_revision_id != current.revision_id
                    || digest.episode_id != current.episode_id
                    || digest.task_id != current.task_id
                    || digest.repository_id != current.repository_instance_id
                    || digest.worktree_id != current.worktree_instance_id
                    || digest.from_watermark != current.semantic_watermark
                    || digest.to_watermark != current.source_watermark
                    || run.episode_revision_id != current.revision_id
                    || run.from_watermark != digest.from_watermark
                    || run.to_watermark != digest.to_watermark
                    || run.selected_direct_refs != digest.selected_direct_refs
                    || run.model_id != digest.model_id
                    || run.prompt_hash != digest.prompt_hash
                    || run.schema_version != digest.schema_version
                    || run.algorithm_revision != digest.algorithm_revision
                    || run.effective_config_hash != digest.effective_config_hash
                    || run.created_at_us != digest.created_at_us
                    || successor.predecessor_revision_id != Some(current.revision_id)
                    || successor.semantic_watermark != digest.to_watermark
                    || !successor
                        .semantic_digest_refs
                        .contains(&digest.semantic_digest_id.to_string())
                    || successor.semantic_digest_refs.len()
                        != current.semantic_digest_refs.len() + 1
                {
                    return Err(StoreError::StoreCorrupt);
                }
                current
                    .validate_successor(successor)
                    .map_err(|_| StoreError::StoreCorrupt)?;
                if self.digests.values().any(|(prior, _)| {
                    prior.episode_id == digest.episode_id
                        && prior.selected_direct_refs.iter().any(|reference| {
                            digest.selected_direct_refs.binary_search(reference).is_ok()
                        })
                }) {
                    return Err(StoreError::StoreCorrupt);
                }
                let candidates = digest
                    .application
                    .candidates
                    .iter()
                    .filter(|candidate| {
                        !matches!(candidate, SemanticCandidate::ScenarioPatch { .. })
                    })
                    .collect::<Vec<_>>();
                let expected_source_cohort = digest
                    .selected_direct_refs
                    .iter()
                    .filter(|reference| view.proposal_evidence_refs.contains(*reference))
                    .cloned()
                    .collect::<Vec<_>>();
                if candidates.iter().any(|candidate| {
                    let same_command = proposals.iter().filter(|proposal| {
                        proposal.status == ProposalStatus::Pending
                            && proposal.eligibility == ProposalEligibility::ManualRequired
                            && proposal.created_by == ProposalCreatedBy::Agent
                            && proposal.evidence_refs == vec![digest.semantic_digest_id.to_string()]
                            && proposal.source_cohort_refs == expected_source_cohort
                            && candidate_matches(candidate, proposal)
                    });
                    let existing = view.proposals.values().filter(|(proposal, _)| {
                        matches!(
                            proposal.status,
                            ProposalStatus::Pending
                                | ProposalStatus::Validating
                                | ProposalStatus::Deferred
                        ) && proposal.eligibility == ProposalEligibility::ManualRequired
                            && proposal.created_by == ProposalCreatedBy::Agent
                            && proposal.source_cohort_refs == expected_source_cohort
                            && candidate_matches(candidate, proposal)
                    });
                    same_command.count() + existing.count() != 1
                }) || proposals.len() > candidates.len()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                for candidate in &digest.application.candidates {
                    match candidate {
                        SemanticCandidate::ScenarioPatch {
                            scenario_revision_id,
                            task_id,
                            repository_id,
                            worktree_id,
                            ..
                        } => {
                            let scenario = view
                                .s23
                                .current_scenario(*scenario_revision_id)
                                .ok_or(StoreError::StoreCorrupt)?;
                            if scenario.scope.task_id != *task_id
                                || scenario.scope.task_id != current.task_id
                                || scenario.scope.repository_instance_id != *repository_id
                                || scenario.scope.worktree_instance_id != *worktree_id
                                || *repository_id != current.repository_instance_id
                                || *worktree_id != current.worktree_instance_id
                            {
                                return Err(StoreError::StoreCorrupt);
                            }
                        }
                        SemanticCandidate::AtomProposal {
                            target_id,
                            base_revision_id,
                            payload,
                        } => {
                            let expected = AtomScope::Task {
                                task_id: current.task_id,
                            };
                            let draft = match payload.as_ref() {
                                evertrace_domain::semantic::AtomProposalPayload::Create {
                                    draft,
                                }
                                | evertrace_domain::semantic::AtomProposalPayload::Replace {
                                    draft,
                                }
                                | evertrace_domain::semantic::AtomProposalPayload::Reclassify {
                                    draft,
                                } => draft,
                                _ => return Err(StoreError::StoreCorrupt),
                            };
                            let expected_epistemic = if draft.kind.is_normative() {
                                EpistemicStatus::NotApplicable
                            } else {
                                EpistemicStatus::Unverified
                            };
                            if draft.scope != expected
                                || draft.epistemic_status != expected_epistemic
                                || draft.provenance != [AtomProvenance::LlmDerived]
                                || !draft.source_observation_refs.is_empty()
                                || draft.evidence_refs != expected_source_cohort
                                || !draft.supersedes_revision_refs.is_empty()
                                || !draft.supports_revision_refs.is_empty()
                                || !draft.contradicts_revision_refs.is_empty()
                                || !draft.value.critical_revision_refs.is_empty()
                                || draft.future_cue_lifecycle_exprs.is_some()
                                || draft.validity_interval.valid_from_us != run.created_at_us
                                || draft.validity_interval.valid_until_us.is_some()
                            {
                                return Err(StoreError::StoreCorrupt);
                            }
                            if let Some(target_id) = target_id {
                                let atom =
                                    view.atoms.get(target_id).ok_or(StoreError::StoreCorrupt)?;
                                if Some(atom.0.revision_id) != *base_revision_id
                                    || atom.0.scope != expected
                                {
                                    return Err(StoreError::StoreCorrupt);
                                }
                            }
                        }
                        SemanticCandidate::ProcedureProposal {
                            target_id,
                            base_revision_id,
                            payload,
                        } => {
                            let expected = match (
                                current.repository_instance_id,
                                current.worktree_instance_id,
                            ) {
                                (Some(repository_id), Some(worktree_id)) => {
                                    evertrace_domain::procedure::ProcedureScope::Worktree {
                                        repository_id,
                                        worktree_id,
                                    }
                                }
                                (Some(repository_id), None) => {
                                    evertrace_domain::procedure::ProcedureScope::Repository {
                                        repository_id,
                                    }
                                }
                                _ => return Err(StoreError::StoreCorrupt),
                            };
                            let draft = payload.draft();
                            if draft.scope != expected
                                || draft.condition_ir_version != 1
                                || draft.evidence_refs != expected_source_cohort
                                || !draft.support_revision_refs.is_empty()
                            {
                                return Err(StoreError::StoreCorrupt);
                            }
                            if let Some(target_id) = target_id {
                                let revision = view
                                    .procedures
                                    .current_revision(*target_id)
                                    .ok_or(StoreError::StoreCorrupt)?;
                                if Some(revision.revision_id) != *base_revision_id
                                    || revision.draft.scope != expected
                                {
                                    return Err(StoreError::StoreCorrupt);
                                }
                            }
                        }
                    }
                }
            } else if digests
                .iter()
                .any(|digest| digest.job_fingerprint == run.job_fingerprint)
                || episodes.iter().any(|episode| {
                    episode.episode_id == run.episode_id
                        && episode.semantic_watermark == run.to_watermark
                })
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if digests.len()
            != runs
                .iter()
                .filter(|run| run.status == DerivationRunStatus::Succeeded)
                .count()
        {
            return Err(StoreError::StoreCorrupt);
        }
        for successor in episodes {
            let Some((current, _)) = view.episodes.get(&successor.episode_id) else {
                continue;
            };
            if successor.semantic_watermark != current.semantic_watermark
                || successor.semantic_digest_refs != current.semantic_digest_refs
            {
                let matching = runs
                    .iter()
                    .filter(|run| {
                        run.status == DerivationRunStatus::Succeeded
                            && run.episode_id == successor.episode_id
                    })
                    .count();
                if matching != 1 {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
        Ok(())
    }

    pub(super) fn apply(&mut self, payload: JournalPayload, seq: u64) -> Result<bool, StoreError> {
        match payload {
            JournalPayload::SemanticDigestRecorded(value) => {
                let value = *value;
                if self
                    .digests
                    .insert(value.semantic_digest_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                Ok(true)
            }
            JournalPayload::SemanticDerivationRunRecorded(value) => {
                let value = *value;
                if value.status == DerivationRunStatus::Succeeded
                    && self
                        .successful_fingerprints
                        .insert(value.job_fingerprint, value.derivation_run_id)
                        .is_some()
                    || self
                        .runs
                        .insert(value.derivation_run_id, (value, seq))
                        .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub(super) fn restore(&mut self, payload: JournalPayload, seq: u64) -> Result<(), StoreError> {
        if !self.apply(payload, seq)? {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    pub(super) fn rebuild(
        &mut self,
        episodes: &BTreeMap<evertrace_domain::ids::WorkEpisodeId, (WorkEpisode, u64)>,
        episode_revisions: &BTreeMap<evertrace_domain::revision::RevisionId, (WorkEpisode, u64)>,
    ) -> Result<(), StoreError> {
        self.successful_fingerprints.clear();
        for (id, (run, _)) in &self.runs {
            run.validate().map_err(|_| StoreError::StoreCorrupt)?;
            let bound_episode = &episode_revisions
                .get(&run.episode_revision_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            if bound_episode.episode_id != run.episode_id
                || bound_episode.semantic_watermark != run.from_watermark
                || bound_episode.source_watermark != run.to_watermark
            {
                return Err(StoreError::StoreCorrupt);
            }
            if run.status == DerivationRunStatus::Succeeded
                && self
                    .successful_fingerprints
                    .insert(run.job_fingerprint, *id)
                    .is_some()
            {
                return Err(StoreError::StoreCorrupt);
            }
            if run.status == DerivationRunStatus::Succeeded {
                let mut matching = self
                    .digests
                    .values()
                    .filter(|(digest, _)| digest.job_fingerprint == run.job_fingerprint);
                let Some((digest, _)) = matching.next() else {
                    return Err(StoreError::StoreCorrupt);
                };
                if matching.next().is_some()
                    || digest.episode_id != run.episode_id
                    || digest.episode_revision_id != run.episode_revision_id
                    || digest.from_watermark != run.from_watermark
                    || digest.to_watermark != run.to_watermark
                    || digest.created_at_us != run.created_at_us
                    || digest.application.candidates.len() > 1
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
        for (digest, _) in self.digests.values() {
            digest.validate().map_err(|_| StoreError::StoreCorrupt)?;
            if self
                .runs
                .values()
                .filter(|(run, _)| {
                    run.status == DerivationRunStatus::Succeeded
                        && run.job_fingerprint == digest.job_fingerprint
                })
                .count()
                != 1
            {
                return Err(StoreError::StoreCorrupt);
            }
            let episode = &episodes
                .get(&digest.episode_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            if episode.task_id != digest.task_id
                || episode.repository_instance_id != digest.repository_id
                || episode.worktree_instance_id != digest.worktree_id
                || episode.semantic_watermark < digest.to_watermark
                || !episode
                    .semantic_digest_refs
                    .contains(&digest.semantic_digest_id.to_string())
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for (episode, _) in episodes.values() {
            for reference in &episode.semantic_digest_refs {
                let id = reference
                    .parse::<SemanticDigestId>()
                    .map_err(|_| StoreError::StoreCorrupt)?;
                if self
                    .digests
                    .get(&id)
                    .is_none_or(|(digest, _)| digest.episode_id != episode.episode_id)
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
        Ok(())
    }

    pub(super) fn rows(self) -> Result<Vec<ObjectRow>, StoreError> {
        let mut rows = Vec::with_capacity(self.digests.len() + self.runs.len());
        for (id, (value, seq)) in self.digests {
            let task_id = value.task_id.to_string();
            let repository_id = value.repository_id.map(|id| id.to_string());
            let worktree_id = value.worktree_id.map(|id| id.to_string());
            rows.push(row(
                format!("object:work:semantic_digest:{id}"),
                "semantic_digest",
                id.to_string(),
                &JournalPayload::SemanticDigestRecorded(Box::new(value)),
                seq,
                Some((task_id, repository_id, worktree_id)),
            )?);
        }
        for (id, (value, seq)) in self.runs {
            rows.push(row(
                format!("object:work:semantic_derivation_run:{id}"),
                "semantic_derivation_run",
                id.to_string(),
                &JournalPayload::SemanticDerivationRunRecorded(Box::new(value)),
                seq,
                None,
            )?);
        }
        Ok(rows)
    }
}

fn candidate_matches(
    candidate: &SemanticCandidate,
    proposal: &evertrace_domain::semantic::RevisionProposal,
) -> bool {
    match candidate {
        SemanticCandidate::ScenarioPatch { .. } => false,
        SemanticCandidate::AtomProposal {
            target_id,
            base_revision_id,
            payload,
        } => {
            proposal.target_kind == ProposalTargetKind::Atom
                && proposal.target_id == target_id.map(ProposalTargetId::Atom)
                && proposal.base_revision_id == *base_revision_id
                && proposal.payload == ProposalPayload::Atom(payload.clone())
        }
        SemanticCandidate::ProcedureProposal {
            target_id,
            base_revision_id,
            payload,
        } => {
            proposal.target_kind == ProposalTargetKind::Procedure
                && proposal.target_id == target_id.map(ProposalTargetId::Procedure)
                && proposal.base_revision_id == *base_revision_id
                && proposal.payload == ProposalPayload::Procedure(payload.clone())
        }
    }
}

fn row(
    row_id: String,
    kind: &str,
    id: String,
    payload: &JournalPayload,
    seq: u64,
    scope: Option<(String, Option<String>, Option<String>)>,
) -> Result<ObjectRow, StoreError> {
    let (task_id, repository_id, worktree_id) = scope
        .map(|(task, repository, worktree)| (Some(task), repository, worktree))
        .unwrap_or((None, None, None));
    Ok(ObjectRow {
        row_id,
        row_kind: ObjectRowKind::Data,
        row_class: Some(ObjectRowClass::Object),
        object_family: Some(ObjectFamily::Work),
        object_kind: Some(kind.into()),
        object_id: Some(id.clone()),
        current_revision_id: Some(id),
        lifecycle: Some("immutable".into()),
        epistemic: Some("derived".into()),
        authority: Some("none".into()),
        publication_state: None,
        support_state: None,
        project_id: None,
        repository_id,
        worktree_id,
        task_id,
        workstream_id: None,
        session_id: None,
        payload_json: Some(payload.canonical_json()?),
        source_event_seq: seq,
        projection_generation: PROJECTION_GENERATION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use evertrace_domain::{
        ids::{AtomId, RepositoryId, RevisionProposalId, SourceObservationId},
        revision::RevisionId,
        semantic::{
            AcceptedProposalTarget, ApplicabilityExpr, AtomAuthority, AtomDraft, AtomKind,
            AtomProposalPayload, AtomProvenance, AtomValue, EpistemicStatus, ProposalAcceptance,
            ProposalAcceptanceAuthority, ProposalCreatedBy, ProposalEligibility, ProposalOperation,
            ProposalPayload, RevisionProposal, ValidityInterval,
        },
    };

    fn reviewed_atom(
        atom_id: AtomId,
        revision_id: RevisionId,
        repository_id: RepositoryId,
        contradiction: Option<RevisionId>,
    ) -> (Atom, RevisionProposal) {
        let proposal_id = RevisionProposalId::new_v7();
        let proposal_revision_id = RevisionId::new_v7();
        let atom = Atom {
            atom_id,
            revision_id,
            parent_revision_id: None,
            kind: AtomKind::Fact,
            epistemic_status: EpistemicStatus::Unverified,
            lifecycle_status: AtomLifecycleStatus::Active,
            authority: AtomAuthority::AgentInferred,
            value: AtomValue {
                text: "reviewed repository conclusion".into(),
                subject: "Build Safety".into(),
                predicate: "records".into(),
                object: Some("bounded evidence".into()),
                qualifiers: vec![],
                critical_revision_refs: vec![],
            },
            scope: AtomScope::Repository {
                repository_instance_id: repository_id,
            },
            condition_ir_version: 1,
            applicability_expr: ApplicabilityExpr::Always,
            future_cue_lifecycle_exprs: None,
            validity_interval: ValidityInterval {
                valid_from_us: 1,
                valid_until_us: None,
            },
            provenance: vec![AtomProvenance::LlmDerived],
            user_authorization_provenance: None,
            policy_authority_provenance: None,
            source_observation_refs: vec![],
            evidence_refs: vec!["evidence:reviewed".into()],
            supersedes_revision_refs: vec![],
            supports_revision_refs: vec![],
            contradicts_revision_refs: contradiction.into_iter().collect(),
            accepted_proposal_id: Some(proposal_id),
            accepted_proposal_revision_id: Some(proposal_revision_id),
            created_at_us: 1,
        };
        let mut proposal = RevisionProposal {
            proposal_id,
            proposal_revision_id,
            parent_proposal_revision_id: Some(RevisionId::new_v7()),
            target_kind: ProposalTargetKind::Atom,
            target_id: None,
            base_revision_id: None,
            operation: ProposalOperation::Create,
            payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Create {
                draft: AtomDraft {
                    kind: atom.kind,
                    epistemic_status: atom.epistemic_status,
                    value: atom.value.clone(),
                    scope: atom.scope.clone(),
                    applicability_expr: atom.applicability_expr.clone(),
                    future_cue_lifecycle_exprs: None,
                    validity_interval: atom.validity_interval.clone(),
                    provenance: atom.provenance.clone(),
                    source_observation_refs: vec![],
                    evidence_refs: atom.evidence_refs.clone(),
                    supersedes_revision_refs: vec![],
                    supports_revision_refs: vec![],
                    contradicts_revision_refs: atom.contradicts_revision_refs.clone(),
                },
            })),
            evidence_refs: vec!["evidence:reviewed".into()],
            source_cohort_refs: vec!["evidence:reviewed".into()],
            source_cohort_hash: [0; 32],
            fingerprint: [0; 32],
            eligibility: ProposalEligibility::ManualRequired,
            status: ProposalStatus::Accepted,
            waiting_on: vec![],
            review_reason: None,
            created_by: ProposalCreatedBy::Agent,
            acceptance: None,
            created_at_us: 1,
            reviewed_at_us: Some(2),
        };
        proposal.source_cohort_hash = proposal.recompute_source_cohort_hash().unwrap();
        proposal.fingerprint = proposal.recompute_fingerprint().unwrap();
        proposal.acceptance = Some(ProposalAcceptance {
            reviewer_identity: "reviewer".into(),
            acceptance_event_ref: "review-event".into(),
            reviewed_proposal_revision_id: proposal.parent_proposal_revision_id.unwrap(),
            reviewed_fingerprint: proposal.fingerprint,
            accepted_target: AcceptedProposalTarget::Atom {
                atom_id,
                atom_revision_id: revision_id,
                structure_hash: atom.semantic_structure_hash().unwrap(),
            },
            authority_basis: ProposalAcceptanceAuthority::TuiAcceptance {
                user_source_observation_ref: SourceObservationId::from_digest([7; 32]),
                authorized_scope_ceiling: atom.scope.clone(),
            },
            accepted_at_us: 2,
        });
        proposal.validate().unwrap();
        (atom, proposal)
    }

    #[test]
    fn wiki_projection_is_reviewed_current_scoped_and_keeps_contradictions() {
        let repository_id = RepositoryId::new_v7();
        let left_revision = RevisionId::new_v7();
        let right_revision = RevisionId::new_v7();
        let (left, left_proposal) = reviewed_atom(
            AtomId::new_v7(),
            left_revision,
            repository_id,
            Some(right_revision),
        );
        let (right, right_proposal) = reviewed_atom(
            AtomId::new_v7(),
            right_revision,
            repository_id,
            Some(left_revision),
        );
        left.validate().unwrap();
        right.validate().unwrap();
        let atoms: BTreeMap<_, _> = [(left.atom_id, (left, 10)), (right.atom_id, (right, 11))]
            .into_iter()
            .collect();
        let proposals = [left_proposal, right_proposal]
            .into_iter()
            .map(|proposal| (proposal.proposal_id, (proposal, 9)))
            .collect();
        let rows = wiki_rows(
            &atoms,
            &proposals,
            &BTreeMap::new(),
            &SynthesisState::default(),
            &super::super::s23::S23State::default(),
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        let projection = restore_wiki_projection(&rows[0]).unwrap().unwrap();
        assert_eq!(projection.topic, "build safety");
        assert_eq!(projection.source_atom_ids.len(), 2);
        let source_atoms = projection
            .source_atom_ids
            .iter()
            .map(|id| &atoms.get(id).unwrap().0)
            .collect::<Vec<_>>();
        let (rendered_blob_ref, contradictions) =
            wiki_render_identity(&projection.topic, &source_atoms, &[]).unwrap();
        assert_eq!(rendered_blob_ref, projection.rendered_blob_ref);
        assert_eq!(contradictions.len(), 1);
        assert_eq!(projection.source_watermark, 11);
    }

    #[test]
    fn wiki_projection_excludes_supported_claim_with_active_same_scope_contradiction() {
        let repository_id = RepositoryId::new_v7();
        let claim_revision = RevisionId::new_v7();
        let other_revision = RevisionId::new_v7();
        let (mut claim, mut claim_proposal) = reviewed_atom(
            AtomId::new_v7(),
            claim_revision,
            repository_id,
            Some(other_revision),
        );
        claim.kind = AtomKind::Claim;
        claim.epistemic_status = EpistemicStatus::Supported;
        claim.authority = AtomAuthority::ObjectiveEvidence;
        claim.provenance = vec![AtomProvenance::ObservedExec];
        let acceptance = claim_proposal.acceptance.as_mut().unwrap();
        let AcceptedProposalTarget::Atom { structure_hash, .. } = &mut acceptance.accepted_target
        else {
            unreachable!()
        };
        *structure_hash = claim.semantic_structure_hash().unwrap();
        claim.validate().unwrap();
        let (other, other_proposal) = reviewed_atom(
            AtomId::new_v7(),
            other_revision,
            repository_id,
            Some(claim_revision),
        );
        let atoms = [(claim.atom_id, (claim, 10)), (other.atom_id, (other, 11))]
            .into_iter()
            .collect();
        let proposals = [claim_proposal, other_proposal]
            .into_iter()
            .map(|proposal| (proposal.proposal_id, (proposal, 9)))
            .collect();
        let rows = wiki_rows(
            &atoms,
            &proposals,
            &BTreeMap::new(),
            &SynthesisState::default(),
            &super::super::s23::S23State::default(),
        )
        .unwrap();
        let projection = restore_wiki_projection(&rows[0]).unwrap().unwrap();
        assert_eq!(projection.source_atom_ids.len(), 1);
    }
}
