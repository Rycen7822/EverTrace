//! Request-local interpretation of readable canonical semantic revisions.
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use evertrace_codex::HostProbeReport;
use evertrace_domain::{
    ids::SourceObservationId,
    query::SearchContext,
    revision::RevisionId,
    semantic::{
        AtomAuthority, DescriptiveResolutionState, NormativeResolutionState,
        ProposalAcceptanceAuthority, SemanticResolution,
    },
};
use evertrace_store::{JournalPayload, ObjectRow, ProjectionSnapshot, SemanticCurrentView};

use crate::semantic::{
    CurrentPolicyBinding, DescriptiveFactResolver, NormativeInstructionResolver, ResolverContext,
    scope_applies,
};

use super::SearchError;

pub(crate) struct SemanticSearchResolution {
    pub frontier: u64,
    pub states: BTreeMap<String, SemanticResolution>,
    pub incomplete: bool,
}

impl SemanticSearchResolution {
    pub fn for_human_read(
        snapshot: &ProjectionSnapshot,
        readable: &BTreeSet<String>,
        index: &BTreeMap<&str, Vec<&ObjectRow>>,
        query: &SearchContext,
        report: Option<&HostProbeReport>,
        now_us: i64,
        deadline: Instant,
    ) -> Result<(Self, BTreeSet<String>), SearchError> {
        let view = SemanticCurrentView::from_snapshot(snapshot)?;
        let (unavailable_core_revisions, mut dependencies) =
            core_read_state(snapshot, readable, index, deadline)?;
        // A human read has no managed execution binding. Unknown phase/verifier
        // fields stay absent rather than borrowing another session's state.
        let mut context = ResolverContext {
            task_id: query.task_id,
            repository_instance_id: query.repository_id.or_else(|| {
                query
                    .worktree_id
                    .and_then(|id| crate::service::active_worktree_repository(snapshot, id))
            }),
            worktree_instance_id: query.worktree_id,
            now_us,
            globally_supported_revisions: snapshot
                .data_rows()
                .filter(|row| {
                    row.object_kind.as_deref() == Some("atom_revision")
                        && row.support_state.as_deref() == Some("valid")
                })
                .filter_map(|row| row.current_revision_id.as_deref()?.parse().ok())
                .collect(),
            unavailable_core_revisions,
            ..ResolverContext::default()
        };
        let atoms = view
            .atoms
            .values()
            .filter(|atom| readable.contains(&atom.revision_id.to_string()))
            .cloned()
            .collect::<Vec<_>>();
        if let Some(report) = report
            && let Some(evidence) = report.current_project_policy_evidence()
        {
            for atom in &atoms {
                if atom.authority != AtomAuthority::ProjectPolicy {
                    continue;
                }
                let Some(provenance) = &atom.policy_authority_provenance else {
                    continue;
                };
                for id in &atom.source_observation_refs {
                    if let Some(binding) =
                        policy_binding(index, *id, report, &evidence, provenance.clone())
                    {
                        context.current_policy_bindings.insert(binding);
                    }
                }
            }
        }
        // An unreturned rule can still shadow a returned one. Its source
        // permission is part of this interpretation and must be rechecked too.
        dependencies.extend(atoms.iter().map(|atom| atom.revision_id.to_string()));
        let (normative_atoms, descriptive_atoms): (Vec<_>, Vec<_>) =
            atoms.into_iter().partition(|atom| atom.kind.is_normative());
        let normative = NormativeInstructionResolver.resolve(&normative_atoms, &context);
        let descriptive = DescriptiveFactResolver.resolve(&descriptive_atoms, &context);
        let mut states = BTreeMap::new();
        let mut incomplete = false;
        for resolution in normative {
            if matches!(
                resolution.state,
                NormativeResolutionState::ApplicabilityUnknown
                    | NormativeResolutionState::SupportUnavailable
            ) && view
                .atom_revisions
                .get(&resolution.revision_id)
                .is_some_and(|atom| scope_applies(&atom.scope, &context))
            {
                incomplete = true;
            }
            states.insert(
                resolution.revision_id.to_string(),
                SemanticResolution::Normative(resolution.state),
            );
        }
        for resolution in descriptive {
            states.insert(
                resolution.revision_id.to_string(),
                SemanticResolution::Descriptive(resolution.state),
            );
        }
        // A readable predecessor is historical, never the current active rule.
        for atom in view.atom_revisions.values() {
            if !readable.contains(&atom.revision_id.to_string()) {
                continue;
            }
            states
                .entry(atom.revision_id.to_string())
                .or_insert_with(|| {
                    if atom.kind.is_normative() {
                        SemanticResolution::Normative(NormativeResolutionState::Shadowed)
                    } else {
                        SemanticResolution::Descriptive(DescriptiveResolutionState::Underdetermined)
                    }
                });
        }
        Ok((
            Self {
                frontier: snapshot.frontier,
                states,
                incomplete,
            },
            dependencies,
        ))
    }

    pub fn active_references(&self) -> Vec<String> {
        self.states
            .iter()
            .filter(|(_, state)| {
                **state == SemanticResolution::Normative(NormativeResolutionState::Active)
            })
            .map(|(reference, _)| reference.clone())
            .collect()
    }
}

fn core_read_state(
    snapshot: &ProjectionSnapshot,
    readable: &BTreeSet<String>,
    index: &BTreeMap<&str, Vec<&ObjectRow>>,
    deadline: Instant,
) -> Result<(BTreeSet<RevisionId>, BTreeSet<String>), SearchError> {
    let mut members = BTreeMap::new();
    let mut unavailable = BTreeSet::new();
    for row in snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("core_membership"))
    {
        if Instant::now() >= deadline {
            return Err(SearchError::Unsupported);
        }
        let JournalPayload::CoreMembershipRecorded(member) = decode(row)? else {
            return Err(SearchError::Corrupt);
        };
        if readable.contains(&member.atom_revision_id.to_string()) {
            unavailable.insert(member.atom_revision_id);
            members.insert(member.membership_revision_id, member);
        }
    }
    let mut checks = BTreeSet::new();
    for row in snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("l3_core_projection"))
    {
        let projection =
            evertrace_store::projections::l3_core_projection(row)?.ok_or(SearchError::Corrupt)?;
        'candidates: for revision in projection.active_membership_revision_ids {
            if Instant::now() >= deadline {
                return Err(SearchError::Unsupported);
            }
            let Some(member) = members.get(&revision) else {
                continue;
            };
            // The compiler chooses current, conflict-free memberships with valid support; the request
            // still needs present and readable contract, authorization, and acknowledgement sources.
            if !member.active
                || member.scope_identity != projection.scope_identity
                || projection
                    .atom_revision_ids
                    .binary_search(&member.atom_revision_id)
                    .is_err()
            {
                return Err(SearchError::Corrupt);
            }
            let mut required = vec![
                revision.to_string(),
                member.support_contract_ref.to_string(),
            ];
            for authorization in &member.authorization_revision_refs {
                let authorization = authorization.to_string();
                let Some([row]) = index.get(authorization.as_str()).map(Vec::as_slice) else {
                    continue 'candidates;
                };
                let JournalPayload::RevisionProposalRecorded(proposal) = decode(row)? else {
                    return Err(SearchError::Corrupt);
                };
                let Some(acceptance) = proposal.acceptance else {
                    continue 'candidates;
                };
                let source = match acceptance.authority_basis {
                    ProposalAcceptanceAuthority::CurrentTaskExactMessage {
                        user_source_observation_ref,
                    }
                    | ProposalAcceptanceAuthority::TuiAcceptance {
                        user_source_observation_ref,
                        ..
                    }
                    | ProposalAcceptanceAuthority::ObjectiveEvidence {
                        user_source_observation_ref,
                    } => user_source_observation_ref,
                };
                required.extend([authorization, source.to_string()]);
            }
            if required.iter().all(|id| readable.contains(id)) {
                unavailable.remove(&member.atom_revision_id);
                checks.extend(required);
            }
        }
    }
    Ok((unavailable, checks))
}

fn decode(row: &ObjectRow) -> Result<JournalPayload, SearchError> {
    serde_json::from_str(row.payload_json.as_deref().ok_or(SearchError::Corrupt)?)
        .map_err(|_| SearchError::Corrupt)
}

fn policy_binding(
    index: &BTreeMap<&str, Vec<&ObjectRow>>,
    observation_id: SourceObservationId,
    report: &HostProbeReport,
    evidence: &evertrace_codex::policy::PolicyEvidence,
    provenance: evertrace_domain::semantic::PolicyAuthorityProvenance,
) -> Option<CurrentPolicyBinding> {
    let observation_ref = observation_id.to_string();
    let [row] = index.get(observation_ref.as_str())?.as_slice() else {
        return None;
    };
    let JournalPayload::SourceObservationRecorded(observation) =
        serde_json::from_str(row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    let receipt_ref = observation.source_receipt_ref.to_string();
    let [row] = index.get(receipt_ref.as_str())?.as_slice() else {
        return None;
    };
    let JournalPayload::SourceReceiptRecorded(receipt) =
        serde_json::from_str(row.payload_json.as_deref()?).ok()?
    else {
        return None;
    };
    CurrentPolicyBinding::from_verified_host_probe(
        report,
        evidence,
        provenance,
        &observation,
        &receipt,
    )
    .ok()
}

pub(super) fn active_rule(candidate: &evertrace_domain::query::SearchCandidate) -> bool {
    candidate.semantic_resolution
        == Some(SemanticResolution::Normative(
            NormativeResolutionState::Active,
        ))
}
