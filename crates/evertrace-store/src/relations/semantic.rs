use std::collections::BTreeSet;

use evertrace_domain::procedure::ProcedureRevision;
use evertrace_domain::semantic::{
    Atom, CoreMembership, GlobalSuccessorSupportContract, ProposalStatus, ProposalTargetId,
    RevisionProposal,
};

use crate::StoreError;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SemanticRelationKind {
    AtomRevisionSuccessor,
    AtomSupersedes,
    AtomSupports,
    AtomContradicts,
    AtomFromSourceObservation,
    ProposalRevisionSuccessor,
    ProposalReviewedRevision,
    ProposalTargetsAtom,
    ProposalAcceptedAtomRevision,
    CoreMembershipToAtomRevision,
    CoreMembershipSuccessor,
    SupportContractSupportsRevision,
    SupportContractAuthorizesRevision,
    ProcedureRevisionSuccessor,
    ProcedureSupportsRevision,
}

pub fn build_procedure_relation_rows(
    procedures: &[ProcedureRevision],
    atoms: &[Atom],
) -> Result<Vec<SemanticRelationRow>, StoreError> {
    let procedure_revisions = procedures
        .iter()
        .map(|value| value.revision_id)
        .collect::<BTreeSet<_>>();
    let atom_revisions = atoms
        .iter()
        .map(|value| value.revision_id)
        .collect::<BTreeSet<_>>();
    if procedure_revisions.len() != procedures.len() {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for procedure in procedures {
        procedure.validate().map_err(|_| StoreError::InvalidInput)?;
        if let Some(parent) = procedure.parent_revision_id {
            require_target(&procedure_revisions, parent)?;
            insert(
                &mut rows,
                SemanticRelationKind::ProcedureRevisionSuccessor,
                procedure.revision_id,
                parent,
            );
        }
        for support in &procedure.draft.support_revision_refs {
            require_target(&atom_revisions, *support)?;
            insert(
                &mut rows,
                SemanticRelationKind::ProcedureSupportsRevision,
                procedure.revision_id,
                *support,
            );
        }
    }
    Ok(rows.into_iter().collect())
}

pub fn build_core_support_relation_rows(
    memberships: &[CoreMembership],
    contracts: &[GlobalSuccessorSupportContract],
) -> Result<Vec<SemanticRelationRow>, StoreError> {
    let membership_revisions = memberships
        .iter()
        .map(|value| value.membership_revision_id)
        .collect::<BTreeSet<_>>();
    let contract_ids = contracts
        .iter()
        .map(|value| value.support_contract_revision_id)
        .collect::<BTreeSet<_>>();
    if membership_revisions.len() != memberships.len() || contract_ids.len() != contracts.len() {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for membership in memberships {
        membership
            .validate()
            .map_err(|_| StoreError::InvalidInput)?;
        if !contract_ids.contains(&membership.support_contract_ref) {
            return Err(StoreError::InvalidInput);
        }
        rows.insert(SemanticRelationRow {
            kind: SemanticRelationKind::CoreMembershipToAtomRevision,
            source_id: membership.membership_revision_id.to_string(),
            target_id: membership.atom_revision_id.to_string(),
        });
        if let Some(parent) = membership.supersedes_membership_revision_id {
            if !membership_revisions.contains(&parent) {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(SemanticRelationRow {
                kind: SemanticRelationKind::CoreMembershipSuccessor,
                source_id: membership.membership_revision_id.to_string(),
                target_id: parent.to_string(),
            });
        }
    }
    for contract in contracts {
        contract.validate().map_err(|_| StoreError::InvalidInput)?;
        for revision in &contract.support_revision_refs {
            rows.insert(SemanticRelationRow {
                kind: SemanticRelationKind::SupportContractSupportsRevision,
                source_id: contract.support_contract_revision_id.to_string(),
                target_id: revision.to_string(),
            });
        }
        for revision in &contract.authorization_revision_refs {
            rows.insert(SemanticRelationRow {
                kind: SemanticRelationKind::SupportContractAuthorizesRevision,
                source_id: contract.support_contract_revision_id.to_string(),
                target_id: revision.to_string(),
            });
        }
    }
    Ok(rows.into_iter().collect())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SemanticRelationRow {
    pub kind: SemanticRelationKind,
    pub source_id: String,
    pub target_id: String,
}

pub fn build_semantic_relation_rows(
    atoms: &[Atom],
    proposals: &[RevisionProposal],
) -> Result<Vec<SemanticRelationRow>, StoreError> {
    let atom_revisions = atoms
        .iter()
        .map(|atom| atom.revision_id)
        .collect::<BTreeSet<_>>();
    let atom_ids = atoms
        .iter()
        .map(|atom| atom.atom_id)
        .collect::<BTreeSet<_>>();
    let proposal_revisions = proposals
        .iter()
        .map(|proposal| proposal.proposal_revision_id)
        .collect::<BTreeSet<_>>();
    if atom_revisions.len() != atoms.len() || proposal_revisions.len() != proposals.len() {
        return Err(StoreError::InvalidInput);
    }
    let mut rows = BTreeSet::new();
    for atom in atoms {
        atom.validate().map_err(|_| StoreError::InvalidInput)?;
        if let Some(parent) = atom.parent_revision_id {
            require_target(&atom_revisions, parent)?;
            insert(
                &mut rows,
                SemanticRelationKind::AtomRevisionSuccessor,
                atom.revision_id,
                parent,
            );
        }
        for revision in &atom.supersedes_revision_refs {
            require_target(&atom_revisions, *revision)?;
            insert(
                &mut rows,
                SemanticRelationKind::AtomSupersedes,
                atom.revision_id,
                *revision,
            );
        }
        for revision in &atom.supports_revision_refs {
            require_target(&atom_revisions, *revision)?;
            insert(
                &mut rows,
                SemanticRelationKind::AtomSupports,
                atom.revision_id,
                *revision,
            );
        }
        for revision in &atom.contradicts_revision_refs {
            require_target(&atom_revisions, *revision)?;
            insert(
                &mut rows,
                SemanticRelationKind::AtomContradicts,
                atom.revision_id,
                *revision,
            );
        }
        for observation in &atom.source_observation_refs {
            rows.insert(SemanticRelationRow {
                kind: SemanticRelationKind::AtomFromSourceObservation,
                source_id: atom.revision_id.to_string(),
                target_id: observation.to_string(),
            });
        }
    }
    for proposal in proposals {
        proposal.validate().map_err(|_| StoreError::InvalidInput)?;
        if let Some(parent) = proposal.parent_proposal_revision_id {
            require_target(&proposal_revisions, parent)?;
            insert(
                &mut rows,
                SemanticRelationKind::ProposalRevisionSuccessor,
                proposal.proposal_revision_id,
                parent,
            );
        }
        if let Some(ProposalTargetId::Atom(atom_id)) = proposal.target_id {
            if !atom_ids.contains(&atom_id) {
                return Err(StoreError::InvalidInput);
            }
            rows.insert(SemanticRelationRow {
                kind: SemanticRelationKind::ProposalTargetsAtom,
                source_id: proposal.proposal_revision_id.to_string(),
                target_id: atom_id.to_string(),
            });
        }
        if proposal.status == ProposalStatus::Accepted {
            let acceptance = proposal
                .acceptance
                .as_ref()
                .ok_or(StoreError::InvalidInput)?;
            require_target(
                &proposal_revisions,
                acceptance.reviewed_proposal_revision_id,
            )?;
            insert(
                &mut rows,
                SemanticRelationKind::ProposalReviewedRevision,
                proposal.proposal_revision_id,
                acceptance.reviewed_proposal_revision_id,
            );
            if let Some((_, accepted_atom_revision_id, _)) = acceptance.accepted_atom() {
                require_target(&atom_revisions, accepted_atom_revision_id)?;
                insert(
                    &mut rows,
                    SemanticRelationKind::ProposalAcceptedAtomRevision,
                    proposal.proposal_revision_id,
                    accepted_atom_revision_id,
                );
            }
        }
    }
    Ok(rows.into_iter().collect())
}

fn require_target(
    values: &BTreeSet<evertrace_domain::revision::RevisionId>,
    value: evertrace_domain::revision::RevisionId,
) -> Result<(), StoreError> {
    if values.contains(&value) {
        Ok(())
    } else {
        Err(StoreError::InvalidInput)
    }
}

fn insert(
    rows: &mut BTreeSet<SemanticRelationRow>,
    kind: SemanticRelationKind,
    source: evertrace_domain::revision::RevisionId,
    target: evertrace_domain::revision::RevisionId,
) {
    rows.insert(SemanticRelationRow {
        kind,
        source_id: source.to_string(),
        target_id: target.to_string(),
    });
}
