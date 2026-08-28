use std::collections::BTreeSet;

use evertrace_domain::semantic::{Atom, ProposalStatus, ProposalTargetId, RevisionProposal};

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
            require_target(&atom_revisions, acceptance.accepted_atom_revision_id)?;
            insert(
                &mut rows,
                SemanticRelationKind::ProposalAcceptedAtomRevision,
                proposal.proposal_revision_id,
                acceptance.accepted_atom_revision_id,
            );
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
