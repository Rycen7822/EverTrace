use std::collections::{BTreeMap, BTreeSet};

use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, EvidenceSourceKind, IdentityStrength, ObservationRole,
        SourceArchiveMode, SourceObservation, SourceReceipt, SourceRevisionMode, SourceRole, hex,
        payload_fingerprint,
    },
    ids::{
        AtomId, RepositoryId, ResultEvidenceId, RevisionProposalId, SemanticDigestId,
        SourceObservationId, SourceReceiptId, TaskId, WorkArtifactId, WorktreeId,
    },
    procedure::{ProcedureRevision, ProcedureScope},
    repository::{RepositoryInstance, WorktreeInstance},
    revision::RevisionId,
    semantic::{
        Atom, AtomAuthority, AtomDraft, AtomLifecycleStatus, AtomProposalPayload, AtomScope,
        CoreMembershipProposalPayload, EpistemicStatus, GlobalSupportState,
        ProcedureProposalPayload, ProposalAcceptanceAuthority, ProposalCreatedBy,
        ProposalEligibility, ProposalOperation, ProposalPayload, ProposalStatus, ProposalTargetId,
        ProposalTargetKind, RevisionProposal, TUI_ACCEPTANCE_EVENT_MANIFEST_REF,
        UserAuthorizationMode, VerifierStatus, tui_acceptance_event_payload,
    },
    work::{ArtifactPayloadStatus, Task, WorkArtifact},
};

use crate::{
    JournalPayload, ObjectRowClass, SourceIngestWatermark, StoreError,
    projections::ProjectionSnapshot,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SemanticCurrentView {
    pub frontier: u64,
    pub atoms: BTreeMap<AtomId, Atom>,
    pub atom_revisions: BTreeMap<RevisionId, Atom>,
    pub proposals: BTreeMap<RevisionProposalId, RevisionProposal>,
    pub proposal_revisions: BTreeMap<RevisionId, RevisionProposal>,
}

impl SemanticCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut atom_revisions = BTreeMap::new();
        let mut proposal_revisions = BTreeMap::new();
        for row in snapshot.data_rows() {
            let Some(kind) = row.object_kind.as_deref() else {
                continue;
            };
            if !matches!(kind, "atom_revision" | "revision_proposal_revision") {
                continue;
            }
            if row.row_class != Some(ObjectRowClass::Object) {
                return Err(StoreError::StoreCorrupt);
            }
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            match payload {
                JournalPayload::AtomRecorded(value) if kind == "atom_revision" => {
                    require_row_identity(
                        row,
                        &value.atom_id.to_string(),
                        &value.revision_id.to_string(),
                    )?;
                    let revision_id = value.revision_id;
                    if atom_revisions
                        .insert(revision_id, (*value, row.source_event_seq))
                        .is_some()
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                JournalPayload::RevisionProposalRecorded(value)
                    if kind == "revision_proposal_revision" =>
                {
                    require_row_identity(
                        row,
                        &value.proposal_id.to_string(),
                        &value.proposal_revision_id.to_string(),
                    )?;
                    let revision_id = value.proposal_revision_id;
                    if proposal_revisions
                        .insert(revision_id, (*value, row.source_event_seq))
                        .is_some()
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                _ => return Err(StoreError::StoreCorrupt),
            }
        }
        let mut atoms = BTreeMap::new();
        let mut proposals = BTreeMap::new();
        rebuild_atoms(&mut atoms, &atom_revisions)?;
        rebuild_proposals(&mut proposals, &proposal_revisions)?;
        Ok(Self {
            frontier: snapshot.frontier,
            atoms: atoms
                .into_iter()
                .map(|(id, (value, _))| (id, value))
                .collect(),
            atom_revisions: atom_revisions
                .into_iter()
                .map(|(id, (value, _))| (id, value))
                .collect(),
            proposals: proposals
                .into_iter()
                .map(|(id, (value, _))| (id, value))
                .collect(),
            proposal_revisions: proposal_revisions
                .into_iter()
                .map(|(id, (value, _))| (id, value))
                .collect(),
        })
    }
}

fn require_row_identity(
    row: &crate::ObjectRow,
    stable_id: &str,
    revision_id: &str,
) -> Result<(), StoreError> {
    if row.object_id.as_deref() != Some(stable_id)
        || row.current_revision_id.as_deref() != Some(revision_id)
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

pub(crate) fn record_atom(
    current: &mut BTreeMap<AtomId, (Atom, u64)>,
    revisions: &mut BTreeMap<RevisionId, (Atom, u64)>,
    value: Atom,
    seq: u64,
    error: StoreError,
) -> Result<(), StoreError> {
    value.validate().map_err(|_| error)?;
    if revisions.contains_key(&value.revision_id) {
        return Err(error);
    }
    match value.parent_revision_id {
        None => {
            if current.contains_key(&value.atom_id) {
                return Err(error);
            }
        }
        Some(parent_id) => {
            let (parent, parent_seq) = revisions.get(&parent_id).ok_or(error)?;
            if seq < *parent_seq {
                return Err(error);
            }
            let parent = parent.clone();
            if current
                .get(&value.atom_id)
                .is_none_or(|(current, _)| current.revision_id != parent_id)
            {
                return Err(error);
            }
            parent.validate_successor(&value).map_err(|_| error)?;
        }
    }
    revisions.insert(value.revision_id, (value.clone(), seq));
    current.insert(value.atom_id, (value, seq));
    Ok(())
}

pub(crate) fn record_proposal(
    current: &mut BTreeMap<RevisionProposalId, (RevisionProposal, u64)>,
    revisions: &mut BTreeMap<RevisionId, (RevisionProposal, u64)>,
    value: RevisionProposal,
    seq: u64,
    error: StoreError,
) -> Result<(), StoreError> {
    value.validate().map_err(|_| error)?;
    if revisions.contains_key(&value.proposal_revision_id) {
        return Err(error);
    }
    if is_unfinished_proposal(&value)
        && current.values().any(|(existing, _)| {
            existing.proposal_id != value.proposal_id
                && blocks_new_unfinished_proposal(existing)
                && existing.fingerprint == value.fingerprint
        })
    {
        return Err(error);
    }
    match value.parent_proposal_revision_id {
        None => {
            if current.contains_key(&value.proposal_id) {
                return Err(error);
            }
        }
        Some(parent_id) => {
            let (parent, parent_seq) = revisions.get(&parent_id).ok_or(error)?;
            if seq < *parent_seq {
                return Err(error);
            }
            let parent = parent.clone();
            if current
                .get(&value.proposal_id)
                .is_none_or(|(current, _)| current.proposal_revision_id != parent_id)
            {
                return Err(error);
            }
            parent.validate_successor(&value).map_err(|_| error)?;
        }
    }
    revisions.insert(value.proposal_revision_id, (value.clone(), seq));
    current.insert(value.proposal_id, (value, seq));
    Ok(())
}

fn is_unfinished_proposal(value: &RevisionProposal) -> bool {
    matches!(
        value.status,
        ProposalStatus::Pending | ProposalStatus::Validating | ProposalStatus::Deferred
    )
}

fn blocks_new_unfinished_proposal(value: &RevisionProposal) -> bool {
    is_unfinished_proposal(value) || value.status == ProposalStatus::Accepted
}

pub(crate) fn rebuild_atoms(
    current: &mut BTreeMap<AtomId, (Atom, u64)>,
    revisions: &BTreeMap<RevisionId, (Atom, u64)>,
) -> Result<(), StoreError> {
    current.clear();
    let mut replayed = BTreeMap::new();
    let mut chains = BTreeMap::<AtomId, BTreeMap<Option<RevisionId>, (Atom, u64)>>::new();
    for (value, seq) in revisions.values().cloned() {
        if chains
            .entry(value.atom_id)
            .or_default()
            .insert(value.parent_revision_id, (value, seq))
            .is_some()
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for (atom_id, mut chain) in chains {
        let (root, seq) = chain.remove(&None).ok_or(StoreError::StoreCorrupt)?;
        record_atom(current, &mut replayed, root, seq, StoreError::StoreCorrupt)?;
        while !chain.is_empty() {
            let parent = current
                .get(&atom_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0
                .revision_id;
            let (value, seq) = chain
                .remove(&Some(parent))
                .ok_or(StoreError::StoreCorrupt)?;
            record_atom(current, &mut replayed, value, seq, StoreError::StoreCorrupt)?;
        }
    }
    if replayed != *revisions {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

pub(crate) fn rebuild_proposals(
    current: &mut BTreeMap<RevisionProposalId, (RevisionProposal, u64)>,
    revisions: &BTreeMap<RevisionId, (RevisionProposal, u64)>,
) -> Result<(), StoreError> {
    current.clear();
    let mut replayed = BTreeMap::new();
    let mut chains =
        BTreeMap::<RevisionProposalId, BTreeMap<Option<RevisionId>, (RevisionProposal, u64)>>::new(
        );
    for (value, seq) in revisions.values().cloned() {
        if chains
            .entry(value.proposal_id)
            .or_default()
            .insert(value.parent_proposal_revision_id, (value, seq))
            .is_some()
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for (proposal_id, mut chain) in chains {
        let (root, seq) = chain.remove(&None).ok_or(StoreError::StoreCorrupt)?;
        record_proposal(current, &mut replayed, root, seq, StoreError::StoreCorrupt)?;
        while !chain.is_empty() {
            let parent = current
                .get(&proposal_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0
                .proposal_revision_id;
            let (value, seq) = chain
                .remove(&Some(parent))
                .ok_or(StoreError::StoreCorrupt)?;
            record_proposal(current, &mut replayed, value, seq, StoreError::StoreCorrupt)?;
        }
    }
    if replayed != *revisions {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

pub(crate) struct SemanticRelationInputs<'a> {
    pub atom_revisions: &'a BTreeMap<RevisionId, (Atom, u64)>,
    pub deleted_revision_ids: &'a BTreeSet<RevisionId>,
    pub proposal_revisions: &'a BTreeMap<RevisionId, (RevisionProposal, u64)>,
    pub source_observations: &'a BTreeMap<SourceObservationId, (SourceObservation, u64)>,
    pub source_receipts: &'a BTreeMap<SourceReceiptId, (SourceReceipt, u64)>,
    pub tasks: &'a BTreeMap<TaskId, (Task, u64)>,
    pub repositories: &'a BTreeMap<RepositoryId, (RepositoryInstance, u64)>,
    pub worktrees: &'a BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
    pub results: &'a BTreeMap<ResultEvidenceId, (evertrace_domain::semantic::ResultEvidence, u64)>,
    pub artifacts: &'a BTreeMap<WorkArtifactId, (WorkArtifact, u64)>,
    pub procedure: &'a super::procedure::ProcedureState,
    pub s23: &'a super::s23::S23State,
    pub semantic_digests:
        &'a BTreeMap<SemanticDigestId, (evertrace_domain::semantic::SemanticDigest, u64)>,
}

pub(crate) fn validate_relations(input: SemanticRelationInputs<'_>) -> Result<(), StoreError> {
    for (atom, _) in input.atom_revisions.values() {
        validate_atom_relations(atom, &input)?;
    }
    for (proposal, _) in input.proposal_revisions.values() {
        validate_proposal_relations(proposal, &input)?;
    }
    Ok(())
}

pub(crate) fn validate_command_boundary<'a>(
    current_atoms: &BTreeMap<AtomId, (Atom, u64)>,
    current_proposals: &BTreeMap<RevisionProposalId, (RevisionProposal, u64)>,
    current_procedures: &super::procedure::ProcedureState,
    current_support: &super::s23::S23State,
    events: impl IntoIterator<Item = (&'a JournalPayload, i64, [u8; 32])>,
    error: StoreError,
) -> Result<BTreeSet<RevisionProposalId>, StoreError> {
    let events = events.into_iter().collect::<Vec<_>>();
    let payloads = events
        .iter()
        .map(|(payload, _, _)| *payload)
        .collect::<Vec<_>>();
    validate_support_proposal_boundaries(
        current_atoms,
        current_procedures,
        current_support,
        &payloads,
        error,
    )?;
    let exact_edit_pairs = exact_edit_pairs(current_proposals, &payloads, error)?;
    let mut validated_edit_pairs = BTreeSet::new();
    let mut accepted_edits = BTreeSet::new();
    for proposal in payloads.iter().filter_map(|payload| match payload {
        JournalPayload::RevisionProposalRecorded(value) => Some(value.as_ref()),
        _ => None,
    }) {
        if proposal.target_kind != ProposalTargetKind::Atom {
            continue;
        }
        match (proposal.target_id, proposal.base_revision_id) {
            (None, None) if proposal.operation == ProposalOperation::Create => {}
            (Some(ProposalTargetId::Atom(atom_id)), Some(base_revision_id)) => {
                if current_atoms
                    .get(&atom_id)
                    .is_none_or(|(atom, _)| atom.revision_id != base_revision_id)
                {
                    return Err(error);
                }
            }
            _ => return Err(error),
        }
    }
    for accepted in payloads.iter().filter_map(|payload| match payload {
        JournalPayload::RevisionProposalRecorded(value)
            if value.status == ProposalStatus::Accepted =>
        {
            Some(value.as_ref())
        }
        _ => None,
    }) {
        let acceptance = accepted.acceptance.as_ref().ok_or(error)?;
        let expected_original_id =
            exact_edit_pairs
                .iter()
                .find_map(|(original_id, candidate_id)| {
                    (*candidate_id == accepted.proposal_id).then_some(*original_id)
                });
        if let Some(original_id) = validate_accepted_edit_boundary(
            current_proposals,
            &payloads,
            accepted,
            expected_original_id,
            error,
        )? {
            if !validated_edit_pairs.insert((original_id, accepted.proposal_id)) {
                return Err(error);
            }
            accepted_edits.insert(accepted.proposal_id);
        }
        let Some((accepted_atom_id, accepted_atom_revision_id, _)) = acceptance.accepted_atom()
        else {
            continue;
        };
        let accepted_atoms = events
            .iter()
            .filter(|(payload, _, _)| {
                matches!(
                    payload,
                    JournalPayload::AtomRecorded(atom)
                        if atom.atom_id == accepted_atom_id
                            && atom.revision_id == accepted_atom_revision_id
                            && atom.accepted_proposal_id == Some(accepted.proposal_id)
                            && atom.accepted_proposal_revision_id
                                == Some(accepted.proposal_revision_id)
                )
            })
            .collect::<Vec<_>>();
        let [(accepted_atom_payload, occurred_at_us, effective_config_hash)] =
            accepted_atoms.as_slice()
        else {
            return Err(error);
        };
        let JournalPayload::AtomRecorded(accepted_atom) = accepted_atom_payload else {
            return Err(error);
        };
        if support_validation_ref(accepted, current_support, error)?.is_some() {
            let base_revision_id = accepted.base_revision_id.ok_or(error)?;
            let replacement_successor = match accepted.operation {
                ProposalOperation::Replace => Some(accepted_atom.revision_id),
                ProposalOperation::Deprecate => None,
                _ => return Err(error),
            };
            current_support.validate_successor_fanout(
                base_revision_id,
                replacement_successor,
                *occurred_at_us,
                *effective_config_hash,
                &payloads,
                error,
            )?;
        }
        if accepted.operation == ProposalOperation::Merge {
            validate_accepted_merge_boundary(current_atoms, &payloads, accepted, error)?;
        }
    }
    for atom in payloads.iter().filter_map(|payload| match payload {
        JournalPayload::AtomRecorded(value) if value.accepted_proposal_revision_id.is_some() => {
            Some(value.as_ref())
        }
        _ => None,
    }) {
        if payloads
            .iter()
            .filter(|payload| {
                matches!(
                    payload,
                    JournalPayload::RevisionProposalRecorded(proposal)
                        if proposal.status == ProposalStatus::Accepted
                            && Some(proposal.proposal_id) == atom.accepted_proposal_id
                            && Some(proposal.proposal_revision_id)
                                == atom.accepted_proposal_revision_id
                )
            })
            .count()
            != 1
        {
            return Err(error);
        }
    }
    if validated_edit_pairs != exact_edit_pairs {
        return Err(error);
    }
    Ok(accepted_edits)
}

fn validate_support_proposal_boundaries(
    current_atoms: &BTreeMap<AtomId, (Atom, u64)>,
    current_procedures: &super::procedure::ProcedureState,
    current_support: &super::s23::S23State,
    payloads: &[&JournalPayload],
    error: StoreError,
) -> Result<(), StoreError> {
    for proposal in payloads.iter().filter_map(|payload| match payload {
        JournalPayload::RevisionProposalRecorded(value)
            if value.parent_proposal_revision_id.is_none()
                && value.status == ProposalStatus::Pending
                || value.status == ProposalStatus::Accepted =>
        {
            Some(value.as_ref())
        }
        _ => None,
    }) {
        if proposal.evidence_refs.len() == 1
            && proposal.evidence_refs == proposal.source_cohort_refs
            && payloads.iter().any(|payload| {
                matches!(
                    payload,
                    JournalPayload::GlobalSupportValidationRecorded(value)
                        if proposal.evidence_refs[0]
                            == value.validation_revision_id.to_string()
                )
            })
        {
            return Err(error);
        }
        let Some(validation_revision_id) =
            support_validation_ref(proposal, current_support, error)?
        else {
            continue;
        };
        let validation = current_support
            .validation(validation_revision_id)
            .ok_or(error)?;
        if validation.state == GlobalSupportState::Valid
            || current_support
                .current_validation(validation.support_contract_ref)
                .is_none_or(|current| {
                    current.validation_revision_id != validation.validation_revision_id
                })
            || payloads.iter().any(|payload| {
                matches!(
                    payload,
                    JournalPayload::GlobalSupportValidationRecorded(value)
                        if value.support_contract_ref == validation.support_contract_ref
                )
            })
        {
            return Err(error);
        }
        validate_support_proposal_target(
            proposal,
            validation.successor_ref.as_str(),
            |atom_id, base| {
                let atom = current_atoms
                    .get(&atom_id)
                    .map(|(atom, _)| atom)
                    .filter(|atom| {
                        atom.revision_id == base
                            && atom.scope == AtomScope::Global
                            && atom.lifecycle_status == AtomLifecycleStatus::Active
                    })?;
                (!payloads.iter().any(|payload| {
                    matches!(payload, JournalPayload::AtomRecorded(value) if value.revision_id == base)
                }))
                .then_some(atom_replacement_payload(atom))
            },
            |procedure_id, base| {
                let procedure = current_procedures.current_revision(procedure_id)?;
                (procedure.revision_id == base
                    && procedure.draft.scope == ProcedureScope::Global
                    && !payloads.iter().any(|payload| {
                        matches!(
                            payload,
                            JournalPayload::ProcedureRevisionRecorded(value)
                                if value.revision_id == base
                        )
                    }))
                .then_some(procedure_replacement_payload(procedure))
            },
            error,
        )?;
    }
    Ok(())
}

fn support_validation_ref(
    proposal: &RevisionProposal,
    support: &super::s23::S23State,
    error: StoreError,
) -> Result<Option<RevisionId>, StoreError> {
    let evidence = proposal
        .evidence_refs
        .iter()
        .filter_map(|reference| reference.parse::<RevisionId>().ok())
        .filter(|revision_id| support.validation(*revision_id).is_some())
        .collect::<Vec<_>>();
    let sources = proposal
        .source_cohort_refs
        .iter()
        .filter_map(|reference| reference.parse::<RevisionId>().ok())
        .filter(|revision_id| support.validation(*revision_id).is_some())
        .collect::<Vec<_>>();
    if evidence.is_empty() && sources.is_empty() {
        return Ok(None);
    }
    let ([evidence], [source]) = (evidence.as_slice(), sources.as_slice()) else {
        return Err(error);
    };
    if evidence != source
        || proposal.evidence_refs != [evidence.to_string()]
        || proposal.source_cohort_refs != [source.to_string()]
        || proposal.target_kind
            != match proposal.target_id {
                Some(ProposalTargetId::Atom(_)) => ProposalTargetKind::Atom,
                Some(ProposalTargetId::Procedure(_)) => ProposalTargetKind::Procedure,
                _ => return Err(error),
            }
        || proposal.eligibility != ProposalEligibility::ManualRequired
        || proposal.created_by != ProposalCreatedBy::User
    {
        return Err(error);
    }
    match (&proposal.payload, proposal.operation, proposal.target_id) {
        (
            ProposalPayload::Atom(payload),
            ProposalOperation::Replace,
            Some(ProposalTargetId::Atom(_)),
        ) if matches!(payload.as_ref(), AtomProposalPayload::Replace { .. }) => {}
        (
            ProposalPayload::Procedure(payload),
            ProposalOperation::Replace,
            Some(ProposalTargetId::Procedure(_)),
        ) if matches!(payload.as_ref(), ProcedureProposalPayload::Replace { .. }) => {}
        (
            ProposalPayload::Atom(payload),
            ProposalOperation::Deprecate,
            Some(ProposalTargetId::Atom(_)),
        ) if matches!(payload.as_ref(), AtomProposalPayload::Deprecate { .. }) => {}
        _ => return Err(error),
    }
    Ok(Some(*evidence))
}

fn validate_support_proposal_target(
    proposal: &RevisionProposal,
    successor_ref: &str,
    atom_payload: impl FnOnce(AtomId, RevisionId) -> Option<ProposalPayload>,
    procedure_payload: impl FnOnce(
        evertrace_domain::ids::ProcedureId,
        RevisionId,
    ) -> Option<ProposalPayload>,
    error: StoreError,
) -> Result<(), StoreError> {
    let base = proposal.base_revision_id.ok_or(error)?;
    if successor_ref != base.to_string() {
        return Err(error);
    }
    let original = match proposal.target_id {
        Some(ProposalTargetId::Atom(atom_id)) => atom_payload(atom_id, base),
        Some(ProposalTargetId::Procedure(procedure_id)) => procedure_payload(procedure_id, base),
        _ => None,
    }
    .ok_or(error)?;
    match proposal.operation {
        ProposalOperation::Replace => original
            .validate_closed_edit(&proposal.payload)
            .map_err(|_| error),
        ProposalOperation::Deprecate => match &proposal.payload {
            ProposalPayload::Atom(payload)
                if matches!(payload.as_ref(), AtomProposalPayload::Deprecate { .. }) =>
            {
                payload.validate().map_err(|_| error)
            }
            _ => Err(error),
        },
        _ => Err(error),
    }
}

fn atom_replacement_payload(atom: &Atom) -> ProposalPayload {
    ProposalPayload::Atom(Box::new(AtomProposalPayload::Replace {
        draft: AtomDraft {
            kind: atom.kind,
            epistemic_status: atom.epistemic_status,
            value: atom.value.clone(),
            scope: atom.scope.clone(),
            applicability_expr: atom.applicability_expr.clone(),
            future_cue_lifecycle_exprs: atom.future_cue_lifecycle_exprs.clone(),
            validity_interval: atom.validity_interval.clone(),
            provenance: atom.provenance.clone(),
            source_observation_refs: atom.source_observation_refs.clone(),
            evidence_refs: atom.evidence_refs.clone(),
            supersedes_revision_refs: atom.supersedes_revision_refs.clone(),
            supports_revision_refs: atom.supports_revision_refs.clone(),
            contradicts_revision_refs: atom.contradicts_revision_refs.clone(),
        },
    }))
}

fn procedure_replacement_payload(procedure: &ProcedureRevision) -> ProposalPayload {
    ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Replace {
        draft: procedure.draft.clone(),
    }))
}

fn exact_edit_pairs(
    current_proposals: &BTreeMap<RevisionProposalId, (RevisionProposal, u64)>,
    payloads: &[&JournalPayload],
    error: StoreError,
) -> Result<BTreeSet<(RevisionProposalId, RevisionProposalId)>, StoreError> {
    let mut pending = Vec::new();
    let mut superseded_by_id = BTreeMap::<RevisionProposalId, Vec<&RevisionProposal>>::new();
    for payload in payloads {
        let JournalPayload::RevisionProposalRecorded(value) = payload else {
            continue;
        };
        match value.status {
            ProposalStatus::Pending => pending.push(value.as_ref()),
            ProposalStatus::Superseded => superseded_by_id
                .entry(value.proposal_id)
                .or_default()
                .push(value.as_ref()),
            _ => {}
        }
    }
    if pending.is_empty() || superseded_by_id.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut candidate_ids = BTreeSet::new();
    let mut pairs = BTreeSet::new();
    for (original_id, events) in superseded_by_id {
        let Some((original, _)) = current_proposals.get(&original_id) else {
            continue;
        };
        let superseded = events
            .iter()
            .copied()
            .filter(|value| original.validate_successor(value).is_ok())
            .collect::<Vec<_>>();
        if superseded.is_empty() {
            continue;
        }
        let candidates = pending
            .iter()
            .copied()
            .filter(|candidate| original.validate_edit_candidate(candidate).is_ok())
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            continue;
        }
        if superseded.len() != 1 {
            return Err(error);
        }
        let [candidate] = candidates.as_slice() else {
            return Err(error);
        };
        if !candidate_ids.insert(candidate.proposal_id) {
            return Err(error);
        }
        pairs.insert((original_id, candidate.proposal_id));
    }
    Ok(pairs)
}

fn validate_accepted_edit_boundary(
    current_proposals: &BTreeMap<RevisionProposalId, (RevisionProposal, u64)>,
    payloads: &[&JournalPayload],
    accepted: &RevisionProposal,
    expected_original_id: Option<RevisionProposalId>,
    error: StoreError,
) -> Result<Option<RevisionProposalId>, StoreError> {
    let Some(acceptance) = accepted.acceptance.as_ref() else {
        return Err(error);
    };
    if !matches!(
        acceptance.authority_basis,
        ProposalAcceptanceAuthority::TuiAcceptance { .. }
    ) {
        return if expected_original_id.is_some() {
            Err(error)
        } else {
            Ok(None)
        };
    }
    let observation_id = acceptance
        .acceptance_event_ref
        .parse::<SourceObservationId>()
        .map_err(|_| error)?;
    let observations = payloads
        .iter()
        .enumerate()
        .filter_map(|(index, payload)| match payload {
            JournalPayload::SourceObservationRecorded(value)
                if value.source_observation_id == observation_id =>
            {
                Some((index, value.as_ref()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if observations.is_empty() {
        return if expected_original_id.is_some() {
            Err(error)
        } else {
            Ok(None)
        };
    }
    let [observation] = observations.as_slice() else {
        return Err(error);
    };
    let receipts = payloads
        .iter()
        .enumerate()
        .filter_map(|(index, payload)| match payload {
            JournalPayload::SourceReceiptRecorded(value)
                if value.source_receipt_id == observation.1.source_receipt_ref =>
            {
                Some((index, value.as_ref()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [receipt] = receipts.as_slice() else {
        return Err(error);
    };
    if receipt.1.source_ref == accepted.proposal_id.to_string() {
        return if expected_original_id.is_some() {
            Err(error)
        } else {
            Ok(None)
        };
    }
    let original_id = receipt
        .1
        .source_ref
        .parse::<RevisionProposalId>()
        .map_err(|_| error)?;
    if expected_original_id != Some(original_id) {
        return Err(error);
    }
    let original_revision_id = receipt
        .1
        .source_revision
        .as_str()
        .parse::<RevisionId>()
        .map_err(|_| error)?;
    let original = current_proposals
        .get(&original_id)
        .filter(|(value, _)| value.proposal_revision_id == original_revision_id)
        .map(|(value, _)| value)
        .ok_or(error)?;
    let reviewed = payloads
        .iter()
        .filter_map(|payload| match payload {
            JournalPayload::RevisionProposalRecorded(value)
                if value.proposal_revision_id == acceptance.reviewed_proposal_revision_id
                    && value.proposal_id == accepted.proposal_id
                    && value.status == ProposalStatus::Pending =>
            {
                Some(value.as_ref())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [reviewed] = reviewed.as_slice() else {
        return Err(error);
    };
    original
        .validate_edit_candidate(reviewed)
        .map_err(|_| error)?;
    let canonical = original.edit_intent_toml(reviewed).map_err(|_| error)?;
    let expected_fingerprint = hex(&payload_fingerprint(
        observation.1.canonicalization_revision,
        canonical.as_bytes(),
        None,
    )
    .map_err(|_| error)?);
    let expected_record = format!(
        "tui-accept-{}-{}",
        original.proposal_id, original.proposal_revision_id
    );
    let expected_instance = format!("tui-acceptance:{}", original.proposal_id);
    if receipt.1.source_instance_id.as_str() != expected_instance
        || receipt.1.source_revision.as_str() != original.proposal_revision_id.to_string()
        || receipt.1.source_record_identity.as_str() != expected_record
        || receipt.1.source_session_ref != "human-governance"
        || receipt.1.source_sequence != 1
        || receipt.1.source_sequence_origin != Some(1)
        || receipt.1.identity_strength != IdentityStrength::StableNative
        || receipt.1.source_kind != EvidenceSourceKind::Other
        || receipt.1.identity_domain != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
        || receipt.1.source_revision_mode != SourceRevisionMode::Append
        || receipt.1.previous_source_revision.is_some()
        || receipt.1.adapter_revision != 1
        || receipt.1.adapter_manifest_ref != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
        || receipt.1.eligible_event_manifest_ref != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
        || receipt.1.parser_revision != 1
        || receipt.1.canonicalization_revision != 1
        || receipt.1.capture_completeness != CaptureCompleteness::Complete
        || receipt.1.archive_mode != SourceArchiveMode::Exact
        || receipt.1.protected_secret_digest.is_some()
        || !receipt.1.redaction_spans.is_empty()
        || receipt.1.protected_length != canonical.len() as u64
        || receipt.1.original_length != canonical.len() as u64
        || observation.1.source_role != SourceRole::User
        || observation.1.content_trust != ContentTrust::UserStatement
        || observation.1.capture_completeness != CaptureCompleteness::Complete
        || observation.1.observation_role != ObservationRole::Message
        || observation.1.payload_fingerprint != expected_fingerprint
    {
        return Err(error);
    }
    let watermark = SourceIngestWatermark {
        source_instance_id: receipt.1.source_instance_id.clone(),
        source_revision: receipt.1.source_revision.clone(),
        source_sequence: 1,
        confirmed_prefix_digest: None,
    };
    let watermarks = payloads
        .iter()
        .enumerate()
        .filter_map(|(index, payload)| match payload {
            JournalPayload::SourceIngestWatermark(value) if value == &watermark => Some(index),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [watermark_index] = watermarks.as_slice() else {
        return Err(error);
    };
    if payloads
        .iter()
        .filter(|payload| matches!(payload, JournalPayload::SourceReceiptRecorded(_)))
        .count()
        != 1
        || payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::SourceObservationRecorded(_)))
            .count()
            != 1
        || payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::SourceIngestWatermark(_)))
            .count()
            != 1
    {
        return Err(error);
    }
    let proposal_events = payloads
        .iter()
        .enumerate()
        .filter_map(|(index, payload)| match payload {
            JournalPayload::RevisionProposalRecorded(value)
                if value.proposal_id == original.proposal_id
                    || value.proposal_id == reviewed.proposal_id =>
            {
                Some((index, value.as_ref()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let superseded = proposal_events
        .iter()
        .filter(|(_, value)| {
            value.proposal_id == original.proposal_id && value.status == ProposalStatus::Superseded
        })
        .collect::<Vec<_>>();
    let pending = proposal_events
        .iter()
        .filter(|(_, value)| *value == *reviewed)
        .collect::<Vec<_>>();
    let validating = proposal_events
        .iter()
        .filter(|(_, value)| {
            value.proposal_id == reviewed.proposal_id && value.status == ProposalStatus::Validating
        })
        .collect::<Vec<_>>();
    let accepted_events = proposal_events
        .iter()
        .filter(|(_, value)| {
            value.proposal_id == reviewed.proposal_id && value.status == ProposalStatus::Accepted
        })
        .collect::<Vec<_>>();
    let ([superseded], [pending], [validating], [accepted_event]) = (
        superseded.as_slice(),
        pending.as_slice(),
        validating.as_slice(),
        accepted_events.as_slice(),
    ) else {
        return Err(error);
    };
    if proposal_events.len() != 4
        || accepted_event.1 != accepted
        || !(observation.0 < superseded.0
            && receipt.0 < superseded.0
            && *watermark_index < superseded.0
            && superseded.0 < pending.0
            && pending.0 < validating.0
            && validating.0 < accepted_event.0)
        || original.validate_successor(superseded.1).is_err()
        || reviewed.validate_successor(validating.1).is_err()
        || validating.1.validate_successor(accepted_event.1).is_err()
    {
        return Err(error);
    }
    Ok(Some(original_id))
}

fn validate_accepted_merge_boundary(
    current_atoms: &BTreeMap<AtomId, (Atom, u64)>,
    payloads: &[&JournalPayload],
    proposal: &RevisionProposal,
    error: StoreError,
) -> Result<(), StoreError> {
    let (Some(ProposalTargetId::Atom(target_atom_id)), Some(base_revision_id)) =
        (proposal.target_id, proposal.base_revision_id)
    else {
        return Err(error);
    };
    let ProposalPayload::Atom(payload) = &proposal.payload else {
        return Err(error);
    };
    let AtomProposalPayload::Merge {
        draft,
        merged_revision_refs,
    } = payload.as_ref()
    else {
        return Err(error);
    };
    if merged_revision_refs != &draft.supersedes_revision_refs
        || !merged_revision_refs.contains(&base_revision_id)
        || current_atoms
            .get(&target_atom_id)
            .is_none_or(|(atom, _)| atom.revision_id != base_revision_id)
    {
        return Err(error);
    }
    let mut input_atom_ids = BTreeSet::new();
    for revision_id in merged_revision_refs {
        let atom = current_atoms
            .values()
            .find_map(|(atom, _)| (atom.revision_id == *revision_id).then_some(atom))
            .ok_or(error)?;
        if atom.lifecycle_status != AtomLifecycleStatus::Active
            || atom.kind != draft.kind
            || !atom.scope.contains(&draft.scope)
        {
            return Err(error);
        }
        input_atom_ids.insert(atom.atom_id);
    }
    if input_atom_ids.len() < 2 {
        return Err(error);
    }
    let result_atoms = payloads
        .iter()
        .filter_map(|payload| match payload {
            JournalPayload::AtomRecorded(atom) => Some(atom.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [result] = result_atoms.as_slice() else {
        return Err(error);
    };
    if result.atom_id != target_atom_id
        || result.parent_revision_id != Some(base_revision_id)
        || result.lifecycle_status != AtomLifecycleStatus::Active
        || result.kind != draft.kind
        || result.scope != draft.scope
        || result.supersedes_revision_refs != *merged_revision_refs
    {
        return Err(error);
    }
    Ok(())
}

fn validate_atom_relations(
    atom: &Atom,
    input: &SemanticRelationInputs<'_>,
) -> Result<(), StoreError> {
    validate_scope(&atom.scope, input)?;
    for observation_id in &atom.source_observation_refs {
        let observation = &input
            .source_observations
            .get(observation_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        if !input
            .source_receipts
            .contains_key(&observation.source_receipt_ref)
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for evidence_ref in &atom.evidence_refs {
        if !evidence_exists(evidence_ref, input)
            && !support_acceptance_evidence_exists(atom, evidence_ref, input)?
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    if atom.epistemic_status == EpistemicStatus::Supported
        && !atom
            .evidence_refs
            .iter()
            .any(|reference| objective_evidence_exists(reference, input))
    {
        return Err(StoreError::StoreCorrupt);
    }
    for revision in atom
        .supersedes_revision_refs
        .iter()
        .chain(&atom.supports_revision_refs)
        .chain(&atom.contradicts_revision_refs)
    {
        if !input.atom_revisions.contains_key(revision)
            && (!input.deleted_revision_ids.contains(revision)
                || input.s23.atom_support_eligible(atom.revision_id))
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    if let Some(user) = &atom.user_authorization_provenance {
        let observation = &input
            .source_observations
            .get(&user.user_source_observation_ref)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        let receipt = &input
            .source_receipts
            .get(&observation.source_receipt_ref)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        if observation.source_role != SourceRole::User
            || observation.content_trust != ContentTrust::UserStatement
            || observation.observation_role != ObservationRole::Message
            || receipt.observation_role != ObservationRole::Message
            || observation.capture_completeness != CaptureCompleteness::Complete
            || receipt.capture_completeness != CaptureCompleteness::Complete
            || observation.source_observation_id != receipt.source_observation_id
            || observation.source_instance_id != receipt.source_instance_id
            || observation.source_revision != receipt.source_revision
            || observation.source_record_identity != receipt.source_record_identity
            || observation.adapter_revision != receipt.adapter_revision
            || observation.canonicalization_revision != receipt.canonicalization_revision
            || observation.correlation.adapter_manifest_ref != receipt.adapter_manifest_ref
            || hex(&user.source_message_hash) != observation.payload_fingerprint
        {
            return Err(StoreError::StoreCorrupt);
        }
        match user.mode {
            UserAuthorizationMode::CurrentTaskExactMessage => {
                let exact_hash = payload_fingerprint(
                    observation.canonicalization_revision,
                    atom.value.text.as_bytes(),
                    None,
                )
                .map_err(|_| StoreError::StoreCorrupt)?;
                if receipt.task_id != atom.scope.task_id()
                    || observation.payload_fingerprint != hex(&exact_hash)
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            UserAuthorizationMode::TuiAcceptance => match &atom.scope {
                AtomScope::Task { task_id } if receipt.task_id == Some(*task_id) => {}
                AtomScope::Repository {
                    repository_instance_id,
                } if receipt.repository_instance_id == Some(*repository_instance_id) => {}
                AtomScope::Global if matches!(user.authorized_scope_ceiling, AtomScope::Global) => {
                }
                _ => return Err(StoreError::StoreCorrupt),
            },
            UserAuthorizationMode::UserStatement => {
                let statement_hash = payload_fingerprint(
                    observation.canonicalization_revision,
                    atom.value.text.as_bytes(),
                    None,
                )
                .map_err(|_| StoreError::StoreCorrupt)?;
                if observation.payload_fingerprint != hex(&statement_hash) {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
    }
    if atom.authority == AtomAuthority::ProjectPolicy {
        let policy = atom
            .policy_authority_provenance
            .as_ref()
            .ok_or(StoreError::StoreCorrupt)?;
        let host_scope = policy.host_resolved_scope.as_atom_scope();
        let verified = atom.source_observation_refs.iter().any(|id| {
            let Some((observation, _)) = input.source_observations.get(id) else {
                return false;
            };
            let Some((receipt, _)) = input.source_receipts.get(&observation.source_receipt_ref)
            else {
                return false;
            };
            matches!(observation.source_role, SourceRole::Host | SourceRole::Tool)
                && observation.content_trust == ContentTrust::Observed
                && observation.observation_role == ObservationRole::StateProbe
                && receipt.observation_role == ObservationRole::StateProbe
                && observation.capture_completeness == CaptureCompleteness::Complete
                && receipt.capture_completeness == CaptureCompleteness::Complete
                && observation.source_observation_id == receipt.source_observation_id
                && observation.source_instance_id == receipt.source_instance_id
                && observation.source_revision == receipt.source_revision
                && observation.source_record_identity == receipt.source_record_identity
                && observation.adapter_revision == receipt.adapter_revision
                && observation.canonicalization_revision == receipt.canonicalization_revision
                && receipt.adapter_manifest_ref == policy.adapter_manifest_id
                && observation.correlation.adapter_manifest_ref == policy.adapter_manifest_id
                && observation.source_revision.as_str() == policy.policy_source_revision_ref
                && receipt.source_ref == policy.policy_source_kind
                && observation.payload_fingerprint == hex(&policy.policy_content_hash)
                && atom
                    .evidence_refs
                    .contains(&observation.source_observation_id.to_string())
                && atom
                    .evidence_refs
                    .contains(&receipt.source_receipt_id.to_string())
                && host_scope.contains(&atom.scope)
                && receipt.repository_instance_id == host_scope.repository_id()
                && host_scope
                    .worktree_id()
                    .is_none_or(|worktree_id| receipt.worktree_instance_id == Some(worktree_id))
        });
        if !verified {
            return Err(StoreError::StoreCorrupt);
        }
    }
    match (
        atom.accepted_proposal_id,
        atom.accepted_proposal_revision_id,
    ) {
        (Some(proposal_id), Some(proposal_revision_id)) => {
            let proposal = &input
                .proposal_revisions
                .get(&proposal_revision_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            let acceptance = proposal
                .acceptance
                .as_ref()
                .ok_or(StoreError::StoreCorrupt)?;
            let (accepted_atom_id, accepted_atom_revision_id, accepted_structure_hash) =
                acceptance.accepted_atom().ok_or(StoreError::StoreCorrupt)?;
            if proposal.proposal_id != proposal_id
                || proposal.status != ProposalStatus::Accepted
                || accepted_atom_id != atom.atom_id
                || accepted_atom_revision_id != atom.revision_id
                || accepted_structure_hash
                    != atom
                        .semantic_structure_hash()
                        .map_err(|_| StoreError::StoreCorrupt)?
            {
                return Err(StoreError::StoreCorrupt);
            }
            validate_accepted_authority(atom, proposal, acceptance)?;
        }
        (None, None) => {}
        _ => return Err(StoreError::StoreCorrupt),
    }
    Ok(())
}

fn support_acceptance_evidence_exists(
    atom: &Atom,
    evidence_ref: &str,
    input: &SemanticRelationInputs<'_>,
) -> Result<bool, StoreError> {
    let (Some(proposal_id), Some(proposal_revision_id)) = (
        atom.accepted_proposal_id,
        atom.accepted_proposal_revision_id,
    ) else {
        return Ok(false);
    };
    let Ok(validation_revision_id) = evidence_ref.parse::<RevisionId>() else {
        return Ok(false);
    };
    if input.s23.validation(validation_revision_id).is_none() {
        return Ok(false);
    }
    if atom.parent_revision_id.is_some_and(|parent_revision_id| {
        input
            .atom_revisions
            .get(&parent_revision_id)
            .is_some_and(|(parent, _)| {
                parent.atom_id == atom.atom_id
                    && parent
                        .evidence_refs
                        .iter()
                        .any(|reference| reference == evidence_ref)
            })
    }) {
        return Ok(true);
    }
    let Some((proposal, _)) = input.proposal_revisions.get(&proposal_revision_id) else {
        return Ok(false);
    };
    if proposal.proposal_id != proposal_id
        || proposal.status != ProposalStatus::Accepted
        || !matches!(atom.scope, AtomScope::Global)
        || proposal
            .acceptance
            .as_ref()
            .and_then(|acceptance| acceptance.accepted_atom())
            != Some((
                atom.atom_id,
                atom.revision_id,
                atom.semantic_structure_hash()
                    .map_err(|_| StoreError::StoreCorrupt)?,
            ))
    {
        return Ok(false);
    }
    Ok(
        support_validation_ref(proposal, input.s23, StoreError::StoreCorrupt)?
            == Some(validation_revision_id),
    )
}

fn validate_proposal_relations(
    proposal: &RevisionProposal,
    input: &SemanticRelationInputs<'_>,
) -> Result<(), StoreError> {
    let support_validation_ref =
        support_validation_ref(proposal, input.s23, StoreError::StoreCorrupt)?;
    if let Some(validation_revision_id) = support_validation_ref {
        let validation = input
            .s23
            .validation(validation_revision_id)
            .ok_or(StoreError::StoreCorrupt)?;
        if validation.state == GlobalSupportState::Valid {
            return Err(StoreError::StoreCorrupt);
        }
        validate_support_proposal_target(
            proposal,
            validation.successor_ref.as_str(),
            |atom_id, base| {
                input
                    .atom_revisions
                    .get(&base)
                    .map(|(atom, _)| atom)
                    .filter(|atom| {
                        atom.atom_id == atom_id
                            && atom.scope == AtomScope::Global
                            && atom.lifecycle_status == AtomLifecycleStatus::Active
                    })
                    .map(atom_replacement_payload)
            },
            |procedure_id, base| {
                input
                    .procedure
                    .revision(base)
                    .filter(|procedure| {
                        procedure.procedure_id == procedure_id
                            && procedure.draft.scope == ProcedureScope::Global
                    })
                    .map(procedure_replacement_payload)
            },
            StoreError::StoreCorrupt,
        )?;
    }
    let support_validation_ref = support_validation_ref.map(|value| value.to_string());
    for reference in &proposal.source_cohort_refs {
        if Some(reference.as_str()) != support_validation_ref.as_deref()
            && !evidence_exists(reference, input)
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for reference in &proposal.evidence_refs {
        if Some(reference.as_str()) != support_validation_ref.as_deref()
            && !evidence_exists(reference, input)
            && !valid_procedure_negative_reference(proposal, reference, input)
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    if proposal.target_kind == ProposalTargetKind::CoreMembership {
        if proposal.target_id.is_some()
            || proposal.base_revision_id.is_some()
            || proposal.operation != ProposalOperation::Create
        {
            return Err(StoreError::StoreCorrupt);
        }
        if proposal.status == ProposalStatus::Accepted {
            if !matches!(
                proposal.payload,
                evertrace_domain::semantic::ProposalPayload::CoreMembership(ref payload)
                    if matches!(payload.as_ref(), CoreMembershipProposalPayload::Create { .. })
            ) {
                return Err(StoreError::StoreCorrupt);
            }
            let sources = validate_acceptance_sources(proposal, input)?;
            let acceptance = proposal
                .acceptance
                .as_ref()
                .ok_or(StoreError::StoreCorrupt)?;
            let ProposalAcceptanceAuthority::TuiAcceptance {
                user_source_observation_ref,
                authorized_scope_ceiling,
            } = &acceptance.authority_basis
            else {
                return Err(StoreError::StoreCorrupt);
            };
            if *user_source_observation_ref != sources.observation_id {
                return Err(StoreError::StoreCorrupt);
            }
            match authorized_scope_ceiling {
                AtomScope::Repository {
                    repository_instance_id,
                } if sources.receipt.repository_instance_id == Some(*repository_instance_id) => {}
                AtomScope::Global => {}
                _ => return Err(StoreError::StoreCorrupt),
            }
            match proposal.eligibility {
                ProposalEligibility::ManualRequired => validate_tui_acceptance_event(
                    proposal,
                    acceptance,
                    sources.reviewed,
                    sources.observation,
                    sources.receipt,
                    input,
                )?,
                ProposalEligibility::AutoEligibleFull => {}
                _ => return Err(StoreError::StoreCorrupt),
            }
        }
        return Ok(());
    }
    if proposal.target_kind == ProposalTargetKind::Procedure {
        let evertrace_domain::semantic::ProposalPayload::Procedure(payload) = &proposal.payload
        else {
            return Err(StoreError::StoreCorrupt);
        };
        match (
            proposal.operation,
            proposal.target_id,
            proposal.base_revision_id,
        ) {
            (ProposalOperation::Create, None, None) => {}
            (ProposalOperation::Replace, Some(ProposalTargetId::Procedure(_)), Some(_)) => {}
            _ => return Err(StoreError::StoreCorrupt),
        }
        if proposal.status == ProposalStatus::Accepted {
            let acceptance = proposal
                .acceptance
                .as_ref()
                .ok_or(StoreError::StoreCorrupt)?;
            let evertrace_domain::semantic::AcceptedProposalTarget::Procedure {
                auto_full_audit,
                ..
            } = &acceptance.accepted_target
            else {
                return Err(StoreError::StoreCorrupt);
            };
            match &acceptance.authority_basis {
                ProposalAcceptanceAuthority::TuiAcceptance {
                    user_source_observation_ref,
                    authorized_scope_ceiling,
                } => {
                    if auto_full_audit.is_some() {
                        return Err(StoreError::StoreCorrupt);
                    }
                    let sources = validate_acceptance_sources(proposal, input)?;
                    if *user_source_observation_ref != sources.observation_id
                        || !authorized_scope_ceiling
                            .contains(&procedure_atom_scope(payload.draft().scope))
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                    validate_tui_acceptance_event(
                        proposal,
                        acceptance,
                        sources.reviewed,
                        sources.observation,
                        sources.receipt,
                        input,
                    )?;
                }
                ProposalAcceptanceAuthority::ObjectiveEvidence {
                    user_source_observation_ref,
                } => {
                    let audit = auto_full_audit.as_deref().ok_or(StoreError::StoreCorrupt)?;
                    audit
                        .validate(matches!(payload.draft().scope, ProcedureScope::Global))
                        .map_err(|_| StoreError::StoreCorrupt)?;
                    if audit.eligibility.verifier_observation_ref
                        != Some(*user_source_observation_ref)
                        || proposal.eligibility != ProposalEligibility::AutoEligibleFull
                        || acceptance.acceptance_event_ref
                            != user_source_observation_ref.to_string()
                        || acceptance.reviewer_identity
                            != format!("objective_evidence:{user_source_observation_ref}")
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                    let (observation, _) = input
                        .source_observations
                        .get(user_source_observation_ref)
                        .ok_or(StoreError::StoreCorrupt)?;
                    let (receipt, _) = input
                        .source_receipts
                        .get(&observation.source_receipt_ref)
                        .ok_or(StoreError::StoreCorrupt)?;
                    if !matches!(observation.source_role, SourceRole::Host | SourceRole::Tool)
                        || observation.content_trust != ContentTrust::Observed
                        || observation.capture_completeness != CaptureCompleteness::Complete
                        || receipt.capture_completeness != CaptureCompleteness::Complete
                        || !proposal.evidence_refs.iter().any(|reference| {
                            reference == &observation.source_observation_id.to_string()
                                || reference == &receipt.source_receipt_id.to_string()
                        })
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                }
                ProposalAcceptanceAuthority::CurrentTaskExactMessage { .. } => {
                    return Err(StoreError::StoreCorrupt);
                }
            }
        }
        return Ok(());
    }
    if proposal.target_kind != ProposalTargetKind::Atom {
        return Ok(());
    }
    match (proposal.target_id, proposal.base_revision_id) {
        (Some(ProposalTargetId::Atom(atom_id)), Some(base_revision_id)) => {
            let base = &input
                .atom_revisions
                .get(&base_revision_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            if base.atom_id != atom_id {
                return Err(StoreError::StoreCorrupt);
            }
        }
        (None, None) if proposal.operation == ProposalOperation::Create => {}
        _ => return Err(StoreError::StoreCorrupt),
    }
    if proposal.status == ProposalStatus::Accepted {
        let acceptance = proposal
            .acceptance
            .as_ref()
            .ok_or(StoreError::StoreCorrupt)?;
        let sources = validate_acceptance_sources(proposal, input)?;
        let acceptance_observation_id = sources.observation_id;
        let acceptance_observation = sources.observation;
        let reviewed = sources.reviewed;
        let (_, accepted_atom_revision_id, _) =
            acceptance.accepted_atom().ok_or(StoreError::StoreCorrupt)?;
        let atom = &input
            .atom_revisions
            .get(&accepted_atom_revision_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        if !matches!(
            atom.scope,
            AtomScope::Task { .. } | AtomScope::Repository { .. } | AtomScope::Global
        ) {
            return Err(StoreError::StoreCorrupt);
        }
        let acceptance_receipt = sources.receipt;
        match &acceptance.authority_basis {
            ProposalAcceptanceAuthority::CurrentTaskExactMessage {
                user_source_observation_ref,
            } => {
                if *user_source_observation_ref != acceptance_observation_id
                    || acceptance_receipt.task_id != atom.scope.task_id()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ProposalAcceptanceAuthority::TuiAcceptance {
                user_source_observation_ref,
                authorized_scope_ceiling,
            } => {
                if *user_source_observation_ref != acceptance_observation_id
                    || !authorized_scope_ceiling.contains(&atom.scope)
                {
                    return Err(StoreError::StoreCorrupt);
                }
                match authorized_scope_ceiling {
                    AtomScope::Task { task_id } if acceptance_receipt.task_id == Some(*task_id) => {
                    }
                    AtomScope::Repository {
                        repository_instance_id,
                    } if acceptance_receipt.repository_instance_id
                        == Some(*repository_instance_id) => {}
                    AtomScope::Global if matches!(atom.scope, AtomScope::Global) => {}
                    _ => return Err(StoreError::StoreCorrupt),
                }
                validate_tui_acceptance_event(
                    proposal,
                    acceptance,
                    reviewed,
                    acceptance_observation,
                    acceptance_receipt,
                    input,
                )?;
            }
            ProposalAcceptanceAuthority::ObjectiveEvidence {
                user_source_observation_ref,
            } => {
                if *user_source_observation_ref != acceptance_observation_id {
                    return Err(StoreError::StoreCorrupt);
                }
                validate_tui_acceptance_event(
                    proposal,
                    acceptance,
                    reviewed,
                    acceptance_observation,
                    acceptance_receipt,
                    input,
                )?;
            }
        }
        let (accepted_atom_id, _, _) =
            acceptance.accepted_atom().ok_or(StoreError::StoreCorrupt)?;
        if atom.atom_id != accepted_atom_id
            || atom.accepted_proposal_id != Some(proposal.proposal_id)
            || atom.accepted_proposal_revision_id != Some(proposal.proposal_revision_id)
        {
            return Err(StoreError::StoreCorrupt);
        }
        match proposal.operation {
            ProposalOperation::Create => {
                if atom.parent_revision_id.is_some() || proposal.target_id.is_some() {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ProposalOperation::Replace | ProposalOperation::Reclassify => {
                let base = input
                    .atom_revisions
                    .get(&proposal.base_revision_id.ok_or(StoreError::StoreCorrupt)?)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0
                    .clone();
                let accepted_support_global = proposal.operation == ProposalOperation::Replace
                    && base.scope == AtomScope::Global
                    && support_validation_ref.is_some();
                if !(matches!(
                    base.scope,
                    AtomScope::Task { .. } | AtomScope::Repository { .. }
                ) || accepted_support_global)
                    || atom.parent_revision_id != Some(base.revision_id)
                    || atom.atom_id != base.atom_id
                    || proposal.operation == ProposalOperation::Replace && atom.kind != base.kind
                    || atom.lifecycle_status != AtomLifecycleStatus::Active
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ProposalOperation::Deprecate => {
                let base = &input
                    .atom_revisions
                    .get(&proposal.base_revision_id.ok_or(StoreError::StoreCorrupt)?)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0;
                let accepted_support_global =
                    base.scope == AtomScope::Global && support_validation_ref.is_some();
                if !(matches!(
                    base.scope,
                    AtomScope::Task { .. } | AtomScope::Repository { .. }
                ) || accepted_support_global)
                    || atom.parent_revision_id != Some(base.revision_id)
                    || atom.atom_id != base.atom_id
                    || atom.lifecycle_status != AtomLifecycleStatus::Deprecated
                    || atom.authority != base.authority
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ProposalOperation::Merge => {
                let ProposalPayload::Atom(payload) = &proposal.payload else {
                    return Err(StoreError::StoreCorrupt);
                };
                let AtomProposalPayload::Merge {
                    draft,
                    merged_revision_refs,
                } = payload.as_ref()
                else {
                    return Err(StoreError::StoreCorrupt);
                };
                let base_revision_id = proposal.base_revision_id.ok_or(StoreError::StoreCorrupt)?;
                let Some(ProposalTargetId::Atom(target_atom_id)) = proposal.target_id else {
                    return Err(StoreError::StoreCorrupt);
                };
                let mut input_atom_ids = BTreeSet::new();
                if merged_revision_refs != &draft.supersedes_revision_refs
                    || !merged_revision_refs.contains(&base_revision_id)
                {
                    return Err(StoreError::StoreCorrupt);
                }
                for revision_id in merged_revision_refs {
                    let input = &input
                        .atom_revisions
                        .get(revision_id)
                        .ok_or(StoreError::StoreCorrupt)?
                        .0;
                    if input.lifecycle_status != AtomLifecycleStatus::Active
                        || input.kind != draft.kind
                        || !input.scope.contains(&draft.scope)
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                    input_atom_ids.insert(input.atom_id);
                }
                if input_atom_ids.len() < 2
                    || atom.atom_id != target_atom_id
                    || atom.parent_revision_id != Some(base_revision_id)
                    || atom.lifecycle_status != AtomLifecycleStatus::Active
                    || atom.kind != draft.kind
                    || atom.scope != draft.scope
                    || atom.supersedes_revision_refs != *merged_revision_refs
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ProposalOperation::Split => return Err(StoreError::StoreCorrupt),
        }
    }
    Ok(())
}

fn procedure_atom_scope(scope: ProcedureScope) -> AtomScope {
    match scope {
        ProcedureScope::Worktree {
            repository_id,
            worktree_id,
        } => AtomScope::Worktree {
            repository_instance_id: repository_id,
            worktree_instance_id: worktree_id,
        },
        ProcedureScope::Repository { repository_id } => AtomScope::Repository {
            repository_instance_id: repository_id,
        },
        ProcedureScope::Global => AtomScope::Global,
    }
}

struct AcceptanceSources<'a> {
    observation_id: SourceObservationId,
    observation: &'a SourceObservation,
    receipt: &'a SourceReceipt,
    reviewed: &'a RevisionProposal,
}

fn validate_acceptance_sources<'a>(
    proposal: &RevisionProposal,
    input: &'a SemanticRelationInputs<'a>,
) -> Result<AcceptanceSources<'a>, StoreError> {
    let acceptance = proposal
        .acceptance
        .as_ref()
        .ok_or(StoreError::StoreCorrupt)?;
    let observation_id = acceptance
        .acceptance_event_ref
        .parse::<SourceObservationId>()
        .map_err(|_| StoreError::StoreCorrupt)?;
    let observation = &input
        .source_observations
        .get(&observation_id)
        .ok_or(StoreError::StoreCorrupt)?
        .0;
    if observation.source_role != SourceRole::User
        || observation.content_trust != ContentTrust::UserStatement
        || observation.observation_role != ObservationRole::Message
        || acceptance.reviewer_identity != format!("user_source:{observation_id}")
    {
        return Err(StoreError::StoreCorrupt);
    }
    let reviewed = &input
        .proposal_revisions
        .get(&acceptance.reviewed_proposal_revision_id)
        .ok_or(StoreError::StoreCorrupt)?
        .0;
    let direct_review_parent =
        proposal.parent_proposal_revision_id == Some(acceptance.reviewed_proposal_revision_id);
    let validating_review_parent = proposal
        .parent_proposal_revision_id
        .and_then(|parent| input.proposal_revisions.get(&parent))
        .is_some_and(|(validating, _)| {
            validating.proposal_id == proposal.proposal_id
                && validating.status == ProposalStatus::Validating
                && validating.parent_proposal_revision_id
                    == Some(acceptance.reviewed_proposal_revision_id)
                && validating.fingerprint == acceptance.reviewed_fingerprint
        });
    if reviewed.proposal_id != proposal.proposal_id
        || reviewed.fingerprint != acceptance.reviewed_fingerprint
        || !matches!(
            reviewed.status,
            ProposalStatus::Pending | ProposalStatus::Validating
        )
        || !(direct_review_parent || validating_review_parent)
    {
        return Err(StoreError::StoreCorrupt);
    }
    let receipt = &input
        .source_receipts
        .get(&observation.source_receipt_ref)
        .ok_or(StoreError::StoreCorrupt)?
        .0;
    if receipt.observation_role != ObservationRole::Message
        || observation.capture_completeness != CaptureCompleteness::Complete
        || receipt.capture_completeness != CaptureCompleteness::Complete
        || observation.source_observation_id != receipt.source_observation_id
        || observation.source_instance_id != receipt.source_instance_id
        || observation.source_revision != receipt.source_revision
        || observation.source_record_identity != receipt.source_record_identity
        || observation.adapter_revision != receipt.adapter_revision
        || observation.canonicalization_revision != receipt.canonicalization_revision
        || observation.correlation.adapter_manifest_ref != receipt.adapter_manifest_ref
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(AcceptanceSources {
        observation_id,
        observation,
        receipt,
        reviewed,
    })
}

fn validate_accepted_authority(
    atom: &Atom,
    proposal: &RevisionProposal,
    acceptance: &evertrace_domain::semantic::ProposalAcceptance,
) -> Result<(), StoreError> {
    if proposal.operation == ProposalOperation::Deprecate {
        if !matches!(
            &acceptance.authority_basis,
            ProposalAcceptanceAuthority::TuiAcceptance { .. }
        ) {
            return Err(StoreError::StoreCorrupt);
        }
        return Ok(());
    }
    match &acceptance.authority_basis {
        ProposalAcceptanceAuthority::CurrentTaskExactMessage {
            user_source_observation_ref,
        } => {
            let user = atom
                .user_authorization_provenance
                .as_ref()
                .ok_or(StoreError::StoreCorrupt)?;
            if atom.authority != AtomAuthority::UserExplicit
                || user.mode != UserAuthorizationMode::CurrentTaskExactMessage
                || user.user_source_observation_ref != *user_source_observation_ref
                || acceptance.acceptance_event_ref != user_source_observation_ref.to_string()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        ProposalAcceptanceAuthority::TuiAcceptance {
            user_source_observation_ref,
            authorized_scope_ceiling,
        } => {
            let user = atom
                .user_authorization_provenance
                .as_ref()
                .ok_or(StoreError::StoreCorrupt)?;
            if atom.authority != AtomAuthority::UserExplicit
                || user.mode != UserAuthorizationMode::TuiAcceptance
                || user.user_source_observation_ref != *user_source_observation_ref
                || user.authorized_scope_ceiling != *authorized_scope_ceiling
                || user.acceptance_event_ref.as_deref()
                    != Some(acceptance.acceptance_event_ref.as_str())
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        ProposalAcceptanceAuthority::ObjectiveEvidence {
            user_source_observation_ref,
        } => {
            if atom.authority != AtomAuthority::ObjectiveEvidence
                || acceptance.acceptance_event_ref != user_source_observation_ref.to_string()
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    Ok(())
}

fn validate_tui_acceptance_event(
    proposal: &RevisionProposal,
    acceptance: &evertrace_domain::semantic::ProposalAcceptance,
    reviewed: &RevisionProposal,
    observation: &SourceObservation,
    receipt: &SourceReceipt,
    input: &SemanticRelationInputs<'_>,
) -> Result<(), StoreError> {
    let plain_payload = tui_acceptance_event_payload(
        proposal.proposal_id,
        acceptance.reviewed_proposal_revision_id,
        &acceptance.reviewed_fingerprint,
    );
    let plain_expected = payload_fingerprint(
        observation.canonicalization_revision,
        plain_payload.as_bytes(),
        None,
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    let expected = if observation.payload_fingerprint == hex(&plain_expected) {
        plain_expected
    } else {
        let original_id = receipt
            .source_ref
            .parse::<RevisionProposalId>()
            .map_err(|_| StoreError::StoreCorrupt)?;
        let original_revision_id = receipt
            .source_revision
            .as_str()
            .parse::<RevisionId>()
            .map_err(|_| StoreError::StoreCorrupt)?;
        let original = &input
            .proposal_revisions
            .get(&original_revision_id)
            .filter(|(value, _)| value.proposal_id == original_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        original
            .validate_edit_candidate(reviewed)
            .map_err(|_| StoreError::StoreCorrupt)?;
        let edit_payload = original
            .edit_intent_toml(reviewed)
            .map_err(|_| StoreError::StoreCorrupt)?;
        payload_fingerprint(
            observation.canonicalization_revision,
            edit_payload.as_bytes(),
            None,
        )
        .map_err(|_| StoreError::StoreCorrupt)?
    };
    if receipt.eligible_event_manifest_ref != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
        || observation.payload_fingerprint != hex(&expected)
        || receipt.recorded_at_us < reviewed.created_at_us
        || acceptance.accepted_at_us < receipt.recorded_at_us
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn validate_scope(scope: &AtomScope, input: &SemanticRelationInputs<'_>) -> Result<(), StoreError> {
    match scope {
        AtomScope::Task { task_id } if input.tasks.contains_key(task_id) => Ok(()),
        AtomScope::Repository {
            repository_instance_id,
        } if input.repositories.contains_key(repository_instance_id) => Ok(()),
        AtomScope::Worktree {
            repository_instance_id,
            worktree_instance_id,
        } if input
            .worktrees
            .get(worktree_instance_id)
            .is_some_and(|(worktree, _)| {
                worktree.repository_instance_id == *repository_instance_id
                    && input.repositories.contains_key(repository_instance_id)
            }) =>
        {
            Ok(())
        }
        AtomScope::Global => Ok(()),
        _ => Err(StoreError::StoreCorrupt),
    }
}

fn evidence_exists(reference: &str, input: &SemanticRelationInputs<'_>) -> bool {
    reference
        .parse::<SourceReceiptId>()
        .is_ok_and(|id| input.source_receipts.contains_key(&id))
        || reference
            .parse::<SourceObservationId>()
            .is_ok_and(|id| input.source_observations.contains_key(&id))
        || reference
            .parse::<ResultEvidenceId>()
            .is_ok_and(|id| input.results.contains_key(&id))
        || reference
            .parse::<WorkArtifactId>()
            .is_ok_and(|id| input.artifacts.contains_key(&id))
        || reference
            .parse::<RevisionId>()
            .is_ok_and(|id| input.atom_revisions.contains_key(&id))
        || reference
            .parse::<SemanticDigestId>()
            .is_ok_and(|id| input.semantic_digests.contains_key(&id))
}

fn valid_procedure_negative_reference(
    proposal: &RevisionProposal,
    reference: &str,
    input: &SemanticRelationInputs<'_>,
) -> bool {
    let (
        ProposalPayload::Procedure(payload),
        Some(ProposalTargetId::Procedure(procedure_id)),
        Some(base_revision_id),
        Ok(negative_id),
    ) = (
        &proposal.payload,
        proposal.target_id,
        proposal.base_revision_id,
        reference.parse::<evertrace_domain::ids::ProcedureNegativeEvidenceId>(),
    )
    else {
        return false;
    };
    proposal.target_kind == ProposalTargetKind::Procedure
        && proposal.operation == ProposalOperation::Replace
        && matches!(
            payload.as_ref(),
            evertrace_domain::semantic::ProcedureProposalPayload::Replace { .. }
        )
        && payload
            .draft()
            .evidence_refs
            .iter()
            .any(|value| value == reference)
        && input
            .procedure
            .negative_entry(negative_id)
            .is_some_and(|(negative, _)| {
                negative.procedure_revision_id == base_revision_id
                    && input
                        .procedure
                        .revision(base_revision_id)
                        .is_some_and(|base| base.procedure_id == procedure_id)
            })
}

fn objective_evidence_exists(reference: &str, input: &SemanticRelationInputs<'_>) -> bool {
    reference.parse::<SourceReceiptId>().is_ok_and(|id| {
        input.source_receipts.get(&id).is_some_and(|(receipt, _)| {
            input
                .source_observations
                .get(&receipt.source_observation_id)
                .is_some_and(|(observation, _)| {
                    matches!(observation.source_role, SourceRole::Tool | SourceRole::Host)
                        && observation.content_trust == ContentTrust::Observed
                })
        })
    }) || reference.parse::<SourceObservationId>().is_ok_and(|id| {
        input
            .source_observations
            .get(&id)
            .is_some_and(|(observation, _)| {
                matches!(observation.source_role, SourceRole::Tool | SourceRole::Host)
                    && observation.content_trust == ContentTrust::Observed
            })
    }) || reference.parse::<ResultEvidenceId>().is_ok_and(|id| {
        input.results.get(&id).is_some_and(|(result, _)| {
            result.completeness == evertrace_domain::semantic::EvidenceCompleteness::Complete
                && result
                    .verifier_receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.status == VerifierStatus::Passed)
        })
    }) || reference.parse::<WorkArtifactId>().is_ok_and(|id| {
        input.artifacts.get(&id).is_some_and(|(artifact, _)| {
            artifact.revision.payload_status == ArtifactPayloadStatus::Available
        })
    })
}
