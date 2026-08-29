use std::collections::BTreeMap;

use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, ObservationRole, SourceObservation, SourceReceipt,
        SourceRole, hex, payload_fingerprint,
    },
    ids::{
        AtomId, RepositoryId, ResultEvidenceId, RevisionProposalId, SourceObservationId,
        SourceReceiptId, TaskId, WorkArtifactId, WorktreeId,
    },
    repository::{RepositoryInstance, WorktreeInstance},
    revision::RevisionId,
    semantic::{
        Atom, AtomAuthority, AtomLifecycleStatus, AtomScope, CoreMembershipProposalPayload,
        EpistemicStatus, ProposalAcceptanceAuthority, ProposalEligibility, ProposalOperation,
        ProposalStatus, ProposalTargetId, ProposalTargetKind, RevisionProposal,
        TUI_ACCEPTANCE_EVENT_MANIFEST_REF, UserAuthorizationMode, VerifierStatus,
        tui_acceptance_event_payload,
    },
    work::{ArtifactPayloadStatus, Task, WorkArtifact},
};

use crate::{JournalPayload, ObjectRowClass, StoreError, projections::ProjectionSnapshot};

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
    pub proposal_revisions: &'a BTreeMap<RevisionId, (RevisionProposal, u64)>,
    pub source_observations: &'a BTreeMap<SourceObservationId, (SourceObservation, u64)>,
    pub source_receipts: &'a BTreeMap<SourceReceiptId, (SourceReceipt, u64)>,
    pub tasks: &'a BTreeMap<TaskId, (Task, u64)>,
    pub repositories: &'a BTreeMap<RepositoryId, (RepositoryInstance, u64)>,
    pub worktrees: &'a BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
    pub results: &'a BTreeMap<ResultEvidenceId, (evertrace_domain::semantic::ResultEvidence, u64)>,
    pub artifacts: &'a BTreeMap<WorkArtifactId, (WorkArtifact, u64)>,
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
    payloads: impl IntoIterator<Item = &'a JournalPayload>,
    error: StoreError,
) -> Result<(), StoreError> {
    let payloads = payloads.into_iter().collect::<Vec<_>>();
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
        let Some((accepted_atom_id, accepted_atom_revision_id, _)) = acceptance.accepted_atom()
        else {
            continue;
        };
        if payloads
            .iter()
            .filter(|payload| {
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
            .count()
            != 1
        {
            return Err(error);
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
        if !evidence_exists(evidence_ref, input) {
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
        if !input.atom_revisions.contains_key(revision) {
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

fn validate_proposal_relations(
    proposal: &RevisionProposal,
    input: &SemanticRelationInputs<'_>,
) -> Result<(), StoreError> {
    for reference in proposal
        .evidence_refs
        .iter()
        .chain(&proposal.source_cohort_refs)
    {
        if !evidence_exists(reference, input) {
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
                    sources.reviewed.created_at_us,
                    sources.observation,
                    sources.receipt,
                )?,
                ProposalEligibility::AutoEligibleFull => {}
                _ => return Err(StoreError::StoreCorrupt),
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
                    reviewed.created_at_us,
                    acceptance_observation,
                    acceptance_receipt,
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
                    reviewed.created_at_us,
                    acceptance_observation,
                    acceptance_receipt,
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
                if !matches!(
                    base.scope,
                    AtomScope::Task { .. } | AtomScope::Repository { .. }
                ) || atom.parent_revision_id != Some(base.revision_id)
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
                if !matches!(
                    base.scope,
                    AtomScope::Task { .. } | AtomScope::Repository { .. }
                ) || atom.parent_revision_id != Some(base.revision_id)
                    || atom.atom_id != base.atom_id
                    || atom.lifecycle_status != AtomLifecycleStatus::Deprecated
                    || atom.authority != base.authority
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ProposalOperation::Merge | ProposalOperation::Split => {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    Ok(())
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
    reviewed_created_at_us: i64,
    observation: &SourceObservation,
    receipt: &SourceReceipt,
) -> Result<(), StoreError> {
    let payload = tui_acceptance_event_payload(
        proposal.proposal_id,
        acceptance.reviewed_proposal_revision_id,
        &acceptance.reviewed_fingerprint,
    );
    let expected = payload_fingerprint(
        observation.canonicalization_revision,
        payload.as_bytes(),
        None,
    )
    .map_err(|_| StoreError::StoreCorrupt)?;
    if receipt.eligible_event_manifest_ref != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
        || observation.payload_fingerprint != hex(&expected)
        || receipt.recorded_at_us < reviewed_created_at_us
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
