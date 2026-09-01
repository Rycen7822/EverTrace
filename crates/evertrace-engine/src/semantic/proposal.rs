use evertrace_domain::{
    evidence::{SourceObservation, SourceReceipt, hex, payload_fingerprint},
    ids::{CommandId, RevisionProposalId},
    revision::RevisionId,
    semantic::{
        AcceptedProposalTarget, Atom, AtomLifecycleStatus, AtomProposalPayload, AtomScope,
        ProposalAcceptance, ProposalAcceptanceAuthority, ProposalCreatedBy, ProposalEligibility,
        ProposalOperation, ProposalPayload, ProposalStatus, ProposalTargetId, ProposalTargetKind,
        ProposalWaitingOn, RevisionProposal, TUI_ACCEPTANCE_EVENT_MANIFEST_REF,
        tui_acceptance_event_payload,
    },
};
use evertrace_store::{JournalCommand, JournalEventDraft, JournalPayload, SemanticCurrentView};

use super::{
    AtomAuthorityBasis, AtomMaterialization, SemanticServiceError, VerifiedTuiAcceptance,
    emission::require_user_source, materialize_atom,
};

#[derive(Clone, Debug)]
pub struct ProposalCommandContext {
    pub command_id: CommandId,
    pub occurred_at_us: i64,
    pub effective_config_hash: [u8; 32],
    pub algorithm_revision: String,
}

#[derive(Clone, Debug)]
pub struct SubmitProposalRequest {
    pub target_kind: ProposalTargetKind,
    pub target_id: Option<ProposalTargetId>,
    pub base_revision_id: Option<RevisionId>,
    pub operation: ProposalOperation,
    pub payload: ProposalPayload,
    pub evidence_refs: Vec<String>,
    pub source_cohort_refs: Vec<String>,
    pub eligibility: ProposalEligibility,
    pub created_by: ProposalCreatedBy,
}

#[derive(Debug)]
pub enum ProposalResolution<T> {
    NoDelta,
    Revision {
        value: Box<T>,
        command: JournalCommand,
    },
}

#[derive(Debug)]
pub struct AcceptedProposalCommand {
    pub proposal: Box<RevisionProposal>,
    pub atom: Box<Atom>,
    pub command: JournalCommand,
}

#[derive(Clone, Debug)]
pub enum AtomAcceptanceContext {
    CurrentTaskExactMessage {
        observation: Box<SourceObservation>,
        receipt: Box<SourceReceipt>,
        canonical_message: String,
    },
    RepositoryTui {
        observation: Box<SourceObservation>,
        receipt: Box<SourceReceipt>,
    },
    TaskTui {
        observation: Box<SourceObservation>,
        receipt: Box<SourceReceipt>,
    },
    GlobalTui {
        observation: Box<SourceObservation>,
        receipt: Box<SourceReceipt>,
    },
    ObjectiveEvidence {
        observation: Box<SourceObservation>,
        receipt: Box<SourceReceipt>,
    },
}

impl AtomAcceptanceContext {
    fn observation(&self) -> &SourceObservation {
        match self {
            Self::CurrentTaskExactMessage { observation, .. }
            | Self::RepositoryTui { observation, .. }
            | Self::TaskTui { observation, .. }
            | Self::GlobalTui { observation, .. }
            | Self::ObjectiveEvidence { observation, .. } => observation,
        }
    }

    pub(crate) fn acceptance_event_ref(&self) -> String {
        self.observation().source_observation_id.to_string()
    }

    pub(crate) fn reviewer_identity(&self) -> String {
        format!("user_source:{}", self.observation().source_observation_id)
    }

    pub(crate) fn validate(
        &self,
        proposal: &RevisionProposal,
        accepted_at_us: i64,
    ) -> Result<(), SemanticServiceError> {
        match self {
            Self::CurrentTaskExactMessage {
                observation,
                receipt,
                canonical_message,
            } => {
                require_user_source(observation, receipt)?;
                if canonical_message.is_empty() {
                    return Err(SemanticServiceError::InvalidInput);
                }
            }
            Self::RepositoryTui {
                observation,
                receipt,
            }
            | Self::TaskTui {
                observation,
                receipt,
            }
            | Self::GlobalTui {
                observation,
                receipt,
            }
            | Self::ObjectiveEvidence {
                observation,
                receipt,
            } => require_tui_acceptance_source(observation, receipt, proposal, accepted_at_us)?,
        }
        Ok(())
    }

    pub(crate) fn authority_basis(
        &self,
    ) -> Result<ProposalAcceptanceAuthority, SemanticServiceError> {
        Ok(match self {
            Self::CurrentTaskExactMessage { observation, .. } => {
                ProposalAcceptanceAuthority::CurrentTaskExactMessage {
                    user_source_observation_ref: observation.source_observation_id,
                }
            }
            Self::RepositoryTui {
                observation,
                receipt,
                ..
            } => ProposalAcceptanceAuthority::TuiAcceptance {
                user_source_observation_ref: observation.source_observation_id,
                authorized_scope_ceiling: AtomScope::Repository {
                    repository_instance_id: receipt
                        .repository_instance_id
                        .ok_or(SemanticServiceError::InvalidInput)?,
                },
            },
            Self::TaskTui {
                observation,
                receipt,
                ..
            } => ProposalAcceptanceAuthority::TuiAcceptance {
                user_source_observation_ref: observation.source_observation_id,
                authorized_scope_ceiling: AtomScope::Task {
                    task_id: receipt.task_id.ok_or(SemanticServiceError::InvalidInput)?,
                },
            },
            Self::GlobalTui { observation, .. } => ProposalAcceptanceAuthority::TuiAcceptance {
                user_source_observation_ref: observation.source_observation_id,
                authorized_scope_ceiling: AtomScope::Global,
            },
            Self::ObjectiveEvidence { observation, .. } => {
                ProposalAcceptanceAuthority::ObjectiveEvidence {
                    user_source_observation_ref: observation.source_observation_id,
                }
            }
        })
    }

    fn validate_edit(
        &self,
        original: &RevisionProposal,
        proposal: &RevisionProposal,
        accepted_at_us: i64,
    ) -> Result<(), SemanticServiceError> {
        let (observation, receipt) = match self {
            Self::RepositoryTui {
                observation,
                receipt,
            }
            | Self::TaskTui {
                observation,
                receipt,
            }
            | Self::GlobalTui {
                observation,
                receipt,
            } => (observation.as_ref(), receipt.as_ref()),
            _ => return Err(SemanticServiceError::UnsupportedTarget),
        };
        require_user_source(observation, receipt)?;
        original
            .validate_edit_candidate(proposal)
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        let canonical = original
            .edit_intent_toml(proposal)
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        let expected = payload_fingerprint(
            observation.canonicalization_revision,
            canonical.as_bytes(),
            None,
        )
        .map_err(|_| SemanticServiceError::InvalidInput)?;
        if receipt.eligible_event_manifest_ref != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
            || receipt.source_ref != original.proposal_id.to_string()
            || receipt.source_revision.as_str() != original.proposal_revision_id.to_string()
            || observation.payload_fingerprint != hex(&expected)
            || receipt.recorded_at_us < proposal.created_at_us
            || accepted_at_us < receipt.recorded_at_us
        {
            return Err(SemanticServiceError::InvalidInput);
        }
        Ok(())
    }
}

pub(crate) fn accepted_proposal_successor(
    current: &RevisionProposal,
    context: &ProposalCommandContext,
    acceptance_context: &AtomAcceptanceContext,
    accepted_revision_id: RevisionId,
    accepted_target: AcceptedProposalTarget,
) -> Result<(RevisionProposal, Vec<JournalPayload>), SemanticServiceError> {
    acceptance_context.validate(current, context.occurred_at_us)?;
    accepted_proposal_successor_with_audit(
        current,
        context,
        accepted_revision_id,
        accepted_target,
        ProposalAcceptanceAudit {
            reviewer_identity: acceptance_context.reviewer_identity(),
            acceptance_event_ref: acceptance_context.acceptance_event_ref(),
            authority_basis: acceptance_context.authority_basis()?,
        },
    )
}

pub(crate) fn accepted_edited_proposal_successor(
    original: &RevisionProposal,
    current: &RevisionProposal,
    context: &ProposalCommandContext,
    acceptance_context: &AtomAcceptanceContext,
    accepted_revision_id: RevisionId,
    accepted_target: AcceptedProposalTarget,
) -> Result<(RevisionProposal, Vec<JournalPayload>), SemanticServiceError> {
    acceptance_context.validate_edit(original, current, context.occurred_at_us)?;
    accepted_proposal_successor_with_audit(
        current,
        context,
        accepted_revision_id,
        accepted_target,
        ProposalAcceptanceAudit {
            reviewer_identity: acceptance_context.reviewer_identity(),
            acceptance_event_ref: acceptance_context.acceptance_event_ref(),
            authority_basis: acceptance_context.authority_basis()?,
        },
    )
}

pub(crate) struct ProposalAcceptanceAudit {
    pub reviewer_identity: String,
    pub acceptance_event_ref: String,
    pub authority_basis: ProposalAcceptanceAuthority,
}

pub(crate) fn accepted_proposal_successor_with_audit(
    current: &RevisionProposal,
    context: &ProposalCommandContext,
    accepted_revision_id: RevisionId,
    accepted_target: AcceptedProposalTarget,
    audit: ProposalAcceptanceAudit,
) -> Result<(RevisionProposal, Vec<JournalPayload>), SemanticServiceError> {
    let mut payloads = Vec::new();
    let parent_revision_id = if current.status == ProposalStatus::Pending {
        let mut validating = current.clone();
        validating.proposal_revision_id = RevisionId::new_v7();
        validating.parent_proposal_revision_id = Some(current.proposal_revision_id);
        validating.status = ProposalStatus::Validating;
        validating.created_at_us = context.occurred_at_us;
        current
            .validate_successor(&validating)
            .map_err(|_| SemanticServiceError::ImmutableConflict)?;
        let parent = validating.proposal_revision_id;
        payloads.push(JournalPayload::RevisionProposalRecorded(Box::new(
            validating,
        )));
        parent
    } else {
        current.proposal_revision_id
    };
    let mut accepted = current.clone();
    accepted.proposal_revision_id = accepted_revision_id;
    accepted.parent_proposal_revision_id = Some(parent_revision_id);
    accepted.status = ProposalStatus::Accepted;
    accepted.waiting_on.clear();
    accepted.review_reason = Some(
        if matches!(
            audit.authority_basis,
            ProposalAcceptanceAuthority::ObjectiveEvidence { .. }
        ) {
            "automatic_acceptance"
        } else {
            "manual_acceptance"
        }
        .into(),
    );
    accepted.acceptance = Some(ProposalAcceptance {
        reviewer_identity: audit.reviewer_identity,
        acceptance_event_ref: audit.acceptance_event_ref,
        reviewed_proposal_revision_id: current.proposal_revision_id,
        reviewed_fingerprint: current.fingerprint,
        accepted_target,
        authority_basis: audit.authority_basis,
        accepted_at_us: context.occurred_at_us,
    });
    accepted.created_at_us = context.occurred_at_us;
    accepted.reviewed_at_us = Some(context.occurred_at_us);
    if let Some(JournalPayload::RevisionProposalRecorded(validating)) = payloads.last() {
        validating
            .validate_successor(&accepted)
            .map_err(|_| SemanticServiceError::ImmutableConflict)?;
    } else {
        current
            .validate_successor(&accepted)
            .map_err(|_| SemanticServiceError::ImmutableConflict)?;
    }
    payloads.push(JournalPayload::RevisionProposalRecorded(Box::new(
        accepted.clone(),
    )));
    Ok((accepted, payloads))
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RevisionProposalService;

impl RevisionProposalService {
    pub(crate) fn validate_atom_merge(
        &self,
        view: &SemanticCurrentView,
        proposal_id: RevisionProposalId,
    ) -> Result<(), SemanticServiceError> {
        let proposal = view
            .proposals
            .get(&proposal_id)
            .ok_or(SemanticServiceError::InvalidInput)?;
        validate_atom_merge(view, proposal)
    }

    pub fn submit(
        &self,
        view: &SemanticCurrentView,
        context: ProposalCommandContext,
        request: SubmitProposalRequest,
    ) -> Result<ProposalResolution<RevisionProposal>, SemanticServiceError> {
        self.submit_inner(view, context, request, None)
    }

    pub(crate) fn submit_with_identity(
        &self,
        view: &SemanticCurrentView,
        context: ProposalCommandContext,
        request: SubmitProposalRequest,
        proposal_id: RevisionProposalId,
        proposal_revision_id: RevisionId,
    ) -> Result<ProposalResolution<RevisionProposal>, SemanticServiceError> {
        self.submit_inner(
            view,
            context,
            request,
            Some((proposal_id, proposal_revision_id)),
        )
    }

    fn submit_inner(
        &self,
        view: &SemanticCurrentView,
        context: ProposalCommandContext,
        mut request: SubmitProposalRequest,
        identity: Option<(RevisionProposalId, RevisionId)>,
    ) -> Result<ProposalResolution<RevisionProposal>, SemanticServiceError> {
        normalize_refs(&mut request.evidence_refs);
        normalize_refs(&mut request.source_cohort_refs);
        validate_target_base(view, &request)?;
        let (proposal_id, proposal_revision_id) =
            identity.unwrap_or_else(|| (RevisionProposalId::new_v7(), RevisionId::new_v7()));
        let mut candidate = RevisionProposal {
            proposal_id,
            proposal_revision_id,
            parent_proposal_revision_id: None,
            target_kind: request.target_kind,
            target_id: request.target_id,
            base_revision_id: request.base_revision_id,
            operation: request.operation,
            payload: request.payload,
            evidence_refs: request.evidence_refs,
            source_cohort_refs: request.source_cohort_refs,
            source_cohort_hash: [0; 32],
            fingerprint: [0; 32],
            eligibility: request.eligibility,
            status: ProposalStatus::Pending,
            waiting_on: Vec::new(),
            review_reason: None,
            created_by: request.created_by,
            acceptance: None,
            created_at_us: context.occurred_at_us,
            reviewed_at_us: None,
        };
        candidate.source_cohort_hash = candidate
            .recompute_source_cohort_hash()
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        candidate.fingerprint = candidate
            .recompute_fingerprint()
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        candidate
            .validate()
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        if view.proposals.values().any(|proposal| {
            proposal.status == ProposalStatus::Rejected
                && proposal.suppression_key() == candidate.suppression_key()
        }) {
            return Ok(ProposalResolution::NoDelta);
        }
        let mut accepted = view.proposals.values().filter(|proposal| {
            proposal.status == ProposalStatus::Accepted
                && proposal.fingerprint == candidate.fingerprint
        });
        if accepted.next().is_some() {
            if accepted.next().is_some() {
                return Err(SemanticServiceError::ImmutableConflict);
            }
            return Ok(ProposalResolution::NoDelta);
        }
        let mut matching = view.proposals.values().filter(|proposal| {
            matches!(
                proposal.status,
                ProposalStatus::Pending | ProposalStatus::Validating | ProposalStatus::Deferred
            ) && proposal.fingerprint == candidate.fingerprint
        });
        if let Some(current) = matching.next() {
            if matching.next().is_some() {
                return Err(SemanticServiceError::ImmutableConflict);
            }
            if current.status == ProposalStatus::Deferred {
                return Ok(ProposalResolution::NoDelta);
            }
            if candidate
                .evidence_refs
                .iter()
                .all(|reference| current.evidence_refs.contains(reference))
            {
                return Ok(ProposalResolution::NoDelta);
            }
            candidate.proposal_id = current.proposal_id;
            candidate.proposal_revision_id = RevisionId::new_v7();
            candidate.parent_proposal_revision_id = Some(current.proposal_revision_id);
            candidate.status = current.status;
            candidate
                .evidence_refs
                .extend(current.evidence_refs.clone());
            normalize_refs(&mut candidate.evidence_refs);
            current
                .validate_successor(&candidate)
                .map_err(|_| SemanticServiceError::ImmutableConflict)?;
        }
        let command = payload_command(
            context,
            vec![JournalPayload::RevisionProposalRecorded(Box::new(
                candidate.clone(),
            ))],
        )?;
        Ok(ProposalResolution::Revision {
            value: Box::new(candidate),
            command,
        })
    }

    pub fn revise_status(
        &self,
        view: &SemanticCurrentView,
        context: ProposalCommandContext,
        proposal_id: RevisionProposalId,
        next_status: ProposalStatus,
        mut waiting_on: Vec<ProposalWaitingOn>,
        review_reason: Option<String>,
    ) -> Result<ProposalResolution<RevisionProposal>, SemanticServiceError> {
        let current = view
            .proposals
            .get(&proposal_id)
            .ok_or(SemanticServiceError::InvalidInput)?;
        if current.status == next_status
            && current.waiting_on == waiting_on
            && current.review_reason == review_reason
        {
            return Ok(ProposalResolution::NoDelta);
        }
        waiting_on.sort();
        waiting_on.dedup();
        let mut next = current.clone();
        next.proposal_revision_id = RevisionId::new_v7();
        next.parent_proposal_revision_id = Some(current.proposal_revision_id);
        next.status = next_status;
        next.waiting_on = waiting_on;
        next.review_reason = review_reason;
        next.acceptance = None;
        next.created_at_us = context.occurred_at_us;
        next.reviewed_at_us = next_status.is_terminal().then_some(context.occurred_at_us);
        current
            .validate_successor(&next)
            .map_err(|_| SemanticServiceError::ImmutableConflict)?;
        let command = payload_command(
            context,
            vec![JournalPayload::RevisionProposalRecorded(Box::new(
                next.clone(),
            ))],
        )?;
        Ok(ProposalResolution::Revision {
            value: Box::new(next),
            command,
        })
    }

    pub fn resume_deferred(
        &self,
        view: &SemanticCurrentView,
        context: ProposalCommandContext,
        proposal_id: RevisionProposalId,
        mut new_evidence_refs: Vec<String>,
        new_base_revision_id: Option<RevisionId>,
    ) -> Result<ProposalResolution<RevisionProposal>, SemanticServiceError> {
        let current = view
            .proposals
            .get(&proposal_id)
            .ok_or(SemanticServiceError::InvalidInput)?;
        if current.status != ProposalStatus::Deferred {
            return Err(SemanticServiceError::ImmutableConflict);
        }
        match (current.target_id, current.operation, new_base_revision_id) {
            (None, ProposalOperation::Create, None) => {}
            (Some(ProposalTargetId::Atom(atom_id)), operation, Some(base_revision_id))
                if operation != ProposalOperation::Create
                    && view
                        .atoms
                        .get(&atom_id)
                        .is_some_and(|atom| atom.revision_id == base_revision_id) => {}
            _ => return Err(SemanticServiceError::BaseConflict),
        }
        new_evidence_refs.extend(current.evidence_refs.clone());
        normalize_refs(&mut new_evidence_refs);
        let mut next = current.clone();
        next.proposal_revision_id = RevisionId::new_v7();
        next.parent_proposal_revision_id = Some(current.proposal_revision_id);
        next.base_revision_id = new_base_revision_id;
        next.evidence_refs = new_evidence_refs;
        next.status = ProposalStatus::Pending;
        next.waiting_on.clear();
        next.review_reason = None;
        next.acceptance = None;
        next.created_at_us = context.occurred_at_us;
        next.reviewed_at_us = None;
        next.fingerprint = next
            .recompute_fingerprint()
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        current
            .validate_successor(&next)
            .map_err(|_| SemanticServiceError::ImmutableConflict)?;
        let command = payload_command(
            context,
            vec![JournalPayload::RevisionProposalRecorded(Box::new(
                next.clone(),
            ))],
        )?;
        Ok(ProposalResolution::Revision {
            value: Box::new(next),
            command,
        })
    }

    pub fn accept(
        &self,
        view: &SemanticCurrentView,
        context: ProposalCommandContext,
        proposal_id: RevisionProposalId,
        acceptance_context: AtomAcceptanceContext,
    ) -> Result<AcceptedProposalCommand, SemanticServiceError> {
        self.accept_inner(view, context, proposal_id, acceptance_context, None, None)
    }

    pub(crate) fn accept_support_linked(
        &self,
        view: &SemanticCurrentView,
        context: ProposalCommandContext,
        proposal_id: RevisionProposalId,
        acceptance_context: AtomAcceptanceContext,
        support: &super::s23::SupportAtomAcceptance,
    ) -> Result<AcceptedProposalCommand, SemanticServiceError> {
        self.accept_inner(
            view,
            context,
            proposal_id,
            acceptance_context,
            None,
            Some(support),
        )
    }

    pub(crate) fn accept_edited(
        &self,
        view: &SemanticCurrentView,
        context: ProposalCommandContext,
        proposal_id: RevisionProposalId,
        acceptance_context: AtomAcceptanceContext,
        original: &RevisionProposal,
    ) -> Result<AcceptedProposalCommand, SemanticServiceError> {
        self.accept_inner(
            view,
            context,
            proposal_id,
            acceptance_context,
            Some(original),
            None,
        )
    }

    pub(crate) fn accept_support_linked_edited(
        &self,
        view: &SemanticCurrentView,
        context: ProposalCommandContext,
        proposal_id: RevisionProposalId,
        acceptance_context: AtomAcceptanceContext,
        original: &RevisionProposal,
        support: &super::s23::SupportAtomAcceptance,
    ) -> Result<AcceptedProposalCommand, SemanticServiceError> {
        self.accept_inner(
            view,
            context,
            proposal_id,
            acceptance_context,
            Some(original),
            Some(support),
        )
    }

    fn accept_inner(
        &self,
        view: &SemanticCurrentView,
        context: ProposalCommandContext,
        proposal_id: RevisionProposalId,
        acceptance_context: AtomAcceptanceContext,
        edit_original: Option<&RevisionProposal>,
        support: Option<&super::s23::SupportAtomAcceptance>,
    ) -> Result<AcceptedProposalCommand, SemanticServiceError> {
        let current = view
            .proposals
            .get(&proposal_id)
            .ok_or(SemanticServiceError::InvalidInput)?;
        if !current.status.is_open()
            || current.target_kind != ProposalTargetKind::Atom
            || current.eligibility == ProposalEligibility::AutoEligibleFull
        {
            return Err(SemanticServiceError::UnsupportedTarget);
        }
        let current_atom = current_target_atom(view, current)?;
        let support_linked_global = support.is_some_and(|support| {
            current.target_id == Some(ProposalTargetId::Atom(support.atom_id))
                && current.base_revision_id == Some(support.base_revision_id)
                && current.evidence_refs == [support.validation_revision_id.to_string()]
                && current.source_cohort_refs == current.evidence_refs
                && matches!(
                    current.operation,
                    ProposalOperation::Replace | ProposalOperation::Deprecate
                )
        });
        if current_atom.is_some_and(|atom| {
            !matches!(
                atom.scope,
                AtomScope::Task { .. } | AtomScope::Repository { .. }
            ) && !(atom.scope == AtomScope::Global && support_linked_global)
        }) {
            return Err(SemanticServiceError::UnsupportedTarget);
        }
        let requested_scope = match &current.payload {
            ProposalPayload::Atom(payload) => match payload.as_ref() {
                AtomProposalPayload::Create { draft }
                | AtomProposalPayload::Replace { draft }
                | AtomProposalPayload::Reclassify { draft } => &draft.scope,
                AtomProposalPayload::Deprecate { .. } => {
                    &current_atom
                        .ok_or(SemanticServiceError::BaseConflict)?
                        .scope
                }
                AtomProposalPayload::Merge { draft, .. } => {
                    validate_atom_merge(view, current)?;
                    &draft.scope
                }
                AtomProposalPayload::Split { .. } => {
                    return Err(SemanticServiceError::UnsupportedTarget);
                }
            },
            ProposalPayload::Procedure(_)
            | ProposalPayload::CoreMembership(_)
            | ProposalPayload::ReservedTarget { .. } => {
                return Err(SemanticServiceError::UnsupportedTarget);
            }
        };
        let global_tui = matches!(acceptance_context, AtomAcceptanceContext::GlobalTui { .. });
        if !matches!(
            requested_scope,
            AtomScope::Task { .. } | AtomScope::Repository { .. }
        ) && !(matches!(requested_scope, AtomScope::Global) && global_tui)
        {
            return Err(SemanticServiceError::UnsupportedTarget);
        }
        if current.operation == ProposalOperation::Deprecate
            && !matches!(
                &acceptance_context,
                AtomAcceptanceContext::RepositoryTui { .. } | AtomAcceptanceContext::TaskTui { .. }
            )
            && !(global_tui && support_linked_global)
        {
            return Err(SemanticServiceError::UnsupportedTarget);
        }
        let accepted_revision_id = RevisionId::new_v7();
        let atom = match &current.payload {
            ProposalPayload::Atom(payload)
                if matches!(payload.as_ref(), AtomProposalPayload::Deprecate { .. }) =>
            {
                let mut atom = current_atom
                    .cloned()
                    .ok_or(SemanticServiceError::BaseConflict)?;
                atom.revision_id = RevisionId::new_v7();
                atom.parent_revision_id = Some(
                    current
                        .base_revision_id
                        .ok_or(SemanticServiceError::BaseConflict)?,
                );
                atom.lifecycle_status = AtomLifecycleStatus::Deprecated;
                atom.accepted_proposal_id = Some(current.proposal_id);
                atom.accepted_proposal_revision_id = Some(accepted_revision_id);
                atom.created_at_us = context.occurred_at_us;
                current_atom
                    .ok_or(SemanticServiceError::BaseConflict)?
                    .validate_successor(&atom)
                    .map_err(|_| SemanticServiceError::ImmutableConflict)?;
                atom
            }
            _ => {
                let draft = accepted_draft(current)?;
                let basis = acceptance_basis(&acceptance_context, &draft)?;
                materialize_atom(
                    AtomMaterialization {
                        draft,
                        authority_basis: basis,
                        accepted_proposal_id: Some(current.proposal_id),
                        accepted_proposal_revision_id: Some(accepted_revision_id),
                        created_at_us: context.occurred_at_us,
                    },
                    current_atom,
                )?
            }
        };
        if !matches!(
            atom.scope,
            AtomScope::Task { .. } | AtomScope::Repository { .. }
        ) && !(matches!(atom.scope, AtomScope::Global) && global_tui)
        {
            return Err(SemanticServiceError::UnsupportedTarget);
        }

        let accepted_target = AcceptedProposalTarget::Atom {
            atom_id: atom.atom_id,
            atom_revision_id: atom.revision_id,
            structure_hash: atom
                .semantic_structure_hash()
                .map_err(|_| SemanticServiceError::InvalidInput)?,
        };
        let (accepted, mut payloads) = if let Some(original) = edit_original {
            accepted_edited_proposal_successor(
                original,
                current,
                &context,
                &acceptance_context,
                accepted_revision_id,
                accepted_target,
            )?
        } else {
            accepted_proposal_successor(
                current,
                &context,
                &acceptance_context,
                accepted_revision_id,
                accepted_target,
            )?
        };
        payloads.push(JournalPayload::AtomRecorded(Box::new(atom.clone())));
        if matches!(atom.scope, AtomScope::Global) {
            match support {
                Some(support) => {
                    if current.operation == ProposalOperation::Replace {
                        payloads.extend(super::s23::global_atom_support_payloads(
                            view,
                            &atom,
                            &accepted,
                            context.occurred_at_us,
                        )?);
                    } else if current.operation != ProposalOperation::Deprecate {
                        return Err(SemanticServiceError::UnsupportedTarget);
                    }
                    payloads.extend(super::s23::support_successor_fanout_payloads(
                        support,
                        context.effective_config_hash,
                        context.occurred_at_us,
                    )?);
                }
                None => payloads.extend(super::s23::global_atom_support_payloads(
                    view,
                    &atom,
                    &accepted,
                    context.occurred_at_us,
                )?),
            }
        }
        let command = payload_command(context, payloads)?;
        Ok(AcceptedProposalCommand {
            proposal: Box::new(accepted),
            atom: Box::new(atom),
            command,
        })
    }
}

fn validate_target_base(
    view: &SemanticCurrentView,
    request: &SubmitProposalRequest,
) -> Result<(), SemanticServiceError> {
    if request.target_kind != ProposalTargetKind::Atom {
        return Ok(());
    }
    match (
        request.target_id,
        request.base_revision_id,
        request.operation,
    ) {
        (None, None, ProposalOperation::Create) => Ok(()),
        (Some(ProposalTargetId::Atom(atom_id)), Some(base_revision_id), operation)
            if operation != ProposalOperation::Create =>
        {
            if view
                .atoms
                .get(&atom_id)
                .is_some_and(|atom| atom.revision_id == base_revision_id)
            {
                Ok(())
            } else {
                Err(SemanticServiceError::BaseConflict)
            }
        }
        _ => Err(SemanticServiceError::InvalidInput),
    }
}

fn current_target_atom<'a>(
    view: &'a SemanticCurrentView,
    proposal: &RevisionProposal,
) -> Result<Option<&'a Atom>, SemanticServiceError> {
    match (
        proposal.target_id,
        proposal.base_revision_id,
        proposal.operation,
    ) {
        (None, None, ProposalOperation::Create) => Ok(None),
        (Some(ProposalTargetId::Atom(atom_id)), Some(base_revision_id), _) => view
            .atoms
            .get(&atom_id)
            .filter(|atom| atom.revision_id == base_revision_id)
            .map(Some)
            .ok_or(SemanticServiceError::BaseConflict),
        _ => Err(SemanticServiceError::BaseConflict),
    }
}

fn require_tui_acceptance_source(
    observation: &SourceObservation,
    receipt: &SourceReceipt,
    proposal: &RevisionProposal,
    accepted_at_us: i64,
) -> Result<(), SemanticServiceError> {
    require_user_source(observation, receipt)?;
    let payload = tui_acceptance_event_payload(
        proposal.proposal_id,
        proposal.proposal_revision_id,
        &proposal.fingerprint,
    );
    let expected = payload_fingerprint(
        observation.canonicalization_revision,
        payload.as_bytes(),
        None,
    )
    .map_err(|_| SemanticServiceError::InvalidInput)?;
    if receipt.eligible_event_manifest_ref != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
        || observation.payload_fingerprint != hex(&expected)
        || receipt.recorded_at_us < proposal.created_at_us
        || accepted_at_us < receipt.recorded_at_us
    {
        return Err(SemanticServiceError::InvalidInput);
    }
    Ok(())
}

fn accepted_draft(
    proposal: &RevisionProposal,
) -> Result<evertrace_domain::semantic::AtomDraft, SemanticServiceError> {
    let mut draft = match &proposal.payload {
        ProposalPayload::Atom(payload) => match payload.as_ref() {
            AtomProposalPayload::Create { draft }
            | AtomProposalPayload::Replace { draft }
            | AtomProposalPayload::Reclassify { draft } => Ok(draft.clone()),
            AtomProposalPayload::Deprecate { .. } => Err(SemanticServiceError::InvalidInput),
            AtomProposalPayload::Merge { draft, .. } => Ok(draft.clone()),
            AtomProposalPayload::Split { .. } => Err(SemanticServiceError::UnsupportedTarget),
        }?,
        ProposalPayload::Procedure(_)
        | ProposalPayload::CoreMembership(_)
        | ProposalPayload::ReservedTarget { .. } => {
            return Err(SemanticServiceError::UnsupportedTarget);
        }
    };
    draft.evidence_refs.extend(proposal.evidence_refs.clone());
    normalize_refs(&mut draft.evidence_refs);
    Ok(draft)
}

fn validate_atom_merge(
    view: &SemanticCurrentView,
    proposal: &RevisionProposal,
) -> Result<(), SemanticServiceError> {
    let (Some(ProposalTargetId::Atom(target_atom_id)), Some(base_revision_id)) =
        (proposal.target_id, proposal.base_revision_id)
    else {
        return Err(SemanticServiceError::BaseConflict);
    };
    let ProposalPayload::Atom(payload) = &proposal.payload else {
        return Err(SemanticServiceError::UnsupportedTarget);
    };
    let AtomProposalPayload::Merge {
        draft,
        merged_revision_refs,
    } = payload.as_ref()
    else {
        return Err(SemanticServiceError::UnsupportedTarget);
    };
    if proposal.operation != ProposalOperation::Merge
        || merged_revision_refs != &draft.supersedes_revision_refs
        || !merged_revision_refs.contains(&base_revision_id)
        || view
            .atoms
            .get(&target_atom_id)
            .is_none_or(|atom| atom.revision_id != base_revision_id)
    {
        return Err(SemanticServiceError::BaseConflict);
    }
    let mut atom_ids = std::collections::BTreeSet::new();
    for revision_id in merged_revision_refs {
        let atom = view
            .atom_revisions
            .get(revision_id)
            .ok_or(SemanticServiceError::BaseConflict)?;
        if atom.lifecycle_status != AtomLifecycleStatus::Active
            || atom.kind != draft.kind
            || !atom.scope.contains(&draft.scope)
            || view.atoms.get(&atom.atom_id) != Some(atom)
        {
            return Err(SemanticServiceError::BaseConflict);
        }
        atom_ids.insert(atom.atom_id);
    }
    if atom_ids.len() < 2 {
        return Err(SemanticServiceError::BaseConflict);
    }
    Ok(())
}

fn acceptance_basis(
    context: &AtomAcceptanceContext,
    draft: &evertrace_domain::semantic::AtomDraft,
) -> Result<AtomAuthorityBasis, SemanticServiceError> {
    match context {
        AtomAcceptanceContext::CurrentTaskExactMessage {
            observation,
            receipt,
            canonical_message,
            ..
        } => Ok(AtomAuthorityBasis::CurrentTaskExactMessage {
            observation: observation.clone(),
            receipt: receipt.clone(),
            canonical_message: canonical_message.clone(),
        }),
        AtomAcceptanceContext::RepositoryTui {
            observation,
            receipt,
        } => {
            let AtomScope::Repository {
                repository_instance_id,
            } = draft.scope
            else {
                return Err(SemanticServiceError::UnsupportedTarget);
            };
            Ok(AtomAuthorityBasis::TuiAcceptance(
                VerifiedTuiAcceptance::new(
                    observation.clone(),
                    receipt.clone(),
                    AtomScope::Repository {
                        repository_instance_id,
                    },
                ),
            ))
        }
        AtomAcceptanceContext::TaskTui {
            observation,
            receipt,
        } => {
            let AtomScope::Task { task_id } = draft.scope else {
                return Err(SemanticServiceError::UnsupportedTarget);
            };
            Ok(AtomAuthorityBasis::TuiAcceptance(
                VerifiedTuiAcceptance::new(
                    observation.clone(),
                    receipt.clone(),
                    AtomScope::Task { task_id },
                ),
            ))
        }
        AtomAcceptanceContext::GlobalTui {
            observation,
            receipt,
        } => {
            if !matches!(draft.scope, AtomScope::Global) {
                return Err(SemanticServiceError::UnsupportedTarget);
            }
            Ok(AtomAuthorityBasis::TuiAcceptance(
                VerifiedTuiAcceptance::new(observation.clone(), receipt.clone(), AtomScope::Global),
            ))
        }
        AtomAcceptanceContext::ObjectiveEvidence { .. } => {
            Ok(AtomAuthorityBasis::ObjectiveEvidence)
        }
    }
}

fn payload_command(
    context: ProposalCommandContext,
    payloads: Vec<JournalPayload>,
) -> Result<JournalCommand, SemanticServiceError> {
    let events = payloads
        .into_iter()
        .map(|payload| {
            JournalEventDraft::runtime(
                context.occurred_at_us,
                context.effective_config_hash,
                context.algorithm_revision.clone(),
                payload,
            )
        })
        .collect();
    JournalCommand::new(context.command_id, events).map_err(SemanticServiceError::Store)
}

fn normalize_refs(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}
