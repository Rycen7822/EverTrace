use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use evertrace_capture::{
    CaptureError, CaptureOutcome, CaptureRecordInput, CaptureRuntime, CasDigest, CasStore,
    DurableSpool, RuntimeSnapshot,
};
use evertrace_domain::{
    config::GlobalPromotionConfig,
    evidence::{
        CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceSourceKind,
        HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceRevisionMode, SourceRole,
        hex, payload_fingerprint,
    },
    ids::{CommandId, CoreMembershipId, RequestId, RevisionProposalId},
    procedure::{ProcedurePublicationState, ProcedureScope},
    purge::{ObjectDeletionLedgerEvent, ObjectReauthorizationIntent},
    revision::RevisionId,
    semantic::{
        AcceptedProposalTarget, AtomProposalPayload, AtomScope, CoreMembershipProposalPayload,
        HumanAtomAuthoring, ProposalAcceptanceAuthority, ProposalCreatedBy, ProposalEligibility,
        ProposalOperation, ProposalPayload, ProposalStatus, ProposalTargetId, ProposalWaitingOn,
        RevisionProposal, SupportThresholdSnapshot, TUI_ACCEPTANCE_EVENT_MANIFEST_REF,
        WEB_ACCEPTANCE_EVENT_MANIFEST_REF, WebAcceptanceIntent, WebAtomEdit,
        is_human_authoring_manifest, tui_acceptance_capture_matches, tui_acceptance_event_payload,
    },
};
use evertrace_store::{
    JournalCommand, JournalPayload, ObjectDeletionCandidateAdmission,
    ObjectDeletionCandidateAdmissionView, ObjectDeletionCurrentView, ProjectionSnapshot,
    RecoveryEvidenceCurrentView, SemanticCurrentView, SourceIngestWatermark,
};
use thiserror::Error;

use crate::{
    WriterHandle,
    capture::verify_capture_frame,
    ingest::capture_event_drafts,
    procedure::{
        EditedProcedureAcceptance, ProcedureAcceptanceContext, ProcedureAcceptanceResolution,
        accept_procedure, accept_procedure_edited,
    },
    semantic::{
        AtomAcceptanceContext, CoreMembershipAcceptanceContext, ProposalCommandContext,
        ProposalResolution, RevisionProposalService, SubmitProposalRequest, SupportAtomAcceptance,
        accept_core_membership, select_support_atom_acceptance,
    },
};

mod authoring;

pub(crate) const ALGORITHM_REVISION: &str = "s31-human-governance-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HumanProposalDecision {
    Accept,
    EditAndAccept(Box<ProposalPayload>),
    Reauthorize,
    MergeAndAccept,
    Defer,
    Reject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HumanActionOutcome {
    Applied {
        current_revision_ref: String,
        audit_event_ref: String,
    },
    NoDelta {
        current_revision_ref: String,
    },
    Conflict {
        current_revision_ref: Option<String>,
    },
    Unavailable {
        reason: &'static str,
    },
    Unknown,
}

#[derive(Debug, Error)]
pub enum HumanGovernanceError {
    #[error("invalid human governance request")]
    InvalidInput,
    #[error("human governance store failure")]
    Store,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProposalEditIntent {
    original_proposal_id: RevisionProposalId,
    original_proposal_revision_id: RevisionId,
    original_fingerprint: [u8; 32],
    new_proposal: RevisionProposal,
}

impl ProposalEditIntent {
    fn new(original: &RevisionProposal, new_proposal: RevisionProposal) -> Self {
        Self {
            original_proposal_id: original.proposal_id,
            original_proposal_revision_id: original.proposal_revision_id,
            original_fingerprint: original.fingerprint,
            new_proposal,
        }
    }

    fn validate(&self, original: &RevisionProposal) -> Result<(), HumanGovernanceError> {
        if self.original_proposal_id != original.proposal_id
            || self.original_proposal_revision_id != original.proposal_revision_id
            || self.original_fingerprint != original.fingerprint
        {
            return Err(HumanGovernanceError::InvalidInput);
        }
        original
            .validate_edit_candidate(&self.new_proposal)
            .map_err(|_| HumanGovernanceError::InvalidInput)
    }

    fn canonical_toml(&self, original: &RevisionProposal) -> Result<String, HumanGovernanceError> {
        self.validate(original)?;
        original
            .edit_intent_toml(&self.new_proposal)
            .map_err(|_| HumanGovernanceError::InvalidInput)
    }

    fn from_toml(value: &str) -> Result<Self, HumanGovernanceError> {
        let (
            original_proposal_id,
            original_proposal_revision_id,
            original_fingerprint,
            new_proposal,
        ) = RevisionProposal::parse_edit_intent_toml(value)
            .map_err(|_| HumanGovernanceError::Store)?;
        Ok(Self {
            original_proposal_id,
            original_proposal_revision_id,
            original_fingerprint,
            new_proposal,
        })
    }
}

/// Protected human decisions and reserved capture recovery, independent of any management surface.
#[derive(Clone)]
pub struct HumanAcceptanceService {
    writer: WriterHandle,
    effective_config_hash: [u8; 32],
    runtime_snapshot: Option<RuntimeSnapshot>,
    global_promotion: GlobalPromotionConfig,
}

impl HumanAcceptanceService {
    pub fn new(
        writer: WriterHandle,
        effective_config_hash: [u8; 32],
        runtime_snapshot: Option<RuntimeSnapshot>,
        global_promotion: GlobalPromotionConfig,
    ) -> Self {
        Self {
            writer,
            effective_config_hash,
            runtime_snapshot,
            global_promotion,
        }
    }

    pub async fn reconcile_reserved_once(&self) -> Result<(), HumanGovernanceError> {
        let Some(runtime_snapshot) = self.runtime_snapshot.as_ref() else {
            return Ok(());
        };
        let spool = DurableSpool::open_read_only(
            runtime_snapshot.spool_dir.clone(),
            runtime_snapshot
                .spool_limits()
                .map_err(|_| HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let limit = usize::try_from(runtime_snapshot.max_main_files)
            .map_err(|_| HumanGovernanceError::Store)?;
        let cas = CasStore::open(runtime_snapshot.cas_dir.clone())
            .map_err(|_| HumanGovernanceError::Store)?;
        for segment in spool
            .isolated_segments(limit)
            .map_err(|_| HumanGovernanceError::Store)?
        {
            let frame = segment
                .frames()
                .first()
                .filter(|_| segment.frames().len() == 1)
                .ok_or(HumanGovernanceError::Store)?;
            let verified =
                verify_capture_frame(frame, &cas).map_err(|_| HumanGovernanceError::Store)?;
            if is_human_authoring_manifest(&verified.body.eligible_event_manifest_ref) {
                Box::pin(self.reconcile_web_authoring(&verified, &cas)).await?;
                spool
                    .acknowledge_segment(segment, 1)
                    .map_err(|_| HumanGovernanceError::Store)?;
                continue;
            }
            let web = match verified.body.eligible_event_manifest_ref.as_str() {
                TUI_ACCEPTANCE_EVENT_MANIFEST_REF => false,
                WEB_ACCEPTANCE_EVENT_MANIFEST_REF => true,
                _ => return Err(HumanGovernanceError::Store),
            };
            let proposal_id = RevisionProposalId::from_str(&verified.body.source_ref)
                .map_err(|_| HumanGovernanceError::Store)?;
            let snapshot = self
                .writer
                .project()
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
            let view = SemanticCurrentView::from_snapshot(&snapshot)
                .map_err(|_| HumanGovernanceError::Store)?;
            let reviewed_revision = RevisionId::from_str(verified.body.source_revision.as_str())
                .map_err(|_| HumanGovernanceError::Store)?;
            let reviewed = view
                .proposal_revisions
                .get(&reviewed_revision)
                .filter(|value| value.proposal_id == proposal_id)
                .ok_or(HumanGovernanceError::Store)?;
            if web {
                Box::pin(self.reconcile_web(&verified, &cas, &snapshot, &view, reviewed)).await?;
                spool
                    .acknowledge_segment(segment, 1)
                    .map_err(|_| HumanGovernanceError::Store)?;
                continue;
            }
            if let Some(reserved) =
                try_read_reauthorization_intent(&verified, &cas, &snapshot, reviewed)?
            {
                let deletion = reserved.deletion;
                let intent = reserved.intent;
                let source = reviewed;
                let canonical = intent
                    .canonical_toml(&deletion, reviewed)
                    .ok_or(HumanGovernanceError::Store)?;
                validate_reauthorization_capture(&verified, source, &canonical)?;
                if let Some(committed) = self
                    .writer
                    .committed_command(verified.body.command_id)
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?
                {
                    let accepted = verify_reauthorization_cohort(
                        &committed.payloads,
                        &verified,
                        &deletion,
                        reviewed,
                    )?;
                    if view.proposals.get(&accepted.proposal_id) != Some(&accepted) {
                        return Err(HumanGovernanceError::Store);
                    }
                    spool
                        .acknowledge_segment(segment, 1)
                        .map_err(|_| HumanGovernanceError::Store)?;
                    continue;
                }
                if view.proposals.get(&source.proposal_id) != Some(source) {
                    continue;
                }
                let request_id = RequestId::from_uuid(verified.body.command_id.as_uuid())
                    .map_err(|_| HumanGovernanceError::Store)?;
                drop(segment);
                let _ = Box::pin(self.accept_reauthorization(request_id, &snapshot, &view, source))
                    .await?;
                continue;
            }
            if let Some(intent) = try_read_edit_intent(&verified, &cas, reviewed)? {
                validate_edit_capture(&verified, reviewed, &intent)?;
                if let Some(committed) = self
                    .writer
                    .committed_command(verified.body.command_id)
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?
                {
                    let (superseded, accepted) = verify_edit_acceptance_cohort(
                        &committed.payloads,
                        &verified,
                        reviewed,
                        &intent,
                    )?;
                    validate_current_edit_cohort(&snapshot, &view, &superseded, &accepted)?;
                    spool
                        .acknowledge_segment(segment, 1)
                        .map_err(|_| HumanGovernanceError::Store)?;
                    continue;
                }
                if view.proposals.get(&proposal_id) != Some(reviewed) {
                    spool
                        .acknowledge_segment(segment, 1)
                        .map_err(|_| HumanGovernanceError::Store)?;
                    continue;
                }
                let request_id = RequestId::from_uuid(verified.body.command_id.as_uuid())
                    .map_err(|_| HumanGovernanceError::Store)?;
                drop(segment);
                let _ = self
                    .accept_edit(
                        request_id,
                        &snapshot,
                        &view,
                        reviewed,
                        intent.new_proposal.payload,
                    )
                    .await?;
                continue;
            }
            validate_acceptance_capture(&verified, reviewed)?;
            if let Some(committed) = self
                .writer
                .committed_command(verified.body.command_id)
                .await
                .map_err(|_| HumanGovernanceError::Store)?
            {
                let accepted = verify_acceptance_payload_cohort(
                    &committed.payloads,
                    &verified,
                    reviewed,
                    None,
                )?;
                if view.proposals.get(&proposal_id) != Some(&accepted) {
                    return Err(HumanGovernanceError::Store);
                }
                spool
                    .acknowledge_segment(segment, 1)
                    .map_err(|_| HumanGovernanceError::Store)?;
                continue;
            }
            let Some(proposal) = view.proposals.get(&proposal_id) else {
                spool
                    .acknowledge_segment(segment, 1)
                    .map_err(|_| HumanGovernanceError::Store)?;
                continue;
            };
            // A reservation is a record of intent, not permission to bypass a later deletion.
            if proposal.proposal_revision_id.to_string() != verified.body.source_revision.as_str()
                || !proposal.status.is_open()
                || !matches!(
                    deletion_admission(&snapshot, proposal)?,
                    ObjectDeletionCandidateAdmission::Clear
                )
            {
                spool
                    .acknowledge_segment(segment, 1)
                    .map_err(|_| HumanGovernanceError::Store)?;
                continue;
            }
            if inactive_unchanged_procedure(&snapshot, proposal)? {
                spool
                    .acknowledge_segment(segment, 1)
                    .map_err(|_| HumanGovernanceError::Store)?;
                continue;
            }
            if proposal.operation == ProposalOperation::Merge
                && RevisionProposalService
                    .validate_atom_merge(&view, proposal.proposal_id)
                    .is_err()
            {
                spool
                    .acknowledge_segment(segment, 1)
                    .map_err(|_| HumanGovernanceError::Store)?;
                continue;
            }
            let request_id = RequestId::from_uuid(verified.body.command_id.as_uuid())
                .map_err(|_| HumanGovernanceError::Store)?;
            drop(segment);
            let _ = self
                .accept_plain(request_id, &snapshot, &view, proposal)
                .await?;
        }
        Ok(())
    }

    /// A durable reservation is not a reusable permission: recheck it at the writer's current frontier.
    async fn reconcile_web(
        &self,
        verified: &crate::capture::VerifiedCapture,
        cas: &CasStore,
        snapshot: &ProjectionSnapshot,
        view: &SemanticCurrentView,
        reviewed: &RevisionProposal,
    ) -> Result<(), HumanGovernanceError> {
        let digest =
            CasDigest::from_str(&verified.body.cas_ref).map_err(|_| HumanGovernanceError::Store)?;
        let bytes = cas.read(&digest).map_err(|_| HumanGovernanceError::Store)?;
        let intent = WebAcceptanceIntent::read_canonical(&bytes, reviewed)
            .filter(|intent| {
                intent.capture_matches(reviewed, &verified.receipt, &verified.observation)
            })
            .ok_or(HumanGovernanceError::Store)?;
        if let Some(committed) = self
            .writer
            .committed_command(verified.body.command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
        {
            // A different already-committed use of this request ID cannot be overwritten.
            if web_acceptance_outcome(&committed, reviewed, |saved| saved == &intent).is_some() {
                verify_acceptance_payload_cohort(
                    &committed.payloads,
                    verified,
                    reviewed,
                    Some(&intent),
                )?;
            }
            return Ok(());
        }
        if intent.reviewed_frontier > snapshot.frontier {
            return Err(HumanGovernanceError::Store);
        }
        if view.proposals.get(&reviewed.proposal_id) != Some(reviewed)
            || !matches!(
                deletion_admission(snapshot, reviewed)?,
                ObjectDeletionCandidateAdmission::Clear
            )
        {
            return Ok(());
        }
        let service =
            crate::HumanGovernanceService::new(self.writer.clone(), self.effective_config_hash);
        if !service.proposal_accessible(snapshot, reviewed).await?
            || !Box::pin(authored_creation_scope_current(
                &service, snapshot, reviewed,
            ))
            .await?
            || (reviewed.core_creation().is_some()
                && service
                    .web_core_anchor_at(snapshot, view, reviewed)
                    .await?
                    .is_none())
            || ((reviewed.operation == ProposalOperation::Replace || intent.atom_edit.is_some())
                && !service.web_base_accessible(snapshot, reviewed).await?)
            || !service.web_merge_accessible_at(snapshot, reviewed).await?
        {
            return Ok(());
        }
        let at = now_us()?;
        let command =
            match self.web_acceptance_command(verified, snapshot, view, reviewed, &intent, at) {
                Err(HumanGovernanceError::InvalidInput) => return Ok(()),
                result => result?,
            };
        self.writer
            .commit_if_frontier(command, at, snapshot.frontier)
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let committed = self
            .writer
            .committed_command(verified.body.command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
            .ok_or(HumanGovernanceError::Store)?;
        verify_acceptance_payload_cohort(&committed.payloads, verified, reviewed, Some(&intent))?;
        Ok(())
    }

    fn web_acceptance_command(
        &self,
        verified: &crate::capture::VerifiedCapture,
        snapshot: &ProjectionSnapshot,
        view: &SemanticCurrentView,
        reviewed: &RevisionProposal,
        intent: &WebAcceptanceIntent,
        occurred_at_us: i64,
    ) -> Result<JournalCommand, HumanGovernanceError> {
        let context = ProposalCommandContext {
            command_id: verified.body.command_id,
            occurred_at_us,
            effective_config_hash: self.effective_config_hash,
            algorithm_revision: ALGORITHM_REVISION.into(),
        };
        let authority = AtomAcceptanceContext::Web {
            observation: Box::new(verified.observation.clone()),
            receipt: Box::new(verified.receipt.clone()),
            authorized_scope_ceiling: intent
                .reviewed_scope(reviewed)
                .ok_or(HumanGovernanceError::Store)?,
            intent: intent.clone(),
        };
        let accepted_events = if let Some(edit) = &intent.atom_edit {
            let payload = edit
                .payload(reviewed)
                .ok_or(HumanGovernanceError::InvalidInput)?;
            let (prepared, _) = prepare_edit_candidate(
                view,
                reviewed,
                payload,
                context.command_id,
                verified.receipt.recorded_at_us,
                self.effective_config_hash,
                None,
            )?;
            if !matches!(
                deletion_admission(snapshot, &prepared.new_proposal)?,
                ObjectDeletionCandidateAdmission::Clear
            ) {
                return Err(HumanGovernanceError::InvalidInput);
            }
            compose_edited_acceptance(EditedAcceptanceInput {
                snapshot,
                view,
                original: reviewed,
                reviewed: &prepared.new_proposal,
                acceptance: authority,
                command_context: context,
                effective_config_hash: self.effective_config_hash,
                global_promotion: &self.global_promotion,
                support: None,
            })?
            .events
        } else {
            self.web_plain_acceptance(snapshot, view, reviewed, context, authority)?
        };
        let mut events = capture_event_drafts(
            verified,
            None,
            self.effective_config_hash,
            ALGORITHM_REVISION,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        events.extend(accepted_events);
        JournalCommand::new(verified.body.command_id, events)
            .map_err(|_| HumanGovernanceError::Store)
    }

    fn web_plain_acceptance(
        &self,
        snapshot: &ProjectionSnapshot,
        view: &SemanticCurrentView,
        reviewed: &RevisionProposal,
        context: ProposalCommandContext,
        authority: AtomAcceptanceContext,
    ) -> Result<Vec<evertrace_store::JournalEventDraft>, HumanGovernanceError> {
        let accepted = if let Some((revision, scope)) = reviewed.core_creation() {
            let atom = scope
                .reviewable_atom(revision, view.atoms.values())
                .ok_or(HumanGovernanceError::Store)?;
            let membership = CoreMembershipId::from_uuid(reviewed.proposal_id.as_uuid())
                .map_err(|_| HumanGovernanceError::Store)?;
            accept_core_membership(
                view,
                context,
                reviewed.proposal_id,
                CoreMembershipAcceptanceContext::Web(authority),
                atom,
                membership,
                SupportThresholdSnapshot {
                    minimum_surviving_support: 1,
                    require_authorization: true,
                },
            )
            .map(|accepted| accepted.command)
        } else if matches!(reviewed.payload, ProposalPayload::Procedure(_)) {
            let (current, publication) = current_procedure(snapshot, reviewed)?;
            accept_procedure(
                view,
                context,
                reviewed.proposal_id,
                ProcedureAcceptanceContext::Manual(authority),
                current.as_ref(),
                publication,
                &self.global_promotion,
            )
            .and_then(|result| match result {
                ProcedureAcceptanceResolution::Command { command, .. }
                | ProcedureAcceptanceResolution::AcceptedExisting { command, .. } => Ok(command),
                ProcedureAcceptanceResolution::NoDelta => {
                    Err(crate::semantic::SemanticServiceError::BaseConflict)
                }
            })
        } else {
            RevisionProposalService
                .accept(view, context, reviewed.proposal_id, authority)
                .map(|accepted| accepted.command)
        }
        .map_err(|err| match err {
            crate::semantic::SemanticServiceError::Store(_) => HumanGovernanceError::Store,
            _ => HumanGovernanceError::InvalidInput,
        })?;
        Ok(accepted.events().to_vec())
    }

    pub async fn accept_reviewed_web(
        &self,
        service: &crate::HumanGovernanceService,
        request_id: RequestId,
        id: RevisionProposalId,
        revision: RevisionId,
        intent: WebAcceptanceIntent,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let conflict = || HumanActionOutcome::Conflict {
            current_revision_ref: None,
        };
        let Some(runtime) = self.runtime_snapshot.as_ref() else {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "web_acceptance_source_unavailable",
            });
        };
        let command = CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        if self
            .writer
            .committed_command(command)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
            .is_some()
        {
            return Ok(conflict());
        }
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let frontier = intent.reviewed_frontier;
        let Some(proposal) = view.proposals.get(&id).filter(|proposal| {
            snapshot.frontier == frontier && proposal.proposal_revision_id == revision
        }) else {
            return Ok(conflict());
        };
        if ((proposal.operation == ProposalOperation::Replace || intent.atom_edit.is_some())
            && !service.web_base_accessible(&snapshot, proposal).await?)
            || !Box::pin(authored_creation_scope_current(
                service, &snapshot, proposal,
            ))
            .await?
            || (intent.atom_edit.is_some()
                && !service.proposal_accessible(&snapshot, proposal).await?)
        {
            return Ok(conflict());
        }
        if proposal.atom_merge_inputs().is_some()
            && (RevisionProposalService
                .validate_atom_merge(&view, id)
                .is_err()
                || !service.web_merge_accessible_at(&snapshot, proposal).await?)
        {
            return Ok(conflict());
        }
        if !matches!(
            deletion_admission(&snapshot, proposal)?,
            ObjectDeletionCandidateAdmission::Clear
        ) {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "web_acceptance_requires_reauthorization",
            });
        }
        if proposal.core_creation().is_some_and(|(revision, scope)| {
            scope
                .reviewable_atom(revision, view.atoms.values())
                .is_none()
        }) {
            return Ok(conflict());
        }
        let canonical = intent
            .canonical(proposal)
            .ok_or(HumanGovernanceError::Store)?;
        let record_id = format!("web-accept-{id}-{revision}");
        let scope = acceptance_capture_scope(proposal, &view)?;
        let spool = DurableSpool::open_read_only(
            runtime.spool_dir.clone(),
            runtime
                .spool_limits()
                .map_err(|_| HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let cas =
            CasStore::open(runtime.cas_dir.clone()).map_err(|_| HumanGovernanceError::Store)?;
        let mut capture = CaptureRuntime::open_for_admission(runtime.clone())
            .map_err(|_| HumanGovernanceError::Store)?;
        let capture_record =
            human_acceptance_capture_input(proposal, &canonical, &record_id, scope, true)?;
        // A repeated request ID cannot reserve a different confirmation. Different requests
        // for one proposal compete at the existing journal frontier check.
        let routing_hint = format!("web-{}", command.as_uuid().hyphenated());
        let segment = match capture.capture_isolated(capture_record, command, &routing_hint) {
            Ok(result) if matches!(result.outcome, CaptureOutcome::Durable { .. }) => {
                result.segment
            }
            Err(CaptureError::ReservationExists) => return Ok(HumanActionOutcome::Unknown),
            _ => return Err(HumanGovernanceError::Store),
        };
        let [frame] = segment.frames() else {
            return Err(HumanGovernanceError::Store);
        };
        let verified =
            verify_capture_frame(frame, &cas).map_err(|_| HumanGovernanceError::Store)?;
        let at = now_us()?;
        let batch =
            match self.web_acceptance_command(&verified, &snapshot, &view, proposal, &intent, at) {
                Err(HumanGovernanceError::InvalidInput) => {
                    acknowledge_web_reservation(&spool, &segment).await?;
                    return Ok(conflict());
                }
                result => result?,
            };
        match self.writer.commit_if_frontier(batch, at, frontier).await {
            Ok(_) => (),
            Err(
                crate::WriterActorError::StaleFrontier
                | crate::WriterActorError::IdempotencyConflict,
            ) => {
                acknowledge_web_reservation(&spool, &segment).await?;
                return Ok(conflict());
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        }
        let committed = self
            .writer
            .committed_command(command)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
            .ok_or(HumanGovernanceError::Store)?;
        verify_acceptance_payload_cohort(&committed.payloads, &verified, proposal, Some(&intent))?;
        let outcome = web_acceptance_outcome(&committed, proposal, |saved| saved == &intent)
            .ok_or(HumanGovernanceError::Store)?;
        acknowledge_web_reservation(&spool, &segment).await?;
        Ok(outcome)
    }

    pub async fn reviewed_web_outcome(
        &self,
        service: &crate::HumanGovernanceService,
        request_id: RequestId,
        frontier: u64,
        (id, revision, digest): (RevisionProposalId, RevisionId, &str),
        submitted_edit: Option<Option<&WebAtomEdit>>,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let command = CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let Some(committed) = self
            .writer
            .committed_command(command)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
        else {
            return Ok(HumanActionOutcome::Unknown);
        };
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let Some(proposal) = view
            .proposal_revisions
            .get(&revision)
            .filter(|proposal| proposal.proposal_id == id)
        else {
            return Ok(HumanActionOutcome::Unknown);
        };
        let Some(outcome) = web_acceptance_outcome(&committed, proposal, |saved| {
            saved.reviewed_frontier == frontier
                && hex(&saved.review_digest) == digest
                && submitted_edit.is_none_or(|edit| saved.atom_edit.as_deref() == edit)
                && saved.canonical(proposal).is_some()
        }) else {
            return Ok(HumanActionOutcome::Unknown);
        };
        if !service.proposal_accessible(&snapshot, proposal).await?
            || !service.web_merge_accessible_at(&snapshot, proposal).await?
        {
            return Ok(HumanActionOutcome::Unknown);
        }
        Ok(outcome)
    }

    pub async fn dispose_reviewed_web(
        &self,
        request_id: RequestId,
        frontier: u64,
        reviewed: &RevisionProposal,
        digest: &str,
        waiting_on: Option<ProposalWaitingOn>,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let current = view.proposals.get(&reviewed.proposal_id);
        let conflict = || HumanActionOutcome::Conflict {
            current_revision_ref: current.map(|proposal| proposal.proposal_revision_id.to_string()),
        };
        if snapshot.frontier != frontier || current != Some(reviewed) || !reviewed.status.is_open()
        {
            return Ok(conflict());
        }
        if let Some(base) = reviewed.base_revision_id {
            let reference = base.to_string();
            let selected =
                evertrace_store::projections::select_object_row_rows(&snapshot.rows, &reference)
                    .map_err(|_| HumanGovernanceError::Store)?;
            if !matches!(selected, Some((row, true)) if row.current_revision_id.as_deref() == Some(reference.as_str()))
            {
                return Ok(conflict());
            }
        }
        let context = command_context(request_id, self.effective_config_hash)?;
        let (status, reason) = web_disposition_status(waiting_on);
        let ProposalResolution::Revision { value, command } = RevisionProposalService
            .revise_status(
                &view,
                context,
                reviewed.proposal_id,
                status,
                waiting_on.into_iter().collect(),
                Some(reason.into()),
            )
            .map_err(|_| HumanGovernanceError::Store)?
        else {
            return Err(HumanGovernanceError::Store);
        };
        let [event] = command.events() else {
            return Err(HumanGovernanceError::Store);
        };
        let mut event = event.clone();
        // Bind the originating Web review to this existing journal event, without an acceptance source or another ledger.
        event.causation_id = Some(web_disposition_cause(frontier, digest));
        let command = JournalCommand::new(command.command_id(), vec![event])
            .map_err(|_| HumanGovernanceError::Store)?;
        match self
            .writer
            .commit_if_frontier(command, now_us()?, frontier)
            .await
        {
            Ok(outcome) => Ok(HumanActionOutcome::Applied {
                current_revision_ref: value.proposal_revision_id.to_string(),
                audit_event_ref: outcome
                    .event_ids
                    .into_iter()
                    .next()
                    .ok_or(HumanGovernanceError::Store)?,
            }),
            Err(
                crate::WriterActorError::StaleFrontier
                | crate::WriterActorError::IdempotencyConflict,
            ) => Ok(conflict()),
            Err(_) => Err(HumanGovernanceError::Store),
        }
    }

    pub async fn web_disposition_outcome(
        &self,
        service: &crate::HumanGovernanceService,
        request_id: RequestId,
        frontier: u64,
        reviewed: (RevisionProposalId, RevisionId, &str),
        waiting_on: Option<ProposalWaitingOn>,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let (id, revision, digest) = reviewed;
        let command_id = CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let Some(committed) = self
            .writer
            .committed_command(command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
        else {
            return Ok(HumanActionOutcome::Unknown);
        };
        let ([JournalPayload::RevisionProposalRecorded(next)], [audit]) = (
            committed.payloads.as_slice(),
            committed.event_ids.as_slice(),
        ) else {
            return Ok(HumanActionOutcome::Unknown);
        };
        let (status, reason) = web_disposition_status(waiting_on);
        if next.proposal_id != id
            || next.parent_proposal_revision_id != Some(revision)
            || next.status != status
            || next.review_reason.as_deref() != Some(reason)
            || !next.waiting_on.iter().copied().eq(waiting_on)
            || committed.first_causation_id.as_deref()
                != Some(web_disposition_cause(frontier, digest).as_str())
        {
            return Ok(HumanActionOutcome::Unknown);
        }
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if !service.proposal_accessible(&snapshot, next).await? {
            return Ok(HumanActionOutcome::Unknown);
        }
        Ok(HumanActionOutcome::Applied {
            current_revision_ref: next.proposal_revision_id.to_string(),
            audit_event_ref: audit.clone(),
        })
    }

    pub async fn decide_proposal(
        &self,
        request_id: RequestId,
        expected_frontier: u64,
        proposal_id: RevisionProposalId,
        expected_revision_id: RevisionId,
        expected_fingerprint: &str,
        decision: HumanProposalDecision,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        if expected_fingerprint.len() != 64
            || !expected_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(HumanGovernanceError::InvalidInput);
        }
        if matches!(
            &decision,
            HumanProposalDecision::Accept
                | HumanProposalDecision::MergeAndAccept
                | HumanProposalDecision::Reauthorize
        ) {
            Box::pin(self.reconcile_reserved_once()).await?;
        }
        let snapshot = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        if let HumanProposalDecision::EditAndAccept(edited_payload) = &decision
            && let Some(original) =
                view.proposal_revisions
                    .get(&expected_revision_id)
                    .filter(|value| {
                        value.proposal_id == proposal_id
                            && hex(&value.fingerprint) == expected_fingerprint
                    })
            && let Some(accepted) = accepted_edit_retry(&snapshot, &view, original, edited_payload)?
        {
            Box::pin(self.reconcile_reserved_once()).await?;
            return Ok(HumanActionOutcome::NoDelta {
                current_revision_ref: accepted.proposal_revision_id.to_string(),
            });
        }
        if let HumanProposalDecision::Reauthorize = &decision
            && let Some(original) =
                view.proposal_revisions
                    .get(&expected_revision_id)
                    .filter(|value| {
                        value.proposal_id == proposal_id
                            && hex(&value.fingerprint) == expected_fingerprint
                    })
            && let Some(accepted) = accepted_reauthorization_retry(&snapshot, &view, original)?
        {
            Box::pin(self.reconcile_reserved_once()).await?;
            return Ok(HumanActionOutcome::NoDelta {
                current_revision_ref: accepted.proposal_revision_id.to_string(),
            });
        }
        let Some(current) = view.proposals.get(&proposal_id) else {
            return Err(HumanGovernanceError::InvalidInput);
        };
        if matches!(
            &decision,
            HumanProposalDecision::Accept | HumanProposalDecision::MergeAndAccept
        ) && current.status == ProposalStatus::Accepted
            && current.acceptance.as_ref().is_some_and(|acceptance| {
                acceptance.reviewed_proposal_revision_id == expected_revision_id
                    && hex(&acceptance.reviewed_fingerprint) == expected_fingerprint
            })
        {
            return Ok(HumanActionOutcome::NoDelta {
                current_revision_ref: current.proposal_revision_id.to_string(),
            });
        }
        if snapshot.frontier != expected_frontier {
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref: Some(current.proposal_revision_id.to_string()),
            });
        }
        if current.proposal_revision_id != expected_revision_id
            || hex(&current.fingerprint) != expected_fingerprint
        {
            return Ok(HumanActionOutcome::Conflict {
                current_revision_ref: Some(current.proposal_revision_id.to_string()),
            });
        }
        let deletion_admission = deletion_admission(&snapshot, current)?;
        if matches!(
            &decision,
            HumanProposalDecision::Accept
                | HumanProposalDecision::EditAndAccept(_)
                | HumanProposalDecision::MergeAndAccept
        ) && !matches!(deletion_admission, ObjectDeletionCandidateAdmission::Clear)
        {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "forgotten_object_requires_explicit_reauthorization",
            });
        }
        let next_status = match &decision {
            HumanProposalDecision::Defer => ProposalStatus::Deferred,
            HumanProposalDecision::Reject => ProposalStatus::Rejected,
            HumanProposalDecision::Accept => {
                let (plain_accept_eligible, _) = proposal_acceptance_eligibility(&view, current);
                if !plain_accept_eligible {
                    return Ok(HumanActionOutcome::Unavailable {
                        reason: "atomic_plain_acceptance_unavailable",
                    });
                }
                return self
                    .accept_plain(request_id, &snapshot, &view, current)
                    .await;
            }
            HumanProposalDecision::EditAndAccept(edited_payload) => {
                if !proposal_edit_supported(&current.payload) {
                    return Ok(HumanActionOutcome::Unavailable {
                        reason: "atomic_edit_and_accept_unavailable",
                    });
                }
                return self
                    .accept_edit(
                        request_id,
                        &snapshot,
                        &view,
                        current,
                        edited_payload.as_ref().clone(),
                    )
                    .await;
            }
            HumanProposalDecision::Reauthorize => {
                if deletion_admission
                    .representative_historical_deletion()
                    .is_none()
                    || current.operation != ProposalOperation::Create
                {
                    return Ok(HumanActionOutcome::Unavailable {
                        reason: "object_reauthorization_unavailable",
                    });
                }
                return Box::pin(
                    self.accept_reauthorization(request_id, &snapshot, &view, current),
                )
                .await;
            }
            HumanProposalDecision::MergeAndAccept => {
                let (_, merge_and_accept_eligible) =
                    proposal_acceptance_eligibility(&view, current);
                if !merge_and_accept_eligible {
                    return Ok(HumanActionOutcome::Unavailable {
                        reason: "atomic_merge_and_accept_unavailable",
                    });
                }
                return self
                    .accept_plain(request_id, &snapshot, &view, current)
                    .await;
            }
        };
        let context = command_context(request_id, self.effective_config_hash)?;
        match RevisionProposalService
            .revise_status(
                &view,
                context,
                proposal_id,
                next_status,
                Vec::new(),
                Some(
                    match &decision {
                        HumanProposalDecision::Defer => "human_deferred",
                        HumanProposalDecision::Reject => "human_rejected",
                        HumanProposalDecision::Reauthorize => unreachable!(),
                        _ => unreachable!(),
                    }
                    .into(),
                ),
            )
            .map_err(|_| HumanGovernanceError::InvalidInput)?
        {
            ProposalResolution::NoDelta => Ok(HumanActionOutcome::NoDelta {
                current_revision_ref: current.proposal_revision_id.to_string(),
            }),
            ProposalResolution::Revision { value, command } => {
                let revision = value.proposal_revision_id.to_string();
                let outcome = match self
                    .writer
                    .commit_if_frontier(command, now_us()?, snapshot.frontier)
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(crate::WriterActorError::StaleFrontier) => {
                        let latest = self
                            .writer
                            .project()
                            .await
                            .map_err(|_| HumanGovernanceError::Store)?;
                        return Ok(HumanActionOutcome::Conflict {
                            current_revision_ref: current_proposal_revision(&latest, proposal_id),
                        });
                    }
                    Err(_) => return Err(HumanGovernanceError::Store),
                };
                let audit = outcome
                    .event_ids
                    .last()
                    .cloned()
                    .ok_or(HumanGovernanceError::Store)?;
                Ok(HumanActionOutcome::Applied {
                    current_revision_ref: revision,
                    audit_event_ref: audit,
                })
            }
        }
    }

    async fn accept_edit(
        &self,
        request_id: RequestId,
        snapshot: &ProjectionSnapshot,
        view: &SemanticCurrentView,
        original: &RevisionProposal,
        edited_payload: ProposalPayload,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let Some(runtime_snapshot) = self.runtime_snapshot.as_ref() else {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "atomic_tui_acceptance_source_unavailable",
            });
        };
        let support = match support_atom_acceptance(snapshot, view, original) {
            Ok(value) => value,
            Err(crate::semantic::SemanticServiceError::Store(_)) => {
                return Err(HumanGovernanceError::Store);
            }
            Err(_) => {
                return Ok(HumanActionOutcome::Unavailable {
                    reason: "support_linked_global_acceptance_unavailable",
                });
            }
        };
        let record_id = format!(
            "tui-accept-{}-{}",
            original.proposal_id, original.proposal_revision_id
        );
        let routing_hint = format!("tui-{}", original.proposal_id.as_uuid().hyphenated());
        let max_segments = usize::try_from(runtime_snapshot.max_main_files)
            .map_err(|_| HumanGovernanceError::Store)?;
        let spool = DurableSpool::open_read_only(
            runtime_snapshot.spool_dir.clone(),
            runtime_snapshot
                .spool_limits()
                .map_err(|_| HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let cas = CasStore::open(runtime_snapshot.cas_dir.clone())
            .map_err(|_| HumanGovernanceError::Store)?;
        let mut claimed = claim_isolated_record(&spool, &record_id, max_segments)?;
        if let Some(segment) = claimed.take() {
            let frame = segment
                .frames()
                .first()
                .filter(|_| segment.frames().len() == 1)
                .ok_or(HumanGovernanceError::Store)?;
            let verified =
                verify_capture_frame(frame, &cas).map_err(|_| HumanGovernanceError::Store)?;
            let stored = read_edit_intent(&verified, &cas, original)?;
            validate_edit_capture(&verified, original, &stored)?;
            if stored.new_proposal.payload == edited_payload {
                claimed = Some(segment);
            } else {
                match self
                    .writer
                    .committed_command(verified.body.command_id)
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?
                {
                    None if view.proposals.get(&original.proposal_id) == Some(original) => {
                        spool
                            .acknowledge_segment(segment, 1)
                            .map_err(|_| HumanGovernanceError::Store)?;
                    }
                    _ => return Err(HumanGovernanceError::Store),
                }
            }
        }
        if claimed.is_none() {
            let command_id = CommandId::from_uuid(request_id.as_uuid())
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
            let created_at_us = now_us()?;
            let (intent, _) = prepare_edit_candidate(
                view,
                original,
                edited_payload.clone(),
                command_id,
                created_at_us,
                self.effective_config_hash,
                None,
            )?;
            let canonical = intent.canonical_toml(original)?;
            let scope = acceptance_capture_scope(&intent.new_proposal, view)?;
            let mut capture = CaptureRuntime::open(runtime_snapshot.clone())
                .map_err(|_| HumanGovernanceError::Store)?;
            let isolated = capture
                .capture_isolated(
                    acceptance_capture_input(original, &canonical, &record_id, scope)?,
                    command_id,
                    &routing_hint,
                )
                .map_err(|_| HumanGovernanceError::Store)?;
            if !matches!(isolated.outcome, CaptureOutcome::Durable { .. }) {
                return Err(HumanGovernanceError::Store);
            }
            claimed = Some(isolated.segment);
        }
        let segment = claimed.ok_or(HumanGovernanceError::Store)?;
        let frame = segment
            .frames()
            .first()
            .filter(|_| segment.frames().len() == 1)
            .ok_or(HumanGovernanceError::Store)?;
        let verified =
            verify_capture_frame(frame, &cas).map_err(|_| HumanGovernanceError::Store)?;
        let intent = read_edit_intent(&verified, &cas, original)?;
        validate_edit_capture(&verified, original, &intent)?;
        if intent.new_proposal.payload != edited_payload {
            return Err(HumanGovernanceError::Store);
        }
        let occurred_at_us = now_us()?;
        let command_context = ProposalCommandContext {
            command_id: verified.body.command_id,
            occurred_at_us,
            effective_config_hash: self.effective_config_hash,
            algorithm_revision: ALGORITHM_REVISION.into(),
        };
        let mut edited_view = view.clone();
        edited_view
            .proposals
            .insert(intent.new_proposal.proposal_id, intent.new_proposal.clone());
        edited_view.proposal_revisions.insert(
            intent.new_proposal.proposal_revision_id,
            intent.new_proposal.clone(),
        );
        let context = acceptance_context(&intent.new_proposal, &edited_view, &verified)?;
        let composed = compose_edited_acceptance(EditedAcceptanceInput {
            snapshot,
            view,
            original,
            reviewed: &intent.new_proposal,
            acceptance: context,
            command_context,
            effective_config_hash: self.effective_config_hash,
            global_promotion: &self.global_promotion,
            support: support.as_ref(),
        })?;
        let accepted_revision = composed.accepted_revision;
        let superseded = composed.superseded;
        let mut events = capture_event_drafts(
            &verified,
            None,
            self.effective_config_hash,
            ALGORITHM_REVISION,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        events.extend(composed.events);
        let audit_ordinal = events
            .iter()
            .position(|event| {
                matches!(
                    &event.payload,
                    JournalPayload::RevisionProposalRecorded(value)
                        if value.proposal_id == intent.new_proposal.proposal_id
                            && value.status == ProposalStatus::Accepted
                )
            })
            .ok_or(HumanGovernanceError::Store)?;
        let command = JournalCommand::new(verified.body.command_id, events)
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let outcome = match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(outcome) => outcome,
            Err(crate::WriterActorError::StaleFrontier) => {
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: current_proposal_revision(
                        &self
                            .writer
                            .project()
                            .await
                            .map_err(|_| HumanGovernanceError::Store)?,
                        original.proposal_id,
                    ),
                });
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        };
        let committed = self
            .writer
            .committed_command(verified.body.command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
            .ok_or(HumanGovernanceError::Store)?;
        let (committed_superseded, committed_accepted) =
            verify_edit_acceptance_cohort(&committed.payloads, &verified, original, &intent)?;
        let fresh = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let fresh_view =
            SemanticCurrentView::from_snapshot(&fresh).map_err(|_| HumanGovernanceError::Store)?;
        validate_current_edit_cohort(
            &fresh,
            &fresh_view,
            &committed_superseded,
            &committed_accepted,
        )?;
        if committed_superseded.as_ref() != superseded.as_ref()
            || committed_accepted.proposal_revision_id != accepted_revision
        {
            return Err(HumanGovernanceError::Store);
        }
        let audit_event_ref = outcome
            .event_ids
            .get(audit_ordinal)
            .cloned()
            .ok_or(HumanGovernanceError::Store)?;
        spool
            .acknowledge_segment(segment, 1)
            .map_err(|_| HumanGovernanceError::Store)?;
        Ok(HumanActionOutcome::Applied {
            current_revision_ref: accepted_revision.to_string(),
            audit_event_ref,
        })
    }

    async fn accept_reauthorization(
        &self,
        request_id: RequestId,
        snapshot: &ProjectionSnapshot,
        view: &SemanticCurrentView,
        original: &RevisionProposal,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let Some(runtime_snapshot) = self.runtime_snapshot.as_ref() else {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "atomic_tui_acceptance_source_unavailable",
            });
        };
        let admission = deletion_admission(snapshot, original)?;
        let deletion = admission
            .representative_historical_deletion()
            .cloned()
            .ok_or(HumanGovernanceError::InvalidInput)?;
        let record_id = format!(
            "tui-reauthorize-{}-{}",
            original.proposal_id, original.proposal_revision_id
        );
        let routing_hint = format!("tui-{}", original.proposal_id.as_uuid().hyphenated());
        let max_segments = usize::try_from(runtime_snapshot.max_main_files)
            .map_err(|_| HumanGovernanceError::Store)?;
        let spool = DurableSpool::open_read_only(
            runtime_snapshot.spool_dir.clone(),
            runtime_snapshot
                .spool_limits()
                .map_err(|_| HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let cas = CasStore::open(runtime_snapshot.cas_dir.clone())
            .map_err(|_| HumanGovernanceError::Store)?;
        let mut claimed = claim_isolated_record(&spool, &record_id, max_segments)?;
        if claimed.is_none() {
            let command_id = CommandId::from_uuid(request_id.as_uuid())
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
            let intent = ObjectReauthorizationIntent::new(&deletion, original)
                .ok_or(HumanGovernanceError::InvalidInput)?;
            let canonical = intent
                .canonical_toml(&deletion, original)
                .ok_or(HumanGovernanceError::InvalidInput)?;
            let scope = acceptance_capture_scope(original, view)?;
            let mut capture = CaptureRuntime::open(runtime_snapshot.clone())
                .map_err(|_| HumanGovernanceError::Store)?;
            let isolated = capture
                .capture_isolated(
                    acceptance_capture_input(original, &canonical, &record_id, scope)?,
                    command_id,
                    &routing_hint,
                )
                .map_err(|_| HumanGovernanceError::Store)?;
            if !matches!(isolated.outcome, CaptureOutcome::Durable { .. }) {
                return Err(HumanGovernanceError::Store);
            }
            claimed = Some(isolated.segment);
        }
        let segment = claimed.ok_or(HumanGovernanceError::Store)?;
        let frame = segment
            .frames()
            .first()
            .filter(|_| segment.frames().len() == 1)
            .ok_or(HumanGovernanceError::Store)?;
        let verified =
            verify_capture_frame(frame, &cas).map_err(|_| HumanGovernanceError::Store)?;
        let intent = read_reauthorization_intent(&verified, &cas, &deletion, original)?;
        let reviewed = original;
        let canonical = intent
            .canonical_toml(&deletion, reviewed)
            .ok_or(HumanGovernanceError::Store)?;
        validate_reauthorization_capture(&verified, reviewed, &canonical)?;
        let occurred_at_us = now_us()?;
        let command_context = ProposalCommandContext {
            command_id: verified.body.command_id,
            occurred_at_us,
            effective_config_hash: self.effective_config_hash,
            algorithm_revision: ALGORITHM_REVISION.into(),
        };
        let mut events = capture_event_drafts(
            &verified,
            None,
            self.effective_config_hash,
            ALGORITHM_REVISION,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let acceptance = reauthorization_acceptance_context(reviewed, view, &verified, canonical)?;
        let (accepted_revision, accepted_command) = match &reviewed.payload {
            ProposalPayload::Atom(_) => {
                let accepted = RevisionProposalService
                    .accept(view, command_context, reviewed.proposal_id, acceptance)
                    .map_err(|_| HumanGovernanceError::InvalidInput)?;
                (accepted.proposal.proposal_revision_id, accepted.command)
            }
            ProposalPayload::Procedure(_) => {
                let result = accept_procedure(
                    view,
                    command_context,
                    reviewed.proposal_id,
                    ProcedureAcceptanceContext::Manual(acceptance),
                    None,
                    None,
                    &self.global_promotion,
                )
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
                match result {
                    ProcedureAcceptanceResolution::Command {
                        proposal, command, ..
                    } => (proposal.proposal_revision_id, command),
                    ProcedureAcceptanceResolution::AcceptedExisting { .. }
                    | ProcedureAcceptanceResolution::NoDelta => {
                        return Err(HumanGovernanceError::Store);
                    }
                }
            }
            ProposalPayload::CoreMembership(payload) => {
                let CoreMembershipProposalPayload::Create {
                    atom_revision_id, ..
                } = payload.as_ref()
                else {
                    return Err(HumanGovernanceError::InvalidInput);
                };
                let atom = view
                    .atom_revisions
                    .get(atom_revision_id)
                    .ok_or(HumanGovernanceError::InvalidInput)?;
                let membership = accept_core_membership(
                    view,
                    command_context,
                    reviewed.proposal_id,
                    CoreMembershipAcceptanceContext::Tui(acceptance),
                    atom,
                    CoreMembershipId::from_uuid(reviewed.proposal_id.as_uuid())
                        .map_err(|_| HumanGovernanceError::InvalidInput)?,
                    SupportThresholdSnapshot {
                        minimum_surviving_support: 1,
                        require_authorization: true,
                    },
                )
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
                (membership.proposal.proposal_revision_id, membership.command)
            }
            ProposalPayload::ReservedTarget { .. } => {
                return Err(HumanGovernanceError::InvalidInput);
            }
        };
        events.extend(accepted_command.events().iter().cloned());
        let audit_ordinal = events
            .iter()
            .position(|event| {
                matches!(
                    &event.payload,
                    JournalPayload::RevisionProposalRecorded(value)
                        if value.proposal_id == reviewed.proposal_id
                            && value.status == ProposalStatus::Accepted
                )
            })
            .ok_or(HumanGovernanceError::Store)?;
        let command = JournalCommand::new(verified.body.command_id, events)
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let outcome = match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(outcome) => outcome,
            Err(crate::WriterActorError::StaleFrontier) => {
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: current_proposal_revision(
                        &self
                            .writer
                            .project()
                            .await
                            .map_err(|_| HumanGovernanceError::Store)?,
                        original.proposal_id,
                    ),
                });
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        };
        let committed = self
            .writer
            .committed_command(verified.body.command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
            .ok_or(HumanGovernanceError::Store)?;
        let accepted =
            verify_reauthorization_cohort(&committed.payloads, &verified, &deletion, reviewed)?;
        if accepted.proposal_revision_id != accepted_revision {
            return Err(HumanGovernanceError::Store);
        }
        let audit_event_ref = outcome
            .event_ids
            .get(audit_ordinal)
            .cloned()
            .ok_or(HumanGovernanceError::Store)?;
        spool
            .acknowledge_segment(segment, 1)
            .map_err(|_| HumanGovernanceError::Store)?;
        Ok(HumanActionOutcome::Applied {
            current_revision_ref: accepted_revision.to_string(),
            audit_event_ref,
        })
    }

    async fn accept_plain(
        &self,
        request_id: RequestId,
        snapshot: &ProjectionSnapshot,
        view: &SemanticCurrentView,
        proposal: &RevisionProposal,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let Some(runtime_snapshot) = self.runtime_snapshot.as_ref() else {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "atomic_tui_acceptance_source_unavailable",
            });
        };
        if inactive_unchanged_procedure(snapshot, proposal)? {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "existing_procedure_not_active",
            });
        }
        let support = match support_atom_acceptance(snapshot, view, proposal) {
            Ok(value) => value,
            Err(crate::semantic::SemanticServiceError::Store(_)) => {
                return Err(HumanGovernanceError::Store);
            }
            Err(_) => {
                return Ok(HumanActionOutcome::Unavailable {
                    reason: "support_linked_global_acceptance_unavailable",
                });
            }
        };
        let payload = tui_acceptance_event_payload(
            proposal.proposal_id,
            proposal.proposal_revision_id,
            &proposal.fingerprint,
        );
        let record_id = format!(
            "tui-accept-{}-{}",
            proposal.proposal_id, proposal.proposal_revision_id
        );
        let routing_hint = format!("tui-{}", proposal.proposal_id.as_uuid().hyphenated());
        let max_segments = usize::try_from(runtime_snapshot.max_main_files)
            .map_err(|_| HumanGovernanceError::Store)?;
        let spool = DurableSpool::open_read_only(
            runtime_snapshot.spool_dir.clone(),
            runtime_snapshot
                .spool_limits()
                .map_err(|_| HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let mut claimed = claim_isolated_record(&spool, &record_id, max_segments)?;
        if claimed.is_none() {
            let scope = acceptance_capture_scope(proposal, view)?;
            let command_id = CommandId::from_uuid(request_id.as_uuid())
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
            let mut capture = CaptureRuntime::open(runtime_snapshot.clone())
                .map_err(|_| HumanGovernanceError::Store)?;
            let isolated = capture
                .capture_isolated(
                    acceptance_capture_input(proposal, &payload, &record_id, scope)?,
                    command_id,
                    &routing_hint,
                )
                .map_err(|_| HumanGovernanceError::Store)?;
            if !matches!(isolated.outcome, CaptureOutcome::Durable { .. }) {
                return Err(HumanGovernanceError::Store);
            }
            claimed = Some(isolated.segment);
        }
        let segment = claimed.ok_or(HumanGovernanceError::Store)?;
        let frame = segment
            .frames()
            .first()
            .filter(|_| segment.frames().len() == 1)
            .ok_or(HumanGovernanceError::Store)?;
        let cas = CasStore::open(runtime_snapshot.cas_dir.clone())
            .map_err(|_| HumanGovernanceError::Store)?;
        let verified =
            verify_capture_frame(frame, &cas).map_err(|_| HumanGovernanceError::Store)?;
        validate_acceptance_capture_payload(&verified, proposal, &payload, "tui-accept")?;
        let context = acceptance_context(proposal, view, &verified)?;
        let occurred_at_us = now_us()?;
        let command_context = ProposalCommandContext {
            command_id: verified.body.command_id,
            occurred_at_us,
            effective_config_hash: self.effective_config_hash,
            algorithm_revision: ALGORITHM_REVISION.into(),
        };
        let (accepted_revision, accepted_command) = match &proposal.payload {
            ProposalPayload::Atom(_) => {
                let accepted = if let Some(support) = &support {
                    RevisionProposalService.accept_support_linked(
                        view,
                        command_context,
                        proposal.proposal_id,
                        context,
                        support,
                    )
                } else {
                    RevisionProposalService.accept(
                        view,
                        command_context,
                        proposal.proposal_id,
                        context,
                    )
                }
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
                (accepted.proposal.proposal_revision_id, accepted.command)
            }
            ProposalPayload::Procedure(_) => {
                let (current, publication) = current_procedure(snapshot, proposal)?;
                let result = accept_procedure(
                    view,
                    command_context,
                    proposal.proposal_id,
                    ProcedureAcceptanceContext::Manual(context),
                    current.as_ref(),
                    publication,
                    &self.global_promotion,
                )
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
                match result {
                    ProcedureAcceptanceResolution::Command {
                        proposal, command, ..
                    }
                    | ProcedureAcceptanceResolution::AcceptedExisting { proposal, command } => {
                        (proposal.proposal_revision_id, command)
                    }
                    ProcedureAcceptanceResolution::NoDelta => {
                        return Err(HumanGovernanceError::Store);
                    }
                }
            }
            ProposalPayload::CoreMembership(payload) => {
                let CoreMembershipProposalPayload::Create {
                    atom_revision_id, ..
                } = payload.as_ref()
                else {
                    return Ok(HumanActionOutcome::Unavailable {
                        reason: "atomic_core_conflict_acceptance_unavailable",
                    });
                };
                let atom = view
                    .atom_revisions
                    .get(atom_revision_id)
                    .ok_or(HumanGovernanceError::InvalidInput)?;
                let membership = accept_core_membership(
                    view,
                    command_context,
                    proposal.proposal_id,
                    CoreMembershipAcceptanceContext::Tui(context),
                    atom,
                    evertrace_domain::ids::CoreMembershipId::from_uuid(
                        proposal.proposal_id.as_uuid(),
                    )
                    .map_err(|_| HumanGovernanceError::InvalidInput)?,
                    SupportThresholdSnapshot {
                        minimum_surviving_support: 1,
                        require_authorization: true,
                    },
                )
                .map_err(|_| HumanGovernanceError::InvalidInput)?;
                (membership.proposal.proposal_revision_id, membership.command)
            }
            ProposalPayload::ReservedTarget { .. } => {
                return Ok(HumanActionOutcome::Unavailable {
                    reason: "atomic_plain_acceptance_unavailable",
                });
            }
        };
        let mut events = capture_event_drafts(
            &verified,
            None,
            self.effective_config_hash,
            ALGORITHM_REVISION,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        events.extend(accepted_command.events().iter().cloned());
        let audit_ordinal = events
            .iter()
            .position(|event| {
                matches!(
                    &event.payload,
                    JournalPayload::RevisionProposalRecorded(value)
                        if value.proposal_id == proposal.proposal_id
                            && value.status == ProposalStatus::Accepted
                )
            })
            .ok_or(HumanGovernanceError::Store)?;
        let command = JournalCommand::new(verified.body.command_id, events)
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let outcome = match self
            .writer
            .commit_if_frontier(command, occurred_at_us, snapshot.frontier)
            .await
        {
            Ok(outcome) => outcome,
            Err(crate::WriterActorError::StaleFrontier) => {
                return Ok(HumanActionOutcome::Conflict {
                    current_revision_ref: current_proposal_revision(
                        &self
                            .writer
                            .project()
                            .await
                            .map_err(|_| HumanGovernanceError::Store)?,
                        proposal.proposal_id,
                    ),
                });
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        };
        let committed = self
            .writer
            .committed_command(verified.body.command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
            .ok_or(HumanGovernanceError::Store)?;
        let accepted =
            verify_acceptance_payload_cohort(&committed.payloads, &verified, proposal, None)?;
        let fresh = self
            .writer
            .project()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let fresh_view =
            SemanticCurrentView::from_snapshot(&fresh).map_err(|_| HumanGovernanceError::Store)?;
        if fresh_view.proposals.get(&proposal.proposal_id) != Some(&accepted)
            || accepted.proposal_revision_id != accepted_revision
        {
            return Err(HumanGovernanceError::Store);
        }
        let audit_event_ref = outcome
            .event_ids
            .get(audit_ordinal)
            .cloned()
            .ok_or(HumanGovernanceError::Store)?;
        spool
            .acknowledge_segment(segment, 1)
            .map_err(|_| HumanGovernanceError::Store)?;
        Ok(HumanActionOutcome::Applied {
            current_revision_ref: accepted_revision.to_string(),
            audit_event_ref,
        })
    }
}

async fn acknowledge_web_reservation(
    spool: &DurableSpool,
    segment: &evertrace_capture::SealedSegment,
) -> Result<(), HumanGovernanceError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
    loop {
        match spool.acknowledge_claimed_segment(segment, 1) {
            Ok(()) => return Ok(()),
            Err(evertrace_capture::SpoolError::Busy) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            Err(_) => return Err(HumanGovernanceError::Store),
        }
    }
}

fn deletion_admission(
    snapshot: &ProjectionSnapshot,
    proposal: &RevisionProposal,
) -> Result<ObjectDeletionCandidateAdmission, HumanGovernanceError> {
    ObjectDeletionCandidateAdmissionView::from_snapshot(snapshot)
        .and_then(|view| view.classify_proposal(proposal))
        .map_err(|_| HumanGovernanceError::Store)
}

pub(crate) fn proposal_acceptance_eligibility(
    view: &SemanticCurrentView,
    proposal: &RevisionProposal,
) -> (bool, bool) {
    let reviewable =
        proposal.status.is_open() && proposal.eligibility != ProposalEligibility::AutoEligibleFull;
    let plain = reviewable
        && match &proposal.payload {
            ProposalPayload::Atom(payload) => matches!(
                payload.as_ref(),
                AtomProposalPayload::Create { .. }
                    | AtomProposalPayload::Replace { .. }
                    | AtomProposalPayload::Deprecate { .. }
                    | AtomProposalPayload::Reclassify { .. }
            ),
            ProposalPayload::Procedure(payload) => matches!(
                payload.as_ref(),
                evertrace_domain::semantic::ProcedureProposalPayload::Create { .. }
                    | evertrace_domain::semantic::ProcedureProposalPayload::Replace { .. }
            ),
            ProposalPayload::CoreMembership(payload) => matches!(
                payload.as_ref(),
                CoreMembershipProposalPayload::Create { .. }
            ),
            ProposalPayload::ReservedTarget { .. } => false,
        };
    let merge = reviewable
        && matches!(
            &proposal.payload,
            ProposalPayload::Atom(payload)
                if matches!(payload.as_ref(), AtomProposalPayload::Merge { .. })
        )
        && RevisionProposalService
            .validate_atom_merge(view, proposal.proposal_id)
            .is_ok();
    (plain, merge)
}

fn proposal_edit_supported(payload: &ProposalPayload) -> bool {
    match payload {
        ProposalPayload::Atom(payload) => matches!(
            payload.as_ref(),
            AtomProposalPayload::Create { .. }
                | AtomProposalPayload::Replace { .. }
                | AtomProposalPayload::Deprecate { .. }
                | AtomProposalPayload::Reclassify { .. }
        ),
        ProposalPayload::Procedure(payload) => matches!(
            payload.as_ref(),
            evertrace_domain::semantic::ProcedureProposalPayload::Create { .. }
                | evertrace_domain::semantic::ProcedureProposalPayload::Replace { .. }
        ),
        ProposalPayload::CoreMembership(_) | ProposalPayload::ReservedTarget { .. } => false,
    }
}

fn current_proposal_revision(
    snapshot: &ProjectionSnapshot,
    proposal_id: RevisionProposalId,
) -> Option<String> {
    SemanticCurrentView::from_snapshot(snapshot)
        .ok()?
        .proposals
        .get(&proposal_id)
        .map(|proposal: &RevisionProposal| proposal.proposal_revision_id.to_string())
}

#[derive(Clone, Copy)]
struct AcceptanceCaptureScope {
    task_id: Option<evertrace_domain::ids::TaskId>,
    repository_id: Option<evertrace_domain::ids::RepositoryId>,
    worktree_id: Option<evertrace_domain::ids::WorktreeId>,
}

fn proposal_scope(
    proposal: &RevisionProposal,
    view: &SemanticCurrentView,
) -> Result<AtomScope, HumanGovernanceError> {
    match &proposal.payload {
        ProposalPayload::Atom(payload) => match payload.as_ref() {
            AtomProposalPayload::Create { draft }
            | AtomProposalPayload::Replace { draft }
            | AtomProposalPayload::Reclassify { draft } => Ok(draft.scope.clone()),
            AtomProposalPayload::Deprecate { .. } => {
                let Some(ProposalTargetId::Atom(atom_id)) = proposal.target_id else {
                    return Err(HumanGovernanceError::InvalidInput);
                };
                view.atoms
                    .get(&atom_id)
                    .map(|atom| atom.scope.clone())
                    .ok_or(HumanGovernanceError::InvalidInput)
            }
            AtomProposalPayload::Merge { draft, .. } => Ok(draft.scope.clone()),
            AtomProposalPayload::Split { .. } => Err(HumanGovernanceError::InvalidInput),
        },
        ProposalPayload::Procedure(payload) => Ok(match payload.draft().scope {
            ProcedureScope::Worktree { repository_id, .. }
            | ProcedureScope::Repository { repository_id } => AtomScope::Repository {
                repository_instance_id: repository_id,
            },
            ProcedureScope::Global => AtomScope::Global,
        }),
        ProposalPayload::CoreMembership(payload) => {
            let CoreMembershipProposalPayload::Create {
                atom_revision_id, ..
            } = payload.as_ref()
            else {
                return Err(HumanGovernanceError::InvalidInput);
            };
            view.atom_revisions
                .get(atom_revision_id)
                .map(|atom| atom.scope.clone())
                .ok_or(HumanGovernanceError::InvalidInput)
        }
        ProposalPayload::ReservedTarget { .. } => Err(HumanGovernanceError::InvalidInput),
    }
}

fn support_atom_acceptance(
    snapshot: &ProjectionSnapshot,
    view: &SemanticCurrentView,
    proposal: &RevisionProposal,
) -> Result<Option<SupportAtomAcceptance>, crate::semantic::SemanticServiceError> {
    let Some(ProposalTargetId::Atom(atom_id)) = proposal.target_id else {
        return Ok(None);
    };
    let Some(base_revision_id) = proposal.base_revision_id else {
        return Ok(None);
    };
    let Some(atom) = view.atoms.get(&atom_id) else {
        return Err(crate::semantic::SemanticServiceError::BaseConflict);
    };
    if atom.revision_id != base_revision_id {
        return Err(crate::semantic::SemanticServiceError::BaseConflict);
    }
    if atom.scope != AtomScope::Global {
        return Ok(None);
    }
    select_support_atom_acceptance(snapshot, proposal).map(Some)
}

fn acceptance_capture_scope(
    proposal: &RevisionProposal,
    view: &SemanticCurrentView,
) -> Result<AcceptanceCaptureScope, HumanGovernanceError> {
    let scope = proposal_scope(proposal, view)?;
    let mut capture = AcceptanceCaptureScope {
        task_id: None,
        repository_id: None,
        worktree_id: None,
    };
    match scope {
        AtomScope::Task { task_id } => capture.task_id = Some(task_id),
        AtomScope::Repository {
            repository_instance_id,
        } => capture.repository_id = Some(repository_instance_id),
        AtomScope::Worktree {
            repository_instance_id,
            worktree_instance_id,
        } => {
            capture.repository_id = Some(repository_instance_id);
            capture.worktree_id = Some(worktree_instance_id);
        }
        AtomScope::Global => {}
    }
    if let ProposalPayload::Procedure(payload) = &proposal.payload
        && let ProcedureScope::Worktree {
            repository_id,
            worktree_id,
        } = payload.draft().scope
    {
        capture.repository_id = Some(repository_id);
        capture.worktree_id = Some(worktree_id);
    }
    Ok(capture)
}

async fn authored_creation_scope_current(
    service: &crate::HumanGovernanceService,
    snapshot: &ProjectionSnapshot,
    proposal: &RevisionProposal,
) -> Result<bool, HumanGovernanceError> {
    match HumanAtomAuthoring::creation_scope_for_review(proposal) {
        Some(scope) => service.web_creation_scope_accessible(snapshot, scope).await,
        None => Ok(true),
    }
}

fn acceptance_capture_input(
    proposal: &RevisionProposal,
    payload: &str,
    record_id: &str,
    scope: AcceptanceCaptureScope,
) -> Result<CaptureRecordInput, HumanGovernanceError> {
    human_acceptance_capture_input(proposal, payload, record_id, scope, false)
}

fn human_acceptance_capture_input(
    proposal: &RevisionProposal,
    payload: &str,
    record_id: &str,
    scope: AcceptanceCaptureScope,
    web: bool,
) -> Result<CaptureRecordInput, HumanGovernanceError> {
    let (source, manifest) = if web {
        ("web-acceptance", WEB_ACCEPTANCE_EVENT_MANIFEST_REF)
    } else {
        ("tui-acceptance", TUI_ACCEPTANCE_EVENT_MANIFEST_REF)
    };
    human_capture_input(
        (proposal.proposal_id, proposal.proposal_revision_id),
        payload,
        record_id,
        scope,
        (source, manifest),
    )
}

fn human_capture_input(
    (proposal_id, revision): (RevisionProposalId, RevisionId),
    payload: &str,
    record_id: &str,
    scope: AcceptanceCaptureScope,
    (source, manifest): (&str, &str),
) -> Result<CaptureRecordInput, HumanGovernanceError> {
    Ok(CaptureRecordInput {
        source_local_evidence: None,
        spool_record_id: Some(record_id.into()),
        source_observation_id_hint: None,
        source_instance_id: format!("{source}:{proposal_id}"),
        source_revision: revision.to_string(),
        source_record_identity: Some(record_id.into()),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: manifest.into(),
        source_ref: proposal_id.to_string(),
        session_ref: "human-governance".into(),
        turn_ref: None,
        tool_ref: None,
        source_sequence: 1,
        source_sequence_origin: Some(1),
        task_id: scope.task_id.map(|value| value.to_string()),
        repository_instance_id: scope.repository_id.map(|value| value.to_string()),
        worktree_instance_id: scope.worktree_id.map(|value| value.to_string()),
        source_byte_range: None,
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: None,
        observation_role: ObservationRole::Message,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            pairing_role: ObservationRole::Message,
            field_provenance: Vec::new(),
            adapter_manifest_ref: manifest.into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: Vec::new(),
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: SourceRole::User,
        content_trust: ContentTrust::UserStatement,
        capture_completeness: CaptureCompleteness::Complete,
        surface_eligible: !is_human_authoring_manifest(manifest),
        adapter_revision: 1,
        adapter_manifest_ref: manifest.into(),
        eligible_event_manifest_ref: manifest.into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: Some(now_us()?),
        event_time_provenance: None,
        raw_payload: payload.as_bytes().to_vec(),
    })
}

fn acceptance_context(
    proposal: &RevisionProposal,
    view: &SemanticCurrentView,
    verified: &crate::capture::VerifiedCapture,
) -> Result<AtomAcceptanceContext, HumanGovernanceError> {
    let observation = Box::new(verified.observation.clone());
    let receipt = Box::new(verified.receipt.clone());
    Ok(match proposal_scope(proposal, view)? {
        AtomScope::Task { .. } => AtomAcceptanceContext::TaskTui {
            observation,
            receipt,
        },
        AtomScope::Repository { .. } | AtomScope::Worktree { .. } => {
            AtomAcceptanceContext::RepositoryTui {
                observation,
                receipt,
            }
        }
        AtomScope::Global => AtomAcceptanceContext::GlobalTui {
            observation,
            receipt,
        },
    })
}

fn reauthorization_acceptance_context(
    proposal: &RevisionProposal,
    view: &SemanticCurrentView,
    verified: &crate::capture::VerifiedCapture,
    canonical_payload: String,
) -> Result<AtomAcceptanceContext, HumanGovernanceError> {
    let scope = proposal_scope(proposal, view)?;
    let authorized_scope_ceiling = match scope {
        AtomScope::Task { task_id } => AtomScope::Task { task_id },
        AtomScope::Repository {
            repository_instance_id,
        }
        | AtomScope::Worktree {
            repository_instance_id,
            ..
        } => AtomScope::Repository {
            repository_instance_id,
        },
        AtomScope::Global => AtomScope::Global,
    };
    Ok(AtomAcceptanceContext::ReauthorizationTui {
        observation: Box::new(verified.observation.clone()),
        receipt: Box::new(verified.receipt.clone()),
        authorized_scope_ceiling,
        canonical_payload,
    })
}

fn claim_isolated_record(
    spool: &DurableSpool,
    record_id: &str,
    limit: usize,
) -> Result<Option<evertrace_capture::SealedSegment>, HumanGovernanceError> {
    let mut matching = spool
        .isolated_segments(limit)
        .map_err(|_| HumanGovernanceError::Store)?
        .into_iter()
        .filter(|segment| {
            segment.frames().len() == 1 && segment.frames()[0].record.spool_record_id == record_id
        });
    let result = matching.next();
    if matching.next().is_some() {
        return Err(HumanGovernanceError::Store);
    }
    Ok(result)
}

fn current_procedure(
    snapshot: &ProjectionSnapshot,
    proposal: &RevisionProposal,
) -> Result<
    (
        Option<evertrace_domain::procedure::ProcedureRevision>,
        Option<ProcedurePublicationState>,
    ),
    HumanGovernanceError,
> {
    let Some(ProposalTargetId::Procedure(procedure_id)) = proposal.target_id else {
        return Ok((None, None));
    };
    let base = proposal
        .base_revision_id
        .ok_or(HumanGovernanceError::InvalidInput)?;
    let mut found = None;
    for row in snapshot.data_rows().filter(|row| {
        row.object_kind.as_deref() == Some("procedure_revision")
            && row.object_id.as_deref() == Some(&procedure_id.to_string())
            && row.current_revision_id.as_deref() == Some(&base.to_string())
    }) {
        let payload: JournalPayload = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let JournalPayload::ProcedureRevisionRecorded(value) = payload else {
            return Err(HumanGovernanceError::Store);
        };
        let publication = match row.publication_state.as_deref() {
            Some("active_probationary") => ProcedurePublicationState::ActiveProbationary,
            Some("review_hold") => ProcedurePublicationState::ReviewHold,
            Some("active_stable") => ProcedurePublicationState::ActiveStable,
            Some("suspended") => ProcedurePublicationState::Suspended,
            Some("rolled_back") => ProcedurePublicationState::RolledBack,
            Some("superseded") => ProcedurePublicationState::Superseded,
            _ => return Err(HumanGovernanceError::Store),
        };
        if found.replace((*value, publication)).is_some() {
            return Err(HumanGovernanceError::Store);
        }
    }
    found
        .map(|value| (Some(value.0), Some(value.1)))
        .ok_or(HumanGovernanceError::InvalidInput)
}

fn inactive_unchanged_procedure(
    snapshot: &ProjectionSnapshot,
    proposal: &RevisionProposal,
) -> Result<bool, HumanGovernanceError> {
    let ProposalPayload::Procedure(payload) = &proposal.payload else {
        return Ok(false);
    };
    if !matches!(
        payload.as_ref(),
        evertrace_domain::semantic::ProcedureProposalPayload::Replace { .. }
    ) {
        return Ok(false);
    }
    let (current, publication) = current_procedure(snapshot, proposal)?;
    Ok(current
        .as_ref()
        .is_some_and(|current| current.draft == *payload.draft())
        && !matches!(
            publication,
            Some(
                ProcedurePublicationState::ActiveProbationary
                    | ProcedurePublicationState::ActiveStable
            )
        ))
}

fn prepare_edit_candidate(
    view: &SemanticCurrentView,
    original: &RevisionProposal,
    edited_payload: ProposalPayload,
    command_id: CommandId,
    created_at_us: i64,
    effective_config_hash: [u8; 32],
    identity: Option<(RevisionProposalId, RevisionId)>,
) -> Result<(ProposalEditIntent, JournalCommand), HumanGovernanceError> {
    let (proposal_id, proposal_revision_id) =
        identity.unwrap_or_else(|| (RevisionProposalId::new_v7(), RevisionId::new_v7()));
    let request = SubmitProposalRequest {
        target_kind: original.target_kind,
        target_id: original.target_id,
        base_revision_id: original.base_revision_id,
        operation: original.operation,
        payload: edited_payload,
        evidence_refs: original.evidence_refs.clone(),
        source_cohort_refs: original.source_cohort_refs.clone(),
        eligibility: ProposalEligibility::ManualRequired,
        created_by: ProposalCreatedBy::User,
    };
    let context = ProposalCommandContext {
        command_id,
        occurred_at_us: created_at_us,
        effective_config_hash,
        algorithm_revision: ALGORITHM_REVISION.into(),
    };
    let ProposalResolution::Revision { value, command } = RevisionProposalService
        .submit_with_identity(view, context, request, proposal_id, proposal_revision_id)
        .map_err(|_| HumanGovernanceError::InvalidInput)?
    else {
        return Err(HumanGovernanceError::InvalidInput);
    };
    let intent = ProposalEditIntent::new(original, *value);
    intent.validate(original)?;
    Ok((intent, command))
}

struct EditedAcceptanceInput<'a> {
    snapshot: &'a ProjectionSnapshot,
    view: &'a SemanticCurrentView,
    original: &'a RevisionProposal,
    reviewed: &'a RevisionProposal,
    acceptance: AtomAcceptanceContext,
    command_context: ProposalCommandContext,
    effective_config_hash: [u8; 32],
    global_promotion: &'a GlobalPromotionConfig,
    support: Option<&'a crate::semantic::SupportAtomAcceptance>,
}

struct EditedAcceptanceCommand {
    superseded: Box<RevisionProposal>,
    accepted_revision: RevisionId,
    events: Vec<evertrace_store::JournalEventDraft>,
}

fn compose_edited_acceptance(
    input: EditedAcceptanceInput<'_>,
) -> Result<EditedAcceptanceCommand, HumanGovernanceError> {
    let ProposalResolution::Revision {
        value: superseded,
        command: supersede,
    } = RevisionProposalService
        .revise_status(
            input.view,
            input.command_context.clone(),
            input.original.proposal_id,
            ProposalStatus::Superseded,
            Vec::new(),
            Some("human_edit_superseded".into()),
        )
        .map_err(|_| HumanGovernanceError::InvalidInput)?
    else {
        return Err(HumanGovernanceError::Store);
    };
    let (rebuilt, pending) = prepare_edit_candidate(
        input.view,
        input.original,
        input.reviewed.payload.clone(),
        input.command_context.command_id,
        input.reviewed.created_at_us,
        input.effective_config_hash,
        Some((
            input.reviewed.proposal_id,
            input.reviewed.proposal_revision_id,
        )),
    )?;
    if rebuilt.new_proposal != *input.reviewed {
        return Err(HumanGovernanceError::Store);
    }
    let mut edited_view = input.view.clone();
    edited_view
        .proposals
        .insert(input.reviewed.proposal_id, input.reviewed.clone());
    edited_view
        .proposal_revisions
        .insert(input.reviewed.proposal_revision_id, input.reviewed.clone());
    let (accepted_revision, accepted) = match &input.reviewed.payload {
        ProposalPayload::Atom(_) => {
            let accepted = if let Some(support) = input.support {
                RevisionProposalService.accept_support_linked_edited(
                    &edited_view,
                    input.command_context,
                    input.reviewed.proposal_id,
                    input.acceptance,
                    input.original,
                    support,
                )
            } else {
                RevisionProposalService.accept_edited(
                    &edited_view,
                    input.command_context,
                    input.reviewed.proposal_id,
                    input.acceptance,
                    input.original,
                )
            }
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
            (accepted.proposal.proposal_revision_id, accepted.command)
        }
        ProposalPayload::Procedure(_) => {
            let (current, publication) = current_procedure(input.snapshot, input.reviewed)?;
            let accepted = accept_procedure_edited(
                &edited_view,
                input.command_context,
                input.reviewed.proposal_id,
                EditedProcedureAcceptance {
                    source: input.acceptance,
                    original: input.original,
                },
                current.as_ref(),
                publication,
                input.global_promotion,
            )
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
            match accepted {
                ProcedureAcceptanceResolution::Command {
                    proposal, command, ..
                }
                | ProcedureAcceptanceResolution::AcceptedExisting { proposal, command } => {
                    (proposal.proposal_revision_id, command)
                }
                ProcedureAcceptanceResolution::NoDelta => {
                    return Err(HumanGovernanceError::Store);
                }
            }
        }
        ProposalPayload::CoreMembership(_) | ProposalPayload::ReservedTarget { .. } => {
            return Err(HumanGovernanceError::InvalidInput);
        }
    };
    let mut events = supersede.events().to_vec();
    events.extend(pending.events().iter().cloned());
    events.extend(accepted.events().iter().cloned());
    Ok(EditedAcceptanceCommand {
        superseded,
        accepted_revision,
        events,
    })
}

fn read_edit_intent(
    verified: &crate::capture::VerifiedCapture,
    cas: &CasStore,
    original: &RevisionProposal,
) -> Result<ProposalEditIntent, HumanGovernanceError> {
    try_read_edit_intent(verified, cas, original)?.ok_or(HumanGovernanceError::Store)
}

fn try_read_edit_intent(
    verified: &crate::capture::VerifiedCapture,
    cas: &CasStore,
    original: &RevisionProposal,
) -> Result<Option<ProposalEditIntent>, HumanGovernanceError> {
    let digest =
        CasDigest::from_str(&verified.body.cas_ref).map_err(|_| HumanGovernanceError::Store)?;
    let bytes = cas.read(&digest).map_err(|_| HumanGovernanceError::Store)?;
    let Ok(value) = std::str::from_utf8(&bytes) else {
        return Ok(None);
    };
    let Ok(intent) = ProposalEditIntent::from_toml(value) else {
        return Ok(None);
    };
    if intent.canonical_toml(original)?.as_bytes() != bytes.as_slice() {
        return Err(HumanGovernanceError::Store);
    }
    Ok(Some(intent))
}

fn read_reauthorization_intent(
    verified: &crate::capture::VerifiedCapture,
    cas: &CasStore,
    deletion: &ObjectDeletionLedgerEvent,
    reviewed: &RevisionProposal,
) -> Result<ObjectReauthorizationIntent, HumanGovernanceError> {
    let digest =
        CasDigest::from_str(&verified.body.cas_ref).map_err(|_| HumanGovernanceError::Store)?;
    let bytes = cas.read(&digest).map_err(|_| HumanGovernanceError::Store)?;
    let value = std::str::from_utf8(&bytes).map_err(|_| HumanGovernanceError::Store)?;
    let intent =
        ObjectReauthorizationIntent::from_toml(value).ok_or(HumanGovernanceError::Store)?;
    let canonical = intent
        .canonical_toml(deletion, reviewed)
        .ok_or(HumanGovernanceError::Store)?;
    if canonical.as_bytes() != bytes.as_slice() {
        return Err(HumanGovernanceError::Store);
    }
    Ok(intent)
}

struct ReservedReauthorizationIntent {
    deletion: ObjectDeletionLedgerEvent,
    intent: ObjectReauthorizationIntent,
}

fn try_read_reauthorization_intent(
    verified: &crate::capture::VerifiedCapture,
    cas: &CasStore,
    snapshot: &ProjectionSnapshot,
    reviewed: &RevisionProposal,
) -> Result<Option<ReservedReauthorizationIntent>, HumanGovernanceError> {
    let digest =
        CasDigest::from_str(&verified.body.cas_ref).map_err(|_| HumanGovernanceError::Store)?;
    let bytes = cas.read(&digest).map_err(|_| HumanGovernanceError::Store)?;
    let Ok(value) = std::str::from_utf8(&bytes) else {
        return Ok(None);
    };
    let Some(intent) = ObjectReauthorizationIntent::from_toml(value) else {
        return Ok(None);
    };
    let ledger = ObjectDeletionCurrentView::from_snapshot(snapshot)
        .map_err(|_| HumanGovernanceError::Store)?;
    let deletion = ledger
        .events
        .get(&intent.deletion.target)
        .filter(|event| event.deletion_generation == intent.deletion.deletion_generation)
        .cloned()
        .ok_or(HumanGovernanceError::Store)?;
    let canonical = intent
        .canonical_toml(&deletion, reviewed)
        .ok_or(HumanGovernanceError::Store)?;
    if canonical.as_bytes() != bytes.as_slice() {
        return Err(HumanGovernanceError::Store);
    }
    Ok(Some(ReservedReauthorizationIntent { deletion, intent }))
}

fn accepted_edit_retry<'a>(
    snapshot: &ProjectionSnapshot,
    view: &'a SemanticCurrentView,
    original: &RevisionProposal,
    edited_payload: &ProposalPayload,
) -> Result<Option<&'a RevisionProposal>, HumanGovernanceError> {
    let mut evidence = None;
    for accepted in view.proposals.values() {
        if accepted.status != ProposalStatus::Accepted {
            continue;
        }
        let Some(acceptance) = accepted.acceptance.as_ref() else {
            continue;
        };
        let Some(reviewed) = view
            .proposal_revisions
            .get(&acceptance.reviewed_proposal_revision_id)
        else {
            continue;
        };
        let intent = ProposalEditIntent::new(original, reviewed.clone());
        if reviewed.payload != *edited_payload || intent.validate(original).is_err() {
            continue;
        }
        let ProposalAcceptanceAuthority::TuiAcceptance {
            user_source_observation_ref,
            ..
        } = &acceptance.authority_basis
        else {
            continue;
        };
        if acceptance.acceptance_event_ref != user_source_observation_ref.to_string() {
            continue;
        }
        if evidence.is_none() {
            evidence = Some(
                RecoveryEvidenceCurrentView::from_snapshot(snapshot)
                    .map_err(|_| HumanGovernanceError::Store)?,
            );
        }
        let evidence = evidence.as_ref().ok_or(HumanGovernanceError::Store)?;
        let observation = evidence
            .observation(*user_source_observation_ref)
            .ok_or(HumanGovernanceError::Store)?;
        let receipt = evidence
            .receipt_for_observation(*user_source_observation_ref)
            .ok_or(HumanGovernanceError::Store)?;
        if observation.source_observation_id == *user_source_observation_ref
            && receipt.eligible_event_manifest_ref == TUI_ACCEPTANCE_EVENT_MANIFEST_REF
            && receipt.source_ref == original.proposal_id.to_string()
            && receipt.source_revision.as_str() == original.proposal_revision_id.to_string()
        {
            return Ok(Some(accepted));
        }
    }
    Ok(None)
}

fn accepted_reauthorization_retry<'a>(
    snapshot: &ProjectionSnapshot,
    view: &'a SemanticCurrentView,
    original: &RevisionProposal,
) -> Result<Option<&'a RevisionProposal>, HumanGovernanceError> {
    let deletion = ObjectDeletionCandidateAdmissionView::from_snapshot(snapshot)
        .map_err(|_| HumanGovernanceError::Store)?
        .classify_proposal(original)
        .map_err(|_| HumanGovernanceError::Store)?
        .representative_historical_deletion()
        .cloned();
    let Some(deletion) = deletion else {
        return Ok(None);
    };
    let mut evidence = None;
    let mut matched = None;
    for accepted in view.proposals.values() {
        if accepted.status != ProposalStatus::Accepted {
            continue;
        }
        let Some(acceptance) = accepted.acceptance.as_ref() else {
            continue;
        };
        let Some(reviewed) = view
            .proposal_revisions
            .get(&acceptance.reviewed_proposal_revision_id)
        else {
            continue;
        };
        if reviewed != original {
            continue;
        }
        let ProposalAcceptanceAuthority::TuiAcceptance {
            user_source_observation_ref,
            ..
        } = &acceptance.authority_basis
        else {
            continue;
        };
        if acceptance.acceptance_event_ref != user_source_observation_ref.to_string() {
            continue;
        }
        let intent = ObjectReauthorizationIntent::new(&deletion, reviewed)
            .ok_or(HumanGovernanceError::Store)?;
        let canonical = intent
            .canonical_toml(&deletion, reviewed)
            .ok_or(HumanGovernanceError::Store)?;
        if evidence.is_none() {
            evidence = Some(
                RecoveryEvidenceCurrentView::from_snapshot(snapshot)
                    .map_err(|_| HumanGovernanceError::Store)?,
            );
        }
        let evidence = evidence.as_ref().ok_or(HumanGovernanceError::Store)?;
        let observation = evidence
            .observation(*user_source_observation_ref)
            .ok_or(HumanGovernanceError::Store)?;
        let receipt = evidence
            .receipt_for_observation(*user_source_observation_ref)
            .ok_or(HumanGovernanceError::Store)?;
        let expected_fingerprint = hex(&payload_fingerprint(1, canonical.as_bytes(), None)
            .map_err(|_| HumanGovernanceError::Store)?);
        if observation.source_observation_id != *user_source_observation_ref
            || observation.payload_fingerprint != expected_fingerprint
            || receipt.eligible_event_manifest_ref != TUI_ACCEPTANCE_EVENT_MANIFEST_REF
            || receipt.source_ref != reviewed.proposal_id.to_string()
            || receipt.source_revision.as_str() != reviewed.proposal_revision_id.to_string()
        {
            continue;
        }
        if matched.replace(accepted).is_some() {
            return Err(HumanGovernanceError::Store);
        }
    }
    Ok(matched)
}

fn verify_edit_acceptance_cohort(
    payloads: &[JournalPayload],
    verified: &crate::capture::VerifiedCapture,
    original: &RevisionProposal,
    intent: &ProposalEditIntent,
) -> Result<(Box<RevisionProposal>, Box<RevisionProposal>), HumanGovernanceError> {
    validate_edit_capture(verified, original, intent)?;
    let expected_watermark = SourceIngestWatermark {
        source_instance_id: verified.body.source_instance_id.clone(),
        source_revision: verified.body.source_revision.clone(),
        source_sequence: 1,
        confirmed_prefix_digest: None,
        earlier_prefix: None,
    };
    if payloads
        .iter()
        .filter(|payload| matches!(payload, JournalPayload::SourceReceiptRecorded(value) if value.as_ref() == &verified.receipt))
        .count()
        != 1
        || payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::SourceObservationRecorded(value) if value.as_ref() == &verified.observation))
            .count()
            != 1
        || payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::SourceIngestWatermark(value) if value == &expected_watermark))
            .count()
            != 1
        || payloads
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
        return Err(HumanGovernanceError::Store);
    }
    let proposal_events = payloads
        .iter()
        .enumerate()
        .filter_map(|(index, payload)| match payload {
            JournalPayload::RevisionProposalRecorded(value)
                if value.proposal_id == original.proposal_id
                    || value.proposal_id == intent.new_proposal.proposal_id =>
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
        .filter(|(_, value)| **value == intent.new_proposal)
        .collect::<Vec<_>>();
    let validating = proposal_events
        .iter()
        .filter(|(_, value)| {
            value.proposal_id == intent.new_proposal.proposal_id
                && value.status == ProposalStatus::Validating
        })
        .collect::<Vec<_>>();
    let accepted = proposal_events
        .iter()
        .filter(|(_, value)| {
            value.proposal_id == intent.new_proposal.proposal_id
                && value.status == ProposalStatus::Accepted
        })
        .collect::<Vec<_>>();
    let ([superseded], [pending], [validating], [accepted]) = (
        superseded.as_slice(),
        pending.as_slice(),
        validating.as_slice(),
        accepted.as_slice(),
    ) else {
        return Err(HumanGovernanceError::Store);
    };
    if proposal_events.len() != 4
        || !(superseded.0 < pending.0 && pending.0 < validating.0 && validating.0 < accepted.0)
        || original.validate_successor(superseded.1).is_err()
        || intent
            .new_proposal
            .validate_successor(validating.1)
            .is_err()
        || validating.1.validate_successor(accepted.1).is_err()
        || accepted.1.acceptance.as_ref().is_none_or(|acceptance| {
            acceptance.reviewed_proposal_revision_id != intent.new_proposal.proposal_revision_id
                || acceptance.reviewed_fingerprint != intent.new_proposal.fingerprint
                || acceptance.acceptance_event_ref
                    != verified.observation.source_observation_id.to_string()
        })
    {
        return Err(HumanGovernanceError::Store);
    }
    let acceptance = accepted
        .1
        .acceptance
        .as_ref()
        .ok_or(HumanGovernanceError::Store)?;
    match &acceptance.accepted_target {
        AcceptedProposalTarget::Atom {
            atom_id,
            atom_revision_id,
            ..
        } => {
            if payloads
                .iter()
                .filter(|payload| {
                    matches!(payload, JournalPayload::AtomRecorded(atom)
                    if atom.atom_id == *atom_id
                        && atom.revision_id == *atom_revision_id
                        && atom.accepted_proposal_id == Some(accepted.1.proposal_id)
                        && atom.accepted_proposal_revision_id
                            == Some(accepted.1.proposal_revision_id))
                })
                .count()
                != 1
            {
                return Err(HumanGovernanceError::Store);
            }
        }
        AcceptedProposalTarget::Procedure {
            procedure_id,
            procedure_revision_id,
            auto_full_audit,
        } => {
            let ProposalPayload::Procedure(procedure_payload) = &accepted.1.payload else {
                return Err(HumanGovernanceError::Store);
            };
            if auto_full_audit.is_some() {
                return Err(HumanGovernanceError::Store);
            }
            let materialized = payloads
                .iter()
                .filter_map(|payload| match payload {
                    JournalPayload::ProcedureRevisionRecorded(value)
                        if value.procedure_id == *procedure_id
                            && value.revision_id == *procedure_revision_id =>
                    {
                        Some(value.as_ref())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            match materialized.as_slice() {
                [procedure]
                    if procedure.draft == *procedure_payload.draft()
                        && match accepted.1.operation {
                            ProposalOperation::Create => {
                                accepted.1.target_id.is_none()
                                    && accepted.1.base_revision_id.is_none()
                                    && procedure.parent_revision_id.is_none()
                                    && procedure.revision_generation == 1
                            }
                            ProposalOperation::Replace => {
                                accepted.1.target_id
                                    == Some(ProposalTargetId::Procedure(*procedure_id))
                                    && procedure.parent_revision_id == accepted.1.base_revision_id
                            }
                            _ => false,
                        } => {}
                [] if accepted.1.operation == ProposalOperation::Replace
                    && accepted.1.target_id == Some(ProposalTargetId::Procedure(*procedure_id))
                    && accepted.1.base_revision_id == Some(*procedure_revision_id) => {}
                _ => return Err(HumanGovernanceError::Store),
            }
        }
        AcceptedProposalTarget::CoreMembership { .. } => {
            return Err(HumanGovernanceError::Store);
        }
    }
    Ok((Box::new(superseded.1.clone()), Box::new(accepted.1.clone())))
}

fn validate_current_edit_cohort(
    snapshot: &ProjectionSnapshot,
    view: &SemanticCurrentView,
    superseded: &RevisionProposal,
    accepted: &RevisionProposal,
) -> Result<(), HumanGovernanceError> {
    if view.proposals.get(&superseded.proposal_id) != Some(superseded)
        || view.proposals.get(&accepted.proposal_id) != Some(accepted)
    {
        return Err(HumanGovernanceError::Store);
    }
    match &accepted
        .acceptance
        .as_ref()
        .ok_or(HumanGovernanceError::Store)?
        .accepted_target
    {
        AcceptedProposalTarget::Atom {
            atom_id,
            atom_revision_id,
            ..
        } if view
            .atoms
            .get(atom_id)
            .is_some_and(|atom| atom.revision_id == *atom_revision_id)
            && view.atom_revisions.get(atom_revision_id) == view.atoms.get(atom_id) =>
        {
            Ok(())
        }
        AcceptedProposalTarget::Procedure {
            procedure_id,
            procedure_revision_id,
            auto_full_audit: None,
        } => {
            let ProposalPayload::Procedure(payload) = &accepted.payload else {
                return Err(HumanGovernanceError::Store);
            };
            let rows = snapshot
                .data_rows()
                .filter(|row| {
                    row.object_kind.as_deref() == Some("procedure_revision")
                        && row.object_id.as_deref() == Some(&procedure_id.to_string())
                        && row.current_revision_id.as_deref()
                            == Some(&procedure_revision_id.to_string())
                })
                .collect::<Vec<_>>();
            let [row] = rows.as_slice() else {
                return Err(HumanGovernanceError::Store);
            };
            let JournalPayload::ProcedureRevisionRecorded(procedure) = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(HumanGovernanceError::Store)?,
            )
            .map_err(|_| HumanGovernanceError::Store)?
            else {
                return Err(HumanGovernanceError::Store);
            };
            if procedure.procedure_id != *procedure_id
                || procedure.revision_id != *procedure_revision_id
                || procedure.draft != *payload.draft()
            {
                return Err(HumanGovernanceError::Store);
            }
            Ok(())
        }
        _ => Err(HumanGovernanceError::Store),
    }
}

fn web_disposition_status(waiting_on: Option<ProposalWaitingOn>) -> (ProposalStatus, &'static str) {
    if waiting_on.is_some() {
        (ProposalStatus::Deferred, "web_deferred")
    } else {
        (ProposalStatus::Rejected, "web_rejected")
    }
}

fn web_disposition_cause(frontier: u64, digest: &str) -> String {
    format!("web-proposal-review:{frontier}:{digest}")
}

fn web_acceptance_outcome(
    committed: &evertrace_store::CommittedCommand,
    proposal: &RevisionProposal,
    matches_intent: impl Fn(&WebAcceptanceIntent) -> bool,
) -> Option<HumanActionOutcome> {
    committed
        .payloads
        .iter()
        .zip(&committed.event_ids)
        .find_map(|(payload, event)| {
            let JournalPayload::RevisionProposalRecorded(value) = payload else {
                return None;
            };
            if valid_web_accepted_candidate(&committed.payloads, proposal, value, &matches_intent) {
                return Some(HumanActionOutcome::Applied {
                    current_revision_ref: value.proposal_revision_id.to_string(),
                    audit_event_ref: event.clone(),
                });
            }
            None
        })
}

fn valid_web_accepted_candidate(
    payloads: &[JournalPayload],
    original: &RevisionProposal,
    accepted: &RevisionProposal,
    matches_intent: impl Fn(&WebAcceptanceIntent) -> bool,
) -> bool {
    let Some(audit) = &accepted.acceptance else {
        return false;
    };
    let ProposalAcceptanceAuthority::WebAcceptance { intent, .. } = &audit.authority_basis else {
        return false;
    };
    if accepted.status != ProposalStatus::Accepted || !matches_intent(intent) {
        return false;
    }
    if intent.atom_edit.is_none() {
        return accepted.proposal_id == original.proposal_id
            && audit.reviewed_proposal_revision_id == original.proposal_revision_id
            && audit.reviewed_fingerprint == original.fingerprint;
    }
    payloads.iter().any(|payload| matches!(payload, JournalPayload::RevisionProposalRecorded(edited)
        if edited.proposal_id == accepted.proposal_id && edited.proposal_revision_id == audit.reviewed_proposal_revision_id
            && edited.fingerprint == audit.reviewed_fingerprint && intent.matches_reviewed(original, edited)))
}

fn verify_acceptance_payload_cohort(
    payloads: &[JournalPayload],
    verified: &crate::capture::VerifiedCapture,
    reviewed: &RevisionProposal,
    expected_web_intent: Option<&WebAcceptanceIntent>,
) -> Result<RevisionProposal, HumanGovernanceError> {
    let mut receipt_count = 0;
    let mut observation_count = 0;
    let mut watermark_count = 0;
    for payload in payloads {
        match payload {
            JournalPayload::SourceReceiptRecorded(value) if value.as_ref() == &verified.receipt => {
                receipt_count += 1;
            }
            JournalPayload::SourceObservationRecorded(value)
                if value.as_ref() == &verified.observation =>
            {
                observation_count += 1;
            }
            JournalPayload::SourceIngestWatermark(value)
                if value
                    == &SourceIngestWatermark {
                        source_instance_id: verified.body.source_instance_id.clone(),
                        source_revision: verified.body.source_revision.clone(),
                        source_sequence: 1,
                        confirmed_prefix_digest: None,
                        earlier_prefix: None,
                    } =>
            {
                watermark_count += 1;
            }
            _ => {}
        }
    }
    if receipt_count != 1 || observation_count != 1 || watermark_count != 1 {
        return Err(HumanGovernanceError::Store);
    }
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
        return Err(HumanGovernanceError::Store);
    }
    let accepted = payloads
        .iter()
        .filter_map(|payload| {
            let JournalPayload::RevisionProposalRecorded(value) = payload else {
                return None;
            };
            let audit = value.acceptance.as_ref()?;
            let source = verified.observation.source_observation_id;
            if value.status != ProposalStatus::Accepted
                || audit.acceptance_event_ref != source.to_string()
            {
                return None;
            }
            let matches = match (expected_web_intent, &audit.authority_basis) {
                (
                    Some(expected),
                    ProposalAcceptanceAuthority::WebAcceptance {
                        user_source_observation_ref,
                        ..
                    },
                ) => {
                    *user_source_observation_ref == source
                        && valid_web_accepted_candidate(payloads, reviewed, value, |saved| {
                            saved == expected
                        })
                }
                (
                    None,
                    ProposalAcceptanceAuthority::TuiAcceptance {
                        user_source_observation_ref,
                        ..
                    },
                ) => {
                    *user_source_observation_ref == source
                        && value.proposal_id == reviewed.proposal_id
                        && audit.reviewed_proposal_revision_id == reviewed.proposal_revision_id
                        && audit.reviewed_fingerprint == reviewed.fingerprint
                }
                _ => false,
            };
            matches.then_some(value.as_ref())
        })
        .collect::<Vec<_>>();
    let [accepted] = accepted.as_slice() else {
        return Err(HumanGovernanceError::Store);
    };
    Ok((*accepted).clone())
}

fn verify_reauthorization_cohort(
    payloads: &[JournalPayload],
    verified: &crate::capture::VerifiedCapture,
    deletion: &ObjectDeletionLedgerEvent,
    reviewed: &RevisionProposal,
) -> Result<RevisionProposal, HumanGovernanceError> {
    let intent =
        ObjectReauthorizationIntent::new(deletion, reviewed).ok_or(HumanGovernanceError::Store)?;
    let canonical = intent
        .canonical_toml(deletion, reviewed)
        .ok_or(HumanGovernanceError::Store)?;
    validate_reauthorization_capture(verified, reviewed, &canonical)?;
    verify_acceptance_payload_cohort(payloads, verified, reviewed, None)
}

fn validate_acceptance_capture(
    verified: &crate::capture::VerifiedCapture,
    reviewed: &RevisionProposal,
) -> Result<(), HumanGovernanceError> {
    let canonical = tui_acceptance_event_payload(
        reviewed.proposal_id,
        reviewed.proposal_revision_id,
        &reviewed.fingerprint,
    );
    validate_acceptance_capture_payload(verified, reviewed, &canonical, "tui-accept")
}

fn validate_edit_capture(
    verified: &crate::capture::VerifiedCapture,
    original: &RevisionProposal,
    intent: &ProposalEditIntent,
) -> Result<(), HumanGovernanceError> {
    intent.validate(original)?;
    let canonical = intent.canonical_toml(original)?;
    validate_acceptance_capture_payload(verified, original, &canonical, "tui-accept")
}

fn validate_reauthorization_capture(
    verified: &crate::capture::VerifiedCapture,
    source: &RevisionProposal,
    canonical: &str,
) -> Result<(), HumanGovernanceError> {
    validate_acceptance_capture_payload(verified, source, canonical, "tui-reauthorize")
}

fn validate_acceptance_capture_payload(
    verified: &crate::capture::VerifiedCapture,
    source: &RevisionProposal,
    canonical: &str,
    record_prefix: &str,
) -> Result<(), HumanGovernanceError> {
    if !tui_acceptance_capture_matches(
        source,
        canonical,
        record_prefix,
        &verified.receipt,
        &verified.observation,
    ) {
        return Err(HumanGovernanceError::Store);
    }
    Ok(())
}

pub(crate) fn command_context(
    request_id: RequestId,
    effective_config_hash: [u8; 32],
) -> Result<ProposalCommandContext, HumanGovernanceError> {
    Ok(ProposalCommandContext {
        command_id: CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?,
        occurred_at_us: now_us()?,
        effective_config_hash,
        algorithm_revision: ALGORITHM_REVISION.into(),
    })
}

pub(crate) fn now_us() -> Result<i64, HumanGovernanceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_micros()).ok())
        .ok_or(HumanGovernanceError::Store)
}
