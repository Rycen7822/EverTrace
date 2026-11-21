//! Human proposals share one protected authoring reservation and the normal proposal compiler.
use super::*;
use evertrace_domain::semantic::{
    Atom, HumanAtomAuthoring, HumanAuthoringTarget, ProposalTargetKind,
};

impl HumanAcceptanceService {
    pub async fn submit_web_authoring(
        &self,
        service: &crate::HumanGovernanceService,
        request: RequestId,
        frontier: u64,
        intent: HumanAtomAuthoring,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let conflict = || HumanActionOutcome::Conflict {
            current_revision_ref: None,
        };
        let Some(runtime) = &self.runtime_snapshot else {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "web_proposal_source_unavailable",
            });
        };
        let command_id = CommandId::from_uuid(request.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let id = authored_proposal_id(command_id)?;
        if let Some(previous) = self
            .writer
            .committed_command(command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
        {
            return Ok(
                match self
                    .authoring_outcome(service, &previous, id, intent.target(), Some(&intent))
                    .await?
                {
                    HumanActionOutcome::Applied {
                        current_revision_ref,
                        ..
                    } => HumanActionOutcome::NoDelta {
                        current_revision_ref,
                    },
                    _ => conflict(),
                },
            );
        }
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if snapshot.frontier != frontier {
            return Ok(conflict());
        }
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let base = authoring_base(&view, intent.target());
        let Some(scope) = authoring_scope(service, &snapshot, &intent, base).await? else {
            return Ok(conflict());
        };
        let valid = match &intent {
            HumanAtomAuthoring::Correct(value) => base
                .and_then(|base| value.replacement_value(base))
                .is_some(),
            HumanAtomAuthoring::Create(value) => value.value().is_some(),
        };
        if !valid {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "invalid_atom_proposal",
            });
        }
        let revision = RevisionId::new_v7();
        let canonical = intent
            .canonical(id, revision)
            .ok_or(HumanGovernanceError::InvalidInput)?;
        let (instance, prefix, manifest) = intent.capture_identity();
        let record = format!("{prefix}-{id}-{revision}");
        let capture_scope = AcceptanceCaptureScope {
            task_id: scope.task_id(),
            repository_id: scope.repository_id(),
            worktree_id: None,
        };
        let input = human_capture_input(
            (id, revision),
            &canonical,
            &record,
            capture_scope,
            (instance, manifest),
        )?;
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
        let segment = match capture.capture_isolated(
            input,
            command_id,
            &format!("web-{}", command_id.as_uuid().hyphenated()),
        ) {
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
        if !HumanAtomAuthoring::exact_capture(&verified.receipt) {
            acknowledge_web_reservation(&spool, &segment).await?;
            return Ok(HumanActionOutcome::Unavailable {
                reason: "authoring_source_not_exact",
            });
        }
        let Some(batch) = self.web_authoring_command(
            &snapshot,
            &view,
            (base, &scope),
            (id, revision),
            &intent,
            &verified,
        )?
        else {
            acknowledge_web_reservation(&spool, &segment).await?;
            return Ok(conflict());
        };
        let outcome = match self
            .writer
            .commit_if_frontier(batch, now_us()?, frontier)
            .await
        {
            Ok(_) => {
                let previous = self
                    .writer
                    .committed_command(command_id)
                    .await
                    .map_err(|_| HumanGovernanceError::Store)?
                    .ok_or(HumanGovernanceError::Store)?;
                authoring_result(&previous, id, intent.target(), Some(&intent))
                    .map(|(_, result)| result)
                    .ok_or(HumanGovernanceError::Store)?
            }
            Err(
                crate::WriterActorError::StaleFrontier
                | crate::WriterActorError::IdempotencyConflict,
            ) => conflict(),
            Err(_) => return Err(HumanGovernanceError::Store),
        };
        acknowledge_web_reservation(&spool, &segment).await?;
        Ok(outcome)
    }

    pub async fn reviewed_web_authoring_outcome(
        &self,
        service: &crate::HumanGovernanceService,
        request: RequestId,
        target: HumanAuthoringTarget,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let id = CommandId::from_uuid(request.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let Some(committed) = self
            .writer
            .committed_command(id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
        else {
            return Ok(HumanActionOutcome::Unknown);
        };
        self.authoring_outcome(service, &committed, authored_proposal_id(id)?, target, None)
            .await
    }

    async fn authoring_outcome(
        &self,
        service: &crate::HumanGovernanceService,
        committed: &evertrace_store::CommittedCommand,
        id: RevisionProposalId,
        target: HumanAuthoringTarget,
        expected: Option<&HumanAtomAuthoring>,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let Some((proposal, outcome)) = authoring_result(committed, id, target, expected) else {
            return Ok(HumanActionOutcome::Unknown);
        };
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        if !service.proposal_accessible(&snapshot, proposal).await? {
            return Ok(HumanActionOutcome::Unknown);
        }
        Ok(outcome)
    }

    pub(super) async fn reconcile_web_authoring(
        &self,
        verified: &crate::capture::VerifiedCapture,
        cas: &CasStore,
    ) -> Result<(), HumanGovernanceError> {
        if !HumanAtomAuthoring::exact_capture(&verified.receipt)
            || self
                .writer
                .committed_command(verified.body.command_id)
                .await
                .map_err(|_| HumanGovernanceError::Store)?
                .is_some()
        {
            // A later or changed use of an already settled request cannot replace it.
            return Ok(());
        }
        let id = authored_proposal_id(verified.body.command_id)?;
        let revision = verified
            .body
            .source_revision
            .as_str()
            .parse::<RevisionId>()
            .map_err(|_| HumanGovernanceError::Store)?;
        let digest =
            CasDigest::from_str(&verified.body.cas_ref).map_err(|_| HumanGovernanceError::Store)?;
        let payload = cas.read(&digest).map_err(|_| HumanGovernanceError::Store)?;
        let intent = HumanAtomAuthoring::read_canonical(&payload, id, revision)
            .ok_or(HumanGovernanceError::Store)?;
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let base = authoring_base(&view, intent.target());
        let service =
            crate::HumanGovernanceService::new(self.writer.clone(), self.effective_config_hash);
        let Some(scope) = authoring_scope(&service, &snapshot, &intent, base).await? else {
            return Ok(());
        };
        if let Some(batch) = self.web_authoring_command(
            &snapshot,
            &view,
            (base, &scope),
            (id, revision),
            &intent,
            verified,
        )? {
            self.writer
                .commit_if_frontier(batch, now_us()?, snapshot.frontier)
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
        }
        Ok(())
    }

    fn web_authoring_command(
        &self,
        snapshot: &ProjectionSnapshot,
        view: &SemanticCurrentView,
        (base, scope): (Option<&Atom>, &AtomScope),
        (id, revision): (RevisionProposalId, RevisionId),
        intent: &HumanAtomAuthoring,
        verified: &crate::capture::VerifiedCapture,
    ) -> Result<Option<JournalCommand>, HumanGovernanceError> {
        if !intent.capture_matches(
            scope,
            id,
            revision,
            &verified.receipt,
            &verified.observation,
        ) {
            return Err(HumanGovernanceError::Store);
        }
        let source = verified.observation.source_observation_id;
        let Some(payload) = intent.payload(base, source, verified.receipt.recorded_at_us) else {
            return Ok(None);
        };
        let (AtomProposalPayload::Replace { draft } | AtomProposalPayload::Create { draft }) =
            &payload
        else {
            return Err(HumanGovernanceError::Store);
        };
        let context = ProposalCommandContext {
            command_id: verified.body.command_id,
            occurred_at_us: verified.receipt.recorded_at_us,
            effective_config_hash: self.effective_config_hash,
            algorithm_revision: ALGORITHM_REVISION.into(),
        };
        let request = SubmitProposalRequest {
            target_kind: ProposalTargetKind::Atom,
            target_id: base.map(|base| ProposalTargetId::Atom(base.atom_id)),
            base_revision_id: base.map(|base| base.revision_id),
            operation: intent.operation(),
            evidence_refs: draft.evidence_refs.clone(),
            payload: ProposalPayload::Atom(Box::new(payload)),
            source_cohort_refs: vec![source.to_string()],
            eligibility: ProposalEligibility::ManualRequired,
            created_by: ProposalCreatedBy::User,
        };
        let ProposalResolution::Revision { value, command } = RevisionProposalService
            .submit_with_identity(view, context, request, id, revision)
            .map_err(|_| HumanGovernanceError::Store)?
        else {
            return Ok(None);
        };
        if !matches!(
            deletion_admission(snapshot, &value)?,
            ObjectDeletionCandidateAdmission::Clear
        ) {
            return Ok(None);
        }
        let mut events = capture_event_drafts(
            verified,
            None,
            self.effective_config_hash,
            ALGORITHM_REVISION,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        events.extend_from_slice(command.events());
        JournalCommand::new(command.command_id(), events)
            .map(Some)
            .map_err(|_| HumanGovernanceError::Store)
    }
}

fn authoring_base(view: &SemanticCurrentView, target: HumanAuthoringTarget) -> Option<&Atom> {
    match target {
        HumanAuthoringTarget::Correct(id, revision) => view
            .atoms
            .get(&id)
            .filter(|atom| atom.revision_id == revision),
        HumanAuthoringTarget::Create(_) => None,
    }
}

async fn authoring_scope(
    service: &crate::HumanGovernanceService,
    snapshot: &ProjectionSnapshot,
    intent: &HumanAtomAuthoring,
    base: Option<&Atom>,
) -> Result<Option<AtomScope>, HumanGovernanceError> {
    let Some(scope) = intent.scope(base) else {
        return Ok(None);
    };
    let accessible = match intent.target() {
        HumanAuthoringTarget::Correct(id, revision) => {
            service
                .web_current_object_accessible(
                    snapshot,
                    "atom_revision",
                    &id.to_string(),
                    &revision.to_string(),
                )
                .await?
        }
        HumanAuthoringTarget::Create(scope) => {
            service
                .web_creation_scope_accessible(snapshot, scope)
                .await?
        }
    };
    Ok(accessible.then_some(scope))
}

fn authored_proposal_id(command_id: CommandId) -> Result<RevisionProposalId, HumanGovernanceError> {
    RevisionProposalId::from_uuid(command_id.as_uuid())
        .map_err(|_| HumanGovernanceError::InvalidInput)
}

fn authoring_result<'a>(
    committed: &'a evertrace_store::CommittedCommand,
    id: RevisionProposalId,
    target: HumanAuthoringTarget,
    expected: Option<&HumanAtomAuthoring>,
) -> Option<(&'a RevisionProposal, HumanActionOutcome)> {
    let got_source = committed.payloads.iter().any(|payload| matches!(payload, JournalPayload::SourceReceiptRecorded(value)
        if is_human_authoring_manifest(&value.eligible_event_manifest_ref) && value.source_ref == id.to_string()));
    if !got_source {
        return None;
    }
    committed
        .payloads
        .iter()
        .zip(&committed.event_ids)
        .find_map(|(payload, event)| {
            let JournalPayload::RevisionProposalRecorded(proposal) = payload else {
                return None;
            };
            let intent = HumanAtomAuthoring::from_pending(proposal)?;
            (proposal.proposal_id == id
                && intent.target() == target
                && expected.is_none_or(|value| *value == intent))
            .then(|| {
                (
                    proposal.as_ref(),
                    HumanActionOutcome::Applied {
                        current_revision_ref: proposal.proposal_revision_id.to_string(),
                        audit_event_ref: event.clone(),
                    },
                )
            })
        })
}
