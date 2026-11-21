//! Authored correction commands, sharing the protected human capture and proposal lifecycle.
use super::*;
use evertrace_domain::{
    ids::AtomId,
    semantic::{Atom, HumanAtomCorrection, ProposalTargetKind},
};

impl HumanAcceptanceService {
    pub async fn submit_web_correction(
        &self,
        service: &crate::HumanGovernanceService,
        request_id: RequestId,
        frontier: u64,
        intent: HumanAtomCorrection,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let conflict = || HumanActionOutcome::Conflict {
            current_revision_ref: None,
        };
        let Some(runtime) = &self.runtime_snapshot else {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "web_correction_source_unavailable",
            });
        };
        let command_id = CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let id = correction_proposal_id(command_id)?;
        if let Some(previous) = self
            .writer
            .committed_command(command_id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
        {
            return Ok(
                match self
                    .correction_outcome(
                        service,
                        &previous,
                        id,
                        (intent.atom_id, intent.base_revision_id),
                        Some(&intent),
                    )
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
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let Some(base) = view.atoms.get(&intent.atom_id).filter(|base| {
            snapshot.frontier == frontier
                && intent.base_revision_id == base.revision_id
                && HumanAtomCorrection::eligible_base(base)
        }) else {
            return Ok(conflict());
        };
        if !service
            .web_current_object_accessible(
                &snapshot,
                "atom_revision",
                &base.atom_id.to_string(),
                &base.revision_id.to_string(),
            )
            .await?
        {
            return Ok(conflict());
        }
        if intent.replacement_value(base).is_none() {
            return Ok(HumanActionOutcome::Unavailable {
                reason: "invalid_atom_correction",
            });
        }
        let revision = RevisionId::new_v7();
        let canonical = intent
            .canonical(id, revision)
            .ok_or(HumanGovernanceError::InvalidInput)?;
        let record = format!("human-correct-{id}-{revision}");
        let scope = AcceptanceCaptureScope {
            task_id: base.scope.task_id(),
            repository_id: base.scope.repository_id(),
            worktree_id: None,
        };
        let input = human_capture_input(
            (id, revision),
            &canonical,
            &record,
            scope,
            ("human-correction", HUMAN_CORRECTION_MANIFEST),
        )?;
        let mut capture = CaptureRuntime::open_for_admission(runtime.clone())
            .map_err(|_| HumanGovernanceError::Store)?;
        let routing_hint = format!("web-{}", command_id.as_uuid().hyphenated());
        let segment = match capture.capture_isolated(input, command_id, &routing_hint) {
            Ok(result) if matches!(result.outcome, CaptureOutcome::Durable { .. }) => {
                result.segment
            }
            Err(CaptureError::ReservationExists) => return Ok(HumanActionOutcome::Unknown),
            _ => return Err(HumanGovernanceError::Store),
        };
        let spool = DurableSpool::open_read_only(
            runtime.spool_dir.clone(),
            runtime
                .spool_limits()
                .map_err(|_| HumanGovernanceError::Store)?,
        )
        .map_err(|_| HumanGovernanceError::Store)?;
        let cas =
            CasStore::open(runtime.cas_dir.clone()).map_err(|_| HumanGovernanceError::Store)?;
        let [frame] = segment.frames() else {
            return Err(HumanGovernanceError::Store);
        };
        let verified =
            verify_capture_frame(frame, &cas).map_err(|_| HumanGovernanceError::Store)?;
        if !HumanAtomCorrection::exact_capture(&verified.receipt) {
            acknowledge_web_reservation(&spool, &segment).await?;
            return Ok(HumanActionOutcome::Unavailable {
                reason: "correction_source_not_exact",
            });
        }
        let Some(batch) = self.web_correction_command(
            &snapshot,
            &view,
            base,
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
                correction_result(
                    &previous,
                    id,
                    (intent.atom_id, intent.base_revision_id),
                    Some(&intent),
                )
                .map(|(_, outcome)| outcome)
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

    pub async fn reviewed_web_correction_outcome(
        &self,
        service: &crate::HumanGovernanceService,
        request_id: RequestId,
        target: (AtomId, RevisionId),
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let id = CommandId::from_uuid(request_id.as_uuid())
            .map_err(|_| HumanGovernanceError::InvalidInput)?;
        let Some(committed) = self
            .writer
            .committed_command(id)
            .await
            .map_err(|_| HumanGovernanceError::Store)?
        else {
            return Ok(HumanActionOutcome::Unknown);
        };
        self.correction_outcome(
            service,
            &committed,
            correction_proposal_id(id)?,
            target,
            None,
        )
        .await
    }

    async fn correction_outcome(
        &self,
        service: &crate::HumanGovernanceService,
        committed: &evertrace_store::CommittedCommand,
        id: RevisionProposalId,
        target: (AtomId, RevisionId),
        expected: Option<&HumanAtomCorrection>,
    ) -> Result<HumanActionOutcome, HumanGovernanceError> {
        let Some((proposal, outcome)) = correction_result(committed, id, target, expected) else {
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

    pub(super) async fn reconcile_web_correction(
        &self,
        verified: &crate::capture::VerifiedCapture,
        cas: &CasStore,
    ) -> Result<(), HumanGovernanceError> {
        if !HumanAtomCorrection::exact_capture(&verified.receipt)
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
        let id = correction_proposal_id(verified.body.command_id)?;
        let revision = verified
            .body
            .source_revision
            .as_str()
            .parse::<RevisionId>()
            .map_err(|_| HumanGovernanceError::Store)?;
        let digest =
            CasDigest::from_str(&verified.body.cas_ref).map_err(|_| HumanGovernanceError::Store)?;
        let payload = cas.read(&digest).map_err(|_| HumanGovernanceError::Store)?;
        let intent = HumanAtomCorrection::read_canonical(&payload, id, revision)
            .ok_or(HumanGovernanceError::Store)?;
        let snapshot = self
            .writer
            .project_objects()
            .await
            .map_err(|_| HumanGovernanceError::Store)?;
        let view = SemanticCurrentView::from_snapshot(&snapshot)
            .map_err(|_| HumanGovernanceError::Store)?;
        let Some(base) = view
            .atoms
            .get(&intent.atom_id)
            .filter(|value| value.revision_id == intent.base_revision_id)
        else {
            return Ok(());
        };
        let service =
            crate::HumanGovernanceService::new(self.writer.clone(), self.effective_config_hash);
        if !service
            .web_current_object_accessible(
                &snapshot,
                "atom_revision",
                &base.atom_id.to_string(),
                &base.revision_id.to_string(),
            )
            .await?
        {
            return Ok(());
        }
        if let Some(batch) =
            self.web_correction_command(&snapshot, &view, base, (id, revision), &intent, verified)?
        {
            self.writer
                .commit_if_frontier(batch, now_us()?, snapshot.frontier)
                .await
                .map_err(|_| HumanGovernanceError::Store)?;
        }
        Ok(())
    }

    fn web_correction_command(
        &self,
        snapshot: &ProjectionSnapshot,
        view: &SemanticCurrentView,
        base: &Atom,
        (id, revision): (RevisionProposalId, RevisionId),
        intent: &HumanAtomCorrection,
        verified: &crate::capture::VerifiedCapture,
    ) -> Result<Option<JournalCommand>, HumanGovernanceError> {
        if !intent.capture_matches(base, id, revision, &verified.receipt, &verified.observation) {
            return Err(HumanGovernanceError::Store);
        }
        let source = verified.observation.source_observation_id;
        let Some(draft) = intent.draft(base, source) else {
            return Ok(None);
        };
        let context = ProposalCommandContext {
            command_id: verified.body.command_id,
            occurred_at_us: verified.receipt.recorded_at_us,
            effective_config_hash: self.effective_config_hash,
            algorithm_revision: ALGORITHM_REVISION.into(),
        };
        let request = SubmitProposalRequest {
            target_kind: ProposalTargetKind::Atom,
            target_id: Some(ProposalTargetId::Atom(base.atom_id)),
            base_revision_id: Some(base.revision_id),
            operation: ProposalOperation::Replace,
            evidence_refs: draft.evidence_refs.clone(),
            payload: ProposalPayload::Atom(Box::new(AtomProposalPayload::Replace { draft })),
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

fn correction_proposal_id(
    command_id: CommandId,
) -> Result<RevisionProposalId, HumanGovernanceError> {
    RevisionProposalId::from_uuid(command_id.as_uuid())
        .map_err(|_| HumanGovernanceError::InvalidInput)
}

fn correction_result<'a>(
    committed: &'a evertrace_store::CommittedCommand,
    id: RevisionProposalId,
    target: (AtomId, RevisionId),
    expected: Option<&HumanAtomCorrection>,
) -> Option<(&'a RevisionProposal, HumanActionOutcome)> {
    let got_source = committed.payloads.iter().any(|payload| matches!(payload, JournalPayload::SourceReceiptRecorded(value)
        if value.eligible_event_manifest_ref == HUMAN_CORRECTION_MANIFEST && value.source_ref == id.to_string()));
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
            let intent = HumanAtomCorrection::from_pending(proposal)?;
            (proposal.proposal_id == id
                && (intent.atom_id, intent.base_revision_id) == target
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
