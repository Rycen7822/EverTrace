use std::collections::{BTreeMap, BTreeSet};

use evertrace_domain::{
    ids::{ProcedureId, ProcedureNegativeEvidenceId, ProcedureUsageId},
    procedure::{
        ProcedureNegativeEvidence, ProcedureNegativeReviewEvent, ProcedureNegativeReviewStatus,
        ProcedurePublicationState, ProcedureRevision, ProcedureScope, ProcedureStateEvent,
        ProcedureUsageRevision,
    },
    revision::RevisionId,
};

use crate::{JournalPayload, ObjectFamily, ObjectRow, ObjectRowClass, ObjectRowKind, StoreError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NegativeReviewActionReason {
    ResolveAsIneffective,
    DismissAttribution,
    ConfirmHarm,
    SuccessorSuperseded,
}

impl NegativeReviewActionReason {
    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "resolve_as_ineffective" => Some(Self::ResolveAsIneffective),
            "dismiss_attribution" => Some(Self::DismissAttribution),
            "confirm_harm" => Some(Self::ConfirmHarm),
            "successor_replay_fixed" => Some(Self::SuccessorSuperseded),
            _ => None,
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct ProcedureState {
    procedures: BTreeMap<ProcedureId, (ProcedureRevision, u64)>,
    revisions: BTreeMap<RevisionId, (ProcedureRevision, u64)>,
    events: BTreeMap<RevisionId, (ProcedureStateEvent, u64)>,
    current_publication: BTreeMap<RevisionId, (ProcedureStateEvent, u64)>,
    usage_revisions: BTreeMap<RevisionId, (ProcedureUsageRevision, u64)>,
    usages: BTreeMap<ProcedureUsageId, (ProcedureUsageRevision, u64)>,
    negative_evidence: BTreeMap<ProcedureNegativeEvidenceId, (ProcedureNegativeEvidence, u64)>,
    negative_evidence_by_revision: BTreeMap<RevisionId, BTreeSet<ProcedureNegativeEvidenceId>>,
    negative_reviews: BTreeMap<RevisionId, (ProcedureNegativeReviewEvent, u64)>,
    current_negative_reviews:
        BTreeMap<ProcedureNegativeEvidenceId, (ProcedureNegativeReviewEvent, u64)>,
}

impl ProcedureState {
    pub(super) fn forget(
        &mut self,
        procedure_ids: &BTreeSet<ProcedureId>,
        revision_ids: &BTreeSet<RevisionId>,
    ) {
        self.procedures.retain(|id, _| !procedure_ids.contains(id));
        self.revisions.retain(|id, _| !revision_ids.contains(id));
        self.events
            .retain(|_, (event, _)| !revision_ids.contains(&event.procedure_revision_id));
        self.current_publication
            .retain(|id, _| !revision_ids.contains(id));
        self.usage_revisions
            .retain(|_, (usage, _)| !revision_ids.contains(&usage.procedure_revision_id));
        self.usages
            .retain(|_, (usage, _)| !revision_ids.contains(&usage.procedure_revision_id));
        let negative_ids = self
            .negative_evidence
            .values()
            .filter_map(|(negative, _)| {
                revision_ids
                    .contains(&negative.procedure_revision_id)
                    .then_some(negative.negative_evidence_id)
            })
            .collect::<BTreeSet<_>>();
        self.negative_evidence
            .retain(|id, _| !negative_ids.contains(id));
        self.negative_evidence_by_revision
            .retain(|id, _| !revision_ids.contains(id));
        self.negative_reviews
            .retain(|_, (review, _)| !negative_ids.contains(&review.negative_evidence_id));
        self.current_negative_reviews
            .retain(|id, _| !negative_ids.contains(id));
    }

    pub(super) fn revision(&self, id: RevisionId) -> Option<&ProcedureRevision> {
        self.revisions.get(&id).map(|(value, _)| value)
    }

    pub(super) fn revision_entry(&self, id: RevisionId) -> Option<(&ProcedureRevision, u64)> {
        self.revisions.get(&id).map(|(value, seq)| (value, *seq))
    }

    pub(super) fn publication(&self, id: RevisionId) -> Option<ProcedurePublicationState> {
        self.current_publication
            .get(&id)
            .map(|(value, _)| value.to_state)
    }

    pub(super) fn deletion_procedure_impacts(
        &self,
        revision_ids: &BTreeSet<RevisionId>,
    ) -> Vec<crate::purge::ObjectDeletionProcedureImpact> {
        let mut impacts = self
            .procedures
            .values()
            .filter_map(|(revision, _)| {
                if revision_ids.contains(&revision.revision_id) {
                    return None;
                }
                let trigger_refs = revision
                    .draft
                    .support_revision_refs
                    .iter()
                    .filter(|support| revision_ids.contains(support))
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                if trigger_refs.is_empty() {
                    return None;
                }
                let current_state = self
                    .current_publication
                    .get(&revision.revision_id)?
                    .0
                    .clone();
                matches!(
                    current_state.to_state,
                    ProcedurePublicationState::ActiveProbationary
                        | ProcedurePublicationState::ActiveStable
                )
                .then_some(crate::purge::ObjectDeletionProcedureImpact {
                    current_state,
                    trigger_refs,
                })
            })
            .collect::<Vec<_>>();
        impacts.sort_by_key(|impact| impact.current_state.procedure_revision_id);
        impacts
    }

    pub(super) fn validate_deletion_review_holds(
        &self,
        impacts: &[crate::purge::ObjectDeletionProcedureImpact],
        occurred_at_us: i64,
        payloads: &[&JournalPayload],
        error: StoreError,
    ) -> Result<(), StoreError> {
        let mut actual = BTreeMap::new();
        for payload in payloads {
            let JournalPayload::ProcedureStateRecorded(event) = payload else {
                continue;
            };
            if actual
                .insert(event.procedure_revision_id, event.as_ref())
                .is_some()
            {
                return Err(error);
            }
        }
        if actual.len() != impacts.len() {
            return Err(error);
        }
        for impact in impacts {
            let current = &impact.current_state;
            let event = *actual.get(&current.procedure_revision_id).ok_or(error)?;
            if self
                .current_publication
                .get(&current.procedure_revision_id)
                .is_none_or(|(state, _)| state != current)
                || event.state_event_id == current.state_event_id
                || event.procedure_revision_id != current.procedure_revision_id
                || event.from_state != Some(current.to_state)
                || event.to_state != ProcedurePublicationState::ReviewHold
                || event.reason != evertrace_domain::procedure::ProcedureStateReason::SupportPending
                || event.resume_state != Some(current.to_state)
                || event.evidence_refs != impact.trigger_refs
                || event.created_at_us != occurred_at_us
                || event.validate().is_err()
            {
                return Err(error);
            }
        }
        Ok(())
    }

    pub(super) fn usage(&self, id: ProcedureUsageId) -> Option<&ProcedureUsageRevision> {
        self.usages.get(&id).map(|(value, _)| value)
    }

    pub(super) fn negative_entry(
        &self,
        id: ProcedureNegativeEvidenceId,
    ) -> Option<(&ProcedureNegativeEvidence, u64)> {
        self.negative_evidence
            .get(&id)
            .map(|(value, seq)| (value, *seq))
    }

    pub(super) fn negative_entries(
        &self,
    ) -> impl Iterator<Item = (&ProcedureNegativeEvidence, u64)> {
        self.negative_evidence
            .values()
            .map(|(value, seq)| (value, *seq))
    }

    pub(super) fn usage_revision(&self, id: RevisionId) -> Option<&ProcedureUsageRevision> {
        self.usage_revisions.get(&id).map(|(value, _)| value)
    }

    pub(super) fn usage_revision_entries(
        &self,
    ) -> impl Iterator<Item = (&ProcedureUsageRevision, u64)> {
        self.usage_revisions
            .values()
            .map(|(value, seq)| (value, *seq))
    }

    pub(super) fn negative_review_entries(
        &self,
    ) -> impl Iterator<Item = (&ProcedureNegativeReviewEvent, u64)> {
        self.negative_reviews
            .values()
            .map(|(value, seq)| (value, *seq))
    }

    pub(super) fn state_event_entries(&self) -> impl Iterator<Item = (&ProcedureStateEvent, u64)> {
        self.events.values().map(|(value, seq)| (value, *seq))
    }

    fn has_active_harm(&self, procedure_revision_id: RevisionId) -> bool {
        self.negative_evidence_by_revision
            .get(&procedure_revision_id)
            .into_iter()
            .flat_map(BTreeSet::iter)
            .any(|negative_evidence_id| {
                self.current_negative_reviews
                    .get(negative_evidence_id)
                    .is_some_and(|(review, _)| {
                        matches!(
                            review.status,
                            ProcedureNegativeReviewStatus::Pending
                                | ProcedureNegativeReviewStatus::Upheld
                        )
                    })
                    && self
                        .negative_evidence
                        .get(negative_evidence_id)
                        .is_some_and(|(negative, _)| {
                            negative.level
                                != evertrace_domain::procedure::ProcedureNegativeLevel::Ineffective
                        })
            })
    }

    pub(super) fn local_quarantined(
        &self,
        procedure_revision_id: RevisionId,
        context: &evertrace_domain::procedure::ProcedureLocalContext,
    ) -> bool {
        self.negative_evidence_by_revision
            .get(&procedure_revision_id)
            .into_iter()
            .flat_map(BTreeSet::iter)
            .any(|negative_evidence_id| {
                self.current_negative_reviews
                    .get(negative_evidence_id)
                    .is_some_and(|(review, _)| {
                        matches!(
                            review.status,
                            ProcedureNegativeReviewStatus::Pending
                                | ProcedureNegativeReviewStatus::Upheld
                        )
                    })
                    && self
                        .negative_evidence
                        .get(negative_evidence_id)
                        .is_some_and(|(negative, _)| {
                            negative.level
                                == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                                && negative
                                    .local_context
                                    .as_ref()
                                    .is_some_and(|local| local.compatible(context))
                        })
            })
    }

    fn promotion_evidence_refs(
        &self,
        tasks: &BTreeMap<evertrace_domain::ids::TaskId, (evertrace_domain::work::Task, u64)>,
        trigger: &ProcedureUsageRevision,
    ) -> Option<Vec<String>> {
        if self.has_active_harm(trigger.procedure_revision_id) {
            return None;
        }
        let mut prior_successes = self
            .usages
            .values()
            .filter(|(usage, _)| {
                usage.procedure_revision_id == trigger.procedure_revision_id
                    && usage.outcome_supported == evertrace_domain::procedure::ProcedureTruth::True
                    && usage.task_id != trigger.task_id
            })
            .map(|(usage, _)| usage)
            .collect::<Vec<_>>();
        prior_successes.sort_by_key(|usage| (usage.task_id, usage.usage_revision_id));
        prior_successes.dedup_by_key(|usage| usage.task_id);
        for first in 0..prior_successes.len() {
            for second in (first + 1)..prior_successes.len() {
                let mut cohort = [prior_successes[first], prior_successes[second], trigger];
                cohort.sort_by_key(|usage| (usage.task_id, usage.usage_revision_id));
                let independent = cohort.iter().enumerate().all(|(index, usage)| {
                    let Some((task, _)) = tasks.get(&usage.task_id) else {
                        return false;
                    };
                    task.continuation_of_task_id.is_none()
                        && task.split_from_task_id.is_none()
                        && cohort[..index].iter().all(|prior| {
                            tasks.get(&prior.task_id).is_some_and(|(prior_task, _)| {
                                prior_task
                                    .request_root_refs
                                    .iter()
                                    .all(|reference| !task.request_root_refs.contains(reference))
                            })
                        })
                });
                if independent {
                    let mut refs = cohort
                        .iter()
                        .map(|usage| usage.usage_revision_id.to_string())
                        .collect::<Vec<_>>();
                    refs.sort();
                    return Some(refs);
                }
            }
        }
        None
    }

    pub(super) fn has_usage_anchor(&self, value: &ProcedureUsageRevision) -> bool {
        self.usages.values().any(|(current, _)| {
            current.procedure_usage_id != value.procedure_usage_id
                && current.procedure_revision_id == value.procedure_revision_id
                && current.task_id == value.task_id
                && current.exposure_episode_revision_id == value.exposure_episode_revision_id
                && current.decision_boundary_ref == value.decision_boundary_ref
        })
    }

    pub(super) fn validate_command_cohort<'a>(
        &self,
        tasks: &BTreeMap<evertrace_domain::ids::TaskId, (evertrace_domain::work::Task, u64)>,
        accepted_edits: &BTreeSet<evertrace_domain::ids::RevisionProposalId>,
        payloads: impl IntoIterator<Item = &'a JournalPayload>,
    ) -> Result<(), StoreError> {
        let payloads = payloads.into_iter().collect::<Vec<_>>();
        for proposal in payloads.iter().filter_map(|payload| match payload {
            JournalPayload::RevisionProposalRecorded(value)
                if value.status == evertrace_domain::semantic::ProposalStatus::Accepted =>
            {
                Some(value.as_ref())
            }
            _ => None,
        }) {
            let Some(evertrace_domain::semantic::AcceptedProposalTarget::Procedure {
                procedure_id,
                procedure_revision_id,
                ..
            }) = proposal
                .acceptance
                .as_ref()
                .map(|acceptance| &acceptance.accepted_target)
            else {
                continue;
            };
            let evertrace_domain::semantic::ProposalPayload::Procedure(procedure_payload) =
                &proposal.payload
            else {
                return Err(StoreError::StoreCorrupt);
            };
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
            let edit_command = accepted_edits.contains(&proposal.proposal_id);
            if edit_command {
                if payloads
                    .iter()
                    .filter(|payload| {
                        matches!(payload, JournalPayload::ProcedureRevisionRecorded(_))
                    })
                    .count()
                    != materialized.len()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                match materialized.as_slice() {
                    [revision]
                        if revision.draft == *procedure_payload.draft()
                            && match proposal.operation {
                                evertrace_domain::semantic::ProposalOperation::Create => {
                                    proposal.target_id.is_none()
                                        && proposal.base_revision_id.is_none()
                                        && revision.parent_revision_id.is_none()
                                        && revision.revision_generation == 1
                                }
                                evertrace_domain::semantic::ProposalOperation::Replace => {
                                    proposal.target_id
                                        == Some(
                                            evertrace_domain::semantic::ProposalTargetId::Procedure(
                                                *procedure_id,
                                            ),
                                        )
                                        && revision.parent_revision_id == proposal.base_revision_id
                                }
                                _ => false,
                            } =>
                    {
                        continue;
                    }
                    [] => {}
                    _ => return Err(StoreError::StoreCorrupt),
                }
            } else if !materialized.is_empty() {
                continue;
            }
            let current = self
                .procedures
                .get(procedure_id)
                .map(|(revision, _)| revision)
                .ok_or(StoreError::StoreCorrupt)?;
            if proposal.operation != evertrace_domain::semantic::ProposalOperation::Replace
                || !matches!(
                    procedure_payload.as_ref(),
                    evertrace_domain::semantic::ProcedureProposalPayload::Replace { .. }
                )
                || proposal.target_id
                    != Some(evertrace_domain::semantic::ProposalTargetId::Procedure(
                        *procedure_id,
                    ))
                || proposal.base_revision_id != Some(*procedure_revision_id)
                || current.revision_id != *procedure_revision_id
                || current.draft != *procedure_payload.draft()
                || !matches!(
                    self.publication(*procedure_revision_id),
                    Some(
                        ProcedurePublicationState::ActiveProbationary
                            | ProcedurePublicationState::ActiveStable
                    )
                )
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        let mut successful_usages = BTreeMap::<RevisionId, Vec<&ProcedureUsageRevision>>::new();
        for usage in payloads.iter().filter_map(|payload| match payload {
            JournalPayload::ProcedureUsageRecorded(value)
                if value.outcome_supported == evertrace_domain::procedure::ProcedureTruth::True =>
            {
                Some(value.as_ref())
            }
            _ => None,
        }) {
            successful_usages
                .entry(usage.procedure_revision_id)
                .or_default()
                .push(usage);
        }
        let mut expected_promotion_refs = BTreeMap::<RevisionId, Vec<String>>::new();
        for (procedure_revision_id, usages) in &successful_usages {
            let current_state = self
                .current_publication
                .get(procedure_revision_id)
                .map(|(event, _)| event.to_state)
                .ok_or(StoreError::StoreCorrupt)?;
            let promotion_states = payloads
                .iter()
                .filter(|payload| {
                    matches!(payload,
                        JournalPayload::ProcedureStateRecorded(event)
                            if event.procedure_revision_id == *procedure_revision_id
                                && event.to_state == ProcedurePublicationState::ActiveStable
                                && event.reason == evertrace_domain::procedure::ProcedureStateReason::ObjectiveSuccesses)
                })
                .count();
            if current_state != ProcedurePublicationState::ActiveProbationary {
                if promotion_states != 0 {
                    return Err(StoreError::StoreCorrupt);
                }
                continue;
            }
            let [usage] = usages.as_slice() else {
                return Err(StoreError::StoreCorrupt);
            };
            match self.promotion_evidence_refs(tasks, usage) {
                Some(evidence_refs) => {
                    if promotion_states != 1 {
                        return Err(StoreError::StoreCorrupt);
                    }
                    expected_promotion_refs.insert(*procedure_revision_id, evidence_refs);
                }
                None if promotion_states == 0 => {}
                None => return Err(StoreError::StoreCorrupt),
            }
        }
        for stable in payloads.iter().filter_map(|payload| {
            match payload {
            JournalPayload::ProcedureStateRecorded(value)
                if value.to_state == ProcedurePublicationState::ActiveStable
                    && value.reason
                        == evertrace_domain::procedure::ProcedureStateReason::ObjectiveSuccesses =>
            {
                Some(value.as_ref())
            }
            _ => None,
        }
        }) {
            let Some([usage]) = successful_usages
                .get(&stable.procedure_revision_id)
                .map(Vec::as_slice)
            else {
                return Err(StoreError::StoreCorrupt);
            };
            if expected_promotion_refs.get(&stable.procedure_revision_id)
                != Some(&stable.evidence_refs)
                || !stable
                    .evidence_refs
                    .contains(&usage.usage_revision_id.to_string())
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for negative in payloads.iter().filter_map(|payload| match payload {
            JournalPayload::ProcedureNegativeEvidenceRecorded(value) => Some(value.as_ref()),
            _ => None,
        }) {
            let usage = self
                .usages
                .get(&negative.procedure_usage_id)
                .map(|(usage, _)| usage)
                .ok_or(StoreError::StoreCorrupt)?;
            let expected_review_refs = {
                let mut refs = negative.evidence_refs.clone();
                refs.push(usage.usage_revision_id.to_string());
                refs.sort();
                refs.dedup();
                refs
            };
            if payloads
                .iter()
                .filter(|payload| {
                    matches!(payload,
                        JournalPayload::ProcedureNegativeReviewRecorded(review)
                            if review.negative_evidence_id == negative.negative_evidence_id
                                && review.review_generation == 1
                                && review.status == ProcedureNegativeReviewStatus::Pending
                                && review.created_at_us == negative.created_at_us
                                && review.evidence_refs == expected_review_refs)
                })
                .count()
                != 1
            {
                return Err(StoreError::StoreCorrupt);
            }
            let current_state = self
                .current_publication
                .get(&negative.procedure_revision_id)
                .map(|(event, _)| event.to_state)
                .ok_or(StoreError::StoreCorrupt)?;
            let expected = match negative.level {
                evertrace_domain::procedure::ProcedureNegativeLevel::Ineffective => None,
                evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                    if negative.attribution_basis
                        == evertrace_domain::procedure::ProcedureAttributionBasis::ResolvedLocalized =>
                {
                    None
                }
                evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                    if matches!(
                        current_state,
                        ProcedurePublicationState::ActiveProbationary
                            | ProcedurePublicationState::ActiveStable
                    ) => Some(ProcedurePublicationState::ReviewHold),
                evertrace_domain::procedure::ProcedureNegativeLevel::ConfirmedHarm
                    if matches!(
                        current_state,
                        ProcedurePublicationState::ActiveProbationary
                            | ProcedurePublicationState::ActiveStable
                            | ProcedurePublicationState::ReviewHold
                    ) => Some(ProcedurePublicationState::Suspended),
                _ => None,
            };
            let states = payloads
                .iter()
                .filter_map(|payload| match payload {
                    JournalPayload::ProcedureStateRecorded(event)
                        if event.procedure_revision_id == negative.procedure_revision_id
                            && event.evidence_refs
                                == vec![negative.negative_evidence_id.to_string()] =>
                    {
                        Some(event.to_state)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            if states.as_slice() != expected.as_slice() {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for review in payloads.iter().filter_map(|payload| match payload {
            JournalPayload::ProcedureNegativeReviewRecorded(value)
                if value.review_generation == 1 =>
            {
                Some(value.as_ref())
            }
            _ => None,
        }) {
            if payloads
                .iter()
                .filter(|payload| {
                    matches!(payload,
                        JournalPayload::ProcedureNegativeEvidenceRecorded(negative)
                            if negative.negative_evidence_id == review.negative_evidence_id)
                })
                .count()
                != 1
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for review in payloads.iter().filter_map(|payload| match payload {
            JournalPayload::ProcedureNegativeReviewRecorded(value)
                if value.review_generation > 1 =>
            {
                Some(value.as_ref())
            }
            _ => None,
        }) {
            let negative = self
                .negative_evidence
                .get(&review.negative_evidence_id)
                .map(|(value, _)| value)
                .ok_or(StoreError::StoreCorrupt)?;
            let current = self
                .current_negative_reviews
                .get(&review.negative_evidence_id)
                .map(|(value, _)| value)
                .ok_or(StoreError::StoreCorrupt)?;
            if review.predecessor_review_event_id != Some(current.review_event_id)
                || review.review_generation != current.review_generation + 1
            {
                return Err(StoreError::StoreCorrupt);
            }
            let action = NegativeReviewActionReason::parse(&review.reason)
                .ok_or(StoreError::StoreCorrupt)?;
            let held = self
                .current_publication
                .get(&negative.procedure_revision_id)
                .map(|(event, _)| event)
                .filter(|event| event.to_state == ProcedurePublicationState::ReviewHold);
            let expected_state = match action {
                NegativeReviewActionReason::ResolveAsIneffective
                    if current.status == ProcedureNegativeReviewStatus::Pending
                        && negative.level
                            == evertrace_domain::procedure::ProcedureNegativeLevel::Ineffective
                        && review.status == ProcedureNegativeReviewStatus::Dismissed
                        && review.successor_usage_revision_id.is_none()
                        && review.evidence_refs == negative.evidence_refs =>
                {
                    None
                }
                NegativeReviewActionReason::DismissAttribution
                    if current.status == ProcedureNegativeReviewStatus::Pending
                        && negative.level
                            == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                        && review.status == ProcedureNegativeReviewStatus::Dismissed
                        && review.successor_usage_revision_id.is_none() =>
                {
                    if let Some(held) = held.filter(|_| negative.local_context.is_none()) {
                        Some((
                            held.resume_state
                                .filter(|state| {
                                    matches!(
                                        state,
                                        ProcedurePublicationState::ActiveProbationary
                                            | ProcedurePublicationState::ActiveStable
                                    )
                                })
                                .ok_or(StoreError::StoreCorrupt)?,
                            evertrace_domain::procedure::ProcedureStateReason::Manual,
                        ))
                    } else {
                        None
                    }
                }
                NegativeReviewActionReason::ConfirmHarm
                    if current.status == ProcedureNegativeReviewStatus::Pending
                        && negative.level
                            == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                        && negative.local_context.is_none()
                        && review.status == ProcedureNegativeReviewStatus::Upheld
                        && review.successor_usage_revision_id.is_none() =>
                {
                    held.ok_or(StoreError::StoreCorrupt)?;
                    Some((
                        ProcedurePublicationState::Suspended,
                        evertrace_domain::procedure::ProcedureStateReason::ConfirmedHarm,
                    ))
                }
                NegativeReviewActionReason::SuccessorSuperseded
                    if matches!(
                        current.status,
                        ProcedureNegativeReviewStatus::Pending
                            | ProcedureNegativeReviewStatus::Upheld
                    ) && review.status == ProcedureNegativeReviewStatus::Superseded =>
                {
                    if let Some(held) = held.filter(|_| negative.local_context.is_none()) {
                        Some((
                            held.resume_state
                                .filter(|state| {
                                    matches!(
                                        state,
                                        ProcedurePublicationState::ActiveProbationary
                                            | ProcedurePublicationState::ActiveStable
                                    )
                                })
                                .ok_or(StoreError::StoreCorrupt)?,
                            evertrace_domain::procedure::ProcedureStateReason::Manual,
                        ))
                    } else {
                        None
                    }
                }
                _ => return Err(StoreError::StoreCorrupt),
            };
            if matches!(
                action,
                NegativeReviewActionReason::ResolveAsIneffective
                    | NegativeReviewActionReason::DismissAttribution
                    | NegativeReviewActionReason::ConfirmHarm
            ) && payloads.iter().any(|payload| {
                matches!(
                    payload,
                    JournalPayload::ProcedureNegativeEvidenceRecorded(_)
                )
            }) {
                return Err(StoreError::StoreCorrupt);
            }
            let states = payloads
                .iter()
                .filter_map(|payload| match payload {
                    JournalPayload::ProcedureStateRecorded(event)
                        if event.procedure_revision_id == negative.procedure_revision_id
                            && event.from_state == Some(ProcedurePublicationState::ReviewHold)
                            && event.evidence_refs
                                == vec![negative.negative_evidence_id.to_string()] =>
                    {
                        Some(event.as_ref())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            match (expected_state, states.as_slice()) {
                (None, []) => {}
                (Some((to_state, reason)), [state])
                    if state.to_state == to_state
                        && state.reason == reason
                        && state.resume_state.is_none()
                        && state.created_at_us == review.created_at_us => {}
                _ => return Err(StoreError::StoreCorrupt),
            }
        }
        for state in payloads.iter().filter_map(|payload| match payload {
            JournalPayload::ProcedureStateRecorded(value)
                if value.from_state == Some(ProcedurePublicationState::ReviewHold)
                    && value.reason
                        == evertrace_domain::procedure::ProcedureStateReason::Manual
                    && value.evidence_refs.len() == 1 =>
            {
                Some(value.as_ref())
            }
            _ => None,
        }) {
            let Ok(negative_id) = state.evidence_refs[0].parse::<ProcedureNegativeEvidenceId>()
            else {
                continue;
            };
            if self.negative_evidence.contains_key(&negative_id)
                && payloads
                    .iter()
                    .filter(|payload| {
                        matches!(payload,
                        JournalPayload::ProcedureNegativeReviewRecorded(review)
                            if review.negative_evidence_id == negative_id
                                && review.review_generation > 1
                                && matches!(
                                    review.status,
                                    ProcedureNegativeReviewStatus::Dismissed
                                        | ProcedureNegativeReviewStatus::Superseded
                                ))
                    })
                    .count()
                    != 1
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for state in payloads.iter().filter_map(|payload| match payload {
            JournalPayload::ProcedureStateRecorded(value)
                if matches!(
                    value.reason,
                    evertrace_domain::procedure::ProcedureStateReason::SuspectedHarm
                        | evertrace_domain::procedure::ProcedureStateReason::ConfirmedHarm
                ) =>
            {
                Some(value.as_ref())
            }
            _ => None,
        }) {
            let new_negative_count = payloads.iter().filter(|payload| {
                matches!(payload,
                    JournalPayload::ProcedureNegativeEvidenceRecorded(negative)
                        if negative.procedure_revision_id == state.procedure_revision_id
                            && state.evidence_refs == vec![negative.negative_evidence_id.to_string()])
            }).count();
            let confirmed_existing_count = state
                .evidence_refs
                .first()
                .and_then(|reference| reference.parse::<ProcedureNegativeEvidenceId>().ok())
                .filter(|negative_id| {
                    self.negative_evidence.get(negative_id).is_some_and(|(negative, _)| {
                        negative.procedure_revision_id == state.procedure_revision_id
                            && negative.level
                                == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                            && negative.local_context.is_none()
                    })
                })
                .map_or(0, |negative_id| {
                    payloads
                        .iter()
                        .filter(|payload| {
                            matches!(payload,
                                JournalPayload::ProcedureNegativeReviewRecorded(review)
                                    if review.negative_evidence_id == negative_id
                                        && review.status == ProcedureNegativeReviewStatus::Upheld
                                        && NegativeReviewActionReason::parse(&review.reason)
                                            == Some(NegativeReviewActionReason::ConfirmHarm))
                        })
                        .count()
                });
            let valid = match state.reason {
                evertrace_domain::procedure::ProcedureStateReason::SuspectedHarm => {
                    new_negative_count == 1 && confirmed_existing_count == 0
                }
                evertrace_domain::procedure::ProcedureStateReason::ConfirmedHarm => {
                    (new_negative_count == 1 && confirmed_existing_count == 0)
                        || (new_negative_count == 0 && confirmed_existing_count == 1)
                }
                _ => false,
            };
            if !valid {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Ok(())
    }

    pub(super) fn contains_revision_ref(&self, reference: &str) -> bool {
        reference
            .parse::<RevisionId>()
            .is_ok_and(|revision_id| self.revisions.contains_key(&revision_id))
    }

    pub(super) fn is_current_revision_id(&self, revision_id: RevisionId) -> bool {
        self.revisions
            .get(&revision_id)
            .is_some_and(|(revision, _)| {
                self.current_revision(revision.procedure_id)
                    .is_some_and(|current| current.revision_id == revision_id)
            })
    }

    pub(super) fn revision_refs(&self) -> impl Iterator<Item = &RevisionId> {
        self.revisions.keys()
    }

    pub(super) fn effect_usages(
        &self,
    ) -> impl Iterator<Item = (&evertrace_domain::procedure::ProcedureUsageRevision, u64)> {
        self.usages.values().map(|(usage, seq)| (usage, *seq))
    }

    pub(super) fn controlled_usage_anchor(
        &self,
        procedure_revision_id: RevisionId,
        attempt_id: evertrace_domain::ids::AttemptId,
    ) -> Result<Option<&evertrace_domain::procedure::ProcedureUsageRevision>, StoreError> {
        let mut matches = self.usages.values().filter_map(|(usage, _)| {
            (usage.procedure_revision_id == procedure_revision_id
                && usage.attempt_ids.contains(&attempt_id))
            .then_some(usage)
        });
        let value = matches.next();
        if matches.next().is_some() {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(value)
    }

    pub(super) fn effect_negative_usage_state(
        &self,
    ) -> (BTreeSet<ProcedureUsageId>, BTreeMap<ProcedureUsageId, u64>) {
        let mut active = BTreeSet::new();
        let mut watermarks = BTreeMap::new();
        for (negative_id, (review, review_seq)) in &self.current_negative_reviews {
            let Some((negative, negative_seq)) = self.negative_evidence.get(negative_id) else {
                continue;
            };
            watermarks
                .entry(negative.procedure_usage_id)
                .and_modify(|watermark: &mut u64| {
                    *watermark = (*watermark).max(*negative_seq).max(*review_seq);
                })
                .or_insert((*negative_seq).max(*review_seq));
            if matches!(
                review.status,
                ProcedureNegativeReviewStatus::Pending | ProcedureNegativeReviewStatus::Upheld
            ) {
                active.insert(negative.procedure_usage_id);
            }
        }
        (active, watermarks)
    }

    pub(super) fn effect_rows(
        &self,
        episodes: &BTreeMap<RevisionId, (evertrace_domain::work::WorkEpisode, u64)>,
        snapshots: &BTreeMap<
            evertrace_domain::ids::WorktreeSnapshotId,
            (evertrace_domain::repository::WorktreeSnapshot, u64),
        >,
        worktrees: &BTreeMap<
            evertrace_domain::ids::WorktreeId,
            (evertrace_domain::repository::WorktreeInstance, u64),
        >,
        results: &BTreeMap<RevisionId, (evertrace_domain::semantic::ResultEvidence, u64)>,
        artifacts: &BTreeMap<RevisionId, (evertrace_domain::work::WorkArtifact, u64)>,
        generation: u64,
    ) -> Result<Vec<ObjectRow>, StoreError> {
        use evertrace_domain::{
            procedure::{
                ObservationalUsageInput, ProcedureContextAnchor, ProcedureEffectContext,
                ProcedureTruth,
            },
            semantic::{ConstraintBinding, ConstraintField, ConstraintValue},
        };

        let mut inputs = Vec::new();
        let mut cohort_watermarks = BTreeMap::new();
        let (active_negative_usages, negative_usage_watermarks) =
            self.effect_negative_usage_state();
        let current_artifacts = current_effect_artifacts(artifacts);
        for (usage, seq) in self.effect_usages() {
            let (episode, episode_seq) = episodes
                .get(&usage.exposure_episode_revision_id)
                .ok_or(StoreError::StoreCorrupt)?;
            if episode.task_id != usage.task_id
                || episode.workstream_id != usage.workstream_id
                || episode.repository_instance_id != usage.local_context.repository_id
                || episode.worktree_instance_id != usage.local_context.worktree_id
            {
                return Err(StoreError::StoreCorrupt);
            }
            let outcome_supported = usage.outcome_supported == ProcedureTruth::True;
            let revision = self
                .current_revision_by_id(usage.procedure_revision_id)
                .ok_or(StoreError::StoreCorrupt)?;
            let fields = revision.draft.applicability_expr.referenced_fields();
            let mut bindings = Vec::new();
            if fields.contains(&ConstraintField::Phase) {
                bindings.push(ConstraintBinding {
                    field: ConstraintField::Phase,
                    value: ConstraintValue::Text(effect_phase(usage.local_context.phase).into()),
                });
            }
            if fields.contains(&ConstraintField::FailureSignature)
                && let Some(value) = &usage.local_context.failure_signature
            {
                bindings.push(ConstraintBinding {
                    field: ConstraintField::FailureSignature,
                    value: ConstraintValue::Text(value.clone()),
                });
            }
            bindings.sort_by_key(|binding| binding.field);
            let anchor = match (
                usage.local_context.repository_id,
                usage.local_context.worktree_id,
            ) {
                (Some(repository_id), Some(worktree_id)) => {
                    let Some(snapshot_id) = episode.entry_worktree_snapshot_id else {
                        continue;
                    };
                    let snapshot = snapshots
                        .get(&snapshot_id)
                        .ok_or(StoreError::StoreCorrupt)?;
                    let worktree = worktrees
                        .get(&worktree_id)
                        .ok_or(StoreError::StoreCorrupt)?;
                    if snapshot.0.worktree_instance_id != worktree_id
                        || worktree.0.repository_instance_id != repository_id
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                    ProcedureContextAnchor::Repository {
                        repository_id,
                        worktree_id,
                        worktree_snapshot_id: snapshot_id,
                        worktree_lineage: worktree_id.to_string(),
                    }
                }
                (None, None) => {
                    let fixture_refs = observational_effect_refs(
                        usage,
                        episode,
                        results,
                        artifacts,
                        &current_artifacts,
                    );
                    if fixture_refs.is_empty() {
                        continue;
                    }
                    ProcedureContextAnchor::NonRepository { fixture_refs }
                }
                _ => return Err(StoreError::StoreCorrupt),
            };
            let context = ProcedureEffectContext {
                procedure_revision_id: usage.procedure_revision_id,
                task_id: usage.task_id,
                anchor,
                operands: bindings,
                phase_kind: usage.local_context.phase,
                failure_signature: usage.local_context.failure_signature.clone(),
                toolchain: "unknown".into(),
                model_revision: "unknown".into(),
                harness_revision: "unknown".into(),
                algorithm_revision: "unknown".into(),
                budget: 0,
                acceptance_boundary: usage.decision_boundary_ref.clone(),
            };
            context.validate().map_err(|_| StoreError::StoreCorrupt)?;
            let source_watermark = usage
                .source_watermark
                .max(seq)
                .max(*episode_seq)
                .max(
                    episode
                        .entry_worktree_snapshot_id
                        .and_then(|id| snapshots.get(&id).map(|(_, seq)| *seq))
                        .unwrap_or(0),
                )
                .max(
                    negative_usage_watermarks
                        .get(&usage.procedure_usage_id)
                        .copied()
                        .unwrap_or(0),
                );
            let fingerprint = context
                .fingerprint()
                .map_err(|_| StoreError::StoreCorrupt)?;
            cohort_watermarks
                .entry((usage.procedure_revision_id, fingerprint))
                .and_modify(|watermark: &mut u64| {
                    *watermark = (*watermark).max(source_watermark);
                })
                .or_insert(source_watermark);
            if !outcome_supported && !active_negative_usages.contains(&usage.procedure_usage_id) {
                continue;
            }
            inputs.push(ObservationalUsageInput {
                procedure_usage_id: usage.procedure_usage_id,
                context,
                outcome_supported,
                evidence_refs: usage.evidence_refs.clone(),
                source_watermark,
            });
        }
        evertrace_domain::procedure::compile_observational_effects(inputs)
            .map_err(|_| StoreError::StoreCorrupt)?
            .into_iter()
            .map(|mut projection| {
                if let Some(watermark) = cohort_watermarks.get(&(
                    projection.procedure_revision_id,
                    projection.context_fingerprint_hash,
                )) {
                    projection.source_watermark = projection.source_watermark.max(*watermark);
                }
                super::procedure_effect::row(projection, generation)
            })
            .collect()
    }

    pub(super) fn current_revision(
        &self,
        procedure_id: evertrace_domain::ids::ProcedureId,
    ) -> Option<&ProcedureRevision> {
        self.procedures
            .get(&procedure_id)
            .map(|(revision, _)| revision)
    }

    pub(super) fn current_revision_by_id(
        &self,
        revision_id: RevisionId,
    ) -> Option<&ProcedureRevision> {
        self.revisions
            .get(&revision_id)
            .map(|(revision, _)| revision)
    }

    pub(super) fn revisions_for_deletion(
        &self,
        procedure_id: evertrace_domain::ids::ProcedureId,
    ) -> impl Iterator<Item = &ProcedureRevision> {
        self.revisions
            .values()
            .map(|(revision, _)| revision)
            .filter(move |revision| revision.procedure_id == procedure_id)
    }

    pub(super) fn live_source_reference_strings(
        &self,
        excluded_revisions: &BTreeSet<RevisionId>,
    ) -> BTreeSet<String> {
        let mut refs = BTreeSet::new();
        for (revision, _) in self.procedures.values() {
            if !excluded_revisions.contains(&revision.revision_id) {
                refs.extend(revision.draft.evidence_refs.iter().cloned());
            }
        }
        for (event, _) in self.current_publication.values() {
            if !excluded_revisions.contains(&event.procedure_revision_id) {
                refs.extend(event.evidence_refs.iter().cloned());
            }
        }
        for (usage, _) in self.usages.values() {
            if !excluded_revisions.contains(&usage.procedure_revision_id) {
                refs.extend(usage.evidence_refs.iter().cloned());
            }
        }
        for (negative, _) in self.negative_evidence.values() {
            if !excluded_revisions.contains(&negative.procedure_revision_id) {
                refs.extend(negative.evidence_refs.iter().cloned());
            }
        }
        for (negative_id, (review, _)) in &self.current_negative_reviews {
            if self
                .negative_evidence
                .get(negative_id)
                .is_some_and(|(negative, _)| {
                    !excluded_revisions.contains(&negative.procedure_revision_id)
                })
            {
                refs.extend(review.evidence_refs.iter().cloned());
            }
        }
        refs
    }

    pub(super) fn apply(&mut self, payload: JournalPayload, seq: u64) -> Result<bool, StoreError> {
        match payload {
            JournalPayload::ProcedureRevisionRecorded(value) => {
                let value = *value;
                if let Some((current, _)) = self.procedures.get(&value.procedure_id) {
                    current
                        .validate_successor(&value)
                        .map_err(|_| StoreError::StoreCorrupt)?;
                } else if value.parent_revision_id.is_some() || value.revision_generation != 1 {
                    return Err(StoreError::StoreCorrupt);
                }
                if self
                    .revisions
                    .insert(value.revision_id, (value.clone(), seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                self.procedures.insert(value.procedure_id, (value, seq));
                Ok(true)
            }
            JournalPayload::ProcedureStateRecorded(value) => {
                let value = *value;
                validate_publication_event(
                    &self.revisions,
                    &self.events,
                    &self.current_publication,
                    &value,
                )?;
                if self
                    .events
                    .insert(value.state_event_id, (value.clone(), seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                self.current_publication
                    .insert(value.procedure_revision_id, (value, seq));
                Ok(true)
            }
            JournalPayload::ProcedureUsageRecorded(value) => {
                let value = *value;
                self.apply_usage(value, seq)
            }
            JournalPayload::ProcedureNegativeEvidenceRecorded(value) => {
                let value = *value;
                if !value.validate()
                    || self
                    .negative_evidence
                    .contains_key(&value.negative_evidence_id)
                    || !self.revisions.contains_key(&value.procedure_revision_id)
                    || self
                        .usages
                        .get(&value.procedure_usage_id)
                        .is_none_or(|(usage, _)| {
                            usage.procedure_revision_id != value.procedure_revision_id
                                || usage.task_id != value.task_id
                            || usage.action_aligned
                                != evertrace_domain::procedure::ProcedureTruth::True
                            || value.created_at_us < usage.created_at_us
                            || value.attribution_basis
                                == evertrace_domain::procedure::ProcedureAttributionBasis::ResolvedLocalized
                                && value.local_context.as_ref() != Some(&usage.local_context)
                    })
                {
                    return Err(StoreError::StoreCorrupt);
                }
                self.negative_evidence_by_revision
                    .entry(value.procedure_revision_id)
                    .or_default()
                    .insert(value.negative_evidence_id);
                self.negative_evidence
                    .insert(value.negative_evidence_id, (value, seq));
                Ok(true)
            }
            JournalPayload::ProcedureNegativeReviewRecorded(value) => {
                let value = *value;
                self.apply_negative_review(value, seq)
            }
            _ => Ok(false),
        }
    }

    pub(super) fn restore(&mut self, payload: JournalPayload, seq: u64) -> Result<(), StoreError> {
        match payload {
            JournalPayload::ProcedureRevisionRecorded(value) => {
                let value = *value;
                if self
                    .revisions
                    .insert(value.revision_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            JournalPayload::ProcedureStateRecorded(value) => {
                let value = *value;
                if self
                    .events
                    .insert(value.state_event_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            JournalPayload::ProcedureUsageRecorded(value) => {
                let value = *value;
                if self
                    .usage_revisions
                    .insert(value.usage_revision_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            JournalPayload::ProcedureNegativeEvidenceRecorded(value) => {
                let value = *value;
                let procedure_revision_id = value.procedure_revision_id;
                let negative_evidence_id = value.negative_evidence_id;
                if self
                    .negative_evidence
                    .insert(value.negative_evidence_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
                self.negative_evidence_by_revision
                    .entry(procedure_revision_id)
                    .or_default()
                    .insert(negative_evidence_id);
            }
            JournalPayload::ProcedureNegativeReviewRecorded(value) => {
                let value = *value;
                if self
                    .negative_reviews
                    .insert(value.review_event_id, (value, seq))
                    .is_some()
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            _ => return Err(StoreError::StoreCorrupt),
        }
        Ok(())
    }

    pub(super) fn rebuild(&mut self) -> Result<(), StoreError> {
        self.procedures.clear();
        let mut revisions = self.revisions.values().cloned().collect::<Vec<_>>();
        revisions.sort_by_key(|(value, _)| (value.procedure_id, value.revision_generation));
        for (value, seq) in revisions {
            value.validate().map_err(|_| StoreError::StoreCorrupt)?;
            if let Some((current, current_seq)) = self.procedures.get(&value.procedure_id) {
                current
                    .validate_successor(&value)
                    .map_err(|_| StoreError::StoreCorrupt)?;
                if seq <= *current_seq {
                    return Err(StoreError::StoreCorrupt);
                }
            } else if value.revision_generation != 1 || value.parent_revision_id.is_some() {
                return Err(StoreError::StoreCorrupt);
            }
            self.procedures.insert(value.procedure_id, (value, seq));
        }
        self.current_publication.clear();
        let mut applied_events = BTreeMap::new();
        let mut events = self.events.values().cloned().collect::<Vec<_>>();
        events.sort_by_key(|(_, seq)| *seq);
        for (event, seq) in events {
            let (_, revision_seq) = self
                .revisions
                .get(&event.procedure_revision_id)
                .ok_or(StoreError::StoreCorrupt)?;
            let previous = self.current_publication.get(&event.procedure_revision_id);
            if seq <= *revision_seq || previous.is_some_and(|entry| seq <= entry.1) {
                return Err(StoreError::StoreCorrupt);
            }
            validate_publication_event(
                &self.revisions,
                &applied_events,
                &self.current_publication,
                &event,
            )?;
            self.current_publication
                .insert(event.procedure_revision_id, (event.clone(), seq));
            applied_events.insert(event.state_event_id, (event, seq));
        }
        if self
            .revisions
            .keys()
            .any(|revision_id| !self.current_publication.contains_key(revision_id))
        {
            return Err(StoreError::StoreCorrupt);
        }
        self.usages.clear();
        let mut usage_revisions = self.usage_revisions.values().cloned().collect::<Vec<_>>();
        usage_revisions.sort_by_key(|(_, seq)| *seq);
        let stored_usage_revisions = std::mem::take(&mut self.usage_revisions);
        for (usage, seq) in usage_revisions {
            self.apply_usage(usage, seq)?;
        }
        if self.usage_revisions.len() != stored_usage_revisions.len() {
            return Err(StoreError::StoreCorrupt);
        }
        self.current_negative_reviews.clear();
        let mut reviews = self.negative_reviews.values().cloned().collect::<Vec<_>>();
        reviews.sort_by_key(|(_, seq)| *seq);
        let stored_reviews = std::mem::take(&mut self.negative_reviews);
        for (review, seq) in reviews {
            self.apply_negative_review(review, seq)?;
        }
        if self.negative_reviews.len() != stored_reviews.len()
            || self.negative_evidence.values().any(|(negative, _)| {
                !negative.validate()
                    || self
                        .usages
                        .get(&negative.procedure_usage_id)
                        .is_none_or(|(usage, _)| {
                            usage.procedure_revision_id != negative.procedure_revision_id
                                || usage.task_id != negative.task_id
                                || usage.action_aligned
                                    != evertrace_domain::procedure::ProcedureTruth::True
                        })
            })
        {
            return Err(StoreError::StoreCorrupt);
        }
        self.negative_evidence_by_revision.clear();
        for (negative_evidence_id, (negative, _)) in &self.negative_evidence {
            self.negative_evidence_by_revision
                .entry(negative.procedure_revision_id)
                .or_default()
                .insert(*negative_evidence_id);
        }
        Ok(())
    }

    fn apply_usage(&mut self, value: ProcedureUsageRevision, seq: u64) -> Result<bool, StoreError> {
        if !value.validate() || !self.revisions.contains_key(&value.procedure_revision_id) {
            return Err(StoreError::StoreCorrupt);
        }
        if let Some((current, current_seq)) = self.usages.get(&value.procedure_usage_id) {
            if seq <= *current_seq || !current.validate_successor(&value) {
                return Err(StoreError::StoreCorrupt);
            }
        } else if value.revision_generation != 1 || value.predecessor_revision_id.is_some() {
            return Err(StoreError::StoreCorrupt);
        }
        if self
            .usage_revisions
            .insert(value.usage_revision_id, (value.clone(), seq))
            .is_some()
        {
            return Err(StoreError::StoreCorrupt);
        }
        self.usages.insert(value.procedure_usage_id, (value, seq));
        Ok(true)
    }

    fn apply_negative_review(
        &mut self,
        value: ProcedureNegativeReviewEvent,
        seq: u64,
    ) -> Result<bool, StoreError> {
        if !value.validate()
            || !self
                .negative_evidence
                .contains_key(&value.negative_evidence_id)
        {
            return Err(StoreError::StoreCorrupt);
        }
        if let Some((current, current_seq)) = self
            .current_negative_reviews
            .get(&value.negative_evidence_id)
        {
            if seq <= *current_seq
                || value.created_at_us < current.created_at_us
                || value.predecessor_review_event_id != Some(current.review_event_id)
                || value.review_generation != current.review_generation + 1
                || !matches!(
                    (current.status, value.status),
                    (
                        ProcedureNegativeReviewStatus::Pending,
                        ProcedureNegativeReviewStatus::Upheld
                            | ProcedureNegativeReviewStatus::Dismissed
                            | ProcedureNegativeReviewStatus::Superseded
                    ) | (
                        ProcedureNegativeReviewStatus::Upheld,
                        ProcedureNegativeReviewStatus::Dismissed
                            | ProcedureNegativeReviewStatus::Superseded
                    )
                )
            {
                return Err(StoreError::StoreCorrupt);
            }
        } else {
            let negative = &self.negative_evidence[&value.negative_evidence_id].0;
            let usage = self
                .usage_revisions
                .values()
                .filter(|(usage, usage_seq)| {
                    usage.procedure_usage_id == negative.procedure_usage_id && *usage_seq < seq
                })
                .max_by_key(|(_, usage_seq)| *usage_seq)
                .map(|(usage, _)| usage)
                .ok_or(StoreError::StoreCorrupt)?;
            let mut expected_refs = negative.evidence_refs.clone();
            expected_refs.push(usage.usage_revision_id.to_string());
            expected_refs.sort();
            expected_refs.dedup();
            if value.review_generation != 1
                || value.status != ProcedureNegativeReviewStatus::Pending
                || value.created_at_us != negative.created_at_us
                || value.evidence_refs != expected_refs
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if self
            .negative_reviews
            .insert(value.review_event_id, (value.clone(), seq))
            .is_some()
        {
            return Err(StoreError::StoreCorrupt);
        }
        self.current_negative_reviews
            .insert(value.negative_evidence_id, (value, seq));
        Ok(true)
    }

    pub(super) fn rows(
        &self,
        generation: u64,
        support: &super::s23::S23State,
    ) -> Result<Vec<ObjectRow>, StoreError> {
        let mut rows = Vec::new();
        let support_states = support.successor_support_states();
        for (revision_id, (value, seq)) in &self.revisions {
            let payload = JournalPayload::ProcedureRevisionRecorded(Box::new(value.clone()));
            let (repository_id, worktree_id) = scope_columns(value.draft.scope);
            rows.push(ObjectRow {
                row_id: format!("object:procedure:{}:{revision_id}", value.procedure_id),
                row_kind: ObjectRowKind::Data,
                row_class: Some(ObjectRowClass::Object),
                object_family: Some(ObjectFamily::Procedure),
                object_kind: Some("procedure_revision".into()),
                object_id: Some(value.procedure_id.to_string()),
                current_revision_id: Some(revision_id.to_string()),
                lifecycle: Some("active".into()),
                epistemic: None,
                authority: None,
                publication_state: self
                    .current_publication
                    .get(revision_id)
                    .map(|entry| publication(entry.0.to_state).into()),
                support_state: support_states
                    .get(&revision_id.to_string())
                    .map(|state| (*state).to_owned()),
                project_id: None,
                repository_id,
                worktree_id,
                task_id: None,
                workstream_id: None,
                session_id: None,
                payload_json: Some(payload.canonical_json()?),
                source_event_seq: *seq,
                projection_generation: generation,
            });
        }
        for (event_id, (event, seq)) in &self.events {
            let revision = self
                .revisions
                .get(&event.procedure_revision_id)
                .ok_or(StoreError::StoreCorrupt)?;
            let payload = JournalPayload::ProcedureStateRecorded(Box::new(event.clone()));
            let (repository_id, worktree_id) = scope_columns(revision.0.draft.scope);
            rows.push(ObjectRow {
                row_id: format!("object:procedure_state:{event_id}"),
                row_kind: ObjectRowKind::Data,
                row_class: Some(ObjectRowClass::Object),
                object_family: Some(ObjectFamily::Procedure),
                object_kind: Some("procedure_state_event".into()),
                object_id: Some(format!("procedure_state:{}", event.procedure_revision_id)),
                current_revision_id: Some(event_id.to_string()),
                lifecycle: Some("active".into()),
                epistemic: None,
                authority: None,
                publication_state: Some(publication(event.to_state).into()),
                support_state: None,
                project_id: None,
                repository_id,
                worktree_id,
                task_id: None,
                workstream_id: None,
                session_id: None,
                payload_json: Some(payload.canonical_json()?),
                source_event_seq: *seq,
                projection_generation: generation,
            });
        }
        for (revision_id, (usage, seq)) in &self.usage_revisions {
            let payload = JournalPayload::ProcedureUsageRecorded(Box::new(usage.clone()));
            rows.push(ObjectRow {
                row_id: format!("object:procedure_usage:{revision_id}"),
                row_kind: ObjectRowKind::Data,
                row_class: Some(ObjectRowClass::Object),
                object_family: Some(ObjectFamily::Procedure),
                object_kind: Some("procedure_usage_revision".into()),
                object_id: Some(usage.procedure_usage_id.to_string()),
                current_revision_id: Some(revision_id.to_string()),
                lifecycle: Some("active".into()),
                epistemic: None,
                authority: None,
                publication_state: None,
                support_state: None,
                project_id: None,
                repository_id: usage.local_context.repository_id.map(|id| id.to_string()),
                worktree_id: usage.local_context.worktree_id.map(|id| id.to_string()),
                task_id: Some(usage.task_id.to_string()),
                workstream_id: Some(usage.workstream_id.to_string()),
                session_id: None,
                payload_json: Some(payload.canonical_json()?),
                source_event_seq: *seq,
                projection_generation: generation,
            });
        }
        for (negative_id, (negative, seq)) in &self.negative_evidence {
            let payload =
                JournalPayload::ProcedureNegativeEvidenceRecorded(Box::new(negative.clone()));
            rows.push(ObjectRow {
                row_id: format!("object:procedure_negative:{negative_id}"),
                row_kind: ObjectRowKind::Data,
                row_class: Some(ObjectRowClass::Object),
                object_family: Some(ObjectFamily::Procedure),
                object_kind: Some("procedure_negative_evidence".into()),
                object_id: Some(negative_id.to_string()),
                current_revision_id: Some(negative_id.to_string()),
                lifecycle: self
                    .current_negative_reviews
                    .get(negative_id)
                    .map(|(review, _)| match review.status {
                        ProcedureNegativeReviewStatus::Pending => "pending",
                        ProcedureNegativeReviewStatus::Upheld => "upheld",
                        ProcedureNegativeReviewStatus::Dismissed => "dismissed",
                        ProcedureNegativeReviewStatus::Superseded => "superseded",
                    })
                    .map(str::to_owned),
                epistemic: None,
                authority: None,
                publication_state: None,
                support_state: None,
                project_id: None,
                repository_id: negative
                    .local_context
                    .as_ref()
                    .and_then(|value| value.repository_id)
                    .map(|id| id.to_string()),
                worktree_id: negative
                    .local_context
                    .as_ref()
                    .and_then(|value| value.worktree_id)
                    .map(|id| id.to_string()),
                task_id: Some(negative.task_id.to_string()),
                workstream_id: None,
                session_id: Some(negative.session_id.clone()),
                payload_json: Some(payload.canonical_json()?),
                source_event_seq: *seq,
                projection_generation: generation,
            });
        }
        for (review_id, (review, seq)) in &self.negative_reviews {
            let negative = self
                .negative_evidence
                .get(&review.negative_evidence_id)
                .ok_or(StoreError::StoreCorrupt)?;
            let payload = JournalPayload::ProcedureNegativeReviewRecorded(Box::new(review.clone()));
            rows.push(ObjectRow {
                row_id: format!("object:procedure_negative_review:{review_id}"),
                row_kind: ObjectRowKind::Data,
                row_class: Some(ObjectRowClass::Object),
                object_family: Some(ObjectFamily::Procedure),
                object_kind: Some("procedure_negative_review".into()),
                object_id: Some(review.negative_evidence_id.to_string()),
                current_revision_id: Some(review_id.to_string()),
                lifecycle: Some(
                    match review.status {
                        ProcedureNegativeReviewStatus::Pending => "pending",
                        ProcedureNegativeReviewStatus::Upheld => "upheld",
                        ProcedureNegativeReviewStatus::Dismissed => "dismissed",
                        ProcedureNegativeReviewStatus::Superseded => "superseded",
                    }
                    .into(),
                ),
                epistemic: None,
                authority: None,
                publication_state: None,
                support_state: None,
                project_id: None,
                repository_id: negative
                    .0
                    .local_context
                    .as_ref()
                    .and_then(|value| value.repository_id)
                    .map(|id| id.to_string()),
                worktree_id: negative
                    .0
                    .local_context
                    .as_ref()
                    .and_then(|value| value.worktree_id)
                    .map(|id| id.to_string()),
                task_id: Some(negative.0.task_id.to_string()),
                workstream_id: None,
                session_id: Some(negative.0.session_id.clone()),
                payload_json: Some(payload.canonical_json()?),
                source_event_seq: *seq,
                projection_generation: generation,
            });
        }
        Ok(rows)
    }
}

fn validate_publication_event(
    revisions: &BTreeMap<RevisionId, (ProcedureRevision, u64)>,
    history: &BTreeMap<RevisionId, (ProcedureStateEvent, u64)>,
    current_publication: &BTreeMap<RevisionId, (ProcedureStateEvent, u64)>,
    event: &ProcedureStateEvent,
) -> Result<(), StoreError> {
    event.validate().map_err(|_| StoreError::StoreCorrupt)?;
    if !revisions.contains_key(&event.procedure_revision_id)
        || event.from_state
            != current_publication
                .get(&event.procedure_revision_id)
                .map(|entry| entry.0.to_state)
        || event.to_state == ProcedurePublicationState::ActiveProbationary
            && history.values().any(|(prior, _)| {
                prior.procedure_revision_id == event.procedure_revision_id
                    && prior.reason
                        == evertrace_domain::procedure::ProcedureStateReason::ConfirmedHarm
            })
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn scope_columns(scope: ProcedureScope) -> (Option<String>, Option<String>) {
    match scope {
        ProcedureScope::Worktree {
            repository_id,
            worktree_id,
        } => (
            Some(repository_id.to_string()),
            Some(worktree_id.to_string()),
        ),
        ProcedureScope::Repository { repository_id } => (Some(repository_id.to_string()), None),
        ProcedureScope::Global => (None, None),
    }
}

pub(super) const fn publication(state: ProcedurePublicationState) -> &'static str {
    match state {
        ProcedurePublicationState::ActiveProbationary => "active_probationary",
        ProcedurePublicationState::ReviewHold => "review_hold",
        ProcedurePublicationState::ActiveStable => "active_stable",
        ProcedurePublicationState::Suspended => "suspended",
        ProcedurePublicationState::RolledBack => "rolled_back",
        ProcedurePublicationState::Superseded => "superseded",
    }
}

fn current_effect_artifacts(
    artifacts: &BTreeMap<RevisionId, (evertrace_domain::work::WorkArtifact, u64)>,
) -> BTreeMap<evertrace_domain::ids::WorkArtifactId, RevisionId> {
    let mut current = BTreeMap::<_, (RevisionId, u64)>::new();
    for (revision_id, (artifact, seq)) in artifacts {
        current
            .entry(artifact.work_artifact_id)
            .and_modify(|value| {
                if value.1 < *seq {
                    *value = (*revision_id, *seq);
                }
            })
            .or_insert((*revision_id, *seq));
    }
    current
        .into_iter()
        .map(|(id, (revision, _))| (id, revision))
        .collect()
}

fn observational_effect_refs(
    usage: &evertrace_domain::procedure::ProcedureUsageRevision,
    episode: &evertrace_domain::work::WorkEpisode,
    results: &BTreeMap<RevisionId, (evertrace_domain::semantic::ResultEvidence, u64)>,
    artifacts: &BTreeMap<RevisionId, (evertrace_domain::work::WorkArtifact, u64)>,
    current_artifacts: &BTreeMap<evertrace_domain::ids::WorkArtifactId, RevisionId>,
) -> Vec<String> {
    use evertrace_domain::work::ArtifactActor;
    let actor = ArtifactActor::WorkEpisode(episode.episode_id);
    usage
        .evidence_refs
        .iter()
        .filter(|reference| {
            let explicit = effect_episode_refs(episode).any(|value| value == *reference);
            let Ok(revision_id) = reference.parse::<RevisionId>() else {
                return false;
            };
            if let Some((artifact, _)) = artifacts.get(&revision_id) {
                return explicit || effect_artifact_has_actor(artifact, actor);
            }
            results.get(&revision_id).is_some_and(|(result, _)| {
                explicit
                    || result.raw_artifact_refs.iter().any(|id| {
                        current_artifacts
                            .get(id)
                            .and_then(|revision| artifacts.get(revision))
                            .is_some_and(|(artifact, _)| effect_artifact_has_actor(artifact, actor))
                    })
            })
        })
        .cloned()
        .collect()
}

fn effect_artifact_has_actor(
    artifact: &evertrace_domain::work::WorkArtifact,
    actor: evertrace_domain::work::ArtifactActor,
) -> bool {
    artifact.revision.produced_by_refs.contains(&actor)
        || artifact.revision.consumed_by_refs.contains(&actor)
}

fn effect_episode_refs(
    episode: &evertrace_domain::work::WorkEpisode,
) -> impl Iterator<Item = &String> {
    episode
        .completed_outcome_refs
        .iter()
        .chain(&episode.selected_outcome_refs)
        .chain(&episode.verification_refs)
        .chain(&episode.semantic_digest_refs)
}

const fn effect_phase(value: evertrace_domain::procedure::ProcedureUsagePhase) -> &'static str {
    use evertrace_domain::procedure::ProcedureUsagePhase;
    match value {
        ProcedureUsagePhase::BeforeEntry => "before_entry",
        ProcedureUsagePhase::AtEntry => "at_entry",
        ProcedureUsagePhase::InProgress => "in_progress",
        ProcedureUsagePhase::RecoverableDeviation => "recoverable_deviation",
        ProcedureUsagePhase::AlreadyCompleted => "already_completed",
        ProcedureUsagePhase::Incompatible => "incompatible",
    }
}

#[cfg(test)]
mod tests {
    use evertrace_domain::{
        procedure::{
            ProcedureActions, ProcedureDone, ProcedureDraft, ProcedureKind, ProcedureStateReason,
            ProcedureWhen,
        },
        semantic::{ConstraintExpr, ConstraintField},
    };

    use super::*;

    fn revision(generation: u32, parent: Option<RevisionId>) -> ProcedureRevision {
        ProcedureRevision {
            procedure_id: ProcedureId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: parent,
            revision_generation: generation,
            draft: ProcedureDraft {
                scope: ProcedureScope::Global,
                title: "title".into(),
                summary: "summary".into(),
                kind: ProcedureKind::Workflow,
                when: ProcedureWhen {
                    goals: vec!["goal".into()],
                    targets: vec!["target".into()],
                    signals: vec!["signal".into()],
                    stage: "stage".into(),
                    requires: Vec::new(),
                    excludes: Vec::new(),
                },
                condition_ir_version: 1,
                applicability_expr: ConstraintExpr::Exists {
                    field: ConstraintField::Phase,
                },
                avoid_expr: ConstraintExpr::Exists {
                    field: ConstraintField::FailureSignature,
                },
                completion_expr: ConstraintExpr::Exists {
                    field: ConstraintField::VerifierState,
                },
                actions: ProcedureActions {
                    stages: vec!["stage".into()],
                    branches: Vec::new(),
                    avoid: Vec::new(),
                },
                done: ProcedureDone {
                    success: vec!["success".into()],
                    abort: vec!["abort".into()],
                    verify: vec!["verify".into()],
                },
                pitfalls: Vec::new(),
                evidence_refs: vec!["evidence".into()],
                support_revision_refs: vec![RevisionId::new_v7()],
            },
            source_watermark: 1,
            created_at_us: 1,
        }
    }

    fn state_event(
        revision_id: RevisionId,
        from_state: Option<ProcedurePublicationState>,
        to_state: ProcedurePublicationState,
        reason: ProcedureStateReason,
        created_at_us: i64,
    ) -> ProcedureStateEvent {
        ProcedureStateEvent {
            state_event_id: RevisionId::new_v7(),
            procedure_revision_id: revision_id,
            from_state,
            to_state,
            reason,
            resume_state: None,
            evidence_refs: vec!["evidence".into()],
            created_at_us,
        }
    }

    fn state_with_initial() -> (ProcedureState, ProcedureRevision) {
        let root = revision(1, None);
        let mut state = ProcedureState::default();
        state
            .apply(
                JournalPayload::ProcedureRevisionRecorded(Box::new(root.clone())),
                1,
            )
            .unwrap();
        state
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    None,
                    ProcedurePublicationState::ActiveProbationary,
                    ProcedureStateReason::Accepted,
                    1,
                ))),
                2,
            )
            .unwrap();
        (state, root)
    }

    #[test]
    fn restore_rebuild_rejects_orphan_revision_and_missing_initial_publication() {
        let mut state = ProcedureState::default();
        state
            .restore(
                JournalPayload::ProcedureRevisionRecorded(Box::new(revision(
                    2,
                    Some(RevisionId::new_v7()),
                ))),
                1,
            )
            .unwrap();
        assert!(state.rebuild().is_err());

        let root = revision(1, None);
        let mut state = ProcedureState::default();
        state
            .restore(
                JournalPayload::ProcedureRevisionRecorded(Box::new(root.clone())),
                1,
            )
            .unwrap();
        assert!(state.rebuild().is_err());
        state
            .restore(
                JournalPayload::ProcedureStateRecorded(Box::new(ProcedureStateEvent {
                    state_event_id: RevisionId::new_v7(),
                    procedure_revision_id: root.revision_id,
                    from_state: None,
                    to_state: ProcedurePublicationState::ActiveProbationary,
                    reason: ProcedureStateReason::Accepted,
                    resume_state: None,
                    evidence_refs: vec!["evidence".into()],
                    created_at_us: 1,
                })),
                2,
            )
            .unwrap();
        state.rebuild().unwrap();
    }

    #[test]
    fn restore_rebuild_rejects_child_revision_before_parent() {
        let root = revision(1, None);
        let mut child = root.clone();
        child.revision_id = RevisionId::new_v7();
        child.parent_revision_id = Some(root.revision_id);
        child.revision_generation = 2;
        child.draft.summary = "changed summary".into();
        child.source_watermark = 2;
        child.created_at_us = 2;
        let mut state = ProcedureState::default();
        state
            .restore(JournalPayload::ProcedureRevisionRecorded(Box::new(root)), 2)
            .unwrap();
        state
            .restore(
                JournalPayload::ProcedureRevisionRecorded(Box::new(child)),
                1,
            )
            .unwrap();
        assert!(state.rebuild().is_err());
    }

    #[test]
    fn restore_rebuild_rejects_initial_state_before_revision() {
        let root = revision(1, None);
        let mut state = ProcedureState::default();
        state
            .restore(
                JournalPayload::ProcedureRevisionRecorded(Box::new(root.clone())),
                2,
            )
            .unwrap();
        state
            .restore(
                JournalPayload::ProcedureStateRecorded(Box::new(ProcedureStateEvent {
                    state_event_id: RevisionId::new_v7(),
                    procedure_revision_id: root.revision_id,
                    from_state: None,
                    to_state: ProcedurePublicationState::ActiveProbationary,
                    reason: ProcedureStateReason::Accepted,
                    resume_state: None,
                    evidence_refs: vec!["evidence".into()],
                    created_at_us: 1,
                })),
                1,
            )
            .unwrap();
        assert!(state.rebuild().is_err());
    }

    #[test]
    fn restore_rebuild_rejects_non_increasing_state_sequence() {
        let root = revision(1, None);
        let first_event_id = "018f0000-0000-7000-8000-000000000001".parse().unwrap();
        let second_event_id = "018f0000-0000-7000-8000-000000000002".parse().unwrap();
        let mut state = ProcedureState::default();
        state
            .restore(
                JournalPayload::ProcedureRevisionRecorded(Box::new(root.clone())),
                1,
            )
            .unwrap();
        state
            .restore(
                JournalPayload::ProcedureStateRecorded(Box::new(ProcedureStateEvent {
                    state_event_id: first_event_id,
                    procedure_revision_id: root.revision_id,
                    from_state: None,
                    to_state: ProcedurePublicationState::ActiveProbationary,
                    reason: ProcedureStateReason::Accepted,
                    resume_state: None,
                    evidence_refs: vec!["evidence".into()],
                    created_at_us: 2,
                })),
                2,
            )
            .unwrap();
        state
            .restore(
                JournalPayload::ProcedureStateRecorded(Box::new(ProcedureStateEvent {
                    state_event_id: second_event_id,
                    procedure_revision_id: root.revision_id,
                    from_state: Some(ProcedurePublicationState::ActiveProbationary),
                    to_state: ProcedurePublicationState::ActiveStable,
                    reason: ProcedureStateReason::ObjectiveSuccesses,
                    resume_state: None,
                    evidence_refs: vec!["evidence".into()],
                    created_at_us: 3,
                })),
                2,
            )
            .unwrap();
        assert!(state.rebuild().is_err());
    }

    #[test]
    fn rollback_restores_non_harm_revision_and_harm_history_never_reactivates() {
        let (mut rollback, root) = state_with_initial();
        rollback
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    Some(ProcedurePublicationState::ActiveProbationary),
                    ProcedurePublicationState::Superseded,
                    ProcedureStateReason::Replaced,
                    2,
                ))),
                3,
            )
            .unwrap();
        rollback
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    Some(ProcedurePublicationState::Superseded),
                    ProcedurePublicationState::ActiveProbationary,
                    ProcedureStateReason::Rollback,
                    3,
                ))),
                4,
            )
            .unwrap();

        let (mut restored, root) = state_with_initial();
        restored
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    Some(ProcedurePublicationState::ActiveProbationary),
                    ProcedurePublicationState::Suspended,
                    ProcedureStateReason::SupportPending,
                    2,
                ))),
                3,
            )
            .unwrap();
        restored
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    Some(ProcedurePublicationState::Suspended),
                    ProcedurePublicationState::ActiveProbationary,
                    ProcedureStateReason::SupportRestored,
                    3,
                ))),
                4,
            )
            .unwrap();

        let (mut harmed, root) = state_with_initial();
        harmed
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    Some(ProcedurePublicationState::ActiveProbationary),
                    ProcedurePublicationState::Suspended,
                    ProcedureStateReason::ConfirmedHarm,
                    2,
                ))),
                3,
            )
            .unwrap();
        assert!(
            harmed
                .apply(
                    JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                        root.revision_id,
                        Some(ProcedurePublicationState::Suspended),
                        ProcedurePublicationState::ActiveProbationary,
                        ProcedureStateReason::SupportRestored,
                        3,
                    ))),
                    4,
                )
                .is_err()
        );
        harmed
            .apply(
                JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                    root.revision_id,
                    Some(ProcedurePublicationState::Suspended),
                    ProcedurePublicationState::Superseded,
                    ProcedureStateReason::Replaced,
                    4,
                ))),
                5,
            )
            .unwrap();
        assert!(
            harmed
                .apply(
                    JournalPayload::ProcedureStateRecorded(Box::new(state_event(
                        root.revision_id,
                        Some(ProcedurePublicationState::Superseded),
                        ProcedurePublicationState::ActiveProbationary,
                        ProcedureStateReason::Rollback,
                        5,
                    ))),
                    6,
                )
                .is_err()
        );
    }

    #[test]
    fn rebuild_rejects_reactivation_after_confirmed_harm() {
        let root = revision(1, None);
        let events = [
            state_event(
                root.revision_id,
                None,
                ProcedurePublicationState::ActiveProbationary,
                ProcedureStateReason::Accepted,
                1,
            ),
            state_event(
                root.revision_id,
                Some(ProcedurePublicationState::ActiveProbationary),
                ProcedurePublicationState::Suspended,
                ProcedureStateReason::ConfirmedHarm,
                2,
            ),
            state_event(
                root.revision_id,
                Some(ProcedurePublicationState::Suspended),
                ProcedurePublicationState::ActiveProbationary,
                ProcedureStateReason::SupportRestored,
                3,
            ),
        ];
        let mut state = ProcedureState::default();
        state
            .restore(JournalPayload::ProcedureRevisionRecorded(Box::new(root)), 1)
            .unwrap();
        for (offset, event) in events.into_iter().enumerate() {
            state
                .restore(
                    JournalPayload::ProcedureStateRecorded(Box::new(event)),
                    offset as u64 + 2,
                )
                .unwrap();
        }
        assert!(state.rebuild().is_err());
    }
}
