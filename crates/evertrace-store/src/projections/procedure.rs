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
        payloads: impl IntoIterator<Item = &'a JournalPayload>,
    ) -> Result<(), StoreError> {
        let payloads = payloads.into_iter().collect::<Vec<_>>();
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
            let expected = if matches!(
                review.status,
                ProcedureNegativeReviewStatus::Dismissed
                    | ProcedureNegativeReviewStatus::Superseded
            ) && negative.local_context.is_none()
                && self
                    .current_publication
                    .get(&negative.procedure_revision_id)
                    .is_some_and(|(event, _)| {
                        event.to_state == ProcedurePublicationState::ReviewHold
                    }) {
                let held = &self.current_publication[&negative.procedure_revision_id].0;
                Some(
                    held.resume_state
                        .filter(|state| {
                            matches!(
                                state,
                                ProcedurePublicationState::ActiveProbationary
                                    | ProcedurePublicationState::ActiveStable
                            )
                        })
                        .ok_or(StoreError::StoreCorrupt)?,
                )
            } else {
                None
            };
            let states = payloads
                .iter()
                .filter_map(|payload| match payload {
                    JournalPayload::ProcedureStateRecorded(event)
                        if event.procedure_revision_id == negative.procedure_revision_id
                            && event.from_state == Some(ProcedurePublicationState::ReviewHold)
                            && event.reason
                                == evertrace_domain::procedure::ProcedureStateReason::Manual
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
            if payloads.iter().filter(|payload| {
                matches!(payload,
                    JournalPayload::ProcedureNegativeEvidenceRecorded(negative)
                        if negative.procedure_revision_id == state.procedure_revision_id
                            && state.evidence_refs == vec![negative.negative_evidence_id.to_string()])
            }).count() != 1 {
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
