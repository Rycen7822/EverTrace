use super::procedure::NegativeReviewActionReason;
use super::*;

fn procedure_usage_scope_matches(
    scope: &evertrace_domain::procedure::ProcedureScope,
    usage: &evertrace_domain::procedure::ProcedureUsageRevision,
) -> bool {
    match scope {
        evertrace_domain::procedure::ProcedureScope::Global => true,
        evertrace_domain::procedure::ProcedureScope::Repository { repository_id } => {
            usage.local_context.repository_id == Some(*repository_id)
        }
        evertrace_domain::procedure::ProcedureScope::Worktree {
            repository_id,
            worktree_id,
        } => {
            usage.local_context.repository_id == Some(*repository_id)
                && usage.local_context.worktree_id == Some(*worktree_id)
        }
    }
}

fn independent_task_ids(
    tasks: &BTreeMap<evertrace_domain::ids::TaskId, (Task, u64)>,
    left_id: evertrace_domain::ids::TaskId,
    right_id: evertrace_domain::ids::TaskId,
) -> bool {
    let (Some((left, _)), Some((right, _))) = (tasks.get(&left_id), tasks.get(&right_id)) else {
        return false;
    };
    left_id != right_id
        && left.continuation_of_task_id.is_none()
        && left.split_from_task_id.is_none()
        && right.continuation_of_task_id.is_none()
        && right.split_from_task_id.is_none()
        && left
            .request_root_refs
            .iter()
            .all(|reference| !right.request_root_refs.contains(reference))
}

struct ProcedureHistoryIndex<'a> {
    bindings: BTreeMap<OperationId, Vec<(&'a WorkBindingRevision, u64)>>,
    attempts: BTreeMap<AttemptId, Vec<(&'a Attempt, u64)>>,
    operations: BTreeMap<OperationId, Vec<(&'a Operation, u64)>>,
    occurrences: BTreeMap<HostOccurrenceId, Vec<(&'a HostOccurrence, u64)>>,
    usages: BTreeMap<
        ProcedureUsageId,
        Vec<(&'a evertrace_domain::procedure::ProcedureUsageRevision, u64)>,
    >,
    reviews: BTreeMap<
        ProcedureNegativeEvidenceId,
        Vec<(
            &'a evertrace_domain::procedure::ProcedureNegativeReviewEvent,
            u64,
        )>,
    >,
    initial_usage_watermarks: BTreeMap<ProcedureUsageId, u64>,
}

impl<'a> ProcedureHistoryIndex<'a> {
    fn new(state: &'a JournalAdmissionState) -> Result<Self, StoreError> {
        current_binding_lineage(state.work_bindings.values().map(|(value, _)| value))?;
        let mut index = Self {
            bindings: BTreeMap::new(),
            attempts: BTreeMap::new(),
            operations: BTreeMap::new(),
            occurrences: BTreeMap::new(),
            usages: BTreeMap::new(),
            reviews: BTreeMap::new(),
            initial_usage_watermarks: BTreeMap::new(),
        };
        for (value, seq) in state.work_bindings.values() {
            index
                .bindings
                .entry(value.operation_id)
                .or_default()
                .push((value, *seq));
        }
        for (value, seq) in state.attempt_revisions.values() {
            index
                .attempts
                .entry(value.attempt_id)
                .or_default()
                .push((value, *seq));
        }
        for (value, seq) in state.operation_revisions.values() {
            index
                .operations
                .entry(value.operation_id)
                .or_default()
                .push((value, *seq));
        }
        for (value, seq) in state.host_occurrence_revisions.values() {
            index
                .occurrences
                .entry(value.host_occurrence_id)
                .or_default()
                .push((value, *seq));
        }
        for (value, seq) in state.procedure.usage_revision_entries() {
            index
                .initial_usage_watermarks
                .entry(value.procedure_usage_id)
                .and_modify(|watermark| *watermark = (*watermark).min(value.source_watermark))
                .or_insert(value.source_watermark);
            index
                .usages
                .entry(value.procedure_usage_id)
                .or_default()
                .push((value, seq));
        }
        for (value, seq) in state.procedure.negative_review_entries() {
            index
                .reviews
                .entry(value.negative_evidence_id)
                .or_default()
                .push((value, seq));
        }
        for rows in index.bindings.values_mut() {
            rows.sort_by_key(|(_, seq)| *seq);
            if rows
                .iter()
                .enumerate()
                .any(|(offset, (value, _))| value.revision_generation != offset as u64 + 1)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for rows in index.attempts.values_mut() {
            rows.sort_by_key(|(_, seq)| *seq);
            if rows
                .iter()
                .enumerate()
                .any(|(offset, (value, _))| value.revision_generation != offset as u64 + 1)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for rows in index.operations.values_mut() {
            rows.sort_by_key(|(_, seq)| *seq);
            if rows
                .iter()
                .enumerate()
                .any(|(offset, (value, _))| value.operation_revision != offset as u32 + 1)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for rows in index.occurrences.values_mut() {
            rows.sort_by_key(|(_, seq)| *seq);
            if rows
                .iter()
                .enumerate()
                .any(|(offset, (value, _))| value.normalization_revision != offset as u32 + 1)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for rows in index.usages.values_mut() {
            rows.sort_by_key(|(_, seq)| *seq);
            if rows
                .iter()
                .enumerate()
                .any(|(offset, (value, _))| value.revision_generation != offset as u32 + 1)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        for rows in index.reviews.values_mut() {
            rows.sort_by_key(|(_, seq)| *seq);
            if rows
                .iter()
                .enumerate()
                .any(|(offset, (value, _))| value.review_generation != offset as u32 + 1)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Ok(index)
    }

    fn before<T: 'a>(rows: &'a [(&'a T, u64)], seq: u64) -> Option<(&'a T, u64)> {
        rows.get(
            rows.partition_point(|(_, row_seq)| *row_seq < seq)
                .checked_sub(1)?,
        )
        .copied()
    }

    fn binding_before(
        &'a self,
        operation_id: OperationId,
        seq: u64,
    ) -> Option<(&'a WorkBindingRevision, u64)> {
        Self::before(self.bindings.get(&operation_id)?, seq)
    }

    fn attempt_before(&'a self, id: AttemptId, seq: u64) -> Option<(&'a Attempt, u64)> {
        Self::before(self.attempts.get(&id)?, seq)
    }

    fn operation_before(&'a self, id: OperationId, seq: u64) -> Option<(&'a Operation, u64)> {
        Self::before(self.operations.get(&id)?, seq)
    }

    fn occurrence_before(
        &'a self,
        id: HostOccurrenceId,
        seq: u64,
    ) -> Option<(&'a HostOccurrence, u64)> {
        Self::before(self.occurrences.get(&id)?, seq)
    }

    fn usage_before(
        &'a self,
        id: ProcedureUsageId,
        seq: u64,
    ) -> Option<(&'a evertrace_domain::procedure::ProcedureUsageRevision, u64)> {
        Self::before(self.usages.get(&id)?, seq)
    }

    fn review_before(
        &'a self,
        id: ProcedureNegativeEvidenceId,
        seq: u64,
    ) -> Option<(
        &'a evertrace_domain::procedure::ProcedureNegativeReviewEvent,
        u64,
    )> {
        Self::before(self.reviews.get(&id)?, seq)
    }
}

impl JournalAdmissionState {
    pub(super) fn validate_procedure_usage_command<'a>(
        &self,
        payloads: impl IntoIterator<Item = &'a JournalPayload>,
    ) -> Result<(), StoreError> {
        let payloads = payloads.into_iter().collect::<Vec<_>>();
        if !payloads.iter().any(|payload| {
            matches!(
                payload,
                JournalPayload::ProcedureUsageRecorded(_)
                    | JournalPayload::ProcedureNegativeEvidenceRecorded(_)
                    | JournalPayload::ProcedureNegativeReviewRecorded(_)
            )
        }) {
            return Ok(());
        }
        let history = ProcedureHistoryIndex::new(self)?;
        for usage in payloads.iter().filter_map(|payload| match payload {
            JournalPayload::ProcedureUsageRecorded(value) => Some(value.as_ref()),
            _ => None,
        }) {
            let procedure = self
                .procedure
                .revision(usage.procedure_revision_id)
                .ok_or(StoreError::StoreCorrupt)?;
            let task = self
                .tasks
                .get(&usage.task_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0
                .clone();
            let workstream = self
                .workstreams
                .get(&usage.workstream_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0
                .clone();
            let exposure = self
                .episode_revisions
                .get(&usage.exposure_episode_revision_id)
                .ok_or(StoreError::StoreCorrupt)?
                .0
                .clone();
            if workstream.task_id != task.task_id
                || exposure.task_id != task.task_id
                || exposure.workstream_id != workstream.workstream_id
                || exposure.phase_contract.acceptance_boundary != usage.decision_boundary_ref
                || !procedure_usage_scope_matches(&procedure.draft.scope, usage)
            {
                return Err(StoreError::StoreCorrupt);
            }
            if usage.revision_generation == 1 {
                let current_episode = self
                    .episodes
                    .get(&exposure.episode_id)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0
                    .clone();
                let active_publication = matches!(
                    self.procedure.publication(usage.procedure_revision_id),
                    Some(
                        evertrace_domain::procedure::ProcedurePublicationState::ActiveProbationary
                            | evertrace_domain::procedure::ProcedurePublicationState::ActiveStable
                    )
                );
                let global_support_valid = !matches!(
                    procedure.draft.scope,
                    evertrace_domain::procedure::ProcedureScope::Global
                ) || self
                    .s23
                    .successor_support_states()
                    .get(&usage.procedure_revision_id.to_string())
                    .is_some_and(|state| *state == "valid");
                if usage.source_watermark != self.frontier
                    || self.procedure.has_usage_anchor(usage)
                    || usage.stage != evertrace_domain::procedure::ProcedureUsageStage::Returned
                    || !usage.attempt_ids.is_empty()
                    || !usage.action_operation_refs.is_empty()
                    || !usage.verification_operation_refs.is_empty()
                    || !usage.work_binding_revision_refs.is_empty()
                    || !usage.scope_effect_refs.is_empty()
                    || usage.correlation_state
                        != evertrace_domain::procedure::ProcedureCorrelationState::Resolved
                    || usage.action_aligned != evertrace_domain::procedure::ProcedureTruth::False
                    || usage.verifier_aligned
                        != evertrace_domain::procedure::ProcedureTruth::Unknown
                    || usage.outcome_supported
                        != evertrace_domain::procedure::ProcedureTruth::Unknown
                    || !active_publication
                    || !global_support_valid
                    || usage.route_decision
                        == evertrace_domain::procedure::ProcedureUsageRouteDecision::Apply
                        && self
                            .procedure
                            .local_quarantined(usage.procedure_revision_id, &usage.local_context)
                    || task.lifecycle != evertrace_domain::work::TaskLifecycle::Active
                    || !task.scope_memberships.iter().any(|membership| {
                        membership.repository_instance_id == usage.local_context.repository_id
                            && usage.local_context.worktree_id.is_none_or(|worktree_id| {
                                membership.worktree_instance_ids.contains(&worktree_id)
                            })
                    })
                    || workstream.status.is_terminal()
                    || current_episode.revision_id != usage.exposure_episode_revision_id
                    || current_episode.lifecycle_status
                        != evertrace_domain::work::EpisodeLifecycle::Open
                    || workstream.active_episode_id != Some(exposure.episode_id)
                {
                    return Err(StoreError::StoreCorrupt);
                }
            } else if self
                .procedure
                .usage(usage.procedure_usage_id)
                .is_none_or(|current| {
                    current.usage_revision_id != usage.predecessor_revision_id.unwrap()
                        || usage.source_watermark != self.frontier
                        || usage.created_at_us < current.created_at_us
                })
            {
                return Err(StoreError::StoreCorrupt);
            }
            if usage.action_aligned == evertrace_domain::procedure::ProcedureTruth::True
                || usage.outcome_supported == evertrace_domain::procedure::ProcedureTruth::True
            {
                self.validate_procedure_physical_usage(usage, u64::MAX, &history)?;
            }
        }
        for negative in payloads.iter().filter_map(|payload| match payload {
            JournalPayload::ProcedureNegativeEvidenceRecorded(value) => Some(value.as_ref()),
            _ => None,
        }) {
            let target_usage = self
                .procedure
                .usage(negative.procedure_usage_id)
                .ok_or(StoreError::StoreCorrupt)?;
            let cross_context_repeated = self.procedure.negative_entries().any(|(prior, _)| {
                prior.procedure_revision_id == negative.procedure_revision_id
                    && prior.task_id != negative.task_id
                    && prior.level
                        == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                    && independent_task_ids(&self.tasks, prior.task_id, negative.task_id)
                    && history
                        .review_before(prior.negative_evidence_id, u64::MAX)
                        .is_some_and(|(review, _)| {
                            matches!(
                                review.status,
                                evertrace_domain::procedure::ProcedureNegativeReviewStatus::Pending
                                    | evertrace_domain::procedure::ProcedureNegativeReviewStatus::Upheld
                            )
                        })
                    && prior
                        .local_context
                        .as_ref()
                        .is_none_or(|context| !context.compatible(&target_usage.local_context))
            });
            self.validate_procedure_negative(negative, u64::MAX, cross_context_repeated, &history)?;
        }
        for review in payloads.iter().filter_map(|payload| match payload {
            JournalPayload::ProcedureNegativeReviewRecorded(value)
                if value.review_generation > 1 =>
            {
                Some(value.as_ref())
            }
            _ => None,
        }) {
            self.validate_procedure_review(review, u64::MAX, &history)?;
        }
        Ok(())
    }

    fn validate_procedure_physical_usage(
        &self,
        usage: &evertrace_domain::procedure::ProcedureUsageRevision,
        as_of_seq: u64,
        history: &ProcedureHistoryIndex<'_>,
    ) -> Result<(), StoreError> {
        let exposure_watermark = history
            .initial_usage_watermarks
            .get(&usage.procedure_usage_id)
            .copied()
            .unwrap_or(usage.source_watermark);
        let mut operation_ids = usage.action_operation_refs.clone();
        operation_ids.extend(usage.verification_operation_refs.iter().copied());
        operation_ids.sort();
        operation_ids.dedup();
        let mut adopted_attempt = None;
        for operation_id in &operation_ids {
            let (operation, operation_seq) = history
                .operation_before(*operation_id, as_of_seq)
                .ok_or(StoreError::StoreCorrupt)?;
            let (occurrence, _) = history
                .occurrence_before(operation.host_occurrence_id, as_of_seq)
                .ok_or(StoreError::StoreCorrupt)?;
            let (current_binding, _) = history
                .binding_before(*operation_id, as_of_seq)
                .ok_or(StoreError::StoreCorrupt)?;
            let referenced = usage
                .work_binding_revision_refs
                .iter()
                .filter_map(|id| {
                    self.work_bindings
                        .get(id)
                        .filter(|(_, seq)| *seq < as_of_seq)
                        .map(|(value, _)| value)
                })
                .filter(|value| value.operation_id == *operation_id)
                .collect::<Vec<_>>();
            let [binding] = referenced.as_slice() else {
                return Err(StoreError::StoreCorrupt);
            };
            let attempt_id = binding
                .primary_binding
                .attempt_id
                .ok_or(StoreError::StoreCorrupt)?;
            let (attempt, _) = history
                .attempt_before(attempt_id, as_of_seq)
                .ok_or(StoreError::StoreCorrupt)?;
            if adopted_attempt.is_some_and(|current| current != attempt_id) {
                return Err(StoreError::StoreCorrupt);
            }
            adopted_attempt = Some(attempt_id);
            let episode_id = binding
                .primary_binding
                .episode_id
                .ok_or(StoreError::StoreCorrupt)?;
            let matches_episode = |revision_id: &evertrace_domain::revision::RevisionId| {
                self.episode_revisions
                    .get(revision_id)
                    .is_some_and(|(episode, seq)| {
                        *seq < as_of_seq
                            && episode.episode_id == episode_id
                            && episode.task_id == usage.task_id
                            && episode.workstream_id == usage.workstream_id
                    })
            };
            let episode_matches = (!usage.action_operation_refs.contains(operation_id)
                || usage
                    .action_episode_revision_ids
                    .iter()
                    .any(matches_episode))
                && (!usage.verification_operation_refs.contains(operation_id)
                    || usage
                        .verification_episode_revision_ids
                        .iter()
                        .any(matches_episode));
            if operation_seq <= exposure_watermark
                || operation.pairing_state != evertrace_domain::evidence::PairingState::Paired
                || occurrence.correlation_strength
                    != evertrace_domain::evidence::CorrelationStrength::Exact
                || occurrence.normalization_state
                    == evertrace_domain::evidence::NormalizationState::NormalizationConflicted
                || occurrence.pairing_state != evertrace_domain::evidence::PairingState::Paired
                || occurrence.possible_duplicate_group_id.is_some()
                || current_binding.work_binding_revision_id != binding.work_binding_revision_id
                || binding.assignment_status != AssignmentStatus::Resolved
                || binding.primary_binding.task_id != Some(usage.task_id)
                || binding.primary_binding.workstream_id != Some(usage.workstream_id)
                || !episode_matches
                || !usage.accepts_adopted_attempt(attempt)
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if adopted_attempt.is_none()
            || usage.attempt_ids.as_slice() != adopted_attempt.as_slice()
            || usage.scope_effect_refs.iter().any(|scope_id| {
                self.scope_effects
                    .get(scope_id)
                    .is_none_or(|(effect, seq)| {
                        *seq >= as_of_seq
                            || !operation_ids.contains(&effect.operation_id)
                            || effect.repository_instance_id != usage.local_context.repository_id
                            || effect.worktree_instance_id != usage.local_context.worktree_id
                            || !usage.work_binding_revision_refs.iter().any(|binding_id| {
                                self.work_bindings.get(binding_id).is_some_and(
                                    |(binding, binding_seq)| {
                                        *binding_seq < as_of_seq
                                            && binding.operation_id == effect.operation_id
                                            && binding.scope_effect_refs.contains(scope_id)
                                    },
                                )
                            })
                    })
            })
        {
            return Err(StoreError::StoreCorrupt);
        }
        if usage.outcome_supported == evertrace_domain::procedure::ProcedureTruth::True {
            let (attempt, _) = history
                .attempt_before(adopted_attempt.unwrap(), as_of_seq)
                .ok_or(StoreError::StoreCorrupt)?;
            let verified_results = usage
                .evidence_refs
                .iter()
                .filter_map(|reference| {
                    reference
                        .parse::<evertrace_domain::revision::RevisionId>()
                        .ok()
                        .and_then(|id| self.result_evidence_revisions.get(&id))
                        .map(|(result, seq)| (reference, result, *seq))
                })
                .filter(|(_, result, seq)| {
                    *seq > exposure_watermark
                        && *seq < as_of_seq
                        && self
                            .experiment_run_revisions
                            .get(&result.experiment_run_revision_id)
                            .is_some_and(|(run, run_seq)| {
                                *run_seq < as_of_seq
                                    && run.run_id == result.experiment_run_id
                                    && run.attempt_id == adopted_attempt
                            })
                        && result.verifier_receipt.as_ref().is_some_and(|receipt| {
                            receipt.status == evertrace_domain::semantic::VerifierStatus::Passed
                        })
                })
                .collect::<Vec<_>>();
            if usage.verification_operation_refs.is_empty()
                || attempt.verification != AttemptVerification::Passed
                || attempt.outcome_refs.is_empty()
                || verified_results.is_empty()
                || verified_results
                    .iter()
                    .any(|(reference, _, _)| !attempt.outcome_refs.contains(reference))
            {
                return Err(StoreError::StoreCorrupt);
            }
        }
        Ok(())
    }

    fn validate_procedure_negative(
        &self,
        negative: &evertrace_domain::procedure::ProcedureNegativeEvidence,
        as_of_seq: u64,
        cross_context_repeated: bool,
        history: &ProcedureHistoryIndex<'_>,
    ) -> Result<(), StoreError> {
        use evertrace_domain::procedure::{ProcedureNegativeLevel, ProcedureTruth};

        let usage = history
            .usage_before(negative.procedure_usage_id, as_of_seq)
            .map(|(usage, _)| usage)
            .filter(|usage| {
                usage.procedure_revision_id == negative.procedure_revision_id
                    && usage.task_id == negative.task_id
                    && usage.action_aligned == ProcedureTruth::True
                    && negative.created_at_us >= usage.created_at_us
            })
            .ok_or(StoreError::StoreCorrupt)?;
        let [attempt_id] = usage.attempt_ids.as_slice() else {
            return Err(StoreError::StoreCorrupt);
        };
        let attempt = history
            .attempt_before(*attempt_id, as_of_seq)
            .map(|(attempt, _)| attempt)
            .filter(|attempt| usage.accepts_adopted_attempt(attempt))
            .ok_or(StoreError::StoreCorrupt)?;
        let exposure_watermark = history
            .initial_usage_watermarks
            .get(&usage.procedure_usage_id)
            .copied()
            .ok_or(StoreError::StoreCorrupt)?;
        let mut results = Vec::with_capacity(negative.evidence_refs.len());
        for reference in &negative.evidence_refs {
            let revision_id = reference
                .parse::<evertrace_domain::revision::RevisionId>()
                .map_err(|_| StoreError::StoreCorrupt)?;
            let (result, seq) = self
                .result_evidence_revisions
                .get(&revision_id)
                .filter(|(_, seq)| *seq < as_of_seq)
                .ok_or(StoreError::StoreCorrupt)?;
            let run = self
                .experiment_run_revisions
                .get(&result.experiment_run_revision_id)
                .filter(|(_, seq)| *seq < as_of_seq)
                .map(|(run, _)| run)
                .filter(|run| {
                    run.run_id == result.experiment_run_id && run.attempt_id == Some(*attempt_id)
                })
                .ok_or(StoreError::StoreCorrupt)?;
            let _ = run;
            if *seq <= exposure_watermark {
                return Err(StoreError::StoreCorrupt);
            }
            results.push(result);
        }
        if results.is_empty() {
            return Err(StoreError::StoreCorrupt);
        }
        let fact = evertrace_domain::procedure::classify_negative_fact(
            usage,
            attempt,
            &negative.evidence_refs,
            &results,
        )
        .ok_or(StoreError::StoreCorrupt)?;
        let procedure = self
            .procedure
            .revision_entry(usage.procedure_revision_id)
            .filter(|(_, seq)| *seq < as_of_seq)
            .map(|(procedure, _)| procedure)
            .ok_or(StoreError::StoreCorrupt)?;
        let fields = procedure.draft.applicability_expr.referenced_fields();
        let localizable = usage.correlation_state
            == evertrace_domain::procedure::ProcedureCorrelationState::Resolved
            && fields.iter().all(|field| {
                matches!(
                    field,
                    evertrace_domain::semantic::ConstraintField::Phase
                        | evertrace_domain::semantic::ConstraintField::FailureSignature
                )
            })
            && (!fields.contains(&evertrace_domain::semantic::ConstraintField::FailureSignature)
                || usage.local_context.failure_signature.is_some());
        let expected = evertrace_domain::procedure::derive_negative_classification(
            fact,
            localizable,
            cross_context_repeated,
        );
        let expected_observed = attempt
            .failure_signature
            .clone()
            .unwrap_or_else(|| "deterministic_reparse_mismatch".into());
        let expected_confounders = (expected.level == ProcedureNegativeLevel::SuspectedHarm)
            .then(|| String::from("causal_attribution_unconfirmed"))
            .into_iter()
            .collect::<Vec<_>>();
        if negative.level != expected.level
            || negative.attribution_basis != expected.attribution_basis
            || negative.decision_source != expected.decision_source
            || negative.local_context != expected.localized.then(|| usage.local_context.clone())
            || negative.observed_effect != expected_observed
            || negative.expected_effect != attempt.strategy_contract.expected_effect
            || negative.confounders != expected_confounders
        {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    fn validate_procedure_review(
        &self,
        review: &evertrace_domain::procedure::ProcedureNegativeReviewEvent,
        as_of_seq: u64,
        history: &ProcedureHistoryIndex<'_>,
    ) -> Result<(), StoreError> {
        use evertrace_domain::procedure::ProcedureNegativeReviewStatus;

        let (negative, negative_seq) = self
            .procedure
            .negative_entry(review.negative_evidence_id)
            .filter(|(_, seq)| *seq < as_of_seq)
            .ok_or(StoreError::StoreCorrupt)?;
        let (predecessor, predecessor_seq) = history
            .review_before(review.negative_evidence_id, as_of_seq)
            .ok_or(StoreError::StoreCorrupt)?;
        if review.review_generation <= 1
            || review.predecessor_review_event_id != Some(predecessor.review_event_id)
            || review.review_generation != predecessor.review_generation + 1
        {
            return Err(StoreError::StoreCorrupt);
        }
        let action =
            NegativeReviewActionReason::parse(&review.reason).ok_or(StoreError::StoreCorrupt)?;
        if action == NegativeReviewActionReason::ResolveAsIneffective {
            if predecessor.status
                != evertrace_domain::procedure::ProcedureNegativeReviewStatus::Pending
                || negative.level
                    != evertrace_domain::procedure::ProcedureNegativeLevel::Ineffective
                || review.status
                    != evertrace_domain::procedure::ProcedureNegativeReviewStatus::Dismissed
                || review.successor_usage_revision_id.is_some()
                || review.evidence_refs != negative.evidence_refs
            {
                return Err(StoreError::StoreCorrupt);
            }
            self.validate_procedure_negative(negative, negative_seq, false, history)?;
            return Ok(());
        }
        let usage = history
            .usage_before(negative.procedure_usage_id, negative_seq)
            .map(|(usage, _)| usage)
            .ok_or(StoreError::StoreCorrupt)?;
        let proof_usage = review
            .successor_usage_revision_id
            .map(|id| {
                let candidate = self
                    .procedure
                    .usage_revision(id)
                    .ok_or(StoreError::StoreCorrupt)?;
                history
                    .usage_before(candidate.procedure_usage_id, as_of_seq)
                    .filter(|(current, _)| current.usage_revision_id == id)
                    .map(|(current, _)| current)
                    .ok_or(StoreError::StoreCorrupt)
            })
            .transpose()?
            .unwrap_or(usage);
        let proof_after = negative_seq.max(predecessor_seq);
        let mut results = Vec::with_capacity(review.evidence_refs.len());
        for reference in &review.evidence_refs {
            let revision_id = reference
                .parse::<evertrace_domain::revision::RevisionId>()
                .map_err(|_| StoreError::StoreCorrupt)?;
            let result = self
                .result_evidence_revisions
                .get(&revision_id)
                .filter(|(_, seq)| *seq > proof_after && *seq < as_of_seq)
                .map(|(result, _)| result)
                .ok_or(StoreError::StoreCorrupt)?;
            let run = self
                .experiment_run_revisions
                .get(&result.experiment_run_revision_id)
                .filter(|(_, seq)| *seq < as_of_seq)
                .map(|(run, _)| run)
                .ok_or(StoreError::StoreCorrupt)?;
            if run.run_id != result.experiment_run_id
                || run
                    .attempt_id
                    .is_none_or(|attempt| !proof_usage.attempt_ids.contains(&attempt))
            {
                return Err(StoreError::StoreCorrupt);
            }
            results.push(result);
        }
        let valid = match action {
            NegativeReviewActionReason::DismissAttribution => {
                predecessor.status == ProcedureNegativeReviewStatus::Pending
                    && negative.level
                        == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                    && review.status == ProcedureNegativeReviewStatus::Dismissed
                    && review.successor_usage_revision_id.is_none()
                    && results.iter().all(|result| {
                        result.completeness
                            == evertrace_domain::semantic::EvidenceCompleteness::Complete
                            && result.failure.is_none()
                            && result.verifier_receipt.as_ref().is_some_and(|receipt| {
                                receipt.status == evertrace_domain::semantic::VerifierStatus::Passed
                            })
                    })
            }
            NegativeReviewActionReason::ConfirmHarm => {
                predecessor.status == ProcedureNegativeReviewStatus::Pending
                    && negative.level
                        == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                    && negative.local_context.is_none()
                    && review.status == ProcedureNegativeReviewStatus::Upheld
                    && review.successor_usage_revision_id.is_none()
                    && results.iter().all(|result| {
                        matches!(
                            result.failure,
                            Some(evertrace_domain::semantic::ResultFailure::Verifier(
                                evertrace_domain::semantic::VerifierFailureCode::DeterministicReparseMismatch
                            ))
                        )
                    })
            }
            NegativeReviewActionReason::SuccessorSuperseded => {
                if review.status != ProcedureNegativeReviewStatus::Superseded {
                    return Err(StoreError::StoreCorrupt);
                }
                let old = self
                    .procedure
                    .revision_entry(negative.procedure_revision_id)
                    .filter(|(_, seq)| *seq < as_of_seq)
                    .map(|(value, _)| value)
                    .ok_or(StoreError::StoreCorrupt)?;
                let successor = self
                    .procedure
                    .revision_entry(proof_usage.procedure_revision_id)
                    .filter(|(_, seq)| *seq < as_of_seq)
                    .map(|(value, _)| value)
                    .ok_or(StoreError::StoreCorrupt)?;
                proof_usage.procedure_usage_id != usage.procedure_usage_id
                    && proof_usage.outcome_supported
                        == evertrace_domain::procedure::ProcedureTruth::True
                    && proof_usage.local_context.compatible(&usage.local_context)
                    && successor.procedure_id == old.procedure_id
                    && successor.parent_revision_id == Some(old.revision_id)
                    && review
                        .evidence_refs
                        .iter()
                        .all(|reference| proof_usage.evidence_refs.contains(reference))
                    && results.iter().all(|result| {
                        result.failure.is_none()
                            && result.verifier_receipt.as_ref().is_some_and(|receipt| {
                                receipt.status
                                    == evertrace_domain::semantic::VerifierStatus::Passed
                            })
                    })
            }
            NegativeReviewActionReason::ResolveAsIneffective => false,
        };
        if results.is_empty() || !valid {
            return Err(StoreError::StoreCorrupt);
        }
        Ok(())
    }

    pub(super) fn validate_procedure_relations(&self) -> Result<(), StoreError> {
        enum AuditPoint<'a> {
            Usage(&'a evertrace_domain::procedure::ProcedureUsageRevision),
            Negative(&'a evertrace_domain::procedure::ProcedureNegativeEvidence),
            Review(&'a evertrace_domain::procedure::ProcedureNegativeReviewEvent),
            Stable(&'a evertrace_domain::procedure::ProcedureStateEvent),
        }

        let history = ProcedureHistoryIndex::new(self)?;
        let mut points = Vec::new();
        points.extend(
            self.procedure
                .usage_revision_entries()
                .map(|(value, seq)| (seq, 0_u8, AuditPoint::Usage(value))),
        );
        points.extend(
            self.procedure
                .negative_entries()
                .map(|(value, seq)| (seq, 1_u8, AuditPoint::Negative(value))),
        );
        points.extend(
            self.procedure
                .negative_review_entries()
                .map(|(value, seq)| (seq, 2_u8, AuditPoint::Review(value))),
        );
        points.extend(
            self.procedure
                .state_event_entries()
                .filter_map(|(value, seq)| {
                    (value.to_state
                == evertrace_domain::procedure::ProcedurePublicationState::ActiveStable
                && value.reason
                    == evertrace_domain::procedure::ProcedureStateReason::ObjectiveSuccesses)
                .then_some((seq, 3_u8, AuditPoint::Stable(value)))
                }),
        );
        points.sort_by_key(|(seq, rank, _)| (*seq, *rank));

        let mut successful_usages = BTreeMap::<
            evertrace_domain::revision::RevisionId,
            BTreeMap<ProcedureUsageId, &evertrace_domain::procedure::ProcedureUsageRevision>,
        >::new();
        let mut active_negatives = BTreeMap::<
            evertrace_domain::revision::RevisionId,
            BTreeMap<
                ProcedureNegativeEvidenceId,
                &evertrace_domain::procedure::ProcedureNegativeEvidence,
            >,
        >::new();
        let mut confirmed_revisions = BTreeSet::new();
        for (seq, _, point) in points {
            match point {
                AuditPoint::Usage(usage) => {
                    if usage.action_aligned == evertrace_domain::procedure::ProcedureTruth::True
                        || usage.outcome_supported
                            == evertrace_domain::procedure::ProcedureTruth::True
                    {
                        self.validate_procedure_physical_usage(usage, seq, &history)?;
                    }
                    let successes = successful_usages
                        .entry(usage.procedure_revision_id)
                        .or_default();
                    if usage.outcome_supported == evertrace_domain::procedure::ProcedureTruth::True
                    {
                        successes.insert(usage.procedure_usage_id, usage);
                    } else {
                        successes.remove(&usage.procedure_usage_id);
                    }
                }
                AuditPoint::Negative(negative) => {
                    let usage = history
                        .usage_before(negative.procedure_usage_id, seq)
                        .map(|(usage, _)| usage)
                        .ok_or(StoreError::StoreCorrupt)?;
                    let cross_context_repeated = active_negatives
                        .get(&negative.procedure_revision_id)
                        .into_iter()
                        .flat_map(BTreeMap::values)
                        .any(|prior| {
                            prior.task_id != negative.task_id
                            && prior.level
                                == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                            && independent_task_ids(&self.tasks, prior.task_id, negative.task_id)
                            && prior.local_context.as_ref().is_none_or(|context| {
                                !context.compatible(&usage.local_context)
                            })
                        });
                    self.validate_procedure_negative(
                        negative,
                        seq,
                        cross_context_repeated,
                        &history,
                    )?;
                    if negative.level
                        == evertrace_domain::procedure::ProcedureNegativeLevel::ConfirmedHarm
                    {
                        confirmed_revisions.insert(negative.procedure_revision_id);
                    }
                }
                AuditPoint::Review(review) => {
                    if review.review_generation > 1 {
                        self.validate_procedure_review(review, seq, &history)?;
                    }
                    let negative = self
                        .procedure
                        .negative_entry(review.negative_evidence_id)
                        .filter(|(_, negative_seq)| *negative_seq < seq)
                        .map(|(negative, _)| negative)
                        .ok_or(StoreError::StoreCorrupt)?;
                    if matches!(
                        review.status,
                        evertrace_domain::procedure::ProcedureNegativeReviewStatus::Pending
                            | evertrace_domain::procedure::ProcedureNegativeReviewStatus::Upheld
                    ) {
                        active_negatives
                            .entry(negative.procedure_revision_id)
                            .or_default()
                            .insert(review.negative_evidence_id, negative);
                    } else if let Some(bucket) =
                        active_negatives.get_mut(&negative.procedure_revision_id)
                    {
                        bucket.remove(&review.negative_evidence_id);
                    }
                }
                AuditPoint::Stable(event) => {
                    if confirmed_revisions.contains(&event.procedure_revision_id)
                        || active_negatives
                            .get(&event.procedure_revision_id)
                            .into_iter()
                            .flat_map(BTreeMap::values)
                            .any(|negative| {
                                negative.level
                                    != evertrace_domain::procedure::ProcedureNegativeLevel::Ineffective
                            })
                    {
                        return Err(StoreError::StoreCorrupt);
                    }
                    let successes = successful_usages
                        .get(&event.procedure_revision_id)
                        .into_iter()
                        .flat_map(BTreeMap::values)
                        .filter(|usage| {
                            event
                                .evidence_refs
                                .contains(&usage.usage_revision_id.to_string())
                        })
                        .copied()
                        .collect::<Vec<_>>();
                    if successes.len() != 3 || event.evidence_refs.len() != 3 {
                        return Err(StoreError::StoreCorrupt);
                    }
                    for (index, usage) in successes.iter().enumerate() {
                        if successes[..index].iter().any(|other| {
                            !independent_task_ids(&self.tasks, other.task_id, usage.task_id)
                        }) {
                            return Err(StoreError::StoreCorrupt);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
