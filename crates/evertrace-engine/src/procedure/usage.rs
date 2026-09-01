use super::*;

#[derive(Clone, Debug, Default)]
pub struct ProcedureUsageCurrentView {
    frontier: u64,
    procedures: std::collections::BTreeMap<RevisionId, ProcedureRevision>,
    current_procedures: std::collections::BTreeMap<ProcedureId, RevisionId>,
    procedure_support: std::collections::BTreeMap<RevisionId, Option<String>>,
    publications: std::collections::BTreeMap<RevisionId, (ProcedureStateEvent, u64)>,
    tasks: std::collections::BTreeMap<evertrace_domain::ids::TaskId, evertrace_domain::work::Task>,
    workstreams: std::collections::BTreeMap<
        evertrace_domain::ids::WorkstreamId,
        evertrace_domain::work::Workstream,
    >,
    bindings: std::collections::BTreeMap<
        evertrace_domain::ids::WorkBindingRevisionId,
        evertrace_domain::work::WorkBindingRevision,
    >,
    current_bindings_by_operation: std::collections::BTreeMap<
        evertrace_domain::ids::OperationId,
        evertrace_domain::ids::WorkBindingRevisionId,
    >,
    attempts: std::collections::BTreeMap<
        evertrace_domain::ids::AttemptId,
        evertrace_domain::work::Attempt,
    >,
    runs: std::collections::BTreeMap<
        evertrace_domain::ids::ExperimentRunId,
        (evertrace_domain::work::ExperimentRun, u64),
    >,
    results: std::collections::BTreeMap<RevisionId, evertrace_domain::semantic::ResultEvidence>,
    result_seqs: std::collections::BTreeMap<RevisionId, u64>,
    episodes: std::collections::BTreeMap<RevisionId, evertrace_domain::work::WorkEpisode>,
    current_episode_revisions:
        std::collections::BTreeMap<evertrace_domain::ids::WorkEpisodeId, RevisionId>,
    operations: std::collections::BTreeMap<
        evertrace_domain::ids::OperationId,
        (evertrace_domain::evidence::Operation, u64),
    >,
    host_occurrences: std::collections::BTreeMap<
        evertrace_domain::ids::HostOccurrenceId,
        (evertrace_domain::evidence::HostOccurrence, u64),
    >,
    scope_effects: std::collections::BTreeMap<
        evertrace_domain::ids::ScopeEffectId,
        evertrace_domain::evidence::ScopeEffect,
    >,
    usages: std::collections::BTreeMap<
        evertrace_domain::ids::ProcedureUsageId,
        evertrace_domain::procedure::ProcedureUsageRevision,
    >,
    usage_exposure_watermarks:
        std::collections::BTreeMap<evertrace_domain::ids::ProcedureUsageId, u64>,
    negatives: std::collections::BTreeMap<
        evertrace_domain::ids::ProcedureNegativeEvidenceId,
        evertrace_domain::procedure::ProcedureNegativeEvidence,
    >,
    negative_seqs:
        std::collections::BTreeMap<evertrace_domain::ids::ProcedureNegativeEvidenceId, u64>,
    negative_reviews: std::collections::BTreeMap<
        evertrace_domain::ids::ProcedureNegativeEvidenceId,
        evertrace_domain::procedure::ProcedureNegativeReviewEvent,
    >,
    negative_review_seqs:
        std::collections::BTreeMap<evertrace_domain::ids::ProcedureNegativeEvidenceId, u64>,
    quarantines: std::collections::BTreeMap<
        RevisionId,
        Vec<evertrace_domain::procedure::ProcedureLocalContext>,
    >,
}

impl ProcedureUsageCurrentView {
    pub(crate) fn current_procedure_by_revision(
        &self,
        revision_id: RevisionId,
    ) -> Option<&ProcedureRevision> {
        let procedure = self.procedures.get(&revision_id)?;
        (self.current_procedures.get(&procedure.procedure_id) == Some(&revision_id))
            .then_some(procedure)
    }

    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, SemanticServiceError> {
        let mut view = Self {
            frontier: snapshot.frontier,
            ..Self::default()
        };
        for row in snapshot.data_rows() {
            if !matches!(
                row.object_kind.as_deref(),
                Some(
                    "procedure_revision"
                        | "procedure_state_event"
                        | "task"
                        | "workstream"
                        | "work_binding"
                        | "attempt"
                        | "experiment_run"
                        | "result_evidence"
                        | "work_episode"
                        | "host_occurrence"
                        | "operation"
                        | "scope_effect"
                        | "procedure_usage_revision"
                        | "procedure_negative_evidence"
                        | "procedure_negative_review"
                )
            ) {
                continue;
            }
            let Some(payload_json) = row.payload_json.as_deref() else {
                return Err(SemanticServiceError::InvalidInput);
            };
            let payload: JournalPayload = serde_json::from_str(payload_json)
                .map_err(|_| SemanticServiceError::InvalidInput)?;
            match payload {
                JournalPayload::ProcedureRevisionRecorded(value) => {
                    let current = view
                        .current_procedures
                        .get(&value.procedure_id)
                        .and_then(|revision_id| view.procedures.get(revision_id));
                    if current.is_some_and(|current| {
                        current.revision_generation == value.revision_generation
                            && current.revision_id != value.revision_id
                    }) {
                        return Err(SemanticServiceError::InvalidInput);
                    }
                    let replace = current.is_none_or(|current| {
                        current.revision_generation < value.revision_generation
                    });
                    view.procedure_support
                        .insert(value.revision_id, row.support_state.clone());
                    if replace {
                        view.current_procedures
                            .insert(value.procedure_id, value.revision_id);
                    }
                    view.procedures.insert(value.revision_id, *value);
                }
                JournalPayload::ProcedureStateRecorded(value) => {
                    if view
                        .publications
                        .get(&value.procedure_revision_id)
                        .is_none_or(|(_, seq)| *seq < row.source_event_seq)
                    {
                        view.publications
                            .insert(value.procedure_revision_id, (*value, row.source_event_seq));
                    }
                }
                JournalPayload::TaskRecorded(value) => {
                    if view.tasks.get(&value.task_id).is_some_and(|current| {
                        current.source_watermark == value.source_watermark
                            && current.revision_id != value.revision_id
                    }) {
                        return Err(SemanticServiceError::InvalidInput);
                    }
                    if view
                        .tasks
                        .get(&value.task_id)
                        .is_none_or(|current| current.source_watermark < value.source_watermark)
                    {
                        view.tasks.insert(value.task_id, *value);
                    }
                }
                JournalPayload::WorkstreamRecorded(value) => {
                    if view
                        .workstreams
                        .get(&value.workstream_id)
                        .is_some_and(|current| {
                            current.source_watermark == value.source_watermark
                                && current.revision_id != value.revision_id
                        })
                    {
                        return Err(SemanticServiceError::InvalidInput);
                    }
                    if view
                        .workstreams
                        .get(&value.workstream_id)
                        .is_none_or(|current| current.source_watermark < value.source_watermark)
                    {
                        view.workstreams.insert(value.workstream_id, *value);
                    }
                }
                JournalPayload::WorkBindingRecorded(value) => {
                    if view
                        .current_bindings_by_operation
                        .get(&value.operation_id)
                        .and_then(|id| view.bindings.get(id))
                        .is_some_and(|current| {
                            current.revision_generation == value.revision_generation
                                && current.work_binding_revision_id
                                    != value.work_binding_revision_id
                        })
                    {
                        return Err(SemanticServiceError::InvalidInput);
                    }
                    let replace = view
                        .current_bindings_by_operation
                        .get(&value.operation_id)
                        .and_then(|id| view.bindings.get(id))
                        .is_none_or(|current| {
                            current.revision_generation < value.revision_generation
                        });
                    if replace {
                        view.current_bindings_by_operation
                            .insert(value.operation_id, value.work_binding_revision_id);
                    }
                    view.bindings.insert(value.work_binding_revision_id, *value);
                }
                JournalPayload::AttemptRecorded(value) => {
                    let replace = view.attempts.get(&value.attempt_id).is_none_or(|current| {
                        current.revision_generation < value.revision_generation
                    });
                    if view.attempts.get(&value.attempt_id).is_some_and(|current| {
                        current.revision_generation == value.revision_generation
                            && current.revision_id != value.revision_id
                    }) {
                        return Err(SemanticServiceError::InvalidInput);
                    }
                    if replace {
                        view.attempts.insert(value.attempt_id, *value);
                    }
                }
                JournalPayload::ExperimentRunRecorded(value) => {
                    let replace = view.runs.get(&value.run_id).is_none_or(|(current, seq)| {
                        current.created_at_us < value.created_at_us
                            || current.created_at_us == value.created_at_us
                                && *seq < row.source_event_seq
                    });
                    if replace {
                        view.runs
                            .insert(value.run_id, (*value, row.source_event_seq));
                    }
                }
                JournalPayload::ResultEvidenceRecorded(value) => {
                    view.result_seqs
                        .insert(value.revision_id, row.source_event_seq);
                    view.results.insert(value.revision_id, *value);
                }
                JournalPayload::WorkEpisodeRecorded(value) => {
                    if view
                        .current_episode_revisions
                        .get(&value.episode_id)
                        .and_then(|revision| view.episodes.get(revision))
                        .is_some_and(|current| {
                            current.revision_generation == value.revision_generation
                                && current.revision_id != value.revision_id
                        })
                    {
                        return Err(SemanticServiceError::InvalidInput);
                    }
                    if view
                        .current_episode_revisions
                        .get(&value.episode_id)
                        .and_then(|revision| view.episodes.get(revision))
                        .is_none_or(|current| {
                            current.revision_generation < value.revision_generation
                        })
                    {
                        view.current_episode_revisions
                            .insert(value.episode_id, value.revision_id);
                    }
                    view.episodes.insert(value.revision_id, *value);
                }
                JournalPayload::OperationDerived(value) => {
                    if view
                        .operations
                        .get(&value.operation_id)
                        .is_none_or(|(current, seq)| {
                            current.operation_revision < value.operation_revision
                                || current.operation_revision == value.operation_revision
                                    && *seq < row.source_event_seq
                        })
                    {
                        view.operations
                            .insert(value.operation_id, (*value, row.source_event_seq));
                    }
                }
                JournalPayload::HostOccurrenceNormalized(value) => {
                    if view
                        .host_occurrences
                        .get(&value.host_occurrence_id)
                        .is_none_or(|(current, seq)| {
                            current.normalization_revision < value.normalization_revision
                                || current.normalization_revision == value.normalization_revision
                                    && *seq < row.source_event_seq
                        })
                    {
                        view.host_occurrences
                            .insert(value.host_occurrence_id, (*value, row.source_event_seq));
                    }
                }
                JournalPayload::ScopeEffectDerived(value) => {
                    view.scope_effects.insert(value.scope_effect_id, *value);
                }
                JournalPayload::ProcedureUsageRecorded(value) => {
                    view.usage_exposure_watermarks
                        .entry(value.procedure_usage_id)
                        .and_modify(|watermark| {
                            *watermark = (*watermark).min(value.source_watermark)
                        })
                        .or_insert(value.source_watermark);
                    if view
                        .usages
                        .get(&value.procedure_usage_id)
                        .is_some_and(|current| {
                            current.revision_generation == value.revision_generation
                                && current.usage_revision_id != value.usage_revision_id
                        })
                    {
                        return Err(SemanticServiceError::InvalidInput);
                    }
                    let replace =
                        view.usages
                            .get(&value.procedure_usage_id)
                            .is_none_or(|current| {
                                current.revision_generation < value.revision_generation
                            });
                    if replace {
                        view.usages.insert(value.procedure_usage_id, *value);
                    }
                }
                JournalPayload::ProcedureNegativeEvidenceRecorded(value) => {
                    view.negative_seqs
                        .insert(value.negative_evidence_id, row.source_event_seq);
                    view.negatives.insert(value.negative_evidence_id, *value);
                }
                JournalPayload::ProcedureNegativeReviewRecorded(value) => {
                    if view
                        .negative_reviews
                        .get(&value.negative_evidence_id)
                        .is_some_and(|current| {
                            current.review_generation == value.review_generation
                                && current.review_event_id != value.review_event_id
                        })
                    {
                        return Err(SemanticServiceError::InvalidInput);
                    }
                    let replace = view
                        .negative_reviews
                        .get(&value.negative_evidence_id)
                        .is_none_or(|current| current.review_generation < value.review_generation);
                    if replace {
                        view.negative_review_seqs
                            .insert(value.negative_evidence_id, row.source_event_seq);
                        view.negative_reviews
                            .insert(value.negative_evidence_id, *value);
                    }
                }
                _ => {}
            }
        }
        for negative in view.negatives.values() {
            if negative.level == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                && view
                    .negative_reviews
                    .get(&negative.negative_evidence_id)
                    .is_some_and(|review| {
                        matches!(
                            review.status,
                            evertrace_domain::procedure::ProcedureNegativeReviewStatus::Pending
                                | evertrace_domain::procedure::ProcedureNegativeReviewStatus::Upheld
                        )
                    })
                && let Some(context) = &negative.local_context
            {
                view.quarantines
                    .entry(negative.procedure_revision_id)
                    .or_default()
                    .push(context.clone());
            }
        }
        Ok(view)
    }

    pub fn local_quarantined(
        &self,
        procedure_revision_id: RevisionId,
        context: &evertrace_domain::procedure::ProcedureLocalContext,
    ) -> bool {
        self.quarantines
            .get(&procedure_revision_id)
            .is_some_and(|values| values.iter().any(|value| value.compatible(context)))
    }

    fn has_local_quarantine(&self, procedure_revision_id: RevisionId) -> bool {
        self.quarantines
            .get(&procedure_revision_id)
            .is_some_and(|values| !values.is_empty())
    }
}

#[derive(Clone, Debug)]
pub struct ProcedureUsageAdvance {
    pub usage_id: evertrace_domain::ids::ProcedureUsageId,
    pub stage: evertrace_domain::procedure::ProcedureUsageStage,
    pub attempt_ids: Vec<evertrace_domain::ids::AttemptId>,
    pub action_episode_revision_ids: Vec<RevisionId>,
    pub verification_episode_revision_ids: Vec<RevisionId>,
    pub action_operation_refs: Vec<evertrace_domain::ids::OperationId>,
    pub verification_operation_refs: Vec<evertrace_domain::ids::OperationId>,
    pub work_binding_revision_refs: Vec<evertrace_domain::ids::WorkBindingRevisionId>,
    pub scope_effect_refs: Vec<evertrace_domain::ids::ScopeEffectId>,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ProcedureNegativeRequest {
    pub procedure_usage_id: evertrace_domain::ids::ProcedureUsageId,
    pub session_id: String,
    pub result_revision_ids: Vec<RevisionId>,
}

#[derive(Debug)]
pub enum ProcedureNegativeResolution {
    NoDelta,
    Command {
        level: evertrace_domain::procedure::ProcedureNegativeLevel,
        command: JournalCommand,
    },
}

#[derive(Clone, Debug)]
pub enum ProcedureNegativeReviewProof {
    IneffectiveResolved {
        result_revision_ids: Vec<RevisionId>,
    },
    ReplayDismissed {
        result_revision_ids: Vec<RevisionId>,
    },
    ReplayUpheld {
        result_revision_ids: Vec<RevisionId>,
    },
    SuccessorSuperseded {
        successor_usage_id: evertrace_domain::ids::ProcedureUsageId,
        result_revision_ids: Vec<RevisionId>,
    },
    RequestRevision {
        procedure_revision_id: RevisionId,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProcedureNegativeReviewDecision {
    ResolveAsIneffective,
    DismissAttribution,
    ConfirmHarm,
    RequestRevision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcedureNegativeReviewAction {
    ResolveAsIneffective,
    DismissAttribution,
    ConfirmHarm,
    SuccessorSuperseded,
}

impl ProcedureNegativeReviewAction {
    const fn reason(self) -> &'static str {
        match self {
            Self::ResolveAsIneffective => "resolve_as_ineffective",
            Self::DismissAttribution => "dismiss_attribution",
            Self::ConfirmHarm => "confirm_harm",
            Self::SuccessorSuperseded => "successor_replay_fixed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProcedureNegativeReviewSelection {
    pub review_revision_id: RevisionId,
    pub review_status: evertrace_domain::procedure::ProcedureNegativeReviewStatus,
    pub available_decisions: Vec<ProcedureNegativeReviewDecision>,
    resolve_as_ineffective: Option<ProcedureNegativeReviewProof>,
    dismiss_attribution: Option<ProcedureNegativeReviewProof>,
    confirm_harm: Option<ProcedureNegativeReviewProof>,
    request_revision: Option<ProcedureNegativeReviewProof>,
}

impl ProcedureNegativeReviewSelection {
    pub fn proof(
        &self,
        decision: ProcedureNegativeReviewDecision,
    ) -> Option<ProcedureNegativeReviewProof> {
        match decision {
            ProcedureNegativeReviewDecision::ResolveAsIneffective => {
                self.resolve_as_ineffective.clone()
            }
            ProcedureNegativeReviewDecision::DismissAttribution => self.dismiss_attribution.clone(),
            ProcedureNegativeReviewDecision::ConfirmHarm => self.confirm_harm.clone(),
            ProcedureNegativeReviewDecision::RequestRevision => self.request_revision.clone(),
        }
    }
}

impl ProcedureUsageCurrentView {
    pub fn select_negative_review(
        &self,
        negative_evidence_id: evertrace_domain::ids::ProcedureNegativeEvidenceId,
    ) -> Result<ProcedureNegativeReviewSelection, SemanticServiceError> {
        let negative = self
            .negatives
            .get(&negative_evidence_id)
            .ok_or(SemanticServiceError::InvalidInput)?;
        let review = self
            .negative_reviews
            .get(&negative_evidence_id)
            .ok_or(SemanticServiceError::InvalidInput)?;
        if matches!(
            review.status,
            evertrace_domain::procedure::ProcedureNegativeReviewStatus::Upheld
                | evertrace_domain::procedure::ProcedureNegativeReviewStatus::Dismissed
                | evertrace_domain::procedure::ProcedureNegativeReviewStatus::Superseded
        ) {
            return Ok(ProcedureNegativeReviewSelection {
                review_revision_id: review.review_event_id,
                review_status: review.status,
                available_decisions: Vec::new(),
                resolve_as_ineffective: None,
                dismiss_attribution: None,
                confirm_harm: None,
                request_revision: None,
            });
        }
        let usage = self
            .usages
            .get(&negative.procedure_usage_id)
            .ok_or(SemanticServiceError::InvalidInput)?;
        if !negative.validate()
            || usage.procedure_revision_id != negative.procedure_revision_id
            || usage.task_id != negative.task_id
        {
            return Err(SemanticServiceError::InvalidInput);
        }
        let proof_after = self
            .negative_seqs
            .get(&negative_evidence_id)
            .copied()
            .zip(
                self.negative_review_seqs
                    .get(&negative_evidence_id)
                    .copied(),
            )
            .map(|(negative_seq, review_seq)| negative_seq.max(review_seq))
            .ok_or(SemanticServiceError::InvalidInput)?;
        let current_results = self.current_result_heads()?;
        let result_ids = self.results_for_usage(&current_results, usage, proof_after);
        let pending =
            review.status == evertrace_domain::procedure::ProcedureNegativeReviewStatus::Pending;
        let resolve_as_ineffective = (pending
            && negative.level == evertrace_domain::procedure::ProcedureNegativeLevel::Ineffective)
            .then(|| self.ineffective_proof(negative, usage))
            .flatten();
        let dismiss_attribution = (pending
            && negative.level
                == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
            && self.uniform_passed(&result_ids))
        .then(|| ProcedureNegativeReviewProof::ReplayDismissed {
            result_revision_ids: result_ids.clone(),
        });
        let confirm_harm = (pending
            && negative.level
                == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
            && negative.local_context.is_none()
            && self.uniform_mismatch(&result_ids)
            && self
                .publications
                .get(&negative.procedure_revision_id)
                .is_some_and(|(state, _)| state.to_state == ProcedurePublicationState::ReviewHold))
        .then(|| ProcedureNegativeReviewProof::ReplayUpheld {
            result_revision_ids: result_ids.clone(),
        });
        let request_revision = (pending && self.revision_request_ready(negative, usage)).then_some(
            ProcedureNegativeReviewProof::RequestRevision {
                procedure_revision_id: negative.procedure_revision_id,
            },
        );
        let mut available_decisions = Vec::with_capacity(4);
        if resolve_as_ineffective.is_some() {
            available_decisions.push(ProcedureNegativeReviewDecision::ResolveAsIneffective);
        }
        if dismiss_attribution.is_some() {
            available_decisions.push(ProcedureNegativeReviewDecision::DismissAttribution);
        }
        if confirm_harm.is_some() {
            available_decisions.push(ProcedureNegativeReviewDecision::ConfirmHarm);
        }
        if request_revision.is_some() {
            available_decisions.push(ProcedureNegativeReviewDecision::RequestRevision);
        }
        Ok(ProcedureNegativeReviewSelection {
            review_revision_id: review.review_event_id,
            review_status: review.status,
            available_decisions,
            resolve_as_ineffective,
            dismiss_attribution,
            confirm_harm,
            request_revision,
        })
    }

    fn ineffective_proof(
        &self,
        negative: &evertrace_domain::procedure::ProcedureNegativeEvidence,
        usage: &evertrace_domain::procedure::ProcedureUsageRevision,
    ) -> Option<ProcedureNegativeReviewProof> {
        let result_revision_ids = self.negative_result_revisions(negative, usage)?;
        let [attempt_id] = usage.attempt_ids.as_slice() else {
            return None;
        };
        let attempt = self
            .attempts
            .get(attempt_id)
            .filter(|attempt| usage.accepts_adopted_attempt(attempt))?;
        let results = result_revision_ids
            .iter()
            .map(|id| self.results.get(id))
            .collect::<Option<Vec<_>>>()?;
        (evertrace_domain::procedure::classify_negative_fact(
            usage,
            attempt,
            &negative.evidence_refs,
            &results,
        ) == Some(evertrace_domain::procedure::ProcedureNegativeFact::Ineffective))
        .then_some(ProcedureNegativeReviewProof::IneffectiveResolved {
            result_revision_ids,
        })
    }

    fn revision_request_ready(
        &self,
        negative: &evertrace_domain::procedure::ProcedureNegativeEvidence,
        usage: &evertrace_domain::procedure::ProcedureUsageRevision,
    ) -> bool {
        self.procedures
            .get(&negative.procedure_revision_id)
            .is_some_and(|procedure| {
                self.current_procedures.get(&procedure.procedure_id)
                    == Some(&negative.procedure_revision_id)
            })
            && self.negative_result_revisions(negative, usage).is_some()
    }

    fn negative_result_revisions(
        &self,
        negative: &evertrace_domain::procedure::ProcedureNegativeEvidence,
        usage: &evertrace_domain::procedure::ProcedureUsageRevision,
    ) -> Option<Vec<RevisionId>> {
        let result_revision_ids = negative
            .evidence_refs
            .iter()
            .map(|reference| reference.parse::<RevisionId>().ok())
            .collect::<Option<Vec<_>>>()?;
        (!result_revision_ids.is_empty()
            && result_revision_ids.len() <= MAX_CANDIDATES
            && result_revision_ids.iter().all(|id| {
                self.results.get(id).is_some_and(|result| {
                    self.runs
                        .get(&result.experiment_run_id)
                        .is_some_and(|(run, _)| {
                            run.revision_id == result.experiment_run_revision_id
                                && run
                                    .attempt_id
                                    .is_some_and(|attempt| usage.attempt_ids.contains(&attempt))
                        })
                })
            }))
        .then_some(result_revision_ids)
    }

    fn current_result_heads(
        &self,
    ) -> Result<Vec<&evertrace_domain::semantic::ResultEvidence>, SemanticServiceError> {
        let predecessors = self
            .results
            .values()
            .filter_map(|result| result.parent_revision_id)
            .collect::<std::collections::BTreeSet<_>>();
        let mut heads = std::collections::BTreeMap::new();
        for result in self
            .results
            .values()
            .filter(|result| !predecessors.contains(&result.revision_id))
        {
            if heads.insert(result.result_evidence_id, result).is_some() {
                return Err(SemanticServiceError::InvalidInput);
            }
        }
        Ok(heads.into_values().collect())
    }

    fn results_for_usage(
        &self,
        current_results: &[&evertrace_domain::semantic::ResultEvidence],
        usage: &evertrace_domain::procedure::ProcedureUsageRevision,
        proof_after: u64,
    ) -> Vec<RevisionId> {
        current_results
            .iter()
            .filter(|result| {
                self.result_seqs
                    .get(&result.revision_id)
                    .is_some_and(|seq| *seq > proof_after)
                    && self
                        .runs
                        .get(&result.experiment_run_id)
                        .and_then(|(run, _)| run.attempt_id)
                        .is_some_and(|attempt| usage.attempt_ids.contains(&attempt))
            })
            .map(|result| result.revision_id)
            .take(MAX_CANDIDATES + 1)
            .collect()
    }

    fn uniform_passed(&self, result_ids: &[RevisionId]) -> bool {
        !result_ids.is_empty()
            && result_ids.len() <= MAX_CANDIDATES
            && result_ids.iter().all(|id| {
                self.results.get(id).is_some_and(|result| {
                    result.completeness
                        == evertrace_domain::semantic::EvidenceCompleteness::Complete
                        && result.failure.is_none()
                        && result.verifier_receipt.as_ref().is_some_and(|receipt| {
                            receipt.status == evertrace_domain::semantic::VerifierStatus::Passed
                        })
                        && self
                            .runs
                            .get(&result.experiment_run_id)
                            .is_some_and(|(run, _)| {
                                run.revision_id == result.experiment_run_revision_id
                            })
                })
            })
    }

    fn uniform_mismatch(&self, result_ids: &[RevisionId]) -> bool {
        !result_ids.is_empty()
            && result_ids.len() <= MAX_CANDIDATES
            && result_ids.iter().all(|id| {
                self.results.get(id).is_some_and(|result| {
                    matches!(
                        result.failure,
                        Some(evertrace_domain::semantic::ResultFailure::Verifier(
                            evertrace_domain::semantic::VerifierFailureCode::DeterministicReparseMismatch
                        ))
                    ) && self.runs.get(&result.experiment_run_id).is_some_and(|(run, _)| {
                        run.revision_id == result.experiment_run_revision_id
                    })
                })
            })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn route_procedures_with_quarantine(
    usage_view: &ProcedureUsageCurrentView,
    local_context: &evertrace_domain::procedure::ProcedureLocalContext,
    context: &SearchContext,
    candidates: Vec<ProcedureCandidate>,
    current: &ConstraintState,
    previous: Option<&ConstraintState>,
    scenario_fresh: bool,
    unresolved_competing: bool,
    sibling_exploration: bool,
    explicit_reuse: bool,
) -> ProcedureRouteResult {
    let mut result = ProcedureRouter::route(
        context,
        candidates,
        current,
        previous,
        scenario_fresh,
        unresolved_competing,
        sibling_exploration,
        explicit_reuse,
    );
    for item in &mut result.items {
        if usage_view.local_quarantined(item.revision_id, local_context) {
            item.decision = ProcedureDecision::Defer;
            item.route_proof.decision = ProcedureDecision::Defer;
            item.mode = ProcedureGuidanceMode::GuardrailOnly;
            item.reason = "local_quarantine";
            item.actions = None;
            if let Some(done) = &mut item.done {
                done.success.clear();
            }
        }
    }
    result.items.sort_by_key(route_rank);
    let apply = result
        .items
        .iter()
        .position(|item| item.decision == ProcedureDecision::Apply)
        .map(|index| result.items.remove(index));
    let defer = result
        .items
        .into_iter()
        .find(|item| item.decision == ProcedureDecision::Defer);
    result.items = apply.into_iter().chain(defer).collect();
    if result.items.is_empty() {
        result.status = "no_applicable_procedure";
    }
    result
}

pub fn record_procedure_negative(
    view: &ProcedureUsageCurrentView,
    context: ProposalCommandContext,
    request: ProcedureNegativeRequest,
) -> Result<ProcedureNegativeResolution, SemanticServiceError> {
    let usage = view
        .usages
        .get(&request.procedure_usage_id)
        .filter(|usage| usage.action_aligned == evertrace_domain::procedure::ProcedureTruth::True)
        .ok_or(SemanticServiceError::InvalidInput)?;
    if request.result_revision_ids.is_empty() {
        return Err(SemanticServiceError::InvalidInput);
    }
    let mut result_revision_ids = request.result_revision_ids;
    result_revision_ids.sort();
    result_revision_ids.dedup();
    let result_refs = result_revision_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if view.negatives.values().any(|negative| {
        negative.procedure_usage_id == usage.procedure_usage_id
            && negative.evidence_refs == result_refs
    }) {
        return Ok(ProcedureNegativeResolution::NoDelta);
    }
    let results = result_revision_ids
        .iter()
        .map(|id| {
            view.results
                .get(id)
                .ok_or(SemanticServiceError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if result_revision_ids.iter().any(|id| {
        view.result_seqs.get(id).is_none_or(|seq| {
            *seq <= view
                .usage_exposure_watermarks
                .get(&usage.procedure_usage_id)
                .copied()
                .unwrap_or(usage.source_watermark)
        })
    }) {
        return Err(SemanticServiceError::InvalidInput);
    }
    if results.iter().any(|result| {
        view.runs
            .get(&result.experiment_run_id)
            .is_none_or(|(run, _)| {
                run.revision_id != result.experiment_run_revision_id
                    || run
                        .attempt_id
                        .is_none_or(|attempt| !usage.attempt_ids.contains(&attempt))
            })
    }) {
        return Err(SemanticServiceError::InvalidInput);
    }
    let [attempt_id] = usage.attempt_ids.as_slice() else {
        return Err(SemanticServiceError::InvalidInput);
    };
    let attempt = view
        .attempts
        .get(attempt_id)
        .filter(|attempt| usage.accepts_adopted_attempt(attempt))
        .ok_or(SemanticServiceError::InvalidInput)?;
    let Some(fact) =
        evertrace_domain::procedure::classify_negative_fact(usage, attempt, &result_refs, &results)
    else {
        return Ok(ProcedureNegativeResolution::NoDelta);
    };
    let procedure = view
        .procedures
        .get(&usage.procedure_revision_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
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
    let cross_context_repeated = view.negatives.values().any(|negative| {
        negative.procedure_revision_id == usage.procedure_revision_id
            && negative.task_id != usage.task_id
            && negative.level == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
            && independent_task_pair(view, negative.task_id, usage.task_id)
            && view
                .negative_reviews
                .get(&negative.negative_evidence_id)
                .is_some_and(|review| {
                    matches!(
                        review.status,
                        evertrace_domain::procedure::ProcedureNegativeReviewStatus::Pending
                            | evertrace_domain::procedure::ProcedureNegativeReviewStatus::Upheld
                    )
                })
            && negative
                .local_context
                .as_ref()
                .is_none_or(|context| !context.compatible(&usage.local_context))
    });
    let classification = evertrace_domain::procedure::derive_negative_classification(
        fact,
        localizable,
        cross_context_repeated,
    );
    let level = classification.level;
    let negative = evertrace_domain::procedure::ProcedureNegativeEvidence {
        negative_evidence_id: evertrace_domain::ids::ProcedureNegativeEvidenceId::new_v7(),
        level,
        procedure_revision_id: usage.procedure_revision_id,
        procedure_usage_id: usage.procedure_usage_id,
        task_id: usage.task_id,
        session_id: request.session_id,
        evidence_refs: result_refs,
        observed_effect: attempt
            .failure_signature
            .clone()
            .unwrap_or_else(|| "deterministic_reparse_mismatch".into()),
        expected_effect: attempt.strategy_contract.expected_effect.clone(),
        confounders: (level == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm)
            .then(|| "causal_attribution_unconfirmed".into())
            .into_iter()
            .collect(),
        attribution_basis: classification.attribution_basis,
        decision_source: classification.decision_source,
        local_context: classification
            .localized
            .then(|| usage.local_context.clone()),
        created_at_us: context.occurred_at_us,
    };
    if !negative.validate() {
        return Err(SemanticServiceError::InvalidInput);
    }
    let review = evertrace_domain::procedure::ProcedureNegativeReviewEvent {
        review_event_id: RevisionId::new_v7(),
        negative_evidence_id: negative.negative_evidence_id,
        predecessor_review_event_id: None,
        review_generation: 1,
        status: evertrace_domain::procedure::ProcedureNegativeReviewStatus::Pending,
        successor_usage_revision_id: None,
        reason: "initial_review".into(),
        evidence_refs: {
            let mut refs = negative.evidence_refs.clone();
            refs.push(usage.usage_revision_id.to_string());
            refs.sort();
            refs.dedup();
            refs
        },
        created_at_us: context.occurred_at_us,
    };
    let publication = match level {
        evertrace_domain::procedure::ProcedureNegativeLevel::Ineffective => None,
        evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
            if classification.attribution_basis
                == evertrace_domain::procedure::ProcedureAttributionBasis::ResolvedLocalized =>
        {
            None
        }
        evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm => Some((
            ProcedurePublicationState::ReviewHold,
            ProcedureStateReason::SuspectedHarm,
        )),
        evertrace_domain::procedure::ProcedureNegativeLevel::ConfirmedHarm => Some((
            ProcedurePublicationState::Suspended,
            ProcedureStateReason::ConfirmedHarm,
        )),
    };
    let mut events = vec![
        JournalEventDraft::runtime(
            context.occurred_at_us,
            context.effective_config_hash,
            &context.algorithm_revision,
            JournalPayload::ProcedureNegativeEvidenceRecorded(Box::new(negative.clone())),
        ),
        JournalEventDraft::runtime(
            context.occurred_at_us,
            context.effective_config_hash,
            &context.algorithm_revision,
            JournalPayload::ProcedureNegativeReviewRecorded(Box::new(review)),
        ),
    ];
    if let Some((to_state, reason)) = publication {
        let current = view
            .publications
            .get(&usage.procedure_revision_id)
            .ok_or(SemanticServiceError::InvalidInput)?;
        if current.0.to_state != to_state
            && (matches!(
                current.0.to_state,
                ProcedurePublicationState::ActiveProbationary
                    | ProcedurePublicationState::ActiveStable
            ) || to_state == ProcedurePublicationState::Suspended
                && current.0.to_state == ProcedurePublicationState::ReviewHold)
        {
            events.push(JournalEventDraft::runtime(
                context.occurred_at_us,
                context.effective_config_hash,
                &context.algorithm_revision,
                JournalPayload::ProcedureStateRecorded(Box::new(ProcedureStateEvent {
                    state_event_id: RevisionId::new_v7(),
                    procedure_revision_id: usage.procedure_revision_id,
                    from_state: Some(current.0.to_state),
                    to_state,
                    reason,
                    resume_state: (to_state == ProcedurePublicationState::ReviewHold)
                        .then_some(current.0.to_state),
                    evidence_refs: vec![negative.negative_evidence_id.to_string()],
                    created_at_us: context.occurred_at_us,
                })),
            ));
        }
    }
    let command =
        JournalCommand::new(context.command_id, events).map_err(SemanticServiceError::Store)?;
    Ok(ProcedureNegativeResolution::Command { level, command })
}

fn independent_task_pair(
    view: &ProcedureUsageCurrentView,
    left_id: evertrace_domain::ids::TaskId,
    right_id: evertrace_domain::ids::TaskId,
) -> bool {
    let (Some(left), Some(right)) = (view.tasks.get(&left_id), view.tasks.get(&right_id)) else {
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

pub fn review_procedure_negative(
    view: &ProcedureUsageCurrentView,
    context: ProposalCommandContext,
    negative_evidence_id: evertrace_domain::ids::ProcedureNegativeEvidenceId,
    proof: ProcedureNegativeReviewProof,
) -> Result<JournalCommand, SemanticServiceError> {
    let current = view
        .negative_reviews
        .get(&negative_evidence_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let negative = view
        .negatives
        .get(&negative_evidence_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let usage = view
        .usages
        .get(&negative.procedure_usage_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let (action, status, mut result_revision_ids, successor_usage_id) = match proof {
        ProcedureNegativeReviewProof::IneffectiveResolved {
            result_revision_ids,
        } => (
            ProcedureNegativeReviewAction::ResolveAsIneffective,
            evertrace_domain::procedure::ProcedureNegativeReviewStatus::Dismissed,
            result_revision_ids,
            None,
        ),
        ProcedureNegativeReviewProof::ReplayDismissed {
            result_revision_ids,
        } => (
            ProcedureNegativeReviewAction::DismissAttribution,
            evertrace_domain::procedure::ProcedureNegativeReviewStatus::Dismissed,
            result_revision_ids,
            None,
        ),
        ProcedureNegativeReviewProof::ReplayUpheld {
            result_revision_ids,
        } => (
            ProcedureNegativeReviewAction::ConfirmHarm,
            evertrace_domain::procedure::ProcedureNegativeReviewStatus::Upheld,
            result_revision_ids,
            None,
        ),
        ProcedureNegativeReviewProof::SuccessorSuperseded {
            successor_usage_id,
            result_revision_ids,
        } => (
            ProcedureNegativeReviewAction::SuccessorSuperseded,
            evertrace_domain::procedure::ProcedureNegativeReviewStatus::Superseded,
            result_revision_ids,
            Some(successor_usage_id),
        ),
        ProcedureNegativeReviewProof::RequestRevision { .. } => {
            return Err(SemanticServiceError::UnsupportedTarget);
        }
    };
    result_revision_ids.sort();
    result_revision_ids.dedup();
    if result_revision_ids.is_empty() {
        return Err(SemanticServiceError::InvalidInput);
    }
    let proof_after = view
        .negative_seqs
        .get(&negative_evidence_id)
        .copied()
        .zip(
            view.negative_review_seqs
                .get(&negative_evidence_id)
                .copied(),
        )
        .map(|(negative_seq, review_seq)| negative_seq.max(review_seq))
        .ok_or(SemanticServiceError::InvalidInput)?;
    if action != ProcedureNegativeReviewAction::ResolveAsIneffective
        && result_revision_ids.iter().any(|id| {
            view.result_seqs
                .get(id)
                .is_none_or(|result_seq| *result_seq <= proof_after)
        })
    {
        return Err(SemanticServiceError::InvalidInput);
    }
    let results = result_revision_ids
        .iter()
        .map(|id| {
            view.results
                .get(id)
                .ok_or(SemanticServiceError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let proof_usage = successor_usage_id
        .map(|id| {
            view.usages
                .get(&id)
                .ok_or(SemanticServiceError::InvalidInput)
        })
        .transpose()?
        .unwrap_or(usage);
    let tied = results.iter().all(|result| {
        view.runs
            .get(&result.experiment_run_id)
            .is_some_and(|(run, _)| {
                run.revision_id == result.experiment_run_revision_id
                    && run
                        .attempt_id
                        .is_some_and(|attempt| proof_usage.attempt_ids.contains(&attempt))
            })
    });
    let proof_valid = match action {
        ProcedureNegativeReviewAction::ResolveAsIneffective => {
            current.status == evertrace_domain::procedure::ProcedureNegativeReviewStatus::Pending
                && negative.level
                    == evertrace_domain::procedure::ProcedureNegativeLevel::Ineffective
                && result_revision_ids
                    .iter()
                    .map(ToString::to_string)
                    .eq(negative.evidence_refs.iter().cloned())
                && view
                    .ineffective_proof(negative, usage)
                    .is_some_and(|proof| {
                        matches!(proof,
                            ProcedureNegativeReviewProof::IneffectiveResolved {
                                result_revision_ids: expected,
                            } if expected == result_revision_ids)
                    })
        }
        ProcedureNegativeReviewAction::DismissAttribution => {
            current.status == evertrace_domain::procedure::ProcedureNegativeReviewStatus::Pending
                && negative.level
                    == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                && results.iter().all(|result| {
                    result.completeness
                        == evertrace_domain::semantic::EvidenceCompleteness::Complete
                        && result.failure.is_none()
                        && result.verifier_receipt.as_ref().is_some_and(|receipt| {
                            receipt.status == evertrace_domain::semantic::VerifierStatus::Passed
                        })
                })
        }
        ProcedureNegativeReviewAction::ConfirmHarm => {
            current.status == evertrace_domain::procedure::ProcedureNegativeReviewStatus::Pending
                && negative.level
                    == evertrace_domain::procedure::ProcedureNegativeLevel::SuspectedHarm
                && negative.local_context.is_none()
                && results.iter().all(|result| {
                    matches!(
                        result.failure,
                        Some(evertrace_domain::semantic::ResultFailure::Verifier(
                            evertrace_domain::semantic::VerifierFailureCode::DeterministicReparseMismatch
                        ))
                    )
                })
                && view
                    .publications
                    .get(&negative.procedure_revision_id)
                    .is_some_and(|(state, _)| {
                        state.to_state == ProcedurePublicationState::ReviewHold
                    })
        }
        ProcedureNegativeReviewAction::SuccessorSuperseded => {
            let old = view
                .procedures
                .get(&negative.procedure_revision_id)
                .ok_or(SemanticServiceError::InvalidInput)?;
            let successor = view
                .procedures
                .get(&proof_usage.procedure_revision_id)
                .ok_or(SemanticServiceError::InvalidInput)?;
            proof_usage.procedure_usage_id != usage.procedure_usage_id
                && proof_usage.outcome_supported
                    == evertrace_domain::procedure::ProcedureTruth::True
                && proof_usage.local_context.compatible(&usage.local_context)
                && successor.procedure_id == old.procedure_id
                && successor.parent_revision_id == Some(old.revision_id)
                && result_revision_ids
                    .iter()
                    .all(|id| proof_usage.evidence_refs.contains(&id.to_string()))
                && results.iter().all(|result| {
                    result.failure.is_none()
                        && result.verifier_receipt.as_ref().is_some_and(|receipt| {
                            receipt.status == evertrace_domain::semantic::VerifierStatus::Passed
                        })
                })
        }
    };
    if context.occurred_at_us < current.created_at_us || !tied || !proof_valid {
        return Err(SemanticServiceError::InvalidInput);
    }
    let event = evertrace_domain::procedure::ProcedureNegativeReviewEvent {
        review_event_id: RevisionId::new_v7(),
        negative_evidence_id,
        predecessor_review_event_id: Some(current.review_event_id),
        review_generation: current.review_generation + 1,
        status,
        successor_usage_revision_id: successor_usage_id.map(|_| proof_usage.usage_revision_id),
        reason: action.reason().into(),
        evidence_refs: result_revision_ids
            .into_iter()
            .map(|value| value.to_string())
            .collect(),
        created_at_us: context.occurred_at_us,
    };
    let mut events = vec![JournalEventDraft::runtime(
        context.occurred_at_us,
        context.effective_config_hash,
        &context.algorithm_revision,
        JournalPayload::ProcedureNegativeReviewRecorded(Box::new(event)),
    )];
    if action == ProcedureNegativeReviewAction::ConfirmHarm {
        view.publications
            .get(&negative.procedure_revision_id)
            .filter(|(state, _)| state.to_state == ProcedurePublicationState::ReviewHold)
            .ok_or(SemanticServiceError::InvalidInput)?;
        events.push(JournalEventDraft::runtime(
            context.occurred_at_us,
            context.effective_config_hash,
            &context.algorithm_revision,
            JournalPayload::ProcedureStateRecorded(Box::new(ProcedureStateEvent {
                state_event_id: RevisionId::new_v7(),
                procedure_revision_id: negative.procedure_revision_id,
                from_state: Some(ProcedurePublicationState::ReviewHold),
                to_state: ProcedurePublicationState::Suspended,
                reason: ProcedureStateReason::ConfirmedHarm,
                resume_state: None,
                evidence_refs: vec![negative.negative_evidence_id.to_string()],
                created_at_us: context.occurred_at_us,
            })),
        ));
    } else if matches!(
        action,
        ProcedureNegativeReviewAction::DismissAttribution
            | ProcedureNegativeReviewAction::SuccessorSuperseded
    ) && negative.local_context.is_none()
    {
        let current_publication = view
            .publications
            .get(&negative.procedure_revision_id)
            .ok_or(SemanticServiceError::InvalidInput)?;
        if current_publication.0.to_state == ProcedurePublicationState::ReviewHold {
            let resume_state = current_publication
                .0
                .resume_state
                .filter(|state| {
                    matches!(
                        state,
                        ProcedurePublicationState::ActiveProbationary
                            | ProcedurePublicationState::ActiveStable
                    )
                })
                .ok_or(SemanticServiceError::InvalidInput)?;
            events.push(JournalEventDraft::runtime(
                context.occurred_at_us,
                context.effective_config_hash,
                &context.algorithm_revision,
                JournalPayload::ProcedureStateRecorded(Box::new(ProcedureStateEvent {
                    state_event_id: RevisionId::new_v7(),
                    procedure_revision_id: negative.procedure_revision_id,
                    from_state: Some(ProcedurePublicationState::ReviewHold),
                    to_state: resume_state,
                    reason: ProcedureStateReason::Manual,
                    resume_state: None,
                    evidence_refs: vec![negative.negative_evidence_id.to_string()],
                    created_at_us: context.occurred_at_us,
                })),
            ));
        }
    }
    JournalCommand::new(context.command_id, events).map_err(SemanticServiceError::Store)
}

pub(crate) fn mark_procedure_support_review_hold(
    impact: &evertrace_store::ObjectDeletionProcedureImpact,
    occurred_at_us: i64,
) -> Result<JournalPayload, SemanticServiceError> {
    let current = &impact.current_state;
    if !matches!(
        current.to_state,
        ProcedurePublicationState::ActiveProbationary | ProcedurePublicationState::ActiveStable
    ) || impact.trigger_refs.is_empty()
        || impact
            .trigger_refs
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(SemanticServiceError::InvalidInput);
    }
    let event = ProcedureStateEvent {
        state_event_id: RevisionId::new_v7(),
        procedure_revision_id: current.procedure_revision_id,
        from_state: Some(current.to_state),
        to_state: ProcedurePublicationState::ReviewHold,
        reason: ProcedureStateReason::SupportPending,
        resume_state: Some(current.to_state),
        evidence_refs: impact.trigger_refs.clone(),
        created_at_us: occurred_at_us,
    };
    event
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    Ok(JournalPayload::ProcedureStateRecorded(Box::new(event)))
}

#[derive(Debug)]
pub enum ProcedureRevisionRequestResolution {
    NoDelta {
        proposal: Box<RevisionProposal>,
    },
    Command {
        proposal: Box<RevisionProposal>,
        command: JournalCommand,
    },
}

pub fn request_procedure_revision(
    view: &ProcedureUsageCurrentView,
    semantic_view: &SemanticCurrentView,
    context: ProposalCommandContext,
    negative_evidence_id: evertrace_domain::ids::ProcedureNegativeEvidenceId,
    proof: ProcedureNegativeReviewProof,
) -> Result<ProcedureRevisionRequestResolution, SemanticServiceError> {
    let ProcedureNegativeReviewProof::RequestRevision {
        procedure_revision_id,
    } = proof
    else {
        return Err(SemanticServiceError::InvalidInput);
    };
    let negative = view
        .negatives
        .get(&negative_evidence_id)
        .filter(|negative| negative.procedure_revision_id == procedure_revision_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let review = view
        .negative_reviews
        .get(&negative_evidence_id)
        .filter(|review| {
            review.status == evertrace_domain::procedure::ProcedureNegativeReviewStatus::Pending
        })
        .ok_or(SemanticServiceError::InvalidInput)?;
    let usage = view
        .usages
        .get(&negative.procedure_usage_id)
        .filter(|usage| {
            usage.procedure_revision_id == negative.procedure_revision_id
                && usage.task_id == negative.task_id
        })
        .ok_or(SemanticServiceError::InvalidInput)?;
    if context.occurred_at_us < review.created_at_us
        || !view.revision_request_ready(negative, usage)
    {
        return Err(SemanticServiceError::InvalidInput);
    }
    let current = view
        .procedures
        .get(&procedure_revision_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let mut source_refs = view
        .negative_result_revisions(negative, usage)
        .ok_or(SemanticServiceError::InvalidInput)?
        .into_iter()
        .map(|revision_id| {
            view.results
                .get(&revision_id)
                .map(|result| result.result_evidence_id.to_string())
                .ok_or(SemanticServiceError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    source_refs.sort();
    source_refs.dedup();
    if source_refs.is_empty() {
        return Err(SemanticServiceError::InvalidInput);
    }
    let negative_ref = negative.negative_evidence_id.to_string();
    let mut draft = current.draft.clone();
    draft.evidence_refs.extend(source_refs.clone());
    draft.evidence_refs.push(negative_ref);
    draft.evidence_refs.sort();
    draft.evidence_refs.dedup();
    draft
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    let proposal_evidence_refs = draft.evidence_refs.clone();
    let payload = ProposalPayload::Procedure(Box::new(ProcedureProposalPayload::Replace { draft }));
    let mut exact = semantic_view.proposals.values().filter(|proposal| {
        proposal.status == evertrace_domain::semantic::ProposalStatus::Pending
            && proposal.target_kind == ProposalTargetKind::Procedure
            && proposal.target_id == Some(ProposalTargetId::Procedure(current.procedure_id))
            && proposal.base_revision_id == Some(current.revision_id)
            && proposal.operation == evertrace_domain::semantic::ProposalOperation::Replace
            && proposal.payload == payload
            && proposal.evidence_refs == proposal_evidence_refs
            && proposal.source_cohort_refs == source_refs
            && proposal.eligibility == ProposalEligibility::ManualRequired
            && proposal.created_by == evertrace_domain::semantic::ProposalCreatedBy::User
    });
    if let Some(existing) = exact.next() {
        if exact.next().is_some() {
            return Err(SemanticServiceError::ImmutableConflict);
        }
        return Ok(ProcedureRevisionRequestResolution::NoDelta {
            proposal: Box::new(existing.clone()),
        });
    }
    let request = crate::semantic::SubmitProposalRequest {
        target_kind: ProposalTargetKind::Procedure,
        target_id: Some(ProposalTargetId::Procedure(current.procedure_id)),
        base_revision_id: Some(current.revision_id),
        operation: evertrace_domain::semantic::ProposalOperation::Replace,
        payload,
        evidence_refs: proposal_evidence_refs,
        source_cohort_refs: source_refs,
        eligibility: ProposalEligibility::ManualRequired,
        created_by: evertrace_domain::semantic::ProposalCreatedBy::User,
    };
    match crate::semantic::RevisionProposalService.submit(semantic_view, context, request)? {
        crate::semantic::ProposalResolution::Revision { value, command } => {
            Ok(ProcedureRevisionRequestResolution::Command {
                proposal: value,
                command,
            })
        }
        crate::semantic::ProposalResolution::NoDelta => {
            Err(SemanticServiceError::ImmutableConflict)
        }
    }
}

#[derive(Debug)]
pub enum ProcedureUsageResolution {
    NoDelta(evertrace_domain::procedure::ProcedureUsageRevision),
    Command {
        usage: evertrace_domain::procedure::ProcedureUsageRevision,
        command: JournalCommand,
    },
}

pub fn begin_procedure_usage(
    view: &ProcedureUsageCurrentView,
    context: ProposalCommandContext,
    routed: &RoutedProcedure,
    workstream_id: evertrace_domain::ids::WorkstreamId,
    exposure_episode_revision_id: RevisionId,
) -> Result<ProcedureUsageResolution, SemanticServiceError> {
    let task_id = routed
        .route_proof
        .task_id
        .ok_or(SemanticServiceError::InvalidInput)?;
    let local_context = evertrace_domain::procedure::ProcedureLocalContext {
        repository_id: routed.route_proof.repository_id,
        worktree_id: routed.route_proof.worktree_id,
        phase: usage_phase(routed.route_proof.phase),
        failure_signature: routed.route_proof.failure_signature.clone(),
    };
    if routed.procedure_id != routed.route_proof.procedure_id
        || routed.revision_id != routed.route_proof.revision_id
        || routed.decision != routed.route_proof.decision
        || routed.publication != routed.route_proof.publication
        || routed.phase != routed.route_proof.phase
        || routed.decision == ProcedureDecision::Reject
        || routed.route_proof.eligibility == ConstraintTruth::False
    {
        return Err(SemanticServiceError::InvalidInput);
    }
    let expected_decision = match routed.decision {
        ProcedureDecision::Apply => evertrace_domain::procedure::ProcedureUsageRouteDecision::Apply,
        ProcedureDecision::Defer => evertrace_domain::procedure::ProcedureUsageRouteDecision::Defer,
        ProcedureDecision::Reject => return Err(SemanticServiceError::InvalidInput),
    };
    let procedure = view
        .procedures
        .get(&routed.revision_id)
        .filter(|value| value.procedure_id == routed.procedure_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let episode = view
        .episodes
        .get(&exposure_episode_revision_id)
        .filter(|value| value.task_id == task_id && value.workstream_id == workstream_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let decision_boundary_ref = episode.phase_contract.acceptance_boundary.clone();
    let mut matching = view.usages.values().filter(|usage| {
        usage.procedure_revision_id == routed.revision_id
            && usage.task_id == task_id
            && usage.exposure_episode_revision_id == exposure_episode_revision_id
    });
    if let Some(existing) = matching.next() {
        if matching.next().is_some()
            || existing.workstream_id != workstream_id
            || existing.decision_boundary_ref != decision_boundary_ref
            || existing.route_decision != expected_decision
            || existing.local_context != local_context
        {
            return Err(SemanticServiceError::InvalidInput);
        }
        return Ok(ProcedureUsageResolution::NoDelta(existing.clone()));
    }
    let task = view
        .tasks
        .get(&task_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let publication = view
        .publications
        .get(&routed.revision_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let workstream = view
        .workstreams
        .get(&workstream_id)
        .filter(|value| value.task_id == task_id && !value.status.is_terminal())
        .ok_or(SemanticServiceError::InvalidInput)?;
    if task.lifecycle != evertrace_domain::work::TaskLifecycle::Active
        || !task.scope_memberships.iter().any(|membership| {
            membership.repository_instance_id == local_context.repository_id
                && local_context.worktree_id.is_none_or(|worktree_id| {
                    membership.worktree_instance_ids.contains(&worktree_id)
                })
        })
        || publication.0.to_state != routed.publication
        || !matches!(
            publication.0.to_state,
            ProcedurePublicationState::ActiveProbationary | ProcedurePublicationState::ActiveStable
        )
        || view.current_episode_revisions.get(&episode.episode_id)
            != Some(&exposure_episode_revision_id)
        || episode.lifecycle_status != evertrace_domain::work::EpisodeLifecycle::Open
        || workstream.active_episode_id != Some(episode.episode_id)
        || matches!(procedure.draft.scope, ProcedureScope::Global)
            && view
                .procedure_support
                .get(&routed.revision_id)
                .and_then(|value| value.as_deref())
                != Some("valid")
        || !usage_scope_matches(procedure.draft.scope, &local_context)
        || expected_decision == evertrace_domain::procedure::ProcedureUsageRouteDecision::Apply
            && view.local_quarantined(routed.revision_id, &local_context)
    {
        return Err(SemanticServiceError::InvalidInput);
    }
    let usage = evertrace_domain::procedure::ProcedureUsageRevision {
        procedure_usage_id: evertrace_domain::ids::ProcedureUsageId::new_v7(),
        usage_revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        revision_generation: 1,
        procedure_revision_id: routed.revision_id,
        task_id,
        workstream_id,
        exposure_episode_revision_id,
        decision_boundary_ref,
        route_decision: expected_decision,
        stage: evertrace_domain::procedure::ProcedureUsageStage::Returned,
        attempt_ids: Vec::new(),
        action_episode_revision_ids: Vec::new(),
        verification_episode_revision_ids: Vec::new(),
        action_operation_refs: Vec::new(),
        verification_operation_refs: Vec::new(),
        work_binding_revision_refs: Vec::new(),
        scope_effect_refs: Vec::new(),
        correlation_state: evertrace_domain::procedure::ProcedureCorrelationState::Resolved,
        eligible: match routed.route_proof.eligibility {
            ConstraintTruth::True => evertrace_domain::procedure::ProcedureTruth::True,
            ConstraintTruth::Unknown => evertrace_domain::procedure::ProcedureTruth::Unknown,
            ConstraintTruth::False => return Err(SemanticServiceError::InvalidInput),
        },
        action_aligned: evertrace_domain::procedure::ProcedureTruth::False,
        verifier_aligned: evertrace_domain::procedure::ProcedureTruth::Unknown,
        outcome_supported: evertrace_domain::procedure::ProcedureTruth::Unknown,
        local_context,
        source_watermark: view.frontier,
        evidence_refs: vec![episode.revision_id.to_string()],
        created_at_us: context.occurred_at_us,
    };
    let command = usage_command(context, usage.clone(), None)?;
    Ok(ProcedureUsageResolution::Command { usage, command })
}

fn usage_phase(value: ProcedurePhase) -> evertrace_domain::procedure::ProcedureUsagePhase {
    match value {
        ProcedurePhase::BeforeEntry => {
            evertrace_domain::procedure::ProcedureUsagePhase::BeforeEntry
        }
        ProcedurePhase::AtEntry => evertrace_domain::procedure::ProcedureUsagePhase::AtEntry,
        ProcedurePhase::InProgress => evertrace_domain::procedure::ProcedureUsagePhase::InProgress,
        ProcedurePhase::RecoverableDeviation => {
            evertrace_domain::procedure::ProcedureUsagePhase::RecoverableDeviation
        }
        ProcedurePhase::AlreadyCompleted => {
            evertrace_domain::procedure::ProcedureUsagePhase::AlreadyCompleted
        }
        ProcedurePhase::Incompatible => {
            evertrace_domain::procedure::ProcedureUsagePhase::Incompatible
        }
    }
}

pub fn advance_procedure_usage(
    view: &ProcedureUsageCurrentView,
    context: ProposalCommandContext,
    request: ProcedureUsageAdvance,
    constraints: &ConstraintState,
    previous_constraints: Option<&ConstraintState>,
) -> Result<
    (
        evertrace_domain::procedure::ProcedureUsageRevision,
        JournalCommand,
    ),
    SemanticServiceError,
> {
    let current = view
        .usages
        .get(&request.usage_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let procedure = view
        .procedures
        .get(&current.procedure_revision_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let mut next = current.clone();
    next.usage_revision_id = RevisionId::new_v7();
    next.predecessor_revision_id = Some(current.usage_revision_id);
    next.revision_generation = current
        .revision_generation
        .checked_add(1)
        .ok_or(SemanticServiceError::InvalidInput)?;
    next.stage = next.stage.max(request.stage);
    merge_sorted(&mut next.attempt_ids, request.attempt_ids);
    merge_sorted(
        &mut next.action_episode_revision_ids,
        request.action_episode_revision_ids,
    );
    merge_sorted(
        &mut next.verification_episode_revision_ids,
        request.verification_episode_revision_ids,
    );
    merge_sorted(
        &mut next.action_operation_refs,
        request.action_operation_refs,
    );
    merge_sorted(
        &mut next.verification_operation_refs,
        request.verification_operation_refs,
    );
    merge_sorted(
        &mut next.work_binding_revision_refs,
        request.work_binding_revision_refs,
    );
    merge_sorted(&mut next.scope_effect_refs, request.scope_effect_refs);
    merge_sorted(&mut next.evidence_refs, request.evidence_refs);
    next.source_watermark = view.frontier;
    if context.occurred_at_us < current.created_at_us {
        return Err(SemanticServiceError::InvalidInput);
    }
    next.created_at_us = context.occurred_at_us;
    let (resolved, adopted_attempt) = validate_physical_usage(view, &next)?;
    if adopted_attempt.is_some() {
        next.stage = next
            .stage
            .max(evertrace_domain::procedure::ProcedureUsageStage::Adopted);
    }
    next.correlation_state = if resolved {
        evertrace_domain::procedure::ProcedureCorrelationState::Resolved
    } else {
        evertrace_domain::procedure::ProcedureCorrelationState::Ambiguous
    };
    next.action_aligned = if next.action_operation_refs.is_empty() {
        evertrace_domain::procedure::ProcedureTruth::False
    } else if resolved {
        evertrace_domain::procedure::ProcedureTruth::True
    } else {
        evertrace_domain::procedure::ProcedureTruth::Ambiguous
    };
    next.verifier_aligned = if next.verification_operation_refs.is_empty() {
        evertrace_domain::procedure::ProcedureTruth::Unknown
    } else if resolved
        && adopted_attempt.is_some_and(|id| {
            view.attempts.get(&id).is_some_and(|attempt| {
                attempt.verification == evertrace_domain::work::AttemptVerification::Passed
                    && !attempt.outcome_refs.is_empty()
                    && verified_result_refs(view, &next, id, attempt)
            })
        })
        && procedure
            .draft
            .completion_expr
            .evaluate(constraints, previous_constraints)
            == ConstraintTruth::True
    {
        evertrace_domain::procedure::ProcedureTruth::True
    } else {
        evertrace_domain::procedure::ProcedureTruth::False
    };
    next.outcome_supported = if next.stage
        == evertrace_domain::procedure::ProcedureUsageStage::Outcome
        && next.action_aligned == evertrace_domain::procedure::ProcedureTruth::True
        && next.verifier_aligned == evertrace_domain::procedure::ProcedureTruth::True
        && next.correlation_state
            == evertrace_domain::procedure::ProcedureCorrelationState::Resolved
    {
        evertrace_domain::procedure::ProcedureTruth::True
    } else {
        evertrace_domain::procedure::ProcedureTruth::False
    };
    if !current.validate_successor(&next) {
        return Err(SemanticServiceError::InvalidInput);
    }
    let promotion = promotion_event(view, &next, context.occurred_at_us)?;
    usage_command(context, next.clone(), promotion).map(|command| (next, command))
}

fn verified_result_refs(
    view: &ProcedureUsageCurrentView,
    usage: &evertrace_domain::procedure::ProcedureUsageRevision,
    attempt_id: evertrace_domain::ids::AttemptId,
    attempt: &evertrace_domain::work::Attempt,
) -> bool {
    let mut found = false;
    for reference in &usage.evidence_refs {
        let Ok(revision_id) = reference.parse::<RevisionId>() else {
            continue;
        };
        let Some(result) = view.results.get(&revision_id) else {
            continue;
        };
        if view.result_seqs.get(&revision_id).is_none_or(|seq| {
            *seq <= view
                .usage_exposure_watermarks
                .get(&usage.procedure_usage_id)
                .copied()
                .unwrap_or(usage.source_watermark)
        }) {
            return false;
        }
        let Some((run, _)) = view.runs.get(&result.experiment_run_id) else {
            return false;
        };
        if run.revision_id != result.experiment_run_revision_id
            || run.attempt_id != Some(attempt_id)
            || result.verifier_receipt.as_ref().is_none_or(|receipt| {
                receipt.status != evertrace_domain::semantic::VerifierStatus::Passed
            })
            || !attempt.outcome_refs.contains(reference)
        {
            return false;
        }
        found = true;
    }
    found
}

fn merge_sorted<T: Ord>(current: &mut Vec<T>, delta: Vec<T>) {
    current.extend(delta);
    current.sort();
    current.dedup();
}

fn validate_physical_usage(
    view: &ProcedureUsageCurrentView,
    usage: &evertrace_domain::procedure::ProcedureUsageRevision,
) -> Result<(bool, Option<evertrace_domain::ids::AttemptId>), SemanticServiceError> {
    let mut operations = usage.action_operation_refs.clone();
    operations.extend(usage.verification_operation_refs.iter().copied());
    operations.sort();
    operations.dedup();
    let mut adopted_attempt = None;
    for operation_id in &operations {
        let (operation, seq) = view
            .operations
            .get(operation_id)
            .ok_or(SemanticServiceError::InvalidInput)?;
        if *seq
            <= view
                .usage_exposure_watermarks
                .get(&usage.procedure_usage_id)
                .copied()
                .unwrap_or(usage.source_watermark)
        {
            return Ok((false, adopted_attempt));
        }
        let bindings = usage
            .work_binding_revision_refs
            .iter()
            .filter_map(|id| view.bindings.get(id))
            .filter(|binding| binding.operation_id == *operation_id)
            .collect::<Vec<_>>();
        let [binding] = bindings.as_slice() else {
            return Ok((false, adopted_attempt));
        };
        let current_binding = view
            .current_bindings_by_operation
            .get(operation_id)
            .ok_or(SemanticServiceError::InvalidInput)?;
        let attempt = binding
            .primary_binding
            .attempt_id
            .and_then(|id| view.attempts.get(&id));
        let attempt_aligned = attempt.is_some_and(|attempt| usage.accepts_adopted_attempt(attempt));
        if attempt_aligned {
            let attempt_id = attempt.expect("attempt alignment checked").attempt_id;
            if adopted_attempt.is_some_and(|current| current != attempt_id) {
                return Ok((false, None));
            }
            adopted_attempt = Some(attempt_id);
        }
        let occurrence = view
            .host_occurrences
            .get(&operation.host_occurrence_id)
            .map(|(occurrence, _)| occurrence)
            .ok_or(SemanticServiceError::InvalidInput)?;
        let episode_aligned = binding
            .primary_binding
            .episode_id
            .is_some_and(|episode_id| {
                let matches_episode = |revision: &RevisionId| {
                    view.episodes.get(revision).is_some_and(|episode| {
                        episode.episode_id == episode_id
                            && episode.task_id == usage.task_id
                            && episode.workstream_id == usage.workstream_id
                    })
                };
                (!usage.action_operation_refs.contains(operation_id)
                    || usage
                        .action_episode_revision_ids
                        .iter()
                        .any(matches_episode))
                    && (!usage.verification_operation_refs.contains(operation_id)
                        || usage
                            .verification_episode_revision_ids
                            .iter()
                            .any(matches_episode))
            });
        if binding.assignment_status != evertrace_domain::work::AssignmentStatus::Resolved
            || current_binding != &binding.work_binding_revision_id
            || binding.primary_binding.task_id != Some(usage.task_id)
            || binding.primary_binding.workstream_id != Some(usage.workstream_id)
            || !attempt_aligned
            || !episode_aligned
            || operation.pairing_state != evertrace_domain::evidence::PairingState::Paired
            || occurrence.correlation_strength
                != evertrace_domain::evidence::CorrelationStrength::Exact
            || occurrence.normalization_state
                == evertrace_domain::evidence::NormalizationState::NormalizationConflicted
            || occurrence.pairing_state != evertrace_domain::evidence::PairingState::Paired
            || occurrence.possible_duplicate_group_id.is_some()
            || binding.scope_effect_refs.iter().any(|id| {
                !operation.scope_effect_ids.contains(id) || !view.scope_effects.contains_key(id)
            })
        {
            return Ok((false, adopted_attempt));
        }
    }
    if usage.scope_effect_refs.iter().any(|scope_id| {
        view.scope_effects.get(scope_id).is_none_or(|effect| {
            !operations.contains(&effect.operation_id)
                || usage.local_context.repository_id != effect.repository_instance_id
                || usage.local_context.worktree_id != effect.worktree_instance_id
                || !usage.work_binding_revision_refs.iter().any(|binding_id| {
                    view.bindings.get(binding_id).is_some_and(|binding| {
                        binding.operation_id == effect.operation_id
                            && binding.scope_effect_refs.contains(scope_id)
                    })
                })
        })
    }) {
        return Ok((false, adopted_attempt));
    }
    if adopted_attempt.is_none()
        || usage.attempt_ids.len() != 1
        || usage.attempt_ids.first() != adopted_attempt.as_ref()
    {
        return Ok((false, adopted_attempt));
    }
    Ok((!operations.is_empty(), adopted_attempt))
}

fn promotion_event(
    view: &ProcedureUsageCurrentView,
    next: &evertrace_domain::procedure::ProcedureUsageRevision,
    occurred_at_us: i64,
) -> Result<Option<ProcedureStateEvent>, SemanticServiceError> {
    if next.outcome_supported != evertrace_domain::procedure::ProcedureTruth::True
        || view.has_local_quarantine(next.procedure_revision_id)
    {
        return Ok(None);
    }
    let publication = view
        .publications
        .get(&next.procedure_revision_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    if publication.0.to_state != ProcedurePublicationState::ActiveProbationary {
        return Ok(None);
    }
    let mut prior_successes = view
        .usages
        .values()
        .filter(|usage| {
            usage.procedure_revision_id == next.procedure_revision_id
                && usage.outcome_supported == evertrace_domain::procedure::ProcedureTruth::True
                && usage.task_id != next.task_id
        })
        .cloned()
        .collect::<Vec<_>>();
    prior_successes.sort_by_key(|usage| (usage.task_id, usage.usage_revision_id));
    prior_successes.dedup_by_key(|usage| usage.task_id);
    let mut selected = None;
    'candidate: for first in 0..prior_successes.len() {
        for second in (first + 1)..prior_successes.len() {
            let mut cohort = vec![
                prior_successes[first].clone(),
                prior_successes[second].clone(),
                next.clone(),
            ];
            cohort.sort_by_key(|usage| (usage.task_id, usage.usage_revision_id));
            if independent_tasks(view, &cohort) {
                selected = Some(cohort);
                break 'candidate;
            }
        }
    }
    let Some(successes) = selected else {
        return Ok(None);
    };
    let mut evidence_refs = successes
        .iter()
        .map(|usage| usage.usage_revision_id.to_string())
        .collect::<Vec<_>>();
    evidence_refs.sort();
    Ok(Some(ProcedureStateEvent {
        state_event_id: RevisionId::new_v7(),
        procedure_revision_id: next.procedure_revision_id,
        from_state: Some(ProcedurePublicationState::ActiveProbationary),
        to_state: ProcedurePublicationState::ActiveStable,
        reason: ProcedureStateReason::ObjectiveSuccesses,
        resume_state: None,
        evidence_refs,
        created_at_us: occurred_at_us,
    }))
}

fn independent_tasks(
    view: &ProcedureUsageCurrentView,
    usages: &[evertrace_domain::procedure::ProcedureUsageRevision],
) -> bool {
    for (index, usage) in usages.iter().enumerate() {
        let Some(task) = view.tasks.get(&usage.task_id) else {
            return false;
        };
        if task.continuation_of_task_id.is_some() || task.split_from_task_id.is_some() {
            return false;
        }
        for other in &usages[..index] {
            let Some(other_task) = view.tasks.get(&other.task_id) else {
                return false;
            };
            if task
                .request_root_refs
                .iter()
                .any(|value| other_task.request_root_refs.contains(value))
            {
                return false;
            }
        }
    }
    true
}

fn usage_command(
    context: ProposalCommandContext,
    usage: evertrace_domain::procedure::ProcedureUsageRevision,
    publication: Option<ProcedureStateEvent>,
) -> Result<JournalCommand, SemanticServiceError> {
    let mut events = vec![JournalEventDraft::runtime(
        context.occurred_at_us,
        context.effective_config_hash,
        &context.algorithm_revision,
        JournalPayload::ProcedureUsageRecorded(Box::new(usage)),
    )];
    if let Some(publication) = publication {
        events.push(JournalEventDraft::runtime(
            context.occurred_at_us,
            context.effective_config_hash,
            context.algorithm_revision,
            JournalPayload::ProcedureStateRecorded(Box::new(publication)),
        ));
    }
    JournalCommand::new(context.command_id, events).map_err(SemanticServiceError::Store)
}

fn usage_scope_matches(
    scope: ProcedureScope,
    context: &evertrace_domain::procedure::ProcedureLocalContext,
) -> bool {
    match scope {
        ProcedureScope::Global => true,
        ProcedureScope::Repository { repository_id } => {
            context.repository_id == Some(repository_id)
        }
        ProcedureScope::Worktree {
            repository_id,
            worktree_id,
        } => {
            context.repository_id == Some(repository_id) && context.worktree_id == Some(worktree_id)
        }
    }
}

#[cfg(test)]
mod negative_review_selection_tests {
    use super::*;
    use evertrace_domain::{
        ids::{
            AttemptId, ExperimentRunId, ProcedureNegativeEvidenceId, ProcedureUsageId,
            ResultEvidenceId, TaskId, WorkArtifactId, WorkstreamId, WorktreeSnapshotId,
        },
        procedure::{
            ProcedureAttributionBasis, ProcedureCorrelationState, ProcedureLocalContext,
            ProcedureNegativeDecisionSource, ProcedureNegativeEvidence, ProcedureNegativeLevel,
            ProcedureNegativeReviewEvent, ProcedureNegativeReviewStatus, ProcedureTruth,
            ProcedureUsagePhase, ProcedureUsageRevision, ProcedureUsageRouteDecision,
            ProcedureUsageStage,
        },
        semantic::{
            EvidenceCompleteness, MetricValue, ParserReceipt, ParserStatus, ResultEvidence,
            ResultFailure, ResultScope, VerifierFailureCode, VerifierReceipt, VerifierStatus,
        },
        work::{
            AttemptBindingStatus, ContractField, ExperimentRun, MultiCasMetricPolicy,
            RunContractValidity, RunExecutionStatus, RunObservability, RunOrigin, SeedPolicy,
            VariableDeclaration,
        },
    };

    #[test]
    fn complete_current_replay_cohort_selects_one_closed_decision() {
        let (view, negative_id) = review_view(ResultKind::Passed);
        let selection = view.select_negative_review(negative_id).unwrap();
        assert_eq!(
            selection.available_decisions,
            vec![ProcedureNegativeReviewDecision::DismissAttribution]
        );
        let command = review_procedure_negative(
            &view,
            ProposalCommandContext {
                command_id: evertrace_domain::ids::CommandId::new_v7(),
                occurred_at_us: 20,
                effective_config_hash: [1; 32],
                algorithm_revision: "negative-review-test-v1".into(),
            },
            negative_id,
            selection
                .proof(ProcedureNegativeReviewDecision::DismissAttribution)
                .unwrap(),
        )
        .unwrap();
        assert!(command.events().iter().any(|event| matches!(
            &event.payload,
            JournalPayload::ProcedureNegativeReviewRecorded(review)
                if review.status == ProcedureNegativeReviewStatus::Dismissed
        )));

        let (view, negative_id) = review_view(ResultKind::Mismatch);
        let selection = view.select_negative_review(negative_id).unwrap();
        assert!(selection.available_decisions.is_empty());
        assert!(
            selection
                .proof(ProcedureNegativeReviewDecision::ConfirmHarm)
                .is_none()
        );
        let result_revision_ids = view.results.keys().copied().collect();
        assert!(
            review_procedure_negative(
                &view,
                ProposalCommandContext {
                    command_id: evertrace_domain::ids::CommandId::new_v7(),
                    occurred_at_us: 20,
                    effective_config_hash: [1; 32],
                    algorithm_revision: "negative-review-test-v1".into(),
                },
                negative_id,
                ProcedureNegativeReviewProof::ReplayUpheld {
                    result_revision_ids,
                },
            )
            .is_err()
        );

        let (mut mixed, negative_id) = review_view(ResultKind::Passed);
        let attempt_id = mixed.usages.values().next().unwrap().attempt_ids[0];
        let run_id = mixed.runs.keys().next().copied().unwrap();
        let run_revision = mixed.runs[&run_id].0.revision_id;
        let mismatch = result(run_id, run_revision, ResultKind::Mismatch);
        mixed.result_seqs.insert(mismatch.revision_id, 13);
        mixed.results.insert(mismatch.revision_id, mismatch);
        assert!(
            mixed
                .select_negative_review(negative_id)
                .unwrap()
                .available_decisions
                .is_empty()
        );
        assert_eq!(mixed.runs[&run_id].0.attempt_id, Some(attempt_id));

        let (mut terminal, negative_id) = review_view(ResultKind::Passed);
        terminal
            .negative_reviews
            .get_mut(&negative_id)
            .unwrap()
            .status = ProcedureNegativeReviewStatus::Dismissed;
        let selection = terminal.select_negative_review(negative_id).unwrap();
        assert_eq!(
            selection.review_status,
            ProcedureNegativeReviewStatus::Dismissed
        );
        assert!(selection.available_decisions.is_empty());
        assert!(
            selection
                .proof(ProcedureNegativeReviewDecision::DismissAttribution)
                .is_none()
        );
    }

    #[derive(Clone, Copy)]
    enum ResultKind {
        Passed,
        Mismatch,
    }

    fn review_view(kind: ResultKind) -> (ProcedureUsageCurrentView, ProcedureNegativeEvidenceId) {
        let mut view = ProcedureUsageCurrentView::default();
        let attempt_id = AttemptId::new_v7();
        let usage_id = ProcedureUsageId::new_v7();
        let procedure_revision_id = RevisionId::new_v7();
        let task_id = TaskId::new_v7();
        let local_context = ProcedureLocalContext {
            repository_id: None,
            worktree_id: None,
            phase: ProcedureUsagePhase::AtEntry,
            failure_signature: Some("failure".into()),
        };
        let usage = ProcedureUsageRevision {
            procedure_usage_id: usage_id,
            usage_revision_id: RevisionId::new_v7(),
            predecessor_revision_id: None,
            revision_generation: 1,
            procedure_revision_id,
            task_id,
            workstream_id: WorkstreamId::new_v7(),
            exposure_episode_revision_id: RevisionId::new_v7(),
            decision_boundary_ref: "boundary".into(),
            route_decision: ProcedureUsageRouteDecision::Apply,
            stage: ProcedureUsageStage::Outcome,
            attempt_ids: vec![attempt_id],
            action_episode_revision_ids: vec![RevisionId::new_v7()],
            verification_episode_revision_ids: vec![RevisionId::new_v7()],
            action_operation_refs: Vec::new(),
            verification_operation_refs: Vec::new(),
            work_binding_revision_refs: Vec::new(),
            scope_effect_refs: Vec::new(),
            correlation_state: ProcedureCorrelationState::Resolved,
            eligible: ProcedureTruth::True,
            action_aligned: ProcedureTruth::True,
            verifier_aligned: ProcedureTruth::True,
            outcome_supported: ProcedureTruth::False,
            local_context: local_context.clone(),
            source_watermark: 1,
            evidence_refs: vec!["usage:evidence".into()],
            created_at_us: 1,
        };
        view.usages.insert(usage_id, usage);
        let run = run(attempt_id);
        let evidence = result(run.run_id, run.revision_id, kind);
        view.runs.insert(run.run_id, (run, 12));
        view.result_seqs.insert(evidence.revision_id, 12);
        view.results.insert(evidence.revision_id, evidence);
        let negative_id = ProcedureNegativeEvidenceId::new_v7();
        view.negatives.insert(
            negative_id,
            ProcedureNegativeEvidence {
                negative_evidence_id: negative_id,
                level: ProcedureNegativeLevel::SuspectedHarm,
                procedure_revision_id,
                procedure_usage_id: usage_id,
                task_id,
                session_id: "session".into(),
                evidence_refs: vec!["negative:evidence".into()],
                observed_effect: "failure".into(),
                expected_effect: "success".into(),
                confounders: vec!["replay_required".into()],
                attribution_basis: ProcedureAttributionBasis::ResolvedLocalized,
                decision_source: ProcedureNegativeDecisionSource::AdoptedAttemptFailed,
                local_context: Some(local_context),
                created_at_us: 10,
            },
        );
        let review = ProcedureNegativeReviewEvent {
            review_event_id: RevisionId::new_v7(),
            negative_evidence_id: negative_id,
            predecessor_review_event_id: None,
            review_generation: 1,
            status: ProcedureNegativeReviewStatus::Pending,
            successor_usage_revision_id: None,
            reason: "review_required".into(),
            evidence_refs: vec!["negative:evidence".into()],
            created_at_us: 11,
        };
        view.negative_seqs.insert(negative_id, 10);
        view.negative_review_seqs.insert(negative_id, 11);
        view.negative_reviews.insert(negative_id, review);
        (view, negative_id)
    }

    fn run(attempt_id: AttemptId) -> ExperimentRun {
        ExperimentRun {
            run_id: ExperimentRunId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            workstream_id: WorkstreamId::new_v7(),
            attempt_id: Some(attempt_id),
            attempt_binding_status: AttemptBindingStatus::Resolved,
            strategy_contract_fingerprint: [1; 32],
            origin: RunOrigin::Local,
            external_system_id: None,
            external_run_key: None,
            source_receipt_refs: Vec::new(),
            observability: RunObservability::Full,
            execution_status: RunExecutionStatus::Completed,
            contract_validity: RunContractValidity::Valid,
            experiment_contract_fingerprint: [2; 32],
            code_snapshot_id: WorktreeSnapshotId::new_v7(),
            data_fingerprint: "data".into(),
            normalized_config: vec![ContractField {
                name: "mode".into(),
                value: "test".into(),
            }],
            variable_declaration: VariableDeclaration {
                varied: Vec::new(),
                fixed: vec!["mode".into()],
                uncontrolled: Vec::new(),
            },
            comparison_key: [3; 32],
            seed_policy: SeedPolicy::Fixed,
            seed_values: vec!["1".into()],
            nondeterministic: false,
            metric_definition: "verification".into(),
            metric_extractor_version: "parser-v1".into(),
            multi_cas_metric_policy: MultiCasMetricPolicy::RejectMultipleParsed,
            environment_fingerprint: "environment".into(),
            comparison_execution_binding: None,
            work_artifact_refs: Vec::new(),
            terminal_evidence_refs: Vec::new(),
            created_at_us: 1,
            started_at_us: Some(1),
            ended_at_us: Some(2),
        }
    }

    fn result(
        run_id: ExperimentRunId,
        run_revision: RevisionId,
        kind: ResultKind,
    ) -> ResultEvidence {
        let artifact = WorkArtifactId::new_v7();
        let (verifier_receipt, completeness, failure) = match kind {
            ResultKind::Passed => (
                VerifierReceipt {
                    verifier_version: "verifier-v1".into(),
                    status: VerifierStatus::Passed,
                    failure_code: None,
                },
                EvidenceCompleteness::Complete,
                None,
            ),
            ResultKind::Mismatch => (
                VerifierReceipt {
                    verifier_version: "verifier-v1".into(),
                    status: VerifierStatus::Failed,
                    failure_code: Some(VerifierFailureCode::DeterministicReparseMismatch),
                },
                EvidenceCompleteness::Incomplete,
                Some(ResultFailure::Verifier(
                    VerifierFailureCode::DeterministicReparseMismatch,
                )),
            ),
        };
        ResultEvidence {
            result_evidence_id: ResultEvidenceId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            experiment_run_id: run_id,
            experiment_run_revision_id: run_revision,
            result_scope: ResultScope::Partial,
            raw_artifact_refs: vec![artifact],
            raw_cas_refs: Vec::new(),
            parsed_metric: Some(MetricValue {
                decimal: "0".into(),
                unit: "boolean".into(),
                uncertainty_decimal: None,
            }),
            parser_receipt: ParserReceipt {
                parser_version: "parser-v1".into(),
                input_artifact_refs: vec![artifact],
                input_cas_refs: Vec::new(),
                status: ParserStatus::Parsed,
                failure_code: None,
            },
            verifier_receipt: Some(verifier_receipt),
            completeness,
            failure,
            created_at_us: 12,
        }
    }
}
