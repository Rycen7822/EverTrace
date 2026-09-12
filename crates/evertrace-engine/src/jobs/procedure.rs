use std::collections::{BTreeMap, BTreeSet};

use evertrace_domain::{
    evidence::hex,
    ids::{CommandId, JobId},
    procedure::{ProcedureDraft, ProcedureScope},
    revision::RevisionId,
    semantic::{ProposalEligibility, ProposalPayload, ProposalStatus, RevisionProposal},
};
use evertrace_store::{
    DurableJob, JobBudget, JobStatus, JobTerminalAudit, JobTerminalOutcome, JobTerminalReason,
    JournalCommand, JournalEventDraft, JournalPayload, ObjectDeletionCandidateAdmission,
    ObjectDeletionCandidateAdmissionView, ProjectionSnapshot, RuntimeSchedulerView,
    SemanticCurrentView, StoreError,
};

use crate::{provider::ProviderProcedureContent, semantic::SemanticServiceError};

pub(crate) const KIND: &str = "procedure_review_v1";
mod source;
pub(crate) use source::is_source as has_source_target;
pub(crate) use source::jobs as source_jobs;
pub(crate) fn source_scope(
    snapshot: &ProjectionSnapshot,
    job: &DurableJob,
) -> Option<ProcedureScope> {
    source::scope(snapshot, job)
}

pub(crate) fn is_current(snapshot: &ProjectionSnapshot, job: &DurableJob) -> bool {
    if source::is_source(job) {
        source::current(snapshot, job)
    } else {
        current(snapshot, job).is_ok()
    }
}

pub(crate) struct Input {
    pub proposal: RevisionProposal,
    pub refs: Vec<String>,
    pub watermark: u64,
    pub key: String,
    evidence: Vec<crate::provider::ProtectedDeltaItem>,
    duplicate: bool,
    existing: Option<evertrace_domain::procedure::ProcedureRevision>,
}

pub(crate) fn budget(
    planner: &super::SynthesisPlanner,
    wall: std::time::Duration,
) -> Result<JobBudget, SemanticServiceError> {
    let mut budget = planner.durable_budget(wall)?;
    budget.max_items = 16;
    budget.max_bytes = Some(16 * 1024);
    budget.max_input_tokens = Some(budget.max_input_tokens.unwrap().min(8192));
    budget.max_output_tokens = Some(budget.max_output_tokens.unwrap().min(2048));
    Ok(budget)
}

// One planning snapshot, metadata only. Text is decoded only for a selected,
// not-yet-reviewed cohort; unrelated surfaces are never deserialized here.
struct ReviewInputs<'a> {
    view: &'a SemanticCurrentView,
    procedures: BTreeMap<RevisionId, &'a evertrace_domain::procedure::ProcedureRevision>,
    refs: BTreeMap<&'a str, Vec<&'a evertrace_store::objects::ObjectRow>>,
    observations: BTreeMap<&'a str, &'a evertrace_store::objects::ObjectRow>,
    tasks: BTreeMap<(String, Option<String>, String), Vec<&'a evertrace_store::objects::ObjectRow>>,
    source_by_observation: BTreeMap<String, (String, String)>,
    sources: BTreeMap<(String, String), Vec<&'a evertrace_store::objects::ObjectRow>>,
}

impl<'a> ReviewInputs<'a> {
    fn new(
        snapshot: &'a ProjectionSnapshot,
        view: &'a SemanticCurrentView,
        usage: &'a crate::procedure::ProcedureUsageCurrentView,
    ) -> Result<Self, SemanticServiceError> {
        let mut result = Self {
            view,
            procedures: Default::default(),
            refs: Default::default(),
            observations: Default::default(),
            tasks: Default::default(),
            source_by_observation: Default::default(),
            sources: Default::default(),
        };
        for row in snapshot.data_rows() {
            for reference in row
                .object_id
                .iter()
                .chain(row.current_revision_id.iter())
                .collect::<BTreeSet<_>>()
            {
                result.refs.entry(reference).or_default().push(row);
            }
            match row.object_kind.as_deref() {
                Some("procedure_revision") => {
                    let revision = row
                        .current_revision_id
                        .as_ref()
                        .and_then(|id| id.parse().ok())
                        .ok_or(StoreError::StoreCorrupt)?;
                    if let Some(procedure) = usage.current_procedure_by_revision(revision) {
                        result.procedures.insert(revision, procedure);
                    }
                }
                Some("evidence_surface") => {
                    let reference = row
                        .current_revision_id
                        .as_deref()
                        .ok_or(StoreError::StoreCorrupt)?;
                    if result.observations.insert(reference, row).is_some() {
                        return Err(StoreError::StoreCorrupt.into());
                    }
                    if let (Some(repository), Some(task)) = (&row.repository_id, &row.task_id) {
                        result
                            .tasks
                            .entry((repository.clone(), None, task.clone()))
                            .or_default()
                            .push(row);
                        if let Some(worktree) = &row.worktree_id {
                            result
                                .tasks
                                .entry((repository.clone(), Some(worktree.clone()), task.clone()))
                                .or_default()
                                .push(row);
                        }
                    }
                }
                _ => {}
            }
        }
        for rows in result.tasks.values_mut() {
            rows.sort_by_key(|row| std::cmp::Reverse(row.source_event_seq));
            rows.truncate(16);
        }
        // Only admitted message metadata expands a taskless source cohort;
        // tool/Stop records do not become automatic method-review triggers.
        for (instance, revision, observation) in source::review_sources(snapshot)? {
            let key = (instance, revision);
            if let Some(surface) = result.observations.get(observation.as_str()) {
                result
                    .sources
                    .entry(key.clone())
                    .or_default()
                    .push(*surface);
                result.source_by_observation.insert(observation, key);
            }
        }
        for rows in result.sources.values_mut() {
            rows.sort_by_key(|row| std::cmp::Reverse(row.source_event_seq));
            rows.truncate(16);
        }
        Ok(result)
    }
}

struct SelectedInput<'a> {
    refs: Vec<String>,
    watermark: u64,
    key: String,
    origin_revision: RevisionId,
    surfaces: Vec<&'a evertrace_store::objects::ObjectRow>,
}

fn select_input<'a>(
    context: &ReviewInputs<'a>,
    proposal: &RevisionProposal,
    existing: Option<&evertrace_domain::procedure::ProcedureRevision>,
) -> Result<SelectedInput<'a>, SemanticServiceError> {
    let ProposalPayload::Procedure(payload) = &proposal.payload else {
        return Err(SemanticServiceError::InvalidInput);
    };
    let (repository, worktree) = match payload.draft().scope {
        ProcedureScope::Worktree {
            repository_id,
            worktree_id,
        } => (repository_id.to_string(), Some(worktree_id.to_string())),
        ProcedureScope::Repository { repository_id } => (repository_id.to_string(), None),
        // A Global support-read closure is not implemented by this worker.
        ProcedureScope::Global => return Err(SemanticServiceError::InvalidInput),
    };
    if !matches!(
        proposal.status,
        ProposalStatus::Pending | ProposalStatus::Validating
    ) && existing.is_none()
    {
        return Err(SemanticServiceError::InvalidInput);
    }
    let mut origin = proposal;
    while let Some(parent) = origin.parent_proposal_revision_id {
        let parent = context
            .view
            .proposal_revisions
            .get(&parent)
            .ok_or(StoreError::StoreCorrupt)?;
        if origin.review_reason.as_deref() != Some(KIND)
            && (origin.payload != parent.payload
                || origin.source_cohort_refs != parent.source_cohort_refs)
        {
            break;
        }
        origin = parent;
    }
    let mut observations = BTreeSet::new();
    let mut tasks = BTreeSet::new();
    let mut watermark = 0;
    for row in proposal
        .source_cohort_refs
        .iter()
        .flat_map(|reference| context.refs.get(reference.as_str()).into_iter().flatten())
    {
        watermark = watermark.max(row.source_event_seq);
        match row.object_kind.as_deref() {
            Some("source_receipt") => {
                let JournalPayload::SourceReceiptRecorded(receipt) =
                    serde_json::from_str::<JournalPayload>(
                        row.payload_json
                            .as_deref()
                            .ok_or(StoreError::StoreCorrupt)?,
                    )
                    .map_err(|_| StoreError::StoreCorrupt)?
                else {
                    return Err(StoreError::StoreCorrupt.into());
                };
                observations.insert(receipt.source_observation_id.to_string());
                tasks.extend(receipt.task_id.map(|task| task.to_string()));
            }
            Some("source_observation" | "evidence_surface") => {
                observations.extend(row.current_revision_id.clone());
            }
            _ => {}
        }
    }
    let mut surfaces = observations
        .iter()
        .filter_map(|reference| context.observations.get(reference.as_str()).copied())
        .chain(
            observations
                .iter()
                .filter_map(|reference| context.source_by_observation.get(reference))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .flat_map(|key| context.sources.get(key).into_iter().flatten().copied()),
        )
        .chain(tasks.into_iter().flat_map(|task| {
            context
                .tasks
                .get(&(repository.clone(), worktree.clone(), task))
                .into_iter()
                .flatten()
                .copied()
        }))
        .filter(|row| {
            row.repository_id.as_deref() == Some(repository.as_str())
                && worktree
                    .as_ref()
                    .is_none_or(|worktree| row.worktree_id.as_ref() == Some(worktree))
        })
        .collect::<Vec<_>>();
    surfaces.sort_by_key(|row| std::cmp::Reverse(row.source_event_seq));
    surfaces.dedup_by_key(|row| row.current_revision_id.as_deref());
    surfaces.truncate(16);
    watermark = watermark.max(
        surfaces
            .iter()
            .map(|row| row.source_event_seq)
            .max()
            .unwrap_or(0),
    );
    let mut cohort = proposal.clone();
    cohort.source_cohort_refs.extend(
        surfaces
            .iter()
            .filter_map(|row| row.current_revision_id.clone()),
    );
    cohort.source_cohort_refs.sort();
    cohort.source_cohort_refs.dedup();
    let hash = cohort
        .recompute_source_cohort_hash()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    Ok(SelectedInput {
        refs: cohort.source_cohort_refs,
        watermark,
        key: format!(
            "{KIND}:{}:{}",
            existing.map_or(origin.proposal_revision_id, |procedure| procedure
                .revision_id),
            hex(&hash)
        ),
        origin_revision: origin.proposal_revision_id,
        surfaces,
    })
}

fn input(
    context: &ReviewInputs<'_>,
    proposal: &RevisionProposal,
    existing: Option<&evertrace_domain::procedure::ProcedureRevision>,
    selected: SelectedInput<'_>,
) -> Result<Input, SemanticServiceError> {
    let ProposalPayload::Procedure(payload) = &proposal.payload else {
        return Err(SemanticServiceError::InvalidInput);
    };
    let mut evidence = BTreeMap::new();
    for row in selected.surfaces {
        let JournalPayload::EvidenceSurfaceRecorded(surface) =
            serde_json::from_str::<JournalPayload>(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?
        else {
            return Err(StoreError::StoreCorrupt.into());
        };
        let same_scope = match payload.draft().scope {
            ProcedureScope::Worktree {
                repository_id,
                worktree_id,
            } => {
                surface.repository_instance_id == Some(repository_id)
                    && surface.worktree_instance_id == Some(worktree_id)
            }
            ProcedureScope::Repository { repository_id } => {
                surface.repository_instance_id == Some(repository_id)
            }
            ProcedureScope::Global => false,
        };
        if !same_scope
            || row.current_revision_id.as_deref()
                != Some(surface.source_observation_revision_ref.to_string().as_str())
            || row.task_id != surface.task_id.map(|task| task.to_string())
        {
            return Err(StoreError::StoreCorrupt.into());
        }
        surface.validate().map_err(|_| StoreError::StoreCorrupt)?;
        let text = &surface.protected_text;
        let mut end = text.len().min(2048);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        evidence.insert(
            surface.source_observation_revision_ref.to_string(),
            (
                row.source_event_seq,
                crate::provider::ProtectedDeltaItem {
                    kind: crate::provider::ProtectedDeltaKind::Progress,
                    value: text[..end].to_owned(),
                    direct_refs: vec![surface.source_observation_revision_ref.to_string()],
                },
            ),
        );
    }
    payload
        .draft()
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    let mut duplicate = false;
    for procedure in context.procedures.values() {
        if existing.is_none_or(|target| target.procedure_id != procedure.procedure_id)
            && procedure.draft.scope.contains(&payload.draft().scope)
            && content(&procedure.draft) == content(payload.draft())
        {
            duplicate = true;
            break;
        }
    }
    Ok(Input {
        proposal: proposal.clone(),
        refs: selected.refs,
        watermark: selected.watermark,
        key: selected.key,
        evidence: evidence.into_values().map(|(_, value)| value).collect(),
        duplicate,
        existing: existing.cloned(),
    })
}

fn accepted<'a>(
    view: &'a SemanticCurrentView,
    procedure: &evertrace_domain::procedure::ProcedureRevision,
) -> Result<&'a RevisionProposal, SemanticServiceError> {
    let mut matching = view.proposals.values().filter(|proposal| proposal.acceptance.as_ref().is_some_and(|acceptance| matches!(acceptance.accepted_target,
        evertrace_domain::semantic::AcceptedProposalTarget::Procedure { procedure_id, procedure_revision_id, .. } if procedure_id == procedure.procedure_id && procedure_revision_id == procedure.revision_id)));
    let proposal = matching.next().ok_or(StoreError::StoreCorrupt)?;
    if matching.next().is_some() {
        return Err(StoreError::StoreCorrupt.into());
    }
    Ok(proposal)
}

pub(crate) fn jobs(
    snapshot: &ProjectionSnapshot,
    planner: &super::SynthesisPlanner,
    config: [u8; 32],
    wall: std::time::Duration,
    limit: usize,
) -> Result<Vec<DurableJob>, SemanticServiceError> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let view = SemanticCurrentView::from_snapshot(snapshot)?;
    let runtime = RuntimeSchedulerView::from_snapshot(snapshot)?;
    let usage = crate::procedure::ProcedureUsageCurrentView::from_promotion_snapshot(snapshot)?;
    let context = ReviewInputs::new(snapshot, &view, &usage)?;
    let mut covered = BTreeMap::<&str, u64>::new();
    let mut last_review = BTreeMap::<&str, JobId>::new();
    for job in runtime.jobs.iter().filter(|job| {
        job.kind == KIND
            && !source::is_source(job)
            && (job.state == JobStatus::Succeeded || job.config_hash == config)
    }) {
        for reference in std::iter::once(job.idempotency_key.as_str())
            .chain(std::iter::once(job.target_revision.as_str()))
            .chain(
                job.terminal
                    .as_ref()
                    .and_then(|terminal| terminal.result_ref.as_deref()),
            )
        {
            let watermark = covered.entry(reference).or_default();
            *watermark = (*watermark).max(job.target_watermark);
            last_review
                .entry(reference)
                .and_modify(|id| *id = (*id).max(job.job_id))
                .or_insert(job.job_id);
        }
    }
    let mut jobs = Vec::new();
    let budget = budget(planner, wall)?;
    let mut enqueue = |proposal: &RevisionProposal,
                       existing: Option<&evertrace_domain::procedure::ProcedureRevision>|
     -> Result<bool, SemanticServiceError> {
        let ProposalPayload::Procedure(payload) = &proposal.payload else {
            return Ok(false);
        };
        if payload.draft().scope == ProcedureScope::Global {
            return Ok(false);
        }
        let selected = select_input(&context, proposal, existing)?;
        let cohort_watermark = proposal
            .source_cohort_refs
            .iter()
            .flat_map(|reference| context.refs.get(reference.as_str()).into_iter().flatten())
            .map(|row| row.source_event_seq)
            .max()
            .unwrap_or(0);
        if selected.watermark == 0
            || !selected.surfaces.iter().any(|row| {
                row.source_event_seq > cohort_watermark
                    && row
                        .current_revision_id
                        .as_ref()
                        .is_some_and(|id| !proposal.source_cohort_refs.contains(id))
            })
            || existing.is_some_and(|procedure| selected.watermark <= procedure.source_watermark)
            || [
                selected.key.as_str(),
                &proposal.proposal_revision_id.to_string(),
                &selected.origin_revision.to_string(),
                &existing
                    .map_or(proposal.proposal_revision_id, |procedure| {
                        procedure.revision_id
                    })
                    .to_string(),
            ]
            .iter()
            .any(|reference| {
                covered
                    .get(*reference)
                    .is_some_and(|watermark| *watermark >= selected.watermark)
            })
        {
            return Ok(false);
        }
        let input = input(&context, proposal, existing, selected)?;
        let model = needs_model(&input);
        let mut job_budget = budget.clone();
        if !model {
            job_budget.max_input_tokens = None;
            job_budget.max_output_tokens = None;
            job_budget.max_calls = None;
        }
        jobs.push(DurableJob {
            job_id: JobId::new_v7(),
            idempotency_key: input.key,
            target_revision: input
                .existing
                .as_ref()
                .map_or(input.proposal.proposal_revision_id, |procedure| {
                    procedure.revision_id
                })
                .to_string(),
            target_watermark: input.watermark,
            target_generation: input.watermark.max(1),
            kind: KIND.into(),
            algorithm_revision: KIND.into(),
            model_id: model.then(|| planner.llm.model.clone()),
            priority: 5,
            state: JobStatus::Queued,
            attempt: 1,
            backoff_until_us: None,
            config_hash: config,
            budget: job_budget,
            terminal: None,
            lease_until_us: None,
        });
        Ok(jobs.len() >= limit)
    };
    let mut candidates = view
        .proposals
        .values()
        .filter(|proposal| {
            matches!(proposal.payload, ProposalPayload::Procedure(_))
                && matches!(
                    proposal.status,
                    ProposalStatus::Pending | ProposalStatus::Validating
                )
        })
        .map(|proposal| (proposal, None))
        .collect::<Vec<_>>();
    let mut accepted_proposals = BTreeMap::new();
    for proposal in view.proposals.values() {
        if let Some(acceptance) = &proposal.acceptance
            && let evertrace_domain::semantic::AcceptedProposalTarget::Procedure {
                procedure_revision_id,
                ..
            } = acceptance.accepted_target
            && accepted_proposals
                .insert(procedure_revision_id, proposal)
                .is_some()
        {
            return Err(StoreError::StoreCorrupt.into());
        }
    }
    for procedure in context.procedures.values() {
        if procedure.draft.scope != ProcedureScope::Global {
            candidates.push((
                *accepted_proposals
                    .get(&procedure.revision_id)
                    .ok_or(StoreError::StoreCorrupt)?,
                Some(*procedure),
            ));
        }
    }
    // Durable job IDs supply fairness: unserved targets, then least recently
    // reviewed targets. Fresh facts for an early target cannot starve the tail.
    candidates.sort_by_key(|(proposal, existing)| {
        (
            last_review
                .get(
                    existing
                        .map_or(proposal.proposal_revision_id, |procedure| {
                            procedure.revision_id
                        })
                        .to_string()
                        .as_str(),
                )
                .copied(),
            proposal.proposal_id,
        )
    });
    for (proposal, existing) in candidates {
        if enqueue(proposal, existing)? {
            break;
        }
    }
    Ok(jobs)
}

pub(crate) fn current(
    snapshot: &ProjectionSnapshot,
    job: &DurableJob,
) -> Result<Input, SemanticServiceError> {
    let view = SemanticCurrentView::from_snapshot(snapshot)?;
    let usage = crate::procedure::ProcedureUsageCurrentView::from_promotion_snapshot(snapshot)?;
    let context = ReviewInputs::new(snapshot, &view, &usage)?;
    let existing = job
        .target_revision
        .parse()
        .ok()
        .and_then(|revision| usage.current_procedure_by_revision(revision));
    let proposal = if let Some(procedure) = existing {
        accepted(&view, procedure)?
    } else {
        view.proposals
            .values()
            .find(|proposal| proposal.proposal_revision_id.to_string() == job.target_revision)
            .ok_or(SemanticServiceError::BaseConflict)?
    };
    let input = input(
        &context,
        proposal,
        existing,
        select_input(&context, proposal, existing)?,
    )?;
    if job.kind != KIND
        || job.algorithm_revision != KIND
        || input.key != job.idempotency_key
        || input.watermark != job.target_watermark
        || job.target_generation != input.watermark.max(1)
    {
        return Err(SemanticServiceError::BaseConflict);
    }
    if existing.is_none()
        && let Some(evertrace_domain::semantic::ProposalTargetId::Procedure(id)) =
            proposal.target_id
        && proposal.base_revision_id.is_none_or(|revision| {
            usage
                .current_procedure_by_revision(revision)
                .is_none_or(|value| value.procedure_id != id)
        })
    {
        return Err(SemanticServiceError::BaseConflict);
    }
    if !matches!(
        ObjectDeletionCandidateAdmissionView::from_snapshot(snapshot)?
            .classify_proposal(proposal)?,
        ObjectDeletionCandidateAdmission::Clear
    ) {
        return Err(SemanticServiceError::BaseConflict);
    }
    Ok(input)
}

pub(crate) async fn allowed(
    writer: &crate::WriterHandle,
    snapshot: &ProjectionSnapshot,
    job: &DurableJob,
    report: Option<&evertrace_codex::HostProbeReport>,
) -> Result<bool, SemanticServiceError> {
    if source::is_source(job) {
        return source::allowed(writer, snapshot, job, report).await;
    }
    let input = match current(snapshot, job) {
        Ok(input) => input,
        Err(SemanticServiceError::BaseConflict | SemanticServiceError::InvalidInput) => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    allowed_input(writer, snapshot, job, &input, report).await
}

async fn allowed_input(
    writer: &crate::WriterHandle,
    snapshot: &ProjectionSnapshot,
    job: &DurableJob,
    input: &Input,
    report: Option<&evertrace_codex::HostProbeReport>,
) -> Result<bool, SemanticServiceError> {
    let ProposalPayload::Procedure(payload) = &input.proposal.payload else {
        unreachable!()
    };
    allowed_refs(
        writer,
        snapshot,
        &input.refs,
        &payload.draft().scope,
        job.config_hash,
        report,
    )
    .await
}

async fn allowed_refs(
    writer: &crate::WriterHandle,
    snapshot: &ProjectionSnapshot,
    refs: &[String],
    scope: &ProcedureScope,
    config_hash: [u8; 32],
    report: Option<&evertrace_codex::HostProbeReport>,
) -> Result<bool, SemanticServiceError> {
    let rows = snapshot
        .data_rows()
        .filter(|row| {
            row.object_id.as_ref().is_some_and(|id| refs.contains(id))
                || row
                    .current_revision_id
                    .as_ref()
                    .is_some_and(|id| refs.contains(id))
        })
        .collect::<Vec<_>>();
    if rows.len() > 64
        || refs.iter().any(|reference| {
            !rows.iter().any(|row| {
                row.object_id.as_ref() == Some(reference)
                    || row.current_revision_id.as_ref() == Some(reference)
            })
        })
    {
        return Ok(false);
    }
    let scopes = crate::repository::row_repository_contexts(snapshot, &rows)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let mut ids = scopes.values().flatten().copied().collect::<BTreeSet<_>>();
    match *scope {
        ProcedureScope::Worktree { repository_id, .. }
        | ProcedureScope::Repository { repository_id } => {
            ids.insert(repository_id);
        }
        ProcedureScope::Global => return Ok(false),
    }
    if !crate::repository::blocked_repositories(writer, ids, report, config_hash)
        .await
        .map_err(|_| StoreError::StoreCorrupt)?
        .is_empty()
    {
        return Ok(false);
    }
    Ok(
        crate::session_import::blocked_source_rows(writer, report, snapshot, &rows, config_hash)
            .await
            .map_err(|_| StoreError::StoreCorrupt)?
            .is_empty(),
    )
}

pub(crate) async fn readable_revisions(
    writer: &crate::WriterHandle,
    snapshot: &ProjectionSnapshot,
    report: Option<&evertrace_codex::HostProbeReport>,
    config: [u8; 32],
    scope: (
        Option<evertrace_domain::ids::RepositoryId>,
        Option<evertrace_domain::ids::WorktreeId>,
    ),
    selected: Option<&BTreeSet<String>>,
    deadline: std::time::Instant,
) -> Result<BTreeSet<String>, SemanticServiceError> {
    let mut output = BTreeSet::new();
    let (repository, worktree) = scope;
    let Some(repository) = repository else {
        return Ok(output);
    };
    if selected.is_some_and(BTreeSet::is_empty) {
        return Ok(output);
    }
    let mut refs_index = BTreeMap::<&str, Vec<&evertrace_store::ObjectRow>>::new();
    let mut lookup = BTreeMap::new();
    let mut current = BTreeMap::<&str, &evertrace_store::ObjectRow>::new();
    for row in snapshot.data_rows() {
        lookup.insert(row.row_id.as_str(), row);
        for reference in row
            .object_id
            .iter()
            .chain(row.current_revision_id.iter())
            .collect::<BTreeSet<_>>()
        {
            refs_index.entry(reference).or_default().push(row);
        }
        if matches!(
            row.object_kind.as_deref(),
            Some("revision_proposal_revision" | "procedure_revision")
        ) {
            let id = row.object_id.as_deref().ok_or(StoreError::StoreCorrupt)?;
            match current.get(id) {
                Some(previous) if previous.source_event_seq > row.source_event_seq => {}
                Some(previous) if previous.source_event_seq == row.source_event_seq => {
                    return Err(StoreError::StoreCorrupt.into());
                }
                _ => {
                    current.insert(id, row);
                }
            }
        }
    }
    let candidate_rows = current
        .values()
        .filter(|row| {
            row.object_kind.as_deref() == Some("revision_proposal_revision")
                && matches!(row.lifecycle.as_deref(), Some("pending" | "validating"))
                && selected.is_none_or(|ids| {
                    row.current_revision_id
                        .as_ref()
                        .is_some_and(|id| ids.contains(id))
                })
        })
        .collect::<Vec<_>>();
    if candidate_rows.is_empty() {
        return Ok(output);
    }
    let deletion = ObjectDeletionCandidateAdmissionView::from_snapshot(snapshot)?;
    let mut candidates = Vec::new();
    let mut union = BTreeMap::new();
    for row in candidate_rows {
        let JournalPayload::RevisionProposalRecorded(proposal) = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?,
        )
        .map_err(|_| StoreError::StoreCorrupt)?
        else {
            return Err(StoreError::StoreCorrupt.into());
        };
        proposal.validate().map_err(|_| StoreError::StoreCorrupt)?;
        if row.row_class != Some(evertrace_store::objects::ObjectRowClass::Object)
            || row.object_id.as_deref() != Some(proposal.proposal_id.to_string().as_str())
            || row.current_revision_id.as_deref()
                != Some(proposal.proposal_revision_id.to_string().as_str())
        {
            return Err(StoreError::StoreCorrupt.into());
        }
        let ProposalPayload::Procedure(payload) = &proposal.payload else {
            continue;
        };
        let scope = &payload.draft().scope;
        let in_scope = match *scope {
            ProcedureScope::Worktree {
                repository_id,
                worktree_id,
            } => repository_id == repository && Some(worktree_id) == worktree,
            ProcedureScope::Repository { repository_id } => repository_id == repository,
            ProcedureScope::Global => false,
        };
        if !in_scope
            || !matches!(
                proposal.status,
                ProposalStatus::Pending | ProposalStatus::Validating
            )
            || !matches!(
                deletion.classify_proposal(&proposal)?,
                ObjectDeletionCandidateAdmission::Clear
            )
        {
            continue;
        }
        if let Some(evertrace_domain::semantic::ProposalTargetId::Procedure(id)) =
            proposal.target_id
            && proposal.base_revision_id.is_none_or(|revision| {
                current.get(id.to_string().as_str()).is_none_or(|row| {
                    row.object_kind.as_deref() != Some("procedure_revision")
                        || row.current_revision_id.as_deref() != Some(revision.to_string().as_str())
                })
            })
        {
            continue;
        }
        let mut refs = proposal.source_cohort_refs.clone();
        refs.extend(proposal.evidence_refs.clone());
        refs.extend(payload.draft().evidence_refs.clone());
        refs.sort();
        refs.dedup();
        if refs
            .iter()
            .any(|reference| !refs_index.contains_key(reference.as_str()))
        {
            continue;
        }
        let rows = refs
            .iter()
            .flat_map(|reference| refs_index[reference.as_str()].iter().copied())
            .map(|row| (row.row_id.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        if rows.len() > 64 {
            continue;
        }
        union.extend(rows.iter().map(|(id, row)| (*id, *row)));
        candidates.push((
            proposal.proposal_revision_id.to_string(),
            rows.into_values().collect::<Vec<_>>(),
        ));
    }
    if candidates.is_empty() {
        return Ok(output);
    }
    let rows = union.into_values().collect::<Vec<_>>();
    let contexts = crate::repository::row_repository_contexts(snapshot, &rows)
        .map_err(|_| StoreError::StoreCorrupt)?;
    let ids = contexts
        .values()
        .flatten()
        .copied()
        .chain([repository])
        .collect();
    let blocked_repositories =
        crate::repository::blocked_repositories_before(writer, ids, report, config, deadline)
            .await
            .map_err(|_| StoreError::StoreCorrupt)?;
    if blocked_repositories.contains(&repository) {
        return Ok(output);
    }
    let blocked_sources = crate::session_import::blocked_source_rows_before(
        writer,
        report,
        snapshot,
        &rows,
        config,
        Some(&lookup),
        Some(deadline),
    )
    .await
    .map_err(|_| StoreError::StoreCorrupt)?;
    for (revision, rows) in candidates {
        if rows.iter().all(|row| {
            !blocked_sources.contains(&row.row_id)
                && contexts[row.row_id.as_str()].is_disjoint(&blocked_repositories)
        }) {
            output.insert(revision);
        }
    }
    Ok(output)
}

pub(crate) fn needs_model(input: &Input) -> bool {
    // A single unchanged observation supplies no distinct material to reconcile.
    // Missing/unknown evidence is a durable no-op, not a periodic model trigger.
    input.evidence.len() > 1 && !input.duplicate
}

fn content(draft: &ProcedureDraft) -> ProviderProcedureContent {
    ProviderProcedureContent {
        title: draft.title.clone(),
        summary: draft.summary.clone(),
        procedure_kind: draft.kind,
        when: draft.when.clone(),
        applicability_expr: draft.applicability_expr.clone(),
        avoid_expr: draft.avoid_expr.clone(),
        completion_expr: draft.completion_expr.clone(),
        stage_alignment: draft.stage_alignment.clone(),
        actions: draft.actions.clone(),
        done: draft.done.clone(),
        pitfalls: draft.pitfalls.clone(),
    }
}

pub(crate) async fn execute(
    writer: &crate::WriterHandle,
    planner: &super::SynthesisPlanner,
    snapshot: &ProjectionSnapshot,
    job: &DurableJob,
    report: Option<&evertrace_codex::HostProbeReport>,
    at: i64,
    runtime: &evertrace_capture::RuntimeSnapshot,
) -> Result<JournalCommand, SemanticServiceError> {
    if source::is_source(job) {
        return Box::pin(source::execute(
            writer, planner, snapshot, job, report, at, runtime,
        ))
        .await;
    }
    let input = current(snapshot, job)?;
    if !allowed_input(writer, snapshot, job, &input, report).await? {
        return Err(SemanticServiceError::BaseConflict);
    }
    let mut payloads = Vec::new();
    let mut reason = JobTerminalReason::Completed;
    if needs_model(&input) && job.model_id.is_some() {
        let ProposalPayload::Procedure(payload) = &input.proposal.payload else {
            unreachable!()
        };
        let draft = payload.draft();
        let json = serde_json::to_string(
            &serde_json::json!({"content": content(draft), "evidence": input.evidence}),
        )
        .map_err(|_| SemanticServiceError::InvalidInput)?;
        if json.len() as u64 > job.budget.max_bytes.unwrap_or(0)
            || (json.len() as u64).saturating_add(2048) > job.budget.max_input_tokens.unwrap_or(0)
        {
            reason = JobTerminalReason::BudgetExhausted;
        } else if let Some(provider) = &planner.provider {
            let response = provider
                .review_procedure(json, job.budget.max_output_tokens.unwrap_or(0), &|| async {
                    let snapshot = writer
                        .project()
                        .await
                        .map_err(|_| crate::provider::ProviderError::Transport)?;
                    if allowed(writer, &snapshot, job, report)
                        .await
                        .unwrap_or(false)
                    {
                        Ok(())
                    } else {
                        Err(crate::provider::ProviderError::Disabled)
                    }
                })
                .await;
            match response {
                Ok((Some(value), input_tokens, output_tokens))
                    if input_tokens <= job.budget.max_input_tokens.unwrap_or(0)
                        && output_tokens <= job.budget.max_output_tokens.unwrap_or(0) =>
                {
                    let mut next_draft = draft.clone();
                    if value.applicability_expr != draft.applicability_expr
                        || value.avoid_expr != draft.avoid_expr
                        || value.completion_expr != draft.completion_expr
                        || value.stage_alignment != draft.stage_alignment
                        || value.actions != draft.actions
                        || value.when != draft.when
                        || value.done != draft.done
                        || value.procedure_kind != draft.kind
                        || !draft
                            .pitfalls
                            .iter()
                            .all(|item| value.pitfalls.contains(item))
                    {
                        reason = JobTerminalReason::Unsupported;
                    } else {
                        next_draft.title = value.title;
                        next_draft.summary = value.summary;
                        next_draft.pitfalls = value.pitfalls;
                        if next_draft != *draft {
                            next_draft.evidence_refs.extend(input.refs.clone());
                            next_draft.evidence_refs.sort();
                            next_draft.evidence_refs.dedup();
                            if let Some(procedure) = &input.existing {
                                let resolution = crate::semantic::RevisionProposalService.submit_with_deletion_admission(
                                    &SemanticCurrentView::from_snapshot(snapshot)?, &ObjectDeletionCandidateAdmissionView::from_snapshot(snapshot)?,
                                    crate::semantic::ProposalCommandContext { command_id: CommandId::new_v7(), occurred_at_us: at, effective_config_hash: job.config_hash, algorithm_revision: KIND.into() },
                                    crate::semantic::SubmitProposalRequest {
                                        target_kind: evertrace_domain::semantic::ProposalTargetKind::Procedure,
                                        target_id: Some(evertrace_domain::semantic::ProposalTargetId::Procedure(procedure.procedure_id)),
                                        base_revision_id: Some(procedure.revision_id), operation: evertrace_domain::semantic::ProposalOperation::Replace,
                                        payload: ProposalPayload::Procedure(Box::new(evertrace_domain::semantic::ProcedureProposalPayload::Replace { draft: next_draft })),
                                        evidence_refs: input.refs.clone(), source_cohort_refs: input.refs.clone(), eligibility: ProposalEligibility::ManualRequired,
                                        created_by: evertrace_domain::semantic::ProposalCreatedBy::Agent,
                                    },
                                )?;
                                if let crate::semantic::DeletionAwareProposalResolution::Proposal(
                                    crate::semantic::ProposalResolution::Revision {
                                        command, ..
                                    },
                                ) = resolution
                                {
                                    payloads.extend(
                                        command.events().iter().map(|event| event.payload.clone()),
                                    );
                                }
                            } else {
                                let mut next = input.proposal.clone();
                                next.proposal_revision_id = RevisionId::new_v7();
                                next.parent_proposal_revision_id =
                                    Some(input.proposal.proposal_revision_id);
                                next.created_at_us = at;
                                next.eligibility = ProposalEligibility::ManualRequired;
                                next.review_reason = Some(KIND.into());
                                next.evidence_refs.extend(input.refs.clone());
                                next.evidence_refs.sort();
                                next.evidence_refs.dedup();
                                next.source_cohort_refs = input.refs.clone();
                                next.source_cohort_hash = next
                                    .recompute_source_cohort_hash()
                                    .map_err(|_| SemanticServiceError::InvalidInput)?;
                                next.payload = ProposalPayload::Procedure(Box::new(match payload.as_ref() {
                                evertrace_domain::semantic::ProcedureProposalPayload::Create { .. } => evertrace_domain::semantic::ProcedureProposalPayload::Create { draft: next_draft },
                                evertrace_domain::semantic::ProcedureProposalPayload::Replace { .. } => evertrace_domain::semantic::ProcedureProposalPayload::Replace { draft: next_draft },
                            }));
                                next.fingerprint = next
                                    .recompute_fingerprint()
                                    .map_err(|_| SemanticServiceError::InvalidInput)?;
                                input
                                    .proposal
                                    .validate_procedure_review_successor(&next)
                                    .map_err(|_| SemanticServiceError::InvalidInput)?;
                                if let Some(inventory) = &planner.inventory {
                                    let ProposalPayload::Procedure(payload) = &next.payload else {
                                        unreachable!()
                                    };
                                    let coverage = inventory
                                        .procedure_coverage(snapshot, payload.draft(), &input.refs)
                                        .await?;
                                    if !coverage.suppresses_duplicate_create() {
                                        payloads.push(JournalPayload::RevisionProposalRecorded(
                                            Box::new(next),
                                        ));
                                    }
                                } else {
                                    payloads.push(JournalPayload::RevisionProposalRecorded(
                                        Box::new(next),
                                    ));
                                }
                            }
                        }
                    }
                }
                Ok((None, input, output))
                    if input <= job.budget.max_input_tokens.unwrap_or(0)
                        && output <= job.budget.max_output_tokens.unwrap_or(0) => {}
                Ok(_) => reason = JobTerminalReason::BudgetExhausted,
                Err(crate::provider::ProviderError::Schema) => {
                    reason = JobTerminalReason::Unsupported
                }
                Err(_) => reason = JobTerminalReason::SourceUnavailable,
            }
        } else {
            reason = JobTerminalReason::SourceUnavailable;
        }
    }
    finish(job, payloads, reason, at)
}

fn finish(
    job: &DurableJob,
    mut payloads: Vec<JournalPayload>,
    reason: JobTerminalReason,
    at: i64,
) -> Result<JournalCommand, SemanticServiceError> {
    let result_ref = payloads
        .iter()
        .find_map(|payload| match payload {
            JournalPayload::RevisionProposalRecorded(value) => {
                Some(value.proposal_revision_id.to_string())
            }
            _ => None,
        })
        .unwrap_or_else(|| job.target_revision.clone());
    let mut terminal = job.clone();
    terminal.state = if reason == JobTerminalReason::Completed {
        JobStatus::Succeeded
    } else {
        JobStatus::Failed
    };
    terminal.lease_until_us = None;
    terminal.terminal = Some(Box::new(JobTerminalAudit {
        outcome: if terminal.state == JobStatus::Succeeded {
            JobTerminalOutcome::Succeeded
        } else {
            JobTerminalOutcome::Failed
        },
        reason,
        result_ref: Some(result_ref),
    }));
    payloads.push(JournalPayload::JobState(terminal));
    Ok(JournalCommand::new(
        CommandId::new_v7(),
        payloads
            .into_iter()
            .map(|payload| JournalEventDraft::runtime(at, job.config_hash, KIND, payload))
            .collect(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_round_indexes_metadata_once_and_bounds_related_surface_selection() {
        let mut rows = Vec::new();
        for seq in 1..=33 {
            let mut row = evertrace_store::ObjectRow::checkpoint(seq, 1);
            row.row_kind = evertrace_store::objects::ObjectRowKind::Data;
            row.object_kind = Some("evidence_surface".into());
            row.current_revision_id = Some(
                evertrace_domain::ids::SourceObservationId::from_digest([seq as u8; 32])
                    .to_string(),
            );
            row.repository_id = Some(if seq == 33 { "unrelated" } else { "selected" }.into());
            row.worktree_id = Some("worktree".into());
            row.task_id = Some("task".into());
            row.payload_json = Some("not decoded during candidate filtering".into());
            rows.push(row);
        }
        let snapshot = ProjectionSnapshot { frontier: 33, rows };
        let view = SemanticCurrentView::from_snapshot(&snapshot).unwrap();
        let usage = crate::procedure::ProcedureUsageCurrentView::from_promotion_snapshot(&snapshot)
            .unwrap();
        let inputs = ReviewInputs::new(&snapshot, &view, &usage).unwrap();
        let selected = &inputs.tasks[&("selected".into(), Some("worktree".into()), "task".into())];
        assert_eq!(selected.len(), 16);
        assert_eq!(selected.first().unwrap().source_event_seq, 32);
        assert_eq!(selected.last().unwrap().source_event_seq, 17);
        assert_eq!(inputs.observations.len(), 33);
    }
}
