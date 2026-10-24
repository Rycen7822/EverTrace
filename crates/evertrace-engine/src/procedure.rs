use evertrace_domain::{
    config::{GlobalPromotionConfig, PromotionLevel},
    ids::ProcedureId,
    procedure::{
        PROCEDURE_ELIGIBILITY_VALIDATOR_REVISION, ProcedureActions, ProcedureAutoFullAudit,
        ProcedureDone, ProcedureEligibilityEvidence, ProcedurePublicationState, ProcedureRevision,
        ProcedureScope, ProcedureStateEvent, ProcedureStateReason,
    },
    query::{SearchContext, SearchIntent},
    revision::RevisionId,
    semantic::{
        AcceptedProposalTarget, AtomScope, ConstraintState, ConstraintTruth, GlobalSupportState,
        ProcedureProposalPayload, ProposalAcceptanceAuthority, ProposalEligibility,
        ProposalPayload, ProposalTargetId, ProposalTargetKind, RevisionProposal,
    },
};
use evertrace_store::{
    JournalCommand, JournalEventDraft, JournalPayload, ProjectionSnapshot, SemanticCurrentView,
};

use crate::semantic::{
    AtomAcceptanceContext, ProposalAcceptanceAudit, ProposalCommandContext, SemanticServiceError,
    accepted_edited_proposal_successor, accepted_proposal_successor,
    accepted_proposal_successor_with_audit, global_support_payloads, validate_current_support_refs,
};

const S24_ALGORITHM: &str = "s24-procedure-v1";
const MAX_CANDIDATES: usize = 64;

#[derive(Clone, Debug)]
pub enum ProcedureAcceptanceContext {
    Manual(AtomAcceptanceContext),
    AutoFull {
        evidence: ProcedureEligibilityEvidence,
        coverage: Option<Box<VerifiedProcedureCoverage>>,
    },
}

/// Only the current, protected inventory reader can construct this value. The
/// display summary is deliberately not accepted as an authorization token.
#[derive(Clone, Debug)]
pub struct VerifiedProcedureCoverage {
    summary: evertrace_domain::inventory::CapabilityCoverageSummary,
    frontier: u64,
    draft: evertrace_domain::procedure::ProcedureDraft,
    source_refs: Vec<String>,
    incremental_target: Option<(ProcedureId, RevisionId)>,
}

impl VerifiedProcedureCoverage {
    pub fn summary(&self) -> &evertrace_domain::inventory::CapabilityCoverageSummary {
        &self.summary
    }

    pub(crate) fn suppresses_duplicate_create(&self) -> bool {
        self.summary.equivalent_assets.iter().any(|value| {
            value.level == evertrace_domain::inventory::CapabilityEvidenceLevel::OutcomeSupported
        })
    }

    pub(crate) fn apply_incremental_boundary(
        &self,
        candidate: &mut evertrace_domain::semantic::SemanticCandidate,
    ) {
        let Some((id, revision)) = self.incremental_target else {
            return;
        };
        let evertrace_domain::semantic::SemanticCandidate::ProcedureProposal {
            target_id,
            base_revision_id,
            payload,
        } = candidate
        else {
            return;
        };
        if target_id.is_none()
            && base_revision_id.is_none()
            && matches!(payload.as_ref(), ProcedureProposalPayload::Create { draft } if draft == &self.draft)
        {
            *target_id = Some(id);
            *base_revision_id = Some(revision);
            **payload = ProcedureProposalPayload::Replace {
                draft: self.draft.clone(),
            };
        }
    }

    fn permits_auto_full(&self, view: &SemanticCurrentView, proposal: &RevisionProposal) -> bool {
        let ProposalPayload::Procedure(payload) = &proposal.payload else {
            return false;
        };
        self.frontier == view.frontier
            && &self.draft == payload.draft()
            && self.source_refs == proposal.source_cohort_refs
            && !self.summary.inventory_refs.is_empty()
            && self.summary.omissions.is_empty()
            && self.summary.equivalent_assets.is_empty()
            && self.incremental_target.is_none()
            && !self.summary.likely_redundant
    }
}

/// The proposal's real source cohort selects its session. A recent inventory
/// from another session or cwd is never a fallback, nor is an old installation
/// backfilled into a session that did not observe it.
pub async fn resolve_procedure_coverage(
    writer: &crate::WriterHandle,
    bindings: &crate::McpBindingAuthority,
    runtime: &evertrace_capture::RuntimeSnapshot,
    snapshot: &ProjectionSnapshot,
    draft: &evertrace_domain::procedure::ProcedureDraft,
    source_refs: &[String],
) -> Result<VerifiedProcedureCoverage, SemanticServiceError> {
    use evertrace_domain::inventory::{
        CapabilityCoverageMatch, CapabilityCoverageOmission as Omission, CapabilityCoverageSummary,
        CapabilityEvidenceLevel,
    };
    use std::collections::BTreeSet;
    // Existing stage/usage facts do not identify natural execution of the
    // same actions across independent tasks or account for exploration cost.
    // False must not stand in for an observed non-redundancy determination.
    let mut coverage = CapabilityCoverageSummary {
        omissions: vec![Omission::NaturalExecutionUnobserved],
        ..CapabilityCoverageSummary::default()
    };
    let refs = source_refs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut sessions = BTreeSet::new();
    let mut source_boundaries = std::collections::BTreeMap::new();
    let mut complete_capture = !refs.is_empty();
    let mut receipts = BTreeSet::new();
    let mut resolved_refs = BTreeSet::new();
    for row in snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("source_observation"))
    {
        if row.object_id.as_deref().is_none_or(|id| !refs.contains(id)) {
            continue;
        }
        let JournalPayload::SourceObservationRecorded(value) = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(SemanticServiceError::InvalidInput)?,
        )
        .map_err(|_| SemanticServiceError::InvalidInput)?
        else {
            return Err(SemanticServiceError::InvalidInput);
        };
        receipts.insert(value.source_receipt_ref.to_string());
        resolved_refs.insert(value.source_observation_id.to_string());
    }
    for row in snapshot
        .data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("source_receipt"))
    {
        if row
            .object_id
            .as_deref()
            .is_none_or(|id| !refs.contains(id) && !receipts.contains(id))
        {
            continue;
        }
        let JournalPayload::SourceReceiptRecorded(value) = serde_json::from_str(
            row.payload_json
                .as_deref()
                .ok_or(SemanticServiceError::InvalidInput)?,
        )
        .map_err(|_| SemanticServiceError::InvalidInput)?
        else {
            return Err(SemanticServiceError::InvalidInput);
        };
        let boundary = (
            row.source_event_seq,
            value.event_time_us.min(value.recorded_at_us),
        );
        if let (Some(repository), Some(worktree)) =
            (value.repository_instance_id, value.worktree_instance_id)
        {
            source_boundaries
                .entry((
                    format!("session:{}", value.source_session_ref),
                    repository,
                    worktree,
                ))
                .and_modify(|old: &mut (u64, i64)| {
                    *old = (old.0.min(boundary.0), old.1.min(boundary.1))
                })
                .or_insert(boundary);
        }
        sessions.insert(format!("session:{}", value.source_session_ref));
        resolved_refs.insert(value.source_receipt_id.to_string());
        receipts.remove(&value.source_receipt_id.to_string());
        complete_capture &= value.capture_completeness
            == evertrace_domain::evidence::CaptureCompleteness::Complete
            && value.close_watermark.is_some();
    }
    if sessions.is_empty() {
        coverage.omissions.push(Omission::SessionUnobserved);
    }
    if sessions.is_empty()
        || !complete_capture
        || !receipts.is_empty()
        || refs
            .iter()
            .any(|reference| !resolved_refs.contains(*reference))
    {
        coverage
            .omissions
            .push(Omission::HistoricalCaptureUnobserved);
    }
    let active = bindings.active_inventory_contexts();
    let mut candidates = std::collections::BTreeMap::new();
    let mut historical = std::collections::BTreeMap::new();
    let mut incremental_targets = Vec::new();
    let inventory_deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut inventory_bytes = 0usize;
    let mut inventory_items = 0usize;
    #[derive(serde::Deserialize)]
    struct InventoryContextRow {
        value: InventoryContextValue,
    }
    #[derive(serde::Deserialize)]
    struct InventoryContextValue {
        context: evertrace_domain::inventory::InventoryContext,
    }
    if !sessions.is_empty() {
        for row in snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("capability_inventory"))
        {
            if std::time::Instant::now() >= inventory_deadline {
                coverage.omissions.push(Omission::CandidateLimit);
                break;
            }
            if row.repository_id.as_ref().is_some_and(|id| {
                !source_boundaries
                    .keys()
                    .any(|(_, repository, _)| repository.to_string() == *id)
            }) {
                continue;
            }
            let context: InventoryContextRow = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(SemanticServiceError::InvalidInput)?,
            )
            .map_err(|_| SemanticServiceError::InvalidInput)?;
            if !source_boundaries.keys().any(|(_, repository, worktree)| {
                *repository == context.value.context.repository_id
                    && *worktree == context.value.context.worktree_id
            }) {
                continue;
            }
            inventory_items += 1;
            inventory_bytes += row.payload_json.as_ref().map_or(0, String::len);
            if inventory_items > 256 || inventory_bytes > 2 * 1024 * 1024 {
                coverage.omissions.push(Omission::CandidateLimit);
                break;
            }
            let JournalPayload::CapabilityInventoryRecorded(value) = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(SemanticServiceError::InvalidInput)?,
            )
            .map_err(|_| SemanticServiceError::InvalidInput)?
            else {
                return Err(SemanticServiceError::InvalidInput);
            };
            let scope = ProcedureScope::Worktree {
                repository_id: value.context.repository_id,
                worktree_id: value.context.worktree_id,
            };
            if draft.scope.contains(&scope)
                && source_boundaries.keys().any(|(_, repository, worktree)| {
                    *repository == value.context.repository_id
                        && *worktree == value.context.worktree_id
                })
                && active.iter().any(|(host, report)| {
                    host.cwd.to_str() == Some(value.context.cwd.as_str())
                        && host.home.to_str() == Some(value.context.host_home.as_str())
                        && host.config_root.to_str()
                            == Some(value.context.host_config_root.as_str())
                        && host.profile == value.context.host_profile
                        && report.manifest().adapter_manifest_id
                            == value.context.adapter_manifest_id
                })
            {
                for ((session, repository, worktree), &(seq, time)) in &source_boundaries {
                    if !historical_inventory_at_source(
                        &value,
                        row.source_event_seq,
                        (session, *repository, *worktree),
                        (seq, time),
                    ) {
                        continue;
                    }
                    let entry = historical
                        .entry((session.clone(), value.context.clone()))
                        .or_insert((row.source_event_seq, value.clone()));
                    if row.source_event_seq > entry.0 {
                        *entry = (row.source_event_seq, value.clone());
                    }
                }
                let entry = candidates
                    .entry(value.context.clone())
                    .or_insert((row.source_event_seq, value.clone()));
                if row.source_event_seq > entry.0 {
                    *entry = (row.source_event_seq, value);
                }
                if candidates.len() > 4 {
                    coverage.omissions.push(Omission::CandidateLimit);
                    break;
                }
            }
        }
    }
    if candidates.is_empty() {
        coverage.omissions.push(Omission::InventoryMissing);
    }
    let contexts = source_boundaries
        .keys()
        .map(|(_, repository, worktree)| (*repository, *worktree))
        .collect::<BTreeSet<_>>();
    for (session, repository, worktree) in source_boundaries.keys() {
        let related = candidates
            .keys()
            .filter(|context| {
                context.repository_id == *repository && context.worktree_id == *worktree
            })
            .collect::<Vec<_>>();
        if related.is_empty()
            || related
                .iter()
                .any(|context| !historical.contains_key(&(session.clone(), (*context).clone())))
        {
            coverage
                .omissions
                .push(Omission::HistoricalCaptureUnobserved);
        }
    }
    for ((session, _), (_, fact)) in &historical {
        if coverage.inventory_refs.len() >= 8 || std::time::Instant::now() >= inventory_deadline {
            coverage.omissions.push(Omission::CandidateLimit);
            break;
        }
        match crate::repository::read_procedure_historical_inventory(
            writer,
            bindings,
            runtime,
            snapshot,
            fact,
            (
                session,
                source_boundaries[&(
                    session.clone(),
                    fact.context.repository_id,
                    fact.context.worktree_id,
                )],
            ),
            inventory_deadline,
        )
        .await
        .map_err(|_| SemanticServiceError::InvalidInput)?
        {
            Some(inventory) => {
                if !coverage.inventory_refs.contains(&fact.job_id) {
                    coverage.inventory_refs.push(fact.job_id);
                }
                if inventory.sources.iter().any(|source| !source.observed) {
                    coverage.omissions.push(Omission::SourceUnobserved);
                }
            }
            None => coverage
                .omissions
                .push(Omission::HistoricalCaptureUnobserved),
        }
    }
    let mut present = BTreeSet::new();
    for (_, (_, fact)) in candidates.into_iter().take(4) {
        if std::time::Instant::now() >= inventory_deadline
            || coverage.inventory_refs.len() >= 8 && !coverage.inventory_refs.contains(&fact.job_id)
        {
            coverage.omissions.push(Omission::CandidateLimit);
            break;
        }
        // Current presence is useful to the reviewer, but an inventory that
        // completed after the source cannot prove that source's historical
        // capability coverage, including when the same session resumes.
        let Some(inventory) = crate::repository::read_inventory_before(
            writer,
            bindings,
            runtime,
            &fact,
            inventory_deadline,
        )
        .await
        .map_err(|_| SemanticServiceError::InvalidInput)?
        else {
            coverage.omissions.push(Omission::InventoryStale);
            continue;
        };
        if !coverage.inventory_refs.contains(&fact.job_id) {
            if coverage.inventory_refs.len() == 8 {
                coverage.omissions.push(Omission::CandidateLimit);
                continue;
            }
            coverage.inventory_refs.push(fact.job_id);
        }
        coverage.unobserved_sources += inventory
            .sources
            .iter()
            .filter(|source| !source.observed)
            .count() as u32;
        if coverage.unobserved_sources != 0 {
            coverage.omissions.push(Omission::SourceUnobserved);
        }
        for signature in &inventory.signatures {
            if !present.insert((
                (signature.scope.clone(), signature.source_path.clone()),
                signature.content_cas_ref.clone(),
            )) {
                continue;
            }
            coverage.present_assets += 1;
            let (
                Some(triggers),
                Some(preconditions),
                Some(actions),
                Some(outputs),
                Some(validation),
                Some(boundaries),
            ) = (
                &signature.triggers,
                &signature.preconditions,
                &signature.key_actions,
                &signature.outputs,
                &signature.validation,
                &signature.failure_boundaries,
            )
            else {
                coverage.unknown_contracts += 1;
                continue;
            };
            if triggers == &draft.when.goals
                && preconditions == &draft.when.requires
                && actions == &draft.actions.stages
                && outputs == &draft.done.success
                && validation == &draft.done.verify
                && boundaries == &draft.pitfalls
            {
                coverage.equivalent_assets.push(CapabilityCoverageMatch {
                    revision_ref: signature.content_cas_ref.clone(),
                    level: CapabilityEvidenceLevel::Present,
                });
            }
        }
        if coverage.unknown_contracts != 0 {
            coverage.omissions.push(Omission::ContractUnknown);
        }
    }
    // Published procedures have their own current/scope evidence and remain
    // comparable even when a file inventory is missing or revoked.
    let usage = usage::ProcedureUsageCurrentView::from_coverage_snapshot(
        snapshot,
        &contexts,
        inventory_deadline,
    )?;
    if usage.is_none() {
        coverage.omissions.push(Omission::CandidateLimit);
    }
    if let Some(usage) = usage {
        for (index, (procedure, level)) in usage
            .coverage_procedures(draft.scope, &contexts)
            .enumerate()
        {
            if index == MAX_CANDIDATES {
                coverage.omissions.push(Omission::CandidateLimit);
                break;
            }
            coverage.present_assets += 1;
            if equivalent_procedure_contract(&procedure.draft, draft) {
                coverage.equivalent_assets.push(CapabilityCoverageMatch {
                    revision_ref: procedure.revision_id.to_string(),
                    level,
                });
            } else if level == CapabilityEvidenceLevel::OutcomeSupported
                && procedure.draft.scope == draft.scope
                && extends_procedure_boundaries(&procedure.draft, draft)
            {
                incremental_targets.push((procedure.procedure_id, procedure.revision_id));
            }
        }
    }
    coverage.inventory_refs.sort();
    coverage.inventory_refs.dedup();
    coverage
        .equivalent_assets
        .sort_by(|left, right| left.revision_ref.cmp(&right.revision_ref));
    coverage
        .equivalent_assets
        .dedup_by(|left, right| left.revision_ref == right.revision_ref);
    if coverage.equivalent_assets.len() > MAX_CANDIDATES {
        coverage.equivalent_assets.truncate(MAX_CANDIDATES);
        coverage.omissions.push(Omission::CandidateLimit);
    }
    coverage.omissions.sort();
    coverage.omissions.dedup();
    let incremental_target = (incremental_targets.len() == 1).then(|| incremental_targets[0]);
    coverage.incremental_base_revision = incremental_target.map(|(_, revision)| revision);
    if !coverage.validate() {
        return Err(SemanticServiceError::InvalidInput);
    }
    Ok(VerifiedProcedureCoverage {
        summary: coverage,
        frontier: snapshot.frontier,
        draft: draft.clone(),
        source_refs: source_refs.to_vec(),
        incremental_target,
    })
}

pub(crate) fn historical_inventory_at_source(
    fact: &evertrace_domain::inventory::CapabilityInventoryRecorded,
    sequence: u64,
    source: (
        &str,
        evertrace_domain::ids::RepositoryId,
        evertrace_domain::ids::WorktreeId,
    ),
    boundary: (u64, i64),
) -> bool {
    sequence <= boundary.0
        && fact.recorded_at_us <= boundary.1
        && fact
            .evidence_refs
            .iter()
            .any(|reference| reference == source.0)
        && fact.context.repository_id == source.1
        && fact.context.worktree_id == source.2
}

fn extends_procedure_boundaries(
    left: &evertrace_domain::procedure::ProcedureDraft,
    right: &evertrace_domain::procedure::ProcedureDraft,
) -> bool {
    // Only an authored, strict extension of the same proven contract. Changing
    // actions, conditions or verification is not a deterministic equivalence.
    if right.pitfalls.len() <= left.pitfalls.len()
        || !left
            .pitfalls
            .iter()
            .all(|boundary| right.pitfalls.contains(boundary))
    {
        return false;
    }
    let mut comparable = right.clone();
    comparable.pitfalls.clone_from(&left.pitfalls);
    equivalent_procedure_contract(left, &comparable)
}

fn equivalent_procedure_contract(
    left: &evertrace_domain::procedure::ProcedureDraft,
    right: &evertrace_domain::procedure::ProcedureDraft,
) -> bool {
    left.scope.contains(&right.scope)
        && left.kind == right.kind
        && left.when == right.when
        && left.condition_ir_version == right.condition_ir_version
        && left.applicability_expr == right.applicability_expr
        && left.avoid_expr == right.avoid_expr
        && left.completion_expr == right.completion_expr
        && left.stage_alignment == right.stage_alignment
        && left.actions == right.actions
        && left.done == right.done
        && left.pitfalls == right.pitfalls
}

pub(crate) struct EditedProcedureAcceptance<'a> {
    pub(crate) source: AtomAcceptanceContext,
    pub(crate) original: &'a RevisionProposal,
}

enum ProcedureAcceptanceInput<'a> {
    Standard(ProcedureAcceptanceContext),
    Edited(EditedProcedureAcceptance<'a>),
}

#[derive(Debug)]
pub enum ProcedureAcceptanceResolution {
    NoDelta,
    AcceptedExisting {
        proposal: Box<evertrace_domain::semantic::RevisionProposal>,
        command: JournalCommand,
    },
    Command {
        proposal: Box<evertrace_domain::semantic::RevisionProposal>,
        procedure: Box<ProcedureRevision>,
        state: Box<ProcedureStateEvent>,
        command: JournalCommand,
    },
}

#[allow(clippy::too_many_arguments)]
pub fn accept_procedure(
    view: &SemanticCurrentView,
    context: ProposalCommandContext,
    proposal_id: evertrace_domain::ids::RevisionProposalId,
    acceptance_context: ProcedureAcceptanceContext,
    current: Option<&ProcedureRevision>,
    current_publication: Option<ProcedurePublicationState>,
    global_config: &GlobalPromotionConfig,
) -> Result<ProcedureAcceptanceResolution, SemanticServiceError> {
    accept_procedure_inner(
        view,
        context,
        proposal_id,
        current,
        current_publication,
        global_config,
        ProcedureAcceptanceInput::Standard(acceptance_context),
    )
}

pub(crate) fn accept_procedure_edited(
    view: &SemanticCurrentView,
    context: ProposalCommandContext,
    proposal_id: evertrace_domain::ids::RevisionProposalId,
    acceptance: EditedProcedureAcceptance<'_>,
    current: Option<&ProcedureRevision>,
    current_publication: Option<ProcedurePublicationState>,
    global_config: &GlobalPromotionConfig,
) -> Result<ProcedureAcceptanceResolution, SemanticServiceError> {
    accept_procedure_inner(
        view,
        context,
        proposal_id,
        current,
        current_publication,
        global_config,
        ProcedureAcceptanceInput::Edited(acceptance),
    )
}

fn accept_procedure_inner(
    view: &SemanticCurrentView,
    context: ProposalCommandContext,
    proposal_id: evertrace_domain::ids::RevisionProposalId,
    current: Option<&ProcedureRevision>,
    current_publication: Option<ProcedurePublicationState>,
    global_config: &GlobalPromotionConfig,
    acceptance: ProcedureAcceptanceInput<'_>,
) -> Result<ProcedureAcceptanceResolution, SemanticServiceError> {
    let (acceptance_context, edit_original) = match acceptance {
        ProcedureAcceptanceInput::Standard(context) => (context, None),
        ProcedureAcceptanceInput::Edited(edited) => (
            ProcedureAcceptanceContext::Manual(edited.source),
            Some(edited.original),
        ),
    };
    let proposal = view
        .proposals
        .get(&proposal_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    if edit_original.is_some_and(|original| original.validate_edit_candidate(proposal).is_err()) {
        return Err(SemanticServiceError::InvalidInput);
    }
    if proposal.target_kind != ProposalTargetKind::Procedure || !proposal.status.is_open() {
        return Err(SemanticServiceError::UnsupportedTarget);
    }
    let ProposalPayload::Procedure(payload) = &proposal.payload else {
        return Err(SemanticServiceError::UnsupportedTarget);
    };
    let draft = payload.draft();
    draft
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    if draft.evidence_refs.iter().any(|reference| {
        // Store validates both source sets. Synthesis proposals cite the
        // digest as evidence and retain its verified direct sources here.
        !proposal.evidence_refs.contains(reference)
            && !proposal.source_cohort_refs.contains(reference)
    }) {
        return Err(SemanticServiceError::InvalidInput);
    }
    let (procedure_id, generation, parent, old_state) = match payload.as_ref() {
        ProcedureProposalPayload::Create { .. } => {
            if current.is_some()
                || current_publication.is_some()
                || proposal.target_id.is_some()
                || proposal.base_revision_id.is_some()
            {
                return Err(SemanticServiceError::BaseConflict);
            }
            (ProcedureId::new_v7(), 1, None, None)
        }
        ProcedureProposalPayload::Replace { .. } => {
            let current = current.ok_or(SemanticServiceError::BaseConflict)?;
            let publication = current_publication.ok_or(SemanticServiceError::BaseConflict)?;
            if proposal.target_id != Some(ProposalTargetId::Procedure(current.procedure_id))
                || proposal.base_revision_id != Some(current.revision_id)
                || !current.draft.scope.contains(&draft.scope)
            {
                return Err(SemanticServiceError::BaseConflict);
            }
            if current.draft == *draft {
                if !matches!(
                    publication,
                    ProcedurePublicationState::ActiveProbationary
                        | ProcedurePublicationState::ActiveStable
                ) {
                    return Err(SemanticServiceError::BaseConflict);
                }
                let ProcedureAcceptanceContext::Manual(manual) = acceptance_context else {
                    return Ok(ProcedureAcceptanceResolution::NoDelta);
                };
                let ProposalAcceptanceAuthority::TuiAcceptance {
                    authorized_scope_ceiling,
                    ..
                } = manual.authority_basis()?
                else {
                    return Err(SemanticServiceError::InvalidInput);
                };
                if !authorized_scope_ceiling.contains(&scope_as_atom(draft.scope)) {
                    return Err(SemanticServiceError::InvalidInput);
                }
                let accepted_target = AcceptedProposalTarget::Procedure {
                    procedure_id: current.procedure_id,
                    procedure_revision_id: current.revision_id,
                    auto_full_audit: None,
                };
                let (accepted, payloads) = if let Some(original) = edit_original {
                    accepted_edited_proposal_successor(
                        original,
                        proposal,
                        &context,
                        &manual,
                        RevisionId::new_v7(),
                        accepted_target,
                    )?
                } else {
                    accepted_proposal_successor(
                        proposal,
                        &context,
                        &manual,
                        RevisionId::new_v7(),
                        accepted_target,
                    )?
                };
                let command = JournalCommand::new(
                    context.command_id,
                    payloads
                        .into_iter()
                        .map(|payload| {
                            JournalEventDraft::runtime(
                                context.occurred_at_us,
                                context.effective_config_hash,
                                S24_ALGORITHM,
                                payload,
                            )
                        })
                        .collect(),
                )?;
                return Ok(ProcedureAcceptanceResolution::AcceptedExisting {
                    proposal: Box::new(accepted),
                    command,
                });
            }
            (
                current.procedure_id,
                current.revision_generation.saturating_add(1),
                Some(current.revision_id),
                Some((current.revision_id, publication)),
            )
        }
    };
    let revision_id = RevisionId::new_v7();
    let procedure = ProcedureRevision {
        procedure_id,
        revision_id,
        parent_revision_id: parent,
        revision_generation: generation,
        draft: draft.clone(),
        source_watermark: view.frontier.saturating_add(1),
        created_at_us: context.occurred_at_us,
    };
    procedure
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    let (accepted, mut payloads) = match acceptance_context {
        ProcedureAcceptanceContext::Manual(manual) => {
            let evertrace_domain::semantic::ProposalAcceptanceAuthority::TuiAcceptance {
                authorized_scope_ceiling,
                ..
            } = manual.authority_basis()?
            else {
                return Err(SemanticServiceError::InvalidInput);
            };
            if !authorized_scope_ceiling.contains(&scope_as_atom(draft.scope)) {
                return Err(SemanticServiceError::InvalidInput);
            }
            let accepted_target = AcceptedProposalTarget::Procedure {
                procedure_id,
                procedure_revision_id: revision_id,
                auto_full_audit: None,
            };
            if let Some(original) = edit_original {
                accepted_edited_proposal_successor(
                    original,
                    proposal,
                    &context,
                    &manual,
                    RevisionId::new_v7(),
                    accepted_target,
                )?
            } else {
                accepted_proposal_successor(
                    proposal,
                    &context,
                    &manual,
                    RevisionId::new_v7(),
                    accepted_target,
                )?
            }
        }
        ProcedureAcceptanceContext::AutoFull {
            mut evidence,
            coverage,
        } => {
            let coverage = coverage
                .filter(|coverage| coverage.permits_auto_full(view, proposal))
                .ok_or(SemanticServiceError::InvalidInput)?;
            // Never trust the caller/LLM's redundancy flag. All other existing
            // objective verifier and independent-success gates remain intact.
            evidence.redundancy_check_passed = true;
            let global = matches!(draft.scope, ProcedureScope::Global);
            if proposal.eligibility != ProposalEligibility::AutoEligibleFull
                || global && global_config.procedure != PromotionLevel::FullAuto
                || !evidence
                    .auto_eligible_full(global, global_config.procedure == PromotionLevel::FullAuto)
            {
                return Err(SemanticServiceError::InvalidInput);
            }
            let observation = evidence
                .verifier_observation_ref
                .ok_or(SemanticServiceError::InvalidInput)?;
            accepted_proposal_successor_with_audit(
                proposal,
                &context,
                RevisionId::new_v7(),
                AcceptedProposalTarget::Procedure {
                    procedure_id,
                    procedure_revision_id: revision_id,
                    auto_full_audit: Some(Box::new(ProcedureAutoFullAudit {
                        validator_revision: PROCEDURE_ELIGIBILITY_VALIDATOR_REVISION.into(),
                        eligibility: evidence,
                        procedure_promotion_level: global_config.procedure,
                        eligible: true,
                        capability_inventory_refs: Some(coverage.summary.inventory_refs),
                    })),
                },
                ProposalAcceptanceAudit {
                    reviewer_identity: format!("objective_evidence:{observation}"),
                    acceptance_event_ref: observation.to_string(),
                    authority_basis: ProposalAcceptanceAuthority::ObjectiveEvidence {
                        user_source_observation_ref: observation,
                    },
                },
            )?
        }
    };
    let state = ProcedureStateEvent {
        state_event_id: RevisionId::new_v7(),
        procedure_revision_id: revision_id,
        from_state: None,
        to_state: ProcedurePublicationState::ActiveProbationary,
        reason: ProcedureStateReason::Accepted,
        resume_state: None,
        evidence_refs: proposal.evidence_refs.clone(),
        created_at_us: context.occurred_at_us,
    };
    payloads.extend([
        JournalPayload::ProcedureRevisionRecorded(Box::new(procedure.clone())),
        JournalPayload::ProcedureStateRecorded(Box::new(state.clone())),
    ]);
    if let Some((old_revision, old_publication)) = old_state {
        payloads.push(JournalPayload::ProcedureStateRecorded(Box::new(
            ProcedureStateEvent {
                state_event_id: RevisionId::new_v7(),
                procedure_revision_id: old_revision,
                from_state: Some(old_publication),
                to_state: ProcedurePublicationState::Superseded,
                reason: ProcedureStateReason::Replaced,
                resume_state: None,
                evidence_refs: proposal.evidence_refs.clone(),
                created_at_us: context.occurred_at_us,
            },
        )));
    }
    if !draft.support_revision_refs.is_empty() {
        validate_current_support_refs(view, &draft.support_revision_refs, revision_id)?;
    }
    if matches!(draft.scope, ProcedureScope::Global) {
        payloads.extend(global_support_payloads(
            revision_id.to_string(),
            draft.support_revision_refs.clone(),
            &accepted,
            serde_json::to_string(&draft.applicability_expr)
                .map_err(|_| SemanticServiceError::InvalidInput)?,
            evertrace_domain::semantic::SupportThresholdSnapshot {
                minimum_surviving_support: 1,
                require_authorization: true,
            },
            context.occurred_at_us,
        )?);
    }
    let command = JournalCommand::new(
        context.command_id,
        payloads
            .into_iter()
            .map(|payload| {
                JournalEventDraft::runtime(
                    context.occurred_at_us,
                    context.effective_config_hash,
                    S24_ALGORITHM,
                    payload,
                )
            })
            .collect(),
    )?;
    Ok(ProcedureAcceptanceResolution::Command {
        proposal: Box::new(accepted),
        procedure: Box::new(procedure),
        state: Box::new(state),
        command,
    })
}

pub fn publication_event(
    revision: &ProcedureRevision,
    from: ProcedurePublicationState,
    to: ProcedurePublicationState,
    reason: ProcedureStateReason,
    resume_state: Option<ProcedurePublicationState>,
    evidence_refs: Vec<String>,
    created_at_us: i64,
) -> Result<ProcedureStateEvent, SemanticServiceError> {
    let event = ProcedureStateEvent {
        state_event_id: RevisionId::new_v7(),
        procedure_revision_id: revision.revision_id,
        from_state: Some(from),
        to_state: to,
        reason,
        resume_state,
        evidence_refs,
        created_at_us,
    };
    event
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    Ok(event)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProcedurePhase {
    BeforeEntry,
    AtEntry,
    InProgress,
    RecoverableDeviation,
    AlreadyCompleted,
    Incompatible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcedureGuidanceMode {
    Normal,
    GuardrailOnly,
}

#[derive(Clone, Debug)]
pub struct ProcedureCandidate {
    pub revision: ProcedureRevision,
    pub publication: ProcedurePublicationState,
    pub global_support: Option<GlobalSupportState>,
    pub phase: Option<ProcedurePhase>,
    pub lexical_rank: u32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProcedureDecision {
    Reject,
    Defer,
    Apply,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedProcedure {
    pub procedure_id: ProcedureId,
    pub revision_id: RevisionId,
    pub decision: ProcedureDecision,
    pub publication: ProcedurePublicationState,
    pub mode: ProcedureGuidanceMode,
    pub reason: &'static str,
    pub phase: Option<ProcedurePhase>,
    pub lexical_rank: u32,
    pub actions: Option<ProcedureActions>,
    pub avoid: Vec<String>,
    pub done: Option<ProcedureDone>,
    pub excludes: Vec<String>,
    pub pitfalls: Vec<String>,
    route_proof: ProcedureRouteProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcedureRouteProof {
    procedure_id: ProcedureId,
    revision_id: RevisionId,
    decision: ProcedureDecision,
    publication: ProcedurePublicationState,
    task_id: Option<evertrace_domain::ids::TaskId>,
    repository_id: Option<evertrace_domain::ids::RepositoryId>,
    worktree_id: Option<evertrace_domain::ids::WorktreeId>,
    phase: Option<ProcedurePhase>,
    failure_signature: Option<String>,
    eligibility: ConstraintTruth,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcedureRouteResult {
    pub status: &'static str,
    pub items: Vec<RoutedProcedure>,
}

pub struct ProcedureRouter;

impl ProcedureRouter {
    #[allow(clippy::too_many_arguments)]
    pub fn route(
        context: &SearchContext,
        candidates: Vec<ProcedureCandidate>,
        current: &ConstraintState,
        previous: Option<&ConstraintState>,
        scenario_fresh: bool,
        unresolved_competing: bool,
        sibling_exploration: bool,
        explicit_reuse: bool,
    ) -> ProcedureRouteResult {
        if context.intent == SearchIntent::HistoryLookup {
            return ProcedureRouteResult {
                status: "history_lookup_bypass",
                items: Vec::new(),
            };
        }
        if candidates.len() > MAX_CANDIDATES || context.validate().is_err() {
            return empty();
        }
        let mode = if !explicit_reuse && (unresolved_competing || sibling_exploration) {
            ProcedureGuidanceMode::GuardrailOnly
        } else {
            ProcedureGuidanceMode::Normal
        };
        let routed = candidates
            .into_iter()
            .filter_map(|candidate| {
                evaluate_candidate(context, candidate, current, previous, scenario_fresh, mode)
            })
            .collect::<Vec<_>>();
        select_route_result(routed)
    }
}

fn select_route_result(mut routed: Vec<RoutedProcedure>) -> ProcedureRouteResult {
    routed.sort_by_key(route_rank);
    let apply = routed
        .iter()
        .position(|item| item.decision == ProcedureDecision::Apply)
        .map(|index| routed.remove(index));
    let apply_probationary = apply
        .as_ref()
        .is_some_and(|item| item.publication == ProcedurePublicationState::ActiveProbationary);
    let defer = routed.into_iter().find(|item| {
        item.decision == ProcedureDecision::Defer
            && !(apply_probationary
                && item.publication == ProcedurePublicationState::ActiveProbationary)
    });
    let mut items = Vec::new();
    if let Some(apply) = apply {
        items.push(apply);
    }
    if let Some(defer) = defer {
        items.push(defer);
    }
    if items.is_empty() {
        empty()
    } else {
        ProcedureRouteResult {
            status: "ok",
            items,
        }
    }
}

fn evaluate_candidate(
    context: &SearchContext,
    candidate: ProcedureCandidate,
    current: &ConstraintState,
    previous: Option<&ConstraintState>,
    scenario_fresh: bool,
    mode: ProcedureGuidanceMode,
) -> Option<RoutedProcedure> {
    if !scope_matches(candidate.revision.draft.scope, context)
        || !matches!(
            candidate.publication,
            ProcedurePublicationState::ActiveProbationary | ProcedurePublicationState::ActiveStable
        )
        || matches!(candidate.revision.draft.scope, ProcedureScope::Global)
            && candidate.global_support != Some(GlobalSupportState::Valid)
        || matches!(
            candidate.phase,
            Some(ProcedurePhase::AlreadyCompleted | ProcedurePhase::Incompatible)
        )
    {
        return None;
    }
    let applicability = candidate
        .revision
        .draft
        .applicability_expr
        .evaluate(current, previous);
    let avoid = candidate
        .revision
        .draft
        .avoid_expr
        .evaluate(current, previous);
    let completion = candidate
        .revision
        .draft
        .completion_expr
        .evaluate(current, previous);
    if applicability == ConstraintTruth::False
        || avoid == ConstraintTruth::True
        || completion == ConstraintTruth::True
    {
        return None;
    }
    let recoverable = candidate.phase != Some(ProcedurePhase::RecoverableDeviation)
        || !candidate.revision.draft.actions.branches.is_empty()
        || !candidate.revision.draft.done.abort.is_empty();
    let (decision, reason) = if !scenario_fresh {
        (ProcedureDecision::Defer, "insufficient_context")
    } else if candidate.phase.is_none()
        || applicability == ConstraintTruth::Unknown
        || avoid == ConstraintTruth::Unknown
        || completion == ConstraintTruth::Unknown
        || !recoverable
    {
        (ProcedureDecision::Defer, "unknown_condition")
    } else {
        (ProcedureDecision::Apply, "applicable")
    };
    let guardrail = mode == ProcedureGuidanceMode::GuardrailOnly;
    Some(RoutedProcedure {
        procedure_id: candidate.revision.procedure_id,
        revision_id: candidate.revision.revision_id,
        decision,
        publication: candidate.publication,
        mode,
        reason,
        phase: candidate.phase,
        lexical_rank: candidate.lexical_rank,
        actions: (!guardrail && decision == ProcedureDecision::Apply)
            .then(|| candidate.revision.draft.actions.clone()),
        avoid: candidate.revision.draft.actions.avoid.clone(),
        done: (guardrail || decision == ProcedureDecision::Apply).then(|| {
            if guardrail {
                ProcedureDone {
                    success: Vec::new(),
                    abort: candidate.revision.draft.done.abort.clone(),
                    verify: candidate.revision.draft.done.verify.clone(),
                }
            } else {
                candidate.revision.draft.done.clone()
            }
        }),
        excludes: candidate.revision.draft.when.excludes.clone(),
        pitfalls: candidate.revision.draft.pitfalls.clone(),
        route_proof: ProcedureRouteProof {
            procedure_id: candidate.revision.procedure_id,
            revision_id: candidate.revision.revision_id,
            decision,
            publication: candidate.publication,
            task_id: context.task_id,
            repository_id: context.repository_id,
            worktree_id: context.worktree_id,
            phase: candidate.phase,
            failure_signature: current.bindings.iter().find_map(|binding| {
                if binding.field == evertrace_domain::semantic::ConstraintField::FailureSignature
                    && let evertrace_domain::semantic::ConstraintValue::Text(value) = &binding.value
                {
                    Some(value.clone())
                } else {
                    None
                }
            }),
            eligibility: applicability,
        },
    })
}

fn route_rank(value: &RoutedProcedure) -> (u8, u8, Option<ProcedurePhase>, u32, ProcedureId) {
    (
        match value.decision {
            ProcedureDecision::Apply => 0,
            ProcedureDecision::Defer => 1,
            ProcedureDecision::Reject => 2,
        },
        if value.publication == ProcedurePublicationState::ActiveStable {
            0
        } else {
            1
        },
        value.phase,
        value.lexical_rank,
        value.procedure_id,
    )
}

fn scope_matches(scope: ProcedureScope, context: &SearchContext) -> bool {
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

fn scope_as_atom(scope: ProcedureScope) -> AtomScope {
    match scope {
        ProcedureScope::Worktree {
            repository_id,
            worktree_id,
        } => AtomScope::Worktree {
            repository_instance_id: repository_id,
            worktree_instance_id: worktree_id,
        },
        ProcedureScope::Repository { repository_id } => AtomScope::Repository {
            repository_instance_id: repository_id,
        },
        ProcedureScope::Global => AtomScope::Global,
    }
}

fn empty() -> ProcedureRouteResult {
    ProcedureRouteResult {
        status: "no_applicable_procedure",
        items: Vec::new(),
    }
}

pub(crate) mod alignment;
pub use alignment::StageTrace;
mod usage;
pub use usage::*;
mod effect;
pub use effect::*;
