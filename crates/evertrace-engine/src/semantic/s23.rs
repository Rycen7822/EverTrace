use std::collections::{BTreeMap, BTreeSet};

use evertrace_domain::{
    canonical::{CanonicalValue, sha256},
    config::{GlobalPromotionConfig, PromotionLevel},
    ids::{CommandId, CoreMembershipId, JobId},
    revision::RevisionId,
    semantic::{
        AcceptedProposalTarget, ActiveScenarioLineage, Atom, AtomAuthority, AtomKind,
        AtomLifecycleStatus, AtomScope, CoreMembership, CoreMembershipProposalPayload,
        CoreScopeIdentity, EpistemicStatus, GlobalSuccessorSupportContract, GlobalSupportState,
        GlobalSupportValidationEvent, ProposalCreatedBy, ProposalEligibility, ProposalOperation,
        ProposalPayload, ProposalTargetKind, RevisionProposal, Scenario, ScenarioScope,
        ScenarioStatus, ScenarioWorkstream, SupportThresholdSnapshot, UserAuthorizationMode,
    },
    work::{
        Attempt, AttemptAdoptionStatus, AttemptExecutionStatus, AttemptLifecycleStatus,
        AttemptVerification, EpisodeLifecycle, ExperimentRun, Task, TaskLifecycle, WorkArtifact,
        WorkEpisode, Workstream, WorkstreamStatus,
    },
};
use evertrace_store::{
    DirtyTarget, DirtyTargetKind, DurableJob, JobStatus, JournalCommand, JournalEventDraft,
    JournalPayload, ObjectRowKind, OutboxEntry, ProjectionSnapshot, SemanticCurrentView,
    StoreError,
};

use super::{
    AtomAcceptanceContext, ProposalCommandContext, ProposalResolution, RevisionProposalService,
    SemanticServiceError, SubmitProposalRequest,
    proposal::{
        ProposalAcceptanceAudit, accepted_proposal_successor,
        accepted_proposal_successor_with_audit,
    },
};

const S23_ALGORITHM: &str = "s23-scenario-core-v1";

pub(crate) fn global_atom_support_payloads(
    view: &SemanticCurrentView,
    atom: &Atom,
    proposal: &RevisionProposal,
    occurred_at_us: i64,
) -> Result<Vec<JournalPayload>, SemanticServiceError> {
    if !matches!(atom.scope, AtomScope::Global)
        || atom.authority != AtomAuthority::UserExplicit
        || atom
            .user_authorization_provenance
            .as_ref()
            .is_none_or(|value| {
                value.mode != UserAuthorizationMode::TuiAcceptance
                    || !matches!(value.authorized_scope_ceiling, AtomScope::Global)
            })
    {
        return Err(SemanticServiceError::InvalidInput);
    }
    let support_contract_ref = RevisionId::new_v7();
    let support_refs = atom.supports_revision_refs.clone();
    if support_refs.is_empty() || support_refs.contains(&atom.revision_id) {
        return Err(SemanticServiceError::InvalidInput);
    }
    for support_ref in &support_refs {
        let support = view
            .atom_revisions
            .get(support_ref)
            .ok_or(SemanticServiceError::InvalidInput)?;
        if support.lifecycle_status != AtomLifecycleStatus::Active
            || view
                .atoms
                .get(&support.atom_id)
                .is_none_or(|current| current.revision_id != *support_ref)
        {
            return Err(SemanticServiceError::InvalidInput);
        }
    }
    let contract = GlobalSuccessorSupportContract {
        support_contract_revision_id: support_contract_ref,
        successor_revision_or_membership_ref: atom.revision_id.to_string(),
        evidence_cohort_hash: digest_revisions("evertrace.support.cohort", &support_refs)?,
        applicability_contract_hash: sha256(
            "evertrace.support.applicability",
            1,
            &CanonicalValue::String(
                serde_json::to_string(&atom.applicability_expr)
                    .map_err(|_| SemanticServiceError::InvalidInput)?,
            ),
        )
        .map_err(|_| SemanticServiceError::InvalidInput)?,
        support_revision_refs: support_refs.clone(),
        authorization_revision_refs: vec![proposal.proposal_revision_id],
        support_threshold_snapshot: SupportThresholdSnapshot {
            minimum_surviving_support: 1,
            require_authorization: true,
        },
        promotion_proposal_revision_id: proposal.proposal_revision_id,
        promotion_validator_revision: 1,
        created_at_us: occurred_at_us,
    };
    let validation = GlobalSupportValidationEvent {
        validation_revision_id: RevisionId::new_v7(),
        support_contract_ref,
        successor_ref: atom.revision_id.to_string(),
        dependency_generation: 1,
        state: GlobalSupportState::Valid,
        provenance_degraded: false,
        surviving_support_refs: support_refs,
        invalid_or_missing_refs: Vec::new(),
        trigger_refs: Vec::new(),
        validator_revision: 1,
        created_at_us: occurred_at_us,
    };
    let dirty = DirtyTarget {
        target_kind: DirtyTargetKind::RuntimeJob,
        target_id: support_contract_ref.to_string(),
        algorithm_revision: S23_ALGORITHM.into(),
        source_watermark: 1,
    };
    Ok(vec![
        JournalPayload::GlobalSupportContractRecorded(Box::new(contract)),
        JournalPayload::GlobalSupportValidationRecorded(Box::new(validation)),
        JournalPayload::DirtyTarget(dirty.clone()),
        JournalPayload::OutboxEnqueued(OutboxEntry {
            outbox_id: format!("support:{support_contract_ref}:1"),
            dirty,
        }),
    ])
}

pub struct ScenarioCompiler;

impl ScenarioCompiler {
    pub fn compile(
        snapshot: &ProjectionSnapshot,
        scope: ScenarioScope,
        previous: Option<&Scenario>,
    ) -> Result<Option<Scenario>, SemanticServiceError> {
        scope
            .validate()
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        let view = ScenarioView::from_snapshot(snapshot)?;
        let task = view
            .tasks
            .get(&scope.task_id)
            .map(|value| &value.0)
            .ok_or(SemanticServiceError::InvalidInput)?;
        let mut workstreams = view
            .workstreams
            .values()
            .map(|value| &value.0)
            .filter(|value| workstream_in_scope(value, &scope))
            .collect::<Vec<_>>();
        workstreams.sort_by_key(|value| value.workstream_id);
        let workstream_ids = workstreams
            .iter()
            .map(|value| value.workstream_id)
            .collect::<BTreeSet<_>>();
        let mut episodes = view
            .episodes
            .values()
            .map(|value| &value.0)
            .filter(|value| workstream_ids.contains(&value.workstream_id))
            .collect::<Vec<_>>();
        episodes.sort_by_key(|value| value.revision_id);
        let mut attempts = view
            .attempts
            .values()
            .map(|value| &value.0)
            .filter(|value| workstream_ids.contains(&value.workstream_id))
            .collect::<Vec<_>>();
        attempts.sort_by_key(|value| value.attempt_id);
        let active_attempts = attempts
            .iter()
            .copied()
            .filter(|value| {
                value.lifecycle_status == AttemptLifecycleStatus::Active
                    && value.execution_status == AttemptExecutionStatus::Active
            })
            .collect::<Vec<_>>();
        let integrated = attempts
            .iter()
            .copied()
            .filter(|value| {
                value.execution_status == AttemptExecutionStatus::Completed
                    && value.adoption_status == AttemptAdoptionStatus::Integrated
                    && value.verification == AttemptVerification::Passed
            })
            .collect::<Vec<_>>();
        let mut atoms = view
            .atoms
            .values()
            .map(|value| &value.0)
            .filter(|value| {
                atom_in_scope(value, &scope)
                    && value.lifecycle_status == AtomLifecycleStatus::Active
            })
            .collect::<Vec<_>>();
        atoms.sort_by_key(|value| value.revision_id);
        let mut constraints = atoms
            .iter()
            .filter(|value| value.kind == AtomKind::Constraint)
            .map(|value| value.revision_id)
            .collect::<Vec<_>>();
        let mut decisions = atoms
            .iter()
            .filter(|value| value.kind == AtomKind::Decision)
            .map(|value| value.revision_id)
            .collect::<Vec<_>>();
        let mut support_atom_ids = atoms.iter().map(|value| value.atom_id).collect::<Vec<_>>();
        constraints.sort();
        constraints.dedup();
        decisions.sort();
        decisions.dedup();
        support_atom_ids.sort();
        support_atom_ids.dedup();
        let active_workstreams_exact = workstreams
            .iter()
            .copied()
            .filter(|value| value.status == WorkstreamStatus::Active)
            .collect::<Vec<_>>();
        let active_workstream = match active_workstreams_exact.as_slice() {
            [only] => Some(*only),
            _ => None,
        };
        let active_episode = active_workstream
            .and_then(|stream| stream.active_episode_id)
            .and_then(|episode_id| view.episodes.get(&episode_id))
            .map(|value| &value.0)
            .filter(|episode| episode.lifecycle_status == EpisodeLifecycle::Open);
        let active_lineage_attempts = active_attempts
            .iter()
            .copied()
            .filter(|attempt| {
                active_workstream
                    .is_some_and(|stream| attempt.workstream_id == stream.workstream_id)
                    && active_episode
                        .is_some_and(|episode| attempt.episode_id == Some(episode.episode_id))
            })
            .collect::<Vec<_>>();
        if active_lineage_attempts.len() > 1 {
            return Err(SemanticServiceError::ImmutableConflict);
        }
        let active_attempt = active_lineage_attempts.first().copied();
        let mut unresolved = active_attempts
            .iter()
            .flat_map(|value| value.competing_group_ids.iter().copied())
            .collect::<Vec<_>>();
        unresolved.sort();
        unresolved.dedup();
        let mut current_state = integrated
            .iter()
            .flat_map(|value| value.outcome_refs.iter().cloned())
            .collect::<Vec<_>>();
        current_state.sort();
        current_state.dedup();
        let mut completed_outcomes = current_state.clone();
        let mut active_failures = attempts
            .iter()
            .filter_map(|value| value.failure_signature.clone())
            .collect::<Vec<_>>();
        active_failures.sort();
        active_failures.dedup();
        let mut open_loops = episodes
            .iter()
            .filter(|value| value.lifecycle_status == EpisodeLifecycle::Open)
            .flat_map(|value| value.open_loops.iter().cloned())
            .collect::<Vec<_>>();
        open_loops.sort();
        open_loops.dedup();
        let mut active_workstreams = workstreams
            .iter()
            .filter(|value| {
                matches!(
                    value.status,
                    WorkstreamStatus::Active | WorkstreamStatus::Paused
                )
            })
            .map(|value| ScenarioWorkstream {
                workstream_id: value.workstream_id,
                phase_kind: value.phase_contract.phase_kind,
                open_episode_id: value.active_episode_id,
            })
            .collect::<Vec<_>>();
        active_workstreams.sort_by_key(|value| value.workstream_id);
        let mut running_experiment_refs = view
            .experiments
            .values()
            .map(|value| &value.0)
            .filter(|value| {
                workstream_ids.contains(&value.workstream_id)
                    && value.execution_status == evertrace_domain::work::RunExecutionStatus::Running
            })
            .map(|value| value.run_id)
            .collect::<Vec<_>>();
        running_experiment_refs.sort();
        running_experiment_refs.dedup();
        let mut relevant_artifacts = view
            .artifacts
            .values()
            .map(|value| &value.0)
            .filter(|value| {
                value.revision.scope.task_id() == Some(scope.task_id)
                    && value.revision.scope.repository_id() == scope.repository_instance_id
            })
            .map(|value| value.work_artifact_id)
            .collect::<Vec<_>>();
        relevant_artifacts.sort();
        relevant_artifacts.dedup();
        let status = if task.lifecycle == TaskLifecycle::Active {
            ScenarioStatus::Active
        } else {
            ScenarioStatus::Closed
        };
        let revision = Scenario {
            scenario_id: scope
                .scenario_id()
                .map_err(|_| SemanticServiceError::InvalidInput)?,
            revision_id: RevisionId::new_v7(),
            predecessor_revision_id: previous.map(|value| value.revision_id),
            revision_generation: previous.map_or(1, |value| value.revision_generation + 1),
            scope,
            active_worktree_snapshot_id: active_episode
                .and_then(|value| value.entry_worktree_snapshot_id),
            worktree_lineage_refs: active_workstream
                .map_or_else(Vec::new, |value| value.worktree_lineage_refs.clone()),
            status,
            goal: task.canonical_goal.clone(),
            current_state,
            active_lineage: ActiveScenarioLineage {
                active_workstream_id: active_workstream.map(|v| v.workstream_id),
                active_episode_id: active_episode.map(|v| v.episode_id),
                active_attempt_id: active_attempt.map(|v| v.attempt_id),
                unresolved_competing_group_ids: unresolved,
            },
            active_workstreams,
            running_experiment_refs,
            constraints,
            decisions,
            open_loops,
            active_failures,
            completed_outcomes: {
                completed_outcomes.sort();
                completed_outcomes.dedup();
                completed_outcomes
            },
            relevant_artifacts,
            support_atom_ids,
            source_watermark: snapshot.frontier,
        };
        revision
            .validate()
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        if previous.is_some_and(|value| same_scenario_content(value, &revision)) {
            return Ok(None);
        }
        if let Some(previous) = previous {
            previous
                .validate_successor(&revision)
                .map_err(|_| SemanticServiceError::ImmutableConflict)?;
        }
        Ok(Some(revision))
    }

    pub fn journal_command(
        command_id: CommandId,
        scenario: Scenario,
        effective_config_hash: [u8; 32],
        occurred_at_us: i64,
    ) -> Result<JournalCommand, SemanticServiceError> {
        scenario
            .validate()
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        JournalCommand::new(
            command_id,
            vec![draft(
                occurred_at_us,
                effective_config_hash,
                JournalPayload::ScenarioRecorded(Box::new(scenario)),
            )],
        )
        .map_err(SemanticServiceError::Store)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreGovernanceDecision {
    pub eligibility: ProposalEligibility,
    pub auto_accept: bool,
}

impl CoreGovernanceDecision {
    pub fn evaluate(atom: &Atom, config: &GlobalPromotionConfig, conflicted: bool) -> Self {
        let eligible_scope = matches!(atom.scope, AtomScope::Global | AtomScope::Repository { .. });
        let base = atom.validate().is_ok()
            && atom.kind == AtomKind::Constraint
            && atom.epistemic_status == EpistemicStatus::NotApplicable
            && atom.lifecycle_status == AtomLifecycleStatus::Active
            && eligible_scope
            && !conflicted;
        if !base || atom.authority == AtomAuthority::AgentInferred {
            return Self {
                eligibility: ProposalEligibility::ManualRequired,
                auto_accept: false,
            };
        }
        let tui_global = atom.authority == AtomAuthority::UserExplicit
            && matches!(atom.scope, AtomScope::Global)
            && atom
                .user_authorization_provenance
                .as_ref()
                .is_some_and(|value| value.mode == UserAuthorizationMode::TuiAcceptance);
        if tui_global && config.core_membership == PromotionLevel::FullAuto {
            Self {
                eligibility: ProposalEligibility::AutoEligibleFull,
                auto_accept: true,
            }
        } else if config.core_membership == PromotionLevel::Manual {
            Self {
                eligibility: ProposalEligibility::ManualRequired,
                auto_accept: false,
            }
        } else {
            Self {
                eligibility: ProposalEligibility::AutoEligible,
                auto_accept: false,
            }
        }
    }
}

pub fn submit_core_conflict_proposal(
    view: &SemanticCurrentView,
    context: ProposalCommandContext,
    left: RevisionId,
    right: RevisionId,
    scope_identity: CoreScopeIdentity,
    evidence_refs: Vec<String>,
) -> Result<ProposalResolution<RevisionProposal>, SemanticServiceError> {
    if left == right || evidence_refs.is_empty() {
        return Err(SemanticServiceError::InvalidInput);
    }
    RevisionProposalService.submit(
        view,
        context,
        SubmitProposalRequest {
            target_kind: ProposalTargetKind::CoreMembership,
            target_id: None,
            base_revision_id: None,
            operation: ProposalOperation::Create,
            payload: ProposalPayload::CoreMembership(Box::new(
                CoreMembershipProposalPayload::ResolveConflict {
                    left_atom_revision_id: left,
                    right_atom_revision_id: right,
                    scope_identity,
                },
            )),
            evidence_refs: evidence_refs.clone(),
            source_cohort_refs: evidence_refs,
            eligibility: ProposalEligibility::ManualRequired,
            created_by: ProposalCreatedBy::Agent,
        },
    )
}

#[derive(Debug)]
pub struct AcceptedCoreMembershipCommand {
    pub proposal: Box<RevisionProposal>,
    pub membership: Box<CoreMembership>,
    pub command: JournalCommand,
}

#[derive(Clone, Debug)]
pub enum CoreMembershipAcceptanceContext {
    Tui(AtomAcceptanceContext),
    AutoFull,
}

#[allow(clippy::too_many_arguments)]
pub fn accept_core_membership(
    view: &SemanticCurrentView,
    context: ProposalCommandContext,
    proposal_id: evertrace_domain::ids::RevisionProposalId,
    acceptance_context: CoreMembershipAcceptanceContext,
    atom: &Atom,
    membership_id: CoreMembershipId,
    threshold: SupportThresholdSnapshot,
) -> Result<AcceptedCoreMembershipCommand, SemanticServiceError> {
    let proposal = view
        .proposals
        .get(&proposal_id)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let ProposalPayload::CoreMembership(payload) = &proposal.payload else {
        return Err(SemanticServiceError::UnsupportedTarget);
    };
    let CoreMembershipProposalPayload::Create {
        atom_revision_id,
        scope_identity,
    } = payload.as_ref()
    else {
        return Err(SemanticServiceError::UnsupportedTarget);
    };
    if !proposal.status.is_open()
        || proposal.target_kind != ProposalTargetKind::CoreMembership
        || proposal.operation != ProposalOperation::Create
        || *atom_revision_id != atom.revision_id
        || atom.validate().is_err()
        || !matches!(
            atom.authority,
            AtomAuthority::UserExplicit | AtomAuthority::ProjectPolicy
        )
        || atom.kind != AtomKind::Constraint
        || atom.lifecycle_status != AtomLifecycleStatus::Active
    {
        return Err(SemanticServiceError::InvalidInput);
    }
    threshold
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    let scope = match atom.scope {
        AtomScope::Global => CoreScopeIdentity::Global,
        AtomScope::Repository {
            repository_instance_id,
        } => CoreScopeIdentity::Repository(repository_instance_id),
        _ => return Err(SemanticServiceError::InvalidInput),
    };
    if &scope != scope_identity {
        return Err(SemanticServiceError::InvalidInput);
    }
    let support_contract_ref = RevisionId::new_v7();
    let membership_revision_id = RevisionId::new_v7();
    let target = AcceptedProposalTarget::CoreMembership {
        core_membership_id: membership_id,
        membership_revision_id,
    };
    let accepted_revision_id = RevisionId::new_v7();
    let (accepted, mut payloads) = match acceptance_context {
        CoreMembershipAcceptanceContext::Tui(value) => {
            let evertrace_domain::semantic::ProposalAcceptanceAuthority::TuiAcceptance {
                authorized_scope_ceiling,
                ..
            } = value.authority_basis()?
            else {
                return Err(SemanticServiceError::InvalidInput);
            };
            if !authorized_scope_ceiling.contains(&atom.scope) {
                return Err(SemanticServiceError::InvalidInput);
            }
            accepted_proposal_successor(proposal, &context, &value, accepted_revision_id, target)?
        }
        CoreMembershipAcceptanceContext::AutoFull => {
            let authorization = atom
                .user_authorization_provenance
                .as_ref()
                .ok_or(SemanticServiceError::InvalidInput)?;
            if proposal.eligibility != ProposalEligibility::AutoEligibleFull
                || atom.authority != AtomAuthority::UserExplicit
                || authorization.mode != UserAuthorizationMode::TuiAcceptance
                || !matches!(authorization.authorized_scope_ceiling, AtomScope::Global)
                || !matches!(atom.scope, AtomScope::Global)
            {
                return Err(SemanticServiceError::InvalidInput);
            }
            accepted_proposal_successor_with_audit(
                proposal,
                &context,
                accepted_revision_id,
                target,
                ProposalAcceptanceAudit {
                    reviewer_identity: format!(
                        "user_source:{}",
                        authorization.user_source_observation_ref
                    ),
                    acceptance_event_ref: authorization
                        .acceptance_event_ref
                        .clone()
                        .ok_or(SemanticServiceError::InvalidInput)?,
                    authority_basis:
                        evertrace_domain::semantic::ProposalAcceptanceAuthority::TuiAcceptance {
                            user_source_observation_ref: authorization.user_source_observation_ref,
                            authorized_scope_ceiling: AtomScope::Global,
                        },
                },
            )?
        }
    };
    let support_refs = vec![atom.revision_id];
    let authorization_refs = vec![accepted.proposal_revision_id];
    let membership = CoreMembership {
        core_membership_id: membership_id,
        membership_revision_id,
        atom_revision_id: atom.revision_id,
        scope_identity: scope,
        support_contract_ref,
        authorization_revision_refs: authorization_refs.clone(),
        supersedes_membership_revision_id: None,
        created_by_acceptance_ref: accepted.proposal_revision_id,
        active: true,
    };
    let contract = GlobalSuccessorSupportContract {
        support_contract_revision_id: support_contract_ref,
        successor_revision_or_membership_ref: membership_revision_id.to_string(),
        evidence_cohort_hash: digest_revisions("evertrace.support.cohort", &support_refs)?,
        applicability_contract_hash: sha256(
            "evertrace.support.applicability",
            1,
            &CanonicalValue::String(
                serde_json::to_string(&atom.applicability_expr)
                    .map_err(|_| SemanticServiceError::InvalidInput)?,
            ),
        )
        .map_err(|_| SemanticServiceError::InvalidInput)?,
        support_revision_refs: support_refs.clone(),
        authorization_revision_refs: authorization_refs,
        support_threshold_snapshot: threshold,
        promotion_proposal_revision_id: accepted.proposal_revision_id,
        promotion_validator_revision: 1,
        created_at_us: context.occurred_at_us,
    };
    let validation = GlobalSupportValidationEvent {
        validation_revision_id: RevisionId::new_v7(),
        support_contract_ref,
        successor_ref: membership_revision_id.to_string(),
        dependency_generation: 1,
        state: GlobalSupportState::Valid,
        provenance_degraded: false,
        surviving_support_refs: support_refs,
        invalid_or_missing_refs: Vec::new(),
        trigger_refs: Vec::new(),
        validator_revision: 1,
        created_at_us: context.occurred_at_us,
    };
    let dirty = DirtyTarget {
        target_kind: DirtyTargetKind::RuntimeJob,
        target_id: support_contract_ref.to_string(),
        algorithm_revision: S23_ALGORITHM.into(),
        source_watermark: 1,
    };
    payloads.extend(vec![
        JournalPayload::CoreMembershipRecorded(Box::new(membership.clone())),
        JournalPayload::GlobalSupportContractRecorded(Box::new(contract)),
        JournalPayload::GlobalSupportValidationRecorded(Box::new(validation)),
        JournalPayload::DirtyTarget(dirty.clone()),
        JournalPayload::OutboxEnqueued(OutboxEntry {
            outbox_id: format!("support:{support_contract_ref}:1"),
            dirty,
        }),
    ]);
    let command = JournalCommand::new(
        context.command_id,
        payloads
            .into_iter()
            .map(|payload| {
                draft(
                    context.occurred_at_us,
                    context.effective_config_hash,
                    payload,
                )
            })
            .collect(),
    )
    .map_err(SemanticServiceError::Store)?;
    Ok(AcceptedCoreMembershipCommand {
        proposal: Box::new(accepted),
        membership: Box::new(membership),
        command,
    })
}

pub fn mark_support_pending(
    current: &GlobalSupportValidationEvent,
    trigger_refs: Vec<String>,
    config_hash: [u8; 32],
    occurred_at_us: i64,
) -> Result<Vec<JournalPayload>, SemanticServiceError> {
    let generation = current
        .dependency_generation
        .checked_add(1)
        .ok_or(SemanticServiceError::InvalidInput)?;
    let pending = GlobalSupportValidationEvent {
        validation_revision_id: RevisionId::new_v7(),
        support_contract_ref: current.support_contract_ref,
        successor_ref: current.successor_ref.clone(),
        dependency_generation: generation,
        state: GlobalSupportState::RevalidationPending,
        provenance_degraded: current.provenance_degraded,
        surviving_support_refs: current.surviving_support_refs.clone(),
        invalid_or_missing_refs: Vec::new(),
        trigger_refs,
        validator_revision: 1,
        created_at_us: occurred_at_us,
    };
    pending
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    let dirty = DirtyTarget {
        target_kind: DirtyTargetKind::RuntimeJob,
        target_id: current.support_contract_ref.to_string(),
        algorithm_revision: S23_ALGORITHM.into(),
        source_watermark: generation,
    };
    let job = DurableJob {
        job_id: JobId::new_v7(),
        idempotency_key: format!("support:{}:{generation}", current.support_contract_ref),
        target_revision: current.successor_ref.clone(),
        target_watermark: generation,
        target_generation: generation,
        kind: "support_closure".into(),
        priority: 0,
        state: JobStatus::Queued,
        attempt: 1,
        backoff_until_us: None,
        config_hash,
        lease_until_us: None,
    };
    Ok(vec![
        JournalPayload::GlobalSupportValidationRecorded(Box::new(pending)),
        JournalPayload::DirtyTarget(dirty.clone()),
        JournalPayload::OutboxEnqueued(OutboxEntry {
            outbox_id: format!("support:{}:{generation}", current.support_contract_ref),
            dirty,
        }),
        JournalPayload::JobState(job),
    ])
}

fn draft(at: i64, config: [u8; 32], payload: JournalPayload) -> JournalEventDraft {
    JournalEventDraft::runtime(at, config, S23_ALGORITHM, payload)
}

fn digest_revisions(tag: &str, values: &[RevisionId]) -> Result<[u8; 32], SemanticServiceError> {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    sha256(
        tag,
        1,
        &CanonicalValue::Sequence(
            values
                .into_iter()
                .map(|value| CanonicalValue::String(value.to_string()))
                .collect(),
        ),
    )
    .map_err(|_| SemanticServiceError::InvalidInput)
}

fn same_scenario_content(left: &Scenario, right: &Scenario) -> bool {
    left.scope == right.scope
        && left.status == right.status
        && left.goal == right.goal
        && left.current_state == right.current_state
        && left.active_lineage == right.active_lineage
        && left.active_workstreams == right.active_workstreams
        && left.constraints == right.constraints
        && left.decisions == right.decisions
        && left.open_loops == right.open_loops
        && left.active_failures == right.active_failures
        && left.completed_outcomes == right.completed_outcomes
        && left.relevant_artifacts == right.relevant_artifacts
        && left.support_atom_ids == right.support_atom_ids
        && left.running_experiment_refs == right.running_experiment_refs
        && left.active_worktree_snapshot_id == right.active_worktree_snapshot_id
        && left.worktree_lineage_refs == right.worktree_lineage_refs
}

fn workstream_in_scope(value: &Workstream, scope: &ScenarioScope) -> bool {
    value.task_id == scope.task_id
        && value.repository_instance_id == scope.repository_instance_id
        && value.active_worktree_instance_id == scope.worktree_instance_id
}
fn atom_in_scope(value: &Atom, scope: &ScenarioScope) -> bool {
    match &value.scope {
        AtomScope::Task { task_id } => *task_id == scope.task_id,
        AtomScope::Repository {
            repository_instance_id,
        } => Some(*repository_instance_id) == scope.repository_instance_id,
        AtomScope::Worktree {
            repository_instance_id,
            worktree_instance_id,
        } => {
            Some(*repository_instance_id) == scope.repository_instance_id
                && Some(*worktree_instance_id) == scope.worktree_instance_id
        }
        AtomScope::Global => false,
    }
}

#[derive(Default)]
struct ScenarioView {
    tasks: BTreeMap<evertrace_domain::ids::TaskId, (Task, u64)>,
    workstreams: BTreeMap<evertrace_domain::ids::WorkstreamId, (Workstream, u64)>,
    episodes: BTreeMap<evertrace_domain::ids::WorkEpisodeId, (WorkEpisode, u64)>,
    attempts: BTreeMap<evertrace_domain::ids::AttemptId, (Attempt, u64)>,
    atoms: BTreeMap<evertrace_domain::ids::AtomId, (Atom, u64)>,
    experiments: BTreeMap<evertrace_domain::ids::ExperimentRunId, (ExperimentRun, u64)>,
    artifacts: BTreeMap<evertrace_domain::ids::WorkArtifactId, (WorkArtifact, u64)>,
}
impl ScenarioView {
    fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut view = Self::default();
        for row in snapshot
            .rows
            .iter()
            .filter(|row| row.row_kind == ObjectRowKind::Data)
        {
            let Some(kind) = row.object_kind.as_deref() else {
                continue;
            };
            if !matches!(
                kind,
                "task"
                    | "workstream"
                    | "work_episode"
                    | "attempt"
                    | "atom_revision"
                    | "experiment_run"
                    | "work_artifact"
            ) {
                continue;
            }
            let payload: JournalPayload = serde_json::from_str(
                row.payload_json
                    .as_deref()
                    .ok_or(StoreError::StoreCorrupt)?,
            )
            .map_err(|_| StoreError::StoreCorrupt)?;
            match payload {
                JournalPayload::TaskRecorded(value) => {
                    replace_seq(&mut view.tasks, value.task_id, *value, row.source_event_seq);
                }
                JournalPayload::WorkstreamRecorded(value) => {
                    replace_seq(
                        &mut view.workstreams,
                        value.workstream_id,
                        *value,
                        row.source_event_seq,
                    );
                }
                JournalPayload::WorkEpisodeRecorded(value) => {
                    replace_generation(
                        &mut view.episodes,
                        value.episode_id,
                        *value,
                        row.source_event_seq,
                        |v| v.revision_generation,
                    );
                }
                JournalPayload::AttemptRecorded(value) => {
                    replace_generation(
                        &mut view.attempts,
                        value.attempt_id,
                        *value,
                        row.source_event_seq,
                        |v| v.revision_generation,
                    );
                }
                JournalPayload::AtomRecorded(value) => {
                    replace_seq(&mut view.atoms, value.atom_id, *value, row.source_event_seq);
                }
                JournalPayload::ExperimentRunRecorded(value) => {
                    replace_seq(
                        &mut view.experiments,
                        value.run_id,
                        *value,
                        row.source_event_seq,
                    );
                }
                JournalPayload::WorkArtifactRecorded(value) => {
                    replace_seq(
                        &mut view.artifacts,
                        value.work_artifact_id,
                        *value,
                        row.source_event_seq,
                    );
                }
                _ => return Err(StoreError::StoreCorrupt),
            }
        }
        Ok(view)
    }
}
fn replace_seq<K: Ord, V>(map: &mut BTreeMap<K, (V, u64)>, key: K, value: V, seq: u64) {
    if map.get(&key).is_none_or(|current| current.1 < seq) {
        map.insert(key, (value, seq));
    }
}
fn replace_generation<K: Ord, V>(
    map: &mut BTreeMap<K, (V, u64)>,
    key: K,
    value: V,
    seq: u64,
    generation: impl Fn(&V) -> u64,
) {
    if map
        .get(&key)
        .is_none_or(|current| generation(&value) > generation(&current.0))
    {
        map.insert(key, (value, seq));
    }
}
