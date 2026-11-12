use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use evertrace_capture::{CasDigest, CasStore};
use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, EvidenceSurface, Operation, PairingState,
        SourceArchiveMode, SourceObservation, SourceReceipt, SourceRole, hex, payload_fingerprint,
    },
    ids::{
        AttemptId, CasId, CommandId, OperationId, ResultEvidenceId, SourceObservationId,
        SourceReceiptId, WorkArtifactId,
    },
    procedure::{ProcedureRevision, ProcedureUsageRevision},
    repository::{WorktreeInstance, WorktreeSnapshot},
    revision::RevisionId,
    semantic::{
        EvidenceCompleteness, MetricValue, ParserFailureCode, ParserReceipt, ParserStatus,
        ResultEvidence, ResultFailure, ResultScope, VerifierFailureCode, VerifierReceipt,
        VerifierStatus,
    },
    work::{
        ArtifactActor, ArtifactPayloadStatus, ArtifactRevision, ArtifactScope, AssignmentStatus,
        Attempt, AttemptBindingStatus, ContractField, ControlledRunSourceEnvelope, ExperimentRun,
        MultiCasMetricPolicy, ResultCohortAssessment, ResultComparisonIssue,
        ResultComparisonReason, RunContractValidity, RunExecutionStatus, RunObservability,
        RunOrigin, SeedPolicy, Task, VariableDeclaration, WorkArtifact, WorkBindingRevision,
        WorkEpisode, Workstream,
    },
};
use evertrace_store::{
    AutoresearchCurrentView, JournalCommand, JournalEventDraft, JournalPayload, ProjectionSnapshot,
};
use serde::Deserialize;
use thiserror::Error;

const RESULT_PARSER_VERSION: &str = "evertrace.result_metric.v1";
const RESULT_VERIFIER_VERSION: &str = "evertrace.result_reparse.v1";
const MAX_COMPARISON_MEMBERS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutoresearchResolution<T> {
    NoDelta,
    Revision(Box<T>),
}

#[derive(Debug)]
pub struct AutoresearchCommandRevision<T> {
    pub value: Box<T>,
    pub command: JournalCommand,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutoresearchCommandContext {
    pub command_id: CommandId,
    pub occurred_at_us: i64,
    pub effective_config_hash: [u8; 32],
    pub algorithm_revision: &'static str,
}

/// Ephemeral fair progress; canonical Run/Result own replay and recovery.
#[derive(Debug, Default)]
pub(crate) struct ControlledSourceScan {
    after: Option<SourceObservationId>,
    completed: u64,
    round: u64,
    checked_frontier: u64,
    context: Option<([u8; 32], Option<String>)>,
}

impl ControlledSourceScan {
    pub(crate) fn observe_context(&mut self, config: [u8; 32], policy_receipt: Option<&str>) {
        if self
            .context
            .as_ref()
            .is_none_or(|(previous_config, previous_policy)| {
                *previous_config != config || previous_policy.as_deref() != policy_receipt
            })
        {
            self.retry();
            self.context = Some((config, policy_receipt.map(str::to_owned)));
        }
    }

    pub(crate) fn resume_after(&mut self, observation: SourceObservationId) {
        self.after = Some(observation);
    }

    pub(crate) fn retry(&mut self) {
        self.after = None;
        self.completed = 0;
        self.checked_frontier = 0;
    }

    pub(crate) fn defer(&mut self) {
        self.round = 0;
        self.completed = 0;
        self.checked_frontier = 0;
    }

    pub(crate) fn page(
        &mut self,
        current: &evertrace_store::CurrentFacts,
    ) -> (Vec<SourceObservationId>, bool) {
        let input_watermark = || {
            current
                .other_data_rows()
                .map(|row| row.source_event_seq)
                .chain(current.source_observations().map(|(_, seq)| seq))
                .max()
                .unwrap_or(0)
        };
        if self.after.is_none() {
            if self.checked_frontier == current.frontier() {
                return (Vec::new(), false);
            }
            self.checked_frontier = current.frontier();
            let watermark = input_watermark();
            if self.completed == watermark {
                return (Vec::new(), false);
            }
            self.round = watermark;
        }
        let mut candidates = Vec::new();
        for (inspected, (observation, _)) in
            current.source_observations_after(self.after).enumerate()
        {
            if inspected == 64 {
                return (candidates, true);
            }
            self.after = Some(observation.source_observation_id);
            if let Some(envelope) = source_candidate(current, observation.source_observation_id)
                && !source_resolved(current, observation, &envelope)
            {
                candidates.push(observation.source_observation_id);
                if candidates.len() == 4 {
                    return (candidates, true);
                }
            }
        }
        self.after = None;
        self.completed = self.round;
        // A fair scan may finish after its own previous commit's wakeup was
        // consumed. New relevant facts still require the next round.
        (candidates, input_watermark() > self.completed)
    }
}

// Replaying an already admitted source must not reopen a repository or mutate current trust.
fn source_resolved(
    current: &evertrace_store::CurrentFacts,
    observation: &SourceObservation,
    envelope: &SourceCandidate,
) -> bool {
    if let SourceCandidate::RootGoal {
        reference,
        objective,
    } = envelope
    {
        let sequence = current
            .source_observation(observation.source_observation_id)
            .map_or(0, |(_, seq)| seq);
        let Ok(scopes) = root_scope_candidates(current, observation.source_observation_id, None)
        else {
            return false;
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(40);
        return current
            .other_data_rows()
            .take_while(|_| std::time::Instant::now() < deadline)
            .any(|row| {
                if row.object_kind.as_deref() != Some("task") {
                    return false;
                }
                let Some(JournalPayload::TaskRecorded(task)) = row
                    .payload_json
                    .as_deref()
                    .and_then(|json| serde_json::from_str::<JournalPayload>(json).ok())
                else {
                    return false;
                };
                task.identity_confidence == evertrace_domain::work::TaskIdentityConfidence::Explicit
                    && task.request_root_refs.contains(reference)
                    && (task.lifecycle.is_terminal()
                        || (objective
                            .as_ref()
                            .map_or(task.source_watermark >= sequence, |goal| {
                                task.canonical_goal == *goal
                            })
                            && scopes.iter().all(|scope| {
                                task.scope_memberships.iter().any(|membership| {
                                    membership.repository_instance_id == Some(scope.repository)
                                        && membership
                                            .worktree_instance_ids
                                            .contains(&scope.worktree)
                                })
                            })))
            });
    }
    if matches!(envelope, SourceCandidate::WorkPlan(_)) {
        let reference = observation.source_observation_id.to_string();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(40);
        return current
            .other_data_rows()
            .take_while(|_| std::time::Instant::now() < deadline)
            .any(|row| {
                if row.object_kind.as_deref() != Some("workstream") {
                    return false;
                }
                let Some(JournalPayload::WorkstreamRecorded(value)) = row
                    .payload_json
                    .as_deref()
                    .and_then(|json| serde_json::from_str::<JournalPayload>(json).ok())
                else {
                    return false;
                };
                value.worktree_lineage_refs.contains(&reference)
                    && (value.status.is_terminal()
                        || (value.active_episode_id.is_some()
                            && current
                                .other_data_rows()
                                .take_while(|_| std::time::Instant::now() < deadline)
                                .any(|row| {
                                    if row.object_kind.as_deref() != Some("work_binding") {
                                        return false;
                                    }
                                    let Some(JournalPayload::WorkBindingRecorded(binding)) =
                                        row.payload_json.as_deref().and_then(|json| {
                                            serde_json::from_str::<JournalPayload>(json).ok()
                                        })
                                    else {
                                        return false;
                                    };
                                    binding.assignment_status == AssignmentStatus::Resolved
                                        && binding.primary_binding.task_id == Some(value.task_id)
                                        && binding.primary_binding.workstream_id
                                            == Some(value.workstream_id)
                                        && binding.evidence_refs.contains(&reference)
                                })))
            });
    }
    if matches!(envelope, SourceCandidate::Trial(_)) {
        return current.other_data_rows().any(|row| {
            row.payload_json
                .as_deref()
                .and_then(|json| serde_json::from_str::<JournalPayload>(json).ok())
                .is_some_and(|payload| {
                    matches!(payload, JournalPayload::ExperimentRunRecorded(run)
                if run.source_receipt_refs.contains(&observation.source_receipt_ref))
                })
        });
    }
    let SourceCandidate::Run(envelope) = envelope else {
        return false;
    };
    current.other_data_rows().any(|row| {
        if row.object_kind.as_deref() != Some("experiment_run") {
            return false;
        }
        let Some(JournalPayload::ExperimentRunRecorded(run)) = row
            .payload_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<JournalPayload>(json).ok())
        else {
            return false;
        };
        match envelope {
            ControlledRunSourceEnvelope::Launch { .. } => run
                .source_receipt_refs
                .contains(&observation.source_receipt_ref),
            ControlledRunSourceEnvelope::Terminal { run_id, .. } => {
                run.run_id == *run_id && !run.is_controlled_declaration()
            }
        }
    })
}

#[derive(Deserialize)]
struct ProcessWorkPlan {
    study_key: String,
    goal: String,
    scope: String,
    phase: evertrace_domain::work::PhaseContract,
    strategy: evertrace_domain::work::StrategyContract,
}

#[derive(Deserialize)]
struct ProcessController {
    pid: u32,
    start_ticks: u64,
    boot_id: String,
    pid_namespace: u64,
}

#[derive(Deserialize)]
struct ProcessWorkDeclaration {
    format: String,
    event: String,
    source_epoch: String,
    study_key: String,
    controller: ProcessController,
    definition: ProcessWorkPlan,
}

impl ProcessWorkDeclaration {
    fn decode(bytes: &[u8], receipt: &SourceReceipt) -> Option<Self> {
        let value: Self = serde_json::from_slice(bytes).ok()?;
        let controller = &value.controller;
        let instance = format!(
            "process:{}:{}:{}:{}",
            controller.boot_id, controller.pid_namespace, controller.pid, controller.start_ticks
        );
        (value.format == evertrace_capture::process_source::FORMAT
            && value.event == "study_opened"
            && value.study_key == value.definition.study_key
            && !value.source_epoch.is_empty()
            && receipt.source_sequence == 1
            && receipt.source_instance_id.as_str() == instance
            && value.definition.phase.validate().is_ok()
            && value.definition.strategy.validate().is_ok())
        .then_some(value)
    }
}

#[derive(Deserialize)]
struct ProcessTrialDeclaration {
    format: String,
    event: String,
    source_epoch: String,
    event_key: String,
    study_key: String,
    sequence: u64,
    controller: ProcessController,
    execution_key: String,
    request_key: String,
    execution_ordinal: u32,
    config: serde_json::Value,
    source_anchor: ProcessTrialAnchor,
}

#[derive(Deserialize)]
struct ProcessTrialAnchor {
    commit: String,
    tree: String,
    scorer_blob: String,
}

impl ProcessTrialDeclaration {
    fn decode(raw: &[u8], source: &SourceObservation, receipt: &SourceReceipt) -> Option<Self> {
        let value: Self = serde_json::from_slice(raw).ok()?;
        let instance = format!(
            "process:{}:{}:{}:{}",
            value.controller.boot_id,
            value.controller.pid_namespace,
            value.controller.pid,
            value.controller.start_ticks
        );
        (value.format == evertrace_capture::process_source::FORMAT
            && value.event == "trial_launch"
            && value.sequence == receipt.source_sequence
            && source.source_instance_id.as_str() == instance
            && receipt.source_record_identity.as_str() == value.event_key
            && source.correlation.host_trace_lineage_id.as_deref()
                == Some(value.source_epoch.as_str())
            && source.correlation.native_request_id.as_deref() == Some(value.request_key.as_str())
            && source.correlation.physical_execution_ordinal == Some(value.execution_ordinal)
            && value.execution_ordinal != 0)
            .then_some(value)
    }
}

enum SourceCandidate {
    WorkPlan(Box<ProcessWorkDeclaration>),
    Trial(Box<ProcessTrialDeclaration>),
    Run(ControlledRunSourceEnvelope),
    RootGoal {
        reference: String,
        objective: Option<String>,
    },
}

fn source_candidate(
    current: &evertrace_store::CurrentFacts,
    id: SourceObservationId,
) -> Option<SourceCandidate> {
    use evertrace_domain::evidence::{ContentTrust, SourceRole};
    let (observation, _) = current.source_observation(id)?;
    if observation.source_revision.as_str() == evertrace_capture::process_source::SOURCE_REVISION
        && observation.source_role == SourceRole::Tool
        && observation.content_trust == ContentTrust::UntrustedSourceContent
    {
        let (receipt, _) = current.source_receipt(observation.source_receipt_ref)?;
        let (surface, _) = current.evidence_surface(id)?;
        return ProcessWorkDeclaration::decode(surface.protected_text.as_bytes(), receipt)
            .map(|declaration| SourceCandidate::WorkPlan(Box::new(declaration)))
            .or_else(|| {
                ProcessTrialDeclaration::decode(
                    surface.protected_text.as_bytes(),
                    observation,
                    receipt,
                )
                .map(|value| SourceCandidate::Trial(Box::new(value)))
            });
    }
    if observation.content_trust != ContentTrust::Observed
        || !matches!(observation.source_role, SourceRole::Host | SourceRole::Tool)
    {
        return None;
    }
    if evertrace_capture::goal_source::is_source_revision(observation.source_revision.as_str()) {
        let (receipt, _) = current.source_receipt(observation.source_receipt_ref)?;
        if receipt.identity_domain != evertrace_capture::goal_source::IDENTITY_DOMAIN
            || receipt.source_ref != format!("native-host-goal:{}", receipt.source_session_ref)
        {
            return None;
        }
        let objective = current
            .evidence_surface(id)
            .and_then(|(surface, _)| {
                evertrace_capture::goal_source::observed_goal(surface.protected_text.as_bytes())
                    .ok()
                    .flatten()
            })
            .filter(|(reference, _)| reference == &receipt.source_ref)
            .map(|(_, goal)| goal);
        return Some(SourceCandidate::RootGoal {
            reference: receipt.source_ref.clone(),
            objective,
        });
    }
    let (surface, _) = current.evidence_surface(id)?;
    // Candidate decoding only: witness() must still verify original CAS/native receipts and eligibility.
    if !(surface.protected_text.starts_with("kind = \"launch\"\n")
        || surface.protected_text.starts_with("kind = \"terminal\"\n"))
    {
        return None;
    }
    ControlledRunSourceEnvelope::decode_canonical(surface.protected_text.as_bytes())
        .ok()
        .map(SourceCandidate::Run)
}

struct RootScopeCandidate {
    source: SourceObservationId,
    operation: OperationId,
    effect: evertrace_domain::ids::ScopeEffectId,
    repository: evertrace_domain::ids::RepositoryId,
    worktree: evertrace_domain::ids::WorktreeId,
}

/// Stored matches only select a finite candidate closure. The resolver must
/// revalidate the live RootGoal and each execution/effect before using it.
fn root_scope_candidates(
    current: &evertrace_store::CurrentFacts,
    goal: SourceObservationId,
    expected_directory: Option<(&CasStore, &str, u32, u64)>,
) -> Result<Vec<RootScopeCandidate>, AutoresearchError> {
    let Some((goal_observation, _)) = current.source_observation(goal) else {
        return Ok(Vec::new());
    };
    let Some((goal_receipt, _)) = current.source_receipt(goal_observation.source_receipt_ref)
    else {
        return Ok(Vec::new());
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(40);
    let mut ids = BTreeSet::new();
    for (receipt, _) in current.source_receipts() {
        if std::time::Instant::now() >= deadline {
            return Err(AutoresearchError::SelectionDeferred);
        }
        if !evertrace_capture::goal_source::same_execution_context(goal_receipt, receipt) {
            continue;
        }
        if let Some((cas, path, pid, start)) = expected_directory {
            let Some((native, _)) = current.source_observation(receipt.source_observation_id)
            else {
                continue;
            };
            let digest =
                CasDigest::from_str(&receipt.cas_ref).map_err(|_| AutoresearchError::Cas)?;
            // Native execution deliberately has no presentation surface. Read its bounded L0 CAS
            // only to select candidates; the resolver still authenticates every source/effect.
            let (raw, _) = cas
                .read_bounded(&digest, 128 * 1024, 65536)
                .map_err(|_| AutoresearchError::Cas)?;
            let directory =
                evertrace_capture::execution_source::execution_directory(native, receipt, &raw);
            if directory
                .as_ref()
                .map(|(path, pid, start)| (path.as_str(), *pid, *start))
                != Some((path, pid, start))
            {
                continue;
            }
        }
        ids.insert(receipt.source_observation_id);
    }
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let needles = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut operations = BTreeMap::<OperationId, Operation>::new();
    for row in current
        .other_data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("operation"))
    {
        if std::time::Instant::now() >= deadline {
            return Err(AutoresearchError::SelectionDeferred);
        }
        let Some(json) = &row.payload_json else {
            continue;
        };
        if !needles.iter().any(|id| json.contains(id)) {
            continue;
        }
        let JournalPayload::OperationDerived(operation) =
            serde_json::from_str(json).map_err(|_| AutoresearchError::EvidenceIncomplete)?
        else {
            continue;
        };
        if operations.get(&operation.operation_id).is_some_and(|old| {
            old.operation_revision == operation.operation_revision && old != operation.as_ref()
        }) {
            return Err(AutoresearchError::EvidenceIncomplete);
        }
        if operations
            .get(&operation.operation_id)
            .is_none_or(|old| old.operation_revision < operation.operation_revision)
        {
            operations.insert(operation.operation_id, *operation);
        }
    }
    let mut selected = BTreeMap::new();
    for row in current
        .other_data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("scope_effect"))
    {
        if std::time::Instant::now() >= deadline {
            return Err(AutoresearchError::SelectionDeferred);
        }
        let Some(JournalPayload::ScopeEffectDerived(effect)) = row
            .payload_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<JournalPayload>(json).ok())
        else {
            continue;
        };
        let Some(operation) = operations.get(&effect.operation_id) else {
            continue;
        };
        if !operation.scope_effect_ids.contains(&effect.scope_effect_id) {
            continue;
        }
        let (Some(repository), Some(worktree)) =
            (effect.repository_instance_id, effect.worktree_instance_id)
        else {
            continue;
        };
        let Some(source) = operation
            .input_source_observation_refs
            .iter()
            .chain(&operation.result_source_observation_refs)
            .find(|id| ids.contains(id) && effect.evidence_refs.contains(id))
            .copied()
        else {
            continue;
        };
        selected
            .entry((
                repository,
                worktree,
                expected_directory.map(|_| (operation.operation_id, effect.scope_effect_id)),
            ))
            .or_insert(RootScopeCandidate {
                source,
                operation: operation.operation_id,
                effect: effect.scope_effect_id,
                repository,
                worktree,
            });
        if selected.len() > 64 {
            return Err(AutoresearchError::EvidenceIncomplete);
        }
    }
    Ok(selected.into_values().collect())
}

/// A declaration only selects candidates here. CAS, publisher, physical scope and
/// the independent RootGoal are verified by the original resolver before writing.
fn process_work_refs(
    current: &evertrace_store::CurrentFacts,
    source: SourceObservationId,
    declaration: &ProcessWorkDeclaration,
    cas: &CasStore,
) -> Result<BTreeSet<String>, AutoresearchError> {
    let (observation, _) = current
        .source_observation(source)
        .ok_or(AutoresearchError::EvidenceIncomplete)?;
    let controller = &declaration.controller;
    let prefix = format!(
        "host-goal:{}:{}:",
        controller.boot_id, controller.pid_namespace
    );
    let mut refs = BTreeSet::new();
    let mut causal = BTreeSet::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(40);
    for (receipt, _) in current.source_receipts() {
        if std::time::Instant::now() >= deadline {
            return Err(AutoresearchError::SelectionDeferred);
        }
        if receipt.source_instance_id == observation.source_instance_id
            && receipt.source_revision == observation.source_revision
        {
            refs.insert(receipt.source_observation_id.to_string());
            causal.insert(receipt.source_observation_id);
        }
        if !receipt.source_instance_id.as_str().starts_with(&prefix) {
            continue;
        }
        let Some(SourceCandidate::RootGoal {
            reference,
            objective: Some(objective),
        }) = source_candidate(current, receipt.source_observation_id)
        else {
            continue;
        };
        if objective != declaration.definition.goal {
            continue;
        }
        refs.extend([receipt.source_observation_id.to_string(), reference]);
        let directory = Some((
            cas,
            declaration.definition.scope.as_str(),
            declaration.controller.pid,
            declaration.controller.start_ticks,
        ));
        for scope in root_scope_candidates(current, receipt.source_observation_id, directory)? {
            causal.insert(scope.source);
            refs.extend([
                scope.source.to_string(),
                scope.operation.to_string(),
                scope.effect.to_string(),
                scope.repository.to_string(),
                scope.worktree.to_string(),
            ]);
        }
    }
    let prefixes = causal
        .iter()
        .map(|id| format!("native-execution-directory:{id}:"))
        .collect::<Vec<_>>();
    for row in current
        .other_data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("worktree_snapshot"))
    {
        if std::time::Instant::now() >= deadline {
            return Err(AutoresearchError::SelectionDeferred);
        }
        let Some(json) = &row.payload_json else {
            continue;
        };
        if !prefixes.iter().any(|prefix| json.contains(prefix)) {
            continue;
        }
        let JournalPayload::WorktreeSnapshotRecorded(snapshot) =
            serde_json::from_str(json).map_err(|_| AutoresearchError::EvidenceIncomplete)?
        else {
            continue;
        };
        if snapshot
            .evidence_refs
            .iter()
            .any(|reference| prefixes.iter().any(|prefix| reference.starts_with(prefix)))
        {
            refs.insert(snapshot.worktree_snapshot_id.to_string());
        }
    }
    Ok(refs)
}

fn process_opening(
    current: &evertrace_store::CurrentFacts,
    source: SourceObservationId,
) -> Result<Option<(SourceObservationId, Box<ProcessWorkDeclaration>)>, AutoresearchError> {
    let Some((observation, _)) = current.source_observation(source) else {
        return Ok(None);
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(40);
    let mut found = None;
    for (receipt, _) in current.source_receipts() {
        if std::time::Instant::now() >= deadline {
            return Err(AutoresearchError::SelectionDeferred);
        }
        if receipt.source_instance_id != observation.source_instance_id
            || receipt.source_revision != observation.source_revision
            || receipt.source_sequence != 1
        {
            continue;
        }
        if let Some(SourceCandidate::WorkPlan(plan)) =
            source_candidate(current, receipt.source_observation_id)
        {
            if Some(plan.source_epoch.as_str())
                != observation.correlation.host_trace_lineage_id.as_deref()
            {
                continue;
            }
            if found.is_some() {
                return Err(AutoresearchError::EvidenceIncomplete);
            }
            found = Some((receipt.source_observation_id, plan));
        }
    }
    Ok(found)
}

/// Select the closed current input closure, never a second Work graph or the complete source snapshot.
pub(crate) fn controlled_source_snapshot(
    current: &evertrace_store::CurrentFacts,
    id: SourceObservationId,
    resolver: &ControlledRunResolver,
) -> Result<Option<ProjectionSnapshot>, AutoresearchError> {
    let Some(envelope) = source_candidate(current, id) else {
        return Ok(None);
    };
    let process_refs = match &envelope {
        SourceCandidate::WorkPlan(declaration) => {
            process_work_refs(current, id, declaration, &resolver.cas)?
        }
        SourceCandidate::Trial(trial) => {
            let Some((opening, declaration)) = process_opening(current, id)? else {
                return Ok(None);
            };
            if trial.study_key != declaration.study_key {
                return Ok(None);
            }
            let mut refs = process_work_refs(current, opening, &declaration, &resolver.cas)?;
            refs.insert(opening.to_string());
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(40);
            for row in current.other_data_rows() {
                if std::time::Instant::now() >= deadline {
                    return Err(AutoresearchError::SelectionDeferred);
                }
                if row.object_kind.as_deref() != Some("workstream") {
                    continue;
                }
                if let Some(JournalPayload::WorkstreamRecorded(stream)) = row
                    .payload_json
                    .as_deref()
                    .and_then(|json| serde_json::from_str(json).ok())
                    && stream.worktree_lineage_refs.contains(&opening.to_string())
                {
                    refs.insert(stream.workstream_id.to_string());
                    if let Some(episode) = stream.active_episode_id {
                        refs.insert(episode.to_string());
                    }
                }
            }
            refs
        }
        _ => BTreeSet::new(),
    };
    let mut root_refs = process_refs
        .iter()
        .filter(|value| value.starts_with("native-host-goal:"))
        .cloned()
        .collect::<BTreeSet<_>>();
    if let SourceCandidate::RootGoal { reference, .. } = &envelope {
        root_refs.insert(reference.clone());
    }
    let is_work_plan = matches!(
        &envelope,
        SourceCandidate::WorkPlan(_) | SourceCandidate::Trial(_)
    );
    let mut refs = BTreeSet::from([id.to_string()]);
    refs.extend(process_refs);
    match envelope {
        SourceCandidate::WorkPlan(_) | SourceCandidate::Trial(_) => {}
        SourceCandidate::RootGoal { reference, .. } => {
            refs.insert(reference);
        }
        SourceCandidate::Run(ControlledRunSourceEnvelope::Launch {
            attempt_id,
            procedure_revision_id,
            code_snapshot_id,
            binding,
            ..
        }) => {
            refs.insert(attempt_id.to_string());
            refs.insert(procedure_revision_id.to_string());
            refs.insert(code_snapshot_id.to_string());
            refs.extend(
                binding
                    .procedure_exposure_revision_id
                    .map(|id| id.to_string()),
            );
        }
        SourceCandidate::Run(ControlledRunSourceEnvelope::Terminal {
            run_id,
            artifact_refs,
            ..
        }) => {
            refs.insert(run_id.to_string());
            refs.extend(artifact_refs.into_iter().map(|id| id.to_string()));
        }
    }
    if matches!(
        source_candidate(current, id),
        Some(SourceCandidate::RootGoal { .. })
    ) {
        for scope in root_scope_candidates(current, id, None)? {
            refs.extend([
                scope.source.to_string(),
                scope.operation.to_string(),
                scope.effect.to_string(),
                scope.repository.to_string(),
                scope.worktree.to_string(),
            ]);
        }
    }
    let mut selected = BTreeSet::new();
    let mut rows = Vec::new();
    let mut bytes = 0_usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(40);
    loop {
        let before = selected.len();
        for reference in refs.clone() {
            if let Ok(observation) = reference.parse::<SourceObservationId>()
                && let Some((value, _)) = current.source_observation(observation)
            {
                refs.insert(value.source_receipt_ref.to_string());
                for kind in ["source_observation", "evidence_surface"] {
                    if let Some(row) = current.selected_source_row(kind, &reference)?
                        && selected.insert(row.row_id.clone())
                    {
                        bytes = bytes
                            .saturating_add(row.payload_json.as_ref().map_or(0, |json| json.len()));
                        rows.push(row);
                    }
                }
            }
            if reference.parse::<SourceReceiptId>().is_ok()
                && let Some(row) = current.selected_source_row("source_receipt", &reference)?
                && selected.insert(row.row_id.clone())
            {
                bytes =
                    bytes.saturating_add(row.payload_json.as_ref().map_or(0, |json| json.len()));
                rows.push(row);
            }
        }
        for row in current.other_data_rows() {
            if std::time::Instant::now() >= deadline {
                return Err(AutoresearchError::SelectionDeferred);
            }
            if rows.len() > 256 || bytes > 2 * 1024 * 1024 {
                return Err(AutoresearchError::EvidenceIncomplete);
            }
            if selected.contains(&row.row_id) {
                continue;
            }
            let direct = row.object_id.as_ref().is_some_and(|key| refs.contains(key))
                || row
                    .current_revision_id
                    .as_ref()
                    .is_some_and(|key| refs.contains(key));
            if !direct
                && !matches!(
                    row.object_kind.as_deref(),
                    Some(
                        "operation"
                            | "work_binding"
                            | "result_evidence"
                            | "procedure_usage_revision"
                    )
                )
                && !(!root_refs.is_empty() && row.object_kind.as_deref() == Some("task"))
                && !(is_work_plan
                    && matches!(row.object_kind.as_deref(), Some("workstream" | "attempt")))
            {
                continue;
            }
            let Some(json) = &row.payload_json else {
                continue;
            };
            let payload: JournalPayload = serde_json::from_str(json)
                .map_err(|_| AutoresearchError::Store(evertrace_store::StoreError::StoreCorrupt))?;
            let inverse = match &payload {
                JournalPayload::TaskRecorded(task) => task
                    .request_root_refs
                    .iter()
                    .any(|key| root_refs.contains(key)),
                JournalPayload::WorkstreamRecorded(workstream) if is_work_plan => {
                    workstream.worktree_lineage_refs.contains(&id.to_string())
                }
                JournalPayload::AttemptRecorded(attempt) if is_work_plan => {
                    refs.contains(&attempt.workstream_id.to_string())
                }
                JournalPayload::OperationDerived(operation) => operation
                    .input_source_observation_refs
                    .iter()
                    .chain(&operation.result_source_observation_refs)
                    .any(|source| refs.contains(&source.to_string())),
                JournalPayload::WorkBindingRecorded(binding) => {
                    refs.contains(&binding.operation_id.to_string())
                }
                JournalPayload::ResultEvidenceRecorded(result) => {
                    refs.contains(&result.experiment_run_id.to_string())
                }
                JournalPayload::ProcedureUsageRecorded(usage) => {
                    refs.contains(&usage.procedure_revision_id.to_string())
                        && usage
                            .attempt_ids
                            .iter()
                            .any(|attempt| refs.contains(&attempt.to_string()))
                }
                _ => false,
            };
            if !direct && !inverse {
                continue;
            }
            refs.extend(evertrace_store::projections::read_dependencies_for(
                row, &payload,
            ));
            refs.extend(row.object_id.iter().cloned());
            refs.extend(row.current_revision_id.iter().cloned());
            match &payload {
                JournalPayload::TaskRecorded(task) if !root_refs.is_empty() => {
                    refs.extend(
                        task.scope_memberships
                            .iter()
                            .filter_map(|scope| scope.repository_instance_id)
                            .map(|id| id.to_string()),
                    );
                }
                JournalPayload::WorkBindingRecorded(binding) => {
                    refs.extend(binding.predecessor_revision_id.map(|key| key.to_string()));
                }
                JournalPayload::AttemptRecorded(attempt) => {
                    refs.extend(
                        attempt
                            .strategy_contract
                            .search_policy_ref
                            .as_deref()
                            .and_then(|value| value.parse::<RevisionId>().ok())
                            .map(|id| id.to_string()),
                    );
                }
                _ => {}
            }
            bytes = bytes.saturating_add(json.len());
            selected.insert(row.row_id.clone());
            rows.push(row.clone());
        }
        if rows.len() > 256 || bytes > 2 * 1024 * 1024 {
            return Err(AutoresearchError::EvidenceIncomplete);
        }
        if selected.len() == before {
            return Ok(Some(ProjectionSnapshot {
                frontier: current.frontier(),
                rows,
            }));
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCreateInput {
    pub workstream_id: evertrace_domain::ids::WorkstreamId,
    pub source_receipt_refs: Vec<SourceReceiptId>,
    pub code_snapshot_id: evertrace_domain::ids::WorktreeSnapshotId,
    pub data_fingerprint: String,
    pub normalized_config: Vec<ContractField>,
    pub variable_declaration: VariableDeclaration,
    pub seed_policy: SeedPolicy,
    pub seed_values: Vec<String>,
    pub nondeterministic: bool,
    pub metric_definition: String,
    pub metric_extractor_version: String,
    pub multi_cas_metric_policy: MultiCasMetricPolicy,
    pub environment_fingerprint: String,
    pub created_at_us: i64,
}

pub fn create_experiment_run(
    attempt: &Attempt,
    mut input: RunCreateInput,
) -> Result<ExperimentRun, AutoresearchError> {
    if attempt.workstream_id != input.workstream_id {
        return Err(AutoresearchError::StrategyDriftRequiresNewAttempt);
    }
    input
        .normalized_config
        .sort_by(|left, right| left.name.cmp(&right.name));
    input.variable_declaration.varied.sort();
    input.variable_declaration.fixed.sort();
    input.variable_declaration.uncontrolled.sort();
    input.source_receipt_refs.sort();
    input.seed_values.sort();
    let mut run = ExperimentRun {
        run_id: evertrace_domain::ids::ExperimentRunId::new_v7(),
        revision_id: RevisionId::new_v7(),
        parent_revision_id: None,
        workstream_id: input.workstream_id,
        attempt_id: Some(attempt.attempt_id),
        attempt_binding_status: AttemptBindingStatus::Resolved,
        strategy_contract_fingerprint: attempt.strategy_contract_fingerprint,
        origin: RunOrigin::Local,
        external_system_id: None,
        external_run_key: None,
        source_receipt_refs: input.source_receipt_refs,
        observability: RunObservability::Declared,
        execution_status: RunExecutionStatus::Unknown,
        contract_validity: RunContractValidity::Unknown,
        experiment_contract_fingerprint: [0; 32],
        code_snapshot_id: input.code_snapshot_id,
        data_fingerprint: input.data_fingerprint,
        normalized_config: input.normalized_config,
        variable_declaration: input.variable_declaration,
        comparison_key: [0; 32],
        seed_policy: input.seed_policy,
        seed_values: input.seed_values,
        nondeterministic: input.nondeterministic,
        metric_definition: input.metric_definition,
        metric_extractor_version: input.metric_extractor_version,
        multi_cas_metric_policy: input.multi_cas_metric_policy,
        environment_fingerprint: input.environment_fingerprint,
        comparison_execution_binding: None,
        work_artifact_refs: Vec::new(),
        terminal_evidence_refs: Vec::new(),
        created_at_us: input.created_at_us,
        started_at_us: None,
        ended_at_us: None,
    };
    run.experiment_contract_fingerprint = run
        .recompute_exact_contract_fingerprint()
        .map_err(|_| AutoresearchError::InvalidInput)?;
    run.comparison_key = run
        .recompute_comparison_key()
        .map_err(|_| AutoresearchError::InvalidInput)?;
    run.validate()
        .map_err(|_| AutoresearchError::InvalidInput)?;
    Ok(run)
}

pub fn run_command(
    context: AutoresearchCommandContext,
    run: &ExperimentRun,
) -> Result<JournalCommand, AutoresearchError> {
    run.validate()
        .map_err(|_| AutoresearchError::InvalidInput)?;
    if !run.is_declaration_only() {
        return Err(AutoresearchError::UntrustedRunEvidence);
    }
    payload_command(
        context,
        vec![JournalPayload::ExperimentRunRecorded(Box::new(run.clone()))],
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunSourceRequest {
    Controlled {
        attempt_id: AttemptId,
        procedure_revision_id: RevisionId,
        source_observation_id: SourceObservationId,
    },
    SourceBound {
        source_observation_id: SourceObservationId,
    },
}

#[derive(Debug)]
pub enum ControlledRunCommand {
    NoDelta,
    WorkRoot {
        command: JournalCommand,
    },
    Declaration {
        run: Box<ExperimentRun>,
        bindings: Vec<WorkBindingRevision>,
        attempt: Option<Box<Attempt>>,
        command: JournalCommand,
    },
    Terminal {
        run: Box<ExperimentRun>,
        result: Box<ResultEvidence>,
        command: JournalCommand,
    },
}

#[derive(Clone, Debug)]
pub struct ControlledRunResolver {
    cas: CasStore,
}

impl ControlledRunResolver {
    pub const fn new(cas: CasStore) -> Self {
        Self { cas }
    }

    /// Source identity is the only dispatch input; write-protected fields still come from the original witness/resolver.
    pub(crate) fn resolve_source(
        &self,
        snapshot: &ProjectionSnapshot,
        source: SourceObservationId,
        context: &AutoresearchCommandContext,
        goal_key_dir: Option<&std::path::Path>,
    ) -> Result<
        (
            ControlledRunCommand,
            Option<crate::repository::SourcePolicy>,
        ),
        AutoresearchError,
    > {
        let facts = ControlledFacts::from_snapshot(snapshot)?;
        if facts.observations.get(&source).is_some_and(|value| {
            value.source_revision.as_str() == evertrace_capture::process_source::SOURCE_REVISION
        }) {
            let observation = facts
                .observations
                .get(&source)
                .ok_or(AutoresearchError::EvidenceIncomplete)?;
            if ProcessTrialDeclaration::decode(
                &self.protected_source(&facts, source)?,
                observation,
                facts.receipt(source)?,
            )
            .is_some()
            {
                return self.resolve_process_trial(snapshot, &facts, source, context, goal_key_dir);
            }
            return self.resolve_process_work(snapshot, &facts, source, context, goal_key_dir);
        }
        if facts.observations.get(&source).is_some_and(|value| {
            evertrace_capture::goal_source::is_source_revision(value.source_revision.as_str())
        }) {
            return self.resolve_root_goal(snapshot, &facts, source, context, goal_key_dir);
        }
        let Some(surface) = facts.surfaces.get(&source) else {
            return Ok((ControlledRunCommand::NoDelta, None));
        };
        let envelope =
            ControlledRunSourceEnvelope::decode_canonical(surface.protected_text.as_bytes())
                .map_err(|_| AutoresearchError::UntrustedRunEvidence)?;
        match envelope {
            ControlledRunSourceEnvelope::Launch {
                attempt_id,
                procedure_revision_id,
                ..
            } => self.declare(
                snapshot,
                RunSourceRequest::Controlled {
                    attempt_id,
                    procedure_revision_id,
                    source_observation_id: source,
                },
                context.clone(),
            ),
            ControlledRunSourceEnvelope::Terminal { run_id, .. } => {
                self.complete(snapshot, run_id, source, context.clone())
            }
        }
        .map(|command| (command, None))
    }

    fn protected_source(
        &self,
        facts: &ControlledFacts,
        source: SourceObservationId,
    ) -> Result<Vec<u8>, AutoresearchError> {
        let receipt = facts.receipt(source)?;
        let observation = facts
            .observations
            .get(&source)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let digest = CasDigest::from_str(&receipt.cas_ref).map_err(|_| AutoresearchError::Cas)?;
        let bytes = self
            .cas
            .read_bounded(&digest, 128 * 1024, 65536)
            .map_err(|_| AutoresearchError::Cas)?
            .0;
        if receipt.archive_mode != SourceArchiveMode::Exact
            || receipt.protected_secret_digest.is_some()
            || !receipt.redaction_spans.is_empty()
            || receipt.protected_length != bytes.len() as u64
            || receipt.source_observation_id != source
            || observation.source_receipt_ref != receipt.source_receipt_id
            || observation.source_instance_id != receipt.source_instance_id
            || observation.source_revision != receipt.source_revision
            || observation.source_record_identity != receipt.source_record_identity
            || observation.canonicalization_revision != receipt.canonicalization_revision
            || observation.payload_fingerprint
                != hex(
                    &payload_fingerprint(receipt.canonicalization_revision, &bytes, None)
                        .map_err(|_| AutoresearchError::UntrustedRunEvidence)?,
                )
        {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        if let Some(surface) = facts.surfaces.get(&source) {
            surface
                .validate()
                .map_err(|_| AutoresearchError::UntrustedRunEvidence)?;
            if surface.protected_text.as_bytes() != bytes
                || surface.source_role != observation.source_role
                || surface.content_trust != observation.content_trust
            {
                return Err(AutoresearchError::UntrustedRunEvidence);
            }
        } else if !evertrace_capture::execution_source::is_execution(observation, receipt) {
            return Err(AutoresearchError::EvidenceIncomplete);
        }
        Ok(bytes)
    }

    fn resolve_process_work(
        &self,
        snapshot: &ProjectionSnapshot,
        facts: &ControlledFacts,
        source: SourceObservationId,
        context: &AutoresearchCommandContext,
        key_dir: Option<&std::path::Path>,
    ) -> Result<
        (
            ControlledRunCommand,
            Option<crate::repository::SourcePolicy>,
        ),
        AutoresearchError,
    > {
        use evertrace_capture::{execution_source, goal_source, process_source};
        let receipt = facts.receipt(source)?;
        let observation = &facts.observations[&source];
        let bytes = self.protected_source(facts, source)?;
        let declaration = ProcessWorkDeclaration::decode(&bytes, receipt)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let manifest = evertrace_codex::probe::HostProbeReport::native_source_contract(
            &process_source::adapter_version(),
            process_source::ELIGIBLE_EVENTS,
            process_source::FORMAT,
        )
        .map_err(|_| AutoresearchError::UntrustedRunEvidence)?;
        if receipt.identity_domain != declaration.format
            || receipt.source_kind != evertrace_domain::evidence::EvidenceSourceKind::Other
            || receipt.unsupported_record_classification.is_some()
            || receipt.canonicalization_revision != 1
            || receipt.adapter_revision != process_source::ADAPTER_REVISION
            || receipt.adapter_manifest_ref != manifest.manifest().adapter_manifest_id
            || receipt.eligible_event_manifest_ref != process_source::ELIGIBLE_EVENTS
            || receipt.parser_revision != process_source::PARSER_REVISION
            || receipt.capture_completeness != CaptureCompleteness::Partial
            || observation.capture_completeness != CaptureCompleteness::Partial
            || observation.source_role != SourceRole::Tool
            || observation.content_trust != ContentTrust::UntrustedSourceContent
            || !observation.scope_effect_claims.is_empty()
        {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        let controller = &declaration.controller;
        let native_prefix = format!(
            "native-events:{}:{}:",
            controller.boot_id, controller.pid_namespace
        );
        let mut roots = BTreeMap::new();
        for (effect, _) in facts.scope_effects.values() {
            let Some(operation) = facts.operations.get(&effect.operation_id) else {
                continue;
            };
            if !operation.scope_effect_ids.contains(&effect.scope_effect_id) {
                continue;
            }
            for id in &operation.input_source_observation_refs {
                if !effect.evidence_refs.contains(id) {
                    continue;
                }
                let native = facts
                    .observations
                    .get(id)
                    .ok_or(AutoresearchError::EvidenceIncomplete)?;
                let native_receipt = facts.receipt(*id)?;
                if !native_receipt
                    .source_instance_id
                    .as_str()
                    .starts_with(&native_prefix)
                    || !execution_source::is_execution(native, native_receipt)
                {
                    continue;
                }
                let raw = self.protected_source(facts, *id)?;
                if execution_source::execution_directory(native, native_receipt, &raw)
                    != Some((
                        declaration.definition.scope.clone(),
                        controller.pid,
                        controller.start_ticks,
                    ))
                {
                    continue;
                }
                for goal in facts
                    .observations
                    .values()
                    .filter(|goal| goal_source::is_source_revision(goal.source_revision.as_str()))
                {
                    let goal_receipt = facts.receipt(goal.source_observation_id)?;
                    if goal_source::same_execution_context(goal_receipt, native_receipt) {
                        roots.insert(
                            (goal.source_observation_id, effect.scope_effect_id),
                            (*id, effect),
                        );
                    }
                }
            }
        }
        let mut verified = Vec::new();
        for ((goal_id, _), (native_id, effect)) in roots {
            let raw = self.protected_source(facts, goal_id)?;
            if goal_source::observed_goal(&raw)
                .ok()
                .flatten()
                .map(|(_, goal)| goal)
                != Some(declaration.definition.goal.clone())
            {
                continue;
            }
            match self.resolve_root_goal(snapshot, facts, goal_id, context, key_dir) {
                Ok((command, Some(policy))) => {
                    verified.push((command, policy, native_id, effect, goal_id))
                }
                Err(AutoresearchError::Store(error)) => {
                    return Err(AutoresearchError::Store(error));
                }
                _ => {}
            }
        }
        if verified.len() != 1 {
            return Ok((ControlledRunCommand::NoDelta, None));
        }
        let (command, policy, native, effect, goal) = verified
            .pop()
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        if !matches!(command, ControlledRunCommand::NoDelta) {
            return Ok((command, Some(policy)));
        }
        let goal_ref = &facts.receipt(goal)?.source_ref;
        let tasks = facts
            .tasks
            .values()
            .filter(|task| {
                task.request_root_refs.contains(goal_ref)
                    && task.canonical_goal == declaration.definition.goal
                    && task.identity_confidence
                        == evertrace_domain::work::TaskIdentityConfidence::Explicit
                    && task.lifecycle == evertrace_domain::work::TaskLifecycle::Active
            })
            .collect::<Vec<_>>();
        let [task] = tasks.as_slice() else {
            return Ok((ControlledRunCommand::NoDelta, Some(policy)));
        };
        let (Some(repository), Some(worktree)) =
            (effect.repository_instance_id, effect.worktree_instance_id)
        else {
            return Err(AutoresearchError::EvidenceIncomplete);
        };
        let mut anchors = Vec::new();
        for launch in facts.observations.values().filter(|value| {
            value.source_instance_id == observation.source_instance_id
                && value.source_revision == observation.source_revision
        }) {
            let launch_receipt = facts.receipt(launch.source_observation_id)?;
            let raw: serde_json::Value = serde_json::from_slice(
                &self.protected_source(facts, launch.source_observation_id)?,
            )
            .map_err(|_| AutoresearchError::EvidenceIncomplete)?;
            if raw["event"] != "trial_launch" || raw["study_key"] != declaration.study_key {
                continue;
            }
            let direct = format!(
                "native-execution-directory:{}:",
                launch.source_observation_id
            );
            let native = format!("native-execution-directory:{native}:");
            for anchor in facts.snapshots.values().filter(|anchor| {
                anchor.worktree_instance_id == worktree
                    && anchor.capture_status
                        == evertrace_domain::repository::SnapshotCaptureStatus::Complete
                    && anchor.head_oid.as_deref() == raw["source_anchor"]["commit"].as_str()
                    && anchor.tree_oid.as_deref() == raw["source_anchor"]["tree"].as_str()
                    && anchor
                        .evidence_refs
                        .iter()
                        .any(|value| value.starts_with(&direct) || value.starts_with(&native))
            }) {
                let inherited = !anchor
                    .evidence_refs
                    .iter()
                    .any(|value| value.starts_with(&direct));
                anchors.push((
                    launch_receipt.source_sequence,
                    inherited,
                    anchor.worktree_snapshot_id,
                ));
            }
        }
        anchors.sort();
        anchors.dedup();
        let Some((first, inherited, anchor)) = anchors.first().copied() else {
            return Ok((ControlledRunCommand::NoDelta, Some(policy)));
        };
        if anchors
            .iter()
            .filter(|(sequence, fallback, _)| *sequence == first && *fallback == inherited)
            .count()
            != 1
        {
            return Err(AutoresearchError::EvidenceIncomplete);
        }
        let anchor = ProcessWorkAnchor {
            repository,
            snapshot: facts
                .snapshots
                .get(&anchor)
                .ok_or(AutoresearchError::EvidenceIncomplete)?,
            session: &facts.receipt(native)?.source_session_ref,
            effect,
            root_source: native,
            goal_source: goal,
        };
        let command = process_work_command(
            snapshot,
            facts,
            source,
            task,
            &anchor,
            &declaration.definition,
            context,
        )?;
        Ok((
            command.map_or(ControlledRunCommand::NoDelta, |command| {
                ControlledRunCommand::WorkRoot { command }
            }),
            Some(policy),
        ))
    }

    fn resolve_process_trial(
        &self,
        snapshot: &ProjectionSnapshot,
        facts: &ControlledFacts,
        source: SourceObservationId,
        context: &AutoresearchCommandContext,
        key_dir: Option<&std::path::Path>,
    ) -> Result<
        (
            ControlledRunCommand,
            Option<crate::repository::SourcePolicy>,
        ),
        AutoresearchError,
    > {
        let opening = facts.process_opening(source)?;
        let (command, policy) = self.resolve_process_work(
            snapshot,
            facts,
            opening.source_observation_id,
            context,
            key_dir,
        )?;
        if !matches!(command, ControlledRunCommand::NoDelta) || policy.is_none() {
            return Ok((command, policy));
        }
        self.declare(
            snapshot,
            RunSourceRequest::SourceBound {
                source_observation_id: source,
            },
            context.clone(),
        )
        .map(|command| (command, policy))
    }

    fn declare_process_trial(
        &self,
        snapshot: &ProjectionSnapshot,
        source: SourceObservationId,
        context: &AutoresearchCommandContext,
    ) -> Result<ControlledRunCommand, AutoresearchError> {
        let facts = ControlledFacts::from_snapshot(snapshot)?;
        let observation = facts
            .observations
            .get(&source)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let opening_source = facts.process_opening(source)?.source_observation_id;
        let trial = ProcessTrialDeclaration::decode(
            &self.protected_source(&facts, source)?,
            observation,
            facts.receipt(source)?,
        )
        .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let plan = ProcessWorkDeclaration::decode(
            &self.protected_source(&facts, opening_source)?,
            facts.receipt(opening_source)?,
        )
        .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let Some((attempt, anchor)) =
            process_trial_target(&facts, &trial, &plan, source, opening_source)?
        else {
            return Ok(ControlledRunCommand::NoDelta);
        };
        let external_key = format!("{}/{}", trial.source_epoch, trial.execution_key);
        if facts.runs.runs.values().any(|run| {
            run.external_system_id.as_deref() == Some(evertrace_capture::process_source::FORMAT)
                && run.external_run_key.as_deref() == Some(external_key.as_str())
        }) {
            return Ok(ControlledRunCommand::NoDelta);
        }
        let mut input = process_trial_input(&trial, attempt, anchor, context.occurred_at_us)?;
        input.source_receipt_refs = vec![
            facts.receipt(source)?.source_receipt_id,
            facts.receipt(opening_source)?.source_receipt_id,
        ];
        let mut run = create_experiment_run(attempt, input)?;
        run.origin = RunOrigin::External;
        run.external_system_id = Some(evertrace_capture::process_source::FORMAT.into());
        run.external_run_key = Some(external_key);
        run.validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        let command = run_command(context.clone(), &run)?;
        Ok(ControlledRunCommand::Declaration {
            run: Box::new(run),
            bindings: Vec::new(),
            attempt: None,
            command,
        })
    }

    fn resolve_root_goal(
        &self,
        snapshot: &ProjectionSnapshot,
        facts: &ControlledFacts,
        source: SourceObservationId,
        context: &AutoresearchCommandContext,
        key_dir: Option<&std::path::Path>,
    ) -> Result<
        (
            ControlledRunCommand,
            Option<crate::repository::SourcePolicy>,
        ),
        AutoresearchError,
    > {
        use evertrace_capture::goal_source;
        let receipt = facts.receipt(source)?;
        let observation = facts
            .observations
            .get(&source)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let report = evertrace_codex::probe::HostProbeReport::unobserved_source_contract(
            &goal_source::adapter_version(receipt.source_revision.as_str())
                .map_err(|_| AutoresearchError::UntrustedRunEvidence)?,
            goal_source::ELIGIBLE_EVENTS,
        )
        .map_err(|_| AutoresearchError::UntrustedRunEvidence)?;
        if receipt.adapter_manifest_ref != report.manifest().adapter_manifest_id
            || receipt.adapter_revision != goal_source::ADAPTER_REVISION
            || receipt.eligible_event_manifest_ref != goal_source::ELIGIBLE_EVENTS
            || receipt.parser_revision != 1
            || receipt.canonicalization_revision != 1
            || receipt.source_observation_id != source
            || receipt.capture_completeness != CaptureCompleteness::Partial
            || observation.capture_completeness != CaptureCompleteness::Partial
            || receipt.unsupported_record_classification.is_some()
            || observation.source_role != SourceRole::Host
            || observation.content_trust != ContentTrust::Observed
            || !observation.scope_effect_claims.is_empty()
            || observation.source_local_evidence.is_some()
            || receipt.lifecycle.is_some()
            || receipt.task_id.is_some()
            || receipt.repository_instance_id.is_some()
            || receipt.worktree_instance_id.is_some()
        {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        let digest = CasDigest::from_str(&receipt.cas_ref).map_err(|_| AutoresearchError::Cas)?;
        let (bytes, _) = self
            .cas
            .read_bounded(&digest, 128 * 1024, 128 * 1024)
            .map_err(|_| AutoresearchError::Cas)?;
        if receipt.protected_length != bytes.len() as u64 {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        let key = evertrace_capture::DeviceKeyStore::new(
            key_dir.ok_or(AutoresearchError::EvidenceIncomplete)?,
        )
        .load()
        .map_err(|_| AutoresearchError::EvidenceIncomplete)?;
        let root = goal_source::revalidate(receipt, observation, &bytes, &key)
            .map_err(|_| AutoresearchError::UntrustedRunEvidence)?;
        let policy = crate::repository::SourcePolicy::from_goal(&root);
        let source_ref = source.to_string();
        let watermark = snapshot
            .rows
            .iter()
            .find(|row| {
                row.object_kind.as_deref() == Some("source_observation")
                    && row.object_id.as_deref() == Some(source_ref.as_str())
            })
            .map(|row| row.source_event_seq)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let mut memberships = BTreeMap::<_, BTreeSet<_>>::new();
        let mut scope_watermark = snapshot
            .data_rows()
            .filter(|row| row.object_kind.as_deref() == Some("task"))
            .map(|row| row.source_event_seq)
            .fold(watermark, u64::max);
        for (effect, sequence) in facts.scope_effects.values() {
            let Some(operation) = facts.operations.get(&effect.operation_id) else {
                continue;
            };
            if !operation.scope_effect_ids.contains(&effect.scope_effect_id) {
                continue;
            }
            let linked = operation
                .input_source_observation_refs
                .iter()
                .chain(&operation.result_source_observation_refs)
                .filter(|id| effect.evidence_refs.contains(id));
            let mut witnessed = false;
            for id in linked {
                let Some(observation) = facts.observations.get(id) else {
                    continue;
                };
                let receipt = facts.receipt(*id)?;
                witnessed |= root.matches_execution(receipt)
                    && evertrace_capture::execution_source::is_execution(observation, receipt);
            }
            if !witnessed {
                continue;
            }
            let (Some(repository), Some(worktree)) =
                (effect.repository_instance_id, effect.worktree_instance_id)
            else {
                continue;
            };
            if effect.effect_role != evertrace_domain::evidence::EffectRole::Observe
                || facts
                    .worktrees
                    .get(&worktree)
                    .is_none_or(|tree| tree.repository_instance_id != repository)
            {
                return Err(AutoresearchError::UntrustedRunEvidence);
            }
            memberships.entry(repository).or_default().insert(worktree);
            scope_watermark = scope_watermark.max(*sequence);
        }
        let memberships = memberships
            .into_iter()
            .map(
                |(repository, worktrees)| evertrace_domain::work::TaskScopeMembership {
                    repository_instance_id: Some(repository),
                    worktree_instance_ids: worktrees.into_iter().collect(),
                },
            )
            .collect();
        let command = crate::work::binding::source_root_task(
            crate::work::WorkCommandContext {
                command_id: context.command_id,
                occurred_at_us: context.occurred_at_us,
                effective_config_hash: context.effective_config_hash,
                algorithm_revision: context.algorithm_revision,
            },
            &facts.tasks,
            &root,
            source,
            memberships,
            scope_watermark,
        )
        .map_err(|_| AutoresearchError::ImmutableConflict)?;
        Ok((
            command.map_or(ControlledRunCommand::NoDelta, |command| {
                ControlledRunCommand::WorkRoot { command }
            }),
            policy,
        ))
    }

    pub fn declare(
        &self,
        snapshot: &ProjectionSnapshot,
        request: RunSourceRequest,
        context: AutoresearchCommandContext,
    ) -> Result<ControlledRunCommand, AutoresearchError> {
        let (requested_attempt, requested_procedure, source_observation_id) = match request {
            RunSourceRequest::Controlled {
                attempt_id,
                procedure_revision_id,
                source_observation_id,
            } => (attempt_id, procedure_revision_id, source_observation_id),
            RunSourceRequest::SourceBound {
                source_observation_id,
            } => return self.declare_process_trial(snapshot, source_observation_id, &context),
        };
        let facts = ControlledFacts::from_snapshot(snapshot)?;
        let Some(attempt) = facts.attempts.get(&requested_attempt) else {
            return Ok(ControlledRunCommand::NoDelta);
        };
        if facts
            .procedures
            .get(&requested_procedure)
            .is_none_or(|procedure| {
                facts.current_procedures.get(&procedure.procedure_id)
                    != Some(&procedure.revision_id)
            })
        {
            return Ok(ControlledRunCommand::NoDelta);
        }
        let envelope = match self.witness(&facts, source_observation_id) {
            Ok(value) => value,
            Err(AutoresearchError::EvidenceIncomplete | AutoresearchError::Cas) => {
                return Ok(ControlledRunCommand::NoDelta);
            }
            Err(error) => return Err(error),
        };
        let ControlledRunSourceEnvelope::Launch {
            attempt_id,
            procedure_revision_id,
            code_snapshot_id,
            data_fingerprint,
            normalized_config,
            variable_declaration,
            seed_policy,
            seed_values,
            nondeterministic,
            metric_definition,
            metric_extractor_version,
            multi_cas_metric_policy,
            environment_fingerprint,
            binding,
            started_at_us,
            ..
        } = envelope
        else {
            return Err(AutoresearchError::UntrustedRunEvidence);
        };
        if attempt_id != requested_attempt
            || procedure_revision_id != requested_procedure
            || attempt.strategy_contract.search_policy_ref.as_deref()
                != Some(procedure_revision_id.to_string()).as_deref()
            || binding
                .procedure_exposure_revision_id
                .is_some_and(|value| value != procedure_revision_id)
            || facts
                .snapshots
                .get(&code_snapshot_id)
                .and_then(|snapshot| snapshot.toolchain_fingerprint.as_deref())
                != Some(binding.toolchain_revision.as_str())
        {
            return Err(AutoresearchError::ImmutableConflict);
        }
        match facts.validate_declaration_anchor(requested_procedure, attempt, code_snapshot_id) {
            Ok(()) => {}
            Err(AutoresearchError::EvidenceIncomplete) => {
                return Ok(ControlledRunCommand::NoDelta);
            }
            Err(error) => return Err(error),
        }
        let (run_id, binding_successors) = match exact_bound_run(
            &facts,
            source_observation_id,
            attempt.attempt_id,
            attempt.workstream_id,
        ) {
            Ok(value) => value,
            Err(AutoresearchError::EvidenceIncomplete) => {
                return Ok(ControlledRunCommand::NoDelta);
            }
            Err(error) => return Err(error),
        };
        if let Some(existing) = facts.runs.runs.get(&run_id) {
            return if existing.source_receipt_refs
                == vec![facts.receipt(source_observation_id)?.source_receipt_id]
            {
                Ok(ControlledRunCommand::NoDelta)
            } else {
                Err(AutoresearchError::ImmutableConflict)
            };
        }
        let receipt_id = facts.receipt(source_observation_id)?.source_receipt_id;
        let mut run = ExperimentRun {
            run_id,
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            workstream_id: attempt.workstream_id,
            attempt_id: Some(attempt.attempt_id),
            attempt_binding_status: AttemptBindingStatus::Resolved,
            strategy_contract_fingerprint: attempt.strategy_contract_fingerprint,
            origin: RunOrigin::Local,
            external_system_id: None,
            external_run_key: None,
            source_receipt_refs: vec![receipt_id],
            observability: RunObservability::Declared,
            execution_status: RunExecutionStatus::Unknown,
            contract_validity: RunContractValidity::Unknown,
            experiment_contract_fingerprint: [0; 32],
            code_snapshot_id,
            data_fingerprint,
            normalized_config,
            variable_declaration,
            comparison_key: [0; 32],
            seed_policy,
            seed_values,
            nondeterministic,
            metric_definition,
            metric_extractor_version,
            multi_cas_metric_policy,
            environment_fingerprint,
            comparison_execution_binding: Some(*binding),
            work_artifact_refs: Vec::new(),
            terminal_evidence_refs: Vec::new(),
            created_at_us: context.occurred_at_us.min(started_at_us),
            started_at_us: Some(started_at_us),
            ended_at_us: None,
        };
        run.experiment_contract_fingerprint = run
            .recompute_exact_contract_fingerprint()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        run.comparison_key = run
            .recompute_comparison_key()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        run.validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        let mut payloads = vec![JournalPayload::ExperimentRunRecorded(Box::new(run.clone()))];
        let mut attempt_successor = None;
        if !binding_successors.is_empty() {
            payloads.extend(
                binding_successors
                    .iter()
                    .cloned()
                    .map(|binding| JournalPayload::WorkBindingRecorded(Box::new(binding))),
            );
            let mut next_attempt = attempt.clone();
            next_attempt.revision_id = RevisionId::new_v7();
            next_attempt.predecessor_revision_id = Some(attempt.revision_id);
            next_attempt.revision_generation = attempt.revision_generation.saturating_add(1);
            next_attempt.work_binding_revision_refs.extend(
                binding_successors
                    .iter()
                    .map(|binding| binding.work_binding_revision_id),
            );
            next_attempt.work_binding_revision_refs.sort();
            next_attempt.work_binding_revision_refs.dedup();
            next_attempt.source_watermark = next_attempt.source_watermark.saturating_add(1);
            attempt
                .validate_successor(&next_attempt)
                .map_err(|_| AutoresearchError::ImmutableConflict)?;
            payloads.push(JournalPayload::AttemptRecorded(Box::new(
                next_attempt.clone(),
            )));
            attempt_successor = Some(next_attempt);
        }
        let command = payload_command(context, payloads)?;
        Ok(ControlledRunCommand::Declaration {
            run: Box::new(run),
            bindings: binding_successors,
            attempt: attempt_successor.map(Box::new),
            command,
        })
    }

    pub fn complete(
        &self,
        snapshot: &ProjectionSnapshot,
        run_id: evertrace_domain::ids::ExperimentRunId,
        terminal_observation_id: SourceObservationId,
        context: AutoresearchCommandContext,
    ) -> Result<ControlledRunCommand, AutoresearchError> {
        let facts = ControlledFacts::from_snapshot(snapshot)?;
        let Some(current) = facts.runs.runs.get(&run_id) else {
            return Ok(ControlledRunCommand::NoDelta);
        };
        if current.comparison_execution_binding.is_none() {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        if !current.is_controlled_declaration() {
            return Ok(ControlledRunCommand::NoDelta);
        }
        let envelope = match self.witness(&facts, terminal_observation_id) {
            Ok(value) => value,
            Err(AutoresearchError::EvidenceIncomplete | AutoresearchError::Cas) => {
                return Ok(ControlledRunCommand::NoDelta);
            }
            Err(error) => return Err(error),
        };
        let ControlledRunSourceEnvelope::Terminal {
            run_id: observed_run_id,
            ended_at_us,
            metric,
            artifact_refs,
            ..
        } = envelope
        else {
            return Err(AutoresearchError::UntrustedRunEvidence);
        };
        if observed_run_id != run_id {
            return Err(AutoresearchError::ImmutableConflict);
        }
        let Some(attempt) = facts.attempts.get(
            &current
                .attempt_id
                .ok_or(AutoresearchError::ImmutableConflict)?,
        ) else {
            return Ok(ControlledRunCommand::NoDelta);
        };
        let Some(target_revision_id) = attempt
            .strategy_contract
            .search_policy_ref
            .as_deref()
            .and_then(|value| value.parse::<RevisionId>().ok())
        else {
            return Err(AutoresearchError::ImmutableConflict);
        };
        if !facts.procedures.contains_key(&target_revision_id) {
            return Err(AutoresearchError::ImmutableConflict);
        }
        match require_bound_operations(
            &facts,
            terminal_observation_id,
            false,
            run_id,
            attempt.attempt_id,
            current.workstream_id,
        ) {
            Ok(()) => {}
            Err(AutoresearchError::EvidenceIncomplete) => {
                return Ok(ControlledRunCommand::NoDelta);
            }
            Err(error) => return Err(error),
        }
        if artifact_refs
            .iter()
            .any(|id| !facts.runs.artifacts.contains_key(id))
        {
            return Ok(ControlledRunCommand::NoDelta);
        }
        let receipt = facts.receipt(terminal_observation_id)?;
        let mut next = current.clone();
        next.revision_id = RevisionId::new_v7();
        next.parent_revision_id = Some(current.revision_id);
        next.observability = RunObservability::Full;
        next.execution_status = RunExecutionStatus::Completed;
        next.contract_validity = RunContractValidity::Valid;
        next.work_artifact_refs = artifact_refs.clone();
        next.terminal_evidence_refs = vec![receipt.source_receipt_id];
        next.ended_at_us = Some(ended_at_us);
        next.created_at_us = current.created_at_us;
        current
            .validate_successor(&next)
            .map_err(|_| AutoresearchError::ImmutableConflict)?;
        let cas = CasId::from_digest(
            *CasDigest::from_str(&receipt.cas_ref)
                .map_err(|_| AutoresearchError::Cas)?
                .as_bytes(),
        );
        let result = ResultEvidence {
            result_evidence_id: ResultEvidenceId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            experiment_run_id: run_id,
            experiment_run_revision_id: next.revision_id,
            result_scope: ResultScope::Complete,
            raw_artifact_refs: artifact_refs.clone(),
            raw_cas_refs: vec![cas],
            parsed_metric: Some(metric),
            parser_receipt: ParserReceipt {
                parser_version: RESULT_PARSER_VERSION.into(),
                status: ParserStatus::Parsed,
                failure_code: None,
                input_artifact_refs: artifact_refs,
                input_cas_refs: vec![cas],
            },
            verifier_receipt: Some(VerifierReceipt {
                verifier_version: RESULT_VERIFIER_VERSION.into(),
                status: VerifierStatus::Passed,
                failure_code: None,
            }),
            completeness: EvidenceCompleteness::Complete,
            failure: None,
            created_at_us: context.occurred_at_us,
        };
        result
            .validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        let command = payload_command(
            context,
            vec![
                JournalPayload::ExperimentRunRecorded(Box::new(next.clone())),
                JournalPayload::ResultEvidenceRecorded(Box::new(result.clone())),
            ],
        )?;
        Ok(ControlledRunCommand::Terminal {
            run: Box::new(next),
            result: Box::new(result),
            command,
        })
    }

    fn witness(
        &self,
        facts: &ControlledFacts,
        observation_id: SourceObservationId,
    ) -> Result<ControlledRunSourceEnvelope, AutoresearchError> {
        let receipt = facts.receipt(observation_id)?;
        let observation = facts
            .observations
            .get(&observation_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let surface = facts
            .surfaces
            .get(&observation_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let bytes = read_cas(
            &self.cas,
            &CasId::from_digest(
                *CasDigest::from_str(&receipt.cas_ref)
                    .map_err(|_| AutoresearchError::Cas)?
                    .as_bytes(),
            ),
        )?;
        surface
            .validate()
            .map_err(|_| AutoresearchError::UntrustedRunEvidence)?;
        if bytes != surface.protected_text.as_bytes()
            || receipt.source_observation_id != observation_id
            || receipt.capture_completeness != CaptureCompleteness::Complete
            || observation.capture_completeness != CaptureCompleteness::Complete
            || surface.capture_completeness != CaptureCompleteness::Complete
            || receipt.archive_mode != SourceArchiveMode::Exact
            || receipt.unsupported_record_classification.is_some()
            || receipt.protected_secret_digest.is_some()
            || !receipt.redaction_spans.is_empty()
            || observation.source_receipt_ref != receipt.source_receipt_id
            || receipt.canonicalization_revision != surface.canonicalization_version
            || observation.canonicalization_revision != surface.canonicalization_version
            || observation.source_role != surface.source_role
            || observation.content_trust != surface.content_trust
            || !matches!(surface.source_role, SourceRole::Host | SourceRole::Tool)
            || surface.content_trust != ContentTrust::Observed
            || receipt.cas_ref != CasDigest::for_protected_bytes(&bytes).to_string()
            || observation.payload_fingerprint
                != hex(
                    &payload_fingerprint(surface.canonicalization_version, &bytes, None)
                        .map_err(|_| AutoresearchError::UntrustedRunEvidence)?,
                )
        {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        ControlledRunSourceEnvelope::decode_canonical(&bytes)
            .map_err(|_| AutoresearchError::UntrustedRunEvidence)
    }
}

fn process_trial_target<'a>(
    facts: &'a ControlledFacts,
    trial: &ProcessTrialDeclaration,
    plan: &ProcessWorkDeclaration,
    source: SourceObservationId,
    opening: SourceObservationId,
) -> Result<Option<(&'a Attempt, &'a WorktreeSnapshot)>, AutoresearchError> {
    if trial.study_key != plan.study_key || trial.source_epoch != plan.source_epoch {
        return Err(AutoresearchError::UntrustedRunEvidence);
    }
    let reference = opening.to_string();
    let mut streams = facts
        .workstreams
        .values()
        .filter(|value| value.worktree_lineage_refs.contains(&reference));
    let Some(stream) = streams.next() else {
        return Ok(None);
    };
    if streams.next().is_some() {
        return Err(AutoresearchError::EvidenceIncomplete);
    }
    if stream.status != evertrace_domain::work::workstream::WorkstreamStatus::Active
        || stream.phase_contract != plan.definition.phase
    {
        return Ok(None);
    }
    let Some(episode) = stream
        .active_episode_id
        .and_then(|id| facts.current_episodes.get(&id))
        .and_then(|revision| facts.episodes.get(revision))
    else {
        return Ok(None);
    };
    if episode.workstream_id != stream.workstream_id
        || episode.phase_contract != plan.definition.phase
    {
        return Err(AutoresearchError::ImmutableConflict);
    }
    let roots = facts
        .bindings
        .values()
        .filter(|binding| {
            binding.assignment_status == AssignmentStatus::Resolved
                && binding.primary_binding.workstream_id == Some(stream.workstream_id)
                && binding.primary_binding.task_id == Some(stream.task_id)
                && binding.evidence_refs.contains(&reference)
        })
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return Ok(None);
    }
    let mut attempts = facts.attempts.values().filter(|attempt| {
        attempt.workstream_id == stream.workstream_id
            && attempt.episode_id == Some(episode.episode_id)
            && episode.attempt_ids.contains(&attempt.attempt_id)
            && attempt.strategy_contract == plan.definition.strategy
    });
    let Some(attempt) = attempts.next() else {
        return Ok(None);
    };
    if attempts.next().is_some() {
        return Err(AutoresearchError::EvidenceIncomplete);
    }
    let mut prefixes = vec![format!("native-execution-directory:{source}:")];
    for binding in roots {
        prefixes.extend(
            binding
                .evidence_refs
                .iter()
                .map(|value| format!("native-execution-directory:{value}:")),
        );
    }
    let snapshots = facts
        .snapshots
        .values()
        .filter(|snapshot| {
            snapshot.capture_status == evertrace_domain::repository::SnapshotCaptureStatus::Complete
                && snapshot
                    .evidence_refs
                    .iter()
                    .any(|value| prefixes.iter().any(|prefix| value.starts_with(prefix)))
                && snapshot.head_oid.as_deref() == Some(trial.source_anchor.commit.as_str())
                && snapshot.tree_oid.as_deref() == Some(trial.source_anchor.tree.as_str())
                && facts
                    .worktrees
                    .get(&snapshot.worktree_instance_id)
                    .is_some_and(|worktree| {
                        Some(worktree.repository_instance_id) == stream.repository_instance_id
                            && stream
                                .worktree_instance_ids
                                .contains(&worktree.worktree_instance_id)
                    })
        })
        .collect::<Vec<_>>();
    let direct = format!("native-execution-directory:{source}:");
    let exact = snapshots
        .iter()
        .copied()
        .filter(|snapshot| {
            snapshot
                .evidence_refs
                .iter()
                .any(|reference| reference.starts_with(&direct))
        })
        .collect::<Vec<_>>();
    let candidates = if exact.is_empty() { &snapshots } else { &exact };
    let Some(snapshot) = candidates.first().copied() else {
        return Ok(None);
    };
    if candidates.len() != 1 {
        return Err(AutoresearchError::EvidenceIncomplete);
    }
    Ok(Some((attempt, snapshot)))
}

fn process_trial_input(
    trial: &ProcessTrialDeclaration,
    attempt: &Attempt,
    snapshot: &WorktreeSnapshot,
    created_at_us: i64,
) -> Result<RunCreateInput, AutoresearchError> {
    let value = &trial.config;
    let text = |name| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(AutoresearchError::EvidenceIncomplete)
    };
    let selected = text("selected")?;
    let implementation = text("implementation")?;
    let framework = text("framework")?;
    let framework_version = text("framework_version")?;
    let python = text("python")?;
    let environment = value
        .get("environment")
        .and_then(serde_json::Value::as_object)
        .ok_or(AutoresearchError::EvidenceIncomplete)?;
    let timeout = value
        .get("timeout_seconds")
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(AutoresearchError::EvidenceIncomplete)?;
    if selected != "fixed_scorer.py::TestTaskEval"
        || framework != "pytest"
        || value.get("uses_model") != Some(&serde_json::Value::Bool(false))
        || value.get("uses_randomness") != Some(&serde_json::Value::Bool(false))
        || environment.len() != 5
        || trial.source_anchor.scorer_blob.len() != 40
        || !trial
            .source_anchor
            .scorer_blob
            .bytes()
            .all(|value| value.is_ascii_hexdigit())
    {
        return Err(AutoresearchError::EvidenceIncomplete);
    }
    // These are the source's declared conditions, not an immutable runtime qualification.
    let environment_fingerprint = serde_json::to_string(&serde_json::json!({"environment":environment,
        "framework":framework,"framework_version":framework_version,"python":python,"uses_model":false}))
        .map_err(|_| AutoresearchError::InvalidInput)?;
    Ok(RunCreateInput {
        workstream_id: attempt.workstream_id,
        source_receipt_refs: Vec::new(),
        code_snapshot_id: snapshot.worktree_snapshot_id,
        data_fingerprint: format!("declared-git-blob:{}", trial.source_anchor.scorer_blob),
        normalized_config: vec![
            ContractField {
                name: "selected".into(),
                value: selected.into(),
            },
            ContractField {
                name: "implementation".into(),
                value: implementation.into(),
            },
            ContractField {
                name: "timeout_seconds".into(),
                value: timeout.to_string(),
            },
        ],
        variable_declaration: VariableDeclaration {
            varied: vec!["implementation".into()],
            fixed: vec!["selected".into(), "timeout_seconds".into()],
            uncontrolled: Vec::new(),
        },
        seed_policy: SeedPolicy::Unspecified,
        seed_values: Vec::new(),
        nondeterministic: false,
        metric_definition: "TestTaskEval passed tests".into(),
        metric_extractor_version: "pytest-junit-xunit2".into(),
        multi_cas_metric_policy: MultiCasMetricPolicy::RejectMultipleParsed,
        environment_fingerprint,
        created_at_us,
    })
}

struct ProcessWorkAnchor<'a> {
    repository: evertrace_domain::ids::RepositoryId,
    snapshot: &'a WorktreeSnapshot,
    session: &'a str,
    effect: &'a evertrace_domain::evidence::ScopeEffect,
    root_source: SourceObservationId,
    goal_source: SourceObservationId,
}

fn process_work_command(
    snapshot: &ProjectionSnapshot,
    facts: &ControlledFacts,
    source: SourceObservationId,
    task: &Task,
    anchor: &ProcessWorkAnchor<'_>,
    plan: &ProcessWorkPlan,
    context: &AutoresearchCommandContext,
) -> Result<Option<JournalCommand>, AutoresearchError> {
    use crate::work::{WorkCommandContext, attempt, episode, workstream};
    let context = WorkCommandContext {
        command_id: context.command_id,
        occurred_at_us: context.occurred_at_us,
        effective_config_hash: context.effective_config_hash,
        algorithm_revision: context.algorithm_revision,
    };
    let repository = anchor.repository;
    let worktree = anchor.snapshot.worktree_instance_id;
    let source_ref = source.to_string();
    let streams = facts
        .workstreams
        .values()
        .filter(|stream| stream.worktree_lineage_refs.contains(&source_ref))
        .collect::<Vec<_>>();
    let map_error = |_| AutoresearchError::ImmutableConflict;
    if let [stream] = streams.as_slice() {
        if stream.task_id != task.task_id
            || stream.repository_instance_id != Some(repository)
            || stream.worktree_instance_ids != [worktree]
            || stream.phase_contract != plan.phase
        {
            return Err(AutoresearchError::ImmutableConflict);
        }
        if stream.status.is_terminal() {
            return Ok(None);
        }
        if stream.active_episode_id.is_some() {
            let view = evertrace_store::WorkIdentityCurrentView::from_snapshot(snapshot)?;
            let sources = vec![
                source.to_string(),
                anchor.root_source.to_string(),
                anchor.goal_source.to_string(),
            ];
            let binding = crate::work::binding::source_root_workstream(
                &view,
                stream,
                anchor.effect.operation_id,
                anchor.effect.scope_effect_id,
                facts.bindings.get(&anchor.effect.operation_id),
                &sources,
            )
            .map_err(map_error)?
            .into_revision();
            return binding
                .map(|binding| {
                    crate::work::binding::record_binding(context, binding).map_err(map_error)
                })
                .transpose();
        }
        let attempts = facts
            .attempts
            .values()
            .filter(|attempt| {
                attempt.workstream_id == stream.workstream_id
                    && attempt.episode_id.is_none()
                    && attempt.strategy_contract == plan.strategy
            })
            .collect::<Vec<_>>();
        let [attempt] = attempts.as_slice() else {
            return Err(AutoresearchError::EvidenceIncomplete);
        };
        let mut episode = episode::new_episode(
            stream,
            Some(anchor.snapshot.worktree_snapshot_id),
            snapshot.frontier,
        )
        .map_err(map_error)?;
        episode.session_ids = vec![anchor.session.to_owned()];
        let linked = episode::link_attempt_to_episode(attempt, &episode, snapshot.frontier)
            .map_err(map_error)?;
        episode.attempt_ids.push(linked.attempt_id);
        return episode::activate_episode(context, stream, episode, vec![linked], vec![])
            .map(Some)
            .map_err(map_error);
    }
    if !streams.is_empty() {
        return Err(AutoresearchError::ImmutableConflict);
    }
    let stream = Workstream {
        workstream_id: evertrace_domain::ids::WorkstreamId::new_v7(),
        revision_id: RevisionId::new_v7(),
        predecessor_revision_id: None,
        task_id: task.task_id,
        repository_instance_id: Some(repository),
        worktree_instance_ids: vec![worktree],
        active_worktree_instance_id: Some(worktree),
        worktree_lineage_refs: vec![source_ref],
        parent_workstream_id: None,
        dependency_workstream_ids: vec![],
        status: evertrace_domain::work::WorkstreamStatus::Active,
        root_goal: task.canonical_goal.clone(),
        workstream_goal: plan.phase.local_goal.clone(),
        target_family: plan.phase.primary_targets.join(";"),
        hypothesis_or_failure_family: plan.strategy.intervention_family.clone(),
        acceptance_boundary: plan.phase.acceptance_boundary.clone(),
        phase_contract: plan.phase.clone(),
        active_episode_id: None,
        execution_lane_ids: vec![],
        source_watermark: snapshot.frontier,
    };
    let attempt = attempt::new_attempt(
        task.task_id,
        stream.workstream_id,
        Some(repository),
        vec![worktree],
        vec![],
        plan.strategy.clone(),
        snapshot.frontier,
    )
    .map_err(map_error)?;
    let repositories = evertrace_store::repository::RepositoryCurrentView::from_snapshot(snapshot)
        .map_err(AutoresearchError::Store)?;
    let declaration =
        workstream::create_workstream(context, task, &repositories, stream).map_err(map_error)?;
    let attempt = attempt::create_attempt(context, attempt).map_err(map_error)?;
    JournalCommand::new(
        context.command_id,
        declaration
            .events()
            .iter()
            .chain(attempt.events())
            .cloned()
            .collect(),
    )
    .map(Some)
    .map_err(AutoresearchError::Store)
}

struct ControlledFacts {
    runs: AutoresearchCurrentView,
    attempts: std::collections::BTreeMap<AttemptId, Attempt>,
    procedures: std::collections::BTreeMap<RevisionId, ProcedureRevision>,
    current_procedures: std::collections::BTreeMap<evertrace_domain::ids::ProcedureId, RevisionId>,
    usages:
        std::collections::BTreeMap<evertrace_domain::ids::ProcedureUsageId, ProcedureUsageRevision>,
    tasks: std::collections::BTreeMap<evertrace_domain::ids::TaskId, Task>,
    workstreams: std::collections::BTreeMap<evertrace_domain::ids::WorkstreamId, Workstream>,
    episodes: std::collections::BTreeMap<RevisionId, WorkEpisode>,
    current_episodes: std::collections::BTreeMap<evertrace_domain::ids::WorkEpisodeId, RevisionId>,
    worktrees: std::collections::BTreeMap<evertrace_domain::ids::WorktreeId, WorktreeInstance>,
    snapshots:
        std::collections::BTreeMap<evertrace_domain::ids::WorktreeSnapshotId, WorktreeSnapshot>,
    receipts: std::collections::BTreeMap<SourceReceiptId, SourceReceipt>,
    observations: std::collections::BTreeMap<SourceObservationId, SourceObservation>,
    surfaces: std::collections::BTreeMap<SourceObservationId, EvidenceSurface>,
    operations: std::collections::BTreeMap<OperationId, Operation>,
    scope_effects: BTreeMap<
        evertrace_domain::ids::ScopeEffectId,
        (evertrace_domain::evidence::ScopeEffect, u64),
    >,
    bindings: std::collections::BTreeMap<OperationId, WorkBindingRevision>,
}

impl ControlledFacts {
    fn process_opening(
        &self,
        source: SourceObservationId,
    ) -> Result<&SourceObservation, AutoresearchError> {
        let observation = self
            .observations
            .get(&source)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let mut openings = self
            .receipts
            .values()
            .filter(|receipt| {
                receipt.source_instance_id == observation.source_instance_id
                    && receipt.source_revision == observation.source_revision
                    && receipt.source_sequence == 1
            })
            .filter_map(|receipt| self.observations.get(&receipt.source_observation_id));
        let opening = openings
            .next()
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        if openings.next().is_some() {
            return Err(AutoresearchError::EvidenceIncomplete);
        }
        Ok(opening)
    }

    fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, AutoresearchError> {
        let mut facts = Self {
            runs: AutoresearchCurrentView::from_snapshot(snapshot)
                .map_err(AutoresearchError::Store)?,
            attempts: Default::default(),
            procedures: Default::default(),
            current_procedures: Default::default(),
            usages: Default::default(),
            tasks: Default::default(),
            workstreams: Default::default(),
            episodes: Default::default(),
            current_episodes: Default::default(),
            worktrees: Default::default(),
            snapshots: Default::default(),
            receipts: Default::default(),
            observations: Default::default(),
            surfaces: Default::default(),
            operations: Default::default(),
            scope_effects: Default::default(),
            bindings: Default::default(),
        };
        let mut attempt_seq = std::collections::BTreeMap::new();
        let mut procedure_seq = std::collections::BTreeMap::new();
        let mut episode_seq = std::collections::BTreeMap::new();
        let mut task_seq = std::collections::BTreeMap::new();
        let mut workstream_seq = std::collections::BTreeMap::new();
        let mut worktree_seq = std::collections::BTreeMap::new();
        let mut usage_seq = std::collections::BTreeMap::new();
        // Background projections also carry derived summaries, which are not
        // JournalPayload envelopes. Read only this resolver's concrete inputs.
        for row in snapshot.data_rows().filter(|row| {
            matches!(
                row.object_kind.as_deref(),
                Some(
                    "attempt"
                        | "procedure_revision"
                        | "procedure_usage_revision"
                        | "task"
                        | "workstream"
                        | "work_episode"
                        | "worktree"
                        | "worktree_snapshot"
                        | "source_receipt"
                        | "source_observation"
                        | "evidence_surface"
                        | "operation"
                        | "scope_effect"
                        | "work_binding"
                )
            )
        }) {
            let Some(payload) = row.payload_json.as_deref() else {
                continue;
            };
            let payload = serde_json::from_str::<JournalPayload>(payload)
                .map_err(|_| AutoresearchError::Store(evertrace_store::StoreError::StoreCorrupt))?;
            match payload {
                JournalPayload::AttemptRecorded(value) => {
                    if attempt_seq
                        .get(&value.attempt_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        attempt_seq.insert(value.attempt_id, row.source_event_seq);
                        facts.attempts.insert(value.attempt_id, *value);
                    }
                }
                JournalPayload::ProcedureRevisionRecorded(value) => {
                    if procedure_seq
                        .get(&value.procedure_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        procedure_seq.insert(value.procedure_id, row.source_event_seq);
                        facts
                            .current_procedures
                            .insert(value.procedure_id, value.revision_id);
                    }
                    facts.procedures.insert(value.revision_id, *value);
                }
                JournalPayload::ProcedureUsageRecorded(value) => {
                    if usage_seq
                        .get(&value.procedure_usage_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        usage_seq.insert(value.procedure_usage_id, row.source_event_seq);
                        facts.usages.insert(value.procedure_usage_id, *value);
                    }
                }
                JournalPayload::TaskRecorded(value) => {
                    if task_seq
                        .get(&value.task_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        task_seq.insert(value.task_id, row.source_event_seq);
                        facts.tasks.insert(value.task_id, *value);
                    }
                }
                JournalPayload::WorkstreamRecorded(value) => {
                    if workstream_seq
                        .get(&value.workstream_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        workstream_seq.insert(value.workstream_id, row.source_event_seq);
                        facts.workstreams.insert(value.workstream_id, *value);
                    }
                }
                JournalPayload::WorkEpisodeRecorded(value) => {
                    if episode_seq
                        .get(&value.episode_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        episode_seq.insert(value.episode_id, row.source_event_seq);
                        facts
                            .current_episodes
                            .insert(value.episode_id, value.revision_id);
                    }
                    facts.episodes.insert(value.revision_id, *value);
                }
                JournalPayload::WorktreeInstanceRecorded(value) => {
                    if worktree_seq
                        .get(&value.worktree_instance_id)
                        .is_none_or(|seq| row.source_event_seq > *seq)
                    {
                        worktree_seq.insert(value.worktree_instance_id, row.source_event_seq);
                        facts.worktrees.insert(value.worktree_instance_id, *value);
                    }
                }
                JournalPayload::WorktreeSnapshotRecorded(value) => {
                    facts.snapshots.insert(value.worktree_snapshot_id, *value);
                }
                JournalPayload::SourceReceiptRecorded(value) => {
                    facts.receipts.insert(value.source_receipt_id, *value);
                }
                JournalPayload::SourceObservationRecorded(value) => {
                    facts
                        .observations
                        .insert(value.source_observation_id, *value);
                }
                JournalPayload::EvidenceSurfaceRecorded(value) => {
                    facts
                        .surfaces
                        .insert(value.source_observation_revision_ref, *value);
                }
                JournalPayload::OperationDerived(value) => {
                    if facts
                        .operations
                        .get(&value.operation_id)
                        .is_some_and(|current| {
                            current.operation_revision == value.operation_revision
                                && current != value.as_ref()
                        })
                    {
                        return Err(AutoresearchError::EvidenceIncomplete);
                    }
                    if facts
                        .operations
                        .get(&value.operation_id)
                        .is_none_or(|current| value.operation_revision > current.operation_revision)
                    {
                        facts.operations.insert(value.operation_id, *value);
                    }
                }
                JournalPayload::ScopeEffectDerived(value) => {
                    facts
                        .scope_effects
                        .insert(value.scope_effect_id, (*value, row.source_event_seq));
                }
                JournalPayload::WorkBindingRecorded(value)
                    if facts
                        .bindings
                        .get(&value.operation_id)
                        .is_none_or(|current| {
                            value.revision_generation > current.revision_generation
                        }) =>
                {
                    facts.bindings.insert(value.operation_id, *value);
                }
                _ => {}
            }
        }
        Ok(facts)
    }

    fn receipt(
        &self,
        observation_id: SourceObservationId,
    ) -> Result<&SourceReceipt, AutoresearchError> {
        let observation = self
            .observations
            .get(&observation_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        self.receipts
            .get(&observation.source_receipt_ref)
            .ok_or(AutoresearchError::EvidenceIncomplete)
    }

    fn validate_declaration_anchor(
        &self,
        procedure_revision_id: RevisionId,
        attempt: &Attempt,
        snapshot_id: evertrace_domain::ids::WorktreeSnapshotId,
    ) -> Result<(), AutoresearchError> {
        let mut usages = self.usages.values().filter(|usage| {
            usage.procedure_revision_id == procedure_revision_id
                && usage.attempt_ids.contains(&attempt.attempt_id)
        });
        let usage = usages.next().ok_or(AutoresearchError::EvidenceIncomplete)?;
        if usages.next().is_some() {
            return Err(AutoresearchError::ImmutableConflict);
        }
        let episode = self
            .episodes
            .get(&usage.exposure_episode_revision_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let task = self
            .tasks
            .get(&usage.task_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let workstream = self
            .workstreams
            .get(&usage.workstream_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let repository_id = usage
            .local_context
            .repository_id
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let worktree_id = usage
            .local_context
            .worktree_id
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let snapshot = self
            .snapshots
            .get(&snapshot_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let worktree = self
            .worktrees
            .get(&worktree_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        if self.current_episodes.get(&episode.episode_id) != Some(&episode.revision_id)
            || episode.entry_worktree_snapshot_id != Some(snapshot_id)
            || episode.task_id != task.task_id
            || episode.workstream_id != workstream.workstream_id
            || episode.repository_instance_id != Some(repository_id)
            || episode.worktree_instance_id != Some(worktree_id)
            || attempt.task_id != task.task_id
            || attempt.workstream_id != workstream.workstream_id
            || attempt.repository_instance_id != Some(repository_id)
            || !attempt.worktree_instance_ids.contains(&worktree_id)
            || workstream.task_id != task.task_id
            || workstream.repository_instance_id != Some(repository_id)
            || !workstream.worktree_instance_ids.contains(&worktree_id)
            || snapshot.worktree_instance_id != worktree_id
            || worktree.repository_instance_id != repository_id
        {
            return Err(AutoresearchError::ImmutableConflict);
        }
        Ok(())
    }
}

fn exact_bound_run(
    facts: &ControlledFacts,
    observation_id: SourceObservationId,
    attempt_id: AttemptId,
    workstream_id: evertrace_domain::ids::WorkstreamId,
) -> Result<
    (
        evertrace_domain::ids::ExperimentRunId,
        Vec<WorkBindingRevision>,
    ),
    AutoresearchError,
> {
    let mut selected = Vec::new();
    for operation in facts.operations.values().filter(|operation| {
        operation
            .input_source_observation_refs
            .contains(&observation_id)
    }) {
        if operation.pairing_state != PairingState::Paired {
            return Err(AutoresearchError::EvidenceIncomplete);
        }
        let binding = facts
            .bindings
            .get(&operation.operation_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        if binding.assignment_status != AssignmentStatus::Resolved
            || binding.primary_binding.attempt_id != Some(attempt_id)
            || binding.primary_binding.workstream_id != Some(workstream_id)
        {
            return Err(AutoresearchError::ImmutableConflict);
        }
        selected.push(binding);
    }
    if selected.is_empty() {
        return Err(AutoresearchError::EvidenceIncomplete);
    }
    let existing = selected
        .iter()
        .filter_map(|binding| binding.primary_binding.experiment_run_id)
        .collect::<std::collections::BTreeSet<_>>();
    if existing.len() > 1 || !existing.is_empty() && existing.len() != selected.len() {
        return Err(AutoresearchError::ImmutableConflict);
    }
    let run_id = existing
        .first()
        .copied()
        .unwrap_or_else(evertrace_domain::ids::ExperimentRunId::new_v7);
    if existing.is_empty() {
        let mut successors = Vec::with_capacity(selected.len());
        for current in selected {
            let mut next = current.clone();
            next.work_binding_revision_id = evertrace_domain::ids::WorkBindingRevisionId::new_v7();
            next.revision_generation = current.revision_generation.saturating_add(1);
            next.predecessor_revision_id = Some(current.work_binding_revision_id);
            next.primary_binding.experiment_run_id = Some(run_id);
            next.evidence_refs.push(observation_id.to_string());
            next.evidence_refs.sort();
            next.evidence_refs.dedup();
            current
                .validate_successor(&next)
                .map_err(|_| AutoresearchError::ImmutableConflict)?;
            successors.push(next);
        }
        Ok((run_id, successors))
    } else {
        Ok((run_id, Vec::new()))
    }
}

fn require_bound_operations(
    facts: &ControlledFacts,
    observation_id: SourceObservationId,
    launch: bool,
    run_id: evertrace_domain::ids::ExperimentRunId,
    attempt_id: AttemptId,
    workstream_id: evertrace_domain::ids::WorkstreamId,
) -> Result<(), AutoresearchError> {
    let operations = facts
        .operations
        .values()
        .filter(|operation| {
            let refs = if launch {
                &operation.input_source_observation_refs
            } else {
                &operation.result_source_observation_refs
            };
            refs.contains(&observation_id)
        })
        .collect::<Vec<_>>();
    if operations.is_empty() {
        return Err(AutoresearchError::EvidenceIncomplete);
    }
    if operations.iter().any(|operation| {
        operation.pairing_state != PairingState::Paired
            || facts
                .bindings
                .get(&operation.operation_id)
                .is_none_or(|binding| {
                    binding.assignment_status != AssignmentStatus::Resolved
                        || binding.primary_binding.experiment_run_id != Some(run_id)
                        || binding.primary_binding.attempt_id != Some(attempt_id)
                        || binding.primary_binding.workstream_id != Some(workstream_id)
                })
    }) {
        Err(AutoresearchError::ImmutableConflict)
    } else {
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMetric {
    decimal: String,
    unit: String,
    uncertainty_decimal: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultParseRequest {
    pub scope: ResultScope,
    pub raw_cas_refs: Vec<CasId>,
    pub created_at_us: i64,
}

#[derive(Clone)]
pub struct ResultEvidenceService {
    cas: CasStore,
}

impl ResultEvidenceService {
    pub const fn new(cas: CasStore) -> Self {
        Self { cas }
    }

    pub fn parse(
        &self,
        run: &ExperimentRun,
        mut request: ResultParseRequest,
    ) -> Result<ResultEvidence, AutoresearchError> {
        require_declaration_run(run)?;
        request.raw_cas_refs.sort();
        request.raw_cas_refs.dedup();
        let bytes = self.read_all(&request.raw_cas_refs)?;
        let (status, metric, parser_failure) =
            parse_metric_set(&bytes, run.multi_cas_metric_policy)?;
        let result = ResultEvidence {
            result_evidence_id: ResultEvidenceId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            experiment_run_id: run.run_id,
            experiment_run_revision_id: run.revision_id,
            result_scope: request.scope,
            raw_artifact_refs: Vec::new(),
            raw_cas_refs: request.raw_cas_refs.clone(),
            parsed_metric: metric,
            parser_receipt: ParserReceipt {
                parser_version: RESULT_PARSER_VERSION.into(),
                input_artifact_refs: Vec::new(),
                input_cas_refs: request.raw_cas_refs,
                status,
                failure_code: parser_failure,
            },
            verifier_receipt: None,
            completeness: EvidenceCompleteness::Incomplete,
            failure: parser_failure.map(ResultFailure::Parser),
            created_at_us: request.created_at_us,
        };
        result
            .validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        Ok(result)
    }

    pub fn parse_command(
        &self,
        context: AutoresearchCommandContext,
        run: &ExperimentRun,
        request: ResultParseRequest,
    ) -> Result<(ResultEvidence, JournalCommand), AutoresearchError> {
        let result = self.parse(run, request)?;
        let command = self.validated_command(context, run, &result)?;
        Ok((result, command))
    }

    pub fn extend(
        &self,
        run: &ExperimentRun,
        current: &ResultEvidence,
        additional_cas_refs: Vec<CasId>,
        created_at_us: i64,
    ) -> Result<AutoresearchResolution<ResultEvidence>, AutoresearchError> {
        require_result_run(run, current)?;
        if created_at_us < current.created_at_us {
            return Err(AutoresearchError::ImmutableConflict);
        }
        let mut combined = current.raw_cas_refs.clone();
        combined.extend(additional_cas_refs);
        combined.sort();
        combined.dedup();
        if combined == current.raw_cas_refs {
            return Ok(AutoresearchResolution::NoDelta);
        }
        let bytes = self.read_all(&combined)?;
        let (status, metric, parser_failure) =
            parse_metric_set(&bytes, run.multi_cas_metric_policy).map_err(|error| {
                if current.parsed_metric.is_some() {
                    AutoresearchError::ImmutableConflict
                } else {
                    error
                }
            })?;
        if current.parsed_metric.is_some() && metric != current.parsed_metric {
            return Err(AutoresearchError::ImmutableConflict);
        }
        let mut next = current.clone();
        next.revision_id = RevisionId::new_v7();
        next.parent_revision_id = Some(current.revision_id);
        next.raw_cas_refs = combined.clone();
        next.parser_receipt.input_cas_refs = combined;
        next.parser_receipt.status = status;
        next.parser_receipt.failure_code = parser_failure;
        next.parsed_metric = metric;
        next.verifier_receipt = None;
        next.completeness = EvidenceCompleteness::Incomplete;
        next.failure = parser_failure.map(ResultFailure::Parser);
        next.created_at_us = created_at_us;
        current
            .validate_successor(&next)
            .map_err(|_| AutoresearchError::ImmutableConflict)?;
        Ok(AutoresearchResolution::Revision(Box::new(next)))
    }

    pub fn verify(
        &self,
        run: &ExperimentRun,
        current: &ResultEvidence,
        created_at_us: i64,
    ) -> Result<AutoresearchResolution<ResultEvidence>, AutoresearchError> {
        require_result_run(run, current)?;
        let bytes = self.read_all(&current.raw_cas_refs)?;
        let (parser_status, parsed_metric, parser_failure) =
            parse_metric_set(&bytes, run.multi_cas_metric_policy)
                .map_err(|_| AutoresearchError::ImmutableConflict)?;
        let matches = parser_status == current.parser_receipt.status
            && parsed_metric == current.parsed_metric
            && parser_failure == current.parser_receipt.failure_code;
        let verifier_failure =
            (!matches).then_some(VerifierFailureCode::DeterministicReparseMismatch);
        let verifier = VerifierReceipt {
            verifier_version: RESULT_VERIFIER_VERSION.into(),
            status: if matches {
                VerifierStatus::Passed
            } else {
                VerifierStatus::Failed
            },
            failure_code: verifier_failure,
        };
        let completeness = if matches && parser_status == ParserStatus::Parsed {
            EvidenceCompleteness::Complete
        } else {
            EvidenceCompleteness::Incomplete
        };
        if current.verifier_receipt.as_ref() == Some(&verifier)
            && current.completeness == completeness
        {
            return Ok(AutoresearchResolution::NoDelta);
        }
        if current.verifier_receipt.is_some() || created_at_us < current.created_at_us {
            return Err(AutoresearchError::ImmutableConflict);
        }
        let mut next = current.clone();
        next.revision_id = RevisionId::new_v7();
        next.parent_revision_id = Some(current.revision_id);
        next.verifier_receipt = Some(verifier);
        next.completeness = completeness;
        next.failure = parser_failure
            .map(ResultFailure::Parser)
            .or(verifier_failure.map(ResultFailure::Verifier));
        next.created_at_us = created_at_us;
        current
            .validate_successor(&next)
            .map_err(|_| AutoresearchError::InvalidInput)?;
        Ok(AutoresearchResolution::Revision(Box::new(next)))
    }

    pub fn verify_command(
        &self,
        context: AutoresearchCommandContext,
        run: &ExperimentRun,
        current: &ResultEvidence,
        created_at_us: i64,
    ) -> Result<Option<AutoresearchCommandRevision<ResultEvidence>>, AutoresearchError> {
        match self.verify(run, current, created_at_us)? {
            AutoresearchResolution::NoDelta => Ok(None),
            AutoresearchResolution::Revision(value) => {
                let command = self.validated_command(context, run, &value)?;
                Ok(Some(AutoresearchCommandRevision { value, command }))
            }
        }
    }

    fn validated_command(
        &self,
        context: AutoresearchCommandContext,
        run: &ExperimentRun,
        result: &ResultEvidence,
    ) -> Result<JournalCommand, AutoresearchError> {
        require_result_run(run, result)?;
        self.read_all(&result.raw_cas_refs)?;
        result
            .validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        payload_command(
            context,
            vec![JournalPayload::ResultEvidenceRecorded(Box::new(
                result.clone(),
            ))],
        )
    }

    fn read_all(&self, refs: &[CasId]) -> Result<Vec<Vec<u8>>, AutoresearchError> {
        if refs.is_empty() {
            return Err(AutoresearchError::EvidenceIncomplete);
        }
        refs.iter().map(|id| read_cas(&self.cas, id)).collect()
    }
}

fn require_declaration_run(run: &ExperimentRun) -> Result<(), AutoresearchError> {
    run.validate()
        .map_err(|_| AutoresearchError::InvalidInput)?;
    if !run.is_declaration_only() {
        return Err(AutoresearchError::UntrustedRunEvidence);
    }
    Ok(())
}

fn require_result_run(
    run: &ExperimentRun,
    result: &ResultEvidence,
) -> Result<(), AutoresearchError> {
    require_declaration_run(run)?;
    if result.experiment_run_id != run.run_id
        || result.experiment_run_revision_id != run.revision_id
        || run.metric_extractor_version != RESULT_PARSER_VERSION
    {
        return Err(AutoresearchError::ImmutableConflict);
    }
    Ok(())
}

fn parse_metric(bytes: &[u8]) -> Option<MetricValue> {
    let value = serde_json::from_slice::<RawMetric>(bytes).ok()?;
    let metric = MetricValue {
        decimal: preserve_valid_decimal(&value.decimal)?,
        unit: value.unit,
        uncertainty_decimal: match value.uncertainty_decimal {
            Some(value) => Some(preserve_valid_decimal(&value)?),
            None => None,
        },
    };
    metric.validate().ok().map(|()| metric)
}

fn preserve_valid_decimal(value: &str) -> Option<String> {
    let parsed = value.parse::<f64>().ok()?;
    parsed.is_finite().then(|| value.to_owned())
}

fn parse_metric_set(
    bytes: &[Vec<u8>],
    policy: MultiCasMetricPolicy,
) -> Result<(ParserStatus, Option<MetricValue>, Option<ParserFailureCode>), AutoresearchError> {
    let parsed = bytes
        .iter()
        .filter_map(|value| parse_metric(value))
        .collect::<Vec<_>>();
    match parsed.as_slice() {
        [] => Ok((
            ParserStatus::Failed,
            None,
            Some(ParserFailureCode::MetricParseFailed),
        )),
        [metric] => Ok((ParserStatus::Parsed, Some(metric.clone()), None)),
        [first, rest @ ..]
            if policy == MultiCasMetricPolicy::AllowIdenticalParsed
                && rest.iter().all(|metric| metric == first) =>
        {
            Ok((ParserStatus::Parsed, Some(first.clone()), None))
        }
        _ => Err(AutoresearchError::AmbiguousMetricInput),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibleResultCohort {
    pub member_result_ids: Vec<ResultEvidenceId>,
}

pub fn compatible_result_cohort(
    members: &[(&ResultEvidence, &ExperimentRun)],
) -> Result<Option<CompatibleResultCohort>, AutoresearchError> {
    if members.is_empty() {
        return Ok(None);
    }
    if members.len() > MAX_COMPARISON_MEMBERS {
        return Err(AutoresearchError::IncompatibleComparison);
    }
    if members[0].0.parsed_metric.is_none() {
        return Err(AutoresearchError::EvidenceIncomplete);
    }
    let mut ids = Vec::with_capacity(members.len());
    for (result, run) in members {
        if cohort_member_issues(result, run, members[0])
            .next()
            .is_some()
        {
            return Err(AutoresearchError::IncompatibleComparison);
        }
        ids.push(result.result_evidence_id);
    }
    ids.sort();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AutoresearchError::IncompatibleComparison);
    }
    Ok(Some(CompatibleResultCohort {
        member_result_ids: ids,
    }))
}

fn cohort_member_issues(
    result: &ResultEvidence,
    run: &ExperimentRun,
    expected: (&ResultEvidence, &ExperimentRun),
) -> impl Iterator<Item = ResultComparisonReason> {
    use ResultComparisonReason as R;
    let terminal = match result.result_scope {
        ResultScope::Complete => run.execution_status == RunExecutionStatus::Completed,
        ResultScope::Partial => matches!(
            run.execution_status,
            RunExecutionStatus::Completed
                | RunExecutionStatus::Failed
                | RunExecutionStatus::Interrupted
        ),
    };
    [
        (run.validate().is_err(), R::InvalidRun),
        (result.validate().is_err(), R::InvalidResult),
        (
            run.attempt_binding_status != AttemptBindingStatus::Resolved
                || run.attempt_id.is_none(),
            R::AttemptUnresolved,
        ),
        (run.attempt_id != expected.1.attempt_id, R::AttemptMismatch),
        (
            run.workstream_id != expected.1.workstream_id,
            R::WorkstreamMismatch,
        ),
        (
            run.strategy_contract_fingerprint != expected.1.strategy_contract_fingerprint,
            R::StrategyMismatch,
        ),
        (
            run.observability != RunObservability::Full,
            R::ObservabilityInsufficient,
        ),
        (
            run.contract_validity != RunContractValidity::Valid,
            R::ContractNotValid,
        ),
        (!terminal, R::ExecutionScopeMismatch),
        (result.experiment_run_id != run.run_id, R::RunMismatch),
        (
            result.experiment_run_revision_id != run.revision_id,
            R::RunRevisionMismatch,
        ),
        (
            result.parser_receipt.parser_version != run.metric_extractor_version,
            R::ExtractorMismatch,
        ),
        (
            run.comparison_key != expected.1.comparison_key,
            R::ComparisonContractMismatch,
        ),
        (
            result.completeness != EvidenceCompleteness::Complete,
            R::EvidenceIncomplete,
        ),
        (
            result.verifier_receipt.as_ref().is_none_or(|receipt| {
                receipt.status != VerifierStatus::Passed
                    || receipt.verifier_version != RESULT_VERIFIER_VERSION
            }),
            R::VerifierNotPassed,
        ),
        (result.parsed_metric.is_none(), R::MetricMissing),
        (
            result.parsed_metric.as_ref().map(|metric| &metric.unit)
                != expected.0.parsed_metric.as_ref().map(|metric| &metric.unit),
            R::UnitMismatch,
        ),
    ]
    .into_iter()
    .filter_map(|(failed, reason)| failed.then_some(reason))
}

pub fn assess_result_cohort(
    members: &[(&ResultEvidence, &ExperimentRun)],
) -> Result<ResultCohortAssessment, AutoresearchError> {
    if members.is_empty() || members.len() > MAX_COMPARISON_MEMBERS {
        return Err(AutoresearchError::InvalidInput);
    }
    let mut issues = Vec::new();
    for (index, (result, run)) in members.iter().enumerate() {
        let reasons = cohort_member_issues(result, run, members[0]).chain(
            members[..index]
                .iter()
                .any(|(prior, _)| prior.result_evidence_id == result.result_evidence_id)
                .then_some(ResultComparisonReason::DuplicateResult),
        );
        for reason in reasons {
            let dimensions = if reason == ResultComparisonReason::ComparisonContractMismatch {
                members[0].1.comparison_mismatches(run)
            } else {
                Vec::new()
            };
            issues.push(ResultComparisonIssue {
                member: index as u16,
                reason,
                dimensions,
            });
        }
    }
    Ok(ResultCohortAssessment {
        compatible: issues.is_empty(),
        issues,
    })
}

/// Reparse only an otherwise eligible cohort using the original parser and verified protected inputs.
/// Reads are request-local, capped at 64 KiB per input / 1 MiB per member, and cancellation checked by CAS.
pub fn read_result_cohort(
    cas_dir: &std::path::Path,
    members: &[(&ResultEvidence, &ExperimentRun)],
    check: &mut dyn FnMut() -> Result<(), evertrace_capture::CasError>,
) -> Result<ResultCohortAssessment, AutoresearchError> {
    let mut assessment = assess_result_cohort(members)?;
    if !assessment.compatible {
        return Ok(assessment);
    }
    let cas = match CasStore::open_existing(cas_dir.to_owned()) {
        Ok(cas) => cas,
        Err(_) => {
            assessment.compatible = false;
            assessment
                .issues
                .extend((0..members.len()).map(|index| ResultComparisonIssue {
                    member: index as u16,
                    reason: ResultComparisonReason::RawEvidenceUnavailable,
                    dimensions: Vec::new(),
                }));
            return Ok(assessment);
        }
    };
    for (index, (result, run)) in members.iter().enumerate() {
        let mut inputs = Vec::new();
        let mut total = 0;
        let mut reason = None;
        for id in &result.raw_cas_refs {
            match cas.read_text_window_checked(
                &CasDigest::from_str(&hex(&id.as_digest()))
                    .map_err(|_| AutoresearchError::InvalidInput)?,
                0..65536,
                check,
            ) {
                Ok((window, text)) => {
                    total += window.bytes.len();
                    if window.total_bytes > 65536 || total > 1024 * 1024 {
                        reason = Some(ResultComparisonReason::EvidenceBudgetExceeded);
                        break;
                    }
                    if !text {
                        reason = Some(ResultComparisonReason::ReparseMismatch);
                        break;
                    }
                    inputs.push(window.bytes);
                }
                Err(evertrace_capture::CasError::ReadBudgetExceeded) => {
                    reason = Some(ResultComparisonReason::EvidenceBudgetExceeded);
                    break;
                }
                Err(_) => {
                    reason = Some(ResultComparisonReason::RawEvidenceUnavailable);
                    break;
                }
            }
        }
        if reason.is_none() {
            let matches = if run.comparison_execution_binding.is_some() {
                matches!(inputs.as_slice(), [bytes] if matches!(
                    ControlledRunSourceEnvelope::decode_canonical(bytes),
                    Ok(ControlledRunSourceEnvelope::Terminal { run_id, ended_at_us, metric, artifact_refs, .. })
                        if run_id == run.run_id && Some(ended_at_us) == run.ended_at_us
                            && Some(&metric) == result.parsed_metric.as_ref()
                            && artifact_refs == result.raw_artifact_refs && artifact_refs == run.work_artifact_refs))
            } else {
                matches!(parse_metric_set(&inputs, run.multi_cas_metric_policy),
                    Ok((ParserStatus::Parsed, Some(metric), None)) if Some(&metric) == result.parsed_metric.as_ref())
            };
            if !matches {
                reason = Some(ResultComparisonReason::ReparseMismatch);
            }
        }
        if let Some(reason) = reason {
            assessment.issues.push(ResultComparisonIssue {
                member: index as u16,
                reason,
                dimensions: Vec::new(),
            });
        }
    }
    assessment.compatible = assessment.issues.is_empty();
    Ok(assessment)
}

#[derive(Clone)]
pub struct ArtifactService {
    cas: CasStore,
}

impl ArtifactService {
    pub const fn new(cas: CasStore) -> Self {
        Self { cas }
    }

    pub fn create(
        &self,
        mut revision: ArtifactRevision,
    ) -> Result<WorkArtifact, AutoresearchError> {
        self.prepare_revision(&mut revision)?;
        revision.revision_id = RevisionId::new_v7();
        revision.parent_revision_id = None;
        let artifact = WorkArtifact {
            work_artifact_id: WorkArtifactId::new_v7(),
            revision,
        };
        artifact
            .validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        Ok(artifact)
    }

    pub fn create_command(
        &self,
        context: AutoresearchCommandContext,
        revision: ArtifactRevision,
    ) -> Result<(WorkArtifact, JournalCommand), AutoresearchError> {
        let artifact = self.create(revision)?;
        let command = self.validated_command(context, &artifact)?;
        Ok((artifact, command))
    }

    pub fn create_for_run_command(
        &self,
        context: AutoresearchCommandContext,
        current_run: &ExperimentRun,
        mut revision: ArtifactRevision,
    ) -> Result<(WorkArtifact, ExperimentRun, JournalCommand), AutoresearchError> {
        require_declaration_run(current_run)?;
        revision
            .produced_by_refs
            .push(ArtifactActor::ExperimentRun(current_run.run_id));
        revision.produced_by_refs.sort();
        revision.produced_by_refs.dedup();
        let artifact = self.create(revision)?;
        let mut next_run = current_run.clone();
        next_run.revision_id = RevisionId::new_v7();
        next_run.parent_revision_id = Some(current_run.revision_id);
        next_run.work_artifact_refs.push(artifact.work_artifact_id);
        next_run.work_artifact_refs.sort();
        next_run.created_at_us = next_run.created_at_us.max(artifact.revision.created_at_us);
        current_run
            .validate_successor(&next_run)
            .map_err(|_| AutoresearchError::ImmutableConflict)?;
        let command = payload_command(
            context,
            vec![
                JournalPayload::ExperimentRunRecorded(Box::new(next_run.clone())),
                JournalPayload::WorkArtifactRecorded(Box::new(artifact.clone())),
            ],
        )?;
        Ok((artifact, next_run, command))
    }

    pub fn revise(
        &self,
        current: &WorkArtifact,
        mut revision: ArtifactRevision,
    ) -> Result<AutoresearchResolution<WorkArtifact>, AutoresearchError> {
        revision.revision_id = current.revision.revision_id;
        revision.parent_revision_id = current.revision.parent_revision_id;
        if current.revision == revision {
            return Ok(AutoresearchResolution::NoDelta);
        }
        self.prepare_revision(&mut revision)?;
        revision.revision_id = RevisionId::new_v7();
        revision.parent_revision_id = Some(current.revision.revision_id);
        let next = WorkArtifact {
            work_artifact_id: current.work_artifact_id,
            revision,
        };
        current
            .validate_successor(&next)
            .map_err(|_| AutoresearchError::ImmutableConflict)?;
        Ok(AutoresearchResolution::Revision(Box::new(next)))
    }

    pub fn revise_command(
        &self,
        context: AutoresearchCommandContext,
        current: &WorkArtifact,
        revision: ArtifactRevision,
    ) -> Result<Option<AutoresearchCommandRevision<WorkArtifact>>, AutoresearchError> {
        match self.revise(current, revision)? {
            AutoresearchResolution::NoDelta => Ok(None),
            AutoresearchResolution::Revision(value) => {
                let command = self.validated_command(context, &value)?;
                Ok(Some(AutoresearchCommandRevision { value, command }))
            }
        }
    }

    fn prepare_revision(&self, revision: &mut ArtifactRevision) -> Result<(), AutoresearchError> {
        if revision.scope == ArtifactScope::Global
            || revision.payload_status == ArtifactPayloadStatus::SourcePurged
        {
            return Err(AutoresearchError::UnsupportedArtifactAuthority);
        }
        revision.produced_by_refs.sort();
        revision.produced_by_refs.dedup();
        revision.consumed_by_refs.sort();
        revision.consumed_by_refs.dedup();
        revision.source_observation_refs.sort();
        revision.source_observation_refs.dedup();
        if let Some(id) = revision.content_blob_ref {
            if revision
                .content_fingerprint
                .is_some_and(|value| value != id)
            {
                return Err(AutoresearchError::ImmutableConflict);
            }
            read_cas(&self.cas, &id)?;
            revision.content_fingerprint = Some(id);
        } else {
            revision.content_fingerprint = None;
        }
        Ok(())
    }

    fn validated_command(
        &self,
        context: AutoresearchCommandContext,
        artifact: &WorkArtifact,
    ) -> Result<JournalCommand, AutoresearchError> {
        if artifact.revision.scope == ArtifactScope::Global
            || artifact.revision.payload_status == ArtifactPayloadStatus::SourcePurged
        {
            return Err(AutoresearchError::UnsupportedArtifactAuthority);
        }
        if let Some(id) = artifact.revision.content_blob_ref {
            read_cas(&self.cas, &id)?;
        }
        artifact
            .validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        payload_command(
            context,
            vec![JournalPayload::WorkArtifactRecorded(Box::new(
                artifact.clone(),
            ))],
        )
    }
}

fn payload_command(
    context: AutoresearchCommandContext,
    payloads: Vec<JournalPayload>,
) -> Result<JournalCommand, AutoresearchError> {
    let drafts = payloads
        .into_iter()
        .map(|payload| {
            JournalEventDraft::runtime(
                context.occurred_at_us,
                context.effective_config_hash,
                context.algorithm_revision,
                payload,
            )
        })
        .collect();
    JournalCommand::new(context.command_id, drafts).map_err(AutoresearchError::Store)
}

fn read_cas(cas: &CasStore, id: &CasId) -> Result<Vec<u8>, AutoresearchError> {
    let text = id.to_string();
    let digest = CasDigest::from_str(
        text.strip_prefix("cas:")
            .ok_or(AutoresearchError::InvalidInput)?,
    )
    .map_err(|_| AutoresearchError::InvalidInput)?;
    cas.read(&digest).map_err(|_| AutoresearchError::Cas)
}

#[derive(Debug, Error)]
pub enum AutoresearchError {
    #[error("autoresearch input is invalid")]
    InvalidInput,
    #[error("strategy change requires a new Attempt")]
    StrategyDriftRequiresNewAttempt,
    #[error("typed evidence conflicts with immutable facts")]
    ImmutableConflict,
    #[error("required evidence is incomplete")]
    EvidenceIncomplete,
    #[error("controlled source selection deferred by read budget")]
    SelectionDeferred,
    #[error("no trusted scheduler or process evidence source is available")]
    UntrustedRunEvidence,
    #[error("result contracts are incompatible")]
    IncompatibleComparison,
    #[error("multiple CAS inputs contain conflicting parsed metrics")]
    AmbiguousMetricInput,
    #[error("artifact authority belongs to a later slice")]
    UnsupportedArtifactAuthority,
    #[error("CAS evidence is unavailable or invalid")]
    Cas,
    #[error(transparent)]
    Store(#[from] evertrace_store::StoreError),
}
