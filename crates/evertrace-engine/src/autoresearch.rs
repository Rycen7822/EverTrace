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
        AttemptId, CasId, CommandId, ExecutionLaneId, OperationId, ResultEvidenceId,
        SourceObservationId, SourceReceiptId, WorkArtifactId,
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
        Attempt, AttemptBindingStatus, CaptureReceipt, ContractField, ControlledRunSourceEnvelope,
        ExecutionLane, ExperimentRun, LaneStatus, MultiCasMetricPolicy, ResultCohortAssessment,
        ResultComparisonIssue, ResultComparisonReason, RunContractValidity, RunExecutionStatus,
        RunObservability, RunOrigin, SeedPolicy, Task, VariableDeclaration, WorkArtifact,
        WorkBindingRevision, WorkEpisode, Workstream,
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

fn lane_capture_receipt<'a>(
    rows: impl Iterator<Item = &'a evertrace_store::ObjectRow>,
    lane: ExecutionLaneId,
) -> Result<Option<CaptureReceipt>, AutoresearchError> {
    let id = lane.to_string();
    rows.filter(|row| {
        row.object_kind.as_deref() == Some("capture_receipt")
            && row.object_id.as_deref() == Some(id.as_str())
    })
    .max_by_key(|row| row.source_event_seq)
    .map(|row| {
        let json = row
            .payload_json
            .as_deref()
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        match serde_json::from_str::<JournalPayload>(json) {
            Ok(JournalPayload::CaptureReceiptRecorded(receipt))
                if receipt.execution_lane_id == lane =>
            {
                Ok(*receipt)
            }
            _ => Err(AutoresearchError::EvidenceIncomplete),
        }
    })
    .transpose()
}

fn source_phase_settled(
    current: &evertrace_store::CurrentFacts,
    id: evertrace_domain::ids::WorkEpisodeId,
    active: Option<evertrace_domain::ids::WorkEpisodeId>,
    deadline: std::time::Instant,
) -> bool {
    let id = id.to_string();
    let episode = current
        .other_data_rows()
        .take_while(|_| std::time::Instant::now() < deadline)
        .filter(|row| {
            row.object_kind.as_deref() == Some("work_episode")
                && row.object_id.as_deref() == Some(id.as_str())
        })
        .max_by_key(|row| row.source_event_seq)
        .and_then(|row| serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok());
    let Some(JournalPayload::WorkEpisodeRecorded(episode)) = episode else {
        return false;
    };
    if episode.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Closed {
        return true;
    }
    if active != Some(episode.episode_id) {
        return false;
    }
    episode.execution_lane_ids.iter().all(|lane| {
        matches!(lane_capture_receipt(current.other_data_rows()
            .take_while(|_| std::time::Instant::now() < deadline), *lane), Ok(Some(receipt))
            if episode.capture_receipt_revision_ids.contains(&receipt.capture_receipt_revision_id))
    })
}

fn strategy_start_candidate(
    current: &evertrace_store::CurrentFacts,
    attempt: Option<evertrace_domain::ids::AttemptId>,
) -> bool {
    use evertrace_domain::work::{
        AttemptExecutionStatus, AttemptLifecycleStatus, EpisodeLifecycle,
    };
    let Some(attempt_id) = attempt else {
        return false;
    };
    let latest = |kind: &str, id: String| {
        current
            .other_data_rows()
            .filter(|row| {
                row.object_kind.as_deref() == Some(kind)
                    && row.object_id.as_deref() == Some(id.as_str())
            })
            .max_by_key(|row| row.source_event_seq)
            .and_then(|row| {
                serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()
            })
    };
    let Some(JournalPayload::AttemptRecorded(attempt)) = latest("attempt", attempt_id.to_string())
    else {
        return false;
    };
    if attempt.execution_status != AttemptExecutionStatus::Proposed
        || attempt.lifecycle_status != AttemptLifecycleStatus::Active
    {
        return false;
    }
    let Some(episode_id) = attempt.episode_id else {
        return false;
    };
    let Some(JournalPayload::WorkEpisodeRecorded(episode)) =
        latest("work_episode", episode_id.to_string())
    else {
        return false;
    };
    let Some(JournalPayload::WorkstreamRecorded(stream)) =
        latest("workstream", attempt.workstream_id.to_string())
    else {
        return false;
    };
    if episode.lifecycle_status != EpisodeLifecycle::Open
        || stream.status.is_terminal()
        || stream.active_episode_id != Some(episode_id)
    {
        return false;
    }
    let lanes = episode
        .execution_lane_ids
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    current.other_data_rows().any(|row| {
        row.object_kind.as_deref() == Some("execution_lane")
            && row.object_id.as_ref().is_some_and(|id| lanes.contains(id))
            && matches!(row.payload_json.as_deref().and_then(|json| serde_json::from_str::<JournalPayload>(json).ok()),
                Some(JournalPayload::ExecutionLaneRecorded(lane)) if lane.status == LaneStatus::Active)
    })
}

// Resolved replay must not reopen a repository or mutate current trust.
// New relevant canonical facts can keep an unfinished source pending.
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
                                    membership.repository_instance_id == scope.repository
                                        && scope.worktree.map_or_else(
                                            || membership.worktree_instance_ids.is_empty(),
                                            |tree| membership.worktree_instance_ids.contains(&tree),
                                        )
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
                let bound = current
                    .other_data_rows()
                    .take_while(|_| std::time::Instant::now() < deadline)
                    .any(|row| {
                        if row.object_kind.as_deref() != Some("work_binding") {
                            return false;
                        }
                        matches!(
                            row.payload_json.as_deref().and_then(|json| {
                                serde_json::from_str::<JournalPayload>(json).ok()
                            }),
                            Some(JournalPayload::WorkBindingRecorded(binding))
                                if source_owns_stream(&binding, &value, &reference)
                                    && (value.status.is_terminal()
                                        || binding.primary_binding.episode_id.is_some_and(|episode| {
                                            source_phase_settled(current, episode, value.active_episode_id, deadline)
                                        }))
                        )
                    });
                bound || (value.status.is_terminal() && value.worktree_lineage_refs.contains(&reference))
            });
    }
    if let SourceCandidate::TestResult(event) = envelope {
        let key = format!("{}/{}", event.source_epoch, event.execution_key);
        // Already accepted terminal receipts need no reprocessing. Legacy declarations keep their own extractor contract.
        if current.other_data_rows().any(|row| row.object_kind.as_deref() == Some("experiment_run")
            && row.payload_json.as_deref().is_some_and(|json| {
                matches!(serde_json::from_str::<JournalPayload>(json),
                    Ok(JournalPayload::ExperimentRunRecorded(run))
                    if run.external_system_id.as_deref() == Some(evertrace_capture::process_source::FORMAT)
                        && run.external_run_key.as_deref() == Some(key.as_str())
                        && (run.terminal_evidence_refs.contains(&observation.source_receipt_ref)
                            || !evertrace_domain::work::is_native_test_parser(&run.metric_extractor_version)
                                && run.source_receipt_refs.iter().any(|id| {
                                    current.source_receipt(*id).is_some_and(|(receipt, _)| {
                                        receipt.source_instance_id == observation.source_instance_id
                                            && receipt.source_record_identity.as_str() == event.launch_event
                                            && receipt.observation_role == evertrace_domain::evidence::ObservationRole::Intent
                                    })
                                })))
            }))
        {
            return true;
        }
        let Some((receipt, _)) = current.source_receipt(observation.source_receipt_ref) else {
            return false;
        };
        let Ok(digest) = receipt.cas_ref.parse::<CasDigest>() else {
            return false;
        };
        let cas = CasId::from_digest(*digest.as_bytes());
        return current.other_data_rows().any(|row| {
            if row.object_kind.as_deref() != Some("result_evidence") {
                return false;
            }
            let Some(JournalPayload::ResultEvidenceRecorded(result)) = row
                .payload_json
                .as_deref()
                .and_then(|json| serde_json::from_str::<JournalPayload>(json).ok())
            else {
                return false;
            };
            if !evertrace_domain::work::is_native_test_parser(&result.parser_receipt.parser_version)
                || result.raw_cas_refs != [cas]
            {
                return false;
            }
            let [artifact] = result.raw_artifact_refs.as_slice() else {
                return false;
            };
            let key = artifact.to_string();
            current.other_data_rows().any(|row| {
                row.object_kind.as_deref() == Some("work_artifact")
                    && row.object_id.as_deref() == Some(key.as_str())
                    && matches!(row.payload_json.as_deref().and_then(|json| serde_json::from_str::<JournalPayload>(json).ok()),
                        Some(JournalPayload::WorkArtifactRecorded(value))
                        if value.revision.source_observation_refs == [observation.source_observation_id])
            })
        });
    }
    if let SourceCandidate::Trial(trial) = envelope {
        let external_key = format!("{}/{}", trial.source_epoch, trial.execution_key);
        let run = current.other_data_rows().find_map(|row| {
            if row.object_kind.as_deref() != Some("experiment_run") {
                return None;
            }
            let JournalPayload::ExperimentRunRecorded(run) = row
                .payload_json
                .as_deref()
                .and_then(|json| serde_json::from_str::<JournalPayload>(json).ok())?
            else {
                return None;
            };
            (run.external_system_id.as_deref() == Some(evertrace_capture::process_source::FORMAT)
                && run.external_run_key.as_deref() == Some(external_key.as_str())
                && run
                    .source_receipt_refs
                    .contains(&observation.source_receipt_ref))
            .then_some((run.run_id, run.attempt_id))
        });
        let Some((run, attempt)) = run else {
            return false;
        };
        // Frozen weak admission cannot become a physical binding on a later scan.
        if observation.correlation.exact_key().is_none() {
            return true;
        }
        // A later native carrier must revisit the original exact declaration, not create another Run.
        if strategy_start_candidate(current, attempt) {
            return false;
        }
        let source = observation.source_observation_id.to_string();
        return current.other_data_rows().any(|row| {
            row.object_kind.as_deref() == Some("work_binding")
                && row.payload_json.as_deref().is_some_and(|json| {
                    matches!(serde_json::from_str::<JournalPayload>(json),
                        Ok(JournalPayload::WorkBindingRecorded(binding))
                        if binding.primary_binding.experiment_run_id == Some(run)
                            && binding.evidence_refs.contains(&source))
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
    #[serde(alias = "work_key")]
    study_key: String,
    goal: String,
    scope: String,
    #[serde(default)]
    scope_kind: ProcessWorkScope,
    phase: evertrace_domain::work::PhaseContract,
    strategy: evertrace_domain::work::StrategyContract,
}

#[derive(Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ProcessWorkScope {
    #[default]
    Repository,
    NonRepository,
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
    #[serde(alias = "work_key")]
    study_key: String,
    controller: ProcessController,
    definition: ProcessWorkPlan,
}

impl ProcessWorkDeclaration {
    fn decode(bytes: &[u8], receipt: &SourceReceipt) -> Option<Self> {
        let raw: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        if raw["format"] == evertrace_capture::process_source::WORK_FORMAT
            && raw["definition"].as_object()?.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "work_key" | "goal" | "scope" | "scope_kind" | "phase" | "strategy"
                )
            })
        {
            return None;
        }
        let value: Self = serde_json::from_value(raw).ok()?;
        let controller = &value.controller;
        let instance = format!(
            "process:{}:{}:{}:{}",
            controller.boot_id, controller.pid_namespace, controller.pid, controller.start_ticks
        );
        let fixed = value.format == evertrace_capture::process_source::FORMAT
            && value.event == "study_opened"
            && value.definition.scope_kind == ProcessWorkScope::Repository;
        let work = value.format == evertrace_capture::process_source::WORK_FORMAT
            && value.event == "work_started";
        ((fixed || work)
            && value.study_key == value.definition.study_key
            && !value.study_key.trim().is_empty()
            && !value.source_epoch.is_empty()
            && receipt.source_sequence == 1
            && receipt.source_instance_id.as_str() == instance
            && value.definition.phase.validate().is_ok()
            && value.definition.strategy.validate().is_ok())
        .then_some(value)
    }
}

/// A source-owned declaration supplies a contract, never a completed boundary or verifier result.
pub(crate) fn declared_work_contract(
    receipt: &SourceReceipt,
    bytes: &[u8],
    native: &SourceObservation,
    native_receipt: &SourceReceipt,
    native_bytes: &[u8],
) -> Option<(
    evertrace_domain::work::PhaseContract,
    evertrace_domain::work::StrategyContract,
)> {
    if !evertrace_capture::process_source::is_work_revision(receipt.source_revision.as_str()) {
        return None;
    }
    let declaration = ProcessWorkDeclaration::decode(bytes, receipt)?;
    (declaration.format == evertrace_capture::process_source::WORK_FORMAT
        && evertrace_capture::execution_source::execution_directory(
            native,
            native_receipt,
            native_bytes,
        ) == Some((
            declaration.definition.scope.clone(),
            declaration.controller.pid,
            declaration.controller.start_ticks,
        )))
    .then_some((
        declaration.definition.phase,
        declaration.definition.strategy,
    ))
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
    process: Option<serde_json::Value>,
    argv: Option<Vec<String>>,
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

fn process_runtime_groups<'a>(
    trial: &ProcessTrialDeclaration,
    receipts: impl Iterator<Item = &'a SourceReceipt>,
) -> Result<Vec<[SourceObservationId; 4]>, AutoresearchError> {
    use evertrace_capture::process_source as source;
    let Some(process) = trial.process.as_ref() else {
        return Ok(Vec::new());
    };
    let (Some(pid), Some(birth)) = (process["pid"].as_u64(), process["start_ticks"].as_u64())
    else {
        return Ok(Vec::new());
    };
    let prefix = format!(
        "procfs:{}:{}:",
        trial.controller.boot_id, trial.controller.pid_namespace
    );
    let stat = format!("procfs:/proc/{pid}/stat@{birth}");
    let command = format!("procfs:/proc/{pid}/cmdline@{birth}");
    let environment = format!("procfs:/proc/{pid}/environ@{birth}");
    let conditions = format!(":trial-{}.conditions.json", trial.execution_key);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(40);
    let mut selected = Vec::new();
    for receipt in receipts {
        if std::time::Instant::now() >= deadline {
            return Err(AutoresearchError::SelectionDeferred);
        }
        if receipt.source_instance_id.as_str().starts_with(&prefix)
            && match receipt.source_revision.as_str() {
                source::KERNEL_SOURCE_REVISION => receipt.source_ref == stat,
                source::INPUT_SOURCE_REVISION => {
                    receipt.source_ref == command || receipt.source_ref == environment
                }
                source::CONDITIONS_SOURCE_REVISION => receipt.source_ref.ends_with(&conditions),
                _ => false,
            }
        {
            selected.push(receipt);
            if selected.len() > 64 {
                return Err(AutoresearchError::EvidenceIncomplete);
            }
        }
    }
    let mut groups = Vec::new();
    for kernel in selected
        .iter()
        .filter(|value| value.source_revision.as_str() == source::KERNEL_SOURCE_REVISION)
    {
        let observer = kernel.source_instance_id.as_str();
        let mut group = vec![kernel.source_observation_id];
        for (suffix, revision, reference) in [
            (":cmdline", source::INPUT_SOURCE_REVISION, command.as_str()),
            (
                ":environ",
                source::INPUT_SOURCE_REVISION,
                environment.as_str(),
            ),
            (":runtime", source::CONDITIONS_SOURCE_REVISION, ""),
        ] {
            let instance = format!("{observer}{suffix}");
            let mut matching = selected.iter().filter(|value| {
                value.source_instance_id.as_str() == instance
                    && value.source_revision.as_str() == revision
                    && (reference.is_empty() || value.source_ref == reference)
            });
            if let Some(receipt) = matching.next() {
                if matching.next().is_some() {
                    return Err(AutoresearchError::EvidenceIncomplete);
                }
                group.push(receipt.source_observation_id);
            }
        }
        if let Ok(group) = group.try_into() {
            groups.push(group);
        }
    }
    Ok(groups)
}

fn process_runtime_images<'a>(
    trial: &ProcessTrialDeclaration,
    receipts: impl Iterator<Item = &'a SourceReceipt>,
) -> Result<Vec<SourceObservationId>, AutoresearchError> {
    let Some(process) = trial.process.as_ref() else {
        return Ok(Vec::new());
    };
    let text = |name| {
        process[name]
            .as_str()
            .ok_or(AutoresearchError::EvidenceIncomplete)
    };
    let number = |name| {
        process[name]
            .as_u64()
            .ok_or(AutoresearchError::EvidenceIncomplete)
    };
    let instance = format!(
        "native-runtime:{}:{}:{}:{}",
        text("boot_id")?,
        number("pid_namespace")?,
        number("pid")?,
        number("start_ticks")?
    );
    let reference = format!(
        "runtime:{}:{}@{}",
        trial.source_epoch,
        trial.execution_key,
        number("start_ticks")?
    );
    let mut result = Vec::new();
    for receipt in receipts {
        if receipt.source_revision.as_str()
            == evertrace_capture::process_source::IMAGE_SOURCE_REVISION
            && receipt.source_instance_id.as_str() == instance
            && receipt.source_ref == reference
        {
            result.push(receipt.source_observation_id);
            if result.len() > 4 {
                return Err(AutoresearchError::EvidenceIncomplete);
            }
        }
    }
    Ok(result)
}

fn recorded_runtime_source(observation: &SourceObservation, receipt: &SourceReceipt) -> bool {
    use evertrace_capture::process_source as source;
    use evertrace_domain::evidence::{
        CorrelationAdmission, EvidenceSourceKind, IdentityStrength, ObservationRole,
    };
    matches!(
        receipt.source_revision.as_str(),
        source::KERNEL_SOURCE_REVISION
            | source::INPUT_SOURCE_REVISION
            | source::CONDITIONS_SOURCE_REVISION
    ) && receipt.source_kind == EvidenceSourceKind::Other
        && receipt.identity_strength == IdentityStrength::SynthesizedBestEffort
        && observation.identity_strength == receipt.identity_strength
        && observation.source_role == SourceRole::Tool
        && observation.content_trust == ContentTrust::Observed
        && observation.capture_completeness == CaptureCompleteness::Partial
        && observation.observation_role == ObservationRole::StateProbe
        && receipt.lifecycle.is_none()
        && observation.correlation.admission == CorrelationAdmission::Unavailable
        && observation.scope_effect_claims.is_empty()
        && observation.source_local_evidence.is_none()
        && receipt.identity_domain == receipt.source_revision.as_str()
        && receipt.adapter_revision == source::KERNEL_ADAPTER_REVISION
        && observation.adapter_revision == receipt.adapter_revision
        && receipt.parser_revision == 1
        && observation.parser_revision == 1
        && receipt.canonicalization_revision == 1
        && receipt.source_sequence == 0
        && receipt.source_sequence_origin == Some(0)
        && receipt.close_watermark == Some(0)
}

fn runtime_environment_fingerprint(value: &serde_json::Value) -> Result<String, AutoresearchError> {
    use evertrace_domain::canonical::{CanonicalValue, sha256};
    fn canonical(value: &serde_json::Value) -> Option<CanonicalValue> {
        use serde_json::Value;
        Some(match value {
            Value::Null => CanonicalValue::Null,
            Value::Bool(value) => CanonicalValue::Bool(*value),
            Value::Number(value) => CanonicalValue::Integer(
                value
                    .as_i64()
                    .map(i128::from)
                    .or_else(|| value.as_u64().map(i128::from))?,
            ),
            Value::String(value) => CanonicalValue::String(value.clone()),
            Value::Array(values) => {
                CanonicalValue::Sequence(values.iter().map(canonical).collect::<Option<_>>()?)
            }
            Value::Object(values) => CanonicalValue::Map(
                values
                    .iter()
                    .map(|(key, value)| Some((key.clone(), canonical(value)?)))
                    .collect::<Option<_>>()?,
            ),
        })
    }
    let fields = ["python", "framework", "environment", "packages"]
        .into_iter()
        .map(|key| Some((key.to_owned(), canonical(value.get(key)?)?)))
        .collect::<Option<Vec<_>>>()
        .ok_or(AutoresearchError::EvidenceIncomplete)?;
    let digest = sha256(
        "evertrace.recorded_runtime_environment",
        1,
        &CanonicalValue::Map(fields),
    )
    .map_err(|_| AutoresearchError::InvalidInput)?;
    Ok(format!("recorded-runtime-v1:{}", hex(&digest)))
}

enum SourceCandidate {
    TestResult(Box<evertrace_domain::work::NativeTestResult>),
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
        && observation.content_trust == ContentTrust::Observed
        && observation.capture_completeness == CaptureCompleteness::Complete
        && observation.correlation.exact_key().is_some()
    {
        let (surface, _) = current.evidence_surface(id)?;
        return evertrace_domain::work::NativeTestResult::decode(surface.protected_text.as_bytes())
            .map(|value| SourceCandidate::TestResult(Box::new(value)));
    }
    if (observation.source_revision.as_str() == evertrace_capture::process_source::SOURCE_REVISION
        || evertrace_capture::process_source::is_work_revision(
            observation.source_revision.as_str(),
        ))
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
    repository: Option<evertrace_domain::ids::RepositoryId>,
    worktree: Option<evertrace_domain::ids::WorktreeId>,
}

fn observed_without_repository(effect: &evertrace_domain::evidence::ScopeEffect) -> bool {
    effect.repository_instance_id.is_none()
        && effect.worktree_instance_id.is_none()
        && effect.effect_role == evertrace_domain::evidence::EffectRole::Observe
        && effect.pre_snapshot_id.is_none()
        && effect.post_snapshot_id.is_none()
        && effect.experiment_run_ids.is_empty()
        && effect.artifact_refs.is_empty()
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
        let (repository, worktree) = (effect.repository_instance_id, effect.worktree_instance_id);
        if !matches!((repository, worktree), (Some(_), Some(_)))
            && !observed_without_repository(&effect)
        {
            continue;
        }
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
    let mut refs = BTreeSet::from([source.to_string()]);
    let mut causal = BTreeSet::new();
    let mut prior = BTreeSet::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(40);
    for (receipt, _) in current.source_receipts() {
        if std::time::Instant::now() >= deadline {
            return Err(AutoresearchError::SelectionDeferred);
        }
        // Only sibling launches can supply the initial study's entry anchor.
        // Terminal witnesses enter through the selected Operation, not the publisher.
        if declaration.format == evertrace_capture::process_source::FORMAT
            && receipt.source_instance_id == observation.source_instance_id
            && receipt.source_revision == observation.source_revision
            && receipt.observation_role == evertrace_domain::evidence::ObservationRole::Intent
            && matches!(source_candidate(current, receipt.source_observation_id),
                Some(SourceCandidate::Trial(trial)) if trial.study_key == declaration.study_key)
        {
            refs.insert(receipt.source_observation_id.to_string());
            causal.insert(receipt.source_observation_id);
        }
        if declaration.format == evertrace_capture::process_source::WORK_FORMAT
            && evertrace_capture::process_source::is_work_revision(receipt.source_revision.as_str())
            && let Some(SourceCandidate::WorkPlan(old)) =
                source_candidate(current, receipt.source_observation_id)
            && old.definition.study_key == declaration.definition.study_key
            && old.definition.goal == declaration.definition.goal
            && old.definition.scope == declaration.definition.scope
            && old.definition.scope_kind == declaration.definition.scope_kind
        {
            prior.insert(receipt.source_observation_id.to_string());
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
            if declaration.definition.scope_kind == ProcessWorkScope::Repository
                && (scope.repository.is_none() || scope.worktree.is_none())
            {
                continue;
            }
            causal.insert(scope.source);
            refs.extend([
                scope.source.to_string(),
                scope.operation.to_string(),
                scope.effect.to_string(),
            ]);
            refs.extend(scope.repository.map(|id| id.to_string()));
            refs.extend(scope.worktree.map(|id| id.to_string()));
        }
    }
    let mut owners = BTreeSet::new();
    for row in current
        .other_data_rows()
        .filter(|row| row.object_kind.as_deref() == Some("work_binding"))
    {
        if std::time::Instant::now() >= deadline {
            return Err(AutoresearchError::SelectionDeferred);
        }
        let Some(JournalPayload::WorkBindingRecorded(binding)) = row
            .payload_json
            .as_deref()
            .and_then(|json| serde_json::from_str(json).ok())
        else {
            continue;
        };
        let linked = binding
            .evidence_refs
            .iter()
            .filter(|value| prior.contains(*value))
            .filter_map(|reference| {
                reference
                    .parse::<SourceObservationId>()
                    .ok()
                    .and_then(|id| {
                        current
                            .source_observation(id)
                            .map(|(_, seq)| (seq, reference))
                    })
            })
            .min_by_key(|(seq, _)| *seq)
            .map(|(_, reference)| reference);
        if let (Some(reference), Some(owner)) = (linked, binding.primary_binding.workstream_id)
            && owners.insert(owner)
        {
            if owners.len() > 2 {
                return Err(AutoresearchError::EvidenceIncomplete);
            }
            refs.insert(reference.clone());
            refs.insert(binding.operation_id.to_string());
            refs.insert(owner.to_string());
            refs.extend(binding.primary_binding.task_id.map(|id| id.to_string()));
            refs.extend(binding.primary_binding.episode_id.map(|id| id.to_string()));
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
    if let SourceCandidate::TestResult(result) = &envelope {
        let observation = current
            .source_observation(id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?
            .0;
        let launch = current.source_observations().find_map(|(value, _)| {
            (value.source_instance_id == observation.source_instance_id
                && value.source_record_identity.as_str() == result.launch_event
                && value.observation_role == evertrace_domain::evidence::ObservationRole::Intent)
                .then_some(value.source_observation_id)
        });
        let Some(launch) = launch else {
            return Ok(None);
        };
        // Exactly one level: the target is a verified Intent, never another terminal.
        let Some(mut snapshot) = controlled_source_snapshot(current, launch, resolver)? else {
            return Ok(None);
        };
        for kind in ["source_observation", "source_receipt", "evidence_surface"] {
            let key = if kind == "source_receipt" {
                observation.source_receipt_ref.to_string()
            } else {
                id.to_string()
            };
            if let Some(row) = current.selected_source_row(kind, &key)?
                && !snapshot.rows.iter().any(|value| value.row_id == row.row_id)
            {
                snapshot.rows.push(row);
            }
        }
        if snapshot.rows.len() > 256
            || snapshot
                .rows
                .iter()
                .map(|row| row.payload_json.as_ref().map_or(0, |json| json.len()))
                .sum::<usize>()
                > 2 * 1024 * 1024
        {
            return Err(AutoresearchError::EvidenceIncomplete);
        }
        return Ok(Some(snapshot));
    }
    let ordinary_work = matches!(&envelope, SourceCandidate::WorkPlan(plan)
        if plan.format == evertrace_capture::process_source::WORK_FORMAT);
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
            for evidence in process_runtime_groups(
                trial,
                current.source_receipts().map(|(value, _)| value.as_ref()),
            )? {
                refs.extend(evidence.into_iter().map(|id| id.to_string()));
            }
            refs.extend(
                process_runtime_images(
                    trial,
                    current.source_receipts().map(|(value, _)| value.as_ref()),
                )?
                .into_iter()
                .map(|id| id.to_string()),
            );
            refs.insert(opening.to_string());
            let opening_receipt = current
                .source_observation(opening)
                .ok_or(AutoresearchError::EvidenceIncomplete)?
                .0
                .source_receipt_ref;
            let external_key = format!("{}/{}", trial.source_epoch, trial.execution_key);
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(40);
            for row in current.other_data_rows() {
                if std::time::Instant::now() >= deadline {
                    return Err(AutoresearchError::SelectionDeferred);
                }
                if row.object_kind.as_deref() == Some("experiment_run")
                    && let Some(JournalPayload::ExperimentRunRecorded(run)) = row
                        .payload_json
                        .as_deref()
                        .and_then(|json| serde_json::from_str(json).ok())
                    && run.external_system_id.as_deref()
                        == Some(evertrace_capture::process_source::FORMAT)
                    && run.external_run_key.as_deref() == Some(external_key.as_str())
                    && run.source_receipt_refs.contains(&opening_receipt)
                {
                    refs.insert(run.run_id.to_string());
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
        SourceCandidate::TestResult(_) => return Err(AutoresearchError::InvalidInput),
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
            ]);
            refs.extend(scope.repository.map(|repository| repository.to_string()));
            refs.extend(scope.worktree.map(|worktree| worktree.to_string()));
        }
    }
    let mut selected = BTreeSet::new();
    let mut expanded = BTreeSet::new();
    let mut rows = Vec::new();
    let mut bytes = 0_usize;
    let mut episode_heads = BTreeMap::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(40);
    loop {
        let before = selected.len();
        let pending = refs.difference(&expanded).cloned().collect::<Vec<_>>();
        for reference in pending {
            if std::time::Instant::now() >= deadline {
                return Err(AutoresearchError::SelectionDeferred);
            }
            expanded.insert(reference.clone());
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
            if ordinary_work && let JournalPayload::WorkEpisodeRecorded(phase) = &payload {
                let head = if let Some(head) = episode_heads.get(&phase.episode_id) {
                    *head
                } else {
                    let mut latest = (phase.revision_generation, phase.revision_id);
                    let key = phase.episode_id.to_string();
                    for candidate in current.other_data_rows().filter(|row| {
                        row.object_kind.as_deref() == Some("work_episode")
                            && row.object_id.as_deref() == Some(key.as_str())
                    }) {
                        if std::time::Instant::now() >= deadline {
                            return Err(AutoresearchError::SelectionDeferred);
                        }
                        if let Some(JournalPayload::WorkEpisodeRecorded(value)) = candidate
                            .payload_json
                            .as_deref()
                            .and_then(|json| serde_json::from_str(json).ok())
                            && value.revision_generation > latest.0
                        {
                            latest = (value.revision_generation, value.revision_id);
                        }
                    }
                    episode_heads.insert(phase.episode_id, latest.1);
                    latest.1
                };
                if phase.revision_id != head {
                    continue;
                }
            }
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
            if ordinary_work && let JournalPayload::WorkEpisodeRecorded(phase) = &payload {
                // Work namespace continuation needs the current Phase/capture/entry, not
                // its full burst/member history. Segmentation owns that separate window.
                refs.extend([phase.task_id.to_string(), phase.workstream_id.to_string()]);
                refs.extend(phase.entry_worktree_snapshot_id.map(|id| id.to_string()));
                refs.extend(phase.attempt_ids.iter().map(ToString::to_string));
                refs.extend(phase.execution_lane_ids.iter().map(ToString::to_string));
                refs.extend(
                    phase
                        .capture_receipt_revision_ids
                        .iter()
                        .map(ToString::to_string),
                );
                refs.extend(resume_checkpoint_refs(phase).cloned());
            } else if !(ordinary_work
                && matches!(payload, JournalPayload::WorkCheckpointRecorded(_)))
            {
                refs.extend(evertrace_store::projections::read_dependencies_for(
                    row, &payload,
                ));
            }
            refs.extend(row.object_id.iter().cloned());
            refs.extend(row.current_revision_id.iter().cloned());
            if ordinary_work && let JournalPayload::WorkstreamRecorded(stream) = &payload {
                refs.extend(stream.active_episode_id.map(|id| id.to_string()));
            }
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
        if selected.len() == before && refs.len() == expanded.len() {
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
        goal: SourceObservationId,
    },
    Declaration {
        run: Box<ExperimentRun>,
        bindings: Vec<WorkBindingRevision>,
        attempt: Option<Box<Attempt>>,
        command: JournalCommand,
    },
    Result {
        command: JournalCommand,
    },
    Terminal {
        run: Box<ExperimentRun>,
        result: Box<ResultEvidence>,
        command: JournalCommand,
    },
}

/// Recheck the exact protected observation against the current Native publisher before publication.
pub(crate) async fn read_live_root_goal(
    current: &evertrace_store::CurrentFacts,
    source: SourceObservationId,
    runtime: &evertrace_capture::RuntimeSnapshot,
) -> Result<Option<evertrace_capture::goal_source::RootGoal>, AutoresearchError> {
    let (observation, _) = current
        .source_observation(source)
        .ok_or(AutoresearchError::EvidenceIncomplete)?;
    let (receipt, _) = current
        .source_receipt(observation.source_receipt_ref)
        .ok_or(AutoresearchError::EvidenceIncomplete)?;
    let (observation, receipt) = (observation.clone(), receipt.clone());
    let (cas_dir, key_dir) = (runtime.cas_dir.clone(), runtime.device_key_dir.clone());
    tokio::task::spawn_blocking(move || {
        let cas = CasStore::open_existing(cas_dir).map_err(|_| AutoresearchError::Cas)?;
        let resolver = ControlledRunResolver::new(cas);
        Ok(resolver
            .verified_root_goal(&receipt, &observation, Some(&key_dir))
            .ok())
    })
    .await
    .map_err(|_| AutoresearchError::Cas)?
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
            evertrace_capture::process_source::is_work_revision(value.source_revision.as_str())
        }) {
            return self.resolve_process_work(snapshot, &facts, source, context, goal_key_dir);
        }
        if facts.observations.get(&source).is_some_and(|value| {
            value.source_revision.as_str() == evertrace_capture::process_source::SOURCE_REVISION
        }) {
            let observation = facts
                .observations
                .get(&source)
                .ok_or(AutoresearchError::EvidenceIncomplete)?;
            if evertrace_domain::work::NativeTestResult::decode(
                &self.protected_source(&facts, source)?,
            )
            .is_some()
            {
                return self.resolve_process_result(
                    snapshot,
                    &facts,
                    source,
                    context,
                    goal_key_dir,
                );
            }
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
        let limit = if recorded_runtime_source(observation, receipt)
            && receipt.source_revision.as_str()
                == evertrace_capture::process_source::CONDITIONS_SOURCE_REVISION
        {
            evertrace_capture::process_source::SOURCE_BYTES
        } else {
            65536
        };
        let bytes = self
            .cas
            .read_bounded(&digest, limit * 2, limit)
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
        } else if !evertrace_capture::execution_source::is_execution(observation, receipt)
            && !recorded_runtime_source(observation, receipt)
        {
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
        let work = declaration.format == process_source::WORK_FORMAT;
        let (adapter, parser, events) = if work {
            (
                process_source::WORK_ADAPTER_REVISION,
                process_source::WORK_PARSER_REVISION,
                process_source::WORK_ELIGIBLE_EVENTS,
            )
        } else {
            (
                process_source::ADAPTER_REVISION,
                process_source::PARSER_REVISION,
                process_source::ELIGIBLE_EVENTS,
            )
        };
        let manifest = if work {
            evertrace_codex::probe::HostProbeReport::unobserved_source_contract(
                &process_source::work_adapter_version(),
                process_source::WORK_ELIGIBLE_EVENTS,
            )
        } else {
            evertrace_codex::probe::HostProbeReport::native_source_contract(
                &process_source::adapter_version(),
                process_source::ELIGIBLE_EVENTS,
                process_source::FORMAT,
            )
        }
        .map_err(|_| AutoresearchError::UntrustedRunEvidence)?;
        if receipt.identity_domain != declaration.format
            || receipt.source_kind != evertrace_domain::evidence::EvidenceSourceKind::Other
            || receipt.unsupported_record_classification.is_some()
            || receipt.canonicalization_revision != 1
            || receipt.adapter_revision != adapter
            || receipt.adapter_manifest_ref != manifest.manifest().adapter_manifest_id
            || receipt.eligible_event_manifest_ref != events
            || receipt.parser_revision != parser
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
            match declaration.definition.scope_kind {
                ProcessWorkScope::Repository
                    if effect.repository_instance_id.is_none()
                        || effect.worktree_instance_id.is_none() =>
                {
                    continue;
                }
                ProcessWorkScope::NonRepository
                    if !observed_without_repository(effect)
                        || facts.scope_effects.values().any(|(other, _)| {
                            other.operation_id == operation.operation_id
                                && !observed_without_repository(other)
                        }) =>
                {
                    continue;
                }
                _ => {}
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
                    verified.push((command, policy, native_id, effect, goal_id, raw))
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
        let (command, policy, native, effect, goal, goal_raw) = verified
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
        let mut continuation = BTreeSet::new();
        if work {
            for old in facts.receipts.values().filter(|receipt| {
                receipt.source_observation_id != source
                    && process_source::is_work_revision(receipt.source_revision.as_str())
                    && receipt.source_sequence == 1
            }) {
                let reference = old.source_observation_id.to_string();
                let owned = facts.bindings.values().any(|binding| {
                    binding.primary_binding.task_id == Some(task.task_id)
                        && binding.evidence_refs.contains(&reference)
                });
                if !owned {
                    continue;
                }
                let raw = self.protected_source(facts, old.source_observation_id)?;
                let prior = ProcessWorkDeclaration::decode(&raw, old)
                    .ok_or(AutoresearchError::EvidenceIncomplete)?;
                if prior.definition.study_key != declaration.definition.study_key
                    || prior.definition.scope != declaration.definition.scope
                    || prior.definition.goal != declaration.definition.goal
                    || prior.definition.scope_kind != declaration.definition.scope_kind
                {
                    continue;
                }
                if !facts.bindings.values().any(|binding| {
                    binding.assignment_status == AssignmentStatus::Resolved
                        && binding.primary_binding.task_id == Some(task.task_id)
                        && binding.evidence_refs.contains(&reference)
                }) {
                    return Err(AutoresearchError::EvidenceIncomplete);
                }
                continuation.insert(reference);
            }
        }
        let code = if declaration.definition.scope_kind == ProcessWorkScope::NonRepository {
            None
        } else if work {
            let repository = effect
                .repository_instance_id
                .ok_or(AutoresearchError::EvidenceIncomplete)?;
            // Observe carries no before/after change claim. Its independently captured
            // entry snapshot is linked by the exact Native source, not by a path or title.
            let prefix = format!("native-execution-directory:{native}:");
            let anchors = facts
                .snapshots
                .values()
                .filter(|anchor| {
                    Some(anchor.worktree_instance_id) == effect.worktree_instance_id
                        && anchor.capture_status
                            == evertrace_domain::repository::SnapshotCaptureStatus::Complete
                        && anchor
                            .evidence_refs
                            .iter()
                            .any(|reference| reference.starts_with(&prefix))
                })
                .collect::<Vec<_>>();
            let anchor = match anchors.as_slice() {
                [anchor] => Some(*anchor),
                [] => {
                    // Continuation keeps the open Phase's original entry anchor. This does not
                    // claim a fresh filesystem state or permit a new Work birth without one.
                    let phases = facts
                        .workstreams
                        .values()
                        .filter(|stream| {
                            stream.task_id == task.task_id
                                && stream.repository_instance_id == Some(repository)
                                && stream.active_worktree_instance_id == effect.worktree_instance_id
                                && !stream.status.is_terminal()
                                && continuation.iter().any(|source| {
                                    facts
                                        .bindings
                                        .values()
                                        .any(|binding| source_owns_stream(binding, stream, source))
                                })
                        })
                        .filter_map(|stream| {
                            stream
                                .active_episode_id
                                .and_then(|id| facts.current_episodes.get(&id))
                                .and_then(|revision| facts.episodes.get(revision))
                        })
                        .filter(|phase| {
                            phase.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Open
                                && phase.repository_instance_id == Some(repository)
                                && phase.worktree_instance_id == effect.worktree_instance_id
                        })
                        .collect::<Vec<_>>();
                    match phases.as_slice() {
                        [phase] => phase
                            .entry_worktree_snapshot_id
                            .and_then(|id| facts.snapshots.get(&id))
                            .filter(|entry| {
                                Some(entry.worktree_instance_id) == effect.worktree_instance_id
                                && entry.capture_status
                                    == evertrace_domain::repository::SnapshotCaptureStatus::Complete
                            }),
                        _ => None,
                    }
                }
                _ => None,
            };
            let Some(anchor) = anchor else {
                return Ok((ControlledRunCommand::NoDelta, Some(policy)));
            };
            Some((repository, anchor))
        } else {
            let (Some(repository), Some(worktree)) =
                (effect.repository_instance_id, effect.worktree_instance_id)
            else {
                return Err(AutoresearchError::EvidenceIncomplete);
            };
            let mut anchors = Vec::new();
            for launch in facts.observations.values().filter(|value| {
                value.source_instance_id == observation.source_instance_id
                    && value.source_revision == observation.source_revision
                    && value.observation_role == evertrace_domain::evidence::ObservationRole::Intent
            }) {
                let launch_receipt = facts.receipt(launch.source_observation_id)?;
                let raw = self.protected_source(facts, launch.source_observation_id)?;
                let Some(trial) = ProcessTrialDeclaration::decode(&raw, launch, launch_receipt)
                    .filter(|trial| trial.study_key == declaration.study_key)
                else {
                    continue;
                };
                let direct = format!(
                    "native-execution-directory:{}:",
                    launch.source_observation_id
                );
                let native = format!("native-execution-directory:{native}:");
                for anchor in facts.snapshots.values().filter(|anchor| {
                    anchor.worktree_instance_id == worktree
                        && anchor.capture_status
                            == evertrace_domain::repository::SnapshotCaptureStatus::Complete
                        && anchor.head_oid.as_deref() == Some(trial.source_anchor.commit.as_str())
                        && anchor.tree_oid.as_deref() == Some(trial.source_anchor.tree.as_str())
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
            Some((
                repository,
                facts
                    .snapshots
                    .get(&anchor)
                    .ok_or(AutoresearchError::EvidenceIncomplete)?,
            ))
        };
        let anchor = ProcessWorkAnchor {
            code,
            session: &facts.receipt(native)?.source_session_ref,
            effect,
            root_source: native,
            goal_source: goal,
            goal_raw: &goal_raw,
            resolver: self,
            ordinary_work: work,
        };
        let command = process_work_command(
            snapshot,
            facts,
            source,
            task,
            &anchor,
            &declaration.definition,
            &continuation,
            context,
        )?;
        Ok((
            command.map_or(ControlledRunCommand::NoDelta, |command| {
                ControlledRunCommand::WorkRoot { command, goal }
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

    fn resolve_process_result(
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
        use evertrace_domain::work::{
            NativeTestResult, is_native_test_contract_parser, is_native_test_parser,
        };
        let terminal = facts
            .observations
            .get(&source)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let raw = self.protected_source(facts, source)?;
        let result =
            NativeTestResult::decode(&raw).ok_or(AutoresearchError::UntrustedRunEvidence)?;
        let launch = facts
            .observations
            .values()
            .find(|value| {
                value.source_instance_id == terminal.source_instance_id
                    && value.source_record_identity.as_str() == result.launch_event
            })
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let launch_source = launch.source_observation_id;
        let (command, policy) =
            self.resolve_process_trial(snapshot, facts, launch_source, context, key_dir)?;
        if !matches!(command, ControlledRunCommand::NoDelta) || policy.is_none() {
            return Ok((command, policy));
        }
        let key = format!("{}/{}", result.source_epoch, result.execution_key);
        let runs = facts
            .runs
            .runs
            .values()
            .filter(|run| {
                run.external_system_id.as_deref() == Some(evertrace_capture::process_source::FORMAT)
                    && run.external_run_key.as_deref() == Some(key.as_str())
                    && run.source_receipt_refs.contains(&launch.source_receipt_ref)
            })
            .collect::<Vec<_>>();
        let [run] = runs.as_slice() else {
            return Ok((ControlledRunCommand::NoDelta, policy));
        };
        if !is_native_test_parser(&run.metric_extractor_version) || !run.is_declaration_only() {
            return Ok((ControlledRunCommand::NoDelta, policy));
        }
        if terminal.source_role != SourceRole::Tool
            || terminal.content_trust != ContentTrust::Observed
            || terminal.capture_completeness != CaptureCompleteness::Complete
            || terminal.correlation.exact_key().is_none()
            || terminal.correlation.exact_key() != launch.correlation.exact_key()
        {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        require_bound_operations(
            facts,
            source,
            false,
            run.run_id,
            run.attempt_id
                .ok_or(AutoresearchError::EvidenceIncomplete)?,
            run.workstream_id,
        )?;
        if is_native_test_contract_parser(&run.metric_extractor_version)
            && result.metric().is_some()
        {
            return self
                .complete(snapshot, run.run_id, source, context.clone())
                .map(|command| (command, policy));
        }
        let digest = CasDigest::from_str(&facts.receipt(source)?.cas_ref)
            .map_err(|_| AutoresearchError::Cas)?;
        let cas = CasId::from_digest(*digest.as_bytes());
        if facts.runs.results.values().any(|value| {
            value.experiment_run_id == run.run_id
                && value.raw_cas_refs == [cas]
                && value.raw_artifact_refs.iter().any(|id| {
                    facts.runs.artifacts.get(id).is_some_and(|artifact| {
                        artifact.revision.source_observation_refs == [source]
                    })
                })
        }) {
            return Ok((ControlledRunCommand::NoDelta, policy));
        }
        let artifact =
            self.process_result_artifact(facts, run, source, cas, None, context.occurred_at_us)?;
        let mut parsed = ResultEvidenceService::new(self.cas.clone()).parse(
            run,
            ResultParseRequest {
                scope: ResultScope::Partial,
                raw_cas_refs: vec![cas],
                created_at_us: context.occurred_at_us,
            },
        )?;
        parsed.raw_artifact_refs = vec![artifact.work_artifact_id];
        parsed.parser_receipt.input_artifact_refs = parsed.raw_artifact_refs.clone();
        let mut payloads = Vec::new();
        if !facts
            .runs
            .artifacts
            .contains_key(&artifact.work_artifact_id)
        {
            payloads.push(JournalPayload::WorkArtifactRecorded(Box::new(artifact)));
        }
        payloads.push(JournalPayload::ResultEvidenceRecorded(Box::new(parsed)));
        let command = payload_command(context.clone(), payloads)?;
        Ok((ControlledRunCommand::Result { command }, policy))
    }

    fn process_result_artifact(
        &self,
        facts: &ControlledFacts,
        run: &ExperimentRun,
        source: SourceObservationId,
        cas: CasId,
        producer: Option<ArtifactActor>,
        created_at_us: i64,
    ) -> Result<WorkArtifact, AutoresearchError> {
        let snapshot = facts
            .snapshots
            .get(&run.code_snapshot_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let worktree = facts
            .worktrees
            .get(&snapshot.worktree_instance_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let scope = ArtifactScope::Worktree {
            repository_instance_id: worktree.repository_instance_id,
            worktree_instance_id: snapshot.worktree_instance_id,
        };
        let produced_by_refs = producer.into_iter().collect::<Vec<_>>();
        if let Some(artifact) = facts.runs.artifacts.values().find(|artifact| {
            artifact.revision.scope == scope
                && artifact.revision.content_blob_ref == Some(cas)
                && artifact.revision.source_observation_refs == [source]
                && artifact.revision.produced_by_refs == produced_by_refs
                && artifact.revision.payload_status == ArtifactPayloadStatus::Available
                && artifact.revision.kind
                    == evertrace_domain::work::WorkArtifactKind::ExperimentOutput
        }) {
            return Ok(artifact.clone());
        }
        ArtifactService::new(self.cas.clone()).create(ArtifactRevision {
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            kind: evertrace_domain::work::WorkArtifactKind::ExperimentOutput,
            logical_name: "Native test output".into(),
            scope,
            media_type: "application/json".into(),
            content_blob_ref: Some(cas),
            external_reference: None,
            content_fingerprint: None,
            payload_status: ArtifactPayloadStatus::Available,
            produced_by_refs,
            consumed_by_refs: Vec::new(),
            source_observation_refs: vec![source],
            derivability: evertrace_domain::work::ArtifactDerivability::Original,
            retention: evertrace_domain::work::ArtifactRetention::Task,
            created_at_us,
        })
    }

    fn complete_process_trial(
        &self,
        facts: &ControlledFacts,
        current: &ExperimentRun,
        source: SourceObservationId,
        context: AutoresearchCommandContext,
    ) -> Result<ControlledRunCommand, AutoresearchError> {
        use evertrace_capture::process_source;
        use evertrace_domain::work::{
            NATIVE_TEST_COHORT_PARSER_VERSION, NativeTestContract, NativeTestResult,
            is_native_test_contract_parser,
        };
        if !is_native_test_contract_parser(&current.metric_extractor_version) {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        if !current.is_declaration_only() {
            return Ok(ControlledRunCommand::NoDelta);
        }
        let launches = current
            .source_receipt_refs
            .iter()
            .filter_map(|id| facts.receipts.get(id))
            .filter(|receipt| receipt.source_revision.as_str() == process_source::SOURCE_REVISION)
            .filter_map(|receipt| facts.observations.get(&receipt.source_observation_id))
            .filter(|value| {
                value.observation_role == evertrace_domain::evidence::ObservationRole::Intent
            })
            .collect::<Vec<_>>();
        let [launch] = launches.as_slice() else {
            return Err(AutoresearchError::EvidenceIncomplete);
        };
        let raw = self.protected_source(facts, launch.source_observation_id)?;
        let trial = ProcessTrialDeclaration::decode(
            &raw,
            launch,
            facts.receipt(launch.source_observation_id)?,
        )
        .ok_or(AutoresearchError::UntrustedRunEvidence)?;
        let anchor = if current.metric_extractor_version == NATIVE_TEST_COHORT_PARSER_VERSION {
            let opening = facts
                .process_opening(launch.source_observation_id)?
                .source_observation_id;
            let plan = ProcessWorkDeclaration::decode(
                &self.protected_source(facts, opening)?,
                facts.receipt(opening)?,
            )
            .ok_or(AutoresearchError::UntrustedRunEvidence)?;
            if trial.study_key != plan.study_key || trial.source_epoch != plan.source_epoch {
                return Err(AutoresearchError::UntrustedRunEvidence);
            }
            let Some((attempt, witness)) = process_trial_target(
                facts,
                &trial,
                &plan,
                launch.source_observation_id,
                opening,
                Some(current),
            )?
            else {
                return Ok(ControlledRunCommand::NoDelta);
            };
            let entry = attempt
                .episode_id
                .and_then(|id| facts.current_episodes.get(&id))
                .and_then(|revision| facts.episodes.get(revision))
                .and_then(|episode| episode.entry_worktree_snapshot_id)
                .and_then(|id| facts.snapshots.get(&id));
            if current.attempt_id != Some(attempt.attempt_id)
                || NativeTestContract::code_basis(witness, entry).worktree_snapshot_id
                    != current.code_snapshot_id
            {
                return Err(AutoresearchError::UntrustedRunEvidence);
            }
            witness
        } else {
            facts
                .snapshots
                .get(&current.code_snapshot_id)
                .ok_or(AutoresearchError::EvidenceIncomplete)?
        };
        let contract = NativeTestContract::decode(
            &raw,
            anchor,
            launch.source_observation_id,
            facts
                .receipt(launch.source_observation_id)?
                .source_revision
                .as_str(),
        )
        .ok_or(AutoresearchError::UntrustedRunEvidence)?;
        let (fingerprint, receipts) = self.process_runtime_environment(facts, &trial)?;
        let images = receipts
            .iter()
            .filter_map(|id| facts.receipts.get(id))
            .filter(|receipt| {
                receipt.source_revision.as_str() == process_source::IMAGE_SOURCE_REVISION
                    && (receipt.adapter_revision, receipt.parser_revision) == (3, 3)
            })
            .collect::<Vec<_>>();
        let [image] = images.as_slice() else {
            return Err(AutoresearchError::EvidenceIncomplete);
        };
        if !contract.matches_run(current)
            || fingerprint != current.environment_fingerprint
            || self.protected_source(facts, image.source_observation_id)? != raw
        {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        let terminal = facts
            .observations
            .get(&source)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let receipt = facts.receipt(source)?;
        let terminal_raw = self.protected_source(facts, source)?;
        let event = NativeTestResult::decode(&terminal_raw)
            .ok_or(AutoresearchError::UntrustedRunEvidence)?;
        let ended_at = serde_json::from_slice::<serde_json::Value>(&terminal_raw)
            .ok()
            .and_then(|value| value["time_us"].as_i64())
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        if terminal.content_trust != ContentTrust::Observed
            || terminal.capture_completeness != CaptureCompleteness::Complete
            || receipt.capture_completeness != CaptureCompleteness::Complete
            || receipt.source_revision.as_str() != process_source::SOURCE_REVISION
            || terminal.source_role != SourceRole::Tool
            || terminal.source_instance_id != launch.source_instance_id
            || launch.correlation.exact_key().is_none()
            || terminal.correlation.exact_key() != launch.correlation.exact_key()
            || event.launch_event != launch.source_record_identity.as_str()
            || event.event_key != terminal.source_record_identity.as_str()
            || current.external_run_key.as_deref()
                != Some(format!("{}/{}", event.source_epoch, event.execution_key).as_str())
            || event.metric().is_none()
            || ended_at < contract.started_at_us
        {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        let attempt = current
            .attempt_id
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        require_bound_operations(
            facts,
            launch.source_observation_id,
            true,
            current.run_id,
            attempt,
            current.workstream_id,
        )?;
        require_bound_operations(
            facts,
            source,
            false,
            current.run_id,
            attempt,
            current.workstream_id,
        )?;
        let cas = CasId::from_digest(
            *receipt
                .cas_ref
                .parse::<CasDigest>()
                .map_err(|_| AutoresearchError::Cas)?
                .as_bytes(),
        );
        let artifact = self.process_result_artifact(
            facts,
            current,
            source,
            cas,
            Some(ArtifactActor::ExperimentRun(current.run_id)),
            context.occurred_at_us,
        )?;
        let mut result = ResultEvidenceService::new(self.cas.clone()).parse(
            current,
            ResultParseRequest {
                scope: ResultScope::Partial,
                raw_cas_refs: vec![cas],
                created_at_us: context.occurred_at_us,
            },
        )?;
        if result.parsed_metric != event.metric()
            || result.parser_receipt.status != ParserStatus::Parsed
        {
            return Err(AutoresearchError::ImmutableConflict);
        }
        let mut next = current.clone();
        next.revision_id = RevisionId::new_v7();
        next.parent_revision_id = Some(current.revision_id);
        next.observability = RunObservability::Full;
        next.execution_status = RunExecutionStatus::Completed;
        next.contract_validity = RunContractValidity::Valid;
        next.started_at_us = Some(contract.started_at_us);
        next.ended_at_us = Some(ended_at);
        next.terminal_evidence_refs = vec![receipt.source_receipt_id];
        next.work_artifact_refs.push(artifact.work_artifact_id);
        next.work_artifact_refs.sort();
        next.work_artifact_refs.dedup();
        current
            .validate_successor(&next)
            .map_err(|_| AutoresearchError::ImmutableConflict)?;
        result.experiment_run_revision_id = next.revision_id;
        result.result_scope = ResultScope::Complete;
        result.raw_artifact_refs = vec![artifact.work_artifact_id];
        result.parser_receipt.input_artifact_refs = result.raw_artifact_refs.clone();
        result.completeness = EvidenceCompleteness::Complete;
        result.verifier_receipt = Some(VerifierReceipt {
            verifier_version: RESULT_VERIFIER_VERSION.into(),
            status: VerifierStatus::Passed,
            failure_code: None,
        });
        result
            .validate()
            .map_err(|_| AutoresearchError::InvalidInput)?;
        let mut payloads = Vec::new();
        if !facts
            .runs
            .artifacts
            .contains_key(&artifact.work_artifact_id)
        {
            payloads.push(JournalPayload::WorkArtifactRecorded(Box::new(artifact)));
        }
        payloads.extend([
            JournalPayload::ExperimentRunRecorded(Box::new(next.clone())),
            JournalPayload::ResultEvidenceRecorded(Box::new(result.clone())),
        ]);
        if current.metric_extractor_version == NATIVE_TEST_COHORT_PARSER_VERSION {
            let stream = facts
                .workstreams
                .get(&current.workstream_id)
                .ok_or(AutoresearchError::EvidenceIncomplete)?;
            let launch_phase = facts
                .attempts
                .get(&attempt)
                .and_then(|value| value.episode_id)
                .and_then(|id| facts.current_episodes.get(&id))
                .and_then(|id| facts.episodes.get(id))
                .ok_or(AutoresearchError::EvidenceIncomplete)?;
            if evertrace_domain::work::awaiting_experiment_result(stream, launch_phase) {
                let mut resumed = stream.clone();
                resumed.revision_id = RevisionId::new_v7();
                resumed.predecessor_revision_id = Some(stream.revision_id);
                resumed.status = evertrace_domain::work::WorkstreamStatus::Active;
                resumed.phase_contract = evertrace_domain::work::experiment_analysis_phase(
                    &next,
                    result.result_evidence_id,
                );
                resumed.source_watermark = facts.runs.frontier.max(
                    stream
                        .source_watermark
                        .checked_add(1)
                        .ok_or(AutoresearchError::InvalidInput)?,
                );
                // The accepted result anchors the analysis. Its launch snapshot is not a fresh Git observation.
                let analysis =
                    crate::work::episode::new_episode(&resumed, None, resumed.source_watermark)
                        .map_err(|_| AutoresearchError::ImmutableConflict)?;
                resumed.active_episode_id = Some(analysis.episode_id);
                payloads.extend([
                    JournalPayload::WorkEpisodeRecorded(Box::new(analysis)),
                    JournalPayload::WorkstreamRecorded(Box::new(resumed)),
                ]);
            }
        }
        let command = payload_command(context, payloads)?;
        Ok(ControlledRunCommand::Terminal {
            run: Box::new(next),
            result: Box::new(result),
            command,
        })
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
        let launch_raw = self.protected_source(&facts, source)?;
        let trial =
            ProcessTrialDeclaration::decode(&launch_raw, observation, facts.receipt(source)?)
                .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let plan = ProcessWorkDeclaration::decode(
            &self.protected_source(&facts, opening_source)?,
            facts.receipt(opening_source)?,
        )
        .ok_or(AutoresearchError::EvidenceIncomplete)?;
        if trial.study_key != plan.study_key || trial.source_epoch != plan.source_epoch {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        let external_key = format!("{}/{}", trial.source_epoch, trial.execution_key);
        let opening_receipt = facts.receipt(opening_source)?.source_receipt_id;
        let existing = facts
            .runs
            .runs
            .values()
            .filter(|run| {
                run.external_system_id.as_deref() == Some(evertrace_capture::process_source::FORMAT)
                    && run.external_run_key.as_deref() == Some(external_key.as_str())
                    && run.source_receipt_refs.contains(&opening_receipt)
            })
            .collect::<Vec<_>>();
        if existing.len() > 1 {
            return Err(AutoresearchError::ImmutableConflict);
        }
        let (run, attempt, is_new) = if let Some(run) = existing.first() {
            let mut expected = vec![
                facts.receipt(source)?.source_receipt_id,
                facts.receipt(opening_source)?.source_receipt_id,
            ];
            expected.sort();
            if !expected
                .iter()
                .all(|id| run.source_receipt_refs.contains(id))
                || run.comparison_execution_binding.is_some()
                || run.origin != RunOrigin::External
            {
                return Err(AutoresearchError::ImmutableConflict);
            }
            let native = run
                .source_receipt_refs
                .iter()
                .filter(|id| !expected.contains(id))
                .collect::<Vec<_>>();
            if !native.is_empty() {
                let (fingerprint, receipts) = self.process_runtime_environment(&facts, &trial)?;
                if run.environment_fingerprint != fingerprint
                    || native.iter().any(|id| !receipts.contains(id))
                {
                    return Err(AutoresearchError::ImmutableConflict);
                }
            }
            let attempt = run
                .attempt_id
                .and_then(|id| facts.attempts.get(&id))
                .ok_or(AutoresearchError::EvidenceIncomplete)?;
            ((*run).clone(), attempt, false)
        } else {
            let Some((attempt, anchor)) =
                process_trial_target(&facts, &trial, &plan, source, opening_source, None)?
            else {
                return Ok(ControlledRunCommand::NoDelta);
            };
            let (fingerprint, mut receipts) = self.process_runtime_environment(&facts, &trial)?;
            let mut input =
                process_trial_input(&trial, attempt, anchor, fingerprint, context.occurred_at_us)?;
            use evertrace_domain::work::NativeTestContract;
            let measured_exact = observation.correlation.exact_key().is_some()
                && receipts.iter().any(|id| {
                    facts.receipts.get(id).is_some_and(|receipt| {
                        receipt.source_revision.as_str()
                            == evertrace_capture::process_source::IMAGE_SOURCE_REVISION
                            && (receipt.adapter_revision, receipt.parser_revision) == (3, 3)
                    })
                });
            let harness = facts.receipt(source)?.source_revision.as_str();
            // Don't freeze a measured launch into the legacy extractor while its snapshot is pending.
            if measured_exact
                && NativeTestContract::awaits_direct_witness(&launch_raw, anchor, source, harness)
            {
                return Ok(ControlledRunCommand::NoDelta);
            }
            if measured_exact
                && let Some(contract) =
                    NativeTestContract::decode(&launch_raw, anchor, source, harness)
            {
                input.data_fingerprint = contract.data_fingerprint;
                input.normalized_config = contract.normalized_config;
                input.variable_declaration = contract.variable_declaration;
                input.metric_extractor_version =
                    evertrace_domain::work::NATIVE_TEST_COHORT_PARSER_VERSION.into();
                let entry = attempt
                    .episode_id
                    .and_then(|id| facts.current_episodes.get(&id))
                    .and_then(|revision| facts.episodes.get(revision))
                    .and_then(|episode| episode.entry_worktree_snapshot_id)
                    .and_then(|id| facts.snapshots.get(&id));
                input.code_snapshot_id =
                    NativeTestContract::code_basis(anchor, entry).worktree_snapshot_id;
                input.created_at_us = input.created_at_us.min(contract.started_at_us);
            }
            receipts.extend([facts.receipt(source)?.source_receipt_id, opening_receipt]);
            input.source_receipt_refs = receipts;
            let mut run = create_experiment_run(attempt, input)?;
            run.origin = RunOrigin::External;
            run.external_system_id = Some(evertrace_capture::process_source::FORMAT.into());
            run.external_run_key = Some(external_key);
            run.validate()
                .map_err(|_| AutoresearchError::InvalidInput)?;
            (run, attempt, true)
        };
        let bindings =
            self.process_trial_bindings(&facts, source, &trial, opening_source, &run, attempt)?;
        let active = if observation.correlation.exact_key().is_some() {
            self.activate_process_attempt(&facts, &plan, &trial, attempt, snapshot.frontier)?
        } else {
            None
        };
        if !is_new && bindings.is_empty() && active.is_none() {
            return Ok(ControlledRunCommand::NoDelta);
        }
        let (mut payloads, mut revision) = run_binding_updates(attempt, &bindings)?;
        if let Some(active) = active {
            let mut next = revision.take().unwrap_or_else(|| active.clone());
            next.execution_status = active.execution_status;
            next.execution_lane_ids = active.execution_lane_ids;
            next.source_watermark = next.source_watermark.max(active.source_watermark);
            attempt
                .validate_successor(&next)
                .map_err(|_| AutoresearchError::ImmutableConflict)?;
            payloads.retain(|payload| !matches!(payload, JournalPayload::AttemptRecorded(_)));
            payloads.push(JournalPayload::AttemptRecorded(Box::new(next.clone())));
            revision = Some(next);
        }
        if is_new {
            payloads.insert(
                0,
                JournalPayload::ExperimentRunRecorded(Box::new(run.clone())),
            );
        }
        let command = payload_command(context.clone(), payloads)?;
        Ok(ControlledRunCommand::Declaration {
            run: Box::new(run),
            bindings,
            attempt: revision.map(Box::new),
            command,
        })
    }

    fn activate_process_attempt(
        &self,
        facts: &ControlledFacts,
        plan: &ProcessWorkDeclaration,
        trial: &ProcessTrialDeclaration,
        attempt: &Attempt,
        watermark: u64,
    ) -> Result<Option<Attempt>, AutoresearchError> {
        use evertrace_domain::work::{
            AttemptExecutionStatus, AttemptLifecycleStatus, EpisodeLifecycle,
        };
        if attempt.execution_status != AttemptExecutionStatus::Proposed
            || attempt.lifecycle_status != AttemptLifecycleStatus::Active
            || plan.controller.pid != trial.controller.pid
            || plan.controller.start_ticks != trial.controller.start_ticks
        {
            return Ok(None);
        }
        let episode = attempt
            .episode_id
            .and_then(|id| facts.current_episodes.get(&id))
            .and_then(|revision| facts.episodes.get(revision))
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        if episode.lifecycle_status != EpisodeLifecycle::Open
            || facts
                .workstreams
                .get(&attempt.workstream_id)
                .is_none_or(|stream| {
                    stream.status.is_terminal() || stream.active_episode_id != attempt.episode_id
                })
            || episode.phase_contract != plan.definition.phase
            || attempt.strategy_contract != plan.definition.strategy
        {
            return Ok(None);
        }
        let mut carriers = BTreeSet::new();
        for binding in facts.bindings.values().filter(|binding| {
            binding.assignment_status == AssignmentStatus::Resolved
                && binding.primary_binding.task_id == Some(attempt.task_id)
                && binding.primary_binding.workstream_id == Some(attempt.workstream_id)
                && binding
                    .primary_binding
                    .episode_id
                    .is_none_or(|id| Some(id) == attempt.episode_id)
        }) {
            let Some(operation) = facts.operations.get(&binding.operation_id) else {
                continue;
            };
            let Some(lane) = operation.execution_lane_id else {
                continue;
            };
            if !episode.execution_lane_ids.contains(&lane)
                || !facts
                    .execution_lanes
                    .get(&lane)
                    .is_some_and(|lane| lane.status == LaneStatus::Active)
            {
                continue;
            }
            for source in &operation.input_source_observation_refs {
                let Some(observation) = facts.observations.get(source) else {
                    continue;
                };
                let receipt = facts.receipt(*source)?;
                if !evertrace_capture::execution_source::is_execution(observation, receipt) {
                    continue;
                }
                let bytes = self.protected_source(facts, *source)?;
                if evertrace_capture::execution_source::execution_directory(
                    observation,
                    receipt,
                    &bytes,
                ) == Some((
                    plan.definition.scope.clone(),
                    trial.controller.pid,
                    trial.controller.start_ticks,
                )) {
                    carriers.insert(lane);
                }
            }
        }
        let lane = match carriers.into_iter().collect::<Vec<_>>().as_slice() {
            [lane] => *lane,
            _ => return Ok(None),
        };
        match crate::work::attempt::revise_execution(
            attempt,
            AttemptExecutionStatus::Active,
            vec![lane],
            vec![],
            None,
            vec![],
            watermark,
        )
        .map_err(|_| AutoresearchError::ImmutableConflict)?
        {
            crate::work::attempt::AttemptResolution::Revision(value) => Ok(Some(*value)),
            crate::work::attempt::AttemptResolution::NoDelta => Ok(None),
        }
    }

    fn process_runtime_environment(
        &self,
        facts: &ControlledFacts,
        trial: &ProcessTrialDeclaration,
    ) -> Result<(String, Vec<SourceReceiptId>), AutoresearchError> {
        use evertrace_capture::process_source;
        let process = trial
            .process
            .as_ref()
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let argv = trial
            .argv
            .as_ref()
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let command = argv
            .iter()
            .flat_map(|arg| arg.bytes().chain(std::iter::once(0)))
            .collect::<Vec<_>>();
        let mut fingerprint = None;
        let mut receipts = Vec::new();
        for group in process_runtime_groups(trial, facts.receipts.values())? {
            let mut raw = Vec::new();
            for id in group {
                let receipt = facts.receipt(id)?;
                let observation = facts
                    .observations
                    .get(&id)
                    .ok_or(AutoresearchError::EvidenceIncomplete)?;
                if !recorded_runtime_source(observation, receipt) {
                    return Err(AutoresearchError::UntrustedRunEvidence);
                }
                raw.push(self.protected_source(facts, id)?);
                receipts.push(receipt.source_receipt_id);
            }
            let [stat, actual_command, environment, conditions] = raw.as_slice() else {
                return Err(AutoresearchError::EvidenceIncomplete);
            };
            let stat =
                std::str::from_utf8(stat).map_err(|_| AutoresearchError::EvidenceIncomplete)?;
            let (head, fields) = stat
                .rsplit_once(") ")
                .ok_or(AutoresearchError::EvidenceIncomplete)?;
            let fields = fields.split_whitespace().collect::<Vec<_>>();
            if head
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                != process["pid"].as_u64()
                || fields.first().is_none_or(|value| *value == "Z")
                || fields.get(1).and_then(|value| value.parse::<u32>().ok())
                    != Some(trial.controller.pid)
                || fields.get(19).and_then(|value| value.parse::<u64>().ok())
                    != process["start_ticks"].as_u64()
                || actual_command != &command
                || !environment.ends_with(&[0])
            {
                return Err(AutoresearchError::UntrustedRunEvidence);
            }
            let mut actual_environment = BTreeMap::new();
            for entry in environment[..environment.len() - 1].split(|byte| *byte == 0) {
                let entry = std::str::from_utf8(entry)
                    .map_err(|_| AutoresearchError::UntrustedRunEvidence)?;
                let (key, value) = entry
                    .split_once('=')
                    .ok_or(AutoresearchError::UntrustedRunEvidence)?;
                if actual_environment.insert(key, value).is_some() {
                    return Err(AutoresearchError::UntrustedRunEvidence);
                }
            }
            let environment = serde_json::to_value(actual_environment)
                .map_err(|_| AutoresearchError::InvalidInput)?;
            let conditions: serde_json::Value = serde_json::from_slice(conditions)
                .map_err(|_| AutoresearchError::EvidenceIncomplete)?;
            if conditions["format"] != process_source::CONDITIONS_SOURCE_REVISION
                || conditions.as_object().is_none_or(|value| value.len() != 6)
                || conditions["process"] != *process
                || conditions["environment"] != environment
                || environment != trial.config["environment"]
                || conditions["python"]["version"] != trial.config["python"]
                || conditions["framework"]["name"] != trial.config["framework"]
                || conditions["framework"]["version"] != trial.config["framework_version"]
            {
                return Err(AutoresearchError::UntrustedRunEvidence);
            }
            let packages = conditions["packages"]
                .as_array()
                .ok_or(AutoresearchError::EvidenceIncomplete)?;
            let names = packages
                .iter()
                .filter_map(|value| value["name"].as_str())
                .collect::<BTreeSet<_>>();
            if names != BTreeSet::from(["pytest", "pluggy", "iniconfig", "packaging", "Pygments"])
                || packages.len() != names.len()
                || packages.iter().any(|value| {
                    ["metadata", "record"]
                        .iter()
                        .any(|field| value[field].as_str().is_none_or(str::is_empty))
                })
            {
                return Err(AutoresearchError::EvidenceIncomplete);
            }
            let current = runtime_environment_fingerprint(&conditions)?;
            if fingerprint
                .as_ref()
                .is_some_and(|previous| previous != &current)
            {
                return Err(AutoresearchError::ImmutableConflict);
            }
            fingerprint = Some(current);
        }
        let mut measured = None;
        for id in process_runtime_images(trial, facts.receipts.values())? {
            let receipt = facts.receipt(id)?;
            let observation = facts
                .observations
                .get(&id)
                .ok_or(AutoresearchError::EvidenceIncomplete)?;
            if observation.content_trust != ContentTrust::Observed
                || observation.capture_completeness != CaptureCompleteness::Complete
                || receipt.capture_completeness != CaptureCompleteness::Complete
            {
                continue;
            }
            let raw: ProcessTrialDeclaration =
                serde_json::from_slice(&self.protected_source(facts, id)?)
                    .map_err(|_| AutoresearchError::UntrustedRunEvidence)?;
            if !matches!(
                (receipt.adapter_revision, receipt.parser_revision),
                (1, 1) | (2, 2) | (3, 3)
            ) || observation.observation_role
                != evertrace_domain::evidence::ObservationRole::StateProbe
                || observation.source_role != SourceRole::Tool
                || receipt.identity_domain != process_source::IMAGE_SOURCE_REVISION
                || receipt.identity_strength
                    != evertrace_domain::evidence::IdentityStrength::StableNative
                || raw.event_key != trial.event_key
                || raw.source_epoch != trial.source_epoch
                || raw.execution_key != trial.execution_key
                || raw.config != trial.config
                || !receipt
                    .source_record_identity
                    .as_str()
                    .starts_with("measured-runtime-v1:")
            {
                return Err(AutoresearchError::UntrustedRunEvidence);
            }
            let current = receipt.source_record_identity.as_str().to_owned();
            if measured
                .as_ref()
                .is_some_and(|previous| previous != &current)
            {
                return Err(AutoresearchError::ImmutableConflict);
            }
            measured = Some(current);
            receipts.push(receipt.source_receipt_id);
        }
        receipts.sort();
        receipts.dedup();
        Ok((
            measured
                .or(fingerprint)
                .ok_or(AutoresearchError::EvidenceIncomplete)?,
            receipts,
        ))
    }

    fn process_trial_bindings(
        &self,
        facts: &ControlledFacts,
        source: SourceObservationId,
        trial: &ProcessTrialDeclaration,
        opening: SourceObservationId,
        run: &ExperimentRun,
        attempt: &Attempt,
    ) -> Result<Vec<WorkBindingRevision>, AutoresearchError> {
        use evertrace_capture::process_source;
        use evertrace_domain::evidence::{ObservationRole, OperationKind};
        let launch = facts
            .observations
            .get(&source)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let Some(key) = launch.correlation.exact_key() else {
            return Ok(Vec::new());
        };
        if launch.source_revision.as_str() != process_source::SOURCE_REVISION
            || (launch.adapter_revision, launch.parser_revision)
                != (
                    process_source::ADAPTER_REVISION,
                    process_source::PARSER_REVISION,
                )
            || launch.source_role != SourceRole::Tool
            || launch.content_trust != ContentTrust::UntrustedSourceContent
            || launch.observation_role != ObservationRole::Intent
            || !process_source::native_correlation_matches(
                &self.protected_source(facts, source)?,
                &launch.correlation,
            )
        {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        let stream = facts
            .workstreams
            .get(&run.workstream_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let anchor = facts
            .snapshots
            .get(&run.code_snapshot_id)
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        let reference = opening.to_string();
        if run.attempt_binding_status != AttemptBindingStatus::Resolved
            || run.attempt_id != Some(attempt.attempt_id)
            || attempt.workstream_id != stream.workstream_id
            || !stream.worktree_lineage_refs.contains(&reference)
            || anchor.capture_status
                != evertrace_domain::repository::SnapshotCaptureStatus::Complete
            || !stream
                .worktree_instance_ids
                .contains(&anchor.worktree_instance_id)
            || facts
                .worktrees
                .get(&anchor.worktree_instance_id)
                .is_none_or(|tree| {
                    Some(tree.repository_instance_id) != stream.repository_instance_id
                })
            || anchor.head_oid.as_deref() != Some(trial.source_anchor.commit.as_str())
            || anchor.tree_oid.as_deref() != Some(trial.source_anchor.tree.as_str())
            || !facts.bindings.values().any(|binding| {
                binding.assignment_status == AssignmentStatus::Resolved
                    && binding.primary_binding.task_id == Some(stream.task_id)
                    && binding.primary_binding.workstream_id == Some(stream.workstream_id)
                    && !binding.scope_effect_refs.is_empty()
                    && binding.evidence_refs.contains(&reference)
            })
        {
            return Ok(Vec::new());
        }
        let mut bindings = Vec::new();
        for operation in facts.operations.values().filter(|operation| {
            operation.operation_kind == OperationKind::Verify
                && operation.pairing_state == PairingState::Paired
                && operation.input_source_observation_refs.as_slice() == [source]
        }) {
            let mut refs = vec![
                source.to_string(),
                reference.clone(),
                run.code_snapshot_id.to_string(),
            ];
            let mut terminal_seen = false;
            for witness_id in &operation.result_source_observation_refs {
                let witness = facts
                    .observations
                    .get(witness_id)
                    .ok_or(AutoresearchError::EvidenceIncomplete)?;
                let receipt = facts.receipt(*witness_id)?;
                let bytes = self.protected_source(facts, *witness_id)?;
                let raw: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|_| AutoresearchError::UntrustedRunEvidence)?;
                let role = match raw["event"].as_str() {
                    Some("trial_started") => ObservationRole::Other,
                    Some("trial_finished") => ObservationRole::Result,
                    _ => return Ok(Vec::new()),
                };
                let measured_terminal = role == ObservationRole::Result
                    && (witness.adapter_revision, witness.parser_revision)
                        == (
                            process_source::ADAPTER_REVISION,
                            process_source::PARSER_REVISION,
                        )
                    && witness.content_trust == ContentTrust::Observed
                    && witness.capture_completeness
                        == evertrace_domain::evidence::CaptureCompleteness::Complete;
                let same_capture = witness.content_trust == launch.content_trust
                    && witness.capture_completeness == launch.capture_completeness;
                if (!same_capture && !measured_terminal)
                    || witness.source_instance_id != launch.source_instance_id
                    || witness.source_revision != launch.source_revision
                    || witness.adapter_revision != launch.adapter_revision
                    || witness.parser_revision != launch.parser_revision
                    || witness.source_role != SourceRole::Tool
                    || witness.observation_role != role
                    || witness.correlation.exact_key().as_ref() != Some(&key)
                    || !process_source::native_correlation_matches(&bytes, &witness.correlation)
                    || raw["format"] != process_source::FORMAT
                    || raw["event_key"].as_str() != Some(receipt.source_record_identity.as_str())
                    || raw["sequence"].as_u64() != Some(receipt.source_sequence)
                    || raw["launch_event"] != trial.event_key
                    || raw["source_epoch"] != trial.source_epoch
                    || raw["execution_key"] != trial.execution_key
                    || raw["study_key"] != trial.study_key
                {
                    return Ok(Vec::new());
                }
                terminal_seen |= role == ObservationRole::Result;
                refs.push(witness_id.to_string());
            }
            if !terminal_seen {
                continue;
            }
            let current = facts.bindings.get(&operation.operation_id);
            let primary = evertrace_domain::work::PrimaryWorkBinding {
                task_id: Some(stream.task_id),
                workstream_id: Some(stream.workstream_id),
                episode_id: attempt.episode_id,
                attempt_id: Some(attempt.attempt_id),
                experiment_run_id: Some(run.run_id),
                competing_group_id: current
                    .and_then(|binding| binding.primary_binding.competing_group_id),
            };
            if let crate::work::binding::BindingResolution::Revision(binding) =
                crate::work::binding::source_run_binding(operation, current, primary, refs)
                    .map_err(|_| AutoresearchError::ImmutableConflict)?
            {
                bindings.push(*binding);
            }
        }
        Ok(bindings)
    }

    pub(crate) fn verified_root_goal(
        &self,
        receipt: &SourceReceipt,
        observation: &SourceObservation,
        key_dir: Option<&std::path::Path>,
    ) -> Result<evertrace_capture::goal_source::RootGoal, AutoresearchError> {
        use evertrace_capture::goal_source;
        let source = observation.source_observation_id;
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
        goal_source::revalidate(receipt, observation, &bytes, &key)
            .map_err(|_| AutoresearchError::UntrustedRunEvidence)
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
        let root = self.verified_root_goal(
            facts.receipt(source)?,
            facts
                .observations
                .get(&source)
                .ok_or(AutoresearchError::EvidenceIncomplete)?,
            key_dir,
        )?;
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
            if observed_without_repository(effect) {
                memberships.entry(None).or_default();
                scope_watermark = scope_watermark.max(*sequence);
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
            memberships
                .entry(Some(repository))
                .or_default()
                .insert(worktree);
            scope_watermark = scope_watermark.max(*sequence);
        }
        let memberships = memberships
            .into_iter()
            .map(
                |(repository, worktrees)| evertrace_domain::work::TaskScopeMembership {
                    repository_instance_id: repository,
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
                ControlledRunCommand::WorkRoot {
                    command,
                    goal: source,
                }
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
        let (mut payloads, attempt_successor) = run_binding_updates(attempt, &binding_successors)?;
        payloads.insert(
            0,
            JournalPayload::ExperimentRunRecorded(Box::new(run.clone())),
        );
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
            return self.complete_process_trial(&facts, current, terminal_observation_id, context);
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
    declared: Option<&ExperimentRun>,
) -> Result<Option<(&'a Attempt, &'a WorktreeSnapshot)>, AutoresearchError> {
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
    // A late terminal belongs to its already admitted launch, not today's active Phase.
    let (episode_id, attempt_id) = if let Some(run) = declared {
        let attempt = run
            .attempt_id
            .and_then(|id| facts.attempts.get(&id))
            .ok_or(AutoresearchError::EvidenceIncomplete)?;
        if run.workstream_id != stream.workstream_id || attempt.task_id != stream.task_id {
            return Err(AutoresearchError::ImmutableConflict);
        }
        (attempt.episode_id, Some(attempt.attempt_id))
    } else {
        if stream.status != evertrace_domain::work::workstream::WorkstreamStatus::Active
            || stream.phase_contract != plan.definition.phase
        {
            return Ok(None);
        }
        (stream.active_episode_id, None)
    };
    let Some(episode) = episode_id
        .and_then(|id| facts.current_episodes.get(&id))
        .and_then(|revision| facts.episodes.get(revision))
    else {
        return Ok(None);
    };
    if episode.workstream_id != stream.workstream_id
        || episode.task_id != stream.task_id
        || episode.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Superseded
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
                && !binding.scope_effect_refs.is_empty()
                && binding.evidence_refs.contains(&reference)
        })
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return Ok(None);
    }
    let mut attempts = facts.attempts.values().filter(|attempt| {
        attempt_id.is_none_or(|id| attempt.attempt_id == id)
            && attempt.workstream_id == stream.workstream_id
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
    environment_fingerprint: String,
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
    text("framework_version")?;
    text("python")?;
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
        metric_extractor_version: evertrace_domain::work::NATIVE_TEST_RESULT_PARSER_VERSION.into(),
        multi_cas_metric_policy: MultiCasMetricPolicy::RejectMultipleParsed,
        environment_fingerprint,
        created_at_us,
    })
}

fn source_owns_stream(binding: &WorkBindingRevision, stream: &Workstream, source: &str) -> bool {
    binding.assignment_status == AssignmentStatus::Resolved
        && binding.primary_binding.task_id == Some(stream.task_id)
        && binding.primary_binding.workstream_id == Some(stream.workstream_id)
        && binding.evidence_refs.iter().any(|value| value == source)
}

struct ProcessWorkAnchor<'a> {
    code: Option<(evertrace_domain::ids::RepositoryId, &'a WorktreeSnapshot)>,
    session: &'a str,
    effect: &'a evertrace_domain::evidence::ScopeEffect,
    root_source: SourceObservationId,
    goal_source: SourceObservationId,
    goal_raw: &'a [u8],
    resolver: &'a ControlledRunResolver,
    ordinary_work: bool,
}

impl ProcessWorkAnchor<'_> {
    fn matches_checkpoint_goal(
        &self,
        snapshot: &ProjectionSnapshot,
        facts: &ControlledFacts,
        stream: &Workstream,
        prior: &str,
        watermark: u64,
    ) -> Result<bool, AutoresearchError> {
        use evertrace_capture::goal_source;
        // A later binding may accumulate the recreated goal. Only the earliest accepted
        // binding for the prior declaration, within the checkpoint prefix, can anchor it.
        let opening = snapshot
            .data_rows()
            .filter_map(|row| {
                if row.object_kind.as_deref() != Some("work_binding")
                    || row.source_event_seq > watermark
                {
                    return None;
                }
                let JournalPayload::WorkBindingRecorded(binding) =
                    serde_json::from_str(row.payload_json.as_deref()?).ok()?
                else {
                    return None;
                };
                source_owns_stream(&binding, stream, prior)
                    .then_some((row.source_event_seq, binding))
            })
            .min_by_key(|(sequence, _)| *sequence);
        let Some((_, opening)) = opening else {
            return Ok(false);
        };
        let reference = &facts.receipt(self.goal_source)?.source_ref;
        let mut roots = opening.evidence_refs.iter().filter_map(|value| {
            let id = value.parse::<SourceObservationId>().ok()?;
            let receipt = facts.receipt(id).ok()?;
            (receipt.source_ref == *reference
                && goal_source::is_source_revision(receipt.source_revision.as_str()))
            .then_some(id)
        });
        let Some(root) = roots.next().filter(|_| roots.next().is_none()) else {
            return Ok(false);
        };
        let raw = self.resolver.protected_source(facts, root)?;
        Ok(goal_source::same_goal_epoch(&raw, self.goal_raw))
    }
}

fn resume_checkpoint_refs(
    phase: &evertrace_domain::work::WorkEpisode,
) -> impl Iterator<Item = &String> {
    // Select only SessionEnd at the still-current operation prefix; stable keys end in algorithm revision.
    let prefix = format!(
        "{}:{}:{}:",
        phase.episode_id,
        phase.source_watermark,
        evertrace_domain::work::CheckpointReason::SessionEnd.as_str()
    );
    phase
        .checkpoint_refs
        .iter()
        .filter(move |key| key.starts_with(&prefix))
}

fn resume_checkpoint<'a>(
    snapshot: &ProjectionSnapshot,
    phase: &'a evertrace_domain::work::WorkEpisode,
    basis: Option<evertrace_domain::ids::WorktreeSnapshotId>,
) -> Option<&'a String> {
    use evertrace_domain::work::CheckpointReason;
    resume_checkpoint_refs(phase).find(|key| {
        snapshot.data_rows().any(|row| {
            row.object_kind.as_deref() == Some("work_checkpoint")
                && row.object_id.as_ref() == Some(*key)
                && matches!(row.payload_json.as_deref().and_then(|json| serde_json::from_str(json).ok()),
                    Some(JournalPayload::WorkCheckpointRecorded(checkpoint))
                    if checkpoint.episode_id == phase.episode_id
                        && checkpoint.source_watermark == phase.source_watermark
                        && checkpoint.created_reason == CheckpointReason::SessionEnd
                        && checkpoint.continuation_candidate
                        && checkpoint.phase_contract == phase.phase_contract
                        && checkpoint.open_loops == phase.open_loops
                        && checkpoint.capture_receipt_revision_ids == phase.capture_receipt_revision_ids
                        && checkpoint.current_worktree_snapshot_id == basis)
        })
    })
}

fn process_work_command(
    snapshot: &ProjectionSnapshot,
    facts: &ControlledFacts,
    source: SourceObservationId,
    task: &Task,
    anchor: &ProcessWorkAnchor<'_>,
    plan: &ProcessWorkPlan,
    continuation: &BTreeSet<String>,
    context: &AutoresearchCommandContext,
) -> Result<Option<JournalCommand>, AutoresearchError> {
    use crate::work::{WorkCommandContext, attempt, episode, workstream};
    let context = WorkCommandContext {
        command_id: context.command_id,
        occurred_at_us: context.occurred_at_us,
        effective_config_hash: context.effective_config_hash,
        algorithm_revision: context.algorithm_revision,
    };
    let repository = anchor.code.map(|(repository, _)| repository);
    let worktree = anchor
        .code
        .map(|(_, snapshot)| snapshot.worktree_instance_id);
    // Only the already admitted Phase-opening Operation supplies this association.
    // A child source's process/thread claims never manufacture an Agent Host lane.
    let root_lane = facts
        .operations
        .get(&anchor.effect.operation_id)
        .and_then(|operation| operation.execution_lane_id);
    let root_capture = root_lane
        .map(|lane| lane_capture_receipt(snapshot.data_rows(), lane))
        .transpose()?
        .flatten();
    // A scope can arrive before lane normalization. Ordinary Work must wait for the
    // lane's current receipt rather than bypass the checkpoint gate as if already attached.
    if anchor.ordinary_work
        && root_capture.as_ref().is_none_or(|receipt| {
            facts
                .execution_lanes
                .get(&receipt.execution_lane_id)
                .is_none_or(|lane| {
                    lane.active_capture_receipt_revision_id != receipt.capture_receipt_revision_id
                })
        })
    {
        return Ok(None);
    }
    let root_lane = root_capture
        .as_ref()
        .map(|receipt| receipt.execution_lane_id);
    let source_ref = source.to_string();
    let mut sources = vec![
        source_ref.clone(),
        anchor.root_source.to_string(),
        anchor.goal_source.to_string(),
    ];
    let current_binding = facts.bindings.get(&anchor.effect.operation_id);
    let streams = facts
        .workstreams
        .values()
        .filter(|stream| {
            stream.worktree_lineage_refs.contains(&source_ref)
                || current_binding
                    .is_some_and(|binding| source_owns_stream(binding, stream, &source_ref))
                || facts.bindings.values().any(|binding| {
                    continuation
                        .iter()
                        .any(|source| source_owns_stream(binding, stream, source))
                })
        })
        .collect::<Vec<_>>();
    let map_error = |_| AutoresearchError::ImmutableConflict;
    if let [stream] = streams.as_slice() {
        let prior = continuation.iter().find(|reference| {
            facts
                .bindings
                .values()
                .any(|binding| source_owns_stream(binding, stream, reference))
        });
        if let Some(reference) = prior {
            sources.push(reference.clone());
        }
        if stream.task_id != task.task_id
            || stream.repository_instance_id != repository
            || stream.worktree_instance_ids != worktree.into_iter().collect::<Vec<_>>()
        {
            return Err(AutoresearchError::ImmutableConflict);
        }
        if stream.status.is_terminal() {
            return Ok(None);
        }
        if current_binding.is_some_and(|binding| {
            binding.evidence_refs.contains(&source_ref)
                && binding.primary_binding.episode_id.is_some_and(|id| {
                    facts
                        .current_episodes
                        .get(&id)
                        .and_then(|revision| facts.episodes.get(revision))
                        .is_some_and(|phase| {
                            phase.lifecycle_status
                                == evertrace_domain::work::EpisodeLifecycle::Closed
                        })
                })
        }) {
            return Ok(None);
        }
        if prior.is_none() && stream.phase_contract != plan.phase {
            return Err(AutoresearchError::ImmutableConflict);
        }
        if let Some(episode_id) = stream.active_episode_id {
            let phase = facts
                .current_episodes
                .get(&episode_id)
                .and_then(|revision| facts.episodes.get(revision))
                .ok_or(AutoresearchError::EvidenceIncomplete)?;
            let mut events = Vec::new();
            let new_lane = root_lane.filter(|lane| {
                !phase.execution_lane_ids.is_empty() && !phase.execution_lane_ids.contains(lane)
            });
            let known_strategy = phase.attempt_ids.iter().any(|id| {
                facts
                    .attempts
                    .get(id)
                    .is_some_and(|attempt| attempt.strategy_contract == plan.strategy)
            });
            if new_lane.is_some() {
                let basis = worktree
                    .and_then(|id| facts.worktrees.get(&id))
                    .and_then(|value| value.current_snapshot_id);
                let Some(prior) = prior else {
                    return Ok(None);
                };
                if !phase.session_ids.iter().any(|id| id == anchor.session)
                    || phase.phase_contract != plan.phase
                    || !known_strategy
                    || (repository.is_some() && basis.is_none())
                {
                    return Ok(None);
                }
                let Some(checkpoint) = resume_checkpoint(snapshot, phase, basis) else {
                    return Ok(None);
                };
                if !anchor.matches_checkpoint_goal(
                    snapshot,
                    facts,
                    stream,
                    prior,
                    phase.source_watermark,
                )? {
                    return Ok(None);
                }
                sources.push(checkpoint.clone());
            }
            if prior.is_none() && (phase.phase_contract != plan.phase || !known_strategy) {
                return Err(AutoresearchError::ImmutableConflict);
            }
            let view = evertrace_store::WorkIdentityCurrentView::from_snapshot(snapshot)?;
            let current_binding = facts.bindings.get(&anchor.effect.operation_id);
            let binding = crate::work::binding::source_root_workstream(
                &view,
                stream,
                anchor.effect.operation_id,
                anchor.effect.scope_effect_id,
                current_binding,
                &sources,
            )
            .map_err(map_error)?
            .into_revision();
            let owned = binding.as_ref().or_else(|| {
                current_binding.filter(|binding| {
                    binding.assignment_status == evertrace_domain::work::AssignmentStatus::Resolved
                        && binding.primary_binding.task_id == Some(stream.task_id)
                        && binding.primary_binding.workstream_id == Some(stream.workstream_id)
                })
            });
            if owned.is_none() {
                return Ok(None);
            }
            if let Some(lane) = new_lane.filter(|id| !stream.execution_lane_ids.contains(id)) {
                let mut next = (*stream).clone();
                next.revision_id = RevisionId::new_v7();
                next.predecessor_revision_id = Some(stream.revision_id);
                next.source_watermark = snapshot.frontier;
                next.execution_lane_ids.push(lane);
                next.execution_lane_ids.sort();
                let repositories =
                    evertrace_store::repository::RepositoryCurrentView::from_snapshot(snapshot)?;
                let command = workstream::revise_workstream(
                    context,
                    task,
                    &repositories,
                    stream,
                    next,
                    crate::work::TypedWorkstreamChange::StructuredRevision,
                    &sources,
                )
                .map_err(map_error)?;
                events.extend_from_slice(command.events());
            }
            let mut proposal = None;
            if !known_strategy && phase.phase_contract == plan.phase {
                let pending = facts
                    .attempts
                    .values()
                    .filter(|attempt| {
                        attempt.task_id == task.task_id
                            && attempt.workstream_id == stream.workstream_id
                            && attempt.episode_id.is_none()
                            && attempt.repository_instance_id == repository
                            && attempt.worktree_instance_ids == stream.worktree_instance_ids
                            && attempt.strategy_contract == plan.strategy
                            && attempt.execution_status
                                == evertrace_domain::work::AttemptExecutionStatus::Proposed
                            && attempt.lifecycle_status
                                == evertrace_domain::work::AttemptLifecycleStatus::Active
                            && attempt.experiment_run_ids.is_empty()
                            && attempt.competing_group_ids.is_empty()
                    })
                    .take(2)
                    .collect::<Vec<_>>();
                match pending.as_slice() {
                    [] => {
                        // Persist the proposal first. Linking uses the later actual journal
                        // frontier, not a fabricated watermark to bypass the successor gate.
                        let proposed = attempt::new_attempt(
                            task.task_id,
                            stream.workstream_id,
                            repository,
                            stream.worktree_instance_ids.clone(),
                            vec![],
                            plan.strategy.clone(),
                            snapshot.frontier,
                        )
                        .map_err(map_error)?;
                        let declared =
                            attempt::create_attempt(context, proposed).map_err(map_error)?;
                        let mut events = declared.events().to_vec();
                        if let Some(binding) = binding {
                            events.extend(
                                crate::work::binding::record_binding(context, binding)
                                    .map_err(map_error)?
                                    .events()
                                    .iter()
                                    .cloned(),
                            );
                        }
                        return JournalCommand::new(context.command_id, events)
                            .map(Some)
                            .map_err(AutoresearchError::Store);
                    }
                    [proposed] => {
                        let linked =
                            episode::link_attempt_to_episode(proposed, phase, snapshot.frontier)
                                .map_err(map_error)?;
                        proposal = Some(linked.attempt_id);
                        events.extend(
                            attempt::record_attempt_revision(context, proposed, linked)
                                .map_err(map_error)?
                                .events()
                                .iter()
                                .cloned(),
                        );
                    }
                    _ => {} // Preserve Work ownership without choosing an ambiguous strategy.
                }
            }
            let mut refreshed = None;
            if !phase.execution_lane_ids.is_empty() {
                let receipts = phase
                    .execution_lane_ids
                    .iter()
                    .map(|lane| {
                        lane_capture_receipt(snapshot.data_rows(), *lane)?
                            .ok_or(AutoresearchError::EvidenceIncomplete)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                refreshed = episode::refresh_capture(phase, &receipts, snapshot.frontier)
                    .map_err(map_error)?;
            }
            if let Some(proposed) = proposal {
                let mut next = refreshed.take().unwrap_or_else(|| phase.clone());
                if next.revision_id == phase.revision_id {
                    next.revision_id = RevisionId::new_v7();
                    next.predecessor_revision_id = Some(phase.revision_id);
                    next.revision_generation = phase
                        .revision_generation
                        .checked_add(1)
                        .ok_or(AutoresearchError::InvalidInput)?;
                }
                next.attempt_ids.push(proposed);
                next.attempt_ids.sort();
                next.attempt_ids.dedup();
                phase
                    .validate_successor(&next)
                    .map_err(|_| AutoresearchError::ImmutableConflict)?;
                refreshed = Some(next);
            }
            if let Some(next) = refreshed {
                events.push(JournalEventDraft::runtime(
                    context.occurred_at_us,
                    context.effective_config_hash,
                    context.algorithm_revision,
                    JournalPayload::WorkEpisodeRecorded(Box::new(next)),
                ));
            }
            let linked = owned
                .filter(|binding| binding.primary_binding.episode_id.is_none())
                .map(|binding| episode::link_binding_to_episode(binding, phase))
                .transpose()
                .map_err(map_error)?;
            for revision in binding.into_iter().chain(linked) {
                events.extend(
                    crate::work::binding::record_binding(context, revision)
                        .map_err(map_error)?
                        .events()
                        .iter()
                        .cloned(),
                );
            }
            return if events.is_empty() {
                Ok(None)
            } else {
                JournalCommand::new(context.command_id, events)
                    .map(Some)
                    .map_err(AutoresearchError::Store)
            };
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
            anchor
                .code
                .map(|(_, snapshot)| snapshot.worktree_snapshot_id),
            snapshot.frontier,
        )
        .map_err(map_error)?;
        episode.session_ids = vec![anchor.session.to_owned()];
        episode.execution_lane_ids = root_lane.into_iter().collect();
        if let Some(receipt) = root_capture.as_ref() {
            episode::pin_capture_receipts(&mut episode, std::slice::from_ref(receipt))
                .map_err(|_| AutoresearchError::InvalidInput)?;
        }
        let linked = episode::link_attempt_to_episode(attempt, &episode, snapshot.frontier)
            .map_err(map_error)?;
        episode.attempt_ids.push(linked.attempt_id);
        let bindings = if facts.observations.get(&source).is_some_and(|observation| {
            evertrace_capture::process_source::is_work_revision(
                observation.source_revision.as_str(),
            )
        }) {
            // This observed invocation opened this Phase; its strategy is still only Proposed.
            let binding = current_binding
                .filter(|binding| source_owns_stream(binding, stream, &source_ref))
                .ok_or(AutoresearchError::EvidenceIncomplete)?;
            vec![episode::link_binding_to_episode(binding, &episode).map_err(map_error)?]
        } else {
            vec![]
        };
        return episode::activate_episode(context, stream, episode, vec![linked], bindings)
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
        repository_instance_id: repository,
        worktree_instance_ids: worktree.into_iter().collect(),
        active_worktree_instance_id: worktree,
        worktree_lineage_refs: repository.map(|_| source_ref).into_iter().collect(),
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
        execution_lane_ids: root_lane.into_iter().collect(),
        source_watermark: snapshot.frontier,
    };
    let attempt = attempt::new_attempt(
        task.task_id,
        stream.workstream_id,
        repository,
        worktree.into_iter().collect(),
        vec![],
        plan.strategy.clone(),
        snapshot.frontier,
    )
    .map_err(map_error)?;
    let repositories = evertrace_store::repository::RepositoryCurrentView::from_snapshot(snapshot)
        .map_err(AutoresearchError::Store)?;
    // Keep source ownership in the same transaction, before a later job activates the Episode.
    let mut view = evertrace_store::WorkIdentityCurrentView::from_snapshot(snapshot)?;
    view.workstreams
        .insert(stream.workstream_id, stream.clone());
    let binding = crate::work::binding::source_root_workstream(
        &view,
        &stream,
        anchor.effect.operation_id,
        anchor.effect.scope_effect_id,
        current_binding,
        &sources,
    )
    .map_err(map_error)?
    .into_revision()
    .ok_or(AutoresearchError::ImmutableConflict)?;
    let binding = crate::work::binding::record_binding(context, binding).map_err(map_error)?;
    let declaration =
        workstream::create_workstream(context, task, &repositories, stream).map_err(map_error)?;
    let attempt = attempt::create_attempt(context, attempt).map_err(map_error)?;
    JournalCommand::new(
        context.command_id,
        declaration
            .events()
            .iter()
            .chain(attempt.events())
            .chain(binding.events())
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
    execution_lanes: BTreeMap<ExecutionLaneId, ExecutionLane>,
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
            execution_lanes: Default::default(),
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
                        | "execution_lane"
                )
            )
        }) {
            let Some(payload) = row.payload_json.as_deref() else {
                continue;
            };
            let payload = serde_json::from_str::<JournalPayload>(payload)
                .map_err(|_| AutoresearchError::Store(evertrace_store::StoreError::StoreCorrupt))?;
            match payload {
                JournalPayload::ExecutionLaneRecorded(value) => {
                    let replace = facts
                        .execution_lanes
                        .get(&value.execution_lane_id)
                        .is_none_or(|current| current.lane_revision < value.lane_revision);
                    if replace {
                        facts
                            .execution_lanes
                            .insert(value.execution_lane_id, *value);
                    }
                }
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

fn run_binding_updates(
    attempt: &Attempt,
    bindings: &[WorkBindingRevision],
) -> Result<(Vec<JournalPayload>, Option<Attempt>), AutoresearchError> {
    if bindings.is_empty() {
        return Ok((Vec::new(), None));
    }
    let mut payloads = bindings
        .iter()
        .cloned()
        .map(|binding| JournalPayload::WorkBindingRecorded(Box::new(binding)))
        .collect::<Vec<_>>();
    let mut next = attempt.clone();
    next.revision_id = RevisionId::new_v7();
    next.predecessor_revision_id = Some(attempt.revision_id);
    next.revision_generation = attempt.revision_generation.saturating_add(1);
    next.work_binding_revision_refs.extend(
        bindings
            .iter()
            .map(|binding| binding.work_binding_revision_id),
    );
    next.work_binding_revision_refs.sort();
    next.work_binding_revision_refs.dedup();
    next.source_watermark = next.source_watermark.saturating_add(1);
    attempt
        .validate_successor(&next)
        .map_err(|_| AutoresearchError::ImmutableConflict)?;
    payloads.push(JournalPayload::AttemptRecorded(Box::new(next.clone())));
    Ok((payloads, Some(next)))
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
        if evertrace_domain::work::is_native_test_parser(&run.metric_extractor_version)
            && request.scope != ResultScope::Partial
        {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        request.raw_cas_refs.sort();
        request.raw_cas_refs.dedup();
        let bytes = self.read_all(&request.raw_cas_refs)?;
        let (status, metric, parser_failure) = parse_metric_set(
            &bytes,
            run.multi_cas_metric_policy,
            &run.metric_extractor_version,
        )?;
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
                parser_version: run.metric_extractor_version.clone(),
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
        let (status, metric, parser_failure) = parse_metric_set(
            &bytes,
            run.multi_cas_metric_policy,
            &run.metric_extractor_version,
        )
        .map_err(|error| {
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
        // A successful native reparse cannot manufacture the missing execution contract.
        if evertrace_domain::work::is_native_test_parser(&run.metric_extractor_version) {
            return Err(AutoresearchError::UntrustedRunEvidence);
        }
        let bytes = self.read_all(&current.raw_cas_refs)?;
        let (parser_status, parsed_metric, parser_failure) = parse_metric_set(
            &bytes,
            run.multi_cas_metric_policy,
            &run.metric_extractor_version,
        )
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
        || !matches!(
            run.metric_extractor_version.as_str(),
            RESULT_PARSER_VERSION
                | evertrace_domain::work::NATIVE_TEST_RESULT_PARSER_VERSION
                | evertrace_domain::work::NATIVE_TEST_CONTRACT_PARSER_VERSION
                | evertrace_domain::work::NATIVE_TEST_COHORT_PARSER_VERSION
        )
        || result.parser_receipt.parser_version != run.metric_extractor_version
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
    version: &str,
) -> Result<(ParserStatus, Option<MetricValue>, Option<ParserFailureCode>), AutoresearchError> {
    let parsed = bytes
        .iter()
        .filter_map(|value| {
            if evertrace_domain::work::is_native_test_parser(version) {
                evertrace_domain::work::NativeTestResult::decode(value)
                    .and_then(|value| value.metric())
            } else if version == RESULT_PARSER_VERSION {
                parse_metric(value)
            } else {
                None
            }
        })
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
                matches!(parse_metric_set(&inputs, run.multi_cas_metric_policy, &run.metric_extractor_version),
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
