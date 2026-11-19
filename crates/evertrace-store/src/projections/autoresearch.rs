use std::collections::BTreeMap;

use evertrace_capture::CasDigest;
use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, Operation, PairingState, SourceArchiveMode,
        SourceReceipt, SourceRole, hex, payload_fingerprint,
    },
    ids::{
        AttemptId, ExperimentRunId, OperationId, ResultEvidenceId, SourceObservationId,
        SourceReceiptId, TaskId, WorkArtifactId, WorkEpisodeId, WorkstreamId, WorktreeId,
        WorktreeSnapshotId,
    },
    repository::{RepositoryInstance, WorktreeInstance, WorktreeSnapshot},
    revision::RevisionId,
    semantic::ResultEvidence,
    work::{
        ArtifactActor, ArtifactScope, AssignmentStatus, Attempt, AttemptBindingStatus,
        ControlledRunSourceEnvelope, ExperimentRun, RunContractValidity, RunExecutionStatus,
        RunObservability, Task, WorkArtifact, WorkBindingRevision, WorkEpisode, Workstream,
    },
};

use crate::{
    JournalPayload,
    command::StoreError,
    projections::{
        EvidenceSurfaceFacts, ProjectionSnapshot, SourceObservationFacts, SourceReceiptFacts,
        current_binding_lineage, procedure::ProcedureState,
    },
};

pub(crate) struct ControlledRunAdmissionView<'a> {
    pub frontier: u64,
    pub runs: &'a BTreeMap<ExperimentRunId, (ExperimentRun, u64)>,
    pub attempts: &'a BTreeMap<AttemptId, (Attempt, u64)>,
    pub work_bindings:
        &'a BTreeMap<evertrace_domain::ids::WorkBindingRevisionId, (WorkBindingRevision, u64)>,
    pub operations: &'a BTreeMap<OperationId, (Operation, u64)>,
    pub snapshots: &'a BTreeMap<WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
    pub receipts: &'a SourceReceiptFacts,
    pub observations: &'a SourceObservationFacts,
    pub surfaces: &'a EvidenceSurfaceFacts,
    pub artifacts: &'a BTreeMap<WorkArtifactId, (WorkArtifact, u64)>,
    pub procedures: &'a ProcedureState,
    pub tasks: &'a BTreeMap<TaskId, (Task, u64)>,
    pub workstreams: &'a BTreeMap<WorkstreamId, (Workstream, u64)>,
    pub episodes: &'a BTreeMap<WorkEpisodeId, (WorkEpisode, u64)>,
    pub bursts: &'a BTreeMap<
        evertrace_domain::ids::OperationBurstId,
        (evertrace_domain::work::OperationBurst, u64),
    >,
    pub episode_revisions: &'a BTreeMap<RevisionId, (WorkEpisode, u64)>,
    pub worktrees: &'a BTreeMap<WorktreeId, (WorktreeInstance, u64)>,
}

impl super::JournalAdmissionState {
    pub(super) fn controlled_run_admission(&self) -> ControlledRunAdmissionView<'_> {
        ControlledRunAdmissionView {
            frontier: self.frontier,
            runs: &self.experiment_runs,
            attempts: &self.attempts,
            work_bindings: &self.work_bindings,
            operations: &self.operations,
            snapshots: &self.worktree_snapshots,
            receipts: &self.source_receipts,
            observations: &self.source_observations,
            surfaces: &self.evidence_surfaces,
            artifacts: &self.work_artifacts,
            procedures: &self.procedure,
            tasks: &self.tasks,
            workstreams: &self.workstreams,
            episodes: &self.episodes,
            bursts: &self.operation_bursts,
            episode_revisions: &self.episode_revisions,
            worktrees: &self.worktrees,
        }
    }
}

impl super::JournalAdmissionState {
    /// Reuse an already accepted native Run's exact launch for one newly verified terminal.
    /// Called under the writer before append, never during replay or historical normalization.
    pub(crate) fn recover_native_terminal_gate(
        &self,
        terminal: &evertrace_domain::evidence::SourceObservation,
        receipt: &SourceReceipt,
        surface: &evertrace_domain::evidence::EvidenceSurface,
    ) -> Result<Option<String>, StoreError> {
        use evertrace_capture::process_source;
        use evertrace_domain::evidence::{CorrelationAdmission, ObservationRole};
        use evertrace_domain::work::NATIVE_TEST_COHORT_PARSER_VERSION;
        if terminal.source_revision.as_str() != process_source::SOURCE_REVISION
            || (terminal.adapter_revision, terminal.parser_revision)
                != (
                    process_source::ADAPTER_REVISION,
                    process_source::PARSER_REVISION,
                )
            || terminal.source_role != SourceRole::Tool
            || terminal.content_trust != ContentTrust::Observed
            || terminal.capture_completeness != CaptureCompleteness::Complete
            || terminal.correlation.admission != CorrelationAdmission::Unavailable
            || surface.source_observation_revision_ref != terminal.source_observation_id
            || surface.validate().is_err()
            || receipt.source_observation_id != terminal.source_observation_id
            || receipt.source_receipt_id != terminal.source_receipt_ref
            || receipt.source_instance_id != terminal.source_instance_id
            || receipt.adapter_manifest_ref != terminal.correlation.adapter_manifest_ref
            || receipt.capture_completeness != CaptureCompleteness::Complete
            || self
                .source_observations
                .contains_key(&terminal.source_observation_id)
        {
            return Ok(None);
        }
        let raw = surface.protected_text.as_bytes();
        let Some(launch_id) = process_source::native_terminal_launch(raw, terminal) else {
            return Ok(None);
        };
        let view = self.controlled_run_admission();
        let Some((launch, _)) = view.observations.get(&launch_id) else {
            return Ok(None);
        };
        let Ok((launch_receipt, _, launch_raw)) = native_source_bytes(
            &view,
            launch.source_receipt_ref,
            ObservationRole::Intent,
            false,
            StoreError::InvalidInput,
        ) else {
            return Ok(None);
        };
        let Some(gate) = launch.correlation.strong_gate_receipt_ref.as_ref() else {
            return Ok(None);
        };
        let mut correlation = terminal.correlation.clone();
        correlation.admission = CorrelationAdmission::ExactCapable;
        correlation.strong_gate_receipt_ref = Some(gate.clone());
        if correlation.validate().is_err()
            || correlation.exact_key().is_none()
            || correlation.exact_key() != launch.correlation.exact_key()
            || correlation.adapter_manifest_ref != launch.correlation.adapter_manifest_ref
            || (launch.adapter_revision, launch.parser_revision)
                != (terminal.adapter_revision, terminal.parser_revision)
            || !process_source::native_correlation_matches(launch_raw, &launch.correlation)
            || !process_source::same_native_execution(launch_raw, raw)
        {
            return Ok(None);
        }
        let Some(identity) = serde_json::from_slice::<NativeTrialIdentity<'_>>(launch_raw).ok()
        else {
            return Ok(None);
        };
        let key = format!("{}/{}", identity.source_epoch, identity.execution_key);
        // The journal already owns the Run identity. Read only this source's accepted owner;
        // do not copy the projection or retain another external-run index.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(25);
        let mut owners = view
            .runs
            .values()
            .take_while(|_| std::time::Instant::now() < deadline)
            .filter(|(run, _)| {
                run.external_system_id.as_deref() == Some(process_source::FORMAT)
                    && run.external_run_key.as_deref() == Some(key.as_str())
            });
        let Some((run, _)) = owners.next() else {
            return Ok(None);
        };
        if owners.next().is_some()
            || std::time::Instant::now() >= deadline
            || !run.is_declaration_only()
            || run.metric_extractor_version != NATIVE_TEST_COHORT_PARSER_VERSION
            || run.attempt_binding_status != AttemptBindingStatus::Resolved
            || !run
                .source_receipt_refs
                .contains(&launch_receipt.source_receipt_id)
        {
            return Ok(None);
        }
        let Some(repository) = view
            .workstreams
            .get(&run.workstream_id)
            .and_then(|(stream, _)| stream.repository_instance_id)
        else {
            return Ok(None);
        };
        if self.scope_purges.current(repository).is_some()
            || self.repositories.get(&repository).is_none_or(|(repo, _)| {
                repo.user_disabled
                    || repo
                        .capability_state
                        .as_ref()
                        .is_some_and(|state| state.trust_revoked)
            })
        {
            return Ok(None);
        }
        if self.deletions.events().next().is_some() {
            use crate::DefaultRetrievalSuppressionGeneration::{ContentSpanV2, ObservationSpanV1};
            let refs = [ObservationSpanV1, ContentSpanV2]
                .into_iter()
                .map(|generation| {
                    crate::default_retrieval_suppression_ref_hash(surface, receipt, generation)
                })
                .collect::<Result<_, _>>()?;
            if super::source_suppressed(self.deletions.events(), Some(&refs)) {
                return Ok(None);
            }
            let lookup = super::CandidateSourceLookup::Current {
                observations: view.observations,
                receipts: view.receipts,
                surfaces: view.surfaces,
            };
            for id in &run.source_receipt_refs {
                let Some((receipt, _)) = view.receipts.get(id) else {
                    return Ok(None);
                };
                let refs = lookup.suppression_refs(receipt.source_observation_id)?;
                if super::source_suppressed(self.deletions.events(), refs.as_ref()) {
                    return Ok(None);
                }
            }
        }
        Ok(Some(gate.clone()))
    }
}

pub(crate) fn validate_controlled_command<'a>(
    view: ControlledRunAdmissionView<'_>,
    payloads: impl IntoIterator<Item = &'a JournalPayload>,
    error: StoreError,
) -> Result<(), StoreError> {
    let payloads = payloads.into_iter().collect::<Vec<_>>();
    for payload in &payloads {
        if let JournalPayload::ResultEvidenceRecorded(result) = payload
            && evertrace_domain::work::is_native_test_parser(&result.parser_receipt.parser_version)
        {
            validate_native_test_result(&view, result, &payloads, error)?;
        }
    }
    let runs = payloads
        .iter()
        .filter_map(|payload| match payload {
            JournalPayload::ExperimentRunRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut closing = payloads.iter().filter_map(|payload| match payload {
        JournalPayload::WorkEpisodeRecorded(episode)
            if !episode.experiment_run_refs.is_empty()
                && view
                    .episodes
                    .get(&episode.episode_id)
                    .is_none_or(|(prior, _)| {
                        prior.experiment_run_refs != episode.experiment_run_refs
                    }) =>
        {
            Some(episode.as_ref())
        }
        _ => None,
    });
    let close = closing.next();
    if let Some(episode) = close {
        let [run] = runs.as_slice() else {
            return Err(error);
        };
        if closing.next().is_some()
            || !run.is_declaration_only()
            || episode.experiment_run_refs != [run.run_id]
            || run.metric_extractor_version
                != evertrace_domain::work::NATIVE_TEST_COHORT_PARSER_VERSION
            || view.runs.contains_key(&run.run_id)
        {
            return Err(error);
        }
    }
    for run in &runs {
        if run.comparison_execution_binding.is_none() && !run.is_declaration_only() {
            validate_native_terminal_cohort(&view, run, &payloads, error)?;
        } else if evertrace_domain::work::is_native_test_contract_parser(
            &run.metric_extractor_version,
        ) {
            validate_native_contract(
                &view,
                run,
                close.map(|episode| (episode, payloads.as_slice())),
                error,
            )?;
        }
    }
    if !runs
        .iter()
        .any(|run| run.comparison_execution_binding.is_some())
    {
        return Ok(());
    }
    let results = payloads
        .iter()
        .filter_map(|payload| match payload {
            JournalPayload::ResultEvidenceRecorded(value) => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let command_artifacts = payloads
        .iter()
        .filter_map(|payload| match payload {
            JournalPayload::WorkArtifactRecorded(value) => Some(value.work_artifact_id),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let mut binding_values = view
        .work_bindings
        .values()
        .map(|(value, _)| value.clone())
        .collect::<Vec<_>>();
    binding_values.extend(payloads.iter().filter_map(|payload| match payload {
        JournalPayload::WorkBindingRecorded(value) => Some(value.as_ref().clone()),
        _ => None,
    }));
    let bindings = current_binding_lineage(binding_values.iter()).map_err(|_| error)?;
    for run in runs {
        let Some(binding) = run.comparison_execution_binding.as_ref() else {
            continue;
        };
        let attempt_id = run.attempt_id.ok_or(error)?;
        let attempt = view.attempts.get(&attempt_id).ok_or(error)?.0.clone();
        if attempt.workstream_id != run.workstream_id
            || attempt.strategy_contract_fingerprint != run.strategy_contract_fingerprint
        {
            return Err(error);
        }
        match view.runs.get(&run.run_id) {
            None => {
                if run.parent_revision_id.is_some() || !run.is_controlled_declaration() {
                    return Err(error);
                }
                let launch = validate_witnesses(
                    run.source_receipt_refs.as_slice(),
                    true,
                    run,
                    &attempt,
                    &bindings,
                    &view,
                    error,
                )?;
                if !launch_matches(run, &attempt, binding, &launch) {
                    return Err(error);
                }
                let ControlledRunSourceEnvelope::Launch {
                    procedure_revision_id,
                    ..
                } = launch
                else {
                    return Err(error);
                };
                if !view
                    .procedures
                    .is_current_revision_id(procedure_revision_id)
                    || view
                        .snapshots
                        .get(&run.code_snapshot_id)
                        .and_then(|(snapshot, _)| snapshot.toolchain_fingerprint.as_deref())
                        != Some(binding.toolchain_revision.as_str())
                {
                    return Err(error);
                }
                validate_declaration_anchor(
                    &view,
                    procedure_revision_id,
                    &attempt,
                    run.code_snapshot_id,
                    error,
                )?;
            }
            Some((current, _)) => {
                if !current.is_controlled_declaration()
                    || run.parent_revision_id != Some(current.revision_id)
                    || run.observability != RunObservability::Full
                    || run.execution_status != RunExecutionStatus::Completed
                    || run.contract_validity != RunContractValidity::Valid
                {
                    return Err(error);
                }
                current.validate_successor(run).map_err(|_| error)?;
                if run.created_at_us != current.created_at_us
                    || run.started_at_us != current.started_at_us
                    || run.source_receipt_refs != current.source_receipt_refs
                    || run.attempt_id != current.attempt_id
                    || run.attempt_binding_status != current.attempt_binding_status
                {
                    return Err(error);
                }
                let terminal = validate_witnesses(
                    run.terminal_evidence_refs.as_slice(),
                    false,
                    run,
                    &attempt,
                    &bindings,
                    &view,
                    error,
                )?;
                let ControlledRunSourceEnvelope::Terminal {
                    ended_at_us,
                    metric,
                    artifact_refs,
                    ..
                } = terminal
                else {
                    return Err(error);
                };
                if run.ended_at_us != Some(ended_at_us)
                    || run.work_artifact_refs != artifact_refs
                    || artifact_refs.iter().any(|id| {
                        !view.artifacts.contains_key(id) && !command_artifacts.contains(id)
                    })
                {
                    return Err(error);
                }
                let matching = results
                    .iter()
                    .filter(|result| {
                        result.experiment_run_id == run.run_id
                            && result.experiment_run_revision_id == run.revision_id
                    })
                    .copied()
                    .collect::<Vec<_>>();
                if matching.len() != 1
                    || matching[0].parsed_metric.as_ref() != Some(&metric)
                    || matching[0].result_scope != evertrace_domain::semantic::ResultScope::Complete
                    || matching[0].completeness
                        != evertrace_domain::semantic::EvidenceCompleteness::Complete
                    || matching[0].failure.is_some()
                {
                    return Err(error);
                }
                let expected_cas = run
                    .terminal_evidence_refs
                    .iter()
                    .map(|id| {
                        let receipt = &view.receipts.get(id).ok_or(error)?.0;
                        let digest = receipt.cas_ref.parse::<CasDigest>().map_err(|_| error)?;
                        Ok(evertrace_domain::ids::CasId::from_digest(
                            *digest.as_bytes(),
                        ))
                    })
                    .collect::<Result<Vec<_>, StoreError>>()?;
                if matching[0].raw_cas_refs != expected_cas
                    || matching[0].raw_artifact_refs != artifact_refs
                {
                    return Err(error);
                }
            }
        }
    }
    for result in results {
        let controlled_in_command = payloads.iter().any(|payload| match payload {
            JournalPayload::ExperimentRunRecorded(run) => {
                run.comparison_execution_binding.is_some()
                    && !run.is_declaration_only()
                    && result.experiment_run_revision_id == run.revision_id
            }
            _ => false,
        });
        if view
            .runs
            .get(&result.experiment_run_id)
            .is_some_and(|(run, _)| run.comparison_execution_binding.is_some())
            && !controlled_in_command
        {
            return Err(error);
        }
    }
    Ok(())
}

fn validate_declaration_anchor(
    view: &ControlledRunAdmissionView<'_>,
    procedure_revision_id: RevisionId,
    attempt: &Attempt,
    snapshot_id: WorktreeSnapshotId,
    error: StoreError,
) -> Result<(), StoreError> {
    let usage = view
        .procedures
        .controlled_usage_anchor(procedure_revision_id, attempt.attempt_id)
        .map_err(|_| error)?
        .ok_or(error)?;
    let episode = &view
        .episode_revisions
        .get(&usage.exposure_episode_revision_id)
        .ok_or(error)?
        .0;
    let current_episode = &view.episodes.get(&episode.episode_id).ok_or(error)?.0;
    let task = &view.tasks.get(&usage.task_id).ok_or(error)?.0;
    let workstream = &view.workstreams.get(&usage.workstream_id).ok_or(error)?.0;
    let repository_id = usage.local_context.repository_id.ok_or(error)?;
    let worktree_id = usage.local_context.worktree_id.ok_or(error)?;
    let snapshot = &view.snapshots.get(&snapshot_id).ok_or(error)?.0;
    let worktree = &view.worktrees.get(&worktree_id).ok_or(error)?.0;
    if current_episode.revision_id != episode.revision_id
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
        return Err(error);
    }
    Ok(())
}

fn validate_witnesses(
    receipt_ids: &[SourceReceiptId],
    launch: bool,
    run: &ExperimentRun,
    attempt: &Attempt,
    bindings: &BTreeMap<OperationId, &WorkBindingRevision>,
    view: &ControlledRunAdmissionView<'_>,
    error: StoreError,
) -> Result<ControlledRunSourceEnvelope, StoreError> {
    let mut selected = None;
    for receipt_id in receipt_ids {
        let receipt = &view.receipts.get(receipt_id).ok_or(error)?.0;
        let observation = &view
            .observations
            .get(&receipt.source_observation_id)
            .ok_or(error)?
            .0;
        let surface = &view
            .surfaces
            .get(&receipt.source_observation_id)
            .ok_or(error)?
            .0;
        if receipt.source_observation_id != observation.source_observation_id
            || observation.source_receipt_ref != receipt.source_receipt_id
            || receipt.capture_completeness != CaptureCompleteness::Complete
            || observation.capture_completeness != CaptureCompleteness::Complete
            || surface.capture_completeness != CaptureCompleteness::Complete
            || receipt.archive_mode != SourceArchiveMode::Exact
            || receipt.unsupported_record_classification.is_some()
            || receipt.protected_secret_digest.is_some()
            || !receipt.redaction_spans.is_empty()
            || receipt.canonicalization_revision != surface.canonicalization_version
            || observation.canonicalization_revision != surface.canonicalization_version
            || observation.source_role != surface.source_role
            || observation.content_trust != surface.content_trust
            || !matches!(surface.source_role, SourceRole::Host | SourceRole::Tool)
            || surface.content_trust != ContentTrust::Observed
            || observation.payload_fingerprint
                != hex(&payload_fingerprint(
                    surface.canonicalization_version,
                    surface.protected_text.as_bytes(),
                    None,
                )
                .map_err(|_| error)?)
            || receipt.cas_ref
                != CasDigest::for_protected_bytes(surface.protected_text.as_bytes()).to_string()
        {
            return Err(error);
        }
        surface.validate().map_err(|_| error)?;
        let envelope =
            ControlledRunSourceEnvelope::decode_canonical(surface.protected_text.as_bytes())
                .map_err(|_| error)?;
        if launch != matches!(envelope, ControlledRunSourceEnvelope::Launch { .. }) {
            return Err(error);
        }
        let operations = view
            .operations
            .values()
            .map(|(operation, _)| operation)
            .filter(|operation| {
                let refs = if launch {
                    &operation.input_source_observation_refs
                } else {
                    &operation.result_source_observation_refs
                };
                refs.contains(&observation.source_observation_id)
            })
            .collect::<Vec<_>>();
        if operations.is_empty()
            || operations.iter().any(|operation| {
                operation.pairing_state != PairingState::Paired
                    || bindings.get(&operation.operation_id).is_none_or(|binding| {
                        binding.assignment_status != AssignmentStatus::Resolved
                            || binding.primary_binding.experiment_run_id != Some(run.run_id)
                            || binding.primary_binding.attempt_id != Some(attempt.attempt_id)
                            || binding.primary_binding.workstream_id != Some(run.workstream_id)
                    })
            })
        {
            return Err(error);
        }
        if selected
            .as_ref()
            .is_some_and(|current| current != &envelope)
        {
            return Err(error);
        }
        selected = Some(envelope);
    }
    selected.ok_or(error)
}

fn launch_matches(
    run: &ExperimentRun,
    attempt: &Attempt,
    binding: &evertrace_domain::work::ComparisonExecutionBinding,
    envelope: &ControlledRunSourceEnvelope,
) -> bool {
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
        binding: source_binding,
        started_at_us,
        ..
    } = envelope
    else {
        return false;
    };
    *attempt_id == attempt.attempt_id
        && binding
            .procedure_exposure_revision_id
            .is_none_or(|value| value == *procedure_revision_id)
        && attempt.strategy_contract.search_policy_ref.as_deref()
            == Some(procedure_revision_id.to_string()).as_deref()
        && run.code_snapshot_id == *code_snapshot_id
        && run.data_fingerprint == *data_fingerprint
        && run.normalized_config == *normalized_config
        && run.variable_declaration == *variable_declaration
        && run.seed_policy == *seed_policy
        && run.seed_values == *seed_values
        && run.nondeterministic == *nondeterministic
        && run.metric_definition == *metric_definition
        && run.metric_extractor_version == *metric_extractor_version
        && run.multi_cas_metric_policy == *multi_cas_metric_policy
        && run.environment_fingerprint == *environment_fingerprint
        && binding == source_binding.as_ref()
        && run.started_at_us == Some(*started_at_us)
}

fn native_source_bytes<'a>(
    view: &'a ControlledRunAdmissionView<'_>,
    id: SourceReceiptId,
    role: evertrace_domain::evidence::ObservationRole,
    complete: bool,
    error: StoreError,
) -> Result<
    (
        &'a SourceReceipt,
        &'a evertrace_domain::evidence::SourceObservation,
        &'a [u8],
    ),
    StoreError,
> {
    let receipt = &view.receipts.get(&id).ok_or(error)?.0;
    let observation = &view
        .observations
        .get(&receipt.source_observation_id)
        .ok_or(error)?
        .0;
    let surface = &view
        .surfaces
        .get(&receipt.source_observation_id)
        .ok_or(error)?
        .0;
    surface.validate().map_err(|_| error)?;
    let raw = surface.protected_text.as_bytes();
    if observation.source_receipt_ref != id
        || observation.observation_role != role
        || observation.source_instance_id != receipt.source_instance_id
        || observation.source_revision != receipt.source_revision
        || observation.source_record_identity != receipt.source_record_identity
        // Intent supplies the admitted namespace; image3 separately authenticates it. A study
        // declaration is never an observed result; only an already accepted root can own it.
        || match role {
            evertrace_domain::evidence::ObservationRole::Intent => false,
            evertrace_domain::evidence::ObservationRole::Other => observation.content_trust != ContentTrust::UntrustedSourceContent,
            _ => observation.content_trust != ContentTrust::Observed,
        }
        || observation.source_role != SourceRole::Tool
        || surface.source_role != observation.source_role
        || surface.content_trust != observation.content_trust
        || surface.source_observation_revision_ref != observation.source_observation_id
        || surface.canonicalization_version != receipt.canonicalization_revision
        || observation.canonicalization_revision != receipt.canonicalization_revision
        || surface.capture_completeness != receipt.capture_completeness
        || observation.capture_completeness != receipt.capture_completeness
        || complete && receipt.capture_completeness != CaptureCompleteness::Complete
        || receipt.archive_mode != SourceArchiveMode::Exact
        || receipt.unsupported_record_classification.is_some()
        || receipt.protected_secret_digest.is_some()
        || !receipt.redaction_spans.is_empty()
        || receipt.protected_length != raw.len() as u64
        || CasDigest::for_protected_bytes(raw).to_string() != receipt.cas_ref
        || observation.payload_fingerprint
            != hex(
                &payload_fingerprint(receipt.canonicalization_revision, raw, None)
                    .map_err(|_| error)?,
            )
    {
        return Err(error);
    }
    Ok((receipt, observation, raw))
}

/// Only a recorded native retry names a parent; equal inputs and metric values never do.
pub(super) fn native_retry_parent(
    view: &ControlledRunAdmissionView<'_>,
    child: &ExperimentRun,
    cancelled: &std::sync::atomic::AtomicBool,
    deadline: std::time::Instant,
) -> Result<Option<RevisionId>, StoreError> {
    let Some((source, launch)) = native_trial_identity(view, child) else {
        return Ok(None);
    };
    let Some(retried) = launch
        .retry_of_execution
        .filter(|value| *value != launch.execution_key)
    else {
        return Ok(None);
    };
    let key = format!("{}/{retried}", launch.source_epoch);
    let mut parent = None;
    for (run, _) in view.runs.values() {
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(StoreError::Io);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        if run.external_run_key.as_deref() == Some(key.as_str())
            && run.workstream_id == child.workstream_id
            && run.attempt_id == child.attempt_id
            && let Some((earlier_source, earlier)) = native_trial_identity(view, run)
            && earlier_source.source_instance_id == source.source_instance_id
            && earlier_source.source_sequence < source.source_sequence
            && earlier.request_key == launch.request_key
            && earlier.execution_ordinal < launch.execution_ordinal
            && parent.replace(run.revision_id).is_some()
        {
            return Ok(None);
        }
    }
    Ok(parent)
}

#[derive(serde::Deserialize)]
struct NativeTrialIdentity<'a> {
    format: &'a str,
    event: &'a str,
    event_key: &'a str,
    source_epoch: &'a str,
    execution_key: &'a str,
    request_key: &'a str,
    execution_ordinal: u32,
    retry_of_execution: Option<&'a str>,
}

fn native_trial_identity<'a>(
    view: &'a ControlledRunAdmissionView<'_>,
    run: &ExperimentRun,
) -> Option<(&'a SourceReceipt, NativeTrialIdentity<'a>)> {
    use evertrace_capture::process_source;
    use evertrace_domain::{evidence::ObservationRole, work::is_native_test_contract_parser};
    if !is_native_test_contract_parser(&run.metric_extractor_version)
        || run.external_system_id.as_deref() != Some(process_source::FORMAT)
        || run.attempt_binding_status != AttemptBindingStatus::Resolved
    {
        return None;
    }
    let mut launches = run.source_receipt_refs.iter().filter_map(|id| {
        let (receipt, observation, raw) = native_source_bytes(
            view,
            *id,
            ObservationRole::Intent,
            false,
            StoreError::InvalidInput,
        )
        .ok()?;
        if receipt.source_revision.as_str() != process_source::SOURCE_REVISION
            || receipt.identity_domain != process_source::FORMAT
        {
            return None;
        }
        let launch: NativeTrialIdentity<'_> = serde_json::from_slice(raw).ok()?;
        let correlation = &observation.correlation;
        (launch.format == process_source::FORMAT
            && launch.event == "trial_launch"
            && launch.event_key == receipt.source_record_identity.as_str()
            && run.external_run_key.as_deref()
                == Some(format!("{}/{}", launch.source_epoch, launch.execution_key).as_str())
            && correlation.exact_key().is_some()
            && correlation.host_trace_lineage_id.as_deref() == Some(launch.source_epoch)
            && correlation.native_request_id.as_deref() == Some(launch.request_key)
            && correlation.physical_execution_ordinal == Some(launch.execution_ordinal))
        .then_some((receipt, launch))
    });
    launches.next().filter(|_| launches.next().is_none())
}

fn validate_native_contract(
    view: &ControlledRunAdmissionView<'_>,
    run: &ExperimentRun,
    close: Option<(&WorkEpisode, &[&JournalPayload])>,
    error: StoreError,
) -> Result<evertrace_domain::work::NativeTestContract, StoreError> {
    use evertrace_capture::process_source;
    use evertrace_domain::evidence::ObservationRole;
    let launches = run
        .source_receipt_refs
        .iter()
        .filter_map(|id| view.receipts.get(id))
        .filter(|(receipt, _)| receipt.source_revision.as_str() == process_source::SOURCE_REVISION)
        .filter(|(receipt, _)| {
            view.observations
                .get(&receipt.source_observation_id)
                .is_some_and(|(observation, _)| {
                    observation.observation_role == ObservationRole::Intent
                })
        })
        .map(|(receipt, _)| receipt.source_receipt_id)
        .collect::<Vec<_>>();
    let [launch_id] = launches.as_slice() else {
        return Err(error);
    };
    let (receipt, launch, raw) =
        native_source_bytes(view, *launch_id, ObservationRole::Intent, false, error)?;
    let basis = &view.snapshots.get(&run.code_snapshot_id).ok_or(error)?.0;
    let anchor = if run.metric_extractor_version
        == evertrace_domain::work::NATIVE_TEST_COHORT_PARSER_VERSION
    {
        let prefix = format!(
            "native-execution-directory:{}:",
            launch.source_observation_id
        );
        let witnesses = view
            .snapshots
            .values()
            .filter(|(snapshot, _)| {
                snapshot
                    .evidence_refs
                    .iter()
                    .any(|reference| reference.starts_with(&prefix))
            })
            .map(|(snapshot, _)| snapshot)
            .collect::<Vec<_>>();
        let [witness] = witnesses.as_slice() else {
            return Err(error);
        };
        *witness
    } else {
        basis
    };
    let contract = evertrace_domain::work::NativeTestContract::decode(
        raw,
        anchor,
        launch.source_observation_id,
        receipt.source_revision.as_str(),
    )
    .ok_or(error)?;
    let value: serde_json::Value = serde_json::from_slice(raw).map_err(|_| error)?;
    let process = &value["process"];
    let instance = format!(
        "native-runtime:{}:{}:{}:{}",
        process["boot_id"].as_str().ok_or(error)?,
        process["pid_namespace"].as_u64().ok_or(error)?,
        process["pid"].as_u64().ok_or(error)?,
        process["start_ticks"].as_u64().ok_or(error)?
    );
    let reference = format!(
        "runtime:{}:{}@{}",
        value["source_epoch"].as_str().ok_or(error)?,
        value["execution_key"].as_str().ok_or(error)?,
        process["start_ticks"].as_u64().ok_or(error)?
    );
    let images = run
        .source_receipt_refs
        .iter()
        .filter_map(|id| view.receipts.get(id))
        .filter(|(receipt, _)| {
            receipt.source_revision.as_str() == process_source::IMAGE_SOURCE_REVISION
        })
        .map(|(receipt, _)| receipt.source_receipt_id)
        .collect::<Vec<_>>();
    let [image_id] = images.as_slice() else {
        return Err(error);
    };
    let (image, _, image_raw) =
        native_source_bytes(view, *image_id, ObservationRole::StateProbe, true, error)?;
    let attempt = &view
        .attempts
        .get(&run.attempt_id.ok_or(error)?)
        .ok_or(error)?
        .0;
    let stream = &view.workstreams.get(&run.workstream_id).ok_or(error)?.0;
    let episode = &view
        .episodes
        .get(&attempt.episode_id.ok_or(error)?)
        .ok_or(error)?
        .0;
    let tree = &view
        .worktrees
        .get(&anchor.worktree_instance_id)
        .ok_or(error)?
        .0;
    let entry = episode
        .entry_worktree_snapshot_id
        .and_then(|id| view.snapshots.get(&id))
        .map(|(value, _)| value);
    if run.metric_extractor_version == evertrace_domain::work::NATIVE_TEST_COHORT_PARSER_VERSION
        && evertrace_domain::work::NativeTestContract::code_basis(anchor, entry)
            .worktree_snapshot_id
            != run.code_snapshot_id
    {
        return Err(error);
    }
    if !contract.matches_run(run)
        || run.comparison_execution_binding.is_some()
        || run.origin != evertrace_domain::work::RunOrigin::External
        || run.external_system_id.as_deref() != Some(process_source::FORMAT)
        || run.external_run_key.as_deref()
            != Some(
                format!(
                    "{}/{}",
                    value["source_epoch"].as_str().ok_or(error)?,
                    value["execution_key"].as_str().ok_or(error)?
                )
                .as_str(),
            )
        || launch.correlation.exact_key().is_none()
        || (receipt.adapter_revision, receipt.parser_revision)
            != (
                process_source::ADAPTER_REVISION,
                process_source::PARSER_REVISION,
            )
        || image_raw != raw
        || (image.adapter_revision, image.parser_revision) != (3, 3)
        || image.source_instance_id.as_str() != instance
        || image.source_ref != reference
        || image.source_record_identity.as_str() != run.environment_fingerprint
        || image.identity_domain != process_source::IMAGE_SOURCE_REVISION
        || image.identity_strength != evertrace_domain::evidence::IdentityStrength::StableNative
        || run.attempt_binding_status != AttemptBindingStatus::Resolved
        || attempt.workstream_id != stream.workstream_id
        || attempt.task_id != stream.task_id
        || attempt.strategy_contract_fingerprint != run.strategy_contract_fingerprint
        || episode.lifecycle_status == evertrace_domain::work::EpisodeLifecycle::Superseded
        || !episode.attempt_ids.contains(&attempt.attempt_id)
        || episode.workstream_id != stream.workstream_id
        || episode.task_id != stream.task_id
        || episode.worktree_instance_id != Some(tree.worktree_instance_id)
        || attempt.repository_instance_id != Some(tree.repository_instance_id)
        || stream.repository_instance_id != Some(tree.repository_instance_id)
        || !attempt
            .worktree_instance_ids
            .contains(&tree.worktree_instance_id)
        || !stream
            .worktree_instance_ids
            .contains(&tree.worktree_instance_id)
    {
        return Err(error);
    }
    // A new execution outside the active Phase requires an exact, protected sibling study binding.
    if run.is_declaration_only() && stream.active_episode_id != Some(episode.episode_id) {
        if stream.status.is_terminal()
            || episode.lifecycle_status != evertrace_domain::work::EpisodeLifecycle::Closed
        {
            return Err(error);
        }
        validate_native_study(view, run, receipt, &value, stream, episode, error)?;
    }
    if let Some((closed, payloads)) = close {
        validate_native_study(view, run, receipt, &value, stream, episode, error)?;
        validate_native_launch_close(
            view, run, attempt, stream, episode, anchor, closed, payloads, error,
        )?;
    }
    Ok(contract)
}

fn validate_native_study(
    view: &ControlledRunAdmissionView<'_>,
    run: &ExperimentRun,
    launch: &SourceReceipt,
    event: &serde_json::Value,
    stream: &Workstream,
    episode: &WorkEpisode,
    error: StoreError,
) -> Result<(), StoreError> {
    use evertrace_domain::{
        evidence::ObservationRole,
        work::{NATIVE_TEST_COHORT_PARSER_VERSION, PhaseKind},
    };
    if run.metric_extractor_version != NATIVE_TEST_COHORT_PARSER_VERSION
        || episode.phase_contract.phase_kind != PhaseKind::Execute
    {
        return Err(error);
    }
    let mut openings = run.source_receipt_refs.iter().filter_map(|id| {
        let (receipt, _) = view.receipts.get(id)?;
        (receipt.source_instance_id == launch.source_instance_id
            && receipt.source_revision == launch.source_revision
            && receipt.source_sequence == 1)
            .then_some(receipt.source_receipt_id)
    });
    let opening = openings
        .next()
        .filter(|_| openings.next().is_none())
        .ok_or(error)?;
    let (receipt, observation, raw) =
        native_source_bytes(view, opening, ObservationRole::Other, false, error)?;
    let study: serde_json::Value = serde_json::from_slice(raw).map_err(|_| error)?;
    let phase: evertrace_domain::work::PhaseContract =
        serde_json::from_value(study["definition"]["phase"].clone()).map_err(|_| error)?;
    let reference = observation.source_observation_id.to_string();
    if receipt.identity_domain != evertrace_capture::process_source::FORMAT
        || study["format"] != evertrace_capture::process_source::FORMAT
        || study["event"] != "study_opened"
        || study["event_key"].as_str() != Some(receipt.source_record_identity.as_str())
        || study["source_epoch"] != event["source_epoch"]
        || study["study_key"] != event["study_key"]
        || phase != episode.phase_contract
        || !stream.worktree_lineage_refs.contains(&reference)
    {
        return Err(error);
    }
    let bindings = current_binding_lineage(view.work_bindings.values().map(|(value, _)| value))
        .map_err(|_| error)?;
    if !bindings.values().any(|binding| {
        binding.assignment_status == AssignmentStatus::Resolved
            && binding.primary_binding.task_id == Some(stream.task_id)
            && binding.primary_binding.workstream_id == Some(stream.workstream_id)
            && binding.primary_binding.episode_id == Some(episode.episode_id)
            && !binding.scope_effect_refs.is_empty()
            && binding.evidence_refs.contains(&reference)
    }) {
        return Err(error);
    }
    Ok(())
}

fn validate_native_launch_close(
    view: &ControlledRunAdmissionView<'_>,
    run: &ExperimentRun,
    attempt: &Attempt,
    stream: &Workstream,
    phase: &WorkEpisode,
    witness: &WorktreeSnapshot,
    closed: &WorkEpisode,
    payloads: &[&JournalPayload],
    error: StoreError,
) -> Result<(), StoreError> {
    use evertrace_domain::work::{
        AttemptExecutionStatus, AttemptLifecycleStatus, OperationBurstLifecycle,
        confirm_experiment_launch,
    };
    let next_attempt = payloads
        .iter()
        .find_map(|payload| match payload {
            JournalPayload::AttemptRecorded(value) if value.attempt_id == attempt.attempt_id => {
                Some(value.as_ref())
            }
            _ => None,
        })
        .unwrap_or(attempt);
    let mut streams = payloads.iter().filter_map(|payload| match payload {
        JournalPayload::WorkstreamRecorded(value) => Some(value.as_ref()),
        _ => None,
    });
    let paused = streams
        .next()
        .filter(|_| streams.next().is_none())
        .ok_or(error)?;
    if next_attempt.execution_status != AttemptExecutionStatus::Active
        || next_attempt.lifecycle_status != AttemptLifecycleStatus::Active
        || confirm_experiment_launch(
            run,
            phase,
            stream,
            witness,
            view.frontier,
            (closed.revision_id, paused.revision_id),
        )
        .is_none_or(|(expected, expected_stream)| expected != *closed || expected_stream != *paused)
    {
        return Err(error);
    }
    let mut updates = payloads.iter().filter_map(|payload| match payload {
        JournalPayload::OperationBurstRecorded(value) => Some(value.as_ref()),
        _ => None,
    });
    for id in &phase.operation_burst_refs {
        let current = &view.bursts.get(id).ok_or(error)?.0;
        if current.lifecycle == OperationBurstLifecycle::Open {
            let next = updates.next().ok_or(error)?;
            let mut expected = current.clone();
            expected.revision_id = next.revision_id;
            expected.predecessor_revision_id = Some(current.revision_id);
            expected.revision_generation =
                current.revision_generation.checked_add(1).ok_or(error)?;
            expected.lifecycle = OperationBurstLifecycle::Closed;
            if expected != *next || current.validate_successor(next).is_err() {
                return Err(error);
            }
        }
    }
    if updates.next().is_some() {
        return Err(error);
    }
    Ok(())
}

fn validate_native_terminal_cohort(
    view: &ControlledRunAdmissionView<'_>,
    run: &ExperimentRun,
    payloads: &[&JournalPayload],
    error: StoreError,
) -> Result<(), StoreError> {
    use evertrace_domain::semantic::{EvidenceCompleteness, ParserStatus, ResultScope};
    if !evertrace_domain::work::is_native_test_contract_parser(&run.metric_extractor_version) {
        return Err(error);
    }
    let current = &view.runs.get(&run.run_id).ok_or(error)?.0;
    let contract = validate_native_contract(view, run, None, error)?;
    current.validate_successor(run).map_err(|_| error)?;
    let results = payloads
        .iter()
        .filter_map(|payload| match payload {
            JournalPayload::ResultEvidenceRecorded(result)
                if result.experiment_run_id == run.run_id =>
            {
                Some(result.as_ref())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [result] = results.as_slice() else {
        return Err(error);
    };
    let [terminal] = run.terminal_evidence_refs.as_slice() else {
        return Err(error);
    };
    let (_, _, raw) = native_source_bytes(
        view,
        *terminal,
        evertrace_domain::evidence::ObservationRole::Result,
        true,
        error,
    )?;
    let event = evertrace_domain::work::NativeTestResult::decode(raw).ok_or(error)?;
    let ended_at = serde_json::from_slice::<serde_json::Value>(raw).map_err(|_| error)?["time_us"]
        .as_i64()
        .ok_or(error)?;
    let digest = hex(&result.raw_cas_refs.first().ok_or(error)?.as_digest());
    let mut artifacts = current.work_artifact_refs.clone();
    artifacts.extend(&result.raw_artifact_refs);
    artifacts.sort();
    artifacts.dedup();
    if !current.is_declaration_only()
        || run.parent_revision_id != Some(current.revision_id)
        || current.metric_extractor_version != run.metric_extractor_version
        || run.source_receipt_refs != current.source_receipt_refs
        || run.created_at_us != current.created_at_us
        || run.attempt_id != current.attempt_id
        || run.attempt_binding_status != current.attempt_binding_status
        || run.observability != RunObservability::Full
        || run.execution_status != RunExecutionStatus::Completed
        || run.contract_validity != RunContractValidity::Valid
        || run.started_at_us != Some(contract.started_at_us)
        || run.ended_at_us != Some(ended_at)
        || run
            .ended_at_us
            .is_none_or(|ended| ended < contract.started_at_us)
        || result.experiment_run_revision_id != run.revision_id
        || result.result_scope != ResultScope::Complete
        || result.completeness != EvidenceCompleteness::Complete
        || result.parser_receipt.status != ParserStatus::Parsed
        || event.metric().is_none()
        || result.parsed_metric != event.metric()
        || result.failure.is_some()
        || run.work_artifact_refs != artifacts
        || result.raw_cas_refs.len() != 1
        || view
            .receipts
            .get(terminal)
            .is_none_or(|(receipt, _)| receipt.cas_ref != digest)
    {
        return Err(error);
    }
    validate_native_analysis_handoff(view, run, result, payloads, error)
}

fn validate_native_analysis_handoff(
    view: &ControlledRunAdmissionView<'_>,
    run: &ExperimentRun,
    result: &ResultEvidence,
    payloads: &[&JournalPayload],
    error: StoreError,
) -> Result<(), StoreError> {
    use evertrace_domain::work::{
        NATIVE_TEST_COHORT_PARSER_VERSION, WorkstreamStatus, awaiting_experiment_result,
        experiment_analysis_phase,
    };
    let mut episodes = payloads.iter().filter_map(|payload| match payload {
        JournalPayload::WorkEpisodeRecorded(episode) => Some(episode.as_ref()),
        _ => None,
    });
    let mut streams = payloads.iter().filter_map(|payload| match payload {
        JournalPayload::WorkstreamRecorded(stream) => Some(stream.as_ref()),
        _ => None,
    });
    let stream = &view.workstreams.get(&run.workstream_id).ok_or(error)?.0;
    let attempt = &view
        .attempts
        .get(&run.attempt_id.ok_or(error)?)
        .ok_or(error)?
        .0;
    let launch = &view
        .episodes
        .get(&attempt.episode_id.ok_or(error)?)
        .ok_or(error)?
        .0;
    let (episode, resumed) = (episodes.next(), streams.next());
    if run.metric_extractor_version != NATIVE_TEST_COHORT_PARSER_VERSION
        || !awaiting_experiment_result(stream, launch)
    {
        return if episode.is_none() && resumed.is_none() {
            Ok(())
        } else {
            Err(error)
        };
    }
    let (Some(episode), Some(resumed)) = (episode, resumed) else {
        return Err(error);
    };
    if episodes.next().is_some()
        || streams.next().is_some()
        || view.episodes.contains_key(&episode.episode_id)
    {
        return Err(error);
    }
    let mut expected = stream.clone();
    expected.predecessor_revision_id = Some(stream.revision_id);
    expected.revision_id = resumed.revision_id;
    expected.status = WorkstreamStatus::Active;
    expected.phase_contract = experiment_analysis_phase(run, result.result_evidence_id);
    expected.source_watermark = view
        .frontier
        .max(stream.source_watermark.checked_add(1).ok_or(error)?);
    let initial = WorkEpisode::start(
        episode.episode_id,
        episode.revision_id,
        &expected,
        None,
        expected.source_watermark,
    )
    .map_err(|_| error)?;
    expected.active_episode_id = Some(episode.episode_id);
    if initial != *episode || expected != *resumed {
        return Err(error);
    }
    Ok(())
}

fn validate_native_test_result(
    view: &ControlledRunAdmissionView<'_>,
    result: &ResultEvidence,
    payloads: &[&JournalPayload],
    error: StoreError,
) -> Result<(), StoreError> {
    use evertrace_domain::{
        semantic::VerifierStatus,
        semantic::{EvidenceCompleteness, ParserFailureCode, ParserStatus, ResultScope},
        work::{NativeTestResult, is_native_test_parser},
    };
    let command_run = payloads.iter().find_map(|payload| match payload {
        JournalPayload::ExperimentRunRecorded(run) if run.run_id == result.experiment_run_id => {
            Some(run.as_ref())
        }
        _ => None,
    });
    let run = command_run
        .or_else(|| view.runs.get(&result.experiment_run_id).map(|(run, _)| run))
        .ok_or(error)?;
    let full =
        evertrace_domain::work::is_native_test_contract_parser(&run.metric_extractor_version)
            && result.result_scope == ResultScope::Complete;
    if result.experiment_run_revision_id != run.revision_id
        || !is_native_test_parser(&run.metric_extractor_version)
        || result.parser_receipt.parser_version != run.metric_extractor_version
        || if full {
            command_run.is_none()
                || run.observability != RunObservability::Full
                || run.execution_status != RunExecutionStatus::Completed
                || run.contract_validity != RunContractValidity::Valid
                || result.completeness != EvidenceCompleteness::Complete
                || result.verifier_receipt.as_ref().is_none_or(|receipt| {
                    receipt.status != VerifierStatus::Passed
                        || receipt.verifier_version != "evertrace.result_reparse.v1"
                        || receipt.failure_code.is_some()
                })
        } else {
            !run.is_declaration_only()
                || result.result_scope != ResultScope::Partial
                || result.completeness != EvidenceCompleteness::Incomplete
                || result.verifier_receipt.is_some()
        }
        || run.attempt_binding_status != AttemptBindingStatus::Resolved
        || result.parent_revision_id.is_some()
        || result.raw_artifact_refs.len() != 1
        || result.parser_receipt.input_artifact_refs != result.raw_artifact_refs
        || result.raw_cas_refs.len() != 1
        || result.parser_receipt.input_cas_refs != result.raw_cas_refs
    {
        return Err(error);
    }
    let digest = hex(&result.raw_cas_refs[0].as_digest());
    let artifact_id = result.raw_artifact_refs[0];
    let artifact = payloads
        .iter()
        .rev()
        .find_map(|payload| match payload {
            JournalPayload::WorkArtifactRecorded(value)
                if value.work_artifact_id == artifact_id =>
            {
                Some(value.as_ref())
            }
            _ => None,
        })
        .or_else(|| view.artifacts.get(&artifact_id).map(|(value, _)| value))
        .ok_or(error)?;
    let snapshot = &view.snapshots.get(&run.code_snapshot_id).ok_or(error)?.0;
    let worktree = &view
        .worktrees
        .get(&snapshot.worktree_instance_id)
        .ok_or(error)?
        .0;
    let [id] = artifact.revision.source_observation_refs.as_slice() else {
        return Err(error);
    };
    let id = *id;
    use evertrace_domain::work::{ArtifactPayloadStatus, WorkArtifactKind};
    if artifact.revision.kind != WorkArtifactKind::ExperimentOutput
        || artifact.revision.payload_status != ArtifactPayloadStatus::Available
        || full && artifact.revision.produced_by_refs != [ArtifactActor::ExperimentRun(run.run_id)]
        || artifact.revision.content_blob_ref != result.raw_cas_refs.first().copied()
        || artifact.revision.scope
            != (ArtifactScope::Worktree {
                repository_instance_id: worktree.repository_instance_id,
                worktree_instance_id: snapshot.worktree_instance_id,
            })
    {
        return Err(error);
    }
    // A CAS digest locates protected bytes, not the physical observation or publisher.
    let receipt_id = view
        .observations
        .get(&id)
        .ok_or(error)?
        .0
        .source_receipt_ref;
    let (receipt, observation, raw) = native_source_bytes(
        view,
        receipt_id,
        evertrace_domain::evidence::ObservationRole::Result,
        true,
        error,
    )?;
    use evertrace_capture::process_source;
    if receipt.source_observation_id != id
        || receipt.cas_ref != digest
        || receipt.source_revision.as_str() != process_source::SOURCE_REVISION
        || (receipt.adapter_revision, receipt.parser_revision)
            != (
                process_source::ADAPTER_REVISION,
                process_source::PARSER_REVISION,
            )
        || receipt.identity_domain != process_source::FORMAT
        || full && run.terminal_evidence_refs != [receipt_id]
    {
        return Err(error);
    }
    let event = NativeTestResult::decode(raw).ok_or(error)?;
    use evertrace_domain::evidence::ObservationRole;
    let mut launches = run.source_receipt_refs.iter().filter_map(|id| {
        let (receipt, _) = view.receipts.get(id)?;
        let (value, _) = view.observations.get(&receipt.source_observation_id)?;
        (value.source_receipt_ref == *id
            && value.source_revision.as_str() == process_source::SOURCE_REVISION
            && value.source_instance_id == observation.source_instance_id
            && value.source_record_identity.as_str() == event.launch_event
            && value.observation_role == ObservationRole::Intent)
            .then_some(value)
    });
    let launch = launches
        .next()
        .filter(|_| launches.next().is_none())
        .ok_or(error)?;
    let key = format!("{}/{}", event.source_epoch, event.execution_key);
    if receipt.source_record_identity.as_str() != event.event_key
        || observation.correlation.exact_key().is_none()
        || observation.correlation.exact_key() != launch.correlation.exact_key()
        || observation.correlation.host_trace_lineage_id.as_deref()
            != Some(event.source_epoch.as_str())
        || observation.correlation.native_request_id.as_deref() != Some(event.request_key.as_str())
        || observation.correlation.physical_execution_ordinal != Some(event.execution_ordinal)
        || run.external_system_id.as_deref() != Some(process_source::FORMAT)
        || run.external_run_key.as_deref() != Some(key.as_str())
    {
        return Err(error);
    }
    let bindings = current_binding_lineage(view.work_bindings.values().map(|(value, _)| value))
        .map_err(|_| error)?;
    let operations = view
        .operations
        .values()
        .filter(|(value, _)| value.result_source_observation_refs.contains(&id))
        .map(|(value, _)| value)
        .collect::<Vec<_>>();
    if operations.is_empty()
        || operations.iter().any(|operation| {
            operation.pairing_state != PairingState::Paired
                || full
                    && !operation
                        .input_source_observation_refs
                        .contains(&launch.source_observation_id)
                || bindings.get(&operation.operation_id).is_none_or(|binding| {
                    binding.assignment_status != AssignmentStatus::Resolved
                        || binding.primary_binding.experiment_run_id != Some(run.run_id)
                        || binding.primary_binding.attempt_id != run.attempt_id
                        || binding.primary_binding.workstream_id != Some(run.workstream_id)
                })
        })
    {
        return Err(error);
    }
    let metric = event.metric();
    let failure = metric
        .is_none()
        .then_some(ParserFailureCode::MetricParseFailed);
    if result.parsed_metric != metric
        || result.parser_receipt.failure_code != failure
        || (result.parser_receipt.status == ParserStatus::Failed) != failure.is_some()
    {
        return Err(error);
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AutoresearchCurrentView {
    pub frontier: u64,
    pub runs: BTreeMap<ExperimentRunId, ExperimentRun>,
    pub results: BTreeMap<ResultEvidenceId, ResultEvidence>,
    pub artifacts: BTreeMap<WorkArtifactId, WorkArtifact>,
}

pub(crate) struct AutoresearchRelationInputs<'a> {
    pub runs: &'a BTreeMap<ExperimentRunId, (ExperimentRun, u64)>,
    pub run_revisions: &'a BTreeMap<RevisionId, (ExperimentRun, u64)>,
    pub results: &'a BTreeMap<ResultEvidenceId, (ResultEvidence, u64)>,
    pub artifacts: &'a BTreeMap<WorkArtifactId, (WorkArtifact, u64)>,
    pub attempts: &'a BTreeMap<AttemptId, (Attempt, u64)>,
    pub tasks: &'a BTreeMap<TaskId, (Task, u64)>,
    pub workstreams: &'a BTreeMap<WorkstreamId, (Workstream, u64)>,
    pub operations: &'a BTreeMap<OperationId, (Operation, u64)>,
    pub episodes: &'a BTreeMap<WorkEpisodeId, (WorkEpisode, u64)>,
    pub snapshots: &'a BTreeMap<WorktreeSnapshotId, (WorktreeSnapshot, u64)>,
    pub repositories: &'a BTreeMap<evertrace_domain::ids::RepositoryId, (RepositoryInstance, u64)>,
    pub worktrees: &'a BTreeMap<evertrace_domain::ids::WorktreeId, (WorktreeInstance, u64)>,
    pub source_receipts: &'a SourceReceiptFacts,
    pub source_observations: &'a SourceObservationFacts,
}

pub(crate) fn validate_relations(input: AutoresearchRelationInputs<'_>) -> Result<(), StoreError> {
    for (run, _) in input.runs.values() {
        let workstream = &input
            .workstreams
            .get(&run.workstream_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        if run
            .source_receipt_refs
            .iter()
            .chain(&run.terminal_evidence_refs)
            .any(|id| !input.source_receipts.contains_key(id))
            || !input.snapshots.contains_key(&run.code_snapshot_id)
        {
            return Err(StoreError::StoreCorrupt);
        }
        if run.attempt_binding_status == AttemptBindingStatus::Resolved {
            let attempt = &input
                .attempts
                .get(&run.attempt_id.ok_or(StoreError::StoreCorrupt)?)
                .ok_or(StoreError::StoreCorrupt)?
                .0;
            if attempt.workstream_id != workstream.workstream_id {
                return Err(StoreError::StoreCorrupt);
            }
            if attempt.strategy_contract_fingerprint != run.strategy_contract_fingerprint {
                return Err(StoreError::StoreCorrupt);
            }
        }
        if run
            .work_artifact_refs
            .iter()
            .any(|id| !input.artifacts.contains_key(id))
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for (result, _) in input.results.values() {
        let run = &input
            .run_revisions
            .get(&result.experiment_run_revision_id)
            .ok_or(StoreError::StoreCorrupt)?
            .0;
        if run.run_id != result.experiment_run_id
            || run.metric_extractor_version != result.parser_receipt.parser_version
            || !matches!(
                result.parser_receipt.parser_version.as_str(),
                "evertrace.result_metric.v1"
                    | evertrace_domain::work::NATIVE_TEST_RESULT_PARSER_VERSION
                    | evertrace_domain::work::NATIVE_TEST_CONTRACT_PARSER_VERSION
                    | evertrace_domain::work::NATIVE_TEST_COHORT_PARSER_VERSION
            )
            || result
                .verifier_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.verifier_version != "evertrace.result_reparse.v1")
            || result
                .raw_artifact_refs
                .iter()
                .chain(&result.parser_receipt.input_artifact_refs)
                .any(|id| !input.artifacts.contains_key(id))
            || result.result_scope == evertrace_domain::semantic::ResultScope::Complete
                && !(run.observability == RunObservability::Full
                    && run.execution_status == RunExecutionStatus::Completed
                    && run.contract_validity == RunContractValidity::Valid)
        {
            return Err(StoreError::StoreCorrupt);
        }
    }
    for (artifact, _) in input.artifacts.values() {
        let revision = &artifact.revision;
        let observations = revision
            .source_observation_refs
            .iter()
            .map(|id| observation_receipt(&input, *id))
            .collect::<Result<Vec<_>, _>>()?;
        if revision
            .produced_by_refs
            .iter()
            .chain(&revision.consumed_by_refs)
            .any(|actor| {
                !actor_matches_scope(&input, actor, &revision.scope, artifact.work_artifact_id)
            })
            || revision.produced_by_refs.is_empty()
                && revision.payload_status
                    == evertrace_domain::work::ArtifactPayloadStatus::Available
                && !revision.content_blob_ref.is_some_and(|content| {
                    let digest = hex(&content.as_digest());
                    observations.iter().any(|receipt| receipt.cas_ref == digest)
                })
        {
            return Err(StoreError::StoreCorrupt);
        }
        match revision.scope {
            ArtifactScope::Task { task_id } => {
                if !input.tasks.contains_key(&task_id) {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ArtifactScope::Repository {
                repository_instance_id,
            } => {
                if !input.repositories.contains_key(&repository_instance_id) {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ArtifactScope::Worktree {
                repository_instance_id,
                worktree_instance_id,
            } => {
                let worktree = &input
                    .worktrees
                    .get(&worktree_instance_id)
                    .ok_or(StoreError::StoreCorrupt)?
                    .0;
                if worktree.repository_instance_id != repository_instance_id
                    || !input.repositories.contains_key(&repository_instance_id)
                {
                    return Err(StoreError::StoreCorrupt);
                }
            }
            ArtifactScope::Global => {}
        }
        for run in input.runs.values().map(|(run, _)| run) {
            let points_to_artifact = run.work_artifact_refs.contains(&artifact.work_artifact_id);
            let artifact_points_to_run = revision
                .produced_by_refs
                .contains(&ArtifactActor::ExperimentRun(run.run_id));
            if points_to_artifact != artifact_points_to_run {
                return Err(StoreError::StoreCorrupt);
            }
        }
    }
    Ok(())
}

fn observation_receipt<'a>(
    input: &'a AutoresearchRelationInputs<'a>,
    id: SourceObservationId,
) -> Result<&'a SourceReceipt, StoreError> {
    let observation = &input
        .source_observations
        .get(&id)
        .ok_or(StoreError::StoreCorrupt)?
        .0;
    let receipt = &input
        .source_receipts
        .get(&observation.source_receipt_ref)
        .ok_or(StoreError::StoreCorrupt)?
        .0;
    if receipt.source_observation_id != id {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(receipt)
}

fn actor_matches_scope(
    input: &AutoresearchRelationInputs<'_>,
    actor: &ArtifactActor,
    scope: &ArtifactScope,
    artifact_id: WorkArtifactId,
) -> bool {
    match actor {
        ArtifactActor::ExperimentRun(id) => input.runs.get(id).is_some_and(|(run, _)| {
            let snapshot = input
                .snapshots
                .get(&run.code_snapshot_id)
                .map(|value| &value.0);
            let worktree = snapshot
                .and_then(|value| input.worktrees.get(&value.worktree_instance_id))
                .map(|value| &value.0);
            match scope {
                ArtifactScope::Task { task_id } => run
                    .attempt_id
                    .filter(|_| run.attempt_binding_status == AttemptBindingStatus::Resolved)
                    .and_then(|id| input.attempts.get(&id))
                    .is_some_and(|(attempt, _)| attempt.task_id == *task_id),
                ArtifactScope::Repository {
                    repository_instance_id,
                } => worktree
                    .is_some_and(|value| value.repository_instance_id == *repository_instance_id),
                ArtifactScope::Worktree {
                    repository_instance_id,
                    worktree_instance_id,
                } => {
                    snapshot
                        .is_some_and(|value| value.worktree_instance_id == *worktree_instance_id)
                        && worktree.is_some_and(|value| {
                            value.repository_instance_id == *repository_instance_id
                        })
                }
                ArtifactScope::Global => true,
            }
        }),
        ArtifactActor::WorkEpisode(id) => {
            input
                .episodes
                .get(id)
                .is_some_and(|(episode, _)| match scope {
                    ArtifactScope::Task { task_id } => episode.task_id == *task_id,
                    ArtifactScope::Repository {
                        repository_instance_id,
                    } => episode.repository_instance_id == Some(*repository_instance_id),
                    ArtifactScope::Worktree {
                        repository_instance_id,
                        worktree_instance_id,
                    } => {
                        episode.repository_instance_id == Some(*repository_instance_id)
                            && episode.worktree_instance_id == Some(*worktree_instance_id)
                    }
                    ArtifactScope::Global => true,
                })
        }
        ArtifactActor::Operation(id) => input.operations.get(id).is_some_and(|(operation, _)| {
            if !operation.artifact_refs.contains(&artifact_id) {
                return false;
            }
            let Ok(receipts) = operation
                .input_source_observation_refs
                .iter()
                .chain(&operation.result_source_observation_refs)
                .map(|id| observation_receipt(input, *id))
                .collect::<Result<Vec<_>, _>>()
            else {
                return false;
            };
            !receipts.is_empty()
                && match scope {
                    ArtifactScope::Task { task_id } => receipts
                        .iter()
                        .all(|receipt| receipt.task_id == Some(*task_id)),
                    ArtifactScope::Repository {
                        repository_instance_id,
                    } => receipts.iter().all(|receipt| {
                        receipt.repository_instance_id == Some(*repository_instance_id)
                    }),
                    ArtifactScope::Worktree {
                        repository_instance_id,
                        worktree_instance_id,
                    } => receipts.iter().all(|receipt| {
                        receipt.repository_instance_id == Some(*repository_instance_id)
                            && receipt.worktree_instance_id == Some(*worktree_instance_id)
                    }),
                    ArtifactScope::Global => true,
                }
        }),
    }
}

impl AutoresearchCurrentView {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Result<Self, StoreError> {
        let mut run_revisions = BTreeMap::<ExperimentRunId, Vec<ExperimentRun>>::new();
        let mut result_revisions = BTreeMap::<ResultEvidenceId, Vec<ResultEvidence>>::new();
        let mut artifact_revisions = BTreeMap::<WorkArtifactId, Vec<WorkArtifact>>::new();
        for row in snapshot.data_rows() {
            let Some(kind) = row.object_kind.as_deref() else {
                continue;
            };
            let payload_json = row
                .payload_json
                .as_deref()
                .ok_or(StoreError::StoreCorrupt)?;
            match kind {
                "experiment_run" => {
                    let payload: crate::command::JournalPayload =
                        serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
                    let crate::command::JournalPayload::ExperimentRunRecorded(value) = payload
                    else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    require_row(
                        row,
                        kind,
                        &value.run_id.to_string(),
                        &value.revision_id.to_string(),
                    )?;
                    run_revisions.entry(value.run_id).or_default().push(*value);
                }
                "result_evidence" => {
                    let payload: crate::command::JournalPayload =
                        serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
                    let crate::command::JournalPayload::ResultEvidenceRecorded(value) = payload
                    else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    require_row(
                        row,
                        kind,
                        &value.result_evidence_id.to_string(),
                        &value.revision_id.to_string(),
                    )?;
                    result_revisions
                        .entry(value.result_evidence_id)
                        .or_default()
                        .push(*value);
                }
                "work_artifact" => {
                    let payload: crate::command::JournalPayload =
                        serde_json::from_str(payload_json).map_err(|_| StoreError::StoreCorrupt)?;
                    let crate::command::JournalPayload::WorkArtifactRecorded(value) = payload
                    else {
                        return Err(StoreError::StoreCorrupt);
                    };
                    require_row(
                        row,
                        kind,
                        &value.work_artifact_id.to_string(),
                        &value.revision.revision_id.to_string(),
                    )?;
                    artifact_revisions
                        .entry(value.work_artifact_id)
                        .or_default()
                        .push(*value);
                }
                _ => {}
            }
        }
        let mut runs = BTreeMap::new();
        for (id, revisions) in run_revisions {
            runs.insert(
                id,
                fold_run_chain(revisions.into_iter().map(|value| (value, 0)).collect())?.0,
            );
        }
        let mut results = BTreeMap::new();
        for (id, revisions) in result_revisions {
            results.insert(
                id,
                fold_result_chain(revisions.into_iter().map(|value| (value, 0)).collect())?.0,
            );
        }
        let mut artifacts = BTreeMap::new();
        for (id, revisions) in artifact_revisions {
            artifacts.insert(
                id,
                fold_artifact_chain(revisions.into_iter().map(|value| (value, 0)).collect())?.0,
            );
        }
        Ok(Self {
            frontier: snapshot.frontier,
            runs,
            results,
            artifacts,
        })
    }
}

fn require_row(
    row: &crate::objects::ObjectRow,
    kind: &str,
    object_id: &str,
    revision_id: &str,
) -> Result<(), StoreError> {
    if row.object_family != Some(crate::command::ObjectFamily::Work)
        || row.row_id != format!("object:work:{kind}:{revision_id}")
        || row.object_id.as_deref() != Some(object_id)
        || row.current_revision_id.as_deref() != Some(revision_id)
    {
        return Err(StoreError::StoreCorrupt);
    }
    Ok(())
}

fn fold_run_chain(
    mut values: Vec<(ExperimentRun, u64)>,
) -> Result<(ExperimentRun, u64), StoreError> {
    let roots = values
        .iter()
        .enumerate()
        .filter(|(_, (value, _))| value.parent_revision_id.is_none())
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(StoreError::StoreCorrupt);
    }
    let (mut current, mut current_seq) = values.remove(roots[0]);
    current.validate().map_err(|_| StoreError::StoreCorrupt)?;
    if !(current.is_declaration_only() || current.is_controlled_declaration()) {
        return Err(StoreError::StoreCorrupt);
    }
    while !values.is_empty() {
        let matches = values
            .iter()
            .enumerate()
            .filter(|(_, (value, _))| value.parent_revision_id == Some(current.revision_id))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(StoreError::StoreCorrupt);
        }
        let (next, seq) = values.remove(matches[0]);
        current
            .validate_successor(&next)
            .map_err(|_| StoreError::StoreCorrupt)?;
        if !allowed_run_shape(&next) {
            return Err(StoreError::StoreCorrupt);
        }
        current = next;
        current_seq = seq;
    }
    Ok((current, current_seq))
}

fn fold_result_chain(
    mut values: Vec<(ResultEvidence, u64)>,
) -> Result<(ResultEvidence, u64), StoreError> {
    let roots = values
        .iter()
        .enumerate()
        .filter(|(_, (value, _))| value.parent_revision_id.is_none())
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(StoreError::StoreCorrupt);
    }
    let (mut current, mut current_seq) = values.remove(roots[0]);
    current.validate().map_err(|_| StoreError::StoreCorrupt)?;
    while !values.is_empty() {
        let matches = values
            .iter()
            .enumerate()
            .filter(|(_, (value, _))| value.parent_revision_id == Some(current.revision_id))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(StoreError::StoreCorrupt);
        }
        let (next, seq) = values.remove(matches[0]);
        current
            .validate_successor(&next)
            .map_err(|_| StoreError::StoreCorrupt)?;
        current = next;
        current_seq = seq;
    }
    Ok((current, current_seq))
}

fn fold_artifact_chain(
    mut values: Vec<(WorkArtifact, u64)>,
) -> Result<(WorkArtifact, u64), StoreError> {
    let roots = values
        .iter()
        .enumerate()
        .filter(|(_, (value, _))| value.revision.parent_revision_id.is_none())
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(StoreError::StoreCorrupt);
    }
    let (mut current, mut current_seq) = values.remove(roots[0]);
    current.validate().map_err(|_| StoreError::StoreCorrupt)?;
    while !values.is_empty() {
        let matches = values
            .iter()
            .enumerate()
            .filter(|(_, (value, _))| {
                value.revision.parent_revision_id == Some(current.revision.revision_id)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(StoreError::StoreCorrupt);
        }
        let (next, seq) = values.remove(matches[0]);
        current
            .validate_successor(&next)
            .map_err(|_| StoreError::StoreCorrupt)?;
        current = next;
        current_seq = seq;
    }
    Ok((current, current_seq))
}

pub(crate) fn rebuild_runs(
    current: &mut BTreeMap<ExperimentRunId, (ExperimentRun, u64)>,
    revisions: &BTreeMap<RevisionId, (ExperimentRun, u64)>,
) -> Result<(), StoreError> {
    let mut grouped = BTreeMap::<ExperimentRunId, Vec<(ExperimentRun, u64)>>::new();
    for (value, seq) in revisions.values() {
        grouped
            .entry(value.run_id)
            .or_default()
            .push((value.clone(), *seq));
    }
    current.clear();
    for (id, values) in grouped {
        current.insert(id, fold_run_chain(values)?);
    }
    Ok(())
}

pub(crate) fn rebuild_results(
    current: &mut BTreeMap<ResultEvidenceId, (ResultEvidence, u64)>,
    revisions: &BTreeMap<RevisionId, (ResultEvidence, u64)>,
) -> Result<(), StoreError> {
    let mut grouped = BTreeMap::<ResultEvidenceId, Vec<(ResultEvidence, u64)>>::new();
    for (value, seq) in revisions.values() {
        grouped
            .entry(value.result_evidence_id)
            .or_default()
            .push((value.clone(), *seq));
    }
    current.clear();
    for (id, values) in grouped {
        current.insert(id, fold_result_chain(values)?);
    }
    Ok(())
}

pub(crate) fn rebuild_artifacts(
    current: &mut BTreeMap<WorkArtifactId, (WorkArtifact, u64)>,
    revisions: &BTreeMap<RevisionId, (WorkArtifact, u64)>,
) -> Result<(), StoreError> {
    let mut grouped = BTreeMap::<WorkArtifactId, Vec<(WorkArtifact, u64)>>::new();
    for (value, seq) in revisions.values() {
        grouped
            .entry(value.work_artifact_id)
            .or_default()
            .push((value.clone(), *seq));
    }
    current.clear();
    for (id, values) in grouped {
        current.insert(id, fold_artifact_chain(values)?);
    }
    Ok(())
}

pub(crate) fn record_run(
    current: &mut BTreeMap<ExperimentRunId, (ExperimentRun, u64)>,
    revisions: Option<&mut BTreeMap<RevisionId, (ExperimentRun, u64)>>,
    value: ExperimentRun,
    seq: u64,
    error: StoreError,
) -> Result<(), StoreError> {
    if !allowed_run_shape(&value) {
        return Err(error);
    }
    if let Some((existing, _)) = current.get(&value.run_id) {
        if existing == &value {
            return Ok(());
        }
        existing.validate_successor(&value).map_err(|_| error)?;
    } else if value.parent_revision_id.is_some() {
        return Err(error);
    } else {
        value.validate().map_err(|_| error)?;
    }
    if let Some(revisions) = revisions {
        if revisions.contains_key(&value.revision_id) {
            return Err(error);
        }
        revisions.insert(value.revision_id, (value.clone(), seq));
    }
    current.insert(value.run_id, (value, seq));
    Ok(())
}

fn allowed_run_shape(value: &ExperimentRun) -> bool {
    value.is_declaration_only()
        || value.is_controlled_declaration()
        || (value.comparison_execution_binding.is_some()
            || evertrace_domain::work::is_native_test_contract_parser(
                &value.metric_extractor_version,
            ))
            && value.observability == RunObservability::Full
            && value.execution_status == RunExecutionStatus::Completed
            && value.contract_validity == RunContractValidity::Valid
}

pub(crate) fn record_result(
    current: &mut BTreeMap<ResultEvidenceId, (ResultEvidence, u64)>,
    revisions: Option<&mut BTreeMap<RevisionId, (ResultEvidence, u64)>>,
    value: ResultEvidence,
    seq: u64,
    error: StoreError,
) -> Result<(), StoreError> {
    if let Some((existing, _)) = current.get(&value.result_evidence_id) {
        if existing == &value {
            return Ok(());
        }
        existing.validate_successor(&value).map_err(|_| error)?;
    } else if value.parent_revision_id.is_some() {
        return Err(error);
    } else {
        value.validate().map_err(|_| error)?;
    }
    if let Some(revisions) = revisions {
        if revisions.contains_key(&value.revision_id) {
            return Err(error);
        }
        revisions.insert(value.revision_id, (value.clone(), seq));
    }
    current.insert(value.result_evidence_id, (value, seq));
    Ok(())
}

pub(crate) fn record_artifact(
    current: &mut BTreeMap<WorkArtifactId, (WorkArtifact, u64)>,
    revisions: Option<&mut BTreeMap<RevisionId, (WorkArtifact, u64)>>,
    value: WorkArtifact,
    seq: u64,
    error: StoreError,
) -> Result<(), StoreError> {
    if let Some((existing, _)) = current.get(&value.work_artifact_id) {
        if existing == &value {
            return Ok(());
        }
        existing.validate_successor(&value).map_err(|_| error)?;
    } else if value.revision.parent_revision_id.is_some() {
        return Err(error);
    } else {
        value.validate().map_err(|_| error)?;
    }
    if let Some(revisions) = revisions {
        if revisions.contains_key(&value.revision.revision_id) {
            return Err(error);
        }
        revisions.insert(value.revision.revision_id, (value.clone(), seq));
    }
    current.insert(value.work_artifact_id, (value, seq));
    Ok(())
}
