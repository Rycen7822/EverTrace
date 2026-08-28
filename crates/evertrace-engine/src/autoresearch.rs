use std::str::FromStr;

use evertrace_capture::{CasDigest, CasStore};
use evertrace_domain::{
    ids::{CasId, CommandId, ResultEvidenceId, SourceReceiptId, WorkArtifactId},
    revision::RevisionId,
    semantic::{
        EvidenceCompleteness, MetricValue, ParserFailureCode, ParserReceipt, ParserStatus,
        ResultEvidence, ResultFailure, ResultScope, VerifierFailureCode, VerifierReceipt,
        VerifierStatus,
    },
    work::{
        ArtifactActor, ArtifactPayloadStatus, ArtifactRevision, ArtifactScope, Attempt,
        AttemptBindingStatus, ContractField, ExperimentRun, MultiCasMetricPolicy,
        RunContractValidity, RunExecutionStatus, RunObservability, RunOrigin, SeedPolicy,
        VariableDeclaration, WorkArtifact,
    },
};
use evertrace_store::{JournalCommand, JournalEventDraft, JournalPayload};
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
    let expected = members[0].1.comparison_key;
    let expected_attempt = members[0].1.attempt_id;
    let expected_workstream = members[0].1.workstream_id;
    let expected_strategy = members[0].1.strategy_contract_fingerprint;
    let expected_unit = members[0]
        .0
        .parsed_metric
        .as_ref()
        .ok_or(AutoresearchError::EvidenceIncomplete)?
        .unit
        .clone();
    let mut ids = Vec::with_capacity(members.len());
    for (result, run) in members {
        let terminal_scope_is_compatible = match result.result_scope {
            ResultScope::Complete => run.execution_status == RunExecutionStatus::Completed,
            ResultScope::Partial => matches!(
                run.execution_status,
                RunExecutionStatus::Completed
                    | RunExecutionStatus::Failed
                    | RunExecutionStatus::Interrupted
            ),
        };
        if run.validate().is_err()
            || result.validate().is_err()
            || run.attempt_binding_status != AttemptBindingStatus::Resolved
            || run.attempt_id.is_none()
            || run.attempt_id != expected_attempt
            || run.workstream_id != expected_workstream
            || run.strategy_contract_fingerprint != expected_strategy
            || run.observability != RunObservability::Full
            || run.contract_validity != RunContractValidity::Valid
            || !terminal_scope_is_compatible
            || result.experiment_run_id != run.run_id
            || result.experiment_run_revision_id != run.revision_id
            || result.parser_receipt.parser_version != run.metric_extractor_version
            || run.comparison_key != expected
            || result.completeness != EvidenceCompleteness::Complete
            || result.verifier_receipt.as_ref().is_none_or(|receipt| {
                receipt.status != VerifierStatus::Passed
                    || receipt.verifier_version != RESULT_VERIFIER_VERSION
            })
            || result.parsed_metric.as_ref().map(|metric| &metric.unit) != Some(&expected_unit)
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
