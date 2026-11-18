use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalValue, sha256},
    ids::{
        AttemptId, CasId, ExperimentRunId, OperationId, RepositoryId, SourceObservationId,
        SourceReceiptId, TaskId, WorkArtifactId, WorkEpisodeId, WorkstreamId, WorktreeId,
        WorktreeSnapshotId,
    },
    revision::RevisionId,
    semantic::MetricValue,
};

use super::WorkError;

const MAX_REFS: usize = 256;
const MAX_FIELDS: usize = 128;
const MAX_TEXT: usize = 1024;
const CONTROLLED_SOURCE_VERSION: u32 = 1;

/// A result can resume its own confirmed launch Phase, never an unrelated active Phase.
pub fn awaiting_experiment_result(stream: &super::Workstream, launch: &super::WorkEpisode) -> bool {
    stream.status == super::WorkstreamStatus::Paused
        && stream.active_episode_id.is_none()
        && launch.workstream_id == stream.workstream_id
        && launch.task_id == stream.task_id
        && launch.lifecycle_status == super::EpisodeLifecycle::Closed
        && launch.boundary_status == super::BoundaryStatus::Confirmed
        && launch.phase_contract.phase_kind == super::PhaseKind::Execute
        && launch.phase_contract == stream.phase_contract
}

pub fn experiment_analysis_phase(
    run: &ExperimentRun,
    result: crate::ids::ResultEvidenceId,
) -> super::PhaseContract {
    super::PhaseContract {
        phase_kind: super::PhaseKind::Analyze,
        phase_label: "Analyze experiment result".into(),
        local_goal: "Interpret the accepted result against the recorded experiment contract".into(),
        primary_targets: vec![run.run_id.to_string()],
        entry_conditions: vec![result.to_string()],
        acceptance_boundary: "Explain the result and its limits using recorded evidence".into(),
        expected_state_transition: "Result analyzed; adoption and comparison remain independent"
            .into(),
    }
}

/// Business eligibility diagnostics, independent of any presentation surface.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultComparisonReason {
    InvalidRun,
    InvalidResult,
    AttemptUnresolved,
    AttemptMismatch,
    WorkstreamMismatch,
    StrategyMismatch,
    ObservabilityInsufficient,
    ContractNotValid,
    ExecutionScopeMismatch,
    RunMismatch,
    RunRevisionMismatch,
    ExtractorMismatch,
    ComparisonContractMismatch,
    EvidenceIncomplete,
    VerifierNotPassed,
    MetricMissing,
    UnitMismatch,
    DuplicateResult,
    RawEvidenceUnavailable,
    EvidenceBudgetExceeded,
    ReparseMismatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultComparisonIssue {
    pub member: u16,
    pub reason: ResultComparisonReason,
    pub dimensions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultCohortAssessment {
    pub compatible: bool,
    pub issues: Vec<ResultComparisonIssue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlledRunSourceEnvelope {
    Launch {
        version: u32,
        attempt_id: AttemptId,
        procedure_revision_id: RevisionId,
        code_snapshot_id: WorktreeSnapshotId,
        data_fingerprint: String,
        normalized_config: Vec<ContractField>,
        variable_declaration: VariableDeclaration,
        seed_policy: SeedPolicy,
        seed_values: Vec<String>,
        nondeterministic: bool,
        metric_definition: String,
        metric_extractor_version: String,
        multi_cas_metric_policy: MultiCasMetricPolicy,
        environment_fingerprint: String,
        binding: Box<ComparisonExecutionBinding>,
        started_at_us: i64,
    },
    Terminal {
        version: u32,
        run_id: ExperimentRunId,
        ended_at_us: i64,
        metric: MetricValue,
        artifact_refs: Vec<WorkArtifactId>,
    },
}

impl ControlledRunSourceEnvelope {
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, WorkError> {
        let text = std::str::from_utf8(bytes).map_err(|_| WorkError::InvalidAutoresearch)?;
        let value = toml::from_str::<Self>(text).map_err(|_| WorkError::InvalidAutoresearch)?;
        value.validate()?;
        if toml::to_string(&value)
            .map_err(|_| WorkError::InvalidAutoresearch)?
            .as_bytes()
            != bytes
        {
            return Err(WorkError::InvalidAutoresearch);
        }
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), WorkError> {
        match self {
            Self::Launch {
                version,
                data_fingerprint,
                normalized_config,
                variable_declaration,
                seed_values,
                metric_definition,
                metric_extractor_version,
                environment_fingerprint,
                binding,
                started_at_us,
                ..
            } => {
                if *version != CONTROLLED_SOURCE_VERSION
                    || *started_at_us < 0
                    || !valid_text(data_fingerprint)
                    || !valid_text(metric_definition)
                    || !valid_text(metric_extractor_version)
                    || !valid_text(environment_fingerprint)
                    || normalized_config.len() > MAX_FIELDS
                    || !normalized_config.iter().all(ContractField::valid)
                    || !normalized_config
                        .windows(2)
                        .all(|pair| pair[0].name < pair[1].name)
                    || !canonical_texts(seed_values)
                {
                    return Err(WorkError::InvalidAutoresearch);
                }
                variable_declaration.validate_against(normalized_config)?;
                binding.validate()
            }
            Self::Terminal {
                version,
                ended_at_us,
                metric,
                artifact_refs,
                ..
            } => {
                if *version != CONTROLLED_SOURCE_VERSION
                    || *ended_at_us < 0
                    || !canonical_unique(artifact_refs, MAX_REFS)
                {
                    return Err(WorkError::InvalidAutoresearch);
                }
                metric
                    .validate()
                    .map_err(|_| WorkError::InvalidAutoresearch)
            }
        }
    }
}

/// The original source event and embedded xUnit2 bytes, not a generated metric envelope.
pub const NATIVE_TEST_RESULT_PARSER_VERSION: &str = "evertrace.native_test_result.v1";
pub const NATIVE_TEST_CONTRACT_PARSER_VERSION: &str = "evertrace.native_test_result.v2";
pub const NATIVE_TEST_COHORT_PARSER_VERSION: &str = "evertrace.native_test_result.v3";

pub fn is_native_test_contract_parser(version: &str) -> bool {
    matches!(
        version,
        NATIVE_TEST_CONTRACT_PARSER_VERSION | NATIVE_TEST_COHORT_PARSER_VERSION
    )
}

pub fn is_native_test_parser(version: &str) -> bool {
    version == NATIVE_TEST_RESULT_PARSER_VERSION || is_native_test_contract_parser(version)
}

/// Transient compilation of the fixed original launch, never a second persisted contract.
#[derive(Debug)]
pub struct NativeTestContract {
    pub started_at_us: i64,
    pub data_fingerprint: String,
    pub normalized_config: Vec<ContractField>,
    pub variable_declaration: VariableDeclaration,
}

impl NativeTestContract {
    /// Keep the direct execution witness distinct from the already recorded comparison basis.
    pub fn code_basis<'a>(
        witness: &'a crate::repository::WorktreeSnapshot,
        episode_entry: Option<&'a crate::repository::WorktreeSnapshot>,
    ) -> &'a crate::repository::WorktreeSnapshot {
        episode_entry
            .filter(|entry| witness.same_code_state(entry))
            .unwrap_or(witness)
    }

    pub fn decode(
        raw: &[u8],
        snapshot: &crate::repository::WorktreeSnapshot,
        source: SourceObservationId,
        harness_revision: &str,
    ) -> Option<Self> {
        if !Self::has_direct_witness(snapshot, source) {
            return None;
        }
        Self::decode_code_state(raw, snapshot, harness_revision)
    }

    /// A matching code state can be seen before its direct execution witness is committed.
    pub fn awaits_direct_witness(
        raw: &[u8],
        snapshot: &crate::repository::WorktreeSnapshot,
        source: SourceObservationId,
        harness_revision: &str,
    ) -> bool {
        !Self::has_direct_witness(snapshot, source)
            && Self::decode_code_state(raw, snapshot, harness_revision).is_some()
    }

    fn has_direct_witness(
        snapshot: &crate::repository::WorktreeSnapshot,
        source: SourceObservationId,
    ) -> bool {
        let prefix = format!("native-execution-directory:{source}:");
        snapshot
            .evidence_refs
            .iter()
            .any(|reference| reference.starts_with(&prefix))
    }

    fn decode_code_state(
        raw: &[u8],
        snapshot: &crate::repository::WorktreeSnapshot,
        harness_revision: &str,
    ) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_slice(raw).ok()?;
        let config = &value["config"];
        let implementation = config["implementation"].as_str()?;
        // These are the audited original external code trees, not inferred model/seed claims.
        let tree = match implementation {
            "baseline" => "976e7817799add9e524e38c3c95b19ac8bdf0062",
            "biased" => "35ebe319ad4ead97d4d3b5a4115d503fb16d5116",
            "equivalent" => "4f696277f28ed6c5721f38dc9ae2b65184201dc6",
            _ => return None,
        };
        let clean = crate::evidence::hex(
            &sha256(
                crate::repository::TRACKED_DIFF_DIGEST_TAG,
                1,
                &CanonicalValue::Bytes(Vec::new()),
            )
            .ok()?,
        );
        let started_at_us = value["time_us"].as_i64()?;
        let anchor = &value["source_anchor"];
        if value["format"] != "process-trial-source-v4"
            || value["event"] != "trial_launch"
            || started_at_us < 0
            || config["selected"] != "fixed_scorer.py::TestTaskEval"
            || config["timeout_seconds"] != 30
            || config["framework"] != "pytest"
            || config["framework_version"] != "9.0.2"
            || config["uses_model"] != false
            || config["uses_randomness"] != false
            || anchor["scorer_blob"] != "3472c5a70052b6b7c4c8969679fb0556a60793a9"
            || anchor["tree"] != tree
            || snapshot.tree_oid.as_deref() != Some(tree)
            || snapshot.head_oid.as_deref() != anchor["commit"].as_str()
            || snapshot.capture_status != crate::repository::SnapshotCaptureStatus::Complete
            || snapshot.tracked_diff_digest.as_deref() != Some(clean.as_str())
        {
            return None;
        }
        let fields = [
            ("budget_unit", "wall_seconds_after_gate"),
            ("harness_revision", harness_revision),
            ("implementation", implementation),
            ("model_use", "not_used"),
            ("randomness", "not_used"),
            ("selected", "fixed_scorer.py::TestTaskEval"),
            ("timeout_seconds", "30"),
        ];
        let normalized_config = fields
            .into_iter()
            .map(|(name, value)| ContractField {
                name: name.into(),
                value: value.into(),
            })
            .collect::<Vec<_>>();
        Some(Self {
            started_at_us,
            data_fingerprint: "git-blob:3472c5a70052b6b7c4c8969679fb0556a60793a9".into(),
            variable_declaration: VariableDeclaration {
                varied: vec!["implementation".into()],
                fixed: normalized_config
                    .iter()
                    .filter(|field| field.name != "implementation")
                    .map(|field| field.name.clone())
                    .collect(),
                uncontrolled: Vec::new(),
            },
            normalized_config,
        })
    }

    pub fn matches_run(&self, run: &ExperimentRun) -> bool {
        run.data_fingerprint == self.data_fingerprint
            && run.normalized_config == self.normalized_config
            && run.variable_declaration == self.variable_declaration
            && run.seed_policy == SeedPolicy::Unspecified
            && run.seed_values.is_empty()
            && !run.nondeterministic
            && run.metric_definition == "TestTaskEval passed tests"
            && is_native_test_contract_parser(&run.metric_extractor_version)
            && run.multi_cas_metric_policy == MultiCasMetricPolicy::RejectMultipleParsed
            && run.created_at_us <= self.started_at_us
    }
}

#[derive(Debug, Deserialize)]
pub struct NativeTestResult {
    format: String,
    event: String,
    pub event_key: String,
    pub source_epoch: String,
    pub execution_key: String,
    pub launch_event: String,
    pub request_key: String,
    pub execution_ordinal: u32,
    returncode: i32,
    scorer: Option<NativeTestReport>,
}

#[derive(Debug, Deserialize)]
struct NativeTestReport {
    format: String,
    original_xml: String,
}

impl NativeTestResult {
    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() > 65536 {
            return None;
        }
        let value: Self = serde_json::from_slice(raw).ok()?;
        let keys = [
            &value.event_key,
            &value.source_epoch,
            &value.execution_key,
            &value.launch_event,
            &value.request_key,
        ];
        (value.format == "process-trial-source-v4"
            && value.event == "trial_finished"
            && value.execution_ordinal > 0
            && keys
                .iter()
                .all(|key| uuid::Uuid::parse_str(key).is_ok_and(|id| id.to_string() == **key)))
        .then_some(value)
    }

    /// Count original passed cases only after validating the complete fixed scorer structure.
    /// Parsing never proves the Run's code/data/seed/environment contract.
    pub fn metric(&self) -> Option<MetricValue> {
        let report = self.scorer.as_ref()?;
        if report.format != "pytest-junit-xunit2" || !matches!(self.returncode, 0 | 1) {
            return None;
        }
        let document = roxmltree::Document::parse_with_options(
            &report.original_xml,
            roxmltree::ParsingOptions {
                allow_dtd: false,
                nodes_limit: 2048,
                ..Default::default()
            },
        )
        .ok()?;
        let root = document.root_element();
        let suites = root
            .children()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        if root.tag_name().name() != "testsuites"
            || root.tag_name().namespace().is_some()
            || suites.len() != 1
            || suites[0].tag_name().name() != "testsuite"
            || suites[0].tag_name().namespace().is_some()
        {
            return None;
        }
        let suite = suites[0];
        let count = |name| suite.attribute(name)?.parse::<usize>().ok();
        if count("tests") != Some(2) || count("errors") != Some(0) || count("skipped") != Some(0) {
            return None;
        }
        let mut names = BTreeSet::new();
        let mut failures = 0;
        for case in suite.children().filter(|node| node.is_element()) {
            if case.tag_name().name() != "testcase"
                || case.tag_name().namespace().is_some()
                || case.attribute("classname") != Some("fixed_scorer.TestTaskEval")
                || !names.insert(case.attribute("name")?)
            {
                return None;
            }
            let mut failed = false;
            for child in case.children().filter(|node| node.is_element()) {
                if child.tag_name().name() != "failure"
                    || child.tag_name().namespace().is_some()
                    || failed
                    || child.children().any(|node| node.is_element())
                {
                    return None;
                }
                failed = true;
            }
            failures += usize::from(failed);
        }
        if names != BTreeSet::from(["test_pass_rate", "test_anchor_mean_missing_scores_zero"])
            || count("failures") != Some(failures)
            || self.returncode != i32::from(failures > 0)
        {
            return None;
        }
        Some(MetricValue {
            decimal: (2 - failures).to_string(),
            unit: "tests".into(),
            uncertainty_decimal: None,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOrigin {
    Local,
    External,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptBindingStatus {
    Resolved,
    Provisional,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunObservability {
    Declared,
    Partial,
    Full,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunExecutionStatus {
    Unknown,
    Queued,
    Running,
    Completed,
    Failed,
    Interrupted,
}

impl RunExecutionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunContractValidity {
    Unknown,
    Valid,
    Invalid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedPolicy {
    Fixed,
    Enumerated,
    Randomized,
    Unspecified,
}

impl SeedPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Enumerated => "enumerated",
            Self::Randomized => "randomized",
            Self::Unspecified => "unspecified",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiCasMetricPolicy {
    RejectMultipleParsed,
    AllowIdenticalParsed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricDirection {
    HigherIsBetter,
    LowerIsBetter,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonExecutionBinding {
    pub binding_version: u32,
    pub toolchain_revision: String,
    pub model_revision: String,
    pub harness_revision: String,
    pub algorithm_revision: String,
    pub budget: u64,
    pub procedure_exposure_revision_id: Option<RevisionId>,
    pub metric_direction: MetricDirection,
    pub metric_unit: String,
    pub positive_delta_threshold: String,
    pub negative_delta_threshold: String,
}

impl ComparisonExecutionBinding {
    pub fn validate(&self) -> Result<(), WorkError> {
        if self.binding_version != 1
            || self.budget == 0
            || [
                &self.toolchain_revision,
                &self.model_revision,
                &self.harness_revision,
                &self.algorithm_revision,
                &self.metric_unit,
            ]
            .into_iter()
            .any(|value| !valid_text(value) || value == "unknown")
            || !positive_decimal(&self.positive_delta_threshold)
            || !positive_decimal(&self.negative_delta_threshold)
        {
            return Err(WorkError::InvalidAutoresearch);
        }
        Ok(())
    }

    fn canonical(&self, include_exposure: bool) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                "algorithm_revision".into(),
                CanonicalValue::String(self.algorithm_revision.clone()),
            ),
            (
                "binding_version".into(),
                CanonicalValue::Integer(i128::from(self.binding_version)),
            ),
            (
                "budget".into(),
                CanonicalValue::Integer(i128::from(self.budget)),
            ),
            (
                "harness_revision".into(),
                CanonicalValue::String(self.harness_revision.clone()),
            ),
            (
                "metric_direction".into(),
                CanonicalValue::String(
                    match self.metric_direction {
                        MetricDirection::HigherIsBetter => "higher_is_better",
                        MetricDirection::LowerIsBetter => "lower_is_better",
                    }
                    .into(),
                ),
            ),
            (
                "metric_unit".into(),
                CanonicalValue::String(self.metric_unit.clone()),
            ),
            (
                "model_revision".into(),
                CanonicalValue::String(self.model_revision.clone()),
            ),
            (
                "negative_delta_threshold".into(),
                CanonicalValue::String(self.negative_delta_threshold.clone()),
            ),
            (
                "positive_delta_threshold".into(),
                CanonicalValue::String(self.positive_delta_threshold.clone()),
            ),
            (
                "procedure_exposure_revision_id".into(),
                if include_exposure {
                    self.procedure_exposure_revision_id
                        .map_or(CanonicalValue::Null, |id| {
                            CanonicalValue::String(id.to_string())
                        })
                } else {
                    CanonicalValue::Null
                },
            ),
            (
                "toolchain_revision".into(),
                CanonicalValue::String(self.toolchain_revision.clone()),
            ),
        ])
    }
}

impl MultiCasMetricPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RejectMultipleParsed => "reject_multiple_parsed",
            Self::AllowIdenticalParsed => "allow_identical_parsed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractField {
    pub name: String,
    pub value: String,
}

impl ContractField {
    fn valid(&self) -> bool {
        valid_text(&self.name) && valid_text(&self.value)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VariableDeclaration {
    pub varied: Vec<String>,
    pub fixed: Vec<String>,
    pub uncontrolled: Vec<String>,
}

impl VariableDeclaration {
    pub fn validate_against(&self, config: &[ContractField]) -> Result<(), WorkError> {
        if !canonical_texts(&self.varied)
            || !canonical_texts(&self.fixed)
            || !canonical_texts(&self.uncontrolled)
        {
            return Err(WorkError::InvalidAutoresearch);
        }
        let mut all = BTreeSet::new();
        for name in self
            .varied
            .iter()
            .chain(&self.fixed)
            .chain(&self.uncontrolled)
        {
            if !all.insert(name) || !config.iter().any(|field| &field.name == name) {
                return Err(WorkError::InvalidAutoresearch);
            }
        }
        if all.len() != config.len() {
            return Err(WorkError::InvalidAutoresearch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentRun {
    pub run_id: ExperimentRunId,
    pub revision_id: RevisionId,
    pub parent_revision_id: Option<RevisionId>,
    pub workstream_id: WorkstreamId,
    pub attempt_id: Option<AttemptId>,
    pub attempt_binding_status: AttemptBindingStatus,
    pub strategy_contract_fingerprint: [u8; 32],
    pub origin: RunOrigin,
    pub external_system_id: Option<String>,
    pub external_run_key: Option<String>,
    pub source_receipt_refs: Vec<SourceReceiptId>,
    pub observability: RunObservability,
    pub execution_status: RunExecutionStatus,
    pub contract_validity: RunContractValidity,
    pub experiment_contract_fingerprint: [u8; 32],
    pub code_snapshot_id: WorktreeSnapshotId,
    pub data_fingerprint: String,
    pub normalized_config: Vec<ContractField>,
    pub variable_declaration: VariableDeclaration,
    pub comparison_key: [u8; 32],
    pub seed_policy: SeedPolicy,
    pub seed_values: Vec<String>,
    pub nondeterministic: bool,
    pub metric_definition: String,
    pub metric_extractor_version: String,
    pub multi_cas_metric_policy: MultiCasMetricPolicy,
    pub environment_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison_execution_binding: Option<ComparisonExecutionBinding>,
    pub work_artifact_refs: Vec<WorkArtifactId>,
    pub terminal_evidence_refs: Vec<SourceReceiptId>,
    pub created_at_us: i64,
    pub started_at_us: Option<i64>,
    pub ended_at_us: Option<i64>,
}

impl ExperimentRun {
    pub fn recompute_exact_contract_fingerprint(&self) -> Result<[u8; 32], WorkError> {
        if let Some(binding) = &self.comparison_execution_binding {
            binding.validate()?;
        }
        let mut fields = vec![
            (
                "strategy".into(),
                CanonicalValue::Bytes(self.strategy_contract_fingerprint.to_vec()),
            ),
            (
                "code_snapshot".into(),
                CanonicalValue::String(self.code_snapshot_id.to_string()),
            ),
            (
                "data".into(),
                CanonicalValue::String(self.data_fingerprint.clone()),
            ),
            ("config".into(), config_value(&self.normalized_config)),
            (
                "variables".into(),
                variables_value(&self.variable_declaration),
            ),
            (
                "seed_policy".into(),
                CanonicalValue::String(self.seed_policy.as_str().into()),
            ),
            ("seed_values".into(), strings_value(&self.seed_values)),
            (
                "nondeterministic".into(),
                CanonicalValue::Bool(self.nondeterministic),
            ),
            (
                "metric".into(),
                CanonicalValue::String(self.metric_definition.clone()),
            ),
            (
                "extractor".into(),
                CanonicalValue::String(self.metric_extractor_version.clone()),
            ),
            (
                "multi_cas".into(),
                CanonicalValue::String(self.multi_cas_metric_policy.as_str().into()),
            ),
            (
                "environment".into(),
                CanonicalValue::String(self.environment_fingerprint.clone()),
            ),
        ];
        if let Some(binding) = &self.comparison_execution_binding {
            fields.push((
                "comparison_execution_binding".into(),
                binding.canonical(true),
            ));
        }
        sha256(
            "evertrace.experiment_contract.exact",
            if self.comparison_execution_binding.is_some() {
                2
            } else {
                1
            },
            &CanonicalValue::Map(fields),
        )
        .map_err(|_| WorkError::InvalidAutoresearch)
    }

    fn comparison_fields(&self) -> Vec<(String, CanonicalValue)> {
        let fixed = self
            .normalized_config
            .iter()
            .filter(|field| self.variable_declaration.fixed.contains(&field.name))
            .cloned()
            .collect::<Vec<_>>();
        let mut fields = vec![
            (
                "code_snapshot".into(),
                CanonicalValue::String(self.code_snapshot_id.to_string()),
            ),
            (
                "data".into(),
                CanonicalValue::String(self.data_fingerprint.clone()),
            ),
            ("fixed_config".into(), config_value(&fixed)),
            (
                "variables".into(),
                variables_value(&self.variable_declaration),
            ),
            (
                "seed_policy".into(),
                CanonicalValue::String(self.seed_policy.as_str().into()),
            ),
            (
                "metric".into(),
                CanonicalValue::String(self.metric_definition.clone()),
            ),
            (
                "extractor".into(),
                CanonicalValue::String(self.metric_extractor_version.clone()),
            ),
            (
                "multi_cas".into(),
                CanonicalValue::String(self.multi_cas_metric_policy.as_str().into()),
            ),
            (
                "environment".into(),
                CanonicalValue::String(self.environment_fingerprint.clone()),
            ),
        ];
        if let Some(binding) = &self.comparison_execution_binding {
            fields.push((
                "comparison_execution_binding".into(),
                binding.canonical(false),
            ));
        }
        fields
    }

    pub fn comparison_mismatches(&self, other: &Self) -> Vec<String> {
        let left = self
            .comparison_fields()
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
        let right = other
            .comparison_fields()
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
        left.keys()
            .chain(right.keys())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|key| left.get(*key) != right.get(*key))
            .cloned()
            .collect()
    }

    pub fn recompute_comparison_key(&self) -> Result<[u8; 32], WorkError> {
        sha256(
            "evertrace.experiment_contract.comparison",
            if self.comparison_execution_binding.is_some() {
                2
            } else {
                1
            },
            &CanonicalValue::Map(self.comparison_fields()),
        )
        .map_err(|_| WorkError::InvalidAutoresearch)
    }

    pub fn is_declaration_only(&self) -> bool {
        self.observability == RunObservability::Declared
            && self.execution_status == RunExecutionStatus::Unknown
            && self.contract_validity == RunContractValidity::Unknown
            && self.terminal_evidence_refs.is_empty()
            && self.started_at_us.is_none()
            && self.ended_at_us.is_none()
    }

    pub fn is_controlled_declaration(&self) -> bool {
        self.comparison_execution_binding.is_some()
            && self.observability == RunObservability::Declared
            && self.execution_status == RunExecutionStatus::Unknown
            && self.contract_validity == RunContractValidity::Unknown
            && self.terminal_evidence_refs.is_empty()
            && self.started_at_us.is_some()
            && self.ended_at_us.is_none()
    }

    pub fn validate(&self) -> Result<(), WorkError> {
        if let Some(binding) = &self.comparison_execution_binding {
            binding.validate()?;
        }
        if self.experiment_contract_fingerprint != self.recompute_exact_contract_fingerprint()?
            || self.comparison_key != self.recompute_comparison_key()?
        {
            return Err(WorkError::InvalidAutoresearch);
        }
        if self.created_at_us < 0
            || self
                .started_at_us
                .is_some_and(|value| value < self.created_at_us)
            || self
                .ended_at_us
                .is_some_and(|value| value < self.started_at_us.unwrap_or(self.created_at_us))
            || self.source_receipt_refs.is_empty()
            || !canonical_unique(&self.source_receipt_refs, MAX_REFS)
            || !canonical_unique(&self.work_artifact_refs, MAX_REFS)
            || !canonical_unique(&self.terminal_evidence_refs, MAX_REFS)
            || self.normalized_config.len() > MAX_FIELDS
            || !self.normalized_config.iter().all(ContractField::valid)
            || !self
                .normalized_config
                .windows(2)
                .all(|pair| pair[0].name < pair[1].name)
            || !canonical_texts(&self.seed_values)
            || !optional_text(&self.external_system_id)
            || !optional_text(&self.external_run_key)
            || !valid_text(&self.data_fingerprint)
            || !valid_text(&self.metric_definition)
            || !valid_text(&self.metric_extractor_version)
            || !valid_text(&self.environment_fingerprint)
        {
            return Err(WorkError::InvalidAutoresearch);
        }
        self.variable_declaration
            .validate_against(&self.normalized_config)?;
        if self.origin == RunOrigin::External
            && (self.external_system_id.is_none() || self.external_run_key.is_none())
            || self.origin == RunOrigin::Local
                && (self.external_system_id.is_some() || self.external_run_key.is_some())
            || (self.attempt_binding_status == AttemptBindingStatus::Resolved
                && self.attempt_id.is_none())
            || (self.attempt_id.is_none()
                && self.attempt_binding_status != AttemptBindingStatus::Unresolved)
            || self.nondeterministic && !self.seed_values.is_empty()
            || self.seed_policy == SeedPolicy::Fixed && self.seed_values.len() != 1
            || self.seed_policy == SeedPolicy::Enumerated && self.seed_values.is_empty()
            || matches!(
                self.seed_policy,
                SeedPolicy::Randomized | SeedPolicy::Unspecified
            ) && !self.seed_values.is_empty()
            || matches!(
                self.execution_status,
                RunExecutionStatus::Completed
                    | RunExecutionStatus::Failed
                    | RunExecutionStatus::Interrupted
            ) != self.ended_at_us.is_some()
            || (!self.terminal_evidence_refs.is_empty() && self.ended_at_us.is_none())
        {
            return Err(WorkError::InvalidAutoresearch);
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), WorkError> {
        next.validate()?;
        let immutable_equal = self.run_id == next.run_id
            && next.parent_revision_id == Some(self.revision_id)
            && self.workstream_id == next.workstream_id
            && self.strategy_contract_fingerprint == next.strategy_contract_fingerprint
            && self.origin == next.origin
            && self.external_system_id == next.external_system_id
            && self.external_run_key == next.external_run_key
            && self.experiment_contract_fingerprint == next.experiment_contract_fingerprint
            && self.code_snapshot_id == next.code_snapshot_id
            && self.data_fingerprint == next.data_fingerprint
            && self.normalized_config == next.normalized_config
            && self.variable_declaration == next.variable_declaration
            && self.comparison_key == next.comparison_key
            && self.seed_policy == next.seed_policy
            && self.seed_values == next.seed_values
            && self.nondeterministic == next.nondeterministic
            && self.metric_definition == next.metric_definition
            && self.metric_extractor_version == next.metric_extractor_version
            && self.multi_cas_metric_policy == next.multi_cas_metric_policy
            && self.environment_fingerprint == next.environment_fingerprint
            && self.comparison_execution_binding == next.comparison_execution_binding
            && next.created_at_us >= self.created_at_us;
        let evidence_progress =
            strict_superset(&self.source_receipt_refs, &next.source_receipt_refs)
                || strict_superset(&self.work_artifact_refs, &next.work_artifact_refs)
                || strict_superset(&self.terminal_evidence_refs, &next.terminal_evidence_refs)
                || self.attempt_binding_status != next.attempt_binding_status
                || self.observability != next.observability
                || self.execution_status != next.execution_status
                || self.contract_validity != next.contract_validity
                || self.ended_at_us != next.ended_at_us;
        if !immutable_equal
            || !contains_all(&next.source_receipt_refs, &self.source_receipt_refs)
            || !contains_all(&next.work_artifact_refs, &self.work_artifact_refs)
            || !contains_all(&next.terminal_evidence_refs, &self.terminal_evidence_refs)
            || next.observability < self.observability
            || !binding_progress(self, next)
            || !status_progress(self.execution_status, next.execution_status)
            || !validity_progress(self.contract_validity, next.contract_validity)
            || !evidence_progress
        {
            return Err(WorkError::InvalidAutoresearchSuccessor);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkArtifactKind {
    File,
    Log,
    Checkpoint,
    DatasetManifest,
    ExperimentOutput,
    Manuscript,
    Review,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPayloadStatus {
    Available,
    MetadataOnly,
    Unavailable,
    SourcePurged,
    Degraded,
}

impl ArtifactPayloadStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::MetadataOnly => "metadata_only",
            Self::Unavailable => "unavailable",
            Self::SourcePurged => "source_purged",
            Self::Degraded => "degraded",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactDerivability {
    Original,
    Reproducible,
    PartiallyReproducible,
    Irreplaceable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRetention {
    Ephemeral,
    Task,
    Repository,
    Retained,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactScope {
    Task {
        task_id: TaskId,
    },
    Worktree {
        repository_instance_id: RepositoryId,
        worktree_instance_id: WorktreeId,
    },
    Repository {
        repository_instance_id: RepositoryId,
    },
    Global,
}

impl ArtifactScope {
    pub const fn task_id(self) -> Option<TaskId> {
        match self {
            Self::Task { task_id } => Some(task_id),
            _ => None,
        }
    }

    pub const fn repository_id(self) -> Option<RepositoryId> {
        match self {
            Self::Worktree {
                repository_instance_id,
                ..
            }
            | Self::Repository {
                repository_instance_id,
            } => Some(repository_instance_id),
            Self::Task { .. } | Self::Global => None,
        }
    }

    pub const fn worktree_id(self) -> Option<WorktreeId> {
        match self {
            Self::Worktree {
                worktree_instance_id,
                ..
            } => Some(worktree_instance_id),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ArtifactActor {
    Operation(OperationId),
    ExperimentRun(ExperimentRunId),
    WorkEpisode(WorkEpisodeId),
}

pub type ArtifactProducer = ArtifactActor;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRevision {
    pub revision_id: RevisionId,
    pub parent_revision_id: Option<RevisionId>,
    pub kind: WorkArtifactKind,
    pub logical_name: String,
    pub scope: ArtifactScope,
    pub media_type: String,
    pub content_blob_ref: Option<CasId>,
    pub external_reference: Option<String>,
    pub content_fingerprint: Option<CasId>,
    pub payload_status: ArtifactPayloadStatus,
    pub produced_by_refs: Vec<ArtifactActor>,
    pub consumed_by_refs: Vec<ArtifactActor>,
    pub source_observation_refs: Vec<SourceObservationId>,
    pub derivability: ArtifactDerivability,
    pub retention: ArtifactRetention,
    pub created_at_us: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkArtifact {
    pub work_artifact_id: WorkArtifactId,
    pub revision: ArtifactRevision,
}

impl WorkArtifact {
    pub fn validate(&self) -> Result<(), WorkError> {
        let value = &self.revision;
        let content_shape = match value.payload_status {
            ArtifactPayloadStatus::Available => {
                value.content_blob_ref.is_some()
                    && value.content_fingerprint == value.content_blob_ref
            }
            ArtifactPayloadStatus::Degraded => value.content_fingerprint == value.content_blob_ref,
            ArtifactPayloadStatus::MetadataOnly
            | ArtifactPayloadStatus::Unavailable
            | ArtifactPayloadStatus::SourcePurged => {
                value.content_blob_ref.is_none() && value.content_fingerprint.is_none()
            }
        };
        if value.created_at_us < 0
            || !valid_text(&value.logical_name)
            || !valid_text(&value.media_type)
            || !optional_text(&value.external_reference)
            || !canonical_unique(&value.produced_by_refs, MAX_REFS)
            || !canonical_unique(&value.consumed_by_refs, MAX_REFS)
            || !canonical_unique(&value.source_observation_refs, MAX_REFS)
            || value.produced_by_refs.is_empty() && value.source_observation_refs.is_empty()
            || value.payload_status == ArtifactPayloadStatus::SourcePurged
                && (value.parent_revision_id.is_none() || value.source_observation_refs.is_empty())
            || !content_shape
        {
            return Err(WorkError::InvalidAutoresearch);
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), WorkError> {
        next.validate()?;
        let current = &self.revision;
        let successor = &next.revision;
        let progress = current.content_blob_ref != successor.content_blob_ref
            || current.external_reference != successor.external_reference
            || current.content_fingerprint != successor.content_fingerprint
            || current.payload_status != successor.payload_status
            || current.consumed_by_refs != successor.consumed_by_refs
            || current.source_observation_refs != successor.source_observation_refs;
        if self.work_artifact_id != next.work_artifact_id
            || successor.parent_revision_id != Some(current.revision_id)
            || current.kind != successor.kind
            || current.logical_name != successor.logical_name
            || current.scope != successor.scope
            || current.media_type != successor.media_type
            || current.produced_by_refs != successor.produced_by_refs
            || current.derivability != successor.derivability
            || current.retention != successor.retention
            || successor.created_at_us < current.created_at_us
            || !contains_all(&successor.consumed_by_refs, &current.consumed_by_refs)
            || !contains_all(
                &successor.source_observation_refs,
                &current.source_observation_refs,
            )
            || matches!(current.payload_status, ArtifactPayloadStatus::SourcePurged)
                && successor.payload_status != ArtifactPayloadStatus::SourcePurged
            || !progress
        {
            return Err(WorkError::InvalidAutoresearchSuccessor);
        }
        Ok(())
    }
}

fn binding_progress(current: &ExperimentRun, next: &ExperimentRun) -> bool {
    match current.attempt_binding_status {
        AttemptBindingStatus::Resolved => {
            next.attempt_binding_status == AttemptBindingStatus::Resolved
                && current.attempt_id == next.attempt_id
        }
        AttemptBindingStatus::Provisional => {
            next.attempt_binding_status != AttemptBindingStatus::Unresolved
                && current.attempt_id == next.attempt_id
        }
        AttemptBindingStatus::Unresolved => {
            next.attempt_binding_status != AttemptBindingStatus::Provisional
                && (current.attempt_id.is_none() || current.attempt_id == next.attempt_id)
        }
    }
}

const fn status_progress(current: RunExecutionStatus, next: RunExecutionStatus) -> bool {
    use RunExecutionStatus::{Completed, Failed, Interrupted, Queued, Running, Unknown};
    match current {
        Unknown => true,
        Queued => matches!(next, Queued | Running | Completed | Failed | Interrupted),
        Running => matches!(next, Running | Completed | Failed | Interrupted),
        Completed => matches!(next, Completed),
        Failed => matches!(next, Failed),
        Interrupted => matches!(next, Interrupted),
    }
}

fn validity_progress(current: RunContractValidity, next: RunContractValidity) -> bool {
    current == RunContractValidity::Unknown || current == next
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
}

fn positive_decimal(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 || value.starts_with('-') || value.starts_with('+') {
        return false;
    }
    let mut dot = false;
    let mut nonzero = false;
    for byte in value.bytes() {
        match byte {
            b'.' if !dot => dot = true,
            b'0' => {}
            b'1'..=b'9' => nonzero = true,
            _ => return false,
        }
    }
    nonzero
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !(value.len() > 1 && value.starts_with('0') && !value.starts_with("0."))
        && !(dot && value.ends_with('0'))
}

fn optional_text(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(valid_text)
}

fn canonical_texts(values: &[String]) -> bool {
    values.len() <= MAX_FIELDS
        && values.iter().all(|value| valid_text(value))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn canonical_unique<T: Ord>(values: &[T], limit: usize) -> bool {
    values.len() <= limit && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn contains_all<T: Eq>(values: &[T], required: &[T]) -> bool {
    required.iter().all(|value| values.contains(value))
}

fn strict_superset<T: Eq>(current: &[T], next: &[T]) -> bool {
    next.len() > current.len() && contains_all(next, current)
}

fn config_value(fields: &[ContractField]) -> CanonicalValue {
    CanonicalValue::Sequence(
        fields
            .iter()
            .map(|field| {
                CanonicalValue::Map(vec![
                    ("name".into(), CanonicalValue::String(field.name.clone())),
                    ("value".into(), CanonicalValue::String(field.value.clone())),
                ])
            })
            .collect(),
    )
}

fn variables_value(value: &VariableDeclaration) -> CanonicalValue {
    CanonicalValue::Map(vec![
        ("varied".into(), strings_value(&value.varied)),
        ("fixed".into(), strings_value(&value.fixed)),
        ("uncontrolled".into(), strings_value(&value.uncontrolled)),
    ])
}

fn strings_value(values: &[String]) -> CanonicalValue {
    CanonicalValue::Sequence(values.iter().cloned().map(CanonicalValue::String).collect())
}
