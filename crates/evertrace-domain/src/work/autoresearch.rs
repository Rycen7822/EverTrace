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

    pub fn recompute_comparison_key(&self) -> Result<[u8; 32], WorkError> {
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
        sha256(
            "evertrace.experiment_contract.comparison",
            if self.comparison_execution_binding.is_some() {
                2
            } else {
                1
            },
            &CanonicalValue::Map(fields),
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
