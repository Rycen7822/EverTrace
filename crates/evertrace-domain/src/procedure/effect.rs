use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalValue, sha256},
    ids::{ProcedureUsageId, RepositoryId, TaskId, WorktreeId, WorktreeSnapshotId},
    revision::RevisionId,
    semantic::{ConstraintBinding, ConstraintField, ConstraintState, SemanticError},
    work::{ComparisonExecutionBinding, MetricDirection},
};

use super::ProcedureUsagePhase;

const MAX_REFS: usize = 64;
const MAX_TEXT: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProcedureContextAnchor {
    Repository {
        repository_id: RepositoryId,
        worktree_id: WorktreeId,
        worktree_snapshot_id: WorktreeSnapshotId,
        worktree_lineage: String,
    },
    NonRepository {
        fixture_refs: Vec<String>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureEffectContext {
    pub procedure_revision_id: RevisionId,
    pub task_id: TaskId,
    pub anchor: ProcedureContextAnchor,
    pub operands: Vec<ConstraintBinding>,
    pub phase_kind: ProcedureUsagePhase,
    pub failure_signature: Option<String>,
    pub toolchain: String,
    pub model_revision: String,
    pub harness_revision: String,
    pub algorithm_revision: String,
    pub budget: u64,
    pub acceptance_boundary: String,
}

impl ProcedureEffectContext {
    pub const FINGERPRINT_VERSION: u32 = 1;

    #[allow(clippy::too_many_arguments)]
    pub fn compile(
        procedure_revision_id: RevisionId,
        task_id: TaskId,
        anchor: ProcedureContextAnchor,
        applicability_fields: &std::collections::BTreeSet<ConstraintField>,
        state: &ConstraintState,
        phase_kind: ProcedureUsagePhase,
        failure_signature: Option<String>,
        toolchain: String,
        model_revision: String,
        harness_revision: String,
        algorithm_revision: String,
        budget: u64,
        acceptance_boundary: String,
    ) -> Result<Self, SemanticError> {
        state.validate()?;
        let operands = state
            .bindings
            .iter()
            .filter(|binding| applicability_fields.contains(&binding.field))
            .cloned()
            .collect::<Vec<_>>();
        let value = Self {
            procedure_revision_id,
            task_id,
            anchor,
            operands,
            phase_kind,
            failure_signature,
            toolchain,
            model_revision,
            harness_revision,
            algorithm_revision,
            budget,
            acceptance_boundary,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SemanticError> {
        if self.operands.len() > MAX_REFS
            || !self
                .operands
                .windows(2)
                .all(|pair| pair[0].field < pair[1].field)
            || self
                .failure_signature
                .as_ref()
                .is_some_and(|v| !valid_text(v))
            || !valid_text(&self.toolchain)
            || !valid_text(&self.model_revision)
            || !valid_text(&self.harness_revision)
            || !valid_text(&self.algorithm_revision)
            || !valid_text(&self.acceptance_boundary)
            || match &self.anchor {
                ProcedureContextAnchor::Repository {
                    worktree_lineage, ..
                } => !valid_text(worktree_lineage),
                ProcedureContextAnchor::NonRepository { fixture_refs } => !valid_refs(fixture_refs),
            }
        {
            return Err(SemanticError::InvalidProcedure);
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<[u8; 32], SemanticError> {
        self.validate()?;
        sha256(
            "evertrace.procedure_context_fingerprint",
            Self::FINGERPRINT_VERSION,
            &CanonicalValue::Map(vec![
                (
                    "acceptance_boundary_ref".into(),
                    CanonicalValue::String(self.acceptance_boundary.clone()),
                ),
                (
                    "algorithm_revision".into(),
                    CanonicalValue::String(self.algorithm_revision.clone()),
                ),
                ("anchor".into(), anchor_value(&self.anchor)),
                (
                    "budget".into(),
                    CanonicalValue::Integer(i128::from(self.budget)),
                ),
                (
                    "failure_signature".into(),
                    self.failure_signature
                        .clone()
                        .map_or(CanonicalValue::Null, CanonicalValue::String),
                ),
                (
                    "harness_revision".into(),
                    CanonicalValue::String(self.harness_revision.clone()),
                ),
                (
                    "model_revision".into(),
                    CanonicalValue::String(self.model_revision.clone()),
                ),
                (
                    "operands".into(),
                    CanonicalValue::Sequence(self.operands.iter().map(binding_value).collect()),
                ),
                (
                    "phase_kind".into(),
                    CanonicalValue::String(phase(self.phase_kind).into()),
                ),
                (
                    "procedure_revision_id".into(),
                    CanonicalValue::String(self.procedure_revision_id.to_string()),
                ),
                (
                    "task_id".into(),
                    CanonicalValue::String(self.task_id.to_string()),
                ),
                (
                    "toolchain".into(),
                    CanonicalValue::String(self.toolchain.clone()),
                ),
            ]),
        )
        .map_err(|_| SemanticError::InvalidProcedure)
    }

    pub fn complete_for(
        &self,
        applicability_fields: &std::collections::BTreeSet<ConstraintField>,
    ) -> bool {
        let operand_fields = self
            .operands
            .iter()
            .map(|binding| binding.field)
            .collect::<std::collections::BTreeSet<_>>();
        let failure_exact = if applicability_fields.contains(&ConstraintField::FailureSignature) {
            self.failure_signature.as_ref().is_some_and(|signature| {
                self.operands.iter().any(|binding| {
                    binding.field == ConstraintField::FailureSignature
                        && binding.value
                            == crate::semantic::ConstraintValue::Text(signature.clone())
                })
            })
        } else {
            true
        };
        self.validate().is_ok()
            && operand_fields == *applicability_fields
            && failure_exact
            && known_text(&self.toolchain)
            && known_text(&self.model_revision)
            && known_text(&self.harness_revision)
            && known_text(&self.algorithm_revision)
            && self.budget > 0
    }

    pub fn exact_compatible(
        &self,
        other: &Self,
        applicability_fields: &std::collections::BTreeSet<ConstraintField>,
    ) -> bool {
        self.complete_for(applicability_fields)
            && other.complete_for(applicability_fields)
            && self.fingerprint().ok() == other.fingerprint().ok()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureEffectEvidenceClass {
    ObservationalAssociation,
    ControlledComparison,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureEffect {
    Insufficient,
    Positive,
    Mixed,
    Negative,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricDeltaDirection {
    Positive,
    Negative,
    Neutral,
}

pub fn classify_metric_delta(
    binding: &ComparisonExecutionBinding,
    procedure: &str,
    control: &str,
) -> Option<MetricDeltaDirection> {
    let (procedure, control, positive, negative) = (
        ExactDecimal::parse(procedure)?,
        ExactDecimal::parse(control)?,
        ExactDecimal::parse(&binding.positive_delta_threshold)?,
        ExactDecimal::parse(&binding.negative_delta_threshold)?,
    );
    let common = procedure
        .scale
        .max(control.scale)
        .max(positive.scale)
        .max(negative.scale);
    let (procedure, control, positive, negative) = (
        procedure.scaled(common)?,
        control.scaled(common)?,
        positive.scaled(common)?,
        negative.scaled(common)?,
    );
    let delta = match binding.metric_direction {
        MetricDirection::HigherIsBetter => procedure.checked_sub(control)?,
        MetricDirection::LowerIsBetter => control.checked_sub(procedure)?,
    };
    Some(if delta >= positive {
        MetricDeltaDirection::Positive
    } else if delta <= negative.checked_neg()? {
        MetricDeltaDirection::Negative
    } else {
        MetricDeltaDirection::Neutral
    })
}

#[derive(Clone, Copy)]
struct ExactDecimal {
    coefficient: i128,
    scale: u32,
}

impl ExactDecimal {
    fn parse(value: &str) -> Option<Self> {
        let (negative, digits) = value
            .strip_prefix('-')
            .map_or((false, value), |value| (true, value));
        let mut parts = digits.split('.');
        let whole = parts.next()?;
        let fraction = parts.next();
        if whole.is_empty() || parts.next().is_some() || fraction.is_some_and(str::is_empty) {
            return None;
        }
        let fraction = fraction.unwrap_or("");
        if !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let mut coefficient = 0_i128;
        for byte in whole.bytes().chain(fraction.bytes()) {
            coefficient = coefficient
                .checked_mul(10)?
                .checked_add(i128::from(byte - b'0'))?;
        }
        Some(Self {
            coefficient: if negative {
                coefficient.checked_neg()?
            } else {
                coefficient
            },
            scale: u32::try_from(fraction.len()).ok()?,
        })
    }

    fn scaled(self, target: u32) -> Option<i128> {
        self.coefficient
            .checked_mul(10_i128.checked_pow(target.checked_sub(self.scale)?)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureContextEffectProjection {
    pub procedure_revision_id: RevisionId,
    pub context_fingerprint_version: u32,
    pub context_fingerprint_hash: [u8; 32],
    pub context: ProcedureEffectContext,
    pub evidence_class: ProcedureEffectEvidenceClass,
    pub effect: ProcedureEffect,
    pub valid_usage_count: u32,
    pub valid_pair_count: u32,
    pub practical_threshold_revision: u32,
    pub evidence_refs: Vec<String>,
    pub source_watermark: u64,
}

impl ProcedureContextEffectProjection {
    pub fn validate(&self) -> Result<(), SemanticError> {
        self.context.validate()?;
        if self.procedure_revision_id != self.context.procedure_revision_id
            || self.context_fingerprint_version != ProcedureEffectContext::FINGERPRINT_VERSION
            || self.context_fingerprint_hash != self.context.fingerprint()?
            || self.practical_threshold_revision == 0
            || !valid_refs(&self.evidence_refs)
            || self.source_watermark == 0
            || self.evidence_class == ProcedureEffectEvidenceClass::ObservationalAssociation
                && self.valid_pair_count != 0
            || self.evidence_class == ProcedureEffectEvidenceClass::ControlledComparison
                && self.valid_usage_count != 0
            || self.evidence_class == ProcedureEffectEvidenceClass::ControlledComparison
                && self.effect == ProcedureEffect::Insufficient
                && self.valid_pair_count >= 2
        {
            return Err(SemanticError::InvalidProcedure);
        }
        Ok(())
    }

    pub fn exact_compatible(
        &self,
        current: &ProcedureEffectContext,
        applicability_fields: &std::collections::BTreeSet<ConstraintField>,
    ) -> bool {
        self.context.exact_compatible(current, applicability_fields)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationalUsageInput {
    pub procedure_usage_id: ProcedureUsageId,
    pub context: ProcedureEffectContext,
    pub outcome_supported: bool,
    pub evidence_refs: Vec<String>,
    pub source_watermark: u64,
}

pub fn compile_observational_effects(
    inputs: impl IntoIterator<Item = ObservationalUsageInput>,
) -> Result<Vec<ProcedureContextEffectProjection>, SemanticError> {
    let mut groups =
        std::collections::BTreeMap::<(RevisionId, [u8; 32]), Vec<ObservationalUsageInput>>::new();
    for mut input in inputs {
        input.evidence_refs.sort();
        input.evidence_refs.dedup();
        let fingerprint = input.context.fingerprint()?;
        groups
            .entry((input.context.procedure_revision_id, fingerprint))
            .or_default()
            .push(input);
    }
    groups
        .into_iter()
        .map(|((revision_id, fingerprint), mut values)| {
            values.sort_by_key(|value| value.procedure_usage_id);
            let context = values
                .first()
                .ok_or(SemanticError::InvalidProcedure)?
                .context
                .clone();
            if values.iter().any(|value| value.context != context) {
                return Err(SemanticError::InvalidProcedure);
            }
            let successes = values
                .iter()
                .filter(|value| value.outcome_supported)
                .count();
            let effect = if values.len() < 2 {
                ProcedureEffect::Insufficient
            } else if successes == values.len() {
                ProcedureEffect::Positive
            } else if successes == 0 {
                ProcedureEffect::Negative
            } else {
                ProcedureEffect::Mixed
            };
            let projection = ProcedureContextEffectProjection {
                procedure_revision_id: revision_id,
                context_fingerprint_version: ProcedureEffectContext::FINGERPRINT_VERSION,
                context_fingerprint_hash: fingerprint,
                context,
                evidence_class: ProcedureEffectEvidenceClass::ObservationalAssociation,
                effect,
                valid_usage_count: u32::try_from(values.len())
                    .map_err(|_| SemanticError::InvalidProcedure)?,
                valid_pair_count: 0,
                practical_threshold_revision: 1,
                evidence_refs: values
                    .iter()
                    .flat_map(|value| value.evidence_refs.iter().cloned())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                source_watermark: values
                    .iter()
                    .map(|value| value.source_watermark)
                    .max()
                    .ok_or(SemanticError::InvalidProcedure)?,
            };
            projection.validate()?;
            Ok(projection)
        })
        .collect()
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
}

fn known_text(value: &str) -> bool {
    valid_text(value) && value != "unknown"
}

fn valid_refs(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_REFS
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values.iter().all(|value| valid_text(value))
}

fn anchor_value(anchor: &ProcedureContextAnchor) -> CanonicalValue {
    match anchor {
        ProcedureContextAnchor::Repository {
            repository_id,
            worktree_id,
            worktree_snapshot_id,
            worktree_lineage,
        } => CanonicalValue::Map(vec![
            ("kind".into(), CanonicalValue::String("repository".into())),
            (
                "repository_id".into(),
                CanonicalValue::String(repository_id.to_string()),
            ),
            (
                "worktree_id".into(),
                CanonicalValue::String(worktree_id.to_string()),
            ),
            (
                "worktree_lineage".into(),
                CanonicalValue::String(worktree_lineage.clone()),
            ),
            (
                "worktree_snapshot_id".into(),
                CanonicalValue::String(worktree_snapshot_id.to_string()),
            ),
        ]),
        ProcedureContextAnchor::NonRepository { fixture_refs } => CanonicalValue::Map(vec![
            (
                "fixture_refs".into(),
                CanonicalValue::Sequence(
                    fixture_refs
                        .iter()
                        .cloned()
                        .map(CanonicalValue::String)
                        .collect(),
                ),
            ),
            (
                "kind".into(),
                CanonicalValue::String("non_repository".into()),
            ),
        ]),
    }
}

fn binding_value(binding: &ConstraintBinding) -> CanonicalValue {
    CanonicalValue::Map(vec![
        (
            "field".into(),
            CanonicalValue::String(field(binding.field).into()),
        ),
        (
            "value".into(),
            match &binding.value {
                crate::semantic::ConstraintValue::Text(value) => CanonicalValue::Map(vec![
                    ("kind".into(), CanonicalValue::String("text".into())),
                    ("value".into(), CanonicalValue::String(value.clone())),
                ]),
                crate::semantic::ConstraintValue::Boolean(value) => CanonicalValue::Map(vec![
                    ("kind".into(), CanonicalValue::String("boolean".into())),
                    ("value".into(), CanonicalValue::Bool(*value)),
                ]),
            },
        ),
    ])
}

const fn phase(value: ProcedureUsagePhase) -> &'static str {
    match value {
        ProcedureUsagePhase::BeforeEntry => "before_entry",
        ProcedureUsagePhase::AtEntry => "at_entry",
        ProcedureUsagePhase::InProgress => "in_progress",
        ProcedureUsagePhase::RecoverableDeviation => "recoverable_deviation",
        ProcedureUsagePhase::AlreadyCompleted => "already_completed",
        ProcedureUsagePhase::Incompatible => "incompatible",
    }
}

const fn field(value: ConstraintField) -> &'static str {
    match value {
        ConstraintField::AgentKind => "agent_kind",
        ConstraintField::TaskKind => "task_kind",
        ConstraintField::ProjectFamily => "project_family",
        ConstraintField::Toolchain => "toolchain",
        ConstraintField::OperationKind => "operation_kind",
        ConstraintField::PhaseKind => "phase_kind",
        ConstraintField::ArtifactKind => "artifact_kind",
        ConstraintField::EnvironmentProfile => "environment_profile",
        ConstraintField::RevisionActive => "revision_active",
        ConstraintField::VerifierState => "verifier_state",
        ConstraintField::Phase => "phase",
        ConstraintField::FailureSignature => "failure_signature",
        ConstraintField::WorktreeLineage => "worktree_lineage",
        ConstraintField::ArtifactVersion => "artifact_version",
        ConstraintField::ExperimentState => "experiment_state",
    }
}
