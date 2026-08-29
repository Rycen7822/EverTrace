use crate::{
    canonical::{CanonicalValue, sha256},
    ids::{
        AttemptId, ExecutionLaneId, PresentationAttemptId, RecallNeedId, RepositoryId,
        ScopeEffectId, TaskId, WorkBindingRevisionId, WorkstreamId, WorktreeId, WorktreeSnapshotId,
    },
    revision::RevisionId,
    semantic::{
        ApplicabilityExpr, Atom, AtomAuthority, AtomLifecycleStatus, ConstraintExpr,
        ConstraintField, ConstraintState, ConstraintTruth, ConstraintValue, UserAuthorizationMode,
    },
    work::{CheckpointVerifierState, PhaseKind},
};
use serde::{Deserialize, Serialize};

pub const FUTURE_CUE_FIELD_REGISTRY_VERSION: u32 = 1;
pub const FUTURE_CUE_COMPILER_VERSION: u32 = 1;
const MAX_RECALL_REFS: usize = 32;
const MAX_RECALL_TEXT: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallDeliveryState {
    Detected,
    Scheduled,
    ClaimedForBoundary,
    Emitted,
    HostPresented,
    PresentationUnknown,
    FailedPreEmit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallAgentResponse {
    NotRetrieved,
    RetrievalClaimed,
    RetrievalReturned,
    RetrievalUnknown,
    Adopted,
    Ignored,
    Dismissed,
    Unobservable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallObligationState {
    Active,
    Resolved,
    Superseded,
    Canceled,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationAttemptState {
    ClaimedForBoundary,
    FailedPreEmit,
    Emitted,
    HostPresented,
    PresentationUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalOutcomeState {
    Claimed,
    Returned,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallCueSnapshot {
    pub session_id: String,
    pub execution_lane_id: ExecutionLaneId,
    pub host_lane_key: String,
    pub adapter_manifest_id: String,
    pub runtime_generation: u64,
    pub recall_need_hash: [u8; 32],
    pub presentation_attempt_id: PresentationAttemptId,
    pub expires_at_us: i64,
    pub checksum: [u8; 32],
}

impl RecallCueSnapshot {
    pub fn seal(mut self) -> Result<Self, crate::canonical::CanonicalError> {
        self.checksum = recall_cue_checksum(&self)?;
        Ok(self)
    }

    pub fn validate(&self) -> bool {
        !self.session_id.is_empty()
            && self.session_id.len() <= MAX_RECALL_TEXT
            && !self.session_id.chars().any(char::is_control)
            && !self.host_lane_key.is_empty()
            && self.host_lane_key.len() <= MAX_RECALL_TEXT
            && !self.host_lane_key.chars().any(char::is_control)
            && !self.adapter_manifest_id.is_empty()
            && self.adapter_manifest_id.len() <= MAX_RECALL_TEXT
            && !self.adapter_manifest_id.chars().any(char::is_control)
            && self.runtime_generation > 0
            && self.expires_at_us > 0
            && recall_cue_checksum(self).ok() == Some(self.checksum)
    }
}

fn recall_cue_checksum(
    snapshot: &RecallCueSnapshot,
) -> Result<[u8; 32], crate::canonical::CanonicalError> {
    sha256(
        "recall_cue_snapshot_v2",
        2,
        &CanonicalValue::Sequence(vec![
            CanonicalValue::String(snapshot.session_id.clone()),
            CanonicalValue::String(snapshot.execution_lane_id.to_string()),
            CanonicalValue::String(snapshot.host_lane_key.clone()),
            CanonicalValue::String(snapshot.adapter_manifest_id.clone()),
            CanonicalValue::Integer(i128::from(snapshot.runtime_generation)),
            CanonicalValue::Bytes(snapshot.recall_need_hash.to_vec()),
            CanonicalValue::String(snapshot.presentation_attempt_id.to_string()),
            CanonicalValue::Integer(i128::from(snapshot.expires_at_us)),
        ]),
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallPlan {
    pub reason: String,
    pub normative_constraint_refs: Vec<String>,
    pub relevant_episode_revision: Option<RevisionId>,
    pub applicable_procedure_revision: Option<RevisionId>,
    pub open_loops: Vec<String>,
    pub stale_delivered_objects: Vec<String>,
    pub supporting_evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallTriggerState {
    pub phase_kind: PhaseKind,
    pub verifier_state: CheckpointVerifierState,
    pub attempt_ids: Vec<AttemptId>,
    pub worktree_snapshot_id: Option<WorktreeSnapshotId>,
    pub binding_revision_id: Option<WorkBindingRevisionId>,
    pub scope_effect_refs: Vec<ScopeEffectId>,
}

impl RecallTriggerState {
    pub fn validate(&self) -> bool {
        self.attempt_ids.len() <= MAX_RECALL_REFS
            && self.attempt_ids.windows(2).all(|pair| pair[0] < pair[1])
            && self.scope_effect_refs.len() <= MAX_RECALL_REFS
            && self
                .scope_effect_refs
                .windows(2)
                .all(|pair| pair[0] < pair[1])
    }
}

impl RecallPlan {
    pub fn validate(&self) -> bool {
        let lists = [
            &self.normative_constraint_refs,
            &self.open_loops,
            &self.stale_delivered_objects,
            &self.supporting_evidence_refs,
        ];
        !self.reason.is_empty()
            && self.reason.len() <= MAX_RECALL_TEXT
            && !self.reason.chars().any(char::is_control)
            && lists.iter().all(|values| {
                values.len() <= MAX_RECALL_REFS
                    && values.windows(2).all(|pair| pair[0] < pair[1])
                    && values.iter().all(|value| {
                        !value.is_empty()
                            && value.len() <= MAX_RECALL_TEXT
                            && !value.chars().any(char::is_control)
                    })
            })
            && (!self.normative_constraint_refs.is_empty()
                || self.relevant_episode_revision.is_some()
                || !self.open_loops.is_empty()
                || !self.stale_delivered_objects.is_empty())
    }

    pub fn fingerprint(&self) -> Result<[u8; 32], crate::canonical::CanonicalError> {
        sha256("recall_plan_v1", 1, &plan_canonical(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallNeed {
    pub recall_need_id: RecallNeedId,
    pub revision_id: RevisionId,
    pub parent_revision_id: Option<RevisionId>,
    pub recall_need_hash: [u8; 32],
    pub trigger_family: TriggerFamily,
    pub source_revision_ids: Vec<RevisionId>,
    pub matched_contract_ids: Vec<[u8; 32]>,
    pub session_id: String,
    pub execution_lane_id: ExecutionLaneId,
    pub task_id: TaskId,
    pub workstream_id: WorkstreamId,
    pub episode_revision_id: RevisionId,
    pub repository_id: Option<RepositoryId>,
    pub worktree_id: Option<WorktreeId>,
    pub boundary_event_ref: String,
    pub trigger_state: RecallTriggerState,
    pub source_watermark: u64,
    pub recall_plan_fingerprint: [u8; 32],
    pub recall_plan: RecallPlan,
    pub delivery_state: RecallDeliveryState,
    pub agent_response: RecallAgentResponse,
    pub obligation_state: RecallObligationState,
    pub created_at_us: i64,
    pub presentation_expires_at_us: i64,
    pub obligation_expires_at_us: Option<i64>,
    pub active_presentation_attempt_id: Option<PresentationAttemptId>,
    pub active_retrieval_request_id: Option<String>,
}

impl RecallNeed {
    pub fn seal(mut self) -> Result<Self, crate::canonical::CanonicalError> {
        self.recall_plan_fingerprint = self.recall_plan.fingerprint()?;
        self.recall_need_hash = recall_need_hash(&self)?;
        Ok(self)
    }

    pub fn validate(&self) -> bool {
        self.source_watermark > 0
            && self.created_at_us >= 0
            && self.presentation_expires_at_us > self.created_at_us
            && self
                .obligation_expires_at_us
                .is_none_or(|value| value > self.created_at_us)
            && !self.session_id.is_empty()
            && self.session_id.len() <= MAX_RECALL_TEXT
            && !self.boundary_event_ref.is_empty()
            && self.boundary_event_ref.len() <= MAX_RECALL_TEXT
            && self.trigger_state.validate()
            && self.source_revision_ids.len() <= MAX_RECALL_REFS
            && !self.source_revision_ids.is_empty()
            && self
                .source_revision_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && self.matched_contract_ids.len() <= MAX_RECALL_REFS
            && self
                .matched_contract_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && self
                .active_retrieval_request_id
                .as_ref()
                .is_none_or(|value| {
                    !value.is_empty()
                        && value.len() <= MAX_RECALL_TEXT
                        && !value.chars().any(char::is_control)
                })
            && self.active_presentation_attempt_id.is_some()
                == !matches!(
                    self.delivery_state,
                    RecallDeliveryState::Detected
                        | RecallDeliveryState::Scheduled
                        | RecallDeliveryState::FailedPreEmit
                )
            && self.active_retrieval_request_id.is_some()
                == (self.agent_response != RecallAgentResponse::NotRetrieved)
            && self.recall_plan.validate()
            && self.recall_plan.fingerprint().ok() == Some(self.recall_plan_fingerprint)
            && recall_need_hash(self).ok() == Some(self.recall_need_hash)
            && (self.parent_revision_id.is_none()
                || self.parent_revision_id != Some(self.revision_id))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallPresentationAttempt {
    pub presentation_attempt_id: PresentationAttemptId,
    pub recall_need_id: RecallNeedId,
    pub recall_need_hash: [u8; 32],
    pub boundary_event_ref: String,
    pub state: PresentationAttemptState,
    pub occurred_at_us: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallRetrievalOutcome {
    pub request_id: String,
    pub recall_need_id: RecallNeedId,
    pub recall_need_hash: [u8; 32],
    pub state: RetrievalOutcomeState,
    pub occurred_at_us: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecallLedgerEvent {
    NeedRecorded { need: Box<RecallNeed> },
    PresentationAttempt { attempt: RecallPresentationAttempt },
    RetrievalOutcome { outcome: RecallRetrievalOutcome },
}

impl RecallLedgerEvent {
    pub fn validate(&self) -> bool {
        match self {
            Self::NeedRecorded { need } => need.validate(),
            Self::PresentationAttempt { attempt } => {
                !attempt.boundary_event_ref.is_empty()
                    && attempt.boundary_event_ref.len() <= MAX_RECALL_TEXT
                    && attempt.occurred_at_us >= 0
            }
            Self::RetrievalOutcome { outcome } => {
                !outcome.request_id.is_empty()
                    && outcome.request_id.len() <= MAX_RECALL_TEXT
                    && outcome.occurred_at_us >= 0
            }
        }
    }
}

pub fn recall_need_hash(need: &RecallNeed) -> Result<[u8; 32], crate::canonical::CanonicalError> {
    sha256(
        "recall_need_v1",
        1,
        &CanonicalValue::Sequence(vec![
            CanonicalValue::String(need.session_id.clone()),
            CanonicalValue::String(need.execution_lane_id.to_string()),
            CanonicalValue::String(need.trigger_family.as_str().to_owned()),
            CanonicalValue::Sequence(
                need.source_revision_ids
                    .iter()
                    .map(|value| CanonicalValue::String(value.to_string()))
                    .collect(),
            ),
            CanonicalValue::Sequence(
                need.matched_contract_ids
                    .iter()
                    .map(|value| CanonicalValue::Bytes(value.to_vec()))
                    .collect(),
            ),
            CanonicalValue::String(need.task_id.to_string()),
            CanonicalValue::String(need.workstream_id.to_string()),
            CanonicalValue::String(need.episode_revision_id.to_string()),
            need.repository_id.map_or(CanonicalValue::Null, |value| {
                CanonicalValue::String(value.to_string())
            }),
            need.worktree_id.map_or(CanonicalValue::Null, |value| {
                CanonicalValue::String(value.to_string())
            }),
            CanonicalValue::String(need.boundary_event_ref.clone()),
            trigger_state_canonical(&need.trigger_state),
            CanonicalValue::Integer(i128::from(need.source_watermark)),
            CanonicalValue::Bytes(need.recall_plan_fingerprint.to_vec()),
        ]),
    )
}

fn plan_canonical(plan: &RecallPlan) -> CanonicalValue {
    let strings = |values: &[String]| {
        CanonicalValue::Sequence(
            values
                .iter()
                .map(|value| CanonicalValue::String(value.clone()))
                .collect(),
        )
    };
    CanonicalValue::Sequence(vec![
        CanonicalValue::String(plan.reason.clone()),
        strings(&plan.normative_constraint_refs),
        plan.applicable_procedure_revision
            .map_or(CanonicalValue::Null, |value| {
                CanonicalValue::String(value.to_string())
            }),
        plan.relevant_episode_revision
            .map_or(CanonicalValue::Null, |value| {
                CanonicalValue::String(value.to_string())
            }),
        strings(&plan.open_loops),
        strings(&plan.stale_delivered_objects),
        strings(&plan.supporting_evidence_refs),
    ])
}

fn trigger_state_canonical(state: &RecallTriggerState) -> CanonicalValue {
    let phase = match state.phase_kind {
        PhaseKind::Orient => "orient",
        PhaseKind::Inspect => "inspect",
        PhaseKind::Reproduce => "reproduce",
        PhaseKind::Diagnose => "diagnose",
        PhaseKind::Design => "design",
        PhaseKind::Implement => "implement",
        PhaseKind::Verify => "verify",
        PhaseKind::Execute => "execute",
        PhaseKind::Analyze => "analyze",
        PhaseKind::Recover => "recover",
        PhaseKind::Deliver => "deliver",
        PhaseKind::Unknown => "unknown",
    };
    let verifier = match state.verifier_state {
        CheckpointVerifierState::Unverified => "unverified",
        CheckpointVerifierState::Passed => "passed",
        CheckpointVerifierState::Failed => "failed",
        CheckpointVerifierState::Inconclusive => "inconclusive",
    };
    CanonicalValue::Sequence(vec![
        CanonicalValue::String(phase.into()),
        CanonicalValue::String(verifier.into()),
        CanonicalValue::Sequence(
            state
                .attempt_ids
                .iter()
                .map(|value| CanonicalValue::String(value.to_string()))
                .collect(),
        ),
        state
            .worktree_snapshot_id
            .map_or(CanonicalValue::Null, |value| {
                CanonicalValue::String(value.to_string())
            }),
        state
            .binding_revision_id
            .map_or(CanonicalValue::Null, |value| {
                CanonicalValue::String(value.to_string())
            }),
        CanonicalValue::Sequence(
            state
                .scope_effect_refs
                .iter()
                .map(|value| CanonicalValue::String(value.to_string()))
                .collect(),
        ),
    ])
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerFamily {
    ExplicitOrRecovery,
    ProspectiveObligation,
    RuntimeAnomaly,
}

impl TriggerFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitOrRecovery => "explicit_or_recovery",
            Self::ProspectiveObligation => "prospective_obligation",
            Self::RuntimeAnomaly => "runtime_anomaly",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FutureCueDiagnostic {
    InvalidSource,
    SourceNotCurrent,
    SourceInactive,
    SourceNotNormative,
    AuthorityUnverified,
    ProjectPolicyProofUnavailable,
    GlobalSupportUnavailable,
    UnstructuredCondition,
    FiniteValidityUnsupported,
    FieldNotAllowed,
    SuppressResolveSourceUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FutureCueContract {
    pub future_cue_contract_id: [u8; 32],
    pub source_revision_id: RevisionId,
    pub trigger_family: TriggerFamily,
    pub condition_ir_version: u32,
    pub match_expr: ConstraintExpr,
    pub suppress_expr: ConstraintExpr,
    pub resolve_expr: ConstraintExpr,
    pub field_registry_version: u32,
    pub global_support_dependency_generation: Option<u64>,
    pub compiler_version: u32,
    pub source_watermark: u64,
}

impl FutureCueContract {
    pub fn validate(&self) -> Result<(), FutureCueDiagnostic> {
        if self.trigger_family != TriggerFamily::ProspectiveObligation
            || self.condition_ir_version != 1
            || self.field_registry_version != FUTURE_CUE_FIELD_REGISTRY_VERSION
            || self.compiler_version != FUTURE_CUE_COMPILER_VERSION
            || self.source_watermark == 0
            || self.global_support_dependency_generation.is_some()
            || self.match_expr.validate().is_err()
            || self.suppress_expr.validate().is_err()
            || self.resolve_expr.validate().is_err()
            || !future_cue_fields_allowed(&self.match_expr)
            || !future_cue_fields_allowed(&self.suppress_expr)
            || !future_cue_fields_allowed(&self.resolve_expr)
            || self.future_cue_contract_id
                != contract_id(self).map_err(|_| FutureCueDiagnostic::InvalidSource)?
        {
            return Err(FutureCueDiagnostic::InvalidSource);
        }
        Ok(())
    }

    pub fn evaluate_match(
        &self,
        current: &ConstraintState,
        previous: Option<&ConstraintState>,
    ) -> ConstraintTruth {
        self.match_expr.evaluate(current, previous)
    }

    pub fn evaluate_suppress(
        &self,
        current: &ConstraintState,
        previous: Option<&ConstraintState>,
    ) -> ConstraintTruth {
        self.suppress_expr.evaluate(current, previous)
    }

    pub fn evaluate_resolve(
        &self,
        current: &ConstraintState,
        previous: Option<&ConstraintState>,
    ) -> ConstraintTruth {
        self.resolve_expr.evaluate(current, previous)
    }
}

pub fn compile_atom_future_cue(
    atom: &Atom,
    is_current: bool,
    global_support_valid: bool,
    source_watermark: u64,
) -> Result<FutureCueContract, FutureCueDiagnostic> {
    atom.validate()
        .map_err(|_| FutureCueDiagnostic::InvalidSource)?;
    if !is_current {
        return Err(FutureCueDiagnostic::SourceNotCurrent);
    }
    if atom.lifecycle_status != AtomLifecycleStatus::Active {
        return Err(FutureCueDiagnostic::SourceInactive);
    }
    if !atom.kind.is_normative() {
        return Err(FutureCueDiagnostic::SourceNotNormative);
    }
    match atom.authority {
        AtomAuthority::UserExplicit
            if atom
                .user_authorization_provenance
                .as_ref()
                .is_some_and(|proof| proof.mode == UserAuthorizationMode::TuiAcceptance) => {}
        AtomAuthority::ProjectPolicy => {
            return Err(FutureCueDiagnostic::ProjectPolicyProofUnavailable);
        }
        _ => return Err(FutureCueDiagnostic::AuthorityUnverified),
    }
    if matches!(atom.scope, crate::semantic::AtomScope::Global) && !global_support_valid {
        return Err(FutureCueDiagnostic::GlobalSupportUnavailable);
    }
    if atom.validity_interval.valid_until_us.is_some() {
        return Err(FutureCueDiagnostic::FiniteValidityUnsupported);
    }
    let ApplicabilityExpr::Constraint(match_expr) = &atom.applicability_expr else {
        return Err(FutureCueDiagnostic::UnstructuredCondition);
    };
    if !future_cue_fields_allowed(match_expr) {
        return Err(FutureCueDiagnostic::FieldNotAllowed);
    }
    let lifecycle = atom
        .future_cue_lifecycle_exprs
        .as_ref()
        .ok_or(FutureCueDiagnostic::SuppressResolveSourceUnavailable)?;
    if !future_cue_fields_allowed(&lifecycle.suppress_expr)
        || !future_cue_fields_allowed(&lifecycle.resolve_expr)
    {
        return Err(FutureCueDiagnostic::FieldNotAllowed);
    }
    if source_watermark == 0 {
        return Err(FutureCueDiagnostic::InvalidSource);
    }
    let mut contract = FutureCueContract {
        future_cue_contract_id: [0; 32],
        source_revision_id: atom.revision_id,
        trigger_family: TriggerFamily::ProspectiveObligation,
        condition_ir_version: atom.condition_ir_version,
        match_expr: match_expr.clone(),
        suppress_expr: lifecycle.suppress_expr.clone(),
        resolve_expr: lifecycle.resolve_expr.clone(),
        field_registry_version: FUTURE_CUE_FIELD_REGISTRY_VERSION,
        global_support_dependency_generation: None,
        compiler_version: FUTURE_CUE_COMPILER_VERSION,
        source_watermark,
    };
    contract.future_cue_contract_id =
        contract_id(&contract).map_err(|_| FutureCueDiagnostic::InvalidSource)?;
    contract.validate()?;
    Ok(contract)
}

fn contract_id(contract: &FutureCueContract) -> Result<[u8; 32], crate::canonical::CanonicalError> {
    sha256(
        "future_cue_contract_v1",
        1,
        &CanonicalValue::Sequence(vec![
            CanonicalValue::String(contract.source_revision_id.to_string()),
            CanonicalValue::Integer(i128::from(contract.condition_ir_version)),
            constraint_canonical(&contract.match_expr),
            constraint_canonical(&contract.suppress_expr),
            constraint_canonical(&contract.resolve_expr),
            CanonicalValue::Integer(i128::from(contract.field_registry_version)),
            contract
                .global_support_dependency_generation
                .map_or(CanonicalValue::Null, |value| {
                    CanonicalValue::Integer(i128::from(value))
                }),
            CanonicalValue::Integer(i128::from(contract.compiler_version)),
            CanonicalValue::Integer(i128::from(contract.source_watermark)),
        ]),
    )
}

fn constraint_canonical(expr: &ConstraintExpr) -> CanonicalValue {
    let field = |field: ConstraintField| {
        CanonicalValue::String(
            match field {
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
            .into(),
        )
    };
    let value = |value: &ConstraintValue| match value {
        ConstraintValue::Text(value) => CanonicalValue::String(value.clone()),
        ConstraintValue::Boolean(value) => CanonicalValue::Bool(*value),
    };
    match expr {
        ConstraintExpr::All { terms } => CanonicalValue::Sequence(vec![
            CanonicalValue::String("all".into()),
            CanonicalValue::Sequence(terms.iter().map(constraint_canonical).collect()),
        ]),
        ConstraintExpr::Any { terms } => CanonicalValue::Sequence(vec![
            CanonicalValue::String("any".into()),
            CanonicalValue::Sequence(terms.iter().map(constraint_canonical).collect()),
        ]),
        ConstraintExpr::Not { term } => CanonicalValue::Sequence(vec![
            CanonicalValue::String("not".into()),
            constraint_canonical(term),
        ]),
        ConstraintExpr::Eq {
            field: expr_field,
            value: expr_value,
        } => CanonicalValue::Sequence(vec![
            CanonicalValue::String("eq".into()),
            field(*expr_field),
            value(expr_value),
        ]),
        ConstraintExpr::In {
            field: expr_field,
            values,
        } => CanonicalValue::Sequence(vec![
            CanonicalValue::String("in".into()),
            field(*expr_field),
            CanonicalValue::Sequence(values.iter().map(value).collect()),
        ]),
        ConstraintExpr::Exists { field: expr_field } => CanonicalValue::Sequence(vec![
            CanonicalValue::String("exists".into()),
            field(*expr_field),
        ]),
        ConstraintExpr::Changed { field: expr_field } => CanonicalValue::Sequence(vec![
            CanonicalValue::String("changed".into()),
            field(*expr_field),
        ]),
        ConstraintExpr::Transitioned {
            field: expr_field,
            from,
            to,
        } => CanonicalValue::Sequence(vec![
            CanonicalValue::String("transitioned".into()),
            field(*expr_field),
            value(from),
            value(to),
        ]),
    }
}

fn future_cue_fields_allowed(expr: &ConstraintExpr) -> bool {
    match expr {
        ConstraintExpr::All { terms } | ConstraintExpr::Any { terms } => {
            terms.iter().all(future_cue_fields_allowed)
        }
        ConstraintExpr::Not { term } => future_cue_fields_allowed(term),
        ConstraintExpr::Eq { field, .. }
        | ConstraintExpr::In { field, .. }
        | ConstraintExpr::Exists { field }
        | ConstraintExpr::Changed { field }
        | ConstraintExpr::Transitioned { field, .. } => matches!(
            field,
            ConstraintField::OperationKind
                | ConstraintField::PhaseKind
                | ConstraintField::ArtifactKind
                | ConstraintField::RevisionActive
                | ConstraintField::VerifierState
                | ConstraintField::Phase
                | ConstraintField::FailureSignature
                | ConstraintField::WorktreeLineage
                | ConstraintField::ArtifactVersion
                | ConstraintField::ExperimentState
        ),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ids::{
            AtomId, ExecutionLaneId, RepositoryId, RevisionProposalId, SourceObservationId, TaskId,
            WorkstreamId,
        },
        revision::RevisionId,
        semantic::{
            ApplicabilityExpr, AtomAuthority, AtomKind, AtomLifecycleStatus, AtomProvenance,
            AtomScope, AtomValue, EpistemicStatus, FutureCueLifecycleExprs,
            PolicyAuthorityProvenance, PolicyHostScope, SemanticQualifier,
            UserAuthorizationProvenance, ValidityInterval,
        },
    };

    use super::*;

    fn atom(expr: ConstraintExpr) -> Atom {
        let scope = AtomScope::Task {
            task_id: TaskId::new_v7(),
        };
        let value = AtomValue {
            text: "no trigger words occur here".into(),
            subject: "obligation".into(),
            predicate: "applies".into(),
            object: None,
            qualifiers: vec![SemanticQualifier {
                name: "structured".into(),
                value: "true".into(),
            }],
            critical_revision_refs: vec![],
        };
        let observation = SourceObservationId::from_digest([2; 32]);
        let proposal_id = RevisionProposalId::new_v7();
        Atom {
            atom_id: AtomId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            kind: AtomKind::Constraint,
            epistemic_status: EpistemicStatus::NotApplicable,
            lifecycle_status: AtomLifecycleStatus::Active,
            authority: AtomAuthority::UserExplicit,
            value: value.clone(),
            scope: scope.clone(),
            condition_ir_version: 1,
            applicability_expr: ApplicabilityExpr::Constraint(expr),
            future_cue_lifecycle_exprs: Some(FutureCueLifecycleExprs {
                suppress_expr: ConstraintExpr::Eq {
                    field: ConstraintField::VerifierState,
                    value: ConstraintValue::Text("blocked".into()),
                },
                resolve_expr: ConstraintExpr::Eq {
                    field: ConstraintField::ArtifactKind,
                    value: ConstraintValue::Text("release".into()),
                },
            }),
            validity_interval: ValidityInterval {
                valid_from_us: 1,
                valid_until_us: None,
            },
            provenance: vec![AtomProvenance::AgentClaimed],
            user_authorization_provenance: Some(UserAuthorizationProvenance {
                mode: UserAuthorizationMode::TuiAcceptance,
                user_source_observation_ref: observation,
                source_message_hash: [1; 32],
                exact_value_hash: value.exact_hash().unwrap(),
                authorized_scope_ceiling: scope,
                acceptance_event_ref: Some("acceptance:s21".into()),
            }),
            policy_authority_provenance: None,
            source_observation_refs: vec![observation],
            evidence_refs: vec!["receipt:s21".into()],
            supersedes_revision_refs: vec![],
            supports_revision_refs: vec![],
            contradicts_revision_refs: vec![],
            accepted_proposal_id: Some(proposal_id),
            accepted_proposal_revision_id: Some(RevisionId::new_v7()),
            created_at_us: 1,
        }
    }

    #[test]
    fn compiler_uses_typed_match_suppress_and_resolve_truth() {
        let source = atom(ConstraintExpr::Eq {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text("deliver".into()),
        });
        source.validate().unwrap();
        let contract = compile_atom_future_cue(&source, true, false, 7).unwrap();
        assert_eq!(
            contract.match_expr,
            match &source.applicability_expr {
                ApplicabilityExpr::Constraint(expr) => expr.clone(),
                ApplicabilityExpr::Always => unreachable!(),
            }
        );
        assert_eq!(
            contract.suppress_expr,
            source
                .future_cue_lifecycle_exprs
                .as_ref()
                .unwrap()
                .suppress_expr
        );
        assert_eq!(
            contract.resolve_expr,
            source
                .future_cue_lifecycle_exprs
                .as_ref()
                .unwrap()
                .resolve_expr
        );
        let mut unchanged = source.clone();
        unchanged.parent_revision_id = Some(source.revision_id);
        unchanged.revision_id = RevisionId::new_v7();
        unchanged.created_at_us += 1;
        assert!(source.validate_successor(&unchanged).is_err());
        let mut changed = unchanged;
        changed
            .future_cue_lifecycle_exprs
            .as_mut()
            .unwrap()
            .resolve_expr = ConstraintExpr::Exists {
            field: ConstraintField::ArtifactKind,
        };
        source.validate_successor(&changed).unwrap();
        let mut missing_lifecycle = source.clone();
        missing_lifecycle.future_cue_lifecycle_exprs = None;
        assert_eq!(
            compile_atom_future_cue(&missing_lifecycle, true, false, 7),
            Err(FutureCueDiagnostic::SuppressResolveSourceUnavailable)
        );
        assert_eq!(
            compile_atom_future_cue(&source, true, false, 0),
            Err(FutureCueDiagnostic::InvalidSource)
        );
        assert_eq!(
            compile_atom_future_cue(&source, false, false, 7),
            Err(FutureCueDiagnostic::SourceNotCurrent)
        );
        let mut inactive = source.clone();
        inactive.lifecycle_status = AtomLifecycleStatus::Deprecated;
        assert_eq!(
            compile_atom_future_cue(&inactive, true, false, 7),
            Err(FutureCueDiagnostic::SourceInactive)
        );
        let mut finite = source.clone();
        finite.validity_interval.valid_until_us = Some(9);
        assert_eq!(
            compile_atom_future_cue(&finite, true, false, 7),
            Err(FutureCueDiagnostic::FiniteValidityUnsupported)
        );
        let mut unstructured = source.clone();
        unstructured.applicability_expr = ApplicabilityExpr::Always;
        assert_eq!(
            compile_atom_future_cue(&unstructured, true, false, 7),
            Err(FutureCueDiagnostic::UnstructuredCondition)
        );
        let mut global = source.clone();
        global.scope = AtomScope::Global;
        global
            .user_authorization_provenance
            .as_mut()
            .unwrap()
            .authorized_scope_ceiling = AtomScope::Global;
        assert_eq!(
            compile_atom_future_cue(&global, true, false, 7),
            Err(FutureCueDiagnostic::GlobalSupportUnavailable)
        );
        let mut policy = source.clone();
        let repository_instance_id = RepositoryId::new_v7();
        policy.scope = AtomScope::Repository {
            repository_instance_id,
        };
        policy.authority = AtomAuthority::ProjectPolicy;
        policy.user_authorization_provenance = None;
        policy.policy_authority_provenance = Some(PolicyAuthorityProvenance {
            policy_source_kind: "host_policy".into(),
            policy_source_revision_ref: "policy_revision_1".into(),
            policy_content_hash: [3; 32],
            host_resolved_scope: PolicyHostScope::Repository {
                repository_instance_id,
            },
            adapter_manifest_id: "adapter_manifest_1".into(),
        });
        assert_eq!(
            compile_atom_future_cue(&policy, true, false, 7),
            Err(FutureCueDiagnostic::ProjectPolicyProofUnavailable)
        );
    }

    #[test]
    fn unknown_or_overloaded_fields_never_trigger() {
        let overloaded = atom(ConstraintExpr::Eq {
            field: ConstraintField::AgentKind,
            value: ConstraintValue::Text("assistant".into()),
        });
        assert_eq!(
            compile_atom_future_cue(&overloaded, true, false, 1),
            Err(FutureCueDiagnostic::FieldNotAllowed)
        );
        let expr = ConstraintExpr::Eq {
            field: ConstraintField::Phase,
            value: ConstraintValue::Text("deliver".into()),
        };
        assert_eq!(
            expr.evaluate(&ConstraintState::default(), None),
            ConstraintTruth::Unknown
        );
    }

    #[test]
    fn recall_need_and_cue_checksums_bind_immutable_identity() {
        let source_revision = RevisionId::new_v7();
        let mut need = RecallNeed {
            recall_need_id: RecallNeedId::new_v7(),
            revision_id: RevisionId::new_v7(),
            parent_revision_id: None,
            recall_need_hash: [0; 32],
            trigger_family: TriggerFamily::ProspectiveObligation,
            source_revision_ids: vec![source_revision],
            matched_contract_ids: vec![[3; 32]],
            session_id: "session-s22".into(),
            execution_lane_id: ExecutionLaneId::new_v7(),
            task_id: TaskId::new_v7(),
            workstream_id: WorkstreamId::new_v7(),
            episode_revision_id: RevisionId::new_v7(),
            repository_id: None,
            worktree_id: None,
            boundary_event_ref: "boundary:s22".into(),
            trigger_state: RecallTriggerState {
                phase_kind: PhaseKind::Deliver,
                verifier_state: CheckpointVerifierState::Passed,
                attempt_ids: Vec::new(),
                worktree_snapshot_id: None,
                binding_revision_id: None,
                scope_effect_refs: Vec::new(),
            },
            source_watermark: 7,
            recall_plan_fingerprint: [0; 32],
            recall_plan: RecallPlan {
                reason: "prospective_obligation".into(),
                normative_constraint_refs: vec![source_revision.to_string()],
                relevant_episode_revision: None,
                applicable_procedure_revision: None,
                open_loops: Vec::new(),
                stale_delivered_objects: Vec::new(),
                supporting_evidence_refs: Vec::new(),
            },
            delivery_state: RecallDeliveryState::Detected,
            agent_response: RecallAgentResponse::NotRetrieved,
            obligation_state: RecallObligationState::Active,
            created_at_us: 1,
            presentation_expires_at_us: 10,
            obligation_expires_at_us: None,
            active_presentation_attempt_id: None,
            active_retrieval_request_id: None,
        }
        .seal()
        .unwrap();
        assert!(need.validate());
        let mut trigger_tamper = need.clone();
        trigger_tamper.trigger_state.verifier_state = CheckpointVerifierState::Failed;
        assert!(!trigger_tamper.validate());
        need.boundary_event_ref.push_str("-tampered");
        assert!(!need.validate());

        let mut cue = RecallCueSnapshot {
            session_id: "session-s22".into(),
            execution_lane_id: need.execution_lane_id,
            host_lane_key: "lane:test".into(),
            adapter_manifest_id: "adapter:test".into(),
            runtime_generation: 1,
            recall_need_hash: [5; 32],
            presentation_attempt_id: PresentationAttemptId::new_v7(),
            expires_at_us: 10,
            checksum: [0; 32],
        }
        .seal()
        .unwrap();
        assert!(cue.validate());
        cue.expires_at_us = 11;
        assert!(!cue.validate());
    }
}
