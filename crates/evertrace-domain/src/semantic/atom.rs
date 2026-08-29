use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalValue, sha256},
    ids::{AtomId, RepositoryId, RevisionProposalId, SourceObservationId, TaskId, WorktreeId},
    revision::RevisionId,
};

use super::{ApplicabilityExpr, ConstraintExpr, SemanticError};

const MAX_VALUE_BYTES: usize = 16 * 1024;
const MAX_TEXT_BYTES: usize = 1024;
const MAX_REFS: usize = 256;
const MAX_QUALIFIERS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomKind {
    Fact,
    Constraint,
    Decision,
    Failure,
    Outcome,
    Hypothesis,
    Result,
    Claim,
    Citation,
    Rationale,
    Annotation,
}

impl AtomKind {
    pub const fn is_normative(self) -> bool {
        matches!(self, Self::Constraint | Self::Decision)
    }

    pub const fn is_descriptive(self) -> bool {
        matches!(
            self,
            Self::Fact
                | Self::Failure
                | Self::Outcome
                | Self::Hypothesis
                | Self::Result
                | Self::Claim
                | Self::Citation
                | Self::Rationale
                | Self::Annotation
        )
    }

    const fn supports_objective_evidence(self) -> bool {
        matches!(
            self,
            Self::Fact
                | Self::Failure
                | Self::Outcome
                | Self::Result
                | Self::Claim
                | Self::Citation
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicStatus {
    NotApplicable,
    Unverified,
    Supported,
    Disputed,
    Refuted,
}

impl EpistemicStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Unverified => "unverified",
            Self::Supported => "supported",
            Self::Disputed => "disputed",
            Self::Refuted => "refuted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomLifecycleStatus {
    Active,
    Superseded,
    Deprecated,
}

impl AtomLifecycleStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Deprecated => "deprecated",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomAuthority {
    UserExplicit,
    ProjectPolicy,
    ObjectiveEvidence,
    AgentInferred,
    ImportedClaim,
}

impl AtomAuthority {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserExplicit => "user_explicit",
            Self::ProjectPolicy => "project_policy",
            Self::ObjectiveEvidence => "objective_evidence",
            Self::AgentInferred => "agent_inferred",
            Self::ImportedClaim => "imported_claim",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomScope {
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

impl AtomScope {
    pub const fn specificity(&self) -> u8 {
        match self {
            Self::Task { .. } => 4,
            Self::Worktree { .. } => 3,
            Self::Repository { .. } => 2,
            Self::Global => 1,
        }
    }

    pub fn contains(&self, candidate: &Self) -> bool {
        match (self, candidate) {
            (Self::Global, _) => true,
            (Self::Task { task_id: left }, Self::Task { task_id: right }) => left == right,
            (
                Self::Worktree {
                    repository_instance_id: left_repository,
                    worktree_instance_id: left_worktree,
                },
                Self::Worktree {
                    repository_instance_id: right_repository,
                    worktree_instance_id: right_worktree,
                },
            ) => left_repository == right_repository && left_worktree == right_worktree,
            (
                Self::Repository {
                    repository_instance_id: left,
                },
                Self::Repository {
                    repository_instance_id: right,
                },
            ) => left == right,
            (
                Self::Repository {
                    repository_instance_id: left,
                },
                Self::Worktree {
                    repository_instance_id: right,
                    ..
                },
            ) => left == right,
            _ => false,
        }
    }

    pub const fn task_id(&self) -> Option<TaskId> {
        match self {
            Self::Task { task_id } => Some(*task_id),
            _ => None,
        }
    }

    pub const fn repository_id(&self) -> Option<RepositoryId> {
        match self {
            Self::Worktree {
                repository_instance_id,
                ..
            }
            | Self::Repository {
                repository_instance_id,
            } => Some(*repository_instance_id),
            _ => None,
        }
    }

    pub const fn worktree_id(&self) -> Option<WorktreeId> {
        match self {
            Self::Worktree {
                worktree_instance_id,
                ..
            } => Some(*worktree_instance_id),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticQualifier {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AtomValue {
    pub text: String,
    pub subject: String,
    pub predicate: String,
    pub object: Option<String>,
    pub qualifiers: Vec<SemanticQualifier>,
    pub critical_revision_refs: Vec<RevisionId>,
}

impl AtomValue {
    pub fn validate(&self) -> Result<(), SemanticError> {
        if !valid_long_text(&self.text)
            || !valid_text(&self.subject)
            || !valid_text(&self.predicate)
            || self
                .object
                .as_deref()
                .is_some_and(|value| !valid_text(value))
            || self.qualifiers.len() > MAX_QUALIFIERS
            || !strictly_sorted(&self.qualifiers)
            || self.critical_revision_refs.len() > MAX_REFS
            || !strictly_sorted(&self.critical_revision_refs)
        {
            return Err(SemanticError::InvalidAtom);
        }
        for qualifier in &self.qualifiers {
            if !valid_text(&qualifier.name) || !valid_text(&qualifier.value) {
                return Err(SemanticError::InvalidAtom);
            }
        }
        Ok(())
    }

    pub fn exact_hash(&self) -> Result<[u8; 32], SemanticError> {
        self.validate()?;
        sha256(
            "atom_value_v1",
            1,
            &CanonicalValue::Map(vec![
                ("text".into(), CanonicalValue::String(self.text.clone())),
                (
                    "subject".into(),
                    CanonicalValue::String(self.subject.clone()),
                ),
                (
                    "predicate".into(),
                    CanonicalValue::String(self.predicate.clone()),
                ),
                (
                    "object".into(),
                    self.object
                        .clone()
                        .map_or(CanonicalValue::Null, CanonicalValue::String),
                ),
                (
                    "qualifiers".into(),
                    CanonicalValue::Sequence(
                        self.qualifiers
                            .iter()
                            .map(|value| {
                                CanonicalValue::Map(vec![
                                    ("name".into(), CanonicalValue::String(value.name.clone())),
                                    ("value".into(), CanonicalValue::String(value.value.clone())),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    "critical_revision_refs".into(),
                    CanonicalValue::Sequence(
                        self.critical_revision_refs
                            .iter()
                            .map(|value| CanonicalValue::String(value.to_string()))
                            .collect(),
                    ),
                ),
            ]),
        )
        .map_err(|_| SemanticError::InvalidAtom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidityInterval {
    pub valid_from_us: i64,
    pub valid_until_us: Option<i64>,
}

impl ValidityInterval {
    pub fn validate(&self) -> Result<(), SemanticError> {
        if self.valid_from_us < 0
            || self
                .valid_until_us
                .is_some_and(|end| end <= self.valid_from_us)
        {
            return Err(SemanticError::InvalidAtom);
        }
        Ok(())
    }

    pub fn contains(&self, at_us: i64) -> bool {
        at_us >= self.valid_from_us && self.valid_until_us.is_none_or(|end| at_us < end)
    }

    fn is_within(&self, ceiling: &Self) -> bool {
        self.valid_from_us >= ceiling.valid_from_us
            && match (self.valid_until_us, ceiling.valid_until_us) {
                (_, None) => true,
                (Some(value), Some(limit)) => value <= limit,
                (None, Some(_)) => false,
            }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomProvenance {
    ObservedExec,
    ObservedHost,
    UserAsserted,
    AgentClaimed,
    LlmDerived,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserAuthorizationMode {
    UserStatement,
    CurrentTaskExactMessage,
    TuiAcceptance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserAuthorizationProvenance {
    pub mode: UserAuthorizationMode,
    pub user_source_observation_ref: SourceObservationId,
    pub source_message_hash: [u8; 32],
    pub exact_value_hash: [u8; 32],
    pub authorized_scope_ceiling: AtomScope,
    pub acceptance_event_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyHostScope {
    Worktree {
        repository_instance_id: RepositoryId,
        worktree_instance_id: WorktreeId,
    },
    Repository {
        repository_instance_id: RepositoryId,
    },
}

impl PolicyHostScope {
    pub fn as_atom_scope(&self) -> AtomScope {
        match self {
            Self::Worktree {
                repository_instance_id,
                worktree_instance_id,
            } => AtomScope::Worktree {
                repository_instance_id: *repository_instance_id,
                worktree_instance_id: *worktree_instance_id,
            },
            Self::Repository {
                repository_instance_id,
            } => AtomScope::Repository {
                repository_instance_id: *repository_instance_id,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityProvenance {
    pub policy_source_kind: String,
    pub policy_source_revision_ref: String,
    pub policy_content_hash: [u8; 32],
    pub host_resolved_scope: PolicyHostScope,
    pub adapter_manifest_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FutureCueLifecycleExprs {
    pub suppress_expr: ConstraintExpr,
    pub resolve_expr: ConstraintExpr,
}

impl FutureCueLifecycleExprs {
    fn validate(&self) -> Result<(), SemanticError> {
        self.suppress_expr.validate()?;
        self.resolve_expr.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AtomDraft {
    pub kind: AtomKind,
    pub epistemic_status: EpistemicStatus,
    pub value: AtomValue,
    pub scope: AtomScope,
    pub applicability_expr: ApplicabilityExpr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub future_cue_lifecycle_exprs: Option<FutureCueLifecycleExprs>,
    pub validity_interval: ValidityInterval,
    pub provenance: Vec<AtomProvenance>,
    pub source_observation_refs: Vec<SourceObservationId>,
    pub evidence_refs: Vec<String>,
    pub supersedes_revision_refs: Vec<RevisionId>,
    pub supports_revision_refs: Vec<RevisionId>,
    pub contradicts_revision_refs: Vec<RevisionId>,
}

impl AtomDraft {
    pub fn validate_unprivileged(&self) -> Result<(), SemanticError> {
        self.value.validate()?;
        self.applicability_expr.validate()?;
        if let Some(exprs) = &self.future_cue_lifecycle_exprs {
            if !self.kind.is_normative() {
                return Err(SemanticError::InvalidAtom);
            }
            exprs.validate()?;
        }
        self.validity_interval.validate()?;
        validate_unprivileged_axes(
            self.kind,
            self.epistemic_status,
            &self.provenance,
            &self.evidence_refs,
        )?;
        validate_references(
            &self.provenance,
            &self.source_observation_refs,
            &self.evidence_refs,
            &self.supersedes_revision_refs,
            &self.supports_revision_refs,
            &self.contradicts_revision_refs,
        )
    }

    pub fn semantic_digest(&self) -> Result<[u8; 32], SemanticError> {
        self.validate_unprivileged()?;
        let serialized = toml::to_string(self).map_err(|_| SemanticError::InvalidAtom)?;
        sha256("atom_draft_v1", 1, &CanonicalValue::String(serialized))
            .map_err(|_| SemanticError::InvalidAtom)
    }
}

fn validate_unprivileged_axes(
    kind: AtomKind,
    epistemic_status: EpistemicStatus,
    provenance: &[AtomProvenance],
    evidence_refs: &[String],
) -> Result<(), SemanticError> {
    if kind.is_normative() && epistemic_status != EpistemicStatus::NotApplicable
        || !kind.is_normative()
            && kind != AtomKind::Annotation
            && epistemic_status == EpistemicStatus::NotApplicable
        || epistemic_status == EpistemicStatus::Supported
            && (!kind.is_descriptive()
                || evidence_refs.is_empty()
                || !provenance.iter().any(|value| {
                    matches!(
                        value,
                        AtomProvenance::ObservedExec | AtomProvenance::ObservedHost
                    )
                }))
    {
        return Err(SemanticError::InvalidAtom);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Atom {
    pub atom_id: AtomId,
    pub revision_id: RevisionId,
    pub parent_revision_id: Option<RevisionId>,
    pub kind: AtomKind,
    pub epistemic_status: EpistemicStatus,
    pub lifecycle_status: AtomLifecycleStatus,
    pub authority: AtomAuthority,
    pub value: AtomValue,
    pub scope: AtomScope,
    pub condition_ir_version: u32,
    pub applicability_expr: ApplicabilityExpr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub future_cue_lifecycle_exprs: Option<FutureCueLifecycleExprs>,
    pub validity_interval: ValidityInterval,
    pub provenance: Vec<AtomProvenance>,
    pub user_authorization_provenance: Option<UserAuthorizationProvenance>,
    pub policy_authority_provenance: Option<PolicyAuthorityProvenance>,
    pub source_observation_refs: Vec<SourceObservationId>,
    pub evidence_refs: Vec<String>,
    pub supersedes_revision_refs: Vec<RevisionId>,
    pub supports_revision_refs: Vec<RevisionId>,
    pub contradicts_revision_refs: Vec<RevisionId>,
    pub accepted_proposal_id: Option<RevisionProposalId>,
    pub accepted_proposal_revision_id: Option<RevisionId>,
    pub created_at_us: i64,
}

impl Atom {
    pub fn validate(&self) -> Result<(), SemanticError> {
        self.value.validate()?;
        self.applicability_expr.validate()?;
        if let Some(exprs) = &self.future_cue_lifecycle_exprs {
            if !self.kind.is_normative() {
                return Err(SemanticError::InvalidAtom);
            }
            exprs.validate()?;
        }
        self.validity_interval.validate()?;
        validate_references(
            &self.provenance,
            &self.source_observation_refs,
            &self.evidence_refs,
            &self.supersedes_revision_refs,
            &self.supports_revision_refs,
            &self.contradicts_revision_refs,
        )?;
        if self.condition_ir_version != 1
            || self.created_at_us < 0
            || self.source_observation_refs.is_empty() && self.evidence_refs.is_empty()
            || self
                .supersedes_revision_refs
                .iter()
                .chain(&self.supports_revision_refs)
                .chain(&self.contradicts_revision_refs)
                .any(|revision| *revision == self.revision_id)
            || self.accepted_proposal_id.is_some() != self.accepted_proposal_revision_id.is_some()
        {
            return Err(SemanticError::InvalidAtom);
        }
        self.validate_axes()?;
        self.validate_authority()?;
        Ok(())
    }

    fn validate_axes(&self) -> Result<(), SemanticError> {
        validate_unprivileged_axes(
            self.kind,
            self.epistemic_status,
            &self.provenance,
            &self.evidence_refs,
        )?;
        if self.epistemic_status == EpistemicStatus::Supported
            && matches!(
                self.authority,
                AtomAuthority::AgentInferred | AtomAuthority::ImportedClaim
            )
        {
            return Err(SemanticError::InvalidAtom);
        }
        Ok(())
    }

    fn validate_authority(&self) -> Result<(), SemanticError> {
        match self.authority {
            AtomAuthority::UserExplicit => {
                let user = self
                    .user_authorization_provenance
                    .as_ref()
                    .ok_or(SemanticError::InvalidAtom)?;
                if self.policy_authority_provenance.is_some()
                    || !self
                        .source_observation_refs
                        .contains(&user.user_source_observation_ref)
                    || user.exact_value_hash != self.value.exact_hash()?
                    || !user.authorized_scope_ceiling.contains(&self.scope)
                    || user.source_message_hash == [0; 32]
                    || user.exact_value_hash == [0; 32]
                {
                    return Err(SemanticError::InvalidAtom);
                }
                match user.mode {
                    UserAuthorizationMode::UserStatement => {
                        if !self.kind.is_descriptive()
                            || self.epistemic_status != EpistemicStatus::Unverified
                            || user.acceptance_event_ref.is_some()
                        {
                            return Err(SemanticError::InvalidAtom);
                        }
                    }
                    UserAuthorizationMode::CurrentTaskExactMessage => {
                        if !self.kind.is_normative()
                            || !matches!(self.scope, AtomScope::Task { .. })
                            || user.authorized_scope_ceiling != self.scope
                            || !matches!(self.applicability_expr, ApplicabilityExpr::Always)
                            || self.validity_interval.valid_until_us.is_none()
                            || user.acceptance_event_ref.is_some()
                        {
                            return Err(SemanticError::InvalidAtom);
                        }
                    }
                    UserAuthorizationMode::TuiAcceptance => {
                        if user
                            .acceptance_event_ref
                            .as_deref()
                            .is_none_or(|value| !valid_identifier(value))
                            || self.accepted_proposal_revision_id.is_none()
                        {
                            return Err(SemanticError::InvalidAtom);
                        }
                    }
                }
            }
            AtomAuthority::ProjectPolicy => {
                let policy = self
                    .policy_authority_provenance
                    .as_ref()
                    .ok_or(SemanticError::InvalidAtom)?;
                if self.user_authorization_provenance.is_some()
                    || !self.kind.is_normative()
                    || !matches!(
                        self.scope,
                        AtomScope::Worktree { .. } | AtomScope::Repository { .. }
                    )
                    || !policy
                        .host_resolved_scope
                        .as_atom_scope()
                        .contains(&self.scope)
                    || !valid_identifier(&policy.policy_source_kind)
                    || !valid_identifier(&policy.policy_source_revision_ref)
                    || !valid_identifier(&policy.adapter_manifest_id)
                    || policy.policy_content_hash == [0; 32]
                {
                    return Err(SemanticError::InvalidAtom);
                }
            }
            AtomAuthority::ObjectiveEvidence => {
                if self.user_authorization_provenance.is_some()
                    || self.policy_authority_provenance.is_some()
                    || !self.kind.supports_objective_evidence()
                    || self.epistemic_status != EpistemicStatus::Supported
                    || self.evidence_refs.is_empty()
                    || !self.provenance.iter().any(|value| {
                        matches!(
                            value,
                            AtomProvenance::ObservedExec | AtomProvenance::ObservedHost
                        )
                    })
                {
                    return Err(SemanticError::InvalidAtom);
                }
            }
            AtomAuthority::AgentInferred | AtomAuthority::ImportedClaim => {
                if self.user_authorization_provenance.is_some()
                    || self.policy_authority_provenance.is_some()
                {
                    return Err(SemanticError::InvalidAtom);
                }
            }
        }
        if matches!(self.scope, AtomScope::Global)
            && matches!(self.applicability_expr, ApplicabilityExpr::Always)
            && !self
                .user_authorization_provenance
                .as_ref()
                .is_some_and(|value| {
                    value.mode == UserAuthorizationMode::TuiAcceptance
                        && matches!(value.authorized_scope_ceiling, AtomScope::Global)
                })
        {
            return Err(SemanticError::InvalidAtom);
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), SemanticError> {
        next.validate()?;
        let authority_same = self.authority == next.authority;
        let accepted_authority_change = next.accepted_proposal_revision_id.is_some()
            && match next.authority {
                AtomAuthority::UserExplicit => next
                    .user_authorization_provenance
                    .as_ref()
                    .is_some_and(|value| {
                        matches!(
                            value.mode,
                            UserAuthorizationMode::CurrentTaskExactMessage
                                | UserAuthorizationMode::TuiAcceptance
                        )
                    }),
                AtomAuthority::ObjectiveEvidence => true,
                _ => false,
            };
        if self.atom_id != next.atom_id
            || next.parent_revision_id != Some(self.revision_id)
            || self.lifecycle_status != AtomLifecycleStatus::Active
            || next.created_at_us < self.created_at_us
            || !self.scope.contains(&next.scope)
            || !next.validity_interval.is_within(&self.validity_interval)
            || !authority_same && !accepted_authority_change
            || !contains_all(&next.source_observation_refs, &self.source_observation_refs)
            || !contains_all(&next.evidence_refs, &self.evidence_refs)
            || !contains_all(&next.supports_revision_refs, &self.supports_revision_refs)
            || !contains_all(
                &next.contradicts_revision_refs,
                &self.contradicts_revision_refs,
            )
            || !self.has_semantic_successor_change(next)
        {
            return Err(SemanticError::InvalidAtomSuccessor);
        }
        Ok(())
    }

    fn has_semantic_successor_change(&self, next: &Self) -> bool {
        self.kind != next.kind
            || self.epistemic_status != next.epistemic_status
            || self.lifecycle_status != next.lifecycle_status
            || self.authority != next.authority
            || self.value != next.value
            || self.scope != next.scope
            || self.applicability_expr != next.applicability_expr
            || self.future_cue_lifecycle_exprs != next.future_cue_lifecycle_exprs
            || self.validity_interval != next.validity_interval
            || self.provenance != next.provenance
            || self.user_authorization_provenance != next.user_authorization_provenance
            || self.policy_authority_provenance != next.policy_authority_provenance
            || self.source_observation_refs != next.source_observation_refs
            || self.evidence_refs != next.evidence_refs
            || self.supersedes_revision_refs != next.supersedes_revision_refs
            || self.supports_revision_refs != next.supports_revision_refs
            || self.contradicts_revision_refs != next.contradicts_revision_refs
    }

    /// Compares the complete semantic state while excluding only lineage,
    /// revision identity, and recording time.
    pub fn same_semantic_state(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.epistemic_status == other.epistemic_status
            && self.lifecycle_status == other.lifecycle_status
            && self.authority == other.authority
            && self.value == other.value
            && self.scope == other.scope
            && self.condition_ir_version == other.condition_ir_version
            && self.applicability_expr == other.applicability_expr
            && self.future_cue_lifecycle_exprs == other.future_cue_lifecycle_exprs
            && self.validity_interval == other.validity_interval
            && self.provenance == other.provenance
            && self.user_authorization_provenance == other.user_authorization_provenance
            && self.policy_authority_provenance == other.policy_authority_provenance
            && self.source_observation_refs == other.source_observation_refs
            && self.evidence_refs == other.evidence_refs
            && self.supersedes_revision_refs == other.supersedes_revision_refs
            && self.supports_revision_refs == other.supports_revision_refs
            && self.contradicts_revision_refs == other.contradicts_revision_refs
    }

    pub fn semantic_structure_hash(&self) -> Result<[u8; 32], SemanticError> {
        AtomDraft {
            kind: self.kind,
            epistemic_status: self.epistemic_status,
            value: self.value.clone(),
            scope: self.scope.clone(),
            applicability_expr: self.applicability_expr.clone(),
            future_cue_lifecycle_exprs: self.future_cue_lifecycle_exprs.clone(),
            validity_interval: self.validity_interval.clone(),
            provenance: self.provenance.clone(),
            source_observation_refs: self.source_observation_refs.clone(),
            evidence_refs: self.evidence_refs.clone(),
            supersedes_revision_refs: self.supersedes_revision_refs.clone(),
            supports_revision_refs: self.supports_revision_refs.clone(),
            contradicts_revision_refs: self.contradicts_revision_refs.clone(),
        }
        .semantic_digest()
    }
}

fn validate_references(
    provenance: &[AtomProvenance],
    source_observation_refs: &[SourceObservationId],
    evidence_refs: &[String],
    supersedes: &[RevisionId],
    supports: &[RevisionId],
    contradicts: &[RevisionId],
) -> Result<(), SemanticError> {
    if provenance.is_empty()
        || provenance.len() > MAX_REFS
        || !strictly_sorted(provenance)
        || source_observation_refs.len() > MAX_REFS
        || !strictly_sorted(source_observation_refs)
        || evidence_refs.len() > MAX_REFS
        || !strictly_sorted(evidence_refs)
        || supersedes.len() > MAX_REFS
        || !strictly_sorted(supersedes)
        || supports.len() > MAX_REFS
        || !strictly_sorted(supports)
        || contradicts.len() > MAX_REFS
        || !strictly_sorted(contradicts)
        || evidence_refs.iter().any(|value| !valid_identifier(value))
    {
        return Err(SemanticError::InvalidAtom);
    }
    Ok(())
}

fn valid_long_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_VALUE_BYTES && !value.contains('\0')
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.chars().any(char::is_control)
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.'))
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn contains_all<T: Eq>(values: &[T], required: &[T]) -> bool {
    required.iter().all(|value| values.contains(value))
}
