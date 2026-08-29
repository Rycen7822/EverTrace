use crate::{
    canonical::{CanonicalValue, sha256},
    revision::RevisionId,
    semantic::{
        ApplicabilityExpr, Atom, AtomAuthority, AtomLifecycleStatus, ConstraintExpr,
        ConstraintField, ConstraintState, ConstraintTruth, ConstraintValue, UserAuthorizationMode,
    },
};
use serde::{Deserialize, Serialize};

pub const FUTURE_CUE_FIELD_REGISTRY_VERSION: u32 = 1;
pub const FUTURE_CUE_COMPILER_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerFamily {
    ExplicitOrRecovery,
    ProspectiveObligation,
    RuntimeAnomaly,
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
    if matches!(atom.scope, crate::semantic::AtomScope::Global) {
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
        ids::{AtomId, RepositoryId, RevisionProposalId, SourceObservationId, TaskId},
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
        let contract = compile_atom_future_cue(&source, true, 7).unwrap();
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
            compile_atom_future_cue(&missing_lifecycle, true, 7),
            Err(FutureCueDiagnostic::SuppressResolveSourceUnavailable)
        );
        assert_eq!(
            compile_atom_future_cue(&source, true, 0),
            Err(FutureCueDiagnostic::InvalidSource)
        );
        assert_eq!(
            compile_atom_future_cue(&source, false, 7),
            Err(FutureCueDiagnostic::SourceNotCurrent)
        );
        let mut inactive = source.clone();
        inactive.lifecycle_status = AtomLifecycleStatus::Deprecated;
        assert_eq!(
            compile_atom_future_cue(&inactive, true, 7),
            Err(FutureCueDiagnostic::SourceInactive)
        );
        let mut finite = source.clone();
        finite.validity_interval.valid_until_us = Some(9);
        assert_eq!(
            compile_atom_future_cue(&finite, true, 7),
            Err(FutureCueDiagnostic::FiniteValidityUnsupported)
        );
        let mut unstructured = source.clone();
        unstructured.applicability_expr = ApplicabilityExpr::Always;
        assert_eq!(
            compile_atom_future_cue(&unstructured, true, 7),
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
            compile_atom_future_cue(&global, true, 7),
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
            compile_atom_future_cue(&policy, true, 7),
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
            compile_atom_future_cue(&overloaded, true, 1),
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
}
