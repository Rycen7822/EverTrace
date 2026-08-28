use std::collections::{BTreeMap, BTreeSet};

use evertrace_codex::{
    HostProbeReport, adapter_manifest::MaxHostResolvedScope, policy::PolicyEvidence,
};
use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, ObservationRole, SourceObservation, SourceReceipt,
        SourceRole, hex,
    },
    ids::{RepositoryId, TaskId, WorktreeId},
    revision::RevisionId,
    semantic::{
        Atom, AtomAuthority, AtomKind, AtomLifecycleStatus, AtomScope, ConstraintState,
        ConstraintTruth, EpistemicStatus, PolicyAuthorityProvenance, PolicyHostScope,
        SemanticQualifier, UserAuthorizationMode,
    },
};

use super::SemanticServiceError;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CurrentPolicyBinding {
    policy_source_kind: String,
    policy_source_revision_ref: String,
    policy_content_hash: [u8; 32],
    host_resolved_scope: AtomScope,
    adapter_manifest_id: String,
    policy_observation_ref: evertrace_domain::ids::SourceObservationId,
    policy_receipt_ref: evertrace_domain::ids::SourceReceiptId,
    policy_evidence_refs: Vec<String>,
}

impl CurrentPolicyBinding {
    pub fn from_verified_host_probe(
        report: &HostProbeReport,
        evidence: &PolicyEvidence,
        provenance: PolicyAuthorityProvenance,
        observation: &SourceObservation,
        receipt: &SourceReceipt,
    ) -> Result<Self, SemanticServiceError> {
        report
            .verify_project_policy_evidence(evidence)
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        observation
            .validate()
            .map_err(|_| SemanticServiceError::InvalidInput)?;
        receipt
            .validate()
            .map_err(|_| SemanticServiceError::InvalidInput)?;

        let host_resolved_scope = provenance.host_resolved_scope.as_atom_scope();
        let declared_scope_matches = matches!(
            (evidence.resolved_scope, &provenance.host_resolved_scope),
            (
                Some(MaxHostResolvedScope::Repository),
                PolicyHostScope::Repository { .. }
            ) | (
                Some(MaxHostResolvedScope::Worktree),
                PolicyHostScope::Worktree { .. }
            )
        );
        let observation_ref = observation.source_observation_id.to_string();
        let receipt_ref = receipt.source_receipt_id.to_string();
        if !declared_scope_matches
            || observation.source_observation_id != receipt.source_observation_id
            || observation.source_receipt_ref != receipt.source_receipt_id
            || observation.source_instance_id != receipt.source_instance_id
            || observation.source_revision != receipt.source_revision
            || observation.source_record_identity != receipt.source_record_identity
            || !matches!(observation.source_role, SourceRole::Host | SourceRole::Tool)
            || observation.content_trust != ContentTrust::Observed
            || observation.observation_role != ObservationRole::StateProbe
            || receipt.observation_role != ObservationRole::StateProbe
            || observation.capture_completeness != CaptureCompleteness::Complete
            || receipt.capture_completeness != CaptureCompleteness::Complete
            || observation.adapter_revision != receipt.adapter_revision
            || observation.canonicalization_revision != receipt.canonicalization_revision
            || receipt.source_ref != evidence.policy_source_kind
            || evidence.policy_source_kind != provenance.policy_source_kind
            || evidence.source_revision != provenance.policy_source_revision_ref
            || observation.source_revision.as_str() != provenance.policy_source_revision_ref
            || evidence.content_digest != hex(&provenance.policy_content_hash)
            || observation.payload_fingerprint != evidence.content_digest
            || receipt.adapter_manifest_ref != provenance.adapter_manifest_id
            || observation.correlation.adapter_manifest_ref != provenance.adapter_manifest_id
            || report.manifest().adapter_manifest_id != provenance.adapter_manifest_id
            || !evidence.evidence_refs.contains(&observation_ref)
            || !evidence.evidence_refs.contains(&receipt_ref)
            || receipt.repository_instance_id != host_resolved_scope.repository_id()
            || host_resolved_scope
                .worktree_id()
                .is_some_and(|id| receipt.worktree_instance_id != Some(id))
        {
            return Err(SemanticServiceError::InvalidInput);
        }

        Ok(Self {
            policy_source_kind: provenance.policy_source_kind,
            policy_source_revision_ref: provenance.policy_source_revision_ref,
            policy_content_hash: provenance.policy_content_hash,
            host_resolved_scope,
            adapter_manifest_id: provenance.adapter_manifest_id,
            policy_observation_ref: observation.source_observation_id,
            policy_receipt_ref: receipt.source_receipt_id,
            policy_evidence_refs: evidence.evidence_refs.clone(),
        })
    }

    pub(crate) fn provenance(&self) -> Option<PolicyAuthorityProvenance> {
        Some(PolicyAuthorityProvenance {
            policy_source_kind: self.policy_source_kind.clone(),
            policy_source_revision_ref: self.policy_source_revision_ref.clone(),
            policy_content_hash: self.policy_content_hash,
            host_resolved_scope: match &self.host_resolved_scope {
                AtomScope::Worktree {
                    repository_instance_id,
                    worktree_instance_id,
                } => PolicyHostScope::Worktree {
                    repository_instance_id: *repository_instance_id,
                    worktree_instance_id: *worktree_instance_id,
                },
                AtomScope::Repository {
                    repository_instance_id,
                } => PolicyHostScope::Repository {
                    repository_instance_id: *repository_instance_id,
                },
                AtomScope::Task { .. } | AtomScope::Global => return None,
            },
            adapter_manifest_id: self.adapter_manifest_id.clone(),
        })
    }

    pub(crate) fn authorizes_materialization(
        &self,
        scope: &AtomScope,
        observation: &SourceObservation,
        receipt: &SourceReceipt,
        source_observation_refs: &[evertrace_domain::ids::SourceObservationId],
        evidence_refs: &[String],
    ) -> bool {
        self.host_resolved_scope.contains(scope)
            && observation.source_observation_id == self.policy_observation_ref
            && observation.source_receipt_ref == self.policy_receipt_ref
            && receipt.source_receipt_id == self.policy_receipt_ref
            && receipt.source_observation_id == self.policy_observation_ref
            && observation.source_instance_id == receipt.source_instance_id
            && observation.source_revision.as_str() == self.policy_source_revision_ref
            && receipt.source_revision.as_str() == self.policy_source_revision_ref
            && observation.source_record_identity == receipt.source_record_identity
            && matches!(observation.source_role, SourceRole::Host | SourceRole::Tool)
            && observation.content_trust == ContentTrust::Observed
            && observation.observation_role == ObservationRole::StateProbe
            && receipt.observation_role == ObservationRole::StateProbe
            && observation.capture_completeness == CaptureCompleteness::Complete
            && receipt.capture_completeness == CaptureCompleteness::Complete
            && observation.adapter_revision == receipt.adapter_revision
            && observation.canonicalization_revision == receipt.canonicalization_revision
            && observation.payload_fingerprint == hex(&self.policy_content_hash)
            && receipt.source_ref == self.policy_source_kind
            && receipt.adapter_manifest_ref == self.adapter_manifest_id
            && observation.correlation.adapter_manifest_ref == self.adapter_manifest_id
            && receipt.repository_instance_id == self.host_resolved_scope.repository_id()
            && self
                .host_resolved_scope
                .worktree_id()
                .is_none_or(|id| receipt.worktree_instance_id == Some(id))
            && source_observation_refs.contains(&self.policy_observation_ref)
            && self
                .policy_evidence_refs
                .iter()
                .all(|reference| evidence_refs.contains(reference))
    }

    fn supports_atom(&self, atom: &Atom) -> bool {
        self.provenance().is_some_and(|provenance| {
            atom.policy_authority_provenance.as_ref() == Some(&provenance)
        }) && atom
            .source_observation_refs
            .contains(&self.policy_observation_ref)
            && self
                .policy_evidence_refs
                .iter()
                .all(|reference| atom.evidence_refs.contains(reference))
    }
}

#[derive(Clone, Debug, Default)]
pub struct ResolverContext {
    pub task_id: Option<TaskId>,
    pub repository_instance_id: Option<RepositoryId>,
    pub worktree_instance_id: Option<WorktreeId>,
    pub now_us: i64,
    pub current_fields: ConstraintState,
    pub previous_fields: Option<ConstraintState>,
    pub current_policy_bindings: BTreeSet<CurrentPolicyBinding>,
    pub globally_supported_revisions: BTreeSet<RevisionId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormativeResolutionState {
    Active,
    Shadowed,
    Inapplicable,
    ApplicabilityUnknown,
    SupportUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormativeResolution {
    pub revision_id: RevisionId,
    pub state: NormativeResolutionState,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NormativeInstructionResolver;

impl NormativeInstructionResolver {
    pub fn resolve(&self, atoms: &[Atom], context: &ResolverContext) -> Vec<NormativeResolution> {
        let mut states = BTreeMap::new();
        let mut eligible = Vec::new();
        for atom in atoms {
            let state = normative_precondition(atom, context);
            if state == NormativeResolutionState::Active {
                eligible.push(atom);
            }
            states.insert(atom.revision_id, state);
        }

        let explicitly_shadowed = eligible
            .iter()
            .flat_map(|atom| atom.supersedes_revision_refs.iter().copied())
            .collect::<BTreeSet<_>>();
        eligible.retain(|atom| !explicitly_shadowed.contains(&atom.revision_id));
        for revision in explicitly_shadowed {
            if states.get(&revision) == Some(&NormativeResolutionState::Active) {
                states.insert(revision, NormativeResolutionState::Shadowed);
            }
        }

        let mut groups = BTreeMap::<NormativeKey, Vec<&Atom>>::new();
        for atom in eligible {
            groups
                .entry(NormativeKey::from_atom(atom))
                .or_default()
                .push(atom);
        }
        for group in groups.into_values() {
            let Some(winner) = group
                .iter()
                .map(|atom| {
                    (
                        atom.scope.specificity(),
                        authority_precedence(atom.authority),
                    )
                })
                .max()
            else {
                continue;
            };
            for atom in group {
                if (
                    atom.scope.specificity(),
                    authority_precedence(atom.authority),
                ) < winner
                {
                    states.insert(atom.revision_id, NormativeResolutionState::Shadowed);
                }
            }
        }

        atoms
            .iter()
            .map(|atom| NormativeResolution {
                revision_id: atom.revision_id,
                state: states[&atom.revision_id],
            })
            .collect()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NormativeKey {
    kind: AtomKind,
    subject: String,
    predicate: String,
    object: Option<String>,
    qualifiers: Vec<SemanticQualifier>,
    critical_revision_refs: Vec<RevisionId>,
}

impl NormativeKey {
    fn from_atom(atom: &Atom) -> Self {
        Self {
            kind: atom.kind,
            subject: atom.value.subject.clone(),
            predicate: atom.value.predicate.clone(),
            object: atom.value.object.clone(),
            qualifiers: atom.value.qualifiers.clone(),
            critical_revision_refs: atom.value.critical_revision_refs.clone(),
        }
    }
}

fn normative_precondition(atom: &Atom, context: &ResolverContext) -> NormativeResolutionState {
    if atom.validate().is_err() || !atom.kind.is_normative() {
        return NormativeResolutionState::Inapplicable;
    }
    match atom.authority {
        AtomAuthority::UserExplicit => {
            let Some(user) = atom.user_authorization_provenance.as_ref() else {
                return NormativeResolutionState::SupportUnavailable;
            };
            if user.mode == UserAuthorizationMode::UserStatement {
                return NormativeResolutionState::Inapplicable;
            }
        }
        AtomAuthority::ProjectPolicy => {
            if atom.policy_authority_provenance.is_none() {
                return NormativeResolutionState::SupportUnavailable;
            }
            if !context
                .current_policy_bindings
                .iter()
                .any(|binding| binding.supports_atom(atom))
            {
                return NormativeResolutionState::SupportUnavailable;
            }
        }
        AtomAuthority::ObjectiveEvidence
        | AtomAuthority::AgentInferred
        | AtomAuthority::ImportedClaim => return NormativeResolutionState::Inapplicable,
    }
    match atom.lifecycle_status {
        AtomLifecycleStatus::Superseded => return NormativeResolutionState::Shadowed,
        AtomLifecycleStatus::Deprecated => return NormativeResolutionState::Inapplicable,
        AtomLifecycleStatus::Active => {}
    }
    if !scope_applies(&atom.scope, context) || !atom.validity_interval.contains(context.now_us) {
        return NormativeResolutionState::Inapplicable;
    }
    if matches!(atom.scope, AtomScope::Global)
        && !context
            .globally_supported_revisions
            .contains(&atom.revision_id)
    {
        return NormativeResolutionState::SupportUnavailable;
    }
    match atom
        .applicability_expr
        .evaluate(&context.current_fields, context.previous_fields.as_ref())
    {
        ConstraintTruth::True => NormativeResolutionState::Active,
        ConstraintTruth::False => NormativeResolutionState::Inapplicable,
        ConstraintTruth::Unknown => NormativeResolutionState::ApplicabilityUnknown,
    }
}

const fn authority_precedence(authority: AtomAuthority) -> u8 {
    match authority {
        AtomAuthority::UserExplicit => 2,
        AtomAuthority::ProjectPolicy => 1,
        _ => 0,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptiveResolutionState {
    Supported,
    Disputed,
    Refuted,
    Underdetermined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescriptiveResolution {
    pub revision_id: RevisionId,
    pub state: DescriptiveResolutionState,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DescriptiveFactResolver;

impl DescriptiveFactResolver {
    pub fn resolve(&self, atoms: &[Atom], context: &ResolverContext) -> Vec<DescriptiveResolution> {
        let applicable = atoms
            .iter()
            .filter(|atom| descriptive_applicable(atom, context))
            .map(|atom| (atom.revision_id, atom))
            .collect::<BTreeMap<_, _>>();
        let supported = applicable
            .values()
            .filter(|atom| atom.epistemic_status == EpistemicStatus::Supported)
            .map(|atom| atom.revision_id)
            .collect::<BTreeSet<_>>();
        let disputed = applicable
            .values()
            .flat_map(|atom| {
                atom.contradicts_revision_refs
                    .iter()
                    .filter(|revision| supported.contains(revision))
                    .map(move |revision| (atom.revision_id, *revision))
            })
            .filter(|(left, _)| supported.contains(left))
            .flat_map(|(left, right)| [left, right])
            .collect::<BTreeSet<_>>();

        atoms
            .iter()
            .map(|atom| {
                let state = if !applicable.contains_key(&atom.revision_id) {
                    DescriptiveResolutionState::Underdetermined
                } else if disputed.contains(&atom.revision_id)
                    || atom.epistemic_status == EpistemicStatus::Disputed
                {
                    DescriptiveResolutionState::Disputed
                } else {
                    match atom.epistemic_status {
                        EpistemicStatus::Supported => DescriptiveResolutionState::Supported,
                        EpistemicStatus::Refuted => DescriptiveResolutionState::Refuted,
                        EpistemicStatus::NotApplicable
                        | EpistemicStatus::Unverified
                        | EpistemicStatus::Disputed => DescriptiveResolutionState::Underdetermined,
                    }
                };
                DescriptiveResolution {
                    revision_id: atom.revision_id,
                    state,
                }
            })
            .collect()
    }
}

fn descriptive_applicable(atom: &Atom, context: &ResolverContext) -> bool {
    atom.validate().is_ok()
        && atom.kind.is_descriptive()
        && atom.lifecycle_status == AtomLifecycleStatus::Active
        && scope_applies(&atom.scope, context)
        && atom.validity_interval.contains(context.now_us)
        && (!matches!(atom.scope, AtomScope::Global)
            || context
                .globally_supported_revisions
                .contains(&atom.revision_id))
        && atom
            .applicability_expr
            .evaluate(&context.current_fields, context.previous_fields.as_ref())
            .allows_enforcement()
}

fn scope_applies(scope: &AtomScope, context: &ResolverContext) -> bool {
    match scope {
        AtomScope::Task { task_id } => context.task_id == Some(*task_id),
        AtomScope::Worktree {
            repository_instance_id,
            worktree_instance_id,
        } => {
            context.repository_instance_id == Some(*repository_instance_id)
                && context.worktree_instance_id == Some(*worktree_instance_id)
        }
        AtomScope::Repository {
            repository_instance_id,
        } => context.repository_instance_id == Some(*repository_instance_id),
        AtomScope::Global => true,
    }
}
