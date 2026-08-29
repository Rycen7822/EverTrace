use evertrace_domain::{
    evidence::{
        CaptureCompleteness, ContentTrust, ObservationRole, SourceObservation, SourceReceipt,
        SourceRole, hex, payload_fingerprint,
    },
    ids::RevisionProposalId,
    revision::RevisionId,
    semantic::{
        ApplicabilityExpr, Atom, AtomAuthority, AtomDraft, AtomKind, AtomLifecycleStatus,
        AtomProvenance, AtomScope, AtomValue, EpistemicStatus, PolicyAuthorityProvenance,
        UserAuthorizationMode, UserAuthorizationProvenance, ValidityInterval,
    },
};

use super::{CurrentPolicyBinding, SemanticServiceError};

#[derive(Clone, Debug)]
pub enum AtomAuthorityBasis {
    CurrentTaskExactMessage {
        observation: Box<SourceObservation>,
        receipt: Box<SourceReceipt>,
        canonical_message: String,
    },
    UserStatement {
        observation: Box<SourceObservation>,
        receipt: Box<SourceReceipt>,
    },
    TuiAcceptance(VerifiedTuiAcceptance),
    ProjectPolicy {
        binding: CurrentPolicyBinding,
        observation: Box<SourceObservation>,
        receipt: Box<SourceReceipt>,
    },
    ObjectiveEvidence,
    AgentInferred,
    ImportedClaim,
}

#[derive(Clone, Debug)]
pub struct VerifiedTuiAcceptance {
    observation: Box<SourceObservation>,
    receipt: Box<SourceReceipt>,
    authorized_scope_ceiling: AtomScope,
}

impl VerifiedTuiAcceptance {
    pub(super) fn new(
        observation: Box<SourceObservation>,
        receipt: Box<SourceReceipt>,
        authorized_scope_ceiling: AtomScope,
    ) -> Self {
        Self {
            observation,
            receipt,
            authorized_scope_ceiling,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AtomMaterialization {
    pub draft: AtomDraft,
    pub authority_basis: AtomAuthorityBasis,
    pub accepted_proposal_id: Option<RevisionProposalId>,
    pub accepted_proposal_revision_id: Option<RevisionId>,
    pub created_at_us: i64,
}

pub fn materialize_atom(
    input: AtomMaterialization,
    current: Option<&Atom>,
) -> Result<Atom, SemanticServiceError> {
    let AtomMaterialization {
        mut draft,
        authority_basis,
        accepted_proposal_id,
        accepted_proposal_revision_id,
        created_at_us,
    } = input;
    draft
        .validate_unprivileged()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    let (authority, user_authorization_provenance, policy_authority_provenance) =
        authority_fields(&draft, &authority_basis)?;
    if let AtomAuthorityBasis::TuiAcceptance(binding) = &authority_basis {
        draft
            .source_observation_refs
            .push(binding.observation.source_observation_id);
        draft.source_observation_refs.sort();
        draft.source_observation_refs.dedup();
    }
    let atom = Atom {
        atom_id: current.map_or_else(evertrace_domain::ids::AtomId::new_v7, |value| value.atom_id),
        revision_id: RevisionId::new_v7(),
        parent_revision_id: current.map(|value| value.revision_id),
        kind: draft.kind,
        epistemic_status: draft.epistemic_status,
        lifecycle_status: AtomLifecycleStatus::Active,
        authority,
        value: draft.value,
        scope: draft.scope,
        condition_ir_version: 1,
        applicability_expr: draft.applicability_expr,
        future_cue_lifecycle_exprs: draft.future_cue_lifecycle_exprs,
        validity_interval: draft.validity_interval,
        provenance: draft.provenance,
        user_authorization_provenance,
        policy_authority_provenance,
        source_observation_refs: draft.source_observation_refs,
        evidence_refs: draft.evidence_refs,
        supersedes_revision_refs: draft.supersedes_revision_refs,
        supports_revision_refs: draft.supports_revision_refs,
        contradicts_revision_refs: draft.contradicts_revision_refs,
        accepted_proposal_id,
        accepted_proposal_revision_id,
        created_at_us,
    };
    if let Some(current) = current {
        current
            .validate_successor(&atom)
            .map_err(|_| SemanticServiceError::ImmutableConflict)?;
    } else {
        atom.validate()
            .map_err(|_| SemanticServiceError::InvalidInput)?;
    }
    Ok(atom)
}

fn authority_fields(
    draft: &AtomDraft,
    basis: &AtomAuthorityBasis,
) -> Result<
    (
        AtomAuthority,
        Option<UserAuthorizationProvenance>,
        Option<PolicyAuthorityProvenance>,
    ),
    SemanticServiceError,
> {
    match basis {
        AtomAuthorityBasis::CurrentTaskExactMessage {
            observation,
            receipt,
            canonical_message,
        } => {
            require_user_source(observation, receipt)?;
            let task_id = receipt.task_id.ok_or(SemanticServiceError::InvalidInput)?;
            if draft.value.text != *canonical_message
                || draft.value.subject != "current_task"
                || draft.value.predicate != "must_follow_user_message"
                || draft.value.object.is_some()
                || !draft.value.qualifiers.is_empty()
                || !draft.value.critical_revision_refs.is_empty()
                || draft.kind != AtomKind::Constraint
                || draft.scope != (AtomScope::Task { task_id })
                || draft.epistemic_status != EpistemicStatus::NotApplicable
                || !matches!(draft.applicability_expr, ApplicabilityExpr::Always)
                || draft.validity_interval.valid_until_us.is_none()
                || draft.provenance.as_slice() != [AtomProvenance::UserAsserted]
                || !draft.supersedes_revision_refs.is_empty()
                || !draft.supports_revision_refs.is_empty()
                || !draft.contradicts_revision_refs.is_empty()
                || draft.source_observation_refs.as_slice() != [observation.source_observation_id]
                || hex(&payload_fingerprint(
                    observation.canonicalization_revision,
                    canonical_message.as_bytes(),
                    None,
                )
                .map_err(|_| SemanticServiceError::InvalidInput)?)
                    != observation.payload_fingerprint
            {
                return Err(SemanticServiceError::InvalidInput);
            }
            let source_message_hash = parse_digest(&observation.payload_fingerprint)?;
            let exact_value_hash = draft
                .value
                .exact_hash()
                .map_err(|_| SemanticServiceError::InvalidInput)?;
            Ok((
                AtomAuthority::UserExplicit,
                Some(UserAuthorizationProvenance {
                    mode: UserAuthorizationMode::CurrentTaskExactMessage,
                    user_source_observation_ref: observation.source_observation_id,
                    source_message_hash,
                    exact_value_hash,
                    authorized_scope_ceiling: AtomScope::Task { task_id },
                    acceptance_event_ref: None,
                }),
                None,
            ))
        }
        AtomAuthorityBasis::UserStatement {
            observation,
            receipt,
        } => {
            require_user_source(observation, receipt)?;
            if !draft.kind.is_descriptive()
                || draft.epistemic_status != EpistemicStatus::Unverified
                || !draft
                    .source_observation_refs
                    .contains(&observation.source_observation_id)
                || hex(&payload_fingerprint(
                    observation.canonicalization_revision,
                    draft.value.text.as_bytes(),
                    None,
                )
                .map_err(|_| SemanticServiceError::InvalidInput)?)
                    != observation.payload_fingerprint
            {
                return Err(SemanticServiceError::InvalidInput);
            }
            Ok((
                AtomAuthority::UserExplicit,
                Some(UserAuthorizationProvenance {
                    mode: UserAuthorizationMode::UserStatement,
                    user_source_observation_ref: observation.source_observation_id,
                    source_message_hash: parse_digest(&observation.payload_fingerprint)?,
                    exact_value_hash: draft
                        .value
                        .exact_hash()
                        .map_err(|_| SemanticServiceError::InvalidInput)?,
                    authorized_scope_ceiling: draft.scope.clone(),
                    acceptance_event_ref: None,
                }),
                None,
            ))
        }
        AtomAuthorityBasis::TuiAcceptance(binding) => {
            let observation = &binding.observation;
            let receipt = &binding.receipt;
            let authorized_scope_ceiling = &binding.authorized_scope_ceiling;
            require_user_source(observation, receipt)?;
            if !authorized_scope_ceiling.contains(&draft.scope) {
                return Err(SemanticServiceError::InvalidInput);
            }
            match &draft.scope {
                AtomScope::Task { task_id } if receipt.task_id == Some(*task_id) => {}
                AtomScope::Repository {
                    repository_instance_id,
                } if receipt.repository_instance_id == Some(*repository_instance_id) => {}
                _ => return Err(SemanticServiceError::InvalidInput),
            }
            Ok((
                AtomAuthority::UserExplicit,
                Some(UserAuthorizationProvenance {
                    mode: UserAuthorizationMode::TuiAcceptance,
                    user_source_observation_ref: observation.source_observation_id,
                    source_message_hash: parse_digest(&observation.payload_fingerprint)?,
                    exact_value_hash: draft
                        .value
                        .exact_hash()
                        .map_err(|_| SemanticServiceError::InvalidInput)?,
                    authorized_scope_ceiling: authorized_scope_ceiling.clone(),
                    acceptance_event_ref: Some(observation.source_observation_id.to_string()),
                }),
                None,
            ))
        }
        AtomAuthorityBasis::ProjectPolicy {
            binding,
            observation,
            receipt,
        } => {
            if !binding.authorizes_materialization(
                &draft.scope,
                observation,
                receipt,
                &draft.source_observation_refs,
                &draft.evidence_refs,
            ) {
                return Err(SemanticServiceError::InvalidInput);
            }
            Ok((
                AtomAuthority::ProjectPolicy,
                None,
                Some(
                    binding
                        .provenance()
                        .ok_or(SemanticServiceError::InvalidInput)?,
                ),
            ))
        }
        AtomAuthorityBasis::ObjectiveEvidence => Ok((AtomAuthority::ObjectiveEvidence, None, None)),
        AtomAuthorityBasis::AgentInferred => Ok((AtomAuthority::AgentInferred, None, None)),
        AtomAuthorityBasis::ImportedClaim => Ok((AtomAuthority::ImportedClaim, None, None)),
    }
}

pub(super) fn require_user_source(
    observation: &SourceObservation,
    receipt: &SourceReceipt,
) -> Result<(), SemanticServiceError> {
    observation
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    receipt
        .validate()
        .map_err(|_| SemanticServiceError::InvalidInput)?;
    if observation.source_observation_id != receipt.source_observation_id
        || observation.source_receipt_ref != receipt.source_receipt_id
        || observation.source_instance_id != receipt.source_instance_id
        || observation.source_revision != receipt.source_revision
        || observation.source_record_identity != receipt.source_record_identity
        || observation.source_role != SourceRole::User
        || observation.content_trust != ContentTrust::UserStatement
        || observation.observation_role != ObservationRole::Message
        || receipt.observation_role != ObservationRole::Message
        || observation.capture_completeness != CaptureCompleteness::Complete
        || receipt.capture_completeness != CaptureCompleteness::Complete
        || observation.adapter_revision != receipt.adapter_revision
        || observation.canonicalization_revision != receipt.canonicalization_revision
        || observation.correlation.adapter_manifest_ref != receipt.adapter_manifest_ref
    {
        return Err(SemanticServiceError::InvalidInput);
    }
    Ok(())
}

fn parse_digest(value: &str) -> Result<[u8; 32], SemanticServiceError> {
    if value.len() != 64 {
        return Err(SemanticServiceError::InvalidInput);
    }
    let mut digest = [0; 32];
    for (index, slot) in digest.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| SemanticServiceError::InvalidInput)?;
    }
    Ok(digest)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SparseNoDeltaReason {
    OrdinaryToolEvent,
    IntermediateState,
    UnadoptedOption,
    UnusedGuess,
    RecoverableFromCode,
    MissingEvidence,
    MissingScope,
    NoCrossEpisodeValue,
    ExactEquivalent,
}

#[derive(Clone, Debug)]
pub enum SparseAtomSignal {
    ExactCurrentUserConstraint(AtomMaterialization),
    AdoptedDecision(AtomMaterialization),
    MaterialObjectiveFailure(AtomMaterialization),
    AcceptanceAlignedOutcome(AtomMaterialization),
    FormalResearchObject(AtomMaterialization),
    OrdinaryToolEvent,
    IntermediatePlan,
    TemporaryTodo,
    UnadoptedOption,
    UnusedGuess,
    RecoverableFromCode,
    MissingEvidence,
    MissingScope,
    NoCrossEpisodeValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AtomEmissionDecision {
    NothingToSave(SparseNoDeltaReason),
    Atom(Box<Atom>),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AtomEmissionGate;

impl AtomEmissionGate {
    pub fn evaluate(
        &self,
        signal: SparseAtomSignal,
        existing: &[Atom],
    ) -> Result<AtomEmissionDecision, SemanticServiceError> {
        let materialization = match signal {
            SparseAtomSignal::ExactCurrentUserConstraint(value) => {
                if value.draft.kind != AtomKind::Constraint
                    || !matches!(
                        &value.authority_basis,
                        AtomAuthorityBasis::CurrentTaskExactMessage { .. }
                    )
                {
                    return Err(SemanticServiceError::InvalidInput);
                }
                value
            }
            SparseAtomSignal::AdoptedDecision(value) => {
                if value.draft.kind != AtomKind::Decision
                    || !matches!(
                        &value.authority_basis,
                        AtomAuthorityBasis::AgentInferred
                            | AtomAuthorityBasis::CurrentTaskExactMessage { .. }
                            | AtomAuthorityBasis::TuiAcceptance(_)
                            | AtomAuthorityBasis::ProjectPolicy { .. }
                    )
                {
                    return Err(SemanticServiceError::InvalidInput);
                }
                value
            }
            SparseAtomSignal::MaterialObjectiveFailure(value) => {
                if value.draft.kind != AtomKind::Failure
                    || value.draft.epistemic_status != EpistemicStatus::Supported
                    || !matches!(
                        &value.authority_basis,
                        AtomAuthorityBasis::ObjectiveEvidence
                    )
                {
                    return Err(SemanticServiceError::InvalidInput);
                }
                value
            }
            SparseAtomSignal::AcceptanceAlignedOutcome(value) => {
                if !matches!(value.draft.kind, AtomKind::Outcome | AtomKind::Result)
                    || value.draft.epistemic_status != EpistemicStatus::Supported
                    || !matches!(
                        &value.authority_basis,
                        AtomAuthorityBasis::ObjectiveEvidence
                    )
                {
                    return Err(SemanticServiceError::InvalidInput);
                }
                value
            }
            SparseAtomSignal::FormalResearchObject(value) => {
                let valid = match value.draft.kind {
                    AtomKind::Hypothesis => {
                        value.draft.epistemic_status == EpistemicStatus::Unverified
                            && matches!(&value.authority_basis, AtomAuthorityBasis::AgentInferred)
                    }
                    AtomKind::Claim | AtomKind::Citation => {
                        value.draft.epistemic_status == EpistemicStatus::Supported
                            && matches!(
                                &value.authority_basis,
                                AtomAuthorityBasis::ObjectiveEvidence
                            )
                    }
                    _ => false,
                };
                if !valid {
                    return Err(SemanticServiceError::InvalidInput);
                }
                value
            }
            SparseAtomSignal::OrdinaryToolEvent => {
                return Ok(AtomEmissionDecision::NothingToSave(
                    SparseNoDeltaReason::OrdinaryToolEvent,
                ));
            }
            SparseAtomSignal::IntermediatePlan | SparseAtomSignal::TemporaryTodo => {
                return Ok(AtomEmissionDecision::NothingToSave(
                    SparseNoDeltaReason::IntermediateState,
                ));
            }
            SparseAtomSignal::UnadoptedOption => {
                return Ok(AtomEmissionDecision::NothingToSave(
                    SparseNoDeltaReason::UnadoptedOption,
                ));
            }
            SparseAtomSignal::UnusedGuess => {
                return Ok(AtomEmissionDecision::NothingToSave(
                    SparseNoDeltaReason::UnusedGuess,
                ));
            }
            SparseAtomSignal::RecoverableFromCode => {
                return Ok(AtomEmissionDecision::NothingToSave(
                    SparseNoDeltaReason::RecoverableFromCode,
                ));
            }
            SparseAtomSignal::MissingEvidence => {
                return Ok(AtomEmissionDecision::NothingToSave(
                    SparseNoDeltaReason::MissingEvidence,
                ));
            }
            SparseAtomSignal::MissingScope => {
                return Ok(AtomEmissionDecision::NothingToSave(
                    SparseNoDeltaReason::MissingScope,
                ));
            }
            SparseAtomSignal::NoCrossEpisodeValue => {
                return Ok(AtomEmissionDecision::NothingToSave(
                    SparseNoDeltaReason::NoCrossEpisodeValue,
                ));
            }
        };
        if matches!(materialization.draft.scope, AtomScope::Global) {
            return Err(SemanticServiceError::InvalidInput);
        }
        let atom = materialize_atom(materialization, None)?;
        if existing.iter().any(|value| {
            value.lifecycle_status == AtomLifecycleStatus::Active
                && value.same_semantic_state(&atom)
        }) {
            return Ok(AtomEmissionDecision::NothingToSave(
                SparseNoDeltaReason::ExactEquivalent,
            ));
        }
        Ok(AtomEmissionDecision::Atom(Box::new(atom)))
    }
}

pub fn exact_task_constraint_draft(
    canonical_message: String,
    task_id: evertrace_domain::ids::TaskId,
    observation_id: evertrace_domain::ids::SourceObservationId,
    receipt_id: evertrace_domain::ids::SourceReceiptId,
    valid_from_us: i64,
    valid_until_us: i64,
) -> AtomDraft {
    AtomDraft {
        kind: AtomKind::Constraint,
        epistemic_status: EpistemicStatus::NotApplicable,
        value: AtomValue {
            text: canonical_message,
            subject: "current_task".into(),
            predicate: "must_follow_user_message".into(),
            object: None,
            qualifiers: Vec::new(),
            critical_revision_refs: Vec::new(),
        },
        scope: AtomScope::Task { task_id },
        applicability_expr: ApplicabilityExpr::Always,
        future_cue_lifecycle_exprs: None,
        validity_interval: ValidityInterval {
            valid_from_us,
            valid_until_us: Some(valid_until_us),
        },
        provenance: vec![AtomProvenance::UserAsserted],
        source_observation_refs: vec![observation_id],
        evidence_refs: vec![receipt_id.to_string()],
        supersedes_revision_refs: Vec::new(),
        supports_revision_refs: Vec::new(),
        contradicts_revision_refs: Vec::new(),
    }
}
