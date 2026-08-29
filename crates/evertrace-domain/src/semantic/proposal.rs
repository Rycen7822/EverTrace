use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalValue, sha256},
    evidence::hex,
    ids::{AtomId, CoreMembershipId, ProcedureId, RevisionProposalId},
    revision::RevisionId,
};

use super::{AtomDraft, AtomScope, CoreScopeIdentity, SemanticError, valid_identifier};

const MAX_REFS: usize = 256;
const MAX_SPLIT_OUTPUTS: usize = 16;
const MAX_REVIEW_TEXT: usize = 2048;

pub const TUI_ACCEPTANCE_EVENT_MANIFEST_REF: &str = "evertrace_tui_acceptance_v1";

pub fn tui_acceptance_event_payload(
    proposal_id: RevisionProposalId,
    reviewed_proposal_revision_id: RevisionId,
    reviewed_fingerprint: &[u8; 32],
) -> String {
    format!(
        "{TUI_ACCEPTANCE_EVENT_MANIFEST_REF}|accept|{proposal_id}|{reviewed_proposal_revision_id}|{}",
        hex(reviewed_fingerprint)
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalTargetKind {
    Procedure,
    Atom,
    CoreMembership,
}

impl ProposalTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Procedure => "procedure",
            Self::Atom => "atom",
            Self::CoreMembership => "core_membership",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProposalTargetId {
    Procedure(ProcedureId),
    Atom(AtomId),
    CoreMembership(CoreMembershipId),
}

impl ProposalTargetId {
    const fn kind(self) -> ProposalTargetKind {
        match self {
            Self::Procedure(_) => ProposalTargetKind::Procedure,
            Self::Atom(_) => ProposalTargetKind::Atom,
            Self::CoreMembership(_) => ProposalTargetKind::CoreMembership,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalOperation {
    Create,
    Replace,
    Merge,
    Split,
    Deprecate,
    Reclassify,
}

impl ProposalOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Replace => "replace",
            Self::Merge => "merge",
            Self::Split => "split",
            Self::Deprecate => "deprecate",
            Self::Reclassify => "reclassify",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum AtomProposalPayload {
    Create {
        draft: AtomDraft,
    },
    Replace {
        draft: AtomDraft,
    },
    Merge {
        draft: AtomDraft,
        merged_revision_refs: Vec<RevisionId>,
    },
    Split {
        drafts: Vec<AtomDraft>,
    },
    Deprecate {
        reason: String,
    },
    Reclassify {
        draft: AtomDraft,
    },
}

impl AtomProposalPayload {
    pub const fn operation(&self) -> ProposalOperation {
        match self {
            Self::Create { .. } => ProposalOperation::Create,
            Self::Replace { .. } => ProposalOperation::Replace,
            Self::Merge { .. } => ProposalOperation::Merge,
            Self::Split { .. } => ProposalOperation::Split,
            Self::Deprecate { .. } => ProposalOperation::Deprecate,
            Self::Reclassify { .. } => ProposalOperation::Reclassify,
        }
    }

    pub fn validate(&self) -> Result<(), SemanticError> {
        match self {
            Self::Create { draft } | Self::Replace { draft } | Self::Reclassify { draft } => {
                draft.validate_unprivileged()
            }
            Self::Merge {
                draft,
                merged_revision_refs,
            } => {
                draft.validate_unprivileged()?;
                if merged_revision_refs.len() < 2
                    || merged_revision_refs.len() > MAX_REFS
                    || !strictly_sorted(merged_revision_refs)
                {
                    return Err(SemanticError::InvalidProposal);
                }
                Ok(())
            }
            Self::Split { drafts } => {
                if !(2..=MAX_SPLIT_OUTPUTS).contains(&drafts.len()) {
                    return Err(SemanticError::InvalidProposal);
                }
                for draft in drafts {
                    draft.validate_unprivileged()?;
                }
                Ok(())
            }
            Self::Deprecate { reason } => {
                if valid_review_text(reason) {
                    Ok(())
                } else {
                    Err(SemanticError::InvalidProposal)
                }
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProposalPayload {
    Atom(Box<AtomProposalPayload>),
    CoreMembership(Box<CoreMembershipProposalPayload>),
    ReservedTarget {
        schema_version: u32,
        summary: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoreMembershipProposalPayload {
    Create {
        atom_revision_id: RevisionId,
        scope_identity: CoreScopeIdentity,
    },
    ResolveConflict {
        left_atom_revision_id: RevisionId,
        right_atom_revision_id: RevisionId,
        scope_identity: CoreScopeIdentity,
    },
}

impl ProposalPayload {
    fn validate(&self, target_kind: ProposalTargetKind) -> Result<(), SemanticError> {
        match (target_kind, self) {
            (ProposalTargetKind::Atom, Self::Atom(payload)) => payload.validate(),
            (ProposalTargetKind::CoreMembership, Self::CoreMembership(payload)) => {
                if matches!(payload.as_ref(), CoreMembershipProposalPayload::ResolveConflict { left_atom_revision_id, right_atom_revision_id, .. } if left_atom_revision_id == right_atom_revision_id)
                {
                    Err(SemanticError::InvalidProposal)
                } else {
                    Ok(())
                }
            }
            (
                ProposalTargetKind::Procedure | ProposalTargetKind::CoreMembership,
                Self::ReservedTarget {
                    schema_version: 1,
                    summary,
                },
            ) if valid_review_text(summary) => Ok(()),
            _ => Err(SemanticError::InvalidProposal),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalEligibility {
    ManualRequired,
    AutoEligible,
    AutoEligibleFull,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Pending,
    Validating,
    Accepted,
    Rejected,
    Deferred,
    Superseded,
}

impl ProposalStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Validating => "validating",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Deferred => "deferred",
            Self::Superseded => "superseded",
        }
    }

    pub const fn is_open(self) -> bool {
        matches!(self, Self::Pending | Self::Validating)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::Rejected | Self::Deferred | Self::Superseded
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalWaitingOn {
    NewEvidence,
    TargetRevisionChange,
    ObjectiveVerifier,
    ConflictResolution,
    ManualReview,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalCreatedBy {
    System,
    User,
    Agent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProposalAcceptanceAuthority {
    CurrentTaskExactMessage {
        user_source_observation_ref: crate::ids::SourceObservationId,
    },
    TuiAcceptance {
        user_source_observation_ref: crate::ids::SourceObservationId,
        authorized_scope_ceiling: AtomScope,
    },
    ObjectiveEvidence {
        user_source_observation_ref: crate::ids::SourceObservationId,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalAcceptance {
    pub reviewer_identity: String,
    pub acceptance_event_ref: String,
    pub reviewed_proposal_revision_id: RevisionId,
    pub reviewed_fingerprint: [u8; 32],
    pub accepted_target: AcceptedProposalTarget,
    pub authority_basis: ProposalAcceptanceAuthority,
    pub accepted_at_us: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AcceptedProposalTarget {
    Atom {
        atom_id: AtomId,
        atom_revision_id: RevisionId,
        structure_hash: [u8; 32],
    },
    CoreMembership {
        core_membership_id: CoreMembershipId,
        membership_revision_id: RevisionId,
    },
}

impl ProposalAcceptance {
    pub const fn accepted_atom(&self) -> Option<(AtomId, RevisionId, [u8; 32])> {
        match self.accepted_target {
            AcceptedProposalTarget::Atom {
                atom_id,
                atom_revision_id,
                structure_hash,
            } => Some((atom_id, atom_revision_id, structure_hash)),
            AcceptedProposalTarget::CoreMembership { .. } => None,
        }
    }
}

impl ProposalAcceptance {
    fn validate(&self) -> Result<(), SemanticError> {
        if !valid_identifier(&self.reviewer_identity)
            || !valid_identifier(&self.acceptance_event_ref)
            || self.accepted_at_us < 0
        {
            return Err(SemanticError::InvalidProposal);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionProposal {
    pub proposal_id: RevisionProposalId,
    pub proposal_revision_id: RevisionId,
    pub parent_proposal_revision_id: Option<RevisionId>,
    pub target_kind: ProposalTargetKind,
    pub target_id: Option<ProposalTargetId>,
    pub base_revision_id: Option<RevisionId>,
    pub operation: ProposalOperation,
    pub payload: ProposalPayload,
    pub evidence_refs: Vec<String>,
    pub source_cohort_refs: Vec<String>,
    pub source_cohort_hash: [u8; 32],
    pub fingerprint: [u8; 32],
    pub eligibility: ProposalEligibility,
    pub status: ProposalStatus,
    pub waiting_on: Vec<ProposalWaitingOn>,
    pub review_reason: Option<String>,
    pub created_by: ProposalCreatedBy,
    pub acceptance: Option<ProposalAcceptance>,
    pub created_at_us: i64,
    pub reviewed_at_us: Option<i64>,
}

impl RevisionProposal {
    pub fn validate(&self) -> Result<(), SemanticError> {
        self.payload.validate(self.target_kind)?;
        if self.created_at_us < 0
            || self
                .reviewed_at_us
                .is_some_and(|reviewed| reviewed < self.created_at_us)
            || self.evidence_refs.is_empty()
            || self.evidence_refs.len() > MAX_REFS
            || !strictly_sorted(&self.evidence_refs)
            || self.source_cohort_refs.is_empty()
            || self.source_cohort_refs.len() > MAX_REFS
            || !strictly_sorted(&self.source_cohort_refs)
            || self
                .evidence_refs
                .iter()
                .chain(&self.source_cohort_refs)
                .any(|value| !valid_identifier(value))
            || self.waiting_on.len() > MAX_REFS
            || !strictly_sorted(&self.waiting_on)
            || self
                .review_reason
                .as_deref()
                .is_some_and(|value| !valid_review_text(value))
            || self
                .target_id
                .is_some_and(|target| target.kind() != self.target_kind)
            || self.source_cohort_hash != self.recompute_source_cohort_hash()?
            || self.fingerprint != self.recompute_fingerprint()?
            || self.parent_proposal_revision_id.is_none() && self.status != ProposalStatus::Pending
        {
            return Err(SemanticError::InvalidProposal);
        }
        self.validate_shape()?;
        self.validate_status()?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), SemanticError> {
        match (&self.payload, self.operation) {
            (ProposalPayload::Atom(payload), operation) if payload.operation() == operation => {}
            (ProposalPayload::CoreMembership(_), ProposalOperation::Create) => {}
            (ProposalPayload::ReservedTarget { .. }, _) => {}
            _ => return Err(SemanticError::InvalidProposal),
        }
        match self.operation {
            ProposalOperation::Create => {
                if self.target_id.is_some() || self.base_revision_id.is_some() {
                    return Err(SemanticError::InvalidProposal);
                }
            }
            ProposalOperation::Replace
            | ProposalOperation::Merge
            | ProposalOperation::Split
            | ProposalOperation::Deprecate
            | ProposalOperation::Reclassify => {
                if self.target_id.is_none() || self.base_revision_id.is_none() {
                    return Err(SemanticError::InvalidProposal);
                }
            }
        }
        Ok(())
    }

    fn validate_status(&self) -> Result<(), SemanticError> {
        if self.status == ProposalStatus::Deferred {
            if self.waiting_on.is_empty() || self.reviewed_at_us.is_none() {
                return Err(SemanticError::InvalidProposal);
            }
        } else if !self.waiting_on.is_empty() {
            return Err(SemanticError::InvalidProposal);
        }
        if self.status.is_terminal() && self.reviewed_at_us.is_none()
            || !self.status.is_terminal() && self.reviewed_at_us.is_some()
            || self.status == ProposalStatus::Accepted && self.acceptance.is_none()
            || self.status != ProposalStatus::Accepted && self.acceptance.is_some()
        {
            return Err(SemanticError::InvalidProposal);
        }
        if let Some(acceptance) = &self.acceptance {
            if matches!(
                self.payload,
                ProposalPayload::CoreMembership(ref payload)
                    if matches!(payload.as_ref(), CoreMembershipProposalPayload::ResolveConflict { .. })
            ) {
                return Err(SemanticError::InvalidProposal);
            }
            acceptance.validate()?;
            let target_matches = matches!(
                (self.target_kind, &acceptance.accepted_target),
                (
                    ProposalTargetKind::Atom,
                    AcceptedProposalTarget::Atom { .. }
                ) | (
                    ProposalTargetKind::CoreMembership,
                    AcceptedProposalTarget::CoreMembership { .. }
                )
            );
            if !target_matches
                || acceptance.reviewed_fingerprint != self.fingerprint
                || acceptance.reviewed_proposal_revision_id == self.proposal_revision_id
            {
                return Err(SemanticError::InvalidProposal);
            }
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), SemanticError> {
        next.validate()?;
        if self.proposal_id != next.proposal_id
            || next.parent_proposal_revision_id != Some(self.proposal_revision_id)
            || self.target_kind != next.target_kind
            || self.target_id != next.target_id
            || next.created_at_us < self.created_at_us
        {
            return Err(SemanticError::InvalidProposalSuccessor);
        }
        if matches!(
            self.status,
            ProposalStatus::Accepted | ProposalStatus::Rejected | ProposalStatus::Superseded
        ) {
            return Err(SemanticError::InvalidProposalSuccessor);
        }
        if self.status == ProposalStatus::Deferred {
            let condition_changed = self.waiting_on != next.waiting_on
                && (self.base_revision_id != next.base_revision_id
                    || self.source_cohort_hash != next.source_cohort_hash
                    || is_strict_superset(&next.evidence_refs, &self.evidence_refs));
            if !condition_changed
                || !matches!(
                    next.status,
                    ProposalStatus::Pending | ProposalStatus::Validating
                )
                || self.operation != next.operation
                || self.payload != next.payload
                || self.eligibility != next.eligibility
                || self.created_by != next.created_by
                || !contains_all(&next.evidence_refs, &self.evidence_refs)
            {
                return Err(SemanticError::InvalidProposalSuccessor);
            }
        } else {
            if self.base_revision_id != next.base_revision_id
                || self.operation != next.operation
                || self.payload != next.payload
                || self.source_cohort_refs != next.source_cohort_refs
                || self.source_cohort_hash != next.source_cohort_hash
                || self.fingerprint != next.fingerprint
                || self.created_by != next.created_by
                || !contains_all(&next.evidence_refs, &self.evidence_refs)
            {
                return Err(SemanticError::InvalidProposalSuccessor);
            }
            let valid_status = match self.status {
                ProposalStatus::Pending => matches!(
                    next.status,
                    ProposalStatus::Pending
                        | ProposalStatus::Validating
                        | ProposalStatus::Rejected
                        | ProposalStatus::Deferred
                        | ProposalStatus::Superseded
                ),
                ProposalStatus::Validating => matches!(
                    next.status,
                    ProposalStatus::Validating
                        | ProposalStatus::Accepted
                        | ProposalStatus::Rejected
                        | ProposalStatus::Deferred
                        | ProposalStatus::Superseded
                ),
                _ => false,
            };
            if !valid_status
                || self.status == next.status
                    && self.eligibility == next.eligibility
                    && !is_strict_superset(&next.evidence_refs, &self.evidence_refs)
            {
                return Err(SemanticError::InvalidProposalSuccessor);
            }
        }
        Ok(())
    }

    pub fn recompute_source_cohort_hash(&self) -> Result<[u8; 32], SemanticError> {
        sha256(
            "revision_proposal_source_cohort_v1",
            1,
            &CanonicalValue::Sequence(
                self.source_cohort_refs
                    .iter()
                    .cloned()
                    .map(CanonicalValue::String)
                    .collect(),
            ),
        )
        .map_err(|_| SemanticError::InvalidProposal)
    }

    pub fn recompute_fingerprint(&self) -> Result<[u8; 32], SemanticError> {
        let serialized =
            toml::to_string(&self.payload).map_err(|_| SemanticError::InvalidProposal)?;
        sha256(
            "revision_proposal_fingerprint_v1",
            1,
            &CanonicalValue::Map(vec![
                (
                    "target_kind".into(),
                    CanonicalValue::String(self.target_kind.as_str().into()),
                ),
                (
                    "target_id".into(),
                    self.target_id.map_or(CanonicalValue::Null, |value| {
                        CanonicalValue::String(match value {
                            ProposalTargetId::Procedure(id) => id.to_string(),
                            ProposalTargetId::Atom(id) => id.to_string(),
                            ProposalTargetId::CoreMembership(id) => id.to_string(),
                        })
                    }),
                ),
                (
                    "base_revision_id".into(),
                    self.base_revision_id.map_or(CanonicalValue::Null, |value| {
                        CanonicalValue::String(value.to_string())
                    }),
                ),
                (
                    "operation".into(),
                    CanonicalValue::String(self.operation.as_str().into()),
                ),
                ("payload".into(), CanonicalValue::String(serialized)),
                (
                    "source_cohort_hash".into(),
                    CanonicalValue::Bytes(self.source_cohort_hash.to_vec()),
                ),
            ]),
        )
        .map_err(|_| SemanticError::InvalidProposal)
    }

    pub fn suppression_key(&self) -> ([u8; 32], [u8; 32], Option<RevisionId>) {
        (
            self.fingerprint,
            self.source_cohort_hash,
            self.base_revision_id,
        )
    }
}

fn valid_review_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_REVIEW_TEXT && !value.contains('\0')
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn contains_all<T: Eq>(values: &[T], required: &[T]) -> bool {
    required.iter().all(|value| values.contains(value))
}

fn is_strict_superset<T: Eq>(values: &[T], required: &[T]) -> bool {
    values.len() > required.len() && contains_all(values, required)
}
