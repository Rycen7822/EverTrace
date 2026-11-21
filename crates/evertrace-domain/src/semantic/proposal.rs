use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalValue, sha256},
    evidence::{
        CaptureCompleteness, ContentTrust, EvidenceSourceKind, IdentityStrength, ObservationRole,
        SourceArchiveMode, SourceObservation, SourceReceipt, SourceRole, hex, payload_fingerprint,
    },
    ids::{
        AtomId, CoreMembershipId, ProcedureId, RepositoryId, RevisionProposalId,
        SourceObservationId, TaskId,
    },
    inventory::{CapabilityCoverageOmission, CapabilityCoverageSummary, CapabilityEvidenceLevel},
    procedure::{ProcedureAutoFullAudit, ProcedureDone, ProcedureDraft, ProcedureScope},
    purge::{ObjectDeletionTarget, ObjectReauthorizationRef},
    revision::RevisionId,
};

use super::{
    ApplicabilityExpr, Atom, AtomDraft, AtomKind, AtomLifecycleStatus, AtomProvenance, AtomScope,
    AtomValue, CoreScopeIdentity, EpistemicStatus, SemanticError, ValidityInterval,
    valid_identifier,
};

const MAX_REFS: usize = 256;
const MAX_SPLIT_OUTPUTS: usize = 16;
const MAX_REVIEW_TEXT: usize = 2048;

pub const TUI_ACCEPTANCE_EVENT_MANIFEST_REF: &str = "evertrace_tui_acceptance_v1";
pub const WEB_ACCEPTANCE_EVENT_MANIFEST_REF: &str = "evertrace_web_acceptance_v1";
pub const HUMAN_CORRECTION_MANIFEST: &str = "evertrace_human_atom_correction_v1";
pub const HUMAN_CREATION_MANIFEST: &str = "evertrace_human_atom_creation_v1";

pub fn is_human_authoring_manifest(manifest: &str) -> bool {
    matches!(
        manifest,
        HUMAN_CORRECTION_MANIFEST | HUMAN_CREATION_MANIFEST
    )
}
const PROPOSAL_EDIT_INTENT_SCHEMA_VERSION: u32 = 1;

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

pub fn proposal_review_digest<Review: Serialize, Base: Serialize>(
    frontier: u64,
    review: Review,
    base: Base,
) -> Option<[u8; 32]> {
    let body = serde_json::to_vec(&(frontier, review, base)).ok()?;
    sha256(
        "evertrace.proposal_review_confirmation",
        1,
        &CanonicalValue::Bytes(body),
    )
    .ok()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebAcceptanceIntent {
    pub reviewed_frontier: u64,
    pub review_digest: [u8; 32],
    /// The Native-reviewed observation is not an automatic eligibility certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure_coverage: Option<Box<WebProcedureCoverage>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atom_edit: Option<Box<WebAtomEdit>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure_edit: Option<Box<WebProcedureEdit>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reauthorization: Option<Box<ObjectReauthorizationRef>>,
}

/// Content-only edit; identity, authority, conditions and provenance stay with the reviewed proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebAtomEdit {
    pub text: String,
    pub subject: String,
    pub predicate: String,
    pub object: Option<String>,
}

impl WebAtomEdit {
    fn apply(&self, value: &mut AtomValue) {
        value.text.clone_from(&self.text);
        value.subject.clone_from(&self.subject);
        value.predicate.clone_from(&self.predicate);
        value.object.clone_from(&self.object);
    }

    fn from_value(value: &AtomValue) -> Self {
        Self {
            text: value.text.clone(),
            subject: value.subject.clone(),
            predicate: value.predicate.clone(),
            object: value.object.clone(),
        }
    }

    fn draft(proposal: &RevisionProposal) -> Option<&AtomDraft> {
        if !proposal.status.is_open()
            || proposal.eligibility == ProposalEligibility::AutoEligibleFull
        {
            return None;
        }
        let ProposalPayload::Atom(payload) = &proposal.payload else {
            return None;
        };
        let draft = match (proposal.operation, payload.as_ref()) {
            (ProposalOperation::Create, AtomProposalPayload::Create { draft })
            | (ProposalOperation::Replace, AtomProposalPayload::Replace { draft })
            | (ProposalOperation::Reclassify, AtomProposalPayload::Reclassify { draft }) => draft,
            _ => return None,
        };
        matches!(
            draft.scope,
            AtomScope::Task { .. } | AtomScope::Repository { .. }
        )
        .then_some(draft)
    }

    pub fn available(proposal: &RevisionProposal) -> bool {
        Self::draft(proposal).is_some()
    }

    pub fn edited_draft(&self, proposal: &RevisionProposal) -> Option<AtomDraft> {
        let original = Self::draft(proposal)?;
        let mut draft = original.clone();
        self.apply(&mut draft.value);
        draft.validate_unprivileged().ok()?;
        (draft != *original).then_some(draft)
    }

    pub fn payload(&self, proposal: &RevisionProposal) -> Option<ProposalPayload> {
        let draft = self.edited_draft(proposal)?;
        let atom = match proposal.operation {
            ProposalOperation::Create => AtomProposalPayload::Create { draft },
            ProposalOperation::Replace => AtomProposalPayload::Replace { draft },
            ProposalOperation::Reclassify => AtomProposalPayload::Reclassify { draft },
            _ => return None,
        };
        Some(ProposalPayload::Atom(Box::new(atom)))
    }
}

/// Editable Procedure content. Typed conditions, scope and source references are not browser input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebProcedureEdit {
    pub title: String,
    pub summary: String,
    pub stages: Vec<String>,
    pub done: ProcedureDone,
}

impl WebProcedureEdit {
    pub fn draft(proposal: &RevisionProposal) -> Option<&ProcedureDraft> {
        WebAcceptanceIntent::scope(proposal)?;
        let ProposalPayload::Procedure(payload) = &proposal.payload else {
            return None;
        };
        Some(payload.draft())
    }

    pub fn from_draft(draft: &ProcedureDraft) -> Self {
        Self {
            title: draft.title.clone(),
            summary: draft.summary.clone(),
            stages: draft.actions.stages.clone(),
            done: draft.done.clone(),
        }
    }

    pub fn edited_draft(&self, proposal: &RevisionProposal) -> Option<ProcedureDraft> {
        let original = Self::draft(proposal)?;
        // Changing the sequence independently would invalidate the meaning of typed step predicates.
        if original.stage_alignment.is_some() && self.stages != original.actions.stages {
            return None;
        }
        let mut draft = original.clone();
        draft.title.clone_from(&self.title);
        draft.summary.clone_from(&self.summary);
        draft.actions.stages.clone_from(&self.stages);
        draft.done.clone_from(&self.done);
        draft.validate().ok()?;
        (draft != *original).then_some(draft)
    }

    fn payload(&self, proposal: &RevisionProposal) -> Option<ProposalPayload> {
        let draft = self.edited_draft(proposal)?;
        let payload = match proposal.operation {
            ProposalOperation::Create => ProcedureProposalPayload::Create { draft },
            ProposalOperation::Replace => ProcedureProposalPayload::Replace { draft },
            _ => return None,
        };
        Some(ProposalPayload::Procedure(Box::new(payload)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebProposalEdit<'a> {
    Atom(&'a WebAtomEdit),
    Procedure(&'a WebProcedureEdit),
}

impl WebProposalEdit<'_> {
    pub fn payload(&self, proposal: &RevisionProposal) -> Option<ProposalPayload> {
        match self {
            Self::Atom(edit) => edit.payload(proposal),
            Self::Procedure(edit) => edit.payload(proposal),
        }
    }
}

/// A statement proposing a correction, never an acceptance or an authority grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAtomCorrection {
    pub atom_id: AtomId,
    pub base_revision_id: RevisionId,
    pub content: WebAtomEdit,
}

impl HumanAtomCorrection {
    pub fn eligible_base(base: &Atom) -> bool {
        base.lifecycle_status == AtomLifecycleStatus::Active
            && matches!(
                base.scope,
                AtomScope::Task { .. } | AtomScope::Repository { .. }
            )
    }

    pub fn replacement_value(&self, base: &Atom) -> Option<AtomValue> {
        if base.atom_id != self.atom_id
            || base.revision_id != self.base_revision_id
            || !Self::eligible_base(base)
        {
            return None;
        }
        let mut value = base.value.clone();
        self.content.apply(&mut value);
        value.validate().ok()?;
        (value != base.value).then_some(value)
    }

    pub fn draft(&self, base: &Atom, source: SourceObservationId) -> Option<AtomDraft> {
        let value = self.replacement_value(base)?;
        let mut provenance = base.provenance.clone();
        provenance.push(AtomProvenance::UserAsserted);
        provenance.sort_unstable();
        provenance.dedup();
        let mut observations = base.source_observation_refs.clone();
        observations.push(source);
        observations.sort_unstable();
        observations.dedup();
        let mut evidence = base.evidence_refs.clone();
        evidence.push(source.to_string());
        evidence.sort_unstable();
        evidence.dedup();
        let draft = AtomDraft {
            kind: base.kind,
            epistemic_status: if base.kind.is_normative() {
                EpistemicStatus::NotApplicable
            } else {
                EpistemicStatus::Unverified
            },
            value,
            scope: base.scope.clone(),
            applicability_expr: base.applicability_expr.clone(),
            future_cue_lifecycle_exprs: base.future_cue_lifecycle_exprs.clone(),
            validity_interval: base.validity_interval.clone(),
            provenance,
            source_observation_refs: observations,
            evidence_refs: evidence,
            supersedes_revision_refs: vec![base.revision_id],
            supports_revision_refs: base.supports_revision_refs.clone(),
            contradicts_revision_refs: base.contradicts_revision_refs.clone(),
        };
        draft.validate_unprivileged().ok()?;
        Some(draft)
    }

    pub fn from_pending(proposal: &RevisionProposal) -> Option<Self> {
        if proposal.status != ProposalStatus::Pending
            || proposal.operation != ProposalOperation::Replace
            || proposal.eligibility != ProposalEligibility::ManualRequired
            || proposal.created_by != ProposalCreatedBy::User
            || proposal.parent_proposal_revision_id.is_some()
        {
            return None;
        }
        let Some(ProposalTargetId::Atom(atom_id)) = proposal.target_id else {
            return None;
        };
        let ProposalPayload::Atom(payload) = &proposal.payload else {
            return None;
        };
        let AtomProposalPayload::Replace { draft } = payload.as_ref() else {
            return None;
        };
        Some(Self {
            atom_id,
            base_revision_id: proposal.base_revision_id?,
            content: WebAtomEdit::from_value(&draft.value),
        })
    }
}

/// New material can name exactly one existing Task or repository, not a guessed or global scope.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields, rename_all = "snake_case")]
pub enum HumanCreationScope {
    Task {
        task_id: TaskId,
    },
    Repository {
        repository_instance_id: RepositoryId,
    },
}

impl From<HumanCreationScope> for AtomScope {
    fn from(value: HumanCreationScope) -> Self {
        match value {
            HumanCreationScope::Task { task_id } => Self::Task { task_id },
            HumanCreationScope::Repository {
                repository_instance_id,
            } => Self::Repository {
                repository_instance_id,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanCreationKind {
    Constraint,
    Claim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAtomCreation {
    pub scope: HumanCreationScope,
    pub kind: HumanCreationKind,
    pub content: WebAtomEdit,
}

impl HumanAtomCreation {
    pub fn value(&self) -> Option<AtomValue> {
        let value = AtomValue {
            text: self.content.text.clone(),
            subject: self.content.subject.clone(),
            predicate: self.content.predicate.clone(),
            object: self.content.object.clone(),
            qualifiers: Vec::new(),
            critical_revision_refs: Vec::new(),
        };
        value.validate().ok()?;
        Some(value)
    }

    fn draft(&self, source: SourceObservationId, recorded_at_us: i64) -> Option<AtomDraft> {
        let (kind, epistemic_status) = match self.kind {
            HumanCreationKind::Constraint => (AtomKind::Constraint, EpistemicStatus::NotApplicable),
            HumanCreationKind::Claim => (AtomKind::Claim, EpistemicStatus::Unverified),
        };
        Some(AtomDraft {
            kind,
            epistemic_status,
            value: self.value()?,
            scope: self.scope.into(),
            applicability_expr: ApplicabilityExpr::Always,
            future_cue_lifecycle_exprs: None,
            validity_interval: ValidityInterval {
                valid_from_us: recorded_at_us,
                valid_until_us: None,
            },
            provenance: vec![AtomProvenance::UserAsserted],
            source_observation_refs: vec![source],
            evidence_refs: vec![source.to_string()],
            supersedes_revision_refs: Vec::new(),
            supports_revision_refs: Vec::new(),
            contradicts_revision_refs: Vec::new(),
        })
    }

    fn from_draft(draft: &AtomDraft, authored_at: i64) -> Option<Self> {
        let scope = match draft.scope {
            AtomScope::Task { task_id } => HumanCreationScope::Task { task_id },
            AtomScope::Repository {
                repository_instance_id,
            } => HumanCreationScope::Repository {
                repository_instance_id,
            },
            _ => return None,
        };
        let kind = match draft.kind {
            AtomKind::Constraint => HumanCreationKind::Constraint,
            AtomKind::Claim => HumanCreationKind::Claim,
            _ => return None,
        };
        let [source] = draft.source_observation_refs.as_slice() else {
            return None;
        };
        let intent = Self {
            scope,
            kind,
            content: WebAtomEdit::from_value(&draft.value),
        };
        (intent.draft(*source, authored_at).as_ref() == Some(draft)).then_some(intent)
    }
}

/// Both variants share one reservation/commit path. The old correction encoding stays unchanged.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum HumanAtomAuthoring {
    Correct(HumanAtomCorrection),
    Create(HumanAtomCreation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanAuthoringTarget {
    Correct(AtomId, RevisionId),
    Create(HumanCreationScope),
}

impl HumanAtomAuthoring {
    pub fn target(&self) -> HumanAuthoringTarget {
        match self {
            Self::Correct(value) => {
                HumanAuthoringTarget::Correct(value.atom_id, value.base_revision_id)
            }
            Self::Create(value) => HumanAuthoringTarget::Create(value.scope),
        }
    }

    pub fn scope(&self, base: Option<&Atom>) -> Option<AtomScope> {
        match self {
            Self::Correct(value) => base
                .filter(|base| {
                    base.atom_id == value.atom_id
                        && base.revision_id == value.base_revision_id
                        && HumanAtomCorrection::eligible_base(base)
                })
                .map(|base| base.scope.clone()),
            Self::Create(value) => Some(value.scope.into()),
        }
    }

    pub fn operation(&self) -> ProposalOperation {
        match self {
            Self::Correct(_) => ProposalOperation::Replace,
            Self::Create(_) => ProposalOperation::Create,
        }
    }

    pub fn payload(
        &self,
        base: Option<&Atom>,
        source: SourceObservationId,
        recorded_at_us: i64,
    ) -> Option<AtomProposalPayload> {
        match self {
            Self::Correct(value) => Some(AtomProposalPayload::Replace {
                draft: value.draft(base?, source)?,
            }),
            Self::Create(value) => Some(AtomProposalPayload::Create {
                draft: value.draft(source, recorded_at_us)?,
            }),
        }
    }

    pub fn from_pending(proposal: &RevisionProposal) -> Option<Self> {
        if proposal.status != ProposalStatus::Pending
            || proposal.created_by != ProposalCreatedBy::User
            || proposal.eligibility != ProposalEligibility::ManualRequired
            || proposal.parent_proposal_revision_id.is_some()
        {
            return None;
        }
        if proposal.operation == ProposalOperation::Replace {
            return HumanAtomCorrection::from_pending(proposal).map(Self::Correct);
        }
        Self::creation_for_review(proposal).map(Self::Create)
    }

    pub fn creation_scope_for_review(proposal: &RevisionProposal) -> Option<HumanCreationScope> {
        Self::creation_for_review(proposal).map(|value| value.scope)
    }

    fn creation_for_review(proposal: &RevisionProposal) -> Option<HumanAtomCreation> {
        if proposal.operation != ProposalOperation::Create
            || proposal.target_id.is_some()
            || proposal.base_revision_id.is_some()
            || proposal.created_by != ProposalCreatedBy::User
            || proposal.eligibility != ProposalEligibility::ManualRequired
        {
            return None;
        }
        let ProposalPayload::Atom(payload) = &proposal.payload else {
            return None;
        };
        let AtomProposalPayload::Create { draft } = payload.as_ref() else {
            return None;
        };
        if draft.evidence_refs != proposal.evidence_refs
            || draft.evidence_refs != proposal.source_cohort_refs
        {
            return None;
        }
        HumanAtomCreation::from_draft(draft, proposal.created_at_us)
    }

    pub fn capture_identity(&self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Correct(_) => (
                "human-correction",
                "human-correct",
                HUMAN_CORRECTION_MANIFEST,
            ),
            Self::Create(_) => ("human-creation", "human-create", HUMAN_CREATION_MANIFEST),
        }
    }

    pub fn canonical(
        &self,
        proposal_id: RevisionProposalId,
        revision: RevisionId,
    ) -> Option<String> {
        serde_json::to_string(&(self.capture_identity().2, proposal_id, revision, self)).ok()
    }

    pub fn read_canonical(
        bytes: &[u8],
        proposal_id: RevisionProposalId,
        revision: RevisionId,
    ) -> Option<Self> {
        let (_, _, _, intent): (String, RevisionProposalId, RevisionId, Self) =
            serde_json::from_slice(bytes).ok()?;
        (intent.canonical(proposal_id, revision)?.as_bytes() == bytes).then_some(intent)
    }

    pub fn exact_capture(receipt: &SourceReceipt) -> bool {
        receipt.archive_mode == SourceArchiveMode::Exact
            && receipt.protected_secret_digest.is_none()
            && receipt.redaction_spans.is_empty()
            && receipt.protected_length == receipt.original_length
    }

    pub fn capture_matches(
        &self,
        scope: &AtomScope,
        proposal_id: RevisionProposalId,
        revision: RevisionId,
        receipt: &SourceReceipt,
        observation: &SourceObservation,
    ) -> bool {
        let (instance, record, manifest) = self.capture_identity();
        receipt.task_id == scope.task_id()
            && receipt.repository_instance_id == scope.repository_id()
            && receipt.worktree_instance_id.is_none()
            && self
                .canonical(proposal_id, revision)
                .is_some_and(|canonical| {
                    human_capture_matches(
                        (proposal_id, revision),
                        &canonical,
                        record,
                        instance,
                        manifest,
                        receipt,
                        observation,
                    )
                })
    }
}

/// Only the displayed coverage, with no inventory identifiers or protected CAS locators.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebProcedureCoverage {
    inventory_count: usize,
    present_assets: u32,
    unobserved_sources: u32,
    unknown_contracts: u32,
    equivalent_levels: Vec<CapabilityEvidenceLevel>,
    incremental_base_revision: Option<RevisionId>,
    omissions: Vec<CapabilityCoverageOmission>,
    likely_redundant: bool,
}

impl WebProcedureCoverage {
    fn from_summary(value: &CapabilityCoverageSummary) -> Option<Self> {
        value.validate().then(|| Self {
            inventory_count: value.inventory_refs.len(),
            present_assets: value.present_assets,
            unobserved_sources: value.unobserved_sources,
            unknown_contracts: value.unknown_contracts,
            equivalent_levels: value
                .equivalent_assets
                .iter()
                .map(|asset| asset.level)
                .collect(),
            incremental_base_revision: value.incremental_base_revision,
            omissions: value.omissions.clone(),
            likely_redundant: value.likely_redundant,
        })
    }

    fn permits_manual(&self, operation: ProposalOperation) -> bool {
        self.inventory_count <= 8
            && self.equivalent_levels.len() <= 64
            && self.unknown_contracts <= self.present_assets
            && self.omissions.windows(2).all(|pair| pair[0] < pair[1])
            && (operation != ProposalOperation::Create
                || !self
                    .equivalent_levels
                    .contains(&CapabilityEvidenceLevel::OutcomeSupported))
    }
}

impl From<ProcedureScope> for AtomScope {
    fn from(scope: ProcedureScope) -> Self {
        match scope {
            ProcedureScope::Worktree {
                repository_id,
                worktree_id,
            } => AtomScope::Worktree {
                repository_instance_id: repository_id,
                worktree_instance_id: worktree_id,
            },
            ProcedureScope::Repository { repository_id } => AtomScope::Repository {
                repository_instance_id: repository_id,
            },
            ProcedureScope::Global => AtomScope::Global,
        }
    }
}

impl WebAcceptanceIntent {
    pub fn scope(proposal: &RevisionProposal) -> Option<AtomScope> {
        if !proposal.status.is_open()
            || proposal.eligibility == ProposalEligibility::AutoEligibleFull
        {
            return None;
        }
        match &proposal.payload {
            ProposalPayload::Atom(payload) => match payload.as_ref() {
                AtomProposalPayload::Create { draft }
                    if proposal.operation == ProposalOperation::Create
                        && proposal.eligibility == ProposalEligibility::ManualRequired
                        && (draft.scope.task_id().is_some()
                            || HumanAtomAuthoring::creation_for_review(proposal).is_some()) =>
                {
                    Some(draft.scope.clone())
                }
                AtomProposalPayload::Replace { draft }
                    if proposal.operation == ProposalOperation::Replace
                        && proposal.eligibility == ProposalEligibility::ManualRequired
                        && matches!(
                            draft.scope,
                            AtomScope::Task { .. } | AtomScope::Repository { .. }
                        ) =>
                {
                    Some(draft.scope.clone())
                }
                AtomProposalPayload::Merge { draft, .. }
                    if proposal.operation == ProposalOperation::Merge
                        && matches!(
                            draft.scope,
                            AtomScope::Task { .. } | AtomScope::Repository { .. }
                        ) =>
                {
                    Some(draft.scope.clone())
                }
                _ => None,
            },
            ProposalPayload::CoreMembership(payload)
                if proposal.operation == ProposalOperation::Create =>
            {
                payload.creation().map(|(_, scope)| scope.atom_scope())
            }
            ProposalPayload::Procedure(payload) if proposal.operation == payload.operation() => {
                Some(payload.draft().scope.into())
            }
            _ => None,
        }
    }

    pub fn for_review(
        proposal: &RevisionProposal,
        frontier: u64,
        coverage: Option<&CapabilityCoverageSummary>,
    ) -> Option<Self> {
        let procedure_coverage = match coverage {
            Some(value) => Some(Box::new(WebProcedureCoverage::from_summary(value)?)),
            None => None,
        };
        Some(Self {
            reviewed_frontier: frontier,
            review_digest: Self::digest(proposal, frontier, procedure_coverage.as_deref())?,
            procedure_coverage,
            atom_edit: None,
            procedure_edit: None,
            reauthorization: None,
        })
    }

    pub fn for_reauthorization(
        proposal: &RevisionProposal,
        frontier: u64,
        reference: &ObjectReauthorizationRef,
        coverage: Option<&CapabilityCoverageSummary>,
    ) -> Option<Self> {
        let mut intent = Self {
            reviewed_frontier: frontier,
            review_digest: [0; 32],
            procedure_coverage: match coverage {
                Some(value) => Some(Box::new(WebProcedureCoverage::from_summary(value)?)),
                None => None,
            },
            atom_edit: None,
            procedure_edit: None,
            reauthorization: Some(Box::new(reference.clone())),
        };
        intent.review_digest = intent.reauthorization_digest(proposal, reference)?;
        Some(intent)
    }

    fn reauthorization_scope(
        proposal: &RevisionProposal,
        target: ObjectDeletionTarget,
    ) -> Option<AtomScope> {
        if proposal.eligibility != ProposalEligibility::ManualRequired
            || !proposal.status.is_open()
            || proposal.operation != ProposalOperation::Create
            || proposal.base_revision_id.is_some()
            || proposal.target_id.is_some()
        {
            return None;
        }
        match (target, &proposal.payload) {
            (ObjectDeletionTarget::Atom { .. }, ProposalPayload::Atom(payload)) => {
                let AtomProposalPayload::Create { draft } = payload.as_ref() else {
                    return None;
                };
                matches!(
                    draft.scope,
                    AtomScope::Task { .. } | AtomScope::Repository { .. } | AtomScope::Global
                )
                .then(|| draft.scope.clone())
            }
            (ObjectDeletionTarget::Procedure { .. }, ProposalPayload::Procedure(_))
            | (ObjectDeletionTarget::CoreMembership { .. }, ProposalPayload::CoreMembership(_)) => {
                Self::scope(proposal)
            }
            _ => None,
        }
    }

    fn reauthorization_digest(
        &self,
        proposal: &RevisionProposal,
        reference: &ObjectReauthorizationRef,
    ) -> Option<[u8; 32]> {
        Self::reauthorization_scope(proposal, reference.target)?;
        let coverage = self.procedure_coverage.as_deref();
        if self.reviewed_frontier == 0
            || self.edit().is_some()
            || reference.deletion_generation == 0
            || reference.purge_job_audit_ref.is_empty()
            || !Self::manual_coverage_valid(proposal, coverage)
        {
            return None;
        }
        proposal_review_digest(
            self.reviewed_frontier,
            ("reauthorize", proposal, reference, coverage),
            proposal.base_revision_id,
        )
    }

    pub fn digest_hex(&self) -> String {
        hex(&self.review_digest)
    }

    pub fn for_atom_edit(
        proposal: &RevisionProposal,
        frontier: u64,
        edit: Box<WebAtomEdit>,
    ) -> Option<Self> {
        let review_digest = Self::edit_digest(proposal, frontier, &edit)?;
        Some(Self {
            reviewed_frontier: frontier,
            review_digest,
            procedure_coverage: None,
            atom_edit: Some(edit),
            procedure_edit: None,
            reauthorization: None,
        })
    }

    pub fn for_procedure_edit(
        proposal: &RevisionProposal,
        frontier: u64,
        edit: Box<WebProcedureEdit>,
        coverage: &CapabilityCoverageSummary,
    ) -> Option<Self> {
        let coverage = Box::new(WebProcedureCoverage::from_summary(coverage)?);
        Some(Self {
            reviewed_frontier: frontier,
            review_digest: Self::procedure_edit_digest(proposal, frontier, &edit, &coverage)?,
            procedure_coverage: Some(coverage),
            atom_edit: None,
            procedure_edit: Some(edit),
            reauthorization: None,
        })
    }

    pub fn procedure_edit_digest(
        proposal: &RevisionProposal,
        frontier: u64,
        edit: &WebProcedureEdit,
        coverage: &WebProcedureCoverage,
    ) -> Option<[u8; 32]> {
        if frontier == 0 || !coverage.permits_manual(proposal.operation) {
            return None;
        }
        proposal_review_digest(
            frontier,
            (
                "edit_and_accept",
                proposal,
                edit.edited_draft(proposal)?,
                coverage,
            ),
            proposal.base_revision_id,
        )
    }

    pub fn edit(&self) -> Option<WebProposalEdit<'_>> {
        self.atom_edit
            .as_deref()
            .map(WebProposalEdit::Atom)
            .or_else(|| {
                self.procedure_edit
                    .as_deref()
                    .map(WebProposalEdit::Procedure)
            })
    }

    fn edit_digest(
        proposal: &RevisionProposal,
        frontier: u64,
        edit: &WebAtomEdit,
    ) -> Option<[u8; 32]> {
        if frontier == 0 {
            return None;
        }
        let edited = edit.edited_draft(proposal)?;
        proposal_review_digest(
            frontier,
            ("edit_and_accept", proposal, edited),
            proposal.base_revision_id,
        )
    }

    pub fn reviewed_scope(&self, original: &RevisionProposal) -> Option<AtomScope> {
        if let Some(reference) = &self.reauthorization {
            Self::reauthorization_scope(original, reference.target)
        } else if self.atom_edit.is_some() {
            WebAtomEdit::draft(original).map(|draft| draft.scope.clone())
        } else {
            Self::scope(original)
        }
    }

    pub fn matches_reviewed(
        &self,
        original: &RevisionProposal,
        reviewed: &RevisionProposal,
    ) -> bool {
        match self.edit() {
            Some(edit) => {
                original.validate_edit_candidate(reviewed).is_ok()
                    && edit.payload(original).as_ref() == Some(&reviewed.payload)
            }
            None => original == reviewed,
        }
    }

    fn digest(
        proposal: &RevisionProposal,
        frontier: u64,
        coverage: Option<&WebProcedureCoverage>,
    ) -> Option<[u8; 32]> {
        #[derive(Serialize)]
        struct Review<'a> {
            proposal: &'a RevisionProposal,
            plain_accept_eligible: bool,
            merge_and_accept_eligible: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            capability_coverage: Option<&'a WebProcedureCoverage>,
        }
        if frontier == 0 {
            return None;
        }
        Self::scope(proposal)?;
        if !Self::manual_coverage_valid(proposal, coverage) {
            return None;
        }
        let merge = proposal.operation == ProposalOperation::Merge;
        let review = Review {
            proposal,
            plain_accept_eligible: !merge,
            merge_and_accept_eligible: merge,
            capability_coverage: coverage,
        };
        // The original base and Core anchor are immutable revisions bound by the proposal, not re-encoded presentation.
        proposal_review_digest(frontier, review, proposal.base_revision_id)
    }

    fn manual_coverage_valid(
        proposal: &RevisionProposal,
        coverage: Option<&WebProcedureCoverage>,
    ) -> bool {
        match (&proposal.payload, coverage) {
            (ProposalPayload::Procedure(_), Some(value)) => {
                value.permits_manual(proposal.operation)
            }
            (ProposalPayload::Procedure(_), None) | (_, Some(_)) => false,
            _ => true,
        }
    }

    pub fn canonical(&self, proposal: &RevisionProposal) -> Option<String> {
        if self.atom_edit.is_some() && self.procedure_edit.is_some() {
            return None;
        }
        let (action, digest) = match (self.reauthorization.as_deref(), self.edit()) {
            (Some(reference), None) => (
                "reauthorize",
                self.reauthorization_digest(proposal, reference)?,
            ),
            (Some(_), Some(_)) => return None,
            (None, Some(WebProposalEdit::Atom(edit))) if self.procedure_coverage.is_none() => (
                "edit_and_accept",
                Self::edit_digest(proposal, self.reviewed_frontier, edit)?,
            ),
            (None, Some(WebProposalEdit::Atom(_))) => return None,
            (None, Some(WebProposalEdit::Procedure(edit))) => (
                "edit_and_accept",
                Self::procedure_edit_digest(
                    proposal,
                    self.reviewed_frontier,
                    edit,
                    self.procedure_coverage.as_deref()?,
                )?,
            ),
            (None, None) => (
                "accept",
                Self::digest(
                    proposal,
                    self.reviewed_frontier,
                    self.procedure_coverage.as_deref(),
                )?,
            ),
        };
        if digest != self.review_digest {
            return None;
        }
        serde_json::to_string(&(
            WEB_ACCEPTANCE_EVENT_MANIFEST_REF,
            action,
            proposal.proposal_id,
            proposal.proposal_revision_id,
            hex(&proposal.fingerprint),
            self,
        ))
        .ok()
    }

    pub fn read_canonical(bytes: &[u8], proposal: &RevisionProposal) -> Option<Self> {
        type Record = (
            String,
            String,
            RevisionProposalId,
            RevisionId,
            String,
            WebAcceptanceIntent,
        );
        let (_, _, _, _, _, intent): Record = serde_json::from_slice(bytes).ok()?;
        (intent.canonical(proposal)?.as_bytes() == bytes).then_some(intent)
    }

    pub fn capture_matches(
        &self,
        source: &RevisionProposal,
        receipt: &SourceReceipt,
        observation: &SourceObservation,
    ) -> bool {
        self.reviewed_scope(source).is_some_and(|scope| {
            let worktree = match scope {
                AtomScope::Worktree {
                    worktree_instance_id,
                    ..
                } => Some(worktree_instance_id),
                _ => None,
            };
            receipt.task_id == scope.task_id()
                && receipt.repository_instance_id == scope.repository_id()
                && receipt.worktree_instance_id == worktree
        }) && self.canonical(source).is_some_and(|canonical| {
            human_capture_matches(
                (source.proposal_id, source.proposal_revision_id),
                &canonical,
                "web-accept",
                "web-acceptance",
                WEB_ACCEPTANCE_EVENT_MANIFEST_REF,
                receipt,
                observation,
            )
        })
    }
}

/// Match the historical human-review capture envelope without re-encoding or granting authority.
pub fn tui_acceptance_capture_matches(
    source: &RevisionProposal,
    canonical: &str,
    record_prefix: &str,
    receipt: &SourceReceipt,
    observation: &SourceObservation,
) -> bool {
    human_capture_matches(
        (source.proposal_id, source.proposal_revision_id),
        canonical,
        record_prefix,
        "tui-acceptance",
        TUI_ACCEPTANCE_EVENT_MANIFEST_REF,
        receipt,
        observation,
    )
}

fn human_capture_matches(
    (proposal_id, revision): (RevisionProposalId, RevisionId),
    canonical: &str,
    record_prefix: &str,
    instance_prefix: &str,
    manifest: &str,
    receipt: &SourceReceipt,
    observation: &SourceObservation,
) -> bool {
    receipt.eligible_event_manifest_ref == manifest
        && receipt.identity_domain == manifest
        && receipt.adapter_manifest_ref == manifest
        && receipt.source_instance_id.as_str() == format!("{instance_prefix}:{proposal_id}")
        && receipt.source_revision.as_str() == revision.to_string()
        && receipt.source_record_identity.as_str()
            == format!("{record_prefix}-{proposal_id}-{revision}")
        && receipt.source_ref == proposal_id.to_string()
        && receipt.source_session_ref == "human-governance"
        && receipt.source_sequence == 1
        && receipt.source_sequence_origin == Some(1)
        && receipt.identity_strength == IdentityStrength::StableNative
        && receipt.source_kind == EvidenceSourceKind::Other
        && receipt.adapter_revision == 1
        && receipt.parser_revision == 1
        && receipt.canonicalization_revision == 1
        && receipt.capture_completeness == CaptureCompleteness::Complete
        && observation.capture_completeness == CaptureCompleteness::Complete
        && observation.source_role == SourceRole::User
        && observation.content_trust == ContentTrust::UserStatement
        && observation.observation_role == ObservationRole::Message
        && receipt.archive_mode == SourceArchiveMode::Exact
        && receipt.protected_secret_digest.is_none()
        && receipt.redaction_spans.is_empty()
        && receipt.protected_length == canonical.len() as u64
        && receipt.original_length == canonical.len() as u64
        && payload_fingerprint(1, canonical.as_bytes(), None)
            .is_ok_and(|expected| observation.payload_fingerprint == hex(&expected))
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
    Procedure(Box<ProcedureProposalPayload>),
    CoreMembership(Box<CoreMembershipProposalPayload>),
    ReservedTarget {
        schema_version: u32,
        summary: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProcedureProposalPayload {
    Create { draft: ProcedureDraft },
    Replace { draft: ProcedureDraft },
}

impl ProcedureProposalPayload {
    pub const fn operation(&self) -> ProposalOperation {
        match self {
            Self::Create { .. } => ProposalOperation::Create,
            Self::Replace { .. } => ProposalOperation::Replace,
        }
    }

    pub fn draft(&self) -> &ProcedureDraft {
        match self {
            Self::Create { draft } | Self::Replace { draft } => draft,
        }
    }
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

impl CoreMembershipProposalPayload {
    pub fn creation(&self) -> Option<(RevisionId, &CoreScopeIdentity)> {
        match self {
            Self::Create {
                atom_revision_id,
                scope_identity,
            } => Some((*atom_revision_id, scope_identity)),
            Self::ResolveConflict { .. } => None,
        }
    }
}

impl ProposalPayload {
    pub fn validate_closed_edit(&self, edited: &Self) -> Result<(), SemanticError> {
        if valid_closed_edit(self, edited) {
            Ok(())
        } else {
            Err(SemanticError::InvalidProposal)
        }
    }

    fn validate(&self, target_kind: ProposalTargetKind) -> Result<(), SemanticError> {
        match (target_kind, self) {
            (ProposalTargetKind::Atom, Self::Atom(payload)) => payload.validate(),
            (ProposalTargetKind::Procedure, Self::Procedure(payload)) => payload.draft().validate(),
            (ProposalTargetKind::CoreMembership, Self::CoreMembership(payload)) => {
                if matches!(payload.as_ref(), CoreMembershipProposalPayload::ResolveConflict { left_atom_revision_id, right_atom_revision_id, .. } if left_atom_revision_id == right_atom_revision_id)
                {
                    Err(SemanticError::InvalidProposal)
                } else {
                    Ok(())
                }
            }
            (
                ProposalTargetKind::CoreMembership,
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
    WebAcceptance {
        user_source_observation_ref: crate::ids::SourceObservationId,
        authorized_scope_ceiling: AtomScope,
        intent: WebAcceptanceIntent,
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
    Procedure {
        procedure_id: ProcedureId,
        procedure_revision_id: RevisionId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auto_full_audit: Option<Box<ProcedureAutoFullAudit>>,
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
            AcceptedProposalTarget::CoreMembership { .. }
            | AcceptedProposalTarget::Procedure { .. } => None,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ClosedProposalEditIntent {
    schema_version: u32,
    original_proposal_id: RevisionProposalId,
    original_proposal_revision_id: RevisionId,
    original_fingerprint: [u8; 32],
    new_proposal: RevisionProposal,
}

impl ClosedProposalEditIntent {
    fn new(original: &RevisionProposal, new_proposal: RevisionProposal) -> Self {
        Self {
            schema_version: PROPOSAL_EDIT_INTENT_SCHEMA_VERSION,
            original_proposal_id: original.proposal_id,
            original_proposal_revision_id: original.proposal_revision_id,
            original_fingerprint: original.fingerprint,
            new_proposal,
        }
    }

    fn validate(&self, original: &RevisionProposal) -> Result<(), SemanticError> {
        original.validate()?;
        self.new_proposal.validate()?;
        if self.schema_version != PROPOSAL_EDIT_INTENT_SCHEMA_VERSION
            || self.original_proposal_id != original.proposal_id
            || self.original_proposal_revision_id != original.proposal_revision_id
            || self.original_fingerprint != original.fingerprint
            || !original.status.is_open()
            || self.new_proposal.proposal_id == original.proposal_id
            || self.new_proposal.proposal_revision_id == original.proposal_revision_id
            || self.new_proposal.parent_proposal_revision_id.is_some()
            || !matches!(
                self.new_proposal.target_kind,
                ProposalTargetKind::Atom | ProposalTargetKind::Procedure
            )
            || self.new_proposal.target_kind != original.target_kind
            || self.new_proposal.target_id != original.target_id
            || self.new_proposal.base_revision_id != original.base_revision_id
            || self.new_proposal.operation != original.operation
            || self.new_proposal.evidence_refs != original.evidence_refs
            || self.new_proposal.source_cohort_refs != original.source_cohort_refs
            || self.new_proposal.source_cohort_hash != original.source_cohort_hash
            || self.new_proposal.eligibility != ProposalEligibility::ManualRequired
            || self.new_proposal.status != ProposalStatus::Pending
            || !self.new_proposal.waiting_on.is_empty()
            || self.new_proposal.review_reason.is_some()
            || self.new_proposal.created_by != ProposalCreatedBy::User
            || self.new_proposal.acceptance.is_some()
            || self.new_proposal.reviewed_at_us.is_some()
            || self.new_proposal.fingerprint == original.fingerprint
            || original
                .payload
                .validate_closed_edit(&self.new_proposal.payload)
                .is_err()
        {
            return Err(SemanticError::InvalidProposal);
        }
        Ok(())
    }

    fn canonical_toml(&self) -> Result<String, SemanticError> {
        toml::to_string(self).map_err(|_| SemanticError::InvalidProposal)
    }

    fn from_toml(value: &str) -> Result<Self, SemanticError> {
        toml::from_str(value).map_err(|_| SemanticError::InvalidProposal)
    }
}

impl RevisionProposal {
    pub fn atom_merge_inputs(&self) -> Option<&[RevisionId]> {
        let ProposalPayload::Atom(payload) = &self.payload else {
            return None;
        };
        match payload.as_ref() {
            AtomProposalPayload::Merge {
                merged_revision_refs,
                ..
            } if self.operation == ProposalOperation::Merge => Some(merged_revision_refs),
            _ => None,
        }
    }

    pub fn core_creation(&self) -> Option<(RevisionId, &CoreScopeIdentity)> {
        let ProposalPayload::CoreMembership(payload) = &self.payload else {
            return None;
        };
        payload.creation()
    }

    pub fn validate_edit_candidate(&self, new_proposal: &Self) -> Result<(), SemanticError> {
        ClosedProposalEditIntent::new(self, new_proposal.clone()).validate(self)
    }

    pub fn edit_intent_toml(&self, new_proposal: &Self) -> Result<String, SemanticError> {
        let intent = ClosedProposalEditIntent::new(self, new_proposal.clone());
        intent.validate(self)?;
        intent.canonical_toml()
    }

    pub fn parse_edit_intent_toml(
        value: &str,
    ) -> Result<(RevisionProposalId, RevisionId, [u8; 32], RevisionProposal), SemanticError> {
        let intent = ClosedProposalEditIntent::from_toml(value)?;
        Ok((
            intent.original_proposal_id,
            intent.original_proposal_revision_id,
            intent.original_fingerprint,
            intent.new_proposal,
        ))
    }

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
            (ProposalPayload::Procedure(payload), operation)
                if payload.operation() == operation => {}
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
                ) | (
                    ProposalTargetKind::Procedure,
                    AcceptedProposalTarget::Procedure { .. }
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
        if self.payload != next.payload
            && next.review_reason.as_deref() == Some("procedure_review_v1")
        {
            return self.validate_procedure_review_successor(next);
        }
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

    /// A bounded background review preserves the Inbox identity and cannot
    /// inherit acceptance or automatic eligibility for changed content.
    pub fn validate_procedure_review_successor(&self, next: &Self) -> Result<(), SemanticError> {
        next.validate()?;
        let (ProposalPayload::Procedure(before), ProposalPayload::Procedure(after)) =
            (&self.payload, &next.payload)
        else {
            return Err(SemanticError::InvalidProposalSuccessor);
        };
        if !matches!(
            self.status,
            ProposalStatus::Pending | ProposalStatus::Validating
        ) || next.status != self.status
            || self.proposal_id != next.proposal_id
            || next.parent_proposal_revision_id != Some(self.proposal_revision_id)
            || self.proposal_revision_id == next.proposal_revision_id
            || self.target_kind != next.target_kind
            || self.target_id != next.target_id
            || self.base_revision_id != next.base_revision_id
            || self.operation != next.operation
            || self.created_by != next.created_by
            || !contains_all(&next.source_cohort_refs, &self.source_cohort_refs)
            || !contains_all(&next.evidence_refs, &self.evidence_refs)
            || before.draft().scope != after.draft().scope
            || !contains_all(&after.draft().evidence_refs, &before.draft().evidence_refs)
            || before.draft().support_revision_refs != after.draft().support_revision_refs
            || next.eligibility != ProposalEligibility::ManualRequired
            || next.created_at_us < self.created_at_us
            || next.review_reason.as_deref() != Some("procedure_review_v1")
            || self.payload == next.payload
        {
            return Err(SemanticError::InvalidProposalSuccessor);
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

fn valid_closed_edit(original: &ProposalPayload, edited: &ProposalPayload) -> bool {
    match (original, edited) {
        (ProposalPayload::Atom(original), ProposalPayload::Atom(edited)) => {
            valid_atom_edit(original, edited)
        }
        (ProposalPayload::Procedure(original), ProposalPayload::Procedure(edited)) => {
            valid_procedure_edit(original, edited)
        }
        _ => false,
    }
}

fn valid_atom_edit(original: &AtomProposalPayload, edited: &AtomProposalPayload) -> bool {
    match (original, edited) {
        (
            AtomProposalPayload::Create { draft: original },
            AtomProposalPayload::Create { draft: edited },
        )
        | (
            AtomProposalPayload::Replace { draft: original },
            AtomProposalPayload::Replace { draft: edited },
        )
        | (
            AtomProposalPayload::Reclassify { draft: original },
            AtomProposalPayload::Reclassify { draft: edited },
        ) => {
            original != edited
                && original.value.critical_revision_refs == edited.value.critical_revision_refs
                && original.provenance == edited.provenance
                && original.source_observation_refs == edited.source_observation_refs
                && original.evidence_refs == edited.evidence_refs
                && original.supersedes_revision_refs == edited.supersedes_revision_refs
                && original.supports_revision_refs == edited.supports_revision_refs
                && original.contradicts_revision_refs == edited.contradicts_revision_refs
        }
        (
            AtomProposalPayload::Deprecate { reason: original },
            AtomProposalPayload::Deprecate { reason: edited },
        ) => original != edited,
        _ => false,
    }
}

fn valid_procedure_edit(
    original: &ProcedureProposalPayload,
    edited: &ProcedureProposalPayload,
) -> bool {
    let (original, edited) = match (original, edited) {
        (
            ProcedureProposalPayload::Create { draft: original },
            ProcedureProposalPayload::Create { draft: edited },
        )
        | (
            ProcedureProposalPayload::Replace { draft: original },
            ProcedureProposalPayload::Replace { draft: edited },
        ) => (original, edited),
        _ => return false,
    };
    original != edited
        && original.evidence_refs == edited.evidence_refs
        && original.support_revision_refs == edited.support_revision_refs
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
