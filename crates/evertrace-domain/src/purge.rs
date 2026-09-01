use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalValue, sha256},
    evidence::hex,
    ids::{AtomId, CoreMembershipId, JobId, ProcedureId, RevisionProposalId},
    revision::RevisionId,
    semantic::{ProposalOperation, RevisionProposal},
};

pub const OBJECT_DELETION_LEDGER_SCHEMA_VERSION: u16 = 1;
const OBJECT_REAUTHORIZATION_INTENT_SCHEMA_VERSION: u16 = 1;
const MAX_DELETED_REVISIONS: usize = 256;
const MAX_SUPPRESSION_REFS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectDeletionTarget {
    Atom {
        atom_id: AtomId,
    },
    Procedure {
        procedure_id: ProcedureId,
    },
    CoreMembership {
        core_membership_id: CoreMembershipId,
    },
}

impl ObjectDeletionTarget {
    pub fn object_ref(self) -> String {
        match self {
            Self::Atom { atom_id } => atom_id.to_string(),
            Self::Procedure { procedure_id } => procedure_id.to_string(),
            Self::CoreMembership { core_membership_id } => core_membership_id.to_string(),
        }
    }

    pub const fn kind_name(self) -> &'static str {
        match self {
            Self::Atom { .. } => "atom",
            Self::Procedure { .. } => "procedure",
            Self::CoreMembership { .. } => "core_membership",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectDeletionPhase {
    Pending,
    Purged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectDeletionGuards {
    pub semantic_kind_hash: String,
    pub canonical_payload_hash: String,
    pub scope_identity_hash: String,
    pub source_derivation_guard_hash: String,
}

impl ObjectDeletionGuards {
    pub fn derive(
        target: ObjectDeletionTarget,
        semantic_kind: &str,
        canonical_payloads: &[String],
        scope_identity: &str,
        source_derivation_refs: &[String],
    ) -> Option<Self> {
        if semantic_kind.is_empty()
            || canonical_payloads.is_empty()
            || canonical_payloads.iter().any(String::is_empty)
            || scope_identity.is_empty()
            || !strictly_sorted(source_derivation_refs)
        {
            return None;
        }
        Some(Self {
            semantic_kind_hash: digest(
                "object_deletion_semantic_kind",
                CanonicalValue::Sequence(vec![
                    CanonicalValue::String(target.kind_name().into()),
                    CanonicalValue::String(semantic_kind.into()),
                ]),
            )?,
            canonical_payload_hash: digest(
                "object_deletion_canonical_payload",
                CanonicalValue::Sequence(
                    canonical_payloads
                        .iter()
                        .cloned()
                        .map(CanonicalValue::String)
                        .collect(),
                ),
            )?,
            scope_identity_hash: digest(
                "object_deletion_scope_identity",
                CanonicalValue::Sequence(vec![
                    CanonicalValue::String(target.kind_name().into()),
                    CanonicalValue::String(scope_identity.into()),
                ]),
            )?,
            source_derivation_guard_hash: digest(
                "object_deletion_source_derivation_guard",
                CanonicalValue::Sequence(vec![
                    CanonicalValue::String(target.kind_name().into()),
                    CanonicalValue::String(semantic_kind.into()),
                    CanonicalValue::String(scope_identity.into()),
                    CanonicalValue::Sequence(
                        source_derivation_refs
                            .iter()
                            .cloned()
                            .map(CanonicalValue::String)
                            .collect(),
                    ),
                ]),
            )?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectDeletionLedgerEvent {
    pub schema_version: u16,
    pub target: ObjectDeletionTarget,
    pub phase: ObjectDeletionPhase,
    pub exact_revision_ids: Vec<RevisionId>,
    pub semantic_kind_hash: String,
    pub canonical_payload_hash: String,
    pub scope_identity_hash: String,
    pub source_derivation_guard_hash: String,
    pub default_retrieval_suppression_ref_hashes: Vec<String>,
    pub deletion_generation: u64,
    pub recorded_at_us: i64,
    pub purge_job_id: JobId,
    pub purge_job_audit_ref: Option<String>,
}

impl ObjectDeletionLedgerEvent {
    pub fn validate(&self) -> bool {
        self.schema_version == OBJECT_DELETION_LEDGER_SCHEMA_VERSION
            && !self.exact_revision_ids.is_empty()
            && self.exact_revision_ids.len() <= MAX_DELETED_REVISIONS
            && strictly_sorted(&self.exact_revision_ids)
            && digest_text(&self.semantic_kind_hash)
            && digest_text(&self.canonical_payload_hash)
            && digest_text(&self.scope_identity_hash)
            && digest_text(&self.source_derivation_guard_hash)
            && self.default_retrieval_suppression_ref_hashes.len() <= MAX_SUPPRESSION_REFS
            && strictly_sorted(&self.default_retrieval_suppression_ref_hashes)
            && self
                .default_retrieval_suppression_ref_hashes
                .iter()
                .all(|value| digest_text(value))
            && self.deletion_generation > 0
            && self.recorded_at_us >= 0
            && match self.phase {
                ObjectDeletionPhase::Pending => self.purge_job_audit_ref.is_none(),
                ObjectDeletionPhase::Purged => self
                    .purge_job_audit_ref
                    .as_deref()
                    .is_some_and(|value| value == self.purge_job_id.to_string()),
            }
    }

    pub fn validate_successor(&self, next: &Self) -> bool {
        self.validate()
            && next.validate()
            && self.phase == ObjectDeletionPhase::Pending
            && next.phase == ObjectDeletionPhase::Purged
            && self.target == next.target
            && self.exact_revision_ids == next.exact_revision_ids
            && self.semantic_kind_hash == next.semantic_kind_hash
            && self.canonical_payload_hash == next.canonical_payload_hash
            && self.scope_identity_hash == next.scope_identity_hash
            && self.source_derivation_guard_hash == next.source_derivation_guard_hash
            && self.default_retrieval_suppression_ref_hashes
                == next.default_retrieval_suppression_ref_hashes
            && self.deletion_generation == next.deletion_generation
            && self.purge_job_id == next.purge_job_id
            && self.recorded_at_us <= next.recorded_at_us
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectReauthorizationRef {
    pub target: ObjectDeletionTarget,
    pub deletion_generation: u64,
    pub purge_job_audit_ref: String,
}

impl ObjectReauthorizationRef {
    pub fn from_deletion(deletion: &ObjectDeletionLedgerEvent) -> Option<Self> {
        if !deletion.validate() || deletion.phase != ObjectDeletionPhase::Purged {
            return None;
        }
        Some(Self {
            target: deletion.target,
            deletion_generation: deletion.deletion_generation,
            purge_job_audit_ref: deletion.purge_job_audit_ref.clone()?,
        })
    }

    pub fn matches(&self, deletion: &ObjectDeletionLedgerEvent) -> bool {
        Self::from_deletion(deletion).as_ref() == Some(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectReauthorizationIntent {
    pub schema_version: u16,
    pub deletion: ObjectReauthorizationRef,
    pub reviewed_proposal_id: RevisionProposalId,
    pub reviewed_proposal_revision_id: RevisionId,
    pub reviewed_fingerprint: String,
}

impl ObjectReauthorizationIntent {
    pub fn new(deletion: &ObjectDeletionLedgerEvent, reviewed: &RevisionProposal) -> Option<Self> {
        let value = Self {
            schema_version: OBJECT_REAUTHORIZATION_INTENT_SCHEMA_VERSION,
            deletion: ObjectReauthorizationRef::from_deletion(deletion)?,
            reviewed_proposal_id: reviewed.proposal_id,
            reviewed_proposal_revision_id: reviewed.proposal_revision_id,
            reviewed_fingerprint: hex(&reviewed.fingerprint),
        };
        value.validate(deletion, reviewed).then_some(value)
    }

    pub fn validate(
        &self,
        deletion: &ObjectDeletionLedgerEvent,
        reviewed: &RevisionProposal,
    ) -> bool {
        deletion.validate()
            && deletion.phase == ObjectDeletionPhase::Purged
            && self.deletion.matches(deletion)
            && self.schema_version == OBJECT_REAUTHORIZATION_INTENT_SCHEMA_VERSION
            && self.reviewed_proposal_id == reviewed.proposal_id
            && self.reviewed_proposal_revision_id == reviewed.proposal_revision_id
            && digest_text(&self.reviewed_fingerprint)
            && self.reviewed_fingerprint == hex(&reviewed.fingerprint)
            && reviewed.validate().is_ok()
            && reviewed.operation == ProposalOperation::Create
            && reviewed.target_id.is_none()
            && reviewed.base_revision_id.is_none()
            && reviewed.status.is_open()
    }

    pub fn canonical_toml(
        &self,
        deletion: &ObjectDeletionLedgerEvent,
        reviewed: &RevisionProposal,
    ) -> Option<String> {
        self.validate(deletion, reviewed)
            .then(|| toml::to_string(self).ok())
            .flatten()
    }

    pub fn from_toml(value: &str) -> Option<Self> {
        toml::from_str(value).ok()
    }
}

fn digest(domain: &str, value: CanonicalValue) -> Option<String> {
    sha256(domain, 1, &value).ok().map(|value| hex(&value))
}

fn digest_text(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_is_closed_content_free_and_successor_is_exact() {
        let target = ObjectDeletionTarget::Atom {
            atom_id: AtomId::new_v7(),
        };
        let guards = ObjectDeletionGuards::derive(
            target,
            "fact",
            &["payload".into()],
            "global",
            &["source".into()],
        )
        .unwrap();
        let job_id = JobId::new_v7();
        let mut pending = ObjectDeletionLedgerEvent {
            schema_version: OBJECT_DELETION_LEDGER_SCHEMA_VERSION,
            target,
            phase: ObjectDeletionPhase::Pending,
            exact_revision_ids: vec![RevisionId::new_v7()],
            semantic_kind_hash: guards.semantic_kind_hash,
            canonical_payload_hash: guards.canonical_payload_hash,
            scope_identity_hash: guards.scope_identity_hash,
            source_derivation_guard_hash: guards.source_derivation_guard_hash,
            default_retrieval_suppression_ref_hashes: Vec::new(),
            deletion_generation: 1,
            recorded_at_us: 1,
            purge_job_id: job_id,
            purge_job_audit_ref: None,
        };
        assert!(pending.validate());
        let mut purged = pending.clone();
        purged.phase = ObjectDeletionPhase::Purged;
        purged.recorded_at_us = 2;
        purged.purge_job_audit_ref = Some(job_id.to_string());
        assert!(pending.validate_successor(&purged));
        pending
            .exact_revision_ids
            .push(pending.exact_revision_ids[0]);
        assert!(!pending.validate());
    }

    #[test]
    fn source_guard_binds_family_kind_scope_and_source_revision_set() {
        let atom = ObjectDeletionTarget::Atom {
            atom_id: AtomId::new_v7(),
        };
        let base = ObjectDeletionGuards::derive(
            atom,
            "constraint",
            &["payload".into()],
            "repository:one",
            &["source-revision".into()],
        )
        .unwrap()
        .source_derivation_guard_hash;
        let procedure = ObjectDeletionGuards::derive(
            ObjectDeletionTarget::Procedure {
                procedure_id: ProcedureId::new_v7(),
            },
            "constraint",
            &["payload".into()],
            "repository:one",
            &["source-revision".into()],
        )
        .unwrap()
        .source_derivation_guard_hash;
        let kind = ObjectDeletionGuards::derive(
            atom,
            "fact",
            &["payload".into()],
            "repository:one",
            &["source-revision".into()],
        )
        .unwrap()
        .source_derivation_guard_hash;
        let scope = ObjectDeletionGuards::derive(
            atom,
            "constraint",
            &["payload".into()],
            "repository:two",
            &["source-revision".into()],
        )
        .unwrap()
        .source_derivation_guard_hash;
        let source = ObjectDeletionGuards::derive(
            atom,
            "constraint",
            &["payload".into()],
            "repository:one",
            &["other-source-revision".into()],
        )
        .unwrap()
        .source_derivation_guard_hash;
        assert_ne!(base, procedure);
        assert_ne!(base, kind);
        assert_ne!(base, scope);
        assert_ne!(base, source);
    }
}
