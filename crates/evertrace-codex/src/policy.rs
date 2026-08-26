use serde::{Deserialize, Serialize};

use crate::adapter_manifest::MaxHostResolvedScope;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCandidateOrigin {
    HostPolicySurface,
    RepositoryTrust,
    Readme,
    Agents,
    Comment,
    SkillText,
    OrdinaryText,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvidence {
    pub policy_source_kind: String,
    pub origin: PolicyCandidateOrigin,
    pub host_loaded: bool,
    pub readback_supported: bool,
    pub readback_matches: bool,
    pub source_revision: String,
    pub content_digest: String,
    pub resolved_scope: Option<MaxHostResolvedScope>,
    pub current_trust: bool,
    pub current: bool,
    pub revoked: bool,
    pub evidence_refs: Vec<String>,
}

pub(crate) fn scope_within(actual: MaxHostResolvedScope, maximum: MaxHostResolvedScope) -> bool {
    matches!(
        (actual, maximum),
        (MaxHostResolvedScope::Worktree, _)
            | (
                MaxHostResolvedScope::Repository,
                MaxHostResolvedScope::Repository
            )
    )
}
