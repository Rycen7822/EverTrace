use serde::{Deserialize, Serialize};
use thiserror::Error;

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryTrustState {
    Trusted,
    Untrusted,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryTrustResult {
    pub state: RepositoryTrustState,
    pub canonical_repository_path: Option<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RepositoryTrustParseError {
    #[error("Codex trust configuration is malformed")]
    Malformed,
    #[error("repository path is invalid")]
    InvalidPath,
}

/// Parses only the exact host-resolved project entry. The caller retains the
/// bytes transiently; neither config contents nor unrelated project entries
/// are returned from this boundary.
pub fn parse_repository_trust(
    config: &[u8],
    canonical_repository_path: &str,
) -> Result<RepositoryTrustState, RepositoryTrustParseError> {
    if canonical_repository_path.is_empty()
        || canonical_repository_path.len() > 4096
        || canonical_repository_path
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || !crate::binding::valid_lexical_absolute_path(canonical_repository_path)
    {
        return Err(RepositoryTrustParseError::InvalidPath);
    }
    let value = std::str::from_utf8(config)
        .ok()
        .and_then(|text| toml::from_str::<toml::Value>(text).ok())
        .ok_or(RepositoryTrustParseError::Malformed)?;
    let Some(projects) = value.get("projects").and_then(toml::Value::as_table) else {
        return Ok(RepositoryTrustState::Unknown);
    };
    let Some(project) = projects
        .get(canonical_repository_path)
        .and_then(toml::Value::as_table)
    else {
        return Ok(RepositoryTrustState::Unknown);
    };
    match project.get("trust_level").and_then(toml::Value::as_str) {
        Some("trusted") => Ok(RepositoryTrustState::Trusted),
        Some("untrusted") => Ok(RepositoryTrustState::Untrusted),
        _ => Ok(RepositoryTrustState::Unknown),
    }
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
