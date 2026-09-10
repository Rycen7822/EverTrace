//! Finite, protected capability observations. Presence is not evidence of use.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ids::{JobId, RepositoryId, WorktreeId};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityInventoryProfile {
    NativeFiniteAssetsV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityEvidenceLevel {
    Present,
    Routed,
    ActionAligned,
    OutcomeSupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityCoverageOmission {
    SessionUnobserved,
    InventoryMissing,
    InventoryStale,
    SourceUnobserved,
    ContractUnknown,
    HistoricalCaptureUnobserved,
    NaturalExecutionUnobserved,
    CandidateLimit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCoverageMatch {
    pub revision_ref: String,
    pub level: CapabilityEvidenceLevel,
}

/// A bounded read result, not a new stored asset or caller authorization.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCoverageSummary {
    pub inventory_refs: Vec<JobId>,
    pub present_assets: u32,
    pub unobserved_sources: u32,
    pub unknown_contracts: u32,
    pub equivalent_assets: Vec<CapabilityCoverageMatch>,
    pub incremental_base_revision: Option<crate::revision::RevisionId>,
    pub omissions: Vec<CapabilityCoverageOmission>,
    pub likely_redundant: bool,
}

impl CapabilityCoverageSummary {
    pub fn validate(&self) -> bool {
        !self
            .inventory_refs
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            && self.inventory_refs.len() <= 8
            && self.equivalent_assets.len() <= 64
            && self.unknown_contracts <= self.present_assets
            && self
                .equivalent_assets
                .iter()
                .all(|value| bounded_text(&value.revision_ref, 4096).is_ok())
            && self
                .equivalent_assets
                .windows(2)
                .all(|pair| pair[0].revision_ref < pair[1].revision_ref)
            && self.omissions.windows(2).all(|pair| pair[0] < pair[1])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryContext {
    pub repository_id: RepositoryId,
    pub worktree_id: WorktreeId,
    pub cwd: String,
    pub adapter_manifest_id: String,
    pub profile: CapabilityInventoryProfile,
    pub host_home: String,
    pub host_config_root: String,
    pub host_profile: Option<String>,
}

impl InventoryContext {
    pub fn validate(&self) -> Result<(), InventoryError> {
        locator(&self.cwd)?;
        locator(&self.host_home)?;
        locator(&self.host_config_root)?;
        if let Some(profile) = &self.host_profile {
            bounded_text(profile, 128)?;
        }
        digest(&self.adapter_manifest_id)
    }
}

/// The completion fact owns its protected snapshot and its direct CAS closure.
/// The snapshot alone contains the source and signature lists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityInventoryRecorded {
    pub job_id: JobId,
    pub context: InventoryContext,
    pub repository_revision: u32,
    pub snapshot_cas_ref: String,
    pub dependency_cas_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub recorded_at_us: i64,
}

impl CapabilityInventoryRecorded {
    pub fn validate(&self) -> Result<(), InventoryError> {
        self.context.validate()?;
        if self.repository_revision == 0 || self.recorded_at_us < 0 {
            return Err(InventoryError::InvalidFact);
        }
        digest(&self.snapshot_cas_ref)?;
        if self
            .dependency_cas_refs
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || self.dependency_cas_refs.contains(&self.snapshot_cas_ref)
            || self.evidence_refs.is_empty()
            || self.evidence_refs.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(InventoryError::InvalidFact);
        }
        for reference in &self.dependency_cas_refs {
            digest(reference)?;
        }
        for reference in &self.evidence_refs {
            bounded_text(reference, 256)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryAssetKind {
    Skill,
    Instruction,
    Documentation,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InventorySourceScope {
    Repository,
    User,
    Plugin { plugin_id: String },
    OtherHost,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventorySource {
    pub scope: InventorySourceScope,
    pub root: Option<String>,
    /// False is unobserved, never an observed empty source.
    pub observed: bool,
    /// Only finite entries actually inspected for selection/enumeration. These
    /// are metadata identities, not a second payload or asset signature list.
    pub entries: Vec<InventoryPathState>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryPathState {
    pub path: String,
    pub directory: bool,
    /// Root selection depends on marker existence/type/identity, not the
    /// contents of a marker directory. Enumeration proofs remain stronger.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub selection_only: bool,
    pub identity: Option<InventoryPathIdentity>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryPathIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: u64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySignature {
    pub asset_kind: InventoryAssetKind,
    pub source_path: String,
    pub scope: InventorySourceScope,
    pub content_cas_ref: String,
    pub authored_name: Option<String>,
    pub authored_description: Option<String>,
    pub triggers: Option<Vec<String>>,
    pub preconditions: Option<Vec<String>>,
    pub key_actions: Option<Vec<String>>,
    pub outputs: Option<Vec<String>>,
    pub validation: Option<Vec<String>>,
    pub failure_boundaries: Option<Vec<String>>,
}

/// This body is serialized only after protection, and stored only in CAS.
/// Published Procedures remain their original revisions, not copied file assets.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityInventorySnapshot {
    pub sources: Vec<InventorySource>,
    pub signatures: Vec<CapabilitySignature>,
}

impl CapabilityInventorySnapshot {
    pub fn validate(&self) -> Result<(), InventoryError> {
        let mut sources = std::collections::BTreeSet::new();
        let mut entries = std::collections::BTreeSet::new();
        for source in &self.sources {
            if source.observed != source.root.is_some()
                || !sources.insert((&source.scope, &source.root))
                || source.scope == InventorySourceScope::OtherHost && source.observed
            {
                return Err(InventoryError::InvalidFact);
            }
            if let InventorySourceScope::Plugin { plugin_id } = &source.scope {
                bounded_text(plugin_id, 256)?;
            }
            if let Some(root) = &source.root {
                locator(root)?;
            }
            for entry in &source.entries {
                locator(&entry.path)?;
                if !source.observed
                    || !entries.insert(&entry.path)
                    || !source
                        .root
                        .as_ref()
                        .is_some_and(|root| std::path::Path::new(&entry.path).starts_with(root))
                    || entry.directory && entry.identity.is_none()
                {
                    return Err(InventoryError::InvalidFact);
                }
            }
        }
        if self.sources.is_empty() {
            return Err(InventoryError::InvalidFact);
        }
        let mut paths = std::collections::BTreeSet::new();
        for signature in &self.signatures {
            locator(&signature.source_path)?;
            digest(&signature.content_cas_ref)?;
            if !paths.insert((&signature.scope, &signature.source_path))
                || !self.sources.iter().any(|source| {
                    source.observed
                        && source.scope == signature.scope
                        && source.root.as_ref().is_some_and(|root| {
                            std::path::Path::new(&signature.source_path).starts_with(root)
                        })
                })
            {
                return Err(InventoryError::InvalidFact);
            }
            for value in [&signature.authored_name, &signature.authored_description]
                .into_iter()
                .flatten()
            {
                if value.is_empty() || value.len() > 4096 || value.contains('\0') {
                    return Err(InventoryError::InvalidFact);
                }
            }
            for values in [
                &signature.triggers,
                &signature.preconditions,
                &signature.key_actions,
                &signature.outputs,
                &signature.validation,
                &signature.failure_boundaries,
            ]
            .into_iter()
            .flatten()
            {
                for value in values {
                    bounded_text(value, 4096)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InventoryError {
    #[error("invalid finite capability inventory")]
    InvalidFact,
}

fn bounded_text(value: &str, limit: usize) -> Result<(), InventoryError> {
    if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
        return Err(InventoryError::InvalidFact);
    }
    Ok(())
}

fn locator(value: &str) -> Result<(), InventoryError> {
    bounded_text(value, 4096)?;
    if !value.starts_with('/')
        || value
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        return Err(InventoryError::InvalidFact);
    }
    Ok(())
}

fn digest(value: &str) -> Result<(), InventoryError> {
    let hex = value;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(InventoryError::InvalidFact);
    }
    Ok(())
}
