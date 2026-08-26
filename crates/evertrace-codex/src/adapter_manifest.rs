use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::source_catalog::{ELIGIBLE_CAPABILITIES, REQUIRED_FOR_FULL};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    CodexHook,
    CodexExecJsonl,
    CodexSessionJsonl,
    HermesSession,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventIdentity {
    StableNative,
    StableSourceSequence,
    SynthesizedBestEffort,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureGuarantee {
    Full,
    Partial,
    Opaque,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOrdering {
    FencedHost,
    BestEffort,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CueBoundary {
    PreRequest,
    NextModelRequest,
    UserTurnOnly,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubagentTrace {
    Full,
    ParentSummaryOnly,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustReadback {
    Supported,
    Inferred,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionFailureObservability {
    Complete,
    Reconcilable,
    BestEffort,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaxHostResolvedScope {
    Worktree,
    Repository,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectPolicySurface {
    pub policy_source_kind: String,
    pub max_host_resolved_scope: MaxHostResolvedScope,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservableCapability {
    DelegationStart,
    ChildSessionId,
    ChildToolCall,
    ChildToolResult,
    ChildFileChange,
    ChildPlan,
    ChildReasoningSummary,
    ChildFinalResult,
    DelegationEnd,
    RawHiddenReasoning,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterCapabilityManifest {
    pub adapter_manifest_id: String,
    pub adapter_kind: AdapterKind,
    pub adapter_version: String,
    pub host_version_range: String,
    pub eligible_event_manifest_refs: Vec<String>,
    pub event_identity: EventIdentity,
    pub capture_guarantee: CaptureGuarantee,
    pub recovery_ordering: RecoveryOrdering,
    pub cue_boundary: CueBoundary,
    pub subagent_trace: SubagentTrace,
    pub trust_readback: TrustReadback,
    pub project_policy_surfaces: Vec<ProjectPolicySurface>,
    pub admission_failure_observability: AdmissionFailureObservability,
    pub mcp_session_binding: crate::capability::McpSessionBinding,
    pub mcp_binding_mechanism: crate::capability::McpBindingMechanism,
    pub observable: Vec<ObservableCapability>,
    pub unavailable_by_design: Vec<ObservableCapability>,
    pub required_for_full: Vec<ObservableCapability>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManifestError {
    #[error("manifest contains an invalid scalar")]
    InvalidScalar,
    #[error("manifest contains a duplicate value")]
    Duplicate,
    #[error("manifest capability relationship is invalid")]
    InvalidCapabilityRelationship,
    #[error("manifest MCP binding relationship is invalid")]
    InvalidMcpBinding,
    #[error("manifest JSON is invalid")]
    InvalidJson,
    #[error("manifest revision does not match its content")]
    InvalidManifestId,
}

impl AdapterCapabilityManifest {
    pub fn validate(&self) -> Result<(), ManifestError> {
        for value in [
            self.adapter_manifest_id.as_str(),
            self.adapter_version.as_str(),
            self.host_version_range.as_str(),
        ] {
            if value.is_empty() || value.len() > 256 {
                return Err(ManifestError::InvalidScalar);
            }
        }
        require_unique_nonempty(&self.eligible_event_manifest_refs)?;
        let policy_kinds = self
            .project_policy_surfaces
            .iter()
            .map(|surface| surface.policy_source_kind.as_str())
            .collect::<Vec<_>>();
        if policy_kinds
            .iter()
            .any(|value| value.is_empty() || value.len() > 256)
            || policy_kinds.iter().collect::<BTreeSet<_>>().len() != policy_kinds.len()
        {
            return Err(ManifestError::InvalidScalar);
        }
        require_unique(&self.observable)?;
        require_unique(&self.unavailable_by_design)?;
        require_unique(&self.required_for_full)?;

        let observable = self.observable.iter().copied().collect::<BTreeSet<_>>();
        let unavailable = self
            .unavailable_by_design
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if !observable.is_disjoint(&unavailable)
            || self.required_for_full.as_slice() != REQUIRED_FOR_FULL
            || self
                .observable
                .iter()
                .chain(&self.unavailable_by_design)
                .any(|capability| !ELIGIBLE_CAPABILITIES.contains(capability))
            || !unavailable.contains(&ObservableCapability::RawHiddenReasoning)
            || observable.contains(&ObservableCapability::RawHiddenReasoning)
        {
            return Err(ManifestError::InvalidCapabilityRelationship);
        }
        if self.capture_guarantee == CaptureGuarantee::Full
            && (!self
                .required_for_full
                .iter()
                .all(|capability| observable.contains(capability))
                || self.subagent_trace != SubagentTrace::Full
                || self.event_identity == EventIdentity::SynthesizedBestEffort
                || !matches!(
                    self.admission_failure_observability,
                    AdmissionFailureObservability::Complete
                        | AdmissionFailureObservability::Reconcilable
                ))
        {
            return Err(ManifestError::InvalidCapabilityRelationship);
        }
        if self.capture_guarantee == CaptureGuarantee::Partial
            && !observable.contains(&ObservableCapability::ChildToolCall)
            && !observable.contains(&ObservableCapability::ChildToolResult)
            && !observable.contains(&ObservableCapability::ChildFileChange)
        {
            return Err(ManifestError::InvalidCapabilityRelationship);
        }
        if !crate::capability::valid_binding_pair(
            self.mcp_session_binding,
            self.mcp_binding_mechanism,
        ) {
            return Err(ManifestError::InvalidMcpBinding);
        }
        if self.adapter_manifest_id != self.content_revision()? {
            return Err(ManifestError::InvalidManifestId);
        }
        Ok(())
    }

    pub(crate) fn bind_content_revision(&mut self) -> Result<(), ManifestError> {
        self.adapter_manifest_id = self.content_revision()?;
        Ok(())
    }

    pub fn from_json(input: &str) -> Result<Self, ManifestError> {
        let manifest: Self = serde_json::from_str(input).map_err(|_| ManifestError::InvalidJson)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn to_json(&self) -> Result<String, ManifestError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|_| ManifestError::InvalidJson)
    }

    fn content_revision(&self) -> Result<String, ManifestError> {
        #[derive(Serialize)]
        struct Content<'a> {
            adapter_kind: AdapterKind,
            adapter_version: &'a str,
            host_version_range: &'a str,
            eligible_event_manifest_refs: &'a [String],
            event_identity: EventIdentity,
            capture_guarantee: CaptureGuarantee,
            recovery_ordering: RecoveryOrdering,
            cue_boundary: CueBoundary,
            subagent_trace: SubagentTrace,
            trust_readback: TrustReadback,
            project_policy_surfaces: &'a [ProjectPolicySurface],
            admission_failure_observability: AdmissionFailureObservability,
            mcp_session_binding: crate::capability::McpSessionBinding,
            mcp_binding_mechanism: crate::capability::McpBindingMechanism,
            observable: &'a [ObservableCapability],
            unavailable_by_design: &'a [ObservableCapability],
            required_for_full: &'a [ObservableCapability],
        }

        let content = Content {
            adapter_kind: self.adapter_kind,
            adapter_version: &self.adapter_version,
            host_version_range: &self.host_version_range,
            eligible_event_manifest_refs: &self.eligible_event_manifest_refs,
            event_identity: self.event_identity,
            capture_guarantee: self.capture_guarantee,
            recovery_ordering: self.recovery_ordering,
            cue_boundary: self.cue_boundary,
            subagent_trace: self.subagent_trace,
            trust_readback: self.trust_readback,
            project_policy_surfaces: &self.project_policy_surfaces,
            admission_failure_observability: self.admission_failure_observability,
            mcp_session_binding: self.mcp_session_binding,
            mcp_binding_mechanism: self.mcp_binding_mechanism,
            observable: &self.observable,
            unavailable_by_design: &self.unavailable_by_design,
            required_for_full: &self.required_for_full,
        };
        let bytes = serde_json::to_vec(&content).map_err(|_| ManifestError::InvalidJson)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

fn require_unique<T: Ord + Copy>(values: &[T]) -> Result<(), ManifestError> {
    if values.iter().copied().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ManifestError::Duplicate);
    }
    Ok(())
}

fn require_unique_nonempty<T: AsRef<str>>(values: &[T]) -> Result<(), ManifestError> {
    if values.is_empty()
        || values
            .iter()
            .any(|value| value.as_ref().is_empty() || value.as_ref().len() > 256)
        || values
            .iter()
            .map(AsRef::as_ref)
            .collect::<BTreeSet<_>>()
            .len()
            != values.len()
    {
        return Err(ManifestError::InvalidScalar);
    }
    Ok(())
}
