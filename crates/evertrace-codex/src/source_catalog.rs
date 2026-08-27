use std::collections::BTreeSet;

use crate::adapter_manifest::{AdapterCapabilityManifest, ManifestError, ObservableCapability};

pub const CODEX_ELIGIBLE_EVENT_MANIFEST: &str = "codex_host_events_v1";

pub const REQUIRED_FOR_FULL: [ObservableCapability; 4] = [
    ObservableCapability::ChildSessionId,
    ObservableCapability::ChildToolCall,
    ObservableCapability::ChildToolResult,
    ObservableCapability::ChildFinalResult,
];

pub const ELIGIBLE_CAPABILITIES: [ObservableCapability; 10] = [
    ObservableCapability::DelegationStart,
    ObservableCapability::ChildSessionId,
    ObservableCapability::ChildToolCall,
    ObservableCapability::ChildToolResult,
    ObservableCapability::ChildFileChange,
    ObservableCapability::ChildPlan,
    ObservableCapability::ChildReasoningSummary,
    ObservableCapability::ChildFinalResult,
    ObservableCapability::DelegationEnd,
    ObservableCapability::RawHiddenReasoning,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledCaptureContract {
    pub adapter_manifest_ref: String,
    pub eligible_event_manifest_refs: Vec<String>,
    pub observed: BTreeSet<String>,
    pub required_for_full: BTreeSet<String>,
    pub missing_required: BTreeSet<String>,
}

pub fn compile_capture_contract(
    manifest: &AdapterCapabilityManifest,
    observations: impl IntoIterator<Item = ObservableCapability>,
) -> Result<CompiledCaptureContract, ManifestError> {
    manifest.validate()?;
    let eligible = manifest.observable.iter().copied().collect::<BTreeSet<_>>();
    let observed_capabilities = observations.into_iter().collect::<BTreeSet<_>>();
    if !observed_capabilities.is_subset(&eligible) {
        return Err(ManifestError::InvalidCapabilityRelationship);
    }
    let observed = observed_capabilities
        .iter()
        .map(|capability| capability.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let required_for_full = manifest
        .required_for_full
        .iter()
        .map(|capability| capability.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let missing_required = required_for_full.difference(&observed).cloned().collect();
    Ok(CompiledCaptureContract {
        adapter_manifest_ref: manifest.adapter_manifest_id.clone(),
        eligible_event_manifest_refs: manifest.eligible_event_manifest_refs.clone(),
        observed,
        required_for_full,
        missing_required,
    })
}
