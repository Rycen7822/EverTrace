#![forbid(unsafe_code)]
#![deny(warnings)]

//! Strict Codex adapter manifest and deterministic host probes.

pub mod adapter_manifest;
pub mod binding;
pub mod capability;
pub mod hook_input;
pub mod install;
pub mod policy;
pub mod probe;
pub mod recovery;
pub mod session_import;
pub mod source_catalog;

pub use adapter_manifest::{AdapterCapabilityManifest, ManifestError};
pub use capability::{
    CanaryStatus, HookActivation, HookDiagnostic, McpBindingMechanism, McpProbeResult,
    McpSessionBinding,
};
pub use probe::{
    EvidenceSourceKind, GateKind, GateReason, GateResult, HostProbeReport, ProbeContext,
    ProbeError, ProbeEvidence,
};
