use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    adapter_manifest::{
        AdapterCapabilityManifest, AdapterKind, AdmissionFailureObservability, CaptureGuarantee,
        CueBoundary, EventIdentity, ManifestError, ObservableCapability, ProjectPolicySurface,
        RecoveryOrdering, SessionCatalogLocatorKind, SessionCatalogRootContract,
        SessionCatalogRootKind, SubagentTrace, TrustReadback,
    },
    capability::{
        CanaryStatus, HookProbeResult, McpBindingEvidence, McpProbeResult, McpSessionBinding,
        evaluate_hook,
    },
    hook_input::HookActivationEvidence,
    policy::{PolicyCandidateOrigin, PolicyEvidence, scope_within},
    source_catalog::{ELIGIBLE_CAPABILITIES, REQUIRED_FOR_FULL},
};

pub const CODEX_SESSION_LAYOUT_REVISION: &str = "codex_session_jsonl_v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateKind {
    CaptureComplete,
    RecoveryComplete,
    ActiveSearchDue,
    StrongHostOccurrenceNormalization,
    ProjectPolicyAuthority,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateResult {
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateReason {
    RequirementsSatisfied,
    MissingEvidence,
    EvidenceIntegrityFailed,
    ManifestInsufficient,
    SourceNotClosed,
    GapOrOutage,
    PairingIncomplete,
    SubagentTraceIncomplete,
    RecoveryNotFenced,
    RecoveryCanaryFailed,
    HookInactive,
    CueBoundaryUnavailable,
    SessionBindingUnproven,
    IdentityUnstable,
    CorrelationUnproven,
    PolicySurfaceUndeclared,
    PolicyNotLoaded,
    PolicyReadbackMismatch,
    PolicyRevoked,
    PolicyScopeUnresolved,
    TrustUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceKind {
    NoHostEvidence,
    OfficialCodexHookContract,
    ObservedHostCanary,
    SyntheticFixture,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeContext {
    pub adapter_kind: AdapterKind,
    pub adapter_revision: String,
    pub observed_host_version_range: String,
    pub eligible_event_manifest_ref: String,
    pub evidence_source: EvidenceSourceKind,
}

impl ProbeContext {
    pub fn unobserved_codex() -> Self {
        Self {
            adapter_kind: AdapterKind::CodexHook,
            adapter_revision: "codex-hook-probe-v1".into(),
            observed_host_version_range: "unobserved".into(),
            eligible_event_manifest_ref: crate::source_catalog::CODEX_ELIGIBLE_EVENT_MANIFEST
                .into(),
            evidence_source: EvidenceSourceKind::NoHostEvidence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureEvidence {
    pub evidence_refs: Vec<String>,
    pub source_identity: String,
    pub source_revision_refs: Vec<String>,
    pub eligible_event_manifest_refs: Vec<String>,
    pub close_watermark: u64,
    pub close_reconciled: bool,
    pub gap_count: u32,
    pub outage_count: u32,
    pub observed: Vec<ObservableCapability>,
    pub tool_calls: u32,
    pub tool_results: u32,
    pub subagent_starts: u32,
    pub subagent_terminals: u32,
    pub unresolved_liveness: u32,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub event_count: u32,
    pub protected_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationPairEvidence {
    pub native_request_id: String,
    pub pre_sequence: u64,
    pub post_sequence: Option<u64>,
    pub physical_execution_ordinal: u32,
    pub fence_completed: bool,
    pub replayed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEvidence {
    pub evidence_refs: Vec<String>,
    pub source_identity: String,
    pub mutation_domain_complete: bool,
    pub race_canary: CanaryStatus,
    pub pairs: Vec<MutationPairEvidence>,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub protected_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CueEvidence {
    pub evidence_refs: Vec<String>,
    pub compact_boundary: CanaryStatus,
    pub model_visible: bool,
    pub same_cwd_session_ids: Vec<String>,
    pub sessions_isolated: bool,
    pub protected_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceEvidence {
    pub source_ref: String,
    #[serde(default)]
    pub occurrence_schema_version: u32,
    #[serde(default)]
    pub host_instance_id: String,
    pub host_trace_lineage_id: String,
    pub host_lane_key: String,
    pub canonical_event_family: String,
    pub native_request_id: String,
    pub physical_execution_ordinal: u32,
    pub similarity_label: Option<String>,
    pub replayed: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizationCanaryEvidence {
    pub fork_isolated: bool,
    pub resume_isolated: bool,
    pub retry_ordinal_isolated: bool,
    pub replay_deduplicated: bool,
    pub nonidentity_similarity_not_merged: bool,
    pub missing_field_rejected: bool,
    pub field_conflict_rejected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizationEvidence {
    pub evidence_refs: Vec<String>,
    pub observations: Vec<OccurrenceEvidence>,
    pub fork_resume_retry_unique: bool,
    pub replay_rejected: bool,
    #[serde(default)]
    pub canaries: NormalizationCanaryEvidence,
    pub protected_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCatalogRootEvidence {
    pub root_kind: SessionCatalogRootKind,
    pub canonical_absolute_path: String,
    pub layout_revision: String,
    pub filesystem_device: u64,
    pub filesystem_inode: u64,
    pub canary: CanaryStatus,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCatalogRootState {
    Unavailable,
    Ready,
    HashChanged,
    CanaryFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCatalogRootResult {
    pub root_kind: SessionCatalogRootKind,
    pub state: SessionCatalogRootState,
    pub canonical_absolute_path: Option<String>,
    pub layout_revision: String,
    pub filesystem_device: Option<u64>,
    pub filesystem_inode: Option<u64>,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProbeEvidence {
    pub hook: Option<HookActivationEvidence>,
    pub capture: Option<CaptureEvidence>,
    pub recovery: Option<RecoveryEvidence>,
    pub cue: Option<CueEvidence>,
    pub mcp: Option<McpBindingEvidence>,
    pub normalization: Option<NormalizationEvidence>,
    pub policy: Option<PolicyEvidence>,
    pub session_catalog_roots: Vec<SessionCatalogRootEvidence>,
}

impl ProbeEvidence {
    pub const fn empty() -> Self {
        Self {
            hook: None,
            capture: None,
            recovery: None,
            cue: None,
            mcp: None,
            normalization: None,
            policy: None,
            session_catalog_roots: Vec::new(),
        }
    }

    pub fn from_json(input: &str) -> Result<Self, ProbeError> {
        serde_json::from_str(input).map_err(|_| ProbeError::InvalidEvidence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSummary {
    evidence_refs: Vec<String>,
    identity: Option<String>,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    event_count: u32,
    evidence_protected_digests: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateReceipt {
    gate_kind: GateKind,
    result: GateResult,
    reason: GateReason,
    adapter_manifest_revision: String,
    adapter_version: String,
    evidence: EvidenceSummary,
    protected_digest: String,
}

impl GateReceipt {
    pub const fn gate_kind(&self) -> GateKind {
        self.gate_kind
    }

    pub const fn result(&self) -> GateResult {
        self.result
    }

    pub const fn reason(&self) -> GateReason {
        self.reason
    }

    pub fn protected_digest(&self) -> &str {
        &self.protected_digest
    }

    pub fn adapter_manifest_revision(&self) -> &str {
        &self.adapter_manifest_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostProbeReport {
    manifest: AdapterCapabilityManifest,
    hook: HookProbeResult,
    mcp: McpProbeResult,
    capture: GateReceipt,
    recovery: GateReceipt,
    active_search_due: GateReceipt,
    strong_normalization: GateReceipt,
    project_policy: GateReceipt,
    session_catalog_roots: Vec<SessionCatalogRootResult>,
}

impl HostProbeReport {
    pub const fn manifest(&self) -> &AdapterCapabilityManifest {
        &self.manifest
    }

    pub const fn hook(&self) -> HookProbeResult {
        self.hook
    }

    pub const fn mcp(&self) -> McpProbeResult {
        self.mcp
    }

    pub const fn capture(&self) -> &GateReceipt {
        &self.capture
    }

    pub const fn recovery(&self) -> &GateReceipt {
        &self.recovery
    }

    /// The runtime snapshot may enable the synchronous barrier only from
    /// this positive, canary-backed receipt. Input payloads never self-enable
    /// the gate.
    pub fn recovery_barrier_active(&self) -> bool {
        self.recovery.gate_kind == GateKind::RecoveryComplete
            && self.recovery.result == GateResult::Enabled
            && self.recovery.reason == GateReason::RequirementsSatisfied
    }

    pub const fn active_search_due(&self) -> &GateReceipt {
        &self.active_search_due
    }

    pub const fn strong_normalization(&self) -> &GateReceipt {
        &self.strong_normalization
    }

    pub const fn project_policy(&self) -> &GateReceipt {
        &self.project_policy
    }

    pub fn session_catalog_roots(&self) -> &[SessionCatalogRootResult] {
        &self.session_catalog_roots
    }

    /// Verifies that `evidence` is the exact policy evidence used by this
    /// report's enabled project-policy gate.
    ///
    /// Callers must use this check instead of treating a manifest surface or
    /// a caller-constructed [`PolicyEvidence`] as authority on its own.
    pub fn verify_project_policy_evidence(
        &self,
        evidence: &PolicyEvidence,
    ) -> Result<(), ProbeError> {
        let recomputed = policy_receipt(
            &self.manifest,
            EvidenceSourceKind::ObservedHostCanary,
            Some(evidence),
        )?;
        let surface_matches = evidence.resolved_scope.is_some_and(|resolved_scope| {
            self.manifest.project_policy_surfaces.len() == 1
                && self.manifest.project_policy_surfaces[0].policy_source_kind
                    == evidence.policy_source_kind
                && self.manifest.project_policy_surfaces[0].max_host_resolved_scope
                    == resolved_scope
        });
        if self.project_policy.gate_kind != GateKind::ProjectPolicyAuthority
            || self.project_policy.result != GateResult::Enabled
            || self.project_policy.reason != GateReason::RequirementsSatisfied
            || self.project_policy.adapter_manifest_revision != self.manifest.adapter_manifest_id
            || recomputed != self.project_policy
            || !surface_matches
        {
            return Err(ProbeError::InvalidEvidence);
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, ProbeError> {
        serde_json::to_string(self).map_err(|_| ProbeError::Serialization)
    }

    pub fn evaluate(context: &ProbeContext, evidence: &ProbeEvidence) -> Result<Self, ProbeError> {
        let manifest = compile_manifest(context, evidence)?;
        let hook = evaluate_hook(evidence.hook.as_ref());
        let mcp = evidence
            .mcp
            .as_ref()
            .map_or_else(unavailable_mcp, McpBindingEvidence::evaluate);
        Ok(Self {
            manifest: manifest.clone(),
            hook,
            mcp,
            capture: capture_receipt(&manifest, evidence.capture.as_ref())?,
            recovery: recovery_receipt(
                &manifest,
                context.evidence_source,
                evidence.recovery.as_ref(),
            )?,
            active_search_due: due_receipt(
                &manifest,
                evidence.hook.as_ref(),
                evidence.cue.as_ref(),
                evidence.mcp.as_ref(),
                hook,
                mcp,
            )?,
            strong_normalization: normalization_receipt(
                context.evidence_source,
                &manifest,
                evidence.normalization.as_ref(),
            )?,
            project_policy: policy_receipt(
                &manifest,
                context.evidence_source,
                evidence.policy.as_ref(),
            )?,
            session_catalog_roots: session_catalog_roots(
                context.evidence_source,
                &manifest,
                &evidence.session_catalog_roots,
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProbeError {
    #[error(transparent)]
    InvalidManifest(#[from] ManifestError),
    #[error("probe evidence JSON is invalid")]
    InvalidEvidence,
    #[error("probe receipt serialization failed")]
    Serialization,
}

fn compile_manifest(
    context: &ProbeContext,
    evidence: &ProbeEvidence,
) -> Result<AdapterCapabilityManifest, ProbeError> {
    let observable = evidence
        .capture
        .as_ref()
        .map(|capture| {
            capture
                .observed
                .iter()
                .copied()
                .filter(|capability| {
                    *capability != ObservableCapability::RawHiddenReasoning
                        && ELIGIBLE_CAPABILITIES.contains(capability)
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let observable_set = observable.iter().copied().collect::<BTreeSet<_>>();
    let has_required = REQUIRED_FOR_FULL
        .iter()
        .all(|capability| observable_set.contains(capability));
    let source_can_prove_full = matches!(
        context.evidence_source,
        EvidenceSourceKind::ObservedHostCanary | EvidenceSourceKind::SyntheticFixture
    );
    let full_trace = source_can_prove_full
        && has_required
        && evidence.capture.as_ref().is_some_and(|capture| {
            capture.subagent_starts == capture.subagent_terminals
                && capture.unresolved_liveness == 0
        });
    let subagent_trace = if full_trace {
        SubagentTrace::Full
    } else if observable_set.contains(&ObservableCapability::ChildFinalResult)
        || observable_set.contains(&ObservableCapability::DelegationEnd)
    {
        SubagentTrace::ParentSummaryOnly
    } else {
        SubagentTrace::Unavailable
    };
    let admission_failure_observability =
        evidence
            .capture
            .as_ref()
            .map_or(AdmissionFailureObservability::Unavailable, |capture| {
                if capture.close_reconciled && !capture.source_revision_refs.is_empty() {
                    AdmissionFailureObservability::Reconcilable
                } else {
                    AdmissionFailureObservability::BestEffort
                }
            });
    let event_identity = if evidence
        .normalization
        .as_ref()
        .is_some_and(|normalization| {
            normalization.fork_resume_retry_unique && normalization.replay_rejected
        }) {
        EventIdentity::StableNative
    } else if evidence.capture.as_ref().is_some_and(|capture| {
        !capture.source_identity.is_empty() && !capture.source_revision_refs.is_empty()
    }) {
        EventIdentity::StableSourceSequence
    } else {
        EventIdentity::SynthesizedBestEffort
    };
    let capture_guarantee = if source_can_prove_full
        && has_required
        && full_trace
        && event_identity != EventIdentity::SynthesizedBestEffort
        && matches!(
            admission_failure_observability,
            AdmissionFailureObservability::Complete | AdmissionFailureObservability::Reconcilable
        ) {
        CaptureGuarantee::Full
    } else if observable_set.contains(&ObservableCapability::ChildToolCall)
        || observable_set.contains(&ObservableCapability::ChildToolResult)
        || observable_set.contains(&ObservableCapability::ChildFileChange)
    {
        CaptureGuarantee::Partial
    } else {
        CaptureGuarantee::Opaque
    };
    let recovery_ordering = if context.evidence_source != EvidenceSourceKind::ObservedHostCanary {
        RecoveryOrdering::Unavailable
    } else {
        evidence
            .recovery
            .as_ref()
            .map_or(RecoveryOrdering::Unavailable, |recovery| {
                if recovery.mutation_domain_complete
                    && recovery.race_canary == CanaryStatus::Passed
                    && !recovery.pairs.is_empty()
                    && recovery.pairs.iter().all(|pair| {
                        pair.fence_completed
                            && !pair.replayed
                            && pair
                                .post_sequence
                                .is_some_and(|post| post > pair.pre_sequence)
                    })
                {
                    RecoveryOrdering::FencedHost
                } else {
                    RecoveryOrdering::BestEffort
                }
            })
    };
    let cue_boundary = evidence
        .cue
        .as_ref()
        .map_or(CueBoundary::Unavailable, |cue| {
            if cue.compact_boundary == CanaryStatus::Passed && cue.model_visible {
                CueBoundary::NextModelRequest
            } else {
                CueBoundary::Unavailable
            }
        });
    let policy_surface = evidence.policy.as_ref().and_then(|policy| {
        (policy.origin == PolicyCandidateOrigin::HostPolicySurface
            && policy.host_loaded
            && policy.readback_supported
            && policy.readback_matches
            && policy.current_trust
            && policy.current
            && !policy.revoked
            && !policy.policy_source_kind.is_empty()
            && policy.resolved_scope.is_some())
        .then(|| ProjectPolicySurface {
            policy_source_kind: policy.policy_source_kind.clone(),
            max_host_resolved_scope: policy
                .resolved_scope
                .expect("surface requires a resolved scope"),
        })
    });
    let mcp = evidence
        .mcp
        .as_ref()
        .map_or_else(unavailable_mcp, McpBindingEvidence::evaluate);
    let mut manifest = AdapterCapabilityManifest {
        adapter_manifest_id: String::new(),
        adapter_kind: context.adapter_kind,
        adapter_version: context.adapter_revision.clone(),
        host_version_range: context.observed_host_version_range.clone(),
        eligible_event_manifest_refs: vec![context.eligible_event_manifest_ref.clone()],
        event_identity,
        capture_guarantee,
        recovery_ordering,
        cue_boundary,
        subagent_trace,
        trust_readback: if policy_surface.is_some() {
            TrustReadback::Supported
        } else {
            TrustReadback::Unavailable
        },
        project_policy_surfaces: policy_surface.into_iter().collect(),
        session_catalog_root_contracts: matches!(
            context.adapter_kind,
            AdapterKind::CodexHook | AdapterKind::CodexSessionJsonl
        )
        .then(|| SessionCatalogRootContract {
            root_kind: SessionCatalogRootKind::CodexSessions,
            locator_kind: SessionCatalogLocatorKind::HostResolved,
            layout_revision: CODEX_SESSION_LAYOUT_REVISION.into(),
        })
        .into_iter()
        .collect(),
        admission_failure_observability,
        mcp_session_binding: mcp.binding,
        mcp_binding_mechanism: mcp.mechanism,
        observable,
        unavailable_by_design: vec![ObservableCapability::RawHiddenReasoning],
        required_for_full: REQUIRED_FOR_FULL.to_vec(),
    };
    manifest.bind_content_revision()?;
    manifest.validate()?;
    Ok(manifest)
}

fn session_catalog_roots(
    source: EvidenceSourceKind,
    manifest: &AdapterCapabilityManifest,
    evidence: &[SessionCatalogRootEvidence],
) -> Vec<SessionCatalogRootResult> {
    manifest
        .session_catalog_root_contracts
        .iter()
        .map(|contract| {
            let matches = evidence
                .iter()
                .filter(|value| value.root_kind == contract.root_kind)
                .collect::<Vec<_>>();
            let unavailable = || SessionCatalogRootResult {
                root_kind: contract.root_kind,
                state: SessionCatalogRootState::Unavailable,
                canonical_absolute_path: None,
                layout_revision: contract.layout_revision.clone(),
                filesystem_device: None,
                filesystem_inode: None,
                evidence_refs: Vec::new(),
            };
            if source != EvidenceSourceKind::ObservedHostCanary || matches.is_empty() {
                return unavailable();
            }
            if matches.len() != 1 {
                return SessionCatalogRootResult {
                    state: SessionCatalogRootState::CanaryFailed,
                    ..unavailable()
                };
            }
            let value = matches[0];
            let path = std::path::Path::new(&value.canonical_absolute_path);
            let refs_valid = !value.evidence_refs.is_empty()
                && value.evidence_refs.len() <= 32
                && value
                    .evidence_refs
                    .iter()
                    .all(|item| !item.is_empty() && item.len() <= 512)
                && value.evidence_refs.windows(2).all(|pair| pair[0] < pair[1]);
            let path_valid = path.is_absolute()
                && value.canonical_absolute_path.len() <= 4096
                && !value
                    .canonical_absolute_path
                    .bytes()
                    .any(|byte| byte.is_ascii_control())
                && !path.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                });
            let state = if value.layout_revision != contract.layout_revision {
                SessionCatalogRootState::HashChanged
            } else if value.canary == CanaryStatus::Failed
                || !path_valid
                || !refs_valid
                || value.filesystem_device == 0
                || value.filesystem_inode == 0
            {
                SessionCatalogRootState::CanaryFailed
            } else if value.canary == CanaryStatus::Passed {
                SessionCatalogRootState::Ready
            } else {
                SessionCatalogRootState::Unavailable
            };
            if state != SessionCatalogRootState::Ready {
                return SessionCatalogRootResult {
                    state,
                    ..unavailable()
                };
            }
            SessionCatalogRootResult {
                root_kind: contract.root_kind,
                state,
                canonical_absolute_path: Some(value.canonical_absolute_path.clone()),
                layout_revision: contract.layout_revision.clone(),
                filesystem_device: Some(value.filesystem_device),
                filesystem_inode: Some(value.filesystem_inode),
                evidence_refs: value.evidence_refs.clone(),
            }
        })
        .collect()
}

fn capture_receipt(
    manifest: &AdapterCapabilityManifest,
    evidence: Option<&CaptureEvidence>,
) -> Result<GateReceipt, ProbeError> {
    let Some(evidence) = evidence else {
        return receipt(
            GateKind::CaptureComplete,
            GateReason::MissingEvidence,
            manifest,
            empty_summary(),
        );
    };
    let summary = EvidenceSummary {
        evidence_refs: evidence.evidence_refs.clone(),
        identity: Some(evidence.source_identity.clone()),
        first_sequence: Some(evidence.first_sequence),
        last_sequence: Some(evidence.last_sequence),
        event_count: evidence.event_count,
        evidence_protected_digests: vec![evidence.protected_digest.clone()],
    };
    let contiguous_count = evidence
        .last_sequence
        .checked_sub(evidence.first_sequence)
        .and_then(|value| value.checked_add(1));
    let observed_unique = evidence
        .observed
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .len()
        == evidence.observed.len();
    let reason = if !valid_summary(&summary)
        || evidence.source_identity.is_empty()
        || !valid_refs(&evidence.source_revision_refs)
        || !observed_unique
        || evidence.first_sequence > evidence.last_sequence
        || evidence.close_watermark < evidence.last_sequence
        || contiguous_count != Some(u64::from(evidence.event_count))
    {
        GateReason::EvidenceIntegrityFailed
    } else if evidence.eligible_event_manifest_refs != manifest.eligible_event_manifest_refs
        || evidence.close_watermark == 0
        || !evidence.close_reconciled
    {
        GateReason::SourceNotClosed
    } else if evidence.gap_count != 0 || evidence.outage_count != 0 {
        GateReason::GapOrOutage
    } else if evidence.tool_calls != evidence.tool_results
        || !manifest
            .required_for_full
            .iter()
            .all(|required| evidence.observed.contains(required))
    {
        GateReason::PairingIncomplete
    } else if evidence.subagent_starts != evidence.subagent_terminals
        || evidence.unresolved_liveness != 0
    {
        GateReason::SubagentTraceIncomplete
    } else if manifest.capture_guarantee != CaptureGuarantee::Full
        || !matches!(
            manifest.admission_failure_observability,
            AdmissionFailureObservability::Complete | AdmissionFailureObservability::Reconcilable
        )
        || manifest.subagent_trace != SubagentTrace::Full
        || manifest.event_identity == EventIdentity::SynthesizedBestEffort
    {
        GateReason::ManifestInsufficient
    } else {
        GateReason::RequirementsSatisfied
    };
    receipt(GateKind::CaptureComplete, reason, manifest, summary)
}

fn recovery_receipt(
    manifest: &AdapterCapabilityManifest,
    evidence_source: EvidenceSourceKind,
    evidence: Option<&RecoveryEvidence>,
) -> Result<GateReceipt, ProbeError> {
    let Some(evidence) = evidence else {
        return receipt(
            GateKind::RecoveryComplete,
            GateReason::MissingEvidence,
            manifest,
            empty_summary(),
        );
    };
    let summary = EvidenceSummary {
        evidence_refs: evidence.evidence_refs.clone(),
        identity: Some(evidence.source_identity.clone()),
        first_sequence: Some(evidence.first_sequence),
        last_sequence: Some(evidence.last_sequence),
        event_count: evidence.pairs.len() as u32 * 2,
        evidence_protected_digests: vec![evidence.protected_digest.clone()],
    };
    let mut identities = BTreeSet::new();
    let pairs_valid = !evidence.pairs.is_empty()
        && evidence.pairs.iter().all(|pair| {
            !pair.native_request_id.is_empty()
                && identities.insert((
                    pair.native_request_id.as_str(),
                    pair.physical_execution_ordinal,
                ))
                && pair
                    .post_sequence
                    .is_some_and(|post| post > pair.pre_sequence)
                && pair.fence_completed
                && !pair.replayed
        });
    let reason = if evidence_source != EvidenceSourceKind::ObservedHostCanary {
        GateReason::RecoveryCanaryFailed
    } else if !valid_summary(&summary)
        || evidence.source_identity.is_empty()
        || evidence.first_sequence > evidence.last_sequence
    {
        GateReason::EvidenceIntegrityFailed
    } else if !evidence.mutation_domain_complete || !pairs_valid {
        GateReason::RecoveryNotFenced
    } else if evidence.race_canary != CanaryStatus::Passed {
        GateReason::RecoveryCanaryFailed
    } else if manifest.recovery_ordering != RecoveryOrdering::FencedHost {
        GateReason::ManifestInsufficient
    } else {
        GateReason::RequirementsSatisfied
    };
    receipt(GateKind::RecoveryComplete, reason, manifest, summary)
}

fn due_receipt(
    manifest: &AdapterCapabilityManifest,
    hook_evidence: Option<&HookActivationEvidence>,
    evidence: Option<&CueEvidence>,
    mcp_evidence: Option<&McpBindingEvidence>,
    hook: HookProbeResult,
    mcp: McpProbeResult,
) -> Result<GateReceipt, ProbeError> {
    let Some(evidence) = evidence else {
        return receipt(
            GateKind::ActiveSearchDue,
            GateReason::MissingEvidence,
            manifest,
            empty_summary(),
        );
    };
    let mut evidence_refs = evidence.evidence_refs.clone();
    let mut evidence_protected_digests = vec![evidence.protected_digest.clone()];
    if let Some(hook_evidence) = hook_evidence {
        evidence_refs.extend(hook_evidence.evidence_refs.clone());
        evidence_protected_digests.extend(hook_evidence.protected_digest.clone());
    }
    if let Some(mcp_evidence) = mcp_evidence {
        evidence_refs.extend(mcp_evidence.evidence_refs().iter().cloned());
        evidence_protected_digests.extend(mcp_evidence.protected_digest().map(str::to_owned));
    }
    let summary = EvidenceSummary {
        evidence_refs,
        identity: mcp_evidence
            .and_then(McpBindingEvidence::session_identity)
            .map(str::to_owned),
        first_sequence: None,
        last_sequence: None,
        event_count: evidence.same_cwd_session_ids.len() as u32,
        evidence_protected_digests,
    };
    let sessions = evidence
        .same_cwd_session_ids
        .iter()
        .collect::<BTreeSet<_>>();
    let reason = if !valid_summary(&summary)
        || evidence.same_cwd_session_ids.iter().any(String::is_empty)
        || sessions.len() != evidence.same_cwd_session_ids.len()
        || evidence.same_cwd_session_ids.len() < 2
    {
        GateReason::EvidenceIntegrityFailed
    } else if hook.activation != crate::capability::HookActivation::Active {
        GateReason::HookInactive
    } else if evidence.compact_boundary != CanaryStatus::Passed || !evidence.model_visible {
        GateReason::CueBoundaryUnavailable
    } else if !evidence.sessions_isolated
        || !matches!(
            mcp.binding,
            McpSessionBinding::Exact | McpSessionBinding::ConnectionScoped
        )
    {
        GateReason::SessionBindingUnproven
    } else if manifest.cue_boundary == CueBoundary::Unavailable
        || !matches!(
            manifest.mcp_session_binding,
            McpSessionBinding::Exact | McpSessionBinding::ConnectionScoped
        )
    {
        GateReason::ManifestInsufficient
    } else {
        GateReason::RequirementsSatisfied
    };
    receipt(GateKind::ActiveSearchDue, reason, manifest, summary)
}

fn normalization_receipt(
    evidence_source: EvidenceSourceKind,
    manifest: &AdapterCapabilityManifest,
    evidence: Option<&NormalizationEvidence>,
) -> Result<GateReceipt, ProbeError> {
    let Some(evidence) = evidence else {
        return receipt(
            GateKind::StrongHostOccurrenceNormalization,
            GateReason::MissingEvidence,
            manifest,
            empty_summary(),
        );
    };
    let summary = EvidenceSummary {
        evidence_refs: evidence.evidence_refs.clone(),
        identity: evidence.observations.first().map(exact_occurrence_identity),
        first_sequence: None,
        last_sequence: None,
        event_count: evidence.observations.len() as u32,
        evidence_protected_digests: vec![evidence.protected_digest.clone()],
    };
    let mut groups: BTreeMap<ExactOccurrenceCanaryKey<'_>, BTreeSet<&str>> = BTreeMap::new();
    for observation in &evidence.observations {
        if !observation.replayed {
            groups
                .entry(exact_occurrence_key(observation))
                .or_default()
                .insert(&observation.source_ref);
        }
    }
    let exact_cross_source = groups.values().any(|sources| sources.len() >= 2);
    let observations_valid = evidence.observations.iter().all(|observation| {
        !observation.source_ref.is_empty()
            && observation.occurrence_schema_version != 0
            && !observation.host_instance_id.is_empty()
            && !observation.host_trace_lineage_id.is_empty()
            && !observation.host_lane_key.is_empty()
            && !observation.canonical_event_family.is_empty()
            && !observation.native_request_id.is_empty()
    }) && evidence.observations.iter().collect::<BTreeSet<_>>().len()
        == evidence.observations.len();
    let reason = if !valid_summary(&summary) || !observations_valid {
        GateReason::EvidenceIntegrityFailed
    } else if !matches!(
        manifest.event_identity,
        EventIdentity::StableNative | EventIdentity::StableSourceSequence
    ) {
        GateReason::ManifestInsufficient
    } else if !matches!(
        evidence_source,
        EvidenceSourceKind::ObservedHostCanary | EvidenceSourceKind::OfficialCodexHookContract
    ) {
        GateReason::CorrelationUnproven
    } else if !evidence.fork_resume_retry_unique
        || !evidence.replay_rejected
        || !evidence.canaries.fork_isolated
        || !evidence.canaries.resume_isolated
        || !evidence.canaries.retry_ordinal_isolated
        || !evidence.canaries.replay_deduplicated
        || !evidence.canaries.nonidentity_similarity_not_merged
        || !evidence.canaries.missing_field_rejected
        || !evidence.canaries.field_conflict_rejected
    {
        GateReason::IdentityUnstable
    } else if !exact_cross_source {
        GateReason::CorrelationUnproven
    } else {
        GateReason::RequirementsSatisfied
    };
    receipt(
        GateKind::StrongHostOccurrenceNormalization,
        reason,
        manifest,
        summary,
    )
}

type ExactOccurrenceCanaryKey<'a> = (u32, &'a str, &'a str, &'a str, &'a str, &'a str, u32);

fn policy_receipt(
    manifest: &AdapterCapabilityManifest,
    evidence_source: EvidenceSourceKind,
    evidence: Option<&PolicyEvidence>,
) -> Result<GateReceipt, ProbeError> {
    let Some(evidence) = evidence else {
        return receipt(
            GateKind::ProjectPolicyAuthority,
            GateReason::MissingEvidence,
            manifest,
            empty_summary(),
        );
    };
    let summary = EvidenceSummary {
        evidence_refs: evidence.evidence_refs.clone(),
        identity: Some(evidence.source_revision.clone()),
        first_sequence: None,
        last_sequence: None,
        event_count: 1,
        evidence_protected_digests: vec![evidence.content_digest.clone()],
    };
    let surface = manifest
        .project_policy_surfaces
        .iter()
        .find(|surface| surface.policy_source_kind == evidence.policy_source_kind);
    let reason = if evidence_source != EvidenceSourceKind::ObservedHostCanary {
        GateReason::TrustUnavailable
    } else if !valid_summary(&summary)
        || evidence.policy_source_kind.is_empty()
        || evidence.source_revision.is_empty()
    {
        GateReason::EvidenceIntegrityFailed
    } else if evidence.origin != PolicyCandidateOrigin::HostPolicySurface {
        GateReason::PolicySurfaceUndeclared
    } else if !evidence.current_trust {
        GateReason::TrustUnavailable
    } else if !evidence.host_loaded {
        GateReason::PolicyNotLoaded
    } else if !evidence.readback_supported || !evidence.readback_matches {
        GateReason::PolicyReadbackMismatch
    } else if evidence.revoked || !evidence.current {
        GateReason::PolicyRevoked
    } else if evidence.resolved_scope.is_none_or(|scope| {
        surface.is_none_or(|surface| !scope_within(scope, surface.max_host_resolved_scope))
    }) {
        GateReason::PolicyScopeUnresolved
    } else if manifest.trust_readback != TrustReadback::Supported || surface.is_none() {
        GateReason::PolicySurfaceUndeclared
    } else {
        GateReason::RequirementsSatisfied
    };
    receipt(GateKind::ProjectPolicyAuthority, reason, manifest, summary)
}

fn exact_occurrence_key(value: &OccurrenceEvidence) -> (u32, &str, &str, &str, &str, &str, u32) {
    (
        value.occurrence_schema_version,
        &value.host_instance_id,
        &value.host_trace_lineage_id,
        &value.host_lane_key,
        &value.canonical_event_family,
        &value.native_request_id,
        value.physical_execution_ordinal,
    )
}

fn exact_occurrence_identity(value: &OccurrenceEvidence) -> String {
    let mut identity = value.occurrence_schema_version.to_string();
    for component in [
        value.host_instance_id.as_str(),
        value.host_trace_lineage_id.as_str(),
        value.host_lane_key.as_str(),
        value.canonical_event_family.as_str(),
        value.native_request_id.as_str(),
    ] {
        use std::fmt::Write as _;
        let _ = write!(identity, "{}:{component}", component.len());
    }
    use std::fmt::Write as _;
    let _ = write!(identity, ":{}", value.physical_execution_ordinal);
    identity
}

fn unavailable_mcp() -> McpProbeResult {
    McpBindingEvidence::Unavailable.evaluate()
}

fn empty_summary() -> EvidenceSummary {
    EvidenceSummary {
        evidence_refs: Vec::new(),
        identity: None,
        first_sequence: None,
        last_sequence: None,
        event_count: 0,
        evidence_protected_digests: Vec::new(),
    }
}

fn valid_summary(summary: &EvidenceSummary) -> bool {
    valid_refs(&summary.evidence_refs)
        && !summary.evidence_protected_digests.is_empty()
        && summary
            .evidence_protected_digests
            .iter()
            .all(|value| valid_digest(value))
}

fn valid_refs(values: &[String]) -> bool {
    !values.is_empty()
        && values.iter().all(|value| !value.is_empty())
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn receipt(
    gate_kind: GateKind,
    reason: GateReason,
    manifest: &AdapterCapabilityManifest,
    evidence: EvidenceSummary,
) -> Result<GateReceipt, ProbeError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        gate_kind: GateKind,
        result: GateResult,
        reason: GateReason,
        adapter_manifest_revision: &'a str,
        adapter_version: &'a str,
        evidence: &'a EvidenceSummary,
    }

    let result = if reason == GateReason::RequirementsSatisfied {
        GateResult::Enabled
    } else {
        GateResult::Disabled
    };
    let digest_input = DigestInput {
        gate_kind,
        result,
        reason,
        adapter_manifest_revision: &manifest.adapter_manifest_id,
        adapter_version: &manifest.adapter_version,
        evidence: &evidence,
    };
    let bytes = serde_json::to_vec(&digest_input).map_err(|_| ProbeError::Serialization)?;
    let protected_digest = format!("{:x}", Sha256::digest(bytes));
    Ok(GateReceipt {
        gate_kind,
        result,
        reason,
        adapter_manifest_revision: manifest.adapter_manifest_id.clone(),
        adapter_version: manifest.adapter_version.clone(),
        evidence,
        protected_digest,
    })
}
