use serde::{Deserialize, Serialize};

use evertrace_domain::evidence::{
    CorrelationAdmission, EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength,
    ScopeEffectClaim, SourceRevisionMode,
};
use evertrace_domain::work::LaneLifecycleEvidence;

use crate::capability::CanaryStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookEventKind {
    PreToolUse,
    PostToolUse,
    SubagentStart,
    SubagentTerminal,
    Compact,
    SourceClose,
    ParentSessionEnd,
    LivenessProbe,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedHookEvent {
    pub evidence_ref: String,
    pub event_kind: HookEventKind,
    pub session_id: String,
    pub lane_id: String,
    pub native_request_id: Option<String>,
    pub sequence: u64,
    pub physical_execution_ordinal: u32,
    pub protected_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HookActivationEvidence {
    pub wiring_detected: bool,
    pub trusted: bool,
    pub enabled: bool,
    pub expected_hash: Option<String>,
    pub observed_hash: Option<String>,
    pub canary: CanaryStatus,
    pub evidence_refs: Vec<String>,
    pub protected_digest: Option<String>,
}

pub const CAPTURE_HOOK_INPUT_VERSION: u16 = 5;
pub const MAX_CAPTURE_HOOK_INPUT: usize = 1_048_576;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureHookInput {
    pub input_version: u16,
    pub spool_record_id: Option<String>,
    pub source_observation_id_hint: Option<String>,
    pub source_instance_id: String,
    pub source_revision: String,
    pub source_record_identity: Option<String>,
    pub identity_strength: Option<IdentityStrength>,
    pub source_kind: EvidenceSourceKind,
    pub identity_domain: String,
    pub adapter_manifest_ref: String,
    pub eligible_event_manifest_ref: String,
    pub source_revision_mode: SourceRevisionMode,
    pub previous_source_revision: Option<String>,
    pub source_ref: String,
    pub session_id: String,
    pub turn_id: Option<String>,
    pub tool_use_id: Option<String>,
    pub event_kind: HookEventKind,
    pub correlation: HostCorrelationEvidence,
    pub scope_effect_claims: Vec<ScopeEffectClaim>,
    pub lifecycle: Option<LaneLifecycleEvidence>,
    pub source_sequence: u64,
    #[serde(default)]
    pub source_sequence_origin: Option<u64>,
    pub task_id: Option<String>,
    pub repository_instance_id: Option<String>,
    pub worktree_instance_id: Option<String>,
    pub event_time_us: Option<i64>,
    pub payload: String,
}

impl std::fmt::Debug for CaptureHookInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureHookInput")
            .field("input_version", &self.input_version)
            .field("source_instance_id", &self.source_instance_id)
            .field("source_revision", &self.source_revision)
            .field("event_kind", &self.event_kind)
            .field("source_sequence", &self.source_sequence)
            .field("payload_length", &self.payload.len())
            .finish()
    }
}

pub fn native_generation_report(
    generation: u64,
) -> Result<crate::probe::HostProbeReport, HookInputError> {
    if generation == 0 {
        return Err(HookInputError::Invalid);
    }
    let mut context = crate::probe::ProbeContext::unobserved_codex();
    context.adapter_revision = format!("native-hook-v1-generation-{generation}");
    crate::probe::HostProbeReport::evaluate(&context, &crate::probe::ProbeEvidence::empty())
        .map_err(|_| HookInputError::Invalid)
}

impl CaptureHookInput {
    /// Recognizes only the ordinary, independently weak native-delivery profile.
    /// Internal v5 callers do not gain namespace authority by supplying a field.
    pub fn native_source_call(&self) -> Option<evertrace_domain::evidence::SourceLocalNativeCall> {
        if self.identity_domain != "native-hook-delivery-v1"
            || self.source_kind != EvidenceSourceKind::CodexHook
        {
            return None;
        }
        let call = native_call_from_raw(self.payload.as_bytes(), self.correlation.pairing_role)?;
        if call.session_id != self.session_id
            || Some(&call.turn_id) != self.turn_id.as_ref()
            || Some(&call.request_id) != self.tool_use_id.as_ref()
        {
            return None;
        }
        Some(call)
    }
}

pub fn native_call_from_raw(
    bytes: &[u8],
    role: evertrace_domain::evidence::ObservationRole,
) -> Option<evertrace_domain::evidence::SourceLocalNativeCall> {
    let raw = crate::binding::NativeToolUse::<serde_json::Value>::from_json(bytes).ok()?;
    raw.validate_host_fields().ok()?;
    let actual_role = match raw.hook_event_name {
        crate::binding::NativeToolUseEvent::PreToolUse => {
            evertrace_domain::evidence::ObservationRole::Intent
        }
        crate::binding::NativeToolUseEvent::PostToolUse => {
            evertrace_domain::evidence::ObservationRole::Result
        }
    };
    if actual_role != role {
        return None;
    }
    let call = evertrace_domain::evidence::SourceLocalNativeCall {
        session_id: raw.session_id,
        agent_id: raw.agent_id,
        transcript_path: raw.transcript_path,
        request_id: raw.tool_use_id,
        turn_id: raw.turn_id,
        tool_name: raw.tool_name,
        namespace_witness: None,
    };
    // An unsupported optional declaration must not break the existing weak
    // capture path (for example, a non-absolute external transcript locator).
    evertrace_domain::evidence::SourceLocalEvidence::NativeCall(call.clone())
        .validate(role)
        .ok()?;
    Some(call)
}

impl CaptureHookInput {
    /// One native delivery is one local weak source, never a host sequence or
    /// retry identity. The launcher invokes this once after selecting its pin.
    pub fn from_native(
        input: crate::binding::NativeToolUse<serde_json::Value>,
        generation: u64,
    ) -> Result<Self, HookInputError> {
        use evertrace_domain::evidence::{
            CorrelationField, CorrelationFieldClaim, ObservationRole, SourceInstanceId,
        };
        input
            .validate_host_fields()
            .map_err(|_| HookInputError::Invalid)?;
        let report = native_generation_report(generation)?;
        let manifest = report.manifest().adapter_manifest_id.clone();
        let source = SourceInstanceId::new_v7().as_str().to_owned();
        let event_kind = match input.hook_event_name {
            crate::binding::NativeToolUseEvent::PreToolUse => HookEventKind::PreToolUse,
            crate::binding::NativeToolUseEvent::PostToolUse => HookEventKind::PostToolUse,
        };
        let payload = serde_json::to_string(&input).map_err(|_| HookInputError::Invalid)?;
        let value = Self {
            input_version: CAPTURE_HOOK_INPUT_VERSION,
            spool_record_id: None,
            source_observation_id_hint: None,
            source_instance_id: source.clone(),
            source_revision: "initial".into(),
            source_record_identity: None,
            identity_strength: Some(IdentityStrength::SynthesizedBestEffort),
            source_kind: EvidenceSourceKind::CodexHook,
            identity_domain: "native-hook-delivery-v1".into(),
            adapter_manifest_ref: manifest.clone(),
            eligible_event_manifest_ref: crate::source_catalog::CODEX_ELIGIBLE_EVENT_MANIFEST
                .into(),
            source_revision_mode: SourceRevisionMode::Append,
            previous_source_revision: None,
            source_ref: source.clone(),
            session_id: input.session_id,
            turn_id: Some(input.turn_id),
            tool_use_id: Some(input.tool_use_id.clone()),
            event_kind,
            correlation: HostCorrelationEvidence {
                occurrence_schema_version: 1,
                host_instance_id: None,
                host_trace_lineage_id: None,
                host_lane_key: None,
                canonical_event_family: None,
                native_request_id: Some(input.tool_use_id),
                physical_execution_ordinal: None,
                pairing_role: if event_kind == HookEventKind::PreToolUse {
                    ObservationRole::Intent
                } else {
                    ObservationRole::Result
                },
                field_provenance: vec![CorrelationFieldClaim {
                    field: CorrelationField::NativeRequestId,
                    source_ref: source.clone(),
                    evidence_ref: source,
                }],
                adapter_manifest_ref: manifest,
                adapter_revision: 1,
                strong_gate_receipt_ref: None,
                admission: CorrelationAdmission::Unavailable,
                partial_correlation_ref: None,
                possible_duplicate_group_id: None,
            },
            scope_effect_claims: Vec::new(),
            lifecycle: None,
            source_sequence: 0,
            source_sequence_origin: Some(0),
            task_id: None,
            repository_instance_id: None,
            worktree_instance_id: None,
            event_time_us: None,
            payload,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, HookInputError> {
        if bytes.len() > MAX_CAPTURE_HOOK_INPUT {
            return Err(HookInputError::Oversize);
        }
        let input: Self = serde_json::from_slice(bytes).map_err(|_| HookInputError::Invalid)?;
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> Result<(), HookInputError> {
        if self.input_version != CAPTURE_HOOK_INPUT_VERSION
            || self
                .spool_record_id
                .as_deref()
                .is_some_and(|value| !valid_ref(value))
            || self
                .source_observation_id_hint
                .as_deref()
                .is_some_and(|value| !valid_ref(value))
            || !valid_ref(&self.source_instance_id)
            || !valid_ref(&self.source_revision)
            || !valid_ref(&self.identity_domain)
            || !valid_ref(&self.adapter_manifest_ref)
            || !valid_ref(&self.eligible_event_manifest_ref)
            || self
                .source_record_identity
                .as_deref()
                .is_some_and(|value| !valid_ref(value))
            || !valid_ref(&self.source_ref)
            || !valid_ref(&self.session_id)
            || self
                .turn_id
                .as_deref()
                .is_some_and(|value| !valid_ref(value))
            || self
                .tool_use_id
                .as_deref()
                .is_some_and(|value| !valid_ref(value))
            || self.event_time_us.is_some_and(|value| value < 0)
            || self
                .source_sequence_origin
                .is_some_and(|origin| origin > self.source_sequence)
            || self.correlation.adapter_manifest_ref != self.adapter_manifest_ref
            || self.correlation.admission == CorrelationAdmission::ExactCapable
            || [
                self.task_id.as_deref(),
                self.repository_instance_id.as_deref(),
                self.worktree_instance_id.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| !valid_ref(value))
            || !matches!(
                (&self.source_record_identity, self.identity_strength),
                (
                    Some(_),
                    Some(IdentityStrength::StableNative | IdentityStrength::StableSourceSequence)
                ) | (None, None | Some(IdentityStrength::SynthesizedBestEffort))
            )
            || (self.source_revision_mode == SourceRevisionMode::Replacement
                && self.previous_source_revision.is_none())
            || (self.source_revision_mode == SourceRevisionMode::Append
                && self.previous_source_revision.is_some())
        {
            return Err(HookInputError::Invalid);
        }
        self.correlation
            .validate()
            .map_err(|_| HookInputError::Invalid)?;
        for claim in &self.scope_effect_claims {
            claim.validate().map_err(|_| HookInputError::Invalid)?;
        }
        if let Some(lifecycle) = &self.lifecycle {
            lifecycle.validate().map_err(|_| HookInputError::Invalid)?;
            if lifecycle.incarnation_ref.is_none()
                || lifecycle.host_session_id != self.session_id
                || lifecycle.adapter_manifest_ref != self.adapter_manifest_ref
                || lifecycle.eligible_event_manifest_ref != self.eligible_event_manifest_ref
            {
                return Err(HookInputError::Invalid);
            }
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<Vec<u8>, HookInputError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| HookInputError::Invalid)
    }
}

#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum HookInputError {
    #[error("hook input is invalid")]
    Invalid,
    #[error("hook input exceeds the fixed limit")]
    Oversize,
}

fn valid_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}
