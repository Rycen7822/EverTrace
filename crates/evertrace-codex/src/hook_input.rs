use serde::{Deserialize, Serialize};

use evertrace_domain::evidence::{
    CorrelationAdmission, EvidenceSourceKind, HostCorrelationEvidence, IdentityStrength,
    ScopeEffectClaim, SourceRevisionMode,
};

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

pub const CAPTURE_HOOK_INPUT_VERSION: u16 = 3;
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
    pub source_sequence: u64,
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

impl CaptureHookInput {
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
