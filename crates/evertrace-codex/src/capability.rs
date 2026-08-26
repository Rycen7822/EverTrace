use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::hook_input::HookActivationEvidence;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryStatus {
    NotRun,
    Passed,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookActivation {
    Missing,
    PendingTrust,
    Active,
    Disabled,
    HashChanged,
    CanaryFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookDiagnostic {
    WiredUnobserved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpSessionBinding {
    Exact,
    ConnectionScoped,
    CwdOnly,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpBindingMechanism {
    DirectProtocol,
    HookStamped,
    ConnectionLease,
    Cwd,
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpIdentityStrength {
    DirectIdentity,
    VerifiedHookStampedClaim,
    ProvenConnectionScopedLease,
    CwdOnly,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HookProbeResult {
    pub activation: HookActivation,
    pub diagnostic: Option<HookDiagnostic>,
}

pub fn evaluate_hook(evidence: Option<&HookActivationEvidence>) -> HookProbeResult {
    let Some(evidence) = evidence else {
        return HookProbeResult {
            activation: HookActivation::Missing,
            diagnostic: None,
        };
    };
    if !evidence.wiring_detected {
        return HookProbeResult {
            activation: HookActivation::Missing,
            diagnostic: None,
        };
    }
    if !evidence.enabled {
        return HookProbeResult {
            activation: HookActivation::Disabled,
            diagnostic: None,
        };
    }
    if !evidence.trusted {
        return HookProbeResult {
            activation: HookActivation::PendingTrust,
            diagnostic: None,
        };
    }
    if evidence.expected_hash != evidence.observed_hash {
        return HookProbeResult {
            activation: HookActivation::HashChanged,
            diagnostic: None,
        };
    }
    if evidence.evidence_refs.is_empty()
        || evidence.evidence_refs.iter().any(String::is_empty)
        || evidence.evidence_refs.iter().collect::<BTreeSet<_>>().len()
            != evidence.evidence_refs.len()
        || evidence
            .protected_digest
            .as_deref()
            .is_none_or(|value| !valid_digest(value))
        || evidence
            .expected_hash
            .as_deref()
            .is_none_or(|value| !valid_digest(value))
    {
        return HookProbeResult {
            activation: HookActivation::CanaryFailed,
            diagnostic: None,
        };
    }
    match evidence.canary {
        CanaryStatus::Passed => HookProbeResult {
            activation: HookActivation::Active,
            diagnostic: None,
        },
        CanaryStatus::Failed => HookProbeResult {
            activation: HookActivation::CanaryFailed,
            diagnostic: None,
        },
        CanaryStatus::NotRun => HookProbeResult {
            activation: HookActivation::Missing,
            diagnostic: Some(HookDiagnostic::WiredUnobserved),
        },
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpBindingEvidence {
    DirectIdentity {
        session_id: String,
        verified: bool,
        evidence_refs: Vec<String>,
        protected_digest: String,
    },
    HookStampedClaim {
        claim_id: String,
        session_id: String,
        issued_at: u64,
        expires_at: u64,
        observed_at: u64,
        call_hash_matches: bool,
        parameter_matches: bool,
        atomically_consumed: bool,
        replayed: bool,
        tampered: bool,
        rewrite_conflict: bool,
        daemon_generation_matches: bool,
        evidence_refs: Vec<String>,
        protected_digest: String,
    },
    ConnectionLease {
        lease_id: String,
        session_id: String,
        connection_id: String,
        expires_at: u64,
        observed_at: u64,
        concurrent_unique: bool,
        reconnect_verified: bool,
        generation_matches: bool,
        replayed: bool,
        tampered: bool,
        evidence_refs: Vec<String>,
        protected_digest: String,
    },
    CwdOnly {
        cwd_identity: String,
        evidence_refs: Vec<String>,
        protected_digest: String,
    },
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpProbeResult {
    pub binding: McpSessionBinding,
    pub mechanism: McpBindingMechanism,
    pub strength: McpIdentityStrength,
}

impl McpBindingEvidence {
    pub fn evaluate(&self) -> McpProbeResult {
        match self {
            Self::DirectIdentity {
                session_id,
                verified,
                ..
            } if *verified && !session_id.is_empty() && self.has_valid_protected_evidence() => {
                McpProbeResult {
                    binding: McpSessionBinding::Exact,
                    mechanism: McpBindingMechanism::DirectProtocol,
                    strength: McpIdentityStrength::DirectIdentity,
                }
            }
            Self::HookStampedClaim {
                claim_id,
                session_id,
                issued_at,
                expires_at,
                observed_at,
                call_hash_matches,
                parameter_matches,
                atomically_consumed,
                replayed,
                tampered,
                rewrite_conflict,
                daemon_generation_matches,
                ..
            } if !claim_id.is_empty()
                && !session_id.is_empty()
                && issued_at <= observed_at
                && observed_at < expires_at
                && *call_hash_matches
                && *parameter_matches
                && *atomically_consumed
                && !replayed
                && !tampered
                && !rewrite_conflict
                && *daemon_generation_matches
                && self.has_valid_protected_evidence() =>
            {
                McpProbeResult {
                    binding: McpSessionBinding::Exact,
                    mechanism: McpBindingMechanism::HookStamped,
                    strength: McpIdentityStrength::VerifiedHookStampedClaim,
                }
            }
            Self::ConnectionLease {
                lease_id,
                session_id,
                connection_id,
                expires_at,
                observed_at,
                concurrent_unique,
                reconnect_verified,
                generation_matches,
                replayed,
                tampered,
                ..
            } if !lease_id.is_empty()
                && !session_id.is_empty()
                && !connection_id.is_empty()
                && observed_at < expires_at
                && *concurrent_unique
                && *reconnect_verified
                && *generation_matches
                && !replayed
                && !tampered
                && self.has_valid_protected_evidence() =>
            {
                McpProbeResult {
                    binding: McpSessionBinding::ConnectionScoped,
                    mechanism: McpBindingMechanism::ConnectionLease,
                    strength: McpIdentityStrength::ProvenConnectionScopedLease,
                }
            }
            Self::CwdOnly { cwd_identity, .. }
                if !cwd_identity.is_empty() && self.has_valid_protected_evidence() =>
            {
                McpProbeResult {
                    binding: McpSessionBinding::CwdOnly,
                    mechanism: McpBindingMechanism::Cwd,
                    strength: McpIdentityStrength::CwdOnly,
                }
            }
            _ => McpProbeResult {
                binding: McpSessionBinding::Unavailable,
                mechanism: McpBindingMechanism::None,
                strength: McpIdentityStrength::Unavailable,
            },
        }
    }

    pub fn evidence_refs(&self) -> &[String] {
        match self {
            Self::DirectIdentity { evidence_refs, .. }
            | Self::HookStampedClaim { evidence_refs, .. }
            | Self::ConnectionLease { evidence_refs, .. }
            | Self::CwdOnly { evidence_refs, .. } => evidence_refs,
            Self::Unavailable => &[],
        }
    }

    pub fn protected_digest(&self) -> Option<&str> {
        match self {
            Self::DirectIdentity {
                protected_digest, ..
            }
            | Self::HookStampedClaim {
                protected_digest, ..
            }
            | Self::ConnectionLease {
                protected_digest, ..
            }
            | Self::CwdOnly {
                protected_digest, ..
            } => Some(protected_digest),
            Self::Unavailable => None,
        }
    }

    pub fn session_identity(&self) -> Option<&str> {
        match self {
            Self::DirectIdentity { session_id, .. }
            | Self::HookStampedClaim { session_id, .. }
            | Self::ConnectionLease { session_id, .. } => Some(session_id),
            Self::CwdOnly { cwd_identity, .. } => Some(cwd_identity),
            Self::Unavailable => None,
        }
    }

    fn has_valid_protected_evidence(&self) -> bool {
        let refs = self.evidence_refs();
        !refs.is_empty()
            && refs.iter().all(|value| !value.is_empty())
            && refs.iter().collect::<BTreeSet<_>>().len() == refs.len()
            && self.protected_digest().is_some_and(valid_digest)
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub const fn valid_binding_pair(
    binding: McpSessionBinding,
    mechanism: McpBindingMechanism,
) -> bool {
    matches!(
        (binding, mechanism),
        (
            McpSessionBinding::Exact,
            McpBindingMechanism::DirectProtocol | McpBindingMechanism::HookStamped
        ) | (
            McpSessionBinding::ConnectionScoped,
            McpBindingMechanism::ConnectionLease
        ) | (McpSessionBinding::CwdOnly, McpBindingMechanism::Cwd)
            | (McpSessionBinding::Unavailable, McpBindingMechanism::None)
    )
}
