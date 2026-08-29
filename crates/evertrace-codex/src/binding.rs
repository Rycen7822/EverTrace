use std::{
    path::{Component, Path},
    str::FromStr,
};

use evertrace_domain::ids::{RepositoryId, WorktreeId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const BINDING_PROTOCOL_REVISION: u32 = 1;
pub const BOUND_WORKSPACE_PREFIX: &str = "@bound:v1:";
pub const CODEX_EVERTRACE_TOOL_NAME: &str = "mcp__evertrace__evertrace";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicWorkspace {
    Active,
    Repository(RepositoryId),
    Worktree(WorktreeId),
    PathHint(String),
}

impl PublicWorkspace {
    pub fn parse(value: &str) -> Result<Self, BindingError> {
        if value == "@active" {
            return Ok(Self::Active);
        }
        if let Ok(id) = RepositoryId::from_str(value) {
            return Ok(Self::Repository(id));
        }
        if let Ok(id) = WorktreeId::from_str(value) {
            return Ok(Self::Worktree(id));
        }
        if let Some(path) = value.strip_prefix("path_hint:")
            && valid_lexical_absolute_path(path)
        {
            return Ok(Self::PathHint(path.into()));
        }
        Err(BindingError::InvalidWorkspace)
    }

    pub fn canonical(&self) -> String {
        match self {
            Self::Active => "@active".into(),
            Self::Repository(id) => id.to_string(),
            Self::Worktree(id) => id.to_string(),
            Self::PathHint(path) => format!("path_hint:{path}"),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum TransportWorkspace {
    Public(PublicWorkspace),
    BoundClaim(String),
}

impl TransportWorkspace {
    pub fn parse(value: &str) -> Result<Self, BindingError> {
        if let Some(token) = value.strip_prefix(BOUND_WORKSPACE_PREFIX) {
            if valid_opaque_token(token) {
                return Ok(Self::BoundClaim(token.into()));
            }
            return Err(BindingError::InvalidWorkspace);
        }
        PublicWorkspace::parse(value).map(Self::Public)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalBindingCall {
    pub action: String,
    pub workspace: String,
    pub input: String,
    #[serde(default)]
    pub refs: Vec<String>,
}

impl CanonicalBindingCall {
    pub fn validate(&self) -> Result<(), BindingError> {
        if !matches!(self.action.as_str(), "search" | "get" | "add" | "organize")
            || PublicWorkspace::parse(&self.workspace).is_err()
            || self.input.is_empty()
            || self.input.len() > 4096
            || self.refs.len() > 32
            || self
                .refs
                .iter()
                .any(|value| value.is_empty() || value.len() > 512)
        {
            return Err(BindingError::InvalidCall);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BindingError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| BindingError::InvalidCall)
    }

    pub fn validate_transport(&self) -> Result<(), BindingError> {
        if !matches!(self.action.as_str(), "search" | "get" | "add" | "organize")
            || TransportWorkspace::parse(&self.workspace).is_err()
            || self.input.is_empty()
            || self.input.len() > 4096
            || self.refs.len() > 32
            || self
                .refs
                .iter()
                .any(|value| value.is_empty() || value.len() > 512)
        {
            Err(BindingError::InvalidCall)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingAnchor {
    pub session_id: String,
    pub turn_id: String,
    pub tool_use_id: String,
    pub agent_id: Option<String>,
}

impl BindingAnchor {
    pub fn validate(&self) -> Result<(), BindingError> {
        if [&self.session_id, &self.turn_id, &self.tool_use_id]
            .into_iter()
            .any(|value| {
                value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
            })
            || self.agent_id.as_deref().is_some_and(|value| {
                value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
            })
        {
            Err(BindingError::InvalidAnchor)
        } else {
            Ok(())
        }
    }
}

pub fn validated_bound_workspace(
    call: &CanonicalBindingCall,
    issued_workspace: &str,
) -> Result<String, BindingError> {
    if !matches!(
        TransportWorkspace::parse(issued_workspace),
        Ok(TransportWorkspace::BoundClaim(_))
    ) {
        return Err(BindingError::InvalidCall);
    }
    call.validate()?;
    Ok(issued_workspace.into())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NativePermissionMode {
    #[serde(rename = "default")]
    Default,
    #[serde(rename = "acceptEdits")]
    AcceptEdits,
    #[serde(rename = "plan")]
    Plan,
    #[serde(rename = "dontAsk")]
    DontAsk,
    #[serde(rename = "bypassPermissions")]
    BypassPermissions,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativePreToolUse<T> {
    pub cwd: String,
    pub hook_event_name: NativePreToolUseEvent,
    pub model: String,
    pub permission_mode: NativePermissionMode,
    pub session_id: String,
    pub tool_input: T,
    pub tool_name: String,
    pub tool_use_id: String,
    pub transcript_path: Option<String>,
    pub turn_id: String,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NativePreToolUseEvent {
    PreToolUse,
}

impl<T> NativePreToolUse<T>
where
    T: for<'de> Deserialize<'de>,
{
    pub fn from_json(input: &[u8]) -> Result<Self, BindingError> {
        serde_json::from_slice(input).map_err(|_| BindingError::InvalidCall)
    }

    pub fn targets_evertrace(&self) -> bool {
        self.tool_name == CODEX_EVERTRACE_TOOL_NAME
    }

    pub fn validate_host_fields(&self) -> Result<(), BindingError> {
        if !valid_lexical_absolute_path(&self.cwd)
            || self.model.is_empty()
            || self.session_id.is_empty()
            || self.tool_use_id.is_empty()
            || self.transcript_path.as_deref().is_some_and(|value| {
                value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control)
            })
            || self.turn_id.is_empty()
            || [
                &self.model,
                &self.session_id,
                &self.tool_use_id,
                &self.turn_id,
            ]
            .into_iter()
            .any(|value| value.len() > 512 || value.chars().any(char::is_control))
        {
            Err(BindingError::InvalidAnchor)
        } else {
            Ok(())
        }
    }
}

pub fn valid_lexical_absolute_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.chars().any(char::is_control)
        && Path::new(value).is_absolute()
        && Path::new(value).components().all(|component| {
            matches!(
                component,
                Component::RootDir | Component::Prefix(_) | Component::Normal(_)
            )
        })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePreToolUseOutput<T> {
    pub hook_specific_output: NativeHookSpecificOutput<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeHookSpecificOutput<T> {
    pub hook_event_name: NativePreToolUseEvent,
    pub permission_decision: NativePermissionDecision,
    pub updated_input: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NativePermissionDecision {
    Allow,
}

impl<T: Serialize> NativePreToolUseOutput<T> {
    pub fn to_json(&self) -> Result<Vec<u8>, BindingError> {
        serde_json::to_vec(self).map_err(|_| BindingError::InvalidCall)
    }
}

fn valid_opaque_token(value: &str) -> bool {
    (32..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BindingError {
    #[error("invalid public or internal workspace")]
    InvalidWorkspace,
    #[error("invalid canonical MCP call")]
    InvalidCall,
    #[error("invalid binding anchor")]
    InvalidAnchor,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct TestToolInput {
        action: String,
        workspace: String,
        input: String,
        refs: Vec<String>,
    }

    #[test]
    fn public_workspace_is_closed_and_internal_claim_is_not_public() {
        assert_eq!(
            PublicWorkspace::parse("@active").unwrap(),
            PublicWorkspace::Active
        );
        let repository = RepositoryId::new_v7();
        let worktree = WorktreeId::new_v7();
        assert_eq!(
            PublicWorkspace::parse(&repository.to_string()).unwrap(),
            PublicWorkspace::Repository(repository)
        );
        assert_eq!(
            PublicWorkspace::parse(&worktree.to_string()).unwrap(),
            PublicWorkspace::Worktree(worktree)
        );
        assert!(matches!(
            PublicWorkspace::parse("path_hint:/workspace/project"),
            Ok(PublicWorkspace::PathHint(_))
        ));
        assert!(PublicWorkspace::parse("@bound:v1:01234567890123456789012345678901").is_err());
        assert!(matches!(
            TransportWorkspace::parse("@bound:v1:01234567890123456789012345678901"),
            Ok(TransportWorkspace::BoundClaim(_))
        ));
        assert!(PublicWorkspace::parse("path_hint:relative").is_err());
        assert!(PublicWorkspace::parse("path_hint:/repo/../other").is_err());
    }

    #[test]
    fn canonical_call_bytes_bind_ref_order_and_rewrite_preserves_other_fields() {
        let first = CanonicalBindingCall {
            action: "search".into(),
            workspace: "@active".into(),
            input: "needle".into(),
            refs: vec!["atom:a".into(), "atom:b".into()],
        };
        let mut reordered = first.clone();
        reordered.refs.reverse();
        assert_ne!(
            first.canonical_bytes().unwrap(),
            reordered.canonical_bytes().unwrap()
        );
        let workspace =
            validated_bound_workspace(&first, "@bound:v1:01234567890123456789012345678901")
                .unwrap();
        assert_eq!(workspace, "@bound:v1:01234567890123456789012345678901");
        assert!(validated_bound_workspace(&first, "@active").is_err());
        let mut transport = first.clone();
        transport.workspace = "@bound:v1:01234567890123456789012345678901".into();
        assert!(transport.validate_transport().is_ok());
        transport.input = "x".repeat(4097);
        assert!(transport.validate_transport().is_err());
    }

    #[test]
    fn native_pretooluse_is_closed_exact_and_serializes_host_output() {
        let raw = serde_json::json!({
            "cwd": "/workspace/project",
            "hook_event_name": "PreToolUse",
            "model": "gpt-5",
            "permission_mode": "acceptEdits",
            "session_id": "session-a",
            "tool_input": {"action":"search","workspace":"@active","input":"needle","refs":["atom:a"]},
            "tool_name": CODEX_EVERTRACE_TOOL_NAME,
            "tool_use_id": "tool-a",
            "transcript_path": "/tmp/transcript.jsonl",
            "turn_id": "turn-a"
        });
        let native =
            NativePreToolUse::<TestToolInput>::from_json(&serde_json::to_vec(&raw).unwrap())
                .unwrap();
        native.validate_host_fields().unwrap();
        assert!(native.targets_evertrace());
        assert_eq!(native.tool_input.action, "search");

        let mut null_transcript = raw.clone();
        null_transcript["transcript_path"] = serde_json::Value::Null;
        NativePreToolUse::<TestToolInput>::from_json(
            &serde_json::to_vec(&null_transcript).unwrap(),
        )
        .unwrap()
        .validate_host_fields()
        .unwrap();

        let output = NativePreToolUseOutput {
            hook_specific_output: NativeHookSpecificOutput {
                hook_event_name: NativePreToolUseEvent::PreToolUse,
                permission_decision: NativePermissionDecision::Allow,
                updated_input: native.tool_input,
            },
        };
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.to_json().unwrap()).unwrap(),
            serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "updatedInput": {"action":"search","workspace":"@active","input":"needle","refs":["atom:a"]}
                }
            })
        );

        let mut unknown = raw.clone();
        unknown["extra"] = serde_json::json!(true);
        assert!(
            NativePreToolUse::<TestToolInput>::from_json(&serde_json::to_vec(&unknown).unwrap())
                .is_err()
        );
        let mut other = raw;
        other["tool_name"] = serde_json::json!("mcp__other__evertrace");
        assert!(
            !NativePreToolUse::<TestToolInput>::from_json(&serde_json::to_vec(&other).unwrap())
                .unwrap()
                .targets_evertrace()
        );
    }
}
