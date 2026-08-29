use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
pub const MCP_TOOL_NAME: &str = "evertrace";
pub const MCP_TOOL_DESCRIPTION: &str =
    "Search, inspect, record, or organize EverTrace data for a workspace.";
pub const MCP_STATIC_INSTRUCTIONS: &str = "When an EverTrace due cue appears, call search(@due).";
pub const MAX_MCP_INPUT: usize = 4096;
pub const MAX_MCP_REFS: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpAction {
    Search,
    Get,
    Add,
    Organize,
}

impl McpAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Search => "search",
            Self::Get => "get",
            Self::Add => "add",
            Self::Organize => "organize",
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolInput {
    pub action: McpAction,
    pub workspace: String,
    pub input: String,
    #[serde(default)]
    pub refs: Vec<String>,
}

impl std::fmt::Debug for McpToolInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpToolInput")
            .field("action", &self.action)
            .field("workspace_redacted", &true)
            .field("input_bytes", &self.input.len())
            .field("refs_count", &self.refs.len())
            .finish()
    }
}

impl McpToolInput {
    pub fn validate(&self) -> bool {
        !self.workspace.is_empty()
            && self.workspace.len() <= 4096
            && !self.input.is_empty()
            && self.input.len() <= MAX_MCP_INPUT
            && self.refs.len() <= MAX_MCP_REFS
            && self
                .refs
                .iter()
                .all(|value| !value.is_empty() && value.len() <= 512)
    }
}

pub fn tool_definition() -> Value {
    json!({
        "name": MCP_TOOL_NAME,
        "description": MCP_TOOL_DESCRIPTION,
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["search", "get", "add", "organize"]},
                "workspace": {"type": "string", "minLength": 1, "maxLength": 4096},
                "input": {"type": "string", "minLength": 1, "maxLength": MAX_MCP_INPUT},
                "refs": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 512}, "maxItems": MAX_MCP_REFS}
            },
            "required": ["action", "workspace", "input"],
            "additionalProperties": false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_contract_is_exact_closed_and_bounded() {
        let tool = tool_definition();
        assert_eq!(tool["name"], MCP_TOOL_NAME);
        assert_eq!(tool["description"], MCP_TOOL_DESCRIPTION);
        assert_eq!(
            tool["inputSchema"]["required"],
            json!(["action", "workspace", "input"])
        );
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        assert_eq!(
            tool["inputSchema"]["properties"]["input"]["maxLength"],
            4096
        );
        assert_eq!(
            tool["inputSchema"]["properties"]["workspace"]["minLength"],
            1
        );
        assert_eq!(
            tool["inputSchema"]["properties"]["workspace"]["maxLength"],
            4096
        );
        assert_eq!(tool["inputSchema"]["properties"]["input"]["minLength"], 1);
        assert_eq!(tool["inputSchema"]["properties"]["refs"]["maxItems"], 32);
        assert_eq!(
            tool["inputSchema"]["properties"]["refs"]["items"]["minLength"],
            1
        );
        assert_eq!(
            tool["inputSchema"]["properties"]["refs"]["items"]["maxLength"],
            512
        );
        assert!(serde_json::to_vec(&tool).unwrap().len() < 1_000);
    }

    #[test]
    fn action_and_unknown_fields_fail_closed() {
        assert!(
            serde_json::from_str::<McpToolInput>(
                r#"{"action":"forget","workspace":"@active","input":"x"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<McpToolInput>(
                r#"{"action":"search","workspace":"@active","input":"x","admin":true}"#
            )
            .is_err()
        );
        let too_many = McpToolInput {
            action: McpAction::Search,
            workspace: "@active".into(),
            input: "x".into(),
            refs: vec!["x".into(); 33],
        };
        assert!(!too_many.validate());
    }
}
