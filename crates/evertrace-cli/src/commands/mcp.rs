use std::{
    env,
    error::Error,
    io::{self, BufRead, Write},
    path::PathBuf,
    time::Duration,
};

use evertrace_domain::ids::RequestId;
use evertrace_protocol::{
    LocalClient,
    command::{Command, McpCallCommand},
    dto::ClientKind,
    envelope::McpResultEnvelope,
    mcp::{
        MCP_PROTOCOL_VERSION, MCP_STATIC_INSTRUCTIONS, MCP_TOOL_NAME, McpToolInput, tool_definition,
    },
    resolve_data_dir,
    response::Response,
};
use serde_json::{Value, json};

use crate::commands::config;

const MCP_FRAME_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    AwaitInitialize,
    AwaitInitialized,
    Ready,
}

pub async fn run(config_path: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    let effective = config::load(config_path)?;
    let home = env::var_os("HOME").map(PathBuf::from);
    let data_dir = resolve_data_dir(
        &effective.config().runtime.data_dir,
        home.as_deref(),
        |name| env::var_os(name),
    )?;
    let socket = data_dir.join("runtime/evertraced-v1.sock");
    let client_cwd = env::current_dir()?.to_string_lossy().into_owned();
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut client = None;
    let mut lifecycle = Lifecycle::AwaitInitialize;
    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let response =
            dispatch_line(&line, &socket, &client_cwd, &mut lifecycle, &mut client).await;
        if let Some(response) = response {
            serde_json::to_writer(&mut stdout, &response)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

async fn dispatch_line(
    line: &str,
    socket: &std::path::Path,
    client_cwd: &str,
    lifecycle: &mut Lifecycle,
    client: &mut Option<LocalClient>,
) -> Option<Value> {
    let request: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(_) => return Some(error_response(Value::Null, -32700, "parse error")),
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if request.get("jsonrpc") != Some(&Value::String("2.0".into())) {
        return Some(error_response(id, -32600, "invalid request"));
    }
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Some(error_response(id, -32600, "invalid request"));
    };
    let notification = request.get("id").is_none();
    if notification {
        if *lifecycle == Lifecycle::AwaitInitialized && method == "notifications/initialized" {
            *lifecycle = Lifecycle::Ready;
        }
        return None;
    }
    if *lifecycle == Lifecycle::AwaitInitialize && method != "initialize" {
        return Some(error_response(id, -32002, "server not initialized"));
    }
    if *lifecycle == Lifecycle::AwaitInitialized {
        return Some(error_response(
            id,
            -32002,
            "initialization notification required",
        ));
    }
    if *lifecycle == Lifecycle::Ready && method == "initialize" {
        return Some(error_response(id, -32600, "already initialized"));
    }
    match method {
        "initialize" => {
            let params = request.get("params");
            if params
                .and_then(|value| value.get("protocolVersion"))
                .and_then(Value::as_str)
                .is_none()
                || params
                    .and_then(|value| value.get("clientInfo"))
                    .and_then(Value::as_object)
                    .is_none_or(|info| {
                        info.get("name").and_then(Value::as_str).is_none()
                            || info.get("version").and_then(Value::as_str).is_none()
                    })
                || params
                    .and_then(|value| value.get("capabilities"))
                    .and_then(Value::as_object)
                    .is_none()
            {
                return Some(error_response(id, -32602, "invalid initialize params"));
            }
            *lifecycle = Lifecycle::AwaitInitialized;
            Some(success_response(
                id,
                json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "evertrace", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": MCP_STATIC_INSTRUCTIONS
                }),
            ))
        }
        "ping" => Some(success_response(id, json!({}))),
        "tools/list" => Some(success_response(id, json!({"tools": [tool_definition()]}))),
        "tools/call" => {
            let Some(name) = request.pointer("/params/name").and_then(Value::as_str) else {
                return Some(error_response(id, -32602, "invalid tool call"));
            };
            if name != MCP_TOOL_NAME {
                return Some(error_response(id, -32602, "unknown tool"));
            }
            let Some(arguments) = request.pointer("/params/arguments") else {
                return Some(error_response(id, -32602, "missing arguments"));
            };
            let input: McpToolInput =
                match serde_json::from_value::<McpToolInput>(arguments.clone()) {
                    Ok(input) if input.validate() => input,
                    _ => return Some(error_response(id, -32602, "invalid arguments")),
                };
            let action = input.action;
            if client.is_none() {
                match LocalClient::connect(
                    socket,
                    env!("CARGO_PKG_VERSION"),
                    ClientKind::Mcp,
                    MCP_FRAME_TIMEOUT,
                )
                .await
                {
                    Ok(connection) => *client = Some(connection),
                    Err(_) => return Some(error_response(id, -32603, "daemon unavailable")),
                }
            }
            let request_id = RequestId::new_v7();
            let response = client
                .as_mut()
                .expect("client was initialized")
                .request(
                    request_id,
                    Command::McpCall(McpCallCommand {
                        input,
                        client_cwd: client_cwd.into(),
                    }),
                )
                .await;
            let Response::McpResult(mut envelope) = (match response {
                Ok(response) => response,
                Err(_) => {
                    *client = None;
                    return Some(error_response(id, -32603, "daemon request failed"));
                }
            }) else {
                *client = None;
                return Some(error_response(id, -32603, "unexpected daemon response"));
            };
            bound_result(&mut envelope, action);
            Some(success_response(
                id,
                json!({
                    "content": [{"type": "text", "text": "EverTrace result is available in structuredContent."}],
                    "structuredContent": envelope,
                    "isError": false
                }),
            ))
        }
        _ => Some(error_response(id, -32601, "method not found")),
    }
}

fn bound_result(envelope: &mut McpResultEnvelope, action: evertrace_protocol::mcp::McpAction) {
    let (target_bytes, hard_bytes) = if action == evertrace_protocol::mcp::McpAction::Get {
        (4_800, 9_600)
    } else {
        (2_400, 4_800)
    };
    while envelope_bytes(envelope) > target_bytes {
        if !trim_one_item(envelope) {
            break;
        }
        envelope.truncated = true;
    }
    if envelope.next_refs.len() > 8 {
        let omitted = envelope.next_refs.len() - 8;
        envelope.next_refs.truncate(8);
        envelope
            .warnings
            .push(format!("next_refs_omitted:{omitted}"));
        envelope.truncated = true;
    }
    if envelope_bytes(envelope) > hard_bytes {
        let omitted = envelope.warnings.len();
        envelope.warnings.clear();
        envelope
            .warnings
            .push(format!("warnings_aggregated:{omitted}"));
        envelope.truncated = true;
    }
    if envelope_bytes(envelope) > hard_bytes {
        let mut omitted = 0;
        while envelope_bytes(envelope) > hard_bytes && envelope.next_refs.len() > 1 {
            let longest = envelope
                .next_refs
                .iter()
                .enumerate()
                .max_by_key(|(_, value)| value.len())
                .map(|(index, _)| index)
                .unwrap_or(0);
            envelope.next_refs.remove(longest);
            omitted += 1;
        }
        envelope
            .warnings
            .push(format!("next_refs_aggregated:{omitted}"));
        envelope.truncated = true;
    }
    if envelope_bytes(envelope) > hard_bytes && envelope.audit_ref.take().is_some() {
        envelope.warnings.push("audit_ref_omitted".into());
        envelope.truncated = true;
    }
    if envelope_bytes(envelope) > hard_bytes {
        envelope.warnings = vec!["output_hard_truncated".into()];
        envelope.next_refs.clear();
        envelope.audit_ref = None;
        envelope.truncated = true;
    }
    if envelope_bytes(envelope) > hard_bytes {
        envelope.scope = "scope_omitted".into();
        envelope.truncated = true;
    }
}

fn envelope_bytes(envelope: &McpResultEnvelope) -> usize {
    serde_json::to_vec(envelope).map_or(usize::MAX, |value| value.len())
}

fn trim_one_item(envelope: &mut McpResultEnvelope) -> bool {
    for partition in [
        &mut envelope.items.evidence,
        &mut envelope.items.warnings,
        &mut envelope.items.procedures,
        &mut envelope.items.normative_constraints,
    ] {
        if let Some(item) = partition
            .iter_mut()
            .rev()
            .find(|item| item.text.as_ref().is_some_and(|text| !text.is_empty()))
            && let Some(text) = &mut item.text
        {
            let mut keep = text.len() / 2;
            while keep > 0 && !text.is_char_boundary(keep) {
                keep -= 1;
            }
            text.truncate(keep);
            return true;
        }
        if let Some(removed) = partition.pop() {
            if let Some(reference) = removed.object_ref
                && envelope.next_refs.len() < 32
                && !envelope.next_refs.contains(&reference)
            {
                envelope.next_refs.push(reference);
            }
            return true;
        }
    }
    false
}

fn success_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error_response(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use evertrace_domain::evidence::{ContentTrust, InstructionAuthority};
    use evertrace_protocol::envelope::{McpItem, McpItems, McpStatus};

    #[test]
    fn tool_definition_is_single_closed_and_small() {
        let definition = tool_definition();
        assert_eq!(definition["name"], MCP_TOOL_NAME);
        assert_eq!(
            definition["description"],
            "Search, inspect, record, or organize EverTrace data for a workspace."
        );
        assert_eq!(definition["inputSchema"]["additionalProperties"], false);
        assert!(serde_json::to_vec(&definition).unwrap().len() < 1_000);
    }

    #[test]
    fn bounded_result_preserves_closed_safety_markers_and_continuation_refs() {
        let critical_ref = "atom:019c0000-0000-7000-8000-000000000001".to_owned();
        let mut envelope = McpResultEnvelope {
            schema_version: 1,
            request_id: RequestId::new_v7(),
            status: McpStatus::Partial,
            scope: "@active".into(),
            freshness: "stale".into(),
            completeness: "partial".into(),
            items: McpItems {
                evidence: (0..16)
                    .map(|_| McpItem {
                        kind: "evidence".into(),
                        object_ref: Some(critical_ref.clone()),
                        object_revision_ref: None,
                        source_revision_ref: None,
                        scope: None,
                        applicability: None,
                        authority: None,
                        text: Some("untrusted body ".repeat(800)),
                        content_trust: ContentTrust::UntrustedSourceContent,
                        capture_completeness: None,
                        instruction_authority: InstructionAuthority::None,
                    })
                    .collect(),
                ..McpItems::default()
            },
            warnings: vec!["search_projection_stale".into(); 64],
            truncated: false,
            next_refs: vec![critical_ref.clone(); 16],
            audit_ref: None,
        };
        bound_result(&mut envelope, evertrace_protocol::mcp::McpAction::Search);
        assert!(envelope.truncated);
        assert!(serde_json::to_vec(&envelope).unwrap().len() <= 4_800);
        assert_eq!(envelope.freshness, "stale");
        assert_eq!(envelope.completeness, "partial");
        assert!(!envelope.warnings.is_empty());
        assert!(
            envelope.next_refs.contains(&critical_ref)
                || envelope
                    .items
                    .evidence
                    .iter()
                    .any(|item| item.object_ref.as_ref() == Some(&critical_ref))
        );
    }

    #[test]
    fn bounded_result_caps_giant_normative_and_procedure_partitions_without_evidence() {
        let item = |kind: &str, reference: &str| McpItem {
            kind: kind.into(),
            object_ref: Some(reference.into()),
            object_revision_ref: None,
            source_revision_ref: None,
            scope: Some("repo:019c0000-0000-7000-8000-000000000001".into()),
            applicability: Some("true".into()),
            authority: Some("user_explicit".into()),
            text: Some("bounded body ".repeat(2_000)),
            content_trust: ContentTrust::UserStatement,
            capture_completeness: Some("complete".into()),
            instruction_authority: InstructionAuthority::None,
        };
        let mut envelope = McpResultEnvelope {
            schema_version: 1,
            request_id: RequestId::new_v7(),
            status: McpStatus::Ok,
            scope: "w".repeat(4_096),
            freshness: "current".into(),
            completeness: "complete".into(),
            items: McpItems {
                normative_constraints: vec![item("constraint", "atom:normative")],
                procedures: vec![item("procedure", "procedure:bounded")],
                evidence: Vec::new(),
                warnings: Vec::new(),
            },
            warnings: Vec::new(),
            truncated: false,
            next_refs: vec!["r".repeat(512)],
            audit_ref: None,
        };
        bound_result(&mut envelope, evertrace_protocol::mcp::McpAction::Search);
        assert!(envelope.truncated);
        assert!(serde_json::to_vec(&envelope).unwrap().len() <= 4_800);
        assert!(
            envelope
                .items
                .normative_constraints
                .iter()
                .any(|value| { value.object_ref.as_deref() == Some("atom:normative") })
                || envelope
                    .next_refs
                    .iter()
                    .any(|value| value == "atom:normative")
        );
        assert!(
            envelope
                .items
                .procedures
                .iter()
                .any(|value| { value.object_ref.as_deref() == Some("procedure:bounded") })
                || envelope
                    .next_refs
                    .iter()
                    .any(|value| value == "procedure:bounded")
        );
    }

    #[test]
    fn bounded_result_trims_large_item_before_preserving_medium_scope() {
        let scope = format!("repo:{}", "s".repeat(300));
        let mut envelope = McpResultEnvelope {
            schema_version: 1,
            request_id: RequestId::new_v7(),
            status: McpStatus::Ok,
            scope: scope.clone(),
            freshness: "current".into(),
            completeness: "complete".into(),
            items: McpItems {
                evidence: vec![McpItem {
                    kind: "evidence".into(),
                    object_ref: Some("atom:bounded".into()),
                    object_revision_ref: Some("revision:bounded".into()),
                    source_revision_ref: None,
                    scope: Some(scope.clone()),
                    applicability: None,
                    authority: None,
                    text: Some("large body ".repeat(4_000)),
                    content_trust: ContentTrust::AgentClaim,
                    capture_completeness: Some("complete".into()),
                    instruction_authority: InstructionAuthority::None,
                }],
                ..McpItems::default()
            },
            warnings: Vec::new(),
            truncated: false,
            next_refs: Vec::new(),
            audit_ref: None,
        };
        bound_result(&mut envelope, evertrace_protocol::mcp::McpAction::Search);
        assert_eq!(envelope.scope, scope);
        assert!(envelope.truncated);
        assert!(envelope_bytes(&envelope) <= 4_800);
    }

    #[test]
    fn bounded_result_shrinks_long_continuation_refs_before_omitting_large_scope() {
        let scope = format!("repo:{}", "s".repeat(600));
        let mut envelope = McpResultEnvelope {
            schema_version: 1,
            request_id: RequestId::new_v7(),
            status: McpStatus::Partial,
            scope: scope.clone(),
            freshness: "current".into(),
            completeness: "partial".into(),
            items: McpItems::default(),
            warnings: Vec::new(),
            truncated: false,
            next_refs: (0..16)
                .map(|index| format!("{index:02}{}", "r".repeat(510)))
                .collect(),
            audit_ref: Some("audit:bounded".into()),
        };
        bound_result(&mut envelope, evertrace_protocol::mcp::McpAction::Search);
        assert_eq!(envelope.scope, scope);
        assert!(envelope.truncated);
        assert!(envelope.next_refs.len() < 16);
        assert!(envelope_bytes(&envelope) <= 4_800);
    }
}
