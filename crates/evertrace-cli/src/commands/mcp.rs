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
        let mut returned = None;
        let response = dispatch_line(
            &line,
            &socket,
            &client_cwd,
            &mut lifecycle,
            &mut client,
            &mut returned,
        )
        .await;
        if let Some(response) = response {
            serde_json::to_writer(&mut stdout, &response)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
            if let Some(request_id) = returned {
                let confirmed = match client.as_mut() {
                    Some(connection) => matches!(
                        connection
                            .request(RequestId::new_v7(), Command::McpReturned { request_id })
                            .await,
                        Ok(Response::McpReturned)
                    ),
                    None => false,
                };
                // Output is already delivered. An unconfirmed receipt never
                // retransmits it or turns that successful write into an error.
                if !confirmed {
                    client = None;
                }
            }
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
    returned: &mut Option<RequestId>,
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
            let search = input.action == evertrace_protocol::mcp::McpAction::Search;
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
            let Response::McpResult(envelope) = (match response {
                Ok(response) => response,
                Err(_) => {
                    *client = None;
                    return Some(error_response(id, -32603, "daemon request failed"));
                }
            }) else {
                *client = None;
                return Some(error_response(id, -32603, "unexpected daemon response"));
            };
            if search && !envelope.items.procedures.is_empty() {
                *returned = Some(request_id);
            }
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

fn success_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error_response(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
