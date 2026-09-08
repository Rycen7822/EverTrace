use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

use evertrace_domain::evidence::{ContentTrust, InstructionAuthority};
use evertrace_domain::ids::RequestId;
use evertrace_protocol::{
    LocalServer, ServerOptions,
    command::Command as ProtocolCommand,
    dto::ClientKind,
    envelope::{McpItem, McpItems, McpResultEnvelope, McpStatus},
    error::ErrorCode,
    response::Response,
};
use tokio::sync::watch;

#[test]
fn stdio_mcp_lifecycle_lists_exactly_one_tool_and_rejects_unknown() {
    let root = std::env::temp_dir().join(format!("evertrace-s20-{}", RequestId::new_v7()));
    fs::create_dir_all(&root).unwrap();
    let config = root.join("config.toml");
    fs::write(
        &config,
        format!(
            "config_version = 1\n[runtime]\ndata_dir = {:?}\n",
            root.join("data").to_string_lossy()
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_evertrace"))
        .args(["--config", config.to_str().unwrap(), "mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let requests = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"tools/list\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"1900-01-01\",\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"},\"capabilities\":{}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/list\"}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"unknown/notification\"}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/list\"}\n"
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(requests.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8(output.stdout).unwrap();
    let messages = lines
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 5);
    assert_eq!(messages[0]["error"]["code"], -32002);
    assert_eq!(messages[1]["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(
        messages[1]["result"]["capabilities"],
        serde_json::json!({"tools": {}})
    );
    assert_eq!(messages[2]["error"]["code"], -32002);
    assert_eq!(messages[3]["result"]["tools"].as_array().unwrap().len(), 1);
    assert_eq!(messages[3]["result"]["tools"][0]["name"], "evertrace");
    assert_eq!(messages[4]["error"]["code"], -32601);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stdio_tool_call_uses_one_persistent_mcp_uds_connection() {
    assert!(
        serde_json::from_value::<ProtocolCommand>(serde_json::json!({
            "mcp_returned": {"request_id": RequestId::new_v7(), "revisions": []}
        }))
        .is_err(),
        "the receipt cannot supply its own returned revision set"
    );
    let root = std::env::temp_dir().join(format!("evertrace-s20-{}", RequestId::new_v7()));
    let data = root.join("data");
    fs::create_dir_all(&root).unwrap();
    let server = LocalServer::bind(&data, ServerOptions::new("s20-test")).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let connection_ids = Arc::new(Mutex::new(Vec::new()));
    let observed_connections = Arc::clone(&connection_ids);
    let confirmations = Arc::new(Mutex::new(Vec::new()));
    let observed_confirmations = Arc::clone(&confirmations);
    let server_task = tokio::spawn(server.run_dispatch_with_context(
        shutdown_rx,
        move |context, request_id, command| {
            let observed_connections = Arc::clone(&observed_connections);
            let observed_confirmations = Arc::clone(&observed_confirmations);
            async move {
                if context.client_kind != ClientKind::Mcp {
                    return Err(ErrorCode::Untrusted);
                }
                match command {
                    ProtocolCommand::McpCall(call) => {
                        assert!(std::path::Path::new(&call.client_cwd).is_absolute());
                        observed_connections
                            .lock()
                            .unwrap()
                            .push(context.connection_id);
                        let historical = call.input.input == "second";
                        let mut envelope = McpResultEnvelope {
                            schema_version: 1,
                            request_id,
                            status: McpStatus::Ok,
                            scope: call.input.workspace,
                            freshness: "current".into(),
                            completeness: "complete".into(),
                            items: McpItems {
                                procedures: vec![McpItem {
                                    kind: "procedure_revision".into(),
                                    object_ref: None,
                                    object_revision_ref: Some(
                                        if historical {
                                            "019c0000-0000-7000-8000-000000000002"
                                        } else {
                                            "019c0000-0000-7000-8000-000000000001"
                                        }
                                        .into(),
                                    ),
                                    source_revision_ref: None,
                                    scope: None,
                                    applicability: Some("defer".into()),
                                    authority: Some("none".into()),
                                    text: Some("DEFER: insufficient context".into()),
                                    content_trust: ContentTrust::UntrustedSourceContent,
                                    capture_completeness: None,
                                    instruction_authority: InstructionAuthority::None,
                                }],
                                evidence: vec![McpItem {
                                    kind: "evidence".into(),
                                    object_ref: Some("atom:test".into()),
                                    object_revision_ref: None,
                                    source_revision_ref: None,
                                    scope: None,
                                    applicability: None,
                                    authority: None,
                                    // The daemon owns output formatting; transport must not
                                    // independently re-trim an already accepted response.
                                    text: Some(call.input.input.repeat(500)),
                                    content_trust: ContentTrust::UntrustedSourceContent,
                                    capture_completeness: None,
                                    instruction_authority: InstructionAuthority::None,
                                }],
                                ..McpItems::default()
                            },
                            warnings: Vec::new(),
                            truncated: false,
                            next_refs: Vec::new(),
                            audit_ref: None,
                        };
                        if !historical {
                            let mut old = envelope.items.procedures[0].clone();
                            old.object_revision_ref =
                                Some("019c0000-0000-7000-8000-000000000002".into());
                            envelope.items.procedures.push(old);
                        }
                        assert!(
                            (2_401..=4_800).contains(&serde_json::to_vec(&envelope).unwrap().len())
                        );
                        Ok(Response::McpResult(Box::new(envelope)))
                    }
                    ProtocolCommand::McpReturned { request_id } => {
                        let (expected, revisions) = context
                            .mcp_returned
                            .expect("server-owned response association");
                        assert_eq!(request_id, expected);
                        assert!((1..=2).contains(&revisions.len()));
                        if revisions.iter().all(|revision| {
                            revision.to_string() == "019c0000-0000-7000-8000-000000000002"
                        }) {
                            return Ok(Response::McpReturned); // real transport, no new eligibility
                        }
                        observed_confirmations
                            .lock()
                            .unwrap()
                            .push((context.connection_id, expected));
                        Ok(Response::McpReturned)
                    }
                    _ => Err(ErrorCode::InvalidInput),
                }
            }
        },
    ));
    let config = root.join("config.toml");
    fs::write(
        &config,
        format!(
            "config_version = 1\n[runtime]\ndata_dir = {:?}\n",
            data.to_string_lossy()
        ),
    )
    .unwrap();
    let executable = env!("CARGO_BIN_EXE_evertrace").to_owned();
    let config_for_child = config.clone();
    let output = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(executable)
            .args(["--config", config_for_child.to_str().unwrap(), "mcp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let requests = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"},\"capabilities\":{}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"evertrace\",\"arguments\":{\"action\":\"search\",\"workspace\":\"repo:019c0000-0000-7000-8000-000000000001\",\"input\":\"needle\",\"refs\":[]}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"evertrace\",\"arguments\":{\"action\":\"search\",\"workspace\":\"repo:019c0000-0000-7000-8000-000000000001\",\"input\":\"second\",\"refs\":[]}}}\n"
        );
        let mut input = child.stdin.take().unwrap();
        input.write_all(requests.as_bytes()).unwrap();
        writeln!(input, "{}", serde_json::json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"evertrace","arguments":{"action":"search","workspace":"repo:019c0000-0000-7000-8000-000000000001","input":"second","refs":[]}}})).unwrap();
        drop(input);
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 4);
    assert_eq!(
        messages[1]["result"]["structuredContent"]["items"]["evidence"][0]["text"],
        "needle".repeat(500)
    );
    assert_eq!(
        messages[2]["result"]["structuredContent"]["items"]["evidence"][0]["text"],
        "second".repeat(500)
    );
    {
        let observed = connection_ids.lock().unwrap();
        assert_eq!(observed.len(), 3);
        assert_eq!(observed[0], observed[1]);
        assert_eq!(observed[1], observed[2]);
        let confirmed = confirmations.lock().unwrap();
        assert_eq!(
            confirmed.len(),
            1,
            "historical-only acknowledgements retain the connection without new confirmations"
        );
        assert_eq!(confirmed[0].0, observed[0]);
    }
    // After initialization succeeds, close the actual stdout reader before
    // sending Search. The server responds, but write/flush cannot confirm it.
    let failed_config = config.clone();
    let failed = tokio::task::spawn_blocking(move || {
        use std::io::{BufRead, BufReader};
        let mut child = Command::new(env!("CARGO_BIN_EXE_evertrace"))
            .args(["--config", failed_config.to_str().unwrap(), "mcp"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        writeln!(input, "{}", serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"test","version":"1"},"capabilities":{}}})).unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut initialized = String::new();
        reader.read_line(&mut initialized).unwrap();
        assert!(!initialized.is_empty());
        drop(reader);
        writeln!(input, "{}", serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"})).unwrap();
        writeln!(input, "{}", serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"evertrace","arguments":{"action":"search","workspace":"repo:019c0000-0000-7000-8000-000000000001","input":"needle","refs":[]}}})).unwrap();
        drop(input);
        child.wait_with_output().unwrap()
    }).await.unwrap();
    assert!(!failed.status.success());
    assert_eq!(connection_ids.lock().unwrap().len(), 4);
    assert_eq!(confirmations.lock().unwrap().len(), 1);
    let socket = data.join("runtime/evertraced-v1.sock");
    let mut first = evertrace_protocol::LocalClient::connect(
        &socket,
        "s25-return",
        ClientKind::Mcp,
        std::time::Duration::from_secs(2),
    )
    .await
    .unwrap();
    let sent_id = RequestId::new_v7();
    first
        .request(
            sent_id,
            ProtocolCommand::McpCall(evertrace_protocol::command::McpCallCommand {
                input: evertrace_protocol::mcp::McpToolInput {
                    action: evertrace_protocol::mcp::McpAction::Search,
                    workspace: "repo:019c0000-0000-7000-8000-000000000001".into(),
                    input: "needle".into(),
                    refs: Vec::new(),
                },
                client_cwd: root.to_string_lossy().into_owned(),
            }),
        )
        .await
        .unwrap();
    let mut other = evertrace_protocol::LocalClient::connect(
        &socket,
        "s25-return",
        ClientKind::Mcp,
        std::time::Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert!(
        other
            .request(
                RequestId::new_v7(),
                ProtocolCommand::McpReturned {
                    request_id: sent_id
                }
            )
            .await
            .is_err()
    );
    assert!(
        first
            .request(
                RequestId::new_v7(),
                ProtocolCommand::McpReturned {
                    request_id: RequestId::new_v7()
                }
            )
            .await
            .is_err()
    );
    assert_eq!(confirmations.lock().unwrap().len(), 1);
    assert_eq!(
        first
            .request(
                RequestId::new_v7(),
                ProtocolCommand::McpReturned {
                    request_id: sent_id
                }
            )
            .await
            .unwrap(),
        Response::McpReturned
    );
    assert!(
        first
            .request(
                RequestId::new_v7(),
                ProtocolCommand::McpReturned {
                    request_id: sent_id
                }
            )
            .await
            .is_err()
    );
    assert_eq!(confirmations.lock().unwrap().len(), 2);
    drop(first);
    drop(other);
    shutdown_tx.send(true).unwrap();
    server_task.await.unwrap().unwrap();
    fs::remove_dir_all(root).unwrap();
}
