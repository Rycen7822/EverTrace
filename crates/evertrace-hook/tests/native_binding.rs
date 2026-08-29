use std::{
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    process::{Command, Stdio},
    thread,
};

use evertrace_capture::{RUNTIME_SNAPSHOT_VERSION, RecoveryGateMode, RuntimeSnapshot, SpoolLimits};
use evertrace_codex::{
    binding::CODEX_EVERTRACE_TOOL_NAME,
    install::{HookGeneration, StableLauncher},
};
use evertrace_protocol::{
    command::Command as ProtocolCommand,
    dto::{ClientKind, MAX_FRAME_SIZE, PROTOCOL_VERSION},
    envelope::{ClientEnvelope, ServerEnvelope},
    frame::{read_frame_sync, write_frame_sync},
    handshake::HandshakeAck,
    response::{McpBindingIssuedResponse, Response, ResponseEnvelope},
};

fn unique_root() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "evertrace-hook-native-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[test]
fn stable_launcher_performs_native_pretooluse_uds_issue_and_exact_rewrite() {
    let root = unique_root();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let data = root.join("data");
    fs::create_dir(&data).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = data.join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = runtime.join("evertraced-v1.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();

    let snapshot = RuntimeSnapshot {
        snapshot_version: RUNTIME_SNAPSHOT_VERSION,
        generation: 1,
        device_key_dir: data.join("keys"),
        cas_dir: data.join("cas"),
        spool_dir: data.join("spool"),
        main_high_watermark_bytes: 256 * 1024,
        main_low_watermark_bytes: 64 * 1024,
        max_main_files: 8,
        emergency_slots: 2,
        effective_config_hash: [1; 32],
        recovery_gate: RecoveryGateMode::Disabled,
        recovery_adapter_manifest_id: None,
        recovery_classifier_revision: 1,
        recovery_socket_path: socket.clone(),
        recovery_preflight_timeout_ms: 250,
        recovery_max_bundle_bytes: 4 << 20,
        recovery_max_untracked_file_bytes: 1 << 20,
        recovery_max_untracked_total_bytes: 2 << 20,
    };
    assert!(snapshot.spool_limits().is_ok_and(|limits| limits
        == SpoolLimits {
            high_watermark_bytes: 256 * 1024,
            low_watermark_bytes: 64 * 1024,
            max_main_files: 8,
            emergency_slots: 2,
        }));
    let snapshot_path = runtime.join("hook-runtime-v1.json");
    snapshot.publish(&snapshot_path).unwrap();

    let install = root.join("install");
    let launcher = StableLauncher::open(&install).unwrap();
    let pinned_executable = root.join("evertrace-hook-generation-1");
    fs::copy(env!("CARGO_BIN_EXE_evertrace-hook"), &pinned_executable).unwrap();
    fs::set_permissions(&pinned_executable, fs::Permissions::from_mode(0o700)).unwrap();
    launcher
        .publish_generation(HookGeneration {
            generation: 1,
            protocol_version: 1,
            executable: pinned_executable,
            runtime_snapshot: snapshot_path,
            compatible: true,
        })
        .unwrap();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let ClientEnvelope::Handshake(handshake) =
            read_frame_sync(&mut stream, MAX_FRAME_SIZE).unwrap()
        else {
            panic!("expected handshake")
        };
        assert_eq!(handshake.client_kind, ClientKind::Hook);
        write_frame_sync(
            &mut stream,
            &ServerEnvelope::HandshakeAck(HandshakeAck {
                protocol_version: PROTOCOL_VERSION,
                build_id: "s20-native-test".into(),
                max_frame: MAX_FRAME_SIZE as u32,
            }),
            MAX_FRAME_SIZE,
        )
        .unwrap();
        let ClientEnvelope::Command(command) =
            read_frame_sync(&mut stream, MAX_FRAME_SIZE).unwrap()
        else {
            panic!("expected command")
        };
        let ProtocolCommand::IssueMcpBinding(issue) = command.command else {
            panic!("expected binding issue")
        };
        assert_eq!(issue.session_id, "session-native");
        assert_eq!(issue.agent_id.as_deref(), Some("agent-native"));
        assert_eq!(issue.original_input.workspace, "@active");
        assert_eq!(issue.original_input.input, "needle");
        assert_eq!(issue.original_input.refs, ["atom:a"]);
        write_frame_sync(
            &mut stream,
            &ServerEnvelope::Response(ResponseEnvelope {
                request_id: command.request_id,
                response: Response::McpBindingIssued(McpBindingIssuedResponse {
                    bound_workspace: "@bound:v1:01234567890123456789012345678901".into(),
                    expires_at_us: 1,
                }),
            }),
            MAX_FRAME_SIZE,
        )
        .unwrap();
    });

    let native = format!(
        "{{\"agent_id\":\"agent-native\",\"cwd\":\"/workspace/project\",\"hook_event_name\":\"PreToolUse\",\"model\":\"gpt-5\",\"permission_mode\":\"default\",\"session_id\":\"session-native\",\"tool_input\":{{\"action\":\"search\",\"workspace\":\"@active\",\"input\":\"needle\",\"refs\":[\"atom:a\"]}},\"tool_name\":\"{CODEX_EVERTRACE_TOOL_NAME}\",\"tool_use_id\":\"tool-native\",\"transcript_path\":null,\"turn_id\":\"turn-native\"}}"
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_evertrace-hook"))
        .args(["--launcher-root", install.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(native.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\",\"updatedInput\":{\"action\":\"search\",\"workspace\":\"@bound:v1:01234567890123456789012345678901\",\"input\":\"needle\",\"refs\":[\"atom:a\"]}}}"
    );
    server.join().unwrap();

    for unchanged in [
        native.replace(CODEX_EVERTRACE_TOOL_NAME, "mcp__other__evertrace"),
        native.clone(),
        native.replacen("{", "{\"unknown\":true,", 1),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_evertrace-hook"))
            .args(["--launcher-root", install.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(unchanged.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    fs::remove_dir_all(root).unwrap();
}
