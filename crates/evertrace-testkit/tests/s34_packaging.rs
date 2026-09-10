use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    process::{Command, Stdio},
};

use evertrace_capture::{DurableSpool, RuntimeSnapshot};
use evertrace_codex::install::ManagedInstallPaths;
use evertrace_domain::{
    config::EffectiveConfig,
    evidence::{CaptureCompleteness, CorrelationAdmission, IdentityStrength},
};
use evertrace_engine::{EvidenceIngestor, maintenance::install_offline, spawn_writer};
use evertrace_store::{JournalPayload, JournalWriter};
use tempfile::TempDir;

fn fixture() -> (TempDir, ManagedInstallPaths, EffectiveConfig) {
    let root = TempDir::new().unwrap();
    let package = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let data = root.path().join("data");
    let default = EffectiveConfig::default();
    let source = default
        .to_toml()
        .unwrap()
        .replace(&default.config().runtime.data_dir, data.to_str().unwrap());
    let config = EffectiveConfig::parse_toml(&source).unwrap();
    let config_path = root.path().join("evertrace.toml");
    fs::write(&config_path, source).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    let host_executable = root.path().join("codex-probe");
    fs::write(&host_executable, "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'codex-cli 0.1.0'; else echo 'hooks experimental true'; fi\n").unwrap();
    fs::set_permissions(&host_executable, fs::Permissions::from_mode(0o700)).unwrap();
    evertrace_codex::probe::probe_install_host(&host_executable, root.path())
        .expect("isolated host probe");
    let paths = ManagedInstallPaths {
        data_root: data,
        host_config: root.path().join("codex/config.toml"),
        unit: root.path().join("systemd/evertraced.service"),
        config: config_path,
        cli: package.join("evertrace"),
        hook: package.join("evertrace-hook"),
        daemon: package.join("evertraced"),
        systemctl: root.path().join("systemctl"),
        host_executable,
    };
    (root, paths, config)
}

#[tokio::test]
async fn strict_reload_keeps_last_good_and_withdraws_whole_pending_config() {
    use evertrace_engine::{
        ConfigReloadOutcome, ConfigReloadService, ConfigReloadSource, EngineService, RuntimeMode,
    };
    use std::sync::Arc;
    let (_root, paths, initial) = fixture();
    fs::create_dir(&paths.data_root).unwrap();
    fs::set_permissions(&paths.data_root, fs::Permissions::from_mode(0o700)).unwrap();
    let source = initial.to_toml().unwrap();
    let engine = Arc::new(EngineService::from_toml(&source, RuntimeMode::Normal).unwrap());
    let writer = JournalWriter::open(&paths.data_root).await.unwrap();
    let (handle, task) = spawn_writer(writer, 16).unwrap();
    let reload = ConfigReloadService::new(
        Arc::clone(&engine),
        handle.clone(),
        paths.data_root.clone(),
        paths.config.clone(),
    )
    .unwrap();
    let startup = reload.initialize_runtime().await.unwrap();
    let old_operation = reload.admit().await.unwrap();
    let hot = source.replace("get_token_budget = 1200", "get_token_budget = 17");
    assert_ne!(hot, source);
    fs::write(&paths.config, &hot).unwrap();
    let applied = reload.reload(ConfigReloadSource::Cli).await.unwrap();
    assert_eq!(applied.outcome, ConfigReloadOutcome::Applied);
    assert_eq!(old_operation.hash(), initial.hash());
    assert_ne!(reload.admit().await.unwrap().hash(), old_operation.hash());
    let runtime = RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&paths.data_root)).unwrap();
    assert_eq!(runtime.generation, startup.generation);
    assert_eq!(runtime.recovery_gate, startup.recovery_gate);
    assert_eq!(runtime.effective_config_hash, applied.active_hash);
    let mixed = hot.replace(
        paths.data_root.to_str().unwrap(),
        paths.data_root.join("other").to_str().unwrap(),
    );
    fs::write(&paths.config, mixed).unwrap();
    let pending = reload.reload(ConfigReloadSource::Cli).await.unwrap();
    assert_eq!(pending.outcome, ConfigReloadOutcome::RestartRequired);
    assert_eq!(pending.active_hash, applied.active_hash);
    assert!(pending.pending_hash.is_some());
    fs::write(&paths.config, "invalid[").unwrap();
    let rejected = reload.reload(ConfigReloadSource::Cli).await.unwrap();
    assert_eq!(rejected.outcome, ConfigReloadOutcome::Rejected);
    assert_eq!(rejected.active_hash, applied.active_hash);
    assert_eq!(rejected.pending_hash, None);
    fs::write(&paths.config, &source).unwrap();
    reload.watch_once().await.unwrap();
    assert_eq!(reload.admit().await.unwrap().hash(), initial.hash());
    let (_, file_hash) = reload.read_editable().unwrap();
    let external = format!("{source}\n# concurrent owner edit\n");
    fs::write(&paths.config, &external).unwrap();
    assert!(reload.write_optimistic(&hot, &file_hash).await.is_err());
    assert_eq!(fs::read_to_string(&paths.config).unwrap(), external);
    let (_, fresh_hash) = reload.read_editable().unwrap();
    let edited = format!("{hot}\n# concurrent owner edit\n");
    assert_eq!(
        reload
            .write_optimistic(&edited, &fresh_hash)
            .await
            .unwrap()
            .outcome,
        ConfigReloadOutcome::Applied
    );
    assert_eq!(fs::read_to_string(&paths.config).unwrap(), edited);
    let fence = evertrace_capture::MaintenanceFence::open(&paths.data_root).unwrap();
    let operation = fence.shared().unwrap();
    fs::write(&paths.config, &source).unwrap();
    assert!(matches!(
        reload.reload(ConfigReloadSource::Cli).await,
        Err(evertrace_engine::ConfigReloadError::Busy)
    ));
    let snapshot = handle.project().await.unwrap();
    let current = snapshot
        .rows
        .iter()
        .find(|row| row.row_id == "runtime:config:current")
        .unwrap();
    let JournalPayload::ConfigAudit(audit) =
        serde_json::from_str(current.payload_json.as_ref().unwrap()).unwrap()
    else {
        panic!("config audit")
    };
    assert_eq!(
        audit.effective_config_hash,
        reload.admit().await.unwrap().hash()
    );
    assert_ne!(
        audit.effective_config_hash,
        initial.hash(),
        "Prepared never advances current"
    );
    drop(operation);
    reload.reload(ConfigReloadSource::Cli).await.unwrap();
    let incremental = handle.project().await.unwrap();
    handle.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let reopened = JournalWriter::open(&paths.data_root).await.unwrap();
    let full = reopened.full_projection().await.unwrap();
    for id in ["runtime:config:current", "runtime:config:attempt"] {
        assert_eq!(
            incremental.rows.iter().find(|row| row.row_id == id),
            full.rows.iter().find(|row| row.row_id == id)
        );
    }
}

#[tokio::test]
async fn strict_reload_config_transport_and_dynamic_log_callsite() {
    use evertrace_protocol::{command::Command as Rpc, dto::ClientKind, response::Response};
    use std::time::{Duration, Instant};
    let (root, paths, initial) = fixture();
    let log_path = root.path().join("daemon.log");
    struct Daemon(std::process::Child);
    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut daemon = Daemon(
        Command::new(&paths.daemon)
            .arg("--config")
            .arg(&paths.config)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log_path).unwrap())
            .spawn()
            .unwrap(),
    );
    let socket = paths.data_root.join("runtime/evertraced-v1.sock");
    let deadline = Instant::now() + Duration::from_secs(15);
    while !package_health(socket.clone()).await {
        assert!(Instant::now() < deadline && daemon.0.try_wait().unwrap().is_none());
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let mut client = evertrace_protocol::LocalClient::connect(
        &socket,
        "reload-test",
        ClientKind::Cli,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    for level in ["error", "info", "error"] {
        let Response::ConfigDocument(document) = client
            .request(evertrace_domain::ids::RequestId::new_v7(), Rpc::ConfigRead)
            .await
            .unwrap()
        else {
            panic!("config read")
        };
        let source = initial
            .to_toml()
            .unwrap()
            .replace("log_level = \"info\"", &format!("log_level = \"{level}\""));
        let Response::ConfigReload(result) = client
            .request(
                evertrace_domain::ids::RequestId::new_v7(),
                Rpc::ConfigWrite(evertrace_protocol::command::ConfigWriteCommand {
                    source,
                    expected_file_hash: document.file_hash,
                }),
            )
            .await
            .unwrap()
        else {
            panic!("config write")
        };
        assert_eq!(
            result.outcome,
            evertrace_protocol::dto::ConfigReloadOutcome::Applied
        );
    }
    // The exact same INFO callsite must be enabled after initially disabled,
    // then disabled again, without rebuilding the subscriber.
    assert_eq!(
        fs::read_to_string(&log_path)
            .unwrap()
            .matches("configuration result")
            .count(),
        1
    );
    fs::write(&paths.config, "invalid[").unwrap();
    let output = Command::new(&paths.cli)
        .args(["config", "reload", "--socket"])
        .arg(&socket)
        .env_clear()
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Rejected"));
    fs::write(&paths.config, initial.to_toml().unwrap()).unwrap();
    client
        .request(
            evertrace_domain::ids::RequestId::new_v7(),
            Rpc::ConfigReload,
        )
        .await
        .unwrap();
    fs::write(&paths.config, "invalid[").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fs::read_to_string(&log_path)
        .unwrap()
        .contains("configuration watch rejected")
    {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(
        fs::read_to_string(&log_path)
            .unwrap()
            .matches("configuration watch rejected")
            .count(),
        1
    );
    assert!(package_health(socket).await);
}

#[test]
#[ignore = "requires a retained pre-reload Hook executable via EVERTRACE_TEST_OLD_HOOK"]
fn strict_reload_real_old_hook_uses_invocation_snapshot_and_inherited_fence() {
    use evertrace_codex::{
        binding::NativeToolUse, hook_input::CaptureHookInput, install::StableLauncher,
    };
    use std::{
        os::unix::net::UnixListener,
        time::{Duration, Instant},
    };
    let old_hook = std::env::var_os("EVERTRACE_TEST_OLD_HOOK").expect("retained old executable");
    let (_root, paths, _) = fixture();
    install_offline(&paths, false).unwrap();
    let launcher = StableLauncher::open(&paths.data_root).unwrap();
    let generation = launcher.resolve_for_session("reload-old-child").unwrap();
    fs::copy(old_hook, &generation.executable).unwrap();
    fs::set_permissions(&generation.executable, fs::Permissions::from_mode(0o700)).unwrap();
    let native = NativeToolUse::from_json(&serde_json::to_vec(&serde_json::json!({
        "cwd": paths.data_root, "hook_event_name":"PreToolUse", "model":"test",
        "permission_mode":"default", "session_id":"reload-old-child", "tool_input":{"command":"rm doomed.txt"},
        "tool_name":"Bash", "tool_use_id":"reload-tool", "transcript_path":null, "turn_id":"reload-turn"
    })).unwrap()).unwrap();
    fs::write(paths.data_root.join("doomed.txt"), "must remain").unwrap();
    let mut input = CaptureHookInput::from_native(native, generation.generation).unwrap();
    // Exercise the existing typed recovery boundary, not native weak-delivery
    // qualification (which deliberately cannot activate recovery).
    input.payload = serde_json::json!({
        "program": "rm", "args": ["doomed.txt"], "cwd": paths.data_root
    })
    .to_string();
    input.repository_instance_id = Some(evertrace_domain::ids::RepositoryId::new_v7().to_string());
    input.worktree_instance_id = Some(evertrace_domain::ids::WorktreeId::new_v7().to_string());
    let mut pinned = RuntimeSnapshot::load(&generation.runtime_snapshot).unwrap();
    pinned.recovery_gate = evertrace_capture::RecoveryGateMode::Active;
    pinned.recovery_adapter_manifest_id = Some(input.adapter_manifest_ref.clone());
    pinned.recovery_preflight_timeout_ms = 3000;
    pinned.publish(&generation.runtime_snapshot).unwrap();
    let pinned_bytes = fs::read(&generation.runtime_snapshot).unwrap();
    let mut current = pinned.clone();
    current.recovery_preflight_timeout_ms = 1000;
    current.effective_config_hash = [42; 32];
    current
        .publish(&RuntimeSnapshot::snapshot_path(&paths.data_root))
        .unwrap();
    let _listener = UnixListener::bind(&current.recovery_socket_path).unwrap();
    fs::set_permissions(
        &current.recovery_socket_path,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let input = input.to_json().unwrap();
    let spawn = |executable: &std::path::Path, option: &str, target: &std::path::Path| {
        let mut child = Command::new(executable)
            .arg(option)
            .arg(target)
            .current_dir(&paths.data_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&input).unwrap();
        child
    };
    let started = Instant::now();
    assert!(
        spawn(
            &generation.executable,
            "--runtime-snapshot",
            &generation.runtime_snapshot
        )
        .wait()
        .unwrap()
        .success()
    );
    assert!(
        started.elapsed() >= Duration::from_millis(2500),
        "artifact must exhibit the old pinned-only timeout behavior"
    );
    let started = Instant::now();
    assert!(
        spawn(&paths.hook, "--launcher-root", &paths.data_root)
            .wait()
            .unwrap()
            .success()
    );
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "current launcher must pass the new timeout to the real old child"
    );
    assert_eq!(
        fs::read(&generation.runtime_snapshot).unwrap(),
        pinned_bytes
    );
    assert!(paths.data_root.join("doomed.txt").exists());
    let mut parent = spawn(&paths.hook, "--launcher-root", &paths.data_root);
    std::thread::sleep(Duration::from_millis(300));
    parent.kill().unwrap();
    parent.wait().unwrap();
    let fence = evertrace_capture::MaintenanceFence::open(&paths.data_root).unwrap();
    assert!(matches!(
        fence.exclusive(),
        Err(evertrace_capture::CasError::LockBusy)
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
    let guard = loop {
        if let Ok(guard) = fence.exclusive() {
            break guard;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    };
    let _second_interrupted = evertrace_capture::InvocationSnapshot::prepare(
        &paths.data_root,
        &generation.runtime_snapshot,
        &guard,
    )
    .unwrap();
    evertrace_capture::InvocationSnapshot::clean_interrupted(&paths.data_root, &guard).unwrap();
    let slots = paths.data_root.join("runtime/hook-invocations");
    for (name, bytes) in [("0.v4", &b""[..]), ("1.v4", &b"partial"[..])] {
        fs::write(slots.join(name), bytes).unwrap();
        fs::set_permissions(slots.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    evertrace_capture::InvocationSnapshot::clean_interrupted(&paths.data_root, &guard).unwrap();
    std::os::unix::fs::symlink(&generation.runtime_snapshot, slots.join("0.v4")).unwrap();
    assert!(
        evertrace_capture::InvocationSnapshot::clean_interrupted(&paths.data_root, &guard).is_err()
    );
    fs::remove_file(slots.join("0.v4")).unwrap();
    fs::write(slots.join("0.v4"), b"").unwrap();
    fs::set_permissions(slots.join("0.v4"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        evertrace_capture::InvocationSnapshot::clean_interrupted(&paths.data_root, &guard).is_err()
    );
    assert!(slots.join("0.v4").is_file());
    fs::set_permissions(slots.join("0.v4"), fs::Permissions::from_mode(0o600)).unwrap();
    evertrace_capture::InvocationSnapshot::clean_interrupted(&paths.data_root, &guard).unwrap();
    assert_eq!(
        fs::read_dir(paths.data_root.join("runtime/hook-invocations"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn mcp_output_budgets_are_consumed_by_the_running_daemon() {
    use evertrace_domain::{
        ids::{CommandId, RepositoryId},
        repository::{FilesystemIdentity, GitObjectFormat, PathObservation, RepositoryInstance},
        semantic::{
            ApplicabilityExpr, AtomDraft, AtomKind, AtomProvenance, AtomScope, AtomValue,
            ConstraintExpr, ConstraintField, EpistemicStatus, ValidityInterval,
        },
    };
    use evertrace_engine::semantic::{AtomAuthorityBasis, AtomMaterialization, materialize_atom};
    use evertrace_store::{JournalCommand, JournalEventDraft};
    use serde_json::{Value, json};
    use std::time::{Duration, Instant};
    let (_root, paths, config) = fixture();
    let repository_id = RepositoryId::new_v7();
    install_offline(&paths, false).unwrap();
    invoke(&paths, &serde_json::to_vec(&json!({"cwd":paths.data_root,"hook_event_name":"PreToolUse","model":"test","permission_mode":"default","session_id":"budget-session","tool_input":{"command":"echo budgetneedle ".repeat(2500)},"tool_name":"Bash","tool_use_id":"budget-tool","transcript_path":null,"turn_id":"budget-turn"})).unwrap());
    let runtime = RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&paths.data_root)).unwrap();
    let (mut spool, _) =
        DurableSpool::open(runtime.spool_dir.clone(), runtime.spool_limits().unwrap()).unwrap();
    spool.seal_active(runtime.generation).unwrap();
    drop(spool);
    let (handle, actor) = spawn_writer(
        evertrace_engine::open_writer(&paths.data_root)
            .await
            .unwrap(),
        8,
    )
    .unwrap();
    EvidenceIngestor::new(runtime, handle.clone(), config.hash(), "s34-budget-v1")
        .unwrap()
        .with_operation_config(std::sync::Arc::new(config.clone()))
        .drain_once()
        .await
        .unwrap();
    let snapshot = handle.project().await.unwrap();
    let receipt_row = snapshot
        .data_rows()
        .find(|row| row.object_kind.as_deref() == Some("source_receipt"))
        .unwrap();
    assert!(receipt_row.payload_json.as_ref().unwrap().len() > 8192);
    let receipt_ref = receipt_row.object_id.clone().unwrap();
    let observation = snapshot
        .data_rows()
        .find_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SourceObservationRecorded(value) => {
                    Some(value.source_observation_id)
                }
                _ => None,
            }
        })
        .unwrap();
    drop(handle);
    actor.await.unwrap().unwrap();
    let path = paths.data_root.to_string_lossy().into_owned();
    let repository = RepositoryInstance {
        user_disabled: false,
        capability_state: None,
        repository_id,
        repository_revision: 1,
        predecessor_revision: None,
        current_path: path.clone(),
        path_history: vec![PathObservation {
            path,
            first_observed_at_us: 1,
            last_observed_at_us: 1,
            evidence_refs: vec!["local-test".into()],
        }],
        git_common_dir_path: Some(format!("{}/.git", paths.data_root.display())),
        common_dir_filesystem: Some(FilesystemIdentity {
            device: 1,
            inode: 1,
        }),
        object_format: Some(GitObjectFormat::Sha1),
        remote_fingerprints: Vec::new(),
        derived_from: None,
        identity_evidence_refs: vec!["local-test".into()],
        recorded_at_us: 1,
    };
    let atom = materialize_atom(
        AtomMaterialization {
            draft: AtomDraft {
                kind: AtomKind::Claim,
                epistemic_status: EpistemicStatus::Unverified,
                value: AtomValue {
                    text: "budgetneedle bounded evidence ".repeat(120),
                    subject: "budgetneedle".into(),
                    predicate: "records".into(),
                    object: None,
                    qualifiers: Vec::new(),
                    critical_revision_refs: Vec::new(),
                },
                scope: AtomScope::Repository {
                    repository_instance_id: repository_id,
                },
                applicability_expr: ApplicabilityExpr::Constraint(ConstraintExpr::Exists {
                    field: ConstraintField::Phase,
                }),
                future_cue_lifecycle_exprs: None,
                validity_interval: ValidityInterval {
                    valid_from_us: 1,
                    valid_until_us: None,
                },
                provenance: vec![AtomProvenance::AgentClaimed],
                source_observation_refs: vec![observation],
                evidence_refs: vec![observation.to_string()],
                supersedes_revision_refs: Vec::new(),
                supports_revision_refs: Vec::new(),
                contradicts_revision_refs: Vec::new(),
            },
            authority_basis: AtomAuthorityBasis::AgentInferred,
            accepted_proposal_id: None,
            accepted_proposal_revision_id: None,
            created_at_us: 1,
        },
        None,
    )
    .unwrap();
    let reference = atom.atom_id.to_string();
    repository.validate().unwrap();
    atom.validate().unwrap();
    let mut writer = evertrace_engine::open_writer(&paths.data_root)
        .await
        .unwrap();
    for payload in [
        JournalPayload::RepositoryInstanceRecorded(Box::new(repository)),
        JournalPayload::AtomRecorded(Box::new(atom)),
    ] {
        let command = JournalCommand::new(
            CommandId::new_v7(),
            vec![JournalEventDraft::runtime(
                1,
                config.hash(),
                "s34-budget-v1",
                payload,
            )],
        )
        .unwrap();
        writer.commit(&command, 1).await.unwrap_or_else(|error| {
            panic!("{}: {error:?}", command.events()[0].payload.event_type())
        });
    }
    writer.project().await.unwrap();
    drop(writer);
    struct Daemon(std::process::Child);
    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut lengths = Vec::new();
    // Reverse low budgets to expose action mixups. The default case also
    // proves the same running daemon consumes a real CLI reload.
    for (search, get) in [(0, 1_200), (600, 1), (600, 1_200), (1_200, 2_400)] {
        let mut source = config.config().clone();
        source.llm.enabled = false;
        source.search.search_token_budget = search;
        source.search.get_token_budget = get;
        let desired = EffectiveConfig::new(source.clone()).unwrap();
        if (search, get) == (600, 1_200) {
            source.search.search_token_budget = 0;
            source.search.get_token_budget = 1;
        }
        fs::write(
            &paths.config,
            EffectiveConfig::new(source).unwrap().to_toml().unwrap(),
        )
        .unwrap();
        let mut daemon = Daemon(
            Command::new(&paths.daemon)
                .arg("--config")
                .arg(&paths.config)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        while !package_health(paths.data_root.join("runtime/evertraced-v1.sock")).await {
            assert!(daemon.0.try_wait().unwrap().is_none());
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        if (search, get) == (600, 1_200) {
            fs::write(&paths.config, desired.to_toml().unwrap()).unwrap();
            let reloaded = Command::new(&paths.cli)
                .args(["config", "reload", "--socket"])
                .arg(paths.data_root.join("runtime/evertraced-v1.sock"))
                .env_clear()
                .output()
                .unwrap();
            assert!(
                reloaded.status.success(),
                "{}",
                String::from_utf8_lossy(&reloaded.stderr)
            );
            assert!(daemon.0.try_wait().unwrap().is_none());
        }
        let mut requests = vec![
            json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"budget-test","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        ];
        for (id, action, input) in [
            (1, "search", "budgetneedle"),
            (2, "get", reference.as_str()),
            (3, "get", receipt_ref.as_str()),
        ] {
            requests.push(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"evertrace","arguments":{"action":action,"workspace":repository_id.to_string(),"input":input,"refs":[]}}}));
        }
        let mut cli = Command::new(&paths.cli)
            .arg("--config")
            .arg(&paths.config)
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = cli.stdin.take().unwrap();
        for request in requests {
            writeln!(stdin, "{request}").unwrap();
        }
        drop(stdin);
        let output = cli.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let messages: Vec<Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let mut pair = Vec::new();
        for (index, target, hard) in [(1, search, 4_800), (2, get, 9_600)] {
            let result = &messages[index]["result"]["structuredContent"];
            assert!(
                matches!(
                    result["status"].as_str(),
                    Some("ok" | "partial" | "degraded_index")
                ),
                "{result}"
            );
            let bytes = serde_json::to_vec(result).unwrap().len();
            assert!(bytes <= hard);
            let items = result["items"]["evidence"].as_array().unwrap();
            if target <= 1 {
                assert!(items.is_empty() && result["truncated"] == true);
                assert!(
                    result["next_refs"]
                        .as_array()
                        .unwrap()
                        .contains(&json!(reference))
                );
            } else {
                assert!(!items.is_empty(), "{result}");
                for item in items {
                    assert_eq!(item["instruction_authority"], "none");
                    assert!(item["content_trust"].is_string());
                    assert!(item["object_ref"].is_string());
                }
            }
            pair.push(bytes);
        }
        lengths.push(pair);
        if get > 1 {
            let receipt_result = &messages[3]["result"]["structuredContent"];
            let items = receipt_result["items"]["evidence"].as_array().unwrap();
            assert_eq!(items.len(), 1, "{receipt_result}");
            assert_eq!(items[0]["instruction_authority"], "none");
            let text = items[0]["text"].as_str().unwrap();
            assert!(
                text.contains("cas_ref") && text.contains("protected_length"),
                "{text}"
            );
            assert!(!text.contains("source_instance_id"));
        }
        drop(daemon);
    }
    assert!(lengths[0][0] < lengths[2][0]);
    assert!(lengths[1][1] < lengths[2][1]);
    assert!(lengths[2][0] <= lengths[3][0] && lengths[2][1] <= lengths[3][1]);
}

fn service(paths: &ManagedInstallPaths, body: &str) {
    fs::write(&paths.systemctl, format!("#!/bin/sh\nif [ \"$2\" = is-enabled ]; then echo disabled; exit 1; fi\nif [ \"$2\" = is-active ]; then echo inactive; exit 3; fi\n{body}\n")).unwrap();
    fs::set_permissions(&paths.systemctl, fs::Permissions::from_mode(0o700)).unwrap();
}

async fn package_health(socket: std::path::PathBuf) -> bool {
    evertrace_protocol::request_health(
        &socket,
        env!("CARGO_PKG_VERSION"),
        std::time::Duration::from_secs(2),
    )
    .await
    .is_ok_and(|health| health.validate())
}

#[tokio::test]
async fn candidate_native_binary_validates_without_starting_or_repairing() {
    let (root, paths, _) = fixture();
    drop(JournalWriter::open(&paths.data_root).await.unwrap());
    let native = evertrace_store::connection::native_root(&paths.data_root);
    let run = |path: &std::path::Path| {
        Command::new(&paths.daemon)
            .arg("--verify-package-native")
            .arg(path)
            .arg("--cas")
            .arg(root.path().join("absent-cas"))
            .env_clear()
            .output()
            .unwrap()
    };
    let valid = run(&native);
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert_eq!(valid.stdout, b"candidate native verified\n");
    assert!(!paths.data_root.join("runtime").exists());
    let broken = root.path().join("broken-native");
    fs::create_dir(&broken).unwrap();
    fs::set_permissions(&broken, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(broken.join("unrelated"), b"preserve").unwrap();
    assert!(!run(&broken).status.success());
    assert_eq!(fs::read_dir(&broken).unwrap().count(), 1);
    assert_eq!(fs::read(broken.join("unrelated")).unwrap(), b"preserve");
}

#[tokio::test]
async fn ordinary_daemon_imports_offline_active_and_replay_but_never_acks_bad_cas() {
    use std::time::Duration;
    let (_root, paths, initial) = fixture();
    let mut settings = initial.config().clone();
    settings.capture.preview_bytes = 256;
    settings.capture.inline_payload_bytes = 1024;
    fs::write(
        &paths.config,
        EffectiveConfig::new(settings.clone())
            .unwrap()
            .to_toml()
            .unwrap(),
    )
    .unwrap();
    install_offline(&paths, false).unwrap();
    let native = serde_json::json!({"cwd":paths.data_root,"hook_event_name":"PreToolUse","model":"test","permission_mode":"default","session_id":"ordinary-backlog","tool_input":{"command":"true ".repeat(500)},"tool_name":"Bash","tool_use_id":"one","transcript_path":null,"turn_id":"one"});
    invoke(&paths, &serde_json::to_vec(&native).unwrap());
    let runtime = RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&paths.data_root)).unwrap();
    let spool =
        DurableSpool::open_read_only(runtime.spool_dir.clone(), runtime.spool_limits().unwrap())
            .unwrap();
    let original = spool.read_active().unwrap().remove(0).record;
    drop(spool);
    struct Daemon(std::process::Child);
    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let spawn = || {
        Daemon(
            Command::new(&paths.daemon)
                .arg("--config")
                .arg(&paths.config)
                .env_clear()
                .env("HOME", paths.data_root.parent().unwrap())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        )
    };
    let mut original_receipt = None;
    for replay in [false, true] {
        if replay {
            settings.capture.preview_bytes = 1024;
            settings.capture.inline_payload_bytes = 8192;
            fs::write(
                &paths.config,
                EffectiveConfig::new(settings.clone())
                    .unwrap()
                    .to_toml()
                    .unwrap(),
            )
            .unwrap();
            let mut spool = DurableSpool::open_read_only(
                runtime.spool_dir.clone(),
                runtime.spool_limits().unwrap(),
            )
            .unwrap();
            spool.append(&original).unwrap();
        }
        let mut daemon = spawn();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if package_health(paths.data_root.join("runtime/evertraced-v1.sock")).await {
                let connection = evertrace_store::connection::CompatibilityStore::connect_local(
                    &evertrace_store::connection::native_root(&paths.data_root),
                )
                .await
                .unwrap();
                let journal = connection
                    .connection()
                    .open_table(evertrace_store::JOURNAL_TABLE)
                    .execute()
                    .await
                    .unwrap();
                let payloads = evertrace_store::journal::read_all_journal_rows(&journal)
                    .await
                    .unwrap()
                    .iter()
                    .map(|row| row.payload().unwrap())
                    .collect::<Vec<_>>();
                let receipts = payloads
                    .iter()
                    .filter(|payload| matches!(payload, JournalPayload::SourceReceiptRecorded(_)))
                    .count();
                assert!(receipts <= 1);
                let spool = DurableSpool::open_read_only(
                    runtime.spool_dir.clone(),
                    runtime.spool_limits().unwrap(),
                )
                .unwrap();
                if receipts == 1
                    && spool.read_active().unwrap().is_empty()
                    && !fs::read_dir(runtime.spool_dir.join("main"))
                        .unwrap()
                        .any(|entry| {
                            entry
                                .unwrap()
                                .path()
                                .extension()
                                .is_some_and(|value| value == "sealed")
                        })
                    && payloads.iter().any(|payload| {
                        matches!(payload, JournalPayload::HostOccurrenceNormalized(_))
                    })
                {
                    let receipt = payloads
                        .iter()
                        .find_map(|payload| match payload {
                            JournalPayload::SourceReceiptRecorded(receipt) => Some(receipt),
                            _ => None,
                        })
                        .unwrap();
                    assert!(matches!(&receipt.protected_presentation,
                        Some(evertrace_domain::evidence::ProtectedPresentation::Preview { text }) if text.len() <= 256));
                    if let Some(previous) = &original_receipt {
                        assert_eq!(
                            receipt, previous,
                            "replayed frame retains its first presentation snapshot"
                        );
                    } else {
                        original_receipt = Some(receipt.clone());
                    }
                    assert!(payloads.iter().any(|payload| matches!(
                        payload,
                        JournalPayload::SourceIngestWatermark(_)
                    )));
                    assert!(!payloads.iter().any(|payload| matches!(
                        payload,
                        JournalPayload::ExecutionLaneRecorded(_)
                            | JournalPayload::CaptureReceiptRecorded(_)
                    )));
                    break;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline && daemon.0.try_wait().unwrap().is_none()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !replay {
            use evertrace_protocol::{
                command::Command as Rpc,
                dto::{
                    ClientKind, HumanActionRequest, HumanActionStatus, HumanGovernanceRequest,
                    HumanGovernanceResponse, HumanReadRequest, HumanSurface,
                },
                response::Response,
            };
            let mut client = evertrace_protocol::LocalClient::connect(
                &paths.data_root.join("runtime/evertraced-v1.sock"),
                "s34-test",
                ClientKind::Cli,
                Duration::from_secs(3),
            )
            .await
            .unwrap();
            let mut requested = false;
            settings.capture.preview_bytes = 512;
            fs::write(
                &paths.config,
                EffectiveConfig::new(settings.clone())
                    .unwrap()
                    .to_toml()
                    .unwrap(),
            )
            .unwrap();
            let response = client
                .request(
                    evertrace_domain::ids::RequestId::new_v7(),
                    Rpc::ConfigReload,
                )
                .await
                .unwrap();
            assert!(
                matches!(response, Response::ConfigReload(result) if result.outcome == evertrace_protocol::dto::ConfigReloadOutcome::Applied)
            );
            for _ in 0..4 {
                let Response::HumanGovernance(HumanGovernanceResponse::Snapshot {
                    frontier, ..
                }) = client
                    .request(
                        evertrace_domain::ids::RequestId::new_v7(),
                        Rpc::HumanGovernance(HumanGovernanceRequest::Read {
                            request: HumanReadRequest::List {
                                surface: HumanSurface::System,
                                expected_frontier: None,
                                after: None,
                                limit: 16,
                            },
                        }),
                    )
                    .await
                    .unwrap()
                else {
                    panic!("system snapshot");
                };
                let response = client
                    .request(
                        evertrace_domain::ids::RequestId::new_v7(),
                        Rpc::HumanGovernance(HumanGovernanceRequest::Act {
                            expected_frontier: frontier,
                            action: HumanActionRequest::CreateBackup,
                        }),
                    )
                    .await
                    .unwrap();
                if matches!(response, Response::HumanGovernance(HumanGovernanceResponse::Action { result }) if result.status == HumanActionStatus::Applied)
                {
                    requested = true;
                    break;
                }
            }
            assert!(requested);
            drop(client);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let complete = fs::read_dir(paths.data_root.join("backups"))
                    .ok()
                    .is_some_and(|entries| {
                        entries.filter_map(Result::ok).any(|entry| {
                            entry.file_name().to_string_lossy().starts_with("backup-")
                                && entry.path().join("manifest.json").is_file()
                        })
                    });
                if complete
                    && package_health(paths.data_root.join("runtime/evertraced-v1.sock")).await
                {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline
                        && daemon.0.try_wait().unwrap().is_none()
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        if replay {
            invoke(&paths, &serde_json::to_vec(&native).unwrap());
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let connection = evertrace_store::connection::CompatibilityStore::connect_local(
                    &evertrace_store::connection::native_root(&paths.data_root),
                )
                .await
                .unwrap();
                let journal = connection
                    .connection()
                    .open_table(evertrace_store::JOURNAL_TABLE)
                    .execute()
                    .await
                    .unwrap();
                let rows = evertrace_store::journal::read_all_journal_rows(&journal)
                    .await
                    .unwrap();
                let current_hash = EffectiveConfig::new(settings.clone()).unwrap().hash();
                if rows.iter().any(|row| matches!(row.payload().unwrap(), JournalPayload::SourceReceiptRecorded(receipt)
                    if matches!(receipt.protected_presentation, Some(evertrace_domain::evidence::ProtectedPresentation::Inline { .. }))
                        && row.effective_config_hash == current_hash)) {
                    break;
                }
                assert!(tokio::time::Instant::now() < deadline);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        assert!(
            Command::new("/usr/bin/kill")
                .args(["-TERM", &daemon.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = daemon.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    invoke(&paths, &serde_json::to_vec(&native).unwrap());
    let spool =
        DurableSpool::open_read_only(runtime.spool_dir.clone(), runtime.spool_limits().unwrap())
            .unwrap();
    let frame = spool.read_active().unwrap().remove(0);
    let cas = evertrace_capture::CasStore::open_existing(runtime.cas_dir.clone()).unwrap();
    let blob = cas
        .blob_path(&evertrace_capture::CasStore::parse_digest(&frame.record.cas_refs[0]).unwrap());
    let valid_cas = fs::read(&blob).unwrap();
    fs::write(&blob, b"corrupt").unwrap();
    drop(spool);
    let mut daemon = spawn();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = daemon.0.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let spool =
        DurableSpool::open_read_only(runtime.spool_dir.clone(), runtime.spool_limits().unwrap())
            .unwrap();
    let segments = spool.sealed_segments(1).unwrap();
    assert_eq!(
        segments[0].frames()[0].record.spool_record_id,
        frame.record.spool_record_id
    );
    drop(segments);
    fs::write(&blob, valid_cas).unwrap();
    let broken = evertrace_capture::encode_frame(&original).unwrap()[..30].to_vec();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(spool.active_path())
        .unwrap();
    file.write_all(&broken).unwrap();
    file.sync_all().unwrap();
    drop(file);
    for _ in 0..2 {
        let mut daemon = spawn();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = daemon.0.try_wait().unwrap() {
                assert!(!status.success());
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(fs::read(spool.active_path()).unwrap(), broken);
    }
}

#[tokio::test]
async fn submitted_inputs_are_weak_independent_and_visible_after_automatic_ingest() {
    use evertrace_domain::{
        evidence::{ContentTrust, ObservationRole, SourceRole},
        ids::RequestId,
    };
    use evertrace_protocol::{
        LocalClient,
        command::Command as Rpc,
        dto::{
            ClientKind, HumanGovernanceRequest, HumanGovernanceResponse, HumanReadRequest,
            HumanSurface,
        },
        response::Response,
    };
    use std::time::{Duration, Instant};
    let (_root, paths, config) = fixture();
    let mut settings = config.config().clone();
    settings.llm.enabled = false;
    settings.capture.inline_payload_bytes = 131_072;
    fs::write(
        &paths.config,
        EffectiveConfig::new(settings).unwrap().to_toml().unwrap(),
    )
    .unwrap();
    install_offline(&paths, false).unwrap();
    let mut raw = serde_json::json!({"cwd":paths.data_root,"hook_event_name":"UserPromptSubmit",
        "model":"test","permission_mode":"default","session_id":"submission-session","turn_id":"same-turn",
        "transcript_path":null,"prompt":"submitted only api_key=secret-canary-value"});
    // Synthetic deliveries cover same-turn multiplicity and child declarations;
    // they do not manufacture a source-local namespace or accepted Task intent.
    let mut malformed = raw.clone();
    malformed["source_local_evidence"] = serde_json::json!({"namespace":"invented"});
    assert!(
        evertrace_codex::binding::NativeInputSubmission::from_json(
            &serde_json::to_vec(&malformed).unwrap()
        )
        .is_err()
    );
    malformed = raw.clone();
    malformed["prompt"] = 7.into();
    assert!(
        evertrace_codex::binding::NativeInputSubmission::from_json(
            &serde_json::to_vec(&malformed).unwrap()
        )
        .is_err()
    );
    invoke(&paths, &serde_json::to_vec(&raw).unwrap());
    invoke(&paths, &serde_json::to_vec(&raw).unwrap());
    raw["agent_id"] = "child-declaration".into();
    raw["agent_type"] = "worker".into();
    raw["prompt"] = "different submitted input in the same turn "
        .repeat(1800)
        .into();
    invoke(&paths, &serde_json::to_vec(&raw).unwrap());
    let runtime = RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&paths.data_root)).unwrap();
    let spool =
        DurableSpool::open_read_only(&runtime.spool_dir, runtime.spool_limits().unwrap()).unwrap();
    let frames = spool.read_active().unwrap();
    assert_eq!(frames.len(), 3);
    let original = frames[0].record.clone();
    for frame in frames {
        let body = evertrace_capture::decode_record_body(&frame.record.record_body).unwrap();
        assert_eq!(body.observation_role, ObservationRole::Message);
        assert_eq!(body.source_role, SourceRole::Host);
        assert_eq!(body.content_trust, ContentTrust::Observed);
        assert_eq!(body.capture_completeness, CaptureCompleteness::Partial);
        assert!(
            body.source_local_evidence.is_none() && body.correlation.native_request_id.is_none()
        );
        assert!(body.task_id.is_none() && body.lifecycle.is_none());
    }
    drop(spool);
    struct Daemon(std::process::Child);
    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for replay in [false, true] {
        if replay {
            let mut spool =
                DurableSpool::open_read_only(&runtime.spool_dir, runtime.spool_limits().unwrap())
                    .unwrap();
            spool.append(&original).unwrap();
        }
        let mut daemon = Daemon(
            Command::new(&paths.daemon)
                .arg("--config")
                .arg(&paths.config)
                .env_clear()
                .env("HOME", paths.data_root.parent().unwrap())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let socket = paths.data_root.join("runtime/evertraced-v1.sock");
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if package_health(socket.clone()).await {
                let connection = evertrace_store::connection::CompatibilityStore::connect_local(
                    &evertrace_store::connection::native_root(&paths.data_root),
                )
                .await
                .unwrap();
                let journal = connection
                    .connection()
                    .open_table(evertrace_store::JOURNAL_TABLE)
                    .execute()
                    .await
                    .unwrap();
                let rows = evertrace_store::journal::read_all_journal_rows(&journal)
                    .await
                    .unwrap();
                let payloads = rows
                    .iter()
                    .map(|row| row.payload().unwrap())
                    .collect::<Vec<_>>();
                let receipts = payloads
                    .iter()
                    .filter_map(|payload| match payload {
                        JournalPayload::SourceReceiptRecorded(value) => Some(value),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert!(receipts.len() <= 3);
                let spool = DurableSpool::open_read_only(
                    &runtime.spool_dir,
                    runtime.spool_limits().unwrap(),
                )
                .unwrap();
                if receipts.len() == 3
                    && spool.read_durable_records(16, 2 << 20).unwrap().is_empty()
                {
                    assert_eq!(
                        receipts
                            .iter()
                            .map(|receipt| receipt.source_instance_id.clone())
                            .collect::<std::collections::BTreeSet<_>>()
                            .len(),
                        3
                    );
                    assert!(!payloads.iter().any(|payload| matches!(
                        payload,
                        JournalPayload::OperationDerived(_)
                            | JournalPayload::TaskRecorded(_)
                            | JournalPayload::ExecutionLaneRecorded(_)
                            | JournalPayload::CaptureReceiptRecorded(_)
                    )));
                    assert!(
                        !serde_json::to_string(&receipts)
                            .unwrap()
                            .contains("secret-canary-value")
                    );
                    let largest = receipts
                        .iter()
                        .max_by_key(|receipt| receipt.protected_length)
                        .unwrap();
                    assert!(
                        matches!(&largest.protected_presentation, Some(evertrace_domain::evidence::ProtectedPresentation::Inline { text }) if text.len() > 65_536)
                    );
                    let object = format!(
                        "object:evidence:source_receipt:{}",
                        largest.source_receipt_id
                    );
                    let mut client = LocalClient::connect(
                        &socket,
                        "s34-submission",
                        ClientKind::Cli,
                        Duration::from_secs(3),
                    )
                    .await
                    .unwrap();
                    let mut observed = false;
                    while Instant::now() < deadline {
                        let Response::HumanGovernance(HumanGovernanceResponse::Snapshot {
                            frontier,
                            items,
                            ..
                        }) = client
                            .request(
                                RequestId::new_v7(),
                                Rpc::HumanGovernance(HumanGovernanceRequest::Read {
                                    request: HumanReadRequest::List {
                                        surface: HumanSurface::Explorer,
                                        expected_frontier: None,
                                        after: None,
                                        limit: 16,
                                    },
                                }),
                            )
                            .await
                            .unwrap()
                        else {
                            panic!("explorer list");
                        };
                        assert!(items.iter().all(|item| item.evidence_detail.is_none()));
                        let response = client
                            .request(
                                RequestId::new_v7(),
                                Rpc::HumanGovernance(HumanGovernanceRequest::Read {
                                    request: HumanReadRequest::Detail {
                                        surface: HumanSurface::Explorer,
                                        object_ref: object.clone(),
                                        expected_frontier: frontier,
                                        expected_revision_ref: None,
                                    },
                                }),
                            )
                            .await
                            .unwrap();
                        match response {
                            Response::HumanGovernance(HumanGovernanceResponse::Conflict {
                                ..
                            }) => continue,
                            Response::HumanGovernance(HumanGovernanceResponse::Snapshot {
                                items,
                                ..
                            }) => {
                                assert_eq!(items.len(), 1);
                                let detail = items[0].evidence_detail.as_ref().unwrap();
                                assert_eq!(detail.observation_role, ObservationRole::Message);
                                assert_eq!(detail.content_trust, ContentTrust::Observed);
                                assert_eq!(
                                    detail.capture_completeness,
                                    CaptureCompleteness::Partial
                                );
                                assert!(
                                    matches!(&detail.protected_presentation, Some(evertrace_domain::evidence::ProtectedPresentation::Preview { text }) if text.len() <= 65_536)
                                );
                                assert_eq!(detail.protected_length, largest.protected_length);
                                let encoded = serde_json::to_string(&items).unwrap();
                                assert!(!encoded.contains("secret-canary-value"));
                                observed = true;
                                break;
                            }
                            other => panic!("unexpected detail: {other:?}"),
                        }
                    }
                    assert!(observed);
                    break;
                }
            }
            assert!(Instant::now() < deadline && daemon.0.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

#[tokio::test]
async fn package_check_prepares_native_and_materials_without_publication() {
    use evertrace_engine::maintenance::{check_package_upgrade, upgrade_offline};
    use std::os::unix::fs::MetadataExt;
    let (root, mut paths, _) = fixture();
    let original_data = paths.data_root.clone();
    paths.data_root = root
        .path()
        .join("a-long-data-directory-for-real-package-socket-validation");
    fs::write(
        &paths.config,
        fs::read_to_string(&paths.config).unwrap().replace(
            original_data.to_str().unwrap(),
            paths.data_root.to_str().unwrap(),
        ),
    )
    .unwrap();
    paths.unit = root.path().join("config/systemd/user/evertraced.service");
    install_offline(&paths, false).unwrap();
    let host_with_token = format!(
        "{}\n[model_providers.private_test]\napi_key = \"fictional-package-token-never-copy\"\n",
        fs::read_to_string(&paths.host_config).unwrap()
    ).replace("# END EverTrace managed wiring v1", "[hooks.state.review]\ntrusted_hash = 'keep-host-state'\n[projects.\"/private/work\"]\ntrust_level = 'trusted'\n[mcp_servers.evertrace.tools.evertrace]\napproval_mode = 'approve'\n# END EverTrace managed wiring v1");
    fs::write(&paths.host_config, &host_with_token).unwrap();
    let connection =
        evertrace_store::connection::CompatibilityStore::connect_local(&paths.data_root)
            .await
            .unwrap();
    evertrace_store::L0001::apply(connection.connection())
        .await
        .unwrap();
    drop(connection);
    let native = serde_json::json!({"cwd": paths.data_root, "hook_event_name":"PreToolUse", "model":"test", "permission_mode":"default", "session_id":"package-pin", "tool_input":{"command":"true"}, "tool_name":"Bash", "tool_use_id":"one", "transcript_path":null, "turn_id":"one"});
    invoke(&paths, &serde_json::to_vec(&native).unwrap());
    let owned = [
        paths.config.clone(),
        paths.host_config.clone(),
        paths.unit.clone(),
        paths.data_root.join("hook-v1"),
        paths.data_root.join("hooks/registry-v1.json"),
        paths.data_root.join("hooks/pins/package-pin.pin"),
        paths.data_root.join("hooks/generations/1/evertrace-hook"),
        paths
            .data_root
            .join("hooks/generations/1/hook-runtime-v1.json"),
        RuntimeSnapshot::snapshot_path(&paths.data_root),
    ];
    let before = owned
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect::<Vec<_>>();
    let package = root.path().join("next-package");
    let refused = std::process::Command::new(&paths.cli)
        .env_clear()
        .env("HOME", root.path())
        .env("CODEX_HOME", paths.host_config.parent().unwrap())
        .args([
            "--config",
            paths.config.to_str().unwrap(),
            "upgrade",
            package.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("requires --live-host"));
    assert!(!paths.data_root.join("backups").exists());
    for invalid in [&package, paths.cli.parent().unwrap()] {
        assert!(
            check_package_upgrade(
                &paths.data_root,
                &paths.config,
                &paths.host_config,
                &paths.unit,
                invalid,
                package_health,
                (None, |_, _| async { None }),
            )
            .await
            .is_err()
        );
        assert!(!paths.data_root.join("backups").exists());
        assert!(!fs::read_dir(&paths.data_root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".upgrade-")
        }));
    }
    fs::create_dir(&package).unwrap();
    fs::set_permissions(&package, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["evertrace", "evertrace-hook", "evertraced"] {
        fs::copy(paths.cli.parent().unwrap().join(name), package.join(name)).unwrap();
        fs::set_permissions(package.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let materials_root = TempDir::new().unwrap();
    let preflight = evertrace_codex::install::preflight_package_check(
        &paths.data_root,
        &paths.config,
        &paths.host_config,
        &paths.unit,
        &package,
    )
    .unwrap();
    let runtime = RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&paths.data_root)).unwrap();
    let materials =
        evertrace_codex::install::prepare_package_check(preflight, materials_root.path(), |path| {
            runtime
                .publish(path)
                .map_err(|_| evertrace_codex::install::InstallError::Io)
        })
        .unwrap();
    let staged = fs::read_to_string(&materials.host_configuration).unwrap();
    assert!(staged.starts_with("# BEGIN EverTrace managed wiring v1\n"));
    assert!(staged.ends_with("# END EverTrace managed wiring v1\n"));
    assert!(!staged.contains("fictional-package-token-never-copy"));
    assert!(!staged.contains("model_providers"));
    assert!(
        !staged.contains("trusted_hash")
            && !staged.contains("approval_mode")
            && !staged.contains("projects")
    );
    assert!(staged.contains("mcp_servers.evertrace") && staged.contains("PreToolUse"));
    materials.validate().unwrap();
    fs::write(
        &materials.host_configuration,
        format!("{staged}# changed\n"),
    )
    .unwrap();
    assert!(materials.validate().is_err());
    drop(materials);
    drop(materials_root);
    let materials_root = TempDir::new().unwrap();
    let preflight = evertrace_codex::install::preflight_package_check(
        &paths.data_root,
        &paths.config,
        &paths.host_config,
        &paths.unit,
        &package,
    )
    .unwrap();
    let materials =
        evertrace_codex::install::prepare_package_check(preflight, materials_root.path(), |path| {
            runtime
                .publish(path)
                .map_err(|_| evertrace_codex::install::InstallError::Io)
        })
        .unwrap();
    materials.validate().unwrap();
    fs::write(
        &paths.host_config,
        format!("{host_with_token}\n# concurrent Host state write\n"),
    )
    .unwrap();
    assert!(materials.validate().is_err()); // Full-file optimistic check, not wiring hash.
    assert!(
        fs::read_to_string(&paths.host_config)
            .unwrap()
            .ends_with("# concurrent Host state write\n")
    );
    fs::write(&paths.host_config, &host_with_token).unwrap();
    assert_eq!(
        fs::read_to_string(&paths.host_config).unwrap(),
        host_with_token
    );
    drop(materials);
    drop(materials_root);
    let probe_roots = std::sync::Mutex::new(Vec::new());
    let health = |socket: std::path::PathBuf| {
        assert!(socket.as_os_str().len() < 108);
        let wrapper = socket
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_owned();
        assert!(wrapper.starts_with("/tmp"));
        assert!(!wrapper.starts_with(&paths.data_root));
        probe_roots.lock().unwrap().push(wrapper);
        package_health(socket)
    };
    let checked = check_package_upgrade(
        &paths.data_root,
        &paths.config,
        &paths.host_config,
        &paths.unit,
        &package,
        &health,
        (None, |_, _| async { None }),
    )
    .await
    .unwrap();
    assert!(
        checked.materials_validated && checked.migrated,
        "native={} daemon={}",
        checked.candidate_native_verified,
        checked.candidate_daemon_verified
    );
    assert!(checked.candidate_native_verified && checked.candidate_daemon_verified);
    assert!(!probe_roots.lock().unwrap().is_empty());
    assert!(
        probe_roots
            .lock()
            .unwrap()
            .iter()
            .all(|path| !path.exists())
    );
    assert_eq!(checked.generation, Some(2));
    assert!(!paths.data_root.join("store").exists());
    assert!(matches!(
        JournalWriter::open(&paths.data_root).await,
        Err(evertrace_store::StoreError::UpgradeRequired)
    ));
    let id = checked
        .backup
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("backup-")
        .unwrap()
        .parse()
        .unwrap();
    let verified = evertrace_store::backup::verify_backup(&paths.data_root, id)
        .await
        .unwrap();
    assert!(verified.table_states.relations.is_none());
    assert!(!fs::read_dir(&paths.data_root).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".upgrade-")
    }));
    upgrade_offline(&paths.data_root, &paths.config)
        .await
        .unwrap();
    let canonical = paths.data_root.join("store");
    let metadata = fs::metadata(&canonical).unwrap();
    let backups_before = fs::read_dir(paths.data_root.join("backups"))
        .unwrap()
        .count();
    let output = Command::new(&paths.cli)
        .arg("--config")
        .arg(&paths.config)
        .args(["upgrade", "--check"])
        .arg(&package)
        .arg("--live-host")
        .arg(root.path().join("missing-host"))
        .env("CODEX_HOME", paths.host_config.parent().unwrap())
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let output = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.contains("scope=package_prepublication check=not-ready"),
        "{output}"
    );
    assert!(output.contains("materials_validated=true"), "{output}");
    assert!(
        output.contains("candidate_host=Some")
            && output.contains("Candidate")
            && output.contains("Unavailable"),
        "{output}"
    );
    assert!(
        output.contains(
            "candidate_native_verified=true candidate_daemon_verified=true host_verified=false"
        ),
        "{output}"
    );
    assert!(output.contains("migrated=false"));
    assert_eq!(
        fs::read_dir(paths.data_root.join("backups"))
            .unwrap()
            .count(),
        backups_before + 1
    );
    // Exit zero from a fake Hook must fail the real CAS/spool probe, then clean.
    fs::write(package.join("evertrace-hook"), b"#!/bin/sh\nexit 0\n").unwrap();
    let rejected = check_package_upgrade(
        &paths.data_root,
        &paths.config,
        &paths.host_config,
        &paths.unit,
        &package,
        package_health,
        (None, |_, _| async { None }),
    )
    .await
    .unwrap();
    assert!(!rejected.materials_validated);
    assert!(rejected.backup.is_dir());
    fs::copy(&paths.hook, package.join("evertrace-hook")).unwrap();
    // Native verification still uses the real candidate implementation; only
    // its ordinary daemon startup fails. This cannot certify daemon readiness.
    fs::write(package.join("evertraced"), format!("#!/bin/sh\nif [ \"$1\" = --verify-package-native ]; then exec '{}' \"$@\"; fi\nexit 1\n", paths.daemon.display())).unwrap();
    let failed_daemon = check_package_upgrade(
        &paths.data_root,
        &paths.config,
        &paths.host_config,
        &paths.unit,
        &package,
        &health,
        (None, |_, _| async { None }),
    )
    .await
    .unwrap();
    assert!(failed_daemon.candidate_native_verified);
    assert!(
        probe_roots
            .lock()
            .unwrap()
            .iter()
            .all(|path| !path.exists())
    );
    assert!(!failed_daemon.candidate_daemon_verified && !failed_daemon.materials_validated);
    assert!(!fs::read_dir(&paths.data_root).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".upgrade-")
    }));
    let after = fs::metadata(&canonical).unwrap();
    assert_eq!((metadata.dev(), metadata.ino()), (after.dev(), after.ino()));
    for (path, expected) in owned.iter().zip(before) {
        assert_eq!(fs::read(path).unwrap(), expected, "{}", path.display());
    }
}

#[tokio::test]
async fn package_prepare_failure_restores_service_only_with_verified_old_side() {
    let (root, paths, _) = fixture();
    install_offline(&paths, false).unwrap();
    drop(JournalWriter::open(&paths.data_root).await.unwrap());
    evertrace_capture::CasStore::open(paths.data_root.join("cas")).unwrap();
    let package = root.path().join("next");
    fs::create_dir(&package).unwrap();
    fs::set_permissions(&package, fs::Permissions::from_mode(0o700)).unwrap();
    // Only preflight is reached: these small scripts are not candidate proof.
    for name in ["evertrace", "evertrace-hook", "evertraced"] {
        let path = package.join(name);
        fs::write(&path, "#!/bin/sh\necho 'configuration is valid'\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let log = root.path().join("service.log");
    let stopped = root.path().join("stopped");
    let control = root.path().join("control");
    fs::write(&paths.systemctl, format!(
        "#!/bin/sh\necho \"$*\" >> '{log}'\nshift\ncase \"$1\" in\nshow) echo '{unit}';;\nis-enabled) echo enabled;;\nis-active) if [ -f '{stopped}' ]; then if [ \"$(cat '{control}')\" = 3 ]; then echo broken; else echo inactive; fi; else echo active; fi;;\ndisable) touch '{stopped}';;\nstart) [ \"$(cat '{control}')\" != 2 ];;\n*) exit 0;;\nesac\n",
        log=log.display(),unit=paths.unit.display(),stopped=stopped.display(),control=control.display()
    )).unwrap();
    fs::set_permissions(&paths.systemctl, fs::Permissions::from_mode(0o700)).unwrap();
    // A regular file makes backup preparation fail before candidate creation.
    fs::write(paths.data_root.join("backups"), b"owned test obstruction").unwrap();
    for case in 0..4 {
        fs::write(&control, case.to_string()).unwrap();
        fs::write(&log, b"").unwrap();
        if stopped.exists() {
            fs::remove_file(&stopped).unwrap();
        }
        let unknown = paths.data_root.join(".upgrade-unknown");
        if case == 1 {
            fs::create_dir(&unknown).unwrap();
        }
        let error = match evertrace_engine::maintenance::package_upgrade(
            &paths.data_root,
            &paths.config,
            &paths.host_config,
            &paths.unit,
            (&package, Some(&paths.systemctl)),
            |_| async { panic!("no candidate daemon before preparation succeeds") },
            (
                Some(evertrace_engine::HostCanaryRequest {
                    host_executable: paths.host_executable.to_string_lossy().into_owned(),
                    host_config: paths.host_config.to_string_lossy().into_owned(),
                }),
                |_, _| async { panic!("no Host before preparation succeeds") },
            ),
        )
        .await
        {
            Err(error) => error.to_string(),
            Ok(_) => panic!("preparation must fail"),
        };
        assert!(stopped.exists());
        let calls = fs::read_to_string(&log).unwrap();
        if case == 1 {
            assert!(error.contains("withheld_unverified_native"), "{error}");
            assert!(!calls.contains("--user start"));
            fs::remove_dir(unknown).unwrap();
        } else {
            assert!(calls.contains("--user start"), "{calls}: {error}");
            assert!(
                error.contains(if case == 2 {
                    "recovery=failed"
                } else {
                    "recovery=restored"
                }),
                "{error}"
            );
        }
        if case == 3 {
            assert!(error.contains("service may have stopped"));
        }
    }
}

fn invoke(paths: &ManagedInstallPaths, bytes: &[u8]) {
    let mut child = Command::new(paths.data_root.join("hook-v1"))
        .arg("--launcher-root")
        .arg(&paths.data_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

#[tokio::test]
async fn submitted_sources_bootstrap_work_through_managed_mcp() {
    use evertrace_domain::ids::{RequestId, TaskId, WorkstreamId};
    use evertrace_protocol::{
        LocalClient,
        command::Command as Rpc,
        dto::{
            ClientKind, HumanGovernanceRequest, HumanGovernanceResponse, HumanReadRequest,
            HumanSurface,
        },
        response::Response,
    };
    use serde_json::{Value, json};
    use std::time::{Duration, Instant};
    // Synthetic Host inputs, but actual managed launcher, binding consume,
    // CLI stdout, ordinary daemon ingest, Store and Explorer consumers.
    fn call(
        paths: &ManagedInstallPaths,
        session: &str,
        action: &str,
        input: &str,
        refs: &[String],
    ) -> Value {
        let arguments = json!({"action":action,"workspace":"@active","input":input,"refs":refs});
        let raw = json!({"cwd":paths.data_root,"hook_event_name":"PreToolUse","model":"test",
            "permission_mode":"default","session_id":session,"turn_id":"work-turn",
            "tool_use_id":RequestId::new_v7().to_string(),"transcript_path":null,
            "tool_name":evertrace_codex::binding::CODEX_EVERTRACE_TOOL_NAME,"tool_input":arguments});
        let mut hook = Command::new(paths.data_root.join("hook-v1"))
            .arg("--launcher-root")
            .arg(&paths.data_root)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        hook.stdin
            .take()
            .unwrap()
            .write_all(raw.to_string().as_bytes())
            .unwrap();
        let output = hook.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stamped: Value = serde_json::from_slice(&output.stdout).unwrap();
        let arguments = &stamped["hookSpecificOutput"]["updatedInput"];
        assert!(
            arguments["workspace"]
                .as_str()
                .unwrap()
                .starts_with("@bound:")
        );
        let mut cli = Command::new(&paths.cli)
            .arg("--config")
            .arg(&paths.config)
            .arg("mcp")
            .current_dir(paths.data_root.parent().unwrap())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = cli.stdin.take().unwrap();
        for request in [
            json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"work-test","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"evertrace","arguments":arguments}}),
        ] {
            writeln!(stdin, "{request}").unwrap();
        }
        drop(stdin);
        let output = cli.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let messages: Vec<Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        messages[1]["result"]["structuredContent"].clone()
    }
    let (_root, paths, config) = fixture();
    let mut settings = config.config().clone();
    settings.llm.enabled = false;
    fs::write(
        &paths.config,
        EffectiveConfig::new(settings).unwrap().to_toml().unwrap(),
    )
    .unwrap();
    install_offline(&paths, false).unwrap();
    let raw = json!({"cwd":paths.data_root,"hook_event_name":"UserPromptSubmit","model":"test",
        "permission_mode":"default","session_id":"work-session","turn_id":"work-turn",
        "transcript_path":null,"prompt":"organize the submitted workneedle api_key=work-secret-canary"});
    invoke(&paths, &serde_json::to_vec(&raw).unwrap());
    struct Daemon(std::process::Child);
    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let daemon = Daemon(
        Command::new(&paths.daemon)
            .arg("--config")
            .arg(&paths.config)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let socket = paths.data_root.join("runtime/evertraced-v1.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !package_health(socket.clone()).await {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let reference = loop {
        let result = call(&paths, "work-session", "search", "workneedle", &[]);
        if let Some(reference) = result["items"]["evidence"][0]["object_ref"].as_str() {
            break reference.to_owned();
        }
        assert!(Instant::now() < deadline, "{result}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert!(
        call(&paths, "other-session", "search", "workneedle", &[])["items"]["evidence"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let task = TaskId::new_v7();
    let stream = WorkstreamId::new_v7();
    let declaration = json!({"kind":"work_annotation","choice":"root","task_id":task,
        "goal":"inspect api_key=plan-secret-canary","workstream":{"workstream_id":stream,
        "goal":"inspect the source","target_family":"source","hypothesis_or_failure_family":"unknown defect",
        "acceptance_boundary":"source inspection recorded","phase_contract":{"local_goal":"inspect source",
        "phase_kind":"inspect","phase_label":"inspection","primary_targets":["source"],
        "entry_conditions":["source available"],"acceptance_boundary":"inspection recorded","expected_state_transition":"uninspected to inspected"}}});
    let mut result = call(
        &paths,
        "work-session",
        "add",
        &declaration.to_string(),
        std::slice::from_ref(&reference),
    );
    if result["status"] == "conflict" {
        result = call(
            &paths,
            "work-session",
            "add",
            &declaration.to_string(),
            std::slice::from_ref(&reference),
        );
    }
    assert_eq!(result["status"], "partial", "{result}");
    assert_eq!(
        result["items"]["evidence"].as_array().unwrap().len(),
        2,
        "{result}"
    );
    assert!(!result.to_string().contains("plan-secret-canary"));
    let revision = result["items"]["evidence"][0]["object_revision_ref"].clone();
    let duplicate = call(
        &paths,
        "work-session",
        "add",
        &declaration.to_string(),
        std::slice::from_ref(&reference),
    );
    assert_eq!(
        duplicate["items"]["evidence"][0]["object_revision_ref"], revision,
        "{duplicate}"
    );
    let read = call(&paths, "other-session", "get", &task.to_string(), &[]);
    assert_eq!(read["items"]["evidence"][0]["authority"], "none", "{read}");
    assert!(read.to_string().contains("provisional"));
    assert_eq!(
        call(
            &paths,
            "other-session",
            "add",
            &declaration.to_string(),
            std::slice::from_ref(&reference)
        )["status"],
        "invalid_input"
    );
    let child = WorkstreamId::new_v7();
    let mut partial = declaration.clone();
    partial["choice"] = "fork".into();
    partial["workstream"] =
        json!({"workstream_id":child,"parent_workstream_id":stream,"goal":"a partial child plan"});
    let pending = call(
        &paths,
        "work-session",
        "add",
        &partial.to_string(),
        std::slice::from_ref(&reference),
    );
    assert_eq!(
        pending["items"]["evidence"][0]["object_revision_ref"], revision,
        "{pending}"
    );
    assert!(
        pending.to_string().contains("annotation_only")
            && pending.to_string().contains("missing_phase_contract")
    );
    partial["expected_task_revision"] = revision.clone();
    partial["workstream"] = declaration["workstream"].clone();
    partial["workstream"]["workstream_id"] = json!(child);
    partial["workstream"]["parent_workstream_id"] = json!(stream);
    let fork = call(
        &paths,
        "work-session",
        "add",
        &partial.to_string(),
        std::slice::from_ref(&reference),
    );
    assert_eq!(
        fork["items"]["evidence"][1]["object_ref"],
        child.to_string(),
        "{fork}"
    );
    let mut changed = declaration.clone();
    changed["workstream"] = Value::Null;
    changed["goal"] = "refined protected goal".into();
    let conflict = call(
        &paths,
        "work-session",
        "add",
        &changed.to_string(),
        std::slice::from_ref(&reference),
    );
    assert_eq!(conflict["status"], "conflict", "{conflict}");
    assert_eq!(
        conflict["items"]["evidence"][0]["object_revision_ref"],
        revision
    );
    changed["expected_task_revision"] = revision.clone();
    let revised = call(
        &paths,
        "work-session",
        "add",
        &changed.to_string(),
        std::slice::from_ref(&reference),
    );
    assert_eq!(revised["status"], "partial", "{revised}");
    assert_ne!(
        revised["items"]["evidence"][0]["object_revision_ref"],
        revision
    );
    let mut another = raw.clone();
    another["session_id"] = "other-session".into();
    another["prompt"] = "continue worknext".into();
    invoke(&paths, &serde_json::to_vec(&another).unwrap());
    let next_reference = loop {
        let result = call(&paths, "other-session", "search", "worknext", &[]);
        if let Some(reference) = result["items"]["evidence"][0]["object_ref"].as_str() {
            break reference.to_owned();
        }
        assert!(Instant::now() < deadline, "{result}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    changed["choice"] = "continue".into();
    let continued = call(
        &paths,
        "other-session",
        "add",
        &changed.to_string(),
        &[next_reference],
    );
    assert_eq!(
        continued["items"]["evidence"][0]["object_revision_ref"],
        revised["items"]["evidence"][0]["object_revision_ref"],
        "{continued}"
    );
    for action in ["add", "organize"] {
        assert_eq!(
            call(&paths, "work-session", action, "ordinary input", &[])["status"],
            "scope_unresolved"
        );
    }
    assert_eq!(
        call(&paths, "work-session", "search", "@due", &[])["status"],
        "scope_unresolved"
    );
    let second_task = TaskId::new_v7();
    let separate = json!({"kind":"work_annotation","choice":"root","task_id":second_task,"goal":"a separate plan"});
    let separate_result = call(
        &paths,
        "work-session",
        "add",
        &separate.to_string(),
        std::slice::from_ref(&reference),
    );
    assert_eq!(
        separate_result["items"]["evidence"][0]["object_ref"],
        second_task.to_string(),
        "{separate_result}"
    );
    let mut foreign_stream = separate.clone();
    foreign_stream["workstream"] = declaration["workstream"].clone();
    let rejected = call(
        &paths,
        "work-session",
        "add",
        &foreign_stream.to_string(),
        std::slice::from_ref(&reference),
    );
    assert_eq!(rejected["status"], "conflict");
    assert_eq!(rejected["items"]["evidence"].as_array().unwrap().len(), 1);
    foreign_stream["expected_task_revision"] =
        separate_result["items"]["evidence"][0]["object_revision_ref"].clone();
    assert_eq!(
        call(
            &paths,
            "work-session",
            "add",
            &foreign_stream.to_string(),
            std::slice::from_ref(&reference)
        )["status"],
        "invalid_input"
    );
    changed["choice"] = "switch".into();
    let switched = call(
        &paths,
        "work-session",
        "add",
        &changed.to_string(),
        std::slice::from_ref(&reference),
    );
    assert_eq!(
        switched["items"]["evidence"][0]["object_revision_ref"],
        revised["items"]["evidence"][0]["object_revision_ref"]
    );
    assert_eq!(
        call(
            &paths,
            "work-session",
            "add",
            &separate.to_string(),
            &["src:missing".into()]
        )["status"],
        "invalid_input"
    );
    let mut client = LocalClient::connect(
        &socket,
        "work-test",
        ClientKind::Cli,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    loop {
        let Response::HumanGovernance(HumanGovernanceResponse::Snapshot { frontier, .. }) = client
            .request(
                RequestId::new_v7(),
                Rpc::HumanGovernance(HumanGovernanceRequest::Read {
                    request: HumanReadRequest::List {
                        surface: HumanSurface::Explorer,
                        expected_frontier: None,
                        after: None,
                        limit: 16,
                    },
                }),
            )
            .await
            .unwrap()
        else {
            panic!("list");
        };
        match client
            .request(
                RequestId::new_v7(),
                Rpc::HumanGovernance(HumanGovernanceRequest::Read {
                    request: HumanReadRequest::Detail {
                        surface: HumanSurface::Explorer,
                        object_ref: format!("object:work:task:{task}"),
                        expected_frontier: frontier,
                        expected_revision_ref: None,
                    },
                }),
            )
            .await
            .unwrap()
        {
            Response::HumanGovernance(HumanGovernanceResponse::Snapshot { items, .. }) => {
                assert_eq!(items.len(), 1);
                let detail = items[0].work_detail.as_ref().unwrap();
                assert_eq!(
                    detail.identity_confidence,
                    evertrace_domain::work::TaskIdentityConfidence::Provisional
                );
                assert!(!detail.canonical_goal.contains("plan-secret-canary"));
                break;
            }
            Response::HumanGovernance(HumanGovernanceResponse::Conflict { .. }) => {
                assert!(Instant::now() < deadline)
            }
            other => panic!("{other:?}"),
        }
    }
    drop(client);
    drop(daemon);
    let connection = evertrace_store::connection::CompatibilityStore::connect_local(
        &evertrace_store::connection::native_root(&paths.data_root),
    )
    .await
    .unwrap();
    let journal = connection
        .connection()
        .open_table(evertrace_store::JOURNAL_TABLE)
        .execute()
        .await
        .unwrap();
    let rows = evertrace_store::journal::read_all_journal_rows(&journal)
        .await
        .unwrap();
    let payloads = rows
        .iter()
        .map(|row| row.payload().unwrap())
        .collect::<Vec<_>>();
    let tasks = payloads
        .iter()
        .filter_map(|payload| {
            if let JournalPayload::TaskRecorded(task) = payload {
                Some(task)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(tasks.len(), 3);
    assert_eq!(tasks[0].request_root_refs, tasks[1].request_root_refs);
    assert_eq!(
        payloads
            .iter()
            .filter(|payload| matches!(payload, JournalPayload::WorkstreamRecorded(_)))
            .count(),
        2
    );
    assert!(!payloads.iter().any(|payload| matches!(
        payload,
        JournalPayload::ExecutionLaneRecorded(_)
            | JournalPayload::WorkBindingRecorded(_)
            | JournalPayload::OperationDerived(_)
            | JournalPayload::AtomRecorded(_)
    )));
    // A synthetic, legally committed terminal transition is only the
    // precondition here; the new continuation still uses the real MCP path.
    let previous = tasks
        .iter()
        .rev()
        .find(|value| value.task_id == task)
        .unwrap()
        .as_ref()
        .clone();
    drop(journal);
    drop(connection);
    let mut writer = JournalWriter::open(&paths.data_root).await.unwrap();
    let snapshot = writer.project().await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    let mut closed = previous.clone();
    closed.predecessor_revision_id = Some(previous.revision_id);
    closed.revision_id = evertrace_domain::revision::RevisionId::new_v7();
    closed.lifecycle = evertrace_domain::work::TaskLifecycle::Completed;
    closed.closed_at_us = Some(now);
    closed.source_watermark = snapshot.frontier;
    writer
        .commit(
            &evertrace_engine::work::task::revise_task(
                evertrace_engine::work::WorkCommandContext {
                    command_id: evertrace_domain::ids::CommandId::new_v7(),
                    occurred_at_us: now,
                    effective_config_hash: config.hash(),
                    algorithm_revision: "work-test-terminal-v1",
                },
                &previous,
                closed.clone(),
                evertrace_engine::work::TypedTaskChange::Lifecycle,
                std::slice::from_ref(&reference),
            )
            .unwrap(),
            now,
        )
        .await
        .unwrap();
    drop(writer);
    let daemon = Daemon(
        Command::new(&paths.daemon)
            .arg("--config")
            .arg(&paths.config)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !package_health(socket.clone()).await {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let continuation = TaskId::new_v7();
    let mut next = json!({"kind":"work_annotation","choice":"continue","task_id":continuation,
        "from_task_id":task,"goal":"different goal"});
    assert_eq!(
        call(
            &paths,
            "work-session",
            "add",
            &next.to_string(),
            std::slice::from_ref(&reference)
        )["status"],
        "invalid_input"
    );
    next["goal"] = closed.canonical_goal.clone().into();
    let result = loop {
        let result = call(
            &paths,
            "work-session",
            "add",
            &next.to_string(),
            std::slice::from_ref(&reference),
        );
        if result["items"]["evidence"][0]["object_ref"].is_string() {
            break result;
        }
        assert!(Instant::now() < deadline, "{result}");
        assert!(
            result["status"] == "conflict" || result["status"] == "partial",
            "{result}"
        );
    };
    assert_eq!(
        result["items"]["evidence"][0]["object_ref"],
        continuation.to_string()
    );
    let repeated = call(
        &paths,
        "work-session",
        "add",
        &next.to_string(),
        std::slice::from_ref(&reference),
    );
    assert_eq!(
        repeated["items"]["evidence"][0]["object_revision_ref"],
        result["items"]["evidence"][0]["object_revision_ref"]
    );
    drop(daemon);
    let writer = JournalWriter::open(&paths.data_root).await.unwrap();
    let snapshot = writer.project().await.unwrap();
    let view = evertrace_store::WorkIdentityCurrentView::from_snapshot(&snapshot).unwrap();
    let created = view.tasks.get(&continuation).unwrap();
    assert_eq!(created.continuation_of_task_id, Some(task));
    assert_eq!(
        created.identity_confidence,
        evertrace_domain::work::TaskIdentityConfidence::Provisional
    );
    assert!(created.scope_memberships.is_empty());
    assert_eq!(
        view.tasks.get(&task).unwrap().revision_id,
        closed.revision_id
    );
}

#[tokio::test]
async fn installed_native_capture_is_weak_durable_and_replay_safe() {
    let (root, paths, config) = fixture();
    fs::create_dir(&paths.data_root).unwrap();
    fs::set_permissions(&paths.data_root, fs::Permissions::from_mode(0o700)).unwrap();
    for _ in 0..3 {
        evertrace_engine::publish_recovery_runtime(&paths.data_root, &config, None).unwrap();
    }
    let result = install_offline(&paths, false).unwrap();
    assert!(!result.service_available);
    // Current installation inspection must not traverse unrelated session pins.
    let unrelated_pin = paths.data_root.join("hooks/pins/unrelated-old-session.pin");
    fs::write(&unrelated_pin, b"999999").unwrap();
    fs::set_permissions(&unrelated_pin, fs::Permissions::from_mode(0o600)).unwrap();
    let current = evertrace_codex::install::StableLauncher::freeze_current_snapshot(
        &paths.data_root,
        std::time::Instant::now() + std::time::Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(current.generation, 1);
    assert_eq!(current.files.len(), 4);
    assert!(
        evertrace_codex::install::StableLauncher::freeze_current_snapshot(
            &paths.data_root,
            std::time::Instant::now(),
        )
        .is_err()
    );
    assert!(
        evertrace_codex::install::StableLauncher::freeze_backup_snapshot(&paths.data_root).is_err()
    );
    fs::remove_file(&unrelated_pin).unwrap();
    let runtime = RuntimeSnapshot::load(&RuntimeSnapshot::snapshot_path(&paths.data_root)).unwrap();
    assert_eq!(runtime.generation, 3);
    let installed_runtime = RuntimeSnapshot::load(
        &paths
            .data_root
            .join("hooks/generations/1/hook-runtime-v1.json"),
    )
    .unwrap();
    assert_eq!(installed_runtime.generation, 3);
    assert_eq!(
        runtime.recovery_gate,
        evertrace_capture::RecoveryGateMode::Disabled
    );
    let mut native = serde_json::json!({"cwd": paths.data_root, "hook_event_name":"PreToolUse", "model":"test", "permission_mode":"default", "session_id":"installed-session", "tool_input":{"command":"echo protected-native-input"}, "tool_name":"Bash", "tool_use_id":"tool-1", "transcript_path":null, "turn_id":"turn-1"});
    let bytes = serde_json::to_vec(&native).unwrap();
    invoke(&paths, &bytes);
    invoke(&paths, &bytes);
    native["hook_event_name"] = "PostToolUse".into();
    native["tool_name"] = "apply_patch".into();
    native["tool_response"] = serde_json::json!({"output":"updated"});
    invoke(&paths, &serde_json::to_vec(&native).unwrap());
    let (mut spool, _) =
        DurableSpool::open(runtime.spool_dir.clone(), runtime.spool_limits().unwrap()).unwrap();
    assert_eq!(spool.read_active().unwrap().len(), 3);
    native["input_version"] = 5.into();
    invoke(&paths, &serde_json::to_vec(&native).unwrap());
    native.as_object_mut().unwrap().remove("input_version");
    native.as_object_mut().unwrap().remove("tool_response");
    invoke(&paths, &serde_json::to_vec(&native).unwrap());
    // A bounded malformed payload is fail-open, never a successful capture.
    invoke(
        &paths,
        &vec![b'x'; evertrace_codex::hook_input::MAX_CAPTURE_HOOK_INPUT + 1],
    );
    assert_eq!(spool.read_active().unwrap().len(), 3);
    spool.seal_active(runtime.generation).unwrap();
    let replay = spool
        .sealed_segments(16)
        .unwrap()
        .into_iter()
        .map(|segment| (segment.path().to_owned(), fs::read(segment.path()).unwrap()))
        .collect::<Vec<_>>();
    drop(spool);
    let writer = JournalWriter::open(&paths.data_root).await.unwrap();
    let (handle, actor) = spawn_writer(writer, 16).unwrap();
    let ingest =
        EvidenceIngestor::new(runtime, handle.clone(), config.hash(), "s34-install-test").unwrap();
    assert_eq!(ingest.drain_once().await.unwrap().committed_frames, 3);
    let snapshot = handle.project().await.unwrap();
    let mut sources = std::collections::BTreeSet::new();
    for row in snapshot.data_rows() {
        if let Some(payload) = row.payload_json.as_deref() {
            if let Ok(JournalPayload::SourceObservationRecorded(value)) =
                serde_json::from_str(payload)
            {
                assert_eq!(
                    value.identity_strength,
                    IdentityStrength::SynthesizedBestEffort
                );
                assert_eq!(value.capture_completeness, CaptureCompleteness::Partial);
                assert_eq!(
                    value.correlation.admission,
                    CorrelationAdmission::Unavailable
                );
                sources.insert(value.source_instance_id);
            }
            if let Ok(JournalPayload::SourceReceiptRecorded(value)) = serde_json::from_str(payload)
            {
                assert_eq!(value.close_watermark, None);
                assert_eq!(value.previous_source_revision, None);
                assert_eq!(
                    value.source_revision_mode,
                    evertrace_domain::evidence::SourceRevisionMode::Append
                );
                assert_eq!(
                    (value.source_sequence, value.source_sequence_origin),
                    (0, Some(0))
                );
                assert_eq!(value.capture_completeness, CaptureCompleteness::Partial);
            }
        }
    }
    assert_eq!(sources.len(), 3);
    let cas = evertrace_capture::CasStore::open_existing(paths.data_root.join("cas")).unwrap();
    let digest = snapshot
        .data_rows()
        .find_map(|row| {
            match serde_json::from_str::<JournalPayload>(row.payload_json.as_deref()?).ok()? {
                JournalPayload::SourceReceiptRecorded(receipt) => {
                    Some(evertrace_capture::CasStore::parse_digest(&receipt.cas_ref).unwrap())
                }
                _ => None,
            }
        })
        .unwrap();
    assert_eq!(
        cas.read_bounded(&digest, 0, 8 << 20),
        Err(evertrace_capture::CasError::ReadBudgetExceeded)
    );
    assert_eq!(
        cas.read_bounded(&digest, 8 << 20, 0),
        Err(evertrace_capture::CasError::ReadBudgetExceeded)
    );
    let blob = cas.blob_path(&digest);
    let original_blob = fs::read(&blob).unwrap();
    let mut bad_header = original_blob.clone();
    bad_header[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
    fs::write(&blob, bad_header).unwrap();
    assert_eq!(
        cas.read_bounded(&digest, 8 << 20, 8 << 20),
        Err(evertrace_capture::CasError::ReadBudgetExceeded)
    );
    fs::write(&blob, original_blob).unwrap();
    assert_eq!(
        cas.read_bounded(&digest, 8 << 20, 8 << 20).unwrap().0,
        cas.read(&digest).unwrap()
    );
    for (path, bytes) in replay {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
    }
    assert_eq!(ingest.drain_once().await.unwrap().replayed_frames, 3);
    assert_eq!(handle.project().await.unwrap().frontier, snapshot.frontier);
    // A scripted Host is only an orchestration/negative test. Old genuine
    // native receipts above cannot qualify this fresh nonce/workspace.
    use evertrace_engine::{
        HostCanaryRequest, HostCanaryService, HostCanaryStatus, McpBindingAuthority,
    };
    let bindings = McpBindingAuthority::from_device_key_dir(&paths.data_root.join("keys")).unwrap();
    let canary = HostCanaryService::new(
        handle.clone(),
        paths.data_root.clone(),
        paths.config.clone(),
        config.hash(),
        bindings.clone(),
    );
    let request = || HostCanaryRequest {
        host_executable: paths.host_executable.to_string_lossy().into_owned(),
        host_config: paths.host_config.to_string_lossy().into_owned(),
    };
    fs::write(&paths.host_executable, "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'codex-cli 0.1.0'; exit 0; fi\nif [ \"$1\" = features ]; then echo 'hooks experimental true'; exit 0; fi\nsleep 60\n").unwrap();
    let running = canary.clone();
    let input = request();
    let probe = tokio::spawn(async move { running.run(input).await });
    for _ in 0..100 {
        if canary.current().is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        canary.run(request()).await.status,
        HostCanaryStatus::Running
    );
    let result = probe.await.unwrap();
    assert_eq!(result.status, HostCanaryStatus::TimedOut);
    assert!(result.qualification.is_none());
    assert!(
        !result.native_delivery_observed
            && !result.mcp_claim_consumed
            && !result.capture_receipt_observed
    );
    assert_eq!(canary.current().unwrap().status, HostCanaryStatus::TimedOut);
    assert_eq!(canary.current(), Some(result.clone()));
    let restarted = HostCanaryService::new(
        handle.clone(),
        paths.data_root.clone(),
        paths.config.clone(),
        config.hash(),
        bindings,
    );
    assert!(restarted.current().is_none());
    let running = canary.clone();
    let input = request();
    let probe = tokio::spawn(async move { running.run(input).await });
    for _ in 0..100 {
        if canary
            .current()
            .is_some_and(|value| value.status == HostCanaryStatus::Running)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    probe.abort();
    assert!(probe.await.unwrap_err().is_cancelled());
    assert_eq!(
        canary.current().unwrap().status,
        HostCanaryStatus::Interrupted
    );
    // Natural leader exit must not orphan a still-running member of its group.
    let child_ids = root.path().join("canary-child-ids");
    fs::write(&paths.host_executable, format!(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'codex-cli 0.1.0'; exit 0; fi\nif [ \"$1\" = features ]; then echo 'hooks experimental true'; exit 0; fi\nsleep 60 &\nprintf '%s %s' \"$$\" \"$!\" > '{}'\nexit 0\n",
        child_ids.display(),
    )).unwrap();
    let running = canary.clone();
    let input = request();
    let probe = tokio::spawn(async move { running.run(input).await });
    let mut stopped = false;
    for _ in 0..100 {
        if let Ok(ids) = fs::read_to_string(&child_ids) {
            let ids = ids
                .split_whitespace()
                .map(|value| value.parse::<u32>().unwrap())
                .collect::<Vec<_>>();
            if ids.len() == 2 {
                let leader_reaped = !std::path::PathBuf::from(format!("/proc/{}", ids[0])).exists();
                let descendant_stopped = fs::read_to_string(format!("/proc/{}/stat", ids[1]))
                    .map_or(true, |stat| {
                        stat.rsplit_once(')')
                            .is_some_and(|(_, fields)| fields.trim_start().starts_with('Z'))
                    });
                if leader_reaped && descendant_stopped {
                    stopped = true;
                    break;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        stopped,
        "natural-exit group was not terminated before leader reap"
    );
    assert!(!probe.is_finished()); // Exit zero is not positive canary evidence.
    probe.abort();
    assert!(probe.await.unwrap_err().is_cancelled());
    let mut changed = fs::read(&paths.host_config).unwrap();
    changed.extend_from_slice(b"\n# changed after probe\n");
    fs::write(&paths.host_config, changed).unwrap();
    assert_eq!(
        canary.current().unwrap().status,
        HostCanaryStatus::IdentityChanged
    );
    let invalidated = canary.current().unwrap();
    assert!(invalidated.qualification.is_none());
    assert!(!invalidated.native_delivery_observed && !invalidated.mcp_claim_consumed);
    assert!(
        fs::read_dir(paths.data_root.join("runtime"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("canary-"))
    );
    drop(canary);
    drop(restarted);
    drop(ingest);
    drop(handle);
    actor.await.unwrap().unwrap();
}

#[test]
fn owned_merge_idempotence_uninstall_and_unknown_owner() {
    let (_root, paths, _) = fixture();
    fs::create_dir(paths.host_config.parent().unwrap()).unwrap();
    let original = "# user comment\nmodel = 'user-choice'\n[mcp_servers.other]\ncommand = 'other'\n[hooks]\n[[hooks.SessionStart]]\nmatcher = '*'\nhooks = [{type = 'command', command = 'user-hook'}]\n";
    fs::write(&paths.host_config, original).unwrap();
    service(&paths, "exit 0");
    let first = install_offline(&paths, false).unwrap();
    assert!(first.service_available);
    assert!(
        fs::read_to_string(&paths.host_config)
            .unwrap()
            .starts_with(original)
    );
    let installed = fs::read(&paths.host_config).unwrap();
    let launcher = evertrace_codex::install::StableLauncher::open(&paths.data_root).unwrap();
    let wiring_hash = || {
        evertrace_codex::install::installed_wiring_hash(
            &paths.data_root,
            &paths.config,
            &paths.host_config,
        )
        .unwrap()
        .1
    };
    let hash = wiring_hash();
    let mut with_comment = installed.clone();
    with_comment.extend_from_slice(b"\n# unrelated user setting\n");
    fs::write(&paths.host_config, with_comment).unwrap();
    assert_eq!(wiring_hash(), hash); // User TOML is not the wiring digest domain.
    fs::write(&paths.host_config, &installed).unwrap();
    let arguments = evertrace_codex::install::candidate_host_arguments();
    let candidate_hash = evertrace_codex::install::candidate_wiring_hash(&arguments);
    let mut reordered = arguments.clone();
    reordered.swap(1, 3);
    assert_ne!(
        evertrace_codex::install::candidate_wiring_hash(&reordered),
        candidate_hash
    );
    let pinned = launcher
        .resolve_for_session("retained-installed-session")
        .unwrap();
    assert!(install_offline(&paths, false).unwrap().backups.is_empty());
    assert_eq!(fs::read(&paths.host_config).unwrap(), installed);
    // Shape written by the real 0.153.4 normal review experiment. State is
    // deliberately inside the markers, but is not an EverTrace declaration.
    let host_state = "\n[hooks.state.\"private:pre_tool_use:0:0\"]\ntrusted_hash = 'sha256:review-state' # keep exact\n[projects.\"/private/work\"]\ntrust_level = 'trusted'\n[mcp_servers.evertrace.tools.evertrace]\napproval_mode = 'approve'\n";
    let with_state = String::from_utf8(installed.clone()).unwrap().replace(
        "# END EverTrace managed wiring v1",
        &format!("{host_state}# END EverTrace managed wiring v1"),
    );
    fs::write(&paths.host_config, &with_state).unwrap();
    assert_eq!(wiring_hash(), hash);
    assert!(install_offline(&paths, false).unwrap().backups.is_empty());
    assert_eq!(fs::read_to_string(&paths.host_config).unwrap(), with_state);
    install_offline(&paths, true).unwrap();
    let uninstalled = fs::read_to_string(&paths.host_config).unwrap();
    assert!(uninstalled.contains(host_state));
    assert!(!uninstalled.contains("--launcher-root"));
    install_offline(&paths, false).unwrap();
    assert!(
        fs::read_to_string(&paths.host_config)
            .unwrap()
            .contains(host_state)
    );
    assert_eq!(wiring_hash(), hash);
    let ambiguous = format!("{with_state}# BEGIN EverTrace managed wiring v1\n");
    fs::write(&paths.host_config, &ambiguous).unwrap();
    assert!(install_offline(&paths, false).is_err());
    assert_eq!(fs::read_to_string(&paths.host_config).unwrap(), ambiguous);
    fs::write(&paths.host_config, &installed).unwrap();
    fs::write(paths.data_root.join("user-data"), b"keep").unwrap();
    // Literal output of the pre-edit package's real isolated install, checked
    // against 5643caa's owned format; not generated by the new compatibility helper.
    let historical = r#"# BEGIN EverTrace managed wiring v1
[[hooks.PostToolUse]]
matcher = ".*"

[[hooks.PostToolUse.hooks]]
command = "'/experiment/old-home/.local/share/evertrace/hook-v1' --launcher-root '/experiment/old-home/.local/share/evertrace'"
timeout = 3
type = "command"

[[hooks.PreToolUse]]
matcher = ".*"

[[hooks.PreToolUse.hooks]]
command = "'/experiment/old-home/.local/share/evertrace/hook-v1' --launcher-root '/experiment/old-home/.local/share/evertrace'"
timeout = 3
type = "command"

[mcp_servers.evertrace]
args = ["--config", "/experiment/old.toml", "mcp"]
command = "/package/evertrace"
enabled_tools = ["evertrace"]
# END EverTrace managed wiring v1
"#
        .replace("/experiment/old-home/.local/share/evertrace", paths.data_root.to_str().unwrap())
        .replace("/experiment/old.toml", paths.config.to_str().unwrap())
        .replace("/package/evertrace", paths.cli.to_str().unwrap());
    fs::write(&paths.host_config, format!("{original}{historical}")).unwrap();
    assert!(
        evertrace_codex::install::validate_installed_wiring(
            &paths.data_root,
            &paths.config,
            &paths.host_config
        )
        .is_err()
    );
    install_offline(&paths, false).unwrap();
    assert_eq!(wiring_hash(), hash);
    assert!(
        fs::read_to_string(&paths.host_config)
            .unwrap()
            .starts_with(&format!(
                "{original}{}",
                historical.split("# END EverTrace").next().unwrap()
            ))
    ); // Existing array positions survive adding the submission declaration.
    let edited_old = format!(
        "{original}{}",
        historical.replace("timeout = 3", "timeout = 4")
    );
    fs::write(&paths.host_config, &edited_old).unwrap();
    assert!(install_offline(&paths, false).is_err());
    assert_eq!(fs::read_to_string(&paths.host_config).unwrap(), edited_old);
    fs::write(&paths.host_config, format!("{original}{historical}")).unwrap();
    install_offline(&paths, true).unwrap();
    let removed = fs::read_to_string(&paths.host_config).unwrap();
    assert!(removed.starts_with(original));
    assert!(removed[original.len()..].trim().is_empty());
    assert_eq!(
        fs::read(paths.data_root.join("user-data")).unwrap(),
        b"keep"
    );
    assert!(paths.data_root.join("hooks/registry-v1.json").is_file());
    assert_eq!(
        launcher
            .resolve_for_session("retained-installed-session")
            .unwrap(),
        pinned
    );
    assert!(pinned.executable.is_file());
    assert!(pinned.runtime_snapshot.is_file());
    assert!(!paths.unit.exists());
    fs::write(
        &paths.host_config,
        "[mcp_servers.evertrace]\ncommand='user-owned'\n",
    )
    .unwrap();
    assert!(install_offline(&paths, false).is_err());
    assert!(
        fs::read_to_string(&paths.host_config)
            .unwrap()
            .contains("user-owned")
    );
    fs::write(&paths.host_config, original).unwrap();
    fs::write(&paths.unit, "# another installation\n").unwrap();
    assert!(install_offline(&paths, false).is_err());
    assert_eq!(
        fs::read_to_string(&paths.unit).unwrap(),
        "# another installation\n"
    );
}

#[tokio::test]
async fn doctor_reads_current_state_and_only_cli_refresh_runs_the_selected_host() {
    use evertrace_protocol::{
        LocalClient,
        command::{Command as Rpc, RunHostCanaryCommand},
        dto::ClientKind,
    };
    use std::time::{Duration, Instant};
    let (_root, paths, config) = fixture();
    let mut config = config.config().clone();
    config.llm.enabled = false;
    fs::write(
        &paths.config,
        EffectiveConfig::new(config).unwrap().to_toml().unwrap(),
    )
    .unwrap();
    install_offline(&paths, false).unwrap();
    let marker = paths.data_root.join("host-probe-called");
    fs::write(
        &paths.host_executable,
        format!(
            "#!/bin/sh\ntouch '{}'\necho unsupported\n",
            marker.display()
        ),
    )
    .unwrap();
    struct Daemon(std::process::Child);
    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut daemon = Daemon(
        Command::new(&paths.daemon)
            .arg("--config")
            .arg(&paths.config)
            .env("CODEX_HOME", paths.host_config.parent().unwrap())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let socket = paths.data_root.join("runtime/evertraced-v1.sock");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if evertrace_protocol::request_health(&socket, "s34-test", Duration::from_millis(100))
            .await
            .is_ok()
        {
            break;
        }
        assert!(Instant::now() < deadline && daemon.0.try_wait().unwrap().is_none());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let doctor = |refresh: bool| {
        let mut command = Command::new(&paths.cli);
        command
            .arg("--config")
            .arg(&paths.config)
            .arg("doctor")
            .env("CODEX_HOME", paths.host_config.parent().unwrap());
        if refresh {
            command.arg("--refresh-host").arg(&paths.host_executable);
        }
        command.output().unwrap()
    };
    let read = doctor(false);
    assert!(read.status.success());
    let read_text = String::from_utf8(read.stdout).unwrap();
    assert!(read_text.contains("host_canary=not_run"));
    assert!(read_text.contains("llm_daily_calls=Disabled"));
    assert!(read_text.contains("journal: schema=Some(true)"));
    assert!(read_text.contains("fts_metadata=Checked"));
    assert!(read_text.contains("journal_content=NotChecked"));
    assert!(read_text.contains("acceptance_a_f=NotRun"));
    let mut system = LocalClient::connect(
        &socket,
        "s34-test",
        ClientKind::Cli,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    let response = system
        .request(
            evertrace_domain::ids::RequestId::new_v7(),
            Rpc::HumanGovernance(evertrace_protocol::dto::HumanGovernanceRequest::Read {
                request: evertrace_protocol::dto::HumanReadRequest::List {
                    surface: evertrace_protocol::dto::HumanSurface::System,
                    expected_frontier: None,
                    after: None,
                    limit: 1,
                },
            }),
        )
        .await
        .unwrap();
    let evertrace_protocol::response::Response::HumanGovernance(system_response) = response else {
        panic!("current System response missing")
    };
    let evertrace_protocol::dto::HumanGovernanceResponse::Snapshot {
        diagnostics: Some(report),
        ..
    } = &system_response
    else {
        panic!("current System diagnostics missing")
    };
    assert!(report.validate());
    assert!(read_text.contains(&format!("diagnostics_config_hash={}", report.config_hash)));
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "fts_metadata"
                && check.state == evertrace_protocol::dto::HumanDiagnosticState::Checked)
    );
    assert!(system_response.validate());
    let encoded = evertrace_protocol::frame::canonical_json(&system_response).unwrap();
    assert!(encoded.len() < 16 * 1024);
    let mut small_frame = Vec::new();
    assert!(matches!(
        evertrace_protocol::frame::write_frame_sync(&mut small_frame, &system_response, 1024),
        Err(evertrace_protocol::frame::FrameError::Oversize)
    ));
    assert!(small_frame.is_empty());
    let mut app = evertrace_tui::App::new();
    app.dispatch(evertrace_tui::UiCommand::Navigate(
        evertrace_tui::Route::System,
    ));
    app.handle(evertrace_tui::AppEvent::HumanRead {
        surface: evertrace_protocol::dto::HumanSurface::System,
        locator: evertrace_tui::HumanReadLocator::List,
        response: system_response.clone(),
    });
    assert_eq!(app.state().human.as_ref(), Some(&system_response));
    assert!(!marker.exists());
    let mut hook = LocalClient::connect(
        &socket,
        "s34-test",
        ClientKind::Hook,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert!(
        hook.request(
            evertrace_domain::ids::RequestId::new_v7(),
            Rpc::RunHostCanary(RunHostCanaryCommand {
                host_executable: paths.host_executable.to_string_lossy().into_owned(),
                host_config: paths.host_config.to_string_lossy().into_owned(),
            })
        )
        .await
        .is_err()
    );
    assert!(!marker.exists());
    let refresh = doctor(true);
    assert!(refresh.status.success());
    assert!(
        String::from_utf8(refresh.stdout)
            .unwrap()
            .contains("Unavailable")
    );
    assert!(marker.exists());
    let current = doctor(false);
    assert!(current.status.success());
    assert!(
        String::from_utf8(current.stdout)
            .unwrap()
            .contains("Unavailable")
    );
    daemon.0.kill().unwrap();
    daemon.0.wait().unwrap();
    for name in ["cas", "spool"] {
        let path = paths.data_root.join(name);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o770)).unwrap();
        let invalid = doctor(false);
        assert!(!invalid.status.success());
        assert!(
            String::from_utf8(invalid.stdout)
                .unwrap()
                .contains(&format!(
                    "{name}_metadata: expected_type=true private=false"
                ))
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o770
        );
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let down = doctor(false);
    assert!(!down.status.success());
    let down = String::from_utf8(down.stdout).unwrap();
    assert!(down.contains("config=valid") && down.contains("daemon=unavailable"));
    fs::write(&paths.config, "not valid = [toml\nDOCTOR_SECRET_MARKER").unwrap();
    let invalid = doctor(false);
    assert!(!invalid.status.success());
    let invalid_output = format!(
        "{}{}",
        String::from_utf8(invalid.stdout).unwrap(),
        String::from_utf8(invalid.stderr).unwrap()
    );
    assert!(invalid_output.contains("config=invalid_or_unreadable"));
    assert!(!invalid_output.contains("DOCTOR_SECRET_MARKER"));
    assert_eq!(
        fs::read_to_string(&paths.config).unwrap(),
        "not valid = [toml\nDOCTOR_SECRET_MARKER"
    );
}

#[tokio::test]
async fn candidate_canary_rpc_is_scoped_and_never_updates_installed_current() {
    use evertrace_protocol::{
        LocalClient,
        command::{Command as Rpc, RunHostCanaryCommand},
        dto::{ClientKind, HostCanaryScope, HostCanaryStatus},
        response::Response,
    };
    use std::time::{Duration, Instant};
    let (root, paths, config) = fixture();
    let mut config = config.config().clone();
    config.llm.enabled = false;
    fs::write(
        &paths.config,
        EffectiveConfig::new(config).unwrap().to_toml().unwrap(),
    )
    .unwrap();
    fs::create_dir(&paths.data_root).unwrap();
    fs::set_permissions(&paths.data_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(paths.host_config.parent().unwrap()).unwrap();
    fs::write(
        &paths.host_config,
        "# normal Host configuration remains unchanged\n",
    )
    .unwrap();
    fs::set_permissions(&paths.host_config, fs::Permissions::from_mode(0o600)).unwrap();
    let original_host = fs::read(&paths.host_config).unwrap();
    let marker = root.path().join("candidate-host-arguments");
    fs::write(&paths.host_executable, format!("#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'codex-cli 0.1.0'; elif [ \"$1\" = features ]; then echo 'hooks experimental true'; else printf '%s\\n' \"$EVERTRACE_CANDIDATE_ROOT\" \"$@\" > '{}'; fi\n", marker.display())).unwrap();
    let check_id = evertrace_domain::ids::JobId::new_v7().to_string();
    let unknown = paths.data_root.join("unrelated-user-file");
    fs::write(&unknown, b"retain").unwrap();
    let rejected = Command::new(&paths.daemon)
        .arg("--config")
        .arg(&paths.config)
        .arg("--candidate-check")
        .arg(&check_id)
        .arg("7")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!rejected.success());
    assert!(!paths.data_root.join("runtime").exists());
    assert_eq!(fs::read(&unknown).unwrap(), b"retain");
    fs::remove_file(unknown).unwrap();
    struct Daemon(std::process::Child);
    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut daemon = Daemon(
        Command::new(&paths.daemon)
            .args(["--config"])
            .arg(&paths.config)
            .arg("--candidate-check")
            .arg(&check_id)
            .arg("7")
            .env_clear()
            .env("HOME", root.path())
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let socket = paths.data_root.join("runtime/evertraced-v1.sock");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !package_health(socket.clone()).await {
        assert!(Instant::now() < deadline && daemon.0.try_wait().unwrap().is_none());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!marker.exists());
    let snapshot = evertrace_codex::install::StableLauncher::freeze_current_snapshot(
        &paths.data_root,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(snapshot.generation, 7);
    let mut client = LocalClient::connect(
        &socket,
        "s34-candidate",
        ClientKind::Cli,
        Duration::from_secs(35),
    )
    .await
    .unwrap();
    let request = || {
        Rpc::RunHostCanary(RunHostCanaryCommand {
            host_executable: paths.host_executable.to_string_lossy().into_owned(),
            host_config: paths.host_config.to_string_lossy().into_owned(),
        })
    };
    let Response::HostCanary(result) = client
        .request(evertrace_domain::ids::RequestId::new_v7(), request())
        .await
        .unwrap()
    else {
        panic!("canary response");
    };
    assert_eq!(
        result.scope,
        HostCanaryScope::Candidate {
            check_id,
            generation: 7
        }
    );
    assert_eq!(result.status, HostCanaryStatus::TimedOut); // Script output is not Host evidence.
    assert!(result.qualification.is_none());
    assert!(!result.native_delivery_observed && !result.mcp_claim_consumed);
    let arguments = fs::read_to_string(&marker).unwrap();
    assert!(arguments.starts_with(paths.data_root.to_str().unwrap()));
    for argument in evertrace_codex::install::candidate_host_arguments() {
        assert!(arguments.contains(&argument));
    }
    assert!(arguments.contains(
        "mcp_servers.evertrace.env_vars=[\"EVERTRACE_CANDIDATE_PACKAGE\",\"EVERTRACE_CANDIDATE_CONFIG\"]"
    ));
    assert!(!arguments.contains("ignore-user-config") && !arguments.contains("bypass"));
    assert_eq!(fs::read(&paths.host_config).unwrap(), original_host);
    assert!(
        !fs::read_dir(paths.data_root.join("runtime"))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("canary-"))
    );
    let doctor = Command::new(&paths.cli)
        .arg("--config")
        .arg(&paths.config)
        .arg("doctor")
        .output()
        .unwrap();
    assert!(doctor.status.success());
    assert!(
        String::from_utf8(doctor.stdout)
            .unwrap()
            .contains("host_canary=not_run")
    );
    let launcher = paths.data_root.join("hook-v1");
    fs::OpenOptions::new()
        .append(true)
        .open(&launcher)
        .unwrap()
        .write_all(b"changed")
        .unwrap();
    let Response::HostCanary(rejected) = client
        .request(evertrace_domain::ids::RequestId::new_v7(), request())
        .await
        .unwrap()
    else {
        panic!("canary response");
    };
    assert_eq!(rejected.status, HostCanaryStatus::IdentityChanged);
    assert!(rejected.qualification.is_none());
}

#[test]
fn failed_owned_service_uninstalls_without_restart_on_rollback() {
    let (_root, paths, _) = fixture();
    service(&paths, "exit 0");
    install_offline(&paths, false).unwrap();
    let installed = fs::read(&paths.host_config).unwrap();
    let unit = fs::read(&paths.unit).unwrap();
    let started = paths.data_root.join("unexpected-start");
    service(
        &paths,
        &format!(
            "if [ \"$2\" = start ]; then touch '{}'; fi\nif [ \"$2\" = daemon-reload ]; then exit 1; fi\nexit 0",
            started.display()
        ),
    );
    let failed = fs::read_to_string(&paths.systemctl)
        .unwrap()
        .replace("echo inactive", "echo failed");
    fs::write(&paths.systemctl, &failed).unwrap();
    assert!(install_offline(&paths, true).is_err());
    assert_eq!(fs::read(&paths.host_config).unwrap(), installed);
    assert_eq!(fs::read(&paths.unit).unwrap(), unit);
    assert!(!started.exists());
    fs::write(
        &paths.systemctl,
        failed.replace("then exit 1; fi", "then exit 0; fi"),
    )
    .unwrap();
    install_offline(&paths, true).unwrap();
    assert!(!paths.unit.exists());
    assert!(!started.exists());
    assert!(paths.data_root.join("hooks/registry-v1.json").is_file());
    assert!(
        !fs::read_to_string(&paths.host_config)
            .unwrap()
            .contains("BEGIN EverTrace")
    );
}

#[test]
fn service_failure_rolls_back_but_never_overwrites_concurrent_user_edit() {
    for concurrent in [false, true] {
        let (_root, paths, _) = fixture();
        fs::create_dir(paths.host_config.parent().unwrap()).unwrap();
        fs::write(&paths.host_config, "# original\n").unwrap();
        let edit = if concurrent {
            format!(
                "printf '# concurrent user edit\\n' >> '{}'",
                paths.host_config.display()
            )
        } else {
            ":".into()
        };
        service(
            &paths,
            &format!("if [ \"$2\" = enable ]; then {edit}; exit 1; fi\nexit 0"),
        );
        let failure = install_offline(&paths, false).unwrap_err();
        let host = fs::read_to_string(&paths.host_config).unwrap();
        if concurrent {
            assert!(host.contains("# concurrent user edit"));
            assert!(failure.preserved.contains(&paths.host_config));
        } else {
            assert_eq!(host, "# original\n");
        }
        assert!(!paths.unit.exists());
        if !concurrent {
            assert!(!paths.data_root.join("hooks/registry-v1.json").exists());
            assert!(!paths.data_root.join("hook-v1").exists());
        }
    }
    let (_root, paths, _) = fixture();
    fs::create_dir(paths.host_config.parent().unwrap()).unwrap();
    fs::write(&paths.host_config, "# before\n").unwrap();
    service(
        &paths,
        &format!(
            "if [ \"$2\" = show ]; then printf '# concurrent before write\\n' >> '{}'; fi\nexit 0",
            paths.host_config.display()
        ),
    );
    assert!(install_offline(&paths, false).is_err());
    assert_eq!(
        fs::read_to_string(&paths.host_config).unwrap(),
        "# before\n# concurrent before write\n"
    );
    assert!(!paths.unit.exists());
}

#[test]
fn unsupported_host_and_bounded_service_probe_never_publish_wiring() {
    let (_root, paths, _) = fixture();
    fs::write(&paths.host_executable, "#!/bin/sh\necho unsupported\n").unwrap();
    assert!(install_offline(&paths, false).is_err());
    assert!(!paths.host_config.exists());
    let (_root, paths, _) = fixture();
    service(&paths, "sleep 10");
    let started = std::time::Instant::now();
    let error = install_offline(&paths, false).unwrap_err();
    assert_eq!(
        error.cause,
        evertrace_codex::install::InstallError::ResourceExhausted
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(6));
    assert!(!paths.host_config.exists());
    assert!(!paths.unit.exists());
}
