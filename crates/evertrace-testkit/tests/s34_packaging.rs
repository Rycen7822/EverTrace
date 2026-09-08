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

fn service(paths: &ManagedInstallPaths, body: &str) {
    fs::write(&paths.systemctl, format!("#!/bin/sh\nif [ \"$2\" = is-enabled ]; then echo disabled; exit 1; fi\nif [ \"$2\" = is-active ]; then echo inactive; exit 3; fi\n{body}\n")).unwrap();
    fs::set_permissions(&paths.systemctl, fs::Permissions::from_mode(0o700)).unwrap();
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
async fn installed_native_capture_is_weak_durable_and_replay_safe() {
    let (_root, paths, config) = fixture();
    fs::create_dir(&paths.data_root).unwrap();
    fs::set_permissions(&paths.data_root, fs::Permissions::from_mode(0o700)).unwrap();
    for _ in 0..3 {
        evertrace_engine::publish_recovery_runtime(&paths.data_root, &config, None).unwrap();
    }
    let result = install_offline(&paths, false).unwrap();
    assert!(!result.service_available);
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
    let pinned = launcher
        .resolve_for_session("retained-installed-session")
        .unwrap();
    assert!(install_offline(&paths, false).unwrap().backups.is_empty());
    assert_eq!(fs::read(&paths.host_config).unwrap(), installed);
    fs::write(paths.data_root.join("user-data"), b"keep").unwrap();
    install_offline(&paths, true).unwrap();
    assert_eq!(fs::read_to_string(&paths.host_config).unwrap(), original);
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
