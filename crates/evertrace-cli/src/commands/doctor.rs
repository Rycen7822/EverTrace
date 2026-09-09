use std::{
    env,
    error::Error,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use evertrace_protocol::resolve_data_dir;

use crate::{commands::config, daemon_client};

fn print_canary(result: &evertrace_protocol::dto::HostCanaryDiagnostic) {
    println!("host_canary={:?} scope={:?}", result.status, result.scope);
    let Some(report) = &result.qualification else {
        println!("host_qualification=unavailable: no current evaluated report");
        return;
    };
    println!(
        "hook={:?} mcp_binding={:?} mechanism={:?}; unique_execution_context=unproven",
        report.hook_activation, report.mcp_binding, report.mcp_mechanism
    );
    for (name, gate) in [
        ("capture", &report.capture),
        ("recovery", &report.recovery),
        ("active_search_due", &report.active_search_due),
        ("strong_normalization", &report.strong_normalization),
        ("project_policy", &report.project_policy),
    ] {
        println!("{name}={:?} reason={:?}", gate.result, gate.reason);
    }
}

pub async fn run(
    config_path: Option<PathBuf>,
    refresh_host: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let selected_config = crate::resolve_config_path(config_path)?;
    print_local_metadata("config", &selected_config, false);
    if !std::fs::symlink_metadata(&selected_config)
        .is_ok_and(|value| value.is_file() && value.len() <= 1 << 20)
    {
        println!("config=invalid_or_unreadable; daemon_location=unavailable; no repair attempted");
        return Err("configuration is not a bounded regular file".into());
    }
    let effective = config::load(Some(selected_config)).map_err(|_| {
        println!("config=invalid_or_unreadable; daemon_location=unavailable; no repair attempted");
        "configuration invalid or unreadable"
    })?;
    println!(
        "config=valid config_version={} config_hash={}",
        effective.config().config_version,
        evertrace_domain::evidence::hex(&effective.hash())
    );
    let home = env::var_os("HOME").map(PathBuf::from);
    let data_dir = resolve_data_dir(
        &effective.config().runtime.data_dir,
        home.as_deref(),
        |name| env::var_os(name),
    )?;
    for (label, path) in [
        ("data_root", data_dir.clone()),
        ("store", data_dir.join("store")),
        ("spool", data_dir.join("spool")),
        ("cas", data_dir.join("cas")),
    ] {
        print_local_metadata(label, &path, true);
    }
    println!("local_checks=metadata_only; native_content=not_checked; acceptance_a_f=not_run");
    if let Some(host) = refresh_host {
        daemon_client::explain_live_host();
        if !host.is_absolute() {
            return Err("Host executable must be absolute".into());
        }
        let host_home = env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|home| home.join(".codex")))
            .ok_or("Host home unavailable")?;
        let result = daemon_client::run_host_canary(
            &data_dir.join("runtime/evertraced-v1.sock"),
            &host,
            &host_home.join("config.toml"),
        )
        .await?;
        print_canary(&result);
    }
    let socket = data_dir.join("runtime/evertraced-v1.sock");
    let health = daemon_client::health(&socket).await.map_err(|_| {
        println!("daemon=unavailable; protocol=unavailable; current_diagnostics=unavailable; local checks retained");
        "daemon unavailable"
    })?;
    let diagnostics = daemon_client::system_diagnostics(&socket).await?;
    match &diagnostics.host {
        Some(result) => print_canary(result),
        None => println!("host_canary=not_run: no current observation in this daemon"),
    }
    println!("refresh: doctor --refresh-host /absolute/host");
    println!(
        "protocol_version={} mode={:?} config_version={} config_hash={} algorithm_revision={}",
        health.protocol_version,
        health.mode,
        health.config_version,
        health.effective_config_hash,
        health.algorithm_revision
    );
    println!(
        "diagnostics_config_hash={} observed_at_us={}; carriers are not an atomic snapshot",
        diagnostics.config_hash, diagnostics.observed_at_us
    );
    for (name, table) in ["journal", "objects", "relations", "search"]
        .into_iter()
        .zip(&diagnostics.tables)
    {
        println!(
            "{name}: schema={:?} version={:?} checkpoint={:?}",
            table.schema_matches, table.version, table.checkpoint
        );
    }
    for check in &diagnostics.checks {
        println!(
            "{}={:?} recorded={:?} limit={:?} remaining={:?}",
            check.name,
            check.state,
            check.count,
            check.limit,
            check
                .limit
                .zip(check.count)
                .map(|(limit, count)| limit.saturating_sub(count))
        );
    }
    println!(
        "metadata is not content integrity; failed jobs/backup counts are historical, not current global failure; daily usage is recorded usage, not next-request eligibility"
    );
    Ok(())
}

fn print_local_metadata(label: &str, path: &Path, directory: bool) {
    match std::fs::symlink_metadata(path) {
        Ok(value) => println!(
            "{label}_metadata: expected_type={} private={} uid={} (local metadata only)",
            if directory {
                value.is_dir()
            } else {
                value.is_file()
            },
            value.mode() & 0o077 == 0,
            value.uid()
        ),
        Err(_) => println!("{label}_metadata=unavailable"),
    }
}
