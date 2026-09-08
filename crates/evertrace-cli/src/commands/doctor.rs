use std::{env, error::Error, path::PathBuf};

use evertrace_protocol::resolve_data_dir;

use crate::{commands::config, daemon_client};

pub async fn run(
    config_path: Option<PathBuf>,
    refresh_host: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let effective = config::load(config_path)?;
    let home = env::var_os("HOME").map(PathBuf::from);
    let data_dir = resolve_data_dir(
        &effective.config().runtime.data_dir,
        home.as_deref(),
        |name| env::var_os(name),
    )?;
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
        println!("host_canary={result:?}; capability qualification remains independent");
    }
    let health = daemon_client::health(&data_dir.join("runtime/evertraced-v1.sock")).await?;
    match &health.host_canary {
        Some(result) => println!("host_canary={result:?}; installed-path diagnosis only"),
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
    Ok(())
}
