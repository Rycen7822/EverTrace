use std::{env, error::Error, path::PathBuf};

use evertrace_codex::{HostProbeReport, ProbeContext, ProbeEvidence};
use evertrace_protocol::resolve_data_dir;

use crate::{commands::config, daemon_client};

pub async fn run(config_path: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    let host_probe =
        HostProbeReport::evaluate(&ProbeContext::unobserved_codex(), &ProbeEvidence::empty())?;
    println!("host_probe={}", host_probe.to_json()?);
    let effective = config::load(config_path)?;
    let home = env::var_os("HOME").map(PathBuf::from);
    let data_dir = resolve_data_dir(
        &effective.config().runtime.data_dir,
        home.as_deref(),
        |name| env::var_os(name),
    )?;
    let health = daemon_client::health(&data_dir.join("runtime/evertraced-v1.sock")).await?;
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
