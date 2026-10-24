use std::{error::Error, fs, path::PathBuf};

use evertrace_domain::config::EffectiveConfig;

use crate::resolve_config_path;

pub fn check(config: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    let _ = load(config)?;
    println!("configuration is valid");
    Ok(())
}

pub async fn reload(
    config: Option<PathBuf>,
    socket: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let socket = if let Some(socket) = socket {
        socket
    } else {
        let effective = load(config).map_err(
            |_| "cannot locate daemon from config; use config reload --socket /absolute/path",
        )?;
        let root = evertrace_protocol::resolve_data_dir(
            &effective.config().runtime.data_dir,
            std::env::var_os("HOME")
                .as_deref()
                .map(std::path::Path::new),
            |name| std::env::var_os(name),
        )?;
        root.join("runtime/evertraced-v1.sock")
    };
    let mut client = evertrace_protocol::LocalClient::connect(
        &socket,
        env!("CARGO_PKG_VERSION"),
        evertrace_protocol::dto::ClientKind::Cli,
        std::time::Duration::from_secs(10),
    )
    .await?;
    let response = client
        .request(
            evertrace_domain::ids::RequestId::new_v7(),
            evertrace_protocol::command::Command::ConfigReload,
        )
        .await?;
    let evertrace_protocol::response::Response::ConfigReload(result) = response else {
        return Err("unexpected configuration response".into());
    };
    println!(
        "reload={:?} active={} pending={}",
        result.outcome,
        evertrace_domain::evidence::hex(&result.active_hash),
        result.pending_hash.map_or_else(
            || "none".into(),
            |hash| evertrace_domain::evidence::hex(&hash)
        )
    );
    if result.outcome == evertrace_protocol::dto::ConfigReloadOutcome::Rejected {
        return Err("configuration rejected; last-good remains active".into());
    }
    Ok(())
}

pub fn show_effective(config: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    let effective = load(config)?;
    print!("{}", effective.to_toml()?);
    Ok(())
}

pub fn load(config: Option<PathBuf>) -> Result<EffectiveConfig, Box<dyn Error>> {
    let path = resolve_config_path(config)?;
    let source = fs::read_to_string(path)?;
    Ok(EffectiveConfig::parse_toml(&source)?)
}
