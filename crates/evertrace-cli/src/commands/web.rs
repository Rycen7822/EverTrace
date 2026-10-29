use super::config;
use std::{env, error::Error, path::PathBuf};

pub async fn run(config_path: Option<PathBuf>, port: Option<u16>) -> Result<(), Box<dyn Error>> {
    let effective = config::load(config_path)?;
    let home = env::var_os("HOME").map(PathBuf::from);
    let data = evertrace_protocol::resolve_data_dir(
        &effective.config().runtime.data_dir,
        home.as_deref(),
        |name| env::var_os(name),
    )?;
    evertrace_web::run(
        data.join("runtime/evertraced-v1.sock"),
        evertrace_domain::evidence::hex(&effective.hash()),
        port,
    )
    .await
}
