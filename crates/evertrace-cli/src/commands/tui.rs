use crate::commands::config;
use evertrace_protocol::resolve_data_dir;
use std::{env, error::Error, path::PathBuf};
pub async fn run(config_path: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    let effective = config::load(config_path)?;
    let home = env::var_os("HOME").map(PathBuf::from);
    let data_dir = resolve_data_dir(
        &effective.config().runtime.data_dir,
        home.as_deref(),
        |name| env::var_os(name),
    )?;
    evertrace_tui::run(data_dir.join("runtime/evertraced-v1.sock")).await
}
