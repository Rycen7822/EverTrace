#![forbid(unsafe_code)]
#![deny(warnings)]

mod args;
mod commands;
mod daemon_client;

use std::{env, path::PathBuf};

use args::Args;

#[tokio::main]
async fn main() {
    let result = match Args::parse(env::args_os().skip(1)) {
        Ok(args) => commands::run(args).await,
        Err(error) => Err(error.into()),
    };
    if let Err(error) = result {
        eprintln!("evertrace: {error}");
        std::process::exit(2);
    }
}

pub(crate) fn resolve_config_path(explicit: Option<PathBuf>) -> Result<PathBuf, &'static str> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Some(path) = env::var_os("EVERTRACE_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|base| base.join("evertrace/config.toml"))
        .ok_or("no platform configuration directory")
}
