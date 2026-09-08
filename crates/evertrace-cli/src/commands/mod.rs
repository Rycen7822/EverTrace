mod admin;
mod config;
mod doctor;
mod install;
mod mcp;
mod restore;
mod tui;

use std::error::Error;

use crate::args::{Args, Command};

pub async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    match args.command {
        Command::ConfigCheck => config::check(args.config),
        Command::ConfigShowEffective => config::show_effective(args.config),
        Command::ConfigReload { socket } => config::reload(args.config, socket).await,
        Command::Doctor { refresh_host } => doctor::run(args.config, refresh_host).await,
        Command::Upgrade {
            check_package,
            live_host,
        } => restore::upgrade(args.config, check_package, live_host).await,
        Command::Install {
            host_executable,
            live_canary,
        } => install::run(args.config, Some(host_executable), live_canary).await,
        Command::Uninstall => install::run(args.config, None, false).await,
        Command::Restore { backup } => restore::run(args.config, backup).await,
        Command::Mcp => mcp::run(args.config).await,
        Command::Tui => tui::run(args.config).await,
        Command::AdminSession { action, session_id } => {
            admin::run(args.config, action, session_id).await
        }
    }
}
