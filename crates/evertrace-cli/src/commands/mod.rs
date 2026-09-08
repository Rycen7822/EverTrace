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
        Command::Doctor { refresh_host } => doctor::run(args.config, refresh_host).await,
        Command::Upgrade => restore::upgrade(args.config).await,
        Command::Install { host_executable } => {
            install::run(args.config, Some(host_executable)).await
        }
        Command::Uninstall => install::run(args.config, None).await,
        Command::Restore { backup } => restore::run(args.config, backup).await,
        Command::Mcp => mcp::run(args.config).await,
        Command::Tui => tui::run(args.config).await,
        Command::AdminSession { action, session_id } => {
            admin::run(args.config, action, session_id).await
        }
    }
}
