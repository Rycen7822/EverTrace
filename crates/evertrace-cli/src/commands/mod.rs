mod admin;
mod backup;
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
        Command::Help => {
            println!("{}", crate::args::usage());
            Ok(())
        }
        Command::ConfigCheck => config::check(args.config),
        Command::ConfigShowEffective => config::show_effective(args.config),
        Command::ConfigReload { socket } => config::reload(args.config, socket).await,
        Command::Doctor { refresh_host } => doctor::run(args.config, refresh_host).await,
        Command::Upgrade {
            check_package,
            live_host,
            commit,
        } => restore::upgrade(args.config, check_package, live_host, commit).await,
        Command::Install {
            host_executable,
            live_canary,
        } => install::run(args.config, Some(host_executable), live_canary).await,
        Command::Uninstall => install::run(args.config, None, false).await,
        Command::BackupCreate => backup::run(args.config, None).await,
        Command::BackupVerify { backup_job_id } => {
            backup::run(args.config, Some(backup_job_id)).await
        }
        Command::Restore { backup } => restore::run(args.config, backup).await,
        Command::Mcp { host_locator } => mcp::run(args.config, host_locator).await,
        Command::Tui => tui::run(args.config).await,
        Command::AdminSession { action, session_id } => {
            admin::run(args.config, action, session_id).await
        }
        Command::AdminRepository {
            action,
            repository_id,
            expected_revision,
            worktree_id,
            inventory_ref,
        } => {
            admin::repository(
                args.config,
                action,
                repository_id,
                expected_revision,
                worktree_id,
                inventory_ref,
            )
            .await
        }
    }
}
