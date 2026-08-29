mod config;
mod doctor;
mod mcp;

use std::error::Error;

use crate::args::{Args, Command};

pub async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    match args.command {
        Command::ConfigCheck => config::check(args.config),
        Command::ConfigShowEffective => config::show_effective(args.config),
        Command::Doctor => doctor::run(args.config).await,
        Command::Mcp => mcp::run(args.config).await,
    }
}
