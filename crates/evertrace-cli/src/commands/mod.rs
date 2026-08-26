mod config;
mod doctor;

use std::error::Error;

use crate::args::{Args, Command};

pub async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    match args.command {
        Command::ConfigCheck => config::check(args.config),
        Command::ConfigShowEffective => config::show_effective(args.config),
        Command::Doctor => doctor::run(args.config).await,
    }
}
