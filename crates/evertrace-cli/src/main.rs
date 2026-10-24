#![forbid(unsafe_code)]
#![deny(warnings)]

mod args;
mod commands;
mod config_input;
mod daemon_client;

use std::env;

use args::Args;

pub(crate) use config_input::resolve_config_path;

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
