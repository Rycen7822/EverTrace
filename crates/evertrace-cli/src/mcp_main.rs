#![forbid(unsafe_code)]
#![deny(warnings)]

mod args;
mod config_input;
#[path = "commands/mcp.rs"]
mod mcp;

use std::env;

use args::{Args, Command};

#[tokio::main]
async fn main() {
    let result = match Args::parse(env::args_os().skip(1)) {
        Ok(args) => match args.command {
            Command::Mcp { host_locator } => mcp::run(args.config, host_locator).await,
            _ => Err("evertrace-mcp only accepts the mcp command".into()),
        },
        Err(error) if error == args::usage() => {
            Err("evertrace-mcp only accepts the mcp command".into())
        }
        Err(error) => Err(error.into()),
    };
    if let Err(error) = result {
        eprintln!("evertrace: {error}");
        std::process::exit(2);
    }
}
