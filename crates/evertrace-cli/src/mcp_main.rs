#![forbid(unsafe_code)]
#![deny(warnings)]

mod args;
mod config_input;
#[path = "commands/mcp.rs"]
mod mcp;

use std::env;

use args::{Args, Command};

/// The standalone transport accepts exactly the `evertrace --mcp` argument
/// contract and no other CLI mode; `--config PATH` stays a mode prefix.
#[tokio::main]
async fn main() {
    let only = "evertrace-mcp only accepts evertrace --mcp (no other CLI mode)";
    let result = match Args::parse(env::args_os().skip(1)) {
        Ok(Args {
            config,
            command: Command::Mcp { host_locator },
        }) => mcp::run(config, host_locator).await,
        Ok(_) | Err(_) => Err(only.into()),
    };
    if let Err(error) = result {
        eprintln!("evertrace: {error}");
        std::process::exit(2);
    }
}
