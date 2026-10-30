use std::{error::Error, os::unix::process::CommandExt, path::PathBuf, process::Command};

fn probe_error(reason: &str) -> Box<dyn Error> {
    format!(
        "refusing to start a daemon that is not this package's evertraced: {reason}; no daemon was started"
    ).into()
}

/// Replace this process with the same-package daemon, preserving PID, signals
/// and exit status. Never fall back to PATH or initialize another runtime.
pub async fn run(config: Option<PathBuf>, maintenance: bool) -> Result<(), Box<dyn Error>> {
    let executable = std::env::current_exe()?;
    let directory = executable
        .parent()
        .ok_or_else(|| probe_error("no package directory"))?;
    let daemon = directory.join("evertraced");
    super::companion::probe(
        tokio::process::Command::new(&daemon),
        &format!("evertraced {}", env!("CARGO_PKG_VERSION")),
    )
    .await
    .map_err(|error| probe_error(&error.to_string()))?;
    let mut command = Command::new(&daemon);
    if let Some(config) = config {
        command.arg("--config").arg(config);
    }
    if maintenance {
        command.arg("--maintenance");
    }
    Err(probe_error(&format!(
        "replacing this process failed ({})",
        command.exec().kind()
    )))
}
