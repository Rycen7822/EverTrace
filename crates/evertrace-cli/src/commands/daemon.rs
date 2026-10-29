use std::{
    error::Error,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use tokio::{io::AsyncReadExt, time::timeout};

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const PROBE_BYTES: u64 = 128;

fn probe_error(reason: &str) -> Box<dyn Error> {
    format!(
        "refusing to start a daemon that is not this package's evertraced: {reason}; no daemon was started"
    )
    .into()
}

async fn probe(executable: &Path) -> Result<String, Box<dyn Error>> {
    let mut child = tokio::process::Command::new(executable)
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| probe_error(&format!("it cannot be executed ({})", error.kind())))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| probe_error("its --version output is unavailable"))?;
    // One deadline covers both EOF and process exit. Read at most one byte past
    // the limit, so a verbose or stalled sibling cannot flood or block startup.
    let result = timeout(PROBE_TIMEOUT, async {
        let mut output = Vec::new();
        stdout
            .take(PROBE_BYTES + 1)
            .read_to_end(&mut output)
            .await
            .map_err(|_| probe_error("its --version output is unreadable"))?;
        if output.len() as u64 > PROBE_BYTES {
            return Err(probe_error("its --version output exceeds 128 bytes"));
        }
        let status = child
            .wait()
            .await
            .map_err(|_| probe_error("its --version exit status is unavailable"))?;
        if !status.success() {
            return Err(probe_error("its --version exited without success"));
        }
        let text = String::from_utf8(output)
            .map_err(|_| probe_error("its --version output is not UTF-8 text"))?;
        Ok(text.trim_end_matches('\n').to_owned())
    })
    .await
    .unwrap_or_else(|_| Err(probe_error("its --version did not finish within 3 seconds")));
    if child.id().is_some() {
        // Timeout, oversized output or a read error must also reap the probe.
        let _ = child.kill().await;
    }
    result
}

/// Replace this process with the same-package daemon, preserving PID, signals
/// and exit status. Never fall back to PATH or initialize another runtime.
pub async fn run(config: Option<PathBuf>, maintenance: bool) -> Result<(), Box<dyn Error>> {
    let executable = std::env::current_exe()?;
    let directory = executable
        .parent()
        .ok_or_else(|| probe_error("this executable has no package directory"))?;
    let daemon = directory.join("evertraced");
    let expected = format!("evertraced {}", env!("CARGO_PKG_VERSION"));
    if probe(&daemon).await? != expected {
        return Err(probe_error(&format!(
            "it does not report `{expected}` for --version"
        )));
    }
    let mut command = Command::new(&daemon);
    if let Some(config) = config {
        command.arg("--config").arg(config);
    }
    if maintenance {
        command.arg("--maintenance");
    }
    // exec returns only when replacement fails; daemon exits belong to the
    // replaced process rather than this launcher's error handler.
    Err(probe_error(&format!(
        "replacing this process failed ({})",
        command.exec().kind()
    )))
}
