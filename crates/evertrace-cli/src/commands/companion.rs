//! Bounded version negotiation shared by the two explicit foreground launchers.
use std::{error::Error, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, time::timeout};

fn failure(reason: &str) -> Box<dyn Error> {
    format!("package companion version check failed: {reason}").into()
}

pub(super) async fn probe(
    mut command: tokio::process::Command,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    let mut child = command
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| failure(&format!("cannot execute ({})", error.kind())))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| failure("no version output"))?;
    let result = timeout(Duration::from_secs(3), async {
        let mut output = Vec::new();
        stdout
            .take(129)
            .read_to_end(&mut output)
            .await
            .map_err(|_| failure("unreadable version output"))?;
        if output.len() > 128 {
            return Err(failure("version output exceeds 128 bytes"));
        }
        let status = child.wait().await.map_err(|_| failure("no exit status"))?;
        if !status.success() {
            return Err(failure("version probe failed"));
        }
        let text = String::from_utf8(output).map_err(|_| failure("version output is not UTF-8"))?;
        if text.trim_end_matches('\n') != expected {
            return Err(failure(&format!("expected `{expected}`")));
        }
        Ok(())
    })
    .await
    .unwrap_or_else(|_| Err(failure("version probe exceeded 3 seconds")));
    if child.id().is_some() {
        let _ = child.kill().await;
    }
    result
}
