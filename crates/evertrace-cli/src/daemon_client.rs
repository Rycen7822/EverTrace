use std::{path::Path, time::Duration};

use evertrace_protocol::{error::ProtocolError, request_health, response::HealthResponse};

pub async fn health(socket: &Path) -> Result<HealthResponse, ProtocolError> {
    request_health(socket, env!("CARGO_PKG_VERSION"), Duration::from_secs(2)).await
}
