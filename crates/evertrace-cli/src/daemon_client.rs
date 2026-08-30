use std::{path::Path, time::Duration};

use evertrace_domain::ids::RequestId;
use evertrace_protocol::{
    LocalClient,
    command::{Command, SessionImportAdminAction, SessionImportAdminCommand},
    dto::ClientKind,
    error::ProtocolError,
    request_health,
    response::{HealthResponse, Response, SessionImportAdminResponse},
};

pub async fn health(socket: &Path) -> Result<HealthResponse, ProtocolError> {
    request_health(socket, env!("CARGO_PKG_VERSION"), Duration::from_secs(2)).await
}

pub async fn session_import_admin(
    socket: &Path,
    session_id: String,
    action: SessionImportAdminAction,
) -> Result<SessionImportAdminResponse, ProtocolError> {
    let mut client = LocalClient::connect(
        socket,
        env!("CARGO_PKG_VERSION"),
        ClientKind::Cli,
        Duration::from_secs(2),
    )
    .await?;
    let request_id = RequestId::new_v7();
    match client
        .request(
            request_id,
            Command::SessionImportAdmin(SessionImportAdminCommand { session_id, action }),
        )
        .await?
    {
        Response::SessionImportAdmin(response) => Ok(response),
        _ => Err(ProtocolError::UnexpectedMessage),
    }
}
