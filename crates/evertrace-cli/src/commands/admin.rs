use std::{env, error::Error, path::PathBuf};

use evertrace_protocol::{
    command::SessionImportAdminAction, resolve_data_dir, response::SessionImportAdminResponse,
};

use crate::{args::AdminSessionAction, commands::config, daemon_client};

pub async fn run(
    config_path: Option<PathBuf>,
    action: AdminSessionAction,
    session_id: String,
) -> Result<(), Box<dyn Error>> {
    let effective = config::load(config_path)?;
    let home = env::var_os("HOME").map(PathBuf::from);
    let data_dir = resolve_data_dir(
        &effective.config().runtime.data_dir,
        home.as_deref(),
        |name| env::var_os(name),
    )?;
    let action = match action {
        AdminSessionAction::Queue => SessionImportAdminAction::QueueImport,
        AdminSessionAction::Revoke => SessionImportAdminAction::RevokeAccess,
    };
    let response = daemon_client::session_import_admin(
        &data_dir.join("runtime/evertraced-v1.sock"),
        session_id,
        action,
    )
    .await?;
    println!(
        "{}",
        match response {
            SessionImportAdminResponse::Queued => "queued",
            SessionImportAdminResponse::Revoked => "revoked",
            SessionImportAdminResponse::NoDelta => "no_delta",
        }
    );
    Ok(())
}
