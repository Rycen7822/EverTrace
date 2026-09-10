use std::{env, error::Error, path::PathBuf};

use evertrace_protocol::{
    command::SessionImportAdminAction, resolve_data_dir, response::SessionImportAdminResponse,
};

use crate::{args::AdminSessionAction, commands::config, daemon_client};

pub async fn repository(
    config_path: Option<PathBuf>,
    action: evertrace_protocol::dto::RepositoryAccessAction,
    repository_id: evertrace_domain::ids::RepositoryId,
    expected_revision: u32,
    worktree_id: Option<evertrace_domain::ids::WorktreeId>,
    inventory_ref: Option<evertrace_domain::ids::JobId>,
) -> Result<(), Box<dyn Error>> {
    use evertrace_domain::ids::RequestId;
    use evertrace_protocol::{
        LocalClient,
        command::Command,
        dto::{
            ClientKind, HumanActionRequest, HumanGovernanceRequest, HumanGovernanceResponse,
            HumanReadRequest, HumanSurface,
        },
        response::Response,
    };
    let effective = config::load(config_path)?;
    let home = env::var_os("HOME").map(PathBuf::from);
    let data = resolve_data_dir(
        &effective.config().runtime.data_dir,
        home.as_deref(),
        |name| env::var_os(name),
    )?;
    let mut client = LocalClient::connect(
        &data.join("runtime/evertraced-v1.sock"),
        env!("CARGO_PKG_VERSION"),
        ClientKind::Cli,
        std::time::Duration::from_secs(10),
    )
    .await?;
    let frontier = match client
        .request(
            RequestId::new_v7(),
            Command::HumanGovernance(HumanGovernanceRequest::Read {
                request: HumanReadRequest::List {
                    surface: HumanSurface::System,
                    expected_frontier: None,
                    after: None,
                    limit: 1,
                },
            }),
        )
        .await?
    {
        Response::HumanGovernance(HumanGovernanceResponse::Snapshot { frontier, .. }) => frontier,
        _ => return Err("repository state unavailable".into()),
    };
    let result = client
        .request(
            RequestId::new_v7(),
            Command::HumanGovernance(HumanGovernanceRequest::Act {
                expected_frontier: frontier,
                action: HumanActionRequest::RepositoryAccess {
                    repository_id,
                    expected_repository_revision: expected_revision,
                    action,
                    worktree_id,
                    inventory_ref,
                },
            }),
        )
        .await?;
    match result {
        Response::HumanGovernance(HumanGovernanceResponse::Action { result }) => {
            println!("{}", serde_json::to_string(&result)?);
            if !matches!(
                result.status,
                evertrace_protocol::dto::HumanActionStatus::Applied
                    | evertrace_protocol::dto::HumanActionStatus::NoDelta
            ) {
                return Err("repository operation was not admitted".into());
            }
        }
        _ => return Err("repository operation conflicted; refresh its exact revision".into()),
    }
    Ok(())
}

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
            SessionImportAdminResponse::Queued => "queued".to_owned(),
            SessionImportAdminResponse::Revoked => "revoked".to_owned(),
            SessionImportAdminResponse::NoDelta => "no_delta".to_owned(),
            SessionImportAdminResponse::Partial {
                changed,
                unavailable,
                remaining,
            } => format!(
                "partial changed={changed} unavailable={unavailable} remaining={remaining}; inspect source rows before retry"
            ),
        }
    );
    Ok(())
}
