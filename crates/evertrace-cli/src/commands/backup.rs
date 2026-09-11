use std::{env, error::Error, path::PathBuf, time::Duration};

use evertrace_domain::ids::{JobId, RequestId};
use evertrace_protocol::{
    LocalClient,
    command::Command,
    dto::{
        ClientKind, HumanActionRequest, HumanActionStatus, HumanGovernanceRequest,
        HumanGovernanceResponse, HumanReadRequest, HumanSurface,
    },
    resolve_data_dir,
    response::Response,
};

use super::config;

pub async fn run(
    config_path: Option<PathBuf>,
    backup_job_id: Option<JobId>,
) -> Result<(), Box<dyn Error>> {
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
        Duration::from_secs(10),
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
        _ => return Err("backup state unavailable; no job submitted".into()),
    };
    let request_id = RequestId::new_v7();
    let response = client
        .request(
            request_id,
            Command::HumanGovernance(HumanGovernanceRequest::Act {
                expected_frontier: frontier,
                action: match backup_job_id {
                    Some(backup_job_id) => HumanActionRequest::VerifyBackup { backup_job_id },
                    None => HumanActionRequest::CreateBackup,
                },
            }),
        )
        .await
        .map_err(|error| {
            format!(
                "backup submission outcome unknown for job {request_id}; inspect System jobs before retrying: {error}"
            )
        })?;
    match response {
        Response::HumanGovernance(HumanGovernanceResponse::Action { result })
            if result.status == HumanActionStatus::Applied =>
        {
            println!(
                "{}",
                serde_json::json!({
                    "status": "queued",
                    "job_id": result.current_revision_ref,
                    "audit_event_ref": result.audit_event_ref,
                })
            );
            eprintln!("Job queued; completion has not been checked. Inspect this job in TUI System.");
            Ok(())
        }
        Response::HumanGovernance(response) => {
            println!("{}", serde_json::to_string(&response)?);
            Err("backup operation was not queued; inspect System before submitting again".into())
        }
        _ => Err(format!(
            "unexpected backup response for job {request_id}; inspect System before submitting again"
        )
        .into()),
    }
}
