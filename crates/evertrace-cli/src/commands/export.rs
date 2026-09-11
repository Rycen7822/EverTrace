use evertrace_domain::ids::RequestId;
use evertrace_protocol::{
    LocalClient,
    command::Command,
    dto::{
        ClientKind, HumanExportSelection, HumanExportStatus, HumanGovernanceRequest,
        HumanGovernanceResponse,
    },
    resolve_data_dir,
    response::Response,
};
use std::{env, error::Error, path::PathBuf, time::Duration};

pub async fn run(config: Option<PathBuf>, refs: Vec<String>) -> Result<(), Box<dyn Error>> {
    let effective = super::config::load(config)?;
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
        Duration::from_secs(35),
    )
    .await?;
    let request = HumanGovernanceRequest::Export {
        selections: refs
            .into_iter()
            .map(|object_ref| HumanExportSelection {
                object_ref,
                expected_revision_ref: None,
            })
            .collect(),
    };
    if !request.validate() {
        return Err("invalid export selection".into());
    }
    let response = client
        .request(RequestId::new_v7(), Command::HumanGovernance(request))
        .await
        .map_err(|error| {
            format!(
                "export outcome unknown; inspect {} before retrying: {error}",
                data.join("exports").display()
            )
        })?;
    match response {
        Response::HumanGovernance(HumanGovernanceResponse::Export { result }) => {
            println!("{}", serde_json::to_string(&result)?);
            if result.status == HumanExportStatus::Published {
                Ok(())
            } else {
                Err("export did not report durable publication; inspect the reported result before retrying".into())
            }
        }
        _ => Err("export outcome unknown; inspect exports before retrying".into()),
    }
}
