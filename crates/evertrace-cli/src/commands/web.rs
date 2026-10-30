use evertrace_domain::{evidence::hex, ids::RequestId};
use evertrace_protocol::{
    LocalClient, command::Command as WireCommand, dto::ClientKind, response::Response,
};
use std::{
    env,
    error::Error,
    fs,
    io::Write,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

fn component_error() -> Box<dyn Error> {
    "optional Python Web component is missing or unsafe; explicitly assemble the matching component for this package (no automatic installation)".into()
}

fn component(directory: &Path) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let owner = fs::metadata(env::current_exe()?)?.uid();
    let root = directory.parent().ok_or_else(component_error)?;
    let environment = root.join("webui");
    let bin = environment.join("bin");
    for path in [root, &environment, &bin] {
        let info = fs::symlink_metadata(path).map_err(|_| component_error())?;
        if !info.is_dir() || info.uid() != owner || info.permissions().mode() & 0o022 != 0 {
            return Err(component_error());
        }
    }
    let entry = bin.join("evertrace-web");
    let info = fs::symlink_metadata(&entry).map_err(|_| component_error())?;
    if !info.is_file() || info.uid() != owner || info.permissions().mode() & 0o022 != 0 {
        return Err(component_error());
    }
    // A venv interpreter may point at the explicitly selected, root/user-owned
    // base Python. There is no PATH search or runtime interpreter fallback.
    let python = bin.join("python");
    let info = fs::metadata(&python).map_err(|_| component_error())?;
    if !info.is_file()
        || ![0, owner].contains(&info.uid())
        || info.permissions().mode() & 0o6022 != 0
        || info.permissions().mode() & 0o111 == 0
    {
        return Err(component_error());
    }
    Ok((python, entry))
}

pub async fn run(config: Option<PathBuf>, port: u16) -> Result<(), Box<dyn Error>> {
    let effective = super::config::load(config)?;
    let data = evertrace_protocol::resolve_data_dir(
        &effective.config().runtime.data_dir,
        env::var_os("HOME").as_deref().map(Path::new),
        |name| env::var_os(name),
    )?;
    let socket = data.join("runtime/evertraced-v1.sock");
    let config_hash = hex(&effective.hash());
    let health = tokio::time::timeout(Duration::from_secs(5), async {
        let mut client = LocalClient::connect(
            &socket,
            env!("CARGO_PKG_VERSION"),
            ClientKind::Web,
            Duration::from_secs(5),
        )
        .await?;
        client
            .request(RequestId::new_v7(), WireCommand::Health)
            .await
    })
    .await
    .map_err(
        |_| "daemon preflight exceeded 5 seconds; start the matching evertrace --daemon first",
    )?
    .map_err(|_| "cannot connect to the matching private daemon; start evertrace --daemon first")?;
    match health {
        Response::Health(health)
            if health.validate() && health.effective_config_hash == config_hash => {}
        _ => {
            return Err(
                "daemon mode/configuration does not match the selected configuration".into(),
            );
        }
    }
    let executable = env::current_exe()?;
    let directory = executable.parent().ok_or_else(component_error)?;
    let (python, entry) = component(directory)?;
    let mut probe = tokio::process::Command::new(&python);
    probe.arg("-I").arg("-B").arg(&entry);
    super::companion::probe(
        probe,
        &format!("evertrace-web {}", env!("CARGO_PKG_VERSION")),
    )
    .await
    .map_err(|error| format!("optional Python Web component is unavailable: {error}"))?;
    let descriptor = serde_json::to_vec(&serde_json::json!({
        "socket": socket,
        "config_hash": config_hash,
        "build_id": env!("CARGO_PKG_VERSION"),
    }))?;
    // Linux pipe capacity is at least PIPE_BUF (4096). Write before exec only
    // within that bound; close the writer so Python observes EOF immediately.
    if descriptor.len() > 4096 {
        return Err("Web startup context exceeds 4096 bytes".into());
    }
    let (reader, mut writer) = std::io::pipe()?;
    writer.write_all(&descriptor)?;
    drop(writer);
    let error = Command::new(python)
        .arg("-I")
        .arg("-B")
        .arg(entry)
        .arg("--startup-stdin")
        .arg("--port")
        .arg(port.to_string())
        .env_clear()
        .current_dir(directory)
        .stdin(Stdio::from(reader))
        .exec();
    Err(format!(
        "replacing launcher with Python Web failed ({})",
        error.kind()
    )
    .into())
}
