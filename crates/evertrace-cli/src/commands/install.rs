use std::{env, error::Error, path::PathBuf};

pub async fn run(
    config: Option<PathBuf>,
    host_executable: Option<PathBuf>,
    live_canary: bool,
) -> Result<(), Box<dyn Error>> {
    let uninstall = host_executable.is_none();
    if host_executable
        .as_ref()
        .is_some_and(|path| !path.is_absolute())
    {
        return Err("Codex executable must be an explicit absolute path".into());
    }
    let config = std::path::absolute(crate::resolve_config_path(config)?)?;
    let effective = if config.try_exists()? {
        super::config::load(Some(config.clone()))?
    } else {
        evertrace_domain::config::EffectiveConfig::default()
    };
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME unavailable")?;
    let host = env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".codex"));
    let configuration = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let cli = env::current_exe()?;
    let package = cli
        .parent()
        .ok_or("installation package directory unavailable")?;
    let paths = evertrace_codex::install::ManagedInstallPaths {
        data_root: evertrace_protocol::resolve_data_dir(
            &effective.config().runtime.data_dir,
            Some(&home),
            |name| env::var_os(name),
        )?,
        host_config: std::path::absolute(host.join("config.toml"))?,
        unit: std::path::absolute(configuration.join("systemd/user/evertraced.service"))?,
        hook: package.join("evertrace-hook"),
        daemon: package.join("evertraced"),
        cli,
        config,
        systemctl: PathBuf::from("/usr/bin/systemctl"),
        host_executable: host_executable.unwrap_or_default(),
    };
    let result = evertrace_engine::maintenance::install_offline(&paths, uninstall)?;
    println!(
        "{}: hook={} systemd_available={}",
        if uninstall { "uninstall" } else { "install" },
        if uninstall {
            "unwired"
        } else {
            "wired_unobserved; review /hooks trust"
        },
        result.service_available
    );
    if !result.service_available {
        println!(
            "manual daemon command (service not managed): {}",
            result.manual_command
        );
    }
    if result.host_hooks_enabled == Some(false) {
        println!("hook=disabled_by_host; installation did not change host policy");
    }
    for backup in result.backups {
        println!("config_backup={}", backup.display());
    }
    println!("data_preserved={}", paths.data_root.display());
    if !uninstall && !live_canary {
        println!("host_canary=not_run: explicit --live-canary or doctor --refresh-host required");
    }
    if !uninstall && live_canary {
        crate::daemon_client::explain_live_host();
        let socket = paths.data_root.join("runtime/evertraced-v1.sock");
        match crate::daemon_client::health(&socket).await {
            Ok(_) => match crate::daemon_client::run_host_canary(
                &socket,
                &paths.host_executable,
                &paths.host_config,
            )
            .await
            {
                Ok(result) => {
                    println!("host_canary={result:?}; independent capability gates unchanged")
                }
                Err(error) => println!("host_canary=unavailable: {error}; installation preserved"),
            },
            Err(_) => println!("host_canary=not_run: daemon unavailable; installation preserved"),
        }
    }
    Ok(())
}
