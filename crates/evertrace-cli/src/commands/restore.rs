use std::{env, error::Error, path::PathBuf};

pub async fn upgrade(
    config: Option<PathBuf>,
    check_package: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let config_path = std::path::absolute(crate::resolve_config_path(config)?)?;
    let effective = super::config::load(Some(config_path.clone()))?;
    let home = env::var_os("HOME").map(PathBuf::from);
    let data_dir = evertrace_protocol::resolve_data_dir(
        &effective.config().runtime.data_dir,
        home.as_deref(),
        |name| env::var_os(name),
    )?;
    if let Some(package) = check_package {
        if !package.is_absolute() {
            return Err("candidate package directory must be absolute".into());
        }
        let home = home.as_ref().ok_or("HOME unavailable")?;
        let host = env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".codex"));
        let configuration = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        let checked = evertrace_engine::maintenance::check_package_upgrade(
            &data_dir,
            &config_path,
            &std::path::absolute(host.join("config.toml"))?,
            &std::path::absolute(configuration.join("systemd/user/evertraced.service"))?,
            &package,
            |socket| async move {
                crate::daemon_client::health(&socket)
                    .await
                    .is_ok_and(|health| health.validate())
            },
        )
        .await?;
        println!(
            "scope=package_prepublication check=not-ready native_prepared=true migrated={} materials_validated={} candidate_native_verified={} candidate_daemon_verified={} host_verified=false generation={:?} backup={} candidate_removed=true",
            checked.migrated,
            checked.materials_validated,
            checked.candidate_native_verified,
            checked.candidate_daemon_verified,
            checked.generation,
            checked.backup.display()
        );
        return Err(if checked.materials_validated {
            "not-ready: candidate Host proof unavailable"
        } else {
            "not-ready: candidate package material validation failed"
        }
        .into());
    }
    println!("scope=native_store");
    use evertrace_store::restore::NativeUpgradeOutcome;
    match evertrace_engine::maintenance::upgrade_offline(&data_dir, &config_path).await? {
        NativeUpgradeOutcome::Empty => println!("upgrade=noop reason=empty_store"),
        NativeUpgradeOutcome::Noop { retained_native } => {
            println!("upgrade=noop profile=L0002");
            for path in retained_native {
                println!("retained_native={}", path.display());
            }
        }
        NativeUpgradeOutcome::Published {
            backup,
            migrated,
            retained_native,
        } => {
            println!(
                "upgrade={} profile=L0002 backup={}",
                if migrated {
                    "L0001_to_L0002"
                } else {
                    "layout_converted"
                },
                backup.display()
            );
            for path in retained_native {
                println!("retained_native={}", path.display());
            }
        }
    }
    Ok(())
}

pub async fn run(config: Option<PathBuf>, backup: PathBuf) -> Result<(), Box<dyn Error>> {
    let config_path = std::path::absolute(crate::resolve_config_path(config)?)?;
    let backup = std::path::absolute(backup)?;
    let effective = super::config::load(Some(config_path.clone()))?;
    let home = env::var_os("HOME").map(PathBuf::from);
    let data_dir = evertrace_protocol::resolve_data_dir(
        &effective.config().runtime.data_dir,
        home.as_deref(),
        |name| env::var_os(name),
    )?;
    // The package source is the explicit sibling of this running installation,
    // never PATH resolution or an executable recovered from the backup.
    let executable = env::current_exe()?;
    let hook = executable
        .parent()
        .ok_or("invalid installation directory")?
        .join("evertrace-hook");
    match evertrace_engine::maintenance::restore_offline(
        &data_dir,
        &config_path,
        &backup,
        &hook,
        effective.hash(),
    )
    .await?
    {
        evertrace_engine::maintenance::OfflineRestoreOutcome::Historical { directory } => {
            println!(
                "historical_only={} reason=current_deletion_ledger_unavailable",
                directory.display()
            );
        }
        evertrace_engine::maintenance::OfflineRestoreOutcome::Activated(result) => {
            println!(
                "restored={} previous_root={}",
                data_dir.display(),
                result.rollback_root.display()
            );
            if let Some(path) = result.retained_config_backup {
                println!("retained_config_backup={}", path.display());
            }
            if let Some(path) = result.retained_candidate_fence {
                println!("retained_candidate_fence={}", path.display());
            }
        }
    }
    Ok(())
}
