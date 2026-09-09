use std::{env, error::Error, path::PathBuf};

fn candidate_host_diagnostic(
    value: evertrace_protocol::dto::HostCanaryDiagnostic,
) -> evertrace_engine::HostCanaryDiagnostic {
    use evertrace_engine::{HostCanaryScope as TargetScope, HostCanaryStatus as Target};
    use evertrace_protocol::dto::{HostCanaryScope as Scope, HostCanaryStatus as Status};
    evertrace_engine::HostCanaryDiagnostic {
        scope: match value.scope {
            Scope::Installed => TargetScope::Installed,
            Scope::Candidate {
                check_id,
                generation,
            } => TargetScope::Candidate {
                check_id,
                generation,
            },
        },
        status: match value.status {
            Status::NotRun => Target::NotRun,
            Status::Running => Target::Running,
            Status::Unavailable => Target::Unavailable,
            Status::BudgetExceeded => Target::BudgetExceeded,
            Status::EvidenceMissing => Target::EvidenceMissing,
            Status::TimedOut => Target::TimedOut,
            Status::IdentityChanged => Target::IdentityChanged,
            Status::Interrupted => Target::Interrupted,
            Status::Observed => Target::Observed,
        },
        native_delivery_observed: value.native_delivery_observed,
        mcp_claim_consumed: value.mcp_claim_consumed,
        capture_receipt_observed: value.capture_receipt_observed,
        qualification: value
            .qualification
            .and_then(|value| serde_json::from_value(serde_json::to_value(value).ok()?).ok()),
    }
}

pub async fn upgrade(
    config: Option<PathBuf>,
    check_package: Option<PathBuf>,
    live_host: Option<PathBuf>,
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
        if live_host.as_ref().is_some_and(|path| !path.is_absolute()) {
            return Err("live Host executable must be absolute".into());
        }
        let host_config = std::path::absolute(host.join("config.toml"))?;
        if live_host.is_some() {
            crate::daemon_client::explain_live_host();
        }
        let checked = evertrace_engine::maintenance::check_package_upgrade(
            &data_dir,
            &config_path,
            &host_config,
            &std::path::absolute(configuration.join("systemd/user/evertraced.service"))?,
            &package,
            |socket| async move {
                crate::daemon_client::health(&socket)
                    .await
                    .is_ok_and(|health| health.validate())
            },
            (
                live_host.map(|path| evertrace_engine::HostCanaryRequest {
                    host_executable: path.to_string_lossy().into_owned(),
                    host_config: host_config.to_string_lossy().into_owned(),
                }),
                |socket, request| async move {
                    crate::daemon_client::run_host_canary(
                        &socket,
                        std::path::Path::new(&request.host_executable),
                        std::path::Path::new(&request.host_config),
                    )
                    .await
                    .ok()
                    .map(candidate_host_diagnostic)
                },
            ),
        )
        .await?;
        println!(
            "candidate_host={:?}; package_publication=not_implemented",
            checked.candidate_host
        );
        println!(
            "scope=package_prepublication check=not-ready native_prepared=true migrated={} materials_validated={} candidate_native_verified={} candidate_daemon_verified={} host_verified={} generation={:?} backup={} candidate_removed=true",
            checked.migrated,
            checked.materials_validated,
            checked.candidate_native_verified,
            checked.candidate_daemon_verified,
            checked
                .candidate_host
                .as_ref()
                .is_some_and(evertrace_engine::HostCanaryDiagnostic::installed_path_observed),
            checked.generation,
            checked.backup.display()
        );
        return Err(if checked
            .candidate_host
            .as_ref()
            .is_some_and(evertrace_engine::HostCanaryDiagnostic::installed_path_observed)
        {
            "not-ready: package publication is not implemented"
        } else if checked.materials_validated {
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
