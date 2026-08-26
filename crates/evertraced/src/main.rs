#![forbid(unsafe_code)]
#![deny(warnings)]

use std::{env, fs, path::PathBuf, sync::Arc};

use evertrace_engine::{
    EngineService, HealthDispatchError, RuntimeMode, open_writer, spawn_writer,
};
use evertrace_protocol::{
    LocalServer, ServerOptions,
    dto::{HealthMode, PROTOCOL_VERSION},
    error::ErrorCode,
    resolve_data_dir,
    response::HealthResponse,
};
use tokio::sync::watch;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("evertraced: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = StartupArgs::parse()?;
    let config_path = config_path(args.config)?;
    let source = fs::read_to_string(config_path)?;
    let mode = if args.maintenance {
        RuntimeMode::Maintenance
    } else {
        RuntimeMode::Normal
    };
    let engine = Arc::new(EngineService::from_toml(&source, mode)?);
    let home = env::var_os("HOME").map(PathBuf::from);
    let data_dir = resolve_data_dir(engine.data_dir(), home.as_deref(), |name| env::var_os(name))?;
    let writer = open_writer(&data_dir).await?;
    let (writer_handle, mut writer_task) = spawn_writer(writer, 64)?;
    let mut writer_handle = Some(writer_handle);
    let server = match LocalServer::bind(&data_dir, ServerOptions::new(env!("CARGO_PKG_VERSION"))) {
        Ok(server) => server,
        Err(error) => {
            if let Some(handle) = writer_handle.take() {
                handle.shutdown().await?;
            }
            writer_task.await??;
            return Err(error.into());
        }
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handler_engine = Arc::clone(&engine);
    let mut task = tokio::spawn(server.run(shutdown_rx, move || {
        let snapshot = handler_engine.health().map_err(|error| match error {
            HealthDispatchError::MaintenanceMode => ErrorCode::MaintenanceMode,
        })?;
        Ok(HealthResponse {
            protocol_version: PROTOCOL_VERSION,
            mode: HealthMode::Normal,
            config_version: snapshot.config_version,
            effective_config_hash: hex(&snapshot.effective_config_hash),
            algorithm_revision: snapshot.algorithm_revision,
        })
    }));
    tokio::select! {
        result = &mut task => {
            let server_result = result;
            if let Some(handle) = writer_handle.take() {
                handle.shutdown().await?;
            }
            writer_task.await??;
            server_result??;
            Err("server stopped unexpectedly".into())
        }
        result = &mut writer_task => {
            let _ = shutdown_tx.send(true);
            task.await??;
            result??;
            Err("writer stopped unexpectedly".into())
        }
        signal = wait_for_signal() => {
            signal?;
            let _ = shutdown_tx.send(true);
            task.await??;
            if let Some(handle) = writer_handle.take() {
                handle.shutdown().await?;
            }
            writer_task.await??;
            Ok(())
        }
    }
}

struct StartupArgs {
    config: Option<PathBuf>,
    maintenance: bool,
}

impl StartupArgs {
    fn parse() -> Result<Self, &'static str> {
        let mut values = env::args_os().skip(1);
        let mut config = None;
        let mut maintenance = false;
        while let Some(value) = values.next() {
            if value == "--config" && config.is_none() {
                config = Some(PathBuf::from(
                    values.next().ok_or("--config requires a path")?,
                ));
            } else if value == "--maintenance" && !maintenance {
                maintenance = true;
            } else {
                return Err("usage: evertraced [--config PATH] [--maintenance]");
            }
        }
        Ok(Self {
            config,
            maintenance,
        })
    }
}

fn config_path(explicit: Option<PathBuf>) -> Result<PathBuf, &'static str> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Some(path) = env::var_os("EVERTRACE_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    default_config_path().ok_or("no platform configuration directory")
}

fn default_config_path() -> Option<PathBuf> {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|base| base.join("evertrace/config.toml"))
}

async fn wait_for_signal() -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
