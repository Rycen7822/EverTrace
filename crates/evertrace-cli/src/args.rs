use std::{ffi::OsString, path::PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Args {
    pub config: Option<PathBuf>,
    pub command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Help,
    Daemon {
        maintenance: bool,
    },
    ConfigCheck,
    ConfigShowEffective,
    ConfigReload {
        socket: Option<PathBuf>,
    },
    Doctor {
        refresh_host: Option<PathBuf>,
    },
    Upgrade {
        check_package: Option<PathBuf>,
        live_host: Option<PathBuf>,
        commit: bool,
    },
    Install {
        host_executable: PathBuf,
        live_canary: bool,
    },
    Uninstall,
    Export {
        refs: Vec<String>,
    },
    BackupCreate,
    BackupVerify {
        backup_job_id: evertrace_domain::ids::JobId,
    },
    Restore {
        backup: PathBuf,
    },
    Mcp {
        host_locator: Option<(PathBuf, PathBuf)>,
    },
    Tui,
    AdminSession {
        action: AdminSessionAction,
        session_id: String,
    },
    AdminRepository {
        action: evertrace_protocol::dto::RepositoryAccessAction,
        repository_id: evertrace_domain::ids::RepositoryId,
        expected_revision: u32,
        worktree_id: Option<evertrace_domain::ids::WorktreeId>,
        inventory_ref: Option<evertrace_domain::ids::JobId>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminSessionAction {
    Queue,
    Revoke,
}

/// `Usage` renders the full command list; the named rejections tell a caller of
/// the retired subcommand grammar which exact top-level mode replaced it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    Usage,
    Rejected(&'static str),
    Retired(String),
}

impl ParseError {
    // Shared by both binaries; only `evertrace` renders the guide or exits with it.
    #[allow(dead_code)]
    pub fn message(self) -> String {
        match self {
            Self::Usage => usage().into(),
            Self::Rejected(message) => message.into(),
            Self::Retired(mode) => {
                format!("unsupported subcommand `{mode}`; use evertrace --{mode}")
            }
        }
    }
}

const PATH_REQUIRED: &str =
    "expected a path argument; top-level modes are mutually exclusive and never take a mode name";
const REFS_REQUIRED: &str = "--export takes 1 to 64 object refs and accepts no options";
const SOCKET_REQUIRED: &str = "--config-reload --socket requires an absolute socket path";
const RESTORE_REQUIRED: &str = "--restore requires a backup directory path";
const PACKAGE_REQUIRED: &str =
    "--upgrade requires --check PACKAGE_DIRECTORY or an explicit PACKAGE_DIRECTORY";
const ADMIN_REQUIRED: &str = "--admin requires a valid session or repository action";
const BACKUP_REQUIRED: &str = "--backup requires create or verify BACKUP_JOB_ID";
const HOST_REQUIRED: &str =
    "--install requires an absolute Host executable path; run --uninstall to remove wiring";
const MCP_LOCATOR_REQUIRED: &str = "--mcp host observation requires --host-executable ABSOLUTE_HOST_EXECUTABLE --host-config ABSOLUTE_CONFIG_PATH";

impl Args {
    pub fn parse(mut values: impl Iterator<Item = OsString>) -> Result<Self, ParseError> {
        let Some(first) = values.next() else {
            return Ok(Self {
                config: None,
                command: Command::Help,
            });
        };
        let mut config = None;
        let mode = if first == "--config" {
            config = Some(argument_path(&mut values)?);
            values.next().ok_or(ParseError::Usage)?
        } else {
            first
        };
        let command = match mode.as_encoded_bytes() {
            b"--help" => Command::Help,
            b"--daemon" => Command::Daemon {
                maintenance: trailing_flag(&mut values, "--maintenance")?,
            },
            b"--tui" => Command::Tui,
            b"--config-check" => Command::ConfigCheck,
            b"--config-show" => Command::ConfigShowEffective,
            b"--config-reload" => Command::ConfigReload {
                socket: match values.next() {
                    None => None,
                    Some(flag) if flag == "--socket" => {
                        let path = match argument_path(&mut values) {
                            Ok(path) if path.is_absolute() => path,
                            _ => return Err(ParseError::Rejected(SOCKET_REQUIRED)),
                        };
                        Some(path)
                    }
                    _ => return Err(ParseError::Usage),
                },
            },
            b"--doctor" => Command::Doctor {
                refresh_host: match values.next() {
                    None => None,
                    Some(flag) if flag == "--refresh-host" => Some(argument_path(&mut values)?),
                    _ => return Err(ParseError::Usage),
                },
            },
            b"--install" => Command::Install {
                host_executable: argument_path(&mut values).map_err(|error| match error {
                    ParseError::Usage => ParseError::Rejected(HOST_REQUIRED),
                    other => other,
                })?,
                live_canary: trailing_flag(&mut values, "--live-canary")?,
            },
            b"--uninstall" => Command::Uninstall,
            b"--upgrade" => parse_upgrade(&mut values)?,
            b"--backup" => match values.next().as_deref().and_then(|value| value.to_str()) {
                Some("create") => Command::BackupCreate,
                Some("verify") => Command::BackupVerify {
                    backup_job_id: values
                        .next()
                        .and_then(|value| value.into_string().ok())
                        .and_then(|value| value.parse().ok())
                        .ok_or(ParseError::Rejected(BACKUP_REQUIRED))?,
                },
                _ => return Err(ParseError::Rejected(BACKUP_REQUIRED)),
            },
            b"--restore" => Command::Restore {
                backup: argument_path(&mut values).map_err(|error| match error {
                    ParseError::Usage => ParseError::Rejected(RESTORE_REQUIRED),
                    other => other,
                })?,
            },
            b"--export" => {
                let refs = values
                    .by_ref()
                    .map(|value| match value.into_string() {
                        Ok(value) if !value.starts_with("--") => Ok(value),
                        Ok(_) => Err(ParseError::Rejected(REFS_REQUIRED)),
                        Err(_) => Err(ParseError::Rejected("--export requires UTF-8 object refs")),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if refs.is_empty() || refs.len() > 64 {
                    return Err(ParseError::Rejected(REFS_REQUIRED));
                }
                Command::Export { refs }
            }
            b"--mcp" => Command::Mcp {
                host_locator: parse_host_locator(&mut values)?,
            },
            b"--admin" => parse_admin(&mut values)?,
            b"config" => {
                return Err(ParseError::Rejected(
                    "unsupported subcommand `config`; use evertrace --config-check, evertrace --config-show or evertrace --config-reload",
                ));
            }
            b"help" | b"doctor" | b"install" | b"uninstall" | b"upgrade" | b"backup"
            | b"restore" | b"export" | b"mcp" | b"tui" | b"admin" => {
                return Err(ParseError::Retired(
                    mode.to_str().ok_or(ParseError::Usage)?.into(),
                ));
            }
            _ => return Err(ParseError::Usage),
        };
        if values.next().is_some() {
            return Err(ParseError::Usage);
        }
        Ok(Self { config, command })
    }
}

/// A path value never absorbs a top-level mode token, so `--restore --tui` is an
/// argument error rather than a backup path. Non-UTF-8 paths stay byte-exact.
fn argument_path(values: &mut impl Iterator<Item = OsString>) -> Result<PathBuf, ParseError> {
    let value = values.next().ok_or(ParseError::Usage)?;
    if value.as_encoded_bytes().starts_with(b"--") {
        return Err(ParseError::Rejected(PATH_REQUIRED));
    }
    Ok(PathBuf::from(value))
}

fn trailing_flag(
    values: &mut impl Iterator<Item = OsString>,
    flag: &'static str,
) -> Result<bool, ParseError> {
    match values.next() {
        None => Ok(false),
        Some(value) if value == flag => Ok(true),
        _ => Err(ParseError::Usage),
    }
}

/// Check and publication keep their original qualification difference: only the
/// positional package form asks for publication, and publication needs
/// `--live-host`.
fn parse_upgrade(values: &mut impl Iterator<Item = OsString>) -> Result<Command, ParseError> {
    let mut commit = false;
    let check_package = match values.next() {
        None => None,
        Some(flag) if flag == "--check" => {
            Some(argument_path(values).map_err(|_| ParseError::Rejected(PACKAGE_REQUIRED))?)
        }
        Some(package) if !package.as_encoded_bytes().starts_with(b"-") => {
            commit = true;
            Some(PathBuf::from(package))
        }
        Some(_) => return Err(ParseError::Rejected(PACKAGE_REQUIRED)),
    };
    let live_host = if check_package.is_some() {
        match values.next() {
            None => None,
            Some(flag) if flag == "--live-host" => Some(argument_path(values)?),
            _ => return Err(ParseError::Usage),
        }
    } else {
        None
    };
    Ok(Command::Upgrade {
        check_package,
        live_host,
        commit,
    })
}

fn parse_host_locator(
    values: &mut impl Iterator<Item = OsString>,
) -> Result<Option<(PathBuf, PathBuf)>, ParseError> {
    match values.next() {
        None => Ok(None),
        Some(flag) if flag == "--host-executable" => {
            let executable =
                argument_path(values).map_err(|_| ParseError::Rejected(MCP_LOCATOR_REQUIRED))?;
            if values.next().as_deref() != Some(std::ffi::OsStr::new("--host-config")) {
                return Err(ParseError::Rejected(MCP_LOCATOR_REQUIRED));
            }
            let config =
                argument_path(values).map_err(|_| ParseError::Rejected(MCP_LOCATOR_REQUIRED))?;
            if !executable.is_absolute() || !config.is_absolute() {
                return Err(ParseError::Rejected(MCP_LOCATOR_REQUIRED));
            }
            Ok(Some((executable, config)))
        }
        _ => Err(ParseError::Rejected(MCP_LOCATOR_REQUIRED)),
    }
}

fn parse_admin(values: &mut impl Iterator<Item = OsString>) -> Result<Command, ParseError> {
    let subject = values.next().ok_or(ParseError::Rejected(ADMIN_REQUIRED))?;
    if subject == "repository" {
        let action = match values.next().as_deref().and_then(|value| value.to_str()) {
            Some("disable") => evertrace_protocol::dto::RepositoryAccessAction::Disable,
            Some("enable") => evertrace_protocol::dto::RepositoryAccessAction::Enable,
            Some("rescan") => evertrace_protocol::dto::RepositoryAccessAction::Rescan,
            _ => return Err(ParseError::Rejected(ADMIN_REQUIRED)),
        };
        let repository_id = values
            .next()
            .and_then(|value| value.into_string().ok())
            .and_then(|value| value.parse().ok())
            .ok_or(ParseError::Rejected(ADMIN_REQUIRED))?;
        let expected_revision = values
            .next()
            .and_then(|value| value.into_string().ok())
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value > 0)
            .ok_or(ParseError::Rejected(ADMIN_REQUIRED))?;
        let (worktree_id, inventory_ref) =
            if action == evertrace_protocol::dto::RepositoryAccessAction::Disable {
                (None, None)
            } else {
                let worktree = values
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .and_then(|value| value.parse().ok())
                    .ok_or(ParseError::Rejected(ADMIN_REQUIRED))?;
                let inventory = values
                    .next()
                    .map(|value| {
                        value
                            .into_string()
                            .ok()
                            .and_then(|value| value.parse().ok())
                            .ok_or(ParseError::Rejected(ADMIN_REQUIRED))
                    })
                    .transpose()?;
                (Some(worktree), inventory)
            };
        Ok(Command::AdminRepository {
            action,
            repository_id,
            expected_revision,
            worktree_id,
            inventory_ref,
        })
    } else if subject == "session" {
        let action = match values.next().as_deref().and_then(|value| value.to_str()) {
            Some("queue") => AdminSessionAction::Queue,
            Some("revoke") => AdminSessionAction::Revoke,
            _ => return Err(ParseError::Rejected(ADMIN_REQUIRED)),
        };
        let session_id = values
            .next()
            .and_then(|value| value.into_string().ok())
            .filter(|value| {
                !value.is_empty()
                    && !value.starts_with("--")
                    && value.len() <= 256
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            })
            .ok_or(ParseError::Rejected(ADMIN_REQUIRED))?;
        Ok(Command::AdminSession { action, session_id })
    } else {
        Err(ParseError::Rejected(ADMIN_REQUIRED))
    }
}

// Shared by both binaries; the standalone MCP transport never prints it.
#[allow(dead_code)]
pub const fn usage() -> &'static str {
    "usage: evertrace [--config PATH] MODE [MODE ARGUMENTS]

Top-level modes are mutually exclusive. --config PATH is accepted only before
the mode. Running without arguments prints this help; it never installs or
starts a service.

Modes:
  --help
  --daemon [--maintenance]
      Run the evertraced of this installation package in the foreground. This
      process is replaced by that program and keeps its signals and exit status.
  --tui
  --doctor [--refresh-host HOST_EXECUTABLE]
  --config-check
  --config-show
  --config-reload [--socket ABSOLUTE_SOCKET_PATH]
  --install HOST_EXECUTABLE [--live-canary]
  --uninstall
  --upgrade
      Upgrade the existing native store offline.
  --upgrade --check PACKAGE_DIRECTORY [--live-host HOST_EXECUTABLE]
  --upgrade PACKAGE_DIRECTORY --live-host HOST_EXECUTABLE
  --backup create
  --backup verify BACKUP_JOB_ID
  --restore BACKUP_PATH
  --export OBJECT_REF [OBJECT_REF ...] (1 to 64 selected current objects)
  --mcp [--host-executable ABSOLUTE_HOST_EXECUTABLE --host-config ABSOLUTE_CONFIG_PATH]
  --admin session queue|revoke SESSION_ID
  --admin repository disable REPOSITORY_ID REVISION
  --admin repository enable|rescan REPOSITORY_ID REVISION WORKTREE_ID [INVENTORY_JOB_ID]

Backup commands submit durable jobs. Exit 0 means queued, not completed.
Use evertrace --tui and inspect the job in System for its final result."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_and_backup_commands_require_exact_arguments() {
        let parse = |args: &[&str]| Args::parse(args.iter().map(OsString::from));
        assert_eq!(
            parse(&["--export", "first", "second"]).unwrap().command,
            Command::Export {
                refs: vec!["first".into(), "second".into()]
            }
        );
        assert!(parse(&["--export"]).is_err());
        assert_eq!(parse(&["--help"]).unwrap().command, Command::Help);
        assert_eq!(
            parse(&["--config", "/missing/config.toml", "--help"])
                .unwrap()
                .command,
            Command::Help
        );
        assert_eq!(
            parse(&["--backup", "create"]).unwrap().command,
            Command::BackupCreate
        );
        let backup_job_id = evertrace_domain::ids::JobId::new_v7();
        assert_eq!(
            parse(&[
                "--config",
                "/config.toml",
                "--backup",
                "verify",
                &backup_job_id.to_string()
            ])
            .unwrap(),
            Args {
                config: Some(PathBuf::from("/config.toml")),
                command: Command::BackupVerify { backup_job_id },
            }
        );
        for invalid in [
            vec!["--help", "extra"],
            vec!["--backup"],
            vec!["--backup", "create", "extra"],
            vec!["--backup", "verify"],
            vec!["--backup", "verify", "invalid"],
            vec!["--backup", "verify", &backup_job_id.to_string(), "extra"],
        ] {
            assert!(parse(&invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn host_lifecycle_requires_an_explicit_live_option() {
        let parse = |args: &[&str]| Args::parse(args.iter().map(OsString::from));
        assert!(matches!(
            parse(&["--install", "/host"]).unwrap().command,
            Command::Install {
                live_canary: false,
                ..
            }
        ));
        assert!(matches!(
            parse(&["--install", "/host", "--live-canary"])
                .unwrap()
                .command,
            Command::Install {
                live_canary: true,
                ..
            }
        ));
        assert!(matches!(
            parse(&["--upgrade", "--check", "/package"])
                .unwrap()
                .command,
            Command::Upgrade {
                live_host: None,
                ..
            }
        ));
        assert!(matches!(
            parse(&["--upgrade", "--check", "/package", "--live-host", "/host"])
                .unwrap()
                .command,
            Command::Upgrade {
                live_host: Some(_),
                ..
            }
        ));
        assert!(parse(&["--upgrade", "--live-host", "/host"]).is_err());
        assert!(matches!(
            parse(&["--upgrade", "/package", "--live-host", "/host"])
                .unwrap()
                .command,
            Command::Upgrade { commit: true, .. }
        ));
    }
}
