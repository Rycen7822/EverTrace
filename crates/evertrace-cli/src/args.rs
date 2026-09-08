use std::{ffi::OsString, path::PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Args {
    pub config: Option<PathBuf>,
    pub command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
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
    },
    Install {
        host_executable: PathBuf,
        live_canary: bool,
    },
    Uninstall,
    Restore {
        backup: PathBuf,
    },
    Mcp,
    Tui,
    AdminSession {
        action: AdminSessionAction,
        session_id: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminSessionAction {
    Queue,
    Revoke,
}

impl Args {
    pub fn parse(mut values: impl Iterator<Item = OsString>) -> Result<Self, &'static str> {
        let mut config = None;
        let first = values.next().ok_or(usage())?;
        let command = if first == "--config" {
            config = Some(PathBuf::from(
                values.next().ok_or("--config requires a path")?,
            ));
            values.next().ok_or(usage())?
        } else {
            first
        };
        let command = if command == "restore" {
            Command::Restore {
                backup: PathBuf::from(values.next().ok_or("restore requires a backup path")?),
            }
        } else if command == "upgrade" {
            let check_package = match values.next() {
                None => None,
                Some(flag) if flag == "--check" => {
                    Some(PathBuf::from(values.next().ok_or(
                        "upgrade --check requires an explicit package directory",
                    )?))
                }
                Some(_) => return Err(usage()),
            };
            let live_host = if check_package.is_some() {
                match values.next() {
                    None => None,
                    Some(flag) if flag == "--live-host" => {
                        Some(PathBuf::from(values.next().ok_or(usage())?))
                    }
                    _ => return Err(usage()),
                }
            } else {
                None
            };
            Command::Upgrade {
                check_package,
                live_host,
            }
        } else if command == "install" {
            Command::Install {
                host_executable: PathBuf::from(
                    values
                        .next()
                        .ok_or("install requires an absolute Codex executable path")?,
                ),
                live_canary: match values.next() {
                    None => false,
                    Some(flag) if flag == "--live-canary" => true,
                    _ => return Err(usage()),
                },
            }
        } else if command == "uninstall" {
            Command::Uninstall
        } else if command == "doctor" {
            Command::Doctor {
                refresh_host: match values.next() {
                    None => None,
                    Some(flag) if flag == "--refresh-host" => {
                        Some(PathBuf::from(values.next().ok_or(usage())?))
                    }
                    _ => return Err(usage()),
                },
            }
        } else if command == "mcp" {
            Command::Mcp
        } else if command == "tui" {
            Command::Tui
        } else if command == "admin" {
            if values.next().as_deref() != Some(std::ffi::OsStr::new("session")) {
                return Err(usage());
            }
            let action = match values.next().as_deref().and_then(|value| value.to_str()) {
                Some("queue") => AdminSessionAction::Queue,
                Some("revoke") => AdminSessionAction::Revoke,
                _ => return Err(usage()),
            };
            let session_id = values
                .next()
                .and_then(|value| value.into_string().ok())
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 256
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
                        })
                })
                .ok_or(usage())?;
            Command::AdminSession { action, session_id }
        } else if command == "config" {
            match values.next().as_deref().and_then(|value| value.to_str()) {
                Some("check") => Command::ConfigCheck,
                Some("reload") => {
                    let socket = match values.next() {
                        None => None,
                        Some(flag) if flag == "--socket" => {
                            let path = PathBuf::from(values.next().ok_or(usage())?);
                            if !path.is_absolute() {
                                return Err(usage());
                            }
                            Some(path)
                        }
                        _ => return Err(usage()),
                    };
                    Command::ConfigReload { socket }
                }
                Some("show")
                    if values.next().as_deref() == Some(std::ffi::OsStr::new("--effective")) =>
                {
                    Command::ConfigShowEffective
                }
                _ => return Err(usage()),
            }
        } else {
            return Err(usage());
        };
        if values.next().is_some() {
            return Err(usage());
        }
        Ok(Self { config, command })
    }
}

const fn usage() -> &'static str {
    "usage: evertrace [--config PATH] config check|config show --effective|restore BACKUP_PATH|upgrade [--check PACKAGE_DIRECTORY [--live-host CODEX_EXECUTABLE]]|install CODEX_EXECUTABLE [--live-canary]|uninstall|doctor [--refresh-host CODEX_EXECUTABLE]|mcp|tui|admin session queue|revoke SESSION_ID"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_lifecycle_requires_an_explicit_live_option() {
        let parse = |args: &[&str]| Args::parse(args.iter().map(OsString::from));
        assert!(matches!(
            parse(&["install", "/host"]).unwrap().command,
            Command::Install {
                live_canary: false,
                ..
            }
        ));
        assert!(matches!(
            parse(&["install", "/host", "--live-canary"])
                .unwrap()
                .command,
            Command::Install {
                live_canary: true,
                ..
            }
        ));
        assert!(matches!(
            parse(&["upgrade", "--check", "/package"]).unwrap().command,
            Command::Upgrade {
                live_host: None,
                ..
            }
        ));
        assert!(matches!(
            parse(&["upgrade", "--check", "/package", "--live-host", "/host"])
                .unwrap()
                .command,
            Command::Upgrade {
                live_host: Some(_),
                ..
            }
        ));
        assert!(parse(&["upgrade", "--live-host", "/host"]).is_err());
    }
}
