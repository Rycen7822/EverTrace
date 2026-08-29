use std::{ffi::OsString, path::PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Args {
    pub config: Option<PathBuf>,
    pub command: Command,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    ConfigCheck,
    ConfigShowEffective,
    Doctor,
    Mcp,
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
        let command = if command == "doctor" {
            Command::Doctor
        } else if command == "mcp" {
            Command::Mcp
        } else if command == "config" {
            match values.next().as_deref().and_then(|value| value.to_str()) {
                Some("check") => Command::ConfigCheck,
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
    "usage: evertrace [--config PATH] config check|config show --effective|doctor|mcp"
}
