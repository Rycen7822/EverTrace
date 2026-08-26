use std::{error::Error, fs, path::PathBuf};

use evertrace_domain::config::EffectiveConfig;

use crate::resolve_config_path;

pub fn check(config: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    let _ = load(config)?;
    println!("configuration is valid");
    Ok(())
}

pub fn show_effective(config: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    let effective = load(config)?;
    print!("{}", effective.to_toml()?);
    Ok(())
}

pub fn load(config: Option<PathBuf>) -> Result<EffectiveConfig, Box<dyn Error>> {
    let path = resolve_config_path(config)?;
    let source = fs::read_to_string(path)?;
    Ok(EffectiveConfig::parse_toml(&source)?)
}
