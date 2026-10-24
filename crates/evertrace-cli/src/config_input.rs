use std::{env, error::Error, fs, path::PathBuf};

use evertrace_domain::config::EffectiveConfig;

pub(crate) fn resolve_config_path(explicit: Option<PathBuf>) -> Result<PathBuf, &'static str> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Some(path) = env::var_os("EVERTRACE_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".evertrace/config.toml"))
        .ok_or("HOME unavailable for default EverTrace configuration")
}

pub fn load(config: Option<PathBuf>) -> Result<EffectiveConfig, Box<dyn Error>> {
    let path = resolve_config_path(config)?;
    let source = fs::read_to_string(path)?;
    Ok(EffectiveConfig::parse_toml(&source)?)
}
