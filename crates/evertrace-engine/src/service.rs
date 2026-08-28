use evertrace_domain::{config::EffectiveConfig, revision::AlgorithmRevision};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMode {
    Normal,
    Maintenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    pub mode: RuntimeMode,
    pub config_version: u32,
    pub effective_config_hash: [u8; 32],
    pub algorithm_revision: u32,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HealthDispatchError {
    #[error("maintenance mode")]
    MaintenanceMode,
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("invalid configuration")]
    InvalidConfiguration,
}

#[derive(Clone, Debug)]
pub struct EngineService {
    config: EffectiveConfig,
    mode: RuntimeMode,
}

impl EngineService {
    pub const fn new(config: EffectiveConfig, mode: RuntimeMode) -> Self {
        Self { config, mode }
    }

    pub fn from_toml(input: &str, mode: RuntimeMode) -> Result<Self, EngineError> {
        EffectiveConfig::parse_toml(input)
            .map(|config| Self::new(config, mode))
            .map_err(|_| EngineError::InvalidConfiguration)
    }

    pub fn data_dir(&self) -> &str {
        &self.config.config().runtime.data_dir
    }

    pub const fn effective_config(&self) -> &EffectiveConfig {
        &self.config
    }

    pub fn health(&self) -> Result<HealthSnapshot, HealthDispatchError> {
        if self.mode == RuntimeMode::Maintenance {
            return Err(HealthDispatchError::MaintenanceMode);
        }
        Ok(HealthSnapshot {
            mode: self.mode,
            config_version: self.config.config().config_version,
            effective_config_hash: self.config.hash(),
            algorithm_revision: AlgorithmRevision::V1.version(),
        })
    }
}
