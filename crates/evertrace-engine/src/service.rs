use evertrace_domain::{config::EffectiveConfig, revision::AlgorithmRevision};
pub use evertrace_store::{ConfigReloadAudit, ConfigReloadOutcome, ConfigReloadSource};
use std::sync::{Arc, RwLock};
use thiserror::Error;

mod actions;
mod binding;
mod human_governance;
mod scope;
pub use actions::*;
pub use binding::*;
pub use human_governance::*;
pub use scope::McpQueryAnchor;

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
    config: Arc<RwLock<Arc<OperationConfig>>>,
    mode: RuntimeMode,
}

pub(crate) struct OperationConfig {
    pub effective: Arc<EffectiveConfig>,
    pub synthesis: crate::SynthesisPlanner,
}

impl std::fmt::Debug for OperationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperationConfig")
            .field("effective", &self.effective)
            .finish_non_exhaustive()
    }
}

impl EngineService {
    pub fn new(config: EffectiveConfig, mode: RuntimeMode) -> Self {
        let synthesis = crate::SynthesisPlanner::new(config.config().llm.clone());
        Self {
            config: Arc::new(RwLock::new(Arc::new(OperationConfig {
                effective: Arc::new(config),
                synthesis,
            }))),
            mode,
        }
    }

    pub fn from_toml(input: &str, mode: RuntimeMode) -> Result<Self, EngineError> {
        EffectiveConfig::parse_toml(input)
            .map(|config| Self::new(config, mode))
            .map_err(|_| EngineError::InvalidConfiguration)
    }

    pub fn data_dir(&self) -> String {
        self.effective_config().config().runtime.data_dir.clone()
    }

    pub fn effective_config(&self) -> Arc<EffectiveConfig> {
        Arc::clone(&self.operation_config().effective)
    }

    pub fn synthesis_planner(&self) -> crate::SynthesisPlanner {
        self.operation_config().synthesis.clone()
    }

    pub(crate) fn operation_config(&self) -> Arc<OperationConfig> {
        Arc::clone(
            &self
                .config
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub(crate) fn prepare_config(
        &self,
        effective: Arc<EffectiveConfig>,
    ) -> Result<Arc<OperationConfig>, EngineError> {
        let synthesis = self
            .operation_config()
            .synthesis
            .reconfigured(effective.config().llm.clone())
            .map_err(|_| EngineError::InvalidConfiguration)?;
        Ok(Arc::new(OperationConfig {
            effective,
            synthesis,
        }))
    }

    pub(crate) fn apply_config(&self, config: Arc<OperationConfig>) {
        *self
            .config
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = config;
    }

    pub(crate) fn finish_config_commit(&self) {
        self.operation_config().synthesis.activate_limit();
    }

    pub fn health(&self) -> Result<HealthSnapshot, HealthDispatchError> {
        if self.mode == RuntimeMode::Maintenance {
            return Err(HealthDispatchError::MaintenanceMode);
        }
        let config = self.effective_config();
        Ok(HealthSnapshot {
            mode: self.mode,
            config_version: config.config().config_version,
            effective_config_hash: config.hash(),
            algorithm_revision: AlgorithmRevision::V1.version(),
        })
    }

    pub fn log_level(&self) -> tracing::Level {
        use evertrace_domain::config::LogLevel;
        match self.effective_config().config().runtime.log_level {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }
}
