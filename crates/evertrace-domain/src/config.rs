use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use url::{Host, Url};

use crate::canonical::{self, CanonicalValue};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConfigError {
    #[error("configuration TOML is invalid")]
    InvalidToml,
    #[error("configuration cannot be serialized")]
    Serialization,
    #[error("configuration field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("configuration field is outside its allowed range: {0}")]
    OutOfRange(&'static str),
    #[error("configuration fields violate a required relation: {0}")]
    InvalidRelation(&'static str),
    #[error("configuration contains an unsupported canonical value")]
    UnsupportedCanonicalValue,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionLevel {
    Manual,
    SemiAuto,
    FullAuto,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeEnrichment {
    Off,
    Adaptive,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DurationValue(u64);

impl DurationValue {
    pub const fn from_seconds(seconds: u64) -> Option<Self> {
        if seconds == 0 {
            None
        } else {
            Some(Self(seconds))
        }
    }

    pub const fn seconds(self) -> u64 {
        self.0
    }

    fn canonical_literal(self) -> String {
        const DAY: u64 = 86_400;
        const HOUR: u64 = 3_600;
        const MINUTE: u64 = 60;
        if self.0.is_multiple_of(DAY) {
            format!("{}d", self.0 / DAY)
        } else if self.0.is_multiple_of(HOUR) {
            format!("{}h", self.0 / HOUR)
        } else if self.0.is_multiple_of(MINUTE) {
            format!("{}m", self.0 / MINUTE)
        } else {
            format!("{}s", self.0)
        }
    }
}

impl FromStr for DurationValue {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() < 2 {
            return Err(ConfigError::InvalidField("duration"));
        }
        let (digits, unit) = value.split_at(value.len() - 1);
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ConfigError::InvalidField("duration"));
        }
        let magnitude = digits
            .parse::<u64>()
            .map_err(|_| ConfigError::InvalidField("duration"))?;
        if magnitude == 0 {
            return Err(ConfigError::InvalidField("duration"));
        }
        let multiplier = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3_600,
            "d" => 86_400,
            _ => return Err(ConfigError::InvalidField("duration")),
        };
        magnitude
            .checked_mul(multiplier)
            .and_then(Self::from_seconds)
            .ok_or(ConfigError::InvalidField("duration"))
    }
}

impl Serialize for DurationValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.canonical_literal())
    }
}

impl<'de> Deserialize<'de> for DurationValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedBaseUrl(Url);

impl ValidatedBaseUrl {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let authority = value
            .split_once("://")
            .map(|(_, remainder)| remainder.split(['/', '?', '#']).next().unwrap_or_default());
        if authority.is_some_and(|authority| authority.contains('@')) {
            return Err(ConfigError::InvalidField("llm.base_url"));
        }
        let parsed = Url::parse(value).map_err(|_| ConfigError::InvalidField("llm.base_url"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ConfigError::InvalidField("llm.base_url"));
        }
        if parsed.scheme() == "http" && !is_loopback_host(&parsed) {
            return Err(ConfigError::InvalidField("llm.base_url"));
        }
        Ok(Self(parsed))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        None => false,
    }
}

impl Serialize for ValidatedBaseUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ValidatedBaseUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub config_version: u32,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub dreaming: DreamingConfig,
    #[serde(default)]
    pub procedure: ProcedureConfig,
    #[serde(default)]
    pub global_promotion: GlobalPromotionConfig,
    #[serde(default)]
    pub search: SearchConfig,
    #[serde(default)]
    pub session_import: SessionImportConfig,
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default)]
    pub recovery: RecoveryConfig,
    #[serde(default)]
    pub llm: LlmConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub data_dir: String,
    pub log_level: LogLevel,
    pub background_workers: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DreamingConfig {
    pub idle_enabled: bool,
    pub idle_after: DurationValue,
    pub integrity_sweep_interval: DurationValue,
    pub max_llm_tasks_per_run: u8,
    pub max_wall_time: DurationValue,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcedureConfig {
    pub auto_publish_full: bool,
    pub include_probationary: bool,
    pub stable_min_outcome_supported: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GlobalPromotionConfig {
    pub atom: PromotionLevel,
    pub procedure: PromotionLevel,
    pub core_membership: PromotionLevel,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SearchConfig {
    pub search_token_budget: u32,
    pub get_token_budget: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionImportConfig {
    pub historical_metadata_backfill: bool,
    pub max_concurrent_body_imports: u8,
    pub max_body_import_mib_per_run: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureConfig {
    pub preview_bytes: u32,
    pub inline_payload_bytes: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecoveryConfig {
    pub capture_timeout: DurationValue,
    pub max_bundle_mib: u32,
    pub max_untracked_file_mib: u32,
    pub max_untracked_total_mib: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LlmConfig {
    pub enabled: bool,
    pub provider: String,
    pub base_url: ValidatedBaseUrl,
    pub model: String,
    pub api_key_env: String,
    pub timeout: DurationValue,
    pub max_concurrency: u8,
    pub episode_enrichment: EpisodeEnrichment,
    pub max_episode_enrichments: u8,
    pub daily_input_token_budget: u64,
    pub daily_output_token_budget: u64,
    pub daily_call_budget: u32,
    pub daily_wall_time_budget: DurationValue,
    pub unlimited_token_budget: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            data_dir: "~/.local/share/evertrace".to_owned(),
            log_level: LogLevel::Info,
            background_workers: 2,
        }
    }
}

impl Default for DreamingConfig {
    fn default() -> Self {
        Self {
            idle_enabled: true,
            idle_after: duration("30m"),
            integrity_sweep_interval: duration("24h"),
            max_llm_tasks_per_run: 4,
            max_wall_time: duration("10m"),
        }
    }
}

impl Default for ProcedureConfig {
    fn default() -> Self {
        Self {
            auto_publish_full: true,
            include_probationary: true,
            stable_min_outcome_supported: 3,
        }
    }
}

impl Default for GlobalPromotionConfig {
    fn default() -> Self {
        Self {
            atom: PromotionLevel::SemiAuto,
            procedure: PromotionLevel::SemiAuto,
            core_membership: PromotionLevel::Manual,
        }
    }
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            search_token_budget: 600,
            get_token_budget: 1_200,
        }
    }
}

impl Default for SessionImportConfig {
    fn default() -> Self {
        Self {
            historical_metadata_backfill: true,
            max_concurrent_body_imports: 1,
            max_body_import_mib_per_run: 256,
        }
    }
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            preview_bytes: 8_192,
            inline_payload_bytes: 32_768,
        }
    }
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            capture_timeout: duration("10s"),
            max_bundle_mib: 256,
            max_untracked_file_mib: 16,
            max_untracked_total_mib: 128,
        }
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: "openai_compatible".to_owned(),
            base_url: ValidatedBaseUrl::parse("https://provider.example/v1")
                .expect("fixed default URL is valid"),
            model: "provider-model-name".to_owned(),
            api_key_env: "EVERTRACE_LLM_API_KEY".to_owned(),
            timeout: duration("90s"),
            max_concurrency: 1,
            episode_enrichment: EpisodeEnrichment::Adaptive,
            max_episode_enrichments: 2,
            daily_input_token_budget: 500_000,
            daily_output_token_budget: 100_000,
            daily_call_budget: 200,
            daily_wall_time_budget: duration("2h"),
            unlimited_token_budget: false,
        }
    }
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            config_version: 1,
            runtime: RuntimeConfig::default(),
            dreaming: DreamingConfig::default(),
            procedure: ProcedureConfig::default(),
            global_promotion: GlobalPromotionConfig::default(),
            search: SearchConfig::default(),
            session_import: SessionImportConfig::default(),
            capture: CaptureConfig::default(),
            recovery: RecoveryConfig::default(),
            llm: LlmConfig::default(),
        }
    }
}

fn duration(value: &str) -> DurationValue {
    value.parse().expect("fixed default duration is valid")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveConfig {
    config: ConfigFile,
    hash: [u8; 32],
}

impl EffectiveConfig {
    pub fn parse_toml(input: &str) -> Result<Self, ConfigError> {
        let config = toml::from_str(input).map_err(|_| ConfigError::InvalidToml)?;
        Self::new(config)
    }

    pub fn new(config: ConfigFile) -> Result<Self, ConfigError> {
        validate(&config)?;
        let hash = effective_hash(&config)?;
        Ok(Self { config, hash })
    }

    pub const fn config(&self) -> &ConfigFile {
        &self.config
    }

    pub const fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(&self.config).map_err(|_| ConfigError::Serialization)
    }
}

impl Default for EffectiveConfig {
    fn default() -> Self {
        Self::new(ConfigFile::default()).expect("fixed default configuration is valid")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeClass {
    HotReload,
    RestartRequired,
}

pub const RESTART_REQUIRED_FIELDS: [&str; 2] = ["runtime.data_dir", "runtime.background_workers"];

pub fn classify_change(field: &str) -> Option<ChangeClass> {
    if RESTART_REQUIRED_FIELDS.contains(&field) {
        return Some(ChangeClass::RestartRequired);
    }
    match field {
        "runtime.log_level"
        | "dreaming.idle_enabled"
        | "dreaming.idle_after"
        | "dreaming.integrity_sweep_interval"
        | "dreaming.max_llm_tasks_per_run"
        | "dreaming.max_wall_time"
        | "procedure.auto_publish_full"
        | "procedure.include_probationary"
        | "procedure.stable_min_outcome_supported"
        | "global_promotion.atom"
        | "global_promotion.procedure"
        | "global_promotion.core_membership"
        | "search.search_token_budget"
        | "search.get_token_budget"
        | "session_import.historical_metadata_backfill"
        | "session_import.max_concurrent_body_imports"
        | "session_import.max_body_import_mib_per_run"
        | "capture.preview_bytes"
        | "capture.inline_payload_bytes"
        | "recovery.capture_timeout"
        | "recovery.max_bundle_mib"
        | "recovery.max_untracked_file_mib"
        | "recovery.max_untracked_total_mib"
        | "llm.enabled"
        | "llm.provider"
        | "llm.base_url"
        | "llm.model"
        | "llm.api_key_env"
        | "llm.timeout"
        | "llm.max_concurrency"
        | "llm.episode_enrichment"
        | "llm.max_episode_enrichments"
        | "llm.daily_input_token_budget"
        | "llm.daily_output_token_budget"
        | "llm.daily_call_budget"
        | "llm.daily_wall_time_budget"
        | "llm.unlimited_token_budget" => Some(ChangeClass::HotReload),
        _ => None,
    }
}

fn validate(config: &ConfigFile) -> Result<(), ConfigError> {
    if config.config_version != 1 {
        return Err(ConfigError::InvalidField("config_version"));
    }
    validate_data_dir(&config.runtime.data_dir)?;
    range_u64(
        u64::from(config.runtime.background_workers),
        1,
        8,
        "runtime.background_workers",
    )?;
    range_duration(
        config.dreaming.idle_after,
        300,
        86_400,
        "dreaming.idle_after",
    )?;
    range_duration(
        config.dreaming.integrity_sweep_interval,
        3_600,
        604_800,
        "dreaming.integrity_sweep_interval",
    )?;
    range_u64(
        u64::from(config.dreaming.max_llm_tasks_per_run),
        0,
        16,
        "dreaming.max_llm_tasks_per_run",
    )?;
    range_duration(
        config.dreaming.max_wall_time,
        60,
        86_400,
        "dreaming.max_wall_time",
    )?;
    if config.procedure.stable_min_outcome_supported < 3 {
        return Err(ConfigError::OutOfRange(
            "procedure.stable_min_outcome_supported",
        ));
    }
    range_u64(
        u64::from(config.search.search_token_budget),
        0,
        1_200,
        "search.search_token_budget",
    )?;
    range_u64(
        u64::from(config.search.get_token_budget),
        0,
        2_400,
        "search.get_token_budget",
    )?;
    range_u64(
        u64::from(config.session_import.max_concurrent_body_imports),
        1,
        4,
        "session_import.max_concurrent_body_imports",
    )?;
    range_u64(
        u64::from(config.session_import.max_body_import_mib_per_run),
        16,
        2_048,
        "session_import.max_body_import_mib_per_run",
    )?;
    range_u64(
        u64::from(config.capture.preview_bytes),
        256,
        65_536,
        "capture.preview_bytes",
    )?;
    range_u64(
        u64::from(config.capture.inline_payload_bytes),
        1_024,
        1_048_576,
        "capture.inline_payload_bytes",
    )?;
    if config.capture.inline_payload_bytes < config.capture.preview_bytes {
        return Err(ConfigError::InvalidRelation(
            "capture.inline_payload_bytes >= capture.preview_bytes",
        ));
    }
    range_duration(
        config.recovery.capture_timeout,
        1,
        120,
        "recovery.capture_timeout",
    )?;
    range_u64(
        u64::from(config.recovery.max_bundle_mib),
        16,
        4_096,
        "recovery.max_bundle_mib",
    )?;
    range_u64(
        u64::from(config.recovery.max_untracked_file_mib),
        1,
        1_024,
        "recovery.max_untracked_file_mib",
    )?;
    range_u64(
        u64::from(config.recovery.max_untracked_total_mib),
        1,
        4_096,
        "recovery.max_untracked_total_mib",
    )?;
    if config.recovery.max_untracked_total_mib > config.recovery.max_bundle_mib {
        return Err(ConfigError::InvalidRelation(
            "recovery.max_untracked_total_mib <= recovery.max_bundle_mib",
        ));
    }
    validate_short_text(&config.llm.provider, "llm.provider")?;
    validate_short_text(&config.llm.model, "llm.model")?;
    validate_env_name(&config.llm.api_key_env)?;
    range_duration(config.llm.timeout, 1, 600, "llm.timeout")?;
    range_u64(
        u64::from(config.llm.max_concurrency),
        1,
        8,
        "llm.max_concurrency",
    )?;
    let enrichment_minimum = match config.llm.episode_enrichment {
        EpisodeEnrichment::Off => 0,
        EpisodeEnrichment::Adaptive => 1,
    };
    range_u64(
        u64::from(config.llm.max_episode_enrichments),
        enrichment_minimum,
        4,
        "llm.max_episode_enrichments",
    )?;
    positive(
        config.llm.daily_input_token_budget,
        "llm.daily_input_token_budget",
    )?;
    positive(
        config.llm.daily_output_token_budget,
        "llm.daily_output_token_budget",
    )?;
    positive(
        u64::from(config.llm.daily_call_budget),
        "llm.daily_call_budget",
    )?;
    range_duration(
        config.llm.daily_wall_time_budget,
        60,
        86_400,
        "llm.daily_wall_time_budget",
    )?;
    Ok(())
}

fn validate_data_dir(value: &str) -> Result<(), ConfigError> {
    let valid = !value.is_empty()
        && !value.contains('\0')
        && (value.starts_with('/')
            || value == "~"
            || value.starts_with("~/")
            || valid_variable_path(value));
    if !valid {
        return Err(ConfigError::InvalidField("runtime.data_dir"));
    }
    Ok(())
}

fn valid_variable_path(value: &str) -> bool {
    if let Some(remainder) = value.strip_prefix("${") {
        let Some(closing) = remainder.find('}') else {
            return false;
        };
        let (name, suffix_with_brace) = remainder.split_at(closing);
        let suffix = &suffix_with_brace[1..];
        return is_valid_env_name(name) && (suffix.is_empty() || suffix.starts_with('/'));
    }
    let Some(remainder) = value.strip_prefix('$') else {
        return false;
    };
    let (name, suffix) = remainder
        .split_once('/')
        .map_or((remainder, ""), |(name, suffix)| (name, suffix));
    is_valid_env_name(name) && (suffix.is_empty() || remainder.starts_with(&format!("{name}/")))
}

fn validate_short_text(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.trim().is_empty() || value.len() > 256 {
        return Err(ConfigError::InvalidField(field));
    }
    Ok(())
}

fn validate_env_name(value: &str) -> Result<(), ConfigError> {
    if !is_valid_env_name(value) {
        return Err(ConfigError::InvalidField("llm.api_key_env"));
    }
    Ok(())
}

fn is_valid_env_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    let valid_first = bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_');
    let valid_rest = bytes[bytes.len().min(1)..]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    !bytes.is_empty() && bytes.len() <= 128 && valid_first && valid_rest
}

fn range_duration(
    value: DurationValue,
    minimum: u64,
    maximum: u64,
    field: &'static str,
) -> Result<(), ConfigError> {
    range_u64(value.seconds(), minimum, maximum, field)
}

fn range_u64(
    value: u64,
    minimum: u64,
    maximum: u64,
    field: &'static str,
) -> Result<(), ConfigError> {
    if !(minimum..=maximum).contains(&value) {
        return Err(ConfigError::OutOfRange(field));
    }
    Ok(())
}

fn positive(value: u64, field: &'static str) -> Result<(), ConfigError> {
    if value == 0 {
        return Err(ConfigError::OutOfRange(field));
    }
    Ok(())
}

fn effective_hash(config: &ConfigFile) -> Result<[u8; 32], ConfigError> {
    let value = toml::Value::try_from(config).map_err(|_| ConfigError::Serialization)?;
    let canonical = canonicalize_toml(&value)?;
    canonical::sha256(
        "evertrace.effective_config",
        config.config_version,
        &canonical,
    )
    .map_err(|_| ConfigError::UnsupportedCanonicalValue)
}

fn canonicalize_toml(value: &toml::Value) -> Result<CanonicalValue, ConfigError> {
    match value {
        toml::Value::String(value) => Ok(CanonicalValue::String(value.clone())),
        toml::Value::Integer(value) => Ok(CanonicalValue::Integer(i128::from(*value))),
        toml::Value::Boolean(value) => Ok(CanonicalValue::Bool(*value)),
        toml::Value::Array(values) => values
            .iter()
            .map(canonicalize_toml)
            .collect::<Result<Vec<_>, _>>()
            .map(CanonicalValue::Sequence),
        toml::Value::Table(table) => table
            .iter()
            .map(|(key, value)| Ok((key.clone(), canonicalize_toml(value)?)))
            .collect::<Result<Vec<_>, ConfigError>>()
            .map(CanonicalValue::Map),
        toml::Value::Float(_) | toml::Value::Datetime(_) => {
            Err(ConfigError::UnsupportedCanonicalValue)
        }
    }
}

impl fmt::Display for DurationValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical_literal())
    }
}
