//! Deterministic destructive classification, capture, and supervised recovery.

use evertrace_domain::repository::{RecoveryOmission, WorktreeSnapshot};
use evertrace_store::StoreError;
use thiserror::Error;

pub const RECOVERY_ALGORITHM_REVISION: &str = "s16_recovery_v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRuntimeSettings {
    pub generation: u64,
    pub effective_config_hash: [u8; 32],
    pub gate: evertrace_capture::RecoveryGateMode,
    pub adapter_manifest_id: Option<String>,
    pub classifier_revision: u32,
    pub capture_timeout_ms: u32,
    pub max_bundle_bytes: u64,
    pub max_untracked_file_bytes: u64,
    pub max_untracked_total_bytes: u64,
}

impl RecoveryRuntimeSettings {
    pub fn compile(
        config: &evertrace_domain::config::EffectiveConfig,
        report: Option<&evertrace_codex::HostProbeReport>,
        generation: u64,
    ) -> Result<Self, RecoveryError> {
        let recovery = &config.config().recovery;
        let capture_timeout_ms = recovery
            .capture_timeout
            .seconds()
            .checked_mul(1_000)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(RecoveryError::InvalidInput)?;
        let mib = |value: u32| {
            u64::from(value)
                .checked_mul(1 << 20)
                .ok_or(RecoveryError::InvalidInput)
        };
        let active_manifest = report
            .filter(|value| {
                value.recovery_barrier_active()
                    && value.recovery().adapter_manifest_revision()
                        == value.manifest().adapter_manifest_id
                    && value.manifest().validate().is_ok()
            })
            .map(|value| value.manifest().adapter_manifest_id.clone());
        Ok(Self {
            generation,
            effective_config_hash: config.hash(),
            gate: if active_manifest.is_some() {
                evertrace_capture::RecoveryGateMode::Active
            } else {
                evertrace_capture::RecoveryGateMode::Disabled
            },
            adapter_manifest_id: active_manifest,
            classifier_revision: evertrace_codex::recovery::RECOVERY_CLASSIFIER_REVISION,
            capture_timeout_ms,
            max_bundle_bytes: mib(recovery.max_bundle_mib)?,
            max_untracked_file_bytes: mib(recovery.max_untracked_file_mib)?,
            max_untracked_total_bytes: mib(recovery.max_untracked_total_mib)?,
        })
    }
}

pub fn publish_recovery_runtime(
    data_dir: &std::path::Path,
    config: &evertrace_domain::config::EffectiveConfig,
    report: Option<&evertrace_codex::HostProbeReport>,
) -> Result<evertrace_capture::RuntimeSnapshot, RecoveryError> {
    evertrace_capture::DeviceKeyStore::new(data_dir.join("keys"))
        .load_or_create()
        .map_err(|_| RecoveryError::Protection)?;
    let path = evertrace_capture::RuntimeSnapshot::snapshot_path(data_dir);
    let (generation, spool_limits) = match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let current = evertrace_capture::RuntimeSnapshot::load(&path)
                .map_err(|_| RecoveryError::InvalidInput)?;
            (
                current
                    .generation
                    .checked_add(1)
                    .ok_or(RecoveryError::InvalidInput)?,
                current
                    .spool_limits()
                    .map_err(|_| RecoveryError::InvalidInput)?,
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            1,
            evertrace_capture::SpoolLimits {
                high_watermark_bytes: 64 << 20,
                low_watermark_bytes: 48 << 20,
                max_main_files: 64,
                emergency_slots: 8,
            },
        ),
        Err(_) => return Err(RecoveryError::InvalidInput),
    };
    let settings = RecoveryRuntimeSettings::compile(config, report, generation)?;
    let snapshot = evertrace_capture::RuntimeSnapshot::for_data_dir(
        data_dir,
        settings.generation,
        spool_limits,
        evertrace_capture::RecoverySnapshotSettings {
            gate: settings.gate,
            preflight_timeout_ms: settings.capture_timeout_ms,
            effective_config_hash: settings.effective_config_hash,
            adapter_manifest_id: settings.adapter_manifest_id,
            classifier_revision: settings.classifier_revision,
            max_bundle_bytes: settings.max_bundle_bytes,
            max_untracked_file_bytes: settings.max_untracked_file_bytes,
            max_untracked_total_bytes: settings.max_untracked_total_bytes,
        },
    )
    .map_err(|_| RecoveryError::InvalidInput)?;
    snapshot
        .publish(&path)
        .map_err(|_| RecoveryError::InvalidInput)?;
    Ok(snapshot)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryItemKind {
    TrackedDiff,
    TrackedFile,
    IndexState,
    UntrackedFile,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryCaptureItem {
    pub item_ref: String,
    pub kind: RecoveryItemKind,
    pub bytes: Vec<u8>,
    pub relative_path: Option<Vec<u8>>,
    pub critical: bool,
    pub metadata_only: bool,
}

impl std::fmt::Debug for RecoveryCaptureItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryCaptureItem")
            .field("item_ref", &self.item_ref)
            .field("kind", &self.kind)
            .field("byte_length", &self.bytes.len())
            .field("has_protected_relative_path", &self.relative_path.is_some())
            .field("critical", &self.critical)
            .field("metadata_only", &self.metadata_only)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCaptureFacts {
    pub snapshot: WorktreeSnapshot,
    pub request_id: evertrace_domain::ids::RecoveryCaptureRequestId,
    pub adapter_manifest_id: String,
    pub mutation_manifest_version: u32,
    pub before_fingerprint: Option<String>,
    pub after_fingerprint: Option<String>,
    pub items: Vec<RecoveryCaptureItem>,
    pub omissions: Vec<RecoveryOmission>,
    pub artifact_refs: Vec<String>,
    pub metadata_artifact_refs: Vec<String>,
    pub config_and_run_refs: Vec<String>,
    pub attempt_anchor_ids: Vec<evertrace_domain::ids::AttemptId>,
    pub captured_at_us: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryBudget {
    pub max_item_bytes: u64,
    pub max_untracked_item_bytes: u64,
    pub max_bundle_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecoveryError {
    #[error("recovery input is invalid")]
    InvalidInput,
    #[error("recovery current view is stale or missing")]
    StaleCurrent,
    #[error("recovery revision successor is invalid")]
    InvalidSuccessor,
    #[error("recovery protection failed")]
    Protection,
    #[error("recovery CAS write failed")]
    Cas,
    #[error("recovery budget was exceeded")]
    Budget,
    #[error("recovery bundle is invalid")]
    InvalidBundle,
    #[error("recovery journal command is invalid")]
    Store,
    #[error("recovery gate is inactive")]
    GateInactive,
    #[error("durable recovery pending intent is unavailable")]
    PendingUnavailable,
    #[error("durable recovery pending intent was not authoritatively admitted")]
    NotAdmitted,
    #[error("recovery spool lookup failed")]
    Spool,
    #[error("worktree mutation fence is busy")]
    FenceBusy,
    #[error("bounded recovery probe failed")]
    Probe,
    #[error("recovery capture deadline expired")]
    Deadline,
}

impl From<StoreError> for RecoveryError {
    fn from(_: StoreError) -> Self {
        Self::Store
    }
}

mod action;
mod application;
mod barrier;
mod bundle;
mod capture;
mod patch;

pub use action::{
    RecoveryActionOutcome, RecoveryActionService, RecoveryRequest, RecoveryUnsupportedReason,
};
pub use application::{
    RECOVERY_APPLICATION_TICKET_VERSION, RecoveryApplicationTicket,
    RecoveryApplicationTicketClaims, RecoveryTicketIssueRequest, RecoveryTicketService,
};
pub use barrier::{RecoveryBarrierLocator, RecoveryBarrierService, RecoveryTerminalAck};
pub use bundle::{capture_recovery_bundle, pending_request_command, terminal_capture_command};
