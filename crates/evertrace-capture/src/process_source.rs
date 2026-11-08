//! A fixed source-side recorder's original bytes, never a caller-selected authority level.
//!
//! Live peer/record identity is checked here. Namespace canaries and semantic Work
//! binding are not yet qualified, so every accepted record remains untrusted/partial.

use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path};

use evertrace_domain::evidence::{
    CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceSourceKind,
    HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceRevisionMode, SourceRole,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::CaptureRecordInput;

const PREFIX: &[u8] = b"{\"format\":\"process-trial-source-v1\",";
const FORMAT: &str = "process-trial-source-v1";
const MANIFEST: &str =
    "process-trial-source-v1:87ec8be34c7583b9b0e7c9d97ccdeb78aecefd08914f935f6fa013539478b00d";
const LIMIT: usize = 65_536;

#[derive(Debug, thiserror::Error)]
#[error("process source record or live peer is unavailable")]
pub struct ProcessSourceError;

type Result<T> = std::result::Result<T, ProcessSourceError>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessIdentity {
    pid: u32,
    start_ticks: u64,
    pid_namespace: u64,
    executable: String,
    boot_id: String,
}

#[derive(Deserialize)]
struct Header {
    format: String,
    event: String,
    event_key: String,
    source_epoch: String,
    study_key: String,
    sequence: u64,
    time_us: i64,
    controller: ProcessIdentity,
}

fn bytes(path: &Path) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    fs::File::open(path)
        .map_err(|_| ProcessSourceError)?
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut value)
        .map_err(|_| ProcessSourceError)?;
    (value.len() <= LIMIT)
        .then_some(value)
        .ok_or(ProcessSourceError)
}

fn text(path: &Path) -> Result<String> {
    String::from_utf8(bytes(path)?)
        .map(|value| value.trim().to_owned())
        .map_err(|_| ProcessSourceError)
}

fn stat(pid: &str) -> Result<(u32, u64)> {
    let raw = text(&Path::new("/proc").join(pid).join("stat"))?;
    let (_, fields) = raw.rsplit_once(") ").ok_or(ProcessSourceError)?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    let parent = fields
        .get(1)
        .ok_or(ProcessSourceError)?
        .parse()
        .map_err(|_| ProcessSourceError)?;
    let start = fields
        .get(19)
        .ok_or(ProcessSourceError)?
        .parse()
        .map_err(|_| ProcessSourceError)?;
    Ok((parent, start))
}

fn uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

fn peer(header: &Header, executable: &Path, snapshot: &Path) -> Result<()> {
    let (parent, _) = stat("self")?;
    let root = Path::new("/proc").join(parent.to_string());
    let own_uid = fs::metadata("/proc/self")
        .map_err(|_| ProcessSourceError)?
        .uid();
    let (_, start) = stat(&parent.to_string())?;
    let identity = &header.controller;
    if identity.pid != parent
        || identity.start_ticks != start
        || identity.pid_namespace
            != fs::metadata(root.join("ns/pid"))
                .map_err(|_| ProcessSourceError)?
                .ino()
        || identity.executable
            != fs::read_link(root.join("exe"))
                .map_err(|_| ProcessSourceError)?
                .to_string_lossy()
        || identity.boot_id != text(Path::new("/proc/sys/kernel/random/boot_id"))?
        || fs::metadata(&root).map_err(|_| ProcessSourceError)?.uid() != own_uid
    {
        return Err(ProcessSourceError);
    }
    let raw = bytes(&root.join("cmdline"))?;
    let args: Vec<_> = raw
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .collect();
    if args.get(1..4) != Some(&[b"-I".as_slice(), b"-S".as_slice(), b"-B".as_slice()]) {
        return Err(ProcessSourceError);
    }
    let script = std::str::from_utf8(args.get(4).ok_or(ProcessSourceError)?)
        .map_err(|_| ProcessSourceError)?;
    let script = fs::read_link(root.join("cwd"))
        .map_err(|_| ProcessSourceError)?
        .join(script);
    let metadata = fs::symlink_metadata(&script).map_err(|_| ProcessSourceError)?;
    if !metadata.is_file() || metadata.uid() != own_uid || metadata.mode() & 0o022 != 0 {
        return Err(ProcessSourceError);
    }
    if format!("{FORMAT}:{:x}", Sha256::digest(bytes(&script)?)) != MANIFEST {
        return Err(ProcessSourceError);
    }
    for (flag, expected) in [
        (b"--native-hook".as_slice(), executable),
        (b"--runtime-snapshot".as_slice(), snapshot),
    ] {
        let index = args
            .iter()
            .position(|arg| *arg == flag)
            .ok_or(ProcessSourceError)?;
        let value = std::str::from_utf8(args.get(index + 1).ok_or(ProcessSourceError)?)
            .map_err(|_| ProcessSourceError)?;
        if fs::canonicalize(value).map_err(|_| ProcessSourceError)?
            != fs::canonicalize(expected).map_err(|_| ProcessSourceError)?
        {
            return Err(ProcessSourceError);
        }
    }
    Ok(())
}

/// The same Hook transport calls this only for the recorder's exact original version signature.
/// No peer/header can select Observed, Complete, an active binding, or an Exact admission.
pub fn record(raw: &[u8], snapshot: &Path) -> Result<Option<CaptureRecordInput>> {
    if !raw.starts_with(PREFIX) {
        return Ok(None);
    }
    if raw.len() > LIMIT {
        return Err(ProcessSourceError);
    }
    let value: Value = serde_json::from_slice(raw).map_err(|_| ProcessSourceError)?;
    let fields = value.as_object().ok_or(ProcessSourceError)?;
    if fields.keys().any(|key| {
        !matches!(
            key.as_str(),
            "format"
                | "event"
                | "event_key"
                | "source_epoch"
                | "sequence"
                | "time_us"
                | "controller"
                | "study_key"
                | "definition"
                | "trial_key"
                | "argv"
                | "config"
                | "source_anchor"
                | "launch_event"
                | "process"
                | "returncode"
                | "scorer"
                | "outcomes"
        )
    }) {
        return Err(ProcessSourceError);
    }
    let header: Header = serde_json::from_value(value).map_err(|_| ProcessSourceError)?;
    let role = match header.event.as_str() {
        "study_opened" | "controller_finished" => ObservationRole::Other,
        "trial_launch" => ObservationRole::Intent,
        "trial_started" => ObservationRole::Other,
        "trial_finished" => ObservationRole::Result,
        _ => return Err(ProcessSourceError),
    };
    if header.format != FORMAT
        || !uuid(&header.event_key)
        || !uuid(&header.source_epoch)
        || !uuid(&header.study_key)
        || header.sequence == 0
        || header.time_us < 0
    {
        return Err(ProcessSourceError);
    }
    let executable = std::env::current_exe().map_err(|_| ProcessSourceError)?;
    peer(&header, &executable, snapshot)?;
    Ok(Some(CaptureRecordInput {
        spool_record_id: Some(header.event_key.clone()),
        source_observation_id_hint: None,
        source_instance_id: format!(
            "process:{}:{}:{}:{}",
            header.controller.boot_id,
            header.controller.pid_namespace,
            header.controller.pid,
            header.controller.start_ticks
        ),
        source_revision: MANIFEST.into(),
        source_record_identity: Some(header.event_key),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: FORMAT.into(),
        source_ref: format!("session:{}", header.source_epoch),
        session_ref: header.source_epoch,
        turn_ref: None,
        tool_ref: None,
        source_sequence: header.sequence,
        source_sequence_origin: Some(1),
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        source_byte_range: None,
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: (header.event == "controller_finished").then_some(header.sequence),
        observation_role: role,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            pairing_role: role,
            field_provenance: vec![],
            adapter_manifest_ref: MANIFEST.into(),
            adapter_revision: 1,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: vec![],
        source_local_evidence: None,
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: SourceRole::Tool,
        content_trust: ContentTrust::UntrustedSourceContent,
        capture_completeness: CaptureCompleteness::Partial,
        surface_eligible: true,
        adapter_revision: 1,
        adapter_manifest_ref: MANIFEST.into(),
        eligible_event_manifest_ref: "process-trial-source-events-v1".into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        // The original clock value remains in raw bytes; its uncertainty is not qualified.
        event_time_us: None,
        event_time_provenance: None,
        raw_payload: raw.to_vec(),
    }))
}
