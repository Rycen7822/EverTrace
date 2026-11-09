//! A fixed source-side recorder's original bytes, never a caller-selected authority level.
//!
//! Live peer/record identity is checked here. Namespace canaries and semantic Work
//! binding are not yet qualified, so every accepted record remains untrusted/partial.

use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path};

use evertrace_domain::evidence::{
    CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
    CorrelationField, CorrelationFieldClaim, EvidenceSourceKind, HostCorrelationEvidence,
    IdentityStrength, ObservationRole, SourceInstanceId, SourceRecordIdentity, SourceRevision,
    SourceRevisionMode, SourceRole, source_observation_id,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::CaptureRecordInput;

const PREFIX: &[u8] = b"{\"format\":\"process-trial-source-v2\",";
const FORMAT: &str = "process-trial-source-v2";
pub const SOURCE_REVISION: &str =
    "process-trial-source-v2:79ba882813eea69af109ace6016462953d63b7c97677392d6673c96bebeee9d6";
pub const ADAPTER_REVISION: u32 = 3;
pub const ELIGIBLE_EVENTS: &str = "process-trial-source-events-v2";
const LIMIT: usize = 65_536;

pub fn adapter_version() -> String {
    format!("{SOURCE_REVISION}:capture-{ADAPTER_REVISION}")
}

pub fn is_record(raw: &[u8]) -> bool {
    raw.starts_with(PREFIX)
}

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
    process: Option<ProcessIdentity>,
    execution_key: Option<String>,
    argv: Option<Vec<String>>,
    returncode: Option<i32>,
}

struct ProcessStat {
    parent: u32,
    start: u64,
    state: String,
    exit_status: u32,
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

fn stat(pid: &str) -> Result<ProcessStat> {
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
    let state = fields.first().ok_or(ProcessSourceError)?.to_string();
    let exit_status = fields
        .get(49)
        .ok_or(ProcessSourceError)?
        .parse()
        .map_err(|_| ProcessSourceError)?;
    Ok(ProcessStat {
        parent,
        start,
        state,
        exit_status,
    })
}

fn uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

fn peer(header: &Header, executable: &Path, snapshot: &Path) -> Result<()> {
    let parent = stat("self")?.parent;
    let root = Path::new("/proc").join(parent.to_string());
    let own_uid = fs::metadata("/proc/self")
        .map_err(|_| ProcessSourceError)?
        .uid();
    let start = stat(&parent.to_string())?.start;
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
    if format!("{FORMAT}:{:x}", Sha256::digest(bytes(&script)?)) != SOURCE_REVISION {
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

// The physical unit is this source's single child process lifetime, not its opaque trial UUID.
// The source holds a pipe before execution and uses WNOWAIT after exit. Both endpoints
// can therefore be checked against the kernel here without a cache, lookup or claimed birth.
fn physical_scope(header: &Header) -> Result<String> {
    let identity = header.process.as_ref().ok_or(ProcessSourceError)?;
    if !header.execution_key.as_deref().is_some_and(uuid) {
        return Err(ProcessSourceError);
    }
    let root = Path::new("/proc").join(identity.pid.to_string());
    let observed = stat(&identity.pid.to_string())?;
    if observed.parent != header.controller.pid
        || observed.start != identity.start_ticks
        || identity.boot_id != header.controller.boot_id
        || identity.pid_namespace
            != fs::metadata(root.join("ns/pid"))
                .map_err(|_| ProcessSourceError)?
                .ino()
    {
        return Err(ProcessSourceError);
    }
    if header.event == "trial_finished" {
        let code = if observed.exit_status & 0x7f == 0 {
            (observed.exit_status >> 8 & 0xff) as i32
        } else {
            -((observed.exit_status & 0x7f) as i32)
        };
        if observed.state != "Z" || header.returncode != Some(code) {
            return Err(ProcessSourceError);
        }
    } else {
        if !matches!(header.event.as_str(), "trial_launch" | "trial_started")
            || observed.state == "Z"
            || identity.executable
                != fs::read_link(root.join("exe"))
                    .map_err(|_| ProcessSourceError)?
                    .to_string_lossy()
        {
            return Err(ProcessSourceError);
        }
        if header.event == "trial_launch" {
            let args = header.argv.as_ref().ok_or(ProcessSourceError)?;
            let mut command = Vec::new();
            for arg in args {
                command.extend_from_slice(arg.as_bytes());
                command.push(0);
            }
            if bytes(&root.join("cmdline"))? != command {
                return Err(ProcessSourceError);
            }
        }
    }
    Ok(format!(
        "process:{}:{}:{}:{}",
        identity.boot_id, identity.pid_namespace, identity.pid, observed.start
    ))
}

/// The same Hook transport calls this only for the recorder's exact original version signature.
/// No peer/header can select Observed, Complete, an active binding, or an Exact admission.
pub fn record(raw: &[u8], snapshot: &Path, manifest_ref: &str) -> Result<CaptureRecordInput> {
    if !is_record(raw)
        || manifest_ref.len() != 64
        || !manifest_ref.bytes().all(|value| value.is_ascii_hexdigit())
    {
        return Err(ProcessSourceError);
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
                | "execution_key"
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
    let source_instance_id = format!(
        "process:{}:{}:{}:{}",
        header.controller.boot_id,
        header.controller.pid_namespace,
        header.controller.pid,
        header.controller.start_ticks,
    );
    let source_ref = format!("session:{}", header.source_epoch);
    let mut correlation = HostCorrelationEvidence {
        occurrence_schema_version: 1,
        host_instance_id: None,
        host_trace_lineage_id: None,
        host_lane_key: None,
        canonical_event_family: None,
        native_request_id: None,
        physical_execution_ordinal: None,
        pairing_role: role,
        field_provenance: vec![],
        adapter_manifest_ref: manifest_ref.into(),
        adapter_revision: ADAPTER_REVISION,
        strong_gate_receipt_ref: None,
        admission: CorrelationAdmission::Unavailable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    };
    // Failed/missing kernel evidence remains an original untrusted/partial record with no
    // physical claims. Even verified fields cannot form an Exact key without a qualified gate.
    if let Ok(scope) = physical_scope(&header) {
        let evidence = source_observation_id(
            &SourceInstanceId::parse(&source_instance_id).map_err(|_| ProcessSourceError)?,
            &SourceRevision::parse(SOURCE_REVISION).map_err(|_| ProcessSourceError)?,
            &SourceRecordIdentity::parse(&header.event_key).map_err(|_| ProcessSourceError)?,
        )
        .map_err(|_| ProcessSourceError)?;
        correlation.host_instance_id = Some(source_instance_id.clone());
        correlation.host_trace_lineage_id = Some(header.source_epoch.clone());
        correlation.host_lane_key = Some(scope);
        correlation.canonical_event_family = Some(CanonicalEventFamily::Verify);
        correlation.native_request_id = header.execution_key.clone();
        correlation.physical_execution_ordinal = Some(1);
        correlation.field_provenance = [
            CorrelationField::HostInstanceId,
            CorrelationField::HostTraceLineageId,
            CorrelationField::HostLaneKey,
            CorrelationField::CanonicalEventFamily,
            CorrelationField::NativeRequestId,
            CorrelationField::PhysicalExecutionOrdinal,
        ]
        .into_iter()
        .map(|field| CorrelationFieldClaim {
            field,
            source_ref: source_ref.clone(),
            evidence_ref: evidence.to_string(),
        })
        .collect();
    }
    Ok(CaptureRecordInput {
        spool_record_id: Some(header.event_key.clone()),
        source_observation_id_hint: None,
        source_instance_id,
        source_revision: SOURCE_REVISION.into(),
        source_record_identity: Some(header.event_key),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: FORMAT.into(),
        source_ref,
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
        correlation,
        scope_effect_claims: vec![],
        source_local_evidence: None,
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: SourceRole::Tool,
        content_trust: ContentTrust::UntrustedSourceContent,
        capture_completeness: CaptureCompleteness::Partial,
        surface_eligible: true,
        adapter_revision: ADAPTER_REVISION,
        adapter_manifest_ref: manifest_ref.into(),
        eligible_event_manifest_ref: ELIGIBLE_EVENTS.into(),
        parser_revision: 2,
        canonicalization_revision: 1,
        // The original clock value remains in raw bytes; its uncertainty is not qualified.
        event_time_us: None,
        event_time_provenance: None,
        raw_payload: raw.to_vec(),
    })
}
