//! Source-owned process records, never caller-selected execution or Work authority.
//!
//! Publisher claims remain untrusted/partial. Separately read kernel state is observed
//! metadata only: it supplies no inherited namespace, execution, or semantic Work authority.

mod image;

use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use evertrace_domain::evidence::{
    CanonicalEventFamily, CaptureCompleteness, ContentTrust, CorrelationAdmission,
    CorrelationField, CorrelationFieldClaim, EvidenceByteRange, EvidenceSourceKind,
    HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceInstanceId,
    SourceRecordIdentity, SourceRevision, SourceRevisionMode, SourceRole, source_observation_id,
};
use evertrace_domain::ids::SourceObservationId;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{CaptureRecordInput, ConfinedFile, ConfinedReadLimits, ConfinedRoot};

const PREFIX: &[u8] = b"{\"format\":\"process-trial-source-v4\",";
pub const FORMAT: &str = "process-trial-source-v4";
pub const WORK_FORMAT: &str = "process-work-source-v1";
const WORK_PREFIX: &[u8] = b"{\"format\":\"process-work-source-v1\",";
pub const WORK_ADAPTER_REVISION: u32 = 1;
pub const WORK_PARSER_REVISION: u32 = 1;
pub const WORK_ELIGIBLE_EVENTS: &str = "process-work-start-events-v1";
pub const SOURCE_REVISION: &str =
    "process-trial-source-v4:84e413385043c92b6723c629b7c0b0481539671827b539dc2f910cf01d432d1d";
pub const ADAPTER_REVISION: u32 = 11;
pub const PARSER_REVISION: u32 = 8;
pub const ELIGIBLE_EVENTS: &str = "process-trial-source-events-v4";
pub const KERNEL_SOURCE_REVISION: &str = "linux-proc-stat-v1";
pub const KERNEL_ADAPTER_REVISION: u32 = 1;
pub const KERNEL_ELIGIBLE_EVENTS: &str = "linux-proc-state-snapshot-v1";
pub const INPUT_SOURCE_REVISION: &str = "linux-proc-inputs-v1";
pub const INPUT_ELIGIBLE_EVENTS: &str = "linux-proc-inputs-snapshot-v1";
pub const OUTPUT_SOURCE_REVISION: &str = "junit-xunit2-output-v1";
pub const OUTPUT_ELIGIBLE_EVENTS: &str = "junit-xunit2-output-snapshot-v1";

pub const CONDITIONS_SOURCE_REVISION: &str = "python-execution-conditions-v1";
pub const CONDITIONS_ELIGIBLE_EVENTS: &str = "python-execution-conditions-snapshot-v1";
pub const IMAGE_SOURCE_REVISION: &str = "python-native-runtime-v1";
pub const IMAGE_ELIGIBLE_EVENTS: &str = "python-native-runtime-measurement-v1";

pub const IMAGE_ADAPTER_REVISION: u32 = 3;

pub fn image_adapter_version(revision: u32) -> String {
    format!("{IMAGE_SOURCE_REVISION}:capture-{revision}")
}

pub fn is_owned_revision(revision: &str) -> bool {
    revision.starts_with("process-trial-source-v")
        || revision.starts_with(WORK_FORMAT)
        || matches!(
            revision,
            KERNEL_SOURCE_REVISION
                | INPUT_SOURCE_REVISION
                | OUTPUT_SOURCE_REVISION
                | CONDITIONS_SOURCE_REVISION
                | IMAGE_SOURCE_REVISION
        )
}
const LIMIT: usize = 65_536;
pub const SOURCE_BYTES: u64 = 262_144;
const SOURCE_RECORDS: u64 = 64;

pub fn adapter_version() -> String {
    format!("{SOURCE_REVISION}:capture-{ADAPTER_REVISION}")
}

pub fn work_adapter_version() -> String {
    format!("{WORK_FORMAT}:capture-{WORK_ADAPTER_REVISION}")
}

pub fn is_work_revision(revision: &str) -> bool {
    revision
        .strip_prefix(WORK_FORMAT)
        .and_then(|value| value.strip_prefix(':'))
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

pub fn is_work_record(raw: &[u8]) -> bool {
    raw.starts_with(WORK_PREFIX)
}

pub fn is_record(raw: &[u8]) -> bool {
    raw.starts_with(PREFIX) || is_work_record(raw)
}

#[derive(Debug, thiserror::Error)]
#[error("process source record or live peer is unavailable")]
pub struct ProcessSourceError;

type Result<T> = std::result::Result<T, ProcessSourceError>;

/// Only the live source reader can construct these original observations.
pub struct Observation(CaptureRecordInput);

impl Observation {
    pub(crate) fn into_record(self) -> CaptureRecordInput {
        self.0
    }

    pub fn is_launch(&self) -> bool {
        self.0.observation_role == ObservationRole::Intent
    }

    pub fn execution_locator(&self) -> Result<Option<SourceObservationId>> {
        if self.0.source_revision != IMAGE_SOURCE_REVISION
            && !matches!(
                self.0.observation_role,
                ObservationRole::Intent | ObservationRole::Result
            )
        {
            return Ok(None);
        }
        source_observation_id(
            &SourceInstanceId::parse(&self.0.source_instance_id).map_err(|_| ProcessSourceError)?,
            &SourceRevision::parse(&self.0.source_revision).map_err(|_| ProcessSourceError)?,
            &SourceRecordIdentity::parse(
                self.0
                    .source_record_identity
                    .as_deref()
                    .ok_or(ProcessSourceError)?,
            )
            .map_err(|_| ProcessSourceError)?,
        )
        .map(Some)
        .map_err(|_| ProcessSourceError)
    }
}

/// A live producer/caller relationship, not authority for the record's claims.
pub struct SourceLaunch {
    controller_pid: u32,
    controller_start: u64,
    directory: PathBuf,
    commit: String,
    tree: String,
}

impl SourceLaunch {
    pub fn controller(&self) -> (u32, u64) {
        (self.controller_pid, self.controller_start)
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn anchor(&self) -> (&str, &str) {
        (&self.commit, &self.tree)
    }
}

/// Recheck only while the actual Hook child and its held trial are still alive.
pub fn source_launch(input: &[u8], snapshot: &Path, caller_pid: u32) -> Result<SourceLaunch> {
    let (header, _) = decode(input)?;
    if header.event != "trial_launch" {
        return Err(ProcessSourceError);
    }
    let caller_image =
        fs::read_link(format!("/proc/{caller_pid}/exe")).map_err(|_| ProcessSourceError)?;
    let caller = fs::metadata(format!("/proc/{caller_pid}")).map_err(|_| ProcessSourceError)?;
    if caller.uid()
        != fs::metadata("/proc/self")
            .map_err(|_| ProcessSourceError)?
            .uid()
    {
        return Err(ProcessSourceError);
    }
    for kind in ["pid", "user", "mnt"] {
        let own = fs::read_link(format!("/proc/{caller_pid}/ns/{kind}"))
            .map_err(|_| ProcessSourceError)?;
        let parent = fs::read_link(format!("/proc/{}/ns/{kind}", header.controller.pid))
            .map_err(|_| ProcessSourceError)?;
        if own != parent {
            return Err(ProcessSourceError);
        }
    }
    let script = peer_at(&header, &caller_image, snapshot, caller_pid)?;
    if published_record(input, &header, &script)?.1.is_none() {
        return Err(ProcessSourceError);
    }
    physical_scope(&header)?;
    let directory = fs::read_link(format!("/proc/{}/cwd", header.controller.pid))
        .map_err(|_| ProcessSourceError)?;
    let process = header.process.as_ref().ok_or(ProcessSourceError)?;
    let root = fs::metadata(&directory).map_err(|_| ProcessSourceError)?;
    let child =
        fs::metadata(format!("/proc/{}/cwd", process.pid)).map_err(|_| ProcessSourceError)?;
    if (root.dev(), root.ino()) != (child.dev(), child.ino()) {
        return Err(ProcessSourceError);
    }
    let value: Value = serde_json::from_slice(input).map_err(|_| ProcessSourceError)?;
    let anchor = value.get("source_anchor").ok_or(ProcessSourceError)?;
    let commit = anchor
        .get("commit")
        .and_then(Value::as_str)
        .ok_or(ProcessSourceError)?;
    let tree = anchor
        .get("tree")
        .and_then(Value::as_str)
        .ok_or(ProcessSourceError)?;
    if [commit, tree]
        .iter()
        .any(|value| value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(ProcessSourceError);
    }
    Ok(SourceLaunch {
        controller_pid: header.controller.pid,
        controller_start: header.controller.start_ticks,
        directory,
        commit: commit.into(),
        tree: tree.into(),
    })
}

pub fn output_adapter_version() -> String {
    format!("{OUTPUT_SOURCE_REVISION}:capture-{KERNEL_ADAPTER_REVISION}")
}

pub fn conditions_adapter_version() -> String {
    format!("{CONDITIONS_SOURCE_REVISION}:capture-{KERNEL_ADAPTER_REVISION}")
}

pub fn input_adapter_version() -> String {
    format!("{INPUT_SOURCE_REVISION}:capture-{KERNEL_ADAPTER_REVISION}")
}

pub fn kernel_adapter_version() -> String {
    format!("{KERNEL_SOURCE_REVISION}:capture-{KERNEL_ADAPTER_REVISION}")
}

#[derive(Deserialize, Eq, PartialEq)]
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
    #[serde(alias = "work_key")]
    study_key: String,
    sequence: u64,
    time_us: i64,
    controller: ProcessIdentity,
    process: Option<ProcessIdentity>,
    execution_key: Option<String>,
    request_key: Option<String>,
    lane_thread_id: u32,
    probe_endpoint: String,
    execution_ordinal: Option<u32>,
    launch_event: Option<String>,
    argv: Option<Vec<String>>,
    config: Option<Value>,
    scorer: Option<Value>,
    returncode: Option<i32>,
}

struct ProcessStat {
    raw: Vec<u8>,
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
    let raw = bytes(&Path::new("/proc").join(pid).join("stat"))?;
    let text = std::str::from_utf8(&raw).map_err(|_| ProcessSourceError)?;
    let (_, fields) = text.rsplit_once(") ").ok_or(ProcessSourceError)?;
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
        raw,
        parent,
        start,
        state,
        exit_status,
    })
}

fn uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

fn peer(header: &Header, executable: &Path, snapshot: &Path) -> Result<PathBuf> {
    peer_at(header, executable, snapshot, std::process::id())
}

fn peer_at(
    header: &Header,
    executable: &Path,
    snapshot: &Path,
    caller_pid: u32,
) -> Result<PathBuf> {
    if stat(&caller_pid.to_string())?.parent != header.controller.pid {
        return Err(ProcessSourceError);
    }
    controller_peer(header, Some(executable), snapshot)
}

fn controller_peer(header: &Header, executable: Option<&Path>, snapshot: &Path) -> Result<PathBuf> {
    let parent = header.controller.pid;
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
    // Generic Work declarations are untrusted intent, not the fixed trial producer's
    // execution evidence. Its immutable source revision is measured separately below.
    if header.format == FORMAT
        && format!("{FORMAT}:{:x}", Sha256::digest(bytes(&script)?)) != SOURCE_REVISION
    {
        return Err(ProcessSourceError);
    }
    for (flag, expected) in [
        (b"--native-hook".as_slice(), executable),
        (b"--runtime-snapshot".as_slice(), Some(snapshot)),
    ] {
        let index = args
            .iter()
            .position(|arg| *arg == flag)
            .ok_or(ProcessSourceError)?;
        let value = std::str::from_utf8(args.get(index + 1).ok_or(ProcessSourceError)?)
            .map_err(|_| ProcessSourceError)?;
        if let Some(expected) = expected {
            if fs::canonicalize(value).map_err(|_| ProcessSourceError)?
                != fs::canonicalize(expected).map_err(|_| ProcessSourceError)?
            {
                return Err(ProcessSourceError);
            }
        } else {
            let file = fs::symlink_metadata(value).map_err(|_| ProcessSourceError)?;
            if !file.is_file() || file.uid() != own_uid || file.mode() & 0o022 != 0 {
                return Err(ProcessSourceError);
            }
        }
    }
    fs::canonicalize(script).map_err(|_| ProcessSourceError)
}

// The physical unit is this source's single child process lifetime, not its opaque trial UUID.
// The source holds a pipe before execution and uses WNOWAIT after exit. Both endpoints
// can therefore be checked against the kernel here without a cache, lookup or claimed birth.
fn physical_scope(header: &Header) -> Result<(String, Vec<u8>)> {
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
            let names = args
                .iter()
                .filter_map(|arg| arg.strip_prefix("--junitxml="))
                .collect::<Vec<_>>();
            let expected = format!(
                "trial-{}.xml",
                header.execution_key.as_deref().ok_or(ProcessSourceError)?
            );
            if names.len() != 1
                || Path::new(names[0])
                    .file_name()
                    .and_then(|name| name.to_str())
                    != Some(expected.as_str())
            {
                return Err(ProcessSourceError);
            }
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
    Ok((
        format!(
            "process:{}:{}:{}:{}",
            identity.boot_id, identity.pid_namespace, identity.pid, observed.start
        ),
        observed.raw,
    ))
}

fn decode(raw: &[u8]) -> Result<(Header, ObservationRole)> {
    if !is_record(raw) || raw.len() > LIMIT {
        return Err(ProcessSourceError);
    }
    let value: Value = serde_json::from_slice(raw).map_err(|_| ProcessSourceError)?;
    let fields = value.as_object().ok_or(ProcessSourceError)?;
    let work = fields.get("format").and_then(Value::as_str) == Some(WORK_FORMAT);
    if work
        && fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "format"
                    | "event"
                    | "event_key"
                    | "source_epoch"
                    | "work_key"
                    | "sequence"
                    | "time_us"
                    | "controller"
                    | "definition"
                    | "lane_thread_id"
                    | "probe_endpoint"
            )
        })
    {
        return Err(ProcessSourceError);
    }
    if !work && fields.contains_key("work_key") {
        return Err(ProcessSourceError);
    }
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
                | "work_key"
                | "definition"
                | "trial_key"
                | "argv"
                | "config"
                | "source_anchor"
                | "launch_event"
                | "process"
                | "execution_key"
                | "execution_ordinal"
                | "returncode"
                | "scorer"
                | "outcomes"
                | "request_key"
                | "lane_thread_id"
                | "probe_endpoint"
                | "generation_parent"
                | "retry_of_execution"
        )
    }) {
        return Err(ProcessSourceError);
    }
    let header: Header = serde_json::from_value(value).map_err(|_| ProcessSourceError)?;
    let role = match header.event.as_str() {
        "work_started" if work && header.sequence == 1 => ObservationRole::Other,
        _ if work => return Err(ProcessSourceError),
        "study_opened" | "controller_finished" => ObservationRole::Other,
        "trial_launch" => ObservationRole::Intent,
        "trial_started" => ObservationRole::Other,
        "trial_finished" => ObservationRole::Result,
        _ => return Err(ProcessSourceError),
    };
    let probe = if work { "work" } else { "trial" };
    if !matches!(header.format.as_str(), FORMAT | WORK_FORMAT)
        || header.lane_thread_id != header.controller.pid
        || header.probe_endpoint != format!(".{probe}-probe-{}.sock", header.source_epoch)
        || !uuid(&header.event_key)
        || !uuid(&header.source_epoch)
        || !uuid(&header.study_key)
        || header.sequence == 0
        || header.time_us < 0
    {
        return Err(ProcessSourceError);
    }
    Ok((header, role))
}

/// Publisher headers never choose trust. Only separately read OS bytes become observed state;
/// neither source supplies Complete capture, an active Work binding, or Exact admission.
pub fn records(
    raw: &[u8],
    snapshot: &Path,
    manifest_ref: &str,
    kernel_manifest: &str,
    input_manifest: &str,
    output_manifest: &str,
    conditions_manifest: &str,
) -> Result<Vec<Observation>> {
    if [
        manifest_ref,
        kernel_manifest,
        input_manifest,
        output_manifest,
        conditions_manifest,
    ]
    .iter()
    .any(|value| value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(ProcessSourceError);
    }
    let (header, role) = decode(raw)?;
    let executable = std::env::current_exe().map_err(|_| ProcessSourceError)?;
    let script = peer(&header, &executable, snapshot)?;
    let (source_range, native_ordinal) = published_record(raw, &header, &script)?;
    let work = header.format == WORK_FORMAT;
    let (revision, adapter, parser, events) = if work {
        (
            format!("{WORK_FORMAT}:{:x}", Sha256::digest(bytes(&script)?)),
            WORK_ADAPTER_REVISION,
            WORK_PARSER_REVISION,
            WORK_ELIGIBLE_EVENTS,
        )
    } else {
        (
            SOURCE_REVISION.into(),
            ADAPTER_REVISION,
            PARSER_REVISION,
            ELIGIBLE_EVENTS,
        )
    };
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
        adapter_revision: adapter,
        strong_gate_receipt_ref: None,
        admission: CorrelationAdmission::Unavailable,
        partial_correlation_ref: None,
        possible_duplicate_group_id: None,
    };
    // Only v3's actual successful Popen counter, linked to the original launch, may
    // populate this candidate axis. Its own gate is still unavailable; never use a cursor.
    let mut kernel = None;
    if let Some(ordinal) = native_ordinal
        && header.request_key.as_deref().is_some_and(uuid)
        && let Ok((_, stat)) = physical_scope(&header)
    {
        kernel = Some(stat);
        let evidence = source_observation_id(
            &SourceInstanceId::parse(&source_instance_id).map_err(|_| ProcessSourceError)?,
            &SourceRevision::parse(SOURCE_REVISION).map_err(|_| ProcessSourceError)?,
            &SourceRecordIdentity::parse(&header.event_key).map_err(|_| ProcessSourceError)?,
        )
        .map_err(|_| ProcessSourceError)?;
        correlation.host_instance_id = Some(source_instance_id.clone());
        correlation.host_trace_lineage_id = Some(header.source_epoch.clone());
        correlation.host_lane_key = Some(format!(
            "{source_instance_id}:thread:{}",
            header.lane_thread_id
        ));
        correlation.canonical_event_family = Some(CanonicalEventFamily::Verify);
        correlation.native_request_id = header.request_key.clone();
        correlation.physical_execution_ordinal = Some(ordinal);
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
    let inputs = if kernel.is_some() && header.event == "trial_launch" {
        execution_inputs(&header).unwrap_or_default()
    } else {
        vec![]
    };
    let output = if kernel.is_some() && header.event == "trial_finished" {
        execution_output(&header, &script).ok()
    } else {
        None
    };
    let conditions = if inputs.len() == 2 {
        execution_conditions(&header, &script).ok()
    } else {
        None
    };
    let primary = CaptureRecordInput {
        spool_record_id: Some(header.event_key.clone()),
        source_observation_id_hint: None,
        source_instance_id,
        source_revision: revision,
        source_record_identity: Some(header.event_key),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: header.format,
        source_ref,
        session_ref: header.source_epoch,
        turn_ref: None,
        tool_ref: None,
        source_sequence: header.sequence,
        source_sequence_origin: Some(1),
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        source_byte_range: Some(source_range),
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
        adapter_revision: adapter,
        adapter_manifest_ref: manifest_ref.into(),
        eligible_event_manifest_ref: events.into(),
        parser_revision: parser,
        canonicalization_revision: 1,
        // The original clock value remains in raw bytes; its uncertainty is not qualified.
        event_time_us: None,
        event_time_provenance: None,
        raw_payload: raw.to_vec(),
    };
    let mut observations = vec![Observation(primary)];
    if let (Some(raw), Some(process)) = (kernel, header.process.as_ref())
        && let Ok(probe) = kernel_observation(raw, process, kernel_manifest)
    {
        observations.push(probe);
        for (endpoint, raw) in inputs {
            let Ok(Observation(mut input)) = kernel_observation(raw, process, input_manifest)
            else {
                continue;
            };
            input.source_instance_id.push(':');
            input.source_instance_id.push_str(endpoint);
            input.source_revision = INPUT_SOURCE_REVISION.into();
            input.identity_domain = INPUT_SOURCE_REVISION.into();
            input.source_ref = format!(
                "procfs:/proc/{}/{endpoint}@{}",
                process.pid, process.start_ticks
            );
            input.eligible_event_manifest_ref = INPUT_ELIGIBLE_EVENTS.into();
            observations.push(Observation(input));
        }
        for (file, manifest, revision, events, suffix) in [
            (
                output,
                output_manifest,
                OUTPUT_SOURCE_REVISION,
                OUTPUT_ELIGIBLE_EVENTS,
                ":junit",
            ),
            (
                conditions,
                conditions_manifest,
                CONDITIONS_SOURCE_REVISION,
                CONDITIONS_ELIGIBLE_EVENTS,
                ":runtime",
            ),
        ] {
            if let Some((raw, reference)) = file
                && let Ok(Observation(mut artifact)) = kernel_observation(raw, process, manifest)
            {
                artifact.source_instance_id.push_str(suffix);
                artifact.source_revision = revision.into();
                artifact.identity_domain = revision.into();
                artifact.source_ref = reference;
                artifact.eligible_event_manifest_ref = events.into();
                observations.push(Observation(artifact));
            }
        }
    }
    Ok(observations)
}

// Preserve the original NUL-delimited procfs bytes. Unknown environment keys,
// missing fields or disagreement with the declared bounded input are not archived.
fn accepted_environment(raw: &[u8], config: Option<&Value>) -> bool {
    let Some(declared) = config
        .and_then(|value| value.get("environment"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    let keys = [
        "HOME",
        "LANG",
        "PATH",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
        "PYTHONDONTWRITEBYTECODE",
    ];
    if declared.len() != keys.len()
        || keys
            .iter()
            .any(|key| declared.get(*key).and_then(Value::as_str).is_none())
        || !raw.ends_with(&[0])
    {
        return false;
    }
    let mut seen = BTreeSet::new();
    for entry in raw[..raw.len() - 1].split(|byte| *byte == 0) {
        let Ok(entry) = std::str::from_utf8(entry) else {
            return false;
        };
        let Some((key, value)) = entry.split_once('=') else {
            return false;
        };
        if !seen.insert(key) || declared.get(key).and_then(Value::as_str) != Some(value) {
            return false;
        }
    }
    seen.len() == keys.len()
}

fn execution_inputs(header: &Header) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let identity = header.process.as_ref().ok_or(ProcessSourceError)?;
    let root = Path::new("/proc").join(identity.pid.to_string());
    let command = bytes(&root.join("cmdline"))?;
    let args = header.argv.as_ref().ok_or(ProcessSourceError)?;
    let declared = args
        .iter()
        .flat_map(|arg| arg.bytes().chain(std::iter::once(0)))
        .collect::<Vec<_>>();
    if command.is_empty() || command != declared {
        return Err(ProcessSourceError);
    }
    let mut inputs = vec![("cmdline", command)];
    if let Ok(environment) = bytes(&root.join("environ"))
        && accepted_environment(&environment, header.config.as_ref())
    {
        inputs.push(("environ", environment));
    }
    // This is the exact child already checked by physical_scope, not a source
    // locator. Recheck birth/parent after reads, before admitting either snapshot.
    let observed = stat(&identity.pid.to_string())?;
    if observed.start != identity.start_ticks
        || observed.parent != header.controller.pid
        || observed.state == "Z"
    {
        return Err(ProcessSourceError);
    }
    Ok(inputs)
}

fn kernel_observation(
    raw: Vec<u8>,
    process: &ProcessIdentity,
    manifest: &str,
) -> Result<Observation> {
    let observer = stat("self")?;
    let boot = text(Path::new("/proc/sys/kernel/random/boot_id"))?;
    let namespace = fs::metadata("/proc/self/ns/pid")
        .map_err(|_| ProcessSourceError)?
        .ino();
    let instance = format!(
        "procfs:{boot}:{namespace}:{}:{}",
        std::process::id(),
        observer.start
    );
    let probe = CaptureRecordInput {
        spool_record_id: None,
        source_observation_id_hint: None,
        source_instance_id: instance.clone(),
        source_revision: KERNEL_SOURCE_REVISION.into(),
        source_record_identity: None,
        identity_strength: Some(IdentityStrength::SynthesizedBestEffort),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: KERNEL_SOURCE_REVISION.into(),
        source_ref: format!("procfs:/proc/{}/stat@{}", process.pid, process.start_ticks),
        session_ref: instance,
        turn_ref: None,
        tool_ref: None,
        source_sequence: 0,
        source_sequence_origin: Some(0),
        task_id: None,
        repository_instance_id: None,
        worktree_instance_id: None,
        source_byte_range: Some(EvidenceByteRange {
            start: 0,
            end: raw.len() as u64,
        }),
        source_revision_mode: SourceRevisionMode::Append,
        previous_source_revision: None,
        close_watermark: Some(0),
        observation_role: ObservationRole::StateProbe,
        correlation: HostCorrelationEvidence {
            occurrence_schema_version: 1,
            host_instance_id: None,
            host_trace_lineage_id: None,
            host_lane_key: None,
            canonical_event_family: None,
            native_request_id: None,
            physical_execution_ordinal: None,
            pairing_role: ObservationRole::StateProbe,
            field_provenance: vec![],
            adapter_manifest_ref: manifest.into(),
            adapter_revision: KERNEL_ADAPTER_REVISION,
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
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Partial,
        surface_eligible: false,
        adapter_revision: KERNEL_ADAPTER_REVISION,
        adapter_manifest_ref: manifest.into(),
        eligible_event_manifest_ref: KERNEL_ELIGIBLE_EVENTS.into(),
        parser_revision: 1,
        canonicalization_revision: 1,
        event_time_us: None,
        event_time_provenance: None,
        raw_payload: raw,
    };
    Ok(Observation(probe))
}

/// Observe this exact source's actual closed file, not a second label on its Hook payload.
/// Failure is returned separately so the caller still durably admits the original Hook record.
pub fn closed_records(primary: &Observation, snapshot: &Path) -> Result<Vec<Observation>> {
    let primary = &primary.0;
    let Some(watermark) = primary.close_watermark else {
        return Ok(vec![]);
    };
    let (closing, _) = decode(&primary.raw_payload)?;
    if closing.event != "controller_finished"
        || watermark != closing.sequence
        || watermark > SOURCE_RECORDS
    {
        return Err(ProcessSourceError);
    }
    let executable = std::env::current_exe().map_err(|_| ProcessSourceError)?;
    let script = peer(&closing, &executable, snapshot)?;
    let deadline = Instant::now() + Duration::from_millis(50);
    let (path, file) = published_file(&script, &closing.controller, deadline)?;
    let instance = format!(
        "{}:file:{}:{}",
        primary.source_instance_id, file.identity.device, file.identity.inode
    );
    let mut records = Vec::new();
    let mut keys = BTreeSet::new();
    let mut offset = 0;
    for line in file.bytes.split_inclusive(|byte| *byte == b'\n') {
        let (header, role) = decode(line)?;
        if Instant::now() >= deadline
            || header.controller != closing.controller
            || header.source_epoch != closing.source_epoch
            || header.study_key != closing.study_key
            || !keys.insert(header.event_key.clone())
            || header.sequence != records.len() as u64 + 1
            || header.sequence > watermark
            || (header.sequence == 1 && header.event != "study_opened")
            || (header.event == "controller_finished") != (header.sequence == watermark)
        {
            return Err(ProcessSourceError);
        }
        let id = source_observation_id(
            &SourceInstanceId::parse(&instance).map_err(|_| ProcessSourceError)?,
            &SourceRevision::parse(SOURCE_REVISION).map_err(|_| ProcessSourceError)?,
            &SourceRecordIdentity::parse(&header.event_key).map_err(|_| ProcessSourceError)?,
        )
        .map_err(|_| ProcessSourceError)?;
        let mut record = primary.clone();
        record.spool_record_id = Some(id.to_string());
        record.source_observation_id_hint = Some(id.to_string());
        record.source_instance_id = instance.clone();
        record.source_ref = format!("file:{}", path.display());
        record.source_record_identity = Some(header.event_key);
        record.source_sequence = header.sequence;
        record.close_watermark = (header.sequence == watermark).then_some(watermark);
        record.source_byte_range = Some(EvidenceByteRange {
            start: offset,
            end: offset + line.len() as u64,
        });
        record.observation_role = role;
        // The closing primary has no kernel correlation. Do not re-observe dead children or
        // promote declarations from a file into independently verified physical facts.
        record.correlation.pairing_role = role;
        record.raw_payload = line.to_vec();
        records.push(Observation(record));
        offset += line.len() as u64;
    }
    if records.len() as u64 != watermark
        || records
            .last()
            .is_none_or(|record| record.0.raw_payload != primary.raw_payload)
    {
        return Err(ProcessSourceError);
    }
    Ok(records)
}

/// Read only fixed source-native execution filenames, never the declared locator.
fn execution_file(header: &Header, script: &Path, suffix: &str) -> Result<(Vec<u8>, String)> {
    let execution = header.execution_key.as_deref().ok_or(ProcessSourceError)?;
    if !uuid(execution) {
        return Err(ProcessSourceError);
    }
    let directory = script.parent().ok_or(ProcessSourceError)?;
    let relative = format!("trial-{execution}.{suffix}");
    let root = ConfinedRoot::open_external_source(directory).map_err(|_| ProcessSourceError)?;
    let file = root
        .read(
            Path::new(&relative),
            ConfinedReadLimits {
                single_file_remaining: SOURCE_BYTES as u64,
                untracked_total_remaining: SOURCE_BYTES as u64,
                bundle_remaining: SOURCE_BYTES as u64,
                deadline: Instant::now() + Duration::from_millis(50),
            },
        )
        .map_err(|_| ProcessSourceError)?;
    physical_scope(header)?;
    let reference = format!(
        "file-native:{}:{}:{relative}",
        file.identity.device, file.identity.inode
    );
    Ok((file.bytes, reference))
}

fn execution_output(header: &Header, script: &Path) -> Result<(Vec<u8>, String)> {
    let scorer = header.scorer.as_ref().ok_or(ProcessSourceError)?;
    if scorer.get("format").and_then(Value::as_str) != Some("pytest-junit-xunit2") {
        return Err(ProcessSourceError);
    }
    let (raw, reference) = execution_file(header, script, "xml")?;
    if scorer
        .get("original_xml")
        .and_then(Value::as_str)
        .map(str::as_bytes)
        != Some(raw.as_slice())
    {
        return Err(ProcessSourceError);
    }
    Ok((raw, reference))
}

fn execution_conditions(header: &Header, script: &Path) -> Result<(Vec<u8>, String)> {
    let (raw, reference) = execution_file(header, script, "conditions.json")?;
    let value: Value = serde_json::from_slice(&raw).map_err(|_| ProcessSourceError)?;
    let process: ProcessIdentity =
        serde_json::from_value(value.get("process").ok_or(ProcessSourceError)?.clone())
            .map_err(|_| ProcessSourceError)?;
    let declared = header
        .config
        .as_ref()
        .and_then(|config| config.get("environment"));
    if value.get("format").and_then(Value::as_str) != Some(CONDITIONS_SOURCE_REVISION)
        || Some(&process) != header.process.as_ref()
        || declared.is_none()
        || value.get("environment") != declared
    {
        return Err(ProcessSourceError);
    }
    Ok((raw, reference))
}

/// Read only the live verified publisher's owned output, never a caller-supplied locator.
fn published_file(
    script: &Path,
    controller: &ProcessIdentity,
    deadline: Instant,
) -> Result<(PathBuf, ConfinedFile)> {
    let root = script.parent().ok_or(ProcessSourceError)?;
    let command = bytes(
        &Path::new("/proc")
            .join(controller.pid.to_string())
            .join("cmdline"),
    )?;
    let args: Vec<_> = command
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .collect();
    let series = args
        .iter()
        .rposition(|arg| *arg == b"--series")
        .map(|index| args.get(index + 1).ok_or(ProcessSourceError))
        .transpose()?
        .copied()
        .unwrap_or(b"recording-v4");
    if series.is_empty()
        || series.len() > 48
        || !series
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return Err(ProcessSourceError);
    }
    let series = std::str::from_utf8(series).map_err(|_| ProcessSourceError)?;
    let relative = format!("events-{series}.jsonl");
    let path = root.join(&relative);
    let metadata = fs::symlink_metadata(&path).map_err(|_| ProcessSourceError)?;
    if !metadata.is_file()
        || metadata.mode() & 0o022 != 0
        || metadata.uid()
            != fs::metadata("/proc/self")
                .map_err(|_| ProcessSourceError)?
                .uid()
    {
        return Err(ProcessSourceError);
    }
    // This is the live, code-verified publisher's owned output root, not an arbitrary
    // Host locator. Pin its owned directory and file; do not relax the generic
    // external-source ancestor policy or mutate permissions to make a probe pass.
    let file = ConfinedRoot::open_owned_private(root)
        .map_err(|_| ProcessSourceError)?
        .read(
            Path::new(&relative),
            ConfinedReadLimits {
                single_file_remaining: SOURCE_BYTES,
                untracked_total_remaining: SOURCE_BYTES,
                bundle_remaining: SOURCE_BYTES,
                deadline,
            },
        )
        .map_err(|_| ProcessSourceError)?;
    if metadata.dev() != file.identity.device
        || metadata.ino() != file.identity.inode
        || !file.bytes.ends_with(b"\n")
    {
        return Err(ProcessSourceError);
    }
    Ok((path, file))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeSnapshot {
    format: String,
    nonce: String,
    controller: ProcessIdentity,
    source_epoch: String,
    source_event_bytes: Vec<String>,
    parent_event_bytes: Vec<String>,
}

fn probe_read(socket: &mut UnixStream, mut output: &mut [u8], deadline: Instant) -> Result<()> {
    while !output.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(ProcessSourceError)?;
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|_| ProcessSourceError)?;
        let length = socket.read(output).map_err(|_| ProcessSourceError)?;
        if length == 0 {
            return Err(ProcessSourceError);
        }
        output = &mut output[length..];
    }
    Ok(())
}

// A live, nonce-bound export from the actual code-pinned controller, not a caller's
// view or a qualification grant. The original file below remains the canonical byte range.
fn source_probe(header: &Header, deadline: Instant) -> Result<Vec<u8>> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let path = Path::new("/proc")
        .join(header.controller.pid.to_string())
        .join("cwd")
        .join(&header.probe_endpoint);
    let before = fs::symlink_metadata(&path).map_err(|_| ProcessSourceError)?;
    let own_uid = fs::metadata("/proc/self")
        .map_err(|_| ProcessSourceError)?
        .uid();
    if !std::os::unix::fs::FileTypeExt::is_socket(&before.file_type())
        || before.uid() != own_uid
        || before.mode() & 0o777 != 0o600
    {
        return Err(ProcessSourceError);
    }
    let fd = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| ProcessSourceError)?;
    let address = SocketAddrUnix::new(&path).map_err(|_| ProcessSourceError)?;
    rustix::net::connect(&fd, &address).map_err(|_| ProcessSourceError)?;
    let credential = rustix::net::sockopt::socket_peercred(&fd).map_err(|_| ProcessSourceError)?;
    if credential.pid.as_raw_nonzero().get() as u32 != header.controller.pid
        || credential.uid.as_raw() != own_uid
    {
        return Err(ProcessSourceError);
    }
    let mut socket = UnixStream::from(fd);
    socket
        .set_nonblocking(false)
        .map_err(|_| ProcessSourceError)?;
    socket
        .set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))
        .map_err(|_| ProcessSourceError)?;
    let nonce = Uuid::new_v4().to_string();
    let format = if header.format == WORK_FORMAT {
        "process-work-probe-v1"
    } else {
        "process-trial-probe-v1"
    };
    let mut request = serde_json::to_vec(&serde_json::json!({
        "format":format, "nonce":nonce
    }))
    .map_err(|_| ProcessSourceError)?;
    request.push(b'\n');
    socket.write_all(&request).map_err(|_| ProcessSourceError)?;
    let mut length = [0_u8; 4];
    probe_read(&mut socket, &mut length, deadline)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > 1024 * 1024 {
        return Err(ProcessSourceError);
    }
    let mut raw = vec![0; length];
    probe_read(&mut socket, &mut raw, deadline)?;
    let snapshot: ProbeSnapshot = serde_json::from_slice(&raw).map_err(|_| ProcessSourceError)?;
    let after = fs::symlink_metadata(&path).map_err(|_| ProcessSourceError)?;
    if snapshot.format != format
        || snapshot.nonce != nonce
        || snapshot.controller != header.controller
        || snapshot.source_epoch != header.source_epoch
        || (before.dev(), before.ino(), before.uid()) != (after.dev(), after.ino(), after.uid())
        || snapshot.source_event_bytes.len() > SOURCE_RECORDS as usize
        || snapshot.parent_event_bytes.len() > SOURCE_RECORDS as usize
        || snapshot
            .source_event_bytes
            .iter()
            .map(String::len)
            .sum::<usize>()
            > SOURCE_BYTES as usize
        || snapshot
            .parent_event_bytes
            .iter()
            .map(String::len)
            .sum::<usize>()
            > SOURCE_BYTES as usize
        || Instant::now() >= deadline
    {
        return Err(ProcessSourceError);
    }
    Ok(snapshot.source_event_bytes.concat().into_bytes())
}

/// Reparse the native axes only. This never grants an admission or constructs an Observation.
pub fn native_correlation_matches(raw: &[u8], value: &HostCorrelationEvidence) -> bool {
    let Ok((header, role)) = decode(raw) else {
        return false;
    };
    let instance = format!(
        "process:{}:{}:{}:{}",
        header.controller.boot_id,
        header.controller.pid_namespace,
        header.controller.pid,
        header.controller.start_ticks
    );
    let lane = format!("{instance}:thread:{}", header.lane_thread_id);
    matches!(
        header.event.as_str(),
        "trial_launch" | "trial_started" | "trial_finished"
    ) && header.execution_key.as_deref().is_some_and(uuid)
        && header.request_key.as_deref().is_some_and(uuid)
        && header.execution_ordinal.is_some_and(|ordinal| ordinal > 0)
        && header
            .config
            .as_ref()
            .and_then(|config| config.get("probe_case"))
            .is_none()
        && value.host_instance_id.as_deref() == Some(instance.as_str())
        && value.host_trace_lineage_id.as_deref() == Some(header.source_epoch.as_str())
        && value.host_lane_key.as_deref() == Some(lane.as_str())
        && value.native_request_id == header.request_key
        && value.physical_execution_ordinal == header.execution_ordinal
        && value.canonical_event_family == Some(CanonicalEventFamily::Verify)
        && value.pairing_role == role
}

/// Native v4 normalization history keeps its original capture contract across replay.
pub fn is_native_profile(adapter: u32, parser: u32) -> bool {
    matches!(
        (adapter, parser),
        (10, 7) | (ADAPTER_REVISION, PARSER_REVISION)
    )
}

/// A new L0 observation may adopt only a currently verified, original native terminal.
/// This proves the terminal event and scorer bytes, not a complete experiment contract.
pub fn verify_native_terminal(raw: &[u8], snapshot: &Path) -> Result<()> {
    let (header, role) = decode(raw)?;
    if role != ObservationRole::Result || header.event != "trial_finished" {
        return Err(ProcessSourceError);
    }
    let script = controller_peer(&header, None, snapshot)?;
    let (_, ordinal) = published_record(raw, &header, &script)?;
    if ordinal.is_none() || ordinal != header.execution_ordinal {
        return Err(ProcessSourceError);
    }
    physical_scope(&header)?;
    execution_output(&header, &script)?;
    // A held zombie and the same nonce-bound source are still required at the end of the read.
    physical_scope(&header)?;
    published_record(raw, &header, &script)?;
    Ok(())
}

/// The same canonical environment identity is measured by the reader and again at first L0 admission.
pub fn verify_runtime_image(raw: &[u8], snapshot: &Path, revision: u32) -> Result<String> {
    if !matches!(revision, 1 | 2 | IMAGE_ADAPTER_REVISION) {
        return Err(ProcessSourceError);
    }
    let (header, role) = decode(raw)?;
    if role != ObservationRole::Intent {
        return Err(ProcessSourceError);
    }
    let script = controller_peer(&header, None, snapshot)?;
    let (_, ordinal) = published_record(raw, &header, &script)?;
    if ordinal.is_none() || ordinal != header.execution_ordinal {
        return Err(ProcessSourceError);
    }
    physical_scope(&header)?;
    let inputs = execution_inputs(&header)?;
    if inputs.len() != 2 {
        return Err(ProcessSourceError);
    }
    let (conditions, _) = execution_conditions(&header, &script)?;
    if revision >= 2 {
        image::verify_source_namespace(&script)?;
    }
    let fingerprint = image::fingerprint(&header, &conditions, revision >= 3)?;
    if revision >= 2 {
        image::verify_source_namespace(&script)?;
    }
    if inputs != execution_inputs(&header)? {
        return Err(ProcessSourceError);
    }
    physical_scope(&header)?;
    published_record(raw, &header, &script)?;
    Ok(fingerprint)
}

/// A native measurement retains the unmodified original launch, not a generated runtime envelope.
pub fn image_record(raw: &[u8], snapshot: &Path, manifest: &str) -> Result<Observation> {
    let fingerprint = verify_runtime_image(raw, snapshot, IMAGE_ADAPTER_REVISION)?;
    let (header, _) = decode(raw)?;
    let process = header.process.as_ref().ok_or(ProcessSourceError)?;
    let Observation(mut record) = kernel_observation(raw.to_vec(), process, manifest)?;
    record.source_instance_id = format!(
        "native-runtime:{}:{}:{}:{}",
        process.boot_id, process.pid_namespace, process.pid, process.start_ticks
    );
    record.source_revision = IMAGE_SOURCE_REVISION.into();
    record.source_record_identity = Some(fingerprint);
    record.identity_strength = Some(IdentityStrength::StableNative);
    record.identity_domain = IMAGE_SOURCE_REVISION.into();
    record.source_ref = format!(
        "runtime:{}:{}@{}",
        header.source_epoch,
        header.execution_key.as_deref().ok_or(ProcessSourceError)?,
        process.start_ticks
    );
    record.session_ref = header.source_epoch;
    record.content_trust = ContentTrust::UntrustedSourceContent;
    record.surface_eligible = true;
    record.adapter_revision = IMAGE_ADAPTER_REVISION;
    record.parser_revision = IMAGE_ADAPTER_REVISION;
    record.correlation.adapter_revision = IMAGE_ADAPTER_REVISION;
    record.eligible_event_manifest_ref = IMAGE_ELIGIBLE_EVENTS.into();
    Ok(Observation(record))
}

/// The untrusted frame cannot grant the native measurement's Observed/Complete L0 classification.
pub fn image_record_matches(raw: &[u8], body: &crate::CaptureRecordBody) -> bool {
    let Ok((header, role)) = decode(raw) else {
        return false;
    };
    let Some(process) = header.process.as_ref() else {
        return false;
    };
    let Some(execution) = header.execution_key.as_deref() else {
        return false;
    };
    let Some(digest) = body
        .source_record_identity
        .as_str()
        .strip_prefix("measured-runtime-v1:")
    else {
        return false;
    };
    role == ObservationRole::Intent
        && body.source_revision.as_str() == IMAGE_SOURCE_REVISION
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        && body.source_instance_id.as_str()
            == format!(
                "native-runtime:{}:{}:{}:{}",
                process.boot_id, process.pid_namespace, process.pid, process.start_ticks
            )
        && body.source_ref
            == format!(
                "runtime:{}:{execution}@{}",
                header.source_epoch, process.start_ticks
            )
        && body.source_session_ref == header.source_epoch
        && body.identity_domain == IMAGE_SOURCE_REVISION
        && body.identity_strength == IdentityStrength::StableNative
        && body.source_kind == EvidenceSourceKind::Other
        && body.source_role == SourceRole::Tool
        && body.content_trust == ContentTrust::UntrustedSourceContent
        && body.capture_completeness == CaptureCompleteness::Partial
        && body.observation_role == ObservationRole::StateProbe
        && body.task_id.is_none()
        && body.repository_instance_id.is_none()
        && body.worktree_instance_id.is_none()
        && body.unsupported_record_classification.is_none()
        && body.surface_eligible
        && body.lifecycle.is_none()
        && body.source_sequence == 0
        && body.source_sequence_origin == Some(0)
        && body.close_watermark == Some(0)
        && matches!(
            (body.adapter_revision, body.parser_revision),
            (1, 1) | (2, 2) | (3, 3)
        )
        && body.canonicalization_revision == 1
        && body.eligible_event_manifest_ref == IMAGE_ELIGIBLE_EVENTS
        && body.correlation.occurrence_schema_version == 1
        && body.correlation.pairing_role == ObservationRole::StateProbe
        && body.correlation.adapter_manifest_ref == body.adapter_manifest_ref
        && body.correlation.adapter_revision == body.adapter_revision
        && body.correlation.partial_correlation_ref.is_none()
        && body.correlation.possible_duplicate_group_id.is_none()
        && body.correlation.admission == CorrelationAdmission::Unavailable
        && body.correlation.host_instance_id.is_none()
        && body.correlation.host_trace_lineage_id.is_none()
        && body.correlation.host_lane_key.is_none()
        && body.correlation.canonical_event_family.is_none()
        && body.correlation.native_request_id.is_none()
        && body.correlation.physical_execution_ordinal.is_none()
        && body.correlation.field_provenance.is_empty()
        && body.correlation.strong_gate_receipt_ref.is_none()
        && body.scope_effect_claims.is_empty()
        && body.source_local_evidence.is_none()
}

/// Verify frozen metadata against original protected bytes without re-reading a live process.
pub fn record_matches(raw: &[u8], body: &crate::CaptureRecordBody) -> bool {
    let Ok((header, role)) = decode(raw) else {
        return false;
    };
    let instance = format!(
        "process:{}:{}:{}:{}",
        header.controller.boot_id,
        header.controller.pid_namespace,
        header.controller.pid,
        header.controller.start_ticks
    );
    let work = header.format == WORK_FORMAT;
    let known_profile = if work {
        is_work_revision(body.source_revision.as_str())
            && (body.adapter_revision, body.parser_revision)
                == (WORK_ADAPTER_REVISION, WORK_PARSER_REVISION)
            && body.identity_domain == WORK_FORMAT
            && body.eligible_event_manifest_ref == WORK_ELIGIBLE_EVENTS
            && body.scope_effect_claims.is_empty()
            && body.source_local_evidence.is_none()
            && body.correlation.host_instance_id.is_none()
            && body.correlation.host_trace_lineage_id.is_none()
            && body.correlation.host_lane_key.is_none()
            && body.correlation.canonical_event_family.is_none()
            && body.correlation.native_request_id.is_none()
            && body.correlation.physical_execution_ordinal.is_none()
            && body.correlation.field_provenance.is_empty()
    } else {
        body.source_revision.as_str() == SOURCE_REVISION
            && (is_native_profile(body.adapter_revision, body.parser_revision)
                || (body.adapter_revision, body.parser_revision) == (9, 6))
    };
    let file_view = body
        .source_instance_id
        .as_str()
        .strip_prefix(&format!("{instance}:file:"))
        .and_then(|suffix| suffix.split_once(':'))
        .is_some_and(|(device, inode)| {
            device.parse::<u64>().is_ok() && inode.parse::<u64>().is_ok_and(|value| value > 0)
        })
        && body
            .source_ref
            .strip_prefix("file:")
            .is_some_and(|path| Path::new(path).is_absolute())
        && body.correlation.host_instance_id.is_none()
        && body.correlation.host_trace_lineage_id.is_none()
        && body.correlation.host_lane_key.is_none()
        && body.correlation.canonical_event_family.is_none()
        && body.correlation.native_request_id.is_none()
        && body.correlation.physical_execution_ordinal.is_none()
        && body.correlation.field_provenance.is_empty();
    body.source_kind == EvidenceSourceKind::Other
        && known_profile
        && body.correlation.adapter_revision == body.adapter_revision
        && body.correlation.admission == CorrelationAdmission::Unavailable
        && body.correlation.strong_gate_receipt_ref.is_none()
        && (body.source_instance_id.as_str() == instance || (!work && file_view))
        && body.source_record_identity.as_str() == header.event_key
        && body.source_sequence == header.sequence
        && body.source_role == SourceRole::Tool
        && body.content_trust == ContentTrust::UntrustedSourceContent
        && body.capture_completeness == CaptureCompleteness::Partial
        && body.correlation.pairing_role == role
        && (body.correlation.host_instance_id.is_none()
            || native_correlation_matches(raw, &body.correlation))
}

/// Unforgeable live probe result. Only the real code-pinned controller can produce one.
pub struct CanaryWitness {
    script: PathBuf,
    executable: PathBuf,
    replayed_record: Vec<u8>,
    opening_record: Vec<u8>,
}

impl CanaryWitness {
    pub fn script(&self) -> &Path {
        &self.script
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn replayed_record(&self) -> &[u8] {
        &self.replayed_record
    }

    pub fn opening_record(&self) -> &[u8] {
        &self.opening_record
    }
}

pub fn canary_witness(raw: &[u8], snapshot: &Path) -> Result<CanaryWitness> {
    let (header, _) = decode(raw)?;
    let script = controller_peer(&header, None, snapshot)?;
    let deadline = Instant::now() + Duration::from_millis(150);
    let first = source_probe(&header, deadline)?;
    let second = source_probe(&header, deadline)?;
    let (_, file) = published_file(&script, &header.controller, deadline)?;
    if !file.bytes.starts_with(&first)
        || !file.bytes.starts_with(&second)
        || !first
            .split_inclusive(|byte| *byte == b'\n')
            .any(|line| line == raw)
        || !second
            .split_inclusive(|byte| *byte == b'\n')
            .any(|line| line == raw)
    {
        return Err(ProcessSourceError);
    }
    let mut keys = BTreeSet::new();
    let mut opening_record = None;
    for (index, line) in first.split_inclusive(|byte| *byte == b'\n').enumerate() {
        let (entry, _) = decode(line)?;
        if entry.sequence != index as u64 + 1
            || entry.controller != header.controller
            || entry.source_epoch != header.source_epoch
            || entry.study_key != header.study_key
            || !keys.insert(entry.event_key)
        {
            return Err(ProcessSourceError);
        }
        if index == 0 {
            if entry.event != "study_opened" {
                return Err(ProcessSourceError);
            }
            opening_record = Some(line.to_vec());
        }
    }
    Ok(CanaryWitness {
        script,
        executable: header.controller.executable.into(),
        replayed_record: raw.to_vec(),
        opening_record: opening_record.ok_or(ProcessSourceError)?,
    })
}

fn published_record(
    raw: &[u8],
    selected: &Header,
    script: &Path,
) -> Result<(EvidenceByteRange, Option<u32>)> {
    let deadline = Instant::now() + Duration::from_millis(50);
    let (_, file) = published_file(script, &selected.controller, deadline)?;
    if source_probe(selected, deadline)? != file.bytes {
        return Err(ProcessSourceError);
    }
    let mut keys = BTreeSet::new();
    let mut offset = 0;
    let mut found = None;
    let mut launch = None;
    let mut count = 0;
    for line in file.bytes.split_inclusive(|byte| *byte == b'\n') {
        let (header, _) = decode(line)?;
        count += 1;
        if count > SOURCE_RECORDS
            || Instant::now() >= deadline
            || header.sequence != count
            || !keys.insert(header.event_key.clone())
            || header.controller != selected.controller
            || header.source_epoch != selected.source_epoch
            || header.study_key != selected.study_key
            || header.format != selected.format
            || (count == 1
                && header.event
                    != if header.format == WORK_FORMAT {
                        "work_started"
                    } else {
                        "study_opened"
                    })
        {
            return Err(ProcessSourceError);
        }
        if header.event_key == selected.event_key {
            if line != raw {
                return Err(ProcessSourceError);
            }
            found = Some(EvidenceByteRange {
                start: offset,
                end: offset + line.len() as u64,
            });
        }
        if launch.is_none()
            && header.event == "trial_launch"
            && header.execution_key.is_some()
            && header.execution_key == selected.execution_key
        {
            launch = Some(header);
        }
        offset += line.len() as u64;
    }
    let range = found.ok_or(ProcessSourceError)?;
    let ordinal = launch
        .filter(|launch| {
            launch.sequence <= selected.sequence
                && launch.process == selected.process
                && launch.request_key == selected.request_key
                && launch.lane_thread_id == selected.lane_thread_id
                && launch.execution_ordinal == selected.execution_ordinal
                && if selected.event == "trial_launch" {
                    selected.event_key == launch.event_key
                } else {
                    selected.launch_event.as_deref() == Some(launch.event_key.as_str())
                }
        })
        .and_then(|launch| launch.execution_ordinal)
        .filter(|ordinal| *ordinal != 0);
    Ok((range, ordinal))
}
