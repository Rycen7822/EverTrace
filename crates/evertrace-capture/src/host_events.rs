//! Original Native JSONRPC transport, not a command/execution API or a qualified namespace.
use std::{
    io::{self, Write},
    path::Path,
    time::{Duration, Instant},
};

use evertrace_domain::evidence::{
    CaptureCompleteness, ContentTrust, CorrelationAdmission, EvidenceByteRange, EvidenceSourceKind,
    HostCorrelationEvidence, IdentityStrength, ObservationRole, SourceRevisionMode, SourceRole,
};
use rustix::event::{PollFd, PollFlags, poll};
use serde::{Deserialize, Deserializer, de::IgnoredAny};
use tungstenite::{
    Error as WireError, Message, client::client_with_config, protocol::WebSocketConfig,
};

use crate::{CaptureRecordInput, CaptureRuntime, RuntimeSnapshot, goal_source};

pub const SOURCE_REVISION: &str = "native-user-shell-live-0.166.0-v1";
pub const ADAPTER_VERSION: &str = "native-user-shell-live-0.166.0-v1:capture-2";
pub const ELIGIBLE_EVENTS: &str = "native-user-shell-state-events-v1";
const INPUT_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("live host source unavailable")]
pub struct HostEventError;
type Result<T> = std::result::Result<T, HostEventError>;

/// Only a verified live connection can construct this value; no caller JSON constructor.
pub(crate) struct Observation(CaptureRecordInput);
impl Observation {
    pub(crate) fn into_record(self) -> CaptureRecordInput {
        self.0
    }
}

// Only decode the eligibility header. Ignore tool output/history without copying it into a JSON tree.
#[derive(Deserialize)]
struct Event {
    #[serde(default, deserialize_with = "id_present")]
    id: bool,
    method: String,
    params: EventParams,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EventParams {
    thread_id: String,
    turn_id: String,
    item: EventItem,
}

#[derive(Deserialize)]
struct EventItem {
    #[serde(rename = "type")]
    kind: String,
    source: String,
    id: String,
    status: String,
}

fn id_present<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<bool, D::Error> {
    IgnoredAny::deserialize(deserializer)?;
    Ok(true)
}

fn uuid(text: &str) -> Option<&str> {
    uuid::Uuid::parse_str(text)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == text)?;
    Some(text)
}

fn observation(raw: &str, instance: &str, sequence: u64, manifest: &str) -> Option<Observation> {
    let event: Event = serde_json::from_str(raw).ok()?;
    let method = event.method.as_str();
    let item = &event.params.item;
    if event.id
        || !matches!(
            (method, item.status.as_str()),
            ("item/started", "inProgress") | ("item/completed", "completed" | "failed")
        )
        || item.kind != "commandExecution"
        || item.source != "userShell"
    {
        return None;
    }
    let thread = uuid(&event.params.thread_id)?;
    let turn = uuid(&event.params.turn_id)?;
    let item = uuid(&item.id)?;
    if uuid::Uuid::parse_str(item).ok()?.get_version_num() != 4 {
        return None;
    }
    Some(Observation(CaptureRecordInput {
        spool_record_id: None,
        source_observation_id_hint: None,
        source_instance_id: instance.into(),
        source_revision: SOURCE_REVISION.into(),
        source_record_identity: Some(format!("{turn}:{item}:{method}")),
        identity_strength: Some(IdentityStrength::StableNative),
        source_kind: EvidenceSourceKind::Other,
        identity_domain: SOURCE_REVISION.into(),
        source_ref: format!("native-user-shell:{thread}:{turn}:{item}:{method}"),
        session_ref: thread.into(),
        turn_ref: Some(turn.into()),
        tool_ref: Some(item.into()),
        source_sequence: sequence,
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
        close_watermark: None,
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
            adapter_revision: 2,
            strong_gate_receipt_ref: None,
            admission: CorrelationAdmission::Unavailable,
            partial_correlation_ref: None,
            possible_duplicate_group_id: None,
        },
        scope_effect_claims: vec![],
        source_local_evidence: None,
        lifecycle: None,
        unsupported_record_classification: None,
        source_role: SourceRole::Host,
        content_trust: ContentTrust::Observed,
        capture_completeness: CaptureCompleteness::Partial,
        surface_eligible: false,
        adapter_revision: 2,
        adapter_manifest_ref: manifest.into(),
        eligible_event_manifest_ref: ELIGIBLE_EVENTS.into(),
        parser_revision: 2,
        canonicalization_revision: 1,
        event_time_us: None,
        event_time_provenance: None,
        raw_payload: raw.as_bytes().to_vec(),
    }))
}

fn blocked(error: &WireError) -> bool {
    matches!(error, WireError::Io(error) if error.kind() == io::ErrorKind::WouldBlock)
}

/// Explicit source connection only. Never start a host, send hidden requests or poll work state.
/// Native JSONRPC text is forwarded unchanged, with stdio's newline framing.
pub fn relay(snapshot: RuntimeSnapshot, endpoint: &Path, manifest: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let (stream, publisher) =
        goal_source::connect_publisher(endpoint, deadline).map_err(|_| HostEventError)?;
    // This is a connection-local capture epoch, never a physical execution/retry identity.
    let instance = format!(
        "{}:capture:{}",
        publisher
            .instance("native-events")
            .map_err(|_| HostEventError)?,
        uuid::Uuid::now_v7()
    );
    let config = WebSocketConfig::default()
        .read_buffer_size(4096)
        .write_buffer_size(0)
        .max_write_buffer_size(INPUT_LIMIT + 4096);
    let (mut socket, _) =
        client_with_config("ws://localhost/", stream, Some(config)).map_err(|_| HostEventError)?;
    socket
        .get_mut()
        .set_read_timeout(None)
        .map_err(|_| HostEventError)?;
    socket
        .get_mut()
        .set_write_timeout(None)
        .map_err(|_| HostEventError)?;
    socket
        .get_mut()
        .set_nonblocking(true)
        .map_err(|_| HostEventError)?;
    publisher.revalidate().map_err(|_| HostEventError)?;
    // Capture/storage failures must not cut the original Native communication.
    let mut runtime = CaptureRuntime::open_for_admission(snapshot).ok();
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut input = Vec::new();
    let mut pending = false;
    let mut sequence = 0;
    loop {
        if pending {
            match socket.flush() {
                Ok(()) => pending = false,
                Err(error) if blocked(&error) => (),
                Err(_) => return Err(HostEventError),
            }
        }
        if !pending && let Some(end) = input.iter().position(|byte| *byte == b'\n') {
            let mut line = input.drain(..=end).collect::<Vec<_>>();
            line.pop();
            let text = String::from_utf8(line).map_err(|_| HostEventError)?;
            match socket.write(Message::text(text)) {
                Ok(()) => pending = true,
                Err(error) if blocked(&error) => pending = true,
                Err(_) => return Err(HostEventError),
            }
        }
        loop {
            match socket.read() {
                Ok(Message::Text(text)) => {
                    stdout
                        .write_all(text.as_bytes())
                        .map_err(|_| HostEventError)?;
                    stdout.write_all(b"\n").map_err(|_| HostEventError)?;
                    stdout.flush().map_err(|_| HostEventError)?;
                    if let Some(observed) = observation(&text, &instance, sequence, manifest) {
                        if publisher.revalidate().is_ok()
                            && let Some(runtime) = &mut runtime
                        {
                            let _ = runtime.capture_host_event(observed);
                        }
                        sequence = sequence.checked_add(1).ok_or(HostEventError)?;
                    }
                }
                Ok(Message::Close(_)) | Err(WireError::ConnectionClosed) => return Ok(()),
                Ok(Message::Ping(_)) => pending = true,
                Ok(_) => (),
                Err(error) if blocked(&error) => break,
                Err(_) => return Err(HostEventError),
            }
        }
        if !pending && input.contains(&b'\n') {
            continue;
        }
        let input_ready = {
            let mut fds = [
                PollFd::new(
                    &stdin,
                    if input.len() < INPUT_LIMIT && !pending {
                        PollFlags::IN
                    } else {
                        PollFlags::empty()
                    },
                ),
                PollFd::new(
                    socket.get_ref(),
                    PollFlags::IN
                        | if pending {
                            PollFlags::OUT
                        } else {
                            PollFlags::empty()
                        },
                ),
            ];
            loop {
                match poll(&mut fds, None) {
                    Ok(_) => break,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(_) => return Err(HostEventError),
                }
            }
            fds[0]
                .revents()
                .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
        };
        if input_ready {
            let mut buffer = [0; 8192];
            let count = rustix::io::read(&stdin, &mut buffer).map_err(|_| HostEventError)?;
            if count == 0 {
                let _ = socket.close(None);
                return Ok(());
            }
            input.extend_from_slice(&buffer[..count]);
            if input.len() > INPUT_LIMIT || (input.len() == INPUT_LIMIT && !input.contains(&b'\n'))
            {
                return Err(HostEventError);
            }
        }
    }
}
